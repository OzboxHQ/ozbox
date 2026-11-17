//! What an approval binds: the **subject** of a request and its digest (ADR 0041 §4).
//!
//! One function, [`Subject::digest`], is used by the box and by the laptop, and both must produce the golden vectors in the
//! tests. The encoding is [`Encoder`]: one version byte, the domain tag, then **length-prefixed fields** (4-byte big-endian
//! length) in a fixed order per scope. The box id, the store id and the scope are the first fields, so a digest cannot be
//! reused on another box, another scope or another version. A set is sorted and a duplicate is refused. Names are ASCII
//! only (`[A-Za-z0-9_]`). The digest hashes the change's own canonical fields, never the 16-hex change code the root
//! helpers print.
//!
//! The encoder is shared: ADR 0040's fleet-apply challenge and ADR 0042's channel messages use [`digest_fields`] with
//! their own tags. A subject holds names, digests and counts only: never a value, a token, a code or a command's output.

use ring::digest::{digest, SHA256};
use serde::{Deserialize, Serialize};

/// The version byte of the encoding. A change to the encoding changes this, so an old digest never verifies as a new one.
pub const ENCODING_VERSION: u8 = 1;
/// The domain tag of a subject digest.
pub const SUBJECT_TAG: &str = "ozbox-approval-subject-v1";
/// The domain tag of the challenge a dashboard assertion is made over (ADR 0041 §3).
pub const DECIDE_TAG: &str = "ozbox-approval-decide-v1";
/// The domain tag the service signs a request envelope under.
pub const ENVELOPE_TAG: &str = "ozbox-approval-envelope-v1";
/// The domain tag of the challenge a laptop key's enrolment attestation is bound to (ADR 0041 §3).
pub const KEY_ENROL_TAG: &str = "ozbox-key-enrol-v1";
const MAX_FIELD: usize = 4096;
const MAX_LIST: usize = 512;

/// The match rule the service gives a stored value that looks like a Production credential (ADR 0029): such a commit is
/// never decided here.
pub const RULE_PRODUCTION_LOOKING: &str = "production-looking";

/// Why a subject is refused. The message is for a person and never contains a value.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SubjectError(pub String);

impl std::fmt::Display for SubjectError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

fn bad<T>(what: &str) -> Result<T, SubjectError> {
    Err(SubjectError(what.to_string()))
}

/// The length-prefixed encoder. Every field is a 4-byte big-endian length then the bytes.
pub struct Encoder(Vec<u8>);

impl Encoder {
    /// Start an encoding for a domain: the version byte, then the tag as a length-prefixed field.
    pub fn new(tag: &str) -> Self {
        let mut e = Encoder(vec![ENCODING_VERSION]);
        e.field(tag.as_bytes());
        e
    }

    pub fn field(&mut self, bytes: &[u8]) -> &mut Self {
        // a field this long was refused by validation; the cast cannot truncate for any field that got here
        let len = u32::try_from(bytes.len()).unwrap_or(u32::MAX);
        self.0.extend_from_slice(&len.to_be_bytes());
        self.0.extend_from_slice(bytes);
        self
    }

    pub fn text(&mut self, s: &str) -> &mut Self {
        self.field(s.as_bytes())
    }

    pub fn u64(&mut self, n: u64) -> &mut Self {
        self.field(&n.to_be_bytes())
    }

    pub fn flag(&mut self, b: bool) -> &mut Self {
        self.field(&[u8::from(b)])
    }

    /// The count of a list, as a field of its own, so a list cannot run into the field after it.
    pub fn count(&mut self, n: usize) -> &mut Self {
        self.u64(n as u64)
    }

    pub fn bytes(&self) -> &[u8] {
        &self.0
    }

    pub fn digest(&self) -> [u8; 32] {
        let d = digest(&SHA256, &self.0);
        let mut out = [0u8; 32];
        out.copy_from_slice(d.as_ref());
        out
    }
}

/// The digest of `fields` under `tag`: the shared function other ADRs use for their own challenges.
pub fn digest_fields(tag: &str, fields: &[&[u8]]) -> [u8; 32] {
    let mut e = Encoder::new(tag);
    for f in fields {
        e.field(f);
    }
    e.digest()
}

/// The digest an import binds each value by: `sha256` over the shared encoding under its own tag of the sender's per-import
/// salt and the value. The sender (the laptop) and the service both compute it; the service keeps only the digest and never
/// returns the salt or a per-value hash on any read path.
pub fn import_value_digest(salt: &str, value: &str) -> String {
    to_hex(&digest_fields(
        "ozbox-import-value-v1",
        &[salt.as_bytes(), value.as_bytes()],
    ))
}

pub fn to_hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

pub fn from_hex(s: &str) -> Option<Vec<u8>> {
    if !s.len().is_multiple_of(2) || !s.is_ascii() {
        return None;
    }
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).ok())
        .collect()
}

/// SHA-256 of `s`, in lowercase hex (used for the hash of a path or a remote URL in an operation key).
pub fn sha256_hex(s: &str) -> String {
    to_hex(digest(&SHA256, s.as_bytes()).as_ref())
}

/// The box and the store a digest is for.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Ids {
    pub box_id: String,
    pub store_id: String,
}

fn id_ok(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= 128
        && s.bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b':' | b'-'))
}

impl Ids {
    pub fn validate(&self) -> Result<(), SubjectError> {
        if id_ok(&self.box_id) && id_ok(&self.store_id) {
            Ok(())
        } else {
            bad("the box id and the store id are letters, digits and . _ : - only")
        }
    }
}

/// A name of a secret: ASCII letters, digits and `_` only (a lookalike letter from another script is refused).
pub fn name_ok(s: &str) -> bool {
    !s.is_empty() && s.len() <= 128 && s.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_')
}

/// A character that is invisible or that reorders what is around it: bidirectional controls (U+061C, U+200E/F,
/// U+202A-E, U+2066-9), the line and paragraph separators (U+2028/9), and the zero-width and formatting characters a
/// lookalike hides behind. (General categories Cf, Zl and Zp, as far as the standard library knows them without a table.)
pub fn is_invisible_or_bidi(c: char) -> bool {
    matches!(
        c,
        '\u{061c}'
            | '\u{00ad}'
            | '\u{180e}'
            | '\u{200b}'..='\u{200f}'
            | '\u{2028}'..='\u{202e}'
            | '\u{2060}'..='\u{2064}'
            | '\u{2066}'..='\u{206f}'
            | '\u{feff}'
            | '\u{fff9}'..='\u{fffb}'
            | '\u{e0000}'..='\u{e007f}'
    )
}

/// Text a person will read on a card: no control characters, no bidirectional controls, bounded.
pub fn text_ok(s: &str) -> bool {
    s.len() <= MAX_FIELD
        && !s.is_empty()
        && s.chars()
            .all(|c| !c.is_control() && !is_invisible_or_bidi(c))
}

fn hex_ok(s: &str, bytes: usize) -> bool {
    s.len() == bytes * 2
        && s.bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

fn word_ok(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= 64
        && s.bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
}

/// The environments a box knows are **not** Production: the same list the box's own secrets declaration accepts
/// (`box_secrets::ENVS`, a parity test in `ozbox-cli` keeps the two equal). Anything else is treated as Production by the
/// rules, the fail-safe reading: an environment named `live` or `qa` is never decided by a member or a software key.
pub const NON_PRODUCTION_ENVS: &[&str] = &["dev", "development", "staging", "test", "e2e"];

/// Whether an environment is Production for the rules. Not in [`NON_PRODUCTION_ENVS`] means Production (`production`,
/// `prod` and `live` are the names `workload::live_reason` already treats so, and so is every name nobody listed).
pub fn is_production_environment(env: &str) -> bool {
    !NON_PRODUCTION_ENVS.contains(&env)
}

/// Whether a key's name says production or live (the same rule as `workload::live_reason`'s name check).
pub fn name_says_production(name: &str) -> bool {
    let up = name.to_ascii_uppercase();
    up.contains("PROD") || up.contains("LIVE")
}

/// The prefixes that make a **value** a live-mode key (the box's own rule, `workload::live_reason`, uses this list).
pub const LIVE_VALUE_PREFIXES: &[&str] =
    &["sk_live_", "pk_live_", "rk_live_", "whsec_live", "live_"];

/// Whether a value says Production by what it is: a live-mode key prefix, or an address that looks like production.
/// The subject holds only a digest of a value, so this is checked where the service sees the value (at an import's spend:
/// [`Subject::check_import_values`]) and by `workload::live_reason`, which calls it.
pub fn value_says_production(value: &str) -> bool {
    if LIVE_VALUE_PREFIXES.iter().any(|p| value.starts_with(p)) {
        return true;
    }
    let v = value.to_ascii_lowercase();
    v.contains("://") && (v.contains("prod") || v.contains(".live."))
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, PartialOrd, Ord)]
#[serde(rename_all = "kebab-case")]
pub enum Classification {
    Public,
    Secret,
}

/// One scanned match of a guard override, derived by the service from the text it scanned.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, PartialOrd, Ord)]
pub struct GuardMatch {
    pub path: String,
    pub line: u64,
    pub rule: String,
    /// The matching stored key's id (shown on the owner's card, never to the box user).
    pub key_id: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, PartialOrd, Ord)]
pub struct RefUpdate {
    pub ref_name: String,
    pub old: String,
    pub new: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "hook", rename_all = "kebab-case")]
pub enum GuardHook {
    Commit {
        repo_path_hash: String,
        hook_kind: String,
        /// The staged tree (`git write-tree`), not `git diff` output.
        tree_id: String,
        matches: Vec<GuardMatch>,
        scanned_text_hash: String,
    },
    Push {
        repo_path_hash: String,
        /// The normalised remote URL, not the remote's name (`git remote set-url` moves a name).
        remote_url: String,
        refs: Vec<RefUpdate>,
        matches: Vec<GuardMatch>,
        scanned_text_hash: String,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, PartialOrd, Ord)]
pub struct ImportName {
    pub name: String,
    pub classification: Classification,
    /// `sha256(salt, value)` in hex; the salt is the sender's, per import. Never returned on any read path.
    pub value_digest: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Import {
    pub project: String,
    pub environment: String,
    /// The filer says the environment is Production. It can only make a rule stricter (see [`is_production_environment`]).
    #[serde(default)]
    pub production: bool,
    pub names: Vec<ImportName>,
    /// The project's store generation, so an old approved import cannot be replayed after a value was rotated.
    pub store_generation: u64,
}

/// What a policy change does to the guarded settings. In the digest, so a spend that claims differently is refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum PolicySensitivity {
    Ordinary,
    /// Widens `host-guard` or `tunnel-token` (decided by a presence key or root once one has ever been enrolled).
    WidensGuarded,
}

impl PolicySensitivity {
    fn word(self) -> &'static str {
        match self {
            PolicySensitivity::Ordinary => "ordinary",
            PolicySensitivity::WidensGuarded => "widens-guarded",
        }
    }
}

/// What a policy allows under the two scopes the rules guard: the entries of `host-guard` and of `tunnel-token`. The service
/// parses a policy into this; a filer never supplies it.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct GuardedSettings {
    pub host_guard: std::collections::BTreeSet<String>,
    pub tunnel_token: std::collections::BTreeSet<String>,
}

/// A policy's sensitivity, computed from the policy it replaces and the new one: it widens a guarded scope when the new
/// policy allows an entry the old one did not. The only place the label is made; the book refuses a filing whose label
/// is not this (see `Derived::policy_sensitivity`).
pub fn policy_sensitivity(old: &GuardedSettings, new: &GuardedSettings) -> PolicySensitivity {
    if new.host_guard.is_subset(&old.host_guard) && new.tunnel_token.is_subset(&old.tunnel_token) {
        PolicySensitivity::Ordinary
    } else {
        PolicySensitivity::WidensGuarded
    }
}

impl PolicyChange {
    /// The change as the service builds it: the digests of the two canonical policies and the sensitivity it computes.
    pub fn derive(
        policy_sha256: String,
        predecessor_sha256: String,
        old: &GuardedSettings,
        new: &GuardedSettings,
    ) -> PolicyChange {
        PolicyChange {
            policy_sha256,
            predecessor_sha256,
            sensitivity: policy_sensitivity(old, new),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PolicyChange {
    /// sha256 of the canonical serialisation of the parsed policy (made by one function both sides use).
    pub policy_sha256: String,
    /// and of the one it replaces.
    pub predecessor_sha256: String,
    pub sensitivity: PolicySensitivity,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TunnelToken {
    pub kind: String,
    /// `sha256(token)` in hex.
    pub token_sha256: String,
    /// The decoded identity, as far as the provider allows (cloudflared: account tag and tunnel id). Empty when not decoded.
    #[serde(default)]
    pub account_tag: String,
    #[serde(default)]
    pub tunnel_id: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BoxSecrets {
    pub address: String,
    /// `set` or `remove`.
    pub action: String,
    /// The change's digest in hex; empty for a removal.
    #[serde(default)]
    pub change_digest: String,
    /// A first setting (no declaration in place yet): the one case a box with no approver may make.
    #[serde(default)]
    pub first_setting: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HostGuard {
    pub action: String,
    /// Only a loosening asks; tightening needs nothing, and filing it is refused.
    pub loosening: bool,
    /// The change's own fields, sorted by key.
    pub fields: Vec<(String, String)>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum EnrolAction {
    Enrol,
    Revoke,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SignerEnroll {
    pub action: EnrolAction,
    pub key_name: String,
    /// `ed25519`, `sk-ssh-ed25519`, `ecdsa-sk` or `webauthn-p256`.
    pub key_type: String,
    /// The public half in hex.
    pub public_half: String,
    /// The digest of the attestation the key was enrolled with, in hex; empty for a key with none (a software key).
    #[serde(default)]
    pub attestation_digest: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WorkerKeys {
    pub orchestration_id: String,
    pub names: Vec<String>,
    /// development or staging only; a Production use on a worker is a `secret-use`, never this scope.
    pub environment: String,
    pub max_workers: u64,
    pub ttl_s: u64,
}

/// A request that is only a challenge the service issued (`setup-code`, `kek-export`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Challenge {
    pub challenge: String,
}

pub const KEY_TYPES: &[&str] = &["ed25519", "sk-ssh-ed25519", "ecdsa-sk", "webauthn-p256"];

/// The typed subject of a request, per scope. Serialised as `{"scope": "...", ...}`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "scope", rename_all = "kebab-case")]
pub enum Subject {
    GuardOverride(GuardHook),
    Import(Import),
    Policy(PolicyChange),
    TunnelToken(TunnelToken),
    BoxSecrets(BoxSecrets),
    HostGuard(HostGuard),
    SignerEnroll(SignerEnroll),
    WorkerKeys(WorkerKeys),
    SetupCode(Challenge),
    KekExport(Challenge),
}

/// A set of names, checked and sorted; a duplicate is refused.
fn sorted_names(names: &[String]) -> Result<Vec<&str>, SubjectError> {
    if names.len() > MAX_LIST {
        return bad("too many names");
    }
    let mut v: Vec<&str> = names.iter().map(String::as_str).collect();
    if !v.iter().all(|n| name_ok(n)) {
        return bad("a name is letters, digits and _ only (ASCII)");
    }
    v.sort_unstable();
    if v.windows(2).any(|w| w[0] == w[1]) {
        return bad("a name is listed twice");
    }
    Ok(v)
}

fn matches_ok(m: &[GuardMatch]) -> Result<Vec<&GuardMatch>, SubjectError> {
    if m.len() > MAX_LIST {
        return bad("too many matches");
    }
    for g in m {
        // line 0 is "the whole file" (an environment file)
        if !text_ok(&g.path) || !word_ok(&g.rule) || !(g.key_id.is_empty() || id_ok(&g.key_id)) {
            return bad("a match is not valid");
        }
    }
    let mut v: Vec<&GuardMatch> = m.iter().collect();
    v.sort();
    if v.windows(2).any(|w| w[0] == w[1]) {
        return bad("a match is listed twice");
    }
    Ok(v)
}

fn need_hex(s: &str, bytes: usize, what: &str) -> Result<(), SubjectError> {
    if hex_ok(s, bytes) {
        Ok(())
    } else {
        bad(&format!("{what} is {} lowercase hex digits", bytes * 2))
    }
}

fn need_text(s: &str, what: &str) -> Result<(), SubjectError> {
    if text_ok(s) {
        Ok(())
    } else {
        bad(&format!(
            "{what} is empty, too long or has control or direction characters"
        ))
    }
}

impl Subject {
    /// The scope's word, the same as `SCOPE_RULES` and the rule table use.
    pub fn scope(&self) -> &'static str {
        match self {
            Subject::GuardOverride(_) => "guard-override",
            Subject::Import(_) => "import",
            Subject::Policy(_) => "policy",
            Subject::TunnelToken(_) => "tunnel-token",
            Subject::BoxSecrets(_) => "box-secrets",
            Subject::HostGuard(_) => "host-guard",
            Subject::SignerEnroll(_) => "signer-enroll",
            Subject::WorkerKeys(_) => "worker-keys",
            Subject::SetupCode(_) => "setup-code",
            Subject::KekExport(_) => "kek-export",
        }
    }

    /// Refuse a subject that could not be encoded or that breaks a rule of its scope.
    pub fn validate(&self) -> Result<(), SubjectError> {
        match self {
            Subject::GuardOverride(h) => match h {
                GuardHook::Commit {
                    repo_path_hash,
                    hook_kind,
                    tree_id,
                    matches,
                    scanned_text_hash,
                } => {
                    need_hex(repo_path_hash, 32, "the repository hash")?;
                    if !word_ok(hook_kind) {
                        return bad("the hook kind is lowercase letters, digits and - only");
                    }
                    if !(tree_id.len() == 40 || tree_id.len() == 64)
                        || !hex_ok(tree_id, tree_id.len() / 2)
                    {
                        return bad("the tree id is a git object id in hex");
                    }
                    matches_ok(matches)?;
                    need_hex(scanned_text_hash, 32, "the scanned text's hash")
                }
                GuardHook::Push {
                    repo_path_hash,
                    remote_url,
                    refs,
                    matches,
                    scanned_text_hash,
                } => {
                    need_hex(repo_path_hash, 32, "the repository hash")?;
                    need_text(remote_url, "the remote URL")?;
                    if refs.is_empty() || refs.len() > MAX_LIST {
                        return bad("a push names at least one ref");
                    }
                    for r in refs {
                        need_text(&r.ref_name, "a ref name")?;
                        for id in [&r.old, &r.new] {
                            if !(id.len() == 40 || id.len() == 64) || !hex_ok(id, id.len() / 2) {
                                return bad("a commit id is a git object id in hex");
                            }
                        }
                    }
                    matches_ok(matches)?;
                    need_hex(scanned_text_hash, 32, "the scanned text's hash")
                }
            },
            Subject::Import(i) => {
                if !word_ok(&i.project) || !word_ok(&i.environment) {
                    return bad(
                        "the project and the environment are lowercase letters, digits and - only",
                    );
                }
                if i.names.is_empty() || i.names.len() > MAX_LIST {
                    return bad("an import names at least one key");
                }
                sorted_names(&i.names.iter().map(|n| n.name.clone()).collect::<Vec<_>>())?;
                for n in &i.names {
                    need_hex(&n.value_digest, 32, "a value's digest")?;
                }
                Ok(())
            }
            Subject::Policy(p) => {
                need_hex(&p.policy_sha256, 32, "the policy's digest")?;
                need_hex(&p.predecessor_sha256, 32, "the replaced policy's digest")
            }
            Subject::TunnelToken(t) => {
                if !word_ok(&t.kind) {
                    return bad("the tunnel kind is lowercase letters, digits and - only");
                }
                need_hex(&t.token_sha256, 32, "the token's digest")?;
                for s in [&t.account_tag, &t.tunnel_id] {
                    if !s.is_empty() && !id_ok(s) {
                        return bad(
                            "the decoded tunnel identity is letters, digits and . _ : - only",
                        );
                    }
                }
                Ok(())
            }
            Subject::BoxSecrets(b) => {
                need_text(&b.address, "the address")?;
                match b.action.as_str() {
                    "set" => need_hex(&b.change_digest, 32, "the change's digest"),
                    "remove" if b.change_digest.is_empty() => Ok(()),
                    "remove" => bad("a removal has no change digest"),
                    _ => bad("the action is set or remove"),
                }
            }
            Subject::HostGuard(h) => {
                if !word_ok(&h.action) {
                    return bad("the action is lowercase letters, digits and - only");
                }
                if !h.loosening {
                    return bad("tightening a host guard needs no approval, so it is not filed");
                }
                if h.fields.len() > 64 {
                    return bad("too many fields");
                }
                let mut keys: Vec<&str> = Vec::new();
                for (k, v) in &h.fields {
                    if !word_ok(k) {
                        return bad("a field name is lowercase letters, digits and - only");
                    }
                    need_text(v, "a field value")?;
                    keys.push(k);
                }
                if keys.windows(2).any(|w| w[0] >= w[1]) {
                    return bad("fields are sorted by name, each once");
                }
                Ok(())
            }
            Subject::SignerEnroll(s) => {
                if !crate::approval_subject::name_ok(&s.key_name.replace('-', "_")) {
                    return bad("a key name is letters, digits, - and _ only");
                }
                if !KEY_TYPES.contains(&s.key_type.as_str()) {
                    return bad("the key type is not one this version knows");
                }
                if !(s.public_half.len() >= 32
                    && s.public_half.len() <= 256
                    && hex_ok(&s.public_half, s.public_half.len() / 2))
                {
                    return bad("the public half is hex");
                }
                if s.attestation_digest.is_empty() {
                    if s.key_type != "ed25519" {
                        return bad("a FIDO2 key is enrolled with its attestation");
                    }
                    Ok(())
                } else {
                    need_hex(&s.attestation_digest, 32, "the attestation's digest")
                }
            }
            Subject::WorkerKeys(w) => {
                if !id_ok(&w.orchestration_id) {
                    return bad("the orchestration id is letters, digits and . _ : - only");
                }
                sorted_names(&w.names)?;
                if w.names.is_empty() {
                    return bad("a worker template names at least one key");
                }
                if !matches!(w.environment.as_str(), "dev" | "development" | "staging") {
                    return bad("worker keys are development and staging only; a Production use on a worker is a secret-use");
                }
                if w.max_workers == 0
                    || w.max_workers > 1000
                    || w.ttl_s == 0
                    || w.ttl_s > 7 * 86_400
                {
                    return bad("the worker limits are out of range");
                }
                Ok(())
            }
            Subject::SetupCode(c) | Subject::KekExport(c) => {
                need_hex(&c.challenge, 16, "the challenge")
            }
        }
    }

    /// The canonical encoding: the version, the tag, the box id, the store id and the scope, then the scope's own fields.
    pub fn encode(&self, ids: &Ids) -> Result<Vec<u8>, SubjectError> {
        ids.validate()?;
        self.validate()?;
        let mut e = Encoder::new(SUBJECT_TAG);
        e.text(&ids.box_id).text(&ids.store_id).text(self.scope());
        match self {
            Subject::GuardOverride(GuardHook::Commit {
                repo_path_hash,
                hook_kind,
                tree_id,
                matches,
                scanned_text_hash,
            }) => {
                e.text("commit")
                    .text(repo_path_hash)
                    .text(hook_kind)
                    .text(tree_id);
                put_matches(&mut e, matches)?;
                e.text(scanned_text_hash);
            }
            Subject::GuardOverride(GuardHook::Push {
                repo_path_hash,
                remote_url,
                refs,
                matches,
                scanned_text_hash,
            }) => {
                e.text("push").text(repo_path_hash).text(remote_url);
                let mut r: Vec<&RefUpdate> = refs.iter().collect();
                r.sort();
                if r.windows(2).any(|w| w[0] == w[1]) {
                    return bad("a ref update is listed twice");
                }
                e.count(r.len());
                for u in r {
                    e.text(&u.ref_name).text(&u.old).text(&u.new);
                }
                put_matches(&mut e, matches)?;
                e.text(scanned_text_hash);
            }
            Subject::Import(i) => {
                e.text(&i.project).text(&i.environment).flag(i.production);
                let mut names: Vec<&ImportName> = i.names.iter().collect();
                names.sort();
                e.count(names.len());
                for n in names {
                    e.text(&n.name)
                        .text(match n.classification {
                            Classification::Public => "public",
                            Classification::Secret => "secret",
                        })
                        .text(&n.value_digest);
                }
                e.u64(i.store_generation);
            }
            Subject::Policy(p) => {
                e.text(&p.policy_sha256)
                    .text(&p.predecessor_sha256)
                    .text(p.sensitivity.word());
            }
            Subject::TunnelToken(t) => {
                e.text(&t.kind)
                    .text(&t.token_sha256)
                    .text(&t.account_tag)
                    .text(&t.tunnel_id);
            }
            Subject::BoxSecrets(b) => {
                e.text(&b.address)
                    .text(&b.action)
                    .text(&b.change_digest)
                    .flag(b.first_setting);
            }
            Subject::HostGuard(h) => {
                e.text(&h.action).flag(h.loosening).count(h.fields.len());
                for (k, v) in &h.fields {
                    e.text(k).text(v);
                }
            }
            Subject::SignerEnroll(s) => {
                e.text(match s.action {
                    EnrolAction::Enrol => "enrol",
                    EnrolAction::Revoke => "revoke",
                })
                .text(&s.key_name)
                .text(&s.key_type)
                .text(&s.public_half)
                .text(&s.attestation_digest);
            }
            Subject::WorkerKeys(w) => {
                e.text(&w.orchestration_id);
                let names = sorted_names(&w.names)?;
                e.count(names.len());
                for n in names {
                    e.text(n);
                }
                e.text(&w.environment).u64(w.max_workers).u64(w.ttl_s);
            }
            Subject::SetupCode(c) | Subject::KekExport(c) => {
                e.text(&c.challenge);
            }
        }
        Ok(e.bytes().to_vec())
    }

    /// The subject digest (SHA-256 of the encoding).
    pub fn digest(&self, ids: &Ids) -> Result<[u8; 32], SubjectError> {
        Ok(to32(digest(&SHA256, &self.encode(ids)?).as_ref()))
    }

    pub fn digest_hex(&self, ids: &Ids) -> Result<String, SubjectError> {
        Ok(to_hex(&self.digest(ids)?))
    }

    /// The operation key (ADR 0041 §4): what makes two requests the same slot. Per scope.
    pub fn operation_key(&self) -> String {
        match self {
            Subject::GuardOverride(GuardHook::Commit {
                repo_path_hash,
                hook_kind,
                ..
            }) => format!("commit:{repo_path_hash}:{hook_kind}"),
            Subject::GuardOverride(GuardHook::Push {
                repo_path_hash,
                remote_url,
                ..
            }) => format!("push:{repo_path_hash}:{}", sha256_hex(remote_url)),
            Subject::TunnelToken(t) => t.kind.clone(),
            Subject::Import(i) => format!("{}/{}", i.project, i.environment),
            Subject::Policy(_) | Subject::SetupCode(_) | Subject::KekExport(_) => "box".into(),
            Subject::BoxSecrets(b) => b.address.clone(),
            Subject::HostGuard(h) => h.action.clone(),
            Subject::SignerEnroll(s) => sha256_hex(&s.public_half),
            Subject::WorkerKeys(w) => w.orchestration_id.clone(),
        }
    }

    /// Whether the change is in the Production tier: the environment is not a known non-Production one, a key's name says
    /// production or live, or the filer said so (which only ever makes a rule stricter).
    pub fn production(&self) -> bool {
        match self {
            Subject::Import(i) => {
                i.production
                    || is_production_environment(&i.environment)
                    || i.names.iter().any(|n| name_says_production(&n.name))
            }
            // a worker template that delivers a key whose name says production is a Production use, whatever its environment
            Subject::WorkerKeys(w) => w.names.iter().any(|n| name_says_production(n)),
            _ => false,
        }
    }

    /// Where the service sees an import's values (its spend): refuses when a value says Production (a live-mode key prefix,
    /// a production address) and the filed subject does not. The filer's `production` flag can only make a rule stricter,
    /// so a laptop that left it off for such a value is wrong, and the import is refused, not decided.
    pub fn check_import_values<'a>(
        &self,
        values: impl IntoIterator<Item = (&'a str, &'a str)>,
    ) -> Result<(), SubjectError> {
        let Subject::Import(_) = self else {
            return Ok(());
        };
        if self.production() {
            return Ok(());
        }
        for (name, value) in values {
            if value_says_production(value) {
                return bad(&format!("{name} holds a Production-looking value, so this import is a Production change: file it as one"));
            }
        }
        Ok(())
    }

    /// Whether any imported key is marked public (an auto-mark is in the digest and needs the owner).
    pub fn any_public(&self) -> bool {
        matches!(self, Subject::Import(i) if i.names.iter().any(|n| n.classification == Classification::Public))
    }

    /// A guard match the service called a Production-looking value (never decided here; ADR 0029 releases those).
    pub fn production_looking(&self) -> bool {
        match self {
            Subject::GuardOverride(GuardHook::Commit { matches, .. })
            | Subject::GuardOverride(GuardHook::Push { matches, .. }) => {
                matches.iter().any(|m| m.rule == RULE_PRODUCTION_LOOKING)
            }
            _ => false,
        }
    }

    /// The fields that differ between two subjects of one request, by name (never a value). Empty when equal.
    pub fn differing_fields(&self, other: &Subject) -> Vec<&'static str> {
        if self == other {
            return Vec::new();
        }
        if self.scope() != other.scope() {
            return vec!["scope"];
        }
        let mut out = Vec::new();
        let mut d = |name: &'static str, same: bool| {
            if !same {
                out.push(name);
            }
        };
        match (self, other) {
            (Subject::GuardOverride(a), Subject::GuardOverride(b)) => match (a, b) {
                (
                    GuardHook::Commit {
                        repo_path_hash: ar,
                        hook_kind: ak,
                        tree_id: at,
                        matches: am,
                        scanned_text_hash: ah,
                    },
                    GuardHook::Commit {
                        repo_path_hash: br,
                        hook_kind: bk,
                        tree_id: bt,
                        matches: bm,
                        scanned_text_hash: bh,
                    },
                ) => {
                    d("repo", ar == br);
                    d("hook", ak == bk);
                    d("tree", at == bt);
                    d("matches", am == bm);
                    d("scanned text", ah == bh);
                }
                (
                    GuardHook::Push {
                        repo_path_hash: ar,
                        remote_url: au,
                        refs: af,
                        matches: am,
                        scanned_text_hash: ah,
                    },
                    GuardHook::Push {
                        repo_path_hash: br,
                        remote_url: bu,
                        refs: bf,
                        matches: bm,
                        scanned_text_hash: bh,
                    },
                ) => {
                    d("repo", ar == br);
                    d("remote", au == bu);
                    d("refs", af == bf);
                    d("matches", am == bm);
                    d("scanned text", ah == bh);
                }
                _ => d("hook", false),
            },
            (Subject::Import(a), Subject::Import(b)) => {
                d("project", a.project == b.project);
                d("environment", a.environment == b.environment);
                d("production", a.production == b.production);
                d("names", names_of(a) == names_of(b));
                d("marks", marks_of(a) == marks_of(b));
                d("values", values_of(a) == values_of(b));
                d("store generation", a.store_generation == b.store_generation);
            }
            (Subject::Policy(a), Subject::Policy(b)) => {
                d("policy", a.policy_sha256 == b.policy_sha256);
                d(
                    "replaced policy",
                    a.predecessor_sha256 == b.predecessor_sha256,
                );
                d("sensitivity", a.sensitivity == b.sensitivity);
            }
            (Subject::TunnelToken(a), Subject::TunnelToken(b)) => {
                d("kind", a.kind == b.kind);
                d("token", a.token_sha256 == b.token_sha256);
                d("account", a.account_tag == b.account_tag);
                d("tunnel", a.tunnel_id == b.tunnel_id);
            }
            (Subject::BoxSecrets(a), Subject::BoxSecrets(b)) => {
                d("address", a.address == b.address);
                d("action", a.action == b.action);
                d("change", a.change_digest == b.change_digest);
                d("first setting", a.first_setting == b.first_setting);
            }
            (Subject::HostGuard(a), Subject::HostGuard(b)) => {
                d("action", a.action == b.action);
                d("loosening", a.loosening == b.loosening);
                d("fields", a.fields == b.fields);
            }
            (Subject::SignerEnroll(a), Subject::SignerEnroll(b)) => {
                d("action", a.action == b.action);
                d("key name", a.key_name == b.key_name);
                d("key type", a.key_type == b.key_type);
                d("public key", a.public_half == b.public_half);
                d("attestation", a.attestation_digest == b.attestation_digest);
            }
            (Subject::WorkerKeys(a), Subject::WorkerKeys(b)) => {
                d("orchestration", a.orchestration_id == b.orchestration_id);
                d("names", a.names == b.names);
                d("environment", a.environment == b.environment);
                d("workers", a.max_workers == b.max_workers);
                d("time to live", a.ttl_s == b.ttl_s);
            }
            (Subject::SetupCode(a), Subject::SetupCode(b))
            | (Subject::KekExport(a), Subject::KekExport(b)) => {
                d("challenge", a.challenge == b.challenge);
            }
            _ => d("scope", false),
        }
        if out.is_empty() {
            // equal in every named field but not equal: a field order or a duplicate; say so without a value
            out.push("fields");
        }
        out
    }
}

fn names_of(i: &Import) -> Vec<&str> {
    let mut v: Vec<&str> = i.names.iter().map(|n| n.name.as_str()).collect();
    v.sort_unstable();
    v
}
fn marks_of(i: &Import) -> Vec<(&str, Classification)> {
    let mut v: Vec<_> = i
        .names
        .iter()
        .map(|n| (n.name.as_str(), n.classification))
        .collect();
    v.sort_unstable();
    v
}
fn values_of(i: &Import) -> Vec<(&str, &str)> {
    let mut v: Vec<_> = i
        .names
        .iter()
        .map(|n| (n.name.as_str(), n.value_digest.as_str()))
        .collect();
    v.sort_unstable();
    v
}

fn put_matches(e: &mut Encoder, m: &[GuardMatch]) -> Result<(), SubjectError> {
    let v = matches_ok(m)?;
    e.count(v.len());
    for g in v {
        e.text(&g.path).u64(g.line).text(&g.rule).text(&g.key_id);
    }
    Ok(())
}

fn to32(b: &[u8]) -> [u8; 32] {
    let mut out = [0u8; 32];
    out.copy_from_slice(b);
    out
}

/// The outcomes a decision can have, as the words the challenge names. A challenge made for one cannot decide another.
pub const DECIDE_OUTCOMES: &[&str] = &["approve", "deny", "revoke"];

/// The challenge a dashboard assertion is made over (ADR 0041 §3), built by the service, never chosen by the dashboard:
/// `H("ozbox-approval-decide-v1", box id, store id, request id, subject digest, outcome)`. The outcome is a field, so an
/// assertion made to deny or revoke a request is not also an assertion that approves it.
pub fn decide_challenge(
    ids: &Ids,
    request_id: &str,
    subject_digest: &[u8; 32],
    outcome: &str,
) -> [u8; 32] {
    digest_fields(
        DECIDE_TAG,
        &[
            ids.box_id.as_bytes(),
            ids.store_id.as_bytes(),
            request_id.as_bytes(),
            subject_digest,
            outcome.as_bytes(),
        ],
    )
}

/// The first line of the text a laptop key signs to decide a request (distinct from the challenge message of the signer
/// path, which starts `ozbox-approval` and a newline).
pub const DECIDE_MESSAGE_HEAD: &str = "ozbox-approval-decide";

/// The text a laptop key signs (Ed25519 over it; `sk` keys over its SHA-256): the head, a newline and the hex of
/// [`decide_challenge`], so it names the box, the store, the request, the digest and the outcome.
pub fn decide_message(
    ids: &Ids,
    request_id: &str,
    subject_digest: &[u8; 32],
    outcome: &str,
) -> String {
    format!(
        "{DECIDE_MESSAGE_HEAD}\n{}",
        to_hex(&decide_challenge(ids, request_id, subject_digest, outcome))
    )
}

/// The challenge a laptop key's enrolment attestation is bound to (ADR 0041 §3, `ssh-keygen -O challenge=`).
pub fn key_enrol_challenge(ids: &Ids, request_id: &str, subject_digest: &[u8; 32]) -> [u8; 32] {
    digest_fields(
        KEY_ENROL_TAG,
        &[
            ids.box_id.as_bytes(),
            ids.store_id.as_bytes(),
            request_id.as_bytes(),
            subject_digest,
        ],
    )
}

/// What a card shows for one derived field, and where the words came from (ADR 0041 §4, "Rendering").
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DisplayField {
    pub label: String,
    pub value: String,
    /// `service`, `root-helper` or `from the box`.
    pub source: String,
}

/// Strip what could spoof a card: control characters and direction overrides go; the length is capped.
pub fn sanitize_display(s: &str, max: usize) -> String {
    let cleaned: String = s
        .chars()
        .filter(|c| !c.is_control() && !is_invisible_or_bidi(*c))
        .collect();
    if cleaned.chars().count() <= max {
        cleaned
    } else {
        let mut t: String = cleaned.chars().take(max.saturating_sub(1)).collect();
        t.push('…');
        t
    }
}

/// How many rows of a list a card shows; the rest are counted, never hidden.
pub const CARD_ROWS: usize = 20;
/// How many key names an import card shows.
pub const CARD_NAMES: usize = 50;

/// A string cut to `max` characters in the middle, so the start and the end both stay.
pub fn cut_middle(s: &str, max: usize) -> String {
    let n = s.chars().count();
    if n <= max || max < 3 {
        return s.to_string();
    }
    let head = (max - 1) / 2;
    let tail = max - 1 - head;
    let mut out: String = s.chars().take(head).collect();
    out.push('…');
    out.extend(s.chars().skip(n - tail));
    out
}

/// A guard match list in the card's order: Production-looking first, then a stored value, then the rest; each by path and
/// line. Deterministic, so the same filing always reads the same.
fn card_matches(m: &[GuardMatch]) -> Vec<&GuardMatch> {
    let mut v: Vec<&GuardMatch> = m.iter().collect();
    v.sort_by_key(|g| {
        (
            g.rule != RULE_PRODUCTION_LOOKING,
            g.key_id.is_empty(),
            g.path.clone(),
            g.line,
            g.rule.clone(),
        )
    });
    v
}

impl Subject {
    /// Whether the card for this scope is derived by the service, or by the root helper.
    fn card_source(&self) -> &'static str {
        match self {
            Subject::TunnelToken(_) | Subject::BoxSecrets(_) | Subject::HostGuard(_) => {
                "root-helper"
            }
            _ => "service",
        }
    }

    /// The card's fields, derived from the subject (so what a person reads is what is hashed), each labelled with its
    /// source. Never a value: names, places, counts and digests' first 16 hex digits only.
    pub fn display(&self) -> Vec<DisplayField> {
        let src = self.card_source().to_string();
        let f = |l: &str, v: String| DisplayField {
            label: l.to_string(),
            // a long path or URL is cut in the middle, so its tail (the part that says what it is) stays
            value: cut_middle(&sanitize_display(&v, usize::MAX), 200),
            source: src.clone(),
        };
        // a list on a card: the most sensitive first in a fixed order, and what is left out is said, with the true total
        let more = |label: &str, total: usize, shown: usize| -> Option<DisplayField> {
            (total > shown).then(|| {
                f(
                    "Not shown",
                    format!(
                        "{} more {label} are bound by the digest but not listed here",
                        total - shown
                    ),
                )
            })
        };
        let short = |h: &str| h.chars().take(16).collect::<String>();
        match self {
            Subject::GuardOverride(GuardHook::Commit {
                hook_kind,
                tree_id,
                matches,
                ..
            }) => {
                let mut v = vec![
                    f(
                        "Change",
                        format!("commit ({hook_kind}), tree {}", short(tree_id)),
                    ),
                    f("Matches", format!("{}", matches.len())),
                ];
                v.extend(
                    card_matches(matches)
                        .into_iter()
                        .take(CARD_ROWS)
                        .map(|m| f("Match", format!("{}:{} ({})", m.path, m.line, m.rule))),
                );
                v.extend(more("matches", matches.len(), CARD_ROWS));
                v
            }
            Subject::GuardOverride(GuardHook::Push {
                remote_url,
                refs,
                matches,
                ..
            }) => {
                let mut v = vec![
                    f("Change", "push".into()),
                    f("Remote", remote_url.clone()),
                    f("Matches", format!("{}", matches.len())),
                    f("Refs", format!("{}", refs.len())),
                ];
                v.extend(
                    card_matches(matches)
                        .into_iter()
                        .take(CARD_ROWS)
                        .map(|m| f("Match", format!("{}:{} ({})", m.path, m.line, m.rule))),
                );
                v.extend(more("matches", matches.len(), CARD_ROWS));
                let mut sorted: Vec<&RefUpdate> = refs.iter().collect();
                sorted.sort();
                v.extend(sorted.iter().take(CARD_ROWS).map(|r| {
                    f(
                        "Ref",
                        format!("{} {}..{}", r.ref_name, short(&r.old), short(&r.new)),
                    )
                }));
                v.extend(more("refs", refs.len(), CARD_ROWS));
                v
            }
            Subject::Import(i) => {
                let mut v = vec![
                    f("Change", format!("import {} keys", i.names.len())),
                    f("Project", i.project.clone()),
                    f("Environment", i.environment.clone()),
                ];
                let mut names: Vec<&ImportName> = i.names.iter().collect();
                // marked public first, then a name that says production, then the rest by name
                names.sort_by_key(|n| {
                    (
                        n.classification != Classification::Public,
                        !name_says_production(&n.name),
                        n.name.clone(),
                    )
                });
                v.extend(names.iter().take(CARD_NAMES).map(|n| {
                    f(
                        "Key",
                        format!(
                            "{} ({})",
                            n.name,
                            match n.classification {
                                Classification::Public => "public",
                                Classification::Secret => "secret",
                            }
                        ),
                    )
                }));
                v.extend(more("keys", i.names.len(), CARD_NAMES));
                v
            }
            Subject::Policy(p) => vec![
                f("Change", "policy".into()),
                f("New policy", short(&p.policy_sha256)),
                f("Replaces", short(&p.predecessor_sha256)),
                f("Effect", p.sensitivity.word().into()),
            ],
            Subject::TunnelToken(t) => vec![
                f("Change", format!("tunnel token ({})", t.kind)),
                f("Account", t.account_tag.clone()),
                f("Tunnel", t.tunnel_id.clone()),
                f("Token", short(&t.token_sha256)),
            ],
            Subject::BoxSecrets(b) => vec![
                f("Change", format!("box secrets: {}", b.action)),
                f("Address", b.address.clone()),
            ],
            Subject::HostGuard(h) => {
                let mut v = vec![f("Change", format!("host guard: {} (loosening)", h.action))];
                v.extend(h.fields.iter().map(|(k, val)| f(k, val.clone())));
                v
            }
            Subject::SignerEnroll(s) => vec![
                f(
                    "Change",
                    match s.action {
                        EnrolAction::Enrol => "enrol a laptop key".into(),
                        EnrolAction::Revoke => "revoke a laptop key".into(),
                    },
                ),
                f("Key", format!("{} ({})", s.key_name, s.key_type)),
                f("Public key", short(&s.public_half)),
            ],
            Subject::WorkerKeys(w) => vec![
                f("Change", format!("worker keys for {}", w.orchestration_id)),
                f("Keys", format!("{}", w.names.len())),
                f("Environment", w.environment.clone()),
                f("Workers", format!("{} for {} s", w.max_workers, w.ttl_s)),
            ],
            Subject::SetupCode(_) => {
                vec![f("Change", "show the dashboard's first-time code".into())]
            }
            Subject::KekExport(_) => vec![f(
                "Change",
                "export the box's key-encryption key (opens every value on the box)".into(),
            )],
        }
    }
}

/// How an approved request is named where a gated change used to carry an approval code (the root helper's request line,
/// the dashboard installer's settings): `req-` and the request's id. Letters, digits and dashes only, so it passes every place
/// a code passes, and never the shape of a code (ADR 0041, amendment of 2026-11-17 for B4-27).
pub const REQUEST_WORD_PREFIX: &str = "req-";

/// The word for an approved request, `req-<id>`.
pub fn request_word(id: &str) -> String {
    format!("{REQUEST_WORD_PREFIX}{id}")
}

/// The request id a `req-<id>` word names, or `None` when it is not such a word.
pub fn request_word_id(word: &str) -> Option<&str> {
    word.trim()
        .strip_prefix(REQUEST_WORD_PREFIX)
        .filter(|id| crate::approval::request_id_ok(id))
}

/// The full digest of a tunnel token as the box binds a request to it: `sha256(token)` of the trimmed token, in hex. Its
/// first 32 digits are the code path's binding (`tunnel_token_binding`).
pub fn tunnel_token_sha256(token: &str) -> String {
    sha256_hex(token.trim())
}

/// The subject of a change the root helper checks at its gate (`ozbox secrets gate`), from what the gate sees: the scope, the
/// project word, the binding it compares (`env`) and, for a tunnel token, the token's full digest. One function, so the
/// computer that files the request and the box that spends it compute the same subject.
///
/// * `tunnel-token`: the token's kind and digest. The binding, when there is one, must be the digest's first 32 digits. The
///   identity is left empty (nothing decodes it on both sides yet).
/// * `box-secrets`: the declaration (`project` is `declaration` or `bao-token`), a `set` bound to the binding, or a `remove`
///   for a declaration with no binding.
pub fn gate_subject(
    scope: &str,
    project: &str,
    env: &str,
    token_sha256: &str,
) -> Result<Subject, SubjectError> {
    let subject = match scope {
        "tunnel-token" => {
            if token_sha256.is_empty() {
                return bad(
                    "a tunnel-token change by request is bound to the token, and none was sent",
                );
            }
            if !env.is_empty() && !token_sha256.starts_with(env) {
                return bad("the binding is not the token's");
            }
            Subject::TunnelToken(TunnelToken {
                kind: project.to_string(),
                token_sha256: token_sha256.to_string(),
                account_tag: String::new(),
                tunnel_id: String::new(),
            })
        }
        "box-secrets" => {
            let remove = project == "declaration" && env.is_empty();
            Subject::BoxSecrets(BoxSecrets {
                address: project.to_string(),
                action: if remove { "remove" } else { "set" }.to_string(),
                change_digest: if remove {
                    String::new()
                } else {
                    to_hex(&digest_fields(
                        "ozbox-gate-box-secrets-v1",
                        &[project.as_bytes(), env.as_bytes()],
                    ))
                },
                first_setting: false,
            })
        }
        _ => return bad("this change is not approved by request at the root helper's gate"),
    };
    subject.validate()?;
    Ok(subject)
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    fn ids() -> Ids {
        Ids {
            box_id: "box-1".into(),
            store_id: "store-1".into(),
        }
    }
    fn h(c: char) -> String {
        std::iter::repeat_n(c, 64).collect()
    }
    fn import(names: &[(&str, Classification)]) -> Subject {
        Subject::Import(Import {
            project: "app".into(),
            environment: "staging".into(),
            production: false,
            names: names
                .iter()
                .map(|(n, c)| ImportName {
                    name: (*n).into(),
                    classification: *c,
                    value_digest: h('a'),
                })
                .collect(),
            store_generation: 3,
        })
    }

    const GOLDEN: &str = include_str!("../testdata/approval_subject_golden.json");

    /// The committed vectors, computed by `testdata/approval_subject_golden.py`, which implements the encoding from the
    /// ADR's text and shares no code with this crate. The laptop crate must produce every one.
    #[test]
    fn golden_vectors_from_the_committed_file() {
        let g: serde_json::Value = serde_json::from_str(GOLDEN).unwrap();
        let mut last: Option<String> = None;
        let vectors = g["vectors"].as_array().unwrap();
        assert!(vectors.len() >= 30);
        let mut scopes = std::collections::BTreeSet::new();
        for v in vectors {
            let name = v["name"].as_str().unwrap();
            let ids = Ids {
                box_id: v["box_id"].as_str().unwrap().into(),
                store_id: v["store_id"].as_str().unwrap().into(),
            };
            let s: Subject = serde_json::from_value(v["subject"].clone()).unwrap();
            let got = s.digest_hex(&ids).unwrap_or_else(|e| panic!("{name}: {e}"));
            assert_eq!(got, v["digest"].as_str().unwrap(), "{name}");
            scopes.insert(s.scope());
            // a vector that says it is the same digest as the one before it is
            if name.contains("(the same digest)") {
                assert_eq!(Some(got.clone()), last, "{name}");
            }
            last = Some(got);
        }
        // every scope of the journal has at least one vector
        for scope in [
            "guard-override",
            "import",
            "policy",
            "tunnel-token",
            "box-secrets",
            "host-guard",
            "signer-enroll",
            "worker-keys",
            "setup-code",
            "kek-export",
        ] {
            assert!(scopes.contains(scope), "no vector for {scope}");
        }
        // the adversarial pairs are all distinct digests
        let by = |n: &str| {
            vectors.iter().find(|v| v["name"] == n).unwrap()["digest"]
                .as_str()
                .unwrap()
                .to_string()
        };
        let moved = by("tunnel-token: a field moved across a boundary (account ab, tunnel c)");
        let other = by("tunnel-token: the same characters the other way (account a, tunnel bc)");
        assert_ne!(moved, other);
        assert_ne!(
            by("tunnel-token: empty account tag"),
            by("tunnel-token: empty tunnel id")
        );
        assert_ne!(
            by("guard-override push"),
            by("guard-override push: a lookalike letter in the url (Cyrillic a)")
        );
        // subjects the encoder refuses before it makes any digest
        let refused = g["refused"].as_array().unwrap();
        assert!(refused.len() >= 8);
        for v in refused {
            let name = v["name"].as_str().unwrap();
            let ids = ids();
            let s: Subject = serde_json::from_value(v["subject"].clone()).unwrap();
            assert!(s.digest(&ids).is_err(), "{name} must be refused");
        }
        // the challenges and the envelope message, each under its own tag
        for c in g["challenges"].as_array().unwrap() {
            let d: [u8; 32] = from_hex(c["digest_hex"].as_str().unwrap())
                .unwrap()
                .try_into()
                .unwrap();
            let name = c["name"].as_str().unwrap();
            let got = match c["kind"].as_str().unwrap() {
                "decide" => {
                    let o = c["outcome"].as_str().unwrap();
                    assert!(DECIDE_OUTCOMES.contains(&o));
                    assert_eq!(
                        decide_message(&ids(), "REQ1", &d, o),
                        c["message"].as_str().unwrap(),
                        "{name}: the text a laptop key signs"
                    );
                    decide_challenge(&ids(), c["request_id"].as_str().unwrap(), &d, o)
                }
                "key-enrol" => key_enrol_challenge(&ids(), c["request_id"].as_str().unwrap(), &d),
                k => panic!("{k}"),
            };
            assert_eq!(to_hex(&got), c["expect"].as_str().unwrap(), "{name}");
        }
        // the envelope: the committed text parses, writes back to the same bytes, names its box and store, and its digest
        // is the subject's; the message the signature is over is the one the independent script computed
        let canonical = g["envelope"]["canonical"].as_str().unwrap();
        assert_eq!(
            crate::approval::SignedEnvelope::signed_message(canonical),
            g["envelope"]["message"].as_str().unwrap()
        );
        let env: crate::approval::Envelope = serde_json::from_str(canonical).unwrap();
        assert_eq!(
            crate::approval::SignedEnvelope::canonical_of(&env).unwrap(),
            canonical
        );
        assert_eq!(
            (env.box_id.as_str(), env.store_id.as_str()),
            ("box-1", "store-1")
        );
        assert_eq!(env.subject.digest_hex(&ids()).unwrap(), env.subject_digest);
    }

    #[test]
    fn the_encoding_of_a_challenge_scope_is_exactly_the_documented_bytes() {
        let s = Subject::SetupCode(Challenge {
            challenge: "00112233445566778899aabbccddeeff".into(),
        });
        let enc = s.encode(&ids()).unwrap();
        let mut want = vec![1u8];
        for f in [
            "ozbox-approval-subject-v1",
            "box-1",
            "store-1",
            "setup-code",
            "00112233445566778899aabbccddeeff",
        ] {
            want.extend_from_slice(&(f.len() as u32).to_be_bytes());
            want.extend_from_slice(f.as_bytes());
        }
        assert_eq!(enc, want);
    }

    #[test]
    fn a_digest_is_for_one_box_one_store_and_one_scope() {
        let a = import(&[("A", Classification::Secret)]);
        let d = a.digest_hex(&ids()).unwrap();
        let other_box = Ids {
            box_id: "box-2".into(),
            ..ids()
        };
        let other_store = Ids {
            store_id: "store-2".into(),
            ..ids()
        };
        assert_ne!(d, a.digest_hex(&other_box).unwrap());
        assert_ne!(d, a.digest_hex(&other_store).unwrap());
        // the same challenge under two scopes is two digests
        let c = Challenge {
            challenge: "00112233445566778899aabbccddeeff".into(),
        };
        assert_ne!(
            Subject::SetupCode(c.clone()).digest_hex(&ids()).unwrap(),
            Subject::KekExport(c).digest_hex(&ids()).unwrap()
        );
    }

    #[test]
    fn a_set_is_sorted_so_the_order_a_filer_lists_it_in_changes_nothing() {
        let a = import(&[("B", Classification::Secret), ("A", Classification::Secret)]);
        let b = import(&[("A", Classification::Secret), ("B", Classification::Secret)]);
        assert_eq!(a.digest_hex(&ids()).unwrap(), b.digest_hex(&ids()).unwrap());
    }

    #[test]
    fn a_duplicate_name_is_refused_not_collapsed() {
        let a = import(&[("A", Classification::Secret), ("A", Classification::Public)]);
        assert!(a.digest(&ids()).is_err());
    }

    #[test]
    fn a_field_moved_across_a_boundary_is_a_different_digest() {
        // "ab"+"c" and "a"+"bc" differ because each field carries its length
        let x = digest_fields("t", &[b"ab", b"c"]);
        let y = digest_fields("t", &[b"a", b"bc"]);
        assert_ne!(x, y);
        // an empty field is not the same as no field
        assert_ne!(
            digest_fields("t", &[b"a", b""]),
            digest_fields("t", &[b"a"])
        );
        assert_ne!(
            digest_fields("t", &[b"", b"a"]),
            digest_fields("t", &[b"a", b""])
        );
        // an embedded separator does not split a field
        assert_ne!(
            digest_fields("t", &[b"a\nb"]),
            digest_fields("t", &[b"a", b"b"])
        );
        // another tag is another digest
        assert_ne!(digest_fields("t", &[b"a"]), digest_fields("u", &[b"a"]));
    }

    #[test]
    fn a_lookalike_letter_in_a_name_is_refused() {
        // CYRILLIC SMALL LETTER A is not ASCII
        let a = import(&[("\u{430}pp", Classification::Secret)]);
        assert!(a.digest(&ids()).is_err());
        assert!(!name_ok("A B"));
        assert!(!name_ok("A-B"));
        assert!(!name_ok(""));
    }

    #[test]
    fn text_with_control_or_direction_characters_is_refused_and_display_strips_them() {
        assert!(!text_ok("a\nb"));
        assert!(!text_ok("a\u{202e}b"));
        assert!(!text_ok(""));
        assert_eq!(sanitize_display("a\u{202e}b\u{0}c\u{200b}", 10), "abc");
        assert_eq!(sanitize_display("abcdefghij", 5), "abcd…");
    }

    #[test]
    fn the_classification_is_in_the_digest_so_an_auto_public_mark_cannot_slip_in() {
        let secret = import(&[("A", Classification::Secret)]);
        let public = import(&[("A", Classification::Public)]);
        assert_ne!(
            secret.digest_hex(&ids()).unwrap(),
            public.digest_hex(&ids()).unwrap()
        );
        assert_eq!(secret.differing_fields(&public), vec!["marks"]);
    }

    #[test]
    fn a_store_generation_is_in_the_digest_so_an_old_import_cannot_be_replayed() {
        let a = import(&[("A", Classification::Secret)]);
        let mut b = a.clone();
        if let Subject::Import(i) = &mut b {
            i.store_generation = 4;
        }
        assert_ne!(a.digest_hex(&ids()).unwrap(), b.digest_hex(&ids()).unwrap());
        assert_eq!(a.differing_fields(&b), vec!["store generation"]);
    }

    #[test]
    fn push_and_commit_overrides_never_collide_and_bind_the_url_not_a_remote_name() {
        let commit = Subject::GuardOverride(GuardHook::Commit {
            repo_path_hash: h('1'),
            hook_kind: "pre-commit".into(),
            tree_id: "a".repeat(40),
            matches: vec![],
            scanned_text_hash: h('2'),
        });
        let push = |url: &str| {
            Subject::GuardOverride(GuardHook::Push {
                repo_path_hash: h('1'),
                remote_url: url.into(),
                refs: vec![RefUpdate {
                    ref_name: "refs/heads/main".into(),
                    old: "a".repeat(40),
                    new: "b".repeat(40),
                }],
                matches: vec![],
                scanned_text_hash: h('2'),
            })
        };
        assert_ne!(
            commit.digest_hex(&ids()).unwrap(),
            push("https://example.test/r.git")
                .digest_hex(&ids())
                .unwrap()
        );
        assert_ne!(
            push("https://example.test/r.git")
                .digest_hex(&ids())
                .unwrap(),
            push("https://evil.test/r.git").digest_hex(&ids()).unwrap()
        );
        // two slots for two remotes
        assert_ne!(
            push("https://example.test/r.git").operation_key(),
            push("https://evil.test/r.git").operation_key()
        );
        assert_eq!(
            commit.operation_key(),
            format!("commit:{}:pre-commit", h('1'))
        );
    }

    #[test]
    fn the_match_list_is_in_the_digest_and_a_lying_path_changes_it() {
        let mk = |path: &str| {
            Subject::GuardOverride(GuardHook::Commit {
                repo_path_hash: h('1'),
                hook_kind: "pre-commit".into(),
                tree_id: "a".repeat(40),
                matches: vec![GuardMatch {
                    path: path.into(),
                    line: 3,
                    rule: "stored-value".into(),
                    key_id: "k1".into(),
                }],
                scanned_text_hash: h('2'),
            })
        };
        let a = mk("src/a.rs");
        let b = mk("src/b.rs");
        assert_ne!(a.digest_hex(&ids()).unwrap(), b.digest_hex(&ids()).unwrap());
        assert_eq!(a.differing_fields(&b), vec!["matches"]);
        assert!(!a.production_looking());
    }

    #[test]
    fn only_a_known_non_production_environment_is_not_production_and_a_name_can_say_production() {
        for e in ["dev", "development", "staging", "test", "e2e"] {
            assert!(!is_production_environment(e), "{e}");
        }
        // production, prod and live are what the box's workload rule already calls production; an unknown name is too
        for e in [
            "production",
            "prod",
            "live",
            "qa",
            "preview",
            "prod-eu",
            "products",
        ] {
            assert!(is_production_environment(e), "{e}");
        }
        let mut s = import(&[("A", Classification::Secret)]);
        assert!(!s.production());
        if let Subject::Import(i) = &mut s {
            i.production = true;
        }
        assert!(s.production());
        // a key whose name says production or live is in the Production tier whatever the environment is called
        assert!(import(&[("STRIPE_LIVE_KEY", Classification::Secret)]).production());
        assert!(import(&[("PROD_DB", Classification::Secret)]).production());
        assert!(!import(&[("API_KEY", Classification::Secret)]).production());
        assert!(name_says_production("live_token"));
    }

    #[test]
    fn worker_keys_refuse_a_production_environment_and_tightening_a_host_guard_is_not_filed() {
        let w = |env: &str| {
            Subject::WorkerKeys(WorkerKeys {
                orchestration_id: "orch-1".into(),
                names: vec!["B".into(), "A".into()],
                environment: env.into(),
                max_workers: 4,
                ttl_s: 3600,
            })
        };
        assert!(w("staging").validate().is_ok());
        assert!(w("production").validate().is_err());
        assert!(w("qa").validate().is_err());
        let hg = |loose: bool| {
            Subject::HostGuard(HostGuard {
                action: "open-port".into(),
                loosening: loose,
                fields: vec![("port".into(), "8080".into())],
            })
        };
        assert!(hg(true).validate().is_ok());
        assert!(hg(false).validate().is_err());
    }

    #[test]
    fn the_decide_challenge_names_the_box_the_store_the_request_and_the_digest() {
        let d = [7u8; 32];
        let base = decide_challenge(&ids(), "REQ1", &d, "approve");
        assert_ne!(base, decide_challenge(&ids(), "REQ2", &d, "approve"));
        assert_ne!(
            base,
            decide_challenge(&ids(), "REQ1", &[8u8; 32], "approve")
        );
        // and the outcome: an assertion made to deny or revoke is not one that approves
        assert_ne!(base, decide_challenge(&ids(), "REQ1", &d, "deny"));
        assert_ne!(base, decide_challenge(&ids(), "REQ1", &d, "revoke"));
        assert_ne!(
            decide_challenge(&ids(), "REQ1", &d, "deny"),
            decide_challenge(&ids(), "REQ1", &d, "revoke")
        );
        assert_ne!(
            base,
            decide_challenge(
                &Ids {
                    box_id: "other".into(),
                    ..ids()
                },
                "REQ1",
                &d,
                "approve"
            )
        );
        // a distinct tag: the enrolment challenge over the same fields is another value
        assert_ne!(base, key_enrol_challenge(&ids(), "REQ1", &d));
    }

    #[test]
    fn a_card_is_derived_from_the_subject_and_carries_no_value() {
        let s = import(&[("API_KEY", Classification::Secret)]);
        let card = s.display();
        let text = format!("{card:?}");
        assert!(text.contains("API_KEY"));
        assert!(!text.contains(&h('a')), "a full value digest is not shown");
        assert!(card.iter().all(|f| f.source == "service"));
        let t = Subject::TunnelToken(TunnelToken {
            kind: "ide".into(),
            token_sha256: h('c'),
            account_tag: "acct1".into(),
            tunnel_id: "tun1".into(),
        });
        assert!(t.display().iter().all(|f| f.source == "root-helper"));
    }

    #[test]
    fn the_wire_form_round_trips_and_an_unknown_scope_is_refused() {
        let s = import(&[("A", Classification::Secret)]);
        let j = serde_json::to_string(&s).unwrap();
        assert!(j.contains("\"scope\":\"import\""));
        let back: Subject = serde_json::from_str(&j).unwrap();
        assert_eq!(s, back);
        let g = Subject::GuardOverride(GuardHook::Commit {
            repo_path_hash: h('1'),
            hook_kind: "pre-commit".into(),
            tree_id: "a".repeat(40),
            matches: vec![],
            scanned_text_hash: h('2'),
        });
        let j = serde_json::to_string(&g).unwrap();
        assert!(j.contains("\"scope\":\"guard-override\"") && j.contains("\"hook\":\"commit\""));
        assert_eq!(serde_json::from_str::<Subject>(&j).unwrap(), g);
        assert!(serde_json::from_str::<Subject>("{\"scope\":\"secret-use\"}").is_err());
        assert!(serde_json::from_str::<Subject>("{\"scope\":\"made-up\"}").is_err());
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod review_tests {
    use super::*;

    fn ids() -> Ids {
        Ids {
            box_id: "box-1".into(),
            store_id: "store-1".into(),
        }
    }
    fn m(path: &str, line: u64, rule: &str, key: &str) -> GuardMatch {
        GuardMatch {
            path: path.into(),
            line,
            rule: rule.into(),
            key_id: key.into(),
        }
    }
    fn commit(matches: Vec<GuardMatch>) -> Subject {
        Subject::GuardOverride(GuardHook::Commit {
            repo_path_hash: "1".repeat(64),
            hook_kind: "pre-commit".into(),
            tree_id: "a".repeat(40),
            matches,
            scanned_text_hash: "2".repeat(64),
        })
    }

    /// a filer lists twenty harmless matches first and the real one 21st; the card must not hide it.
    #[test]
    fn the_twenty_first_match_is_on_the_card_or_the_card_says_it_is_not_shown() {
        let mut ms: Vec<GuardMatch> = (1..=20)
            .map(|i| m("README.md", i, "stored-value", "k1"))
            .collect();
        ms.push(m("deploy/prod.env", 1, RULE_PRODUCTION_LOOKING, "k9"));
        let card = commit(ms.clone()).display();
        let text: String = card
            .iter()
            .map(|f| format!("{}={}\n", f.label, f.value))
            .collect();
        // the most sensitive entry is listed first, whatever order it was filed in
        let first = card.iter().find(|f| f.label == "Match").unwrap();
        assert!(first.value.contains("deploy/prod.env"), "{text}");
        // and what is left out is counted, with the true total
        assert!(text.contains("Matches=21"), "{text}");
        assert!(text.contains("Not shown=1 more matches"), "{text}");
        // the same filing in another order reads the same
        ms.reverse();
        assert_eq!(card, commit(ms).display());
        // 20 or fewer: nothing is left out, so nothing is said
        let few: Vec<GuardMatch> = (1..=20)
            .map(|i| m("a.rs", i, "stored-value", "k1"))
            .collect();
        assert!(commit(few).display().iter().all(|f| f.label != "Not shown"));
    }

    #[test]
    fn the_fifty_first_import_name_is_counted_and_a_risky_one_comes_first() {
        let names: Vec<ImportName> = (0..60)
            .map(|i| ImportName {
                name: if i == 59 {
                    "STRIPE_LIVE_KEY".into()
                } else {
                    format!("K{i:02}")
                },
                classification: Classification::Secret,
                value_digest: "a".repeat(64),
            })
            .collect();
        let s = Subject::Import(Import {
            project: "app".into(),
            environment: "staging".into(),
            production: false,
            names,
            store_generation: 1,
        });
        let card = s.display();
        let keys: Vec<&DisplayField> = card.iter().filter(|f| f.label == "Key").collect();
        assert_eq!(keys.len(), CARD_NAMES);
        assert!(
            keys[0].value.starts_with("STRIPE_LIVE_KEY"),
            "the name that says production is first"
        );
        assert!(card
            .iter()
            .any(|f| f.label == "Not shown" && f.value.starts_with("10 more keys")));
    }

    #[test]
    fn a_long_path_is_cut_in_the_middle_so_its_tail_stays() {
        let long = format!("{}/credentials.json", "d".repeat(400));
        let card = commit(vec![m(&long, 1, "stored-value", "k1")]).display();
        let v = &card.iter().find(|f| f.label == "Match").unwrap().value;
        assert!(
            v.chars().count() <= 200 && v.contains('…') && v.contains("credentials.json"),
            "{v}"
        );
        assert_eq!(cut_middle("short", 200), "short");
    }

    /// U+061C and the line separators are refused in a field and stripped from a card.
    #[test]
    fn the_arabic_letter_mark_and_the_line_separators_are_refused_and_stripped() {
        for c in [
            '\u{061c}',
            '\u{2028}',
            '\u{2029}',
            '\u{2060}',
            '\u{00ad}',
            '\u{e0041}',
            '\u{200b}',
            '\u{202e}',
            '\u{2066}',
        ] {
            let t = format!("a{c}b");
            assert!(!text_ok(&t), "{c:?} refused in a field");
            assert_eq!(sanitize_display(&t, 50), "ab", "{c:?} stripped from a card");
        }
        assert!(
            text_ok("src/ünïcode.rs"),
            "ordinary non-ASCII text is still fine"
        );
    }

    /// a worker key whose NAME says production is Production, and a value's live prefixes are the box's own.
    #[test]
    fn production_covers_worker_key_names_and_the_boxs_live_value_prefixes() {
        let wk = |n: &str| {
            Subject::WorkerKeys(WorkerKeys {
                orchestration_id: "orch-1".into(),
                names: vec![n.into()],
                environment: "staging".into(),
                max_workers: 4,
                ttl_s: 3600,
            })
        };
        assert!(wk("STRIPE_LIVE_KEY").production());
        assert!(wk("PROD_DB").production());
        assert!(!wk("STAGING_DB").production());
        for v in [
            "sk_live_abc",
            "pk_live_abc",
            "rk_live_x",
            "whsec_live_x",
            "live_abc",
            "https://db.prod.example.com/x",
        ] {
            assert!(value_says_production(v), "{v}");
        }
        assert!(!value_says_production("sk_test_abc") && !value_says_production("hello"));
        // an import of a live-looking value into staging whose filer did not say so is refused where the values are seen
        let imp = Subject::Import(Import {
            project: "app".into(),
            environment: "staging".into(),
            production: false,
            names: vec![ImportName {
                name: "STRIPE_KEY".into(),
                classification: Classification::Secret,
                value_digest: "a".repeat(64),
            }],
            store_generation: 1,
        });
        assert!(!imp.production(), "a digest says nothing about the value");
        assert!(imp
            .check_import_values([("STRIPE_KEY", concat!("sk_", "live_abc123"))])
            .unwrap_err()
            .0
            .contains("Production-looking"));
        assert!(imp
            .check_import_values([("STRIPE_KEY", "sk_test_abc123")])
            .is_ok());
        // when the filer already said Production there is nothing to refuse
        let mut p = imp.clone();
        if let Subject::Import(i) = &mut p {
            i.production = true;
        }
        assert!(p
            .check_import_values([("STRIPE_KEY", concat!("sk_", "live_abc123"))])
            .is_ok());
    }

    #[test]
    fn a_decide_message_starts_with_its_own_head_and_never_the_signer_paths() {
        let d = [7u8; 32];
        let msg = decide_message(&ids(), "REQ1", &d, "approve");
        assert!(msg.starts_with("ozbox-approval-decide\n"));
        assert!(
            !msg.starts_with("ozbox-approval\n"),
            "a challenge signature cannot be replayed as a decision"
        );
        assert_ne!(msg, decide_message(&ids(), "REQ1", &d, "deny"));
    }

    #[test]
    fn a_gate_subject_is_the_same_on_both_sides_and_bound_to_what_the_gate_sees() {
        let tok = "token-a-aaaaaaaaaaaaaaaaaaaa";
        let full = tunnel_token_sha256(tok);
        assert_eq!(full, tunnel_token_sha256(&format!(" {tok}\n")));
        let bind = &full[..32];
        let a = gate_subject("tunnel-token", "cloudflare", bind, &full).unwrap();
        assert_eq!(
            a,
            gate_subject("tunnel-token", "cloudflare", "", &full).unwrap()
        );
        assert_eq!(a.scope(), "tunnel-token");
        assert!(!a.production());
        // another token, a binding that is not the token's, or no digest at all
        let other = tunnel_token_sha256("token-b-bbbbbbbbbbbbbbbbbbbb");
        assert_ne!(
            a,
            gate_subject("tunnel-token", "cloudflare", "", &other).unwrap()
        );
        assert!(gate_subject("tunnel-token", "cloudflare", &other[..32], &full).is_err());
        assert!(gate_subject("tunnel-token", "cloudflare", bind, "").is_err());
        // a declaration: set is bound to its binding, remove has none
        let s1 = gate_subject("box-secrets", "declaration", "d-0123456789abcdef", "").unwrap();
        let s2 = gate_subject("box-secrets", "declaration", "d-fedcba9876543210", "").unwrap();
        assert_ne!(s1, s2);
        let rm = gate_subject("box-secrets", "declaration", "", "").unwrap();
        let Subject::BoxSecrets(b) = &rm else {
            panic!()
        };
        assert_eq!(b.action, "remove");
        let Subject::BoxSecrets(b) = gate_subject("box-secrets", "bao-token", "", "").unwrap()
        else {
            panic!()
        };
        assert_eq!(b.action, "set");
        assert!(gate_subject("import", "app", "staging", "").is_err());
    }

    #[test]
    fn a_request_word_names_a_request_and_is_never_a_code() {
        let id = "abcdefghijklmnopqrstuvwxyz";
        let id = &id[..26];
        let w = request_word(id);
        assert_eq!(request_word_id(&w), Some(id));
        assert!(w.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-'));
        assert_eq!(request_word_id("ABCD-EFGH-JKMN-PQRS"), None);
        assert_eq!(request_word_id("req-short"), None);
        assert_eq!(request_word_id("req-ABCDEFGHIJKLMNOPQRSTUVWXYZ"), None);
    }
}
