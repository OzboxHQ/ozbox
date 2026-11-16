//! The encrypted secret store: envelope encryption for a machine where agents run as the box user.
//!
//! Every secret gets its own random data key. The value is sealed with AES-256-GCM under that key, and the data key is
//! wrapped by a key-encryption key (KEK) that never sits on the disk next to the ciphertext (ADR 0018). What is
//! authenticated with each seal (the AAD) is the store's id, the box or fleet it belongs to and the secret's name, so a
//! ciphertext cannot be moved to another name, another store or another box and still open.
//!
//! The KEK comes from a [`KeyProvider`]:
//!
//! * [`KmsProvider`]: AWS KMS, called natively with the box's own role (no `aws` command: the box image does not carry it).
//!   The plaintext data key is only in the request and the answer, never in an argument or a file. The encryption context
//!   repeats the AAD, so the key policy and the audit trail see what was opened.
//! * [`LocalKekProvider`]: a 256-bit KEK held outside the store file: in the operating system's keychain on a laptop,
//!   sealed to the machine's TPM on a server that has one, or derived from a passphrase an operator types at start
//!   (never written anywhere).
//!
//! When the KEK is not available every call fails closed with a plain message; nothing falls back to a weaker store.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use ring::aead::{Aad, LessSafeKey, Nonce, UnboundKey, AES_256_GCM};
use ring::pbkdf2;
use serde::{Deserialize, Serialize};
use zeroize::{Zeroize, Zeroizing};

use ozbox_core::{CommandRunner, CommandSpec};

use crate::secrets::{check_value, SecretError, SecretStore};
use crate::serve::auth::b64::{decode_std, encode_std};

/// The file format of a store with no encoded value: what every released program reads and writes. A file only moves to
/// [`ENCODED_FORMAT`] when it holds an encoded value, so existing stores need no migration.
const PLAIN_FORMAT: u32 = 1;
/// The format of a file that holds at least one encoded value ([`Entry::enc`]). A program from before this format refuses
/// the file ("from a newer version") rather than hand base64 text to a program as if it were the value.
const ENCODED_FORMAT: u32 = 2;
/// `Entry::enc` of a value stored as base64 text. The marker is metadata beside the seal, never part of the value: every
/// printable prefix is a legal plain value, so a marker inside it would be ambiguous.
pub const ENC_B64: &str = "b64";
/// The longest value [`EncryptedSecrets::set_exact_with_meta`] stores (the bytes of the value itself). Linux refuses to start a
/// program whose one environment string (`NAME=value`) is over 128 KB, so a value near that could be stored and never run.
pub const MAX_EXACT_VALUE: usize = 96 * 1024;
const AAD_PREFIX: &[u8] = b"ozbox-secret-v1";
/// How long an unwrapped data key may be kept in memory so a busy reader does not call the key service for every read.
const DATA_KEY_TTL: Duration = Duration::from_secs(300);

fn err(msg: &str) -> SecretError {
    SecretError(msg.into())
}

/// What a KMS call that the key service REFUSED (an access-denied answer) is reported as, apart from [`KEK_UNAVAILABLE`] (a
/// network fault, a timeout, a tool that would not start). The distinction is for one reader: the box's root check of whether a
/// moved store's grant is really gone, which must never take a timeout for a revoked grant. Nothing from the tool is in it.
pub const KEK_DENIED: &str = "the key service refused this machine's role (access denied), so the key that protects its secrets is not available and nothing was read or changed";

/// The message for every call while the KEK cannot be reached. It never carries a tool's own words (they can name
/// accounts or paths).
pub const KEK_UNAVAILABLE: &str = "the key that protects this machine's secrets is not available, so nothing was read or changed (check the key service or the keychain, then try again)";

// ----------------------------------------------------------------------------------------------------------------
// Key providers
// ----------------------------------------------------------------------------------------------------------------

/// Wraps and unwraps a 256-bit data key. `aad` is the same text the value's seal is bound to; a provider that can bind
/// it (KMS, AES-GCM) must, so a wrapped key cannot be moved either.
pub trait KeyProvider: Send + Sync {
    /// A short stable label stored in the file, so a wrong provider is told apart from a wrong key.
    fn label(&self) -> String;
    fn wrap(&self, data_key: &[u8; 32], aad: &[u8]) -> Result<Vec<u8>, SecretError>;
    fn unwrap(&self, wrapped: &[u8], aad: &[u8]) -> Result<Zeroizing<Vec<u8>>, SecretError>;
}

/// The provider for tests and for callers that hold a KEK already: AES-256-GCM under a key in memory.
pub struct LocalKekProvider {
    label: String,
    kek: Zeroizing<[u8; 32]>,
}

impl LocalKekProvider {
    pub fn new(label: &str, kek: [u8; 32]) -> Self {
        Self {
            label: label.to_string(),
            kek: Zeroizing::new(kek),
        }
    }

    pub fn random(label: &str) -> Result<Self, SecretError> {
        let mut k = [0u8; 32];
        getrandom::getrandom(&mut k).map_err(|_| err("no random numbers are available"))?;
        let p = Self::new(label, k);
        k.zeroize();
        Ok(p)
    }

    /// The KEK as text, for a keychain or the TPM to hold. Handle it as a secret.
    pub fn kek_text(&self) -> Zeroizing<String> {
        Zeroizing::new(encode_std(&*self.kek))
    }

    pub fn from_text(label: &str, text: &str) -> Result<Self, SecretError> {
        let raw = Zeroizing::new(decode_std(text.trim()).ok_or_else(|| err(KEK_UNAVAILABLE))?);
        let arr: [u8; 32] = raw
            .as_slice()
            .try_into()
            .map_err(|_| err(KEK_UNAVAILABLE))?;
        Ok(Self::new(label, arr))
    }

    /// A KEK derived from a passphrase an operator types at start. The salt is stored in the store file (it is not a
    /// secret); the passphrase never is.
    pub fn from_passphrase(
        label: &str,
        passphrase: &str,
        salt: &[u8],
    ) -> Result<Self, SecretError> {
        if passphrase.len() < 12 {
            return Err(err("the passphrase must be at least 12 characters"));
        }
        let mut k = [0u8; 32];
        let iterations = std::num::NonZeroU32::new(600_000).ok_or_else(|| err("bad setting"))?;
        pbkdf2::derive(
            pbkdf2::PBKDF2_HMAC_SHA256,
            iterations,
            salt,
            passphrase.as_bytes(),
            &mut k,
        );
        let p = Self::new(label, k);
        k.zeroize();
        Ok(p)
    }
}

fn seal(key: &[u8; 32], aad: &[u8], plain: &[u8]) -> Result<Vec<u8>, SecretError> {
    let mut nonce = [0u8; 12];
    getrandom::getrandom(&mut nonce).map_err(|_| err("no random numbers are available"))?;
    let unbound = UnboundKey::new(&AES_256_GCM, key).map_err(|_| err("encryption failed"))?;
    let key = LessSafeKey::new(unbound);
    let mut guard = Zeroizing::new(plain.to_vec());
    let buf: &mut Vec<u8> = &mut guard;
    key.seal_in_place_append_tag(Nonce::assume_unique_for_key(nonce), Aad::from(aad), buf)
        .map_err(|_| err("encryption failed"))?;
    let mut out = nonce.to_vec();
    out.extend_from_slice(&guard);
    Ok(out)
}

fn open(key: &[u8], aad: &[u8], blob: &[u8]) -> Result<Zeroizing<Vec<u8>>, SecretError> {
    if blob.len() < 12 + 16 {
        return Err(err("a stored secret is damaged"));
    }
    let (nonce, rest) = blob.split_at(12);
    let nonce: [u8; 12] = nonce
        .try_into()
        .map_err(|_| err("a stored secret is damaged"))?;
    let unbound =
        UnboundKey::new(&AES_256_GCM, key).map_err(|_| err("a stored secret is damaged"))?;
    let key = LessSafeKey::new(unbound);
    let mut buf = Zeroizing::new(rest.to_vec());
    let plain_len = key
        .open_in_place(
            Nonce::assume_unique_for_key(nonce),
            Aad::from(aad),
            &mut buf,
        )
        .map_err(|_| err("a stored secret failed its integrity check and was not used"))?
        .len();
    buf.truncate(plain_len);
    Ok(buf)
}

impl KeyProvider for LocalKekProvider {
    fn label(&self) -> String {
        self.label.clone()
    }
    fn wrap(&self, data_key: &[u8; 32], aad: &[u8]) -> Result<Vec<u8>, SecretError> {
        seal(&self.kek, aad, data_key)
    }
    fn unwrap(&self, wrapped: &[u8], aad: &[u8]) -> Result<Zeroizing<Vec<u8>>, SecretError> {
        open(&*self.kek, aad, wrapped)
    }
}

/// AWS KMS, called natively (ADR 0008: no SDK, and no `aws` command: the box image does not carry it). The request is AWS
/// JSON signed with SigV4 by the box's own role (see [`crate::aws_native`]). The plaintext data key is in the request body
/// and the answer only, both zeroized, and never in an argument, a file or an error. The encryption context repeats the AAD,
/// so the key policy and the audit trail see what was opened.
pub struct KmsProvider {
    client: crate::aws_native::AwsJson,
    key_id: String,
    region: Option<String>,
    /// The key service's address, for a test; `None` is the real one for the region.
    base: Option<String>,
}

impl KmsProvider {
    pub fn new(key_id: &str, region: Option<&str>) -> Result<Self, SecretError> {
        Self::build(crate::aws_native::AwsJson::new(), key_id, region, None)
    }

    fn build(
        client: crate::aws_native::AwsJson,
        key_id: &str,
        region: Option<&str>,
        base: Option<&str>,
    ) -> Result<Self, SecretError> {
        let plain = |s: &str| {
            !s.is_empty()
                && s.len() <= 2048
                && s.bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b"-_/:.".contains(&b))
        };
        if !plain(key_id)
            || region.is_some_and(|r| !plain(r) || !crate::aws_native::valid_region(r))
        {
            return Err(err("the key service settings are not valid"));
        }
        Ok(Self {
            client,
            key_id: key_id.to_string(),
            region: region.map(str::to_string),
            base: base.map(str::to_string),
        })
    }

    /// The region to call: the setting, else the one a key ARN names, else the environment's, else this machine's own.
    fn region(&self) -> Option<String> {
        use crate::aws_native::valid_region;
        if let Some(r) = &self.region {
            return Some(r.clone());
        }
        if let Some(r) = self
            .key_id
            .strip_prefix("arn:")
            .and_then(|t| t.split(':').nth(2))
        {
            if valid_region(r) {
                return Some(r.to_string());
            }
        }
        ["AWS_REGION", "AWS_DEFAULT_REGION"]
            .iter()
            .find_map(|n| std::env::var(n).ok().filter(|v| valid_region(v)))
            .or_else(|| self.client.imds_region())
    }

    fn call(
        &self,
        target: &'static str,
        body: &impl Serialize,
    ) -> Result<Zeroizing<Vec<u8>>, &'static str> {
        use crate::aws_native::{service_base, Failure};
        let region = self.region().ok_or(KEK_UNAVAILABLE)?;
        let base = self
            .base
            .clone()
            .unwrap_or_else(|| service_base("kms", &region));
        // sized up front, so writing the request (which holds the data key's text) never grows the buffer and leaves an
        // unwiped copy of it behind
        let mut bytes = Zeroizing::new(Vec::with_capacity(4096));
        serde_json::to_writer(&mut *bytes, body).map_err(|_| KEK_UNAVAILABLE)?;
        self.client
            .call(&base, &region, "kms", target, bytes)
            .map_err(|f| match f {
                Failure::Denied => KEK_DENIED,
                Failure::Unavailable => KEK_UNAVAILABLE,
            })
    }
}

/// The encryption context for KMS, from the AAD parts `store\0scope\0name`.
#[derive(Serialize)]
struct KmsContext {
    store: String,
    scope: String,
    name: String,
}

fn context_of(aad: &[u8]) -> KmsContext {
    let text = String::from_utf8_lossy(aad);
    let mut parts = text.split('\0').skip(1).map(str::to_string);
    KmsContext {
        store: parts.next().unwrap_or_default(),
        scope: parts.next().unwrap_or_default(),
        name: parts.next().unwrap_or_default(),
    }
}

/// The request bodies borrow the data key's text, so no unzeroized copy of it is made here.
#[derive(Serialize)]
#[serde(rename_all = "PascalCase")]
struct EncryptRequest<'a> {
    key_id: &'a str,
    plaintext: &'a str,
    encryption_context: KmsContext,
}

#[derive(Serialize)]
#[serde(rename_all = "PascalCase")]
struct DecryptRequest<'a> {
    ciphertext_blob: &'a str,
    encryption_context: KmsContext,
}

/// The one field of a KMS answer that is read.
#[derive(Deserialize)]
struct KmsAnswer {
    #[serde(rename = "CiphertextBlob", default)]
    ciphertext: Option<String>,
    #[serde(rename = "Plaintext", default)]
    plaintext: Option<String>,
}

impl KeyProvider for KmsProvider {
    fn label(&self) -> String {
        "kms".into()
    }
    fn wrap(&self, data_key: &[u8; 32], aad: &[u8]) -> Result<Vec<u8>, SecretError> {
        let plain = Zeroizing::new(encode_std(data_key));
        let out = self
            .call(
                "TrentService.Encrypt",
                &EncryptRequest {
                    key_id: &self.key_id,
                    plaintext: plain.as_str(),
                    encryption_context: context_of(aad),
                },
            )
            .map_err(err)?;
        let a: KmsAnswer = serde_json::from_slice(&out).map_err(|_| err(KEK_UNAVAILABLE))?;
        a.ciphertext
            .as_deref()
            .and_then(decode_std)
            .filter(|c| !c.is_empty())
            .ok_or_else(|| err(KEK_UNAVAILABLE))
    }
    fn unwrap(&self, wrapped: &[u8], aad: &[u8]) -> Result<Zeroizing<Vec<u8>>, SecretError> {
        let out = self
            .call(
                "TrentService.Decrypt",
                &DecryptRequest {
                    ciphertext_blob: &encode_std(wrapped),
                    encryption_context: context_of(aad),
                },
            )
            .map_err(err)?;
        let a: KmsAnswer = serde_json::from_slice(&out).map_err(|_| err(KEK_UNAVAILABLE))?;
        let mut text = a.plaintext.unwrap_or_default();
        let plain = decode_std(text.trim());
        text.zeroize();
        plain
            .map(Zeroizing::new)
            .filter(|p| p.len() == 32)
            .ok_or_else(|| err(KEK_UNAVAILABLE))
    }
}

// ----------------------------------------------------------------------------------------------------------------
// The file
// ----------------------------------------------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize)]
struct Entry {
    /// Wrapped data key.
    wk: String,
    /// nonce || ciphertext || tag, sealed under the data key.
    ct: String,
    created: u64,
    rotated: u64,
    #[serde(default)]
    meta: Meta,
    /// How the sealed bytes are to be read: empty (the value itself, every entry made before encoded values) or
    /// [`ENC_B64`] (base64 of the value). Not part of the seal; a damaged marker fails to decode and says so.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    enc: String,
}

/// What is kept beside a secret, never secret itself: who put it there, and whether it is a production credential.
/// Part of the file, not of the seal, so listing never needs the key.
#[derive(Debug, Clone, Serialize, Deserialize, Default, PartialEq, Eq)]
pub struct Meta {
    #[serde(default)]
    pub owner: String,
    #[serde(default)]
    pub production: bool,
    /// Marked PUBLIC at import (`ozbox secrets import --public`): a public URL or an anonymous key, which a command may be given as
    /// plain environment. A person's explicit mark, never inferred from a value; left out of the file when false, so an entry
    /// from before it keeps its bytes. Kept beside the seal, not in it, like `production`.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub public: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
struct Migration {
    from: String,
    at: u64,
    count: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct File {
    version: u32,
    store_id: String,
    scope: String,
    kek: String,
    /// Salt for a passphrase-derived KEK. Not a secret.
    #[serde(default)]
    salt: String,
    #[serde(default)]
    migrated: Option<Migration>,
    secrets: BTreeMap<String, Entry>,
}

/// What [`EncryptedSecrets::set_exact_with_meta`] refuses: nothing a person can fix by quoting differently.
pub(crate) fn check_exact(value: &str) -> Result<(), SecretError> {
    if value.is_empty() {
        return Err(SecretError("the value is empty".into()));
    }
    if value.contains('\0') {
        return Err(SecretError(
            "the value contains a NUL byte, which an environment variable cannot hold".into(),
        ));
    }
    if value.len() > MAX_EXACT_VALUE {
        return Err(SecretError(format!(
            "the value is too long (over {} KB)",
            MAX_EXACT_VALUE / 1024
        )));
    }
    Ok(())
}

fn now_s() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_secs())
}

fn aad_for(store_id: &str, scope: &str, name: &str) -> Vec<u8> {
    let mut v = AAD_PREFIX.to_vec();
    for part in [store_id, scope, name] {
        v.push(0);
        v.extend_from_slice(part.as_bytes());
    }
    v
}

/// The AAD of an entry. A PUBLIC entry is sealed under a different one, so the mark is inside the seal: flipping `meta.public` in
/// the file without the store key makes the entry unreadable (it is sealed under the other form), never public. An entry with no
/// mark is sealed exactly as before, so every earlier store stays readable and stays secret.
fn aad_for_entry(store_id: &str, scope: &str, name: &str, public: bool) -> Vec<u8> {
    let mut v = aad_for(store_id, scope, name);
    if public {
        v.push(0);
        v.extend_from_slice(b"public");
    }
    v
}

/// Whether `provider` can wrap a throwaway data key under the encryption context a secret of `scope` would carry and give it
/// back: what a move of the store to a new key needs, found BEFORE the secrets service is stopped. Nothing of the store is read
/// or written.
pub fn probe(provider: &dyn KeyProvider, scope: &str) -> Result<(), SecretError> {
    let mut k = [0u8; 32];
    getrandom::getrandom(&mut k).map_err(|_| err("no random numbers are available"))?;
    let aad = aad_for("probe", scope, "probe");
    let wrapped = provider.wrap(&k, &aad)?;
    let back = provider.unwrap(&wrapped, &aad)?;
    let same = back.as_slice() == k.as_slice();
    k.zeroize();
    if same {
        Ok(())
    } else {
        Err(err("the key gave back something else than it was given"))
    }
}

fn plain_id(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= 64
        && s.bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
}

/// The store name of a workload secret (a `.env` key): scoped to a project and an environment, and bound into the seal
/// like any name. `NAME` is an environment variable name.
pub fn workload_name(project: &str, env: &str, name: &str) -> Result<String, SecretError> {
    let var_ok = !name.is_empty()
        && name.len() <= 64
        && name
            .bytes()
            .all(|b| b.is_ascii_uppercase() || b.is_ascii_digit() || b == b'_')
        && !name.as_bytes()[0].is_ascii_digit();
    let seg = |s: &str| {
        !s.is_empty()
            && s.len() <= 32
            && s.bytes()
                .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
    };
    if var_ok && seg(project) && seg(env) {
        Ok(format!("workload.{project}.{env}.{name}"))
    } else {
        Err(err(
            "that is not a valid project, environment or variable name",
        ))
    }
}

/// An unwrapped data key kept for a short time: when it was cached, the wrapped form it came from, the key.
type CachedKey = (Instant, String, Zeroizing<Vec<u8>>);

pub struct EncryptedSecrets {
    path: PathBuf,
    scope: String,
    provider: Arc<dyn KeyProvider>,
    lock: Mutex<()>,
    cache: Mutex<BTreeMap<String, CachedKey>>,
    cache_ttl: Duration,
    /// Keyed hashes of the values held as production (see [`EncryptedSecrets::is_production_value`]).
    prod: Mutex<Option<ProdSet>>,
}

/// The values this store holds as production, as HMAC-SHA256 tags under a key made for this process and never written: no value is
/// kept, a lookup is one hash, and the set is rebuilt only when the file changes (G5 third round, NV-L2). Before this, every resolve
/// read and parsed the whole file once per stored secret and unwrapped every production value again.
pub struct ProdSet {
    /// What the file looked like when this was built: its inode, size, modification time and change time. A write by another
    /// process changes it.
    stamp: Option<(u64, u64, i128, i128)>,
    key: ring::hmac::Key,
    tags: std::collections::BTreeSet<Vec<u8>>,
}

impl ProdSet {
    /// Whether the value is one of those the store held as production when the set was built (or added since).
    pub fn holds(&self, value: &str) -> bool {
        value.len() >= 4
            && self
                .tags
                .contains(ring::hmac::sign(&self.key, value.as_bytes()).as_ref())
    }
    /// Count a value as production from now on: an import that stores a production value counts it for the lines that follow.
    pub fn add(&mut self, value: &str) {
        if value.len() >= 4 {
            self.tags.insert(
                ring::hmac::sign(&self.key, value.as_bytes())
                    .as_ref()
                    .to_vec(),
            );
        }
    }
}

/// The sentence for "the store could not say whether a value is production": it is never taken as "no" (G5 fourth round, NV3-M2).
fn unknown_production() -> SecretError {
    SecretError(
        "whether this value is also stored as production could not be settled just now (the store or its key could not be read), so it is not given out: try again in a moment".to_string(),
    )
}

/// What a store sealed by one kind of key says when the service is configured for another.
pub const KEK_KIND_MISMATCH: &str =
    "the secrets file is protected by a different kind of key than the one configured";

impl EncryptedSecrets {
    /// `scope` names the box or fleet the store belongs to (it is part of every seal).
    pub fn new(
        path: PathBuf,
        scope: &str,
        provider: Arc<dyn KeyProvider>,
    ) -> Result<Self, SecretError> {
        if !plain_id(scope) {
            return Err(err(
                "the box or fleet name for the secret store is not valid",
            ));
        }
        Ok(Self {
            path,
            scope: scope.to_string(),
            provider,
            lock: Mutex::new(()),
            cache: Mutex::new(BTreeMap::new()),
            cache_ttl: DATA_KEY_TTL,
            prod: Mutex::new(None),
        })
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    fn read(&self) -> Result<Option<File>, SecretError> {
        match std::fs::read_to_string(&self.path) {
            Ok(text) => {
                let v: serde_json::Value = serde_json::from_str(&text)
                    .map_err(|_| err("the secrets file is not valid"))?;
                if v.get("version").is_none() {
                    // The old plaintext format: handled by `migrate_plaintext`, never read as if it were this one.
                    return Err(err("the secrets file is in the old plaintext format and must be migrated first"));
                }
                let f: File =
                    serde_json::from_value(v).map_err(|_| err("the secrets file is not valid"))?;
                if f.version != PLAIN_FORMAT && f.version != ENCODED_FORMAT {
                    return Err(err(
                        "the secrets file is from a newer version of this program",
                    ));
                }
                if f.scope != self.scope {
                    return Err(err("the secrets file belongs to a different box"));
                }
                if f.kek != self.provider.label() {
                    return Err(err(KEK_KIND_MISMATCH));
                }
                Ok(Some(f))
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(_) => Err(err("the secrets file could not be read")),
        }
    }

    fn fresh_file(&self) -> Result<File, SecretError> {
        let mut id = [0u8; 12];
        getrandom::getrandom(&mut id).map_err(|_| err("no random numbers are available"))?;
        Ok(File {
            version: PLAIN_FORMAT,
            store_id: crate::notify::hex(&id),
            scope: self.scope.clone(),
            kek: self.provider.label(),
            salt: String::new(),
            migrated: None,
            secrets: BTreeMap::new(),
        })
    }

    fn write(&self, f: &File) -> Result<(), SecretError> {
        use std::io::Write;
        let fail = || err("the secrets file could not be written");
        if let Some(dir) = self.path.parent() {
            std::fs::create_dir_all(dir).map_err(|_| fail())?;
        }
        let tmp = self.path.with_extension("tmp");
        let mut opts = std::fs::OpenOptions::new();
        opts.write(true).create(true).truncate(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            opts.mode(0o600);
        }
        let mut file = opts.open(&tmp).map_err(|_| fail())?;
        // the format is what the content needs: only a file with an encoded value is one an older program must refuse
        let mut doc = serde_json::to_value(f).map_err(|_| fail())?;
        doc["version"] = serde_json::json!(if f.secrets.values().any(|e| !e.enc.is_empty()) {
            ENCODED_FORMAT
        } else {
            PLAIN_FORMAT
        });
        file.write_all(serde_json::to_string(&doc).map_err(|_| fail())?.as_bytes())
            .map_err(|_| fail())?;
        file.sync_all().map_err(|_| fail())?;
        drop(file);
        let done = std::fs::rename(&tmp, &self.path).map_err(|_| fail());
        // what was held as production may have changed: it is worked out again on the next question
        if let Ok(mut p) = self.prod.lock() {
            *p = None;
        }
        done
    }

    fn stamp(&self) -> Option<(u64, u64, i128, i128)> {
        use std::os::unix::fs::MetadataExt;
        let m = std::fs::metadata(&self.path).ok()?;
        Some((
            m.ino(),
            m.len(),
            i128::from(m.mtime()) * 1_000_000_000 + i128::from(m.mtime_nsec()),
            // the change time cannot be set by a program, so two writes inside one clock tick on a reused inode still differ
            i128::from(m.ctime()) * 1_000_000_000 + i128::from(m.ctime_nsec()),
        ))
    }

    fn seal_entry(
        &self,
        f: &File,
        name: &str,
        value: &[u8],
        created: u64,
        public: bool,
    ) -> Result<Entry, SecretError> {
        let aad = aad_for_entry(&f.store_id, &f.scope, name, public);
        let mut dk = Zeroizing::new([0u8; 32]);
        getrandom::getrandom(&mut *dk).map_err(|_| err("no random numbers are available"))?;
        let wk = self.provider.wrap(&dk, &aad)?;
        let ct = seal(&dk, &aad, value)?;
        Ok(Entry {
            wk: encode_std(&wk),
            ct: encode_std(&ct),
            created,
            rotated: now_s(),
            meta: Meta {
                public,
                ..Meta::default()
            },
            enc: String::new(),
        })
    }

    fn open_entry(
        &self,
        f: &File,
        name: &str,
        e: &Entry,
    ) -> Result<Zeroizing<Vec<u8>>, SecretError> {
        let aad = aad_for_entry(&f.store_id, &f.scope, name, e.meta.public);
        let ct = decode_std(&e.ct).ok_or_else(|| err("a stored secret is damaged"))?;
        // The cache is keyed by name and checked against the wrapped key, so a swapped entry never reuses a key.
        if !self.cache_ttl.is_zero() {
            if let Ok(c) = self.cache.lock() {
                if let Some((at, wk, dk)) = c.get(name) {
                    if *wk == e.wk && at.elapsed() < self.cache_ttl {
                        return open(dk, &aad, &ct);
                    }
                }
            }
        }
        let wk = decode_std(&e.wk).ok_or_else(|| err("a stored secret is damaged"))?;
        let dk = self.provider.unwrap(&wk, &aad)?;
        let plain = open(&dk, &aad, &ct)?;
        if !self.cache_ttl.is_zero() {
            if let Ok(mut c) = self.cache.lock() {
                c.insert(name.to_string(), (Instant::now(), e.wk.clone(), dk));
            }
        }
        Ok(plain)
    }

    fn forget_cache(&self) {
        if let Ok(mut c) = self.cache.lock() {
            c.clear();
        }
    }

    /// When each secret was created and last rotated (seconds since 1970), never a value.
    pub fn ages(&self) -> Result<BTreeMap<String, (u64, u64)>, SecretError> {
        let _g = self.lock.lock().unwrap_or_else(|e| e.into_inner());
        Ok(self
            .read()?
            .map(|f| {
                f.secrets
                    .into_iter()
                    .map(|(k, e)| (k, (e.created, e.rotated)))
                    .collect()
            })
            .unwrap_or_default())
    }

    /// Names only, optionally those starting with `prefix`. Needs no key: nothing is decrypted.
    pub fn names(&self, prefix: &str) -> Result<Vec<String>, SecretError> {
        let _g = self.lock.lock().unwrap_or_else(|e| e.into_inner());
        Ok(self
            .read()?
            .map(|f| {
                f.secrets
                    .keys()
                    .filter(|k| k.starts_with(prefix))
                    .cloned()
                    .collect()
            })
            .unwrap_or_default())
    }

    /// Whether `value` is one this store holds as PRODUCTION: flagged so, or stored under an environment named `production`, `prod` or
    /// `live` in any letter case (G5 second review N-M4, third round NV-L2). A value is production wherever else it is stored: a
    /// production file imported under a `staging` name still carries a value that is held here, so it is held back at import and
    /// refused at resolve. The answer comes from a set of keyed hashes built once and rebuilt when the file changes, so a resolve
    /// costs one hash, not a read of every stored secret. No value is returned or kept.
    pub fn is_production_value(&self, value: &str) -> Result<bool, SecretError> {
        if value.len() < 4 {
            return Ok(false);
        }
        let _g = self.lock.lock().unwrap_or_else(|e| e.into_inner());
        let stamp = self.stamp();
        let mut slot = self.prod.lock().unwrap_or_else(|e| e.into_inner());
        if slot.as_ref().is_none_or(|p| p.stamp != stamp) {
            // fails closed: an incomplete set is never kept, so one blip is not remembered until the file changes
            *slot = None;
            *slot = Some(self.build_production_set(stamp)?);
        }
        Ok(slot.as_ref().is_some_and(|p| p.holds(value)))
    }

    /// A set built now and owned by the caller, for an import that asks about many values and stores some of them: built once,
    /// and told about each production value it stores. Fails (never "empty") when the store cannot be read completely.
    pub fn production_checker(&self) -> Result<ProdSet, SecretError> {
        let _g = self.lock.lock().unwrap_or_else(|e| e.into_inner());
        let stamp = self.stamp();
        self.build_production_set(stamp)
    }

    /// One read of the file, and one unwrap per production value. Called with the store's lock held. Every production candidate must
    /// be read and opened: one that cannot is an `Err`, because a set with a hole in it would answer "no" for that value.
    fn build_production_set(
        &self,
        stamp: Option<(u64, u64, i128, i128)>,
    ) -> Result<ProdSet, SecretError> {
        let mut raw = [0u8; 32];
        getrandom::getrandom(&mut raw).map_err(|_| unknown_production())?;
        let key = ring::hmac::Key::new(ring::hmac::HMAC_SHA256, &raw);
        let mut tags = std::collections::BTreeSet::new();
        if let Some(f) = self.read().map_err(|_| unknown_production())? {
            for (n, e) in &f.secrets {
                if !n.starts_with("workload.") {
                    continue;
                }
                // workload.<project>.<env>.<NAME>
                let env = n.split('.').nth(2).unwrap_or("").to_ascii_lowercase();
                if !(matches!(env.as_str(), "production" | "prod" | "live") || e.meta.production) {
                    continue;
                }
                let plain = self
                    .open_entry(&f, n, e)
                    .map_err(|_| unknown_production())?;
                let bytes: Zeroizing<Vec<u8>> = match e.enc.as_str() {
                    "" => plain,
                    ENC_B64 => match std::str::from_utf8(&plain).ok().and_then(decode_std) {
                        Some(b) => Zeroizing::new(b),
                        None => return Err(unknown_production()),
                    },
                    _ => return Err(unknown_production()),
                };
                if bytes.len() >= 4 {
                    tags.insert(ring::hmac::sign(&key, &bytes).as_ref().to_vec());
                }
            }
        }
        Ok(ProdSet { stamp, key, tags })
    }

    /// The metadata of one secret (never its value).
    pub fn meta(&self, name: &str) -> Result<Option<Meta>, SecretError> {
        let _g = self.lock.lock().unwrap_or_else(|e| e.into_inner());
        Ok(self
            .read()?
            .and_then(|f| f.secrets.get(name).map(|e| e.meta.clone())))
    }

    /// Store a value with its metadata (owner, production flag), under the plain rule ([`check_value`]).
    pub fn set_with_meta(&self, name: &str, value: &str, meta: Meta) -> Result<(), SecretError> {
        check_value(value)?;
        self.put(name, value, false, meta)
    }

    /// Store ANY value exactly (spaces, quotes, JSON, several lines, any text): the value is kept as it is when the plain
    /// rule holds it, and as base64 text, marked in the entry's metadata, when it does not. Returns whether it was
    /// encoded. Refused: an empty value, a NUL byte (an environment variable cannot hold one), over [`MAX_EXACT_VALUE`].
    pub fn set_exact_with_meta(
        &self,
        name: &str,
        value: &str,
        meta: Meta,
    ) -> Result<bool, SecretError> {
        check_exact(value)?;
        let encoded = check_value(value).is_err();
        self.put(name, value, encoded, meta)?;
        Ok(encoded)
    }

    fn put(&self, name: &str, value: &str, encoded: bool, meta: Meta) -> Result<(), SecretError> {
        let _g = self.lock.lock().unwrap_or_else(|e| e.into_inner());
        let mut f = match self.read()? {
            Some(f) => f,
            None => self.fresh_file()?,
        };
        let created = f.secrets.get(name).map_or_else(now_s, |e| e.created);
        let bytes: Zeroizing<Vec<u8>> = if encoded {
            Zeroizing::new(encode_std(value.as_bytes()).into_bytes())
        } else {
            Zeroizing::new(value.as_bytes().to_vec())
        };
        let mut e = self.seal_entry(&f, name, &bytes, created, meta.public)?;
        e.meta = meta;
        if encoded {
            e.enc = ENC_B64.to_string();
        }
        f.secrets.insert(name.to_string(), e);
        self.write(&f)?;
        if let Ok(mut c) = self.cache.lock() {
            c.remove(name);
        }
        Ok(())
    }

    /// Whether one secret is stored encoded (its value is read back exactly all the same).
    #[cfg(test)]
    pub fn is_encoded(&self, name: &str) -> Result<bool, SecretError> {
        let _g = self.lock.lock().unwrap_or_else(|e| e.into_inner());
        Ok(self
            .read()?
            .and_then(|f| f.secrets.get(name).map(|e| !e.enc.is_empty()))
            .unwrap_or(false))
    }

    /// How many secrets are stored encoded. A project's declaration is a record, not a secret, and is kept encoded when it
    /// holds characters a plain value may not: it is not counted here.
    pub fn encoded_count(&self) -> Result<usize, SecretError> {
        let _g = self.lock.lock().unwrap_or_else(|e| e.into_inner());
        Ok(self.read()?.map_or(0, |f| {
            f.secrets
                .iter()
                .filter(|(n, e)| {
                    !e.enc.is_empty() && !n.starts_with(crate::workload_policy::POLICY_NAME_PREFIX)
                })
                .count()
        }))
    }

    /// One value by name, exactly as it was stored, for a name on `allowed` (the command's allow-list) that exists under
    /// that project and environment and is not flagged production (unless `allow_production`). This is for an
    /// environment variable: no text ever parses the result. Any failure names the name, never a value.
    pub fn resolve_exact(
        &self,
        project: &str,
        env: &str,
        name: &str,
        allowed: &[String],
        allow_production: bool,
    ) -> Result<Zeroizing<String>, SecretError> {
        let full = workload_name(project, env, name)?;
        if !allowed.iter().any(|a| a == name) {
            return Err(SecretError(format!(
                "{name} is not allowed for this command"
            )));
        }
        if !allow_production && self.meta(&full)?.is_some_and(|m| m.production) {
            return Err(SecretError(format!(
                "{name} is a production key and is not given to agents"
            )));
        }
        let v = self
            .get(&full)?
            .map(Zeroizing::new)
            .ok_or_else(|| SecretError(format!("{name} is not set for {project}/{env}")))?;
        // the same value held anywhere as production is production, whatever name it was stored under
        if !allow_production && self.is_production_value(&v)? {
            return Err(SecretError(format!(
                "{name} holds a value this box also stores as production, so it is not given to agents"
            )));
        }
        Ok(v)
    }

    /// One value marked public at import, by name, exactly as stored. The command must declare the name (`declared`), the entry
    /// must carry the public mark, and it must not be flagged production. A value that is not marked is never returned here,
    /// whatever it looks like.
    pub fn resolve_public(
        &self,
        project: &str,
        env: &str,
        name: &str,
        declared: &[String],
    ) -> Result<Zeroizing<String>, SecretError> {
        let full = workload_name(project, env, name)?;
        if !declared.iter().any(|a| a == name) {
            return Err(SecretError(format!(
                "{name} is not declared public for this command"
            )));
        }
        match self.meta(&full)? {
            Some(m) if m.public && !m.production => {}
            Some(_) => {
                return Err(SecretError(format!(
                    "{name} is not marked public (import it with --public {name}, or declare it as a secret)"
                )))
            }
            None => {
                return Err(SecretError(format!(
                    "{name} is not set for {project}/{env}"
                )))
            }
        }
        let v = self
            .get(&full)?
            .map(Zeroizing::new)
            .ok_or_else(|| SecretError(format!("{name} is not set for {project}/{env}")))?;
        // the same value held anywhere as production is production, whatever name it was stored under
        if self.is_production_value(&v)? {
            return Err(SecretError(format!(
                "{name} holds a value this box also stores as production, so it is not given to agents"
            )));
        }
        // the import checked it too, but the mark is only ever honoured for a value that today's rules still call public
        if let Some(why) = crate::workload_policy::public_mark_refusal(name, &v, false) {
            return Err(SecretError(format!(
                "{name} is marked public but is not given as a public value: {why}"
            )));
        }
        Ok(v)
    }

    /// Resolve `{{secret:NAME}}` references in `text` for one project and environment (see [`Self::resolve_exact`] for who
    /// may receive what). A reference sits in a command line, which is a poor place for a value with spaces, quotes or
    /// lines (it shows in the process list and is split by shells), so a value the plain rule does not hold is refused
    /// there and read from the environment instead. Any failure names the reference, never a value, and resolves nothing.
    pub fn resolve_refs(
        &self,
        project: &str,
        env: &str,
        text: &str,
        allowed: &[String],
        allow_production: bool,
    ) -> Result<Zeroizing<String>, SecretError> {
        let mut out = Zeroizing::new(String::new());
        let mut rest = text;
        while let Some(i) = rest.find("{{secret:") {
            out.push_str(&rest[..i]);
            let after = &rest[i + 9..];
            let j = after
                .find("}}")
                .ok_or_else(|| err("a {{secret:...}} reference is not closed"))?;
            let name = &after[..j];
            let v = self.resolve_exact(project, env, name, allowed, allow_production)?;
            if check_value(&v).is_err() {
                return Err(SecretError(format!(
                    "{name} holds a value that cannot go in a command line (spaces, quotes or several lines): read it from the environment instead"
                )));
            }
            out.push_str(&v);
            rest = &after[j + 2..];
        }
        out.push_str(rest);
        Ok(out)
    }

    #[allow(dead_code)] // `rotate-data-keys` rotates all; a single-secret rotation is for the dashboard's rotate action
    /// Give one secret a new data key (the value is unchanged).
    pub fn rotate_data_key(&self, name: &str) -> Result<bool, SecretError> {
        let _g = self.lock.lock().unwrap_or_else(|e| e.into_inner());
        let Some(mut f) = self.read()? else {
            return Ok(false);
        };
        let Some(e) = f.secrets.get(name).cloned() else {
            return Ok(false);
        };
        let plain = self.open_entry(&f, name, &e)?;
        let mut fresh = self.seal_entry(&f, name, &plain, e.created, e.meta.public)?;
        fresh.meta = e.meta.clone();
        fresh.enc = e.enc.clone();
        f.secrets.insert(name.to_string(), fresh);
        self.write(&f)?;
        self.forget_cache();
        Ok(true)
    }

    /// Give every secret a new data key. Returns how many.
    pub fn rotate_all_data_keys(&self) -> Result<usize, SecretError> {
        let _g = self.lock.lock().unwrap_or_else(|e| e.into_inner());
        let Some(mut f) = self.read()? else {
            return Ok(0);
        };
        let names: Vec<String> = f.secrets.keys().cloned().collect();
        for n in &names {
            let e = f.secrets[n].clone();
            let plain = self.open_entry(&f, n, &e)?;
            let mut fresh = self.seal_entry(&f, n, &plain, e.created, e.meta.public)?;
            fresh.meta = e.meta.clone();
            fresh.enc = e.enc.clone();
            f.secrets.insert(n.clone(), fresh);
        }
        self.write(&f)?;
        self.forget_cache();
        Ok(names.len())
    }

    /// Move the store to a new key-encryption key: every data key is unwrapped with the old provider and wrapped with
    /// the new one, and the file is replaced in one write. A failure leaves the old file as it was. Returns how many
    /// secrets were re-wrapped.
    pub fn rotate_kek(
        &self,
        new: Arc<dyn KeyProvider>,
        new_salt: Option<&[u8]>,
    ) -> Result<usize, SecretError> {
        let _g = self.lock.lock().unwrap_or_else(|e| e.into_inner());
        let Some(mut f) = self.read()? else {
            return Ok(0);
        };
        for (name, e) in f.secrets.iter_mut() {
            let aad = aad_for_entry(&f.store_id, &f.scope, name, e.meta.public);
            let wk = decode_std(&e.wk).ok_or_else(|| err("a stored secret is damaged"))?;
            let dk = self.provider.unwrap(&wk, &aad)?;
            let arr: [u8; 32] = dk
                .as_slice()
                .try_into()
                .map_err(|_| err("a stored secret is damaged"))?;
            let wrapped = new.wrap(&arr, &aad)?;
            // The new key must be able to give the data key back before the file is replaced (a KMS key that may encrypt
            // and may not decrypt, or an encryption context that does not match, is found here, with the old file
            // untouched, not by a service that cannot start afterwards).
            let back = new.unwrap(&wrapped, &aad)?;
            if back.as_slice() != dk.as_slice() {
                return Err(err("the new key did not give a stored secret back"));
            }
            e.wk = encode_std(&wrapped);
        }
        f.kek = new.label();
        if let Some(s) = new_salt {
            f.salt = encode_std(s);
        }
        self.write(&f)?;
        self.forget_cache();
        Ok(f.secrets.len())
    }

    /// The salt stored for a passphrase-derived KEK, if the file exists and has one.
    /// The kind of key that sealed the store at `path` (its label: `file`, `kms`, ...), when it can be read. Only the label is
    /// read; nothing is opened.
    pub fn stored_kek(path: &Path) -> Option<String> {
        let f: File = serde_json::from_str(&std::fs::read_to_string(path).ok()?).ok()?;
        Some(f.kek).filter(|k| !k.is_empty())
    }

    pub fn stored_salt(path: &Path) -> Option<Vec<u8>> {
        let f: File = serde_json::from_str(&std::fs::read_to_string(path).ok()?).ok()?;
        decode_std(&f.salt).filter(|s| !s.is_empty())
    }

    /// If `path` holds the old plaintext store, read it once, write the encrypted store in its place, overwrite the
    /// plaintext with zeros and remove it, and record that this happened. Returns how many secrets moved (0 when there
    /// was nothing to migrate). Safe to run again after a crash: the plaintext is only destroyed after the encrypted
    /// file is on disk.
    pub fn migrate_plaintext(&self) -> Result<usize, SecretError> {
        let _g = self.lock.lock().unwrap_or_else(|e| e.into_inner());
        let Ok(text) = std::fs::read_to_string(&self.path) else {
            return Ok(0);
        };
        let text = Zeroizing::new(text);
        let Ok(v) = serde_json::from_str::<serde_json::Value>(&text) else {
            return Ok(0);
        };
        if v.get("version").is_some() {
            return Ok(0);
        }
        let old: BTreeMap<String, String> = serde_json::from_value(v)
            .map_err(|_| err("the old secrets file is not valid; it was left as it is"))?;
        let mut f = self.fresh_file()?;
        let now = now_s();
        for (name, value) in &old {
            let e = self.seal_entry(&f, name, value.as_bytes(), now, false)?;
            f.secrets.insert(name.clone(), e);
        }
        f.migrated = Some(Migration {
            from: "plaintext-file".into(),
            at: now,
            count: old.len() as u64,
        });
        // The encrypted copy goes to a side file first and is checked by opening it again.
        let side = self.path.with_extension("enc");
        let keep = self.path.clone();
        let moved = EncryptedSecrets {
            prod: Mutex::new(None),
            path: side.clone(),
            scope: self.scope.clone(),
            provider: self.provider.clone(),
            lock: Mutex::new(()),
            cache: Mutex::new(BTreeMap::new()),
            cache_ttl: Duration::ZERO,
        };
        moved.write(&f)?;
        for (name, e) in &f.secrets {
            let back = moved.open_entry(&f, name, e)?;
            if back.as_slice() != old[name].as_bytes() {
                let _ = std::fs::remove_file(&side);
                return Err(err(
                    "the encrypted copy did not match; the old file was left as it is",
                ));
            }
        }
        shred(&keep)?;
        std::fs::rename(&side, &keep).map_err(|_| err("the secrets file could not be written"))?;
        Ok(old.len())
    }

    /// Whether the plaintext migration has been recorded, and when and how many.
    pub fn migration_record(&self) -> Option<(u64, u64)> {
        let f = self.read().ok().flatten()?;
        f.migrated.map(|m| (m.at, m.count))
    }
}

/// Overwrite a file with zeros, flush it, and remove it. (On a journaled or flash disk an overwrite is a best effort;
/// the disk itself is encrypted, and the value is rotated with the vendor when this matters.)
pub fn shred(path: &Path) -> Result<(), SecretError> {
    use std::io::{Seek, Write};
    let fail = || err("the old plaintext file could not be removed");
    let len = std::fs::metadata(path).map_err(|_| fail())?.len();
    let mut f = std::fs::OpenOptions::new()
        .write(true)
        .open(path)
        .map_err(|_| fail())?;
    f.seek(std::io::SeekFrom::Start(0)).map_err(|_| fail())?;
    let zeros = [0u8; 4096];
    let mut left = len;
    while left > 0 {
        let n = left.min(zeros.len() as u64) as usize;
        f.write_all(&zeros[..n]).map_err(|_| fail())?;
        left -= n as u64;
    }
    f.sync_all().map_err(|_| fail())?;
    drop(f);
    std::fs::remove_file(path).map_err(|_| fail())
}

impl SecretStore for EncryptedSecrets {
    fn set(&self, name: &str, value: &str) -> Result<(), SecretError> {
        check_value(value)?;
        self.put(name, value, false, Meta::default())
    }

    fn set_exact(&self, name: &str, value: &str) -> Result<(), SecretError> {
        self.set_exact_with_meta(name, value, Meta::default())
            .map(|_| ())
    }

    /// A record is sealed and integrity-protected exactly like a secret (the same entry, the same key, the same file); only its
    /// size rule differs ([`crate::secrets::MAX_RECORD_VALUE`]). Text that is not a plain value is kept as base64, as for
    /// [`Self::set_exact`], and read back as it was.
    fn set_record(&self, name: &str, value: &str) -> Result<(), SecretError> {
        crate::secrets::check_record(value)?;
        self.put(name, value, check_value(value).is_err(), Meta::default())
    }

    fn get(&self, name: &str) -> Result<Option<String>, SecretError> {
        let _g = self.lock.lock().unwrap_or_else(|e| e.into_inner());
        let Some(f) = self.read()? else {
            return Ok(None);
        };
        let Some(e) = f.secrets.get(name) else {
            return Ok(None);
        };
        let plain = self.open_entry(&f, name, e)?;
        let bytes: Zeroizing<Vec<u8>> = match e.enc.as_str() {
            "" => plain,
            ENC_B64 => {
                let text =
                    std::str::from_utf8(&plain).map_err(|_| err("a stored secret is damaged"))?;
                Zeroizing::new(decode_std(text).ok_or_else(|| err("a stored secret is damaged"))?)
            }
            _ => {
                return Err(err(
                    "a stored secret is from a newer version of this program",
                ))
            }
        };
        String::from_utf8(bytes.to_vec())
            .map(Some)
            .map_err(|_| err("a stored secret is damaged"))
    }

    fn exists(&self, name: &str) -> Result<bool, SecretError> {
        let _g = self.lock.lock().unwrap_or_else(|e| e.into_inner());
        Ok(self.read()?.is_some_and(|f| f.secrets.contains_key(name)))
    }

    fn delete(&self, name: &str) -> Result<(), SecretError> {
        let _g = self.lock.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(mut f) = self.read()? {
            if f.secrets.remove(name).is_some() {
                self.write(&f)?;
            }
        }
        if let Ok(mut c) = self.cache.lock() {
            c.remove(name);
        }
        Ok(())
    }

    fn label(&self) -> &'static str {
        "an encrypted store on this machine"
    }
}

// ----------------------------------------------------------------------------------------------------------------
// Choosing the KEK
// ----------------------------------------------------------------------------------------------------------------

/// The KEK kept in a file only the secrets user can read (`0600`, made on first use). It protects the store from the box
/// user and every agent, which is what the box's threat model asks of it (ADR 0018); it does **not** protect against someone
/// who can read the disk as the secrets user or as root. A box with a KMS key or a TPM uses that instead.
pub fn file_kek_provider(path: &std::path::Path) -> Result<Arc<dyn KeyProvider>, SecretError> {
    use std::io::Write;
    match std::fs::read_to_string(path) {
        Ok(t) => return Ok(Arc::new(LocalKekProvider::from_text("file", &t)?)),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
        Err(_) => return Err(err(KEK_UNAVAILABLE)),
    }
    let p = LocalKekProvider::random("file")?;
    let mut o = std::fs::OpenOptions::new();
    o.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        o.mode(0o600);
    }
    match o.open(path) {
        Ok(mut f) => {
            f.write_all(p.kek_text().as_bytes())
                .and_then(|_| f.sync_all())
                .map_err(|_| err(KEK_UNAVAILABLE))?;
            Ok(Arc::new(p))
        }
        // another start made it first: use theirs
        Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {
            let t = std::fs::read_to_string(path).map_err(|_| err(KEK_UNAVAILABLE))?;
            Ok(Arc::new(LocalKekProvider::from_text("file", &t)?))
        }
        Err(_) => Err(err(KEK_UNAVAILABLE)),
    }
}

/// The KEK stored in the operating system's keychain (made on first use), under the secret name `store-kek`.
pub fn keychain_provider(keychain: &dyn SecretStore) -> Result<Arc<dyn KeyProvider>, SecretError> {
    match keychain
        .get("store-kek")
        .map_err(|_| err(KEK_UNAVAILABLE))?
    {
        Some(t) => Ok(Arc::new(LocalKekProvider::from_text("keychain", &t)?)),
        None => {
            let p = LocalKekProvider::random("keychain")?;
            keychain
                .set("store-kek", &p.kek_text())
                .map_err(|_| err(KEK_UNAVAILABLE))?;
            Ok(Arc::new(p))
        }
    }
}

/// A KEK sealed to this machine's TPM 2.0 with `tpm2-tools`. The sealed blobs sit beside the store; they open only on
/// this machine. The KEK travels to and from the tools as text on standard input and output, never in an argument.
pub struct TpmKek;

impl TpmKek {
    pub fn available() -> bool {
        Path::new("/dev/tpmrm0").exists()
            && std::env::var_os("PATH")
                .is_some_and(|p| std::env::split_paths(&p).any(|d| d.join("tpm2_unseal").is_file()))
    }

    pub fn load_or_create(
        runner: &dyn CommandRunner,
        dir: &Path,
    ) -> Result<Arc<dyn KeyProvider>, SecretError> {
        let d = dir.to_string_lossy().into_owned();
        let (primary, publ, privb, ctx) = (
            format!("{d}/tpm-primary.ctx"),
            format!("{d}/tpm-kek.pub"),
            format!("{d}/tpm-kek.priv"),
            format!("{d}/tpm-kek.ctx"),
        );
        let run = |c: CommandSpec| runner.run(&c).map_err(|_| err(KEK_UNAVAILABLE));
        let ok = |o: &ozbox_core::Output| o.status == Some(0);
        std::fs::create_dir_all(dir).map_err(|_| err(KEK_UNAVAILABLE))?;
        if !Path::new(&publ).exists() {
            let p = LocalKekProvider::random("tpm2")?;
            let o = run(CommandSpec::new("tpm2_createprimary").args([
                "-C",
                "o",
                "-c",
                primary.as_str(),
            ]))?;
            if !ok(&o) {
                return Err(err(KEK_UNAVAILABLE));
            }
            let o = run(CommandSpec::new("tpm2_create")
                .args([
                    "-C",
                    primary.as_str(),
                    "-i",
                    "-",
                    "-u",
                    publ.as_str(),
                    "-r",
                    privb.as_str(),
                ])
                .stdin(p.kek_text().as_bytes().to_vec()))?;
            if !ok(&o) {
                return Err(err(KEK_UNAVAILABLE));
            }
        }
        let o =
            run(CommandSpec::new("tpm2_createprimary").args(["-C", "o", "-c", primary.as_str()]))?;
        if !ok(&o) {
            return Err(err(KEK_UNAVAILABLE));
        }
        let o = run(CommandSpec::new("tpm2_load").args([
            "-C",
            primary.as_str(),
            "-u",
            publ.as_str(),
            "-r",
            privb.as_str(),
            "-c",
            ctx.as_str(),
        ]))?;
        if !ok(&o) {
            return Err(err(KEK_UNAVAILABLE));
        }
        let mut o = run(CommandSpec::new("tpm2_unseal").args(["-c", ctx.as_str()]))?;
        let text = Zeroizing::new(std::mem::take(&mut o.stdout));
        if !ok(&o) {
            return Err(err(KEK_UNAVAILABLE));
        }
        Ok(Arc::new(LocalKekProvider::from_text("tpm2", &text)?))
    }
}

/// Values that break anything that parses text, for the tests of every store and of `env run`: a newline that tries to
/// add a variable, quotes, command substitution, spaces at the ends, JSON, unicode, CRLF, a PEM key with a final newline,
/// and 64 KB.
#[cfg(test)]
pub(crate) mod hostile {
    pub fn values() -> Vec<String> {
        vec![
            "line one\nPATH=/tmp/evil\nLD_PRELOAD=/tmp/x.so".to_string(),
            "has \"double\" and 'single' quotes and \\ backslash".to_string(),
            "$(touch MARKER) `touch MARKER`; touch MARKER & echo pwned | cat > MARKER ${HOME}".to_string(),
            "  leading and trailing spaces  ".to_string(),
            "{\"k\":[1,2],\"s\":\"a b\"}".to_string(),
            "日本語 ünïcödé 🔑 emoji".to_string(),
            "tab\there\r\nCRLF line".to_string(),
            "a=b=c== # not a comment".to_string(),
            format!("{}{}", "-----BEGIN PRIV", "ATE KEY-----\nMIIEvQIBADANBgkqhkiG9w0BAQEFAASC==\nabcdEFGH12345678=\n-----END PRIVATE KEY-----\n"),
            "x".repeat(64 * 1024),
            // plain: must stay the plain form
            "plain-0123456789".to_string(),
        ]
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    /// The fleet-key policy `ozbox init` makes (aws-box-policy) lets a box's role use the key only when `kms:EncryptionContext:scope`
    /// equals the role's `ozbox-box` tag, which is the box's name, which is also the store's scope. The probe and the re-wrap send
    /// their scope in that context, so a probe that said `local` (or a policy that changed its variable) would be refused as if
    /// the grant were gone. Read from the module's source, so neither side can drift alone.
    #[test]
    fn the_context_a_probe_and_a_secret_send_satisfies_the_fleet_key_policys_condition() {
        let root =
            std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../infra/tofu/modules");
        let policy = std::fs::read_to_string(root.join("aws-box-policy/main.tf")).unwrap();
        let box_tf = std::fs::read_to_string(root.join("aws-box/main.tf")).unwrap();
        let (_, doc) = policy
            .split_once("data \"aws_iam_policy_document\" \"fleet_key\"")
            .unwrap();
        let (doc, _) = doc
            .split_once("resource \"aws_iam_policy\" \"fleet_key\"")
            .unwrap();
        assert!(
            doc.contains("variable = \"kms:EncryptionContext:scope\""),
            "{doc}"
        );
        assert!(doc.contains("PrincipalTag/ozbox-box}"), "{doc}");
        // the role carries the tag the condition reads, set to the box's name
        assert!(box_tf.contains("\"ozbox-box\"     = var.box_name"));
        assert!(
            box_tf.contains("resource \"aws_iam_role\" \"box\"") && box_tf.contains("local.tags,")
        );
        // a box named dev-1 has the store scope dev-1 (first boot passes its name), and the probe and a secret both send it
        let probe = context_of(&aad_for("probe", "dev-1", "probe"));
        let secret = context_of(&aad_for("sid", "dev-1", "workload.app.staging.KEY"));
        for ctx in [probe, secret] {
            assert_eq!(ctx.scope, "dev-1");
        }
    }

    #[test]
    fn any_value_is_stored_and_returned_exactly_and_only_a_value_the_plain_rule_refuses_is_encoded()
    {
        let d = tempfile::tempdir().unwrap();
        let s = store(d.path(), "box-a", local());
        let all = hostile::values();
        for (i, v) in all.iter().enumerate() {
            let name = format!("workload.app.staging.H{i}");
            let encoded = s.set_exact_with_meta(&name, v, Meta::default()).unwrap();
            assert_eq!(encoded, check_value(v).is_err(), "{i}");
            assert_eq!(s.get(&name).unwrap().as_deref(), Some(v.as_str()), "{i}");
            assert_eq!(s.is_encoded(&name).unwrap(), encoded);
        }
        let text = std::fs::read_to_string(s.path()).unwrap();
        let doc: serde_json::Value = serde_json::from_str(&text).unwrap();
        // a file with an encoded value is the format an older program refuses; a sealed file shows no value
        assert_eq!(doc["version"], 2);
        assert!(
            !text.contains("PATH=/tmp/evil")
                && !text.contains("plain-0123456789")
                && !text.contains("🔑 emoji")
        );
        assert_eq!(s.encoded_count().unwrap(), all.len() - 1);
        // a declaration kept as an encoded record is not a secret and is not counted as one
        s.set_record("workload-policy.app", "{\n\"commands\": {}\n}")
            .unwrap();
        assert!(s.is_encoded("workload-policy.app").unwrap());
        assert_eq!(s.encoded_count().unwrap(), all.len() - 1);
        // a data-key rotation keeps every value, and the marker
        s.rotate_all_data_keys().unwrap();
        for (i, v) in all.iter().enumerate() {
            let name = format!("workload.app.staging.H{i}");
            assert_eq!(
                s.get(&name).unwrap().as_deref(),
                Some(v.as_str()),
                "after rotation {i}"
            );
        }
        // what cannot be stored at all: blank, NUL, over the cap
        for bad in [
            "".to_string(),
            "a\0b".to_string(),
            "y".repeat(MAX_EXACT_VALUE + 1),
        ] {
            assert!(s
                .set_exact_with_meta("workload.app.staging.BAD", &bad, Meta::default())
                .is_err());
        }
        // the plain `set` stays strict, and overwriting an encoded name with a plain value clears the marker
        assert!(s.set("workload.app.staging.H0", "has space").is_err());
        s.set("workload.app.staging.H0", "plain-again-123").unwrap();
        assert!(!s.is_encoded("workload.app.staging.H0").unwrap());
        // a store that never held an encoded value is still the format every released program reads
        let d2 = tempfile::tempdir().unwrap();
        let s2 = store(d2.path(), "box-a", local());
        s2.set_exact_with_meta(
            "workload.app.staging.P",
            "plain-0123456789",
            Meta::default(),
        )
        .unwrap();
        let doc: serde_json::Value =
            serde_json::from_str(&std::fs::read_to_string(s2.path()).unwrap()).unwrap();
        assert_eq!(doc["version"], 1);
        // and going back: remove the last encoded entry and the file is format 1 again
        s2.set_exact_with_meta("workload.app.staging.Q", "has space", Meta::default())
            .unwrap();
        assert_eq!(
            serde_json::from_str::<serde_json::Value>(&std::fs::read_to_string(s2.path()).unwrap())
                .unwrap()["version"],
            2
        );
        s2.delete("workload.app.staging.Q").unwrap();
        assert_eq!(
            serde_json::from_str::<serde_json::Value>(&std::fs::read_to_string(s2.path()).unwrap())
                .unwrap()["version"],
            1
        );
    }

    #[test]
    fn a_command_line_reference_refuses_a_value_that_is_not_plain_and_an_environment_variable_gets_it_exactly(
    ) {
        let d = tempfile::tempdir().unwrap();
        let s = store(d.path(), "box-a", local());
        s.set_exact_with_meta("workload.app.staging.SPACED", "two words", Meta::default())
            .unwrap();
        s.set_exact_with_meta(
            "workload.app.staging.PLAIN",
            "plain-0123456789",
            Meta::default(),
        )
        .unwrap();
        let allow = ["SPACED".to_string(), "PLAIN".to_string()];
        let e = s
            .resolve_refs("app", "staging", "{{secret:SPACED}}", &allow, false)
            .unwrap_err();
        assert!(e.0.contains("command line") && !e.0.contains("two words"));
        assert_eq!(
            s.resolve_refs("app", "staging", "x={{secret:PLAIN}}", &allow, false)
                .unwrap()
                .as_str(),
            "x=plain-0123456789"
        );
        assert_eq!(
            s.resolve_exact("app", "staging", "SPACED", &allow, false)
                .unwrap()
                .as_str(),
            "two words"
        );
        assert!(s
            .resolve_exact("app", "staging", "SPACED", &[], false)
            .is_err());
    }

    #[test]
    fn a_file_with_a_damaged_marker_says_damaged_and_never_hands_back_base64() {
        let d = tempfile::tempdir().unwrap();
        let s = store(d.path(), "box-a", local());
        s.set_exact_with_meta("n", "has space", Meta::default())
            .unwrap();
        let text = std::fs::read_to_string(s.path())
            .unwrap()
            .replace("\"enc\":\"b64\"", "\"enc\":\"zzz\"");
        std::fs::write(s.path(), text).unwrap();
        assert!(s.get("n").unwrap_err().0.contains("newer version"));
    }

    const SENTINEL: &str = "SENTINEL-sk-live-0123456789abcdef";

    fn store(dir: &Path, scope: &str, p: Arc<dyn KeyProvider>) -> EncryptedSecrets {
        EncryptedSecrets::new(dir.join("secrets.json"), scope, p).unwrap()
    }

    fn local() -> Arc<dyn KeyProvider> {
        Arc::new(LocalKekProvider::random("local").unwrap())
    }

    /// A provider that counts how often it unwraps a key.
    struct Counting(LocalKekProvider, std::sync::atomic::AtomicUsize);
    impl KeyProvider for Counting {
        fn label(&self) -> String {
            self.0.label()
        }
        fn wrap(&self, k: &[u8; 32], aad: &[u8]) -> Result<Vec<u8>, SecretError> {
            self.0.wrap(k, aad)
        }
        fn unwrap(&self, w: &[u8], aad: &[u8]) -> Result<Zeroizing<Vec<u8>>, SecretError> {
            self.1.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            self.0.unwrap(w, aad)
        }
    }

    /// G5 fourth round, NV3-M2: the production question fails CLOSED. A key provider that fails once while the set is built does not
    /// make a production value look like a staging one, and the failure is not remembered: the next resolve builds the set again.
    #[test]
    fn a_key_provider_that_fails_once_never_lets_a_production_value_through_and_is_not_remembered()
    {
        struct Flaky(LocalKekProvider, std::sync::atomic::AtomicI64);
        impl KeyProvider for Flaky {
            fn label(&self) -> String {
                self.0.label()
            }
            fn wrap(&self, k: &[u8; 32], aad: &[u8]) -> Result<Vec<u8>, SecretError> {
                self.0.wrap(k, aad)
            }
            fn unwrap(&self, w: &[u8], aad: &[u8]) -> Result<Zeroizing<Vec<u8>>, SecretError> {
                // 0: fine; 1: fail the next unwrap; 2: let one through, then fail the one after
                match self.1.load(std::sync::atomic::Ordering::SeqCst) {
                    1 => {
                        self.1.store(0, std::sync::atomic::Ordering::SeqCst);
                        return Err(SecretError("kms unavailable".into()));
                    }
                    2 => self.1.store(1, std::sync::atomic::Ordering::SeqCst),
                    _ => {}
                }
                self.0.unwrap(w, aad)
            }
        }
        let dir = tempfile::tempdir().unwrap();
        let p = Arc::new(Flaky(
            LocalKekProvider::random("local").unwrap(),
            std::sync::atomic::AtomicI64::new(0),
        ));
        let s = store(dir.path(), "box-a", p.clone());
        let meta = |production| Meta {
            owner: "me".into(),
            production,
            ..Default::default()
        };
        s.set_with_meta(
            "workload.p.production.PROD_KEY",
            "the-production-value-1",
            meta(false),
        )
        .unwrap();
        s.set_with_meta(
            "workload.p.staging.K",
            "the-production-value-1",
            meta(false),
        )
        .unwrap();
        s.set_with_meta(
            "workload.p.staging.OTHER",
            "an-ordinary-staging-value",
            meta(false),
        )
        .unwrap();
        let allowed = ["K".to_string(), "OTHER".to_string()];
        // the value of K is read (one unwrap), then the production entry cannot be opened
        p.1.store(2, std::sync::atomic::Ordering::SeqCst);
        let e = s
            .resolve_exact("p", "staging", "K", &allowed, false)
            .unwrap_err()
            .0;
        assert!(
            e.contains("could not be settled") && !e.contains("the-production-value"),
            "{e}"
        );
        // not cached: the provider is back, and the same value is now refused as production, not handed out
        let e = s
            .resolve_exact("p", "staging", "K", &allowed, false)
            .unwrap_err()
            .0;
        assert!(e.contains("also stores as production"), "{e}");
        // an ordinary value resolves once the set is complete
        assert!(s
            .resolve_exact("p", "staging", "OTHER", &allowed, false)
            .is_ok());
        // an import asks the same question and stops rather than guess
        // (a new store object: the first one still holds the data key in its cache, and would not ask the provider)
        let fresh = store(dir.path(), "box-a", p.clone());
        p.1.store(1, std::sync::atomic::Ordering::SeqCst);
        assert!(fresh.production_checker().is_err());
        assert!(fresh.production_checker().is_ok());
    }

    /// G5 third round, NV-L2: the question "is this held as production" is answered from a set of keyed hashes, built once. Resolves
    /// no longer unwrap (decrypt) every production value, nor read the whole file once per stored secret; a write, by this process
    /// or another, makes the set be built again.
    #[test]
    fn the_production_question_is_answered_from_a_set_built_once_and_rebuilt_when_the_file_changes()
    {
        let dir = tempfile::tempdir().unwrap();
        let counting = Arc::new(Counting(
            LocalKekProvider::random("local").unwrap(),
            std::sync::atomic::AtomicUsize::new(0),
        ));
        let s = store(dir.path(), "box-a", counting.clone());
        let meta = |production| Meta {
            owner: "me".into(),
            production,
            ..Default::default()
        };
        for i in 0..300 {
            s.set_with_meta(
                &format!("workload.p.staging.K{i}"),
                &format!("staging-value-{i:04}"),
                meta(false),
            )
            .unwrap();
        }
        for i in 0..3 {
            s.set_with_meta(
                &format!("workload.p.production.P{i}"),
                &format!("production-value-{i:04}"),
                meta(false),
            )
            .unwrap();
        }
        assert!(s.is_production_value("production-value-0001").unwrap());
        let after_build = counting.1.load(std::sync::atomic::Ordering::SeqCst);
        let t = std::time::Instant::now();
        for i in 0..300 {
            assert!(!s
                .is_production_value(&format!("staging-value-{i:04}"))
                .unwrap());
        }
        let per = t.elapsed().as_micros() / 300;
        eprintln!("MEASURED production question over 303 stored secrets: {per} us each");
        assert_eq!(
            counting.1.load(std::sync::atomic::Ordering::SeqCst),
            after_build,
            "no value was unwrapped again"
        );
        assert!(per < 2_000, "{per} us");
        // a write makes the set be built again: a value that becomes production is seen at once
        s.set_with_meta("workload.p.live.NEW", "freshly-production-9", meta(false))
            .unwrap();
        assert!(s.is_production_value("freshly-production-9").unwrap());
        // another process writing the same file is seen too (the file's stamp moved)
        let other = store(dir.path(), "box-a", counting.clone());
        other
            .set_with_meta(
                "workload.p.staging.FLAGGED",
                "flagged-elsewhere-77",
                meta(true),
            )
            .unwrap();
        assert!(s.is_production_value("flagged-elsewhere-77").unwrap());
    }

    #[test]
    fn a_value_round_trips_and_the_file_holds_no_plaintext() {
        let dir = tempfile::tempdir().unwrap();
        let s = store(dir.path(), "box-a", local());
        s.set("model-key-a", SENTINEL).unwrap();
        assert_eq!(s.get("model-key-a").unwrap().as_deref(), Some(SENTINEL));
        assert!(s.exists("model-key-a").unwrap());
        let raw = std::fs::read_to_string(s.path()).unwrap();
        assert!(!raw.contains(SENTINEL) && !raw.contains("SENTINEL"));
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(s.path()).unwrap().permissions().mode() & 0o777;
            assert_eq!(mode, 0o600);
        }
        s.delete("model-key-a").unwrap();
        assert!(!s.exists("model-key-a").unwrap());
    }

    #[test]
    fn a_tampered_ciphertext_is_refused() {
        let dir = tempfile::tempdir().unwrap();
        let p = local();
        let s = store(dir.path(), "box-a", p.clone());
        s.set("tunnel-token-x", SENTINEL).unwrap();
        let mut f: File =
            serde_json::from_str(&std::fs::read_to_string(s.path()).unwrap()).unwrap();
        let e = f.secrets.get_mut("tunnel-token-x").unwrap();
        let mut ct = decode_std(&e.ct).unwrap();
        let last = ct.len() - 1;
        ct[last] ^= 1;
        e.ct = encode_std(&ct);
        std::fs::write(s.path(), serde_json::to_string(&f).unwrap()).unwrap();
        let e = store(dir.path(), "box-a", p)
            .get("tunnel-token-x")
            .unwrap_err();
        assert!(e.0.contains("integrity"), "{}", e.0);
        assert!(!e.0.contains(SENTINEL));
    }

    #[test]
    fn a_ciphertext_moved_to_another_name_store_or_box_does_not_open() {
        let dir = tempfile::tempdir().unwrap();
        let p = local();
        let s = store(dir.path(), "box-a", p.clone());
        s.set("model-key-a", SENTINEL).unwrap();
        s.set("model-key-b", "other-value").unwrap();
        // swap the two entries under their names
        let mut f: File =
            serde_json::from_str(&std::fs::read_to_string(s.path()).unwrap()).unwrap();
        let a = f.secrets["model-key-a"].clone();
        let b = f.secrets["model-key-b"].clone();
        f.secrets.insert("model-key-a".into(), b);
        f.secrets.insert("model-key-b".into(), a.clone());
        std::fs::write(s.path(), serde_json::to_string(&f).unwrap()).unwrap();
        assert!(store(dir.path(), "box-a", p.clone())
            .get("model-key-a")
            .is_err());
        assert!(store(dir.path(), "box-a", p.clone())
            .get("model-key-b")
            .is_err());

        // a different store id (a copy of the entry into another store)
        let other = tempfile::tempdir().unwrap();
        let t = store(other.path(), "box-a", p.clone());
        t.set("model-key-a", "x").unwrap();
        let mut g: File =
            serde_json::from_str(&std::fs::read_to_string(t.path()).unwrap()).unwrap();
        g.secrets.insert("model-key-a".into(), a);
        std::fs::write(t.path(), serde_json::to_string(&g).unwrap()).unwrap();
        assert!(t.get("model-key-a").is_err());

        // a different box: the file is refused outright, and rewriting its scope breaks every seal
        assert!(store(dir.path(), "box-b", p.clone())
            .get("model-key-a")
            .is_err());
        let mut h: File =
            serde_json::from_str(&std::fs::read_to_string(s.path()).unwrap()).unwrap();
        h.scope = "box-b".into();
        std::fs::write(s.path(), serde_json::to_string(&h).unwrap()).unwrap();
        assert!(store(dir.path(), "box-b", p).get("model-key-a").is_err());
    }

    struct Down;
    impl KeyProvider for Down {
        fn label(&self) -> String {
            "local".into()
        }
        fn wrap(&self, _: &[u8; 32], _: &[u8]) -> Result<Vec<u8>, SecretError> {
            Err(err(KEK_UNAVAILABLE))
        }
        fn unwrap(&self, _: &[u8], _: &[u8]) -> Result<Zeroizing<Vec<u8>>, SecretError> {
            Err(err(KEK_UNAVAILABLE))
        }
    }

    #[test]
    fn an_unavailable_kek_fails_closed_for_every_call_that_needs_it() {
        let dir = tempfile::tempdir().unwrap();
        let p = local();
        store(dir.path(), "box-a", p)
            .set("model-key-a", SENTINEL)
            .unwrap();
        let s = store(dir.path(), "box-a", Arc::new(Down));
        assert_eq!(s.get("model-key-a").unwrap_err().0, KEK_UNAVAILABLE);
        assert_eq!(s.set("model-key-b", "v").unwrap_err().0, KEK_UNAVAILABLE);
        // and the file did not change
        assert!(!store(dir.path(), "box-a", local())
            .exists("model-key-b")
            .unwrap_or(false));
    }

    #[test]
    fn the_wrong_kind_of_key_is_named_not_confused_with_a_wrong_key() {
        let dir = tempfile::tempdir().unwrap();
        store(dir.path(), "box-a", local())
            .set("model-key-a", "v")
            .unwrap();
        let other: Arc<dyn KeyProvider> = Arc::new(LocalKekProvider::random("keychain").unwrap());
        let e = store(dir.path(), "box-a", other)
            .get("model-key-a")
            .unwrap_err();
        assert!(e.0.contains("different kind of key"));
        // the right kind with the wrong key fails the integrity route, not a panic
        assert!(store(dir.path(), "box-a", local())
            .get("model-key-a")
            .is_err());
    }

    /// The old plaintext file's shape: a flat object of names to values.
    fn old_file(pairs: &[(&str, &str)]) -> String {
        let m: BTreeMap<&str, &str> = pairs.iter().copied().collect();
        serde_json::to_string(&m).unwrap()
    }

    #[test]
    fn migration_encrypts_the_old_plaintext_file_and_destroys_it() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("secrets.json");
        std::fs::write(
            &path,
            old_file(&[("old-entry-a", SENTINEL), ("old-entry-b", "pw-plain-12345")]),
        )
        .unwrap();
        let s = EncryptedSecrets::new(path.clone(), "box-a", local()).unwrap();
        // reading the plaintext as the new store is refused, not silently accepted
        assert!(s.get("old-entry-b").is_err());
        assert_eq!(s.migrate_plaintext().unwrap(), 2);
        let raw = std::fs::read_to_string(&path).unwrap();
        assert!(!raw.contains(SENTINEL) && !raw.contains("pw-plain-12345"));
        assert_eq!(s.get("old-entry-a").unwrap().as_deref(), Some(SENTINEL));
        assert_eq!(s.migration_record().map(|m| m.1), Some(2));
        // no side file is left, and a second run does nothing
        assert!(!path.with_extension("enc").exists());
        assert_eq!(s.migrate_plaintext().unwrap(), 0);
    }

    #[test]
    fn shred_zeroes_then_removes() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("old.json");
        std::fs::write(&p, SENTINEL).unwrap();
        shred(&p).unwrap();
        assert!(!p.exists());
    }

    #[test]
    fn data_key_rotation_changes_the_wrapped_key_not_the_value() {
        let dir = tempfile::tempdir().unwrap();
        let s = store(dir.path(), "box-a", local());
        s.set("model-key-a", SENTINEL).unwrap();
        let before: File =
            serde_json::from_str(&std::fs::read_to_string(s.path()).unwrap()).unwrap();
        assert!(s.rotate_data_key("model-key-a").unwrap());
        assert!(!s.rotate_data_key("nothing-here").unwrap());
        let after: File =
            serde_json::from_str(&std::fs::read_to_string(s.path()).unwrap()).unwrap();
        assert_ne!(
            before.secrets["model-key-a"].wk,
            after.secrets["model-key-a"].wk
        );
        assert_ne!(
            before.secrets["model-key-a"].ct,
            after.secrets["model-key-a"].ct
        );
        assert_eq!(
            before.secrets["model-key-a"].created,
            after.secrets["model-key-a"].created
        );
        assert_eq!(s.get("model-key-a").unwrap().as_deref(), Some(SENTINEL));
        assert_eq!(s.rotate_all_data_keys().unwrap(), 1);
    }

    #[test]
    fn kek_rotation_rewraps_everything_and_the_old_key_stops_working() {
        let dir = tempfile::tempdir().unwrap();
        let old = local();
        let s = store(dir.path(), "box-a", old.clone());
        s.set("model-key-a", SENTINEL).unwrap();
        s.set("restic-password", "pw-12345678").unwrap();
        let new: Arc<dyn KeyProvider> = Arc::new(LocalKekProvider::random("local").unwrap());
        assert_eq!(s.rotate_kek(new.clone(), None).unwrap(), 2);
        let n = store(dir.path(), "box-a", new);
        assert_eq!(n.get("model-key-a").unwrap().as_deref(), Some(SENTINEL));
        assert_eq!(
            n.get("restic-password").unwrap().as_deref(),
            Some("pw-12345678")
        );
        assert!(store(dir.path(), "box-a", old).get("model-key-a").is_err());
    }

    /// A key that may encrypt and may not decrypt (a KMS grant with only one of the two, an encryption context that does not
    /// match): found while the old file is still the store, not by a service that cannot start afterwards.
    #[test]
    fn a_kek_rotation_to_a_key_that_cannot_give_the_data_key_back_changes_nothing() {
        struct EncryptOnly(LocalKekProvider);
        impl KeyProvider for EncryptOnly {
            fn label(&self) -> String {
                "kms".into()
            }
            fn wrap(&self, k: &[u8; 32], aad: &[u8]) -> Result<Vec<u8>, SecretError> {
                self.0.wrap(k, aad)
            }
            fn unwrap(&self, _: &[u8], _: &[u8]) -> Result<Zeroizing<Vec<u8>>, SecretError> {
                Err(err("AccessDenied: kms:Decrypt"))
            }
        }
        let dir = tempfile::tempdir().unwrap();
        let old = local();
        let s = store(dir.path(), "box-a", old.clone());
        s.set("model-key-a", SENTINEL).unwrap();
        let bytes = std::fs::read(s.path()).unwrap();
        let new: Arc<dyn KeyProvider> =
            Arc::new(EncryptOnly(LocalKekProvider::random("kms").unwrap()));
        // the probe a move makes before it stops anything finds it too, and passes for a key that works
        assert!(probe(new.as_ref(), "box-a").is_err());
        assert!(probe(&LocalKekProvider::random("kms").unwrap(), "box-a").is_ok());
        assert!(s.rotate_kek(new, None).is_err());
        assert_eq!(
            std::fs::read(s.path()).unwrap(),
            bytes,
            "the file is as it was"
        );
        assert_eq!(
            store(dir.path(), "box-a", old)
                .get("model-key-a")
                .unwrap()
                .as_deref(),
            Some(SENTINEL)
        );
    }

    #[test]
    fn a_passphrase_kek_needs_the_same_passphrase_and_salt() {
        let dir = tempfile::tempdir().unwrap();
        let salt = [7u8; 16];
        let p: Arc<dyn KeyProvider> = Arc::new(
            LocalKekProvider::from_passphrase("passphrase", "correct horse battery", &salt)
                .unwrap(),
        );
        store(dir.path(), "box-a", p)
            .set("model-key-a", SENTINEL)
            .unwrap();
        let ok: Arc<dyn KeyProvider> = Arc::new(
            LocalKekProvider::from_passphrase("passphrase", "correct horse battery", &salt)
                .unwrap(),
        );
        assert_eq!(
            store(dir.path(), "box-a", ok)
                .get("model-key-a")
                .unwrap()
                .as_deref(),
            Some(SENTINEL)
        );
        let bad: Arc<dyn KeyProvider> = Arc::new(
            LocalKekProvider::from_passphrase("passphrase", "wrong horse battery!", &salt).unwrap(),
        );
        assert!(store(dir.path(), "box-a", bad).get("model-key-a").is_err());
        assert!(LocalKekProvider::from_passphrase("passphrase", "short", &salt).is_err());
    }

    use crate::aws_native::fakes::{self, Fake, Kms};
    use crate::aws_native::AwsJson;

    fn kms_against(f: &Fake, region: Option<&str>) -> KmsProvider {
        KmsProvider::build(
            AwsJson::with_imds(&f.imds),
            "alias/ozbox-fleet",
            region,
            Some(&f.kms),
        )
        .unwrap()
    }

    /// What the fake KMS verified for every request it saw: it recomputes each signature from the raw request, by its own
    /// canonicalisation, and refuses a request whose SignedHeaders leave out `content-type` or `x-amz-target`.
    fn assert_signed_by_the_role(s: &fakes::Seen, f: &Fake, region: &str) {
        assert_eq!(fakes::verify_sigv4(s), Ok(()));
        assert!(f.sig_errors.lock().unwrap().is_empty());
        let auth = s.header("authorization").unwrap();
        assert!(auth.contains(&format!("Credential={}/", fakes::ACCESS_KEY)));
        assert!(auth.contains(&format!("/{region}/kms/aws4_request")));
        assert!(auth.contains(
            "SignedHeaders=content-type;host;x-amz-date;x-amz-security-token;x-amz-target,"
        ));
        // the session token travels as the role's temporary credential, and the secret key never
        assert_eq!(s.header("x-amz-security-token"), Some(fakes::SESSION_TOKEN));
        assert!(!s.body.contains(fakes::SECRET_KEY));
        assert!(s
            .headers
            .iter()
            .all(|(_, v)| !v.contains(fakes::SECRET_KEY)));
    }

    #[test]
    fn kms_round_trips_natively_signed_by_the_roles_credentials() {
        let f = Fake::start();
        let kms = kms_against(&f, Some("us-east-1"));
        let dk = [9u8; 32];
        let aad = aad_for("sid", "box-a", "model-key-a");
        let wrapped = kms.wrap(&dk, &aad).unwrap();
        let back = kms.unwrap(&wrapped, &aad).unwrap();
        assert_eq!(back.as_slice(), &dk);

        let seen = f.kms_seen.lock().unwrap().clone();
        assert_eq!(seen.len(), 2);
        for (s, target) in seen
            .iter()
            .zip(["TrentService.Encrypt", "TrentService.Decrypt"])
        {
            assert_eq!(s.method, "POST");
            assert_eq!(s.header("x-amz-target"), Some(target));
            assert_eq!(s.header("content-type"), Some("application/x-amz-json-1.1"));
            assert_signed_by_the_role(s, &f, "us-east-1");
            // the same encryption context the key policy's condition and the audit trail have always seen
            let v: serde_json::Value = serde_json::from_str(&s.body).unwrap();
            assert_eq!(
                v["EncryptionContext"],
                serde_json::json!({"store": "sid", "scope": "box-a", "name": "model-key-a"})
            );
        }
        let enc: serde_json::Value = serde_json::from_str(&seen[0].body).unwrap();
        assert_eq!(enc["KeyId"], "alias/ozbox-fleet");
        assert_eq!(enc["Plaintext"], encode_std(&dk));
        let dec: serde_json::Value = serde_json::from_str(&seen[1].body).unwrap();
        assert_eq!(dec["CiphertextBlob"], encode_std(&wrapped));
    }

    #[test]
    fn kms_credentials_come_from_the_instance_role_and_are_kept_until_they_expire() {
        let f = Fake::start();
        let kms = kms_against(&f, Some("us-east-1"));
        let aad = aad_for("s", "b", "n");
        kms.wrap(&[1; 32], &aad).unwrap();
        kms.wrap(&[2; 32], &aad).unwrap();
        // one token, one role lookup and one credentials read served both calls
        assert_eq!(f.imds_seen.lock().unwrap().len(), 3);
        assert_eq!(f.imds_seen.lock().unwrap()[0].method, "PUT");

        // credentials about to expire are read again for the next call
        *f.expiration.lock().unwrap() = "2001-01-01T00:00:00Z".into();
        let kms = kms_against(&f, Some("us-east-1"));
        f.imds_seen.lock().unwrap().clear();
        kms.wrap(&[1; 32], &aad).unwrap();
        kms.wrap(&[2; 32], &aad).unwrap();
        assert_eq!(f.imds_seen.lock().unwrap().len(), 6);
    }

    #[test]
    fn the_region_comes_from_the_setting_then_the_key_arn_then_the_machine() {
        let f = Fake::start();
        let aad = aad_for("s", "b", "n");
        let signed_region = |k: &KmsProvider| {
            f.kms_seen.lock().unwrap().clear();
            k.wrap(&[1; 32], &aad).unwrap();
            let s = f.kms_seen.lock().unwrap()[0].clone();
            let auth = s.header("authorization").unwrap().to_string();
            auth.split('/').nth(2).unwrap().to_string()
        };
        let arn = "arn:aws:kms:ap-south-1:123456789012:key/abcd";
        let by_arn =
            KmsProvider::build(AwsJson::with_imds(&f.imds), arn, None, Some(&f.kms)).unwrap();
        assert_eq!(signed_region(&by_arn), "ap-south-1");
        let set = KmsProvider::build(
            AwsJson::with_imds(&f.imds),
            arn,
            Some("us-west-2"),
            Some(&f.kms),
        )
        .unwrap();
        assert_eq!(signed_region(&set), "us-west-2");
        // an alias with no setting: this machine's own region, from the metadata service
        let none =
            KmsProvider::build(AwsJson::with_imds(&f.imds), "alias/x", None, Some(&f.kms)).unwrap();
        if std::env::var("AWS_REGION").is_err() && std::env::var("AWS_DEFAULT_REGION").is_err() {
            assert_eq!(signed_region(&none), "eu-west-2");
        }
    }

    #[test]
    fn kms_works_with_no_aws_command_anywhere() {
        // Run the round trip in a child process whose PATH holds nothing, so any attempt to start the `aws` command (the
        // defect this replaces) would fail it. The child is this same test binary, asked for one test.
        if std::env::var("OZBOX_KMS_NO_AWS_CHILD").is_ok() {
            let f = Fake::start();
            let kms = kms_against(&f, Some("us-east-1"));
            let aad = aad_for("s", "b", "n");
            let w = kms.wrap(&[5; 32], &aad).unwrap();
            assert_eq!(kms.unwrap(&w, &aad).unwrap().as_slice(), &[5u8; 32]);
            return;
        }
        let empty = tempfile::tempdir().unwrap();
        let out = std::process::Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "secrets_enc::tests::kms_works_with_no_aws_command_anywhere",
                "--nocapture",
            ])
            .env("OZBOX_KMS_NO_AWS_CHILD", "1")
            .env("PATH", empty.path())
            .output()
            .unwrap();
        assert!(
            out.status.success(),
            "{}{}",
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr)
        );
        let text = String::from_utf8_lossy(&out.stdout);
        assert!(text.contains("1 passed"), "{text}");
    }

    #[test]
    fn the_secrets_path_never_starts_the_aws_command() {
        // a guard on the source: a store that needs a program the image does not carry is the defect
        for (name, src) in [
            ("secrets_enc.rs", include_str!("secrets_enc.rs")),
            ("aws_native.rs", include_str!("aws_native.rs")),
        ] {
            let code: String = src
                .split("\nmod tests {")
                .next()
                .unwrap()
                .lines()
                .filter(|l| !l.trim_start().starts_with("//"))
                .collect::<Vec<_>>()
                .join("\n");
            let needle = ["CommandSpec::new(", "\"aws\""].concat();
            assert!(!code.contains(&needle), "{name} starts the aws command");
            assert!(!code.contains(&["program: ", "\"aws\""].concat()), "{name}");
            assert!(!code.contains(&["Command", "::new("].concat()), "{name}");
        }
    }

    #[test]
    fn kms_failures_are_one_plain_message_with_nothing_from_the_service() {
        let f = Fake::start();
        let aad = aad_for("s", "b", "n");
        for (mode, want) in [
            (Kms::Denied, KEK_DENIED),
            (Kms::Throttled, KEK_UNAVAILABLE),
            (Kms::ServerError, KEK_UNAVAILABLE),
        ] {
            *f.mode.lock().unwrap() = mode;
            let kms = kms_against(&f, Some("us-east-1"));
            for e in [
                kms.unwrap(b"x", &aad).unwrap_err(),
                kms.wrap(&[1; 32], &aad).map(|_| ()).unwrap_err(),
            ] {
                assert_eq!(e.0, want, "{mode:?}");
                assert!(!e.0.contains("arn:") && !e.0.contains("assumed-role"));
                assert!(!e.0.contains(fakes::SECRET_KEY) && !e.0.contains(fakes::SESSION_TOKEN));
            }
        }
        // a name that merely contains the refusal's is not a refusal, and a bad answer is unavailable, not a panic
        *f.mode.lock().unwrap() = Kms::Works;
        let kms = kms_against(&f, Some("us-east-1"));
        assert_eq!(
            kms.unwrap(b"not-a-blob", &aad).unwrap_err().0,
            KEK_UNAVAILABLE
        );
        assert!(KmsProvider::new("bad key;id", None).is_err());
        assert!(KmsProvider::new("alias/x", Some("US EAST")).is_err());
    }

    #[test]
    fn an_unreachable_key_service_or_metadata_service_is_unavailable_never_denied() {
        let aad = aad_for("s", "b", "n");
        // the key service: nothing listens
        let f = Fake::start();
        let dead = {
            let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
            format!("http://{}", l.local_addr().unwrap())
        };
        let kms = KmsProvider::build(
            AwsJson::with_imds(&f.imds),
            "alias/x",
            Some("us-east-1"),
            Some(&dead),
        )
        .unwrap();
        assert_eq!(kms.wrap(&[1; 32], &aad).unwrap_err().0, KEK_UNAVAILABLE);
        // the metadata service: down, so no credentials
        *f.imds_up.lock().unwrap() = false;
        let kms = kms_against(&f, Some("us-east-1"));
        assert_eq!(kms.wrap(&[1; 32], &aad).unwrap_err().0, KEK_UNAVAILABLE);
        assert!(
            f.kms_seen.lock().unwrap().is_empty(),
            "a call was made with no credentials"
        );
        // and no metadata service at all
        let kms = KmsProvider::build(
            AwsJson::with_imds(&dead),
            "alias/x",
            Some("us-east-1"),
            Some(&f.kms),
        )
        .unwrap();
        assert_eq!(kms.unwrap(b"x", &aad).unwrap_err().0, KEK_UNAVAILABLE);
    }

    #[test]
    fn the_data_key_cache_spares_the_provider_and_is_dropped_on_change() {
        struct Counting(LocalKekProvider, Mutex<u32>);
        impl KeyProvider for Counting {
            fn label(&self) -> String {
                self.0.label()
            }
            fn wrap(&self, d: &[u8; 32], a: &[u8]) -> Result<Vec<u8>, SecretError> {
                self.0.wrap(d, a)
            }
            fn unwrap(&self, w: &[u8], a: &[u8]) -> Result<Zeroizing<Vec<u8>>, SecretError> {
                *self.1.lock().unwrap() += 1;
                self.0.unwrap(w, a)
            }
        }
        let dir = tempfile::tempdir().unwrap();
        let c = Arc::new(Counting(
            LocalKekProvider::random("local").unwrap(),
            Mutex::new(0),
        ));
        let s = store(dir.path(), "box-a", c.clone());
        s.set("model-key-a", "v1234").unwrap();
        s.get("model-key-a").unwrap();
        s.get("model-key-a").unwrap();
        assert_eq!(*c.1.lock().unwrap(), 1);
        s.set("model-key-a", "v5678").unwrap();
        assert_eq!(s.get("model-key-a").unwrap().as_deref(), Some("v5678"));
        assert_eq!(*c.1.lock().unwrap(), 2);
    }

    #[test]
    fn workload_secrets_are_scoped_listed_by_name_and_resolved_by_allow_list() {
        let dir = tempfile::tempdir().unwrap();
        let s = store(dir.path(), "box-a", local());
        let n = workload_name("app", "staging", "SUPABASE_ANON_KEY").unwrap();
        s.set_with_meta(
            &n,
            SENTINEL,
            Meta {
                owner: "me".into(),
                production: false,
                ..Default::default()
            },
        )
        .unwrap();
        let p = workload_name("app", "prod", "STRIPE_KEY").unwrap();
        s.set_with_meta(
            &p,
            "sk-live-xyz-1234",
            Meta {
                owner: "me".into(),
                production: true,
                ..Default::default()
            },
        )
        .unwrap();
        assert_eq!(s.names("workload.app.staging.").unwrap(), vec![n.clone()]);
        assert!(s.meta(&p).unwrap().unwrap().production);
        let ok = vec!["SUPABASE_ANON_KEY".to_string()];
        let r = s
            .resolve_refs(
                "app",
                "staging",
                "KEY={{secret:SUPABASE_ANON_KEY}};x",
                &ok,
                false,
            )
            .unwrap();
        assert_eq!(r.as_str(), format!("KEY={SENTINEL};x"));
        // not on the allow-list, other environment, production, unset: each refuses without a value
        for (env, name, allow) in [
            ("staging", "OTHER", vec!["OTHER".to_string()]),
            ("staging", "SUPABASE_ANON_KEY", vec![]),
            ("prod", "STRIPE_KEY", vec!["STRIPE_KEY".to_string()]),
        ] {
            let e = s
                .resolve_refs("app", env, &format!("{{{{secret:{name}}}}}"), &allow, false)
                .unwrap_err();
            assert!(!e.0.contains(SENTINEL) && !e.0.contains("sk-live"));
        }
        assert!(
            workload_name("a", "b", "lower").is_err() && workload_name("a b", "b", "X").is_err()
        );
        // rotation keeps the metadata
        s.rotate_all_data_keys().unwrap();
        assert!(s.meta(&p).unwrap().unwrap().production);
        // another project's name cannot be opened as this one's (the name is in the seal)
        assert!(!s
            .exists(&workload_name("other", "staging", "SUPABASE_ANON_KEY").unwrap())
            .unwrap());
    }

    #[test]
    fn the_secret_appears_in_no_error_and_no_debug_text() {
        let dir = tempfile::tempdir().unwrap();
        let s = store(dir.path(), "box-a", local());
        s.set("model-key-a", SENTINEL).unwrap();
        let bad = s.set("model-key-b", "has space");
        assert!(bad.is_err());
        assert!(!format!("{:?}", bad.unwrap_err()).contains("space-value"));
        let ages = s.ages().unwrap();
        assert!(ages.contains_key("model-key-a"));
        assert!(!format!("{ages:?}").contains(SENTINEL));
    }

    /// ADR 0029 Amendment 12 (owner, 2026-11-13): the public mark is inside the seal. Flipping it in the file, without the store key,
    /// never makes a secret public (the entry stops opening), and an entry from before the mark stays secret.
    #[test]
    fn the_public_mark_is_inside_the_seal_and_cannot_be_flipped_in_the_file() {
        let d = tempfile::tempdir().unwrap();
        let s = store(d.path(), "box-a", local());
        let meta = |public| Meta {
            owner: "me".into(),
            production: false,
            public,
        };
        let p = "workload.app.staging.PUB";
        let q = "workload.app.staging.SEC";
        s.set_with_meta(p, "https://staging.example.com", meta(true))
            .unwrap();
        s.set_with_meta(q, "an-ordinary-secret-value", meta(false))
            .unwrap();
        let declared = |n: &str| vec![n.to_string()];
        assert_eq!(
            s.resolve_public("app", "staging", "PUB", &declared("PUB"))
                .unwrap()
                .as_str(),
            "https://staging.example.com"
        );
        // rotation keeps the mark and the value
        s.rotate_all_data_keys().unwrap();
        assert!(s.meta(p).unwrap().unwrap().public);
        assert_eq!(
            s.get(p).unwrap().as_deref(),
            Some("https://staging.example.com")
        );
        // flip the file: secret -> public, and public -> secret
        let text = std::fs::read_to_string(s.path()).unwrap();
        let mut v: serde_json::Value = serde_json::from_str(&text).unwrap();
        v["secrets"][q]["meta"]["public"] = serde_json::json!(true);
        v["secrets"][p]["meta"]
            .as_object_mut()
            .unwrap()
            .remove("public");
        std::fs::write(s.path(), serde_json::to_string(&v).unwrap()).unwrap();
        let s2 = &s;
        // the secret that was flipped to public does not open at all, so it is never delivered
        assert!(s2
            .resolve_public("app", "staging", "SEC", &declared("SEC"))
            .is_err());
        assert!(s2.get(q).is_err());
        // and the public one that was flipped to secret does not open either: it is not readable under the wrong form
        assert!(s2.get(p).is_err());
        // an entry made before the mark existed (no mark, the original seal) is read as secret: its seal is unchanged
        assert_eq!(aad_for_entry("s", "c", "n", false), aad_for("s", "c", "n"));
        assert_ne!(aad_for_entry("s", "c", "n", true), aad_for("s", "c", "n"));
        let old = tempfile::tempdir().unwrap();
        let o = store(old.path(), "box-a", local());
        o.set_with_meta(q, "an-ordinary-secret-value", Meta::default())
            .unwrap();
        assert!(!o.meta(q).unwrap().unwrap().public);
        assert_eq!(
            o.get(q).unwrap().as_deref(),
            Some("an-ordinary-secret-value")
        );
        assert!(o
            .resolve_public("app", "staging", "SEC", &declared("SEC"))
            .is_err());
    }
}
