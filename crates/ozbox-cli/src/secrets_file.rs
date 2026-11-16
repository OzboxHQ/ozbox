//! Choosing the secret store for this run. `OZBOX_SECRET_STORE` picks it:
//!
//! * unset: on a box (its secrets service's socket exists), that service, as `socket` would pick it; anywhere else the
//!   operating system's keychain (a laptop). A box has no desktop keychain, so a command the box user runs by hand
//!   (`ozbox tunnel setup` on the box) would otherwise fail with "no keychain was found";
//! * `memory`: forgets everything when the process stops (tests, demos);
//! * `file`: the encrypted store (`secrets_enc`) at `OZBOX_SECRET_FILE`. The plaintext file store that used to live here
//!   is gone: a file written by it is encrypted on first start and the plaintext is destroyed;
//! * `socket`: the box's secrets service (`secrets_service`) at `OZBOX_SECRET_SOCKET`, for a process that runs as the box
//!   user and so must not be able to read the store itself.
//!
//! The encrypted store's key-encryption key comes from `OZBOX_SECRET_KEK`: `kms` (with `OZBOX_KMS_KEY_ID` and optionally
//! `OZBOX_KMS_REGION`), `keychain`, or `tpm2`. Left unset, a TPM is used when the machine has one, then KMS when a key id
//! is given, then the keychain. `OZBOX_SECRET_SCOPE` names the box or fleet the seals are bound to.

use std::path::{Path, PathBuf};
use std::sync::Arc;

use ozbox_core::{CommandRunner, SystemRunner};

use crate::secrets::{SecretError, SecretStore, UnavailableSecrets};
use crate::secrets_enc::{keychain_provider, EncryptedSecrets, KeyProvider, KmsProvider, TpmKek};

fn env(name: &str) -> Option<String> {
    std::env::var(name).ok().filter(|v| !v.is_empty())
}

/// The key provider of the named kind (`kms`, `tpm2`, `keychain`), for the store at `path`.
pub fn provider_named(kind: &str, path: &Path) -> Result<Arc<dyn KeyProvider>, SecretError> {
    let runner: Arc<dyn CommandRunner> = Arc::new(SystemRunner);
    match kind {
        "kms" => {
            let id = env("OZBOX_KMS_KEY_ID").ok_or_else(|| {
                SecretError("OZBOX_SECRET_KEK=kms needs OZBOX_KMS_KEY_ID to name the key".into())
            })?;
            Ok(Arc::new(KmsProvider::new(
                &id,
                env("OZBOX_KMS_REGION").as_deref(),
            )?))
        }
        "tpm2" => TpmKek::load_or_create(&*runner, path.parent().unwrap_or_else(|| Path::new("."))),
        "keychain" => keychain_provider(&*crate::secrets::KeychainSecrets::detect()),
        "file" => {
            // A store whose key file is gone must not be given a new key: that would make it unopenable for good, where
            // the escrowed key (see `secrets_escrow`) can still bring it back.
            let kek = path.with_file_name(crate::secrets_persist::KEY_FILE);
            if !kek.exists() && path.exists() {
                return Err(SecretError(KEY_FILE_MISSING.into()));
            }
            crate::secrets_enc::file_kek_provider(&kek)
        }
        "passphrase" => Err(SecretError(
            "a passphrase key is entered when the secrets service starts (ozbox secrets serve --passphrase-stdin), not here".into(),
        )),
        _ => Err(SecretError(
            "OZBOX_SECRET_KEK must be kms, tpm2, keychain or file".into(),
        )),
    }
}

/// What a person is told when nothing can hold the store's key-encryption key.
pub const NO_KEK: &str = "no key for the encrypted secret store is configured. Give the box a KMS key (the box module's secrets_key_arn on AWS), or a TPM, or set OZBOX_SECRET_ALLOW_FILE_KEK=1 in /etc/ozbox/secrets.env to keep the key in a file only the secrets user can read (it protects against the box user and agents, not against someone who can read the disk as root)";

/// What a person is told when the store is there and the file that held its key is not.
pub const KEY_FILE_MISSING: &str = "the store's key file is missing, so the store cannot be opened; a new key is never made for an existing store";

/// Whether the environment picks the file-kept key (no KMS key, no TPM, file allowed): the box whose key is escrowed.
pub fn file_kek_selected() -> bool {
    kek_kind_with(&env, TpmKek::available()) == Some("file")
}

/// Which kind of key protects the store, as [`provider_from_env`] would choose it from these settings (`get`) on a
/// machine that has a TPM or not. `None` when nothing is configured. The one place that order is written down.
pub fn kek_kind_with(get: &dyn Fn(&str) -> Option<String>, tpm: bool) -> Option<&'static str> {
    let get = |k: &str| get(k).filter(|v| !v.is_empty());
    match get("OZBOX_SECRET_KEK").as_deref() {
        Some("kms") => Some("kms"),
        Some("tpm2") => Some("tpm2"),
        Some("keychain") => Some("keychain"),
        Some("file") => Some("file"),
        Some("passphrase") => Some("passphrase"),
        Some(_) => None,
        None if tpm => Some("tpm2"),
        None if get("OZBOX_KMS_KEY_ID").is_some() => Some("kms"),
        None if cfg!(target_os = "macos") => Some("keychain"),
        None if get("OZBOX_SECRET_ALLOW_FILE_KEK").as_deref() == Some("1") => Some("file"),
        None => None,
    }
}

/// The settings of a `KEY=value` file such as `/etc/ozbox/secrets.env` (what the secrets service's unit reads), for a
/// process that is not the service and does not have them in its environment (the root helper). Blank and `#` lines are
/// skipped; nothing is expanded.
pub fn env_file(path: &Path) -> std::collections::BTreeMap<String, String> {
    std::fs::read_to_string(path)
        .unwrap_or_default()
        .lines()
        .map(str::trim)
        .filter(|l| !l.is_empty() && !l.starts_with('#'))
        .filter_map(|l| l.split_once('='))
        .map(|(k, v)| (k.trim().to_string(), v.trim().to_string()))
        .collect()
}

/// The key provider named by the environment, for the store at `path`.
pub fn provider_from_env(path: &Path) -> Result<Arc<dyn KeyProvider>, SecretError> {
    match env("OZBOX_SECRET_KEK").as_deref() {
        Some(k) => provider_named(k, path),
        None if TpmKek::available() => provider_named("tpm2", path),
        None if env("OZBOX_KMS_KEY_ID").is_some() => provider_named("kms", path),
        None if cfg!(target_os = "macos") => provider_named("keychain", path),
        // a box with neither KMS nor a TPM: the setup script says so explicitly, and the status says what protects the store
        None if env("OZBOX_SECRET_ALLOW_FILE_KEK").as_deref() == Some("1") => {
            provider_named("file", path)
        }
        None => Err(SecretError(NO_KEK.into())),
    }
}

/// The encrypted store at `path`, migrating an old plaintext file first. Fails closed with a message that is safe to show.
pub fn open_encrypted(
    path: PathBuf,
    scope: &str,
    provider: Arc<dyn KeyProvider>,
) -> Result<EncryptedSecrets, SecretError> {
    let s = EncryptedSecrets::new(path, scope, provider)?;
    s.migrate_plaintext()?;
    Ok(s)
}

fn unavailable(msg: String) -> Arc<dyn SecretStore> {
    // The message is fixed text built from our own words, so keeping it for the life of the process is fine.
    Arc::new(UnavailableSecrets(Box::leak(msg.into_boxed_str())))
}

/// The store for this run.
pub fn select() -> Arc<dyn SecretStore> {
    match env("OZBOX_SECRET_STORE").as_deref() {
        Some("memory") => Arc::new(crate::secrets::MemorySecrets::default()),
        Some("file") => {
            let Some(path) = env("OZBOX_SECRET_FILE") else {
                return unavailable(
                    "OZBOX_SECRET_STORE=file needs OZBOX_SECRET_FILE to name the file".into(),
                );
            };
            let path = PathBuf::from(path);
            let scope = env("OZBOX_SECRET_SCOPE").unwrap_or_else(|| "local".into());
            match provider_from_env(&path).and_then(|p| open_encrypted(path, &scope, p)) {
                Ok(s) => Arc::new(s),
                Err(e) => unavailable(e.0),
            }
        }
        #[cfg(unix)]
        Some("socket") => match env("OZBOX_SECRET_SOCKET") {
            // The supervisor's own socket serves the box socket's operations and the broker's both, so a process told about it
            // (`OZBOX_SUPERVISOR_SOCKET`) sends everything there.
            Some(p) => Arc::new(match env("OZBOX_SUPERVISOR_SOCKET") {
                Some(sup) => crate::secrets_service::SocketSecrets::supervisor(PathBuf::from(sup)),
                None => crate::secrets_service::SocketSecrets::new(PathBuf::from(p)),
            }),
            None => unavailable("OZBOX_SECRET_STORE=socket needs OZBOX_SECRET_SOCKET".into()),
        },
        // a mistyped value must not fall through to the box's own service (or the keychain): that is a different store from
        // the one the person asked for
        Some(other) if !other.is_empty() => unavailable(format!(
            "OZBOX_SECRET_STORE={other} is not a store this program knows (memory, file or socket)"
        )),
        _ => default_store(Path::new(crate::tunnel::unit::SECRET_SOCKET)),
    }
}

/// With no `OZBOX_SECRET_STORE`: the box's secrets service when its socket is there, else the keychain.
fn default_store(box_socket: &Path) -> Arc<dyn SecretStore> {
    #[cfg(unix)]
    if box_socket.exists() {
        return Arc::new(crate::secrets_service::SocketSecrets::new(
            box_socket.to_path_buf(),
        ));
    }
    let _ = box_socket;
    Arc::from(crate::secrets::KeychainSecrets::detect())
}

/// The encrypted store named by the environment, concrete, for the commands that rotate and report on it.
pub fn open_from_env() -> Result<EncryptedSecrets, SecretError> {
    let path =
        PathBuf::from(env("OZBOX_SECRET_FILE").ok_or_else(|| {
            SecretError("OZBOX_SECRET_FILE must name the encrypted store".into())
        })?);
    let scope = env("OZBOX_SECRET_SCOPE").unwrap_or_else(|| "local".into());
    let p = provider_from_env(&path)?;
    open_encrypted(path, &scope, p)
}

#[cfg(all(test, unix))]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;

    /// Found on a real box (2026-11-12): `ozbox tunnel setup` run by hand on the box looked for a desktop keychain and
    /// failed "no keychain was found". With no store named, a box's own secrets service is the store.
    #[test]
    fn with_no_store_named_a_box_uses_its_secrets_service_and_a_laptop_its_keychain() {
        let d = tempfile::tempdir().unwrap();
        let sock = d.path().join("box.sock");
        let _listener = std::os::unix::net::UnixListener::bind(&sock).unwrap();
        assert_eq!(
            default_store(&sock).label(),
            "the secrets service on this box"
        );
        let absent = d.path().join("none.sock");
        assert_ne!(
            default_store(&absent).label(),
            "the secrets service on this box"
        );
    }

    /// Root reads the service's settings from its file (it does not have them in its environment) and comes to the same
    /// choice the service makes, in the same order: an explicit kind, a TPM, a KMS key, then the file when allowed.
    #[test]
    fn the_kind_of_key_is_chosen_the_same_way_from_a_settings_file() {
        let d = tempfile::tempdir().unwrap();
        let f = d.path().join("secrets.env");
        let kind = |text: &str, tpm: bool| {
            std::fs::write(&f, text).unwrap();
            let m = env_file(&f);
            kek_kind_with(&|k| m.get(k).cloned(), tpm)
        };
        let file = "OZBOX_SECRET_SCOPE=dev\nOZBOX_KMS_KEY_ID=\nOZBOX_KMS_REGION=\nOZBOX_SECRET_ALLOW_FILE_KEK=1\n";
        let kms =
            "OZBOX_SECRET_SCOPE=dev\nOZBOX_KMS_KEY_ID=arn:aws:kms:us-east-1:123456789012:key/x\n";
        if !cfg!(target_os = "macos") {
            assert_eq!(kind(file, false), Some("file"));
        }
        assert_eq!(kind(file, true), Some("tpm2"));
        assert_eq!(kind(kms, false), Some("kms"));
        assert_eq!(
            kind("# a comment\nOZBOX_SECRET_KEK=kms\n", true),
            Some("kms")
        );
        assert_eq!(kind("OZBOX_SECRET_KEK=floppy\n", false), None);
    }

    #[test]
    fn a_box_with_no_kms_or_tpm_keeps_its_key_in_a_file_only_its_user_reads_and_reopens_with_it() {
        let d = tempfile::tempdir().unwrap();
        let store = d.path().join("secrets.json");
        let p = provider_named("file", &store).unwrap();
        let kek = d.path().join("kek.key");
        assert_eq!(
            std::fs::metadata(&kek).unwrap().permissions().mode() & 0o777,
            0o600
        );
        // the same key comes back on the next start, so what was sealed opens
        let s = open_encrypted(store.clone(), "box-a", p).unwrap();
        s.set("model-key-x", "SENTINEL-value-123456").unwrap();
        drop(s);
        let again = open_encrypted(
            store,
            "box-a",
            provider_named("file", &d.path().join("secrets.json")).unwrap(),
        )
        .unwrap();
        assert_eq!(
            again.get("model-key-x").unwrap().as_deref(),
            Some("SENTINEL-value-123456")
        );
        // the key is not in the store file
        let text = std::fs::read_to_string(d.path().join("secrets.json")).unwrap();
        assert!(
            !text.contains("SENTINEL-value")
                && !text.contains(&std::fs::read_to_string(&kek).unwrap())
        );
    }

    #[test]
    fn with_nothing_configured_the_answer_says_what_to_set_and_what_each_choice_protects() {
        assert!(
            NO_KEK.contains("secrets_key_arn")
                && NO_KEK.contains("TPM")
                && NO_KEK.contains("ALLOW_FILE_KEK")
        );
        assert!(NO_KEK.contains("not against someone who can read the disk"));
    }
}
