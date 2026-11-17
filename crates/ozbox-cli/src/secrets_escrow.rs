//! Escrow of a file-kept store key off the box (ADR 0029, Amendment 6 §9, as built in Amendment 7).
//!
//! A box with neither KMS nor a TPM keeps its store's key-encryption key in a file on the system disk, readable by the
//! secrets user and root only (`kek.key`). That file is never copied to `/work` (see `secrets_persist`), so a snapshot, a
//! clone or a backup of `/work` cannot open the store. An upgrade replaces the system disk, though, and the key would go
//! with it. So the key is **escrowed in the vault the box already uses for its own secrets**, under a path that is this
//! box's alone, and fetched back by the secrets service when a replaced system disk has the store but not its key.
//!
//! * Where: OpenBao (KV version 2), mount `OZBOX_BOX_SECRETS_MOUNT` (default `secret`), at
//!   `<OZBOX_BOX_SECRETS_PATH>/_escrow/<box>`, field `kek`. The `_` keeps it out of every role's own folder (a role is
//!   lowercase letters, digits and dashes), so the loader never reads it as one of the box's secrets.
//! * With what: the box-secrets credential (`BAO_ADDR`, `BAO_TOKEN`), which systemd gives the secrets user's units from
//!   root-only files. The box user never holds it. The vault policy for the token must allow `create`, `update` and `read`
//!   on that one path.
//! * How: natively, over https (see `openbao`: no `bao` command, which the box image does not carry). The key travels only
//!   in the body of the one request that writes it, and the token only as a header read at the moment of the request; never
//!   in an argument, a URL, a log or an error.
//!
//! Not built: escrow in the laptop keychain, put back by `ozbox upgrade`. Without the ingress account of ADR 0029
//! Amendment 6 §3 every route from the laptop into the box passes through a process of the box user, which could keep the
//! key; so a box without a vault has no escrow, and a replaced system disk starts a new store (`ozbox admin <box> -- recover-secrets`, approved by the key pinned when the box was made).

use zeroize::Zeroizing;

use crate::openbao::Bao;

/// Where the escrowed key lives, and the vault that holds it (an address; the token is read at each request).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Escrow {
    pub mount: String,
    pub path: String,
    pub vault: Bao,
}

fn plain(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= 200
        && s.bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"-_/.".contains(&b))
        && !s.contains("..")
}

impl Escrow {
    /// The escrow named by the environment the units give the secrets user, for the box `scope`. `None` when the box has no
    /// vault, or no token for it.
    pub fn from_env(get: &dyn Fn(&str) -> Option<String>, scope: &str) -> Option<Escrow> {
        if get("OZBOX_BOX_SECRETS_BACKEND").as_deref() != Some("openbao") {
            return None;
        }
        let vault = Bao::new(&get("BAO_ADDR")?)?;
        get("BAO_TOKEN").filter(|t| !t.is_empty())?;
        let prefix = get("OZBOX_BOX_SECRETS_PATH").unwrap_or_default();
        let prefix = prefix.trim_matches('/');
        let mount = get("OZBOX_BOX_SECRETS_MOUNT").unwrap_or_else(|| "secret".into());
        let path = if prefix.is_empty() {
            format!("_escrow/{scope}")
        } else {
            format!("{prefix}/_escrow/{scope}")
        };
        (plain(&mount) && plain(&path) && plain(scope)).then_some(Escrow { mount, path, vault })
    }

    /// Whether the box declares an escrow at all (box secrets on OpenBao at an https address), whether or not its token is
    /// here. A rebuilt system disk loses a token placed by hand, so "declared, no token" is a token to place again, never a
    /// store with no escrow (a security review, 2026-11-11: it was read as one, which would have let its store be set aside).
    pub fn declared(get: &dyn Fn(&str) -> Option<String>) -> bool {
        get("OZBOX_BOX_SECRETS_BACKEND").as_deref() == Some("openbao")
            && get("BAO_ADDR").is_some_and(|a| a.starts_with("https://"))
    }

    /// The escrowed key, or why it could not be had. The vault's own words are not repeated (they can name a path).
    pub fn fetch(&self) -> Result<Zeroizing<String>, String> {
        let fields = self
            .vault
            .read(&self.mount, &self.path)
            .ok()
            .flatten()
            .unwrap_or_default();
        let value = fields
            .into_iter()
            .find(|(k, _)| k == "kek")
            .map(|(_, v)| Zeroizing::new(v.trim().to_string()))
            .filter(|v| !v.is_empty());
        value.ok_or_else(|| "the vault did not return this box's escrowed store key (there may be none, or the vault cannot be reached with the box's token)".into())
    }

    /// Put `kek_text` in escrow, unless the vault already holds exactly that. The value goes in the request body only.
    pub fn place(&self, kek_text: &str) -> Result<bool, String> {
        let kek = Zeroizing::new(kek_text.trim().to_string());
        if self.fetch().is_ok_and(|have| have.as_str() == kek.as_str()) {
            return Ok(false);
        }
        self.vault
            .write(&self.mount, &self.path, &[("kek", kek.as_str())])
            .map_err(|_| "the store key could not be escrowed in the vault (the box's token needs create, update and read on its escrow path)".to_string())?;
        Ok(true)
    }
}

/// What the service does at start when the store is there and its key file is not.
#[derive(Debug, PartialEq, Eq)]
pub enum Missing {
    /// The key came back from escrow and was written beside the store.
    Recovered,
    /// No escrow is configured: nothing will bring the key back. A configuration state (exit 78).
    NoEscrow(String),
    /// Escrow is configured and did not answer: worth trying again.
    Unavailable(String),
}

pub const NO_ESCROW: &str = "the store's key is not on this disk (its system disk was replaced) and this box has no escrow for it, so its secrets cannot be opened. `ozbox upgrade` asks before it does this. To start a new store, run `ozbox admin <box> -- recover-secrets` from the computer that made the box (it signs the box's one-time challenge with the key pinned then; the old store is set aside, never deleted); the box's own secrets come back from the vault, and anything kept only on the box (a tunnel token, backup credentials, imported keys, enrolled laptop keys) must be entered again";

/// What the service says while a declared vault's token is missing after a rebuild.
pub const TOKEN_MISSING: &str = "the store's key is not on this disk and this box's vault token is not here yet (a rebuilt system disk loses a token placed by hand): place it again with `ozbox admin <box> -- place-bao-token ID`, and the key comes back from the vault's escrow";

/// Bring back a missing key file from escrow. `key_file` is where the file-kept key belongs.
#[cfg(unix)]
pub fn recover_key(escrow: Option<&Escrow>, declared: bool, key_file: &std::path::Path) -> Missing {
    use std::io::Write;
    use std::os::unix::fs::OpenOptionsExt;
    let Some(e) = escrow else {
        if declared {
            // the vault is declared and its token is not here (a rebuilt disk loses one placed by hand): wait for it
            return Missing::Unavailable(TOKEN_MISSING.into());
        }
        return Missing::NoEscrow(NO_ESCROW.into());
    };
    let kek = match e.fetch() {
        Ok(k) => k,
        Err(why) => {
            return Missing::Unavailable(format!(
                "the store's key is not on this disk and {why}; if the box was rebuilt, place its vault token again (`ozbox admin <box> -- place-bao-token ID`)"
            ))
        }
    };
    let written = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(key_file)
        .and_then(|mut f| {
            f.write_all(kek.as_bytes())?;
            f.write_all(b"\n")?;
            f.sync_all()
        });
    match written {
        Ok(()) => Missing::Recovered,
        Err(e) => Missing::Unavailable(format!(
            "the store's key came back from escrow but could not be written ({})",
            e.kind()
        )),
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use crate::openbao::fakes::{Vault, TOKEN};

    /// The escrow of `FULL` for box dev-1, against a loopback vault.
    fn against(v: &Vault) -> Escrow {
        Escrow {
            vault: v.client(),
            ..Escrow::from_env(&env(FULL), "dev-1").unwrap()
        }
    }

    fn env(pairs: &'static [(&'static str, &'static str)]) -> impl Fn(&str) -> Option<String> {
        move |k| {
            pairs
                .iter()
                .find(|(n, _)| *n == k)
                .map(|(_, v)| v.to_string())
        }
    }

    const FULL: &[(&str, &str)] = &[
        ("OZBOX_BOX_SECRETS_BACKEND", "openbao"),
        ("OZBOX_BOX_SECRETS_PATH", "/ozbox/dev"),
        ("BAO_ADDR", "https://vault.example.com"),
        ("BAO_TOKEN", "s.SENTINELTOKEN"),
    ];

    /// A declared vault whose token went with a rebuilt disk is a token to place again, retried, never a lost store.
    #[test]
    fn a_declared_vault_with_no_token_yet_is_waited_for_not_read_as_no_escrow() {
        let d = tempfile::tempdir().unwrap();
        let key = d.path().join("kek.key");
        let declared_no_token = env(&[
            ("OZBOX_BOX_SECRETS_BACKEND", "openbao"),
            ("BAO_ADDR", "https://vault.example.com"),
        ]);
        assert!(Escrow::declared(&declared_no_token));
        assert!(Escrow::from_env(&declared_no_token, "dev-1").is_none());
        assert!(
            matches!(recover_key(None, true, &key), Missing::Unavailable(m) if m.contains("place-bao-token"))
        );
        assert!(matches!(
            recover_key(None, false, &key),
            Missing::NoEscrow(_)
        ));
        assert!(!Escrow::declared(&env(&[(
            "OZBOX_BOX_SECRETS_BACKEND",
            "aws-ssm"
        )])));
    }

    #[test]
    fn the_escrow_is_the_boxs_own_path_outside_every_role_and_needs_a_vault_and_a_token() {
        let e = Escrow::from_env(&env(FULL), "dev-1").unwrap();
        assert_eq!(e.path, "ozbox/dev/_escrow/dev-1");
        assert_eq!(e.mount, "secret");
        assert!(
            Escrow::from_env(&env(&[("OZBOX_BOX_SECRETS_BACKEND", "openbao")]), "dev-1").is_none()
        );
        assert!(
            Escrow::from_env(&env(&[("OZBOX_BOX_SECRETS_BACKEND", "aws-ssm")]), "dev-1").is_none()
        );
        // an address that is not https is no escrow at all
        assert!(Escrow::from_env(
            &env(&[
                ("OZBOX_BOX_SECRETS_BACKEND", "openbao"),
                ("BAO_ADDR", "http://vault.example.com"),
                ("BAO_TOKEN", "t")
            ]),
            "dev-1"
        )
        .is_none());
    }

    #[test]
    fn the_key_goes_to_the_vault_in_the_request_body_only_and_is_not_written_twice() {
        let v = Vault::start();
        let e = against(&v);
        // no escrow yet, then the write succeeds
        assert!(e.place("SENTINEL-KEK-TEXT\n").unwrap());
        {
            let seen = v.seen.lock().unwrap();
            let methods: Vec<String> = seen
                .iter()
                .map(|s| format!("{} {}", s.method, s.url))
                .collect();
            assert_eq!(
                methods,
                [
                    "GET /v1/secret/data/ozbox/dev/_escrow/dev-1",
                    "POST /v1/secret/data/ozbox/dev/_escrow/dev-1",
                ]
            );
            let put = &seen[1];
            let body: serde_json::Value = serde_json::from_str(&put.body).unwrap();
            assert_eq!(
                body,
                serde_json::json!({"data": {"kek": "SENTINEL-KEK-TEXT"}})
            );
            for s in seen.iter() {
                assert!(!s.url.contains("SENTINEL") && !s.url.contains(TOKEN));
                assert!(s.headers.iter().all(
                    |(k, v)| k.eq_ignore_ascii_case("x-vault-token") || !v.contains("SENTINEL")
                ));
            }
        }
        assert_eq!(e.fetch().unwrap().as_str(), "SENTINEL-KEK-TEXT");
        // the same key already there: nothing is written
        let before = v.seen.lock().unwrap().len();
        assert!(!e.place("SENTINEL-KEK-TEXT").unwrap());
        assert_eq!(v.seen.lock().unwrap().len(), before + 1);
        // a refused write is one plain sentence with nothing of the key or the token in it
        *v.force.lock().unwrap() = Some((403, "permission denied SENTINEL".into()));
        let err = e.place("ANOTHER-SENTINEL").unwrap_err();
        assert!(err.contains("create, update and read"), "{err}");
        assert!(!err.contains("SENTINEL") && !err.contains(TOKEN));
    }

    #[test]
    fn escrow_works_with_no_bao_command_anywhere() {
        // the defect this replaces: the image has no `bao`. A child process with an empty PATH places and fetches the key.
        if std::env::var("OZBOX_ESCROW_NO_PROGRAM_CHILD").is_ok() {
            let v = Vault::start();
            let e = against(&v);
            assert!(e.place("SENTINEL-KEK-TEXT").unwrap());
            assert_eq!(e.fetch().unwrap().as_str(), "SENTINEL-KEK-TEXT");
            return;
        }
        let empty = tempfile::tempdir().unwrap();
        let out = std::process::Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "secrets_escrow::tests::escrow_works_with_no_bao_command_anywhere",
                "--nocapture",
            ])
            .env("OZBOX_ESCROW_NO_PROGRAM_CHILD", "1")
            .env("PATH", empty.path())
            .output()
            .unwrap();
        let text = format!(
            "{}{}",
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr)
        );
        assert!(out.status.success(), "{text}");
        assert!(text.contains("1 passed"), "{text}");
    }

    #[cfg(unix)]
    #[test]
    fn a_missing_key_comes_back_from_escrow_or_says_which_kind_of_missing_it_is() {
        let d = tempfile::tempdir().unwrap();
        let file = d.path().join("kek.key");
        // no escrow configured: nothing can bring it back
        assert!(matches!(
            recover_key(None, false, &file),
            Missing::NoEscrow(_)
        ));
        let v = Vault::start();
        let e = against(&v);
        // the vault does not answer: worth retrying, and the error names no value
        *v.force.lock().unwrap() = Some((503, "sealed".into()));
        match recover_key(Some(&e), true, &file) {
            Missing::Unavailable(why) => assert!(why.contains("place-bao-token"), "{why}"),
            m => panic!("{m:?}"),
        }
        assert!(!file.exists());
        *v.force.lock().unwrap() = None;
        v.put("secret/ozbox/dev/_escrow/dev-1", &[("kek", "KEKTEXT\n")]);
        assert_eq!(recover_key(Some(&e), true, &file), Missing::Recovered);
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(std::fs::read_to_string(&file).unwrap(), "KEKTEXT\n");
        assert_eq!(
            std::fs::metadata(&file).unwrap().permissions().mode() & 0o777,
            0o600
        );
    }
}
