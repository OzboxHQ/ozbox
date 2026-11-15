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
//! * How: the `bao` command, with the value on standard input (`kek=-`), never in an argument, a log or an error.
//!
//! Not built: escrow in the laptop keychain, put back by `ozbox upgrade`. Without the ingress account of ADR 0029
//! Amendment 6 §3 every route from the laptop into the box passes through a process of the box user, which could keep the
//! key; so a box without a vault has no escrow, and a replaced system disk starts a new store (`ozbox admin <box> -- recover-secrets`, approved by the key pinned when the box was made).

use ozbox_core::{CommandRunner, CommandSpec};
use zeroize::Zeroizing;

/// Where the escrowed key lives, and that there is a credential to reach it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Escrow {
    pub mount: String,
    pub path: String,
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
        get("BAO_ADDR").filter(|a| a.starts_with("https://"))?;
        get("BAO_TOKEN").filter(|t| !t.is_empty())?;
        let prefix = get("OZBOX_BOX_SECRETS_PATH").unwrap_or_default();
        let prefix = prefix.trim_matches('/');
        let mount = get("OZBOX_BOX_SECRETS_MOUNT").unwrap_or_else(|| "secret".into());
        let path = if prefix.is_empty() {
            format!("_escrow/{scope}")
        } else {
            format!("{prefix}/_escrow/{scope}")
        };
        (plain(&mount) && plain(&path) && plain(scope)).then_some(Escrow { mount, path })
    }

    /// Whether the box declares an escrow at all (box secrets on OpenBao at an https address), whether or not its token is
    /// here. A rebuilt system disk loses a token placed by hand, so "declared, no token" is a token to place again, never a
    /// store with no escrow (a security review, 2026-11-11: it was read as one, which would have let its store be set aside).
    pub fn declared(get: &dyn Fn(&str) -> Option<String>) -> bool {
        get("OZBOX_BOX_SECRETS_BACKEND").as_deref() == Some("openbao")
            && get("BAO_ADDR").is_some_and(|a| a.starts_with("https://"))
    }

    /// The escrowed key, or why it could not be had. The vault's own words are not repeated (they can name a path).
    pub fn fetch(&self, runner: &dyn CommandRunner) -> Result<Zeroizing<String>, String> {
        let out = runner
            .run(&CommandSpec::new("bao").args([
                "kv".to_string(),
                "get".into(),
                format!("-mount={}", self.mount),
                "-field=kek".into(),
                self.path.clone(),
            ]))
            .map_err(|_| "the bao command could not be started".to_string())?;
        let value = Zeroizing::new(out.stdout.trim().to_string());
        if out.status != Some(0) || value.is_empty() {
            return Err("the vault did not return this box's escrowed store key (there may be none, or the vault cannot be reached with the box's token)".into());
        }
        Ok(value)
    }

    /// Put `kek_text` in escrow, unless the vault already holds exactly that. The value goes on standard input only.
    pub fn place(&self, runner: &dyn CommandRunner, kek_text: &str) -> Result<bool, String> {
        if self
            .fetch(runner)
            .is_ok_and(|have| have.as_str() == kek_text.trim())
        {
            return Ok(false);
        }
        let out = runner
            .run(
                &CommandSpec::new("bao")
                    .args([
                        "kv".to_string(),
                        "put".into(),
                        format!("-mount={}", self.mount),
                        self.path.clone(),
                        "kek=-".into(),
                    ])
                    .stdin(kek_text.trim().as_bytes().to_vec()),
            )
            .map_err(|_| "the bao command could not be started".to_string())?;
        if out.status != Some(0) {
            return Err("the store key could not be escrowed in the vault (the box's token needs create, update and read on its escrow path)".into());
        }
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
pub fn recover_key(
    escrow: Option<&Escrow>,
    declared: bool,
    runner: &dyn CommandRunner,
    key_file: &std::path::Path,
) -> Missing {
    use std::io::Write;
    use std::os::unix::fs::OpenOptionsExt;
    let Some(e) = escrow else {
        if declared {
            // the vault is declared and its token is not here (a rebuilt disk loses one placed by hand): wait for it
            return Missing::Unavailable(TOKEN_MISSING.into());
        }
        return Missing::NoEscrow(NO_ESCROW.into());
    };
    let kek = match e.fetch(runner) {
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
    use ozbox_core::{Output, RecordingRunner};

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
        let r = RecordingRunner::new();
        let declared_no_token = env(&[
            ("OZBOX_BOX_SECRETS_BACKEND", "openbao"),
            ("BAO_ADDR", "https://vault.example.com"),
        ]);
        assert!(Escrow::declared(&declared_no_token));
        assert!(Escrow::from_env(&declared_no_token, "dev-1").is_none());
        assert!(
            matches!(recover_key(None, true, &r, &key), Missing::Unavailable(m) if m.contains("place-bao-token"))
        );
        assert!(matches!(
            recover_key(None, false, &r, &key),
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
    fn the_key_goes_to_the_vault_on_standard_input_only() {
        let e = Escrow::from_env(&env(FULL), "dev-1").unwrap();
        let r = RecordingRunner::new();
        // no escrow yet, then the put succeeds
        r.reply(Output {
            status: Some(2),
            stdout: String::new(),
            stderr: "No value found at secret/data/ozbox/dev/_escrow/dev-1".into(),
        });
        r.reply(Output {
            status: Some(0),
            stdout: String::new(),
            stderr: String::new(),
        });
        assert!(e.place(&r, "SENTINEL-KEK-TEXT").unwrap());
        let calls = r.calls();
        let put = &calls[1];
        assert!(put.args.iter().any(|a| a == "kek=-"));
        assert!(!format!("{:?}", put.args).contains("SENTINEL-KEK-TEXT"));
        assert_eq!(put.stdin.as_deref(), Some(b"SENTINEL-KEK-TEXT".as_slice()));
        // the same key already there: nothing is written
        let r = RecordingRunner::new();
        r.reply(Output {
            status: Some(0),
            stdout: "SENTINEL-KEK-TEXT\n".into(),
            stderr: String::new(),
        });
        assert!(!e.place(&r, "SENTINEL-KEK-TEXT").unwrap());
        assert_eq!(r.calls().len(), 1);
    }

    #[cfg(unix)]
    #[test]
    fn a_missing_key_comes_back_from_escrow_or_says_which_kind_of_missing_it_is() {
        let d = tempfile::tempdir().unwrap();
        let file = d.path().join("kek.key");
        let r = RecordingRunner::new();
        // no escrow configured: nothing can bring it back
        assert!(matches!(
            recover_key(None, false, &r, &file),
            Missing::NoEscrow(_)
        ));
        let e = Escrow::from_env(&env(FULL), "dev-1").unwrap();
        // the vault does not answer: worth retrying, and the error names no value
        r.reply(Output {
            status: Some(1),
            stdout: String::new(),
            stderr: "permission denied".into(),
        });
        match recover_key(Some(&e), true, &r, &file) {
            Missing::Unavailable(why) => assert!(why.contains("place-bao-token"), "{why}"),
            m => panic!("{m:?}"),
        }
        assert!(!file.exists());
        r.reply(Output {
            status: Some(0),
            stdout: "KEKTEXT\n".into(),
            stderr: String::new(),
        });
        assert_eq!(recover_key(Some(&e), true, &r, &file), Missing::Recovered);
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(std::fs::read_to_string(&file).unwrap(), "KEKTEXT\n");
        assert_eq!(
            std::fs::metadata(&file).unwrap().permissions().mode() & 0o777,
            0o600
        );
    }
}
