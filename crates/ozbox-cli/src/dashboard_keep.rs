//! What this computer keeps about a box's hosted dashboard, so an upgrade that starts a new secrets store can put it back.
//!
//! An upgrade replaces the box's system disk, and with it the box's own secrets store when its key cannot be carried over.
//! The dashboard's tunnel token lived only there, so the dashboard stayed down until the owner installed it again with a token
//! that was no longer to hand. This module keeps, in the same place the web IDE's tunnel token is kept (this computer's secret
//! store: the keychain on a laptop, never a plain file), the two things `ozbox dashboard install` was given:
//!
//! * the **token**, under `dashboard-tunnel-token-<box>` (beside `ide-tunnel-token-<box>`), written only after the box took it;
//! * the **install settings** (address, tunnel, people, Access and Caddy fields), under `dashboard-install-<box>`. They hold no
//!   secret, but live with the token so one `forget` removes both and no settings file appears under `~/.config/ozbox`.
//!   They are stored as hexadecimal text so any secret store carries them (a store takes plain visible characters).
//!
//! Neither is ever printed, logged, serialized into a report or put in a command line. [`Kept`] has no token field, and its
//! `Debug` is the derived one over non-secret fields only.

use serde::{Deserialize, Serialize};

use crate::cli::DashboardCommand;
use crate::secrets::{SecretStore, MAX_VALUE};

/// The secret that holds the hosted dashboard's tunnel token for one box.
pub fn token_name(box_name: &str) -> String {
    format!("{}{box_name}", crate::secrets::DASHBOARD_TOKEN_PREFIX)
}

/// The secret that holds the install settings for one box (hex of a small JSON document).
pub fn settings_name(box_name: &str) -> String {
    format!("{}{box_name}", crate::secrets::DASHBOARD_INSTALL_PREFIX)
}

/// What `ozbox dashboard install` was given, minus the token, the approval and the program (the program is chosen again from
/// the box's own image release when it is put back, and verified again).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Kept {
    pub public_url: String,
    pub tunnel: Option<String>,
    pub people: Vec<String>,
    pub access_team: Option<String>,
    pub access_audience: Option<String>,
    pub ssh_host: Option<String>,
    pub ssh_user: Option<String>,
    pub ssh_port: u16,
    pub remote_port: u16,
}

impl Kept {
    /// What an install command asked for. `None` for any other command.
    pub fn from_command(cmd: &DashboardCommand) -> Option<Self> {
        let DashboardCommand::Install {
            public_url,
            tunnel,
            people,
            access_team,
            access_audience,
            ssh_host,
            ssh_user,
            ssh_port,
            remote_port,
            ..
        } = cmd
        else {
            return None;
        };
        Some(Self {
            public_url: public_url.clone(),
            tunnel: tunnel.clone(),
            people: people.clone(),
            access_team: access_team.clone(),
            access_audience: access_audience.clone(),
            ssh_host: ssh_host.clone(),
            ssh_user: ssh_user.clone(),
            ssh_port: *ssh_port,
            remote_port: *remote_port,
        })
    }

    /// The install command this record stands for: the program is the box's own signed release, the token (when one is kept)
    /// comes from the keychain, and nothing is approved here (an approval is the owner's, see `approve_with_laptop_key`).
    pub fn to_command(
        &self,
        name: ozbox_core::BoxName,
        release: Option<String>,
        approve_with_laptop_key: bool,
        with_token: bool,
    ) -> DashboardCommand {
        DashboardCommand::Install {
            name,
            public_url: self.public_url.clone(),
            tunnel: self.tunnel.clone(),
            binary_url: None,
            binary_sha256: None,
            release,
            release_repo: None,
            people: self.people.clone(),
            access_team: self.access_team.clone(),
            access_audience: self.access_audience.clone(),
            token_stdin: false,
            ssh_host: self.ssh_host.clone(),
            ssh_user: self.ssh_user.clone(),
            ssh_port: self.ssh_port,
            remote_port: self.remote_port,
            approval: None,
            approval_stdin: false,
            token_from_keychain: with_token,
            approve_with_laptop_key: approve_with_laptop_key && with_token,
            replace_sign_in: false,
            settings_approval: None,
        }
    }
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn unhex(s: &str) -> Option<Vec<u8>> {
    if !s.len().is_multiple_of(2) || !s.is_ascii() {
        return None;
    }
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).ok())
        .collect()
}

/// Keep the settings, and the token when one was sent and the box took it. An error is a sentence for a person and never
/// contains the token.
pub fn remember(
    store: &dyn SecretStore,
    box_name: &str,
    kept: &Kept,
    token: Option<&str>,
) -> Result<(), String> {
    let json = serde_json::to_vec(kept).map_err(|e| e.to_string())?;
    let text = hex(&json);
    if text.len() > MAX_VALUE {
        return Err("the install settings are too long to keep".into());
    }
    // the token first: it is the part a person cannot get back, and the settings are only useful beside it
    if let Some(t) = token {
        store
            .set(&token_name(box_name), t)
            .map_err(|e| e.to_string())?;
    }
    store
        .set(&settings_name(box_name), &text)
        .map_err(|e| e.to_string())
}

/// The settings kept for a box, if any (a value that does not read back as settings is as good as none).
pub fn recall(store: &dyn SecretStore, box_name: &str) -> Option<Kept> {
    let text = store.get(&settings_name(box_name)).ok().flatten()?;
    serde_json::from_slice(&unhex(&text)?).ok()
}

/// The token kept for a box, for the one call that hands it to the box. Never for output.
pub fn token(store: &dyn SecretStore, box_name: &str) -> Option<String> {
    store.get(&token_name(box_name)).ok().flatten()
}

/// Whether a token is kept (for a message that must say so without reading it).
pub fn has_token(store: &dyn SecretStore, box_name: &str) -> bool {
    store.exists(&token_name(box_name)).unwrap_or(false)
}

/// Remove both. Best effort: a store that cannot delete has nothing more to say here.
pub fn forget(store: &dyn SecretStore, box_name: &str) {
    let _ = store.delete(&token_name(box_name));
    let _ = store.delete(&settings_name(box_name));
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use crate::secrets::{KeychainSecrets, MemorySecrets};

    /// A store that applies the SAME name rule the keychain applies (`KeychainSecrets::check_name`, the function behind `set`,
    /// `get`, `exists` and `delete` there) and keeps values in memory. A plain `MemorySecrets` accepts any name, which is how
    /// "that is not a name this server stores" shipped: the tests of keeping a token passed against a store with no rule.
    #[derive(Default)]
    struct RuleChecked(MemorySecrets);

    impl SecretStore for RuleChecked {
        fn set(&self, name: &str, value: &str) -> Result<(), crate::secrets::SecretError> {
            KeychainSecrets::check_name(name)?;
            self.0.set(name, value)
        }
        fn get(&self, name: &str) -> Result<Option<String>, crate::secrets::SecretError> {
            KeychainSecrets::check_name(name)?;
            self.0.get(name)
        }
        fn exists(&self, name: &str) -> Result<bool, crate::secrets::SecretError> {
            KeychainSecrets::check_name(name)?;
            self.0.exists(name)
        }
        fn delete(&self, name: &str) -> Result<(), crate::secrets::SecretError> {
            KeychainSecrets::check_name(name)?;
            self.0.delete(name)
        }
        fn label(&self) -> &'static str {
            "rule-checked memory"
        }
    }

    fn kept() -> Kept {
        Kept {
            public_url: "https://dash.example.com".into(),
            tunnel: Some("cloudflare".into()),
            people: vec!["owner".into()],
            access_team: None,
            access_audience: None,
            ssh_host: None,
            ssh_user: None,
            ssh_port: 22,
            remote_port: 7878,
        }
    }

    #[test]
    fn what_is_kept_for_a_box_is_accepted_by_the_real_name_rule_for_every_box_name() {
        // a short name, a name with digits and dashes, and the longest a box may have (40 characters)
        for box_name in ["main", "my-box-2", &"a".repeat(40)] {
            let s = RuleChecked::default();
            remember(&s, box_name, &kept(), Some("tok_abc123XYZ.="))
                .unwrap_or_else(|e| panic!("{box_name}: {e}"));
            assert!(has_token(&s, box_name), "{box_name}");
            assert_eq!(token(&s, box_name).as_deref(), Some("tok_abc123XYZ.="));
            assert_eq!(recall(&s, box_name), Some(kept()), "{box_name}");
            forget(&s, box_name);
            assert!(!has_token(&s, box_name) && recall(&s, box_name).is_none());
        }
    }

    /// Sentinel: the kept tunnel token is in the store under its own name and nowhere else: not in the settings record beside
    /// it, not in what a refused keep says (a box name the rule refuses), and not after `forget`.
    #[test]
    fn the_kept_token_is_in_the_store_only_and_never_in_an_error_or_the_settings_record() {
        const SENTINEL: &str = "SENTINEL-tunnel-token-4f2a9c";
        let s = RuleChecked::default();
        remember(&s, "main", &kept(), Some(SENTINEL)).unwrap();
        let record = s.0.get(&settings_name("main")).unwrap().unwrap();
        assert!(!record.contains(SENTINEL) && !record.contains(&hex(SENTINEL.as_bytes())));
        assert!(!format!("{:?}", recall(&s, "main")).contains(SENTINEL));
        // refused by the name rule: the error says why, never the value
        let e = remember(&s, &"a".repeat(41), &kept(), Some(SENTINEL)).unwrap_err();
        assert!(!e.contains(SENTINEL), "{e}");
        forget(&s, "main");
        assert!(token(&s, "main").is_none());
    }

    #[test]
    fn the_names_are_only_ever_for_a_valid_box_name_and_the_generic_routes_cannot_write_them() {
        assert!(KeychainSecrets::check_name(&token_name(&"a".repeat(41))).is_err());
        assert!(KeychainSecrets::check_name("dashboard-tunnel-token-").is_err());
        assert!(KeychainSecrets::check_name("dashboard-install-UP").is_err());
        assert!(KeychainSecrets::check_name("dashboard-install-a/b").is_err());
        // set by `ozbox dashboard install` on this computer only: the dashboard server's generic secret routes refuse them
        assert!(crate::secrets::is_managed_secret(&token_name("main")));
        assert!(crate::secrets::is_managed_secret(&settings_name("main")));
    }
}
