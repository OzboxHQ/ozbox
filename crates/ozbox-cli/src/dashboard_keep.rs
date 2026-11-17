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
    format!("dashboard-tunnel-token-{box_name}")
}

/// The secret that holds the install settings for one box (hex of a small JSON document).
pub fn settings_name(box_name: &str) -> String {
    format!("dashboard-install-{box_name}")
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
