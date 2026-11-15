//! What is kept on disk: who has which passkeys, whether an authenticator app is set up (never its secret: that is
//! in the secret store), and the provider client ids a signed-in person entered. A file with mode 0600, rewritten
//! whole and renamed into place.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use super::webauthn::Passkey;

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct UserState {
    pub passkeys: Vec<Passkey>,
    pub totp: bool,
    pub totp_last_step: Option<u64>,
    /// The numeric GitHub id, pinned at the first sign-in so a re-registered login cannot take the place.
    pub github_id: Option<u64>,
    /// The role an owner gave this person from the dashboard. Absent for everyone on a dashboard made before roles, who then
    /// have the settings file's role or the default.
    pub role: Option<ozbox_core::roles::Role>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct AuthState {
    pub users: BTreeMap<String, UserState>,
    pub github_client_id: Option<String>,
    pub google_client_id: Option<String>,
}

impl AuthState {
    #[cfg(test)]
    pub fn load(path: &Path) -> Self {
        std::fs::read_to_string(path)
            .ok()
            .and_then(|t| serde_json::from_str(&t).ok())
            .unwrap_or_default()
    }

    /// Like [`AuthState::load`], but a file that exists and cannot be read is an error, not an empty state: an empty state
    /// would quietly undo every role an owner set from the dashboard (a demoted first person would be the owner again).
    pub fn try_load(path: &Path) -> Result<Self, String> {
        match std::fs::read_to_string(path) {
            Ok(t) => serde_json::from_str(&t).map_err(|e| {
                format!(
                    "{} cannot be read ({e}). It holds who has which role and passkey, so the dashboard will not start on an empty one: restore it from a backup, or move it aside to start the sign-in setup again",
                    path.display()
                )
            }),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(Self::default()),
            Err(e) => Err(format!("{} cannot be read ({e})", path.display())),
        }
    }

    pub fn save(&self, path: &PathBuf) -> std::io::Result<()> {
        use std::io::Write;
        #[cfg(unix)]
        use std::os::unix::fs::OpenOptionsExt;
        let tmp = path.with_extension("tmp");
        let mut opts = std::fs::OpenOptions::new();
        opts.write(true).create(true).truncate(true);
        #[cfg(unix)]
        opts.mode(0o600);
        let mut f = opts.open(&tmp)?;
        f.write_all(serde_json::to_string_pretty(self)?.as_bytes())?;
        f.sync_all()?;
        std::fs::rename(tmp, path)
    }
}
