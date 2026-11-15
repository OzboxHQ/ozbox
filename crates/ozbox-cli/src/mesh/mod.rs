//! A tailnet you run yourself (ADR 0028): a Headscale control server on a machine of yours, to which your boxes and your
//! computers join. It is an alternative to Session Manager and to a Cloudflare tunnel for reaching a box (SSH, the
//! dashboard, the web IDE), and like them it opens nothing inbound on a box (ADR 0005): every node dials out to the
//! control server, and a box's own SSH server stays on loopback.
//!
//! The pieces: [`MeshFile`] (`mesh.toml`, no secret), [`policy`] (the access rules generated from the fleet, a pure
//! function), [`headscale`] (the Headscale command line, through [`ozbox_core::CommandRunner`]), and [`join`] (the script
//! that joins a box, carrying a one-use key on standard input).

use std::path::Path;

use serde::{Deserialize, Serialize};

pub mod headscale;
pub mod join;
pub mod policy;

/// The account on a box that the person signs in as.
pub const DEFAULT_SSH_USER: &str = "ozbox";

/// The tag every node of a box carries: `tag:ozbox-<box>`.
pub fn box_tag(box_name: &str) -> String {
    format!("tag:ozbox-{box_name}")
}

/// A rule letting one box open connections to another. Boxes cannot reach each other unless one of these says so.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(default, deny_unknown_fields)]
pub struct Allow {
    pub from: String,
    pub to: String,
    pub ports: Vec<u16>,
}

/// `mesh.toml`, beside the main configuration. Holds no secret.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(default, deny_unknown_fields)]
pub struct MeshFile {
    /// The address of your Headscale server, `https://headscale.example.com`.
    pub control_url: String,
    /// The Headscale user that owns your computers and your boxes.
    pub user: String,
    /// An SSH host name (as `ssh` knows it) of the machine that runs Headscale, when it is not this computer. Empty means
    /// the `headscale` program runs here.
    pub admin_host: String,
    /// The account on a box that the person signs in as (default `ozbox`).
    pub ssh_user: String,
    /// Your tailnet's base domain, for names like `<box>.<base_domain>`. Empty means the box's tailnet name is not
    /// guessed and the SSH entry uses the box name alone (MagicDNS short name).
    pub base_domain: String,
    /// Declared box-to-box rules.
    pub allow: Vec<Allow>,
}

fn word_ok(s: &str, max: usize) -> bool {
    !s.is_empty()
        && s.len() <= max
        && !s.starts_with(['-', '.'])
        && s.bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.'))
}

impl MeshFile {
    pub fn ssh_user(&self) -> &str {
        if self.ssh_user.is_empty() {
            DEFAULT_SSH_USER
        } else {
            &self.ssh_user
        }
    }

    /// Everything that can be checked without running anything. The error is a catalogue key.
    pub fn validate(&self) -> Result<(), &'static str> {
        crate::tunnel::public_host(&self.control_url).map_err(|_| "mesh.bad_control_url")?;
        if !word_ok(&self.user.replacen('@', "x", 1), 64) || self.user.matches('@').count() > 1 {
            return Err("mesh.bad_user");
        }
        if !self.admin_host.is_empty() && !word_ok(&self.admin_host, 253) {
            return Err("mesh.bad_admin_host");
        }
        if !self.ssh_user.is_empty() && !word_ok(&self.ssh_user, 32) {
            return Err("mesh.bad_ssh_user");
        }
        if !self.base_domain.is_empty()
            && (!word_ok(&self.base_domain, 253) || !self.base_domain.contains('.'))
        {
            return Err("mesh.bad_base_domain");
        }
        for a in &self.allow {
            if ozbox_core::BoxName::new(a.from.as_str()).is_err()
                || ozbox_core::BoxName::new(a.to.as_str()).is_err()
                || a.from == a.to
                || a.ports.is_empty()
                || a.ports.contains(&0)
            {
                return Err("mesh.bad_allow");
            }
        }
        Ok(())
    }

    pub fn load(path: &Path) -> Result<Option<MeshFile>, String> {
        match std::fs::read_to_string(path) {
            Ok(text) => toml::from_str(&text)
                .map(Some)
                .map_err(|e| format!("the mesh settings are not valid: {}", e.message())),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(_) => Err("the mesh settings could not be read".into()),
        }
    }

    pub fn save(&self, path: &Path) -> Result<(), String> {
        if let Some(dir) = path.parent() {
            let _ = std::fs::create_dir_all(dir);
        }
        let text = toml::to_string_pretty(self).map_err(|e| e.to_string())?;
        std::fs::write(path, text).map_err(|_| "the mesh settings could not be written".into())
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    pub fn sample() -> MeshFile {
        MeshFile {
            control_url: "https://headscale.example.com".into(),
            user: "alice".into(),
            ..Default::default()
        }
    }

    #[test]
    fn a_plain_file_is_valid_and_round_trips() {
        let f = sample();
        f.validate().unwrap();
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("mesh.toml");
        f.save(&p).unwrap();
        assert_eq!(MeshFile::load(&p).unwrap().unwrap(), f);
        assert_eq!(MeshFile::load(&dir.path().join("none")).unwrap(), None);
    }

    #[test]
    fn bad_values_are_refused_with_a_catalogue_key() {
        let mut f = sample();
        f.control_url = "http://headscale.example.com".into();
        assert_eq!(f.validate(), Err("mesh.bad_control_url"));
        let mut f = sample();
        f.user = "a b".into();
        assert_eq!(f.validate(), Err("mesh.bad_user"));
        let mut f = sample();
        f.admin_host = "-oProxyCommand=x".into();
        assert_eq!(f.validate(), Err("mesh.bad_admin_host"));
        let mut f = sample();
        f.allow.push(Allow {
            from: "a".into(),
            to: "a".into(),
            ports: vec![22],
        });
        assert_eq!(f.validate(), Err("mesh.bad_allow"));
        f.allow[0].to = "b".into();
        f.allow[0].ports.clear();
        assert_eq!(f.validate(), Err("mesh.bad_allow"));
    }

    #[test]
    fn unknown_keys_are_refused() {
        assert!(toml::from_str::<MeshFile>("surprise = 1").is_err());
    }
}
