//! What a deployer sets once: the public address, who may sign in, and which providers are connected. Everything a
//! provider needs is the deployer's own: Oz Box ships no OAuth client of its own.

use serde::{Deserialize, Serialize};

use super::webauthn::Rp;

#[derive(Debug, Clone, Deserialize, Serialize, Default)]
#[serde(default, deny_unknown_fields)]
pub struct UserEntry {
    /// Lower-case letters, digits and `-`.
    pub id: String,
    pub label: String,
    /// A GitHub login allowed to sign in as this person.
    pub github: Option<String>,
    /// A Google account e-mail address allowed to sign in as this person (must be verified by Google).
    pub google: Option<String>,
    /// An e-mail address Cloudflare Access may vouch for.
    pub access_email: Option<String>,
    /// What this person may do (`owner`, `member` or `viewer`). Left out, the first person on the list is the owner and the
    /// rest are members. An owner can change it from the dashboard, which is then what counts.
    pub role: Option<ozbox_core::roles::Role>,
}

#[derive(Debug, Clone, Deserialize, Serialize, Default)]
#[serde(default, deny_unknown_fields)]
pub struct ClientCfg {
    pub client_id: Option<String>,
}

#[derive(Debug, Clone, Deserialize, Serialize, Default)]
#[serde(default, deny_unknown_fields)]
pub struct AccessCfg {
    /// `myteam.cloudflareaccess.com`.
    pub team_domain: String,
    /// The application's audience tag.
    pub audience: String,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(default, deny_unknown_fields)]
pub struct AuthFile {
    pub public_origin: String,
    pub name: String,
    pub session_idle_hours: u64,
    pub session_absolute_days: u64,
    /// How long a passkey confirmation stays fresh (minutes; fractions allowed).
    pub stepup_minutes: f64,
    pub users: Vec<UserEntry>,
    pub github: ClientCfg,
    pub google: ClientCfg,
    pub access: Option<AccessCfg>,
}

impl Default for AuthFile {
    fn default() -> Self {
        Self {
            public_origin: String::new(),
            name: "Oz Box".into(),
            session_idle_hours: 12,
            session_absolute_days: 7,
            stepup_minutes: 5.0,
            users: Vec::new(),
            github: ClientCfg::default(),
            google: ClientCfg::default(),
            access: None,
        }
    }
}

#[derive(Debug, Clone)]
pub struct AuthConfig {
    pub file: AuthFile,
    pub rp: Rp,
    pub host: String,
    pub idle_ms: u64,
    pub absolute_ms: u64,
    pub stepup_ms: u64,
}

pub fn valid_user_id(id: &str) -> bool {
    !id.is_empty()
        && id.len() <= 32
        && id
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
}

fn valid_login(s: &str) -> bool {
    !s.is_empty() && s.len() <= 39 && s.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-')
}

fn valid_email(s: &str) -> bool {
    s.len() <= 254
        && s.matches('@').count() == 1
        && !s.starts_with('@')
        && !s.ends_with('@')
        && s.bytes().all(|b| b.is_ascii_graphic())
}

impl AuthConfig {
    pub fn new(mut file: AuthFile) -> Result<Self, String> {
        let origin = file.public_origin.trim_end_matches('/').to_string();
        let (scheme, rest) = origin
            .split_once("://")
            .ok_or("the public address must start with https://")?;
        if rest.is_empty() || rest.contains(['/', '?', '#', '@', ' ']) {
            return Err(
                "the public address must be just a scheme and a host, like https://box.example.com"
                    .into(),
            );
        }
        let host = rest.rsplit_once(':').map_or(rest, |(h, p)| {
            if p.bytes().all(|b| b.is_ascii_digit()) {
                h
            } else {
                rest
            }
        });
        let local = host == "localhost";
        if !(scheme == "https" || (scheme == "http" && local)) {
            return Err(
                "the public address must be https (plain http is accepted for localhost only)"
                    .into(),
            );
        }
        if host.parse::<std::net::IpAddr>().is_ok() || host.starts_with('[') {
            return Err("a passkey needs a host name, not an IP address".into());
        }
        if file.users.is_empty() {
            return Err("at least one person must be allowed to sign in".into());
        }
        let mut seen = std::collections::HashSet::new();
        for u in &mut file.users {
            if !valid_user_id(&u.id) || !seen.insert(u.id.clone()) {
                return Err(
                    "each person needs a unique id of lower-case letters, digits and -".into(),
                );
            }
            if let Some(g) = &mut u.github {
                *g = g.trim().to_ascii_lowercase();
                if !valid_login(g) {
                    return Err("a GitHub login has letters, digits and - only".into());
                }
            }
            for e in [&mut u.google, &mut u.access_email].into_iter().flatten() {
                *e = e.trim().to_ascii_lowercase();
                if !valid_email(e) {
                    return Err("an e-mail address is not valid".into());
                }
            }
            if u.label.is_empty() {
                u.label = u.id.clone();
            }
        }
        // somebody has to be able to change the settings: the first person is the owner unless the file says otherwise
        let has_owner = file.users.iter().enumerate().any(|(i, u)| {
            u.role == Some(ozbox_core::roles::Role::Owner) || (i == 0 && u.role.is_none())
        });
        if !has_owner {
            return Err("at least one person must be an owner".into());
        }
        if file.session_idle_hours == 0
            || file.session_absolute_days == 0
            || !(file.stepup_minutes > 0.0 && file.stepup_minutes <= 60.0)
        {
            return Err("session times must be more than zero, and the step-up window between 0 and 60 minutes".into());
        }
        if let Some(a) = &file.access {
            // An identity-aware proxy is trusted only after its token is verified, and that needs both values. A half
            // configuration is refused rather than ignored, so nobody believes Access is protecting the dashboard.
            let team_ok = a.team_domain.ends_with(".cloudflareaccess.com")
                && a.team_domain.len() > ".cloudflareaccess.com".len()
                && a.team_domain.bytes().all(|b| {
                    b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-' || b == b'.'
                });
            let aud_ok = !a.audience.is_empty()
                && a.audience.len() <= 128
                && a.audience.bytes().all(|b| b.is_ascii_alphanumeric());
            if !team_ok || !aud_ok {
                return Err("Cloudflare Access needs the team domain (like myteam.cloudflareaccess.com) and the application's audience tag".into());
            }
        }
        let rp = Rp {
            id: host.to_string(),
            origin: origin.clone(),
            name: file.name.clone(),
        };
        let cfg = Self {
            idle_ms: file.session_idle_hours * 3_600_000,
            absolute_ms: file.session_absolute_days * 86_400_000,
            stepup_ms: (file.stepup_minutes * 60_000.0) as u64,
            host: rest.to_string(),
            rp,
            file,
        };
        if cfg.strong_methods().is_empty() {
            return Err("this address cannot offer a passkey or Cloudflare Access, so nothing strong protects the dashboard; refusing to serve it publicly".into());
        }
        Ok(cfg)
    }

    /// Like [`Self::load`], but a public address given on the command line replaces the one in the file. Everything
    /// that depends on the address (passkey relying-party id, allowed Host and Origin, cookie scope, sign-in
    /// redirects) is derived from the result, so there is one place it can come from.
    pub fn load_with_origin(path: &std::path::Path, origin: Option<&str>) -> Result<Self, String> {
        let text = std::fs::read_to_string(path)
            .map_err(|_| "the sign-in settings file could not be read".to_string())?;
        let mut file: AuthFile = toml::from_str(&text)
            .map_err(|e| format!("the sign-in settings are not valid: {}", e.message()))?;
        if let Some(o) = origin {
            file.public_origin = o.trim().to_string();
        }
        Self::new(file)
    }

    /// The sign-in methods that stand on their own, without a second factor behind them: a passkey (always offered;
    /// `new` has already required an https host name, which is what a passkey needs) and Cloudflare Access with its
    /// token verified against the team's keys and this application's audience.
    pub fn strong_methods(&self) -> Vec<&'static str> {
        let mut m = Vec::new();
        let secure = self.rp.origin.starts_with("https://") || self.rp.id == "localhost";
        if secure && !self.rp.id.is_empty() {
            m.push("passkey");
        }
        if self.file.access.is_some() {
            m.push("cloudflare_access");
        }
        m
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn file(origin: &str) -> AuthFile {
        AuthFile {
            public_origin: origin.into(),
            users: vec![UserEntry {
                id: "owner".into(),
                github: Some("Alice".into()),
                ..Default::default()
            }],
            ..Default::default()
        }
    }

    #[test]
    fn the_origin_and_allow_list_are_validated() {
        let c = AuthConfig::new(file("https://box.example.com/")).unwrap();
        assert_eq!(c.rp.id, "box.example.com");
        assert_eq!(c.rp.origin, "https://box.example.com");
        assert_eq!(c.file.users[0].github.as_deref(), Some("alice"));
        assert_eq!(
            (c.idle_ms, c.absolute_ms, c.stepup_ms),
            (12 * 3_600_000, 7 * 86_400_000, 300_000)
        );
        let l = AuthConfig::new(file("http://localhost:8080")).unwrap();
        assert_eq!(
            (l.rp.id.as_str(), l.host.as_str()),
            ("localhost", "localhost:8080")
        );
        for bad in [
            "http://box.example.com",
            "https://box.example.com/x",
            "https://1.2.3.4",
            "box.example.com",
            "https://u@box.example.com",
        ] {
            assert!(AuthConfig::new(file(bad)).is_err(), "{bad}");
        }
        let mut none = file("https://box.example.com");
        none.users.clear();
        assert!(AuthConfig::new(none).is_err());
        let mut dup = file("https://box.example.com");
        dup.users.push(dup.users[0].clone());
        assert!(AuthConfig::new(dup).is_err());
    }

    #[test]
    fn a_half_configured_access_is_refused_and_a_complete_one_counts_as_strong() {
        let with = |team: &str, aud: &str| {
            let mut f = file("https://box.example.com");
            f.access = Some(AccessCfg {
                team_domain: team.into(),
                audience: aud.into(),
            });
            AuthConfig::new(f)
        };
        assert!(with("team.cloudflareaccess.com", "").is_err());
        assert!(with("", "abc123").is_err());
        assert!(
            with("team.example.com", "abc123").is_err(),
            "not an Access team domain"
        );
        assert!(with("team.cloudflareaccess.com", "a b").is_err());
        let ok = with("team.cloudflareaccess.com", "abc123").unwrap();
        assert_eq!(ok.strong_methods(), vec!["passkey", "cloudflare_access"]);
        let plain = AuthConfig::new(file("https://box.example.com")).unwrap();
        assert_eq!(plain.strong_methods(), vec!["passkey"]);
    }

    #[test]
    fn a_public_url_replaces_the_files_address_and_every_derived_value_follows() {
        let dir = std::env::temp_dir().join(format!("ozbox-cfg-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("auth.toml");
        std::fs::write(
            &path,
            "public_origin = \"https://old.example.com\"\n[[users]]\nid = \"owner\"\n",
        )
        .unwrap();
        let c = AuthConfig::load_with_origin(&path, Some("https://new.example.com:8443/")).unwrap();
        assert_eq!(c.rp.id, "new.example.com");
        assert_eq!(c.rp.origin, "https://new.example.com:8443");
        assert_eq!(c.host, "new.example.com:8443");
        assert!(AuthConfig::load_with_origin(&path, Some("http://new.example.com")).is_err());
        assert!(AuthConfig::load_with_origin(&path, Some("https://10.0.0.1")).is_err());
        assert_eq!(
            AuthConfig::load_with_origin(&path, None).unwrap().rp.id,
            "old.example.com"
        );
        std::fs::remove_dir_all(&dir).ok();
    }
}
