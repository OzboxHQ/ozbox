//! `code.toml`: which box's IDE or desktop is served on which of the person's own addresses. Holds no secret.

use std::path::Path;

use serde::{Deserialize, Serialize};

use super::Service;
use crate::tunnel::{public_host, Kind};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PublicHost {
    #[serde(rename = "box")]
    pub box_name: String,
    pub service: Service,
    /// The host name only, lower case: `ide.example.com`.
    pub host: String,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct CodeSettings {
    #[serde(default)]
    pub public: Vec<PublicHost>,
}

/// Can this kind of tunnel carry one more host name? Cloudflare's tunnel (a Public Hostname per name) and Caddy (a site
/// per name) can; Tailscale serves one name per machine and ngrok's free address is one name.
pub fn supports_more_hosts(kind: Kind) -> bool {
    matches!(kind, Kind::Cloudflare | Kind::Caddy)
}

impl CodeSettings {
    pub fn load(path: &Path) -> Result<Self, String> {
        match std::fs::read_to_string(path) {
            Ok(t) => toml::from_str(&t)
                .map_err(|e| format!("the code settings are not valid: {}", e.message())),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(Self::default()),
            Err(_) => Err("the code settings could not be read".into()),
        }
    }

    pub fn save(&self, path: &Path) -> Result<(), String> {
        if let Some(d) = path.parent() {
            let _ = std::fs::create_dir_all(d);
        }
        let t = toml::to_string_pretty(self).map_err(|e| e.to_string())?;
        std::fs::write(path, t).map_err(|_| "the code settings could not be written".to_string())
    }

    pub fn host_of(&self, box_name: &str, s: Service) -> Option<&str> {
        self.public
            .iter()
            .find(|p| p.box_name == box_name && p.service == s)
            .map(|p| p.host.as_str())
    }

    /// Who is served on this host name.
    pub fn by_host(&self, host: &str) -> Option<&PublicHost> {
        self.public
            .iter()
            .find(|p| p.host.eq_ignore_ascii_case(host))
    }

    /// Serve `box`'s `service` on `address` (`https://ide.example.com`). Checks everything that can be checked without
    /// the network: the shape, that it is not the dashboard's own host, that no other service has it, and that the
    /// tunnel can carry another host. Returns the host.
    pub fn set(
        &mut self,
        box_name: &str,
        service: Service,
        address: &str,
        dashboard_host: Option<&str>,
        tunnel: Option<Kind>,
    ) -> Result<String, &'static str> {
        let host = public_host(address)?;
        if tunnel.is_some_and(|k| !supports_more_hosts(k)) {
            return Err("code.err_tunnel_one_host");
        }
        if dashboard_host.is_some_and(|d| d.eq_ignore_ascii_case(&host)) {
            return Err("code.err_same_as_dashboard");
        }
        if self
            .public
            .iter()
            .any(|p| p.host == host && !(p.box_name == box_name && p.service == service))
        {
            return Err("code.err_host_taken");
        }
        self.public
            .retain(|p| !(p.box_name == box_name && p.service == service));
        self.public.push(PublicHost {
            box_name: box_name.to_string(),
            service,
            host: host.clone(),
        });
        Ok(host)
    }

    pub fn clear(&mut self, box_name: &str, service: Service) -> bool {
        let before = self.public.len();
        self.public
            .retain(|p| !(p.box_name == box_name && p.service == service));
        self.public.len() != before
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_host_is_checked_stored_replaced_and_cleared() {
        let mut s = CodeSettings::default();
        let h = s
            .set(
                "dev",
                Service::Ide,
                "https://IDE.example.com/",
                Some("ozbox.example.com"),
                Some(Kind::Cloudflare),
            )
            .unwrap();
        assert_eq!(h, "ide.example.com");
        assert_eq!(s.host_of("dev", Service::Ide), Some("ide.example.com"));
        assert_eq!(s.by_host("Ide.Example.com").unwrap().box_name, "dev");
        // another name replaces the first for the same box and service
        s.set("dev", Service::Ide, "https://code.example.com", None, None)
            .unwrap();
        assert_eq!(s.public.len(), 1);
        assert!(s.clear("dev", Service::Ide));
        assert!(!s.clear("dev", Service::Ide));
    }

    #[test]
    fn refusals_say_why() {
        let mut s = CodeSettings::default();
        assert_eq!(
            s.set("dev", Service::Ide, "http://ide.example.com", None, None),
            Err("tunnel.public_url_https")
        );
        assert_eq!(
            s.set(
                "dev",
                Service::Ide,
                "https://ozbox.example.com",
                Some("ozbox.example.com"),
                None
            ),
            Err("code.err_same_as_dashboard")
        );
        assert_eq!(
            s.set(
                "dev",
                Service::Ide,
                "https://ide.example.com",
                None,
                Some(Kind::TailscaleFunnel)
            ),
            Err("code.err_tunnel_one_host")
        );
        assert_eq!(
            s.set(
                "dev",
                Service::Ide,
                "https://ide.example.com",
                None,
                Some(Kind::Ngrok)
            ),
            Err("code.err_tunnel_one_host")
        );
        s.set("dev", Service::Ide, "https://ide.example.com", None, None)
            .unwrap();
        assert_eq!(
            s.set("other", Service::Ide, "https://ide.example.com", None, None),
            Err("code.err_host_taken")
        );
    }

    #[test]
    fn it_round_trips_through_a_file_and_a_missing_file_is_empty() {
        let d = tempfile::tempdir().unwrap();
        let p = d.path().join("code.toml");
        assert_eq!(CodeSettings::load(&p).unwrap(), CodeSettings::default());
        let mut s = CodeSettings::default();
        s.set(
            "dev",
            Service::Desktop,
            "https://desk.example.com",
            None,
            None,
        )
        .unwrap();
        s.save(&p).unwrap();
        assert_eq!(CodeSettings::load(&p).unwrap(), s);
        std::fs::write(&p, "nonsense = 1").unwrap();
        assert!(CodeSettings::load(&p).is_err());
    }
}
