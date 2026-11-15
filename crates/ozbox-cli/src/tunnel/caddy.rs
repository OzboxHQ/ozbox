//! Caddy on the person's own server, reached by a reverse SSH tunnel that the box dials out. Caddy on that server
//! terminates TLS (its own Let's Encrypt certificate) and forwards to a loopback port; the SSH session carries that
//! port back to this computer's dashboard. Nothing connects inward: this side only ever opens the one outbound
//! connection. The key is a file the person made for this one job; only its path is kept.

use std::sync::Arc;

use ozbox_core::CommandSpec;

use super::{
    CaddyCfg, Env, Health, HttpClient, Kind, Process, Tunnel, TunnelError, TunnelFile, TunnelStatus,
};

pub struct Caddy {
    public_url: String,
    port: u16,
    cfg: CaddyCfg,
    process: Process,
}

impl Caddy {
    pub fn new(file: &TunnelFile, env: &Env) -> Self {
        Self {
            public_url: file.public_url.clone(),
            port: env.port,
            cfg: file.caddy.clone().unwrap_or_default(),
            process: Process::new(Arc::clone(&env.spawner), Kind::Caddy.program()),
        }
    }

    /// The whole command. The server's identity is pinned (`StrictHostKeyChecking=yes`), nothing is ever asked on a
    /// terminal (`BatchMode`), and the forward must bind or the session ends (`ExitOnForwardFailure`).
    pub fn command(cfg: &CaddyCfg, port: u16) -> CommandSpec {
        CommandSpec::new("ssh").args([
            "-N".to_string(),
            "-T".to_string(),
            "-o".to_string(),
            "ExitOnForwardFailure=yes".to_string(),
            "-o".to_string(),
            "ServerAliveInterval=30".to_string(),
            "-o".to_string(),
            "ServerAliveCountMax=3".to_string(),
            "-o".to_string(),
            "StrictHostKeyChecking=yes".to_string(),
            "-o".to_string(),
            "BatchMode=yes".to_string(),
            "-o".to_string(),
            "IdentitiesOnly=yes".to_string(),
            "-i".to_string(),
            cfg.key_file.clone(),
            "-p".to_string(),
            cfg.ssh_port.to_string(),
            "-R".to_string(),
            format!("127.0.0.1:{}:127.0.0.1:{port}", cfg.remote_port),
            format!("{}@{}", cfg.user, cfg.host),
        ])
    }
}

impl Tunnel for Caddy {
    fn kind(&self) -> Kind {
        Kind::Caddy
    }

    fn start(&mut self) -> Result<(), TunnelError> {
        self.process.start(&Self::command(&self.cfg, self.port))
    }

    fn stop(&mut self) -> Result<(), TunnelError> {
        self.process.stop();
        Ok(())
    }

    fn status(&mut self) -> TunnelStatus {
        self.process.status()
    }

    fn health(&mut self, http: &dyn HttpClient) -> Health {
        if !self.process.alive() {
            return Health {
                ok: false,
                code: "not_running",
                http_status: None,
            };
        }
        super::probe(http, &self.public_url)
    }
}

/// The Caddyfile the person puts on their own server, for the guide.
pub fn caddyfile(public_url: &str, remote_port: u16) -> String {
    let host = super::public_host(public_url).unwrap_or_else(|_| "ozbox.example.com".into());
    format!("{host} {{\n\treverse_proxy 127.0.0.1:{remote_port}\n}}\n")
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::super::testing::*;
    use super::*;

    fn file() -> TunnelFile {
        TunnelFile {
            provider: "caddy".into(),
            public_url: "https://ozbox.example.com".into(),
            caddy: Some(CaddyCfg {
                host: "vps.example.com".into(),
                user: "ozbox-tunnel".into(),
                ssh_port: 22,
                key_file: "/etc/ozbox/tunnel_ed25519".into(),
                remote_port: 7878,
            }),
        }
    }

    #[test]
    fn the_box_only_dials_out_and_pins_the_servers_identity() {
        let sp = Arc::new(FakeSpawner::default());
        let e = env(
            Arc::clone(&sp),
            Arc::new(ozbox_core::RecordingRunner::new()),
            Arc::new(crate::secrets::MemorySecrets::default()),
        );
        let mut t = Caddy::new(&file(), &e);
        t.start().unwrap();
        let c = sp.spawned.lock().unwrap()[0].clone();
        assert_eq!(c.program, "ssh");
        let a = c.args.join(" ");
        assert!(a.contains("-R 127.0.0.1:7878:127.0.0.1:7878"), "{a}");
        assert!(a.contains("StrictHostKeyChecking=yes") && a.contains("BatchMode=yes"));
        assert!(a.contains("ExitOnForwardFailure=yes"));
        assert!(a.ends_with("ozbox-tunnel@vps.example.com"));
        // a remote forward only ever listens on the server's loopback; no local listener, no -L, no -D
        assert!(!a.contains(" -L") && !a.contains(" -D") && !a.contains("0.0.0.0"));
        assert_eq!(t.status(), TunnelStatus::running());
    }

    #[test]
    fn settings_that_could_inject_an_option_are_refused() {
        let mut f = file();
        f.caddy.as_mut().unwrap().host = "-oProxyCommand=x".into();
        assert_eq!(f.validate(), Err("tunnel.caddy_bad"));
        let mut f = file();
        f.caddy.as_mut().unwrap().user = "a b".into();
        assert_eq!(f.validate(), Err("tunnel.caddy_bad"));
        let mut f = file();
        f.caddy.as_mut().unwrap().key_file = "-i/etc/passwd".into();
        assert_eq!(f.validate(), Err("tunnel.caddy_bad"));
        let mut f = file();
        f.caddy = None;
        assert_eq!(f.validate(), Err("tunnel.caddy_missing"));
        assert!(file().validate().is_ok());
        assert_eq!(
            caddyfile("https://ozbox.example.com", 7878),
            "ozbox.example.com {\n\treverse_proxy 127.0.0.1:7878\n}\n"
        );
    }
}
