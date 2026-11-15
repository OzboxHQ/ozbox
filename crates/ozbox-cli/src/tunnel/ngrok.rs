//! ngrok with the person's own account: `ngrok http` publishes the dashboard on the person's domain. A custom domain
//! needs one of ngrok's paid plans; the account's free static domain also works. The auth token goes in
//! `NGROK_AUTHTOKEN`, never in the argument list.

use std::sync::Arc;

use ozbox_core::CommandSpec;

use super::{
    public_host, Env, Health, HttpClient, Kind, Process, Tunnel, TunnelError, TunnelFile,
    TunnelStatus,
};
use crate::secrets::SecretStore;

pub struct Ngrok {
    public_url: String,
    port: u16,
    secrets: Arc<dyn SecretStore>,
    process: Process,
}

impl Ngrok {
    pub fn new(file: &TunnelFile, env: &Env) -> Self {
        Self {
            public_url: file.public_url.clone(),
            port: env.port,
            secrets: Arc::clone(&env.secrets),
            process: Process::new(Arc::clone(&env.spawner), Kind::Ngrok.program()),
        }
    }

    pub fn command(public_url: &str, port: u16) -> Result<CommandSpec, TunnelError> {
        let host = public_host(public_url).map_err(|_| TunnelError::Failed("bad_address"))?;
        Ok(CommandSpec::new("ngrok").args([
            "http".to_string(),
            format!("127.0.0.1:{port}"),
            format!("--url=https://{host}"),
            "--log=false".to_string(),
        ]))
    }
}

impl Tunnel for Ngrok {
    fn kind(&self) -> Kind {
        Kind::Ngrok
    }

    fn start(&mut self) -> Result<(), TunnelError> {
        let token = self
            .secrets
            .get("tunnel-token-ngrok")
            .ok()
            .flatten()
            .ok_or(TunnelError::NoToken)?;
        let cmd = Self::command(&self.public_url, self.port)?.env("NGROK_AUTHTOKEN", token);
        self.process.start(&cmd)
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

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::super::testing::*;
    use super::*;

    #[test]
    fn the_domain_and_port_are_arguments_and_the_token_is_environment() {
        let sp = Arc::new(FakeSpawner::default());
        let secrets = Arc::new(crate::secrets::MemorySecrets::default());
        let e = env(
            Arc::clone(&sp),
            Arc::new(ozbox_core::RecordingRunner::new()),
            Arc::clone(&secrets),
        );
        let f = TunnelFile {
            provider: "ngrok".into(),
            public_url: "https://ozbox.example.com".into(),
            caddy: None,
        };
        let mut t = Ngrok::new(&f, &e);
        assert_eq!(t.start(), Err(TunnelError::NoToken));
        secrets.set("tunnel-token-ngrok", "SENTINEL").unwrap();
        t.start().unwrap();
        let c = sp.spawned.lock().unwrap()[0].clone();
        assert_eq!(c.program, "ngrok");
        assert_eq!(
            c.args,
            vec![
                "http",
                "127.0.0.1:7878",
                "--url=https://ozbox.example.com",
                "--log=false"
            ]
        );
        assert!(!c.args.join(" ").contains("SENTINEL"));
        assert_eq!(c.env.get("NGROK_AUTHTOKEN").unwrap(), "SENTINEL");
        assert!(Ngrok::command("http://x.example.com", 1).is_err());
    }
}
