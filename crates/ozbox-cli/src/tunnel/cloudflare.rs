//! Cloudflare Tunnel with the person's own remotely managed tunnel: `cloudflared` runs with the tunnel token, and the
//! public hostname (set in the person's Cloudflare account) forwards to `http://localhost:<port>`.
//!
//! The token goes in `TUNNEL_TOKEN`, never in the argument list, where any user on the machine could read it.

use std::sync::Arc;

use ozbox_core::CommandSpec;

use super::{
    Env, Health, HttpClient, Kind, Process, Tunnel, TunnelError, TunnelFile, TunnelStatus,
};
use crate::secrets::SecretStore;

pub struct Cloudflare {
    public_url: String,
    secrets: Arc<dyn SecretStore>,
    process: Process,
    runner: Arc<dyn ozbox_core::CommandRunner>,
    /// On a box, cloudflared runs as the secrets user under this system unit (it is the only account that may open the
    /// token), so the dashboard starts nothing and only reports on the unit.
    system_unit: Option<String>,
}

impl Cloudflare {
    pub fn new(file: &TunnelFile, env: &Env) -> Self {
        Self {
            public_url: file.public_url.clone(),
            secrets: Arc::clone(&env.secrets),
            process: Process::new(Arc::clone(&env.spawner), Kind::Cloudflare.program()),
            runner: Arc::clone(&env.runner),
            system_unit: std::env::var("OZBOX_TUNNEL_SYSTEM_UNIT").ok().filter(|u| {
                u.bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b"-_.@".contains(&b))
                    && !u.is_empty()
            }),
        }
    }

    /// The command, without the token (which the caller adds to the environment).
    pub fn command() -> CommandSpec {
        CommandSpec::new("cloudflared").args(["tunnel", "--no-autoupdate", "run"])
    }
}

impl Cloudflare {
    fn unit_active(&self) -> bool {
        let Some(u) = &self.system_unit else {
            return false;
        };
        self.runner
            .run(&CommandSpec::new("systemctl").args(["is-active", "--quiet", u.as_str()]))
            .is_ok_and(|o| o.status == Some(0))
    }
}

impl Tunnel for Cloudflare {
    fn kind(&self) -> Kind {
        Kind::Cloudflare
    }

    fn start(&mut self) -> Result<(), TunnelError> {
        if self.system_unit.is_some() {
            // The token is only ever opened by the unit's own user; here it is enough that one is saved.
            return match self.secrets.exists("tunnel-token-cloudflare") {
                Ok(true) => Ok(()),
                _ => Err(TunnelError::NoToken),
            };
        }
        let token = self
            .secrets
            .get("tunnel-token-cloudflare")
            .ok()
            .flatten()
            .ok_or(TunnelError::NoToken)?;
        // The token lives in this one value for the length of the call.
        let cmd = Self::command().env("TUNNEL_TOKEN", token);
        self.process.start(&cmd)
    }

    fn stop(&mut self) -> Result<(), TunnelError> {
        self.process.stop();
        Ok(())
    }

    fn status(&mut self) -> TunnelStatus {
        match &self.system_unit {
            Some(_) if self.unit_active() => TunnelStatus::running(),
            Some(_) => TunnelStatus::failed("exited"),
            None => self.process.status(),
        }
    }

    fn health(&mut self, http: &dyn HttpClient) -> Health {
        let alive = match &self.system_unit {
            Some(_) => self.unit_active(),
            None => self.process.alive(),
        };
        if !alive {
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
    use crate::netguard::FakeHttp;
    use crate::tunnel::State;

    fn file() -> TunnelFile {
        TunnelFile {
            provider: "cloudflare".into(),
            public_url: "https://ozbox.example.com".into(),
            caddy: None,
        }
    }

    #[test]
    fn it_needs_a_saved_token_and_never_puts_it_in_the_argument_list() {
        let sp = Arc::new(FakeSpawner::default());
        let secrets = Arc::new(crate::secrets::MemorySecrets::default());
        let e = env(
            Arc::clone(&sp),
            Arc::new(ozbox_core::RecordingRunner::new()),
            Arc::clone(&secrets),
        );
        let mut t = Cloudflare::new(&file(), &e);
        assert_eq!(t.start(), Err(TunnelError::NoToken));
        assert!(sp.spawned.lock().unwrap().is_empty());
        secrets
            .set("tunnel-token-cloudflare", "SENTINEL-TOKEN")
            .unwrap();
        t.start().unwrap();
        let calls = sp.spawned.lock().unwrap().clone();
        assert_eq!(calls.len(), 1);
        assert_eq!(calls[0].program, "cloudflared");
        assert_eq!(calls[0].args, vec!["tunnel", "--no-autoupdate", "run"]);
        assert!(!calls[0].args.join(" ").contains("SENTINEL"));
        assert_eq!(calls[0].env.get("TUNNEL_TOKEN").unwrap(), "SENTINEL-TOKEN");
        // idempotent
        t.start().unwrap();
        assert_eq!(sp.spawned.lock().unwrap().len(), 1);
        assert_eq!(t.status(), TunnelStatus::running());
    }

    #[test]
    fn it_reports_a_dead_process_a_missing_program_and_the_public_address() {
        let sp = Arc::new(FakeSpawner::default());
        let secrets = Arc::new(crate::secrets::MemorySecrets::default());
        secrets.set("tunnel-token-cloudflare", "t").unwrap();
        let e = env(
            Arc::clone(&sp),
            Arc::new(ozbox_core::RecordingRunner::new()),
            secrets,
        );
        let mut t = Cloudflare::new(&file(), &e);
        let http = FakeHttp::default();
        assert_eq!(t.health(&http).code, "not_running");
        t.start().unwrap();
        http.reply(200, r#"{"mode":"session"}"#);
        assert!(t.health(&http).ok);
        assert_eq!(
            http.requests()[0].url,
            "https://ozbox.example.com/auth/session"
        );
        http.reply(502, "");
        assert_eq!(t.health(&http).code, "bad_status");
        sp.alive.store(false, std::sync::atomic::Ordering::SeqCst);
        assert_eq!(t.status().state, State::Failed);
        assert_eq!(t.status().code, Some("exited"));
        t.stop().unwrap();
        assert_eq!(t.status().state, State::Stopped);
        sp.missing.store(true, std::sync::atomic::Ordering::SeqCst);
        assert_eq!(t.start(), Err(TunnelError::ToolMissing("cloudflared")));
    }
}
