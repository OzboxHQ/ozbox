//! Reaching the dashboard from outside without opening a port (ADR 0005): an outbound tunnel the person brings
//! themselves, with their own account, token and domain.
//!
//! Five providers share one trait, [`Tunnel`]: Cloudflare Tunnel, Tailscale Funnel, Tailscale Serve, Caddy on the
//! person's own server behind a reverse SSH tunnel, and ngrok. Every command is an argv array (through
//! [`ozbox_core::CommandRunner`] for one-shot commands, through a [`Spawner`] for the long-running ones), a token is
//! handed to the program in its environment and never in its argument list, and nothing here keeps a token: it is read
//! from the secret store when the tunnel starts.

use std::collections::BTreeMap;
use std::path::Path;

use ozbox_core::CommandSpec;
use serde::{Deserialize, Serialize};

use crate::netguard::{Guard, HttpClient, HttpRequest};

pub mod caddy;
pub mod cloudflare;
pub mod ngrok;
pub mod runner;
pub mod tailscale;
pub mod unit;

/// Every short code a tunnel or its check can report. Each has a catalogue message `tunnel.code_<code>` (a test holds
/// the two lists together).
#[cfg(test)]
pub const KNOWN_CODES: [&str; 17] = [
    "no_token",
    "tool_missing",
    "spawn_failed",
    "exited",
    "signed_out",
    "name_mismatch",
    "funnel_is_on",
    "funnel_off",
    "tailscale_failed",
    "bad_answer",
    "bad_address",
    "ok",
    "unreachable",
    "refused",
    "bad_status",
    "not_running",
    "not_applicable",
];

/// The port `ozbox serve` listens on unless told otherwise.
pub const DEFAULT_PORT: u16 = 7878;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Kind {
    #[serde(rename = "cloudflare")]
    Cloudflare,
    #[serde(rename = "tailscale-funnel")]
    TailscaleFunnel,
    #[serde(rename = "tailscale-serve")]
    TailscaleServe,
    #[serde(rename = "caddy")]
    Caddy,
    #[serde(rename = "ngrok")]
    Ngrok,
}

pub const ALL_KINDS: [Kind; 5] = [
    Kind::Cloudflare,
    Kind::TailscaleFunnel,
    Kind::TailscaleServe,
    Kind::Caddy,
    Kind::Ngrok,
];

impl Kind {
    pub fn id(self) -> &'static str {
        match self {
            Kind::Cloudflare => "cloudflare",
            Kind::TailscaleFunnel => "tailscale-funnel",
            Kind::TailscaleServe => "tailscale-serve",
            Kind::Caddy => "caddy",
            Kind::Ngrok => "ngrok",
        }
    }

    pub fn parse(id: &str) -> Option<Kind> {
        ALL_KINDS.into_iter().find(|k| k.id() == id)
    }

    /// The program the tunnel runs, which must be installed where the tunnel runs.
    pub fn program(self) -> &'static str {
        match self {
            Kind::Cloudflare => "cloudflared",
            Kind::TailscaleFunnel | Kind::TailscaleServe => "tailscale",
            Kind::Caddy => "ssh",
            Kind::Ngrok => "ngrok",
        }
    }

    /// The name of the write-only secret holding the person's token, if the provider uses one.
    pub fn token_secret(self) -> Option<&'static str> {
        match self {
            Kind::Cloudflare => Some("tunnel-token-cloudflare"),
            Kind::Ngrok => Some("tunnel-token-ngrok"),
            _ => None,
        }
    }

    /// Does anyone on the internet reach the address? Tailscale Serve is the one that stays inside the tailnet.
    pub fn is_public(self) -> bool {
        self != Kind::TailscaleServe
    }

    /// Can the machine running the tunnel check its own public address over the internet? A tailnet-only name resolves
    /// to a private address, which the outbound guard refuses, so that provider is checked through `tailscale` instead.
    pub fn probes_public_url(self) -> bool {
        self != Kind::TailscaleServe
    }
}

/// How the person's own server (for Caddy) is reached. The private key is a file the person made; only its path is
/// kept here, never the key.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct CaddyCfg {
    pub host: String,
    pub user: String,
    pub ssh_port: u16,
    /// Path of the private key file on the machine running the tunnel.
    pub key_file: String,
    /// The loopback port on the server that Caddy forwards to.
    pub remote_port: u16,
}

impl Default for CaddyCfg {
    fn default() -> Self {
        Self {
            host: String::new(),
            user: String::new(),
            ssh_port: 22,
            key_file: String::new(),
            remote_port: 7878,
        }
    }
}

/// `tunnel.toml`: which provider, and the public address it serves. Holds no secret.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(default, deny_unknown_fields)]
pub struct TunnelFile {
    pub provider: String,
    pub public_url: String,
    pub caddy: Option<CaddyCfg>,
}

fn host_ok(h: &str) -> bool {
    !h.is_empty()
        && h.len() <= 253
        && !h.starts_with(['-', '.'])
        && !h.ends_with(['-', '.'])
        && h.bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'.')
}

fn user_ok(u: &str) -> bool {
    !u.is_empty()
        && u.len() <= 32
        && !u.starts_with('-')
        && u.bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_' || b == b'.')
}

fn path_ok(p: &str) -> bool {
    !p.is_empty()
        && p.len() <= 256
        && !p.starts_with('-')
        && p.bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'/' | b'.' | b'_' | b'-' | b'~'))
}

/// The host of an `https://host[:port]` address, or why it is not one.
pub fn public_host(url: &str) -> Result<String, &'static str> {
    let rest = url
        .trim_end_matches('/')
        .strip_prefix("https://")
        .ok_or("tunnel.public_url_https")?;
    if rest.contains(['/', '?', '#', '@', ' ']) || rest.is_empty() {
        return Err("tunnel.public_url_shape");
    }
    let host = rest.split(':').next().unwrap_or("");
    if !host_ok(host) || host.parse::<std::net::IpAddr>().is_ok() || !host.contains('.') {
        return Err("tunnel.public_url_shape");
    }
    Ok(host.to_ascii_lowercase())
}

impl TunnelFile {
    pub fn kind(&self) -> Option<Kind> {
        Kind::parse(&self.provider)
    }

    /// Everything that can be checked without running anything. The error is a catalogue key.
    pub fn validate(&self) -> Result<Kind, &'static str> {
        let kind = self.kind().ok_or("tunnel.bad_provider")?;
        let host = public_host(&self.public_url)?;
        if matches!(kind, Kind::TailscaleFunnel | Kind::TailscaleServe)
            && !host.ends_with(".ts.net")
        {
            return Err("tunnel.tailscale_name");
        }
        if kind == Kind::Caddy {
            let c = self.caddy.as_ref().ok_or("tunnel.caddy_missing")?;
            if !host_ok(&c.host)
                || !user_ok(&c.user)
                || !path_ok(&c.key_file)
                || c.ssh_port == 0
                || c.remote_port < 1024
            {
                return Err("tunnel.caddy_bad");
            }
        }
        Ok(kind)
    }

    pub fn load(path: &Path) -> Result<Option<TunnelFile>, String> {
        match std::fs::read_to_string(path) {
            Ok(text) => toml::from_str(&text)
                .map(Some)
                .map_err(|e| format!("the tunnel settings are not valid: {}", e.message())),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(_) => Err("the tunnel settings could not be read".into()),
        }
    }

    pub fn save(&self, path: &Path) -> Result<(), String> {
        if let Some(dir) = path.parent() {
            let _ = std::fs::create_dir_all(dir);
        }
        let text = toml::to_string_pretty(self).map_err(|e| e.to_string())?;
        std::fs::write(path, text).map_err(|_| "the tunnel settings could not be written".into())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum State {
    Stopped,
    Running,
    Failed,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct TunnelStatus {
    pub state: State,
    /// A short code the dashboard and the command line turn into words; `None` when all is well.
    pub code: Option<&'static str>,
}

impl TunnelStatus {
    pub fn running() -> Self {
        Self {
            state: State::Running,
            code: None,
        }
    }
    pub fn stopped() -> Self {
        Self {
            state: State::Stopped,
            code: None,
        }
    }
    pub fn failed(code: &'static str) -> Self {
        Self {
            state: State::Failed,
            code: Some(code),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Health {
    pub ok: bool,
    /// `ok`, `unreachable`, `refused`, `bad_answer`, `not_running`, `not_applicable` or a status code from the provider.
    pub code: &'static str,
    pub http_status: Option<u16>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TunnelError {
    /// The token was not saved yet.
    NoToken,
    /// The provider's program is not installed here.
    ToolMissing(&'static str),
    /// Anything else, as a short code. Never carries a token or a command line.
    Failed(&'static str),
}

impl TunnelError {
    pub fn code(&self) -> &'static str {
        match self {
            TunnelError::NoToken => "no_token",
            TunnelError::ToolMissing(_) => "tool_missing",
            TunnelError::Failed(c) => c,
        }
    }
}

/// A tunnel the person owns. `start` is idempotent; `stop` leaves nothing running that this started.
pub trait Tunnel: Send {
    fn kind(&self) -> Kind;
    fn start(&mut self) -> Result<(), TunnelError>;
    fn stop(&mut self) -> Result<(), TunnelError>;
    fn status(&mut self) -> TunnelStatus;
    /// Is the dashboard reachable the way people will reach it?
    fn health(&mut self, http: &dyn HttpClient) -> Health;
}

/// Ask the public address for the dashboard's own sign-in mode (no sign-in needed to ask). A real answer proves the
/// whole path: DNS, the tunnel, the loopback server and the Host check.
pub fn probe(http: &dyn HttpClient, public_url: &str) -> Health {
    let url = format!("{}/auth/session", public_url.trim_end_matches('/'));
    let req = HttpRequest::new("GET", url, Guard::Public);
    match http.send(&req) {
        Ok(r)
            if r.status == 200
                && serde_json::from_str::<serde_json::Value>(&r.body)
                    .is_ok_and(|v| v.get("mode").is_some()) =>
        {
            Health {
                ok: true,
                code: "ok",
                http_status: Some(200),
            }
        }
        Ok(r) if r.status == 200 => Health {
            ok: false,
            code: "bad_answer",
            http_status: Some(200),
        },
        Ok(r) => Health {
            ok: false,
            code: "bad_status",
            http_status: Some(r.status),
        },
        Err(crate::netguard::HttpError::Refused(_)) => Health {
            ok: false,
            code: "refused",
            http_status: None,
        },
        Err(_) => Health {
            ok: false,
            code: "unreachable",
            http_status: None,
        },
    }
}

// ---- Long-running programs ----

pub trait Child: Send {
    /// Is the program still running?
    fn alive(&mut self) -> bool;
    fn kill(&mut self);
}

pub trait Spawner: Send + Sync {
    /// Start the program and return at once. `Err(true)` means the program is not installed.
    fn spawn(&self, cmd: &CommandSpec) -> Result<Box<dyn Child>, bool>;
}

#[derive(Debug, Default, Clone, Copy)]
pub struct SystemSpawner;

struct SysChild(std::process::Child);

impl Child for SysChild {
    fn alive(&mut self) -> bool {
        matches!(self.0.try_wait(), Ok(None))
    }
    fn kill(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

impl Spawner for SystemSpawner {
    fn spawn(&self, cmd: &CommandSpec) -> Result<Box<dyn Child>, bool> {
        use std::process::{Command, Stdio};
        let mut c = Command::new(&cmd.program);
        c.args(&cmd.args)
            .envs(&cmd.env)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null());
        match c.spawn() {
            Ok(child) => Ok(Box::new(SysChild(child))),
            Err(e) => Err(e.kind() == std::io::ErrorKind::NotFound),
        }
    }
}

/// The part every long-running tunnel shares: start once, notice when it died, stop it.
pub struct Process {
    spawner: std::sync::Arc<dyn Spawner>,
    child: Option<Box<dyn Child>>,
    program: &'static str,
}

impl Process {
    pub fn new(spawner: std::sync::Arc<dyn Spawner>, program: &'static str) -> Self {
        Self {
            spawner,
            child: None,
            program,
        }
    }

    pub fn start(&mut self, cmd: &CommandSpec) -> Result<(), TunnelError> {
        if self.alive() {
            return Ok(());
        }
        match self.spawner.spawn(cmd) {
            Ok(c) => {
                self.child = Some(c);
                Ok(())
            }
            Err(true) => Err(TunnelError::ToolMissing(self.program)),
            Err(false) => Err(TunnelError::Failed("spawn_failed")),
        }
    }

    pub fn alive(&mut self) -> bool {
        self.child.as_mut().is_some_and(|c| c.alive())
    }

    pub fn stop(&mut self) {
        if let Some(mut c) = self.child.take() {
            c.kill();
        }
    }

    pub fn status(&mut self) -> TunnelStatus {
        match (self.child.is_some(), self.alive()) {
            (_, true) => TunnelStatus::running(),
            (true, false) => TunnelStatus::failed("exited"),
            (false, false) => TunnelStatus::stopped(),
        }
    }
}

/// What starts a tunnel: the settings, the port the dashboard listens on, how to run programs, and the secret store.
pub struct Env {
    pub port: u16,
    pub spawner: std::sync::Arc<dyn Spawner>,
    pub runner: std::sync::Arc<dyn ozbox_core::CommandRunner>,
    pub secrets: std::sync::Arc<dyn crate::secrets::SecretStore>,
}

/// Build the tunnel for validated settings.
pub fn build(file: &TunnelFile, env: &Env) -> Result<Box<dyn Tunnel>, &'static str> {
    let kind = file.validate()?;
    Ok(match kind {
        Kind::Cloudflare => Box::new(cloudflare::Cloudflare::new(file, env)),
        Kind::Ngrok => Box::new(ngrok::Ngrok::new(file, env)),
        Kind::Caddy => Box::new(caddy::Caddy::new(file, env)),
        Kind::TailscaleFunnel | Kind::TailscaleServe => {
            Box::new(tailscale::Tailscale::new(kind, file, env))
        }
    })
}

/// For the dashboard's provider list.
pub fn catalogue() -> Vec<BTreeMap<&'static str, serde_json::Value>> {
    ALL_KINDS
        .iter()
        .map(|k| {
            let mut m = BTreeMap::new();
            m.insert("id", serde_json::json!(k.id()));
            m.insert("public", serde_json::json!(k.is_public()));
            m.insert("program", serde_json::json!(k.program()));
            m.insert("token_secret", serde_json::json!(k.token_secret()));
            m
        })
        .collect()
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
pub mod testing {
    //! Fakes shared by the provider tests.
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::{Arc, Mutex};

    use super::*;

    #[derive(Default)]
    pub struct FakeSpawner {
        pub spawned: Mutex<Vec<CommandSpec>>,
        pub alive: Arc<AtomicBool>,
        pub missing: AtomicBool,
    }

    pub struct FakeChild(Arc<AtomicBool>);

    impl Child for FakeChild {
        fn alive(&mut self) -> bool {
            self.0.load(Ordering::SeqCst)
        }
        fn kill(&mut self) {
            self.0.store(false, Ordering::SeqCst);
        }
    }

    impl Spawner for FakeSpawner {
        fn spawn(&self, cmd: &CommandSpec) -> Result<Box<dyn Child>, bool> {
            if self.missing.load(Ordering::SeqCst) {
                return Err(true);
            }
            self.spawned.lock().unwrap().push(cmd.clone());
            self.alive.store(true, Ordering::SeqCst);
            Ok(Box::new(FakeChild(Arc::clone(&self.alive))))
        }
    }

    pub fn env(
        spawner: Arc<FakeSpawner>,
        runner: Arc<ozbox_core::RecordingRunner>,
        secrets: Arc<crate::secrets::MemorySecrets>,
    ) -> Env {
        Env {
            port: 7878,
            spawner,
            runner,
            secrets,
        }
    }
}
