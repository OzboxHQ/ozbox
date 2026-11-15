//! `/v1/dashboard-access`: how this dashboard is reached from outside, and the tunnel that carries it. The page that
//! shows it (Settings, Dashboard access) lets a person save the provider and the address, check the address, and
//! forget it. A token is written through the secrets route and is never returned. A saved change takes effect the
//! next time `ozbox serve` starts, unless the person starts or restarts the tunnel from the page, which applies the
//! saved settings at once. Starting, stopping and restarting need a fresh passkey in sign-in mode, like saving.

use std::path::PathBuf;
use std::sync::{Arc, Mutex};

use serde_json::{json, Value};

use super::{unix_ms, App, Req, Resp};
use crate::tunnel::runner::{Runner, Snapshot};
use crate::tunnel::{self, CaddyCfg, Kind, State, TunnelFile};

/// Builds a tunnel runner from saved settings. The server supplies one that uses the real programs; tests supply fakes.
pub type RunnerFactory = Box<dyn Fn(&TunnelFile) -> Result<Runner, &'static str> + Send>;

/// What the server knows about how it is reached.
#[derive(Default)]
pub struct AccessCtx {
    /// `tunnel.toml`, when this installation has a place for settings.
    pub tunnel_path: Option<PathBuf>,
    /// The sign-in methods that stand alone, in public mode. Empty in the local-token mode.
    pub strong_methods: Vec<&'static str>,
    /// The public address in sign-in mode.
    pub public_url: Option<String>,
    /// The running tunnel's state, when this process started one.
    pub snapshot: Option<Arc<Mutex<Snapshot>>>,
    /// The tunnel this process keeps up, when it has one. The dashboard starts, stops and restarts it through here.
    pub runner: Option<Runner>,
    /// How to make a tunnel from the saved settings, so a tunnel can be started that was not running at start-up.
    pub factory: Option<RunnerFactory>,
}

fn lock(m: &Mutex<Snapshot>) -> std::sync::MutexGuard<'_, Snapshot> {
    m.lock().unwrap_or_else(|e| e.into_inner())
}

#[derive(serde::Deserialize, Default)]
#[serde(default, deny_unknown_fields)]
struct PutTunnel {
    provider: String,
    public_url: String,
    caddy: Option<CaddyCfg>,
}

impl App {
    pub(super) fn dashboard_access(&mut self, req: &Req, rest: &[&str]) -> Resp {
        match (req.method.as_str(), rest) {
            ("GET", []) => self.access_status(),
            ("PUT", ["tunnel"]) => self.access_save(req),
            ("DELETE", ["tunnel"]) => self.access_remove(req),
            ("POST", ["check"]) => self.access_check(),
            ("POST", ["tunnel", action @ ("start" | "stop" | "restart")]) => {
                self.access_control(req, action)
            }
            (_, [] | ["tunnel"] | ["check"] | ["tunnel", "start" | "stop" | "restart"]) => {
                Resp::error(405, "method_not_allowed", "method not allowed")
            }
            _ => Resp::error(404, "not_found", "no such endpoint"),
        }
    }

    fn saved_tunnel(&self) -> Result<Option<TunnelFile>, Resp> {
        let Some(p) = self.access.tunnel_path.as_deref() else {
            return Ok(None);
        };
        TunnelFile::load(p).map_err(|_| {
            Resp::error(
                500,
                "tunnel_settings_unreadable",
                "the saved tunnel settings could not be read",
            )
        })
    }

    fn token_set(&self, kind: Kind) -> Value {
        match kind.token_secret() {
            None => Value::Null,
            Some(name) => json!(self.secrets.exists(name).unwrap_or(false)),
        }
    }

    fn access_status(&self) -> Resp {
        let saved = match self.saved_tunnel() {
            Ok(s) => s,
            Err(r) => return r,
        };
        let tunnel = saved.as_ref().and_then(|f| {
            let kind = f.kind()?;
            let snapshot = match &self.access.runner {
                Some(r) => Some(r.snapshot()),
                None => self.access.snapshot.clone(),
            };
            let live = snapshot
                .as_ref()
                .map(|s| serde_json::to_value(&*lock(s)).unwrap_or(Value::Null));
            Some(json!({
                "provider": kind.id(),
                "public_url": f.public_url,
                "public": kind.is_public(),
                "token_secret": kind.token_secret(),
                "token_set": self.token_set(kind),
                "caddy": f.caddy,
                // `running` is what this process started; without it the tunnel is whatever the person runs by hand.
                "managed": live.is_some(),
                "live": live,
            }))
        });
        Resp::json(
            200,
            &json!({
                "mode": if self.auth.is_some() { "public" } else { "token" },
                "public_url": self.access.public_url,
                "strong_methods": self.access.strong_methods,
                "can_save": self.access.tunnel_path.is_some(),
                "can_control": self.access.factory.is_some(),
                "tunnel": tunnel,
                "providers": tunnel::catalogue(),
            }),
        )
    }

    /// Behind a sign-in, changing how the dashboard is reached needs a passkey shown a moment ago, like a change that
    /// cannot be undone.
    pub(super) fn access_step_up(&self, req: &Req) -> Option<Resp> {
        super::roles::step_up_refusal(
            self.step_up_state(req),
            "changing how this dashboard is reached",
        )
    }

    /// As [`App::access_step_up`], for an act that only reduces how far the dashboard is reached (stopping or removing the
    /// tunnel, deleting its token). On a box with no sign-in it is allowed: refusing to turn exposure off would be the
    /// wrong side to fail on. Behind a sign-in it still needs the passkey.
    pub(super) fn access_step_up_reducing(&self, req: &Req) -> Option<Resp> {
        match self.step_up_state(req) {
            super::roles::StepUp::LocalOnly => None,
            _ => self.access_step_up(req),
        }
    }

    /// A tunnel token being replaced needs the full second factor; being deleted only reduces exposure.
    pub(super) fn token_step_up(&self, req: &Req) -> Option<Resp> {
        if req.method == "DELETE" {
            self.access_step_up_reducing(req)
        } else {
            self.access_step_up(req)
        }
    }

    fn access_save(&mut self, req: &Req) -> Resp {
        if let Some(r) = self.access_step_up(req) {
            return r;
        }
        let Some(path) = self.access.tunnel_path.clone() else {
            return Resp::error(
                409,
                "no_settings_file",
                "this server has nowhere to keep settings",
            );
        };
        let body: PutTunnel = match serde_json::from_slice(&req.body) {
            Ok(b) => b,
            Err(_) => return Resp::error(400, "bad_request", "the request is not valid"),
        };
        let file = TunnelFile {
            provider: body.provider,
            public_url: body.public_url.trim().trim_end_matches('/').to_string(),
            caddy: body.caddy,
        };
        if let Err(key) = file.validate() {
            return Resp::error(400, key, &crate::messages::t(key, &[]));
        }
        // In sign-in mode the tunnel must serve the address the sign-in is bound to, or people would land on a page
        // that refuses them.
        if let Some(open) = &self.access.public_url {
            if open.trim_end_matches('/') != file.public_url {
                return Resp::error(
                    400,
                    "tunnel.address_differs",
                    &crate::messages::t("tunnel.address_differs", &[("address", open)]),
                );
            }
        }
        if file.save(&path).is_err() {
            return Resp::error(500, "save_failed", "the tunnel settings could not be saved");
        }
        self.log_activity(
            "save the tunnel settings",
            file.provider.as_str(),
            None,
            "ok",
        );
        self.access_status()
    }

    fn access_remove(&mut self, req: &Req) -> Resp {
        if let Some(r) = self.access_step_up_reducing(req) {
            return r;
        }
        let saved = match self.saved_tunnel() {
            Ok(s) => s,
            Err(r) => return r,
        };
        if let (Some(path), Some(file)) = (self.access.tunnel_path.clone(), saved) {
            let _ = std::fs::remove_file(path);
            for name in tunnel::ALL_KINDS.iter().filter_map(|k| k.token_secret()) {
                let _ = self.secrets.delete(name);
            }
            self.log_activity(
                "remove the tunnel settings",
                file.provider.as_str(),
                None,
                "ok",
            );
        }
        self.access_status()
    }

    /// Keep the tunnel up while the server runs: restart a dead one, check the address. Called about once a second.
    pub(super) fn tunnel_tick(&mut self, now: u64) {
        if let Some(r) = self.access.runner.as_mut() {
            r.tick(now);
        }
    }

    /// Take the tunnel down (the server is stopping). Tailscale keeps forwarding after its program exits, so this is
    /// not optional.
    pub(super) fn tunnel_shutdown(&mut self, now: u64) {
        if let Some(r) = self.access.runner.as_mut() {
            r.stop(now);
        }
    }

    /// Start the tunnel from the saved settings, stop it, or do both. The answer is the page's usual status, so what
    /// happened (a program that is not installed, a missing token) shows at once.
    fn access_control(&mut self, req: &Req, action: &str) -> Resp {
        if let Some(r) = if action == "stop" {
            self.access_step_up_reducing(req)
        } else {
            self.access_step_up(req)
        } {
            return r;
        }
        if action == "stop" {
            let Some(r) = self.access.runner.as_mut() else {
                return Resp::error(409, "tunnel_not_started", "no tunnel is running here");
            };
            r.stop(unix_ms());
            self.log_activity("stop the tunnel", "dashboard", None, "ok");
            return self.access_status();
        }
        let saved = match self.saved_tunnel() {
            Ok(Some(s)) => s,
            Ok(None) => return Resp::error(404, "no_tunnel", "no tunnel is saved"),
            Err(r) => return r,
        };
        let Some(factory) = self.access.factory.as_ref() else {
            return Resp::error(
                409,
                "tunnel_unavailable",
                "this server cannot start a tunnel",
            );
        };
        if action == "start" {
            let running = self
                .access
                .runner
                .as_ref()
                .is_some_and(|r| lock(&r.snapshot()).state == State::Running);
            if running {
                return Resp::error(409, "tunnel_running", "the tunnel is already running");
            }
        }
        let mut fresh = match factory(&saved) {
            Ok(r) => r,
            Err(key) => return Resp::error(400, key, &crate::messages::t(key, &[])),
        };
        if let Some(old) = self.access.runner.as_mut() {
            old.stop(unix_ms());
        }
        fresh.start(unix_ms());
        self.access.runner = Some(fresh);
        let what = if action == "start" {
            "start the tunnel"
        } else {
            "restart the tunnel"
        };
        self.log_activity(what, saved.provider.as_str(), None, "ok");
        self.access_status()
    }

    fn access_check(&self) -> Resp {
        let saved = match self.saved_tunnel() {
            Ok(Some(s)) => s,
            Ok(None) => return Resp::error(404, "no_tunnel", "no tunnel is saved"),
            Err(r) => return r,
        };
        let Some(kind) = saved.kind() else {
            return Resp::error(
                409,
                "bad_provider",
                "the saved provider is not one this version knows",
            );
        };
        let health = if kind.probes_public_url() {
            let h = tunnel::probe(self.http.as_ref(), &saved.public_url);
            json!({ "ok": h.ok, "code": h.code, "http_status": h.http_status, "checked_ms": unix_ms() })
        } else {
            json!({ "ok": false, "code": "not_applicable", "http_status": null, "checked_ms": unix_ms() })
        };
        Resp::json(200, &json!({ "health": health }))
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use std::collections::HashMap;
    use std::net::{IpAddr, Ipv4Addr, SocketAddr};

    use crate::netguard::FakeHttp;
    use crate::secrets::{MemorySecrets, SecretStore};

    use super::*;

    const TOKEN: &str = "test-token";

    struct Rig {
        app: App,
        path: PathBuf,
        secrets: Arc<MemorySecrets>,
        http: Arc<FakeHttp>,
        _dir: tempfile::TempDir,
    }

    fn rig(public_url: Option<&str>) -> Rig {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("tunnel.toml");
        let secrets = Arc::new(MemorySecrets::default());
        let http = Arc::new(FakeHttp::default());
        let app = App::new(
            Box::new(ozbox_provider_fake::open(dir.path())),
            true,
            SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 7878),
            TOKEN.into(),
        )
        .with_secrets(secrets.clone())
        .with_http(http.clone())
        .with_access(AccessCtx {
            tunnel_path: Some(path.clone()),
            public_url: public_url.map(String::from),
            strong_methods: if public_url.is_some() {
                vec!["passkey"]
            } else {
                vec![]
            },
            ..Default::default()
        });
        Rig {
            app,
            path,
            secrets,
            http,
            _dir: dir,
        }
    }

    fn call(a: &mut App, method: &str, path: &str, body: Value, token: bool) -> (u16, Value) {
        let mut headers = HashMap::new();
        headers.insert("host".to_string(), "127.0.0.1:7878".to_string());
        if token {
            headers.insert("authorization".to_string(), format!("Bearer {TOKEN}"));
        }
        let r = a.handle(&Req {
            method: method.into(),
            path: path.into(),
            query: String::new(),
            headers,
            body: if body.is_null() {
                Vec::new()
            } else {
                body.to_string().into_bytes()
            },
        });
        (
            r.status,
            serde_json::from_slice(&r.body).unwrap_or(Value::Null),
        )
    }

    #[test]
    fn the_local_dashboard_lists_the_providers_and_needs_its_token() {
        let mut r = rig(None);
        assert_eq!(
            call(
                &mut r.app,
                "GET",
                "/v1/dashboard-access",
                Value::Null,
                false
            )
            .0,
            401
        );
        let (s, v) = call(&mut r.app, "GET", "/v1/dashboard-access", Value::Null, true);
        assert_eq!(s, 200);
        assert_eq!(v["mode"], "token");
        assert!(v["tunnel"].is_null());
        assert_eq!(v["can_save"], true);
        let ids: Vec<&str> = v["providers"]
            .as_array()
            .unwrap()
            .iter()
            .map(|p| p["id"].as_str().unwrap())
            .collect();
        assert_eq!(
            ids,
            [
                "cloudflare",
                "tailscale-funnel",
                "tailscale-serve",
                "caddy",
                "ngrok"
            ]
        );
        assert_eq!(
            call(
                &mut r.app,
                "POST",
                "/v1/dashboard-access",
                Value::Null,
                true
            )
            .0,
            405
        );
        assert_eq!(
            call(
                &mut r.app,
                "GET",
                "/v1/dashboard-access/nope",
                Value::Null,
                true
            )
            .0,
            404
        );
    }

    #[test]
    fn a_tunnel_is_saved_validated_and_forgotten_with_its_token_and_the_token_is_never_returned() {
        let mut r = rig(None);
        r.secrets
            .set("tunnel-token-cloudflare", "SENTINEL-TOKEN")
            .unwrap();
        for bad in [
            json!({"provider":"nope","public_url":"https://ozbox.example.com"}),
            json!({"provider":"cloudflare","public_url":"http://ozbox.example.com"}),
            json!({"provider":"cloudflare","public_url":"https://10.0.0.1"}),
            json!({"provider":"tailscale-funnel","public_url":"https://ozbox.example.com"}),
            json!({"provider":"caddy","public_url":"https://ozbox.example.com"}),
            json!({"provider":"caddy","public_url":"https://ozbox.example.com","caddy":{"host":"-oProxyCommand=x","user":"u","ssh_port":22,"key_file":"/k","remote_port":7878}}),
            json!({"provider":"cloudflare","public_url":"https://ozbox.example.com","token":"x"}),
        ] {
            assert_eq!(
                call(
                    &mut r.app,
                    "PUT",
                    "/v1/dashboard-access/tunnel",
                    bad.clone(),
                    true
                )
                .0,
                400,
                "{bad}"
            );
        }
        assert!(!r.path.exists());
        let (s, v) = call(
            &mut r.app,
            "PUT",
            "/v1/dashboard-access/tunnel",
            json!({"provider":"cloudflare","public_url":"https://ozbox.example.com/"}),
            true,
        );
        assert_eq!(s, 200);
        assert_eq!(v["tunnel"]["provider"], "cloudflare");
        assert_eq!(v["tunnel"]["public_url"], "https://ozbox.example.com");
        assert_eq!(v["tunnel"]["token_set"], true);
        assert_eq!(v["tunnel"]["managed"], false);
        // nothing returned or written to the settings file holds the token
        assert!(!v.to_string().contains("SENTINEL"));
        assert!(!std::fs::read_to_string(&r.path)
            .unwrap()
            .contains("SENTINEL"));
        // it is what a later read says too, and what the start-up reads
        let saved = TunnelFile::load(&r.path).unwrap().unwrap();
        assert_eq!(saved.provider, "cloudflare");
        let (_, v) = call(&mut r.app, "GET", "/v1/dashboard-access", Value::Null, true);
        assert_eq!(v["tunnel"]["token_secret"], "tunnel-token-cloudflare");
        // forgetting removes the file and the token
        let (s, v) = call(
            &mut r.app,
            "DELETE",
            "/v1/dashboard-access/tunnel",
            Value::Null,
            true,
        );
        assert_eq!(s, 200);
        assert!(v["tunnel"].is_null());
        assert!(!r.path.exists());
        assert!(!r.secrets.exists("tunnel-token-cloudflare").unwrap());
        // a token left from an earlier choice of provider goes too
        r.secrets.set("tunnel-token-ngrok", "OTHER").unwrap();
        let put = json!({"provider":"cloudflare","public_url":"https://ozbox.example.com"});
        call(&mut r.app, "PUT", "/v1/dashboard-access/tunnel", put, true);
        call(
            &mut r.app,
            "DELETE",
            "/v1/dashboard-access/tunnel",
            Value::Null,
            true,
        );
        assert!(!r.secrets.exists("tunnel-token-ngrok").unwrap());
    }

    #[test]
    fn a_signed_in_dashboard_only_saves_a_tunnel_for_the_address_it_is_signed_in_at() {
        let mut r = rig(Some("https://ozbox.example.com"));
        let other = json!({"provider":"cloudflare","public_url":"https://other.example.com"});
        let (s, v) = call(
            &mut r.app,
            "PUT",
            "/v1/dashboard-access/tunnel",
            other,
            true,
        );
        assert_eq!(
            (s, v["code"].as_str()),
            (400, Some("tunnel.address_differs"))
        );
        let ok = json!({"provider":"cloudflare","public_url":"https://ozbox.example.com"});
        assert_eq!(
            call(&mut r.app, "PUT", "/v1/dashboard-access/tunnel", ok, true).0,
            200
        );
    }

    #[test]
    fn check_asks_the_public_address_and_a_tailnet_only_provider_is_not_asked() {
        let mut r = rig(None);
        assert_eq!(
            call(
                &mut r.app,
                "POST",
                "/v1/dashboard-access/check",
                Value::Null,
                true
            )
            .0,
            404
        );
        let put = json!({"provider":"cloudflare","public_url":"https://ozbox.example.com"});
        call(&mut r.app, "PUT", "/v1/dashboard-access/tunnel", put, true);
        r.http.reply(200, r#"{"mode":"session"}"#);
        let (s, v) = call(
            &mut r.app,
            "POST",
            "/v1/dashboard-access/check",
            Value::Null,
            true,
        );
        assert_eq!((s, v["health"]["ok"].as_bool()), (200, Some(true)));
        assert_eq!(
            r.http.requests()[0].url,
            "https://ozbox.example.com/auth/session"
        );
        r.http.reply(502, "");
        let (_, v) = call(
            &mut r.app,
            "POST",
            "/v1/dashboard-access/check",
            Value::Null,
            true,
        );
        assert_eq!(v["health"]["code"], "bad_status");
        let put = json!({"provider":"tailscale-serve","public_url":"https://box.tail1234.ts.net"});
        call(&mut r.app, "PUT", "/v1/dashboard-access/tunnel", put, true);
        let n = r.http.requests().len();
        let (_, v) = call(
            &mut r.app,
            "POST",
            "/v1/dashboard-access/check",
            Value::Null,
            true,
        );
        assert_eq!(v["health"]["code"], "not_applicable");
        assert_eq!(r.http.requests().len(), n);
    }

    #[test]
    fn without_a_settings_file_there_is_nowhere_to_save() {
        let mut r = rig(None);
        r.app = r.app.with_access(AccessCtx::default());
        let (_, v) = call(&mut r.app, "GET", "/v1/dashboard-access", Value::Null, true);
        assert_eq!(v["can_save"], false);
        let put = json!({"provider":"cloudflare","public_url":"https://ozbox.example.com"});
        assert_eq!(
            call(&mut r.app, "PUT", "/v1/dashboard-access/tunnel", put, true).0,
            409
        );
    }

    /// A factory over a fake program launcher, so a started tunnel is visible without running anything.
    fn fake_factory(
        sp: Arc<crate::tunnel::testing::FakeSpawner>,
        secrets: Arc<MemorySecrets>,
    ) -> RunnerFactory {
        Box::new(move |file: &TunnelFile| {
            let env = crate::tunnel::testing::env(
                Arc::clone(&sp),
                Arc::new(ozbox_core::RecordingRunner::new()),
                Arc::clone(&secrets),
            );
            let built = tunnel::build(file, &env)?;
            Ok(Runner::new(
                built,
                &file.public_url,
                Arc::new(FakeHttp::default()),
                None,
                7878,
                0,
            ))
        })
    }

    #[test]
    fn the_tunnel_is_started_stopped_and_restarted_from_the_page_and_a_stop_sticks() {
        let mut r = rig(None);
        let sp = Arc::new(crate::tunnel::testing::FakeSpawner::default());
        r.secrets
            .set("tunnel-token-cloudflare", "SENTINEL")
            .unwrap();
        r.app = r.app.with_access(AccessCtx {
            tunnel_path: Some(r.path.clone()),
            factory: Some(fake_factory(Arc::clone(&sp), r.secrets.clone())),
            ..Default::default()
        });
        let go = |a: &mut App, m: &str, p: &str| call(a, m, p, Value::Null, true);
        // nothing saved: nothing to start; nothing running: nothing to stop
        assert_eq!(
            go(&mut r.app, "POST", "/v1/dashboard-access/tunnel/start").0,
            404
        );
        assert_eq!(
            go(&mut r.app, "POST", "/v1/dashboard-access/tunnel/stop").0,
            409
        );
        let put = json!({"provider":"cloudflare","public_url":"https://ozbox.example.com"});
        call(&mut r.app, "PUT", "/v1/dashboard-access/tunnel", put, true);
        let (_, v) = go(&mut r.app, "GET", "/v1/dashboard-access");
        assert_eq!(
            (v["can_control"].as_bool(), v["tunnel"]["managed"].as_bool()),
            (Some(true), Some(false))
        );

        let (s, v) = go(&mut r.app, "POST", "/v1/dashboard-access/tunnel/start");
        assert_eq!(s, 200, "{v}");
        assert_eq!(v["tunnel"]["managed"], true);
        assert_eq!(v["tunnel"]["live"]["state"], "running");
        assert_eq!(sp.spawned.lock().unwrap().len(), 1);
        assert!(!v.to_string().contains("SENTINEL"));
        // starting what is running is refused; restarting it is not
        assert_eq!(
            go(&mut r.app, "POST", "/v1/dashboard-access/tunnel/start").0,
            409
        );
        let (s, v) = go(&mut r.app, "POST", "/v1/dashboard-access/tunnel/restart");
        assert_eq!(
            (s, v["tunnel"]["live"]["state"].as_str()),
            (200, Some("running"))
        );
        assert_eq!(sp.spawned.lock().unwrap().len(), 2);

        let (s, v) = go(&mut r.app, "POST", "/v1/dashboard-access/tunnel/stop");
        assert_eq!(
            (s, v["tunnel"]["live"]["state"].as_str()),
            (200, Some("stopped"))
        );
        assert!(
            !sp.alive.load(std::sync::atomic::Ordering::SeqCst),
            "the program is gone"
        );
        // the keep-alive tick does not undo a stop
        r.app.tunnel_tick(10_000_000);
        assert_eq!(sp.spawned.lock().unwrap().len(), 2);
        // and a start brings it back
        let (_, v) = go(&mut r.app, "POST", "/v1/dashboard-access/tunnel/start");
        assert_eq!(v["tunnel"]["live"]["state"], "running");
        // shutting the server down takes it down too
        r.app.tunnel_shutdown(20_000_000);
        assert!(!sp.alive.load(std::sync::atomic::Ordering::SeqCst));
        // wrong methods and unknown actions
        assert_eq!(
            go(&mut r.app, "GET", "/v1/dashboard-access/tunnel/start").0,
            405
        );
        assert_eq!(
            go(&mut r.app, "POST", "/v1/dashboard-access/tunnel/pause").0,
            404
        );
        assert_eq!(
            call(
                &mut r.app,
                "POST",
                "/v1/dashboard-access/tunnel/stop",
                Value::Null,
                false
            )
            .0,
            401
        );
    }

    #[test]
    fn a_server_that_cannot_make_a_tunnel_says_so() {
        let mut r = rig(None);
        let put = json!({"provider":"cloudflare","public_url":"https://ozbox.example.com"});
        call(&mut r.app, "PUT", "/v1/dashboard-access/tunnel", put, true);
        let (s, v) = call(
            &mut r.app,
            "POST",
            "/v1/dashboard-access/tunnel/start",
            Value::Null,
            true,
        );
        assert_eq!((s, v["code"].as_str()), (409, Some("tunnel_unavailable")));
        let (_, v) = call(&mut r.app, "GET", "/v1/dashboard-access", Value::Null, true);
        assert_eq!(v["can_control"], false);
    }
}
