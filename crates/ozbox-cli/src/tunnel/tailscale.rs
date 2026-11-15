//! Tailscale on the person's own tailnet. Funnel gives the dashboard a public `*.ts.net` address; Serve keeps it inside
//! the tailnet, with no public address at all. Both ask the local Tailscale to forward HTTPS to the dashboard's
//! loopback port; no token is involved, because the person signed this machine in to Tailscale themselves.
//!
//! Funnel must be allowed for this machine in the tailnet's policy, and HTTPS must be on for the tailnet. Tailscale
//! keeps the forwarding after this program exits, so `stop` removes it.

use std::sync::Arc;

use ozbox_core::{CommandRunner, CommandSpec, Error};
use serde_json::Value;

use super::{
    public_host, Env, Health, HttpClient, Kind, Tunnel, TunnelError, TunnelFile, TunnelStatus,
};

pub struct Tailscale {
    kind: Kind,
    host: String,
    port: u16,
    runner: Arc<dyn CommandRunner>,
}

/// What `tailscale status --json` says about this machine: whether it is signed in and online, and its name.
#[derive(Debug, PartialEq, Eq)]
pub struct Node {
    pub running: bool,
    pub dns_name: String,
}

pub fn parse_node(json: &str) -> Option<Node> {
    let v: Value = serde_json::from_str(json).ok()?;
    Some(Node {
        running: v["BackendState"].as_str() == Some("Running"),
        dns_name: v["Self"]["DNSName"]
            .as_str()?
            .trim_end_matches('.')
            .to_ascii_lowercase(),
    })
}

/// What `tailscale serve status --json` says about our address.
#[derive(Debug, PartialEq, Eq)]
pub struct Forward {
    /// Is `https://<host>` forwarded to our loopback port?
    pub ours: bool,
    /// Is it open to the whole internet (Funnel)?
    pub funnel: bool,
}

pub fn parse_forward(json: &str, host: &str, port: u16) -> Option<Forward> {
    let v: Value = serde_json::from_str(json).ok()?;
    let key = format!("{host}:443");
    let want = [
        format!("http://127.0.0.1:{port}"),
        format!("http://localhost:{port}"),
        format!("127.0.0.1:{port}"),
        format!("localhost:{port}"),
    ];
    let ours = v["Web"][&key]["Handlers"].as_object().is_some_and(|h| {
        h.values().any(|x| {
            x["Proxy"]
                .as_str()
                .is_some_and(|p| want.iter().any(|w| w == p))
        })
    });
    Some(Forward {
        ours,
        funnel: v["AllowFunnel"][&key].as_bool() == Some(true),
    })
}

impl Tailscale {
    pub fn new(kind: Kind, file: &TunnelFile, env: &Env) -> Self {
        Self {
            kind,
            host: public_host(&file.public_url).unwrap_or_default(),
            port: env.port,
            runner: Arc::clone(&env.runner),
        }
    }

    // Command forms checked against Tailscale's documentation on 2026-11-09:
    //   https://tailscale.com/kb/1242/tailscale-serve  and  https://tailscale.com/kb/1311/tailscale-funnel
    //   start (background):  `tailscale serve|funnel --bg --https=443 <target>`  (Funnel serves ports 443, 8443, 10000 only)
    //   stop:  the same command with `off` on the end; the target is optional but the original flags are not
    //          (`tailscale serve|funnel --https=443 off`)
    //   status:  `tailscale serve status --json` (its `AllowFunnel` map says which names are public)
    //   `tailscale serve|funnel reset` clears EVERYTHING, so it is never used here: it would remove forwards that
    //   are not ours.
    pub fn start_command(kind: Kind, port: u16) -> CommandSpec {
        let sub = if kind == Kind::TailscaleFunnel {
            "funnel"
        } else {
            "serve"
        };
        CommandSpec::new("tailscale").args([
            sub.to_string(),
            "--bg".to_string(),
            "--https=443".to_string(),
            format!("http://127.0.0.1:{port}"),
        ])
    }

    pub fn stop_command(kind: Kind) -> CommandSpec {
        let sub = if kind == Kind::TailscaleFunnel {
            "funnel"
        } else {
            "serve"
        };
        CommandSpec::new("tailscale").args([sub, "--https=443", "off"])
    }

    fn json(&self, args: &[&str]) -> Result<String, TunnelError> {
        match self
            .runner
            .run(&CommandSpec::new("tailscale").args(args.iter().copied()))
        {
            Ok(o) if o.status == Some(0) => Ok(o.stdout),
            Ok(_) => Err(TunnelError::Failed("tailscale_failed")),
            Err(Error::Io(e)) if e.kind() == std::io::ErrorKind::NotFound => {
                Err(TunnelError::ToolMissing("tailscale"))
            }
            Err(_) => Err(TunnelError::Failed("tailscale_failed")),
        }
    }

    fn node(&self) -> Result<Node, TunnelError> {
        let out = self.json(&["status", "--json"])?;
        parse_node(&out).ok_or(TunnelError::Failed("bad_answer"))
    }

    fn forward(&self) -> Result<Forward, TunnelError> {
        let out = self.json(&["serve", "status", "--json"])?;
        // An empty configuration prints `{}`.
        parse_forward(&out, &self.host, self.port).ok_or(TunnelError::Failed("bad_answer"))
    }
}

impl Tunnel for Tailscale {
    fn kind(&self) -> Kind {
        self.kind
    }

    fn start(&mut self) -> Result<(), TunnelError> {
        let node = self.node()?;
        if !node.running {
            return Err(TunnelError::Failed("signed_out"));
        }
        if node.dns_name != self.host {
            return Err(TunnelError::Failed("name_mismatch"));
        }
        // Serve must never leave the dashboard open to the internet: refuse while Funnel is on for this address.
        if self.kind == Kind::TailscaleServe && self.forward()?.funnel {
            return Err(TunnelError::Failed("funnel_is_on"));
        }
        let cmd = Self::start_command(self.kind, self.port);
        match self.runner.run_ok(&cmd) {
            Ok(_) => Ok(()),
            Err(_) => Err(TunnelError::Failed("tailscale_failed")),
        }
    }

    fn stop(&mut self) -> Result<(), TunnelError> {
        self.runner
            .run_ok(&Self::stop_command(self.kind))
            .map(|_| ())
            .map_err(|_| TunnelError::Failed("tailscale_failed"))
    }

    fn status(&mut self) -> TunnelStatus {
        let node = match self.node() {
            Ok(n) => n,
            Err(e) => return TunnelStatus::failed(e.code()),
        };
        if !node.running {
            return TunnelStatus::failed("signed_out");
        }
        match self.forward() {
            Err(e) => TunnelStatus::failed(e.code()),
            Ok(f) if !f.ours => TunnelStatus::stopped(),
            Ok(f) if self.kind == Kind::TailscaleServe && f.funnel => {
                TunnelStatus::failed("funnel_is_on")
            }
            Ok(f) if self.kind == Kind::TailscaleFunnel && !f.funnel => {
                TunnelStatus::failed("funnel_off")
            }
            Ok(_) => TunnelStatus::running(),
        }
    }

    fn health(&mut self, http: &dyn HttpClient) -> Health {
        let st = self.status();
        if st.state != super::State::Running {
            return Health {
                ok: false,
                code: st.code.unwrap_or("not_running"),
                http_status: None,
            };
        }
        if self.kind.probes_public_url() {
            return super::probe(http, &format!("https://{}", self.host));
        }
        // Tailnet only: the address resolves to a private one, so the check is Tailscale's own answer.
        Health {
            ok: true,
            code: "ok",
            http_status: None,
        }
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::super::testing::*;
    use super::*;
    use crate::netguard::FakeHttp;
    use crate::tunnel::State;
    use ozbox_core::{Output, RecordingRunner};

    const NODE: &str =
        r#"{"BackendState":"Running","Self":{"DNSName":"ozbox.tail1234.ts.net.","Online":true}}"#;
    const FUNNEL: &str = r#"{"TCP":{"443":{"HTTPS":true}},"Web":{"ozbox.tail1234.ts.net:443":{"Handlers":{"/":{"Proxy":"http://127.0.0.1:7878"}}}},"AllowFunnel":{"ozbox.tail1234.ts.net:443":true}}"#;
    const SERVE: &str = r#"{"TCP":{"443":{"HTTPS":true}},"Web":{"ozbox.tail1234.ts.net:443":{"Handlers":{"/":{"Proxy":"http://127.0.0.1:7878"}}}}}"#;

    fn ok(stdout: &str) -> Output {
        Output {
            status: Some(0),
            stdout: stdout.into(),
            stderr: String::new(),
        }
    }

    fn make(kind: Kind) -> (Tailscale, Arc<RecordingRunner>) {
        let r = Arc::new(RecordingRunner::new());
        let e = env(
            Arc::new(FakeSpawner::default()),
            Arc::clone(&r),
            Arc::new(crate::secrets::MemorySecrets::default()),
        );
        let f = TunnelFile {
            provider: kind.id().into(),
            public_url: "https://ozbox.tail1234.ts.net".into(),
            caddy: None,
        };
        (Tailscale::new(kind, &f, &e), r)
    }

    fn args(r: &RecordingRunner) -> Vec<String> {
        r.calls()
            .iter()
            .map(|c| format!("{} {}", c.program, c.args.join(" ")))
            .collect()
    }

    #[test]
    fn the_status_documents_are_parsed() {
        assert_eq!(
            parse_node(NODE),
            Some(Node {
                running: true,
                dns_name: "ozbox.tail1234.ts.net".into()
            })
        );
        assert!(
            !parse_node(r#"{"BackendState":"NeedsLogin","Self":{"DNSName":"x."}}"#)
                .unwrap()
                .running
        );
        assert_eq!(parse_node("nope"), None);
        assert_eq!(
            parse_forward(FUNNEL, "ozbox.tail1234.ts.net", 7878),
            Some(Forward {
                ours: true,
                funnel: true
            })
        );
        assert_eq!(
            parse_forward(SERVE, "ozbox.tail1234.ts.net", 7878),
            Some(Forward {
                ours: true,
                funnel: false
            })
        );
        assert_eq!(
            parse_forward(SERVE, "ozbox.tail1234.ts.net", 9999),
            Some(Forward {
                ours: false,
                funnel: false
            }),
            "another port is not ours"
        );
        assert_eq!(
            parse_forward("{}", "h.ts.net", 7878),
            Some(Forward {
                ours: false,
                funnel: false
            })
        );
    }

    #[test]
    fn funnel_starts_after_checking_sign_in_and_name_and_reports_public() {
        let (mut t, r) = make(Kind::TailscaleFunnel);
        r.reply(ok(NODE));
        r.reply(ok(""));
        t.start().unwrap();
        assert_eq!(
            args(&r),
            vec![
                "tailscale status --json".to_string(),
                "tailscale funnel --bg --https=443 http://127.0.0.1:7878".to_string()
            ]
        );
        r.reply(ok(NODE));
        r.reply(ok(FUNNEL));
        assert_eq!(t.status(), TunnelStatus::running());
        // funnel is meant to be public: serve-only config is a failure of what was asked for
        r.reply(ok(NODE));
        r.reply(ok(SERVE));
        assert_eq!(t.status(), TunnelStatus::failed("funnel_off"));
        t.stop().unwrap();
        assert_eq!(args(&r).last().unwrap(), "tailscale funnel --https=443 off");
    }

    #[test]
    fn serve_refuses_to_start_while_funnel_would_expose_it_and_is_checked_without_the_internet() {
        let (mut t, r) = make(Kind::TailscaleServe);
        r.reply(ok(NODE));
        r.reply(ok(FUNNEL));
        assert_eq!(t.start(), Err(TunnelError::Failed("funnel_is_on")));
        assert!(!args(&r)
            .iter()
            .any(|a| a.starts_with("tailscale serve --bg")));
        r.reply(ok(NODE));
        r.reply(ok(SERVE));
        r.reply(ok(""));
        t.start().unwrap();
        assert_eq!(
            args(&r).last().unwrap(),
            "tailscale serve --bg --https=443 http://127.0.0.1:7878"
        );
        // health is Tailscale's own answer: no request leaves this computer
        r.reply(ok(NODE));
        r.reply(ok(SERVE));
        let http = FakeHttp::default();
        let h = t.health(&http);
        assert!(h.ok);
        assert!(http.requests().is_empty());
        assert!(!Kind::TailscaleServe.is_public());
    }

    #[test]
    fn signed_out_wrong_name_and_missing_program_are_reported() {
        let (mut t, r) = make(Kind::TailscaleFunnel);
        r.reply(ok(
            r#"{"BackendState":"NeedsLogin","Self":{"DNSName":"ozbox.tail1234.ts.net."}}"#,
        ));
        assert_eq!(t.start(), Err(TunnelError::Failed("signed_out")));
        r.reply(ok(
            r#"{"BackendState":"Running","Self":{"DNSName":"other.tail1234.ts.net."}}"#,
        ));
        assert_eq!(t.start(), Err(TunnelError::Failed("name_mismatch")));
        r.reply(Output {
            status: Some(1),
            ..Output::default()
        });
        assert_eq!(t.status().state, State::Failed);
        let http = FakeHttp::default();
        r.reply(ok(NODE));
        r.reply(ok(FUNNEL));
        http.reply(200, r#"{"mode":"session"}"#);
        assert!(t.health(&http).ok);
        assert_eq!(
            http.requests()[0].url,
            "https://ozbox.tail1234.ts.net/auth/session"
        );
    }

    #[test]
    fn only_ts_net_names_are_accepted_for_tailscale() {
        let f = TunnelFile {
            provider: "tailscale-funnel".into(),
            public_url: "https://ozbox.example.com".into(),
            caddy: None,
        };
        assert_eq!(f.validate(), Err("tunnel.tailscale_name"));
    }
}
