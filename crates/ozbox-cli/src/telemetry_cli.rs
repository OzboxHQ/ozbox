//! `ozbox telemetry status | on | off | preview | send` (ADR 0029).

use std::io::{BufRead, IsTerminal, Write};

use crate::cli::TelemetryCommand;
use crate::messages::t;
use crate::netguard::UreqClient;
use crate::run::CliError;
use crate::telemetry::{self, Outcome, Paths, Settings};

fn msg(key: &str) -> CliError {
    CliError::Msg(t(key, &[]))
}

fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

/// What a run of the command touches, so a test can stand in for each.
pub struct Ctx<'a> {
    pub paths: &'a Paths,
    pub http: &'a dyn crate::netguard::HttpClient,
    pub now: u64,
    pub interactive: bool,
    pub input: &'a mut dyn BufRead,
    pub out: &'a mut dyn Write,
}

pub fn run(cmd: &TelemetryCommand, yes: bool, dry_run: bool, json: bool) -> Result<(), CliError> {
    let paths = Paths::detect().ok_or_else(|| msg("init.cli_no_home"))?;
    let stdin = std::io::stdin();
    let mut lock = stdin.lock();
    let mut out = std::io::stdout();
    let mut c = Ctx {
        paths: &paths,
        http: &UreqClient,
        now: now_ms(),
        interactive: std::io::stdin().is_terminal(),
        input: &mut lock,
        out: &mut out,
    };
    run_with(cmd, &mut c, yes, dry_run, json)
}

pub fn run_with(
    cmd: &TelemetryCommand,
    c: &mut Ctx,
    yes: bool,
    dry_run: bool,
    json: bool,
) -> Result<(), CliError> {
    let paths = c.paths;
    let s = telemetry::load(&paths.settings);
    match cmd {
        TelemetryCommand::Status => {
            if json {
                let _ = writeln!(
                    c.out,
                    "{}",
                    serde_json::json!({"enabled": s.enabled, "endpoint": if s.enabled { s.endpoint.as_str() } else { "" }})
                );
            } else if s.enabled {
                let _ = writeln!(
                    c.out,
                    "{}",
                    t("telemetry.status_on", &[("endpoint", &s.endpoint)])
                );
            } else {
                let _ = writeln!(c.out, "{}", t("telemetry.status_off", &[]));
            }
            Ok(())
        }
        TelemetryCommand::Preview => {
            let ev = telemetry::current_event(paths, c.now);
            if !json {
                let _ = writeln!(c.out, "{}", t("telemetry.preview_head", &[]));
            }
            let _ = writeln!(c.out, "{}", ev.body());
            Ok(())
        }
        TelemetryCommand::On { endpoint } => {
            let endpoint = endpoint.trim().to_string();
            if !telemetry::endpoint_ok(&endpoint) {
                return Err(msg("telemetry.bad_endpoint"));
            }
            let ev = telemetry::current_event(paths, c.now);
            let _ = writeln!(
                c.out,
                "{}",
                t("telemetry.plan_head", &[("endpoint", &endpoint)])
            );
            let _ = writeln!(c.out, "  {}", ev.body());
            let _ = writeln!(c.out, "{}", t("telemetry.plan_rules", &[]));
            if dry_run {
                let _ = writeln!(c.out, "{}", t("mesh.dry_run", &[]));
                return Ok(());
            }
            if !yes {
                if !c.interactive {
                    return Err(msg("mesh.refuse_no_tty"));
                }
                let _ = write!(c.out, "{} [y/N] ", t("telemetry.confirm", &[]));
                let _ = c.out.flush();
                let mut line = String::new();
                let _ = c.input.read_line(&mut line);
                if !matches!(line.trim().to_ascii_lowercase().as_str(), "y" | "yes") {
                    return Err(msg("mesh.aborted"));
                }
            }
            telemetry::save(
                &paths.settings,
                &Settings {
                    enabled: true,
                    endpoint,
                },
            )
            .map_err(CliError::Msg)?;
            let _ = writeln!(c.out, "{}", t("telemetry.is_on", &[]));
            Ok(())
        }
        TelemetryCommand::Off => {
            telemetry::save(
                &paths.settings,
                &Settings {
                    enabled: false,
                    endpoint: String::new(),
                },
            )
            .map_err(CliError::Msg)?;
            let _ = std::fs::remove_file(&paths.facts);
            let _ = writeln!(c.out, "{}", t("telemetry.is_off", &[]));
            Ok(())
        }
        TelemetryCommand::Send => match telemetry::send(paths, c.http, c.now, true) {
            Outcome::Off => Err(msg("telemetry.not_on")),
            Outcome::Delivered => {
                let _ = writeln!(c.out, "{}", t("telemetry.sent", &[]));
                Ok(())
            }
            _ => Err(msg("telemetry.send_failed")),
        },
    }
}

/// After a command succeeded: send the day's event when telemetry is on. Silent, quick, and never an error. When it is
/// off this reads one small file and does nothing else.
pub fn after_command(command_is_telemetry: bool) {
    if command_is_telemetry {
        return;
    }
    let Some(paths) = Paths::detect() else { return };
    if !telemetry::load(&paths.settings).enabled {
        return;
    }
    let _ = telemetry::send(&paths, &UreqClient, now_ms(), false);
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use crate::netguard::{HttpClient, HttpError, HttpRequest, HttpResponse};

    struct Never;
    impl HttpClient for Never {
        fn send(&self, _: &HttpRequest) -> Result<HttpResponse, HttpError> {
            panic!("nothing may be sent");
        }
    }

    fn go(p: &Paths, c: &TelemetryCommand, yes: bool) -> (Result<(), CliError>, String) {
        let mut out = Vec::new();
        let mut input = std::io::Cursor::new(Vec::new());
        let mut ctx = Ctx {
            paths: p,
            http: &Never,
            now: 1_794_000_000_000,
            interactive: false,
            input: &mut input,
            out: &mut out,
        };
        let r = run_with(c, &mut ctx, yes, false, false);
        (r, String::from_utf8(out).unwrap())
    }

    fn paths() -> (tempfile::TempDir, Paths) {
        let d = tempfile::tempdir().unwrap();
        let p = Paths {
            settings: d.path().join("t.toml"),
            facts: d.path().join("f.json"),
        };
        (d, p)
    }

    #[test]
    fn it_is_off_by_default_and_status_preview_and_off_send_nothing() {
        let (_d, p) = paths();
        let (r, out) = go(&p, &TelemetryCommand::Status, false);
        r.unwrap();
        assert!(out.contains("off"));
        go(&p, &TelemetryCommand::Preview, false).0.unwrap();
        go(&p, &TelemetryCommand::Off, false).0.unwrap();
        assert!(go(&p, &TelemetryCommand::Send, false).0.is_err());
    }

    #[test]
    fn turning_it_on_shows_the_event_first_and_needs_a_confirmation() {
        let (_d, p) = paths();
        let on = TelemetryCommand::On {
            endpoint: "https://collect.example.com/x".into(),
        };
        let (r, _) = go(&p, &on, false);
        assert!(
            r.is_err(),
            "without --yes and without a terminal nothing is turned on"
        );
        assert!(!telemetry::load(&p.settings).enabled);
        let (r, out) = go(&p, &on, true);
        r.unwrap();
        assert!(out.contains("\"schema\":1"));
        assert!(telemetry::load(&p.settings).enabled);
        let bad = TelemetryCommand::On {
            endpoint: "http://x.example.com".into(),
        };
        assert!(go(&p, &bad, true).0.is_err());
    }
}
