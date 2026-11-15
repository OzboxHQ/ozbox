//! Interruption watcher (AWS): polls the instance metadata service for a Spot interruption or a scheduled
//! maintenance event, so the daemon can checkpoint before the box goes away.
//!
//! IMDSv2 through `curl` argv via a [`CommandRunner`]: a token `PUT`, then a `GET` that also prints the HTTP status
//! so "no notice" (404) is told apart from a notice (200). The short-lived metadata token appears in curl's argv for
//! the instant of the call; it is only valid from this instance and expires in 60 s.
//!
//! Only root and the machine's own services may reach the metadata service (ADR 0029, amendment 6 §2), and the daemon runs
//! as the box user. So the polling runs as a user of its own (`ozboxd interruption-watch`, user `ozbox-meta`), which leaves
//! the notice in effect in [`NOTICE_FILE`]; the daemon reads that file ([`InterruptionWatcher::poll_file`]). A box made before
//! the guard has no such file's folder, and the daemon asks the metadata service itself, as before.

use std::path::Path;
use std::sync::Arc;

use ozbox_core::{CommandRunner, CommandSpec};

const BASE: &str = "http://169.254.169.254/latest";
/// Where the watcher leaves the notice in effect (absent: none). World-readable, no secret in it.
pub const NOTICE_FILE: &str = "/run/ozbox-meta/notice.json";

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Notice {
    /// Spot interruption: what AWS will do and when (as reported).
    SpotInterruption { action: String, time: String },
    /// A scheduled maintenance event is pending (number of events).
    Maintenance { events: usize },
}

impl Notice {
    /// A stable key so the same notice is acted on once.
    pub fn key(&self) -> String {
        match self {
            Notice::SpotInterruption { action, time } => format!("spot:{action}:{time}"),
            Notice::Maintenance { events } => format!("maintenance:{events}"),
        }
    }

    /// The notice as the watcher writes it.
    pub fn to_json(&self) -> String {
        match self {
            Notice::SpotInterruption { action, time } => {
                serde_json::json!({"kind": "spot", "action": action, "time": time})
            }
            Notice::Maintenance { events } => {
                serde_json::json!({"kind": "maintenance", "events": events})
            }
        }
        .to_string()
    }

    /// Read back what [`to_json`](Self::to_json) wrote, with the same limits the metadata parsers apply.
    pub fn from_json(text: &str) -> Option<Self> {
        let v: serde_json::Value = serde_json::from_str(text.trim()).ok()?;
        match v.get("kind")?.as_str()? {
            "spot" => Some(Notice::SpotInterruption {
                action: v.get("action")?.as_str()?.chars().take(32).collect(),
                time: v
                    .get("time")
                    .and_then(|t| t.as_str())
                    .unwrap_or("")
                    .chars()
                    .take(40)
                    .collect(),
            }),
            "maintenance" => Some(Notice::Maintenance {
                events: usize::try_from(v.get("events")?.as_u64()?).ok()?,
            }),
            _ => None,
        }
    }

    pub fn describe(&self) -> String {
        match self {
            Notice::SpotInterruption { action, time } => {
                format!("spot interruption notice: {action} at {time}")
            }
            Notice::Maintenance { events } => format!("{events} scheduled maintenance event(s)"),
        }
    }
}

/// Split curl output written with `-w '\n%{http_code}'` into (body, status).
pub fn split_status(stdout: &str) -> Option<(&str, u16)> {
    let t = stdout.trim_end();
    let (body, code) = t.rsplit_once('\n').unwrap_or(("", t));
    Some((body, code.trim().parse().ok()?))
}

/// `{"action": "terminate", "time": "2026-11-09T12:00:00Z"}` -> the notice.
pub fn parse_spot_action(body: &str) -> Option<Notice> {
    let v: serde_json::Value = serde_json::from_str(body.trim()).ok()?;
    Some(Notice::SpotInterruption {
        action: v.get("action")?.as_str()?.chars().take(32).collect(),
        time: v
            .get("time")
            .and_then(|t| t.as_str())
            .unwrap_or("")
            .chars()
            .take(40)
            .collect(),
    })
}

/// The scheduled-events body is a JSON array; empty means nothing pending.
pub fn parse_maintenance(body: &str) -> Option<Notice> {
    let v: serde_json::Value = serde_json::from_str(body.trim()).ok()?;
    let n = v.as_array().map(Vec::len).unwrap_or(0);
    (n > 0).then_some(Notice::Maintenance { events: n })
}

pub struct InterruptionWatcher {
    runner: Arc<dyn CommandRunner>,
    last_key: Option<String>,
}

impl InterruptionWatcher {
    pub fn new(runner: Arc<dyn CommandRunner>) -> Self {
        Self {
            runner,
            last_key: None,
        }
    }

    fn token_cmd() -> CommandSpec {
        CommandSpec::new("curl").args([
            "-s",
            "-m",
            "2",
            "-X",
            "PUT",
            "-H",
            "X-aws-ec2-metadata-token-ttl-seconds: 60",
            &format!("{BASE}/api/token"),
        ])
    }

    fn get_cmd(token: &str, path: &str) -> CommandSpec {
        CommandSpec::new("curl").args([
            "-s",
            "-m",
            "2",
            "-w",
            "\\n%{http_code}",
            "-H",
            &format!("X-aws-ec2-metadata-token: {token}"),
            &format!("{BASE}/meta-data/{path}"),
        ])
    }

    /// One poll. `Err` = the metadata service could not be reached (not a notice); `Ok(Some)` = a NEW notice
    /// (a repeat of the previous one returns `Ok(None)`).
    pub fn poll(&mut self) -> Result<Option<Notice>, String> {
        let found = self.current()?;
        Ok(self.fresh(found))
    }

    /// The same, from the watcher's file: no file is no notice; a file that cannot be read is not a notice either.
    pub fn poll_file(&mut self, path: &Path) -> Result<Option<Notice>, String> {
        let found = match std::fs::read_to_string(path) {
            Ok(t) => Some(Notice::from_json(&t).ok_or("the notice file is not a notice")?),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => None,
            Err(_) => return Err("the notice file could not be read".into()),
        };
        Ok(self.fresh(found))
    }

    /// A notice once: the same one again is `None`, and no notice clears what was seen.
    fn fresh(&mut self, found: Option<Notice>) -> Option<Notice> {
        match found {
            Some(n) if self.last_key.as_deref() != Some(&n.key()) => {
                self.last_key = Some(n.key());
                Some(n)
            }
            Some(_) => None,
            None => {
                self.last_key = None;
                None
            }
        }
    }

    /// What the metadata service says now, without remembering anything.
    pub fn current(&self) -> Result<Option<Notice>, String> {
        let tok = self
            .runner
            .run(&Self::token_cmd())
            .map_err(|_| "metadata token request failed".to_string())?;
        let token = tok.stdout.trim().to_string();
        if tok.status != Some(0) || token.is_empty() || token.contains(char::is_whitespace) {
            return Err("metadata service unreachable".into());
        }
        let mut found = None;
        for (path, is_spot) in [
            ("spot/instance-action", true),
            ("events/maintenance/scheduled", false),
        ] {
            let out = self
                .runner
                .run(&Self::get_cmd(&token, path))
                .map_err(|_| "metadata request failed".to_string())?;
            if out.status != Some(0) {
                return Err("metadata request failed".into());
            }
            let Some((body, code)) = split_status(&out.stdout) else {
                return Err("unreadable metadata response".into());
            };
            if code != 200 {
                continue; // 404 = no notice
            }
            found = if is_spot {
                parse_spot_action(body)
            } else {
                parse_maintenance(body)
            };
            if found.is_some() {
                break;
            }
        }
        Ok(found)
    }
}

/// One round of `ozboxd interruption-watch`: ask the metadata service, and leave the notice in effect at `path` (written
/// whole, then renamed into place), or remove the file when there is none. An unreachable service changes nothing.
pub fn watch_once(w: &InterruptionWatcher, path: &Path) -> Result<(), String> {
    match w.current()? {
        Some(n) => {
            let tmp = path.with_extension("tmp");
            std::fs::write(&tmp, n.to_json())
                .and_then(|()| std::fs::rename(&tmp, path))
                .map_err(|_| "the notice file could not be written".to_string())
        }
        None => match std::fs::remove_file(path) {
            Err(e) if e.kind() != std::io::ErrorKind::NotFound => {
                Err("the old notice file could not be removed".into())
            }
            _ => Ok(()),
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ozbox_core::{Output, RecordingRunner};

    fn out(s: &str) -> Output {
        Output {
            status: Some(0),
            stdout: s.into(),
            stderr: String::new(),
        }
    }

    #[test]
    fn parsers() {
        assert_eq!(split_status("{\"a\":1}\n200"), Some(("{\"a\":1}", 200)));
        assert_eq!(split_status("\n404"), Some(("", 404)));
        assert_eq!(split_status("404"), Some(("", 404)));
        assert_eq!(split_status("garbage"), None);
        assert_eq!(
            parse_spot_action("{\"action\": \"stop\", \"time\": \"2026-11-09T12:00:00Z\"}"),
            Some(Notice::SpotInterruption {
                action: "stop".into(),
                time: "2026-11-09T12:00:00Z".into()
            })
        );
        assert_eq!(parse_spot_action("<html>"), None);
        assert_eq!(parse_maintenance("[]"), None);
        assert_eq!(
            parse_maintenance("[{\"Code\":\"system-reboot\"}]"),
            Some(Notice::Maintenance { events: 1 })
        );
    }

    #[test]
    fn no_notice_is_404_on_both_paths_and_argv_is_exact() {
        let r = Arc::new(RecordingRunner::new());
        r.reply(out("TOKEN123"));
        r.reply(out("\n404"));
        r.reply(out("\n404"));
        let mut w = InterruptionWatcher::new(r.clone());
        assert_eq!(w.poll(), Ok(None));
        let c = r.calls();
        assert_eq!(c.len(), 3);
        assert_eq!(c[0].program, "curl");
        assert_eq!(
            c[0].args,
            [
                "-s",
                "-m",
                "2",
                "-X",
                "PUT",
                "-H",
                "X-aws-ec2-metadata-token-ttl-seconds: 60",
                "http://169.254.169.254/latest/api/token"
            ]
        );
        assert_eq!(
            c[1].args,
            [
                "-s",
                "-m",
                "2",
                "-w",
                "\\n%{http_code}",
                "-H",
                "X-aws-ec2-metadata-token: TOKEN123",
                "http://169.254.169.254/latest/meta-data/spot/instance-action"
            ]
        );
        assert!(c[2]
            .args
            .last()
            .is_some_and(|a| a.ends_with("events/maintenance/scheduled")));
    }

    #[test]
    #[allow(clippy::unwrap_used)]
    fn the_watcher_leaves_the_notice_in_a_file_and_the_daemon_reads_it_once() {
        let d = tempfile::tempdir().unwrap();
        let f = d.path().join("notice.json");
        let r = Arc::new(RecordingRunner::new());
        r.reply(out("T"));
        r.reply(out(
            "{\"action\":\"stop\",\"time\":\"2026-11-09T12:00:00Z\"}\n200",
        ));
        let w = InterruptionWatcher::new(r.clone());
        watch_once(&w, &f).unwrap();
        let mut daemon = InterruptionWatcher::new(Arc::new(RecordingRunner::new()));
        assert_eq!(
            daemon.poll_file(&f),
            Ok(Some(Notice::SpotInterruption {
                action: "stop".into(),
                time: "2026-11-09T12:00:00Z".into()
            }))
        );
        assert_eq!(daemon.poll_file(&f), Ok(None), "once");
        // no notice any more: the file goes, and nothing is reported
        r.reply(out("T"));
        r.reply(out("\n404"));
        r.reply(out("\n404"));
        watch_once(&w, &f).unwrap();
        assert!(!f.exists());
        assert_eq!(daemon.poll_file(&f), Ok(None));
        // a file that is not a notice is not one
        std::fs::write(&f, "{\"kind\":\"other\"}").unwrap();
        assert!(daemon.poll_file(&f).is_err());
        let m = Notice::Maintenance { events: 2 };
        assert_eq!(Notice::from_json(&m.to_json()), Some(m));
    }

    #[test]
    fn a_spot_notice_is_reported_once() {
        let r = Arc::new(RecordingRunner::new());
        let body = "{\"action\":\"terminate\",\"time\":\"2026-11-09T12:00:00Z\"}\n200";
        for _ in 0..2 {
            r.reply(out("T"));
            r.reply(out(body));
        }
        let mut w = InterruptionWatcher::new(r.clone());
        assert!(matches!(
            w.poll(),
            Ok(Some(Notice::SpotInterruption { .. }))
        ));
        assert_eq!(w.poll(), Ok(None)); // same notice, already handled
    }

    #[test]
    fn maintenance_notice_and_unreachable_metadata() {
        let r = Arc::new(RecordingRunner::new());
        r.reply(out("T"));
        r.reply(out("\n404"));
        r.reply(out("[{\"Code\":\"instance-retirement\"}]\n200"));
        let mut w = InterruptionWatcher::new(r.clone());
        assert_eq!(w.poll(), Ok(Some(Notice::Maintenance { events: 1 })));

        let r2 = Arc::new(RecordingRunner::new());
        r2.reply(Output {
            status: Some(28),
            ..Default::default()
        }); // curl timeout
        let mut w2 = InterruptionWatcher::new(r2);
        assert!(w2.poll().is_err());
        let r3 = Arc::new(RecordingRunner::new());
        r3.reply(out("")); // empty token
        assert!(InterruptionWatcher::new(r3).poll().is_err());
    }
}
