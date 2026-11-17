//! `ozbox chat lock` and `ozbox chat unlink`: make Telegram links less able from the command line (ADR 0050 §1c).
//!
//! Both only reduce what a chat can do, so, like `/lock` and `/unlink` in the chat and the dashboard's buttons, they need no
//! passkey. They follow plan, then apply (ADR 0002): the plan lists the links that would change, read from the dashboard's
//! Telegram state beside its settings, and nothing changes until it is confirmed.
//!
//! The dashboard owns that state and writes it, so the command does not write it. It appends one request per link to
//! `telegram-requests.jsonl` in the same folder, and the running dashboard applies it on its next tick (a few seconds),
//! records it in the audit chain as done from the command line, and removes the file. Only `lock` and `unlink` are ever read
//! from that file: a request in it can make a link less able, never more. Run it where the dashboard keeps its state (on
//! the box that runs it, as the dashboard's own user).

use std::io::{BufRead, IsTerminal, Write};
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use serde_json::json;

use crate::cli::ChatCommand;
use crate::run::CliError;
use crate::telegram_store::{LinkState, TgStore};

/// The file the dashboard reads requests from, beside `telegram.json`.
pub const REQUESTS_FILE: &str = "telegram-requests.jsonl";
/// The most requests the dashboard reads from the file at once.
pub const MAX_REQUESTS: usize = 1000;

/// One request in the file. Only these two acts exist.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Request {
    pub act: RequestAct,
    pub link: String,
    pub at_ms: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RequestAct {
    Lock,
    Unlink,
}

fn fail(s: impl std::fmt::Display) -> CliError {
    CliError::Core(ozbox_core::Error::Config(s.to_string()))
}

fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_millis() as u64)
}

/// The folder the dashboard keeps its state in: `--state-dir`, or beside the settings file.
fn state_dir(given: Option<&PathBuf>) -> Result<PathBuf, CliError> {
    if let Some(d) = given {
        return Ok(d.clone());
    }
    crate::settings::Settings::path()
        .and_then(|p| p.parent().map(Path::to_path_buf))
        .ok_or_else(|| fail("no settings folder: pass --state-dir"))
}

/// One planned change.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Planned {
    pub link: String,
    pub person: String,
    pub label: String,
    pub state: &'static str,
}

/// What a lock or an unlink would change. Pure over the store, so it can be tested.
pub fn plan(store: &TgStore, act: RequestAct, link: Option<&str>, all: bool) -> Vec<Planned> {
    store
        .data
        .links
        .iter()
        .filter(|l| all || Some(l.record.id.as_str()) == link)
        .filter(|l| match act {
            RequestAct::Lock => l.state == LinkState::Active,
            RequestAct::Unlink => l.state != LinkState::Revoked,
        })
        .map(|l| Planned {
            link: l.record.id.clone(),
            person: l.record.person.clone(),
            label: l.record.label.clone(),
            state: match l.state {
                LinkState::Active => "active",
                LinkState::Locked => "locked",
                LinkState::Revoked => "revoked",
            },
        })
        .collect()
}

/// Append the requests to the file the dashboard reads. Created 0600.
pub fn write_requests(dir: &Path, act: RequestAct, links: &[Planned]) -> Result<(), String> {
    let path = dir.join(REQUESTS_FILE);
    let mut o = std::fs::OpenOptions::new();
    o.create(true).append(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        o.mode(0o600);
    }
    let mut f = o
        .open(&path)
        .map_err(|e| format!("{} cannot be written ({e})", path.display()))?;
    let at = now_ms();
    for p in links {
        let line = serde_json::to_string(&Request {
            act,
            link: p.link.clone(),
            at_ms: at,
        })
        .map_err(|e| e.to_string())?;
        writeln!(f, "{line}").map_err(|e| e.to_string())?;
    }
    f.sync_all().map_err(|e| e.to_string())
}

/// What the dashboard reads: at most [`MAX_REQUESTS`] well-formed requests; a line that is not one is skipped. The file is
/// removed after it is read, so a request is applied once.
pub fn take_requests(dir: &Path) -> Vec<Request> {
    let path = dir.join(REQUESTS_FILE);
    let taken = path.with_extension("jsonl.taking");
    if std::fs::rename(&path, &taken).is_err() {
        return Vec::new();
    }
    let out: Vec<Request> = std::fs::File::open(&taken)
        .map(|f| {
            std::io::BufReader::new(f)
                .lines()
                .map_while(Result::ok)
                .filter_map(|l| serde_json::from_str::<Request>(&l).ok())
                .take(MAX_REQUESTS)
                .collect()
        })
        .unwrap_or_default();
    let _ = std::fs::remove_file(&taken);
    out
}

pub fn run(c: &ChatCommand, yes: bool, dry_run: bool, json_out: bool) -> Result<(), CliError> {
    let (act, link, all, dir) = match c {
        ChatCommand::Lock {
            link,
            all,
            state_dir: d,
        } => (RequestAct::Lock, link.as_deref(), *all, d.as_ref()),
        ChatCommand::Unlink {
            link,
            all,
            state_dir: d,
        } => (RequestAct::Unlink, link.as_deref(), *all, d.as_ref()),
    };
    if link.is_none() && !all {
        return Err(fail("name a link with --link <id>, or pass --all"));
    }
    let dir = state_dir(dir)?;
    let store = TgStore::open(dir.join("telegram.json")).map_err(fail)?;
    let planned = plan(&store, act, link, all);
    let verb = match act {
        RequestAct::Lock => "lock",
        RequestAct::Unlink => "unlink",
    };
    if json_out {
        println!(
            "{}",
            json!({ "act": verb, "links": planned, "applied": false, "dry_run": dry_run })
        );
    } else if planned.is_empty() {
        println!("Nothing to do: no link to {verb}.");
    } else {
        println!("Plan: {verb} {} Telegram link(s):", planned.len());
        for p in &planned {
            println!("  {}  {} ({}), now {}", p.link, p.person, p.label, p.state);
        }
        println!(
            "{}",
            match act {
                RequestAct::Lock => "A locked link can only read until a passkey in the dashboard lifts the lock.",
                RequestAct::Unlink => "An unlinked chat is not answered any more, and everything delegated to it ends.",
            }
        );
    }
    if planned.is_empty() || dry_run {
        return Ok(());
    }
    if !yes {
        if !std::io::stdin().is_terminal() {
            return Err(fail("this needs a person's yes: run it in a terminal, or pass --yes"));
        }
        print!("Go ahead? [y/N] ");
        let _ = std::io::stdout().flush();
        let mut a = String::new();
        std::io::stdin().lock().read_line(&mut a).map_err(fail)?;
        if !matches!(a.trim(), "y" | "Y" | "yes") {
            println!("Nothing changed.");
            return Ok(());
        }
    }
    write_requests(&dir, act, &planned).map_err(fail)?;
    if json_out {
        println!("{}", json!({ "act": verb, "links": planned, "applied": true }));
    } else {
        println!("Sent to the dashboard, which applies it within a few seconds and records it in the audit chain.");
    }
    Ok(())
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn requests_round_trip_once_and_only_lock_and_unlink_are_read() {
        let dir = tempfile::tempdir().unwrap();
        let p = Planned {
            link: "l1".into(),
            person: "owner".into(),
            label: "phone".into(),
            state: "active",
        };
        write_requests(dir.path(), RequestAct::Lock, std::slice::from_ref(&p)).unwrap();
        // a hand-written line that tries to do more is not a request
        let path = dir.path().join(REQUESTS_FILE);
        let mut f = std::fs::OpenOptions::new().append(true).open(&path).unwrap();
        writeln!(f, r#"{{"act":"unlock","link":"l1","at_ms":1}}"#).unwrap();
        writeln!(f, r#"{{"act":"lock","link":"l1","at_ms":1,"delegate":"power"}}"#).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
            assert_eq!(mode, 0o600);
        }
        let got = take_requests(dir.path());
        assert_eq!(got.len(), 1);
        assert_eq!(got[0].act, RequestAct::Lock);
        assert!(take_requests(dir.path()).is_empty(), "applied once");
    }
}
