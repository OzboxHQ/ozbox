//! `ozbox agent-mcp`: the bridge an engine starts, and the commands that put it in (or take it out of) the engines' settings.

use std::io::Write;

use serde_json::json;

use crate::agent_mcp::engines::{self, Outcome};
use crate::cli::AgentMcpCommand;
use crate::messages::t;
use crate::run::CliError;

fn home() -> Result<std::path::PathBuf, CliError> {
    dirs::home_dir().ok_or_else(|| CliError::Msg(t("agent_mcp.no_home", &[])))
}

fn program() -> String {
    std::env::current_exe()
        .ok()
        .and_then(|p| p.to_str().map(str::to_string))
        .unwrap_or_else(|| "ozbox".to_string())
}

fn check_engine(e: Option<&str>) -> Result<(), CliError> {
    match e {
        Some(id) if !engines::ENGINES.iter().any(|x| x.id == id) => Err(CliError::Msg(t(
            "agent_mcp.unknown_engine",
            &[("engine", id)],
        ))),
        _ => Ok(()),
    }
}

fn name_of(id: &str) -> &'static str {
    engines::ENGINES
        .iter()
        .find(|e| e.id == id)
        .map_or("", |e| e.name)
}

fn line(id: &str, o: &Outcome) -> String {
    let engine = name_of(id);
    match o {
        Outcome::Wrote => t("agent_mcp.wrote", &[("engine", engine)]),
        Outcome::Unchanged => t("agent_mcp.unchanged", &[("engine", engine)]),
        Outcome::Removed => t("agent_mcp.removed", &[("engine", engine)]),
        Outcome::Absent => t("agent_mcp.absent", &[("engine", engine)]),
        Outcome::LeftYours => t("agent_mcp.left_yours", &[("engine", engine)]),
        Outcome::Refused(why) => t("agent_mcp.refused", &[("engine", engine), ("why", why)]),
    }
}

fn word(o: &Outcome) -> &'static str {
    match o {
        Outcome::Wrote => "wrote",
        Outcome::Unchanged => "unchanged",
        Outcome::Removed => "removed",
        Outcome::Absent => "absent",
        Outcome::LeftYours => "left_yours",
        Outcome::Refused(_) => "refused",
    }
}

fn report(results: &[(&'static str, Outcome)], json_out: bool, next: bool) {
    if json_out {
        let v: Vec<_> = results
            .iter()
            .map(|(id, o)| json!({ "engine": id, "result": word(o) }))
            .collect();
        println!("{}", json!({ "engines": v }));
        return;
    }
    for (id, o) in results {
        println!("{}", line(id, o));
    }
    if next
        && results
            .iter()
            .any(|(_, o)| matches!(o, Outcome::Wrote | Outcome::Unchanged))
    {
        println!("{}", t("agent_mcp.next", &[]));
    }
}

pub fn run(c: &AgentMcpCommand, json_out: bool) -> Result<(), CliError> {
    match c {
        AgentMcpCommand::Bridge => {
            let stdin = std::io::stdin();
            let stdout = std::io::stdout();
            crate::agent_mcp::bridge::run(
                &crate::agent_mcp::bridge::socket_path(),
                crate::serve::unix_ms,
                stdin.lock(),
                stdout.lock(),
            )
            .map_err(|e| CliError::Msg(e.to_string()))
        }
        AgentMcpCommand::Install { engine } => {
            check_engine(engine.as_deref())?;
            let r = engines::install(&home()?, &program(), engine.as_deref());
            report(&r, json_out, true);
            let _ = std::io::stdout().flush();
            // a refused engine is a failure the setup step must see, not a silent skip
            let refused = r
                .iter()
                .filter(|(_, o)| matches!(o, Outcome::Refused(_)))
                .count();
            if refused > 0 {
                return Err(CliError::Msg(t(
                    "agent_mcp.some_refused",
                    &[("n", &refused.to_string())],
                )));
            }
            Ok(())
        }
        AgentMcpCommand::Remove { engine } => {
            check_engine(engine.as_deref())?;
            let r = engines::remove(&home()?, engine.as_deref());
            report(&r, json_out, false);
            Ok(())
        }
        AgentMcpCommand::Status => {
            let s = engines::status(&home()?, &program());
            if json_out {
                let v: Vec<_> = s
                    .iter()
                    .map(|(id, on)| json!({ "engine": id, "set_up": on }))
                    .collect();
                println!("{}", json!({ "engines": v }));
                return Ok(());
            }
            for (id, on) in s {
                let key = if on {
                    "agent_mcp.status_on"
                } else {
                    "agent_mcp.status_off"
                };
                println!("{}", t(key, &[("engine", name_of(id))]));
            }
            Ok(())
        }
    }
}
