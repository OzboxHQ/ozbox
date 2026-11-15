//! `ozbox memory ...` and `ozbox skills ...`: the same stores the dashboard and the agents' tools use, on this computer.
//!
//! Everything here is the person acting: notes they add are approved, and approving a skill records them as the reviewer.
//! Approving a skill prints its files first and asks for a yes (or `--yes`), because the approval is of exactly those files.

use std::io::{BufRead, IsTerminal, Write};

use ozbox_memory::memory::{Caller, Entry, Filter, NewEntry, Patch, Scope, State};
use ozbox_memory::now_ms;
use ozbox_memory::skills::InstallScope;
use serde_json::{json, Value};

use crate::cli::{MemoryCommand, SkillsCommand};
use crate::memory_tools::MemoryHost;
use crate::run::CliError;

fn fail(e: impl std::fmt::Display) -> CliError {
    CliError::Msg(e.to_string())
}

fn host() -> Result<MemoryHost, CliError> {
    let dir = crate::settings::Settings::path()
        .map(|p| p.with_file_name("agent-memory"))
        .ok_or_else(|| fail("this computer has no home folder to keep memory in"))?;
    MemoryHost::open(&dir).map_err(fail)
}

fn print_json(v: &Value) {
    println!("{}", serde_json::to_string_pretty(v).unwrap_or_default());
}

fn line(e: &Entry) -> String {
    let state = match e.state {
        State::Pending => "PENDING ",
        State::Approved => "",
    };
    let exp = if e.expired { " (expired)" } else { "" };
    format!("{}  {:<22} {state}{}{exp}", e.id, e.scope, e.title)
}

pub fn run_memory(c: &MemoryCommand, json_out: bool) -> Result<(), CliError> {
    let h = host()?;
    let me = Caller::Person("owner".into());
    let now = now_ms();
    let scope = |s: &Option<String>| -> Result<Option<Scope>, CliError> {
        s.as_deref().map(Scope::parse).transpose().map_err(fail)
    };
    match c {
        MemoryCommand::List { scope: sc, pending } => {
            let f = Filter {
                scope: scope(sc)?,
                state: pending.then_some(State::Pending),
                include_expired: true,
            };
            let list = h.memory.list(&me, &f, now).map_err(fail)?;
            if json_out {
                print_json(
                    &json!({ "notes": list.iter().map(|e| json!({"id": e.id, "scope": e.scope, "title": e.title, "state": e.state})).collect::<Vec<_>>() }),
                );
            } else if list.is_empty() {
                println!("No notes.");
            } else {
                list.iter().for_each(|e| println!("{}", line(e)));
            }
        }
        MemoryCommand::Search { query, scope: sc } => {
            let f = Filter {
                scope: scope(sc)?,
                ..Filter::default()
            };
            let list = h.memory.search(&me, query, &f, 25, now).map_err(fail)?;
            if json_out {
                print_json(
                    &json!({ "notes": list.iter().map(|e| json!({"id": e.id, "scope": e.scope, "title": e.title})).collect::<Vec<_>>() }),
                );
            } else {
                list.iter().for_each(|e| println!("{}", line(e)));
            }
        }
        MemoryCommand::Show { id } => {
            let e = h.memory.get(&me, id, now).map_err(fail)?;
            if json_out {
                print_json(
                    &json!({ "id": e.id, "scope": e.scope, "title": e.title, "body": e.body, "tags": e.tags,
                    "state": e.state, "written_by": e.provenance.actor, "run": e.provenance.run,
                    "reviewed_by": e.provenance.reviewed_by, "revision": e.revision }),
                );
            } else {
                println!(
                    "{}\n{}  by {}{}\n\n{}",
                    e.title,
                    e.scope,
                    e.provenance.actor,
                    e.provenance
                        .run
                        .as_ref()
                        .map(|r| format!(" (run {r})"))
                        .unwrap_or_default(),
                    e.body
                );
            }
        }
        MemoryCommand::Add {
            scope: sc,
            title,
            body,
            tags,
            expires_days,
        } => {
            let sc = Scope::parse(sc).map_err(fail)?;
            let e = h
                .memory
                .write(
                    &me,
                    &sc,
                    NewEntry {
                        title: title.clone(),
                        body: body.clone(),
                        tags: tags.clone(),
                        expires_ms: expires_days.map(|d| now + d.min(3650) * 86_400_000),
                    },
                    now,
                )
                .map_err(fail)?;
            println!("Added {}", e.id);
        }
        MemoryCommand::Edit { id, title, body } => {
            let e = h
                .memory
                .update(
                    &me,
                    id,
                    Patch {
                        title: title.clone(),
                        body: body.clone(),
                        ..Patch::default()
                    },
                    now,
                )
                .map_err(fail)?;
            println!("Changed {} (revision {})", e.id, e.revision);
        }
        MemoryCommand::Approve { id } => {
            let e = h.memory.approve(&me, id, now).map_err(fail)?;
            println!("Approved {}: agents can now read it.", e.id);
        }
        MemoryCommand::Forget { id } => {
            h.memory.forget(&me, id, now).map_err(fail)?;
            println!("Forgotten {id}. Git history keeps it.");
        }
        MemoryCommand::Reindex => println!("Indexed {} notes.", h.memory.reindex().map_err(fail)?),
    }
    Ok(())
}

fn confirm(yes: bool, q: &str) -> Result<bool, CliError> {
    if yes {
        return Ok(true);
    }
    if !std::io::stdin().is_terminal() {
        return Err(fail("this needs a person's yes: run it in a terminal, or pass --yes after reading the files"));
    }
    print!("{q} [y/N] ");
    let _ = std::io::stdout().flush();
    let mut a = String::new();
    std::io::stdin().lock().read_line(&mut a).map_err(fail)?;
    Ok(matches!(a.trim(), "y" | "Y" | "yes"))
}

pub fn run_skills(c: &SkillsCommand, json_out: bool, yes: bool) -> Result<(), CliError> {
    let h = host()?;
    let now = now_ms();
    match c {
        SkillsCommand::List => {
            let cat = h.skills.catalog();
            if json_out {
                print_json(&json!({ "skills": cat }));
            } else {
                for s in &cat {
                    println!(
                        "{:<24} v{:<8} {:<8} {}  {}",
                        s.name,
                        s.version,
                        s.source,
                        &s.hash[..12],
                        if s.approved {
                            "approved"
                        } else {
                            "not approved"
                        }
                    );
                    for i in &s.installs {
                        println!(
                            "    {} {:?}{}",
                            i.scope,
                            i.status,
                            if i.update_available {
                                "  (update available)"
                            } else {
                                ""
                            }
                        );
                    }
                }
            }
        }
        SkillsCommand::Show { name } => {
            let r = h.skills.review(name, None).map_err(fail)?;
            if json_out {
                print_json(&json!(r));
            } else {
                println!(
                    "{} v{}  {}\nLicence: {}\n{}\n",
                    r.name,
                    r.version,
                    r.hash,
                    r.license.as_deref().unwrap_or("not stated"),
                    r.description
                );
                for f in &r.files {
                    println!("--- {} ---\n{}\n", f.path, f.text);
                }
            }
        }
        SkillsCommand::Add { dir } => {
            let it = h.skills.add_to_library(dir).map_err(fail)?;
            println!(
                "Added {} ({}). It is not approved or installed yet.",
                it.name,
                &it.hash[..12]
            );
        }
        SkillsCommand::Install { name, scope } => {
            let sc = InstallScope::parse(scope).map_err(fail)?;
            let v = h.skills.install(name, &sc, "owner", now).map_err(fail)?;
            println!("Installed {name} at {scope} ({:?}). Review and approve it before an agent can use it.", v.status);
        }
        SkillsCommand::Uninstall { name, scope } => {
            h.skills
                .uninstall(name, &InstallScope::parse(scope).map_err(fail)?)
                .map_err(fail)?;
            println!("Removed {name} from {scope}.");
        }
        SkillsCommand::Approve { name } => {
            let r = h.skills.review(name, None).map_err(fail)?;
            for f in &r.files {
                println!("--- {} ---\n{}\n", f.path, f.text);
            }
            if !confirm(
                yes,
                &format!("Approve exactly these files of {name} ({})?", &r.hash[..12]),
            )? {
                println!("Not approved.");
                return Ok(());
            }
            h.skills
                .approve(name, &r.hash, "owner", now)
                .map_err(fail)?;
            println!("Approved {name} ({}).", &r.hash[..12]);
        }
        SkillsCommand::Revoke { name } => {
            h.skills.revoke(name).map_err(fail)?;
            println!("Withdrew every approval of {name}.");
        }
    }
    Ok(())
}
