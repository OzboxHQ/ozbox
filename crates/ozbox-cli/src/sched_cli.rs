//! `ozbox schedule add|list|show|pause|resume|run-now|remove` and `ozbox trigger add|list|remove|deliveries`.
//!
//! These work on the fleet store beside the configuration, the same file `ozbox serve` reads, so the dashboard and the
//! command line show one set of schedules. `run-now` asks the server (the lease holder) to run it; nothing here starts
//! a run itself. A trigger's secret is shown once, when it is made.

use std::io::{BufRead, IsTerminal, Write};
use std::path::PathBuf;

use serde_json::{json, Value};

use crate::cli::{ScheduleCommand, ScheduleFlags, TriggerCommand, TriggerFlags};
use crate::messages::t;
use crate::run::CliError;
use crate::sched::engine::new_id;
use crate::sched::input::{self, ScheduleIn, TriggerIn};
use crate::sched::model::*;
use crate::sched::receive::secret_name;
use crate::sched::store::Store;
use crate::sched::view::{self, PreviewIn};

fn now_ms() -> u64 {
    crate::sched::now_ms()
}

pub fn store_path() -> Option<PathBuf> {
    crate::settings::Settings::path().map(|p| p.with_file_name("fleet-schedules.json"))
}

fn store() -> Result<Store, CliError> {
    store_path()
        .map(crate::sched::shared::store_at)
        .ok_or_else(|| CliError::Msg(t("sched.cli_no_home", &[])))
}

fn owner_zone() -> String {
    crate::settings::Settings::path()
        .and_then(|p| crate::settings::Settings::load_from(&p).ok())
        .map(|s| s.locale.zone().to_string())
        .unwrap_or_else(|| "UTC".into())
}

fn invalid((k, d): Invalid) -> CliError {
    CliError::Msg(t(k, &[("detail", &d)]))
}

fn io(e: std::io::Error) -> CliError {
    CliError::Msg(t("sched.cli_store", &[("error", &e.to_string())]))
}

fn print_json(v: &Value) {
    println!("{}", serde_json::to_string_pretty(v).unwrap_or_default());
}

fn confirm(yes: bool, question: &str) -> Result<bool, CliError> {
    if yes {
        return Ok(true);
    }
    if !std::io::stdin().is_terminal() {
        return Err(CliError::Msg(t("sched.cli_refuse_no_tty", &[])));
    }
    print!("{question} [y/N] ");
    let _ = std::io::stdout().flush();
    let mut line = String::new();
    let _ = std::io::stdin().lock().read_line(&mut line);
    Ok(matches!(
        line.trim().to_ascii_lowercase().as_str(),
        "y" | "yes"
    ))
}

fn target_of(box_name: &Option<String>, profile: &Option<String>) -> Target {
    Target {
        box_name: box_name.clone(),
        profile: profile.clone(),
    }
}

fn line(s: &Schedule, v: &Value) -> String {
    let when = match &s.when {
        When::Cron { expr } => format!("{expr} ({})", s.time_zone),
        When::Every { minutes } => format!("every {minutes} min"),
    };
    let next = v["next"]["local"].as_str().unwrap_or("-");
    let state = if s.enabled { "on " } else { "off" };
    format!("{}  {state}  {}  {when}  next {next}", s.id, s.name)
}

fn run_failover(c: &crate::cli::FailoverCommand) -> Result<(), CliError> {
    use crate::sched::shared::{load_config, save_config, SharedConfig};
    let path = store_path().ok_or_else(|| CliError::Msg(t("sched.cli_no_home", &[])))?;
    match c {
        crate::cli::FailoverCommand::Set { s3, profile } => {
            save_config(
                &path,
                &SharedConfig {
                    s3: s3.clone(),
                    profile: profile.clone(),
                },
            )
            .map_err(CliError::Msg)?;
            println!("Schedules and triggers are now kept in {s3}. Do the same on the other computer; whichever holds the lease fires, and the other takes over after about 30 seconds of silence.");
        }
        crate::cli::FailoverCommand::Off => {
            let _ = std::fs::remove_file(crate::sched::shared::config_path(&path));
            println!(
                "This computer keeps its own schedules again. Restart `ozbox serve` to apply it."
            );
        }
        crate::cli::FailoverCommand::Status => match load_config(&path) {
            None => println!("Failover is off: this computer keeps its own schedules."),
            Some(c) => {
                let st = store()?;
                let d = st.read();
                println!("Shared: {}", c.s3);
                match d.lease {
                    Some(l) if l.expires_ms != 0 => println!(
                        "Lease held by {} (epoch {}, beat {})",
                        l.holder, l.epoch, l.beat
                    ),
                    Some(l) => println!(
                        "Lease released by {} (epoch {}); the next dashboard to tick takes it",
                        l.holder, l.epoch
                    ),
                    None => println!("No dashboard has held the lease yet."),
                }
            }
        },
    }
    Ok(())
}

pub fn run_schedule(cmd: &ScheduleCommand, fl: &ScheduleFlags) -> Result<(), CliError> {
    if let ScheduleCommand::Failover { command } = cmd {
        return run_failover(command);
    }
    let st = store()?;
    let now = now_ms();
    match cmd {
        ScheduleCommand::Add(a) => {
            let i = ScheduleIn {
                name: Some(a.name.clone()),
                when_text: a.when.clone(),
                cron: a.cron.clone(),
                every_minutes: a.every_minutes,
                time_zone: a.time_zone.clone(),
                owner: a.owner.clone(),
                engine: Some(a.engine.clone()),
                prompt: a.prompt.clone(),
                skill: a.skill.clone(),
                target: Some(target_of(&a.box_name, &a.profile)),
                caps: Some(Caps {
                    max_spend_cents: a.max_spend_cents,
                    max_minutes: a.max_minutes,
                }),
                results_to: Some(a.results_to.clone()),
                catch_up_minutes: a.catch_up_minutes,
                enabled: if a.disabled { Some(false) } else { None },
                heartbeat: Some(a.heartbeat),
            };
            let mut s = input::new_schedule(now);
            input::apply_schedule(&mut s, i, &owner_zone(), true, now).map_err(invalid)?;
            let doc = st.read();
            if doc.schedules.len() >= MAX_SCHEDULES {
                return Err(CliError::Msg(t("sched.cli_too_many", &[])));
            }
            let stt = SchedState {
                armed_ms: now,
                ..Default::default()
            };
            let v = view::schedule(
                &s,
                &Doc {
                    state: [(s.id.clone(), stt.clone())].into(),
                    ..Default::default()
                },
                now,
                None,
            );
            if fl.json {
                print_json(&json!({ "dry_run": fl.dry_run, "schedule": v }));
            } else {
                println!(
                    "{}",
                    t(
                        "sched.cli_plan_head",
                        &[("name", &s.name), ("zone", &s.time_zone)]
                    )
                );
                if let When::Cron { expr } = &s.when {
                    println!("{}", t("sched.cli_plan_cron", &[("cron", expr)]));
                }
                for n in view::next_runs(&s, &stt, now, 5) {
                    println!("  {}", n["local"].as_str().unwrap_or(""));
                }
            }
            if fl.dry_run {
                if !fl.json {
                    println!("{}", t("sched.cli_dry_run", &[]));
                }
                return Ok(());
            }
            let id = s.id.clone();
            st.update(|d| {
                d.state.insert(id, stt);
                d.schedules.push(s.clone());
            })
            .map_err(io)?;
            if !fl.json {
                println!("{}", t("sched.cli_added", &[("id", &s.id)]));
            }
            Ok(())
        }
        ScheduleCommand::List => {
            let doc = st.read();
            let items: Vec<Value> = doc
                .schedules
                .iter()
                .map(|s| view::schedule(s, &doc, now, None))
                .collect();
            if fl.json {
                print_json(&json!({ "schedules": items }));
            } else if items.is_empty() {
                println!("{}", t("sched.cli_none", &[]));
            } else {
                for (s, v) in doc.schedules.iter().zip(&items) {
                    println!("{}", line(s, v));
                }
            }
            Ok(())
        }
        ScheduleCommand::Show { id } => {
            let doc = st.read();
            let s = doc
                .schedule(id)
                .ok_or_else(|| CliError::Msg(t("sched.cli_not_found", &[("id", id)])))?;
            let v = view::schedule(s, &doc, now, None);
            let runs: Vec<&RunRec> = doc
                .runs
                .iter()
                .rev()
                .filter(|r| r.owner_id == *id)
                .take(10)
                .collect();
            if fl.json {
                print_json(&json!({ "schedule": v, "runs": runs }));
            } else {
                println!("{}", line(s, &v));
                let stt = doc.state.get(id).cloned().unwrap_or_default();
                for n in view::next_runs(s, &stt, now, 5) {
                    println!("  next  {}", n["local"].as_str().unwrap_or(""));
                }
                for r in runs {
                    println!(
                        "  {:?}  {}  {}",
                        r.status,
                        crate::state::format_rfc3339(r.started_ms),
                        r.detail
                    );
                }
            }
            Ok(())
        }
        ScheduleCommand::Pause { id } | ScheduleCommand::Resume { id } => {
            let on = matches!(cmd, ScheduleCommand::Resume { .. });
            if fl.dry_run {
                println!("{}", t("sched.cli_dry_run", &[]));
                return Ok(());
            }
            let sid = id.clone();
            let found = st
                .update(|d| {
                    let Some(s) = d.schedules.iter_mut().find(|s| s.id == sid) else {
                        return false;
                    };
                    s.enabled = on;
                    s.updated_ms = now;
                    if on {
                        let x = d.state.entry(sid.clone()).or_default();
                        x.armed_ms = now;
                        x.last_slot_ms = None;
                    }
                    true
                })
                .map_err(io)?;
            if !found {
                return Err(CliError::Msg(t("sched.cli_not_found", &[("id", id)])));
            }
            if fl.json {
                print_json(&json!({ "id": id, "enabled": on }));
            } else {
                println!(
                    "{}",
                    t(
                        if on {
                            "sched.cli_resumed"
                        } else {
                            "sched.cli_paused"
                        },
                        &[("id", id)]
                    )
                );
            }
            Ok(())
        }
        ScheduleCommand::RunNow { id } => {
            if st.read().schedule(id).is_none() {
                return Err(CliError::Msg(t("sched.cli_not_found", &[("id", id)])));
            }
            if fl.dry_run {
                println!("{}", t("sched.cli_dry_run", &[]));
                return Ok(());
            }
            let sid = id.clone();
            st.update(|d| {
                d.run_now.push(RunNow {
                    id: new_id("now"),
                    schedule_id: sid,
                    requested_ms: now,
                    by: "cli".into(),
                })
            })
            .map_err(io)?;
            if fl.json {
                print_json(&json!({ "queued": true, "id": id }));
            } else {
                println!("{}", t("sched.cli_run_queued", &[("id", id)]));
            }
            Ok(())
        }
        ScheduleCommand::Remove { id } => {
            let doc = st.read();
            let s = doc
                .schedule(id)
                .ok_or_else(|| CliError::Msg(t("sched.cli_not_found", &[("id", id)])))?;
            if fl.dry_run {
                println!("{}", t("sched.cli_remove_plan", &[("name", &s.name)]));
                println!("{}", t("sched.cli_dry_run", &[]));
                return Ok(());
            }
            if !confirm(fl.yes, &t("sched.cli_remove_confirm", &[("name", &s.name)]))? {
                println!("{}", t("sched.cli_aborted", &[]));
                return Ok(());
            }
            let sid = id.clone();
            st.update(|d| {
                d.schedules.retain(|s| s.id != sid);
                d.state.remove(&sid);
            })
            .map_err(io)?;
            if fl.json {
                print_json(&json!({ "removed": id }));
            } else {
                println!("{}", t("sched.cli_removed", &[("id", id)]));
            }
            Ok(())
        }
        ScheduleCommand::Failover { .. } => Ok(()),
        ScheduleCommand::Preview {
            text,
            cron,
            time_zone,
            count,
        } => {
            let zone = time_zone.clone().unwrap_or_else(owner_zone);
            let v = view::preview(
                &PreviewIn {
                    text: text.as_deref(),
                    cron: cron.as_deref(),
                    time_zone: &zone,
                    count: *count,
                },
                now,
            )
            .map_err(invalid)?;
            if fl.json {
                print_json(&v);
            } else {
                println!(
                    "{} ({})",
                    v["cron"].as_str().unwrap_or(""),
                    v["time_zone"].as_str().unwrap_or("")
                );
                for n in v["next"].as_array().into_iter().flatten() {
                    println!("  {}", n["local"].as_str().unwrap_or(""));
                }
            }
            Ok(())
        }
    }
}

pub fn run_trigger(cmd: &TriggerCommand, fl: &TriggerFlags) -> Result<(), CliError> {
    let st = store()?;
    let now = now_ms();
    match cmd {
        TriggerCommand::Add(a) => {
            let scheme = match a.scheme.as_str() {
                "github" => Scheme::Github,
                "generic" => Scheme::Generic,
                "stripe" => Scheme::Stripe,
                _ => return Err(CliError::Msg(t("trigger.cli_bad_scheme", &[]))),
            };
            let i = TriggerIn {
                name: Some(a.name.clone()),
                scheme: Some(scheme),
                engine: Some(a.engine.clone()),
                template: Some(a.template.clone()),
                skill: a.skill.clone(),
                target: Some(target_of(&a.box_name, &a.profile)),
                caps: Some(Caps {
                    max_spend_cents: a.max_spend_cents,
                    max_minutes: a.max_minutes,
                }),
                results_to: Some(a.results_to.clone()),
                events: Some(a.events.clone()),
                owner: a.owner.clone(),
                enabled: Some(true),
            };
            let tr = input::build_trigger(i, now).map_err(invalid)?;
            if st.read().triggers.len() >= MAX_TRIGGERS {
                return Err(CliError::Msg(t("sched.cli_too_many", &[])));
            }
            if fl.dry_run {
                if fl.json {
                    print_json(
                        &json!({ "dry_run": true, "trigger": view::trigger(&tr, &Doc::default(), false, None) }),
                    );
                } else {
                    println!(
                        "{}",
                        t(
                            "trigger.cli_plan",
                            &[("name", &tr.name), ("scheme", tr.scheme.id())]
                        )
                    );
                    println!("{}", t("sched.cli_dry_run", &[]));
                }
                return Ok(());
            }
            let secret = input::new_secret().ok_or_else(|| {
                CliError::Msg(t("sched.cli_store", &[("error", "no randomness")]))
            })?;
            let secrets = crate::secrets_file::select();
            secrets
                .set(&secret_name(&tr.id), &secret)
                .map_err(|e| CliError::Msg(e.to_string()))?;
            let t2 = tr.clone();
            if let Err(e) = st.update(|d| d.triggers.push(t2)) {
                let _ = secrets.delete(&secret_name(&tr.id));
                return Err(io(e));
            }
            let base = crate::tunnel_cli::tunnel_path()
                .and_then(|p| crate::tunnel::TunnelFile::load(&p).ok().flatten())
                .map(|f| f.public_url)
                .filter(|u| !u.is_empty());
            let mut v = view::trigger(&tr, &st.read(), true, base.as_deref());
            if fl.json {
                if let Value::Object(m) = &mut v {
                    m.insert("secret".into(), json!(secret));
                }
                print_json(&v);
            } else {
                println!("{}", t("trigger.cli_added", &[("id", &tr.id)]));
                match &base {
                    Some(u) => println!(
                        "{}",
                        t(
                            "trigger.cli_url",
                            &[(
                                "url",
                                &format!("{}/hooks/{}", u.trim_end_matches('/'), tr.id)
                            )]
                        )
                    ),
                    None => println!(
                        "{}",
                        t(
                            "trigger.cli_path",
                            &[("path", &format!("/hooks/{}", tr.id))]
                        )
                    ),
                }
                println!("{}", t("trigger.cli_secret_once", &[("secret", &secret)]));
            }
            Ok(())
        }
        TriggerCommand::List => {
            let doc = st.read();
            let secrets = crate::secrets_file::select();
            let items: Vec<Value> = doc
                .triggers
                .iter()
                .map(|tr| {
                    view::trigger(
                        tr,
                        &doc,
                        secrets.exists(&secret_name(&tr.id)).unwrap_or(false),
                        None,
                    )
                })
                .collect();
            if fl.json {
                print_json(&json!({ "triggers": items }));
            } else if items.is_empty() {
                println!("{}", t("trigger.cli_none", &[]));
            } else {
                for tr in &doc.triggers {
                    println!(
                        "{}  {}  {}  /hooks/{}",
                        tr.id,
                        if tr.enabled { "on " } else { "off" },
                        tr.name,
                        tr.id
                    );
                }
            }
            Ok(())
        }
        TriggerCommand::Remove { id } => {
            let doc = st.read();
            let tr = doc
                .trigger(id)
                .ok_or_else(|| CliError::Msg(t("trigger.cli_not_found", &[("id", id)])))?;
            if fl.dry_run {
                println!("{}", t("trigger.cli_remove_plan", &[("name", &tr.name)]));
                println!("{}", t("sched.cli_dry_run", &[]));
                return Ok(());
            }
            if !confirm(
                fl.yes,
                &t("trigger.cli_remove_confirm", &[("name", &tr.name)]),
            )? {
                println!("{}", t("sched.cli_aborted", &[]));
                return Ok(());
            }
            let tid = id.clone();
            st.update(|d| d.triggers.retain(|t| t.id != tid))
                .map_err(io)?;
            let _ = crate::secrets_file::select().delete(&secret_name(id));
            if fl.json {
                print_json(&json!({ "removed": id }));
            } else {
                println!("{}", t("trigger.cli_removed", &[("id", id)]));
            }
            Ok(())
        }
        TriggerCommand::RotateSecret { id } => {
            let doc = st.read();
            let tr = doc
                .trigger(id)
                .ok_or_else(|| CliError::Msg(t("trigger.cli_not_found", &[("id", id)])))?;
            if fl.dry_run {
                println!("{}", t("trigger.cli_rotate_plan", &[("name", &tr.name)]));
                println!("{}", t("sched.cli_dry_run", &[]));
                return Ok(());
            }
            if !confirm(
                fl.yes,
                &t("trigger.cli_rotate_confirm", &[("name", &tr.name)]),
            )? {
                println!("{}", t("sched.cli_aborted", &[]));
                return Ok(());
            }
            let secrets = crate::secrets_file::select();
            let current = secrets
                .get(&secret_name(id))
                .map_err(|e| CliError::Msg(e.to_string()))?
                .ok_or_else(|| CliError::Msg(t("trigger.cli_no_secret", &[("id", id)])))?;
            let fresh =
                input::new_secret().ok_or_else(|| CliError::Msg(t("sched.cli_no_random", &[])))?;
            secrets
                .set(&crate::sched::receive::previous_secret_name(id), &current)
                .and_then(|()| secrets.set(&secret_name(id), &fresh))
                .map_err(|e| CliError::Msg(e.to_string()))?;
            let until = now + crate::sched::receive::SECRET_OVERLAP_MS;
            let tid = id.clone();
            st.update(|d| {
                if let Some(t) = d.triggers.iter_mut().find(|t| t.id == tid) {
                    t.previous_secret_until_ms = Some(until);
                }
            })
            .map_err(io)?;
            if fl.json {
                print_json(
                    &json!({ "id": id, "secret": fresh, "previous_secret_until_ms": until }),
                );
            } else {
                println!("{}", t("trigger.cli_rotated", &[("id", id)]));
                println!("{}", t("trigger.cli_secret_once", &[("secret", &fresh)]));
            }
            Ok(())
        }
        TriggerCommand::Deliveries { id } => {
            let doc = st.read();
            if doc.trigger(id).is_none() {
                return Err(CliError::Msg(t("trigger.cli_not_found", &[("id", id)])));
            }
            let d: Vec<&Delivery> = doc
                .deliveries
                .iter()
                .rev()
                .filter(|d| d.trigger_id == *id)
                .take(50)
                .collect();
            if fl.json {
                print_json(&json!({ "deliveries": d }));
            } else if d.is_empty() {
                println!("{}", t("trigger.cli_no_deliveries", &[]));
            } else {
                for x in d {
                    println!(
                        "{}  {}  {}  {} bytes",
                        crate::state::format_rfc3339(x.ts_ms),
                        x.outcome,
                        x.reason,
                        x.size
                    );
                }
            }
            Ok(())
        }
    }
}
