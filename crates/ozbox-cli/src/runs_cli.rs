//! `ozbox run ...` and `ozbox approvals ...`: the command line for supervised agent runs. It reads and changes the same
//! task store the dashboard server supervises (`ozbox_core::run`), so what one shows the other shows. Starting a run only
//! queues it; `ozbox serve` admits and supervises it. The `--json` shapes are the ones `/v1/tasks` and
//! `/v1/approval-requests` answer with.

use ozbox_core::run::{
    ApprovalState, DeliverTo, RunCaps, RunOrigin, RunSpec, TaskState, TaskStore,
};
use ozbox_core::supervisor::{self, AddBudget};
use ozbox_core::{Error, Result};
use serde_json::{json, Value};

use crate::cli::{ApprovalsCommand, RunCommand};
use crate::messages::t;
use crate::serve::runs_routes::{approval_json, task_json};

pub struct Flags {
    pub json: bool,
    pub dry_run: bool,
    pub yes: bool,
}

/// Where the task store is: beside the settings file, the same place `ozbox serve` uses.
pub fn store_path() -> Option<std::path::PathBuf> {
    crate::settings::Settings::path().map(|p| p.with_file_name("tasks.json"))
}

fn store() -> Result<TaskStore> {
    store_path()
        .map(TaskStore::new)
        .ok_or_else(|| Error::Config(t("runs.no_store", &[])))
}

fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

fn money(cents: u64) -> String {
    format!("${}.{:02}", cents / 100, cents % 100)
}

fn minutes(s: u64) -> String {
    format!("{}m{:02}s", s / 60, s % 60)
}

fn print_json(v: &Value) -> Result<()> {
    println!("{}", serde_json::to_string_pretty(v)?);
    Ok(())
}

fn state_of(s: &str) -> Result<&'static str> {
    [
        "queued",
        "running",
        "needs_you",
        "review",
        "done",
        "failed",
        "cancelled",
    ]
    .into_iter()
    .find(|x| *x == s)
    .ok_or_else(|| Error::Config(t("runs.bad_state", &[("value", s)])))
}

fn state_name(s: TaskState) -> &'static str {
    task_json_state(s)
}

fn task_json_state(s: TaskState) -> &'static str {
    match s {
        TaskState::Queued => "queued",
        TaskState::Running => "running",
        TaskState::NeedsYou => "needs_you",
        TaskState::Review => "review",
        TaskState::Done => "done",
        TaskState::Failed => "failed",
        TaskState::Cancelled => "cancelled",
    }
}

fn caps_text(c: &RunCaps) -> String {
    let mut v = Vec::new();
    if let Some(m) = c.max_runtime_s {
        v.push(format!("{} min", m / 60));
    }
    if let Some(s) = c.max_spend_cents {
        v.push(money(s));
    }
    if let Some(k) = c.max_tokens {
        v.push(format!("{k} tokens"));
    }
    if v.is_empty() {
        String::new()
    } else {
        format!(", limits: {}", v.join(", "))
    }
}

pub fn run(cmd: &RunCommand, f: &Flags) -> Result<()> {
    let store = store()?;
    let who = "owner";
    match cmd {
        RunCommand::Start {
            engine,
            box_name,
            repo,
            branch,
            skill,
            prompt,
            prompt_file,
            max_minutes,
            max_spend,
            max_tokens,
            deliver,
            idempotency_key,
            model,
        } => {
            let text = match (prompt, prompt_file) {
                (Some(_), Some(_)) => return Err(Error::Config(t("runs.prompt_both", &[]))),
                (Some(p), None) => p.clone(),
                (None, Some(path)) => std::fs::read_to_string(path).map_err(|e| {
                    Error::Config(t(
                        "runs.prompt_unreadable",
                        &[("why", &e.kind().to_string())],
                    ))
                })?,
                (None, None) => String::new(),
            };
            if text.trim().is_empty() && skill.is_none() {
                return Err(Error::Config(t("runs.need_prompt", &[])));
            }
            let mut to = Vec::new();
            for d in deliver {
                to.push(match d.as_str() {
                    "pr" => DeliverTo::PullRequest,
                    "alert" => DeliverTo::Alert,
                    other => return Err(Error::Config(t("runs.bad_deliver", &[("value", other)]))),
                });
            }
            let spec = RunSpec {
                interactive: false,
                engine: engine.clone(),
                prompt: text,
                skill: skill.clone(),
                box_name: box_name.as_str().to_string(),
                repo: repo.clone(),
                branch: branch.clone(),
                caps: RunCaps {
                    max_runtime_s: max_minutes.map(|m| m * 60),
                    max_spend_cents: max_spend.map(|d| (d * 100.0).round().max(0.0) as u64),
                    max_tokens: *max_tokens,
                },
                deliver_to: to,
                requested_by: who.into(),
                origin: RunOrigin::Manual,
                idempotency_key: idempotency_key.clone(),
                model: match model {
                    None => None,
                    Some(m) => match m.split_once('/') {
                        Some((p, name)) if !p.is_empty() && !name.is_empty() => {
                            Some(ozbox_core::run::ModelRef {
                                provider_id: p.to_string(),
                                model: name.to_string(),
                            })
                        }
                        _ => return Err(Error::Config(t("runs.bad_model", &[("value", m)]))),
                    },
                },
            };
            spec.validate().map_err(|e| Error::Config(e.to_string()))?;
            if f.dry_run {
                let ahead = store
                    .load()?
                    .tasks
                    .iter()
                    .filter(|t| t.state == TaskState::Queued)
                    .count();
                if f.json {
                    return print_json(&json!({
                        "dry_run": true,
                        "would_queue": { "engine": spec.engine, "box": spec.box_name, "repo": spec.repo,
                            "branch": spec.branch, "person": spec.requested_by, "caps": spec.caps, "deliver_to": spec.deliver_to },
                        "queued_ahead": ahead,
                        "note": "Nothing was started.",
                    }));
                }
                println!(
                    "{}",
                    t(
                        "runs.dry_run_start",
                        &[
                            ("engine", &spec.engine),
                            ("box", &spec.box_name),
                            ("person", &spec.requested_by),
                            ("caps", &caps_text(&spec.caps)),
                            ("ahead", &ahead.to_string()),
                        ]
                    )
                );
                return Ok(());
            }
            let box_name = spec.box_name.clone();
            let started = ozbox_core::run::RunStarter::start_run(&store, spec)
                .map_err(|e| Error::Config(e.to_string()))?;
            if f.json {
                return print_json(&serde_json::to_value(&started)?);
            }
            println!(
                "{}",
                t("runs.queued", &[("id", &started.id), ("box", &box_name)])
            );
            Ok(())
        }
        RunCommand::List {
            box_name,
            engine,
            state,
            person,
            since,
        } => {
            let state = state.as_deref().map(state_of).transpose()?;
            let since_ms = match since {
                Some(s) => crate::serve::parse_rfc3339_ms(s)
                    .ok_or_else(|| Error::Config(t("runs.bad_time", &[("value", s)])))?,
                None => 0,
            };
            let book = store.load()?;
            let items: Vec<&ozbox_core::run::Task> = book
                .tasks
                .iter()
                .rev()
                .filter(|x| {
                    box_name
                        .as_ref()
                        .is_none_or(|b| x.spec.box_name == b.as_str())
                })
                .filter(|x| engine.as_ref().is_none_or(|e| &x.spec.engine == e))
                .filter(|x| person.as_ref().is_none_or(|p| &x.spec.requested_by == p))
                .filter(|x| state.is_none_or(|s| state_name(x.state) == s))
                .filter(|x| x.created_ms >= since_ms)
                .collect();
            if f.json {
                return print_json(
                    &json!({ "items": items.iter().map(|x| task_json(x, false)).collect::<Vec<_>>() }),
                );
            }
            if items.is_empty() {
                println!("{}", t("runs.none", &[]));
            }
            for x in items {
                let note = match (&x.needs, &x.queue_reason) {
                    (Some(ozbox_core::run::Needs::SpendCap), _) => t("runs.cap_note_spend", &[]),
                    (Some(ozbox_core::run::Needs::TimeCap), _) => t("runs.cap_note_time", &[]),
                    (Some(ozbox_core::run::Needs::TokenCap), _) => t("runs.cap_note_tokens", &[]),
                    (Some(ozbox_core::run::Needs::MonthlyCap { .. }), _) => {
                        t("runs.cap_note_monthly", &[])
                    }
                    (Some(ozbox_core::run::Needs::Approval { .. }), _) => {
                        t("runs.cap_note_approval", &[])
                    }
                    (None, Some(why)) => t("runs.wait_note", &[("why", why)]),
                    _ => String::new(),
                };
                println!(
                    "{}",
                    t(
                        "runs.row",
                        &[
                            ("id", &x.id),
                            ("state", state_name(x.state)),
                            ("engine", &x.spec.engine),
                            ("box", &x.spec.box_name),
                            ("person", &x.spec.requested_by),
                            ("spend", &money(x.spend_cents)),
                            ("elapsed", &minutes(x.active_s)),
                            ("note", &note),
                        ]
                    )
                );
            }
            Ok(())
        }
        RunCommand::Show { id } => {
            let book = store.load()?;
            let x = book.task(id).ok_or_else(|| Error::NotFound(id.clone()))?;
            if f.json {
                return print_json(&task_json(x, true));
            }
            println!(
                "{}",
                t(
                    "runs.show_head",
                    &[("id", &x.id), ("state", state_name(x.state))]
                )
            );
            let line = |label: &str, value: String| {
                println!(
                    "{}",
                    t("runs.show_line", &[("label", label), ("value", &value)])
                )
            };
            line("engine", x.spec.engine.clone());
            line("box", x.spec.box_name.clone());
            if let Some(r) = &x.spec.repo {
                line("repo", r.clone());
            }
            line("person", x.spec.requested_by.clone());
            line("spend", money(x.spend_cents));
            line("elapsed", minutes(x.active_s));
            if let Some(b) = &x.wip_branch {
                line("saved work", b.clone());
            }
            for l in &x.links {
                line(&l.label, l.url.clone());
            }
            if let Some(e) = &x.error {
                line("error", e.clone());
            }
            Ok(())
        }
        RunCommand::Logs { id, tail } => {
            let book = store.load()?;
            let x = book.task(id).ok_or_else(|| Error::NotFound(id.clone()))?;
            let skip = x.log.len().saturating_sub(*tail);
            let lines: Vec<&String> = x.log.iter().skip(skip).collect();
            if f.json {
                return print_json(&json!({ "id": id, "lines": lines }));
            }
            if lines.is_empty() {
                println!("{}", t("runs.logs_none", &[]));
            }
            for l in lines {
                println!("{l}");
            }
            Ok(())
        }
        RunCommand::Cancel { id } => {
            if f.dry_run {
                return dry_action(f, "cancel", id);
            }
            store
                .update(|b| supervisor::cancel(b, id, who, now_ms()))?
                .map_err(|e| Error::Config(e.to_string()))?;
            if f.json {
                return print_json(&json!({ "id": id, "cancelling": true }));
            }
            println!("{}", t("runs.cancelled", &[("id", id)]));
            Ok(())
        }
        RunCommand::Retry { id } => {
            if f.dry_run {
                return dry_action(f, "retry", id);
            }
            let new = store
                .update(|b| supervisor::retry(b, id, who, now_ms()))?
                .map_err(|e| Error::Config(e.to_string()))?;
            if f.json {
                return print_json(&json!({ "id": new, "retry_of": id }));
            }
            println!("{}", t("runs.retried", &[("id", id), ("new", &new)]));
            Ok(())
        }
        RunCommand::Resume {
            id,
            add_spend,
            add_minutes,
            add_tokens,
        } => {
            let add = AddBudget {
                cents: add_spend
                    .map(|d| (d * 100.0).round().max(0.0) as u64)
                    .unwrap_or(0),
                seconds: add_minutes.unwrap_or(0) * 60,
                tokens: add_tokens.unwrap_or(0),
            };
            if add == AddBudget::default() {
                return Err(Error::Config(t("runs.resume_need", &[])));
            }
            if f.dry_run {
                return dry_action(f, "resume", id);
            }
            store
                .update(|b| supervisor::resume(b, id, add, who, now_ms()))?
                .map_err(|e| Error::Config(e.to_string()))?;
            if f.json {
                return print_json(&json!({ "id": id, "state": "queued" }));
            }
            println!("{}", t("runs.resumed", &[("id", id)]));
            Ok(())
        }
    }
}

fn dry_action(f: &Flags, action: &str, id: &str) -> Result<()> {
    if f.json {
        return print_json(&json!({ "dry_run": true, "action": action, "id": id }));
    }
    println!(
        "{}",
        t("runs.dry_run_action", &[("action", action), ("id", id)])
    );
    Ok(())
}

pub fn approvals(cmd: &ApprovalsCommand, f: &Flags) -> Result<()> {
    let store = store()?;
    let who = "owner";
    match cmd {
        ApprovalsCommand::List { all } => {
            let book = store.load()?;
            let now = now_ms();
            let items: Vec<_> = book
                .approvals
                .iter()
                .filter(|a| *all || a.state == ApprovalState::Pending)
                .collect();
            if f.json {
                return print_json(&json!({
                    "items": items.iter().map(|a| approval_json(a, now, true)).collect::<Vec<_>>()
                }));
            }
            if items.is_empty() {
                println!("{}", t("approvals.none", &[]));
            }
            for a in items {
                let mut flags = String::new();
                if a.production {
                    flags.push_str(&t("approvals.flag_prod", &[]));
                }
                if a.needs_step_up {
                    flags.push_str(&t("approvals.flag_step_up", &[]));
                }
                let kind = serde_json::to_value(a.kind)?
                    .as_str()
                    .unwrap_or("")
                    .to_string();
                println!(
                    "{}",
                    t(
                        "approvals.row",
                        &[
                            ("id", &a.id),
                            ("kind", &kind),
                            ("box", &a.box_name),
                            ("by", &a.asked_by),
                            ("expires", &minutes(a.expires_ms.saturating_sub(now) / 1000)),
                            ("action", &a.action),
                            ("flags", &flags),
                        ]
                    )
                );
            }
            Ok(())
        }
        ApprovalsCommand::Approve { id } | ApprovalsCommand::Deny { id } => {
            let approve = matches!(cmd, ApprovalsCommand::Approve { .. });
            let book = store.load()?;
            let a = book
                .approval(id)
                .ok_or_else(|| Error::Config(t("approvals.unknown", &[("id", id)])))?;
            if approve && a.needs_step_up && !f.yes {
                return Err(Error::Config(t("approvals.step_up_here", &[("id", id)])));
            }
            if f.dry_run {
                let verb = if approve { "approve" } else { "deny" };
                if f.json {
                    return print_json(
                        &json!({ "dry_run": true, "action": verb, "id": id, "what": a.action }),
                    );
                }
                println!(
                    "{}",
                    t(
                        "approvals.dry_run",
                        &[("verb", verb), ("id", id), ("action", &a.action)]
                    )
                );
                return Ok(());
            }
            // `--yes` is the person at this computer saying so; it stands in for the second factor here.
            store
                .update(|b| {
                    let factor = f
                        .yes
                        .then_some(ozbox_core::permissions::SecondFactor::TypedConfirmation)
                        .or_else(|| {
                            (!a.needs_step_up)
                                .then_some(ozbox_core::permissions::SecondFactor::NoSignIn)
                        });
                    supervisor::decide_with(b, id, approve, who, factor, now_ms())
                })?
                .map_err(|e| Error::Config(e.to_string()))?;
            let state = if approve { "approved" } else { "denied" };
            if f.json {
                return print_json(&json!({ "id": id, "state": state }));
            }
            println!(
                "{}",
                t("approvals.decided", &[("id", id), ("state", state)])
            );
            Ok(())
        }
    }
}
