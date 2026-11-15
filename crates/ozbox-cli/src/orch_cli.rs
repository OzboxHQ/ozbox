//! `ozbox orch ...`: the command line for orchestrations. It reads and changes the same task store `ozbox serve`
//! supervises (`ozbox_core::orch`), and runs the same tool functions the MCP server and the dashboard run
//! (`crate::orch_tools`), so what one shows the other shows. Starting a feature only records it; `ozbox serve` makes the
//! worker's task when the box is running. The `--json` shapes are the ones `/v1/orchestrations` answers with.
//!
//! The three box tools (`box_clone`, `box_create`, `box_pause`) are `ozbox clone`, `ozbox create` and `ozbox pause`, which
//! already plan, confirm and apply. An agent's own use of them goes through the server, inside the limits.

use std::sync::Arc;

use ozbox_core::orch::{effective, FeatureReq, MergeApproval};
use ozbox_core::orch_rules::{parse_rules, Overrides};
use ozbox_core::run::{RunCaps, TaskStore};
use ozbox_core::{Error, Result};
use serde_json::{json, Value};

use crate::cli::OrchCommand;
use crate::messages::t;
use crate::orch_tools::{orch_json, orch_summary, BoxOps, Role, Session, ToolError, Tools};
use crate::runs_cli::Flags;

/// The fleet is not reachable from the command line's tools (the box commands do that): no boxes are listed.
struct NoFleet;

impl BoxOps for NoFleet {
    fn list(&self) -> std::result::Result<Vec<Value>, String> {
        Err("the boxes are not listed from here".into())
    }
    fn plan(&self, _: Value) -> std::result::Result<Value, String> {
        Err("use `ozbox clone`, `ozbox create` or `ozbox pause`".into())
    }
    fn apply(&self, _: &str, _: &Value) -> std::result::Result<Value, String> {
        Err("use `ozbox clone`, `ozbox create` or `ozbox pause`".into())
    }
}

fn store() -> Result<TaskStore> {
    crate::runs_cli::store_path()
        .map(TaskStore::new)
        .ok_or_else(|| Error::Config(t("orch.no_store", &[])))
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

fn print_json(v: &Value) -> Result<()> {
    println!("{}", serde_json::to_string_pretty(v)?);
    Ok(())
}

fn refused(e: impl std::fmt::Display) -> Error {
    Error::Config(t("orch.refused", &[("why", &e.to_string())]))
}

fn tool(name: &str, args: &Value) -> Result<Value> {
    let tools = Tools::new(store()?, Arc::new(NoFleet));
    let s = Session {
        person: "owner".into(),
        role: Role::Person,
    };
    tools
        .call(&s, name, args, now_ms())
        .map_err(|e: ToolError| refused(e.message()))
}

fn rules_from(path: &std::path::Path) -> Result<Overrides> {
    let text = std::fs::read_to_string(path).map_err(|e| {
        Error::Config(t(
            "orch.rules_unreadable",
            &[("why", &e.kind().to_string())],
        ))
    })?;
    parse_rules(&text).map_err(|why| Error::Config(t("orch.bad_rules", &[("why", &why)])))
}

pub fn run(cmd: &OrchCommand, f: &Flags) -> Result<()> {
    let who = "owner";
    let now = now_ms();
    match cmd {
        OrchCommand::List => {
            let book = store()?.load()?;
            let items: Vec<Value> = book
                .orchestrations
                .iter()
                .rev()
                .map(|o| orch_summary(&book, o, now))
                .collect();
            if f.json {
                return print_json(&json!({ "items": items }));
            }
            if items.is_empty() {
                println!("{}", t("orch.none", &[]));
            }
            for i in &items {
                println!(
                    "{}",
                    t(
                        "orch.row",
                        &[
                            ("id", i["id"].as_str().unwrap_or("")),
                            ("state", i["state"].as_str().unwrap_or("")),
                            ("features", &i["features"].to_string()),
                            ("spend", &money(i["spent_cents"].as_u64().unwrap_or(0))),
                            (
                                "cap",
                                &i["cap_cents"].as_u64().map_or("no cap".into(), money)
                            ),
                            ("box", i["conductor_box"].as_str().unwrap_or("")),
                            (
                                "note",
                                &if i["needs_you"] == true {
                                    t("orch.note_needs_you", &[])
                                } else {
                                    String::new()
                                }
                            ),
                            ("goal", i["goal"].as_str().unwrap_or("")),
                        ],
                    )
                );
            }
            Ok(())
        }
        OrchCommand::Show { id } => {
            let book = store()?.load()?;
            let o = book
                .orchestration(id)
                .ok_or_else(|| Error::Config(t("orch.unknown", &[("id", id)])))?;
            let j = orch_json(&book, o, now);
            if f.json {
                return print_json(&j);
            }
            println!(
                "{}",
                t(
                    "orch.head",
                    &[("id", id), ("state", j["state"].as_str().unwrap_or(""))]
                )
            );
            let line =
                |l: &str, v: &str| println!("{}", t("orch.line", &[("label", l), ("value", v)]));
            line("goal", &o.goal);
            line("conductor box", &o.conductor_box);
            line(
                "spend",
                &format!(
                    "{} of {}",
                    money(j["spent_cents"].as_u64().unwrap_or(0)),
                    j["cap_cents"].as_u64().map_or("no cap".into(), money)
                ),
            );
            if o.features.is_empty() {
                println!("{}", t("orch.no_features", &[]));
            }
            for x in &j["features"].as_array().cloned().unwrap_or_default() {
                println!(
                    "{}",
                    t(
                        "orch.feature_row",
                        &[
                            ("id", x["id"].as_str().unwrap_or("")),
                            ("state", x["state"].as_str().unwrap_or("")),
                            ("title", x["title"].as_str().unwrap_or("")),
                            ("box", x["box"].as_str().unwrap_or("")),
                            ("branch", x["branch"].as_str().unwrap_or("")),
                            ("spend", &money(x["spent_cents"].as_u64().unwrap_or(0))),
                        ],
                    )
                );
            }
            Ok(())
        }
        OrchCommand::Start {
            goal,
            box_name,
            rules_file,
            max_workers,
            max_sub_agents,
            max_spend,
            conduct,
            prompt,
        } => {
            let rules = match rules_file {
                Some(p) => rules_from(p)?,
                None => Overrides::default(),
            };
            let ask = Overrides {
                max_workers: *max_workers,
                max_sub_agents: *max_sub_agents,
                spend_cap_cents: max_spend.map(|d| (d * 100.0).round().max(1.0) as u64),
                ..Default::default()
            };
            let st = store()?;
            if f.dry_run {
                let p = effective(&st.load()?.orch_settings, &[&rules, &ask]);
                println!(
                    "{}",
                    t(
                        "orch.dry_run_start",
                        &[
                            ("box", box_name.as_str()),
                            ("workers", &p.max_workers.to_string()),
                            ("subs", &p.max_sub_agents.to_string()),
                            ("cap", &p.spend_cap_cents.map_or("no cap".into(), money)),
                        ],
                    )
                );
                return Ok(());
            }
            let (id, task) = st
                .update(|b| {
                    let id =
                        b.start_orchestration(goal, who, box_name.as_str(), &[&rules, &ask], now)?;
                    let task = if *conduct {
                        Some(b.start_conductor(&id, prompt.as_deref().unwrap_or(""), now)?)
                    } else {
                        None
                    };
                    Ok::<_, ozbox_core::orch::OrchError>((id, task))
                })?
                .map_err(refused)?;
            if f.json {
                return print_json(&json!({ "id": id, "conductor_task": task }));
            }
            let mut m = t("orch.started", &[("id", &id), ("box", box_name.as_str())]);
            if let Some(tk) = task {
                m.push_str(&t("orch.started_conductor", &[("task", &tk)]));
            }
            println!("{m}");
            Ok(())
        }
        OrchCommand::Rules { file } => {
            let o = rules_from(file)?;
            let p = effective(&store()?.load()?.orch_settings, &[&o]);
            if f.json {
                return print_json(&serde_json::to_value(&p)?);
            }
            println!("{}", t("orch.rules_ok", &[]));
            print_json(&serde_json::to_value(&p)?)?;
            for n in &p.notes {
                println!("{}", t("orch.rules_note", &[("note", n)]));
            }
            Ok(())
        }
        OrchCommand::Settings {
            max_workers,
            max_sub_agents,
            max_spend,
            merge_approval,
        } => {
            let st = store()?;
            let change = max_workers.is_some()
                || max_sub_agents.is_some()
                || max_spend.is_some()
                || merge_approval.is_some();
            if change && f.dry_run {
                println!(
                    "{}",
                    t(
                        "orch.dry_run",
                        &[("action", "change your limits for orchestrations")]
                    )
                );
                return Ok(());
            }
            let r = st.update(|b| {
                if change {
                    let mut s = b.orch_settings.clone();
                    if let Some(n) = max_workers {
                        s.max_workers = *n;
                    }
                    if let Some(n) = max_sub_agents {
                        s.max_sub_agents = *n;
                    }
                    if let Some(d) = max_spend {
                        s.spend_cap_cents = Some((d * 100.0).round().max(0.0) as u64);
                    }
                    if let Some(m) = merge_approval {
                        s.merge_approval = match m.as_str() {
                            "none" => MergeApproval::None,
                            "conductor" => MergeApproval::Conductor,
                            "person" => MergeApproval::Person,
                            _ => {
                                return Err(
                                    "merge approval: use none, conductor or person".to_string()
                                )
                            }
                        };
                    }
                    s.validate()?;
                    b.orch_settings = s;
                    b.record(now, who, "orchestration.settings_changed", None, "");
                }
                Ok(b.orch_settings.clone())
            })?;
            let s = r.map_err(refused)?;
            if f.json {
                return print_json(&serde_json::to_value(&s)?);
            }
            println!(
                "{}",
                t(
                    "orch.settings",
                    &[
                        ("workers", &s.max_workers.to_string()),
                        ("subs", &s.max_sub_agents.to_string()),
                        ("cap", &s.spend_cap_cents.map_or("no cap".into(), money)),
                        (
                            "approval",
                            serde_json::to_value(s.merge_approval)?
                                .as_str()
                                .unwrap_or("")
                        ),
                    ],
                )
            );
            if change {
                println!("{}", t("orch.settings_saved", &[]));
            }
            Ok(())
        }
        OrchCommand::Feature {
            id,
            title,
            brief,
            box_name,
            claim,
            contract,
            engine,
            sub_agents,
            max_spend,
            branch,
            repo,
        } => {
            let req = FeatureReq {
                title: title.clone(),
                brief: brief.clone(),
                box_name: box_name.as_ref().map(|b| b.as_str().to_string()),
                repo: repo.clone(),
                branch: branch.clone(),
                claims: claim.clone(),
                contracts: contract.clone(),
                engine: engine.clone(),
                sub_agents: *sub_agents,
                caps: RunCaps {
                    max_spend_cents: max_spend.map(|d| (d * 100.0).round().max(1.0) as u64),
                    ..Default::default()
                },
                ..Default::default()
            };
            if f.dry_run {
                println!(
                    "{}",
                    t(
                        "orch.dry_run",
                        &[("action", &format!("add the feature \"{title}\" to {id}"))]
                    )
                );
                return Ok(());
            }
            let r = store()?
                .update(|b| {
                    let o = b
                        .orchestration_mut(id)
                        .ok_or(ozbox_core::orch::OrchError::NoOrchestration)?;
                    let fid = o.add_feature(&req, now)?;
                    let x = o
                        .feature(&fid)
                        .cloned()
                        .ok_or(ozbox_core::orch::OrchError::NoFeature)?;
                    b.record(
                        now,
                        who,
                        "orchestration.feature_added",
                        None,
                        &format!("{id}/{fid}"),
                    );
                    Ok::<_, ozbox_core::orch::OrchError>(x)
                })?
                .map_err(refused)?;
            if f.json {
                return print_json(
                    &json!({ "feature": r.id, "box": r.box_name, "branch": r.branch, "after": r.after }),
                );
            }
            let mut m = t(
                "orch.feature_added",
                &[
                    ("feature", &r.id),
                    ("box", &r.box_name),
                    ("branch", &r.branch),
                ],
            );
            if !r.after.is_empty() {
                m.push_str(&t(
                    "orch.feature_sequenced",
                    &[("after", &r.after.join(", "))],
                ));
            }
            println!("{m}");
            Ok(())
        }
        OrchCommand::Worker { verb, id, feature } => {
            if f.dry_run {
                println!(
                    "{}",
                    t(
                        "orch.dry_run",
                        &[("action", &format!("{verb} {feature} of {id}"))]
                    )
                );
                return Ok(());
            }
            let st = store()?;
            let v = verb.as_str();
            let r = st.update(|b| match v {
                "pause" | "stop" => b
                    .halt_feature(id, feature, v == "pause", now)
                    .map(|()| v.to_string()),
                "resume" => b
                    .resume_feature(id, feature, now)
                    .map(|_| "starting".to_string()),
                _ => Err(ozbox_core::orch::OrchError::Invalid(
                    "use pause, resume or stop".into(),
                )),
            })?;
            let state = r.map_err(refused)?;
            if f.json {
                return print_json(&json!({ "feature": feature, "state": state }));
            }
            println!(
                "{}",
                t(
                    "orch.feature_state",
                    &[("feature", feature), ("state", &state)]
                )
            );
            Ok(())
        }
        OrchCommand::Pause { id } | OrchCommand::Resume { id } | OrchCommand::Stop { id } => {
            let (key, verb) = match cmd {
                OrchCommand::Pause { .. } => ("orch.paused", 0),
                OrchCommand::Resume { .. } => ("orch.resumed", 1),
                _ => ("orch.stopped", 2),
            };
            if f.dry_run {
                println!(
                    "{}",
                    t("orch.dry_run", &[("action", &format!("change {id}"))])
                );
                return Ok(());
            }
            store()?
                .update(|b| match verb {
                    0 => b.halt_orchestration(id, false, who, now),
                    1 => b.resume_orchestration(id, who, now),
                    _ => b.halt_orchestration(id, true, who, now),
                })?
                .map_err(refused)?;
            if f.json {
                return print_json(&json!({ "id": id, "ok": true }));
            }
            println!("{}", t(key, &[("id", id)]));
            Ok(())
        }
        OrchCommand::Messages { id, since } => {
            let book = store()?.load()?;
            let o = book
                .orchestration(id)
                .ok_or_else(|| Error::Config(t("orch.unknown", &[("id", id)])))?;
            let msgs: Vec<&_> = o.messages.iter().filter(|m| m.seq > *since).collect();
            if f.json {
                return print_json(
                    &json!({ "messages": msgs, "open_questions": o.open_questions() }),
                );
            }
            if msgs.is_empty() {
                println!("{}", t("orch.messages_none", &[]));
            }
            for m in msgs {
                let open = !m.resolved
                    && matches!(
                        m.kind,
                        ozbox_core::orch::MsgKind::Question | ozbox_core::orch::MsgKind::Blocked
                    );
                println!(
                    "{}",
                    t(
                        "orch.message_row",
                        &[
                            ("seq", &m.seq.to_string()),
                            ("from", &m.from),
                            ("to", &m.to),
                            ("kind", serde_json::to_value(m.kind)?.as_str().unwrap_or("")),
                            (
                                "flag",
                                &if open {
                                    t("orch.flag_open", &[])
                                } else {
                                    String::new()
                                }
                            ),
                            ("text", &m.text),
                        ],
                    )
                );
            }
            Ok(())
        }
        OrchCommand::Answer { id, question, text } => {
            if f.dry_run {
                println!(
                    "{}",
                    t(
                        "orch.dry_run",
                        &[("action", &format!("answer question {question}"))]
                    )
                );
                return Ok(());
            }
            let q = *question;
            store()?
                .update(|b| {
                    let o = b
                        .orchestration_mut(id)
                        .ok_or(ozbox_core::orch::OrchError::NoOrchestration)?;
                    o.answer(now, q, true, text)?;
                    b.record(now, who, "orchestration.answered", None, id);
                    Ok::<_, ozbox_core::orch::OrchError>(())
                })?
                .map_err(refused)?;
            if f.json {
                return print_json(&json!({ "answered": q }));
            }
            println!("{}", t("orch.answered", &[("question", &q.to_string())]));
            Ok(())
        }
        OrchCommand::Message { id, feature, text } => {
            if f.dry_run {
                println!(
                    "{}",
                    t(
                        "orch.dry_run",
                        &[("action", &format!("send {feature} a message"))]
                    )
                );
                return Ok(());
            }
            let seq = store()?
                .update(|b| {
                    let o = b
                        .orchestration_mut(id)
                        .ok_or(ozbox_core::orch::OrchError::NoOrchestration)?;
                    let s = o.post(
                        now,
                        "person",
                        &format!("feature:{feature}"),
                        ozbox_core::orch::MsgKind::Instruction,
                        text,
                        None,
                        false,
                    )?;
                    if let Some(x) = o.feature_mut(feature) {
                        x.resume_pending = true;
                    }
                    Ok::<_, ozbox_core::orch::OrchError>(s)
                })?
                .map_err(refused)?;
            if f.json {
                return print_json(&json!({ "message": seq }));
            }
            println!("{}", t("orch.sent", &[("message", &seq.to_string())]));
            Ok(())
        }
        OrchCommand::Claims {
            id,
            feature,
            declare,
            check,
        } => {
            if !declare.is_empty() {
                if f.dry_run {
                    println!(
                        "{}",
                        t(
                            "orch.dry_run",
                            &[("action", &format!("declare claims for {feature}"))]
                        )
                    );
                    return Ok(());
                }
                let v = tool(
                    "claims_declare",
                    &json!({ "orchestration": id, "feature": feature, "claims": declare }),
                )?;
                if f.json {
                    return print_json(&v);
                }
                println!(
                    "{}",
                    t(
                        "orch.claims_set",
                        &[
                            ("feature", feature),
                            ("result", v["result"].as_str().unwrap_or(""))
                        ]
                    )
                );
            }
            if !check.is_empty() {
                let v = tool(
                    "claims_check",
                    &json!({ "orchestration": id, "feature": feature, "paths": check }),
                )?;
                if f.json {
                    return print_json(&v);
                }
                for p in v["paths"].as_array().cloned().unwrap_or_default() {
                    let verdict = if p["allowed"] == true {
                        "yours".to_string()
                    } else {
                        p["why"].as_str().unwrap_or("not allowed").to_string()
                    };
                    println!(
                        "{}",
                        t(
                            "orch.claim_row",
                            &[
                                ("path", p["path"].as_str().unwrap_or("")),
                                ("verdict", &verdict)
                            ]
                        )
                    );
                }
            }
            Ok(())
        }
        OrchCommand::Contract {
            id,
            name,
            kind,
            body_file,
            paths,
        } => {
            let (Some(name), Some(file)) = (name, body_file) else {
                let v = tool("contract_read", &json!({ "orchestration": id }))?;
                return print_json(&v);
            };
            if f.dry_run {
                println!(
                    "{}",
                    t(
                        "orch.dry_run",
                        &[("action", &format!("publish the contract {name}"))]
                    )
                );
                return Ok(());
            }
            let body = std::fs::read_to_string(file).map_err(|e| {
                Error::Config(t(
                    "orch.rules_unreadable",
                    &[("why", &e.kind().to_string())],
                ))
            })?;
            let v = tool(
                "contract_publish",
                &json!({ "orchestration": id, "name": name, "kind": kind, "body": body, "paths": paths }),
            )?;
            if f.json {
                return print_json(&v);
            }
            println!(
                "{}",
                t(
                    "orch.contract_set",
                    &[
                        ("id", v["id"].as_str().unwrap_or("")),
                        ("version", &v["version"].to_string())
                    ]
                )
            );
            Ok(())
        }
        OrchCommand::Merge { id, feature } => {
            let v = match feature {
                Some(fe) => {
                    if f.dry_run {
                        println!(
                            "{}",
                            t(
                                "orch.dry_run",
                                &[("action", &format!("queue {fe} for the merge"))]
                            )
                        );
                        return Ok(());
                    }
                    let v = tool(
                        "merge_queue",
                        &json!({ "orchestration": id, "feature": fe }),
                    )?;
                    if !f.json {
                        println!(
                            "{}",
                            t(
                                "orch.queued",
                                &[("feature", fe), ("position", &v["position"].to_string())]
                            )
                        );
                        return Ok(());
                    }
                    v
                }
                None => tool("merge_status", &json!({ "orchestration": id }))?,
            };
            if f.json {
                return print_json(&v);
            }
            let q = v["queue"].as_array().cloned().unwrap_or_default();
            if q.is_empty() {
                println!("{}", t("orch.queue_empty", &[]));
            }
            for e in q {
                println!(
                    "{}",
                    t(
                        "orch.queue_row",
                        &[
                            ("feature", e["feature_id"].as_str().unwrap_or("")),
                            ("state", e["state"].as_str().unwrap_or("")),
                            ("detail", e["detail"].as_str().unwrap_or("")),
                        ],
                    )
                );
            }
            Ok(())
        }
        OrchCommand::Budget { id, add } => {
            if let Some(usd) = add {
                if f.dry_run {
                    println!(
                        "{}",
                        t(
                            "orch.dry_run",
                            &[("action", &format!("add ${usd:.2} to the cap of {id}"))]
                        )
                    );
                    return Ok(());
                }
                let cents = (usd * 100.0).round().max(1.0) as u64;
                let cap = store()?
                    .update(|b| b.add_orch_budget(id, cents, who, now))?
                    .map_err(refused)?;
                if f.json {
                    return print_json(&json!({ "id": id, "cap_cents": cap }));
                }
                println!("{}", t("orch.budget_added", &[("cap", &money(cap))]));
                return Ok(());
            }
            let v = tool("budget_status", &json!({ "orchestration": id }))?;
            if f.json {
                return print_json(&v);
            }
            println!(
                "{}",
                t(
                    "orch.budget",
                    &[
                        ("spend", &money(v["spent_cents"].as_u64().unwrap_or(0))),
                        (
                            "cap",
                            &v["cap_cents"].as_u64().map_or("no cap".into(), money)
                        ),
                    ],
                )
            );
            Ok(())
        }
        OrchCommand::McpConfig => {
            let cfg = json!({ "mcpServers": { "ozbox": {
                "type": "http",
                "url": "${OZBOX_MCP_URL}",
                "headers": { "Authorization": "Bearer ${OZBOX_MCP_TOKEN}" },
            } } });
            if f.json {
                return print_json(&cfg);
            }
            println!("{}", t("orch.mcp_config", &[]));
            print_json(&cfg)
        }
    }
}
