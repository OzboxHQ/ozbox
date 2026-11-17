//! `ozbox tools ...` and `ozbox profile ...`: the same plan-then-apply flow as the dashboard, against a box's own daemon.

use std::collections::BTreeMap;
use std::io::{BufRead, IsTerminal, Write};
use std::path::PathBuf;
use std::time::{Duration, Instant};

use ozbox_catalog::Catalog;
use ozbox_core::{BoxName, BoxRecord, BoxState, Provider};
use serde_json::{json, Value};

use crate::messages::t;
use crate::profiles::{self, Profile, ProfileBox, Store};
use crate::run::CliError;
use crate::serve::BoxAgent;

type Result<T> = std::result::Result<T, CliError>;

pub struct Flags {
    pub yes: bool,
    pub dry_run: bool,
    pub json: bool,
}

fn msg<T>(m: String) -> Result<T> {
    Err(CliError::Msg(m))
}

fn catalog() -> Result<Catalog> {
    ozbox_catalog::embedded().map_err(CliError::Msg)
}

fn running(p: &dyn Provider, name: &BoxName) -> Result<BoxRecord> {
    let rec = p
        .get(name)?
        .ok_or_else(|| ozbox_core::Error::NotFound(name.to_string()))?;
    if rec.state != BoxState::Running {
        return msg(format!(
            "{name} is {}; its tools can only be changed while it runs",
            rec.state
        ));
    }
    Ok(rec)
}

/// One call to the box's installer; an error answer becomes the CLI's error with the daemon's own message.
fn call(
    agent: &dyn BoxAgent,
    rec: &BoxRecord,
    method: &str,
    segs: &[&str],
    body: &Value,
) -> Result<Value> {
    let bytes = if body.is_null() {
        Vec::new()
    } else {
        serde_json::to_vec(body).unwrap_or_default()
    };
    let (status, v) = agent
        .tools(rec, method, segs, &bytes)
        .map_err(|e| CliError::Msg(e.to_string()))?;
    if (200..300).contains(&status) {
        Ok(v)
    } else {
        let m = v["message"]
            .as_str()
            .or(v["error"].as_str())
            .unwrap_or("the box refused the request");
        msg(m.to_string())
    }
}

fn pending_path() -> Option<PathBuf> {
    crate::config::Config::path().map(|p| p.with_file_name("pending-tools.json"))
}

fn read_pending() -> BTreeMap<String, Vec<String>> {
    pending_path()
        .and_then(|p| std::fs::read(p).ok())
        .and_then(|b| serde_json::from_slice(&b).ok())
        .unwrap_or_default()
}

fn write_pending(m: &BTreeMap<String, Vec<String>>) {
    if let Some(p) = pending_path() {
        if let Some(d) = p.parent() {
            let _ = std::fs::create_dir_all(d);
        }
        let _ = std::fs::write(p, serde_json::to_vec(m).unwrap_or_default());
    }
}

/// Remember tools to install once the box can be reached.
pub fn set_pending(box_name: &str, ids: &[String]) {
    let mut m = read_pending();
    m.insert(box_name.to_string(), ids.to_vec());
    write_pending(&m);
}

fn print_json(v: &Value) -> Result<()> {
    println!("{}", serde_json::to_string_pretty(v).unwrap_or_default());
    Ok(())
}

pub fn list(p: &dyn Provider, agent: &dyn BoxAgent, name: &BoxName, f: &Flags) -> Result<()> {
    let rec = running(p, name)?;
    let v = call(agent, &rec, "GET", &[], &Value::Null)?;
    if f.json {
        return print_json(&v);
    }
    let cat = catalog()?;
    let state: BTreeMap<&str, &Value> = v["tools"]
        .as_array()
        .map(|a| {
            a.iter()
                .filter_map(|t| Some((t["id"].as_str()?, t)))
                .collect()
        })
        .unwrap_or_default();
    for g in &cat.groups {
        println!("{}", g.name);
        for tool in cat.tools.iter().filter(|x| x.group == g.id) {
            let s = state.get(tool.id.as_str());
            let status = match s {
                Some(s) if s["installed"] == true => {
                    format!("installed {}", s["version"].as_str().unwrap_or(""))
                }
                _ if !tool.verified => "not available yet".to_string(),
                _ => "not installed".to_string(),
            };
            println!("  {:<22} {}", tool.id, status.trim());
        }
    }
    Ok(())
}

fn expand(ids: &[String]) -> Result<Vec<String>> {
    if ids.is_empty() {
        return msg(t("tools.need_ids", &[]));
    }
    catalog()?.expand(ids).map_err(CliError::Msg)
}

/// Whether a plan has anything to do.
fn has_steps(plan: &Value) -> bool {
    plan["steps"].as_array().is_some_and(|a| !a.is_empty())
}

fn show_plan(plan: &Value, box_name: &str) {
    println!(
        "{}",
        t(
            "tools.plan_head",
            &[
                ("box", box_name),
                (
                    "count",
                    &plan["steps"].as_array().map_or(0, Vec::len).to_string()
                ),
                ("size", &plan["total_size_mb"].to_string()),
            ]
        )
    );
    for tool in plan["tools"].as_array().into_iter().flatten() {
        let name = tool["name"].as_str().unwrap_or("");
        if tool["op"] == "remove" {
            println!("{}", t("tools.plan_tool_remove", &[("name", name)]));
        } else {
            let why = tool["reason"]
                .as_str()
                .and_then(|r| r.strip_prefix("required_by:"))
                .map(|b| format!(", needed by {b}"))
                .unwrap_or_default();
            println!(
                "{}",
                t(
                    "tools.plan_tool_install",
                    &[
                        ("name", name),
                        ("size", &tool["size_mb"].to_string()),
                        ("why", &why)
                    ]
                )
            );
        }
    }
    for (i, s) in plan["steps"].as_array().into_iter().flatten().enumerate() {
        let root = if s["privilege"] == "root" {
            t("tools.root_note", &[])
        } else {
            String::new()
        };
        println!(
            "{}",
            t(
                "tools.plan_step",
                &[
                    ("n", &(i + 1).to_string()),
                    ("title", s["title"].as_str().unwrap_or("")),
                    ("root", &root)
                ]
            )
        );
    }
    let list = |k: &str| -> String {
        plan[k]
            .as_array()
            .into_iter()
            .flatten()
            .filter_map(Value::as_str)
            .collect::<Vec<_>>()
            .join(", ")
    };
    if !list("already_installed").is_empty() {
        println!(
            "{}",
            t("tools.already", &[("ids", &list("already_installed"))])
        );
    }
    if !list("not_installed").is_empty() {
        println!(
            "{}",
            t("tools.not_installed", &[("ids", &list("not_installed"))])
        );
    }
}

fn confirm(box_name: &str, f: &Flags) -> Result<()> {
    if f.yes {
        return Ok(());
    }
    if !std::io::stdin().is_terminal() {
        return msg(t("tools.refuse_no_tty", &[("box", box_name)]));
    }
    let mut err = std::io::stderr();
    let _ = write!(err, "{}", t("tools.prompt", &[]));
    let _ = err.flush();
    let mut line = String::new();
    std::io::stdin()
        .lock()
        .read_line(&mut line)
        .map_err(|e| CliError::Core(e.into()))?;
    if matches!(line.trim().to_ascii_lowercase().as_str(), "y" | "yes") {
        Ok(())
    } else {
        msg(t("tools.aborted", &[]))
    }
}

/// Plan, show, confirm, apply, and follow the job to its end.
pub fn change(
    p: &dyn Provider,
    agent: &dyn BoxAgent,
    name: &BoxName,
    install: Vec<String>,
    remove: Vec<String>,
    f: &Flags,
    plan_only: bool,
) -> Result<()> {
    let rec = running(p, name)?;
    let sel = json!({ "install": install, "remove": remove });
    let plan = call(agent, &rec, "POST", &["plan"], &sel)?["plan"].clone();
    if f.json && (plan_only || f.dry_run) {
        return print_json(&json!({ "plan": plan, "applied": false }));
    }
    if !f.json {
        if !has_steps(&plan) {
            show_plan(&plan, name.as_str());
            println!("{}", t("tools.nothing_to_do", &[]));
            return Ok(());
        }
        show_plan(&plan, name.as_str());
    }
    if plan_only || f.dry_run {
        if !f.json && f.dry_run {
            println!("{}", t("tools.dry_run", &[]));
        }
        return Ok(());
    }
    if !has_steps(&plan) {
        return print_json(&json!({ "plan": plan, "applied": false }));
    }
    confirm(name.as_str(), f)?;
    let mut body = sel;
    body["plan_hash"] = plan["hash"].clone();
    let started = call(agent, &rec, "POST", &["apply"], &body)?;
    let Some(id) = started["job_id"].as_str().map(str::to_string) else {
        return Ok(());
    };
    if !f.json {
        println!("{}", t("tools.started", &[("id", &id)]));
    }
    let outcome = follow(agent, &rec, &id, f)?;
    if f.json {
        return print_json(&json!({ "plan": plan, "applied": true, "job": outcome }));
    }
    if outcome["job"]["state"] == "succeeded" {
        for tool in plan["tools"].as_array().into_iter().flatten() {
            if let Some(note) = tool["post_install"].as_str() {
                println!(
                    "{}",
                    t(
                        "tools.post_install",
                        &[
                            ("name", tool["name"].as_str().unwrap_or("")),
                            ("note", note)
                        ]
                    )
                );
            }
        }
        println!("{}", t("tools.job_ok", &[]));
        Ok(())
    } else {
        // One line per tool, so a tool that failed does not hide the ones that installed (or were not tried).
        let lines = outcome_lines(&outcome["job"]);
        if lines.is_empty() {
            return msg(t(
                "tools.job_failed",
                &[(
                    "error",
                    outcome["job"]["error"].as_str().unwrap_or("unknown"),
                )],
            ));
        }
        for l in &lines {
            println!("{l}");
        }
        let total = lines.len().to_string();
        let bad = outcome["job"]["outcomes"]
            .as_array()
            .map_or(0, |o| o.iter().filter(|x| x["state"] != "ok").count())
            .to_string();
        msg(t(
            "tools.job_partly_failed",
            &[("failed", bad.as_str()), ("total", total.as_str())],
        ))
    }
}

/// How each tool of a finished job ended, one line each. A status from an older daemon has no outcomes: no lines.
pub fn outcome_lines(job: &Value) -> Vec<String> {
    job["outcomes"]
        .as_array()
        .into_iter()
        .flatten()
        .map(|o| {
            let id = o["id"].as_str().unwrap_or("");
            let error = o["error"].as_str().unwrap_or("");
            match o["state"].as_str() {
                Some("ok") => t("tools.outcome_ok", &[("id", id)]),
                Some("skipped") => t("tools.outcome_skipped", &[("id", id), ("error", error)]),
                _ => t("tools.outcome_failed", &[("id", id), ("error", error)]),
            }
        })
        .collect()
}

fn follow(agent: &dyn BoxAgent, rec: &BoxRecord, id: &str, f: &Flags) -> Result<Value> {
    let start = Instant::now();
    let mut shown = 0usize;
    let poll = Duration::from_millis(if rec.provider == "fake" { 300 } else { 2000 });
    loop {
        let v = call(agent, rec, "GET", &["jobs", id], &Value::Null)?;
        if !f.json {
            for s in v["job"]["steps"].as_array().into_iter().flatten() {
                let idx = s["index"].as_u64().unwrap_or(0) as usize;
                if s["state"] != "pending" && idx >= shown {
                    let key = if s["state"] == "skipped" {
                        "tools.step_skipped_line"
                    } else {
                        "tools.step_line"
                    };
                    println!("{}", t(key, &[("line", s["title"].as_str().unwrap_or(""))]));
                    shown = idx + 1;
                }
            }
        }
        if matches!(v["job"]["state"].as_str(), Some("succeeded" | "failed")) {
            return Ok(v);
        }
        if start.elapsed() > Duration::from_secs(3 * 3600) {
            return msg(t("tools.job_timeout", &[("box", rec.spec.name.as_str())]));
        }
        std::thread::sleep(poll);
    }
}

pub fn jobs(p: &dyn Provider, agent: &dyn BoxAgent, name: &BoxName, f: &Flags) -> Result<()> {
    let rec = running(p, name)?;
    let v = call(agent, &rec, "GET", &["jobs"], &Value::Null)?;
    if f.json {
        return print_json(&v);
    }
    for j in v["jobs"].as_array().into_iter().flatten() {
        println!(
            "  {}  {}  {}",
            j["id"].as_str().unwrap_or(""),
            j["state"].as_str().unwrap_or(""),
            j["tools"]
                .as_array()
                .into_iter()
                .flatten()
                .filter_map(Value::as_str)
                .collect::<Vec<_>>()
                .join(", ")
        );
    }
    Ok(())
}

pub fn requests(p: &dyn Provider, agent: &dyn BoxAgent, name: &BoxName, f: &Flags) -> Result<()> {
    let rec = running(p, name)?;
    let v = call(agent, &rec, "GET", &["requests"], &Value::Null)?;
    if f.json {
        return print_json(&v);
    }
    let list = v["requests"].as_array().cloned().unwrap_or_default();
    if list.is_empty() {
        println!("{}", t("tools.no_requests", &[]));
    }
    for r in list {
        println!(
            "{}",
            t(
                "tools.request_line",
                &[
                    ("id", r["id"].as_str().unwrap_or("")),
                    ("tool", r["tool"].as_str().unwrap_or("")),
                    ("state", r["state"].as_str().unwrap_or("")),
                    ("by", r["requested_by"].as_str().unwrap_or("")),
                    ("reason", r["reason"].as_str().unwrap_or("")),
                ]
            )
        );
    }
    Ok(())
}

pub fn decide(
    p: &dyn Provider,
    agent: &dyn BoxAgent,
    name: &BoxName,
    id: &str,
    decision: &str,
    f: &Flags,
) -> Result<()> {
    let rec = running(p, name)?;
    let v = call(
        agent,
        &rec,
        "POST",
        &["requests", id, "decision"],
        &json!({ "decision": decision }),
    )?;
    if f.json {
        return print_json(&v);
    }
    println!(
        "{}",
        t(
            "tools.decided",
            &[
                ("id", id),
                ("state", v["request"]["state"].as_str().unwrap_or(""))
            ]
        )
    );
    Ok(())
}

/// Tools left for later at create time.
pub fn pending(name: &BoxName) -> Vec<String> {
    read_pending()
        .get(name.as_str())
        .cloned()
        .unwrap_or_default()
}

pub fn clear_pending(name: &BoxName) {
    let mut m = read_pending();
    if m.remove(name.as_str()).is_some() {
        write_pending(&m);
    }
}

/// Install what was chosen at create time (`--pending`).
pub fn install_pending(
    p: &dyn Provider,
    agent: &dyn BoxAgent,
    name: &BoxName,
    f: &Flags,
) -> Result<()> {
    let ids = pending(name);
    if ids.is_empty() {
        println!("{}", t("tools.pending_none", &[("box", name.as_str())]));
        return Ok(());
    }
    change(p, agent, name, ids, vec![], f, false)?;
    if !f.dry_run {
        clear_pending(name);
    }
    Ok(())
}

pub fn expand_ids(ids: &[String]) -> Result<Vec<String>> {
    expand(ids)
}

/// Like [`expand_ids`], but nothing named is fine.
pub fn expand_ids_or_empty(ids: &[String]) -> Result<Vec<String>> {
    if ids.is_empty() {
        return Ok(Vec::new());
    }
    expand(ids)
}

/// A box was just created with tools chosen. The demo provider installs them at once; a real box is not reachable for
/// a few minutes, so the choice is kept and `ozbox tools install <box> --pending` (or the dashboard) applies it.
pub fn after_create(
    p: &dyn Provider,
    simulated: bool,
    inputs: &crate::sshconfig::RouteInputs,
    name: &BoxName,
    ids: Vec<String>,
    yes: bool,
    json: bool,
) -> Result<()> {
    if simulated {
        let agent = crate::serve::agent_for(true, inputs.clone());
        let f = Flags {
            yes,
            dry_run: false,
            json,
        };
        return change(p, agent.as_ref(), name, ids, vec![], &f, false);
    }
    set_pending(name.as_str(), &ids);
    if !json {
        println!(
            "{}",
            t(
                "tools.pending_saved",
                &[("ids", &ids.join(", ")), ("box", name.as_str())]
            )
        );
    }
    Ok(())
}

/// A line-by-line checklist, one question per group: choose tools by number, `all`, or skip. Terminal only.
pub fn choose_interactively() -> Result<Vec<String>> {
    let cat = catalog()?;
    let mut chosen = Vec::new();
    let mut err = std::io::stderr();
    for g in &cat.groups {
        let tools: Vec<_> = cat
            .tools
            .iter()
            .filter(|x| {
                x.group == g.id
                    && x.verified
                    && x.verification != ozbox_catalog::Verification::ClientManaged
            })
            .collect();
        if tools.is_empty() {
            continue;
        }
        let _ = writeln!(err, "{}", g.name);
        for (i, tool) in tools.iter().enumerate() {
            let _ = writeln!(
                err,
                "{}",
                t(
                    "tools.pick_item",
                    &[
                        ("mark", if tool.default { "[x]" } else { "[ ]" }),
                        ("n", &(i + 1).to_string()),
                        ("name", &tool.name),
                        ("desc", &tool.description)
                    ]
                )
            );
        }
        let _ = write!(err, "{}", t("tools.pick_prompt", &[("group", &g.name)]));
        let _ = err.flush();
        let mut line = String::new();
        std::io::stdin()
            .lock()
            .read_line(&mut line)
            .map_err(|e| CliError::Core(e.into()))?;
        let line = line.trim().to_ascii_lowercase();
        if line.is_empty() {
            // Enter keeps what is ticked: the default tools (already in the image, so nothing to install).
            continue;
        }
        if line == "none" {
            continue;
        }
        if line == "all" {
            chosen.extend(tools.iter().map(|x| x.id.clone()));
            continue;
        }
        for n in line
            .split(',')
            .filter_map(|s| s.trim().parse::<usize>().ok())
        {
            if let Some(tool) = tools.get(n.wrapping_sub(1)) {
                chosen.push(tool.id.clone());
            }
        }
    }
    chosen.dedup();
    Ok(chosen)
}

// ---- profiles ----------------------------------------------------------------------------------------------------

fn store() -> Result<Store> {
    Store::default_dir()
        .map(Store::new)
        .ok_or_else(|| CliError::Msg("there is no home folder; set OZBOX_PROFILES".into()))
}

pub fn profile_load(name: &str) -> Result<Profile> {
    store()?.load(name, &catalog()?).map_err(CliError::Msg)
}

pub fn profile_save(
    p: &dyn Provider,
    agent: &dyn BoxAgent,
    box_name: &BoxName,
    name: &str,
    description: Option<String>,
    overwrite: bool,
    f: &Flags,
) -> Result<()> {
    let rec = running(p, box_name)?;
    let v = call(agent, &rec, "GET", &[], &Value::Null)?;
    let cat = catalog()?;
    let tools: Vec<String> = v["tools"]
        .as_array()
        .into_iter()
        .flatten()
        .filter(|t| t["installed"] == true)
        .filter_map(|t| t["id"].as_str())
        .filter(|id| cat.tool(id).is_some_and(|t| t.verified))
        .map(str::to_string)
        .collect();
    let settings = crate::settings::Settings::path()
        .and_then(|p| crate::settings::Settings::load_from(&p).ok())
        .unwrap_or_default();
    let profile = Profile {
        description,
        tools,
        defaults: ProfileBox {
            size: Some(rec.spec.size.to_string()),
            disk_gb: Some(rec.spec.work_disk_gb),
            auto_pause_minutes: Some(settings.defaults.auto_pause_minutes),
            always_on: Some(
                rec.spec.labels.get("ozbox-always-on").map(String::as_str) == Some("true"),
            ),
            labels: profiles::clean_labels(&rec.spec.labels),
        },
    };
    let path = store()?
        .save(name, &profile, &cat, overwrite)
        .map_err(CliError::Msg)?;
    if f.json {
        return print_json(
            &json!({ "name": name, "path": path.display().to_string(), "profile": profile }),
        );
    }
    println!(
        "{}",
        t(
            "profile.saved",
            &[("name", name), ("path", &path.display().to_string())]
        )
    );
    Ok(())
}

pub fn profile_list(f: &Flags) -> Result<()> {
    let items = store()?.list(&catalog()?);
    if f.json {
        let v: Vec<Value> = items
            .iter()
            .map(|(n, r)| match r {
                Ok(p) => json!({ "name": n, "description": p.description, "tools": p.tools, "box": p.defaults }),
                Err(e) => json!({ "name": n, "error": e }),
            })
            .collect();
        return print_json(&json!({ "profiles": v }));
    }
    if items.is_empty() {
        println!("{}", t("profile.none", &[]));
    }
    for (n, r) in items {
        match r {
            Ok(p) => println!(
                "{}",
                t(
                    "profile.line",
                    &[
                        ("name", &n),
                        ("tools", &p.tools.len().to_string()),
                        (
                            "desc",
                            &p.description.map(|d| format!(" - {d}")).unwrap_or_default()
                        ),
                    ]
                )
            ),
            Err(e) => println!("{}", t("profile.bad", &[("name", &n), ("error", &e)])),
        }
    }
    Ok(())
}

pub fn profile_show(name: &str, f: &Flags) -> Result<()> {
    let p = profile_load(name)?;
    if f.json {
        return print_json(&json!({ "name": name, "profile": p }));
    }
    print!("{}", toml::to_string_pretty(&p).unwrap_or_default());
    Ok(())
}

pub fn profile_delete(name: &str, f: &Flags) -> Result<()> {
    store()?.delete(name).map_err(CliError::Msg)?;
    if f.json {
        return print_json(&json!({ "deleted": name }));
    }
    println!("{}", t("profile.deleted", &[("name", name)]));
    Ok(())
}

#[cfg(test)]
mod tests {
    #[test]
    fn a_finished_job_says_how_each_tool_ended() {
        let job = serde_json::json!({ "state": "failed", "outcomes": [
            { "id": "packer", "state": "failed", "error": "Add the hashicorp package source: the signing key could not be read" },
            { "id": "codex", "state": "skipped", "error": "not tried, because node (which it needs) failed" },
            { "id": "ripgrep", "state": "ok" },
        ]});
        let lines = super::outcome_lines(&job);
        assert_eq!(lines.len(), 3);
        assert!(lines[0].contains("packer: failed: Add the hashicorp"));
        assert!(lines[1].contains("codex: not tried"));
        assert_eq!(lines[2].trim(), "ripgrep: done");
        // an older daemon's status has no outcomes
        assert!(super::outcome_lines(&serde_json::json!({ "state": "failed" })).is_empty());
        for k in ["tools.step_skipped_line", "tools.job_partly_failed"] {
            assert!(crate::messages::keys().contains(&k), "{k}");
        }
    }

    #[test]
    fn every_message_key_used_here_exists() {
        let src = include_str!("tools_cli.rs");
        let keys = crate::messages::keys();
        let mut rest = src;
        while let Some(i) = rest.find("t(\"") {
            let before = rest[..i].chars().last().unwrap_or(' ');
            let after = &rest[i + 3..];
            if !(before.is_alphanumeric() || before == '_') {
                let key = after.split('"').next().unwrap_or("");
                assert!(keys.contains(&key), "missing message {key}");
            }
            rest = after;
        }
    }
}
