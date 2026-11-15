//! `ozbox cost bill|reconcile|orphans`: the same reads and the same plan-then-apply as the Bill page.
//!
//! Everything here reads. The one change, `orphans --delete`, shows its plan, stops there under `--dry-run`, and needs
//! the words the plan names typed (or given with `--confirm` where there is no terminal): `--yes` alone does not delete
//! anything, because a deleted disk cannot be brought back.

use std::io::{BufRead, IsTerminal, Write};
use std::sync::Arc;

use ozbox_core::SystemRunner;
use serde_json::json;

use crate::bill::{self, BillSource};
use crate::cli::{CostCommand, ProviderKind};
use crate::cost_demo;
use crate::messages::t;
use crate::orphans::{self, OrphanSource};
use crate::pricing::PriceCache;
use crate::run::CliError;
use crate::settings::Settings;
use crate::sshconfig::RouteInputs;
use crate::state::ServerState;

type Result<T> = std::result::Result<T, CliError>;

pub struct Flags {
    pub dry_run: bool,
    pub json: bool,
}

fn msg<T>(m: String) -> Result<T> {
    Err(CliError::Msg(m))
}

fn print_json(v: &serde_json::Value) -> Result<()> {
    println!("{}", serde_json::to_string_pretty(v).unwrap_or_default());
    Ok(())
}

fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

fn demo_boxes() -> Vec<String> {
    vec!["alpha".into(), "beta".into()]
}

fn bill_source(kind: ProviderKind, inputs: &RouteInputs) -> Arc<dyn BillSource> {
    match kind {
        ProviderKind::Aws => Arc::new(bill::AwsBill {
            runner: Arc::new(SystemRunner),
            profile: inputs.aws_profile.clone(),
        }),
        ProviderKind::Fake => Arc::new(cost_demo::DemoBill {
            boxes: demo_boxes(),
        }),
        ProviderKind::Hcloud => Arc::new(bill::NoBill("hcloud".into())),
        ProviderKind::Plugin => Arc::new(bill::NoBill("plugin".into())),
    }
}

fn orphan_source(kind: ProviderKind, inputs: &RouteInputs) -> Arc<dyn OrphanSource> {
    match kind {
        ProviderKind::Aws => Arc::new(orphans::AwsOrphans {
            runner: Arc::new(SystemRunner),
            profile: inputs.aws_profile.clone(),
        }),
        ProviderKind::Fake => Arc::new(cost_demo::DemoOrphans::default()),
        ProviderKind::Hcloud | ProviderKind::Plugin => Arc::new(orphans::NoOrphans),
    }
}

/// A problem with the bill, printed the way the mode asks for, and returned as the failure.
fn problem<T>(e: &bill::BillError, f: &Flags) -> Result<T> {
    if f.json {
        let _ = print_json(&json!({ "ok": false, "problem": e.problem, "message": e.message }));
    }
    msg(e.message.clone())
}

pub fn run(cmd: &CostCommand, kind: ProviderKind, inputs: &RouteInputs, f: &Flags) -> Result<()> {
    match cmd {
        CostCommand::Bill => bill_cmd(kind, inputs, f),
        CostCommand::Reconcile => reconcile_cmd(kind, inputs, f),
        CostCommand::Orphans {
            delete,
            confirm,
            regions,
        } => orphans_cmd(kind, inputs, delete, confirm.as_deref(), regions, f),
    }
}

fn dry_read(kind: ProviderKind, inputs: &RouteInputs, f: &Flags) -> Result<bool> {
    // Only a real cloud is read over the network; the demo and a provider with no bill answer without one.
    if !f.dry_run || kind != ProviderKind::Aws {
        return Ok(false);
    }
    let calls = bill::AwsBill {
        runner: Arc::new(SystemRunner),
        profile: inputs.aws_profile.clone(),
    }
    .planned_calls(now_ms());
    if f.json {
        print_json(&json!({ "dry_run": true, "reads": calls }))?;
    } else {
        println!("{}", t("cost.cli.dry_read", &[]));
        for c in &calls {
            println!("  {c}");
        }
    }
    Ok(true)
}

fn bill_cmd(kind: ProviderKind, inputs: &RouteInputs, f: &Flags) -> Result<()> {
    if dry_read(kind, inputs, f)? {
        return Ok(());
    }
    let now = now_ms();
    let report = match bill_source(kind, inputs).fetch(now) {
        Ok(r) => r,
        Err(e) => return problem(&e, f),
    };
    let m = bill::month_summary(&report, now);
    if f.json {
        return print_json(&json!({
            "ok": true,
            "provider": report.provider,
            "source": report.source,
            "month": m.month,
            "currency": m.currency,
            "through": m.through,
            "total": m.total,
            "boxes": m.boxes.iter().map(|(b, r)| json!({ "box": b, "real": r })).collect::<Vec<_>>(),
            "services": m.services,
            "lag_hours": 24,
        }));
    }
    let Some(through) = &m.through else {
        return msg(t(
            "cost.cli.bill_none",
            &[("why", &t("cost.cli.bill_nothing_yet", &[]))],
        ));
    };
    println!(
        "{}",
        t(
            "cost.cli.bill_total",
            &[
                ("month", &m.month),
                ("real", &format!("{:.2}", m.total)),
                ("currency", &m.currency),
                ("through", through)
            ],
        )
    );
    for (b, r) in &m.boxes {
        let name = b.clone().unwrap_or_else(|| t("cost.untagged_name", &[]));
        println!(
            "{}",
            t(
                "cost.cli.bill_row",
                &[
                    ("box", &name),
                    ("real", &format!("{r:.2}")),
                    ("currency", &m.currency)
                ]
            )
        );
    }
    for s in &m.services {
        println!(
            "{}",
            t(
                "cost.cli.service_row",
                &[
                    ("service", &s.service),
                    ("real", &format!("{:.2}", s.real)),
                    ("currency", &m.currency)
                ]
            )
        );
    }
    println!("{}", t("cost.cli.bill_lag", &[]));
    Ok(())
}

fn settings() -> Settings {
    Settings::path()
        .and_then(|p| Settings::load_from(&p).ok())
        .unwrap_or_default()
}

fn beside(name: &str) -> Option<std::path::PathBuf> {
    Settings::path().map(|p| p.with_file_name(name))
}

fn reconcile_cmd(kind: ProviderKind, inputs: &RouteInputs, f: &Flags) -> Result<()> {
    if dry_read(kind, inputs, f)? {
        return Ok(());
    }
    let now = now_ms();
    let report = match bill_source(kind, inputs).fetch(now) {
        Ok(r) => r,
        Err(e) => return problem(&e, f),
    };
    let days = if kind == ProviderKind::Fake {
        cost_demo::fixture(now, &demo_boxes()).1
    } else {
        beside("state.json")
            .map(|p| ServerState::load(&p).ledger.days)
            .unwrap_or_default()
    };
    if days.is_empty() {
        return msg(t("cost.cli.no_ledger", &[]));
    }
    let settings = settings();
    let book = beside("prices.json").and_then(|p| PriceCache::load(&p).book);
    let uncertain = book.as_ref().is_none_or(|b| b.is_stale(now))
        || !settings.budget.size_prices_usd.is_empty();
    let r = bill::reconcile(&days, &report, now, bill::tuning(&settings, uncertain));
    if f.json {
        return print_json(&json!({
            "ok": true,
            "drift_threshold": { "percent": settings.budget.drift_alert_pct, "min": settings.budget.drift_alert_min_usd },
            "reconciliation": r,
        }));
    }
    println!(
        "{}",
        t(
            "cost.cli.reconcile_total",
            &[
                ("month", &r.month),
                ("real", &format!("{:.2}", r.month_real)),
                ("estimate", &format!("{:.2}", r.month_estimate)),
                ("currency", &r.currency),
            ],
        )
    );
    if r.drift.is_empty() {
        println!(
            "{}",
            t(
                "cost.cli.no_drift",
                &[
                    ("pct", &format!("{}", settings.budget.drift_alert_pct)),
                    (
                        "min",
                        &format!("{:.2}", settings.budget.drift_alert_min_usd)
                    ),
                    ("currency", &r.currency),
                ],
            )
        );
    }
    for d in &r.drift {
        let who = d
            .box_name
            .clone()
            .unwrap_or_else(|| t("cost.untagged_name", &[]));
        let cause = d
            .causes
            .first()
            .map(|c| {
                t(
                    &format!("cost.cause.{}", c.kind),
                    &[("detail", c.detail.as_deref().unwrap_or(""))],
                )
            })
            .unwrap_or_else(|| t("cost.cause.unknown", &[]));
        println!(
            "{}",
            t(
                "cost.cli.drift_row",
                &[
                    ("date", &d.date),
                    ("box", &who),
                    ("real", &format!("{:.2}", d.real)),
                    ("estimate", &format!("{:.2}", d.estimate)),
                    ("cause", &cause),
                ],
            )
        );
    }
    Ok(())
}

fn read_line() -> Result<String> {
    let mut line = String::new();
    std::io::stdin()
        .lock()
        .read_line(&mut line)
        .map_err(|e| CliError::Core(e.into()))?;
    Ok(line.trim().to_string())
}

fn orphans_cmd(
    kind: ProviderKind,
    inputs: &RouteInputs,
    delete: &[String],
    confirm: Option<&str>,
    regions: &[String],
    f: &Flags,
) -> Result<()> {
    if kind == ProviderKind::Hcloud {
        return msg(t("cost.cli.orphans_unsupported", &[]));
    }
    let mut regions: Vec<String> = regions.to_vec();
    regions.extend(inputs.aws_region.clone());
    regions.sort();
    regions.dedup();
    if kind == ProviderKind::Aws && regions.is_empty() {
        return msg(t("cost.cli.need_region", &[]));
    }
    let now = now_ms();
    let book = beside("prices.json").and_then(|p| PriceCache::load(&p).book);
    let src = orphan_source(kind, inputs);
    if f.dry_run && kind == ProviderKind::Aws {
        let lines: Vec<String> = regions
            .iter()
            .flat_map(|r| {
                [
                    "describe-instances",
                    "describe-volumes",
                    "describe-snapshots",
                    "describe-images",
                ]
                .map(|v| format!("aws ec2 {v} --region {r} --output json"))
            })
            .collect();
        if f.json {
            return print_json(&json!({ "dry_run": true, "reads": lines }));
        }
        println!("{}", t("cost.cli.dry_read", &[]));
        for l in lines {
            println!("  {l}");
        }
        return Ok(());
    }
    let scan = src.scan(&regions, book.as_ref(), now);
    if let Some(e) = &scan.error {
        if scan.items.is_empty() {
            return msg(e.clone());
        }
    }
    if delete.is_empty() {
        let total: Option<f64> = scan.items.iter().map(|i| i.month_cost).sum();
        if f.json {
            return print_json(&json!({ "ok": true, "scan": scan, "month_cost": total }));
        }
        if scan.items.is_empty() {
            println!("{}", t("cost.cli.orphans_none", &[]));
            return Ok(());
        }
        let cur = scan.currency.clone().unwrap_or_default();
        for i in &scan.items {
            let size = i.size_gb.map_or("-".to_string(), |g| format!("{g} GB"));
            let cost = i
                .month_cost
                .map_or("-".to_string(), |c| format!("{c:.2} {cur}"));
            println!(
                "{}",
                t(
                    "cost.cli.orphan_row",
                    &[
                        ("id", &i.id),
                        ("kind", &i.kind),
                        ("region", &i.region),
                        ("reason", &i.reason),
                        ("size", &size),
                        ("cost", &cost)
                    ],
                )
            );
        }
        let cost = total.map_or("-".to_string(), |c| format!("{c:.2}"));
        println!(
            "{}",
            t(
                "cost.cli.orphans_total",
                &[
                    ("n", &scan.items.len().to_string()),
                    ("cost", &cost),
                    ("currency", &cur)
                ]
            )
        );
        return Ok(());
    }

    let plan = orphans::plan(&scan, delete).map_err(CliError::Msg)?;
    let cost = plan
        .month_cost
        .map_or("-".to_string(), |c| format!("{c:.2}"));
    if f.json && f.dry_run {
        return print_json(&json!({ "dry_run": true, "plan": plan }));
    }
    if !f.json {
        println!(
            "{}",
            t(
                "cost.cli.orphans_plan",
                &[("n", &plan.items.len().to_string()), ("cost", &cost)]
            )
        );
        for i in &plan.items {
            println!("  {}  {}  {}  {}", i.id, i.kind, i.region, i.reason);
        }
    }
    if f.dry_run {
        println!("{}", t("cost.cli.orphans_dry", &[]));
        return Ok(());
    }
    let typed = match confirm {
        Some(c) => c.to_string(),
        None if std::io::stdin().is_terminal() => {
            let mut err = std::io::stderr();
            let _ = write!(
                err,
                "{}",
                t(
                    "cost.cli.orphans_confirm_tty",
                    &[("text", &plan.confirm_text)]
                )
            );
            let _ = err.flush();
            read_line()?
        }
        None => {
            return msg(t(
                "cost.cli.orphans_needs_confirm",
                &[("text", &plan.confirm_text)],
            ))
        }
    };
    if typed != plan.confirm_text {
        return msg(t(
            "cost.orphans.err_confirm",
            &[("text", &plan.confirm_text)],
        ));
    }
    let mut results = Vec::new();
    for it in &plan.items {
        let r = src.delete(it);
        if !f.json {
            match &r {
                Ok(()) => println!("{}", t("cost.cli.orphans_deleted", &[("id", &it.id)])),
                Err(why) => println!(
                    "{}",
                    t("cost.cli.orphans_left", &[("id", &it.id), ("why", why)])
                ),
            }
        }
        results.push(orphans::ItemResult {
            id: it.id.clone(),
            ok: r.is_ok(),
            message: r.err(),
        });
    }
    if f.json {
        return print_json(&json!({ "ok": results.iter().all(|r| r.ok), "results": results }));
    }
    if results.iter().all(|r| r.ok) {
        Ok(())
    } else {
        msg(t("cost.cli.orphans_some_left", &[]))
    }
}
