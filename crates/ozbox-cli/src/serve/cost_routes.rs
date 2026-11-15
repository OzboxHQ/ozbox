//! `/v1/cost/bill` and `/v1/cost/orphans...`: the real bill beside the estimate, the drift between them, the budget on the
//! real figure, and the resources in the account that nothing uses.
//!
//! Reading the provider is slow and, for the bill, costs a cent a request, so it happens in the server's background
//! worker once a day (and when asked, not more than every few minutes) and the answers are kept in `bill.json`. A page
//! view only reads what is kept. Deleting an orphan is plan, then apply with typed words, and the apply runs on the
//! worker too.

use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration, Instant};

use ozbox_core::BoxRecord;
use serde::Deserialize;
use serde_json::{json, Value};

use super::worker::{Done, Job};
use super::{unix_ms, App, Resp};
use crate::bill::{self, BillCache, BillError, BillReport, BillSource, BudgetBasis};
use crate::cost_demo;
use crate::messages::t;
use crate::model_usage;
use crate::orphans::{self, ItemResult, OrphanPlan, OrphanScan, OrphanSource};
use crate::state::{day_key, DayEstimate};

/// How often the server looks at whether the daily read is due.
const CHECK_EVERY_MS: u64 = 5 * 60_000;
/// A refresh on request is refused sooner than this after the last attempt.
const MIN_REFRESH_GAP_MS: u64 = 5 * 60_000;
/// Drift older than this is shown but not alerted on: a first read finds old history and must not flood.
const ALERT_WINDOW_DAYS: u64 = 7;
const PLAN_TTL: Duration = Duration::from_secs(10 * 60);
const MAX_PLAN_ITEMS: usize = 25;
const DAY_MS: u64 = 86_400_000;

#[derive(Default)]
pub struct CostRt {
    pub cache: BillCache,
    pub path: Option<PathBuf>,
    pub next_check_ms: u64,
    pub busy: bool,
    pub delete_busy: bool,
    plans: HashMap<String, (OrphanPlan, Instant)>,
    /// What the last delete did, for the page to show.
    last_delete: Option<Value>,
    demo: Arc<cost_demo::DemoOrphans>,
}

#[derive(Deserialize)]
struct PlanBody {
    ids: Vec<String>,
}

#[derive(Deserialize)]
struct ApplyBody {
    plan_id: String,
    confirm_text: Option<String>,
}

impl App {
    pub fn with_bill_file(mut self, path: Option<PathBuf>) -> Self {
        if let Some(p) = &path {
            self.cost.cache = BillCache::load(p);
        }
        self.cost.path = path;
        self
    }

    fn save_bill(&self) {
        if let Some(p) = &self.cost.path {
            self.cost.cache.save(p);
        }
    }

    fn bill_source(&self, boxes: &[BoxRecord]) -> Arc<dyn BillSource> {
        if self.simulated_metrics {
            return Arc::new(cost_demo::DemoBill {
                boxes: boxes.iter().map(|b| b.spec.name.to_string()).collect(),
            });
        }
        match self.provider_id.as_str() {
            "aws" => Arc::new(bill::AwsBill {
                runner: Arc::clone(&self.runner),
                profile: self.route_inputs.aws_profile.clone(),
            }),
            other => Arc::new(bill::NoBill(other.to_string())),
        }
    }

    fn orphan_source(&self) -> Arc<dyn OrphanSource> {
        if self.simulated_metrics {
            return self.cost.demo.clone();
        }
        match self.provider_id.as_str() {
            "aws" => Arc::new(orphans::AwsOrphans {
                runner: Arc::clone(&self.runner),
                profile: self.route_inputs.aws_profile.clone(),
            }),
            _ => Arc::new(orphans::NoOrphans),
        }
    }

    fn scan_regions(&self, boxes: &[BoxRecord]) -> Vec<String> {
        let mut r: Vec<String> = boxes.iter().filter_map(|b| b.spec.region.clone()).collect();
        r.extend(self.route_inputs.aws_region.clone());
        r.sort();
        r.dedup();
        r
    }

    /// The estimate by day: the ledger's, or the demo's made-up one.
    fn estimate_days(&self, now_ms: u64) -> std::collections::BTreeMap<String, DayEstimate> {
        if self.simulated_metrics {
            // The demo's estimate is made for the boxes its bill names, so boxes made or removed since the bill was
            // read do not turn into "not in the bill" on every day.
            let names: Vec<String> = self
                .cost
                .cache
                .report
                .iter()
                .flat_map(|r| &r.days)
                .flat_map(|d| &d.lines)
                .filter_map(|l| l.box_name.clone())
                .collect();
            // Made for the moment the bill was read, so a request after midnight does not shift every day.
            let at = self
                .cost
                .cache
                .report
                .as_ref()
                .map_or(now_ms, |r| r.fetched_at_ms);
            return cost_demo::fixture(at, &names).1;
        }
        self.state.ledger.days.clone()
    }

    fn prices_uncertain(&self, now_ms: u64) -> bool {
        self.prices.book.as_ref().is_none_or(|b| b.is_stale(now_ms))
            || !self.settings.budget.size_prices_usd.is_empty()
    }

    pub(super) fn reconciliation(&self, now_ms: u64) -> Option<bill::Reconciliation> {
        let report = self.cost.cache.report.as_ref()?;
        Some(bill::reconcile(
            &self.estimate_days(now_ms),
            report,
            now_ms,
            bill::tuning(&self.settings, self.prices_uncertain(now_ms)),
        ))
    }

    /// The month's spend for the budget: the real bill where there is one, else the estimate, and which it was.
    pub(super) fn budget_figure(
        &self,
        now_ms: u64,
    ) -> Option<(f64, String, BudgetBasis, Option<String>)> {
        if let Some(m) = bill::month_spend(
            &self.estimate_days(now_ms),
            self.cost.cache.report.as_ref(),
            now_ms,
        ) {
            return Some((m.spent, m.currency, BudgetBasis::Bill, Some(m.real_through)));
        }
        self.state
            .ledger
            .month_to_date()
            .map(|(s, c)| (s, c, BudgetBasis::Estimate, None))
    }

    // ---------- the daily read ----------

    /// Called from the server tick: start the daily read when it is due.
    pub(super) fn tick_cost(&mut self, now_ms: u64) {
        if now_ms < self.cost.next_check_ms || self.cost.busy {
            return;
        }
        self.cost.next_check_ms = now_ms + CHECK_EVERY_MS;
        let bill_due = self.cost.cache.refresh_due(now_ms);
        let orphans_due = self
            .cost
            .cache
            .orphans
            .as_ref()
            .is_none_or(|o| now_ms.saturating_sub(o.scanned_at_ms) >= bill::REFRESH_AFTER_MS)
            && now_ms.saturating_sub(self.cost.cache.last_attempt_ms) >= bill::RETRY_AFTER_MS;
        if bill_due || orphans_due {
            self.start_cost_read(now_ms, bill_due, orphans_due);
        }
    }

    fn start_cost_read(&mut self, now_ms: u64, bill_too: bool, orphans_too: bool) -> bool {
        let Ok(recs) = self.provider.list() else {
            return false;
        };
        let bills = self.bill_source(&recs);
        let found = self.orphan_source();
        let regions = self.scan_regions(&recs);
        let book = self.prices.book.clone();
        let job: Job = Box::new(move || Done::Bill {
            now_ms,
            bill: bill_too.then(|| bills.fetch(now_ms)),
            orphans: orphans_too.then(|| found.scan(&regions, book.as_ref(), now_ms)),
        });
        if self.submit(job) {
            self.cost.busy = true;
            true
        } else {
            false
        }
    }

    pub(super) fn bill_done(
        &mut self,
        at: u64,
        bill: Option<Result<BillReport, BillError>>,
        found: Option<OrphanScan>,
    ) {
        self.cost.busy = false;
        let had_bill = bill.is_some();
        if let Some(r) = bill {
            self.cost.cache.record(r, at);
        }
        if let Some(mut scan) = found {
            // A failed scan keeps what the last good one found, and says it failed.
            if scan.error.is_some() && !scan.unsupported {
                if let Some(old) = &self.cost.cache.orphans {
                    scan.items.clone_from(&old.items);
                }
            }
            self.cost.cache.orphans = Some(scan);
        }
        if had_bill && !self.simulated_metrics {
            self.alert_on_drift(at);
        }
        self.save_bill();
        self.version
            .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
    }

    /// Drift on a recent finished day is an alert, through the same routing as every other. Older drift is remembered as
    /// already known, so the first read of a month of history does not send a month of messages.
    fn alert_on_drift(&mut self, at: u64) {
        if self.cost.cache.problem.is_some() {
            return;
        }
        let Some(mut recon) = self.reconciliation(at) else {
            return;
        };
        let cutoff = day_key(at.saturating_sub(ALERT_WINDOW_DAYS * DAY_MS));
        let (recent, old): (Vec<_>, Vec<_>) = recon.drift.drain(..).partition(|r| r.date >= cutoff);
        for r in &old {
            self.cost.cache.alerted.insert(format!(
                "{}:{}",
                r.date,
                r.box_name.as_deref().unwrap_or("-")
            ));
        }
        recon.drift = recent;
        let alerts = bill::drift_alerts(&recon, &mut self.cost.cache.alerted, at);
        if !alerts.is_empty() {
            self.route_alerts(alerts, at);
        }
    }

    // ---------- routes ----------

    pub(super) fn cost_route(
        &mut self,
        method: &str,
        rest: &[&str],
        body: &[u8],
        step_up: super::roles::StepUp,
    ) -> Resp {
        let now = unix_ms();
        match (method, rest) {
            ("GET", ["bill"]) => self.bill_json(now),
            ("POST", ["bill", "refresh"]) => {
                if self.cost.busy {
                    return Resp::error(409, "busy", &t("cost.api.busy", &[]));
                }
                if now.saturating_sub(self.cost.cache.last_attempt_ms) < MIN_REFRESH_GAP_MS
                    && !self.simulated_metrics
                {
                    return Resp::error(429, "too_soon", &t("cost.api.too_soon", &[]));
                }
                if !self.start_cost_read(now, true, true) {
                    return Resp::error(429, "busy", &t("cost.api.busy", &[]));
                }
                self.bill_json(now)
            }
            ("GET", ["orphans"]) => self.orphans_json(),
            ("POST", ["orphans", "scan"]) => {
                if self.cost.busy {
                    return Resp::error(409, "busy", &t("cost.api.busy", &[]));
                }
                if !self.start_cost_read(now, false, true) {
                    return Resp::error(429, "busy", &t("cost.api.busy", &[]));
                }
                self.orphans_json()
            }
            ("POST", ["orphans", "plan"]) => self.orphans_plan(body),
            ("POST", ["orphans", "apply"]) => self.orphans_apply(body, step_up),
            ("GET" | "POST", _) => Resp::error(404, "not_found", "no such endpoint"),
            _ => Resp::error(405, "method_not_allowed", "method not allowed"),
        }
    }

    fn bill_json(&self, now_ms: u64) -> Resp {
        let c = &self.cost.cache;
        let recon = self.reconciliation(now_ms);
        let boxes_estimate: Vec<Value> = self
            .state
            .ledger
            .boxes
            .iter()
            .filter(|(_, a)| a.machine_cost + a.disk_cost > 0.0)
            .map(|(n, a)| json!({ "box": n, "estimate": a.machine_cost + a.disk_cost, "currency": a.currency }))
            .collect();
        let budget = {
            let monthly = self.settings.budget.monthly_usd;
            let fig = self.budget_figure(now_ms);
            let month = crate::state::month_key(now_ms);
            let fired: Vec<u32> = if self.state.alerts.budget_month == month {
                self.state.alerts.budget_fired.clone()
            } else {
                Vec::new()
            };
            json!({
                "monthly_usd": monthly,
                "spent": fig.as_ref().map(|f| f.0),
                "currency": fig.as_ref().map(|f| f.1.clone()),
                "basis": fig.as_ref().map(|f| f.2),
                "real_through": fig.as_ref().and_then(|f| f.3.clone()),
                "percent": monthly.zip(fig.as_ref()).filter(|(m, _)| *m > 0.0).map(|(m, f)| f.0 / m * 100.0),
                "thresholds": [
                    { "percent": 50, "on": self.settings.budget.alert_50 },
                    { "percent": 80, "on": self.settings.budget.alert_80 },
                    { "percent": 100, "on": self.settings.budget.alert_100 },
                ],
                "fired": fired,
            })
        };
        Resp::json(
            200,
            &json!({
                "provider": self.provider_id,
                "demo": self.simulated_metrics,
                "month": crate::state::month_key(now_ms),
                "basis": if c.report.is_some() { "bill" } else { "estimate" },
                "source": c.report.as_ref().map(|r| r.source.clone()),
                "currency": c.report.as_ref().map(|r| r.currency.clone()),
                "fetched_at_ms": c.report.as_ref().map(|r| r.fetched_at_ms),
                "age_s": c.report.as_ref().map(|r| now_ms.saturating_sub(r.fetched_at_ms) / 1000),
                "stale": c.report.as_ref().is_some_and(|r| now_ms.saturating_sub(r.fetched_at_ms) > 2 * bill::REFRESH_AFTER_MS),
                "problem": c.problem,
                "refreshing": self.cost.busy,
                "last_attempt_ms": (c.last_attempt_ms > 0).then_some(c.last_attempt_ms),
                // The two things a person has to know about AWS data, said as numbers so the page can word them.
                "needs": { "cost_allocation_tag": bill::MANAGED_TAG, "box_tag": bill::BOX_TAG, "lag_hours": 24 },
                "drift_threshold": { "percent": self.settings.budget.drift_alert_pct, "min": self.settings.budget.drift_alert_min_usd },
                "reconciliation": recon,
                "estimate_boxes": boxes_estimate,
                "budget": budget,
                "model_spend": self.model_spend(now_ms),
            }),
        )
    }

    /// Model and API spend this month, always an estimate from token counts: no provider reports its own bill here.
    fn model_spend(&self, now_ms: u64) -> Value {
        let (_, _, day) = crate::state::civil(now_ms);
        let records = self
            .settings_path
            .as_deref()
            .map(|p| model_usage::read(&model_usage::path_for(p), now_ms))
            .unwrap_or_default();
        let s = model_usage::summarize(&self.settings.models, &records, now_ms, day as u32);
        json!({
            "basis": "estimate",
            "currency": "USD",
            "calls": s.total.calls,
            "input_tokens": s.total.input_tokens,
            "output_tokens": s.total.output_tokens,
            "est_cost_usd": s.total.est_cost_usd,
            "unpriced_calls": s.total.unpriced_calls,
            "by_model": s.by_model.iter().map(|r| json!({ "model": r.key, "calls": r.totals.calls, "est_cost_usd": r.totals.est_cost_usd })).collect::<Vec<_>>(),
        })
    }

    fn orphans_json(&self) -> Resp {
        Resp::json(
            200,
            &json!({
                "scan": self.cost.cache.orphans,
                "scanning": self.cost.busy,
                "deleting": self.cost.delete_busy,
                "last_delete": self.cost.last_delete,
                "month_cost": self.cost.cache.orphans.as_ref().and_then(|o| {
                    let v: Option<Vec<f64>> = o.items.iter().map(|i| i.month_cost).collect();
                    v.map(|v| v.iter().sum::<f64>())
                }),
            }),
        )
    }

    fn orphans_plan(&mut self, body: &[u8]) -> Resp {
        let b: PlanBody = match serde_json::from_slice(body) {
            Ok(b) => b,
            Err(e) => return Resp::error(400, "bad_request", &format!("invalid request: {e}")),
        };
        if b.ids.len() > MAX_PLAN_ITEMS {
            return Resp::error(
                400,
                "too_many",
                &t("cost.api.too_many", &[("n", &MAX_PLAN_ITEMS.to_string())]),
            );
        }
        let Some(scan) = &self.cost.cache.orphans else {
            return Resp::error(409, "no_scan", &t("cost.api.no_scan", &[]));
        };
        let plan = match orphans::plan(scan, &b.ids) {
            Ok(p) => p,
            Err(m) => return Resp::error(400, "refused", &m),
        };
        let now = Instant::now();
        self.cost
            .plans
            .retain(|_, (_, at)| now.duration_since(*at) < PLAN_TTL);
        if self.cost.plans.len() >= 10 {
            return Resp::error(429, "too_many_plans", "too many open plans; apply or wait");
        }
        let id = match super::random_hex(16) {
            Ok(i) => i,
            Err(m) => return Resp::error(500, "internal", &m),
        };
        let out = json!({
            "plan_id": id,
            "expires_in_s": PLAN_TTL.as_secs(),
            "risk": "high",
            "requires_confirm_text": plan.confirm_text,
            "plan": plan,
        });
        self.cost.plans.insert(id, (plan, now));
        self.log_activity(
            "plan delete-orphans",
            "-",
            Some(ozbox_core::Risk::High),
            "proposed, nothing changed",
        );
        Resp::json(200, &out)
    }

    fn orphans_apply(&mut self, body: &[u8], step_up: super::roles::StepUp) -> Resp {
        let b: ApplyBody = match serde_json::from_slice(body) {
            Ok(b) => b,
            Err(e) => return Resp::error(400, "bad_request", &format!("invalid request: {e}")),
        };
        let Some((plan, at)) = self.cost.plans.get(&b.plan_id) else {
            return Resp::error(
                409,
                "unknown_plan",
                "this server did not issue that plan (or it was already used); plan again",
            );
        };
        if at.elapsed() >= PLAN_TTL {
            self.cost.plans.remove(&b.plan_id);
            return Resp::error(409, "stale_plan", "that plan has expired; plan again");
        }
        // The scan the plan came from must still be the current one: a newer scan may have found that things changed.
        if self.cost.cache.orphans.as_ref().map(|o| o.scanned_at_ms) != Some(plan.based_on_ms) {
            self.cost.plans.remove(&b.plan_id);
            return Resp::error(409, "stale_plan", &t("cost.api.scan_changed", &[]));
        }
        if b.confirm_text.as_deref() != Some(plan.confirm_text.as_str()) {
            return Resp::error(
                400,
                "confirmation_required",
                &t("cost.orphans.err_confirm", &[("text", &plan.confirm_text)]),
            );
        }
        if let Some(r) =
            super::roles::step_up_refusal(step_up, "deleting the resources the bill found")
        {
            return r;
        }
        if self.cost.delete_busy {
            return Resp::error(409, "busy", &t("cost.api.busy", &[]));
        }
        let Some((plan, _)) = self.cost.plans.remove(&b.plan_id) else {
            return Resp::error(409, "unknown_plan", "plan again");
        };
        let src = self.orphan_source();
        let recs = self.provider.list().unwrap_or_default();
        let regions = self.scan_regions(&recs);
        let book = self.prices.book.clone();
        let plan_id = b.plan_id.clone();
        let n = plan.items.len();
        let now = unix_ms();
        let asked_by = self.current_actor.clone();
        let job: Job = Box::new(move || {
            let results: Vec<ItemResult> = plan
                .items
                .iter()
                .map(|it| match src.delete(it) {
                    Ok(()) => ItemResult {
                        id: it.id.clone(),
                        ok: true,
                        message: None,
                    },
                    Err(m) => ItemResult {
                        id: it.id.clone(),
                        ok: false,
                        message: Some(m),
                    },
                })
                .collect();
            let rescan = src.scan(&regions, book.as_ref(), now);
            Done::OrphansDeleted {
                now_ms: now,
                plan_id,
                results,
                rescan,
                actor: asked_by,
            }
        });
        if !self.submit(job) {
            return Resp::error(429, "busy", &t("cost.api.busy", &[]));
        }
        self.cost.delete_busy = true;
        self.log_activity(
            "apply delete-orphans",
            "-",
            Some(ozbox_core::Risk::High),
            &format!("{n} resource(s) being deleted"),
        );
        Resp::json(202, &json!({ "status": "deleting", "count": n }))
    }

    pub(super) fn orphans_deleted(
        &mut self,
        at: u64,
        plan_id: &str,
        results: &[ItemResult],
        rescan: OrphanScan,
    ) {
        self.cost.delete_busy = false;
        if rescan.error.is_none() {
            self.cost.cache.orphans = Some(rescan);
        } else if let Some(o) = &mut self.cost.cache.orphans {
            let gone: Vec<&str> = results
                .iter()
                .filter(|r| r.ok)
                .map(|r| r.id.as_str())
                .collect();
            o.items.retain(|i| !gone.contains(&i.id.as_str()));
        }
        let ok = results.iter().filter(|r| r.ok).count();
        self.log_activity(
            "applied delete-orphans",
            "-",
            Some(ozbox_core::Risk::High),
            &format!("{ok} of {} deleted", results.len()),
        );
        self.cost.last_delete =
            Some(json!({ "plan_id": plan_id, "at_ms": at, "results": results }));
        self.save_bill();
        self.version
            .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr, SocketAddr};

    type Keep = (tempfile::TempDir, App);

    fn demo_app() -> Keep {
        let dir = tempfile::tempdir().unwrap();
        let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 7878);
        let app = App::new(
            Box::new(ozbox_provider_fake::open(dir.path())),
            true,
            addr,
            "tok".into(),
        );
        (dir, app)
    }

    fn call(app: &mut App, method: &str, rest: &[&str], body: Value, fresh: bool) -> (u16, Value) {
        use super::super::roles::StepUp;
        call_with(
            app,
            method,
            rest,
            body,
            if fresh { StepUp::Fresh } else { StepUp::Needed },
        )
    }

    fn call_with(
        app: &mut App,
        method: &str,
        rest: &[&str],
        body: Value,
        step_up: super::super::roles::StepUp,
    ) -> (u16, Value) {
        let bytes = if body.is_null() {
            Vec::new()
        } else {
            body.to_string().into_bytes()
        };
        let r = app.cost_route(method, rest, &bytes, step_up);
        (
            r.status,
            serde_json::from_slice(&r.body).unwrap_or(Value::Null),
        )
    }

    #[test]
    fn the_bill_page_reads_what_was_kept_and_never_asks_the_provider() {
        let (_dir, mut app) = demo_app();
        let (s, v) = call(&mut app, "GET", &["bill"], Value::Null, true);
        assert_eq!(s, 200);
        assert_eq!(v["basis"], "estimate", "nothing read yet");
        assert!(v["reconciliation"].is_null());
        assert_eq!(v["needs"]["cost_allocation_tag"], "ozbox-managed");
        assert_eq!(v["model_spend"]["basis"], "estimate");
        // the daily read is due on the first tick; the inline worker finishes it on the spot
        app.tick_cost(unix_ms());
        app.apply_done(unix_ms());
        let (_, v) = call(&mut app, "GET", &["bill"], Value::Null, true);
        assert_eq!(v["basis"], "bill");
        assert_eq!(v["source"], "Demo data, made up for this page");
        assert!(v["reconciliation"]["drift"]
            .as_array()
            .is_some_and(|d| !d.is_empty()));
        assert!(v["reconciliation"]["days"]
            .as_array()
            .is_some_and(|d| d.len() > 10));
    }

    #[test]
    fn a_refresh_is_one_read_and_a_second_is_refused_while_one_runs() {
        let (_dir, mut app) = demo_app();
        app.cost.busy = true;
        let (s, v) = call(&mut app, "POST", &["bill", "refresh"], Value::Null, true);
        assert_eq!(s, 409, "{v}");
        app.cost.busy = false;
        let (s, v) = call(&mut app, "POST", &["bill", "refresh"], Value::Null, true);
        assert_eq!(s, 200, "{v}");
        assert_eq!(v["refreshing"], true, "the read is with the worker");
        app.apply_done(unix_ms());
        let (_, v) = call(&mut app, "GET", &["bill"], Value::Null, true);
        assert_eq!(v["refreshing"], false);
        assert_eq!(v["basis"], "bill");
    }

    #[test]
    fn deleting_an_orphan_is_a_plan_then_typed_words_and_never_an_untagged_thing() {
        let (_dir, mut app) = demo_app();
        app.tick_cost(unix_ms());
        app.apply_done(unix_ms());
        let (_, v) = call(&mut app, "GET", &["orphans"], Value::Null, true);
        assert_eq!(v["scan"]["items"].as_array().unwrap().len(), 5);
        // an untagged resource and an image cannot even be planned
        for id in ["i-0demo000stray", "ami-0demo000unsigned"] {
            let (s, _) = call(
                &mut app,
                "POST",
                &["orphans", "plan"],
                json!({ "ids": [id] }),
                true,
            );
            assert_eq!(s, 400, "{id}");
        }
        let (s, plan) = call(
            &mut app,
            "POST",
            &["orphans", "plan"],
            json!({ "ids": ["vol-0demo000retired", "snap-0demo000gone"] }),
            true,
        );
        assert_eq!(s, 200);
        assert_eq!(plan["requires_confirm_text"], "delete-2");
        assert_eq!(plan["risk"], "high");
        let id = plan["plan_id"].as_str().unwrap().to_string();
        // wrong words, and no fresh passkey, change nothing
        let (s, _) = call(
            &mut app,
            "POST",
            &["orphans", "apply"],
            json!({ "plan_id": id, "confirm_text": "yes" }),
            true,
        );
        assert_eq!(s, 400);
        let (s, _) = call(
            &mut app,
            "POST",
            &["orphans", "apply"],
            json!({ "plan_id": id, "confirm_text": "delete-2" }),
            false,
        );
        assert_eq!(s, 403);
        let (_, v) = call(&mut app, "GET", &["orphans"], Value::Null, true);
        assert_eq!(v["scan"]["items"].as_array().unwrap().len(), 5);
        // the right words
        let (s, _) = call(
            &mut app,
            "POST",
            &["orphans", "apply"],
            json!({ "plan_id": id, "confirm_text": "delete-2" }),
            true,
        );
        assert_eq!(s, 202);
        app.apply_done(unix_ms());
        let (_, v) = call(&mut app, "GET", &["orphans"], Value::Null, true);
        assert_eq!(v["scan"]["items"].as_array().unwrap().len(), 3);
        assert_eq!(v["last_delete"]["results"].as_array().unwrap().len(), 2);
        assert!(v["last_delete"]["results"][0]["ok"].as_bool().unwrap());
        // a plan is used once
        let (s, _) = call(
            &mut app,
            "POST",
            &["orphans", "apply"],
            json!({ "plan_id": id, "confirm_text": "delete-2" }),
            true,
        );
        assert_eq!(s, 409);
    }

    /// A security review (2026-11-11): deleting what the bill found asked for a passkey behind a sign-in and nothing on a
    /// box without one, so any process holding the access token could delete cloud resources. It is refused there now.
    #[test]
    fn on_a_box_without_a_sign_in_deleting_an_orphan_is_refused_and_says_why() {
        use super::super::roles::StepUp;
        let (_dir, mut app) = demo_app();
        app.tick_cost(unix_ms());
        app.apply_done(unix_ms());
        let (_, plan) = call(
            &mut app,
            "POST",
            &["orphans", "plan"],
            json!({ "ids": ["vol-0demo000retired"] }),
            true,
        );
        let id = plan["plan_id"].as_str().unwrap().to_string();
        let words = plan["requires_confirm_text"].as_str().unwrap().to_string();
        let (s, v) = call_with(
            &mut app,
            "POST",
            &["orphans", "apply"],
            json!({ "plan_id": id, "confirm_text": words }),
            StepUp::LocalOnly,
        );
        assert_eq!(
            (s, v["code"].as_str()),
            (403, Some("sign_in_required")),
            "{v}"
        );
        assert!(v["message"].as_str().unwrap().contains("runs on a box"));
        let (_, v) = call(&mut app, "GET", &["orphans"], Value::Null, true);
        assert_eq!(
            v["scan"]["items"].as_array().unwrap().len(),
            5,
            "nothing was deleted"
        );
        // the plan was not used up: on the person's own computer the same words go through
        let (s, _) = call_with(
            &mut app,
            "POST",
            &["orphans", "apply"],
            json!({ "plan_id": id, "confirm_text": words }),
            StepUp::Fresh,
        );
        assert_eq!(s, 202);
    }

    #[test]
    fn the_budget_uses_the_real_bill_when_there_is_one_and_says_which() {
        let (_dir, mut app) = demo_app();
        app.settings.budget.monthly_usd = Some(1000.0);
        let (_, v) = call(&mut app, "GET", &["bill"], Value::Null, true);
        assert!(
            v["budget"]["basis"].is_null(),
            "no estimate and no bill yet: no figure, not zero"
        );
        app.tick_cost(unix_ms());
        app.apply_done(unix_ms());
        let (_, v) = call(&mut app, "GET", &["bill"], Value::Null, true);
        assert_eq!(v["budget"]["basis"], "bill");
        assert!(v["budget"]["real_through"].is_string());
        assert!(v["budget"]["spent"].as_f64().unwrap() > 0.0);
        assert!(v["budget"]["percent"].as_f64().is_some());
    }

    struct CeRunner(String);

    impl ozbox_core::CommandRunner for CeRunner {
        fn run(&self, cmd: &ozbox_core::CommandSpec) -> ozbox_core::Result<ozbox_core::Output> {
            assert_eq!(
                cmd.args.get(1).map(String::as_str),
                Some("get-cost-and-usage"),
                "only the bill is read"
            );
            Ok(ozbox_core::Output {
                status: Some(0),
                stdout: self.0.clone(),
                stderr: String::new(),
            })
        }
    }

    #[test]
    fn a_real_provider_day_that_differs_is_an_alert_once_through_the_normal_routing() {
        let dir = tempfile::tempdir().unwrap();
        let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 7878);
        let mut app = App::new(
            Box::new(ozbox_provider_fake::open(dir.path())),
            false,
            addr,
            "tok".into(),
        );
        let now = unix_ms();
        let day = day_key(now.saturating_sub(3 * DAY_MS));
        let old = day_key(now.saturating_sub(20 * DAY_MS));
        let page = |d: &str, a: &str| {
            json!({ "ResultsByTime": [{
                "TimePeriod": { "Start": d, "End": "x" }, "Estimated": false,
                "Groups": [{ "Keys": ["ozbox-box$alpha", bill::SVC_COMPUTE], "Metrics": { "UnblendedCost": { "Amount": a, "Unit": "USD" } } }]
            }]})
        };
        let mut both = page(&day, "40.0");
        both["ResultsByTime"].as_array_mut().unwrap().extend(
            page(&old, "40.0")["ResultsByTime"]
                .as_array()
                .unwrap()
                .clone(),
        );
        app.provider_id = "aws".into();
        app.runner = Arc::new(CeRunner(both.to_string()));
        for d in [&day, &old] {
            let mut e = DayEstimate {
                watched_ms: DAY_MS,
                ..DayEstimate::default()
            };
            e.boxes.insert(
                "alpha".into(),
                crate::state::DayBox {
                    machine_cost: 20.0,
                    disk_cost: 0.0,
                },
            );
            app.state.ledger.days.insert(d.clone(), e);
        }
        app.tick_cost(now);
        app.apply_done(now);
        let recent = &app.state.alerts.recent;
        let drift: Vec<_> = recent.iter().filter(|r| r.kind == "cost_drift").collect();
        assert_eq!(
            drift.len(),
            1,
            "the recent day alerts; the old one is only remembered: {}",
            recent.len()
        );
        assert!(drift[0].title.contains("alpha"));
        assert!(app.cost.cache.alerted.len() == 2);
        // asking again does not send it again
        app.cost.cache.last_ok_ms = 0;
        app.cost.cache.last_attempt_ms = 0;
        app.cost.next_check_ms = 0;
        app.tick_cost(now + 1);
        app.apply_done(now + 1);
        assert_eq!(
            app.state
                .alerts
                .recent
                .iter()
                .filter(|r| r.kind == "cost_drift")
                .count(),
            1
        );
    }
}
