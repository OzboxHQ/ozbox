//! The parts of the dashboard server that talk to the outside world on the owner's behalf: cost estimates from public
//! prices, alert delivery, the Telegram bot, write-only secrets and the model providers. Everything here hangs off
//! [`App`], and the periodic work is driven by [`App::tick`], which the server loop calls about once a second.
//!
//! No response in this file carries a secret. A secret goes in by `PUT /v1/secrets/<name>`, and the API reports only
//! whether a name is set.

use std::sync::Arc;

use ozbox_core::{BoxRecord, BoxState};
use serde::de::DeserializeOwned;
use serde::Deserialize;
use serde_json::{json, Value};

use super::test_runs;
use super::worker::{Done, Job};
use super::{unix_ms, App, Resp};
use crate::channels::{self, routing};
use crate::models;
use crate::netguard::Guard;
use crate::notify::{self, Alert, BoxObs, BudgetObs, Channels, Engine, Inputs};
use crate::pricing::{self, box_cost, PriceSource, HOURS_PER_MONTH};
use crate::secrets;
use crate::settings::{valid_id, WebhookConfig};
use crate::state::{Observed, TelegramChat};

const ALERT_EVERY_MS: u64 = 60_000;
const PRICE_CHECK_EVERY_MS: u64 = 5 * 60_000;
/// How soon the next poll is considered after one ends (or when there was nothing to poll for).
const TELEGRAM_RETRY_EVERY_MS: u64 = 1_000;
const ROUTING_EVERY_MS: u64 = 30_000;
const TEST_SEND_BOUND: std::time::Duration = std::time::Duration::from_secs(12);

fn parse<T: DeserializeOwned>(b: &[u8]) -> Result<T, Resp> {
    serde_json::from_slice(b)
        .map_err(|e| Resp::error(400, "bad_request", &format!("invalid request: {e}")))
}

/// What the server schedules between requests.
#[derive(Debug, Default)]
pub struct Schedule {
    pub next_alerts_ms: u64,
    pub next_prices_ms: u64,
    pub next_telegram_ms: u64,
    pub next_routing_ms: u64,
    /// Boxes whose chosen tools are being installed by the worker right now.
    pub tools_busy: std::collections::BTreeSet<String>,
    /// A job of this kind is with the worker: do not start another until it reports.
    pub housekeeping_busy: bool,
    pub prices_busy: bool,
    pub telegram_busy: bool,
    pub alerts_busy: bool,
}

impl App {
    pub(super) fn channels(&self) -> Channels {
        Channels {
            secrets: Arc::clone(&self.secrets),
            http: Arc::clone(&self.http),
            runner: Arc::clone(&self.runner),
            aws_profile: self.route_inputs.aws_profile.clone(),
        }
    }

    pub(super) fn configured(&self, name: &str) -> bool {
        self.secrets.exists(name).unwrap_or(false)
    }

    pub(super) fn save_state(&self) {
        if let Some(p) = &self.state_path {
            self.state.save(p);
        }
    }

    fn save_settings(&self) -> Result<(), Resp> {
        if let Some(p) = &self.settings_path {
            self.settings
                .save_to(p)
                .map_err(|e| Resp::error(500, "cannot_save", &e.to_string()))?;
        }
        Ok(())
    }

    // ---------- periodic work ----------

    /// Called about once a second. Starts what is due and applies what the worker has finished; it never waits on the
    /// network itself (see `worker`).
    pub fn tick(&mut self, now_ms: u64) {
        self.apply_done(now_ms);
        self.start_pending_tools(now_ms);
        self.tick_orchestrations(now_ms);
        self.tick_runs(now_ms);
        self.tick_subscriptions();
        self.tick_chat(now_ms);
        if !self.schedule.housekeeping_busy {
            let agent = Arc::clone(&self.agent);
            if self.submit(Box::new(move || {
                agent.housekeeping(now_ms);
                Done::Housekeeping
            })) {
                self.schedule.housekeeping_busy = true;
            }
        }
        if now_ms >= self.schedule.next_prices_ms && !self.schedule.prices_busy {
            self.schedule.next_prices_ms = now_ms + PRICE_CHECK_EVERY_MS;
            self.start_prices(now_ms);
        }
        if now_ms >= self.schedule.next_telegram_ms && !self.schedule.telegram_busy {
            // a poll waits up to thirty seconds at the vendor on a thread of its own, so the next one may start at once
            self.schedule.next_telegram_ms = now_ms + TELEGRAM_RETRY_EVERY_MS;
            self.start_telegram();
        }
        self.tg_sweep(now_ms);
        if now_ms >= self.schedule.next_alerts_ms && !self.schedule.alerts_busy {
            self.schedule.next_alerts_ms = now_ms + ALERT_EVERY_MS;
            self.start_alerts(now_ms);
        }
        if now_ms >= self.schedule.next_routing_ms {
            self.schedule.next_routing_ms = now_ms + ROUTING_EVERY_MS;
            self.start_routing(now_ms);
        }
        self.tick_cost(now_ms);
        self.apply_done(now_ms);
    }

    pub(super) fn submit(&mut self, job: Job) -> bool {
        self.worker.submit(job)
    }

    /// Apply every result the worker has ready. Applying one may start more work, whose results are applied too when
    /// the worker is inline.
    ///
    /// Draining never depends on who asked for it: a finished change is recorded under the person who asked for it (it
    /// carries them), or under automation when nobody did, never under the request that happens to drain it (a viewer
    /// polling `GET /v1/jobs/<id>`).
    pub(super) fn apply_done(&mut self, now_ms: u64) {
        let draining_for = std::mem::replace(&mut self.current_actor, super::Actor::Automation);
        self.drain_done(now_ms);
        self.current_actor = draining_for;
    }

    fn drain_done(&mut self, now_ms: u64) {
        loop {
            let done = self.worker.drain();
            if done.is_empty() {
                return;
            }
            for d in done {
                // each result is its own: one that carries an asker sets it below
                self.current_actor = super::Actor::Automation;
                match d {
                    Done::Nothing => {}
                    Done::ChatSent { flag, to, ok } => self.chat_sent(flag, to, ok, now_ms),
                    Done::Housekeeping => self.schedule.housekeeping_busy = false,
                    Done::Prices { now_ms: at, result } => {
                        self.schedule.prices_busy = false;
                        if let Some(r) = result {
                            pricing::record_attempt(&mut self.prices, r, at);
                            if let Some(p) = &self.prices_path {
                                self.prices.save(p);
                            }
                            self.version
                                .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                        }
                    }
                    Done::Bill {
                        now_ms: at,
                        bill,
                        orphans,
                    } => self.bill_done(at, bill, orphans),
                    Done::OrphansDeleted {
                        now_ms: at,
                        plan_id,
                        results,
                        rescan,
                        actor,
                    } => {
                        self.current_actor = actor;
                        self.orphans_deleted(at, &plan_id, &results, rescan);
                    }
                    Done::TelegramPoll(p) => self.tg_polled(*p, now_ms),
                    Done::TelegramSent {
                        chat_id,
                        message_id,
                        expires_ms,
                    } => self.tg_note_sent(chat_id, message_id, expires_ms),
                    Done::Observed {
                        now_ms: at,
                        budget,
                        boxes,
                    } => {
                        self.schedule.alerts_busy = false;
                        self.evaluate_alerts(at, budget, boxes);
                    }
                    Done::Applied(a) => self.applied_done(*a),
                    Done::ToolsInstalled { name, ok, actor } => {
                        self.current_actor = actor;
                        self.tools_install_done(&name, ok);
                    }
                    Done::UpgradeSettled {
                        what,
                        name,
                        ready,
                        selftest_ok,
                        backup,
                        actor,
                    } => {
                        self.current_actor = actor;
                        self.upgrade_settled(what, &name, &ready, selftest_ok, &backup, now_ms);
                    }
                    Done::TestSent {
                        alert,
                        channel,
                        results,
                    } => {
                        let (planned, deliveries): (Vec<_>, Vec<_>) = results.into_iter().unzip();
                        self.record_test(&alert, &channel, &planned, deliveries);
                        self.version
                            .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                    }
                    Done::Routed {
                        now_ms: at,
                        alert,
                        results,
                        skipped,
                        retry,
                    } => self.apply_routed(at, alert, results, skipped, retry),
                }
            }
        }
    }

    fn start_prices(&mut self, now_ms: u64) {
        let Some(recs) = self.boxes_quietly() else {
            return;
        };
        let wanted = pricing::wanted_types(&recs);
        if !self.prices.refresh_due(now_ms, &wanted) {
            return;
        }
        let aws = pricing::AwsFetcher {
            runner: Arc::clone(&self.runner),
            profile: self.route_inputs.aws_profile.clone(),
            default_region: self.route_inputs.aws_region.clone(),
        };
        let hcloud = pricing::HcloudFetcher {
            http: Arc::clone(&self.http),
        };
        let provider_id = self.provider_id.clone();
        let job: Job = Box::new(move || Done::Prices {
            now_ms,
            result: pricing::fetch(&provider_id, &aws, &hcloud, &recs, now_ms),
        });
        if self.submit(job) {
            self.schedule.prices_busy = true;
        }
    }

    /// Fetch public prices when the cache says so (or `force`). A failure keeps the old prices and says why.
    fn refresh_prices(&mut self, now_ms: u64, force: bool) -> Option<Result<(), String>> {
        let recs = self.boxes_quietly()?;
        let wanted = pricing::wanted_types(&recs);
        if !force && !self.prices.refresh_due(now_ms, &wanted) {
            return None;
        }
        let aws = pricing::AwsFetcher {
            runner: Arc::clone(&self.runner),
            profile: self.route_inputs.aws_profile.clone(),
            default_region: self.route_inputs.aws_region.clone(),
        };
        let hcloud = pricing::HcloudFetcher {
            http: Arc::clone(&self.http),
        };
        let result = pricing::fetch(&self.provider_id, &aws, &hcloud, &recs, now_ms)?;
        let outcome = result.as_ref().map(|_| ()).map_err(Clone::clone);
        pricing::record_attempt(&mut self.prices, result, now_ms);
        if let Some(p) = &self.prices_path {
            self.prices.save(p);
        }
        self.version
            .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        Some(outcome)
    }

    /// Start an alert round: account the cost (cheap, here), then ask every running box how it is doing (slow, on the
    /// worker). The result comes back as [`Done::Observed`].
    fn start_alerts(&mut self, now_ms: u64) {
        let Some(recs) = self.boxes_quietly() else {
            return;
        };
        // Cost first: the budget alert needs this month's total.
        let costs: Vec<_> = recs
            .iter()
            .map(|r| box_cost(r, &self.settings, self.prices.book.as_ref()))
            .collect();
        let observed: Vec<Observed<'_>> = recs
            .iter()
            .zip(&costs)
            .map(|(r, c)| Observed {
                name: r.spec.name.as_str(),
                running: r.state == BoxState::Running,
                cost: c,
            })
            .collect();
        self.state.ledger.accrue(now_ms, &observed);
        // The real bill where the provider has told us, the estimate otherwise, and which one it was.
        let budget = self
            .budget_figure(now_ms)
            .map(|(spent, currency, basis, real_through)| BudgetObs {
                month: self.state.ledger.month.clone(),
                spent,
                currency,
                basis,
                real_through,
            });
        let agent = Arc::clone(&self.agent);
        let watch = self.state.alerts.watch_since_ms.clone();
        let job: Job = Box::new(move || Done::Observed {
            now_ms,
            budget,
            boxes: observe(agent.as_ref(), &recs, now_ms, &watch),
        });
        if self.submit(job) {
            self.schedule.alerts_busy = true;
        }
    }

    /// The boxes have been observed: decide which alerts fire, and hand each delivery to the worker.
    fn evaluate_alerts(&mut self, now_ms: u64, budget: Option<BudgetObs>, boxes: Vec<BoxObs>) {
        let mut alerts = self.engine.evaluate(
            &mut self.state.alerts,
            &Inputs {
                now_ms,
                settings: &self.settings,
                boxes: &boxes,
                budget,
            },
        );
        // a change request waiting for a person: a message with the details and a link to the dashboard (never a button)
        alerts.extend(self.pending_request_alerts(now_ms));
        for key in self.route_alerts(alerts, now_ms) {
            if let Some(id) = key.strip_prefix("areq:") {
                self.notified_requests.insert(id.to_string());
            }
        }
    }

    /// Apply the hourly limit to alerts that fired, decide where each goes under the routing rules and hand the
    /// deliveries to the worker.
    pub(super) fn route_alerts(&mut self, alerts: Vec<Alert>, now_ms: u64) -> Vec<String> {
        let (admitted, dropped) = Engine::admit_split(&mut self.state.alerts, alerts, now_ms);
        routing::note_dropped(&self.settings, &mut self.state.alerts, &dropped);
        // An alert the hourly limit refused is still listed, and says it was sent to nobody.
        for a in &dropped {
            Engine::record(&mut self.state.alerts, a, Vec::new());
            self.log_activity(
                "alert",
                a.box_name.as_deref().unwrap_or("-"),
                None,
                "not sent: too many alerts this hour",
            );
        }
        let sent_any = !admitted.is_empty();
        let admitted_keys: Vec<String> = admitted.iter().map(|a| a.key.clone()).collect();
        for a in admitted {
            let chats = self.state.telegram.chats.clone();
            let plan = routing::plan(&self.settings, &chats, &a, &mut self.state.alerts, now_ms);
            let first: Vec<(routing::Planned, u32)> =
                plan.send.into_iter().map(|p| (p, 1)).collect();
            self.dispatch(a, first, plan.skipped, false, now_ms);
        }
        self.save_state();
        if sent_any {
            self.version
                .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        }
        admitted_keys
    }

    /// Hand a set of deliveries to the worker. With nothing to send, only what was decided is recorded.
    fn dispatch(
        &mut self,
        alert: Alert,
        planned: Vec<(routing::Planned, u32)>,
        skipped: Vec<crate::notify::Delivery>,
        retry: bool,
        now_ms: u64,
    ) {
        if planned.is_empty() {
            if retry {
                return;
            }
            self.record_delivery(&alert, skipped);
            return;
        }
        let channels = self.channels();
        let (settings, chats) = (self.settings.clone(), self.state.telegram.chats.clone());
        let (a2, sk2, pl2) = (alert.clone(), skipped.clone(), planned.clone());
        let job: Job = Box::new(move || {
            let results = channels.execute_all(
                &pl2,
                &settings,
                &chats,
                &a2,
                now_ms / 1000,
                routing::DELIVERY_BOUND,
            );
            Done::Routed {
                now_ms,
                alert: a2,
                results,
                skipped: sk2,
                retry,
            }
        });
        if self.worker.submit_delivery(job) {
            return;
        }
        if retry {
            // The worker is saturated: try again shortly rather than lose the delivery.
            for (pl, at) in planned {
                self.state.alerts.retries.push(routing::Retry {
                    alert: alert.clone(),
                    planned: pl,
                    attempt: at,
                    due_ms: now_ms + 60_000,
                });
            }
        } else {
            // The alert still shows in the dashboard, and the activity list says it was not sent anywhere. Each
            // channel that was to carry it says so, so the alert is never counted as delivered.
            let mut all = skipped;
            for (pl, _) in &planned {
                let mut d = crate::notify::Delivery::new(
                    &pl.channel,
                    false,
                    "not sent: the delivery queue was full",
                );
                d.person.clone_from(&pl.person);
                all.push(d);
            }
            self.record_delivery(&alert, all);
            self.log_activity(
                "alert",
                alert.box_name.as_deref().unwrap_or("-"),
                None,
                "not sent: the delivery queue was full",
            );
        }
    }

    /// Retries and daily summaries that have come due.
    fn start_routing(&mut self, now_ms: u64) {
        let due = routing::take_due_retries(&mut self.state.alerts, now_ms);
        for r in due {
            self.dispatch(
                r.alert,
                vec![(r.planned, r.attempt)],
                Vec::new(),
                true,
                now_ms,
            );
        }
        let chats = self.state.telegram.chats.clone();
        let digests = routing::due_digests(&self.settings, &chats, &mut self.state.alerts, now_ms);
        for (alert, send, skipped) in digests {
            let first = send.into_iter().map(|p| (p, 1)).collect();
            self.dispatch(alert, first, skipped, false, now_ms);
        }
        self.save_state();
    }

    fn apply_routed(
        &mut self,
        now_ms: u64,
        alert: Alert,
        results: Vec<(routing::Planned, crate::notify::Delivery)>,
        skipped: Vec<crate::notify::Delivery>,
        retry: bool,
    ) {
        let mut deliveries = skipped;
        let pause = self.demo_retry_pause();
        if let Some(p) = pause {
            // The demo server looks for a due retry as soon as the short pause is over, not at the idle rate.
            self.schedule.next_routing_ms = self.schedule.next_routing_ms.min(now_ms + p);
        }
        for (pl, d) in results {
            if d.detail == channels::push::GONE {
                self.forget_push_device(&pl.target);
            }
            routing::schedule_retry_after(
                &mut self.state.alerts,
                &alert,
                &pl,
                d.attempts,
                &d,
                now_ms,
                pause,
            );
            deliveries.push(d);
        }
        if retry {
            let ok = deliveries.iter().filter(|d| d.ok).count();
            let outcome = format!("retried: {ok} of {} delivered", deliveries.len());
            Engine::append(&mut self.state.alerts, &alert, deliveries);
            self.log_activity(
                "alert",
                alert.box_name.as_deref().unwrap_or("-"),
                None,
                &outcome,
            );
            self.save_state();
            self.version
                .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        } else {
            self.record_delivery(&alert, deliveries);
        }
    }

    fn forget_push_device(&mut self, target: &routing::Target) {
        let routing::Target::Push(id) = target else {
            return;
        };
        for p in self.settings.routing.people.values_mut() {
            p.push.retain(|d| &d.id != id);
        }
        for k in ["push-endpoint-", "push-key-", "push-auth-"] {
            let _ = self.secrets.delete(&format!("{k}{id}"));
        }
        let _ = self.save_settings();
        self.log_activity("forget push device", id, None, "the device is gone");
    }

    fn record_delivery(&mut self, a: &Alert, deliveries: Vec<crate::notify::Delivery>) {
        let outcome = if deliveries.is_empty() {
            "recorded in the dashboard".to_string()
        } else {
            let ok = deliveries.iter().filter(|d| d.ok).count();
            format!("sent to {ok} of {} channels", deliveries.len())
        };
        Engine::record(&mut self.state.alerts, a, deliveries);
        self.log_activity(
            "alert",
            a.box_name.as_deref().unwrap_or("-"),
            None,
            &outcome,
        );
        self.save_state();
        self.version
            .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
    }

    /// Names and states only.
    pub(super) fn fleet_summary(&self) -> String {
        match self.boxes_for_loop() {
            Ok(recs) if recs.is_empty() => "No boxes yet.".into(),
            Ok(recs) => {
                let running = recs.iter().filter(|r| r.state == BoxState::Running).count();
                let lines: Vec<String> = recs
                    .iter()
                    .take(20)
                    .map(|r| format!("{}: {}", r.spec.name, r.state))
                    .collect();
                format!(
                    "{} boxes, {running} running.\n{}",
                    recs.len(),
                    lines.join("\n")
                )
            }
            Err(_) => "The provider could not be reached just now.".into(),
        }
    }

    // ---------- cost ----------

    pub(super) fn cost(&self) -> Resp {
        let recs = match self.boxes_for_loop() {
            Ok(r) => r,
            Err(r) => return r,
        };
        let now = unix_ms();
        let book = self.prices.book.as_ref();
        let mut boxes = Vec::new();
        let mut unpriced = Vec::new();
        let (mut run_rate, mut currency, mut mixed) = (0.0, None::<String>, false);
        for r in &recs {
            let c = box_cost(r, &self.settings, book);
            let running = r.state == BoxState::Running;
            let machine = if running { c.machine_hourly } else { Some(0.0) };
            let rate = machine.map(|m| (m + c.disk_hourly.unwrap_or(0.0)) * HOURS_PER_MONTH);
            if rate.is_none() {
                unpriced.push(r.spec.name.to_string());
            }
            if let (Some(rt), Some(cur)) = (rate, &c.currency) {
                match &currency {
                    Some(x) if x != cur => mixed = true,
                    _ => currency = Some(cur.clone()),
                }
                run_rate += rt;
            }
            let accrued = self.state.ledger.boxes.get(r.spec.name.as_str());
            boxes.push(json!({
                "name": r.spec.name,
                "state": r.state,
                "currency": c.currency,
                "source": c.machine_source,
                "machine_hourly": c.machine_hourly,
                "run_rate_month": rate,
                "month_to_date": accrued.map(|a| a.machine_cost + a.disk_cost).filter(|x| *x > 0.0),
                "snapshots_unpriced": c.snapshots_unpriced,
            }));
        }
        let mtd = self.state.ledger.month_to_date();
        let prices = book.map(|b| {
            json!({
                "provider": b.provider,
                "source": b.source,
                "region": b.region,
                "currency": b.currency,
                "fetched_at_ms": b.fetched_at_ms,
                "age_s": b.age_ms(now) / 1000,
                "stale": b.is_stale(now),
            })
        });
        let any_entered = boxes
            .iter()
            .any(|b| b["source"] == json!(PriceSource::Entered));
        Resp::json(
            200,
            &json!({
                "basis": "estimate",
                "note": "An estimate: hours this server has watched times the public price, plus disks. It is not the provider's bill; where the provider's bill can be read it is at /v1/cost/bill, beside this estimate.",
                "prices": prices,
                "price_error": self.prices.last_error,
                "entered_prices_used": any_entered,
                "currency": if mixed { None } else { currency },
                "fleet": {
                    "run_rate_month": if mixed || recs.is_empty() || !unpriced.is_empty() { None } else { Some(run_rate) },
                    "month_to_date": mtd.as_ref().map(|(s, _)| s),
                    "month_to_date_currency": mtd.as_ref().map(|(_, c)| c),
                    "observed_since_ms": (self.state.ledger.observed_since_ms > 0).then_some(self.state.ledger.observed_since_ms),
                    "unpriced": unpriced,
                },
                "boxes": boxes,
            }),
        )
    }

    pub(super) fn refresh_prices_now(&mut self) -> Resp {
        match self.refresh_prices(unix_ms(), true) {
            Some(Ok(())) => self.cost(),
            Some(Err(e)) => Resp::error(502, "price_list_unavailable", &e),
            None => Resp::error(
                501,
                "price_list_unavailable",
                "this provider has no public price list to read",
            ),
        }
    }

    // ---------- secrets ----------

    pub(super) fn secrets_status(&self) -> Resp {
        let mut names: Vec<String> = [
            "email-api-key",
            "telegram-bot-token",
            "slack-webhook-url",
            "smtp-password",
            "sms-account",
            "sms-secret",
            "whatsapp-token",
            "discord-webhook-url",
            "teams-webhook-url",
        ]
        .map(String::from)
        .to_vec();
        names.extend(self.settings.apps.webhooks.iter().flat_map(|w| {
            [
                format!("webhook-url-{}", w.id),
                format!("webhook-secret-{}", w.id),
            ]
        }));
        names.extend(
            self.settings
                .models
                .providers
                .iter()
                .map(|p| models::key_name(&p.id)),
        );
        let map: serde_json::Map<String, Value> = names
            .into_iter()
            .map(|n| {
                let c = self.configured(&n);
                (n, Value::Bool(c))
            })
            .collect();
        Resp::json(
            200,
            &json!({ "store": self.secrets.label(), "configured": map }),
        )
    }

    fn known_secret(&self, name: &str) -> bool {
        if !secrets::valid_name(name)
            || secrets::is_auth_secret(name)
            || secrets::is_managed_secret(name)
        {
            return false;
        }
        if let Some(id) = name.strip_prefix("model-key-") {
            return self.settings.models.providers.iter().any(|p| p.id == id);
        }
        if let Some(id) = name.strip_prefix("webhook-") {
            let id = id.trim_start_matches("url-").trim_start_matches("secret-");
            return self.settings.apps.webhooks.iter().any(|w| w.id == id);
        }
        true
    }

    pub(super) fn put_secret(&mut self, name: &str, body: &[u8]) -> Resp {
        #[derive(Deserialize)]
        #[serde(deny_unknown_fields)]
        struct B {
            value: String,
        }
        let b: B = match parse(body) {
            Ok(b) => b,
            Err(r) => return r,
        };
        if !self.known_secret(name) {
            return Resp::error(404, "not_found", "that is not a secret this server keeps");
        }
        if name.starts_with("slack-webhook-url")
            || name == "discord-webhook-url"
            || name == "teams-webhook-url"
        {
            if let Err(e) = crate::netguard::check_url(Guard::Public, &b.value) {
                return Resp::error(400, "invalid_secret", e);
            }
        }
        if name == "discord-webhook-url" && !channels::chat::discord_host_ok(&b.value) {
            return Resp::error(
                400,
                "invalid_secret",
                "that is not a Discord webhook address (https://discord.com/api/webhooks/...)",
            );
        }
        if name == "teams-webhook-url" && !channels::chat::teams_host_ok(&b.value) {
            return Resp::error(
                400,
                "invalid_secret",
                "that is not a Microsoft Teams or Workflows webhook address",
            );
        }
        if matches!(name, "sms-account" | "sms-secret" | "whatsapp-token") && b.value.len() < 6 {
            return Resp::error(
                400,
                "invalid_secret",
                "that value is too short to be a credential",
            );
        }
        match self.secrets.set(name, &b.value) {
            Ok(()) => {
                self.log_activity("save secret", name, None, "saved, write-only");
                Resp::json(200, &json!({ "name": name, "configured": true }))
            }
            Err(e) => Resp::error(422, "secret_store", &e.to_string()),
        }
    }

    pub(super) fn delete_secret(&mut self, name: &str) -> Resp {
        if !self.known_secret(name) {
            return Resp::error(404, "not_found", "that is not a secret this server keeps");
        }
        match self.secrets.delete(name) {
            Ok(()) => {
                self.log_activity("remove secret", name, None, "removed");
                Resp::json(200, &json!({ "name": name, "configured": false }))
            }
            Err(e) => Resp::error(422, "secret_store", &e.to_string()),
        }
    }

    // ---------- apps ----------

    pub(super) fn apps(&self) -> Resp {
        let a = &self.settings.apps;
        let tg_token = self.configured("telegram-bot-token");
        let webhooks: Vec<Value> = a
            .webhooks
            .iter()
            .map(|w| {
                json!({
                    "id": w.id, "label": w.label, "host": w.host, "enabled": w.enabled,
                    "configured": self.configured(&format!("webhook-url-{}", w.id))
                        && self.configured(&format!("webhook-secret-{}", w.id)),
                })
            })
            .collect();
        Resp::json(
            200,
            &json!({
                "store": self.secrets.label(),
                "public_url_set": self.chat_public_base().is_some(),
                "email": {
                    "enabled": a.email.enabled,
                    "provider": a.email.provider,
                    "configured": self.email_configured(),
                    "reply_to": a.email.reply_to,
                    "unsubscribed": a.email.unsubscribed.len(),
                },
                "sms": {
                    "enabled": a.sms.enabled,
                    "provider": a.sms.provider,
                    "configured": self.sms_configured(),
                },
                "whatsapp": {
                    "enabled": a.whatsapp.enabled,
                    "configured": self.configured("whatsapp-token") && !a.whatsapp.phone_number_id.is_empty() && !a.whatsapp.template.is_empty() && !a.whatsapp.language.is_empty(),
                },
                "discord": { "enabled": a.discord.enabled, "configured": self.configured("discord-webhook-url") },
                "teams": { "enabled": a.teams.enabled, "configured": self.configured("teams-webhook-url") },
                "push": { "enabled": a.push.enabled, "configured": self.configured("vapid-private-key"), "devices": self.settings.routing.people.values().map(|p| p.push.len()).sum::<usize>() },
                "people": self.known_people(),
                "telegram": {
                    "enabled": a.telegram.enabled,
                    "configured": tg_token,
                    "bot": self.tg.store.data.bot.as_ref().map(|b| format!("@{}", b.username)),
                    // true when "Telegram" is this server's local stand-in bot, not a real chat: the page says so
                    "demo": self.demo_telegram.is_some(),
                    "chats": self.state.telegram.chats,
                    // linking is a passkey flow of its own: see `GET /v1/telegram`
                    "links": self.tg.store.data.links.iter().filter(|l| l.state != crate::telegram_store::LinkState::Revoked).count(),
                    "halted": self.tg.store.data.halted.as_ref().map(|h| json!({ "code": h.code, "message": super::telegram_link::halt_message(h) })),
                },
                "slack": { "enabled": a.slack.enabled, "configured": self.configured("slack-webhook-url") },
                "webhooks": webhooks,
                "quiet_hours": { "from": self.settings.budget.quiet_from, "to": self.settings.budget.quiet_to, "utc_offset_minutes": self.settings.budget.utc_offset_minutes, "time_zone": self.settings.locale.time_zone },
            }),
        )
    }

    fn email_configured(&self) -> bool {
        use crate::notify_config::EmailProviderKind as K;
        let e = &self.settings.apps.email;
        let has_to = !e.to.is_empty()
            || self
                .settings
                .routing
                .people
                .values()
                .any(|p| !p.emails.is_empty());
        let creds = match e.provider {
            K::Resend | K::Postmark | K::Sendgrid => self.configured("email-api-key"),
            K::Smtp => {
                !e.smtp.host.is_empty()
                    && (e.smtp.username.is_empty() || self.configured("smtp-password"))
            }
            K::Ses => true,
        };
        creds && !e.from.is_empty() && has_to
    }

    fn sms_configured(&self) -> bool {
        let c = &self.settings.apps.sms;
        !c.from.is_empty()
            && channels::sms::needs_secrets(c.provider)
                .iter()
                .all(|n| self.configured(n))
    }

    /// The people who can sign in, for the routing screen: their ids and labels, nothing else.
    fn known_people(&self) -> Vec<Value> {
        match &self.auth {
            Some(a) => a
                .cfg
                .file
                .users
                .iter()
                .map(|u| json!({ "id": u.id, "label": u.label }))
                .collect(),
            None => Vec::new(),
        }
    }

    pub(super) fn alerts(&self) -> Resp {
        Resp::json(
            200,
            &json!({ "source": "server", "entries": self.state.alerts.recent }),
        )
    }

    /// `GET /v1/alerts/summary?date=YYYY-MM-DD[&person=<id>]`: the alerts of one calendar day (in the person's time zone,
    /// else the fleet's, else the fixed offset) with what became of each: delivered, held by quiet hours, held by the
    /// text limit or not sent, and through which channels. Today when no date is given. Alerts recorded before outcomes
    /// were kept appear with no status. Test sends and the summaries themselves are left out.
    pub(super) fn alerts_summary(&self, query: &str) -> Resp {
        use crate::channels::routing::DigestStatus;
        let q = super::parse_query(query);
        let person = q.get("person").filter(|p| !p.is_empty());
        if let Some(p) = person {
            if !self.settings.routing.people.contains_key(p) {
                return Resp::error(404, "not_found", "that person has no routing yet");
            }
        }
        let zone = person
            .and_then(|p| self.settings.routing.people.get(p))
            .and_then(|p| p.time_zone.clone())
            .or_else(|| self.settings.locale.time_zone.clone());
        let now = unix_ms();
        let fixed = self.settings.budget.utc_offset_minutes;
        let offset_at = |ms: u64| -> i64 {
            i64::from(
                zone.as_deref()
                    .and_then(|z| crate::timezone::offset_minutes(z, ms))
                    .unwrap_or(fixed),
            )
        };
        let date = match q.get("date").filter(|d| !d.is_empty()) {
            Some(d) => {
                let well_formed = d.len() == 10
                    && d.bytes().enumerate().all(|(i, b)| {
                        if i == 4 || i == 7 {
                            b == b'-'
                        } else {
                            b.is_ascii_digit()
                        }
                    });
                if !well_formed || super::parse_rfc3339_ms(&format!("{d}T00:00:00Z")).is_none() {
                    return Resp::error(400, "bad_request", "date must look like 2026-11-09");
                }
                d.clone()
            }
            None => {
                let local = (now as i64 + offset_at(now) * 60_000).max(0) as u64;
                let (y, m, d) = crate::state::civil(local);
                format!("{y:04}-{m:02}-{d:02}")
            }
        };
        let Some(utc_midnight) = super::parse_rfc3339_ms(&format!("{date}T00:00:00Z")) else {
            return Resp::error(400, "bad_request", "date must look like 2026-11-09");
        };
        // Each end of the local day has its own offset, so a day the clocks change in is 23 or 25 hours long.
        let (start, end) = crate::timezone::local_day_bounds(zone.as_deref(), &date, fixed)
            .unwrap_or_else(|| {
                let s = (utc_midnight as i64 - i64::from(fixed) * 60_000).max(0) as u64;
                (s, s + 86_400_000)
            });
        let offset = offset_at(start);
        let mut counts = [0usize; 8];
        let mut items: Vec<Value> = Vec::new();
        for r in
            self.state.alerts.recent.iter().rev().filter(|r| {
                r.ts_ms >= start && r.ts_ms < end && r.kind != "test" && r.kind != "digest"
            })
        {
            let mut row = |who: Option<&str>, status: Option<DigestStatus>, channels: &[String]| {
                let slot = match status {
                    Some(DigestStatus::Delivered) => 0,
                    Some(DigestStatus::HeldQuiet) => 1,
                    Some(DigestStatus::HeldLimit) => 2,
                    Some(DigestStatus::NotSent) => 3,
                    Some(DigestStatus::Retrying) => 5,
                    Some(DigestStatus::Failed) => 6,
                    Some(DigestStatus::Partial) => 7,
                    _ => 4,
                };
                counts[slot] += 1;
                items.push(json!({
                    "ts_ms": r.ts_ms,
                    "key": r.key,
                    "kind": r.kind,
                    "title": r.title,
                    "severity": r.severity,
                    "box_name": r.box_name,
                    "person": who,
                    "status": status.filter(|s| *s != DigestStatus::Unrecorded),
                    "channels": channels,
                }));
            };
            if r.outcomes.is_empty() {
                if person.is_none() {
                    row(None, None, &[]);
                }
                continue;
            }
            for o in r
                .outcomes
                .iter()
                .filter(|o| person.is_none() || o.person.as_deref() == person.map(String::as_str))
            {
                row(o.person.as_deref(), Some(o.status), &o.channels);
            }
        }
        Resp::json(
            200,
            &json!({
                "date": date,
                "person": person,
                "time_zone": zone,
                "utc_offset_minutes": offset,
                "counts": {
                    "delivered": counts[0],
                    "held_quiet": counts[1],
                    "held_limit": counts[2],
                    "not_sent": counts[3],
                    "unknown": counts[4],
                    "retrying": counts[5],
                    "failed": counts[6],
                    "partial": counts[7],
                },
                "start_ms": start,
                "end_ms": end,
                "items": items,
            }),
        )
    }

    pub(super) fn test_alert(&mut self, body: &[u8]) -> Resp {
        #[derive(Deserialize)]
        #[serde(deny_unknown_fields)]
        struct B {
            channel: String,
            #[serde(default)]
            person: Option<String>,
            /// Answer at once with a test id and send in the background; read the outcome from
            /// `GET /v1/alerts/tests/<id>`.
            #[serde(default, rename = "async")]
            run_async: bool,
        }
        let b: B = match parse(body) {
            Ok(b) => b,
            Err(r) => return r,
        };
        let known = matches!(
            b.channel.as_str(),
            "email" | "telegram" | "slack" | "sms" | "whatsapp" | "discord" | "teams" | "push"
        ) || b
            .channel
            .strip_prefix("webhook:")
            .is_some_and(|id| self.settings.apps.webhooks.iter().any(|w| w.id == id));
        if !known {
            return Resp::error(
                400,
                "bad_request",
                "channel must be sms, email, telegram, slack, whatsapp, discord, teams, push or webhook:<id>",
            );
        }
        if let Some(p) = &b.person {
            if !self.settings.routing.people.contains_key(p) {
                return Resp::error(404, "not_found", "that person has no routing yet");
            }
        }
        let now = unix_ms();
        let alert = notify::test_alert(now);
        let planned_list = routing::test_plan(
            &self.settings,
            &self.state.telegram.chats,
            b.person.as_deref(),
            &b.channel,
        );
        if b.run_async {
            return self.start_test_run(alert, &b.channel, planned_list, now);
        }
        let deliveries: Vec<crate::notify::Delivery> = match &planned_list {
            Err(why) => vec![crate::notify::Delivery::new(&b.channel, false, why.clone())],
            // A test send answers the person who pressed the button, so it waits, but only as long as the slowest
            // channel's own limit (a mail server gets ten seconds in all), and its channels go side by side.
            Ok(list) => {
                let items: Vec<(routing::Planned, u32)> =
                    list.iter().map(|pl| (pl.clone(), 1)).collect();
                self.channels()
                    .execute_all(
                        &items,
                        &self.settings,
                        &self.state.telegram.chats,
                        &alert,
                        now / 1000,
                        TEST_SEND_BOUND,
                    )
                    .into_iter()
                    .map(|(_, d)| d)
                    .collect()
            }
        };
        let shown = deliveries
            .iter()
            .find(|d| !d.ok)
            .or(deliveries.first())
            .cloned()
            .unwrap_or_else(|| {
                crate::notify::Delivery::new(&b.channel, false, "nothing to send to")
            });
        let planned: Vec<routing::Planned> = planned_list.unwrap_or_default();
        self.record_test(&alert, &b.channel, &planned, deliveries);
        Resp::json(200, &json!({ "delivery": shown }))
    }

    /// What a finished test send leaves behind: a forgotten push device, the alert record and an activity line.
    fn record_test(
        &mut self,
        alert: &Alert,
        channel: &str,
        planned: &[routing::Planned],
        deliveries: Vec<crate::notify::Delivery>,
    ) {
        let all_ok = !deliveries.is_empty() && deliveries.iter().all(|d| d.ok);
        for (pl, d) in planned.iter().zip(&deliveries) {
            if d.detail == channels::push::GONE {
                self.forget_push_device(&pl.target);
            }
        }
        Engine::record(&mut self.state.alerts, alert, deliveries);
        self.save_state();
        self.log_activity(
            "send test alert",
            channel,
            None,
            if all_ok { "delivered" } else { "not delivered" },
        );
    }

    /// The asynchronous test send: answer with an id now, send on the delivery worker, and let the caller read each
    /// channel's outcome from [`App::test_run`] as it arrives.
    fn start_test_run(
        &mut self,
        alert: Alert,
        channel: &str,
        planned_list: Result<Vec<routing::Planned>, String>,
        now: u64,
    ) -> Resp {
        let id = match super::random_hex(8) {
            Ok(id) => id,
            Err(m) => return Resp::error(500, "internal", &m),
        };
        let planned = match planned_list {
            Ok(l) if !l.is_empty() => l,
            other => {
                // Nothing can be sent (not set up yet, or nowhere to send): the answer is already known.
                let why = other.err().unwrap_or_else(|| "nothing to send to".into());
                let d = crate::notify::Delivery::new(channel, false, why);
                if let Ok(mut runs) = self.test_runs.lock() {
                    runs.begin(&id, vec![test_runs::pending(channel, None)], false);
                    runs.set(&id, 0, &d);
                    runs.finish(&id);
                }
                self.record_test(&alert, channel, &[], vec![d]);
                return self.test_run_resp(202, &id);
            }
        };
        let items: Vec<(routing::Planned, u32)> =
            planned.iter().map(|pl| (pl.clone(), 1)).collect();
        if let Ok(mut runs) = self.test_runs.lock() {
            let rows = planned
                .iter()
                .map(|pl| test_runs::pending(&pl.channel, pl.person.as_deref()))
                .collect();
            runs.begin(&id, rows, false);
        }
        let channels = self.channels();
        let (settings, chats) = (self.settings.clone(), self.state.telegram.chats.clone());
        let runs = Arc::clone(&self.test_runs);
        let (run_id, a2, ch) = (id.clone(), alert, channel.to_string());
        let job: Job = Box::new(move || {
            let results = channels.execute_each(
                &items,
                &settings,
                &chats,
                &a2,
                now / 1000,
                TEST_SEND_BOUND,
                |i, d| {
                    if let Ok(mut r) = runs.lock() {
                        r.set(&run_id, i, d);
                    }
                },
            );
            if let Ok(mut r) = runs.lock() {
                r.finish(&run_id);
            }
            Done::TestSent {
                alert: a2,
                channel: ch,
                results,
            }
        });
        if !self.worker.submit_delivery(job) {
            if let Ok(mut runs) = self.test_runs.lock() {
                runs.forget(&id);
            }
            return Resp::error(
                503,
                "busy",
                "alerts are being delivered right now; try again in a moment",
            );
        }
        self.test_run_resp(202, &id)
    }

    fn test_run_resp(&self, status: u16, id: &str) -> Resp {
        match self.test_runs.lock().ok().and_then(|r| r.get(id)) {
            Some(v) => Resp::json(status, &v),
            None => Resp::error(404, "not_found", "no such test send"),
        }
    }

    /// `GET /v1/alerts/tests/<id>`: each channel of a background test send, pending until it answers.
    pub(super) fn test_run(&self, id: &str) -> Resp {
        self.test_run_resp(200, id)
    }

    // ---------- web push devices ----------

    /// The public key a browser subscribes with. The signing key is made the first time it is asked for.
    pub(super) fn push_key(&mut self) -> Resp {
        let ctx = self.channels().ctx();
        let private = match channels::push::ensure_vapid(&ctx) {
            Ok(k) => k,
            Err(e) => return Resp::error(422, "secret_store", &e),
        };
        match channels::push::vapid_public(&private) {
            Ok(k) => Resp::json(200, &json!({ "public_key": k })),
            Err(e) => Resp::error(500, "internal", &e),
        }
    }

    pub(super) fn push_add_device(&mut self, body: &[u8]) -> Resp {
        #[derive(Deserialize)]
        #[serde(deny_unknown_fields)]
        struct Keys {
            p256dh: String,
            auth: String,
        }
        #[derive(Deserialize)]
        #[serde(deny_unknown_fields)]
        struct Sub {
            endpoint: String,
            keys: Keys,
            #[serde(default, rename = "expirationTime")]
            expiration_time: Option<f64>,
        }
        #[derive(Deserialize)]
        #[serde(deny_unknown_fields)]
        struct B {
            person: String,
            label: String,
            subscription: Sub,
        }
        let b: B = match parse(body) {
            Ok(b) => b,
            Err(r) => return r,
        };
        let _ = b.subscription.expiration_time;
        let Some(person) = self.settings.routing.people.get(&b.person) else {
            return Resp::error(404, "not_found", "that person has no routing yet");
        };
        if person.push.len() >= crate::notify_config::MAX_DEVICES {
            return Resp::error(
                400,
                "too_many",
                "eight devices is the most one person can have",
            );
        }
        if b.label.trim().is_empty()
            || b.label.chars().count() > 40
            || b.label.chars().any(char::is_control)
        {
            return Resp::error(400, "invalid_device", "a device needs a short label");
        }
        let sub = &b.subscription;
        if sub.endpoint.len() > 1000 {
            return Resp::error(400, "invalid_device", "the device address is too long");
        }
        if let Err(e) = crate::netguard::check_url(Guard::Public, &sub.endpoint) {
            return Resp::error(400, "invalid_device", e);
        }
        // A push service has a name; an address typed as digits is refused here, and a name that resolves to a
        // private address is refused when the message is sent.
        let endpoint_host = sub
            .endpoint
            .strip_prefix("https://")
            .and_then(|r| r.split(['/', '?', '#']).next())
            .unwrap_or("");
        let bare = endpoint_host
            .rsplit_once(':')
            .map_or(endpoint_host, |(h, p)| {
                if p.bytes().all(|b| b.is_ascii_digit()) {
                    h
                } else {
                    endpoint_host
                }
            })
            .trim_start_matches('[')
            .trim_end_matches(']');
        if bare.parse::<std::net::IpAddr>().is_ok() {
            return Resp::error(
                400,
                "invalid_device",
                "a push service is a host name, not an address",
            );
        }
        // The keys must be what a browser makes: a P-256 point and a 16-byte secret.
        let key_ok = crate::serve::auth::b64::decode_url(&sub.keys.p256dh)
            .is_some_and(|k| k.len() == 65 && k[0] == 4);
        let auth_ok =
            crate::serve::auth::b64::decode_url(&sub.keys.auth).is_some_and(|k| k.len() == 16);
        if !key_ok || !auth_ok {
            return Resp::error(400, "invalid_device", "the device keys are not valid");
        }
        let host = sub
            .endpoint
            .strip_prefix("https://")
            .and_then(|r| r.split(['/', '?', '#']).next())
            .unwrap_or("")
            .to_string();
        let mut raw = [0u8; 6];
        if getrandom::getrandom(&mut raw).is_err() {
            return Resp::error(500, "internal", "no randomness is available");
        }
        let id = notify::hex(&raw);
        for (k, v) in [
            ("push-endpoint-", &sub.endpoint),
            ("push-key-", &sub.keys.p256dh),
            ("push-auth-", &sub.keys.auth),
        ] {
            if let Err(e) = self.secrets.set(&format!("{k}{id}"), v) {
                return Resp::error(422, "secret_store", &e.to_string());
            }
        }
        if let Some(p) = self.settings.routing.people.get_mut(&b.person) {
            p.push.push(crate::notify_config::PushDevice {
                id: id.clone(),
                label: b.label.trim().to_string(),
                host,
            });
        }
        if let Err(r) = self.save_settings() {
            return r;
        }
        self.log_activity("add push device", &id, None, "notifications turned on");
        Resp::json(200, &json!({ "id": id }))
    }

    pub(super) fn push_remove_device(&mut self, id: &str) -> Resp {
        let had = self
            .settings
            .routing
            .people
            .values()
            .any(|p| p.push.iter().any(|d| d.id == id));
        if !had {
            return Resp::error(404, "not_found", "that device is not registered");
        }
        self.forget_push_device(&routing::Target::Push(id.to_string()));
        Resp::json(200, &json!({ "removed": id }))
    }

    /// Link a paired chat to a person (or, with `null`, to nobody).
    pub(super) fn link_chat(&mut self, id: &str, body: &[u8]) -> Resp {
        #[derive(serde::Deserialize)]
        struct B {
            person: Option<String>,
        }
        let Ok(id) = id.parse::<i64>() else {
            return Resp::error(400, "bad_request", "a chat id is a number");
        };
        let b: B = match parse(body) {
            Ok(b) => b,
            Err(r) => return r,
        };
        if let Some(p) = &b.person {
            if !self.settings.routing.people.contains_key(p) {
                return Resp::error(404, "not_found", "that person has no routing yet");
            }
        }
        // a link made with a passkey belongs to the person who made it, and that is not something to reassign
        if self
            .tg
            .store
            .data
            .links
            .iter()
            .any(|l| l.record.chat_id == id && l.state != crate::telegram_store::LinkState::Revoked)
        {
            return Resp::error(409, "passkey_link", "that chat was linked with a passkey by its person: unlink it and link it again to change whose it is");
        }
        let Some(chat) = self.state.telegram.chats.iter_mut().find(|c| c.id == id) else {
            return Resp::error(404, "not_found", "that chat is not paired");
        };
        chat.person = b.person;
        self.save_state();
        self.log_activity("link telegram chat", "-", None, "updated");
        Resp::json(200, &json!({ "chats": self.state.telegram.chats }))
    }

    pub(super) fn unpair(&mut self, id: &str) -> Resp {
        let Ok(id) = id.parse::<i64>() else {
            return Resp::error(400, "bad_request", "a chat id is a number");
        };
        let before = self.state.telegram.chats.len();
        let link = self
            .tg
            .store
            .data
            .links
            .iter()
            .find(|l| {
                l.record.chat_id == id && l.state != crate::telegram_store::LinkState::Revoked
            })
            .map(|l| l.record.id.clone());
        if let Some(lid) = link {
            self.tg_do_revoke(&lid, "revoked_by_owner", unix_ms());
        }
        self.state.telegram.chats.retain(|c| c.id != id);
        if self.state.telegram.chats.len() == before {
            return Resp::error(404, "not_found", "that chat is not paired");
        }
        self.save_state();
        self.log_activity("unpair telegram chat", "-", None, "removed");
        Resp::json(200, &json!({ "chats": self.state.telegram.chats }))
    }

    pub(super) fn add_webhook(&mut self, body: &[u8]) -> Resp {
        #[derive(Deserialize)]
        #[serde(deny_unknown_fields)]
        struct B {
            id: String,
            label: String,
            url: String,
            secret: String,
        }
        let b: B = match parse(body) {
            Ok(b) => b,
            Err(r) => return r,
        };
        if !valid_id(&b.id, 24) || self.settings.apps.webhooks.iter().any(|w| w.id == b.id) {
            return Resp::error(
                400,
                "invalid_webhook",
                "the id must be new and use lower-case letters, digits and dashes",
            );
        }
        if self.settings.apps.webhooks.len() >= 10 {
            return Resp::error(400, "invalid_webhook", "at most 10 webhooks");
        }
        if b.label.trim().is_empty()
            || b.label.chars().count() > 40
            || b.label.chars().any(char::is_control)
        {
            return Resp::error(
                400,
                "invalid_webhook",
                "give the webhook a label of up to 40 characters",
            );
        }
        if let Err(e) = crate::netguard::check_url(Guard::Public, &b.url) {
            return Resp::error(400, "invalid_webhook", e);
        }
        if b.secret.len() < 16 {
            return Resp::error(
                400,
                "invalid_webhook",
                "the signing secret must be at least 16 characters",
            );
        }
        let host = b
            .url
            .trim_start_matches("https://")
            .split(['/', '?', '#'])
            .next()
            .unwrap_or("")
            .to_string();
        let (url_key, secret_key) = (
            format!("webhook-url-{}", b.id),
            format!("webhook-secret-{}", b.id),
        );
        if let Err(e) = self.secrets.set(&url_key, &b.url) {
            return Resp::error(422, "secret_store", &e.to_string());
        }
        if let Err(e) = self.secrets.set(&secret_key, &b.secret) {
            let _ = self.secrets.delete(&url_key);
            return Resp::error(422, "secret_store", &e.to_string());
        }
        self.settings.apps.webhooks.push(WebhookConfig {
            id: b.id.clone(),
            label: b.label.trim().to_string(),
            enabled: true,
            host,
        });
        if let Err(r) = self.save_settings() {
            self.settings.apps.webhooks.retain(|w| w.id != b.id);
            let _ = self.secrets.delete(&url_key);
            let _ = self.secrets.delete(&secret_key);
            return r;
        }
        self.log_activity("add webhook", &b.id, None, "saved, write-only");
        Resp::json(200, &json!({ "id": b.id }))
    }

    pub(super) fn remove_webhook(&mut self, id: &str) -> Resp {
        if !self.settings.apps.webhooks.iter().any(|w| w.id == id) {
            return Resp::error(404, "not_found", "no such webhook");
        }
        self.settings.apps.webhooks.retain(|w| w.id != id);
        if let Err(r) = self.save_settings() {
            return r;
        }
        let _ = self.secrets.delete(&format!("webhook-url-{id}"));
        let _ = self.secrets.delete(&format!("webhook-secret-{id}"));
        self.log_activity("remove webhook", id, None, "removed");
        Resp::json(200, &json!({ "removed": id }))
    }

    /// After a settings save: forget the secrets of providers that were removed.
    pub(super) fn forget_removed(&mut self, old: &crate::settings::Settings) {
        for p in &old.models.providers {
            if !self.settings.models.providers.iter().any(|n| n.id == p.id) {
                let _ = self.secrets.delete(&models::key_name(&p.id));
            }
        }
        // A removed person or device takes its push subscription with it: the address is a capability.
        for d in old.routing.people.values().flat_map(|p| p.push.iter()) {
            let kept = self
                .settings
                .routing
                .people
                .values()
                .any(|p| p.push.iter().any(|n| n.id == d.id));
            if !kept {
                for k in ["push-endpoint-", "push-key-", "push-auth-"] {
                    let _ = self.secrets.delete(&format!("{k}{}", d.id));
                }
            }
        }
        for w in &old.apps.webhooks {
            if !self.settings.apps.webhooks.iter().any(|n| n.id == w.id) {
                let _ = self.secrets.delete(&format!("webhook-url-{}", w.id));
                let _ = self.secrets.delete(&format!("webhook-secret-{}", w.id));
            }
        }
    }

    // ---------- models ----------

    pub(super) fn models(&self) -> Resp {
        let providers: Vec<Value> = self
            .settings
            .models
            .providers
            .iter()
            .map(|p| json!({ "id": p.id, "configured": self.configured(&models::key_name(&p.id)) }))
            .collect();
        Resp::json(
            200,
            &json!({
                "store": self.secrets.label(),
                "providers": providers,
                "spend_note": "Oz Box itself only sends the test message you ask for. Spend by runs is counted under Usage below, as an estimate.",
            }),
        )
    }

    pub(super) fn test_model(&self, id: &str, body: &[u8]) -> Resp {
        #[derive(Deserialize)]
        #[serde(deny_unknown_fields, default)]
        #[derive(Default)]
        struct B {
            confirm: bool,
            model: Option<String>,
        }
        let b: B = if body.is_empty() {
            B::default()
        } else {
            match parse(body) {
                Ok(b) => b,
                Err(r) => return r,
            }
        };
        if !b.confirm {
            return Resp::error(
                400,
                "confirm_required",
                "This sends one tiny request to the provider and can cost a fraction of a cent. Confirm to go ahead.",
            );
        }
        let Some(p) = self.settings.models.providers.iter().find(|p| p.id == id) else {
            return Resp::error(404, "not_found", "no such model provider");
        };
        let model = b
            .model
            .or_else(|| models::default_model_for(&self.settings.models, id).map(str::to_string));
        let Some(model) = model else {
            return Resp::error(
                400,
                "no_model",
                "choose a default model that uses this provider first, or name one to test",
            );
        };
        if model.len() > 100
            || !model
                .bytes()
                .all(|c| c.is_ascii_alphanumeric() || matches!(c, b'.' | b'_' | b':' | b'/' | b'-'))
        {
            return Resp::error(
                400,
                "no_model",
                "that model name has characters that are not allowed",
            );
        }
        match models::test_connection(self.http.as_ref(), self.secrets.as_ref(), p, &model) {
            Ok(r) => Resp::json(200, &json!({ "result": r })),
            Err(e) => Resp::error(409, "not_ready", &e),
        }
    }

    #[allow(dead_code)]
    pub(super) fn paired_chats(&self) -> &[TelegramChat] {
        &self.state.telegram.chats
    }
}

/// What the alert rules need to know about each running box. Slow (it asks the box), so it runs on the worker.
fn observe(
    agent: &dyn super::agent::BoxAgent,
    recs: &[BoxRecord],
    now_ms: u64,
    watch_since_ms: &std::collections::BTreeMap<String, u64>,
) -> Vec<BoxObs> {
    recs.iter()
        .filter(|r| r.state == BoxState::Running)
        .map(|r| {
            let mut o = BoxObs {
                name: r.spec.name.to_string(),
                ..BoxObs::default()
            };
            if let Ok(s) = agent.metrics_now(r, now_ms) {
                o.mem_used_pct = (s.mem_total_bytes > 0).then(|| super::usage::mem_used_pct(&s));
                o.psi_mem = Some(s.psi_mem_some_avg10);
                o.disk_used_pct = (s.disk_total_bytes > 0).then(|| {
                    s.disk_total_bytes.saturating_sub(s.disk_free_bytes) as f64
                        / s.disk_total_bytes as f64
                        * 100.0
                });
            }
            if let Ok(Some(t)) = agent.selftest_last(r, now_ms) {
                o.selftest_failed = t.checks.iter().find_map(|c| match &c.outcome {
                    super::agent::Outcome::Fail { step, .. } => Some(step.clone()),
                    _ => None,
                });
            }
            let since = watch_since_ms
                .get(r.spec.name.as_str())
                .copied()
                .unwrap_or(now_ms);
            if let Ok(list) = agent.incidents(r, since, now_ms) {
                o.incidents = list
                    .into_iter()
                    .map(|i| (i.ts_ms, i.kind, i.detail))
                    .collect();
            }
            o
        })
        .collect()
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use crate::channels::routing;
    use crate::notify;
    use std::collections::HashMap;
    use std::net::{IpAddr, Ipv4Addr, SocketAddr};

    use ozbox_core::{BoxName, BoxSpec, Operation, Size};

    use serde_json::{json, Value};

    use super::super::{App, Req, Resp};
    use crate::netguard::FakeHttp;
    use crate::secrets::{MemorySecrets, SecretStore};
    use std::sync::Arc;

    type TestResult = Result<(), Box<dyn std::error::Error>>;
    const TOKEN: &str = "test-token";
    // 2026-11-09 12:00 UTC: outside the default quiet hours.
    const NOON: u64 = 1_794_182_400_000 + 12 * 3_600_000;
    const SENTINEL: &str = "SENTINEL-s3cret-4711";

    struct Rig {
        app: App,
        http: Arc<FakeHttp>,
        secrets: Arc<MemorySecrets>,
        _dir: tempfile::TempDir,
    }

    fn rig() -> Result<Rig, Box<dyn std::error::Error>> {
        let dir = tempfile::tempdir()?;
        let http = Arc::new(FakeHttp::default());
        let secrets = Arc::new(MemorySecrets::default());
        let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 7878);
        let app = App::new(
            Box::new(ozbox_provider_fake::open(dir.path())),
            true,
            addr,
            TOKEN.into(),
        )
        .with_http(http.clone())
        .with_secrets(secrets.clone());
        Ok(Rig {
            app,
            http,
            secrets,
            _dir: dir,
        })
    }

    fn req(method: &str, path: &str, body: Value) -> Req {
        let mut headers = HashMap::new();
        headers.insert("host".to_string(), "127.0.0.1:7878".to_string());
        headers.insert("authorization".to_string(), format!("Bearer {TOKEN}"));
        Req {
            method: method.into(),
            path: path.into(),
            query: String::new(),
            headers,
            body: if body.is_null() {
                Vec::new()
            } else {
                body.to_string().into_bytes()
            },
        }
    }

    fn call(a: &mut App, method: &str, path: &str, body: Value) -> (u16, Value) {
        let (path, query) = path.split_once('?').unwrap_or((path, ""));
        let mut rq = req(method, path, body);
        rq.query = query.to_string();
        let r = a.handle(&rq);
        (
            r.status,
            serde_json::from_slice(&r.body).unwrap_or(Value::Null),
        )
    }

    fn create(a: &mut App, name: &str, label: Option<(&str, &str)>) -> TestResult {
        let mut spec = BoxSpec::new(BoxName::new(name)?, Size::M);
        if let Some((k, v)) = label {
            spec.labels.insert(k.into(), v.into());
        }
        let p = a.provider.plan(&Operation::Create { spec })?;
        a.provider.apply(&p)?;
        Ok(())
    }

    fn set_settings(a: &mut App, f: impl FnOnce(&mut crate::settings::Settings)) -> TestResult {
        let mut s = a.settings.clone();
        f(&mut s);
        let (st, v) = call(a, "PUT", "/v1/settings", serde_json::to_value(&s)?);
        assert_eq!(st, 200, "{v}");
        Ok(())
    }

    #[test]
    fn a_secret_is_write_only_and_appears_in_no_response() -> TestResult {
        let mut r = rig()?;
        create(&mut r.app, "dev", None)?;
        let a = &mut r.app;
        let (st, _) = call(
            a,
            "PUT",
            "/v1/secrets/email-api-key",
            json!({ "value": SENTINEL }),
        );
        assert_eq!(st, 200);
        assert_eq!(r.secrets.get("email-api-key")?.as_deref(), Some(SENTINEL));
        // A webhook, a model provider, a Telegram token and a Slack address as well.
        let (st, _) = call(
            a,
            "POST",
            "/v1/apps/webhooks",
            json!({ "id": "ci", "label": "CI", "url": format!("https://hooks.example.com/{SENTINEL}"), "secret": format!("{SENTINEL}-signing") }),
        );
        assert_eq!(st, 200);
        set_settings(a, |s| {
            s.models.providers.push(crate::settings::ModelProvider {
                id: "main".into(),
                kind: crate::settings::ModelKind::Anthropic,
                label: "Main".into(),
                base_url: None,
                local_endpoint: false,
                monthly_cap_usd: None,
                region: None,
                resource: None,
                hosted_on: None,
            });
        })?;
        for (n, v) in [
            ("model-key-main", SENTINEL.to_string()),
            ("telegram-bot-token", format!("1:{SENTINEL}")),
            (
                "slack-webhook-url",
                format!("https://hooks.slack.com/{SENTINEL}"),
            ),
        ] {
            assert_eq!(
                call(a, "PUT", &format!("/v1/secrets/{n}"), json!({ "value": v })).0,
                200,
                "{n}"
            );
        }
        // Every readable endpoint, and a spread of error paths: the value is nowhere.
        let mut seen = Vec::new();
        for path in [
            "/v1/info",
            "/v1/settings",
            "/v1/secrets",
            "/v1/apps",
            "/v1/models",
            "/v1/alerts",
            "/v1/activity",
            "/v1/cost",
            "/v1/usage",
            "/v1/boxes",
            "/v1/boxes/dev",
        ] {
            let resp = a.handle(&req("GET", path, Value::Null));
            seen.push((
                path.to_string(),
                String::from_utf8_lossy(&resp.body).into_owned(),
            ));
        }
        for (method, path, body) in [
            (
                "PUT",
                "/v1/secrets/not-a-name",
                json!({ "value": SENTINEL }),
            ),
            (
                "PUT",
                "/v1/secrets/model-key-ghost",
                json!({ "value": SENTINEL }),
            ),
            (
                "PUT",
                "/v1/secrets/email-api-key",
                json!({ "value": format!("bad {SENTINEL}") }),
            ),
            (
                "PUT",
                "/v1/secrets/email-api-key",
                json!({ "value": SENTINEL, "extra": SENTINEL }),
            ),
            (
                "POST",
                "/v1/apps/webhooks",
                json!({ "id": "ci", "label": "x", "url": format!("https://hooks.example.com/{SENTINEL}"), "secret": SENTINEL }),
            ),
            (
                "POST",
                "/v1/apps/webhooks",
                json!({ "id": "x2", "label": "x", "url": format!("http://10.0.0.1/{SENTINEL}"), "secret": format!("{SENTINEL}{SENTINEL}") }),
            ),
            ("POST", "/v1/alerts/test", json!({ "channel": "slack" })),
            ("POST", "/v1/alerts/test", json!({ "channel": "email" })),
            (
                "POST",
                "/v1/alerts/test",
                json!({ "channel": "webhook:ci" }),
            ),
            (
                "POST",
                "/v1/models/main/test",
                json!({ "confirm": true, "model": "m" }),
            ),
        ] {
            let resp = a.handle(&req(method, path, body));
            seen.push((
                format!("{method} {path}"),
                String::from_utf8_lossy(&resp.body).into_owned(),
            ));
        }
        // Also what was sent to the fake provider's endpoints never leaks back; the activity log names, never values.
        for (path, body) in &seen {
            assert!(!body.contains("SENTINEL"), "{path} leaked: {body}");
        }
        let (_, list) = call(a, "GET", "/v1/secrets", Value::Null);
        assert_eq!(list["configured"]["email-api-key"], true);
        assert_eq!(list["configured"]["webhook-secret-ci"], true);
        Ok(())
    }

    #[test]
    fn removing_a_secret_or_a_provider_removes_the_value() -> TestResult {
        let mut r = rig()?;
        let a = &mut r.app;
        r.secrets.set("email-api-key", "abc")?;
        assert_eq!(
            call(a, "DELETE", "/v1/secrets/email-api-key", Value::Null).0,
            200
        );
        assert!(!r.secrets.exists("email-api-key")?);
        set_settings(a, |s| {
            s.models.providers.push(crate::settings::ModelProvider {
                id: "main".into(),
                kind: crate::settings::ModelKind::Openai,
                label: "Main".into(),
                base_url: None,
                local_endpoint: false,
                monthly_cap_usd: None,
                region: None,
                resource: None,
                hosted_on: None,
            });
        })?;
        r.secrets.set("model-key-main", "k")?;
        set_settings(a, |s| s.models.providers.clear())?;
        assert!(
            !r.secrets.exists("model-key-main")?,
            "the key goes with its provider"
        );
        Ok(())
    }

    #[test]
    fn webhooks_refuse_private_and_plain_addresses_and_cannot_be_added_through_settings(
    ) -> TestResult {
        let mut r = rig()?;
        let a = &mut r.app;
        for url in [
            "http://hooks.example.com/x",
            "https://127.0.0.1/x",
            "https://169.254.169.254/latest",
            "https://user:pw@example.com/",
            "ftp://example.com",
        ] {
            let (st, v) = call(
                a,
                "POST",
                "/v1/apps/webhooks",
                json!({ "id": "w", "label": "W", "url": url, "secret": "placeholder-signing-secret" }),
            );
            // the static rules refuse the scheme and credentials; literal private addresses are refused when sending
            if url.starts_with("https://127") || url.contains("169.254") {
                assert_eq!(st, 200, "{url}: {v}");
                let (_, d) = call(
                    a,
                    "POST",
                    "/v1/alerts/test",
                    json!({ "channel": "webhook:w" }),
                );
                assert_eq!(
                    d["delivery"]["ok"], true,
                    "the fake client sends; the real one refuses in netguard tests"
                );
                call(a, "DELETE", "/v1/apps/webhooks/w", Value::Null);
            } else {
                assert_eq!(st, 400, "{url}");
            }
        }
        assert_eq!(call(a, "POST", "/v1/apps/webhooks", json!({ "id": "w", "label": "W", "url": "https://example.com/x", "secret": "short" })).0, 400);
        let mut s = a.settings.clone();
        s.apps.webhooks.push(crate::settings::WebhookConfig {
            id: "sneaky".into(),
            label: "S".into(),
            enabled: true,
            host: "x".into(),
        });
        assert_eq!(
            call(a, "PUT", "/v1/settings", serde_json::to_value(&s)?).0,
            400
        );
        Ok(())
    }

    #[test]
    fn a_test_alert_goes_to_one_channel_and_is_recorded() -> TestResult {
        let mut r = rig()?;
        let a = &mut r.app;
        let (_, v) = call(a, "POST", "/v1/alerts/test", json!({ "channel": "slack" }));
        assert_eq!(v["delivery"]["ok"], false, "no webhook address saved yet");
        r.secrets
            .set("slack-webhook-url", "https://hooks.example.com/abc")?;
        let (st, v) = call(a, "POST", "/v1/alerts/test", json!({ "channel": "slack" }));
        assert_eq!((st, &v["delivery"]["ok"]), (200, &json!(true)));
        assert_eq!(r.http.requests().len(), 1);
        assert_eq!(
            call(
                a,
                "POST",
                "/v1/alerts/test",
                json!({ "channel": "carrier-pigeon" })
            )
            .0,
            400
        );
        let (_, list) = call(a, "GET", "/v1/alerts", Value::Null);
        assert_eq!(list["entries"].as_array().map(Vec::len), Some(2));
        Ok(())
    }

    #[test]
    fn the_tick_sends_a_failed_self_test_once_to_every_enabled_channel() -> TestResult {
        let mut r = rig()?;
        create(&mut r.app, "bad", Some(("sim_profile", "failing")))?;
        create(&mut r.app, "good", None)?;
        r.secrets
            .set("slack-webhook-url", "https://hooks.example.com/abc")?;
        r.secrets
            .set("webhook-url-ci", "https://hooks.example.com/ci")?;
        r.secrets
            .set("webhook-secret-ci", "placeholder-signing-secret")?;
        let a = &mut r.app;
        // webhooks cannot arrive through settings: add it the proper way, then enable slack
        assert_eq!(call(a, "POST", "/v1/apps/webhooks", json!({ "id": "ci", "label": "CI", "url": "https://hooks.example.com/ci", "secret": "placeholder-signing-secret" })).0, 200);
        set_settings(a, |s| s.apps.slack.enabled = true)?;
        r.http.sent.lock().map_err(|_| "lock")?.clear();
        a.tick(NOON);
        let sent = r.http.requests();
        assert_eq!(
            sent.len(),
            2,
            "slack and the webhook, once: {:?}",
            sent.iter().map(|s| s.url.clone()).collect::<Vec<_>>()
        );
        assert!(sent
            .iter()
            .all(
                |s| String::from_utf8_lossy(s.body.as_deref().unwrap_or_default()).contains("bad")
            ));
        // a minute later the same condition is deduped; the day's rate limit is not involved
        a.tick(NOON + 61_000);
        assert_eq!(r.http.requests().len(), 2);
        let (_, list) = call(a, "GET", "/v1/alerts", Value::Null);
        assert_eq!(list["entries"][0]["kind"], "self_test_failed");
        assert_eq!(
            list["entries"][0]["deliveries"].as_array().map(Vec::len),
            Some(2)
        );
        Ok(())
    }

    #[test]
    fn the_old_telegram_pairing_is_gone_and_a_chat_on_the_list_is_linked_to_a_person_and_removed(
    ) -> TestResult {
        let mut r = rig()?;
        create(&mut r.app, "dev", None)?;
        let a = &mut r.app;
        // a code the dashboard makes and a chat sends is the design that bound whoever sent it first: it is not a route any more
        assert_eq!(
            call(a, "POST", "/v1/apps/telegram/pairing", Value::Null).0,
            404
        );
        // a chat linked the old way is on the list that receives alerts
        a.state.telegram.chats.push(crate::state::TelegramChat {
            id: 7,
            name: "Ada".into(),
            person: None,
        });
        assert_eq!(
            call(
                a,
                "PUT",
                "/v1/apps/telegram/chats/7",
                json!({ "person": "ada" })
            )
            .0,
            404,
            "no such person yet"
        );
        set_settings(a, |s| {
            s.routing
                .people
                .insert("ada".into(), crate::notify_config::PersonRouting::default());
        })?;
        let (st, v) = call(
            a,
            "PUT",
            "/v1/apps/telegram/chats/7",
            json!({ "person": "ada" }),
        );
        assert_eq!((st, v["chats"][0]["person"].clone()), (200, json!("ada")));
        assert_eq!(
            call(
                a,
                "PUT",
                "/v1/apps/telegram/chats/99",
                json!({ "person": null })
            )
            .0,
            404
        );
        assert_eq!(
            call(a, "DELETE", "/v1/apps/telegram/chats/7", Value::Null).0,
            200
        );
        assert_eq!(
            call(a, "DELETE", "/v1/apps/telegram/chats/7", Value::Null).0,
            404
        );
        Ok(())
    }

    #[test]
    fn a_model_test_needs_confirmation_and_a_default_model() -> TestResult {
        let mut r = rig()?;
        let a = &mut r.app;
        set_settings(a, |s| {
            s.models.providers.push(crate::settings::ModelProvider {
                id: "main".into(),
                kind: crate::settings::ModelKind::Anthropic,
                label: "Main".into(),
                base_url: None,
                local_endpoint: false,
                monthly_cap_usd: Some(50.0),
                region: None,
                resource: None,
                hosted_on: None,
            });
        })?;
        r.secrets.set("model-key-main", SENTINEL)?;
        let (st, v) = call(a, "POST", "/v1/models/main/test", json!({}));
        assert_eq!((st, v["code"].as_str()), (400, Some("confirm_required")));
        assert!(r.http.requests().is_empty(), "nothing is sent unconfirmed");
        let (st, v) = call(
            a,
            "POST",
            "/v1/models/main/test",
            json!({ "confirm": true }),
        );
        assert_eq!((st, v["code"].as_str()), (400, Some("no_model")));
        set_settings(a, |s| {
            s.models.defaults.coding = Some(crate::settings::ModelChoice {
                provider_id: "main".into(),
                model: "some-model".into(),
            })
        })?;
        let (st, v) = call(
            a,
            "POST",
            "/v1/models/main/test",
            json!({ "confirm": true }),
        );
        assert_eq!((st, &v["result"]["ok"]), (200, &json!(true)));
        assert_eq!(r.http.requests().len(), 1);
        assert_eq!(
            call(
                a,
                "POST",
                "/v1/models/ghost/test",
                json!({ "confirm": true })
            )
            .0,
            404
        );
        // defaults must name a provider that exists
        let mut s = a.settings.clone();
        s.models.defaults.chat = Some(crate::settings::ModelChoice {
            provider_id: "ghost".into(),
            model: "m".into(),
        });
        assert_eq!(
            call(a, "PUT", "/v1/settings", serde_json::to_value(&s)?).0,
            400
        );
        Ok(())
    }

    #[test]
    fn the_cost_estimate_labels_its_basis_and_leaves_unknown_prices_unknown() -> TestResult {
        let mut r = rig()?;
        create(&mut r.app, "dev", None)?;
        let a = &mut r.app;
        let (st, v) = call(a, "GET", "/v1/cost", Value::Null);
        assert_eq!(st, 200);
        assert_eq!(v["basis"], "estimate");
        assert!(
            v["boxes"][0]["run_rate_month"].is_null(),
            "no price is known, so none is shown"
        );
        assert_eq!(v["fleet"]["unpriced"][0], "dev");
        assert!(v["fleet"]["run_rate_month"].is_null());
        set_settings(a, |s| {
            s.budget.size_prices_usd.insert("M".into(), 73.0);
        })?;
        let (_, v) = call(a, "GET", "/v1/cost", Value::Null);
        assert_eq!(v["boxes"][0]["source"], "entered");
        assert_eq!(
            v["boxes"][0]["run_rate_month"]
                .as_f64()
                .map(|x| (x * 100.0).round()),
            Some(7300.0)
        );
        assert_eq!(v["currency"], "USD");
        // the demo provider has no public price list
        assert_eq!(call(a, "POST", "/v1/cost/refresh", Value::Null).0, 501);
        Ok(())
    }

    #[test]
    fn errors_have_the_code_and_message_shape() {
        let r: Resp = Resp::error(400, "bad_request", "nope");
        let v: Value = serde_json::from_slice(&r.body).unwrap_or(Value::Null);
        assert_eq!(
            (v["code"].as_str(), v["message"].as_str()),
            (Some("bad_request"), Some("nope"))
        );
    }

    fn sms_person(a: &mut App) -> TestResult {
        set_settings(a, |s| {
            s.locale.time_zone = Some("Africa/Lagos".into());
            s.apps.sms.enabled = true;
            s.apps.sms.from = "+15005550006".into();
            s.apps.push.enabled = true;
            s.routing.people.insert(
                "ada".into(),
                crate::notify_config::PersonRouting {
                    phone: Some("+2348012345678".into()),
                    urgent: crate::notify_config::Route {
                        channels: vec!["sms".into()],
                        bypass_quiet: true,
                    },
                    normal: crate::notify_config::Route {
                        channels: vec!["sms".into()],
                        bypass_quiet: false,
                    },
                    ..Default::default()
                },
            );
        })
    }

    #[test]
    fn new_channel_secrets_are_write_only_and_only_the_right_hosts_are_accepted() -> TestResult {
        let mut r = rig()?;
        let a = &mut r.app;
        for (n, v) in [
            ("sms-account", format!("AC{SENTINEL}")),
            ("sms-secret", SENTINEL.to_string()),
            ("smtp-password", SENTINEL.to_string()),
            ("whatsapp-token", SENTINEL.to_string()),
            (
                "discord-webhook-url",
                format!("https://discord.com/api/webhooks/1/{SENTINEL}"),
            ),
            (
                "teams-webhook-url",
                format!("https://x.logic.azure.com/workflows/{SENTINEL}"),
            ),
        ] {
            assert_eq!(
                call(a, "PUT", &format!("/v1/secrets/{n}"), json!({ "value": v })).0,
                200,
                "{n}"
            );
        }
        for (n, v) in [
            (
                "discord-webhook-url",
                "https://evil.example/api/webhooks/1/x",
            ),
            ("discord-webhook-url", "https://127.0.0.1/api/webhooks/1/x"),
            ("teams-webhook-url", "https://evil.example/x"),
            ("teams-webhook-url", "http://x.logic.azure.com/x"),
            ("sms-secret", "abc"),
        ] {
            assert_eq!(
                call(a, "PUT", &format!("/v1/secrets/{n}"), json!({ "value": v })).0,
                400,
                "{n} {v}"
            );
        }
        // The push signing key and device secrets are made by the server, never through the generic route.
        for n in ["vapid-private-key", "push-endpoint-abc", "push-auth-abc"] {
            assert_eq!(
                call(
                    a,
                    "PUT",
                    &format!("/v1/secrets/{n}"),
                    json!({ "value": "abcdefgh" })
                )
                .0,
                404,
                "{n}"
            );
        }
        for path in ["/v1/settings", "/v1/secrets", "/v1/apps", "/v1/activity"] {
            let body =
                String::from_utf8_lossy(&a.handle(&req("GET", path, Value::Null)).body).to_string();
            assert!(!body.contains(SENTINEL), "{path}");
        }
        let (_, apps) = call(a, "GET", "/v1/apps", Value::Null);
        assert_eq!(apps["discord"]["configured"], true);
        assert_eq!(
            apps["whatsapp"]["configured"], false,
            "the template is not set"
        );
        Ok(())
    }

    #[test]
    fn a_routed_urgent_alert_texts_the_person_and_a_busy_service_is_retried_with_backoff(
    ) -> TestResult {
        let mut r = rig()?;
        create(&mut r.app, "bad", Some(("sim_profile", "failing")))?;
        r.secrets.set("sms-account", "ACtest123")?;
        r.secrets.set("sms-secret", "token123")?;
        let a = &mut r.app;
        sms_person(a)?;
        r.http.sent.lock().map_err(|_| "lock")?.clear();
        r.http.reply(503, "{}");
        a.tick(NOON);
        let sent = r.http.requests();
        assert_eq!(
            sent.len(),
            1,
            "{:?}",
            sent.iter().map(|s| s.url.clone()).collect::<Vec<_>>()
        );
        assert!(sent[0]
            .url
            .starts_with("https://api.twilio.com/2010-04-01/Accounts/ACtest123/"));
        let body = String::from_utf8_lossy(sent[0].body.as_deref().unwrap_or_default()).to_string();
        assert!(body.contains("To=%2B2348012345678") && body.contains("bad"));
        let (_, list) = call(a, "GET", "/v1/alerts", Value::Null);
        let d = &list["entries"][0]["deliveries"][0];
        assert_eq!(
            (
                d["channel"].as_str(),
                d["ok"].as_bool(),
                d["person"].as_str()
            ),
            (Some("sms"), Some(false), Some("ada"))
        );
        assert_eq!(a.state.alerts.retries.len(), 1);
        // Too early: nothing. After the first backoff: sent again, and the second attempt is recorded.
        a.tick(NOON + 30_000);
        assert_eq!(r.http.requests().len(), 1);
        r.http.reply(201, r#"{"sid":"SM1"}"#);
        a.tick(NOON + 62_000);
        assert_eq!(r.http.requests().len(), 2);
        assert!(a.state.alerts.retries.is_empty());
        let (_, list) = call(a, "GET", "/v1/alerts", Value::Null);
        let ds = list["entries"][0]["deliveries"]
            .as_array()
            .ok_or("deliveries")?;
        assert_eq!(ds.len(), 2);
        assert_eq!(
            (ds[1]["ok"].as_bool(), ds[1]["attempts"].as_u64()),
            (Some(true), Some(2))
        );
        Ok(())
    }

    fn first_alert(a: &mut App) -> Value {
        let (_, list) = call(a, "GET", "/v1/alerts", Value::Null);
        list["entries"][0].clone()
    }

    #[test]
    fn an_alert_reads_retrying_until_a_try_succeeds_and_only_then_delivered() -> TestResult {
        let mut r = rig()?;
        create(&mut r.app, "bad", Some(("sim_profile", "failing")))?;
        r.secrets.set("sms-account", "ACtest123")?;
        r.secrets.set("sms-secret", "token123")?;
        let a = &mut r.app;
        sms_person(a)?;
        r.http.reply(503, "{}");
        a.tick(NOON);
        let e = first_alert(a);
        assert_eq!(e["outcome"], "retrying", "{e}");
        assert_eq!(e["outcomes"][0]["status"], "retrying");
        assert_eq!(e["outcomes"][0]["results"][0]["state"], "retrying");
        r.http.reply(201, r#"{"sid":"SM1"}"#);
        a.tick(NOON + 62_000);
        let e = first_alert(a);
        assert_eq!(e["outcome"], "delivered", "{e}");
        assert_eq!(e["outcomes"][0]["results"][0]["state"], "sent");
        assert_eq!(e["outcomes"][0]["results"][0]["attempts"], 2);
        Ok(())
    }

    #[test]
    fn an_alert_whose_every_try_fails_ends_failed_with_the_reason_and_a_refusal_at_once(
    ) -> TestResult {
        let mut r = rig()?;
        create(&mut r.app, "bad", Some(("sim_profile", "failing")))?;
        r.secrets.set("sms-account", "ACtest123")?;
        r.secrets.set("sms-secret", "token123")?;
        let a = &mut r.app;
        sms_person(a)?;
        for _ in 0..4 {
            r.http.reply(503, "{}");
        }
        let mut t = NOON;
        a.tick(t);
        for wait in [61_000, 301_000, 901_000] {
            assert_eq!(first_alert(a)["outcome"], "retrying");
            t += wait;
            a.tick(t);
        }
        let e = first_alert(a);
        assert_eq!(e["outcome"], "failed", "{e}");
        let res = &e["outcomes"][0]["results"][0];
        assert_eq!(res["state"], "failed");
        assert_eq!(res["attempts"], 4);
        assert_eq!(res["detail"], "the service answered HTTP 503");
        assert!(a.state.alerts.retries.is_empty());
        assert_eq!(r.http.requests().len(), 4);

        // A refusal is final on the first try.
        let mut r = rig()?;
        create(&mut r.app, "bad", Some(("sim_profile", "failing")))?;
        r.secrets.set("sms-account", "ACtest123")?;
        r.secrets.set("sms-secret", "token123")?;
        let a = &mut r.app;
        sms_person(a)?;
        r.http.reply(401, "{}");
        a.tick(NOON);
        let e = first_alert(a);
        assert_eq!(e["outcome"], "failed", "{e}");
        assert_eq!(e["outcomes"][0]["results"][0]["state"], "refused");
        assert!(a.state.alerts.retries.is_empty());
        Ok(())
    }

    #[test]
    fn a_test_send_goes_to_the_persons_number_and_says_why_when_it_cannot() -> TestResult {
        let mut r = rig()?;
        r.secrets.set("sms-account", "ACtest123")?;
        r.secrets.set("sms-secret", "token123")?;
        let a = &mut r.app;
        let (st, v) = call(a, "POST", "/v1/alerts/test", json!({ "channel": "sms" }));
        assert_eq!(st, 200);
        assert_eq!(v["delivery"]["ok"], false, "no one is set up yet");
        sms_person(a)?;
        r.http.reply(201, "{}");
        let (_, v) = call(
            a,
            "POST",
            "/v1/alerts/test",
            json!({ "channel": "sms", "person": "ada" }),
        );
        assert_eq!(v["delivery"]["ok"], true);
        assert_eq!(r.http.requests().len(), 1);
        let (_, v) = call(
            a,
            "POST",
            "/v1/alerts/test",
            json!({ "channel": "push", "person": "ada" }),
        );
        assert!(v["delivery"]["detail"]
            .as_str()
            .unwrap_or("")
            .contains("no device"));
        assert_eq!(
            call(
                a,
                "POST",
                "/v1/alerts/test",
                json!({ "channel": "sms", "person": "ghost" })
            )
            .0,
            404
        );
        assert_eq!(
            call(a, "POST", "/v1/alerts/test", json!({ "channel": "fax" })).0,
            400
        );
        Ok(())
    }

    #[test]
    fn a_push_device_is_registered_checked_and_forgotten() -> TestResult {
        let mut r = rig()?;
        let a = &mut r.app;
        sms_person(a)?;
        let (st, v) = call(a, "GET", "/v1/push/key", Value::Null);
        assert_eq!(st, 200);
        assert_eq!(v["public_key"].as_str().map(str::len), Some(87));
        assert!(r.secrets.exists("vapid-private-key")?);
        let key = {
            use ring::rand::SystemRandom;
            let k = ring::agreement::EphemeralPrivateKey::generate(
                &ring::agreement::ECDH_P256,
                &SystemRandom::new(),
            )
            .map_err(|_| "key")?;
            crate::serve::auth::b64::encode_url(k.compute_public_key().map_err(|_| "pub")?.as_ref())
        };
        let sub = |endpoint: &str, key: &str, auth: &str| json!({ "person": "ada", "label": "Phone", "subscription": { "endpoint": endpoint, "keys": { "p256dh": key, "auth": auth } } });
        let auth = crate::serve::auth::b64::encode_url(&[7u8; 16]);
        for bad in [
            sub("https://127.0.0.1/x", &key, &auth),
            sub("http://fcm.googleapis.com/x", &key, &auth),
            sub("https://fcm.googleapis.com/x", "AAAA", &auth),
            sub("https://fcm.googleapis.com/x", &key, "AAAA"),
        ] {
            assert_eq!(call(a, "POST", "/v1/push/devices", bad).0, 400);
        }
        let mut ghost = sub("https://fcm.googleapis.com/fcm/send/abc", &key, &auth);
        ghost["person"] = json!("ghost");
        assert_eq!(call(a, "POST", "/v1/push/devices", ghost).0, 404);
        let (st, v) = call(
            a,
            "POST",
            "/v1/push/devices",
            sub("https://fcm.googleapis.com/fcm/send/abc", &key, &auth),
        );
        assert_eq!(st, 200);
        let id = v["id"].as_str().ok_or("id")?.to_string();
        assert!(r.secrets.exists(&format!("push-endpoint-{id}"))?);
        let (_, s) = call(a, "GET", "/v1/settings", Value::Null);
        assert_eq!(
            s["settings"]["routing"]["people"]["ada"]["push"][0]["host"],
            "fcm.googleapis.com"
        );
        assert!(
            !s.to_string().contains("/fcm/send/abc"),
            "the address is a secret"
        );
        // Without a sender address the push service cannot be told who is calling: say so instead of sending.
        let (_, v) = call(
            a,
            "POST",
            "/v1/alerts/test",
            json!({ "channel": "push", "person": "ada" }),
        );
        assert!(v["delivery"]["detail"]
            .as_str()
            .unwrap_or("")
            .contains("sender address"));
        set_settings(a, |s| s.apps.email.from = "alerts@example.com".into())?;
        // A push service that says 410 gets the device forgotten.
        r.http.reply(410, "");
        let (_, v) = call(
            a,
            "POST",
            "/v1/alerts/test",
            json!({ "channel": "push", "person": "ada" }),
        );
        assert_eq!(v["delivery"]["ok"], false);
        assert!(!r.secrets.exists(&format!("push-endpoint-{id}"))?);
        assert_eq!(
            call(a, "DELETE", &format!("/v1/push/devices/{id}"), Value::Null).0,
            404
        );
        Ok(())
    }

    #[test]
    fn only_the_device_that_is_gone_is_forgotten_and_removing_a_person_removes_their_devices(
    ) -> TestResult {
        let mut r = rig()?;
        let a = &mut r.app;
        sms_person(a)?;
        set_settings(a, |s| s.apps.email.from = "alerts@example.com".into())?;
        assert_eq!(call(a, "GET", "/v1/push/key", Value::Null).0, 200);
        let key = {
            let k = ring::agreement::EphemeralPrivateKey::generate(
                &ring::agreement::ECDH_P256,
                &ring::rand::SystemRandom::new(),
            )
            .map_err(|_| "key")?;
            crate::serve::auth::b64::encode_url(k.compute_public_key().map_err(|_| "pub")?.as_ref())
        };
        let auth = crate::serve::auth::b64::encode_url(&[7u8; 16]);
        let mut ids = Vec::new();
        for n in 0..2 {
            let (st, v) = call(
                a,
                "POST",
                "/v1/push/devices",
                json!({ "person": "ada", "label": format!("D{n}"), "subscription": { "endpoint": format!("https://fcm.googleapis.com/fcm/send/{n}"), "keys": { "p256dh": key, "auth": auth } } }),
            );
            assert_eq!(st, 200);
            ids.push(v["id"].as_str().ok_or("id")?.to_string());
        }
        // The first device answers, the second is gone.
        r.http.reply(201, "");
        r.http.reply(410, "");
        call(
            a,
            "POST",
            "/v1/alerts/test",
            json!({ "channel": "push", "person": "ada" }),
        );
        // The two sends go side by side, so which device took the 410 is not fixed: exactly one is forgotten.
        let mut kept = Vec::new();
        for id in &ids {
            if r.secrets.exists(&format!("push-endpoint-{id}"))? {
                kept.push(id.clone());
            }
        }
        assert_eq!(kept.len(), 1, "only the device that is gone is forgotten");
        // Removing the person through settings forgets the remaining device's secrets too.
        set_settings(a, |s| {
            s.routing.people.clear();
        })?;
        for k in ["push-endpoint-", "push-key-", "push-auth-"] {
            assert!(!r.secrets.exists(&format!("{k}{}", kept[0]))?, "{k}");
        }
        Ok(())
    }
    /// An HTTP client that holds every request until the test lets it go, to stand in for a slow service.
    struct GateHttp {
        open: std::sync::Mutex<bool>,
        cv: std::sync::Condvar,
    }

    impl GateHttp {
        fn new() -> Arc<Self> {
            Arc::new(Self {
                open: std::sync::Mutex::new(false),
                cv: std::sync::Condvar::new(),
            })
        }

        fn release(&self) {
            if let Ok(mut o) = self.open.lock() {
                *o = true;
            }
            self.cv.notify_all();
        }
    }

    impl crate::netguard::HttpClient for GateHttp {
        fn send(
            &self,
            _req: &crate::netguard::HttpRequest,
        ) -> Result<crate::netguard::HttpResponse, crate::netguard::HttpError> {
            let mut open = self
                .open
                .lock()
                .map_err(|_| crate::netguard::HttpError::Transport("gate"))?;
            while !*open {
                open = self
                    .cv
                    .wait(open)
                    .map_err(|_| crate::netguard::HttpError::Transport("gate"))?;
            }
            Ok(crate::netguard::HttpResponse {
                status: 200,
                body: "ok".into(),
            })
        }
    }

    fn gated_app(
        dir: &std::path::Path,
        gate: Arc<GateHttp>,
    ) -> Result<App, Box<dyn std::error::Error>> {
        let secrets = Arc::new(MemorySecrets::default());
        secrets.set("slack-webhook-url", "https://hooks.example.com/abc")?;
        let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 7878);
        let mut app = App::new(
            Box::new(ozbox_provider_fake::open(dir)),
            true,
            addr,
            TOKEN.into(),
        )
        .with_http(gate)
        .with_secrets(secrets)
        .with_background_worker();
        set_settings(&mut app, |s| s.apps.slack.enabled = true)?;
        Ok(app)
    }

    #[test]
    fn an_async_test_send_answers_at_once_and_each_channel_reports_when_it_finishes() -> TestResult
    {
        let dir = tempfile::tempdir()?;
        let gate = GateHttp::new();
        let mut app = gated_app(dir.path(), gate.clone())?;
        let a = &mut app;
        let started = std::time::Instant::now();
        let (st, v) = call(
            a,
            "POST",
            "/v1/alerts/test",
            json!({ "channel": "slack", "async": true }),
        );
        assert_eq!(st, 202, "{v}");
        assert!(
            started.elapsed() < std::time::Duration::from_secs(2),
            "the request did not wait for the slow channel"
        );
        let id = v["id"].as_str().ok_or("id")?.to_string();
        assert_eq!(v["state"], "running");
        assert_eq!(v["items"][0]["channel"], "slack");
        assert_eq!(v["items"][0]["status"], "pending");
        // Still waiting on the service: the poll says so, and other requests are served.
        let (st, v) = call(a, "GET", &format!("/v1/alerts/tests/{id}"), Value::Null);
        assert_eq!((st, v["state"].as_str()), (200, Some("running")));
        assert_eq!(v["items"][0]["status"], "pending");
        assert_eq!(call(a, "GET", "/v1/alerts", Value::Null).0, 200);
        gate.release();
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
        let done = loop {
            a.apply_done(NOON);
            let (_, v) = call(a, "GET", &format!("/v1/alerts/tests/{id}"), Value::Null);
            if v["state"] == "done" || std::time::Instant::now() > deadline {
                break v;
            }
            std::thread::sleep(std::time::Duration::from_millis(10));
        };
        assert_eq!(done["state"], "done", "{done}");
        assert_eq!(done["items"][0]["status"], "sent");
        // The finished test is recorded like a synchronous one.
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
        loop {
            a.apply_done(NOON);
            let (_, list) = call(a, "GET", "/v1/alerts", Value::Null);
            if list["entries"].as_array().is_some_and(|e| !e.is_empty())
                || std::time::Instant::now() > deadline
            {
                assert_eq!(list["entries"][0]["kind"], "test");
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(10));
        }
        assert_eq!(call(a, "GET", "/v1/alerts/tests/nope", Value::Null).0, 404);
        Ok(())
    }

    #[test]
    fn an_async_test_send_with_nothing_set_up_is_already_finished_and_says_why() -> TestResult {
        let mut r = rig()?;
        let a = &mut r.app;
        let (st, v) = call(
            a,
            "POST",
            "/v1/alerts/test",
            json!({ "channel": "sms", "async": true }),
        );
        assert_eq!(st, 202, "{v}");
        assert_eq!(v["state"], "done");
        assert_eq!(v["items"][0]["status"], "failed");
        assert!(v["items"][0]["detail"]
            .as_str()
            .is_some_and(|d| !d.is_empty()));
        let id = v["id"].as_str().ok_or("id")?;
        let (st, again) = call(a, "GET", &format!("/v1/alerts/tests/{id}"), Value::Null);
        assert_eq!((st, &again), (200, &v));
        // The synchronous call is unchanged for a caller that does not ask for the new behaviour.
        let (st, v) = call(a, "POST", "/v1/alerts/test", json!({ "channel": "sms" }));
        assert_eq!((st, v["delivery"]["ok"].clone()), (200, json!(false)));
        // An unknown field is still refused.
        assert_eq!(
            call(
                a,
                "POST",
                "/v1/alerts/test",
                json!({ "channel": "sms", "later": true })
            )
            .0,
            400
        );
        Ok(())
    }
    fn seeded(
        key: &str,
        kind: &str,
        ts_ms: u64,
        outcomes: Vec<(&str, routing::DigestStatus, &[&str])>,
    ) -> crate::notify::RecentAlert {
        let outcomes: Vec<routing::AlertOutcome> = outcomes
            .into_iter()
            .map(|(p, status, ch)| routing::AlertOutcome {
                person: Some(p.into()),
                status,
                channels: ch.iter().map(|c| (*c).into()).collect(),
                results: Vec::new(),
            })
            .collect();
        crate::notify::RecentAlert {
            ts_ms,
            key: key.into(),
            kind: kind.into(),
            severity: notify::Severity::Normal,
            box_name: None,
            title: format!("Title {key}"),
            body: String::new(),
            deliveries: Vec::new(),
            outcome: routing::DigestStatus::overall(&outcomes),
            outcomes,
        }
    }

    #[test]
    fn the_summary_day_follows_each_ends_own_offset_on_a_clock_change_day() -> TestResult {
        use routing::DigestStatus::Delivered;
        let mut r = rig()?;
        let a = &mut r.app;
        sms_person(a)?;
        let h = 3_600_000;
        // New York, 2026-11-01: the clocks go back, so the day runs 04:00 UTC to 05:00 UTC the next day (25 hours).
        let start = 1_793_505_600_000; // 2026-11-01T04:00:00Z
        a.state.alerts.recent = vec![
            seeded(
                "before",
                "disk",
                start - 1,
                vec![("ada", Delivered, &["sms"])],
            ),
            seeded("first", "disk", start, vec![("ada", Delivered, &["sms"])]),
            // 04:30 UTC on the 2nd is 23:30 EST on the 1st: still the same day, an hour past a 24-hour day.
            seeded(
                "late",
                "disk",
                start + 24 * h + h / 2,
                vec![("ada", Delivered, &["sms"])],
            ),
            seeded(
                "after",
                "disk",
                start + 25 * h,
                vec![("ada", Delivered, &["sms"])],
            ),
        ];
        a.settings
            .routing
            .people
            .get_mut("ada")
            .ok_or("ada")?
            .time_zone = Some("America/New_York".into());
        let (st, v) = call(
            a,
            "GET",
            "/v1/alerts/summary?date=2026-11-01&person=ada",
            Value::Null,
        );
        assert_eq!(st, 200, "{v}");
        assert_eq!(v["time_zone"], "America/New_York");
        assert_eq!(
            (v["start_ms"].as_u64(), v["end_ms"].as_u64()),
            (Some(start), Some(start + 25 * h))
        );
        let keys: Vec<&str> = v["items"]
            .as_array()
            .ok_or("items")?
            .iter()
            .filter_map(|i| i["key"].as_str())
            .collect();
        assert_eq!(keys, ["late", "first"]);
        // Spring forward, 2026-03-08: 23 hours, from 05:00 UTC to 04:00 UTC the next day.
        let (_, v) = call(
            a,
            "GET",
            "/v1/alerts/summary?date=2026-03-08&person=ada",
            Value::Null,
        );
        let (s, e) = (
            v["start_ms"].as_u64().ok_or("s")?,
            v["end_ms"].as_u64().ok_or("e")?,
        );
        assert_eq!(e - s, 23 * h);
        // The fleet's zone (Lagos, no daylight saving) is always 24 hours.
        let (_, v) = call(a, "GET", "/v1/alerts/summary?date=2026-11-01", Value::Null);
        assert_eq!(v["time_zone"], "Africa/Lagos");
        assert_eq!(
            v["end_ms"].as_u64().ok_or("e")? - v["start_ms"].as_u64().ok_or("s")?,
            24 * h
        );
        Ok(())
    }

    #[test]
    fn the_daily_summary_lists_one_days_alerts_with_what_became_of_each() -> TestResult {
        use routing::DigestStatus::{Delivered, HeldLimit, HeldQuiet};
        let mut r = rig()?;
        let a = &mut r.app;
        sms_person(a)?; // time zone Africa/Lagos, UTC+1
        let h = 3_600_000;
        a.state.alerts.recent = vec![
            // 22:30 UTC on the 8th is 23:30 on the 8th in Lagos: the day before.
            seeded(
                "before",
                "disk",
                NOON - 13 * h - h / 2,
                vec![("ada", Delivered, &["sms"])],
            ),
            seeded(
                "a",
                "disk",
                NOON,
                vec![("ada", Delivered, &["sms", "push"])],
            ),
            seeded(
                "b",
                "memory",
                NOON + h,
                vec![("ada", HeldLimit, &["sms"]), ("bo", HeldQuiet, &["push"])],
            ),
            seeded("old", "budget", NOON + 2 * h, Vec::new()),
            seeded(
                "t",
                "test",
                NOON + 3 * h,
                vec![("ada", Delivered, &["sms"])],
            ),
            seeded("d", "digest", NOON + 3 * h, Vec::new()),
            // 23:30 UTC on the 9th is 00:30 on the 10th in Lagos: the day after.
            seeded(
                "after",
                "disk",
                NOON + 11 * h + h / 2,
                vec![("ada", Delivered, &["sms"])],
            ),
        ];
        let (st, v) = call(a, "GET", "/v1/alerts/summary?date=2026-11-09", Value::Null);
        assert_eq!(st, 200, "{v}");
        assert_eq!(v["date"], "2026-11-09");
        assert_eq!(v["time_zone"], "Africa/Lagos");
        let keys: Vec<&str> = v["items"]
            .as_array()
            .ok_or("items")?
            .iter()
            .filter_map(|i| i["key"].as_str())
            .collect();
        assert_eq!(
            keys,
            ["old", "b", "b", "a"],
            "newest first; test, digest and other days left out"
        );
        assert_eq!(
            v["counts"],
            json!({"delivered":1,"held_quiet":1,"held_limit":1,"not_sent":0,"unknown":1,"retrying":0,"failed":0,"partial":0})
        );
        let item = &v["items"][3];
        assert_eq!(
            (item["person"].clone(), item["status"].clone()),
            (json!("ada"), json!("delivered"))
        );
        assert_eq!(item["channels"], json!(["sms", "push"]));
        assert!(
            v["items"][0]["status"].is_null(),
            "an alert from before outcomes were kept has no status"
        );
        // One person's view.
        set_settings(a, |s| {
            let ada = s.routing.people["ada"].clone();
            s.routing.people.insert("bo".into(), ada);
        })?;
        let (_, v) = call(
            a,
            "GET",
            "/v1/alerts/summary?date=2026-11-09&person=bo",
            Value::Null,
        );
        let rows = v["items"].as_array().ok_or("items")?;
        assert_eq!(
            (rows.len(), rows[0]["status"].clone()),
            (1, json!("held_quiet"))
        );
        // Bad input.
        for bad in ["date=yesterday", "date=2026-13-40", "date=2026-11-9"] {
            assert_eq!(
                call(a, "GET", &format!("/v1/alerts/summary?{bad}"), Value::Null).0,
                400,
                "{bad}"
            );
        }
        assert_eq!(
            call(a, "GET", "/v1/alerts/summary?person=ghost", Value::Null).0,
            404
        );
        let (st, v) = call(a, "GET", "/v1/alerts/summary", Value::Null);
        assert_eq!(st, 200, "today by default");
        assert_eq!(v["date"].as_str().map(str::len), Some(10));
        assert_eq!(call(a, "POST", "/v1/alerts/summary", Value::Null).0, 405);
        Ok(())
    }

    #[test]
    fn an_alert_the_hourly_limit_refused_is_listed_as_not_sent() -> TestResult {
        let mut r = rig()?;
        let a = &mut r.app;
        sms_person(a)?;
        let now = NOON;
        a.state.alerts.sent_ms = vec![now; notify::HOURLY_CAP];
        let alert = notify::Alert {
            key: "k".into(),
            kind: "disk".into(),
            severity: notify::Severity::Normal,
            box_name: Some("dev".into()),
            title: "Disk".into(),
            body: String::new(),
            ts_ms: now,
        };
        let (admitted, dropped) =
            notify::Engine::admit_split(&mut a.state.alerts, vec![alert], now);
        assert!(admitted.is_empty());
        routing::note_dropped(&a.settings, &mut a.state.alerts, &dropped);
        for d in &dropped {
            notify::Engine::record(&mut a.state.alerts, d, Vec::new());
        }
        let (_, list) = call(a, "GET", "/v1/alerts", Value::Null);
        assert_eq!(list["entries"][0]["outcome"], "not_sent");
        assert_eq!(list["entries"][0]["outcomes"][0]["person"], "ada");
        Ok(())
    }
    #[test]
    fn the_demo_telegram_puts_a_chat_on_the_list_for_a_person_and_is_off_otherwise() -> TestResult {
        let dir = tempfile::tempdir()?;
        let secrets = Arc::new(MemorySecrets::default());
        let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 7878);
        let mut app = App::new(
            Box::new(ozbox_provider_fake::open(dir.path())),
            true,
            addr,
            TOKEN.into(),
        )
        .with_secrets(secrets.clone());
        let a = &mut app;
        // Off by default: the route does not exist, whatever the provider.
        for (m, p) in [
            ("POST", "/v1/demo/telegram/message"),
            ("GET", "/v1/demo/telegram/sent"),
            ("POST", "/v1/demo/alerts"),
        ] {
            assert_eq!(
                call(a, m, p, json!({ "chat_id": 1, "text": "x" })).0,
                404,
                "{p}"
            );
        }
        a.use_demo_telegram(true);
        secrets.set("telegram-bot-token", "123:abc")?;
        set_settings(a, |s| {
            s.apps.telegram.enabled = true;
            // The alert below goes out at the real clock's time: no quiet hours, or it is held after 23:00.
            s.budget.quiet_from = "00:00".into();
            s.budget.quiet_to = "00:00".into();
            s.routing
                .people
                .insert("ada".into(), crate::notify_config::PersonRouting::default());
        })?;
        // linking a real account is a passkey flow; the demo bot's route puts a chat on the list the way an old link was
        let (st, _) = call(
            a,
            "POST",
            "/v1/demo/telegram/legacy-chat",
            json!({ "chat_id": 41, "name": "Ada phone", "person": "ada" }),
        );
        assert_eq!(st, 200);
        let (_, apps) = call(a, "GET", "/v1/apps", Value::Null);
        assert_eq!(
            apps["telegram"]["demo"], true,
            "the stand-in bot is labelled a demo"
        );
        let chats = apps["telegram"]["chats"].as_array().ok_or("chats")?;
        assert_eq!(chats.len(), 1, "{apps}");
        assert_eq!(
            (chats[0]["id"].clone(), chats[0]["person"].clone()),
            (json!(41), json!("ada"))
        );
        // A test send to that person reaches the demo chat, through the same send code.
        let (_, d) = call(
            a,
            "POST",
            "/v1/alerts/test",
            json!({ "channel": "telegram", "person": "ada" }),
        );
        assert_eq!(d["delivery"]["ok"], true, "{d}");
        let (_, sent) = call(a, "GET", "/v1/demo/telegram/sent", Value::Null);
        assert_eq!(sent["sent"].as_array().map(Vec::len), Some(1));
        assert_eq!(sent["sent"][0]["chat_id"], 41);
        // A demo alert goes through the real routing, and the recorded alert says what became of it for Ada.
        assert_eq!(
            call(
                a,
                "POST",
                "/v1/demo/alerts",
                json!({ "title": "Demo disk alert" })
            )
            .0,
            202
        );
        a.apply_done(NOON);
        let (_, list) = call(a, "GET", "/v1/alerts", Value::Null);
        let e = list["entries"]
            .as_array()
            .and_then(|l| l.iter().find(|e| e["kind"] == "demo"))
            .ok_or("the demo alert is listed")?;
        assert_eq!(e["outcome"], "delivered", "{e}");
        assert_eq!(e["outcomes"][0]["person"], "ada");
        assert_eq!(e["outcomes"][0]["channels"], json!(["telegram"]));
        // A send the demo bot refuses with 503 is retried after the demo's short pause, and the alert reads
        // "retrying" until it lands.
        let find = |a: &mut App, title: &str| -> Value {
            let (_, list) = call(a, "GET", "/v1/alerts", Value::Null);
            list["entries"]
                .as_array()
                .and_then(|l| l.iter().find(|e| e["title"] == title))
                .cloned()
                .unwrap_or(Value::Null)
        };
        let fail = json!({ "count": 1, "retry_ms": 500 });
        assert_eq!(call(a, "POST", "/v1/demo/telegram/fail", fail).0, 200);
        call(a, "POST", "/v1/demo/alerts", json!({ "title": "Retry me" }));
        a.apply_done(NOON);
        let e = find(a, "Retry me");
        assert_eq!(e["outcome"], "retrying", "{e}");
        assert_eq!(e["outcomes"][0]["results"][0]["state"], "retrying");
        // (an alert raised by the demo route is stamped with the real clock, so the retry is due on that clock)
        let base = crate::serve::unix_ms();
        a.tick(base + 1_000);
        a.apply_done(base + 1_000);
        let e = find(a, "Retry me");
        assert_eq!(e["outcome"], "delivered", "{e}");
        assert_eq!(e["outcomes"][0]["results"][0]["attempts"], 2);
        // Four failures are every try there is: it ends as failed, after four tries.
        let fail = json!({ "count": 4, "retry_ms": 500 });
        assert_eq!(call(a, "POST", "/v1/demo/telegram/fail", fail).0, 200);
        call(a, "POST", "/v1/demo/alerts", json!({ "title": "Give up" }));
        a.apply_done(NOON);
        let base = crate::serve::unix_ms();
        for i in 1..=3 {
            a.tick(base + i * 1_000);
            a.apply_done(base + i * 1_000);
        }
        let e = find(a, "Give up");
        assert_eq!(e["outcome"], "failed", "{e}");
        assert_eq!(e["outcomes"][0]["results"][0]["attempts"], 4);
        assert!(e["outcomes"][0]["results"][0]["detail"]
            .as_str()
            .is_some_and(|d| d.contains("could not be reached")));
        // Unlinking and unpairing work as with a real bot.
        assert_eq!(
            call(
                a,
                "PUT",
                "/v1/apps/telegram/chats/41",
                json!({ "person": null })
            )
            .0,
            200
        );
        assert_eq!(
            call(a, "DELETE", "/v1/apps/telegram/chats/41", Value::Null).0,
            200
        );
        // Turning it off removes the route again.
        a.use_demo_telegram(false);
        assert_eq!(call(a, "GET", "/v1/demo/telegram/sent", Value::Null).0, 404);
        assert!(a.demo_telegram.is_none());
        let (_, apps) = call(a, "GET", "/v1/apps", Value::Null);
        assert_eq!(apps["telegram"]["demo"], false);
        Ok(())
    }
}
