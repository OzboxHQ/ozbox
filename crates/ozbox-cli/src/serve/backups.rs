//! Backups in the dashboard server: the schedule, the routes, and the plans for backups that go through a box's agent.
//!
//! Who does what:
//!
//! * **Provider snapshots** (`Operation::Snapshot`, `DeleteSnapshot`, `RestoreWork`, `Clone`) are the provider's, planned
//!   and applied like every other change.
//! * **Restic backups** run on the box. This server plans them (`ResticBackup`, `ResticForget`, `ResticRestore`), starts
//!   them through the box's agent and follows them to the end; the box's own schedule stays off (this server owns it).
//! * **The schedule** runs from [`App::backups_tick`], and every call that can wait on a provider or a box runs on the
//!   background worker, never on the request thread. A run is started for a slot at most once, never twice for one box
//!   at the same time, catches up after downtime inside a window, and ends in Activity and, when it fails, an alert.
//! * **Credentials** for a bring-your-own repository live only in the secret store. They are read at the moment they are
//!   handed to a box and never kept, logged or returned.

use std::collections::{HashMap, HashSet};
use std::sync::{Arc, Mutex};

use ozbox_core::{BoxName, BoxRecord, BoxState, Error, Operation, Plan, Provider, SnapshotInfo};
use serde_json::{json, Value};

use super::agent::BoxAgent;
use super::{unix_ms, App, Resp};
use crate::backup_ops::{
    apply_restic, box_last_finished, call, ensure_credentials, plan_restic, reason,
};
use crate::backups::{
    self, due, prune, Backups, Due, ResticTarget, RunRecord, SECRET_ACCESS_KEY, SECRET_PASSWORD,
    SECRET_SECRET_KEY,
};
use crate::notify::{Alert, Severity};
use crate::secrets::SecretStore;

const SCAN_EVERY_MS: u64 = 30_000;
const POLL_EVERY_MS: u64 = 10_000;
/// A box that cannot be reached for this long while a backup was running is reported as failed.
const GIVE_UP_AFTER_MS: u64 = 30 * 60_000;

// ---------- what the worker reports ----------

struct SnapDone {
    id: Option<String>,
    pruned: Vec<String>,
    prune_failed: usize,
}

struct Ran {
    name: String,
    scheduled: bool,
    now_ms: u64,
    snapshot: Option<Result<SnapDone, String>>,
    /// `Ok(Some(b))` started (`b` is when the box last finished an operation, before this one), `Ok(None)` skipped
    /// (the box is not running), `Err` failed to start.
    restic: Option<Result<Option<u64>, String>>,
}

enum Finished {
    Scan(Result<Vec<BoxRecord>, String>),
    Ran(Ran),
    Polled {
        name: String,
        status: Result<Value, String>,
    },
    /// One look at a new box a backup is being restored into.
    NewBoxStep {
        name: String,
        step: crate::restore_new::Step,
    },
}

struct Inflight {
    /// When the box last finished an operation before this one began, on the box's own clock: the run has ended once
    /// it reports a later one. (Never compared with this server's clock.)
    baseline_ms: u64,
    scheduled: bool,
    polling: bool,
    unreachable_since: Option<u64>,
    idle_since: Option<u64>,
}

#[derive(Default)]
pub(super) struct Runtime {
    /// Boxes with a run in flight: no second run starts for them.
    busy: HashSet<String>,
    /// Restic backups started on a box, followed until the box says they ended.
    inflight: HashMap<String, Inflight>,
    done: Arc<Mutex<Vec<Finished>>>,
    scanning: bool,
    next_scan_ms: u64,
    next_poll_ms: u64,
    /// New boxes with a look in flight, and when the next round of looks is due.
    restoring: HashSet<String>,
    next_restore_ms: u64,
    /// How long the follow-up of an upgrade waits for the box (tests make it short).
    pub(super) upgrade_waits: Option<crate::run::upgrade::Waits>,
}

fn lock<T>(m: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    m.lock().unwrap_or_else(|p| p.into_inner())
}

// ---------- one scheduled run (on the worker) ----------

fn parse_ms(t: &str) -> Option<u64> {
    super::parse_rfc3339_ms(t)
}

#[allow(clippy::too_many_arguments)]
fn run_box(
    provider: &dyn Provider,
    agent: &dyn BoxAgent,
    secrets: &dyn SecretStore,
    cfg: &Backups,
    zone: &str,
    name: &BoxName,
    scheduled_ids: &[String],
    scheduled: bool,
    now_ms: u64,
) -> Ran {
    let mut ran = Ran {
        name: name.to_string(),
        scheduled,
        now_ms,
        snapshot: None,
        restic: None,
    };
    if cfg.provider_snapshots {
        ran.snapshot = Some(snapshot_and_prune(
            provider,
            cfg,
            zone,
            name,
            scheduled_ids,
            scheduled,
        ));
    }
    if let Some(target) = &cfg.restic {
        ran.restic = Some(start_restic(provider, agent, secrets, cfg, target, name));
    }
    ran
}

fn snapshot_and_prune(
    provider: &dyn Provider,
    cfg: &Backups,
    zone: &str,
    name: &BoxName,
    scheduled_ids: &[String],
    prune_after: bool,
) -> Result<SnapDone, String> {
    let before = provider
        .get(name)
        .map_err(|e| e.to_string())?
        .ok_or_else(|| format!("{name} no longer exists"))?;
    let op = Operation::Snapshot { name: name.clone() };
    let plan = provider.plan(&op).map_err(|e| e.to_string())?;
    let after = provider
        .apply(&plan)
        .map_err(|e| e.to_string())?
        .ok_or_else(|| format!("{name} no longer exists"))?;
    let id = after
        .snapshots
        .iter()
        .find(|s| !before.snapshots.contains(s))
        .cloned();
    let mut done = SnapDone {
        id: id.clone(),
        pruned: Vec::new(),
        prune_failed: 0,
    };
    if !prune_after {
        return Ok(done);
    }
    // Only snapshots the schedule made are ever candidates: one a person took by hand is theirs to delete.
    let mut mine: HashSet<&str> = scheduled_ids.iter().map(String::as_str).collect();
    if let Some(i) = &id {
        mine.insert(i.as_str());
    }
    let Ok(listed) = provider.snapshots(name) else {
        return Ok(done);
    };
    let items: Vec<(String, u64)> = listed
        .iter()
        .filter(|s| mine.contains(s.id.as_str()) && s.status == "completed")
        .filter_map(|s| Some((s.id.clone(), parse_ms(s.created_at.as_deref()?)?)))
        .collect();
    for gone in prune(&items, &cfg.retention, zone) {
        let del = Operation::DeleteSnapshot {
            name: name.clone(),
            snapshot: gone.clone(),
        };
        match provider.plan(&del).and_then(|p| provider.apply(&p)) {
            Ok(_) => done.pruned.push(gone),
            Err(_) => done.prune_failed += 1,
        }
    }
    Ok(done)
}

fn start_restic(
    provider: &dyn Provider,
    agent: &dyn BoxAgent,
    secrets: &dyn SecretStore,
    cfg: &Backups,
    target: &ResticTarget,
    name: &BoxName,
) -> Result<Option<u64>, String> {
    let rec = provider
        .get(name)
        .map_err(|e| e.to_string())?
        .ok_or_else(|| format!("{name} no longer exists"))?;
    if rec.state != BoxState::Running {
        return Ok(None);
    }
    ensure_credentials(agent, &rec, target, secrets, false)?;
    let baseline = box_last_finished(agent, &rec);
    let keep = &cfg.retention;
    let body = json!({
        "keep_daily": keep.keep_daily,
        "keep_weekly": keep.keep_weekly,
        "keep_monthly": keep.keep_monthly,
    });
    let (s, v) = call(agent, &rec, "POST", "/run", &body)?;
    match s {
        202 => Ok(Some(baseline)),
        409 if v.get("code").and_then(Value::as_str) == Some("busy") => {
            Err("the box is still running an earlier backup".into())
        }
        _ => Err(reason(&v, "the box did not start the backup")),
    }
}

// ---------- the server side ----------

/// Whether the provider's snapshots of a box include `/work`, read from a backup of the box. A copy of an old system disk is not
/// one (it never holds `/work`, and an upgrade's copy is often the newest in the list), so it never answers for the rest.
fn provider_includes_work(list: &[SnapshotInfo]) -> Option<bool> {
    list.iter()
        .find(|s| s.is_work_backup())
        .map(|s| s.includes_work)
}

fn items_of(list: &[SnapshotInfo], scheduled: &[String]) -> Vec<Value> {
    list.iter()
        .map(|s| {
            json!({
                "id": s.id,
                "kind": "snapshot",
                "created_at": s.created_at,
                "size_bytes": s.size_bytes,
                "status": s.status,
                "includes_work": s.includes_work,
                "labels": s.labels,
                "scheduled": scheduled.contains(&s.id),
            })
        })
        .collect()
}

impl App {
    fn zone(&self) -> String {
        self.settings.locale.zone().to_string()
    }

    fn window_ms(&self) -> u64 {
        u64::from(self.settings.backups.catch_up_hours) * 3_600_000
    }

    fn save_backup_state(&self) {
        if let Some(p) = &self.state_path {
            self.state.save(p);
        }
    }

    fn backup_alert(&mut self, name: &str, title: &str, body: &str, now_ms: u64) {
        let alert = Alert {
            key: format!("backup:{name}:{now_ms}"),
            kind: "backup".into(),
            severity: Severity::Normal,
            box_name: Some(name.to_string()),
            title: title.to_string(),
            body: body.to_string(),
            ts_ms: now_ms,
        };
        self.route_alerts(vec![alert], now_ms);
    }

    fn record_run(
        &mut self,
        name: &str,
        ok: bool,
        kind: &str,
        detail: &str,
        scheduled: bool,
        now: u64,
    ) {
        let st = self.state.backups.entry(name.to_string()).or_default();
        st.last = Some(RunRecord {
            ts_ms: now,
            ok,
            kind: kind.into(),
            detail: detail.into(),
            scheduled,
        });
        self.log_activity(
            if scheduled {
                "scheduled backup"
            } else {
                "backup"
            },
            name,
            None,
            &format!("{kind}: {detail}"),
        );
    }

    /// Called about once a second: start what is due, follow what is running, apply what the worker finished.
    pub fn backups_tick(&mut self, now_ms: u64) {
        self.backups_apply(now_ms);
        let any_on = self.settings.backups.schedule.is_on()
            || self
                .settings
                .backups
                .overrides
                .values()
                .any(|o| o.schedule.as_ref().is_some_and(|s| s.is_on()));
        if any_on
            && self.settings.backups.has_destination()
            && now_ms >= self.backup_rt.next_scan_ms
            && !self.backup_rt.scanning
        {
            self.backup_rt.next_scan_ms = now_ms + SCAN_EVERY_MS;
            let provider = Arc::clone(&self.provider);
            let done = Arc::clone(&self.backup_rt.done);
            let job = Box::new(move || {
                lock(&done).push(Finished::Scan(provider.list().map_err(|e| e.to_string())));
                super::worker::Done::Nothing
            });
            if self.submit(job) {
                self.backup_rt.scanning = true;
            }
        }
        if now_ms >= self.backup_rt.next_poll_ms && !self.backup_rt.inflight.is_empty() {
            self.backup_rt.next_poll_ms = now_ms + POLL_EVERY_MS;
            let names: Vec<String> = self
                .backup_rt
                .inflight
                .iter()
                .filter(|(_, i)| !i.polling)
                .map(|(n, _)| n.clone())
                .collect();
            for n in names {
                self.start_poll(&n);
            }
        }
        self.drive_new_box_restores(now_ms);
        self.backups_apply(now_ms);
    }

    /// An upgrade just replaced a box's machine, whose system disk held its repository credentials. Finish it the way
    /// `ozbox upgrade` does (the same code): wait for the box, self-test it, put the credentials back. It runs on the
    /// worker, never on the request that applied the upgrade, and ends in Activity (and an alert if it failed).
    pub(super) fn after_upgrade_applied(
        &mut self,
        plan: &Plan,
        new_store: bool,
        backups_before: bool,
    ) {
        let (name, what) = match &plan.operation {
            Operation::Upgrade { name, .. } => (name, "upgrade"),
            // A restored /work leaves the system disk alone, so only the check applies (no credentials to put back).
            Operation::RestoreWork { name, .. } => (name, "restore"),
            _ => return,
        };
        let (provider, agent, secrets) = (
            Arc::clone(&self.provider),
            Arc::clone(&self.agent),
            Arc::clone(&self.secrets),
        );
        let settings = self.settings.clone();
        let waits = self.backup_rt.upgrade_waits.unwrap_or_default();
        let n = name.clone();
        let asked_by = self.current_actor.clone();
        let job = Box::new(move || {
            let settled = crate::run::upgrade::settle_after_replace(
                provider.as_ref(),
                agent.as_ref(),
                &n,
                waits,
                // the person accepted a new store when the plan said the old one would not survive: set it aside first,
                // approved by this computer's pinned key (the same step as the command)
                &|ag, rec| {
                    new_store.then(|| {
                        crate::run::upgrade::recover_store_step(
                            ag,
                            rec,
                            crate::approval_key_cli::keychain().as_ref(),
                            waits,
                        )
                    })
                },
                &|ag, rec| {
                    if what == "upgrade" {
                        crate::run::upgrade::restore_with(&settings, ag, rec, secrets.as_ref())
                    } else {
                        None
                    }
                },
                // read from the box before the replace (see `Applied`): a box made before the record existed has no record on
                // /work to say its backups were set up, so what was seen while it was still the old machine is what tells a
                // stop from "never had any". A restore leaves the system disk alone and reads nothing.
                backups_before,
            );
            let (ready, selftest, backup) = (settled.ready, settled.selftest, settled.backup);
            if let Some(r) = settled.recovery {
                // said in Activity with the rest of the follow-up
                return super::worker::Done::UpgradeSettled {
                    what,
                    name: n.to_string(),
                    ready: crate::run::upgrade::Step {
                        outcome: if r.outcome == crate::run::upgrade::StepOutcome::Failed {
                            crate::run::upgrade::StepOutcome::Failed
                        } else {
                            ready.outcome
                        },
                        detail: format!("{} {}", ready.detail, r.detail),
                    },
                    selftest_ok: selftest.map(|t| t.ok),
                    backup,
                    actor: asked_by,
                };
            }
            super::worker::Done::UpgradeSettled {
                what,
                name: n.to_string(),
                ready,
                selftest_ok: selftest.map(|t| t.ok),
                backup,
                actor: asked_by,
            }
        });
        if !self.submit(job) {
            self.log_activity(
                &format!("{what} follow-up"),
                name.as_str(),
                None,
                "not started (the server is busy): put the repository credentials back with Send credentials in the box's Backups tab",
            );
        }
    }

    /// The follow-up of an upgrade has finished.
    pub(super) fn upgrade_settled(
        &mut self,
        what: &str,
        name: &str,
        ready: &crate::run::upgrade::Step,
        selftest_ok: Option<bool>,
        backup: &crate::run::upgrade::Step,
        now_ms: u64,
    ) {
        use crate::run::upgrade::StepOutcome;
        self.log_activity(&format!("{what} check"), name, None, &ready.detail);
        if selftest_ok == Some(false) {
            self.log_activity(
                &format!("{what} self-test"),
                name,
                None,
                "reported a problem",
            );
        }
        if backup.outcome != StepOutcome::Skipped {
            self.log_activity(&format!("{what} backups"), name, None, &backup.detail);
        }
        if backup.outcome == StepOutcome::Failed {
            self.backup_alert(
                name,
                &format!("{name} was upgraded but its backup credentials were not put back"),
                &backup.detail,
                now_ms,
            );
        }
        self.version
            .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
    }

    /// Every few seconds, look at each new box a backup is being restored into and let it do its next thing. The looks
    /// run on the worker (they wait on the network); what they found is applied on the next tick.
    fn drive_new_box_restores(&mut self, now_ms: u64) {
        const EVERY_MS: u64 = 5_000;
        if now_ms < self.backup_rt.next_restore_ms {
            return;
        }
        let due: Vec<(String, String)> = self
            .state
            .backups
            .iter()
            .filter_map(|(n, st)| Some((n.clone(), st.new_box_restore.as_ref()?.snapshot.clone())))
            .filter(|(n, _)| !self.backup_rt.restoring.contains(n))
            .collect();
        if due.is_empty() {
            return;
        }
        self.backup_rt.next_restore_ms = now_ms + EVERY_MS;
        for (name, snapshot) in due {
            let Ok(to) = BoxName::new(&name) else {
                continue;
            };
            let (provider, agent, secrets, done) = (
                Arc::clone(&self.provider),
                Arc::clone(&self.agent),
                Arc::clone(&self.secrets),
                Arc::clone(&self.backup_rt.done),
            );
            let settings = self.settings.clone();
            let n = name.clone();
            let job = Box::new(move || {
                let step = crate::restore_new::step(
                    provider.as_ref(),
                    agent.as_ref(),
                    secrets.as_ref(),
                    &settings,
                    &to,
                    &snapshot,
                    unix_ms(),
                );
                lock(&done).push(Finished::NewBoxStep { name: n, step });
                super::worker::Done::Nothing
            });
            if self.submit(job) {
                self.backup_rt.restoring.insert(name);
            }
        }
    }

    fn new_box_stepped(&mut self, name: &str, step: crate::restore_new::Step, now_ms: u64) {
        use crate::restore_new::Step;
        /// A restore that has not finished in this long is given up on (and can be run again).
        const GIVE_UP_MS: u64 = 24 * 3_600_000;
        self.backup_rt.restoring.remove(name);
        let Some(st) = self.state.backups.get_mut(name) else {
            return;
        };
        let Some(r) = st.new_box_restore.as_mut() else {
            return;
        };
        let (from, started) = (r.from.clone(), r.started_ms);
        let step = match step {
            Step::Waiting(_) if now_ms.saturating_sub(started) >= GIVE_UP_MS => Step::Failed(
                "it did not finish within a day; run the same restore again to carry on".into(),
            ),
            other => other,
        };
        match step {
            Step::Waiting(detail) => {
                if r.detail != detail {
                    r.detail = detail;
                    self.version
                        .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                }
            }
            Step::Done { detail, .. } => {
                st.new_box_restore = None;
                self.log_activity(
                    "restore a backup into a new box",
                    name,
                    None,
                    &format!("from {from}: {detail}"),
                );
                self.save_backup_state();
                self.version
                    .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            }
            Step::Failed(why) => {
                st.new_box_restore = None;
                self.log_activity(
                    "restore a backup into a new box",
                    name,
                    None,
                    &format!("stopped: {why}"),
                );
                self.backup_alert(
                    name,
                    &format!("Restoring a backup into {name} stopped"),
                    &format!("{why}. Nothing was deleted; plan and apply the same restore again to carry on."),
                    now_ms,
                );
                self.save_backup_state();
                self.version
                    .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            }
        }
    }

    fn start_poll(&mut self, name: &str) {
        let Ok(bn) = BoxName::new(name) else { return };
        let (provider, agent, done) = (
            Arc::clone(&self.provider),
            Arc::clone(&self.agent),
            Arc::clone(&self.backup_rt.done),
        );
        let n = name.to_string();
        let job = Box::new(move || {
            let status = provider
                .get(&bn)
                .map_err(|e| e.to_string())
                .and_then(|r| r.ok_or_else(|| "the box no longer exists".to_string()))
                .and_then(|rec| call(agent.as_ref(), &rec, "GET", "/status", &Value::Null))
                .and_then(|(s, v)| {
                    if s == 200 {
                        Ok(v)
                    } else {
                        Err(reason(&v, "the box did not report its backup status"))
                    }
                });
            lock(&done).push(Finished::Polled { name: n, status });
            super::worker::Done::Nothing
        });
        if self.submit(job) {
            if let Some(i) = self.backup_rt.inflight.get_mut(name) {
                i.polling = true;
            }
        }
    }

    fn backups_apply(&mut self, now_ms: u64) {
        let finished: Vec<Finished> = std::mem::take(&mut *lock(&self.backup_rt.done));
        for f in finished {
            match f {
                Finished::Scan(r) => {
                    self.backup_rt.scanning = false;
                    if let Ok(recs) = r {
                        self.backups_scan_done(recs, now_ms);
                    }
                }
                Finished::Ran(ran) => self.backups_ran(ran),
                Finished::Polled { name, status } => self.backups_polled(&name, status, now_ms),
                Finished::NewBoxStep { name, step } => self.new_box_stepped(&name, step, now_ms),
            }
        }
    }

    fn backups_scan_done(&mut self, recs: Vec<BoxRecord>, now_ms: u64) {
        let zone = self.zone();
        let window = self.window_ms();
        let mut changed = false;
        for rec in recs {
            let name = rec.spec.name.to_string();
            let sch = self.settings.backups.schedule_for(&name);
            let has_dest = self.settings.backups.has_destination();
            if !sch.is_on() || !has_dest {
                // Off: forget when it was armed, so turning it on again arms it afresh.
                if let Some(st) = self.state.backups.get_mut(&name) {
                    if st.armed_ms.take().is_some() {
                        changed = true;
                    }
                }
                continue;
            }
            let st = self.state.backups.entry(name.clone()).or_default();
            if st.armed_ms.is_none() {
                st.armed_ms = Some(now_ms);
                changed = true;
            }
            let decision = due(&sch, &zone, st, now_ms, window);
            match decision {
                Due::No => {}
                Due::Missed { slot_ms } => {
                    st.last_slot_ms = Some(slot_ms);
                    changed = true;
                    let when = crate::timezone::format_with_utc(&zone, slot_ms).unwrap_or_default();
                    let detail = format!(
                        "the backup due at {when} was not run: this server was not running within {} hours of it",
                        self.settings.backups.catch_up_hours
                    );
                    self.record_run(&name, false, "schedule", &detail, true, now_ms);
                    self.backup_alert(
                        &name,
                        &format!("A backup of {name} was missed"),
                        &detail,
                        now_ms,
                    );
                }
                Due::Run { slot_ms, late_ms } => {
                    if self.backup_rt.busy.contains(&name) {
                        // Still running the last one: this slot waits (and is served when that one is over), never overlaps.
                        continue;
                    }
                    if self.start_scheduled(&rec, slot_ms, late_ms, now_ms) {
                        changed = true;
                    }
                }
            }
        }
        if changed {
            self.save_backup_state();
        }
    }

    fn start_scheduled(
        &mut self,
        rec: &BoxRecord,
        slot_ms: u64,
        late_ms: u64,
        now_ms: u64,
    ) -> bool {
        let name = rec.spec.name.clone();
        let (provider, agent, secrets, done) = (
            Arc::clone(&self.provider),
            Arc::clone(&self.agent),
            Arc::clone(&self.secrets),
            Arc::clone(&self.backup_rt.done),
        );
        let cfg = self.settings.backups.clone();
        let zone = self.zone();
        let ids = self
            .state
            .backups
            .get(name.as_str())
            .map(|s| s.scheduled_snapshots.clone())
            .unwrap_or_default();
        let n = name.clone();
        let job = Box::new(move || {
            let ran = run_box(
                provider.as_ref(),
                agent.as_ref(),
                secrets.as_ref(),
                &cfg,
                &zone,
                &n,
                &ids,
                true,
                now_ms,
            );
            lock(&done).push(Finished::Ran(ran));
            super::worker::Done::Nothing
        });
        if !self.submit(job) {
            return false;
        }
        self.backup_rt.busy.insert(name.to_string());
        if let Some(st) = self.state.backups.get_mut(name.as_str()) {
            st.last_slot_ms = Some(slot_ms);
        }
        let late = if late_ms > 120_000 {
            format!(" ({} min after its time)", late_ms / 60_000)
        } else {
            String::new()
        };
        self.log_activity(
            "scheduled backup",
            name.as_str(),
            None,
            &format!("started{late}"),
        );
        true
    }

    fn backups_ran(&mut self, ran: Ran) {
        let Ran {
            name,
            scheduled,
            now_ms,
            snapshot,
            restic,
        } = ran;
        let mut failures: Vec<String> = Vec::new();
        let mut restic_started = false;
        if let Some(r) = snapshot {
            match r {
                Ok(d) => {
                    if let Some(id) = &d.id {
                        let st = self.state.backups.entry(name.clone()).or_default();
                        st.scheduled_snapshots.push(id.clone());
                    }
                    if let Some(st) = self.state.backups.get_mut(&name) {
                        st.scheduled_snapshots.retain(|s| !d.pruned.contains(s));
                    }
                    let mut detail = "snapshot of /work taken".to_string();
                    if !d.pruned.is_empty() {
                        detail.push_str(&format!(
                            "; {} older snapshot{} removed by the retention",
                            d.pruned.len(),
                            if d.pruned.len() == 1 { "" } else { "s" }
                        ));
                    }
                    if d.prune_failed > 0 {
                        detail.push_str(&format!(
                            "; {} could not be removed and will be tried at the next run",
                            d.prune_failed
                        ));
                    }
                    self.record_run(&name, true, "snapshot", &detail, scheduled, now_ms);
                }
                Err(e) => {
                    self.record_run(&name, false, "snapshot", &e, scheduled, now_ms);
                    failures.push(format!("snapshot: {e}"));
                }
            }
        }
        match restic {
            Some(Ok(Some(baseline))) => {
                restic_started = true;
                self.backup_rt.inflight.insert(
                    name.clone(),
                    Inflight {
                        baseline_ms: baseline,
                        scheduled,
                        polling: false,
                        unreachable_since: None,
                        idle_since: None,
                    },
                );
                self.log_activity("backup", &name, None, "restic backup started on the box");
            }
            Some(Ok(None)) => {
                self.log_activity(
                    if scheduled {
                        "scheduled backup"
                    } else {
                        "backup"
                    },
                    &name,
                    None,
                    "restic backup skipped: the box is not running",
                );
            }
            Some(Err(e)) => {
                self.record_run(&name, false, "restic", &e, scheduled, now_ms);
                failures.push(format!("restic: {e}"));
            }
            None => {}
        }
        if !restic_started {
            self.backup_rt.busy.remove(&name);
        }
        if !failures.is_empty() {
            self.backup_alert(
                &name,
                &format!("A backup of {name} failed"),
                &failures.join("; "),
                now_ms,
            );
        }
        self.save_backup_state();
        self.version
            .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
    }

    fn backups_polled(&mut self, name: &str, status: Result<Value, String>, now_ms: u64) {
        enum Out {
            Wait,
            Ended(bool, String),
        }
        let Some(inf) = self.backup_rt.inflight.get_mut(name) else {
            return;
        };
        inf.polling = false;
        let (baseline, scheduled) = (inf.baseline_ms, inf.scheduled);
        let out = match status {
            Err(e) => {
                let since = *inf.unreachable_since.get_or_insert(now_ms);
                if now_ms.saturating_sub(since) >= GIVE_UP_AFTER_MS {
                    Out::Ended(
                        false,
                        format!("the box could not be reached to follow the backup: {e}"),
                    )
                } else {
                    Out::Wait
                }
            }
            Ok(v) => {
                inf.unreachable_since = None;
                if v.get("running").is_some_and(|r| !r.is_null()) {
                    inf.idle_since = None;
                    Out::Wait
                } else {
                    let last = v.get("last").filter(|l| !l.is_null());
                    let fresh = last
                        .and_then(|l| l.get("finished_ms").and_then(Value::as_u64))
                        .is_some_and(|f| f > baseline);
                    match last {
                        Some(l) if fresh && l.get("ok").and_then(Value::as_bool) == Some(true) => {
                            Out::Ended(true, "backup to the repository finished".into())
                        }
                        Some(l) if fresh => Out::Ended(
                            false,
                            l.get("error")
                                .and_then(Value::as_str)
                                .unwrap_or("it failed")
                                .to_string(),
                        ),
                        _ => {
                            // Not running and nothing recorded for this run yet: give the box a little while to say so.
                            let since = *inf.idle_since.get_or_insert(now_ms);
                            if now_ms.saturating_sub(since) >= 120_000 {
                                Out::Ended(false, "the box has no record of this backup".into())
                            } else {
                                Out::Wait
                            }
                        }
                    }
                }
            }
        };
        if let Out::Ended(ok, detail) = out {
            self.backup_rt.inflight.remove(name);
            self.backup_rt.busy.remove(name);
            self.record_run(name, ok, "restic", &detail, scheduled, now_ms);
            if !ok {
                self.backup_alert(
                    name,
                    &format!("A backup of {name} failed"),
                    &format!("restic: {detail}"),
                    now_ms,
                );
            }
            self.save_backup_state();
            self.version
                .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        }
    }

    // ---------- plans for backups that go through the box ----------

    /// A restic operation as a plan, or `None` when `op` is the provider's.
    pub(super) fn plan_restic(&self, op: &Operation) -> Option<Result<Plan, Resp>> {
        if let Operation::RestoreToNewBox { from, to, snapshot } = op {
            return Some(
                crate::restore_new::plan(
                    &self.settings,
                    self.agent.as_ref(),
                    self.provider.as_ref(),
                    from,
                    to,
                    snapshot,
                )
                .map_err(|e| Resp::error(e.status, e.code, &e.message)),
            );
        }
        let name = match op {
            Operation::ResticBackup { name }
            | Operation::ResticForget { name, .. }
            | Operation::ResticRestore { name, .. } => name,
            _ => return None,
        };
        let rec = match self.record(name.as_str()) {
            Ok(r) => r,
            Err(r) => return Some(Err(r)),
        };
        Some(
            plan_restic(
                &self.settings,
                self.agent.as_ref(),
                &self.provider_id,
                &rec,
                op,
                unix_ms(),
            )
            .map_err(|e| Resp::error(e.status, e.code, &e.message)),
        )
    }

    /// Carry out a restic plan through the box's agent. The caller has used the plan up. A restore into a new box is a
    /// change to the provider, so it runs as a job (`apply_jobs`), not here.
    pub(super) fn apply_restic(&mut self, plan: &Plan) -> Option<Result<Option<BoxRecord>, Error>> {
        let name = match &plan.operation {
            Operation::ResticBackup { name }
            | Operation::ResticForget { name, .. }
            | Operation::ResticRestore { name, .. } => name.clone(),
            _ => return None,
        };
        Some(self.apply_restic_for(plan, &name))
    }

    /// Remember a restore into a new box BEFORE the box is made: the next ticks hand it the credentials, restore into it
    /// and check it, and a restarted server carries on from the same record. If the create is interrupted, the same plan
    /// applied again carries on.
    pub(super) fn remember_new_box_restore(
        &mut self,
        from: &BoxName,
        to: &BoxName,
        snapshot: &str,
    ) {
        let st = self.state.backups.entry(to.to_string()).or_default();
        st.new_box_restore = Some(crate::backups::NewBoxRestore {
            from: from.to_string(),
            snapshot: snapshot.to_string(),
            started_ms: unix_ms(),
            detail: "creating the box".into(),
        });
        self.save_backup_state();
    }

    /// The create failed and no box was made: forget the restore that was remembered for it.
    pub(super) fn forget_new_box_restore_if_absent(&mut self, to: &BoxName) {
        if self.provider.get(to).ok().flatten().is_none() {
            if let Some(st) = self.state.backups.get_mut(to.as_str()) {
                st.new_box_restore = None;
            }
            self.save_backup_state();
        }
    }

    fn apply_restic_for(
        &mut self,
        plan: &Plan,
        name: &BoxName,
    ) -> Result<Option<BoxRecord>, Error> {
        let rec = self
            .provider
            .get(name)?
            .ok_or_else(|| Error::NotFound(name.to_string()))?;
        let started = apply_restic(
            &self.settings,
            self.agent.as_ref(),
            self.secrets.as_ref(),
            &rec,
            plan,
        )?;
        if matches!(plan.operation, Operation::ResticBackup { .. }) {
            // A backup that starts now serves the schedule's latest slot too, and is followed to its end.
            self.note_manual_run(name.as_str(), unix_ms());
            self.backup_rt.busy.insert(name.to_string());
            self.backup_rt.inflight.insert(
                name.to_string(),
                Inflight {
                    baseline_ms: started.baseline_ms,
                    scheduled: false,
                    polling: false,
                    unreachable_since: None,
                    idle_since: None,
                },
            );
        }
        self.save_backup_state();
        self.provider.get(name)
    }

    /// A backup started by hand counts as serving the latest slot of the schedule: no second one right after.
    pub(super) fn note_manual_run(&mut self, name: &str, now_ms: u64) {
        let zone = self.zone();
        let slot = self
            .settings
            .backups
            .schedule_for(name)
            .prev_slot(&zone, now_ms);
        let st = self.state.backups.entry(name.to_string()).or_default();
        if let Some(s) = slot {
            st.last_slot_ms = Some(st.last_slot_ms.map_or(s, |l| l.max(s)));
        }
    }

    // ---------- routes ----------

    pub(super) fn backups_fleet(&mut self, method: &str, rest: &[&str], body: &[u8]) -> Resp {
        match (method, rest) {
            ("GET", []) => self.backups_overview(),
            ("PUT", ["settings"]) => self.backups_put_settings(body),
            _ => Resp::error(404, "not_found", "no such endpoint"),
        }
    }

    fn backups_put_settings(&mut self, body: &[u8]) -> Resp {
        let new: Backups = match serde_json::from_slice(body) {
            Ok(b) => b,
            Err(e) => {
                return Resp::error(400, "bad_request", &format!("invalid backup settings: {e}"))
            }
        };
        if let Err(e) = new.validate() {
            return Resp::error(400, "invalid_settings", &e.to_string());
        }
        let mut next = self.settings.clone();
        next.backups = new;
        if let Some(p) = &self.settings_path {
            if let Err(e) = next.save_to(p) {
                return Resp::error(500, "cannot_save", &e.to_string());
            }
        }
        self.settings = next;
        self.log_activity("update backup settings", "-", None, "saved");
        self.backups_overview()
    }

    fn secret_flags(&self) -> Value {
        let has = |n: &str| self.secrets.exists(n).unwrap_or(false);
        json!({
            "password": has(SECRET_PASSWORD),
            "access_key": has(SECRET_ACCESS_KEY),
            "secret_key": has(SECRET_SECRET_KEY),
        })
    }

    fn backups_overview(&self) -> Resp {
        let zone = self.zone();
        let now = unix_ms();
        let recs = match self.boxes_for_loop() {
            Ok(r) => r,
            Err(r) => return r,
        };
        let b = &self.settings.backups;
        let price = self
            .prices
            .book
            .as_ref()
            .and_then(|bk| bk.snapshot_gb_month.map(|p| (p, bk.currency.clone())));
        let mut total = Some(0.0f64);
        let boxes: Vec<Value> = recs
            .iter()
            .map(|r| {
                let name = r.spec.name.to_string();
                let sch = b.schedule_for(&name);
                if sch.is_on() && b.provider_snapshots {
                    total = total.and_then(|t| {
                        backups::estimate_monthly(
                            r.spec.work_disk_gb,
                            &b.retention,
                            price.as_ref().map(|p| p.0),
                        )
                        .map(|e| t + e)
                    });
                }
                let st = self.state.backups.get(&name);
                json!({
                    "name": name,
                    "state": r.state,
                    "schedule": sch,
                    "next_run_ms": sch.next_slot(&zone, now),
                    "last": st.and_then(|s| s.last.clone()),
                    "running": self.backup_rt.busy.contains(&name),
                })
            })
            .collect();
        let any_snapshots_on = recs
            .iter()
            .any(|r| b.schedule_for(r.spec.name.as_str()).is_on())
            && b.provider_snapshots;
        Resp::json(
            200,
            &json!({
                // `simulated` when the snapshots and repository below are the demo's own, not a real box's
                "source": self.data_source(),
                "zone": zone,
                "now_ms": now,
                "settings": b,
                "secrets": self.secret_flags(),
                "boxes": boxes,
                "estimate": {
                    "basis": "estimate",
                    "monthly": if any_snapshots_on { total } else { None },
                    "currency": price.as_ref().map(|p| p.1.clone()),
                    "snapshot_gb_month": price.as_ref().map(|p| p.0),
                    "note": "At most: every snapshot the retention can hold, each priced at the full size of the /work disk. Snapshots are incremental, so the bill is usually less. A bring-your-own repository is billed by its own provider and is not estimated here.",
                },
            }),
        )
    }

    pub(super) fn box_backups(&mut self, name: &str, method: &str, rest: &[&str]) -> Resp {
        let rec = match self.record(name) {
            Ok(r) => r,
            Err(r) => return r,
        };
        match (method, rest) {
            ("GET", []) => self.box_backup_list(&rec),
            ("POST", ["credentials"]) => self.box_backup_credentials(&rec, true),
            ("DELETE", ["credentials"]) => self.box_backup_credentials(&rec, false),
            ("POST", ["off"]) => self.box_backup_off(&rec),
            _ => Resp::error(404, "not_found", "no such endpoint"),
        }
    }

    fn box_backup_list(&self, rec: &BoxRecord) -> Resp {
        let b = &self.settings.backups;
        let name = rec.spec.name.to_string();
        let st = self.state.backups.get(&name);
        let scheduled = st
            .map(|s| s.scheduled_snapshots.clone())
            .unwrap_or_default();
        let mut items: Vec<Value> = Vec::new();
        let provider = match self.provider.snapshots(&rec.spec.name) {
            Ok(list) => {
                items.extend(items_of(&list, &scheduled));
                json!({ "supported": true, "includes_work": provider_includes_work(&list), "error": null })
            }
            Err(Error::Unsupported { why, .. }) => {
                json!({ "supported": false, "includes_work": null, "error": why })
            }
            Err(e) => json!({ "supported": true, "includes_work": null, "error": e.to_string() }),
        };
        let mut restic = json!({ "target_set": b.restic.is_some(), "configured_on_box": null, "secrets_ready": true, "error": null, "busy": false, "running": null });
        if b.restic.is_some() && rec.state == BoxState::Running {
            match call(self.agent.as_ref(), rec, "GET", "/status", &Value::Null) {
                Ok((200, v)) => {
                    restic["configured_on_box"] = v["configured"].clone();
                    // false: the box's secrets service is not up yet, so "not configured" is "not known" (an older box
                    // says nothing and reads as ready)
                    restic["secrets_ready"] = json!(!crate::backup_ops::status_not_ready(&v));
                    restic["running"] = v["running"].clone();
                    restic["last"] = v["last"].clone();
                    if v["configured"] == json!(true) {
                        match call(self.agent.as_ref(), rec, "GET", "/snapshots", &Value::Null) {
                            Ok((200, l)) => {
                                for i in l["items"].as_array().cloned().unwrap_or_default() {
                                    items.push(json!({
                                        "id": i["id"],
                                        "kind": "restic",
                                        "created_at": i["time"],
                                        "size_bytes": i["size_bytes"],
                                        "status": "completed",
                                        "includes_work": true,
                                        "labels": { "tags": i["tags"] },
                                        "scheduled": false,
                                    }));
                                }
                            }
                            // an operation is using the repository: that is not "no backups" and not a failure, so the
                            // list says so and the page keeps the last list it had
                            Ok((409, l))
                                if l.get("code").and_then(Value::as_str) == Some("busy") =>
                            {
                                restic["busy"] = json!(true)
                            }
                            Ok((_, l)) => {
                                restic["error"] =
                                    json!(reason(&l, "the box could not list its backups"))
                            }
                            Err(e) => restic["error"] = json!(e),
                        }
                    }
                }
                Ok((_, v)) => {
                    restic["error"] = json!(reason(&v, "the box did not report its backup status"))
                }
                Err(e) => restic["error"] = json!(e),
            }
        } else if b.restic.is_some() {
            restic["error"] = json!(format!(
                "the box is {}, so its repository backups cannot be listed",
                rec.state
            ));
        }
        let zone = self.zone();
        let sch = b.schedule_for(&name);
        items.sort_by(|a, c| c["created_at"].as_str().cmp(&a["created_at"].as_str()));
        Resp::json(
            200,
            &json!({
                "source": self.data_source(),
                "box": name,
                "state": rec.state,
                "items": items,
                "provider": provider,
                "restic": restic,
                // The /work disks restores replaced and kept: they keep costing storage until a person deletes them.
                "old_disks": self.provider.old_work_disks(&rec.spec.name).unwrap_or_default(),
                // A restore into this (new) box that is still being carried out.
                "new_box_restore": st.and_then(|s| s.new_box_restore.clone()),
                "schedule": sch,
                // switched off for this box (Settings -> Backups, or "Turn off backups on this box")
                "turned_off": b.is_off_for(&name),
                "zone": zone,
                "next_run_ms": sch.next_slot(&zone, unix_ms()),
                "last": st.and_then(|s| s.last.clone()),
                "running": self.backup_rt.busy.contains(&name),
            }),
        )
    }

    /// Retire a box's backups for good reason: its repository credentials leave the box (and with them the record that
    /// backups were set up, so the self-test and an upgrade stop expecting them), and its schedule is switched off so the
    /// next slot does not send them again. What was already backed up stays where it is. Credentials first: when the box
    /// cannot be reached nothing is changed, and the person is told.
    fn box_backup_off(&mut self, rec: &BoxRecord) -> Resp {
        let name = rec.spec.name.to_string();
        if rec.state != BoxState::Running {
            return Resp::error(
                409,
                "box_not_running",
                &format!(
                    "box {name} is {}, so its credentials cannot be removed; start it first (nothing was changed)",
                    rec.state
                ),
            );
        }
        if let Err(e) = crate::backup_ops::remove_credentials(self.agent.as_ref(), rec) {
            return Resp::error(422, "provision_failed", &e);
        }
        let mut next = self.settings.clone();
        next.backups.turn_off_box(&name);
        if let Some(p) = &self.settings_path {
            if let Err(e) = next.save_to(p) {
                return Resp::error(
                    500,
                    "cannot_save",
                    &format!(
                        "the credentials were removed from the box, but the setting could not be saved ({e}); switch this box's backups off in Settings -> Backups"
                    ),
                );
            }
        }
        self.settings = next;
        self.log_activity(
            "turn off backups",
            &name,
            None,
            "credentials removed from the box, its schedule switched off",
        );
        Resp::json(200, &json!({ "ok": true, "box": name }))
    }

    fn box_backup_credentials(&mut self, rec: &BoxRecord, set: bool) -> Resp {
        if rec.state != BoxState::Running {
            return Resp::error(
                409,
                "box_not_running",
                &format!(
                    "box {} is {}, so it cannot be reached",
                    rec.spec.name, rec.state
                ),
            );
        }
        let result = if set {
            let Some(target) = self.settings.backups.restic.clone() else {
                return Resp::error(
                    422,
                    "no_repository",
                    "no backup repository is set up; add one in Settings → Backups first",
                );
            };
            ensure_credentials(
                self.agent.as_ref(),
                rec,
                &target,
                self.secrets.as_ref(),
                true,
            )
            .map(|_| ())
        } else {
            crate::backup_ops::remove_credentials(self.agent.as_ref(), rec)
        };
        match result {
            Ok(()) => {
                self.log_activity(
                    if set {
                        "backup credentials"
                    } else {
                        "remove backup credentials"
                    },
                    rec.spec.name.as_str(),
                    None,
                    if set {
                        "put on the box, write-only"
                    } else {
                        "removed from the box"
                    },
                );
                Resp::json(200, &json!({ "ok": true }))
            }
            Err(e) => Resp::error(422, "provision_failed", &e),
        }
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use std::net::{IpAddr, Ipv4Addr, SocketAddr};

    use jiff::Timestamp;
    use ozbox_core::{BoxSpec, Size};

    use super::*;
    use crate::backup_ops::credentials_body;
    use crate::backups::{BoxBackupState, ResticKind, Retention, Schedule, ScheduleKind};
    use crate::serve::Req;
    use crate::settings::Settings;

    const HOUR: u64 = 3_600_000;
    const DAY: u64 = 24 * HOUR;

    fn ms(s: &str) -> u64 {
        s.parse::<Timestamp>().unwrap().as_millisecond() as u64
    }

    fn daily(t: &str) -> Schedule {
        Schedule {
            kind: ScheduleKind::Daily,
            time: t.into(),
            weekday: 0,
        }
    }

    fn app(dir: &std::path::Path, b: Backups) -> App {
        let mut s = Settings {
            backups: b,
            ..Settings::default()
        };
        s.locale.time_zone = Some("UTC".into());
        let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 7878);
        let mut a = App::new(
            Box::new(ozbox_provider_fake::open(dir)),
            true,
            addr,
            "tok".into(),
        )
        .with_settings(s, None);
        a.provider_id = "fake".into();
        a
    }

    fn req(method: &str, path: &str, body: Value) -> Req {
        let (p, q) = path.split_once('?').unwrap_or((path, ""));
        let mut headers = HashMap::new();
        headers.insert("host".to_string(), "127.0.0.1:7878".to_string());
        headers.insert("authorization".to_string(), "Bearer tok".to_string());
        Req {
            method: method.into(),
            path: p.into(),
            query: q.into(),
            headers,
            body: if body.is_null() {
                Vec::new()
            } else {
                body.to_string().into_bytes()
            },
        }
    }

    fn call_api(a: &mut App, method: &str, path: &str, body: Value) -> (u16, Value) {
        let r = a.handle(&req(method, path, body));
        (
            r.status,
            serde_json::from_slice(&r.body).unwrap_or(Value::Null),
        )
    }

    fn make_box(a: &mut App, name: &str) {
        let op = Operation::Create {
            spec: BoxSpec::new(BoxName::new(name).unwrap(), Size::S),
        };
        let p = a.provider.plan(&op).unwrap();
        a.provider.apply(&p).unwrap();
    }

    fn snaps(a: &App, name: &str) -> Vec<String> {
        a.provider
            .get(&BoxName::new(name).unwrap())
            .unwrap()
            .unwrap()
            .snapshots
    }

    /// Tick until the work the tick started has been applied (the worker is inline in tests).
    fn settle(a: &mut App, at: u64) {
        a.backups_tick(at);
        a.backups_tick(at + 1);
    }

    fn snapshots_only(schedule: Schedule, keep: Retention) -> Backups {
        Backups {
            schedule,
            retention: keep,
            provider_snapshots: true,
            restic: None,
            catch_up_hours: 12,
            overrides: Default::default(),
        }
    }

    const KEEP2: Retention = Retention {
        keep_daily: 2,
        keep_weekly: 0,
        keep_monthly: 0,
    };

    #[test]
    fn a_scheduled_snapshot_runs_once_per_slot_and_is_recorded_in_activity() {
        let dir = tempfile::tempdir().unwrap();
        let mut a = app(dir.path(), snapshots_only(daily("02:00"), KEEP2));
        make_box(&mut a, "dev");
        let t0 = ms("2026-11-09T12:00:00Z");
        settle(&mut a, t0);
        assert!(
            snaps(&a, "dev").is_empty(),
            "turning it on does not run it for a slot that is already past"
        );
        // the next 02:00 passes; the scan that sees it starts exactly one run
        let t1 = ms("2026-11-10T02:05:00Z");
        settle(&mut a, t1);
        settle(&mut a, t1 + 40_000);
        assert_eq!(snaps(&a, "dev").len(), 1);
        let last = a.state.backups["dev"].last.clone().unwrap();
        assert!(last.ok && last.scheduled && last.kind == "snapshot");
        // later scans in the same slot do nothing
        for k in 2..6 {
            settle(&mut a, t1 + k * 40_000);
        }
        assert_eq!(snaps(&a, "dev").len(), 1);
        let act = serde_json::to_string(&a.activity).unwrap();
        assert!(act.contains("scheduled backup"), "{act}");
        // and the slot after that runs again
        // (the fake stamps snapshots with the real clock, so the retention folds both into one day: the second run is
        // seen in the record, not in the count)
        settle(&mut a, t1 + DAY);
        settle(&mut a, t1 + DAY + 40_000);
        assert_eq!(
            a.state.backups["dev"].last.as_ref().unwrap().ts_ms,
            t1 + DAY
        );
    }

    #[test]
    fn after_downtime_one_run_not_one_per_missed_day_and_a_slot_outside_the_window_is_a_missed_alert(
    ) {
        let served_on_the_3rd = || BoxBackupState {
            armed_ms: Some(ms("2026-11-01T00:00:00Z")),
            last_slot_ms: Some(ms("2026-11-03T02:00:00Z")),
            ..Default::default()
        };
        // The server was down from the 3rd until the morning of the 9th. Back at 05:00 (3 h late): one run, and
        // nothing for the days in between.
        let dir = tempfile::tempdir().unwrap();
        let mut a = app(dir.path(), snapshots_only(daily("02:00"), KEEP2));
        make_box(&mut a, "dev");
        a.state.backups.insert("dev".into(), served_on_the_3rd());
        settle(&mut a, ms("2026-11-09T05:00:00Z"));
        settle(&mut a, ms("2026-11-09T05:01:00Z"));
        assert_eq!(snaps(&a, "dev").len(), 1);
        settle(&mut a, ms("2026-11-09T06:00:00Z"));
        assert_eq!(
            snaps(&a, "dev").len(),
            1,
            "the days in between are not replayed"
        );
        // Back at 20:00 instead, beyond the 12 hour window: nothing runs, the miss is recorded and raised.
        let dir = tempfile::tempdir().unwrap();
        let mut b = app(dir.path(), snapshots_only(daily("02:00"), KEEP2));
        make_box(&mut b, "late");
        b.state.backups.insert("late".into(), served_on_the_3rd());
        settle(&mut b, ms("2026-11-09T20:00:00Z"));
        settle(&mut b, ms("2026-11-09T20:01:00Z"));
        assert!(snaps(&b, "late").is_empty());
        let last = b.state.backups["late"].last.clone().unwrap();
        assert!(!last.ok && last.detail.contains("was not run"), "{last:?}");
        assert!(
            b.state
                .alerts
                .recent
                .iter()
                .any(|r| r.kind == "backup" && r.box_name.as_deref() == Some("late")),
            "a missed backup is an alert"
        );
        // and it is not tried again for that slot
        settle(&mut b, ms("2026-11-09T21:00:00Z"));
        assert!(snaps(&b, "late").is_empty());
    }

    #[test]
    fn a_box_is_never_backed_up_twice_at_once_and_its_slot_waits() {
        let dir = tempfile::tempdir().unwrap();
        let mut a = app(dir.path(), snapshots_only(daily("02:00"), KEEP2));
        make_box(&mut a, "dev");
        a.state.backups.insert(
            "dev".into(),
            BoxBackupState {
                armed_ms: Some(ms("2026-11-01T00:00:00Z")),
                ..Default::default()
            },
        );
        a.backup_rt.busy.insert("dev".into());
        settle(&mut a, ms("2026-11-09T03:00:00Z"));
        assert!(
            snaps(&a, "dev").is_empty(),
            "a run is already in flight for it"
        );
        assert_eq!(
            a.state.backups["dev"].last_slot_ms, None,
            "the slot is still owed"
        );
        a.backup_rt.busy.clear();
        settle(&mut a, ms("2026-11-09T03:01:00Z"));
        settle(&mut a, ms("2026-11-09T03:02:00Z"));
        assert_eq!(snaps(&a, "dev").len(), 1);
    }

    #[test]
    fn retention_prunes_only_what_the_schedule_made_and_never_a_snapshot_taken_by_hand() {
        let dir = tempfile::tempdir().unwrap();
        let mut a = app(dir.path(), snapshots_only(daily("02:00"), KEEP2));
        make_box(&mut a, "dev");
        // a person's own snapshot, taken before the schedule exists
        let n = BoxName::new("dev").unwrap();
        let by_hand = a
            .provider
            .plan(&Operation::Snapshot { name: n.clone() })
            .and_then(|p| a.provider.apply(&p))
            .unwrap()
            .unwrap()
            .snapshots[0]
            .clone();
        // The fake stamps snapshots with the real clock, so every run is "today" and counts as one day.
        // Give the schedule's snapshots distinct days by running them with a retention that keeps by distinct day:
        // keep_daily 2 over snapshots that all fall on one real day keeps only the newest of that day.
        let t = ms("2026-11-09T12:00:00Z");
        settle(&mut a, t);
        for k in 1..=3u64 {
            settle(&mut a, t + k * DAY - 8 * HOUR);
            settle(&mut a, t + k * DAY - 8 * HOUR + 40_000);
        }
        let now = snaps(&a, "dev");
        assert!(
            now.contains(&by_hand),
            "a snapshot taken by hand is never pruned: {now:?}"
        );
        let mine = &a.state.backups["dev"].scheduled_snapshots;
        assert_eq!(
            mine.len(),
            1,
            "three runs on one real day leave the newest of that day: {mine:?}"
        );
        assert!(now.contains(&mine[0]));
        assert_eq!(now.len(), 2);
    }

    fn restic_backups() -> Backups {
        Backups {
            schedule: daily("02:00"),
            retention: KEEP2,
            provider_snapshots: false,
            restic: Some(ResticTarget {
                kind: ResticKind::S3,
                location: "https://objects.example.com/bucket".into(),
            }),
            catch_up_hours: 12,
            overrides: Default::default(),
        }
    }

    fn set_secrets(a: &App) {
        a.secrets
            .set(SECRET_PASSWORD, "correct-horse-battery")
            .unwrap();
        a.secrets.set(SECRET_ACCESS_KEY, "AKIAEXAMPLE").unwrap();
        a.secrets
            .set(SECRET_SECRET_KEY, "sekrit-key-value")
            .unwrap();
    }

    #[test]
    fn a_scheduled_restic_backup_puts_credentials_on_the_box_starts_and_follows_the_backup() {
        let dir = tempfile::tempdir().unwrap();
        let mut a = app(dir.path(), restic_backups());
        make_box(&mut a, "dev");
        set_secrets(&a);
        settle(&mut a, ms("2026-11-09T12:00:00Z"));
        let t1 = ms("2026-11-10T02:05:00Z");
        settle(&mut a, t1);
        settle(&mut a, t1 + 40_000);
        // the box now holds credentials and a backup; the run is followed until the box says it ended
        settle(&mut a, t1 + 80_000);
        let st = &a.state.backups["dev"];
        assert!(
            st.last.as_ref().is_some_and(|l| l.ok && l.kind == "restic"),
            "{:?}",
            st.last
        );
        assert!(!a.backup_rt.busy.contains("dev") && a.backup_rt.inflight.is_empty());
        let (s, v) = call_api(&mut a, "GET", "/v1/boxes/dev/backups", Value::Null);
        assert_eq!(s, 200);
        let items = v["items"].as_array().unwrap();
        assert_eq!(
            items.iter().filter(|i| i["kind"] == "restic").count(),
            1,
            "{v}"
        );
        assert_eq!(v["restic"]["configured_on_box"], true);
        let all = v.to_string();
        assert!(
            !all.contains("correct-horse")
                && !all.contains("sekrit-key")
                && !all.contains("objects.example.com/bucket/"),
            "{all}"
        );
    }

    #[test]
    fn a_restic_backup_with_a_missing_secret_fails_loudly_and_never_names_a_value() {
        let dir = tempfile::tempdir().unwrap();
        let mut a = app(dir.path(), restic_backups());
        make_box(&mut a, "dev");
        a.secrets
            .set(SECRET_PASSWORD, "correct-horse-battery")
            .unwrap();
        settle(&mut a, ms("2026-11-09T12:00:00Z"));
        let t1 = ms("2026-11-10T02:05:00Z");
        settle(&mut a, t1);
        settle(&mut a, t1 + 40_000);
        let last = a.state.backups["dev"].last.clone().unwrap();
        assert!(
            !last.ok && last.detail.contains("restic-access-key"),
            "{last:?}"
        );
        assert!(!last.detail.contains("correct-horse"));
        assert!(a.state.alerts.recent.iter().any(|r| r.kind == "backup"));
        assert!(
            !a.backup_rt.busy.contains("dev"),
            "a failed start frees the box for the next slot"
        );
    }

    #[test]
    fn credentials_are_write_only_everywhere_the_server_answers() {
        let dir = tempfile::tempdir().unwrap();
        let mut a = app(dir.path(), restic_backups());
        make_box(&mut a, "dev");
        for (n, v) in [
            (SECRET_PASSWORD, "correct-horse-battery"),
            (SECRET_ACCESS_KEY, "AKIAEXAMPLE"),
            (SECRET_SECRET_KEY, "sekrit-key-value"),
        ] {
            let (s, body) = call_api(
                &mut a,
                "PUT",
                &format!("/v1/secrets/{n}"),
                json!({ "value": v }),
            );
            assert_eq!(s, 200, "{body}");
            assert!(!body.to_string().contains(v));
        }
        let (_, fleet) = call_api(&mut a, "GET", "/v1/backups", Value::Null);
        assert_eq!(
            fleet["secrets"],
            json!({ "password": true, "access_key": true, "secret_key": true })
        );
        let (s, _) = call_api(
            &mut a,
            "POST",
            "/v1/boxes/dev/backups/credentials",
            Value::Null,
        );
        assert_eq!(s, 200);
        for path in [
            "/v1/backups",
            "/v1/boxes/dev/backups",
            "/v1/activity",
            "/v1/secrets",
            "/v1/settings",
        ] {
            let (_, v) = call_api(&mut a, "GET", path, Value::Null);
            let t = v.to_string();
            for secret in ["correct-horse-battery", "AKIAEXAMPLE", "sekrit-key-value"] {
                assert!(!t.contains(secret), "{path} returned a secret");
            }
        }
        // a secret that is not one of ours is refused, and the three can be removed
        assert_eq!(
            call_api(
                &mut a,
                "DELETE",
                &format!("/v1/secrets/{SECRET_PASSWORD}"),
                Value::Null
            )
            .0,
            200
        );
        let (_, fleet) = call_api(&mut a, "GET", "/v1/backups", Value::Null);
        assert_eq!(fleet["secrets"]["password"], false);
    }

    #[test]
    fn the_error_for_a_missing_credential_names_it_and_never_a_value() {
        let secrets = crate::secrets::MemorySecrets::default();
        secrets
            .set(SECRET_PASSWORD, "correct-horse-battery")
            .unwrap();
        let t = ResticTarget {
            kind: ResticKind::B2,
            location: "bucket:prefix".into(),
        };
        let e = credentials_body(&t, &secrets).unwrap_err();
        assert!(
            e.contains(SECRET_ACCESS_KEY) && !e.contains("correct-horse"),
            "{e}"
        );
        secrets.set(SECRET_ACCESS_KEY, "keyid").unwrap();
        secrets.set(SECRET_SECRET_KEY, "keysecret").unwrap();
        let body = credentials_body(&t, &secrets).unwrap();
        assert_eq!(body["env"]["RESTIC_REPOSITORY"], "b2:bucket:prefix");
        assert_eq!(body["env"]["B2_ACCOUNT_ID"], "keyid");
        let local = ResticTarget {
            kind: ResticKind::Local,
            location: "/mnt/b".into(),
        };
        assert!(credentials_body(&local, &secrets).unwrap()["env"]
            .get("AWS_ACCESS_KEY_ID")
            .is_none());
    }

    fn plan_and_apply(a: &mut App, op: Value, confirm: Option<&str>) -> (u16, Value) {
        let (s, p) = call_api(a, "POST", "/v1/plans", json!({ "operation": op }));
        if s != 200 {
            return (s, p);
        }
        let mut body = json!({ "plan_id": p["plan_id"], "plan": p["plan"] });
        if let Some(c) = confirm {
            body["confirm_name"] = json!(c);
        }
        // a change that stops a box first gets it ready on a thread: ask again until the change is made
        for _ in 0..2000 {
            let (status, v) = call_api(a, "POST", "/v1/apply", body.clone());
            if status == 202 && v["quiescing"] == true {
                std::thread::sleep(std::time::Duration::from_millis(5));
                continue;
            }
            if status != 202 {
                return (status, v);
            }
            // a change runs as a job (already finished in tests): answer as the change did
            let id = v["job_id"].as_str().unwrap().to_string();
            let (_, job) = call_api(a, "GET", &format!("/v1/jobs/{id}"), Value::Null);
            return match job["state"].as_str() {
                Some("done") => (200, job["result"].clone()),
                _ => (
                    job["status"].as_u64().unwrap_or(500) as u16,
                    job["failure"].clone(),
                ),
            };
        }
        (0, json!({ "error": "still quiescing" }))
    }

    #[test]
    fn manual_restic_back_up_delete_and_restore_go_through_plans_with_their_risks() {
        let dir = tempfile::tempdir().unwrap();
        let mut a = app(
            dir.path(),
            Backups {
                schedule: Schedule::default(),
                ..restic_backups()
            },
        );
        make_box(&mut a, "dev");
        set_secrets(&a);
        // Back up now: planned (credentials, then the backup), nothing runs until applied
        let (s, p) = call_api(
            &mut a,
            "POST",
            "/v1/plans",
            json!({ "operation": { "op": "restic_backup", "name": "dev" } }),
        );
        assert_eq!(s, 200, "{p}");
        let kinds: Vec<&str> = p["plan"]["changes"]
            .as_array()
            .unwrap()
            .iter()
            .map(|c| c["kind"].as_str().unwrap())
            .collect();
        assert_eq!(kinds, ["backup.credentials", "backup.run"]);
        assert_eq!(p["max_risk"], "low");
        let (s, v) = plan_and_apply(
            &mut a,
            json!({ "op": "restic_backup", "name": "dev" }),
            None,
        );
        assert_eq!(s, 200, "{v}");
        settle(&mut a, unix_ms() + 15_000);
        settle(&mut a, unix_ms() + 30_000);
        let (_, v) = call_api(&mut a, "GET", "/v1/boxes/dev/backups", Value::Null);
        let id = v["items"]
            .as_array()
            .unwrap()
            .iter()
            .find(|i| i["kind"] == "restic")
            .unwrap()["id"]
            .as_str()
            .unwrap()
            .to_string();
        // restoring over /work needs the way back (just made) and the typed name; into a folder is lower risk
        let folder =
            json!({ "op": "restic_restore", "name": "dev", "snapshot": id, "in_place": false });
        let (_, p) = call_api(&mut a, "POST", "/v1/plans", json!({ "operation": folder }));
        assert_eq!(p["max_risk"], "medium");
        assert!(p["plan"]["changes"][0]["description"]
            .as_str()
            .unwrap()
            .contains("/work/restored-"));
        let over =
            json!({ "op": "restic_restore", "name": "dev", "snapshot": id, "in_place": true });
        let (_, p) = call_api(&mut a, "POST", "/v1/plans", json!({ "operation": over }));
        assert_eq!(p["max_risk"], "high");
        assert_eq!(p["requires_confirm_name"], true);
        let (s, _) = plan_and_apply(&mut a, over.clone(), None);
        assert_eq!(s, 400, "the name must be typed");
        let (s, v) = plan_and_apply(&mut a, over, Some("dev"));
        assert_eq!(s, 200, "{v}");
        // delete: high risk, and a backup that is already gone plans to nothing
        let del = json!({ "op": "restic_forget", "name": "dev", "snapshot": id });
        let (s, v) = plan_and_apply(&mut a, del.clone(), Some("dev"));
        assert_eq!(s, 200, "{v}");
        let (_, p) = call_api(&mut a, "POST", "/v1/plans", json!({ "operation": del }));
        assert_eq!(p["noop"], true);
    }

    #[test]
    fn a_restore_over_work_is_refused_without_a_recent_backup_of_its_current_state() {
        let dir = tempfile::tempdir().unwrap();
        let mut a = app(dir.path(), restic_backups());
        make_box(&mut a, "dev");
        set_secrets(&a);
        let over = json!({ "op": "restic_restore", "name": "dev", "snapshot": "aaaaaaaaaaaaaaaa", "in_place": true });
        let (s, v) = call_api(&mut a, "POST", "/v1/plans", json!({ "operation": over }));
        assert_eq!((s, v["code"].as_str()), (409, Some("no_way_back")), "{v}");
        // without a repository nothing restic is planned at all
        let mut b = app(dir.path(), Backups::default());
        let (s, v) = call_api(
            &mut b,
            "POST",
            "/v1/plans",
            json!({ "operation": { "op": "restic_backup", "name": "dev" } }),
        );
        assert_eq!((s, v["code"].as_str()), (422, Some("no_repository")));
    }

    #[test]
    fn the_fleet_view_estimates_snapshot_cost_only_with_a_price_and_calls_it_an_estimate() {
        let dir = tempfile::tempdir().unwrap();
        let mut a = app(
            dir.path(),
            snapshots_only(
                daily("02:00"),
                Retention {
                    keep_daily: 7,
                    keep_weekly: 4,
                    keep_monthly: 6,
                },
            ),
        );
        make_box(&mut a, "dev");
        let (s, v) = call_api(&mut a, "GET", "/v1/backups", Value::Null);
        assert_eq!(s, 200);
        assert_eq!(v["estimate"]["basis"], "estimate");
        assert!(
            v["estimate"]["monthly"].is_null(),
            "no price list, no figure"
        );
        a.prices.book = Some(crate::pricing::PriceBook {
            provider: "aws".into(),
            currency: "USD".into(),
            source: "test".into(),
            region: "us-east-1".into(),
            fetched_at_ms: 1,
            machine_hourly: Default::default(),
            disk_gb_month: None,
            snapshot_gb_month: Some(0.05),
        });
        let (_, v) = call_api(&mut a, "GET", "/v1/backups", Value::Null);
        // 17 snapshots at most x the work disk (100 GB by default) x $0.05
        let disk = f64::from(BoxSpec::new(BoxName::new("x").unwrap(), Size::S).work_disk_gb);
        let want = 17.0 * disk * 0.05;
        assert!(
            (v["estimate"]["monthly"].as_f64().unwrap() - want).abs() < 1e-6,
            "{v}"
        );
        assert_eq!(v["estimate"]["currency"], "USD");
    }

    #[test]
    fn settings_for_backups_are_validated_and_a_bad_one_changes_nothing() {
        let dir = tempfile::tempdir().unwrap();
        let mut a = app(dir.path(), Backups::default());
        let ok = Backups {
            schedule: daily("03:30"),
            ..Backups::default()
        };
        let (s, v) = call_api(
            &mut a,
            "PUT",
            "/v1/backups/settings",
            serde_json::to_value(&ok).unwrap(),
        );
        assert_eq!(s, 200, "{v}");
        assert_eq!(v["settings"]["schedule"]["time"], "03:30");
        let mut bad = ok.clone();
        bad.restic = Some(ResticTarget {
            kind: ResticKind::S3,
            location: "http://not-https".into(),
        });
        let (s, _) = call_api(
            &mut a,
            "PUT",
            "/v1/backups/settings",
            serde_json::to_value(&bad).unwrap(),
        );
        assert_eq!(s, 400);
        let (_, v) = call_api(&mut a, "GET", "/v1/backups", Value::Null);
        assert_eq!(v["settings"]["schedule"]["time"], "03:30");
        assert!(v["settings"]["restic"].is_null());
    }

    #[test]
    fn provider_snapshots_are_listed_per_box_and_a_manual_snapshot_serves_the_slot() {
        let dir = tempfile::tempdir().unwrap();
        let mut a = app(dir.path(), snapshots_only(daily("02:00"), KEEP2));
        make_box(&mut a, "dev");
        let (s, _) = plan_and_apply(&mut a, json!({ "op": "snapshot", "name": "dev" }), None);
        assert_eq!(s, 200);
        let (_, v) = call_api(&mut a, "GET", "/v1/boxes/dev/backups", Value::Null);
        let items = v["items"].as_array().unwrap();
        assert_eq!(items.len(), 1);
        assert_eq!(items[0]["kind"], "snapshot");
        assert_eq!(
            items[0]["scheduled"], false,
            "a manual snapshot is never pruned by the schedule"
        );
        assert!(items[0]["created_at"].is_string() && items[0]["size_bytes"].is_u64());
        assert!(
            a.state.backups["dev"].last_slot_ms.is_some(),
            "a manual backup counts as serving the latest slot"
        );
    }
    fn restic_target_only() -> Backups {
        Backups {
            schedule: Schedule::default(),
            ..restic_backups()
        }
    }

    fn configured_on_box(a: &mut App, name: &str) -> bool {
        let (_, v) = call_api(a, "GET", &format!("/v1/boxes/{name}/backups"), Value::Null);
        v["restic"]["configured_on_box"] == json!(true)
    }

    #[test]
    fn an_upgrade_from_the_dashboard_puts_the_repository_credentials_back_like_the_command_does() {
        let dir = tempfile::tempdir().unwrap();
        let mut a = app(dir.path(), restic_target_only());
        make_box(&mut a, "dev");
        set_secrets(&a);
        a.backup_rt.upgrade_waits = Some(crate::run::upgrade::Waits {
            timeout: std::time::Duration::from_secs(5),
            poll: std::time::Duration::from_millis(1),
        });
        assert!(!configured_on_box(&mut a, "dev"), "no credentials before");
        let (s, v) = plan_and_apply(
            &mut a,
            json!({ "op": "upgrade", "name": "dev", "image": "latest" }),
            None,
        );
        assert_eq!(s, 200, "{v}");
        // The follow-up runs on the worker (inline in tests) and its result is applied on the next tick.
        a.tick(unix_ms() + 1_000);
        assert!(
            configured_on_box(&mut a, "dev"),
            "the upgrade put the credentials back from the secret store"
        );
        let (_, act) = call_api(&mut a, "GET", "/v1/activity", Value::Null);
        let text = act.to_string();
        assert!(text.contains("upgrade backups"), "{text}");
        assert!(
            !text.contains("sekrit") && !text.contains("correct-horse"),
            "no secret reaches Activity"
        );
    }

    /// A box that backs up to a repository, keeps no record of it (made before the record existed), and whose new machine
    /// starts without the credentials (a new secrets store): what the dashboard's own upgrade has to catch.
    struct LosesItsStore {
        configured: std::sync::Mutex<bool>,
        /// Answers what getting the box ready for the stop asks (runs, quiesce, checkpoint), as the demo box does.
        stand_in: crate::serve::agent::SimulatedAgent,
        /// What the box answers to listing its repository, and whether its secrets service is up.
        held: std::sync::Mutex<Held>,
    }

    #[derive(Clone, Copy, Default)]
    struct Held {
        /// A prune holds the repository: the list answers 409 `busy`.
        busy: bool,
        /// The secrets service is not up yet.
        not_ready: bool,
    }

    impl crate::serve::BoxAgent for LosesItsStore {
        fn metrics_now(
            &self,
            _: &BoxRecord,
            _: u64,
        ) -> std::result::Result<ozbox_core::MetricsSample, crate::serve::agent::AgentError>
        {
            Err(crate::serve::agent::AgentError::Unsupported("none".into()))
        }
        fn metrics_series(
            &self,
            _: &BoxRecord,
            _: u64,
            _: u64,
            _: u64,
        ) -> std::result::Result<Vec<ozbox_core::MetricsSample>, crate::serve::agent::AgentError>
        {
            Err(crate::serve::agent::AgentError::Unsupported("none".into()))
        }
        fn incidents(
            &self,
            _: &BoxRecord,
            _: u64,
            _: u64,
        ) -> std::result::Result<Vec<crate::serve::agent::Incident>, crate::serve::agent::AgentError>
        {
            Ok(Vec::new())
        }
        fn selftest(
            &self,
            _: &BoxRecord,
            _: u64,
        ) -> std::result::Result<crate::serve::agent::SelfTest, crate::serve::agent::AgentError>
        {
            // the new machine's first self-test: from here the store is new
            *self.configured.lock().unwrap() = false;
            Ok(crate::serve::agent::SelfTest {
                ts_ms: 1,
                ok: true,
                all_verified: true,
                checks: Vec::new(),
            })
        }
        fn checkpoint(
            &self,
            rec: &BoxRecord,
        ) -> std::result::Result<
            crate::serve::agent::CheckpointOutcome,
            crate::serve::agent::AgentError,
        > {
            self.stand_in.checkpoint(rec)
        }
        fn runs(
            &self,
            rec: &BoxRecord,
            m: &str,
            sub: &str,
            b: &[u8],
        ) -> std::result::Result<(u16, Value), crate::serve::agent::AgentError> {
            self.stand_in.runs(rec, m, sub, b)
        }
        fn quiesce_call(
            &self,
            rec: &BoxRecord,
            m: &str,
            b: &[u8],
        ) -> std::result::Result<(u16, Value), crate::serve::agent::AgentError> {
            self.stand_in.quiesce_call(rec, m, b)
        }
        fn agent_call(
            &self,
            rec: &BoxRecord,
            m: &str,
            p: &str,
            b: &[u8],
        ) -> std::result::Result<(u16, Value), crate::serve::agent::AgentError> {
            self.stand_in.agent_call(rec, m, p, b)
        }
        fn restic(
            &self,
            _: &BoxRecord,
            method: &str,
            sub: &str,
            _: &[u8],
        ) -> std::result::Result<(u16, Value), crate::serve::agent::AgentError> {
            let configured = *self.configured.lock().unwrap();
            let held = *self.held.lock().unwrap();
            Ok(match (method, sub) {
                ("GET", "/status") => (
                    200,
                    json!({ "configured": configured && !held.not_ready, "secrets_ready": !held.not_ready, "expected": false, "running": null, "last": null }),
                ),
                ("GET", "/snapshots") if configured && held.busy => (
                    409,
                    json!({ "error": "a backup operation is using the repository right now", "code": "busy" }),
                ),
                ("GET", "/snapshots") if configured => (200, json!({ "items": [] })),
                _ => (
                    409,
                    json!({ "error": "no repository", "code": "not_configured" }),
                ),
            })
        }
    }

    #[test]
    fn a_dashboard_upgrade_reads_the_box_before_the_replace_so_backups_that_stopped_are_not_taken_for_none(
    ) {
        let dir = tempfile::tempdir().unwrap();
        // this computer holds no repository: nothing to put back, so the only way to tell is what the box said before
        let mut a = app(dir.path(), Backups::default()).with_agent(Box::new(LosesItsStore {
            configured: std::sync::Mutex::new(true),
            stand_in: Default::default(),
            held: Default::default(),
        }));
        make_box(&mut a, "dev");
        a.backup_rt.upgrade_waits = Some(crate::run::upgrade::Waits {
            timeout: std::time::Duration::from_secs(5),
            poll: std::time::Duration::from_millis(1),
        });
        let (s, v) = plan_and_apply(
            &mut a,
            json!({ "op": "upgrade", "name": "dev", "image": "latest" }),
            None,
        );
        assert_eq!(s, 200, "{v}");
        a.tick(unix_ms() + 1_000);
        let (_, act) = call_api(&mut a, "GET", "/v1/activity", Value::Null);
        let text = act.to_string();
        assert!(
            text.contains("HAVE STOPPED") && text.contains("ozbox backup credentials dev"),
            "{text}"
        );
    }

    #[test]
    fn a_box_whose_repository_is_busy_says_so_and_is_not_an_error_or_an_empty_list() {
        let dir = tempfile::tempdir().unwrap();
        let mut a = app(dir.path(), restic_target_only()).with_agent(Box::new(LosesItsStore {
            configured: std::sync::Mutex::new(true),
            stand_in: Default::default(),
            held: std::sync::Mutex::new(Held {
                busy: true,
                not_ready: false,
            }),
        }));
        make_box(&mut a, "dev");
        let (s, v) = call_api(&mut a, "GET", "/v1/boxes/dev/backups", Value::Null);
        assert_eq!(s, 200, "{v}");
        assert_eq!(v["restic"]["busy"], json!(true), "{v}");
        assert!(
            v["restic"]["error"].is_null(),
            "a busy repository is not an error: {v}"
        );
        assert_eq!(v["restic"]["configured_on_box"], json!(true));
    }

    #[test]
    fn a_box_whose_secrets_service_is_not_up_is_not_offered_credentials_as_if_it_had_none() {
        let dir = tempfile::tempdir().unwrap();
        let mut a = app(dir.path(), restic_target_only()).with_agent(Box::new(LosesItsStore {
            configured: std::sync::Mutex::new(true),
            stand_in: Default::default(),
            held: std::sync::Mutex::new(Held {
                busy: false,
                not_ready: true,
            }),
        }));
        make_box(&mut a, "dev");
        let (_, v) = call_api(&mut a, "GET", "/v1/boxes/dev/backups", Value::Null);
        assert_eq!(v["restic"]["secrets_ready"], json!(false), "{v}");
        // an unforced send (what a scheduled backup and an upgrade do) never goes on a guess
        let rec = a
            .provider
            .get(&BoxName::new("dev").unwrap())
            .unwrap()
            .unwrap();
        let t = ResticTarget {
            kind: ResticKind::S3,
            location: "https://objects.example.com/bucket".into(),
        };
        set_secrets(&a);
        let e = crate::backup_ops::ensure_credentials(
            a.agent.as_ref(),
            &rec,
            &t,
            a.secrets.as_ref(),
            false,
        )
        .unwrap_err();
        assert!(
            e.contains("not ready") && e.contains("nothing was sent"),
            "{e}"
        );
    }

    #[test]
    fn turning_a_box_off_removes_its_credentials_and_its_schedule_so_nothing_puts_them_back() {
        let dir = tempfile::tempdir().unwrap();
        let mut a = app(dir.path(), restic_backups());
        make_box(&mut a, "dev");
        make_box(&mut a, "other");
        set_secrets(&a);
        for b in ["dev", "other"] {
            let (s, _) = call_api(
                &mut a,
                "POST",
                &format!("/v1/boxes/{b}/backups/credentials"),
                Value::Null,
            );
            assert_eq!(s, 200);
        }
        assert!(configured_on_box(&mut a, "dev"));
        let (_, before) = call_api(&mut a, "GET", "/v1/boxes/dev/backups", Value::Null);
        assert_eq!(before["turned_off"], json!(false));
        assert_eq!(before["schedule"]["kind"], "daily");
        let (s, v) = call_api(&mut a, "POST", "/v1/boxes/dev/backups/off", Value::Null);
        assert_eq!(s, 200, "{v}");
        // the box holds nothing, and its schedule is off, so the next slot sends nothing
        assert!(!configured_on_box(&mut a, "dev"));
        let (_, after) = call_api(&mut a, "GET", "/v1/boxes/dev/backups", Value::Null);
        assert_eq!(after["turned_off"], json!(true));
        assert_eq!(after["schedule"]["kind"], "off");
        assert!(a.settings.backups.is_off_for("dev"));
        settle(&mut a, ms("2026-11-09T12:00:00Z"));
        let t1 = ms("2026-11-10T02:05:00Z");
        settle(&mut a, t1);
        settle(&mut a, t1 + 40_000);
        assert!(
            !configured_on_box(&mut a, "dev"),
            "a scheduled slot must not send the credentials back"
        );
        // another box is untouched
        assert!(configured_on_box(&mut a, "other"));
        // it is in Activity, with no secret
        let (_, act) = call_api(&mut a, "GET", "/v1/activity", Value::Null);
        let text = act.to_string();
        assert!(text.contains("turn off backups"), "{text}");
        assert!(!text.contains("sekrit") && !text.contains("correct-horse"));
        // a box that does not exist
        let (s, _) = call_api(&mut a, "POST", "/v1/boxes/ghost/backups/off", Value::Null);
        assert_eq!(s, 404);
    }

    #[test]
    fn turning_a_box_off_when_it_cannot_be_reached_changes_nothing() {
        let dir = tempfile::tempdir().unwrap();
        let mut a = app(dir.path(), restic_backups());
        make_box(&mut a, "dev");
        let plan = a
            .provider
            .plan(&Operation::Pause {
                name: BoxName::new("dev").unwrap(),
            })
            .unwrap();
        a.provider.apply(&plan).unwrap();
        let (s, v) = call_api(&mut a, "POST", "/v1/boxes/dev/backups/off", Value::Null);
        assert_eq!(s, 409, "{v}");
        assert_eq!(v["code"], "box_not_running");
        assert!(!a.settings.backups.is_off_for("dev"), "nothing was changed");
    }

    #[test]
    fn an_upgrade_with_no_repository_says_nothing_about_backups() {
        let dir = tempfile::tempdir().unwrap();
        let mut a = app(dir.path(), Backups::default());
        make_box(&mut a, "dev");
        let (s, v) = plan_and_apply(
            &mut a,
            json!({ "op": "upgrade", "name": "dev", "image": "latest" }),
            None,
        );
        assert_eq!(s, 200, "{v}");
        a.tick(unix_ms() + 1_000);
        let (_, act) = call_api(&mut a, "GET", "/v1/activity", Value::Null);
        assert!(act.to_string().contains("upgrade check"));
        assert!(!act.to_string().contains("upgrade backups"));
    }

    #[test]
    fn a_missing_secret_after_an_upgrade_is_reported_and_alerted_not_ignored() {
        let dir = tempfile::tempdir().unwrap();
        let mut a = app(dir.path(), restic_target_only());
        make_box(&mut a, "dev");
        // no secrets in the store
        a.backup_rt.upgrade_waits = Some(crate::run::upgrade::Waits {
            timeout: std::time::Duration::from_secs(5),
            poll: std::time::Duration::from_millis(1),
        });
        let (s, _) = plan_and_apply(
            &mut a,
            json!({ "op": "upgrade", "name": "dev", "image": "latest" }),
            None,
        );
        assert_eq!(s, 200);
        a.tick(unix_ms() + 1_000);
        let (_, act) = call_api(&mut a, "GET", "/v1/activity", Value::Null);
        let text = act.to_string();
        assert!(
            text.contains("upgrade backups") && text.contains("NOT restored"),
            "{text}"
        );
    }

    #[test]
    fn a_repository_backup_is_restored_into_a_new_box_in_one_plan_and_followed_to_the_end() {
        let dir = tempfile::tempdir().unwrap();
        let mut a = app(dir.path(), restic_target_only());
        make_box(&mut a, "dev");
        set_secrets(&a);
        // A backup of dev in the repository.
        let (s, v) = plan_and_apply(
            &mut a,
            json!({ "op": "restic_backup", "name": "dev" }),
            None,
        );
        assert_eq!(s, 200, "{v}");
        settle(&mut a, unix_ms() + 15_000);
        settle(&mut a, unix_ms() + 30_000);
        let (_, v) = call_api(&mut a, "GET", "/v1/boxes/dev/backups", Value::Null);
        let id = v["items"]
            .as_array()
            .unwrap()
            .iter()
            .find(|i| i["kind"] == "restic")
            .unwrap()["id"]
            .as_str()
            .unwrap()
            .to_string();
        let op = json!({ "op": "restore_to_new_box", "from": "dev", "to": "copy", "snapshot": id });
        let (s, p) = call_api(&mut a, "POST", "/v1/plans", json!({ "operation": op }));
        assert_eq!(s, 200, "{p}");
        let kinds: Vec<&str> = p["plan"]["changes"]
            .as_array()
            .unwrap()
            .iter()
            .map(|c| c["kind"].as_str().unwrap())
            .collect();
        assert!(kinds.contains(&"box.create"), "{kinds:?}");
        assert_eq!(
            &kinds[kinds.len() - 3..],
            ["backup.credentials", "backup.restore", "box.selftest"]
        );
        // Planning created nothing.
        assert!(a
            .provider
            .get(&BoxName::new("copy").unwrap())
            .unwrap()
            .is_none());
        let (s, v) = plan_and_apply(&mut a, op, None);
        assert_eq!(s, 200, "{v}");
        let copy = BoxName::new("copy").unwrap();
        assert!(
            a.provider.get(&copy).unwrap().is_some(),
            "the box was created"
        );
        assert!(
            a.state.backups["copy"].new_box_restore.is_some(),
            "and remembered, so a restart carries on"
        );
        // The ticks hand over the credentials, start the restore and check the box; each one does one thing.
        let mut at = unix_ms();
        for _ in 0..8 {
            at += 6_000;
            settle(&mut a, at);
            if a.state.backups["copy"].new_box_restore.is_none() {
                break;
            }
        }
        assert!(
            a.state.backups["copy"].new_box_restore.is_none(),
            "{:?}",
            a.state.backups["copy"].new_box_restore
        );
        let (_, act) = call_api(&mut a, "GET", "/v1/activity", Value::Null);
        let text = act.to_string();
        assert!(
            text.contains("restore a backup into a new box") && text.contains("restored files"),
            "{text}"
        );
        assert!(!text.contains("sekrit") && !text.contains("correct-horse"));
        // The new box is a real, ordinary box now.
        assert!(configured_on_box(&mut a, "copy"));
    }

    #[test]
    fn a_restore_into_a_new_box_is_refused_for_a_missing_repository_backup_or_source() {
        let dir = tempfile::tempdir().unwrap();
        let mut a = app(dir.path(), restic_target_only());
        make_box(&mut a, "dev");
        set_secrets(&a);
        // Once dev holds the credentials it can say which backups the repository has: one it lacks is refused.
        let (s, v) = call_api(
            &mut a,
            "POST",
            "/v1/boxes/dev/backups/credentials",
            Value::Null,
        );
        assert_eq!(s, 200, "{v}");
        let (s, v) = call_api(
            &mut a,
            "POST",
            "/v1/plans",
            json!({ "operation": { "op": "restore_to_new_box", "from": "dev", "to": "copy", "snapshot": "aaaaaaaa" } }),
        );
        assert_eq!(s, 404, "{v}");
        let (s, _) = call_api(
            &mut a,
            "POST",
            "/v1/plans",
            json!({ "operation": { "op": "restore_to_new_box", "from": "ghost", "to": "copy", "snapshot": "aaaaaaaa" } }),
        );
        assert_eq!(s, 404);
        let mut b = app(dir.path(), Backups::default());
        let (s, v) = call_api(
            &mut b,
            "POST",
            "/v1/plans",
            json!({ "operation": { "op": "restore_to_new_box", "from": "dev", "to": "copy", "snapshot": "aaaaaaaa" } }),
        );
        assert_eq!((s, v["code"].as_str()), (422, Some("no_repository")));
    }
    #[test]
    fn a_restored_work_disk_is_followed_by_a_check_of_the_box_and_no_credentials_step() {
        let dir = tempfile::tempdir().unwrap();
        let mut a = app(dir.path(), restic_target_only());
        make_box(&mut a, "dev");
        set_secrets(&a);
        a.backup_rt.upgrade_waits = Some(crate::run::upgrade::Waits {
            timeout: std::time::Duration::from_secs(5),
            poll: std::time::Duration::from_millis(1),
        });
        let (s, v) = plan_and_apply(&mut a, json!({ "op": "snapshot", "name": "dev" }), None);
        assert_eq!(s, 200, "{v}");
        let snap = snaps(&a, "dev")[0].clone();
        let (s, v) = plan_and_apply(
            &mut a,
            json!({ "op": "restore_work", "name": "dev", "snapshot": snap }),
            Some("dev"),
        );
        assert_eq!(s, 200, "{v}");
        a.tick(unix_ms() + 1_000);
        let (_, act) = call_api(&mut a, "GET", "/v1/activity", Value::Null);
        let text = act.to_string();
        assert!(text.contains("restore check"), "{text}");
        assert!(!text.contains("restore backups"), "{text}");
        assert!(
            !configured_on_box(&mut a, "dev"),
            "a /work swap does not touch the credentials"
        );
    }

    /// An upgrade's copy of an old system disk is often the newest snapshot of a box, and is listed first: it must never decide
    /// whether the provider's backups include /work.
    #[test]
    fn a_copy_of_an_old_system_disk_never_answers_for_whether_backups_include_work() {
        let snap = |id: &str, includes_work: bool, purpose: Option<&str>| SnapshotInfo {
            id: id.into(),
            kind: ozbox_core::SnapshotKind::Provider,
            created_at: None,
            size_bytes: None,
            status: "completed".into(),
            includes_work,
            labels: purpose
                .map(|p| {
                    std::collections::BTreeMap::from([(
                        ozbox_core::PURPOSE_LABEL.to_string(),
                        p.to_string(),
                    )])
                })
                .unwrap_or_default(),
        };
        let copy = snap(
            "snap-root",
            false,
            Some(ozbox_core::PRE_UPGRADE_ROOT_PURPOSE),
        );
        let work = snap("snap-work", true, None);
        assert_eq!(
            provider_includes_work(&[copy.clone(), work.clone()]),
            Some(true)
        );
        assert_eq!(provider_includes_work(&[work]), Some(true));
        // only copies: there is no backup to speak for
        assert_eq!(provider_includes_work(&[copy]), None);
        assert_eq!(provider_includes_work(&[]), None);
    }
}
