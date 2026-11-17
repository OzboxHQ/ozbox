//! Schedules and triggers in the dashboard server: the `/v1` routes, the public `/hooks/<id>` route and the tick.
//!
//! Everything that can wait (waking a box, starting a run, following one) runs on the background worker; the request
//! thread only reads and writes the small fleet store. See `sched::store` for the one-fire guarantee.

use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};

use serde::Deserialize;
use serde_json::{json, Value};

use super::worker::Done;
use super::{unix_ms, App, Req, Resp};
use crate::messages::t;
use crate::notify::{Alert, Severity};
use crate::sched::engine::{self, new_id, Fire, Notice};
use crate::sched::hooks::RateLimiter;
use crate::sched::input::{self, ScheduleIn, TriggerIn};
use crate::sched::model::*;
use crate::sched::receive;
use crate::sched::runner::{BoxControl, NoRunSystem, ProviderBoxes, RunStarter};
use crate::sched::store::{self, Store};
use crate::sched::view::{self, CostInputs, PreviewIn};

const TICK_EVERY_MS: u64 = 5_000;

pub struct Rt {
    store: Option<Store>,
    me: String,
    next_tick_ms: u64,
    busy: bool,
    pub runs: Arc<dyn RunStarter>,
    pub connected: bool,
    limiter: RateLimiter,
    done: Arc<Mutex<Vec<Vec<Notice>>>>,
}

impl Default for Rt {
    fn default() -> Self {
        let mut b = [0u8; 6];
        let _ = getrandom::getrandom(&mut b);
        let hex: String = b.iter().map(|x| format!("{x:02x}")).collect();
        Rt {
            store: None,
            me: format!("dash-{}-{hex}", std::process::id()),
            next_tick_ms: 0,
            busy: false,
            runs: Arc::new(NoRunSystem),
            connected: false,
            limiter: RateLimiter::default(),
            done: Arc::default(),
        }
    }
}

fn parse<T: serde::de::DeserializeOwned>(b: &[u8]) -> Result<T, Resp> {
    serde_json::from_slice(b)
        .map_err(|e| Resp::error(400, "bad_request", &format!("invalid request: {e}")))
}

fn invalid(key: &str, detail: &str) -> Resp {
    Resp::error(400, "invalid", &t(key, &[("detail", detail)]))
}

fn unavailable() -> Resp {
    Resp::error(503, "unavailable", &t("hook.store_busy", &[]))
}

impl App {
    fn sched_store(&mut self) -> Store {
        if let Some(s) = &self.sched.store {
            return s.clone();
        }
        let path = match &self.settings_path {
            Some(p) => p.with_file_name("fleet-schedules.json"),
            None => std::env::temp_dir().join(format!(
                "ozbox-sched-{}-{}.json",
                std::process::id(),
                self.sched.me
            )),
        };
        let s = crate::sched::shared::store_at(path);
        self.sched.store = Some(s.clone());
        s
    }

    /// Use this file as the fleet store (tests, and a server told where its state lives).
    #[cfg(test)]
    pub fn with_sched_store(mut self, path: std::path::PathBuf) -> Self {
        self.sched.store = Some(Store::new(path));
        self
    }

    /// The system that starts runs. Until one is connected, runs fail with a plain reason.
    pub fn with_run_system(mut self, runs: Arc<dyn RunStarter>) -> Self {
        self.sched.runs = runs;
        self.sched.connected = true;
        self
    }

    fn person_zone(&self, owner: &str) -> String {
        self.settings
            .routing
            .people
            .get(owner)
            .and_then(|p| p.time_zone.clone())
            .unwrap_or_else(|| self.settings.locale.zone().to_string())
    }

    fn cost_inputs(&self, s: &Schedule) -> Option<CostInputs> {
        let name = match (&s.target.box_name, &s.target.profile) {
            (Some(b), _) => b.clone(),
            (None, Some(p)) => self
                .provider
                .list()
                .ok()?
                .into_iter()
                .find(|r| r.spec.labels.get("profile").is_some_and(|v| v == p))?
                .spec
                .name
                .to_string(),
            _ => return None,
        };
        let rec = self
            .provider
            .get(&ozbox_core::BoxName::new(&name).ok()?)
            .ok()??;
        let c = crate::pricing::box_cost(&rec, &self.settings, self.prices.book.as_ref());
        Some(CostInputs {
            hourly: c.machine_hourly?,
            currency: c.currency,
            auto_pause_minutes: self.settings.defaults.auto_pause_minutes,
        })
    }

    pub(super) fn public_base(&self) -> Option<String> {
        let p = crate::tunnel_cli::tunnel_path()?;
        let f = crate::tunnel::TunnelFile::load(&p).ok()??;
        (!f.public_url.is_empty()).then_some(f.public_url)
    }

    // ---------- routes ----------

    pub(super) fn sched_route(&mut self, method: &str, rest: &[&str], body: &[u8]) -> Resp {
        let store = self.sched_store();
        let now = unix_ms();
        match (method, rest) {
            ("GET", []) => {
                let doc = store.read();
                let items: Vec<Value> = doc
                    .schedules
                    .iter()
                    .map(|s| {
                        let inp = self.cost_inputs(s);
                        view::schedule(s, &doc, now, inp.as_ref())
                    })
                    .collect();
                let lease = doc.lease.as_ref().map(|l| {
                    json!({ "holder_is_me": l.holder == self.sched.me, "epoch": l.epoch, "expires_ms": l.expires_ms })
                });
                Resp::json(
                    200,
                    &json!({
                        "schedules": items,
                        "lease": lease,
                        "time_zone": self.settings.locale.zone(),
                        "now_ms": now,
                        "run_system_connected": self.sched.connected,
                        "source": if self.simulated_metrics { "simulated" } else { "live" },
                        "catch_up_default_minutes": DEFAULT_CATCH_UP_MINUTES,
                    }),
                )
            }
            ("POST", ["preview"]) => {
                #[derive(Deserialize, Default)]
                #[serde(default)]
                struct P {
                    when_text: Option<String>,
                    cron: Option<String>,
                    time_zone: Option<String>,
                    owner: Option<String>,
                    count: Option<usize>,
                }
                let p: P = match parse(body) {
                    Ok(p) => p,
                    Err(r) => return r,
                };
                let zone = p
                    .time_zone
                    .clone()
                    .unwrap_or_else(|| self.person_zone(p.owner.as_deref().unwrap_or("")));
                match view::preview(
                    &PreviewIn {
                        text: p.when_text.as_deref(),
                        cron: p.cron.as_deref(),
                        time_zone: &zone,
                        count: p.count.unwrap_or(5),
                    },
                    now,
                ) {
                    Ok(v) => Resp::json(200, &v),
                    Err((k, d)) => invalid(k, &d),
                }
            }
            ("POST", []) => {
                let input: ScheduleIn = match parse(body) {
                    Ok(i) => i,
                    Err(r) => return r,
                };
                let mut s = input::new_schedule(now);
                if let Err(r) = self.apply_schedule_in(&mut s, input, true, now) {
                    return r;
                }
                if store.read().schedules.len() >= MAX_SCHEDULES {
                    return invalid("sched.bad_name", "too many schedules");
                }
                let id = s.id.clone();
                let sc = s.clone();
                if store
                    .update(|d| {
                        d.state.insert(
                            id.clone(),
                            SchedState {
                                armed_ms: now,
                                ..Default::default()
                            },
                        );
                        d.schedules.push(sc);
                    })
                    .is_err()
                {
                    return unavailable();
                }
                self.log_activity(
                    "schedule created",
                    s.target.box_name.as_deref().unwrap_or("-"),
                    None,
                    "ok",
                );
                self.sched_one(&store, &id, now)
            }
            ("GET", ["runs"]) => {
                let doc = store.read();
                let names: BTreeMap<String, String> = doc
                    .schedules
                    .iter()
                    .map(|s| (s.id.clone(), s.name.clone()))
                    .chain(doc.triggers.iter().map(|t| (t.id.clone(), t.name.clone())))
                    .collect();
                let runs: Vec<Value> = doc
                    .runs
                    .iter()
                    .rev()
                    .take(100)
                    .map(|r| {
                        let mut v = serde_json::to_value(r).unwrap_or(Value::Null);
                        if let Value::Object(m) = &mut v {
                            m.insert("name".into(), json!(names.get(&r.owner_id)));
                        }
                        v
                    })
                    .collect();
                Resp::json(200, &json!({ "runs": runs }))
            }
            ("GET", [id]) => self.sched_one(&store, id, now),
            ("GET", [id, "runs"]) => {
                let doc = store.read();
                if doc.schedule(id).is_none() {
                    return Resp::error(404, "not_found", "no such schedule");
                }
                let runs: Vec<&RunRec> = doc
                    .runs
                    .iter()
                    .rev()
                    .filter(|r| r.owner_id == *id)
                    .take(50)
                    .collect();
                Resp::json(200, &json!({ "runs": runs }))
            }
            ("PUT", [id]) => {
                let input: ScheduleIn = match parse(body) {
                    Ok(i) => i,
                    Err(r) => return r,
                };
                let Some(mut s) = store.read().schedule(id).cloned() else {
                    return Resp::error(404, "not_found", "no such schedule");
                };
                let before = (s.when.clone(), s.time_zone.clone(), s.enabled);
                if let Err(r) = self.apply_schedule_in(&mut s, input, false, now) {
                    return r;
                }
                s.updated_ms = now;
                let rearm = before != (s.when.clone(), s.time_zone.clone(), s.enabled);
                let sid = id.to_string();
                let _ = store.update(|d| {
                    if let Some(x) = d.schedules.iter_mut().find(|x| x.id == sid) {
                        *x = s;
                    }
                    if rearm {
                        let st = d.state.entry(sid.clone()).or_default();
                        st.armed_ms = now;
                        st.last_slot_ms = None;
                    }
                });
                self.sched_one(&store, id, now)
            }
            ("DELETE", [id]) => {
                let sid = id.to_string();
                let found = store
                    .update(|d| {
                        let n = d.schedules.len();
                        d.schedules.retain(|s| s.id != sid);
                        d.state.remove(&sid);
                        d.run_now.retain(|r| r.schedule_id != sid);
                        d.schedules.len() != n
                    })
                    .unwrap_or(false);
                if found {
                    Resp::json(200, &json!({ "removed": id }))
                } else {
                    Resp::error(404, "not_found", "no such schedule")
                }
            }
            ("POST", [id, action @ ("pause" | "resume")]) => {
                let on = *action == "resume";
                let sid = id.to_string();
                let found = store
                    .update(|d| {
                        let Some(s) = d.schedules.iter_mut().find(|s| s.id == sid) else {
                            return false;
                        };
                        s.enabled = on;
                        s.updated_ms = now;
                        if on {
                            // Never replay what was missed while it was off.
                            let st = d.state.entry(sid.clone()).or_default();
                            st.armed_ms = now;
                            st.last_slot_ms = None;
                        }
                        true
                    })
                    .unwrap_or(false);
                if !found {
                    return Resp::error(404, "not_found", "no such schedule");
                }
                self.sched_one(&store, id, now)
            }
            ("POST", [id, "run-now"]) => {
                let sid = id.to_string();
                let ok = store
                    .update(|d| {
                        if d.schedule(&sid).is_none() {
                            return false;
                        }
                        d.run_now.push(RunNow {
                            id: new_id("now"),
                            schedule_id: sid.clone(),
                            requested_ms: now,
                            by: "dashboard".into(),
                        });
                        true
                    })
                    .unwrap_or(false);
                self.sched.next_tick_ms = 0;
                if ok {
                    Resp::json(202, &json!({ "queued": true }))
                } else {
                    Resp::error(404, "not_found", "no such schedule")
                }
            }
            _ => Resp::error(404, "not_found", "no such endpoint"),
        }
    }

    fn sched_one(&self, store: &Store, id: &str, now: u64) -> Resp {
        let doc = store.read();
        match doc.schedule(id) {
            Some(s) => {
                let inp = self.cost_inputs(s);
                Resp::json(200, &view::schedule(s, &doc, now, inp.as_ref()))
            }
            None => Resp::error(404, "not_found", "no such schedule"),
        }
    }

    fn apply_schedule_in(
        &self,
        s: &mut Schedule,
        i: ScheduleIn,
        is_new: bool,
        now: u64,
    ) -> Result<(), Resp> {
        let zone = self.person_zone(i.owner.as_deref().unwrap_or(&s.owner));
        input::apply_schedule(s, i, &zone, is_new, now).map_err(|(k, d)| invalid(k, &d))
    }

    pub(super) fn trigger_route(&mut self, method: &str, rest: &[&str], body: &[u8]) -> Resp {
        let store = self.sched_store();
        let now = unix_ms();
        match (method, rest) {
            ("GET", []) => {
                // a retired secret whose overlap is over is deleted
                let lapsed: Vec<String> = store
                    .read()
                    .triggers
                    .iter()
                    .filter(|t| t.previous_secret_until_ms.is_some_and(|u| now >= u))
                    .map(|t| t.id.clone())
                    .collect();
                if !lapsed.is_empty() {
                    for id in &lapsed {
                        let _ = self.secrets.delete(&receive::previous_secret_name(id));
                    }
                    let _ = store.update(|d| {
                        for t in d.triggers.iter_mut().filter(|t| lapsed.contains(&t.id)) {
                            t.previous_secret_until_ms = None;
                        }
                    });
                }
                let doc = store.read();
                let base = self.public_base();
                let items: Vec<Value> = doc
                    .triggers
                    .iter()
                    .map(|tr| {
                        let set = self
                            .secrets
                            .exists(&receive::secret_name(&tr.id))
                            .unwrap_or(false);
                        view::trigger(tr, &doc, set, base.as_deref())
                    })
                    .collect();
                Resp::json(
                    200,
                    &json!({ "triggers": items, "public_url_set": base.is_some(), "max_body_bytes": crate::sched::hooks::MAX_BODY, "source": if self.simulated_metrics { "simulated" } else { "live" } }),
                )
            }
            ("POST", []) => {
                let i: TriggerIn = match parse(body) {
                    Ok(i) => i,
                    Err(r) => return r,
                };
                let tr = match input::build_trigger(i, now) {
                    Ok(t) => t,
                    Err((k, d)) => return invalid(k, &d),
                };
                if store.read().triggers.len() >= MAX_TRIGGERS {
                    return invalid("sched.bad_name", "too many triggers");
                }
                let Some(secret) = input::new_secret() else {
                    return Resp::error(500, "internal", "no randomness available");
                };
                if let Err(e) = self.secrets.set(&receive::secret_name(&tr.id), &secret) {
                    return Resp::error(500, "cannot_save", &e.to_string());
                }
                let t2 = tr.clone();
                if store.update(|d| d.triggers.push(t2)).is_err() {
                    let _ = self.secrets.delete(&receive::secret_name(&tr.id));
                    return unavailable();
                }
                self.log_activity("trigger created", "-", None, "ok");
                let doc = store.read();
                let mut v = view::trigger(&tr, &doc, true, self.public_base().as_deref());
                // The one time the secret is ever shown.
                if let Value::Object(m) = &mut v {
                    m.insert("secret".into(), json!(secret));
                }
                Resp::json(201, &v)
            }
            ("DELETE", [id]) => {
                let tid = id.to_string();
                let found = store
                    .update(|d| {
                        let n = d.triggers.len();
                        d.triggers.retain(|t| t.id != tid);
                        d.triggers.len() != n
                    })
                    .unwrap_or(false);
                if !found {
                    return Resp::error(404, "not_found", "no such trigger");
                }
                let _ = self.secrets.delete(&receive::secret_name(id));
                let _ = self.secrets.delete(&receive::previous_secret_name(id));
                Resp::json(200, &json!({ "removed": id }))
            }
            ("POST", [id, "rotate-secret"]) => {
                let tid = id.to_string();
                if !store.read().triggers.iter().any(|t| t.id == tid) {
                    return Resp::error(404, "not_found", "no such trigger");
                }
                let current = match self.secrets.get(&receive::secret_name(id)) {
                    Ok(Some(s)) => s,
                    _ => return Resp::error(409, "no_secret", "this trigger has no secret"),
                };
                let Some(fresh) = input::new_secret() else {
                    return Resp::error(500, "internal", "no randomness available");
                };
                // the old secret is kept, apart, for the overlap window; the new one is current from now on
                if self
                    .secrets
                    .set(&receive::previous_secret_name(id), &current)
                    .and_then(|()| self.secrets.set(&receive::secret_name(id), &fresh))
                    .is_err()
                {
                    return Resp::error(500, "cannot_save", "the secret could not be saved");
                }
                let until = now + receive::SECRET_OVERLAP_MS;
                if store
                    .update(|d| {
                        if let Some(t) = d.triggers.iter_mut().find(|t| t.id == tid) {
                            t.previous_secret_until_ms = Some(until);
                        }
                    })
                    .is_err()
                {
                    return unavailable();
                }
                self.log_activity("trigger secret rotated", "-", None, "ok");
                let doc = store.read();
                let mut v = doc
                    .triggers
                    .iter()
                    .find(|t| t.id == *id)
                    .map(|t| view::trigger(t, &doc, true, self.public_base().as_deref()))
                    .unwrap_or(Value::Null);
                if let Value::Object(m) = &mut v {
                    // the one time the new secret is shown
                    m.insert("secret".into(), json!(fresh));
                    m.insert("previous_secret_until_ms".into(), json!(until));
                }
                Resp::json(200, &v)
            }
            ("POST", [id, action @ ("enable" | "disable")]) => {
                let (tid, on) = (id.to_string(), *action == "enable");
                let found = store
                    .update(|d| match d.triggers.iter_mut().find(|t| t.id == tid) {
                        Some(t) => {
                            t.enabled = on;
                            true
                        }
                        None => false,
                    })
                    .unwrap_or(false);
                if !found {
                    return Resp::error(404, "not_found", "no such trigger");
                }
                let doc = store.read();
                match doc.trigger(id) {
                    Some(tr) => Resp::json(
                        200,
                        &view::trigger(tr, &doc, true, self.public_base().as_deref()),
                    ),
                    None => Resp::error(404, "not_found", "no such trigger"),
                }
            }
            ("GET", [id, "deliveries"]) => {
                let doc = store.read();
                if doc.trigger(id).is_none() {
                    return Resp::error(404, "not_found", "no such trigger");
                }
                let d: Vec<&Delivery> = doc
                    .deliveries
                    .iter()
                    .rev()
                    .filter(|d| d.trigger_id == *id)
                    .take(50)
                    .collect();
                Resp::json(200, &json!({ "deliveries": d }))
            }
            ("POST", [id, "test"]) => {
                let doc = store.read();
                let Some(tr) = doc.trigger(id).cloned() else {
                    return Resp::error(404, "not_found", "no such trigger");
                };
                let Ok(Some(secret)) = self.secrets.get(&receive::secret_name(id)) else {
                    return Resp::error(409, "no_secret", "this trigger has no secret");
                };
                let (h, b) = receive::signed_sample(&tr, &secret, now / 1000);
                // Through the same pipeline as a real delivery, but it starts nothing.
                let r = receive::receive(
                    &store,
                    &*self.secrets,
                    &mut self.sched.limiter,
                    id,
                    &h,
                    &b,
                    now,
                    true,
                );
                Resp::json(r.status, &r.body)
            }
            _ => Resp::error(404, "not_found", "no such endpoint"),
        }
    }

    /// `POST /hooks/<trigger id>`: public, signed, never reached with the dashboard's own sign-in.
    pub(super) fn hook_route(&mut self, req: &Req) -> Resp {
        let id = req.path.trim_start_matches("/hooks/").trim_end_matches('/');
        if req.method != "POST" {
            return Resp::error(405, "method_not_allowed", "method not allowed");
        }
        let store = self.sched_store();
        let headers: BTreeMap<String, String> = req
            .headers
            .iter()
            .map(|(k, v)| (k.clone(), v.clone()))
            .collect();
        let r = receive::receive(
            &store,
            &*self.secrets,
            &mut self.sched.limiter,
            id,
            &headers,
            &req.body,
            unix_ms(),
            false,
        );
        if let Some(fire) = r.fire {
            self.sched_execute(vec![fire]);
        }
        Resp::json(r.status, &r.body)
    }

    // ---------- the tick ----------

    fn sched_alert(&mut self, n: Notice, now: u64) {
        let a = Alert {
            notice: None,
            reach: Default::default(),
            key: n.key,
            kind: "schedule".into(),
            severity: Severity::Normal,
            box_name: n.box_name,
            title: n.title,
            body: n.body,
            ts_ms: now,
        };
        self.route_alerts(vec![a], now);
    }

    fn sched_execute(&mut self, fires: Vec<Fire>) {
        if fires.is_empty() {
            return;
        }
        let store = self.sched_store();
        let boxes: Arc<dyn BoxControl> = Arc::new(ProviderBoxes {
            provider: Arc::clone(&self.provider),
        });
        let runs = Arc::clone(&self.sched.runs);
        let done = Arc::clone(&self.sched.done);
        let job = Box::new(move || {
            let mut notices = Vec::new();
            for f in &fires {
                let o = engine::execute(f, &*boxes, &*runs);
                if let Ok(n) = engine::settle(&store, &o, unix_ms()) {
                    notices.extend(n);
                }
            }
            if let Ok(mut d) = done.lock() {
                d.push(notices);
            }
            Done::Nothing
        });
        let _ = self.submit(job);
    }

    /// Called about once a second. Takes the lease, fires what is due, follows runs in flight.
    pub fn sched_tick(&mut self, now_ms: u64) {
        let finished: Vec<Vec<Notice>> = self
            .sched
            .done
            .lock()
            .map(|mut d| std::mem::take(&mut *d))
            .unwrap_or_default();
        for ns in finished {
            for n in ns {
                self.sched_alert(n, now_ms);
            }
        }
        if now_ms < self.sched.next_tick_ms || self.sched.busy {
            return;
        }
        self.sched.next_tick_ms = now_ms + TICK_EVERY_MS;
        let store = self.sched_store();
        // Nothing to do on a fleet with no schedules; do not even take the lease.
        let doc = store.read();
        if doc.schedules.is_empty()
            && doc.run_now.is_empty()
            && !doc.runs.iter().any(|r| r.status.is_open())
        {
            return;
        }
        let Ok(d) = engine::decide(&store, &self.sched.me, now_ms) else {
            return;
        };
        for n in d.notices {
            self.sched_alert(n, now_ms);
        }
        self.sched_execute(d.fires);
        // Follow the runs in flight (any dashboard may; only the holder fires).
        let open = engine::open_runs(&store.read());
        if !open.is_empty() && d.holder {
            let runs = Arc::clone(&self.sched.runs);
            let done = Arc::clone(&self.sched.done);
            let job = Box::new(move || {
                let polls: Vec<_> = open
                    .into_iter()
                    .map(|(id, r)| (id, runs.poll(&r)))
                    .collect();
                if let Ok(n) = engine::settle_polls(&store, &polls, unix_ms()) {
                    if let Ok(mut dn) = done.lock() {
                        dn.push(n);
                    }
                }
                Done::Nothing
            });
            let _ = self.submit(job);
        }
    }

    /// Hand the lease over at once when the server stops.
    pub fn sched_shutdown(&mut self) {
        let me = self.sched.me.clone();
        let store = self.sched_store();
        if store.path().exists() {
            let _ = store.update(|d| store::release(d, &me));
        }
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use std::collections::HashMap;
    use std::net::{IpAddr, Ipv4Addr, SocketAddr};

    use super::*;
    use crate::sched::hooks;

    fn app(dir: &std::path::Path) -> App {
        let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 7878);
        App::new(
            Box::new(ozbox_provider_fake::open(dir)),
            true,
            addr,
            "tok".into(),
        )
        .with_sched_store(dir.join("fleet-schedules.json"))
        .with_run_system(Arc::new(crate::sched::runner::SimulatedRuns::new(0)))
    }

    fn req(method: &str, path: &str, body: Value) -> Req {
        let mut headers = HashMap::new();
        headers.insert("host".to_string(), "127.0.0.1:7878".to_string());
        headers.insert("authorization".to_string(), "Bearer tok".to_string());
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

    fn json_of(r: &Resp) -> Value {
        serde_json::from_slice(&r.body).unwrap_or(Value::Null)
    }

    fn make_box(a: &mut App, name: &str) {
        let spec =
            ozbox_core::BoxSpec::new(ozbox_core::BoxName::new(name).unwrap(), ozbox_core::Size::M);
        let p = a
            .provider
            .plan(&ozbox_core::Operation::Create { spec })
            .unwrap();
        a.provider.apply(&p).unwrap();
    }

    #[test]
    fn a_schedule_is_made_from_words_listed_with_local_and_utc_and_run_by_the_tick() {
        let d = tempfile::tempdir().unwrap();
        let mut a = app(d.path());
        make_box(&mut a, "alpha");
        let p = a.handle(&req(
            "POST",
            "/v1/schedules/preview",
            json!({ "when_text": "every weekday at 9am Lagos time" }),
        ));
        assert_eq!(p.status, 200);
        let pv = json_of(&p);
        assert_eq!(pv["cron"], "0 9 * * 1-5");
        assert_eq!(pv["next"].as_array().unwrap().len(), 5);
        let bad = a.handle(&req(
            "POST",
            "/v1/schedules/preview",
            json!({ "when_text": "whenever" }),
        ));
        assert_eq!(bad.status, 400);
        let made = a.handle(&req(
            "POST",
            "/v1/schedules",
            json!({ "name": "Brief", "when_text": "every day at 3am UTC", "prompt": "Check.", "engine": "claude", "target": { "box_name": "alpha" } }),
        ));
        assert_eq!(made.status, 200, "{}", String::from_utf8_lossy(&made.body));
        let id = json_of(&made)["id"].as_str().unwrap().to_string();
        let list = json_of(&a.handle(&req("GET", "/v1/schedules", Value::Null)));
        assert_eq!(list["schedules"][0]["time_zone"], "UTC");
        assert!(list["schedules"][0]["next"]["local"]
            .as_str()
            .unwrap()
            .contains("UTC"));
        // Run now: the tick takes the lease, starts it through the run system and settles it.
        assert_eq!(
            a.handle(&req(
                "POST",
                &format!("/v1/schedules/{id}/run-now"),
                Value::Null
            ))
            .status,
            202
        );
        let now = unix_ms();
        a.sched_tick(now);
        a.sched_tick(now + 6_000);
        let runs = json_of(&a.handle(&req(
            "GET",
            &format!("/v1/schedules/{id}/runs"),
            Value::Null,
        )));
        assert_eq!(runs["runs"].as_array().unwrap().len(), 1, "{runs}");
        assert_eq!(runs["runs"][0]["status"], "succeeded");
        // Pause stops the next-run display; remove deletes.
        let paused = json_of(&a.handle(&req(
            "POST",
            &format!("/v1/schedules/{id}/pause"),
            Value::Null,
        )));
        assert_eq!(
            (paused["enabled"].as_bool(), paused["next"].is_null()),
            (Some(false), true)
        );
        assert_eq!(
            a.handle(&req("DELETE", &format!("/v1/schedules/{id}"), Value::Null))
                .status,
            200
        );
        assert_eq!(
            a.handle(&req("GET", &format!("/v1/schedules/{id}"), Value::Null))
                .status,
            404
        );
    }

    #[test]
    fn a_heartbeat_is_off_until_turned_on_and_bad_input_is_a_400() {
        let d = tempfile::tempdir().unwrap();
        let mut a = app(d.path());
        let ok = a.handle(&req("POST", "/v1/schedules", json!({ "name": "Check-in", "heartbeat": true, "every_minutes": 30, "engine": "claude", "target": { "box_name": "alpha" } })));
        assert_eq!(ok.status, 200);
        assert_eq!(json_of(&ok)["enabled"], false);
        let fast = a.handle(&req("POST", "/v1/schedules", json!({ "name": "x", "heartbeat": true, "every_minutes": 1, "engine": "claude", "target": { "box_name": "alpha" } })));
        assert_eq!(fast.status, 400);
        let none = a.handle(&req("POST", "/v1/schedules", json!({ "name": "x", "when_text": "every day at 9am", "engine": "claude", "target": { "box_name": "alpha" } })));
        assert_eq!(none.status, 400, "a task needs a prompt or a skill");
    }

    #[test]
    fn rotating_a_triggers_secret_shows_the_new_one_once_and_keeps_the_old_for_a_day() {
        let d = tempfile::tempdir().unwrap();
        let mut a = app(d.path());
        make_box(&mut a, "alpha");
        let made = json_of(&a.handle(&req("POST", "/v1/triggers", json!({ "name": "PR", "template": "Review {{title}}", "engine": "claude", "target": { "box_name": "alpha" } }))));
        let id = made["id"].as_str().unwrap().to_string();
        let old = made["secret"].as_str().unwrap().to_string();
        let r = a.handle(&req(
            "POST",
            &format!("/v1/triggers/{id}/rotate-secret"),
            json!({}),
        ));
        assert_eq!(r.status, 200);
        let v = json_of(&r);
        let fresh = v["secret"].as_str().unwrap().to_string();
        assert_eq!(fresh.len(), 48);
        assert_ne!(fresh, old);
        assert!(v["previous_secret_until_ms"].as_u64().unwrap() > unix_ms() + 23 * 3600 * 1000);
        // shown once: not in the list, not in the store file
        let list = a.handle(&req("GET", "/v1/triggers", Value::Null));
        for secret in [&fresh, &old] {
            assert!(!String::from_utf8_lossy(&list.body).contains(secret.as_str()));
            assert!(
                !std::fs::read_to_string(d.path().join("fleet-schedules.json"))
                    .unwrap()
                    .contains(secret.as_str())
            );
        }
        // both secrets are accepted by the public route within the overlap
        let hit = |a: &mut App, secret: &str, delivery: &str| {
            let body = br#"{"title":"Fix"}"#.to_vec();
            let mut headers = HashMap::new();
            headers.insert("host".to_string(), "ozbox.example.com".to_string());
            headers.insert(
                "x-hub-signature-256".to_string(),
                format!("sha256={}", hooks::sign(secret, &body)),
            );
            headers.insert("x-github-delivery".to_string(), delivery.to_string());
            headers.insert("x-github-event".to_string(), "push".to_string());
            a.handle(&Req {
                method: "POST".into(),
                path: format!("/hooks/{id}"),
                query: String::new(),
                headers,
                body,
            })
            .status
        };
        assert_eq!(hit(&mut a, &fresh, "r-1"), 202);
        assert_eq!(hit(&mut a, &old, "r-2"), 202);
        assert_eq!(hit(&mut a, "wrong", "r-3"), 401);
        assert_eq!(
            a.handle(&req(
                "POST",
                "/v1/triggers/trg-nope/rotate-secret",
                json!({})
            ))
            .status,
            404
        );
    }

    #[test]
    fn a_trigger_shows_its_secret_once_and_the_public_route_needs_no_sign_in() {
        let d = tempfile::tempdir().unwrap();
        let mut a = app(d.path());
        make_box(&mut a, "alpha");
        let made = a.handle(&req("POST", "/v1/triggers", json!({ "name": "PR", "template": "Review {{title}}", "engine": "claude", "target": { "box_name": "alpha" } })));
        assert_eq!(made.status, 201);
        let v = json_of(&made);
        let id = v["id"].as_str().unwrap().to_string();
        let secret = v["secret"].as_str().unwrap().to_string();
        assert_eq!(secret.len(), 48);
        // Never again: not in the list, not in the store file, and the generic secrets route refuses the name.
        let list = a.handle(&req("GET", "/v1/triggers", Value::Null));
        assert!(!String::from_utf8_lossy(&list.body).contains(&secret));
        assert!(
            !std::fs::read_to_string(d.path().join("fleet-schedules.json"))
                .unwrap()
                .contains(&secret)
        );
        assert_eq!(json_of(&list)["triggers"][0]["secret_set"], true);
        assert_eq!(
            a.handle(&req(
                "PUT",
                &format!("/v1/secrets/trigger-secret-{id}"),
                json!({ "value": "x" })
            ))
            .status,
            404
        );
        // A signed request with no Authorization header and a foreign Host is accepted: the signature is the credential.
        let body = br#"{"title":"Fix"}"#.to_vec();
        let mut headers = HashMap::new();
        headers.insert("host".to_string(), "ozbox.example.com".to_string());
        headers.insert(
            "x-hub-signature-256".to_string(),
            format!("sha256={}", hooks::sign(&secret, &body)),
        );
        headers.insert("x-github-delivery".to_string(), "g-1".to_string());
        headers.insert("x-github-event".to_string(), "push".to_string());
        let hook = Req {
            method: "POST".into(),
            path: format!("/hooks/{id}"),
            query: String::new(),
            headers: headers.clone(),
            body: body.clone(),
        };
        assert_eq!(a.handle(&hook).status, 202);
        assert_eq!(a.handle(&hook).status, 409);
        headers.remove("x-hub-signature-256");
        assert_eq!(
            a.handle(&Req {
                method: "POST".into(),
                path: format!("/hooks/{id}"),
                query: String::new(),
                headers,
                body
            })
            .status,
            401
        );
        let dl = json_of(&a.handle(&req(
            "GET",
            &format!("/v1/triggers/{id}/deliveries"),
            Value::Null,
        )));
        let reasons: Vec<&str> = dl["deliveries"]
            .as_array()
            .unwrap()
            .iter()
            .map(|x| x["reason"].as_str().unwrap())
            .collect();
        assert_eq!(reasons, vec!["missing_signature", "replayed", ""]);
        // Test delivery: verified, no run.
        let t = json_of(&a.handle(&req(
            "POST",
            &format!("/v1/triggers/{id}/test"),
            Value::Null,
        )));
        assert_eq!(t["verified"], true);
        // Removing deletes the secret.
        assert_eq!(
            a.handle(&req("DELETE", &format!("/v1/triggers/{id}"), Value::Null))
                .status,
            200
        );
        assert!(!a.secrets.exists(&format!("trigger-secret-{id}")).unwrap());
        let again = Req {
            method: "POST".into(),
            path: format!("/hooks/{id}"),
            query: String::new(),
            headers: HashMap::new(),
            body: Vec::new(),
        };
        assert_eq!(a.handle(&again).status, 401);
    }
}
