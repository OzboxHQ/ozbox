//! The executors behind the chat's power acts and its addressed messages (ADR 0050 §3 and "End-to-end path").
//!
//! Everything here runs **after** `chat_policy::decide` allowed the act and `Allowed::confirm` asked again with the facts of
//! that moment (`telegram_bridge`). What this adds is the second half of each act:
//!
//! * **Box power** (`/box resume|pause|extend|create|resize`): the same `Provider::plan` as every other screen, the fleet
//!   caps of the settings, the delegation's own caps (`chat_policy::power::check`), the permission engine, then the change as
//!   a job on its own thread. The chat is shown the plan and one pointer link to the dashboard, and told when it finished. A
//!   plan that is outside the caps is a handoff: the same plan, done in the dashboard with a passkey.
//! * **Addressed messages** (`@box`, `@box/session`, `@group`, `@fleet`, `/to`): the address is expanded to the boxes this
//!   person may reach, each target is put to `decide` on its own, and each copy is handed to the box's agent through the
//!   supervisor (a box this dashboard runs) or the hub's channel (a worker box, `chat::remote`). Every copy has a state, and
//!   every reply is attributed to its box and session and redacted by `chat_policy::reply`.
//!
//! What the person reads is a catalogue key with arguments ([`Said`]), rendered once at the edge.

use std::collections::BTreeMap;

use ozbox_core::chat_policy::acts::ChatAct;
use ozbox_core::chat_policy::address::{
    self, expand, reachable, reachable_groups, Address, BoxReach, Delivery, DeliveryState,
};
use ozbox_core::chat_policy::decide::{decide, BoxFacts, Decision};
use ozbox_core::chat_policy::power::{self, PowerAct, PowerFacts, PowerRefusal};
use ozbox_core::chat_policy::records::Caps;
use ozbox_core::chat_policy::reply::{agent_output, Detail};
use ozbox_core::{BoxName, BoxSpec, BoxState, Operation, Size};

use super::telegram_bridge::Sender;
use super::App;
use crate::chat::gateway::{Bind, Channel, Effect, Watch};
use crate::messages::t;

/// The most structured messages kept in memory.
const KEEP_SAID: usize = 500;

/// One message the bridge sent, as data: the catalogue key and its arguments, before it was put into words.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Said {
    /// The conversation it went to (`<channel>:<id>`).
    pub to: String,
    pub key: &'static str,
    pub args: Vec<(&'static str, String)>,
}

impl Said {
    #[cfg(test)]
    pub fn arg(&self, name: &str) -> Option<&str> {
        self.args
            .iter()
            .find(|(k, _)| *k == name)
            .map(|(_, v)| v.as_str())
    }
}

/// A box change started from a chat, waiting for its job.
#[derive(Debug, Clone)]
pub struct PowerJob {
    pub job_id: String,
    pub chat_id: i64,
    pub person: String,
    pub box_name: String,
    pub verb: &'static str,
}

/// A message addressed from one chat, and where each copy stands.
#[derive(Debug, Clone)]
pub struct Tracked {
    /// The conversation it came from (`<channel>:<id>`).
    pub to: String,
    /// The message it answers, so every reply is threaded under it.
    pub thread: Option<String>,
    pub delivery: Delivery,
    pub fanout: bool,
    pub told_done: bool,
}

fn act_of(act: &ChatAct) -> Option<(&'static str, &str)> {
    Some(match act {
        ChatAct::BoxResume(b) => ("resume", b),
        ChatAct::BoxPause(b) => ("pause", b),
        ChatAct::BoxExtend { box_name, .. } => ("extend", box_name),
        ChatAct::BoxCreate { box_name, .. } => ("create", box_name),
        ChatAct::BoxResize { box_name, .. } => ("resize", box_name),
        _ => return None,
    })
}

/// Cents an hour from a monthly price in dollars (730 hours a month), rounded up so a cap is never undercounted.
fn hourly_cents(monthly_usd: f64) -> u64 {
    if !monthly_usd.is_finite() || monthly_usd <= 0.0 {
        return 0;
    }
    let monthly_cents = (monthly_usd * 100.0).round() as u64;
    monthly_cents.div_ceil(730)
}

fn dollars(cents: u64) -> String {
    format!("${}.{:02}", cents / 100, cents % 100)
}

impl App {
    // ---------- saying things, as data ----------

    /// Say a catalogue message to a chat, and keep it as data.
    pub(super) fn tg_tell(
        &mut self,
        who: &Sender,
        key: &'static str,
        args: &[(&'static str, String)],
        now: u64,
    ) {
        let text = self.tg_note_said(&who.conv(), key, args);
        self.tg_reply(who, text, now);
    }

    /// The same, as a structured notice whose one action is the **Open in dashboard** button: a pointer link made for this
    /// person to the page at `path` (or the page named in words when there is no public address). The words keep a `{where}`
    /// line too, so a chat app that cannot show a button still carries the link.
    pub(super) fn tg_tell_where(
        &mut self,
        who: &Sender,
        key: &'static str,
        args: &[(&'static str, String)],
        path: &str,
        now: u64,
    ) {
        let (action, where_text) = self.tg_action(&who.person, path, now);
        let button = matches!(action, crate::notice::Action::OneTime { .. });
        let mut all = args.to_vec();
        all.push(("where", where_text));
        let _ = self.tg_note_said(&who.conv(), key, &all);
        // the words: the link is the button when there is one, and named in the words when there is none
        let mut words = args.to_vec();
        if button {
            words.push(("where", String::new()));
        } else {
            words.push(("where", all.last().map(|w| w.1.clone()).unwrap_or_default()));
        }
        let borrowed: Vec<(&str, &str)> = words.iter().map(|(k, v)| (*k, v.as_str())).collect();
        let text = t(key, &borrowed).trim().to_string();
        let box_name = args
            .iter()
            .find(|(k, _)| *k == "box")
            .map(|(_, v)| v.clone());
        let title = match (args.iter().find(|(k, _)| *k == "verb"), &box_name) {
            (Some((_, verb)), Some(b)) => t("tg.notice_power", &[("verb", verb), ("box", b)]),
            _ => t("tg.notice_dashboard", &[]),
        };
        let mut n = crate::notice::Notice::new(crate::notice::NoticeKind::Alert, title, text);
        n.box_name = box_name;
        n.created_ms = now;
        n.only_tells = true;
        let tracked = button;
        let n = n
            .opens(path, t("tg.notice_place", &[]))
            .with_action(Some(action))
            .in_thread(who.thread.clone());
        if tracked {
            self.tg_send_tracked_notice(who, n, now);
        } else {
            self.tg_reply_notice(who, n, now);
        }
    }

    /// The Open in dashboard action for one person, and the words that say the same.
    fn tg_action(&mut self, person: &str, path: &str, now: u64) -> (crate::notice::Action, String) {
        let Some(base) = self.chat_public_base() else {
            return (crate::notice::Action::Words, t("tg.where_none", &[]));
        };
        match self.tg_pointer(person, path, now) {
            Some(tok) => {
                let host = crate::notice::host_of(&base);
                let url = format!("{base}/go#{tok}");
                let words = t("tg.where", &[("host", &host), ("url", &url)]);
                (crate::notice::Action::OneTime { url, host }, words)
            }
            None => (crate::notice::Action::Words, t("tg.where_none", &[])),
        }
    }

    pub(super) fn tg_note_said(
        &mut self,
        to: &str,
        key: &'static str,
        args: &[(&'static str, String)],
    ) -> String {
        self.tg.said.push_back(Said {
            to: to.to_string(),
            key,
            args: args.to_vec(),
        });
        while self.tg.said.len() > KEEP_SAID {
            self.tg.said.pop_front();
        }
        let borrowed: Vec<(&str, &str)> = args.iter().map(|(k, v)| (*k, v.as_str())).collect();
        t(key, &borrowed)
    }

    fn tg_sender_for(&self, chat_id: i64, person: &str) -> Sender {
        Sender::telegram(String::new(), person.to_string(), chat_id, false)
    }

    /// Who to answer for a conversation key (`<channel>:<id>`).
    pub(super) fn tg_sender_of_conv(
        &self,
        conv: &str,
        person: &str,
        thread: Option<String>,
    ) -> Sender {
        let (chan, id) = conv.split_once(':').unwrap_or(("telegram", conv));
        let channel = match chan {
            "slack" => Channel::Slack,
            "whatsapp" => Channel::Whatsapp,
            "dashboard" => Channel::Dashboard,
            _ => Channel::Telegram,
        };
        Sender {
            link_id: String::new(),
            person: person.to_string(),
            chat_id: if channel == Channel::Telegram {
                id.parse().unwrap_or(0)
            } else {
                0
            },
            legacy: false,
            channel,
            id: id.to_string(),
            thread,
        }
    }

    // ---------- box power ----------

    /// The caps of the delegation that allowed an act.
    fn tg_caps(&self, digest: Option<&str>) -> Caps {
        digest
            .and_then(|d| {
                self.tg
                    .store
                    .data
                    .delegations
                    .iter()
                    .find(|x| x.digest == d)
            })
            .map(|d| d.record.caps.clone())
            .unwrap_or_default()
    }

    /// Start the day's counters again when the day changed.
    fn tg_power_day(&mut self, now: u64) {
        let day = power::day_of(now);
        let l = &mut self.tg.store.data.power;
        if l.day != day {
            l.day = day;
            l.used.clear();
        }
    }

    fn tg_price(&self, size: Size) -> Option<u64> {
        self.settings.price(size).map(hourly_cents)
    }

    /// Whether the box record says Production (a label), as well as the owner's mark.
    fn tg_is_production(&self, name: &str) -> bool {
        if self
            .tg
            .store
            .data
            .marks
            .production
            .iter()
            .any(|p| p == name)
        {
            return true;
        }
        BoxName::new(name)
            .ok()
            .and_then(|n| self.provider.get(&n).ok().flatten())
            .is_some_and(|r| {
                let l = &r.spec.labels;
                l.get("env").is_some_and(|v| v == "production")
                    || l.get("production").is_some_and(|v| v == "true")
            })
    }

    /// A size word, or a saved profile that names a size.
    fn tg_size_of(&self, word: &str) -> Option<(Size, Option<BTreeMap<String, String>>)> {
        if let Ok(s) = word.parse::<Size>() {
            return Some((s, None));
        }
        let dir = self.tools_cfg.profiles_dir.clone()?;
        let cat = ozbox_catalog::embedded().ok()?;
        let p = crate::profiles::Store::new(dir).load(word, &cat).ok()?;
        let size = p.defaults.size.as_deref()?.parse::<Size>().ok()?;
        Some((
            size,
            Some(crate::profiles::clean_labels(&p.defaults.labels)),
        ))
    }

    /// `/box resume|pause|extend|create|resize`: plan, show, and apply only inside the delegation's caps.
    pub(super) fn tg_power(
        &mut self,
        who: &Sender,
        act: &ChatAct,
        delegation: Option<&str>,
        update_id: i64,
        now: u64,
    ) {
        let Some((verb, name)) = act_of(act) else {
            return;
        };
        let name = name.to_string();
        let box_path = format!("/boxes/{name}");
        // a Production box, by the owner's mark or by its own label, is the dashboard's: never acted on from chat
        if self.tg_is_production(&name) {
            self.tg_tell(who, "tg.production", &[], now);
            return;
        }
        let Ok(bn) = BoxName::new(&name) else {
            self.tg_tell(who, "chat.no_such_box", &[("box", name.clone())], now);
            return;
        };
        let caps = self.tg_caps(delegation);
        self.tg_power_day(now);
        let rec = self.provider.get(&bn).ok().flatten();
        // the operation, and the act the caps judge
        let (op, pact): (Option<Operation>, PowerAct) = match act {
            ChatAct::BoxResume(_) => (
                Some(Operation::Resume { name: bn.clone() }),
                PowerAct::Resume,
            ),
            ChatAct::BoxPause(_) => (Some(Operation::Pause { name: bn.clone() }), PowerAct::Pause),
            ChatAct::BoxExtend { hours, .. } => (None, PowerAct::Extend { hours: *hours }),
            ChatAct::BoxResize { size, .. } => match size.parse::<Size>() {
                Ok(s) => (
                    Some(Operation::Resize {
                        name: bn.clone(),
                        size: Some(s),
                        work_disk_gb: None,
                    }),
                    PowerAct::Resize { size: s },
                ),
                Err(_) => {
                    self.tg_tell(who, "chat.usage_box_resize", &[], now);
                    return;
                }
            },
            ChatAct::BoxCreate { size, .. } => match self.tg_size_of(size) {
                Some((s, labels)) => {
                    let mut spec = BoxSpec::new(bn.clone(), s);
                    spec.work_disk_gb = self.settings.defaults.work_disk_gb;
                    if let Some(l) = labels {
                        spec.labels = l;
                    }
                    spec.labels.insert("ozbox-chat".into(), "created".into());
                    (
                        Some(Operation::Create { spec }),
                        PowerAct::Create { size: s },
                    )
                }
                None => {
                    self.tg_tell(who, "tg.power_no_profile", &[("what", size.clone())], now);
                    return;
                }
            },
            _ => return,
        };
        if rec.is_none() && !matches!(pact, PowerAct::Create { .. }) {
            self.tg_tell(who, "chat.no_such_box", &[("box", name.clone())], now);
            return;
        }
        // the provider's plan, through the same fleet caps as the dashboard; plan never changes anything
        let plan = match &op {
            Some(op) => {
                if let Err(e) = crate::settings::enforce(&self.settings, self.provider.as_ref(), op)
                {
                    let why = crate::chat::text::outgoing(&e.to_string(), &[], 200);
                    self.tg_tell_where(who, "tg.power_fleet_cap", &[("why", why)], &box_path, now);
                    return;
                }
                match self.provider.plan(op) {
                    Ok(p) => Some(p),
                    Err(ozbox_core::Error::Unsupported { .. }) => {
                        self.tg_tell_where(who, "tg.power_unsupported", &[], &box_path, now);
                        return;
                    }
                    Err(e) => {
                        let why = crate::chat::text::outgoing(&e.to_string(), &[], 200);
                        self.tg_tell(who, "tg.power_plan_failed", &[("why", why)], now);
                        return;
                    }
                }
            }
            None => None,
        };
        let noop = plan.as_ref().is_some_and(|p| p.is_noop());
        // the facts the caps judge
        let used = self
            .tg
            .store
            .data
            .power
            .used
            .get(&who.person)
            .cloned()
            .unwrap_or_default();
        let bp = self
            .tg
            .store
            .data
            .power
            .boxes
            .get(&name)
            .cloned()
            .unwrap_or_default();
        let running_from_chat = self
            .tg
            .store
            .data
            .power
            .boxes
            .iter()
            .filter(|(_, b)| b.deadline_ms.is_some())
            .count() as u32;
        let size_now = match pact {
            PowerAct::Create { size } | PowerAct::Resize { size } => Some(size),
            _ => rec.as_ref().map(|r| r.spec.size),
        };
        let would_end = if pact == PowerAct::Pause && !noop {
            rec.as_ref().and_then(|r| {
                let p = crate::quiesce::preview(self.agent.as_ref(), r);
                match (&p.service, &p.runs, &p.sessions) {
                    (crate::quiesce::Service::Unknown(_), _, _)
                    | (_, Err(_), _)
                    | (_, _, Err(_)) => None,
                    (_, Ok(runs), Ok(sessions)) => Some(
                        runs.iter()
                            .map(|r| format!("run {r}"))
                            .chain(sessions.iter().map(|s| format!("session {s}")))
                            .collect::<Vec<_>>(),
                    ),
                }
            })
        } else {
            Some(Vec::new())
        };
        let facts = PowerFacts {
            resumes_today: used.resumes,
            creates_today: used.creates,
            spent_today_cents: used.spent_cents,
            running_from_chat,
            last_on_box_ms: bp.last_ms,
            hourly_cents: size_now.and_then(|s| self.tg_price(s)),
            would_end,
            has_deadline: bp.deadline_ms.is_some(),
            extended: bp.extended,
        };
        let summary = plan
            .as_ref()
            .map(|p| {
                if p.is_noop() {
                    t("tg.power_plan_noop", &[("box", &name)])
                } else {
                    p.changes
                        .iter()
                        .take(4)
                        .map(|c| c.description.clone())
                        .collect::<Vec<_>>()
                        .join("; ")
                }
            })
            .unwrap_or_else(|| {
                let h = match pact {
                    PowerAct::Extend { hours } => hours,
                    _ => 0,
                };
                t(
                    "tg.power_plan_extend",
                    &[("box", &name), ("hours", &h.to_string())],
                )
            });
        let summary = crate::chat::text::outgoing(&summary, &[], 400);
        if let Err(r) = power::check(pact, &caps, &facts, noop, now) {
            let mut args = vec![
                ("verb", verb.to_string()),
                ("box", name.clone()),
                ("plan", summary),
            ];
            if let PowerRefusal::NotIdle(v) = &r {
                args.push(("ends", v.join(", ")));
            }
            self.tg_chain(
                &who.person,
                "telegram.power",
                Some(&name),
                &format!("verb={verb} upd={update_id} refused={}", r.code()),
            );
            self.tg_tell_where(who, r.message(), &args, &box_path, now);
            return;
        }
        if noop {
            self.tg_tell(who, "tg.power_plan_noop", &[("box", name.clone())], now);
            return;
        }
        let cost = power::projected_cents(pact, facts.hourly_cents).unwrap_or(0);
        // extend: the deadline is the whole change
        let Some(plan) = plan else {
            let hours = match pact {
                PowerAct::Extend { hours } => hours,
                _ => 0,
            };
            let b = self
                .tg
                .store
                .data
                .power
                .boxes
                .entry(name.clone())
                .or_default();
            b.deadline_ms = b.deadline_ms.map(|d| d + u64::from(hours) * 3_600_000);
            b.extended = true;
            b.last_ms = now;
            self.tg
                .store
                .data
                .power
                .used
                .entry(who.person.clone())
                .or_default()
                .spent_cents += cost;
            let _ = self.tg.store.save();
            self.tg_chain(
                &who.person,
                "telegram.power",
                Some(&name),
                &format!("verb=extend upd={update_id} hours={hours}"),
            );
            self.tg_tell(
                who,
                "tg.power_extended",
                &[("box", name.clone()), ("hours", hours.to_string())],
                now,
            );
            return;
        };
        // the permission engine has the last word, as for the dashboard, under the person's own name
        let was = std::mem::replace(
            &mut self.current_actor,
            super::Actor::Person(who.person.clone()),
        );
        let refused = self
            .box_permission(&plan)
            .or_else(|| self.apply_job_refusal(&plan));
        if let Some(r) = refused {
            self.current_actor = was;
            let code = serde_json::from_slice::<serde_json::Value>(&r.body)
                .ok()
                .and_then(|v| v["code"].as_str().map(str::to_string))
                .unwrap_or_else(|| "refused".into());
            self.tg_tell_where(
                who,
                "tg.power_refused_by_engine",
                &[
                    ("verb", verb.to_string()),
                    ("box", name.clone()),
                    ("why", code),
                ],
                &box_path,
                now,
            );
            return;
        }
        let started = self.start_apply_job(&plan, false, None, None);
        self.current_actor = was;
        let job_id = started
            .as_ref()
            .filter(|r| r.status == 202)
            .and_then(|r| serde_json::from_slice::<serde_json::Value>(&r.body).ok())
            .and_then(|v| v["job_id"].as_str().map(str::to_string));
        let Some(job_id) = job_id else {
            self.tg_tell(
                who,
                "tg.power_plan_failed",
                &[("why", "the change could not be started".into())],
                now,
            );
            return;
        };
        // the ledger: counts, money and the deadline, written before the chat is told
        {
            let l = &mut self.tg.store.data.power;
            let u = l.used.entry(who.person.clone()).or_default();
            match pact {
                PowerAct::Resume => u.resumes += 1,
                PowerAct::Create { .. } => u.creates += 1,
                _ => {}
            }
            u.spent_cents += cost;
            let b = l.boxes.entry(name.clone()).or_default();
            b.last_ms = now;
            match pact {
                PowerAct::Pause => {
                    b.deadline_ms = None;
                    b.extended = false;
                }
                _ => {
                    b.deadline_ms = Some(now + power::DEADLINE_MS);
                    b.extended = false;
                    b.by_person = Some(who.person.clone());
                    b.chat_id = Some(who.chat_id);
                }
            }
        }
        let _ = self.tg.store.save();
        self.tg.power_jobs.push(PowerJob {
            job_id: job_id.clone(),
            chat_id: who.chat_id,
            person: who.person.clone(),
            box_name: name.clone(),
            verb,
        });
        self.tg_chain(
            &who.person,
            "telegram.power",
            Some(&name),
            &format!("verb={verb} upd={update_id} job={job_id} cents={cost}"),
        );
        let key = match pact {
            PowerAct::Create { .. } => "tg.power_started_create",
            PowerAct::Resize { .. } => "tg.power_started_resize",
            PowerAct::Pause => "tg.power_started_pause",
            _ => "tg.power_started",
        };
        self.tg_tell_where(
            who,
            key,
            &[
                ("verb", verb.to_string()),
                ("box", name.clone()),
                ("plan", summary),
                ("cost", dollars(cost)),
            ],
            &box_path,
            now,
        );
        // a job that ran inline (tests) has already finished
        self.tg_power_jobs_finished(now);
    }

    /// Tell each chat whose box change finished how it went.
    pub(super) fn tg_power_jobs_finished(&mut self, now: u64) {
        let pending = std::mem::take(&mut self.tg.power_jobs);
        let mut keep = Vec::new();
        for j in pending {
            match self.apply_job_outcome(&j.job_id) {
                None => keep.push(j),
                Some(ok) => {
                    let who = self.tg_sender_for(j.chat_id, &j.person);
                    let key = if ok {
                        "tg.power_done"
                    } else {
                        "tg.power_failed"
                    };
                    if !ok {
                        // a change that did not happen does not keep a deadline
                        if let Some(b) = self.tg.store.data.power.boxes.get_mut(&j.box_name) {
                            if j.verb != "pause" {
                                b.deadline_ms = None;
                            }
                        }
                        let _ = self.tg.store.save();
                    }
                    let mut args = vec![("verb", j.verb.to_string()), ("box", j.box_name.clone())];
                    if ok && j.verb != "pause" {
                        args.push(("hours", (power::DEADLINE_MS / 3_600_000).to_string()));
                    }
                    self.tg_tell(&who, key, &args, now);
                }
            }
        }
        keep.extend(std::mem::take(&mut self.tg.power_jobs));
        self.tg.power_jobs = keep;
    }

    /// A box started from chat is paused at its deadline (ADR 0050 §3). This is the hub's sweep; the box's own timer is the
    /// first check and is not built in this release.
    pub(super) fn tg_deadlines(&mut self, now: u64) {
        let due: Vec<(String, Option<i64>, Option<String>)> = self
            .tg
            .store
            .data
            .power
            .boxes
            .iter()
            .filter(|(_, b)| b.deadline_ms.is_some_and(|d| d <= now))
            .map(|(n, b)| (n.clone(), b.chat_id, b.by_person.clone()))
            .collect();
        for (name, chat, person) in due {
            if let Some(b) = self.tg.store.data.power.boxes.get_mut(&name) {
                b.deadline_ms = None;
                b.extended = false;
            }
            let _ = self.tg.store.save();
            let Ok(bn) = BoxName::new(&name) else {
                continue;
            };
            let op = Operation::Pause { name: bn };
            let Ok(plan) = self.provider.plan(&op) else {
                continue;
            };
            if plan.is_noop() {
                continue;
            }
            let started = self.start_apply_job(&plan, false, None, None);
            self.tg_chain(
                person.as_deref().unwrap_or("-"),
                "telegram.power",
                Some(&name),
                "verb=pause deadline",
            );
            if let (Some(chat), Some(p)) = (chat, person) {
                let who = self.tg_sender_for(chat, &p);
                let key = if started.is_some_and(|r| r.status == 202) {
                    "tg.power_deadline"
                } else {
                    "tg.power_deadline_failed"
                };
                self.tg_tell(&who, key, &[("box", name.clone())], now);
            }
        }
    }

    // ---------- addressing ----------

    /// What each box is for this person now: Production, delegated (by `decide`, so a lock or a role change counts),
    /// running, and whether it is a worker reached over the hub's channel.
    pub(super) fn tg_reach(
        &self,
        who: &Sender,
        link: Option<&crate::telegram_store::TgLink>,
        now: u64,
    ) -> Vec<BoxReach> {
        let delegations = self.tg_delegations(link);
        let mut out: Vec<BoxReach> = Vec::new();
        let local = self.provider.list().unwrap_or_default();
        let marks = self.tg.store.data.marks.clone();
        let mut push = |name: String, running: bool, remote: bool, production: bool, app: &App| {
            let facts = BoxFacts {
                production,
                hub: marks.hub.as_deref() == Some(name.as_str()),
                hosts_bot: marks.hub.as_deref() == Some(name.as_str()),
            };
            let target = (name.clone(), facts);
            let ctx = app.chat_ctx(who, link, Some(&target), &delegations, now);
            let probe = ChatAct::Address {
                to: Address::Name(name.clone()),
                text: String::from("."),
            };
            let delegated = matches!(decide(&probe, &ctx), Decision::Allow(_));
            out.push(BoxReach {
                name,
                production,
                delegated,
                online: running,
                remote,
            });
        };
        for r in &local {
            let n = r.spec.name.to_string();
            let prod = self.tg_is_production(&n);
            push(n, r.state == BoxState::Running, false, prod, self);
        }
        for w in self.remote_agents.workers() {
            if local.iter().any(|r| r.spec.name.as_str() == w.name) {
                continue;
            }
            let prod = w.production || marks.production.contains(&w.name);
            push(w.name, w.online, true, prod, self);
        }
        out
    }

    /// The facts of this moment for `decide`, for any chat app. Telegram: the link and the delegations just verified. Slack
    /// and WhatsApp: the account the person paired with a one-time code (no passkey, so no delegation), under that app's
    /// ceiling (ADR 0050 decision 1: what they have today).
    pub(super) fn chat_ctx<'a>(
        &self,
        who: &Sender,
        link: Option<&crate::telegram_store::TgLink>,
        target: Option<&'a (String, BoxFacts)>,
        delegations: &'a [ozbox_core::chat_policy::decide::DelegationFacts],
        now: u64,
    ) -> ozbox_core::chat_policy::decide::Context<'a> {
        use ozbox_core::chat_policy::decide::{ChatChannel, Context, LinkFacts, LinkStatus};
        let channel = match who.channel {
            Channel::Slack => ChatChannel::Slack,
            Channel::Whatsapp => ChatChannel::Whatsapp,
            _ => return self.tg_context(who, link, target, delegations, now).1,
        };
        Context {
            channel,
            role: self.tg_role(&who.person),
            link: Some(LinkFacts {
                status: LinkStatus::Active,
                created_ms: 0,
                expires_ms: u64::MAX,
            }),
            target_box: target.map(|(n, f)| (n.as_str(), *f)),
            delegations,
            pairing_open: false,
            now_ms: now,
        }
    }

    /// One message from Slack or WhatsApp, from a person who paired that account: the same act table and the same `decide`
    /// as Telegram, then the same executors. The adapter's only jobs were to verify the vendor's signature, find the person
    /// and say whether the message was someone else's words.
    pub(super) fn chat_gate(
        &mut self,
        channel: Channel,
        id: &str,
        person: &str,
        text: &str,
        forwarded: bool,
        thread: Option<String>,
        now: u64,
    ) {
        // someone else's words are data: the gateway says so, as it always has
        if forwarded {
            return self.chat_inbound(channel, id, person, text, true, now);
        }
        let who = Sender {
            link_id: String::new(),
            person: person.to_string(),
            chat_id: 0,
            legacy: false,
            channel,
            id: id.to_string(),
            thread,
        };
        let conv = who.conv();
        let act = ozbox_core::chat_policy::acts::parse_act(text, None);
        let target = self.tg_target(&act, &conv);
        let ctx = self.chat_ctx(&who, None, target.as_ref(), &[], now);
        match decide(&act, &ctx) {
            Decision::Refuse(r) => {
                if !r.silent() {
                    self.tg_tell(&who, r.message(), &[], now);
                }
            }
            Decision::Handoff(h) => self.tg_tell_where(&who, h.message(), &[], "/chat", now),
            Decision::Allow(_) => match act {
                ChatAct::Address { to, text } => self.tg_address(&who, None, &to, &text, None, now),
                ChatAct::To(to) => self.tg_set_to(&who, &to, now),
                ChatAct::Who => self.tg_show_to(&who, now),
                ChatAct::Boxes => self.tg_boxes(&who, None, now),
                ChatAct::Fleets => self.tg_fleets(&who, None, now),
                ChatAct::RunSession(t) => match self.tg_run_target(&t, &conv) {
                    None => self.tg_tell(&who, "tg.run_which_box", &[], now),
                    Some((b, prompt)) => self.chat_inbound(
                        channel,
                        id,
                        person,
                        &format!("/new {b} {prompt}"),
                        false,
                        now,
                    ),
                },
                ChatAct::Converse(t)
                    if self.tg_sticky(&conv).is_some()
                        && !self.state.chat.binds.contains_key(&conv) =>
                {
                    if let Some(to) = self.tg_sticky(&conv) {
                        self.tg_address(&who, None, &to, &t, None, now);
                    }
                }
                // everything else that is allowed is the chat gateway's own code, unchanged
                _ => self.chat_inbound(channel, id, person, text, false, now),
            },
        }
    }

    /// `/to <address>`: where plain messages go from now on.
    pub(super) fn tg_set_to(&mut self, who: &Sender, to: &Address, now: u64) {
        let key = who.conv();
        self.state.chat.to.insert(key.clone(), to.render());
        // a session address follows that session; anything else starts from no session
        if let Address::Session { session, .. } = to {
            if self.chat_book().is_some_and(|b| b.task(session).is_some()) {
                self.state.chat.binds.insert(
                    key,
                    Bind::Task {
                        id: session.clone(),
                    },
                );
            }
        } else {
            self.state.chat.binds.remove(&key);
        }
        self.save_state();
        self.tg_tell(who, "tg.to_set", &[("to", to.render())], now);
    }

    /// `/who`: where plain messages go now.
    pub(super) fn tg_show_to(&mut self, who: &Sender, now: u64) {
        let key = who.conv();
        let to = self.state.chat.to.get(&key).cloned();
        let bound = match self.state.chat.binds.get(&key) {
            Some(Bind::Task { id }) => self
                .chat_book()
                .and_then(|b| b.task(id).map(|t| format!("@{}/{}", t.spec.box_name, id))),
            Some(Bind::Terminal {
                box_name, session, ..
            }) => Some(format!("@{box_name}/{session}")),
            None => None,
        };
        match (to, bound) {
            (None, None) => self.tg_tell(who, "tg.who_none", &[], now),
            (to, bound) => self.tg_tell(
                who,
                "tg.who",
                &[
                    ("to", to.unwrap_or_else(|| "-".into())),
                    ("session", bound.unwrap_or_else(|| "-".into())),
                ],
                now,
            ),
        }
    }

    /// `/boxes`: the boxes this person may talk to, and whether each is up.
    pub(super) fn tg_boxes(
        &mut self,
        who: &Sender,
        link: Option<&crate::telegram_store::TgLink>,
        now: u64,
    ) {
        let reach = self.tg_reach(who, link, now);
        let lines: Vec<String> = reachable(&reach)
            .iter()
            .map(|b| {
                t(
                    if b.online {
                        "tg.boxes_line_up"
                    } else {
                        "tg.boxes_line_down"
                    },
                    &[
                        ("box", &b.name),
                        ("where", if b.remote { "worker" } else { "fleet" }),
                    ],
                )
            })
            .collect();
        if lines.is_empty() {
            self.tg_tell(who, "tg.boxes_none", &[], now);
        } else {
            self.tg_tell(who, "tg.boxes", &[("list", lines.join("\n"))], now);
        }
    }

    /// `/fleets`: the groups this person may address.
    pub(super) fn tg_fleets(
        &mut self,
        who: &Sender,
        link: Option<&crate::telegram_store::TgLink>,
        now: u64,
    ) {
        let reach = self.tg_reach(who, link, now);
        let groups = self.tg.store.data.marks.groups.clone();
        let all = reachable(&reach).len();
        let mut lines = vec![t("tg.fleets_all", &[("n", &all.to_string())])];
        for (g, n, of) in reachable_groups(&reach, &groups) {
            lines.push(t(
                "tg.fleets_line",
                &[("group", g), ("n", &n.to_string()), ("of", &of.to_string())],
            ));
        }
        self.tg_tell(who, "tg.fleets", &[("list", lines.join("\n"))], now);
    }

    /// Whether this conversation's sticky address is a group or the fleet (and no session is followed), so a plain message is
    /// judged per box.
    pub(super) fn tg_sticky_fans_out(&self, conv: &str) -> bool {
        if self.state.chat.binds.contains_key(conv) {
            return false;
        }
        match self.state.chat.to.get(conv).and_then(|a| Address::parse(a)) {
            Some(Address::Fleet) => true,
            Some(Address::Name(n)) => self.tg.store.data.marks.groups.contains_key(&n),
            _ => false,
        }
    }

    /// The one box this conversation's sticky address names, when it names one and no session is followed.
    pub(super) fn tg_sticky_box(&self, conv: &str) -> Option<String> {
        if self.state.chat.binds.contains_key(conv) {
            return None;
        }
        match self
            .state
            .chat
            .to
            .get(conv)
            .and_then(|a| Address::parse(a))?
        {
            Address::Session { box_name, .. } => Some(box_name),
            Address::Name(n) if !self.tg.store.data.marks.groups.contains_key(&n) => Some(n),
            _ => None,
        }
    }

    /// `/run [box] <what to do>`: the box and the prompt. The first word is a box when this dashboard knows a box (or a worker)
    /// by that name and words follow it; otherwise the box is the one the sticky address or the followed session names.
    pub(super) fn tg_run_target(&self, text: &str, conv: &str) -> Option<(String, String)> {
        let text = text.trim();
        if let Some((first, rest)) = text.split_once(char::is_whitespace) {
            let first = first.strip_prefix('@').unwrap_or(first);
            let known = BoxName::new(first)
                .ok()
                .and_then(|n| self.provider.get(&n).ok().flatten())
                .is_some()
                || self.remote_agents.workers().iter().any(|w| w.name == first);
            if known && !rest.trim().is_empty() {
                return Some((first.to_string(), rest.trim().to_string()));
            }
        }
        let followed = match self.state.chat.binds.get(conv) {
            Some(Bind::Task { id }) => self
                .chat_book()
                .and_then(|b| b.task(id).map(|t| t.spec.box_name.to_string())),
            Some(Bind::Terminal { box_name, .. }) => Some(box_name.clone()),
            None => None,
        };
        let sticky = match self.state.chat.to.get(conv).and_then(|a| Address::parse(a)) {
            Some(Address::Session { box_name, .. }) => Some(box_name),
            Some(Address::Name(n)) if !self.tg.store.data.marks.groups.contains_key(&n) => Some(n),
            _ => None,
        };
        followed
            .or(sticky)
            .filter(|_| !text.is_empty())
            .map(|b| (b, text.to_string()))
    }

    /// The sticky address of this conversation, if one was set with `/to`.
    pub(super) fn tg_sticky(&self, conv: &str) -> Option<Address> {
        self.state.chat.to.get(conv).and_then(|a| Address::parse(a))
    }

    /// A message for an address: expand it to the boxes this person may reach, judge each, and hand each copy to its box.
    pub(super) fn tg_address(
        &mut self,
        who: &Sender,
        link: Option<&crate::telegram_store::TgLink>,
        to: &Address,
        text: &str,
        delegation: Option<&str>,
        now: u64,
    ) {
        let reach = self.tg_reach(who, link, now);
        let groups = self.tg.store.data.marks.groups.clone();
        let e = expand(to, &reach, &groups);
        let msg_id = super::random_hex(3).unwrap_or_else(|_| format!("{:x}", now % 0xffffff));
        let mut d = Delivery::new(&msg_id, to.clone(), &e);
        let conv = who.conv();
        if e.targets.is_empty() {
            let why: Vec<String> = e
                .skipped
                .iter()
                .map(|(b, s)| format!("{b} ({})", s.code()))
                .collect();
            self.tg_tell_where(
                who,
                "tg.address_nobody",
                &[("to", to.render()), ("why", why.join(", "))],
                "/chat",
                now,
            );
            return;
        }
        for target in &e.targets {
            let b = target.box_name.clone();
            if !target.online {
                d.advance(&b, DeliveryState::Unreachable("box_not_running"));
                continue;
            }
            // the one delivery seam: the conversation fabric's chat-participant bridge replaces this call
            let copy = self.fabric_deliver(who, target, text, &msg_id, delegation, now);
            let (task, failed, outs) = match copy {
                Copy::Delivered { session } if target.remote => {
                    if let Some(t) = d.targets.iter_mut().find(|t| t.box_name == b) {
                        t.session = Some(session);
                    }
                    d.advance(&b, DeliveryState::Delivered);
                    continue;
                }
                Copy::Delivered { session } => (Some(session), None, Vec::new()),
                Copy::NotDelivered { state, said } => {
                    if said.is_empty() {
                        d.advance(&b, state);
                        continue;
                    }
                    (None, Some(()), said)
                }
            };
            match (task, failed) {
                (Some(tid), None) => {
                    if let Some(tt) = d.targets.iter_mut().find(|x| x.box_name == b) {
                        tt.session = Some(tid.clone());
                    }
                    d.advance(&b, DeliveryState::Delivered);
                    if e.fanout {
                        let w = self.state.chat.watch.entry(conv.clone()).or_default();
                        w.retain(|x| x.task != tid);
                        w.push(Watch {
                            task: tid.clone(),
                            box_name: b.clone(),
                            msg_id: msg_id.clone(),
                            thread: who.thread.clone(),
                        });
                        let seen = self
                            .chat_book()
                            .and_then(|bk| bk.task(&tid).map(|t| t.turns))
                            .unwrap_or(0);
                        self.chat.seen_turns.insert(format!("{conv}|{tid}"), seen);
                    } else {
                        // one box: this conversation follows that session from now on
                        self.state
                            .chat
                            .binds
                            .insert(conv.clone(), Bind::Task { id: tid.clone() });
                        let w = self.state.chat.watch.entry(conv.clone()).or_default();
                        w.retain(|x| x.task != tid);
                        w.push(Watch {
                            task: tid.clone(),
                            box_name: b.clone(),
                            msg_id: msg_id.clone(),
                            thread: who.thread.clone(),
                        });
                    }
                }
                _ => {
                    d.advance(&b, DeliveryState::Failed("box_refused"));
                    // the gateway's own words (a refusal of an elevated session, a role) go to the person as they are
                    for o in outs {
                        self.tg_reply(who, o, now);
                    }
                }
            }
        }
        self.save_state();
        if let Some(dg) = delegation {
            self.tg_mark_used(dg, now);
        }
        let s = d.summary();
        let states: Vec<String> = s.states.iter().map(|(k, n)| format!("{n} {k}")).collect();
        let skipped: Vec<String> = s.skipped.iter().map(|(k, n)| format!("{n} {k}")).collect();
        self.tg_chain(
            &who.person,
            "telegram.address",
            None,
            &format!(
                "msg={msg_id} to={} targets={} skipped={}",
                to.render().chars().take(40).collect::<String>(),
                d.targets.len(),
                d.skipped.len()
            ),
        );
        self.tg_tell(
            who,
            if e.fanout {
                "tg.address_fanout"
            } else {
                "tg.address_sent"
            },
            &[
                ("msg", msg_id.clone()),
                ("to", to.render()),
                ("states", states.join(", ")),
                (
                    "skipped",
                    if skipped.is_empty() {
                        "-".into()
                    } else {
                        skipped.join(", ")
                    },
                ),
            ],
            now,
        );
        // the boxes that could not take it are named, never left out
        for tdl in &d.targets {
            if let DeliveryState::Unreachable(why) | DeliveryState::Failed(why) = &tdl.state {
                self.tg_tell(
                    who,
                    "tg.address_unreachable",
                    &[
                        ("msg", msg_id.clone()),
                        ("box", tdl.box_name.clone()),
                        ("why", (*why).to_string()),
                    ],
                    now,
                );
            }
        }
        self.tg.deliveries.push(Tracked {
            to: conv.clone(),
            thread: who.thread.clone(),
            fanout: e.fanout,
            told_done: d.done(),
            delivery: d,
        });
        if self.tg.deliveries.len() > 200 {
            self.tg.deliveries.remove(0);
        }
        self.tg_remote_pump(now);
    }

    /// The detail level of a box for a chat.
    fn tg_detail(&self, box_name: &str) -> Detail {
        let set = self
            .tg
            .store
            .data
            .marks
            .detail
            .get(box_name)
            .and_then(|d| Detail::from_name(d))
            .unwrap_or_default();
        Detail::effective(set, self.tg_is_production(box_name), false)
    }

    /// An agent's reply for a Telegram chat: attributed to its box and session, redacted and cut to the box's detail level.
    /// Returns the catalogue key and its arguments.
    pub(super) fn tg_agent_reply(
        &mut self,
        to: &str,
        box_name: &str,
        session: &str,
        msg_id: Option<&str>,
        reply: &str,
        now: u64,
    ) -> String {
        let secrets = self.chat_secrets();
        let detail = self.tg_detail(box_name);
        let shown = agent_output(reply, &secrets, detail);
        let mut args = vec![
            ("box", box_name.to_string()),
            ("session", session.to_string()),
            ("msg", msg_id.unwrap_or("-").to_string()),
        ];
        let tagged = msg_id.is_some();
        let (key, rest) = if detail == Detail::Metadata {
            (
                if tagged {
                    "tg.reply_to_metadata"
                } else {
                    "tg.reply_metadata"
                },
                true,
            )
        } else if shown.left_out > 0 {
            args.push(("text", shown.text));
            args.push(("more", shown.left_out.to_string()));
            (
                if tagged {
                    "tg.reply_to_more"
                } else {
                    "tg.reply_more"
                },
                true,
            )
        } else {
            args.push(("text", shown.text));
            (if tagged { "tg.reply_to" } else { "tg.reply" }, false)
        };
        // the dashboard link for the rest is built by the server, never taken from the agent's words
        if rest {
            let person = self
                .chat_book()
                .and_then(|b| b.task(session).map(|t| t.spec.requested_by.clone()))
                .unwrap_or_default();
            let (w, _) = self.tg_where(&person, "/chat", now);
            args.push(("where", w));
        } else {
            args.push(("where", String::new()));
        }
        if let Some(m) = msg_id {
            for tr in self.tg.deliveries.iter_mut().filter(|x| x.to == to) {
                if tr.delivery.msg_id == m {
                    tr.delivery.advance(box_name, DeliveryState::Replied);
                }
            }
        }
        self.tg_note_said(to, key, &args)
    }

    /// Replies from worker boxes, and the grouped end of a fan-out.
    pub(super) fn tg_remote_pump(&mut self, now: u64) {
        for r in self.remote_agents.take_replies() {
            let Some((to, thread)) = self
                .tg
                .deliveries
                .iter()
                .find(|x| x.delivery.msg_id == r.msg_id)
                .map(|x| (x.to.clone(), x.thread.clone()))
            else {
                continue;
            };
            let text =
                self.tg_agent_reply(&to, &r.box_name, &r.session, Some(&r.msg_id), &r.text, now);
            let who = self.tg_sender_of_conv(&to, "", thread.clone());
            self.tg_reply_notice(
                &who,
                crate::notice::Notice::reply(text).in_thread(thread),
                now,
            );
        }
        self.tg_deliveries_done(now);
    }

    /// A fan-out whose every copy reached a final state gets one grouped line, in the thread of the message.
    pub(super) fn tg_deliveries_done(&mut self, now: u64) {
        type Done = (String, Option<String>, address::Summary);
        let done: Vec<Done> = self
            .tg
            .deliveries
            .iter_mut()
            .filter(|x| x.fanout && !x.told_done && x.delivery.done())
            .map(|x| {
                x.told_done = true;
                (x.to.clone(), x.thread.clone(), x.delivery.summary())
            })
            .collect();
        for (to, thread, s) in done {
            let states: Vec<String> = s.states.iter().map(|(k, n)| format!("{n} {k}")).collect();
            let text = self.tg_note_said(
                &to,
                "tg.address_done",
                &[
                    ("msg", s.msg_id.clone()),
                    ("to", s.address.clone()),
                    ("states", states.join(", ")),
                ],
            );
            let who = self.tg_sender_of_conv(&to, "", thread.clone());
            self.tg_reply_notice(
                &who,
                crate::notice::Notice::reply(text).in_thread(thread),
                now,
            );
        }
    }
}

/// What became of one copy of a message.
pub(super) enum Copy {
    /// The box's agent took it: the session it went to.
    Delivered { session: String },
    /// It did not go: its state, and anything the box's gateway said about why (to pass on as it is).
    NotDelivered {
        state: DeliveryState,
        said: Vec<String>,
    },
}

impl App {
    /// **The delivery seam** (ADR 0050, End-to-end path): hand one copy of a message to one target's agent. Today a box this
    /// dashboard runs is reached through the supervisor (the same start and send as `/new` and a plain message) and a worker
    /// box through `chat::remote::RemoteAgents`. The hub's conversation fabric (its chat-participant bridge) replaces this one
    /// function; nothing above it knows which transport carried the copy.
    pub(super) fn fabric_deliver(
        &mut self,
        who: &Sender,
        target: &address::Target,
        text: &str,
        msg_id: &str,
        delegation: Option<&str>,
        now: u64,
    ) -> Copy {
        let b = target.box_name.clone();
        let conv = who.conv();
        if target.remote {
            let dg = delegation.unwrap_or("");
            return match self
                .remote_agents
                .send(&b, target.session.as_deref(), text, msg_id, dg)
            {
                Ok(session) => Copy::Delivered { session },
                Err(e) => Copy::NotDelivered {
                    state: match e {
                        crate::chat::remote::RemoteError::Refused => {
                            DeliveryState::Failed(e.code())
                        }
                        _ => DeliveryState::Unreachable(e.code()),
                    },
                    said: Vec::new(),
                },
            };
        }
        // a box this dashboard runs: the supervisor's own path, the same as /new and a plain message
        let session = target.session.clone().or_else(|| {
            // the box's agent: the session this chat follows there, if there is one
            match self.state.chat.binds.get(&conv) {
                Some(Bind::Task { id: tid }) => self
                    .chat_book()
                    .and_then(|bk| {
                        bk.task(tid)
                            .map(|t| (t.spec.box_name.to_string(), tid.clone()))
                    })
                    .filter(|(bx, _)| *bx == b)
                    .map(|(_, tid)| tid),
                _ => None,
            }
        });
        let mut bind = self.state.chat.binds.get(&conv).cloned();
        let effect = match &session {
            Some(s) => Effect::Send {
                task: s.clone(),
                text: text.to_string(),
            },
            None => Effect::Start {
                box_name: b.clone(),
                prompt: text.to_string(),
            },
        };
        let outs = self.chat_exec(
            who.channel,
            &who.id,
            &who.person,
            &mut bind,
            vec![effect],
            now,
        );
        let started = match (&session, &bind) {
            (None, Some(Bind::Task { id: tid })) => Some(tid.clone()),
            _ => None,
        };
        // a line typed into a session says nothing when it went; a session that was started is the new bind
        let ok = match &session {
            Some(_) => outs.is_empty(),
            None => started.is_some(),
        };
        match (ok, session.or(started)) {
            (true, Some(s)) => Copy::Delivered { session: s },
            _ => Copy::NotDelivered {
                state: DeliveryState::Failed("box_refused"),
                said: outs.into_iter().map(|o| o.text).collect(),
            },
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_monthly_price_becomes_cents_an_hour_rounded_up() {
        assert_eq!(hourly_cents(73.0), 10);
        assert_eq!(hourly_cents(73.01), 11);
        assert_eq!(hourly_cents(0.0), 0);
        assert_eq!(hourly_cents(f64::NAN), 0);
        assert_eq!(dollars(805), "$8.05");
    }

    #[test]
    fn only_the_power_acts_have_a_verb() {
        assert_eq!(
            act_of(&ChatAct::BoxResume("a".into())),
            Some(("resume", "a"))
        );
        assert_eq!(act_of(&ChatAct::Status), None);
    }
}
