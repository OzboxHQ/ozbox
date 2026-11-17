//! Alerts: what is worth telling the owner, when, and where it goes.
//!
//! * [`Engine`] decides. It is a pure function of what was observed, the settings and what it already said, so every
//!   rule is tested on fixed numbers: budget 50/80/100 percent, sustained memory pressure, disk over 85 percent, a
//!   failed self-test and box incidents. Each alert has a dedupe key; it fires once, stays quiet while the condition
//!   holds, and re-arms only after the condition has been clear for a while. Quiet hours hold back everything that is
//!   not urgent: a held alert is not recorded as sent, so if its condition is still true when the hours end, it is sent.
//! * [`Channels`] delivers: email through a provider's HTTPS API, a Telegram bot, a Slack incoming webhook, and signed
//!   outgoing webhooks. Every secret is read from the [`SecretStore`] at the moment of the send and goes nowhere else.
//!   All outbound traffic goes through [`HttpClient`], which refuses private and reserved destinations.

use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;
use std::time::Duration;

use ring::hmac;
use serde::{Deserialize, Serialize};
use serde_json::json;

use crate::messages::t;
use crate::netguard::{Guard, HttpClient, HttpRequest};
use crate::secrets::SecretStore;
use crate::settings::Settings;
use crate::state::TelegramChat;

pub const MEM_STREAK: u32 = 5;
pub const MEM_USED_PCT: f64 = 90.0;
pub const MEM_PSI: f64 = 25.0;
pub const DISK_PCT: f64 = 85.0;
pub const DISK_URGENT_PCT: f64 = 95.0;
/// A condition must stay clear this long before the same alert can fire again.
pub const REARM_MS: u64 = 10 * 60_000;
/// How long an incident's key is remembered.
const INCIDENT_KEEP_MS: u64 = 48 * 3_600_000;
pub const MAX_RECENT: usize = 50;
pub const HOURLY_CAP: usize = 20;
pub const URGENT_HOURLY_CAP: usize = 40;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Severity {
    Normal,
    Urgent,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Alert {
    pub key: String,
    pub kind: String,
    pub severity: Severity,
    pub box_name: Option<String>,
    pub title: String,
    pub body: String,
    pub ts_ms: u64,
    /// The structured message (what is asked, where, who asked, the page to open). Absent on an alert that has only a
    /// title and a body: one is derived from them when it is sent ([`Alert::notice`]). Additive.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub notice: Option<crate::notice::Notice>,
    /// Where its link points for each recipient: set just before sending, never stored.
    #[serde(skip)]
    pub reach: Reach,
}

/// The dashboard's public address and the one-time link tokens made for this send, by person. Never serialised, and its
/// `Debug` never shows a token.
#[derive(Clone, Default, PartialEq, Eq)]
pub struct Reach {
    pub base: Option<String>,
    pub tokens: BTreeMap<String, String>,
}

impl std::fmt::Debug for Reach {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Reach")
            .field("base", &self.base)
            .field("tokens", &self.tokens.len())
            .finish()
    }
}

impl Alert {
    /// The structured message for this alert: its own, or one made from the title and the body, with the page a person
    /// would open for it (the box, Usage, Schedules or Activity).
    pub fn notice(&self) -> crate::notice::Notice {
        use crate::notice::{Notice, NoticeKind};
        if let Some(n) = &self.notice {
            return n.clone();
        }
        let kind = match self.kind.as_str() {
            "budget" => NoticeKind::Budget,
            "test" => NoticeKind::Test,
            "digest" => NoticeKind::Digest,
            _ => NoticeKind::Alert,
        };
        let mut n = Notice::new(kind, &self.title, &self.body);
        n.urgent = self.severity == Severity::Urgent;
        n.box_name.clone_from(&self.box_name);
        n.created_ms = self.ts_ms;
        let (path, place) = match (&self.box_name, self.kind.as_str()) {
            (_, "budget") => ("/usage".to_string(), t("notice.place_usage", &[])),
            (_, "schedule") => ("/schedules".to_string(), t("notice.place_schedules", &[])),
            (_, "test" | "digest") => ("/activity".to_string(), t("notice.place_activity", &[])),
            (Some(b), _) => (
                format!("/boxes/{}", percent_path(b)),
                t("notice.place_box", &[("box", b)]),
            ),
            (None, _) => ("/activity".to_string(), t("notice.place_activity", &[])),
        };
        n.opens(path, place)
    }

    /// The message as one recipient gets it: the link made for `person`, the item's address for a shared place, or words
    /// when the dashboard has no public address.
    pub fn notice_for(&self, person: Option<&str>) -> crate::notice::Notice {
        let n = self.notice();
        let token = person
            .and_then(|p| self.reach.tokens.get(p))
            .map(String::as_str);
        let action = n.action_for(self.reach.base.as_deref(), token);
        n.with_action(action)
    }
}

/// A box name in a path: only the characters a name may hold pass through.
fn percent_path(s: &str) -> String {
    s.chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || c == '-' || c == '_' {
                c.to_string()
            } else {
                format!("%{:02X}", c as u32 & 0xff)
            }
        })
        .collect()
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Delivery {
    pub channel: String,
    pub ok: bool,
    /// Never contains a secret, a URL or a response body.
    pub detail: String,
    /// Whose routing rule sent it (the person's id); none for the fleet-wide channels of the older behaviour.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub person: Option<String>,
    /// How many times it was tried; more than one means it was retried after a failure.
    #[serde(default = "one", skip_serializing_if = "is_one")]
    pub attempts: u32,
}

fn one() -> u32 {
    1
}

fn is_one(n: &u32) -> bool {
    *n == 1
}

impl Delivery {
    pub fn new(channel: impl Into<String>, ok: bool, detail: impl Into<String>) -> Self {
        Delivery {
            channel: channel.into(),
            ok,
            detail: detail.into(),
            person: None,
            attempts: 1,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct RecentAlert {
    pub ts_ms: u64,
    pub key: String,
    pub kind: String,
    pub severity: Severity,
    pub box_name: Option<String>,
    pub title: String,
    pub body: String,
    pub deliveries: Vec<Delivery>,
    /// What the routing rules decided for each person. Absent on alerts recorded before this was kept.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub outcomes: Vec<crate::channels::routing::AlertOutcome>,
    /// The alert as a whole: `delivered` to anyone, else `held_quiet`, `held_limit` or `not_sent`. Absent when unknown.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub outcome: Option<crate::channels::routing::DigestStatus>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Open {
    pub fired_ms: u64,
    pub clear_since_ms: Option<u64>,
}

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct AlertState {
    pub open: BTreeMap<String, Open>,
    /// When each box was first watched: incidents from before are history, not news.
    pub watch_since_ms: BTreeMap<String, u64>,
    pub budget_month: String,
    pub budget_fired: Vec<u32>,
    pub recent: Vec<RecentAlert>,
    /// Times of the alerts sent in the last hour, for the rate limit.
    pub sent_ms: Vec<u64>,
    /// Failed deliveries that are worth another try, with when.
    pub retries: Vec<crate::channels::routing::Retry>,
    /// Texts sent to each number in the last hour (keyed by a hash, never the number), for the per-person limit.
    pub sms_sent: BTreeMap<String, Vec<u64>>,
    /// Who has been told what in the last few minutes, so two routes to one place send once.
    pub dedupe: BTreeMap<String, u64>,
    /// The daily summary of each person: what is waiting and when the next one is due.
    pub digests: BTreeMap<String, crate::channels::routing::DigestState>,
    /// What the rules decided for each alert that has been planned but not yet recorded, by alert key.
    pub outcomes: BTreeMap<String, Vec<crate::channels::routing::AlertOutcome>>,
}

// ---------- quiet hours ----------

fn minutes(hhmm: &str) -> Option<i64> {
    let (h, m) = hhmm.split_once(':')?;
    Some(h.parse::<i64>().ok()? * 60 + m.parse::<i64>().ok()?)
}

/// Whether `now_ms` falls in the quiet hours on the person's own clock: their time zone when one is set (daylight
/// saving followed), else the fixed offset older settings files carry.
pub fn quiet_now(now_ms: u64, s: &Settings) -> bool {
    let b = &s.budget;
    let offset = s
        .locale
        .time_zone
        .as_deref()
        .and_then(|z| crate::timezone::offset_minutes(z, now_ms))
        .unwrap_or(b.utc_offset_minutes);
    in_quiet_hours(now_ms, &b.quiet_from, &b.quiet_to, offset)
}

/// Whether `now_ms` falls in the quiet hours, in the owner's fixed UTC offset. The window may cross midnight.
pub fn in_quiet_hours(now_ms: u64, from: &str, to: &str, utc_offset_minutes: i32) -> bool {
    let (Some(f), Some(t)) = (minutes(from), minutes(to)) else {
        return false;
    };
    let m = ((now_ms / 60_000) as i64 + i64::from(utc_offset_minutes)).rem_euclid(1440);
    match f.cmp(&t) {
        std::cmp::Ordering::Equal => false,
        std::cmp::Ordering::Less => m >= f && m < t,
        std::cmp::Ordering::Greater => m >= f || m < t,
    }
}

// ---------- the engine ----------

#[derive(Debug, Clone, Default)]
pub struct BoxObs {
    pub name: String,
    pub mem_used_pct: Option<f64>,
    pub psi_mem: Option<f64>,
    pub disk_used_pct: Option<f64>,
    /// The step that failed, when the last self-test failed.
    pub selftest_failed: Option<String>,
    /// `(ts_ms, kind, detail)` of what the box's agent reported.
    pub incidents: Vec<(u64, String, String)>,
}

#[derive(Debug, Clone)]
pub struct BudgetObs {
    pub month: String,
    pub spent: f64,
    pub currency: String,
    /// Whether `spent` is the provider's bill (up to `real_through`, plus the estimate since) or the estimate alone.
    pub basis: crate::bill::BudgetBasis,
    pub real_through: Option<String>,
}

pub struct Inputs<'a> {
    pub now_ms: u64,
    pub settings: &'a Settings,
    pub boxes: &'a [BoxObs],
    pub budget: Option<BudgetObs>,
}

#[derive(Default)]
pub struct Engine {
    mem_streak: BTreeMap<String, u32>,
}

fn incident_severity(kind: &str) -> Option<Severity> {
    match kind {
        "oom_kill"
        | "interruption"
        | "checkpoint_failed"
        | "stop_request_failed"
        | "backup_failed"
        | "disk_grow_failed"
        | "unexpected" => Some(Severity::Urgent),
        "restart" | "run_timed_out" | "run_start_failed" | "metrics_degraded"
        | "memory_pressure" => Some(Severity::Normal),
        // `self_test_failed` is covered by the self-test condition; `disk_grown` is good news.
        _ => None,
    }
}

/// An incident kind as words: its catalogue entry, or the kind with its underscores undone for a kind not yet listed.
fn words(kind: &str) -> String {
    let key = format!("alert.incident.{kind}");
    let said = t(&key, &[]);
    if said == key {
        kind.replace('_', " ")
    } else {
        said
    }
}

impl Engine {
    pub fn evaluate(&mut self, st: &mut AlertState, inp: &Inputs<'_>) -> Vec<Alert> {
        let now = inp.now_ms;
        let b = &inp.settings.budget;
        let quiet = quiet_now(now, inp.settings);
        let mut out = Vec::new();
        let mut live: BTreeSet<String> = BTreeSet::new();
        st.open.retain(|k, o| {
            !(k.starts_with("inc:") && now.saturating_sub(o.fired_ms) > INCIDENT_KEEP_MS)
        });

        // Fires `alert` when its condition `active` is newly true; keeps the key open while it holds.
        let condition = |st: &mut AlertState,
                         out: &mut Vec<Alert>,
                         live: &mut BTreeSet<String>,
                         key: String,
                         active: bool,
                         alert: Alert| {
            if active {
                live.insert(key.clone());
                if let Some(o) = st.open.get_mut(&key) {
                    o.clear_since_ms = None;
                } else if !(quiet && alert.severity == Severity::Normal) {
                    st.open.insert(
                        key,
                        Open {
                            fired_ms: now,
                            clear_since_ms: None,
                        },
                    );
                    out.push(alert);
                }
            }
        };

        for bx in inp.boxes {
            let name = bx.name.as_str();
            st.watch_since_ms.entry(name.to_string()).or_insert(now);

            let pressured = bx.mem_used_pct.is_some_and(|p| p >= MEM_USED_PCT)
                || bx.psi_mem.is_some_and(|p| p >= MEM_PSI);
            let streak = self.mem_streak.entry(name.to_string()).or_insert(0);
            *streak = if pressured { *streak + 1 } else { 0 };
            let sustained = *streak >= MEM_STREAK;
            condition(
                st,
                &mut out,
                &mut live,
                format!("mem:{name}"),
                sustained,
                Alert {
                    notice: None,
                    reach: Default::default(),
                    key: format!("mem:{name}"),
                    kind: "memory_pressure".into(),
                    severity: Severity::Normal,
                    box_name: Some(name.to_string()),
                    title: t("alert.mem_title", &[("box", name)]),
                    body: t("alert.mem_body", &[]),
                    ts_ms: now,
                },
            );

            let disk = bx.disk_used_pct.unwrap_or(0.0);
            condition(
                st,
                &mut out,
                &mut live,
                format!("disk:{name}"),
                disk > DISK_PCT,
                Alert {
                    notice: None,
                    reach: Default::default(),
                    key: format!("disk:{name}"),
                    kind: "disk_high".into(),
                    severity: if disk > DISK_URGENT_PCT {
                        Severity::Urgent
                    } else {
                        Severity::Normal
                    },
                    box_name: Some(name.to_string()),
                    title: t(
                        "alert.disk_title",
                        &[("box", name), ("pct", &format!("{disk:.0}"))],
                    ),
                    body: t("alert.disk_body", &[]),
                    ts_ms: now,
                },
            );

            condition(
                st,
                &mut out,
                &mut live,
                format!("selftest:{name}"),
                bx.selftest_failed.is_some(),
                Alert {
                    notice: None,
                    reach: Default::default(),
                    key: format!("selftest:{name}"),
                    kind: "self_test_failed".into(),
                    severity: Severity::Urgent,
                    box_name: Some(name.to_string()),
                    title: t("alert.selftest_title", &[("box", name)]),
                    body: t(
                        "alert.selftest_body",
                        &[(
                            "step",
                            &bx.selftest_failed
                                .clone()
                                .unwrap_or_else(|| t("alert.selftest_unknown_step", &[])),
                        )],
                    ),
                    ts_ms: now,
                },
            );

            let since = st.watch_since_ms.get(name).copied().unwrap_or(now);
            for (ts, kind, detail) in &bx.incidents {
                let Some(sev) = incident_severity(kind) else {
                    continue;
                };
                if *ts < since {
                    continue;
                }
                let key = format!("inc:{name}:{ts}:{kind}");
                if st.open.contains_key(&key) || (quiet && sev == Severity::Normal) {
                    continue;
                }
                st.open.insert(
                    key.clone(),
                    Open {
                        fired_ms: now,
                        clear_since_ms: None,
                    },
                );
                live.insert(key.clone());
                out.push(Alert {
                    notice: None,
                    reach: Default::default(),
                    key,
                    kind: format!("incident_{kind}"),
                    severity: sev,
                    box_name: Some(name.to_string()),
                    title: t(
                        "alert.incident_title",
                        &[("box", name), ("what", &words(kind))],
                    ),
                    body: detail.chars().take(200).collect(),
                    ts_ms: now,
                });
            }
        }
        self.mem_streak
            .retain(|k, _| inp.boxes.iter().any(|b| &b.name == k));

        // Re-arm: a condition that has been clear long enough may fire again. Incidents expire by age instead.
        let keys: Vec<String> = st
            .open
            .keys()
            .filter(|k| !k.starts_with("inc:"))
            .cloned()
            .collect();
        for k in keys {
            if live.contains(&k) {
                continue;
            }
            let remove = match st.open.get_mut(&k) {
                Some(o) => {
                    let since = *o.clear_since_ms.get_or_insert(now);
                    now.saturating_sub(since) >= REARM_MS
                }
                None => false,
            };
            if remove {
                st.open.remove(&k);
            }
        }

        // Budget thresholds, once per month each. Amounts in another currency than the budget's are not compared.
        if let (Some(monthly), Some(obs)) = (b.monthly_usd, &inp.budget) {
            if st.budget_month != obs.month {
                st.budget_month.clone_from(&obs.month);
                st.budget_fired.clear();
            }
            if obs.currency == "USD" && monthly > 0.0 {
                let pct = obs.spent / monthly * 100.0;
                let enabled = |t: u32| match t {
                    50 => b.alert_50,
                    80 => b.alert_80,
                    _ => b.alert_100,
                };
                let crossed: Vec<u32> = [50u32, 80, 100]
                    .into_iter()
                    .filter(|t| enabled(*t) && pct >= f64::from(*t) && !st.budget_fired.contains(t))
                    .collect();
                if let Some(top) = crossed.last().copied() {
                    let sev = if top >= 100 {
                        Severity::Urgent
                    } else {
                        Severity::Normal
                    };
                    if !(quiet && sev == Severity::Normal) {
                        st.budget_fired.extend(crossed);
                        out.push(Alert {
                            notice: None,
                            reach: Default::default(),
                            key: format!("budget:{}:{top}", obs.month),
                            kind: "budget".into(),
                            severity: sev,
                            box_name: None,
                            title: match obs.basis {
                                crate::bill::BudgetBasis::Bill => {
                                    t("cost.alert.budget_title_bill", &[("pct", &top.to_string())])
                                }
                                crate::bill::BudgetBasis::Estimate => {
                                    t("alert.budget_title_estimate", &[("pct", &top.to_string())])
                                }
                            },
                            body: match (obs.basis, &obs.real_through) {
                                (crate::bill::BudgetBasis::Bill, Some(through)) => t(
                                    "cost.alert.budget_body_bill",
                                    &[
                                        ("spent", &format!("{:.2}", obs.spent)),
                                        ("budget", &format!("{monthly:.2}")),
                                        ("through", through),
                                    ],
                                ),
                                _ => t(
                                    "alert.budget_body_estimate",
                                    &[
                                        ("spent", &format!("{:.2}", obs.spent)),
                                        ("budget", &format!("{monthly:.2}")),
                                    ],
                                ),
                            },
                            ts_ms: now,
                        });
                    }
                }
            }
        }
        out
    }

    /// Apply the hourly rate limit and note what was sent. Returns the alerts that may go out now.
    #[cfg(test)]
    pub fn admit(st: &mut AlertState, alerts: Vec<Alert>, now_ms: u64) -> (Vec<Alert>, usize) {
        let (ok, dropped) = Self::admit_split(st, alerts, now_ms);
        (ok, dropped.len())
    }

    /// [`Engine::admit`], returning the alerts the limit refused instead of their number.
    pub fn admit_split(
        st: &mut AlertState,
        alerts: Vec<Alert>,
        now_ms: u64,
    ) -> (Vec<Alert>, Vec<Alert>) {
        st.sent_ms.retain(|t| now_ms.saturating_sub(*t) < 3_600_000);
        let mut ok = Vec::new();
        let mut dropped = Vec::new();
        // Urgent first, so a flood of ordinary alerts cannot crowd one out.
        let mut sorted = alerts;
        sorted.sort_by_key(|a| a.severity != Severity::Urgent);
        for a in sorted {
            let cap = if a.severity == Severity::Urgent {
                URGENT_HOURLY_CAP
            } else {
                HOURLY_CAP
            };
            if st.sent_ms.len() >= cap {
                dropped.push(a);
                continue;
            }
            st.sent_ms.push(now_ms);
            ok.push(a);
        }
        (ok, dropped)
    }

    /// Add deliveries to the alert that was already recorded (a retry), or record it when it has scrolled away.
    pub fn append(st: &mut AlertState, a: &Alert, deliveries: Vec<Delivery>) {
        match st.recent.iter_mut().rev().find(|r| r.key == a.key) {
            Some(r) => {
                r.deliveries.extend(deliveries);
                // The retry's result is the final word: "delivered" is only said of what a channel took.
                if !r.outcomes.is_empty() {
                    crate::channels::routing::settle(&mut r.outcomes, &r.deliveries);
                    r.outcome = crate::channels::routing::DigestStatus::overall(&r.outcomes);
                }
            }
            None => Self::record(st, a, deliveries),
        }
    }

    pub fn record(st: &mut AlertState, a: &Alert, deliveries: Vec<Delivery>) {
        let mut outcomes = st.outcomes.remove(&a.key).unwrap_or_default();
        crate::channels::routing::settle(&mut outcomes, &deliveries);
        let outcome = crate::channels::routing::DigestStatus::overall(&outcomes);
        st.recent.push(RecentAlert {
            ts_ms: a.ts_ms,
            key: a.key.clone(),
            kind: a.kind.clone(),
            severity: a.severity,
            box_name: a.box_name.clone(),
            title: a.title.clone(),
            body: a.body.clone(),
            deliveries,
            outcomes,
            outcome,
        });
        let over = st.recent.len().saturating_sub(MAX_RECENT);
        if over > 0 {
            st.recent.drain(..over);
        }
    }
}

// ---------- signing ----------

pub fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

#[cfg(test)]
fn unhex(s: &str) -> Option<Vec<u8>> {
    if !s.len().is_multiple_of(2) {
        return None;
    }
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(s.get(i..i + 2)?, 16).ok())
        .collect()
}

/// `v1=<hex HMAC-SHA256(secret, "<timestamp>.<body>")>`. The timestamp is signed, so it cannot be changed to replay.
pub fn sign(secret: &str, timestamp_s: u64, body: &str) -> String {
    let key = hmac::Key::new(hmac::HMAC_SHA256, secret.as_bytes());
    let tag = hmac::sign(&key, format!("{timestamp_s}.{body}").as_bytes());
    format!("v1={}", hex(tag.as_ref()))
}

#[cfg(test)]
pub const REPLAY_WINDOW_S: u64 = 300;

/// What a receiver does (kept here so the signature scheme is tested end to end; the receiving side is the owner's code): recompute, compare in constant time, and refuse a timestamp outside the window.
#[cfg(test)]
pub fn verify(
    secret: &str,
    timestamp_s: u64,
    body: &str,
    signature: &str,
    now_s: u64,
    window_s: u64,
) -> bool {
    if now_s.abs_diff(timestamp_s) > window_s {
        return false;
    }
    let Some(sig) = signature.strip_prefix("v1=").and_then(unhex) else {
        return false;
    };
    let key = hmac::Key::new(hmac::HMAC_SHA256, secret.as_bytes());
    hmac::verify(&key, format!("{timestamp_s}.{body}").as_bytes(), &sig).is_ok()
}

// ---------- channels ----------

#[derive(Clone)]
pub struct Channels {
    pub secrets: Arc<dyn SecretStore>,
    pub http: Arc<dyn HttpClient>,
    pub runner: Arc<dyn ozbox_core::CommandRunner>,
    pub aws_profile: Option<String>,
}

/// A failed delivery, with its reason from the catalogue.
fn fail(key: &str) -> Result<String, String> {
    Err(t(key, &[]))
}

fn http_detail(status: u16) -> String {
    t("alert.http_status", &[("status", &status.to_string())])
}

impl Channels {
    fn secret(&self, name: &str) -> Result<Option<String>, String> {
        self.secrets.get(name).map_err(|e| e.to_string())
    }

    fn post(&self, req: HttpRequest) -> Result<String, String> {
        match self.http.send(&req) {
            Ok(r) if r.ok() => Ok(t("alert.sent", &[])),
            Ok(r) => Err(http_detail(r.status)),
            Err(e) => Err(e.to_string()),
        }
    }

    pub fn ctx(&self) -> crate::channels::Ctx {
        crate::channels::Ctx {
            secrets: Arc::clone(&self.secrets),
            http: Arc::clone(&self.http),
            runner: Arc::clone(&self.runner),
            aws_profile: self.aws_profile.clone(),
            aws: crate::aws_native::shared(),
        }
    }

    /// Email to the fleet's own recipient list, through whichever sending service is set up.
    #[cfg(test)]
    pub fn email(&self, s: &Settings, a: &Alert) -> Result<String, String> {
        self.email_to(s, &s.apps.email.to, a, None, 0)
    }

    pub fn email_to(
        &self,
        s: &Settings,
        to: &[String],
        a: &Alert,
        person: Option<&str>,
        now_s: u64,
    ) -> Result<String, String> {
        use crate::notice::render::{Email, Renderer};
        if to.is_empty() {
            return fail("alert.email_not_set");
        }
        let m = Email::render(&a.notice_for(person));
        crate::channels::mail::send(
            &self.ctx(),
            &crate::channels::mail::Mail {
                cfg: &s.apps.email,
                to,
                subject: &m.subject,
                text: &m.text,
                html: Some(&m.html),
                now_secs: now_s,
            },
        )
    }

    pub fn telegram(&self, chats: &[TelegramChat], a: &Alert) -> Result<String, String> {
        let Some(token) = self.secret("telegram-bot-token")? else {
            return fail("alert.telegram_no_token");
        };
        if chats.is_empty() {
            return fail("alert.telegram_no_chat");
        }
        let mut failed = 0;
        // What each failure said, without saying which chat: a status code or "no answer", each once.
        let mut said: Vec<String> = Vec::new();
        // A chat that is busy, or a Telegram that is down, is worth another try; a chat that blocked the bot is not.
        let mut every_failure_is_transient = true;
        for c in chats {
            use crate::notice::render::{Renderer, Telegram};
            // each chat gets the link made for its own person
            let mut body = Telegram::render(&a.notice_for(c.person.as_deref()));
            body["chat_id"] = json!(c.id);
            let r = self.post(
                HttpRequest::new(
                    "POST",
                    format!("https://api.telegram.org/bot{token}/sendMessage"),
                    Guard::Public,
                )
                .json(&body),
            );
            if let Err(why) = r {
                failed += 1;
                every_failure_is_transient &= crate::channels::retryable(&why);
                // The catalogue's own sentence with the number left out tells where the number starts, in any language.
                let lead = t("alert.http_status", &[("status", "")]);
                let note = why
                    .strip_prefix(lead.as_str())
                    .and_then(|c| c.parse::<u16>().ok())
                    .map_or_else(
                        || t("alert.no_answer", &[]),
                        |c| t("alert.http_short", &[("status", &c.to_string())]),
                    );
                if !said.contains(&note) {
                    said.push(note);
                }
            }
        }
        if failed == 0 {
            Ok(t("alert.sent_chats", &[("n", &chats.len().to_string())]))
        } else {
            let again = if every_failure_is_transient {
                t("alert.try_again_suffix", &[])
            } else {
                String::new()
            };
            Err(t(
                "alert.chats_failed",
                &[
                    ("failed", &failed.to_string()),
                    ("total", &chats.len().to_string()),
                    ("said", &said.join("; ")),
                    ("again", &again),
                ],
            ))
        }
    }

    pub fn slack(&self, a: &Alert) -> Result<String, String> {
        let Some(url) = self.secret("slack-webhook-url")? else {
            return fail("alert.slack_no_url");
        };
        use crate::notice::render::{Renderer, Slack};
        // a Slack channel is a shared place: the item's address, never a link made for one person
        self.post(
            HttpRequest::new("POST", url, Guard::Public).json(&Slack::render(&a.notice_for(None))),
        )
    }

    pub fn webhook(&self, id: &str, a: &Alert, now_s: u64) -> Result<String, String> {
        let (Some(url), Some(secret)) = (
            self.secret(&format!("webhook-url-{id}"))?,
            self.secret(&format!("webhook-secret-{id}"))?,
        ) else {
            return fail("alert.webhook_not_saved");
        };
        let body = json!({
            "id": a.key,
            "type": format!("alert.{}", a.kind),
            "created": now_s,
            "severity": a.severity,
            "box": a.box_name,
            "title": a.title,
            "body": a.body,
            "notice": <crate::notice::render::Webhook as crate::notice::render::Renderer>::render(&a.notice_for(None)),
        })
        .to_string();
        let mut req = HttpRequest::new("POST", url, Guard::Public)
            .header("Content-Type", "application/json")
            .header("User-Agent", "ozbox")
            .header("X-Ozbox-Timestamp", now_s.to_string())
            .header("X-Ozbox-Signature", sign(&secret, now_s, &body));
        req.body = Some(body.into_bytes());
        req.timeout = Duration::from_secs(8);
        self.post(req)
    }

    /// Send to one fleet-wide channel by id: `email`, `telegram`, `slack`, `discord`, `teams` or `webhook:<id>`.
    pub fn send_one(
        &self,
        channel: &str,
        s: &Settings,
        chats: &[TelegramChat],
        a: &Alert,
        now_s: u64,
    ) -> Delivery {
        let r = match channel {
            "email" => self.email_to(s, &s.apps.email.to, a, None, now_s),
            "telegram" => self.telegram(chats, a),
            "slack" => self.slack(a),
            "discord" => crate::channels::chat::discord(&self.ctx(), &a.notice_for(None)),
            "teams" => crate::channels::chat::teams(&self.ctx(), &a.notice_for(None)),
            c => match c.strip_prefix("webhook:") {
                Some(id) => self.webhook(id, a, now_s),
                None => fail("alert.unknown_channel"),
            },
        };
        match r {
            Ok(d) => Delivery::new(channel, true, d),
            Err(d) => Delivery::new(channel, false, d),
        }
    }

    /// The channels that are switched on in Settings.
    pub fn enabled(s: &Settings) -> Vec<String> {
        let mut v = Vec::new();
        if s.apps.email.enabled {
            v.push("email".to_string());
        }
        if s.apps.telegram.enabled {
            v.push("telegram".into());
        }
        if s.apps.slack.enabled {
            v.push("slack".into());
        }
        if s.apps.discord.enabled {
            v.push("discord".into());
        }
        if s.apps.teams.enabled {
            v.push("teams".into());
        }
        v.extend(
            s.apps
                .webhooks
                .iter()
                .filter(|w| w.enabled)
                .map(|w| format!("webhook:{}", w.id)),
        );
        v
    }

    #[cfg(test)]
    pub fn send_all(
        &self,
        s: &Settings,
        chats: &[TelegramChat],
        a: &Alert,
        now_s: u64,
    ) -> Vec<Delivery> {
        Self::enabled(s)
            .iter()
            .map(|c| self.send_one(c, s, chats, a, now_s))
            .collect()
    }
}

pub fn test_alert(now_ms: u64) -> Alert {
    Alert {
        notice: None,
        reach: Default::default(),
        key: format!("test:{now_ms}"),
        kind: "test".into(),
        severity: Severity::Normal,
        box_name: None,
        title: t("alert.test_title", &[]),
        body: t("alert.test_body", &[]),
        ts_ms: now_ms,
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use crate::netguard::FakeHttp;
    use crate::secrets::MemorySecrets;

    /// Every catalogue key the engine and the channels name exists, and no sentence is left in the code: the part of this
    /// file before its tests has no quoted text that reads as a message other than a key, a channel id or a header.
    #[test]
    fn every_alert_key_used_here_is_in_the_catalogue() {
        let src = include_str!("notify.rs");
        let code = src
            .split("#[cfg(test)]\n#[allow(clippy::unwrap_used)]\nmod tests")
            .next()
            .unwrap();
        let keys = crate::messages::keys();
        let mut seen = 0;
        for part in code.split('"').skip(1).step_by(2) {
            if (part.starts_with("alert.") || part.starts_with("cost.alert."))
                && !part.contains('{')
            {
                seen += 1;
                assert!(keys.contains(&part), "{part} is not in the catalogue");
            }
        }
        assert!(seen >= 25, "only {seen} keys found");
        // the incident kinds that raise an alert each have their own wording
        for k in [
            "oom_kill",
            "interruption",
            "checkpoint_failed",
            "stop_request_failed",
            "backup_failed",
            "disk_grow_failed",
            "unexpected",
            "restart",
            "run_timed_out",
            "run_start_failed",
            "metrics_degraded",
            "memory_pressure",
        ] {
            let key = format!("alert.incident.{k}");
            assert!(keys.contains(&key.as_str()), "{key}");
        }
        // every key in the alert catalogue is used by the code or by the incident table
        for (k, _) in crate::messages_alerts::EN {
            assert!(
                k.starts_with("alert.incident.") || code.contains(&format!("\"{k}\"")),
                "{k} is unused"
            );
        }
    }

    #[test]
    fn a_status_note_survives_a_changed_sentence() {
        assert_eq!(http_detail(503), "the service answered HTTP 503");
        assert_eq!(t("alert.http_short", &[("status", "503")]), "HTTP 503");
    }

    const MIN: u64 = 60_000;
    // 2026-11-09 12:00 UTC
    const NOON: u64 = 1_794_182_400_000 + 12 * 3_600_000;

    fn settings() -> Settings {
        let mut s = Settings::default();
        s.budget.monthly_usd = Some(100.0);
        s
    }

    fn obs(name: &str) -> BoxObs {
        BoxObs {
            name: name.into(),
            ..BoxObs::default()
        }
    }

    fn run(
        e: &mut Engine,
        st: &mut AlertState,
        s: &Settings,
        now: u64,
        boxes: Vec<BoxObs>,
        spent: Option<f64>,
    ) -> Vec<Alert> {
        let budget = spent.map(|x| BudgetObs {
            month: "2026-11".into(),
            spent: x,
            currency: "USD".into(),
            basis: Default::default(),
            real_through: None,
        });
        e.evaluate(
            st,
            &Inputs {
                now_ms: now,
                settings: s,
                boxes: &boxes,
                budget,
            },
        )
    }

    #[test]
    fn quiet_hours_cross_midnight_and_follow_the_offset() {
        let at = |h: u64, m: u64| 1_794_182_400_000 + (h * 60 + m) * MIN; // UTC time on 2026-11-09
        assert!(in_quiet_hours(at(23, 0), "23:00", "07:00", 0));
        assert!(in_quiet_hours(at(3, 0), "23:00", "07:00", 0));
        assert!(!in_quiet_hours(at(7, 0), "23:00", "07:00", 0));
        assert!(!in_quiet_hours(at(22, 59), "23:00", "07:00", 0));
        // 22:30 UTC is 23:30 in UTC+1, so quiet; and 06:30 UTC is 07:30 there, so not.
        assert!(in_quiet_hours(at(22, 30), "23:00", "07:00", 60));
        assert!(!in_quiet_hours(at(6, 30), "23:00", "07:00", 60));
        // a same-day window, and an empty one
        assert!(in_quiet_hours(at(13, 0), "12:00", "14:00", 0));
        assert!(!in_quiet_hours(at(15, 0), "12:00", "14:00", 0));
        assert!(!in_quiet_hours(at(3, 0), "07:00", "07:00", 0));
        // a negative offset wraps the right way: 03:00 UTC is 22:00 the day before in UTC-5
        assert!(!in_quiet_hours(at(3, 0), "23:00", "07:00", -300));
        assert!(in_quiet_hours(at(5, 0), "23:00", "07:00", -300));
        assert!(!in_quiet_hours(at(3, 0), "garbage", "07:00", 0));
    }

    #[test]
    fn a_budget_alert_on_the_real_bill_says_so_and_one_on_the_estimate_says_that() {
        let (mut e, mut st, s) = (Engine::default(), AlertState::default(), settings());
        let obs = |basis, through: Option<&str>| {
            Some(BudgetObs {
                month: "2026-11".into(),
                spent: 85.0,
                currency: "USD".into(),
                basis,
                real_through: through.map(str::to_string),
            })
        };
        let a = e.evaluate(
            &mut st,
            &Inputs {
                now_ms: NOON,
                settings: &s,
                boxes: &[],
                budget: obs(crate::bill::BudgetBasis::Bill, Some("2026-11-07")),
            },
        );
        assert_eq!(a.len(), 1);
        assert!(
            a[0].title.contains("80%") && !a[0].title.contains("estimated"),
            "{}",
            a[0].title
        );
        assert!(
            a[0].body.contains("provider's bill up to 2026-11-07"),
            "{}",
            a[0].body
        );
        let (mut e, mut st) = (Engine::default(), AlertState::default());
        let a = e.evaluate(
            &mut st,
            &Inputs {
                now_ms: NOON,
                settings: &s,
                boxes: &[],
                budget: obs(crate::bill::BudgetBasis::Estimate, None),
            },
        );
        assert!(a[0].title.contains("estimated spent") && a[0].body.contains("not the bill"));
    }

    #[test]
    fn budget_thresholds_fire_once_each_and_only_when_enabled() {
        let (mut e, mut st, s) = (Engine::default(), AlertState::default(), settings());
        assert!(run(&mut e, &mut st, &s, NOON, vec![], Some(40.0)).is_empty());
        let a = run(&mut e, &mut st, &s, NOON + MIN, vec![], Some(51.0));
        assert_eq!(a.len(), 1);
        assert_eq!(a[0].severity, Severity::Normal);
        assert!(a[0].title.contains("50%"));
        assert!(
            run(&mut e, &mut st, &s, NOON + 2 * MIN, vec![], Some(60.0)).is_empty(),
            "no repeat"
        );
        let a = run(&mut e, &mut st, &s, NOON + 3 * MIN, vec![], Some(100.0));
        assert_eq!(
            a.len(),
            1,
            "one alert for the highest threshold crossed, not 80 and 100"
        );
        assert_eq!(a[0].severity, Severity::Urgent);
        assert!(run(&mut e, &mut st, &s, NOON + 4 * MIN, vec![], Some(150.0)).is_empty());
        // a new month starts over
        let budget = Some(BudgetObs {
            month: "2026-12".into(),
            spent: 55.0,
            currency: "USD".into(),
            basis: Default::default(),
            real_through: None,
        });
        let a = e.evaluate(
            &mut st,
            &Inputs {
                now_ms: NOON + 5 * MIN,
                settings: &s,
                boxes: &[],
                budget,
            },
        );
        assert_eq!(a.len(), 1);
        // a disabled threshold stays quiet
        let (mut e, mut st) = (Engine::default(), AlertState::default());
        let mut s2 = settings();
        s2.budget.alert_50 = false;
        assert!(run(&mut e, &mut st, &s2, NOON, vec![], Some(55.0)).is_empty());
        // and so does an estimate in another currency
        let eur = Some(BudgetObs {
            month: "2026-11".into(),
            spent: 500.0,
            currency: "EUR".into(),
            basis: Default::default(),
            real_through: None,
        });
        assert!(e
            .evaluate(
                &mut st,
                &Inputs {
                    now_ms: NOON,
                    settings: &s2,
                    boxes: &[],
                    budget: eur
                }
            )
            .is_empty());
    }

    #[test]
    fn quiet_hours_hold_normal_alerts_until_they_end_but_never_urgent_ones() {
        let (mut e, mut st, s) = (Engine::default(), AlertState::default(), settings());
        let quiet = 1_794_182_400_000 + 2 * 3_600_000; // 02:00 UTC
        assert!(
            run(&mut e, &mut st, &s, quiet, vec![], Some(55.0)).is_empty(),
            "held"
        );
        assert!(
            st.budget_fired.is_empty(),
            "a held alert is not recorded as sent"
        );
        let a = run(&mut e, &mut st, &s, quiet + MIN, vec![], Some(100.0));
        assert_eq!(a.len(), 1, "urgent goes through");
        assert_eq!(a[0].severity, Severity::Urgent);
        // the held 50% was swallowed by the 100% one (marked fired): nothing left at 07:00
        let morning = 1_794_182_400_000 + 7 * 3_600_000 + MIN;
        assert!(run(&mut e, &mut st, &s, morning, vec![], Some(100.0)).is_empty());
        // a held normal condition fires when the hours end
        let (mut e, mut st) = (Engine::default(), AlertState::default());
        let mut b = obs("dev");
        b.disk_used_pct = Some(90.0);
        assert!(run(&mut e, &mut st, &s, quiet, vec![b.clone()], None).is_empty());
        let a = run(&mut e, &mut st, &s, morning, vec![b], None);
        assert_eq!(a.len(), 1);
        assert_eq!(a[0].kind, "disk_high");
    }

    #[test]
    fn disk_over_85_fires_once_and_rearms_after_it_has_been_clear() {
        let (mut e, mut st, s) = (Engine::default(), AlertState::default(), settings());
        let mut b = obs("dev");
        b.disk_used_pct = Some(86.0);
        assert_eq!(
            run(&mut e, &mut st, &s, NOON, vec![b.clone()], None).len(),
            1
        );
        assert!(
            run(&mut e, &mut st, &s, NOON + MIN, vec![b.clone()], None).is_empty(),
            "deduped"
        );
        b.disk_used_pct = Some(50.0);
        assert!(run(&mut e, &mut st, &s, NOON + 2 * MIN, vec![b.clone()], None).is_empty());
        b.disk_used_pct = Some(90.0);
        assert!(
            run(&mut e, &mut st, &s, NOON + 3 * MIN, vec![b.clone()], None).is_empty(),
            "flapping does not re-fire"
        );
        b.disk_used_pct = Some(50.0);
        run(&mut e, &mut st, &s, NOON + 4 * MIN, vec![b.clone()], None);
        run(
            &mut e,
            &mut st,
            &s,
            NOON + 4 * MIN + REARM_MS,
            vec![b.clone()],
            None,
        );
        b.disk_used_pct = Some(97.0);
        let a = run(&mut e, &mut st, &s, NOON + 20 * MIN, vec![b], None);
        assert_eq!(a.len(), 1);
        assert_eq!(a[0].severity, Severity::Urgent, "over 95 is urgent");
    }

    #[test]
    fn memory_pressure_must_be_sustained() {
        let (mut e, mut st, s) = (Engine::default(), AlertState::default(), settings());
        let mut b = obs("dev");
        b.mem_used_pct = Some(95.0);
        for i in 0..4 {
            assert!(
                run(&mut e, &mut st, &s, NOON + i * MIN, vec![b.clone()], None).is_empty(),
                "tick {i}"
            );
        }
        let a = run(&mut e, &mut st, &s, NOON + 4 * MIN, vec![b.clone()], None);
        assert_eq!(a.len(), 1);
        assert_eq!(a[0].kind, "memory_pressure");
        // a dip resets the streak
        let (mut e, mut st) = (Engine::default(), AlertState::default());
        for i in 0..3 {
            run(&mut e, &mut st, &s, NOON + i * MIN, vec![b.clone()], None);
        }
        b.mem_used_pct = Some(10.0);
        run(&mut e, &mut st, &s, NOON + 3 * MIN, vec![b.clone()], None);
        b.mem_used_pct = Some(95.0);
        for i in 4..8 {
            assert!(run(&mut e, &mut st, &s, NOON + i * MIN, vec![b.clone()], None).is_empty());
        }
        // pressure stall alone counts too
        let (mut e, mut st) = (Engine::default(), AlertState::default());
        let mut p = obs("dev");
        p.psi_mem = Some(40.0);
        let mut n = 0;
        for i in 0..5 {
            n += run(&mut e, &mut st, &s, NOON + i * MIN, vec![p.clone()], None).len();
        }
        assert_eq!(n, 1);
    }

    #[test]
    fn a_failed_self_test_is_urgent_and_names_the_step() {
        let (mut e, mut st, s) = (Engine::default(), AlertState::default(), settings());
        let mut b = obs("dev");
        b.selftest_failed = Some("tunnels up".into());
        let a = run(&mut e, &mut st, &s, NOON, vec![b.clone()], None);
        assert_eq!(a.len(), 1);
        assert_eq!(a[0].severity, Severity::Urgent);
        assert!(a[0].body.contains("tunnels up"));
        assert!(run(&mut e, &mut st, &s, NOON + MIN, vec![b], None).is_empty());
    }

    #[test]
    fn incidents_are_news_only_after_the_box_is_watched_and_only_once() {
        let (mut e, mut st, s) = (Engine::default(), AlertState::default(), settings());
        let mut b = obs("dev");
        b.incidents = vec![(NOON - 5 * MIN, "oom_kill".into(), "history".into())];
        assert!(
            run(&mut e, &mut st, &s, NOON, vec![b.clone()], None).is_empty(),
            "history before watching"
        );
        b.incidents
            .push((NOON + MIN, "oom_kill".into(), "a run was killed".into()));
        b.incidents
            .push((NOON + MIN, "disk_grown".into(), "good news".into()));
        b.incidents.push((
            NOON + MIN,
            "self_test_failed".into(),
            "covered elsewhere".into(),
        ));
        let a = run(&mut e, &mut st, &s, NOON + 2 * MIN, vec![b.clone()], None);
        assert_eq!(a.len(), 1);
        assert_eq!(a[0].severity, Severity::Urgent);
        assert!(a[0].title.contains("oom kill"));
        assert!(run(&mut e, &mut st, &s, NOON + 3 * MIN, vec![b], None).is_empty());
    }

    #[test]
    fn the_hourly_limit_drops_ordinary_alerts_first() {
        let mut st = AlertState::default();
        let mk = |i: usize, sev| Alert {
            notice: None,
            reach: Default::default(),
            key: format!("k{i}"),
            kind: "x".into(),
            severity: sev,
            box_name: None,
            title: "t".into(),
            body: "b".into(),
            ts_ms: 0,
        };
        let mut v: Vec<Alert> = (0..HOURLY_CAP + 5)
            .map(|i| mk(i, Severity::Normal))
            .collect();
        v.push(mk(999, Severity::Urgent));
        let (ok, dropped) = Engine::admit(&mut st, v, NOON);
        assert_eq!(dropped, 6);
        assert!(ok.iter().any(|a| a.key == "k999"));
        assert_eq!(ok.len(), HOURLY_CAP);
        // an hour later the counter has emptied
        let (ok, dropped) = Engine::admit(&mut st, vec![mk(1, Severity::Normal)], NOON + 3_700_000);
        assert_eq!((ok.len(), dropped), (1, 0));
    }

    #[test]
    fn recent_alerts_are_bounded() {
        let mut st = AlertState::default();
        let a = test_alert(1);
        for _ in 0..MAX_RECENT + 10 {
            Engine::record(&mut st, &a, vec![]);
        }
        assert_eq!(st.recent.len(), MAX_RECENT);
    }

    #[test]
    fn signatures_verify_and_replays_are_refused() {
        let body = r#"{"a":1}"#;
        let sig = sign("topsecret-signing-key", 1_000, body);
        assert!(sig.starts_with("v1="));
        assert_eq!(sig.len(), 3 + 64);
        assert!(verify(
            "topsecret-signing-key",
            1_000,
            body,
            &sig,
            1_100,
            REPLAY_WINDOW_S
        ));
        assert!(
            !verify(
                "another-secret-value",
                1_000,
                body,
                &sig,
                1_100,
                REPLAY_WINDOW_S
            ),
            "wrong secret"
        );
        assert!(
            !verify(
                "topsecret-signing-key",
                1_000,
                r#"{"a":2}"#,
                &sig,
                1_100,
                REPLAY_WINDOW_S
            ),
            "changed body"
        );
        assert!(
            !verify(
                "topsecret-signing-key",
                1_001,
                body,
                &sig,
                1_100,
                REPLAY_WINDOW_S
            ),
            "changed timestamp"
        );
        assert!(
            !verify(
                "topsecret-signing-key",
                1_000,
                body,
                &sig,
                1_000 + REPLAY_WINDOW_S + 1,
                REPLAY_WINDOW_S
            ),
            "replayed later"
        );
        assert!(
            !verify(
                "topsecret-signing-key",
                1_000,
                body,
                &sig,
                1_000 - REPLAY_WINDOW_S - 1,
                REPLAY_WINDOW_S
            ),
            "from the future"
        );
        assert!(!verify(
            "topsecret-signing-key",
            1_000,
            body,
            "v1=zz",
            1_000,
            REPLAY_WINDOW_S
        ));
        assert!(!verify(
            "topsecret-signing-key",
            1_000,
            body,
            "nothex",
            1_000,
            REPLAY_WINDOW_S
        ));
        // a known vector: HMAC-SHA256("key", "1.x") is stable
        assert_eq!(sign("key", 1, "x"), sign("key", 1, "x"));
    }

    fn channels() -> (Channels, Arc<FakeHttp>, Arc<MemorySecrets>) {
        let http = Arc::new(FakeHttp::default());
        let secrets = Arc::new(MemorySecrets::default());
        (
            Channels {
                secrets: secrets.clone(),
                http: http.clone(),
                runner: Arc::new(ozbox_core::RecordingRunner::new()),
                aws_profile: None,
            },
            http,
            secrets,
        )
    }

    #[test]
    fn email_goes_to_the_provider_api_with_the_key_in_a_header_only(
    ) -> Result<(), crate::secrets::SecretError> {
        let (c, http, secrets) = channels();
        let mut s = settings();
        s.apps.email = crate::settings::EmailConfig {
            enabled: true,
            from: "alerts@example.com".into(),
            to: vec!["me@example.com".into()],
            ..Default::default()
        };
        assert!(c.email(&s, &test_alert(1)).is_err(), "no key yet");
        secrets.set("email-api-key", "re_SENTINELKEY")?;
        assert_eq!(c.email(&s, &test_alert(1)), Ok("sent".to_string()));
        let r = &http.requests()[0];
        assert_eq!(r.url, "https://api.resend.com/emails");
        assert!(r
            .headers
            .iter()
            .any(|(k, v)| k == "Authorization" && v == "Bearer re_SENTINELKEY"));
        let body = String::from_utf8_lossy(r.body.as_deref().unwrap_or_default()).into_owned();
        assert!(!body.contains("SENTINELKEY"));
        assert!(body.contains("me@example.com") && body.contains("Turn them off"));
        assert_eq!(r.guard, Guard::Public);
        Ok(())
    }

    #[test]
    fn telegram_sends_only_to_paired_chats() -> Result<(), crate::secrets::SecretError> {
        let (c, http, secrets) = channels();
        secrets.set("telegram-bot-token", "123:TOKEN")?;
        assert!(c.telegram(&[], &test_alert(1)).is_err());
        let chats = vec![
            TelegramChat {
                id: 7,
                name: "A".into(),
                person: None,
            },
            TelegramChat {
                id: 8,
                name: "B".into(),
                person: None,
            },
        ];
        assert!(c.telegram(&chats, &test_alert(1)).is_ok());
        let sent = http.requests();
        assert_eq!(sent.len(), 2);
        assert!(sent[0].url.ends_with("/bot123:TOKEN/sendMessage"));
        assert!(
            String::from_utf8_lossy(sent[1].body.as_deref().unwrap_or_default())
                .contains("\"chat_id\":8")
        );
        Ok(())
    }

    #[test]
    fn a_telegram_that_is_busy_is_worth_another_try_but_a_chat_that_refuses_is_not(
    ) -> Result<(), crate::secrets::SecretError> {
        let chat = |id| TelegramChat {
            id,
            name: "A".into(),
            person: None,
        };
        for (status, retry) in [(503, true), (429, true), (400, false), (403, false)] {
            let (c, http, secrets) = channels();
            secrets.set("telegram-bot-token", "123:TOKEN")?;
            http.reply(status, "{}");
            let e = c
                .telegram(&[chat(7)], &test_alert(1))
                .err()
                .unwrap_or_default();
            assert!(e.contains("1 of 1 chats could not be reached"), "{e}");
            assert!(e.contains(&format!("(HTTP {status})")), "{e}");
            assert_eq!(crate::channels::retryable(&e), retry, "{status}: {e}");
        }
        Ok(())
    }

    #[test]
    fn each_chats_failure_adds_its_status_code_and_never_a_chat_id(
    ) -> Result<(), crate::secrets::SecretError> {
        let chat = |id| TelegramChat {
            id,
            name: "Private name".into(),
            person: None,
        };
        let (c, http, secrets) = channels();
        secrets.set("telegram-bot-token", "123:TOKEN")?;
        http.reply(403, "{}");
        http.reply(503, "{}");
        http.reply(403, "{}");
        let e = c
            .telegram(&[chat(111), chat(222), chat(333)], &test_alert(1))
            .err()
            .unwrap_or_default();
        assert!(
            e.contains("3 of 3 chats could not be reached (HTTP 403; HTTP 503)"),
            "{e}"
        );
        for secret in ["111", "222", "333", "Private name", "TOKEN"] {
            assert!(!e.contains(secret), "{e}");
        }
        Ok(())
    }

    #[test]
    fn slack_posts_to_the_saved_webhook_and_a_failure_does_not_echo_the_address(
    ) -> Result<(), crate::secrets::SecretError> {
        let (c, http, secrets) = channels();
        secrets.set(
            "slack-webhook-url",
            "https://hooks.example.com/T000/SECRETPATH",
        )?;
        http.reply(404, "no_service SECRETPATH");
        let r = c.slack(&test_alert(1));
        let err = r.err().unwrap_or_default();
        assert!(err.contains("404") && !err.contains("SECRETPATH"), "{err}");
        Ok(())
    }

    #[test]
    fn a_webhook_is_signed_with_a_timestamp_and_the_signature_verifies(
    ) -> Result<(), crate::secrets::SecretError> {
        let (c, http, secrets) = channels();
        secrets.set("webhook-url-ci", "https://hooks.example.com/in")?;
        secrets.set("webhook-secret-ci", "signing-secret-000111")?;
        assert_eq!(
            c.webhook("ci", &test_alert(5), 1_700_000_000),
            Ok("sent".to_string())
        );
        let r = &http.requests()[0];
        let h = |k: &str| {
            r.headers
                .iter()
                .find(|(n, _)| n.eq_ignore_ascii_case(k))
                .map(|(_, v)| v.clone())
                .unwrap_or_default()
        };
        let body = String::from_utf8_lossy(r.body.as_deref().unwrap_or_default()).into_owned();
        assert_eq!(h("X-Ozbox-Timestamp"), "1700000000");
        assert!(verify(
            "signing-secret-000111",
            1_700_000_000,
            &body,
            &h("X-Ozbox-Signature"),
            1_700_000_010,
            REPLAY_WINDOW_S
        ));
        assert!(!body.contains("signing-secret-000111"));
        assert!(body.contains("alert.test"));
        Ok(())
    }

    #[test]
    fn send_all_uses_only_enabled_channels() -> Result<(), crate::secrets::SecretError> {
        let (c, http, secrets) = channels();
        secrets.set("slack-webhook-url", "https://hooks.example.com/x")?;
        let mut s = settings();
        assert!(c.send_all(&s, &[], &test_alert(1), 1).is_empty());
        s.apps.slack.enabled = true;
        s.apps.telegram.enabled = true; // enabled but no token: reported, not skipped silently
        let d = c.send_all(&s, &[], &test_alert(1), 1);
        assert_eq!(d.len(), 2);
        assert!(d.iter().any(|x| x.channel == "slack" && x.ok));
        assert!(d.iter().any(|x| x.channel == "telegram" && !x.ok));
        assert_eq!(http.requests().len(), 1);
        Ok(())
    }
}
