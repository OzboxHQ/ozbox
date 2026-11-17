//! Who is told what, and when. Each person has a rule per severity (which channels, and whether an urgent alert may break
//! through their quiet hours), quiet hours and a daily summary in their own time zone, and the plan below turns one alert
//! into the list of deliveries to make. Planning is pure apart from the small counters it keeps in [`AlertState`], so
//! the rules are tested without any network.
//!
//! With no one listed under `routing.people`, the older behaviour holds: every fleet channel that is switched on gets
//! every alert.

use std::collections::BTreeSet;
use std::sync::mpsc;
use std::time::{Duration, Instant};

use ring::digest::{digest, SHA256};
use serde::{Deserialize, Serialize};

use super::sms::PER_RECIPIENT_PER_HOUR;
use crate::notify::{Alert, AlertState, Channels, Delivery, Severity};
use crate::notify_config::{PersonRouting, Route};
use crate::settings::Settings;
use crate::state::TelegramChat;

/// Where one delivery goes.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", content = "to", rename_all = "snake_case")]
pub enum Target {
    Sms(String),
    Email(Vec<String>),
    Whatsapp(String),
    /// A stored push device, by id.
    Push(String),
    Telegram(i64),
    /// A channel with one fleet-wide destination: `email`, `slack`, `discord`, `teams`, `telegram`, `webhook:<id>`.
    Fleet(String),
}

impl Target {
    /// What makes two deliveries the same one: the same place, not the same channel name.
    pub fn key(&self) -> String {
        match self {
            Target::Sms(n) => format!("sms:{n}"),
            Target::Whatsapp(n) => format!("whatsapp:{n}"),
            Target::Push(d) => format!("push:{d}"),
            Target::Telegram(c) => format!("telegram:{c}"),
            Target::Email(l) => {
                let mut v: Vec<String> = l.iter().map(|a| a.to_ascii_lowercase()).collect();
                v.sort();
                format!("email:{}", v.join(","))
            }
            Target::Fleet(c) => format!("fleet:{c}"),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Planned {
    pub person: Option<String>,
    /// The name shown in Activity: `sms`, `push`, `telegram`...
    pub channel: String,
    pub target: Target,
}

/// A failed delivery that will be tried again.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Retry {
    pub alert: Alert,
    pub planned: Planned,
    /// The attempt this retry will be (2 is the first retry).
    pub attempt: u32,
    pub due_ms: u64,
}

/// What became of an alert for the person whose summary it is in.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DigestStatus {
    /// Kept before this was recorded: listed without a tag.
    #[default]
    Unrecorded,
    /// At least one of their channels was sent it (or had already been told).
    Delivered,
    /// Kept for this summary because it arrived in their quiet hours.
    HeldQuiet,
    /// Not sent to a number because of the hourly limit on texts to it.
    HeldLimit,
    /// No channel of theirs could take it, or the fleet's hourly limit on alerts had been reached.
    NotSent,
    /// Sent, but every channel is still being retried after a failure and none has succeeded yet.
    Retrying,
    /// Every channel failed, even after the retries (or was refused), so nobody was reached.
    Failed,
    /// For the alert as a whole: some of the people it was routed to were reached and some were not.
    Partial,
}

impl DigestStatus {
    fn tag(self) -> &'static str {
        match self {
            DigestStatus::Unrecorded => "",
            DigestStatus::Delivered => "[delivered] ",
            DigestStatus::HeldQuiet => "[held: quiet hours] ",
            DigestStatus::HeldLimit => "[held: text limit] ",
            DigestStatus::NotSent => "[not sent] ",
            DigestStatus::Retrying => "[retrying] ",
            DigestStatus::Failed => "[delivery failed] ",
            DigestStatus::Partial => "[partly delivered] ",
        }
    }

    fn not_delivered(self) -> bool {
        matches!(
            self,
            DigestStatus::HeldQuiet
                | DigestStatus::HeldLimit
                | DigestStatus::NotSent
                | DigestStatus::Failed
        )
    }
}

/// What finally became of one channel of one person's route.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ChannelState {
    /// The service took it.
    Sent,
    /// It failed and another try is coming.
    Retrying,
    /// It failed on every try; the reason is in `detail`.
    Failed,
    /// The service refused it for a reason another try cannot fix (credentials, a wrong number); see `detail`.
    Refused,
}

/// One channel's result, kept so "delivered" means a channel really took the message.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ChannelResult {
    pub channel: String,
    pub state: ChannelState,
    /// How many tries were made.
    pub attempts: u32,
    /// Why it failed or was refused. Never holds a secret, an address or a response body.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub detail: String,
}

/// What became of one alert for one person, kept with the recorded alert so the dashboard can say so.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct AlertOutcome {
    /// Whose rules decided it; none when no one has routing rules (or the alert was refused for everyone).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub person: Option<String>,
    pub status: DigestStatus,
    /// The channels it went to (delivered), or would have gone to (held, not sent).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub channels: Vec<String>,
    /// What finally became of each of those channels. Empty on alerts recorded before this was kept, and on a hold.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub results: Vec<ChannelResult>,
}

impl DigestStatus {
    /// Whether this person was sent the alert (as opposed to held, or never routable).
    fn routed(self) -> bool {
        matches!(
            self,
            DigestStatus::Delivered | DigestStatus::Retrying | DigestStatus::Failed
        )
    }

    /// Which of several outcomes stands for the alert as a whole. Among the people it was sent to: all reached is
    /// `delivered`, some reached is `partial`, none reached is `retrying` while a try is pending and `failed` after.
    /// When it was sent to no one: the most specific hold.
    pub fn overall(outcomes: &[AlertOutcome]) -> Option<DigestStatus> {
        let routed: Vec<DigestStatus> = outcomes
            .iter()
            .map(|o| o.status)
            .filter(|s| s.routed())
            .collect();
        if !routed.is_empty() {
            let reached = routed
                .iter()
                .filter(|s| **s == DigestStatus::Delivered)
                .count();
            return Some(if reached == routed.len() {
                DigestStatus::Delivered
            } else if reached > 0 {
                DigestStatus::Partial
            } else if routed.contains(&DigestStatus::Retrying) {
                DigestStatus::Retrying
            } else {
                DigestStatus::Failed
            });
        }
        [
            DigestStatus::HeldQuiet,
            DigestStatus::HeldLimit,
            DigestStatus::NotSent,
        ]
        .into_iter()
        .find(|want| outcomes.iter().any(|o| o.status == *want))
    }
}

/// Fold what was really delivered into the outcomes of an alert. A person who was sent the alert is `delivered` once
/// one of their channels succeeded, `retrying` while every try so far failed but another is coming, and `failed`
/// when the last try failed or was refused. A channel with no delivery of its own was told by another route to the same
/// place, and takes that route's result. A channel with several places (two devices) reads from the one with the most
/// tries, so it is `sent` when any place took it.
pub fn settle(outcomes: &mut [AlertOutcome], deliveries: &[Delivery]) {
    for o in outcomes.iter_mut().filter(|o| o.status.routed()) {
        if o.channels.is_empty() {
            continue;
        }
        let mut results = Vec::new();
        for ch in &o.channels {
            let own: Vec<&Delivery> = deliveries
                .iter()
                .filter(|d| d.channel == *ch && d.person == o.person)
                .collect();
            let ds: Vec<&Delivery> = if own.is_empty() {
                deliveries.iter().filter(|d| d.channel == *ch).collect()
            } else {
                own
            };
            let tries = ds.iter().map(|d| d.attempts).max().unwrap_or(1);
            let last = ds.iter().max_by_key(|d| d.attempts);
            let (state, detail) = match last {
                _ if ds.iter().any(|d| d.ok) => (ChannelState::Sent, String::new()),
                None => (ChannelState::Sent, String::new()),
                Some(d) if !super::retryable(&d.detail) => {
                    (ChannelState::Refused, d.detail.clone())
                }
                Some(d) if (d.attempts as usize) <= BACKOFF_MS.len() => {
                    (ChannelState::Retrying, d.detail.clone())
                }
                Some(d) => (ChannelState::Failed, d.detail.clone()),
            };
            results.push(ChannelResult {
                channel: ch.clone(),
                state,
                attempts: tries,
                detail,
            });
        }
        o.status = if results.iter().any(|r| r.state == ChannelState::Sent) {
            DigestStatus::Delivered
        } else if results.iter().any(|r| r.state == ChannelState::Retrying) {
            DigestStatus::Retrying
        } else {
            DigestStatus::Failed
        };
        o.results = results;
    }
}

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct DigestItem {
    pub ts_ms: u64,
    pub urgent: bool,
    pub title: String,
    #[serde(skip_serializing_if = "is_unrecorded")]
    pub status: DigestStatus,
}

fn is_unrecorded(s: &DigestStatus) -> bool {
    *s == DigestStatus::Unrecorded
}

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct DigestState {
    pub next_ms: u64,
    pub items: Vec<DigestItem>,
}

/// Backoff before the second, third and fourth attempt. A delivery is tried at most four times.
pub const BACKOFF_MS: [u64; 3] = [60_000, 5 * 60_000, 15 * 60_000];
pub const DEDUPE_MS: u64 = 10 * 60_000;
const MAX_DIGEST_ITEMS: usize = 100;

#[derive(Debug, Default)]
pub struct Plan {
    pub send: Vec<Planned>,
    /// What was decided without sending: held for quiet hours, not set up, rate limited. Recorded in Activity.
    pub skipped: Vec<Delivery>,
}

fn zone_of<'a>(s: &'a Settings, p: &'a PersonRouting) -> &'a str {
    p.time_zone.as_deref().unwrap_or_else(|| s.locale.zone())
}

/// Whether it is quiet for this person at `now_ms`: their own hours in their own zone, else the fleet's hours.
pub fn person_quiet(s: &Settings, p: &PersonRouting, now_ms: u64) -> bool {
    let (from, to) = match (&p.quiet_from, &p.quiet_to) {
        (Some(f), Some(t)) => (f.as_str(), t.as_str()),
        _ => (s.budget.quiet_from.as_str(), s.budget.quiet_to.as_str()),
    };
    let zone = zone_of(s, p);
    let offset =
        crate::timezone::offset_minutes(zone, now_ms).unwrap_or(s.budget.utc_offset_minutes);
    crate::notify::in_quiet_hours(now_ms, from, to, offset)
}

fn rate_key(number: &str) -> String {
    crate::notify::hex(&digest(&SHA256, number.as_bytes()).as_ref()[..8])
}

/// Count one more text to this number, or say it is over the hourly limit.
pub fn sms_allowed(st: &mut AlertState, number: &str, now_ms: u64) -> bool {
    let e = st.sms_sent.entry(rate_key(number)).or_default();
    e.retain(|t| now_ms.saturating_sub(*t) < 3_600_000);
    if e.len() >= PER_RECIPIENT_PER_HOUR {
        return false;
    }
    e.push(now_ms);
    true
}

/// The person a paired chat is linked to, if that person still has routing.
fn chat_owner<'a>(s: &'a Settings, c: &'a TelegramChat) -> Option<&'a str> {
    c.person
        .as_deref()
        .filter(|p| s.routing.people.contains_key(*p))
}

/// Resolve one channel name of a person's route to its destinations, or the reason there are none.
pub fn resolve(
    s: &Settings,
    chats: &[TelegramChat],
    person: &str,
    p: &PersonRouting,
    channel: &str,
) -> Result<Vec<Planned>, String> {
    let a = &s.apps;
    let mk = |t: Target| Planned {
        person: Some(person.to_string()),
        channel: channel.to_string(),
        target: t,
    };
    match channel {
        "sms" => {
            if !a.sms.enabled {
                return Err("SMS is not switched on".into());
            }
            p.phone
                .clone()
                .map(|n| vec![mk(Target::Sms(n))])
                .ok_or_else(|| "no phone number is set for this person".into())
        }
        "whatsapp" => {
            if !a.whatsapp.enabled {
                return Err("WhatsApp is not switched on".into());
            }
            p.whatsapp
                .clone()
                .or_else(|| p.phone.clone())
                .map(|n| vec![mk(Target::Whatsapp(n))])
                .ok_or_else(|| "no WhatsApp number is set for this person".into())
        }
        "email" => {
            if !a.email.enabled {
                return Err("email is not switched on".into());
            }
            if !p.emails.is_empty() {
                Ok(vec![mk(Target::Email(p.emails.clone()))])
            } else if !a.email.to.is_empty() {
                Ok(vec![mk(Target::Email(a.email.to.clone()))])
            } else {
                Err("no email address is set for this person".into())
            }
        }
        "push" => {
            if !a.push.enabled {
                return Err("push notifications are not switched on".into());
            }
            if p.push.is_empty() {
                return Err("this person has no device with notifications turned on".into());
            }
            Ok(p.push
                .iter()
                .map(|d| mk(Target::Push(d.id.clone())))
                .collect())
        }
        "telegram" => {
            if !a.telegram.enabled {
                return Err("Telegram is not switched on".into());
            }
            if chats.is_empty() {
                return Err("no chat is paired with the bot yet".into());
            }
            let mine: Vec<&TelegramChat> = chats
                .iter()
                .filter(|c| chat_owner(s, c) == Some(person))
                .collect();
            let chosen: Vec<&TelegramChat> = if mine.is_empty() {
                // Nothing is linked to this person: fall back to the chats nobody has claimed, as before.
                chats
                    .iter()
                    .filter(|c| chat_owner(s, c).is_none())
                    .collect()
            } else {
                mine
            };
            if chosen.is_empty() {
                return Err("no Telegram chat is linked to this person".into());
            }
            Ok(chosen
                .into_iter()
                .map(|c| mk(Target::Telegram(c.id)))
                .collect())
        }
        "slack" | "discord" | "teams" => {
            let on = match channel {
                "slack" => a.slack.enabled,
                "discord" => a.discord.enabled,
                _ => a.teams.enabled,
            };
            if on {
                Ok(vec![mk(Target::Fleet(channel.into()))])
            } else {
                Err(format!("{channel} is not switched on"))
            }
        }
        c => match c.strip_prefix("webhook:") {
            Some(id) if a.webhooks.iter().any(|w| w.id == id && w.enabled) => {
                Ok(vec![mk(Target::Fleet(c.into()))])
            }
            _ => Err("that webhook is not switched on".into()),
        },
    }
}

fn route_for(p: &PersonRouting, sev: Severity) -> &Route {
    match sev {
        Severity::Urgent => &p.urgent,
        Severity::Normal => &p.normal,
    }
}

fn legacy(s: &Settings) -> Vec<Planned> {
    Channels::enabled(s)
        .into_iter()
        .map(|c| Planned {
            person: None,
            channel: c.clone(),
            target: Target::Fleet(c),
        })
        .collect()
}

fn skipped(person: &str, channel: &str, why: impl Into<String>, ok: bool) -> Delivery {
    let mut d = Delivery::new(channel, ok, why);
    d.person = Some(person.to_string());
    d
}

/// Decide every delivery for one alert. Also queues the alert for each person's daily summary.
pub fn plan(
    s: &Settings,
    chats: &[TelegramChat],
    a: &Alert,
    st: &mut AlertState,
    now_ms: u64,
) -> Plan {
    let mut out = Plan::default();
    st.dedupe
        .retain(|_, t| now_ms.saturating_sub(*t) < DEDUPE_MS);
    if s.routing.people.is_empty() {
        out.send = legacy(s);
        return out;
    }
    let mut seen: BTreeSet<String> = BTreeSet::new();
    for (pid, p) in &s.routing.people {
        // a person's own rule for this kind of alert decides which route it follows, or that it is not sent to them
        let sev = match p.kind_routes.get(&a.kind).map(String::as_str) {
            Some("off") => {
                out.skipped.push(skipped(
                    pid,
                    "routing",
                    "not sent: this person turned off this kind of alert",
                    true,
                ));
                continue;
            }
            Some("urgent") => Severity::Urgent,
            Some("normal") => Severity::Normal,
            _ => a.severity,
        };
        let route = route_for(p, sev);
        let quiet = person_quiet(s, p, now_ms);
        if quiet && !(sev == Severity::Urgent && route.bypass_quiet) {
            if !route.channels.is_empty() {
                let note = if p.digest.enabled {
                    "held: quiet hours; it is in the daily summary"
                } else {
                    "not sent: quiet hours"
                };
                out.skipped.push(skipped(pid, "routing", note, true));
            }
            note_digest(st, pid, p, a, DigestStatus::HeldQuiet);
            note_outcome(
                st,
                a,
                Some(pid),
                DigestStatus::HeldQuiet,
                route.channels.clone(),
            );
            continue;
        }
        let (mut told, mut over_limit) = (false, false);
        let (mut via, mut limited): (Vec<String>, Vec<String>) = (Vec::new(), Vec::new());
        for c in &route.channels {
            match resolve(s, chats, pid, p, c) {
                Err(why) => out.skipped.push(skipped(pid, c, why, false)),
                Ok(list) => {
                    for pl in list {
                        let key = format!("{}|{}", a.key, pl.target.key());
                        if !seen.insert(key.clone()) || st.dedupe.contains_key(&key) {
                            told = true;
                            if !via.contains(c) {
                                via.push(c.clone());
                            }
                            continue;
                        }
                        if let Target::Sms(n) = &pl.target {
                            if !sms_allowed(st, n, now_ms) {
                                out.skipped.push(skipped(
                                    pid,
                                    c,
                                    "not sent: this number has already had the most texts allowed in an hour",
                                    false,
                                ));
                                over_limit = true;
                                if !limited.contains(c) {
                                    limited.push(c.clone());
                                }
                                continue;
                            }
                        }
                        st.dedupe.insert(key, now_ms);
                        out.send.push(pl);
                        told = true;
                        if !via.contains(c) {
                            via.push(c.clone());
                        }
                    }
                }
            }
        }
        let status = if told {
            DigestStatus::Delivered
        } else if over_limit {
            DigestStatus::HeldLimit
        } else {
            DigestStatus::NotSent
        };
        note_digest(st, pid, p, a, status);
        let channels = match status {
            DigestStatus::Delivered => via,
            DigestStatus::HeldLimit => limited,
            _ => route.channels.clone(),
        };
        note_outcome(st, a, Some(pid), status, channels);
    }
    out
}

/// What became of an alert for a person, kept until the alert is recorded.
fn note_outcome(
    st: &mut AlertState,
    a: &Alert,
    person: Option<&str>,
    status: DigestStatus,
    channels: Vec<String>,
) {
    if st.outcomes.len() >= 200 {
        st.outcomes.clear(); // an outcome whose alert was never recorded: bounded, never unbounded
    }
    st.outcomes
        .entry(a.key.clone())
        .or_default()
        .push(AlertOutcome {
            person: person.map(str::to_string),
            status,
            channels,
            results: Vec::new(),
        });
}

/// Put an alert in a person's daily summary with what became of it for them.
fn note_digest(st: &mut AlertState, pid: &str, p: &PersonRouting, a: &Alert, status: DigestStatus) {
    if !p.digest.enabled {
        return;
    }
    let d = st.digests.entry(pid.to_string()).or_default();
    d.items.push(DigestItem {
        ts_ms: a.ts_ms,
        urgent: a.severity == Severity::Urgent,
        title: a.title.clone(),
        status,
    });
    let over = d.items.len().saturating_sub(MAX_DIGEST_ITEMS);
    d.items.drain(..over);
}

/// Alerts the fleet's hourly limit refused: nobody was sent them, and each person's summary says so.
pub fn note_dropped(s: &Settings, st: &mut AlertState, dropped: &[Alert]) {
    for a in dropped {
        for (pid, p) in &s.routing.people {
            note_digest(st, pid, p, a, DigestStatus::NotSent);
            note_outcome(st, a, Some(pid), DigestStatus::NotSent, Vec::new());
        }
        if s.routing.people.is_empty() {
            note_outcome(st, a, None, DigestStatus::NotSent, Vec::new());
        }
    }
}

/// What a test send of one channel to one person would use, ignoring routes and quiet hours.
pub fn test_plan(
    s: &Settings,
    chats: &[TelegramChat],
    person: Option<&str>,
    channel: &str,
) -> Result<Vec<Planned>, String> {
    let fleet = matches!(
        channel,
        "email" | "telegram" | "slack" | "discord" | "teams"
    ) || channel.starts_with("webhook:");
    let pid = person
        .map(str::to_string)
        .or_else(|| s.routing.people.keys().next().cloned());
    match pid
        .as_deref()
        .and_then(|id| s.routing.people.get(id).map(|p| (id, p)))
    {
        Some((id, p)) => resolve(s, chats, id, p, channel),
        None if fleet && s.routing.people.is_empty() => Ok(vec![Planned {
            person: None,
            channel: channel.into(),
            target: Target::Fleet(channel.into()),
        }]),
        None => Err("add yourself under Routing first, with a phone number or a device".into()),
    }
}

// ---------- the daily summary ----------

/// The summary of a person's day as an alert, or none when nothing happened.
pub fn digest_alert(pid: &str, items: &[DigestItem], now_ms: u64) -> Option<Alert> {
    if items.is_empty() {
        return None;
    }
    let urgent = items.iter().filter(|i| i.urgent).count();
    let held = items.iter().filter(|i| i.status.not_delivered()).count();
    let mut lines: Vec<String> = items
        .iter()
        .rev()
        .take(20)
        .map(|i| {
            format!(
                "{} {}{}",
                if i.urgent { "(urgent)" } else { "-" },
                i.status.tag(),
                i.title
            )
        })
        .collect();
    if items.len() > 20 {
        lines.push(format!("...and {} more", items.len() - 20));
    }
    Some(Alert {
        notice: None,
        reach: Default::default(),
        key: format!("digest:{pid}:{}", now_ms / 86_400_000),
        kind: "digest".into(),
        severity: Severity::Normal,
        box_name: None,
        title: format!(
            "Daily summary: {} alert{}{}",
            items.len(),
            if items.len() == 1 { "" } else { "s" },
            if urgent > 0 {
                format!(", {urgent} urgent")
            } else {
                String::new()
            } + &if held > 0 {
                format!(", {held} held or not sent")
            } else {
                String::new()
            }
        ),
        body: lines.join("\n"),
        ts_ms: now_ms,
    })
}

/// The summaries that are due: one alert per person whose chosen local time has passed and who has something to read.
/// The next one is scheduled for the following occurrence of that local time (daylight saving followed).
pub fn due_digests(
    s: &Settings,
    chats: &[TelegramChat],
    st: &mut AlertState,
    now_ms: u64,
) -> Vec<(Alert, Vec<Planned>, Vec<Delivery>)> {
    let mut out = Vec::new();
    for (pid, p) in &s.routing.people {
        if !p.digest.enabled {
            st.digests.remove(pid);
            continue;
        }
        let Some((h, m)) = p
            .digest
            .time
            .split_once(':')
            .and_then(|(h, m)| Some((h.parse::<i8>().ok()?, m.parse::<i8>().ok()?)))
        else {
            continue;
        };
        let next = crate::timezone::next_local_time(zone_of(s, p), now_ms, h, m);
        let d = st.digests.entry(pid.clone()).or_default();
        if d.next_ms == 0 {
            d.next_ms = next.unwrap_or(now_ms + 86_400_000);
            continue;
        }
        if now_ms < d.next_ms {
            continue;
        }
        d.next_ms = next.unwrap_or(now_ms + 86_400_000);
        let items = std::mem::take(&mut d.items);
        let Some(alert) = digest_alert(pid, &items, now_ms) else {
            continue;
        };
        let (mut send, mut skip) = (Vec::new(), Vec::new());
        for c in &p.digest.channels {
            match resolve(s, chats, pid, p, c) {
                Ok(list) => send.extend(list),
                Err(why) => skip.push(skipped(pid, c, why, false)),
            }
        }
        // The summary is an alert like any other: it says whom it was sent to, and `settle` follows it.
        let mut via: Vec<String> = Vec::new();
        for pl in &send {
            if !via.contains(&pl.channel) {
                via.push(pl.channel.clone());
            }
        }
        if via.is_empty() {
            note_outcome(
                st,
                &alert,
                Some(pid),
                DigestStatus::NotSent,
                p.digest.channels.clone(),
            );
        } else {
            note_outcome(st, &alert, Some(pid), DigestStatus::Delivered, via);
        }
        out.push((alert, send, skip));
    }
    out
}

// ---------- retries ----------

/// Queue a failed delivery for another try, unless it has had its four or the failure is a refusal.
#[cfg(test)]
pub fn schedule_retry(
    st: &mut AlertState,
    alert: &Alert,
    planned: &Planned,
    attempt: u32,
    d: &Delivery,
    now_ms: u64,
) -> bool {
    schedule_retry_after(st, alert, planned, attempt, d, now_ms, None)
}

/// [`schedule_retry`] with the pause between tries replaced by `pause_ms`. Only the demo server (a browser test that has
/// to see "retrying" and then the result) passes one; a real server always uses [`BACKOFF_MS`], and how many tries there
/// are never changes.
pub fn schedule_retry_after(
    st: &mut AlertState,
    alert: &Alert,
    planned: &Planned,
    attempt: u32,
    d: &Delivery,
    now_ms: u64,
    pause_ms: Option<u64>,
) -> bool {
    if d.ok || !super::retryable(&d.detail) {
        return false;
    }
    let Some(wait) = BACKOFF_MS.get((attempt as usize).saturating_sub(1)) else {
        return false;
    };
    st.retries.push(Retry {
        alert: alert.clone(),
        planned: planned.clone(),
        attempt: attempt + 1,
        due_ms: now_ms + pause_ms.unwrap_or(*wait),
    });
    true
}

/// Take the retries that are due out of the queue.
pub fn take_due_retries(st: &mut AlertState, now_ms: u64) -> Vec<Retry> {
    let (due, later): (Vec<Retry>, Vec<Retry>) = std::mem::take(&mut st.retries)
        .into_iter()
        .partition(|r| r.due_ms <= now_ms);
    st.retries = later;
    due
}

// ---------- doing it ----------

impl Channels {
    /// Make one delivery and say what happened.
    pub fn execute(
        &self,
        pl: &Planned,
        s: &Settings,
        chats: &[TelegramChat],
        a: &Alert,
        now_s: u64,
        attempt: u32,
    ) -> Delivery {
        let ctx = self.ctx();
        // the message as this recipient gets it: a one-time link made for this person, if any
        let notice = a.notice_for(pl.person.as_deref());
        let r = match &pl.target {
            Target::Sms(n) => super::sms::send(&ctx, &s.apps.sms, n, &notice),
            Target::Email(list) => self.email_to(s, list, a, pl.person.as_deref(), now_s),
            Target::Whatsapp(n) => super::chat::whatsapp(&ctx, &s.apps.whatsapp, n, &notice),
            Target::Push(dev) => match push_subject(s) {
                Some(sub) => super::push::send(&ctx, dev, &sub, a, &notice, now_s),
                None => Err(
                    "set a sender address under Email so push services can identify this fleet"
                        .into(),
                ),
            },
            Target::Telegram(id) => {
                let one: Vec<TelegramChat> =
                    chats.iter().filter(|c| c.id == *id).cloned().collect();
                self.telegram(&one, a)
            }
            Target::Fleet(c) => {
                let mut d = self.send_one(c, s, chats, a, now_s);
                d.channel = pl.channel.clone();
                d.person.clone_from(&pl.person);
                d.attempts = attempt;
                return d;
            }
        };
        let mut d = match r {
            Ok(x) => Delivery::new(&pl.channel, true, x),
            Err(x) => Delivery::new(&pl.channel, false, x),
        };
        d.person.clone_from(&pl.person);
        d.attempts = attempt;
        d
    }
}

/// How long all the deliveries of one alert may take together. Each runs on its own thread, so a slow one delays none of
/// the others, and a delivery that is still running at this point (a name lookup or an HTTP call that never answers) is
/// reported as failed and retried, its thread left to finish on its own.
pub const DELIVERY_BOUND: Duration = Duration::from_secs(25);
/// At most this many deliveries of one alert run at the same time.
const MAX_PARALLEL: usize = 8;

impl Channels {
    /// Make a set of deliveries side by side and return each one's outcome, in the order given.
    pub fn execute_all(
        &self,
        items: &[(Planned, u32)],
        s: &Settings,
        chats: &[TelegramChat],
        a: &Alert,
        now_s: u64,
        bound: Duration,
    ) -> Vec<(Planned, Delivery)> {
        self.execute_each(items, s, chats, a, now_s, bound, |_, _| {})
    }

    /// Like [`Channels::execute_all`], and `done(index, delivery)` is called as each delivery finishes (or is given up
    /// on at the deadline), so a caller can show progress while the slowest channel is still running.
    #[allow(clippy::too_many_arguments)]
    pub fn execute_each(
        &self,
        items: &[(Planned, u32)],
        s: &Settings,
        chats: &[TelegramChat],
        a: &Alert,
        now_s: u64,
        bound: Duration,
        mut done: impl FnMut(usize, &Delivery),
    ) -> Vec<(Planned, Delivery)> {
        let deadline = Instant::now() + bound;
        let mut out = Vec::with_capacity(items.len());
        for (batch_no, batch) in items.chunks(MAX_PARALLEL).enumerate() {
            let base = batch_no * MAX_PARALLEL;
            let (tx, rx) = mpsc::channel::<(usize, Delivery)>();
            let mut spawned = vec![false; batch.len()];
            for (i, (pl, at)) in batch.iter().enumerate() {
                let (ch, pl, at, s, chats, a, tx) = (
                    self.clone(),
                    pl.clone(),
                    *at,
                    s.clone(),
                    chats.to_vec(),
                    a.clone(),
                    tx.clone(),
                );
                spawned[i] = std::thread::Builder::new()
                    .name("ozbox-delivery".into())
                    .spawn(move || {
                        let d = ch.execute(&pl, &s, &chats, &a, now_s, at);
                        let _ = tx.send((i, d));
                    })
                    .is_ok();
            }
            drop(tx);
            let mut got: Vec<Option<Delivery>> = vec![None; batch.len()];
            let want = spawned.iter().filter(|x| **x).count();
            let mut have = 0;
            while have < want {
                let left = deadline.saturating_duration_since(Instant::now());
                match rx.recv_timeout(left) {
                    Ok((i, d)) => {
                        done(base + i, &d);
                        got[i] = Some(d);
                        have += 1;
                    }
                    Err(_) => break,
                }
            }
            for (i, (pl, at)) in batch.iter().enumerate() {
                let reported = got[i].is_some();
                let d = got[i].take().unwrap_or_else(|| {
                    let why = if spawned[i] {
                        "the delivery took too long (try again)"
                    } else {
                        "the delivery could not be started (try again)"
                    };
                    let mut d = Delivery::new(&pl.channel, false, why);
                    d.person.clone_from(&pl.person);
                    d.attempts = *at;
                    d
                });
                if !reported {
                    done(base + i, &d);
                }
                out.push((pl.clone(), d));
            }
        }
        out
    }
}

/// The contact a push service wants in the signed token: the sender address.
pub fn push_subject(s: &Settings) -> Option<String> {
    if !s.apps.email.from.is_empty() {
        return Some(format!("mailto:{}", s.apps.email.from));
    }
    s.routing
        .people
        .values()
        .find_map(|p| p.emails.first())
        .map(|e| format!("mailto:{e}"))
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use crate::notify_config::{PersonRouting, PushDevice};

    // Sunday 2026-11-08 12:00 UTC.
    const NOON: u64 = 1_794_139_200_000;
    const H: u64 = 3_600_000;

    fn alert(sev: Severity, key: &str) -> Alert {
        Alert {
            notice: None,
            reach: Default::default(),
            key: key.into(),
            kind: "x".into(),
            severity: sev,
            box_name: None,
            title: format!("Title {key}"),
            body: "body".into(),
            ts_ms: NOON,
        }
    }

    fn fleet() -> Settings {
        let mut s = Settings::default();
        s.locale.time_zone = Some("Africa/Lagos".into());
        s.apps.sms.enabled = true;
        s.apps.sms.from = "+15005550006".into();
        s.apps.telegram.enabled = true;
        s.apps.slack.enabled = true;
        s.apps.push.enabled = true;
        s.apps.email.enabled = true;
        s.apps.email.from = "alerts@example.com".into();
        s.budget.quiet_from = "22:00".into();
        s.budget.quiet_to = "07:00".into();
        let p = PersonRouting {
            phone: Some("+2348012345678".into()),
            emails: vec!["ada@example.com".into()],
            push: vec![PushDevice {
                id: "d1".into(),
                label: "Phone".into(),
                host: "fcm.googleapis.com".into(),
            }],
            ..PersonRouting::default()
        };
        s.routing.people.insert("ada".into(), p);
        s
    }

    fn chats() -> Vec<TelegramChat> {
        vec![TelegramChat {
            id: 7,
            name: "Ada".into(),
            person: None,
        }]
    }

    fn channels(p: &Plan) -> Vec<String> {
        p.send.iter().map(|x| x.channel.clone()).collect()
    }

    #[test]
    fn with_no_one_listed_every_enabled_fleet_channel_gets_every_alert() {
        let mut s = fleet();
        s.routing.people.clear();
        let mut st = AlertState::default();
        let p = plan(&s, &chats(), &alert(Severity::Normal, "a"), &mut st, NOON);
        assert_eq!(channels(&p), ["email", "telegram", "slack"]);
        assert!(p.send.iter().all(|x| x.person.is_none()));
    }

    #[test]
    fn the_defaults_send_urgent_to_sms_telegram_and_push_and_normal_to_telegram_and_slack() {
        let s = fleet();
        let mut st = AlertState::default();
        let u = plan(&s, &chats(), &alert(Severity::Urgent, "u"), &mut st, NOON);
        assert_eq!(channels(&u), ["sms", "telegram", "push"]);
        let n = plan(&s, &chats(), &alert(Severity::Normal, "n"), &mut st, NOON);
        assert_eq!(channels(&n), ["telegram", "slack"]);
        assert!(u.send.iter().all(|x| x.person.as_deref() == Some("ada")));
    }

    #[test]
    fn a_persons_rule_for_schedule_alerts_picks_the_route_or_turns_them_off() {
        let mut a = alert(Severity::Normal, "s");
        a.kind = "schedule".into();
        let fresh = AlertState::default;
        // no rule: the alert's own severity (normal) decides
        let s = fleet();
        assert_eq!(
            channels(&plan(&s, &chats(), &a, &mut fresh(), NOON)),
            ["telegram", "slack"]
        );
        // a rule that schedule alerts are urgent for this person sends them by the urgent route
        let mut s = fleet();
        s.routing
            .people
            .get_mut("ada")
            .unwrap()
            .kind_routes
            .insert("schedule".into(), "urgent".into());
        assert_eq!(
            channels(&plan(&s, &chats(), &a, &mut fresh(), NOON)),
            ["sms", "telegram", "push"]
        );
        // other kinds are not affected
        let mut other = alert(Severity::Normal, "o");
        other.kind = "disk".into();
        assert_eq!(
            channels(&plan(&s, &chats(), &other, &mut fresh(), NOON)),
            ["telegram", "slack"]
        );
        // off: this person is not told, and the plan says why
        s.routing
            .people
            .get_mut("ada")
            .unwrap()
            .kind_routes
            .insert("schedule".into(), "off".into());
        let p = plan(&s, &chats(), &a, &mut fresh(), NOON);
        assert!(p.send.is_empty() && p.skipped[0].detail.contains("turned off"));
        // a rule for a kind that has no rule option, or a choice that does not exist, is refused when saved
        let mut bad = fleet();
        bad.routing
            .people
            .get_mut("ada")
            .unwrap()
            .kind_routes
            .insert("disk".into(), "off".into());
        assert!(bad.validate().is_err());
        let mut bad = fleet();
        bad.routing
            .people
            .get_mut("ada")
            .unwrap()
            .kind_routes
            .insert("schedule".into(), "loud".into());
        assert!(bad.validate().is_err());
    }

    #[test]
    fn quiet_hours_follow_the_persons_own_time_zone_and_urgent_may_break_through() {
        let s = fleet();
        // 01:00 UTC is 02:00 in Lagos (UTC+1): quiet. 12:00 UTC is 13:00: not.
        let night = NOON + 13 * H;
        let mut st = AlertState::default();
        let n = plan(&s, &chats(), &alert(Severity::Normal, "n"), &mut st, night);
        assert!(n.send.is_empty());
        assert!(n.skipped[0].detail.contains("quiet hours") && n.skipped[0].ok);
        assert_eq!(
            st.digests["ada"].items.len(),
            1,
            "held for the daily summary"
        );
        let u = plan(&s, &chats(), &alert(Severity::Urgent, "u"), &mut st, night);
        assert_eq!(channels(&u), ["sms", "telegram", "push"]);
        // Without the bypass an urgent alert is held too.
        let mut s2 = s.clone();
        s2.routing
            .people
            .get_mut("ada")
            .unwrap()
            .urgent
            .bypass_quiet = false;
        let u2 = plan(
            &s2,
            &chats(),
            &alert(Severity::Urgent, "u2"),
            &mut st,
            night,
        );
        assert!(u2.send.is_empty());
        // A person in another zone is not quiet at the same instant: 01:00 UTC is 20:00 in New York.
        let mut s3 = s.clone();
        s3.routing.people.get_mut("ada").unwrap().time_zone = Some("America/New_York".into());
        let n3 = plan(
            &s3,
            &chats(),
            &alert(Severity::Normal, "n3"),
            &mut st,
            night,
        );
        assert_eq!(channels(&n3), ["telegram", "slack"]);
    }

    #[test]
    fn a_person_with_their_own_quiet_hours_uses_them() {
        let mut s = fleet();
        let p = s.routing.people.get_mut("ada").unwrap();
        p.quiet_from = Some("12:00".into());
        p.quiet_to = Some("14:00".into());
        let mut st = AlertState::default();
        // 12:00 UTC = 13:00 Lagos, inside 12:00-14:00.
        assert!(
            plan(&s, &chats(), &alert(Severity::Normal, "n"), &mut st, NOON)
                .send
                .is_empty()
        );
    }

    #[test]
    fn the_same_place_is_told_once_even_when_two_people_route_to_it() {
        let mut s = fleet();
        let mut b = s.routing.people["ada"].clone();
        b.phone = Some("+2348099999999".into());
        s.routing.people.insert("bo".into(), b);
        let mut st = AlertState::default();
        let p = plan(&s, &chats(), &alert(Severity::Urgent, "u"), &mut st, NOON);
        let telegram = p.send.iter().filter(|x| x.channel == "telegram").count();
        assert_eq!(telegram, 1, "one chat, two routes");
        assert_eq!(
            p.send.iter().filter(|x| x.channel == "sms").count(),
            2,
            "two numbers"
        );
        // The same alert key a minute later (the engine re-fired) goes nowhere new.
        let again = plan(
            &s,
            &chats(),
            &alert(Severity::Urgent, "u"),
            &mut st,
            NOON + 60_000,
        );
        assert!(again.send.is_empty());
        // A different alert is not deduped.
        assert!(!plan(
            &s,
            &chats(),
            &alert(Severity::Urgent, "v"),
            &mut st,
            NOON + 60_000
        )
        .send
        .is_empty());
    }

    #[test]
    fn a_channel_that_cannot_deliver_is_reported_not_silently_dropped() {
        let mut s = fleet();
        s.apps.sms.enabled = false;
        s.routing.people.get_mut("ada").unwrap().push.clear();
        let mut st = AlertState::default();
        let p = plan(&s, &[], &alert(Severity::Urgent, "u"), &mut st, NOON);
        assert!(p.send.is_empty());
        let why: Vec<&str> = p.skipped.iter().map(|d| d.detail.as_str()).collect();
        assert!(why.iter().any(|w| w.contains("SMS is not switched on")));
        assert!(why.iter().any(|w| w.contains("no chat is paired")));
        assert!(why.iter().any(|w| w.contains("no device")));
        assert!(p
            .skipped
            .iter()
            .all(|d| !d.ok && d.person.as_deref() == Some("ada")));
    }

    #[test]
    fn a_number_gets_at_most_six_texts_an_hour() {
        let s = fleet();
        let mut st = AlertState::default();
        let mut sent = 0;
        for i in 0..8 {
            let p = plan(
                &s,
                &chats(),
                &alert(Severity::Urgent, &format!("u{i}")),
                &mut st,
                NOON + i * 1000,
            );
            sent += p.send.iter().filter(|x| x.channel == "sms").count();
        }
        assert_eq!(sent, PER_RECIPIENT_PER_HOUR);
        // An hour later the allowance is back.
        let p = plan(
            &s,
            &chats(),
            &alert(Severity::Urgent, "late"),
            &mut st,
            NOON + H + 60_000,
        );
        assert_eq!(p.send.iter().filter(|x| x.channel == "sms").count(), 1);
        // The counter never holds the number itself.
        assert!(st.sms_sent.keys().all(|k| !k.contains("2348")));
    }

    #[test]
    fn a_failed_delivery_is_retried_with_backoff_up_to_four_tries_but_a_refusal_never() {
        let mut st = AlertState::default();
        let a = alert(Severity::Urgent, "u");
        let pl = Planned {
            person: None,
            channel: "sms".into(),
            target: Target::Sms("+2348012345678".into()),
        };
        let busy = Delivery::new("sms", false, "the service answered HTTP 503");
        assert!(schedule_retry(&mut st, &a, &pl, 1, &busy, NOON));
        assert_eq!(st.retries[0].due_ms, NOON + 60_000);
        assert_eq!(st.retries[0].attempt, 2);
        assert!(take_due_retries(&mut st, NOON + 59_000).is_empty());
        let due = take_due_retries(&mut st, NOON + 60_000);
        assert_eq!(due.len(), 1);
        assert!(st.retries.is_empty());
        assert!(schedule_retry(&mut st, &a, &pl, 2, &busy, NOON));
        assert_eq!(st.retries[0].due_ms, NOON + 300_000);
        st.retries.clear();
        assert!(schedule_retry(&mut st, &a, &pl, 3, &busy, NOON));
        assert_eq!(st.retries[0].due_ms, NOON + 900_000);
        st.retries.clear();
        assert!(
            !schedule_retry(&mut st, &a, &pl, 4, &busy, NOON),
            "the fourth try is the last"
        );
        assert!(!schedule_retry(
            &mut st,
            &a,
            &pl,
            1,
            &Delivery::new("sms", false, "Twilio refused the account id or the token"),
            NOON
        ));
        assert!(!schedule_retry(
            &mut st,
            &a,
            &pl,
            1,
            &Delivery::new("sms", true, "sent"),
            NOON
        ));
    }

    #[test]
    fn the_daily_summary_lands_at_the_chosen_local_time_on_both_sides_of_a_clock_change() {
        let mut s = fleet();
        s.locale.time_zone = Some("America/New_York".into());
        s.routing.people.get_mut("ada").unwrap().digest.time = "08:00".into();
        // The US clocks went forward at 02:00 on 2027-03-14: 07:00 UTC the day before is 02:00 EST, after is EDT.
        let before = 1_804_852_800_000_u64; // 2027-03-12 12:00 UTC
        let (h, m) = (8, 0);
        let first = crate::timezone::next_local_time("America/New_York", before, h, m).unwrap();
        let second = crate::timezone::next_local_time("America/New_York", first, h, m).unwrap();
        let third = crate::timezone::next_local_time("America/New_York", second, h, m).unwrap();
        let local = |t| crate::timezone::local_minutes("America/New_York", t).unwrap();
        assert_eq!((local(first), local(second), local(third)), (480, 480, 480));
        let gaps: Vec<u64> = vec![(second - first) / H, (third - second) / H];
        assert!(
            gaps.contains(&23),
            "the day of the change is 23 hours long: {gaps:?}"
        );
        // The plan: the first call only schedules; later one sends once and moves on.
        let mut st = AlertState::default();
        assert!(due_digests(&s, &chats(), &mut st, before).is_empty());
        let next = st.digests["ada"].next_ms;
        assert_eq!(next, first);
        st.digests.get_mut("ada").unwrap().items.push(DigestItem {
            ts_ms: before,
            urgent: true,
            title: "Disk full".into(),
            status: DigestStatus::Delivered,
        });
        assert!(due_digests(&s, &chats(), &mut st, next - 1).is_empty());
        let due = due_digests(&s, &chats(), &mut st, next + 1000);
        assert_eq!(due.len(), 1);
        let (alert, send, _) = &due[0];
        assert!(alert.title.contains("1 alert, 1 urgent") && alert.body.contains("Disk full"));
        assert_eq!(send[0].channel, "email");
        use crate::notify::Engine;
        // The summary is an alert like any other: it has an outcome, and it settles on what the channel did.
        let digest = alert.clone();
        assert_eq!(st.outcomes[&digest.key][0].status, DigestStatus::Delivered);
        let ok = vec![{
            let mut d = Delivery::new("email", true, "sent");
            d.person = Some("ada".into());
            d
        }];
        Engine::record(&mut st, &digest, ok);
        assert_eq!(st.recent[0].outcome, Some(DigestStatus::Delivered));
        assert_eq!(
            st.recent[0].outcomes[0].results[0].state,
            ChannelState::Sent
        );
        assert_eq!(st.digests["ada"].next_ms, second);
        assert!(st.digests["ada"].items.is_empty());
        // Nothing waiting: nothing is sent, and the next one is still scheduled.
        let empty = due_digests(&s, &chats(), &mut st, second + 1000);
        assert!(empty.is_empty());
        assert_eq!(st.digests["ada"].next_ms, third);
    }

    #[test]
    fn delivered_means_a_channel_took_it_and_the_last_try_has_the_last_word() {
        use crate::notify::Engine;
        let mk = |ch: &[&str]| AlertOutcome {
            person: Some("ada".into()),
            status: DigestStatus::Delivered,
            channels: ch.iter().map(|c| (*c).into()).collect(),
            results: Vec::new(),
        };
        let d = |ch: &str, ok: bool, why: &str, at: u32| {
            let mut d = Delivery::new(ch, ok, why);
            d.person = Some("ada".into());
            d.attempts = at;
            d
        };
        let busy = "the service answered HTTP 503";
        let a = alert(Severity::Normal, "k");
        // A failed first try is retrying, not delivered; the retry then succeeds.
        let mut st = AlertState::default();
        st.outcomes.insert("k".into(), vec![mk(&["sms"])]);
        Engine::record(&mut st, &a, vec![d("sms", false, busy, 1)]);
        assert_eq!(st.recent[0].outcome, Some(DigestStatus::Retrying));
        Engine::append(&mut st, &a, vec![d("sms", true, "sent", 2)]);
        assert_eq!(st.recent[0].outcome, Some(DigestStatus::Delivered));
        assert_eq!(st.recent[0].outcomes[0].results[0].attempts, 2);
        // Four failures: failed, with the reason, and no further retry.
        let mut st = AlertState::default();
        st.outcomes.insert("k".into(), vec![mk(&["sms"])]);
        Engine::record(&mut st, &a, vec![d("sms", false, busy, 1)]);
        for at in 2..=4 {
            Engine::append(&mut st, &a, vec![d("sms", false, busy, at)]);
        }
        let r = &st.recent[0].outcomes[0].results[0];
        assert_eq!(st.recent[0].outcome, Some(DigestStatus::Failed));
        assert_eq!(
            (r.state, r.attempts, r.detail.as_str()),
            (ChannelState::Failed, 4, busy)
        );
        // A refusal is final at once.
        let mut st = AlertState::default();
        st.outcomes.insert("k".into(), vec![mk(&["sms"])]);
        Engine::record(
            &mut st,
            &a,
            vec![d(
                "sms",
                false,
                "Twilio refused the account id or the token",
                1,
            )],
        );
        assert_eq!(
            st.recent[0].outcomes[0].results[0].state,
            ChannelState::Refused
        );
        assert_eq!(st.recent[0].outcome, Some(DigestStatus::Failed));
        // One channel taking it is enough for the person; the other's failure stays in the results.
        let mut st = AlertState::default();
        st.outcomes.insert("k".into(), vec![mk(&["sms", "push"])]);
        Engine::record(
            &mut st,
            &a,
            vec![d("sms", true, "sent", 1), d("push", false, busy, 1)],
        );
        assert_eq!(st.recent[0].outcome, Some(DigestStatus::Delivered));
        assert_eq!(
            st.recent[0].outcomes[0].results[1].state,
            ChannelState::Retrying
        );
        // Two people, one reached and one not: partial. A held person does not count against it.
        let mut st = AlertState::default();
        let mut bo = mk(&["sms"]);
        bo.person = Some("bo".into());
        let held = AlertOutcome {
            person: Some("cy".into()),
            status: DigestStatus::HeldQuiet,
            channels: vec!["sms".into()],
            results: Vec::new(),
        };
        st.outcomes.insert("k".into(), vec![mk(&["sms"]), bo, held]);
        let mut bo_fail = d(
            "sms",
            false,
            "Twilio refused the account id or the token",
            1,
        );
        bo_fail.person = Some("bo".into());
        Engine::record(&mut st, &a, vec![d("sms", true, "sent", 1), bo_fail]);
        assert_eq!(st.recent[0].outcome, Some(DigestStatus::Partial));
        // An alert recorded before results were kept is left as it was.
        let old: AlertOutcome =
            serde_json::from_str(r#"{"person":"ada","status":"delivered","channels":["sms"]}"#)
                .unwrap();
        assert!(old.results.is_empty() && old.status == DigestStatus::Delivered);
    }

    #[test]
    fn a_test_send_resolves_one_channel_for_one_person() {
        let s = fleet();
        let t = test_plan(&s, &chats(), Some("ada"), "sms").unwrap();
        assert_eq!(t[0].target, Target::Sms("+2348012345678".into()));
        assert!(test_plan(&s, &chats(), Some("ada"), "whatsapp").is_err());
        let mut none = fleet();
        none.routing.people.clear();
        assert_eq!(
            test_plan(&none, &chats(), None, "slack").unwrap()[0].target,
            Target::Fleet("slack".into())
        );
        assert!(test_plan(&none, &chats(), None, "sms").is_err());
    }

    fn two_chats() -> Vec<TelegramChat> {
        vec![
            TelegramChat {
                id: 7,
                name: "Ada".into(),
                person: Some("ada".into()),
            },
            TelegramChat {
                id: 8,
                name: "Bo".into(),
                person: Some("bo".into()),
            },
            TelegramChat {
                id: 9,
                name: "Desk".into(),
                person: None,
            },
        ]
    }

    fn telegram_ids(s: &Settings, chats: &[TelegramChat], who: &str) -> Vec<i64> {
        let p = &s.routing.people[who];
        resolve(s, chats, who, p, "telegram")
            .unwrap()
            .into_iter()
            .map(|x| match x.target {
                Target::Telegram(id) => id,
                _ => 0,
            })
            .collect()
    }

    #[test]
    fn a_persons_telegram_alerts_go_only_to_their_own_chats() {
        let mut s = fleet();
        let b = s.routing.people["ada"].clone();
        s.routing.people.insert("bo".into(), b);
        let c = two_chats();
        assert_eq!(telegram_ids(&s, &c, "ada"), [7]);
        assert_eq!(telegram_ids(&s, &c, "bo"), [8]);
        // A person with no linked chat gets only the chats nobody has claimed, never someone else's.
        s.routing
            .people
            .insert("cy".into(), s.routing.people["ada"].clone());
        assert_eq!(telegram_ids(&s, &c, "cy"), [9]);
        // With every chat claimed, they are told so instead of reaching a stranger.
        let claimed = &c[..2];
        let p = &s.routing.people["cy"];
        assert_eq!(
            resolve(&s, claimed, "cy", p, "telegram").unwrap_err(),
            "no Telegram chat is linked to this person"
        );
        // A chat linked to a person who no longer has routing counts as unclaimed.
        s.routing.people.remove("bo");
        assert_eq!(telegram_ids(&s, &c, "cy"), [8, 9]);
        // Through the whole plan: an urgent alert reaches Ada's chat and no other.
        let mut st = AlertState::default();
        let mut s2 = fleet();
        s2.routing
            .people
            .insert("bo".into(), s2.routing.people["ada"].clone());
        let p = plan(&s2, &c, &alert(Severity::Urgent, "u"), &mut st, NOON);
        let tg: Vec<&Target> = p
            .send
            .iter()
            .filter(|x| x.channel == "telegram")
            .map(|x| &x.target)
            .collect();
        assert_eq!(tg, [&Target::Telegram(7), &Target::Telegram(8)]);
    }

    #[test]
    fn with_no_one_listed_every_chat_still_gets_every_alert_whoever_it_is_linked_to() {
        let mut s = fleet();
        s.routing.people.clear();
        let mut st = AlertState::default();
        let c = two_chats();
        let p = plan(&s, &c, &alert(Severity::Normal, "a"), &mut st, NOON);
        assert!(p.send.iter().any(|x| x.channel == "telegram"));
        // The fleet-wide send uses every chat (see `Channels::telegram`), so nothing here narrows it.
        assert!(p
            .send
            .iter()
            .all(|x| x.target == Target::Fleet(x.channel.clone())));
    }

    fn ada_with_summary(s: &mut Settings) {
        s.routing.people.get_mut("ada").unwrap().digest.enabled = true;
    }

    fn statuses(st: &AlertState) -> Vec<DigestStatus> {
        st.digests["ada"].items.iter().map(|i| i.status).collect()
    }

    #[test]
    fn the_daily_summary_says_for_each_alert_whether_it_was_delivered_or_held() {
        let mut s = fleet();
        ada_with_summary(&mut s);
        let mut st = AlertState::default();
        // Delivered: in the daytime, to her channels.
        plan(&s, &chats(), &alert(Severity::Normal, "day"), &mut st, NOON);
        // Held: 01:00 UTC is 02:00 in Lagos, quiet hours.
        let night = NOON + 13 * H;
        plan(
            &s,
            &chats(),
            &alert(Severity::Normal, "night"),
            &mut st,
            night,
        );
        // Not sent: nothing of hers can take it.
        let mut none = s.clone();
        none.routing.people.get_mut("ada").unwrap().normal.channels = vec!["sms".into()];
        none.routing.people.get_mut("ada").unwrap().phone = None;
        plan(
            &none,
            &chats(),
            &alert(Severity::Normal, "nowhere"),
            &mut st,
            NOON + 2 * H,
        );
        // Held by the text limit: she has had the most texts allowed in an hour.
        let mut texts = s.clone();
        texts.routing.people.get_mut("ada").unwrap().normal.channels = vec!["sms".into()];
        for i in 0..=PER_RECIPIENT_PER_HOUR {
            plan(
                &texts,
                &chats(),
                &alert(Severity::Normal, &format!("t{i}")),
                &mut st,
                NOON + 3 * H + i as u64,
            );
        }
        let got = statuses(&st);
        assert_eq!(got[0], DigestStatus::Delivered);
        assert_eq!(got[1], DigestStatus::HeldQuiet);
        assert_eq!(got[2], DigestStatus::NotSent);
        assert_eq!(*got.last().unwrap(), DigestStatus::HeldLimit);
        assert_eq!(got[3], DigestStatus::Delivered);
        // The summary text carries it per item and counts what was not delivered.
        let alert = digest_alert("ada", &st.digests["ada"].items, NOON + 24 * H).unwrap();
        assert!(
            alert.body.contains("- [delivered] Title day"),
            "{}",
            alert.body
        );
        assert!(alert.body.contains("- [held: quiet hours] Title night"));
        assert!(alert.body.contains("- [not sent] Title nowhere"));
        assert!(alert.body.contains("- [held: text limit] Title t6"));
        assert!(alert.title.contains("held or not sent"), "{}", alert.title);
        // An item kept before the status existed is listed as it always was.
        let old = [DigestItem {
            ts_ms: 1,
            urgent: false,
            title: "Old".into(),
            status: DigestStatus::Unrecorded,
        }];
        assert_eq!(digest_alert("ada", &old, 2).unwrap().body, "- Old");
        let json = serde_json::to_string(&old[0]).unwrap();
        assert!(!json.contains("status"));
        let back: DigestItem = serde_json::from_str(r#"{"ts_ms":1,"title":"x"}"#).unwrap();
        assert_eq!(back.status, DigestStatus::Unrecorded);
    }

    #[test]
    fn an_alert_the_hourly_limit_refused_is_in_the_summary_as_not_sent() {
        let mut s = fleet();
        ada_with_summary(&mut s);
        let mut st = AlertState::default();
        note_dropped(&s, &mut st, &[alert(Severity::Normal, "flood")]);
        assert_eq!(statuses(&st), [DigestStatus::NotSent]);
    }

    /// An HTTP client whose answer to one address takes a long time.
    struct Sluggish {
        slow: Duration,
    }

    impl crate::netguard::HttpClient for Sluggish {
        fn send(
            &self,
            req: &crate::netguard::HttpRequest,
        ) -> Result<crate::netguard::HttpResponse, crate::netguard::HttpError> {
            if req.url.contains("slow") {
                std::thread::sleep(self.slow);
            }
            Ok(crate::netguard::HttpResponse {
                status: 200,
                body: "{}".into(),
            })
        }
    }

    fn sluggish(slow: Duration) -> Channels {
        let secrets = std::sync::Arc::new(crate::secrets::MemorySecrets::default());
        use crate::secrets::SecretStore;
        secrets
            .set("slack-webhook-url", "https://hooks.example.com/slow")
            .unwrap();
        secrets
            .set("discord-webhook-url", "https://hooks.example.com/fast")
            .unwrap();
        Channels {
            secrets,
            http: std::sync::Arc::new(Sluggish { slow }),
            runner: std::sync::Arc::new(ozbox_core::RecordingRunner::new()),
            aws_profile: None,
        }
    }

    fn fleet_item(c: &str) -> (Planned, u32) {
        (
            Planned {
                person: None,
                channel: c.into(),
                target: Target::Fleet(c.into()),
            },
            1,
        )
    }

    #[test]
    fn one_slow_delivery_does_not_delay_the_others_of_the_same_alert() {
        let c = sluggish(Duration::from_millis(1500));
        let items = [fleet_item("slack"), fleet_item("discord")];
        // The bound is longer than the slow answer: everyone is delivered, and the whole set takes the slowest, not the sum.
        let started = Instant::now();
        let r = c.execute_all(
            &items,
            &Settings::default(),
            &[],
            &alert(Severity::Normal, "a"),
            1,
            Duration::from_secs(10),
        );
        assert!(r.iter().all(|(_, d)| d.ok), "{r:?}");
        assert!(started.elapsed() < Duration::from_millis(2800));
        // The bound is shorter: the slow one is reported as too slow and gets the normal retry; the fast one was done at once.
        let started = Instant::now();
        let r = c.execute_all(
            &items,
            &Settings::default(),
            &[],
            &alert(Severity::Normal, "a"),
            1,
            Duration::from_millis(300),
        );
        assert!(started.elapsed() < Duration::from_millis(1200));
        assert_eq!(r[0].0.channel, "slack");
        assert!(!r[0].1.ok);
        assert_eq!(r[0].1.detail, "the delivery took too long (try again)");
        assert!(r[1].1.ok, "the fast channel was not held up");
        let mut st = AlertState::default();
        assert!(schedule_retry(
            &mut st,
            &alert(Severity::Normal, "a"),
            &r[0].0,
            1,
            &r[0].1,
            NOON
        ));
    }
    #[test]
    fn a_recorded_alert_keeps_what_was_decided_for_each_person_and_where() {
        use crate::notify::Engine;
        let s = fleet();
        let mut st = AlertState::default();
        let day = alert(Severity::Normal, "day");
        let p = plan(&s, &chats(), &day, &mut st, NOON);
        Engine::record(&mut st, &day, Vec::new());
        let night = alert(Severity::Normal, "night");
        plan(&s, &chats(), &night, &mut st, NOON + 13 * H);
        Engine::record(&mut st, &night, Vec::new());
        let nowhere = alert(Severity::Normal, "nowhere");
        let mut none = s.clone();
        none.routing.people.get_mut("ada").unwrap().normal.channels = vec!["sms".into()];
        none.routing.people.get_mut("ada").unwrap().phone = None;
        plan(&none, &chats(), &nowhere, &mut st, NOON + 2 * H);
        Engine::record(&mut st, &nowhere, Vec::new());
        // Refused by the fleet's hourly limit: no person, no channel.
        let limited = alert(Severity::Normal, "limit");
        note_dropped(&s, &mut st, std::slice::from_ref(&limited));
        Engine::record(&mut st, &limited, Vec::new());

        let plain = alert(Severity::Normal, "plain");
        Engine::record(&mut st, &plain, Vec::new());
        let by_key = |k: &str| st.recent.iter().find(|r| r.key == k).unwrap();
        let d = by_key("day");
        assert_eq!(d.outcome, Some(DigestStatus::Delivered));
        assert_eq!(d.outcomes[0].person.as_deref(), Some("ada"));
        assert!(
            d.outcomes[0].channels.iter().any(|c| c == "slack"),
            "{:?}",
            d.outcomes
        );
        assert!(!p.send.is_empty());
        let n = by_key("night");
        assert_eq!(n.outcome, Some(DigestStatus::HeldQuiet));
        assert!(!n.outcomes[0].channels.is_empty());
        assert_eq!(by_key("nowhere").outcome, Some(DigestStatus::NotSent));
        let l = by_key("limit");
        assert_eq!(l.outcome, Some(DigestStatus::NotSent));
        assert_eq!(l.outcomes[0].person.as_deref(), Some("ada"));
        // Nothing planned: nothing is invented, and the kept list is emptied by recording.
        assert_eq!(by_key("plain").outcome, None);
        assert!(st.outcomes.is_empty());
        // An alert recorded before outcomes existed still reads, and writes no field for them.
        let old: crate::notify::RecentAlert = serde_json::from_str(
            r#"{"ts_ms":1,"key":"k","kind":"x","severity":"normal","box_name":null,"title":"t","body":"b","deliveries":[]}"#,
        )
        .unwrap();
        assert!(old.outcomes.is_empty() && old.outcome.is_none());
        let json = serde_json::to_value(&old).unwrap();
        assert!(json.get("outcome").is_none() && json.get("outcomes").is_none());
    }
}
