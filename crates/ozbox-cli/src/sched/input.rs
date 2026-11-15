//! What a person (or the API, or the CLI) may say when making or changing a schedule or a trigger, and how it lands on
//! the stored shape. One place, so the dashboard and the command line accept and refuse the same things.

use serde::Deserialize;

use super::engine::new_id;
use super::model::*;
use super::view::{self, PreviewIn};

#[derive(Deserialize, Default, Clone)]
#[serde(default)]
pub struct ScheduleIn {
    pub name: Option<String>,
    /// "every weekday at 9am Lagos time".
    pub when_text: Option<String>,
    pub cron: Option<String>,
    pub every_minutes: Option<u32>,
    pub time_zone: Option<String>,
    pub owner: Option<String>,
    pub engine: Option<String>,
    pub prompt: Option<String>,
    pub skill: Option<String>,
    pub target: Option<Target>,
    pub caps: Option<Caps>,
    pub results_to: Option<Vec<String>>,
    pub catch_up_minutes: Option<u32>,
    pub enabled: Option<bool>,
    pub heartbeat: Option<bool>,
}

#[derive(Deserialize, Default, Clone)]
#[serde(default)]
pub struct TriggerIn {
    pub name: Option<String>,
    pub scheme: Option<Scheme>,
    pub engine: Option<String>,
    pub template: Option<String>,
    pub skill: Option<String>,
    pub target: Option<Target>,
    pub caps: Option<Caps>,
    pub results_to: Option<Vec<String>>,
    pub events: Option<Vec<String>>,
    pub owner: Option<String>,
    pub enabled: Option<bool>,
}

pub fn new_schedule(now: u64) -> Schedule {
    Schedule {
        id: new_id("sch"),
        created_ms: now,
        updated_ms: now,
        ..Default::default()
    }
}

/// Lay `i` over `s`. `owner_zone` is the owner's time zone, used when nothing else names one. `is_new` makes a
/// heartbeat start switched off.
pub fn apply_schedule(
    s: &mut Schedule,
    i: ScheduleIn,
    owner_zone: &str,
    is_new: bool,
    now: u64,
) -> Result<(), Invalid> {
    if let Some(v) = i.name {
        s.name = v;
    }
    if let Some(v) = i.owner {
        s.owner = v;
    }
    if let Some(v) = i.engine {
        s.engine = super::model::current_engine(&v);
    }
    if let Some(v) = i.prompt {
        s.prompt = Some(v);
    }
    if let Some(v) = i.skill {
        s.skill = Some(v);
    }
    if let Some(v) = i.target {
        s.target = v;
    }
    if let Some(v) = i.caps {
        s.caps = v;
    }
    if let Some(v) = i.results_to {
        s.results_to = v;
    }
    if let Some(v) = i.catch_up_minutes {
        s.catch_up_minutes = v;
    }
    if let Some(h) = i.heartbeat {
        s.heartbeat = h;
    }
    // A heartbeat is off until a person turns it on.
    s.enabled = match i.enabled {
        Some(e) => e,
        None if is_new && s.heartbeat => false,
        None => s.enabled,
    };
    if let Some(m) = i.every_minutes {
        s.when = When::Every { minutes: m };
        s.plain = None;
        s.time_zone = i
            .time_zone
            .clone()
            .unwrap_or_else(|| owner_zone.to_string());
    } else if i.when_text.is_some() || i.cron.is_some() {
        let zone_default = i
            .time_zone
            .clone()
            .unwrap_or_else(|| owner_zone.to_string());
        let p = view::preview(
            &PreviewIn {
                text: i.when_text.as_deref(),
                cron: i.cron.as_deref(),
                time_zone: &zone_default,
                count: 1,
            },
            now,
        )?;
        s.when = When::Cron {
            expr: p["cron"].as_str().unwrap_or_default().to_string(),
        };
        s.plain = i.when_text.filter(|t| !t.trim().is_empty());
        s.time_zone = p["time_zone"].as_str().unwrap_or("UTC").to_string();
    } else if let Some(z) = i.time_zone {
        s.time_zone = z;
    } else if is_new {
        s.time_zone = owner_zone.to_string();
    }
    s.validate()
}

pub fn build_trigger(i: TriggerIn, now: u64) -> Result<Trigger, Invalid> {
    let t = Trigger {
        id: new_id("trg"),
        name: i.name.unwrap_or_default(),
        scheme: i.scheme.unwrap_or(Scheme::Github),
        engine: i
            .engine
            .map(|e| super::model::current_engine(&e))
            .unwrap_or_else(|| super::model::DEFAULT_ENGINE.into()),
        template: i.template.unwrap_or_default(),
        skill: i.skill,
        target: i.target.unwrap_or_default(),
        caps: i.caps.unwrap_or_default(),
        results_to: i.results_to.unwrap_or_default(),
        events: i.events.unwrap_or_default(),
        enabled: i.enabled.unwrap_or(true),
        owner: i.owner.unwrap_or_default(),
        created_ms: now,
        previous_secret_until_ms: None,
    };
    t.validate()?;
    Ok(t)
}

/// A new random secret for a trigger: 48 hex characters.
pub fn new_secret() -> Option<String> {
    let mut raw = [0u8; 24];
    getrandom::getrandom(&mut raw).ok()?;
    Some(raw.iter().map(|b| format!("{b:02x}")).collect())
}
