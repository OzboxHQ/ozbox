//! The JSON the API and `--json` give for schedules, triggers and previews. Fields are only ever added.

use serde_json::{json, Value};

use super::cron::Cron;
use super::engine;
use super::model::*;
use super::plain;
use crate::timezone;

/// What the cost estimate needs from the fleet.
#[derive(Debug, Clone, PartialEq)]
pub struct CostInputs {
    pub hourly: f64,
    pub currency: Option<String>,
    pub auto_pause_minutes: u32,
}

pub fn when_json(ms: u64, zone: &str) -> Value {
    json!({
        "ms": ms,
        "local": timezone::format_with_utc(zone, ms).unwrap_or_default(),
        "utc": crate::state::format_rfc3339(ms),
    })
}

/// The next `n` runs, each as local time with UTC beside it.
pub fn next_runs(s: &Schedule, st: &SchedState, now_ms: u64, n: usize) -> Vec<Value> {
    let mut out = Vec::new();
    let mut at = now_ms;
    while out.len() < n {
        match engine::next_after(s, st, at) {
            Some(f) => {
                out.push(when_json(f, &s.time_zone));
                at = f;
            }
            None => break,
        }
    }
    out
}

fn runs_in_30_days(s: &Schedule, st: &SchedState, now_ms: u64) -> u64 {
    const CAP: u64 = 3000;
    let end = now_ms + 30 * 86_400_000;
    let mut at = now_ms;
    let mut n = 0;
    while n < CAP {
        match engine::next_after(s, st, at) {
            Some(f) if f <= end => {
                n += 1;
                at = f;
            }
            _ => return n,
        }
    }
    // Too many to count one by one: extrapolate from the span the first CAP covered.
    let span = at.saturating_sub(now_ms).max(1);
    CAP * (30 * 86_400_000) / span
}

/// What a schedule costs if every run wakes a paused box that its own auto-pause then puts back to sleep.
pub fn cost(s: &Schedule, st: &SchedState, doc: &Doc, now_ms: u64, inp: &CostInputs) -> Value {
    let finished: Vec<f64> = doc
        .runs
        .iter()
        .rev()
        .filter(|r| {
            r.owner_id == s.id && r.finished_ms.is_some() && r.status == RunStatus::Succeeded
        })
        .take(10)
        .map(|r| {
            r.finished_ms
                .unwrap_or(r.started_ms)
                .saturating_sub(r.started_ms) as f64
                / 60_000.0
        })
        .collect();
    let avg = if finished.is_empty() {
        5.0
    } else {
        finished.iter().sum::<f64>() / finished.len() as f64
    };
    let per_run = inp.hourly * (avg + f64::from(inp.auto_pause_minutes)) / 60.0;
    let runs = runs_in_30_days(s, st, now_ms);
    let per_month = (per_run * runs as f64).min(inp.hourly * 730.0);
    json!({
        "currency": inp.currency,
        "per_run": per_run,
        "per_month": per_month,
        "runs_per_month": runs,
        "avg_run_minutes": avg,
        "auto_pause_minutes": inp.auto_pause_minutes,
        "assumes": "wakes_paused_box",
        "estimate": true,
    })
}

pub fn schedule(s: &Schedule, doc: &Doc, now_ms: u64, inp: Option<&CostInputs>) -> Value {
    let st = doc.state.get(&s.id).cloned().unwrap_or(SchedState {
        armed_ms: now_ms,
        ..Default::default()
    });
    let last = doc.runs.iter().rev().find(|r| r.owner_id == s.id);
    let next = if s.enabled {
        engine::next_after(s, &st, now_ms).map(|m| when_json(m, &s.time_zone))
    } else {
        None
    };
    let mut v = serde_json::to_value(s).unwrap_or(Value::Null);
    if let Value::Object(m) = &mut v {
        m.insert("next".into(), next.unwrap_or(Value::Null));
        m.insert(
            "last_run".into(),
            last.map_or(Value::Null, |r| {
                serde_json::to_value(r).unwrap_or(Value::Null)
            }),
        );
        m.insert("running".into(), json!(st.running.is_some()));
        m.insert(
            "cost".into(),
            inp.map_or(Value::Null, |i| cost(s, &st, doc, now_ms, i)),
        );
    }
    v
}

pub struct PreviewIn<'a> {
    pub text: Option<&'a str>,
    pub cron: Option<&'a str>,
    pub time_zone: &'a str,
    pub count: usize,
}

/// Turn plain words (or raw cron) into cron and show the next runs, before anything is saved.
pub fn preview(inp: &PreviewIn<'_>, now_ms: u64) -> Result<Value, (&'static str, String)> {
    let (expr, zone_from_text) = match (inp.text.map(str::trim).filter(|t| !t.is_empty()), inp.cron)
    {
        (Some(t), _) => match plain::parse(t) {
            Ok(p) => (p.cron, p.zone),
            Err(e) => {
                // Someone who typed raw cron into the sentence box still gets it.
                if Cron::parse(t).is_ok() {
                    (t.to_string(), None)
                } else {
                    return Err((e.key, e.detail));
                }
            }
        },
        (None, Some(c)) => (c.trim().to_string(), None),
        (None, None) => return Err(("sched.plain_empty", String::new())),
    };
    let c = Cron::parse(&expr).map_err(|e| (e.key, e.detail))?;
    let zone = zone_from_text.unwrap_or_else(|| inp.time_zone.to_string());
    if !timezone::valid_zone(&zone) {
        return Err(("sched.bad_zone", zone));
    }
    let next: Vec<Value> = c
        .next_n(&zone, now_ms, inp.count.clamp(1, 10))
        .into_iter()
        .map(|m| when_json(m, &zone))
        .collect();
    Ok(json!({ "cron": expr, "time_zone": zone, "next": next }))
}

pub fn trigger(t: &Trigger, doc: &Doc, secret_set: bool, public_url: Option<&str>) -> Value {
    let mut v = serde_json::to_value(t).unwrap_or(Value::Null);
    if let Value::Object(m) = &mut v {
        m.insert("path".into(), json!(format!("/hooks/{}", t.id)));
        m.insert(
            "url".into(),
            public_url.map_or(Value::Null, |u| {
                json!(format!("{}/hooks/{}", u.trim_end_matches('/'), t.id))
            }),
        );
        m.insert("secret_set".into(), json!(secret_set));
        let last = doc.deliveries.iter().rev().find(|d| d.trigger_id == t.id);
        m.insert(
            "last_delivery".into(),
            last.map_or(Value::Null, |d| {
                serde_json::to_value(d).unwrap_or(Value::Null)
            }),
        );
    }
    v
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    fn ms(s: &str) -> u64 {
        s.parse::<jiff::Timestamp>().unwrap().as_millisecond() as u64
    }

    #[test]
    fn plain_words_preview_five_runs_in_local_time_and_utc() {
        let v = preview(
            &PreviewIn {
                text: Some("every weekday at 9am Lagos time"),
                cron: None,
                time_zone: "UTC",
                count: 5,
            },
            ms("2026-11-06T10:00:00Z"),
        )
        .unwrap();
        assert_eq!(v["cron"], "0 9 * * 1-5");
        assert_eq!(v["time_zone"], "Africa/Lagos");
        let next = v["next"].as_array().unwrap();
        assert_eq!(next.len(), 5);
        assert_eq!(next[0]["utc"], "2026-11-09T08:00:00Z");
        assert!(next[0]["local"].as_str().unwrap().contains("09:00"));
        assert!(next[0]["local"].as_str().unwrap().contains("(08:00 UTC)"));
    }

    #[test]
    fn raw_cron_is_accepted_and_nonsense_is_refused_with_a_key() {
        let v = preview(
            &PreviewIn {
                text: None,
                cron: Some("*/20 * * * *"),
                time_zone: "America/New_York",
                count: 3,
            },
            0,
        )
        .unwrap();
        assert_eq!(v["time_zone"], "America/New_York");
        assert_eq!(
            preview(
                &PreviewIn {
                    text: Some("sometime soon"),
                    cron: None,
                    time_zone: "UTC",
                    count: 5
                },
                0
            )
            .unwrap_err()
            .0,
            "sched.plain_need_time"
        );
        assert_eq!(
            preview(
                &PreviewIn {
                    text: None,
                    cron: Some("1 2"),
                    time_zone: "UTC",
                    count: 5
                },
                0
            )
            .unwrap_err()
            .0,
            "sched.cron_five_fields"
        );
        assert_eq!(
            preview(
                &PreviewIn {
                    text: None,
                    cron: Some("0 9 * * *"),
                    time_zone: "Nope/Nope",
                    count: 5
                },
                0
            )
            .unwrap_err()
            .0,
            "sched.bad_zone"
        );
    }

    #[test]
    fn the_wake_cost_is_the_run_plus_the_auto_pause_wait_and_never_more_than_always_on() {
        let s = Schedule {
            id: "sch-1".into(),
            when: When::Cron {
                expr: "*/10 * * * *".into(),
            },
            ..Default::default()
        };
        let st = SchedState {
            armed_ms: 0,
            ..Default::default()
        };
        let c = cost(
            &s,
            &st,
            &Doc::default(),
            0,
            &CostInputs {
                hourly: 1.0,
                currency: Some("USD".into()),
                auto_pause_minutes: 90,
            },
        );
        assert!((c["per_run"].as_f64().unwrap() - 95.0 / 60.0).abs() < 1e-9);
        assert_eq!(
            c["per_month"].as_f64().unwrap(),
            730.0,
            "capped at an always-on month"
        );
        let daily = Schedule {
            when: When::Cron {
                expr: "0 9 * * *".into(),
            },
            ..s
        };
        let c = cost(
            &daily,
            &st,
            &Doc::default(),
            0,
            &CostInputs {
                hourly: 0.6,
                currency: None,
                auto_pause_minutes: 60,
            },
        );
        assert_eq!(c["runs_per_month"], 30);
        assert!((c["per_month"].as_f64().unwrap() - 30.0 * 0.6 * 65.0 / 60.0).abs() < 1e-6);
    }
}
