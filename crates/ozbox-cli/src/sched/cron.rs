//! Five-field cron (`minute hour day-of-month month day-of-week`) read on a person's own clock.
//!
//! The time-zone database is real (see `timezone`), so "every day at 09:00" is 09:00 on the wall all year. A time the
//! clock skips (spring forward) runs just after the jump; a time that happens twice (fall back) runs once, the first
//! time. As in classic cron, when both day-of-month and day-of-week are restricted a day matches if either does.

use jiff::civil::{Date, Time};
use jiff::tz::TimeZone;
use jiff::Timestamp;

/// A parsed expression. Each set is the allowed values, ascending.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Cron {
    pub minutes: Vec<u8>,
    pub hours: Vec<u8>,
    pub days: Vec<u8>,
    pub months: Vec<u8>,
    /// 0 = Sunday .. 6 = Saturday.
    pub weekdays: Vec<u8>,
    dom_any: bool,
    dow_any: bool,
}

/// Why an expression was refused: a catalogue key and the offending text.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CronError {
    pub key: &'static str,
    pub detail: String,
}

fn err(key: &'static str, detail: impl Into<String>) -> CronError {
    CronError {
        key,
        detail: detail.into(),
    }
}

const MONTHS: [&str; 12] = [
    "jan", "feb", "mar", "apr", "may", "jun", "jul", "aug", "sep", "oct", "nov", "dec",
];
const DAYS: [&str; 7] = ["sun", "mon", "tue", "wed", "thu", "fri", "sat"];

fn number(tok: &str, names: &[&str], names_base: u32) -> Option<u32> {
    if let Ok(n) = tok.parse::<u32>() {
        return Some(n);
    }
    let low = tok.to_ascii_lowercase();
    names
        .iter()
        .position(|n| *n == low)
        .map(|i| i as u32 + names_base)
}

fn field(
    text: &str,
    min: u32,
    max: u32,
    names: &[&str],
    names_base: u32,
    which: &'static str,
) -> Result<(Vec<u8>, bool), CronError> {
    let mut out = std::collections::BTreeSet::new();
    let mut any = false;
    for part in text.split(',') {
        if part.is_empty() {
            return Err(err("sched.cron_bad_field", which));
        }
        let (range, step) = match part.split_once('/') {
            Some((r, s)) => {
                let step: u32 = s.parse().map_err(|_| err("sched.cron_bad_field", which))?;
                if step == 0 {
                    return Err(err("sched.cron_bad_field", which));
                }
                (r, Some(step))
            }
            None => (part, None),
        };
        let (lo, hi) = if range == "*" {
            if step.is_none() {
                any = true;
            }
            (min, max)
        } else if let Some((a, b)) = range.split_once('-') {
            let a =
                number(a, names, names_base).ok_or_else(|| err("sched.cron_bad_field", which))?;
            let b =
                number(b, names, names_base).ok_or_else(|| err("sched.cron_bad_field", which))?;
            (a, b)
        } else {
            let a = number(range, names, names_base)
                .ok_or_else(|| err("sched.cron_bad_field", which))?;
            // `5/10` means from 5 to the end, every 10.
            (a, if step.is_some() { max } else { a })
        };
        // Day-of-week accepts 7 for Sunday.
        let hi_limit = if which == "day of week" { 7 } else { max };
        if lo < min || hi > hi_limit || lo > hi {
            return Err(err("sched.cron_out_of_range", which));
        }
        let mut v = lo;
        while v <= hi {
            let v2 = if which == "day of week" && v == 7 {
                0
            } else {
                v
            };
            out.insert(v2 as u8);
            v += step.unwrap_or(1);
        }
    }
    if which == "day of week" && out.len() == 7 {
        any = true;
    }
    Ok((out.into_iter().collect(), any))
}

impl Cron {
    pub fn parse(expr: &str) -> Result<Cron, CronError> {
        let expr = expr.trim();
        let expanded = match expr {
            "@yearly" | "@annually" => "0 0 1 1 *",
            "@monthly" => "0 0 1 * *",
            "@weekly" => "0 0 * * 0",
            "@daily" | "@midnight" => "0 0 * * *",
            "@hourly" => "0 * * * *",
            other => other,
        };
        if expanded.len() > 120 {
            return Err(err("sched.cron_too_long", ""));
        }
        let parts: Vec<&str> = expanded.split_whitespace().collect();
        if parts.len() != 5 {
            return Err(err("sched.cron_five_fields", parts.len().to_string()));
        }
        let (minutes, _) = field(parts[0], 0, 59, &[], 0, "minute")?;
        let (hours, _) = field(parts[1], 0, 23, &[], 0, "hour")?;
        let (days, dom_any) = field(parts[2], 1, 31, &[], 0, "day of month")?;
        let (months, _) = field(parts[3], 1, 12, &MONTHS, 1, "month")?;
        let (weekdays, dow_any) = field(parts[4], 0, 6, &DAYS, 0, "day of week")?;
        Ok(Cron {
            minutes,
            hours,
            days,
            months,
            weekdays,
            dom_any,
            dow_any,
        })
    }

    fn day_matches(&self, d: Date) -> bool {
        if !self.months.contains(&(d.month() as u8)) {
            return false;
        }
        let dom = self.days.contains(&(d.day() as u8));
        let dow = self
            .weekdays
            .contains(&(d.weekday().to_sunday_zero_offset() as u8));
        match (self.dom_any, self.dow_any) {
            (true, true) => true,
            (true, false) => dow,
            (false, true) => dom,
            (false, false) => dom || dow,
        }
    }

    /// Every fire time on one local day, ascending, as Unix milliseconds. A skipped wall time becomes the moment just
    /// after the jump; a repeated one is the first of its two occurrences; two readings that land on one moment count once.
    fn fires_on(&self, tz: &TimeZone, d: Date) -> Vec<i64> {
        if !self.day_matches(d) {
            return Vec::new();
        }
        let mut out = Vec::new();
        for h in &self.hours {
            for m in &self.minutes {
                let Ok(t) = Time::new(*h as i8, *m as i8, 0, 0) else {
                    continue;
                };
                if let Ok(z) = tz.to_ambiguous_zoned(d.to_datetime(t)).compatible() {
                    out.push(z.timestamp().as_millisecond());
                }
            }
        }
        out.sort_unstable();
        out.dedup();
        out
    }

    /// The first fire time strictly after `after_ms`. `None` when the zone is unknown or nothing fires within about
    /// eight years (for example `0 0 30 2 *`).
    pub fn next_after(&self, zone: &str, after_ms: u64) -> Option<u64> {
        let tz = TimeZone::get(zone).ok()?;
        let after = i64::try_from(after_ms).ok()?;
        let mut date = Timestamp::from_millisecond(after)
            .ok()?
            .to_zoned(tz.clone())
            .date();
        // The date one day back too: a skipped time moves later, never earlier, so one day is enough.
        date = date.yesterday().ok()?;
        for _ in 0..(366 * 8) {
            if let Some(f) = self.fires_on(&tz, date).into_iter().find(|f| *f > after) {
                return u64::try_from(f).ok();
            }
            date = date.tomorrow().ok()?;
        }
        None
    }

    /// The next `n` fire times after `after_ms`.
    pub fn next_n(&self, zone: &str, after_ms: u64, n: usize) -> Vec<u64> {
        let mut out = Vec::new();
        let mut at = after_ms;
        while out.len() < n {
            match self.next_after(zone, at) {
                Some(f) => {
                    out.push(f);
                    at = f;
                }
                None => break,
            }
        }
        out
    }

    /// Fire times in `(after_ms, upto_ms]`, ascending, at most `limit` of them (the earliest ones are dropped first if
    /// there are more, so the result is always the most recent). Looks back at most 31 days.
    pub fn between(&self, zone: &str, after_ms: u64, upto_ms: u64, limit: usize) -> Vec<u64> {
        let Ok(tz) = TimeZone::get(zone) else {
            return Vec::new();
        };
        let after = after_ms.max(upto_ms.saturating_sub(31 * 86_400_000));
        let (Ok(a), Ok(u)) = (i64::try_from(after), i64::try_from(upto_ms)) else {
            return Vec::new();
        };
        let Ok(start) = Timestamp::from_millisecond(a) else {
            return Vec::new();
        };
        let Ok(end) = Timestamp::from_millisecond(u) else {
            return Vec::new();
        };
        let mut date = match start.to_zoned(tz.clone()).date().yesterday() {
            Ok(d) => d,
            Err(_) => return Vec::new(),
        };
        let last = end.to_zoned(tz.clone()).date();
        let mut out: Vec<u64> = Vec::new();
        while date <= last {
            for f in self.fires_on(&tz, date) {
                if f > a && f <= u {
                    if let Ok(f) = u64::try_from(f) {
                        out.push(f);
                    }
                }
            }
            match date.tomorrow() {
                Ok(d) => date = d,
                Err(_) => break,
            }
        }
        if out.len() > limit {
            out.drain(..out.len() - limit);
        }
        out
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    fn ms(s: &str) -> u64 {
        s.parse::<Timestamp>().unwrap().as_millisecond() as u64
    }

    #[test]
    fn fields_lists_ranges_steps_and_names() {
        let c = Cron::parse("*/15 9-17 * jan,mar mon-fri").unwrap();
        assert_eq!(c.minutes, vec![0, 15, 30, 45]);
        assert_eq!(c.hours, (9..=17).collect::<Vec<u8>>());
        assert_eq!(c.months, vec![1, 3]);
        assert_eq!(c.weekdays, vec![1, 2, 3, 4, 5]);
        let c = Cron::parse("5/20 0 1 1 7").unwrap();
        assert_eq!(c.minutes, vec![5, 25, 45]);
        assert_eq!(c.weekdays, vec![0]);
        assert_eq!(
            Cron::parse("@daily").unwrap(),
            Cron::parse("0 0 * * *").unwrap()
        );
    }

    #[test]
    fn what_is_not_cron_is_refused_with_a_reason() {
        for bad in [
            "",
            "* * * *",
            "* * * * * *",
            "60 * * * *",
            "* 24 * * *",
            "* * 0 * *",
            "* * 32 * *",
            "* * * 13 *",
            "* * * * 8",
            "*/0 * * * *",
            "5-1 * * * *",
            "a * * * *",
            "1,,2 * * * *",
        ] {
            assert!(Cron::parse(bad).is_err(), "{bad:?} should be refused");
        }
        assert_eq!(
            Cron::parse("61 * * * *").unwrap_err().key,
            "sched.cron_out_of_range"
        );
        assert_eq!(
            Cron::parse("1 2 3").unwrap_err().key,
            "sched.cron_five_fields"
        );
    }

    #[test]
    fn weekdays_at_nine_in_lagos() {
        let c = Cron::parse("0 9 * * 1-5").unwrap();
        // Friday 2026-11-06 10:00 UTC -> next is Monday 2026-11-09 09:00 WAT = 08:00 UTC.
        let n = c
            .next_after("Africa/Lagos", ms("2026-11-06T10:00:00Z"))
            .unwrap();
        assert_eq!(n, ms("2026-11-09T08:00:00Z"));
        let five = c.next_n("Africa/Lagos", ms("2026-11-06T10:00:00Z"), 5);
        assert_eq!(five.len(), 5);
        assert_eq!(five[4], ms("2026-11-13T08:00:00Z"));
    }

    #[test]
    fn a_daily_time_follows_the_wall_clock_across_daylight_saving() {
        let c = Cron::parse("30 9 * * *").unwrap();
        // New York leaves EST on 2026-03-08: 09:30 is 14:30Z before and 13:30Z after.
        let before = c
            .next_after("America/New_York", ms("2026-03-07T00:00:00Z"))
            .unwrap();
        assert_eq!(before, ms("2026-03-07T14:30:00Z"));
        let after = c
            .next_after("America/New_York", ms("2026-03-08T00:00:00Z"))
            .unwrap();
        assert_eq!(after, ms("2026-03-08T13:30:00Z"));
        // Fall back on 2026-11-01.
        let a = c
            .next_after("America/New_York", ms("2026-10-31T20:00:00Z"))
            .unwrap();
        assert_eq!(a, ms("2026-11-01T14:30:00Z"));
        let b = c
            .next_after("America/New_York", ms("2026-11-01T15:00:00Z"))
            .unwrap();
        assert_eq!(b, ms("2026-11-02T14:30:00Z"));
        // Lagos never changes.
        let l = c.next_n("Africa/Lagos", ms("2026-03-07T00:00:00Z"), 3);
        assert_eq!(l[1] - l[0], 86_400_000);
        assert_eq!(l[2] - l[1], 86_400_000);
    }

    #[test]
    fn a_skipped_time_runs_just_after_the_jump_and_a_repeated_one_runs_once() {
        // 02:30 does not exist in New York on 2026-03-08: it runs at 03:30 EDT = 07:30Z.
        let c = Cron::parse("30 2 * * *").unwrap();
        let n = c
            .next_after("America/New_York", ms("2026-03-08T00:00:00Z"))
            .unwrap();
        assert_eq!(n, ms("2026-03-08T07:30:00Z"));
        // 01:30 happens twice on 2026-11-01: only the first (05:30Z, EDT) fires.
        let c = Cron::parse("30 1 * * *").unwrap();
        let day = c.between(
            "America/New_York",
            ms("2026-11-01T00:00:00Z"),
            ms("2026-11-02T04:00:00Z"),
            10,
        );
        assert_eq!(day, vec![ms("2026-11-01T05:30:00Z")]);
        // Hourly across the repeated hour: 24 fires on a 25-hour day would be wrong; the repeated hour runs once.
        let c = Cron::parse("0 * * * *").unwrap();
        let (s, e) = (ms("2026-11-01T04:00:00Z"), ms("2026-11-02T05:00:00Z"));
        let all = c.between("America/New_York", s - 1, e - 1, 100);
        assert_eq!(
            all.len(),
            24,
            "hourly on a 25-hour day fires once per distinct wall hour"
        );
    }

    #[test]
    fn day_of_month_or_day_of_week_when_both_are_restricted() {
        let c = Cron::parse("0 0 13 * 5").unwrap(); // the 13th, or any Friday
        let n = c.next_n("UTC", ms("2026-11-01T00:00:00Z"), 3);
        assert_eq!(n[0], ms("2026-11-06T00:00:00Z")); // Friday
        assert_eq!(n[1], ms("2026-11-13T00:00:00Z")); // both
        assert_eq!(n[2], ms("2026-11-20T00:00:00Z"));
    }

    #[test]
    fn impossible_dates_and_unknown_zones_give_nothing() {
        assert_eq!(
            Cron::parse("0 0 30 2 *").unwrap().next_after("UTC", 0),
            None
        );
        assert_eq!(
            Cron::parse("0 0 * * *").unwrap().next_after("Mars/Base", 0),
            None
        );
        let leap = Cron::parse("0 0 29 2 *").unwrap();
        assert_eq!(
            leap.next_after("UTC", ms("2026-11-01T00:00:00Z")),
            Some(ms("2028-02-29T00:00:00Z"))
        );
    }

    #[test]
    fn between_returns_the_most_recent_up_to_the_limit() {
        let c = Cron::parse("*/10 * * * *").unwrap();
        let v = c.between(
            "UTC",
            ms("2026-11-09T10:00:00Z"),
            ms("2026-11-09T11:00:00Z"),
            2,
        );
        assert_eq!(
            v,
            vec![ms("2026-11-09T10:50:00Z"), ms("2026-11-09T11:00:00Z")]
        );
    }
}
