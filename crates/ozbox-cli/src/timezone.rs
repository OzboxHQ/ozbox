//! Time zones and countries, from a real time-zone database (bundled, so the answer does not depend on the machine),
//! so daylight-saving time is followed: quiet hours, and the scheduler's "every day at 09:00", mean the person's own
//! clock all year.

use jiff::civil::Time;
use jiff::tz::TimeZone;
use jiff::{Timestamp, Zoned};

/// ISO 3166-1 alpha-2 codes.
const COUNTRIES: &str = "AD AE AF AG AI AL AM AO AQ AR AS AT AU AW AX AZ BA BB BD BE BF BG BH BI BJ BL BM BN BO BQ BR BS BT BV BW BY BZ CA CC CD CF CG CH CI CK CL CM CN CO CR CU CV CW CX CY CZ DE DJ DK DM DO DZ EC EE EG EH ER ES ET FI FJ FK FM FO FR GA GB GD GE GF GG GH GI GL GM GN GP GQ GR GS GT GU GW GY HK HM HN HR HT HU ID IE IL IM IN IO IQ IR IS IT JE JM JO JP KE KG KH KI KM KN KP KR KW KY KZ LA LB LC LI LK LR LS LT LU LV LY MA MC MD ME MF MG MH MK ML MM MN MO MP MQ MR MS MT MU MV MW MX MY MZ NA NC NE NF NG NI NL NO NP NR NU NZ OM PA PE PF PG PH PK PL PM PN PR PS PT PW PY QA RE RO RS RU RW SA SB SC SD SE SG SH SI SJ SK SL SM SN SO SR SS ST SV SX SY SZ TC TD TF TG TH TJ TK TL TM TN TO TR TT TV TW TZ UA UG UM US UY UZ VA VC VE VG VI VN VU WF WS XK YE YT ZA ZM ZW";

/// Whether `code` is an ISO 3166-1 alpha-2 country code (upper case).
pub fn valid_country(code: &str) -> bool {
    code.len() == 2 && COUNTRIES.split(' ').any(|c| c == code)
}

fn zone(name: &str) -> Option<TimeZone> {
    if name.is_empty() || name.len() > 64 {
        return None;
    }
    TimeZone::get(name).ok()
}

/// Whether `name` is an IANA time-zone name the database knows (`Africa/Lagos`, `America/New_York`, `UTC`).
pub fn valid_zone(name: &str) -> bool {
    zone(name).is_some()
}

fn at(ms: u64) -> Option<Timestamp> {
    Timestamp::from_millisecond(i64::try_from(ms).ok()?).ok()
}

/// The zone's offset from UTC, in minutes, at that moment (east is positive).
pub fn offset_minutes(zone_name: &str, ms: u64) -> Option<i32> {
    let tz = zone(zone_name)?;
    Some(tz.to_offset(at(ms)?).seconds() / 60)
}

/// The next moment (after `after_ms`) the wall clock in `zone_name` reads `hh:mm`. A time that does not exist that day
/// (the clock jumped over it) is taken as the moment just after the jump; one that happens twice, as the first.
pub fn next_local_time(zone_name: &str, after_ms: u64, hh: i8, mm: i8) -> Option<u64> {
    let tz = zone(zone_name)?;
    let now = at(after_ms)?.to_zoned(tz.clone());
    let time = Time::new(hh, mm, 0, 0).ok()?;
    let mut date = now.date();
    for _ in 0..3 {
        let candidate = tz
            .to_ambiguous_zoned(date.to_datetime(time))
            .compatible()
            .ok()?;
        if candidate.timestamp() > now.timestamp() {
            return u64::try_from(candidate.timestamp().as_millisecond()).ok();
        }
        date = date.tomorrow().ok()?;
    }
    None
}

/// The latest moment at or before `at_ms` at which the wall clock in `zone_name` read `hh:mm` (on `weekday`, Monday = 0,
/// when one is given). A time that does not exist that day (the clock jumped over it) is taken as the same reading moved
/// forward by the jump (02:30 becomes 03:30); one that happens twice, as the first. `None` for an unknown zone or when
/// nothing is found in 8 days.
pub fn prev_local_time(
    zone_name: &str,
    at_ms: u64,
    hh: i8,
    mm: i8,
    weekday: Option<u8>,
) -> Option<u64> {
    let tz = zone(zone_name)?;
    let now = at(at_ms)?.to_zoned(tz.clone());
    let time = Time::new(hh, mm, 0, 0).ok()?;
    let mut date = now.date();
    for _ in 0..9 {
        let candidate = tz
            .to_ambiguous_zoned(date.to_datetime(time))
            .compatible()
            .ok()?;
        let day_ok = weekday.is_none_or(|w| {
            u8::try_from(candidate.date().weekday().to_monday_zero_offset()).ok() == Some(w)
        });
        if day_ok && candidate.timestamp() <= now.timestamp() {
            return u64::try_from(candidate.timestamp().as_millisecond()).ok();
        }
        date = date.yesterday().ok()?;
    }
    None
}

/// The weekday of `ms` on the clock of `zone_name`, Monday = 0.
pub fn weekday_monday_zero(zone_name: &str, ms: u64) -> Option<u8> {
    let z = zoned(zone_name, ms)?;
    u8::try_from(z.date().weekday().to_monday_zero_offset()).ok()
}

/// A day `(year, month, day)`, an ISO week `(year, week)` and a month `(year, month)`.
pub type CalendarKeys = ((i16, i8, i8), (i16, i8), (i16, i8));

/// The calendar day, ISO week and month `ms` falls in, on the clock of `zone_name`: the buckets retention counts in.
pub fn calendar_keys(zone_name: &str, ms: u64) -> Option<CalendarKeys> {
    let z = zoned(zone_name, ms)?;
    let d = z.date();
    let w = d.iso_week_date();
    Some((
        (d.year(), d.month(), d.day()),
        (w.year(), w.week()),
        (d.year(), d.month()),
    ))
}

fn zoned(zone_name: &str, ms: u64) -> Option<Zoned> {
    Some(at(ms)?.to_zoned(zone(zone_name)?))
}

#[allow(dead_code)] // the scheduler's helper
/// Minutes since local midnight in `zone_name`.
pub fn local_minutes(zone_name: &str, ms: u64) -> Option<i64> {
    let z = zoned(zone_name, ms)?;
    Some(i64::from(z.hour()) * 60 + i64::from(z.minute()))
}

/// The start (inclusive) and end (exclusive) of the local calendar day `date` (`2026-11-09`), each with the offset the
/// zone has at that moment, so a day the clocks change in is 23 or 25 hours long. Without a zone the fixed offset
/// (minutes east of UTC) is used. A midnight that does not exist (the clock jumped over it) is the moment just after.
pub fn local_day_bounds(
    zone_name: Option<&str>,
    date: &str,
    fixed_offset_min: i32,
) -> Option<(u64, u64)> {
    let day: jiff::civil::Date = date.parse().ok()?;
    let next = day.tomorrow().ok()?;
    let tz = match zone_name {
        Some(n) => zone(n)?,
        None => {
            TimeZone::fixed(jiff::tz::Offset::from_seconds(fixed_offset_min.checked_mul(60)?).ok()?)
        }
    };
    let ms = |d: jiff::civil::Date| -> Option<u64> {
        let t = tz
            .to_ambiguous_zoned(d.to_datetime(Time::midnight()))
            .compatible()
            .ok()?;
        u64::try_from(t.timestamp().as_millisecond()).ok()
    };
    Some((ms(day)?, ms(next)?))
}

/// `2026-11-09 23:15 WAT (22:15 UTC)`: a time in the person's zone with UTC beside it.
pub fn format_with_utc(zone_name: &str, ms: u64) -> Option<String> {
    let z = zoned(zone_name, ms)?;
    let utc = at(ms)?.to_zoned(TimeZone::UTC);
    Some(format!(
        "{} ({} UTC)",
        z.strftime("%Y-%m-%d %H:%M %Z"),
        utc.strftime("%H:%M")
    ))
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    fn ms(s: &str) -> u64 {
        s.parse::<Timestamp>().unwrap().as_millisecond() as u64
    }

    #[test]
    fn a_local_day_has_the_offset_of_each_of_its_own_ends() {
        let h = 3_600_000u64;
        // Spring forward in New York: 2026-03-08 is 23 hours long (EST at midnight, EDT the next midnight).
        let (s, e) = local_day_bounds(Some("America/New_York"), "2026-03-08", 0).unwrap();
        assert_eq!(s, ms("2026-03-08T05:00:00Z"));
        assert_eq!(e, ms("2026-03-09T04:00:00Z"));
        assert_eq!(e - s, 23 * h);
        // Fall back: 2026-11-01 is 25 hours long.
        let (s, e) = local_day_bounds(Some("America/New_York"), "2026-11-01", 0).unwrap();
        assert_eq!(s, ms("2026-11-01T04:00:00Z"));
        assert_eq!(e, ms("2026-11-02T05:00:00Z"));
        assert_eq!(e - s, 25 * h);
        // An ordinary day is 24 hours.
        let (s, e) = local_day_bounds(Some("America/New_York"), "2026-06-01", 0).unwrap();
        assert_eq!(e - s, 24 * h);
        // A zone with no daylight saving never changes length.
        for d in ["2026-03-08", "2026-11-01"] {
            let (s, e) = local_day_bounds(Some("Africa/Lagos"), d, 0).unwrap();
            assert_eq!(e - s, 24 * h);
            assert_eq!(s % h, 23 * h % h);
        }
        let (s, _) = local_day_bounds(Some("Africa/Lagos"), "2026-11-09", 0).unwrap();
        assert_eq!(s, ms("2026-11-08T23:00:00Z"));
        // No zone: the fixed offset.
        let (s, e) = local_day_bounds(None, "2026-11-09", 120).unwrap();
        assert_eq!((s, e - s), (ms("2026-11-08T22:00:00Z"), 24 * h));
        assert!(local_day_bounds(Some("Mars/Olympus"), "2026-11-09", 0).is_none());
        assert!(local_day_bounds(None, "not-a-date", 0).is_none());
    }

    #[test]
    fn names_and_codes_are_validated() {
        for ok in [
            "UTC",
            "Africa/Lagos",
            "America/New_York",
            "Asia/Kolkata",
            "Europe/London",
        ] {
            assert!(valid_zone(ok), "{ok}");
        }
        for bad in [
            "",
            "Mars/Olympus",
            "EST5EDT; rm",
            "africa/lagos ",
            "a".repeat(65).as_str(),
        ] {
            assert!(!valid_zone(bad), "{bad}");
        }
        for ok in ["NG", "US", "GB", "ZW"] {
            assert!(valid_country(ok));
        }
        for bad in ["", "ng", "XX", "USA", "N", "NG "] {
            assert!(!valid_country(bad), "{bad}");
        }
        assert_eq!(COUNTRIES.split(' ').count(), 250);
    }

    #[test]
    fn the_offset_follows_daylight_saving_time() {
        // New York is UTC-5 in winter and UTC-4 in summer.
        assert_eq!(
            offset_minutes("America/New_York", ms("2026-01-15T12:00:00Z")),
            Some(-300)
        );
        assert_eq!(
            offset_minutes("America/New_York", ms("2026-07-15T12:00:00Z")),
            Some(-240)
        );
        // The jump itself: 2026-03-08 at 07:00 UTC the clocks go from 02:00 to 03:00.
        assert_eq!(
            offset_minutes("America/New_York", ms("2026-03-08T06:59:59Z")),
            Some(-300)
        );
        assert_eq!(
            offset_minutes("America/New_York", ms("2026-03-08T07:00:00Z")),
            Some(-240)
        );
        // And back on 2026-11-01 at 06:00 UTC.
        assert_eq!(
            offset_minutes("America/New_York", ms("2026-11-01T05:59:59Z")),
            Some(-240)
        );
        assert_eq!(
            offset_minutes("America/New_York", ms("2026-11-01T06:00:00Z")),
            Some(-300)
        );
        // Lagos has none.
        assert_eq!(
            offset_minutes("Africa/Lagos", ms("2026-07-15T12:00:00Z")),
            Some(60)
        );
        assert_eq!(offset_minutes("Nope/Nope", 0), None);
    }

    #[test]
    fn local_time_of_day_uses_the_zone() {
        assert_eq!(
            local_minutes("America/New_York", ms("2026-07-15T12:30:00Z")),
            Some(8 * 60 + 30)
        );
        assert_eq!(
            local_minutes("America/New_York", ms("2026-01-15T12:30:00Z")),
            Some(7 * 60 + 30)
        );
        assert_eq!(
            local_minutes("Asia/Kolkata", ms("2026-01-15T00:00:00Z")),
            Some(5 * 60 + 30)
        );
    }

    #[test]
    fn a_daily_time_stays_at_the_same_wall_clock_across_the_change() {
        // 09:00 in New York, the day before and the day of the spring change.
        let before = next_local_time("America/New_York", ms("2026-03-07T20:00:00Z"), 9, 0).unwrap();
        assert_eq!(before, ms("2026-03-08T13:00:00Z")); // 09:00 EDT, already summer time that morning
        let after = next_local_time("America/New_York", before, 9, 0).unwrap();
        assert_eq!(after, ms("2026-03-09T13:00:00Z"));
        // Winter: 09:00 EST is 14:00 UTC.
        let w = next_local_time("America/New_York", ms("2026-01-10T00:00:00Z"), 9, 0).unwrap();
        assert_eq!(w, ms("2026-01-10T14:00:00Z"));
    }

    #[test]
    fn a_time_inside_the_spring_gap_is_taken_just_after_it_and_a_repeated_time_once() {
        // 02:30 does not exist on 2026-03-08 in New York: it becomes 03:30 EDT.
        let gap = next_local_time("America/New_York", ms("2026-03-08T00:00:00Z"), 2, 30).unwrap();
        assert_eq!(gap, ms("2026-03-08T07:30:00Z"));
        // 01:30 happens twice on 2026-11-01; the first one (EDT, 05:30 UTC) is used.
        let twice = next_local_time("America/New_York", ms("2026-11-01T00:00:00Z"), 1, 30).unwrap();
        assert_eq!(twice, ms("2026-11-01T05:30:00Z"));
        // Asked again after it, the next one is the following day, not the repeat.
        let next = next_local_time("America/New_York", twice, 1, 30).unwrap();
        assert_eq!(next, ms("2026-11-02T06:30:00Z"));
    }

    #[test]
    fn a_time_that_has_just_passed_is_tomorrow_and_a_bad_time_is_none() {
        let t = ms("2026-01-10T10:00:00Z");
        assert_eq!(
            next_local_time("UTC", t, 10, 0),
            Some(ms("2026-01-11T10:00:00Z"))
        );
        assert_eq!(next_local_time("UTC", t, 24, 0), None);
        assert_eq!(next_local_time("Nope/Nope", t, 9, 0), None);
    }

    #[test]
    fn times_are_shown_in_the_persons_zone_with_utc_beside_them() {
        let s = format_with_utc("Africa/Lagos", ms("2026-11-09T22:15:00Z")).unwrap();
        assert_eq!(s, "2026-11-09 23:15 WAT (22:15 UTC)");
        let s = format_with_utc("America/New_York", ms("2026-07-15T12:00:00Z")).unwrap();
        assert_eq!(s, "2026-07-15 08:00 EDT (12:00 UTC)");
    }

    #[test]
    fn quiet_hours_follow_the_persons_clock_through_daylight_saving() {
        let mut st = crate::settings::Settings::default();
        st.budget.quiet_from = "23:00".into();
        st.budget.quiet_to = "07:00".into();
        st.locale.time_zone = Some("America/New_York".into());
        // 03:30 UTC in January is 22:30 in New York: not yet quiet. In July the same UTC time is 23:30: quiet.
        assert!(!crate::notify::quiet_now(ms("2026-01-15T03:30:00Z"), &st));
        assert!(crate::notify::quiet_now(ms("2026-07-15T03:30:00Z"), &st));
        // With no zone set the old fixed offset is used.
        st.locale.time_zone = None;
        st.budget.utc_offset_minutes = 0;
        assert!(!crate::notify::quiet_now(ms("2026-07-15T12:00:00Z"), &st));
        assert!(crate::notify::quiet_now(ms("2026-07-15T03:30:00Z"), &st));
    }

    #[test]
    fn settings_reject_a_bad_zone_or_country() {
        let mut st = crate::settings::Settings::default();
        assert!(st.validate().is_ok());
        st.locale.time_zone = Some("Mars/Olympus".into());
        assert!(st.validate().is_err());
        st.locale.time_zone = Some("Africa/Lagos".into());
        st.locale.country_code = Some("ng".into());
        assert!(st.validate().is_err());
        st.locale.country_code = Some("NG".into());
        assert!(st.validate().is_ok());
    }
}
