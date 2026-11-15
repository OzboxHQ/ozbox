//! Time without a time crate: a clock trait (so tests use a fake) and UTC civil-date conversions.

use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

/// Source of "now", in Unix milliseconds.
pub trait Clock: Send + Sync {
    fn now_ms(&self) -> u64;
}

#[derive(Debug, Default, Clone, Copy)]
pub struct SystemClock;

impl Clock for SystemClock {
    fn now_ms(&self) -> u64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_millis() as u64)
            .unwrap_or(0)
    }
}

/// A clock that only moves when told to.
#[derive(Debug, Default)]
pub struct FakeClock(AtomicU64);

impl FakeClock {
    pub fn new(ms: u64) -> Self {
        Self(AtomicU64::new(ms))
    }
    pub fn set(&self, ms: u64) {
        self.0.store(ms, Ordering::SeqCst);
    }
    pub fn advance(&self, ms: u64) {
        self.0.fetch_add(ms, Ordering::SeqCst);
    }
}

impl Clock for FakeClock {
    fn now_ms(&self) -> u64 {
        self.0.load(Ordering::SeqCst)
    }
}

pub const MINUTE_MS: u64 = 60_000;
pub const HOUR_MS: u64 = 3_600_000;
pub const DAY_MS: u64 = 86_400_000;

/// Days since 1970-01-01 -> (year, month, day). Howard Hinnant's civil-from-days.
pub fn civil_from_days(z: i64) -> (i64, u32, u32) {
    let z = z + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let m = if mp < 10 { mp + 3 } else { mp - 9 } as u32;
    (if m <= 2 { y + 1 } else { y }, m, d)
}

pub fn days_from_civil(y: i64, m: u32, d: u32) -> i64 {
    let y = if m <= 2 { y - 1 } else { y };
    let era = y.div_euclid(400);
    let yoe = y.rem_euclid(400);
    let mp = (if m > 2 { m - 3 } else { m + 9 }) as i64;
    let doy = (153 * mp + 2) / 5 + d as i64 - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146_097 + doe - 719_468
}

/// `(year, month, day, hour, minute, second)` in UTC.
pub fn utc_parts(ms: u64) -> (i64, u32, u32, u32, u32, u32) {
    let secs = ms / 1000;
    let (y, m, d) = civil_from_days((secs / 86_400) as i64);
    let rem = secs % 86_400;
    (
        y,
        m,
        d,
        (rem / 3600) as u32,
        (rem % 3600 / 60) as u32,
        (rem % 60) as u32,
    )
}

/// `yyyymmddThhmmssZ`, as used in WIP branch names.
pub fn compact_utc(ms: u64) -> String {
    let (y, mo, d, h, mi, s) = utc_parts(ms);
    format!("{y:04}{mo:02}{d:02}T{h:02}{mi:02}{s:02}Z")
}

pub fn rfc3339(ms: u64) -> String {
    let (y, mo, d, h, mi, s) = utc_parts(ms);
    format!("{y:04}-{mo:02}-{d:02}T{h:02}:{mi:02}:{s:02}Z")
}

/// `yyyymmdd` (one 1-minute segment file per day).
pub fn day_stamp(ms: u64) -> String {
    let (y, mo, d, ..) = utc_parts(ms);
    format!("{y:04}{mo:02}{d:02}")
}

/// `yyyymm` (one 1-hour segment file per month).
pub fn month_stamp(ms: u64) -> String {
    let (y, mo, ..) = utc_parts(ms);
    format!("{y:04}{mo:02}")
}

/// Start of the UTC day / month a stamp names, in Unix ms.
pub fn day_stamp_start_ms(stamp: &str) -> Option<u64> {
    if stamp.len() != 8 || !stamp.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    let y: i64 = stamp[0..4].parse().ok()?;
    let m: u32 = stamp[4..6].parse().ok()?;
    let d: u32 = stamp[6..8].parse().ok()?;
    if !(1..=12).contains(&m) || !(1..=31).contains(&d) {
        return None;
    }
    u64::try_from(days_from_civil(y, m, d) * 86_400_000).ok()
}

pub fn month_stamp_start_ms(stamp: &str) -> Option<u64> {
    if stamp.len() != 6 || !stamp.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    day_stamp_start_ms(&format!("{stamp}01"))
}

/// Parse `YYYY-MM-DDTHH:MM:SS[.frac](Z|+HH:MM|-HH:MM)` to Unix ms. Dates before 1970 are refused.
pub fn parse_rfc3339(s: &str) -> Option<u64> {
    let b = s.as_bytes();
    if b.len() < 20 || !s.is_ascii() {
        return None;
    }
    let num = |a: usize, z: usize| -> Option<i64> { s.get(a..z)?.parse::<i64>().ok() };
    if b[4] != b'-'
        || b[7] != b'-'
        || !(b[10] == b'T' || b[10] == b't')
        || b[13] != b':'
        || b[16] != b':'
    {
        return None;
    }
    let (y, mo, d, h, mi, sec) = (
        num(0, 4)?,
        num(5, 7)?,
        num(8, 10)?,
        num(11, 13)?,
        num(14, 16)?,
        num(17, 19)?,
    );
    if !(1..=12).contains(&mo) || !(1..=31).contains(&d) || h > 23 || mi > 59 || sec > 60 {
        return None;
    }
    let mut i = 19;
    let mut frac_ms = 0i64;
    if b[i] == b'.' {
        i += 1;
        let start = i;
        while i < b.len() && b[i].is_ascii_digit() {
            i += 1;
        }
        let digits = &s[start..i];
        if digits.is_empty() {
            return None;
        }
        let first3: String = digits.chars().chain("000".chars()).take(3).collect();
        frac_ms = first3.parse().ok()?;
    }
    let off_s = match b.get(i)? {
        b'Z' | b'z' if i + 1 == b.len() => 0,
        sign @ (b'+' | b'-') if i + 6 == b.len() && b[i + 3] == b':' => {
            let oh = num(i + 1, i + 3)?;
            let om = num(i + 4, i + 6)?;
            let v = oh * 3600 + om * 60;
            if *sign == b'+' {
                v
            } else {
                -v
            }
        }
        _ => return None,
    };
    let days = days_from_civil(y, mo as u32, d as u32);
    let total = days * 86_400 + h * 3600 + mi * 60 + sec - off_s;
    if total < 0 {
        return None;
    }
    Some(total as u64 * 1000 + frac_ms as u64)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn formats_known_instants() {
        // 2026-11-09T12:34:56Z
        let ms = 1_794_227_696_000;
        assert_eq!(rfc3339(ms), "2026-11-09T12:34:56Z");
        assert_eq!(compact_utc(ms), "20261109T123456Z");
        assert_eq!(day_stamp(ms), "20261109");
        assert_eq!(month_stamp(ms), "202611");
        assert_eq!(parse_rfc3339("2026-11-09T12:34:56Z"), Some(ms));
    }

    #[test]
    fn parses_offsets_and_fractions() {
        let z = parse_rfc3339("2026-11-09T12:00:00Z");
        assert_eq!(parse_rfc3339("2026-11-09T13:00:00+01:00"), z);
        assert_eq!(parse_rfc3339("2026-11-09T11:00:00-01:00"), z);
        assert_eq!(
            parse_rfc3339("2026-11-09T12:00:00.250Z"),
            z.map(|v| v + 250)
        );
        assert_eq!(parse_rfc3339("not a time"), None);
        assert_eq!(parse_rfc3339("2026-13-09T12:00:00Z"), None);
        assert_eq!(parse_rfc3339("1969-01-01T00:00:00Z"), None);
    }

    #[test]
    fn stamps_round_trip() {
        let ms = day_stamp_start_ms("20240229").unwrap_or(0);
        assert_eq!(day_stamp(ms), "20240229");
        let m = month_stamp_start_ms("202402").unwrap_or(0);
        assert_eq!(month_stamp(m), "202402");
        assert_eq!(day_stamp_start_ms("2024022x"), None);
    }
}
