//! Plain language to cron: "every weekday at 9am Lagos time" becomes `0 9 * * 1-5` in `Africa/Lagos`.
//!
//! Only phrases this reads with certainty are accepted; anything else is refused with a reason, never guessed at. The
//! dashboard shows the cron and the next five runs before anything is saved, so a wrong reading is caught there.

/// What a sentence meant.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Plain {
    pub cron: String,
    /// The IANA zone named in the sentence, if one was.
    pub zone: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PlainError {
    pub key: &'static str,
    pub detail: String,
}

fn err(key: &'static str, detail: impl Into<String>) -> PlainError {
    PlainError {
        key,
        detail: detail.into(),
    }
}

const ALIASES: &[(&str, &str)] = &[
    ("utc", "UTC"),
    ("gmt", "UTC"),
    ("z", "UTC"),
    ("wat", "Africa/Lagos"),
    ("nigeria", "Africa/Lagos"),
    ("eastern", "America/New_York"),
    ("et", "America/New_York"),
    ("central", "America/Chicago"),
    ("ct", "America/Chicago"),
    ("mountain", "America/Denver"),
    ("mt", "America/Denver"),
    ("pacific", "America/Los_Angeles"),
    ("pt", "America/Los_Angeles"),
    ("uk", "Europe/London"),
    ("cet", "Europe/Paris"),
    ("ist", "Asia/Kolkata"),
    ("india", "Asia/Kolkata"),
];

/// A zone named in words: an IANA name, an alias, or a city that exactly one IANA name ends with.
fn zone_from(words: &str) -> Option<String> {
    let w = words.trim().trim_end_matches(" time").trim();
    if w.is_empty() {
        return None;
    }
    if w.contains('/') {
        let ok = jiff::tz::TimeZone::get(&iana_case(w)).is_ok();
        return ok.then(|| iana_case(w));
    }
    if let Some((_, z)) = ALIASES.iter().find(|(a, _)| *a == w) {
        return Some((*z).to_string());
    }
    let want = w.replace(' ', "_");
    let mut hits = jiff::tz::db()
        .available()
        .map(|n| n.as_str().to_string())
        .filter(|n| n.contains('/'))
        .filter(|n| {
            n.rsplit('/')
                .next()
                .is_some_and(|c| c.eq_ignore_ascii_case(&want))
        });
    let first = hits.next()?;
    // Two cities with one name would be a guess.
    if hits.next().is_some() {
        return None;
    }
    Some(first)
}

/// `africa/lagos` -> `Africa/Lagos` (the database is case sensitive, people are not).
fn iana_case(s: &str) -> String {
    jiff::tz::db()
        .available()
        .map(|n| n.as_str().to_string())
        .find(|n| n.eq_ignore_ascii_case(s))
        .unwrap_or_else(|| s.to_string())
}

fn clean(sentence: &str) -> Vec<String> {
    sentence
        .to_lowercase()
        .replace([',', ';', '.'], " ")
        .split_whitespace()
        .map(str::to_string)
        .collect()
}

fn parse_clock(tok: &[String], i: usize) -> Option<(u8, u8, usize)> {
    let t = tok.get(i)?;
    match t.as_str() {
        "noon" | "midday" => return Some((12, 0, 1)),
        "midnight" => return Some((0, 0, 1)),
        _ => {}
    }
    let (num, mut suffix) = match t.strip_suffix("am") {
        Some(n) => (n, Some(false)),
        None => match t.strip_suffix("pm") {
            Some(n) => (n, Some(true)),
            None => (t.as_str(), None),
        },
    };
    let mut used = 1;
    if suffix.is_none() {
        match tok.get(i + 1).map(String::as_str) {
            Some("am") => {
                suffix = Some(false);
                used = 2;
            }
            Some("pm") => {
                suffix = Some(true);
                used = 2;
            }
            _ => {}
        }
    }
    let (h, m) = match num.split_once(':') {
        Some((h, m)) => (h.parse::<u8>().ok()?, m.parse::<u8>().ok()?),
        None => {
            // A bare number with no am/pm is an hour only after "at".
            (num.parse::<u8>().ok()?, 0)
        }
    };
    if m > 59 {
        return None;
    }
    let h = match suffix {
        Some(pm) => {
            if !(1..=12).contains(&h) {
                return None;
            }
            match (pm, h) {
                (false, 12) => 0,
                (true, 12) => 12,
                (true, h) => h + 12,
                (false, h) => h,
            }
        }
        None => {
            if h > 23 {
                return None;
            }
            h
        }
    };
    Some((h, m, used))
}

fn weekday(tok: &str) -> Option<u8> {
    let t = tok.trim_end_matches('s');
    let t = if tok == "tues" || tok == "thurs" {
        &tok[..3]
    } else {
        t
    };
    match t {
        "sun" | "sunday" => Some(0),
        "mon" | "monday" => Some(1),
        "tue" | "tuesday" => Some(2),
        "wed" | "wednesday" => Some(3),
        "thu" | "thursday" => Some(4),
        "fri" | "friday" => Some(5),
        "sat" | "saturday" => Some(6),
        _ => None,
    }
}

fn ordinal(tok: &str) -> Option<u8> {
    let digits: String = tok.chars().take_while(char::is_ascii_digit).collect();
    let rest = &tok[digits.len()..];
    if !matches!(rest, "st" | "nd" | "rd" | "th" | "") || digits.is_empty() {
        return None;
    }
    let n: u8 = digits.parse().ok()?;
    (1..=31).contains(&n).then_some(n)
}

pub fn parse(sentence: &str) -> Result<Plain, PlainError> {
    if sentence.len() > 200 {
        return Err(err("sched.plain_too_long", ""));
    }
    let mut tok = clean(sentence);
    if tok.is_empty() {
        return Err(err("sched.plain_empty", ""));
    }

    // 1. The zone: an IANA name anywhere, else "... <place> time" / "in <place>" at the end.
    let mut zone: Option<String> = None;
    if let Some(i) = tok.iter().position(|t| t.contains('/')) {
        zone = Some(zone_from(&tok[i]).ok_or_else(|| err("sched.plain_zone", tok[i].clone()))?);
        tok.remove(i);
        if i > 0 && matches!(tok[i - 1].as_str(), "in" | "timezone" | "zone") {
            tok.remove(i - 1);
        }
    } else if let Some(i) = tok.iter().rposition(|t| t == "time") {
        // "... lagos time" or "... new york time": the words before "time", up to an "at"/"in"/clock.
        let mut start = i;
        while start > 0 && start > i.saturating_sub(3) {
            let w = &tok[start - 1];
            if matches!(w.as_str(), "at" | "in" | "every" | "daily" | "on")
                || parse_clock(&tok, start - 1).is_some()
            {
                break;
            }
            start -= 1;
        }
        let name = tok[start..i].join(" ");
        if !name.is_empty() {
            let z = zone_from(&name).ok_or_else(|| err("sched.plain_zone", name.clone()))?;
            zone = Some(z);
            tok.drain(start..=i);
        }
    }
    if zone.is_none() {
        if let Some(last) = tok.last() {
            if matches!(last.as_str(), "utc" | "gmt") {
                zone = Some("UTC".into());
                tok.pop();
            }
        }
    }
    tok.retain(|t| !matches!(t.as_str(), "in" | "the" | "and") || t == "and");

    let has = |w: &str| tok.iter().any(|t| t == w);

    // 2. Intervals: every minute / N minutes / hour / N hours.
    for (i, t) in tok.iter().enumerate() {
        if t == "every" || t == "each" {
            let (n, unit) = match (tok.get(i + 1), tok.get(i + 2)) {
                (Some(a), Some(u)) if a.parse::<u32>().is_ok() => {
                    (a.parse::<u32>().ok(), u.as_str())
                }
                (Some(u), _) => (Some(1), u.as_str()),
                _ => (None, ""),
            };
            let Some(n) = n else { continue };
            match unit.trim_end_matches('s') {
                "minute" | "min" => {
                    if !(1..=59).contains(&n) {
                        return Err(err("sched.plain_interval_range", "minutes 1-59"));
                    }
                    let cron = if n == 1 {
                        "* * * * *".to_string()
                    } else {
                        format!("*/{n} * * * *")
                    };
                    return Ok(Plain { cron, zone });
                }
                "hour" | "hr" => {
                    if !(1..=23).contains(&n) {
                        return Err(err("sched.plain_interval_range", "hours 1-23"));
                    }
                    let cron = if n == 1 {
                        "0 * * * *".to_string()
                    } else {
                        format!("0 */{n} * * *")
                    };
                    return Ok(Plain { cron, zone });
                }
                _ => {}
            }
        }
    }
    if tok == ["hourly"] || has("hourly") {
        return Ok(Plain {
            cron: "0 * * * *".into(),
            zone,
        });
    }

    // 3. The clock time: after "at", or an am/pm/noon/midnight/hh:mm token.
    let mut clock: Option<(u8, u8)> = None;
    let mut i = 0;
    while i < tok.len() {
        let after_at = i > 0 && tok[i - 1] == "at";
        let has_colon_or_suffix = tok[i].contains(':')
            || tok[i].ends_with("am")
            || tok[i].ends_with("pm")
            || matches!(tok[i].as_str(), "noon" | "midday" | "midnight")
            || tok.get(i + 1).is_some_and(|n| n == "am" || n == "pm");
        if after_at || has_colon_or_suffix {
            if let Some((h, m, used)) = parse_clock(&tok, i) {
                if clock.is_some() {
                    return Err(err("sched.plain_two_times", ""));
                }
                clock = Some((h, m));
                i += used;
                continue;
            }
        }
        i += 1;
    }

    // 4. The days.
    let mut dows: Vec<u8> = Vec::new();
    let mut dom: Option<u8> = None;
    let mut daily = false;
    let mut monthly = false;
    for (i, t) in tok.iter().enumerate() {
        match t.as_str() {
            "weekday" | "weekdays" => dows.extend(1..=5),
            "weekend" | "weekends" => dows.extend([0, 6]),
            "day" | "daily" | "night" | "nightly" | "morning" | "evening" => {
                if t == "day" && tok.get(i + 1).is_some_and(|n| n == "of") {
                    continue;
                }
                daily = true;
            }
            "monthly" | "month" => monthly = true,
            other => {
                if let Some(d) = weekday(other) {
                    dows.push(d);
                } else if let Some(n) = ordinal(other) {
                    if tok
                        .get(i.wrapping_sub(1))
                        .is_some_and(|p| p == "on" || p == "the")
                        || other.ends_with("st")
                        || other.ends_with("nd")
                        || other.ends_with("rd")
                        || other.ends_with("th")
                    {
                        dom = Some(n);
                    }
                }
            }
        }
    }
    let Some((h, m)) = clock else {
        return Err(err("sched.plain_need_time", ""));
    };
    dows.sort_unstable();
    dows.dedup();
    let cron = if let Some(d) = dom {
        if !dows.is_empty() {
            return Err(err("sched.plain_unrecognized", ""));
        }
        format!("{m} {h} {d} * *")
    } else if monthly {
        return Err(err("sched.plain_need_day_of_month", ""));
    } else if !dows.is_empty() {
        let list: Vec<String> = dows.iter().map(u8::to_string).collect();
        format!("{m} {h} * * {}", compact(&list.join(",")))
    } else if daily {
        format!("{m} {h} * * *")
    } else {
        return Err(err("sched.plain_unrecognized", ""));
    };
    Ok(Plain { cron, zone })
}

/// `1,2,3,4,5` -> `1-5` (only that exact run, which is what "weekdays" is).
fn compact(list: &str) -> String {
    if list == "1,2,3,4,5" {
        "1-5".into()
    } else {
        list.to_string()
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    fn p(s: &str) -> (String, Option<String>) {
        let r = parse(s).unwrap();
        (r.cron, r.zone)
    }

    #[test]
    fn the_phrases_people_write() {
        assert_eq!(
            p("every weekday at 9am Lagos time"),
            ("0 9 * * 1-5".into(), Some("Africa/Lagos".into()))
        );
        assert_eq!(p("every day at 14:30"), ("30 14 * * *".into(), None));
        assert_eq!(
            p("daily at 9:05 pm UTC"),
            ("5 21 * * *".into(), Some("UTC".into()))
        );
        assert_eq!(p("every Monday at 8am"), ("0 8 * * 1".into(), None));
        assert_eq!(
            p("every Mon, Wed and Fri at 18:30 America/New_York"),
            ("30 18 * * 1,3,5".into(), Some("America/New_York".into()))
        );
        assert_eq!(p("every weekend at noon"), ("0 12 * * 0,6".into(), None));
        assert_eq!(p("every night at midnight"), ("0 0 * * *".into(), None));
        assert_eq!(p("every 15 minutes"), ("*/15 * * * *".into(), None));
        assert_eq!(p("every minute"), ("* * * * *".into(), None));
        assert_eq!(p("every 2 hours"), ("0 */2 * * *".into(), None));
        assert_eq!(p("hourly"), ("0 * * * *".into(), None));
        assert_eq!(p("monthly on the 1st at 8am"), ("0 8 1 * *".into(), None));
        assert_eq!(
            p("every month on the 15th at 07:00 new york time"),
            ("0 7 15 * *".into(), Some("America/New_York".into()))
        );
        assert_eq!(p("Every weekday at 12am"), ("0 0 * * 1-5".into(), None));
        assert_eq!(p("every day at 12pm"), ("0 12 * * *".into(), None));
    }

    #[test]
    fn what_it_cannot_read_is_refused_not_guessed() {
        for bad in [
            "",
            "whenever",
            "every day",
            "every weekday at 25:00",
            "every day at 13pm",
            "every 90 minutes",
            "every day at 9am at 10am",
            "monthly at 9am",
            "every day at 9am Atlantis time",
            "every blorp at 9am",
        ] {
            assert!(parse(bad).is_err(), "{bad:?} should be refused");
        }
        assert_eq!(parse("every day").unwrap_err().key, "sched.plain_need_time");
        assert_eq!(
            parse("every day at 9am Atlantis time").unwrap_err().key,
            "sched.plain_zone"
        );
    }

    #[test]
    fn a_result_is_valid_cron() {
        for s in [
            "every weekday at 9am",
            "every 5 minutes",
            "daily at noon",
            "every sat at 6:15am",
        ] {
            let r = parse(s).unwrap();
            assert!(
                crate::sched::cron::Cron::parse(&r.cron).is_ok(),
                "{s}: {}",
                r.cron
            );
        }
    }
}
