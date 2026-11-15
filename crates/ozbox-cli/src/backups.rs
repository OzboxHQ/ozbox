//! Backup policy and the schedule's arithmetic. No I/O: everything here is a pure function of the settings, the
//! remembered state and the clock, so the rules (catch-up after downtime, one run per slot, retention, daylight-saving
//! time) are tested without a server, a provider or a box.
//!
//! The rules, in words:
//!
//! * A schedule is a wall-clock time in the person's own time zone: "every day at 02:30" stays 02:30 all year.
//! * A slot is served at most once. After downtime, only the **latest** missed slot is run (never a replay of every
//!   one), and only if it is within the catch-up window; an older one is recorded as missed.
//! * Any run that starts, scheduled or by hand, counts as serving the latest slot, so a manual backup just before the
//!   scheduled time is not followed by a second one.
//! * A schedule that was just turned on does not run for slots before it was turned on.
//! * Retention only ever deletes snapshots the schedule itself made (their ids are remembered), never one a person took
//!   by hand.

use std::collections::BTreeMap;

use ozbox_core::{BoxName, Result};
use serde::{Deserialize, Serialize};

use crate::settings::{bad, hhmm};
use crate::timezone;

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ScheduleKind {
    #[default]
    Off,
    Daily,
    Weekly,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct Schedule {
    pub kind: ScheduleKind,
    /// `HH:MM`, on the person's clock.
    pub time: String,
    /// Weekly only: 0 = Monday … 6 = Sunday.
    pub weekday: u8,
}

impl Default for Schedule {
    fn default() -> Self {
        Self {
            kind: ScheduleKind::Off,
            time: "02:00".into(),
            weekday: 6,
        }
    }
}

impl Schedule {
    pub fn is_on(&self) -> bool {
        self.kind != ScheduleKind::Off
    }

    pub fn validate(&self) -> Result<()> {
        if !hhmm(&self.time) {
            return Err(bad("a backup time must be HH:MM, for example 02:30"));
        }
        if self.weekday > 6 {
            return Err(bad("a backup weekday must be 0 (Monday) to 6 (Sunday)"));
        }
        Ok(())
    }

    fn hm(&self) -> Option<(i8, i8)> {
        Some((
            self.time.get(..2)?.parse().ok()?,
            self.time.get(3..5)?.parse().ok()?,
        ))
    }

    /// The latest slot at or before `now_ms`, in Unix milliseconds. `None` when the schedule is off or the zone unknown.
    pub fn prev_slot(&self, zone: &str, now_ms: u64) -> Option<u64> {
        let (h, m) = self.hm()?;
        match self.kind {
            ScheduleKind::Off => None,
            ScheduleKind::Daily => timezone::prev_local_time(zone, now_ms, h, m, None),
            ScheduleKind::Weekly => {
                timezone::prev_local_time(zone, now_ms, h, m, Some(self.weekday))
            }
        }
    }

    /// The first slot after `now_ms`.
    pub fn next_slot(&self, zone: &str, now_ms: u64) -> Option<u64> {
        let (h, m) = self.hm()?;
        if self.kind == ScheduleKind::Off {
            return None;
        }
        let mut after = now_ms;
        // At most eight days ahead: a weekly slot is never further.
        for _ in 0..9 {
            let c = timezone::next_local_time(zone, after, h, m)?;
            let ok = match self.kind {
                ScheduleKind::Weekly => {
                    timezone::weekday_monday_zero(zone, c) == Some(self.weekday)
                }
                _ => true,
            };
            if ok {
                return Some(c);
            }
            after = c;
        }
        None
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Retention {
    pub keep_daily: u32,
    pub keep_weekly: u32,
    pub keep_monthly: u32,
}

impl Default for Retention {
    fn default() -> Self {
        Self {
            keep_daily: 7,
            keep_weekly: 4,
            keep_monthly: 6,
        }
    }
}

impl Retention {
    pub fn validate(&self) -> Result<()> {
        let max = 3650;
        if self.keep_daily > max || self.keep_weekly > max || self.keep_monthly > max {
            return Err(bad("retention keeps at most 3650 of each kind"));
        }
        if self.keep_daily + self.keep_weekly + self.keep_monthly == 0 {
            return Err(bad("retention must keep at least one backup"));
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ResticKind {
    /// Any S3-compatible object store.
    S3,
    /// Backblaze B2.
    B2,
    /// A server reached over SSH (the box needs a key of its own for it).
    Sftp,
    /// A folder on a disk mounted on the box.
    Local,
}

/// Where a bring-your-own repository is. The location is not a secret; the password and keys are, and live only in the
/// secret store (see [`SECRET_PASSWORD`] and the others).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ResticTarget {
    pub kind: ResticKind,
    /// `https://objects.example.com/bucket/prefix` (S3), `bucket:prefix` (B2), `user@host:/path` (SFTP) or `/path`.
    pub location: String,
}

pub const SECRET_PASSWORD: &str = "restic-password";
pub const SECRET_ACCESS_KEY: &str = "restic-access-key";
pub const SECRET_SECRET_KEY: &str = "restic-secret-key";

impl ResticTarget {
    /// The restic repository string for this location.
    pub fn repository(&self) -> String {
        match self.kind {
            ResticKind::S3 => format!("s3:{}", self.location),
            ResticKind::B2 => format!("b2:{}", self.location),
            ResticKind::Sftp => format!("sftp:{}", self.location),
            ResticKind::Local => self.location.clone(),
        }
    }

    /// Whether this kind needs an access key and a secret key besides the password.
    pub fn needs_keys(&self) -> bool {
        matches!(self.kind, ResticKind::S3 | ResticKind::B2)
    }

    pub fn validate(&self) -> Result<()> {
        let l = &self.location;
        let plain = !l.is_empty()
            && l.len() <= 512
            && l.bytes()
                .all(|b| (0x21..=0x7e).contains(&b) && !matches!(b, b'"' | b'\'' | b'\\'));
        let ok = plain
            && match self.kind {
                ResticKind::S3 => l.starts_with("https://") && l.len() > 8,
                ResticKind::B2 => l.contains(':') && !l.starts_with(':') && !l.ends_with(':'),
                ResticKind::Sftp => l.contains('@') && l.contains(':'),
                ResticKind::Local => l.starts_with('/') && !l.split('/').any(|s| s == ".."),
            };
        if ok {
            Ok(())
        } else {
            Err(bad(
                "the repository location is not valid for its kind (S3 needs an https:// address, B2 bucket:prefix, SFTP user@host:/path, local an absolute path)",
            ))
        }
    }
}

/// A box's own choice, over the fleet's.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct BoxOverride {
    /// `Some(false)` turns this box's backups off whatever the fleet says.
    pub enabled: Option<bool>,
    /// A schedule of its own; `None` follows the fleet's.
    pub schedule: Option<Schedule>,
}

/// Settings → Backups, fleet-wide.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct Backups {
    pub schedule: Schedule,
    pub retention: Retention,
    /// Keep provider snapshots of `/work` (EBS snapshots on AWS).
    pub provider_snapshots: bool,
    /// Also (or instead) back up to a repository the person owns.
    pub restic: Option<ResticTarget>,
    /// How long after a missed slot it is still run when the server comes back, in hours.
    pub catch_up_hours: u32,
    pub overrides: BTreeMap<String, BoxOverride>,
}

impl Default for Backups {
    fn default() -> Self {
        Self {
            schedule: Schedule::default(),
            retention: Retention::default(),
            provider_snapshots: true,
            restic: None,
            catch_up_hours: 12,
            overrides: BTreeMap::new(),
        }
    }
}

impl Backups {
    pub fn validate(&self) -> Result<()> {
        self.schedule.validate()?;
        self.retention.validate()?;
        if let Some(r) = &self.restic {
            r.validate()?;
        }
        if !(1..=168).contains(&self.catch_up_hours) {
            return Err(bad("the catch-up window is 1 to 168 hours"));
        }
        if self.overrides.len() > 200 {
            return Err(bad("too many per-box backup settings"));
        }
        for (name, o) in &self.overrides {
            BoxName::new(name.as_str())
                .map_err(|_| bad("a per-box backup setting names an invalid box"))?;
            if let Some(s) = &o.schedule {
                s.validate()?;
            }
        }
        Ok(())
    }

    /// The schedule that applies to a box: its own, the fleet's, or none when the box is switched off.
    pub fn schedule_for(&self, box_name: &str) -> Schedule {
        let o = self.overrides.get(box_name);
        if o.and_then(|o| o.enabled) == Some(false) {
            return Schedule::default();
        }
        o.and_then(|o| o.schedule.clone())
            .unwrap_or_else(|| self.schedule.clone())
    }

    /// Whether anything would be backed up at all.
    pub fn has_destination(&self) -> bool {
        self.provider_snapshots || self.restic.is_some()
    }
}

/// How a run ended, for the list and the status.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RunRecord {
    pub ts_ms: u64,
    pub ok: bool,
    /// `snapshot` or `restic`.
    pub kind: String,
    /// Words a person reads; never a secret or a repository location.
    pub detail: String,
    pub scheduled: bool,
}

/// What is remembered about one box between runs and restarts.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct BoxBackupState {
    /// When the schedule was first seen on; slots before it are never run.
    pub armed_ms: Option<u64>,
    /// The latest slot that has been served (run, or recorded as missed).
    pub last_slot_ms: Option<u64>,
    pub last: Option<RunRecord>,
    /// Provider snapshots the schedule made: the only ones retention may delete.
    pub scheduled_snapshots: Vec<String>,
    /// A restore into this (new) box that is still being carried out: remembered, so a restarted server carries on.
    pub new_box_restore: Option<NewBoxRestore>,
}

/// A repository backup being restored into a new box.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct NewBoxRestore {
    pub from: String,
    pub snapshot: String,
    pub started_ms: u64,
    /// What it is waiting for now, in words a person reads. Never a secret.
    pub detail: String,
}

/// What the scheduler should do for one box now.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Due {
    /// Nothing is due (or the schedule is off).
    No,
    /// Run now, for this slot.
    Run { slot_ms: u64, late_ms: u64 },
    /// A slot passed while nothing ran and it is beyond the catch-up window: record it, do not run it.
    Missed { slot_ms: u64 },
}

pub fn due(sch: &Schedule, zone: &str, st: &BoxBackupState, now_ms: u64, window_ms: u64) -> Due {
    let Some(slot) = sch.prev_slot(zone, now_ms) else {
        return Due::No;
    };
    if let Some(armed) = st.armed_ms {
        if slot <= armed {
            return Due::No;
        }
    }
    if st.last_slot_ms.is_some_and(|l| l >= slot) {
        return Due::No;
    }
    let late = now_ms.saturating_sub(slot);
    if late <= window_ms {
        Due::Run {
            slot_ms: slot,
            late_ms: late,
        }
    } else {
        Due::Missed { slot_ms: slot }
    }
}

/// Which snapshots to delete so that only `keep` remain: the newest of each of the last `keep_daily` days that have a
/// snapshot, `keep_weekly` ISO weeks and `keep_monthly` months, counted on the person's clock. The newest snapshot is
/// always kept. `items` are `(id, created_ms)`.
pub fn prune(items: &[(String, u64)], keep: &Retention, zone: &str) -> Vec<String> {
    let mut sorted: Vec<&(String, u64)> = items.iter().collect();
    sorted.sort_by(|a, b| b.1.cmp(&a.1).then_with(|| a.0.cmp(&b.0)));
    let mut keep_ids: std::collections::BTreeSet<&str> = std::collections::BTreeSet::new();
    if let Some(newest) = sorted.first() {
        keep_ids.insert(newest.0.as_str());
    }
    let (mut days, mut weeks, mut months) = (Vec::new(), Vec::new(), Vec::new());
    for (id, ms) in &sorted {
        let Some((d, w, m)) = timezone::calendar_keys(zone, *ms) else {
            // An unreadable time is never a reason to delete.
            keep_ids.insert(id.as_str());
            continue;
        };
        if !days.contains(&d) && days.len() < keep.keep_daily as usize {
            days.push(d);
            keep_ids.insert(id.as_str());
        }
        if !weeks.contains(&w) && weeks.len() < keep.keep_weekly as usize {
            weeks.push(w);
            keep_ids.insert(id.as_str());
        }
        if !months.contains(&m) && months.len() < keep.keep_monthly as usize {
            months.push(m);
            keep_ids.insert(id.as_str());
        }
    }
    let mut gone: Vec<String> = sorted
        .iter()
        .filter(|(id, _)| !keep_ids.contains(id.as_str()))
        .map(|(id, _)| id.clone())
        .collect();
    gone.sort();
    gone
}

/// A monthly estimate of what the box's provider snapshots cost, in the price book's currency: the most snapshots the
/// retention can hold times the work disk times the provider's price per GB-month. It is an upper bound (snapshots
/// are incremental), so the screen says "estimate". `None` when there is no price.
pub fn estimate_monthly(
    work_disk_gb: u32,
    keep: &Retention,
    usd_per_gb_month: Option<f64>,
) -> Option<f64> {
    let price = usd_per_gb_month?;
    let count = f64::from(keep.keep_daily + keep.keep_weekly + keep.keep_monthly);
    Some(count * f64::from(work_disk_gb) * price)
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use jiff::Timestamp;

    fn ms(s: &str) -> u64 {
        s.parse::<Timestamp>().unwrap().as_millisecond() as u64
    }

    fn daily(t: &str) -> Schedule {
        Schedule {
            kind: ScheduleKind::Daily,
            time: t.into(),
            weekday: 0,
        }
    }

    const HOUR: u64 = 3_600_000;
    const NY: &str = "America/New_York";

    #[test]
    fn a_daily_slot_is_the_persons_wall_clock_all_year() {
        let s = daily("02:30");
        // Lagos has no daylight saving: 02:30 is 01:30 UTC always.
        assert_eq!(
            s.prev_slot("Africa/Lagos", ms("2026-11-09T12:00:00Z")),
            Some(ms("2026-11-09T01:30:00Z"))
        );
        // New York: 02:30 is 07:30 UTC in winter and 06:30 UTC in summer.
        assert_eq!(
            s.prev_slot(NY, ms("2026-01-15T12:00:00Z")),
            Some(ms("2026-01-15T07:30:00Z"))
        );
        assert_eq!(
            s.prev_slot(NY, ms("2026-07-15T12:00:00Z")),
            Some(ms("2026-07-15T06:30:00Z"))
        );
        // Before today's slot the latest slot is yesterday's.
        assert_eq!(
            s.prev_slot("Africa/Lagos", ms("2026-11-09T00:30:00Z")),
            Some(ms("2026-11-08T01:30:00Z"))
        );
    }

    #[test]
    fn a_time_the_clock_skips_runs_just_after_the_jump_and_a_repeated_time_runs_once() {
        // 2026-03-08 in New York: 02:00 -> 03:00. 02:30 does not exist; it is taken as 03:30 EDT = 07:30 UTC.
        let s = daily("02:30");
        assert_eq!(
            s.prev_slot(NY, ms("2026-03-08T12:00:00Z")),
            Some(ms("2026-03-08T07:30:00Z"))
        );
        assert_eq!(
            s.prev_slot(NY, ms("2026-03-09T12:00:00Z")),
            Some(ms("2026-03-09T06:30:00Z"))
        );
        // 2026-11-01: 01:00-02:00 happens twice. 01:30 means the first one, 05:30 UTC (EDT).
        let s = daily("01:30");
        assert_eq!(
            s.prev_slot(NY, ms("2026-11-01T12:00:00Z")),
            Some(ms("2026-11-01T05:30:00Z"))
        );
        // between the two 01:30s there is still exactly one slot that day
        let mut st = BoxBackupState::default();
        let w = 12 * HOUR;
        let first = ms("2026-11-01T05:30:00Z");
        assert_eq!(
            due(&s, NY, &st, first + 60_000, w),
            Due::Run {
                slot_ms: first,
                late_ms: 60_000
            }
        );
        st.last_slot_ms = Some(first);
        assert_eq!(
            due(&s, NY, &st, ms("2026-11-01T06:31:00Z"), w),
            Due::No,
            "the repeated 01:30 does not run again"
        );
    }

    #[test]
    fn the_day_the_clocks_change_is_not_23_or_25_hours_of_waiting() {
        let s = daily("12:00");
        // Noon the day before and the day of the spring change differ by 23 real hours.
        let a = s.prev_slot(NY, ms("2026-03-07T23:00:00Z")).unwrap();
        let b = s.prev_slot(NY, ms("2026-03-08T23:00:00Z")).unwrap();
        assert_eq!(b - a, 23 * HOUR);
        let next = s.next_slot(NY, ms("2026-03-07T18:00:00Z")).unwrap();
        assert_eq!(next, ms("2026-03-08T16:00:00Z"), "noon EDT");
    }

    #[test]
    fn weekly_runs_on_its_weekday_only() {
        let s = Schedule {
            kind: ScheduleKind::Weekly,
            time: "03:00".into(),
            weekday: 6, // Sunday
        };
        // 2026-11-09 is a Monday: the latest Sunday slot was 2026-11-08 03:00 Lagos = 02:00 UTC.
        assert_eq!(
            s.prev_slot("Africa/Lagos", ms("2026-11-09T12:00:00Z")),
            Some(ms("2026-11-08T02:00:00Z"))
        );
        assert_eq!(
            s.next_slot("Africa/Lagos", ms("2026-11-09T12:00:00Z")),
            Some(ms("2026-11-15T02:00:00Z"))
        );
        assert_eq!(
            Schedule::default().prev_slot("UTC", 5),
            None,
            "off has no slot"
        );
        assert_eq!(Schedule::default().next_slot("UTC", 5), None);
    }

    #[test]
    fn after_downtime_only_the_latest_missed_slot_runs_and_only_inside_the_window() {
        let s = daily("02:00");
        let z = "UTC";
        let w = 12 * HOUR;
        let st = BoxBackupState {
            armed_ms: Some(ms("2026-11-01T00:00:00Z")),
            last_slot_ms: Some(ms("2026-11-03T02:00:00Z")),
            ..Default::default()
        };
        // The server was down for days and comes back at 05:00 on the 9th: one run, for the 9th's slot, 3 hours late.
        assert_eq!(
            due(&s, z, &st, ms("2026-11-09T05:00:00Z"), w),
            Due::Run {
                slot_ms: ms("2026-11-09T02:00:00Z"),
                late_ms: 3 * HOUR
            }
        );
        // Back at 20:00 the same day, beyond the window: recorded as missed, not run.
        assert_eq!(
            due(&s, z, &st, ms("2026-11-09T20:00:00Z"), w),
            Due::Missed {
                slot_ms: ms("2026-11-09T02:00:00Z")
            }
        );
        // Once served, nothing more is due until the next slot.
        let served = BoxBackupState {
            last_slot_ms: Some(ms("2026-11-09T02:00:00Z")),
            ..st.clone()
        };
        assert_eq!(due(&s, z, &served, ms("2026-11-09T23:00:00Z"), w), Due::No);
    }

    #[test]
    fn a_schedule_that_was_just_turned_on_does_not_run_for_earlier_slots() {
        let s = daily("02:00");
        let w = 12 * HOUR;
        let st = BoxBackupState {
            armed_ms: Some(ms("2026-11-09T03:00:00Z")),
            ..Default::default()
        };
        assert_eq!(due(&s, "UTC", &st, ms("2026-11-09T04:00:00Z"), w), Due::No);
        assert_eq!(
            due(&s, "UTC", &st, ms("2026-11-10T02:10:00Z"), w),
            Due::Run {
                slot_ms: ms("2026-11-10T02:00:00Z"),
                late_ms: 10 * 60_000
            }
        );
        assert_eq!(
            due(
                &Schedule::default(),
                "UTC",
                &st,
                ms("2026-11-10T02:10:00Z"),
                w
            ),
            Due::No
        );
    }

    fn snaps(days: &[&str]) -> Vec<(String, u64)> {
        days.iter()
            .enumerate()
            .map(|(i, d)| (format!("s{i}"), ms(d)))
            .collect()
    }

    #[test]
    fn retention_keeps_the_newest_of_each_day_week_and_month_and_always_the_newest_snapshot() {
        // Two snapshots on Nov 8 (only the later counts for that day), one a day for Nov 5-7, then older ones.
        let items = snaps(&[
            "2026-11-08T01:00:00Z", // s0 older of the 8th
            "2026-11-08T23:00:00Z", // s1 newest
            "2026-11-07T12:00:00Z", // s2
            "2026-11-06T12:00:00Z", // s3
            "2026-10-30T12:00:00Z", // s4 older week
            "2026-10-02T12:00:00Z", // s5 older month
            "2026-01-05T12:00:00Z", // s6 much older
        ]);
        let keep = Retention {
            keep_daily: 3,
            keep_weekly: 0,
            keep_monthly: 0,
        };
        // 3 days: Nov 8 (s1), 7 (s2), 6 (s3). Everything else goes, including the older snapshot of the 8th.
        assert_eq!(prune(&items, &keep, "UTC"), ["s0", "s4", "s5", "s6"]);
        // Monthly counts months that have a snapshot (as restic does): Nov (s1), Oct (s4, the 30th) and Jan (s6).
        let keep = Retention {
            keep_daily: 1,
            keep_weekly: 0,
            keep_monthly: 3,
        };
        assert_eq!(
            prune(&items, &keep, "UTC"),
            ["s0", "s2", "s3", "s5"].map(String::from)
        );
        // Weekly: ISO weeks. Nov 8 (Sun) is in week 45, Nov 6-7 (Fri-Sat) in week 45 too, Oct 30 in week 44.
        let keep = Retention {
            keep_daily: 0,
            keep_weekly: 2,
            keep_monthly: 0,
        };
        assert_eq!(
            prune(&items, &keep, "UTC"),
            ["s0", "s2", "s3", "s5", "s6"].map(String::from)
        );
        // A policy that would keep nothing still keeps the newest.
        let keep = Retention {
            keep_daily: 0,
            keep_weekly: 0,
            keep_monthly: 0,
        };
        assert!(!prune(&items, &keep, "UTC").contains(&"s1".to_string()));
        assert!(prune(&[], &keep, "UTC").is_empty());
    }

    #[test]
    fn a_day_is_the_persons_day_not_utcs() {
        // 23:30 and 00:30 UTC are the same evening in New York, so only the later one is the day's.
        let items = snaps(&[
            "2026-06-10T03:30:00Z",
            "2026-06-10T04:30:00Z",
            "2026-06-09T12:00:00Z",
        ]);
        let keep = Retention {
            keep_daily: 2,
            keep_weekly: 0,
            keep_monthly: 0,
        };
        // New York (EDT): 03:30Z is June 9 23:30, 04:30Z is June 10 00:30, 12:00Z June 9 08:00.
        // s0 (June 9 23:30) is the later of June 9's two, so the morning one (s2) goes.
        assert_eq!(prune(&items, &keep, NY), ["s2"]);
        // In UTC, s0 and s1 are on the same day (June 10) instead, and the earlier of them goes.
        assert_eq!(
            prune(&items, &keep, "UTC"),
            ["s0"].map(String::from).to_vec()
        );
    }

    #[test]
    fn policy_validation_refuses_what_cannot_work() {
        let mut b = Backups::default();
        b.validate().unwrap();
        b.schedule.time = "25:00".into();
        assert!(b.validate().is_err());
        b.schedule.time = "02:00".into();
        b.retention = Retention {
            keep_daily: 0,
            keep_weekly: 0,
            keep_monthly: 0,
        };
        assert!(b.validate().is_err());
        b.retention = Retention::default();
        b.catch_up_hours = 0;
        assert!(b.validate().is_err());
        b.catch_up_hours = 12;
        for (kind, loc, ok) in [
            (ResticKind::S3, "https://objects.example.com/b/p", true),
            (ResticKind::S3, "http://objects.example.com/b", false),
            (ResticKind::B2, "bucket:prefix", true),
            (ResticKind::B2, "bucket", false),
            (ResticKind::Sftp, "backup@host.example.com:/srv/x", true),
            (ResticKind::Sftp, "host", false),
            (ResticKind::Local, "/mnt/backups/ozbox", true),
            (ResticKind::Local, "/mnt/../etc", false),
            (ResticKind::Local, "relative", false),
        ] {
            b.restic = Some(ResticTarget {
                kind,
                location: loc.into(),
            });
            assert_eq!(b.validate().is_ok(), ok, "{loc}");
        }
        b.restic = None;
        b.overrides
            .insert("Bad_Name".into(), BoxOverride::default());
        assert!(b.validate().is_err());
    }

    #[test]
    fn a_box_follows_the_fleet_unless_it_has_its_own_or_is_off() {
        let mut b = Backups {
            schedule: daily("02:00"),
            ..Backups::default()
        };
        b.overrides.insert(
            "quiet".into(),
            BoxOverride {
                enabled: Some(false),
                schedule: None,
            },
        );
        b.overrides.insert(
            "early".into(),
            BoxOverride {
                enabled: None,
                schedule: Some(daily("05:00")),
            },
        );
        assert_eq!(b.schedule_for("any").time, "02:00");
        assert!(!b.schedule_for("quiet").is_on());
        assert_eq!(b.schedule_for("early").time, "05:00");
    }

    #[test]
    fn the_repository_string_and_the_estimate() {
        let t = ResticTarget {
            kind: ResticKind::S3,
            location: "https://o.example.com/b".into(),
        };
        assert_eq!(t.repository(), "s3:https://o.example.com/b");
        assert!(t.needs_keys());
        assert!(!ResticTarget {
            kind: ResticKind::Local,
            location: "/m".into()
        }
        .needs_keys());
        let keep = Retention {
            keep_daily: 7,
            keep_weekly: 4,
            keep_monthly: 6,
        };
        let e = estimate_monthly(100, &keep, Some(0.05)).unwrap();
        assert!((e - 85.0).abs() < 1e-9);
        assert_eq!(estimate_monthly(100, &keep, None), None);
    }
}
