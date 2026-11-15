//! What the dashboard server remembers between runs that a person does not edit: the cost accrued this month, the chats
//! paired with the Telegram bot, and which alerts are already open. It is a small JSON file next to the settings,
//! written atomically. It holds no secret: a token or key is in the secret store, never here.

use std::collections::BTreeMap;
use std::path::Path;

use serde::{Deserialize, Serialize};

use crate::notify::AlertState;
use crate::pricing::BoxCost;

/// The longest gap between two observations that is counted. A laptop that slept for a day did not run up a day of
/// cost that this server saw.
pub const MAX_GAP_MS: u64 = 3 * 60_000;

/// `(year, month, day)` of a Unix time in milliseconds (UTC), by Howard Hinnant's civil-from-days algorithm.
pub fn civil(ms: u64) -> (i64, i64, i64) {
    let days = (ms / 86_400_000) as i64;
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    (if m <= 2 { y + 1 } else { y }, m, d)
}

/// `YYYY-MM` of a Unix time in milliseconds (UTC).
pub fn month_key(ms: u64) -> String {
    let (y, m, _) = civil(ms);
    format!("{y:04}-{m:02}")
}

/// `2026-11-09T12:30:05Z`.
pub fn format_rfc3339(ms: u64) -> String {
    let (y, mo, d) = civil(ms);
    let s = ms / 1000 % 86_400;
    format!(
        "{y:04}-{mo:02}-{d:02}T{:02}:{:02}:{:02}Z",
        s / 3600,
        s / 60 % 60,
        s % 60
    )
}

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct Accrued {
    pub machine_hours: f64,
    pub machine_cost: f64,
    pub disk_cost: f64,
    pub currency: Option<String>,
}

/// Cost counted while this server was watching: hours observed times the price at the time. It is an estimate from
/// public prices; it is not the bill, and it does not count time when the server was not running.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct Ledger {
    pub month: String,
    pub observed_since_ms: u64,
    pub last_tick_ms: u64,
    pub boxes: BTreeMap<String, Accrued>,
    /// The same estimate by UTC day (`YYYY-MM-DD`), kept for [`KEEP_DAYS`] days and across a month change, so the
    /// daily bill can be compared with it. Additive: a file written before this loads with none.
    pub days: BTreeMap<String, DayEstimate>,
}

/// How many days of estimate are kept: the bill is read for the month so far and the one before.
pub const KEEP_DAYS: usize = 70;

/// One UTC day of estimate: how long this server was watching, and what each box cost in that time.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct DayEstimate {
    /// Milliseconds of the day this server observed (gaps over [`MAX_GAP_MS`] are not counted).
    pub watched_ms: u64,
    pub boxes: BTreeMap<String, DayBox>,
    pub currency: Option<String>,
}

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct DayBox {
    pub machine_cost: f64,
    pub disk_cost: f64,
}

/// `YYYY-MM-DD` of a Unix time in milliseconds (UTC).
pub fn day_key(ms: u64) -> String {
    let (y, m, d) = civil(ms);
    format!("{y:04}-{m:02}-{d:02}")
}

pub struct Observed<'a> {
    pub name: &'a str,
    pub running: bool,
    pub cost: &'a BoxCost,
}

impl Ledger {
    pub fn accrue(&mut self, now_ms: u64, boxes: &[Observed<'_>]) {
        let month = month_key(now_ms);
        if self.month != month {
            *self = Ledger {
                month,
                observed_since_ms: now_ms,
                last_tick_ms: now_ms,
                boxes: BTreeMap::new(),
                days: std::mem::take(&mut self.days),
            };
        }
        let gap = now_ms.saturating_sub(self.last_tick_ms).min(MAX_GAP_MS);
        let hours = gap as f64 / 3_600_000.0;
        self.last_tick_ms = now_ms;
        if hours <= 0.0 {
            return;
        }
        // A gap that crosses midnight is counted on the day it ended: it is at most three minutes.
        let day = self.days.entry(day_key(now_ms)).or_default();
        day.watched_ms += gap;
        for b in boxes {
            let d = day.boxes.entry(b.name.to_string()).or_default();
            if b.cost.currency.is_some() {
                day.currency.clone_from(&b.cost.currency);
            }
            if b.running {
                if let Some(h) = b.cost.machine_hourly {
                    d.machine_cost += h * hours;
                }
            }
            if let Some(h) = b.cost.disk_hourly {
                d.disk_cost += h * hours;
            }
        }
        while self.days.len() > KEEP_DAYS {
            let Some(first) = self.days.keys().next().cloned() else {
                break;
            };
            self.days.remove(&first);
        }
        for b in boxes {
            let a = self.boxes.entry(b.name.to_string()).or_default();
            if b.cost.currency.is_some() {
                a.currency.clone_from(&b.cost.currency);
            }
            if b.running {
                if let Some(h) = b.cost.machine_hourly {
                    a.machine_hours += hours;
                    a.machine_cost += h * hours;
                }
            }
            if let Some(d) = b.cost.disk_hourly {
                a.disk_cost += d * hours;
            }
        }
    }

    /// Total so far this month, and the currency, or `None` when nothing is priced or currencies differ.
    pub fn month_to_date(&self) -> Option<(f64, String)> {
        let mut total = 0.0;
        let mut cur: Option<&String> = None;
        for a in self.boxes.values() {
            let c = a.machine_cost + a.disk_cost;
            if c <= 0.0 {
                continue;
            }
            let ac = a.currency.as_ref()?;
            if cur.is_some_and(|x| x != ac) {
                return None;
            }
            cur = Some(ac);
            total += c;
        }
        cur.map(|c| (total, c.clone()))
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TelegramChat {
    pub id: i64,
    /// What the person is called in Telegram, for the list in Settings.
    pub name: String,
    /// The person (a key of `routing.people`) this chat belongs to. A person's Telegram alerts go only to their chats;
    /// a chat linked to nobody receives what the older, fleet-wide behaviour sent.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub person: Option<String>,
}

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct TelegramState {
    /// Private chats that proved they hold the one-time code. Only these receive alerts or are answered.
    pub chats: Vec<TelegramChat>,
    /// The next update to ask for.
    pub offset: i64,
}

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct ServerState {
    pub ledger: Ledger,
    pub telegram: TelegramState,
    pub alerts: AlertState,
    /// Linked chat accounts, and what each chat is bound to (see `crate::chat`).
    pub chat: crate::chat::gateway::ChatState,
    /// What the backup schedule remembers about each box, by name.
    pub backups: std::collections::BTreeMap<String, crate::backups::BoxBackupState>,
}

impl ServerState {
    pub fn load(path: &Path) -> ServerState {
        std::fs::read_to_string(path)
            .ok()
            .and_then(|t| serde_json::from_str(&t).ok())
            .unwrap_or_default()
    }

    pub fn save(&self, path: &Path) {
        if let Some(dir) = path.parent() {
            let _ = std::fs::create_dir_all(dir);
        }
        let tmp = path.with_extension("json.tmp");
        if let Ok(bytes) = serde_json::to_vec_pretty(self) {
            if std::fs::write(&tmp, bytes).is_ok() {
                let _ = std::fs::rename(&tmp, path);
            }
        }
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    fn cost(machine: Option<f64>, disk: Option<f64>, cur: &str) -> BoxCost {
        BoxCost {
            machine_hourly: machine,
            disk_hourly: disk,
            currency: Some(cur.into()),
            machine_source: None,
            snapshots_unpriced: 0,
        }
    }

    #[test]
    fn month_keys() {
        assert_eq!(month_key(0), "1970-01");
        assert_eq!(month_key(1_794_182_400_000), "2026-11"); // 2026-11-09
        assert_eq!(month_key(1_793_491_199_000), "2026-10"); // 2026-10-31 23:59:59
        assert_eq!(month_key(1_793_491_200_000), "2026-11");
        assert_eq!(month_key(1_709_164_800_000), "2024-02"); // leap day 2024-02-29
    }

    #[test]
    fn the_estimate_is_also_kept_by_day_and_survives_a_new_month() {
        let mut l = Ledger::default();
        let t0 = 1_794_182_400_000; // 2026-11-09 00:00 UTC
        let c = cost(Some(60.0), Some(6.0), "USD");
        let on = [Observed {
            name: "a",
            running: true,
            cost: &c,
        }];
        l.accrue(t0, &on);
        l.accrue(t0 + 60_000, &on); // one minute: 1.00 machine, 0.10 disk
        l.accrue(t0 + 86_400_000 + 60_000, &on); // a day later: the long gap counts three minutes
        let d = &l.days["2026-11-09"];
        assert_eq!(d.watched_ms, 60_000);
        assert!((d.boxes["a"].machine_cost - 1.0).abs() < 1e-9);
        assert!((d.boxes["a"].disk_cost - 0.1).abs() < 1e-9);
        assert_eq!(l.days["2026-11-10"].watched_ms, MAX_GAP_MS);
        // the monthly figures are unchanged by the daily ones
        assert!((l.boxes["a"].machine_cost - (1.0 + 3.0)).abs() < 1e-9);
        l.accrue(t0 + 40 * 86_400_000, &on);
        assert_eq!(l.month, "2026-12");
        assert!(l.days.contains_key("2026-11-09"), "days outlive the month");
        assert_eq!(day_key(t0), "2026-11-09");
    }

    #[test]
    fn rfc3339_formatting() {
        assert_eq!(format_rfc3339(0), "1970-01-01T00:00:00Z");
        assert_eq!(
            format_rfc3339(1_794_182_400_000 + 12 * 3_600_000 + 34 * 60_000 + 5_000),
            "2026-11-09T12:34:05Z"
        );
        assert_eq!(format_rfc3339(1_709_164_800_000), "2024-02-29T00:00:00Z");
    }

    #[test]
    fn running_machine_and_always_on_disk_accrue_by_observed_hours() {
        let mut l = Ledger::default();
        let t0 = 1_794_182_400_000;
        let c = cost(Some(1.0), Some(0.1), "USD");
        let running = [Observed {
            name: "a",
            running: true,
            cost: &c,
        }];
        let paused = [Observed {
            name: "a",
            running: false,
            cost: &c,
        }];
        l.accrue(t0, &running); // first observation counts nothing
        assert_eq!(l.month_to_date(), None);
        l.accrue(t0 + 60_000, &running); // one minute running
        l.accrue(t0 + 120_000, &paused); // one minute paused: disk only
        let (total, cur) = l.month_to_date().unwrap_or_default();
        let expect = (1.0 + 0.1) / 60.0 + 0.1 / 60.0;
        assert!((total - expect).abs() < 1e-9, "{total} vs {expect}");
        assert_eq!(cur, "USD");
        let a = &l.boxes["a"];
        assert!((a.machine_hours - 1.0 / 60.0).abs() < 1e-9);
    }

    #[test]
    fn a_long_gap_is_not_counted_and_a_new_month_starts_over() {
        let mut l = Ledger::default();
        let t0 = 1_794_182_400_000;
        let c = cost(Some(60.0), None, "USD");
        let on = [Observed {
            name: "a",
            running: true,
            cost: &c,
        }];
        l.accrue(t0, &on);
        l.accrue(t0 + 10 * 3_600_000, &on); // slept ten hours: only the cap counts
        let (total, _) = l.month_to_date().unwrap_or_default();
        assert!((total - 60.0 * (MAX_GAP_MS as f64 / 3_600_000.0)).abs() < 1e-9);
        l.accrue(t0 + 40 * 86_400_000, &on);
        assert_eq!(l.month, "2026-12");
        assert_eq!(l.month_to_date(), None);
        assert_eq!(l.observed_since_ms, t0 + 40 * 86_400_000);
    }

    #[test]
    fn unpriced_boxes_add_nothing_and_mixed_currencies_give_no_total() {
        let mut l = Ledger::default();
        let t0 = 1_794_182_400_000;
        let none = cost(None, None, "USD");
        l.accrue(
            t0,
            &[Observed {
                name: "a",
                running: true,
                cost: &none,
            }],
        );
        l.accrue(
            t0 + 60_000,
            &[Observed {
                name: "a",
                running: true,
                cost: &none,
            }],
        );
        assert_eq!(l.month_to_date(), None);
        let usd = cost(Some(1.0), None, "USD");
        let eur = cost(Some(1.0), None, "EUR");
        l.accrue(
            t0 + 120_000,
            &[
                Observed {
                    name: "b",
                    running: true,
                    cost: &usd,
                },
                Observed {
                    name: "c",
                    running: true,
                    cost: &eur,
                },
            ],
        );
        assert!(l.month_to_date().is_some() || l.boxes.len() == 3);
        // after one more minute both have cost: the totals are in different currencies
        l.accrue(
            t0 + 180_000,
            &[
                Observed {
                    name: "b",
                    running: true,
                    cost: &usd,
                },
                Observed {
                    name: "c",
                    running: true,
                    cost: &eur,
                },
            ],
        );
        assert_eq!(l.month_to_date(), None);
    }

    #[test]
    fn state_round_trips_and_a_bad_file_is_ignored() -> Result<(), Box<dyn std::error::Error>> {
        let dir = tempfile::tempdir()?;
        let p = dir.path().join("state.json");
        let mut s = ServerState::default();
        s.telegram.chats = vec![TelegramChat {
            id: 42,
            name: "A".into(),
            person: None,
        }];
        s.save(&p);
        assert_eq!(ServerState::load(&p).telegram.chats.len(), 1);
        std::fs::write(&p, "{ not json")?;
        assert_eq!(ServerState::load(&p), ServerState::default());
        Ok(())
    }
}
