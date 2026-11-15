//! Embedded time-series store.
//!
//! Layout under the store directory (default `/work/.ozbox/metrics`):
//!
//! - an in-memory ring of raw 5 s samples covering the last 15 minutes (lost on restart by design);
//! - `1m/YYYYMMDD.jsonl` - one JSON line per finished minute, one file per UTC day, kept 7 days;
//! - `1h/YYYYMM.jsonl`   - one JSON line per finished hour, one file per UTC month, kept 13 months.
//!
//! A line is a [`Point`]: its bucket start, how many raw samples it summarises, and min / max / mean / last per
//! field. Files are append-only and fsynced at every rollup boundary. A crash can leave one torn last line; readers
//! skip any line that does not parse, and the next append starts on a fresh line. Retention is enforced at each
//! rollup, and the total size of the directory is bounded: when over budget the oldest segments go first (a full
//! disk degrades history, never the box). An unfinished minute or hour is held only in memory.

use std::collections::{BTreeMap, VecDeque};
use std::fs::{self, File, OpenOptions};
use std::io::{self, BufRead, BufReader, Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};

use ozbox_core::MetricsSample;
use serde::{Deserialize, Serialize};

use crate::timeutil::{
    day_stamp, day_stamp_start_ms, month_stamp, month_stamp_start_ms, utc_parts, DAY_MS, HOUR_MS,
    MINUTE_MS,
};

/// Most points a single query returns (the newest are kept).
pub const MAX_QUERY_POINTS: usize = 10_000;

#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
pub struct Agg {
    pub min: f64,
    pub max: f64,
    pub mean: f64,
    pub last: f64,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Point {
    pub ts_ms: u64,
    /// Number of raw samples summarised (1 for a raw point).
    pub n: u32,
    pub fields: BTreeMap<String, Agg>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Step {
    Raw5s,
    Minute,
    Hour,
}

impl Step {
    pub fn parse(s: &str) -> Option<Step> {
        match s {
            "5s" => Some(Step::Raw5s),
            "1m" => Some(Step::Minute),
            "1h" => Some(Step::Hour),
            _ => None,
        }
    }
}

#[derive(Debug, Clone)]
pub struct StoreConfig {
    pub dir: PathBuf,
    pub ring_ms: u64,
    pub keep_minute_days: u64,
    pub keep_hour_months: u64,
    pub max_bytes: u64,
}

impl StoreConfig {
    pub fn new(dir: impl Into<PathBuf>) -> Self {
        Self {
            dir: dir.into(),
            ring_ms: 15 * MINUTE_MS,
            keep_minute_days: 7,
            keep_hour_months: 13,
            max_bytes: 256 * 1024 * 1024,
        }
    }
}

struct FieldAcc {
    min: f64,
    max: f64,
    sum: f64,
    last: f64,
}

/// Running summary of one bucket.
struct Acc {
    start: u64,
    n: u64,
    fields: BTreeMap<String, FieldAcc>,
}

impl Acc {
    fn new(start: u64) -> Self {
        Self {
            start,
            n: 0,
            fields: BTreeMap::new(),
        }
    }

    /// Fold in a summary of `count` samples (a raw sample is count 1 with min = max = mean = last).
    fn add(&mut self, count: u64, fields: &BTreeMap<String, Agg>) {
        self.n += count;
        for (k, a) in fields {
            let f = self.fields.entry(k.clone()).or_insert(FieldAcc {
                min: a.min,
                max: a.max,
                sum: 0.0,
                last: a.last,
            });
            f.min = f.min.min(a.min);
            f.max = f.max.max(a.max);
            f.sum += a.mean * count as f64;
            f.last = a.last;
        }
    }

    fn finish(&self) -> Point {
        let n = self.n.max(1) as f64;
        Point {
            ts_ms: self.start,
            n: self.n as u32,
            fields: self
                .fields
                .iter()
                .map(|(k, f)| {
                    (
                        k.clone(),
                        Agg {
                            min: f.min,
                            max: f.max,
                            mean: f.sum / n,
                            last: f.last,
                        },
                    )
                })
                .collect(),
        }
    }
}

fn raw_point(s: &MetricsSample) -> Point {
    Point {
        ts_ms: s.ts_ms,
        n: 1,
        fields: s
            .fields()
            .into_iter()
            .map(|(k, v)| {
                (
                    k,
                    Agg {
                        min: v,
                        max: v,
                        mean: v,
                        last: v,
                    },
                )
            })
            .collect(),
    }
}

pub struct Store {
    cfg: StoreConfig,
    ring: VecDeque<Point>,
    minute: Option<Acc>,
    hour: Option<Acc>,
}

impl Store {
    pub fn open(cfg: StoreConfig) -> io::Result<Self> {
        fs::create_dir_all(cfg.dir.join("1m"))?;
        fs::create_dir_all(cfg.dir.join("1h"))?;
        Ok(Self {
            cfg,
            ring: VecDeque::new(),
            minute: None,
            hour: None,
        })
    }

    /// Record one raw sample. Rollups are written (and fsynced) when a minute or hour finishes; the error, if any,
    /// concerns only that write - the sample is already in the ring.
    pub fn push(&mut self, sample: &MetricsSample) -> io::Result<()> {
        let p = raw_point(sample);
        let ts = p.ts_ms;
        while self
            .ring
            .front()
            .is_some_and(|f| f.ts_ms + self.cfg.ring_ms < ts)
        {
            self.ring.pop_front();
        }
        let minute_start = ts / MINUTE_MS * MINUTE_MS;
        let mut result = Ok(());
        if self
            .minute
            .as_ref()
            .is_some_and(|m| m.start != minute_start)
        {
            result = self.finish_minute(ts);
        }
        self.minute
            .get_or_insert_with(|| Acc::new(minute_start))
            .add(1, &p.fields);
        self.ring.push_back(p);
        result
    }

    fn finish_minute(&mut self, now_ms: u64) -> io::Result<()> {
        let Some(acc) = self.minute.take() else {
            return Ok(());
        };
        let point = acc.finish();
        let mut result = self.append(
            &self
                .cfg
                .dir
                .join("1m")
                .join(format!("{}.jsonl", day_stamp(point.ts_ms))),
            &point,
        );

        let hour_start = point.ts_ms / HOUR_MS * HOUR_MS;
        if self.hour.as_ref().is_some_and(|h| h.start != hour_start) {
            if let Some(h) = self.hour.take() {
                let hp = h.finish();
                let r = self.append(
                    &self
                        .cfg
                        .dir
                        .join("1h")
                        .join(format!("{}.jsonl", month_stamp(hp.ts_ms))),
                    &hp,
                );
                result = result.and(r);
            }
        }
        self.hour
            .get_or_insert_with(|| Acc::new(hour_start))
            .add(u64::from(point.n), &point.fields);
        let r = self.enforce_retention(now_ms);
        result.and(r)
    }

    /// Append one JSON line, starting on a fresh line if a crash left a torn one, then fsync.
    fn append(&self, path: &Path, point: &Point) -> io::Result<()> {
        let mut f = OpenOptions::new()
            .create(true)
            .append(true)
            .read(true)
            .open(path)?;
        let len = f.metadata()?.len();
        let mut line = String::new();
        if len > 0 {
            let mut last = [0u8; 1];
            f.seek(SeekFrom::Start(len - 1))?;
            f.read_exact(&mut last)?;
            if last[0] != b'\n' {
                line.push('\n');
            }
        }
        line.push_str(&serde_json::to_string(point).map_err(io::Error::other)?);
        line.push('\n');
        f.write_all(line.as_bytes())?;
        f.sync_data()
    }

    /// Delete segments past their retention, then the oldest ones while the directory is over its size budget.
    pub fn enforce_retention(&self, now_ms: u64) -> io::Result<()> {
        let mut files: Vec<(u64, PathBuf, u64, bool)> = Vec::new(); // (start, path, size, is_minute)
        for (sub, is_minute) in [("1m", true), ("1h", false)] {
            let Ok(rd) = fs::read_dir(self.cfg.dir.join(sub)) else {
                continue;
            };
            for e in rd.flatten() {
                let path = e.path();
                let stem = path.file_stem().and_then(|s| s.to_str()).unwrap_or("");
                let start = if is_minute {
                    day_stamp_start_ms(stem)
                } else {
                    month_stamp_start_ms(stem)
                };
                let (Some(start), Ok(md)) = (start, e.metadata()) else {
                    continue;
                };
                files.push((start, path, md.len(), is_minute));
            }
        }
        let min_cutoff = now_ms.saturating_sub(self.cfg.keep_minute_days * DAY_MS);
        let (y, m, ..) = utc_parts(now_ms);
        let months = y * 12 + i64::from(m) - 1 - self.cfg.keep_hour_months as i64;
        let hour_cutoff = day_stamp_start_ms(&format!(
            "{:04}{:02}01",
            months.div_euclid(12),
            months.rem_euclid(12) + 1
        ))
        .unwrap_or(0);
        let mut result = Ok(());
        files.retain(|(start, path, _, is_minute)| {
            let expired = if *is_minute {
                start + DAY_MS <= min_cutoff
            } else {
                *start < hour_cutoff
            };
            if expired {
                if let Err(e) = fs::remove_file(path) {
                    result = Err(e);
                }
            }
            !expired
        });
        let mut total: u64 = files.iter().map(|f| f.2).sum();
        // Oldest minute segments first, then oldest hour segments; the segment still being written survives.
        files.sort_by_key(|(start, _, _, is_minute)| (!*is_minute, *start));
        let keep_now_min = day_stamp(now_ms);
        let keep_now_hour = month_stamp(now_ms);
        for (_, path, size, is_minute) in &files {
            if total <= self.cfg.max_bytes {
                break;
            }
            let stem = path.file_stem().and_then(|s| s.to_str()).unwrap_or("");
            if (*is_minute && stem == keep_now_min) || (!*is_minute && stem == keep_now_hour) {
                continue;
            }
            if fs::remove_file(path).is_ok() {
                total = total.saturating_sub(*size);
            }
        }
        result
    }

    /// Total bytes of segment files.
    pub fn disk_bytes(&self) -> u64 {
        ["1m", "1h"]
            .iter()
            .filter_map(|s| fs::read_dir(self.cfg.dir.join(s)).ok())
            .flat_map(|rd| rd.flatten())
            .filter_map(|e| e.metadata().ok())
            .map(|m| m.len())
            .sum()
    }

    /// Points with `since_ms <= ts_ms <= until_ms` at the requested resolution, oldest first, at most
    /// [`MAX_QUERY_POINTS`] (the newest).
    pub fn query(&self, since_ms: u64, until_ms: u64, step: Step) -> Vec<Point> {
        let mut out: Vec<Point> = match step {
            Step::Raw5s => self
                .ring
                .iter()
                .filter(|p| p.ts_ms >= since_ms && p.ts_ms <= until_ms)
                .cloned()
                .collect(),
            Step::Minute => self.read_segments("1m", since_ms, until_ms, true),
            Step::Hour => self.read_segments("1h", since_ms, until_ms, false),
        };
        if out.len() > MAX_QUERY_POINTS {
            out.drain(..out.len() - MAX_QUERY_POINTS);
        }
        out
    }

    fn read_segments(
        &self,
        sub: &str,
        since_ms: u64,
        until_ms: u64,
        is_minute: bool,
    ) -> Vec<Point> {
        let mut segs: Vec<(u64, PathBuf)> = Vec::new();
        if let Ok(rd) = fs::read_dir(self.cfg.dir.join(sub)) {
            for e in rd.flatten() {
                let path = e.path();
                let stem = path.file_stem().and_then(|s| s.to_str()).unwrap_or("");
                let start = if is_minute {
                    day_stamp_start_ms(stem)
                } else {
                    month_stamp_start_ms(stem)
                };
                if let Some(s) = start {
                    // A segment can hold points from its start to (at most) 31 days later.
                    let span = if is_minute { DAY_MS } else { 31 * DAY_MS };
                    if s <= until_ms && s + span > since_ms {
                        segs.push((s, path));
                    }
                }
            }
        }
        segs.sort();
        let mut out = Vec::new();
        for (_, path) in segs {
            let Ok(f) = File::open(&path) else { continue };
            for line in BufReader::new(f).split(b'\n').map_while(Result::ok) {
                // A torn or corrupt line is skipped, never fatal.
                if let Ok(p) = serde_json::from_slice::<Point>(&line) {
                    if p.ts_ms >= since_ms && p.ts_ms <= until_ms {
                        out.push(p);
                    }
                }
            }
        }
        out.sort_by_key(|p| p.ts_ms);
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::timeutil::{Clock, FakeClock};

    fn sample(ts: u64, cpu: f64) -> MetricsSample {
        MetricsSample {
            ts_ms: ts,
            cpu_pct: cpu,
            ..MetricsSample::default()
        }
    }

    // 2026-11-09T00:00:00Z
    const T0: u64 = 1_794_182_400_000;

    fn store(dir: &Path) -> Store {
        Store::open(StoreConfig::new(dir)).unwrap()
    }

    #[test]
    fn ring_keeps_fifteen_minutes() {
        let d = tempfile::tempdir().unwrap();
        let clock = FakeClock::new(T0);
        let mut s = store(d.path());
        for i in 0..400 {
            // 400 samples at 5 s = 33 minutes
            s.push(&sample(clock.now_ms(), i as f64)).unwrap();
            clock.advance(5000);
        }
        let all = s.query(0, u64::MAX, Step::Raw5s);
        assert!(all.len() <= 181 && all.len() >= 180, "{}", all.len());
        assert_eq!(all.last().map(|p| p.fields["cpu_pct"].last), Some(399.0));
    }

    #[test]
    fn minute_rollup_has_min_max_mean_last() {
        let d = tempfile::tempdir().unwrap();
        let mut s = store(d.path());
        for (i, v) in [10.0, 30.0, 20.0].iter().enumerate() {
            s.push(&sample(T0 + i as u64 * 5000, *v)).unwrap();
        }
        // First sample of the next minute finalises the previous one.
        s.push(&sample(T0 + MINUTE_MS, 99.0)).unwrap();
        let pts = s.query(T0, T0 + MINUTE_MS, Step::Minute);
        assert_eq!(pts.len(), 1);
        let a = pts[0].fields["cpu_pct"];
        assert_eq!(
            (a.min, a.max, a.mean, a.last, pts[0].n),
            (10.0, 30.0, 20.0, 20.0, 3)
        );
    }

    #[test]
    fn hour_rollup_is_count_weighted() {
        let d = tempfile::tempdir().unwrap();
        let mut s = store(d.path());
        // minute 0: 2 samples (mean 10); minute 1: 1 sample (value 40) -> hour mean = (10*2+40)/3 = 20
        s.push(&sample(T0, 10.0)).unwrap();
        s.push(&sample(T0 + 5000, 10.0)).unwrap();
        s.push(&sample(T0 + MINUTE_MS, 40.0)).unwrap();
        // cross into the next minute, then the next hour
        s.push(&sample(T0 + 2 * MINUTE_MS, 1.0)).unwrap();
        s.push(&sample(T0 + HOUR_MS, 1.0)).unwrap();
        s.push(&sample(T0 + HOUR_MS + MINUTE_MS, 1.0)).unwrap();
        let h = s.query(T0, T0 + HOUR_MS, Step::Hour);
        assert_eq!(h.len(), 1);
        assert_eq!(h[0].n, 4);
        let a = h[0].fields["cpu_pct"];
        assert_eq!((a.min, a.max), (1.0, 40.0));
        assert!((a.mean - (10.0 * 2.0 + 40.0 + 1.0) / 4.0).abs() < 1e-9);
    }

    #[test]
    fn torn_last_line_is_skipped_and_next_append_is_clean() {
        let d = tempfile::tempdir().unwrap();
        {
            let mut s = store(d.path());
            s.push(&sample(T0, 5.0)).unwrap();
            s.push(&sample(T0 + MINUTE_MS, 6.0)).unwrap();
        }
        let seg = d.path().join("1m").join(format!("{}.jsonl", day_stamp(T0)));
        let mut f = OpenOptions::new().append(true).open(&seg).unwrap();
        f.write_all(b"{\"ts_ms\":17941").unwrap(); // simulated crash mid-write
        drop(f);
        let mut s = store(d.path());
        s.push(&sample(T0 + 5 * MINUTE_MS, 7.0)).unwrap();
        s.push(&sample(T0 + 6 * MINUTE_MS, 8.0)).unwrap();
        let pts = s.query(T0, T0 + DAY_MS, Step::Minute);
        let stamps: Vec<u64> = pts.iter().map(|p| p.ts_ms).collect();
        assert_eq!(stamps, vec![T0, T0 + 5 * MINUTE_MS]);
    }

    #[test]
    fn retention_drops_old_segments() {
        let d = tempfile::tempdir().unwrap();
        let s = store(d.path());
        let old_day = T0 - 10 * DAY_MS;
        let recent_day = T0 - 2 * DAY_MS;
        for t in [old_day, recent_day] {
            fs::write(
                d.path().join("1m").join(format!("{}.jsonl", day_stamp(t))),
                "{}\n",
            )
            .unwrap();
        }
        fs::write(d.path().join("1h").join("202001.jsonl"), "{}\n").unwrap();
        fs::write(d.path().join("1h").join("202610.jsonl"), "{}\n").unwrap();
        s.enforce_retention(T0).unwrap();
        assert!(!d
            .path()
            .join("1m")
            .join(format!("{}.jsonl", day_stamp(old_day)))
            .exists());
        assert!(d
            .path()
            .join("1m")
            .join(format!("{}.jsonl", day_stamp(recent_day)))
            .exists());
        assert!(!d.path().join("1h/202001.jsonl").exists());
        assert!(d.path().join("1h/202610.jsonl").exists());
    }

    #[test]
    fn size_budget_removes_oldest_first_but_keeps_current() {
        let d = tempfile::tempdir().unwrap();
        let mut cfg = StoreConfig::new(d.path());
        cfg.max_bytes = 100;
        let s = Store::open(cfg).unwrap();
        let blob = "x".repeat(80);
        for t in [T0 - 3 * DAY_MS, T0 - DAY_MS, T0] {
            fs::write(
                d.path().join("1m").join(format!("{}.jsonl", day_stamp(t))),
                &blob,
            )
            .unwrap();
        }
        s.enforce_retention(T0 + 1000).unwrap();
        assert!(!d
            .path()
            .join("1m")
            .join(format!("{}.jsonl", day_stamp(T0 - 3 * DAY_MS)))
            .exists());
        assert!(!d
            .path()
            .join("1m")
            .join(format!("{}.jsonl", day_stamp(T0 - DAY_MS)))
            .exists());
        assert!(d
            .path()
            .join("1m")
            .join(format!("{}.jsonl", day_stamp(T0)))
            .exists());
        assert!(s.disk_bytes() <= 100);
    }

    #[test]
    fn step_parses() {
        assert_eq!(Step::parse("1m"), Some(Step::Minute));
        assert_eq!(Step::parse("2m"), None);
    }
}
