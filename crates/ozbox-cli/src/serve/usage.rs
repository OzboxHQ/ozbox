//! Usage rollups and the weekly "downsize or pause?" suggestions.
//!
//! Everything here is a pure function of samples: no clock, no provider, so every rule is tested on fixed numbers.
//! Suggestions are only ever shown. Applying one is the normal plan, confirm, apply flow.

use std::collections::BTreeMap;

use ozbox_core::{BoxRecord, MetricsSample, Size};
use serde::Serialize;

/// The requested chart range. The step is the sample spacing; the window is how far back it looks. These follow the
/// retention tiers: 5 s live, 1 min kept 7 days, 1 h kept 13 months.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Range {
    Live5s,
    Min1,
    Hour1,
}

impl Range {
    pub fn parse(s: &str) -> Option<Range> {
        match s {
            "5s" => Some(Range::Live5s),
            "1m" => Some(Range::Min1),
            "1h" => Some(Range::Hour1),
            _ => None,
        }
    }

    pub fn label(self) -> &'static str {
        match self {
            Range::Live5s => "5s",
            Range::Min1 => "1m",
            Range::Hour1 => "1h",
        }
    }

    pub fn step_ms(self) -> u64 {
        match self {
            Range::Live5s => 5_000,
            Range::Min1 => 60_000,
            Range::Hour1 => 3_600_000,
        }
    }

    /// 15 minutes, 3 hours and 7 days.
    pub fn window_ms(self) -> u64 {
        match self {
            Range::Live5s => 15 * 60_000,
            Range::Min1 => 3 * 3_600_000,
            Range::Hour1 => 7 * 24 * 3_600_000,
        }
    }
}

pub fn mem_used_pct(s: &MetricsSample) -> f64 {
    if s.mem_total_bytes == 0 {
        return 0.0;
    }
    (s.mem_total_bytes.saturating_sub(s.mem_available_bytes)) as f64 / s.mem_total_bytes as f64
        * 100.0
}

/// The p-th percentile (0..=100) by nearest rank. `None` for no values.
pub fn percentile(values: &[f64], p: f64) -> Option<f64> {
    if values.is_empty() {
        return None;
    }
    let mut v: Vec<f64> = values.iter().copied().filter(|x| x.is_finite()).collect();
    if v.is_empty() {
        return None;
    }
    v.sort_by(|a, b| a.total_cmp(b));
    let rank = ((p / 100.0) * v.len() as f64).ceil().max(1.0) as usize;
    v.get(rank.min(v.len()) - 1).copied()
}

#[derive(Debug, Clone, Copy, PartialEq, Serialize)]
pub struct Stat {
    pub mean: f64,
    pub p95: f64,
    pub max: f64,
}

pub fn stat(values: &[f64]) -> Option<Stat> {
    let p95 = percentile(values, 95.0)?;
    let max = values.iter().copied().fold(f64::MIN, f64::max);
    Some(Stat {
        mean: values.iter().sum::<f64>() / values.len() as f64,
        p95,
        max,
    })
}

#[derive(Debug, Clone, Serialize)]
pub struct Point {
    pub ts_ms: u64,
    pub cpu_pct: f64,
    pub mem_pct: f64,
}

#[derive(Debug, Clone, Serialize)]
pub struct BoxUsage {
    pub name: String,
    pub size: Size,
    pub labels: BTreeMap<String, String>,
    pub cpu: Option<Stat>,
    pub mem_pct: Option<Stat>,
    pub points: Vec<Point>,
    pub cost_month_est_usd: Option<f64>,
}

pub fn box_usage(rec: &BoxRecord, samples: &[MetricsSample], price: Option<f64>) -> BoxUsage {
    let cpu: Vec<f64> = samples.iter().map(|s| s.cpu_pct).collect();
    let mem: Vec<f64> = samples.iter().map(mem_used_pct).collect();
    BoxUsage {
        name: rec.spec.name.to_string(),
        size: rec.spec.size,
        labels: rec.spec.labels.clone(),
        cpu: stat(&cpu),
        mem_pct: stat(&mem),
        points: samples
            .iter()
            .map(|s| Point {
                ts_ms: s.ts_ms,
                cpu_pct: s.cpu_pct,
                mem_pct: mem_used_pct(s),
            })
            .collect(),
        cost_month_est_usd: price,
    }
}

#[derive(Debug, Clone, Serialize, PartialEq)]
pub struct Group {
    /// The label value, or `(none)` for boxes without that label.
    pub value: String,
    pub boxes: Vec<String>,
    pub cpu_mean: Option<f64>,
    pub mem_mean: Option<f64>,
    pub cost_month_est_usd: Option<f64>,
}

pub const NO_LABEL: &str = "(none)";

/// Group box usage by the value of one label (the project label, say). Means are of the boxes' means.
pub fn group_by_label(boxes: &[BoxUsage], key: &str) -> Vec<Group> {
    let mut m: BTreeMap<String, Vec<&BoxUsage>> = BTreeMap::new();
    for b in boxes {
        let v = b
            .labels
            .get(key)
            .filter(|v| !v.is_empty())
            .cloned()
            .unwrap_or_else(|| NO_LABEL.to_string());
        m.entry(v).or_default().push(b);
    }
    m.into_iter()
        .map(|(value, bs)| {
            let mean = |f: fn(&BoxUsage) -> Option<f64>| {
                let v: Vec<f64> = bs.iter().filter_map(|b| f(b)).collect();
                (!v.is_empty()).then(|| v.iter().sum::<f64>() / v.len() as f64)
            };
            let costs: Option<Vec<f64>> = bs.iter().map(|b| b.cost_month_est_usd).collect();
            Group {
                value,
                boxes: bs.iter().map(|b| b.name.clone()).collect(),
                cpu_mean: mean(|b| b.cpu.map(|s| s.mean)),
                mem_mean: mean(|b| b.mem_pct.map(|s| s.mean)),
                cost_month_est_usd: costs.map(|c| c.iter().sum()),
            }
        })
        .collect()
}

#[derive(Debug, Clone, Serialize, PartialEq)]
pub struct RunRollup {
    pub id: String,
    pub box_name: String,
    pub cpu_mean: f64,
    pub mem_peak_bytes: u64,
    pub samples: usize,
}

/// Per-run usage across a window: mean CPU and peak memory per run id, summed over the samples that carried it.
pub fn by_run(box_name: &str, samples: &[MetricsSample]) -> Vec<RunRollup> {
    let mut acc: BTreeMap<&str, (f64, u64, usize)> = BTreeMap::new();
    for s in samples {
        for r in &s.runs {
            let e = acc.entry(r.id.as_str()).or_insert((0.0, 0, 0));
            e.0 += r.cpu_pct;
            e.1 = e.1.max(r.mem_bytes);
            e.2 += 1;
        }
    }
    acc.into_iter()
        .map(|(id, (sum, peak, n))| RunRollup {
            id: format!("{box_name}-{id}"),
            box_name: box_name.to_string(),
            cpu_mean: sum / n as f64,
            mem_peak_bytes: peak,
            samples: n,
        })
        .collect()
}

// ---- suggestions --------------------------------------------------------------------------------------------

/// A week of hourly samples is needed before anything is suggested.
pub const MIN_SAMPLES: usize = 7 * 24 * 9 / 10;
pub const DOWNSIZE_CPU_P95_BELOW: f64 = 30.0;
pub const DOWNSIZE_MEM_P95_BELOW: f64 = 50.0;
/// After the move, the projected p95 CPU on the smaller box and its memory use must stay under these.
pub const FIT_CPU_BELOW: f64 = 60.0;
pub const FIT_MEM_BELOW: f64 = 75.0;
/// A sample is idle when CPU stays under this; a box idle in this share of samples should pause when unused.
pub const IDLE_CPU_BELOW: f64 = 5.0;
pub const IDLE_SHARE_AT_LEAST: f64 = 0.8;

#[derive(Debug, Clone, PartialEq, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum Advice {
    Downsize { to: Size },
    AutoPause { idle_share: f64 },
}

#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct Suggestion {
    pub box_name: String,
    pub advice: Advice,
    pub reason: String,
    /// Estimated saving per month in US dollars, from the entered price table; `None` shows as "—".
    pub saving_month_usd: Option<f64>,
}

/// The next size down in the standard line, if the box is on it and is not the smallest.
pub fn one_size_down(size: Size) -> Option<Size> {
    let i = Size::STANDARD.iter().position(|s| *s == size)?;
    i.checked_sub(1).map(|j| Size::STANDARD[j])
}

/// Decide for one box from its (hourly) samples over the last week. Pure.
///
/// Idle comes first: a box that is mostly idle should pause, and that saves more than a smaller size would.
pub fn suggest(
    box_name: &str,
    size: Size,
    samples: &[MetricsSample],
    price: impl Fn(Size) -> Option<f64>,
) -> Option<Suggestion> {
    if samples.len() < MIN_SAMPLES {
        return None;
    }
    let cpu: Vec<f64> = samples.iter().map(|s| s.cpu_pct).collect();
    let idle_share = cpu.iter().filter(|c| **c < IDLE_CPU_BELOW).count() as f64 / cpu.len() as f64;
    if idle_share >= IDLE_SHARE_AT_LEAST {
        return Some(Suggestion {
            box_name: box_name.to_string(),
            advice: Advice::AutoPause { idle_share },
            reason: format!(
                "Idle (CPU under {IDLE_CPU_BELOW:.0}%) for {:.0}% of the last 7 days. Let it pause itself when nobody is using it.",
                idle_share * 100.0
            ),
            saving_month_usd: price(size).map(|p| p * idle_share),
        });
    }
    let to = one_size_down(size)?;
    let cpu_p95 = percentile(&cpu, 95.0)?;
    let mem: Vec<f64> = samples.iter().map(mem_used_pct).collect();
    let mem_p95 = percentile(&mem, 95.0)?;
    if cpu_p95 >= DOWNSIZE_CPU_P95_BELOW || mem_p95 >= DOWNSIZE_MEM_P95_BELOW {
        return None;
    }
    let (now, then) = (size.spec(), to.spec());
    let projected_cpu = cpu_p95 * f64::from(now.vcpus) / f64::from(then.vcpus);
    let projected_mem = mem_p95 * f64::from(now.memory_gb) / f64::from(then.memory_gb);
    if projected_cpu >= FIT_CPU_BELOW || projected_mem >= FIT_MEM_BELOW {
        return None;
    }
    let saving = match (price(size), price(to)) {
        (Some(a), Some(b)) if a > b => Some(a - b),
        _ => None,
    };
    Some(Suggestion {
        box_name: box_name.to_string(),
        advice: Advice::Downsize { to },
        reason: format!(
            "CPU stayed under {cpu_p95:.0}% and memory under {mem_p95:.0}% for 95% of the last 7 days. Size {to} would have been enough."
        ),
        saving_month_usd: saving,
    })
}

#[cfg(test)]
#[allow(clippy::expect_used)]
mod tests {
    use super::*;

    const GIB: u64 = 1 << 30;

    fn s(cpu: f64, mem_pct: f64, mem_total_gib: u64) -> MetricsSample {
        let total = mem_total_gib * GIB;
        let used = (total as f64 * mem_pct / 100.0) as u64;
        MetricsSample {
            cpu_pct: cpu,
            mem_total_bytes: total,
            mem_available_bytes: total - used,
            ..MetricsSample::default()
        }
    }

    fn week(cpu: f64, mem_pct: f64, gib: u64) -> Vec<MetricsSample> {
        (0..168).map(|_| s(cpu, mem_pct, gib)).collect()
    }

    fn no_price(_: Size) -> Option<f64> {
        None
    }

    fn price(z: Size) -> Option<f64> {
        match z {
            Size::S => Some(100.0),
            Size::M => Some(200.0),
            Size::L => Some(300.0),
            _ => None,
        }
    }

    #[test]
    fn percentile_is_nearest_rank() {
        let v: Vec<f64> = (1..=100).map(f64::from).collect();
        assert_eq!(percentile(&v, 95.0), Some(95.0));
        assert_eq!(percentile(&v, 100.0), Some(100.0));
        assert_eq!(percentile(&[7.0], 95.0), Some(7.0));
        assert_eq!(percentile(&[], 95.0), None);
        assert_eq!(percentile(&[f64::NAN], 95.0), None);
    }

    #[test]
    fn a_lightly_used_box_gets_a_downsize_with_the_saving() {
        // M is 8 vCPU / 32 GB; S is 4 / 16. 20% CPU and 30% memory fits S (40% and 60%).
        let got = suggest("dev", Size::M, &week(20.0, 30.0, 32), price);
        let got = got.expect("a suggestion");
        assert_eq!(got.advice, Advice::Downsize { to: Size::S });
        assert_eq!(got.saving_month_usd, Some(100.0));
    }

    #[test]
    fn the_saving_is_absent_without_prices() {
        let got = suggest("dev", Size::M, &week(20.0, 30.0, 32), no_price).expect("a suggestion");
        assert_eq!(got.saving_month_usd, None);
    }

    #[test]
    fn busy_or_memory_hungry_boxes_are_left_alone() {
        assert!(suggest("a", Size::M, &week(35.0, 30.0, 32), price).is_none());
        assert!(suggest("a", Size::M, &week(20.0, 55.0, 32), price).is_none());
    }

    #[test]
    fn a_smaller_size_that_would_not_fit_is_not_suggested() {
        // 29% CPU on 8 vCPU is 58% on 4 vCPU: under the 60% line. 29.9% -> 59.8%: still fits.
        assert!(suggest("a", Size::M, &week(29.0, 20.0, 32), price).is_some());
        // memory 45% of 32 GB = 14.4 GB; on S (16 GB) that is 90%: refused even though the rule's 50% allows it
        assert!(suggest("a", Size::M, &week(10.0, 45.0, 32), price).is_none());
    }

    #[test]
    fn the_smallest_and_gpu_sizes_have_no_downsize() {
        assert!(suggest("a", Size::XS, &week(10.0, 10.0, 8), price).is_none());
        assert_eq!(one_size_down(Size::XS), None);
        assert_eq!(one_size_down(Size::S), Some(Size::XS));
        assert_eq!(one_size_down(Size::XXL), Some(Size::XL));
        assert_eq!(one_size_down(Size::Gpu(ozbox_core::GpuKind::Small)), None);
    }

    #[test]
    fn a_mostly_idle_box_is_told_to_auto_pause_with_a_share_of_its_price() {
        let mut samples = week(1.0, 20.0, 32);
        for x in samples.iter_mut().take(20) {
            x.cpu_pct = 60.0;
        }
        let got = suggest("dev", Size::M, &samples, price).expect("a suggestion");
        match got.advice {
            Advice::AutoPause { idle_share } => assert!((idle_share - 148.0 / 168.0).abs() < 1e-9),
            other => panic!("unexpected {other:?}"),
        }
        assert!((got.saving_month_usd.unwrap_or(0.0) - 200.0 * 148.0 / 168.0).abs() < 1e-6);
    }

    #[test]
    fn less_than_a_week_of_history_suggests_nothing() {
        let short: Vec<MetricsSample> = (0..100).map(|_| s(1.0, 5.0, 32)).collect();
        assert!(suggest("a", Size::M, &short, price).is_none());
        assert!(suggest("a", Size::M, &[], price).is_none());
    }

    #[test]
    fn groups_by_label_with_a_none_bucket() {
        let mk = |n: &str, project: Option<&str>, cpu: f64, cost: Option<f64>| BoxUsage {
            name: n.into(),
            size: Size::M,
            labels: project
                .map(|p| BTreeMap::from([("project".to_string(), p.to_string())]))
                .unwrap_or_default(),
            cpu: Some(Stat {
                mean: cpu,
                p95: cpu,
                max: cpu,
            }),
            mem_pct: None,
            points: vec![],
            cost_month_est_usd: cost,
        };
        let g = group_by_label(
            &[
                mk("a", Some("web"), 10.0, Some(100.0)),
                mk("b", Some("web"), 30.0, Some(50.0)),
                mk("c", None, 5.0, None),
            ],
            "project",
        );
        assert_eq!(g.len(), 2);
        let web = g.iter().find(|x| x.value == "web").expect("web");
        assert_eq!(web.boxes, ["a", "b"]);
        assert_eq!(web.cpu_mean, Some(20.0));
        assert_eq!(web.cost_month_est_usd, Some(150.0));
        let none = g.iter().find(|x| x.value == NO_LABEL).expect("none");
        assert_eq!(none.cost_month_est_usd, None);
    }

    #[test]
    fn runs_roll_up_across_samples() {
        let mut a = s(10.0, 10.0, 8);
        a.runs = vec![ozbox_core::RunUsage {
            id: "run-1".into(),
            cpu_pct: 10.0,
            mem_bytes: 5,
            mem_max_bytes: None,
        }];
        let mut b = a.clone();
        b.runs[0].cpu_pct = 30.0;
        b.runs[0].mem_bytes = 9;
        let r = by_run("dev", &[a, b]);
        assert_eq!(r.len(), 1);
        assert_eq!(r[0].id, "dev-run-1");
        assert_eq!(r[0].cpu_mean, 20.0);
        assert_eq!(r[0].mem_peak_bytes, 9);
    }

    #[test]
    fn ranges_parse_and_stay_bounded() {
        for r in ["5s", "1m", "1h"] {
            let r = Range::parse(r).expect("range");
            assert!(r.window_ms() / r.step_ms() <= 200);
        }
        assert!(Range::parse("1d").is_none());
    }
}
