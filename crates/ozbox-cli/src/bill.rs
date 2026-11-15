//! The real bill, read from the provider with the person's own read access, and how it compares with the estimate.
//!
//! * AWS: Cost Explorer through the `aws` CLI (`aws ce get-cost-and-usage`), filtered to what carries the
//!   `ozbox-managed=true` tag and grouped by the `ozbox-box` tag and the service. Read-only. The tag has to be turned on
//!   as a cost-allocation tag in the account (Billing -> Cost allocation tags), and the data trails the usage by about
//!   a day, so the two newest days are never compared and never alerted on.
//! * Hetzner Cloud: its API has no invoice or usage endpoint, so there is nothing to read. That is said plainly; the
//!   estimate is all there is.
//!
//! Everything here is pure or goes through [`CommandRunner`], so it is tested on fixed JSON. The server calls it from its
//! background worker once a day, never from a request.

use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;
use std::sync::Arc;

use ozbox_core::{CommandRunner, CommandSpec};
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::messages::t;
use crate::state::{civil, day_key, DayEstimate};

pub const MANAGED_TAG: &str = "ozbox-managed";
pub const BOX_TAG: &str = "ozbox-box";
/// Cost Explorer's name for instance hours.
pub const SVC_COMPUTE: &str = "Amazon Elastic Compute Cloud - Compute";
/// Cost Explorer's name for disks, snapshots, data transfer, NAT gateways and addresses: everything else EC2 bills.
pub const SVC_EC2_OTHER: &str = "EC2 - Other";

const DAY_MS: u64 = 86_400_000;
/// The bill is read once a day, and again after a failure no sooner than this.
pub const REFRESH_AFTER_MS: u64 = 24 * 3_600_000;
pub const RETRY_AFTER_MS: u64 = 3_600_000;
/// Days this old or newer are not complete in the provider's data and are not compared.
pub const LAG_DAYS: u64 = 1;
/// A day is flagged when the two figures differ by at least this share of the larger one...
pub const DEFAULT_DRIFT_PCT: f64 = 25.0;
/// ...and by at least this much money.
pub const DEFAULT_DRIFT_MIN: f64 = 2.0;
/// Most flagged rows kept and shown.
const MAX_DRIFT_ROWS: usize = 60;

// ---------- what the provider answered ----------

/// What one box and one service cost on one day.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct BillLine {
    /// The `ozbox-box` tag; `None` for spend that carries `ozbox-managed` but no box.
    pub box_name: Option<String>,
    pub service: String,
    pub amount: f64,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct BillDay {
    /// `YYYY-MM-DD` (UTC).
    pub date: String,
    /// The provider itself calls this day an estimate.
    pub estimated: bool,
    pub lines: Vec<BillLine>,
}

impl BillDay {
    pub fn total(&self) -> f64 {
        self.lines.iter().map(|l| l.amount).sum()
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct BillReport {
    pub provider: String,
    pub currency: String,
    pub source: String,
    pub fetched_at_ms: u64,
    pub days: Vec<BillDay>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Problem {
    /// The tag is not a cost-allocation tag yet (or nothing carrying it has been billed yet).
    TagNotActive,
    /// The signed-in session may not read Cost Explorer.
    AccessDenied,
    /// Cost Explorer is not turned on in the account, or has no data yet.
    NotEnabled,
    /// The provider has no bill to read.
    Unsupported,
    Other,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct BillError {
    pub problem: Problem,
    /// Plain English from the catalogue; never a credential.
    pub message: String,
}

impl BillError {
    fn new(problem: Problem, message: String) -> Self {
        Self { problem, message }
    }
}

fn short(s: &str) -> String {
    let line = s
        .lines()
        .find(|l| !l.trim().is_empty())
        .unwrap_or("")
        .trim();
    line.chars().take(240).collect()
}

/// What stderr from `aws ce` means.
pub fn classify(stderr: &str) -> BillError {
    let low = stderr.to_ascii_lowercase();
    if low.contains("accessdenied")
        || low.contains("not authorized")
        || low.contains("unauthorized")
    {
        BillError::new(Problem::AccessDenied, t("cost.err.access_denied", &[]))
    } else if low.contains("optinrequired")
        || low.contains("not enabled")
        || low.contains("dataunavailable")
        || low.contains("data is not available")
    {
        BillError::new(Problem::NotEnabled, t("cost.err.not_enabled", &[]))
    } else if low.contains("ozbox-managed") || low.contains("tag key") || low.contains("tagkey") {
        BillError::new(Problem::TagNotActive, t("cost.err.tag_not_active", &[]))
    } else {
        BillError::new(
            Problem::Other,
            t("cost.err.other", &[("why", &short(stderr))]),
        )
    }
}

// ---------- reading Cost Explorer ----------

/// One page of `get-cost-and-usage`: the days in it, the next page token, and the currency.
/// The days in a page, the next page token and the currency.
type Page = (Vec<BillDay>, Option<String>, Option<String>);

pub fn parse_page(text: &str) -> Result<Page, String> {
    let v: Value = serde_json::from_str(text).map_err(|_| "not JSON".to_string())?;
    let results = v
        .get("ResultsByTime")
        .and_then(Value::as_array)
        .ok_or("no ResultsByTime")?;
    let mut currency = None;
    let mut days = Vec::new();
    for r in results {
        let date = r
            .pointer("/TimePeriod/Start")
            .and_then(Value::as_str)
            .ok_or("a day has no start")?
            .chars()
            .take(10)
            .collect::<String>();
        let estimated = r.get("Estimated").and_then(Value::as_bool).unwrap_or(false);
        let mut lines = Vec::new();
        for g in r
            .get("Groups")
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
        {
            let keys: Vec<&str> = g
                .get("Keys")
                .and_then(Value::as_array)
                .map(|k| k.iter().filter_map(Value::as_str).collect())
                .unwrap_or_default();
            let (Some(box_key), Some(service)) = (keys.first(), keys.get(1)) else {
                continue;
            };
            // A tag group key is `key$value`; an empty value is a resource without that tag.
            let value = box_key
                .strip_prefix(BOX_TAG)
                .and_then(|r| r.strip_prefix('$'))
                .unwrap_or(box_key);
            let metric = g.pointer("/Metrics/UnblendedCost");
            let amount: f64 = metric
                .and_then(|m| m.get("Amount"))
                .and_then(Value::as_str)
                .and_then(|a| a.trim().parse().ok())
                .filter(|a: &f64| a.is_finite())
                .unwrap_or(0.0);
            if currency.is_none() {
                currency = metric
                    .and_then(|m| m.get("Unit"))
                    .and_then(Value::as_str)
                    .map(str::to_string);
            }
            lines.push(BillLine {
                box_name: (!value.is_empty()).then(|| value.to_string()),
                service: (*service).to_string(),
                amount,
            });
        }
        days.push(BillDay {
            date,
            estimated,
            lines,
        });
    }
    let next = v
        .get("NextPageToken")
        .and_then(Value::as_str)
        .filter(|s| !s.is_empty())
        .map(str::to_string);
    Ok((days, next, currency))
}

/// The first day of the month before the one `now_ms` is in, and tomorrow (Cost Explorer's end is exclusive).
pub fn period(now_ms: u64) -> (String, String) {
    let (y, m, _) = civil(now_ms);
    let (py, pm) = if m == 1 { (y - 1, 12) } else { (y, m - 1) };
    (
        format!("{py:04}-{pm:02}-01"),
        day_key(now_ms.saturating_add(DAY_MS)),
    )
}

pub struct AwsBill {
    pub runner: Arc<dyn CommandRunner>,
    pub profile: Option<String>,
}

impl AwsBill {
    fn base(&self, sub: &str) -> CommandSpec {
        let mut c = CommandSpec::new("aws").args(["ce", sub]);
        // Cost Explorer answers from one region only, whatever region the boxes are in.
        c = c.args(["--region", "us-east-1", "--output", "json"]);
        if let Some(p) = &self.profile {
            c = c.args(["--profile", p]);
        }
        c
    }

    fn run(&self, c: &CommandSpec) -> Result<String, BillError> {
        self.runner
            .run_ok(c)
            .map(|o| o.stdout)
            .map_err(|e| match e {
                ozbox_core::Error::Command { stderr, .. } => classify(&stderr),
                other => classify(&other.to_string()),
            })
    }

    /// Whether the tag exists in the account's cost data at all: `ce get-tags` answers with the values it has seen.
    fn tag_seen(&self, start: &str, end: &str) -> Result<bool, BillError> {
        let c = self
            .base("get-tags")
            .args(["--time-period", &format!("Start={start},End={end}")])
            .args(["--tag-key", MANAGED_TAG]);
        let out = self.run(&c)?;
        let v: Value = serde_json::from_str(&out).unwrap_or(Value::Null);
        Ok(v.get("Tags")
            .and_then(Value::as_array)
            .is_some_and(|a| a.iter().any(|x| x.as_str().is_some_and(|s| !s.is_empty()))))
    }

    /// The one request that reads the bill, without a page token.
    fn usage_request(&self, start: &str, end: &str) -> CommandSpec {
        let filter =
            serde_json::json!({ "Tags": { "Key": MANAGED_TAG, "Values": ["true"] } }).to_string();
        self.base("get-cost-and-usage")
            .args(["--granularity", "DAILY", "--metrics", "UnblendedCost"])
            .args(["--time-period", &format!("Start={start},End={end}")])
            .args(["--filter", &filter])
            .arg("--group-by")
            .arg(format!("Type=TAG,Key={BOX_TAG}"))
            .arg("Type=DIMENSION,Key=SERVICE")
    }

    /// What a read would run, for `--dry-run`: nothing is sent.
    pub fn planned_calls(&self, now_ms: u64) -> Vec<String> {
        let (start, end) = period(now_ms);
        let c = self.usage_request(&start, &end);
        vec![format!("{} {}", c.program, c.args.join(" "))]
    }

    /// The managed spend of the month before and this month so far, by day, box and service.
    pub fn fetch(&self, now_ms: u64) -> Result<BillReport, BillError> {
        let (start, end) = period(now_ms);
        let mut days: Vec<BillDay> = Vec::new();
        let mut currency = None;
        let mut token: Option<String> = None;
        for _ in 0..20 {
            let mut c = self.usage_request(&start, &end);
            if let Some(tok) = &token {
                c = c.args(["--next-page-token", tok]);
            }
            let out = self.run(&c)?;
            let (page, next, cur) = parse_page(&out).map_err(|why| {
                BillError::new(Problem::Other, t("cost.err.other", &[("why", &why)]))
            })?;
            days.extend(page);
            currency = currency.or(cur);
            match next {
                Some(n) => token = Some(n),
                None => break,
            }
        }
        if days.iter().all(|d| d.lines.is_empty()) && !self.tag_seen(&start, &end)? {
            return Err(BillError::new(
                Problem::TagNotActive,
                t("cost.err.tag_not_active", &[]),
            ));
        }
        Ok(BillReport {
            provider: "aws".into(),
            currency: currency.unwrap_or_else(|| "USD".into()),
            source: t("cost.source.aws", &[]),
            fetched_at_ms: now_ms,
            days,
        })
    }
}

/// Where a bill comes from. The server and the CLI use the provider's; the demo has its own.
pub trait BillSource: Send + Sync {
    fn fetch(&self, now_ms: u64) -> Result<BillReport, BillError>;
}

impl BillSource for AwsBill {
    fn fetch(&self, now_ms: u64) -> Result<BillReport, BillError> {
        AwsBill::fetch(self, now_ms)
    }
}

/// A provider with no bill to read.
pub struct NoBill(pub String);

impl BillSource for NoBill {
    fn fetch(&self, _now_ms: u64) -> Result<BillReport, BillError> {
        Err(unsupported(&self.0))
    }
}

/// This month so far, finished days only, by box and by service.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct MonthSummary {
    pub month: String,
    pub currency: String,
    pub through: Option<String>,
    pub boxes: Vec<(Option<String>, f64)>,
    pub services: Vec<ServiceTotal>,
    pub total: f64,
}

pub fn month_summary(bill: &BillReport, now_ms: u64) -> MonthSummary {
    let month = crate::state::month_key(now_ms);
    let mut boxes: BTreeMap<Option<String>, f64> = BTreeMap::new();
    let mut services: BTreeMap<String, f64> = BTreeMap::new();
    let mut through: Option<String> = None;
    for d in bill
        .days
        .iter()
        .filter(|d| d.date.starts_with(&month) && !is_partial(d, now_ms))
    {
        if through.as_deref().is_none_or(|t| t < d.date.as_str()) {
            through = Some(d.date.clone());
        }
        for l in &d.lines {
            *boxes.entry(l.box_name.clone()).or_default() += l.amount;
            *services.entry(l.service.clone()).or_default() += l.amount;
        }
    }
    let total = boxes.values().sum();
    let mut services: Vec<ServiceTotal> = services
        .into_iter()
        .map(|(service, real)| ServiceTotal { service, real })
        .collect();
    services.sort_by(|a, b| b.real.total_cmp(&a.real));
    MonthSummary {
        month,
        currency: bill.currency.clone(),
        through,
        boxes: boxes.into_iter().collect(),
        services,
        total,
    }
}

/// What a provider without a bill answers.
pub fn unsupported(provider: &str) -> BillError {
    BillError::new(
        Problem::Unsupported,
        t("cost.err.unsupported", &[("provider", provider)]),
    )
}

// ---------- what is kept ----------

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct BillCache {
    pub report: Option<BillReport>,
    pub problem: Option<BillError>,
    pub last_attempt_ms: u64,
    pub last_ok_ms: u64,
    /// Drift alerts already sent, by day and box, so one is sent once.
    pub alerted: BTreeSet<String>,
    pub orphans: Option<crate::orphans::OrphanScan>,
}

impl BillCache {
    pub fn load(path: &Path) -> BillCache {
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

    /// Once a day, and after a failure no sooner than an hour: Cost Explorer charges a cent for each request, and a
    /// person looking at the page is not a reason to ask again.
    pub fn refresh_due(&self, now_ms: u64) -> bool {
        if now_ms.saturating_sub(self.last_attempt_ms) < RETRY_AFTER_MS {
            return false;
        }
        self.last_ok_ms == 0 || now_ms.saturating_sub(self.last_ok_ms) >= REFRESH_AFTER_MS
    }

    pub fn record(&mut self, result: Result<BillReport, BillError>, now_ms: u64) {
        self.last_attempt_ms = now_ms;
        match result {
            Ok(r) => {
                self.report = Some(r);
                self.problem = None;
                self.last_ok_ms = now_ms;
            }
            Err(e) => self.problem = Some(e),
        }
    }
}

// ---------- reconciliation ----------

/// Whether a bill day is too new to trust: the provider's data trails the usage by about a day.
pub fn is_partial(day: &BillDay, now_ms: u64) -> bool {
    day.estimated || day.date.as_str() >= day_key(now_ms.saturating_sub(LAG_DAYS * DAY_MS)).as_str()
}

#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct Cause {
    /// `untagged_box`, `unmodelled_service`, `unmodelled_in_ec2_other`, `price_changed`, `partly_watched`,
    /// `discount_or_spot`, `not_in_bill`.
    pub kind: &'static str,
    /// A service name or a short number, never a sentence: the dashboard words the cause.
    pub detail: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct DriftRow {
    pub date: String,
    pub box_name: Option<String>,
    pub estimate: f64,
    pub real: f64,
    /// Real minus estimate: positive means the bill is higher.
    pub diff: f64,
    pub pct: f64,
    pub causes: Vec<Cause>,
}

#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct DayTotal {
    pub date: String,
    pub partial: bool,
    pub estimate: Option<f64>,
    pub real: Option<f64>,
}

#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct BoxTotal {
    pub box_name: Option<String>,
    pub estimate: f64,
    pub real: f64,
    pub diff: f64,
    /// Complete days these two figures cover.
    pub days: u32,
}

#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct ServiceTotal {
    pub service: String,
    pub real: f64,
}

#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct Reconciliation {
    pub currency: String,
    pub month: String,
    /// The newest complete day of the bill.
    pub through: Option<String>,
    pub days: Vec<DayTotal>,
    /// This month, complete days only, by box.
    pub boxes: Vec<BoxTotal>,
    pub services: Vec<ServiceTotal>,
    pub month_real: f64,
    pub month_estimate: f64,
    pub drift: Vec<DriftRow>,
}

#[derive(Debug, Clone, Copy)]
pub struct Tuning {
    pub pct: f64,
    pub min: f64,
    /// The price list is old, or an entered price is in use: a likely reason for a gap.
    pub prices_uncertain: bool,
}

fn estimate_split(day: Option<&DayEstimate>, name: &str) -> (f64, f64) {
    day.and_then(|d| d.boxes.get(name))
        .map_or((0.0, 0.0), |b| (b.machine_cost, b.disk_cost))
}

/// Why one box's day differs. Pure: the same numbers give the same answer.
fn causes_for(
    real_lines: &[&BillLine],
    est_machine: f64,
    est_disk: f64,
    watched_ms: u64,
    tuning: Tuning,
    untagged: bool,
) -> Vec<Cause> {
    let mut out = Vec::new();
    let sum = |f: &dyn Fn(&BillLine) -> bool| -> f64 {
        real_lines.iter().filter(|l| f(l)).map(|l| l.amount).sum()
    };
    let real_compute = sum(&|l| l.service == SVC_COMPUTE);
    let real_other = sum(&|l| l.service == SVC_EC2_OTHER);
    let rest: Vec<&&BillLine> = real_lines
        .iter()
        .filter(|l| l.service != SVC_COMPUTE && l.service != SVC_EC2_OTHER)
        .collect();
    if untagged {
        out.push(Cause {
            kind: "untagged_box",
            detail: None,
        });
    }
    let rest_total: f64 = rest.iter().map(|l| l.amount).sum();
    if rest_total >= 0.01 {
        let names: BTreeSet<&str> = rest.iter().map(|l| l.service.as_str()).collect();
        out.push(Cause {
            kind: "unmodelled_service",
            detail: Some(names.into_iter().collect::<Vec<_>>().join(", ")),
        });
    }
    if real_other - est_disk >= 0.01 && real_other > est_disk * 1.2 {
        out.push(Cause {
            kind: "unmodelled_in_ec2_other",
            detail: None,
        });
    }
    // Machine hours: the one part the estimate models fully.
    if !untagged && !real_lines.is_empty() && (est_machine > 0.0 || real_compute > 0.0) {
        let day_ms = DAY_MS;
        if watched_ms < day_ms * 5 / 6 && real_compute > est_machine {
            out.push(Cause {
                kind: "partly_watched",
                detail: Some(format!("{}", watched_ms / 3_600_000)),
            });
        } else if real_compute > est_machine * 1.1 && tuning.prices_uncertain {
            out.push(Cause {
                kind: "price_changed",
                detail: None,
            });
        } else if est_machine > real_compute * 1.1 {
            out.push(Cause {
                kind: if tuning.prices_uncertain {
                    "price_changed"
                } else {
                    "discount_or_spot"
                },
                detail: None,
            });
        } else if real_compute > est_machine * 1.1 {
            out.push(Cause {
                kind: "price_changed",
                detail: None,
            });
        }
    }
    if real_lines.is_empty() && (est_machine + est_disk) > 0.0 {
        out.push(Cause {
            kind: "not_in_bill",
            detail: None,
        });
    }
    out
}

/// Compare the estimate with the bill, per box and day. Days the provider has not finished are shown but never flagged.
pub fn reconcile(
    ledger_days: &BTreeMap<String, DayEstimate>,
    bill: &BillReport,
    now_ms: u64,
    tuning: Tuning,
) -> Reconciliation {
    let month = crate::state::month_key(now_ms);
    let mut days = Vec::new();
    let mut drift = Vec::new();
    let mut per_box: BTreeMap<Option<String>, (f64, f64, u32)> = BTreeMap::new();
    let mut services: BTreeMap<String, f64> = BTreeMap::new();
    let (mut month_real, mut month_estimate) = (0.0, 0.0);
    let mut through: Option<String> = None;
    let mut sorted: Vec<&BillDay> = bill.days.iter().collect();
    sorted.sort_by(|a, b| a.date.cmp(&b.date));
    for day in sorted {
        let partial = is_partial(day, now_ms);
        let est_day = ledger_days.get(&day.date);
        let est_total = est_day.map(|d| {
            d.boxes
                .values()
                .map(|b| b.machine_cost + b.disk_cost)
                .sum::<f64>()
        });
        days.push(DayTotal {
            date: day.date.clone(),
            partial,
            estimate: est_total,
            real: Some(day.total()),
        });
        if partial {
            continue;
        }
        if through.as_deref().is_none_or(|t| t < day.date.as_str()) {
            through = Some(day.date.clone());
        }
        let in_month = day.date.starts_with(&month);
        if in_month {
            for l in &day.lines {
                *services.entry(l.service.clone()).or_default() += l.amount;
            }
        }
        // Every box seen on either side of this day.
        let mut names: BTreeSet<Option<String>> =
            day.lines.iter().map(|l| l.box_name.clone()).collect();
        if let Some(d) = est_day {
            names.extend(d.boxes.keys().map(|k| Some(k.clone())));
        }
        for name in names {
            let lines: Vec<&BillLine> = day.lines.iter().filter(|l| l.box_name == name).collect();
            let real: f64 = lines.iter().map(|l| l.amount).sum();
            let (em, ed) = name
                .as_deref()
                .map_or((0.0, 0.0), |n| estimate_split(est_day, n));
            let estimate = em + ed;
            if in_month {
                let e = per_box.entry(name.clone()).or_default();
                e.0 += estimate;
                e.1 += real;
                e.2 += 1;
                month_real += real;
                month_estimate += estimate;
            }
            let diff = real - estimate;
            let big = real.max(estimate);
            let pct = if big > 0.0 {
                diff.abs() / big * 100.0
            } else {
                0.0
            };
            if diff.abs() >= tuning.min && pct >= tuning.pct {
                let watched = est_day.map_or(0, |d| d.watched_ms);
                drift.push(DriftRow {
                    date: day.date.clone(),
                    box_name: name.clone(),
                    estimate,
                    real,
                    diff,
                    pct,
                    causes: causes_for(&lines, em, ed, watched, tuning, name.is_none()),
                });
            }
        }
    }
    drift.sort_by(|a, b| {
        b.date
            .cmp(&a.date)
            .then(b.diff.abs().total_cmp(&a.diff.abs()))
    });
    drift.truncate(MAX_DRIFT_ROWS);
    let boxes = per_box
        .into_iter()
        .map(|(box_name, (estimate, real, n))| BoxTotal {
            box_name,
            estimate,
            real,
            diff: real - estimate,
            days: n,
        })
        .collect();
    let mut services: Vec<ServiceTotal> = services
        .into_iter()
        .map(|(service, real)| ServiceTotal { service, real })
        .collect();
    services.sort_by(|a, b| b.real.total_cmp(&a.real));
    Reconciliation {
        currency: bill.currency.clone(),
        month,
        through,
        days,
        boxes,
        services,
        month_real,
        month_estimate,
        drift,
    }
}

// ---------- the budget on the real figure ----------

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum BudgetBasis {
    /// The provider's bill for the days it has finished, and the estimate for the days since.
    Bill,
    #[default]
    Estimate,
}

#[derive(Debug, Clone, PartialEq)]
pub struct MonthSpend {
    pub spent: f64,
    pub currency: String,
    pub real_through: String,
}

/// This month's spend using the real bill where there is one and the estimate after it. `None` when the bill has no
/// finished day this month, so the caller keeps using the estimate alone and says so.
pub fn month_spend(
    estimate_days: &BTreeMap<String, DayEstimate>,
    bill: Option<&BillReport>,
    now_ms: u64,
) -> Option<MonthSpend> {
    let bill = bill?;
    let month = crate::state::month_key(now_ms);
    let real_days: BTreeMap<&str, f64> = bill
        .days
        .iter()
        .filter(|d| d.date.starts_with(&month) && !is_partial(d, now_ms))
        .map(|d| (d.date.as_str(), d.total()))
        .collect();
    let through = real_days.keys().next_back().copied()?;
    let real: f64 = real_days.values().sum();
    let later: f64 = estimate_days
        .iter()
        .filter(|(d, _)| d.starts_with(&month) && d.as_str() > through)
        .flat_map(|(_, e)| e.boxes.values())
        .map(|b| b.machine_cost + b.disk_cost)
        .sum();
    Some(MonthSpend {
        spent: real + later,
        currency: bill.currency.clone(),
        real_through: through.to_string(),
    })
}

// ---------- alerts ----------

/// Alerts for flagged days not yet told about. At most [`MAX_ALERTS_PER_RUN`] are written out; the rest are folded
/// into the last one so a bad week is one message, not a flood.
pub const MAX_ALERTS_PER_RUN: usize = 3;

pub fn drift_alerts(
    recon: &Reconciliation,
    alerted: &mut BTreeSet<String>,
    now_ms: u64,
) -> Vec<crate::notify::Alert> {
    let fresh: Vec<&DriftRow> = recon
        .drift
        .iter()
        .filter(|r| !alerted.contains(&key_of(r)))
        .collect();
    let mut out = Vec::new();
    for (i, r) in fresh.iter().enumerate() {
        alerted.insert(key_of(r));
        if i >= MAX_ALERTS_PER_RUN {
            continue;
        }
        let who = r
            .box_name
            .clone()
            .unwrap_or_else(|| t("cost.untagged_name", &[]));
        let more = fresh.len().saturating_sub(MAX_ALERTS_PER_RUN);
        let cause = r
            .causes
            .first()
            .map(|c| {
                t(
                    &format!("cost.cause.{}", c.kind),
                    &[("detail", c.detail.as_deref().unwrap_or(""))],
                )
            })
            .unwrap_or_else(|| t("cost.cause.unknown", &[]));
        let mut body = t(
            "cost.alert.drift_body",
            &[
                ("date", &r.date),
                ("real", &format!("{:.2}", r.real)),
                ("estimate", &format!("{:.2}", r.estimate)),
                ("currency", &recon.currency),
                ("cause", &cause),
            ],
        );
        if i + 1 == MAX_ALERTS_PER_RUN && more > 0 {
            body.push(' ');
            body.push_str(&t("cost.alert.drift_more", &[("n", &more.to_string())]));
        }
        out.push(crate::notify::Alert {
            key: format!("drift:{}", key_of(r)),
            kind: "cost_drift".into(),
            severity: crate::notify::Severity::Normal,
            box_name: r.box_name.clone(),
            title: t(
                "cost.alert.drift_title",
                &[("box", &who), ("date", &r.date)],
            ),
            body,
            ts_ms: now_ms,
        });
    }
    out
}

fn key_of(r: &DriftRow) -> String {
    format!("{}:{}", r.date, r.box_name.as_deref().unwrap_or("-"))
}

/// The drift thresholds, from the settings.
pub fn tuning(settings: &crate::settings::Settings, prices_uncertain: bool) -> Tuning {
    Tuning {
        pct: settings.budget.drift_alert_pct,
        min: settings.budget.drift_alert_min_usd,
        prices_uncertain,
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use crate::state::DayBox;
    use ozbox_core::{Error, Output, Result as CoreResult};
    use serde_json::json;
    use std::sync::Mutex;

    const NOW: u64 = 1_794_182_400_000 + 12 * 3_600_000; // 2026-11-09 12:00 UTC

    type Group<'a> = (&'a str, &'a str, &'a str);
    type CeDay<'a> = (&'a str, bool, &'a [Group<'a>]);

    fn ce_page(days: &[CeDay<'_>], next: Option<&str>) -> String {
        let results: Vec<Value> = days
            .iter()
            .map(|(date, est, groups)| {
                json!({
                    "TimePeriod": { "Start": date, "End": "x" },
                    "Total": {},
                    "Groups": groups.iter().map(|(b, s, a)| json!({
                        "Keys": [format!("{BOX_TAG}${b}"), s],
                        "Metrics": { "UnblendedCost": { "Amount": a, "Unit": "USD" } }
                    })).collect::<Vec<_>>(),
                    "Estimated": est,
                })
            })
            .collect();
        let mut v = json!({ "ResultsByTime": results, "DimensionValueAttributes": [] });
        if let Some(n) = next {
            v["NextPageToken"] = json!(n);
        }
        v.to_string()
    }

    #[test]
    fn a_page_is_grouped_by_the_box_tag_and_the_service() {
        let text = ce_page(
            &[(
                "2026-11-03",
                false,
                &[
                    ("alpha", SVC_COMPUTE, "19.35"),
                    ("alpha", SVC_EC2_OTHER, "1.20"),
                    ("", "Amazon Virtual Private Cloud", "1.08"),
                ],
            )],
            None,
        );
        let (days, next, cur) = parse_page(&text).unwrap();
        assert_eq!(next, None);
        assert_eq!(cur.as_deref(), Some("USD"));
        assert_eq!(days.len(), 1);
        let d = &days[0];
        assert_eq!(d.date, "2026-11-03");
        assert_eq!(d.lines[0].box_name.as_deref(), Some("alpha"));
        assert_eq!(d.lines[0].service, SVC_COMPUTE);
        assert!((d.lines[0].amount - 19.35).abs() < 1e-9);
        // a tag group with an empty value is spend that is managed but has no box
        assert_eq!(d.lines[2].box_name, None);
        assert!((d.total() - 21.63).abs() < 1e-9);
        assert!(parse_page("nope").is_err());
        assert!(parse_page("{}").is_err());
    }

    #[test]
    fn the_period_starts_last_month_and_ends_tomorrow() {
        assert_eq!(period(NOW), ("2026-10-01".into(), "2026-11-10".into()));
        // January looks back into December of the year before
        let jan = 1_767_225_600_000 + 5 * DAY_MS; // 2026-01-06
        assert_eq!(period(jan).0, "2025-12-01");
    }

    struct Fake {
        calls: Mutex<Vec<Vec<String>>>,
        answers: Mutex<Vec<CoreResult<Output>>>,
    }

    impl Fake {
        fn new(answers: Vec<CoreResult<Output>>) -> Arc<Self> {
            Arc::new(Self {
                calls: Mutex::new(Vec::new()),
                answers: Mutex::new(answers),
            })
        }
    }

    impl CommandRunner for Fake {
        fn run(&self, cmd: &CommandSpec) -> CoreResult<Output> {
            let mut a = vec![cmd.program.clone()];
            a.extend(cmd.args.clone());
            self.calls.lock().unwrap().push(a);
            self.answers.lock().unwrap().remove(0)
        }
    }

    fn ok(s: String) -> CoreResult<Output> {
        Ok(Output {
            status: Some(0),
            stdout: s,
            stderr: String::new(),
        })
    }

    fn denied(msg: &str) -> CoreResult<Output> {
        Err(Error::Command {
            program: "aws".into(),
            code: Some(254),
            stderr: msg.into(),
        })
    }

    #[test]
    fn the_request_is_read_only_filtered_by_the_managed_tag_and_grouped_two_ways() {
        let fake = Fake::new(vec![ok(ce_page(
            &[("2026-11-03", false, &[("alpha", SVC_COMPUTE, "5.00")])],
            None,
        ))]);
        let bill = AwsBill {
            runner: fake.clone(),
            profile: Some("ozbox".into()),
        };
        let r = bill.fetch(NOW).unwrap();
        assert_eq!(r.days.len(), 1);
        let calls = fake.calls.lock().unwrap();
        assert_eq!(calls.len(), 1);
        let a = &calls[0];
        assert_eq!(&a[..3], ["aws", "ce", "get-cost-and-usage"]);
        let has = |s: &str| a.iter().any(|x| x == s);
        assert!(has("us-east-1") && has("DAILY") && has("UnblendedCost"));
        assert!(has("Start=2026-10-01,End=2026-11-10"));
        assert!(a
            .iter()
            .any(|x| x.contains(r#""Key":"ozbox-managed""#) && x.contains(r#""true""#)));
        assert!(has("Type=TAG,Key=ozbox-box") && has("Type=DIMENSION,Key=SERVICE"));
        assert!(has("--profile") && has("ozbox"));
        // only read verbs ever reach the provider
        assert!(a.iter().all(|x| !x.starts_with("create")
            && !x.starts_with("delete")
            && !x.starts_with("update")));
    }

    #[test]
    fn a_dry_run_names_the_read_and_the_month_summary_leaves_out_unfinished_days() {
        let bill = AwsBill {
            runner: Fake::new(vec![]),
            profile: None,
        };
        let planned = bill.planned_calls(NOW);
        assert_eq!(planned.len(), 1);
        assert!(
            planned[0].starts_with("aws ce get-cost-and-usage")
                && planned[0].contains("Start=2026-10-01,End=2026-11-10")
        );
        let r = report(vec![
            day(
                "2026-11-03",
                false,
                vec![(Some("a"), SVC_COMPUTE, 5.0), (None, SVC_EC2_OTHER, 1.0)],
            ),
            day("2026-11-08", false, vec![(Some("a"), SVC_COMPUTE, 9.0)]), // yesterday
            day("2026-10-31", false, vec![(Some("a"), SVC_COMPUTE, 7.0)]), // last month
        ]);
        let m = month_summary(&r, NOW);
        assert_eq!(m.through.as_deref(), Some("2026-11-03"));
        assert!((m.total - 6.0).abs() < 1e-9);
        assert_eq!(m.boxes, vec![(None, 1.0), (Some("a".to_string()), 5.0)]);
        assert_eq!(m.services[0].service, SVC_COMPUTE);
    }

    #[test]
    fn pages_are_followed_until_there_is_no_token() {
        let p1 = ce_page(
            &[("2026-11-01", false, &[("alpha", SVC_COMPUTE, "1.00")])],
            Some("tok"),
        );
        let p2 = ce_page(
            &[("2026-11-02", false, &[("alpha", SVC_COMPUTE, "2.00")])],
            None,
        );
        let fake = Fake::new(vec![ok(p1), ok(p2)]);
        let bill = AwsBill {
            runner: fake.clone(),
            profile: None,
        };
        let r = bill.fetch(NOW).unwrap();
        assert_eq!(r.days.len(), 2);
        let calls = fake.calls.lock().unwrap();
        assert!(calls[1]
            .windows(2)
            .any(|w| w[0] == "--next-page-token" && w[1] == "tok"));
    }

    #[test]
    fn no_spend_and_no_tag_values_says_the_tag_is_not_activated() {
        let empty = ce_page(&[("2026-11-03", false, &[])], None);
        let none = json!({ "Tags": [], "ReturnSize": 0, "TotalSize": 0 }).to_string();
        let fake = Fake::new(vec![ok(empty.clone()), ok(none)]);
        let err = AwsBill {
            runner: fake.clone(),
            profile: None,
        }
        .fetch(NOW)
        .unwrap_err();
        assert_eq!(err.problem, Problem::TagNotActive);
        assert!(
            err.message.contains("cost-allocation tag") && err.message.contains("24 hours"),
            "{}",
            err.message
        );
        assert_eq!(fake.calls.lock().unwrap()[1][2], "get-tags");
        // the tag is known to the account but nothing was billed yet: no problem, just an empty bill
        let some = json!({ "Tags": ["true"] }).to_string();
        let r = AwsBill {
            runner: Fake::new(vec![ok(empty), ok(some)]),
            profile: None,
        }
        .fetch(NOW)
        .unwrap();
        assert!(r.days.iter().all(|d| d.lines.is_empty()));
    }

    #[test]
    fn a_refusal_names_the_two_permissions_and_is_not_dressed_up() {
        let e = AwsBill {
            runner: Fake::new(vec![denied("An error occurred (AccessDeniedException) when calling the GetCostAndUsage operation: User is not authorized")]),
            profile: None,
        }
        .fetch(NOW)
        .unwrap_err();
        assert_eq!(e.problem, Problem::AccessDenied);
        assert!(e.message.contains("ce:GetCostAndUsage") && e.message.contains("ce:GetTags"));
        let e = classify("An error occurred (OptInRequired): not subscribed");
        assert_eq!(e.problem, Problem::NotEnabled);
        let e = classify("boom\nsecond line");
        assert_eq!(e.problem, Problem::Other);
        assert!(e.message.contains("boom") && !e.message.contains("second line"));
    }

    #[test]
    fn hetzner_has_no_bill_to_read_and_says_so() {
        let e = unsupported("hcloud");
        assert_eq!(e.problem, Problem::Unsupported);
        assert!(e.message.contains("hcloud") && e.message.to_lowercase().contains("invoice"));
    }

    #[test]
    fn the_cache_asks_once_a_day_and_backs_off_after_a_failure() {
        let mut c = BillCache::default();
        assert!(c.refresh_due(NOW));
        c.record(Err(unsupported("x")), NOW);
        assert!(!c.refresh_due(NOW + 60_000), "not again within the hour");
        assert!(
            c.refresh_due(NOW + RETRY_AFTER_MS),
            "but an hour later, since nothing ever succeeded"
        );
        c.record(
            Ok(BillReport {
                provider: "aws".into(),
                currency: "USD".into(),
                source: String::new(),
                fetched_at_ms: NOW,
                days: vec![],
            }),
            NOW,
        );
        assert!(c.problem.is_none());
        assert!(!c.refresh_due(NOW + 23 * 3_600_000));
        assert!(c.refresh_due(NOW + REFRESH_AFTER_MS));
    }

    // ----- reconciliation -----

    fn day(date: &str, estimated: bool, lines: Vec<(Option<&str>, &str, f64)>) -> BillDay {
        BillDay {
            date: date.into(),
            estimated,
            lines: lines
                .into_iter()
                .map(|(b, s, a)| BillLine {
                    box_name: b.map(str::to_string),
                    service: s.into(),
                    amount: a,
                })
                .collect(),
        }
    }

    fn est(watched_h: u64, boxes: &[(&str, f64, f64)]) -> DayEstimate {
        DayEstimate {
            watched_ms: watched_h * 3_600_000,
            currency: Some("USD".into()),
            boxes: boxes
                .iter()
                .map(|(n, m, d)| {
                    (
                        (*n).to_string(),
                        DayBox {
                            machine_cost: *m,
                            disk_cost: *d,
                        },
                    )
                })
                .collect(),
        }
    }

    fn report(days: Vec<BillDay>) -> BillReport {
        BillReport {
            provider: "aws".into(),
            currency: "USD".into(),
            source: String::new(),
            fetched_at_ms: NOW,
            days,
        }
    }

    const TUNE: Tuning = Tuning {
        pct: 25.0,
        min: 2.0,
        prices_uncertain: false,
    };

    #[test]
    fn matching_days_are_not_flagged_and_the_month_adds_up() {
        let bill = report(vec![
            day(
                "2026-11-03",
                false,
                vec![
                    (Some("alpha"), SVC_COMPUTE, 19.4),
                    (Some("alpha"), SVC_EC2_OTHER, 1.1),
                ],
            ),
            day(
                "2026-11-04",
                false,
                vec![
                    (Some("alpha"), SVC_COMPUTE, 19.4),
                    (Some("alpha"), SVC_EC2_OTHER, 1.1),
                ],
            ),
        ]);
        let mut days = BTreeMap::new();
        days.insert("2026-11-03".to_string(), est(24, &[("alpha", 19.35, 1.15)]));
        days.insert("2026-11-04".to_string(), est(24, &[("alpha", 19.35, 1.15)]));
        let r = reconcile(&days, &bill, NOW, TUNE);
        assert!(r.drift.is_empty(), "{:?}", r.drift);
        assert_eq!(r.through.as_deref(), Some("2026-11-04"));
        assert!((r.month_real - 41.0).abs() < 1e-9);
        assert!((r.month_estimate - 41.0).abs() < 1e-9);
        assert_eq!(r.boxes.len(), 1);
        assert_eq!(r.boxes[0].days, 2);
        assert_eq!(r.services[0].service, SVC_COMPUTE);
    }

    #[test]
    fn the_newest_days_are_shown_but_never_compared() {
        let bill = report(vec![
            day(
                "2026-11-08",
                false,
                vec![(Some("alpha"), SVC_COMPUTE, 0.50)],
            ), // yesterday: not finished
            day("2026-11-09", true, vec![(Some("alpha"), SVC_COMPUTE, 0.10)]),
            day(
                "2026-11-07",
                false,
                vec![(Some("alpha"), SVC_COMPUTE, 20.0)],
            ),
        ]);
        let mut days = BTreeMap::new();
        for d in ["2026-11-07", "2026-11-08", "2026-11-09"] {
            days.insert(d.to_string(), est(24, &[("alpha", 20.0, 0.0)]));
        }
        let r = reconcile(&days, &bill, NOW, TUNE);
        assert!(r.drift.is_empty());
        assert_eq!(r.through.as_deref(), Some("2026-11-07"));
        let partials: Vec<bool> = r.days.iter().map(|d| d.partial).collect();
        assert_eq!(partials, vec![false, true, true]);
        assert!(
            (r.month_real - 20.0).abs() < 1e-9,
            "only finished days count"
        );
    }

    #[test]
    fn drift_needs_both_a_share_and_an_amount() {
        let bill = report(vec![
            day("2026-11-01", false, vec![(Some("a"), SVC_COMPUTE, 1.0)]), // 100% but 1.00 < 2.00
            day("2026-11-02", false, vec![(Some("a"), SVC_COMPUTE, 21.0)]), // 5% of 20
            day("2026-11-03", false, vec![(Some("a"), SVC_COMPUTE, 30.0)]), // 33% and 10.00
        ]);
        let mut days = BTreeMap::new();
        days.insert("2026-11-01".to_string(), est(24, &[("a", 0.0, 0.0)]));
        days.insert("2026-11-02".to_string(), est(24, &[("a", 20.0, 0.0)]));
        days.insert("2026-11-03".to_string(), est(24, &[("a", 20.0, 0.0)]));
        let r = reconcile(&days, &bill, NOW, TUNE);
        assert_eq!(r.drift.len(), 1);
        assert_eq!(r.drift[0].date, "2026-11-03");
        assert!((r.drift[0].diff - 10.0).abs() < 1e-9);
    }

    fn one(lines: Vec<(Option<&str>, &str, f64)>, e: DayEstimate, tuning: Tuning) -> DriftRow {
        let bill = report(vec![day("2026-11-03", false, lines)]);
        let mut days = BTreeMap::new();
        days.insert("2026-11-03".to_string(), e);
        let mut r = reconcile(&days, &bill, NOW, tuning);
        assert!(!r.drift.is_empty(), "expected drift");
        r.drift.remove(0)
    }

    fn kinds(r: &DriftRow) -> Vec<&'static str> {
        r.causes.iter().map(|c| c.kind).collect()
    }

    #[test]
    fn a_service_the_estimate_does_not_model_is_named() {
        let r = one(
            vec![
                (Some("alpha"), SVC_COMPUTE, 20.0),
                (Some("alpha"), "Amazon Virtual Private Cloud", 33.0),
            ],
            est(24, &[("alpha", 20.0, 0.0)]),
            TUNE,
        );
        assert_eq!(kinds(&r), vec!["unmodelled_service"]);
        assert_eq!(
            r.causes[0].detail.as_deref(),
            Some("Amazon Virtual Private Cloud")
        );
    }

    #[test]
    fn snapshots_transfer_or_nat_show_up_as_ec2_other_beyond_the_disks() {
        let r = one(
            vec![
                (Some("alpha"), SVC_COMPUTE, 20.0),
                (Some("alpha"), SVC_EC2_OTHER, 12.0),
            ],
            est(24, &[("alpha", 20.0, 1.0)]),
            TUNE,
        );
        assert_eq!(kinds(&r), vec!["unmodelled_in_ec2_other"]);
    }

    #[test]
    fn spend_with_no_box_tag_is_its_own_row() {
        let r = one(vec![(None, SVC_COMPUTE, 9.0)], est(24, &[]), TUNE);
        assert_eq!(r.box_name, None);
        assert!(kinds(&r).contains(&"untagged_box"));
    }

    #[test]
    fn a_bill_below_the_estimate_is_a_discount_unless_the_prices_are_old() {
        let lines = || vec![(Some("alpha"), SVC_COMPUTE, 10.0)];
        let e = || est(24, &[("alpha", 20.0, 0.0)]);
        assert_eq!(kinds(&one(lines(), e(), TUNE)), vec!["discount_or_spot"]);
        assert_eq!(
            kinds(&one(
                lines(),
                e(),
                Tuning {
                    prices_uncertain: true,
                    ..TUNE
                }
            )),
            vec!["price_changed"]
        );
    }

    #[test]
    fn a_bill_above_the_estimate_on_a_day_the_server_slept_is_blamed_on_the_gap() {
        let r = one(
            vec![(Some("alpha"), SVC_COMPUTE, 20.0)],
            est(6, &[("alpha", 5.0, 0.0)]),
            TUNE,
        );
        assert_eq!(kinds(&r), vec!["partly_watched"]);
        assert_eq!(r.causes[0].detail.as_deref(), Some("6"));
    }

    #[test]
    fn an_estimate_with_nothing_billed_says_it_is_not_in_the_bill() {
        let bill = report(vec![day("2026-11-03", false, vec![])]);
        let mut days = BTreeMap::new();
        days.insert("2026-11-03".to_string(), est(24, &[("alpha", 20.0, 1.0)]));
        let r = reconcile(&days, &bill, NOW, TUNE);
        assert_eq!(r.drift.len(), 1);
        assert!(kinds(&r.drift[0]).contains(&"not_in_bill"));
    }

    // ----- budget and alerts -----

    #[test]
    fn the_month_uses_the_bill_for_finished_days_and_the_estimate_after() {
        let mut ledger: BTreeMap<String, DayEstimate> = BTreeMap::new();
        ledger.insert("2026-11-03".into(), est(24, &[("a", 99.0, 0.0)])); // replaced by the bill
        ledger.insert("2026-11-08".into(), est(24, &[("a", 10.0, 1.0)]));
        ledger.insert("2026-11-09".into(), est(12, &[("a", 5.0, 0.5)]));
        ledger.insert("2026-10-30".into(), est(24, &[("a", 50.0, 0.0)])); // last month: not counted
        let bill = report(vec![
            day("2026-11-03", false, vec![(Some("a"), SVC_COMPUTE, 20.0)]),
            day("2026-11-07", false, vec![(Some("a"), SVC_COMPUTE, 20.0)]),
            day("2026-11-08", false, vec![(Some("a"), SVC_COMPUTE, 20.0)]), // yesterday: not finished
            day("2026-10-30", false, vec![(Some("a"), SVC_COMPUTE, 20.0)]),
        ]);
        let m = month_spend(&ledger, Some(&bill), NOW).unwrap();
        assert_eq!(m.real_through, "2026-11-07");
        // 20 + 20 real, then the estimate for the 8th and the 9th
        assert!((m.spent - (40.0 + 11.0 + 5.5)).abs() < 1e-9, "{}", m.spent);
        assert!(month_spend(&ledger, None, NOW).is_none());
        let only_partial = report(vec![day("2026-11-09", true, vec![])]);
        assert!(month_spend(&ledger, Some(&only_partial), NOW).is_none());
    }

    #[test]
    fn a_flagged_day_alerts_once_and_a_bad_week_is_one_message() {
        let row = |d: &str, b: &str| DriftRow {
            date: d.into(),
            box_name: Some(b.into()),
            estimate: 20.0,
            real: 40.0,
            diff: 20.0,
            pct: 50.0,
            causes: vec![Cause {
                kind: "unmodelled_service",
                detail: Some("Amazon Virtual Private Cloud".into()),
            }],
        };
        let mut recon = Reconciliation {
            currency: "USD".into(),
            month: "2026-11".into(),
            through: None,
            days: vec![],
            boxes: vec![],
            services: vec![],
            month_real: 0.0,
            month_estimate: 0.0,
            drift: vec![row("2026-11-03", "alpha")],
        };
        let mut told = BTreeSet::new();
        let a = drift_alerts(&recon, &mut told, NOW);
        assert_eq!(a.len(), 1);
        assert_eq!(a[0].kind, "cost_drift");
        assert!(
            a[0].title.contains("alpha")
                && a[0].body.contains("40.00")
                && a[0].body.contains("Amazon Virtual Private Cloud")
        );
        assert!(
            drift_alerts(&recon, &mut told, NOW).is_empty(),
            "the same day is not told twice"
        );
        recon.drift = (1..=6)
            .map(|i| row(&format!("2026-11-0{i}"), "beta"))
            .collect();
        let a = drift_alerts(&recon, &mut told, NOW);
        assert_eq!(a.len(), MAX_ALERTS_PER_RUN);
        assert!(
            a.last().is_some_and(|x| x.body.contains("3 more")),
            "{}",
            a[2].body
        );
        assert!(
            drift_alerts(&recon, &mut told, NOW).is_empty(),
            "the folded ones are remembered too"
        );
    }
}
