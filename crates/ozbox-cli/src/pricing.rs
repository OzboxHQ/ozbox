//! Public prices, so a cost can be shown without anyone typing a number.
//!
//! * AWS: the Price List API, through the `aws` CLI (`aws pricing get-products`), on-demand Linux, shared tenancy, per
//!   instance type, plus the EBS gp3 and snapshot GB-month prices of the box's region.
//! * Hetzner Cloud: `GET /pricing`, with the API token read from the environment at the moment of the call.
//!
//! Prices are cached on disk with the time they were fetched, refreshed daily, and shown as **stale** once they are old:
//! an old price is never presented as current. A price the owner enters in Settings overrides the public one. A
//! machine the price list does not answer for has no price, and the dashboard shows "—" rather than a guess.

use std::collections::BTreeMap;
use std::path::Path;
use std::sync::Arc;

use ozbox_core::{BoxRecord, BoxState, CommandRunner, CommandSpec};
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::netguard::{Guard, HttpClient, HttpRequest};
use crate::settings::Settings;

pub const HOURS_PER_MONTH: f64 = 730.0;
const HOUR_MS: u64 = 3_600_000;
/// Refreshed when older than this.
pub const REFRESH_AFTER_MS: u64 = 24 * HOUR_MS;
/// Shown as stale when older than this (a missed refresh or two).
pub const STALE_AFTER_MS: u64 = 36 * HOUR_MS;
/// Do not retry a failed fetch sooner than this.
pub const RETRY_AFTER_MS: u64 = 15 * 60_000;

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct PriceBook {
    pub provider: String,
    pub currency: String,
    pub source: String,
    /// The AWS region (or Hetzner location) the prices are for.
    pub region: String,
    pub fetched_at_ms: u64,
    /// Per hour, by machine type (`m7i.4xlarge`; for Hetzner also `ccx43@fsn1`).
    pub machine_hourly: BTreeMap<String, f64>,
    pub disk_gb_month: Option<f64>,
    pub snapshot_gb_month: Option<f64>,
}

impl PriceBook {
    pub fn age_ms(&self, now_ms: u64) -> u64 {
        now_ms.saturating_sub(self.fetched_at_ms)
    }

    pub fn is_stale(&self, now_ms: u64) -> bool {
        self.age_ms(now_ms) > STALE_AFTER_MS
    }

    /// Hourly price of a machine type, preferring the one for this location.
    pub fn machine(&self, machine_type: &str, region: Option<&str>) -> Option<f64> {
        region
            .and_then(|r| self.machine_hourly.get(&format!("{machine_type}@{r}")))
            .or_else(|| self.machine_hourly.get(machine_type))
            .copied()
    }
}

/// What is kept in `prices.json`.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct PriceCache {
    pub book: Option<PriceBook>,
    pub last_error: Option<String>,
    pub last_attempt_ms: u64,
}

impl PriceCache {
    pub fn load(path: &Path) -> PriceCache {
        std::fs::read_to_string(path)
            .ok()
            .and_then(|t| serde_json::from_str(&t).ok())
            .unwrap_or_default()
    }

    pub fn save(&self, path: &Path) {
        // A cache that cannot be written is only a cache: the next start fetches again.
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

    /// Whether the cache should be refreshed now. `wanted` are the machine types the boxes use.
    pub fn refresh_due(&self, now_ms: u64, wanted: &[String]) -> bool {
        if now_ms.saturating_sub(self.last_attempt_ms) < RETRY_AFTER_MS {
            return false;
        }
        match &self.book {
            None => true,
            Some(b) => {
                b.age_ms(now_ms) >= REFRESH_AFTER_MS
                    || wanted
                        .iter()
                        .any(|t| b.provider == "aws" && !b.machine_hourly.contains_key(t))
            }
        }
    }
}

// ---------- parsing ----------

fn f64_of(v: &Value) -> Option<f64> {
    match v {
        Value::String(s) => s.trim().parse().ok(),
        Value::Number(n) => n.as_f64(),
        _ => None,
    }
    .filter(|x: &f64| x.is_finite() && *x >= 0.0)
}

/// The products in `aws pricing get-products` output. `PriceList` holds JSON documents as strings.
fn aws_products(output: &str) -> Vec<Value> {
    let Ok(outer) = serde_json::from_str::<Value>(output) else {
        return Vec::new();
    };
    outer
        .get("PriceList")
        .and_then(Value::as_array)
        .map(|a| {
            a.iter()
                .filter_map(|e| match e {
                    Value::String(s) => serde_json::from_str(s).ok(),
                    other => Some(other.clone()),
                })
                .collect()
        })
        .unwrap_or_default()
}

/// Every on-demand price in a product, `(unit, usd)`.
fn on_demand_dimensions(product: &Value) -> Vec<(String, f64)> {
    let mut out = Vec::new();
    let Some(terms) = product
        .pointer("/terms/OnDemand")
        .and_then(Value::as_object)
    else {
        return out;
    };
    for term in terms.values() {
        let Some(dims) = term.get("priceDimensions").and_then(Value::as_object) else {
            continue;
        };
        for d in dims.values() {
            let unit = d.get("unit").and_then(Value::as_str).unwrap_or("");
            if let Some(usd) = d.pointer("/pricePerUnit/USD").and_then(f64_of) {
                if usd > 0.0 {
                    out.push((unit.to_string(), usd));
                }
            }
        }
    }
    out
}

fn cheapest(prices: impl Iterator<Item = f64>) -> Option<f64> {
    prices.fold(None, |m: Option<f64>, p| Some(m.map_or(p, |m| m.min(p))))
}

/// Hourly USD of an instance type from a `get-products` answer.
pub fn parse_aws_hourly(output: &str) -> Option<f64> {
    cheapest(
        aws_products(output)
            .iter()
            .flat_map(on_demand_dimensions)
            .filter(|(u, _)| u == "Hrs")
            .map(|(_, p)| p),
    )
}

/// GB-month USD of a storage product. `usagetype_suffix` picks standard snapshots out of the snapshot family.
pub fn parse_aws_gb_month(output: &str, usagetype_suffix: Option<&str>) -> Option<f64> {
    cheapest(
        aws_products(output)
            .iter()
            .filter(|p| {
                usagetype_suffix.is_none_or(|s| {
                    p.pointer("/product/attributes/usagetype")
                        .and_then(Value::as_str)
                        .is_some_and(|u| u.ends_with(s))
                })
            })
            .flat_map(on_demand_dimensions)
            .filter(|(u, _)| u == "GB-Mo")
            .map(|(_, p)| p),
    )
}

/// The AWS Price List API names a region by its long name.
pub fn aws_location(region: &str) -> Option<&'static str> {
    Some(match region {
        "us-east-1" => "US East (N. Virginia)",
        "us-east-2" => "US East (Ohio)",
        "us-west-1" => "US West (N. California)",
        "us-west-2" => "US West (Oregon)",
        "ca-central-1" => "Canada (Central)",
        "sa-east-1" => "South America (Sao Paulo)",
        "eu-west-1" => "EU (Ireland)",
        "eu-west-2" => "EU (London)",
        "eu-west-3" => "EU (Paris)",
        "eu-central-1" => "EU (Frankfurt)",
        "eu-north-1" => "EU (Stockholm)",
        "eu-south-1" => "EU (Milan)",
        "af-south-1" => "Africa (Cape Town)",
        "me-south-1" => "Middle East (Bahrain)",
        "ap-south-1" => "Asia Pacific (Mumbai)",
        "ap-southeast-1" => "Asia Pacific (Singapore)",
        "ap-southeast-2" => "Asia Pacific (Sydney)",
        "ap-northeast-1" => "Asia Pacific (Tokyo)",
        "ap-northeast-2" => "Asia Pacific (Seoul)",
        "ap-east-1" => "Asia Pacific (Hong Kong)",
        _ => return None,
    })
}

/// What a Hetzner `GET /pricing` answer holds.
#[derive(Debug, Clone, PartialEq)]
pub struct HcloudPrices {
    pub currency: String,
    pub machine_hourly: BTreeMap<String, f64>,
    pub volume_gb_month: Option<f64>,
    pub snapshot_gb_month: Option<f64>,
}

pub fn parse_hcloud(body: &str) -> Option<HcloudPrices> {
    let v: Value = serde_json::from_str(body).ok()?;
    let p = v.get("pricing")?;
    let mut machines = BTreeMap::new();
    for t in p.get("server_types")?.as_array()? {
        let name = t.get("name")?.as_str()?;
        for pr in t.get("prices")?.as_array()? {
            let loc = pr.get("location").and_then(Value::as_str).unwrap_or("");
            if let Some(h) = pr.pointer("/price_hourly/net").and_then(f64_of) {
                machines.insert(format!("{name}@{loc}"), h);
                machines
                    .entry(name.to_string())
                    .and_modify(|e: &mut f64| *e = e.min(h))
                    .or_insert(h);
            }
        }
    }
    if machines.is_empty() {
        return None;
    }
    Some(HcloudPrices {
        currency: p
            .get("currency")
            .and_then(Value::as_str)
            .unwrap_or("EUR")
            .to_string(),
        machine_hourly: machines,
        volume_gb_month: p.pointer("/volume/price_per_gb_month/net").and_then(f64_of),
        snapshot_gb_month: p.pointer("/image/price_per_gb_month/net").and_then(f64_of),
    })
}

// ---------- fetching ----------

fn machine_types(boxes: &[BoxRecord], provider: &str) -> Vec<String> {
    let mut v: Vec<String> = boxes
        .iter()
        .filter(|r| r.provider == provider && r.state != BoxState::Destroying)
        .filter_map(|r| r.machine_type.clone())
        .collect();
    v.sort();
    v.dedup();
    v
}

fn short(s: &str) -> String {
    let line = s
        .lines()
        .find(|l| !l.trim().is_empty())
        .unwrap_or("")
        .trim();
    line.chars().take(200).collect()
}

pub struct AwsFetcher {
    pub runner: Arc<dyn CommandRunner>,
    pub profile: Option<String>,
    pub default_region: Option<String>,
}

impl AwsFetcher {
    fn call(&self, filters: &[(&str, &str)]) -> Result<String, String> {
        let mut c = CommandSpec::new("aws")
            .args(["pricing", "get-products", "--service-code", "AmazonEC2"])
            // The Price List API answers from a few regions only, whatever region is being priced.
            .args([
                "--region",
                "us-east-1",
                "--max-results",
                "20",
                "--output",
                "json",
            ])
            .arg("--filters");
        for (field, value) in filters {
            c = c.arg(format!("Type=TERM_MATCH,Field={field},Value={value}"));
        }
        if let Some(p) = &self.profile {
            c = c.args(["--profile", p]);
        }
        self.runner
            .run_ok(&c)
            .map(|o| o.stdout)
            .map_err(|e| match e {
                ozbox_core::Error::Command { stderr, .. } => {
                    format!("the AWS price list could not be read: {}", short(&stderr))
                }
                other => format!(
                    "the AWS price list could not be read: {}",
                    short(&other.to_string())
                ),
            })
    }

    pub fn fetch(&self, boxes: &[BoxRecord], now_ms: u64) -> Result<PriceBook, String> {
        let region = boxes
            .iter()
            .filter(|r| r.provider == "aws")
            .find_map(|r| r.spec.region.clone())
            .or_else(|| self.default_region.clone())
            .ok_or("no AWS region is known to price")?;
        let location = aws_location(&region)
            .ok_or_else(|| format!("the region {region} is not in the price table yet"))?;
        fn common<'a>(
            location: &'a str,
            extra: Vec<(&'a str, &'a str)>,
        ) -> Vec<(&'a str, &'a str)> {
            let mut f = vec![("location", location)];
            f.extend(extra);
            f
        }
        let mut machines = BTreeMap::new();
        for t in machine_types(boxes, "aws") {
            let out = self.call(&common(
                location,
                vec![
                    ("instanceType", &t),
                    ("operatingSystem", "Linux"),
                    ("tenancy", "Shared"),
                    ("preInstalledSw", "NA"),
                    ("capacitystatus", "Used"),
                ],
            ))?;
            if let Some(h) = parse_aws_hourly(&out) {
                machines.insert(t, h);
            }
        }
        let disk = self
            .call(&common(
                location,
                vec![("productFamily", "Storage"), ("volumeApiName", "gp3")],
            ))
            .ok()
            .and_then(|o| parse_aws_gb_month(&o, None));
        let snap = self
            .call(&common(
                location,
                vec![("productFamily", "Storage Snapshot")],
            ))
            .ok()
            .and_then(|o| parse_aws_gb_month(&o, Some("EBS:SnapshotUsage")));
        if machines.is_empty() && disk.is_none() {
            return Err("the AWS price list returned no price for this fleet".into());
        }
        Ok(PriceBook {
            provider: "aws".into(),
            currency: "USD".into(),
            source: "AWS Price List API, on-demand Linux".into(),
            region,
            fetched_at_ms: now_ms,
            machine_hourly: machines,
            disk_gb_month: disk,
            snapshot_gb_month: snap,
        })
    }
}

pub struct HcloudFetcher {
    pub http: Arc<dyn HttpClient>,
}

impl HcloudFetcher {
    pub fn fetch(&self, boxes: &[BoxRecord], now_ms: u64) -> Result<PriceBook, String> {
        // Read at the moment of the call, the way the provider adapter does.
        let token = std::env::var("HCLOUD_TOKEN").map_err(|_| {
            "HCLOUD_TOKEN is not set, so the Hetzner price list cannot be read".to_string()
        })?;
        let resp = self
            .http
            .send(
                &HttpRequest::new("GET", "https://api.hetzner.cloud/v1/pricing", Guard::Public)
                    .header("Authorization", format!("Bearer {token}")),
            )
            .map_err(|e| format!("the Hetzner price list could not be read: {e}"))?;
        if !resp.ok() {
            return Err(format!(
                "the Hetzner price list could not be read (HTTP {})",
                resp.status
            ));
        }
        let p = parse_hcloud(&resp.body).ok_or("the Hetzner price list had an unexpected shape")?;
        let region = boxes
            .iter()
            .find_map(|r| r.spec.region.clone())
            .unwrap_or_default();
        Ok(PriceBook {
            provider: "hcloud".into(),
            currency: p.currency,
            source: "Hetzner Cloud pricing API, net of VAT".into(),
            region,
            fetched_at_ms: now_ms,
            machine_hourly: p.machine_hourly,
            disk_gb_month: p.volume_gb_month,
            snapshot_gb_month: p.snapshot_gb_month,
        })
    }
}

/// Fetch for the provider this server runs. The fake provider has no public prices.
pub fn fetch(
    provider: &str,
    aws: &AwsFetcher,
    hcloud: &HcloudFetcher,
    boxes: &[BoxRecord],
    now_ms: u64,
) -> Option<Result<PriceBook, String>> {
    match provider {
        "aws" => Some(aws.fetch(boxes, now_ms)),
        "hcloud" => Some(hcloud.fetch(boxes, now_ms)),
        _ => None,
    }
}

/// Fold a fetch into the cache. A failed fetch keeps the old book (it will show stale) and records why.
pub fn record_attempt(cache: &mut PriceCache, result: Result<PriceBook, String>, now_ms: u64) {
    cache.last_attempt_ms = now_ms;
    match result {
        Ok(book) => {
            cache.book = Some(book);
            cache.last_error = None;
        }
        Err(e) => cache.last_error = Some(e),
    }
}

pub fn wanted_types(boxes: &[BoxRecord]) -> Vec<String> {
    let mut v: Vec<String> = boxes
        .iter()
        .filter(|r| r.state != BoxState::Destroying)
        .filter_map(|r| r.machine_type.clone())
        .collect();
    v.sort();
    v.dedup();
    v
}

// ---------- estimates ----------

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PriceSource {
    /// Typed in Settings.
    Entered,
    /// From the provider's public price list.
    PriceList,
}

/// What a box costs per hour, as far as it is known. A part with no price is `None`, never zero.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct BoxCost {
    pub machine_hourly: Option<f64>,
    pub disk_hourly: Option<f64>,
    pub currency: Option<String>,
    pub machine_source: Option<PriceSource>,
    /// `Some(n)` snapshots exist and are not priced, because their size is not known.
    pub snapshots_unpriced: u32,
}

pub fn box_cost(rec: &BoxRecord, settings: &Settings, book: Option<&PriceBook>) -> BoxCost {
    let region = rec.spec.region.as_deref();
    let entered = settings.price(rec.spec.size).map(|m| m / HOURS_PER_MONTH);
    let listed = rec
        .machine_type
        .as_deref()
        .zip(book)
        .and_then(|(t, b)| b.machine(t, region).map(|h| (h, b.currency.clone())));
    let (machine_hourly, machine_source, currency) = match (entered, listed.clone()) {
        (Some(h), _) => (Some(h), Some(PriceSource::Entered), Some("USD".to_string())),
        (None, Some((h, c))) => (Some(h), Some(PriceSource::PriceList), Some(c)),
        (None, None) => (None, None, book.map(|b| b.currency.clone())),
    };
    let disk_hourly = book
        .and_then(|b| b.disk_gb_month)
        .map(|gb| gb * f64::from(rec.spec.work_disk_gb) / HOURS_PER_MONTH);
    BoxCost {
        machine_hourly,
        disk_hourly,
        currency,
        machine_source,
        snapshots_unpriced: rec.snapshots.len() as u32,
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use serde_json::json;

    fn aws_answer(products: Vec<Value>) -> String {
        let list: Vec<String> = products.iter().map(Value::to_string).collect();
        json!({ "FormatVersion": "aws_v1", "PriceList": list }).to_string()
    }

    fn product(usagetype: &str, unit: &str, usd: &str) -> Value {
        json!({
            "product": { "attributes": { "usagetype": usagetype } },
            "terms": { "OnDemand": { "T1": { "priceDimensions": { "D1": { "unit": unit, "pricePerUnit": { "USD": usd } } } } } }
        })
    }

    #[test]
    fn aws_hourly_is_read_from_a_doubly_encoded_answer() {
        let out = aws_answer(vec![product("BoxUsage:m7i.4xlarge", "Hrs", "0.8064000000")]);
        assert_eq!(parse_aws_hourly(&out), Some(0.8064));
        // The cheapest positive Hrs price wins; zero prices and other units are ignored.
        let out = aws_answer(vec![
            product("a", "Hrs", "0.0000000000"),
            product("b", "Hrs", "1.5"),
            product("c", "Hrs", "0.9"),
            product("d", "GB-Mo", "0.01"),
        ]);
        assert_eq!(parse_aws_hourly(&out), Some(0.9));
        assert_eq!(parse_aws_hourly("not json"), None);
        assert_eq!(parse_aws_hourly(&aws_answer(vec![])), None);
    }

    #[test]
    fn aws_storage_and_standard_snapshots() {
        let ebs = aws_answer(vec![product(
            "EBS:VolumeUsage.gp3",
            "GB-Mo",
            "0.0800000000",
        )]);
        assert_eq!(parse_aws_gb_month(&ebs, None), Some(0.08));
        let snaps = aws_answer(vec![
            product("EBS:SnapshotArchiveStorage", "GB-Mo", "0.0125"),
            product("EBS:SnapshotUsage", "GB-Mo", "0.0500000000"),
            product("EBS:SnapshotUsage", "Hrs", "9"),
        ]);
        assert_eq!(
            parse_aws_gb_month(&snaps, Some("EBS:SnapshotUsage")),
            Some(0.05)
        );
        assert_eq!(parse_aws_gb_month(&snaps, Some("Nope")), None);
    }

    #[test]
    fn hetzner_pricing_answer() {
        let body = json!({ "pricing": {
            "currency": "EUR",
            "volume": { "price_per_gb_month": { "net": "0.0440000000", "gross": "0.0524" } },
            "image": { "price_per_gb_month": { "net": "0.0119000000" } },
            "server_types": [
                { "id": 1, "name": "ccx43", "prices": [
                    { "location": "fsn1", "price_hourly": { "net": "0.2000000000" } },
                    { "location": "ash", "price_hourly": { "net": "0.2500000000" } } ] }
            ] } })
        .to_string();
        let p = parse_hcloud(&body).unwrap();
        assert_eq!(p.currency, "EUR");
        assert_eq!(p.machine_hourly.get("ccx43@fsn1"), Some(&0.2));
        assert_eq!(p.machine_hourly.get("ccx43@ash"), Some(&0.25));
        assert_eq!(p.machine_hourly.get("ccx43"), Some(&0.2));
        assert_eq!(p.volume_gb_month, Some(0.044));
        assert_eq!(p.snapshot_gb_month, Some(0.0119));
        assert!(parse_hcloud("{}").is_none());
    }

    #[test]
    fn region_names() {
        assert_eq!(aws_location("us-east-1"), Some("US East (N. Virginia)"));
        assert_eq!(aws_location("mars-north-1"), None);
    }

    fn rec_with(
        machine: Option<&str>,
        size: ozbox_core::Size,
    ) -> Result<BoxRecord, ozbox_core::Error> {
        Ok(BoxRecord {
            spec: ozbox_core::BoxSpec::new(ozbox_core::BoxName::new("dev")?, size),
            state: BoxState::Running,
            provider: "aws".into(),
            provider_id: None,
            machine_type: machine.map(str::to_string),
            snapshots: vec!["s1".into()],
            created_at: None,
            last_activity_at: None,
        })
    }

    fn book() -> PriceBook {
        PriceBook {
            provider: "aws".into(),
            currency: "USD".into(),
            source: "AWS Price List API, on-demand Linux".into(),
            region: "us-east-1".into(),
            fetched_at_ms: 1_000,
            machine_hourly: BTreeMap::from([("m7i.4xlarge".to_string(), 0.8)]),
            disk_gb_month: Some(0.08),
            snapshot_gb_month: Some(0.05),
        }
    }

    #[test]
    fn staleness_and_refresh_rules() {
        let b = book();
        assert!(!b.is_stale(1_000 + 35 * HOUR_MS));
        assert!(b.is_stale(1_000 + 37 * HOUR_MS));
        let mut c = PriceCache {
            book: Some(b),
            ..PriceCache::default()
        };
        let t0 = 1_000 + 25 * HOUR_MS;
        assert!(c.refresh_due(t0, &[]), "older than a day");
        assert!(!c.refresh_due(1_000 + 2 * HOUR_MS, &[]));
        assert!(
            c.refresh_due(1_000 + 2 * HOUR_MS, &["c7i.large".to_string()]),
            "a machine we have no price for"
        );
        c.last_attempt_ms = t0 - 60_000;
        assert!(
            !c.refresh_due(t0, &[]),
            "a failed attempt is not retried at once"
        );
        assert!(PriceCache::default().refresh_due(RETRY_AFTER_MS, &[]));
    }

    #[test]
    fn a_failed_refresh_keeps_the_old_book_and_says_why() {
        let mut c = PriceCache {
            book: Some(book()),
            ..PriceCache::default()
        };
        record_attempt(&mut c, Err("no credentials".into()), 5_000);
        assert!(c.book.is_some());
        assert_eq!(c.last_error.as_deref(), Some("no credentials"));
        record_attempt(&mut c, Ok(book()), 6_000);
        assert!(c.last_error.is_none());
    }

    #[test]
    fn the_cache_round_trips_on_disk() -> Result<(), Box<dyn std::error::Error>> {
        let dir = tempfile::tempdir()?;
        let p = dir.path().join("prices.json");
        let c = PriceCache {
            book: Some(book()),
            last_error: Some("x".into()),
            last_attempt_ms: 9,
        };
        c.save(&p);
        assert_eq!(PriceCache::load(&p), c);
        assert_eq!(
            PriceCache::load(&dir.path().join("none.json")),
            PriceCache::default()
        );
        Ok(())
    }

    #[test]
    fn a_box_is_priced_from_the_list_or_from_what_the_owner_entered(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let rec = rec_with(Some("m7i.4xlarge"), ozbox_core::Size::M)?;
        let s = Settings::default();
        let c = box_cost(&rec, &s, Some(&book()));
        assert_eq!(c.machine_hourly, Some(0.8));
        assert_eq!(c.machine_source, Some(PriceSource::PriceList));
        assert!(c.disk_hourly.is_some_and(|d| d > 0.0));
        assert_eq!(c.snapshots_unpriced, 1);
        // The owner's own price overrides the list.
        let mut s2 = Settings::default();
        s2.budget.size_prices_usd.insert("M".into(), 73.0);
        let c2 = box_cost(&rec, &s2, Some(&book()));
        assert_eq!(c2.machine_source, Some(PriceSource::Entered));
        assert!((c2.machine_hourly.unwrap_or(0.0) - 0.1).abs() < 1e-9);
        // A machine the list does not answer for has no price at all.
        let unknown = rec_with(Some("x9.huge"), ozbox_core::Size::M)?;
        let c3 = box_cost(&unknown, &s, Some(&book()));
        assert_eq!(c3.machine_hourly, None);
        assert_eq!(box_cost(&rec, &s, None).machine_hourly, None);
        Ok(())
    }

    #[test]
    fn the_aws_fetch_goes_through_the_command_runner_with_filters_and_no_credentials_here(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let runner = Arc::new(ozbox_core::RecordingRunner::new());
        let hourly = aws_answer(vec![product("BoxUsage:m7i.4xlarge", "Hrs", "0.8064")]);
        let ebs = aws_answer(vec![product("EBS:VolumeUsage.gp3", "GB-Mo", "0.08")]);
        let snap = aws_answer(vec![product("EBS:SnapshotUsage", "GB-Mo", "0.05")]);
        for out in [hourly, ebs, snap] {
            runner.reply(ozbox_core::Output {
                status: Some(0),
                stdout: out,
                stderr: String::new(),
            });
        }
        let mut rec = rec_with(Some("m7i.4xlarge"), ozbox_core::Size::M)?;
        rec.spec.region = Some("us-east-1".into());
        let f = AwsFetcher {
            runner: runner.clone(),
            profile: Some("dev".into()),
            default_region: None,
        };
        let b = f.fetch(&[rec], 42)?;
        assert_eq!(b.machine_hourly.get("m7i.4xlarge"), Some(&0.8064));
        assert_eq!(b.disk_gb_month, Some(0.08));
        assert_eq!(b.snapshot_gb_month, Some(0.05));
        assert_eq!(b.fetched_at_ms, 42);
        let calls = runner.calls();
        assert_eq!(calls.len(), 3);
        let first = &calls[0].args;
        assert_eq!(
            &first[..4],
            ["pricing", "get-products", "--service-code", "AmazonEC2"]
        );
        assert!(first.contains(&"Type=TERM_MATCH,Field=instanceType,Value=m7i.4xlarge".to_string()));
        assert!(first
            .contains(&"Type=TERM_MATCH,Field=location,Value=US East (N. Virginia)".to_string()));
        assert!(first.contains(&"Type=TERM_MATCH,Field=operatingSystem,Value=Linux".to_string()));
        assert!(first.contains(&"Type=TERM_MATCH,Field=tenancy,Value=Shared".to_string()));
        assert!(first.contains(&"Type=TERM_MATCH,Field=preInstalledSw,Value=NA".to_string()));
        assert!(first.contains(&"Type=TERM_MATCH,Field=capacitystatus,Value=Used".to_string()));
        assert!(first.windows(2).any(|w| w == ["--profile", "dev"]));
        Ok(())
    }

    #[test]
    fn missing_credentials_come_back_as_a_reason_not_a_panic(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let runner = Arc::new(ozbox_core::RecordingRunner::new());
        runner.reply(ozbox_core::Output {
            status: Some(255),
            stdout: String::new(),
            stderr: "Unable to locate credentials. You can configure credentials by running \"aws configure\".\n".into(),
        });
        let mut rec = rec_with(Some("m7i.4xlarge"), ozbox_core::Size::M)?;
        rec.spec.region = Some("us-east-1".into());
        let f = AwsFetcher {
            runner,
            profile: None,
            default_region: None,
        };
        let e = f.fetch(&[rec], 1).err().unwrap_or_default();
        assert!(e.contains("Unable to locate credentials"), "{e}");
        Ok(())
    }

    #[test]
    fn an_unknown_region_is_a_reason() -> Result<(), Box<dyn std::error::Error>> {
        let runner = Arc::new(ozbox_core::RecordingRunner::new());
        let mut rec = rec_with(Some("m7i.4xlarge"), ozbox_core::Size::M)?;
        rec.spec.region = Some("mars-north-1".into());
        let f = AwsFetcher {
            runner: runner.clone(),
            profile: None,
            default_region: None,
        };
        assert!(f.fetch(&[rec], 1).is_err());
        assert!(runner.calls().is_empty());
        Ok(())
    }
}
