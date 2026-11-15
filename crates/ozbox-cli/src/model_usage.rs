//! Model usage: the record the runs write, and the rollups Settings -> Models and `ozbox models usage` show.
//!
//! **The recording hook is [`record`].** Whatever makes a model call on a person's behalf (an agent run, a scheduled
//! task) calls it once per call or per finished run with an [`ozbox_core::ModelUsage`]: the provider id and model it
//! used, the box and engine, and the token counts the provider reported. It appends one line to `model-usage.jsonl`
//! beside the settings file. Records hold names and counts only. [`month_spend_usd`] is what a spend cap checks.
//! Costs are estimates (see `model_prices`) and say so.

use std::collections::BTreeMap;
use std::io::Write;
use std::path::{Path, PathBuf};

use ozbox_core::ModelUsage;
use serde::Serialize;

use crate::model_prices::{estimate_usd, lookup};
use crate::settings::{ModelsConfig, Settings};
use crate::state::{civil, month_key};

const DAY_MS: u64 = 86_400_000;
/// Records older than this are not read (the file is only ever appended to; a year is more than any chart shows).
const KEEP_DAYS: u64 = 400;
const MAX_READ_BYTES: u64 = 64 * 1024 * 1024;

/// Where the usage file lives: beside the settings file.
pub fn path_for(settings_path: &Path) -> PathBuf {
    settings_path.with_file_name("model-usage.jsonl")
}

/// Append one record. A record that is not valid is refused; a write that fails is reported, never panics.
pub fn record(path: &Path, u: &ModelUsage) -> Result<(), String> {
    if !u.is_valid() {
        return Err("that usage record is not valid".into());
    }
    if let Some(dir) = path.parent() {
        std::fs::create_dir_all(dir)
            .map_err(|_| "could not create the usage folder".to_string())?;
    }
    let mut f = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)
        .map_err(|_| "could not open the usage file".to_string())?;
    let mut line = serde_json::to_string(u).map_err(|e| e.to_string())?;
    line.push('\n');
    f.write_all(line.as_bytes())
        .map_err(|_| "could not write the usage file".to_string())
}

/// Every readable, recent record, oldest first. A line that does not parse is skipped.
pub fn read(path: &Path, now_ms: u64) -> Vec<ModelUsage> {
    let Ok(meta) = std::fs::metadata(path) else {
        return Vec::new();
    };
    if meta.len() > MAX_READ_BYTES {
        return Vec::new();
    }
    let Ok(text) = std::fs::read_to_string(path) else {
        return Vec::new();
    };
    let floor = now_ms.saturating_sub(KEEP_DAYS * DAY_MS);
    text.lines()
        .filter_map(|l| serde_json::from_str::<ModelUsage>(l).ok())
        .filter(|u| u.is_valid() && u.ts_ms >= floor)
        .collect()
}

#[derive(Debug, Clone, Default, PartialEq, Serialize)]
pub struct Totals {
    pub input_tokens: u64,
    pub output_tokens: u64,
    pub cached_input_tokens: u64,
    pub calls: u64,
    /// Estimated, in US dollars. Calls whose model has no price are counted in `unpriced_calls` and add nothing.
    pub est_cost_usd: f64,
    pub unpriced_calls: u64,
}

impl Totals {
    fn add(&mut self, u: &ModelUsage, cost: Option<f64>) {
        self.input_tokens += u.input_tokens;
        self.output_tokens += u.output_tokens;
        self.cached_input_tokens += u.cached_input_tokens;
        self.calls += 1;
        match cost {
            Some(c) => self.est_cost_usd += c,
            None => self.unpriced_calls += 1,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct Row {
    /// `YYYY-MM-DD` (UTC) for a day row; the key (provider id / `provider/model` / box / engine) for the others.
    pub key: String,
    #[serde(flatten)]
    pub totals: Totals,
}

#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct Summary {
    pub days: u32,
    pub estimate: bool,
    pub total: Totals,
    pub by_day: Vec<Row>,
    pub by_provider: Vec<Row>,
    pub by_model: Vec<Row>,
    pub by_box: Vec<Row>,
    pub by_engine: Vec<Row>,
}

fn day_key(ms: u64) -> String {
    let (y, m, d) = civil(ms);
    format!("{y:04}-{m:02}-{d:02}")
}

pub fn cost_of(cfg: &ModelsConfig, u: &ModelUsage) -> Option<f64> {
    let p = cfg.providers.iter().find(|p| p.id == u.provider_id)?;
    let price = lookup(cfg, p, &u.model)?;
    Some(estimate_usd(
        &price,
        u.input_tokens,
        u.output_tokens,
        u.cached_input_tokens,
    ))
}

fn rows(m: BTreeMap<String, Totals>) -> Vec<Row> {
    m.into_iter()
        .map(|(key, totals)| Row { key, totals })
        .collect()
}

/// Add up the records of the last `days` days (ending now), every day present even when empty.
pub fn summarize(cfg: &ModelsConfig, records: &[ModelUsage], now_ms: u64, days: u32) -> Summary {
    let days = days.clamp(1, 366);
    let from = now_ms.saturating_sub(u64::from(days - 1) * DAY_MS);
    let from_day = from / DAY_MS;
    let mut by_day: BTreeMap<String, Totals> = (0..u64::from(days))
        .map(|i| (day_key((from_day + i) * DAY_MS), Totals::default()))
        .collect();
    let (mut prov, mut model, mut bx, mut eng) = (
        BTreeMap::new(),
        BTreeMap::new(),
        BTreeMap::new(),
        BTreeMap::new(),
    );
    let mut total = Totals::default();
    for u in records
        .iter()
        .filter(|u| u.ts_ms / DAY_MS >= from_day && u.ts_ms <= now_ms)
    {
        let cost = cost_of(cfg, u);
        total.add(u, cost);
        by_day.entry(day_key(u.ts_ms)).or_default().add(u, cost);
        prov.entry(u.provider_id.clone())
            .or_insert_with(Totals::default)
            .add(u, cost);
        model
            .entry(format!("{}/{}", u.provider_id, u.model))
            .or_insert_with(Totals::default)
            .add(u, cost);
        bx.entry(u.box_name.clone().unwrap_or_else(|| "-".into()))
            .or_insert_with(Totals::default)
            .add(u, cost);
        eng.entry(u.engine.clone().unwrap_or_else(|| "-".into()))
            .or_insert_with(Totals::default)
            .add(u, cost);
    }
    Summary {
        days,
        estimate: true,
        total,
        by_day: rows(by_day),
        by_provider: rows(prov),
        by_model: rows(model),
        by_box: rows(bx),
        by_engine: rows(eng),
    }
}

/// Estimated dollars one provider has used this calendar month (UTC): what a monthly cap is compared with.
pub fn month_spend_usd(
    cfg: &ModelsConfig,
    records: &[ModelUsage],
    provider_id: &str,
    now_ms: u64,
) -> f64 {
    let month = month_key(now_ms);
    records
        .iter()
        .filter(|u| u.provider_id == provider_id && month_key(u.ts_ms) == month)
        .filter_map(|u| cost_of(cfg, u))
        .sum()
}

/// Whether a provider has reached its monthly cap (no cap = never). Unpriced models add nothing, so a provider whose
/// models have no price is never stopped by a cap it cannot measure; the dashboard says so.
pub fn cap_reached(
    cfg: &ModelsConfig,
    records: &[ModelUsage],
    provider_id: &str,
    now_ms: u64,
) -> bool {
    cfg.providers
        .iter()
        .find(|p| p.id == provider_id)
        .and_then(|p| p.monthly_cap_usd)
        .is_some_and(|cap| month_spend_usd(cfg, records, provider_id, now_ms) >= cap)
}

pub fn summary_for(
    settings: &Settings,
    settings_path: Option<&Path>,
    now_ms: u64,
    days: u32,
) -> Summary {
    let records = settings_path
        .map(|p| read(&path_for(p), now_ms))
        .unwrap_or_default();
    summarize(&settings.models, &records, now_ms, days)
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use crate::settings::{ModelKind, ModelProvider};

    const NOW: u64 = 1_794_000_000_000; // 2026-11-06

    fn cfg() -> ModelsConfig {
        let p = |id: &str, kind: ModelKind, local: bool, cap: Option<f64>| ModelProvider {
            id: id.into(),
            kind,
            label: id.into(),
            base_url: local.then(|| "http://127.0.0.1:11434/v1".into()),
            local_endpoint: local,
            monthly_cap_usd: cap,
            region: None,
            resource: None,
            hosted_on: None,
        };
        ModelsConfig {
            providers: vec![
                p("oa", ModelKind::Openai, false, Some(1.0)),
                p("loc", ModelKind::OpenaiCompatible, true, None),
            ],
            ..Default::default()
        }
    }

    fn u(ts: u64, prov: &str, model: &str, i: u64, o: u64) -> ModelUsage {
        ModelUsage {
            ts_ms: ts,
            box_name: Some("dev".into()),
            engine: Some("codex".into()),
            provider_id: prov.into(),
            model: model.into(),
            input_tokens: i,
            output_tokens: o,
            cached_input_tokens: 0,
        }
    }

    #[test]
    fn records_append_one_line_each_and_invalid_ones_are_refused() {
        let dir = tempfile::tempdir().unwrap();
        let path = path_for(&dir.path().join("settings.json"));
        record(&path, &u(NOW, "oa", "gpt-4o", 10, 5)).unwrap();
        record(&path, &u(NOW, "oa", "gpt-4o", 1, 1)).unwrap();
        assert!(record(&path, &u(0, "oa", "gpt-4o", 1, 1)).is_err());
        assert_eq!(read(&path, NOW).len(), 2);
        std::fs::write(&path, "not json\n").unwrap();
        assert!(read(&path, NOW).is_empty());
    }

    #[test]
    fn a_summary_has_every_day_prices_what_it_can_and_counts_the_rest() {
        let recs = vec![
            u(NOW, "oa", "gpt-4o", 1_000_000, 100_000),
            u(NOW - DAY_MS, "oa", "unknown-model", 5, 5),
            u(NOW, "loc", "llama3.1:8b", 9_000_000, 1_000_000),
            u(NOW - 40 * DAY_MS, "oa", "gpt-4o", 1, 1),
        ];
        let s = summarize(&cfg(), &recs, NOW, 7);
        assert_eq!(s.by_day.len(), 7);
        assert!(s.estimate);
        assert_eq!(s.total.calls, 3);
        // 1M in at 2.5 + 0.1M out at 10 = 3.5, local is free
        assert!(
            (s.total.est_cost_usd - 3.5).abs() < 1e-9,
            "{}",
            s.total.est_cost_usd
        );
        assert_eq!(s.total.unpriced_calls, 1);
        assert_eq!(s.by_provider.len(), 2);
        assert_eq!(s.by_engine[0].key, "codex");
        assert_eq!(s.by_box[0].key, "dev");
        assert_eq!(
            s.by_model
                .iter()
                .find(|r| r.key == "oa/gpt-4o")
                .unwrap()
                .totals
                .calls,
            1
        );
    }

    #[test]
    fn a_cap_is_compared_with_this_months_estimated_spend() {
        let recs = vec![u(NOW, "oa", "gpt-4o", 1_000_000, 0)]; // $2.50 > $1 cap
        assert!(cap_reached(&cfg(), &recs, "oa", NOW));
        assert!(
            !cap_reached(&cfg(), &recs, "loc", NOW),
            "no cap, never reached"
        );
        let old = vec![u(NOW - 40 * DAY_MS, "oa", "gpt-4o", 1_000_000, 0)];
        assert!(
            !cap_reached(&cfg(), &old, "oa", NOW),
            "last month does not count"
        );
    }
}
