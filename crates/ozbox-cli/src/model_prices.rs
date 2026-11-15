//! What a model costs, as an **estimate**: US dollars per million tokens, with where the number came from and how old
//! it is. The built-in table is a small list of well-known hosted models; a price the person enters for a model wins;
//! a local endpoint costs nothing per token (the box it runs on is billed as a box); anything else has no price and is
//! shown as "—", never as a guess.

use serde::Serialize;

use crate::settings::{ModelKind, ModelProvider, ModelsConfig};

struct Entry {
    /// Matched anywhere in the lower-cased model name; the longest match wins (`gpt-4o-mini` over `gpt-4o`).
    needle: &'static str,
    input: f64,
    output: f64,
    source: &'static str,
    /// `YYYY-MM` the vendor's page was read for this entry. An old entry is called old.
    as_of: &'static str,
    /// Only for providers of this kind (the same model name is priced differently by each host).
    kind: Option<ModelKind>,
    /// A condition the price carries, shown beside it (for example the context size it holds for).
    note: &'static str,
}

/// When the built-in table was last checked against the vendors' pages (the newest entry). Every built-in price also
/// carries its own month, so an entry that was not re-read says so.
pub const TABLE_AS_OF: &str = "2026-11";

const ANTHROPIC: &str = "https://www.anthropic.com/pricing";
const OPENAI: &str = "https://developers.openai.com/api/docs/pricing";
const GROQ: &str = "https://console.groq.com/docs/models";
/// OpenAI prices its models by the size of the request: the table holds the short-context price.
const SHORT_CONTEXT: &str = "short context, up to 272K input tokens; longer requests cost more";
const GOOGLE: &str = "https://ai.google.dev/gemini-api/docs/pricing";
const MISTRAL: &str = "https://mistral.ai/pricing";
const TOGETHER: &str = "https://www.together.ai/pricing";
// Pages read 2026-11-10: claude.com/pricing (the old anthropic.com/pricing address redirects there), the Gemini API
// pricing page (ai.google.dev redirects to aistudio.google.com/docs/pricing), mistral.ai/pricing and together.ai/pricing.
// developers.openai.com/api/docs/pricing and console.groq.com/docs/models (read 2026-11-10; Groq lists no public price for
// its Llama models, so they are absent). gpt-5.6-sol is left out: its page price is promotional and ends 2026-11-30 with no
// published price after it. OpenRouter prices are not in this table: they are read live from its own model list
// (see `remember_live`).

const TABLE: &[Entry] = &[
    Entry {
        needle: "gpt-6-astra",
        input: 10.0,
        output: 50.0,
        source: OPENAI,
        as_of: "2026-11",
        kind: None,
        note: SHORT_CONTEXT,
    },
    Entry {
        needle: "gpt-6.1-sol",
        input: 2.0,
        output: 10.0,
        source: OPENAI,
        as_of: "2026-11",
        kind: None,
        note: SHORT_CONTEXT,
    },
    Entry {
        needle: "gpt-6.1-terra",
        input: 1.0,
        output: 5.0,
        source: OPENAI,
        as_of: "2026-11",
        kind: None,
        note: SHORT_CONTEXT,
    },
    Entry {
        needle: "gpt-6-luna",
        input: 0.1,
        output: 0.5,
        source: OPENAI,
        as_of: "2026-11",
        kind: None,
        note: SHORT_CONTEXT,
    },
    Entry {
        needle: "gpt-6-sol",
        input: 2.0,
        output: 10.0,
        source: OPENAI,
        as_of: "2026-11",
        kind: None,
        note: SHORT_CONTEXT,
    },
    Entry {
        needle: "gpt-5.6-terra",
        input: 2.0,
        output: 12.0,
        source: OPENAI,
        as_of: "2026-11",
        kind: None,
        note: SHORT_CONTEXT,
    },
    Entry {
        needle: "gpt-5.6-luna",
        input: 0.2,
        output: 1.2,
        source: OPENAI,
        as_of: "2026-11",
        kind: None,
        note: SHORT_CONTEXT,
    },
    Entry {
        needle: "gpt-5.5-pro",
        input: 30.0,
        output: 180.0,
        source: OPENAI,
        as_of: "2026-11",
        kind: None,
        note: SHORT_CONTEXT,
    },
    Entry {
        needle: "gpt-5.5",
        input: 5.0,
        output: 30.0,
        source: OPENAI,
        as_of: "2026-11",
        kind: None,
        note: SHORT_CONTEXT,
    },
    Entry {
        needle: "gpt-5.4-pro",
        input: 30.0,
        output: 180.0,
        source: OPENAI,
        as_of: "2026-11",
        kind: None,
        note: SHORT_CONTEXT,
    },
    Entry {
        needle: "gpt-5.4-mini",
        input: 0.75,
        output: 4.5,
        source: OPENAI,
        as_of: "2026-11",
        kind: None,
        note: SHORT_CONTEXT,
    },
    Entry {
        needle: "gpt-5.4-nano",
        input: 0.2,
        output: 1.25,
        source: OPENAI,
        as_of: "2026-11",
        kind: None,
        note: SHORT_CONTEXT,
    },
    Entry {
        needle: "gpt-5.4",
        input: 2.5,
        output: 15.0,
        source: OPENAI,
        as_of: "2026-11",
        kind: None,
        note: SHORT_CONTEXT,
    },
    Entry {
        needle: "gpt-5.2-pro",
        input: 21.0,
        output: 168.0,
        source: OPENAI,
        as_of: "2026-11",
        kind: None,
        note: SHORT_CONTEXT,
    },
    Entry {
        needle: "gpt-5.2",
        input: 1.75,
        output: 14.0,
        source: OPENAI,
        as_of: "2026-11",
        kind: None,
        note: SHORT_CONTEXT,
    },
    Entry {
        needle: "gpt-5.1",
        input: 1.25,
        output: 10.0,
        source: OPENAI,
        as_of: "2026-11",
        kind: None,
        note: SHORT_CONTEXT,
    },
    Entry {
        needle: "gpt-5-pro",
        input: 15.0,
        output: 120.0,
        source: OPENAI,
        as_of: "2026-11",
        kind: None,
        note: SHORT_CONTEXT,
    },
    Entry {
        needle: "gpt-5-mini",
        input: 0.25,
        output: 2.0,
        source: OPENAI,
        as_of: "2026-11",
        kind: None,
        note: SHORT_CONTEXT,
    },
    Entry {
        needle: "gpt-5-nano",
        input: 0.05,
        output: 0.4,
        source: OPENAI,
        as_of: "2026-11",
        kind: None,
        note: SHORT_CONTEXT,
    },
    Entry {
        needle: "gpt-5",
        input: 1.25,
        output: 10.0,
        source: OPENAI,
        as_of: "2026-11",
        kind: None,
        note: SHORT_CONTEXT,
    },
    Entry {
        needle: "gpt-4.1-mini",
        input: 0.4,
        output: 1.6,
        source: OPENAI,
        as_of: "2026-11",
        kind: None,
        note: SHORT_CONTEXT,
    },
    Entry {
        needle: "gpt-4.1",
        input: 2.0,
        output: 8.0,
        source: OPENAI,
        as_of: "2026-11",
        kind: None,
        note: SHORT_CONTEXT,
    },
    Entry {
        needle: "gpt-4o-mini",
        input: 0.15,
        output: 0.6,
        source: OPENAI,
        as_of: "2026-11",
        kind: None,
        note: SHORT_CONTEXT,
    },
    Entry {
        needle: "gpt-4o",
        input: 2.5,
        output: 10.0,
        source: OPENAI,
        as_of: "2026-11",
        kind: None,
        note: SHORT_CONTEXT,
    },
    Entry {
        needle: "o3-pro",
        input: 20.0,
        output: 80.0,
        source: OPENAI,
        as_of: "2026-11",
        kind: Some(ModelKind::Openai),
        note: SHORT_CONTEXT,
    },
    Entry {
        needle: "o3",
        input: 2.0,
        output: 8.0,
        source: OPENAI,
        as_of: "2026-11",
        kind: Some(ModelKind::Openai),
        note: SHORT_CONTEXT,
    },
    Entry {
        needle: "gpt-oss-120b",
        input: 0.15,
        output: 0.6,
        source: GROQ,
        as_of: "2026-11",
        kind: Some(ModelKind::Groq),
        note: "",
    },
    Entry {
        needle: "gpt-oss-20b",
        input: 0.075,
        output: 0.3,
        source: GROQ,
        as_of: "2026-11",
        kind: Some(ModelKind::Groq),
        note: "",
    },
    Entry {
        needle: "claude-opus-4",
        input: 15.0,
        output: 75.0,
        source: ANTHROPIC,
        as_of: "2025-06",
        kind: None,
        note: "",
    },
    Entry {
        needle: "claude-sonnet-4",
        input: 3.0,
        output: 15.0,
        source: ANTHROPIC,
        as_of: "2025-06",
        kind: None,
        note: "",
    },
    Entry {
        needle: "claude-3-7-sonnet",
        input: 3.0,
        output: 15.0,
        source: ANTHROPIC,
        as_of: "2025-06",
        kind: None,
        note: "",
    },
    Entry {
        needle: "claude-3-5-haiku",
        input: 0.8,
        output: 4.0,
        source: ANTHROPIC,
        as_of: "2025-06",
        kind: None,
        note: "",
    },
    Entry {
        needle: "gemini-2.5-pro",
        input: 1.25,
        output: 10.0,
        source: GOOGLE,
        as_of: "2025-06",
        kind: None,
        note: "",
    },
    Entry {
        needle: "gemini-2.5-flash",
        input: 0.30,
        output: 2.50,
        source: GOOGLE,
        as_of: "2026-11",
        kind: None,
        note: "",
    },
    Entry {
        needle: "mistral-small",
        input: 0.1,
        output: 0.3,
        source: MISTRAL,
        as_of: "2025-06",
        kind: None,
        note: "",
    },
    Entry {
        needle: "codestral",
        input: 0.3,
        output: 0.9,
        source: MISTRAL,
        as_of: "2025-06",
        kind: None,
        note: "",
    },
    Entry {
        needle: "mistral-large",
        input: 0.5,
        output: 1.5,
        source: MISTRAL,
        as_of: "2026-11",
        kind: None,
        note: "",
    },
    Entry {
        needle: "claude-fable-5",
        input: 8.0,
        output: 40.0,
        source: ANTHROPIC,
        as_of: "2026-11",
        kind: None,
        note: "",
    },
    Entry {
        needle: "claude-opus-5",
        input: 4.0,
        output: 20.0,
        source: ANTHROPIC,
        as_of: "2026-11",
        kind: None,
        note: "",
    },
    Entry {
        needle: "claude-sonnet-5",
        input: 2.0,
        output: 10.0,
        source: ANTHROPIC,
        as_of: "2026-11",
        kind: None,
        note: "",
    },
    Entry {
        needle: "gemini-2.5-flash-lite",
        input: 0.10,
        output: 0.40,
        source: GOOGLE,
        as_of: "2026-11",
        kind: None,
        note: "",
    },
    Entry {
        needle: "gemini-3.1-flash-lite",
        input: 0.25,
        output: 1.50,
        source: GOOGLE,
        as_of: "2026-11",
        kind: None,
        note: "",
    },
    Entry {
        needle: "gemini-3-flash",
        input: 0.50,
        output: 3.00,
        source: GOOGLE,
        as_of: "2026-11",
        kind: None,
        note: "",
    },
    Entry {
        needle: "gpt-oss-120b",
        input: 0.15,
        output: 0.60,
        source: TOGETHER,
        as_of: "2026-11",
        kind: Some(ModelKind::Together),
        note: "",
    },
    Entry {
        needle: "qwen2.5-7b-instruct-turbo",
        input: 0.30,
        output: 0.30,
        source: TOGETHER,
        as_of: "2026-11",
        kind: Some(ModelKind::Together),
        note: "",
    },
];

/// How much of a normal input price a cached input token costs (an estimate; providers differ).
pub const CACHED_INPUT_FACTOR: f64 = 0.1;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Origin {
    /// From the built-in table.
    BuiltIn,
    /// Entered by the person.
    Entered,
    /// A local endpoint: no price per token.
    Local,
    /// Read from the provider's own public model list, at the time shown.
    Live,
}

#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct PriceInfo {
    pub input_per_mtok_usd: f64,
    pub output_per_mtok_usd: f64,
    pub origin: Origin,
    /// Where the number comes from: the vendor's pricing page, or a sentence for an entered or local price.
    pub source: String,
    /// `YYYY-MM` the number was checked, for a built-in price.
    pub as_of: Option<String>,
    pub estimate: bool,
    /// A condition the price carries, if any (for example the context size).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub note: Option<String>,
    /// For a live price: when it was read, in milliseconds since 1970.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub read_at_ms: Option<u64>,
}

pub fn lookup(cfg: &ModelsConfig, p: &ModelProvider, model: &str) -> Option<PriceInfo> {
    if let Some(e) = cfg.prices.get(&format!("{}/{model}", p.id)) {
        return Some(PriceInfo {
            input_per_mtok_usd: e.input_per_mtok_usd,
            output_per_mtok_usd: e.output_per_mtok_usd,
            origin: Origin::Entered,
            source: "entered in Settings".into(),
            as_of: None,
            estimate: true,
            note: None,
            read_at_ms: None,
        });
    }
    if p.local_endpoint {
        return Some(PriceInfo {
            input_per_mtok_usd: 0.0,
            output_per_mtok_usd: 0.0,
            origin: Origin::Local,
            source: "runs on your own hardware; the box it runs on is billed as a box".into(),
            as_of: None,
            estimate: false,
            note: None,
            read_at_ms: None,
        });
    }
    if p.kind == ModelKind::Openrouter {
        // OpenRouter's prices differ per model and change: only what its own list said, with when.
        return live_price(model);
    }
    let lower = model.to_ascii_lowercase();
    TABLE
        .iter()
        .filter(|e| lower.contains(e.needle) && e.kind.is_none_or(|k| k == p.kind))
        .max_by_key(|e| e.needle.len())
        .map(|e| PriceInfo {
            input_per_mtok_usd: e.input,
            output_per_mtok_usd: e.output,
            origin: Origin::BuiltIn,
            source: e.source.into(),
            as_of: Some(e.as_of.into()),
            estimate: true,
            note: (!e.note.is_empty()).then(|| e.note.to_string()),
            read_at_ms: None,
        })
}

/// Where OpenRouter's prices are read.
pub const OPENROUTER_MODELS: &str = "https://openrouter.ai/api/v1/models";

/// One model's price from OpenRouter's list: dollars per million tokens.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct LiveRow {
    pub input: f64,
    pub output: f64,
}

struct LiveCache {
    read_at_ms: u64,
    rows: std::collections::BTreeMap<String, LiveRow>,
}

static LIVE: std::sync::Mutex<Option<LiveCache>> = std::sync::Mutex::new(None);

/// The prices in OpenRouter's model list. Its `pricing.prompt` and `pricing.completion` are dollars per TOKEN, as text;
/// a model with no price, a negative one (OpenRouter's "varies" is -1), or one that is not a number is skipped, never
/// shown as free.
pub fn parse_openrouter(body: &str) -> std::collections::BTreeMap<String, LiveRow> {
    let mut out = std::collections::BTreeMap::new();
    let Ok(v) = serde_json::from_str::<serde_json::Value>(body) else {
        return out;
    };
    let Some(items) = v.get("data").and_then(serde_json::Value::as_array) else {
        return out;
    };
    for i in items {
        let Some(id) = i.get("id").and_then(serde_json::Value::as_str) else {
            continue;
        };
        let per_token = |k: &str| -> Option<f64> {
            let x = i.get("pricing")?.get(k)?;
            let n = x
                .as_str()
                .map_or_else(|| x.as_f64(), |t| t.trim().parse::<f64>().ok())?;
            (n.is_finite() && n >= 0.0).then_some(n * 1_000_000.0)
        };
        if let (Some(input), Some(output)) = (per_token("prompt"), per_token("completion")) {
            out.insert(id.to_string(), LiveRow { input, output });
        }
    }
    out
}

/// Keep the prices from a list answer, with the time it was read.
pub fn remember_live(rows: std::collections::BTreeMap<String, LiveRow>, now_ms: u64) {
    if rows.is_empty() {
        return;
    }
    if let Ok(mut g) = LIVE.lock() {
        match g.as_mut() {
            Some(c) => {
                c.read_at_ms = now_ms;
                c.rows.extend(rows);
            }
            None => {
                *g = Some(LiveCache {
                    read_at_ms: now_ms,
                    rows,
                })
            }
        }
    }
}

fn live_price(model: &str) -> Option<PriceInfo> {
    let g = LIVE.lock().ok()?;
    let c = g.as_ref()?;
    let row = c.rows.get(model)?;
    let (y, m, _) = crate::state::civil(c.read_at_ms);
    Some(PriceInfo {
        input_per_mtok_usd: row.input,
        output_per_mtok_usd: row.output,
        origin: Origin::Live,
        source: OPENROUTER_MODELS.into(),
        as_of: Some(format!("{y:04}-{m:02}")),
        estimate: true,
        note: None,
        read_at_ms: Some(c.read_at_ms),
    })
}

/// Estimated cost in US dollars of some tokens at a price.
pub fn estimate_usd(price: &PriceInfo, input: u64, output: u64, cached_input: u64) -> f64 {
    (input as f64 * price.input_per_mtok_usd
        + cached_input as f64 * price.input_per_mtok_usd * CACHED_INPUT_FACTOR
        + output as f64 * price.output_per_mtok_usd)
        / 1_000_000.0
}

/// Whole months between a `YYYY-MM` and now (never negative); `None` if the text is not a month.
pub fn age_months(as_of: &str, now_ms: u64) -> Option<u32> {
    let (y, m) = as_of.split_once('-')?;
    let (y, m): (i64, i64) = (y.parse().ok()?, m.parse().ok()?);
    let (ny, nm, _) = crate::state::civil(now_ms);
    u32::try_from(((ny - y) * 12 + (nm - m)).max(0)).ok()
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use crate::settings::{ModelKind, ModelPriceOverride};

    fn prov(local: bool) -> ModelProvider {
        ModelProvider {
            id: "main".into(),
            kind: ModelKind::Openai,
            label: "Main".into(),
            base_url: None,
            local_endpoint: local,
            monthly_cap_usd: None,
            region: None,
            resource: None,
            hosted_on: None,
        }
    }

    #[test]
    fn the_longest_name_wins_and_a_built_in_price_says_where_and_when() {
        let cfg = ModelsConfig::default();
        let mini = lookup(&cfg, &prov(false), "gpt-4o-mini-2024-07-18").unwrap();
        assert_eq!(mini.input_per_mtok_usd, 0.15);
        assert_eq!(mini.origin, Origin::BuiltIn);
        assert!(mini.source.starts_with("https://") && mini.estimate);
        assert_eq!(mini.as_of.as_deref(), Some("2026-11"));
        assert!(mini.note.as_deref().unwrap().contains("272K"));
        assert_eq!(
            lookup(&cfg, &prov(false), "gpt-4o")
                .unwrap()
                .input_per_mtok_usd,
            2.5
        );
        assert!(lookup(&cfg, &prov(false), "some-new-model").is_none());
    }

    fn priced(kind: ModelKind, model: &str) -> Option<PriceInfo> {
        let mut p = prov(false);
        p.kind = kind;
        lookup(&ModelsConfig::default(), &p, model)
    }

    #[test]
    fn the_openai_entries_are_the_november_2026_ones() {
        for (m, i, o) in [
            ("gpt-6-astra", 10.0, 50.0),
            ("gpt-6.1-sol", 2.0, 10.0),
            ("gpt-5.5-pro", 30.0, 180.0),
            ("gpt-5.5", 5.0, 30.0),
            ("gpt-5.4-mini", 0.75, 4.5),
            ("gpt-5-nano", 0.05, 0.4),
            ("gpt-5", 1.25, 10.0),
            ("o3-pro", 20.0, 80.0),
            ("o3", 2.0, 8.0),
        ] {
            let p = priced(ModelKind::Openai, m).unwrap();
            assert_eq!((p.input_per_mtok_usd, p.output_per_mtok_usd), (i, o), "{m}");
            assert_eq!(p.source, "https://developers.openai.com/api/docs/pricing");
        }
        // the promotional price ends 2026-11-30 and no later price is published: nothing is said about gpt-5.6-sol
        assert!(TABLE.iter().all(|e| e.needle != "gpt-5.6-sol"));
        assert!(TABLE
            .iter()
            .all(|e| e.source != OPENAI || e.as_of == "2026-11"));
    }

    #[test]
    fn groq_prices_two_models_and_not_its_llamas() {
        let p = priced(ModelKind::Groq, "openai/gpt-oss-120b").unwrap();
        assert_eq!((p.input_per_mtok_usd, p.output_per_mtok_usd), (0.15, 0.6));
        assert_eq!(p.source, "https://console.groq.com/docs/models");
        assert_eq!(
            priced(ModelKind::Groq, "openai/gpt-oss-20b")
                .unwrap()
                .input_per_mtok_usd,
            0.075
        );
        assert!(priced(ModelKind::Groq, "llama-3.3-70b-versatile").is_none());
    }

    const OPENROUTER_FIXTURE: &str = r#"{"data":[
        {"id":"vendor-x/model-one","pricing":{"prompt":"0.000003","completion":"0.000015","request":"0"}},
        {"id":"vendor-x/model-free","pricing":{"prompt":"0","completion":"0"}},
        {"id":"vendor-x/model-varies","pricing":{"prompt":"-1","completion":"-1"}},
        {"id":"vendor-x/model-bad","pricing":{"prompt":"lots","completion":"0.1"}},
        {"id":"vendor-x/model-none"}]}"#;

    #[test]
    fn openrouter_prices_are_parsed_per_million_and_bad_rows_are_skipped() {
        let rows = parse_openrouter(OPENROUTER_FIXTURE);
        let one = rows["vendor-x/model-one"];
        assert!(
            (one.input - 3.0).abs() < 1e-9 && (one.output - 15.0).abs() < 1e-9,
            "{one:?}"
        );
        assert_eq!(
            rows["vendor-x/model-free"],
            LiveRow {
                input: 0.0,
                output: 0.0
            }
        );
        assert_eq!(rows.len(), 2);
        assert!(parse_openrouter("not json").is_empty() && parse_openrouter("{}").is_empty());
    }

    #[test]
    fn an_openrouter_model_is_priced_only_from_what_its_list_said_with_when() {
        // never from the built-in table, even for a model name the table knows
        assert!(priced(ModelKind::Openrouter, "openai/gpt-4o-never-listed").is_none());
        assert!(priced(ModelKind::Openrouter, "vendor-x/model-one").is_none());
        // 2026-11-09 12:00 UTC
        let read = 1_794_182_400_000 + 12 * 3_600_000;
        remember_live(parse_openrouter(OPENROUTER_FIXTURE), read);
        let p = priced(ModelKind::Openrouter, "vendor-x/model-one").unwrap();
        assert_eq!(p.origin, Origin::Live);
        assert!((p.input_per_mtok_usd - 3.0).abs() < 1e-9);
        assert_eq!(p.source, OPENROUTER_MODELS);
        assert_eq!(p.read_at_ms, Some(read));
        assert!(p.as_of.is_some());
        assert!(priced(ModelKind::Openrouter, "vendor-x/model-varies").is_none());
        // another provider kind is not affected by the cache
        assert!(priced(ModelKind::Openai, "vendor-x/model-one").is_none());
    }

    #[test]
    fn an_entered_price_wins_and_a_local_endpoint_is_free_per_token() {
        let mut cfg = ModelsConfig::default();
        cfg.prices.insert(
            "main/gpt-4o".into(),
            ModelPriceOverride {
                input_per_mtok_usd: 1.0,
                output_per_mtok_usd: 2.0,
            },
        );
        let p = lookup(&cfg, &prov(false), "gpt-4o").unwrap();
        assert_eq!((p.input_per_mtok_usd, p.origin), (1.0, Origin::Entered));
        let l = lookup(&ModelsConfig::default(), &prov(true), "llama3.1:8b").unwrap();
        assert_eq!(l.origin, Origin::Local);
        assert_eq!(estimate_usd(&l, 1_000_000, 1_000_000, 0), 0.0);
    }

    #[test]
    fn the_estimate_counts_cached_input_at_a_discount_and_the_age_is_in_months() {
        let p = lookup(&ModelsConfig::default(), &prov(false), "gpt-4o").unwrap();
        let c = estimate_usd(&p, 1_000_000, 100_000, 1_000_000);
        assert!((c - (2.5 + 1.0 + 0.25)).abs() < 1e-9, "{c}");
        // 2026-11-09
        assert_eq!(
            age_months("2025-06", 1_794_000_000_000 / 1000 * 1000),
            Some(17)
        );
        assert_eq!(age_months("bad", 0), None);
    }
}
