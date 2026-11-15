//! What one model call used, recorded by whatever made the call.
//!
//! An agent run (or anything else that calls a model through a provider the person configured) reports one
//! [`ModelUsage`] per call or per run segment. Settings -> Models and `ozbox models usage` add them up by day,
//! provider, model, box and engine, and price them as an estimate. A record carries ids, names and token counts only:
//! never a prompt, a reply, a key or a file name.

use serde::{Deserialize, Serialize};

/// Tokens a model call used. Counts are of tokens, as the provider reports them.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ModelUsage {
    /// Unix time in milliseconds when the call finished.
    pub ts_ms: u64,
    /// The box the call ran on, if it ran on one.
    #[serde(default)]
    pub box_name: Option<String>,
    /// The agent engine that made the call (`claude-code`, `codex`, ...), if one did.
    #[serde(default)]
    pub engine: Option<String>,
    /// The id of the configured model provider (not its kind).
    pub provider_id: String,
    pub model: String,
    pub input_tokens: u64,
    pub output_tokens: u64,
    /// Input tokens the provider served from its prompt cache (billed lower), included in neither count above.
    #[serde(default)]
    pub cached_input_tokens: u64,
}

impl ModelUsage {
    /// The record is sane: names are short plain text and the time is set.
    pub fn is_valid(&self) -> bool {
        let plain = |s: &str, max: usize| {
            !s.is_empty() && s.len() <= max && !s.chars().any(char::is_control)
        };
        self.ts_ms > 0
            && plain(&self.provider_id, 24)
            && plain(&self.model, 100)
            && self.box_name.iter().all(|b| plain(b, 40))
            && self.engine.iter().all(|e| plain(e, 40))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_record_needs_a_time_and_plain_names() {
        let mut u = ModelUsage {
            ts_ms: 1,
            box_name: Some("dev".into()),
            engine: None,
            provider_id: "main".into(),
            model: "m".into(),
            input_tokens: 1,
            output_tokens: 2,
            cached_input_tokens: 0,
        };
        assert!(u.is_valid());
        u.model = "a\nb".into();
        assert!(!u.is_valid());
        u.model = "m".into();
        u.ts_ms = 0;
        assert!(!u.is_valid());
    }
}
