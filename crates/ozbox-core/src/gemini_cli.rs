//! The Gemini CLI adapter: `gemini --output-format stream-json`, one process per turn ([`crate::headless`]).
//!
//! Followed from the vendor's public pages (read 2026-11-17):
//!
//! - headless mode, the `stream-json` event types (`init`, `message`, `tool_use`, `tool_result`, `error`, `result`) and the
//!   exit codes (0, 1, 42 input error, 53 turn limit): <https://geminicli.com/docs/cli/headless/>
//! - `--prompt` ("appended to stdin input if provided. Forces non-interactive mode"), `--output-format`, `--model`,
//!   `--approval-mode` (`default`, `auto_edit`, `yolo`, `plan`) and `--resume <session-id>`:
//!   <https://github.com/google-gemini/gemini-cli/blob/main/docs/cli/cli-reference.md>
//!
//! The pages name the event types but not every field. The fields read here (`session_id`, `role`, `content`, `delta`,
//! `tool_name`, `status`, `stats.input_tokens`, `stats.output_tokens`, `stats.cached`, `error.message`) follow the program's
//! own stream formatter; anything missing is read as absent, never guessed. **Not yet checked against a real run.**
//!
//! **The task text** is standard input; `--prompt` carries a fixed sentence only, so the program runs headless.
//! **Credentials**: the per-run token as `GEMINI_API_KEY` and the broker's address, as the Models routing hands them (ADR 0015,
//! 0017). **The ask list**: headless mode refuses every tool that needs a confirmation, which is every shell command in
//! `auto_edit` mode (a chat-started run is `default`, so it edits nothing either). Gemini never stops to ask.
//! **The Oz Box tools**: Gemini CLI reads MCP servers from a settings file only, and a file for one run is not built, so a run
//! does not reach them (`engine_turn::capabilities` says so).

use serde_json::Value;

use crate::agent_engine::{EngineError, EngineEvent, EngineStart};
use crate::headless::{safe_model, Dialect, HeadlessEngine, LineState};

/// The engine id.
pub const ENGINE: &str = "gemini-cli";

/// The fixed text given as `--prompt`: appended to the task on standard input, it only forces headless mode.
pub const PROMPT_FLAG_TEXT: &str = "Carry out the task above.";

#[derive(Debug, Default, Clone, Copy)]
pub struct Gemini;

pub type GeminiEngine<T> = HeadlessEngine<T, Gemini>;

pub fn engine<T: crate::claude_code::RunTransport>(transport: T) -> GeminiEngine<T> {
    HeadlessEngine::new(transport, Gemini)
}

impl Dialect for Gemini {
    fn id(&self) -> &'static str {
        ENGINE
    }

    fn argv(&self, req: &EngineStart, resume: Option<&str>) -> Result<Vec<String>, EngineError> {
        let mut v: Vec<String> = [
            "gemini",
            "--output-format",
            "stream-json",
            "--approval-mode",
        ]
        .iter()
        .map(|s| s.to_string())
        .collect();
        v.push(
            if req.ask_for_edits {
                "default"
            } else {
                "auto_edit"
            }
            .into(),
        );
        if let Some(m) = req
            .model
            .as_deref()
            .map(str::trim)
            .filter(|m| !m.is_empty())
        {
            if !safe_model(m) {
                return Err(EngineError::Failed(
                    "that model name cannot be passed to Gemini CLI".into(),
                ));
            }
            v.push("--model".into());
            v.push(m.to_string());
        }
        if let Some(s) = resume {
            v.push("--resume".into());
            v.push(s.to_string());
        }
        v.push("--prompt".into());
        v.push(PROMPT_FLAG_TEXT.into());
        Ok(v)
    }

    fn parse_line(&self, line: &str, st: &mut LineState) -> Vec<EngineEvent> {
        parse_line(line, st)
    }

    fn exit_failure(&self, code: i32) -> String {
        match code {
            42 => "Gemini CLI refused the input (exit code 42)".into(),
            53 => "Gemini CLI reached its turn limit (exit code 53)".into(),
            c => format!("the agent exited with code {c}"),
        }
    }
}

fn flush_message(st: &mut LineState, out: &mut Vec<EngineEvent>) {
    let text = std::mem::take(&mut st.partial_message);
    if text.trim().is_empty() {
        return;
    }
    for l in text.lines().filter(|l| !l.trim().is_empty()).take(3) {
        out.push(EngineEvent::Log(l.chars().take(300).collect()));
    }
    st.last_message = text.chars().take(crate::run::MAX_REPLY_CHARS).collect();
}

/// What one line of `stream-json` output means.
pub fn parse_line(line: &str, st: &mut LineState) -> Vec<EngineEvent> {
    let line = line.trim();
    if line.is_empty() {
        return Vec::new();
    }
    let Ok(v) = serde_json::from_str::<Value>(line) else {
        return vec![EngineEvent::Log(line.chars().take(300).collect())];
    };
    let mut out = Vec::new();
    let kind = v.get("type").and_then(Value::as_str);
    if kind != Some("message") {
        flush_message(st, &mut out);
    }
    match kind {
        Some("init") => {
            if let Some(id) = v["session_id"].as_str().filter(|s| !s.is_empty()) {
                st.session = Some(id.chars().take(100).collect());
            }
            if let Some(m) = v["model"].as_str().filter(|m| !m.is_empty()) {
                st.model = Some(m.chars().take(100).collect());
            }
        }
        Some("message") if v["role"].as_str() == Some("assistant") => {
            let text = v["content"].as_str().unwrap_or("");
            if v["delta"].as_bool().unwrap_or(false) {
                if st.partial_message.len() < crate::run::MAX_REPLY_CHARS * 4 {
                    st.partial_message.push_str(text);
                }
            } else {
                flush_message(st, &mut out);
                st.partial_message.push_str(text);
                flush_message(st, &mut out);
            }
        }
        Some("tool_use") => {
            let name = v["tool_name"].as_str().unwrap_or("tool");
            out.push(EngineEvent::ToolUse {
                name: name.chars().take(100).collect(),
            });
        }
        Some("tool_result") if v["status"].as_str() == Some("error") => {
            // the output may hold anything: only that it failed
            out.push(EngineEvent::Log("a tool call failed".into()));
        }
        Some("error") => {
            let msg = v["message"].as_str().unwrap_or("an error");
            out.push(EngineEvent::Log(msg.chars().take(300).collect()));
        }
        Some("result") => {
            let s = &v["stats"];
            let n = |k: &str| s[k].as_u64().unwrap_or(0);
            let (input, output, cached) = (n("input_tokens"), n("output_tokens"), n("cached"));
            if input + output > 0 {
                out.push(EngineEvent::TokenUsage {
                    input_tokens: input.saturating_sub(cached),
                    output_tokens: output,
                    cached_input_tokens: cached,
                    model: st.model.clone(),
                });
            }
            st.end = Some(if v["status"].as_str() == Some("error") {
                Err(v["error"]["message"]
                    .as_str()
                    .unwrap_or("the agent reported an error")
                    .chars()
                    .take(500)
                    .collect())
            } else {
                Ok(std::mem::take(&mut st.last_message))
            });
        }
        _ => {}
    }
    out
}
