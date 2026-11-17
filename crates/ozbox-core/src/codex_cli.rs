//! The Codex CLI adapter: `codex exec --json -`, one process per turn ([`crate::headless`]).
//!
//! Followed from the vendor's public pages (read 2026-11-17):
//!
//! - non-interactive mode, the JSONL events, `-` for the prompt on standard input, `resume <SESSION_ID>`, the sandbox modes
//!   and `CODEX_API_KEY` for `codex exec`: <https://learn.chatgpt.com/docs/non-interactive-mode>
//! - `openai_base_url`, `mcp_servers.<id>.url` and `mcp_servers.<id>.bearer_token_env_var`:
//!   <https://learn.chatgpt.com/docs/config-file/config-reference>
//! - one-off `-c key=value` overrides (TOML values): <https://learn.chatgpt.com/docs/config-file/config-basic>
//!
//! **Credentials.** The run is handed a per-run token as `OPENAI_API_KEY` and the broker's address as `OPENAI_BASE_URL`
//! (ADR 0017, the Models routing of ADR 0015). Codex reads its key for `exec` from `CODEX_API_KEY`, so the token is also put
//! there, and the broker's address is given as `openai_base_url` on the command line (an address, never a key). A run of an
//! engine opted in to a ChatGPT sign-in (ADR 0055) is handed nothing here: the box writes that run's `CODEX_HOME`.
//!
//! **The Oz Box tools (ADR 0043).** When the run carries `OZBOX_MCP_URL` and `OZBOX_MCP_TOKEN`, Codex is told the server's
//! address and the *name* of the variable holding the token (`bearer_token_env_var`); the token itself stays in the
//! environment.
//!
//! **The ask list.** Codex takes no list of commands to refuse. A run is sandboxed to its workspace (`workspace-write`, which
//! has no network), so pushes, downloads and remote shells fail; a run started from a chat app is `read-only`, so it edits
//! nothing on the strength of a chat message. `codex exec` never stops to ask, so nothing reaches ADR 0041 from it.
//!
//! **Output.** `thread.started` names the session; `item.completed` items are the agent's messages and the tools it used
//! (only their kind leaves this adapter: a command line may hold anything); `turn.completed` carries the tokens; `turn.failed`
//! and `error` are failures. Codex reports tokens and no cost; the supervisor prices them.

use std::collections::BTreeMap;

use serde_json::Value;

use crate::agent_engine::{EngineError, EngineEvent, EngineStart};
use crate::headless::{safe_model, safe_url, Dialect, HeadlessEngine, LineState};

/// The engine id.
pub const ENGINE: &str = "codex";

#[derive(Debug, Default, Clone, Copy)]
pub struct Codex;

/// A Codex engine over a transport to the box daemon.
pub type CodexEngine<T> = HeadlessEngine<T, Codex>;

pub fn engine<T: crate::claude_code::RunTransport>(transport: T) -> CodexEngine<T> {
    HeadlessEngine::new(transport, Codex)
}

fn toml_str(v: &str) -> String {
    // callers pass only `safe_url`/fixed names, so there is nothing to escape; quote it as a TOML basic string
    format!("\"{v}\"")
}

impl Dialect for Codex {
    fn id(&self) -> &'static str {
        ENGINE
    }

    fn argv(&self, req: &EngineStart, resume: Option<&str>) -> Result<Vec<String>, EngineError> {
        let mut v: Vec<String> = ["codex", "exec", "--json"]
            .iter()
            .map(|s| s.to_string())
            .collect();
        v.push("--sandbox".into());
        v.push(
            if req.ask_for_edits {
                "read-only"
            } else {
                "workspace-write"
            }
            .into(),
        );
        if req.repo.is_none() {
            v.push("--skip-git-repo-check".into());
        }
        if let Some(m) = req
            .model
            .as_deref()
            .map(str::trim)
            .filter(|m| !m.is_empty())
        {
            if !safe_model(m) {
                return Err(EngineError::Failed(
                    "that model name cannot be passed to Codex".into(),
                ));
            }
            v.push("--model".into());
            v.push(m.to_string());
        }
        if let Some(base) = req.secret_env.get("OPENAI_BASE_URL") {
            if !safe_url(base) {
                return Err(EngineError::Failed(
                    "the model address for this run cannot be passed to Codex".into(),
                ));
            }
            v.push("-c".into());
            v.push(format!("openai_base_url={}", toml_str(base)));
        }
        if let (Some(url), true) = (
            req.secret_env.get("OZBOX_MCP_URL"),
            req.secret_env.contains_key("OZBOX_MCP_TOKEN"),
        ) {
            if safe_url(url) {
                v.push("-c".into());
                v.push(format!("mcp_servers.ozbox.url={}", toml_str(url)));
                v.push("-c".into());
                v.push("mcp_servers.ozbox.bearer_token_env_var=\"OZBOX_MCP_TOKEN\"".into());
            }
        }
        if let Some(s) = resume {
            v.push("resume".into());
            v.push(s.to_string());
        }
        // the task text is standard input
        v.push("-".into());
        Ok(v)
    }

    fn env(&self, mut env: BTreeMap<String, String>) -> BTreeMap<String, String> {
        if let Some(t) = env.get("OPENAI_API_KEY").cloned() {
            env.entry("CODEX_API_KEY".to_string()).or_insert(t);
        }
        env
    }

    fn parse_line(&self, line: &str, st: &mut LineState) -> Vec<EngineEvent> {
        parse_line(line, st)
    }
}

/// What one JSONL line of `codex exec --json` means.
pub fn parse_line(line: &str, st: &mut LineState) -> Vec<EngineEvent> {
    let line = line.trim();
    if line.is_empty() {
        return Vec::new();
    }
    let Ok(v) = serde_json::from_str::<Value>(line) else {
        // progress goes to standard error, which the box may interleave: a line, nothing more
        return vec![EngineEvent::Log(line.chars().take(300).collect())];
    };
    let mut out = Vec::new();
    match v.get("type").and_then(Value::as_str) {
        Some("thread.started") => {
            if let Some(id) = v["thread_id"].as_str().filter(|s| !s.is_empty()) {
                st.session = Some(id.chars().take(100).collect());
            }
        }
        Some("item.completed") => {
            let item = &v["item"];
            match item["type"].as_str() {
                Some("agent_message") => {
                    let text = item["text"].as_str().unwrap_or("");
                    for l in text.lines().filter(|l| !l.trim().is_empty()).take(3) {
                        out.push(EngineEvent::Log(l.chars().take(300).collect()));
                    }
                    st.last_message = text.chars().take(crate::run::MAX_REPLY_CHARS).collect();
                }
                Some("command_execution") => out.push(EngineEvent::ToolUse {
                    name: "shell".into(),
                }),
                Some("file_change") => out.push(EngineEvent::ToolUse {
                    name: "edit".into(),
                }),
                Some("mcp_tool_call") => {
                    let tool = item["tool"].as_str().unwrap_or("tool");
                    let server = item["server"].as_str();
                    let name: String = match server {
                        Some(s) => format!("{s}.{tool}"),
                        None => tool.to_string(),
                    };
                    out.push(EngineEvent::ToolUse {
                        name: name.chars().take(100).collect(),
                    });
                }
                Some("web_search") => out.push(EngineEvent::ToolUse {
                    name: "web_search".into(),
                }),
                // reasoning and plan updates stay inside the agent
                _ => {}
            }
        }
        Some("turn.completed") => {
            let u = &v["usage"];
            let n = |k: &str| u[k].as_u64().unwrap_or(0);
            let (input, cached, output) = (
                n("input_tokens"),
                n("cached_input_tokens"),
                // the reasoning tokens are part of the output tokens already
                n("output_tokens"),
            );
            if input + output > 0 {
                out.push(EngineEvent::TokenUsage {
                    // Codex counts cached tokens inside the input; the supervisor prices them apart
                    input_tokens: input.saturating_sub(cached),
                    output_tokens: output,
                    cached_input_tokens: cached,
                    model: st.model.clone(),
                });
            }
            st.end = Some(Ok(std::mem::take(&mut st.last_message)));
        }
        Some("turn.failed") => {
            let msg = v["error"]["message"]
                .as_str()
                .unwrap_or("the agent reported an error");
            st.end = Some(Err(msg.chars().take(500).collect()));
        }
        Some("error") => {
            // a stream error: retries are reported this way too, so it is a line, and the turn's end says the rest
            let msg = v["message"].as_str().unwrap_or("an error");
            out.push(EngineEvent::Log(msg.chars().take(300).collect()));
        }
        _ => {}
    }
    out
}
