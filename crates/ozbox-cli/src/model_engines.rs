//! Which provider and model each agent engine uses, and what a run on a box gets.
//!
//! The fleet sets a choice per engine (with a fallback); a box may override it. When a run is about to start, the
//! caller asks [`resolve`] for the choice and the environment that carries the credentials: the key is read from the
//! secret store at that moment and handed to the run's own process environment (the box daemon keeps a run's
//! environment in memory and never logs it). **Nothing here writes a key to a file, and a key is never stored on
//! `/work`.** The returned value has no `Debug` output of its values.

use std::collections::BTreeMap;

use serde::Serialize;

use crate::model_providers::kind_id;
use crate::models::key_name;
use crate::secrets::SecretStore;
use crate::settings::{EngineModel, ModelChoice, ModelKind, ModelProvider, ModelsConfig};

/// An agent engine and the kinds of provider it can speak to.
pub struct EngineInfo {
    pub id: &'static str,
    pub label: &'static str,
    pub kinds: &'static [ModelKind],
}

use ModelKind as K;

/// The engines of the tools catalog's AI agents group.
pub const ENGINES: &[EngineInfo] = &[
    EngineInfo {
        id: "claude-code",
        label: "Claude Code",
        kinds: &[K::Anthropic, K::Bedrock, K::Vertex],
    },
    EngineInfo {
        id: "codex",
        label: "Codex CLI",
        kinds: &[
            K::Openai,
            K::AzureOpenai,
            K::Openrouter,
            K::Groq,
            K::Mistral,
            K::Together,
            K::OpenaiCompatible,
        ],
    },
    EngineInfo {
        id: "gemini-cli",
        label: "Gemini CLI",
        kinds: &[K::Google, K::Vertex],
    },
    EngineInfo {
        id: "aider",
        label: "Aider",
        kinds: &[
            K::Anthropic,
            K::Openai,
            K::Google,
            K::Bedrock,
            K::AzureOpenai,
            K::Vertex,
            K::Openrouter,
            K::Mistral,
            K::Groq,
            K::Together,
            K::OpenaiCompatible,
        ],
    },
    EngineInfo {
        id: "opencode",
        label: "OpenCode",
        kinds: &[
            K::Anthropic,
            K::Openai,
            K::Google,
            K::Bedrock,
            K::AzureOpenai,
            K::Vertex,
            K::Openrouter,
            K::Mistral,
            K::Groq,
            K::Together,
            K::OpenaiCompatible,
        ],
    },
];

pub fn known(engine: &str) -> bool {
    ENGINES.iter().any(|e| e.id == engine)
}

pub fn info(engine: &str) -> Option<&'static EngineInfo> {
    ENGINES.iter().find(|e| e.id == engine)
}

/// The engine's own choice on a box: the box's override, else the fleet's.
pub fn choice_for<'a>(
    cfg: &'a ModelsConfig,
    box_name: Option<&str>,
    engine: &str,
) -> Option<&'a EngineModel> {
    box_name
        .and_then(|b| cfg.box_overrides.get(b))
        .and_then(|m| m.get(engine))
        .or_else(|| cfg.engines.get(engine))
}

/// A provider, a model and the environment that lets the engine reach it. The values are secret.
pub struct Resolved {
    pub engine: String,
    pub provider_id: String,
    pub model: String,
    /// The engine falls back to this when the primary fails (the caller decides when).
    pub fallback: Option<Box<Resolved>>,
    env: BTreeMap<String, String>,
}

impl Resolved {
    /// Environment variable names only.
    pub fn env_names(&self) -> Vec<&str> {
        self.env.keys().map(String::as_str).collect()
    }

    /// The environment for the run's process. Hand it straight to the run; do not log it or write it to a file.
    #[allow(dead_code)]
    pub fn into_env(self) -> BTreeMap<String, String> {
        self.env
    }

    /// The choice, the environment (secret) and the fallback, taken apart. The environment goes to the engine at start.
    pub fn into_parts(self) -> ResolvedParts {
        ResolvedParts {
            provider_id: self.provider_id,
            model: self.model,
            env: self.env,
            fallback: self.fallback,
        }
    }
}

pub struct ResolvedParts {
    pub provider_id: String,
    pub model: String,
    pub env: BTreeMap<String, String>,
    pub fallback: Option<Box<Resolved>>,
}

impl std::fmt::Debug for Resolved {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Resolved")
            .field("engine", &self.engine)
            .field("provider_id", &self.provider_id)
            .field("model", &self.model)
            .field("env_names", &self.env_names())
            .finish_non_exhaustive()
    }
}

/// What a run is given to reach a provider: never the provider's key. A per-run token and the address of the credential
/// broker (see `broker`), or, for a local server that needs no key at all, nothing secret.
pub struct Access {
    pub token: Option<String>,
    pub base_url: String,
}

/// Hands out access for one provider. The host's version asks the credential broker for a token bound to the run.
pub type Issue<'a> = &'a mut dyn FnMut(&ModelProvider) -> Result<Access, String>;

/// The variables an engine reads for a provider kind, with the run token where a key would be.
fn env_for(
    engine: &str,
    p: &ModelProvider,
    model: &str,
    access: &Access,
) -> BTreeMap<String, String> {
    let mut e = BTreeMap::new();
    let mut put = |k: &str, v: &str| {
        e.insert(k.to_string(), v.to_string());
    };
    let t = access.token.as_deref().unwrap_or("none");
    let base = access.base_url.trim_end_matches('/');
    match p.kind {
        K::Anthropic => {
            put("ANTHROPIC_API_KEY", t);
            put("ANTHROPIC_BASE_URL", base);
        }
        K::Openai => {
            put("OPENAI_API_KEY", t);
            put("OPENAI_BASE_URL", &format!("{base}/v1"));
        }
        K::Google => {
            put("GEMINI_API_KEY", t);
            put("GOOGLE_GEMINI_BASE_URL", base);
        }
        K::Openrouter | K::Mistral | K::Groq | K::Together => {
            let own = match p.kind {
                K::Openrouter => "OPENROUTER_API_KEY",
                K::Mistral => "MISTRAL_API_KEY",
                K::Groq => "GROQ_API_KEY",
                _ => "TOGETHER_API_KEY",
            };
            put(own, t);
            put("OPENAI_API_KEY", t);
            put("OPENAI_BASE_URL", &format!("{base}/v1"));
        }
        K::OpenaiCompatible => {
            put("OPENAI_API_KEY", t);
            put("OPENAI_BASE_URL", base);
        }
        // The person's own cloud account, through the broker (ADR 0028). The broker signs or fetches the token; the engine
        // is told to skip its own cloud sign-in and to send its run token as the bearer. Not verified against a real engine.
        K::Bedrock => {
            put("CLAUDE_CODE_USE_BEDROCK", "1");
            put("CLAUDE_CODE_SKIP_BEDROCK_AUTH", "1");
            put("ANTHROPIC_BEDROCK_BASE_URL", base);
            put("AWS_BEARER_TOKEN_BEDROCK", t);
            put("AWS_REGION", p.region.as_deref().unwrap_or("us-east-1"));
        }
        K::Vertex => {
            put("CLAUDE_CODE_USE_VERTEX", "1");
            put("CLAUDE_CODE_SKIP_VERTEX_AUTH", "1");
            put("ANTHROPIC_VERTEX_BASE_URL", base);
            // the SDK wants a project in every path; the broker puts the account's own in
            put("ANTHROPIC_VERTEX_PROJECT_ID", "ozbox");
            put("CLOUD_ML_REGION", p.region.as_deref().unwrap_or("global"));
            put("ANTHROPIC_AUTH_TOKEN", t);
        }
        K::AzureOpenai => {
            put("OPENAI_API_KEY", t);
            put("OPENAI_BASE_URL", &format!("{base}/openai/v1"));
        }
    }
    if engine == "claude-code" {
        put("ANTHROPIC_MODEL", model);
    }
    e
}

/// Whether an engine has an environment for a cloud-account provider. The others are refused, not given nothing.
fn cloud_wired(engine: &str, kind: ModelKind) -> bool {
    match kind {
        K::Bedrock | K::Vertex => engine == "claude-code",
        K::AzureOpenai => engine == "codex",
        _ => true,
    }
}

/// The demo provider's stand-in engine runs like Claude Code but accepts a provider of any kind, so the whole path from
/// the choice to the run can be tried without a real agent.
const DEMO_ENGINE: &str = "fake";

fn one(
    cfg: &ModelsConfig,
    secrets: &dyn SecretStore,
    box_name: Option<&str>,
    engine: &str,
    c: &ModelChoice,
    issue: Issue,
) -> Result<Resolved, String> {
    let demo = engine == DEMO_ENGINE;
    let engine = if demo { "claude-code" } else { engine };
    let info =
        info(engine).ok_or_else(|| format!("{engine} is not an agent engine Oz Box knows"))?;
    let p = cfg
        .providers
        .iter()
        .find(|p| p.id == c.provider_id)
        .ok_or("that provider is no longer set up")?;
    if !demo && !info.kinds.contains(&p.kind) {
        return Err(format!(
            "{} cannot use a {} provider",
            info.label,
            kind_id(p.kind)
        ));
    }
    if !cloud_wired(engine, p.kind) {
        return Err(format!(
            "{} cannot reach a {} provider through the credential broker yet",
            info.label,
            kind_id(p.kind)
        ));
    }
    if let (Some(host), Some(b)) = (p.hosted_on.as_deref(), box_name) {
        if host != b {
            return Err(format!(
                "{} runs on {host} and is not reachable from {b}",
                p.label
            ));
        }
    }
    // Only whether a key is saved matters here; the value is dropped at once and never reaches the run.
    let has_key = secrets
        .exists(&key_name(&p.id))
        .map_err(|e| e.to_string())?;
    if !has_key && !crate::model_providers::key_optional(p) {
        return Err(format!("no key is saved for {}", p.label));
    }
    let access = if p.local_endpoint && !has_key {
        // a server on the box's own loopback that asks for no key: nothing secret to protect
        Access {
            token: None,
            base_url: p.base_url.clone().unwrap_or_default(),
        }
    } else {
        issue(p)?
    };
    Ok(Resolved {
        engine: engine.to_string(),
        provider_id: p.id.clone(),
        model: c.model.clone(),
        fallback: None,
        env: env_for(engine, p, &c.model, &access),
    })
}

/// The choice and credentials for `engine` on `box_name` (or fleet-wide). Errors say what to fix, never the key.
pub fn resolve(
    cfg: &ModelsConfig,
    secrets: &dyn SecretStore,
    box_name: Option<&str>,
    engine: &str,
) -> Result<Resolved, String> {
    // a preview of the environment's names: the token is a placeholder, nothing is issued
    resolve_for(cfg, secrets, box_name, engine, None, &mut |p| {
        if !crate::broker::brokerable(p) {
            return Err(format!("{} cannot be used by runs yet", p.label));
        }
        Ok(Access {
            token: Some("<per-run token>".into()),
            base_url: "http://127.0.0.1:0/provider".into(),
        })
    })
}

/// Whether anything is chosen for a run: its own model, the box's, or the fleet's for the engine. When nothing is, the
/// engine uses its own login and there is nothing to resolve.
pub fn has_choice(
    cfg: &ModelsConfig,
    box_name: Option<&str>,
    engine: &str,
    run_choice: Option<&ModelChoice>,
) -> bool {
    run_choice.is_some() || choice_for(cfg, box_name, lookup_id(engine)).is_some()
}

/// The demo engine reads the settings of Claude Code.
fn lookup_id(engine: &str) -> &str {
    if engine == DEMO_ENGINE {
        "claude-code"
    } else {
        engine
    }
}

/// [`resolve`] with a choice made for one run, which wins over the box's and the fleet's. The engine's fallback still
/// applies to it.
pub fn resolve_for(
    cfg: &ModelsConfig,
    secrets: &dyn SecretStore,
    box_name: Option<&str>,
    engine: &str,
    run_choice: Option<&ModelChoice>,
    issue: Issue,
) -> Result<Resolved, String> {
    let configured = choice_for(cfg, box_name, lookup_id(engine));
    let (primary, fallback) = match (run_choice, configured) {
        (Some(c), e) => (c.clone(), e.and_then(|e| e.fallback.clone())),
        (None, Some(e)) => (
            ModelChoice {
                provider_id: e.provider_id.clone(),
                model: e.model.clone(),
            },
            e.fallback.clone(),
        ),
        (None, None) => {
            return Err(format!(
                "no model is chosen for {engine}; choose one in Settings -> Models"
            ))
        }
    };
    let mut r = one(cfg, secrets, box_name, engine, &primary, &mut *issue)?;
    if let Some(f) = &fallback {
        // A fallback that cannot be used is left out rather than failing the run it only backs up.
        r.fallback = one(cfg, secrets, box_name, engine, f, &mut *issue)
            .ok()
            .map(Box::new);
    }
    Ok(r)
}

#[derive(Debug, Serialize)]
pub struct EngineRow {
    pub id: &'static str,
    pub label: &'static str,
    pub kinds: Vec<&'static str>,
    /// Whether Oz Box can start this engine as a run on a box (an adapter exists, ADR 0056). `false` is Planned.
    pub runs: bool,
}

pub fn rows() -> Vec<EngineRow> {
    ENGINES
        .iter()
        .map(|e| EngineRow {
            id: e.id,
            label: e.label,
            kinds: e.kinds.iter().map(|k| kind_id(*k)).collect(),
            runs: ozbox_core::engine_turn::capabilities_of(e.id)
                .is_some_and(|c| c.headless.is_yes()),
        })
        .collect()
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use crate::secrets::MemorySecrets;

    fn prov(id: &str, kind: ModelKind) -> ModelProvider {
        ModelProvider {
            id: id.into(),
            kind,
            label: id.into(),
            base_url: (kind == K::OpenaiCompatible).then(|| "http://127.0.0.1:11434/v1".into()),
            local_endpoint: kind == K::OpenaiCompatible,
            monthly_cap_usd: None,
            region: (kind == K::Bedrock).then(|| "us-east-1".into()),
            resource: None,
            hosted_on: None,
        }
    }

    fn cfg() -> ModelsConfig {
        let mut c = ModelsConfig {
            providers: vec![
                prov("anth", K::Anthropic),
                prov("oa", K::Openai),
                prov("br", K::Bedrock),
                prov("loc", K::OpenaiCompatible),
            ],
            ..Default::default()
        };
        c.engines.insert(
            "claude-code".into(),
            EngineModel {
                provider_id: "anth".into(),
                model: "claude-sonnet-4".into(),
                fallback: Some(ModelChoice {
                    provider_id: "br".into(),
                    model: "x".into(),
                }),
            },
        );
        c
    }

    #[test]
    fn a_run_gets_a_token_and_the_brokers_address_never_the_key() {
        let s = MemorySecrets::default();
        s.set("model-key-anth", "sk-SENTINEL-1").unwrap();
        s.set("model-key-br", "bk-SENTINEL-2").unwrap();
        let r = resolve(&cfg(), &s, None, "claude-code").unwrap();
        assert!(!format!("{r:?}").contains("SENTINEL"));
        // Bedrock is brokered now (ADR 0028): the fallback gets the gateway-style variables and the run token, never the key
        let fb = r.fallback.as_ref().unwrap();
        let fenv = fb.env_names();
        assert!(
            fenv.contains(&"CLAUDE_CODE_USE_BEDROCK") && fenv.contains(&"AWS_BEARER_TOKEN_BEDROCK")
        );
        let env = r.into_env();
        assert_eq!(env["ANTHROPIC_API_KEY"], "<per-run token>");
        assert_eq!(env["ANTHROPIC_BASE_URL"], "http://127.0.0.1:0/provider");
        assert_eq!(env["ANTHROPIC_MODEL"], "claude-sonnet-4");
        assert!(
            env.values().all(|v| !v.contains("SENTINEL")),
            "the key never reaches a run"
        );
    }

    #[test]
    fn a_box_override_wins_and_an_engine_refuses_a_provider_it_cannot_use() {
        let s = MemorySecrets::default();
        s.set("model-key-oa", "k").unwrap();
        let mut c = cfg();
        c.box_overrides.entry("dev".into()).or_default().insert(
            "claude-code".into(),
            EngineModel {
                provider_id: "oa".into(),
                model: "gpt-4o".into(),
                fallback: None,
            },
        );
        assert_eq!(
            choice_for(&c, Some("dev"), "claude-code")
                .unwrap()
                .provider_id,
            "oa"
        );
        assert_eq!(
            choice_for(&c, Some("other"), "claude-code")
                .unwrap()
                .provider_id,
            "anth"
        );
        let e = resolve(&c, &s, Some("dev"), "claude-code").unwrap_err();
        assert!(e.contains("cannot use"), "{e}");
    }

    #[test]
    fn a_missing_key_or_choice_says_what_to_fix_and_a_local_server_needs_no_key() {
        let s = MemorySecrets::default();
        assert!(resolve(&cfg(), &s, None, "claude-code")
            .unwrap_err()
            .contains("no key"));
        assert!(resolve(&cfg(), &s, None, "codex")
            .unwrap_err()
            .contains("no model is chosen"));
        let mut c = cfg();
        c.engines.insert(
            "codex".into(),
            EngineModel {
                provider_id: "loc".into(),
                model: "llama3.1:8b".into(),
                fallback: None,
            },
        );
        let env = resolve(&c, &s, None, "codex").unwrap().into_env();
        assert_eq!(env["OPENAI_BASE_URL"], "http://127.0.0.1:11434/v1");
        assert_eq!(env["OPENAI_API_KEY"], "none");
    }

    #[test]
    fn a_provider_hosted_on_one_box_is_not_offered_to_another() {
        let s = MemorySecrets::default();
        let mut c = cfg();
        c.providers[3].hosted_on = Some("gpu-1".into());
        c.engines.insert(
            "codex".into(),
            EngineModel {
                provider_id: "loc".into(),
                model: "m".into(),
                fallback: None,
            },
        );
        assert!(resolve(&c, &s, Some("gpu-1"), "codex").is_ok());
        assert!(resolve(&c, &s, Some("dev"), "codex")
            .unwrap_err()
            .contains("not reachable"));
    }
}
