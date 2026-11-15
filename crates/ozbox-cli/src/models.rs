//! Model provider keys, the free "list models" check and the one paid "test message".
//!
//! The server keeps the provider list, the default model per job (coding, chat, review), the model per agent engine and
//! the monthly cap in settings, and each provider's key in the secret store, write-only. The request each provider
//! needs is built in `model_providers`. **Listing models costs nothing**; the test message sends one tiny request, only
//! when the person has confirmed that it may cost a fraction of a cent. Neither answer ever echoes the key: a
//! provider's error text is trimmed and scrubbed of the key before it is shown.

use std::time::Instant;

use serde::Serialize;
use serde_json::Value;

use crate::model_providers as mp;
use crate::netguard::{HttpClient, HttpRequest};
use crate::secrets::SecretStore;
use crate::settings::{ModelProvider, ModelsConfig};

pub fn key_name(id: &str) -> String {
    format!("model-key-{id}")
}

#[derive(Debug, Clone, Serialize, serde::Deserialize, PartialEq)]
pub struct TestResult {
    pub ok: bool,
    pub status: Option<u16>,
    pub latency_ms: u64,
    pub detail: String,
}

/// The models a provider offers, from its own list call.
#[derive(Debug, Clone, Serialize, serde::Deserialize, PartialEq)]
pub struct ListResult {
    pub ok: bool,
    pub status: Option<u16>,
    pub latency_ms: u64,
    pub detail: String,
    pub models: Vec<String>,
    /// OpenRouter only: the prices its list carried. Not part of the answer; the server keeps them with the read time.
    #[serde(skip)]
    pub live_prices: std::collections::BTreeMap<String, crate::model_prices::LiveRow>,
}

/// The model the person set as the default for a job that uses this provider.
pub fn default_model_for<'a>(models: &'a ModelsConfig, provider_id: &str) -> Option<&'a str> {
    [
        &models.defaults.coding,
        &models.defaults.chat,
        &models.defaults.review,
    ]
    .into_iter()
    .flatten()
    .find(|c| c.provider_id == provider_id)
    .map(|c| c.model.as_str())
}

fn scrub(text: &str, key: &str) -> String {
    let t = if key.is_empty() {
        text.to_string()
    } else {
        text.replace(key, "[key]")
    };
    t.chars().filter(|c| !c.is_control()).take(160).collect()
}

/// Build the one request: a one-word prompt and the smallest reply.
pub fn build_request(p: &ModelProvider, model: &str, key: Option<&str>) -> Option<HttpRequest> {
    mp::ping_request(p, model, key)
}

/// What a failed answer means, in words, with the provider's own message scrubbed of the key.
fn explain(status: u16, body: &str, key: &str) -> String {
    let msg = serde_json::from_str::<Value>(body)
        .ok()
        .and_then(|v| {
            v.pointer("/error/message")
                .or_else(|| v.pointer("/error"))
                .or_else(|| v.get("message"))
                .and_then(Value::as_str)
                .map(str::to_string)
        })
        .unwrap_or_default();
    let lead = match status {
        401 | 403 => "The provider rejected the key",
        404 => "The provider does not know that endpoint or model",
        429 => "The provider is rate limiting or out of quota",
        s if (300..400).contains(&s) => "The endpoint redirected, which is not followed",
        _ => "The provider returned an error",
    };
    if msg.is_empty() {
        format!("{lead} (HTTP {status}).")
    } else {
        format!("{lead} (HTTP {status}): {}", scrub(&msg, key))
    }
}

/// The request for these credentials. A cloud account's structured credentials (an AWS key pair, an Azure client, a Google
/// service account) are signed or exchanged here, exactly as the credential broker does for a run; anything else is the
/// provider's one header, as the builder makes it.
fn authorized(
    http: &dyn HttpClient,
    p: &ModelProvider,
    key: Option<&str>,
    build: impl Fn(Option<&str>) -> Option<HttpRequest>,
) -> Result<HttpRequest, String> {
    use crate::broker_cloud as bc;
    if let (Some(k), true) = (key, mp::own_cloud(p.kind)) {
        let cred = bc::parse(p.kind, k)?;
        if cred.structured() {
            let mut req = build(None).ok_or("this provider has no endpoint address")?;
            let ctx = bc::Ctx {
                kind: p.kind,
                provider_id: &p.id,
                region: p.region.as_deref(),
                now_ms: crate::serve::unix_ms(),
            };
            let send = |r: &HttpRequest| {
                http.send(r)
                    .map(|a| (a.status, a.body.into_bytes()))
                    .map_err(|e| e.to_string())
            };
            bc::authorize(&mut req, &ctx, &cred, &bc::TokenCache::default(), &send)?;
            return Ok(req);
        }
    }
    build(key).ok_or_else(|| "this provider has no endpoint address".to_string())
}

fn key_for(secrets: &dyn SecretStore, p: &ModelProvider) -> Result<Option<String>, String> {
    let key = secrets.get(&key_name(&p.id)).map_err(|e| e.to_string())?;
    // A local open-weight server may need no key; the hosted providers always do.
    if key.is_none() && !mp::key_optional(p) {
        return Err("no key is saved for this provider".into());
    }
    Ok(key)
}

/// Ask the provider which models these credentials can use. Free; this is the "Test connection".
pub fn list_models(
    http: &dyn HttpClient,
    secrets: &dyn SecretStore,
    p: &ModelProvider,
) -> Result<ListResult, String> {
    if let Some(r) = secrets.probe("list_models", &serde_json::json!({ "provider": p })) {
        let v = r.map_err(|e| e.0)?;
        return serde_json::from_value(v).map_err(|_| "the answer could not be read".to_string());
    }
    let key = key_for(secrets, p)?;
    let req = authorized(http, p, key.as_deref(), |k| mp::list_request(p, k))?;
    let start = Instant::now();
    let sent = http.send(&req);
    let latency_ms = start.elapsed().as_millis() as u64;
    let r = match sent {
        Ok(r) => r,
        Err(e) => {
            return Ok(ListResult {
                ok: false,
                status: None,
                latency_ms,
                detail: e.to_string(),
                models: Vec::new(),
                live_prices: std::collections::BTreeMap::new(),
            });
        }
    };
    if !r.ok() {
        return Ok(ListResult {
            ok: false,
            status: Some(r.status),
            latency_ms,
            detail: explain(r.status, &r.body, key.as_deref().unwrap_or("")),
            models: Vec::new(),
            live_prices: std::collections::BTreeMap::new(),
        });
    }
    let models = mp::parse_models(&r.body);
    let detail = if models.is_empty() {
        "The credentials work, but the provider listed no models. Type the model name you want to use.".to_string()
    } else {
        format!("Connected. The provider offers {} model(s).", models.len())
    };
    Ok(ListResult {
        ok: true,
        status: Some(r.status),
        latency_ms,
        detail,
        models,
        live_prices: if p.kind == crate::settings::ModelKind::Openrouter {
            crate::model_prices::parse_openrouter(&r.body)
        } else {
            std::collections::BTreeMap::new()
        },
    })
}

/// The one-word test message. Can cost a fraction of a cent.
pub fn test_connection(
    http: &dyn HttpClient,
    secrets: &dyn SecretStore,
    p: &ModelProvider,
    model: &str,
) -> Result<TestResult, String> {
    if let Some(r) = secrets.probe(
        "test_connection",
        &serde_json::json!({ "provider": p, "model": model }),
    ) {
        let v = r.map_err(|e| e.0)?;
        return serde_json::from_value(v).map_err(|_| "the answer could not be read".to_string());
    }
    let key = key_for(secrets, p)?;
    let req = authorized(http, p, key.as_deref(), |k| build_request(p, model, k))?;
    let start = Instant::now();
    let sent = http.send(&req);
    let latency_ms = start.elapsed().as_millis() as u64;
    let r = match sent {
        Ok(r) => r,
        Err(e) => {
            return Ok(TestResult {
                ok: false,
                status: None,
                latency_ms,
                detail: e.to_string(),
            });
        }
    };
    let detail = if r.ok() {
        "The provider accepted a one-word request with this key and model.".to_string()
    } else {
        explain(r.status, &r.body, key.as_deref().unwrap_or(""))
    };
    Ok(TestResult {
        ok: r.ok(),
        status: Some(r.status),
        latency_ms,
        detail,
    })
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use crate::netguard::{FakeHttp, Guard};
    use crate::secrets::MemorySecrets;
    use crate::settings::{ModelChoice, ModelDefaults, ModelKind};

    fn provider(kind: ModelKind, base: Option<&str>, local: bool) -> ModelProvider {
        ModelProvider {
            id: "main".into(),
            kind,
            label: "Main".into(),
            base_url: base.map(str::to_string),
            local_endpoint: local,
            monthly_cap_usd: None,
            region: (kind == ModelKind::Bedrock).then(|| "us-east-1".into()),
            resource: (kind == ModelKind::AzureOpenai).then(|| "res".into()),
            hosted_on: None,
        }
    }

    #[test]
    fn requests_per_provider_kind() {
        let a = build_request(
            &provider(ModelKind::Anthropic, None, false),
            "m-1",
            Some("K"),
        )
        .unwrap();
        assert_eq!(a.url, "https://api.anthropic.com/v1/messages");
        assert!(a.headers.iter().any(|(k, v)| k == "x-api-key" && v == "K"));
        assert!(a.headers.iter().any(|(k, _)| k == "anthropic-version"));
        let body = String::from_utf8_lossy(a.body.as_deref().unwrap_or_default()).into_owned();
        assert!(body.contains("\"max_tokens\":1") && body.contains("\"model\":\"m-1\""));
        let o = build_request(&provider(ModelKind::Openai, None, false), "m", Some("K")).unwrap();
        assert_eq!(o.url, "https://api.openai.com/v1/chat/completions");
        assert!(o
            .headers
            .iter()
            .any(|(k, v)| k == "Authorization" && v == "Bearer K"));
        let c = build_request(
            &provider(
                ModelKind::OpenaiCompatible,
                Some("http://localhost:11434/v1/"),
                true,
            ),
            "m",
            None,
        )
        .unwrap();
        assert_eq!(c.url, "http://localhost:11434/v1/chat/completions");
        assert_eq!(c.guard, Guard::Private);
        assert!(!c.headers.iter().any(|(k, _)| k == "Authorization"));
        let remote = build_request(
            &provider(
                ModelKind::OpenaiCompatible,
                Some("https://models.example.com/v1"),
                false,
            ),
            "m",
            Some("K"),
        )
        .unwrap();
        assert_eq!(remote.guard, Guard::Public);
    }

    #[test]
    fn a_request_never_prints_its_key() {
        let r = build_request(
            &provider(ModelKind::Openai, None, false),
            "m",
            Some("sk-SENTINEL-77"),
        )
        .unwrap();
        let shown = format!("{r:?}");
        assert!(!shown.contains("SENTINEL"), "{shown}");
        assert!(shown.contains("Authorization"));
    }

    #[test]
    fn a_test_needs_a_key_for_hosted_providers_and_never_echoes_it(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let http = FakeHttp::default();
        let secrets = MemorySecrets::default();
        let p = provider(ModelKind::Anthropic, None, false);
        assert!(test_connection(&http, &secrets, &p, "m").is_err());
        assert!(list_models(&http, &secrets, &p).is_err());
        assert!(http.requests().is_empty(), "nothing is sent without a key");
        secrets.set("model-key-main", "sk-SENTINEL-9999")?;
        http.reply(200, "{}");
        let ok = test_connection(&http, &secrets, &p, "m")?;
        assert!(ok.ok && ok.status == Some(200));
        // an error body that repeats the key is scrubbed
        http.reply(
            401,
            r#"{"error":{"message":"invalid x-api-key sk-SENTINEL-9999"}}"#,
        );
        let bad = test_connection(&http, &secrets, &p, "m")?;
        assert!(!bad.ok);
        assert!(!bad.detail.contains("SENTINEL"), "{}", bad.detail);
        assert!(bad.detail.contains("rejected the key") && bad.detail.contains("401"));
        http.reply(404, "{}");
        assert!(test_connection(&http, &secrets, &p, "m")?
            .detail
            .contains("model"));
        Ok(())
    }

    #[test]
    fn listing_models_maps_answers_and_errors_and_never_echoes_the_key(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let http = FakeHttp::default();
        let secrets = MemorySecrets::default();
        secrets.set("model-key-main", "AKIA-SENTINEL-1")?;
        let p = provider(ModelKind::Bedrock, None, false);
        http.reply(
            200,
            r#"{"modelSummaries":[{"modelId":"anthropic.x-v1:0"},{"modelId":"amazon.y"}]}"#,
        );
        let r = list_models(&http, &secrets, &p)?;
        assert!(r.ok);
        assert_eq!(r.models, ["amazon.y", "anthropic.x-v1:0"]);
        assert_eq!(http.requests()[0].method, "GET");
        http.reply(403, r#"{"message":"bad token AKIA-SENTINEL-1"}"#);
        let bad = list_models(&http, &secrets, &p)?;
        assert!(!bad.ok && bad.models.is_empty());
        assert!(
            !bad.detail.contains("SENTINEL") && bad.detail.contains("rejected the key"),
            "{}",
            bad.detail
        );
        http.reply(200, "{}");
        let empty = list_models(&http, &secrets, &p)?;
        assert!(empty.ok && empty.detail.contains("listed no models"));
        Ok(())
    }

    #[test]
    fn a_local_server_needs_no_key() -> Result<(), Box<dyn std::error::Error>> {
        let http = FakeHttp::default();
        let secrets = MemorySecrets::default();
        let p = provider(
            ModelKind::OpenaiCompatible,
            Some("http://127.0.0.1:8000/v1"),
            true,
        );
        assert!(test_connection(&http, &secrets, &p, "llama")?.ok);
        http.reply(200, r#"{"data":[{"id":"llama3.1:8b"}]}"#);
        assert_eq!(list_models(&http, &secrets, &p)?.models, ["llama3.1:8b"]);
        Ok(())
    }

    #[test]
    fn the_default_model_comes_from_the_job_that_names_the_provider() {
        let m = ModelsConfig {
            providers: vec![provider(ModelKind::Openai, None, false)],
            defaults: ModelDefaults {
                coding: None,
                chat: Some(ModelChoice {
                    provider_id: "main".into(),
                    model: "gpt-x".into(),
                }),
                review: Some(ModelChoice {
                    provider_id: "other".into(),
                    model: "y".into(),
                }),
            },
            ..Default::default()
        };
        assert_eq!(default_model_for(&m, "main"), Some("gpt-x"));
        assert_eq!(default_model_for(&m, "none"), None);
    }
}
