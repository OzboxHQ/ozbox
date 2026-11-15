//! The model providers Oz Box can use with a person's own key or cloud account: what each one needs, the one cheap
//! "list models" request that proves the credentials, the one-word test request, and how the model list is read.
//!
//! Nothing here sends anything: it builds [`HttpRequest`]s (every one goes through the outbound guard) and reads
//! answers. Keys are put in headers only, never in an address, and an error never repeats one.

use serde_json::{json, Value};

use crate::netguard::{Guard, HttpRequest};
use crate::settings::{ModelKind, ModelProvider};

pub const ALL: [ModelKind; 11] = [
    ModelKind::Anthropic,
    ModelKind::Openai,
    ModelKind::Google,
    ModelKind::Bedrock,
    ModelKind::AzureOpenai,
    ModelKind::Vertex,
    ModelKind::Openrouter,
    ModelKind::Mistral,
    ModelKind::Groq,
    ModelKind::Together,
    ModelKind::OpenaiCompatible,
];

pub fn kind_id(k: ModelKind) -> &'static str {
    match k {
        ModelKind::Anthropic => "anthropic",
        ModelKind::Openai => "openai",
        ModelKind::OpenaiCompatible => "openai_compatible",
        ModelKind::Google => "google",
        ModelKind::Bedrock => "bedrock",
        ModelKind::AzureOpenai => "azure_openai",
        ModelKind::Vertex => "vertex",
        ModelKind::Openrouter => "openrouter",
        ModelKind::Mistral => "mistral",
        ModelKind::Groq => "groq",
        ModelKind::Together => "together",
    }
}

pub fn parse_kind(s: &str) -> Option<ModelKind> {
    ALL.into_iter().find(|k| kind_id(*k) == s)
}

/// Whether the provider is reached through the person's own cloud account rather than a vendor key.
pub fn own_cloud(k: ModelKind) -> bool {
    matches!(
        k,
        ModelKind::Bedrock | ModelKind::AzureOpenai | ModelKind::Vertex
    )
}

/// Model names worth offering before the list has been fetched. The fetched list is the truth.
pub fn suggested_models(k: ModelKind) -> &'static [&'static str] {
    match k {
        ModelKind::Anthropic => &[
            "claude-sonnet-4-20250514",
            "claude-opus-4-20250514",
            "claude-3-5-haiku-20241022",
        ],
        ModelKind::Openai => &["gpt-4o", "gpt-4o-mini", "gpt-4.1"],
        ModelKind::Google | ModelKind::Vertex => &["gemini-2.5-pro", "gemini-2.5-flash"],
        ModelKind::Bedrock => &["anthropic.claude-sonnet-4-20250514-v1:0"],
        ModelKind::Openrouter => &["anthropic/claude-sonnet-4", "openai/gpt-4o"],
        ModelKind::Mistral => &[
            "mistral-large-latest",
            "mistral-small-latest",
            "codestral-latest",
        ],
        ModelKind::Groq => &["llama-3.3-70b-versatile"],
        ModelKind::Together => &["meta-llama/Llama-3.3-70B-Instruct-Turbo"],
        ModelKind::AzureOpenai | ModelKind::OpenaiCompatible => &[],
    }
}

fn region_ok(r: &str) -> bool {
    let parts: Vec<&str> = r.split('-').collect();
    parts.len() >= 3
        && r.len() <= 25
        && parts.iter().all(|p| {
            !p.is_empty()
                && p.bytes()
                    .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit())
        })
        && parts
            .last()
            .is_some_and(|l| l.bytes().all(|b| b.is_ascii_digit()))
}

/// A Vertex location: `global`, or a region such as `us-east5` (it becomes part of an address).
pub fn location_ok(l: &str) -> bool {
    !l.is_empty()
        && l.len() <= 24
        && !l.starts_with('-')
        && l.bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
}

/// The region itself when it is a valid AWS region name (it becomes part of an address).
pub fn valid_region(r: &str) -> Option<&str> {
    region_ok(r).then_some(r)
}

/// The resource name itself when it is a valid Azure resource name (it becomes part of an address).
pub fn valid_resource(r: &str) -> Option<&str> {
    resource_ok(r).then_some(r)
}

fn resource_ok(r: &str) -> bool {
    !r.is_empty()
        && r.len() <= 63
        && !r.starts_with('-')
        && !r.ends_with('-')
        && r.bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
}

/// The fields beyond the common ones: each kind takes exactly the ones it needs.
pub fn validate_extras(p: &ModelProvider) -> Result<(), String> {
    match (p.kind, p.region.as_deref()) {
        (ModelKind::Bedrock, Some(r)) if region_ok(r) => {}
        (ModelKind::Bedrock, _) => {
            return Err(
                "an AWS Bedrock provider needs the AWS region of your account, like us-east-1"
                    .into(),
            )
        }
        (ModelKind::Vertex, Some(l)) if location_ok(l) => {}
        (ModelKind::Vertex, Some(_)) => {
            return Err(
                "a Google Vertex location looks like us-east5, europe-west4 or global".into(),
            )
        }
        (_, Some(_)) => {
            return Err("only an AWS Bedrock or Google Vertex provider has a region".into())
        }
        (_, None) => {}
    }
    match (p.kind, p.resource.as_deref()) {
        (ModelKind::AzureOpenai, Some(r)) if resource_ok(r) => {}
        (ModelKind::AzureOpenai, _) => {
            return Err(
                "an Azure OpenAI provider needs the name of your Azure OpenAI resource".into(),
            )
        }
        (_, Some(_)) => return Err("only an Azure OpenAI provider has a resource name".into()),
        (_, None) => {}
    }
    if let Some(b) = p.hosted_on.as_deref() {
        if ozbox_core::BoxName::new(b).is_err() || !p.local_endpoint {
            return Err(
                "a provider hosted on a box must be a local endpoint on a valid box name".into(),
            );
        }
    }
    Ok(())
}

pub fn guard(p: &ModelProvider) -> Guard {
    if p.local_endpoint {
        Guard::Private
    } else {
        Guard::Public
    }
}

const AZURE_API: &str = "2024-10-21";

fn enc(model: &str) -> String {
    model.replace('/', "%2F")
}

fn bearer(req: HttpRequest, key: Option<&str>) -> HttpRequest {
    match key {
        Some(k) => req.header("Authorization", format!("Bearer {k}")),
        None => req,
    }
}

/// The cheap request that lists the models these credentials can use. It costs nothing.
pub fn list_request(p: &ModelProvider, key: Option<&str>) -> Option<HttpRequest> {
    let g = guard(p);
    let k = key.unwrap_or_default();
    let get = |url: String| HttpRequest::new("GET", url, g);
    Some(match p.kind {
        ModelKind::Anthropic => get("https://api.anthropic.com/v1/models?limit=100".into())
            .header("x-api-key", k)
            .header("anthropic-version", "2023-06-01"),
        ModelKind::Openai => bearer(get("https://api.openai.com/v1/models".into()), key),
        ModelKind::Google => {
            get("https://generativelanguage.googleapis.com/v1beta/models?pageSize=200".into())
                .header("x-goog-api-key", k)
        }
        ModelKind::Bedrock => bearer(
            get(format!(
                "https://bedrock.{}.amazonaws.com/foundation-models",
                p.region.as_deref()?
            )),
            key,
        ),
        ModelKind::AzureOpenai => get(format!(
            "https://{}.openai.azure.com/openai/models?api-version={AZURE_API}",
            p.resource.as_deref()?
        ))
        .header("api-key", k),
        ModelKind::Vertex => get(
            "https://aiplatform.googleapis.com/v1beta1/publishers/google/models?pageSize=100"
                .into(),
        )
        .header("x-goog-api-key", k),
        ModelKind::Openrouter => bearer(get("https://openrouter.ai/api/v1/models".into()), key),
        ModelKind::Mistral => bearer(get("https://api.mistral.ai/v1/models".into()), key),
        ModelKind::Groq => bearer(get("https://api.groq.com/openai/v1/models".into()), key),
        ModelKind::Together => bearer(get("https://api.together.xyz/v1/models".into()), key),
        ModelKind::OpenaiCompatible => bearer(
            get(format!(
                "{}/models",
                p.base_url.as_deref()?.trim_end_matches('/')
            )),
            key,
        ),
    })
}

/// The model names in a list answer, sorted and without duplicates. Unreadable answers give an empty list.
pub fn parse_models(body: &str) -> Vec<String> {
    let Ok(v) = serde_json::from_str::<Value>(body) else {
        return Vec::new();
    };
    let items: &[Value] = v
        .as_array()
        .or_else(|| {
            ["data", "models", "modelSummaries", "publisherModels"]
                .iter()
                .find_map(|k| v.get(*k).and_then(Value::as_array))
        })
        .map_or(&[], Vec::as_slice);
    let mut out: Vec<String> = items
        .iter()
        .filter_map(|i| {
            ["id", "modelId", "name"]
                .iter()
                .find_map(|k| i.get(*k).and_then(Value::as_str))
                .or_else(|| i.as_str())
        })
        .map(|n| {
            if n.starts_with("publishers/") {
                n.rsplit_once("/models/").map_or(n, |(_, m)| m).to_string()
            } else {
                n.strip_prefix("models/").unwrap_or(n).to_string()
            }
        })
        .filter(|n| !n.is_empty() && n.len() <= 100 && !n.chars().any(char::is_control))
        .collect();
    out.sort();
    out.dedup();
    out.truncate(500);
    out
}

/// The one-word request that proves a model answers. It can cost a fraction of a cent.
pub fn ping_request(p: &ModelProvider, model: &str, key: Option<&str>) -> Option<HttpRequest> {
    let g = guard(p);
    let k = key.unwrap_or_default();
    let post = |url: String| HttpRequest::new("POST", url, g);
    let chat = json!([{ "role": "user", "content": "ping" }]);
    let openai_body = |limit: &str| json!({ "model": model, limit: 16, "messages": chat });
    Some(match p.kind {
        ModelKind::Anthropic => post("https://api.anthropic.com/v1/messages".into())
            .header("x-api-key", k)
            .header("anthropic-version", "2023-06-01")
            .json(&json!({ "model": model, "max_tokens": 1, "messages": chat })),
        ModelKind::Openai => bearer(post("https://api.openai.com/v1/chat/completions".into()), key)
            .json(&openai_body("max_completion_tokens")),
        ModelKind::Google => post(format!(
            "https://generativelanguage.googleapis.com/v1beta/models/{}:generateContent",
            enc(model)
        ))
        .header("x-goog-api-key", k)
        .json(&json!({ "contents": [{ "role": "user", "parts": [{ "text": "ping" }] }], "generationConfig": { "maxOutputTokens": 16 } })),
        ModelKind::Vertex => post(format!(
            "https://aiplatform.googleapis.com/v1/publishers/google/models/{}:generateContent",
            enc(model)
        ))
        .header("x-goog-api-key", k)
        .json(&json!({ "contents": [{ "role": "user", "parts": [{ "text": "ping" }] }], "generationConfig": { "maxOutputTokens": 16 } })),
        ModelKind::Bedrock => bearer(
            post(format!(
                "https://bedrock-runtime.{}.amazonaws.com/model/{}/converse",
                p.region.as_deref()?,
                enc(model)
            )),
            key,
        )
        .json(&json!({ "messages": [{ "role": "user", "content": [{ "text": "ping" }] }], "inferenceConfig": { "maxTokens": 16 } })),
        ModelKind::AzureOpenai => post(format!(
            "https://{}.openai.azure.com/openai/deployments/{}/chat/completions?api-version={AZURE_API}",
            p.resource.as_deref()?,
            enc(model)
        ))
        .header("api-key", k)
        .json(&openai_body("max_completion_tokens")),
        ModelKind::Openrouter => bearer(post("https://openrouter.ai/api/v1/chat/completions".into()), key)
            .json(&openai_body("max_tokens")),
        ModelKind::Mistral => bearer(post("https://api.mistral.ai/v1/chat/completions".into()), key)
            .json(&openai_body("max_tokens")),
        ModelKind::Groq => bearer(post("https://api.groq.com/openai/v1/chat/completions".into()), key)
            .json(&openai_body("max_tokens")),
        ModelKind::Together => bearer(post("https://api.together.xyz/v1/chat/completions".into()), key)
            .json(&openai_body("max_tokens")),
        ModelKind::OpenaiCompatible => bearer(
            post(format!(
                "{}/chat/completions",
                p.base_url.as_deref()?.trim_end_matches('/')
            )),
            key,
        )
        .json(&openai_body("max_tokens")),
    })
}

/// Whether a provider of this kind works without a key (a local server may).
pub fn key_optional(p: &ModelProvider) -> bool {
    p.kind == ModelKind::OpenaiCompatible
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    pub fn prov(kind: ModelKind) -> ModelProvider {
        ModelProvider {
            id: "main".into(),
            kind,
            label: "Main".into(),
            base_url: (kind == ModelKind::OpenaiCompatible)
                .then(|| "https://models.example.com/v1/".into()),
            local_endpoint: false,
            monthly_cap_usd: None,
            region: (kind == ModelKind::Bedrock).then(|| "us-east-1".into()),
            resource: (kind == ModelKind::AzureOpenai).then(|| "my-resource".into()),
            hosted_on: None,
        }
    }

    fn header<'a>(r: &'a HttpRequest, k: &str) -> Option<&'a str> {
        r.headers
            .iter()
            .find(|(n, _)| n.eq_ignore_ascii_case(k))
            .map(|(_, v)| v.as_str())
    }

    #[test]
    fn every_kind_lists_models_with_the_key_in_a_header_never_in_the_address() {
        for k in ALL {
            let r = list_request(&prov(k), Some("KEY-123")).unwrap();
            assert_eq!(r.method, "GET", "{k:?}");
            assert!(r.url.starts_with("https://"), "{}", r.url);
            assert!(
                !r.url.contains("KEY-123"),
                "{k:?} puts the key in the address"
            );
            assert!(r.body.is_none());
            assert!(
                r.headers.iter().any(|(_, v)| v.contains("KEY-123")),
                "{k:?} sends no credential"
            );
            assert_eq!(r.guard, Guard::Public);
        }
    }

    #[test]
    fn auth_styles_follow_each_provider() {
        let a = list_request(&prov(ModelKind::Anthropic), Some("K")).unwrap();
        assert_eq!(header(&a, "x-api-key"), Some("K"));
        assert!(header(&a, "anthropic-version").is_some());
        let g = list_request(&prov(ModelKind::Google), Some("K")).unwrap();
        assert_eq!(header(&g, "x-goog-api-key"), Some("K"));
        let az = list_request(&prov(ModelKind::AzureOpenai), Some("K")).unwrap();
        assert_eq!(header(&az, "api-key"), Some("K"));
        assert!(az.url.starts_with("https://my-resource.openai.azure.com/"));
        let b = list_request(&prov(ModelKind::Bedrock), Some("K")).unwrap();
        assert_eq!(header(&b, "Authorization"), Some("Bearer K"));
        assert_eq!(
            b.url,
            "https://bedrock.us-east-1.amazonaws.com/foundation-models"
        );
        let c = list_request(&prov(ModelKind::OpenaiCompatible), None).unwrap();
        assert_eq!(c.url, "https://models.example.com/v1/models");
        assert!(header(&c, "Authorization").is_none());
    }

    #[test]
    fn ping_requests_are_one_word_and_tiny() {
        for k in ALL {
            let r = ping_request(&prov(k), "m/1:0", Some("KEY-123")).unwrap();
            assert_eq!(r.method, "POST");
            assert!(!r.url.contains("KEY-123"));
            let body = String::from_utf8_lossy(r.body.as_deref().unwrap()).into_owned();
            assert!(body.contains("ping"), "{k:?}");
            assert!(
                body.contains(":16") || body.contains("\"max_tokens\":1"),
                "{k:?}: {body}"
            );
        }
        let b = ping_request(&prov(ModelKind::Bedrock), "anthropic.x-v1:0", Some("K")).unwrap();
        assert!(b.url.ends_with("/model/anthropic.x-v1:0/converse"));
        let g = ping_request(&prov(ModelKind::Google), "gemini-2.5-pro", Some("K")).unwrap();
        assert!(g.url.ends_with("/models/gemini-2.5-pro:generateContent"));
    }

    #[test]
    fn a_missing_region_or_resource_builds_nothing() {
        let mut b = prov(ModelKind::Bedrock);
        b.region = None;
        assert!(list_request(&b, Some("K")).is_none());
        assert!(validate_extras(&b).is_err());
        let mut a = prov(ModelKind::AzureOpenai);
        a.resource = Some("-bad".into());
        assert!(validate_extras(&a).is_err());
        a.resource = Some("evil.example.com/x".into());
        assert!(validate_extras(&a).is_err());
        let mut o = prov(ModelKind::Openai);
        o.region = Some("us-east-1".into());
        assert!(validate_extras(&o).is_err());
        assert!(validate_extras(&prov(ModelKind::Bedrock)).is_ok());
    }

    #[test]
    fn a_local_endpoint_uses_the_private_guard_and_a_box_host_needs_it() {
        let mut p = prov(ModelKind::OpenaiCompatible);
        p.base_url = Some("http://10.0.0.5:11434/v1".into());
        p.local_endpoint = true;
        assert_eq!(list_request(&p, None).unwrap().guard, Guard::Private);
        p.hosted_on = Some("gpu-1".into());
        assert!(validate_extras(&p).is_ok());
        p.local_endpoint = false;
        assert!(validate_extras(&p).is_err());
    }

    #[test]
    fn model_lists_are_read_from_every_provider_shape() {
        assert_eq!(
            parse_models(r#"{"data":[{"id":"b"},{"id":"a"},{"id":"a"}]}"#),
            ["a", "b"]
        );
        assert_eq!(
            parse_models(r#"{"models":[{"name":"models/gemini-2.5-pro"}]}"#),
            ["gemini-2.5-pro"]
        );
        assert_eq!(
            parse_models(r#"{"modelSummaries":[{"modelId":"anthropic.x-v1:0"}]}"#),
            ["anthropic.x-v1:0"]
        );
        assert_eq!(
            parse_models(r#"{"publisherModels":[{"name":"publishers/google/models/gemini-x"}]}"#),
            ["gemini-x"]
        );
        assert_eq!(parse_models(r#"[{"id":"meta/llama"}]"#), ["meta/llama"]);
        assert!(parse_models("not json").is_empty());
        assert!(parse_models(r#"{"error":"x"}"#).is_empty());
    }
}
