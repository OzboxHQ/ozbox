//! Which requests the credential broker relays, per provider: the model-inference endpoints and the model list, and nothing
//! else (ADR 0028 item 3, as amended).
//!
//! The broker adds the provider's credential to what a run sends. Before this list it relayed any GET or POST under the
//! provider's address, so a run holding a Vertex token could start a training job in the owner's project, and one holding
//! an Azure token could upload files or start fine-tuning, none of it counted against the run's spend limit. A run may now
//! only ask a model for an answer (or count tokens, or embed), and list the models. Everything else is refused with 403
//! before any credential is read.
//!
//! A pattern is a path of segments: a literal, `*` (any one non-empty segment), or `*:a|b` (a segment that ends in one of
//! those `:verb`s, as Google's APIs write them). The query may name only `alt` (server-sent events), `api-version` (Azure)
//! and `beta` (Anthropic's beta flag), with plain values.

use crate::settings::ModelKind;

/// What a relayed endpoint is.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Kind {
    /// Makes the model work: its answer carries the usage the broker counts against the run.
    Generation,
    /// Counts tokens, embeds or lists models: its answer carries no usage worth counting.
    Free,
}

struct Rule {
    method: &'static str,
    path: &'static str,
    kind: Kind,
}

const fn post(path: &'static str) -> Rule {
    Rule {
        method: "POST",
        path,
        kind: Kind::Generation,
    }
}

const fn post_free(path: &'static str) -> Rule {
    Rule {
        method: "POST",
        path,
        kind: Kind::Free,
    }
}

const fn get(path: &'static str) -> Rule {
    Rule {
        method: "GET",
        path,
        kind: Kind::Free,
    }
}

const ANTHROPIC: &[Rule] = &[
    post("/v1/messages"),
    post_free("/v1/messages/count_tokens"),
    get("/v1/models"),
    get("/v1/models/*"),
];

/// The OpenAI shape, under `/v1` (OpenAI, OpenRouter, Mistral, Groq, Together).
const OPENAI_V1: &[Rule] = &[
    post("/v1/chat/completions"),
    post("/v1/completions"),
    post("/v1/responses"),
    post_free("/v1/embeddings"),
    get("/v1/models"),
    get("/v1/models/*"),
];

const OPENROUTER: &[Rule] = &[
    post("/v1/chat/completions"),
    post("/v1/completions"),
    post("/v1/responses"),
    post("/v1/messages"),
    post_free("/v1/embeddings"),
    get("/v1/models"),
];

const MISTRAL: &[Rule] = &[
    post("/v1/chat/completions"),
    post("/v1/fim/completions"),
    post_free("/v1/embeddings"),
    get("/v1/models"),
];

/// An OpenAI-compatible endpoint's base address ends before `/chat/completions`, with or without its own `/v1`.
const OPENAI_COMPATIBLE: &[Rule] = &[
    post("/chat/completions"),
    post("/completions"),
    post("/responses"),
    post_free("/embeddings"),
    get("/models"),
    post("/v1/chat/completions"),
    post("/v1/completions"),
    post("/v1/responses"),
    post_free("/v1/embeddings"),
    get("/v1/models"),
];

const GOOGLE: &[Rule] = &[
    post("/v1beta/models/*:generateContent|streamGenerateContent"),
    post("/v1/models/*:generateContent|streamGenerateContent"),
    post_free("/v1beta/models/*:countTokens|embedContent|batchEmbedContents"),
    post_free("/v1/models/*:countTokens|embedContent|batchEmbedContents"),
    get("/v1beta/models"),
    get("/v1beta/models/*"),
    get("/v1/models"),
    get("/v1/models/*"),
];

/// Bedrock's runtime: invoking a model, nothing of the control plane (that is another host, which the broker never uses).
const BEDROCK: &[Rule] = &[
    post("/model/*/invoke"),
    post("/model/*/invoke-with-response-stream"),
    post("/model/*/converse"),
    post("/model/*/converse-stream"),
    post_free("/model/*/count-tokens"),
];

/// Azure OpenAI: a deployment's inference, or the `v1` surface's; never files, fine-tuning, batches or assistants.
const AZURE: &[Rule] = &[
    post("/openai/deployments/*/chat/completions"),
    post("/openai/deployments/*/completions"),
    post_free("/openai/deployments/*/embeddings"),
    post("/openai/responses"),
    post("/openai/v1/chat/completions"),
    post("/openai/v1/completions"),
    post("/openai/v1/responses"),
    post_free("/openai/v1/embeddings"),
    get("/openai/v1/models"),
    get("/openai/models"),
];

/// Vertex: a publisher model's prediction, with or without the API version in front (the Anthropic SDK puts it in the base
/// address), and the OpenAI-compatible chat endpoint. Never jobs, endpoints, datasets or anything else in the project.
const VERTEX: &[Rule] = &[
    post("/v1/projects/*/locations/*/publishers/*/models/*:generateContent|streamGenerateContent|predict|rawPredict|streamRawPredict"),
    post("/v1beta1/projects/*/locations/*/publishers/*/models/*:generateContent|streamGenerateContent|predict|rawPredict|streamRawPredict"),
    post("/projects/*/locations/*/publishers/*/models/*:generateContent|streamGenerateContent|predict|rawPredict|streamRawPredict"),
    post_free("/v1/projects/*/locations/*/publishers/*/models/*:countTokens"),
    post_free("/v1beta1/projects/*/locations/*/publishers/*/models/*:countTokens"),
    post_free("/projects/*/locations/*/publishers/*/models/*:countTokens"),
    post("/v1/projects/*/locations/*/endpoints/openapi/chat/completions"),
    post("/v1beta1/projects/*/locations/*/endpoints/openapi/chat/completions"),
    get("/v1/publishers/*/models"),
    get("/v1beta1/publishers/*/models"),
];

fn rules(kind: ModelKind) -> &'static [Rule] {
    match kind {
        ModelKind::Anthropic => ANTHROPIC,
        ModelKind::Openai | ModelKind::Groq | ModelKind::Together => OPENAI_V1,
        ModelKind::Openrouter => OPENROUTER,
        ModelKind::Mistral => MISTRAL,
        ModelKind::OpenaiCompatible => OPENAI_COMPATIBLE,
        ModelKind::Google => GOOGLE,
        ModelKind::Bedrock => BEDROCK,
        ModelKind::AzureOpenai => AZURE,
        ModelKind::Vertex => VERTEX,
    }
}

fn segment_matches(pat: &str, seg: &str) -> bool {
    if seg.is_empty() {
        return false;
    }
    match pat {
        "*" => true,
        p if p.starts_with("*:") => {
            let verbs = &p[2..];
            seg.rsplit_once(':')
                .is_some_and(|(name, verb)| !name.is_empty() && verbs.split('|').any(|v| v == verb))
        }
        p => p == seg,
    }
}

fn path_matches(pat: &str, path: &str) -> bool {
    let (p, s): (Vec<&str>, Vec<&str>) = (pat.split('/').collect(), path.split('/').collect());
    p.len() == s.len()
        && p.iter().zip(&s).enumerate().all(|(i, (a, b))| {
            // the leading empty segment of an absolute path
            (i == 0 && a.is_empty() && b.is_empty()) || segment_matches(a, b)
        })
}

const QUERY_KEYS: &[&str] = &["alt", "api-version", "beta"];

fn query_ok(q: &str) -> bool {
    q.split('&').filter(|p| !p.is_empty()).all(|pair| {
        let (k, v) = pair.split_once('=').unwrap_or((pair, ""));
        QUERY_KEYS.contains(&k)
            && v.len() <= 32
            && v.bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"-_.".contains(&b))
    })
}

/// Whether the broker relays `method` on `path` (with its query) for a provider of `kind`, and what the endpoint is.
pub fn allowed(kind: ModelKind, method: &str, path: &str) -> Result<Kind, &'static str> {
    let (p, q) = path.split_once('?').unwrap_or((path, ""));
    if !query_ok(q) {
        return Err("that request's query is not one the broker relays");
    }
    rules(kind)
        .iter()
        .find(|r| r.method == method && path_matches(r.path, p))
        .map(|r| r.kind)
        .ok_or("the broker relays a model's answers and its model list only, not that endpoint")
}

#[cfg(test)]
mod tests {
    use super::*;
    use ModelKind::*;

    #[test]
    fn each_provider_reaches_its_inference_endpoints_and_its_model_list() {
        for (k, m, p) in [
            (Anthropic, "POST", "/v1/messages?beta=true"),
            (Anthropic, "POST", "/v1/messages/count_tokens"),
            (Anthropic, "GET", "/v1/models"),
            (Openai, "POST", "/v1/responses"),
            (Openai, "POST", "/v1/chat/completions"),
            (Openai, "GET", "/v1/models"),
            (Groq, "POST", "/v1/chat/completions"),
            (Together, "POST", "/v1/completions"),
            (Openrouter, "POST", "/v1/messages"),
            (Mistral, "POST", "/v1/fim/completions"),
            (OpenaiCompatible, "POST", "/chat/completions"),
            (OpenaiCompatible, "GET", "/v1/models"),
            (Google, "POST", "/v1beta/models/gemini-2.5-pro:streamGenerateContent?alt=sse"),
            (Google, "POST", "/v1beta/models/gemini-2.5-pro:countTokens"),
            (Bedrock, "POST", "/model/anthropic.claude-sonnet-4%3A0/invoke-with-response-stream"),
            (Bedrock, "POST", "/model/us.anthropic.claude-opus:0/converse"),
            (AzureOpenai, "POST", "/openai/deployments/gpt-4o/chat/completions?api-version=2024-10-21"),
            (AzureOpenai, "POST", "/openai/v1/responses"),
            (Vertex, "POST", "/v1/projects/p/locations/us-east5/publishers/anthropic/models/claude-sonnet-4:streamRawPredict"),
            (Vertex, "POST", "/projects/p/locations/global/publishers/anthropic/models/claude:rawPredict"),
            (Vertex, "POST", "/v1/projects/p/locations/us-central1/publishers/google/models/gemini:generateContent?alt=sse"),
            (Vertex, "GET", "/v1/publishers/google/models"),
        ] {
            assert!(allowed(k, m, p).is_ok(), "{k:?} {m} {p}");
        }
        assert_eq!(
            allowed(Anthropic, "POST", "/v1/messages"),
            Ok(Kind::Generation)
        );
        assert_eq!(allowed(Openai, "GET", "/v1/models"), Ok(Kind::Free));
    }

    /// The finding this closes: the run's token drove the cloud account, not only the model.
    #[test]
    fn everything_else_the_account_can_do_is_refused() {
        for (k, m, p) in [
            (
                Vertex,
                "POST",
                "/v1/projects/p/locations/us-central1/customJobs",
            ),
            (
                Vertex,
                "POST",
                "/v1/projects/p/locations/us-central1/endpoints/e:deployModel",
            ),
            (
                Vertex,
                "POST",
                "/v1/projects/p/locations/us-central1/publishers/google/models/gemini:undeploy",
            ),
            (
                Vertex,
                "GET",
                "/v1/projects/p/locations/us-central1/datasets",
            ),
            (
                Vertex,
                "POST",
                "/v1/projects/p/locations/us-central1/batchPredictionJobs",
            ),
            (AzureOpenai, "POST", "/openai/files"),
            (
                AzureOpenai,
                "POST",
                "/openai/fine_tuning/jobs?api-version=2024-10-21",
            ),
            (AzureOpenai, "POST", "/openai/v1/files"),
            (AzureOpenai, "POST", "/openai/assistants"),
            (
                AzureOpenai,
                "GET",
                "/openai/deployments/gpt-4o/chat/completions",
            ),
            (Bedrock, "POST", "/model/x/invoke/extra"),
            (Bedrock, "GET", "/model/x/invoke"),
            (Bedrock, "POST", "/async-invoke"),
            (Bedrock, "POST", "/guardrail/g/version/1/apply"),
            (Openai, "POST", "/v1/files"),
            (Openai, "POST", "/v1/fine_tuning/jobs"),
            (Openai, "POST", "/v1/batches"),
            (Openai, "GET", "/v1/organization/api_keys"),
            (Anthropic, "POST", "/v1/messages/batches"),
            (Anthropic, "POST", "/v1/files"),
            (Google, "POST", "/v1beta/tunedModels"),
            (
                Google,
                "POST",
                "/v1beta/models/gemini:streamGenerateContent/x",
            ),
            (Google, "POST", "/upload/v1beta/files"),
            (Mistral, "POST", "/v1/fine_tuning/jobs"),
            // an empty segment, an unknown verb, an empty model name
            (Openai, "POST", "/v1//chat/completions"),
            (Google, "POST", "/v1beta/models/:generateContent"),
            (Google, "POST", "/v1beta/models/gemini:deleteEverything"),
            // only the known query keys, with plain values
            (
                Anthropic,
                "POST",
                "/v1/messages?redirect=https://evil.example",
            ),
            (
                Google,
                "POST",
                "/v1beta/models/g:generateContent?alt=sse&key=x",
            ),
            (AzureOpenai, "POST", "/openai/v1/responses?api-version=a b"),
            // a method that is not GET or POST
            (Openai, "DELETE", "/v1/models/x"),
        ] {
            assert!(allowed(k, m, p).is_err(), "{k:?} {m} {p}");
        }
    }
}
