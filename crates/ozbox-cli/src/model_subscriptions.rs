//! Subscription sign-ins: whether each agent engine can run on a person's own subscription (a chat plan or a coding
//! plan) instead of an API key, and why not where it cannot (ADR 0054).
//!
//! This is a catalogue, not a credential path: the one engine whose sign-in can be handed to its runs, on the owner's
//! opt-in, is in `subscription_signin` (ADR 0055), and its row says `opt_in`. No row says `available` (the sign-in held
//! by the service and reached only through a per-run token, ADR 0054 rule 4), because no vendor documents that today; a
//! test holds both. Each row names the vendor pages its
//! status rests on, so the dashboard can link them and never imply that a use is allowed when the vendor's terms forbid
//! it or do not address it. The pages were read on [`CHECKED_ON`]; terms change, so re-read them before building an
//! adapter.

use serde::Serialize;

use crate::model_engines;

/// When the vendor pages below were last read.
pub const CHECKED_ON: &str = "2026-11-17";

/// What Oz Box can do with one engine's subscription sign-in.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Status {
    /// A sign-in adapter is built and the vendor documents remote use. None is, today, so nothing constructs it yet; it is
    /// part of the answer's contract so a client handles it before the first adapter ships.
    #[allow(dead_code)]
    Available,
    /// The engine must read the sign-in itself, so it is handed to that engine's runs only after the owner turns it on, with
    /// a warning, and an agent in such a run can read it (ADR 0055).
    OptIn,
    /// The vendor documents something close, but an adapter, or a rule in ADR 0054, is still missing.
    Planned,
    /// The vendor's terms forbid it, or the engine has no subscription to sign in with.
    NotOffered,
}

/// How the vendor documents signing in on a machine without a browser.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SignIn {
    /// A device code: the person opens the vendor's page anywhere and types a short code there.
    DeviceCode,
    /// A browser on the same machine (or a code pasted back into the engine's own terminal).
    BrowserOnly,
    /// Nothing documented.
    NotDocumented,
    /// There is no subscription sign-in at all.
    None,
}

/// One engine and one subscription. Every text the dashboard shows is a message id it looks up (`reason`, `id`).
#[derive(Debug, Clone, Serialize)]
pub struct Subscription {
    pub id: &'static str,
    /// The agent engine (an id from `model_engines::ENGINES`).
    pub engine: &'static str,
    pub status: Status,
    pub sign_in: SignIn,
    /// Why, as a stable code.
    pub reason: &'static str,
    /// The vendor's own pages the status rests on (documentation and terms), https only.
    pub sources: &'static [&'static str],
}

const ANTHROPIC_TERMS: &str = "https://code.claude.com/docs/en/legal-and-compliance";
const ANTHROPIC_AUTH: &str = "https://code.claude.com/docs/en/authentication";
const CODEX_AUTH: &str = "https://learn.chatgpt.com/docs/auth";
const CODEX_CI: &str = "https://learn.chatgpt.com/docs/auth/ci-cd-auth";
const GEMINI_AUTH: &str = "https://geminicli.com/docs/get-started/authentication/";
const GEMINI_TERMS: &str = "https://geminicli.com/docs/resources/tos-privacy/";
const OPENCODE_PROVIDERS: &str = "https://opencode.ai/docs/providers/";
const COPILOT_OPENCODE: &str =
    "https://github.blog/changelog/2026-01-16-github-copilot-now-supports-opencode/";
const AIDER_COPILOT: &str = "https://aider.chat/docs/llms/github.html";

/// Every engine's subscription sign-ins, as of [`CHECKED_ON`].
pub const SUBSCRIPTIONS: &[Subscription] = &[
    Subscription {
        id: "claude-code-claude",
        engine: "claude-code",
        status: Status::NotOffered,
        sign_in: SignIn::BrowserOnly,
        reason: "terms_forbid_storing",
        sources: &[ANTHROPIC_TERMS, ANTHROPIC_AUTH],
    },
    Subscription {
        id: "codex-chatgpt",
        engine: "codex",
        status: Status::OptIn,
        sign_in: SignIn::DeviceCode,
        reason: "opt_in_engine_reads_login",
        sources: &[CODEX_AUTH, CODEX_CI],
    },
    Subscription {
        id: "gemini-cli-google",
        engine: "gemini-cli",
        status: Status::Planned,
        sign_in: SignIn::BrowserOnly,
        reason: "no_remote_sign_in",
        sources: &[GEMINI_AUTH, GEMINI_TERMS],
    },
    Subscription {
        id: "opencode-claude",
        engine: "opencode",
        status: Status::NotOffered,
        sign_in: SignIn::NotDocumented,
        reason: "terms_forbid_other_tools",
        sources: &[ANTHROPIC_TERMS, OPENCODE_PROVIDERS],
    },
    Subscription {
        id: "opencode-chatgpt",
        engine: "opencode",
        status: Status::Planned,
        sign_in: SignIn::NotDocumented,
        reason: "login_location_not_documented",
        sources: &[OPENCODE_PROVIDERS, CODEX_AUTH],
    },
    Subscription {
        id: "opencode-copilot",
        engine: "opencode",
        status: Status::Planned,
        sign_in: SignIn::DeviceCode,
        reason: "login_location_not_documented",
        sources: &[OPENCODE_PROVIDERS, COPILOT_OPENCODE],
    },
    Subscription {
        id: "opencode-google",
        engine: "opencode",
        status: Status::NotOffered,
        sign_in: SignIn::NotDocumented,
        reason: "terms_forbid_other_tools",
        sources: &[GEMINI_TERMS],
    },
    Subscription {
        id: "aider-none",
        engine: "aider",
        status: Status::NotOffered,
        sign_in: SignIn::None,
        reason: "no_subscription",
        sources: &[AIDER_COPILOT],
    },
];

/// The reason codes. The dashboard's message catalogue has one message per code (`models.sub_reason_<code>`).
#[cfg(test)]
const REASONS: &[&str] = &[
    "terms_forbid_storing",
    "opt_in_engine_reads_login",
    "no_remote_sign_in",
    "terms_forbid_other_tools",
    "login_location_not_documented",
    "no_subscription",
];

/// One row of `GET /v1/models/catalog`'s `subscriptions`.
#[derive(Debug, Serialize)]
pub struct Row {
    pub id: &'static str,
    pub engine: &'static str,
    pub engine_label: &'static str,
    /// Always `subscription`: the provider kind this row would become once it can be added.
    pub kind: &'static str,
    pub status: Status,
    pub sign_in: SignIn,
    pub reason: &'static str,
    pub sources: &'static [&'static str],
    pub checked_on: &'static str,
    /// Whether this row has an opt-in in Settings, Models (ADR 0055). Added in 0.3.0; an older server leaves it out.
    pub opt_in: bool,
}

pub fn rows() -> Vec<Row> {
    SUBSCRIPTIONS
        .iter()
        .map(|s| Row {
            id: s.id,
            engine: s.engine,
            engine_label: model_engines::info(s.engine).map_or(s.engine, |e| e.label),
            kind: "subscription",
            status: s.status,
            sign_in: s.sign_in,
            reason: s.reason,
            sources: s.sources,
            checked_on: CHECKED_ON,
            opt_in: crate::subscription_signin::adapter(s.id).is_some(),
        })
        .collect()
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn nothing_claims_to_be_available_and_only_a_built_adapter_says_opt_in() {
        // ADR 0054: `available` needs the sign-in held by the service and reached by a per-run token, which no vendor
        // documents. ADR 0055: `opt_in` needs a built adapter, and a row has an opt-in exactly when it says so.
        assert!(SUBSCRIPTIONS.iter().all(|s| s.status != Status::Available));
        for r in rows() {
            assert_eq!(r.opt_in, r.status == Status::OptIn, "{}", r.id);
        }
        assert_eq!(
            rows()
                .iter()
                .filter(|r| r.opt_in)
                .map(|r| r.id)
                .collect::<Vec<_>>(),
            vec!["codex-chatgpt"]
        );
    }

    #[test]
    fn every_engine_has_a_row_and_every_row_names_a_known_engine_and_a_vendor_source() {
        for e in model_engines::ENGINES {
            assert!(
                SUBSCRIPTIONS.iter().any(|s| s.engine == e.id),
                "{} has no subscription row",
                e.id
            );
        }
        let mut ids = std::collections::BTreeSet::new();
        for s in SUBSCRIPTIONS {
            assert!(model_engines::known(s.engine), "{}", s.id);
            assert!(ids.insert(s.id), "{} twice", s.id);
            assert!(REASONS.contains(&s.reason), "{}: {}", s.id, s.reason);
            assert!(!s.sources.is_empty(), "{} cites nothing", s.id);
            assert!(s.sources.iter().all(|u| u.starts_with("https://")));
        }
    }

    #[test]
    fn a_vendor_whose_terms_forbid_a_tool_holding_its_login_is_never_planned() {
        // Anthropic forbids a third party collecting, storing or intermediating subscription credentials; Google forbids
        // other software reaching the service behind Gemini CLI. Those rows must stay "not offered", never "planned".
        for id in ["claude-code-claude", "opencode-claude", "opencode-google"] {
            let s = SUBSCRIPTIONS.iter().find(|s| s.id == id).unwrap();
            assert_eq!(s.status, Status::NotOffered, "{id}");
        }
    }

    #[test]
    fn the_rows_carry_no_credential_field_only_ids_codes_and_links() {
        let v = serde_json::to_value(rows()).unwrap();
        let keys: std::collections::BTreeSet<String> = v
            .as_array()
            .unwrap()
            .iter()
            .flat_map(|r| r.as_object().unwrap().keys().cloned())
            .collect();
        let want = [
            "checked_on",
            "engine",
            "engine_label",
            "id",
            "kind",
            "opt_in",
            "reason",
            "sign_in",
            "sources",
            "status",
        ];
        assert_eq!(keys, want.iter().map(|s| s.to_string()).collect());
        assert_eq!(v[0]["kind"], "subscription");
        assert_eq!(v[0]["engine_label"], "Claude Code");
    }
}
