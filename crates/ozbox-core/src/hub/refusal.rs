//! Decision D2: a worker is never given Production. Hard-coded, not a setting.
//!
//! ADR 0042 designs "Production to a worker" (ADR 0029's per-use release, sealed to the worker's attested key, verified by the
//! issuer, decided with a laptop presence key) and **refuses it in this release**. The refusal lives in code, in three places that
//! each stand alone: here (the hub, before it assigns; and the worker, before it accepts), and in `ozbox-issuer` (before it makes
//! a challenge or releases). Turning it on later is a code change with its own review (phase H3b), never a flag, an environment
//! variable, a rules-file line or a message from `main`.
//!
//! "Production" is read the fail-safe way, with the helpers the approval rules already use: an environment is Production unless
//! it is one of the few known not to be ([`is_production_environment`]), and a key whose name says production or live is
//! Production whatever environment it is filed under ([`name_says_production`]).

use serde::{Deserialize, Serialize};

use crate::approval_subject::{
    is_production_environment, name_says_production, NON_PRODUCTION_ENVS,
};

/// The most names one declaration lists, and the longest one.
pub const MAX_NAMES: usize = 64;
const MAX_NAME_LEN: usize = 128;

/// What a task asks the worker's keys to be: names in one environment. Never a value.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct KeyDeclaration {
    pub env: String,
    pub names: Vec<String>,
}

/// Why a declaration was refused, in a form that is also the audit record.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Refusal {
    pub code: &'static str,
    pub message: String,
}

/// The one audit word for any refusal under this module.
pub const AUDIT_REFUSED: &str = "hub.keys.refused";

impl Refusal {
    fn new(code: &'static str, message: impl Into<String>) -> Self {
        Refusal {
            code,
            message: message.into(),
        }
    }

    /// The audit line: who it was for and why. Names only, never a value.
    pub fn audit_detail(&self, worker: &str, task: &str) -> String {
        format!("worker={worker} task={task} code={}", self.code)
    }
}

impl std::fmt::Display for Refusal {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.message)
    }
}

pub const CODE_PRODUCTION: &str = "production-to-worker-refused";
pub const CODE_INVALID: &str = "declaration-invalid";

/// Refuse Production. Takes the declaration and nothing else: there is no second argument that relaxes it.
pub fn refuse_production(d: &KeyDeclaration) -> Result<(), Refusal> {
    if d.names.is_empty() && d.env.is_empty() {
        return Ok(());
    }
    if d.names.len() > MAX_NAMES {
        return Err(Refusal::new(
            CODE_INVALID,
            "a declaration lists too many names",
        ));
    }
    if d.env.is_empty() || is_production_environment(&d.env) {
        return Err(Refusal::new(
            CODE_PRODUCTION,
            format!(
                "A worker box is never given Production in this release. The environment must be one of {}. \
                 Use a laptop-approved Production step on `main` instead.",
                NON_PRODUCTION_ENVS.join(", ")
            ),
        ));
    }
    for n in &d.names {
        if n.is_empty() || n.len() > MAX_NAME_LEN || !n.bytes().all(|b| b.is_ascii_graphic()) {
            return Err(Refusal::new(
                CODE_INVALID,
                "a key name is empty, too long or has characters that are not allowed",
            ));
        }
        if name_says_production(n) {
            return Err(Refusal::new(
                CODE_PRODUCTION,
                "A worker box is never given a key whose name says production or live in this release.",
            ));
        }
    }
    Ok(())
}
