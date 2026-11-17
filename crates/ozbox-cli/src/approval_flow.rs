//! One approval flow for a gated change made from a computer (ADR 0041, amendment of 2026-11-17 for B4-27): the command
//! **files a request** on the box, says where to approve it, **waits**, and goes on by itself once the request is approved.
//! Nothing is copied between commands: no code is shown, pasted or typed.
//!
//! * The person approves on the dashboard (Approvals) with their passkey or authenticator code; a chat message or a push
//!   only says that a request is waiting (ADR 0041 §3.1).
//! * For a change a key kept on this computer may approve (never Production, ADR 0041 §3 and its amendment of 2026-11-17),
//!   the command offers to approve it here, after asking. Whether the key may is decided by the box, not by this file: this
//!   file only leaves out the offer where the box would refuse it anyway.
//! * Ctrl-C stops waiting and changes nothing; the request on the box expires by itself (30 minutes). A wait has a limit of
//!   its own (`--wait`), and running out of it changes nothing either.
//!
//! The `call` a caller hands in is one request line to the box's secrets service over the sealed route; this file never sees
//! a value, and the subject it files holds names and salted digests only.

use std::sync::atomic::AtomicBool;

use ozbox_core::approval_subject::{
    import_value_digest, is_production_environment, Classification, Import, ImportName, Subject,
};
use serde_json::{json, Value};

use crate::approval_wait::{wait_quietly, Waited};
use crate::messages::t;
use crate::run::CliError;

/// The longest a command waits, in minutes: a request's own pending life.
pub const MAX_WAIT_MINUTES: u64 = 30;

/// What this computer's key did when it was offered the request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Inline {
    /// The person said no, or did not answer yes: the dashboard decides.
    Declined,
    /// The key approved it.
    Approved,
    /// The box refused the key's decision; the sentence says why. The dashboard can still approve it.
    Refused(String),
}

/// An approved request, ready to be spent by the change it was filed for.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Approved {
    pub id: String,
    pub digest: String,
}

/// The offer to approve with this computer's key: given the request id and its digest, what the key did.
pub type InlineFn<'a> = &'a mut dyn FnMut(&str, &str) -> Inline;

/// Everything the flow needs from its caller. Each part is a function so the flow is tested in process, against the real
/// service, without a network.
pub struct Flow<'a> {
    /// One request line to the box's secrets service (sealed route); returns the service's `result`, or the refusal.
    pub call: &'a mut dyn FnMut(&Value) -> Result<Value, String>,
    /// A line for the person (standard error in the command).
    pub say: &'a mut dyn FnMut(&str),
    /// The offer to approve with this computer's key, given the request id and its digest; `None` when this computer holds
    /// no key or nobody is at a terminal to say yes.
    pub inline: Option<InlineFn<'a>>,
    pub elapsed_ms: &'a dyn Fn() -> u64,
    pub stop: &'a AtomicBool,
    /// How long to wait, in milliseconds (at most a request's pending life).
    pub max_wait_ms: u64,
}

/// A fresh per-import salt (16 random bytes, hex): the digest of each value is bound by it, so a digest on a card says
/// nothing about the value to anyone who does not hold the value.
pub fn new_salt() -> Result<String, CliError> {
    let mut b = [0u8; 16];
    getrandom::getrandom(&mut b).map_err(|_| CliError::Msg(t("ingress.no_random", &[])))?;
    Ok(ozbox_core::approval_subject::to_hex(&b))
}

/// The subject of an import request for exactly these rows: every name, as a secret, with its value's digest under `salt`,
/// in name order, and Production as the box's own rule says for this environment. It is what the box recomputes when the
/// import is spent, so a value changed after the approval is refused. A Production-looking value in a non-Production
/// environment is refused here, before anything is filed (the box would refuse to spend it).
pub fn import_subject(
    project: &str,
    env: &str,
    rows: &[(&str, &str)],
    salt: &str,
) -> Result<Subject, CliError> {
    let mut names: Vec<ImportName> = rows
        .iter()
        .map(|(name, value)| ImportName {
            name: (*name).to_string(),
            classification: Classification::Secret,
            value_digest: import_value_digest(salt, value),
        })
        .collect();
    names.sort();
    let subject = Subject::Import(Import {
        project: project.to_string(),
        environment: env.to_string(),
        production: is_production_environment(env),
        names,
        // the box binds the generation it holds itself; the filer's number is never used
        store_generation: 0,
    });
    subject
        .check_import_values(rows.iter().copied())
        .map_err(|_| {
            let name = rows
                .iter()
                .find(|(_, v)| ozbox_core::approval_subject::value_says_production(v))
                .map_or("", |(n, _)| *n);
            CliError::Msg(t(
                "approval.flow_prod_value",
                &[("name", name), ("env", env)],
            ))
        })?;
    Ok(subject)
}

/// Whether a refusal from the box means "this needs an approval": the words the box has always used, so an older box is
/// recognised too.
pub fn needs_approval(refusal: &str) -> bool {
    refusal.contains("this change needs a fresh approval")
        || refusal.contains("this box takes approvals as requests")
}

/// Whether the box keeps approval requests for `scope` (`areq_capabilities`).
pub fn box_files(call: &mut dyn FnMut(&Value) -> Result<Value, String>, scope: &str) -> bool {
    call(&json!({"op": "areq_capabilities"})).is_ok_and(|r| {
        r["request_ops"] == json!(true)
            && r["scopes"]
                .as_array()
                .is_some_and(|s| s.iter().any(|x| x.as_str() == Some(scope)))
    })
}

/// File a request for `subject`, say where to approve it, offer this computer's key where it may decide, wait, and return
/// the approved request. `what` names the change in the person's words ("the import of 3 keys into app/staging").
pub fn file_and_wait(
    flow: &mut Flow<'_>,
    subject: &Subject,
    what: &str,
) -> Result<Approved, CliError> {
    let production = subject.production();
    let filed = (flow.call)(&json!({"op": "areq_file", "subject": subject}))
        .map_err(|e| CliError::Msg(t("approval.flow_not_filed", &[("why", &e)])))?;
    let r = &filed["request"];
    let (Some(id), Some(digest)) = (r["id"].as_str(), r["subject_digest"].as_str()) else {
        return Err(CliError::Msg(t("approval.flow_bad_answer", &[])));
    };
    let (id, digest) = (id.to_string(), digest.to_string());
    let minutes = (flow.max_wait_ms / 60_000).max(1).to_string();
    (flow.say)(&t(
        if production {
            "approval.flow_waiting_production"
        } else {
            "approval.flow_waiting"
        },
        &[("what", what), ("id", &id), ("minutes", &minutes)],
    ));
    // a software key never decides Production: the offer is left out, and the line above already says the dashboard decides
    if !production {
        if let Some(inline) = flow.inline.as_mut() {
            match inline(&id, &digest) {
                Inline::Approved | Inline::Declined => {}
                Inline::Refused(why) => {
                    (flow.say)(&t("approval.flow_inline_refused", &[("why", &why)]))
                }
            }
        }
    }
    let call = &mut *flow.call;
    let mut result_of = |v: &Value| call(v);
    match wait_quietly(
        &mut result_of,
        &id,
        flow.max_wait_ms,
        flow.elapsed_ms,
        flow.stop,
    ) {
        Waited::Approved { digest: got } if got.eq_ignore_ascii_case(&digest) => {
            (flow.say)(&t("approval.flow_approved", &[("id", &id)]));
            Ok(Approved { id, digest })
        }
        // the box approved something else under this id: nothing is spent on a digest this computer did not file
        Waited::Approved { .. } => Err(CliError::Msg(t("approval.flow_bad_answer", &[]))),
        Waited::Refused(why) => Err(CliError::Msg(t(
            "approval.flow_refused",
            &[("what", what), ("why", &why)],
        ))),
        Waited::Stopped => Err(CliError::Msg(t("approval.flow_stopped", &[]))),
        Waited::TimedOut => Err(CliError::Msg(t(
            "approval.flow_timed_out",
            &[("minutes", &minutes)],
        ))),
        Waited::GaveUp(why) => Err(CliError::Msg(t("approval.flow_gave_up", &[("why", &why)]))),
    }
}

/// Ask the person at the terminal whether to approve with this computer's key. Anything but `y` or `yes` is a no.
pub fn ask_inline(input: &mut dyn std::io::BufRead, key: &str) -> bool {
    eprint!("{}", t("approval.flow_inline_ask", &[("key", key)]));
    let mut line = String::new();
    if input.read_line(&mut line).is_err() {
        return false;
    }
    matches!(line.trim().to_ascii_lowercase().as_str(), "y" | "yes")
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
#[path = "approval_flow_tests.rs"]
mod tests;
