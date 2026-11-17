//! `ozbox secrets ingress requests`: the laptop side of the approval requests (ADR 0041 phase 2), over the sealed route.
//!
//! * `list` and `show` read the requests of a box. `show` prints the card the service derived (every field with where its
//!   words came from) and the **full** subject digest, never a prefix.
//! * `approve <id> --digest <64 hex>` and `deny <id>` decide. The digest must be the whole 64 digits and must equal the
//!   request's own: a prefix can be ground by someone who chooses an import's salt, so a short one is refused, and a request
//!   that changed since the person looked is not approved by a digest read earlier.
//! * Every decision is a signature over the message the service built for this request and outcome
//!   (`ozbox-approval-decide`, the challenge naming the request, the digest, the outcome, the box and the store), made by this
//!   computer's key and sent sealed. Nothing here carries a code and nothing goes through the box user's shell.
//! * A key kept in this computer's keychain is a **software key**: it decides only what a member may decide
//!   (`guard-override`, and new names in a non-Production import), never an owner-only scope and never Production
//!   (ADR 0041 §3). A hardware key through ssh-agent is not built in this version.

use ozbox_core::approval_subject::DECIDE_MESSAGE_HEAD;
use ozbox_core::{BoxName, CommandRunner, SystemRunner};
use serde_json::{json, Value};

use crate::approval_key as ak;
use crate::cli::RequestsAction;
use crate::ingress_client::call;
use crate::run::CliError;
use crate::secrets::SecretStore;

fn say(json: bool, v: &Value, text: String) {
    if json {
        println!("{v}");
    } else {
        println!("{text}");
    }
}

/// A request as one screen of text: the scope, who asked as the service sent it, each derived field with its source, the
/// reason quoted and labelled as the box's own word, the time left and the whole digest.
pub fn card_text(r: &Value, now_ms: u64) -> String {
    use ozbox_core::approval_subject::sanitize_display;
    let s = |v: &Value, max| sanitize_display(v.as_str().unwrap_or("-"), max);
    let mut out = String::new();
    out.push_str(&format!(
        "{}  [{}]  request {}\n",
        s(&r["scope"], 40),
        s(&r["state"], 20),
        s(&r["id"], 40)
    ));
    let q = &r["requester"];
    out.push_str(&format!(
        "  asked by: {}{}{}\n",
        s(&q["kind"], 20),
        q["uid"]
            .as_u64()
            .map_or(String::new(), |u| format!(" uid {u}")),
        q["claimed"].as_str().map_or(String::new(), |c| format!(
            " (it says: {})",
            sanitize_display(c, 64)
        ))
    ));
    for f in r["display"].as_array().into_iter().flatten() {
        out.push_str(&format!(
            "  {}: {}   ({})\n",
            s(&f["label"], 40),
            s(&f["value"], 200),
            s(&f["source"], 20)
        ));
    }
    if let Some(reason) = r["reason"].as_str() {
        out.push_str(&format!(
            "  reason (from the box, not verified): \"{}\"\n",
            sanitize_display(reason, 200)
        ));
    }
    if let Some(at) = r["expires_at_ms"].as_u64() {
        let left = at.saturating_sub(now_ms) / 1000;
        out.push_str(&format!("  time left: {}:{:02}\n", left / 60, left % 60));
    }
    out.push_str(&format!("  digest: {}\n", s(&r["subject_digest"], 64)));
    out
}

fn get(runner: &dyn CommandRunner, on_box: &BoxName, id: &str) -> Result<Value, CliError> {
    let v = call(
        runner,
        on_box.as_str(),
        &json!({"op": "areq_get", "id": id}),
    )?;
    Ok(v["result"]["request"].clone())
}

/// The box and store ids this computer pinned the first time it saw the box, checked against what the box says now. A decision's
/// challenge is recomputed from them, so the laptop signs what it worked out and not an opaque value the box handed it.
/// A box whose ids changed (its store was replaced, or it is another box) is refused until the pin is
/// replaced on purpose.
pub(crate) fn pinned_ids(
    runner: &dyn CommandRunner,
    on_box: &BoxName,
) -> Result<ozbox_core::approval_subject::Ids, CliError> {
    let caps = call(runner, on_box.as_str(), &json!({"op": "areq_capabilities"}))?;
    let (b, s) = (
        caps["result"]["ids"]["box_id"]
            .as_str()
            .unwrap_or("")
            .to_string(),
        caps["result"]["ids"]["store_id"]
            .as_str()
            .unwrap_or("")
            .to_string(),
    );
    let ids = ozbox_core::approval_subject::Ids {
        box_id: b,
        store_id: s,
    };
    ids.validate().map_err(|_| {
        CliError::Msg("the box does not keep approval requests (or answered badly)".into())
    })?;
    let pins = crate::ingress_client::FilePins(crate::ingress_client::FilePins::default_path());
    match pins.ids_get(on_box.as_str()) {
        Some((pb, ps)) if pb == ids.box_id && ps == ids.store_id => Ok(ids),
        Some(_) => Err(CliError::Msg(
            "this box's approval identity is not the one this computer first saw (its store was replaced, or this is another box): nothing was signed. If you replaced it on purpose, run `ozbox secrets ingress pin --replace` for this box".into(),
        )),
        None => {
            pins.ids_put(on_box.as_str(), &ids.box_id, &ids.store_id).map_err(CliError::Msg)?;
            Ok(ids)
        }
    }
}

/// Check that the challenge the box offered is the one this computer works out for this request, digest and outcome.
pub fn check_challenge(
    ids: &ozbox_core::approval_subject::Ids,
    id: &str,
    digest_hex: &str,
    outcome: &str,
    offered: &str,
) -> Result<(), CliError> {
    use ozbox_core::approval_subject::{decide_challenge, from_hex, to_hex};
    let d: [u8; 32] = from_hex(digest_hex)
        .and_then(|b| b.try_into().ok())
        .ok_or_else(|| CliError::Msg("the box answered badly".into()))?;
    if !to_hex(&decide_challenge(ids, id, &d, outcome)).eq_ignore_ascii_case(offered) {
        return Err(CliError::Msg(
            "the box offered a challenge that is not for this request, digest and decision: nothing was signed".into(),
        ));
    }
    Ok(())
}

/// Decide `id` with the software key `key_id` kept in `keys`. `digest` is the full digest the person read; `None` is only
/// for a deny, which needs nothing to be read.
#[allow(clippy::too_many_arguments)]
pub fn decide(
    runner: &dyn CommandRunner,
    keys: &dyn SecretStore,
    ids: &ozbox_core::approval_subject::Ids,
    on_box: &BoxName,
    id: &str,
    approve: bool,
    digest: Option<&str>,
    key_id: &str,
) -> Result<Value, CliError> {
    if !ak::id_ok(key_id) {
        return Err(CliError::Msg("that key name is not valid".into()));
    }
    let r = get(runner, on_box, id)?;
    let have = r["subject_digest"].as_str().unwrap_or("");
    if approve {
        let d = digest.unwrap_or("");
        if d.len() != 64 || !d.bytes().all(|b| b.is_ascii_hexdigit()) {
            return Err(CliError::Msg(
                "approve needs the whole digest (64 hex digits, as `show` prints it): a prefix can be forged".into(),
            ));
        }
        if !d.eq_ignore_ascii_case(have) {
            return Err(CliError::Msg(
                "that digest is not this request's: it changed since you read it, or it is another request. Show it again.".into(),
            ));
        }
    }
    let state = r["state"].as_str().unwrap_or("");
    // a deny of an approved, unspent request is a revoke, signed as one
    let outcome = match (approve, state) {
        (true, "pending") => "approve",
        (false, "pending") => "deny",
        (false, "approved") => "revoke",
        _ => return Err(CliError::Msg(format!("the request is {state}"))),
    };
    let ch = call(
        runner,
        on_box.as_str(),
        &json!({"op": "areq_decide_challenge", "id": id, "outcome": outcome}),
    )?;
    let challenge = ch["result"]["challenge"].as_str().unwrap_or("");
    if ch["result"]["subject_digest"].as_str() != Some(have) || challenge.len() != 64 {
        return Err(CliError::Msg("the box answered badly".into()));
    }
    check_challenge(ids, id, have, outcome, challenge)?;
    let seed = keys
        .get(&format!("{}{key_id}", ak::KEYCHAIN_PREFIX))
        .map_err(|e| CliError::Msg(e.0))?
        .map(zeroize::Zeroizing::new)
        .ok_or_else(|| {
            CliError::Msg(format!(
                "this computer holds no approval key named {key_id}"
            ))
        })?;
    let message = format!("{DECIDE_MESSAGE_HEAD}\n{challenge}");
    let signature = ak::sign(&seed, &message).map_err(CliError::Msg)?;
    let done = call(
        runner,
        on_box.as_str(),
        &json!({
            "op": "areq_decide", "id": id, "outcome": outcome, "key_id": key_id,
            "evidence": {"laptop": {
                "key_id": key_id, "key_type": "ed25519", "signature_format": "ed25519-message",
                "signed_message": ozbox_core::audit::hex(message.as_bytes()), "signature": signature,
            }},
        }),
    )?;
    Ok(done["result"]["request"].clone())
}

pub fn run(on_box: &BoxName, action: &RequestsAction, json: bool) -> Result<(), CliError> {
    let runner = SystemRunner;
    let keys = crate::approval_key_cli::keychain();
    let now = crate::tokenmac::now_ms();
    match action {
        RequestsAction::List => {
            let v = call(&runner, on_box.as_str(), &json!({"op": "areq_list"}))?;
            let list = v["result"]["requests"]
                .as_array()
                .cloned()
                .unwrap_or_default();
            if json {
                println!("{}", json!({"requests": list}));
            } else if list.is_empty() {
                println!("No requests on {}.", on_box.as_str());
            } else {
                for r in &list {
                    println!("{}", card_text(r, now));
                }
            }
            Ok(())
        }
        RequestsAction::Show { id } => {
            let r = get(&runner, on_box, id)?;
            say(json, &json!({"request": r}), card_text(&r, now));
            Ok(())
        }
        RequestsAction::Approve { id, digest, key } => {
            let ids = pinned_ids(&runner, on_box)?;
            let r = decide(
                &runner,
                keys.as_ref(),
                &ids,
                on_box,
                id,
                true,
                Some(digest),
                key,
            )?;
            say(
                json,
                &json!({"request": r}),
                format!("Approved request {id}. The waiting operation goes ahead on its own."),
            );
            Ok(())
        }
        RequestsAction::Deny { id, key } => {
            let ids = pinned_ids(&runner, on_box)?;
            let r = decide(&runner, keys.as_ref(), &ids, on_box, id, false, None, key)?;
            say(
                json,
                &json!({"request": r}),
                format!("Denied request {id}."),
            );
            Ok(())
        }
        RequestsAction::Keys => {
            let v = call(&runner, on_box.as_str(), &json!({"op": "approval_keys"}))?;
            let info = v["result"]["info"].as_array().cloned().unwrap_or_default();
            if json {
                println!("{}", json!({"keys": info}));
            } else if info.is_empty() {
                println!("No laptop keys are enrolled on {}.", on_box.as_str());
            } else {
                for k in &info {
                    println!(
                        "{}  {}  {}  enrolled via {}",
                        k["id"].as_str().unwrap_or("-"),
                        k["key_type"].as_str().unwrap_or("-"),
                        if k["presence"] == "proved" {
                            "with presence"
                        } else {
                            "software key (no presence)"
                        },
                        k["enrolled_via"].as_str().unwrap_or("unknown"),
                    );
                }
            }
            Ok(())
        }
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use ozbox_core::approval_subject::Ids;

    fn ids() -> Ids {
        Ids {
            box_id: "box-1".into(),
            store_id: "store-1".into(),
        }
    }

    fn golden() -> serde_json::Value {
        serde_json::from_str(include_str!(
            "../../ozbox-core/testdata/approval_subject_golden.json"
        ))
        .unwrap()
    }

    /// The laptop's own computation reproduces the frozen vectors the service is held to, so the two cannot drift apart.
    #[test]
    fn the_laptops_challenge_is_the_one_the_golden_file_freezes() {
        let g = golden();
        let mut n = 0;
        for c in g["challenges"]
            .as_array()
            .unwrap()
            .iter()
            .filter(|c| c["kind"] == "decide")
        {
            let (rid, d, o, want) = (
                c["request_id"].as_str().unwrap(),
                c["digest_hex"].as_str().unwrap(),
                c["outcome"].as_str().unwrap(),
                c["expect"].as_str().unwrap(),
            );
            check_challenge(&ids(), rid, d, o, want).unwrap();
            n += 1;
        }
        assert!(n >= 3, "approve, deny and revoke vectors");
    }

    #[test]
    fn a_challenge_for_another_request_digest_outcome_or_box_is_not_signed() {
        let g = golden();
        let c = g["challenges"]
            .as_array()
            .unwrap()
            .iter()
            .find(|c| c["kind"] == "decide" && c["outcome"] == "approve")
            .unwrap();
        let (rid, d, want) = (
            c["request_id"].as_str().unwrap(),
            c["digest_hex"].as_str().unwrap(),
            c["expect"].as_str().unwrap(),
        );
        assert!(check_challenge(&ids(), rid, d, "approve", want).is_ok());
        // the same offered value, asked about another outcome, request, digest or box
        assert!(check_challenge(&ids(), rid, d, "deny", want).is_err());
        assert!(check_challenge(&ids(), "OTHER", d, "approve", want).is_err());
        assert!(check_challenge(&ids(), rid, &"08".repeat(32), "approve", want).is_err());
        let other_box = Ids {
            box_id: "box-2".into(),
            store_id: "store-1".into(),
        };
        assert!(check_challenge(&other_box, rid, d, "approve", want).is_err());
        assert!(check_challenge(&ids(), rid, "short", "approve", want).is_err());
    }
}
