//! Receiving one webhook, start to finish: the same function serves the public route and the test button.

use std::collections::BTreeMap;

use serde_json::{json, Value};

use super::engine::{new_id, Fire};
use super::hooks::{self, RateLimiter, Refusal, Verified, GLOBAL_PER_MIN, PER_TRIGGER_PER_MIN};
use super::model::*;
use super::runner::RunRequest;
use super::store::Store;
use crate::secrets::SecretStore;

/// At most this many runs of one trigger may be open at once; more are refused (429), not queued.
pub const MAX_OPEN_PER_TRIGGER: usize = 5;

pub fn secret_name(trigger_id: &str) -> String {
    format!("trigger-secret-{trigger_id}")
}

/// Where the secret from before the last rotation is kept while it is still accepted.
pub fn previous_secret_name(trigger_id: &str) -> String {
    format!("trigger-secret-{trigger_id}-previous")
}

/// How long the old secret keeps working after a rotation: long enough to update the sender, short enough not to leave a
/// retired secret valid for good.
pub const SECRET_OVERLAP_MS: u64 = 24 * 3600 * 1000;

#[derive(Debug)]
pub struct Reply {
    pub status: u16,
    pub body: Value,
    /// The run to start, when the delivery was accepted.
    pub fire: Option<Fire>,
}

fn refuse(r: Refusal) -> Reply {
    // One message for every way in, so the endpoint says nothing about which triggers exist.
    Reply {
        status: r.status(),
        body: json!({ "code": r.code(), "message": crate::messages::t("hook.refused", &[]) }),
        fire: None,
    }
}

fn uniform_unknown() -> Reply {
    refuse(Refusal::Unknown)
}

struct Note<'a> {
    outcome: &'a str,
    reason: &'a str,
    verified: Option<&'a Verified>,
    size: usize,
    run: Option<&'a str>,
}

fn record(doc: &mut Doc, trigger: &str, now: u64, n: Note<'_>) {
    doc.deliveries.push(Delivery {
        id: new_id("dlv"),
        trigger_id: trigger.to_string(),
        ts_ms: now,
        outcome: n.outcome.into(),
        reason: n.reason.into(),
        delivery_id: n.verified.map(|v| v.delivery_id.clone()),
        event: n.verified.and_then(|v| v.event.clone()),
        size: n.size as u64,
        run_id: n.run.map(str::to_string),
    });
}

/// Handle `POST /hooks/<trigger id>`. `headers` are lower-cased. `test` runs the whole check but starts nothing.
#[allow(clippy::too_many_arguments)]
pub fn receive(
    store: &Store,
    secrets: &dyn SecretStore,
    limiter: &mut RateLimiter,
    trigger_id: &str,
    headers: &BTreeMap<String, String>,
    body: &[u8],
    now_ms: u64,
    test: bool,
) -> Reply {
    if !limiter.allow("*", GLOBAL_PER_MIN, now_ms) {
        return refuse(Refusal::RateLimited);
    }
    if !valid_id(trigger_id) {
        return uniform_unknown();
    }
    let doc = store.read();
    let Some(trigger) = doc.trigger(trigger_id).filter(|t| t.enabled).cloned() else {
        return uniform_unknown();
    };
    let log = |outcome: &str, reason: &str, v: Option<&Verified>, run: Option<&str>| {
        let _ = store.update(|d| {
            record(
                d,
                trigger_id,
                now_ms,
                Note {
                    outcome,
                    reason,
                    verified: v,
                    size: body.len(),
                    run,
                },
            );
            d.trim(now_ms);
        });
    };
    if !limiter.allow(trigger_id, PER_TRIGGER_PER_MIN, now_ms) {
        log("refused", Refusal::RateLimited.code(), None, None);
        return refuse(Refusal::RateLimited);
    }
    if body.len() > hooks::MAX_BODY {
        log("refused", Refusal::TooLarge.code(), None, None);
        return refuse(Refusal::TooLarge);
    }
    let secret = match secrets.get(&secret_name(trigger_id)) {
        Ok(Some(s)) => s,
        _ => {
            log("refused", "no_secret", None, None);
            return uniform_unknown();
        }
    };
    let mut checked = hooks::verify(trigger.scheme, &secret, headers, body, now_ms / 1000);
    if checked.is_err() && trigger.previous_secret_until_ms.is_some_and(|u| now_ms < u) {
        // within the overlap after a rotation, a request signed with the old secret is still accepted
        if let Ok(Some(old)) = secrets.get(&previous_secret_name(trigger_id)) {
            if let Ok(v) = hooks::verify(trigger.scheme, &old, headers, body, now_ms / 1000) {
                checked = Ok(v);
            }
        }
    }
    let verified = match checked {
        Ok(v) => v,
        Err(r) => {
            log("refused", r.code(), None, None);
            return refuse(r);
        }
    };
    if test {
        log("test", "", Some(&verified), None);
        let prompt = hooks::render(
            &trigger.template,
            verified.event.as_deref(),
            &verified.delivery_id,
            body,
            "test",
        );
        return Reply {
            status: 200,
            body: json!({ "ok": true, "verified": true, "scheme": trigger.scheme.id(), "prompt_preview": prompt }),
            fire: None,
        };
    }
    // The event filter runs after the signature, so an unsigned request learns nothing about which events are wanted.
    if trigger.scheme == Scheme::Github {
        let ev = verified.event.as_deref().unwrap_or("");
        let wanted = if trigger.events.is_empty() {
            ev != "ping"
        } else {
            trigger.events.iter().any(|e| e == ev)
        };
        if !wanted {
            log(
                "ignored",
                if ev == "ping" {
                    "ping"
                } else {
                    "event_not_listed"
                },
                Some(&verified),
                None,
            );
            return Reply {
                status: 200,
                body: json!({ "ok": true, "ignored": true }),
                fire: None,
            };
        }
    }
    let fence = ozbox_core::fence::random_fence();
    let prompt = hooks::render(
        &trigger.template,
        verified.event.as_deref(),
        &verified.delivery_id,
        body,
        &fence,
    );
    let run_id = new_id("run");
    let result = store.update(|d| {
        let key = format!("{trigger_id}:{}", verified.delivery_id);
        let size = body.len();
        if d.seen.contains_key(&key) {
            record(
                d,
                trigger_id,
                now_ms,
                Note {
                    outcome: "refused",
                    reason: Refusal::Replayed.code(),
                    verified: Some(&verified),
                    size,
                    run: None,
                },
            );
            return Err(Refusal::Replayed);
        }
        let open = d
            .runs
            .iter()
            .filter(|r| r.owner_id == trigger_id && r.status.is_open())
            .count();
        if open >= MAX_OPEN_PER_TRIGGER {
            record(
                d,
                trigger_id,
                now_ms,
                Note {
                    outcome: "refused",
                    reason: Refusal::Busy.code(),
                    verified: Some(&verified),
                    size,
                    run: None,
                },
            );
            return Err(Refusal::Busy);
        }
        d.seen.insert(key, now_ms);
        let mut r = RunRec {
            id: run_id.clone(),
            owner_id: trigger_id.to_string(),
            source: "trigger".into(),
            started_ms: now_ms,
            ..Default::default()
        };
        r.args
            .insert("delivery".into(), verified.delivery_id.clone());
        d.runs.push(r);
        record(
            d,
            trigger_id,
            now_ms,
            Note {
                outcome: "accepted",
                reason: "",
                verified: Some(&verified),
                size,
                run: Some(&run_id),
            },
        );
        d.trim(now_ms);
        Ok(())
    });
    match result {
        Ok(Ok(())) => Reply {
            status: 202,
            body: json!({ "ok": true, "run": run_id }),
            fire: Some(Fire {
                run_id: run_id.clone(),
                req: RunRequest {
                    run_id,
                    source: "trigger".into(),
                    owner_id: trigger_id.to_string(),
                    engine: trigger.engine.clone(),
                    prompt,
                    skill: trigger.skill.clone().filter(|s| !s.is_empty()),
                    box_name: String::new(),
                    caps: trigger.caps.clone(),
                    results_to: trigger.results_to.clone(),
                },
                target: trigger.target.clone(),
            }),
        },
        Ok(Err(r)) => refuse(r),
        Err(_) => Reply {
            status: 503,
            body: json!({ "code": "busy", "message": crate::messages::t("hook.store_busy", &[]) }),
            fire: None,
        },
    }
}

/// Headers and body for a correctly signed sample delivery, for the dashboard's test button.
pub fn signed_sample(
    t: &Trigger,
    secret: &str,
    now_secs: u64,
) -> (BTreeMap<String, String>, Vec<u8>) {
    let body = hooks::sample_body(t);
    let mut h = BTreeMap::new();
    let ts = now_secs.to_string();
    let mut msg = format!("{ts}.").into_bytes();
    msg.extend_from_slice(&body);
    match t.scheme {
        Scheme::Github => {
            h.insert(
                "x-hub-signature-256".into(),
                format!("sha256={}", hooks::sign(secret, &body)),
            );
            h.insert("x-github-delivery".into(), format!("test-{now_secs}"));
            h.insert("x-github-event".into(), "ping".into());
        }
        Scheme::Generic => {
            h.insert("x-ozbox-timestamp".into(), ts);
            h.insert(
                "x-ozbox-signature".into(),
                format!("v1={}", hooks::sign(secret, &msg)),
            );
            h.insert("x-ozbox-delivery".into(), format!("test-{now_secs}"));
        }
        Scheme::Stripe => {
            h.insert(
                "stripe-signature".into(),
                format!("t={ts},v1={}", hooks::sign(secret, &msg)),
            );
        }
    }
    (h, body)
}
