//! The waiting hook (ADR 0041 §6): what a blocked operation does after its gate refused.
//!
//! The operation files a request (`areq_file`), prints one line saying where to decide it, and waits on the request id with a
//! long poll: each call is held by the service for at most a few seconds inside the client's read timeout, and this loop calls
//! again, so nothing spins. When the request is approved the service answers with the request's `subject_digest`; the
//! operation **recomputes its own** and spends the approval (`areq_spend`), which is refused if the subject changed. Nothing a
//! person sees, copies or types is a bearer value: what comes back is a digest and a state.
//!
//! The wait is bounded by the request's own life (30 minutes pending) and by [`MAX_WAIT_MS`] here, and a Ctrl-C (the `stop`
//! flag) leaves the request standing for its 30 minutes, as the line says.

use std::sync::atomic::{AtomicBool, Ordering};

use serde_json::{json, Value};

/// How long one `areq_await` is asked to hold (the service caps it at 60 s; the box socket client reads for 20 s).
pub const POLL_MS: u64 = 15_000;
/// The longest this hook waits in total: the pending life of a request plus a minute.
pub const MAX_WAIT_MS: u64 = 31 * 60_000;

/// What the wait ended with.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Waited {
    /// Approved: the digest to recompute against, and the request's state word.
    Approved { digest: String },
    /// Denied, cancelled, superseded or expired: the sentence to show.
    Refused(String),
    /// The person stopped waiting; the request stands.
    Stopped,
    /// The wait ran out or the service stopped answering.
    GaveUp(String),
    /// The caller's own limit (shorter than a request's life) ran out; the request stands until it expires.
    TimedOut,
}

/// One line for the person: where to decide, and that stopping the wait leaves the request.
pub fn waiting_line(id: &str) -> String {
    format!(
        "Waiting for approval, request {id}. Decide it in the dashboard (Approvals), from the link in your chat message, or with `ozbox secrets ingress requests`. Ctrl-C stops waiting; the request stays for 30 minutes."
    )
}

/// Wait for `id`. `call` sends one request line to the service and returns its `result`; `elapsed_ms` is the clock;
/// `say` prints a line (the waiting line, once); `stop` is the Ctrl-C flag.
pub fn wait_for_decision(
    call: &mut dyn FnMut(&Value) -> Result<Value, String>,
    id: &str,
    elapsed_ms: &dyn Fn() -> u64,
    say: &mut dyn FnMut(&str),
    stop: &AtomicBool,
) -> Waited {
    say(&waiting_line(id));
    wait_quietly(call, id, MAX_WAIT_MS, elapsed_ms, stop)
}

/// The wait itself, with no waiting line of its own (the caller said where to decide) and a limit of the caller's choosing,
/// never longer than [`MAX_WAIT_MS`]. A wait that runs out is [`Waited::TimedOut`], so the caller can say how long it waited.
pub fn wait_quietly(
    call: &mut dyn FnMut(&Value) -> Result<Value, String>,
    id: &str,
    max_wait_ms: u64,
    elapsed_ms: &dyn Fn() -> u64,
    stop: &AtomicBool,
) -> Waited {
    let limit = max_wait_ms.min(MAX_WAIT_MS);
    let mut failures = 0;
    loop {
        if stop.load(Ordering::SeqCst) {
            return Waited::Stopped;
        }
        if elapsed_ms() >= limit {
            return if limit < MAX_WAIT_MS {
                Waited::TimedOut
            } else {
                Waited::GaveUp("the wait ran out: ask again".into())
            };
        }
        match call(&json!({"op": "areq_await", "id": id, "wait_ms": POLL_MS})) {
            Ok(v) => {
                failures = 0;
                let r = &v["request"];
                match r["state"].as_str().unwrap_or("") {
                    "pending" => continue,
                    "approved" => {
                        return match r["subject_digest"].as_str() {
                            Some(d) if d.len() == 64 => Waited::Approved {
                                digest: d.to_string(),
                            },
                            _ => Waited::GaveUp("the service answered badly".into()),
                        }
                    }
                    s @ ("denied" | "cancelled" | "superseded" | "expired") => {
                        return Waited::Refused(format!("the request was {s}"))
                    }
                    other => return Waited::GaveUp(format!("the request is {other}")),
                }
            }
            // a service that is restarting, or a poll that timed out: a few tries, then give up with the reason
            Err(e) => {
                failures += 1;
                if failures >= 3 {
                    return Waited::GaveUp(e);
                }
            }
        }
    }
}

// The guard's hook files and waits in one call (phase 3); until it does, `ozbox guard wait` waits for a request someone filed.
#[cfg_attr(not(test), allow(dead_code))]
/// File a request on the box socket and wait for it, returning the approved digest. The hook calls this only **after** its
/// own gate has refused, never on a clean path (a clean commit costs nothing).
pub fn file_and_wait(
    call: &mut dyn FnMut(&Value) -> Result<Value, String>,
    filing: &Value,
    elapsed_ms: &dyn Fn() -> u64,
    say: &mut dyn FnMut(&str),
    stop: &AtomicBool,
) -> Waited {
    let id = match call(filing) {
        Ok(v) => match v["request"]["id"].as_str() {
            Some(i) => i.to_string(),
            None => return Waited::GaveUp("the service answered badly".into()),
        },
        Err(e) => return Waited::GaveUp(e),
    };
    wait_for_decision(call, &id, elapsed_ms, say, stop)
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use std::cell::Cell;

    fn pending() -> Value {
        json!({"request": {"id": "R1", "state": "pending", "subject_digest": "a".repeat(64)}})
    }

    #[test]
    fn a_pending_request_is_polled_again_and_an_approval_returns_the_digest() {
        let n = Cell::new(0);
        let mut call = |v: &Value| -> Result<Value, String> {
            assert_eq!(v["op"], "areq_await");
            assert_eq!(v["wait_ms"], POLL_MS);
            n.set(n.get() + 1);
            if n.get() < 3 {
                Ok(pending())
            } else {
                Ok(
                    json!({"request": {"id": "R1", "state": "approved", "subject_digest": "b".repeat(64)}}),
                )
            }
        };
        let mut lines = Vec::new();
        let got = wait_for_decision(
            &mut call,
            "R1",
            &|| 0,
            &mut |l| lines.push(l.to_string()),
            &AtomicBool::new(false),
        );
        assert_eq!(
            got,
            Waited::Approved {
                digest: "b".repeat(64)
            }
        );
        assert_eq!(n.get(), 3);
        assert_eq!(lines.len(), 1, "the waiting line is said once");
        assert!(
            lines[0].contains("R1")
                && lines[0].contains("Ctrl-C")
                && lines[0].contains("30 minutes")
        );
    }

    #[test]
    fn a_denied_or_expired_request_ends_the_wait_with_the_state() {
        for s in ["denied", "cancelled", "superseded", "expired"] {
            let mut call = |_: &Value| -> Result<Value, String> {
                Ok(json!({"request": {"id": "R1", "state": s, "subject_digest": "a".repeat(64)}}))
            };
            let got =
                wait_for_decision(&mut call, "R1", &|| 0, &mut |_| {}, &AtomicBool::new(false));
            assert_eq!(got, Waited::Refused(format!("the request was {s}")));
        }
    }

    #[test]
    fn ctrl_c_stops_the_wait_without_touching_the_request_and_a_long_wait_gives_up() {
        let stop = AtomicBool::new(true);
        let mut never = |_: &Value| -> Result<Value, String> { panic!("no call after a stop") };
        assert_eq!(
            wait_for_decision(&mut never, "R1", &|| 0, &mut |_| {}, &stop),
            Waited::Stopped
        );
        let mut pend = |_: &Value| -> Result<Value, String> { Ok(pending()) };
        let got = wait_for_decision(
            &mut pend,
            "R1",
            &|| MAX_WAIT_MS,
            &mut |_| {},
            &AtomicBool::new(false),
        );
        assert!(matches!(got, Waited::GaveUp(_)));
    }

    #[test]
    fn a_service_that_stops_answering_is_given_a_few_tries_and_a_bad_digest_is_not_trusted() {
        let n = Cell::new(0);
        let mut down = |_: &Value| -> Result<Value, String> {
            n.set(n.get() + 1);
            Err("the box's secrets service is not reachable".into())
        };
        let got = wait_for_decision(&mut down, "R1", &|| 0, &mut |_| {}, &AtomicBool::new(false));
        assert!(matches!(got, Waited::GaveUp(m) if m.contains("not reachable")));
        assert_eq!(n.get(), 3);
        let mut odd = |_: &Value| -> Result<Value, String> {
            Ok(json!({"request": {"id": "R1", "state": "approved", "subject_digest": "short"}}))
        };
        assert!(matches!(
            wait_for_decision(&mut odd, "R1", &|| 0, &mut |_| {}, &AtomicBool::new(false)),
            Waited::GaveUp(_)
        ));
    }

    #[test]
    fn filing_then_waiting_uses_the_id_the_service_gave() {
        let calls = std::cell::RefCell::new(Vec::new());
        let mut call = |v: &Value| -> Result<Value, String> {
            calls
                .borrow_mut()
                .push(v["op"].as_str().unwrap().to_string());
            match v["op"].as_str().unwrap() {
                "areq_file" => Ok(json!({"request": {"id": "R9", "state": "pending"}})),
                _ => {
                    assert_eq!(v["id"], "R9");
                    Ok(
                        json!({"request": {"id": "R9", "state": "approved", "subject_digest": "c".repeat(64)}}),
                    )
                }
            }
        };
        let got = file_and_wait(
            &mut call,
            &json!({"op": "areq_file"}),
            &|| 0,
            &mut |_| {},
            &AtomicBool::new(false),
        );
        assert_eq!(
            got,
            Waited::Approved {
                digest: "c".repeat(64)
            }
        );
        assert_eq!(*calls.borrow(), vec!["areq_file", "areq_await"]);
    }
}
