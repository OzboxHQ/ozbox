//! The fleet inbox (ADR 0042 section 8, ADR 0041 section 5): requests filed on worker boxes, shown on `main`'s dashboard, decided
//! once by the person with a passkey, and relayed to the worker, **whose own service verifies the assertion**.
//!
//! `main` is a viewer and a relay here, never an approver: it lists the cards it verified from each worker's signed envelope, and it
//! passes a person's assertion on. It cannot make one, and a worker refuses a decision that carries none. A Deny of a pending request
//! needs no assertion (fail safe). Routes, under `/v1/approvals/fleet` (so the role table's "decide approvals" applies):
//!
//! * `GET  fleet`: the cards, each with the worker's ids and the challenge to sign, derived from the signed fields.
//! * `POST fleet/<worker>/<request>/decide`: `{ "outcome": "approve" | "deny" | "revoke", "subject_digest": "...", "passkey": {...} }`.

use serde_json::{json, Value};

use super::{App, Req, Resp};
use ozbox_core::approval::{Outcome, PasskeyEvidence};
use ozbox_core::hub::approvals::DecisionBody;

impl App {
    pub(super) fn fleet_approvals_route(&mut self, req: &Req, rest: &[&str]) -> Resp {
        let (get, post) = (req.method == "GET", req.method == "POST");
        let now = super::unix_ms();
        // the cards come from the worker's own service, through the hub: nothing here is a store of requests
        let Some(hub) = self.orch.hub.clone() else {
            return Resp::json(
                200,
                &json!({"available": false, "why": "this box has no worker channel", "cards": []}),
            );
        };
        match rest {
            [] if get => {
                let cards = hub
                    .with(now, |h, st| {
                        h.poll(st, now);
                        st.inbox(now)
                    })
                    .unwrap_or_default();
                Resp::json(200, &json!({"available": true, "cards": cards}))
            }
            [worker, id, "decide"] if post => {
                // who relays it is recorded; who decided is what the worker reads from its own approver set
                let person = self.who(req);
                let v: Value = match serde_json::from_slice(&req.body) {
                    Ok(v) => v,
                    Err(_) => return Resp::error(400, "invalid", "the body is not JSON"),
                };
                let outcome = match v["outcome"].as_str() {
                    Some("approve") => Outcome::Approve,
                    Some("deny") => Outcome::Deny,
                    Some("revoke") => Outcome::Revoke,
                    _ => return Resp::error(400, "invalid", "outcome is approve, deny or revoke"),
                };
                let passkey = match v.get("passkey").filter(|p| !p.is_null()) {
                    None => None,
                    Some(p) => match serde_json::from_value::<PasskeyEvidence>(p.clone()) {
                        Ok(p) => Some(p),
                        Err(_) => {
                            return Resp::error(
                                400,
                                "invalid",
                                "the passkey assertion is not valid",
                            )
                        }
                    },
                };
                let d = DecisionBody {
                    request_id: id.to_string(),
                    subject_digest: v["subject_digest"].as_str().unwrap_or_default().to_string(),
                    outcome,
                    claimed_person: person.clone(),
                    passkey,
                };
                let r = hub.with(now, |h, st| h.relay_decision(st, worker, &d, now));
                if let Some(store) = self.runs.store.clone() {
                    // the relay is recorded in this box's audit trail by number, as every hub event is
                    let _ = crate::orch_tools::record_hub_audit(&store, &hub, &person);
                }
                match r {
                    Some(Ok(())) => Resp::json(
                        202,
                        &json!({"relayed": true, "note": "the worker's own service decides whether this is valid; its answer appears on the card"}),
                    ),
                    Some(Err(e)) => Resp::error(409, "not_relayed", &e.to_string()),
                    None => Resp::error(503, "unavailable", "the hub's state could not be used"),
                }
            }
            _ => Resp::error(404, "not_found", "no such route"),
        }
    }
}
