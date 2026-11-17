//! A fleet change from a box's own dashboard (ADR 0040): the passkey challenge for one issued plan, and the gate `apply`
//! runs before it changes anything. Planning and applying are the laptop's own code (`issue_plan`, `apply`): this file adds
//! only what a box's dashboard must also show, never a second way to change a box.
//!
//! Every refusal and every allowed change is an entry in the audit chain (`fleet.refused`, `fleet.apply.start`), with the box
//! and the plan id only.

use serde_json::{json, Value};

use super::{unix_ms, App, Req, Resp};
use crate::fleet_gate::{Factor, Refusal};

fn refusal(r: &Refusal) -> Resp {
    Resp::error(r.status, r.code, &r.message)
}

impl App {
    fn fleet_audit(&self, kind: &str, box_name: &str, detail: &str) {
        self.chain_event(
            &self.current_actor.chain(),
            &format!("fleet.{kind}"),
            Some(box_name),
            detail,
        );
    }

    /// `POST /v1/fleet/plans/{id}/challenge`: passkey options over this plan's fleet challenge, offered only when the gate
    /// would let the plan through apart from the passkey (so nobody confirms a change that would be refused anyway).
    pub(super) fn fleet_challenge(&mut self, req: &Req, plan_id: &str) -> Resp {
        let Some(gate) = self.fleet_gate.as_ref() else {
            return Resp::error(404, "not_found", "no such endpoint");
        };
        let Some(issued) = self.plans.get(plan_id) else {
            return Resp::error(
                409,
                "unknown_plan",
                "this server did not issue that plan (or it was already used); plan again",
            );
        };
        if let Err(r) = gate.precheck(plan_id, &issued.plan, unix_ms()) {
            return refusal(&r);
        }
        let ch = gate.challenge_for(plan_id, &issued.plan);
        let Some(auth) = self.auth.clone() else {
            return Resp::error(
                403,
                "no_sign_in",
                &crate::messages::t("fleet.sign_in_needed", &[]),
            );
        };
        match auth.approval_options(req, &ch) {
            Ok(options) => Resp::json(
                200,
                &json!({"options": options, "challenge": ozbox_core::audit::hex(&ch)}),
            ),
            Err((s, code, m)) => Resp::error(s, code, &m),
        }
    }

    /// The fleet gate for one apply: `None` lets the apply go on, `Some` is the answer. A dashboard that does not manage the
    /// fleet has no gate and nothing changes for it.
    pub(super) fn fleet_gate_refusal(
        &mut self,
        req: Option<&Req>,
        plan_id: &str,
        plan: &ozbox_core::Plan,
        assertion: Option<&Value>,
    ) -> Option<Resp> {
        let gate = self.fleet_gate.as_ref()?;
        let box_name = plan.operation.box_name().to_string();
        let now = unix_ms();
        if let Err(r) = gate.precheck(plan_id, plan, now) {
            self.fleet_audit("refused", &box_name, r.code);
            return Some(refusal(&r));
        }
        let ch = gate.challenge_for(plan_id, plan);
        let factor = match (self.auth.clone(), req.zip(assertion)) {
            (None, _) => {
                self.fleet_audit("refused", &box_name, "no_sign_in");
                return Some(Resp::error(
                    403,
                    "no_sign_in",
                    &crate::messages::t("fleet.sign_in_needed", &[]),
                ));
            }
            (Some(_), None) => Factor::None,
            (Some(auth), Some((req, a))) => match auth.approval_assertion(req, &ch, a) {
                Ok(signed) => Factor::Passkey {
                    person: signed.person,
                    role: signed.role,
                    challenge: ch,
                },
                Err((s, code, m)) => {
                    self.fleet_audit("refused", &box_name, code);
                    return Some(Resp::error(s, code, &m));
                }
            },
        };
        let gate = self.fleet_gate.as_mut()?;
        match gate.authorize(plan_id, plan, &factor, now) {
            Ok(()) => {
                self.fleet_audit("apply.start", &box_name, &format!("plan {plan_id}"));
                None
            }
            Err(r) => {
                self.fleet_audit("refused", &box_name, r.code);
                Some(refusal(&r))
            }
        }
    }
}
