//! Approvals for changes to a box's secrets (ADR 0018, item 10). Behind a sign-in, a person who has just shown their
//! passkey or authenticator code can ask for a short-lived approval code; the box's secrets service (which only this
//! process can talk to for that) hands it out and spends it on the one change it is for. Nothing here carries a secret.

use serde::Deserialize;
use serde_json::json;

use super::{unix_ms, App, Req, Resp};

#[derive(Deserialize)]
struct Ask {
    scope: String,
    #[serde(default)]
    project: String,
    #[serde(default)]
    env: String,
}

impl App {
    /// Tell the secrets service a second factor exists, so changes to secrets need an approval from now on. Best effort:
    /// a store that is not a box's service has nothing to tell.
    pub(super) fn sync_second_factor(&self) {
        if let Some(a) = &self.auth {
            if a.has_second_factor() {
                let _ = self.secrets.probe("enroll", &json!({}));
            }
        }
    }

    /// What the page shows: whether this dashboard has a box secrets service to approve for, whether a second factor is
    /// enrolled there, and the recent uses (scope, project, how and when; never a value or a code).
    pub(super) fn secrets_approvals_list(&self) -> Resp {
        match self.secrets.probe("recent_approvals", &json!({})) {
            Some(Ok(v)) => Resp::json(
                200,
                &json!({"available": true, "enrolled": v["enrolled"].as_bool().unwrap_or(false),
                    "recent": v["recent"].clone(), "signed_in": self.auth.is_some()}),
            ),
            Some(Err(e)) => Resp::error(502, "secrets_service", &e.0),
            None => Resp::json(
                200,
                &json!({"available": false, "enrolled": false, "recent": [], "signed_in": self.auth.is_some()}),
            ),
        }
    }

    pub(super) fn secrets_approval(&mut self, req: &Req) -> Resp {
        let Some(auth) = self.auth.clone() else {
            return Resp::error(
                409,
                "no_sign_in",
                "approvals come from a dashboard that has a sign-in with a passkey or authenticator code",
            );
        };
        if !auth.step_up_fresh(req) {
            return Resp::error(
                403,
                "step_up_required",
                "confirm with your passkey to continue",
            );
        }
        let Ok(ask) = serde_json::from_slice::<Ask>(&req.body) else {
            return Resp::error(400, "bad_request", "the request is not valid");
        };
        // A fresh second factor was just shown, so one exists: say so before the first approval is used.
        let _ = self.secrets.probe("enroll", &json!({}));
        let args = json!({"scope": ask.scope, "project": ask.project, "env": ask.env});
        match self.secrets.probe("approve_mint", &args) {
            Some(Ok(v)) => match v["value"].as_str() {
                Some(code) => {
                    self.log_activity("secret_approval", "", None, "ok");
                    // the page shows the code once and never asks for it again: nothing here keeps it
                    Resp::json(
                        200,
                        &json!({"code": code, "scope": ask.scope, "project": ask.project, "env": ask.env,
                            "expires_in_seconds": 300, "expires_at_ms": unix_ms() + 300_000}),
                    )
                }
                None => Resp::error(502, "bad_answer", "the secrets service answered badly"),
            },
            Some(Err(e)) => Resp::error(400, "refused", &e.0),
            None => Resp::error(
                501,
                "no_secrets_service",
                "this dashboard does not keep secrets in a box's secrets service",
            ),
        }
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use std::collections::HashMap;

    use super::*;

    #[test]
    fn without_a_sign_in_nobody_can_ask_for_an_approval() {
        let dir = tempfile::tempdir().unwrap();
        let mut app = App::new(
            Box::new(ozbox_provider_fake::open(dir.path())),
            true,
            "127.0.0.1:7878".parse().unwrap(),
            "tok".into(),
        );
        let mut headers = HashMap::new();
        headers.insert("host".to_string(), "127.0.0.1:7878".to_string());
        headers.insert("authorization".to_string(), "Bearer tok".to_string());
        let r = app.handle(&Req {
            method: "POST".into(),
            path: "/v1/secrets/approvals".into(),
            query: String::new(),
            headers,
            body: br#"{"scope":"import","project":"app","env":"staging"}"#.to_vec(),
        });
        assert_eq!(r.status, 409);
        assert!(String::from_utf8_lossy(&r.body).contains("no_sign_in"));
    }
}
