//! A passkey check for one approval request (ADR 0041 §3, "Dashboard decision").
//!
//! The challenge is not one this server makes up: it is the one the secrets service built for this request, its digest, the
//! outcome, the box and the store (`areq_decide_challenge`), so one assertion decides one request. This module offers the
//! person's own passkeys for it, checks the assertion with the relying party's id and exact origin, user presence and user
//! verification (`webauthn::verify_assertion`), keeps the signature counter moving, and hands back the evidence the service
//! stores and checks again (its own challenge, flags, counter and relying party).

use serde_json::Value;

use super::b64::decode_url;
use super::webauthn;
use super::Auth;
use crate::serve::Req;

/// A refusal: the status, a code, and the sentence to show.
pub type Refusal = (u16, &'static str, String);

fn hex(b: &[u8]) -> String {
    ozbox_core::audit::hex(b)
}

/// A checked assertion, in the form the service takes as evidence.
pub struct SignedApproval {
    pub person: String,
    pub role: ozbox_core::roles::Role,
    pub credential_id: String,
    pub authenticator_data_hex: String,
    pub client_data_hex: String,
    pub signature_hex: String,
    pub rp_id: String,
    pub origin: String,
}

impl Auth {
    /// Options for a passkey check over `challenge`, offering only the signed-in person's own passkeys.
    pub fn approval_options(&self, req: &Req, challenge: &[u8; 32]) -> Result<Value, Refusal> {
        let (person, _) = self.who_and_role(req).ok_or((
            403,
            "no_sign_in",
            "sign in to decide a request".to_string(),
        ))?;
        let inner = self.lock();
        let ids: Vec<String> = Self::user_passkeys(&inner, &person)
            .into_iter()
            .map(|p| p.id)
            .collect();
        if ids.is_empty() {
            return Err((
                409,
                "no_passkey",
                "this account has no passkey: add one on the account page, then decide here"
                    .to_string(),
            ));
        }
        Ok(webauthn::assertion_options(&self.cfg.rp, challenge, &ids))
    }

    /// Check an assertion over `challenge` by the signed-in person. `assertion` is the browser's JSON as the dashboard
    /// forwards it (`id`, `response.{clientDataJSON, authenticatorData, signature}`).
    pub fn approval_assertion(
        &self,
        req: &Req,
        challenge: &[u8; 32],
        assertion: &Value,
    ) -> Result<SignedApproval, Refusal> {
        let refuse = || {
            (
                400,
                "bad_assertion",
                "that passkey was not accepted".to_string(),
            )
        };
        let (person, role) = self.who_and_role(req).ok_or((
            403,
            "no_sign_in",
            "sign in to decide a request".to_string(),
        ))?;
        let get = |k: &str| assertion["response"][k].as_str().unwrap_or("");
        let id = assertion["id"].as_str().ok_or_else(refuse)?;
        let mut inner = self.lock();
        if !inner
            .limiter
            .hit_n(&format!("approve:{person}"), self.now(), 30)
        {
            return Err((
                429,
                "too_many_attempts",
                "too many attempts; wait a few minutes and try again".to_string(),
            ));
        }
        let idx = inner
            .state
            .users
            .get(&person)
            .and_then(|u| u.passkeys.iter().position(|p| p.id == id))
            .ok_or_else(refuse)?;
        if let Some(h) = assertion["response"]["userHandle"]
            .as_str()
            .filter(|h| !h.is_empty())
        {
            if decode_url(h).as_deref() != Some(person.as_bytes()) {
                return Err(refuse());
            }
        }
        let pk = inner
            .state
            .users
            .get(&person)
            .map(|u| u.passkeys[idx].clone())
            .ok_or_else(refuse)?;
        let n = webauthn::verify_assertion(
            &self.cfg.rp,
            challenge,
            &pk,
            get("clientDataJSON"),
            get("authenticatorData"),
            get("signature"),
        )
        .map_err(|_| refuse())?;
        let now = self.now();
        if let Some(p) = inner
            .state
            .users
            .get_mut(&person)
            .and_then(|u| u.passkeys.get_mut(idx))
        {
            p.sign_count = n;
            p.last_used_ms = now;
        }
        self.save(&inner);
        let dec = |k: &str| decode_url(get(k)).ok_or_else(refuse);
        Ok(SignedApproval {
            person,
            role,
            credential_id: id.to_string(),
            authenticator_data_hex: hex(&dec("authenticatorData")?),
            client_data_hex: hex(&dec("clientDataJSON")?),
            signature_hex: hex(&dec("signature")?),
            rp_id: self.cfg.rp.id.clone(),
            origin: self.cfg.rp.origin.clone(),
        })
    }
}
