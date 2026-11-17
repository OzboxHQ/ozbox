//! A passkey check for one approval request (ADR 0041 §3, "Dashboard decision").
//!
//! The challenge is not one this server makes up: it is the one the secrets service built for this request, its digest, the
//! outcome, the box and the store (`areq_decide_challenge`), so one assertion decides one request. This module offers the
//! person's own passkeys for it, checks the assertion with the relying party's id and exact origin, user presence and user
//! verification (`webauthn::verify_assertion`), keeps the signature counter moving, and hands back the evidence the service
//! stores and checks again (its own challenge, flags, counter and relying party).

use serde::{Deserialize, Serialize};
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

/// The evidence of one passkey assertion, kept with what it signed so it can be checked again later (a delegation's
/// signature is checked every time the delegation is used). Hex, as the approval service stores it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SignedEvidence {
    pub person: String,
    pub credential_id: String,
    pub authenticator_data_hex: String,
    pub client_data_hex: String,
    pub signature_hex: String,
    pub rp_id: String,
    pub origin: String,
    pub at_ms: u64,
}

impl SignedApproval {
    pub fn evidence(&self, at_ms: u64) -> SignedEvidence {
        SignedEvidence {
            person: self.person.clone(),
            credential_id: self.credential_id.clone(),
            authenticator_data_hex: self.authenticator_data_hex.clone(),
            client_data_hex: self.client_data_hex.clone(),
            signature_hex: self.signature_hex.clone(),
            rp_id: self.rp_id.clone(),
            origin: self.origin.clone(),
            at_ms,
        }
    }
}

impl Auth {
    /// Whether `ev` is a valid assertion over `challenge` by a passkey this person **still has**, for this dashboard's own
    /// relying party. The signature, the relying party, the origin, user presence and verification and the challenge are all
    /// checked again; the counter is not (it moved on when the evidence was made). A passkey that was removed, another
    /// dashboard's origin or a challenge that is not this record's is `false`.
    pub fn verify_evidence(&self, ev: &SignedEvidence, challenge: &[u8; 32]) -> bool {
        if ev.rp_id != self.cfg.rp.id || ev.origin != self.cfg.rp.origin {
            return false;
        }
        let inner = self.lock();
        let Some(pk) = inner
            .state
            .users
            .get(&ev.person)
            .and_then(|u| u.passkeys.iter().find(|p| p.id == ev.credential_id))
            .cloned()
        else {
            return false;
        };
        drop(inner);
        let b64 =
            |h: &str| ozbox_core::approval_subject::from_hex(h).map(|b| super::b64::encode_url(&b));
        let (Some(cd), Some(ad), Some(sig)) = (
            b64(&ev.client_data_hex),
            b64(&ev.authenticator_data_hex),
            b64(&ev.signature_hex),
        ) else {
            return false;
        };
        webauthn::verify_stored_assertion(&self.cfg.rp, challenge, &pk, &cd, &ad, &sig).is_ok()
    }

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

    /// The signed-in person approving a request with an authenticator-app code (ADR 0041, amendment of 2026-11-17): only a
    /// person with no passkey (whoever has one approves with it, as a step-up does), and only with an authenticator set up.
    /// The code is checked here as at sign-in, so it cannot be used again for a sign-in or a step-up; the secrets service
    /// then checks it again itself, against the same secret, before it records the decision. Returns the person and role.
    pub fn approval_authenticator(
        &self,
        req: &Req,
        code: &str,
    ) -> Result<(String, ozbox_core::roles::Role), Refusal> {
        let (person, role) = self.who_and_role(req).ok_or((
            403,
            "no_sign_in",
            "sign in to decide a request".to_string(),
        ))?;
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
        let user = inner.state.users.get(&person);
        if user.is_some_and(|u| !u.passkeys.is_empty()) {
            return Err((
                409,
                "passkey_required",
                "this account has a passkey: approve with it".to_string(),
            ));
        }
        if !user.is_some_and(|u| u.totp) {
            return Err((
                409,
                "no_authenticator",
                crate::messages::t("approval.authenticator_none", &[]),
            ));
        }
        self.check_totp(&mut inner, &person, code).map_err(|_| {
            (
                401,
                "code_refused",
                crate::messages::t("approval.authenticator_refused", &[]),
            )
        })?;
        Ok((person, role))
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
