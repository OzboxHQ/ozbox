//! Who signed an approval, and what that signer may approve (ADR 0041 §3): a key kept on a computer (a software laptop key)
//! never approves Production, on any path. These tests drive the real secrets service in process (its request handler, its
//! gate, its laptop-key operations), with a key made here; no box, no socket.
#![allow(clippy::unwrap_used)]

use std::sync::Arc;

use serde_json::{json, Value};

use crate::secrets::SecretStore;
use crate::secrets_enc::{EncryptedSecrets, KeyProvider, LocalKekProvider};
use crate::secrets_service::{handle_with, Gates, Policy};
use crate::tokenmac::TokenMac;

const SENTINEL: &str = "SENTINEL-b428-value-0123456789";

struct Rig {
    store: Arc<EncryptedSecrets>,
    mac: Arc<TokenMac>,
    gates: Gates,
    seed: zeroize::Zeroizing<String>,
    _t: tempfile::TempDir,
}

/// A box with one laptop key enrolled by root (so a second factor exists), as `ozbox create` leaves it.
fn rig() -> Rig {
    let t = tempfile::tempdir().unwrap();
    let p: Arc<dyn KeyProvider> = Arc::new(LocalKekProvider::random("local").unwrap());
    let store = Arc::new(EncryptedSecrets::new(t.path().join("s.json"), "box-a", p).unwrap());
    let mac = Arc::new(TokenMac::new(store.clone() as Arc<dyn SecretStore>));
    let gates = Gates::default();
    let (seed, pk) = crate::approval_key::generate().unwrap();
    let r = Rig {
        store,
        mac,
        gates,
        seed,
        _t: t,
    };
    let out = r.ask(
        Policy::Admin,
        json!({"op":"approval_key_enroll","key_id":"laptop","public_key":pk}),
    );
    assert!(ok(&out), "{out}");
    r
}

fn ok(v: &Value) -> bool {
    v["ok"] == true
}

fn err(v: &Value) -> String {
    v["error"].as_str().unwrap_or("").to_string()
}

impl Rig {
    fn ask(&self, p: Policy, v: Value) -> Value {
        serde_json::from_str(&handle_with(
            &self.store,
            &self.mac,
            &self.gates,
            p,
            &v.to_string(),
        ))
        .unwrap()
    }

    /// The laptop's whole legacy path over the ingress route: a challenge, this computer's software key signs it, and the box
    /// makes a code. `Err` with the box's sentence when the box refuses at either step.
    fn laptop_code(&self, scope: &str, project: &str, env: &str) -> Result<String, String> {
        let ch = self.ask(
            Policy::Unsealed,
            json!({"op":"approval_challenge","key_id":"laptop","scope":scope,"project":project,"env":env}),
        );
        if !ok(&ch) {
            return Err(err(&ch));
        }
        let res = &ch["result"];
        let nonce = res["nonce"].as_str().unwrap();
        let exp = res["expires_ms"].as_u64().unwrap();
        let msg = crate::approval_key::message(scope, project, env, "laptop", nonce, exp);
        let sig = crate::approval_key::sign(&self.seed, &msg).unwrap();
        let out = self.ask(
            Policy::Unsealed,
            json!({"op":"approval_redeem","key_id":"laptop","nonce":nonce,"signature":sig}),
        );
        if !ok(&out) {
            return Err(err(&out));
        }
        Ok(out["result"]["code"].as_str().unwrap().to_string())
    }

    /// A code from the dashboard after the person's passkey or authenticator code (the supervisor's step-up).
    fn dashboard_code(&self, scope: &str, project: &str, env: &str) -> String {
        let v = self.ask(
            Policy::Supervisor,
            json!({"op":"approve_mint","scope":scope,"project":project,"env":env}),
        );
        assert!(ok(&v), "{v}");
        v["value"].as_str().unwrap().to_string()
    }

    fn import(&self, env: &str, name: &str, code: &str) -> Value {
        self.ask(
            Policy::Unsealed,
            // `allowed` is what the laptop sends once the person has typed the confirmation for a Production import
            json!({"op":"import","project":"app","env":env,"approval":code,"allowed":[name],
                "lines":[{"name":name,"value":SENTINEL}]}),
        )
    }

    fn policy(&self, envs: &[&str], code: &str) -> Value {
        let text = json!({"dir":"/work/projects/app","commands":{"t":{"allow":["API_KEY"],"env":["API_KEY"],
            "argv":["node","t.mjs"],"envs":envs,
            "pin":[{"file":"t.mjs","sha256":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}]}}})
        .to_string();
        self.ask(
            Policy::Unsealed,
            json!({"op":"policy","project":"app","text":text,"approval":code}),
        )
    }

    fn stored(&self, env: &str, name: &str) -> bool {
        self.store
            .exists(&format!("workload.app.{env}.{name}"))
            .unwrap()
    }
}

/// B4-28: a code this computer's software key made, for exactly the Production import it is spent on, is refused, and the
/// refusal names what does approve it. Before the fix the box made the code and stored the value.
#[test]
fn a_software_key_code_for_an_exact_production_import_is_refused() {
    let r = rig();
    for env in ["production", "prod", "live", "qa"] {
        match r.laptop_code("import", "app", env) {
            // refused at the box when the code is asked for: the rule, and where to go instead
            Err(e) => assert!(
                e.contains("dashboard") && e.contains("passkey") && e.contains("Production"),
                "{env}: {e}"
            ),
            // a code was made: it must not be spent on the Production import it names
            Ok(code) => {
                let out = r.import(env, "API_KEY", &code);
                assert!(
                    !ok(&out),
                    "{env}: a software key's code imported into Production: {out}"
                );
            }
        }
        assert!(!r.stored(env, "API_KEY"), "{env}: nothing stored");
    }
}

/// The dashboard's approval (the person's passkey or authenticator code) still imports into Production, and this computer's
/// key still imports into a non-Production environment: only the software key for Production changed.
#[test]
fn the_dashboard_still_approves_production_and_a_software_key_still_approves_staging() {
    let r = rig();
    let code = r.dashboard_code("import", "app", "production");
    let out = r.import("production", "API_KEY", &code);
    assert!(ok(&out), "{out}");
    assert!(r.stored("production", "API_KEY"));
    for env in ["staging", "dev", "test", "e2e", "development"] {
        let code = r.laptop_code("import", "app", env).unwrap();
        let out = r.import(env, "API_KEY", &code);
        assert!(ok(&out), "{env}: {out}");
        assert!(r.stored(env, "API_KEY"), "{env}");
    }
}

/// The gate is the boundary, not the mint: a software key's code that somehow exists for a Production import (made by an
/// older program, or by a path that forgot the check) is refused when it is spent, names what approves it, and is not
/// spent by the refusal. Nothing is stored, and the refusal holds no code and no value.
#[test]
fn the_gate_refuses_a_software_keys_production_code_even_when_one_exists() {
    let r = rig();
    // made directly on the gate, as a code an earlier program could have made
    let code = r
        .gates
        .approvals
        .mint_unchecked_for_test(
            "import",
            "app",
            "production",
            &crate::secrets_signer::Signer::SoftwareKey("laptop".into()),
        )
        .unwrap();
    let out = r.import("production", "API_KEY", &code);
    assert!(!ok(&out), "{out}");
    let e = err(&out);
    assert!(
        e.contains("dashboard") && e.contains("passkey") && e.contains("authenticator"),
        "{e}"
    );
    assert!(!e.contains(&code) && !e.contains(SENTINEL), "{e}");
    assert!(!r.stored("production", "API_KEY"));
    // it is still that code, still refused: the refusal did not spend it, and it never becomes good for Production
    assert!(!ok(&r.import("production", "API_KEY", &code)));
}

/// A declaration with a command that takes secrets from Production (or that removes one) is a Production change: a software
/// key's policy code is refused for it and the dashboard's is not. A staging-only declaration still takes a software key's code.
#[test]
fn a_software_key_never_approves_a_declaration_that_touches_production() {
    let r = rig();
    let code = r.laptop_code("policy", "app", "").unwrap();
    let out = r.policy(&["production"], &code);
    assert!(!ok(&out), "{out}");
    assert!(err(&out).contains("dashboard"), "{out}");
    assert!(
        crate::workload_policy::load(r.store.as_ref(), "app")
            .unwrap()
            .is_none(),
        "nothing was declared"
    );
    // the same code still approves a staging-only declaration: the refusal did not spend it
    let out = r.policy(&["staging"], &code);
    assert!(ok(&out), "{out}");
    // the dashboard approves the Production one
    let dash = r.dashboard_code("policy", "app", "");
    assert!(ok(&r.policy(&["staging", "production"], &dash)));
    // and now a software key can no longer replace it, not even with a staging-only one (that removes a Production command)
    let code = r.laptop_code("policy", "app", "").unwrap();
    assert!(!ok(&r.policy(&["staging"], &code)));
}

/// A guard override names one change by digest. A software key asking for an override "for production" (or for anything that
/// is not a change digest) is refused before it signs anything; one for a digest is made as before.
#[test]
fn a_software_key_gets_a_guard_override_only_for_a_change_digest() {
    let r = rig();
    let e = r
        .laptop_code("guard-override", "0123456789abcdef", "production")
        .unwrap_err();
    assert!(e.contains("dashboard") && e.contains("passkey"), "{e}");
    assert!(r
        .laptop_code("guard-override", "0123456789abcdef", "fedcba9876543210")
        .is_ok());
}

/// The scopes that are the box's own settings (not a project environment) keep their laptop-key route: this change narrows
/// Production only.
#[test]
fn the_box_own_scopes_still_take_a_software_keys_code() {
    let r = rig();
    for scope in [
        "tunnel-token",
        "signer-enroll",
        "setup-code",
        "kek-export",
        "box-secrets",
        "host-guard",
    ] {
        assert!(r.laptop_code(scope, "", "").is_ok(), "{scope}");
    }
}
