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
