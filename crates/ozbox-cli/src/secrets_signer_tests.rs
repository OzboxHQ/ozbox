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

    fn import_value(&self, env: &str, name: &str, value: &str, code: &str) -> Value {
        self.ask(
            Policy::Unsealed,
            json!({"op":"import","project":"app","env":env,"approval":code,"allowed":[name],
                "lines":[{"name":name,"value":value}]}),
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

/// A declaration decides which commands receive a project's secrets. On the request path a software key never decides one
/// (`software_cell`), and the legacy path now agrees (review H1): no policy code for a software key, and one that somehow exists is
/// refused at the gate, for a staging-only declaration as for a Production one. The dashboard approves both.
#[test]
fn a_software_key_never_approves_a_declaration() {
    let r = rig();
    let e = r.laptop_code("policy", "app", "").unwrap_err();
    assert!(e.contains("policy") && e.contains("passkey"), "{e}");
    let code = r
        .gates
        .approvals
        .mint_unchecked_for_test(
            "policy",
            "app",
            "",
            &crate::secrets_signer::Signer::SoftwareKey("laptop".into()),
        )
        .unwrap();
    for envs in [&["production"][..], &["staging"][..]] {
        let out = r.policy(envs, &code);
        assert!(!ok(&out), "{envs:?}: {out}");
        assert!(err(&out).contains("dashboard"), "{out}");
    }
    assert!(
        crate::workload_policy::load(r.store.as_ref(), "app")
            .unwrap()
            .is_none(),
        "nothing was declared"
    );
    let dash = r.dashboard_code("policy", "app", "");
    assert!(ok(&r.policy(&["staging", "production"], &dash)));
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

/// Review H1 (B4-28): the box's own acts are Production-tier for a software key on EVERY path, as on the request path
/// (`software_cell`): the store key's escrow (it decrypts every stored secret), the dashboard's first-time code (it enrols a
/// passkey that then approves anything), who may approve, the tunnel token, the box's own vault and its guards. Laptop malware
/// holding the software key must get none of them. Refused when the code is asked for, and refused at the gate for a code that
/// somehow exists, without spending it.
#[test]
fn a_software_key_never_approves_the_boxs_own_acts_on_the_legacy_path() {
    let r = rig();
    for scope in [
        "tunnel-token",
        "signer-enroll",
        "setup-code",
        "kek-export",
        "box-secrets",
        "host-guard",
    ] {
        let Err(e) = r.laptop_code(scope, "", "") else {
            panic!("{scope}: a software key got a code");
        };
        assert!(e.contains(scope) && e.contains("passkey"), "{scope}: {e}");
    }
    // past the first-day window (someone enrolled in the dashboard), with a first-time code held: only then is an approval
    // what stands between a caller and the code
    assert!(ok(
        &r.ask(Policy::Supervisor, json!({"op":"setup_code_close"}))
    ));
    let held = r.ask(
        Policy::Supervisor,
        json!({"op":"setup_code_put","value":"HELDC-0DE42","msg":(crate::tokenmac::now_ms() + 60_000).to_string()}),
    );
    assert!(ok(&held), "{held}");
    for (op, scope) in [("kek_export", "kek-export"), ("setup_code", "setup-code")] {
        let code = r
            .gates
            .approvals
            .mint_unchecked_for_test(
                scope,
                "",
                "",
                &crate::secrets_signer::Signer::SoftwareKey("laptop".into()),
            )
            .unwrap();
        let out = r.ask(Policy::Unsealed, json!({"op":op,"approval":code}));
        assert!(!ok(&out), "{scope}: {out}");
        assert!(err(&out).contains("passkey"), "{scope}: {out}");
        assert!(
            !err(&out).contains(&code) && !out.to_string().contains("HELDC"),
            "{out}"
        );
        // the refusal did not spend it, and it never becomes good
        assert!(!ok(
            &r.ask(Policy::Unsealed, json!({"op":op,"approval":code}))
        ));
    }
    // the dashboard's code for the same acts is untouched
    for scope in ["signer-enroll", "kek-export", "box-secrets", "host-guard"] {
        let v = r.ask(
            Policy::Supervisor,
            json!({"op":"approve_mint","scope":scope,"project":"","env":""}),
        );
        assert!(ok(&v), "{scope}: {v}");
    }
}

/// Review H1: the legacy path and the request path agree on what a software key may decide, scope by scope, because the legacy
/// tier is read from the request path's rule table (`ozbox_core::approval::RULES`, the `software` column `software_cell` reads),
/// not kept beside it. The scopes a software key may never decide are the same set on both paths.
#[test]
fn the_legacy_tier_and_the_request_paths_software_rule_are_one_table() {
    use crate::secrets_signer::{allowed, Signer};
    use ozbox_core::approval::{rule_for, Soft};
    let soft = Signer::SoftwareKey("laptop".into());
    let mut never_legacy = std::collections::BTreeSet::new();
    let mut never_request = std::collections::BTreeSet::new();
    for scope in crate::secrets_approval::SCOPES {
        let rule = rule_for(scope)
            .unwrap_or_else(|| panic!("{scope}: a legacy scope the request path does not know"))
            .software;
        if matches!(rule, Soft::Never | Soft::NotApplicable) {
            never_request.insert(*scope);
        }
        // a non-Production act of the scope's own shape: a change digest for an override, a listed environment otherwise
        let env = if rule == Soft::MemberLevel {
            "0123456789abcdef"
        } else {
            "staging"
        };
        if !allowed(&soft, scope, env, false) {
            never_legacy.insert(*scope);
        }
        assert!(!allowed(&soft, scope, "production", false), "{scope}");
    }
    assert_eq!(never_legacy, never_request);
    for s in [
        "policy",
        "tunnel-token",
        "signer-enroll",
        "setup-code",
        "kek-export",
        "box-secrets",
        "host-guard",
    ] {
        assert!(never_legacy.contains(s), "{s}");
    }
}

/// Review M1 (B4-28): a legacy import is Production by what it carries, not by its environment's name alone, as on the request
/// path (`Subject::production` reads the names, `check_import_values` the values). A software key's code for `staging` that
/// carries a key named live, or a live-mode value, is refused, nothing is stored, and the code is not spent.
#[test]
fn a_software_key_code_for_staging_is_refused_for_an_import_whose_names_or_values_say_production() {
    let r = rig();
    let code = r.laptop_code("import", "app", "staging").unwrap();
    let live_value = format!("sk_live_{SENTINEL}");
    for (name, value) in [
        ("STRIPE_LIVE_KEY", SENTINEL),
        ("PROD_DB_PASSWORD", SENTINEL),
        ("API_KEY", live_value.as_str()),
        ("DATABASE_URL", "postgres://u@db.prod.example.com/app"),
    ] {
        let out = r.import_value("staging", name, value, &code);
        assert!(
            !ok(&out),
            "{name}: a software key imported a Production value: {out}"
        );
        assert!(err(&out).contains("passkey"), "{name}: {out}");
        assert!(!err(&out).contains(SENTINEL), "{out}");
        assert!(!r.stored("staging", name), "{name}: nothing stored");
    }
    // the code was not spent by the refusals: it still approves the ordinary staging import it names
    let out = r.import("staging", "API_KEY", &code);
    assert!(ok(&out), "{out}");
    // and the dashboard's code still imports a live value into staging
    let dash = r.dashboard_code("import", "app", "staging");
    assert!(ok(&r.import_value(
        "staging",
        "STRIPE_LIVE_KEY",
        SENTINEL,
        &dash
    )));
}
