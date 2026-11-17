//! What the box user (and every agent, which runs as it) can reach in the box's secrets store, and what the dashboard's own
//! user can: the table in `secrets_service::BOX_REACH`, checked op by op. A security review (2026-11-17) found the owner's
//! authenticator secret (`totp-<user>`) readable and writable over the box socket; these tests fail on that code.
#![allow(clippy::unwrap_used)]

use std::sync::Arc;

use serde_json::{json, Value};

use crate::audit_service::AuditCfg;
use crate::secrets::SecretStore;
use crate::secrets_enc::{EncryptedSecrets, KeyProvider, LocalKekProvider};
use crate::secrets_service::{
    box_reach, handle_with, supervisor_may_get, BoxReach, Gates, NameRule, Policy, BOX_REACH,
};
use crate::tokenmac::TokenMac;

const SEED: &str = "SENTINELTOTPSEEDJBSWY3DPEHPK3PXP";

struct Rig {
    store: Arc<EncryptedSecrets>,
    mac: Arc<TokenMac>,
    gates: Gates,
    dir: std::path::PathBuf,
    _t: tempfile::TempDir,
}

fn rig() -> Rig {
    let t = tempfile::tempdir().unwrap();
    let p: Arc<dyn KeyProvider> = Arc::new(LocalKekProvider::random("local").unwrap());
    let store = Arc::new(EncryptedSecrets::new(t.path().join("s.json"), "box-a", p).unwrap());
    let mac = Arc::new(TokenMac::new(store.clone() as Arc<dyn SecretStore>));
    let gates = Gates::default();
    let dir = t.path().join("audit");
    gates
        .audit
        .set(Arc::new(AuditCfg::new(&dir, t.path().join("anchor"))))
        .ok()
        .unwrap();
    Rig {
        store,
        mac,
        gates,
        dir,
        _t: t,
    }
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
    fn chain(&self) -> String {
        let mut all = String::new();
        if let Ok(rd) = std::fs::read_dir(&self.dir) {
            for e in rd.flatten() {
                all.push_str(&std::fs::read_to_string(e.path()).unwrap_or_default());
            }
        }
        all
    }
}

/// The two sockets the box user may connect to that answer the store's plain operations.
const BOX_USER: [Policy; 2] = [Policy::Box, Policy::BoxLocked];

#[test]
fn the_box_user_cannot_read_write_delete_ask_about_or_list_an_authenticator_secret() {
    let r = rig();
    r.store.set("totp-owner", SEED).unwrap();
    for p in BOX_USER {
        // the refusal is the same words for a seed that is set and one that is not, so nothing says which users have one
        for op in ["get", "exists", "delete"] {
            let set = r.ask(p, json!({"op":op,"name":"totp-owner"}));
            let unset = r.ask(p, json!({"op":op,"name":"totp-nobody"}));
            assert_eq!(set["ok"], false, "{p:?} {op}");
            assert_eq!(set, unset, "{p:?} {op}");
            assert!(!set.to_string().contains(SEED));
        }
        let w = r.ask(
            p,
            json!({"op":"set","name":"totp-owner","value":"AGENTSEED"}),
        );
        assert_eq!(w["ok"], false, "{p:?} set");
        assert_eq!(
            w,
            r.ask(
                p,
                json!({"op":"set","name":"totp-nobody","value":"AGENTSEED"})
            )
        );
        assert!(!r.store.exists("totp-nobody").unwrap());
        for prefix in ["", "t", "totp", "totp-", "totp-owner"] {
            let n = r.ask(p, json!({"op":"names","prefix":prefix}));
            assert!(!n.to_string().contains("totp-owner"), "{p:?} {prefix}: {n}");
        }
    }
    // the seed is untouched
    assert_eq!(r.store.get("totp-owner").unwrap().as_deref(), Some(SEED));
}

#[test]
fn the_dashboards_own_user_still_reads_and_writes_an_authenticator_secret() {
    let r = rig();
    let s = Policy::Supervisor;
    assert_eq!(
        r.ask(s, json!({"op":"set","name":"totp-owner","value":SEED}))["ok"],
        true
    );
    assert_eq!(
        r.ask(s, json!({"op":"get","name":"totp-owner"}))["value"],
        SEED
    );
    assert_eq!(
        r.ask(s, json!({"op":"exists","name":"totp-owner"}))["flag"],
        true
    );
    assert!(r.ask(s, json!({"op":"names","prefix":"totp-"}))["names"]
        .to_string()
        .contains("totp-owner"));
    assert_eq!(
        r.ask(s, json!({"op":"delete","name":"totp-owner"}))["ok"],
        true
    );
    assert!(!r.store.exists("totp-owner").unwrap());
    // and root's admin socket
    r.store.set("totp-owner", SEED).unwrap();
    assert_eq!(
        r.ask(Policy::Admin, json!({"op":"get","name":"totp-owner"}))["value"],
        SEED
    );
}

/// A name that a row of the table matches (and no earlier row does).
fn sample(rule: NameRule) -> String {
    match rule {
        NameRule::Exact(n) => n.to_string(),
        NameRule::Prefix(p) => format!("{p}owner"),
    }
}

/// What the box user can do with `name` on one socket, found by asking: (read, write, delete, ask, listed).
fn observed(r: &Rig, p: Policy, name: &str) -> (bool, bool, bool, bool, bool) {
    r.store.set(name, "v1").unwrap();
    let read = r.ask(p, json!({"op":"get","name":name}))["value"] == "v1";
    let ask = r.ask(p, json!({"op":"exists","name":name}))["flag"] == true;
    let listed = r.ask(p, json!({"op":"names","prefix":""}))["names"]
        .as_array()
        .is_some_and(|a| a.iter().any(|n| n == name));
    let write = r.ask(p, json!({"op":"set","name":name,"value":"v2"}))["ok"] == true
        && r.store.get(name).unwrap().as_deref() == Some("v2");
    r.store.set(name, "v1").unwrap();
    let delete = r.ask(p, json!({"op":"delete","name":name}))["ok"] == true
        && !r.store.exists(name).unwrap();
    let _ = r.store.delete(name);
    (read, write, delete, ask, listed)
}

fn expected(reach: BoxReach, p: Policy) -> (bool, bool, bool, bool, bool) {
    let unlocked = p == Policy::Box;
    match reach {
        BoxReach::None => (false, false, false, false, false),
        BoxReach::Ask => (false, false, false, true, true),
        BoxReach::Write => (false, unlocked, unlocked, true, true),
        BoxReach::Read => (unlocked, unlocked, unlocked, true, true),
    }
}

#[test]
fn every_name_the_store_keeps_is_reached_by_the_box_user_exactly_as_the_table_says() {
    let r = rig();
    // every row of the table, the store's own records, and names no row matches
    let mut names: Vec<(String, BoxReach)> = BOX_REACH
        .iter()
        .map(|row| (sample(row.rule), row.box_user))
        .collect();
    for (n, reach) in [
        // sign-in and second factors, device subscriptions: never the box user's
        ("totp-owner", BoxReach::None),
        ("totp-a-second-person", BoxReach::None),
        ("google-client-secret", BoxReach::None),
        ("vapid-private-key", BoxReach::None),
        ("push-endpoint-phone", BoxReach::None),
        ("push-key-phone", BoxReach::None),
        ("push-auth-phone", BoxReach::None),
        // the store's keys and its modules' own records
        ("store-kek", BoxReach::None),
        ("internal-hmac-keys", BoxReach::None),
        (crate::secrets_approval::ENROLLED_MARKER, BoxReach::None),
        ("approval-key.laptop", BoxReach::None),
        (crate::approval_key::PIN_APPLIED, BoxReach::None),
        (crate::approval_requests::EVER_KEY_MARKER, BoxReach::None),
        (crate::secrets_ingress::KEY_NAME, BoxReach::None),
        ("audit-seal-key.1", BoxReach::None),
        ("workload.app.staging.API_KEY", BoxReach::None),
        ("workload-policy.app", BoxReach::None),
        // the root helper writes it
        ("tunnel-token-cloudflare", BoxReach::Ask),
        // written, never read back
        ("model-key-anth", BoxReach::Write),
        ("restic-password", BoxReach::Write),
        ("restic-env", BoxReach::Write),
        ("ide-password-dev", BoxReach::Write),
        ("desktop-password-dev", BoxReach::Write),
        ("dashboard-tunnel-token-dev", BoxReach::Write),
        ("dashboard-install-dev", BoxReach::Write),
        ("ide-tunnel-token-dev", BoxReach::Write),
        ("my-own-secret", BoxReach::Write),
        // the dashboard sends with these
        ("telegram-bot-token", BoxReach::Read),
        ("sms-secret", BoxReach::Read),
        ("webhook-secret-ci", BoxReach::Read),
        ("trigger-secret-t1", BoxReach::Read),
    ] {
        names.push((n.to_string(), reach));
    }
    for (name, reach) in &names {
        assert_eq!(box_reach(name), *reach, "{name}");
        for p in BOX_USER {
            assert_eq!(
                observed(&r, p, name),
                expected(*reach, p),
                "{p:?} {name}: (read, write, delete, ask, listed)"
            );
        }
    }
    // reading back is an allow-list of the dashboard's send keys: every such row is one the supervisor reads too, and no
    // row reads back a name a factor row also matches
    for row in BOX_REACH.iter().filter(|r| r.box_user == BoxReach::Read) {
        assert!(row.supervisor_get, "{}", sample(row.rule));
        assert_ne!(
            box_reach(&sample(row.rule)),
            BoxReach::None,
            "{}",
            sample(row.rule)
        );
    }
}

/// The supervisor reads what the dashboard needs, including the factors it owns, and none of the store's own keys.
#[test]
fn the_supervisor_reads_the_factors_it_owns_and_not_the_stores_keys() {
    for n in [
        "totp-owner",
        "google-client-secret",
        "vapid-private-key",
        "push-endpoint-phone",
        "telegram-bot-token",
    ] {
        assert!(supervisor_may_get(n), "{n}");
    }
    for n in [
        "store-kek",
        "internal-hmac-keys",
        "model-key-anth",
        "restic-password",
        "tunnel-token-cloudflare",
        "workload.app.staging.K",
        "approval-key.laptop",
        crate::secrets_ingress::KEY_NAME,
        crate::secrets_approval::ENROLLED_MARKER,
    ] {
        assert!(!supervisor_may_get(n), "{n}");
    }
}

/// The seed is never in anything the box user can see: an answer, an error or the audit chain.
#[test]
fn an_authenticator_seed_appears_in_no_answer_the_box_user_gets_and_in_no_record() {
    let r = rig();
    assert_eq!(
        r.ask(
            Policy::Supervisor,
            json!({"op":"set","name":"totp-owner","value":SEED})
        )["ok"],
        true
    );
    let mut answers = Vec::new();
    for p in [Policy::Box, Policy::BoxLocked, Policy::Import] {
        for req in [
            json!({"op":"get","name":"totp-owner"}),
            json!({"op":"exists","name":"totp-owner"}),
            json!({"op":"names","prefix":""}),
            json!({"op":"names","prefix":"totp-owner"}),
            json!({"op":"set","name":"totp-owner","value":"X"}),
            json!({"op":"set","name":"totp-owner","value_b64":"WA=="}),
            json!({"op":"delete","name":"totp-owner"}),
            json!({"op":"mac","msg":"dG90cC1vd25lcg=="}),
            json!({"op":"resolve","name":"totp-owner","project":"app","env":"staging","allowed":["totp-owner"]}),
            json!({"op":"scan","text":"totp-owner"}),
            json!({"op":"enrolled"}),
            json!({"op":"areq_capabilities"}),
            json!({"op":"audit_verify"}),
            json!({"op":"approval_key_list"}),
            json!({"op":"get","name":"totp-owner\u{0}"}),
            json!({"op":"get","name":"TOTP-owner"}),
        ] {
            answers.push(r.ask(p, req).to_string());
        }
    }
    for a in &answers {
        assert!(!a.contains(SEED), "{a}");
    }
    assert!(!r.chain().contains(SEED));
    // the supervisor's write was recorded by name only
    assert!(r.chain().contains("totp-owner"));
    assert_eq!(r.store.get("totp-owner").unwrap().as_deref(), Some(SEED));
}
