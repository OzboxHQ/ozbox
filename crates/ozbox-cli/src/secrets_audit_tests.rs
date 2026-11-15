//! What the secrets service and the credential broker write into the audit chain (ADR 0028): the actions, never the values.
#![allow(clippy::unwrap_used)]

use std::sync::Arc;

use serde_json::{json, Value};

use crate::audit_service::AuditCfg;
use crate::broker::Broker;
use crate::secrets::SecretStore;
use crate::secrets_enc::{EncryptedSecrets, KeyProvider, LocalKekProvider};
use crate::secrets_service::{
    handle_broker_with, handle_with, BrokerAccess, Gates, IssuerGate, Policy,
};
use crate::tokenmac::TokenMac;

const SENTINEL: &str = "SENTINEL-sk-live-0123456789abcdef";
const CODE_WORD: &str = "SENTINEL-approval-code";

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
        std::fs::read_to_string(self.dir.join("tasks.audit.jsonl")).unwrap_or_default()
    }
    fn actions(&self) -> Vec<String> {
        self.chain()
            .lines()
            .filter_map(|l| serde_json::from_str::<Value>(l).ok())
            .filter(|v| v["k"] == "e")
            .map(|v| {
                format!(
                    "{} {} {}",
                    v["action"].as_str().unwrap(),
                    v["subject"].as_str().unwrap_or(""),
                    v["detail"].as_str().unwrap_or("")
                )
            })
            .collect()
    }
    fn has(&self, action: &str) -> bool {
        self.actions().iter().any(|a| a.starts_with(action))
    }
}

fn ok(v: &Value) -> bool {
    v["ok"] == true
}

#[test]
fn imports_approvals_policies_overrides_and_box_loads_are_recorded_without_a_value_or_a_code() {
    let r = rig();
    let import = |approval: &str| {
        r.ask(
            Policy::Unsealed,
            json!({"op":"import","project":"app","env":"staging","approval":approval,
                "lines":[{"name":"API_KEY","value":SENTINEL}]}),
        )
    };
    // bootstrap
    assert!(ok(&import("")));
    assert!(r.has("secrets.approval.bootstrap import"));
    assert!(r
        .actions()
        .iter()
        .any(|a| a.starts_with("secrets.import app") && a.contains("env=staging stored=1")));
    // enrolled: a missing or wrong code is refused and recorded, a minted one is minted, spent and recorded
    assert!(ok(&r.ask(Policy::Supervisor, json!({"op":"enroll"}))));
    assert!(r.has("secrets.second-factor.enrolled"));
    assert!(!ok(&import("")));
    assert!(!ok(&import(CODE_WORD)));
    assert!(r.has("secrets.approval.refused import"));
    let code = r.ask(
        Policy::Supervisor,
        json!({"op":"approve_mint","scope":"import","project":"app","env":"staging"}),
    )["value"]
        .as_str()
        .unwrap()
        .to_string();
    assert!(r.has("secrets.approval.minted import"));
    assert!(ok(&import(&code)));
    assert!(r.has("secrets.approval.spent import"));
    // a declaration and a guard override
    let text = r#"{"dir":"/work/projects/app","commands":{"t":{"allow":["API_KEY"],"env":["API_KEY"],"argv":["node","t.mjs"],"envs":["staging"],"pin":[{"file":"t.mjs","sha256":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}]}}}"#;
    let pc = r.ask(
        Policy::Supervisor,
        json!({"op":"approve_mint","scope":"policy","project":"app"}),
    )["value"]
        .as_str()
        .unwrap()
        .to_string();
    assert!(ok(&r.ask(
        Policy::Unsealed,
        json!({"op":"policy","project":"app","text":text,"approval":pc})
    )));
    assert!(r.has("secrets.policy.write app"));
    let gc = r.ask(
        Policy::Supervisor,
        json!({"op":"approve_mint","scope":"guard-override","project":"aaaaaaaaaaaaaaaa","env":"bbbbbbbbbbbbbbbb"}),
    )["value"]
        .as_str()
        .unwrap()
        .to_string();
    // a code is for one change: a scope-only call, and another change, are both refused and do not spend it
    assert!(!ok(
        &r.ask(Policy::Import, json!({"op":"override","approval":gc}))
    ));
    assert!(!ok(&r.ask(
        Policy::Import,
        json!({"op":"override","approval":gc,"project":"aaaaaaaaaaaaaaaa","env":"cccccccccccccccc"})
    )));
    assert!(ok(&r.ask(
        Policy::Import,
        json!({"op":"override","approval":gc,"project":"aaaaaaaaaaaaaaaa","env":"bbbbbbbbbbbbbbbb"})
    )));
    assert!(r.has("secrets.guard.override"));
    // the box's own secrets load
    let mem_p: Arc<dyn KeyProvider> = Arc::new(LocalKekProvider::random("local").unwrap());
    let mem =
        Arc::new(EncryptedSecrets::new(r._t.path().join("mem.json"), "box-a", mem_p).unwrap());
    r.gates.memory.set(mem).ok().unwrap();
    let loaded = r.ask(
        Policy::Admin,
        json!({"op":"box_load","scope":"main","items":[{"project":"app","env":"staging","name":"K","value":SENTINEL}]}),
    );
    assert!(ok(&loaded));
    assert!(r
        .actions()
        .iter()
        .any(|a| a.starts_with("secrets.box.loaded main") && a.contains("count=1")));
    // none of it carries a value or a code
    let chain = r.chain();
    assert!(!chain.contains(SENTINEL) && !chain.contains(CODE_WORD));
    for c in [&code, &pc, &gc] {
        assert!(!chain.contains(c.as_str()), "a code is in the chain");
    }
    // and the chain is whole
    let cfg = AuditCfg::new(&r.dir, r._t.path().join("anchor"));
    let v = cfg
        .respond(
            r.store.as_ref(),
            Policy::Admin,
            None,
            &json!({"op":"audit_verify"}),
        )
        .unwrap();
    assert_eq!(v["report"]["ok"], true, "{v}");
}

#[test]
fn a_secret_written_deleted_or_resolved_is_recorded_by_name_and_a_command_with_no_reference_is_not()
{
    let r = rig();
    assert!(ok(&r.ask(
        Policy::Box,
        json!({"op":"set","name":"email-api-key","value":SENTINEL})
    )));
    assert!(ok(&r.ask(
        Policy::Box,
        json!({"op":"delete","name":"email-api-key"})
    )));
    assert!(r.has("secrets.set email-api-key via=box") && r.has("secrets.delete email-api-key"));
    // a refused write is not a record of a change
    let before = r.actions().len();
    assert!(!ok(&r.ask(
        Policy::Box,
        json!({"op":"set","name":"tunnel-token-x","value":SENTINEL})
    )));
    assert_eq!(r.actions().len(), before);
    // resolving a reference from the runner's socket
    let n = crate::secrets_enc::workload_name("app", "staging", "API_KEY").unwrap();
    r.store.set(&n, SENTINEL).unwrap();
    // nothing is resolved on a box with no second factor
    r.store
        .set(crate::secrets_approval::ENROLLED_MARKER, "1")
        .unwrap();
    let go = |text: &str, allowed: Value| {
        r.ask(
            Policy::Runner,
            json!({"op":"resolve","project":"app","env":"staging","text":text,"allowed":allowed}),
        )
    };
    assert!(ok(&go("curl {{secret:API_KEY}}", json!(["API_KEY"]))));
    assert!(r.has("secrets.resolve app env=staging"));
    assert!(!ok(&go("curl {{secret:API_KEY}}", json!(["OTHER"]))));
    assert!(r.has("secrets.resolve.refused app"));
    let n_events = r.actions().len();
    assert!(ok(&go("ls -la", json!([]))));
    assert_eq!(
        r.actions().len(),
        n_events,
        "no reference, nothing resolved, no line"
    );
    assert!(!r.chain().contains(SENTINEL));
}

#[test]
fn tokens_issued_and_revoked_are_recorded_by_run_and_provider_never_the_token_or_the_key() {
    let r = rig();
    let key = crate::models::key_name("p1");
    r.store.set(&key, SENTINEL).unwrap();
    let up = Arc::new(crate::broker::tests::FakeUpstream::default());
    let b = Broker::start_with(r.store.clone() as Arc<dyn SecretStore>, up, None).unwrap();
    let g = IssuerGate::default();
    let cfg = r.gates.audit.get().unwrap().clone();
    let run = |a: BrokerAccess, v: Value| -> Value {
        serde_json::from_str(&handle_broker_with(
            &b,
            &g,
            a,
            Some((cfg.as_ref(), r.store.as_ref() as &dyn SecretStore)),
            &v.to_string(),
        ))
        .unwrap()
    };
    let provider = json!({"id":"p1","kind":"anthropic","label":"A","base_url":null,"local_endpoint":false,"monthly_cap_usd":null});
    let issued = run(
        BrokerAccess::Trusted,
        json!({"op":"issue","run_id":"run-1","provider":provider}),
    );
    assert!(ok(&issued));
    let token = issued["token"].as_str().unwrap().to_string();
    assert!(r.has("secrets.token.issued run-1 provider=p1 via=supervisor"));
    // the box user's socket without a claim is refused, and the refusal is recorded too
    assert!(!ok(&run(
        BrokerAccess::Claimed,
        json!({"op":"issue","run_id":"run-2","provider":provider})
    )));
    assert!(r.has("secrets.token.refused run-2"));
    assert!(ok(&run(
        BrokerAccess::Trusted,
        json!({"op":"revoke","run_id":"run-1"})
    )));
    assert!(r.has("secrets.token.revoked run-1"));
    let chain = r.chain();
    assert!(!chain.contains(&token) && !chain.contains(SENTINEL) && !chain.contains("ozrt_"));
}
