//! The approval flow end to end, in process, against the real secrets service (B4-27): a computer files an import request
//! over the sealed route's dispatch, the owner approves it on the dashboard's socket with an authenticator code, and the
//! waiting command goes on and stores exactly what was approved. No code is copied anywhere, and no value leaves the import.

use std::cell::RefCell;
use std::sync::atomic::AtomicBool;
use std::sync::Arc;

use serde_json::{json, Value};

use super::*;
use crate::secrets::SecretStore;
use crate::secrets_enc::{EncryptedSecrets, KeyProvider, LocalKekProvider};
use crate::secrets_service::{handle_from, Gates, Policy};
use crate::tokenmac::TokenMac;

/// A value no request, answer, line or record may carry, apart from the import that stores it.
pub(super) const SENTINEL: &str = "sentinel-b4-27-value-0123456789";
/// The owner's authenticator secret (base32), as the dashboard keeps it in the box's store.
pub(super) const TOTP_SECRET: &str = "JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP";

pub(super) struct Rig {
    pub(super) dir: tempfile::TempDir,
    pub(super) store: Arc<EncryptedSecrets>,
    pub(super) mac: TokenMac,
    pub(super) gates: Gates,
}

pub(super) fn rig() -> Rig {
    let dir = tempfile::tempdir().unwrap();
    let p: Arc<dyn KeyProvider> = Arc::new(LocalKekProvider::random("local").unwrap());
    let store = Arc::new(EncryptedSecrets::new(dir.path().join("s.json"), "box-a", p).unwrap());
    let mac = TokenMac::new(store.clone() as Arc<dyn SecretStore>);
    let gates = Gates::default();
    store
        .set(crate::secrets_approval::ENROLLED_MARKER, "1")
        .unwrap();
    store
        .set(&crate::serve::auth::totp::secret_name("alice"), TOTP_SECRET)
        .unwrap();
    let ad = dir.path().join("audit");
    std::fs::create_dir_all(&ad).unwrap();
    let _ = gates
        .audit
        .set(Arc::new(crate::audit_service::AuditCfg::new(
            &ad,
            dir.path().join("anchor"),
        )));
    gates
        .enable_requests(
            &store,
            &dir.path().join("req"),
            &dir.path().join("state"),
            "box-1",
            crate::tokenmac::now_ms(),
        )
        .unwrap();
    Rig {
        dir,
        store,
        mac,
        gates,
    }
}

impl Rig {
    /// One request line through the service's real dispatch, as the given socket.
    pub(super) fn raw(&self, policy: Policy, v: &Value) -> Value {
        serde_json::from_str(&handle_from(
            &self.store,
            &self.mac,
            &self.gates,
            policy,
            None,
            &v.to_string(),
        ))
        .unwrap()
    }

    /// The laptop's side of the sealed route: the `result`, or the refusal sentence.
    pub(super) fn laptop(&self, v: &Value) -> Result<Value, String> {
        let mut v = v.clone();
        // a test does not hold the service's long poll for its full 15 seconds
        if v["op"] == "areq_await" {
            v["wait_ms"] = json!(1);
        }
        let out = self.raw(Policy::Unsealed, &v);
        if out["ok"] == true {
            Ok(out["result"].clone())
        } else {
            Err(out["error"].as_str().unwrap_or("").to_string())
        }
    }

    /// The owner approves on the dashboard with an authenticator code: the supervisor socket, `factor: authenticator`.
    pub(super) fn dashboard_approve_with_code(&self, id: &str, code: &str) -> Value {
        self.raw(
            Policy::Supervisor,
            &json!({"op":"areq_decide","id":id,"outcome":"approve","person":"alice","role":"owner",
                    "surface":"dashboard","factor":"authenticator","code":code}),
        )
    }

    /// Everything the service wrote beside its store: the journal, the state, the audit chain.
    pub(super) fn on_disk(&self) -> String {
        let mut all = String::new();
        for e in walk(self.dir.path()) {
            if e.file_name().is_some_and(|n| n == "s.json") {
                continue; // the store itself holds the value, sealed
            }
            all.push_str(&String::from_utf8_lossy(
                &std::fs::read(&e).unwrap_or_default(),
            ));
        }
        all
    }
}

fn walk(p: &std::path::Path) -> Vec<std::path::PathBuf> {
    let mut out = Vec::new();
    for e in std::fs::read_dir(p).into_iter().flatten().flatten() {
        let path = e.path();
        if path.is_dir() {
            out.extend(walk(&path));
        } else {
            out.push(path);
        }
    }
    out
}

pub(super) fn code_now() -> String {
    let secret = crate::serve::auth::b64::decode_base32(TOTP_SECRET).unwrap();
    crate::serve::auth::totp::hotp(
        &secret,
        crate::tokenmac::now_ms() / 1000 / crate::serve::auth::totp::STEP_S,
        6,
    )
}

fn import_line(env: &str, rows: &[(&str, &str)]) -> Value {
    let lines: Vec<Value> = rows
        .iter()
        .map(|(n, v)| json!({"name": n, "value": v}))
        .collect();
    json!({"op":"import","project":"app","env":env,"approval":"","lines":lines})
}

#[test]
fn the_box_says_an_import_needs_an_approval_in_words_the_command_recognises() {
    let r = rig();
    let out = r.laptop(&import_line("staging", &[("API_KEY", SENTINEL)]));
    let e = out.unwrap_err();
    assert!(needs_approval(&e), "{e}");
    assert!(!e.contains(SENTINEL));
    let mut call = |v: &Value| r.laptop(v);
    assert!(box_files(&mut call, "import"));
    assert!(!box_files(&mut call, "no-such-scope"));
    assert!(!r
        .store
        .exists(&crate::secrets_enc::workload_name("app", "staging", "API_KEY").unwrap())
        .unwrap());
}

/// The whole flow for a Production import: filed, approved on the dashboard with an authenticator code (an owner factor),
/// and the waiting command goes on and stores exactly what was approved. Nothing to copy, no value outside the import.
#[test]
fn a_production_import_is_filed_approved_with_an_authenticator_and_the_waiting_command_completes() {
    let r = rig();
    let rows = [
        ("API_KEY", SENTINEL),
        ("API_URL", "https://api.example.com"),
    ];
    let salt = new_salt().unwrap();
    let subject = import_subject("app", "production", &rows, &salt).unwrap();
    assert!(subject.production());
    let sent = RefCell::new(Vec::<String>::new());
    let answers = RefCell::new(Vec::<String>::new());
    let approved_once = RefCell::new(false);
    let mut call = |v: &Value| {
        sent.borrow_mut().push(v.to_string());
        // the owner taps Approve while the command waits
        if v["op"] == "areq_await" && !*approved_once.borrow() {
            let id = v["id"].as_str().unwrap();
            let d = r.dashboard_approve_with_code(id, &code_now());
            assert_eq!(d["ok"], true, "{d}");
            answers.borrow_mut().push(d.to_string());
            *approved_once.borrow_mut() = true;
        }
        let out = r.laptop(v);
        answers.borrow_mut().push(format!("{out:?}"));
        out
    };
    let mut lines = Vec::new();
    let mut say = |l: &str| lines.push(l.to_string());
    let stop = AtomicBool::new(false);
    let mut flow = Flow {
        call: &mut call,
        say: &mut say,
        // never offered for Production
        inline: None,
        elapsed_ms: &|| 0,
        stop: &stop,
        max_wait_ms: 30 * 60_000,
    };
    let a = file_and_wait(
        &mut flow,
        &subject,
        "the import of 2 keys into app/production",
    )
    .unwrap();
    // the waiting line names where to approve, and that only the dashboard approves Production
    assert!(
        lines[0].contains("Waiting for approval in your dashboard"),
        "{lines:?}"
    );
    assert!(lines[0].contains("Production") && lines[0].contains("authenticator"));
    assert!(lines[0].contains(&a.id));
    // the decision is recorded as an authenticator decision by an owner, never as a passkey
    let list = r.raw(
        Policy::Supervisor,
        &json!({"op":"areq_list","role":"owner"}),
    );
    let card = list["result"]["requests"]
        .as_array()
        .unwrap()
        .iter()
        .find(|c| c["id"] == a.id.as_str())
        .unwrap()
        .clone();
    assert_eq!(card["decision"]["factor_label"], "authenticator", "{card}");
    assert_eq!(card["decision"]["role"], "owner");
    // the waiting command goes on: the import carries the request and the salt, and is stored
    let mut imp = import_line("production", &rows);
    // what `--allow-live` names (the typed confirmation came first, on the computer)
    imp["allowed"] = json!(["API_KEY", "API_URL"]);
    imp["request_id"] = json!(a.id);
    imp["salt"] = json!(salt);
    let done = r.raw(Policy::Unsealed, &imp);
    assert_eq!(done["ok"], true, "{done}");
    assert_eq!(
        r.store
            .get(&crate::secrets_enc::workload_name("app", "production", "API_KEY").unwrap())
            .unwrap()
            .as_deref(),
        Some(SENTINEL)
    );
    // and only once
    assert_eq!(r.raw(Policy::Unsealed, &imp)["ok"], false);
    // sentinel: the value is in no request line of the flow, no answer, no line for the person, no dashboard card, and
    // nothing the service wrote beside its sealed store; the code is in no answer or record either
    let code = code_now();
    for s in sent
        .borrow()
        .iter()
        .chain(answers.borrow().iter())
        .chain(lines.iter())
    {
        assert!(!s.contains(SENTINEL), "{s}");
    }
    assert!(!list.to_string().contains(SENTINEL) && !list.to_string().contains(&code));
    let disk = r.on_disk();
    assert!(
        !disk.contains(SENTINEL),
        "the value reached a file beside the store"
    );
    assert!(
        !disk.contains(&format!("\"{code}\"")),
        "the code reached a file"
    );
}

/// The dashboard's authenticator decision is checked by the service itself: a wrong code, a code used twice, a viewer and
/// a person with no authenticator approve nothing, and the wire cannot claim an authenticator check of its own.
#[test]
fn an_authenticator_approval_is_checked_by_the_service_and_never_taken_on_the_wire_s_word() {
    let r = rig();
    let salt = new_salt().unwrap();
    let subject = import_subject("app", "production", &[("K", SENTINEL)], &salt).unwrap();
    let f = r
        .laptop(&json!({"op":"areq_file","subject":subject}))
        .unwrap();
    let id = f["request"]["id"].as_str().unwrap().to_string();
    let wrong = if code_now() == "000000" {
        "111111"
    } else {
        "000000"
    };
    let x = r.dashboard_approve_with_code(&id, wrong);
    assert_eq!(x["ok"], false);
    assert!(x["error"].as_str().unwrap().contains("not accepted"), "{x}");
    // evidence on the wire is ignored: only the service's own check counts
    let forged = r.raw(
        Policy::Supervisor,
        &json!({"op":"areq_decide","id":id,"outcome":"approve","person":"alice","role":"owner",
                "surface":"dashboard","factor":"authenticator","code":"",
                "evidence":{"authenticator":{"step": 99_999_999u64}}}),
    );
    assert_eq!(forged["ok"], false, "{forged}");
    // someone with no authenticator secret on this box
    let nobody = r.raw(
        Policy::Supervisor,
        &json!({"op":"areq_decide","id":id,"outcome":"approve","person":"bob","role":"owner",
                "surface":"dashboard","factor":"authenticator","code":code_now()}),
    );
    assert_eq!(nobody["ok"], false);
    assert!(
        nobody["error"]
            .as_str()
            .unwrap()
            .contains("no authenticator"),
        "{nobody}"
    );
    // a viewer decides nothing
    let viewer = r.raw(
        Policy::Supervisor,
        &json!({"op":"areq_decide","id":id,"outcome":"approve","person":"alice","role":"viewer",
                "surface":"dashboard","factor":"authenticator","code":code_now()}),
    );
    assert_eq!(viewer["ok"], false);
    // the right code approves, once; the same time step cannot decide a second request
    let ok = r.dashboard_approve_with_code(&id, &code_now());
    assert_eq!(ok["ok"], true, "{ok}");
    let f2 = r
        .laptop(&json!({"op":"areq_file","subject":import_subject("app", "production", &[("K2", "v2")], &salt).unwrap()}))
        .unwrap();
    let id2 = f2["request"]["id"].as_str().unwrap().to_string();
    let again = r.dashboard_approve_with_code(&id2, &code_now());
    assert_eq!(again["ok"], false, "{again}");
    // an authenticator code is not a way in from a laptop or a box user
    let from_laptop = r.raw(
        Policy::Unsealed,
        &json!({"op":"areq_decide","id":id2,"outcome":"approve","factor":"authenticator","code":code_now()}),
    );
    assert_eq!(from_laptop["ok"], false);
}

/// A key kept on a computer is refused for Production on the request path, and the refusal names what does approve it and
/// where; the command does not even offer it.
#[test]
fn a_laptop_key_attempt_at_production_is_refused_with_the_dashboard_named() {
    let r = rig();
    let (seed, public) = crate::approval_key::generate().unwrap();
    let e = r.raw(
        Policy::Admin,
        &json!({"op":"approval_key_enroll","key_id":"laptop","public_key":public}),
    );
    assert_eq!(e["ok"], true, "{e}");
    let salt = new_salt().unwrap();
    let subject = import_subject("app", "production", &[("K", "v")], &salt).unwrap();
    let f = r
        .laptop(&json!({"op":"areq_file","subject":subject}))
        .unwrap();
    let id = f["request"]["id"].as_str().unwrap().to_string();
    let ch = r
        .laptop(&json!({"op":"areq_decide_challenge","id":id,"outcome":"approve"}))
        .unwrap();
    let challenge = ch["challenge"].as_str().unwrap();
    let message = format!(
        "{}\n{challenge}",
        ozbox_core::approval_subject::DECIDE_MESSAGE_HEAD
    );
    let signature = crate::approval_key::sign(&seed, &message).unwrap();
    let x = r.laptop(&json!({
        "op": "areq_decide", "id": id, "outcome": "approve", "key_id": "laptop",
        "evidence": {"laptop": {"key_id": "laptop", "key_type": "ed25519", "signature_format": "ed25519-message",
            "signed_message": ozbox_core::audit::hex(message.as_bytes()), "signature": signature}},
    }));
    let why = x.unwrap_err();
    assert!(why.contains("never decides Production"), "{why}");
    assert!(
        why.contains("dashboard (Approvals)")
            && why.contains("passkey")
            && why.contains("authenticator"),
        "{why}"
    );
    // and the command's flow never offers this computer's key for Production
    let mut offered = false;
    let mut inline = |_: &str, _: &str| {
        offered = true;
        Inline::Approved
    };
    let mut call = |v: &Value| r.laptop(v);
    let mut lines = Vec::new();
    let mut say = |l: &str| lines.push(l.to_string());
    let stop = AtomicBool::new(true);
    let mut flow = Flow {
        call: &mut call,
        say: &mut say,
        inline: Some(&mut inline),
        elapsed_ms: &|| 0,
        stop: &stop,
        max_wait_ms: 60_000,
    };
    let _ = file_and_wait(
        &mut flow,
        &import_subject("app", "production", &[("K3", "v")], &salt).unwrap(),
        "x",
    );
    assert!(!offered);
    assert!(
        lines[0].contains("only the dashboard approves it"),
        "{lines:?}"
    );
}

/// A non-Production import may be approved here with this computer's key after the person says yes; a refusal of that key
/// is said, and the command keeps waiting for the dashboard.
#[test]
fn a_non_production_import_offers_this_computer_s_key_and_falls_back_to_the_dashboard() {
    let r = rig();
    let salt = new_salt().unwrap();
    let rows = [("API_URL", "https://api.example.com")];
    let subject = import_subject("app", "staging", &rows, &salt).unwrap();
    let decided = RefCell::new(false);
    // the key's decision stands in for `approval_laptop::decide`: root approves, as a key that may would
    let mut inline = |id: &str, digest: &str| {
        assert_eq!(digest.len(), 64);
        let d = r.raw(
            Policy::Admin,
            &json!({"op":"areq_decide","id":id,"outcome":"approve"}),
        );
        assert_eq!(d["ok"], true, "{d}");
        *decided.borrow_mut() = true;
        Inline::Approved
    };
    let mut call = |v: &Value| r.laptop(v);
    let mut lines = Vec::new();
    let mut say = |l: &str| lines.push(l.to_string());
    let stop = AtomicBool::new(false);
    let mut flow = Flow {
        call: &mut call,
        say: &mut say,
        inline: Some(&mut inline),
        elapsed_ms: &|| 0,
        stop: &stop,
        max_wait_ms: 60_000,
    };
    let a = file_and_wait(&mut flow, &subject, "the import of 1 key into app/staging").unwrap();
    assert!(*decided.borrow());
    assert!(
        lines[0].contains("Waiting for approval in your dashboard")
            && !lines[0].contains("only the dashboard")
    );
    let mut imp = import_line("staging", &rows);
    imp["request_id"] = json!(a.id);
    imp["salt"] = json!(salt);
    assert_eq!(r.raw(Policy::Unsealed, &imp)["ok"], true);

    // a key the box refuses: the reason is said, and the wait goes on (here it is stopped at once)
    let subject = import_subject("app", "staging", &[("OTHER", "x")], &salt).unwrap();
    let mut refused = |_: &str, _: &str| Inline::Refused("that key was revoked".into());
    let mut call = |v: &Value| r.laptop(v);
    let mut lines = Vec::new();
    let mut say = |l: &str| lines.push(l.to_string());
    let stop = AtomicBool::new(true);
    let mut flow = Flow {
        call: &mut call,
        say: &mut say,
        inline: Some(&mut refused),
        elapsed_ms: &|| 0,
        stop: &stop,
        max_wait_ms: 60_000,
    };
    let e = file_and_wait(&mut flow, &subject, "x")
        .unwrap_err()
        .to_string();
    assert!(lines.iter().any(
        |l| l.contains("that key was revoked") && l.contains("Still waiting for the dashboard")
    ));
    assert!(
        e.contains("Stopped waiting") && e.contains("Nothing was changed"),
        "{e}"
    );
}

/// The wait has a limit of its own: it ends cleanly, says so, and changes nothing; the request stays until it expires. Ctrl-C
/// does the same.
#[test]
fn the_waiting_command_times_out_cleanly_and_ctrl_c_leaves_the_request_to_expire() {
    let r = rig();
    let salt = new_salt().unwrap();
    let subject = import_subject("app", "staging", &[("K", SENTINEL)], &salt).unwrap();
    let clock = RefCell::new(0u64);
    let mut call = |v: &Value| {
        // each poll takes a minute on this clock
        *clock.borrow_mut() += 60_000;
        r.laptop(v)
    };
    let mut lines = Vec::new();
    let mut say = |l: &str| lines.push(l.to_string());
    let stop = AtomicBool::new(false);
    let elapsed = || *clock.borrow();
    let mut flow = Flow {
        call: &mut call,
        say: &mut say,
        inline: None,
        elapsed_ms: &elapsed,
        stop: &stop,
        max_wait_ms: 2 * 60_000,
    };
    let e = file_and_wait(&mut flow, &subject, "x")
        .unwrap_err()
        .to_string();
    assert!(
        e.contains("No decision within 2 minutes") && e.contains("nothing was changed"),
        "{e}"
    );
    assert!(lines[0].contains("up to 2 minutes"));
    assert!(!e.contains(SENTINEL));
    // the request is still there, pending, for the dashboard; nothing was stored
    let list = r.raw(
        Policy::Supervisor,
        &json!({"op":"areq_list","role":"owner"}),
    );
    assert_eq!(list["result"]["requests"][0]["state"], "pending", "{list}");
    assert!(!r
        .store
        .exists(&crate::secrets_enc::workload_name("app", "staging", "K").unwrap())
        .unwrap());
}

#[test]
fn a_production_looking_value_in_a_non_production_import_is_refused_before_anything_is_filed() {
    let live = concat!("sk_", "live_0123456789abcdefghijklmn");
    let e = import_subject(
        "app",
        "staging",
        &[("STRIPE_KEY", live)],
        "00112233445566778899aabbccddeeff",
    )
    .unwrap_err()
    .to_string();
    assert!(
        e.contains("STRIPE_KEY") && e.contains("--env production"),
        "{e}"
    );
    assert!(!e.contains(live));
}

/// B4-29 with B4-27: the box user (an agent) gets no authenticator seed and no way to use one through anything this flow added.
/// The service reads the seed only for a decision that came in as the supervisor; on the box sockets the seed is not readable,
/// an authenticator decision is refused before any seed is read, and no answer to the box user carries the seed or a code.
#[test]
fn an_agent_cannot_obtain_or_use_an_authenticator_code_through_the_approval_flow() {
    let r = rig();
    let salt = new_salt().unwrap();
    let subject = import_subject("app", "production", &[("K", SENTINEL)], &salt).unwrap();
    let id = r
        .laptop(&json!({"op":"areq_file","subject":subject}))
        .unwrap()["request"]["id"]
        .as_str()
        .unwrap()
        .to_string();
    let code = code_now();
    let mut seen = Vec::new();
    for policy in [Policy::Box, Policy::BoxLocked] {
        // the seed is not readable by name, and its name is not even listed
        for v in [
            json!({"op":"get","name":"totp-alice"}),
            json!({"op":"exists","name":"totp-alice"}),
            json!({"op":"names"}),
        ] {
            seen.push(r.raw(policy, &v));
        }
        // an authenticator decision from the box user's side is refused, with the right code or without one
        for c in [code.as_str(), ""] {
            let d = r.raw(
                policy,
                &json!({"op":"areq_decide","id":id,"outcome":"approve","person":"alice","role":"owner",
                        "surface":"dashboard","factor":"authenticator","code":c}),
            );
            assert_eq!(d["ok"], false, "{d}");
            seen.push(d);
        }
        // what the box user may read of the request says nothing about the factor's secret
        seen.push(r.raw(policy, &json!({"op":"areq_get","id":id})));
        seen.push(r.raw(policy, &json!({"op":"areq_list"})));
    }
    // still pending: nothing the box user did approved it
    let list = r.raw(
        Policy::Supervisor,
        &json!({"op":"areq_list","role":"owner"}),
    );
    assert_eq!(list["result"]["requests"][0]["state"], "pending", "{list}");
    for v in &seen {
        let s = v.to_string();
        assert!(
            !s.contains(TOTP_SECRET),
            "the seed reached the box user: {s}"
        );
        assert!(
            !s.contains("totp-alice"),
            "the seed's name reached the box user: {s}"
        );
        assert!(!s.contains(SENTINEL), "{s}");
    }
    // the supervisor identity still approves with the person's code
    assert_eq!(r.dashboard_approve_with_code(&id, &code)["ok"], true);
}
