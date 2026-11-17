//! B4-27 part 2: the one file-and-wait flow for every other gated act a computer makes: a declaration (`env policy set --box`),
//! a dashboard's tunnel token (`dashboard install`), and the box's own secrets declaration (`box-secrets`, Hetzner). Each is
//! filed over the sealed route, approved on the dashboard, and the waiting command goes on with the approved request, all in
//! process against the real secrets service. The guard override already files and waits from the box (`guard_hold`).

use std::cell::RefCell;
use std::sync::atomic::AtomicBool;

use serde_json::{json, Value};

use super::tests::{code_now, rig, Rig, SENTINEL};
use super::*;
use crate::secrets_service::Policy;

/// A token value no request, answer, line, card or file may carry (the gate sees only its digest).
const TOKEN: &str = "sentinel-b4-27-tunnel-token-0123456789abcdef";

fn declaration(cmd: &str) -> String {
    let text = format!(
        r#"{{"dir":"/work/projects/app","commands":{{"{cmd}":{{"allow":["API_KEY"],"env":["API_KEY"],"argv":["node","t.mjs"],"envs":["staging"],"pin":[{{"file":"t.mjs","sha256":"{}"}}]}}}}}}"#,
        "a".repeat(64)
    );
    crate::workload_policy::Policy::parse(&text)
        .unwrap()
        .check_before_write()
        .unwrap()
}

fn policy_filing(text: &str) -> Value {
    json!({"op": "areq_file", "subject": {"scope": "policy"}, "project": "app", "policy_text": text})
}

fn tunnel_subject(token: &str) -> ozbox_core::approval_subject::Subject {
    ozbox_core::approval_subject::gate_subject(
        "tunnel-token",
        "cloudflare",
        &crate::secrets_approval::tunnel_token_binding(token),
        &ozbox_core::approval_subject::tunnel_token_sha256(token),
    )
    .unwrap()
}

/// What the root helper's gate sends (`ozbox secrets gate --bind-token-stdin`), on the admin socket.
fn tunnel_gate(r: &Rig, approval: &str, token: &str) -> Value {
    r.raw(
        Policy::Admin,
        &json!({"op":"gate","scope":"tunnel-token","project":"cloudflare",
            "env": crate::secrets_approval::tunnel_token_binding(token), "approval": approval,
            "token_sha256": ozbox_core::approval_subject::tunnel_token_sha256(token)}),
    )
}

fn declaration_gate(r: &Rig, approval: &str, bind: &str) -> Value {
    r.raw(
        Policy::Admin,
        &json!({"op":"gate","scope":"box-secrets","project":"declaration","env": bind, "approval": approval}),
    )
}

/// Run the flow with the dashboard approving (an owner's authenticator code) while the command waits. Returns the approved
/// request, every line sent and answered, the lines for the person, and whether this computer's key was offered.
fn approve_while_waiting(
    r: &Rig,
    filing: &Value,
    scope: &str,
) -> (Approved, Vec<String>, Vec<String>, bool) {
    let seen = RefCell::new(Vec::<String>::new());
    let approved = RefCell::new(false);
    let mut call = |v: &Value| {
        seen.borrow_mut().push(v.to_string());
        if v["op"] == "areq_await" && !*approved.borrow() {
            let d = r.dashboard_approve_with_code(v["id"].as_str().unwrap(), &code_now());
            assert_eq!(d["ok"], true, "{d}");
            seen.borrow_mut().push(d.to_string());
            *approved.borrow_mut() = true;
        }
        let out = r.laptop(v);
        seen.borrow_mut().push(format!("{out:?}"));
        out
    };
    let mut lines = Vec::new();
    let mut say = |l: &str| lines.push(l.to_string());
    let mut offered = false;
    let mut inline = |_: &str, _: &str| {
        offered = true;
        Inline::Approved
    };
    let stop = AtomicBool::new(false);
    let mut flow = Flow {
        call: &mut call,
        say: &mut say,
        inline: Some(&mut inline),
        elapsed_ms: &|| 0,
        stop: &stop,
        max_wait_ms: 30 * 60_000,
    };
    let a = file_and_wait_with(&mut flow, filing, scope, false, "the change").unwrap();
    drop(flow);
    (a, seen.into_inner(), lines, offered)
}

#[test]
fn the_box_says_which_acts_it_can_take_by_request() {
    let r = rig();
    let mut call = |v: &Value| r.laptop(v);
    for scope in ["import", "policy", "tunnel-token", "box-secrets"] {
        assert!(box_files(&mut call, scope), "{scope}");
    }
    // a scope the box cannot spend by request from a computer
    assert!(!box_files(&mut call, "host-guard"));
    // the box's own rule: only an import and a guard override may ever be decided by a key kept on a computer
    assert!(software_key_may_decide("import") && software_key_may_decide("guard-override"));
    for scope in ["policy", "tunnel-token", "box-secrets"] {
        assert!(!software_key_may_decide(scope), "{scope}");
    }
}

/// `ozbox env policy set --box` with no code: the box refuses with words the command recognises, the declaration is filed
/// (the box works out its digests itself), approved on the dashboard, and the waiting command saves exactly that declaration,
/// once. This computer's key is never offered, and the waiting line says only the dashboard approves it.
#[test]
fn a_declaration_is_filed_approved_in_the_dashboard_and_the_waiting_command_saves_it() {
    let r = rig();
    let text = declaration("t");
    let send = |extra: Value| {
        let mut v = json!({"op":"policy","project":"app","text":text});
        for (k, x) in extra.as_object().unwrap() {
            v[k] = x.clone();
        }
        r.raw(Policy::Unsealed, &v)
    };
    let refused = send(json!({}));
    assert_eq!(refused["ok"], false);
    let why = refused["error"].as_str().unwrap();
    assert!(needs_approval(why), "{why}");
    assert!(
        why.contains("dashboard (Approvals)") && why.contains("--approval CODE"),
        "the refusal names what approves it and where: {why}"
    );
    let (a, _, lines, offered) = approve_while_waiting(&r, &policy_filing(&text), "policy");
    assert!(
        !offered,
        "a key kept on this computer never decides a declaration"
    );
    assert!(
        lines[0].contains("Only the dashboard approves this change"),
        "{lines:?}"
    );
    // the card names the project, and was worked out by the box
    let list = r.raw(
        Policy::Supervisor,
        &json!({"op":"areq_list","role":"owner"}),
    );
    let card = &list["result"]["requests"][0];
    assert_eq!(card["scope"], "policy");
    assert!(card.to_string().contains("declaration for project app"));
    assert_eq!(card["decision"]["factor_label"], "authenticator");
    // a different declaration sent with this request is refused, and the approval is kept for the one it was filed for
    let other = declaration("u");
    let mut v = json!({"op":"policy","project":"app","text":other,"request_id":a.id});
    assert_eq!(r.raw(Policy::Unsealed, &v)["ok"], false);
    v["text"] = json!(text);
    assert_eq!(r.raw(Policy::Unsealed, &v)["ok"], true, "the approved one");
    assert!(crate::workload_policy::load(r.store.as_ref(), "app")
        .unwrap()
        .is_some());
    // and only once
    assert_eq!(r.raw(Policy::Unsealed, &v)["ok"], false);
}

/// The box never takes a filer's own fields for a declaration: a subject with digests and a label of the filer's making, or no
/// declaration text, is refused.
#[test]
fn a_declaration_request_is_worked_out_by_the_box_never_taken_from_the_filer() {
    let r = rig();
    let h = "d".repeat(64);
    for bad in [
        json!({"op":"areq_file","subject":{"scope":"policy","policy_sha256":h,"predecessor_sha256":h,"sensitivity":"ordinary"},"project":"app"}),
        json!({"op":"areq_file","subject":{"scope":"policy"},"project":"app","policy_text":"{"}),
        json!({"op":"areq_file","subject":{"scope":"policy"},"project":"Not A Project","policy_text":declaration("t")}),
    ] {
        assert!(r.laptop(&bad).is_err(), "{bad}");
    }
}

/// `ozbox dashboard install` with a new tunnel token and no code: the request is bound to the token's digest, approved on the
/// dashboard, and the root helper's gate takes `req-<id>` for that token only. The token itself is in no request, answer, line,
/// card or file. A gate from an older helper (no digest) is refused, and the request kept.
#[test]
fn a_tunnel_token_is_approved_in_the_dashboard_and_the_gate_takes_the_request_for_that_token_only()
{
    let r = rig();
    let refused = tunnel_gate(&r, "", TOKEN);
    assert_eq!(refused["ok"], false);
    assert!(needs_approval(refused["error"].as_str().unwrap()));
    let filing = json!({"op": "areq_file", "subject": tunnel_subject(TOKEN)});
    let (a, seen, lines, offered) = approve_while_waiting(&r, &filing, "tunnel-token");
    assert!(!offered);
    assert!(lines[0].contains("Only the dashboard approves this change"));
    let word = ozbox_core::approval_subject::request_word(&a.id);
    // another token, or a gate that sent no digest, is refused; the request stays approved
    let swapped = tunnel_gate(&r, &word, "token-b-bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb");
    assert_eq!(swapped["ok"], false, "{swapped}");
    let older = r.raw(
        Policy::Admin,
        &json!({"op":"gate","scope":"tunnel-token","project":"cloudflare",
            "env": crate::secrets_approval::tunnel_token_binding(TOKEN), "approval": word}),
    );
    assert_eq!(older["ok"], false, "{older}");
    let ok = tunnel_gate(&r, &word, TOKEN);
    assert_eq!(ok["ok"], true, "{ok}");
    assert_eq!(ok["value"], "request:authenticator");
    // spent: the same word does not pass twice
    assert_eq!(tunnel_gate(&r, &word, TOKEN)["ok"], false);
    // sentinel: the token is nowhere outside the helper's own memory
    let list = r.raw(
        Policy::Supervisor,
        &json!({"op":"areq_list","role":"owner"}),
    );
    for s in seen
        .iter()
        .chain(lines.iter())
        .chain(std::iter::once(&list.to_string()))
    {
        assert!(!s.contains(TOKEN), "{s}");
    }
    assert!(!r.on_disk().contains(TOKEN), "the token reached a file");
}

/// `ozbox box-secrets` on a provider with no instance tags: the request is bound to the declaration's binding (and so its vault
/// address), approved on the dashboard, and the gate takes it for that declaration only. A removal is its own request.
#[test]
fn a_box_secrets_declaration_is_approved_in_the_dashboard_and_bound_to_its_address() {
    let r = rig();
    let bind = "d-0123456789abcdef";
    assert!(needs_approval(
        declaration_gate(&r, "", bind)["error"].as_str().unwrap()
    ));
    let subject =
        ozbox_core::approval_subject::gate_subject("box-secrets", "declaration", bind, "").unwrap();
    let (a, _, lines, offered) = approve_while_waiting(
        &r,
        &json!({"op":"areq_file","subject":subject}),
        "box-secrets",
    );
    assert!(!offered && lines[0].contains("Only the dashboard"));
    let word = ozbox_core::approval_subject::request_word(&a.id);
    // another declaration (another vault address) is refused, and the approval kept
    assert_eq!(
        declaration_gate(&r, &word, "d-fedcba9876543210")["ok"],
        false
    );
    // the removal is not the setting
    assert_eq!(declaration_gate(&r, &word, "")["ok"], false);
    let ok = declaration_gate(&r, &word, bind);
    assert_eq!(ok["ok"], true, "{ok}");
    // a removal by request (decided here by root: one authenticator time step decides once, and the owner just used it)
    let rm =
        ozbox_core::approval_subject::gate_subject("box-secrets", "declaration", "", "").unwrap();
    let id = r.laptop(&json!({"op":"areq_file","subject":rm})).unwrap()["request"]["id"]
        .as_str()
        .unwrap()
        .to_string();
    let d = r.raw(
        Policy::Admin,
        &json!({"op":"areq_decide","id":id,"outcome":"approve"}),
    );
    assert_eq!(d["ok"], true, "{d}");
    let ok = declaration_gate(&r, &ozbox_core::approval_subject::request_word(&id), "");
    assert_eq!(ok["ok"], true, "{ok}");
}

/// A key kept on a computer never decides a declaration, a tunnel token or the box's own secrets on the request path (the
/// box's rule, as for Production), and its refusal names the dashboard.
#[test]
fn a_laptop_key_is_refused_for_every_dashboard_only_act_with_the_dashboard_named() {
    let r = rig();
    let (seed, public) = crate::approval_key::generate().unwrap();
    let e = r.raw(
        Policy::Admin,
        &json!({"op":"approval_key_enroll","key_id":"laptop","public_key":public}),
    );
    assert_eq!(e["ok"], true, "{e}");
    let filings = [
        policy_filing(&declaration("t")),
        json!({"op":"areq_file","subject":tunnel_subject(TOKEN)}),
        json!({"op":"areq_file","subject":ozbox_core::approval_subject::gate_subject("box-secrets","declaration","d-0123456789abcdef","").unwrap()}),
    ];
    for f in filings {
        let id = r.laptop(&f).unwrap()["request"]["id"]
            .as_str()
            .unwrap()
            .to_string();
        let ch = r
            .laptop(&json!({"op":"areq_decide_challenge","id":id,"outcome":"approve"}))
            .unwrap();
        let message = format!(
            "{}\n{}",
            ozbox_core::approval_subject::DECIDE_MESSAGE_HEAD,
            ch["challenge"].as_str().unwrap()
        );
        let signature = crate::approval_key::sign(&seed, &message).unwrap();
        let x = r.laptop(&json!({
            "op": "areq_decide", "id": id, "outcome": "approve", "key_id": "laptop",
            "evidence": {"laptop": {"key_id": "laptop", "key_type": "ed25519", "signature_format": "ed25519-message",
                "signed_message": ozbox_core::audit::hex(message.as_bytes()), "signature": signature}},
        }));
        let why = x.unwrap_err();
        assert!(why.contains("dashboard"), "{f}: {why}");
    }
}

/// The wait ends cleanly: nothing is saved, the request stays pending for the dashboard, and Ctrl-C does the same.
#[test]
fn a_declaration_wait_times_out_cleanly_and_saves_nothing() {
    let r = rig();
    let text = declaration("t");
    let clock = RefCell::new(0u64);
    let mut call = |v: &Value| {
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
    let e = file_and_wait_with(&mut flow, &policy_filing(&text), "policy", false, "x")
        .unwrap_err()
        .to_string();
    assert!(e.contains("No decision within 2 minutes"), "{e}");
    let list = r.raw(
        Policy::Supervisor,
        &json!({"op":"areq_list","role":"owner"}),
    );
    assert_eq!(list["result"]["requests"][0]["state"], "pending");
    assert!(crate::workload_policy::load(r.store.as_ref(), "app")
        .unwrap()
        .is_none());
    // Ctrl-C before the first poll: the same, and said so
    let stop = AtomicBool::new(true);
    let mut call = |v: &Value| r.laptop(v);
    let mut say = |_: &str| {};
    let mut flow = Flow {
        call: &mut call,
        say: &mut say,
        inline: None,
        elapsed_ms: &|| 0,
        stop: &stop,
        max_wait_ms: 60_000,
    };
    let e = file_and_wait_with(&mut flow, &policy_filing(&text), "policy", false, "x")
        .unwrap_err()
        .to_string();
    assert!(e.contains("Stopped waiting") && e.contains("Nothing was changed"));
}

/// The box user (any agent on the box) can file none of these acts, decide none, spend none at the gate, and read no token:
/// the request path adds nothing to what it can reach.
#[test]
fn an_agent_cannot_file_decide_spend_or_read_any_of_these_acts() {
    let r = rig();
    // the person's own request, approved on the dashboard
    let (a, _, _, _) = approve_while_waiting(
        &r,
        &json!({"op":"areq_file","subject":tunnel_subject(TOKEN)}),
        "tunnel-token",
    );
    let word = ozbox_core::approval_subject::request_word(&a.id);
    let pending = r.laptop(&policy_filing(&declaration("t"))).unwrap()["request"]["id"]
        .as_str()
        .unwrap()
        .to_string();
    let mut answers = Vec::new();
    for policy in [Policy::Box, Policy::BoxLocked] {
        for v in [
            json!({"op":"areq_file","subject":tunnel_subject(TOKEN)}),
            json!({"op":"areq_file","subject":ozbox_core::approval_subject::gate_subject("box-secrets","declaration","","").unwrap()}),
            policy_filing(&declaration("t")),
            json!({"op":"areq_decide","id":pending,"outcome":"approve","person":"alice","role":"owner",
                "surface":"dashboard","factor":"authenticator","code":code_now()}),
            json!({"op":"gate","scope":"tunnel-token","project":"cloudflare","approval":word,
                "token_sha256": ozbox_core::approval_subject::tunnel_token_sha256(TOKEN)}),
            json!({"op":"policy","project":"app","text":declaration("t"),"request_id":pending}),
            json!({"op":"get","name":"tunnel-token-cloudflare"}),
            json!({"op":"get","name":"totp-alice"}),
        ] {
            let out = r.raw(policy, &v);
            assert_eq!(out["ok"], false, "{policy:?} {v}");
            answers.push(out.to_string());
        }
    }
    // the person's request is still theirs to spend, at the root helper's gate
    assert_eq!(tunnel_gate(&r, &word, TOKEN)["ok"], true);
    for s in &answers {
        assert!(!s.contains(TOKEN) && !s.contains(SENTINEL), "{s}");
        assert!(!s.contains(super::tests::TOTP_SECRET), "{s}");
    }
}
