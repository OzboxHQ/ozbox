//! `infra/aws/box-policy-admin-policy.json` (`OzBoxPolicyAdmin`): what the SETUP identity needs for `ozbox init` to make the
//! account's Session Manager policy for boxes (ADR 0029, Amendment 9). The daily operator role never has it.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::path::Path;

use serde_json::Value;

fn policy() -> Value {
    let p =
        Path::new(env!("CARGO_MANIFEST_DIR")).join("../../infra/aws/box-policy-admin-policy.json");
    serde_json::from_str(&std::fs::read_to_string(p).expect("the policy file")).expect("valid JSON")
}

fn list(v: &Value) -> Vec<String> {
    match v {
        Value::String(s) => vec![s.clone()],
        Value::Array(a) => a.iter().map(|x| x.as_str().unwrap().to_string()).collect(),
        _ => panic!("strings"),
    }
}

#[test]
fn it_may_make_only_policies_named_ozbox_box_and_attach_nothing() {
    let doc = policy();
    assert_eq!(doc["Version"], "2012-10-17");
    let st = doc["Statement"].as_array().unwrap();
    let mut saw_allow = false;
    for s in st {
        let actions = list(&s["Action"]);
        if s["Effect"] == "Allow" {
            saw_allow = true;
            // only IAM policy bookkeeping, no wildcard, and only on the box-managed prefix
            for a in &actions {
                assert!(a.starts_with("iam:") && !a.contains('*'), "{a}");
                assert!(
                    a.ends_with("Policy")
                        || a.contains("PolicyVersion")
                        || a.contains("PolicyVersions")
                        || a.contains("PolicyTags"),
                    "{a}"
                );
            }
            assert_eq!(
                list(&s["Resource"]),
                ["arn:aws:iam::${account_id}:policy/ozbox-box-*"]
            );
            // it cannot be used to attach the policy to anything, or to make a role that carries it
            for bad in [
                "iam:AttachRolePolicy",
                "iam:PutRolePolicy",
                "iam:CreateRole",
                "iam:DeletePolicy",
            ] {
                assert!(!actions.iter().any(|a| a == bad), "{bad}");
            }
        } else {
            assert_eq!(s["Effect"], "Deny");
            for must in [
                "iam:AttachRolePolicy",
                "iam:PutRolePolicy",
                "iam:CreateRole",
            ] {
                assert!(actions.iter().any(|a| a == must), "{must} must be denied");
            }
        }
    }
    assert!(saw_allow);
}

#[test]
fn it_is_public_safe() {
    let text = serde_json::to_string(&policy()).unwrap();
    assert!(!text.contains("arn:aws:iam::1") && !text.contains("AKIA"));
    assert!(text.contains("${account_id}"));
}
