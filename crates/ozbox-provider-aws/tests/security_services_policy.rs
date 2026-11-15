#![allow(clippy::unwrap_used)]
//! The extra permissions for the opt-in security services (`ozbox harden`) are narrow, and never let anyone read, delete or
//! unlock a session log: nothing allows it, a Deny refuses it, and the bucket's own policy (pinned by the module's tests)
//! refuses to be replaced. The operator policy itself is unchanged: this one is attached only by someone who opts in.

use serde_json::Value;

fn statements() -> Vec<Value> {
    let text = include_str!("../../../infra/aws/security-services-policy.json");
    let v: Value = serde_json::from_str(text).unwrap();
    v["Statement"].as_array().unwrap().clone()
}

fn strings(v: &Value) -> Vec<String> {
    match v {
        Value::String(s) => vec![s.clone()],
        Value::Array(a) => a
            .iter()
            .filter_map(|x| x.as_str().map(str::to_string))
            .collect(),
        _ => vec![],
    }
}

#[test]
fn nothing_is_allowed_on_everything_for_iam_or_s3_and_no_action_is_a_wildcard() {
    for s in statements() {
        for a in strings(&s["Action"]) {
            assert!(!a.ends_with(":*") && a != "*", "{a}");
            if a.starts_with("iam:") {
                assert_eq!(a, "iam:CreateServiceLinkedRole");
            }
        }
        if strings(&s["Action"])
            .iter()
            .any(|a| a.starts_with("s3:") || a.starts_with("iam:"))
        {
            assert!(
                !strings(&s["Resource"]).iter().any(|r| r == "*"),
                "{}",
                s["Sid"]
            );
        }
    }
}

fn allows() -> Vec<Value> {
    statements()
        .into_iter()
        .filter(|s| s["Effect"] == "Allow")
        .collect()
}

#[test]
fn the_logs_can_be_neither_read_nor_deleted_nor_unlocked_by_this_policy() {
    for s in allows() {
        for a in strings(&s["Action"]) {
            for bad in [
                "s3:GetObject",
                "s3:DeleteObject",
                "s3:DeleteObjectVersion",
                "s3:BypassGovernanceRetention",
                "s3:PutObject",
                "s3:PutObjectRetention",
                "s3:PutObjectLegalHold",
                "s3:DeleteBucketPolicy",
                "s3:DeleteBucket",
            ] {
                assert_ne!(a, bad, "{}", s["Sid"]);
            }
        }
    }
}

#[test]
fn and_it_denies_unlocking_or_removing_a_log_outright_whatever_else_is_attached() {
    // a Deny in the attached policy wins over an Allow from any other policy the same principal holds
    let deny: Vec<Value> = statements()
        .into_iter()
        .filter(|s| s["Effect"] == "Deny")
        .collect();
    assert_eq!(deny.len(), 1);
    let actions = strings(&deny[0]["Action"]);
    for a in [
        "s3:BypassGovernanceRetention",
        "s3:DeleteObjectVersion",
        "s3:DeleteBucketPolicy",
        "s3:DeleteBucket",
        "s3:PutObjectRetention",
    ] {
        assert!(actions.iter().any(|x| x == a), "{a}");
    }
    assert_eq!(
        strings(&deny[0]["Resource"]),
        [
            "arn:aws:s3:::ozbox-sessionlogs-*",
            "arn:aws:s3:::ozbox-sessionlogs-*/*"
        ]
    );
    // it can still write the bucket policy once, at creation; the bucket policy itself then denies changing it
    assert!(allows().iter().any(|s| strings(&s["Action"])
        .iter()
        .any(|a| a == "s3:PutBucketPolicy")));
}

#[test]
fn s3_is_limited_to_the_session_log_buckets_and_ssm_to_oz_boxs_own_documents() {
    for s in allows() {
        let actions = strings(&s["Action"]);
        if actions.iter().any(|a| a.starts_with("s3:")) {
            assert_eq!(
                strings(&s["Resource"]),
                ["arn:aws:s3:::ozbox-sessionlogs-*"]
            );
        }
        if actions.iter().any(|a| a == "ssm:CreateDocument") {
            for r in strings(&s["Resource"]) {
                assert!(
                    r.ends_with("document/SSM-SessionManagerRunShell")
                        || r.ends_with("document/ozbox-*"),
                    "{r}"
                );
            }
        }
    }
}

#[test]
fn the_policy_names_only_a_placeholder_account() {
    let text = include_str!("../../../infra/aws/security-services-policy.json");
    assert!(text.contains("${account_id}"));
    let digits: Vec<&str> = text
        .split(|c: char| !c.is_ascii_digit())
        .filter(|d| d.len() == 12)
        .collect();
    assert!(digits.is_empty(), "{digits:?}");
}
