//! A box's role gets every permission from a customer-managed policy `ozbox init` made once, which the module only attaches.
//! The daily operator role is denied `iam:PutRolePolicy` (and cannot create a policy or a credential) on purpose, so a module
//! that planned an inline role policy would pass its plan and then fail partway through an upgrade, after the box was stopped.
//! This reads the module's source, so adding one fails here, in CI, before it can reach a person's box.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::path::Path;

/// Resource types the operator cannot apply. Matches `UNAPPLIABLE_TYPES` in the adapter, which refuses such a plan before an
/// upgrade stops anything.
const OPERATOR_CANNOT_APPLY: &[&str] = &[
    "aws_iam_role_policy",
    "aws_iam_policy",
    "aws_iam_policy_attachment",
    "aws_iam_user",
    "aws_iam_user_policy",
    "aws_iam_user_policy_attachment",
    "aws_iam_access_key",
    "aws_iam_group",
    "aws_iam_group_policy",
    "aws_iam_group_policy_attachment",
];

fn tf_files(dir: &Path) -> Vec<(String, String)> {
    std::fs::read_dir(dir)
        .unwrap()
        .filter_map(Result::ok)
        .map(|e| e.path())
        .filter(|p| p.extension().is_some_and(|x| x == "tf"))
        .map(|p| {
            (
                p.display().to_string(),
                std::fs::read_to_string(&p).unwrap(),
            )
        })
        .collect()
}

#[test]
fn the_box_module_has_no_resource_the_operator_role_cannot_apply() {
    let dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../infra/tofu/modules/aws-box");
    let files = tf_files(&dir);
    assert!(!files.is_empty());
    for (name, text) in files {
        for line in text.lines().map(str::trim_start) {
            // a real declaration, not a comment that names the type
            if let Some(rest) = line.strip_prefix("resource \"") {
                let ty = rest.split('"').next().unwrap_or("");
                assert!(
                    !OPERATOR_CANNOT_APPLY.contains(&ty),
                    "{name} declares {ty}, which the operator role cannot apply (it is denied iam:PutRolePolicy and cannot create a policy): make it a customer-managed policy in aws-box-policy and attach it"
                );
            }
        }
    }
}

#[test]
fn the_attachments_the_module_makes_are_the_ones_the_operator_policy_allows() {
    let dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../infra/tofu/modules/aws-box");
    let text: String = tf_files(&dir).into_iter().map(|(_, t)| t).collect();
    let policy: serde_json::Value = serde_json::from_str(
        &std::fs::read_to_string(
            Path::new(env!("CARGO_MANIFEST_DIR")).join("../../infra/aws/operator-policy.json"),
        )
        .unwrap(),
    )
    .unwrap();
    let allowed: String = policy.to_string();
    // every policy name the module attaches appears in the operator's allowed ARNs
    for name in [
        "ozbox-box-session-manager",
        "ozbox-box-parameters",
        "ozbox-box-parameters-key",
        "ozbox-box-session-logs",
        "ozbox-box-notify",
        "ozbox-box-fleet-key-",
    ] {
        assert!(text.contains(name), "the module no longer names {name}");
        assert!(
            allowed.contains(name),
            "the operator policy cannot attach {name}"
        );
    }
}

/// swapping the Session Manager policy replaces `ssm_core`. It is created before the old one goes, and the
/// machine waits for every attachment, so the role is never without Session Manager while a new agent registers.
#[test]
fn the_session_manager_attachment_is_swapped_create_before_destroy_and_the_instance_waits_for_it() {
    let dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../infra/tofu/modules/aws-box");
    let text: String = tf_files(&dir).into_iter().map(|(_, t)| t).collect();
    let attach = text
        .split("resource \"aws_iam_role_policy_attachment\" \"ssm_core\"")
        .nth(1)
        .unwrap();
    let attach = &attach[..attach.find("\nresource ").unwrap_or(attach.len())];
    assert!(attach.contains("create_before_destroy = true"));
    let instance = text
        .split("resource \"aws_instance\" \"box\"")
        .nth(1)
        .unwrap();
    let instance = &instance[..instance.find("ami ").unwrap()];
    assert!(instance.contains("depends_on"));
    assert!(instance.contains("aws_iam_role_policy_attachment.ssm_core"));
}
