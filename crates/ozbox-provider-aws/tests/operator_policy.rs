//! The operator permission policy (`infra/aws/operator-policy.json`) is code: these tests pin the invariants that make
//! it least privilege, and that it still covers every call the AWS adapter and the CLI make.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::collections::BTreeSet;
use std::path::Path;

use serde_json::Value;

fn policy() -> Value {
    let p = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../infra/aws/operator-policy.json");
    let text = std::fs::read_to_string(p).expect("infra/aws/operator-policy.json");
    serde_json::from_str(&text).expect("the policy is valid JSON")
}

fn strings(v: Option<&Value>) -> Vec<String> {
    match v {
        None => Vec::new(),
        Some(Value::String(s)) => vec![s.clone()],
        Some(Value::Array(a)) => a
            .iter()
            .map(|x| x.as_str().expect("strings only").to_string())
            .collect(),
        Some(other) => panic!("expected a string or an array, found {other}"),
    }
}

struct Stmt {
    sid: String,
    allow: bool,
    actions: Vec<String>,
    resources: Vec<String>,
    condition: Option<Value>,
}

fn statements() -> Vec<Stmt> {
    let doc = policy();
    assert_eq!(doc["Version"], "2012-10-17");
    doc["Statement"]
        .as_array()
        .expect("Statement is a list")
        .iter()
        .map(|s| {
            assert!(
                s.get("NotAction").is_none()
                    && s.get("NotResource").is_none()
                    && s.get("Principal").is_none(),
                "no NotAction, NotResource or Principal"
            );
            Stmt {
                sid: s["Sid"]
                    .as_str()
                    .expect("every statement has a Sid")
                    .to_string(),
                allow: match s["Effect"].as_str() {
                    Some("Allow") => true,
                    Some("Deny") => false,
                    other => panic!("bad effect {other:?}"),
                },
                actions: strings(s.get("Action")),
                resources: strings(s.get("Resource")),
                condition: s.get("Condition").cloned(),
            }
        })
        .collect()
}

fn read_only(action: &str) -> bool {
    let name = action.split(':').nth(1).unwrap_or("");
    ["Describe", "Get", "List"]
        .iter()
        .any(|p| name.starts_with(p))
}

/// IAM action matching: `*` wildcards, case-insensitive.
fn matches(pattern: &str, action: &str) -> bool {
    let (p, a) = (pattern.to_ascii_lowercase(), action.to_ascii_lowercase());
    match p.split_once('*') {
        None => p == a,
        Some((head, tail)) => {
            a.starts_with(head) && a.ends_with(tail) && a.len() >= head.len() + tail.len()
        }
    }
}

fn allowed(action: &str) -> bool {
    statements()
        .iter()
        .any(|s| s.allow && s.actions.iter().any(|p| matches(p, action)))
}

fn cond_has(s: &Stmt, key: &str) -> bool {
    s.condition
        .as_ref()
        .and_then(Value::as_object)
        .is_some_and(|ops| ops.values().any(|m| m.get(key).is_some()))
}

fn cond_value(s: &Stmt, key: &str) -> Vec<String> {
    s.condition
        .as_ref()
        .and_then(Value::as_object)
        .and_then(|ops| ops.values().find_map(|m| m.get(key)))
        .map(|v| strings(Some(v)))
        .unwrap_or_default()
}

#[test]
fn statements_are_well_formed_and_public_safe() {
    let all = statements();
    let sids: BTreeSet<_> = all.iter().map(|s| s.sid.clone()).collect();
    assert_eq!(sids.len(), all.len(), "Sids are unique");
    let text = std::fs::read_to_string(
        Path::new(env!("CARGO_MANIFEST_DIR")).join("../../infra/aws/operator-policy.json"),
    )
    .unwrap();
    // the template variables are the account, the region and the fleet; no real account id, key or address is written in
    let mut vars = BTreeSet::new();
    let mut rest = text.as_str();
    while let Some(i) = rest.find("${") {
        let end = rest[i..].find('}').unwrap() + i;
        vars.insert(rest[i..=end].to_string());
        rest = &rest[end..];
    }
    assert_eq!(
        vars,
        BTreeSet::from([
            "${account_id}".to_string(),
            "${aws:username}".to_string(),
            "${fleet}".to_string(),
            "${region}".to_string(),
        ]),
        "only the account, region and fleet placeholders and one IAM policy variable"
    );
    let digits: Vec<char> = text.chars().collect();
    let mut run = 0;
    for c in digits {
        run = if c.is_ascii_digit() { run + 1 } else { 0 };
        assert!(run < 12, "no 12-digit account id in the policy");
    }
}

#[test]
fn every_ec2_write_is_tag_conditioned() {
    for s in statements().iter().filter(|s| s.allow) {
        let writes: Vec<&String> = s
            .actions
            .iter()
            .filter(|a| {
                (a.starts_with("ec2:") || a.starts_with("ec2-instance-connect:")) && !read_only(a)
            })
            .collect();
        if writes.is_empty() {
            continue;
        }
        let tagged = cond_has(s, "aws:RequestTag/ozbox-managed")
            || cond_has(s, "aws:ResourceTag/ozbox-managed")
            || cond_has(s, "ec2:CreateAction");
        // The one documented exception: RunInstances reads an image and creates the volume and network interface of
        // the instance it launches; those carry no tag of ours to test. The instance itself, the subnet and the
        // security group stay conditioned in their own statements.
        let base_resources = s.actions == ["ec2:RunInstances"]
            && s.resources.iter().all(|r| {
                r.contains(":image/") || r.contains(":network-interface/") || r.contains(":volume/")
            });
        assert!(
            tagged || base_resources,
            "{}: an ec2 write ({writes:?}) without a tag condition",
            s.sid
        );
    }
}

#[test]
fn tagging_is_only_on_create_or_on_our_resources() {
    for s in statements()
        .iter()
        .filter(|s| s.allow && s.actions.iter().any(|a| a == "ec2:CreateTags"))
    {
        assert!(
            cond_has(s, "ec2:CreateAction") || cond_has(s, "aws:ResourceTag/ozbox-managed"),
            "{}: CreateTags needs ec2:CreateAction or an ozbox-managed resource tag",
            s.sid
        );
    }
    // CreateTags never rides in the create statement, where it would tag anything on a request tag alone
    for s in statements()
        .iter()
        .filter(|s| s.allow && cond_has(s, "aws:RequestTag/ozbox-managed"))
    {
        assert!(
            !s.actions.iter().any(|a| a == "ec2:CreateTags"),
            "{}",
            s.sid
        );
    }
}

#[test]
fn no_allow_on_every_resource_for_iam_or_s3() {
    for s in statements().iter().filter(|s| s.allow) {
        if s.actions
            .iter()
            .any(|a| a.starts_with("iam:") || a.starts_with("s3:"))
        {
            assert!(
                !s.resources.is_empty()
                    && s.resources.iter().all(|r| r != "*" && !r.ends_with(":*")),
                "{}: iam and s3 actions must be scoped to named resources",
                s.sid
            );
        }
        // and no statement mixes iam or s3 with other services
        let services: BTreeSet<&str> = s
            .actions
            .iter()
            .filter_map(|a| a.split(':').next())
            .collect();
        assert!(
            !(services.contains("iam") || services.contains("s3")) || services.len() == 1,
            "{}: iam and s3 live in statements of their own",
            s.sid
        );
    }
}

#[test]
fn iam_is_limited_to_ozbox_named_roles_and_profiles() {
    for s in statements()
        .iter()
        .filter(|s| s.allow && s.actions.iter().any(|a| a.starts_with("iam:")))
    {
        for r in &s.resources {
            assert!(
                r == "arn:aws:iam::${account_id}:role/ozbox-*"
                    || r == "arn:aws:iam::${account_id}:instance-profile/ozbox-*"
                    // the one read of the account's Session Manager policy, which the module looks up before attaching it
                    || (r == "arn:aws:iam::${account_id}:policy/ozbox-box-*"
                        && s.actions.iter().all(|a| matches!(a.as_str(), "iam:GetPolicy" | "iam:GetPolicyVersion"))),
                "{}: {r}",
                s.sid
            );
        }
        assert!(
            !s.actions.iter().any(|a| matches!(
                a.as_str(),
                "iam:PutRolePolicy" | "iam:CreateUser" | "iam:CreateAccessKey" | "iam:*"
            )),
            "{}",
            s.sid
        );
    }
    // Only the account's own box policies (made once by `ozbox init` with the setup identity): AWS's AmazonSSMManagedInstanceCore
    // grants ssm:GetParameter(s) on every parameter in the account, and the operator can neither create nor change a policy or
    // put an inline one, so what a box's role may do cannot be widened from here (ADR 0029, Amendment 9).
    let attach: Vec<Stmt> = statements()
        .into_iter()
        .filter(|s| s.actions == ["iam:AttachRolePolicy"])
        .collect();
    assert_eq!(
        attach.len(),
        2,
        "one statement of exact ARNs, one for the fleet-key policy"
    );
    let mut arns: Vec<String> = attach
        .iter()
        .flat_map(|s| cond_value(s, "iam:PolicyARN"))
        .collect();
    arns.sort();
    assert_eq!(
        arns,
        [
            "arn:aws:iam::${account_id}:policy/ozbox-box-fleet-key-*",
            "arn:aws:iam::${account_id}:policy/ozbox-box-parameters",
            "arn:aws:iam::${account_id}:policy/ozbox-box-parameters-key",
            "arn:aws:iam::${account_id}:policy/ozbox-box-session-logs",
            "arn:aws:iam::${account_id}:policy/ozbox-box-session-manager",
        ],
        "only the account's own box policies may be attached"
    );
    assert!(
        !arns
            .iter()
            .any(|a| a.contains("arn:aws:iam::aws:") || a.ends_with(":policy/*")),
        "never an AWS-managed policy or a wildcard"
    );
    for s in statements().iter().filter(|s| s.allow) {
        assert!(
            !s.actions.iter().any(|a| matches!(
                a.as_str(),
                "iam:CreatePolicy"
                    | "iam:CreatePolicyVersion"
                    | "iam:SetDefaultPolicyVersion"
                    | "iam:DeletePolicy"
                    | "iam:PutRolePolicy"
                    | "iam:DeleteRolePolicy"
            )),
            "{}: the operator must not create or change a managed policy or put an inline one",
            s.sid
        );
    }
    let pass = statements()
        .into_iter()
        .find(|s| s.actions == ["iam:PassRole"])
        .unwrap();
    assert_eq!(
        cond_value(&pass, "iam:PassedToService"),
        ["ec2.amazonaws.com"]
    );
    assert_eq!(pass.resources, ["arn:aws:iam::${account_id}:role/ozbox-*"]);
}

#[test]
fn s3_is_limited_to_state_buckets() {
    for s in statements()
        .iter()
        .filter(|s| s.allow && s.actions.iter().any(|a| a.starts_with("s3:")))
    {
        for r in &s.resources {
            assert!(
                r.starts_with("arn:aws:s3:::ozbox-tfstate-"),
                "{}: {r}",
                s.sid
            );
        }
    }
}

#[test]
fn the_deny_block_is_present_and_nothing_allows_what_it_denies() {
    let all = statements();
    let deny: Vec<&Stmt> = all.iter().filter(|s| !s.allow).collect();
    assert!(!deny.is_empty(), "an explicit Deny block exists");
    let denied: BTreeSet<String> = deny.iter().flat_map(|s| s.actions.clone()).collect();
    for must in [
        "iam:CreateUser",
        "iam:CreateAccessKey",
        "iam:PutRolePolicy",
        "iam:PutUserPolicy",
        "iam:AttachUserPolicy",
        "organizations:*",
        "sso:*",
        "account:*",
        "ec2:AuthorizeSecurityGroupIngress",
    ] {
        assert!(denied.contains(must), "{must} must be denied");
    }
    // the one scoped deny is the reserved obx role namespace (its own test below); every other deny applies to everything
    assert!(
        deny.iter()
            .filter(|s| s.sid != RESERVED_DENY)
            .all(|s| s.resources == ["*"]),
        "denies apply to everything"
    );
    let denied: BTreeSet<String> = deny
        .iter()
        .filter(|s| s.sid != RESERVED_DENY)
        .flat_map(|s| s.actions.clone())
        .collect();
    for s in all.iter().filter(|s| s.allow) {
        for a in &s.actions {
            assert!(
                !a.contains('*') || read_only(a) || a == "ec2:Describe*",
                "{}: a wildcard allow ({a}) outside the read-only set",
                s.sid
            );
            for d in &denied {
                assert!(
                    !matches(d, a) || read_only(a),
                    "{}: allows {a}, which is denied",
                    s.sid
                );
            }
        }
    }
    // inbound is never opened: no ingress action is allowed at all
    assert!(!allowed("ec2:AuthorizeSecurityGroupIngress"));
    assert!(!allowed("ec2:ModifySecurityGroupRules"));
    assert!(!allowed("ec2:CreateNetworkAclEntry"));
}

#[test]
fn sessions_and_key_pushes_reach_only_ozbox_instances() {
    let all = statements();
    for s in all
        .iter()
        .filter(|s| s.allow && s.actions.iter().any(|a| a == "ssm:StartSession"))
    {
        let on_instances = s.resources.iter().all(|r| r.contains(":instance/"));
        let docs: Vec<&String> = s
            .resources
            .iter()
            .filter(|r| r.contains(":document/"))
            .collect();
        if on_instances {
            assert!(cond_has(s, "aws:ResourceTag/ozbox-managed"), "{}", s.sid);
        } else {
            assert_eq!(docs.len(), s.resources.len(), "{}: documents only", s.sid);
            assert!(
                docs.iter()
                    .all(|d| d.ends_with("document/AWS-StartSSHSession")
                        || d.ends_with("document/SSM-SessionManagerRunShell")),
                "{}",
                s.sid
            );
        }
    }
    let own = all
        .iter()
        .find(|s| s.actions.iter().any(|a| a == "ssm:TerminateSession"))
        .unwrap();
    assert!(
        own.resources
            .iter()
            .all(|r| r.ends_with("session/${aws:username}-*")),
        "only the caller's own sessions"
    );
    assert_eq!(own.actions.len(), 2);
    let eic = all
        .iter()
        .find(|s| s.actions == ["ec2-instance-connect:SendSSHPublicKey"])
        .unwrap();
    assert!(cond_has(eic, "aws:ResourceTag/ozbox-managed"));
    assert_eq!(
        cond_value(eic, "ec2:osuser"),
        ["ozbox", "ozbox-ingress"],
        "only the box user and the ingress account (the account's forced command runs one program; neither is root)"
    );
}

#[test]
fn it_covers_what_the_cli_and_the_adapter_do() {
    // From the AWS adapter, the box and network modules, `ozbox connect --ssh` and the plan-time quota check.
    for action in [
        "ec2:DescribeInstances",
        "ec2:DescribeVolumes",
        "ec2:DescribeVolumesModifications",
        "ec2:DescribeSnapshots",
        "ec2:DescribeInstanceTypes",
        "ec2:StopInstances",
        "ec2:StartInstances",
        "ec2:ModifyInstanceAttribute",
        "ec2:ModifyVolume",
        "ec2:CreateSnapshot",
        "ec2:DeleteSnapshot",
        "ec2:CreateTags",
        "ec2:DeleteTags",
        "ec2:RunInstances",
        "ec2:TerminateInstances",
        "ec2:CreateVolume",
        "ec2:AttachVolume",
        // A /work restore detaches the old disk and keeps it; deleting it is its own confirmed action.
        "ec2:DetachVolume",
        "ec2:DeleteVolume",
        "ec2:CreateVpc",
        "ec2:CreateSubnet",
        "ec2:CreateNatGateway",
        "ec2:CreateRoute",
        "ec2:AssociateRouteTable",
        "ec2:AuthorizeSecurityGroupEgress",
        "servicequotas:GetServiceQuota",
        "sts:GetCallerIdentity",
        "ssm:GetParameter",
        "ssm:StartSession",
        "ec2-instance-connect:SendSSHPublicKey",
        "iam:CreateRole",
        "iam:CreateInstanceProfile",
        "iam:AttachRolePolicy",
        "iam:PassRole",
        "s3:GetObject",
        "s3:PutObject",
        "pricing:GetProducts",
        // `ozbox cost bill` and the Bill page: the real bill, read-only, and the check that the tag is a
        // cost-allocation tag
        "ce:GetCostAndUsage",
        "ce:GetTags",
    ] {
        assert!(allowed(action), "{action} is used but not allowed");
    }
}

#[test]
fn reading_the_bill_is_exactly_two_read_only_cost_explorer_actions() {
    let all = statements();
    let ce: Vec<(&str, &str)> = all
        .iter()
        .filter(|s| s.allow)
        .flat_map(|s| s.actions.iter().map(move |a| (s.sid.as_str(), a.as_str())))
        .filter(|(_, a)| a.starts_with("ce:") || a.starts_with("billing:") || a.starts_with("cur:"))
        .collect();
    let mut got: Vec<&str> = ce.iter().map(|(_, a)| *a).collect();
    got.sort_unstable();
    assert_eq!(got, ["ce:GetCostAndUsage", "ce:GetTags"]);
    // nothing that reads the bill can change it: no wildcard, no Create/Update/Delete/Start verbs
    for (sid, a) in &ce {
        assert!(
            read_only(a) && !a.contains('*'),
            "{sid}: {a} must be a plain read"
        );
    }
    // and the deletes behind "Delete forgotten resources" are the ones already tied to the ozbox-managed tag
    for action in ["ec2:DeleteVolume", "ec2:DeleteSnapshot"] {
        let stmts: Vec<&Stmt> = all
            .iter()
            .filter(|s| s.allow && s.actions.iter().any(|a| a == action))
            .collect();
        assert!(
            !stmts.is_empty(),
            "{action} is needed to delete a forgotten disk or snapshot"
        );
        assert!(
            stmts
                .iter()
                .all(|s| cond_value(s, "aws:ResourceTag/ozbox-managed") == ["true"]),
            "{action} must only reach resources tagged ozbox-managed"
        );
    }
    // an unsigned or failed image is listed, not deleted from here: no deregister right is given
    assert!(!allowed("ec2:DeregisterImage"));
}

/// A clone or restore makes its /work disk from a snapshot. AWS checks `ec2:CreateVolume` on the source snapshot too,
/// where a request-tag condition can never hold (the snapshot already exists), so the snapshot needs its own statement:
/// only snapshots Oz Box tagged as its own. Found by the first real clone (CreateVolume denied on the snapshot).
#[test]
fn a_disk_can_be_made_only_from_our_own_snapshots() {
    let found = statements().into_iter().any(|s| {
        s.actions.iter().any(|a| a == "ec2:CreateVolume")
            && s.resources.iter().any(|r| r == "arn:aws:ec2:*::snapshot/*")
            && cond_value(&s, "aws:ResourceTag/ozbox-managed") == vec!["true".to_string()]
    });
    assert!(
        found,
        "no statement lets CreateVolume use an Oz Box snapshot"
    );
}

const RESERVED_DENY: &str = "NeverTouchTheReservedObxRoles";

/// ADR 0040 section 3.1 and ADR 0029 NH1: roles in the reserved namespace (path `/obx/`, name `obx-*`: the issuer's two
/// roles) are not the daily operator's to change, pass or put in a profile. The Deny is explicit because the Allow side
/// covers `role/ozbox-*` and a mistake in the pattern must still lose.
#[test]
fn the_operator_cannot_change_pass_or_profile_a_reserved_obx_role() {
    let all = statements();
    let deny = all
        .iter()
        .find(|s| s.sid == RESERVED_DENY)
        .expect("the reserved-namespace deny exists");
    assert!(!deny.allow && deny.condition.is_none());
    assert_eq!(
        deny.resources,
        [
            "arn:aws:iam::*:role/obx/*",
            "arn:aws:iam::*:role/obx-*",
            "arn:aws:iam::*:role/*/obx-*"
        ],
        "the path, the bare name prefix, and the name at any path (role names are unique across paths)"
    );
    for must in [
        "iam:CreateRole",
        "iam:DeleteRole",
        "iam:UpdateAssumeRolePolicy",
        "iam:AttachRolePolicy",
        "iam:DetachRolePolicy",
        "iam:PutRolePolicy",
        "iam:DeleteRolePolicy",
        "iam:PassRole",
        "iam:TagRole",
        "iam:UntagRole",
        "iam:UpdateRole",
        "iam:PutRolePermissionsBoundary",
    ] {
        assert!(
            deny.actions.iter().any(|a| a == must),
            "{must} must be denied on the obx roles"
        );
    }
    // Every IAM write the policy allows, on a reserved role ARN: refused by the deny (or never allowed there).
    let issuer = "arn:aws:iam::123456789012:role/obx/obx-fleet-a-issuer";
    let release = "arn:aws:iam::123456789012:role/obx/obx-fleet-a-issuer-release";
    for s in all.iter().filter(|s| {
        s.allow
            && s.actions
                .iter()
                .any(|a| a.starts_with("iam:") && !read_only(a))
    }) {
        for arn in [issuer, release] {
            let reaches = s
                .resources
                .iter()
                .any(|r| arn_matches(&r.replace("${account_id}", "123456789012"), arn));
            assert!(
                !reaches,
                "{}: an Allow reaches a reserved role ARN ({arn}) by pattern",
                s.sid
            );
        }
    }
    // And the deny does match them.
    for arn in [issuer, release] {
        assert!(deny.resources.iter().any(|r| arn_matches(
            &r.replace("*:role", "123456789012:role"),
            arn
        ) || arn_matches(r, arn)));
    }
    // Role management is box roles only: creation needs the tag, the rest the tag on the role.
    for sid in ["CreateOzboxBoxRoles", "ManageOzboxBoxRoles"] {
        let s = all.iter().find(|s| s.sid == sid).expect(sid);
        assert_eq!(s.resources, ["arn:aws:iam::${account_id}:role/ozbox-*"]);
        assert!(
            cond_has(s, "aws:RequestTag/ozbox-managed")
                || cond_has(s, "iam:ResourceTag/ozbox-managed"),
            "{sid}"
        );
    }
    assert!(
        !all.iter().any(|s| s.allow && s.sid.contains("Obx")),
        "nothing allows the reserved namespace"
    );
}

/// IAM role names are unique per account across paths, so a role NAMED `obx-<fleet>-issuer-release` at another
/// path (which the `role/ozbox-*` Allow reaches, for example `/ozbox-x/obx-...`) would squat the issuer's name. Both a role
/// at any path and one at no path are denied.
#[test]
fn an_issuer_role_name_cannot_be_squatted_at_any_path() {
    let all = statements();
    let deny = all.iter().find(|s| s.sid == RESERVED_DENY).unwrap();
    let allow_create = all.iter().find(|s| s.sid == "CreateOzboxBoxRoles").unwrap();
    for arn in [
        "arn:aws:iam::123456789012:role/ozbox-x/obx-fleet-a-issuer-release",
        "arn:aws:iam::123456789012:role/ozbox-x/obx-fleet-a-issuer",
        "arn:aws:iam::123456789012:role/obx-fleet-a-issuer",
        "arn:aws:iam::123456789012:role/a/b/obx-fleet-a-issuer",
    ] {
        assert!(
            deny.resources.iter().any(|r| arn_matches(r, arn)),
            "{arn} must be denied"
        );
    }
    // The first one is exactly what the Allow would reach, so the Deny is what stops it.
    assert!(allow_create.resources.iter().any(|r| arn_matches(
        &r.replace("${account_id}", "123456789012"),
        "arn:aws:iam::123456789012:role/ozbox-x/obx-fleet-a-issuer-release"
    )));
    // An ordinary box role is not caught by the deny.
    assert!(!deny
        .resources
        .iter()
        .any(|r| arn_matches(r, "arn:aws:iam::123456789012:role/ozbox-dev-1")));
}

/// creating a role WITH tags needs `iam:TagRole` as well as `iam:CreateRole`, authorised against a role that has
/// no tags yet, so it must be allowed on the request tag. Retagging after the fact stays on the resource tag; nothing allows
/// TagRole with no condition or outside `role/ozbox-*`.
#[test]
fn creating_a_tagged_box_role_is_allowed_and_tagging_a_foreign_role_is_not() {
    let all = statements();
    let create = all.iter().find(|s| s.sid == "CreateOzboxBoxRoles").unwrap();
    assert!(create.allow);
    assert!(
        create.actions.contains(&"iam:CreateRole".to_string())
            && create.actions.contains(&"iam:TagRole".to_string()),
        "tag-on-create needs TagRole beside CreateRole"
    );
    assert_eq!(cond_value(create, "aws:RequestTag/ozbox-managed"), ["true"]);
    assert_eq!(
        create.resources,
        ["arn:aws:iam::${account_id}:role/ozbox-*"]
    );
    // every Allow that can tag a role is conditioned and limited to role/ozbox-*
    for s in all
        .iter()
        .filter(|s| s.allow && s.actions.iter().any(|a| a == "iam:TagRole"))
    {
        assert_eq!(
            s.resources,
            ["arn:aws:iam::${account_id}:role/ozbox-*"],
            "{}",
            s.sid
        );
        assert!(
            cond_has(s, "aws:RequestTag/ozbox-managed")
                || cond_has(s, "iam:ResourceTag/ozbox-managed"),
            "{}: TagRole without a tag condition",
            s.sid
        );
    }
    // A foreign role (not named ozbox-*) is reached by no TagRole Allow, and a reserved role is denied it.
    for arn in [
        "arn:aws:iam::123456789012:role/admin",
        "arn:aws:iam::123456789012:role/obx/obx-fleet-a-issuer",
    ] {
        assert!(!all.iter().any(|s| s.allow
            && s.actions.iter().any(|a| a == "iam:TagRole")
            && s.resources
                .iter()
                .any(|r| arn_matches(&r.replace("${account_id}", "123456789012"), arn))));
    }
}

/// `*`-wildcard ARN matching, case-sensitive.
fn arn_matches(pattern: &str, arn: &str) -> bool {
    let parts: Vec<&str> = pattern.split('*').collect();
    if parts.len() == 1 {
        return pattern == arn;
    }
    let mut rest = arn;
    for (i, part) in parts.iter().enumerate() {
        if i == 0 {
            if !rest.starts_with(part) {
                return false;
            }
            rest = &rest[part.len()..];
        } else if i == parts.len() - 1 {
            return rest.ends_with(part);
        } else if let Some(at) = rest.find(part) {
            rest = &rest[at + part.len()..];
        } else {
            return false;
        }
    }
    true
}

/// `ozbox upgrade` keeps an encrypted copy of the OLD system disk when the secrets store's key may be lost with it, and the
/// way back from it (`docs/use-cases/keeping-boxes-healthy.md`, "Recovering an old secrets store") makes a volume from it and
/// attaches that to the box. Every one of those calls must work, and only on what Oz Box tagged as its own: the snapshot is
/// made from a managed volume and carries our tag from its first moment, the tags it is given (the purpose, the box, the
/// source volume) ride on the create, and deleting it is a tagged-resource action. Nothing here is loosened for it.
#[test]
fn a_system_disk_can_be_snapshotted_tagged_recovered_from_and_deleted_only_as_ours() {
    let all = statements();
    let covers = |action: &str, resource_prefix: &str, cond: &str| {
        all.iter().any(|s| {
            s.allow
                && s.actions.iter().any(|a| matches(a, action))
                && s.resources.iter().any(|r| r.starts_with(resource_prefix))
                && cond_value(s, cond) == vec!["true".to_string()]
        })
    };
    // 1. the copy is made from one of our volumes (checked on the volume) ...
    assert!(
        covers(
            "ec2:CreateSnapshot",
            "arn:aws:ec2:*:${account_id}:",
            "aws:ResourceTag/ozbox-managed"
        ),
        "CreateSnapshot on a managed volume"
    );
    // ... and carries our tag from the moment it exists (checked on the snapshot, which does not exist yet)
    assert!(
        covers(
            "ec2:CreateSnapshot",
            "arn:aws:ec2:*::snapshot/",
            "aws:RequestTag/ozbox-managed"
        ),
        "CreateSnapshot of a snapshot that is tagged ozbox-managed on the request"
    );
    // 2. the purpose, box, upgrade and source-volume tags are written ON the create, never by a free-standing CreateTags
    assert!(
        all.iter().any(|s| s.allow
            && s.actions == ["ec2:CreateTags"]
            && s.resources.iter().any(|r| r == "arn:aws:ec2:*::snapshot/*")
            && cond_value(s, "ec2:CreateAction") == vec!["CreateSnapshot".to_string()]),
        "CreateTags on a snapshot only as part of CreateSnapshot"
    );
    // 3. the way back: a volume from our snapshot, attached to our machine, detached and deleted when done
    assert!(
        covers(
            "ec2:CreateVolume",
            "arn:aws:ec2:*::snapshot/",
            "aws:ResourceTag/ozbox-managed"
        ),
        "CreateVolume from an Oz Box snapshot"
    );
    for action in [
        "ec2:AttachVolume",
        "ec2:DetachVolume",
        "ec2:DeleteVolume",
        "ec2:DeleteSnapshot",
    ] {
        assert!(
            covers(action, "arn:aws:ec2:", "aws:ResourceTag/ozbox-managed"),
            "{action} on a managed resource"
        );
    }
    // 4. and no statement allows any of it on a resource of ours or anyone's with no condition
    for s in all.iter().filter(|s| s.allow) {
        if s.actions
            .iter()
            .any(|a| a == "ec2:CreateSnapshot" || a == "ec2:DeleteSnapshot")
        {
            assert!(
                s.condition.is_some(),
                "{}: a snapshot action with no tag condition",
                s.sid
            );
        }
    }
}

/// Whether a policy document allows `ec2:CreateTags` (called on its own, not as part of creating the resource) on an existing
/// volume, when the volume has `resource_tag` set to `true` (or no tags at all, when `None`). A condition that a standalone call
/// cannot satisfy keeps a statement from applying: `ec2:CreateAction` is only present when a create call is tagging what it made,
/// and a resource-tag condition needs the tag on the volume. Any other condition (the request's tags and keys) is taken as met.
fn standalone_create_tags_on_a_volume(file: &str, resource_tag: Option<&str>) -> Vec<String> {
    let text = std::fs::read_to_string(Path::new(env!("CARGO_MANIFEST_DIR")).join(file)).unwrap();
    let doc: Value = serde_json::from_str(&text).unwrap();
    let arn = "arn:aws:ec2:us-east-1:123456789012:volume/vol-0foreign";
    let mut hits = Vec::new();
    for s in doc["Statement"].as_array().unwrap() {
        if s["Effect"] != "Allow" {
            continue;
        }
        if !strings(s.get("Action"))
            .iter()
            .any(|a| matches(a, "ec2:CreateTags"))
        {
            continue;
        }
        if !strings(s.get("Resource"))
            .iter()
            .any(|r| arn_matches(&r.replace("${account_id}", "123456789012"), arn))
        {
            continue;
        }
        let keys: Vec<String> = s
            .get("Condition")
            .and_then(Value::as_object)
            .map(|ops| {
                ops.values()
                    .filter_map(Value::as_object)
                    .flat_map(|m| m.keys().cloned())
                    .collect()
            })
            .unwrap_or_default();
        let met = keys.iter().all(|k| {
            if k == "ec2:CreateAction" {
                false
            } else if let Some(tag) = k.strip_prefix("aws:ResourceTag/") {
                resource_tag == Some(tag)
            } else {
                !k.starts_with("ec2:ResourceTag/")
            }
        });
        if met {
            hits.push(s["Sid"].as_str().unwrap().to_string());
        }
    }
    hits
}

/// A box made by an earlier version has a system disk with no tags. Neither the daily operator role nor the setup identity may
/// give an existing disk its first `ozbox-managed` tag: IAM cannot say "a disk attached to one of our machines", so a statement
/// that allowed it would let either identity mark ANY volume in the account as its own and then change or delete it. Ownership of
/// a resource that already exists is only ever given by an account administrator (ADR 0053, amendment 1); the program refuses the
/// plan that needs it, before anything is applied, and says what to run. If this test fails because a statement was added, that
/// decision was reversed: say so in the ADR.
#[test]
fn nothing_but_an_administrator_can_give_an_existing_volume_its_first_tag() {
    for file in [
        "../../infra/aws/operator-policy.json",
        "../../infra/aws/setup-policy.json",
    ] {
        assert_eq!(
            standalone_create_tags_on_a_volume(file, None),
            Vec::<String>::new(),
            "{file}: a foreign, untagged volume must not be taggable"
        );
        // a volume that is already ours is: that is how the rest of a box's tags are kept
        assert!(
            !standalone_create_tags_on_a_volume(file, Some("ozbox-managed")).is_empty()
                || file.contains("setup"),
            "{file}: the operator must still change the tags of a volume that is already ours"
        );
        // and a volume tagged with some OTHER tag is not ours
        assert_eq!(
            standalone_create_tags_on_a_volume(file, Some("team")),
            Vec::<String>::new(),
            "{file}"
        );
    }
}

// ---------- the adopt statements: one source, rendered for an account, and nothing the code calls left out ----------

use ozbox_provider_aws::operator_policy::{self, ADOPT_STATEMENTS};

fn rendered() -> Value {
    operator_policy::render("123456789012", "us-east-1", "ozbox").expect("renders")
}

fn statement<'a>(doc: &'a Value, sid: &str) -> &'a Value {
    doc["Statement"]
        .as_array()
        .unwrap()
        .iter()
        .find(|s| s["Sid"] == sid)
        .unwrap_or_else(|| panic!("the policy has no statement {sid}"))
}

#[test]
fn the_policy_carries_the_statements_the_adopt_commands_need() {
    let doc = rendered();
    for sid in ADOPT_STATEMENTS {
        statement(&doc, sid);
    }
    assert!(
        allowed("ssm:SendCommand"),
        "adopt-fleet-key sends a command"
    );
    assert!(
        allowed("ssm:GetCommandInvocation"),
        "adopt-fleet-key reads the result"
    );
    // scoped exactly as the module's own output is: the fleet's document, boxes Oz Box manages, in the account and region
    assert_eq!(
        statement(&doc, "SendOnlyTheAdoptDocument")["Resource"],
        "arn:aws:ssm:us-east-1:123456789012:document/ozbox-adopt-ozbox"
    );
    let boxes = statement(&doc, "ToBoxesOzBoxManages");
    assert_eq!(
        boxes["Resource"],
        "arn:aws:ec2:us-east-1:123456789012:instance/*"
    );
    assert_eq!(
        boxes["Condition"]["StringEquals"]["ssm:resourceTag/ozbox-managed"],
        "true"
    );
    // never a command of the caller's choosing: no statement allows SendCommand on every resource or on a foreign document
    for s in statements().iter().filter(|s| {
        s.allow
            && s.actions
                .iter()
                .any(|a| a == "ssm:SendCommand" || a == "ssm:*")
    }) {
        assert!(
            s.resources.iter().all(|r| r.contains("ozbox-adopt-")
                || (r.contains(":instance/*") && s.condition.is_some())),
            "{}: SendCommand reaches only the adopt document, or tagged boxes",
            s.sid
        );
    }
    for s in statements().iter().filter(|s| s.allow) {
        for forbidden in [
            "ssm:CancelCommand",
            "ssm:CreateDocument",
            "ssm:UpdateDocument",
        ] {
            assert!(!s.actions.iter().any(|a| a == forbidden), "{}", s.sid);
        }
    }
}

/// The module outputs the same statements for someone who only wants the adopt part; the two must never drift apart.
#[test]
fn the_operator_policy_and_the_adopt_module_output_say_the_same_thing() {
    let main = std::fs::read_to_string(
        Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../infra/tofu/modules/aws-adopt-command/main.tf"),
    )
    .unwrap();
    let block = main
        .split("data \"aws_iam_policy_document\" \"operator_adopt\"")
        .nth(1)
        .expect("the module outputs the operator adopt policy");
    let normal = |s: &str| {
        s.replace("${data.aws_region.this.name}", "${region}")
            .replace("${var.account_id}", "${account_id}")
            .replace("${local.adopt_document}", "ozbox-adopt-${fleet}")
    };
    let template: Value = serde_json::from_str(operator_policy::TEMPLATE).unwrap();
    for sid in ADOPT_STATEMENTS {
        let at = block
            .find(&format!("sid       = \"{sid}\""))
            .unwrap_or_else(|| panic!("the module has no statement {sid}"));
        let stmt = &block[at..];
        let end = stmt.find("\n  }\n").unwrap();
        let stmt = &stmt[..end];
        let want = statement(&template, sid);
        let actions = stmt
            .split("actions")
            .nth(1)
            .unwrap()
            .split('[')
            .nth(1)
            .unwrap()
            .split(']')
            .next()
            .unwrap();
        assert_eq!(
            actions.trim().trim_matches('"'),
            want["Action"].as_str().unwrap(),
            "{sid}: action"
        );
        let resources = normal(
            stmt.split("resources")
                .nth(1)
                .unwrap()
                .split('[')
                .nth(1)
                .unwrap()
                .split(']')
                .next()
                .unwrap()
                .trim()
                .trim_matches('"'),
        );
        assert_eq!(
            resources,
            want["Resource"].as_str().unwrap(),
            "{sid}: resource"
        );
        assert_eq!(
            stmt.contains("condition"),
            want.get("Condition").is_some(),
            "{sid}: condition"
        );
    }
}

#[test]
fn rendering_fills_three_names_and_refuses_anything_else() {
    let text = rendered().to_string();
    for placeholder in ["${account_id}", "${region}", "${fleet}"] {
        assert!(!text.contains(placeholder), "{placeholder} left unfilled");
    }
    assert!(text.contains("123456789012") && text.contains("ozbox-adopt-ozbox"));
    for (a, r, f) in [
        ("12345", "us-east-1", "ozbox"),
        ("123456789012", "us-east-1\"", "ozbox"),
        ("123456789012", "us-east-1", "a${b}"),
        ("123456789012", "", "ozbox"),
        ("123456789012", "us-east-1", "Fleet"),
    ] {
        assert!(operator_policy::render(a, r, f).is_err(), "{a} {r} {f}");
    }
}

/// An administrator applies the policy as an inline policy; AWS allows 10,240 characters there (and 6,144 for a managed
/// policy, which this one has outgrown: the documentation says so).
#[test]
fn it_still_fits_an_inline_policy() {
    let n = rendered().to_string().len();
    assert!(
        n > 6144,
        "if it fits a managed policy again, update the documentation that says it does not"
    );
    assert!(n < 10240, "{n} characters: over the inline policy limit");
}

fn rust_sources(dir: &Path, out: &mut Vec<std::path::PathBuf>) {
    for e in std::fs::read_dir(dir).unwrap() {
        let p = e.unwrap().path();
        if p.is_dir() {
            if p.file_name().is_some_and(|n| n == "tests" || n == "target") {
                continue;
            }
            rust_sources(&p, out);
        } else if p.extension().is_some_and(|x| x == "rs")
            && !p.file_name().is_some_and(|n| n == "testing.rs")
        {
            out.push(p);
        }
    }
}

/// `"<service>", "<command>"` pairs, the way every AWS CLI call in this program's non-test code is written as an argv list.
fn aws_calls() -> BTreeSet<(String, String)> {
    let mut files = Vec::new();
    rust_sources(
        &Path::new(env!("CARGO_MANIFEST_DIR")).join("../"),
        &mut files,
    );
    let mut found = BTreeSet::new();
    for f in files {
        let text = std::fs::read_to_string(&f).unwrap();
        let end = text
            .find("#[cfg(test)]\nmod tests")
            .or_else(|| text.find("#[cfg(test)]\n#[allow(clippy::unwrap_used)]\nmod tests"))
            .unwrap_or(text.len());
        let text = &text[..end];
        for service in [
            "ec2",
            "ssm",
            "iam",
            "kms",
            "sts",
            "pricing",
            "ce",
            "service-quotas",
            "ec2-instance-connect",
            "s3api",
        ] {
            let needle = format!("\"{service}\"");
            for (at, _) in text.match_indices(&needle) {
                let after = text[at + needle.len()..].trim_start();
                let Some(after) = after.strip_prefix(',') else {
                    continue;
                };
                let Some(after) = after.trim_start().strip_prefix('"') else {
                    continue;
                };
                let Some(k) = after.find('"') else { continue };
                let command = &after[..k];
                if command.is_empty()
                    || !command
                        .bytes()
                        .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
                    || command.starts_with('-')
                    || command == "wait"
                {
                    continue;
                }
                found.insert((service.to_string(), command.to_string()));
            }
        }
    }
    found
}

fn action_of(service: &str, command: &str) -> String {
    let svc = match service {
        "service-quotas" => "servicequotas",
        "s3api" => "s3",
        other => other,
    };
    let camel: String = command
        .split('-')
        .map(|w| {
            let mut c = w.chars();
            c.next()
                .map(|f| f.to_ascii_uppercase().to_string() + c.as_str())
                .unwrap_or_default()
        })
        .collect();
    format!("{svc}:{camel}")
}

/// Calls the program makes that the DAILY operator role does not, with the reason. Each is made by `ozbox init` (the setup
/// identity or an administrator, a different permission set: `infra/aws/setup-policy.json`), or is not an AWS call at all.
const NOT_THE_OPERATORS: [(&str, &str, &str); 19] = [
    (
        "kms",
        "file",
        "not an AWS call: a secrets-store backend name",
    ),
    (
        "kms",
        "main",
        "not an AWS call: a secrets-store backend name",
    ),
    (
        "kms",
        "tpm2",
        "not an AWS call: a secrets-store backend name",
    ),
    (
        "kms",
        "list-aliases",
        "setup identity: looks for the fleet key's alias before adopting it",
    ),
    (
        "kms",
        "list-resource-tags",
        "setup identity: reads the key's ownership tag before adopting it",
    ),
    (
        "ssm",
        "describe-document",
        "setup identity: looks for the adopt document before adopting it",
    ),
    (
        "iam",
        "get-role",
        "setup identity: reads its own role to check its permissions",
    ),
    (
        "iam",
        "simulate-principal-policy",
        "setup identity: asks whether it may make a step",
    ),
    (
        "iam",
        "list-access-keys",
        "setup identity: the sign-in advice check",
    ),
    (
        "iam",
        "list-mfa-devices",
        "setup identity: the sign-in advice check",
    ),
    ("s3api", "create-bucket", "setup identity: the state bucket"),
    (
        "s3api",
        "delete-bucket",
        "setup identity: undoes a state bucket it made in the same run and left half set up",
    ),
    (
        "s3api",
        "get-bucket-encryption",
        "setup identity: the state bucket",
    ),
    (
        "s3api",
        "get-public-access-block",
        "setup identity: the state bucket",
    ),
    ("s3api", "head-bucket", "setup identity: the state bucket"),
    (
        "s3api",
        "put-bucket-encryption",
        "setup identity: the state bucket",
    ),
    (
        "s3api",
        "put-bucket-policy",
        "setup identity: the state bucket",
    ),
    (
        "s3api",
        "put-bucket-versioning",
        "setup identity: the state bucket",
    ),
    (
        "s3api",
        "put-public-access-block",
        "setup identity: the state bucket",
    ),
];

/// The hand list in `it_covers_what_the_cli_and_the_adapter_do` is what missed the adopt statements: an action the code
/// added was in nobody's list. This reads the calls out of the program's own source instead, so a new one fails here until
/// the policy allows it or the table above says whose it is.
#[test]
fn every_aws_call_the_program_makes_is_allowed_to_the_operator_or_named_as_setups() {
    let calls = aws_calls();
    // the scan must be seeing the code it is meant to guard
    for must_see in [
        ("ssm", "send-command"),
        ("ssm", "get-command-invocation"),
        ("ec2", "describe-instances"),
        ("ec2-instance-connect", "send-ssh-public-key"),
        ("iam", "list-attached-role-policies"),
    ] {
        // (a call built from a variable, like `["ce", sub]` in the bill, is not seen: the hand list above covers those)
        assert!(
            calls.contains(&(must_see.0.to_string(), must_see.1.to_string())),
            "the scan did not find {must_see:?}: it no longer reads the source it guards"
        );
    }
    let exempt: BTreeSet<(String, String)> = NOT_THE_OPERATORS
        .iter()
        .map(|(s, c, _)| ((*s).to_string(), (*c).to_string()))
        .collect();
    let gone: Vec<_> = exempt.difference(&calls).collect();
    assert!(
        gone.is_empty(),
        "{gone:?} is exempted but no longer called: remove it from the table"
    );
    let mut missing = Vec::new();
    for (service, command) in calls.difference(&exempt) {
        let action = action_of(service, command);
        if !allowed(&action) {
            missing.push(action);
        }
    }
    assert!(
        missing.is_empty(),
        "the operator policy does not allow what the program calls: {missing:?}. Add a statement to \
         infra/aws/operator-policy.json (least privilege, tag- or resource-scoped), or, if setup alone makes the call, \
         name it in NOT_THE_OPERATORS"
    );
}
