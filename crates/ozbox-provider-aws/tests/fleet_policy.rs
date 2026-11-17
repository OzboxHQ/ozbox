//! The fleet roles (ADR 0040 §3) are code: these tests evaluate the RENDERED documents the way IAM does (an explicit Deny
//! wins; otherwise an Allow whose action, resource and every condition match; otherwise denied) over a matrix of requests a
//! box's dashboard could make, and pin what must be refused: untagged and foreign resources, `main` itself, IAM, direct KMS,
//! secrets, shells, data paths out, and a pool role that is not reserved for the session.
//!
//! The evaluator below is small on purpose and covers only the operators the documents use; a document that uses another
//! operator fails [`every_condition_operator_is_one_the_evaluator_knows`], so a new shape cannot pass by being ignored. It is
//! not AWS's simulator: the facts ADR 0040 §15 lists are still to be confirmed there (an owner run, with a read-only identity).

#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::collections::HashMap;

use ozbox_provider_aws::fleet_policy::{self, Doc, FleetVars};
use serde_json::Value;

const ACCT: &str = "123456789012";
const REGION: &str = "us-east-1";

fn vars() -> FleetVars {
    FleetVars {
        account_id: ACCT.into(),
        regions: vec![REGION.into()],
        sizes: vec!["m7i.xlarge".into(), "c7i.xlarge".into()],
        image_ids: vec!["ami-0123456789abcdef0".into()],
        max_volume_gb: 500,
        max_iops: 6000,
        max_throughput: 500,
        window_principal_arn: format!(
            "arn:aws:iam::{ACCT}:role/aws-reserved/sso.amazonaws.com/AWSReservedSSO_OzboxFleetWindow_*"
        ),
        subnet_ids: vec![OZBOX_SUBNET.into()],
        fleet_manager_box: MAIN_BOX.into(),
    }
}

fn doc(d: Doc) -> Value {
    fleet_policy::render(d, &vars()).unwrap()
}

#[derive(Debug, PartialEq, Eq, Clone, Copy)]
enum Decision {
    Allow,
    ExplicitDeny,
    ImplicitDeny,
}

/// One request: the action, the resource and the request context (each key may hold several values, like `aws:TagKeys`).
#[derive(Clone)]
struct Ask {
    action: String,
    resource: String,
    ctx: HashMap<String, Vec<String>>,
}

fn ask(action: &str, resource: &str) -> Ask {
    let mut ctx = HashMap::new();
    ctx.insert("aws:RequestedRegion".into(), vec![REGION.into()]);
    ctx.insert("aws:userid".into(), vec!["AROAEXAMPLE:plan-abc".into()]);
    ctx.insert("aws:ViaAWSService".into(), vec!["false".into()]);
    Ask {
        action: action.into(),
        resource: resource.into(),
        ctx,
    }
}

impl Ask {
    fn with(mut self, k: &str, v: &str) -> Self {
        self.ctx.insert(k.into(), vec![v.into()]);
        self
    }
    fn with_many(mut self, k: &str, vs: &[&str]) -> Self {
        self.ctx
            .insert(k.into(), vs.iter().map(|s| s.to_string()).collect());
        self
    }
    fn without(mut self, k: &str) -> Self {
        self.ctx.remove(k);
        self
    }
}

fn strings(v: Option<&Value>) -> Vec<String> {
    match v {
        None => Vec::new(),
        Some(Value::String(s)) => vec![s.clone()],
        Some(Value::Array(a)) => a
            .iter()
            .map(|x| x.as_str().expect("strings only").to_string())
            .collect(),
        Some(Value::Bool(b)) => vec![b.to_string()],
        Some(Value::Number(n)) => vec![n.to_string()],
        Some(other) => panic!("expected a string or an array, found {other}"),
    }
}

/// `*` and `?` wildcards.
fn glob(pattern: &str, s: &str, case_insensitive: bool) -> bool {
    let (p, s): (Vec<char>, Vec<char>) = if case_insensitive {
        (
            pattern.to_ascii_lowercase().chars().collect(),
            s.to_ascii_lowercase().chars().collect(),
        )
    } else {
        (pattern.chars().collect(), s.chars().collect())
    };
    fn go(p: &[char], s: &[char]) -> bool {
        match p.first() {
            None => s.is_empty(),
            Some('*') => (0..=s.len()).any(|i| go(&p[1..], &s[i..])),
            Some('?') => !s.is_empty() && go(&p[1..], &s[1..]),
            Some(c) => s.first() == Some(c) && go(&p[1..], &s[1..]),
        }
    }
    go(&p, &s)
}

/// IAM policy variables in a condition VALUE (`${aws:userid}`), filled from the request. `None` when one names a key the
/// request does not have: IAM then evaluates that condition as not matching (so a Deny on it does nothing, which is why a
/// fail-closed rule pairs it with a `Null` Deny; ADR 0040 §15 fact 4).
fn fill(v: &str, a: &Ask) -> Option<String> {
    let mut out = v.to_string();
    for (k, vals) in &a.ctx {
        if let Some(first) = vals.first() {
            out = out.replace(&format!("${{{k}}}"), first);
        }
    }
    (!out.contains("${")).then_some(out)
}

const OPERATORS: [&str; 12] = [
    "StringEquals",
    "StringNotEquals",
    "StringLike",
    "ArnEquals",
    "ArnLike",
    "Bool",
    "Null",
    "NumericLessThanEquals",
    "ForAllValues:StringEquals",
    "ForAnyValue:StringEquals",
    "DateLessThan",
    "DateGreaterThan",
];

fn condition_holds(op: &str, key: &str, want: &[String], a: &Ask) -> bool {
    let Some(want) = want
        .iter()
        .map(|w| fill(w, a))
        .collect::<Option<Vec<String>>>()
    else {
        return false;
    };
    let have = a.ctx.get(key);
    match op {
        "Null" => {
            let absent = have.is_none_or(|h| h.is_empty());
            want.iter().any(|w| (w == "true") == absent)
        }
        "ForAllValues:StringEquals" => {
            have.is_none_or(|h| h.iter().all(|x| want.iter().any(|w| w == x)))
        }
        "ForAnyValue:StringEquals" => {
            have.is_some_and(|h| h.iter().any(|x| want.iter().any(|w| w == x)))
        }
        "StringNotEquals" => have.is_none_or(|h| h.iter().all(|x| !want.contains(x))),
        _ => {
            let Some(h) = have.and_then(|h| h.first()) else {
                return false; // a non-negated operator over an absent key does not match
            };
            match op {
                "StringEquals" | "ArnEquals" | "Bool" => want.iter().any(|w| w == h),
                "StringLike" | "ArnLike" => want.iter().any(|w| glob(w, h, false)),
                // UTC times in one fixed form compare as text
                "DateGreaterThan" => want.iter().any(|w| h.as_str() > w.as_str()),
                "DateLessThan" => want.iter().any(|w| h.as_str() < w.as_str()),
                "NumericLessThanEquals" => {
                    let (Ok(x), true) = (h.parse::<f64>(), !want.is_empty()) else {
                        return false;
                    };
                    want.iter().any(|w| w.parse::<f64>().is_ok_and(|w| x <= w))
                }
                other => panic!("operator {other} not modelled"),
            }
        }
    }
}

fn statement_applies(s: &Value, a: &Ask) -> bool {
    let actions = strings(s.get("Action"));
    if !actions.iter().any(|p| glob(p, &a.action, true)) {
        return false;
    }
    // a trust policy names no resource: it is the role itself
    let resources = strings(s.get("Resource"));
    // a policy variable in a resource (`${aws:PrincipalTag/ozbox-window-box}`) is filled from the request, like one in a condition
    if s.get("Resource").is_some()
        && !resources
            .iter()
            .any(|p| fill(p, a).is_some_and(|p| glob(&p, &a.resource, false)))
    {
        return false;
    }
    let Some(cond) = s.get("Condition").and_then(Value::as_object) else {
        return true;
    };
    cond.iter().all(|(op, keys)| {
        keys.as_object()
            .unwrap()
            .iter()
            .all(|(k, v)| condition_holds(op, k, &strings(Some(v)), a))
    })
}

fn decide(docs: &[Value], a: &Ask) -> Decision {
    let all: Vec<&Value> = docs
        .iter()
        .flat_map(|d| d["Statement"].as_array().unwrap().iter())
        .collect();
    if all
        .iter()
        .any(|s| s["Effect"] == "Deny" && statement_applies(s, a))
    {
        return Decision::ExplicitDeny;
    }
    if all
        .iter()
        .any(|s| s["Effect"] == "Allow" && statement_applies(s, a))
    {
        return Decision::Allow;
    }
    Decision::ImplicitDeny
}

fn change() -> Vec<Value> {
    vec![doc(Doc::Change), doc(Doc::ChangeGuard)]
}

fn read() -> Vec<Value> {
    vec![doc(Doc::Read)]
}

fn instance(id: &str) -> String {
    format!("arn:aws:ec2:{REGION}:{ACCT}:instance/{id}")
}

fn volume(id: &str) -> String {
    format!("arn:aws:ec2:{REGION}:{ACCT}:volume/{id}")
}

fn snapshot(id: &str) -> String {
    format!("arn:aws:ec2:{REGION}::snapshot/{id}")
}

fn allowed(docs: &[Value], a: &Ask) -> bool {
    decide(docs, a) == Decision::Allow
}

// ---- the shape of the documents --------------------------------------------------------------------------------------------

#[test]
fn every_condition_operator_is_one_the_evaluator_knows() {
    for d in Doc::ALL {
        for s in doc(d)["Statement"].as_array().unwrap() {
            for op in s
                .get("Condition")
                .and_then(Value::as_object)
                .map(|c| c.keys().cloned().collect::<Vec<_>>())
                .unwrap_or_default()
            {
                assert!(
                    OPERATORS.contains(&op.as_str()),
                    "{d:?}: {op} is not modelled here"
                );
            }
            assert!(
                s.get("NotAction").is_none() && s.get("NotResource").is_none(),
                "{d:?}: no NotAction or NotResource"
            );
        }
    }
}

#[test]
fn no_allow_changes_anything_on_every_resource() {
    for d in [Doc::Change, Doc::Read, Doc::Cost] {
        for s in doc(d)["Statement"].as_array().unwrap() {
            if s["Effect"] != "Allow" || !strings(s.get("Resource")).contains(&"*".to_string()) {
                continue;
            }
            for a in strings(s.get("Action")) {
                let name = a.split(':').nth(1).unwrap_or("");
                assert!(
                    ["Describe", "Get", "List"]
                        .iter()
                        .any(|p| name.starts_with(p)),
                    "{d:?}: {a} on every resource is not a read"
                );
            }
        }
    }
}

#[test]
fn every_change_statement_is_held_to_the_fleets_regions() {
    for s in doc(Doc::Change)["Statement"].as_array().unwrap() {
        let acts = strings(s.get("Action"));
        if acts
            .iter()
            .all(|a| a.starts_with("s3:") || a == "iam:PassRole")
        {
            continue; // S3 and IAM are global; their resources are the boundary
        }
        let regions = s["Condition"]["StringEquals"]["aws:RequestedRegion"].clone();
        assert_eq!(regions, serde_json::json!([REGION]), "{}", s["Sid"]);
    }
}

/// The operator policy stays the ceiling (ADR 0040 §6): every action the fleet roles allow is one the operator may do, but
/// for the named exceptions that exist only for the fleet.
#[test]
fn every_fleet_allow_is_also_an_operator_allow_but_the_named_exceptions() {
    let op: Value =
        serde_json::from_str(include_str!("../../../infra/aws/operator-policy.json")).unwrap();
    let op_allows: Vec<String> = op["Statement"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|s| s["Effect"] == "Allow")
        .flat_map(|s| strings(s.get("Action")))
        .collect();
    let exceptions = [
        "sts:GetCallerIdentity",
        "sts:AssumeRole",
        "sts:SetSourceIdentity",
        "servicequotas:GetServiceQuota",
        "pricing:DescribeServices",
        "pricing:GetAttributeValues",
    ];
    for d in [Doc::Change, Doc::Read, Doc::Cost, Doc::MainAssume] {
        for s in doc(d)["Statement"].as_array().unwrap() {
            if s["Effect"] != "Allow" {
                continue;
            }
            for a in strings(s.get("Action")) {
                assert!(
                    exceptions.contains(&a.as_str()) || op_allows.iter().any(|p| glob(p, &a, true)),
                    "{d:?}: {a} is above the operator's ceiling"
                );
            }
        }
    }
}

// ---- who may assume which role ---------------------------------------------------------------------------------------------

#[test]
fn only_mains_own_role_may_assume_the_read_role_and_main_may_never_assume_the_change_role() {
    let main = fleet_policy::main_role_arn(ACCT);
    let laptop = format!(
        "arn:aws:iam::{ACCT}:role/aws-reserved/sso.amazonaws.com/AWSReservedSSO_OzboxFleetWindow_0123abcd"
    );
    let trust = |d: Doc, principal: &str, name: &str| {
        allowed(
            &[doc(d)],
            &ask("sts:AssumeRole", "*")
                .with("aws:PrincipalArn", principal)
                .with("sts:SourceIdentity", "ozbox-owner")
                .with("sts:RoleSessionName", name),
        )
    };
    assert!(trust(Doc::ReadTrust, &main, "read"));
    assert!(!trust(Doc::ReadTrust, &laptop, "read"));
    assert!(!trust(
        Doc::ReadTrust,
        &format!("arn:aws:iam::{ACCT}:role/ozbox-dev"),
        "read"
    ));
    assert!(trust(Doc::ChangeTrust, &laptop, "plan-abc"));
    assert!(
        !trust(Doc::ChangeTrust, &main, "plan-abc"),
        "main is never in the change role's trust"
    );
    assert!(
        !trust(Doc::ChangeTrust, &laptop, "anything"),
        "a window is named for its plan"
    );
    // a session without the person's source identity is refused by both
    let anon = ask("sts:AssumeRole", "*").with("aws:PrincipalArn", &main);
    assert!(!allowed(&[doc(Doc::ReadTrust)], &anon));
    // the principal is the account, never a wildcard
    for d in [Doc::ReadTrust, Doc::ChangeTrust] {
        for s in doc(d)["Statement"].as_array().unwrap() {
            assert_eq!(s["Principal"]["AWS"], format!("arn:aws:iam::{ACCT}:root"));
        }
    }
    // main's own permission: the read role, nothing else
    let mine = doc(Doc::MainAssume);
    assert!(allowed(
        std::slice::from_ref(&mine),
        &ask(
            "sts:AssumeRole",
            &format!("arn:aws:iam::{ACCT}:role/obx/obx-fleet-read")
        )
    ));
    assert!(!allowed(
        std::slice::from_ref(&mine),
        &ask(
            "sts:AssumeRole",
            &format!("arn:aws:iam::{ACCT}:role/obx/obx-fleet-change")
        )
    ));
}

// ---- the read role ---------------------------------------------------------------------------------------------------------

#[test]
fn the_read_role_reads_and_changes_nothing() {
    assert!(allowed(&read(), &ask("ec2:DescribeInstances", "*")));
    assert!(!allowed(
        &read(),
        &ask("ec2:DescribeInstances", "*").with("aws:RequestedRegion", "eu-west-1")
    ));
    for a in [
        "ec2:DescribeInstanceAttribute",
        "ec2:GetConsoleOutput",
        "ebs:GetSnapshotBlock",
        "s3:GetObject",
        "ssm:GetParameter",
        "kms:Decrypt",
    ] {
        assert_eq!(decide(&read(), &ask(a, "*")), Decision::ExplicitDeny, "{a}");
    }
    for a in [
        "ec2:TerminateInstances",
        "ec2:RunInstances",
        "iam:PassRole",
        "ce:GetCostAndUsage",
    ] {
        assert!(!allowed(&read(), &ask(a, &instance("i-1"))), "{a}");
    }
    // the bill only with the cost document, which the setup attaches only in an account of Oz Box's own
    assert!(allowed(
        &[doc(Doc::Read), doc(Doc::Cost)],
        &ask("ce:GetCostAndUsage", "*")
    ));
}

// ---- the change role -------------------------------------------------------------------------------------------------------

fn managed(a: Ask) -> Ask {
    a.with("aws:ResourceTag/ozbox-managed", "true")
}

#[test]
fn pause_resume_and_destroy_reach_only_ozbox_managed_resources() {
    for act in [
        "ec2:StopInstances",
        "ec2:StartInstances",
        "ec2:TerminateInstances",
    ] {
        assert!(
            allowed(&change(), &managed(ask(act, &instance("i-1")))),
            "{act}"
        );
        // untagged: refused
        assert!(
            !allowed(&change(), &ask(act, &instance("i-2"))),
            "{act} untagged"
        );
        // tagged as someone else's
        assert!(
            !allowed(
                &change(),
                &ask(act, &instance("i-3")).with("aws:ResourceTag/ozbox-managed", "false")
            ),
            "{act} foreign"
        );
        // another region
        assert!(
            !allowed(
                &change(),
                &managed(ask(act, &instance("i-4"))).with("aws:RequestedRegion", "eu-west-1")
            ),
            "{act} region"
        );
        // another account's instance
        assert!(
            !allowed(
                &change(),
                &managed(ask(act, "arn:aws:ec2:us-east-1:210987654321:instance/i-5"))
            ),
            "{act} account"
        );
    }
    assert!(allowed(
        &change(),
        &managed(ask("ec2:DeleteVolume", &volume("vol-1")))
    ));
    assert!(!allowed(
        &change(),
        &ask("ec2:DeleteVolume", &volume("vol-2"))
    ));
    assert_eq!(
        decide(
            &change(),
            &managed(ask("ec2:DeleteSnapshot", &snapshot("snap-1")))
        ),
        Decision::ExplicitDeny,
        "no snapshot is ever deleted from a box"
    );
}

#[test]
fn main_itself_cannot_be_stopped_destroyed_resized_snapshotted_or_cloned() {
    let me = |act: &str, res: &str| {
        managed(ask(act, res)).with("aws:ResourceTag/ozbox-fleet-manager", "true")
    };
    for act in [
        "ec2:StopInstances",
        "ec2:TerminateInstances",
        "ec2:ModifyInstanceAttribute",
        "ec2:CreateTags",
    ] {
        assert_eq!(
            decide(&change(), &me(act, &instance("i-main"))),
            Decision::ExplicitDeny,
            "{act}"
        );
    }
    for act in [
        "ec2:DeleteVolume",
        "ec2:DetachVolume",
        "ec2:CreateSnapshot",
        "ec2:ModifyVolume",
    ] {
        assert_eq!(
            decide(&change(), &me(act, &volume("vol-main"))),
            Decision::ExplicitDeny,
            "{act}"
        );
    }
    for act in ["ec2:RunInstances", "ec2:CreateVolume"] {
        assert_eq!(
            decide(&change(), &me(act, &snapshot("snap-main"))),
            Decision::ExplicitDeny,
            "{act}"
        );
    }
    // and nothing can be MADE to look like main
    let launch = good_launch().with_many(
        "aws:TagKeys",
        &["ozbox-managed", "ozbox-box", "ozbox-fleet-manager"],
    );
    assert_eq!(decide(&change(), &launch), Decision::ExplicitDeny);
}

fn good_launch() -> Ask {
    ask("ec2:RunInstances", &instance("*"))
        .with("aws:RequestTag/ozbox-managed", "true")
        .with("ec2:MetadataHttpTokens", "required")
        .with("ec2:InstanceType", "m7i.xlarge")
        .with_many(
            "aws:TagKeys",
            &["ozbox-managed", "ozbox-box", "ozbox-region"],
        )
}

#[test]
fn a_launch_is_tagged_sized_and_locked_down_or_refused() {
    assert!(allowed(&change(), &good_launch()));
    assert!(
        !allowed(
            &change(),
            &good_launch().with("ec2:InstanceType", "p5.48xlarge")
        ),
        "size"
    );
    assert!(
        !allowed(
            &change(),
            &good_launch().without("aws:RequestTag/ozbox-managed")
        ),
        "tag"
    );
    assert!(
        !allowed(
            &change(),
            &good_launch().with("ec2:MetadataHttpTokens", "optional")
        ),
        "IMDSv1"
    );
    assert!(
        !allowed(
            &change(),
            &good_launch().with_many("aws:TagKeys", &["ozbox-managed", "owner-team"])
        ),
        "an unknown tag key"
    );
    // the image, the volumes and the network the launch names
    let img = |id: &str| {
        ask(
            "ec2:RunInstances",
            &format!("arn:aws:ec2:{REGION}::image/{id}"),
        )
        .with("ec2:ImageID", id)
    };
    assert!(allowed(&change(), &img("ami-0123456789abcdef0")));
    assert!(
        !allowed(&change(), &img("ami-0fffffffffffffff0")),
        "someone else's image"
    );
    let vol = || {
        ask("ec2:RunInstances", &volume("*"))
            .with("aws:RequestTag/ozbox-managed", "true")
            .with("ec2:VolumeType", "gp3")
            .with("ec2:Encrypted", "true")
            .with("ec2:VolumeSize", "200")
            .with("ec2:VolumeIops", "3000")
            .with("ec2:VolumeThroughput", "125")
    };
    assert!(allowed(&change(), &vol()));
    assert!(
        !allowed(&change(), &vol().with("ec2:Encrypted", "false")),
        "unencrypted"
    );
    assert!(
        !allowed(&change(), &vol().with("ec2:VolumeSize", "16000")),
        "oversized"
    );
    assert!(
        !allowed(&change(), &vol().with("ec2:VolumeType", "io2")),
        "type"
    );
    assert!(
        !allowed(&change(), &vol().with("ec2:VolumeIops", "64000")),
        "iops"
    );
    let net = |kind: &str| {
        ask(
            "ec2:RunInstances",
            &format!("arn:aws:ec2:{REGION}:{ACCT}:{kind}/x"),
        )
    };
    assert!(allowed(&change(), &managed(net("subnet"))));
    assert!(!allowed(&change(), &net("subnet")), "an untagged subnet");
    assert!(
        !allowed(&change(), &net("security-group")),
        "an untagged group"
    );
    // a clone from a managed snapshot, never from anyone else's
    assert!(allowed(
        &change(),
        &managed(ask("ec2:RunInstances", &snapshot("snap-1")))
    ));
    assert!(!allowed(
        &change(),
        &ask("ec2:RunInstances", &snapshot("snap-2"))
    ));
}

#[test]
fn tags_are_written_only_while_creating() {
    let t = |create: Option<&str>| {
        let a = managed(ask("ec2:CreateTags", &instance("i-1")));
        match create {
            Some(c) => a.with("ec2:CreateAction", c),
            None => a,
        }
    };
    assert!(allowed(&change(), &t(Some("RunInstances"))));
    assert!(
        !allowed(&change(), &t(None)),
        "a tag on an existing resource"
    );
    assert!(!allowed(&change(), &t(Some("ModifyInstanceAttribute"))));
    assert!(!allowed(
        &change(),
        &ask("ec2:DeleteTags", &instance("i-1"))
    ));
}

#[test]
fn resize_changes_the_instance_type_and_nothing_else() {
    let m = || managed(ask("ec2:ModifyInstanceAttribute", &instance("i-1")));
    assert!(allowed(
        &change(),
        &m().with("ec2:Attribute/InstanceType", "c7i.xlarge")
    ));
    assert!(!allowed(
        &change(),
        &m().with("ec2:Attribute/InstanceType", "x2iedn.32xlarge")
    ));
    assert!(
        !allowed(&change(), &m()),
        "no instance type named: not a resize"
    );
    for attr in [
        "ec2:Attribute/UserData",
        "ec2:Attribute/GroupId",
        "ec2:Attribute/DisableApiTermination",
    ] {
        assert_eq!(
            decide(
                &change(),
                &m().with("ec2:Attribute/InstanceType", "c7i.xlarge")
                    .with(attr, "x")
            ),
            Decision::ExplicitDeny,
            "{attr}"
        );
    }
}

#[test]
fn no_iam_no_direct_kms_no_secrets_no_shell_no_data_path_out() {
    for a in [
        "iam:CreateRole",
        "iam:PutRolePolicy",
        "iam:AttachRolePolicy",
        "iam:UpdateAssumeRolePolicy",
        "iam:CreateAccessKey",
        "iam:TagRole",
        "secretsmanager:GetSecretValue",
        "ssm:GetParameter",
        "ssm:GetParametersByPath",
        "ssm:PutParameter",
        "sts:AssumeRole",
        "ssm:StartSession",
        "ssm:SendCommand",
        "ec2-instance-connect:SendSSHPublicKey",
        "ebs:GetSnapshotBlock",
        "ec2:ModifySnapshotAttribute",
        "ec2:CopySnapshot",
        "ec2:CreateImage",
        "ec2:DescribeInstanceAttribute",
        "ec2:GetConsoleOutput",
        "ec2:AssociateIamInstanceProfile",
        "ec2:ModifyInstanceMetadataOptions",
        "ec2:AuthorizeSecurityGroupIngress",
        "ec2:CreateSecurityGroup",
        "organizations:LeaveOrganization",
        "cloudtrail:StopLogging",
    ] {
        assert_eq!(
            decide(&change(), &managed(ask(a, "*"))),
            Decision::ExplicitDeny,
            "{a}"
        );
    }
    // KMS directly: refused; on the caller's behalf by EBS: not refused (the encrypted launch needs it), and never granted
    assert_eq!(
        decide(&change(), &ask("kms:Decrypt", "*")),
        Decision::ExplicitDeny
    );
    assert_eq!(
        decide(
            &change(),
            &ask("kms:Decrypt", "*").with("aws:ViaAWSService", "true")
        ),
        Decision::ImplicitDeny
    );
}

#[test]
fn a_create_may_pass_only_a_pool_role_reserved_for_this_session_and_not_yet_bound() {
    let pool = |name: &str| {
        ask(
            "iam:PassRole",
            &format!("arn:aws:iam::{ACCT}:role/obx/{name}"),
        )
        .with("iam:PassedToService", "ec2.amazonaws.com")
    };
    let reserved =
        |name: &str| pool(name).with("iam:ResourceTag/ozbox-reserved-for", "AROAEXAMPLE:plan-abc");
    assert!(allowed(&change(), &reserved("obx-pool-03")));
    assert_eq!(
        decide(
            &change(),
            &reserved("obx-pool-03").with("iam:ResourceTag/ozbox-bound-instance", &instance("i-9"))
        ),
        Decision::ExplicitDeny,
        "a role a live box uses"
    );
    assert!(
        !allowed(
            &change(),
            &pool("obx-pool-04").with(
                "iam:ResourceTag/ozbox-reserved-for",
                "AROAEXAMPLE:plan-other"
            )
        ),
        "reserved for another window"
    );
    assert!(!allowed(&change(), &pool("obx-pool-05")), "not reserved");
    for other in [
        "obx-main",
        "obx-fleet-change",
        "obx-fleet-read",
        "obx-ozbox-issuer",
    ] {
        assert!(!allowed(&change(), &reserved(other)), "{other}");
    }
    assert!(!allowed(
        &change(),
        &ask(
            "iam:PassRole",
            &format!("arn:aws:iam::{ACCT}:role/ozbox-dev")
        )
        .with("iam:PassedToService", "ec2.amazonaws.com")
        .with("iam:ResourceTag/ozbox-reserved-for", "AROAEXAMPLE:plan-abc")
    ));
    assert!(!allowed(
        &change(),
        &reserved("obx-pool-03").with("iam:PassedToService", "lambda.amazonaws.com")
    ));
}

#[test]
fn state_is_the_managed_buckets_box_objects_only() {
    let bucket = format!("ozbox-tfstate-managed-{ACCT}");
    assert!(allowed(
        &change(),
        &ask(
            "s3:PutObject",
            &format!("arn:aws:s3:::{bucket}/ozbox/boxes/dev.tfstate")
        )
    ));
    assert!(
        !allowed(
            &change(),
            &ask(
                "s3:PutObject",
                &format!("arn:aws:s3:::ozbox-tfstate-{ACCT}/ozbox/boxes/dev.tfstate")
            )
        ),
        "the laptop's own state bucket"
    );
    assert!(!allowed(
        &change(),
        &ask("s3:PutObject", &format!("arn:aws:s3:::{bucket}/other/x"))
    ));
    assert!(!allowed(
        &change(),
        &ask("s3:PutBucketPolicy", &format!("arn:aws:s3:::{bucket}"))
    ));
    assert!(
        !allowed(
            &change(),
            &ask("s3:ListBucket", &format!("arn:aws:s3:::{bucket}"))
        ),
        "no prefix"
    );
}

/// The setup module fills the same tokens with the same rule (lists replace the quoted token); a token one side knows and the
/// other does not would leave a document half filled.
#[test]
fn the_setup_module_fills_exactly_the_tokens_render_fills() {
    let module = include_str!("../../../infra/tofu/modules/aws-fleet-manager/main.tf");
    for token in [
        "\\\"$${regions}\\\"",
        "\\\"$${sizes}\\\"",
        "\\\"$${image_ids}\\\"",
        "\\\"$${subnet_arns}\\\"",
        "$${fleet_manager_box}",
        "$${account_id}",
        "$${max_volume_gb}",
        "$${max_iops}",
        "$${max_throughput}",
        "$${main_role_arn}",
        "$${window_principal_arn}",
    ] {
        assert!(module.contains(token), "the module does not fill {token}");
    }
    for d in Doc::ALL {
        assert!(
            module.contains(d.file()),
            "the module does not read {}",
            d.file()
        );
    }
}

// ---- review findings M3, L1, L2 (2026-11-17) -------------------------------------------------------------------------------

/// The fleet manager's box name the setup module is given (`fleet_manager_box`).
const MAIN_BOX: &str = "main";
/// A subnet the setup module is given as Oz Box's own (`subnet_ids`), and one it is not.
const OZBOX_SUBNET: &str = "subnet-0123456789abcdef0";
const FOREIGN_SUBNET: &str = "subnet-0fffffffffffffff0";

fn subnet_arn(id: &str) -> String {
    format!("arn:aws:ec2:{REGION}:{ACCT}:subnet/{id}")
}

fn interface(id: &str) -> String {
    format!("arn:aws:ec2:{REGION}:{ACCT}:network-interface/{id}")
}

/// M3: a launch that names an EXISTING network interface takes that interface's subnet and groups, so the interface itself
/// must be in one of Oz Box's subnets (`ec2:Subnet`), and an interface tagged as someone else's is refused outright.
#[test]
fn a_launch_on_an_existing_interface_in_a_foreign_network_is_refused() {
    let eni = |id: &str, subnet: &str| {
        ask("ec2:RunInstances", &interface(id)).with("ec2:Subnet", &subnet_arn(subnet))
    };
    assert!(
        allowed(&change(), &eni("*", OZBOX_SUBNET)),
        "the launch's own new interface, in an Oz Box subnet"
    );
    assert!(
        !allowed(&change(), &eni("eni-0fffffffffffffff0", FOREIGN_SUBNET)),
        "an existing interface in a foreign subnet"
    );
    assert!(
        !allowed(
            &change(),
            &ask("ec2:RunInstances", &interface("eni-0fffffffffffffff0"))
        ),
        "an interface whose subnet is not in the request"
    );
    assert_eq!(
        decide(
            &change(),
            &eni("eni-0eeeeeeeeeeeeeee0", OZBOX_SUBNET)
                .with("aws:ResourceTag/ozbox-managed", "false")
        ),
        Decision::ExplicitDeny,
        "an interface tagged as someone else's, even inside an Oz Box subnet"
    );
}

/// L1: nothing may be attached to `main`, `main` is never started by a fleet role, and a plan window attaches only its own
/// box's disks to its own box's machine.
#[test]
fn nothing_is_attached_to_main_and_a_window_attaches_only_its_own_boxs_disks() {
    let main_tagged = |a: Ask| managed(a).with("aws:ResourceTag/ozbox-fleet-manager", "true");
    for act in ["ec2:AttachVolume", "ec2:StartInstances", "ec2:DetachVolume"] {
        assert_eq!(
            decide(&change(), &main_tagged(ask(act, &instance("i-main")))),
            Decision::ExplicitDeny,
            "{act} on main"
        );
    }
    assert_eq!(
        decide(
            &change(),
            &main_tagged(ask("ec2:AttachVolume", &volume("vol-main")))
        ),
        Decision::ExplicitDeny,
        "main's disk to another box"
    );
    let attach = |res: String, owner: &str, window: Option<&str>| {
        let a = managed(ask("ec2:AttachVolume", &res)).with("aws:ResourceTag/ozbox-box", owner);
        match window {
            Some(w) => a.with("aws:PrincipalTag/ozbox-window-box", w),
            None => a,
        }
    };
    assert!(allowed(&change(), &attach(volume("vol-b"), "b", Some("b"))));
    assert!(allowed(&change(), &attach(instance("i-b"), "b", Some("b"))));
    assert_eq!(
        decide(&change(), &attach(volume("vol-a"), "a", Some("b"))),
        Decision::ExplicitDeny,
        "box a's detached disk, in box b's window"
    );
    assert_eq!(
        decide(&change(), &attach(instance("i-a"), "a", Some("b"))),
        Decision::ExplicitDeny,
        "onto box a's machine, in box b's window"
    );
    assert_eq!(
        decide(&change(), &attach(volume("vol-b"), "b", None)),
        Decision::ExplicitDeny,
        "a plan window that does not name its box attaches nothing"
    );
}

/// L2: `main`'s snapshots taken before it was marked (and every snapshot the CLI makes, which carries `ozbox-box` but not the
/// fleet manager's tag), and its system disk (whose tags are never rewritten in place), are protected by its box NAME too.
#[test]
fn main_is_protected_by_its_name_as_well_as_its_tag() {
    let mains = |a: Ask| managed(a).with("aws:ResourceTag/ozbox-box", MAIN_BOX);
    for act in ["ec2:RunInstances", "ec2:CreateVolume"] {
        assert_eq!(
            decide(&change(), &mains(ask(act, &snapshot("snap-old-main")))),
            Decision::ExplicitDeny,
            "{act} from a snapshot of main taken before the mark"
        );
    }
    for act in [
        "ec2:CreateSnapshot",
        "ec2:AttachVolume",
        "ec2:DetachVolume",
        "ec2:DeleteVolume",
        "ec2:ModifyVolume",
    ] {
        assert_eq!(
            decide(&change(), &mains(ask(act, &volume("vol-main-root")))),
            Decision::ExplicitDeny,
            "{act} on main's unmarked system disk"
        );
    }
    for act in [
        "ec2:StopInstances",
        "ec2:StartInstances",
        "ec2:TerminateInstances",
    ] {
        assert_eq!(
            decide(&change(), &mains(ask(act, &instance("i-main")))),
            Decision::ExplicitDeny,
            "{act} on main by name"
        );
    }
    // and nothing new may be named main
    assert_eq!(
        decide(
            &change(),
            &good_launch().with("aws:RequestTag/ozbox-box", MAIN_BOX)
        ),
        Decision::ExplicitDeny,
        "a launch named like main"
    );
    // another box's snapshot still clones
    assert!(allowed(
        &change(),
        &managed(ask("ec2:RunInstances", &snapshot("snap-dev")))
            .with("aws:ResourceTag/ozbox-box", "dev")
    ));
}

/// Each managed policy stays under IAM's managed-policy size (6,144 characters, whitespace not counted), with room for the
/// longest values the setup module accepts, so a guard statement added later cannot make the setup refuse at apply.
#[test]
fn every_managed_policy_fits_iams_size_limit() {
    let mut v = vars();
    v.regions = vec![
        "ap-southeast-3".into(),
        "us-east-1".into(),
        "eu-west-1".into(),
    ];
    v.subnet_ids = (0..6)
        .map(|i| format!("subnet-0123456789abcdef{i}"))
        .collect();
    v.image_ids = (0..4).map(|i| format!("ami-0123456789abcdef{i}")).collect();
    v.fleet_manager_box = "a".repeat(40);
    for d in [
        Doc::Read,
        Doc::Cost,
        Doc::Change,
        Doc::ChangeGuard,
        Doc::MainAssume,
    ] {
        let text = fleet_policy::render(d, &v).unwrap().to_string();
        let n = text.chars().filter(|c| !c.is_whitespace()).count();
        assert!(n <= 6144, "{d:?} is {n} characters");
    }
}

// ---- a window's session policy (Amendment 2) -----------------------------------------------------------------------------------
//
// IAM gives a session what the role AND its session policy both allow; an explicit deny in either wins. These tests render the
// session policy the laptop would attach for one plan, evaluate it together with the role's documents, and prove that the
// session can do what the plan does and nothing more.

use ozbox_core::{BoxName, BoxSpec, Operation, Size};
use ozbox_provider_aws::fleet_session::{self, rfc3339, WindowGrant, WindowRequest};

const NOW: u64 = 1_800_000_000;

fn grant_for(op: &Operation, machine_type: Option<&str>) -> WindowGrant {
    fleet_session::grant(&WindowRequest {
        operation: op,
        account_id: ACCT,
        plan_id: "p1",
        person: "owner",
        now_secs: NOW,
        window_secs: 1800,
        machine_type,
    })
    .unwrap()
}

fn session_of(g: &WindowGrant) -> Value {
    serde_json::from_str(&g.session_policy).unwrap()
}

/// The session's decision: an explicit deny from the role or the session wins; an allow needs BOTH.
fn effective(g: &WindowGrant, a: &Ask) -> Decision {
    let sess = vec![session_of(g)];
    let (r, s) = (decide(&change(), a), decide(&sess, a));
    if r == Decision::ExplicitDeny || s == Decision::ExplicitDeny {
        Decision::ExplicitDeny
    } else if r == Decision::Allow && s == Decision::Allow {
        Decision::Allow
    } else {
        Decision::ImplicitDeny
    }
}

/// A request from inside the window of the plan's box, a minute after it opened.
fn in_window(g: &WindowGrant, a: Ask) -> Ask {
    let (k, v) = &g.tags[0];
    a.with(&format!("aws:PrincipalTag/{k}"), v)
        .with("aws:CurrentTime", &rfc3339(NOW + 60))
}

fn on_box(a: Ask, b: &str) -> Ask {
    managed(a).with("aws:ResourceTag/ozbox-box", b)
}

fn n(s: &str) -> BoxName {
    BoxName::new(s).unwrap()
}

#[test]
fn a_destroy_window_destroys_that_box_and_nothing_else() {
    let op = Operation::Destroy {
        name: n("dev"),
        final_snapshot: false,
        keep_old_system_disks: false,
    };
    let g = grant_for(&op, None);
    for act in ["ec2:TerminateInstances", "ec2:DeleteVolume"] {
        let res = if act.contains("Volume") {
            volume("vol-1")
        } else {
            instance("i-1")
        };
        assert_eq!(
            effective(&g, &in_window(&g, on_box(ask(act, &res), "dev"))),
            Decision::Allow,
            "{act} on the plan's box"
        );
        // the role alone would allow another managed box: the session does not
        assert!(
            allowed(&change(), &on_box(ask(act, &res), "other")),
            "the role's ceiling allows it"
        );
        assert_eq!(
            effective(&g, &in_window(&g, on_box(ask(act, &res), "other"))),
            Decision::ImplicitDeny,
            "{act} on another box"
        );
        // and a resource with no box tag at all
        assert_eq!(
            effective(&g, &in_window(&g, managed(ask(act, &res)))),
            Decision::ImplicitDeny,
            "{act} untagged by box"
        );
    }
    // acts the plan does not make: refused although the role allows each
    for (act, res) in [
        ("ec2:StopInstances", instance("i-1")),
        ("ec2:StartInstances", instance("i-1")),
        ("ec2:CreateSnapshot", volume("vol-1")),
    ] {
        let a = in_window(&g, on_box(ask(act, &res), "dev"));
        assert!(allowed(&change(), &a), "the role allows {act}");
        assert_eq!(
            effective(&g, &a),
            Decision::ImplicitDeny,
            "{act} is not in a destroy plan"
        );
    }
    // the box's state objects, and no other box's
    let st = |b: &str| {
        in_window(
            &g,
            ask(
                "s3:DeleteObject",
                &format!("arn:aws:s3:::ozbox-tfstate-managed-{ACCT}/ozbox/boxes/{b}/main.tfstate"),
            ),
        )
    };
    assert_eq!(effective(&g, &st("dev")), Decision::Allow);
    assert_eq!(effective(&g, &st("other")), Decision::ImplicitDeny);
}

#[test]
fn a_destroy_that_keeps_a_final_snapshot_may_snapshot_and_only_that_box() {
    let op = Operation::Destroy {
        name: n("dev"),
        final_snapshot: true,
        keep_old_system_disks: false,
    };
    let g = grant_for(&op, None);
    let snap = |b: &str| in_window(&g, on_box(ask("ec2:CreateSnapshot", &volume("vol-1")), b));
    assert_eq!(effective(&g, &snap("dev")), Decision::Allow);
    assert_eq!(effective(&g, &snap("other")), Decision::ImplicitDeny);
}

#[test]
fn a_pause_window_stops_that_box_and_cannot_start_or_destroy_it() {
    let op = Operation::Pause { name: n("dev") };
    let g = grant_for(&op, None);
    let stop = |b: &str| in_window(&g, on_box(ask("ec2:StopInstances", &instance("i-1")), b));
    assert_eq!(effective(&g, &stop("dev")), Decision::Allow);
    assert_eq!(effective(&g, &stop("other")), Decision::ImplicitDeny);
    for act in ["ec2:StartInstances", "ec2:TerminateInstances"] {
        assert_eq!(
            effective(
                &g,
                &in_window(&g, on_box(ask(act, &instance("i-1")), "dev"))
            ),
            Decision::ImplicitDeny,
            "{act}"
        );
    }
    // main stays protected by the role's own deny, whatever the session says
    let main_tagged = in_window(
        &g,
        on_box(ask("ec2:StopInstances", &instance("i-main")), "dev")
            .with("aws:ResourceTag/ozbox-fleet-manager", "true"),
    );
    assert_eq!(effective(&g, &main_tagged), Decision::ExplicitDeny);
}

#[test]
fn a_resume_window_starts_that_box_and_cannot_stop_it() {
    let op = Operation::Resume { name: n("dev") };
    let g = grant_for(&op, None);
    let a = |act: &str| in_window(&g, on_box(ask(act, &instance("i-1")), "dev"));
    assert_eq!(effective(&g, &a("ec2:StartInstances")), Decision::Allow);
    assert_eq!(
        effective(&g, &a("ec2:StopInstances")),
        Decision::ImplicitDeny
    );
}

#[test]
fn a_snapshot_window_snapshots_that_boxs_volume_and_tags_it_at_birth_only() {
    let op = Operation::Snapshot { name: n("dev") };
    let g = grant_for(&op, None);
    assert_eq!(
        effective(
            &g,
            &in_window(
                &g,
                on_box(ask("ec2:CreateSnapshot", &volume("vol-1")), "dev")
            )
        ),
        Decision::Allow
    );
    // the new snapshot carries the box's tag at birth
    let born = |b: &str| {
        in_window(
            &g,
            ask("ec2:CreateSnapshot", &snapshot("*"))
                .with("aws:RequestTag/ozbox-managed", "true")
                .with("aws:RequestTag/ozbox-box", b),
        )
    };
    assert_eq!(effective(&g, &born("dev")), Decision::Allow);
    assert_eq!(effective(&g, &born("other")), Decision::ImplicitDeny);
    assert_eq!(
        effective(
            &g,
            &in_window(
                &g,
                on_box(ask("ec2:TerminateInstances", &instance("i-1")), "dev")
            )
        ),
        Decision::ImplicitDeny
    );
}

fn volume_make(size: &str) -> Ask {
    ask("ec2:CreateVolume", &volume("*"))
        .with("aws:RequestTag/ozbox-managed", "true")
        .with("ec2:VolumeType", "gp3")
        .with("ec2:Encrypted", "true")
        .with("ec2:VolumeSize", size)
        .with("ec2:VolumeIops", "3000")
        .with("ec2:VolumeThroughput", "125")
}

#[test]
fn a_create_window_launches_the_one_box_of_the_one_type_with_the_one_disk_size() {
    let mut spec = BoxSpec::new(n("dev"), Size::S);
    spec.work_disk_gb = 100;
    let op = Operation::Create { spec };
    let g = grant_for(&op, None);
    let launch = |b: &str, ty: &str| {
        in_window(
            &g,
            good_launch()
                .with("ec2:InstanceType", ty)
                .with("aws:RequestTag/ozbox-box", b),
        )
    };
    assert_eq!(effective(&g, &launch("dev", "m7i.xlarge")), Decision::Allow);
    // the role allows both of these; the session names neither
    assert!(allowed(&change(), &launch("dev", "c7i.xlarge")));
    assert_eq!(
        effective(&g, &launch("dev", "c7i.xlarge")),
        Decision::ImplicitDeny,
        "another type"
    );
    assert_eq!(
        effective(&g, &launch("other", "m7i.xlarge")),
        Decision::ImplicitDeny,
        "another box"
    );
    // the /work disk is at most the plan's size, and carries the plan's box
    let vol =
        |size: &str, b: &str| in_window(&g, volume_make(size).with("aws:RequestTag/ozbox-box", b));
    assert_eq!(effective(&g, &vol("100", "dev")), Decision::Allow);
    assert!(allowed(&change(), &vol("400", "dev")));
    assert_eq!(
        effective(&g, &vol("400", "dev")),
        Decision::ImplicitDeny,
        "a larger disk"
    );
    assert_eq!(effective(&g, &vol("100", "other")), Decision::ImplicitDeny);
    // a create has no business destroying, stopping or snapshotting anything
    for (act, res) in [
        ("ec2:TerminateInstances", instance("i-1")),
        ("ec2:StopInstances", instance("i-1")),
        ("ec2:DeleteVolume", volume("vol-1")),
        ("ec2:CreateSnapshot", volume("vol-1")),
    ] {
        assert_eq!(
            effective(&g, &in_window(&g, on_box(ask(act, &res), "dev"))),
            Decision::ImplicitDeny,
            "{act}"
        );
    }
}

#[test]
fn a_clone_window_reads_only_its_source_snapshots_and_launches_the_one_type() {
    let op = Operation::Clone {
        from: n("src"),
        to: n("copy"),
        snapshot: None,
    };
    let g = grant_for(&op, Some("m7i.xlarge"));
    let from_snap = |b: &str| {
        in_window(
            &g,
            ask("ec2:RunInstances", &snapshot("snap-1"))
                .with("aws:ResourceTag/ozbox-managed", "true")
                .with("aws:ResourceTag/ozbox-box", b),
        )
    };
    assert_eq!(effective(&g, &from_snap("src")), Decision::Allow);
    assert!(allowed(&change(), &from_snap("elsewhere")));
    assert_eq!(
        effective(&g, &from_snap("elsewhere")),
        Decision::ImplicitDeny,
        "another box's snapshot"
    );
    let launch = |ty: &str| {
        in_window(
            &g,
            good_launch()
                .with("ec2:InstanceType", ty)
                .with("aws:RequestTag/ozbox-box", "copy"),
        )
    };
    assert_eq!(effective(&g, &launch("m7i.xlarge")), Decision::Allow);
    assert!(allowed(&change(), &launch("c7i.xlarge")));
    assert_eq!(
        effective(&g, &launch("c7i.xlarge")),
        Decision::ImplicitDeny,
        "another type"
    );
    // the new box is `copy` (the window's tag), never the source
    assert_eq!(
        g.tags,
        vec![("ozbox-window-box".to_string(), "copy".to_string())]
    );
}

#[test]
fn a_resize_window_changes_one_boxs_type_to_the_one_planned_type_only() {
    let op = Operation::Resize {
        name: n("dev"),
        size: Some(Size::XS),
        work_disk_gb: None,
    };
    let g = grant_for(&op, None);
    let attr = |b: &str, ty: &str| {
        in_window(
            &g,
            on_box(ask("ec2:ModifyInstanceAttribute", &instance("i-1")), b)
                .with("ec2:Attribute/InstanceType", ty),
        )
    };
    // c7i.xlarge is XS: the plan's type
    assert_eq!(effective(&g, &attr("dev", "c7i.xlarge")), Decision::Allow);
    // the role allows the other type and the other box; the session names neither
    assert!(allowed(&change(), &attr("dev", "m7i.xlarge")));
    assert_eq!(
        effective(&g, &attr("dev", "m7i.xlarge")),
        Decision::ImplicitDeny,
        "not the planned type"
    );
    assert_eq!(
        effective(&g, &attr("other", "c7i.xlarge")),
        Decision::ImplicitDeny,
        "not the plan's box"
    );
    // stop and start belong to the resize; terminate does not
    let a = |act: &str| in_window(&g, on_box(ask(act, &instance("i-1")), "dev"));
    assert_eq!(effective(&g, &a("ec2:StopInstances")), Decision::Allow);
    assert_eq!(effective(&g, &a("ec2:StartInstances")), Decision::Allow);
    assert_eq!(
        effective(&g, &a("ec2:TerminateInstances")),
        Decision::ImplicitDeny
    );
}

#[test]
fn nothing_is_allowed_after_the_window_ends_and_nothing_before_it_for_another_plans_box() {
    let op = Operation::Pause { name: n("dev") };
    let g = grant_for(&op, None);
    let stop = ask("ec2:StopInstances", &instance("i-1"));
    let at = |secs: u64| {
        on_box(stop.clone(), "dev")
            .with("aws:PrincipalTag/ozbox-window-box", "dev")
            .with("aws:CurrentTime", &rfc3339(secs))
    };
    assert_eq!(effective(&g, &at(NOW + 1799)), Decision::Allow);
    assert_eq!(
        effective(&g, &at(NOW + 1801)),
        Decision::ExplicitDeny,
        "after the expiry"
    );
    // even a read
    let read = ask("ec2:DescribeInstances", "*")
        .with("aws:PrincipalTag/ozbox-window-box", "dev")
        .with("aws:CurrentTime", &rfc3339(NOW + 5000));
    assert_eq!(effective(&g, &read), Decision::ExplicitDeny);
    // a session whose tag names another box finds the policy's variable naming that box
    let wrong = on_box(stop.clone(), "dev")
        .with("aws:PrincipalTag/ozbox-window-box", "other")
        .with("aws:CurrentTime", &rfc3339(NOW + 60));
    assert_eq!(effective(&g, &wrong), Decision::ImplicitDeny);
}

#[test]
fn no_plan_window_ever_reaches_iam_kms_secrets_a_shell_or_another_role() {
    let ops = vec![
        Operation::Pause { name: n("dev") },
        Operation::Destroy {
            name: n("dev"),
            final_snapshot: true,
            keep_old_system_disks: false,
        },
        Operation::Create {
            spec: BoxSpec::new(n("dev"), Size::S),
        },
        Operation::Resize {
            name: n("dev"),
            size: Some(Size::XS),
            work_disk_gb: Some(300),
        },
    ];
    for op in ops {
        let g = grant_for(&op, None);
        for (act, res) in [
            ("iam:CreateRole", "*"),
            ("iam:AttachRolePolicy", "*"),
            (
                "iam:PassRole",
                "arn:aws:iam::123456789012:role/obx/obx-main",
            ),
            (
                "iam:PassRole",
                "arn:aws:iam::123456789012:role/obx/obx-fleet-change",
            ),
            ("kms:Decrypt", "*"),
            ("secretsmanager:GetSecretValue", "*"),
            ("ssm:GetParameter", "*"),
            ("ssm:StartSession", "*"),
            ("ssm:SendCommand", "*"),
            ("sts:AssumeRole", "*"),
            ("ec2:DeleteSnapshot", "*"),
            ("ec2:ModifyInstanceAttribute", "*"),
            ("s3:GetObject", "arn:aws:s3:::someone-elses-bucket/x"),
        ] {
            let a = in_window(
                &g,
                ask(act, res)
                    .with("aws:ResourceTag/ozbox-managed", "true")
                    .with("aws:ResourceTag/ozbox-box", "dev"),
            );
            assert_ne!(
                effective(&g, &a),
                Decision::Allow,
                "{} window: {act} on {res}",
                op.verb()
            );
        }
    }
}

#[test]
fn a_window_session_is_one_the_roles_trust_accepts_and_the_guard_reads() {
    let op = Operation::Pause { name: n("dev") };
    let g = grant_for(&op, None);
    let trust = doc(Doc::ChangeTrust);
    let st = &trust["Statement"][0];
    let names = strings(st["Condition"]["StringLike"].get("sts:RoleSessionName"));
    assert_eq!(names, vec!["plan-*".to_string()], "plan windows only");
    assert!(names.iter().any(|p| glob(p, &g.role_session_name, false)));
    assert!(glob(
        st["Condition"]["StringLike"]["sts:SourceIdentity"]
            .as_str()
            .unwrap(),
        &g.source_identity,
        false
    ));
    assert!(g.role_arn.ends_with("/obx/obx-fleet-change"));
    // the guard's attach rule reads the session tag the grant carries
    assert_eq!(g.tags[0].0, "ozbox-window-box");
}
