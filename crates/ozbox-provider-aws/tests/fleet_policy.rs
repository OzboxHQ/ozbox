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

/// IAM policy variables in a condition VALUE (`${aws:userid}`), filled from the request.
fn fill(v: &str, a: &Ask) -> String {
    let mut out = v.to_string();
    for (k, vals) in &a.ctx {
        if let Some(first) = vals.first() {
            out = out.replace(&format!("${{{k}}}"), first);
        }
    }
    out
}

const OPERATORS: [&str; 11] = [
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
];

fn condition_holds(op: &str, key: &str, want: &[String], a: &Ask) -> bool {
    let want: Vec<String> = want.iter().map(|w| fill(w, a)).collect();
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
    if s.get("Resource").is_some() && !resources.iter().any(|p| glob(p, &a.resource, false)) {
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
