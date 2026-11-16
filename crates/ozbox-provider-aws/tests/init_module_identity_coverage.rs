#![allow(clippy::unwrap_used)]
//! Every module `ozbox init` applies with a dedicated permission set is made only of resource types that set can apply.
//!
//! `ozbox init` applies each of these modules as the **setup identity**, with the permission set named beside it. Its
//! pre-flight asks about the actions of the step it is about to run, so a module that gains a resource type the set does not
//! cover passes the check and then fails part way through the apply (the round-4 defect: a Systems Manager document added to
//! the KMS-only key module). Mocked `tofu test` runs cannot see that, so this test does:
//!
//! - it lists every `resource "<type>"` block in each module's `.tf` files;
//! - it maps each type to the actions applying it calls (`ozbox_provider_aws::init_actions`, the table the CLI's pre-flight
//!   lists are also held to: a type missing from it fails, so a new resource is a deliberate edit there). The table covers
//!   create, read back, tag, update and destroy; an action the set deliberately does not grant is named in
//!   `DELIBERATELY_NOT_GRANTED` with the reason;
//! - it checks every action is allowed by an `Allow` statement of the module's permission set whose `Resource` reaches a
//!   resource of that type and whose `Condition` uses only keys the apply can satisfy, and is not denied on any such resource
//!   (a Deny with a `Condition` counts, since the apply cannot be shown to avoid it);
//! - it checks every module `ozbox init` plans (read from `init.rs`) is either in the list below or in the exempt list with its
//!   reason, so a new init step with a new module is not unguarded.

use ozbox_provider_aws::init_actions::{resource_actions, DELIBERATELY_NOT_GRANTED};
use serde_json::Value;
use std::collections::BTreeSet;
use std::path::Path;

/// Sample ARNs of a resource type in a region and account, for `Resource` matching.
fn samples(resource_type: &str) -> Vec<String> {
    let acct = "123456789012";
    match resource_type {
        "aws_kms_key" => vec![format!("arn:aws:kms:us-east-1:{acct}:key/00000000")],
        "aws_kms_alias" => vec![
            format!("arn:aws:kms:us-east-1:{acct}:alias/ozbox-fleet-secrets"),
            format!("arn:aws:kms:us-east-1:{acct}:key/00000000"),
        ],
        "aws_iam_policy" => vec![format!(
            "arn:aws:iam::{acct}:policy/ozbox-box-session-manager"
        )],
        "aws_ssm_document" => vec![format!(
            "arn:aws:ssm:us-east-1:{acct}:document/ozbox-adopt-fleet"
        )],
        "aws_vpc" => vec![format!("arn:aws:ec2:us-east-1:{acct}:vpc/vpc-0")],
        "aws_internet_gateway" => vec![format!(
            "arn:aws:ec2:us-east-1:{acct}:internet-gateway/igw-0"
        )],
        "aws_subnet" => vec![format!("arn:aws:ec2:us-east-1:{acct}:subnet/subnet-0")],
        "aws_eip" => vec![format!(
            "arn:aws:ec2:us-east-1:{acct}:elastic-ip/eipalloc-0"
        )],
        "aws_nat_gateway" => vec![format!("arn:aws:ec2:us-east-1:{acct}:natgateway/nat-0")],
        "aws_route_table" | "aws_route" | "aws_route_table_association" => {
            vec![format!("arn:aws:ec2:us-east-1:{acct}:route-table/rtb-0")]
        }
        other => panic!("no sample ARN for {other}"),
    }
}

/// Condition keys an apply can satisfy: the tags the modules put on what they make.
const SATISFIABLE_CONDITION_KEYS: [&str; 3] = [
    "aws:RequestTag/ozbox-managed",
    "aws:ResourceTag/ozbox-managed",
    "aws:TagKeys",
];

fn glob(pattern: &str, text: &str) -> bool {
    // `*` matches any run; the policies use no other wildcard in a Resource
    let parts: Vec<&str> = pattern.split('*').collect();
    let mut rest = text;
    for (i, part) in parts.iter().enumerate() {
        if i == 0 {
            if !rest.starts_with(part) {
                return false;
            }
            rest = &rest[part.len()..];
        } else if i == parts.len() - 1 {
            return rest.ends_with(part);
        } else {
            match rest.find(part) {
                Some(at) => rest = &rest[at + part.len()..],
                None => return false,
            }
        }
    }
    rest.is_empty()
}

fn reaches(statement: &Value, samples: &[String]) -> bool {
    strings(&statement["Resource"]).iter().any(|p| {
        let p = p.replace("${account_id}", "123456789012");
        samples.iter().any(|s| glob(&p, s))
    })
}

fn condition_keys(statement: &Value) -> Vec<String> {
    statement
        .get("Condition")
        .and_then(Value::as_object)
        .map(|c| {
            c.values()
                .filter_map(Value::as_object)
                .flat_map(|m| m.keys().cloned())
                .collect()
        })
        .unwrap_or_default()
}

/// (module directory, the permission set `ozbox init` applies it with)
const APPLIED_BY_INIT: [(&str, &str); 3] = [
    ("aws-secrets-key", "key-admin-policy.json"),
    ("aws-box-policy", "box-policy-admin-policy.json"),
    ("aws-adopt-command", "adopt-admin-policy.json"),
];

/// Every module `ozbox init` applies on a plain run (`ozbox init --provider aws`), all with the one setup identity.
const SETUP_MODULES: [&str; 4] = [
    "aws-secrets-key",
    "aws-box-policy",
    "aws-adopt-command",
    "aws-network",
];

fn infra() -> std::path::PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../../infra")
}

fn resource_types(module: &str) -> BTreeSet<String> {
    let dir = infra().join("tofu/modules").join(module);
    let mut found = BTreeSet::new();
    for e in std::fs::read_dir(&dir).unwrap() {
        let p = e.unwrap().path();
        if p.extension().and_then(|x| x.to_str()) != Some("tf") {
            continue;
        }
        for line in std::fs::read_to_string(&p).unwrap().lines() {
            if let Some(rest) = line.trim_start().strip_prefix("resource \"") {
                found.insert(rest.split('"').next().unwrap().to_string());
            }
        }
    }
    found
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

fn matches(pattern: &str, action: &str) -> bool {
    pattern == action
        || (pattern.ends_with('*') && action.starts_with(pattern.trim_end_matches('*')))
}

fn permission_set(file: &str) -> Vec<Value> {
    let text = std::fs::read_to_string(infra().join("aws").join(file)).unwrap();
    let v: Value = serde_json::from_str(&text).unwrap();
    v["Statement"].as_array().unwrap().clone()
}

fn check_modules(modules: &[(&str, &str)]) {
    for (module, policy) in modules.iter().copied() {
        let types = resource_types(module);
        assert!(!types.is_empty(), "{module} has no resources: wrong path?");
        let set = permission_set(policy);
        for t in &types {
            let actions = resource_actions(t).unwrap_or_else(|| {
                panic!(
                    "{module} has a `{t}` resource the coverage table does not know: add its actions to init_actions::resource_actions, and to {policy} if `ozbox init` must apply it with that set"
                )
            });
            let reach = samples(t);
            for a in actions {
                if let Some((_, why)) = DELIBERATELY_NOT_GRANTED.iter().find(|(x, _)| x == a) {
                    assert!(!why.is_empty());
                    let granted = set.iter().any(|s| {
                        s["Effect"] == "Allow"
                            && strings(&s["Action"]).iter().any(|p| matches(p, a))
                    });
                    assert!(
                        !granted,
                        "{a} is listed as deliberately not granted but {policy} grants it"
                    );
                    continue;
                }
                let allowed = set.iter().any(|s| {
                    s["Effect"] == "Allow"
                        && strings(&s["Action"]).iter().any(|p| matches(p, a))
                        && reaches(s, &reach)
                        && condition_keys(s)
                            .iter()
                            .all(|k| SATISFIABLE_CONDITION_KEYS.contains(&k.as_str()))
                });
                assert!(
                    allowed,
                    "{module}: `{t}` needs {a}, which {policy} does not allow on a {t} (an Allow that names the action, reaches the resource and sets only conditions the apply can meet): init would pass its check and fail mid-apply"
                );
                let denied = set.iter().any(|s| {
                    s["Effect"] == "Deny"
                        && strings(&s["Action"]).iter().any(|p| matches(p, a))
                        && reaches(s, &reach)
                        && s.get("Condition").is_none_or(|c| {
                            // a Deny on a production tag never meets what init makes (it makes no production key)
                            !c.to_string().contains("ozbox-production")
                                && !c.to_string().contains("BypassPolicyLockoutSafetyCheck")
                        })
                });
                assert!(!denied, "{module}: {a} is denied on a {t} by {policy}");
            }
        }
    }
}

#[test]
fn every_resource_type_in_a_module_init_applies_is_covered_by_the_identity_that_applies_it() {
    check_modules(&APPLIED_BY_INIT);
}

/// Every module `ozbox init` applies by default (not the opt-in security baseline and issuer) is covered by `OzBoxSetup`, the ONE
/// permission set a person signs in as to run it: on IAM Identity Center a sign-in profile is exactly one permission set, so
/// a module covered only by a separate file nobody can combine with it is a module init cannot apply. The network, which has
/// no file of its own, is checked here for the first time.
#[test]
fn every_resource_type_in_every_module_init_applies_by_default_is_covered_by_the_setup_policy() {
    let all: Vec<(&str, &str)> = SETUP_MODULES
        .iter()
        .map(|m| (*m, "setup-policy.json"))
        .collect();
    check_modules(&all);
}

fn init_modules() -> BTreeSet<String> {
    let src = std::fs::read_to_string(
        Path::new(env!("CARGO_MANIFEST_DIR")).join("../ozbox-cli/src/init.rs"),
    )
    .unwrap();
    // `fn <x>_dir(&self) -> PathBuf { self.modules.join("<module>") }`
    let mut dirs = std::collections::BTreeMap::new();
    let mut lines = src.lines().peekable();
    while let Some(l) = lines.next() {
        if let Some(name) = l
            .trim()
            .strip_prefix("fn ")
            .and_then(|r| r.strip_suffix("_dir(&self) -> PathBuf {"))
        {
            let body = lines.peek().copied().unwrap_or_default();
            if let Some(m) = body.split("self.modules.join(\"").nth(1) {
                dirs.insert(name.to_string(), m.split('"').next().unwrap().to_string());
            }
        }
    }
    assert!(
        dirs.len() >= 6,
        "found only {dirs:?}: did init.rs change shape?"
    );
    let mut used = BTreeSet::new();
    for (name, module) in &dirs {
        if src.contains(&format!("paths.{name}_dir()")) {
            used.insert(module.clone());
        }
    }
    used
}

/// Modules `ozbox init` plans that have NO dedicated permission set and are not in `SETUP_MODULES`, each with the reason.
const EXEMPT: [(&str, &str); 3] = [
    ("aws-security-baseline", "opt-in: not part of `ozbox init`'s default run but of `ozbox harden` (init_cli.rs, plan_security), which has its own permission set, security-services-policy.json, checked by its own tests"),
    ("aws-issuer", "opt-in: planned only from a package the person names (`--issuer-package`), and its first apply needs an account administrator (it creates roles in the reserved /obx/ namespace, which the setup policy denies)"),
    ("aws-box", "read by init only to check it exists; boxes are made by `ozbox create` with the daily operator role"),
];

#[test]
fn every_module_init_plans_is_covered_or_exempt_with_a_reason() {
    let covered: BTreeSet<&str> = APPLIED_BY_INIT
        .iter()
        .map(|(m, _)| *m)
        .chain(SETUP_MODULES)
        .collect();
    for m in init_modules() {
        let exempt = EXEMPT.iter().any(|(e, why)| *e == m && !why.is_empty());
        assert!(
            covered.contains(m.as_str()) || exempt,
            "init.rs uses the module {m}, which is neither in APPLIED_BY_INIT (with its permission set) nor in EXEMPT (with a reason)"
        );
    }
    for m in APPLIED_BY_INIT.iter().map(|(m, _)| *m).chain(SETUP_MODULES) {
        assert!(
            init_modules().contains(m),
            "{m} is listed but init no longer applies it"
        );
    }
}

#[test]
fn the_key_module_is_kms_only_and_the_document_module_is_ssm_only() {
    for t in resource_types("aws-secrets-key") {
        assert!(
            t.starts_with("aws_kms_"),
            "aws-secrets-key holds {t}: its identity is KMS-only"
        );
    }
    for t in resource_types("aws-adopt-command") {
        assert!(t.starts_with("aws_ssm_"), "aws-adopt-command holds {t}");
    }
}

#[test]
fn the_adopt_permission_set_reaches_only_the_adopt_documents() {
    let set = permission_set("adopt-admin-policy.json");
    for s in set.iter().filter(|s| s["Effect"] == "Allow") {
        for a in strings(&s["Action"]) {
            assert!(a.starts_with("ssm:") && !a.ends_with('*'), "{a}");
        }
        for r in strings(&s["Resource"]) {
            assert!(r.ends_with(":document/ozbox-adopt-*"), "{r}");
        }
    }
    for a in [
        "ssm:SendCommand",
        "ssm:StartSession",
        "ssm:ModifyDocumentPermission",
    ] {
        assert!(
            set.iter().any(|s| s["Effect"] == "Deny"
                && s.get("Condition").is_none()
                && strings(&s["Action"]).iter().any(|p| p == a)),
            "{a} must be denied"
        );
    }
}

// ---------- the state bucket, which no module makes: the CLI does ----------

/// Statements of `file` as (Allow?, actions, resources, condition keys).
fn allows_on(set: &[Value], action: &str, arn: &str) -> bool {
    set.iter().any(|s| {
        s["Effect"] == "Allow"
            && strings(&s["Action"]).iter().any(|p| matches(p, action))
            && reaches(s, &[arn.to_string()])
            && condition_keys(s).is_empty()
    })
}

fn denied_on(set: &[Value], action: &str, arn: &str) -> bool {
    set.iter().any(|s| {
        s["Effect"] == "Deny"
            && strings(&s["Action"]).iter().any(|p| matches(p, action))
            && reaches(s, &[arn.to_string()])
    })
}

/// The `aws s3api <subcommand>` calls init.rs makes: the literal after each `"s3api"`.
fn s3api_subcommands() -> BTreeSet<String> {
    let src = std::fs::read_to_string(
        Path::new(env!("CARGO_MANIFEST_DIR")).join("../ozbox-cli/src/init.rs"),
    )
    .unwrap();
    // only the production code, before the test module
    let code = src.split("#[cfg(test)]").next().unwrap();
    let mut found = BTreeSet::new();
    let mut rest = code;
    while let Some(at) = rest.find("\"s3api\"") {
        rest = &rest[at + "\"s3api\"".len()..];
        let after = rest.trim_start_matches([',', ' ', '\n', '\t']);
        if let Some(lit) = after.strip_prefix('"') {
            found.insert(lit.split('"').next().unwrap().to_string());
        }
    }
    found
}

#[test]
fn the_state_bucket_init_makes_is_covered_by_the_setup_policy_and_not_by_the_operators() {
    use ozbox_provider_aws::init_actions::{
        s3api_action, STATE_BUCKET_EXTRA_ACTIONS, STATE_OBJECT_ACTIONS,
    };
    let cmds = s3api_subcommands();
    // the scan finds what init really calls, or this test would pass on an empty list
    for must in ["create-bucket", "head-bucket", "put-bucket-policy"] {
        assert!(
            cmds.contains(must),
            "found only {cmds:?}: did init.rs change shape?"
        );
    }
    let bucket = "arn:aws:s3:::ozbox-state-123456789012-us-east-1";
    let object = format!("{bucket}/ozbox/network/us-east-1.tfstate");
    let lock = format!("{bucket}/ozbox/network/us-east-1.tfstate.tflock");
    let setup = permission_set("setup-policy.json");
    let operator = permission_set("operator-policy.json");
    let mut actions: BTreeSet<&str> = STATE_BUCKET_EXTRA_ACTIONS.into_iter().collect();
    for c in &cmds {
        actions.insert(s3api_action(c).unwrap_or_else(|| {
            panic!("init.rs runs `aws s3api {c}`: add it to init_actions::s3api_action and to setup-policy.json")
        }));
    }
    for a in &actions {
        assert!(
            allows_on(&setup, a, bucket),
            "setup-policy.json must allow {a} on {bucket}"
        );
        assert!(
            !denied_on(&setup, a, bucket),
            "setup-policy.json denies {a} on the state bucket"
        );
        // the state bucket is the setup identity's: the daily role has no right to it
        assert!(
            !allows_on(&operator, a, bucket),
            "operator-policy.json must not reach the state bucket ({a})"
        );
    }
    for a in STATE_OBJECT_ACTIONS {
        for o in [&object, &lock] {
            assert!(
                allows_on(&setup, a, o),
                "setup-policy.json must allow {a} on {o}"
            );
            assert!(
                !allows_on(&operator, a, o),
                "the operator must not reach state objects ({a})"
            );
        }
    }
    // only this account's state buckets: another account's, and any other bucket, are out of reach
    for other in [
        "arn:aws:s3:::ozbox-state-999999999999-us-east-1",
        "arn:aws:s3:::some-other-bucket",
        "arn:aws:s3:::ozbox-tfstate-123456789012-us-east-1",
    ] {
        assert!(!allows_on(&setup, "s3:CreateBucket", other), "{other}");
    }
    // negative control: take the S3 statements out and the same check fails, so it is not vacuous
    let stripped: Vec<Value> = setup
        .iter()
        .filter(|s| !strings(&s["Action"]).iter().any(|a| a.starts_with("s3:")))
        .cloned()
        .collect();
    assert!(!allows_on(&stripped, "s3:CreateBucket", bucket));
    assert!(!allows_on(&stripped, "s3:PutObject", &object));
}

// ---------- the setup policy and the three files it must contain ----------

const IAM_IDENTITY_CENTER_INLINE_LIMIT: usize = 32_768;

#[test]
fn the_setup_policy_fits_an_identity_center_inline_policy() {
    let text = std::fs::read_to_string(infra().join("aws/setup-policy.json")).unwrap();
    // the whole file, whitespace included: stricter than the limit counts, so a reformat cannot push it over
    assert!(
        text.len() < IAM_IDENTITY_CENTER_INLINE_LIMIT,
        "setup-policy.json is {} characters; an Identity Center inline policy holds {IAM_IDENTITY_CENTER_INLINE_LIMIT}",
        text.len()
    );
    let v: Value = serde_json::from_str(&text).unwrap();
    assert_eq!(v["Version"], "2012-10-17");
    // a placeholder account, never a real one
    assert!(text.contains("${account_id}"));
    assert!(
        !regex_like_account_id(&text),
        "a real-looking account id is in the file"
    );
}

fn regex_like_account_id(text: &str) -> bool {
    let b = text.as_bytes();
    let mut i = 0;
    while i < b.len() {
        if b[i].is_ascii_digit() {
            let start = i;
            while i < b.len() && b[i].is_ascii_digit() {
                i += 1;
            }
            if i - start == 12 {
                return true;
            }
        } else {
            i += 1;
        }
    }
    false
}

/// Whether `set` allows `action` on the resource `pattern` of an admin statement: an Allow naming the action whose Resource
/// covers that whole pattern (a pattern covers another when every ARN of the other matches it) with the same Condition.
fn covers_resource(have: &str, want: &str) -> bool {
    have == "*"
        || have == want
        || (have.ends_with('*') && want.starts_with(have.trim_end_matches('*')))
}

#[test]
fn the_setup_policy_contains_every_statement_of_the_three_admin_policies() {
    let setup = permission_set("setup-policy.json");
    for file in [
        "key-admin-policy.json",
        "adopt-admin-policy.json",
        "box-policy-admin-policy.json",
    ] {
        for st in permission_set(file) {
            let sid = st["Sid"].as_str().unwrap();
            let effect = st["Effect"].as_str().unwrap();
            let acts = strings(&st["Action"]);
            let res = strings(&st["Resource"]);
            // every action of the admin statement, on every resource of it, has a setup statement of the same effect that
            // reaches it with the same Condition (a Deny: or the named exception below)
            for a in &acts {
                for r in &res {
                    let ok = setup.iter().any(|s| {
                        s["Effect"] == effect
                            && strings(&s["Action"]).iter().any(|p| matches(p, a))
                            && strings(&s["Resource"])
                                .iter()
                                .any(|h| covers_resource(h, r))
                            && s.get("Condition") == st.get("Condition")
                    });
                    if ok {
                        continue;
                    }
                    // the one deliberate difference: the key-admin "never use a key" Deny, which in the setup identity must
                    // let S3 use the account's S3 key for the state bucket (see SETUP_DENY_EXCEPTIONS)
                    let excepted = SETUP_DENY_EXCEPTIONS.iter().any(|(esid, _)| *esid == sid);
                    assert!(
                        excepted,
                        "{file}: {effect} `{sid}` ({a} on {r}) is not carried by setup-policy.json: the files have drifted"
                    );
                }
            }
        }
    }
}

/// Deny statements of an admin file that the setup policy carries NARROWER, with the reason.
const SETUP_DENY_EXCEPTIONS: [(&str, &str); 1] = [(
    "NeverUseAKey",
    "the state bucket is encrypted with aws:kms, so S3 calls kms:GenerateDataKey and kms:Decrypt as the caller on every state read and write; the setup policy keeps the Deny for every other use (kms:ViaService must be S3)",
)];

#[test]
fn the_setup_policys_narrower_key_deny_still_denies_every_direct_use_of_a_key() {
    let setup = permission_set("setup-policy.json");
    let original = permission_set("key-admin-policy.json");
    let want = original
        .iter()
        .find(|s| s["Sid"] == "NeverUseAKey")
        .unwrap();
    let ours = setup
        .iter()
        .find(|s| s["Sid"] == "NeverUseAKeyExceptThroughTheStateBucket")
        .unwrap_or_else(|| panic!("the narrowed key Deny is present"));
    assert_eq!(ours["Effect"], "Deny");
    assert_eq!(ours["Action"], want["Action"], "it denies the same actions");
    assert_eq!(ours["Resource"], want["Resource"], "on the same resources");
    // the only difference is: not when S3 is the caller's proxy
    assert_eq!(
        ours["Condition"],
        serde_json::json!({"StringNotLike": {"kms:ViaService": "s3.*.amazonaws.com"}})
    );
    // and nothing in the file allows a direct use of a key at all
    for s in setup.iter().filter(|s| s["Effect"] == "Allow") {
        for a in strings(&s["Action"]) {
            for used in [
                "kms:Encrypt",
                "kms:Decrypt",
                "kms:GenerateDataKey",
                "kms:CreateGrant",
            ] {
                assert!(!matches(&a, used), "{a} would allow {used}");
            }
        }
    }
}

#[test]
fn the_setup_policy_carries_the_operators_explicit_denies_and_nothing_allows_what_they_deny() {
    let setup = permission_set("setup-policy.json");
    let operator = permission_set("operator-policy.json");
    for sid in [
        "NeverTouchTheReservedObxRoles",
        "NeverGrantAccessOrOpenInbound",
    ] {
        let o = operator.iter().find(|s| s["Sid"] == sid).unwrap();
        let ours = setup
            .iter()
            .find(|s| s["Sid"] == sid)
            .unwrap_or_else(|| panic!("{sid} missing"));
        assert_eq!(ours["Action"], o["Action"], "{sid}");
        assert_eq!(ours["Resource"], o["Resource"], "{sid}");
    }
    // the named Denies hold: no users or keys, no Identity Center, Organizations or Account, no open inbound rule
    for a in [
        "iam:CreateUser",
        "iam:CreateAccessKey",
        "sso:CreateInstance",
        "organizations:CreateAccount",
        "account:CloseAccount",
        "ec2:AuthorizeSecurityGroupIngress",
    ] {
        assert!(denied_on(&setup, a, "*"), "{a} must be denied");
        assert!(
            !setup
                .iter()
                .any(|s| s["Effect"] == "Allow"
                    && strings(&s["Action"]).iter().any(|p| matches(p, a))),
            "{a} is allowed"
        );
    }
}

#[test]
fn the_setup_policy_never_allows_an_action_on_every_resource_for_iam_s3_or_a_wildcard_write() {
    for s in permission_set("setup-policy.json")
        .iter()
        .filter(|s| s["Effect"] == "Allow")
    {
        let res = strings(&s["Resource"]);
        for a in strings(&s["Action"]) {
            if res.iter().any(|r| r == "*") {
                let read = a.contains(":Describe")
                    || a.contains(":List")
                    || a.contains(":Get")
                    || a == "ec2:Describe*"
                    || a == "sts:GetCallerIdentity"
                    || a.starts_with("tag:Get");
                // a wildcard-resource key write (creating a key, which has no ARN yet, or tagging one) must carry its tag conditions
                let tagged_key_write = a.starts_with("kms:") && s.get("Condition").is_some();
                assert!(
                    read || tagged_key_write,
                    "`{a}` is allowed on every resource"
                );
            }
            assert!(
                !a.starts_with("iam:*") && !a.starts_with("s3:*") && a != "*",
                "{a}"
            );
        }
    }
}

// ---------- the lookups that let init adopt what already exists (ADR 0053) ----------

/// The (service, subcommand) of every `aws <service> <subcommand>` call written as `&["<service>", "<subcommand>", ...]` in the
/// adoption code (`init/adopt.rs`, production code only).
fn adoption_lookup_calls() -> BTreeSet<(String, String)> {
    let src = std::fs::read_to_string(
        Path::new(env!("CARGO_MANIFEST_DIR")).join("../ozbox-cli/src/init/adopt.rs"),
    )
    .unwrap();
    let code = src.split("#[cfg(test)]").next().unwrap();
    let mut found = BTreeSet::new();
    let mut rest = code;
    while let Some(at) = rest.find("&[\"") {
        rest = &rest[at + 3..];
        let service = rest.split('"').next().unwrap().to_string();
        let after = &rest[service.len() + 1..];
        let after = after.trim_start_matches([',', ' ', '\n', '\t']);
        if let Some(lit) = after.strip_prefix('"') {
            found.insert((service, lit.split('"').next().unwrap().to_string()));
        }
    }
    found
}

#[test]
fn every_lookup_init_makes_to_adopt_what_exists_is_a_call_both_the_setup_set_and_the_steps_own_set_allow(
) {
    use ozbox_provider_aws::init_actions::ADOPTION_LOOKUPS;
    let made = adoption_lookup_calls();
    // the scan finds what the code really calls, or this test would pass on an empty list
    assert!(
        made.contains(&("kms".into(), "list-aliases".into()))
            && made.contains(&("iam".into(), "get-policy".into())),
        "found only {made:?}: did init/adopt.rs change shape?"
    );
    let listed: BTreeSet<(String, String)> = ADOPTION_LOOKUPS
        .iter()
        .map(|(s, c, ..)| (s.to_string(), c.to_string()))
        .collect();
    assert_eq!(
        made, listed,
        "init/adopt.rs makes lookups the coverage table does not list (or the table lists one it no longer makes): edit init_actions::ADOPTION_LOOKUPS"
    );
    let setup = permission_set("setup-policy.json");
    for (service, call, actions, arn, step_set) in ADOPTION_LOOKUPS {
        let own = permission_set(step_set);
        for a in actions {
            for (label, set) in [("setup-policy.json", &setup), (step_set, &own)] {
                let allowed = set.iter().any(|s| {
                    s["Effect"] == "Allow"
                        && strings(&s["Action"]).iter().any(|p| matches(p, a))
                        && reaches(s, &[arn.to_string()])
                        && condition_keys(s)
                            .iter()
                            .all(|k| SATISFIABLE_CONDITION_KEYS.contains(&k.as_str()))
                });
                assert!(
                    allowed,
                    "`aws {service} {call}` needs {a}, which {label} does not allow on {arn}: init would fail finding what to adopt"
                );
                let denied = set.iter().any(|s| {
                    s["Effect"] == "Deny"
                        && strings(&s["Action"]).iter().any(|p| matches(p, a))
                        && reaches(s, &[arn.to_string()])
                });
                assert!(!denied, "{label} denies {a} on {arn}");
            }
        }
        // a lookup is a read: never a write action in the table
        assert!(
            actions
                .iter()
                .all(|a| a.contains(":List") || a.contains(":Describe") || a.contains(":Get")),
            "{service} {call} must be a read"
        );
    }
}

/// Every address init adopts (`init.rs`, `init/adopt.rs`) names a resource its module really declares, so an import block can
/// never point at something the generated root does not have (OpenTofu refuses the plan if it does).
#[test]
fn every_address_init_adopts_is_a_resource_its_module_declares() {
    let src = std::fs::read_to_string(
        Path::new(env!("CARGO_MANIFEST_DIR")).join("../ozbox-cli/src/init.rs"),
    )
    .unwrap();
    let code = src.split("#[cfg(test)]").next().unwrap();
    let mut seen = 0;
    for (module_name, module_dir) in [
        ("key", "aws-secrets-key"),
        ("adopt", "aws-adopt-command"),
        ("policy", "aws-box-policy"),
    ] {
        let prefix = format!("\"module.{module_name}.");
        let declared = {
            let dir = infra().join("tofu/modules").join(module_dir);
            let mut all = String::new();
            for e in std::fs::read_dir(dir).unwrap() {
                let p = e.unwrap().path();
                if p.extension().and_then(|x| x.to_str()) == Some("tf") {
                    all.push_str(&std::fs::read_to_string(p).unwrap());
                }
            }
            all
        };
        let mut rest = code;
        while let Some(at) = rest.find(&prefix) {
            rest = &rest[at + prefix.len()..];
            let addr = rest.split('"').next().unwrap();
            let (ty, name) = addr.split_once('.').unwrap();
            let name = name.split('[').next().unwrap();
            assert!(
                declared.contains(&format!("resource \"{ty}\" \"{name}\"")),
                "init adopts module.{module_name}.{addr}, but {module_dir} declares no such resource"
            );
            seen += 1;
        }
    }
    assert!(
        seen >= 7,
        "found only {seen} adopted addresses: did init.rs change shape?"
    );
}
