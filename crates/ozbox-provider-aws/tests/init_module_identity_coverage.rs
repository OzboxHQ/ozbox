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

#[test]
fn every_resource_type_in_a_module_init_applies_is_covered_by_the_identity_that_applies_it() {
    for (module, policy) in APPLIED_BY_INIT {
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
                        && match s.get("Condition") {
                            None => true,
                            // a Deny on a production tag never meets what init makes (it makes no production key)
                            Some(c) => {
                                !c.to_string().contains("ozbox-production")
                                    && !c.to_string().contains("BypassPolicyLockoutSafetyCheck")
                            }
                        }
                });
                assert!(!denied, "{module}: {a} is denied on a {t} by {policy}");
            }
        }
    }
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

/// Modules `ozbox init` applies WITHOUT a dedicated permission set, each with the reason.
const EXEMPT: [(&str, &str); 4] = [
    ("aws-network", "applied with the setup identity's own network rights (no dedicated set exists)"),
    ("aws-security-baseline", "applied with the setup identity's own rights; its own policy file (security-services-policy.json) is checked by its own tests"),
    ("aws-issuer", "planned only from a package the person names; applied with the setup identity's own rights"),
    ("aws-box", "read by init only to check it exists; boxes are made by `ozbox create` with the daily operator role"),
];

#[test]
fn every_module_init_plans_is_covered_or_exempt_with_a_reason() {
    let covered: BTreeSet<&str> = APPLIED_BY_INIT.iter().map(|(m, _)| *m).collect();
    for m in init_modules() {
        let exempt = EXEMPT.iter().any(|(e, why)| *e == m && !why.is_empty());
        assert!(
            covered.contains(m.as_str()) || exempt,
            "init.rs uses the module {m}, which is neither in APPLIED_BY_INIT (with its permission set) nor in EXEMPT (with a reason)"
        );
    }
    for (m, _) in APPLIED_BY_INIT {
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
