#![allow(clippy::unwrap_used)]
//! The key-administration permission set (`infra/aws/key-admin-policy.json`) creates and administers only Oz Box's own
//! KMS keys, and never uses one. The operator role keeps no KMS rights at all; this set is attached, by an account
//! administrator, only to the person who creates a fleet's secrets key (`aws-secrets-key`).
//!
//! What it must never allow, pinned here:
//! - using a key (encrypt, decrypt, grants, imported material, replicas): an explicit Deny;
//! - turning someone else's key into an Oz Box key: tagging is allowed only on a key that already carries
//!   `ozbox-managed=true`, and removing tags is denied, so the tag cannot be moved;
//! - administering any key that is not tagged `ozbox-managed=true`;
//! - an alias outside the `ozbox-` prefix;
//! - bypassing the key policy's lock-out check.

use serde_json::Value;

fn statements() -> Vec<Value> {
    let text = include_str!("../../../infra/aws/key-admin-policy.json");
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

fn allows() -> Vec<Value> {
    statements()
        .into_iter()
        .filter(|s| s["Effect"] == "Allow")
        .collect()
}

fn denies(action: &str) -> bool {
    statements().iter().any(|s| {
        s["Effect"] == "Deny"
            && s.get("Condition").is_none()
            && strings(&s["Action"]).iter().any(|a| {
                a == action || (a.ends_with('*') && action.starts_with(a.trim_end_matches('*')))
            })
    })
}

#[test]
fn every_action_is_kms_and_none_is_a_wildcard_allow() {
    for s in allows() {
        for a in strings(&s["Action"]) {
            assert!(a.starts_with("kms:"), "{a}");
            assert!(!a.ends_with('*'), "an allowed action is a wildcard: {a}");
        }
    }
}

#[test]
fn a_key_is_never_used_and_its_tag_never_removed() {
    for a in [
        "kms:Encrypt",
        "kms:Decrypt",
        "kms:ReEncryptFrom",
        "kms:GenerateDataKey",
        "kms:CreateGrant",
        "kms:ImportKeyMaterial",
        "kms:ReplicateKey",
        "kms:UntagResource",
    ] {
        assert!(denies(a), "{a} must be denied outright");
        for s in allows() {
            assert!(
                !strings(&s["Action"]).contains(&a.to_string()),
                "{a} is allowed"
            );
        }
    }
}

#[test]
fn only_oz_box_keys_are_created_tagged_or_administered() {
    for s in allows() {
        let actions = strings(&s["Action"]);
        let cond = s["Condition"].to_string();
        if actions == ["kms:ListKeys", "kms:ListAliases"] {
            continue;
        }
        let alias_only = strings(&s["Resource"])
            .iter()
            .all(|r| r.contains(":alias/ozbox-"));
        if alias_only {
            continue;
        }
        if actions.contains(&"kms:CreateKey".to_string()) {
            assert!(cond.contains("aws:RequestTag/ozbox-managed"), "{s}");
            continue;
        }
        // Everything else, tagging included, needs the key to be an Oz Box key already.
        assert!(cond.contains("aws:ResourceTag/ozbox-managed"), "{s}");
    }
}

#[test]
fn tagging_needs_both_the_existing_and_the_requested_oz_box_tag() {
    let tag: Vec<Value> = allows()
        .into_iter()
        .filter(|s| strings(&s["Action"]).contains(&"kms:TagResource".to_string()))
        .collect();
    assert_eq!(tag.len(), 1);
    let c = tag[0]["Condition"].to_string();
    assert!(
        c.contains("aws:ResourceTag/ozbox-managed") && c.contains("aws:RequestTag/ozbox-managed")
    );
}

#[test]
fn the_key_policy_lock_out_check_is_never_bypassed() {
    let lock = statements().into_iter().find(|s| {
        s["Effect"] == "Deny"
            && s["Condition"]
                .to_string()
                .contains("kms:BypassPolicyLockoutSafetyCheck")
    });
    let lock = lock.unwrap();
    let a = strings(&lock["Action"]);
    assert!(
        a.contains(&"kms:CreateKey".to_string()) && a.contains(&"kms:PutKeyPolicy".to_string())
    );
}

#[test]
fn the_account_is_a_placeholder_never_a_real_id() {
    let text = include_str!("../../../infra/aws/key-admin-policy.json");
    assert!(text.contains("${account_id}"));
    assert!(!text
        .chars()
        .collect::<String>()
        .split(|c: char| !c.is_ascii_digit())
        .any(|d| d.len() == 12));
}

/// ADR 0029 Amendment 9: the setup identity cannot change a Production key (`ozbox-production=true`): not its
/// policy, not its grants, not its tags (an overwrite of the value would lift the deny), not delete or disable it. The
/// administrators of the account still can, and every such call is a CloudTrail event.
#[test]
fn the_production_key_is_out_of_the_setup_identitys_reach() {
    let deny = statements()
        .into_iter()
        .find(|s| s["Sid"] == "NeverChangeTheProductionKey")
        .unwrap();
    assert_eq!(deny["Effect"], "Deny");
    let actions = strings(&deny["Action"]);
    for must in [
        "kms:PutKeyPolicy",
        "kms:CreateGrant",
        "kms:TagResource",
        "kms:ScheduleKeyDeletion",
        "kms:DisableKey",
    ] {
        assert!(actions.contains(&must.to_string()), "{must} must be denied");
    }
    assert_eq!(
        deny["Condition"]["StringEquals"]["aws:ResourceTag/ozbox-production"],
        "true"
    );
    // The deny is keyed on the tag, and nothing may move the tag: removal is already denied everywhere.
    assert!(denies("kms:UntagResource"));
}

/// the issuer's alias (`alias/ozbox-<fleet>-production`) is created by the identity that applies the issuer
/// (an administrator), not by the setup identity. KMS authorises an alias call against the alias ARN AND the key it points at
/// (for UpdateAlias, the old and the new key), so two denies cover both ends: no alias call on a key tagged
/// `ozbox-production`, and none on the production alias name, so the alias cannot be repointed at a decoy key.
#[test]
fn the_production_alias_cannot_be_created_moved_or_deleted_by_the_setup_identity() {
    let alias = ["kms:CreateAlias", "kms:UpdateAlias", "kms:DeleteAlias"];
    let by_key = statements()
        .into_iter()
        .find(|s| s["Sid"] == "NeverAliasTheProductionKey")
        .unwrap();
    let by_name = statements()
        .into_iter()
        .find(|s| s["Sid"] == "NeverUseTheProductionAliasName")
        .unwrap();
    for d in [&by_key, &by_name] {
        assert_eq!(d["Effect"], "Deny");
        let a = strings(&d["Action"]);
        for must in alias {
            assert!(a.contains(&must.to_string()), "{must}");
        }
    }
    assert_eq!(
        by_key["Condition"]["StringEquals"]["aws:ResourceTag/ozbox-production"],
        "true"
    );
    assert_eq!(
        strings(&by_name["Resource"]),
        ["arn:aws:kms:*:${account_id}:alias/ozbox-*-production"]
    );
    assert!(by_name.get("Condition").is_none());
    // the pattern matches the issuer's alias and not the fleet's secrets-key alias, which the setup identity still manages
    let pat = "alias/ozbox-*-production";
    let (pre, post) = pat.split_once('*').unwrap();
    let hit = |n: &str| n.starts_with(pre) && n.ends_with(post) && n.len() >= pat.len() - 1;
    assert!(hit("alias/ozbox-fleet-a-production"));
    assert!(!hit("alias/ozbox-fleet-a-secrets"));
}
