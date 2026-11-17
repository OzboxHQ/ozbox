//! `ozbox init` writes ONE operator policy: the template with the adopt step's statements merged in, never a second file for a
//! person to merge by hand. These fixtures pin the merge: order-stable, de-duplicated and idempotent.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::path::Path;

use ozbox_provider_aws::operator_policy::{
    merge_statements, render, MergeReport, ADOPT_STATEMENTS,
};
use serde_json::Value;

fn fixture(name: &str) -> Value {
    let p = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures/policy-merge")
        .join(name);
    serde_json::from_str(&std::fs::read_to_string(p).expect("fixture")).expect("fixture JSON")
}

fn adopt() -> Vec<Value> {
    fixture("adopt.json")["Statement"]
        .as_array()
        .cloned()
        .unwrap()
}

#[test]
fn the_adopt_statements_are_merged_in_place_and_new_ones_appended_in_order() {
    let (merged, report) = merge_statements(&fixture("base.json"), &adopt());
    assert_eq!(merged, fixture("expected.json"));
    assert_eq!(
        report,
        MergeReport {
            added: vec!["ReadACommandThatWasSent".into()],
            replaced: vec!["SendOnlyTheAdoptDocument".into()],
            // a one-value list and a plain value are the same statement; an empty Sid that matches exactly is not added twice
            unchanged: vec!["ToBoxesOzBoxManages".into(), "#5".into()],
        }
    );
}

#[test]
fn merging_twice_changes_nothing() {
    let (once, _) = merge_statements(&fixture("base.json"), &adopt());
    let (twice, report) = merge_statements(&once, &adopt());
    assert_eq!(once, twice);
    assert!(
        report.added.is_empty() && report.replaced.is_empty(),
        "{report:?}"
    );
}

#[test]
fn no_sid_appears_twice_and_the_policy_keeps_its_version() {
    let (merged, _) = merge_statements(&fixture("base.json"), &adopt());
    let sids: Vec<&str> = merged["Statement"]
        .as_array()
        .unwrap()
        .iter()
        .filter_map(|s| s["Sid"].as_str())
        .collect();
    let mut unique = sids.clone();
    unique.sort_unstable();
    unique.dedup();
    assert_eq!(unique.len(), sids.len(), "{sids:?}");
    assert_eq!(merged["Version"], "2012-10-17");
}

#[test]
fn the_rendered_template_already_holds_the_adopt_statements_so_its_own_merge_adds_nothing() {
    let policy = render("123456789012", "us-east-1", "ozbox").unwrap();
    let own = ozbox_provider_aws::operator_policy::statements_named(&policy, &ADOPT_STATEMENTS);
    let (merged, report) = merge_statements(&policy, &own);
    assert_eq!(merged, policy);
    assert_eq!(report.unchanged.len(), ADOPT_STATEMENTS.len());
}
