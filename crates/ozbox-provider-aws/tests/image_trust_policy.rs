//! The image build role's trust policy (`infra/aws/image-build-trust-policy.json`) must let exactly one thing sign in: a job
//! of the repository's `image` environment, named by the immutable ids GitHub puts in the subject of this organization's
//! tokens. No wildcard, no branch or tag form, no list: the environment (its reviewer and branch rule) is the one gate, so
//! the trust must not also admit anything the environment does not control. And it holds no real account or repository.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::path::Path;

use serde_json::Value;

const SUB: &str = "token.actions.githubusercontent.com:sub";
const AUD: &str = "token.actions.githubusercontent.com:aud";

fn text() -> String {
    let p =
        Path::new(env!("CARGO_MANIFEST_DIR")).join("../../infra/aws/image-build-trust-policy.json");
    std::fs::read_to_string(p).expect("infra/aws/image-build-trust-policy.json")
}

fn statement() -> Value {
    let v: Value = serde_json::from_str(&text()).expect("valid JSON");
    assert_eq!(
        v["Statement"].as_array().map(Vec::len),
        Some(1),
        "one statement"
    );
    v["Statement"][0].clone()
}

#[test]
fn it_trusts_only_the_image_environment_of_one_repository_by_its_immutable_ids() {
    let st = statement();
    assert_eq!(st["Effect"], "Allow");
    assert_eq!(st["Action"], "sts:AssumeRoleWithWebIdentity");
    let eq = &st["Condition"]["StringEquals"];
    assert_eq!(eq[AUD], "sts.amazonaws.com");
    // exact match on one subject: a string, not a list, and no StringLike at all
    let sub = eq[SUB].as_str().expect("one exact subject, not a list");
    assert_eq!(sub, "repo:ORG@ORG_ID/REPO@REPO_ID:environment:image");
    assert!(
        st["Condition"].get("StringLike").is_none(),
        "no pattern match anywhere in the trust"
    );
    assert_eq!(
        st["Condition"].as_object().map(|c| c.len()),
        Some(1),
        "StringEquals is the only condition"
    );
    assert_eq!(
        eq.as_object().map(|c| c.len()),
        Some(2),
        "the audience and the subject, nothing else"
    );
}

#[test]
fn the_subject_has_the_shape_github_presents_and_no_wildcard() {
    let st = statement();
    let sub = st["Condition"]["StringEquals"][SUB].as_str().unwrap();
    let rest = sub.strip_prefix("repo:").expect("a repository subject");
    let (repo_part, claim) = rest.split_once(':').expect("a claim after the repository");
    assert_eq!(
        claim, "environment:image",
        "the image environment, not a ref"
    );
    let (org, repo) = repo_part.split_once('/').expect("org/repo");
    for half in [org, repo] {
        let (name, id) = half.split_once('@').expect("name@id: the immutable form");
        assert!(!name.is_empty() && !id.is_empty());
    }
    assert!(
        !sub.contains('*') && !sub.contains('?'),
        "no wildcard in the subject: {sub}"
    );
    assert!(
        !sub.contains(":ref:"),
        "a branch or tag form would bypass the environment: {sub}"
    );
}

#[test]
fn it_names_no_real_account_or_repository() {
    let t = text();
    for placeholder in ["123456789012", "ORG@ORG_ID/REPO@REPO_ID"] {
        assert!(t.contains(placeholder), "{placeholder}");
    }
    // the placeholders must be replaced by whoever applies it; a real id is never committed here
    assert!(!t.contains("372115812457"));
}

#[test]
fn the_workflow_says_what_the_role_must_trust_when_aws_refuses() {
    let w = std::fs::read_to_string(
        Path::new(env!("CARGO_MANIFEST_DIR")).join("../../.github/workflows/image.yml"),
    )
    .expect("the image workflow");
    assert!(
        w.contains("steps.aws.outcome == 'failure'") && w.contains("image-build-trust-policy.json")
    );
    assert!(w.contains("continue-on-error: true"));
    assert!(
        w.contains(":environment:image"),
        "the refusal and the pre-check name the environment form"
    );
    assert!(
        !w.contains("refs/heads/main") && !w.contains(":ref:"),
        "the workflow no longer describes a branch or tag subject"
    );
}

/// The text of each job of the workflow: a job starts at a line `  <name>:` (two-space indent) under `jobs:`.
fn jobs(workflow: &str) -> Vec<(String, String)> {
    let body = workflow.split_once("\njobs:\n").expect("a jobs section").1;
    let mut out: Vec<(String, String)> = Vec::new();
    for line in body.lines() {
        let is_head = line.starts_with("  ")
            && !line.starts_with("   ")
            && line.trim_end().ends_with(':')
            && !line.trim().starts_with('#');
        if is_head {
            out.push((line.trim().trim_end_matches(':').to_string(), String::new()));
        } else if let Some(last) = out.last_mut() {
            last.1.push_str(line);
            last.1.push('\n');
        }
    }
    out
}

#[test]
fn the_jobs_that_sign_in_or_sign_the_manifest_run_in_the_image_environment_and_no_other_does() {
    let w = std::fs::read_to_string(
        Path::new(env!("CARGO_MANIFEST_DIR")).join("../../.github/workflows/image.yml"),
    )
    .expect("the image workflow");
    let mut inside = Vec::new();
    for (name, text) in jobs(&w) {
        let in_env = text.contains("\n    environment: image\n");
        // every job that uses the role is in the environment the role trusts
        if text.contains("configure-aws-credentials") {
            assert!(
                in_env,
                "job {name} signs in to AWS outside the environment the role trusts"
            );
        }
        // the manifest job holds the signing identity: it is reviewer-gated like the build
        if text.contains("cosign sign-blob") {
            assert!(
                in_env,
                "job {name} signs the manifest outside the environment"
            );
        }
        // the OIDC token can be minted only where the environment gates it
        let mints = text.contains("id-token: write");
        assert_eq!(
            mints, in_env,
            "job {name}: id-token: write must be exactly where the environment is"
        );
        if in_env {
            inside.push(name);
        }
    }
    // and no other job is there for nothing (each approval is a person's time)
    assert_eq!(inside, ["build", "manifest", "publish"]);
}
