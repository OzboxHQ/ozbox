//! Every workflow pins what it runs, and the publishing ones hold the program release's rule: a tag that is not on `main`
//! publishes nothing. Read as text; nothing runs.
#![allow(clippy::unwrap_used)]

use std::path::{Path, PathBuf};

fn root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../..")
}

fn workflows() -> Vec<(String, String)> {
    let dir = root().join(".github/workflows");
    let mut v: Vec<(String, String)> = std::fs::read_dir(&dir)
        .unwrap()
        .flatten()
        .map(|e| e.path())
        .filter(|p| p.extension().is_some_and(|x| x == "yml" || x == "yaml"))
        .map(|p| {
            (
                p.file_name().unwrap().to_string_lossy().to_string(),
                std::fs::read_to_string(&p).unwrap(),
            )
        })
        .collect();
    v.sort();
    assert!(!v.is_empty());
    v
}

#[test]
fn every_action_is_pinned_to_a_full_commit() {
    for (name, text) in workflows() {
        for line in text.lines() {
            let Some(rest) = line.trim().trim_start_matches("- ").strip_prefix("uses:") else {
                continue;
            };
            let target = rest.split('#').next().unwrap().trim();
            if target.starts_with("./") {
                continue; // a workflow of this repository
            }
            let sha = target.rsplit_once('@').map(|(_, r)| r).unwrap_or("");
            assert!(
                sha.len() == 40 && sha.bytes().all(|b| b.is_ascii_hexdigit()),
                "{name}: {target} is not pinned to a commit"
            );
        }
    }
}

#[test]
fn the_publishing_workflows_refuse_a_tag_that_is_not_on_main_and_pin_npm() {
    for (name, text) in workflows() {
        if !name.starts_with("publish-crates") && !name.starts_with("publish-npm") {
            continue;
        }
        assert!(
            text.contains("git merge-base --is-ancestor \"$GITHUB_SHA\" origin/main"),
            "{name}"
        );
        assert!(text.contains("fetch-depth: 0"), "{name}");
        for line in text.lines().filter(|l| l.contains("npm install -g npm@")) {
            let v = line.split("npm@").nth(1).unwrap().trim();
            let parts: Vec<&str> = v.split('.').collect();
            assert!(
                parts.len() == 3 && parts.iter().all(|p| p.parse::<u32>().is_ok()),
                "{name}: npm@{v} is not an exact version"
            );
        }
    }
}

#[test]
fn the_sign_off_check_skips_only_the_known_bots_by_their_address() {
    let (_, dco) = workflows()
        .into_iter()
        .find(|(n, _)| n == "dco.yml")
        .unwrap();
    // a name containing [bot] is anyone's to choose; the address GitHub gives a bot is not
    assert!(!dco.contains("*\"[bot]\"*"));
    assert!(dco.contains("--format='%ae'"));
    for bot in [
        "\"49699333+dependabot[bot]@users.noreply.github.com\"",
        "\"41898282+github-actions[bot]@users.noreply.github.com\"",
    ] {
        assert!(dco.contains(bot), "{bot}");
    }
}
