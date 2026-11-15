//! Choosing among the public Oz images (ADR 0052). Pure: no AWS call, no process, tested on fixture data.
//!
//! The project publishes its machine images from one AWS account, in a few regions, so that `ozbox create` works without
//! anyone building an image. A public image is only ever picked here when
//!
//! 1. it is **owned by the publisher account** (a look-alike published by anyone else is never a candidate), and
//! 2. its release is **listed in the signed manifest for that region** (the caller checks this with
//!    [`ozbox_core::ReleaseVerifier`], the one verification path; this module only decides the order to try them in).
//!
//! AWS shows a resource's tags only to the account that owns it, so a public image carries no `ozbox-image` tag for anyone
//! else. Its **name** (`ozbox-<version>-<timestamp>`, set by the image build) says which release it claims to be. The name only
//! chooses which manifest to fetch: trust comes from the manifest listing this exact image id, never from the name.

use std::cmp::Ordering;

use ozbox_core::release::{compat, is_release_version, Compat};

/// The AWS account the project's public images are published from. Public once the images are public; not a secret.
pub const PUBLISHER_ACCOUNT_ID: &str = "372115812457";

/// The regions the public images are published in (the build region and the copies).
pub const PUBLIC_IMAGE_REGIONS: [&str; 3] = ["us-east-1", "eu-west-1", "ap-southeast-1"];

/// How many candidates are checked against the signed manifest, newest first. Each release is one manifest download and one
/// signature check, and the publisher keeps only the last three releases public, so a handful is already every one of them.
pub const MAX_PUBLIC_CANDIDATES: usize = 6;

/// The most time the whole lookup of a public image may take.
pub const LOOKUP_DEADLINE: std::time::Duration = std::time::Duration::from_secs(90);

/// The `image_publisher` setting that turns the public images off (only the caller's own account's images are used).
pub const NO_PUBLISHER: &str = "none";

/// Is `s` a 12-digit AWS account id?
pub fn is_account_id(s: &str) -> bool {
    s.len() == 12 && s.bytes().all(|b| b.is_ascii_digit())
}

/// What `describe-images` says about a public image, as far as choosing goes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PublicCandidate {
    pub id: String,
    pub owner: String,
    pub name: String,
    pub created: Option<String>,
}

/// A candidate that may be checked: owned by the publisher, with a release its name claims.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Ranked {
    pub candidate: PublicCandidate,
    pub release: String,
}

/// The release an image name claims: `ozbox-<version>-<14-digit timestamp>` is `<version>` (which may carry a
/// pre-release part, `0.3.0-rc.1`). `None` for any other name.
pub fn release_of_name(name: &str) -> Option<String> {
    let rest = name.strip_prefix("ozbox-")?;
    let (version, stamp) = rest.rsplit_once('-')?;
    (stamp.len() == 14 && stamp.bytes().all(|b| b.is_ascii_digit()) && is_release_version(version))
        .then(|| version.to_string())
}

/// Order two release versions: by number (`0.10.0` after `0.9.0`), and a pre-release before the release it leads to.
pub fn version_order(a: &str, b: &str) -> Ordering {
    fn key(v: &str) -> (Vec<u64>, bool, Vec<String>) {
        let (core, pre) = match v.split_once('-') {
            Some((c, p)) => (c, Some(p)),
            None => (v, None),
        };
        let nums = core
            .split('.')
            .map(|p| p.parse::<u64>().unwrap_or(0))
            .collect();
        (
            nums,
            pre.is_none(),
            pre.map(|p| p.split('.').map(str::to_string).collect())
                .unwrap_or_default(),
        )
    }
    let (ka, kb) = (key(a), key(b));
    ka.0.cmp(&kb.0)
        .then(ka.1.cmp(&kb.1))
        .then_with(|| compare_pre(&ka.2, &kb.2))
}

fn compare_pre(a: &[String], b: &[String]) -> Ordering {
    for (x, y) in a.iter().zip(b) {
        let o = match (x.parse::<u64>(), y.parse::<u64>()) {
            (Ok(x), Ok(y)) => x.cmp(&y),
            // numeric identifiers rank below text ones, as in semantic versioning
            (Ok(_), Err(_)) => Ordering::Less,
            (Err(_), Ok(_)) => Ordering::Greater,
            (Err(_), Err(_)) => x.cmp(y),
        };
        if o != Ordering::Equal {
            return o;
        }
    }
    a.len().cmp(&b.len())
}

/// The candidates worth checking, in the order to check them, and a line for each one refused outright.
///
/// Refused: an image the publisher does not own (a look-alike), and one whose name claims no release. The rest are ordered
/// **compatible with this program first** (same major and minor version: a program refuses an image of another minor, ADR
/// 0036, so the newest image is the wrong choice the day after a minor release), then the newest release, then the newest
/// build. At most [`MAX_PUBLIC_CANDIDATES`].
pub fn rank(
    candidates: &[PublicCandidate],
    publisher: &str,
    program_version: &str,
) -> (Vec<Ranked>, Vec<String>) {
    let mut ok = Vec::new();
    let mut refused = Vec::new();
    for c in candidates {
        if c.owner != publisher {
            refused.push(format!(
                "{} is owned by another account, not the Oz Box publisher",
                c.id
            ));
            continue;
        }
        match release_of_name(&c.name) {
            Some(release) => ok.push(Ranked {
                candidate: c.clone(),
                release,
            }),
            None => refused.push(format!("{} is not named like an Oz Box image", c.id)),
        }
    }
    let fits = |r: &Ranked| compat(program_version, &r.release) == Compat::Compatible;
    ok.sort_by(|a, b| {
        fits(b)
            .cmp(&fits(a))
            .then_with(|| version_order(&b.release, &a.release))
            .then_with(|| b.candidate.created.cmp(&a.candidate.created))
            .then_with(|| b.candidate.id.cmp(&a.candidate.id))
    });
    ok.truncate(MAX_PUBLIC_CANDIDATES);
    (ok, refused)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cand(id: &str, owner: &str, name: &str, created: &str) -> PublicCandidate {
        PublicCandidate {
            id: id.into(),
            owner: owner.into(),
            name: name.into(),
            created: Some(created.into()),
        }
    }

    #[test]
    fn a_name_claims_a_release() {
        assert_eq!(
            release_of_name("ozbox-0.3.0-20261114093000").as_deref(),
            Some("0.3.0")
        );
        assert_eq!(
            release_of_name("ozbox-0.3.0-rc.1-20261114093000").as_deref(),
            Some("0.3.0-rc.1")
        );
        for bad in [
            "",
            "ozbox-",
            "ozbox-0.3.0",
            "ozbox-0.3.0-2026",
            "ubuntu-0.3.0-20261114093000",
            "ozbox-latest-20261114093000",
            "ozbox-0.3.0-2026111409300x",
        ] {
            assert_eq!(release_of_name(bad), None, "{bad}");
        }
    }

    #[test]
    fn versions_order_by_number_and_a_pre_release_leads_its_release() {
        let mut v = ["0.10.0", "0.9.0", "0.9.0-rc.2", "0.9.0-rc.10", "0.9.0-rc.1"];
        v.sort_by(|a, b| version_order(a, b));
        assert_eq!(
            v,
            ["0.9.0-rc.1", "0.9.0-rc.2", "0.9.0-rc.10", "0.9.0", "0.10.0"]
        );
    }

    #[test]
    fn only_the_publishers_own_images_are_candidates() {
        let (ranked, refused) = rank(
            &[
                cand(
                    "ami-evil",
                    "999999999999",
                    "ozbox-9.9.9-20261114093000",
                    "2026-11-14",
                ),
                cand(
                    "ami-ok",
                    PUBLISHER_ACCOUNT_ID,
                    "ozbox-0.3.0-20261110093000",
                    "2026-11-10",
                ),
            ],
            PUBLISHER_ACCOUNT_ID,
            "0.3.0",
        );
        assert_eq!(ranked.len(), 1);
        assert_eq!(ranked[0].candidate.id, "ami-ok");
        assert_eq!(refused.len(), 1);
        assert!(refused[0].contains("ami-evil") && refused[0].contains("another account"));
    }

    #[test]
    fn a_publisher_image_with_a_foreign_name_is_refused_not_guessed() {
        let (ranked, refused) = rank(
            &[cand(
                "ami-odd",
                PUBLISHER_ACCOUNT_ID,
                "something-else",
                "2026-11-10",
            )],
            PUBLISHER_ACCOUNT_ID,
            "0.3.0",
        );
        assert!(ranked.is_empty());
        assert!(refused[0].contains("not named like an Oz Box image"));
    }

    #[test]
    fn the_release_this_program_can_use_comes_before_a_newer_one_it_cannot() {
        let publisher = PUBLISHER_ACCOUNT_ID;
        let all = [
            cand(
                "ami-04",
                publisher,
                "ozbox-0.4.0-20261201000000",
                "2026-12-01",
            ),
            cand(
                "ami-032",
                publisher,
                "ozbox-0.3.2-20261120000000",
                "2026-11-20",
            ),
            cand(
                "ami-030",
                publisher,
                "ozbox-0.3.0-20261105000000",
                "2026-11-05",
            ),
            cand(
                "ami-020",
                publisher,
                "ozbox-0.2.0-20261001000000",
                "2026-10-01",
            ),
        ];
        let (ranked, _) = rank(&all, publisher, "0.3.1");
        let ids: Vec<&str> = ranked.iter().map(|r| r.candidate.id.as_str()).collect();
        assert_eq!(ids, ["ami-032", "ami-030", "ami-04", "ami-020"]);
        // a program that is the newest: its own minor first
        let (ranked, _) = rank(&all, publisher, "0.4.0");
        assert_eq!(ranked[0].candidate.id, "ami-04");
        // a program older than everything: nothing fits, newest first (the caller then reports the mismatch)
        let (ranked, _) = rank(&all, publisher, "0.1.0");
        assert_eq!(ranked[0].candidate.id, "ami-04");
    }

    #[test]
    fn the_newest_build_of_a_release_wins_and_the_list_is_capped() {
        let publisher = PUBLISHER_ACCOUNT_ID;
        let mut all = Vec::new();
        for i in 0..10 {
            all.push(cand(
                &format!("ami-{i:02}"),
                publisher,
                &format!("ozbox-0.3.0-2026110100{i:04}"),
                &format!("2026-11-0{}", i % 9 + 1),
            ));
        }
        let (ranked, _) = rank(&all, publisher, "0.3.0");
        assert_eq!(ranked.len(), MAX_PUBLIC_CANDIDATES);
        assert!(ranked
            .windows(2)
            .all(|w| w[0].candidate.created >= w[1].candidate.created));
    }

    #[test]
    fn a_beta_program_is_moved_to_the_stable_image_of_its_minor_and_a_stable_one_is_not_handed_the_beta(
    ) {
        let publisher = PUBLISHER_ACCOUNT_ID;
        let all = [
            cand(
                "ami-beta",
                publisher,
                "ozbox-0.2.0-beta.0-20261110000000",
                "2026-11-10",
            ),
            cand(
                "ami-020",
                publisher,
                "ozbox-0.2.0-20261201000000",
                "2026-12-01",
            ),
        ];
        // 0.2.0-beta.0 and 0.2.0 are the same minor: the beta program takes the stable one first, so it is not stranded
        let (ranked, _) = rank(&all, publisher, "0.2.0-beta.0");
        assert_eq!(ranked[0].candidate.id, "ami-020");
        // the order alone does not hide a pre-release from a stable program: that is decided by the signed manifest after
        // it is verified (never by the name, which anyone can write)
        let (ranked, _) = rank(&all, publisher, "0.2.0");
        assert_eq!(ranked.len(), 2);
        assert_eq!(ranked[0].candidate.id, "ami-020");
    }

    #[test]
    fn account_ids_are_twelve_digits() {
        assert!(is_account_id(PUBLISHER_ACCOUNT_ID));
        for bad in ["", "none", "12345678901", "1234567890123", "12345678901a"] {
            assert!(!is_account_id(bad), "{bad}");
        }
    }
}
