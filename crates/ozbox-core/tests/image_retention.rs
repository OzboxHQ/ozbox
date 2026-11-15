//! Retiring old public images (ADR 0052): the selector (`scripts/image/retention.jq`) and the script that applies it
//! (`scripts/image/retention.sh`), run for real against fixtures. The rules under test are the ones that protect the
//! release just made and anything that is not ours.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::path::{Path, PathBuf};
use std::process::Command;

use serde_json::{json, Value};

const OWNER: &str = "372115812457";

fn root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../..")
}

/// A test that needs jq (and bash) never reads as a pass without them: CI always has both.
fn have(tool: &str) -> bool {
    let found = Command::new(tool)
        .arg("--version")
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false);
    if !found {
        assert!(
            std::env::var_os("CI").is_none(),
            "{tool} is not installed, and this test runs the retention selector"
        );
        eprintln!("SKIPPED: {tool} is not installed, so the retention selector was NOT run");
    }
    found
}

fn tags(pairs: &[(&str, &str)]) -> Value {
    Value::Array(
        pairs
            .iter()
            .map(|(k, v)| json!({"Key": k, "Value": v}))
            .collect(),
    )
}

/// An image of ours: id `ami-<n>`, one snapshot `snap-<n>` that is tagged ours.
fn ours(n: u32, version: &str, arch: &str) -> (Value, Value) {
    let id = format!("ami-{n:08x}");
    let snap = format!("snap-{n:08x}");
    (
        json!({
            "ImageId": id, "OwnerId": OWNER, "Name": format!("ozbox-{version}-2026111400{n:04}"),
            "Architecture": arch, "CreationDate": "2026-11-14T00:00:00.000Z",
            "Tags": tags(&[("ozbox-managed", "true"), ("ozbox-image", version), ("ozbox-image-version", version)]),
            "BlockDeviceMappings": [{"DeviceName": "/dev/sda1", "Ebs": {"SnapshotId": snap}}],
        }),
        json!({"SnapshotId": snap, "Tags": tags(&[("ozbox-managed", "true")])}),
    )
}

struct Fixture {
    images: Vec<Value>,
    snaps: Vec<Value>,
}

impl Fixture {
    fn with_versions(versions: &[&str]) -> Self {
        let mut f = Fixture {
            images: vec![],
            snaps: vec![],
        };
        let mut n = 1;
        for v in versions {
            for arch in ["x86_64", "arm64"] {
                let (i, s) = ours(n, v, arch);
                f.images.push(i);
                f.snaps.push(s);
                n += 1;
            }
        }
        f
    }

    fn files(&self, dir: &Path) -> (PathBuf, PathBuf) {
        let (i, s) = (dir.join("images.json"), dir.join("snaps.json"));
        std::fs::write(&i, json!({"Images": self.images}).to_string()).unwrap();
        std::fs::write(&s, json!({"Snapshots": self.snaps}).to_string()).unwrap();
        (i, s)
    }
}

/// Seconds for 2026-11-20 (inside the 14 days after the fixtures' builds) and 2026-12-20 (past them).
const WITHIN_GRACE: u64 = 1_795_132_800;
const AFTER_GRACE: u64 = 1_797_724_800;

fn select(f: &Fixture, released: &str, keep: u32) -> Result<Value, String> {
    select_at(f, released, keep, AFTER_GRACE)
}

fn select_at(f: &Fixture, released: &str, keep: u32, now: u64) -> Result<Value, String> {
    let d = tempfile::tempdir().unwrap();
    let (i, s) = f.files(d.path());
    let out = Command::new("jq")
        .args(["-n", "--slurpfile", "images"])
        .arg(&i)
        .args(["--slurpfile", "snaps"])
        .arg(&s)
        .args(["--arg", "owner", OWNER, "--arg", "released", released])
        .args(["--argjson", "keep", &keep.to_string()])
        .args(["--argjson", "now", &now.to_string()])
        .arg("-f")
        .arg(root().join("scripts/image/retention.jq"))
        .output()
        .unwrap();
    if out.status.success() {
        Ok(serde_json::from_slice(&out.stdout).unwrap())
    } else {
        Err(String::from_utf8_lossy(&out.stderr).to_string())
    }
}

fn deleted_versions(v: &Value) -> Vec<String> {
    let mut x: Vec<String> = v["delete"]
        .as_array()
        .unwrap()
        .iter()
        .map(|d| d["version"].as_str().unwrap().to_string())
        .collect();
    x.sort();
    x.dedup();
    x
}

#[test]
fn it_keeps_the_newest_three_versions_by_number_and_retires_the_rest_of_both_architectures() {
    if !have("jq") {
        return;
    }
    let f = Fixture::with_versions(&["0.1.0", "0.2.0", "0.3.0", "0.9.0", "0.10.0", "0.11.0"]);
    let v = select(&f, "0.11.0", 3).unwrap();
    assert_eq!(v["keep_versions"], json!(["0.11.0", "0.10.0", "0.9.0"]));
    assert_eq!(deleted_versions(&v), ["0.1.0", "0.2.0", "0.3.0"]);
    // both architectures of each retired version, each with its own snapshot
    assert_eq!(v["delete"].as_array().unwrap().len(), 6);
    assert!(v["delete"]
        .as_array()
        .unwrap()
        .iter()
        .all(|d| d["snapshots"].as_array().unwrap().len() == 1));
}

#[test]
fn it_never_selects_the_released_version_or_anything_newer() {
    if !have("jq") {
        return;
    }
    let all = ["0.1.0", "0.2.0", "0.3.0", "0.4.0", "0.5.0"];
    let f = Fixture::with_versions(&all);
    for released in all {
        for keep in 1..=4 {
            let v = select(&f, released, keep).unwrap();
            for d in v["delete"].as_array().unwrap() {
                let ver = d["version"].as_str().unwrap();
                assert!(
                    ver < released,
                    "released {released} keep {keep}: selected {ver}"
                );
            }
        }
    }
    // a newer version than the one released is kept and does not use up the window
    let v = select(&f, "0.4.0", 3).unwrap();
    assert_eq!(
        v["keep_versions"],
        json!(["0.5.0", "0.4.0", "0.3.0", "0.2.0"])
    );
    assert_eq!(deleted_versions(&v), ["0.1.0"]);
}

#[test]
fn a_pre_release_never_counts_toward_the_window_and_goes_once_its_release_ships() {
    if !have("jq") {
        return;
    }
    let f = Fixture::with_versions(&[
        "0.2.0",
        "0.3.0",
        "0.4.0-rc.1",
        "0.4.0-rc.2",
        "0.4.0",
        "0.5.0-rc.1",
    ]);
    let v = select(&f, "0.4.0", 3).unwrap();
    // the rcs of the shipped release are gone and did not use up the window; a newer pre-release is kept
    assert_eq!(
        v["keep_versions"],
        json!(["0.5.0-rc.1", "0.4.0", "0.3.0", "0.2.0"])
    );
    assert_eq!(deleted_versions(&v), ["0.4.0-rc.1", "0.4.0-rc.2"]);
    // inside the 14 days after its release was built they stay (a person on a beta is given time to move)
    let v = select_at(&f, "0.4.0", 3, WITHIN_GRACE).unwrap();
    assert_eq!(deleted_versions(&v), Vec::<String>::new());
    assert!(v["keep_versions"]
        .as_array()
        .unwrap()
        .iter()
        .any(|x| x == "0.4.0-rc.1"));
    // a pre-release whose release never shipped is not removed at all
    let g = Fixture::with_versions(&["0.2.0", "0.3.0", "0.4.0", "0.5.0-beta.0"]);
    let v = select(&g, "0.4.0", 3).unwrap();
    assert!(v["keep_versions"]
        .as_array()
        .unwrap()
        .iter()
        .any(|x| x == "0.5.0-beta.0"));
    let g = Fixture::with_versions(&["0.2.0", "0.3.0", "0.3.1-beta.0", "0.4.0"]);
    let v = select(&g, "0.4.0", 3).unwrap();
    assert!(
        v["keep_versions"]
            .as_array()
            .unwrap()
            .iter()
            .any(|x| x == "0.3.1-beta.0"),
        "no 0.3.1 shipped, so its beta stays"
    );
}

#[test]
fn the_newest_build_of_each_of_the_last_three_minors_stays_beside_the_last_three_versions() {
    if !have("jq") {
        return;
    }
    // five patches of 0.5, then single releases of older minors
    let f = Fixture::with_versions(&[
        "0.1.0", "0.2.0", "0.3.0", "0.4.0", "0.4.1", "0.5.0", "0.5.1", "0.5.2", "0.5.3", "0.5.4",
    ]);
    let v = select(&f, "0.5.4", 3).unwrap();
    // last three versions: 0.5.4, 0.5.3, 0.5.2; last three minors: 0.5 (0.5.4), 0.4 (0.4.1), 0.3 (0.3.0)
    assert_eq!(
        v["keep_versions"],
        json!(["0.5.4", "0.5.3", "0.5.2", "0.4.1", "0.3.0"])
    );
    assert_eq!(
        deleted_versions(&v),
        ["0.1.0", "0.2.0", "0.4.0", "0.5.0", "0.5.1"]
    );
}

#[test]
fn it_refuses_to_select_anything_when_the_released_version_is_not_there() {
    if !have("jq") {
        return;
    }
    let f = Fixture::with_versions(&["0.1.0", "0.2.0", "0.3.0"]);
    let e = select(&f, "0.4.0", 3).unwrap_err();
    assert!(e.contains("not among the images"), "{e}");
    let e = select(&f, "latest", 3).unwrap_err();
    assert!(e.contains("not a release version"), "{e}");
}

#[test]
fn it_never_selects_what_is_not_ours() {
    if !have("jq") {
        return;
    }
    let mut f = Fixture::with_versions(&["0.1.0", "0.2.0", "0.3.0", "0.4.0"]);
    let old = |n: u32, owner: &str, name: &str, t: Value| {
        json!({
            "ImageId": format!("ami-{n:08x}"), "OwnerId": owner, "Name": name, "Tags": t,
            "BlockDeviceMappings": [{"Ebs": {"SnapshotId": format!("snap-{n:08x}")}}],
        })
    };
    let managed = |v: &str| tags(&[("ozbox-managed", "true"), ("ozbox-image", v)]);
    f.images.extend([
        // another account's image carrying our tags
        old(
            900,
            "999999999999",
            "ozbox-0.0.1-20250101000000",
            managed("0.0.1"),
        ),
        // no tags at all
        old(901, OWNER, "ozbox-0.0.2-20250101000000", json!([])),
        // not marked managed
        old(
            902,
            OWNER,
            "ozbox-0.0.3-20250101000000",
            tags(&[("ozbox-image", "0.0.3")]),
        ),
        // an image tag that is not a version
        old(903, OWNER, "ozbox-0.0.4-20250101000000", managed("latest")),
        // a name that is not ours
        old(904, OWNER, "ubuntu-base", managed("0.0.5")),
        // no name at all
        old(905, OWNER, "", managed("0.0.6")),
    ]);
    let v = select(&f, "0.4.0", 3).unwrap();
    assert_eq!(deleted_versions(&v), ["0.1.0"]);
    assert_eq!(v["ignored"], 6);
    for d in v["delete"].as_array().unwrap() {
        let id = d["image_id"].as_str().unwrap();
        assert!(
            ![
                "ami-00000384",
                "ami-00000385",
                "ami-00000386",
                "ami-00000387",
                "ami-00000388",
                "ami-00000389"
            ]
            .contains(&id),
            "{id}"
        );
    }
}

#[test]
fn it_selects_only_snapshots_that_are_themselves_tagged_ours() {
    if !have("jq") {
        return;
    }
    let mut f = Fixture::with_versions(&["0.1.0", "0.2.0", "0.3.0", "0.4.0"]);
    // the oldest image's snapshot is not tagged (a copy that was never tagged), and another has a foreign one too
    f.snaps[0] = json!({"SnapshotId": f.snaps[0]["SnapshotId"], "Tags": []});
    f.images[1]["BlockDeviceMappings"] = json!([
        {"Ebs": {"SnapshotId": f.snaps[1]["SnapshotId"]}},
        {"Ebs": {"SnapshotId": "snap-ffffffff"}},
    ]);
    let v = select(&f, "0.4.0", 3).unwrap();
    let first = &v["delete"][0];
    assert_eq!(first["snapshots"], json!([]));
    assert_eq!(v["snapshots_left"].as_array().unwrap().len(), 2);
    assert!(v["delete"][1]["snapshots"]
        .as_array()
        .unwrap()
        .iter()
        .all(|s| s != "snap-ffffffff"));
}

// ---- the script -------------------------------------------------------------------------------------------------

/// A stand-in for the `aws` program: lists the fixture, records every call.
fn fake_aws(dir: &Path, f: &Fixture) -> PathBuf {
    let (images, snaps) = f.files(dir);
    let log = dir.join("calls.log");
    let script = dir.join("aws");
    std::fs::write(
        &script,
        format!(
            "#!/bin/sh\necho \"$@\" >>'{log}'\ncase \"$2\" in\n  describe-images) cat '{images}' ;;\n  describe-snapshots) cat '{snaps}' ;;\n  *) : ;;\nesac\n",
            log = log.display(),
            images = images.display(),
            snaps = snaps.display()
        ),
    )
    .unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&script, std::fs::Permissions::from_mode(0o755)).unwrap();
    }
    script
}

fn run_script(dir: &Path, aws: &Path, extra: &[&str]) -> (bool, String, String) {
    let out = Command::new("bash")
        .arg(root().join("scripts/image/retention.sh"))
        .args([
            "--released",
            "0.4.0",
            "--regions",
            "us-east-1,eu-west-1",
            "--owner",
            OWNER,
        ])
        .args(extra)
        .env("OZBOX_AWS", aws)
        .current_dir(dir)
        .output()
        .unwrap();
    (
        out.status.success(),
        String::from_utf8_lossy(&out.stdout).to_string(),
        std::fs::read_to_string(dir.join("calls.log")).unwrap_or_default(),
    )
}

#[test]
fn the_script_is_a_dry_run_unless_told_to_apply() {
    if !have("jq") || !have("bash") {
        return;
    }
    let d = tempfile::tempdir().unwrap();
    let f = Fixture::with_versions(&["0.1.0", "0.2.0", "0.3.0", "0.4.0"]);
    let aws = fake_aws(d.path(), &f);
    let (ok, out, calls) = run_script(d.path(), &aws, &[]);
    assert!(ok, "{out}");
    assert!(
        out.contains("dry run") && out.contains("retire ami-"),
        "{out}"
    );
    assert!(
        !calls.contains("deregister-image") && !calls.contains("delete-snapshot"),
        "a dry run changed nothing: {calls}"
    );
}

#[test]
fn applying_retires_each_old_image_and_its_snapshot_in_every_region_and_never_a_kept_one() {
    if !have("jq") || !have("bash") {
        return;
    }
    let d = tempfile::tempdir().unwrap();
    let f = Fixture::with_versions(&["0.1.0", "0.2.0", "0.3.0", "0.4.0"]);
    let aws = fake_aws(d.path(), &f);
    let (ok, _, calls) = run_script(d.path(), &aws, &["--apply"]);
    assert!(ok);
    for region in ["us-east-1", "eu-west-1"] {
        // 0.1.0 has two architectures: ami-1 and ami-2
        for id in ["ami-00000001", "ami-00000002"] {
            assert!(
                calls.contains(&format!(
                    "ec2 deregister-image --region {region} --image-id {id}"
                )),
                "{region} {id}: {calls}"
            );
        }
        assert!(calls.contains(&format!(
            "ec2 delete-snapshot --region {region} --snapshot-id snap-00000001"
        )));
    }
    // 0.2.0..0.4.0 stay: ami-3.. are never deregistered
    for kept in 3..=8 {
        assert!(
            !calls.contains(&format!("--image-id ami-{kept:08x}")),
            "kept image {kept} was touched: {calls}"
        );
    }
    // an image is deregistered before its snapshot is deleted
    let dereg = calls.find("deregister-image").unwrap();
    let del = calls.find("delete-snapshot").unwrap();
    assert!(dereg < del);
}

#[test]
fn a_bad_argument_or_a_missing_release_changes_nothing() {
    if !have("jq") || !have("bash") {
        return;
    }
    let d = tempfile::tempdir().unwrap();
    let f = Fixture::with_versions(&["0.1.0", "0.2.0"]);
    let aws = fake_aws(d.path(), &f);
    // the released version is not in the account: every region refuses
    let (ok, _, calls) = run_script(d.path(), &aws, &["--apply"]);
    assert!(!ok);
    assert!(
        !calls.contains("deregister-image") && !calls.contains("delete-snapshot"),
        "{calls}"
    );
    let out = Command::new("bash")
        .arg(root().join("scripts/image/retention.sh"))
        .args([
            "--released",
            "0.4.0",
            "--regions",
            "us-east-1; rm -rf /",
            "--owner",
            OWNER,
        ])
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(2));
}

#[test]
fn the_workflow_retires_only_after_the_release_is_signed_and_public() {
    let w = std::fs::read_to_string(root().join(".github/workflows/image.yml")).unwrap();
    assert!(w.contains("scripts/image/retention.sh") && w.contains("scripts/image/publish.sh"));
    let publish = w.find("scripts/image/publish.sh").unwrap();
    let retire = w.find("scripts/image/retention.sh").unwrap();
    let sign = w.find("cosign sign-blob").unwrap();
    assert!(
        sign < publish && publish < retire,
        "sign, then publish, then retire"
    );
}

// ---- publishing ---------------------------------------------------------------------------------------------------

fn publish(dir: &Path, manifest: &Value, extra: &[&str]) -> (bool, String, String, String) {
    let log = dir.join("calls.log");
    let aws = dir.join("aws");
    std::fs::write(
        &aws,
        format!(
            "#!/bin/sh\necho \"$@\" >>'{}'\ncase \"$2\" in\n  describe-images) case \"$*\" in *Public*) echo True ;; *) echo snap-0000000a ;; esac ;;\nesac\n",
            log.display()
        ),
    )
    .unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&aws, std::fs::Permissions::from_mode(0o755)).unwrap();
    }
    let m = dir.join("manifest.json");
    std::fs::write(&m, manifest.to_string()).unwrap();
    let out = Command::new("bash")
        .arg(root().join("scripts/image/publish.sh"))
        .arg("--manifest")
        .arg(&m)
        .args(["--version", "0.4.0", "--regions", "us-east-1,eu-west-1"])
        .args(extra)
        .env("OZBOX_AWS", &aws)
        .output()
        .unwrap();
    (
        out.status.success(),
        String::from_utf8_lossy(&out.stdout).to_string(),
        String::from_utf8_lossy(&out.stderr).to_string(),
        std::fs::read_to_string(&log).unwrap_or_default(),
    )
}

fn manifest() -> Value {
    json!({"version": "0.4.0", "images": [
        {"arch": "amd64", "amis": {"us-east-1": "ami-0000000a", "eu-west-1": "ami-0000000b"}},
        {"arch": "arm64", "amis": {"us-east-1": "ami-0000000c", "eu-west-1": "ami-0000000d"}},
    ]})
}

#[test]
fn publishing_lists_by_default_and_with_apply_tags_then_makes_each_manifest_image_public() {
    if !have("jq") || !have("bash") {
        return;
    }
    let d = tempfile::tempdir().unwrap();
    let (ok, out, _, calls) = publish(d.path(), &manifest(), &[]);
    assert!(
        ok && out.contains("dry run") && out.contains("eu-west-1 ami-0000000d"),
        "{out}"
    );
    assert!(calls.is_empty(), "a dry run calls nothing: {calls}");

    let d = tempfile::tempdir().unwrap();
    let (ok, _, err, calls) = publish(d.path(), &manifest(), &["--apply"]);
    assert!(ok, "{err}");
    for (region, id) in [
        ("us-east-1", "ami-0000000a"),
        ("us-east-1", "ami-0000000c"),
        ("eu-west-1", "ami-0000000b"),
        ("eu-west-1", "ami-0000000d"),
    ] {
        let tag = calls
            .find(&format!("create-tags --region {region} --resources {id}"))
            .unwrap();
        let public = calls
            .find(&format!("modify-image-attribute --region {region} --image-id {id} --launch-permission Add=[{{Group=all}}]"))
            .unwrap();
        assert!(
            tag < public,
            "{id} is tagged as ours before it is made public"
        );
    }
    // nothing outside the manifest is touched
    assert_eq!(calls.matches("modify-image-attribute").count(), 4);
}

#[test]
fn publishing_refuses_a_manifest_for_another_version_or_a_region_it_does_not_list() {
    if !have("jq") || !have("bash") {
        return;
    }
    let d = tempfile::tempdir().unwrap();
    let mut other = manifest();
    other["version"] = json!("0.3.0");
    let (ok, _, err, calls) = publish(d.path(), &other, &["--apply"]);
    assert!(!ok && err.contains("not for version"), "{err}");
    assert!(calls.is_empty());
    let d = tempfile::tempdir().unwrap();
    let (ok, _, err, calls) = publish(
        d.path(),
        &manifest(),
        &["--apply", "--regions", "ap-southeast-1"],
    );
    assert!(
        !ok && err.contains("lists no image for ap-southeast-1"),
        "{err}"
    );
    assert!(!calls.contains("modify-image-attribute"));
}

#[test]
fn the_preflight_refuses_a_region_that_blocks_public_sharing_and_changes_nothing() {
    if !have("bash") {
        return;
    }
    let d = tempfile::tempdir().unwrap();
    for (state, ok) in [("unblocked", true), ("block-new-sharing", false)] {
        let aws = d.path().join("aws");
        std::fs::write(&aws, format!("#!/bin/sh\necho {state}\n")).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&aws, std::fs::Permissions::from_mode(0o755)).unwrap();
        }
        let out = Command::new("bash")
            .arg(root().join("scripts/image/preflight.sh"))
            .args(["--regions", "us-east-1,eu-west-1"])
            .env("OZBOX_AWS", &aws)
            .output()
            .unwrap();
        assert_eq!(out.status.success(), ok, "{state}");
        if !ok {
            assert!(
                String::from_utf8_lossy(&out.stderr).contains("disable-image-block-public-access")
            );
        }
    }
}

#[test]
fn a_pre_release_is_public_only_through_the_exact_beta_opt_in_and_nothing_is_scheduled() {
    let w = std::fs::read_to_string(root().join(".github/workflows/image.yml")).unwrap();
    // a pre-release is public only through the exact beta opt-in, decided in the plan job and nowhere else
    assert!(w.contains("publish_prerelease_version"));
    assert!(w.contains("-beta\\.[0-9]+$"));
    assert!(w.contains("if [ \"$IN_PUBPRE\" != \"$version\" ] ||"));
    assert!(w.contains("a pre-release would be public without the exact opt-in"));
    assert!(
        w.contains("prerelease: $prerelease"),
        "the manifest carries it signed"
    );
    // no scheduled run builds, signs or publishes anything
    assert!(!w.contains("schedule:"), "the monthly build is gone");
    assert!(w.contains("scripts/image/preflight.sh"));
    assert!(
        w.contains("certificate-identity-regexp"),
        "a republish checks the signing identity"
    );
}

// ---- the end of the image build ---------------------------------------------------------------------------------------

fn packer_file(rel: &str) -> String {
    std::fs::read_to_string(root().join("infra/packer/ozbox-image").join(rel)).unwrap()
}

#[test]
fn the_wipe_removes_the_build_instances_state_and_nothing_else() {
    if !have("bash") {
        return;
    }
    let d = tempfile::tempdir().unwrap();
    let r = d.path();
    for (path, body) in [
        (
            "home/ubuntu/.ssh/authorized_keys",
            "ssh-ed25519 AAAA packer",
        ),
        ("home/ubuntu/.ssh/known_hosts", "keep"),
        ("root/.ssh/authorized_keys", "ssh-ed25519 AAAA other"),
        ("var/lib/amazon/ssm/registration", "id"),
        ("var/lib/amazon/ssm/sub/x", "id"),
        ("var/log/amazon/ssm/amazon-ssm-agent.log", "log"),
        ("var/log/journal/abc/system.journal", "journal"),
        ("etc/ozbox/image-release", "keep"),
    ] {
        let p = r.join(path);
        std::fs::create_dir_all(p.parent().unwrap()).unwrap();
        std::fs::write(p, body).unwrap();
    }
    let run = |root_dir: &Path| {
        Command::new("sh")
            .arg(root().join("infra/packer/ozbox-image/scripts/image-wipe.sh"))
            .env("OZBOX_WIPE_ROOT", root_dir)
            .output()
            .unwrap()
    };
    assert!(run(r).status.success());
    for gone in [
        "home/ubuntu/.ssh/authorized_keys",
        "root/.ssh/authorized_keys",
        "var/lib/amazon/ssm/registration",
        "var/lib/amazon/ssm/sub/x",
        "var/log/amazon/ssm/amazon-ssm-agent.log",
        "var/log/journal/abc/system.journal",
    ] {
        assert!(!r.join(gone).exists(), "{gone} is still there");
    }
    for kept in ["home/ubuntu/.ssh/known_hosts", "etc/ozbox/image-release"] {
        assert!(r.join(kept).exists(), "{kept} was removed");
    }
    // and with nothing to remove it is still fine
    let empty = tempfile::tempdir().unwrap();
    assert!(run(empty.path()).status.success());
}

#[test]
fn the_wipe_runs_at_shutdown_after_the_agent_stops_and_leaves_nothing_in_the_image() {
    let hcl = packer_file("ozbox-image.pkr.hcl");
    let install = packer_file("scripts/image-wipe-install.sh");
    // wired in, last, for the AWS source only, with the key cleared by Packer too
    assert!(hcl.contains("ssh_clear_authorized_keys   = true"));
    let wipe = hcl.find("image-wipe-install.sh").unwrap();
    assert!(
        hcl.find("dpkg-status").unwrap() < wipe,
        "after the downloads that use the session"
    );
    assert!(wipe < hcl.find("post-processor \"manifest\"").unwrap());
    // it is not removed while the session is open
    assert!(!hcl.contains("rm -rf /var/lib/amazon"));
    // started before the agent, so stopped after it; only while the marker exists; nothing persistent
    assert!(install.contains("Before=snap.amazon-ssm-agent.amazon-ssm-agent.service"));
    assert!(install.contains("ConditionPathExists=/run/ozbox-image-wipe.marker"));
    assert!(install.contains("ExecStop=/bin/sh /run/ozbox-image-wipe.sh"));
    assert!(install.contains("/run/systemd/system/"));
    for persistent in [
        "/etc/systemd",
        "/usr/local",
        "/lib/systemd",
        "systemctl enable",
    ] {
        assert!(
            !install.contains(persistent),
            "{persistent} would persist into the image"
        );
    }
}

#[test]
fn the_wipe_stops_journald_writing_to_var_before_it_deletes_the_journal() {
    let w = packer_file("scripts/image-wipe.sh");
    let flush = w.find("journalctl --flush").expect("flush");
    let rotate = w.find("journalctl --rotate").expect("rotate");
    let relinquish = w
        .find("journalctl --relinquish-var")
        .expect("relinquish-var");
    let delete = w
        .find("find \"$r/var/log/journal\"")
        .expect("journal delete");
    assert!(
        flush < rotate && rotate < relinquish,
        "flush, rotate, then relinquish /var"
    );
    assert!(
        relinquish < delete,
        "journald must stop writing to /var BEFORE the files are removed, or the build boot lands in the image"
    );
}

#[test]
fn the_image_workflow_marks_a_pre_release_version_as_a_github_pre_release() {
    let w = std::fs::read_to_string(root().join(".github/workflows/image.yml")).unwrap();
    assert!(w.contains("case \"$VERSION\" in *-*) flags+=(--prerelease) ;; esac"));
    assert!(w.contains("gh release create \"$tag\" \"${flags[@]}\""));
}

#[test]
fn the_packer_fallback_policy_has_a_statement_and_ci_validates_both_profile_paths() {
    let hcl = packer_file("ozbox-image.pkr.hcl");
    let at = hcl
        .find("temporary_iam_instance_profile_policy_document")
        .unwrap();
    let block = &hcl[at..at + 700];
    assert!(
        block.contains("Statement {"),
        "the policy document needs a Statement block"
    );
    let ci = std::fs::read_to_string(root().join(".github/workflows/ci.yml")).unwrap();
    assert!(ci.contains("-var aws_instance_profile= "));
    assert!(ci.contains("-var aws_instance_profile=ozbox-build"));
}
