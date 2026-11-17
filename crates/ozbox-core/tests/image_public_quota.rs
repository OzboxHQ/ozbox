//! The public-image quota (ADR 0052): AWS lets an account share only a few images publicly per region, so a release must make
//! room first, publish all or nothing, and be republishable when it is half public. `scripts/image/make-room.sh`,
//! `public-quota.jq`, `publish.sh` and `preflight.sh` run for real against a stateful stand-in for the `aws` program that
//! enforces the quota the way AWS does (it refuses the grant that would pass it, with `ResourceLimitExceeded`).
#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::path::{Path, PathBuf};
use std::process::Command;

use serde_json::{json, Value};

const OWNER: &str = "372115812457";
const RELEASE: &str = "0.2.0-beta.2";
const REGION: &str = "us-east-1";

fn root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../..")
}

fn have(tool: &str) -> bool {
    let found = Command::new(tool)
        .arg("--version")
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false);
    if !found {
        assert!(
            std::env::var_os("CI").is_none(),
            "{tool} is not installed, and this test runs the quota scripts"
        );
        eprintln!("SKIPPED: {tool} is not installed");
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

fn id(n: u32) -> String {
    format!("ami-{n:08x}")
}

/// One image of ours (two per version: n and n+1 are its architectures).
fn ours(n: u32, version: &str, public: bool) -> Value {
    json!({
        "ImageId": id(n), "OwnerId": OWNER, "Name": format!("ozbox-{version}-2026111400{n:04}"),
        "Public": public,
        "Tags": tags(&[("ozbox-managed", "true"), ("ozbox-image", version), ("ozbox-image-version", version)]),
        "BlockDeviceMappings": [{"Ebs": {"SnapshotId": format!("snap-{n:08x}")}}],
    })
}

fn foreign(n: u32, owner: &str, name: &str, t: Value) -> Value {
    json!({"ImageId": id(n), "OwnerId": owner, "Name": name, "Public": true, "Tags": t,
           "BlockDeviceMappings": [{"Ebs": {"SnapshotId": format!("snap-{n:08x}")}}]})
}

/// A stateful `aws`: `state-<region>.json` holds every image and whether it is public.
struct World {
    dir: tempfile::TempDir,
}

impl World {
    fn new(images: &[(&str, Vec<Value>)]) -> World {
        let w = World {
            dir: tempfile::tempdir().unwrap(),
        };
        for (region, imgs) in images {
            std::fs::write(
                w.dir.path().join(format!("state-{region}.json")),
                Value::Array(imgs.clone()).to_string(),
            )
            .unwrap();
        }
        let script = r#"#!/bin/sh
echo "$@" >>"$OZBOX_FAKE_DIR/calls.log"
cmd="$2"; region=""; id=""; perm=""; q=""
while [ $# -gt 0 ]; do
  case "$1" in --region) region="$2" ;; --image-id|--image-ids) id="$2" ;; --launch-permission) perm="$2" ;; --query) q="$2" ;; esac
  shift
done
st="$OZBOX_FAKE_DIR/state-$region.json"
setpub() { jq --arg id "$id" --argjson v "$1" 'map(if .ImageId == $id then .Public = $v else . end)' "$st" >"$st.n" && mv "$st.n" "$st"; }
case "$cmd" in
  list-service-quotas)
    [ -z "${QUOTA_UNREADABLE:-}" ] || { echo "AccessDenied" >&2; exit 255; }
    echo "${QUOTA:-5}.0" ;;
  describe-images)
    if [ -n "$id" ]; then
      case "$q" in
        *Public*) jq -r --arg id "$id" '[.[] | select(.ImageId == $id)][0] | if . == null then "None" elif .Public then "True" else "False" end' "$st" ;;
        *) echo "snap-$(echo "$id" | cut -c5-)" ;;
      esac
    else jq '{Images: map(select(.Public))}' "$st"; fi ;;
  modify-image-attribute)
    case "$perm" in
      Add*)
        if [ "$id" = "${FAIL_ID:-}" ]; then echo "An error occurred (OperationNotPermitted) when calling the ModifyImageAttribute operation" >&2; exit 254; fi
        n="$(jq '[.[] | select(.Public)] | length' "$st")"
        if [ "$n" -ge "${QUOTA:-5}" ]; then
          echo "An error occurred (ResourceLimitExceeded) when calling the ModifyImageAttribute operation: You have reached your quota of ${QUOTA:-5}" >&2; exit 254
        fi
        setpub true ;;
      Remove*) setpub false ;;
    esac ;;
  get-image-block-public-access-state) echo unblocked ;;
esac
"#;
        let p = w.dir.path().join("aws");
        std::fs::write(&p, script).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o755)).unwrap();
        }
        w
    }

    fn run(&self, script: &str, args: &[&str], env: &[(&str, &str)]) -> (bool, String, String) {
        let out = Command::new("bash")
            .arg(root().join("scripts/image").join(script))
            .args(args)
            .env("OZBOX_AWS", self.dir.path().join("aws"))
            .env("OZBOX_FAKE_DIR", self.dir.path())
            .envs(env.iter().copied())
            .output()
            .unwrap();
        (
            out.status.success(),
            String::from_utf8_lossy(&out.stdout).to_string(),
            String::from_utf8_lossy(&out.stderr).to_string(),
        )
    }

    fn manifest(&self, regions: &[&str]) -> PathBuf {
        let amis = |base: u32| {
            let mut m = serde_json::Map::new();
            for (i, r) in regions.iter().enumerate() {
                m.insert((*r).into(), json!(id(base + i as u32 * 0x100)));
            }
            Value::Object(m)
        };
        let p = self.dir.path().join("manifest.json");
        std::fs::write(
            &p,
            json!({"version": RELEASE, "images": [
                {"arch": "amd64", "amis": amis(0xa1)}, {"arch": "arm64", "amis": amis(0xa2)}]})
            .to_string(),
        )
        .unwrap();
        p
    }

    fn calls(&self) -> String {
        std::fs::read_to_string(self.dir.path().join("calls.log")).unwrap_or_default()
    }

    fn public(&self, region: &str) -> Vec<String> {
        let v: Value = serde_json::from_slice(
            &std::fs::read(self.dir.path().join(format!("state-{region}.json"))).unwrap(),
        )
        .unwrap();
        let mut ids: Vec<String> = v
            .as_array()
            .unwrap()
            .iter()
            .filter(|i| i["Public"] == true)
            .map(|i| i["ImageId"].as_str().unwrap().to_string())
            .collect();
        ids.sort();
        ids
    }

    fn make_room(
        &self,
        regions: &str,
        extra: &[&str],
        env: &[(&str, &str)],
    ) -> (bool, String, String) {
        let m = self.manifest(&regions.split(',').collect::<Vec<_>>());
        let mut args = vec![
            "--manifest",
            m.to_str().unwrap(),
            "--version",
            RELEASE,
            "--regions",
            regions,
            "--owner",
            OWNER,
        ];
        args.extend_from_slice(extra);
        self.run("make-room.sh", &args, env)
    }

    fn publish(&self, regions: &str, env: &[(&str, &str)]) -> (bool, String, String) {
        let m = self.manifest(&regions.split(',').collect::<Vec<_>>());
        self.run(
            "publish.sh",
            &[
                "--manifest",
                m.to_str().unwrap(),
                "--version",
                RELEASE,
                "--regions",
                regions,
                "--apply",
            ],
            env,
        )
    }
}

/// The state on 2026-11-15: beta.0 (1, 2) and beta.1 (3, 4) public, beta.2 (0xa1, 0xa2) built and signed but private.
fn incident() -> Vec<Value> {
    vec![
        ours(1, "0.2.0-beta.0", true),
        ours(2, "0.2.0-beta.0", true),
        ours(3, "0.2.0-beta.1", true),
        ours(4, "0.2.0-beta.1", true),
        ours(0xa1, RELEASE, false),
        ours(0xa2, RELEASE, false),
    ]
}

fn modified(calls: &str, perm: &str, image: &str) -> bool {
    calls.contains(&format!("--image-id {image} --launch-permission {perm}"))
}

#[test]
fn a_full_quota_makes_the_oldest_version_private_and_the_release_then_fits() {
    if !have("jq") || !have("bash") {
        return;
    }
    let w = World::new(&[(REGION, incident())]);
    // as it was: the release does not fit, and is half published before AWS refuses
    let (ok, out, err) = w.make_room(REGION, &["--apply"], &[]);
    assert!(ok, "{out}{err}");
    // the oldest whole version (both architectures) went private; the newer previous version did not
    assert_eq!(w.public(REGION), [id(3), id(4)]);
    let calls = w.calls();
    assert!(
        modified(&calls, "Remove=[{Group=all}]", &id(1))
            && modified(&calls, "Remove=[{Group=all}]", &id(2))
    );
    assert!(
        !calls.contains(&id(3)) && !calls.contains(&id(4)),
        "{calls}"
    );
    // nothing is deleted: private, not retired
    assert!(!calls.contains("deregister-image") && !calls.contains("delete-snapshot"));
    let (ok, _, err) = w.publish(REGION, &[]);
    assert!(ok, "{err}");
    assert_eq!(w.public(REGION), [id(3), id(4), id(0xa1), id(0xa2)]);
}

#[test]
fn without_making_room_the_publish_fails_by_rolling_back_and_naming_the_quota() {
    if !have("jq") || !have("bash") {
        return;
    }
    // the incident: 4 public, quota 5: the first of the release's images goes public, the second is refused
    let w = World::new(&[(REGION, incident())]);
    let (ok, _, err) = w.publish(REGION, &[]);
    assert!(!ok);
    assert!(
        err.contains("quota") && err.contains("make-room.sh"),
        "{err}"
    );
    // the one that went public was made private again: the release is not left half public
    let calls = w.calls();
    assert!(modified(&calls, "Add=[{Group=all}]", &id(0xa1)));
    assert!(
        modified(&calls, "Remove=[{Group=all}]", &id(0xa1)),
        "{calls}"
    );
    assert_eq!(w.public(REGION), [id(1), id(2), id(3), id(4)]);
}

#[test]
fn it_never_touches_the_released_version_a_newer_one_or_an_image_that_is_not_ours() {
    if !have("jq") || !have("bash") {
        return;
    }
    let mut imgs = vec![
        ours(1, "0.2.0-beta.0", true),
        ours(2, "0.2.0-beta.0", true),
        // a NEWER version is public too, and the release is already half public (its amd64)
        ours(5, "0.3.0", true),
        ours(0xa1, RELEASE, true),
        ours(0xa2, RELEASE, false),
    ];
    // not ours: another account's image wearing our tags, an untagged one, one with a foreign name
    let managed = tags(&[("ozbox-managed", "true"), ("ozbox-image", "0.0.1")]);
    imgs.push(foreign(
        0x90,
        "999999999999",
        "ozbox-0.0.1-x",
        managed.clone(),
    ));
    imgs.push(foreign(0x91, OWNER, "ozbox-0.0.1-y", json!([])));
    imgs.push(foreign(0x92, OWNER, "ubuntu-base", managed));
    let w = World::new(&[(REGION, imgs)]);
    // 7 public, quota 7: 1 more is needed, so exactly one whole older version goes private
    let (ok, out, err) = w.make_room(REGION, &["--apply"], &[("QUOTA", "7")]);
    assert!(ok, "{out}{err}");
    let calls = w.calls();
    for untouched in [id(5), id(0xa1), id(0xa2), id(0x90), id(0x91), id(0x92)] {
        assert!(
            !modified(&calls, "Remove=[{Group=all}]", &untouched),
            "{untouched}: {calls}"
        );
    }
    assert_eq!(
        calls.matches("modify-image-attribute").count(),
        2,
        "{calls}"
    );
    assert!(w.public(REGION).contains(&id(5)) && w.public(REGION).contains(&id(0x90)));
}

#[test]
fn it_frees_only_what_the_release_needs() {
    if !have("jq") || !have("bash") {
        return;
    }
    // plenty of room: nothing is made private, even when old versions are public
    let w = World::new(&[(REGION, incident())]);
    let (ok, out, err) = w.make_room(REGION, &["--apply"], &[("QUOTA", "6")]);
    assert!(ok, "{out}{err}");
    assert!(!w.calls().contains("modify-image-attribute"));
    assert_eq!(w.public(REGION).len(), 4);
    // a quota that the service reports is the one used (10 here): still nothing
    let w = World::new(&[(REGION, incident())]);
    let (ok, _, _) = w.make_room(REGION, &["--apply"], &[("QUOTA", "10")]);
    assert!(ok && !w.calls().contains("modify-image-attribute"));
}

#[test]
fn when_the_quota_cannot_be_read_it_assumes_five_and_says_so() {
    if !have("jq") || !have("bash") {
        return;
    }
    let w = World::new(&[(REGION, incident())]);
    let (ok, _, err) = w.make_room(REGION, &["--apply"], &[("QUOTA_UNREADABLE", "1")]);
    assert!(ok && err.contains("assuming AWS's default of 5"), "{err}");
    assert_eq!(w.public(REGION), [id(3), id(4)]);
}

#[test]
fn a_release_that_cannot_fit_changes_nothing_in_any_region_and_names_the_quota() {
    if !have("jq") || !have("bash") {
        return;
    }
    // eu-west-1 is fine; us-east-1 is full of public images that are not ours, so nothing we may change helps
    let mut full: Vec<Value> = (0..5)
        .map(|n| foreign(0x80 + n, "999999999999", "someone-elses", json!([])))
        .collect();
    full.extend([ours(0xa1, RELEASE, false), ours(0xa2, RELEASE, false)]);
    full.extend([ours(1, "0.2.0-beta.0", true), ours(2, "0.2.0-beta.0", true)]);
    let ok_region = vec![
        ours(1, "0.2.0-beta.0", true),
        ours(2, "0.2.0-beta.0", true),
        ours(3, "0.2.0-beta.1", true),
        ours(4, "0.2.0-beta.1", true),
        ours(0xb1, RELEASE, false),
        ours(0xb2, RELEASE, false),
    ];
    let w = World::new(&[(REGION, full), ("eu-west-1", ok_region)]);
    let (ok, _, err) = w.make_room("eu-west-1,us-east-1", &["--apply"], &[]);
    assert!(!ok);
    assert!(
        err.contains("Public AMIs") && err.contains("quota") && err.contains("Nothing was changed"),
        "{err}"
    );
    assert!(
        !w.calls().contains("modify-image-attribute"),
        "{}",
        w.calls()
    );
}

#[test]
fn a_failure_part_way_through_rolls_back_every_image_this_run_made_public() {
    if !have("jq") || !have("bash") {
        return;
    }
    let regions = "us-east-1,eu-west-1";
    let img = |a: u32, b: u32| vec![ours(a, RELEASE, false), ours(b, RELEASE, false)];
    let w = World::new(&[
        (REGION, img(0xa1, 0xa2)),
        ("eu-west-1", img(0xa1 + 0x100, 0xa2 + 0x100)),
    ]);
    // the third image (eu-west-1 amd64) is refused
    let (ok, _, err) = w.publish(regions, &[("FAIL_ID", &id(0xa1 + 0x100))]);
    assert!(!ok && err.contains("private again"), "{err}");
    assert!(
        w.public(REGION).is_empty(),
        "us-east-1 was rolled back: {:?}",
        w.public(REGION)
    );
    assert!(w.public("eu-west-1").is_empty());
    let calls = w.calls();
    assert_eq!(calls.matches("Add=[{Group=all}]").count(), 3, "{calls}");
    assert_eq!(calls.matches("Remove=[{Group=all}]").count(), 2, "{calls}");
}

#[test]
fn a_half_public_release_is_published_again_by_skipping_what_is_public() {
    if !have("jq") || !have("bash") {
        return;
    }
    // beta.2: the state after the failed run: amd64 public in us-east-1 (5 public), arm64 refused
    let mut imgs = incident();
    imgs[4] = ours(0xa1, RELEASE, true);
    let w = World::new(&[(REGION, imgs)]);
    let (ok, out, err) = w.make_room(REGION, &["--apply"], &[]);
    assert!(ok, "{out}{err}");
    // one image is needed (not two): the oldest version goes private, the already-public amd64 stays
    assert_eq!(w.public(REGION), [id(3), id(4), id(0xa1)]);
    let (ok, out, err) = w.publish(REGION, &[]);
    assert!(ok, "{out}{err}");
    assert!(
        out.contains(&format!("{REGION} {} (already public, skipped)", id(0xa1))),
        "{out}"
    );
    assert_eq!(w.public(REGION), [id(3), id(4), id(0xa1), id(0xa2)]);
    // the already-public image was not tagged or granted again
    assert!(!modified(&w.calls(), "Add=[{Group=all}]", &id(0xa1)));
    // and with nothing left to do, publishing again changes nothing
    let (ok, _, _) = w.publish(REGION, &[]);
    assert!(ok);
}

#[test]
fn make_room_is_a_dry_run_unless_told_to_apply() {
    if !have("jq") || !have("bash") {
        return;
    }
    let w = World::new(&[(REGION, incident())]);
    let (ok, out, _) = w.make_room(REGION, &[], &[]);
    assert!(
        ok && out.contains("dry run") && out.contains("make private ami-00000001"),
        "{out}"
    );
    assert!(!w.calls().contains("modify-image-attribute"));
    // a bad argument is refused before any call
    let (ok, _, _) = w.make_room(REGION, &["--quota", "0"], &[]);
    assert!(!ok);
}

#[test]
fn the_preflight_checks_the_quota_can_hold_the_release_before_a_build() {
    if !have("jq") || !have("bash") {
        return;
    }
    // old Oz Box versions do not count (they are made private); other public images do
    let w = World::new(&[(REGION, incident())]);
    let (ok, out, err) = w.run(
        "preflight.sh",
        &["--regions", REGION, "--owner", OWNER, "--need", "2"],
        &[],
    );
    assert!(ok, "{out}{err}");
    let full: Vec<Value> = (0..4)
        .map(|n| foreign(0x80 + n, "999999999999", "someone-elses", json!([])))
        .collect();
    let w = World::new(&[(REGION, full)]);
    let (ok, _, err) = w.run(
        "preflight.sh",
        &["--regions", REGION, "--owner", OWNER, "--need", "2"],
        &[],
    );
    assert!(!ok && err.contains("quota"), "{err}");
}

#[test]
fn the_workflow_checks_the_quota_first_makes_room_then_publishes_then_may_retire() {
    let w = std::fs::read_to_string(root().join(".github/workflows/image.yml")).unwrap();
    let build_preflight = w
        .find("preflight.sh --regions \"$REGIONS\" --owner")
        .unwrap();
    let packer = w.find("hashicorp/setup-packer").unwrap();
    assert!(
        build_preflight < packer,
        "the quota is checked before anything is built"
    );
    let publish_job = w.find("\n  publish:").unwrap();
    let room = w.find("scripts/image/make-room.sh").unwrap();
    let publish = w.find("scripts/image/publish.sh").unwrap();
    let retire = w.find("scripts/image/retention.sh").unwrap();
    assert!(
        publish_job < room && room < publish && publish < retire,
        "make room, then publish, then retire"
    );
    assert!(w[room..publish].contains("--apply"));
    assert!(
        w[room..publish].contains("signed/ozbox-image-manifest.json"),
        "planned from the signed manifest"
    );
    // the retirement stays its own step with its own switch
    assert!(w[retire - 600..retire].contains("RETIRE: ${{ inputs.retire_old }}"));
}
