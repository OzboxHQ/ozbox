//! The verifier and the image workflow must agree: the file names the workflow uploads, the keys its manifest has, and
//! the workflow file the signing identity names. If the workflow changes one of them, the verifier would start
//! refusing every real release (or, worse, trusting a file nobody signs); this fails first.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use ozbox_core::release::{identity_regexp, manifest_lists};
use ozbox_core::ReleaseKind;

fn workflow() -> String {
    let path =
        std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../.github/workflows/image.yml");
    std::fs::read_to_string(path).unwrap_or_default()
}

#[test]
fn the_workflow_signs_the_manifest_the_verifier_fetches() {
    let w = workflow();
    assert!(!w.is_empty(), "the image workflow was not found");
    for needle in [
        "ozbox-image-manifest.json",
        "cosign sign-blob",
        "--output-signature ozbox-image-manifest.json.sig",
        "--output-certificate ozbox-image-manifest.json.pem",
        "--bundle ozbox-image-manifest.json.sigstore.json",
        "tag=\"image-v$VERSION\"",
        "gh release upload",
    ] {
        assert!(
            w.contains(needle),
            "the workflow no longer contains {needle:?}"
        );
    }
    // the keys the verifier reads from the manifest are the keys the workflow writes
    for key in ["version:", "images:", "amis:"] {
        assert!(w.contains(key), "the workflow's manifest has no {key}");
    }
}

#[test]
fn the_manifest_records_the_first_boot_the_program_renders() {
    let w = workflow();
    // computed with the shared recipe, checked against the program itself, written under the key the verifier reads
    for needle in [
        "sh scripts/first-boot-hash.sh infra",
        "infra --json | jq -r .first_boot_sha256",
        "first_boot: $first_boot",
        "jq -e '.first_boot | test(",
    ] {
        assert!(
            w.contains(needle),
            "the workflow no longer contains {needle:?}"
        );
    }
    // M2: the program of EVERY architecture is run (arm64 under emulation) and compared, and an architecture with no
    // check fails closed rather than being skipped
    let agent_check = w
        .split("The program carries this commit's box modules")
        .nth(1)
        .and_then(|rest| rest.split("\n      - ").next())
        .unwrap_or_default();
    for needle in [
        "amd64) run=() ;;",
        "qemu-aarch64-static",
        "*)",
        "exit 1",
        "\"./out/ozbox-linux-$ARCH\" infra --json",
        ">\"out/ozbox-linux-$ARCH.first-boot\"",
    ] {
        assert!(
            agent_check.contains(needle),
            "the per-architecture check no longer contains {needle:?}"
        );
    }
    for needle in [
        "for arch in $archs; do",
        "check=\"parts/ozboxd-$arch/ozbox-linux-$arch.first-boot\"",
        "if [ ! -f \"$check\" ]; then",
        // the published program is the checked one, by hash
        "checked_sha=\"$(tr -d '\\n' <\"parts/ozboxd-$arch/ozbox-linux-$arch.sha256\")\"",
        "published_sha=\"$(tr -d '\\n' <\"parts/image-$arch/agent/ozbox-linux-$arch.sha256\")\"",
        "is not the one whose first boot was checked",
    ] {
        assert!(
            w.contains(needle),
            "the release job no longer contains {needle:?}"
        );
    }
    // an empty `parts/image-*` already fails at the first copy: no unreachable guard stands in for that
    assert!(!w.contains("no image part was downloaded"));
    assert!(
        !w.contains("if [ -f out/ozbox-linux-amd64 ]"),
        "the check must not depend on one architecture being present"
    );
    // both architectures are built by the agent job, whatever the image plan
    assert!(w.contains("- arch: amd64") && w.contains("- arch: arm64"));
    let h = "0".repeat(64);
    assert_eq!(
        ozbox_core::release::manifest_first_boot(&format!(r#"{{"first_boot":"{h}"}}"#)),
        Some(h)
    );
}

#[test]
fn the_signing_identity_names_the_workflow_file_that_signs() {
    let w = workflow();
    assert!(
        w.starts_with("name: Image"),
        "the workflow this identity names is image.yml"
    );
    let re = identity_regexp("example-org/example-repo", ReleaseKind::Image);
    assert!(re.contains("workflows/image\\.yml@"));
    // an id the workflow's jq produces (region to image id) is found by the verifier
    let manifest =
        r#"{"version":"0.1.0","images":[{"arch":"amd64","amis":{"us-east-1":"ami-1"}}]}"#;
    assert!(manifest_lists(manifest, "0.1.0", "us-east-1", "ami-1").is_ok());
}

// ---- ADR 0038, phase 1: the manifest's `upgrade` record and the image's disk generation ----

fn repo_file(rel: &str) -> String {
    std::fs::read_to_string(
        std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../..")
            .join(rel),
    )
    .unwrap_or_default()
}

#[test]
fn the_workflow_writes_the_upgrade_record_the_verifier_reads() {
    let w = workflow();
    for needle in [
        // the image is built for this commit's first boot, and says so to provisioning
        "PKR_VAR_first_boot_sha256=$fb",
        // every part the image computed is required, exactly once, as a SHA-256
        "for k in kernel packages first_boot build units accounts sshd config disk_generation; do",
        "disk-parts-${{ matrix.arch }}.txt",
        // the record, under the keys the parser reads
        "upgrade: $upgrade",
        "-f infra/packer/ozbox-image/upgrade-record.jq",
        "infra/packer/ozbox-image/upgrade-policy.json",
        // the recipe's hash is one part of the generation, computed the same way in the build and the release job
        "sh scripts/packer-build-hash.sh infra/packer/ozbox-image",
        "PKR_VAR_build_sha256=$build",
        "'.disk.build == $b'",
        // refused when the image's first boot is not this commit's, or a generation is missing
        "'.disk.first_boot == $fb'",
        "'.upgrade.disk_parts.first_boot == .first_boot'",
        ".upgrade.disk_generation as $g | .images | all(",
    ] {
        assert!(
            w.contains(needle),
            "the workflow no longer contains {needle:?}"
        );
    }
    // the policy file is never merged whole into the signed record (see the jq tests below)
    assert!(
        !w.contains("$policy[0]"),
        "the workflow reads the policy file itself; the record is made by upgrade-record.jq"
    );
    let policy: serde_json::Value =
        serde_json::from_str(&repo_file("infra/packer/ozbox-image/upgrade-policy.json")).unwrap();
    assert!(policy["work_format_reads"]
        .as_array()
        .unwrap()
        .contains(&policy["work_format"]));
}

#[test]
fn the_image_records_its_disk_generation_for_the_box_and_the_manifest() {
    let p = repo_file("infra/packer/ozbox-image/scripts/provision.sh");
    for needle in [
        ": \"${OZBOX_FIRST_BOOT_SHA256:?}\"",
        ": \"${OZBOX_BUILD_SHA256:?}\"",
        "sh /tmp/ozbox-disk-generation.sh",
        "\\ndisk_generation=%s\\n",
        "/etc/ozbox/disk-parts",
    ] {
        assert!(
            p.contains(needle),
            "provision.sh no longer contains {needle:?}"
        );
    }
    // the package map is written before the generation is computed from it
    assert!(
        p.find("/etc/ozbox/packages.txt").unwrap()
            < p.find("sh /tmp/ozbox-disk-generation.sh").unwrap()
    );
    let h = repo_file("infra/packer/ozbox-image/ozbox-image.pkr.hcl");
    for needle in [
        "OZBOX_FIRST_BOOT_SHA256=${var.first_boot_sha256}",
        "OZBOX_BUILD_SHA256=${var.build_sha256}",
        "/tmp/ozbox-disk-generation.sh",
        "disk-parts-${var.arch}.txt",
    ] {
        assert!(
            h.contains(needle),
            "the Packer template no longer contains {needle:?}"
        );
    }
}

/// Run the real `disk-generation.sh` over a fixture root and return its `key=value` lines.
fn generation(
    root: &std::path::Path,
    first_boot: &str,
) -> std::collections::BTreeMap<String, String> {
    generation_with(root, first_boot, &"b".repeat(64))
}

fn generation_with(
    root: &std::path::Path,
    first_boot: &str,
    build: &str,
) -> std::collections::BTreeMap<String, String> {
    let script = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../infra/packer/ozbox-image/scripts/disk-generation.sh");
    let out = std::process::Command::new("sh")
        .arg(script)
        .env("ROOT", root)
        .env("OZBOX_FIRST_BOOT_SHA256", first_boot)
        .env("OZBOX_BUILD_SHA256", build)
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    String::from_utf8(out.stdout)
        .unwrap()
        .lines()
        .filter_map(|l| l.split_once('='))
        .map(|(k, v)| (k.to_string(), v.to_string()))
        .collect()
}

/// One thing that changes in the fixture: the part it should move, the edit, the first boot and the build hash to use.
type Case<'a> = (&'a str, Box<dyn Fn(&std::path::Path)>, String, String);

fn put(root: &std::path::Path, rel: &str, text: &str) {
    let p = root.join(rel);
    std::fs::create_dir_all(p.parent().unwrap()).unwrap();
    std::fs::write(p, text).unwrap();
}

fn fixture_root() -> tempfile::TempDir {
    let d = tempfile::tempdir().unwrap();
    let w = |rel: &str, text: &str| put(d.path(), rel, text);
    w(
        "etc/ozbox/packages.txt",
        "linux-image-6.8.0-1-aws\t6.8.0-1\nopenssh-server\t1:9.6\ntmux\t3.4\n",
    );
    w(
        "etc/passwd",
        "root:x:0:0:root:/root:/bin/bash\nozbox:x:1500:1500:Oz:/work/home/ozbox:/bin/bash\n",
    );
    w("etc/group", "root:x:0:\nsudo:x:27:\nozbox:x:1500:\n");
    w(
        "etc/ssh/sshd_config.d/10-ozbox.conf",
        "PasswordAuthentication no\n",
    );
    w(
        "etc/systemd/system/ssh.socket.d/10-ozbox.conf",
        "[Socket]\nListenStream=127.0.0.1:22\n",
    );
    // what provision.sh writes outside the units, the accounts and sshd (ADR 0038, the config part)
    w(
        "etc/sysctl.d/10-ozbox-yama.conf",
        "kernel.yama.ptrace_scope = 1\n",
    );
    w(
        "etc/apt/sources.list.d/mozilla.sources",
        "Types: deb\nURIs: https://packages.mozilla.org/apt\n",
    );
    w("etc/apt/keyrings/mozilla.gpg", "key-bytes-1");
    w(
        "etc/apt/preferences.d/mozilla",
        "Pin: origin packages.mozilla.org\n",
    );
    w("etc/default/google-chrome", "repo_add_once=false\n");
    w(
        "etc/apt/apt.conf.d/20auto-upgrades",
        "APT::Periodic::Update-Package-Lists \"0\";\n",
    );
    w("var/lib/systemd/linger/ozbox", "");
    w("var/lib/snapd/snaps/amazon-ssm-agent_9876.snap", "snap");
    // what a machine makes or changes by itself
    w("etc/machine-id", "aaaa\n");
    w("etc/hostname", "ip-10-0-0-1\n");
    w("etc/ssh/ssh_host_ed25519_key", "host-key-1");
    w("etc/shadow", "root:$6$x::0:::::\n");
    w("etc/ozbox/image-release", "image_version=0.1.0\n");
    d
}

#[test]
fn the_disk_generation_is_stable_and_moves_with_each_thing_a_running_machine_cannot_change() {
    let fb = "f".repeat(64);
    let bd = "b".repeat(64);
    let base = fixture_root();
    let a = generation(base.path(), &fb);
    for k in [
        "kernel",
        "packages",
        "first_boot",
        "build",
        "units",
        "accounts",
        "sshd",
        "config",
        "disk_generation",
    ] {
        let v = &a[k];
        assert!(
            v.len() == 64
                && v.bytes()
                    .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase()),
            "{k}: {v}"
        );
    }
    assert_eq!(a["first_boot"], fb);
    assert_eq!(a["build"], bd);
    // the same tree and the same first boot give the same generation, however often it is asked
    assert_eq!(a, generation(base.path(), &fb));

    let changed = |edit: &dyn Fn(&std::path::Path), first_boot: &str, build: &str| {
        let d = fixture_root();
        edit(d.path());
        generation_with(d.path(), first_boot, build)
    };
    // every input moves the generation, and moves its own part
    let append = |rel: &'static str, text: &'static str| {
        move |root: &std::path::Path| {
            use std::io::Write;
            let p = root.join(rel);
            std::fs::create_dir_all(p.parent().unwrap()).unwrap();
            let mut f = std::fs::OpenOptions::new()
                .append(true)
                .create(true)
                .open(p)
                .unwrap();
            f.write_all(text.as_bytes()).unwrap();
        }
    };
    let replace =
        |rel: &'static str, text: &'static str| move |root: &std::path::Path| put(root, rel, text);
    let case = |part: &'static str, edit: Box<dyn Fn(&std::path::Path)>| -> Case<'static> {
        (part, edit, "f".repeat(64), "b".repeat(64))
    };
    let cases: Vec<Case> =
        vec![
        case(
            "kernel",
            Box::new(append(
                "etc/ozbox/packages.txt",
                "linux-image-6.8.0-2-aws\t6.8.0-2\n",
            )),
        ),
        case(
            "packages",
            Box::new(append("etc/ozbox/packages.txt", "git\t2.43\n")),
        ),
        case(
            "units",
            Box::new(append(
                "etc/systemd/system/ssh.socket.d/10-ozbox.conf",
                "x\n",
            )),
        ),
        // accounts: ids, group membership, home and shell all count (Z2)
        case(
            "accounts",
            Box::new(append("etc/passwd", "extra:x:1600:1600::/:/bin/false\n")),
        ),
        case(
            "accounts",
            Box::new(replace("etc/group", "root:x:0:\nsudo:x:27:ozbox\nozbox:x:1500:\n")),
        ),
        case(
            "accounts",
            Box::new(replace(
                "etc/passwd",
                "root:x:0:0:root:/root:/bin/sh\nozbox:x:1500:1500:Oz:/work/home/ozbox:/bin/bash\n",
            )),
        ),
        case(
            "accounts",
            Box::new(replace(
                "etc/passwd",
                "root:x:0:0:root:/root:/bin/bash\nozbox:x:1500:1500:Oz:/elsewhere:/bin/bash\n",
            )),
        ),
        case(
            "sshd",
            Box::new(append(
                "etc/ssh/sshd_config.d/10-ozbox.conf",
                "X11Forwarding no\n",
            )),
        ),
        // config: what provision.sh writes that no other part reads (Z2)
        case(
            "config",
            Box::new(replace(
                "etc/sysctl.d/10-ozbox-yama.conf",
                "kernel.yama.ptrace_scope = 0\n",
            )),
        ),
        case(
            "config",
            Box::new(append(
                "etc/apt/sources.list.d/mozilla.sources",
                "Suites: mozilla\n",
            )),
        ),
        case(
            "config",
            Box::new(replace("etc/apt/keyrings/mozilla.gpg", "key-bytes-2")),
        ),
        case(
            "config",
            Box::new(replace("etc/apt/preferences.d/mozilla", "Pin: origin elsewhere\n")),
        ),
        case(
            "config",
            Box::new(replace("etc/default/google-chrome", "repo_add_once=true\n")),
        ),
        case(
            "config",
            Box::new(replace(
                "etc/apt/apt.conf.d/20auto-upgrades",
                "APT::Periodic::Update-Package-Lists \"1\";\n",
            )),
        ),
        case(
            "config",
            Box::new(replace("etc/anything-else.conf", "new\n")),
        ),
        case(
            "config",
            Box::new(|root: &std::path::Path| {
                std::fs::remove_file(root.join("var/lib/systemd/linger/ozbox")).unwrap()
            }),
        ),
        case(
            "config",
            Box::new(replace("var/lib/snapd/snaps/amazon-ssm-agent_9999.snap", "snap")),
        ),
        (
            "first_boot",
            Box::new(|_| {}),
            "e".repeat(64),
            "b".repeat(64),
        ),
        ("build", Box::new(|_| {}), "f".repeat(64), "c".repeat(64)),
    ];
    for (part, edit, first_boot, build) in cases {
        let b = changed(&*edit, &first_boot, &build);
        assert_ne!(
            b["disk_generation"], a["disk_generation"],
            "{part} did not move the generation"
        );
        assert_ne!(b[part], a[part], "{part} did not move its own part");
    }
    // what a machine makes or changes by itself does not move it: its id and name, a host key, a user's password hash,
    // the image's own record
    let noise = |root: &std::path::Path| {
        put(root, "etc/machine-id", "bbbb\n");
        put(root, "etc/hostname", "ip-10-9-9-9\n");
        put(root, "etc/ssh/ssh_host_ed25519_key", "host-key-2");
        put(
            root,
            "etc/ozbox/image-release",
            "image_version=0.1.1\nx=y\n",
        );
        put(root, "etc/ozbox/disk-parts", "kernel=00\n");
        put(root, "etc/shadow", "root:$6$y::0:::::\n");
        put(
            root,
            "etc/netplan/50-cloud-init.yaml",
            "macaddress: aa:bb\n",
        );
    };
    assert_eq!(changed(&noise, &fb, &bd), a);
}

#[test]
fn the_disk_generation_script_refuses_a_missing_first_boot_or_package_map() {
    let script = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../infra/packer/ozbox-image/scripts/disk-generation.sh");
    let root = fixture_root();
    for bad in ["", "abc", &"F".repeat(64)] {
        let st = std::process::Command::new("sh")
            .arg(&script)
            .env("ROOT", root.path())
            .env("OZBOX_FIRST_BOOT_SHA256", bad)
            .env("OZBOX_BUILD_SHA256", "b".repeat(64))
            .output()
            .unwrap();
        assert!(!st.status.success(), "{bad:?} was accepted");
    }
    let empty = tempfile::tempdir().unwrap();
    let st = std::process::Command::new("sh")
        .arg(&script)
        .env("ROOT", empty.path())
        .env("OZBOX_FIRST_BOOT_SHA256", "a".repeat(64))
        .env("OZBOX_BUILD_SHA256", "b".repeat(64))
        .output()
        .unwrap();
    assert!(!st.status.success());
    // a missing or malformed build hash is refused as well
    for bad in ["", "abc", &"F".repeat(64)] {
        let st = std::process::Command::new("sh")
            .arg(&script)
            .env("ROOT", root.path())
            .env("OZBOX_FIRST_BOOT_SHA256", "a".repeat(64))
            .env("OZBOX_BUILD_SHA256", bad)
            .output()
            .unwrap();
        assert!(!st.status.success(), "build {bad:?} was accepted");
    }
}

// ---- ADR 0038, rules that hold before any release turns live updates on ----

/// The build hash of a copy of the recipe folder.
fn build_hash(dir: &std::path::Path) -> String {
    let script =
        std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../scripts/packer-build-hash.sh");
    let out = std::process::Command::new("sh")
        .arg(script)
        .arg(dir)
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    String::from_utf8(out.stdout).unwrap().trim().to_string()
}

#[test]
fn the_build_hash_moves_with_the_image_recipe_and_not_with_its_outputs() {
    let d = tempfile::tempdir().unwrap();
    put(d.path(), "ozbox-image.pkr.hcl", "source x {}\n");
    put(d.path(), "scripts/provision.sh", "echo one\n");
    put(d.path(), "scripts/disk-generation.sh", "echo gen\n");
    let a = build_hash(d.path());
    assert_eq!(a.len(), 64);
    assert_eq!(a, build_hash(d.path()));
    // a change to the template or to any script in it is a different recipe (Z2: provision.sh and the template were
    // outside every part)
    put(d.path(), "scripts/provision.sh", "echo two\n");
    let b = build_hash(d.path());
    assert_ne!(a, b);
    put(d.path(), "ozbox-image.pkr.hcl", "source y {}\n");
    assert_ne!(b, build_hash(d.path()));
    // a new file in the folder is a change too
    let c = build_hash(d.path());
    put(d.path(), "scripts/new.sh", "echo new\n");
    assert_ne!(c, build_hash(d.path()));
    // the outputs of a build and the two files only the release workflow reads are not the recipe
    let e = build_hash(d.path());
    put(d.path(), "agent/ozboxd-linux-amd64", "binary");
    put(d.path(), "packer-manifest-amd64.json", "{}");
    put(d.path(), "packages-amd64.txt", "x\t1\n");
    put(d.path(), "dpkg-status-amd64", "x");
    put(d.path(), "disk-parts-amd64.txt", "x=y\n");
    put(d.path(), "upgrade-policy.json", "{}");
    put(d.path(), "upgrade-record.jq", ".");
    assert_eq!(e, build_hash(d.path()));
}

fn have_jq() -> bool {
    let found = std::process::Command::new("jq")
        .arg("--version")
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false);
    if !found {
        // A skipped test must never read as a pass. CI always has jq, and a CI run without it is a failure.
        assert!(
            std::env::var_os("CI").is_none(),
            "jq is not installed, and this test runs the release workflow's jq"
        );
        eprintln!(
            "SKIPPED: jq is not installed on this machine, so the release record's jq was NOT run"
        );
    }
    found
}

fn run_jq(args: &[&str], file: &str) -> String {
    let jq = std::process::Command::new("jq")
        .args(args)
        .arg("-f")
        .arg(
            std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
                .join("../..")
                .join(file),
        )
        .output()
        .unwrap();
    assert!(
        jq.status.success(),
        "{}",
        String::from_utf8_lossy(&jq.stderr)
    );
    String::from_utf8(jq.stdout).unwrap()
}

/// The record the release job writes, from part files and a policy file, by the same jq file the workflow runs.
fn upgrade_record_for(policy: &str) -> serde_json::Value {
    let d = tempfile::tempdir().unwrap();
    let h = |c: char| c.to_string().repeat(64);
    let part = |arch: &str, c: char| {
        serde_json::json!({
            "arch": arch,
            "disk": {
                "kernel": h(c), "packages": h(c), "first_boot": h('f'), "build": h('b'),
                "units": h(c), "accounts": h(c), "sshd": h(c), "config": h(c), "disk_generation": h(c),
            }
        })
    };
    // the workflow slurps `cat part-*.json`: two objects, one per architecture
    let parts = format!("{}\n{}\n", part("amd64", 'a'), part("arm64", 'c'));
    std::fs::write(d.path().join("parts.json"), parts).unwrap();
    std::fs::write(d.path().join("policy.json"), policy).unwrap();
    let out = run_jq(
        &[
            "-n",
            "--arg",
            "first_boot",
            &h('f'),
            "--arg",
            "build",
            &h('b'),
            "--slurpfile",
            "policy",
            d.path().join("policy.json").to_str().unwrap(),
            "--slurpfile",
            "parts",
            d.path().join("parts.json").to_str().unwrap(),
        ],
        "infra/packer/ozbox-image/upgrade-record.jq",
    );
    serde_json::from_str(&out).unwrap()
}

/// Z5: the tracked policy file cannot override the computed generation or switch live updates on in the signed record.
#[test]
fn a_policy_file_cannot_inject_live_from_or_override_the_disk_generation() {
    if !have_jq() {
        return;
    }
    let h = |c: char| c.to_string().repeat(64);
    // the real, tracked policy file
    let real = upgrade_record_for(&repo_file("infra/packer/ozbox-image/upgrade-policy.json"));
    let hostile = upgrade_record_for(
        r#"{"work_format": 1, "work_format_reads": [1], "secrets_keys": ["file", "kms"],
            "disk_generation": {"amd64": "0000000000000000000000000000000000000000000000000000000000000000"},
            "disk_parts": {"first_boot": "x"},
            "live_from": "0.0.1", "upgrade": {"live_from": "0.0.1"}, "anything": true}"#,
    );
    // the hostile keys changed nothing: the record is the one the real policy gives
    assert_eq!(hostile, real);
    let keys =
        |v: &serde_json::Value| -> Vec<String> { v.as_object().unwrap().keys().cloned().collect() };
    assert_eq!(
        keys(&hostile),
        [
            "disk_generation",
            "disk_parts",
            "secrets_keys",
            "work_format",
            "work_format_reads"
        ]
    );
    // the tracked policy says this release's secrets service opens a store on the fleet's KMS key by itself
    assert_eq!(hostile["secrets_keys"], serde_json::json!(["file", "kms"]));
    assert!(hostile.get("live_from").is_none());
    assert_eq!(hostile["disk_generation"]["amd64"], h('a'));
    assert_eq!(hostile["disk_generation"]["arm64"], h('c'));
    assert_eq!(hostile["disk_parts"]["first_boot"], h('f'));
    assert_eq!(hostile["disk_parts"]["build"], h('b'));
    assert_eq!(
        keys(&hostile["disk_parts"]),
        [
            "accounts",
            "build",
            "config",
            "first_boot",
            "kernel",
            "packages",
            "sshd",
            "units"
        ]
    );
    // the verifier reads it as a record with no live update on offer
    let manifest = serde_json::json!({"upgrade": hostile}).to_string();
    match ozbox_core::upgrade_kind::upgrade_record(&manifest, Some("amd64")) {
        ozbox_core::UpgradeRecord::Present(b) => {
            assert_eq!(b.disk_generation, h('a'));
            assert!(b.live_from.is_none());
        }
        other => panic!("{other:?}"),
    }
    // and the test can fail: the whole-file merge this replaced DOES let that policy file in
    let d = tempfile::tempdir().unwrap();
    std::fs::write(
        d.path().join("old.jq"),
        r#"{disk_generation: {amd64: "a"}} + $policy[0]"#,
    )
    .unwrap();
    std::fs::write(
        d.path().join("policy.json"),
        r#"{"live_from":"0.0.1","disk_generation":{"amd64":"0"}}"#,
    )
    .unwrap();
    let old = std::process::Command::new("jq")
        .args(["-n", "--slurpfile", "policy"])
        .arg(d.path().join("policy.json"))
        .arg("-f")
        .arg(d.path().join("old.jq"))
        .output()
        .unwrap();
    let old: serde_json::Value = serde_json::from_slice(&old.stdout).unwrap();
    assert_eq!(old["live_from"], "0.0.1");
    assert_eq!(old["disk_generation"]["amd64"], "0");
}

/// The rules in ADR 0038 ("Rules that hold before any release turns live updates on", Z2 and Z4) are not met yet, so
/// nothing may write `live_from`. This fails the day a workflow, a script or the policy starts to; whoever does that
/// must first make the rules true, delete this test in the same change, and say so in the ADR.
#[test]
fn nothing_writes_live_from_until_the_adr_rules_hold() {
    let code_only = |text: &str| -> String {
        text.lines()
            .filter(|l| !l.trim_start().starts_with('#'))
            .collect::<Vec<_>>()
            .join("\n")
    };
    for rel in [
        ".github/workflows/image.yml",
        "infra/packer/ozbox-image/upgrade-record.jq",
        "infra/packer/ozbox-image/upgrade-policy.json",
        "infra/packer/ozbox-image/scripts/provision.sh",
        "infra/packer/ozbox-image/scripts/disk-generation.sh",
        "infra/packer/ozbox-image/ozbox-image.pkr.hcl",
        "scripts/packer-build-hash.sh",
    ] {
        let text = repo_file(rel);
        assert!(!text.is_empty(), "{rel} was not found");
        // the needle is built so this file never contains it as one string
        let needle = format!("live{}from", "_");
        assert!(
            !code_only(&text).contains(&needle),
            "{rel} writes {needle}: ADR 0038's rules (the disk generation's reach, and a decision that reads the box's applied release and its disk from the provider with a first-boot check) are not met yet"
        );
    }
    let policy: serde_json::Value =
        serde_json::from_str(&repo_file("infra/packer/ozbox-image/upgrade-policy.json")).unwrap();
    let mut keys: Vec<_> = policy.as_object().unwrap().keys().cloned().collect();
    keys.sort();
    // the `/work` format, and the store keys the release's secrets service opens (ADR 0029 Amendment 17); never live_from
    assert_eq!(keys, ["secrets_keys", "work_format", "work_format_reads"]);
    // the rules are written down where the next person looks
    let adr =
        repo_file("docs/adr/0038-upgrades-keep-the-box-up-live-update-or-blue-green-replace.md");
    for needle in [
        "Rules that hold before any release turns live updates on",
        "The disk generation covers everything a running machine cannot change",
        "applied release",
    ] {
        assert!(adr.contains(needle), "ADR 0038 no longer says {needle:?}");
    }
}

#[test]
fn only_a_manifest_for_this_release_that_lacks_the_image_is_a_final_answer() {
    use ozbox_core::release::{manifest_listing, manifest_prerelease, Listing};
    let m = r#"{"version":"0.2.0","images":[{"arch":"amd64","amis":{"us-east-1":"ami-1"}}]}"#;
    assert_eq!(
        manifest_listing(m, "0.2.0", "us-east-1", "ami-1"),
        Listing::Listed
    );
    assert!(matches!(
        manifest_listing(m, "0.2.0", "us-east-1", "ami-2"),
        Listing::NotListed(_)
    ));
    assert!(matches!(
        manifest_listing(m, "0.2.0", "eu-west-1", "ami-1"),
        Listing::NotListed(_)
    ));
    // another release's manifest, an unreadable one, or one naming no release says nothing about the image
    assert!(matches!(
        manifest_listing(m, "0.3.0", "us-east-1", "ami-1"),
        Listing::Unusable(_)
    ));
    assert!(matches!(
        manifest_listing("not json", "0.2.0", "us-east-1", "ami-1"),
        Listing::Unusable(_)
    ));
    assert!(matches!(
        manifest_listing("{}", "0.2.0", "us-east-1", "ami-1"),
        Listing::Unusable(_)
    ));
    // the signed field, else the signed version
    assert_eq!(
        manifest_prerelease(r#"{"version":"0.2.0","prerelease":true}"#),
        Some(true)
    );
    // a field that says stable cannot make a -beta version one
    assert_eq!(
        manifest_prerelease(r#"{"version":"0.2.0-beta.0","prerelease":false}"#),
        Some(true)
    );
    assert_eq!(
        manifest_prerelease(r#"{"version":"0.2.0","prerelease":false}"#),
        Some(false)
    );
    assert_eq!(
        manifest_prerelease(r#"{"version":"0.2.0-beta.0"}"#),
        Some(true)
    );
    assert_eq!(manifest_prerelease(r#"{"version":"0.2.0"}"#), Some(false));
    assert_eq!(manifest_prerelease("{}"), None);
}
