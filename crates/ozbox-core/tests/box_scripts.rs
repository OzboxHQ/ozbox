//! The helper scripts first-boot configuration puts on every box (`infra/cloud-init/scripts/`), run for real in a
//! temporary directory with their commands replaced by recorders, plus what the template, the image build and the image
//! workflow must say about them. Nothing here needs root, a network or a cloud.
#![cfg(unix)]
#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

type R = Result<(), Box<dyn std::error::Error>>;

fn root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../..")
}

fn read(rel: &str) -> String {
    fs::read_to_string(root().join(rel)).unwrap_or_default()
}

fn script(name: &str) -> PathBuf {
    root().join("infra/cloud-init/scripts").join(name)
}

fn sh(path: &Path, args: &[&str], env: &[(&str, &str)]) -> std::io::Result<Output> {
    let mut c = Command::new("bash");
    c.arg(path).args(args).env_remove("BASH_ENV");
    for (k, v) in env {
        c.env(k, v);
    }
    c.output()
}

fn text(o: &Output) -> String {
    format!(
        "{}{}",
        String::from_utf8_lossy(&o.stdout),
        String::from_utf8_lossy(&o.stderr)
    )
}

/// The part of a stand-in for `ozbox` that answers `host-guard take-file` the way the program does for a plain file (the
/// program's own tests cover links, owners and sizes): the first line, then the file is gone.
const TAKE_FILE: &str = "if [ \"$1 $2\" = 'host-guard take-file' ]; then f=\"$4/$6.tok\"; if [ -f \"$f\" ] && [ ! -L \"$f\" ]; then head -n 1 \"$f\"; rm -f \"$f\"; exit 0; fi; rm -f \"$f\"; exit 1; fi\n";

/// An executable stub that appends its arguments to a log file.
fn recorder(dir: &Path, name: &str) -> PathBuf {
    let p = dir.join(name);
    fs::write(
        &p,
        format!(
            "#!/bin/sh\necho \"$@\" >> '{}'\n",
            dir.join(format!("{name}.log")).display()
        ),
    )
    .unwrap();
    fs::set_permissions(&p, fs::Permissions::from_mode(0o755)).unwrap();
    p
}

fn log(dir: &Path, name: &str) -> String {
    fs::read_to_string(dir.join(format!("{name}.log"))).unwrap_or_default()
}

fn my_gids() -> Vec<String> {
    let o = Command::new("id").arg("-G").output().unwrap();
    String::from_utf8_lossy(&o.stdout)
        .split_whitespace()
        .map(str::to_string)
        .collect()
}

// ---------------------------------------------------------------- re-own

struct Reown {
    dir: tempfile::TempDir,
}

impl Reown {
    fn new() -> Self {
        let dir = tempfile::tempdir().unwrap();
        for d in ["home/sub", "repos/a"] {
            fs::create_dir_all(dir.path().join(d)).unwrap();
        }
        for f in ["home/.profile", "home/sub/config.yml", "repos/a/file"] {
            fs::write(dir.path().join(f), "x").unwrap();
        }
        recorder(dir.path(), "chown");
        recorder(dir.path(), "chgrp");
        Reown { dir }
    }

    fn run(&self, args: &[&str]) -> Output {
        self.run_with(args, "1", "")
    }

    /// With the floor `min_id`, and `services` (lines `name:uid`) as the accounts `getent` knows.
    fn run_with(&self, args: &[&str], min_id: &str, services: &str) -> Output {
        let d = self.dir.path();
        let roots = format!("{} {}", d.join("home").display(), d.join("repos").display());
        // a stand-in for getent: the same name and id in the passwd and the group database
        let mut lines = String::new();
        for l in services.split_whitespace() {
            let (n, id) = l.split_once(':').unwrap();
            lines.push_str(&format!(
                "{n}:x:{id}:{id}::/nonexistent:/usr/sbin/nologin\n"
            ));
        }
        fs::write(d.join("getent.db"), lines).unwrap();
        fs::write(
            d.join("getent"),
            format!("#!/bin/sh\ncat '{}'\n", d.join("getent.db").display()),
        )
        .unwrap();
        fs::set_permissions(d.join("getent"), fs::Permissions::from_mode(0o755)).unwrap();
        sh(
            &script("ozbox-reown.sh"),
            args,
            &[
                // the files in the fixture belong to the account running the test: that is "the old box user"
                ("OZBOX_BOX_UID", "1500"),
                ("OZBOX_BOX_GID", "1500"),
                ("OZBOX_MIN_ID", min_id),
                ("OZBOX_CHOWN", &d.join("chown").to_string_lossy()),
                ("OZBOX_CHGRP", &d.join("chgrp").to_string_lossy()),
                ("OZBOX_GETENT", &d.join("getent").to_string_lossy()),
                (
                    "OZBOX_REOWN_MARKER",
                    &d.join("work-marker").to_string_lossy(),
                ),
                ("OZBOX_REOWN_ROOTS", &roots),
            ],
        )
        .unwrap()
    }
}

fn my_id(flag: &str) -> String {
    String::from_utf8_lossy(&Command::new("id").arg(flag).output().unwrap().stdout)
        .trim()
        .to_string()
}

#[test]
fn an_old_id_given_in_a_request_obeys_the_floor_and_is_never_one_of_the_boxs_own_accounts() -> R {
    // the box user files these requests, and the box user may be an agent: a restored secrets store must never become its
    let t = Reown::new();
    for (args, floor) in [
        (&["--force", "--from-uid", "999"][..], "1000"),
        (&["--force", "--from-gid", "100"][..], "1000"),
        (&["--force", "--from-uid", "65534"][..], "1"),
    ] {
        let o = t.run_with(args, floor, "");
        assert_eq!(o.status.code(), Some(2), "{args:?}: {}", text(&o));
        assert!(text(&o).contains("system"), "{}", text(&o));
    }
    let services =
        "ozbox-secrets:4300 ozbox-supervisor:4301 ozbox-meta:4302 ozbox-run-web:4303 someone:4304";
    for id in ["4300", "4301", "4302", "4303"] {
        for flag in ["--from-uid", "--from-gid"] {
            let o = t.run_with(&["--force", flag, id], "1", services);
            assert_eq!(o.status.code(), Some(2), "{flag} {id}: {}", text(&o));
            assert!(text(&o).contains("service accounts"), "{}", text(&o));
        }
    }
    assert_eq!(log(t.dir.path(), "chown"), "");
    assert_eq!(log(t.dir.path(), "chgrp"), "");
    // an ordinary old account is still moved
    assert!(t
        .run_with(&["--force", "--from-uid", "4304"], "1", services)
        .status
        .success());
    // and when the box's own service account is what owns the files, nothing is picked on its own either
    let t2 = Reown::new();
    let mine = format!(
        "ozbox-secrets:{} ozbox-run-web:{}",
        my_id("-u"),
        my_id("-g")
    );
    let o = t2.run_with(&[], "1", &mine);
    assert!(o.status.success(), "{}", text(&o));
    assert_eq!(log(t2.dir.path(), "chown"), "");
    assert_eq!(log(t2.dir.path(), "chgrp"), "");
    Ok(())
}

#[test]
fn files_with_the_old_ids_are_moved_to_the_box_user_by_numeric_id_and_the_marker_says_so() -> R {
    let t = Reown::new();
    let o = t.run(&[]);
    assert!(o.status.success(), "{}", text(&o));
    let chown = log(t.dir.path(), "chown");
    // changed, not followed (-h), onto the box user, and every file of both trees was named to chown
    assert!(chown.starts_with("-h 1500 "), "{chown}");
    for f in ["home/sub/config.yml", "home/.profile", "repos/a/file"] {
        assert!(
            chown.contains(&t.dir.path().join(f).to_string_lossy().to_string()),
            "{f} missing from {chown}"
        );
    }
    assert!(log(t.dir.path(), "chgrp").starts_with("-h 1500 "));
    let marker = fs::read_to_string(t.dir.path().join("work-marker"))?;
    assert!(marker.starts_with("1500 1500 migrated "), "{marker}");
    // counts, never names
    let said = text(&o);
    assert!(said.contains("re-owned"), "{said}");
    assert!(!said.contains("config.yml") && !said.contains(&*t.dir.path().to_string_lossy()));
    Ok(())
}

#[test]
fn it_runs_once_per_disk() -> R {
    let t = Reown::new();
    assert!(t.run(&[]).status.success());
    let before = log(t.dir.path(), "chown");
    let again = t.run(&[]);
    assert!(again.status.success());
    assert!(text(&again).contains("already done"), "{}", text(&again));
    assert_eq!(
        log(t.dir.path(), "chown"),
        before,
        "nothing ran a second time"
    );
    // --force (the admin action) does run again
    assert!(t.run(&["--force"]).status.success());
    assert_ne!(log(t.dir.path(), "chown"), before);
    Ok(())
}

#[test]
fn files_that_already_belong_to_the_box_user_or_to_root_are_never_selected() -> R {
    let t = Reown::new();
    // pretend the box user IS the account that owns the fixture: nothing is foreign
    let uid = String::from_utf8_lossy(&Command::new("id").arg("-u").output()?.stdout)
        .trim()
        .to_string();
    let gid = String::from_utf8_lossy(&Command::new("id").arg("-g").output()?.stdout)
        .trim()
        .to_string();
    let d = t.dir.path();
    let roots = format!("{} {}", d.join("home").display(), d.join("repos").display());
    let o = sh(
        &script("ozbox-reown.sh"),
        &[],
        &[
            ("OZBOX_BOX_UID", &uid),
            ("OZBOX_BOX_GID", &gid),
            ("OZBOX_MIN_ID", "1"),
            ("OZBOX_CHOWN", &d.join("chown").to_string_lossy()),
            ("OZBOX_CHGRP", &d.join("chgrp").to_string_lossy()),
            (
                "OZBOX_REOWN_MARKER",
                &d.join("work-marker").to_string_lossy(),
            ),
            ("OZBOX_REOWN_ROOTS", &roots),
        ],
    )?;
    assert!(o.status.success(), "{}", text(&o));
    assert_eq!(log(d, "chown"), "");
    assert_eq!(log(d, "chgrp"), "");
    // an explicit old id nobody carries changes nothing either
    let t2 = Reown::new();
    let o = t2.run(&["--from-uid", "4242", "--from-gid", "4243"]);
    assert!(o.status.success(), "{}", text(&o));
    assert_eq!(log(t2.dir.path(), "chown"), "");
    // and root is refused as an "old" id outright
    let o = t2.run(&["--force", "--from-uid", "0"]);
    assert!(!o.status.success());
    Ok(())
}

#[test]
fn system_ids_are_never_treated_as_an_old_box_user() -> R {
    let t = Reown::new();
    let d = t.dir.path();
    let roots = format!("{} {}", d.join("home").display(), d.join("repos").display());
    // with the real floor (1000), an account below it is a system account: left alone
    let uid: u32 = String::from_utf8_lossy(&Command::new("id").arg("-u").output()?.stdout)
        .trim()
        .parse()?;
    if uid >= 1000 {
        return Ok(()); // a login account (mac, CI): the floor would select the fixture; the next test covers the floor
    }
    let o = sh(
        &script("ozbox-reown.sh"),
        &[],
        &[
            ("OZBOX_BOX_UID", "1500"),
            ("OZBOX_BOX_GID", "1500"),
            ("OZBOX_CHOWN", &d.join("chown").to_string_lossy()),
            ("OZBOX_CHGRP", &d.join("chgrp").to_string_lossy()),
            (
                "OZBOX_REOWN_MARKER",
                &d.join("work-marker").to_string_lossy(),
            ),
            ("OZBOX_REOWN_ROOTS", &roots),
        ],
    )?;
    assert!(o.status.success(), "{}", text(&o));
    assert_eq!(log(d, "chown"), "");
    Ok(())
}

#[test]
fn two_different_old_groups_stop_it_and_name_the_way_forward() -> R {
    let gids = my_gids();
    let primary = String::from_utf8_lossy(&Command::new("id").arg("-g").output()?.stdout)
        .trim()
        .to_string();
    let Some(other) = gids.iter().find(|g| **g != primary) else {
        return Ok(()); // an account in one group only cannot make a second group's file
    };
    let t = Reown::new();
    let status = Command::new("chgrp")
        .arg(other)
        .arg(t.dir.path().join("repos/a/file"))
        .status()?;
    if !status.success() {
        return Ok(());
    }
    let o = t.run(&[]);
    assert_eq!(o.status.code(), Some(3), "{}", text(&o));
    assert!(text(&o).contains("--from-"), "{}", text(&o));
    assert!(!t.dir.path().join("work-marker").exists());
    assert_eq!(
        log(t.dir.path(), "chown"),
        "",
        "nothing is changed when it cannot tell"
    );
    Ok(())
}

// ------------------------------------------------------- agent install

struct Agent {
    dir: tempfile::TempDir,
}

impl Agent {
    /// A release directory with a manifest and an ozboxd for this machine's architecture, and a curl that serves it.
    fn new(manifest_sha_override: Option<&str>) -> Self {
        let dir = tempfile::tempdir().unwrap();
        let rel = dir.path().join("release");
        fs::create_dir_all(&rel).unwrap();
        let binary = b"#!/bin/sh\necho ozboxd\n";
        let asset = rel.join("ozboxd-linux-amd64");
        fs::write(&asset, binary).unwrap();
        let arm = rel.join("ozboxd-linux-arm64");
        fs::write(&arm, binary).unwrap();
        let sha = {
            let o = Command::new("shasum")
                .args(["-a", "256"])
                .arg(&asset)
                .output()
                .or_else(|_| Command::new("sha256sum").arg(&asset).output())
                .unwrap();
            String::from_utf8_lossy(&o.stdout)
                .split_whitespace()
                .next()
                .unwrap_or("")
                .to_string()
        };
        let listed = manifest_sha_override.unwrap_or(&sha);
        // the ozbox program: its own bytes, its own hash, listed under its own key (never confused with ozboxd's)
        let cli_bytes = b"#!/bin/sh\necho ozbox\n";
        for a in ["amd64", "arm64"] {
            fs::write(rel.join(format!("ozbox-linux-{a}")), cli_bytes).unwrap();
        }
        let cli_sha = {
            let o = Command::new("shasum")
                .args(["-a", "256"])
                .arg(rel.join("ozbox-linux-amd64"))
                .output()
                .or_else(|_| {
                    Command::new("sha256sum")
                        .arg(rel.join("ozbox-linux-amd64"))
                        .output()
                })
                .unwrap();
            String::from_utf8_lossy(&o.stdout)
                .split_whitespace()
                .next()
                .unwrap_or("")
                .to_string()
        };
        fs::write(
            rel.join("ozbox-image-manifest.json"),
            format!(
                "{{\n  \"version\": \"2026.11.09\",\n  \"ozbox\": {{\n    \"amd64\": \"{cli_sha}\",\n    \"arm64\": \"{cli_sha}\"\n  }},\n  \"ozboxd\": {{\n    \"amd64\": \"{listed}\",\n    \"arm64\": \"{listed}\"\n  }}\n}}\n"
            ),
        )
        .unwrap();
        // curl stand-in: --output FILE URL, served from the release directory by the last path segment
        let curl = dir.path().join("curl");
        fs::write(
            &curl,
            format!(
                "#!/bin/sh\nout=''\nurl=''\nwhile [ $# -gt 0 ]; do case \"$1\" in --output) out=\"$2\"; shift;; --*) ;; *) url=\"$1\";; esac; shift; done\nf='{}'/$(basename \"$url\")\n[ -f \"$f\" ] || exit 22\ncp \"$f\" \"$out\"\n",
                rel.display()
            ),
        )
        .unwrap();
        fs::set_permissions(&curl, fs::Permissions::from_mode(0o755)).unwrap();
        fs::write(
            dir.path().join("agent.env"),
            "OZBOX_RELEASE_REPO=\"example-org/example-repo\"\nOZBOX_RELEASE_TAG=\"image-v2026.11.09\"\n",
        )
        .unwrap();
        Agent { dir }
    }

    fn run(&self, args: &[&str], with_marker: bool) -> Output {
        let d = self.dir.path();
        let marker = d.join("image-release");
        if with_marker {
            fs::write(&marker, "image_version=2026.11.09\n").unwrap();
        }
        sh(
            &script("ozbox-install-agent.sh"),
            args,
            &[
                ("OZBOX_AGENT_DEST", &d.join("bin/ozboxd").to_string_lossy()),
                ("OZBOX_AGENT_CONF", &d.join("agent.env").to_string_lossy()),
                ("OZBOX_IMAGE_MARKER", &marker.to_string_lossy()),
                ("OZBOX_CURL", &d.join("curl").to_string_lossy()),
                ("PATH", "/usr/bin:/bin:/usr/sbin:/sbin"),
            ],
        )
        .unwrap()
    }

    fn installed(&self) -> bool {
        self.dir.path().join("bin/ozboxd").exists()
    }
}

#[test]
fn a_stock_machine_installs_ozboxd_only_when_the_download_matches_the_manifest() -> R {
    let a = Agent::new(None);
    let o = a.run(&[], false);
    assert!(o.status.success(), "{}", text(&o));
    assert!(a.installed());
    let mode = fs::metadata(a.dir.path().join("bin/ozboxd"))?
        .permissions()
        .mode();
    assert_eq!(mode & 0o777, 0o755);
    Ok(())
}

#[test]
fn the_ozbox_program_is_installed_root_style_beside_the_daemon_and_only_if_its_own_hash_matches(
) -> R {
    let a = Agent::new(None);
    let o = a.run(&[], false);
    assert!(o.status.success(), "{}", text(&o));
    let cli = a.dir.path().join("bin/ozbox");
    assert!(cli.exists(), "{}", text(&o));
    assert_eq!(fs::metadata(&cli)?.permissions().mode() & 0o777, 0o755);
    assert_eq!(fs::read(&cli)?, b"#!/bin/sh\necho ozbox\n");
    // a tampered program: neither file is installed, and the message names the program
    let b = Agent::new(None);
    let m = b.dir.path().join("release/ozbox-image-manifest.json");
    let wrong = fs::read_to_string(&m)?;
    let wrong = {
        let key = "\"ozbox\": {\n    \"amd64\": \"";
        let at = wrong.find(key).unwrap() + key.len();
        format!("{}{}{}", &wrong[..at], "f".repeat(64), &wrong[at + 64..])
    };
    fs::write(&m, wrong)?;
    let o = b.run(&[], false);
    assert!(!o.status.success(), "{}", text(&o));
    assert!(
        text(&o).contains("downloaded ozbox does not match"),
        "{}",
        text(&o)
    );
    assert!(!b.installed() && !b.dir.path().join("bin/ozbox").exists());
    // an older manifest without the key installs the daemon only
    let c = Agent::new(None);
    let m = c.dir.path().join("release/ozbox-image-manifest.json");
    let old = fs::read_to_string(&m)?;
    let start = old.find("  \"ozbox\"").unwrap();
    let end = old.find("  \"ozboxd\"").unwrap();
    fs::write(&m, format!("{}{}", &old[..start], &old[end..]))?;
    let o = c.run(&[], false);
    assert!(o.status.success(), "{}", text(&o));
    assert!(c.installed() && !c.dir.path().join("bin/ozbox").exists());
    // a hash given for the daemon alone never installs the program
    let d = Agent::new(None);
    let manifest = fs::read_to_string(d.dir.path().join("release/ozbox-image-manifest.json"))?;
    let daemon_sha = manifest
        .split("\"ozboxd\"")
        .nth(1)
        .unwrap()
        .split('"')
        .nth(3)
        .unwrap();
    let o = d.run(&["--force", "--sha256", daemon_sha], false);
    assert!(o.status.success(), "{}", text(&o));
    assert!(d.installed() && !d.dir.path().join("bin/ozbox").exists());
    Ok(())
}

#[test]
fn a_download_that_does_not_match_is_refused_and_nothing_is_installed() -> R {
    let a = Agent::new(Some(&"0".repeat(64)));
    let o = a.run(&[], false);
    assert!(!o.status.success(), "{}", text(&o));
    assert!(text(&o).contains("does not match"), "{}", text(&o));
    assert!(!a.installed());
    // a manifest with no ozboxd for the machine is refused too
    let b = Agent::new(None);
    fs::write(
        b.dir.path().join("release/ozbox-image-manifest.json"),
        "{\"version\":\"x\"}",
    )?;
    let o = b.run(&[], false);
    assert!(!o.status.success());
    assert!(text(&o).contains("lists no ozboxd"), "{}", text(&o));
    assert!(!b.installed());
    Ok(())
}

#[test]
fn it_never_runs_on_the_oz_image_unless_forced() -> R {
    let a = Agent::new(None);
    let o = a.run(&[], true);
    assert!(o.status.success(), "{}", text(&o));
    assert!(text(&o).contains("Oz image"), "{}", text(&o));
    assert!(!a.installed());
    // the admin action forces it (an image whose agent went missing)
    let o = a.run(&["--force"], true);
    assert!(o.status.success(), "{}", text(&o));
    assert!(a.installed());
    Ok(())
}

#[test]
fn a_hash_given_by_the_caller_must_still_match_the_download() -> R {
    let a = Agent::new(None);
    let o = a.run(&["--force", "--sha256", &"1".repeat(64)], false);
    assert!(!o.status.success(), "{}", text(&o));
    assert!(!a.installed());
    let o = a.run(&["--force", "--sha256", "not-a-hash"], false);
    assert!(!o.status.success());
    assert!(!a.installed());
    Ok(())
}

#[test]
fn a_release_repository_or_tag_that_is_not_plain_is_refused() -> R {
    let a = Agent::new(None);
    fs::write(
        a.dir.path().join("agent.env"),
        "OZBOX_RELEASE_REPO=\"x/y;touch-pwned\"\nOZBOX_RELEASE_TAG=\"\"\n",
    )?;
    assert!(!a.run(&[], false).status.success());
    fs::write(
        a.dir.path().join("agent.env"),
        "OZBOX_RELEASE_REPO=\"x/y\"\nOZBOX_RELEASE_TAG=\"v1; id\"\n",
    )?;
    assert!(!a.run(&[], false).status.success());
    assert!(!a.installed());
    Ok(())
}

// ------------------------------------------------------------- admin

struct Admin {
    dir: tempfile::TempDir,
}

impl Admin {
    fn new() -> Self {
        let dir = tempfile::tempdir().unwrap();
        fs::create_dir_all(dir.path().join("run/requests")).unwrap();
        for n in [
            "reown",
            "install",
            "systemctl",
            "journalctl",
            "loginctl",
            "runuser",
            "user-manager",
        ] {
            recorder(dir.path(), n);
        }
        Admin { dir }
    }

    fn request(&self, id: &str, line: &str) {
        fs::write(
            self.dir.path().join(format!("run/requests/{id}.req")),
            format!("{line}\n"),
        )
        .unwrap();
    }

    fn process(&self, requester_uid: &str) -> Output {
        let d = self.dir.path();
        let me = String::from_utf8_lossy(&Command::new("id").arg("-u").output().unwrap().stdout)
            .trim()
            .to_string();
        let _ = requester_uid;
        sh(
            &script("ozbox-admin.sh"),
            &[],
            &[
                ("OZBOX_ADMIN_DIR", &d.join("run").to_string_lossy()),
                ("OZBOX_ADMIN_LOG", &d.join("audit.log").to_string_lossy()),
                ("OZBOX_REOWN", &d.join("reown").to_string_lossy()),
                ("OZBOX_INSTALL_AGENT", &d.join("install").to_string_lossy()),
                ("OZBOX_SYSTEMCTL", &d.join("systemctl").to_string_lossy()),
                ("OZBOX_JOURNALCTL", &d.join("journalctl").to_string_lossy()),
                ("OZBOX_LOGINCTL", &d.join("loginctl").to_string_lossy()),
                (
                    "OZBOX_USER_MANAGER",
                    &d.join("user-manager").to_string_lossy(),
                ),
                ("OZBOX_BIN", &d.join("ozbox").to_string_lossy()),
                ("OZBOX_USERADD", &d.join("useradd").to_string_lossy()),
                ("OZBOX_INSTALL", &d.join("install").to_string_lossy()),
                ("OZBOX_ID", &d.join("id").to_string_lossy()),
                ("OZBOX_GPASSWD", &d.join("gpasswd").to_string_lossy()),
                ("OZBOX_BOX_HOME", &d.join("home").to_string_lossy()),
                ("OZBOX_SHRED", &d.join("shred").to_string_lossy()),
                ("OZBOX_RUNUSER", &d.join("runuser").to_string_lossy()),
                ("OZBOX_REQUESTER_UID", requester_uid_or(&me, requester_uid)),
            ],
        )
        .unwrap()
    }

    fn answer(&self, id: &str) -> String {
        fs::read_to_string(self.dir.path().join(format!("run/results/{id}.out")))
            .unwrap_or_default()
    }
}

fn requester_uid_or<'a>(me: &'a str, given: &'a str) -> &'a str {
    if given.is_empty() {
        me
    } else {
        given
    }
}

#[test]
fn reown_and_reinstall_are_run_with_force_and_only_their_own_arguments() -> R {
    let a = Admin::new();
    a.request("aaaaaaaa01", "reown --from-uid 1000 --from-gid 1000");
    a.request(
        "aaaaaaaa02",
        &format!("reinstall-ozboxd {}", "a".repeat(64)),
    );
    let o = a.process("");
    assert!(o.status.success(), "{}", text(&o));
    assert_eq!(
        log(a.dir.path(), "reown").trim(),
        "--force --from-uid 1000 --from-gid 1000"
    );
    assert_eq!(
        log(a.dir.path(), "install").trim(),
        format!("--force --sha256 {}", "a".repeat(64))
    );
    assert!(log(a.dir.path(), "systemctl").contains("restart ozboxd"));
    assert!(a.answer("aaaaaaaa01").starts_with("status=ok"));
    // every request is recorded, as words and a result
    let audit = fs::read_to_string(a.dir.path().join("audit.log"))?;
    assert!(
        audit.contains("action=reown result=ok")
            && audit.contains("action=reinstall-ozboxd result=ok")
    );
    // the request files are consumed
    assert!(!a.dir.path().join("run/requests/aaaaaaaa01.req").exists());
    Ok(())
}

/// ADR 0043 upgrade order: `reinstall-ozboxd` installs the new `ozbox` program BEFORE it runs `supervisor-setup --socket-only`,
/// and does not run the step at all when the install failed.
#[test]
fn reinstall_installs_the_new_program_before_it_runs_the_socket_step() -> R {
    let a = Admin::new();
    let d = a.dir.path();
    for (name, body) in [
        (
            "install",
            format!(
                "#!/bin/sh\necho \"install $@\" >> '{0}/order.log'\nexit \"${{INSTALL_RC:-0}}\"\n",
                d.display()
            ),
        ),
        (
            "ozbox",
            format!(
                "#!/bin/sh\necho \"ozbox $@\" >> '{0}/order.log'\n",
                d.display()
            ),
        ),
    ] {
        fs::write(d.join(name), body)?;
        fs::set_permissions(d.join(name), fs::Permissions::from_mode(0o755))?;
    }
    a.request("cccccccc01", "reinstall-ozboxd");
    let o = a.process("");
    assert!(o.status.success(), "{}", text(&o));
    let order = fs::read_to_string(d.join("order.log"))?;
    let at = |needle: &str| {
        order
            .lines()
            .position(|l| l.contains(needle))
            .unwrap_or_else(|| panic!("no {needle}:\n{order}"))
    };
    assert!(
        at("install --force") < at("supervisor-setup --socket-only"),
        "{order}"
    );

    // an install that failed: the socket step is not run
    let b = Admin::new();
    let e = b.dir.path();
    fs::write(
        e.join("install"),
        format!(
            "#!/bin/sh\necho install >> '{0}/order.log'\nexit 1\n",
            e.display()
        ),
    )?;
    fs::write(
        e.join("ozbox"),
        format!(
            "#!/bin/sh\necho \"ozbox $@\" >> '{0}/order.log'\n",
            e.display()
        ),
    )?;
    for n in ["install", "ozbox"] {
        fs::set_permissions(e.join(n), fs::Permissions::from_mode(0o755))?;
    }
    b.request("cccccccc02", "reinstall-ozboxd");
    let _ = b.process("");
    let order = fs::read_to_string(e.join("order.log"))?;
    assert!(
        order.contains("install") && !order.contains("supervisor-setup"),
        "{order}"
    );
    // it is reported as failed and ozboxd is not restarted onto a program that did not install
    assert!(
        b.answer("cccccccc02").starts_with("status=failed"),
        "{}",
        b.answer("cccccccc02")
    );
    assert!(
        !log(e, "systemctl").contains("restart ozboxd"),
        "{}",
        log(e, "systemctl")
    );
    Ok(())
}

/// the install worked but `systemctl restart ozboxd` did not. The action reads failed (not ok), and the steps after
/// the restart still ran.
#[test]
fn a_failed_ozboxd_restart_makes_the_reinstall_report_failure() -> R {
    let a = Admin::new();
    let d = a.dir.path();
    fs::write(d.join("install"), "#!/bin/sh\nexit 0\n")?;
    fs::write(
        d.join("ozbox"),
        format!(
            "#!/bin/sh\necho \"ozbox $@\" >> '{0}/order.log'\n",
            d.display()
        ),
    )?;
    fs::write(
        d.join("systemctl"),
        format!("#!/bin/sh\necho \"$@\" >> '{0}/systemctl.log'\n[ \"$1\" = restart ] && exit 1\nexit 0\n", d.display()),
    )?;
    for n in ["install", "ozbox", "systemctl"] {
        fs::set_permissions(d.join(n), fs::Permissions::from_mode(0o755))?;
    }
    a.request("cccccccc03", "reinstall-ozboxd");
    let _ = a.process("");
    let ans = a.answer("cccccccc03");
    assert!(ans.starts_with("status=failed"), "{ans}");
    assert!(ans.contains("ozboxd did not restart"), "{ans}");
    assert!(
        fs::read_to_string(d.join("order.log"))?.contains("host-guard metadata install"),
        "the later steps still ran"
    );
    Ok(())
}

#[test]
fn a_request_reaches_the_guards_only_never_the_programs_own_token_reader() -> R {
    let a = Admin::new();
    let d = a.dir.path();
    fs::write(
        d.join("ozbox"),
        format!("#!/bin/sh\necho \"$@\" >> '{}/ozbox.args'\n", d.display()),
    )?;
    fs::set_permissions(d.join("ozbox"), fs::Permissions::from_mode(0o755))?;
    a.request(
        "ffffffff01",
        "host-guard take-file --dir x --id 0123456789abcdef --owner 0",
    );
    a.request("ffffffff02", "host-guard egress report");
    a.request("ffffffff03", "host-guard metadata install");
    let o = a.process("");
    assert!(o.status.success(), "{}", text(&o));
    assert!(a.answer("ffffffff01").starts_with("status=failed"));
    let args = fs::read_to_string(d.join("ozbox.args"))?;
    assert!(!args.contains("take-file"), "{args}");
    assert!(
        args.contains("host-guard egress report") && args.contains("host-guard metadata install")
    );
    Ok(())
}

#[test]
fn the_memory_guard_is_reachable_through_the_helper_and_is_installed_again_by_a_reinstall() -> R {
    let a = Admin::new();
    let d = a.dir.path();
    fs::write(
        d.join("ozbox"),
        format!("#!/bin/sh\necho \"$@\" >> '{}/ozbox.args'\n", d.display()),
    )?;
    fs::set_permissions(d.join("ozbox"), fs::Permissions::from_mode(0o755))?;
    a.request("ffffffff04", "host-guard memory install");
    a.request("ffffffff05", "host-guard memory status");
    // a word the box user adds is not a word of the guard's: the whole request is refused before anything runs
    a.request("ffffffff06", "host-guard memory install; id");
    a.request("ffffffff07", "reinstall-ozboxd");
    // the helper's own refresh is reachable as a guard word, and a reinstall does it before the guards (ADR 0045, M2)
    a.request("ffffffff08", "host-guard helper refresh");
    a.request("ffffffff09", "host-guard helper refresh; id");
    let o = a.process("");
    assert!(o.status.success(), "{}", text(&o));
    let args = fs::read_to_string(d.join("ozbox.args"))?;
    assert!(args.contains("host-guard memory status"), "{args}");
    assert_eq!(
        args.matches("host-guard helper refresh").count(),
        2,
        "once asked for, once by the reinstall: {args}"
    );
    assert!(a.answer("ffffffff09").starts_with("status=failed"));
    assert!(
        args.find("host-guard helper refresh").unwrap()
            < args
                .find("host-guard metadata install")
                .unwrap_or(usize::MAX),
        "{args}"
    );
    // asked for once directly, and once more by the reinstall (a box made before the guard gets it there)
    assert_eq!(
        args.matches("host-guard memory install").count(),
        2,
        "{args}"
    );
    assert!(a.answer("ffffffff06").starts_with("status=failed"));
    assert!(!args.contains("; id"));
    // it is ungated: it only ever tightens, so it asks the secrets service for no approval
    let script = fs::read_to_string(script("ozbox-admin.sh"))?;
    assert!(script.contains("egress|patch|metadata|memory|helper)"));
    Ok(())
}

#[test]
fn first_boot_installs_the_memory_guard_after_the_metadata_guard_and_nothing_here_makes_swap_on_a_disk(
) {
    let t = read("infra/cloud-init/box.yaml.tftpl");
    let runcmd = &t[t.find("\nruncmd:\n").expect("runcmd")..];
    let metadata = runcmd
        .find("host-guard metadata install")
        .expect("metadata guard");
    let memory = runcmd
        .find("host-guard memory install")
        .expect("memory guard");
    let manager = runcmd
        .find("/usr/local/sbin/ozbox-user-manager.sh")
        .expect("user manager");
    // before the box user's manager starts (so the delegation drop-in is read by its first start), and a failure does not stop the boot
    assert!(metadata < memory && memory < manager);
    assert!(runcmd[memory..manager].contains("|| echo"));
    // one line, no new script: first boot is held to a size (a tofu test)
    assert!(!t.contains("ozbox-memory.sh") && !t.contains("zram"));
    // Swap is compressed RAM and only that (ADR 0045): a page of the secrets service must not reach a disk. Nothing the box is
    // built from makes a swap file or a swap partition.
    let mut files = vec![];
    for dir in ["infra/cloud-init", "infra/packer", "infra/box"] {
        let mut stack = vec![root().join(dir)];
        while let Some(p) = stack.pop() {
            let Ok(rd) = fs::read_dir(&p) else { continue };
            for e in rd.flatten() {
                if e.path().is_dir() {
                    stack.push(e.path());
                } else {
                    files.push(e.path());
                }
            }
        }
    }
    assert!(files.len() > 5);
    for f in files {
        let text = fs::read_to_string(&f).unwrap_or_default();
        for word in [
            "swapfile",
            "fallocate",
            "mkswap",
            "swapon",
            "/swap.img",
            "swap.img",
        ] {
            assert!(!text.contains(word), "{} makes swap ({word})", f.display());
        }
    }
}

#[test]
fn the_root_helper_refuses_a_system_id_for_reown_before_the_script_runs() -> R {
    let a = Admin::new();
    a.request("aaaaaaaa03", "reown --from-uid 999");
    a.request("aaaaaaaa04", "reown --from-gid 65534");
    let o = a.process("");
    assert!(o.status.success(), "{}", text(&o));
    for id in ["aaaaaaaa03", "aaaaaaaa04"] {
        assert!(
            a.answer(id).starts_with("status=failed"),
            "{}",
            a.answer(id)
        );
    }
    assert_eq!(log(a.dir.path(), "reown"), "");
    Ok(())
}

#[test]
fn nothing_outside_the_list_reaches_root() -> R {
    let a = Admin::new();
    a.request("bbbbbbbb01", "bash -c id");
    a.request("bbbbbbbb02", "reown --from-uid 0x1; id");
    a.request("bbbbbbbb03", "reown --from-uid abc");
    a.request("bbbbbbbb04", "reown --path /etc");
    a.request("bbbbbbbb05", "restart-services ssh");
    a.request("bbbbbbbb06", "reinstall-ozboxd not-a-hash");
    let o = a.process("");
    assert!(o.status.success(), "{}", text(&o));
    for id in ["01", "02", "03", "04", "05", "06"] {
        assert!(
            a.answer(&format!("bbbbbbbb{id}"))
                .starts_with("status=failed"),
            "{id}"
        );
    }
    for n in ["reown", "install", "systemctl"] {
        assert_eq!(log(a.dir.path(), n), "", "{n} must not have run");
    }
    Ok(())
}

#[test]
fn a_request_from_anyone_but_the_box_user_is_refused_and_recorded() -> R {
    let a = Admin::new();
    a.request("cccccccc01", "collect-logs");
    // the file is owned by this account; the helper is told the box user is someone else
    let o = a.process("4242");
    assert!(o.status.success(), "{}", text(&o));
    assert_eq!(a.answer("cccccccc01"), "");
    assert_eq!(log(a.dir.path(), "journalctl"), "");
    assert!(fs::read_to_string(a.dir.path().join("audit.log"))?.contains("refused"));
    Ok(())
}

#[test]
fn restart_services_takes_only_the_listed_units_and_collect_logs_is_bounded() -> R {
    let a = Admin::new();
    a.request("dddddddd01", "restart-services ozboxd ozbox-tools.path");
    a.request("dddddddd02", "collect-logs");
    let o = a.process("");
    assert!(o.status.success(), "{}", text(&o));
    let calls = log(a.dir.path(), "systemctl");
    assert!(calls.contains("restart ozboxd") && calls.contains("restart ozbox-tools.path"));
    assert!(a.answer("dddddddd02").contains("== ozboxd"));
    // the browser's launcher is among them: its socket may be restarted, and its journal (redacted like the rest) is collected
    let a = Admin::new();
    a.request("dddddddd03", "restart-services ozbox-browser.socket");
    a.request("dddddddd04", "collect-logs");
    let o = a.process("");
    assert!(o.status.success(), "{}", text(&o));
    assert!(log(a.dir.path(), "systemctl").contains("restart ozbox-browser.socket"));
    assert!(log(a.dir.path(), "journalctl").contains("ozbox-browser@*"));
    Ok(())
}

#[test]
fn enable_linger_runs_for_the_box_user_only_and_takes_no_arguments() -> R {
    let a = Admin::new();
    a.request("eeeeeeee01", "enable-linger");
    a.request("eeeeeeee02", "enable-linger root");
    a.request("eeeeeeee03", "enable-linger --now");
    let o = a.process("");
    assert!(o.status.success(), "{}", text(&o));
    assert!(a.answer("eeeeeeee01").starts_with("status=ok"));
    assert!(a.answer("eeeeeeee02").starts_with("status=failed"));
    assert!(a.answer("eeeeeeee03").starts_with("status=failed"));
    // exactly one call, with the fixed user
    assert_eq!(log(a.dir.path(), "loginctl").trim(), "enable-linger ozbox");
    // and the box user's manager is started properly once (the helper leaves a healthy one alone)
    assert_eq!(log(a.dir.path(), "user-manager").lines().count(), 1);
    Ok(())
}

#[test]
fn the_image_carries_google_chrome_from_its_signed_repository_with_the_key_pinned_and_recorded() {
    let p = read("infra/packer/ozbox-image/scripts/provision.sh");
    // the key is accepted only if it is one Google publishes, and only our deb822 source (key pinned) stays
    assert!(
        p.contains("add_apt_repo google-chrome https://dl.google.com/linux/linux_signing_key.pub")
    );
    assert!(p.contains(
        "4CCA1EAF950CEE4AB83976DCA040830F7FAC5991 EB4C1BFD4F042F6DDDCCEC917721F63BD38B4796"
    ));
    assert!(p.contains("rm -f /etc/apt/sources.list.d/google-chrome.list"));
    assert!(p.contains("repo_add_once=\"false\""));
    // never the snap, and amd64 only (Google ships no arm64 package)
    assert!(!p.contains("snap install chromium"));
    assert!(p.contains("if [ \"$(dpkg --print-architecture)\" = \"amd64\" ]; then"));
    // the exact package is recorded for the release manifest
    assert!(p.contains("chrome_version=%s\\nchrome_deb_sha256=%s"));
}

#[test]
fn recover_secrets_never_touches_a_running_service_and_otherwise_sets_the_store_aside_then_starts_it(
) -> R {
    // the default systemctl answers 0 to everything, so the service reads as running: refused, nothing called
    let a = Admin::new();
    recorder(a.dir.path(), "ozbox");
    a.request("ffffffff01", "recover-secrets");
    a.request("ffffffff02", "recover-secrets --force");
    let o = a.process("");
    assert!(o.status.success(), "{}", text(&o));
    assert!(a.answer("ffffffff01").starts_with("status=failed"));
    assert!(a.answer("ffffffff01").contains("running"));
    assert!(a.answer("ffffffff02").starts_with("status=failed"));
    assert_eq!(
        log(a.dir.path(), "ozbox"),
        "",
        "a running service's store is never set aside"
    );
    assert!(
        !log(a.dir.path(), "systemctl").contains("stop"),
        "a request never stops the service"
    );

    // a service still in its retry loop reads `activating`: refused, and the refusal says which state the unit is in
    let c = Admin::new();
    recorder(c.dir.path(), "ozbox");
    let sc = c.dir.path().join("systemctl");
    fs::write(&sc, "#!/bin/sh\n[ \"$1\" = is-active ] && [ \"${2:-}\" != --quiet ] && echo activating\nexit 0\n")?;
    fs::set_permissions(&sc, fs::Permissions::from_mode(0o755))?;
    c.request("ffffffff07", "recover-secrets challenge");
    assert!(c.process("").status.success());
    let said = c.answer("ffffffff07");
    assert!(said.starts_with("status=failed"), "{said}");
    assert!(
        said.contains("unit state: activating") && said.contains("nothing is recorded as lost"),
        "{said}"
    );
    assert_eq!(log(c.dir.path(), "ozbox"), "");

    // a service that is not running (not ready: its key is gone): the program sets the store aside, then it starts
    let b = Admin::new();
    recorder(b.dir.path(), "ozbox");
    let sc = b.dir.path().join("systemctl");
    fs::write(
        &sc,
        format!(
            "#!/bin/sh\necho \"$@\" >> '{}'\n[ \"$1\" = is-active ] && exit 3\nexit 0\n",
            b.dir.path().join("systemctl.log").display()
        ),
    )?;
    fs::set_permissions(&sc, fs::Permissions::from_mode(0o755))?;
    // no approval words: refused before the program is asked; the program alone judges the state and the signature
    b.request("ffffffff03", "recover-secrets");
    b.request("ffffffff04", "recover-secrets challenge");
    let (nonce, sig) = ("0a".repeat(16), "1b".repeat(64));
    b.request("ffffffff05", &format!("recover-secrets {nonce} 1234 {sig}"));
    b.request("ffffffff06", &format!("recover-secrets {nonce} 1234 xyz"));
    let o = b.process("");
    assert!(o.status.success(), "{}", text(&o));
    assert!(b.answer("ffffffff03").starts_with("status=failed"));
    assert!(b.answer("ffffffff06").starts_with("status=failed"));
    for id in ["ffffffff04", "ffffffff05"] {
        assert!(b.answer(id).starts_with("status=ok"), "{}", b.answer(id));
    }
    assert_eq!(
        log(b.dir.path(), "ozbox").trim(),
        format!("secrets recover-store --challenge\nsecrets recover-store --nonce {nonce} --expires 1234 --signature {sig}")
    );
    let calls = log(b.dir.path(), "systemctl");
    assert!(calls.contains("start ozbox-secrets.service") && !calls.contains("stop"));
    Ok(())
}

#[test]
fn first_boot_and_the_image_turn_linger_on_and_carry_tmux_and_python() {
    let t = read("infra/cloud-init/box.yaml.tftpl");
    for pkg in ["  - tmux\n", "  - python3\n"] {
        assert!(t.contains(pkg), "the template must install {pkg}");
    }
    let runcmd = &t[t.find("\nruncmd:\n").expect("runcmd")..];
    let setup = runcmd.find("ozbox-work-setup.sh]").expect("work setup");
    let secrets = runcmd
        .find("ozbox-secrets-setup.sh,")
        .expect("secrets setup");
    let guard = runcmd
        .find("host-guard metadata install")
        .expect("metadata guard");
    let manager = runcmd
        .find("/usr/local/sbin/ozbox-user-manager.sh")
        .expect("the user manager is started by first boot");
    let svc = runcmd
        .find("enable, --now, ozboxd.service")
        .expect("ozboxd start");
    // The box user's manager starts once: after /work is mounted and owned, after the secrets service and after the
    // metadata guard (so none of the box user's services ever reaches the metadata service), before the box daemon.
    assert!(setup < secrets && secrets < guard && guard < manager && manager < svc);
    // and nothing restarts it in the middle of first boot (that raced the rest of first boot)
    assert!(
        !t.contains("restart user@"),
        "first boot must not restart the box user's manager"
    );
    let helper = fs::read_to_string(script("ozbox-user-manager.sh")).unwrap();
    assert!(helper.contains("enable-linger \"$user\""));
    // the helper is written by the template like the other scripts
    assert!(
        written_file(&t, "/usr/local/sbin/ozbox-user-manager.sh").contains("ozbox-user-manager.sh")
    );
    let p = read("infra/packer/ozbox-image/scripts/provision.sh");
    assert!(
        p.contains("tmux python3"),
        "the image carries tmux and python3"
    );
    assert!(p.contains("/var/lib/systemd/linger/ozbox"));
    // the image holds the box user's manager back until /work is a mount point, with the very drop-in first boot writes
    assert!(p.contains("user@${OZBOX_UID}.service.d"));
    assert!(p.contains(
        "printf '[Unit]\\nRequiresMountsFor=/work\\nAfter=work.mount\\nConditionPathIsMountPoint=/work\\n'"
    ));
    assert!(helper.contains(
        "printf '[Unit]\\nRequiresMountsFor=%s\\nAfter=work.mount\\nConditionPathIsMountPoint=%s\\n' \"$work\" \"$work\""
    ));
    // the controllers runs need are delegated to the box user's manager by ONE file with ONE writer, the memory guard's
    // (10-ozbox-memory.conf): neither the image nor first boot writes a second drop-in for it
    assert!(
        !p.contains("Delegate="),
        "the image must not write its own delegation drop-in"
    );
    assert!(
        !helper.contains("Delegate="),
        "first boot's user-manager step must not write its own delegation drop-in"
    );
    assert!(!p.contains("20-ozbox-delegate") && !helper.contains("20-ozbox-delegate"));
}

/// Sessions come back at every boot (ADR 0049). The user unit is NOT in the first-boot template: the daemon writes it into the
/// box user's own systemd folder (so a box made before this release gets it too, and user data does not grow). The box user's
/// manager is still held back until /work is a mount point, which is what makes the records readable.
#[test]
fn the_session_resume_unit_is_written_by_the_daemon_not_the_first_boot_template() {
    let t = read("infra/cloud-init/box.yaml.tftpl");
    assert!(
        !t.contains("ozbox-session-resume"),
        "the unit comes from ozboxd, not from user data"
    );
    let p = read("infra/packer/ozbox-image/scripts/provision.sh");
    assert!(p.contains("ConditionPathIsMountPoint=/work"));
    // the daemon is what installs it, in the box user's own folder and not under /etc
    let d = read("crates/ozboxd/src/session_resume.rs");
    assert!(d.contains(".config/systemd/user") && !d.contains("/etc/systemd/user"));
    let m = read("crates/ozboxd/src/main.rs");
    assert!(m.contains("install_user_unit"));
}

// ------------------------------------------------------------ user manager

struct UserManager {
    dir: tempfile::TempDir,
}

impl UserManager {
    /// `active`: whether the box user's manager is running already; `started`/`mounted`: their monotonic start times.
    fn new(active: bool, started: u64, mounted: u64) -> Self {
        let dir = tempfile::tempdir().unwrap();
        let d = dir.path();
        let log = d.join("systemctl.log");
        let stub = format!(
            "#!/bin/sh\necho \"$@\" >> '{log}'\ncase \"$1 $2\" in\n  'is-active --quiet') [ {active} = 1 ] && exit 0; exit 3 ;;\n  'show -p') case \"$5\" in work.mount) echo {mounted} ;; *) echo {started} ;; esac ;;\nesac\nexit 0\n",
            log = log.display(),
            active = u8::from(active),
        );
        fs::write(d.join("systemctl"), stub).unwrap();
        fs::write(d.join("id"), "#!/bin/sh\necho 1500\n").unwrap();
        fs::write(
            d.join("mountpoint"),
            "#!/bin/sh\n[ -e \"$(dirname \"$0\")/mounted\" ]\n",
        )
        .unwrap();
        for f in ["systemctl", "id", "mountpoint"] {
            fs::set_permissions(d.join(f), fs::Permissions::from_mode(0o755)).unwrap();
        }
        recorder(d, "loginctl");
        fs::write(d.join("mounted"), "").unwrap();
        Self { dir }
    }

    fn run(&self) -> Output {
        let d = self.dir.path();
        let s = |n: &str| d.join(n).to_string_lossy().into_owned();
        sh(
            &script("ozbox-user-manager.sh"),
            &[],
            &[
                ("OZBOX_SYSTEMD_DIR", &s("units")),
                ("OZBOX_SYSTEMCTL", &s("systemctl")),
                ("OZBOX_LOGINCTL", &s("loginctl")),
                ("OZBOX_ID", &s("id")),
                ("OZBOX_MOUNTPOINT", &s("mountpoint")),
            ],
        )
        .unwrap()
    }
}

#[test]
fn the_user_manager_is_started_once_with_its_home_and_held_back_until_work_is_mounted() {
    // a stock machine, or an image whose drop-in held the manager back: it is not running, so it is started
    let m = UserManager::new(false, 0, 0);
    let o = m.run();
    assert!(o.status.success(), "{}", text(&o));
    let calls = log(m.dir.path(), "systemctl");
    assert_eq!(
        calls
            .lines()
            .filter(|l| l.starts_with("start ") || l.starts_with("restart "))
            .collect::<Vec<_>>(),
        ["start user@1500.service"]
    );
    // the drop-in is loaded before the start, and linger is on
    assert!(calls.find("daemon-reload") < calls.find("start user@1500.service"));
    assert_eq!(log(m.dir.path(), "loginctl").trim(), "enable-linger ozbox");
    let dropin = fs::read_to_string(
        m.dir
            .path()
            .join("units/user@1500.service.d/10-ozbox-work.conf"),
    )
    .unwrap();
    assert!(
        dropin.contains("ConditionPathIsMountPoint=/work")
            && dropin.contains("RequiresMountsFor=/work")
    );
    // no second delegation drop-in is written here (the memory guard owns it)
    assert!(!m
        .dir
        .path()
        .join("units/user@.service.d/20-ozbox-delegate.conf")
        .exists());
}

#[test]
fn a_user_manager_that_started_before_work_was_mounted_is_restarted_once_and_a_healthy_one_is_left_alone(
) {
    // started at 5 s, /work mounted at 30 s: it found no home and started nothing
    let early = UserManager::new(true, 5_000_000, 30_000_000);
    assert!(early.run().status.success());
    let calls = log(early.dir.path(), "systemctl");
    assert!(calls.contains("restart user@1500.service"), "{calls}");
    assert!(!calls.lines().any(|l| l == "start user@1500.service"));
    // started after the mount (a second run of first boot, or the admin action on a healthy box): untouched
    let ok = UserManager::new(true, 40_000_000, 30_000_000);
    assert!(ok.run().status.success());
    let calls = log(ok.dir.path(), "systemctl");
    assert!(
        !calls.contains("restart") && !calls.lines().any(|l| l.starts_with("start ")),
        "{calls}"
    );
}

#[test]
fn the_user_manager_is_not_started_while_work_is_not_mounted() {
    let m = UserManager::new(false, 0, 0);
    fs::remove_file(m.dir.path().join("mounted")).unwrap();
    let o = m.run();
    assert!(!o.status.success());
    assert!(text(&o).contains("not mounted"));
    assert!(!log(m.dir.path(), "systemctl").contains("start"));
}

#[test]
fn the_request_helper_refuses_anything_that_is_not_plain_words() -> R {
    let d = tempfile::tempdir()?;
    fs::create_dir_all(d.path().join("requests"))?;
    let o = sh(
        &script("ozbox-admin-request.sh"),
        &["reown; id"],
        &[("OZBOX_ADMIN_DIR", &d.path().to_string_lossy())],
    )?;
    assert!(!o.status.success());
    assert_eq!(fs::read_dir(d.path().join("requests"))?.count(), 0);
    Ok(())
}

// ------------------------------------- template, image build, workflow

fn written_file(template: &str, path: &str) -> String {
    let at = template
        .find(&format!("  - path: {path}\n"))
        .unwrap_or_else(|| panic!("{path} is not written by the template"));
    let rest = &template[at + 4..];
    let end = rest.find("\n  - path: ").unwrap_or(rest.len());
    rest[..end].to_string()
}

#[test]
fn the_template_writes_the_helpers_with_the_right_owner_and_modes() {
    let t = read("infra/cloud-init/box.yaml.tftpl");
    for (path, mode) in [
        ("/usr/local/sbin/ozbox-reown.sh", "0755"),
        ("/usr/local/sbin/ozbox-install-agent.sh", "0755"),
        ("/usr/local/sbin/ozbox-admin.sh", "0755"),
        ("/usr/local/bin/ozbox-admin-request", "0755"),
    ] {
        let f = written_file(&t, path);
        assert!(f.contains(&format!("permissions: \"{mode}\"")), "{path}");
        assert!(f.contains("owner: root:root"), "{path}");
        assert!(f.contains("encoding: gz+b64"), "{path} is sent compressed");
    }
    // the request directory is writable by the box user only to create requests; answers are root's
    let tmp = written_file(&t, "/etc/tmpfiles.d/ozbox-admin.conf");
    assert!(tmp.contains("requests 1770 root ozbox"));
    assert!(tmp.contains("results  0755 root root"));
}

#[test]
fn the_box_user_gets_no_sudo_and_the_admin_service_does_not_need_the_daemon() {
    let t = read("infra/cloud-init/box.yaml.tftpl");
    assert!(!t.contains("sudoers") && !t.contains("NOPASSWD") && !t.contains("sudo:"));
    let svc = written_file(&t, "/etc/systemd/system/ozbox-admin.service");
    assert!(svc.contains("ExecStart=/usr/local/sbin/ozbox-admin.sh"));
    assert!(
        !svc.contains("ConditionPathExists"),
        "it is how ozboxd is put back"
    );
    let provision = read("infra/packer/ozbox-image/scripts/provision.sh");
    assert!(!provision.contains("sudoers") && !provision.contains("NOPASSWD"));
}

/// Release-gate T1: the root tool helper must keep what apt needs to run as root. It must not be a private user
/// namespace, and any capability list or syscall filter must keep the uid changes. (This passes on the unit as written;
/// the fix for the observed `seteuid 42` failure is in ozboxd's apt fallback, pinned by tests/tools.rs.) A guard only: it
/// passed on the unit that failed, so it is NOT evidence about the cause. What the real box showed is in `APT_GET`'s comment.
#[test]
fn the_tool_helper_unit_does_not_forbid_what_apt_needs_as_root() {
    let t = read("infra/cloud-init/box.yaml.tftpl");
    let svc = written_file(&t, "/etc/systemd/system/ozbox-tools.service");
    assert!(
        svc.contains("User=root") && svc.contains("ExecStart=/usr/local/bin/ozboxd tools-root")
    );
    for forbidden in ["PrivateUsers", "RestrictSUIDSGID", "ProtectSystem=strict"] {
        assert!(!svc.contains(forbidden), "{forbidden}");
    }
    for line in svc.lines().map(str::trim) {
        if line.starts_with("CapabilityBoundingSet=") {
            assert!(
                line.contains("CAP_SETUID") && line.contains("CAP_SETGID"),
                "{line}"
            );
        }
        if line.starts_with("SystemCallFilter=") {
            assert!(
                line.contains("@setuid") || line.contains("@system-service"),
                "{line}"
            );
        }
    }
}

#[test]
fn work_setup_re_owns_before_anything_starts_and_the_agent_is_installed_before_it_is_enabled() {
    let t = read("infra/cloud-init/box.yaml.tftpl");
    let setup = written_file(&t, "/usr/local/sbin/ozbox-work-setup.sh");
    let adopt = setup
        .find("usermod -u \"$disk_uid\" ozbox")
        .expect("adoption");
    let reown = setup
        .find("/usr/local/sbin/ozbox-reown.sh")
        .expect("re-own call");
    assert!(
        reown > adopt,
        "re-own comes after the adoption of a free id"
    );
    // it must not stop the boot
    assert!(setup[reown..].lines().next().unwrap_or("").contains("||"));
    let run = t.find("\nruncmd:").expect("runcmd");
    let cmds = &t[run..];
    let at = |needle: &str| cmds.find(needle).unwrap_or_else(|| panic!("{needle}"));
    assert!(at("ozbox-work-setup.sh") < at("ozbox-install-agent.sh"));
    assert!(at("ozbox-install-agent.sh") < at("enable, --now, ozboxd.service"));
    assert!(at("ozbox-admin.conf") < at("enable, --now, ozbox-admin.path"));
    // G1 N8 (benchmark: lifecycle, spawn): the dashboard's socket unit is written and started BEFORE the daemon first starts,
    // so a first boot never restarts the daemon to hand it the socket
    assert!(at("secrets supervisor-setup") < at("enable, --now, ozboxd.service"));
}

#[test]
fn the_image_build_places_the_binary_and_writes_the_marker() {
    let p = read("infra/packer/ozbox-image/scripts/provision.sh");
    assert!(p.contains("install -m 0755 -o root -g root \"$ozboxd_upload\" /usr/local/bin/ozboxd"));
    // checked against the hash the workflow computed, before it is installed
    let check = p.find("sha256sum --check --strict").unwrap();
    let place = p.find("/usr/local/bin/ozboxd\n").unwrap();
    assert!(p.find("\"$OZBOXD_SHA256  $ozboxd_upload\"").unwrap() < place && check < place);
    assert!(
        p.contains("OZBOXD_SHA256:?"),
        "the build fails without the hash"
    );
    assert!(p.contains("/etc/ozbox/image-release"));
    assert!(p.contains("ozboxd_sha256=%s"));
    let hcl = read("infra/packer/ozbox-image/ozbox-image.pkr.hcl");
    assert!(hcl.contains("provisioner \"file\""));
    assert!(hcl.contains("source      = var.ozboxd_binary"));
    assert!(hcl.contains("destination = \"/tmp/ozboxd-upload\""));
    assert!(hcl.contains("OZBOXD_SHA256=${var.ozboxd_sha256}"));
    // the upload comes before the shell provisioner that installs it
    assert!(
        hcl.find("var.ozboxd_binary").unwrap()
            < hcl.find("${path.root}/scripts/provision.sh").unwrap()
    );
}

#[test]
fn the_image_workflow_builds_the_agent_from_the_same_commit_and_signs_its_hash_into_the_manifest() {
    let w = read(".github/workflows/image.yml");
    assert!(w.contains("-p ozboxd"));
    assert!(w.contains("x86_64-unknown-linux-musl") && w.contains("aarch64-unknown-linux-musl"));
    assert!(
        w.contains("needs: [plan, agent]"),
        "the image build waits for the agent"
    );
    assert!(w.contains("PKR_VAR_ozboxd_binary") && w.contains("PKR_VAR_ozboxd_sha256"));
    assert!(w.contains("PKR_VAR_source_commit: ${{ github.sha }}"));
    // the manifest carries it, and it is signed (the manifest is what cosign signs)
    assert!(w.contains("ozboxd: ($parts | map({(.arch): .ozboxd}) | add)"));
    assert!(w.contains("sign-blob --yes ozbox-image-manifest.json"));
    // and the binaries are published beside it, for a machine that did not come from the image
    assert!(w.contains("cp \"$d/agent/ozboxd-linux-$arch\" \"out/ozboxd-linux-$arch\""));
}

#[test]
fn the_image_installs_a_root_owned_ozbox_built_from_the_same_commit_and_records_its_hash() {
    let w = read(".github/workflows/image.yml");
    assert!(
        w.contains("-p ozboxd -p ozbox-cli"),
        "the same cross build makes both"
    );
    assert!(w.contains("PKR_VAR_ozbox_binary") && w.contains("PKR_VAR_ozbox_sha256"));
    assert!(w.contains("ozbox: ($parts | map({(.arch): .ozbox}) | add)"));
    assert!(w.contains("cp \"$d/agent/ozbox-linux-$arch\" \"out/ozbox-linux-$arch\""));
    assert!(
        w.contains(".ozbox as $o | .images | all("),
        "an image without it is refused"
    );
    let hcl = read("infra/packer/ozbox-image/ozbox-image.pkr.hcl");
    assert!(hcl.contains("source      = var.ozbox_binary"));
    assert!(hcl.contains("destination = \"/tmp/ozbox-upload\""));
    assert!(hcl.contains("OZBOX_CLI_SHA256=${var.ozbox_sha256}"));
    assert!(
        hcl.find("var.ozbox_binary").unwrap()
            < hcl.find("${path.root}/scripts/provision.sh").unwrap()
    );
    let p = read("infra/packer/ozbox-image/scripts/provision.sh");
    let check = p.find("\"$OZBOX_CLI_SHA256  $ozbox_upload\"").unwrap();
    let place = p
        .find("install -m 0755 -o root -g root \"$ozbox_upload\" /usr/local/bin/ozbox")
        .unwrap();
    assert!(
        check < place,
        "the hash is checked before the program is installed"
    );
    assert!(p.contains("OZBOX_CLI_SHA256:?") && p.contains("ozbox_sha256=%s"));
    // the secrets units run exactly that path
    let s = read("infra/cloud-init/scripts/ozbox-secrets-setup.sh");
    assert!(s.contains("ConditionPathExists=/usr/local/bin/ozbox"));
}

#[test]
fn a_tunnel_token_is_taken_from_the_box_users_file_once_and_stored_through_the_secrets_program() -> R
{
    let a = Admin::new();
    let d = a.dir.path();
    // a stand-in for `ozbox`: records its arguments and what arrived on standard input
    fs::write(
        d.join("ozbox"),
        format!(
            "#!/bin/sh\n{TAKE_FILE}echo \"$@\" >> '{0}/ozbox.args'\ncat >> \"{0}/ozbox.$2.stdin\"\n",
            d.display()
        ),
    )?;
    fs::set_permissions(d.join("ozbox"), fs::Permissions::from_mode(0o755))?;
    let token = "abcdabcdabcdabcdabcdabcd";
    fs::write(
        d.join("run/requests/0123456789abcdef.tok"),
        format!("{token}\n"),
    )?;
    a.request(
        "cccccccc01",
        "replace-tunnel-token ide 0123456789abcdef ABCD-EFGH-JKMN-PQRS",
    );
    // a request that names no file, a bad name and a bad id are refused
    a.request("cccccccc02", "replace-tunnel-token ide ffffffffffffffff");
    a.request("cccccccc03", "replace-tunnel-token evil 0123456789abcdef");
    a.request("cccccccc04", "replace-tunnel-token ide nothex");
    let o = a.process("");
    assert!(o.status.success(), "{}", text(&o));
    assert!(
        a.answer("cccccccc01").starts_with("status=ok"),
        "{}",
        a.answer("cccccccc01")
    );
    assert!(
        fs::read_to_string(d.join("ozbox.args"))?.contains("secrets put --name tunnel-token-ide")
    );
    assert_eq!(fs::read_to_string(d.join("ozbox.put.stdin"))?.trim(), token);
    // The approval is checked against the token the helper itself read (it cannot be swapped afterwards): the gate gets the
    // code on its first line and that token on its second, asks for the binding by flag, and neither is in any argument.
    let args = fs::read_to_string(d.join("ozbox.args"))?;
    let gate_line = args
        .lines()
        .find(|l| l.starts_with("secrets gate"))
        .unwrap();
    assert!(gate_line.contains("--bind-token-stdin") && gate_line.contains("--scope tunnel-token"));
    assert!(
        !args.contains(token) && !args.contains("ABCD-EFGH-JKMN-PQRS"),
        "{args}"
    );
    assert_eq!(
        fs::read_to_string(d.join("ozbox.gate.stdin"))?,
        format!("ABCD-EFGH-JKMN-PQRS\n{token}\n")
    );
    // the token file is consumed, the connector is started, and the token is in no answer or audit line
    assert!(!d.join("run/requests/0123456789abcdef.tok").exists());
    assert!(log(d, "systemctl").contains("enable --now ozbox-code-connector.service"));
    for id in ["cccccccc01", "cccccccc02", "cccccccc03", "cccccccc04"] {
        assert!(!a.answer(id).contains(token));
    }
    for id in ["cccccccc02", "cccccccc03", "cccccccc04"] {
        assert!(!a.answer(id).starts_with("status=ok"), "{id}");
    }
    assert!(!fs::read_to_string(d.join("audit.log"))?.contains(token));
    // removing one is its own action
    a.request("cccccccc05", "clear-tunnel-token ide");
    let o = a.process("");
    assert!(o.status.success(), "{}", text(&o));
    assert!(fs::read_to_string(d.join("ozbox.args"))?
        .contains("secrets remove --name tunnel-token-ide"));
    assert!(log(d, "systemctl").contains("disable --now ozbox-code-connector.service"));
    Ok(())
}

#[test]
fn a_project_runner_is_made_with_no_login_and_its_own_private_directories() -> R {
    let a = Admin::new();
    let d = a.dir.path();
    recorder(d, "useradd");
    recorder(d, "install");
    recorder(d, "ozbox");
    recorder(d, "gpasswd");
    // `id` says the user does not exist yet
    fs::write(d.join("id"), "#!/bin/sh\nexit 1\n")?;
    fs::set_permissions(d.join("id"), fs::Permissions::from_mode(0o755))?;
    a.request("dddddddd11", "ensure-runner app");
    a.request("dddddddd12", "ensure-runner ../etc");
    a.request("dddddddd13", "ensure-runner Bad_Name");
    let o = a.process("");
    assert!(o.status.success(), "{}", text(&o));
    assert!(
        a.answer("dddddddd11").starts_with("status=ok"),
        "{}",
        a.answer("dddddddd11")
    );
    let adds = log(d, "useradd");
    assert!(adds.contains("--system") && adds.contains("--shell /usr/sbin/nologin"));
    // in no shared group: the runner reads nothing of the box user's; what it may read is set from the stored declaration
    assert!(
        !adds.contains("--groups") && !adds.contains(" ozbox,"),
        "{adds}"
    );
    assert_eq!(
        log(d, "ozbox").trim(),
        "secrets runner-setup app",
        "the setup acts on the project name only, and the stored declaration decides the rest"
    );
    assert!(adds.contains("ozbox-run-app") && !adds.contains("sudo"));
    let dirs = log(d, "install");
    assert!(dirs.contains("-m 0700 -o ozbox-run-app -g ozbox-run-app /var/lib/ozbox-run/app"));
    // the runner never talks to the secrets service: no socket directory is made for it
    assert!(!dirs.contains("/run/ozbox-secrets"));
    for id in ["dddddddd12", "dddddddd13"] {
        assert!(!a.answer(id).starts_with("status=ok"), "{id}");
    }
    assert_eq!(adds.lines().count(), 1, "a bad name made no user");
    Ok(())
}

#[test]
fn a_runner_from_an_older_image_is_taken_out_of_the_box_users_group() -> R {
    let a = Admin::new();
    let d = a.dir.path();
    recorder(d, "install");
    recorder(d, "ozbox");
    recorder(d, "gpasswd");
    // `id` finds the user, and `id -nG` lists the box user's group among its groups
    fs::write(
        d.join("id"),
        "#!/bin/sh\n[ \"$1\" = -nG ] && echo 'ozbox-run-app ozbox'\nexit 0\n",
    )?;
    fs::set_permissions(d.join("id"), fs::Permissions::from_mode(0o755))?;
    a.request("dddddddd21", "ensure-runner app");
    let o = a.process("");
    assert!(o.status.success(), "{}", text(&o));
    assert!(
        a.answer("dddddddd21").starts_with("status=ok"),
        "{}",
        a.answer("dddddddd21")
    );
    assert_eq!(log(d, "gpasswd").trim(), "-d ozbox-run-app ozbox");
    assert_eq!(log(d, "ozbox").trim(), "secrets runner-setup app");
    // a setup that fails (a folder that is a link, a tool whose digest changed) fails the request and says why
    fs::write(
        d.join("ozbox"),
        "#!/bin/sh\necho 'the declared project folder must be a real folder'\nexit 1\n",
    )?;
    fs::set_permissions(d.join("ozbox"), fs::Permissions::from_mode(0o755))?;
    a.request("dddddddd22", "ensure-runner app");
    let o = a.process("");
    assert!(o.status.success(), "{}", text(&o));
    let ans = a.answer("dddddddd22");
    assert!(
        !ans.starts_with("status=ok") && ans.contains("real folder"),
        "{ans}"
    );
    Ok(())
}

#[test]
fn an_old_cloudflared_env_file_is_moved_into_the_store_and_destroyed() -> R {
    let a = Admin::new();
    let d = a.dir.path();
    fs::write(
        d.join("ozbox"),
        format!(
            "#!/bin/sh\necho \"$@\" >> '{0}/ozbox.args'\ncat >> '{0}/ozbox.stdin'\n",
            d.display()
        ),
    )?;
    fs::set_permissions(d.join("ozbox"), fs::Permissions::from_mode(0o755))?;
    // the stand-in for shred removes the file but records that it was asked to
    fs::write(
        d.join("shred"),
        format!(
            "#!/bin/sh\necho \"$@\" >> '{0}/shred.log'\nshift\nrm -f \"$@\"\n",
            d.display()
        ),
    )?;
    fs::set_permissions(d.join("shred"), fs::Permissions::from_mode(0o755))?;
    let token = "abcdabcdabcdabcdabcdabcd";
    fs::create_dir_all(d.join("home/.config/ozbox"))?;
    fs::create_dir_all(d.join("home/.config/systemd/user"))?;
    fs::write(
        d.join("home/.config/ozbox/cloudflared.env"),
        format!("TUNNEL_TOKEN={token}\n"),
    )?;
    fs::write(
        d.join("home/.config/systemd/user/ozbox-cloudflared.service"),
        "x",
    )?;
    a.request("eeeeeeee01", "migrate-legacy-tunnel");
    a.request("eeeeeeee02", "migrate-legacy-tunnel");
    let o = a.process("");
    assert!(o.status.success(), "{}", text(&o));
    assert!(
        a.answer("eeeeeeee01").starts_with("status=ok"),
        "{}",
        a.answer("eeeeeeee01")
    );
    assert!(
        fs::read_to_string(d.join("ozbox.args"))?.contains("secrets put --name tunnel-token-ide")
    );
    assert_eq!(fs::read_to_string(d.join("ozbox.stdin"))?.trim(), token);
    assert!(!d.join("home/.config/ozbox/cloudflared.env").exists());
    assert!(!d
        .join("home/.config/systemd/user/ozbox-cloudflared.service")
        .exists());
    assert!(log(d, "runuser").contains("disable --now ozbox-cloudflared.service"));
    assert!(log(d, "systemctl").contains("enable --now ozbox-code-connector.service"));
    // the token is in no answer, and a second run finds nothing to do
    assert!(!a.answer("eeeeeeee01").contains(token));
    assert!(a.answer("eeeeeeee02").contains("no old tunnel token file"));
    Ok(())
}

#[test]
fn the_launcher_is_socket_activated_for_the_box_user_only_and_the_secrets_service_listens_on_the_new_sockets(
) {
    let s = read("infra/cloud-init/scripts/ozbox-secrets-setup.sh");
    assert!(s.contains("ListenStream=/run/ozbox-runner/launch.sock"));
    assert!(
        s.contains("SocketMode=0660")
            && s.contains("SocketGroup=ozbox")
            && s.contains("Accept=yes")
    );
    assert!(s.contains("ExecStart=/usr/local/bin/ozbox secrets run-as"));
    assert!(s.contains("d /run/ozbox-runner/env       0700 root root"));
    assert!(s.contains("--import-socket /run/ozbox-secrets/import/import.sock"));
    assert!(s.contains("--runner-socket /run/ozbox-secrets/resolver/resolver.sock"));
    assert!(s.contains("ozbox-admin.sh --run migrate-legacy-tunnel"));
}

// ---- the box's secrets declaration where the provider has no instance tags (Hetzner) ----

struct BoxSecrets {
    dir: tempfile::TempDir,
}

impl BoxSecrets {
    fn new(gate: &str) -> Self {
        let dir = tempfile::tempdir().unwrap();
        fs::create_dir_all(dir.path().join("requests")).unwrap();
        recorder(dir.path(), "systemctl");
        // a stand-in for `ozbox secrets gate`: it answers how the change was allowed, or refuses
        fs::write(
            dir.path().join("ozbox"),
            format!("#!/bin/sh\n{TAKE_FILE}cat >/dev/null\n{gate}\n"),
        )
        .unwrap();
        fs::set_permissions(dir.path().join("ozbox"), fs::Permissions::from_mode(0o755)).unwrap();
        BoxSecrets { dir }
    }

    fn run(&self, args: &[&str]) -> Output {
        let d = self.dir.path();
        let me = String::from_utf8_lossy(&Command::new("id").arg("-u").output().unwrap().stdout)
            .trim()
            .to_string();
        sh(
            &script("ozbox-box-secrets.sh"),
            args,
            &[
                ("OZBOX_ADMIN_DIR", &d.to_string_lossy()),
                ("OZBOX_SYSTEMCTL", &d.join("systemctl").to_string_lossy()),
                ("OZBOX_BIN", &d.join("ozbox").to_string_lossy()),
                (
                    "OZBOX_BOX_SECRETS_ENV",
                    &d.join("box-secrets.env").to_string_lossy(),
                ),
                ("OZBOX_BAO_ENV", &d.join("bao.env").to_string_lossy()),
                ("OZBOX_REQUESTER_UID", &me),
            ],
        )
        .unwrap()
    }

    fn file(&self, n: &str) -> String {
        fs::read_to_string(self.dir.path().join(n)).unwrap_or_default()
    }
}

fn hexs(s: &str) -> String {
    s.bytes().map(|b| format!("{b:02x}")).collect()
}

#[test]
fn the_declaration_is_written_as_the_settings_file_the_loader_reads_and_the_secrets_are_reloaded(
) -> R {
    // allowed by a second factor: in bootstrap a vault address is not the box user's to set (see below)
    let b = BoxSecrets::new("echo laptop-key:laptop");
    let o = b.run(&[
        "write-box-secrets",
        "-",
        "openbao",
        "main",
        "ozbox..dev",
        &hexs("https://vault.example.com:8200"),
        "secret",
    ]);
    assert!(o.status.success(), "{}", text(&o));
    assert_eq!(
        b.file("box-secrets.env"),
        "# written by ozbox write-box-secrets (no instance tags here)\n\
         OZBOX_BOX_SECRETS_BACKEND=openbao\nOZBOX_BOX_SECRETS_PATH=/ozbox/dev\nOZBOX_BOX_ROLE=main\nOZBOX_BOX_SECRETS_REGION=\n\
         OZBOX_BOX_SECRETS_MOUNT=secret\nBAO_ADDR=https://vault.example.com:8200\n"
    );
    assert!(log(b.dir.path(), "systemctl").contains("restart ozbox-box-secrets.service"));
    // removing it removes only a file this script wrote
    let c = b.run(&["clear-box-secrets", "-"]);
    assert!(
        c.status.success() && !b.dir.path().join("box-secrets.env").exists(),
        "{}",
        text(&c)
    );
    fs::write(
        b.dir.path().join("box-secrets.env"),
        "OZBOX_BOX_SECRETS_BACKEND=openbao\n",
    )?;
    let c = b.run(&["clear-box-secrets", "-"]);
    assert!(text(&c).contains("placed by hand") && b.dir.path().join("box-secrets.env").exists());
    Ok(())
}

#[test]
fn the_declaration_refuses_anything_that_is_not_plain_and_a_refused_approval_writes_nothing() -> R {
    let b = BoxSecrets::new("echo bootstrap");
    let good = hexs("https://v.example.com");
    for args in [
        vec![
            "write-box-secrets",
            "-",
            "aws-ssm",
            "main",
            "a",
            "-",
            "secret",
        ],
        vec![
            "write-box-secrets",
            "-",
            "openbao",
            "Main",
            "a",
            "-",
            "secret",
        ],
        vec![
            "write-box-secrets",
            "-",
            "openbao",
            "main",
            "a...b",
            "-",
            "secret",
        ],
        vec![
            "write-box-secrets",
            "-",
            "openbao",
            "main",
            ".a",
            "-",
            "secret",
        ],
        vec![
            "write-box-secrets",
            "-",
            "openbao",
            "main",
            "a",
            "zz",
            "secret",
        ],
        vec![
            "write-box-secrets",
            "-",
            "openbao",
            "main",
            "a",
            &hexs("http://v.example.com"),
            "secret",
        ],
        vec![
            "write-box-secrets",
            "-",
            "openbao",
            "main",
            "a",
            &hexs("https://v.example.com/x"),
            "secret",
        ],
        vec![
            "write-box-secrets",
            "-",
            "openbao",
            "main",
            "a",
            &good,
            "bad/mount",
        ],
        vec!["write-box-secrets", "-", "openbao", "main", "a"],
    ] {
        let o = b.run(&args);
        assert!(!o.status.success(), "{args:?}");
        assert!(!b.dir.path().join("box-secrets.env").exists(), "{args:?}");
    }
    // a box with a second factor refuses without an approval, and writes nothing
    let r = BoxSecrets::new("echo 'this change needs a fresh approval'; exit 1");
    let o = r.run(&[
        "write-box-secrets",
        "-",
        "openbao",
        "main",
        "a",
        "-",
        "secret",
    ]);
    assert!(!o.status.success() && text(&o).contains("fresh approval"));
    assert!(!r.dir.path().join("box-secrets.env").exists());
    assert!(log(r.dir.path(), "systemctl").is_empty());
    Ok(())
}

#[test]
fn an_approval_is_bound_to_the_declaration_and_its_address() -> R {
    // the stand-in gate records what it was asked; the laptop computes the same binding (run/box_secrets.rs)
    let b =
        BoxSecrets::new("echo \"$*\" >>\"$(dirname \"$0\")/gate.args\"; echo laptop-key:laptop");
    let o = b.run(&[
        "write-box-secrets",
        "CODE-1234",
        "openbao",
        "main",
        "ozbox..dev",
        &hexs("https://vault.example.com:8200"),
        "secret",
    ]);
    assert!(o.status.success(), "{}", text(&o));
    assert!(b
        .file("gate.args")
        .contains("--scope box-secrets --project declaration --env d-7805e83e21b45add"));
    Ok(())
}

#[test]
fn a_new_vault_address_removes_the_token_and_bootstrap_cannot_change_it() -> R {
    let addr = |a: &str| hexs(a);
    let write = |b: &BoxSecrets, a: &str| {
        b.run(&[
            "write-box-secrets",
            "-",
            "openbao",
            "main",
            "ozbox..dev",
            &addr(a),
            "secret",
        ])
    };
    // with a second factor: the address changes, and the token placed for the old one goes in the same step
    let b = BoxSecrets::new("echo laptop-key:laptop");
    assert!(write(&b, "https://vault.example.com").status.success());
    fs::write(
        b.dir.path().join("bao.env"),
        "BAO_TOKEN=hvs.SENTINEL-old-token-0123456789\n",
    )?;
    // the same address again keeps it
    assert!(write(&b, "https://vault.example.com").status.success());
    assert!(b.dir.path().join("bao.env").exists());
    let o = write(&b, "https://evil.example");
    assert!(o.status.success(), "{}", text(&o));
    assert!(text(&o).contains("token was removed"));
    assert!(!b.dir.path().join("bao.env").exists());
    assert!(!text(&o).contains("SENTINEL"));
    // clearing the declaration takes the token too
    fs::write(b.dir.path().join("bao.env"), "BAO_TOKEN=x\n")?;
    assert!(b.run(&["clear-box-secrets", "-"]).status.success());
    assert!(!b.dir.path().join("bao.env").exists());

    // bootstrap: an address cannot be set or changed, and nothing changes while a token is in place
    let z = BoxSecrets::new("echo bootstrap");
    let o = write(&z, "https://evil.example");
    assert!(
        !o.status.success() && text(&o).contains("no second factor"),
        "{}",
        text(&o)
    );
    assert!(!z.dir.path().join("box-secrets.env").exists());
    // no address at all is still a bootstrap declaration a fresh box may make
    assert!(z
        .run(&[
            "write-box-secrets",
            "-",
            "openbao",
            "main",
            "ozbox..dev",
            "-",
            "secret"
        ])
        .status
        .success());
    fs::write(
        z.dir.path().join("bao.env"),
        "BAO_TOKEN=hvs.SENTINEL-0123456789abcdef\n",
    )?;
    let o = z.run(&[
        "write-box-secrets",
        "-",
        "openbao",
        "main",
        "ozbox..other",
        "-",
        "secret",
    ]);
    assert!(!o.status.success(), "{}", text(&o));
    assert!(z
        .file("box-secrets.env")
        .contains("OZBOX_BOX_SECRETS_PATH=/ozbox/dev"));
    assert!(z.dir.path().join("bao.env").exists());
    // nor can it be removed, which would take the token with it
    assert!(!z.run(&["clear-box-secrets", "-"]).status.success());
    assert!(z.dir.path().join("box-secrets.env").exists() && z.dir.path().join("bao.env").exists());
    Ok(())
}

#[test]
fn the_vault_token_goes_to_a_root_only_file_once_and_never_appears_in_any_output() -> R {
    let b = BoxSecrets::new("echo bootstrap");
    let token = "hvs.SENTINEL-bao-token-0123456789abcdef";
    let id = "0123456789abcdef";
    fs::write(
        b.dir.path().join(format!("requests/{id}.tok")),
        format!("{token}\n"),
    )?;
    let o = b.run(&["place-bao-token", id, "-"]);
    assert!(o.status.success(), "{}", text(&o));
    assert!(!text(&o).contains(token));
    assert_eq!(b.file("bao.env"), format!("BAO_TOKEN={token}\n"));
    let mode = fs::metadata(b.dir.path().join("bao.env"))?
        .permissions()
        .mode()
        & 0o777;
    assert_eq!(mode, 0o600);
    assert!(
        !b.dir.path().join(format!("requests/{id}.tok")).exists(),
        "the request file is taken once"
    );
    // a token of the wrong shape, or a missing file, stores nothing
    fs::write(b.dir.path().join("bao.env"), "")?;
    fs::write(b.dir.path().join(format!("requests/{id}.tok")), "short\n")?;
    assert!(!b.run(&["place-bao-token", id, "-"]).status.success());
    assert!(b.file("bao.env").is_empty());
    assert!(!b.run(&["place-bao-token", id, "-"]).status.success());
    // nothing in the declaration script writes the token anywhere else
    assert!(!b.file("box-secrets.env").contains(token));
    Ok(())
}

#[test]
fn a_token_file_is_read_once_through_the_programs_descriptor_reader_never_by_name_twice() {
    // checking the name and then reading it again is a race the box user, who owns the file, can win with a link
    for f in [
        "infra/cloud-init/scripts/ozbox-admin.sh",
        "infra/cloud-init/scripts/ozbox-box-secrets.sh",
    ] {
        let s = read(f);
        assert!(
            s.contains("host-guard take-file --dir \"$dir/requests\" --id \"$tid\""),
            "{f}"
        );
        assert!(
            !s.contains("head -n 1 \"$tok\""),
            "{f} reads the token file by name"
        );
    }
}

#[test]
fn collect_logs_names_the_tool_installer_the_loaded_security_modules_and_the_kernels_denials() -> R
{
    let a = Admin::new();
    let d = a.dir.path();
    // a journalctl that says which units and filters it was asked for
    fs::write(
        d.join("journalctl"),
        "#!/bin/sh\necho \"journalctl $*\" >> '%D/journal.calls'\necho \"line from $*\"\n"
            .replace("%D", &d.to_string_lossy()),
    )?;
    fs::write(
        d.join("lsm"),
        "lockdown,capability,landlock,yama,apparmor,ima,evm\n",
    )?;
    a.request("dddddddd05", "collect-logs");
    let o = {
        let me = String::from_utf8_lossy(&Command::new("id").arg("-u").output()?.stdout)
            .trim()
            .to_string();
        sh(
            &script("ozbox-admin.sh"),
            &[],
            &[
                ("OZBOX_ADMIN_DIR", &d.join("run").to_string_lossy()),
                ("OZBOX_ADMIN_LOG", &d.join("audit.log").to_string_lossy()),
                ("OZBOX_JOURNALCTL", &d.join("journalctl").to_string_lossy()),
                ("OZBOX_LSM_LIST", &d.join("lsm").to_string_lossy()),
                ("OZBOX_REQUESTER_UID", &me),
            ],
        )?
    };
    assert!(o.status.success(), "{}", text(&o));
    let out = a.answer("dddddddd05");
    let calls = fs::read_to_string(d.join("journal.calls"))?;
    assert!(
        calls.contains("-u ozbox-tools.service") && calls.contains("-u ozbox-tools.path"),
        "{calls}"
    );
    assert!(
        calls.contains("-k -n 50"),
        "the kernel's denial lines are asked for: {calls}"
    );
    assert!(
        calls.contains("apparmor=\"DENIED\"") && calls.contains("type=1326"),
        "{calls}"
    );
    assert!(
        out.contains("== ozbox-tools.service ==") && out.contains("== security modules loaded =="),
        "{out}"
    );
    assert!(
        out.contains("lockdown,capability,landlock,yama,apparmor"),
        "{out}"
    );
    Ok(())
}

#[test]
fn the_request_helper_takes_an_approval_code_on_standard_input_and_never_in_its_arguments() -> R {
    use std::io::Write;
    use std::process::Stdio;
    let d = tempfile::tempdir()?;
    fs::create_dir_all(d.path().join("requests"))?;
    fs::create_dir_all(d.path().join("results"))?;
    // an answer is waiting before the request is even made, so the helper does not wait
    let run = |args: &[&str], stdin: &str| -> std::io::Result<Output> {
        let mut c = Command::new("bash")
            .arg(script("ozbox-admin-request.sh"))
            .args(args)
            .env("OZBOX_ADMIN_DIR", d.path())
            .env("OZBOX_ADMIN_WAIT", "1")
            .env_remove("BASH_ENV")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()?;
        c.stdin.take().unwrap().write_all(stdin.as_bytes())?;
        c.wait_with_output()
    };
    let request_text = || -> String {
        fs::read_dir(d.path().join("requests"))
            .unwrap()
            .filter_map(|e| e.ok())
            .map(|e| fs::read_to_string(e.path()).unwrap_or_default())
            .collect()
    };
    // no answer comes (nothing is listening here), but the request file is what matters: its last word is the code
    let _ = run(
        &[
            "--approval-stdin",
            "replace-tunnel-token",
            "cloudflare",
            "0123456789abcdef",
        ],
        "ABCD-EFGH-JKMN-PQRS\n",
    )?;
    assert_eq!(
        request_text().trim(),
        "replace-tunnel-token cloudflare 0123456789abcdef ABCD-EFGH-JKMN-PQRS"
    );
    // a line that is not a code is refused and writes no request
    for f in fs::read_dir(d.path().join("requests"))? {
        fs::remove_file(f?.path())?;
    }
    let o = run(
        &[
            "--approval-stdin",
            "replace-tunnel-token",
            "cloudflare",
            "0123456789abcdef",
        ],
        "x; id\n",
    )?;
    assert!(
        !o.status.success() && request_text().is_empty(),
        "{}",
        text(&o)
    );
    // the program carries the flag in its own text (the laptop-side program reads it to decide how to pass the code)
    assert!(read("infra/cloud-init/scripts/ozbox-admin-request.sh").contains("--approval-stdin"));
    Ok(())
}

/// The dashboard installer's branch for a box whose dashboard already runs as its own user, run for real with the box's
/// paths pointed at a temporary directory: the token goes through the root helper's request program (not the image's `ozbox`
/// program, which a box from before the flag cannot be relied on to understand), the code on standard input when that
/// program reads it there and as the last word when it is older, and a refusal is said in the installer's own words.
#[test]
fn the_installer_hands_a_new_token_to_the_root_helper_on_a_box_whose_dashboard_runs_as_its_own_user(
) -> R {
    let d = tempfile::tempdir()?;
    let p = d.path();
    fs::create_dir_all(p.join("requests"))?;
    fs::write(p.join("unit"), "")?;
    let setup = read("infra/box/dashboard-setup.sh");
    let branch = setup
        .split("if [ -e /etc/systemd/system/ozbox-dashboard.service ]; then")
        .nth(1)
        .unwrap()
        .split("\nfi\n")
        .next()
        .unwrap()
        .to_string();
    let make_req = |name: &str, reads_stdin: bool, fail_with: &str| {
        let f = p.join(name);
        fs::write(
            &f,
            format!(
                "#!/bin/sh\n# {}\necho \"$@\" > '{d}/{name}.args'\ncat > '{d}/{name}.stdin'\ncat '{d}/requests/'*.tok > '{d}/{name}.token' 2>/dev/null\n{}",
                if reads_stdin { "--approval-stdin" } else { "no flag" },
                if fail_with.is_empty() {
                    "echo status=ok; echo stored".to_string()
                } else {
                    format!("echo status=failed; echo '{fail_with}'; exit 3")
                },
                d = p.display(),
            ),
        )
        .unwrap();
        fs::set_permissions(&f, fs::Permissions::from_mode(0o755)).unwrap();
        f
    };
    let run = |req: &Path, token: &str, code: &str| -> Output {
        let body = branch
            .replace(
                "/etc/systemd/system/ozbox-dashboard.service",
                &p.join("unit").to_string_lossy(),
            )
            .replace("/usr/local/bin/ozbox-admin-request", &req.to_string_lossy())
            .replace(
                "/run/ozbox-admin/requests",
                &p.join("requests").to_string_lossy(),
            )
            .replace("$home", &p.join("home").to_string_lossy());
        let script = format!(
            "set -euo pipefail\nTUNNEL_ARGS=(cloudflare --public-url https://x.example --token-stdin)\nTUNNEL_TOKEN='{token}'\nTUNNEL_APPROVAL='{code}'\nif [ -e {} ]; then{body}\nfi\n",
            p.join("unit").display()
        );
        fs::write(p.join("branch.sh"), script).unwrap();
        Command::new("bash")
            .arg(p.join("branch.sh"))
            .env_remove("BASH_ENV")
            .output()
            .unwrap()
    };
    let token = "tok-SENTINELSENTINELSENTINEL0123";
    // a helper that reads the code on stdin
    let new = make_req("new", true, "");
    let o = run(&new, token, "ABCD-EFGH-JKMN-PQRS");
    assert!(text(&o).contains("tunnel-token-stored"), "{}", text(&o));
    let args = fs::read_to_string(p.join("new.args"))?;
    assert!(
        args.starts_with("--approval-stdin replace-tunnel-token cloudflare "),
        "{args}"
    );
    assert!(
        !args.contains("ABCD-EFGH") && !args.contains(token),
        "{args}"
    );
    assert_eq!(
        fs::read_to_string(p.join("new.stdin"))?.trim(),
        "ABCD-EFGH-JKMN-PQRS"
    );
    assert_eq!(
        fs::read_to_string(p.join("new.token"))?,
        token,
        "the token was in the private file when the helper ran"
    );
    assert!(
        fs::read_dir(p.join("requests"))?.next().is_none(),
        "the token file is not left behind"
    );
    // a helper from before the flag takes the code as the last word, and the token is still no argument
    let old = make_req("old", false, "");
    let o = run(&old, token, "ABCD-EFGH-JKMN-PQRS");
    assert!(text(&o).contains("tunnel-token-stored"), "{}", text(&o));
    let args = fs::read_to_string(p.join("old.args"))?;
    assert!(
        args.trim_end().ends_with("ABCD-EFGH-JKMN-PQRS")
            && !args.contains("--approval-stdin")
            && !args.contains(token),
        "{args}"
    );
    // with no code at all, no code word is sent
    let o = run(&old, token, "");
    assert!(text(&o).contains("tunnel-token-stored"), "{}", text(&o));
    assert_eq!(
        fs::read_to_string(p.join("old.args"))?
            .split_whitespace()
            .count(),
        3
    );
    // a refusal is said in the installer's words, so the laptop can show how to get an approval
    let no = make_req(
        "no",
        true,
        "this change needs a fresh approval from the dashboard: run the command again with --approval CODE",
    );
    let o = run(&no, token, "");
    assert!(!o.status.success());
    let err = String::from_utf8_lossy(&o.stderr).to_string();
    assert!(
        err.contains("did not take the tunnel token")
            && err.contains("fresh approval")
            && !err.contains(token),
        "{err}"
    );
    assert!(fs::read_dir(p.join("requests"))?.next().is_none());
    Ok(())
}

#[test]
fn collect_logs_blanks_bearer_tokens_quoted_values_and_known_prefixes() -> R {
    let a = Admin::new();
    let d = a.dir.path();
    // the journal of each unit holds lines shaped like cloudflared's and the dashboard's
    fs::write(
        d.join("journalctl"),
        "#!/bin/sh\nprintf '%s\\n' 'INF Authorization: Bearer eyJSENTINEL1.abc/def==' '{\"tunnelToken\":\"SENTINEL2\",\"keep\":\"visible\"}' 'TUNNEL_TOKEN=SENTINEL3abcdef' 'GET /x?password=SENTINEL4 ok' 'key ozrt_SENTINEL5'\n",
    )?;
    a.request("dddddddd03", "collect-logs");
    let o = a.process("");
    assert!(o.status.success(), "{}", text(&o));
    let out = a.answer("dddddddd03");
    assert!(
        out.contains("visible") && out.contains("[redacted]"),
        "{out}"
    );
    assert!(!out.contains("SENTINEL"), "{out}");
    Ok(())
}

#[test]
fn the_root_helper_hands_these_actions_to_the_program_and_the_program_carries_the_script() {
    let a = read("infra/cloud-init/scripts/ozbox-admin.sh");
    assert!(a.contains("write-box-secrets|clear-box-secrets|place-bao-token)"));
    assert!(a.contains("secrets box-secrets-admin"));
    // the script is not in the first-boot configuration (its limit is tight); the program includes it
    let t = read("infra/cloud-init/box.yaml.tftpl");
    assert!(!t.contains("ozbox-box-secrets.sh"));
    let c = read("crates/ozbox-cli/src/secrets_cli.rs");
    assert!(c.contains("include_str!(\"../../../infra/cloud-init/scripts/ozbox-box-secrets.sh\")"));
}

// ---- the browser's own user (ADR 0037, amendment 4) ----

struct BrowserSetup {
    dir: tempfile::TempDir,
}

impl BrowserSetup {
    /// A machine with stand-ins for the account and service commands. `has` names what already exists on it, as the
    /// files `getent.<database>.<key>` and `user-exists`; `stat_uid` is the owner the folders are found with.
    fn new(has: &[&str], stat_uid: &str) -> Self {
        let dir = tempfile::tempdir().unwrap();
        let d = dir.path();
        for n in [
            "useradd",
            "groupadd",
            "passwd",
            "chown",
            "systemctl",
            "chgrp",
            "systemd-tmpfiles",
            "setfacl",
        ] {
            recorder(d, n);
        }
        // install records what it was asked and makes the folder, because the staging copy needs one
        fs::write(
            d.join("install"),
            format!(
                "#!/bin/sh\necho \"$@\" >> '{}/install.log'\neval last=\\${{$#}}\nmkdir -p \"$last\"\n",
                d.display()
            ),
        )
        .unwrap();
        fs::set_permissions(d.join("install"), fs::Permissions::from_mode(0o755)).unwrap();
        // runuser records what it was asked, then does it as the test's own user (the copy into the private folder is its job)
        fs::write(
            d.join("runuser"),
            format!(
                "#!/bin/sh\necho \"$@\" >> '{}/runuser.log'\nshift 3\nexec \"$@\"\n",
                d.display()
            ),
        )
        .unwrap();
        fs::set_permissions(d.join("runuser"), fs::Permissions::from_mode(0o755)).unwrap();
        // `id -u` answers the browser user's id; `id <user>` succeeds only when the user exists
        fs::write(
            d.join("id"),
            format!(
                "#!/bin/sh\nif [ \"$1\" = -u ]; then echo 1501; exit 0; fi\n[ -f '{}/user-exists' ]\n",
                d.display()
            ),
        )
        .unwrap();
        fs::write(
            d.join("getent"),
            format!("#!/bin/sh\n[ -f '{}/getent.'\"$1\".\"$2\" ]\n", d.display()),
        )
        .unwrap();
        fs::write(d.join("stat"), format!("#!/bin/sh\necho {stat_uid}\n")).unwrap();
        for n in ["id", "getent", "stat"] {
            fs::set_permissions(d.join(n), fs::Permissions::from_mode(0o755)).unwrap();
        }
        for h in has {
            fs::write(d.join(h), "").unwrap();
        }
        fs::create_dir_all(d.join("units")).unwrap();
        fs::create_dir_all(d.join("tmpfiles")).unwrap();
        BrowserSetup { dir }
    }

    fn run(&self) -> Output {
        self.run_with(&[])
    }

    fn run_with(&self, extra: &[(&str, &str)]) -> Output {
        let d = self.dir.path();
        let p = |n: &str| d.join(n).to_string_lossy().into_owned();
        let mut env: Vec<(&str, &str)> = Vec::new();
        let base = [
            ("OZBOX_BROWSER_ROOT", &p("work/ozbox-browser")),
            ("OZBOX_UNIT_DIR", &p("units")),
            ("OZBOX_TMPFILES_DIR", &p("tmpfiles")),
            ("OZBOX_UPLOADS", &p("work/uploads")),
            ("OZBOX_OLD_PROFILES", &p("work/.ozbox/browser/profiles")),
            ("OZBOX_ID", &p("id")),
            ("OZBOX_GETENT", &p("getent")),
            ("OZBOX_STAT", &p("stat")),
            ("OZBOX_USERADD", &p("useradd")),
            ("OZBOX_GROUPADD", &p("groupadd")),
            ("OZBOX_PASSWD", &p("passwd")),
            ("OZBOX_INSTALL", &p("install")),
            ("OZBOX_CHOWN", &p("chown")),
            ("OZBOX_SYSTEMCTL", &p("systemctl")),
            ("OZBOX_RUNUSER", &p("runuser")),
            ("OZBOX_CHGRP", &p("chgrp")),
            ("OZBOX_SETFACL", &p("setfacl")),
            ("OZBOX_TMPFILES", &p("systemd-tmpfiles")),
            ("OZBOX_RUN_DIR", &p("run/ozbox-browser")),
        ];
        env.extend(base.iter().map(|(k, v)| (*k, v.as_str())));
        env.extend_from_slice(extra);
        sh(&script("ozbox-browser-setup.sh"), &[], &env).unwrap()
    }

    fn unit(&self, n: &str) -> String {
        fs::read_to_string(self.dir.path().join("units").join(n)).unwrap_or_default()
    }
}

#[test]
fn the_browser_user_is_made_with_a_fixed_id_no_login_and_a_locked_password() {
    let s = BrowserSetup::new(&[], "1501");
    let o = s.run();
    assert!(o.status.success(), "{}", text(&o));
    let d = s.dir.path();
    let adds = log(d, "useradd");
    assert!(
        adds.contains("--system")
            && adds.contains("--uid 1501")
            && adds.contains("--shell /usr/sbin/nologin")
            && adds.contains("ozbox-browser"),
        "{adds}"
    );
    assert!(
        !adds.contains("--groups"),
        "no supplementary group: it must not reach the box daemon's socket, nor be in the box group"
    );
    assert!(log(d, "groupadd").contains("--gid 1501 ozbox-browser"));
    assert!(log(d, "passwd").contains("--lock ozbox-browser"));
}

#[test]
fn the_browsers_folders_have_the_owners_and_modes_that_keep_the_private_part_private() {
    let s = BrowserSetup::new(&[], "1501");
    s.run();
    let dirs = log(s.dir.path(), "install");
    let root = s.dir.path().join("work/ozbox-browser");
    let r = root.display();
    // the root is root's: the browser's user can enter it but cannot rename `private` or `shared`, so root never follows a
    // link it plants
    assert!(
        dirs.contains(&format!("-d -m 0751 -o root -g ozbox {r}\n")),
        "{dirs}"
    );
    // the shared part: the browser's user writes, the box's group reads, nobody else
    assert!(
        dirs.contains(&format!("-d -m 2750 -o ozbox-browser -g ozbox {r}/shared")),
        "{dirs}"
    );
    // the private part: 0700, its own group, never the box's; what is inside is made by that user itself
    assert!(
        dirs.contains(&format!(
            "-d -m 0700 -o ozbox-browser -g ozbox-browser {r}/private\n"
        )),
        "{dirs}"
    );
    let made = log(s.dir.path(), "runuser");
    assert!(
        made.contains(&format!(
            "-u ozbox-browser -- mkdir -p -m 0700 {r}/private/home {r}/private/profiles"
        )),
        "{made}"
    );
    // the default upload folder is made readable by others, because the worker is not the box user
    assert!(dirs.contains("-d -m 0755 -o ozbox -g ozbox"), "{dirs}");
}

#[test]
fn the_launcher_socket_is_the_dashboards_and_never_the_box_groups() {
    let s = BrowserSetup::new(&[], "1501");
    s.run();
    let sock = s.unit("ozbox-browser.socket");
    assert!(sock.contains("ListenStream=/run/ozbox-browser/launch.sock"));
    assert!(sock.contains("SocketMode=0660") && sock.contains("SocketUser=root"));
    assert!(sock.contains("SocketGroup=ozbox-supervisor"), "{sock}");
    assert!(
        !sock.contains("SocketGroup=ozbox\n"),
        "an agent that could open it could start a worker of its own"
    );
    assert!(sock.contains("Accept=yes") && sock.contains("MaxConnections=16"));
    let svc = s.unit("ozbox-browser@.service");
    assert!(svc.contains("ExecStart=/usr/local/bin/ozbox browser-launch"));
    assert!(svc.contains("StandardInput=socket") && svc.contains("StandardOutput=socket"));
    assert!(
        svc.contains("StandardError=journal"),
        "an error line must never go into the sealed channel"
    );
    // the folder the socket is in is the dashboard's too
    let tmp = fs::read_to_string(s.dir.path().join("tmpfiles/ozbox-browser.conf")).unwrap();
    assert_eq!(
        tmp.trim(),
        "d /run/ozbox-browser 0750 root ozbox-supervisor -"
    );
}

#[test]
fn the_launcher_starts_only_once_the_dashboard_has_a_user_of_its_own() {
    let without = BrowserSetup::new(&[], "1501");
    let o = without.run();
    assert!(text(&o).contains("not started"), "{}", text(&o));
    assert!(!log(without.dir.path(), "systemctl").contains("enable"));
    let with = BrowserSetup::new(&["getent.group.ozbox-supervisor"], "1501");
    let o = with.run();
    assert!(o.status.success(), "{}", text(&o));
    let ctl = log(with.dir.path(), "systemctl");
    assert!(ctl.contains("daemon-reload") && ctl.contains("enable --now ozbox-browser.socket"));
}

#[test]
fn a_second_run_makes_no_second_user() {
    let s = BrowserSetup::new(&["user-exists"], "1501");
    let o = s.run();
    assert!(o.status.success(), "{}", text(&o));
    assert_eq!(log(s.dir.path(), "useradd"), "");
    assert_eq!(log(s.dir.path(), "groupadd"), "");
}

#[test]
fn an_id_that_is_taken_is_not_taken_over_and_the_next_free_system_id_is_used() {
    let s = BrowserSetup::new(&["getent.passwd.1501"], "1501");
    s.run();
    let adds = log(s.dir.path(), "useradd");
    assert!(
        adds.contains("--user-group") && !adds.contains("--uid"),
        "{adds}"
    );
    assert_eq!(log(s.dir.path(), "groupadd"), "");
}

#[test]
fn folders_that_carry_another_id_are_followed_to_the_users_new_id() {
    let same = BrowserSetup::new(&["user-exists"], "1501");
    same.run();
    assert_eq!(log(same.dir.path(), "chown"), "");
    let drifted = BrowserSetup::new(&["user-exists"], "998");
    let o = drifted.run();
    assert!(text(&o).contains("re-owned"), "{}", text(&o));
    let c = log(drifted.dir.path(), "chown");
    assert!(
        c.contains("-R -h ozbox-browser") && c.contains("private"),
        "{c}"
    );
}

#[test]
fn an_existing_upload_folder_is_left_alone() {
    let s = BrowserSetup::new(&["user-exists"], "1501");
    let d = s.dir.path();
    fs::create_dir_all(d.join("work/uploads")).unwrap();
    let o = s.run();
    assert!(o.status.success(), "{}", text(&o));
    assert!(!log(d, "install").contains("-o ozbox -g ozbox"));
}

#[test]
fn old_profiles_are_moved_into_the_private_folder_and_no_copy_is_left_where_the_box_user_reads() {
    let s = BrowserSetup::new(&["user-exists"], "1501");
    let d = s.dir.path();
    let old = d.join("work/.ozbox/browser/profiles");
    fs::create_dir_all(old.join("work/Default")).unwrap();
    fs::write(old.join("work/Default/Cookies"), "COOKIE-JAR").unwrap();
    fs::create_dir_all(old.join("other")).unwrap();
    fs::write(old.join("other/x"), "y").unwrap();
    // a link in the old folder is removed, never followed
    std::os::unix::fs::symlink("/etc", old.join("evil")).unwrap();
    // one profile is already in the private folder: it is not overwritten, and its old copy goes
    let new = d.join("work/ozbox-browser/private/profiles");
    fs::create_dir_all(new.join("other")).unwrap();
    fs::write(new.join("other/x"), "newer").unwrap();
    let o = s.run();
    assert!(o.status.success(), "{}", text(&o));
    assert_eq!(
        fs::read_to_string(new.join("work/Default/Cookies")).unwrap(),
        "COOKIE-JAR",
        "sign-ins carry over"
    );
    assert_eq!(fs::read_to_string(new.join("other/x")).unwrap(), "newer");
    assert!(!old.exists(), "nothing the box user could read is left");
    let c = log(d, "chown");
    assert!(
        c.contains("-R -h ozbox-browser:ozbox-browser") && c.contains(".migrate/old/work"),
        "root only ever re-owns what it moved into its own staging folder: {c}"
    );
    assert!(!c.contains("private/profiles"), "{c}");
    // idempotent: a second run has nothing to move and changes nothing
    let again = s.run();
    assert!(again.status.success(), "{}", text(&again));
    assert_eq!(
        fs::read_to_string(new.join("work/Default/Cookies")).unwrap(),
        "COOKIE-JAR"
    );
}

#[test]
fn the_migration_runs_once_and_a_profile_planted_afterwards_is_not_carried_in() {
    let s = BrowserSetup::new(&["user-exists"], "1501");
    let d = s.dir.path();
    let old = d.join("work/.ozbox/browser/profiles");
    fs::create_dir_all(old.join("a")).unwrap();
    assert!(s.run().status.success());
    assert!(d.join("work/ozbox-browser/private/profiles/a").is_dir());
    fs::create_dir_all(old.join("planted")).unwrap();
    assert!(s.run().status.success());
    assert!(!d
        .join("work/ozbox-browser/private/profiles/planted")
        .exists());
    assert!(old.join("planted").exists(), "untouched after the marker");
}

#[test]
fn a_browser_folder_that_is_a_link_to_the_private_folder_is_refused_and_no_profile_is_lost() {
    let s = BrowserSetup::new(&["user-exists"], "1501");
    let d = s.dir.path();
    let private = d.join("work/ozbox-browser/private");
    fs::create_dir_all(private.join("profiles/signed-in")).unwrap();
    fs::write(private.join("profiles/signed-in/Cookies"), "JAR").unwrap();
    fs::create_dir_all(d.join("work/.ozbox")).unwrap();
    // rm -rf /work/.ozbox/browser; ln -s private /work/.ozbox/browser
    std::os::unix::fs::symlink(&private, d.join("work/.ozbox/browser")).unwrap();
    let o = s.run();
    assert!(
        o.status.success(),
        "the units are still written: {}",
        text(&o)
    );
    assert!(text(&o).contains("symbolic link"), "{}", text(&o));
    assert_eq!(
        fs::read_to_string(private.join("profiles/signed-in/Cookies")).unwrap(),
        "JAR"
    );
    // the marker is written in every terminal case, so a refused box is not left armed
    let marker = d.join("work/ozbox-browser/.profiles-migrated");
    assert_eq!(fs::read_to_string(&marker).unwrap(), "");
    assert!(
        !s.unit("ozbox-browser.socket").is_empty(),
        "the launcher's units do not depend on the migration"
    );
}

#[test]
fn a_browser_folder_owned_by_someone_else_is_refused() {
    let s = BrowserSetup::new(&["user-exists"], "4242");
    let d = s.dir.path();
    fs::create_dir_all(d.join("work/.ozbox/browser/profiles/a")).unwrap();
    let o = s.run();
    assert!(
        text(&o).contains("neither the box user nor root"),
        "{}",
        text(&o)
    );
    assert!(d.join("work/.ozbox/browser/profiles/a").exists());
}

#[test]
fn a_link_planted_in_the_browsers_tree_is_refused_before_root_touches_anything() {
    for planted in ["shared", "private"] {
        let s = BrowserSetup::new(&["user-exists"], "1501");
        let d = s.dir.path();
        let root = d.join("work/ozbox-browser");
        fs::create_dir_all(&root).unwrap();
        std::os::unix::fs::symlink("/etc", root.join(planted)).unwrap();
        let o = s.run();
        assert!(!o.status.success(), "{planted}: {}", text(&o));
        assert!(text(&o).contains("symbolic link"), "{}", text(&o));
        let dirs = log(d, "install");
        assert!(
            !dirs.contains(&format!("{}/{planted}", root.display())),
            "root was never told to change what the link points at: {dirs}"
        );
        assert_eq!(log(d, "chown"), "", "{planted}");
    }
    // the root itself as a link
    let s = BrowserSetup::new(&["user-exists"], "1501");
    let d = s.dir.path();
    fs::create_dir_all(d.join("work")).unwrap();
    std::os::unix::fs::symlink("/etc", d.join("work/ozbox-browser")).unwrap();
    let o = s.run();
    assert!(
        !o.status.success() && log(d, "install").is_empty(),
        "{}",
        text(&o)
    );
}

/// A stand-in for `mv` that first does what the agent does mid-run, then moves. `$1` is what to do.
fn swapping_mv(d: &Path, body: &str) -> PathBuf {
    let p = d.join("mv-swap");
    fs::write(&p, format!("#!/bin/sh\n{body}\nexec /bin/mv \"$@\"\n")).unwrap();
    fs::set_permissions(&p, fs::Permissions::from_mode(0o755)).unwrap();
    p
}

/// A signed-in profile in the private folder, and an old folder holding a planted profile of the same name.
fn signed_in_and_planted(d: &Path) -> (PathBuf, PathBuf) {
    let private = d.join("work/ozbox-browser/private");
    fs::create_dir_all(private.join("profiles/bank/Default")).unwrap();
    fs::write(private.join("profiles/bank/Default/Cookies"), "JAR").unwrap();
    let old = d.join("work/.ozbox/browser/profiles");
    fs::create_dir_all(old.join("bank")).unwrap();
    (private, old)
}

/// the agent swaps the folder it owns for a link to the private folder after the checks and before the move. Root
/// holds the folder it walked into, so the swap changes nothing, and no profile of the person is deleted.
#[test]
fn a_browser_folder_swapped_for_a_link_while_root_works_deletes_no_profile() {
    let s = BrowserSetup::new(&["user-exists"], "1501");
    let d = fs::canonicalize(s.dir.path()).unwrap();
    let (private, _old) = signed_in_and_planted(&d);
    let b = d.join("work/.ozbox/browser");
    let swap = swapping_mv(
        &d,
        &format!(
            "/bin/mv '{b}' '{b}.moved' && ln -s '{p}' '{b}'",
            b = b.display(),
            p = private.display()
        ),
    );
    let o = s.run_with(&[("OZBOX_MV", &swap.to_string_lossy())]);
    assert!(o.status.success(), "{}", text(&o));
    assert_eq!(
        fs::read_to_string(private.join("profiles/bank/Default/Cookies")).unwrap(),
        "JAR",
        "the person's profile survives: {}",
        text(&o)
    );
    assert!(private.join("profiles").is_dir());
    // the swap really happened while root worked (the folder it held is now elsewhere, and the path is a link)
    assert!(b.with_file_name("browser.moved").is_dir());
    assert!(fs::symlink_metadata(&b).unwrap().file_type().is_symlink());
}

/// The same attack one step earlier: the old folder itself is swapped for a link to the private profiles, between the checks
/// and the move. The rename moves the link as a link, which is removed and never followed.
#[test]
fn the_profiles_folder_swapped_for_a_link_is_moved_as_a_link_and_never_followed() {
    let s = BrowserSetup::new(&["user-exists"], "1501");
    let d = fs::canonicalize(s.dir.path()).unwrap();
    let (private, _old) = signed_in_and_planted(&d);
    let swap = swapping_mv(
        &d,
        &format!(
            "rm -rf profiles && ln -s '{}' profiles",
            private.join("profiles").display()
        ),
    );
    let o = s.run_with(&[("OZBOX_MV", &swap.to_string_lossy())]);
    assert!(o.status.success(), "{}", text(&o));
    assert_eq!(
        fs::read_to_string(private.join("profiles/bank/Default/Cookies")).unwrap(),
        "JAR",
        "{}",
        text(&o)
    );
    assert!(text(&o).contains("symbolic link"), "{}", text(&o));
}

/// no recursive chmod or chown is ever given a path inside the agent's tree. Every operand is in the staging folder
/// root made (GNU `chmod -R` follows a link named on its command line; on this macOS test host `chmod -R` does not, so what is
/// proven here is the SHAPE of the calls. GNU behaviour is for a real box).
#[test]
fn root_never_names_the_agents_tree_to_a_recursive_chmod_or_chown() {
    let s = BrowserSetup::new(&["user-exists"], "1501");
    let d = fs::canonicalize(s.dir.path()).unwrap();
    let rec = d.join("chmod");
    fs::write(
        &rec,
        format!(
            "#!/bin/sh\necho \"$@\" >> '{}/chmod.log'\nexec /bin/chmod \"$@\"\n",
            d.display()
        ),
    )
    .unwrap();
    fs::set_permissions(&rec, fs::Permissions::from_mode(0o755)).unwrap();
    let old = d.join("work/.ozbox/browser/profiles");
    fs::create_dir_all(old.join("a/Default")).unwrap();
    fs::write(old.join("a/Default/Cookies"), "J").unwrap();
    let o = s.run_with(&[("OZBOX_CHMOD", &rec.to_string_lossy())]);
    assert!(o.status.success(), "{}", text(&o));
    let all = format!("{}{}", log(&d, "chmod"), log(&d, "chown"));
    assert!(
        !all.contains(".ozbox"),
        "root never names a path in the agent's tree to chmod or chown: {all}"
    );
    assert!(
        log(&d, "chmod").contains(&format!(
            "-R go-rwx {}/work/ozbox-browser/.migrate/old",
            s.dir.path().display()
        )),
        "{}",
        log(&d, "chmod")
    );
    // and the script does not use a copy: the folder is MOVED, so there is no second copy and no window to swap a source in
    let t = read("infra/cloud-init/scripts/ozbox-browser-setup.sh");
    assert!(t.contains("cd -P") && t.contains("pwd -P"));
    assert!(!t.contains("cp_bin") && !t.contains("cp -a"));
}

/// a box that never had old profiles is not left armed. The first run writes the marker, so a folder the agent
/// plants afterwards is never carried into the private folder.
#[test]
fn a_box_without_old_profiles_is_not_left_armed_for_the_agent_to_plant_one() {
    let s = BrowserSetup::new(&["user-exists"], "1501");
    let d = s.dir.path();
    assert!(s.run().status.success());
    let marker = d.join("work/ozbox-browser/.profiles-migrated");
    assert_eq!(fs::read_to_string(&marker).unwrap(), "");
    let old = d.join("work/.ozbox/browser/profiles");
    fs::create_dir_all(old.join("evil/Default")).unwrap();
    fs::write(old.join("evil/Default/Preferences"), "{}").unwrap();
    let o = s.run();
    assert!(o.status.success(), "{}", text(&o));
    assert!(!d.join("work/ozbox-browser/private/profiles/evil").exists());
    assert!(old.join("evil").exists(), "left where it is, and said so");
    assert!(text(&o).contains("not moved again"), "{}", text(&o));
}

/// a move that was secured but could not be handed over keeps its staging folder and is finished by the next run,
/// and only what is in the staging folder is finished (a profile planted meanwhile is not carried in).
#[test]
fn a_move_that_could_not_be_handed_over_is_finished_by_the_next_run_and_nothing_else_is() {
    let s = BrowserSetup::new(&["user-exists"], "1501");
    let d = s.dir.path();
    let old = d.join("work/.ozbox/browser/profiles");
    fs::create_dir_all(old.join("a")).unwrap();
    fs::write(old.join("a/x"), "1").unwrap();
    // a chown that refuses to hand anything to the browser's user
    let failing = d.join("chown-fails");
    fs::write(
        &failing,
        "#!/bin/sh\ncase \"$*\" in *ozbox-browser:*) exit 1;; esac\nexit 0\n",
    )
    .unwrap();
    fs::set_permissions(&failing, fs::Permissions::from_mode(0o755)).unwrap();
    let o = s.run_with(&[("OZBOX_CHOWN", &failing.to_string_lossy())]);
    assert!(
        o.status.success(),
        "the units are still written: {}",
        text(&o)
    );
    let marker = d.join("work/ozbox-browser/.profiles-migrated");
    assert_eq!(fs::read_to_string(&marker).unwrap(), "pending");
    assert!(d.join("work/ozbox-browser/.migrate/old/a/x").exists());
    assert!(
        !old.exists(),
        "the old folder is already out of the agent's reach"
    );
    // the agent plants one meanwhile; the next run (with a working chown) finishes only the staged one
    fs::create_dir_all(old.join("planted")).unwrap();
    assert!(s.run().status.success());
    assert_eq!(fs::read_to_string(&marker).unwrap(), "");
    assert_eq!(
        fs::read_to_string(d.join("work/ozbox-browser/private/profiles/a/x")).unwrap(),
        "1"
    );
    assert!(!d
        .join("work/ozbox-browser/private/profiles/planted")
        .exists());
    assert!(!d.join("work/ozbox-browser/.migrate").exists());
}

#[test]
fn the_launchers_folder_is_made_the_dashboards_before_the_socket_starts() {
    let s = BrowserSetup::new(&["getent.group.ozbox-supervisor"], "1501");
    // the folder already exists, root's own (a socket started first made it)
    fs::create_dir_all(s.dir.path().join("run/ozbox-browser")).unwrap();
    let o = s.run();
    assert!(o.status.success(), "{}", text(&o));
    let d = s.dir.path();
    let conf = d.join("tmpfiles/ozbox-browser.conf");
    assert_eq!(
        log(d, "systemd-tmpfiles").trim(),
        format!("--create {}", conf.display())
    );
    assert!(
        log(d, "chgrp").contains("-h ozbox-supervisor"),
        "{}",
        log(d, "chgrp")
    );
    // and the script itself does that before it enables the socket
    let t = read("infra/cloud-init/scripts/ozbox-browser-setup.sh");
    let create = t.find("\"$tmpfiles_bin\" --create").unwrap();
    let enable = t.find("enable --now ozbox-browser.socket").unwrap();
    assert!(
        create < enable,
        "the entry is applied before the socket starts"
    );
}

#[test]
fn the_launcher_is_small_in_what_it_can_do_and_every_session_has_a_slice_with_a_ceiling() {
    let s = BrowserSetup::new(&[], "1501");
    s.run();
    let svc = s.unit("ozbox-browser@.service");
    for p in [
        "ProtectSystem=strict",
        "NoNewPrivileges=yes",
        "RestrictAddressFamilies=AF_UNIX",
        "MemoryMax=",
        "RuntimeMaxSec=",
    ] {
        assert!(svc.contains(p), "{p}");
    }
    assert!(s.unit("ozbox-browser.slice").contains("MemoryMax=60%"));
}

#[test]
fn the_image_and_first_boot_make_the_browser_user_and_the_reown_script_never_hands_its_files_to_the_box_user(
) {
    let p = read("infra/packer/ozbox-image/scripts/provision.sh");
    assert!(p.contains("OZBOX_BROWSER_ID=1501"));
    assert!(p.contains("groupadd --system --gid \"$OZBOX_BROWSER_ID\" ozbox-browser"));
    assert!(p.contains("--shell /usr/sbin/nologin --comment \"Oz Box browser\" ozbox-browser"));
    assert!(p.contains("passwd --lock ozbox-browser"));
    let t = read("infra/cloud-init/box.yaml.tftpl");
    let sup = t.find("ozbox secrets supervisor-setup").unwrap();
    let br = t.find("ozbox browser-setup").unwrap();
    assert!(
        br > sup,
        "the launcher's group exists only after the dashboard's setup"
    );
    // the script is carried by the program, not by the first-boot configuration (Hetzner's user data is nearly full)
    assert!(!t.contains("ozbox-browser-setup.sh"));
    let r = read("infra/cloud-init/scripts/ozbox-reown.sh");
    assert!(
        r.contains("$1==\"ozbox-browser\""),
        "its files are never an old box user's"
    );
    let c = read("crates/ozbox-cli/src/browser_launch.rs");
    assert!(
        c.contains("include_str!(\"../../../infra/cloud-init/scripts/ozbox-browser-setup.sh\")")
    );
    // the launcher's socket is the dashboard's group's, which exists only once the dashboard's own user is made: that step
    // starts the launcher
    let sup = read("infra/cloud-init/scripts/ozbox-supervisor-setup.sh");
    let made = sup.find("\nensure_user\n").unwrap();
    let setup = sup.find("browser-setup").unwrap();
    assert!(
        setup > made,
        "the browser's setup runs after the supervisor user exists"
    );
}

/// ADR 0040, decision 3: the dashboard user's own socket to the box daemon is bound by systemd, as
/// root, in a folder root owns (`ozboxd-supervisor.socket`, written by the program's supervisor setup) and handed to the
/// daemon. The daemon's unit makes no folder for it and runs no root step in `/run/ozboxd`, which the box user owns.
#[test]
fn the_daemon_unit_makes_no_folder_for_the_supervisor_socket_and_runs_no_root_step() {
    let t = read("infra/cloud-init/box.yaml.tftpl");
    let unit = written_file(&t, "/etc/systemd/system/ozboxd.service");
    // the folder mode is what it was before the dashboard had a socket of its own
    assert!(unit.contains("RuntimeDirectoryMode=0750"), "{unit}");
    assert!(!unit.contains("RuntimeDirectoryMode=0751"));
    // no ExecStartPre at all (the old one was a root `install -d` in the box user's folder)
    assert!(
        !unit
            .lines()
            .any(|l| l.trim_start().starts_with("ExecStartPre")),
        "{unit}"
    );
    assert!(unit.contains("User=ozbox") && unit.contains("Group=ozbox"));
    assert!(!unit.contains("0777") && !unit.contains("RuntimeDirectoryMode=0755"));
    // the socket unit and the drop-in that passes it come from the program's setup script
    let setup = read("infra/cloud-init/scripts/ozbox-supervisor-setup.sh");
    assert!(setup.contains("ListenStream=/run/ozbox-supervisor-api/daemon.sock"));
    assert!(setup.contains("Sockets=ozboxd-supervisor.socket"));
}

/// The rule behind C1, as a guard over everything that can run as root on a box: not one executable line of a script in
/// `infra/`, nor of the first-boot template, names a path under `/run/ozboxd`. A root `install -d`, `chown` or `chmod` there
/// follows a link the box user plants (the box user owns the folder and can fill it), and ends in root.
#[test]
fn nothing_that_runs_as_root_names_a_path_under_the_box_users_run_folder() {
    fn walk(dir: &Path, out: &mut Vec<PathBuf>) {
        for e in fs::read_dir(dir).into_iter().flatten().flatten() {
            let p = e.path();
            if p.is_dir() {
                walk(&p, out);
            } else if matches!(p.extension().and_then(|x| x.to_str()), Some("sh" | "tftpl")) {
                out.push(p);
            }
        }
    }
    let mut files = Vec::new();
    walk(&root().join("infra"), &mut files);
    assert!(files.len() >= 8, "the scan found only {files:?}");
    for f in files {
        let text = fs::read_to_string(&f).unwrap_or_default();
        for (n, l) in text.lines().enumerate() {
            if l.trim_start().starts_with('#') {
                continue;
            }
            assert!(
                !l.contains("run/ozboxd"),
                "{}:{}: a root step names the box user's folder: {l}",
                f.display(),
                n + 1
            );
        }
    }
}

/// G1 F1 (the merge of the scoped dashboard socket with the browser's isolation): the on-box dashboard reads recordings and the
/// documents a session released from the shared folder. G1 takes the dashboard's user out of the box user's group, so the folder
/// grants it read by an ACL entry of its own, as an access entry and a default entry, set by the browser's user (never by
/// root in a tree that user fills), and the group membership is never put back.
#[test]
fn the_dashboards_user_reads_the_shared_folder_by_an_acl_entry_and_not_by_the_box_group() {
    let s = BrowserSetup::new(&["getent.group.ozbox-supervisor"], "1501");
    let o = s.run();
    assert!(o.status.success(), "{}", text(&o));
    let acl = log(s.dir.path(), "setfacl");
    let access = acl.lines().any(|l| {
        l.contains("-R")
            && !l.contains(" -d ")
            && l.contains("u:ozbox-supervisor:rX")
            && l.contains("work/ozbox-browser/shared")
    });
    let default = acl.lines().any(|l| {
        l.contains(" -d ")
            && l.contains("u:ozbox-supervisor:rX")
            && l.contains("work/ozbox-browser/shared")
    });
    assert!(
        access && default,
        "an access entry and a default entry on the shared folder:\n{acl}"
    );
    assert!(
        !acl.contains(":rw") && !acl.contains(":w"),
        "read only: {acl}"
    );
    // set as the browser's user, never by root in a tree that user owns
    let who = log(s.dir.path(), "runuser");
    assert!(
        who.lines()
            .any(|l| l.contains("ozbox-browser") && l.contains("setfacl")),
        "{who}"
    );
    // before the dashboard has a user of its own there is nothing to grant, and nothing is attempted
    let without = BrowserSetup::new(&[], "1501");
    assert!(without.run().status.success());
    assert_eq!(log(without.dir.path(), "setfacl"), "");
    // the script's code never puts the dashboard's user in the box user's group (decision 3 of ADR 0040)
    let code: String = read("infra/cloud-init/scripts/ozbox-browser-setup.sh")
        .lines()
        .filter(|l| !l.trim_start().starts_with('#'))
        .collect::<Vec<_>>()
        .join("\n");
    for bad in [
        "usermod",
        "gpasswd",
        "adduser",
        "SupplementaryGroups",
        "-aG",
    ] {
        assert!(
            !code.contains(bad),
            "{bad}: the dashboard's user is not put in the box user's group"
        );
    }
    // and the folder the worker writes to stays the box group's for the agent
    assert!(code.contains("-m 2750 -o \"$user\" -g ozbox \"$root/shared\""));
}

/// the daemon is ordered after (and pulls in) the box user's manager, which holds the runs that outlive it, so it
/// does not start first and fall back to cgroup scopes for its whole life.
#[test]
fn the_daemon_starts_after_the_box_users_manager() {
    let t = read("infra/cloud-init/box.yaml.tftpl");
    let unit = written_file(&t, "/etc/systemd/system/ozboxd.service");
    let line = |p: &str| {
        unit.lines()
            .map(str::trim_start)
            .find(|l| l.starts_with(p))
            .unwrap_or("")
            .to_string()
    };
    assert!(line("After=").contains("user@1500.service"), "{unit}");
    assert!(line("Wants=").contains("user@1500.service"), "{unit}");
    // never Requires: a manager that is held back (no /work yet) must not stop the daemon
    assert!(!unit.contains("Requires=user@"));
}

#[test]
fn the_hub_daemon_runs_as_its_own_user_from_a_socket_root_binds_and_reaches_no_network() -> R {
    let d = tempfile::tempdir()?;
    let bin = d.path().join("bin");
    fs::create_dir_all(&bin)?;
    // stand-ins: the hub's user exists (the secrets setup made it), and every call is recorded
    for name in ["id", "systemctl", "systemd-tmpfiles"] {
        let p = bin.join(name);
        let body = if name == "id" {
            "#!/bin/sh\nexit 0\n".to_string()
        } else {
            format!(
                "#!/bin/sh\necho \"{name} $@\" >> '{}'\n",
                d.path().join("calls.log").display()
            )
        };
        fs::write(&p, body)?;
        fs::set_permissions(&p, fs::Permissions::from_mode(0o755))?;
    }
    let etc = d.path().join("etc");
    let path = format!(
        "{}:{}",
        bin.display(),
        std::env::var("PATH").unwrap_or_default()
    );
    let env = [
        ("OZBOX_ETC", etc.to_str().unwrap_or_default()),
        ("OZBOX_HUB_NO_SYSTEMCTL", "1"),
        ("PATH", path.as_str()),
    ];
    // a box id that is not one is refused before anything is written
    let bad = sh(&script("ozbox-hub-setup.sh"), &["x;id"], &env)?;
    assert!(!bad.status.success());
    assert!(!etc.join("systemd/system/ozbox-hubd.service").exists());
    let out = sh(&script("ozbox-hub-setup.sh"), &["main-1"], &env)?;
    assert!(out.status.success(), "{}", text(&out));
    let tmpfiles = fs::read_to_string(etc.join("tmpfiles.d/ozbox-hub.conf"))?;
    // the state is the hub user's alone; the socket's folder is root's, entered by the supervisor's group
    assert!(tmpfiles.contains("d /var/lib/ozbox-hub          0700 ozbox-hub ozbox-hub"));
    assert!(tmpfiles.contains("d /run/ozbox-hub/supervisor   0750 root ozbox-supervisor"));
    let sock = fs::read_to_string(etc.join("systemd/system/ozbox-hubd.socket"))?;
    assert!(sock.contains("ListenStream=/run/ozbox-hub/supervisor/hubd.sock"));
    assert!(
        sock.contains("FileDescriptorName=ozbox-hubd.socket") && sock.contains("SocketMode=0660")
    );
    // a socket unit never listens on a port
    assert!(!sock.contains("ListenStream=0") && !sock.contains(":"));
    let unit = fs::read_to_string(etc.join("systemd/system/ozbox-hubd.service"))?;
    assert!(unit.contains("User=ozbox-hub") && unit.contains("--box-id main-1"));
    assert!(unit.contains("--secrets-socket /run/ozbox-secrets/hub/hub.sock"));
    assert!(unit.contains("RestrictAddressFamilies=AF_UNIX"));
    assert!(unit.contains("ProtectSystem=strict") && unit.contains("NoNewPrivileges=true"));
    assert!(unit.contains("CapabilityBoundingSet=\n"));
    // no registrar until the laptop pins one; an existing file is never overwritten
    let regs = etc.join("ozbox/hub-registrars.json");
    assert_eq!(fs::read_to_string(&regs)?.trim(), r#"{"registrars":[]}"#);
    fs::write(
        &regs,
        r#"{"registrars":[{"provider":"aws","public":"00"}]}"#,
    )?;
    let again = sh(&script("ozbox-hub-setup.sh"), &["main-1"], &env)?;
    assert!(again.status.success(), "{}", text(&again));
    assert!(fs::read_to_string(&regs)?.contains("aws"));
    // carried in the program, never in user-data
    let t = read("infra/cloud-init/box.yaml.tftpl");
    assert!(!t.contains("ozbox-hub-setup.sh"));
    Ok(())
}

#[test]
fn the_task_router_gets_a_user_of_its_own_and_the_sockets_split_by_directory_mode() -> R {
    let d = tempfile::tempdir()?;
    let bin = d.path().join("bin");
    fs::create_dir_all(&bin)?;
    // stand-ins for the commands that need root: the user exists after "useradd", and every call is recorded
    for name in ["id", "useradd", "passwd", "systemctl", "systemd-tmpfiles"] {
        let p = bin.join(name);
        let body = if name == "id" {
            "#!/bin/sh\nexit 1\n".to_string()
        } else {
            format!(
                "#!/bin/sh\necho \"{name} $@\" >> '{}'\n",
                d.path().join("calls.log").display()
            )
        };
        fs::write(&p, body)?;
        fs::set_permissions(&p, fs::Permissions::from_mode(0o755))?;
    }
    let etc = d.path().join("etc");
    let path = format!(
        "{}:{}",
        bin.display(),
        std::env::var("PATH").unwrap_or_default()
    );
    let out = sh(
        &script("ozbox-mesh-setup.sh"),
        &[],
        &[
            ("OZBOX_ETC", etc.to_str().unwrap_or_default()),
            ("OZBOX_MESH_NO_SYSTEMCTL", "1"),
            ("PATH", &path),
        ],
    )?;
    assert!(out.status.success(), "{}", text(&out));
    let calls = fs::read_to_string(d.path().join("calls.log")).unwrap_or_default();
    assert!(
        calls.contains("useradd --system")
            && calls.contains("ozbox-mesh")
            && calls.contains("passwd --lock"),
        "{calls}"
    );
    let tmpfiles = fs::read_to_string(etc.join("tmpfiles.d/ozbox-mesh.conf"))?;
    // the directory modes decide who may connect: the box user's group for the agent and relay sockets, root alone for admin
    assert!(tmpfiles.contains("/var/lib/ozbox-mesh      0700 ozbox-mesh ozbox-mesh"));
    assert!(tmpfiles.contains("/run/ozbox-mesh/agent    0750 ozbox-mesh ozbox"));
    assert!(tmpfiles.contains("/run/ozbox-mesh/relay    0750 ozbox-mesh ozbox"));
    assert!(tmpfiles.contains("/run/ozbox-mesh/admin    0700 ozbox-mesh ozbox-mesh"));
    let unit = fs::read_to_string(etc.join("systemd/system/ozbox-mesh.service"))?;
    assert!(
        unit.contains("User=ozbox-mesh") && unit.contains("tasks serve --dir /var/lib/ozbox-mesh")
    );
    assert!(unit.contains("ProtectSystem=strict") && unit.contains("NoNewPrivileges=true"));
    // carried in the program (user-data has a hard size limit), run once at first boot through it
    let t = read("infra/cloud-init/box.yaml.tftpl");
    assert!(
        !t.contains("ozbox-mesh-setup.sh"),
        "the router's setup is not in user-data"
    );
    assert!(t.contains("/usr/local/bin/ozbox tasks router-setup ||"));
    Ok(())
}
