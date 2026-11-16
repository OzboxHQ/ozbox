//! Running restic for the box, as the secrets user. The repository password and the cloud credentials are opened here,
//! put in restic's environment and nowhere else: not in a file the box user can read, and not in a process the box user
//! can look into. The box daemon asks for one of a few exact command shapes and gets the exit status and the output back
//! (ADR 0018). Nothing the daemon sends can name a repository, a password source or a backend option.

use std::io::Read;
use std::process::{Command, Stdio};

use crate::secrets::SecretStore;

/// The names the credentials are kept under in the store.
pub const ENV_SECRET: &str = "restic-env";
pub const PASSWORD_SECRET: &str = "restic-password";

const MAX_OUTPUT: u64 = 16 * 1024 * 1024;

pub struct ResticOut {
    pub status: Option<i32>,
    pub stdout: String,
}

use ozbox_core::backup_scope::{NEVER_BACKED_UP, NEVER_RESTORED};

fn snapshot_ok(s: &str) -> bool {
    (8..=64).contains(&s.len()) && s.bytes().all(|b| b.is_ascii_hexdigit())
}

fn tag_ok(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= 200
        && s.bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'=' | b',' | b'.' | b'_' | b'-'))
}

fn under_work(p: &str) -> bool {
    (p == "/work" || p.starts_with("/work/"))
        && !p.split('/').any(|c| c == "..")
        && !p.bytes().any(|b| b.is_ascii_control())
}

fn number_ok(s: &str) -> bool {
    !s.is_empty() && s.len() <= 4 && s.bytes().all(|b| b.is_ascii_digit())
}

/// Whether `args` is one of the exact shapes the box daemon runs. Anything else is refused: a restic flag can name another
/// repository, run a program (`-o`), read a password from a file or write anywhere.
pub fn args_ok(args: &[String]) -> Result<(), &'static str> {
    const NO: &str = "that restic command is not one this box runs";
    let a: Vec<&str> = args.iter().map(String::as_str).collect();
    let Some(&verb) = a.first() else {
        return Err(NO);
    };
    match verb {
        // backup --one-file-system --tag T [--exclude P]... PATH...
        "backup" => {
            let mut i = 1;
            if a.get(i) != Some(&"--one-file-system") || a.get(i + 1) != Some(&"--tag") {
                return Err(NO);
            }
            if !a.get(i + 2).is_some_and(|t| tag_ok(t)) {
                return Err(NO);
            }
            i += 3;
            let mut excluded = Vec::new();
            while a.get(i) == Some(&"--exclude") {
                match a.get(i + 1) {
                    Some(p) if under_work(p) => excluded.push(*p),
                    _ => return Err(NO),
                }
                i += 2;
            }
            if i >= a.len() || !a[i..].iter().all(|p| under_work(p)) {
                return Err(NO);
            }
            // a backup that would take the private folder (the store's copy, the chain's anchors) is not run
            if !NEVER_BACKED_UP.iter().all(|p| excluded.contains(p)) {
                return Err("a backup must leave out the secrets service's private folder");
            }
            Ok(())
        }
        // forget --prune --tag T --keep-daily N --keep-weekly N --keep-monthly N | forget --prune ID
        "forget" => match a.as_slice() {
            ["forget", "--prune", id] if snapshot_ok(id) => Ok(()),
            ["forget", "--prune", "--tag", t, "--keep-daily", d, "--keep-weekly", w, "--keep-monthly", m]
                if tag_ok(t) && number_ok(d) && number_ok(w) && number_ok(m) =>
            {
                Ok(())
            }
            _ => Err(NO),
        },
        // restore latest|ID --target / | --target /work/...
        // restore latest|ID --target / | --target /work/...  --exclude P... (exactly the never-restored paths)
        "restore" => match a.as_slice() {
            ["restore", snap, "--target", target, rest @ ..]
                if (*snap == "latest" || snapshot_ok(snap))
                    && (*target == "/" || under_work(target)) =>
            {
                let want: Vec<&str> = NEVER_RESTORED
                    .iter()
                    .flat_map(|p| ["--exclude", *p])
                    .collect();
                if rest == want.as_slice() {
                    Ok(())
                } else {
                    Err("a restore must leave out the secrets service's private folder, the audit chain and the backup record")
                }
            }
            _ => Err(NO),
        },
        "snapshots" => match a.as_slice() {
            ["snapshots", "--json", "--tag", t] if tag_ok(t) => Ok(()),
            _ => Err(NO),
        },
        _ => Err(NO),
    }
}

/// The settings rest as hex (the store takes plain single-line values only); see the daemon's helper.
fn hex_decode(h: &str) -> Option<String> {
    if !h.len().is_multiple_of(2) {
        return None;
    }
    let bytes: Option<Vec<u8>> = (0..h.len() / 2)
        .map(|i| u8::from_str_radix(h.get(2 * i..2 * i + 2)?, 16).ok())
        .collect();
    String::from_utf8(bytes?).ok()
}

/// The credentials as restic's environment: only the settings a repository uses, never anything else the text carries.
fn env_from(text: &str) -> Vec<(String, String)> {
    text.lines()
        .filter_map(|l| l.split_once('='))
        .filter(|(k, _)| ozboxd::backup_root::ALLOWED_KEYS.contains(k))
        .map(|(k, v)| (k.to_string(), v.to_string()))
        .collect()
}

/// Whether credentials are on file, without opening them.
#[allow(dead_code)]
pub fn configured(store: &dyn SecretStore) -> bool {
    store.exists(ENV_SECRET).unwrap_or(false) && store.exists(PASSWORD_SECRET).unwrap_or(false)
}

/// Run `bin` with the box's restic credentials for one validated command. The output has every credential value removed
/// before it is returned, and standard error is dropped (restic echoes the repository there).
pub fn run(
    store: &dyn SecretStore,
    bin: &str,
    cache_dir: &str,
    args: &[String],
) -> Result<ResticOut, String> {
    args_ok(args).map_err(str::to_string)?;
    let env_text = store
        .get(ENV_SECRET)
        .map_err(|e| e.0)?
        .ok_or("no backup credentials are saved on this box")?;
    let password = store
        .get(PASSWORD_SECRET)
        .map_err(|e| e.0)?
        .ok_or("no backup credentials are saved on this box")?;
    let env_text = hex_decode(&env_text).ok_or("the saved backup credentials are unreadable")?;
    let env = env_from(&env_text);
    if !env.iter().any(|(k, _)| k == "RESTIC_REPOSITORY") {
        return Err("the saved backup credentials name no repository".into());
    }
    // The secrets service is protected from the OOM killer (ADR 0045) and a child inherits that. A backup reads a whole folder and
    // can grow large, so it puts its own score back up before it starts, like a run does (a process may raise its own score,
    // never lower it): when memory runs out the backup is picked, never the secrets service.
    let mut c = Command::new("sh");
    c.arg("-c")
        .arg(format!(
            "{}; exec \"$@\"",
            ozbox_core::memory_plan::raise_score_snippet(
                ozbox_core::memory_plan::RUN_OOM_SCORE_ADJ
            )
        ))
        .arg("ozbox-restic")
        .arg(bin)
        .args(args)
        .env_clear()
        .env("PATH", "/usr/local/bin:/usr/bin:/bin")
        .env("HOME", cache_dir)
        .env("RESTIC_CACHE_DIR", cache_dir)
        .env("RESTIC_PASSWORD", &password)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null());
    for (k, v) in &env {
        c.env(k, v);
    }
    let mut child = c
        .spawn()
        .map_err(|_| "restic could not be started".to_string())?;
    let mut out = Vec::new();
    if let Some(mut so) = child.stdout.take() {
        let _ = (&mut so).take(MAX_OUTPUT).read_to_end(&mut out);
    }
    let status = child
        .wait()
        .map_err(|_| "restic did not finish".to_string())?
        .code();
    let mut text = String::from_utf8_lossy(&out).into_owned();
    for secret in env
        .iter()
        .filter(|(k, _)| k != "RESTIC_REPOSITORY")
        .map(|(_, v)| v.as_str())
        .chain(std::iter::once(password.as_str()))
    {
        if secret.len() >= 6 {
            text = text.replace(secret, "[redacted]");
        }
    }
    Ok(ResticOut {
        status,
        stdout: text,
    })
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use crate::secrets::MemorySecrets;
    use std::os::unix::fs::PermissionsExt;

    fn v(a: &[&str]) -> Vec<String> {
        a.iter().map(|s| s.to_string()).collect()
    }

    #[test]
    fn the_broker_and_the_daemon_never_restore_the_backup_record_and_read_one_list() {
        // the folder the root helper writes is on the never-restored list the daemon builds its command from and this check
        // compares against: they change together, and a restore that does not name it is refused
        assert!(NEVER_RESTORED.contains(
            &ozboxd::backup_state::dir_for(std::path::Path::new("/work"))
                .to_str()
                .unwrap()
        ));
        let id = "aaaaaaaa11111111";
        let mut full = vec!["restore", id, "--target", "/work/r"];
        for p in NEVER_RESTORED {
            full.extend(["--exclude", p]);
        }
        assert!(args_ok(&v(&full)).is_ok());
        let without: Vec<&str> = full[..full.len() - 2].to_vec();
        assert!(args_ok(&v(&without)).is_err());
    }

    #[test]
    fn only_the_exact_shapes_the_daemon_runs_are_accepted() {
        let id = "0123456789abcdef";
        for ok in [
            v(&[
                "backup",
                "--one-file-system",
                "--tag",
                "ozbox,ozbox-box=dev",
                "--exclude",
                "/work/.ozbox/metrics",
                "--exclude",
                "/work/ozbox-secrets-private",
                "/work",
            ]),
            v(&[
                "forget",
                "--prune",
                "--tag",
                "ozbox",
                "--keep-daily",
                "7",
                "--keep-weekly",
                "4",
                "--keep-monthly",
                "6",
            ]),
            v(&["forget", "--prune", id]),
            v(&[
                "restore",
                "latest",
                "--target",
                "/",
                "--exclude",
                "/work/ozbox-secrets-private",
                "--exclude",
                "/work/ozbox-audit",
                "--exclude",
                "/work/ozbox-backup",
            ]),
            v(&[
                "restore",
                id,
                "--target",
                "/work/restore-1",
                "--exclude",
                "/work/ozbox-secrets-private",
                "--exclude",
                "/work/ozbox-audit",
                "--exclude",
                "/work/ozbox-backup",
            ]),
            v(&["snapshots", "--json", "--tag", "ozbox,ozbox-box=dev"]),
        ] {
            assert!(args_ok(&ok).is_ok(), "{ok:?}");
        }
        for bad in [
            v(&[]),
            v(&["init"]),
            v(&["dump", id, "/etc/shadow"]),
            v(&["backup", "--one-file-system", "--tag", "ozbox", "/etc"]),
            v(&[
                "backup",
                "--one-file-system",
                "--tag",
                "ozbox",
                "/work/../etc",
            ]),
            v(&[
                "backup",
                "--one-file-system",
                "--tag",
                "ozbox",
                "-o",
                "rclone.program=/bin/sh",
                "/work",
            ]),
            v(&[
                "backup",
                "--one-file-system",
                "--tag",
                "ozbox",
                "--files-from",
                "/etc/passwd",
                "/work",
            ]),
            v(&[
                "backup",
                "-r",
                "/tmp/repo",
                "--one-file-system",
                "--tag",
                "ozbox",
                "/work",
            ]),
            v(&[
                "snapshots",
                "--json",
                "--tag",
                "ozbox",
                "--password-command",
                "cat /etc/shadow",
            ]),
            v(&["snapshots", "--json", "--tag", "a;b"]),
            v(&["restore", id, "--target", "/etc"]),
            // a backup that takes the private folder, and a restore that puts it (or the chain) back
            v(&[
                "backup",
                "--one-file-system",
                "--tag",
                "ozbox",
                "--exclude",
                "/work/.ozbox/metrics",
                "/work",
            ]),
            v(&["restore", "latest", "--target", "/"]),
            v(&[
                "restore",
                id,
                "--target",
                "/work/r",
                "--exclude",
                "/work/ozbox-secrets-private",
            ]),
            // a restore that leaves out the folder and the chain but not the backup record (the shape before the record existed)
            v(&[
                "restore",
                id,
                "--target",
                "/work/r",
                "--exclude",
                "/work/ozbox-secrets-private",
                "--exclude",
                "/work/ozbox-audit",
            ]),
            v(&["restore", id, "--target", "/work/../etc"]),
            v(&[
                "forget",
                "--prune",
                "--tag",
                "ozbox",
                "--keep-daily",
                "-1",
                "--keep-weekly",
                "4",
                "--keep-monthly",
                "6",
            ]),
            v(&["forget", "--prune", "not-an-id"]),
        ] {
            assert!(args_ok(&bad).is_err(), "{bad:?}");
        }
    }

    #[test]
    fn restic_gets_the_credentials_in_its_environment_and_the_caller_never_sees_them() {
        let d = tempfile::tempdir().unwrap();
        let bin = d.path().join("restic");
        // a stand-in that echoes its whole environment and arguments, to show where the values are and are not
        std::fs::write(
            &bin,
            "#!/bin/sh\necho \"pw=$RESTIC_PASSWORD repo=$RESTIC_REPOSITORY key=$AWS_SECRET_ACCESS_KEY other=$SHOULD_NOT_PASS args=$*\"\n",
        )
        .unwrap();
        std::fs::set_permissions(&bin, std::fs::Permissions::from_mode(0o755)).unwrap();
        let s = MemorySecrets::default();
        s.set(PASSWORD_SECRET, "SENTINEL-restic-password").unwrap();
        s.set(
            ENV_SECRET,
            &"RESTIC_REPOSITORY=s3:https://objects.example.com/b\nAWS_SECRET_ACCESS_KEY=SENTINEL-aws-secret\nEVIL=1\n"
                .bytes()
                .map(|b| format!("{b:02x}"))
                .collect::<String>(),
        )
        .unwrap();
        let out = run(
            &s,
            &bin.to_string_lossy(),
            &d.path().to_string_lossy(),
            &v(&["snapshots", "--json", "--tag", "ozbox"]),
        )
        .unwrap();
        assert_eq!(out.status, Some(0));
        // restic really received them (the stand-in printed them) ...
        assert!(out.stdout.contains("pw=[redacted]") && out.stdout.contains("key=[redacted]"));
        assert!(out.stdout.contains("repo=s3:https://objects.example.com/b"));
        // ... and the caller's answer carries no value, nor the caller's own environment
        assert!(!out.stdout.contains("SENTINEL"));
        assert!(out.stdout.contains("other= "), "{}", out.stdout);
        // a command outside the list never starts
        assert!(run(&s, &bin.to_string_lossy(), "/tmp", &v(&["dump", "x"])).is_err());
        // no credentials, no run, and the message names no value
        let empty = MemorySecrets::default();
        let e = run(
            &empty,
            &bin.to_string_lossy(),
            "/tmp",
            &v(&["snapshots", "--json", "--tag", "ozbox"]),
        )
        .err()
        .unwrap();
        assert!(e.contains("no backup credentials"));
        assert!(!configured(&empty) && configured(&s));
    }
}
