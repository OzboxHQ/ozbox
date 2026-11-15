//! The ingress account: the one way a person's computer reaches a box's secrets service (ADR 0029, Amendment 6 section 3 and
//! Amendment 9).
//!
//! Everything a laptop sends to a box's secrets service (staging keys, a signer's enrolment, an approval's signature, the
//! first-time dashboard code on its way back) used to enter through the box user's own SSH account, where the box user's
//! shell startup files, `~/.ssh/rc` and shell functions are in the path of the bytes. So the route is a different account:
//!
//! * `ozbox-ingress`, with a home owned by root that nothing writable by it or by the box user is inside, and a shell that
//!   reads no startup file for a command (`/bin/sh`);
//! * a `Match User` block that forces one command, `ozbox secrets receive`, whatever the client asks to run, and turns off
//!   the terminal, forwarding, tunnels, `~/.ssh/rc` and `~/.ssh/environment`;
//! * an `AuthorizedKeysFile` in a root-owned directory, so no process of the box user can add a key. The key is the person's
//!   own for this account (`~/.ssh/ozbox_ingress_ed25519`), never the box user's. On AWS it also arrives through EC2 Instance Connect, as for the box user; elsewhere it is pinned when the box is made (the
//!   `ozbox-ingress` label), as the first approval key is;
//! * a socket of its own in the secrets service, a folder only the secrets user and this account can enter.
//!
//! `ozbox secrets ingress-setup [KEY]`, as root, makes all of that. It is not an admin action and takes no word from the
//! box user: the key it is given is the person's own, pinned at first boot. Safe to run again; first boot of a machine that
//! is not the Oz image runs it, and the image build runs it once.

use std::path::{Path, PathBuf};

use ozbox_core::{CommandRunner, CommandSpec};

/// The account.
pub const USER: &str = "ozbox-ingress";
/// The program the account is forced to run.
pub const RECEIVE_PROGRAM: &str = "/usr/local/bin/ozbox secrets receive";
/// Where the secrets service listens for the account, and where a key placed while the service is down waits for it.
pub const SOCKET: &str = "/run/ozbox-secrets/ingress/ingress.sock";
pub const KEK_INBOX: &str = "/run/ozbox-secrets/kek-inbox";

#[derive(Debug, Clone)]
pub struct Paths {
    /// `/etc/ssh`.
    pub ssh: PathBuf,
    /// `/var/lib/ozbox-ingress`: the account's home, owned by root.
    pub home: PathBuf,
    /// `/etc/tmpfiles.d`.
    pub tmpfiles: PathBuf,
    /// `/etc/systemd/system`.
    pub units: PathBuf,
    /// `/run/sshd`: the folder sshd's own configuration test needs (an image build, or a first boot before sshd has run).
    pub run_sshd: PathBuf,
}

impl Default for Paths {
    fn default() -> Self {
        Self {
            ssh: "/etc/ssh".into(),
            home: "/var/lib/ozbox-ingress".into(),
            tmpfiles: "/etc/tmpfiles.d".into(),
            units: "/etc/systemd/system".into(),
            run_sshd: "/run/sshd".into(),
        }
    }
}

impl Paths {
    pub fn keys_dir(&self) -> PathBuf {
        self.ssh.join("ozbox-ingress")
    }
    pub fn authorized_keys(&self) -> PathBuf {
        self.keys_dir().join("authorized_keys")
    }
    pub fn sshd_drop_in(&self) -> PathBuf {
        self.ssh.join("sshd_config.d/20-ozbox-ingress.conf")
    }
}

/// The shell the account has until everything else is in place and sshd has accepted the settings: it cannot log in with it,
/// whatever sshd is configured to do. A failed or half-done setup therefore never leaves a login-capable account with no forced
/// command.
const LOCKED_SHELL: &str = "/usr/sbin/nologin";

/// The sshd settings. `PermitUserEnvironment` is global-only in sshd (it is refused inside `Match`), so it is stated before the
/// block; everything inside the block is a keyword `Match` accepts (checked against a real `sshd -t` by the tests). The account is allowed to log in by the box's `AllowUsers` line in `10-ozbox.conf`, which names it; this
/// block adds no `AllowUsers` of its own, so a machine whose first-boot file has none (the image before first boot) is
/// never narrowed to this account alone. Pure.
pub fn sshd_config(keys_file: &Path) -> String {
    format!(
        "# The ingress account: the one way a person's computer reaches this box's secrets service (ADR 0029).\n\
         PermitUserEnvironment no\n\
         Match User {USER}\n\
         \x20   AuthorizedKeysFile {keys}\n\
         \x20   AuthenticationMethods publickey\n\
         \x20   ForceCommand {RECEIVE_PROGRAM}\n\
         \x20   DisableForwarding yes\n\
         \x20   PermitTTY no\n\
         \x20   PermitUserRC no\n\
         \x20   X11Forwarding no\n\
         \x20   AllowTcpForwarding no\n\
         \x20   AllowStreamLocalForwarding no\n\
         \x20   AllowAgentForwarding no\n\
         \x20   PermitTunnel no\n\
         \x20   GatewayPorts no\n",
        keys = keys_file.display()
    )
}

/// The OpenSSH line for an Ed25519 public key given as 32 raw bytes: `restrict` (no forwarding, no terminal, no rc file) and
/// the key. Pure.
pub fn authorized_line(public: &[u8]) -> Result<String, String> {
    if public.len() != 32 {
        return Err("the ingress key is not an Ed25519 public key".into());
    }
    let mut blob = Vec::new();
    for part in [&b"ssh-ed25519"[..], public] {
        blob.extend_from_slice(&(part.len() as u32).to_be_bytes());
        blob.extend_from_slice(part);
    }
    Ok(format!(
        "restrict ssh-ed25519 {} ozbox-ingress\n",
        crate::serve::auth::b64::encode_std(&blob)
    ))
}

/// The SSH public key (`ssh-ed25519 AAAA...` as `ssh-keygen` writes it) as its 32 raw bytes. Pure.
pub fn public_from_openssh(line: &str) -> Result<[u8; 32], String> {
    let mut it = line.split_whitespace();
    if it.next() != Some("ssh-ed25519") {
        return Err("that is not an Ed25519 SSH key".into());
    }
    let blob = crate::serve::auth::b64::decode_std(it.next().unwrap_or(""))
        .ok_or_else(|| "that SSH key is not valid".to_string())?;
    // string "ssh-ed25519", string key
    let ok = blob.len() == 4 + 11 + 4 + 32
        && blob[..4] == 11u32.to_be_bytes()
        && &blob[4..15] == b"ssh-ed25519"
        && blob[15..19] == 32u32.to_be_bytes();
    if !ok {
        return Err("that SSH key is not valid".into());
    }
    let mut out = [0u8; 32];
    out.copy_from_slice(&blob[19..]);
    Ok(out)
}

/// The label value that pins a laptop's SSH public key: its 32 bytes in lowercase base32 (52 characters).
pub fn label_for(openssh_public: &str) -> Result<String, String> {
    Ok(crate::approval_key::base32(&public_from_openssh(
        openssh_public,
    )?))
}

/// The label value that pins this computer's dedicated SSH key for the ingress account, made when a box is created: the key is
/// made if it does not exist (it is the ingress account's own, never the box user's), and only its public half is read. `OZBOX_INGRESS_PIN=off`
/// pins none (a box then has the account with no key; on AWS Instance Connect still reaches it).
pub fn label_for_create(
    runner: &dyn CommandRunner,
    ssh_dir: &Path,
) -> Result<Option<String>, String> {
    if std::env::var("OZBOX_INGRESS_PIN").as_deref() == Ok("off") {
        return Ok(None);
    }
    let (public, _) =
        crate::sshconfig::ensure_named_key(runner, ssh_dir, crate::sshconfig::INGRESS_KEY_NAME)
            .map_err(|e| e.to_string())?;
    let text = std::fs::read_to_string(&public)
        .map_err(|_| "the SSH key could not be read".to_string())?;
    label_for(text.trim()).map(Some)
}

/// The folders the service and the account share. `kek-inbox` is where a key placed by the person's computer while the
/// service is down waits: written by the account, read and removed by the secrets service, entered by nobody else.
pub fn tmpfiles() -> String {
    format!(
        "d /run/ozbox-secrets/ingress 0750 ozbox-secrets {USER} -\nd {KEK_INBOX} 2770 {USER} ozbox-secrets -\n"
    )
}

const KEK_PATH_UNIT: &str = "[Unit]\nDescription=Oz Box: a store key was placed by its owner while the secrets service was down\nConditionPathExists=/usr/local/bin/ozbox\n\n[Path]\nPathExistsGlob=/run/ozbox-secrets/kek-inbox/kek\nUnit=ozbox-secrets-kek.service\n\n[Install]\nWantedBy=multi-user.target\n";
const KEK_SERVICE_UNIT: &str = "[Unit]\nDescription=Oz Box: start the secrets service again so it can use the store key that was placed\n\n[Service]\nType=oneshot\nExecStart=/usr/bin/systemctl restart --no-block ozbox-secrets.service\n";

pub struct Guard<'a> {
    pub runner: &'a dyn CommandRunner,
    pub paths: Paths,
}

fn write(path: &Path, text: &str, mode: u32) -> Result<(), String> {
    let io = |_| format!("could not write {}", path.display());
    if let Some(d) = path.parent() {
        std::fs::create_dir_all(d).map_err(io)?;
    }
    let tmp = path.with_extension("tmp");
    std::fs::write(&tmp, text).map_err(io)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&tmp, std::fs::Permissions::from_mode(mode)).map_err(io)?;
    }
    #[cfg(not(unix))]
    let _ = mode;
    std::fs::rename(&tmp, path).map_err(io)
}

fn dir(path: &Path, mode: u32) -> Result<(), String> {
    let io = |_| format!("could not make {}", path.display());
    std::fs::create_dir_all(path).map_err(io)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode)).map_err(io)?;
    }
    #[cfg(not(unix))]
    let _ = mode;
    Ok(())
}

impl Guard<'_> {
    fn ok(&self, c: CommandSpec) -> bool {
        matches!(self.runner.run(&c), Ok(o) if o.status == Some(0))
    }

    fn user_exists(&self) -> bool {
        self.ok(CommandSpec::new("id").args(["-u", USER]))
    }

    /// Make the account and everything it needs. `key` is the person's SSH public key in lowercase base32 (the label's
    /// value), or empty: with none the account exists and nobody can log in to it (on AWS Instance Connect still can).
    pub fn install(&self, key: &str) -> Result<String, String> {
        let public = if key.is_empty() {
            None
        } else {
            Some(
                crate::approval_key::unbase32(key)
                    .filter(|b| b.len() == 32 && key.len() == 52)
                    .ok_or("the ingress key is not an Ed25519 public key in lowercase base32")?,
            )
        };
        if !self.user_exists()
            && !self.ok(CommandSpec::new("useradd").args([
                "--system",
                "--user-group",
                "--no-create-home",
                "--home-dir",
                &self.paths.home.display().to_string(),
                "--shell",
                // locked until the block is in and sshd has accepted it (see the end of `install`)
                LOCKED_SHELL,
                "--comment",
                "Oz Box ingress",
                USER,
            ]))
        {
            return Err(format!("the {USER} account could not be made"));
        }
        // an account left by an earlier run is locked again while this one works: fail closed
        if !self.ok(CommandSpec::new("usermod").args(["--shell", LOCKED_SHELL, USER])) {
            return Err(format!("the {USER} account could not be locked"));
        }
        // the home belongs to root and holds nothing: neither this account nor the box user can write a startup file there
        dir(&self.paths.home, 0o755)?;
        // keys are read by sshd as the account, so the folder must be enterable and no one but root may write it
        dir(&self.paths.keys_dir(), 0o755)?;
        let keys = self.paths.authorized_keys();
        match &public {
            Some(p) => write(&keys, &authorized_line(p)?, 0o644)?,
            None if !keys.exists() => write(&keys, "", 0o644)?,
            None => {}
        }
        let conf = self.paths.sshd_drop_in();
        write(&conf, &sshd_config(&keys), 0o644)?;
        // `sshd -t` refuses to run without its privilege-separation folder, which sshd itself makes when it starts
        dir(&self.paths.run_sshd, 0o755)?;
        // a configuration sshd refuses would lock out the box user's route too: take it back out and say so
        if !self.ok(CommandSpec::new("sshd").args(["-t"])) {
            let _ = std::fs::remove_file(&conf);
            // and nothing may log in to the account: no key, and still the shell that refuses
            let _ = write(&keys, "", 0o644);
            return Err(
                "sshd refused the ingress settings, so they were removed and the account stays locked".into(),
            );
        }
        write(
            &self.paths.tmpfiles.join("ozbox-ingress.conf"),
            &tmpfiles(),
            0o644,
        )?;
        write(
            &self.paths.units.join("ozbox-secrets-kek.path"),
            KEK_PATH_UNIT,
            0o644,
        )?;
        write(
            &self.paths.units.join("ozbox-secrets-kek.service"),
            KEK_SERVICE_UNIT,
            0o644,
        )?;
        let _ = self.ok(CommandSpec::new("systemd-tmpfiles").args(["--create"]));
        let _ = self.ok(CommandSpec::new("systemctl").args(["daemon-reload"]));
        let _ = self.ok(CommandSpec::new("systemctl").args(["enable", "ozbox-secrets-kek.path"]));
        // a running sshd picks the new block up now; a build or a first boot has none yet and ignores this
        let _ = self.ok(CommandSpec::new("systemctl").args(["reload", "ssh"]));
        // only now, with the forced command accepted by sshd, may the account have a shell a forced command can run through
        // (`/bin/sh` reads no startup file for `sh -c`)
        if !self.ok(CommandSpec::new("usermod").args(["--shell", "/bin/sh", USER])) {
            return Err(format!(
                "the {USER} account could not be opened, so it stays locked"
            ));
        }
        Ok(match public {
            Some(_) => {
                format!("The ingress account {USER} is ready, with the key this box was made with.")
            }
            None => format!(
                "The ingress account {USER} is ready, with no key: on AWS it is reached through Instance Connect; elsewhere a box made with the ozbox-ingress label has its key."
            ),
        })
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use ozbox_core::{Output, RecordingRunner};

    fn ok() -> Output {
        Output {
            status: Some(0),
            stdout: String::new(),
            stderr: String::new(),
        }
    }
    fn fail() -> Output {
        Output {
            status: Some(1),
            stdout: String::new(),
            stderr: String::new(),
        }
    }
    fn paths(d: &Path) -> Paths {
        Paths {
            ssh: d.join("ssh"),
            home: d.join("home"),
            tmpfiles: d.join("tmpfiles"),
            units: d.join("units"),
            run_sshd: d.join("run-sshd"),
        }
    }
    fn key_b32() -> (String, [u8; 32]) {
        let raw: Vec<u8> = (0u8..32)
            .map(|i| i.wrapping_mul(7).wrapping_add(3))
            .collect();
        let mut a = [0u8; 32];
        a.copy_from_slice(&raw);
        (crate::approval_key::base32(&raw), a)
    }

    #[test]
    fn the_sshd_block_forces_one_command_and_turns_off_everything_the_box_users_route_has() {
        let c = sshd_config(Path::new("/etc/ssh/ozbox-ingress/authorized_keys"));
        assert!(c.contains("Match User ozbox-ingress"));
        assert!(c.contains("ForceCommand /usr/local/bin/ozbox secrets receive"));
        for must in [
            "PermitUserRC no",
            "DisableForwarding yes",
            "PermitTTY no",
            "AllowTcpForwarding no",
            "AllowAgentForwarding no",
            "PermitTunnel no",
            "X11Forwarding no",
            "AuthenticationMethods publickey",
            "AuthorizedKeysFile /etc/ssh/ozbox-ingress/authorized_keys",
        ] {
            assert!(c.contains(must), "missing {must}");
        }
        // no AllowUsers of its own: one here, on a machine with no other, would lock the box user out
        assert!(!c.contains("AllowUsers"));
        // the key file is not under any directory the box user or the account can write
        assert!(
            !c.contains("/work") && !c.contains("/home") && !c.contains(".ssh/authorized_keys")
        );
    }

    #[test]
    fn an_ssh_public_key_converts_both_ways_and_a_wrong_one_is_refused() {
        let (b32, raw) = key_b32();
        let line = authorized_line(&raw).unwrap();
        assert!(line.starts_with("restrict ssh-ed25519 "));
        let openssh = line.trim_start_matches("restrict ").trim().to_string();
        assert_eq!(public_from_openssh(&openssh).unwrap(), raw);
        assert_eq!(label_for(&openssh).unwrap(), b32);
        assert_eq!(b32.len(), 52);
        assert!(authorized_line(&[1u8; 31]).is_err());
        assert!(public_from_openssh("ssh-rsa AAAA").is_err());
        assert!(public_from_openssh("ssh-ed25519 !!!").is_err());
        // a blob with the right type name and a short key
        let short = crate::serve::auth::b64::encode_std(&[0, 0, 0, 11]);
        assert!(public_from_openssh(&format!("ssh-ed25519 {short}")).is_err());
    }

    #[test]
    fn install_makes_the_account_the_root_owned_key_file_the_block_and_the_inbox_units() {
        let d = tempfile::tempdir().unwrap();
        let r = RecordingRunner::new();
        // id (no such user), useradd, usermod (lock), sshd -t, usermod (open), then the best-effort calls
        r.reply(fail());
        for _ in 0..10 {
            r.reply(ok());
        }
        let (b32, raw) = key_b32();
        let g = Guard {
            runner: &r,
            paths: paths(d.path()),
        };
        let said = g.install(&b32).unwrap();
        assert!(said.contains("ozbox-ingress"));
        let calls = r.calls();
        let useradd = calls.iter().find(|c| c.program == "useradd").unwrap();
        let joined = useradd.args.join(" ");
        assert!(joined.contains("--system") && joined.contains("--shell /usr/sbin/nologin"));
        assert!(joined.contains("--no-create-home") && joined.ends_with("ozbox-ingress"));
        assert!(calls
            .iter()
            .any(|c| c.program == "sshd" && c.args == ["-t"]));
        // locked first, and given its shell only after sshd accepted the block
        let order: Vec<String> = calls
            .iter()
            .filter(|c| c.program == "sshd" || c.program == "usermod")
            .map(|c| format!("{} {}", c.program, c.args.join(" ")))
            .collect();
        assert_eq!(
            order,
            [
                "usermod --shell /usr/sbin/nologin ozbox-ingress",
                "sshd -t",
                "usermod --shell /bin/sh ozbox-ingress"
            ]
        );
        let p = paths(d.path());
        assert_eq!(
            std::fs::read_to_string(p.authorized_keys()).unwrap(),
            authorized_line(&raw).unwrap()
        );
        let conf = std::fs::read_to_string(p.sshd_drop_in()).unwrap();
        assert!(conf.contains(&p.authorized_keys().display().to_string()));
        assert!(
            std::fs::read_to_string(p.tmpfiles.join("ozbox-ingress.conf"))
                .unwrap()
                .contains("d /run/ozbox-secrets/ingress 0750 ozbox-secrets ozbox-ingress")
        );
        // the inbox is written by the account and read by the secrets service, and nobody else enters it
        assert!(tmpfiles().contains("2770 ozbox-ingress ozbox-secrets"));
        let path_unit = std::fs::read_to_string(p.units.join("ozbox-secrets-kek.path")).unwrap();
        assert!(path_unit.contains("PathExistsGlob=/run/ozbox-secrets/kek-inbox/kek"));
        use std::os::unix::fs::PermissionsExt;
        let mode = |f: &Path| std::fs::metadata(f).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode(&p.authorized_keys()), 0o644);
        assert_eq!(mode(&p.home), 0o755);
        assert_eq!(mode(&p.keys_dir()), 0o755);
    }

    #[test]
    fn an_existing_account_is_not_made_again_and_a_run_with_no_key_keeps_the_key_file() {
        let d = tempfile::tempdir().unwrap();
        let p = paths(d.path());
        let (b32, raw) = key_b32();
        let r = RecordingRunner::new();
        for _ in 0..10 {
            r.reply(ok());
        }
        let g = Guard {
            runner: &r,
            paths: p.clone(),
        };
        g.install(&b32).unwrap();
        assert!(!r.calls().iter().any(|c| c.program == "useradd"));
        // run again (an image's own boot, with no label): the key the box was made with stays
        let r = RecordingRunner::new();
        for _ in 0..10 {
            r.reply(ok());
        }
        Guard {
            runner: &r,
            paths: p.clone(),
        }
        .install("")
        .unwrap();
        assert_eq!(
            std::fs::read_to_string(p.authorized_keys()).unwrap(),
            authorized_line(&raw).unwrap()
        );
    }

    #[test]
    fn creating_a_box_pins_the_public_half_of_this_computers_ssh_key_and_never_reads_the_private_half(
    ) {
        let d = tempfile::tempdir().unwrap();
        let (b32, raw) = key_b32();
        let pubtext = authorized_line(&raw)
            .unwrap()
            .trim_start_matches("restrict ")
            .to_string();
        std::fs::write(d.path().join("ozbox_ingress_ed25519"), "PRIVATE-SENTINEL").unwrap();
        std::fs::write(d.path().join("ozbox_ingress_ed25519.pub"), pubtext).unwrap();
        let r = RecordingRunner::new();
        let label = label_for_create(&r, d.path()).unwrap().unwrap();
        assert_eq!(label, b32);
        // the key existed, so nothing was run to make one
        assert!(r.calls().is_empty());
    }

    #[test]
    fn a_bad_key_is_refused_before_anything_is_written() {
        let d = tempfile::tempdir().unwrap();
        let r = RecordingRunner::new();
        let g = Guard {
            runner: &r,
            paths: paths(d.path()),
        };
        for bad in ["not-a-key", &"a".repeat(51), &"1".repeat(52)] {
            assert!(g.install(bad).is_err());
        }
        assert!(r.calls().is_empty());
        assert!(!paths(d.path()).sshd_drop_in().exists());
    }

    #[test]
    fn settings_sshd_refuses_are_taken_back_out_so_the_box_users_route_is_not_lost() {
        let d = tempfile::tempdir().unwrap();
        let r = RecordingRunner::new();
        r.reply(ok()); // id: the account exists
        r.reply(ok()); // usermod: locked
        r.reply(fail()); // sshd -t refuses
        let g = Guard {
            runner: &r,
            paths: paths(d.path()),
        };
        let e = g.install("").unwrap_err();
        assert!(e.contains("refused") && e.contains("locked"));
        assert!(!paths(d.path()).sshd_drop_in().exists());
        // fail closed: the account never got a shell it could log in with, and holds no key
        assert!(!r
            .calls()
            .iter()
            .any(|c| c.program == "usermod" && c.args.join(" ").contains("/bin/sh")));
        assert_eq!(
            std::fs::read_to_string(paths(d.path()).authorized_keys()).unwrap(),
            ""
        );
    }

    /// A real `sshd -t` on the real block, not a fake runner's "0": the first version of the block used a keyword sshd refuses
    /// inside `Match`, and every unit test passed. Needs OpenSSH (`sshd`, `ssh-keygen`); CI sets `OZBOX_REQUIRE_SSHD=1` so a
    /// runner without it fails rather than skips.
    fn real_sshd() -> Option<(String, String)> {
        let find = |name: &str| {
            ["/usr/sbin", "/usr/bin", "/sbin", "/bin", "/usr/local/sbin"]
                .iter()
                .map(|d| format!("{d}/{name}"))
                .find(|p| Path::new(p).exists())
        };
        match (find("sshd"), find("ssh-keygen")) {
            (Some(a), Some(b)) => Some((a, b)),
            _ if std::env::var("OZBOX_REQUIRE_SSHD").as_deref() == Ok("1") => {
                panic!("OZBOX_REQUIRE_SSHD=1 but sshd or ssh-keygen is not installed")
            }
            _ => None,
        }
    }

    fn sshd_t(sshd: &str, keygen: &str, dir: &Path, config: &str) -> (bool, String) {
        let host = dir.join("host");
        if !host.exists() {
            let ok = std::process::Command::new(keygen)
                .args(["-q", "-t", "ed25519", "-N", "", "-f"])
                .arg(&host)
                .status()
                .unwrap()
                .success();
            assert!(ok);
        }
        let conf = dir.join("sshd_test_config");
        std::fs::write(
            &conf,
            format!(
                "HostKey {}\nAllowUsers ozbox ozbox-ingress\nPasswordAuthentication no\n{config}",
                host.display()
            ),
        )
        .unwrap();
        let out = std::process::Command::new(sshd)
            .arg("-t")
            .arg("-f")
            .arg(&conf)
            .output()
            .unwrap();
        (
            out.status.success(),
            String::from_utf8_lossy(&out.stderr).into_owned(),
        )
    }

    #[test]
    fn the_real_sshd_accepts_the_block_and_would_have_refused_the_first_version() {
        let Some((sshd, keygen)) = real_sshd() else {
            eprintln!("skipped: no sshd on this machine");
            return;
        };
        let d = tempfile::tempdir().unwrap();
        let good = sshd_config(Path::new("/etc/ssh/ozbox-ingress/authorized_keys"));
        let (ok_, err) = sshd_t(&sshd, &keygen, d.path(), &good);
        assert!(ok_, "sshd -t refused the block: {err}");
        // the check has teeth: the keyword that broke the first version is refused by the same sshd
        let old = good.replace(
            "    PermitUserRC no\n",
            "    PermitUserRC no\n    PermitUserEnvironment no\n",
        );
        let (ok_, err) = sshd_t(&sshd, &keygen, d.path(), &old);
        assert!(!ok_ && err.contains("PermitUserEnvironment"), "{err}");
    }
}
