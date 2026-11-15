//! The instance metadata service is for the machine's own services, not for the box user (ADR 0029, amendment 6 §2).
//!
//! On AWS the metadata service hands out the instance role's credentials to any process that asks, and a hop limit or a
//! token requirement does not stop a process on the machine. On Hetzner it hands out the first-boot configuration. So an
//! always-on table in the kernel's packet filter lets only these reach 169.254.169.254 (and AWS's IPv6 address for it):
//! root (cloud-init, the Systems Manager agent), the secrets user (the store's key and the box's own secrets), the metadata
//! user that runs the interruption watcher, and, where it exists, the account EC2 Instance Connect looks keys up as. Every
//! other user's packet to it is dropped, and nothing forwarded (a container) reaches it at all. The table is its own, so the
//! box-wide egress list (ADR 0034), in any mode, neither loosens nor removes it.
//!
//! The interruption watcher used to run inside the box daemon, as the box user. It now runs as `ozbox-meta`
//! (`ozboxd interruption-watch`) and leaves what it saw in a file the daemon reads.
//!
//! `ozbox host-guard metadata install [aws|hcloud]`, as root: makes the user, writes the table and the units that load it at
//! every boot (before the box daemon and the box user's own services) and run the watcher, and loads the table now. Safe to
//! run again; first boot and `reinstall-ozboxd` run it.

use std::path::{Path, PathBuf};

use ozbox_core::{CommandRunner, CommandSpec};

/// The metadata service's addresses: IPv4, and AWS's IPv6 one.
pub const V4: &str = "169.254.169.254";
pub const V6: &str = "fd00:ec2::254";
/// The user the interruption watcher runs as.
pub const USER: &str = "ozbox-meta";
/// Accounts besides root that may reach the metadata service, when they exist.
const ALLOWED: [&str; 3] = ["ozbox-secrets", USER, "ec2-instance-connect"];

#[derive(Debug, Clone)]
pub struct Paths {
    /// `/etc/ozbox`: the table.
    pub etc: PathBuf,
    /// `/etc/systemd/system`.
    pub units: PathBuf,
    /// The machine's vendor, to tell AWS from elsewhere when the caller does not say.
    pub dmi_vendor: PathBuf,
}

impl Default for Paths {
    fn default() -> Self {
        Self {
            etc: "/etc/ozbox".into(),
            units: "/etc/systemd/system".into(),
            dmi_vendor: "/sys/devices/virtual/dmi/id/sys_vendor".into(),
        }
    }
}

/// The table: allowed uids pass, everyone else's packets to the metadata service are dropped; forwarded ones always are.
/// Loaded in one step (`add` then `delete` then the table), so there is no moment with a half-built list. Pure.
pub fn render(uids: &[u32]) -> String {
    let mut ids: Vec<u32> = uids.to_vec();
    ids.push(0);
    ids.sort_unstable();
    ids.dedup();
    let set = ids
        .iter()
        .map(u32::to_string)
        .collect::<Vec<_>>()
        .join(", ");
    format!(
        "add table inet ozbox_metadata\n\
         delete table inet ozbox_metadata\n\
         table inet ozbox_metadata {{\n\
         \x20 chain output {{\n\
         \x20   type filter hook output priority -10; policy accept;\n\
         \x20   ip daddr {V4} meta skuid {{ {set} }} accept\n\
         \x20   ip6 daddr {V6} meta skuid {{ {set} }} accept\n\
         \x20   ip daddr {V4} counter drop\n\
         \x20   ip6 daddr {V6} counter drop\n\
         \x20 }}\n\
         \x20 chain forward {{\n\
         \x20   type filter hook forward priority -10; policy accept;\n\
         \x20   ip daddr {V4} drop\n\
         \x20   ip6 daddr {V6} drop\n\
         \x20 }}\n\
         }}\n"
    )
}

const LOAD_UNIT: &str = "[Unit]\nDescription=Oz Box: only the machine's own services reach the instance metadata service\nDefaultDependencies=no\nAfter=local-fs.target\nBefore=network-pre.target ozboxd.service ozbox-dashboard.service systemd-user-sessions.service\nWants=network-pre.target\nConditionPathExists=/etc/ozbox/metadata-guard.nft\n\n[Service]\nType=oneshot\nRemainAfterExit=yes\nExecStart=/usr/sbin/nft -f /etc/ozbox/metadata-guard.nft\n\n[Install]\nWantedBy=sysinit.target\n";

const WATCH_UNIT: &str = "[Unit]\nDescription=Oz Box: watch the metadata service for an interruption notice (as its own user)\nAfter=network-online.target ozbox-metadata-guard.service\nWants=network-online.target\nConditionPathExists=/usr/local/bin/ozboxd\n\n[Service]\nType=simple\nUser=ozbox-meta\nGroup=ozbox-meta\nRuntimeDirectory=ozbox-meta\nRuntimeDirectoryMode=0755\nExecStart=/usr/local/bin/ozboxd interruption-watch\nRestart=always\nRestartSec=10\nNoNewPrivileges=true\nPrivateTmp=true\nProtectHome=true\nProtectSystem=strict\nPrivateDevices=true\nLockPersonality=true\nLimitCORE=0\n\n[Install]\nWantedBy=multi-user.target\n";

pub struct Guard<'a> {
    pub runner: &'a dyn CommandRunner,
    pub paths: Paths,
}

fn write(path: &Path, text: &str) -> Result<(), String> {
    let io = |_| format!("could not write {}", path.display());
    if let Some(d) = path.parent() {
        std::fs::create_dir_all(d).map_err(io)?;
    }
    let tmp = path.with_extension("tmp");
    std::fs::write(&tmp, text).map_err(io)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&tmp, std::fs::Permissions::from_mode(0o644)).map_err(io)?;
    }
    std::fs::rename(&tmp, path).map_err(io)
}

impl Guard<'_> {
    fn ok(&self, c: CommandSpec) -> Result<String, ()> {
        match self.runner.run(&c) {
            Ok(o) if o.status == Some(0) => Ok(o.stdout),
            _ => Err(()),
        }
    }

    fn uid(&self, name: &str) -> Option<u32> {
        self.ok(CommandSpec::new("id").args(["-u", name]))
            .ok()
            .and_then(|s| s.trim().parse().ok())
    }

    /// Whether this machine is on AWS: the caller's word, or the machine's own vendor string.
    fn on_aws(&self, provider: Option<&str>) -> bool {
        match provider {
            Some(p) => p == "aws",
            None => {
                std::fs::read_to_string(&self.paths.dmi_vendor).is_ok_and(|v| v.contains("Amazon"))
            }
        }
    }

    pub fn install(&self, provider: Option<&str>) -> Result<String, String> {
        if let Some(p) = provider {
            if p != "aws" && p != "hcloud" {
                return Err("the provider is aws or hcloud".into());
            }
        }
        if self.uid(USER).is_none() {
            self.ok(CommandSpec::new("useradd").args([
                "--system",
                "--user-group",
                "--no-create-home",
                "--home-dir",
                "/nonexistent",
                "--shell",
                "/usr/sbin/nologin",
                "--comment",
                "Oz Box metadata watcher",
                USER,
            ]))
            .map_err(|()| format!("the {USER} user could not be made"))?;
        }
        let uids: Vec<u32> = ALLOWED.iter().filter_map(|n| self.uid(n)).collect();
        if self.uid(USER).is_none() {
            return Err(format!("the {USER} user has no id"));
        }
        let file = self.paths.etc.join("metadata-guard.nft");
        write(&file, &render(&uids))?;
        let f = file.display().to_string();
        self.ok(CommandSpec::new("nft").args(["-c", "-f", &f]))
            .map_err(|()| "nft refused the metadata table; nothing was loaded".to_string())?;
        self.ok(CommandSpec::new("nft").args(["-f", &f]))
            .map_err(|()| "nft could not load the metadata table".to_string())?;
        write(
            &self.paths.units.join("ozbox-metadata-guard.service"),
            LOAD_UNIT,
        )?;
        let aws = self.on_aws(provider);
        if aws {
            write(
                &self.paths.units.join("ozbox-metadata-watch.service"),
                WATCH_UNIT,
            )?;
        }
        let _ = self.ok(CommandSpec::new("systemctl").args(["daemon-reload"]));
        let _ =
            self.ok(CommandSpec::new("systemctl").args(["enable", "ozbox-metadata-guard.service"]));
        if aws {
            let _ = self.ok(CommandSpec::new("systemctl").args([
                "enable",
                "--now",
                "ozbox-metadata-watch.service",
            ]));
        }
        Ok(format!(
            "Only root and {} of the box's own services reach the metadata service now; the box user's requests to it are dropped.",
            uids.len()
        ))
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use ozbox_core::{Output, RecordingRunner};

    fn out(stdout: &str) -> Output {
        Output {
            status: Some(0),
            stdout: stdout.into(),
            stderr: String::new(),
        }
    }

    fn missing() -> Output {
        Output {
            status: Some(1),
            ..Output::default()
        }
    }

    #[test]
    fn only_the_allowed_uids_pass_everyone_else_is_dropped_and_nothing_forwarded_reaches_it() {
        let t = render(&[998, 997, 998]);
        let allow4 = "ip daddr 169.254.169.254 meta skuid { 0, 997, 998 } accept";
        let drop4 = "ip daddr 169.254.169.254 counter drop";
        assert!(t.contains(allow4) && t.contains(drop4), "{t}");
        assert!(
            t.find(allow4) < t.find(drop4),
            "the drop comes after the accept"
        );
        assert!(t.contains("ip6 daddr fd00:ec2::254 meta skuid { 0, 997, 998 } accept"));
        assert!(t.contains("ip6 daddr fd00:ec2::254 counter drop"));
        assert!(t.contains("hook forward") && t.contains("    ip daddr 169.254.169.254 drop\n"));
        // replaced in one step, and a table of its own, apart from the egress list's
        assert!(t.starts_with("add table inet ozbox_metadata\ndelete table inet ozbox_metadata\n"));
        assert!(!t.contains("ozbox_egress"));
        // the box user (1500) is not in the set: its packets fall to the drop
        assert!(!t.contains("1500"));
        // root is always there, even when no other account exists
        assert!(render(&[]).contains("meta skuid { 0 } accept"));
    }

    #[test]
    fn install_makes_the_user_checks_then_loads_the_table_and_writes_the_boot_units() {
        let d = tempfile::tempdir().unwrap();
        let r = RecordingRunner::new();
        r.reply(missing()); // id -u ozbox-meta: not yet
        r.reply(out("")); // useradd
        r.reply(out("998\n")); // id -u ozbox-secrets
        r.reply(out("997\n")); // id -u ozbox-meta
        r.reply(missing()); // id -u ec2-instance-connect: not on this machine
        r.reply(out("997\n")); // id -u ozbox-meta again
        let g = Guard {
            runner: &r,
            paths: Paths {
                etc: d.path().join("etc"),
                units: d.path().join("units"),
                dmi_vendor: d.path().join("vendor"),
            },
        };
        let msg = g.install(Some("aws")).unwrap();
        assert!(msg.contains("dropped"), "{msg}");
        let calls = r.calls();
        assert_eq!(calls[1].program, "useradd");
        assert!(
            calls[1].args.contains(&"--system".to_string())
                && calls[1].args.contains(&"/usr/sbin/nologin".to_string())
        );
        let nft: Vec<&CommandSpec> = calls.iter().filter(|c| c.program == "nft").collect();
        assert_eq!(nft[0].args[0], "-c", "checked before it is loaded");
        assert_eq!(nft[1].args[0], "-f");
        let table = std::fs::read_to_string(d.path().join("etc/metadata-guard.nft")).unwrap();
        assert!(
            table.contains("meta skuid { 0, 997, 998 } accept"),
            "{table}"
        );
        let load =
            std::fs::read_to_string(d.path().join("units/ozbox-metadata-guard.service")).unwrap();
        assert!(
            load.contains("Before=network-pre.target ozboxd.service")
                && load.contains("DefaultDependencies=no")
        );
        let watch =
            std::fs::read_to_string(d.path().join("units/ozbox-metadata-watch.service")).unwrap();
        assert!(watch.contains("User=ozbox-meta") && watch.contains("ozboxd interruption-watch"));
        assert!(!watch.contains("User=ozbox\n"));
    }

    #[test]
    fn off_aws_the_table_is_loaded_but_no_watcher_runs_and_a_table_nft_refuses_is_not_loaded() {
        let d = tempfile::tempdir().unwrap();
        std::fs::write(d.path().join("vendor"), "Hetzner\n").unwrap();
        let paths = Paths {
            etc: d.path().join("etc"),
            units: d.path().join("units"),
            dmi_vendor: d.path().join("vendor"),
        };
        let r = RecordingRunner::new();
        for _ in 0..5 {
            r.reply(out("990\n"));
        }
        let g = Guard {
            runner: &r,
            paths: paths.clone(),
        };
        g.install(None).unwrap();
        assert!(d
            .path()
            .join("units/ozbox-metadata-guard.service")
            .is_file());
        assert!(!d.path().join("units/ozbox-metadata-watch.service").exists());
        // nft refuses the check: nothing is loaded
        let r2 = RecordingRunner::new();
        for _ in 0..5 {
            r2.reply(out("990\n"));
        }
        r2.reply(missing()); // nft -c
        let g2 = Guard { runner: &r2, paths };
        assert!(g2.install(Some("hcloud")).is_err());
        assert_eq!(r2.calls().iter().filter(|c| c.program == "nft").count(), 1);
        assert!(g2.install(Some("gcp")).is_err());
    }
}
