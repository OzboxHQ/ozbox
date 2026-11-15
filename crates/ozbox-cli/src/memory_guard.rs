//! The box memory guard (ADR 0045): a box must not fail the way one did on 2026-11-13, when a build, a test browser and a
//! coding agent filled 15.7 GB with no swap, the kernel killed the person's whole terminal scope and, in the stall before,
//! the tunnel missed its keep-alives and the web IDE went unreachable.
//!
//! `ozbox host-guard memory install|boot|apply|status`, as root (the helper runs `install`; the units run `boot` and `apply`):
//!
//! * **zram swap**, in RAM only, about half of it, zstd, high priority. Never a file or a partition: a page of the secrets
//!   service must not reach a disk. A kernel without the module gets no swap, and the box says so (`status`, the self-test).
//! * **OOM scores**: the box's own services are put at -900 so the kernel picks a workload first. The system units get a
//!   drop-in (`OOMScoreAdjust`); the box user's own units and the SSH daemon are set live by `apply`, because the user manager
//!   cannot lower a score without privilege. Nothing here touches the whole user manager, which would protect the workloads
//!   equally.
//! * **A soft limit** (`MemoryHigh`, throttle and never kill) on the person's interactive scopes, so a runaway build slows
//!   down instead of stalling the box.
//!
//! Only ever tightens, so it needs no approval (like the metadata guard). Safe to run again; it restarts nothing: every unit
//! it touches keeps running, and a score or a limit reaches a running process by being written to it.

use std::path::{Path, PathBuf};

use ozbox_core::memory_plan::{
    self as plan, sizing, Sizing, IDE_OOM_SCORE_ADJ, PAGE_CLUSTER, PROTECTED_OOM_SCORE_ADJ,
    SWAPPINESS, TERMINAL_OOM_SCORE_ADJ, ZRAM_PRIORITY,
};
use ozbox_core::{CommandRunner, CommandSpec};

/// The compressed swap device. Never a path under `/swap*`, never a partition.
pub const ZRAM_DEVICE: &str = "/dev/zram0";
/// The box user.
const BOX_USER: &str = "ozbox";

/// System units of the box (ours), each given `OOMScoreAdjust` in a drop-in and set live. None of them starts a workload,
/// except the daemon, whose children put themselves back up (`RUN_OOM_SCORE_ADJ`, `TERMINAL_OOM_SCORE_ADJ`).
pub const SYSTEM_PROTECTED: [&str; 5] = [
    "ozbox-secrets.service",
    "ozbox-cloudflared.service",
    "ozbox-code-connector.service",
    "ozbox-dashboard.service",
    "ozboxd.service",
];
/// The SSH daemon: set live only. A drop-in would reach every login session as well (an inherited score); a live write after
/// the daemon started is not what the daemon hands its sessions, which it restores from the value it read at start.
pub const LIVE_ONLY_SYSTEM: [&str; 1] = ["ssh.service"];

/// What a process of a box user's unit must be before the timer protects it. The box user owns the subtree the timer reads
/// (`cgroup.procs` under its own manager), so the unit's name alone proves nothing: it could name a unit of its own after one
/// of ours (ADR 0045, L1).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Exe {
    /// The binary is a root-owned file, writable by no one else, with one of these names (the tunnel: `/usr/bin/cloudflared`).
    RootOwned(&'static [&'static str]),
    /// The binary has one of these names. The web IDE is installed per user, so its binary is the box user's: the check is the
    /// name, and what a process that passes it can gain is a different place in the box user's own kill order.
    Named(&'static [&'static str]),
}

/// One of the box user's own units, protected live.
#[derive(Debug, Clone, Copy)]
pub struct UserUnit {
    pub unit: &'static str,
    /// The score of the unit's MAIN process. Its children are the person's work and are never given it; the one exception is the
    /// editor server behind a wrapper (`terminals` units: the main's direct children of the same binary with no `--type=`).
    pub score: i32,
    pub exe: Exe,
    /// The unit runs terminals (the web IDE): the processes below its pty host are put at `TERMINAL_OOM_SCORE_ADJ`, the same as
    /// a tmux pane, because they inherit the IDE's protected score when they start and a build must be picked before the agent.
    pub terminals: bool,
}

/// The box user's own units, set live: the names Oz Box ships (`ozbox-ide`, the old per-user tunnel) and the names a box set
/// up by hand uses (`oz-cloudflared`, `oz-code-server`, the ones that were on the box that ran out of memory). Fixed here:
/// a request never names a unit.
pub const USER_PROTECTED: [UserUnit; 4] = [
    UserUnit {
        unit: "oz-cloudflared.service",
        score: PROTECTED_OOM_SCORE_ADJ,
        exe: Exe::RootOwned(&["cloudflared"]),
        terminals: false,
    },
    UserUnit {
        unit: "ozbox-cloudflared.service",
        score: PROTECTED_OOM_SCORE_ADJ,
        exe: Exe::RootOwned(&["cloudflared"]),
        terminals: false,
    },
    UserUnit {
        unit: "oz-code-server.service",
        score: IDE_OOM_SCORE_ADJ,
        exe: Exe::Named(&["node", "code-server"]),
        terminals: true,
    },
    UserUnit {
        unit: "ozbox-ide.service",
        score: IDE_OOM_SCORE_ADJ,
        exe: Exe::Named(&["node", "code-server"]),
        terminals: true,
    },
];

/// The web IDE's units: an OOM kill of a build in one of its terminals must end that process and nothing else.
pub const IDE_UNITS: [&str; 2] = ["oz-code-server.service", "ozbox-ide.service"];

/// The secrets service's pages never leave RAM, not even to the compressed device.
const SECRETS_UNIT: &str = "ozbox-secrets.service";

#[derive(Debug, Clone)]
pub struct Paths {
    /// `/etc/systemd/system`.
    pub system_units: PathBuf,
    /// Where a unit file may already be (to write a drop-in only for a unit the box has).
    pub unit_dirs: Vec<PathBuf>,
    /// `/etc/systemd/user`.
    pub user_units: PathBuf,
    /// `/etc/sysctl.d`.
    pub sysctl_d: PathBuf,
    /// `/sys/block` and `/sys/class/zram-control`.
    pub sys_block: PathBuf,
    pub zram_control: PathBuf,
    /// `/proc`.
    pub proc: PathBuf,
    /// `/sys/fs/cgroup`.
    pub cgroup: PathBuf,
    /// The owner a root-owned binary has (0). A field so a test, which is not root, can say who its files belong to.
    pub root_uid: u32,
}

impl Default for Paths {
    fn default() -> Self {
        Self {
            system_units: "/etc/systemd/system".into(),
            unit_dirs: vec![
                "/etc/systemd/system".into(),
                "/usr/lib/systemd/system".into(),
                "/lib/systemd/system".into(),
            ],
            user_units: "/etc/systemd/user".into(),
            sysctl_d: "/etc/sysctl.d".into(),
            sys_block: "/sys/block".into(),
            zram_control: "/sys/class/zram-control".into(),
            proc: "/proc".into(),
            cgroup: "/sys/fs/cgroup".into(),
            root_uid: 0,
        }
    }
}

// ---- what is written (pure) ---------------------------------------------------------------------------------------------

/// Compressed swap at every boot. The size is worked out from the RAM the box has at that moment (`boot`), so a resized box
/// never carries a stale number in a file.
pub const BOOT_UNIT: &str = "[Unit]\nDescription=Oz Box: swap compressed in RAM (never on a disk) and the memory settings that go with it\nDefaultDependencies=no\nAfter=systemd-modules-load.service local-fs.target\nBefore=ozbox-secrets.service ozboxd.service\nConditionPathExists=/usr/local/bin/ozbox\n\n[Service]\nType=oneshot\nRemainAfterExit=yes\nExecStart=/usr/local/bin/ozbox host-guard memory boot\n\n[Install]\nWantedBy=multi-user.target\n";

/// Puts the box's own services back at their protected score, every 30 seconds and at boot: a unit that restarts, or the box
/// user's manager starting a tunnel again, is protected again within half a minute. It runs as root (it must lower a score), so
/// it is held to what it needs: a read-only file system (`/proc` stays writable), no kernel modules, and no journal line for a
/// routine start and finish (those were about 5,800 lines a day).
pub const APPLY_UNIT: &str = "[Unit]\nDescription=Oz Box: keep the box's own services at their protected OOM score\nConditionPathExists=/usr/local/bin/ozbox\n\n[Service]\nType=oneshot\nExecStart=/usr/local/bin/ozbox host-guard memory apply\nNoNewPrivileges=true\nPrivateTmp=true\nLockPersonality=true\nProtectSystem=strict\nProtectKernelModules=true\nLogLevelMax=warning\n";
pub const APPLY_TIMER: &str = "[Unit]\nDescription=Oz Box: keep the box's own services at their protected OOM score\n\n[Timer]\nOnBootSec=20s\nOnUnitActiveSec=30s\nAccuracySec=5s\n\n[Install]\nWantedBy=timers.target\n";

pub fn sysctl_conf() -> String {
    format!(
        "# Written by the Oz Box memory guard (ADR 0045). Swap is compressed RAM only: weigh an idle page as cheap to reclaim as a\n# cache page, and read no pages ahead (a compressed page is not on a disk).\nvm.swappiness = {SWAPPINESS}\nvm.page-cluster = {PAGE_CLUSTER}\n"
    )
}

/// A drop-in for one of the box's own system units.
pub fn oom_dropin(unit: &str) -> String {
    let swap = if unit == SECRETS_UNIT {
        "# The secrets service's pages never reach the swap device either, compressed or not.\nMemorySwapMax=0\n"
    } else {
        ""
    };
    format!(
        "# Written by the Oz Box memory guard (ADR 0045). The kernel picks a workload before it picks this service.\n[Service]\nOOMScoreAdjust={PROTECTED_OOM_SCORE_ADJ}\n{swap}"
    )
}

/// The soft limit on an interactive scope: throttle at this much, never kill (`MemoryHigh` only, no `MemoryMax`).
pub fn soft_limit_dropin(s: &Sizing) -> String {
    format!(
        "# Written by the Oz Box memory guard (ADR 0045). A soft limit: past it the scope is slowed down, never killed.\n# OOMPolicy=continue: when the kernel kills one process in an emergency (a build), systemd must not stop the whole scope, which\n# is the person's shell, their agent and everything else started from it (systemd's default is to stop it).\n[Scope]\nMemoryAccounting=yes\nMemoryHigh={}\nOOMPolicy=continue\n",
        s.run_high_bytes
    )
}

/// The web IDE's units: a kill of a build in one of its terminals ends that process only, never the editor with every open
/// terminal (systemd's default for a service the kernel killed a process of is to stop it, unless it has `Delegate=`).
pub const IDE_DROPIN: &str = "# Written by the Oz Box memory guard (ADR 0045): an OOM kill of one process (a build in a terminal) must not stop the editor.\n[Service]\nOOMPolicy=continue\n";

/// The box user's manager must hand the memory controller to its own units, or a limit on one of them does nothing.
pub const DELEGATE_DROPIN: &str = "# Written by the Oz Box memory guard (ADR 0045): the box user's units may be given memory limits.\n[Service]\nDelegate=pids memory cpu\n";

// ---- the guard ----------------------------------------------------------------------------------------------------------

/// One process's `/proc/<pid>` folder, held open (see `Guard::open_proc`).
struct ProcHandle {
    _dir: std::fs::File,
    base: PathBuf,
}

impl ProcHandle {
    fn get(&self, name: &str) -> Option<String> {
        // a process's cmdline and stat are bytes, not always text: read lossily
        std::fs::read(self.base.join(name))
            .ok()
            .map(|b| String::from_utf8_lossy(&b).into_owned())
    }
    fn put(&self, name: &str, text: &str) -> bool {
        std::fs::write(self.base.join(name), text).is_ok()
    }
}

pub struct Guard<'a> {
    pub runner: &'a dyn CommandRunner,
    pub paths: Paths,
}

fn write(path: &Path, text: &str) -> Result<(), String> {
    let io = |_| format!("could not write {}", path.display());
    if let Some(d) = path.parent() {
        std::fs::create_dir_all(d).map_err(io)?;
    }
    if std::fs::read_to_string(path).is_ok_and(|old| old == text) {
        return Ok(());
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

fn read(path: &Path) -> Option<String> {
    std::fs::read_to_string(path).ok()
}

impl Guard<'_> {
    fn ok(&self, c: CommandSpec) -> Result<String, ()> {
        match self.runner.run(&c) {
            Ok(o) if o.status == Some(0) => Ok(o.stdout),
            _ => Err(()),
        }
    }

    fn total(&self) -> u64 {
        read(&self.paths.proc.join("meminfo"))
            .and_then(|t| plan::mem_total_from_meminfo(&t))
            .unwrap_or(0)
    }

    fn box_uid(&self) -> Option<u32> {
        self.ok(CommandSpec::new("id").args(["-u", BOX_USER]))
            .ok()
            .and_then(|s| s.trim().parse().ok())
    }

    fn unit_exists(&self, unit: &str) -> bool {
        self.paths.unit_dirs.iter().any(|d| d.join(unit).is_file())
    }

    /// Swap compressed in RAM, and nothing else. `Ok` says what is in place; `Err` says why the box has none (the box then
    /// runs without swap, as it did: never a disk in its place).
    pub fn zram_up(&self) -> Result<String, String> {
        let swaps = read(&self.paths.proc.join("swaps")).unwrap_or_default();
        let (zram, _) = plan::swap_devices(&swaps);
        if !zram.is_empty() {
            return Ok(format!(
                "compressed swap already active ({})",
                zram.join(", ")
            ));
        }
        let total = self.total();
        if total == 0 {
            return Err("the box's memory could not be read".into());
        }
        let s = sizing(total);
        let dev = self.paths.sys_block.join("zram0");
        if !dev.is_dir() {
            let _ = self.ok(CommandSpec::new("modprobe").args(["-q", "zram"]));
        }
        if !dev.is_dir() {
            // a loaded module with no device yet makes one when `hot_add` is READ (writing to it does nothing)
            let _ = std::fs::read_to_string(self.paths.zram_control.join("hot_add"));
        }
        if !dev.is_dir() {
            return Err("this kernel has no zram module (on Ubuntu: the package linux-modules-extra-<kernel version>), so the box runs without swap; it is not given a swap file instead, because the secrets service's pages must not reach a disk".to_string());
        }
        let set = |file: &str, v: &str| std::fs::write(dev.join(file), v);
        // a device configured but not swapping is reset first (this fails harmlessly on one in use)
        if read(&dev.join("disksize")).is_some_and(|d| d.trim() != "0") {
            let _ = set("reset", "1");
        }
        // zstd compresses best at a cost a build does not notice; lzo-rle is the kernel's fallback
        if set("comp_algorithm", "zstd").is_err() {
            let _ = set("comp_algorithm", "lzo-rle");
        }
        set("disksize", &s.zram_bytes.to_string())
            .map_err(|e| format!("zram disksize: {}", e.kind()))?;
        let _ = set("mem_limit", &s.zram_mem_limit_bytes.to_string());
        self.ok(CommandSpec::new("mkswap").args(["-q", "-L", "ozbox-zram", ZRAM_DEVICE]))
            .map_err(|()| "mkswap refused the zram device".to_string())?;
        self.ok(CommandSpec::new("swapon").args([
            "--priority",
            &ZRAM_PRIORITY.to_string(),
            ZRAM_DEVICE,
        ]))
        .map_err(|()| "swapon refused the zram device".to_string())?;
        Ok(format!(
            "compressed swap on: {} MiB, at most {} MiB of RAM, zstd",
            s.zram_bytes / plan::MIB,
            s.zram_mem_limit_bytes / plan::MIB
        ))
    }

    /// The files whose content depends on this box's RAM, and the sysctl settings. Run at every boot and by `install`.
    fn sized_files(&self) -> Result<(), String> {
        let s = sizing(self.total());
        if s.run_high_bytes > 0 {
            let body = soft_limit_dropin(&s);
            write(
                &self
                    .paths
                    .user_units
                    .join("tmux-spawn-.scope.d/10-ozbox-memory.conf"),
                &body,
            )?;
            write(
                &self
                    .paths
                    .system_units
                    .join("session-.scope.d/10-ozbox-memory.conf"),
                &body,
            )?;
        }
        for u in IDE_UNITS {
            write(
                &self
                    .paths
                    .user_units
                    .join(format!("{u}.d/10-ozbox-memory.conf")),
                IDE_DROPIN,
            )?;
        }
        write(
            &self.paths.sysctl_d.join("60-ozbox-memory.conf"),
            &sysctl_conf(),
        )?;
        let f = self
            .paths
            .sysctl_d
            .join("60-ozbox-memory.conf")
            .display()
            .to_string();
        let _ = self.ok(CommandSpec::new("sysctl").args(["-q", "-p", &f]));
        Ok(())
    }

    /// Reload what systemd read, so a unit or drop-in just written is known. Restarts nothing.
    fn reload_system(&self) {
        let _ = self.ok(CommandSpec::new("systemctl").args(["daemon-reload"]));
    }

    /// Whether the box user's own service manager is running (it is not at first boot, before it starts).
    fn user_manager_running(&self, uid: u32) -> bool {
        self.paths
            .cgroup
            .join(format!("user.slice/user-{uid}.slice/user@{uid}.service"))
            .is_dir()
    }

    /// A `systemctl --user` command for the box user's manager, run from root over that user's own bus (`runuser`, with its
    /// runtime directory named).
    fn user_systemctl(&self, uid: u32, args: &[&str]) -> Result<String, ()> {
        let run = format!("/run/user/{uid}");
        let mut a: Vec<&str> = vec!["-u", BOX_USER, "--", "systemctl", "--user"];
        a.extend_from_slice(args);
        self.ok(CommandSpec::new("runuser")
            .args(a)
            .env("XDG_RUNTIME_DIR", run.clone())
            .env("DBUS_SESSION_BUS_ADDRESS", format!("unix:path={run}/bus")))
    }

    /// Reload the box user's manager, so the next interactive scope it makes carries the soft limit (it reads its drop-in
    /// folders when it starts and when it reloads, and a folder made later is not seen before). Only ever from a root unit
    /// that can reach `/run/user`: the root helper runs with `ProtectHome=true`, which hides it, so `install` asks the guard's
    /// own unit (`ozbox-memory.service`) to do it by restarting it. Two ways, the first being the plain one: root becomes
    /// the box user and talks to its bus; the second asks systemd to do the same (`systemctl --user -M ozbox@`). `Ok` says
    /// which worked; a manager that is not running has nothing to reload and reads the files when it starts.
    fn reload_user(&self) -> Result<&'static str, String> {
        let Some(uid) = self.box_uid() else {
            return Ok("the box user does not exist yet");
        };
        if !self.user_manager_running(uid) {
            return Ok("the box user's manager is not running; it reads the files when it starts");
        }
        if self.user_systemctl(uid, &["daemon-reload"]).is_ok() {
            return Ok("the box user's manager was reloaded");
        }
        if self
            .ok(CommandSpec::new("systemctl").args(["--user", "-M", "ozbox@", "daemon-reload"]))
            .is_ok()
        {
            return Ok("the box user's manager was reloaded (through machined)");
        }
        Err("the box user's manager could not be reloaded, so a terminal started before its next restart is not slowed at its soft limit; reload it by hand with `systemctl --user daemon-reload` as the box user".to_string())
    }

    /// At every boot, and when `install` restarts the guard's unit.
    pub fn boot(&self) -> Result<String, String> {
        let zram = self.zram_up();
        self.sized_files()?;
        let reloaded = self.reload_user()?;
        match zram {
            Ok(m) => Ok(format!("{m}; {reloaded}")),
            // the box is otherwise in order: the unit does not fail the boot over swap
            Err(e) => Ok(format!("no compressed swap: {e}; {reloaded}")),
        }
    }

    /// A handle on one process's `/proc/<pid>` folder, opened ONCE. Everything read or written about the process goes through
    /// that one handle, so a process id that is reused between the read and the write is a different folder, and the write
    /// fails with ESRCH instead of landing on a stranger. (On a real `/proc` the handle is reached as `/proc/self/fd/<n>`.)
    fn open_proc(&self, pid: u32) -> Option<ProcHandle> {
        let dir = self.paths.proc.join(pid.to_string());
        let f = std::fs::File::open(&dir).ok()?;
        #[cfg(target_os = "linux")]
        let base = if self.paths.proc == Path::new("/proc") {
            use std::os::fd::AsRawFd;
            PathBuf::from(format!("/proc/self/fd/{}", f.as_raw_fd()))
        } else {
            dir
        };
        #[cfg(not(target_os = "linux"))]
        let base = dir;
        Some(ProcHandle { _dir: f, base })
    }

    /// Write a live score only DOWNWARDS: protect a process, and never raise one that something already set lower.
    fn lower_adj(&self, h: &ProcHandle, score: i32) -> bool {
        let now: i32 = h
            .get("oom_score_adj")
            .and_then(|t| t.trim().parse().ok())
            .unwrap_or(0);
        now > score && h.put("oom_score_adj", &score.to_string())
    }

    /// Write a live score only UPWARDS: a process that inherited a protected score gives it up.
    fn raise_adj(&self, h: &ProcHandle, score: i32) -> bool {
        let now: i32 = h
            .get("oom_score_adj")
            .and_then(|t| t.trim().parse().ok())
            .unwrap_or(0);
        now < score && h.put("oom_score_adj", &score.to_string())
    }

    fn main_pid(&self, unit: &str) -> Option<u32> {
        self.ok(CommandSpec::new("systemctl").args(["show", "-p", "MainPID", "--value", unit]))
            .ok()
            .and_then(|s| s.trim().parse().ok())
            .filter(|p| *p > 0)
    }

    /// The main process of one of the box user's units, as its manager says. `Err`: the manager could not be asked; `Ok(None)`:
    /// the unit is not running.
    fn user_main_pid(&self, uid: u32, unit: &str) -> Result<Option<u32>, ()> {
        let s = self.user_systemctl(uid, &["show", "-p", "MainPID", "--value", unit])?;
        Ok(s.trim().parse().ok().filter(|p| *p > 0))
    }

    /// Whether the process behind `h` is the binary a unit of ours runs (see [`Exe`]).
    fn exe_is(&self, h: &ProcHandle, want: Exe) -> bool {
        use std::os::unix::fs::MetadataExt;
        let exe = h.base.join("exe");
        let Ok(link) = std::fs::read_link(&exe) else {
            return false;
        };
        // after a package upgrade replaces the binary, the kernel reads the link as `<path> (deleted)` until the unit restarts: the
        // name is still the one we protect, and the owner and mode check below follows the magic link to the running file
        let name = link.file_name().and_then(|n| n.to_str()).unwrap_or("");
        let name = name.strip_suffix(" (deleted)").unwrap_or(name);
        match want {
            Exe::Named(names) => names.contains(&name),
            Exe::RootOwned(names) => {
                names.contains(&name)
                    && std::fs::metadata(&exe)
                        .is_ok_and(|m| m.uid() == self.paths.root_uid && m.mode() & 0o022 == 0)
            }
        }
    }

    /// The pids of the web IDE's terminals: everything below one of its pty hosts (the process that starts a terminal's shell).
    /// Only those are raised, so the editor's own helpers (its extension host) keep the editor's order.
    fn terminal_pids(&self, procs: &[u32], main: u32) -> Vec<u32> {
        let mut parent = std::collections::BTreeMap::new();
        let mut hosts = Vec::new();
        for &p in procs {
            let Some(h) = self.open_proc(p) else { continue };
            // `pid (comm) S ppid ...`: the name may hold spaces and parentheses, so read after the LAST `)`
            let ppid = h.get("stat").and_then(|t| {
                t.rsplit_once(')')
                    .and_then(|(_, rest)| rest.split_whitespace().nth(1).map(str::to_string))
                    .and_then(|v| v.parse::<u32>().ok())
            });
            if let Some(pp) = ppid {
                parent.insert(p, pp);
            }
            if h.get("cmdline")
                .is_some_and(|c| c.split('\0').any(|w| w == "--type=ptyHost"))
            {
                hosts.push(p);
            }
        }
        procs
            .iter()
            .copied()
            .filter(|p| *p != main && !hosts.contains(p))
            .filter(|p| {
                let mut at = *p;
                // a process below a pty host, however deep (a build under a shell under a terminal)
                (0..64).any(|_| match parent.get(&at) {
                    Some(&pp) if hosts.contains(&pp) => true,
                    Some(&pp) => {
                        at = pp;
                        false
                    }
                    None => false,
                })
            })
            .collect()
    }

    /// The editor server's own processes: the direct children of the unit's main process that are the same binary and carry no
    /// `--type=` argument. code-server's main process is a wrapper that starts the server as its child within milliseconds of the
    /// start, so the child is what the editor actually is, and it keeps the user manager's score unless it is lowered too (N3).
    /// A helper the server starts (`--type=ptyHost`, `--type=extensionHost`) is not one of them: it keeps the editor's order, and
    /// the terminals below the pty host are raised, never lowered.
    fn server_pids(&self, procs: &[u32], main: u32, want: Exe) -> Vec<u32> {
        procs
            .iter()
            .copied()
            .filter(|p| *p != main)
            .filter(|p| {
                let Some(h) = self.open_proc(*p) else {
                    return false;
                };
                let ppid = h.get("stat").and_then(|t| {
                    t.rsplit_once(')')
                        .and_then(|(_, rest)| rest.split_whitespace().nth(1).map(str::to_string))
                        .and_then(|v| v.parse::<u32>().ok())
                });
                ppid == Some(main)
                    && !h
                        .get("cmdline")
                        .is_some_and(|c| c.split('\0').any(|w| w.starts_with("--type=")))
                    && self.exe_is(&h, want)
            })
            .collect()
    }

    /// Put the box's own services at their protected score now, wherever they run. Returns how many processes were changed.
    pub fn apply(&self) -> Result<String, String> {
        let mut changed = 0;
        for u in SYSTEM_PROTECTED.iter().chain(LIVE_ONLY_SYSTEM.iter()) {
            if let Some(h) = self.main_pid(u).and_then(|pid| self.open_proc(pid)) {
                changed += usize::from(self.lower_adj(&h, PROTECTED_OOM_SCORE_ADJ));
            }
        }
        if let Some(uid) = self.box_uid() {
            let base = self.paths.cgroup.join(format!(
                "user.slice/user-{uid}.slice/user@{uid}.service/app.slice"
            ));
            for u in USER_PROTECTED {
                let mut procs: Vec<u32> = read(&base.join(u.unit).join("cgroup.procs"))
                    .map(|t| t.lines().filter_map(|l| l.trim().parse().ok()).collect())
                    .unwrap_or_default();
                procs.sort_unstable();
                if procs.is_empty() {
                    continue;
                }
                // the MAIN process, as the unit's manager says (the box user owns the cgroup, so what it lists proves nothing);
                // a manager that cannot be asked leaves the first process, which must still pass the binary check below
                let main = match self.user_main_pid(uid, u.unit) {
                    Ok(m) => m.filter(|p| procs.contains(p)),
                    Err(()) => procs.first().copied(),
                };
                let Some(main) = main else { continue };
                let Some(h) = self.open_proc(main) else {
                    continue;
                };
                if !self.exe_is(&h, u.exe) {
                    continue;
                }
                changed += usize::from(self.lower_adj(&h, u.score));
                if u.terminals {
                    for sp in self.server_pids(&procs, main, u.exe) {
                        if let Some(sh) = self.open_proc(sp) {
                            changed += usize::from(self.lower_adj(&sh, u.score));
                        }
                    }
                    for t in self.terminal_pids(&procs, main) {
                        if let Some(th) = self.open_proc(t) {
                            changed += usize::from(self.raise_adj(&th, TERMINAL_OOM_SCORE_ADJ));
                        }
                    }
                }
            }
        }
        Ok(format!(
            "{changed} process(es) of the box's own services and terminals set to their OOM score"
        ))
    }

    /// Everything, once, on a running box; run by the helper (`ozbox admin <box> -- host-guard memory install`), first boot
    /// and `ozbox upgrade`. Restarts no unit.
    pub fn install(&self) -> Result<String, String> {
        write(
            &self.paths.system_units.join("ozbox-memory.service"),
            BOOT_UNIT,
        )?;
        write(
            &self.paths.system_units.join("ozbox-oom-apply.service"),
            APPLY_UNIT,
        )?;
        write(
            &self.paths.system_units.join("ozbox-oom-apply.timer"),
            APPLY_TIMER,
        )?;
        write(
            &self
                .paths
                .system_units
                .join("user@.service.d/10-ozbox-memory.conf"),
            DELEGATE_DROPIN,
        )?;
        let mut protected = 0;
        for u in SYSTEM_PROTECTED {
            if self.unit_exists(u) {
                write(
                    &self
                        .paths
                        .system_units
                        .join(format!("{u}.d/10-ozbox-memory.conf")),
                    &oom_dropin(u),
                )?;
                protected += 1;
            }
        }
        self.reload_system();
        // The swap and the sized files are made by the box's own unit, not in this process: the root helper runs this under a
        // sandbox that forbids loading a kernel module, and the unit is the same code a boot runs. Restarting THIS unit is the
        // only restart there is; it is a one-shot with nothing depending on it staying up.
        let _ = self.ok(CommandSpec::new("systemctl").args(["enable", "ozbox-memory.service"]));
        // The restart runs the guard's own `boot`, as root and outside this helper's sandbox, and that reloads the box user's
        // manager: so a failure here is the swap, the sized files or the reload, and is said, not assumed to have worked.
        let restarted =
            self.ok(CommandSpec::new("systemctl").args(["restart", "ozbox-memory.service"]));
        self.reload_system();
        let _ = self.ok(CommandSpec::new("systemctl").args([
            "enable",
            "--now",
            "ozbox-oom-apply.timer",
        ]));
        let applied = self.apply()?;
        let swaps = read(&self.paths.proc.join("swaps")).unwrap_or_default();
        let zram = if plan::swap_devices(&swaps).0.is_empty() {
            "NO compressed swap yet (this kernel may lack the zram module: `ozbox host-guard memory status` and `journalctl -u ozbox-memory` say why; no swap file is ever made in its place)".to_string()
        } else {
            "swap is compressed RAM".to_string()
        };
        if restarted.is_err() {
            return Err(format!("the files of the memory guard are written, but its unit failed ({zram}); read `journalctl -u ozbox-memory` for why (swap, the box user's manager or a file), then run this again. {applied}"));
        }
        Ok(format!(
            "Memory guard in place: {zram}. {protected} of the box's own services protected from the OOM killer at boot ({applied}); interactive terminals are slowed at their soft limit and a build killed in one dies alone, never the terminal or the editor. No service was restarted."
        ))
    }

    /// What is in force, in words a person reads.
    pub fn status(&self) -> String {
        let total = self.total();
        let s = sizing(total);
        let swaps = read(&self.paths.proc.join("swaps")).unwrap_or_default();
        let (zram, other) = plan::swap_devices(&swaps);
        let mut l = vec![format!("memory: {} MiB", total / plan::MIB)];
        l.push(if zram.is_empty() {
            "swap: none in RAM (a box without the memory guard, or a kernel without zram)"
                .to_string()
        } else {
            format!(
                "swap: compressed RAM {} ({} MiB wanted)",
                zram.join(", "),
                s.zram_bytes / plan::MIB
            )
        });
        if !other.is_empty() {
            l.push(format!(
                "swap: ON A DISK: {} (a secret page could reach it: run swapoff and remove it)",
                other.join(", ")
            ));
        }
        let vm = |f: &str| {
            read(&self.paths.proc.join("sys/vm").join(f))
                .map_or_else(|| "?".into(), |v| v.trim().to_string())
        };
        l.push(format!(
            "vm.swappiness={} vm.page-cluster={}",
            vm("swappiness"),
            vm("page-cluster")
        ));
        let psi = read(&self.paths.proc.join("pressure/memory")).unwrap_or_default();
        l.push(format!(
            "pressure (last 10 s): some {}% full {}%",
            plan::psi_value(&psi, "some", "avg10").map_or("?".into(), |v| v.to_string()),
            plan::psi_value(&psi, "full", "avg10").map_or("?".into(), |v| v.to_string())
        ));
        if let Some(uid) = self.box_uid() {
            let c = read(&self.paths.cgroup.join(format!(
                "user.slice/user-{uid}.slice/user@{uid}.service/cgroup.controllers"
            )));
            l.push(match c {
                Some(c) if c.split_whitespace().any(|w| w == "memory") => {
                    "the box user's manager has the memory controller: limits on its units work".to_string()
                }
                Some(_) => "the box user's manager does NOT have the memory controller yet (it is delegated at its next start: log the box user out, or restart the box when it is idle)".to_string(),
                None => "the box user's manager is not running".to_string(),
            });
        }
        let alone = |f: PathBuf| read(&f).is_some_and(|t| t.contains("OOMPolicy=continue"));
        l.push(
            if alone(
                self.paths
                    .user_units
                    .join("tmux-spawn-.scope.d/10-ozbox-memory.conf"),
            ) && IDE_UNITS.iter().all(|u| {
                alone(
                    self.paths
                        .user_units
                        .join(format!("{u}.d/10-ozbox-memory.conf")),
                )
            }) {
                "a build killed for memory in a terminal or the web IDE dies alone: OOMPolicy=continue is in place".to_string()
            } else {
                "OOMPolicy=continue is NOT in place for terminals and the web IDE: a build killed for memory can take its whole terminal scope with it (run `ozbox host-guard memory install`)".to_string()
            },
        );
        l.push(format!(
            "one job's cap: {} MiB (throttled at {} MiB); the box keeps {} MiB",
            s.run_max_bytes / plan::MIB,
            s.run_high_bytes / plan::MIB,
            s.reserve_bytes / plan::MIB
        ));
        l.join("\n")
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;
    use std::sync::Mutex;

    use ozbox_core::Output;

    fn out(stdout: &str) -> Output {
        Output {
            status: Some(0),
            stdout: stdout.into(),
            stderr: String::new(),
        }
    }

    /// A box in a temporary folder: 8 GiB, a zram device the kernel offers, and the cgroup and proc trees the guard reads.
    struct Machine {
        d: tempfile::TempDir,
    }

    impl Machine {
        fn new() -> Self {
            let d = tempfile::tempdir().unwrap();
            let p = d.path();
            std::fs::create_dir_all(p.join("proc/sys/vm")).unwrap();
            std::fs::write(p.join("proc/meminfo"), "MemTotal:       8388608 kB\n").unwrap();
            std::fs::write(
                p.join("proc/swaps"),
                "Filename\tType\tSize\tUsed\tPriority\n",
            )
            .unwrap();
            std::fs::create_dir_all(p.join("sys/block/zram0")).unwrap();
            std::fs::create_dir_all(p.join("units")).unwrap();
            for u in SYSTEM_PROTECTED {
                std::fs::write(p.join("units").join(u), "[Service]\n").unwrap();
            }
            Self { d }
        }
        fn paths(&self) -> Paths {
            let p = self.d.path();
            Paths {
                system_units: p.join("etc/system"),
                unit_dirs: vec![p.join("units")],
                user_units: p.join("etc/user"),
                sysctl_d: p.join("etc/sysctl.d"),
                sys_block: p.join("sys/block"),
                zram_control: p.join("sys/class/zram-control"),
                proc: p.join("proc"),
                cgroup: p.join("cgroup"),
                // the test's own files are owned by whoever runs the test, standing in for root
                root_uid: {
                    use std::os::unix::fs::MetadataExt;
                    std::fs::metadata(p).unwrap().uid()
                },
            }
        }
        /// A process of the fake box: its score, its binary (a symlink to a real file, as `/proc/<pid>/exe` is), its command line
        /// and its parent.
        fn process(&self, pid: u32, adj: i32, exe: &str, cmdline: &str, ppid: u32) {
            let d = self.d.path().join(format!("proc/{pid}"));
            std::fs::create_dir_all(&d).unwrap();
            std::fs::write(d.join("oom_score_adj"), format!("{adj}\n")).unwrap();
            let bin = self.d.path().join("bin").join(exe);
            std::fs::create_dir_all(bin.parent().unwrap()).unwrap();
            std::fs::write(&bin, "").unwrap();
            let _ = std::fs::remove_file(d.join("exe"));
            std::os::unix::fs::symlink(&bin, d.join("exe")).unwrap();
            std::fs::write(d.join("cmdline"), cmdline.replace(' ', "\0")).unwrap();
            std::fs::write(d.join("stat"), format!("{pid} (a (b) c) S {ppid} 1 1 0\n")).unwrap();
        }
        /// The unit's cgroup (the box user's manager owns it) with these processes.
        fn unit_procs(&self, unit: &str, pids: &str) {
            let c = self.d.path().join(format!(
                "cgroup/user.slice/user-1500.slice/user@1500.service/app.slice/{unit}"
            ));
            std::fs::create_dir_all(&c).unwrap();
            std::fs::write(c.join("cgroup.procs"), pids).unwrap();
        }
        fn status_line_oom_policy(&self) -> bool {
            let r = Fake::default();
            Guard {
                runner: &r,
                paths: self.paths(),
            }
            .status()
            .contains("OOMPolicy=continue is in place")
        }
        fn adj(&self, pid: u32) -> String {
            self.file(&format!("proc/{pid}/oom_score_adj"))
                .trim()
                .to_string()
        }
        fn file(&self, rel: &str) -> String {
            std::fs::read_to_string(self.d.path().join(rel)).unwrap_or_default()
        }
    }

    /// Answers by program: `id` is 1500, `systemctl show` gives the unit's pid (0 when the unit is not listed), everything else
    /// succeeds with no output. Records every command.
    #[derive(Default)]
    struct Fake {
        calls: Mutex<Vec<CommandSpec>>,
        pids: BTreeMap<String, u32>,
        /// What the box user's manager says is a unit's main process (`runuser ... systemctl --user show`).
        user_pids: BTreeMap<String, u32>,
        /// `runuser` fails (the box user's bus cannot be reached).
        runuser_fails: bool,
        /// `systemctl --user -M` fails too.
        machined_fails: bool,
    }

    impl Fake {
        fn calls(&self) -> Vec<CommandSpec> {
            self.calls.lock().unwrap().clone()
        }
    }

    impl CommandRunner for Fake {
        fn run(&self, cmd: &CommandSpec) -> ozbox_core::Result<Output> {
            self.calls.lock().unwrap().push(cmd.clone());
            let refused = (cmd.program == "runuser" && self.runuser_fails)
                || (cmd.program == "systemctl"
                    && cmd.args.iter().any(|a| a == "-M")
                    && self.machined_fails);
            if refused {
                return Ok(Output {
                    status: Some(1),
                    stdout: String::new(),
                    stderr: String::new(),
                });
            }
            if cmd.program == "runuser" && cmd.args.iter().any(|a| a == "show") {
                let unit = cmd.args.last().map_or("", String::as_str);
                return Ok(out(&format!(
                    "{}\n",
                    self.user_pids.get(unit).copied().unwrap_or(0)
                )));
            }
            let stdout = match (cmd.program.as_str(), cmd.args.first().map(String::as_str)) {
                ("id", _) => "1500\n".to_string(),
                ("systemctl", Some("show")) => {
                    format!(
                        "{}\n",
                        self.pids
                            .get(cmd.args.last().map_or("", String::as_str))
                            .copied()
                            .unwrap_or(0)
                    )
                }
                _ => String::new(),
            };
            Ok(out(&stdout))
        }
    }

    fn runner() -> Fake {
        Fake::default()
    }

    #[test]
    fn compressed_ram_is_the_only_swap_the_guard_ever_makes() {
        let b = Machine::new();
        let r = runner();
        let g = Guard {
            runner: &r,
            paths: b.paths(),
        };
        let msg = g.zram_up().unwrap();
        assert!(msg.contains("4096 MiB") && msg.contains("zstd"), "{msg}");
        // what was configured on the device: the algorithm, the size and the cap on what it may hold
        assert_eq!(b.file("sys/block/zram0/comp_algorithm"), "zstd");
        assert_eq!(b.file("sys/block/zram0/disksize"), (4u64 << 30).to_string());
        assert_eq!(
            b.file("sys/block/zram0/mem_limit"),
            sizing(8 << 30).zram_mem_limit_bytes.to_string()
        );
        // every command that makes or turns on swap names only the zram device, and swap is high priority
        let calls = r.calls();
        let swap: Vec<_> = calls
            .iter()
            .filter(|c| c.program == "mkswap" || c.program == "swapon")
            .collect();
        assert_eq!(swap.len(), 2);
        for c in swap {
            assert!(c.args.iter().any(|a| a == ZRAM_DEVICE), "{c:?}");
            assert!(
                !c.args.iter().any(|a| a.starts_with("/swap")
                    || a.contains("nvme")
                    || a.contains("xvd")
                    || a.contains("work")),
                "{c:?}"
            );
        }
        assert!(calls.iter().any(|c| c.program == "swapon"
            && c.args.join(" ") == format!("--priority 100 {ZRAM_DEVICE}")));
    }

    #[test]
    fn a_kernel_without_the_module_gets_no_swap_and_says_why_never_a_file() {
        let b = Machine::new();
        std::fs::remove_dir_all(b.d.path().join("sys/block/zram0")).unwrap();
        let r = runner();
        let g = Guard {
            runner: &r,
            paths: b.paths(),
        };
        let e = g.zram_up().unwrap_err();
        assert!(
            e.contains("linux-modules-extra") && e.contains("must not reach a disk"),
            "{e}"
        );
        assert!(
            r.calls().iter().any(|c| c.program == "modprobe"),
            "it tried the module first"
        );
        assert!(!r.calls().iter().any(|c| c.program == "mkswap"
            || c.program == "swapon"
            || c.program == "fallocate"
            || c.program == "dd"));
        // and the boot does not fail over it
        let g = Guard {
            runner: &r,
            paths: b.paths(),
        };
        assert!(g.boot().unwrap().starts_with("no compressed swap"));
    }

    #[test]
    fn a_box_that_already_swaps_to_zram_is_left_alone() {
        let b = Machine::new();
        std::fs::write(
            b.d.path().join("proc/swaps"),
            "Filename\tType\tSize\tUsed\tPriority\n/dev/zram0 partition 1 0 100\n",
        )
        .unwrap();
        let r = runner();
        let g = Guard {
            runner: &r,
            paths: b.paths(),
        };
        assert!(g.zram_up().unwrap().contains("already active"));
        assert!(r.calls().is_empty());
    }

    #[test]
    fn nothing_the_guard_writes_names_a_disk_for_swap() {
        let all = [
            BOOT_UNIT.to_string(),
            APPLY_UNIT.into(),
            APPLY_TIMER.into(),
            sysctl_conf(),
            DELEGATE_DROPIN.into(),
            oom_dropin(SECRETS_UNIT),
            soft_limit_dropin(&sizing(8 << 30)),
        ];
        for t in &all {
            for word in [
                "swapfile",
                "fallocate",
                "dd if=",
                "/dev/sd",
                "/dev/nvme",
                "/dev/xvd",
                "mkswap /",
                "swapon /",
            ] {
                assert!(!t.contains(word), "{word} in {t}");
            }
        }
        assert!(oom_dropin(SECRETS_UNIT).contains("MemorySwapMax=0"));
        assert!(!oom_dropin("ozboxd.service").contains("MemorySwapMax"));
    }

    #[test]
    fn the_box_services_get_a_protected_score_and_the_workloads_never_do() {
        let b = Machine::new();
        let r = runner();
        let g = Guard {
            runner: &r,
            paths: b.paths(),
        };
        g.install().unwrap();
        for u in SYSTEM_PROTECTED {
            let t = b.file(&format!("etc/system/{u}.d/10-ozbox-memory.conf"));
            assert!(t.contains("OOMScoreAdjust=-900"), "{u}: {t}");
        }
        // the SSH daemon's sessions would inherit a unit setting: it is live only
        assert!(!b.d.path().join("etc/system/ssh.service.d").exists());
        // the whole user manager is never lowered (that would protect the workloads equally), and no workload unit is named
        for dir in ["etc/system/user@.service.d", "etc/user"] {
            let walk = |p: PathBuf| -> String {
                let mut s = String::new();
                fn go(p: &Path, s: &mut String) {
                    if let Ok(rd) = std::fs::read_dir(p) {
                        for e in rd.flatten() {
                            if e.path().is_dir() {
                                go(&e.path(), s)
                            } else {
                                s.push_str(&std::fs::read_to_string(e.path()).unwrap_or_default())
                            }
                        }
                    }
                }
                go(&p, &mut s);
                s
            };
            assert!(
                !walk(b.d.path().join(dir)).contains("OOMScoreAdjust"),
                "{dir}"
            );
        }
        assert!(b
            .file("etc/system/user@.service.d/10-ozbox-memory.conf")
            .contains("Delegate=pids memory cpu"));
        assert!(!b.d.path().join("etc/system/user.slice.d").exists());
        // only units the box has get a drop-in
        let b2 = Machine::new();
        std::fs::remove_file(b2.d.path().join("units/ozbox-code-connector.service")).unwrap();
        let r2 = runner();
        Guard {
            runner: &r2,
            paths: b2.paths(),
        }
        .install()
        .unwrap();
        assert!(!b2
            .d
            .path()
            .join("etc/system/ozbox-code-connector.service.d")
            .exists());
    }

    #[test]
    fn user_units_are_protected_at_their_main_process_only_and_the_ides_terminals_are_raised() {
        let b = Machine::new();
        // the tunnel: its main process (the manager's word) and a stranger the box user put in the cgroup
        b.unit_procs("oz-cloudflared.service", "300\n301\n");
        b.process(300, 100, "cloudflared", "cloudflared tunnel run", 1);
        b.process(301, 100, "cloudflared", "cloudflared", 300);
        // the IDE: node (main, 400), the pty host (410), a shell (420), a build under it (430), the extension host (440)
        b.unit_procs("oz-code-server.service", "430\n400\n410\n420\n440\n");
        b.process(400, 100, "node", "node code-server", 1);
        b.process(410, 100, "node", "node --type=ptyHost", 400);
        b.process(420, -500, "bash", "bash", 410);
        b.process(430, -500, "node", "node build", 420);
        b.process(440, -500, "node", "node --type=extensionHost", 400);
        let mut r = runner();
        r.user_pids.insert("oz-cloudflared.service".into(), 300);
        r.user_pids.insert("oz-code-server.service".into(), 400);
        let g = Guard {
            runner: &r,
            paths: b.paths(),
        };
        g.apply().unwrap();
        assert_eq!(b.adj(300), "-900", "the tunnel's main process");
        assert_eq!(
            b.adj(301),
            "100",
            "not its other processes: only the main one"
        );
        assert_eq!(b.adj(400), "-500", "the IDE's main process");
        // what a terminal started with, inherited from the IDE, is raised to a tmux pane's score, and only that
        assert_eq!((b.adj(420).as_str(), b.adj(430).as_str()), ("200", "200"));
        assert_eq!(
            b.adj(440),
            "-500",
            "the editor's own helper keeps the editor's order"
        );
        assert_eq!(b.adj(410), "100", "the pty host itself is not a terminal");
        // a process already lower is never raised by the protection, and one already higher is never lowered by the raise
        std::fs::write(b.d.path().join("proc/300/oom_score_adj"), "-1000").unwrap();
        std::fs::write(b.d.path().join("proc/420/oom_score_adj"), "500").unwrap();
        Guard {
            runner: &r,
            paths: b.paths(),
        }
        .apply()
        .unwrap();
        assert_eq!((b.adj(300).as_str(), b.adj(420).as_str()), ("-1000", "500"));
    }

    #[test]
    fn the_editor_server_behind_the_wrapper_is_protected_and_its_terminals_stay_at_a_terminals_score(
    ) {
        let b = Machine::new();
        // code-server: the wrapper (main, 600), the server it starts (610, no --type), its pty host (620) and extension host
        // (640), a terminal shell (630) with a build under it (650), a stranger's process that is not node (660) and a
        // node that is not a direct child of the main (670, below the server)
        b.unit_procs(
            "oz-code-server.service",
            "600\n610\n620\n630\n640\n650\n660\n670\n",
        );
        b.process(600, 100, "node", "node wrapper", 1);
        b.process(610, 100, "node", "node server", 600);
        b.process(620, 100, "node", "node --type=ptyHost", 610);
        b.process(630, 100, "bash", "bash", 620);
        b.process(650, 100, "node", "node build", 630);
        b.process(640, 100, "node", "node --type=extensionHost", 610);
        b.process(660, 100, "sleep", "sleep 5", 600);
        b.process(670, 100, "node", "node other", 610);
        let mut r = runner();
        r.user_pids.insert("oz-code-server.service".into(), 600);
        Guard {
            runner: &r,
            paths: b.paths(),
        }
        .apply()
        .unwrap();
        assert_eq!(b.adj(600), "-500", "the wrapper");
        assert_eq!(
            b.adj(610),
            "-500",
            "the editor server: a direct child, same binary, no --type"
        );
        assert_eq!(
            (b.adj(630).as_str(), b.adj(650).as_str()),
            ("200", "200"),
            "terminals below the pty host are raised, never lowered"
        );
        assert_eq!(b.adj(620), "100", "the pty host is not protected");
        assert_eq!(
            b.adj(640),
            "100",
            "a --type= helper keeps the editor's order"
        );
        assert_eq!(
            b.adj(660),
            "100",
            "a direct child that is not the editor binary"
        );
        assert_eq!(
            b.adj(670),
            "100",
            "only direct children of the main process"
        );
        // a server that was already lower is not raised, and one at a higher score is lowered only to the unit's score
        std::fs::write(b.d.path().join("proc/610/oom_score_adj"), "-900").unwrap();
        Guard {
            runner: &r,
            paths: b.paths(),
        }
        .apply()
        .unwrap();
        assert_eq!(b.adj(610), "-900");
        // the tunnel (terminals: false) never gets this treatment for its children
        b.unit_procs("oz-cloudflared.service", "700\n710\n");
        b.process(700, 100, "cloudflared", "cloudflared tunnel", 1);
        b.process(710, 100, "cloudflared", "cloudflared child", 700);
        r.user_pids.insert("oz-cloudflared.service".into(), 700);
        Guard {
            runner: &r,
            paths: b.paths(),
        }
        .apply()
        .unwrap();
        assert_eq!((b.adj(700).as_str(), b.adj(710).as_str()), ("-900", "100"));
    }

    #[test]
    fn a_unit_the_box_user_made_up_is_never_protected_a_stranger_binary_a_wrong_main_process_a_reused_id(
    ) {
        let b = Machine::new();
        // L1: the box user names a unit after ours and puts a process of its own in it
        b.unit_procs("oz-cloudflared.service", "500\n");
        b.process(500, 0, "sleep", "sleep 1000", 1);
        // a tunnel whose binary is the right name but not root-owned stays unprotected
        b.unit_procs("ozbox-cloudflared.service", "510\n");
        b.process(510, 0, "cloudflared", "cloudflared", 1);
        let mut paths = b.paths();
        paths.root_uid += 1;
        // the manager says the main process is 520, which the cgroup does not list: nothing is protected
        b.unit_procs("oz-code-server.service", "530\n");
        b.process(530, 0, "node", "node", 1);
        b.process(520, 0, "node", "node", 1);
        let mut r = runner();
        r.user_pids.insert("oz-cloudflared.service".into(), 500);
        r.user_pids.insert("ozbox-cloudflared.service".into(), 510);
        r.user_pids.insert("oz-code-server.service".into(), 520);
        Guard { runner: &r, paths }.apply().unwrap();
        assert_eq!(b.adj(500), "0", "sleep is not cloudflared");
        assert_eq!(
            b.adj(510),
            "0",
            "a cloudflared the box user owns is not the root-owned one"
        );
        assert_eq!((b.adj(520).as_str(), b.adj(530).as_str()), ("0", "0"));
        // a process id that vanished between the manager's answer and the write is skipped without a trace
        b.unit_procs("oz-code-server.service", "999\n");
        let mut r2 = runner();
        r2.user_pids.insert("oz-code-server.service".into(), 999);
        assert!(Guard {
            runner: &r2,
            paths: b.paths(),
        }
        .apply()
        .is_ok());
    }

    #[test]
    fn a_binary_replaced_by_a_package_upgrade_keeps_its_score_but_a_lookalike_name_does_not() {
        let b = Machine::new();
        // `/proc/<pid>/exe` reads `.../cloudflared (deleted)` after the package replaces the file under a running unit
        b.unit_procs("oz-cloudflared.service", "300\n");
        b.process(300, 100, "cloudflared (deleted)", "cloudflared", 1);
        // the suffix is stripped once and only at the end: another name with it is still a stranger
        b.unit_procs("ozbox-cloudflared.service", "310\n");
        b.process(310, 100, "sleep (deleted)", "sleep", 1);
        let mut r = runner();
        r.user_pids.insert("oz-cloudflared.service".into(), 300);
        r.user_pids.insert("ozbox-cloudflared.service".into(), 310);
        Guard {
            runner: &r,
            paths: b.paths(),
        }
        .apply()
        .unwrap();
        assert_eq!(
            b.adj(300),
            "-900",
            "an upgraded tunnel keeps its protection"
        );
        assert_eq!(b.adj(310), "100");
    }

    #[test]
    fn a_manager_that_cannot_be_asked_leaves_the_first_process_still_subject_to_the_binary_check() {
        let b = Machine::new();
        b.unit_procs("oz-cloudflared.service", "300\n301\n");
        b.process(300, 100, "cloudflared", "cloudflared", 1);
        b.process(301, 100, "sleep", "sleep", 1);
        let mut r = runner();
        r.runuser_fails = true;
        Guard {
            runner: &r,
            paths: b.paths(),
        }
        .apply()
        .unwrap();
        assert_eq!((b.adj(300).as_str(), b.adj(301).as_str()), ("-900", "100"));
    }

    #[test]
    fn the_system_units_main_processes_are_set_live_and_a_stopped_unit_is_skipped() {
        let b = Machine::new();
        std::fs::create_dir_all(b.d.path().join("proc/900")).unwrap();
        std::fs::write(b.d.path().join("proc/900/oom_score_adj"), "0\n").unwrap();
        let mut r = runner();
        r.pids.insert("ozboxd.service".into(), 900);
        let g = Guard {
            runner: &r,
            paths: b.paths(),
        };
        g.apply().unwrap();
        assert_eq!(b.file("proc/900/oom_score_adj"), "-900");
        let shows: Vec<_> = r
            .calls()
            .into_iter()
            .filter(|c| c.program == "systemctl")
            .collect();
        assert_eq!(shows.len(), SYSTEM_PROTECTED.len() + LIVE_ONLY_SYSTEM.len());
        assert!(
            shows.iter().all(|c| c.args[0] == "show"),
            "it only asks, it never restarts"
        );
    }

    #[test]
    fn install_restarts_nothing_and_asks_systemd_only_to_reload_and_enable() {
        let b = Machine::new();
        let r = runner();
        let g = Guard {
            runner: &r,
            paths: b.paths(),
        };
        let msg = g.install().unwrap();
        assert!(msg.contains("No service was restarted"), "{msg}");
        for c in r.calls() {
            if c.program == "systemctl" {
                let verb = c.args.first().map(String::as_str).unwrap_or("");
                assert!(
                    ["daemon-reload", "enable", "show", "restart"].contains(&verb),
                    "{c:?}"
                );
                // the guard's own one-shot is the only unit it restarts; no service of the box is stopped or restarted
                if verb == "restart" {
                    assert_eq!(c.args, ["restart", "ozbox-memory.service"], "{c:?}");
                }
                assert!(
                    !c.args
                        .iter()
                        .any(|a| a == "stop" || a == "start" || a == "try-restart" || a == "kill"),
                    "{c:?}"
                );
            }
            assert!(
                !["kill", "pkill", "swapoff", "reboot"].contains(&c.program.as_str()),
                "{c:?}"
            );
        }
        // the timer is what keeps the scores, and it is started without touching another unit
        assert!(r
            .calls()
            .iter()
            .any(|c| c.args.join(" ") == "enable --now ozbox-oom-apply.timer"));
        // the unit does the swap and the sized files: run what it runs
        Guard {
            runner: &runner(),
            paths: b.paths(),
        }
        .boot()
        .unwrap();
        // the soft limits: a throttle for an interactive scope, never a kill
        for f in [
            "etc/user/tmux-spawn-.scope.d/10-ozbox-memory.conf",
            "etc/system/session-.scope.d/10-ozbox-memory.conf",
        ] {
            let t = b.file(f);
            assert!(
                t.contains(&format!("MemoryHigh={}", sizing(8 << 30).run_high_bytes)),
                "{f}: {t}"
            );
            assert!(
                !t.contains("MemoryMax") && !t.contains("MemorySwapMax"),
                "{f}"
            );
        }
        // a kill of one process in them ends that process only (OOMPolicy), never the scope or the editor (H1)
        for f in [
            "etc/user/tmux-spawn-.scope.d/10-ozbox-memory.conf",
            "etc/system/session-.scope.d/10-ozbox-memory.conf",
            "etc/user/oz-code-server.service.d/10-ozbox-memory.conf",
            "etc/user/ozbox-ide.service.d/10-ozbox-memory.conf",
        ] {
            assert!(b.file(f).contains("OOMPolicy=continue"), "{f}");
        }
        assert!(b.status_line_oom_policy());
        assert!(b
            .file("etc/sysctl.d/60-ozbox-memory.conf")
            .contains("vm.swappiness = 100"));
        // running it again changes nothing on disk and still restarts nothing
        let r2 = runner();
        Guard {
            runner: &r2,
            paths: b.paths(),
        }
        .install()
        .unwrap();
        assert!(r2
            .calls()
            .iter()
            .filter(|c| c.args.iter().any(|a| a == "restart"))
            .all(|c| c.args == ["restart", "ozbox-memory.service"]));
    }

    #[test]
    fn the_box_users_manager_is_reloaded_from_root_with_a_second_way_and_a_failure_is_said() {
        let manager = |b: &Machine| {
            std::fs::create_dir_all(
                b.d.path()
                    .join("cgroup/user.slice/user-1500.slice/user@1500.service"),
            )
            .unwrap()
        };
        // a manager that is not running has nothing to reload
        let b = Machine::new();
        let r = runner();
        let g = Guard {
            runner: &r,
            paths: b.paths(),
        };
        assert!(g.reload_user().unwrap().contains("not running"));
        assert!(!r.calls().iter().any(|c| c.program == "runuser"));
        // the first way: root becomes the box user and names its runtime folder
        manager(&b);
        let r = runner();
        let g = Guard {
            runner: &r,
            paths: b.paths(),
        };
        assert!(g.reload_user().unwrap().contains("reloaded"));
        let c = r.calls();
        let c = c.iter().find(|c| c.program == "runuser").unwrap();
        assert_eq!(
            c.args,
            ["-u", "ozbox", "--", "systemctl", "--user", "daemon-reload"]
        );
        assert!(c
            .env
            .iter()
            .any(|(k, v)| k == "XDG_RUNTIME_DIR" && v == "/run/user/1500"));
        // the second way, when the first fails
        let mut r = runner();
        r.runuser_fails = true;
        let g = Guard {
            runner: &r,
            paths: b.paths(),
        };
        assert!(g.reload_user().unwrap().contains("machined"));
        assert!(r
            .calls()
            .iter()
            .any(|c| c.args == ["--user", "-M", "ozbox@", "daemon-reload"]));
        // both fail: said in words, and the boot fails with it so the restart that `install` makes reports it
        let mut r = runner();
        r.runuser_fails = true;
        r.machined_fails = true;
        let g = Guard {
            runner: &r,
            paths: b.paths(),
        };
        assert!(g
            .reload_user()
            .unwrap_err()
            .contains("could not be reloaded"));
        assert!(g.boot().is_err());
    }

    #[test]
    fn an_install_whose_unit_failed_says_so_instead_of_saying_the_guard_is_in_place() {
        struct Failing(Fake);
        impl CommandRunner for Failing {
            fn run(&self, cmd: &CommandSpec) -> ozbox_core::Result<Output> {
                if cmd.program == "systemctl" && cmd.args.first().is_some_and(|a| a == "restart") {
                    return Ok(Output {
                        status: Some(1),
                        stdout: String::new(),
                        stderr: String::new(),
                    });
                }
                self.0.run(cmd)
            }
        }
        let b = Machine::new();
        let r = Failing(runner());
        let e = Guard {
            runner: &r,
            paths: b.paths(),
        }
        .install()
        .unwrap_err();
        assert!(e.contains("journalctl -u ozbox-memory"), "{e}");
        assert!(!e.contains("Memory guard in place"), "{e}");
    }

    #[test]
    fn status_names_a_swap_on_a_disk_and_a_missing_memory_controller() {
        let b = Machine::new();
        std::fs::write(
            b.d.path().join("proc/swaps"),
            "Filename\tType\tSize\tUsed\tPriority\n/swapfile file 1 0 -2\n",
        )
        .unwrap();
        std::fs::create_dir_all(
            b.d.path()
                .join("cgroup/user.slice/user-1500.slice/user@1500.service"),
        )
        .unwrap();
        std::fs::write(
            b.d.path()
                .join("cgroup/user.slice/user-1500.slice/user@1500.service/cgroup.controllers"),
            "cpu pids\n",
        )
        .unwrap();
        let r = runner();
        let s = Guard {
            runner: &r,
            paths: b.paths(),
        }
        .status();
        assert!(
            s.contains("ON A DISK: /swapfile") && s.contains("does NOT have the memory controller"),
            "{s}"
        );
        assert!(s.contains("one job's cap: 7168 MiB"), "{s}");
    }
}
