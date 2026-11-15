//! Growing the `/work` filesystem after its disk was enlarged.
//!
//! A cloud disk can be made bigger while the box runs, but the filesystem on it stays the old size until something
//! tells it to grow. This module is the pure decision plus the one command that does it.
//!
//! Privilege: growing a mounted filesystem needs `CAP_SYS_RESOURCE` (ext4) or `CAP_SYS_ADMIN` (xfs), which the unprivileged daemon deliberately does not
//! have. So the daemon never grows anything itself. `ozboxd growfs` (this module, run by a dedicated hardened
//! one-shot unit on a one-minute timer) does the single command and writes a small result file; the daemon only reads
//! that file, reports it as an incident, and the self-test checks the outcome.

use std::path::Path;

use ozbox_core::{CommandRunner, CommandSpec};
use serde::{Deserialize, Serialize};

use crate::host::HostSource;

/// Sectors in `/sys/class/block/<dev>/size` are always 512 bytes, whatever the device's block size.
pub const SECTOR_BYTES: u64 = 512;
/// Where the one-shot writes its last result (a systemd runtime directory, readable by the daemon).
pub const RESULT_PATH: &str = "/run/ozbox-growfs/last.json";
/// A growth that failed is not retried for the same device size until this long has passed.
pub const RETRY_AFTER_MS: u64 = 3_600_000;

/// Size in bytes from the text of `/sys/class/block/<dev>/size`.
pub fn parse_block_size(text: &str) -> Option<u64> {
    text.trim()
        .parse::<u64>()
        .ok()
        .and_then(|s| s.checked_mul(SECTOR_BYTES))
}

/// The sysfs entry for a device path such as `/dev/nvme1n1`. Only a plain `/dev/<name>` qualifies; device-mapper
/// and other aliases return `None` (the check then reports that it cannot tell, never a guess).
pub fn size_path(device: &str) -> Option<String> {
    let name = device.strip_prefix("/dev/")?;
    if name.is_empty() || name.contains('/') || name.contains("..") || name.starts_with("mapper") {
        return None;
    }
    Some(format!("/sys/class/block/{name}/size"))
}

/// `(device, filesystem type)` of the mount at `mountpoint` in `/proc/mounts`.
pub fn parse_mount_entry(text: &str, mountpoint: &str) -> Option<(String, String)> {
    text.lines().find_map(|l| {
        let mut it = l.split_whitespace();
        let dev = it.next()?;
        let mp = it.next()?;
        let fs = it.next()?;
        (mp == mountpoint).then(|| (dev.to_string(), fs.to_string()))
    })
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Observation {
    pub device: String,
    pub fstype: String,
    pub device_bytes: u64,
    /// Total bytes of the mounted filesystem (statvfs): the data area, without its own metadata.
    pub fs_bytes: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ObserveError {
    NotMounted,
    UnknownDevice(String),
    Unreadable(String),
}

impl std::fmt::Display for ObserveError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NotMounted => write!(f, "the work disk is not mounted"),
            Self::UnknownDevice(d) => write!(f, "cannot find the size of device {d}"),
            Self::Unreadable(w) => write!(f, "cannot read {w}"),
        }
    }
}

/// Look at the `/work` disk and its filesystem.
pub fn observe(host: &dyn HostSource, work: &Path) -> Result<Observation, ObserveError> {
    let mounts = host
        .read("/proc/mounts")
        .map_err(|_| ObserveError::Unreadable("the mount table".into()))?;
    let (device, fstype) =
        parse_mount_entry(&mounts, &work.to_string_lossy()).ok_or(ObserveError::NotMounted)?;
    let path = size_path(&device).ok_or_else(|| ObserveError::UnknownDevice(device.clone()))?;
    let device_bytes = host
        .read(&path)
        .ok()
        .and_then(|t| parse_block_size(&t))
        .ok_or_else(|| ObserveError::UnknownDevice(device.clone()))?;
    let fs_bytes = host
        .disk_space(work)
        .map_err(|_| ObserveError::Unreadable("the filesystem size".into()))?
        .total_bytes;
    Ok(Observation {
        device,
        fstype,
        device_bytes,
        fs_bytes,
    })
}

/// How much smaller than its disk a filesystem may be and still count as filling it: the filesystem's own metadata
/// (inode tables, journal) is not in the figure statvfs reports. 1/16 of the disk, at least 128 MiB.
pub fn slack_bytes(device_bytes: u64) -> u64 {
    (device_bytes / 16).max(128 << 20)
}

/// Does the filesystem fill its disk (within the metadata allowance)?
pub fn fills_disk(o: &Observation) -> bool {
    o.device_bytes <= o.fs_bytes.saturating_add(slack_bytes(o.device_bytes))
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Tool {
    Resize2fs,
    XfsGrowfs,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Decision {
    InSync,
    Grow(Tool),
    Unsupported(String),
}

pub fn decide(o: &Observation) -> Decision {
    if fills_disk(o) {
        return Decision::InSync;
    }
    match o.fstype.as_str() {
        "ext2" | "ext3" | "ext4" => Decision::Grow(Tool::Resize2fs),
        "xfs" => Decision::Grow(Tool::XfsGrowfs),
        other => Decision::Unsupported(format!("cannot grow a {other} filesystem")),
    }
}

/// argv for the grow. ext4 takes the device, xfs the mount point. Never a shell string.
pub fn grow_command(tool: Tool, o: &Observation, work: &Path) -> CommandSpec {
    match tool {
        Tool::Resize2fs => CommandSpec::new("resize2fs").arg(o.device.clone()),
        Tool::XfsGrowfs => CommandSpec::new("xfs_growfs").arg(work.to_string_lossy().into_owned()),
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Action {
    Grown,
    Failed,
    Unsupported,
}

/// The one-shot's result. Numbers and an action word only, never paths of user files.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GrowRecord {
    pub ts_ms: u64,
    pub action: Action,
    pub device_bytes: u64,
    pub fs_bytes_before: u64,
    pub fs_bytes_after: Option<u64>,
    pub tool: Option<String>,
    pub detail: String,
}

fn gib(b: u64) -> String {
    let tenths = b.saturating_mul(10) / (1 << 30);
    format!("{}.{} GiB", tenths / 10, tenths % 10)
}

/// Look, and grow when the disk is bigger than the filesystem. `None` means nothing to report: already in sync, or a
/// failure for this very disk size that is still inside its retry window.
pub fn run_once(
    host: &dyn HostSource,
    runner: &dyn CommandRunner,
    work: &Path,
    now_ms: u64,
    previous: Option<&GrowRecord>,
) -> Option<GrowRecord> {
    let obs = match observe(host, work) {
        Ok(o) => o,
        Err(_) => return None, // not mounted yet, or not a plain device: the self-test says so
    };
    let tool = match decide(&obs) {
        Decision::InSync => return None,
        Decision::Unsupported(why) => {
            let rec = GrowRecord {
                ts_ms: now_ms,
                action: Action::Unsupported,
                device_bytes: obs.device_bytes,
                fs_bytes_before: obs.fs_bytes,
                fs_bytes_after: None,
                tool: None,
                detail: why,
            };
            return if retry_suppressed(previous, &rec) {
                None
            } else {
                Some(rec)
            };
        }
        Decision::Grow(t) => t,
    };
    if let Some(p) = previous {
        if matches!(p.action, Action::Failed)
            && p.device_bytes == obs.device_bytes
            && now_ms.saturating_sub(p.ts_ms) < RETRY_AFTER_MS
        {
            return None;
        }
    }
    let name = match tool {
        Tool::Resize2fs => "resize2fs",
        Tool::XfsGrowfs => "xfs_growfs",
    };
    let result = runner.run_ok(&grow_command(tool, &obs, work));
    let after = observe(host, work).ok().map(|o| o.fs_bytes);
    let (action, detail) = match result {
        Ok(_) => (
            Action::Grown,
            format!(
                "grew the /work filesystem from {} to {} to fill its {} disk ({name})",
                gib(obs.fs_bytes),
                gib(after.unwrap_or(obs.fs_bytes)),
                gib(obs.device_bytes)
            ),
        ),
        Err(e) => (
            Action::Failed,
            format!("could not grow the /work filesystem ({name}): {e}"),
        ),
    };
    Some(GrowRecord {
        ts_ms: now_ms,
        action,
        device_bytes: obs.device_bytes,
        fs_bytes_before: obs.fs_bytes,
        fs_bytes_after: after,
        tool: Some(name.into()),
        detail,
    })
}

fn retry_suppressed(previous: Option<&GrowRecord>, rec: &GrowRecord) -> bool {
    previous.is_some_and(|p| {
        p.action == rec.action
            && p.device_bytes == rec.device_bytes
            && rec.ts_ms.saturating_sub(p.ts_ms) < RETRY_AFTER_MS
    })
}

/// Should the daemon report this result as an incident? Only a result newer than the last one it reported, and not
/// older than shortly before the daemon started (so a restart does not report an old growth again).
pub fn should_report(rec: &GrowRecord, last_reported_ms: u64, daemon_started_ms: u64) -> bool {
    rec.ts_ms > last_reported_ms && rec.ts_ms.saturating_add(120_000) >= daemon_started_ms
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::host::FakeHost;
    use ozbox_core::{Output, RecordingRunner};

    const GIB: u64 = 1 << 30;

    fn host(dev_gib: u64, fs_gib_tenths: u64, fstype: &str) -> FakeHost {
        let h = FakeHost::default();
        h.set(
            "/proc/mounts",
            &format!("/dev/nvme1n1 /work {fstype} rw,relatime 0 0\n"),
        );
        h.set(
            "/sys/class/block/nvme1n1/size",
            &format!("{}\n", dev_gib * GIB / SECTOR_BYTES),
        );
        h.set_disk(fs_gib_tenths * GIB / 10, GIB);
        h
    }

    #[test]
    fn parses_sysfs_sizes_and_device_paths() {
        assert_eq!(parse_block_size("41943040\n"), Some(20 * GIB));
        assert_eq!(parse_block_size("nope"), None);
        assert_eq!(
            size_path("/dev/nvme1n1").as_deref(),
            Some("/sys/class/block/nvme1n1/size")
        );
        assert_eq!(size_path("/dev/mapper/vg-lv"), None);
        assert_eq!(size_path("/dev/../etc/passwd"), None);
        assert_eq!(size_path("tmpfs"), None);
        assert_eq!(
            parse_mount_entry("a /x ext4 rw 0 0\n/dev/b /work xfs rw 0 0\n", "/work"),
            Some(("/dev/b".into(), "xfs".into()))
        );
    }

    #[test]
    fn a_freshly_formatted_disk_counts_as_filling_it() {
        // 20 GiB disk, 19.0 GiB of data area (journal and inode tables take the rest)
        let o = observe(&host(20, 190, "ext4"), Path::new("/work")).unwrap();
        assert!(fills_disk(&o));
        assert_eq!(decide(&o), Decision::InSync);
    }

    #[test]
    fn a_grown_disk_is_not_filled_until_the_filesystem_grows() {
        let o = observe(&host(30, 190, "ext4"), Path::new("/work")).unwrap();
        assert!(!fills_disk(&o));
        assert_eq!(decide(&o), Decision::Grow(Tool::Resize2fs));
        let x = observe(&host(30, 190, "xfs"), Path::new("/work")).unwrap();
        assert_eq!(decide(&x), Decision::Grow(Tool::XfsGrowfs));
        let b = observe(&host(30, 190, "btrfs"), Path::new("/work")).unwrap();
        assert!(matches!(decide(&b), Decision::Unsupported(_)));
    }

    #[test]
    fn small_differences_are_metadata_not_a_pending_grow() {
        assert!(slack_bytes(GIB) >= 128 << 20);
        assert_eq!(slack_bytes(100 * GIB), 100 * GIB / 16);
    }

    #[test]
    fn commands_are_argv_arrays() {
        let o = observe(&host(30, 190, "ext4"), Path::new("/work")).unwrap();
        let c = grow_command(Tool::Resize2fs, &o, Path::new("/work"));
        assert_eq!(
            (c.program.as_str(), c.args.as_slice()),
            ("resize2fs", ["/dev/nvme1n1".to_string()].as_slice())
        );
        let c = grow_command(Tool::XfsGrowfs, &o, Path::new("/work"));
        assert_eq!(
            (c.program.as_str(), c.args.as_slice()),
            ("xfs_growfs", ["/work".to_string()].as_slice())
        );
    }

    #[test]
    fn grows_once_and_reports_it() {
        let h = host(30, 190, "ext4");
        let r = RecordingRunner::new();
        let rec = run_once(&h, &r, Path::new("/work"), 1000, None).unwrap();
        assert_eq!(rec.action, Action::Grown);
        assert_eq!(rec.device_bytes, 30 * GIB);
        assert_eq!(rec.tool.as_deref(), Some("resize2fs"));
        assert!(rec.detail.contains("19.0 GiB") && rec.detail.contains("30.0 GiB"));
        assert_eq!(r.calls().len(), 1);
        assert_eq!(r.calls()[0].program, "resize2fs");
    }

    #[test]
    fn in_sync_does_nothing() {
        let h = host(20, 190, "ext4");
        let r = RecordingRunner::new();
        assert!(run_once(&h, &r, Path::new("/work"), 1, None).is_none());
        assert!(r.calls().is_empty());
    }

    #[test]
    fn a_failure_is_recorded_and_not_retried_every_minute() {
        let h = host(30, 190, "ext4");
        let r = RecordingRunner::new();
        r.reply(Output {
            status: Some(1),
            stdout: String::new(),
            stderr: "resize2fs: Permission denied".into(),
        });
        let rec = run_once(&h, &r, Path::new("/work"), 1000, None).unwrap();
        assert_eq!(rec.action, Action::Failed);
        assert!(rec.detail.contains("Permission denied"));
        // a minute later, same disk size: left alone
        assert!(run_once(&h, &r, Path::new("/work"), 61_000, Some(&rec)).is_none());
        assert_eq!(r.calls().len(), 1);
        // an hour later: tried again
        assert!(run_once(
            &h,
            &r,
            Path::new("/work"),
            1000 + RETRY_AFTER_MS,
            Some(&rec)
        )
        .is_some());
        assert_eq!(r.calls().len(), 2);
    }

    #[test]
    fn a_disk_that_cannot_be_read_is_left_to_the_self_test() {
        let h = FakeHost::default();
        let r = RecordingRunner::new();
        assert!(run_once(&h, &r, Path::new("/work"), 1, None).is_none());
        assert!(r.calls().is_empty());
    }

    #[test]
    fn reporting_skips_old_and_already_reported_results() {
        let rec = GrowRecord {
            ts_ms: 500_000,
            action: Action::Grown,
            device_bytes: 0,
            fs_bytes_before: 0,
            fs_bytes_after: None,
            tool: None,
            detail: String::new(),
        };
        assert!(should_report(&rec, 0, 400_000));
        assert!(!should_report(&rec, 500_000, 400_000));
        // the daemon started long after this was written: not new
        assert!(!should_report(&rec, 0, 900_000));
        let json = serde_json::to_string(&rec).unwrap();
        assert!(json.contains("\"action\":\"grown\""));
    }
}
