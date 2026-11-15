//! Access to the host's files and disk space behind a trait, so everything above it is testable on any OS.

use std::io;
use std::path::Path;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DiskSpace {
    pub total_bytes: u64,
    pub free_bytes: u64,
}

pub trait HostSource: Send + Sync {
    /// Read a whole (small, procfs/cgroupfs/sysfs) file as text.
    fn read(&self, path: &str) -> io::Result<String>;
    /// Total and available bytes of the filesystem holding `path`.
    fn disk_space(&self, path: &Path) -> io::Result<DiskSpace>;
}

/// The real host. `disk_space` needs Linux; elsewhere it reports `Unsupported`.
#[derive(Debug, Default, Clone, Copy)]
pub struct FsHost;

impl HostSource for FsHost {
    fn read(&self, path: &str) -> io::Result<String> {
        std::fs::read_to_string(path)
    }

    #[cfg(target_os = "linux")]
    fn disk_space(&self, path: &Path) -> io::Result<DiskSpace> {
        let s = rustix::fs::statvfs(path)?;
        let frsize = s.f_frsize;
        Ok(DiskSpace {
            total_bytes: s.f_blocks.saturating_mul(frsize),
            free_bytes: s.f_bavail.saturating_mul(frsize),
        })
    }

    #[cfg(not(target_os = "linux"))]
    fn disk_space(&self, _path: &Path) -> io::Result<DiskSpace> {
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "disk space needs Linux",
        ))
    }
}

/// A scripted host for tests: files by path, a fixed disk.
#[derive(Debug, Default)]
pub struct FakeHost {
    pub files: std::sync::Mutex<std::collections::BTreeMap<String, String>>,
    pub disk: std::sync::Mutex<Option<DiskSpace>>,
}

impl FakeHost {
    pub fn set(&self, path: &str, text: &str) {
        if let Ok(mut f) = self.files.lock() {
            f.insert(path.to_string(), text.to_string());
        }
    }
    pub fn set_disk(&self, total: u64, free: u64) {
        if let Ok(mut d) = self.disk.lock() {
            *d = Some(DiskSpace {
                total_bytes: total,
                free_bytes: free,
            });
        }
    }
}

impl HostSource for FakeHost {
    fn read(&self, path: &str) -> io::Result<String> {
        self.files
            .lock()
            .ok()
            .and_then(|f| f.get(path).cloned())
            .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "no such fake file"))
    }
    fn disk_space(&self, _path: &Path) -> io::Result<DiskSpace> {
        self.disk
            .lock()
            .ok()
            .and_then(|d| *d)
            .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "no fake disk"))
    }
}
