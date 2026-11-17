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
    /// Whether a folder (or a file) is there. Through the host, so a check that asks "is this service on this machine at all?"
    /// answers from a fixture in a test, never from the machine the test happens to run on.
    fn exists(&self, path: &Path) -> bool;
}

/// The real host. `disk_space` needs Linux; elsewhere it reports `Unsupported`.
#[derive(Debug, Default, Clone, Copy)]
pub struct FsHost;

impl HostSource for FsHost {
    fn read(&self, path: &str) -> io::Result<String> {
        std::fs::read_to_string(path)
    }

    fn exists(&self, path: &Path) -> bool {
        path.exists()
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
    /// Folders that are there (a file's folders are there too).
    pub dirs: std::sync::Mutex<std::collections::BTreeSet<String>>,
}

impl FakeHost {
    pub fn set(&self, path: &str, text: &str) {
        if let Ok(mut f) = self.files.lock() {
            f.insert(path.to_string(), text.to_string());
        }
    }
    /// A folder that is there, with nothing in it the fake was told about.
    pub fn set_dir(&self, path: &str) {
        if let Ok(mut d) = self.dirs.lock() {
            d.insert(path.trim_end_matches('/').to_string());
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
    fn exists(&self, path: &Path) -> bool {
        let p = path.to_string_lossy();
        let p = p.trim_end_matches('/');
        let under = |f: &String| f == p || f.strip_prefix(p).is_some_and(|r| r.starts_with('/'));
        self.files.lock().is_ok_and(|f| f.keys().any(under))
            || self.dirs.lock().is_ok_and(|d| d.iter().any(under))
    }
    fn disk_space(&self, _path: &Path) -> io::Result<DiskSpace> {
        self.disk
            .lock()
            .ok()
            .and_then(|d| *d)
            .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "no fake disk"))
    }
}
