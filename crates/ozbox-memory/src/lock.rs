//! A lock file created exclusively, removed on drop. A lock older than a minute belongs to a crashed writer and is broken.

use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

const STALE: Duration = Duration::from_secs(60);
const WAIT: Duration = Duration::from_secs(10);

pub struct FileLock(PathBuf);

impl FileLock {
    pub fn take(path: &Path) -> io::Result<FileLock> {
        if let Some(dir) = path.parent() {
            fs::create_dir_all(dir)?;
        }
        let start = Instant::now();
        loop {
            match fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(path)
            {
                Ok(_) => return Ok(FileLock(path.to_path_buf())),
                Err(e) if e.kind() == io::ErrorKind::AlreadyExists => {
                    let stale = fs::metadata(path)
                        .and_then(|m| m.modified())
                        .ok()
                        .and_then(|t| t.elapsed().ok())
                        .is_some_and(|age| age > STALE);
                    if stale {
                        let _ = fs::remove_file(path);
                        continue;
                    }
                    if start.elapsed() > WAIT {
                        return Err(io::Error::new(io::ErrorKind::TimedOut, "store is busy"));
                    }
                    std::thread::sleep(Duration::from_millis(5));
                }
                Err(e) => return Err(e),
            }
        }
    }
}

impl Drop for FileLock {
    fn drop(&mut self) {
        let _ = fs::remove_file(&self.0);
    }
}
