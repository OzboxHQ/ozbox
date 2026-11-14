//! One advisory lock for every store that is read, changed and written back: held on an open file descriptor (`flock`), so a
//! process that dies releases it, two threads of one process exclude each other, and nobody ever judges a lock by its age.
//!
//! This replaces the earlier `create_new` file that was treated as stale after a minute. That scheme let two processes both
//! take the lock (each saw the stale file, each removed it, each created its own) and let a laptop that slept mid-update lose
//! its lock to the next process. The lock file is **never removed**: removing it is exactly what lets a second holder in.
//!
//! Lock order, everywhere: the state store's lock first, then the audit log's. Nothing takes them the other way round.

use std::fs::{File, OpenOptions};
use std::io;
use std::path::Path;
use std::time::{Duration, Instant};

/// A held lock. Dropping it (or the process ending) releases it.
#[derive(Debug)]
pub struct FileLock {
    _file: File,
}

impl FileLock {
    /// Take the lock on `path` (made if absent, mode 0600), waiting up to `wait`.
    // `File::try_lock` is stable from Rust 1.89, and the toolchain is `stable`; the declared MSRV is older than that.
    #[allow(clippy::incompatible_msrv)]
    pub fn acquire(path: &Path, wait: Duration) -> io::Result<FileLock> {
        let mut opts = OpenOptions::new();
        opts.read(true).write(true).create(true).truncate(false);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            opts.mode(0o600);
        }
        let file = opts.open(path)?;
        let start = Instant::now();
        loop {
            match file.try_lock() {
                Ok(()) => return Ok(FileLock { _file: file }),
                Err(std::fs::TryLockError::WouldBlock) => {
                    if start.elapsed() >= wait {
                        return Err(io::Error::new(io::ErrorKind::TimedOut, "the lock is busy"));
                    }
                    std::thread::sleep(Duration::from_millis(10));
                }
                Err(std::fs::TryLockError::Error(e)) => return Err(e),
            }
        }
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn a_held_lock_excludes_a_second_taker_and_is_released_on_drop() {
        let d = tempfile::tempdir().unwrap();
        let p = d.path().join("lock");
        let a = FileLock::acquire(&p, Duration::from_millis(50)).unwrap();
        let second = FileLock::acquire(&p, Duration::from_millis(60));
        assert!(second.is_err(), "a second holder must not get in");
        assert!(p.exists(), "the lock file is never removed");
        drop(a);
        assert!(FileLock::acquire(&p, Duration::from_millis(50)).is_ok());
    }

    #[test]
    fn an_old_lock_file_is_not_stolen() {
        let d = tempfile::tempdir().unwrap();
        let p = d.path().join("lock");
        let _held = FileLock::acquire(&p, Duration::from_millis(50)).unwrap();
        // age does not matter: only the descriptor does
        let old = std::time::SystemTime::now() - Duration::from_secs(3600);
        if let Ok(f) = OpenOptions::new().write(true).open(&p) {
            let _ = f.set_modified(old);
        }
        assert!(FileLock::acquire(&p, Duration::from_millis(60)).is_err());
    }
}
