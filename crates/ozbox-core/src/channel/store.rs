//! The file that holds an end's state. Written atomically (a temp file of the writer's own, fsync, rename, directory fsync)
//! under an advisory lock, so a crash leaves the old state or the new one and never half of either. Nothing is acknowledged to a
//! peer before the write that recorded it returned: the journal comes before the acknowledgement.
//!
//! Generic over the state, so the hub's [`crate::hub`] state and the mesh's task state persist through one implementation.

use std::fs::{self, File};
use std::io::Write;
use std::marker::PhantomData;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use serde::de::DeserializeOwned;
use serde::Serialize;

use crate::filelock::FileLock;

pub struct Store<T> {
    dir: PathBuf,
    writes: AtomicU64,
    _t: PhantomData<fn() -> T>,
}

#[derive(Debug)]
pub enum StoreError {
    Io(String),
    Corrupt,
    NotInitialised,
    Locked,
}

impl std::fmt::Display for StoreError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            StoreError::Io(e) => write!(f, "the channel store could not be read or written: {e}"),
            StoreError::Corrupt => f.write_str("the channel store is damaged; restore it from a backup and acknowledge the restore"),
            StoreError::NotInitialised => f.write_str("this end has no channel identity yet"),
            StoreError::Locked => f.write_str("another process is using the store; try again in a moment"),
        }
    }
}

fn io(e: std::io::Error) -> StoreError {
    StoreError::Io(e.kind().to_string())
}

impl<T: Serialize + DeserializeOwned> Store<T> {
    pub fn new(dir: impl Into<PathBuf>) -> Store<T> {
        Store {
            dir: dir.into(),
            writes: AtomicU64::new(0),
            _t: PhantomData,
        }
    }

    pub fn dir(&self) -> &Path {
        &self.dir
    }

    fn state_path(&self) -> PathBuf {
        self.dir.join("state.json")
    }

    pub fn exists(&self) -> bool {
        self.state_path().exists()
    }

    fn lock(&self) -> Result<FileLock, StoreError> {
        fs::create_dir_all(&self.dir).map_err(io)?;
        FileLock::acquire(&self.dir.join("lock"), Duration::from_secs(10)).map_err(|e| {
            if e.kind() == std::io::ErrorKind::TimedOut {
                StoreError::Locked
            } else {
                io(e)
            }
        })
    }

    fn read_unlocked(&self) -> Result<T, StoreError> {
        let bytes = match fs::read(self.state_path()) {
            Ok(b) => b,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                return Err(StoreError::NotInitialised)
            }
            Err(e) => return Err(io(e)),
        };
        serde_json::from_slice(&bytes).map_err(|_| StoreError::Corrupt)
    }

    fn write_unlocked(&self, st: &T) -> Result<(), StoreError> {
        let bytes = serde_json::to_vec(st).map_err(|_| StoreError::Corrupt)?;
        // every writer has its own temp file: two writers can never truncate each other's
        let mut salt = [0u8; 6];
        let _ = ring::rand::SecureRandom::fill(&ring::rand::SystemRandom::new(), &mut salt);
        let tmp = self.dir.join(format!(
            "state.json.{}.{}.tmp",
            std::process::id(),
            super::wire::hex(&salt)
        ));
        let result = (|| {
            let mut f = File::create(&tmp).map_err(io)?;
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                let _ = f.set_permissions(fs::Permissions::from_mode(0o600));
            }
            f.write_all(&bytes).map_err(io)?;
            f.sync_all().map_err(io)?;
            fs::rename(&tmp, self.state_path()).map_err(io)
        })();
        if result.is_err() {
            let _ = fs::remove_file(&tmp);
            return result;
        }
        if let Ok(d) = File::open(&self.dir) {
            let _ = d.sync_all();
        }
        self.writes.fetch_add(1, Ordering::Relaxed);
        Ok(())
    }

    /// How many times this handle has written the state (for tests and diagnostics: a round should cost one write, or none).
    pub fn writes(&self) -> u64 {
        self.writes.load(Ordering::Relaxed)
    }

    /// Create the state. Refuses to overwrite one.
    pub fn create(&self, st: &T) -> Result<(), StoreError> {
        #[cfg(unix)]
        {
            use std::os::unix::fs::DirBuilderExt;
            let _ = fs::DirBuilder::new()
                .recursive(true)
                .mode(0o700)
                .create(&self.dir);
        }
        let _l = self.lock()?;
        if self.exists() {
            return Err(StoreError::Io("already exists".into()));
        }
        self.write_unlocked(st)
    }

    /// Read the state without the lock (a snapshot; the file is replaced atomically).
    pub fn read(&self) -> Result<T, StoreError> {
        self.read_unlocked()
    }

    /// Change the state under the lock and write it before returning, once. The closure may do I/O (it holds the lock for as long
    /// as it runs, so keep it short) but must send nothing to a peer.
    pub fn update<R>(&self, f: impl FnOnce(&mut T) -> R) -> Result<R, StoreError> {
        let _l = self.lock()?;
        let mut st = self.read_unlocked()?;
        let out = f(&mut st);
        self.write_unlocked(&st)?;
        Ok(out)
    }

    /// [`Store::update`] that writes **only when the closure says something changed** (its second value). A round in which nothing
    /// happened costs no write and no fsync.
    pub fn update_if<R>(&self, f: impl FnOnce(&mut T) -> (R, bool)) -> Result<R, StoreError> {
        let _l = self.lock()?;
        let mut st = self.read_unlocked()?;
        let (out, changed) = f(&mut st);
        if changed {
            self.write_unlocked(&st)?;
        }
        Ok(out)
    }

    /// Read the state while holding the lock, and write nothing. For work that must not race a writer (draining the audit).
    pub fn with_lock<R>(&self, f: impl FnOnce(&T) -> R) -> Result<R, StoreError> {
        let _l = self.lock()?;
        let st = self.read_unlocked()?;
        Ok(f(&st))
    }
}
