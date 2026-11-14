//! The file that holds an endpoint's state. Written atomically (temp file, fsync, rename, directory fsync) under a lock, so a
//! crash leaves the old state or the new one and never half of either. Nothing is acknowledged to a peer before the write that
//! recorded it returned (ADR 0044 section 2.3: the journal comes before the acknowledgement).

use std::fs::{self, File, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use super::state::State;

pub struct Store {
    dir: PathBuf,
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
            StoreError::Io(e) => write!(f, "the task store could not be read or written: {e}"),
            StoreError::Corrupt => f.write_str("the task store is damaged; restore it from a backup and run `ozbox tasks restored`"),
            StoreError::NotInitialised => f.write_str("this computer has no task identity yet; run `ozbox tasks init --name <name>`"),
            StoreError::Locked => f.write_str("another `ozbox tasks` command is using the store; try again in a moment"),
        }
    }
}

fn io(e: std::io::Error) -> StoreError {
    StoreError::Io(e.kind().to_string())
}

struct Lock(PathBuf);

impl Drop for Lock {
    fn drop(&mut self) {
        let _ = fs::remove_file(&self.0);
    }
}

impl Store {
    pub fn new(dir: impl Into<PathBuf>) -> Store {
        Store { dir: dir.into() }
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

    fn lock(&self) -> Result<Lock, StoreError> {
        fs::create_dir_all(&self.dir).map_err(io)?;
        let path = self.dir.join("lock");
        let start = Instant::now();
        loop {
            match OpenOptions::new().write(true).create_new(true).open(&path) {
                Ok(_) => return Ok(Lock(path)),
                Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {
                    // a lock older than a minute belongs to a process that died
                    let stale = fs::metadata(&path)
                        .and_then(|m| m.modified())
                        .ok()
                        .and_then(|t| t.elapsed().ok())
                        .is_some_and(|d| d > Duration::from_secs(60));
                    if stale {
                        let _ = fs::remove_file(&path);
                        continue;
                    }
                    if start.elapsed() > Duration::from_secs(10) {
                        return Err(StoreError::Locked);
                    }
                    std::thread::sleep(Duration::from_millis(25));
                }
                Err(e) => return Err(io(e)),
            }
        }
    }

    fn read_unlocked(&self) -> Result<State, StoreError> {
        let bytes = match fs::read(self.state_path()) {
            Ok(b) => b,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                return Err(StoreError::NotInitialised)
            }
            Err(e) => return Err(io(e)),
        };
        serde_json::from_slice(&bytes).map_err(|_| StoreError::Corrupt)
    }

    fn write_unlocked(&self, st: &State) -> Result<(), StoreError> {
        let bytes = serde_json::to_vec(st).map_err(|_| StoreError::Corrupt)?;
        let tmp = self.dir.join("state.json.tmp");
        let mut f = File::create(&tmp).map_err(io)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = f.set_permissions(fs::Permissions::from_mode(0o600));
        }
        f.write_all(&bytes).map_err(io)?;
        f.sync_all().map_err(io)?;
        fs::rename(&tmp, self.state_path()).map_err(io)?;
        if let Ok(d) = File::open(&self.dir) {
            let _ = d.sync_all();
        }
        Ok(())
    }

    /// Create the state. Refuses to overwrite one.
    pub fn create(&self, st: &State) -> Result<(), StoreError> {
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
    pub fn read(&self) -> Result<State, StoreError> {
        self.read_unlocked()
    }

    /// Change the state under the lock and write it before returning. The closure does no I/O and sends nothing.
    pub fn update<T>(&self, f: impl FnOnce(&mut State) -> T) -> Result<T, StoreError> {
        let _l = self.lock()?;
        let mut st = self.read_unlocked()?;
        let out = f(&mut st);
        self.write_unlocked(&st)?;
        Ok(out)
    }
}
