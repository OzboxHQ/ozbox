//! An upload is judged on what is OPEN, not on a path that can change after it was looked at.
//!
//! The worker can read the browser's private folder (profiles with their cookies) and the agent cannot, so the worker must
//! never be the agent's way to it. `policy::upload_allowed` judges a path; between that judgement and Chromium opening the
//! file the agent can swap a folder it owns for a link. So the file is opened here, once, with no link followed in its last
//! part; the path of what is actually open is read back from the kernel and judged again; and the bytes are copied into a
//! file only the worker owns, whose path is what Chromium is given. Nothing the agent does to the original afterwards changes
//! what is uploaded, and the copy is what the person's approval was about.
use std::fs::File;
use std::io::{Read, Write};
use std::path::{Path, PathBuf};

/// What an upload may be read from: the same arguments as [`crate::policy::upload_allowed`].
pub struct Where<'a> {
    pub work: &'a Path,
    pub dirs: &'a [String],
    pub session_downloads: &'a Path,
    pub private_root: Option<&'a Path>,
}

fn open_no_follow(p: &Path) -> std::io::Result<File> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        std::fs::OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NOFOLLOW)
            .open(p)
    }
    #[cfg(not(unix))]
    {
        File::open(p)
    }
}

/// Where the open file really is now. On Linux the kernel says so (`/proc/self/fd`); elsewhere this falls back to resolving
/// the path again, which is the best a platform without that can do (the product runs on Linux).
fn path_of_open(f: &File, again: &Path) -> std::io::Result<PathBuf> {
    #[cfg(target_os = "linux")]
    {
        use std::os::fd::AsRawFd;
        let _ = again;
        std::fs::read_link(format!("/proc/self/fd/{}", f.as_raw_fd()))
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = f;
        std::fs::canonicalize(again)
    }
}

/// Copy the file at `path` into `stage_dir` after judging it, and return the copy's path and the name to show. `between` runs
/// after the first judgement and before the file is opened (a test swaps a folder there; real callers pass nothing).
pub fn stage_with(
    path: &Path,
    at: &Where<'_>,
    stage_dir: &Path,
    n: u32,
    between: impl FnOnce(),
) -> Result<(PathBuf, String), String> {
    let judge = |p: &Path| {
        crate::policy::upload_allowed(p, at.work, at.dirs, at.session_downloads, at.private_root)
    };
    let (real, shown) = judge(path)?;
    between();
    let mut src = open_no_follow(&real).map_err(|_| {
        "that file could not be opened (it changed while it was being read)".to_string()
    })?;
    let opened =
        path_of_open(&src, &real).map_err(|_| "that file could not be checked".to_string())?;
    // judged again, on what is open: a folder swapped for a link in between puts the open file somewhere else
    let (again, _) = judge(&opened)?;
    if again != opened {
        return Err("that file changed while it was being read".to_string());
    }
    let meta = src
        .metadata()
        .map_err(|_| "that file could not be read".to_string())?;
    if !meta.is_file() {
        return Err("only a file can be uploaded".to_string());
    }
    std::fs::create_dir_all(stage_dir).map_err(|_| "the copy could not be made".to_string())?;
    let name = opened
        .file_name()
        .map(|s| s.to_string_lossy().into_owned())
        .filter(|s| !s.is_empty() && !s.starts_with('.'))
        .unwrap_or_else(|| "file".to_string());
    // one folder per upload, so the page sees the original's name and two uploads never share a file
    let dir = stage_dir.join(format!("{n}"));
    std::fs::create_dir_all(&dir).map_err(|_| "the copy could not be made".to_string())?;
    let to = dir.join(&name);
    let mut out = {
        use std::os::unix::fs::OpenOptionsExt;
        // `create_new` is O_EXCL: it never writes through a link that is already there
        std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&to)
            .map_err(|_| "the copy could not be made".to_string())?
    };
    let mut buf = vec![0u8; 64 * 1024];
    loop {
        let k = src
            .read(&mut buf)
            .map_err(|_| "that file could not be read".to_string())?;
        if k == 0 {
            break;
        }
        out.write_all(&buf[..k])
            .map_err(|_| "the copy could not be made".to_string())?;
    }
    Ok((to, shown))
}

pub fn stage(
    path: &Path,
    at: &Where<'_>,
    stage_dir: &Path,
    n: u32,
) -> Result<(PathBuf, String), String> {
    stage_with(path, at, stage_dir, n, || {})
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;

    struct Fx {
        _d: tempfile::TempDir,
        work: PathBuf,
        private: PathBuf,
        dl: PathBuf,
        dirs: Vec<String>,
        stage: PathBuf,
    }

    fn fx() -> Fx {
        let d = tempfile::tempdir().unwrap();
        let work = std::fs::canonicalize(d.path()).unwrap();
        let private = work.join("ozbox-browser/private");
        std::fs::create_dir_all(private.join("profiles/p/Default")).unwrap();
        std::fs::write(private.join("profiles/p/Default/Cookies"), "COOKIE-JAR").unwrap();
        std::fs::create_dir_all(work.join("uploads/x")).unwrap();
        std::fs::write(work.join("uploads/x/Cookies"), "harmless").unwrap();
        let dl = work.join("dl");
        std::fs::create_dir_all(&dl).unwrap();
        Fx {
            stage: work.join("stage"),
            work,
            private,
            dl,
            dirs: vec!["uploads".to_string()],
            _d: d,
        }
    }

    impl Fx {
        fn at(&self) -> Where<'_> {
            Where {
                work: &self.work,
                dirs: &self.dirs,
                session_downloads: &self.dl,
                private_root: Some(&self.private),
            }
        }
    }

    #[test]
    fn a_file_is_copied_into_the_stage_and_the_copy_is_what_is_handed_over() {
        let f = fx();
        let (to, shown) = stage(&f.work.join("uploads/x/Cookies"), &f.at(), &f.stage, 1).unwrap();
        assert!(to.starts_with(&f.stage) && !to.starts_with(f.work.join("uploads")));
        assert_eq!(std::fs::read_to_string(&to).unwrap(), "harmless");
        assert!(shown.contains("Cookies"));
        // the original can change afterwards: the copy does not
        std::fs::write(f.work.join("uploads/x/Cookies"), "changed").unwrap();
        assert_eq!(std::fs::read_to_string(&to).unwrap(), "harmless");
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(
            std::fs::metadata(&to).unwrap().permissions().mode() & 0o777,
            0o600
        );
    }

    /// The finding (M2): the folder is a real folder when the path is judged, and a link into the private folder when
    /// Chromium would have opened it.
    #[test]
    fn a_folder_swapped_for_a_link_after_the_check_does_not_reach_the_private_folder() {
        let f = fx();
        let (work, private) = (f.work.clone(), f.private.clone());
        let r = stage_with(
            &work.join("uploads/x/Cookies"),
            &f.at(),
            &f.stage,
            1,
            || {
                std::fs::remove_dir_all(work.join("uploads/x")).unwrap();
                std::os::unix::fs::symlink(
                    private.join("profiles/p/Default"),
                    work.join("uploads/x"),
                )
                .unwrap();
            },
        );
        assert!(r.is_err(), "{r:?}");
        assert!(
            !f.stage.exists() || std::fs::read_dir(&f.stage).unwrap().next().is_none(),
            "nothing was copied"
        );
    }

    #[test]
    fn a_last_part_swapped_for_a_link_is_not_followed() {
        let f = fx();
        let (work, private) = (f.work.clone(), f.private.clone());
        let r = stage_with(
            &work.join("uploads/x/Cookies"),
            &f.at(),
            &f.stage,
            1,
            || {
                std::fs::remove_file(work.join("uploads/x/Cookies")).unwrap();
                std::os::unix::fs::symlink(
                    private.join("profiles/p/Default/Cookies"),
                    work.join("uploads/x/Cookies"),
                )
                .unwrap();
            },
        );
        assert!(r.is_err(), "{r:?}");
    }
}
