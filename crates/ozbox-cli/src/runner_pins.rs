//! Files a declaration pins by content (`pin`), checked at every run, and run from a copy that cannot change.
//!
//! The folder a command runs in is writable by the box user, and so by an agent. Checking a file's hash and then letting the
//! command open it would leave a gap: an agent that swaps the file after the check runs its own code with whatever the
//! command receives. So the check and the run use the SAME bytes: the launcher reads the file once, hashes what it read, writes
//! those bytes to a root-owned, content-named copy (`blobs/<sha256>`, read-only), and the unit is started with that copy bound
//! read-only over the file's path (`BindReadOnlyPaths=<blob>:<file>`). What the command opens is the approved content,
//! whatever the folder holds a moment later.
//!
//! **The cache.** Hashing a file every run is cheap for a script and wasteful for a bundle, so the launcher remembers, per
//! project, `(device, inode, size, mtime, ctime)` of the last file it verified and the digest it found. A file whose five
//! numbers are unchanged is not read again. `ctime` is what makes this safe: any write, rename or `chmod` moves it, and only
//! root can set it back, so an owner-set `mtime` cannot hide a change. The cache is a time saver only: the run always uses the
//! content-named copy, so a stale cache entry could at worst have a run use an approved copy of a file the folder no longer
//! matches, never an unapproved one. The cache and the copies live in a root-owned folder the box user cannot write.
//!
//! **Folders.** `pin_tree` pins a folder (a package under `node_modules`) the same way: the launcher walks it once, digests the
//! bytes it reads while writing a root-owned copy of those same bytes (`blobs`-like, named `trees/<sha256>`), and binds the copy
//! read-only over the folder. Its cache is a fingerprint of `stat` for every entry (device, inode, size, mtime, ctime; folders
//! included, so an added or removed file shows), so an unchanged tree costs a walk and no reads.
//!
//! **What a pin covers, and what it cannot.** A pin covers the bytes of that file or folder. For a command that receives a
//! secret and runs a script, the launcher ALSO reads the script (the verified bytes) and refuses to start it unless everything it
//! loads is pinned too (`runner_imports`): a STATIC check, which refuses a computed `import(x)` rather than guess. What is not
//! covered: a program that reads a path from data and runs it, native add-ons, a `package.json` script's children and `.npmrc`
//! (so a pinned command that receives a secret is `node FILE`, never `npm run`), and **the swap of a folder ABOVE a pinned path
//! for a link in the milliseconds between the mount being set up and the program opening the file**: the launcher refuses a link
//! it can see, opens every pinned file by a descriptor walk that follows no link, and locks a project out after repeated
//! mismatches, but systemd resolves the working directory and the mount destinations on its own, afterwards. That window is
//! reduced, not closed, and is to be proven on a real box.

use std::collections::BTreeMap;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::runner_imports::{self, Source};
use crate::runner_setup::{tree_digest, tree_fingerprint, tree_scan};
use crate::workload_policy::{Pin, TreePin};

/// A pinned file is read whole, so it is bounded.
pub const MAX_PIN_BYTES: u64 = 4 << 20;
/// After this many changed pins inside [`FAIL_WINDOW_MS`], a project's pinned commands are refused for [`LOCK_MS`]: a change that is
/// not an accident is somebody searching for a window.
pub const MAX_MISMATCHES: usize = 5;
pub const FAIL_WINDOW_MS: u64 = 60_000;
pub const LOCK_MS: u64 = 300_000;

pub fn sha256_hex(bytes: &[u8]) -> String {
    ring::digest::digest(&ring::digest::SHA256, bytes)
        .as_ref()
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct Seen {
    dev: u64,
    ino: u64,
    size: u64,
    mtime_ns: i128,
    ctime_ns: i128,
    sha256: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct SeenTree {
    fingerprint: String,
    sha256: String,
}

#[derive(Debug, Default, Serialize, Deserialize)]
struct Cache {
    #[serde(default)]
    files: BTreeMap<String, Seen>,
    #[serde(default)]
    trees: BTreeMap<String, SeenTree>,
}

#[derive(Debug, Default, Serialize, Deserialize)]
struct Fails {
    #[serde(default)]
    at_ms: Vec<u64>,
}

/// One file or folder to bind: the verified copy, and the path it covers inside the unit.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Mount {
    pub blob: PathBuf,
    pub dest: PathBuf,
}

impl Mount {
    /// The `BindReadOnlyPaths=` property.
    pub fn property(&self) -> String {
        format!(
            "BindReadOnlyPaths={}:{}",
            self.blob.display(),
            self.dest.display()
        )
    }
}

/// What the check found, for the one call that can say which file and why, and how much was read.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct Checked {
    pub mounts: Vec<Mount>,
    /// Files and folders whose bytes were read and hashed this time (the rest were answered from the cache).
    pub hashed: usize,
    /// Pinned files: path relative to the project folder, and the verified copy.
    pub files: BTreeMap<String, PathBuf>,
    /// Pinned folders: path relative to the project folder, and the verified copy.
    pub trees: BTreeMap<String, PathBuf>,
}

pub struct PinStore {
    pub root: PathBuf,
    /// The clock, in milliseconds (a test sets its own).
    pub now: fn() -> u64,
}

fn ns(secs: i64, nanos: i64) -> i128 {
    i128::from(secs) * 1_000_000_000 + i128::from(nanos)
}

fn stat_key(m: &std::fs::Metadata) -> (u64, u64, u64, i128, i128) {
    (
        m.dev(),
        m.ino(),
        m.size(),
        ns(m.mtime(), m.mtime_nsec()),
        ns(m.ctime(), m.ctime_nsec()),
    )
}

/// A check refused: the sentence for the person, and whether it is a CHANGE of a pinned thing (counted toward the lockout).
struct Refusal {
    msg: String,
    changed: bool,
}

fn refuse<T>(msg: impl Into<String>) -> Result<T, Refusal> {
    Err(Refusal {
        msg: msg.into(),
        changed: false,
    })
}

fn changed<T>(msg: impl Into<String>) -> Result<T, Refusal> {
    Err(Refusal {
        msg: msg.into(),
        changed: true,
    })
}

impl PinStore {
    pub fn new(root: impl Into<PathBuf>) -> PinStore {
        PinStore {
            root: root.into(),
            now: crate::tokenmac::now_ms,
        }
    }

    fn blob_path(&self, sha: &str) -> PathBuf {
        self.root.join("blobs").join(sha)
    }

    fn tree_path(&self, sha: &str) -> PathBuf {
        self.root.join("trees").join(sha)
    }

    fn cache_path(&self, project: &str) -> PathBuf {
        self.root.join(format!("{project}.cache.json"))
    }

    fn fails_path(&self, project: &str) -> PathBuf {
        self.root.join(format!("{project}.fails.json"))
    }

    fn load_cache(&self, project: &str) -> Cache {
        std::fs::read(self.cache_path(project))
            .ok()
            .and_then(|b| serde_json::from_slice(&b).ok())
            .unwrap_or_default()
    }

    fn save_cache(&self, project: &str, c: &Cache) {
        let tmp = self.root.join(format!("{project}.cache.tmp"));
        let ok = serde_json::to_vec(c)
            .ok()
            .is_some_and(|b| write_private(&tmp, &b, 0o600).is_ok());
        if ok {
            let _ = std::fs::rename(&tmp, self.cache_path(project));
        }
    }

    fn load_fails(&self, project: &str) -> Fails {
        std::fs::read(self.fails_path(project))
            .ok()
            .and_then(|b| serde_json::from_slice(&b).ok())
            .unwrap_or_default()
    }

    /// Refuse while a project is locked out.
    fn locked(&self, project: &str) -> Result<(), Refusal> {
        let now = (self.now)();
        let recent: Vec<u64> = self
            .load_fails(project)
            .at_ms
            .into_iter()
            .filter(|t| now.saturating_sub(*t) < FAIL_WINDOW_MS + LOCK_MS)
            .collect();
        // locked once MAX_MISMATCHES fell inside one window, until LOCK_MS after the last of them
        let mut sorted = recent.clone();
        sorted.sort_unstable();
        for w in sorted.windows(MAX_MISMATCHES) {
            if w[MAX_MISMATCHES - 1] - w[0] < FAIL_WINDOW_MS {
                let until = w[MAX_MISMATCHES - 1] + LOCK_MS;
                if now < until {
                    return refuse(format!(
                        "pinned commands of this project are paused for {} more seconds: its pinned files changed {MAX_MISMATCHES} times in a minute",
                        (until - now).div_ceil(1000)
                    ));
                }
            }
        }
        Ok(())
    }

    fn record_failure(&self, project: &str) {
        let now = (self.now)();
        let mut f = self.load_fails(project);
        f.at_ms
            .retain(|t| now.saturating_sub(*t) < FAIL_WINDOW_MS + LOCK_MS);
        f.at_ms.push(now);
        let tmp = self.root.join(format!("{project}.fails.tmp"));
        if std::fs::create_dir_all(&self.root).is_ok()
            && serde_json::to_vec(&f)
                .ok()
                .is_some_and(|b| write_private(&tmp, &b, 0o600).is_ok())
        {
            let _ = std::fs::rename(&tmp, self.fails_path(project));
        }
    }

    /// Make sure the content-named copy of `bytes` exists, read-only.
    fn put_blob(&self, sha: &str, bytes: &[u8]) -> std::io::Result<PathBuf> {
        let dir = self.root.join("blobs");
        std::fs::create_dir_all(&dir)?;
        let _ = std::fs::set_permissions(&self.root, std::fs::Permissions::from_mode(0o755));
        let _ = std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o755));
        let path = self.blob_path(sha);
        if let Ok(m) = std::fs::symlink_metadata(&path) {
            // a copy written by this program is a regular file of exactly this size; anything else is replaced
            if m.is_file() && m.len() == bytes.len() as u64 {
                return Ok(path);
            }
            let _ = std::fs::remove_file(&path);
        }
        let tmp = dir.join(format!(".{sha}.tmp"));
        write_private(&tmp, bytes, 0o444)?;
        std::fs::rename(&tmp, &path)?;
        Ok(path)
    }

    /// A test's stand-in for "a first run already made the copy": the content-named, read-only blob for `bytes`.
    #[cfg(test)]
    #[allow(clippy::unwrap_used)]
    pub fn seed_blob_for_test(&self, bytes: &[u8]) -> PathBuf {
        self.put_blob(&sha256_hex(bytes), bytes).unwrap()
    }

    /// Check every pinned file and folder of a command against the folder `dir`. `Err` is a sentence for the person that names
    /// the file.
    ///
    /// `private`: the command runs in a PRIVATE VIEW of the project (`runner::sandbox_props`): the live folder is not in its mount
    /// namespace at all, only these verified copies at their paths. Then the live folder is irrelevant once a copy exists, and a
    /// copy already made (named by the digest the owner approved, root-owned) is bound WITHOUT reading or walking the live folder:
    /// no link on the way can be swapped, because nothing on the way is looked at. A copy that does not exist yet is made from one
    /// read of the live folder, checked against the approved digest first.
    pub fn check(
        &self,
        project: &str,
        dir: &Path,
        pins: &[Pin],
        trees: &[TreePin],
        private: bool,
    ) -> Result<Checked, String> {
        if pins.is_empty() && trees.is_empty() {
            return Ok(Checked::default());
        }
        let run = || -> Result<Checked, Refusal> {
            self.locked(project)?;
            if private
                && pins.iter().all(|p| self.blob_path(&p.sha256).is_file())
                && trees.iter().all(|t| self.tree_path(&t.sha256).is_dir())
            {
                let mut out = Checked::default();
                for p in pins {
                    let blob = self.blob_path(&p.sha256);
                    out.files.insert(p.file.clone(), blob.clone());
                    out.mounts.push(Mount {
                        blob,
                        dest: dir.join(&p.file),
                    });
                }
                for t in trees {
                    let copy = self.tree_path(&t.sha256);
                    out.trees.insert(t.path.clone(), copy.clone());
                    out.mounts.push(Mount {
                        blob: copy,
                        dest: dir.join(&t.path),
                    });
                }
                return Ok(out);
            }
            let real_dir = std::fs::canonicalize(dir).map_err(|_| Refusal {
                msg: "the project folder cannot be read".into(),
                changed: false,
            })?;
            // the folder the declaration names is its own real path: no link on the way to it, now or when the unit starts
            if real_dir != dir {
                return changed("the project folder is reached through a link: a pinned command only runs from a real folder");
            }
            let mut out = Checked::default();
            let mut cache = self.load_cache(project);
            let before = (cache.files.clone(), cache.trees.clone());
            let result = self.check_all(&real_dir, pins, trees, &mut cache, &mut out);
            if (cache.files.clone(), cache.trees.clone()) != before {
                self.save_cache(project, &cache);
            }
            result.map(|()| out)
        };
        run().map_err(|r| {
            if r.changed {
                self.record_failure(project);
            }
            r.msg
        })
    }

    fn check_all(
        &self,
        real_dir: &Path,
        pins: &[Pin],
        trees: &[TreePin],
        cache: &mut Cache,
        out: &mut Checked,
    ) -> Result<(), Refusal> {
        for p in pins {
            let joined = real_dir.join(&p.file);
            let real = std::fs::canonicalize(&joined).map_err(|_| Refusal {
                msg: format!("the pinned file {} is missing", p.file),
                changed: false,
            })?;
            // a path that leaves the folder (a symlink, say) is not the file the owner approved
            if !real.starts_with(real_dir) || real != joined {
                return changed(format!(
                    "the pinned file {} is a link or leaves the project folder: it cannot be pinned",
                    p.file
                ));
            }
            let md = std::fs::symlink_metadata(&real).map_err(|_| Refusal {
                msg: format!("the pinned file {} is missing", p.file),
                changed: false,
            })?;
            if !md.is_file() || md.len() > MAX_PIN_BYTES {
                return refuse(format!(
                    "the pinned file {} is not a regular file of at most 4 MiB",
                    p.file
                ));
            }
            let (dev, ino, size, mtime_ns, ctime_ns) = stat_key(&md);
            let hit = cache.files.get(&p.file).filter(|s| {
                s.dev == dev
                    && s.ino == ino
                    && s.size == size
                    && s.mtime_ns == mtime_ns
                    && s.ctime_ns == ctime_ns
                    && s.sha256 == p.sha256
            });
            let blob_ready = self.blob_path(&p.sha256).is_file();
            let blob = if hit.is_some() && blob_ready {
                self.blob_path(&p.sha256)
            } else {
                // read once, by a walk of descriptors that follows no link; the hash and the copy are of these bytes and no others
                let bytes = read_pinned(real_dir, &p.file).map_err(|_| Refusal {
                    msg: format!("the pinned file {} cannot be read", p.file),
                    changed: false,
                })?;
                out.hashed += 1;
                let got = sha256_hex(&bytes);
                if got != p.sha256 {
                    cache.files.remove(&p.file);
                    return changed(format!(
                        "the pinned file {} has changed since it was approved (approved {}, found {}): the command was not started",
                        p.file,
                        &p.sha256[..12],
                        &got[..12]
                    ));
                }
                let blob = self.put_blob(&got, &bytes).map_err(|_| Refusal {
                    msg: "the verified copy of a pinned file could not be written".into(),
                    changed: false,
                })?;
                // the five numbers are taken from the file we just read, after reading it: a write in between shows in ctime
                if let Ok(after) = std::fs::symlink_metadata(&real) {
                    let (d, i, s, mt, ct) = stat_key(&after);
                    if (d, i, s, mt, ct) == (dev, ino, size, mtime_ns, ctime_ns) {
                        cache.files.insert(
                            p.file.clone(),
                            Seen {
                                dev: d,
                                ino: i,
                                size: s,
                                mtime_ns: mt,
                                ctime_ns: ct,
                                sha256: got,
                            },
                        );
                    }
                }
                blob
            };
            out.files.insert(p.file.clone(), blob.clone());
            out.mounts.push(Mount { blob, dest: real });
        }
        for t in trees {
            self.check_tree(real_dir, t, cache, out)?;
        }
        Ok(())
    }

    fn check_tree(
        &self,
        real_dir: &Path,
        t: &TreePin,
        cache: &mut Cache,
        out: &mut Checked,
    ) -> Result<(), Refusal> {
        let joined = real_dir.join(&t.path);
        let missing = || Refusal {
            msg: format!("the pinned folder {} is missing", t.path),
            changed: false,
        };
        let real = std::fs::canonicalize(&joined).map_err(|_| missing())?;
        if !real.starts_with(real_dir) || real != joined {
            return changed(format!(
                "the pinned folder {} is a link or leaves the project folder: it cannot be pinned (pnpm's node_modules/<name> is a link into .pnpm, so a package under pnpm cannot be pinned: pin an npm install, or the real folder under node_modules/.pnpm)",
                t.path
            ));
        }
        if !std::fs::symlink_metadata(&real).is_ok_and(|m| m.is_dir()) {
            return refuse(format!("the pinned folder {} is not a folder", t.path));
        }
        let fp = tree_fingerprint(&real).map_err(|e| Refusal {
            msg: format!("the pinned folder {}: {e}", t.path),
            changed: false,
        })?;
        let copy = self.tree_path(&t.sha256);
        let hit = cache
            .trees
            .get(&t.path)
            .is_some_and(|s| s.fingerprint == fp && s.sha256 == t.sha256)
            && copy.is_dir();
        if !hit {
            // one walk: the digest and the copy are of the bytes read, and the copy is what the unit gets
            let parent = self.root.join("trees");
            std::fs::create_dir_all(&parent).map_err(|_| Refusal {
                msg: "the verified copy of a pinned folder could not be written".into(),
                changed: false,
            })?;
            let _ = std::fs::set_permissions(&self.root, std::fs::Permissions::from_mode(0o755));
            let _ = std::fs::set_permissions(&parent, std::fs::Permissions::from_mode(0o755));
            let stage = parent.join(format!(".stage-{}-{}", std::process::id(), &t.sha256[..16]));
            let _ = std::fs::remove_dir_all(&stage);
            let got = tree_scan(&real, Some(&stage)).map_err(|e| {
                let _ = std::fs::remove_dir_all(&stage);
                Refusal {
                    msg: format!("the pinned folder {}: {e}", t.path),
                    changed: false,
                }
            })?;
            out.hashed += 1;
            if got != t.sha256 {
                let _ = std::fs::remove_dir_all(&stage);
                cache.trees.remove(&t.path);
                return changed(format!(
                    "the pinned folder {} has changed since it was approved (approved {}, found {}): the command was not started",
                    t.path,
                    &t.sha256[..12],
                    &got[..12]
                ));
            }
            if copy.exists() {
                let _ = std::fs::remove_dir_all(&stage);
            } else {
                std::fs::rename(&stage, &copy).map_err(|_| Refusal {
                    msg: "the verified copy of a pinned folder could not be put in place".into(),
                    changed: false,
                })?;
            }
            // the live folder is remembered only if nothing wrote to it while it was read
            if tree_fingerprint(&real).ok().as_deref() == Some(fp.as_str()) {
                cache.trees.insert(
                    t.path.clone(),
                    SeenTree {
                        fingerprint: fp,
                        sha256: t.sha256.clone(),
                    },
                );
            }
        }
        out.trees.insert(t.path.clone(), copy.clone());
        out.mounts.push(Mount {
            blob: copy,
            dest: real,
        });
        Ok(())
    }

    /// A command that receives a secret and runs a script: the script must be pinned, and everything it loads (read from the
    /// VERIFIED bytes) must be pinned too. `argv` is the command's words; `dir` the project folder.
    pub fn check_code(&self, dir: &Path, argv: &[String], checked: &Checked) -> Result<(), String> {
        let prefix = format!("{}/", dir.display().to_string().trim_end_matches('/'));
        let mut entries: Vec<String> = Vec::new();
        // only the word after `node` is the entry; options before it are refused by `secret_rules`, and later words are the script's own
        for w in argv.iter().skip(1).take(1) {
            if w.starts_with('-') || !runner_imports::is_script(w) {
                continue;
            }
            let rel = w
                .strip_prefix(&prefix)
                .unwrap_or(w)
                .trim_start_matches("./")
                .to_string();
            if rel.starts_with('/') || rel.split('/').any(|s| s == "..") {
                return Err(format!("{w} is outside the project folder: a script that receives a secret is a pinned file inside it"));
            }
            entries.push(rel);
        }
        if entries.is_empty() {
            // NV5-H1: no script entry means nothing to check, which must never read as "checked"
            return Err("a command that receives a secret runs `node FILE` with a pinned script: no script was found in its words".to_string());
        }
        let mut src = PinnedSource {
            dir,
            files: &checked.files,
            trees: &checked.trees,
        };
        for e in entries {
            if !checked.files.contains_key(&e) {
                return Err(format!(
                    "{e} runs with a secret but is not pinned: pin it and what it loads (`ozbox env policy pin --entry {e}`)"
                ));
            }
            runner_imports::closure(&e, &mut src).map_err(|why| {
                format!("{e} runs with a secret, but not everything it loads is pinned: {why} (`ozbox env policy pin --entry {e}` lists what to pin)")
            })?;
        }
        Ok(())
    }
}

/// What a script's loading reads, from the VERIFIED copies: a pinned file's blob, a pinned folder's copy.
struct PinnedSource<'a> {
    dir: &'a Path,
    files: &'a BTreeMap<String, PathBuf>,
    trees: &'a BTreeMap<String, PathBuf>,
}

impl PinnedSource<'_> {
    /// The verified copy's root of the pinned folder holding `rel`, and the rest of the path below it.
    fn tree_parts(&self, rel: &str) -> Option<(PathBuf, String)> {
        self.trees.iter().find_map(|(t, copy)| {
            rel.strip_prefix(&format!("{t}/"))
                .map(|rest| (copy.clone(), rest.to_string()))
        })
    }
    /// Where `rel` is, if it lies inside a pinned folder: the verified copy's path.
    fn in_tree(&self, rel: &str) -> Option<PathBuf> {
        self.trees.iter().find_map(|(t, copy)| {
            if rel == t {
                Some(copy.clone())
            } else {
                rel.strip_prefix(&format!("{t}/"))
                    .map(|rest| copy.join(rest))
            }
        })
    }
}

impl Source for PinnedSource<'_> {
    fn file(&mut self, rel: &str) -> Result<Vec<u8>, String> {
        let path = self
            .files
            .get(rel)
            .cloned()
            .or_else(|| self.in_tree(rel))
            .ok_or_else(|| format!("{rel} is loaded but not pinned (pin the file; a folder that holds it is read file by file, and a package folder goes under node_modules)"))?;
        // G5 eighth round, NV7-L1: a file read from a pinned project folder (not a package under node_modules/) may not be, or sit
        // behind, a link: Node resolves its relative imports from the link's TARGET folder, the walk from the path it was reached by.
        if !rel.starts_with("node_modules/") && !self.files.contains_key(rel) {
            if let Some((root, rest)) = self.tree_parts(rel) {
                let mut p = root;
                for c in Path::new(&rest).components() {
                    p.push(c);
                    if std::fs::symlink_metadata(&p)
                        .map(|m| m.file_type().is_symlink())
                        .unwrap_or(true)
                    {
                        return Err(format!(
                            "{rel} is, or is under, a link: a pinned project folder may not hold a link on the path of a file a secret command loads"
                        ));
                    }
                }
            }
        }
        std::fs::read(path).map_err(|_| format!("{rel} cannot be read"))
    }
    fn package_json(&mut self, name: &str) -> Result<Option<Vec<u8>>, String> {
        let rel = format!("node_modules/{name}");
        if let Some(copy) = self.trees.get(&rel) {
            return Ok(Some(
                std::fs::read(copy.join("package.json")).unwrap_or_else(|_| b"{}".to_vec()),
            ));
        }
        if self.dir.join(&rel).is_dir() {
            return Err(format!(
                "the package {name} is loaded but its folder is not pinned (pin {rel})"
            ));
        }
        Ok(None)
    }
    fn dir_exists(&mut self, rel: &str) -> bool {
        match self.in_tree(rel) {
            Some(p) => p.is_dir(),
            None => self.dir.join(rel).is_dir(),
        }
    }
    fn covered(&mut self, rel: &str) -> bool {
        // G5 seventh round, NV6-H1: only a package under `node_modules/` is trusted as pinned bytes. A pinned project folder
        // (`lib`) is READ file by file from the verified copy, so what it loads from a writable folder, or a spawner it imports, is seen.
        rel.starts_with("node_modules/") && self.in_tree(rel).is_some()
    }
}

/// What a script's loading reads, from the folder as it is now: for the person who is working out what to pin.
struct LiveSource<'a> {
    dir: &'a Path,
}

impl Source for LiveSource<'_> {
    fn file(&mut self, rel: &str) -> Result<Vec<u8>, String> {
        read_pinned(self.dir, rel).map_err(|_| format!("{rel} cannot be read as a plain file"))
    }
    fn package_json(&mut self, name: &str) -> Result<Option<Vec<u8>>, String> {
        let p = self.dir.join("node_modules").join(name);
        if !p.is_dir() {
            return Ok(None);
        }
        Ok(Some(
            std::fs::read(p.join("package.json")).unwrap_or_else(|_| b"{}".to_vec()),
        ))
    }
    fn dir_exists(&mut self, rel: &str) -> bool {
        self.dir.join(rel).is_dir()
    }
    fn covered(&mut self, rel: &str) -> bool {
        rel.starts_with("node_modules/")
    }
}

/// The pins that cover a script and everything it loads, as they are now: for `ozbox env policy pin --entry`.
pub fn closure_pins(dir: &Path, entry: &str) -> Result<(Vec<Pin>, Vec<TreePin>), String> {
    let entry = entry.trim_start_matches("./");
    let c = runner_imports::closure(entry, &mut LiveSource { dir })?;
    let mut names: std::collections::BTreeSet<String> = c.files.into_iter().collect();
    // The `package.json` files Node reads to scope a script (its `type`, its `exports`, a self-reference by package name) are
    // the project's own and the ones on the way from the script up to the project folder. They are pinned when they exist, so
    // what scopes the script is the approved file; the private view (`runner::sandbox_props`) shows no other (G5 third round, NV-H1).
    let mut chain = Some(Path::new(entry));
    while let Some(p) = chain {
        let parent = p.parent().filter(|q| !q.as_os_str().is_empty());
        let pj = parent.map_or_else(
            || "package.json".to_string(),
            |q| format!("{}/package.json", q.display()),
        );
        if std::fs::symlink_metadata(dir.join(&pj)).is_ok_and(|m| m.is_file()) {
            names.insert(pj);
        }
        chain = parent;
    }
    if std::fs::symlink_metadata(dir.join("package.json")).is_ok_and(|m| m.is_file()) {
        names.insert("package.json".to_string());
    }
    let files = digests(dir, &names.into_iter().collect::<Vec<_>>())?;
    let mut trees = Vec::new();
    for t in c.trees {
        trees.push(TreePin {
            sha256: tree_digest(&dir.join(&t))?,
            path: t,
        });
    }
    Ok((files, trees))
}

fn write_private(path: &Path, bytes: &[u8], mode: u32) -> std::io::Result<()> {
    use std::io::Write;
    let _ = std::fs::remove_file(path);
    let mut f = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(mode | 0o200)
        .open(path)?;
    f.write_all(bytes)?;
    f.sync_all()?;
    drop(f);
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode))
}

/// Read a regular file without following a link at the last component.
fn read_nofollow(path: &Path) -> std::io::Result<Vec<u8>> {
    use std::io::Read;
    let mut f = std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW)
        .open(path)?;
    let mut v = Vec::new();
    (&mut f).take(MAX_PIN_BYTES + 1).read_to_end(&mut v)?;
    if v.len() as u64 > MAX_PIN_BYTES {
        return Err(std::io::Error::other("too large"));
    }
    Ok(v)
}

/// Read the pinned file `rel` under the project folder `dir`, opening EVERY component (the folder's own path included) with
/// `O_NOFOLLOW` from a descriptor, so a link put in place anywhere on the way, even a moment ago, refuses instead of being
/// followed. (Linux; elsewhere the last component alone is checked.)
#[cfg(target_os = "linux")]
fn read_pinned(dir: &Path, rel: &str) -> std::io::Result<Vec<u8>> {
    use rustix::fs::{openat, Mode, OFlags, CWD};
    use std::io::Read;
    use std::path::Component;
    let dirflags = OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC;
    let mut fd = openat(CWD, "/", dirflags, Mode::empty())?;
    let comps: Vec<_> = dir
        .components()
        .chain(Path::new(rel).components())
        .filter_map(|c| match c {
            Component::Normal(n) => Some(Ok(n.to_os_string())),
            Component::RootDir | Component::CurDir => None,
            _ => Some(Err(std::io::Error::other("a path with .. or a prefix"))),
        })
        .collect::<Result<_, _>>()?;
    let (last, parents) = comps
        .split_last()
        .ok_or_else(|| std::io::Error::other("empty path"))?;
    for c in parents {
        fd = openat(&fd, c.as_os_str(), dirflags, Mode::empty())?;
    }
    let f = openat(
        &fd,
        last.as_os_str(),
        OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
    )?;
    let mut f = std::fs::File::from(f);
    let mut v = Vec::new();
    (&mut f).take(MAX_PIN_BYTES + 1).read_to_end(&mut v)?;
    if v.len() as u64 > MAX_PIN_BYTES {
        return Err(std::io::Error::other("too large"));
    }
    Ok(v)
}

#[cfg(not(target_os = "linux"))]
fn read_pinned(dir: &Path, rel: &str) -> std::io::Result<Vec<u8>> {
    read_nofollow(&dir.join(rel))
}

/// The pin entries for files, as a person pastes them into a declaration: path and digest of what is there now.
pub fn digests(dir: &Path, files: &[String]) -> Result<Vec<Pin>, String> {
    let mut v = Vec::new();
    for f in files {
        let p = dir.join(f);
        let bytes = read_nofollow(&p).map_err(|_| format!("{f} cannot be read as a plain file"))?;
        v.push(Pin {
            file: f.clone(),
            sha256: sha256_hex(&bytes),
        });
    }
    Ok(v)
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::time::Instant;

    fn setup() -> (tempfile::TempDir, PinStore, PathBuf) {
        let d = tempfile::tempdir().unwrap();
        let base = std::fs::canonicalize(d.path()).unwrap();
        let proj = base.join("proj");
        std::fs::create_dir_all(proj.join("tests")).unwrap();
        std::fs::write(proj.join("tests/mint.mjs"), "console.log('ok')\n").unwrap();
        std::fs::write(proj.join("package.json"), "{}\n").unwrap();
        let store = PinStore::new(base.join("pins"));
        (d, store, proj)
    }

    fn pins(proj: &Path, files: &[&str]) -> Vec<Pin> {
        digests(
            proj,
            &files.iter().map(|s| s.to_string()).collect::<Vec<_>>(),
        )
        .unwrap()
    }

    fn check(store: &PinStore, proj: &Path, p: &[Pin]) -> Result<Checked, String> {
        store.check("app", proj, p, &[], false)
    }

    #[test]
    fn a_pinned_file_is_run_from_a_read_only_copy_of_the_bytes_that_were_hashed() {
        let (_d, store, proj) = setup();
        let p = pins(&proj, &["tests/mint.mjs", "package.json"]);
        let c = check(&store, &proj, &p).unwrap();
        assert_eq!(c.mounts.len(), 2);
        assert_eq!(c.hashed, 2);
        let m = &c.mounts[0];
        assert_eq!(std::fs::read(&m.blob).unwrap(), b"console.log('ok')\n");
        assert_eq!(
            std::fs::metadata(&m.blob).unwrap().permissions().mode() & 0o777,
            0o444
        );
        assert!(m.blob.starts_with(store.root.join("blobs")));
        assert!(
            m.property().starts_with("BindReadOnlyPaths=")
                && m.property().ends_with("tests/mint.mjs")
        );
        // the copy is what the unit sees: changing the file afterwards does not change the copy
        std::fs::write(proj.join("tests/mint.mjs"), "steal()\n").unwrap();
        assert_eq!(std::fs::read(&m.blob).unwrap(), b"console.log('ok')\n");
    }

    #[test]
    fn a_changed_file_stops_the_run_and_names_the_file() {
        let (_d, store, proj) = setup();
        let p = pins(&proj, &["tests/mint.mjs", "package.json"]);
        check(&store, &proj, &p).unwrap();
        std::fs::write(proj.join("tests/mint.mjs"), "steal()\n").unwrap();
        let e = check(&store, &proj, &p).unwrap_err();
        assert!(
            e.contains("tests/mint.mjs")
                && e.contains("has changed")
                && !e.contains("package.json"),
            "{e}"
        );
        // putting the content back is accepted again (it is the approved content)
        std::fs::write(proj.join("tests/mint.mjs"), "console.log('ok')\n").unwrap();
        assert!(check(&store, &proj, &p).is_ok());
    }

    #[test]
    fn a_same_size_edit_with_the_old_modification_time_is_still_caught() {
        let (_d, store, proj) = setup();
        let p = pins(&proj, &["tests/mint.mjs"]);
        let f = proj.join("tests/mint.mjs");
        check(&store, &proj, &p).unwrap();
        let old = std::fs::metadata(&f).unwrap().modified().unwrap();
        // same length, written in place, then the time set back: the five numbers include ctime, which cannot be set back
        std::fs::write(&f, "console.log('NO')\n").unwrap();
        std::fs::File::options()
            .write(true)
            .open(&f)
            .unwrap()
            .set_modified(old)
            .unwrap();
        assert!(check(&store, &proj, &p).is_err());
    }

    #[test]
    fn an_unchanged_file_is_not_read_again() {
        let (_d, store, proj) = setup();
        let p = pins(&proj, &["tests/mint.mjs", "package.json"]);
        assert_eq!(check(&store, &proj, &p).unwrap().hashed, 2);
        let again = check(&store, &proj, &p).unwrap();
        assert_eq!(again.hashed, 0, "answered from the cache");
        assert_eq!(again.mounts.len(), 2);
        // the cache is private to the root-owned folder
        let m = std::fs::metadata(store.cache_path("app")).unwrap();
        assert_eq!(m.permissions().mode() & 0o777, 0o600);
        // a lost copy is rewritten from the file, which still matches
        std::fs::remove_dir_all(store.root.join("blobs")).unwrap();
        let c = check(&store, &proj, &p).unwrap();
        assert_eq!(c.hashed, 2);
        assert!(c.mounts[0].blob.is_file());
    }

    #[test]
    fn a_link_a_missing_file_and_a_path_out_of_the_folder_are_refused() {
        let (d, store, proj) = setup();
        let p = pins(&proj, &["tests/mint.mjs"]);
        std::fs::write(d.path().join("outside.mjs"), "x").unwrap();
        let bad = |file: &str| Pin {
            file: file.into(),
            sha256: p[0].sha256.clone(),
        };
        assert!(check(&store, &proj, &[bad("nope.mjs")])
            .unwrap_err()
            .contains("missing"));
        std::fs::remove_file(proj.join("tests/mint.mjs")).unwrap();
        std::os::unix::fs::symlink(d.path().join("outside.mjs"), proj.join("tests/mint.mjs"))
            .unwrap();
        assert!(check(&store, &proj, &p).unwrap_err().contains("link"));
        // the directory above it swapped for a link is the same refusal
        std::fs::remove_file(proj.join("tests/mint.mjs")).unwrap();
        std::fs::remove_dir(proj.join("tests")).unwrap();
        std::fs::create_dir_all(d.path().join("elsewhere")).unwrap();
        std::fs::write(d.path().join("elsewhere/mint.mjs"), "console.log('ok')\n").unwrap();
        std::os::unix::fs::symlink(d.path().join("elsewhere"), proj.join("tests")).unwrap();
        assert!(check(&store, &proj, &p).unwrap_err().contains("link"));
    }

    /// the project folder itself reached through a link is refused, and a link anywhere on the walk to a pinned
    /// file is refused by the descriptor walk even when the path check would have been fooled.
    #[test]
    fn a_project_folder_reached_through_a_link_is_refused_and_the_read_follows_no_link() {
        let (d, store, proj) = setup();
        let p = pins(&proj, &["tests/mint.mjs"]);
        let alias = d.path().join("alias");
        std::os::unix::fs::symlink(&proj, &alias).unwrap();
        let e = store.check("app", &alias, &p, &[], false).unwrap_err();
        assert!(e.contains("through a link"), "{e}");
        // the read itself: a link in the middle of the path, or as the file, is not followed
        assert!(read_pinned(&proj, "tests/mint.mjs").is_ok());
        std::fs::rename(proj.join("tests"), proj.join("tests-real")).unwrap();
        std::os::unix::fs::symlink(proj.join("tests-real"), proj.join("tests")).unwrap();
        #[cfg(target_os = "linux")]
        assert!(
            read_pinned(&proj, "tests/mint.mjs").is_err(),
            "a link on the walk is refused"
        );
        assert!(read_pinned(&proj.join("tests-real"), "mint.mjs").is_ok());
        std::fs::remove_file(proj.join("tests")).unwrap();
        std::fs::rename(proj.join("tests-real"), proj.join("tests")).unwrap();
        std::fs::remove_file(proj.join("tests/mint.mjs")).unwrap();
        std::os::unix::fs::symlink(proj.join("package.json"), proj.join("tests/mint.mjs")).unwrap();
        assert!(
            read_pinned(&proj, "tests/mint.mjs").is_err(),
            "a link as the file is refused"
        );
    }

    static NOW: AtomicU64 = AtomicU64::new(1_000_000);
    fn fake_now() -> u64 {
        NOW.load(Ordering::SeqCst)
    }

    /// repeated changes to a pinned file are somebody searching for a window; the project is locked out for a while.
    #[test]
    fn repeated_mismatches_lock_the_project_out_for_a_while() {
        let (_d, mut store, proj) = setup();
        store.now = fake_now;
        NOW.store(1_000_000, Ordering::SeqCst);
        let p = pins(&proj, &["tests/mint.mjs"]);
        check(&store, &proj, &p).unwrap();
        std::fs::write(proj.join("tests/mint.mjs"), "steal()\n").unwrap();
        for i in 0..MAX_MISMATCHES {
            NOW.fetch_add(1_000, Ordering::SeqCst);
            let e = check(&store, &proj, &p).unwrap_err();
            assert!(e.contains("has changed"), "{i}: {e}");
        }
        // now locked, even for the approved content
        std::fs::write(proj.join("tests/mint.mjs"), "console.log('ok')\n").unwrap();
        NOW.fetch_add(1_000, Ordering::SeqCst);
        let e = check(&store, &proj, &p).unwrap_err();
        assert!(e.contains("paused") && e.contains("seconds"), "{e}");
        // other projects are not affected, and it passes after the pause
        assert!(store.check("other", &proj, &p, &[], false).is_ok());
        NOW.fetch_add(LOCK_MS + 1_000, Ordering::SeqCst);
        assert!(check(&store, &proj, &p).is_ok());
    }

    fn make_pkg(proj: &Path, name: &str, files: &[(&str, &str)]) {
        for (f, body) in files {
            let p = proj.join("node_modules").join(name).join(f);
            std::fs::create_dir_all(p.parent().unwrap()).unwrap();
            std::fs::write(p, body).unwrap();
        }
    }

    fn tree_pin(proj: &Path, rel: &str) -> TreePin {
        TreePin {
            path: rel.to_string(),
            sha256: tree_digest(&proj.join(rel)).unwrap(),
        }
    }

    /// a folder is pinned like a file: a verified copy bound over it, a change refused by name, and no re-read of an
    /// unchanged tree.
    #[test]
    fn a_pinned_folder_is_run_from_a_verified_copy_and_a_change_to_it_is_refused() {
        let (_d, store, proj) = setup();
        make_pkg(
            &proj,
            "pkg",
            &[
                ("index.js", "module.exports = 1\n"),
                ("lib/a.js", "exports.a = 1\n"),
                ("package.json", "{\"name\":\"pkg\"}"),
            ],
        );
        let t = tree_pin(&proj, "node_modules/pkg");
        let one = std::slice::from_ref(&t);
        let c = store.check("app", &proj, &[], one, false).unwrap();
        assert_eq!(c.hashed, 1);
        let m = &c.mounts[0];
        assert_eq!(m.dest, proj.join("node_modules/pkg"));
        assert_eq!(m.blob, store.root.join("trees").join(&t.sha256));
        assert_eq!(
            std::fs::read_to_string(m.blob.join("lib/a.js")).unwrap(),
            "exports.a = 1\n"
        );
        assert_eq!(
            tree_digest(&m.blob).unwrap(),
            t.sha256,
            "the copy digests like the source"
        );
        assert!(
            m.property().starts_with("BindReadOnlyPaths=")
                && m.property().ends_with("node_modules/pkg")
        );
        // unchanged: answered from the fingerprint, no read
        assert_eq!(
            store.check("app", &proj, &[], one, false).unwrap().hashed,
            0
        );
        // the copy is not the live folder: editing the live one afterwards leaves the copy alone
        std::fs::write(proj.join("node_modules/pkg/lib/a.js"), "steal()\n").unwrap();
        assert_eq!(
            std::fs::read_to_string(m.blob.join("lib/a.js")).unwrap(),
            "exports.a = 1\n"
        );
        // a changed file, an added file and a removed file each stop the run and name the folder
        let e = store.check("app", &proj, &[], one, false).unwrap_err();
        assert!(
            e.contains("node_modules/pkg") && e.contains("has changed"),
            "{e}"
        );
        std::fs::write(proj.join("node_modules/pkg/lib/a.js"), "exports.a = 1\n").unwrap();
        assert!(store.check("app", &proj, &[], one, false).is_ok());
        std::fs::write(proj.join("node_modules/pkg/evil.js"), "steal()\n").unwrap();
        assert!(
            store
                .check("app", &proj, &[], one, false)
                .unwrap_err()
                .contains("has changed"),
            "an added file"
        );
        std::fs::remove_file(proj.join("node_modules/pkg/evil.js")).unwrap();
        std::fs::remove_file(proj.join("node_modules/pkg/lib/a.js")).unwrap();
        assert!(
            store
                .check("app", &proj, &[], one, false)
                .unwrap_err()
                .contains("has changed"),
            "a removed file"
        );
    }

    #[test]
    fn a_same_size_edit_inside_a_pinned_folder_with_the_old_time_is_caught_and_a_link_out_is_refused(
    ) {
        let (d, store, proj) = setup();
        make_pkg(&proj, "pkg", &[("index.js", "module.exports = 1\n")]);
        let t = tree_pin(&proj, "node_modules/pkg");
        let one = std::slice::from_ref(&t);
        store.check("app", &proj, &[], one, false).unwrap();
        let f = proj.join("node_modules/pkg/index.js");
        let old = std::fs::metadata(&f).unwrap().modified().unwrap();
        std::fs::write(&f, "module.exports = 2\n").unwrap();
        std::fs::File::options()
            .write(true)
            .open(&f)
            .unwrap()
            .set_modified(old)
            .unwrap();
        assert!(store
            .check("app", &proj, &[], one, false)
            .unwrap_err()
            .contains("has changed"));
        // restore, then: the folder itself a link, and a link inside it that leaves it
        std::fs::write(&f, "module.exports = 1\n").unwrap();
        let outside = d.path().join("outside");
        std::fs::create_dir_all(&outside).unwrap();
        std::os::unix::fs::symlink(&outside, proj.join("node_modules/linked")).unwrap();
        let lt = TreePin {
            path: "node_modules/linked".into(),
            sha256: t.sha256.clone(),
        };
        assert!(store
            .check("app", &proj, &[], &[lt], false)
            .unwrap_err()
            .contains("link"));
        std::os::unix::fs::symlink("/etc/passwd", proj.join("node_modules/pkg/evil")).unwrap();
        let e = store.check("app", &proj, &[], one, false).unwrap_err();
        assert!(e.contains("leaves") || e.contains("has changed"), "{e}");
    }

    fn mint_project() -> (tempfile::TempDir, PinStore, PathBuf) {
        let (d, store, proj) = setup();
        std::fs::write(
            proj.join("tests/mint.mjs"),
            "import { createClient } from '@supabase/supabase-js'\nimport { retry } from './retry.mjs'\nimport fs from 'node:fs'\nconsole.log(createClient, retry, fs)\n",
        )
        .unwrap();
        std::fs::write(proj.join("tests/retry.mjs"), "export const retry = 1\n").unwrap();
        make_pkg(
            &proj,
            "@supabase/supabase-js",
            &[
                ("index.js", "exports.createClient = 1"),
                (
                    "package.json",
                    r#"{"dependencies":{"@supabase/auth-js":"1"}}"#,
                ),
            ],
        );
        make_pkg(
            &proj,
            "@supabase/auth-js",
            &[("index.js", "exports.auth = 1"), ("package.json", "{}")],
        );
        (d, store, proj)
    }

    /// On the real shape of the session minter this feature exists for: it imports a sibling and a package that
    /// itself needs another. A pin of the entry alone leaves all three unpinned and the run is refused; the closure that
    /// `policy pin --entry` prints is accepted, and a change to any of it is refused.
    #[test]
    fn a_script_that_receives_a_secret_runs_only_when_everything_it_loads_is_pinned() {
        let (_d, store, proj) = mint_project();
        let argv: Vec<String> = ["node", "tests/mint.mjs"].map(String::from).to_vec();
        // the entry alone: the sibling is not pinned
        let only = pins(&proj, &["tests/mint.mjs"]);
        let c = store.check("app", &proj, &only, &[], false).unwrap();
        let e = store.check_code(&proj, &argv, &c).unwrap_err();
        assert!(e.contains("not pinned"), "{e}");
        // with the sibling: the package is not pinned
        let two = pins(&proj, &["tests/mint.mjs", "tests/retry.mjs"]);
        let c = store.check("app", &proj, &two, &[], false).unwrap();
        let e = store.check_code(&proj, &argv, &c).unwrap_err();
        assert!(
            e.contains("@supabase/supabase-js") && e.contains("not pinned"),
            "{e}"
        );
        // what the tool says to pin is the whole closure: two files, and the package AND the package it needs
        let (files, trees) = closure_pins(&proj, "tests/mint.mjs").unwrap();
        assert_eq!(
            files.iter().map(|f| f.file.as_str()).collect::<Vec<_>>(),
            ["package.json", "tests/mint.mjs", "tests/retry.mjs"]
        );
        assert_eq!(
            trees.iter().map(|t| t.path.as_str()).collect::<Vec<_>>(),
            [
                "node_modules/@supabase/auth-js",
                "node_modules/@supabase/supabase-js"
            ]
        );
        let c = store.check("app", &proj, &files, &trees, false).unwrap();
        store.check_code(&proj, &argv, &c).unwrap();
        // the unpinned pieces an agent could rewrite are each refused: a sibling edit, a package edit
        std::fs::write(
            proj.join("tests/retry.mjs"),
            "import fs from 'node:fs'; fs.readFileSync('/etc/passwd')\n",
        )
        .unwrap();
        assert!(store
            .check("app", &proj, &files, &trees, false)
            .unwrap_err()
            .contains("tests/retry.mjs"));
        std::fs::write(proj.join("tests/retry.mjs"), "export const retry = 1\n").unwrap();
        std::fs::write(
            proj.join("node_modules/@supabase/auth-js/index.js"),
            "exports.auth = steal()",
        )
        .unwrap();
        assert!(store
            .check("app", &proj, &files, &trees, false)
            .unwrap_err()
            .contains("@supabase/auth-js"));
    }

    /// G5 seventh round, NV6-H1: a pinned PROJECT folder (`lib`) is not trusted as pinned bytes: every file the script reaches in it
    /// is read, so an import of a writable folder or of a spawner is refused. Only a package under `node_modules/` is covered.
    #[test]
    fn a_file_in_a_pinned_project_folder_is_read_and_may_not_load_from_a_writable_folder_or_spawn()
    {
        let (_d, store, proj) = setup();
        std::fs::create_dir_all(proj.join("lib")).unwrap();
        std::fs::create_dir_all(proj.join("out")).unwrap();
        std::fs::write(
            proj.join("tests/mint.mjs"),
            "import { a } from '../lib/a.mjs'\nconsole.log(a)\n",
        )
        .unwrap();
        std::fs::write(proj.join("out/x.mjs"), "export const x = 1\n").unwrap();
        let argv: Vec<String> = ["node", "tests/mint.mjs"].map(String::from).to_vec();
        let run = |lib_src: &str| -> Result<(), String> {
            std::fs::write(proj.join("lib/a.mjs"), lib_src).unwrap();
            let c = store.check(
                "app",
                &proj,
                &pins(&proj, &["tests/mint.mjs"]),
                &[tree_pin(&proj, "lib")],
                false,
            )?;
            store.check_code(&proj, &argv, &c)
        };
        assert!(run("export const a = 1\n").is_ok());
        let e = run("import { x } from '../out/x.mjs'\nexport const a = x\n").unwrap_err();
        assert!(e.contains("out/x.mjs") && e.contains("not pinned"), "{e}");
        let e = run("import cp from 'node:child_process'\nexport const a = cp\n").unwrap_err();
        assert!(e.contains("not covered by the pin"), "{e}");
        // a sibling inside the same pinned folder is followed and read from the verified copy
        std::fs::write(proj.join("lib/b.mjs"), "import '../out/x.mjs'\n").unwrap();
        let e = run("import './b.mjs'\nexport const a = 1\n").unwrap_err();
        assert!(e.contains("out/x.mjs"), "{e}");
    }

    /// G5 eighth round, NV7-L1: a link inside a pinned project folder on the path of a loaded file is refused, because Node would
    /// resolve its imports from the link's target folder.
    #[test]
    fn a_link_inside_a_pinned_project_folder_on_a_loaded_path_is_refused() {
        let (_d, store, proj) = setup();
        std::fs::create_dir_all(proj.join("lib/sub")).unwrap();
        std::fs::create_dir_all(proj.join("lib/out")).unwrap();
        std::fs::create_dir_all(proj.join("out")).unwrap();
        std::fs::write(
            proj.join("tests/mint.mjs"),
            "import { a } from '../lib/sub/a.mjs'\nconsole.log(a)\n",
        )
        .unwrap();
        std::fs::write(
            proj.join("lib/b.mjs"),
            "import { x } from '../out/x.mjs'\nexport const a = x\n",
        )
        .unwrap();
        std::fs::write(proj.join("lib/out/x.mjs"), "export const x = 1\n").unwrap();
        std::fs::write(proj.join("out/x.mjs"), "export const x = 2\n").unwrap();
        std::os::unix::fs::symlink("../b.mjs", proj.join("lib/sub/a.mjs")).unwrap();
        let argv: Vec<String> = ["node", "tests/mint.mjs"].map(String::from).to_vec();
        let c = store
            .check(
                "app",
                &proj,
                &pins(&proj, &["tests/mint.mjs"]),
                &[tree_pin(&proj, "lib")],
                false,
            )
            .unwrap();
        let e = store.check_code(&proj, &argv, &c).unwrap_err();
        assert!(e.contains("link"), "{e}");
    }

    /// G5 third round, NV-H1: the project's own `package.json`, and any on the way from the script up to the project folder, are
    /// pinned when they exist, so what scopes the script (its `type`, a self-reference by name) is the approved file.
    #[test]
    fn the_package_json_files_that_scope_a_script_are_pinned_with_it() {
        let (_d, _store, proj) = mint_project();
        std::fs::write(
            proj.join("package.json"),
            r#"{"name":"app","type":"module"}"#,
        )
        .unwrap();
        std::fs::write(proj.join("tests/package.json"), r#"{"type":"module"}"#).unwrap();
        let (files, _) = closure_pins(&proj, "tests/mint.mjs").unwrap();
        let names: Vec<&str> = files.iter().map(|f| f.file.as_str()).collect();
        assert_eq!(
            names,
            [
                "package.json",
                "tests/mint.mjs",
                "tests/package.json",
                "tests/retry.mjs"
            ]
        );
    }

    #[test]
    fn what_cannot_be_checked_is_refused_for_a_script_that_receives_a_secret() {
        let (_d, store, proj) = mint_project();
        let argv: Vec<String> = ["node", "tests/mint.mjs"].map(String::from).to_vec();
        let run = |src: &str, store: &PinStore| -> Result<(), String> {
            std::fs::write(proj.join("tests/mint.mjs"), src).unwrap();
            let c = store.check(
                "app",
                &proj,
                &pins(&proj, &["tests/mint.mjs", "tests/retry.mjs"]),
                &[],
                false,
            )?;
            store.check_code(&proj, &argv, &c)
        };
        assert!(run(
            "import fs from 'node:fs'; import { retry } from './retry.mjs'; console.log(fs, retry)",
            &store
        )
        .is_ok());
        // a computed loader, an extension-less sibling, an absolute path, createRequire
        for bad in [
            "const m = await import(process.env.X)",
            "import './retry'",
            "import '/tmp/evil.mjs'",
            "import { createRequire } from 'node:module'",
        ] {
            assert!(run(bad, &store).is_err(), "{bad}");
        }
        // a secret command with no script entry is refused (NV5-H1); a script that is not pinned, or is outside the folder, is refused
        let c = Checked::default();
        for argv in [
            vec!["node", "--version"],
            vec!["node", "-e", "0"],
            vec!["node", "tests/mint"],
            vec!["node"],
        ] {
            let argv: Vec<String> = argv.into_iter().map(String::from).collect();
            assert!(
                store
                    .check_code(&proj, &argv, &c)
                    .unwrap_err()
                    .contains("no script was found"),
                "{argv:?}"
            );
        }
        assert!(store
            .check_code(&proj, &["node".into(), "x.mjs".into()], &c)
            .unwrap_err()
            .contains("not pinned"));
        assert!(store
            .check_code(&proj, &["node".into(), "../x.mjs".into()], &c)
            .unwrap_err()
            .contains("outside"));
    }

    /// Per-run cost on this computer; the number to repeat on a 4 vCPU / 8 GiB box is in the report.
    #[test]
    fn the_check_is_cheap_for_a_handful_of_small_files() {
        let (_d, store, proj) = setup();
        let p = pins(&proj, &["tests/mint.mjs", "package.json"]);
        check(&store, &proj, &p).unwrap();
        let t = Instant::now();
        for _ in 0..200 {
            check(&store, &proj, &p).unwrap();
        }
        let per = t.elapsed().as_micros() / 200;
        eprintln!("MEASURED pin check, 2 files, warm cache: {per} us per run");
        assert!(per < 20_000, "{per} us");
    }

    /// Cold and warm cost of pinning the packages a real minter needs: about a dozen packages and 1,500 files of 6 KiB.
    #[test]
    fn the_cost_of_pinning_a_dependency_tree_is_measured_cold_and_warm() {
        let (_d, store, proj) = setup();
        let mut trees = Vec::new();
        for k in 0..12 {
            let name = format!("pkg{k}");
            for i in 0..125 {
                make_pkg(
                    &proj,
                    &name,
                    &[(&format!("d{}/f{i}.js", i % 10), &"x".repeat(6144))],
                );
            }
            trees.push(tree_pin(&proj, &format!("node_modules/{name}")));
        }
        let t = Instant::now();
        let c = store.check("app", &proj, &[], &trees, false).unwrap();
        let cold = t.elapsed().as_millis();
        assert_eq!(c.hashed, 12);
        let t = Instant::now();
        for _ in 0..20 {
            assert_eq!(
                store
                    .check("app", &proj, &[], &trees, false)
                    .unwrap()
                    .hashed,
                0
            );
        }
        let warm = t.elapsed().as_micros() / 20;
        // the private view (a secret command): once the copies exist the live folder is not touched at all
        let t = Instant::now();
        for _ in 0..20 {
            assert_eq!(
                store.check("app", &proj, &[], &trees, true).unwrap().hashed,
                0
            );
        }
        let private = t.elapsed().as_micros() / 20;
        eprintln!("MEASURED 12 pinned packages / 1,500 files / 9 MB: cold (read, hash, copy) {cold} ms, warm plain (stat fingerprint walk) {warm} us per run, private view (copies exist, no live access) {private} us per run");
        assert!(warm < 300_000, "{warm} us");
        assert!(
            private < warm.max(1000),
            "the private view is no slower than the walk it replaces: {private} us vs {warm} us"
        );
    }
}
