//! What a project's declaration needs on the machine before its commands can run as the project's runner user, set up by the
//! root helper (`ensure-runner`, then `ozbox secrets runner-setup PROJECT`) and only ever from the STORED, approved
//! declaration: nothing in a request chooses a path, a tool or a folder. Three things, each with its own permission model.
//!
//! **The project folder.** The runner user is in no shared group, so it can read nothing of the box user's. It is given
//! access to the declared folder and nothing else, with a POSIX ACL for that one user:
//! - read and search (`r-X`) on `dir`, recursively, and as a *default* so files the box user adds later are readable too;
//!   `.git` is taken back out (history and a repository's own configuration are not the runner's);
//! - search only (`--x`) on each parent from `/work` down to `dir` (it can walk through, not list);
//! - read, write and search (`rwX`) on each `writable` folder, with a default entry for the runner and the box user, so what
//!   the runner creates there stays manageable by the box user.
//!
//! Every `setfacl` call is `-P` (never follows a link), and the declared folder must already be its own real path. A removed
//! declaration, or a changed folder, takes the entries away again (the state file says what was granted).
//!
//! **Runner users.** The project has one runner user, which runs its plain commands and its services. A command that is given a
//! secret has a runner user of ITS OWN (`runner::runner_user_for`), made here from the stored declaration and granted the same
//! folder access. So a service, a browser or any other command never shares a user with the process that holds a secret, and
//! `/proc/<pid>/environ` of the one is not readable by the other.
//!
//! **Tools.** The box user's own `~/.local/opt/<tool>` is writable by the box user, so putting it on a runner's PATH would let
//! an agent replace `node` and read whatever the command receives. So the tools are a root-owned *copy*: files owned by root, no
//! group or other write, no setuid, links that stay inside the tree. Which paths and which programs a tool has comes from the
//! catalog compiled into this program, never from a record in the box user's home. The copy is named by the digest of its content
//! (so one project's setup cannot change what another runs) and is made from ONE read that is compared with the digest the
//! declaration approved. **A project with a command that receives a secret must pin every tool:** `ensure-runner` is run by an
//! ungated helper an agent can ask for, and an unpinned tool is whatever the box user has put there at that moment.
//!
//! **Browsers.** Playwright's cache directories, copied by revision, ONLY when the declaration approved that directory's digest
//! (`browser_digests`), into content-named folders, with a folder of links per project. A directory the box user planted, or
//! changed, is not copied. A browser is never given to a command that receives a secret.

use std::collections::{BTreeMap, BTreeSet};
use std::os::unix::fs::PermissionsExt;
use std::path::{Component, Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::runner::{runner_user, runner_users, BROWSERS_ROOT, RUN_HOME, TOOLS_ROOT};
use crate::runner_pins::sha256_hex;
use crate::workload_policy::Policy;

#[derive(Clone)]
pub struct Paths {
    pub box_home: PathBuf,
    pub tools: PathBuf,
    pub browsers: PathBuf,
    pub state: PathBuf,
    pub work: PathBuf,
    pub box_user: String,
}

impl Paths {
    pub fn system(box_home: PathBuf) -> Paths {
        Paths {
            box_home,
            tools: PathBuf::from(TOOLS_ROOT),
            browsers: PathBuf::from(BROWSERS_ROOT),
            state: PathBuf::from(RUN_HOME).join(".state"),
            work: PathBuf::from("/work"),
            box_user: "ozbox".into(),
        }
    }
}

/// Runs the one program this module needs (`setfacl`); a test supplies a recorder.
pub trait Acl {
    fn run(&self, argv: &[String]) -> Result<(), String>;
    /// The exit status of the program, for the one caller that must tell "nothing found" (1) from "could not look" (2, 3, a missing
    /// program). The default maps a refusal to 1, which is what a recorder in a test means by it.
    fn run_code(&self, argv: &[String]) -> Result<i32, String> {
        self.run(argv).map(|()| 0).or(Ok(1))
    }
}

pub struct SystemAcl;

impl Acl for SystemAcl {
    fn run_code(&self, argv: &[String]) -> Result<i32, String> {
        let st = std::process::Command::new(&argv[0])
            .args(&argv[1..])
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .status()
            .map_err(|_| format!("{} could not be run", argv[0]))?;
        // killed by a signal: no code, so not "nothing found"
        Ok(st.code().unwrap_or(-1))
    }
    fn run(&self, argv: &[String]) -> Result<(), String> {
        let out = std::process::Command::new(&argv[0])
            .args(&argv[1..])
            .stdin(std::process::Stdio::null())
            .output()
            .map_err(|_| "setfacl is not installed on this box (the `acl` package)".to_string())?;
        if out.status.success() {
            Ok(())
        } else {
            Err(format!(
                "setfacl refused: {}",
                String::from_utf8_lossy(&out.stderr)
                    .trim()
                    .chars()
                    .take(200)
                    .collect::<String>()
            ))
        }
    }
}

/// Bump when what setup does changes, so a box set up by an earlier program is set up again (the stored digest no longer matches).
pub const SETUP_VERSION: u32 = 3;
/// Records below this version were made by a program that gave a private runner read access to the whole project (round 2); only
/// they need that removal. A later bump of `SETUP_VERSION` must not run it again (G5 sixth round, NV5-I1).
const LEGACY_ACL_VERSION: u32 = 3;
fn needs_legacy_acl_removal(record_version: u32) -> bool {
    record_version < LEGACY_ACL_VERSION
}

#[derive(Debug, Default, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct State {
    /// What the declaration asked for, as a digest; the launcher compares it before every run.
    pub digest: String,
    pub dir: String,
    #[serde(default)]
    pub writable: Vec<String>,
    /// Every runner user granted access to the folder: the project's own, and one per command that receives a secret.
    #[serde(default)]
    pub runners: Vec<String>,
    /// The root-owned copies this setup made (tools and browsers, named by content) and a stat fingerprint of each, so the
    /// launcher can see a copy that is not what setup left without hashing hundreds of megabytes before every run.
    #[serde(default)]
    pub copies: BTreeMap<String, String>,
    /// A digest of the whole stored declaration this setup was made for: when it changes, every process of the project's runner users
    /// is stopped before the new declaration is applied (a process started under the old one must not outlive it with the same uid).
    #[serde(default)]
    pub decl: String,
    /// The `SETUP_VERSION` of the program that made this record. A record from an earlier program (0 when it predates the field) is
    /// stopped and migrated once: the round-2 read-only entries of a private user are taken back (G5 fifth round, NV4-L3).
    #[serde(default)]
    pub version: u32,
}

/// The digest of a whole declaration.
pub fn decl_digest(p: &Policy) -> String {
    sha256_hex(p.to_hex().as_bytes())
}

/// The parts of a declaration this setup depends on, as a digest. A change to a command's words, a secret name or an egress rule
/// is not one of them; WHICH commands receive a secret is (each has a user of its own).
pub fn setup_digest(p: &Policy) -> String {
    let bearers: Vec<&String> = p
        .commands
        .iter()
        .filter(|(_, c)| c.bears_secrets())
        .map(|(n, _)| n)
        .collect();
    let v = serde_json::json!({"v": SETUP_VERSION, "dir": p.dir, "writable": p.writable, "tools": p.tools,
        "browsers": p.browsers, "browser_digests": p.browser_digests, "bearers": bearers});
    sha256_hex(v.to_string().as_bytes())
}

fn state_path(paths: &Paths, project: &str) -> PathBuf {
    paths.state.join(format!("{project}.json"))
}

fn read_state(paths: &Paths, project: &str) -> Option<State> {
    serde_json::from_slice(&std::fs::read(state_path(paths, project)).ok()?).ok()
}

/// Whether the machine was set up for exactly this declaration. A record read and a digest compared: nothing is walked per run (G5
/// second review, N-L1). The copies setup made are root-owned and named by their content, so only root could change one, and root is
/// outside the threat model; they are checked once, when they are made (`apply`).
pub fn current(paths: &Paths, project: &str, p: &Policy) -> bool {
    // the setup AND the whole declaration: a change to anything a command is given (a pin, the words, the names it may take, its
    // environments, its egress) is not current, so the launcher asks for `ensure-runner`, which stops what ran under the old one
    read_state(paths, project)
        .is_some_and(|s| s.digest == setup_digest(p) && s.decl == decl_digest(p))
}

fn acl(args: &[&str], path: &Path) -> Vec<String> {
    let mut v: Vec<String> = ["setfacl", "-P"].map(String::from).to_vec();
    v.extend(args.iter().map(|s| s.to_string()));
    v.push(path.display().to_string());
    v
}

/// The `setfacl` calls that give a runner its access, in the order they run. Pure.
pub fn grant_calls(
    paths: &Paths,
    runner: &str,
    dir: &Path,
    writable: &[String],
    has_git: bool,
    private: bool,
) -> Vec<Vec<String>> {
    let mut v = Vec::new();
    let u = format!("u:{runner}");
    // A user that receives a secret runs in a PRIVATE VIEW (`runner::sandbox_props`): the live project is not in its mount namespace,
    // only root-owned copies and the declared writable folders (bound from the live folder, resolved by the service manager, not by
    // this user). So it is granted nothing on the project, nor on the folders above it: only the writable folders (G5 third round,
    // NV-H1: the grant `r-X -R` on a live folder an agent can write to was a read it never needed).
    if private {
        let bu = format!("u:{}", paths.box_user);
        for w in writable {
            let p = dir.join(w);
            v.push(acl(&["-R", "-m", &format!("{u}:rwX")], &p));
            v.push(acl(&["-R", "-d", "-m", &format!("{u}:rwX,{bu}:rwX")], &p));
        }
        return v;
    }
    // search only on the way down: it can walk to the folder, not list a parent
    let mut chain: Vec<PathBuf> = dir
        .ancestors()
        .skip(1)
        .filter(|a| a.starts_with(&paths.work))
        .map(Path::to_path_buf)
        .collect();
    chain.reverse();
    for a in &chain {
        v.push(acl(&["-m", &format!("{u}:--x")], a));
    }
    v.push(acl(&["-R", "-m", &format!("{u}:r-X")], dir));
    v.push(acl(&["-R", "-d", "-m", &format!("{u}:r-X")], dir));
    if has_git {
        let g = dir.join(".git");
        v.push(acl(&["-R", "-x", &u], &g));
        v.push(acl(&["-R", "-d", "-x", &u], &g));
    }
    let bu = format!("u:{}", paths.box_user);
    for w in writable {
        let p = dir.join(w);
        v.push(acl(&["-R", "-m", &format!("{u}:rwX")], &p));
        v.push(acl(&["-R", "-d", "-m", &format!("{u}:rwX,{bu}:rwX")], &p));
    }
    v
}

/// The calls that take a runner's access away again.
pub fn revoke_calls(paths: &Paths, runner: &str, dir: &Path) -> Vec<Vec<String>> {
    let u = format!("u:{runner}");
    let mut v = vec![
        acl(&["-R", "-x", &u], dir),
        acl(&["-R", "-d", "-x", &u], dir),
    ];
    for a in dir
        .ancestors()
        .skip(1)
        .filter(|a| a.starts_with(&paths.work))
    {
        v.push(acl(&["-x", &u], a));
    }
    v
}

/// The declared folder must already be its own real path under /work: no link on the way can point a grant elsewhere.
fn real_dir(paths: &Paths, dir: &str) -> Result<PathBuf, String> {
    let d = Path::new(dir);
    let real =
        std::fs::canonicalize(d).map_err(|_| "the project folder does not exist".to_string())?;
    if real != d || !real.starts_with(&paths.work) || real == paths.work {
        return Err("the declared project folder must be a real folder under /work (a link on the way, or /work itself, is refused)".into());
    }
    Ok(real)
}

// ---- trees: digest and read-only copy -------------------------------------------------------------------------------

#[derive(Debug)]
enum Kind {
    Dir,
    File,
    Link(PathBuf),
}

/// The most entries and bytes one tree may hold: a package, a tool, a browser. Bounded so a hostile tree cannot fill the disk or
/// the launcher's memory.
pub const MAX_TREE_ENTRIES: usize = 60_000;
pub const MAX_TREE_BYTES: u64 = 1 << 30;

fn walk(root: &Path, rel: &Path, out: &mut Vec<(PathBuf, Kind, u32)>) -> Result<(), String> {
    let here = root.join(rel);
    let mut names: Vec<_> = std::fs::read_dir(&here)
        .map_err(|_| format!("cannot read {}", rel.display()))?
        .filter_map(Result::ok)
        .map(|e| e.file_name())
        .collect();
    names.sort();
    for n in names {
        let r = rel.join(&n);
        let md = std::fs::symlink_metadata(root.join(&r))
            .map_err(|_| "cannot read a file".to_string())?;
        let mode = md.permissions().mode();
        if out.len() >= MAX_TREE_ENTRIES {
            return Err(format!(
                "{} holds more than {MAX_TREE_ENTRIES} entries",
                root.display()
            ));
        }
        if md.is_dir() {
            out.push((r.clone(), Kind::Dir, 0));
            walk(root, &r, out)?;
        } else if md.is_symlink() {
            let t =
                std::fs::read_link(root.join(&r)).map_err(|_| "cannot read a link".to_string())?;
            out.push((r, Kind::Link(t), 0));
        } else if md.is_file() {
            out.push((r, Kind::File, mode & 0o111));
        } else {
            return Err(format!(
                "{} is not a plain file, folder or link",
                r.display()
            ));
        }
    }
    Ok(())
}

/// A link may point inside the tree and nowhere else (no absolute target, no way out with `..`).
fn link_stays_inside(rel_of_link: &Path, target: &Path) -> bool {
    if target.is_absolute() {
        return false;
    }
    let mut depth: i64 = rel_of_link
        .parent()
        .map_or(0, |p| p.components().count() as i64);
    for c in target.components() {
        match c {
            Component::ParentDir => depth -= 1,
            Component::Normal(_) => depth += 1,
            _ => {}
        }
        if depth < 0 {
            return false;
        }
    }
    true
}

/// Read a regular file once, never following a link at its last component, in chunks: hash it, and write the same bytes to `to`
/// when given. Returns the SHA-256 (hex) of the bytes read and how many there were.
fn read_hash_copy(path: &Path, to: Option<&Path>) -> Result<(String, u64), String> {
    use std::io::{Read, Write};
    use std::os::unix::fs::OpenOptionsExt;
    let mut f = std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW)
        .open(path)
        .map_err(|_| format!("cannot read {}", path.display()))?;
    let mut out = match to {
        Some(t) => Some(std::fs::File::create(t).map_err(|_| "cannot make the copy".to_string())?),
        None => None,
    };
    let mut ctx = ring::digest::Context::new(&ring::digest::SHA256);
    let mut buf = vec![0u8; 1 << 20];
    let mut total = 0u64;
    loop {
        let n = f
            .read(&mut buf)
            .map_err(|_| format!("cannot read {}", path.display()))?;
        if n == 0 {
            break;
        }
        total += n as u64;
        ctx.update(&buf[..n]);
        if let Some(o) = out.as_mut() {
            o.write_all(&buf[..n])
                .map_err(|_| "cannot make the copy".to_string())?;
        }
    }
    let hex = ctx
        .finish()
        .as_ref()
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect();
    Ok((hex, total))
}

/// Walk `src` ONCE: digest what is there (paths, kinds, whether a file is executable, file bytes, link targets; not owners, times or
/// other mode bits, so the same install digests the same on any box) and, when `dst` is given, write a copy of exactly the bytes
/// that were digested: root-owned, no group or other write, no setuid, links that stay inside the tree. Because the digest and
/// the copy come from the same read, a file swapped while the tree is being read can make them disagree with the source but never
/// with each other.
pub fn tree_scan(src: &Path, dst: Option<&Path>) -> Result<String, String> {
    let mut items = Vec::new();
    walk(src, Path::new(""), &mut items)?;
    if let Some(d) = dst {
        std::fs::create_dir_all(d).map_err(|_| "cannot make the copy".to_string())?;
    }
    let mut ctx = ring::digest::Context::new(&ring::digest::SHA256);
    let mut bytes = 0u64;
    for (rel, kind, exec) in &items {
        ctx.update(rel.to_string_lossy().as_bytes());
        ctx.update(&[0]);
        let to = dst.map(|d| d.join(rel));
        match kind {
            Kind::Dir => {
                ctx.update(b"d");
                if let Some(t) = &to {
                    std::fs::create_dir_all(t).map_err(|_| "cannot make the copy".to_string())?;
                }
            }
            Kind::Link(t) => {
                ctx.update(b"l");
                ctx.update(t.to_string_lossy().as_bytes());
                if let Some(to) = &to {
                    if !link_stays_inside(rel, t) {
                        return Err(format!(
                            "{} is a link that leaves the tool's folder",
                            rel.display()
                        ));
                    }
                    std::os::unix::fs::symlink(t, to)
                        .map_err(|_| "cannot make the copy".to_string())?;
                }
            }
            Kind::File => {
                ctx.update(if *exec != 0 { b"x" } else { b"f" });
                let (h, n) = read_hash_copy(&src.join(rel), to.as_deref())?;
                bytes += n;
                if bytes > MAX_TREE_BYTES {
                    return Err(format!(
                        "{} holds more than {} MiB",
                        src.display(),
                        MAX_TREE_BYTES >> 20
                    ));
                }
                ctx.update(h.as_bytes());
            }
        }
        ctx.update(&[0]);
    }
    if let Some(d) = dst {
        // modes last, deepest first, so a folder is not made unwritable before its content is in it
        for (rel, kind, exec) in items.iter().rev() {
            let to = d.join(rel);
            match kind {
                Kind::Dir => {
                    let _ = std::fs::set_permissions(&to, std::fs::Permissions::from_mode(0o755));
                    make_root_owned(&to);
                }
                Kind::File => {
                    let _ = std::fs::set_permissions(
                        &to,
                        std::fs::Permissions::from_mode(if *exec != 0 { 0o755 } else { 0o644 }),
                    );
                    make_root_owned(&to);
                }
                Kind::Link(_) => make_root_owned(&to),
            }
        }
        let _ = std::fs::set_permissions(d, std::fs::Permissions::from_mode(0o755));
        make_root_owned(d);
    }
    Ok(ctx
        .finish()
        .as_ref()
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect())
}

/// A digest of a tree's content (see [`tree_scan`]).
pub fn tree_digest(root: &Path) -> Result<String, String> {
    tree_scan(root, None)
}

/// A hash of what `stat` says about every entry of a tree (type, size, device, inode, mtime, ctime) and nothing it holds. Cheap
/// (no file is read) and it moves whenever an entry is written, renamed, added or removed; `ctime` cannot be set back by the box
/// user. Used to recognise a tree that has not changed since it was verified.
pub fn tree_fingerprint(root: &Path) -> Result<String, String> {
    use std::os::unix::fs::MetadataExt;
    fn rec(
        dir: &Path,
        rel: &Path,
        ctx: &mut ring::digest::Context,
        n: &mut usize,
    ) -> Result<(), String> {
        let mut names: Vec<_> = std::fs::read_dir(dir)
            .map_err(|_| "cannot read a folder".to_string())?
            .filter_map(Result::ok)
            .map(|e| e.file_name())
            .collect();
        names.sort();
        for name in names {
            let p = dir.join(&name);
            let md = std::fs::symlink_metadata(&p).map_err(|_| "cannot read a file".to_string())?;
            *n += 1;
            if *n > MAX_TREE_ENTRIES {
                return Err("too many entries".into());
            }
            let r = rel.join(&name);
            ctx.update(r.to_string_lossy().as_bytes());
            let kind = if md.is_dir() {
                b'd'
            } else if md.is_symlink() {
                b'l'
            } else {
                b'f'
            };
            ctx.update(&[0, kind]);
            for v in [
                md.dev(),
                md.ino(),
                md.size(),
                md.mtime() as u64,
                md.mtime_nsec() as u64,
                md.ctime() as u64,
                md.ctime_nsec() as u64,
            ] {
                ctx.update(&v.to_le_bytes());
            }
            if md.is_dir() {
                rec(&p, &r, ctx, n)?;
            }
        }
        Ok(())
    }
    let rm = std::fs::symlink_metadata(root).map_err(|_| "cannot read a folder".to_string())?;
    let mut ctx = ring::digest::Context::new(&ring::digest::SHA256);
    for v in [
        rm.dev(),
        rm.ino(),
        rm.mtime() as u64,
        rm.ctime() as u64,
        rm.ctime_nsec() as u64,
    ] {
        ctx.update(&v.to_le_bytes());
    }
    let mut n = 0;
    rec(root, Path::new(""), &mut ctx, &mut n)?;
    Ok(ctx
        .finish()
        .as_ref()
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect())
}

/// Whether this process runs as root: the owner of `/proc/self` is its effective user. (No `unsafe`; off Linux it is false.)
pub fn is_root() -> bool {
    use std::os::unix::fs::MetadataExt;
    std::fs::metadata("/proc/self").is_ok_and(|m| m.uid() == 0)
}

pub(crate) fn make_root_owned(path: &Path) {
    // only root can: a test runs as someone else and checks the modes, not the owner
    if is_root() {
        let _ = std::os::unix::fs::lchown(path, Some(0), Some(0));
    }
}

/// Put a verified copy of `src` at `dst`, once: read ONCE into a copy made next to it (so what was digested is what was written),
/// checked against `approved` when the declaration named a digest, hashed again as written, then moved into place. `dst` is
/// named by content by the callers, so an existing one is already the answer and is left alone.
pub fn publish_tree(src: &Path, dst: &Path, approved: Option<&str>) -> Result<String, String> {
    let staging = dst.with_extension("new");
    let _ = std::fs::remove_dir_all(&staging);
    let want = match tree_scan(src, Some(&staging)) {
        Ok(w) => w,
        Err(e) => {
            let _ = std::fs::remove_dir_all(&staging);
            return Err(e);
        }
    };
    if let Some(a) = approved {
        if a != want {
            let _ = std::fs::remove_dir_all(&staging);
            return Err(format!(
                "the installed copy is not the one the declaration approved (approved {}, found {}): nothing was exposed",
                &a[..12.min(a.len())],
                &want[..12]
            ));
        }
    }
    let got = tree_digest(&staging)?;
    if got != want {
        let _ = std::fs::remove_dir_all(&staging);
        return Err("the source changed while it was being copied; nothing was exposed".into());
    }
    if dst.exists() {
        // already there under its own content name: that IS this tree
        let _ = std::fs::remove_dir_all(&staging);
        return Ok(got);
    }
    if let Some(parent) = dst.parent() {
        std::fs::create_dir_all(parent).map_err(|_| "cannot make the copies folder".to_string())?;
        let _ = std::fs::set_permissions(parent, std::fs::Permissions::from_mode(0o755));
        make_root_owned(parent);
    }
    std::fs::rename(&staging, dst).map_err(|_| "cannot put the copy in place".to_string())?;
    Ok(got)
}

// ---- tools and browsers ---------------------------------------------------------------------------------------------

/// What a catalog tool installs as, if it is something a runner can be given: its folder under `.local/opt` and its programs.
fn release_of(
    catalog: &ozbox_catalog::Catalog,
    name: &str,
) -> Result<Option<Vec<(String, String)>>, String> {
    let tool = catalog
        .tools
        .iter()
        .find(|t| t.id == name)
        .ok_or_else(|| format!("{name} is not a tool in the catalog"))?;
    let mut bins = Vec::new();
    let mut system = false;
    for d in &tool.install {
        match &d.step {
            ozbox_catalog::Step::Release { bins: b, .. } => {
                bins.extend(b.iter().map(|x| (x.name.clone(), x.path.clone())));
            }
            ozbox_catalog::Step::AptInstall { .. } | ozbox_catalog::Step::AptRepo { .. } => system = true,
            _ => {
                return Err(format!(
                    "{name} installs into the box user's own home by a package manager, which a runner cannot be given safely; use a tool that is a vendor release or a system package"
                ))
            }
        }
    }
    if bins.is_empty() && system {
        return Ok(None); // a system package: already on every PATH
    }
    if bins.is_empty() {
        return Err(format!("{name} has nothing a runner could be given"));
    }
    Ok(Some(bins))
}

/// The digest of what the box user has installed for a tool, for the owner to pin (`ozbox env policy pin --tool`).
pub fn installed_tool_digest(
    paths: &Paths,
    catalog: &ozbox_catalog::Catalog,
    name: &str,
) -> Result<String, String> {
    if release_of(catalog, name)?.is_none() {
        return Err(format!(
            "{name} is a system package: it needs no digest and no entry in a declaration"
        ));
    }
    let src = paths.box_home.join(".local/opt").join(name);
    if !src.is_dir() {
        return Err(format!(
            "{name} is not installed on this box: install it from the tool catalog first"
        ));
    }
    tree_digest(&src)
}

/// Where a tool's verified copy lives: named by the digest of its content, so one project's setup can never change what another
/// project's command runs (the copy is not replaced, a different install is a different folder).
fn tool_store(paths: &Paths, digest: &str) -> PathBuf {
    paths.tools.join("store").join(digest)
}

/// One tool's root-owned copy and the links in this project's own `bin`. Returns the digest of what was exposed (None for a system
/// package). `approved` is the digest the declaration named: the copy is made from the SAME read that is checked against it, so
/// what is exposed is exactly what was approved. A tool with no digest is refused when `must_pin` (the project has a command
/// that receives a secret): setup is run by an ungated helper an agent can ask, and it would otherwise copy whatever the box
/// user has put where the tool should be.
pub fn expose_tool(
    paths: &Paths,
    catalog: &ozbox_catalog::Catalog,
    project: &str,
    name: &str,
    approved: Option<&str>,
    must_pin: bool,
) -> Result<Option<String>, String> {
    let Some(bins) = release_of(catalog, name)? else {
        if approved.is_some() {
            return Err(format!(
                "{name} is a system package and cannot be pinned: leave it out of the declaration"
            ));
        }
        return Ok(None);
    };
    if must_pin && approved.is_none() {
        return Err(format!("the tool {name} has no digest, and this project has a command that receives a secret: it is not copied"));
    }
    let src = paths.box_home.join(".local/opt").join(name);
    if !src.is_dir() {
        return Err(format!(
            "{name} is not installed on this box: install it from the tool catalog first"
        ));
    }
    // the digest of the tree as it is read now, before anything is put in place; a pinned tool that is not the approved one stops
    // here, and a copy named by its content already in place is simply used
    std::fs::create_dir_all(paths.tools.join("store"))
        .map_err(|_| "cannot make the tools folder".to_string())?;
    let _ = std::fs::set_permissions(&paths.tools, std::fs::Permissions::from_mode(0o755));
    make_root_owned(&paths.tools);
    let digest = match approved {
        Some(a) if tool_store(paths, a).is_dir() && tree_digest(&src).is_ok_and(|d| d == a) => {
            a.to_string()
        }
        _ => {
            // read once into a staging copy, compare, then name it by what was read
            let stage = paths
                .tools
                .join("store")
                .join(format!(".stage-{}", std::process::id()));
            let _ = std::fs::remove_dir_all(&stage);
            let want = tree_scan(&src, Some(&stage)).inspect_err(|_| {
                let _ = std::fs::remove_dir_all(&stage);
            })?;
            if let Some(a) = approved {
                if a != want {
                    let _ = std::fs::remove_dir_all(&stage);
                    return Err(format!(
                        "the installed {name} is not the one the declaration approved (approved {}, found {}): nothing was exposed",
                        &a[..12.min(a.len())],
                        &want[..12]
                    ));
                }
            }
            if tree_digest(&stage)? != want {
                let _ = std::fs::remove_dir_all(&stage);
                return Err(
                    "the source changed while it was being copied; nothing was exposed".into(),
                );
            }
            let dst = tool_store(paths, &want);
            if dst.exists() {
                let _ = std::fs::remove_dir_all(&stage);
            } else {
                std::fs::rename(&stage, &dst)
                    .map_err(|_| "cannot put the copy in place".to_string())?;
            }
            want
        }
    };
    let dst = tool_store(paths, &digest);
    let bin_dir = paths.tools.join("bin").join(project);
    std::fs::create_dir_all(&bin_dir).map_err(|_| "cannot make the tools folder".to_string())?;
    let _ = std::fs::set_permissions(&bin_dir, std::fs::Permissions::from_mode(0o755));
    make_root_owned(&paths.tools.join("bin"));
    make_root_owned(&bin_dir);
    for (bin, path) in &bins {
        if !dst.join(path).exists() {
            return Err(format!("{bin} is not in the installed {name}"));
        }
        let link = bin_dir.join(bin);
        let _ = std::fs::remove_file(&link);
        std::os::unix::fs::symlink(format!("../../store/{digest}/{path}"), &link)
            .map_err(|_| "cannot link a program".to_string())?;
        make_root_owned(&link);
    }
    Ok(Some(digest))
}

/// The digests of Playwright's installed browser directories for the browsers asked for, for the owner to pin
/// (`ozbox env policy pin --browser chromium`): `chromium-1169` and so on.
pub fn installed_browser_digests(
    paths: &Paths,
    browsers: &[String],
) -> Result<BTreeMap<String, String>, String> {
    browser_digests_in(&paths.box_home.join(".cache/ms-playwright"), browsers)
}

/// The digest of each wanted revision in a Playwright cache folder.
pub fn browser_digests_in(
    cache: &Path,
    browsers: &[String],
) -> Result<BTreeMap<String, String>, String> {
    if !cache.is_dir() {
        return Err("no browsers are installed for the box user yet: install the Playwright browsers from the tool catalog first".into());
    }
    let wanted = wanted_kinds(browsers);
    let mut out = BTreeMap::new();
    for e in std::fs::read_dir(cache)
        .map_err(|_| "cannot read the browser cache".to_string())?
        .flatten()
    {
        let name = e.file_name().to_string_lossy().to_string();
        if !crate::workload_policy::browser_dir_ok(&name) || !e.path().is_dir() {
            continue;
        }
        let kind = name.rsplit_once('-').map_or("", |(k, _)| k);
        if wanted.contains(kind) {
            out.insert(name, tree_digest(&e.path())?);
        }
    }
    Ok(out)
}

fn wanted_kinds(browsers: &[String]) -> BTreeSet<&'static str> {
    // one table, in the policy module (G5 fifth round)
    browsers
        .iter()
        .flat_map(|b| crate::workload_policy::implied_kinds(b))
        .collect()
}

/// Playwright's cache directories for the browsers asked for. A directory is copied ONLY when the declaration approved its
/// digest, into a folder named by that digest, and the project's own folder holds a link per revision (`chromium-1169`), so
/// another project's setup cannot change what this one runs. A directory with no approved digest, or a different one, is not
/// copied: the box user's cache can hold anything, and this is run by an ungated helper. Returns the copies made and their paths.
pub fn expose_browsers(
    paths: &Paths,
    project: &str,
    browsers: &[String],
    digests: &BTreeMap<String, String>,
) -> Result<(usize, Vec<PathBuf>), String> {
    let cache = paths.box_home.join(".cache/ms-playwright");
    if !cache.is_dir() {
        return Err("no browsers are installed for the box user yet: install the Playwright browsers from the tool catalog first".into());
    }
    let wanted = wanted_kinds(browsers);
    // a kind the declaration implies but has no approved digest for is refused here, by name, and never skipped: the browser would
    // fail to start at run time with no word of why (G5 fourth round, NV3-L4)
    for kind in &wanted {
        if !digests.keys().any(|d| d.starts_with(&format!("{kind}-"))) {
            return Err(format!("the declaration approves no digest for {kind}: the browsers it names need one for each of their folders"));
        }
    }
    std::fs::create_dir_all(paths.browsers.join("store"))
        .map_err(|_| "cannot make the browsers folder".to_string())?;
    let _ = std::fs::set_permissions(&paths.browsers, std::fs::Permissions::from_mode(0o755));
    make_root_owned(&paths.browsers);
    let proj = paths.browsers.join(project);
    let _ = std::fs::remove_dir_all(&proj);
    std::fs::create_dir_all(&proj).map_err(|_| "cannot make the browsers folder".to_string())?;
    let _ = std::fs::set_permissions(&proj, std::fs::Permissions::from_mode(0o755));
    make_root_owned(&proj);
    let mut copied = 0;
    let mut stores = Vec::new();
    let mut found = BTreeSet::new();
    let mut refused: Vec<String> = Vec::new();
    for e in std::fs::read_dir(&cache)
        .map_err(|_| "cannot read the browser cache".to_string())?
        .flatten()
    {
        let name = e.file_name().to_string_lossy().to_string();
        if !crate::workload_policy::browser_dir_ok(&name) || !e.path().is_dir() {
            continue;
        }
        let kind = name.rsplit_once('-').map_or("", |(k, _)| k);
        if !wanted.contains(kind) {
            continue;
        }
        let Some(approved) = digests.get(&name) else {
            continue;
        };
        let dst = paths.browsers.join("store").join(approved);
        let fresh = !dst.is_dir();
        match publish_tree(&e.path(), &dst, Some(approved)) {
            Ok(_) => {}
            Err(why) => {
                refused.push(format!("{name}: {why}"));
                continue;
            }
        }
        if fresh {
            copied += 1;
        }
        let link = proj.join(&name);
        std::os::unix::fs::symlink(format!("../store/{approved}"), &link)
            .map_err(|_| "cannot link a browser".to_string())?;
        make_root_owned(&link);
        stores.push(dst);
        // only the browser itself counts as the browser being there (not its headless shell or ffmpeg)
        if matches!(kind, "chromium" | "firefox" | "webkit") {
            found.insert(kind.to_string());
        }
    }
    for b in browsers {
        if !found.contains(b.as_str()) {
            let why = if refused.is_empty() {
                "no installed revision matches an approved digest: install it from the tool catalog, then `ozbox env policy pin --browser`".to_string()
            } else {
                refused.join("; ")
            };
            return Err(format!("{b} was not exposed: {why}"));
        }
    }
    Ok((copied, stores))
}

// ---- runner users -------------------------------------------------------------------------------------------------------

/// Make a command's runner user if it is not there: no login, no group of the box user's, a home of its own the user alone can
/// enter. (The project's own runner is made by the root helper; the users of commands that receive a secret are made here, from
/// the stored declaration, so no name comes from a request.)
fn ensure_user(acl: &dyn Acl, paths: &Paths, user: &str, owner: &str) -> Result<(), String> {
    let home = format!("{RUN_HOME}/{user}");
    // Who each user was made for. Written BEFORE the user is made, so a crash leaves a registered name, never a user nobody knows:
    // an existing user that this registry does not list for exactly this project and command is refused, never reused (a name that
    // collides, or an account made by something else, would put another command's code on this command's uid).
    let reg_path = paths.state.join("users.json");
    let mut reg = read_registry(paths)?;
    let exists = |a: &dyn Acl| {
        a.run(&["id".to_string(), "-u".to_string(), user.to_string()])
            .is_ok()
    };
    match reg.get(user) {
        Some(o) if o != owner => {
            return Err(format!(
                "the runner user {user} was made for another command: it is not reused"
            ));
        }
        Some(_) => {}
        None => {
            if exists(acl) {
                return Err(format!("a user named {user} already exists and was not made by runner setup for this command: it is not reused"));
            }
            reg.insert(user.to_string(), owner.to_string());
            std::fs::create_dir_all(&paths.state)
                .map_err(|_| "cannot write the setup record".to_string())?;
            let _ = std::fs::set_permissions(&paths.state, std::fs::Permissions::from_mode(0o700));
            write_atomic(&reg_path, &serde_json::to_vec(&reg).unwrap_or_default())?;
        }
    }
    if !exists(acl) {
        let args: Vec<String> = [
            "useradd",
            "--system",
            "--user-group",
            "--no-create-home",
            "--home-dir",
            &home,
            "--shell",
            "/usr/sbin/nologin",
            "--comment",
            "Oz Box runner",
            user,
        ]
        .map(String::from)
        .to_vec();
        acl.run(&args)
            .map_err(|_| format!("the runner user {user} could not be made"))?;
    }
    let args: Vec<String> = ["install", "-d", "-m", "0700", "-o", user, "-g", user, &home]
        .map(String::from)
        .to_vec();
    acl.run(&args)
        .map_err(|_| format!("the home of {user} could not be made"))
}

// ---- the whole setup ---------------------------------------------------------------------------------------------------

#[derive(Debug, Default, PartialEq, Eq)]
pub struct Summary {
    pub granted: bool,
    pub revoked: bool,
    /// Tool name and the digest of what was exposed, for the owner to pin.
    pub tools: Vec<(String, Option<String>)>,
    pub browsers_copied: usize,
    /// Runner users set up, by name: the project's, then one per command that receives a secret.
    pub runners: Vec<String>,
}

/// How many passes of "kill what is left" a stop makes before it gives up: a process that forks as fast as it is killed does not
/// outlive 50 passes of a kill that takes a few milliseconds, and a stop that cannot finish is a refusal, never a quiet success.
const STOP_PASSES: usize = 50;

/// Stop everything the project's runner users run: its run units by name first (a unit's whole cgroup is killed, so a process that
/// forks inside it goes with it), then every process still owned by one of the users, again and again until there is none (G5 third
/// round, N-M2). `systemctl` and `pkill` answer "nothing there" with a failure, which is the end of the loop and not an error.
fn stop_everything_of(acl_runner: &dyn Acl, project: &str, users: &[String]) -> Result<(), String> {
    // What is stopped, and in which order: **the services, then their routes** (a route's ports are let go only once the last
    // process that could use them is dead, E4). A run unit is `ozbox-run-<project>-<16 hex characters>` (the exact length keeps `app`
    // from matching a project named `app-two`); a service is `ozbox-svc-<project>_<command>`, and a project name has no `_`, so
    // that glob reaches this project's services and no other's. A service an earlier release started under its hyphen name
    // (`ozbox-svc-<project>-<command>`) cannot be globbed without reaching another project's, so it is stopped through its user
    // below, which every service has. A service's proxy and socket are units of their own, run as a user systemd makes (not one of
    // `users`), so `pkill -u` never finds them: they are stopped by name, last. The proxy first, then its socket (which holds the
    // ports).
    let services = [
        format!("ozbox-run-{project}-????????????????.service"),
        format!("ozbox-svc-{project}_*.service"),
    ];
    let routes = [
        format!("{}{project}_*.service", crate::runner_egress::UNIT_PREFIX),
        format!("{}{project}_*.socket", crate::runner_egress::UNIT_PREFIX),
    ];
    let s = |v: &[&str]| v.iter().map(|x| x.to_string()).collect::<Vec<_>>();
    for u in &services {
        let _ = acl_runner.run(&s(&[
            "systemctl",
            "kill",
            "--signal=KILL",
            "--kill-whom=all",
            u,
        ]));
        let _ = acl_runner.run(&s(&["systemctl", "stop", "--no-block", u]));
    }
    for u in users {
        let mut left = true;
        for pass in 0..STOP_PASSES {
            // 0: it found and killed something, so look again (it may have forked first, or still be a zombie that matches); 1: nothing
            // of the user is left; anything else (2, 3, no `pkill`) is "could not look", which is never "nothing left"
            match acl_runner.run_code(&s(&["pkill", "-KILL", "-u", u])) {
                Ok(1) => {
                    left = false;
                    break;
                }
                Ok(0) => std::thread::sleep(stop_pause(pass)),
                _ => {
                    return Err(format!("the processes of {u} could not be looked for: the declaration was not applied"));
                }
            }
        }
        if left {
            return Err(format!(
                "the processes of {u} could not all be stopped: the declaration was not applied"
            ));
        }
    }
    // a launch that was already starting a unit when the pass above ran
    std::thread::sleep(stop_pause(STOP_PASSES));
    for u in &services {
        let _ = acl_runner.run(&s(&[
            "systemctl",
            "kill",
            "--signal=KILL",
            "--kill-whom=all",
            u,
        ]));
    }
    // every process of every service is dead: only now are the routes let go (waiting for each, so none outlives this setup)
    for u in &routes {
        let _ = acl_runner.run(&s(&["systemctl", "stop", u]));
    }
    Ok(())
}

/// The wait between two passes of the stop loop: a process that was just killed needs a moment to be reaped (a zombie still matches),
/// so the passes back off, 20 ms to 250 ms. None in a test.
fn stop_pause(pass: usize) -> std::time::Duration {
    if cfg!(test) {
        return std::time::Duration::ZERO;
    }
    std::time::Duration::from_millis((20 * (pass as u64 + 1)).min(250))
}

/// One lock for the box's launcher and setup (G5 fourth round, NV3-L5): setup holds it for its whole run, and a launch holds it
/// shared from the moment it reads "set up for this declaration" until its unit has been handed to `systemd-run`, so a launch that
/// read the old declaration cannot start a unit after setup's last kill. `None` when the state folder does not exist yet (no setup,
/// so nothing to race).
pub fn lock_file(paths: &Paths, exclusive: bool) -> Result<Option<std::fs::File>, String> {
    let f = match std::fs::OpenOptions::new()
        .create(true)
        .truncate(false)
        .write(true)
        .read(true)
        .open(paths.state.join(".launch.lock"))
    {
        Ok(f) => f,
        // no state folder yet: no setup has ever run, so there is nothing to race
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(_) => return Err("the setup lock could not be opened".to_string()),
    };
    #[cfg(target_os = "linux")]
    {
        use rustix::fs::{flock, FlockOperation};
        let op = if exclusive {
            FlockOperation::LockExclusive
        } else {
            FlockOperation::LockShared
        };
        // an interrupted wait is retried; any other failure is a refusal, never "no lock" (G5 sixth round, NV5-L1)
        loop {
            match flock(&f, op) {
                Ok(()) => break,
                Err(rustix::io::Errno::INTR) => continue,
                Err(_) => return Err("the setup lock could not be taken".to_string()),
            }
        }
    }
    #[cfg(not(target_os = "linux"))]
    let _ = exclusive;
    Ok(Some(f))
}

/// Write a file so that a crash leaves the old bytes or the new ones, never a name with none: a temporary file, synced, renamed into
/// place, and the folder synced (G5 fifth round, NV4-L1). Mode 0600, owned by root when this runs as root.
fn write_atomic(path: &Path, bytes: &[u8]) -> Result<(), String> {
    use std::io::Write;
    let fail = |_| "cannot write the setup record".to_string();
    let tmp = path.with_extension("json.tmp");
    let _ = std::fs::remove_file(&tmp);
    let mut f = std::fs::OpenOptions::new()
        .create_new(true)
        .write(true)
        .mode_600()
        .open(&tmp)
        .map_err(fail)?;
    f.write_all(bytes).map_err(fail)?;
    f.sync_all().map_err(fail)?;
    drop(f);
    make_root_owned(&tmp);
    std::fs::rename(&tmp, path).map_err(fail)?;
    if let Some(dir) = path.parent() {
        std::fs::File::open(dir)
            .and_then(|d| d.sync_all())
            .map_err(fail)?;
    }
    Ok(())
}

trait Mode600 {
    fn mode_600(&mut self) -> &mut Self;
}
impl Mode600 for std::fs::OpenOptions {
    fn mode_600(&mut self) -> &mut Self {
        use std::os::unix::fs::OpenOptionsExt;
        self.mode(0o600)
    }
}

/// The runner users the registry names for this project's commands: the stop uses them when no record says which users there were.
/// The registry of runner users. A file that does not exist is an empty registry; one that exists and cannot be read or parsed is an
/// error, never "empty": the stop and the reuse check both depend on it (G5 sixth round, NV5-L2).
fn read_registry(paths: &Paths) -> Result<BTreeMap<String, String>, String> {
    match std::fs::read(paths.state.join("users.json")) {
        Ok(b) => serde_json::from_slice(&b).map_err(|_| {
            "the runner user registry cannot be read: nothing was applied".to_string()
        }),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(BTreeMap::new()),
        Err(_) => Err("the runner user registry cannot be read: nothing was applied".to_string()),
    }
}

/// The runner users the registry names for this project's commands: the stop uses them when no record says which users there were.
fn registered_users(paths: &Paths, project: &str) -> Result<Vec<String>, String> {
    let prefix = format!("{project}\0");
    Ok(read_registry(paths)?
        .into_iter()
        .filter(|(_, owner)| owner.starts_with(&prefix))
        .map(|(u, _)| u)
        .collect())
}

fn pending_path(paths: &Paths, project: &str) -> PathBuf {
    paths.state.join(format!("{project}.stop-pending.json"))
}

/// Set the machine up for the stored declaration, or take it all back when there is none.
pub fn apply(
    paths: &Paths,
    acl_runner: &dyn Acl,
    catalog: &ozbox_catalog::Catalog,
    project: &str,
    policy: Option<&Policy>,
) -> Result<Summary, String> {
    std::fs::create_dir_all(&paths.state)
        .map_err(|_| "cannot write the setup record".to_string())?;
    let _ = std::fs::set_permissions(&paths.state, std::fs::Permissions::from_mode(0o700));
    make_root_owned(&paths.state);
    // setup and the launcher never overlap (see `lock_file`)
    let _guard = lock_file(paths, true)?;
    // A stop that did not finish is remembered until one does (G5 fourth round, NV3-M1): the record of the setup being replaced is
    // kept in a "stop pending" file, which is removed only when this setup has gone through, so a refused stop, or any failure before
    // the end, makes the next `apply` stop and revoke again, whatever declaration it is then given. The marker is written on EVERY
    // apply that finds a record, not only when the declaration changed (a re-run of the same declaration that fails would otherwise
    // lose the stop, NV4-M2), and a marker or a record that exists but cannot be read counts as "stop pending", never as none (NV4-L1).
    let (pending, marker_broken) = match std::fs::read(pending_path(paths, project)) {
        Ok(b) => match serde_json::from_slice::<State>(&b) {
            Ok(s) => (Some(s), false),
            Err(_) => (None, true),
        },
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => (None, false),
        Err(_) => (None, true),
    };
    let recorded = read_state(paths, project);
    let record_broken = recorded.is_none() && state_path(paths, project).exists();
    let marker_present = pending.is_some() || marker_broken;
    if !marker_present {
        if let Some(r) = &recorded {
            write_atomic(
                &pending_path(paths, project),
                &serde_json::to_vec(r).unwrap_or_default(),
            )?;
        } else if record_broken {
            // nothing readable to remember: the empty record says "stop what the registry names"
            write_atomic(
                &pending_path(paths, project),
                &serde_json::to_vec(&State::default()).unwrap_or_default(),
            )?;
        }
    }
    // what is stopped and revoked: the record being replaced and, if one is left over from a failed run, the one before it
    let olds: Vec<&State> = recorded.iter().chain(pending.iter()).collect();
    let old = recorded.clone().or(pending.clone());
    let decl_changed = match (&old, policy) {
        (Some(o), Some(p)) => o.decl != decl_digest(p),
        (Some(_), None) => true,
        _ => false,
    };
    let stale_version = olds.iter().any(|o| o.version < SETUP_VERSION);
    let stop_needed = decl_changed || marker_present || record_broken || stale_version;
    // a setup that fails part way is not a setup: the record goes first, and is written again only when everything is in place
    let _ = std::fs::remove_file(state_path(paths, project));
    let done = || {
        let _ = std::fs::remove_file(pending_path(paths, project));
    };
    let mut sum = Summary::default();
    let wanted: Vec<String> = policy.map(|p| runner_users(project, p)).unwrap_or_default();
    // what an earlier declaration granted and this one does not (a removed declaration, a moved folder, a command that no longer
    // receives a secret)
    for o in &olds {
        let same_dir = policy.is_some_and(|p| p.dir == o.dir);
        if !o.dir.is_empty() {
            let old_runners: Vec<String> = if o.runners.is_empty() {
                vec![runner_user(project)]
            } else {
                o.runners.clone()
            };
            for r in old_runners
                .iter()
                .filter(|r| !same_dir || !wanted.contains(r))
            {
                for c in revoke_calls(paths, r, Path::new(&o.dir)) {
                    // the folder may be gone, or an entry already removed: a refusal here is not a failure to set up
                    let _ = acl_runner.run(&c);
                }
                sum.revoked = true;
            }
        }
    }
    // what ran under the old declaration, or under one whose stop was refused, is stopped before the new one is applied: it must
    // not outlive it with the same uid. This also runs before any ACL is taken off or granted, under the exclusive lock, so no unit
    // of the old setup is running while its entries are changed.
    if stop_needed {
        let mut users: Vec<String> = olds
            .iter()
            .flat_map(|o| o.runners.iter().cloned())
            .collect();
        users.extend(wanted.iter().cloned());
        users.push(runner_user(project));
        // an unreadable registry does not skip the stop: the users known from the records and the project are stopped first, and the
        // setup refuses afterwards (G5 seventh round, NV6-L2)
        let registry = registered_users(paths, project);
        if let Ok(r) = &registry {
            users.extend(r.iter().cloned());
        }
        users.sort();
        users.dedup();
        stop_everything_of(acl_runner, project, &users)?;
        // the staged secrets of a start the launcher never cleared (killed between staging and clearing): its services are stopped
        // now, so none of this project's folders is in use. (A project named `app-two` shares the prefix `app-`: a start of it that is
        // in flight right now would fail and be started again, which is the price of not parsing a unit name.)
        crate::runner::sweep_credentials_in(
            std::path::Path::new(crate::runner::CRED_ROOT),
            Some(project),
            crate::runner::CRED_STALE_SECS,
        );
        // a runner's home outlives its processes: a file an older approved declaration left there stays on Node's lookup path
        // (`$HOME/.node_modules`), so it is emptied, and a home that cannot be emptied refuses the setup (NV3-L3, NV4-L2)
        for u in users.iter().filter(|u| u.starts_with("ozrc-")) {
            acl_runner
                .run(&[
                    "rm".into(),
                    "-rf".into(),
                    "--one-file-system".into(),
                    "--".into(),
                    format!("{RUN_HOME}/{u}"),
                ])
                .map_err(|_| {
                    format!("the home of {u} could not be emptied: the declaration was not applied")
                })?;
        }
        registry.map_err(|e| {
            format!(
                "{e}. What the records and the project name was stopped. `users.json` in the setup state folder is shared by EVERY project on \
                 this box. To recover: repair it, or delete it AND remove every `ozrc-` user on the box (`getent passwd | grep '^ozrc-'`, then \
                 `userdel` each one, and the runner records of each project name the same users), then run setup again for each project. \
                 Deleting it affects all projects: `ensure_user` refuses every existing `ozrc-` user until its record is back or the user is removed"
            )
        })?;
    }
    let Some(p) = policy else {
        let _ = std::fs::remove_file(state_path(paths, project));
        done();
        return Ok(sum);
    };
    let dir = real_dir(paths, &p.dir)?;
    let has_git = dir.join(".git").exists();
    for (name, c) in p.commands.iter().filter(|(_, c)| c.bears_secrets()) {
        let u = crate::runner::secret_runner_user(project, name);
        let _ = c;
        ensure_user(acl_runner, paths, &u, &format!("{project}\0{name}"))?;
    }
    for u in &wanted {
        // an upgraded box: the earlier round gave a private user read access to the whole project; take every entry back before the
        // writable folders are granted again (G5 fourth round, NV3-L6)
        if u != &runner_user(project)
            && olds
                .iter()
                .any(|o| needs_legacy_acl_removal(o.version) && o.runners.contains(u))
        {
            for c in legacy_private_acl_removal(paths, u, &dir) {
                let _ = acl_runner.run(&c);
            }
        }
        for c in grant_calls(
            paths,
            u,
            &dir,
            &p.writable,
            has_git,
            u != &runner_user(project),
        ) {
            acl_runner.run(&c)?;
        }
    }
    sum.granted = true;
    sum.runners = wanted.clone();
    let must_pin = p.commands.values().any(|c| c.bears_secrets());
    let mut copies: BTreeMap<String, String> = BTreeMap::new();
    let _ = std::fs::remove_dir_all(paths.tools.join("bin").join(project));
    for t in &p.tools {
        let d = expose_tool(
            paths,
            catalog,
            project,
            &t.name,
            t.sha256.as_deref(),
            must_pin,
        )?;
        if let Some(d) = &d {
            let store = tool_store(paths, d);
            copies.insert(store.display().to_string(), tree_fingerprint(&store)?);
        }
        sum.tools.push((t.name.clone(), d));
    }
    if !p.browsers.is_empty() {
        let (n, stores) = expose_browsers(paths, project, &p.browsers, &p.browser_digests)?;
        sum.browsers_copied = n;
        for s in stores {
            copies.insert(s.display().to_string(), tree_fingerprint(&s)?);
        }
    }
    std::fs::create_dir_all(&paths.state)
        .map_err(|_| "cannot write the setup record".to_string())?;
    let _ = std::fs::set_permissions(&paths.state, std::fs::Permissions::from_mode(0o700));
    make_root_owned(&paths.state);
    let st = State {
        digest: setup_digest(p),
        dir: p.dir.clone(),
        writable: p.writable.clone(),
        runners: wanted,
        copies,
        decl: decl_digest(p),
        version: SETUP_VERSION,
    };
    write_atomic(
        &state_path(paths, project),
        &serde_json::to_vec(&st).unwrap_or_default(),
    )?;
    done();
    Ok(sum)
}

/// The entries an earlier setup gave a private (secret-command) user on the project and the folders above it. Pure.
pub fn legacy_private_acl_removal(paths: &Paths, runner: &str, dir: &Path) -> Vec<Vec<String>> {
    let u = format!("u:{runner}");
    let mut v = vec![
        acl(&["-R", "-x", &u], dir),
        acl(&["-R", "-d", "-x", &u], dir),
    ];
    for a in dir
        .ancestors()
        .skip(1)
        .filter(|a| a.starts_with(&paths.work))
    {
        v.push(acl(&["-x", &u], a));
    }
    v
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use std::cell::RefCell;

    #[derive(Default)]
    struct Rec {
        calls: RefCell<Vec<Vec<String>>>,
        users: RefCell<BTreeSet<String>>,
        /// how many more `pkill` passes find (and kill) a process: one that forks as fast as it is killed
        forks: std::cell::Cell<u32>,
    }
    impl Acl for Rec {
        fn run(&self, argv: &[String]) -> Result<(), String> {
            self.calls.borrow_mut().push(argv.to_vec());
            match argv[0].as_str() {
                "id" => self
                    .users
                    .borrow()
                    .contains(&argv[2])
                    .then_some(())
                    .ok_or_else(|| "no such user".to_string()),
                "useradd" => {
                    self.users.borrow_mut().insert(argv.last().unwrap().clone());
                    Ok(())
                }
                "pkill" if self.forks.get() > 0 => {
                    self.forks.set(self.forks.get() - 1);
                    Ok(())
                }
                // no process of that user: pkill exits 1
                "pkill" => Err("none".to_string()),
                _ => Ok(()),
            }
        }
    }
    impl Rec {
        fn lines(&self) -> Vec<String> {
            self.calls.borrow().iter().map(|c| c.join(" ")).collect()
        }
    }

    fn catalog() -> ozbox_catalog::Catalog {
        ozbox_catalog::embedded().unwrap()
    }

    fn fixture() -> (tempfile::TempDir, Paths) {
        let d = tempfile::tempdir().unwrap();
        let r = std::fs::canonicalize(d.path()).unwrap();
        let paths = Paths {
            box_home: r.join("home"),
            tools: r.join("opt/tools"),
            browsers: r.join("opt/browsers"),
            state: r.join("state"),
            work: r.join("work"),
            box_user: "ozbox".into(),
        };
        std::fs::create_dir_all(paths.work.join("repos/app/.git")).unwrap();
        std::fs::create_dir_all(paths.work.join("repos/app/.next")).unwrap();
        // an installed "node" as the catalog's release step lays it out
        let n = paths.box_home.join(".local/opt/node/bin");
        std::fs::create_dir_all(&n).unwrap();
        for b in ["node", "npm", "npx"] {
            std::fs::write(n.join(b), format!("#!/bin/sh\necho {b}\n")).unwrap();
            std::fs::set_permissions(n.join(b), std::fs::Permissions::from_mode(0o4755)).unwrap();
        }
        (d, paths)
    }

    /// `extra` is top-level JSON (ends with a comma); `cmds` the commands (default: one that receives nothing).
    fn policy_with(paths: &Paths, extra: &str, cmds: &str) -> Policy {
        let mut p = Policy::parse(&format!(
            r#"{{"dir":"/work/repos/app","writable":[".next"],{extra}"commands":{{{cmds}}}}}"#
        ))
        .unwrap();
        p.dir = paths.work.join("repos/app").display().to_string();
        p
    }

    fn policy(paths: &Paths, extra: &str) -> Policy {
        policy_with(paths, extra, r#""a":{"allow":[]}"#)
    }

    #[test]
    fn the_runner_gets_the_declared_folder_and_the_walk_to_it_and_nothing_else() {
        let (_d, paths) = fixture();
        let acl = Rec::default();
        let p = policy(&paths, "");
        let sum = apply(&paths, &acl, &catalog(), "app", Some(&p)).unwrap();
        assert!(sum.granted);
        assert_eq!(
            sum.runners,
            ["ozbox-run-app"],
            "no secret anywhere: the project's own runner only"
        );
        let calls = acl.lines();
        let w = paths.work.display().to_string();
        // never follows a link; the way down is search-only
        assert!(calls.iter().all(|c| c.starts_with("setfacl -P ")));
        assert!(calls.contains(&format!("setfacl -P -m u:ozbox-run-app:--x {w}")));
        assert!(calls.contains(&format!("setfacl -P -m u:ozbox-run-app:--x {w}/repos")));
        assert!(!calls
            .iter()
            .any(|c| c.contains("--x") && c.ends_with("/repos/app")));
        // the folder: read and search, and a default for what is added later; .git is taken out
        assert!(calls.contains(&format!(
            "setfacl -P -R -m u:ozbox-run-app:r-X {w}/repos/app"
        )));
        assert!(calls.contains(&format!(
            "setfacl -P -R -d -m u:ozbox-run-app:r-X {w}/repos/app"
        )));
        assert!(calls.contains(&format!(
            "setfacl -P -R -x u:ozbox-run-app {w}/repos/app/.git"
        )));
        // a writable folder: the runner writes, and what it creates stays the box user's to manage
        assert!(calls.contains(&format!(
            "setfacl -P -R -m u:ozbox-run-app:rwX {w}/repos/app/.next"
        )));
        assert!(calls.contains(&format!(
            "setfacl -P -R -d -m u:ozbox-run-app:rwX,u:ozbox:rwX {w}/repos/app/.next"
        )));
        // nothing names the box's home, a group, or /work/home
        assert!(!calls
            .iter()
            .any(|c| c.contains("/home") || c.contains("g:") || c.contains("chmod")));
        // the machine is now recorded as set up for this declaration, and not for a changed one
        assert!(current(&paths, "app", &p));
        let mut other = p.clone();
        other.writable.push("dist".into());
        assert!(!current(&paths, "app", &other));
        let mut cmds = p.clone();
        cmds.commands.get_mut("a").unwrap().argv = vec!["x".into()];
        assert!(
            !current(&paths, "app", &cmds),
            "a change of a command's words is not current: it stops what ran under the old one"
        );
    }

    /// a command that receives a secret has a user of its own, made from the stored declaration and granted the
    /// folder like the project's runner, so no service, browser or other command shares its uid.
    #[test]
    fn a_command_that_receives_a_secret_gets_a_runner_user_of_its_own_with_its_own_grants() {
        let (_d, paths) = fixture();
        let acl = Rec::default();
        let p = policy_with(
            &paths,
            "",
            r#""mint":{"allow":["K"],"env":["K"]},"mint2":{"allow":["J"],"env":["J"]},"web":{"allow":[]}"#,
        );
        let sum = apply(&paths, &acl, &catalog(), "app", Some(&p)).unwrap();
        assert_eq!(sum.runners.len(), 3);
        let secret_users: Vec<&String> = sum
            .runners
            .iter()
            .filter(|u| u.starts_with("ozrc-"))
            .collect();
        assert_eq!(
            secret_users.len(),
            2,
            "one per secret-receiving command: {:?}",
            sum.runners
        );
        assert_ne!(secret_users[0], secret_users[1]);
        assert!(sum.runners.contains(&"ozbox-run-app".to_string()));
        let calls = acl.lines();
        for u in secret_users {
            assert!(
                u.len() <= 32,
                "a Linux user name is at most 32 characters: {u}"
            );
            // made once, no login, no home made by useradd, a private home
            assert!(
                calls.iter().any(|c| c
                    .starts_with("useradd --system --user-group --no-create-home")
                    && c.ends_with(u.as_str())),
                "{u}"
            );
            assert!(calls
                .iter()
                .any(|c| c == &format!("install -d -m 0700 -o {u} -g {u} {RUN_HOME}/{u}")));
            // G5 third round, NV-H1: this uid runs in a private view and is granted NOTHING on the live project or the folders
            // above it (it only ever sees root-owned copies); it is granted the writable folders and no more
            let w = paths.work.display().to_string();
            let mine: Vec<&String> = calls
                .iter()
                .filter(|c| c.starts_with("setfacl") && c.contains(&format!("u:{u}:")))
                .collect();
            assert!(!mine.is_empty());
            assert!(
                mine.iter()
                    .all(|c| c.contains("rwX") && c.ends_with("/repos/app/.next")),
                "{mine:?}"
            );
            assert!(calls.contains(&format!("setfacl -P -R -m u:{u}:rwX {w}/repos/app/.next")));
            assert!(!calls.iter().any(|c| c.contains(&format!("u:{u}:r-X")) || c.contains(&format!("u:{u}:--x"))), "{calls:?}");
        }
        // the project's own runner is never made here (the root helper makes it)
        assert!(!calls
            .iter()
            .any(|c| c.starts_with("useradd") && c.ends_with("ozbox-run-app")));
        assert!(current(&paths, "app", &p));
        // which commands receive a secret is part of the setup: a command that starts receiving one needs setup again
        let mut more = p.clone();
        more.commands.get_mut("web").unwrap().allow = vec!["X".into()];
        more.commands.get_mut("web").unwrap().env =
            vec![crate::workload_policy::EnvEntry::plain("X")];
        assert!(!current(&paths, "app", &more));
        // a second setup does not make the users again
        acl.calls.borrow_mut().clear();
        apply(&paths, &acl, &catalog(), "app", Some(&p)).unwrap();
        assert!(!acl.lines().iter().any(|c| c.starts_with("useradd")));
        // a command that stops receiving a secret loses its user's access
        let mut fewer = p.clone();
        fewer.commands.get_mut("mint2").unwrap().allow.clear();
        fewer.commands.get_mut("mint2").unwrap().env.clear();
        acl.calls.borrow_mut().clear();
        let sum = apply(&paths, &acl, &catalog(), "app", Some(&fewer)).unwrap();
        assert!(sum.revoked && sum.runners.len() == 2);
        assert!(acl
            .lines()
            .iter()
            .any(|c| c.starts_with("setfacl -P -R -x u:ozrc-")));
    }

    /// The launcher asks this before every run: one small file read and one hash of a few hundred bytes.
    #[test]
    fn the_per_run_setup_check_is_cheap() {
        let (_d, paths) = fixture();
        let p = policy(&paths, "");
        apply(&paths, &Rec::default(), &catalog(), "app", Some(&p)).unwrap();
        let t = std::time::Instant::now();
        for _ in 0..1000 {
            assert!(current(&paths, "app", &p));
        }
        let per = t.elapsed().as_micros() / 1000;
        eprintln!("setup check per run (no copies): {per} us");
        assert!(per < 5_000, "{per} us");
    }

    #[test]
    fn a_folder_that_is_a_link_or_outside_work_is_refused_before_any_grant() {
        let (d, paths) = fixture();
        let acl = Rec::default();
        std::os::unix::fs::symlink(paths.work.join("repos/app"), paths.work.join("repos/alias"))
            .unwrap();
        for bad in [
            paths.work.join("repos/alias"),
            d.path().to_path_buf(),
            paths.work.clone(),
        ] {
            let mut p = policy(&paths, "");
            p.dir = bad.display().to_string();
            assert!(
                apply(&paths, &acl, &catalog(), "app", Some(&p)).is_err(),
                "{}",
                bad.display()
            );
        }
        assert!(acl.calls.borrow().is_empty());
    }

    #[test]
    fn removing_the_declaration_or_moving_the_folder_takes_the_access_back() {
        let (_d, paths) = fixture();
        let acl = Rec::default();
        let p = policy(&paths, "");
        apply(&paths, &acl, &catalog(), "app", Some(&p)).unwrap();
        acl.calls.borrow_mut().clear();
        let sum = apply(&paths, &acl, &catalog(), "app", None).unwrap();
        assert!(sum.revoked);
        let calls = acl.lines();
        let w = paths.work.display().to_string();
        assert!(calls.contains(&format!("setfacl -P -R -x u:ozbox-run-app {w}/repos/app")));
        assert!(calls.contains(&format!(
            "setfacl -P -R -d -x u:ozbox-run-app {w}/repos/app"
        )));
        assert!(calls.contains(&format!("setfacl -P -x u:ozbox-run-app {w}/repos")));
        assert!(!current(&paths, "app", &p), "the record is gone");
        // a move revokes the old folder before granting the new
        apply(&paths, &acl, &catalog(), "app", Some(&p)).unwrap();
        std::fs::create_dir_all(paths.work.join("repos/app2")).unwrap();
        let mut moved = p.clone();
        moved.dir = paths.work.join("repos/app2").display().to_string();
        acl.calls.borrow_mut().clear();
        let sum = apply(&paths, &acl, &catalog(), "app", Some(&moved)).unwrap();
        assert!(sum.revoked && sum.granted);
        let first = acl.calls.borrow()[0].join(" ");
        assert!(
            first.contains("-x") && first.ends_with("/repos/app"),
            "{first}"
        );
    }

    fn node_src(paths: &Paths) -> PathBuf {
        paths.box_home.join(".local/opt/node")
    }

    #[test]
    fn a_tool_is_a_root_owned_copy_named_by_its_content_and_the_declared_digest_is_checked() {
        let (_d, paths) = fixture();
        let acl = Rec::default();
        // a link that leaves the tree is refused
        let src = node_src(&paths);
        std::os::unix::fs::symlink("/etc/passwd", src.join("evil")).unwrap();
        let p = policy(&paths, r#""tools":["node"],"#);
        assert!(apply(&paths, &acl, &catalog(), "app", Some(&p))
            .unwrap_err()
            .contains("leaves"));
        std::fs::remove_file(src.join("evil")).unwrap();
        // the owner's digest of what they approved
        let good = installed_tool_digest(&paths, &catalog(), "node").unwrap();
        let pinned = policy(
            &paths,
            &format!(r#""tools":[{{"name":"node","sha256":"{good}"}}],"#),
        );
        let sum = apply(&paths, &acl, &catalog(), "app", Some(&pinned)).unwrap();
        assert_eq!(sum.tools, vec![("node".to_string(), Some(good.clone()))]);
        let store = paths.tools.join("store").join(&good);
        let copy = store.join("bin/node");
        let mode = std::fs::metadata(&copy).unwrap().permissions().mode();
        assert_eq!(
            mode & 0o7777,
            0o755,
            "no setuid, no group or other write: {mode:o}"
        );
        assert_eq!(
            std::fs::read_link(paths.tools.join("bin/app/npm")).unwrap(),
            PathBuf::from(format!("../../store/{good}/bin/npm")),
            "a link in this project's own bin"
        );
        assert_eq!(
            tree_digest(&store).unwrap(),
            good,
            "a copy digests like its source"
        );
        // the box user changing its own tool afterwards changes nothing a runner runs
        std::fs::write(src.join("bin/node"), "#!/bin/sh\nsteal\n").unwrap();
        assert!(std::fs::read_to_string(&copy)
            .unwrap()
            .contains("echo node"));
        // and a refresh against the approved digest now refuses the changed source, leaving the copy as it was
        let e = apply(&paths, &acl, &catalog(), "app", Some(&pinned)).unwrap_err();
        assert!(e.contains("not the one the declaration approved"), "{e}");
        assert!(std::fs::read_to_string(&copy)
            .unwrap()
            .contains("echo node"));
        assert!(
            std::fs::read_dir(paths.tools.join("store"))
                .unwrap()
                .flatten()
                .all(|e| !e.file_name().to_string_lossy().starts_with(".stage")),
            "a refused copy leaves nothing behind"
        );
    }

    /// `ensure-runner` is ungated, so an agent chooses WHEN the copy is made. With a secret in the project the copy
    /// is only ever of a tool whose digest the declaration approved, and what is copied is checked against that digest.
    #[test]
    fn an_agent_cannot_get_its_own_tool_copied_where_a_secret_command_runs_it() {
        let (_d, paths) = fixture();
        let acl = Rec::default();
        let src = node_src(&paths);
        let good = installed_tool_digest(&paths, &catalog(), "node").unwrap();
        // the agent rewrites node, then asks for ensure-runner: the declaration's digest is the original, so nothing is copied
        std::fs::write(src.join("bin/node"), "#!/bin/sh\ncat /proc/self/environ\n").unwrap();
        let p = policy_with(
            &paths,
            &format!(r#""tools":[{{"name":"node","sha256":"{good}"}}],"#),
            r#""mint":{"allow":["K"],"env":["K"]}"#,
        );
        let e = apply(&paths, &acl, &catalog(), "app", Some(&p)).unwrap_err();
        assert!(e.contains("not the one the declaration approved"), "{e}");
        assert!(
            !paths.tools.join("store").exists()
                || std::fs::read_dir(paths.tools.join("store"))
                    .unwrap()
                    .count()
                    == 0
        );
        assert!(!paths.tools.join("bin/app").exists());
        assert!(
            !current(&paths, "app", &p),
            "no record of a setup that did not happen"
        );
        // an unpinned tool with a secret in the project is refused here even if a declaration somehow carried it
        assert!(expose_tool(&paths, &catalog(), "app", "node", None, true)
            .unwrap_err()
            .contains("receives a secret"));
        // a system package cannot be pinned
        assert!(expose_tool(
            &paths,
            &catalog(),
            "app",
            "jq",
            Some(&"a".repeat(64)),
            false
        )
        .unwrap_err()
        .contains("system package"));
    }

    /// One project's setup cannot change what another's command runs.
    #[test]
    fn two_projects_keep_the_tool_each_was_set_up_with() {
        let (_d, paths) = fixture();
        let acl = Rec::default();
        let p = policy(&paths, r#""tools":["node"],"#);
        apply(&paths, &acl, &catalog(), "app", Some(&p)).unwrap();
        let first = std::fs::read_link(paths.tools.join("bin/app/node")).unwrap();
        std::fs::write(
            node_src(&paths).join("bin/node"),
            "#!/bin/sh\necho second\n",
        )
        .unwrap();
        apply(&paths, &acl, &catalog(), "other", Some(&p)).unwrap();
        let second = std::fs::read_link(paths.tools.join("bin/other/node")).unwrap();
        assert_ne!(first, second, "a different install is a different folder");
        // the first project still resolves to its own, unchanged
        let resolved = paths.tools.join("bin/app").join(&first);
        assert!(std::fs::read_to_string(resolved)
            .unwrap()
            .contains("echo node"));
        assert_eq!(
            std::fs::read_link(paths.tools.join("bin/app/node")).unwrap(),
            first
        );
    }

    #[test]
    fn what_a_runner_cannot_safely_be_given_is_said_so() {
        let (_d, paths) = fixture();
        let acl = Rec::default();
        for (tool, why) in [
            ("codex", "package manager"),
            ("not-a-tool", "not a tool in the catalog"),
        ] {
            let p = policy(&paths, &format!(r#""tools":["{tool}"],"#));
            let e = apply(&paths, &acl, &catalog(), "app", Some(&p)).unwrap_err();
            assert!(e.contains(why), "{tool}: {e}");
        }
        // a system package needs no copy: it is on every PATH already
        let p = policy(&paths, r#""tools":["jq"],"#);
        let sum = apply(&paths, &acl, &catalog(), "app", Some(&p)).unwrap();
        assert_eq!(sum.tools, vec![("jq".to_string(), None)]);
        // a tool that is not installed
        let p = policy(&paths, r#""tools":["kubectl"],"#);
        assert!(apply(&paths, &acl, &catalog(), "app", Some(&p))
            .unwrap_err()
            .contains("not installed"));
    }

    fn plant_browsers(paths: &Paths) -> BTreeMap<String, String> {
        let c = paths.box_home.join(".cache/ms-playwright");
        for d in [
            "chromium-1169",
            "chromium_headless_shell-1169",
            "chromium-1200",
            "ffmpeg-1011",
            "firefox-1488",
            "notes",
        ] {
            std::fs::create_dir_all(c.join(d)).unwrap();
            std::fs::write(c.join(d).join("f"), d).unwrap();
        }
        installed_browser_digests(paths, &["chromium".to_string()]).unwrap()
    }

    /// a browser directory is copied only when its digest was approved; a planted or changed one is not.
    #[test]
    fn only_an_approved_browser_revision_is_copied_and_a_planted_one_is_not() {
        let (_d, paths) = fixture();
        let acl = Rec::default();
        let c = paths.box_home.join(".cache/ms-playwright");
        let top = |m: &BTreeMap<String, String>| {
            let j: Vec<String> = m.iter().map(|(k, v)| format!(r#""{k}":"{v}""#)).collect();
            format!(
                r#""browsers":["chromium"],"browser_digests":{{{}}},"#,
                j.join(",")
            )
        };
        assert!(installed_browser_digests(&paths, &["chromium".to_string()])
            .unwrap_err()
            .contains("no browsers"));
        let all = plant_browsers(&paths);
        assert_eq!(
            all.len(),
            4,
            "chromium and its headless shell and ffmpeg: {all:?}"
        );
        assert!(!all.contains_key("firefox-1488") && !all.contains_key("notes"));
        // approve only revision 1169 (and its parts)
        let approved: BTreeMap<String, String> = all
            .iter()
            .filter(|(k, _)| k.ends_with("1169") || k.starts_with("ffmpeg"))
            .map(|(k, v)| (k.clone(), v.clone()))
            .collect();
        let p = policy(&paths, &top(&approved));
        let sum = apply(&paths, &acl, &catalog(), "app", Some(&p)).unwrap();
        assert_eq!(sum.browsers_copied, 3);
        assert!(
            paths.browsers.join("app/chromium-1169/f").is_file(),
            "a link per revision in this project's folder"
        );
        assert!(
            !paths.browsers.join("app/chromium-1200").exists(),
            "an unapproved revision is not exposed"
        );
        // the agent replaces the approved revision with its own bytes, then asks for ensure-runner: it is refused, not copied
        std::fs::write(c.join("chromium-1169/f"), "evil").unwrap();
        let before = std::fs::read(paths.browsers.join("app/chromium-1169/f")).unwrap();
        let e = apply(&paths, &acl, &catalog(), "app", Some(&p)).unwrap_err();
        assert!(
            e.contains("chromium was not exposed") && e.contains("approved"),
            "{e}"
        );
        assert_eq!(
            before, b"chromium-1169",
            "what was exposed before is what was approved"
        );
        // a planted directory with no approved digest is never copied
        std::fs::write(c.join("chromium-1169/f"), "chromium-1169").unwrap();
        std::fs::create_dir_all(c.join("chromium-9999")).unwrap();
        std::fs::write(c.join("chromium-9999/f"), "planted").unwrap();
        apply(&paths, &acl, &catalog(), "app", Some(&p)).unwrap();
        assert!(!paths.browsers.join("app/chromium-9999").exists());
        assert!(!paths
            .browsers
            .join("store")
            .read_dir()
            .unwrap()
            .flatten()
            .any(|e| {
                std::fs::read_to_string(e.path().join("f")).is_ok_and(|t| t == "planted")
            }));
    }

    /// G5 second review, N-L1: the per-run question is one record and one digest; no copy is walked. A copy is root-owned and named by
    /// its content, so only root could change it; a changed DECLARATION is what makes a setup not current.
    #[test]
    fn whether_a_setup_is_current_is_a_record_and_a_digest_and_walks_nothing() {
        let (_d, paths) = fixture();
        let acl = Rec::default();
        let good = installed_tool_digest(&paths, &catalog(), "node").unwrap();
        let p = policy(
            &paths,
            &format!(r#""tools":[{{"name":"node","sha256":"{good}"}}],"#),
        );
        apply(&paths, &acl, &catalog(), "app", Some(&p)).unwrap();
        assert!(current(&paths, "app", &p));
        let mut other = p;
        other.writable.push("dist".into());
        assert!(
            !current(&paths, "app", &other),
            "a changed declaration is not current"
        );
    }

    /// G5 second review, N-M1: a runner user that exists and was not made for exactly this project and command is refused.
    #[test]
    fn a_user_runner_setup_did_not_make_for_this_command_is_never_reused() {
        let (_d, paths) = fixture();
        let acl = Rec::default();
        let secret = crate::runner::secret_runner_user("app", "mint");
        // something else made an account with that name first
        acl.users.borrow_mut().insert(secret.clone());
        let p = policy(&paths, "");
        let mut p = p;
        p.commands.insert(
            "mint".into(),
            crate::workload_policy::CommandPolicy {
                allow: vec!["K".into()],
                env: vec![crate::workload_policy::EnvEntry::plain("K")],
                ..Default::default()
            },
        );
        let e = apply(&paths, &acl, &catalog(), "app", Some(&p)).unwrap_err();
        assert!(e.contains("not reused") && e.contains(&secret), "{e}");
        // a second command whose name was registered for another pair is refused too
        let (_d2, paths2) = fixture();
        let acl2 = Rec::default();
        std::fs::create_dir_all(&paths2.state).unwrap();
        std::fs::write(
            paths2.state.join("users.json"),
            serde_json::json!({secret.clone(): "other\0command"}).to_string(),
        )
        .unwrap();
        let mut p2 = policy(&paths2, "");
        p2.commands = p.commands.clone();
        let e = apply(&paths2, &acl2, &catalog(), "app", Some(&p2)).unwrap_err();
        assert!(e.contains("another command"), "{e}");
    }

    /// G5 second review, N-M2: when the declaration changes, every process of its runner users is stopped before it is applied.
    #[test]
    fn a_changed_declaration_stops_what_its_runner_users_started() {
        let (_d, paths) = fixture();
        let acl = Rec::default();
        let p = policy(&paths, "");
        apply(&paths, &acl, &catalog(), "app", Some(&p)).unwrap();
        assert!(
            !acl.lines().iter().any(|c| c.starts_with("pkill")),
            "the first setup kills nothing"
        );
        apply(&paths, &acl, &catalog(), "app", Some(&p)).unwrap();
        assert!(
            !acl.lines().iter().any(|c| c.starts_with("pkill")),
            "the same declaration again kills nothing"
        );
        let mut q = p;
        q.writable.push("dist".into());
        apply(&paths, &acl, &catalog(), "app", Some(&q)).unwrap();
        assert!(
            acl.lines()
                .iter()
                .any(|c| c.starts_with("pkill -KILL -u ozbox-run-app")),
            "{:?}",
            acl.lines()
        );
    }

    /// G5 third round, N-M2: ANY change to a declaration is not current (a pin, the words, the names a command may take, its
    /// environments, its egress), so the launcher asks for setup and setup stops what ran under the old one. The second
    /// verification's case: the same command with a new pin.
    #[test]
    fn a_change_to_anything_a_secret_command_is_given_stops_the_old_processes() {
        let (_d, paths) = fixture();
        let p = policy_with(
            &paths,
            "",
            r#""mint":{"allow":["K"],"env":["K"],"argv":["node","a.mjs"],"envs":["staging"],"pin":[{"file":"a.mjs","sha256":"1111111111111111111111111111111111111111111111111111111111111111"}]}"#,
        );
        type Change = Box<dyn Fn(&mut Policy)>;
        let variants: Vec<(&str, Change)> = vec![
            (
                "pin",
                Box::new(|q| q.commands.get_mut("mint").unwrap().pin[0].sha256 = "2".repeat(64)),
            ),
            (
                "argv",
                Box::new(|q| {
                    q.commands.get_mut("mint").unwrap().argv = vec!["node".into(), "b.mjs".into()]
                }),
            ),
            (
                "allow",
                Box::new(|q| q.commands.get_mut("mint").unwrap().allow.push("J".into())),
            ),
            (
                "envs",
                Box::new(|q| {
                    q.commands.get_mut("mint").unwrap().envs = vec!["staging".into(), "dev".into()]
                }),
            ),
            (
                "egress",
                Box::new(|q| q.egress = vec!["api.example.com".into()]),
            ),
        ];
        for (what, change) in variants {
            let acl = Rec::default();
            apply(&paths, &acl, &catalog(), "app", Some(&p)).unwrap();
            assert!(current(&paths, "app", &p));
            let mut q = p.clone();
            change(&mut q);
            assert!(
                !current(&paths, "app", &q),
                "{what}: a changed declaration is not current"
            );
            let _ = apply(&paths, &acl, &catalog(), "app", Some(&q));
            let lines = acl.lines();
            assert!(
                lines.iter().any(|c| c.starts_with("pkill -KILL -u ozrc-")),
                "{what}: {lines:?}"
            );
            assert!(
                lines.iter().any(|c| c
                    .starts_with("systemctl kill --signal=KILL --kill-whom=all ozbox-run-app-")),
                "{what}"
            );
            // the services are stopped (by exact new name, and through their users for an earlier release's hyphen name) BEFORE their
            // routes, and only the project's own routes by name: the proxy first and then the socket that holds the ports
            // (the last pass of the setup is the one read: the declaration was applied twice)
            let last = |w: &str| {
                lines
                    .iter()
                    .rposition(|c| c == w)
                    .unwrap_or_else(|| panic!("{w} is not in {lines:?}"))
            };
            let svc_stop = last("systemctl stop --no-block ozbox-svc-app_*.service");
            let last_pkill = lines
                .iter()
                .rposition(|c| c.starts_with("pkill -KILL -u ozrc-"))
                .unwrap();
            let svc_kill_again =
                last("systemctl kill --signal=KILL --kill-whom=all ozbox-svc-app_*.service");
            let proxy = last("systemctl stop ozbox-egress-app_*.service");
            let socket = last("systemctl stop ozbox-egress-app_*.socket");
            assert!(
                svc_stop < last_pkill
                    && last_pkill < svc_kill_again
                    && svc_kill_again < proxy
                    && proxy < socket,
                "{what}: {lines:?}"
            );
            // never a glob that a project named `app-two` would match (a hyphen after the project name)
            assert!(
                !lines
                    .iter()
                    .any(|c| c.contains("ozbox-egress-app-") || c.contains("ozbox-svc-app-*")),
                "{what}: {lines:?}"
            );
        }
    }

    /// A process that forks as it is killed does not survive: the kill is repeated until nothing is left, and a stop that cannot
    /// finish refuses the new declaration rather than applying it over a live process.
    #[test]
    fn a_forking_process_does_not_outlive_a_changed_declaration() {
        let (_d, paths) = fixture();
        let acl = Rec::default();
        let p = policy(&paths, "");
        apply(&paths, &acl, &catalog(), "app", Some(&p)).unwrap();
        let mut q = p.clone();
        q.writable.push("dist".into());
        acl.forks.set(7);
        apply(&paths, &acl, &catalog(), "app", Some(&q)).unwrap();
        let kills = acl
            .lines()
            .iter()
            .filter(|c| c.starts_with("pkill -KILL -u ozbox-run-app"))
            .count();
        assert_eq!(kills, 8, "7 passes found something, the 8th found nothing");
        // one that never stops: refused, and the new setup is not recorded
        let mut r = q.clone();
        r.writable.push("out".into());
        acl.forks.set(10_000);
        let e = apply(&paths, &acl, &catalog(), "app", Some(&r)).unwrap_err();
        assert!(e.contains("could not all be stopped"), "{e}");
        assert!(!current(&paths, "app", &r));
        // `app` does not name the units of a project called `app-two`
        assert!(acl.lines().iter().all(|c| !c.contains("ozbox-run-app-*")));
    }

    /// G5 fourth round, NV3-M1: a refused stop is remembered. The next `apply` stops again, whatever declaration it is given (the
    /// same one, or the one that was running), and it never reports success with no kill.
    #[test]
    fn a_refused_stop_makes_the_next_apply_stop_again() {
        let (_d, paths) = fixture();
        let acl = Rec::default();
        let p = policy(&paths, "");
        apply(&paths, &acl, &catalog(), "app", Some(&p)).unwrap();
        let mut q = p.clone();
        q.writable.push("dist".into());
        acl.forks.set(10_000);
        assert!(apply(&paths, &acl, &catalog(), "app", Some(&q))
            .unwrap_err()
            .contains("could not all be stopped"));
        // the same declaration again, the process now stoppable: it must be stopped, not skipped
        acl.forks.set(0);
        let before = acl
            .lines()
            .iter()
            .filter(|c| c.starts_with("pkill"))
            .count();
        apply(&paths, &acl, &catalog(), "app", Some(&q)).unwrap();
        let after = acl
            .lines()
            .iter()
            .filter(|c| c.starts_with("pkill"))
            .count();
        assert!(
            after > before,
            "the retry must kill again: {before} -> {after}"
        );
        assert!(current(&paths, "app", &q));
        // and it is forgotten once it has worked: a third apply of the same thing kills nothing
        apply(&paths, &acl, &catalog(), "app", Some(&q)).unwrap();
        assert_eq!(
            acl.lines()
                .iter()
                .filter(|c| c.starts_with("pkill"))
                .count(),
            after
        );
        // the owner changes their mind after a refused stop and goes back to the old declaration: still stopped
        let mut r = q.clone();
        r.writable.push("out".into());
        acl.forks.set(10_000);
        assert!(apply(&paths, &acl, &catalog(), "app", Some(&r)).is_err());
        acl.forks.set(0);
        let n = acl
            .lines()
            .iter()
            .filter(|c| c.starts_with("pkill"))
            .count();
        apply(&paths, &acl, &catalog(), "app", Some(&q)).unwrap();
        assert!(
            acl.lines()
                .iter()
                .filter(|c| c.starts_with("pkill"))
                .count()
                > n,
            "going back must stop what the refused change may have started"
        );
    }

    /// G5 fifth round, NV4-L4 (Linux only: elsewhere `lock_file` is a no-op): a running setup holds launches off, and a launch past
    /// "current" holds setup off, until it lets go.
    #[cfg(target_os = "linux")]
    #[test]
    fn setup_and_a_launch_never_overlap() {
        use std::sync::atomic::{AtomicBool, Ordering};
        use std::sync::Arc;
        use std::time::Duration;
        let (_d, paths) = fixture();
        std::fs::create_dir_all(&paths.state).unwrap();
        let blocked = |first_exclusive: bool| {
            let held = lock_file(&paths, first_exclusive).unwrap().unwrap();
            let got = Arc::new(AtomicBool::new(false));
            let (g2, p2) = (got.clone(), paths.clone());
            let t = std::thread::spawn(move || {
                let _l = lock_file(&p2, !first_exclusive).unwrap().unwrap();
                g2.store(true, Ordering::SeqCst);
            });
            std::thread::sleep(Duration::from_millis(150));
            let early = got.load(Ordering::SeqCst);
            drop(held);
            t.join().unwrap();
            (early, got.load(Ordering::SeqCst))
        };
        // a setup holds a launch off; a launch holds setup off
        assert_eq!(
            blocked(true),
            (false, true),
            "a launch must wait for a running setup"
        );
        assert_eq!(
            blocked(false),
            (false, true),
            "setup must wait for a launch that has not handed over its unit"
        );
        // two launches are not held off by each other
        let a = lock_file(&paths, false).unwrap().unwrap();
        let b = lock_file(&paths, false).unwrap().unwrap();
        drop((a, b));
    }

    fn count(acl: &Rec, prefix: &str) -> usize {
        acl.lines().iter().filter(|c| c.starts_with(prefix)).count()
    }

    /// G5 fifth round, NV4-M2: a re-run of the SAME declaration that fails must not forget the stop. The reviewer's sequence: apply A,
    /// apply A again with the project folder gone (fails), then a changed declaration C must still stop everything.
    #[test]
    fn a_failed_rerun_of_the_same_declaration_still_stops_when_a_changed_one_follows() {
        let (_d, paths) = fixture();
        let acl = Rec::default();
        let a = policy(&paths, "");
        apply(&paths, &acl, &catalog(), "app", Some(&a)).unwrap();
        let away = paths.work.join("repos/app-away");
        std::fs::rename(paths.work.join("repos/app"), &away).unwrap();
        assert!(apply(&paths, &acl, &catalog(), "app", Some(&a))
            .unwrap_err()
            .contains("does not exist"));
        // the replaced record is kept, whole, in a marker that was written atomically
        let marker: State =
            serde_json::from_slice(&std::fs::read(pending_path(&paths, "app")).unwrap()).unwrap();
        assert_eq!(marker.decl, decl_digest(&a));
        assert!(!paths.state.join("app.stop-pending.json.tmp").exists());
        std::fs::rename(&away, paths.work.join("repos/app")).unwrap();
        let mut c = a.clone();
        c.writable.push("dist".into());
        let (pk, sk) = (count(&acl, "pkill"), count(&acl, "systemctl kill"));
        apply(&paths, &acl, &catalog(), "app", Some(&c)).unwrap();
        assert!(
            count(&acl, "pkill") > pk,
            "the changed declaration must stop what the failed re-run left"
        );
        assert!(count(&acl, "systemctl kill") > sk);
        assert!(
            !pending_path(&paths, "app").exists(),
            "a setup that went through forgets it"
        );
        // and a re-run of the same declaration that WORKS stops nothing
        let pk = count(&acl, "pkill");
        apply(&paths, &acl, &catalog(), "app", Some(&c)).unwrap();
        assert_eq!(count(&acl, "pkill"), pk);
    }

    /// G5 fifth round, NV4-L1: a marker or a record that exists but cannot be read is "stop pending", never "none", and the stop uses
    /// the users the registry names for the project.
    #[test]
    fn an_unreadable_marker_or_record_means_stop_pending() {
        let (_d, paths) = fixture();
        let acl = Rec::default();
        let secret = policy_with(
            &paths,
            "",
            r#""mint":{"allow":["K"],"env":["K"]},"web":{"allow":[]}"#,
        );
        let sum = apply(&paths, &acl, &catalog(), "app", Some(&secret)).unwrap();
        let ozrc = sum
            .runners
            .iter()
            .find(|u| u.starts_with("ozrc-"))
            .unwrap()
            .clone();
        // a half-written marker
        std::fs::write(pending_path(&paths, "app"), b"{\"digest\":").unwrap();
        let n = count(&acl, "pkill");
        apply(&paths, &acl, &catalog(), "app", Some(&secret)).unwrap();
        assert!(
            count(&acl, "pkill") > n,
            "an unreadable marker is a stop pending"
        );
        assert!(!pending_path(&paths, "app").exists());
        // a record that does not parse, and a declaration that drops the secret command: its user is still stopped
        std::fs::write(state_path(&paths, "app"), b"").unwrap();
        let plain = policy(&paths, "");
        acl.calls.borrow_mut().clear();
        apply(&paths, &acl, &catalog(), "app", Some(&plain)).unwrap();
        assert!(
            acl.lines()
                .iter()
                .any(|c| c == &format!("pkill -KILL -u {ozrc}")),
            "{:?}",
            acl.lines()
        );
        assert!(current(&paths, "app", &plain));
    }

    /// G5 fifth round, NV4-L2: a home that cannot be emptied refuses the setup, and the stop stays pending.
    #[test]
    fn a_runner_home_that_cannot_be_emptied_refuses_the_setup() {
        struct NoRm(Rec);
        impl Acl for NoRm {
            fn run(&self, argv: &[String]) -> Result<(), String> {
                if argv[0] == "rm" {
                    return Err("busy".into());
                }
                self.0.run(argv)
            }
        }
        let (_d, paths) = fixture();
        let acl = NoRm(Rec::default());
        let p = policy_with(&paths, "", r#""mint":{"allow":["K"],"env":["K"]}"#);
        apply(&paths, &acl.0, &catalog(), "app", Some(&p)).unwrap();
        let mut q = p.clone();
        q.writable.push("dist".into());
        let e = apply(&paths, &acl, &catalog(), "app", Some(&q)).unwrap_err();
        assert!(e.contains("could not be emptied"), "{e}");
        assert!(!current(&paths, "app", &q));
        assert!(pending_path(&paths, "app").exists());
        apply(&paths, &acl.0, &catalog(), "app", Some(&q)).unwrap();
        assert!(current(&paths, "app", &q));
    }

    /// G5 fifth round, NV4-L3: the round-2 entries of a private user are taken back ONCE, for a record made by an earlier program,
    /// after the user's processes are stopped; a record of this version never triggers it again.
    #[test]
    fn the_round_two_acl_removal_runs_once_and_only_after_the_stop() {
        let (_d, paths) = fixture();
        let acl = Rec::default();
        let p = policy_with(&paths, "", r#""mint":{"allow":["K"],"env":["K"]}"#);
        let sum = apply(&paths, &acl, &catalog(), "app", Some(&p)).unwrap();
        let ozrc = sum
            .runners
            .iter()
            .find(|u| u.starts_with("ozrc-"))
            .unwrap()
            .clone();
        let legacy = format!("setfacl -P -R -x u:{ozrc}");
        assert!(
            !acl.lines().iter().any(|c| c.starts_with(&legacy)),
            "a fresh setup removes nothing"
        );
        // the record an earlier program left
        let mut old = read_state(&paths, "app").unwrap();
        assert_eq!(old.version, SETUP_VERSION);
        old.version = 2;
        std::fs::write(state_path(&paths, "app"), serde_json::to_vec(&old).unwrap()).unwrap();
        acl.calls.borrow_mut().clear();
        apply(&paths, &acl, &catalog(), "app", Some(&p)).unwrap();
        let lines = acl.lines();
        let stop = lines
            .iter()
            .position(|c| c.starts_with(&format!("pkill -KILL -u {ozrc}")))
            .unwrap();
        let removal = lines.iter().position(|c| c.starts_with(&legacy)).unwrap();
        let grant = lines
            .iter()
            .position(|c| c.starts_with(&format!("setfacl -P -R -m u:{ozrc}:rwX")))
            .unwrap();
        assert!(stop < removal && removal < grant, "{lines:?}");
        // once
        acl.calls.borrow_mut().clear();
        apply(&paths, &acl, &catalog(), "app", Some(&p)).unwrap();
        assert!(
            !acl.lines()
                .iter()
                .any(|c| c.starts_with(&legacy) || c.starts_with("pkill")),
            "{:?}",
            acl.lines()
        );
    }

    /// G5 sixth round, NV5-I1: the round-2 removal is for records below the version that ended those ACLs, whatever `SETUP_VERSION`
    /// becomes later.
    #[test]
    fn the_legacy_acl_removal_is_pinned_to_the_version_that_introduced_the_acls() {
        assert!(needs_legacy_acl_removal(0) && needs_legacy_acl_removal(2));
        assert!(
            !needs_legacy_acl_removal(3)
                && !needs_legacy_acl_removal(4)
                && !needs_legacy_acl_removal(SETUP_VERSION + 1)
        );
    }

    /// G5 sixth round, NV5-L2: a registry that exists and cannot be read stops the setup; it never reads as empty.
    #[test]
    fn an_unreadable_runner_registry_refuses_the_setup_and_is_written_atomically() {
        let (_d, paths) = fixture();
        let acl = Rec::default();
        let p = policy_with(&paths, "", r#""mint":{"allow":["K"],"env":["K"]}"#);
        apply(&paths, &acl, &catalog(), "app", Some(&p)).unwrap();
        let reg = paths.state.join("users.json");
        assert!(
            serde_json::from_slice::<BTreeMap<String, String>>(&std::fs::read(&reg).unwrap())
                .is_ok()
        );
        assert!(
            !paths.state.join("users.json.tmp").exists(),
            "the temporary file is renamed away"
        );
        std::fs::write(&reg, b"").unwrap();
        let e = apply(&paths, &acl, &catalog(), "app", Some(&p)).unwrap_err();
        assert!(e.contains("registry cannot be read"), "{e}");
        assert!(read_registry(&paths).is_err());
        // NV6-L2: with a CHANGED declaration, the users known from the record and the project are stopped before the refusal, and the
        // error says how to recover
        let mut c = p.clone();
        c.writable.push("dist".into());
        let (pk, sk) = (count(&acl, "pkill"), count(&acl, "systemctl kill"));
        let e = apply(&paths, &acl, &catalog(), "app", Some(&c)).unwrap_err();
        assert!(
            e.contains("registry cannot be read") && e.contains("To recover"),
            "{e}"
        );
        assert!(
            count(&acl, "pkill") > pk && count(&acl, "systemctl kill") > sk,
            "the stop ran before the refusal"
        );
    }

    /// `pkill` exit 2 or 3 (could not look), or a missing program, is not "nothing left".
    #[test]
    fn a_pkill_that_could_not_look_is_never_nothing_left() {
        struct Broken;
        impl Acl for Broken {
            fn run(&self, _: &[String]) -> Result<(), String> {
                Ok(())
            }
            fn run_code(&self, argv: &[String]) -> Result<i32, String> {
                if argv[0] == "pkill" {
                    Ok(2)
                } else {
                    Ok(0)
                }
            }
        }
        let e = stop_everything_of(&Broken, "app", &["ozrc-x".to_string()]).unwrap_err();
        assert!(e.contains("could not be looked for"), "{e}");
    }

    /// Numbers for the report (this computer, not a 4 vCPU / 8 GiB box): what setup and the per-run check cost on a node-sized tree.
    #[test]
    fn the_cost_of_a_tree_copy_and_of_checking_one_is_measured() {
        let d = tempfile::tempdir().unwrap();
        let src = d.path().join("pkg");
        // about 2,000 files of about 8 KiB: the order of one `node` release, a tenth of its bytes
        for i in 0..2000 {
            let dir = src.join(format!("d{}", i % 40));
            std::fs::create_dir_all(&dir).unwrap();
            std::fs::write(
                dir.join(format!("f{i}.js")),
                vec![b'a' + (i % 26) as u8; 8192],
            )
            .unwrap();
        }
        let t = std::time::Instant::now();
        let dg = tree_digest(&src).unwrap();
        let hash_ms = t.elapsed().as_millis();
        let t = std::time::Instant::now();
        let got = publish_tree(&src, &d.path().join("copy"), Some(&dg)).unwrap();
        let copy_ms = t.elapsed().as_millis();
        assert_eq!(got, dg);
        let fp = tree_fingerprint(&d.path().join("copy")).unwrap();
        let t = std::time::Instant::now();
        for _ in 0..50 {
            assert_eq!(tree_fingerprint(&d.path().join("copy")).unwrap(), fp);
        }
        let fp_us = t.elapsed().as_micros() / 50;
        eprintln!("MEASURED tree of 2000 files / 16 MB: digest {hash_ms} ms, verified copy {copy_ms} ms, stat fingerprint (every run) {fp_us} us");
        // relative, not absolute (NV6-I4): one fingerprint costs less than the full digest of the same tree, whatever the machine's
        // load, since both slow down together. The absolute budget is only for a person measuring on the 4/8/40 box.
        let t = std::time::Instant::now();
        tree_digest(&d.path().join("copy")).unwrap();
        let digest_us = t.elapsed().as_micros();
        assert!(
            fp_us < digest_us,
            "a fingerprint ({fp_us} us) must cost less than the full digest ({digest_us} us)"
        );
        if std::env::var("OZBOX_PERF_ASSERT").as_deref() == Ok("1") {
            assert!(fp_us < 200_000, "{fp_us} us");
        }
    }
}
