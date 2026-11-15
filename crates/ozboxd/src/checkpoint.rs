//! Checkpoints: commit uncommitted work in every git repo under a root to `wip/<box>/<UTC timestamp>`.
//!
//! The snapshot is built with plumbing and a **temporary index**, so the working tree, the real index and the
//! current branch are never touched: `read-tree HEAD` and `add -A` into a throwaway `GIT_INDEX_FILE`, `write-tree`,
//! `commit-tree`, `update-ref refs/heads/wip/...`. Only a `wip/` ref is ever written - never a default or protected
//! branch - and nothing is pushed unless a remote is configured. All git calls are argv arrays through a
//! [`CommandRunner`].

use std::fs;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use ozbox_core::{BoxName, CommandRunner, CommandSpec};
use serde::Serialize;

use crate::timeutil::{compact_utc, Clock};

#[derive(Debug, Clone)]
pub struct CheckpointConfig {
    pub root: PathBuf,
    pub max_depth: usize,
    /// Push each WIP branch here when set (`None` = never push).
    pub push_remote: Option<String>,
    /// Keep the newest this-many `wip/<box>/*` branches per repo (at least 1); older local ones are deleted.
    pub keep_wip: usize,
    /// Where the quiesce snapshot looks for repositories (`None` = the checkpoint root). On a box it is `/work`, so a
    /// repository in the box user's home is covered too.
    pub snapshot_root: Option<PathBuf>,
    /// How many levels below the snapshot root a repository may be (the root itself is level 0).
    pub snapshot_depth: usize,
    /// The box user's home folder. A repository whose top level is this folder (a dotfiles repository) is never snapshotted:
    /// everything in a home folder is "untracked", and a snapshot would copy keys and history into the git directory.
    pub home_dir: Option<PathBuf>,
}

impl CheckpointConfig {
    pub fn new(root: impl Into<PathBuf>) -> Self {
        Self {
            root: root.into(),
            max_depth: 3,
            push_remote: None,
            keep_wip: 20,
            snapshot_root: None,
            snapshot_depth: 4,
            home_dir: None,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct CheckpointBranch {
    /// Repository path relative to the root.
    pub repo: String,
    pub branch: String,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
pub struct CheckpointReport {
    pub repos_scanned: usize,
    pub branches: Vec<CheckpointBranch>,
    /// One line per repo that failed (path and step only, no file names or contents).
    pub errors: Vec<String>,
    /// Old local WIP branches deleted by retention.
    #[serde(default)]
    pub pruned: usize,
    /// What a snapshot deliberately left out: a repository that is not saved at all, or files over the size cap. Not errors:
    /// the person is told, and a strict stop is not refused for a choice the snapshot makes by design. No file names.
    #[serde(default)]
    pub skipped: Vec<String>,
}

pub struct Checkpointer {
    cfg: CheckpointConfig,
    box_name: BoxName,
    runner: Arc<dyn CommandRunner>,
    clock: Arc<dyn Clock>,
}

impl Checkpointer {
    pub fn new(
        cfg: CheckpointConfig,
        box_name: BoxName,
        runner: Arc<dyn CommandRunner>,
        clock: Arc<dyn Clock>,
    ) -> Self {
        Self {
            cfg,
            box_name,
            runner,
            clock,
        }
    }

    /// Git repositories under the root (a directory that holds `.git`), not descending into a repo or hidden dirs.
    pub fn find_repos(&self) -> Vec<PathBuf> {
        let mut out = Vec::new();
        walk(&self.cfg.root, 0, self.cfg.max_depth, &mut out);
        out.sort();
        out
    }

    /// Checkpoint every dirty repo, then `sync`.
    pub fn checkpoint_all(&self) -> CheckpointReport {
        self.checkpoint_all_with(true)
    }

    /// A run's pause: the local branch `wip/<box>/<time>` its resume needs is always written; it is pushed only when `push`
    /// is true (the opt-in `checkpoint.push_wip_on_stop`) and a push remote is set.
    pub fn checkpoint_all_for_run(&self, push: bool) -> CheckpointReport {
        self.checkpoint_all_with(push)
    }

    fn checkpoint_all_with(&self, push: bool) -> CheckpointReport {
        let mut rep = CheckpointReport::default();
        for repo in self.find_repos() {
            rep.repos_scanned += 1;
            let rel = repo
                .strip_prefix(&self.cfg.root)
                .unwrap_or(&repo)
                .to_string_lossy()
                .into_owned();
            match self.checkpoint_repo_with(&repo, push) {
                Ok(Some(branch)) => rep.branches.push(CheckpointBranch {
                    repo: rel.clone(),
                    branch,
                }),
                Ok(None) => {}
                Err(step) => rep.errors.push(format!("{rel}: {step}")),
            }
            match self.prune_wip(&repo) {
                Ok(n) => rep.pruned += n,
                Err(step) => rep.errors.push(format!("{rel}: {step}")),
            }
        }
        // Flush to the persistent disk; a failure here is not fatal to the checkpoint itself.
        if let Err(e) = self.runner.run_ok(&CommandSpec::new("sync")) {
            rep.errors.push(format!("sync: {e}"));
        }
        rep
    }

    fn git(&self, repo: &Path, args: &[&str]) -> CommandSpec {
        CommandSpec::new("git")
            .arg("--no-optional-locks")
            .arg("-c")
            .arg(format!("safe.directory={}", repo.display()))
            .arg("-c")
            .arg("commit.gpgsign=false")
            .args(args.iter().copied())
            .cwd(repo)
    }

    fn out(&self, spec: &CommandSpec, step: &str) -> Result<String, String> {
        self.runner
            .run_ok(spec)
            .map(|o| o.stdout.trim().to_string())
            .map_err(|_| format!("git {step} failed"))
    }

    /// Delete local `wip/<box>/*` branches beyond the newest `keep_wip`. Only local refs under this box's own
    /// `wip/` prefix are ever deleted - never a remote, never another box's, never a checked-out branch.
    pub fn prune_wip(&self, repo: &Path) -> Result<usize, String> {
        let prefix = format!("refs/heads/wip/{}/", self.box_name);
        let listing = self.out(
            &self.git(
                repo,
                &[
                    "for-each-ref",
                    "--sort=-refname",
                    "--format=%(refname)",
                    &prefix,
                ],
            ),
            "for-each-ref",
        )?;
        let current = self
            .runner
            .run(&self.git(repo, &["symbolic-ref", "-q", "HEAD"]))
            .ok()
            .filter(|o| o.status == Some(0))
            .map(|o| o.stdout.trim().to_string());
        let keep = self.cfg.keep_wip.max(1);
        let mut pruned = 0;
        // Newest first: names embed a UTC timestamp (and a -N suffix for a same-second repeat), so reverse name
        // order is newest first.
        for r in listing
            .lines()
            .map(str::trim)
            .filter(|l| !l.is_empty())
            .skip(keep)
        {
            if !r.starts_with(&prefix) || current.as_deref() == Some(r) {
                continue;
            }
            self.out(&self.git(repo, &["update-ref", "-d", r]), "update-ref -d")?;
            pruned += 1;
        }
        Ok(pruned)
    }

    /// `Ok(Some(branch))` when a WIP branch was written, `Ok(None)` when there was nothing to save.
    pub fn checkpoint_repo(&self, repo: &Path) -> Result<Option<String>, String> {
        self.checkpoint_repo_with(repo, true)
    }

    fn checkpoint_repo_with(&self, repo: &Path, push: bool) -> Result<Option<String>, String> {
        let status = self.out(&self.git(repo, &["status", "--porcelain"]), "status")?;
        if status.is_empty() {
            return Ok(None);
        }
        let gitdir = self.out(
            &self.git(repo, &["rev-parse", "--absolute-git-dir"]),
            "rev-parse git-dir",
        )?;
        let head = self
            .runner
            .run(&self.git(repo, &["rev-parse", "--verify", "-q", "HEAD"]))
            .ok()
            .filter(|o| o.status == Some(0))
            .map(|o| o.stdout.trim().to_string())
            .filter(|h| !h.is_empty());

        let ts = compact_utc(self.clock.now_ms());
        let index = Path::new(&gitdir).join(format!("ozbox-wip-index-{ts}-{}", std::process::id()));
        let result = self.snapshot(repo, &index, head.as_deref(), &ts, push);
        let _ = fs::remove_file(&index);
        result
    }

    fn snapshot(
        &self,
        repo: &Path,
        index: &Path,
        head: Option<&str>,
        ts: &str,
        push: bool,
    ) -> Result<Option<String>, String> {
        let with_index =
            |s: CommandSpec| s.env("GIT_INDEX_FILE", index.to_string_lossy().into_owned());
        if head.is_some() {
            self.out(
                &with_index(self.git(repo, &["read-tree", "HEAD"])),
                "read-tree",
            )?;
        }
        self.out(&with_index(self.git(repo, &["add", "-A"])), "add")?;
        let tree = self.out(&with_index(self.git(repo, &["write-tree"])), "write-tree")?;
        if head.is_some() {
            let head_tree = self.out(
                &self.git(repo, &["rev-parse", "HEAD^{tree}"]),
                "rev-parse tree",
            )?;
            if head_tree == tree {
                return Ok(None); // only ignored or empty changes
            }
        }
        let message = format!("ozbox checkpoint {ts}");
        let mut commit = self.git(repo, &["commit-tree", &tree, "-m", &message]);
        if let Some(h) = head {
            commit.args.push("-p".into());
            commit.args.push(h.to_string());
        }
        let commit = commit
            .env("GIT_AUTHOR_NAME", "ozbox")
            .env("GIT_AUTHOR_EMAIL", "ozbox@localhost")
            .env("GIT_COMMITTER_NAME", "ozbox")
            .env("GIT_COMMITTER_EMAIL", "ozbox@localhost");
        let sha = self.out(&commit, "commit-tree")?;

        let base = format!("wip/{}/{ts}", self.box_name);
        let mut branch = base.clone();
        for n in 2..=20 {
            let exists = self
                .runner
                .run(&self.git(
                    repo,
                    &[
                        "show-ref",
                        "--verify",
                        "--quiet",
                        &format!("refs/heads/{branch}"),
                    ],
                ))
                .map(|o| o.status == Some(0))
                .unwrap_or(false);
            if !exists {
                break;
            }
            branch = format!("{base}-{n}");
        }
        // The only ref ever written is under wip/.
        if !branch.starts_with("wip/") {
            return Err("refusing to write outside wip/".into());
        }
        self.out(
            &self.git(repo, &["update-ref", &format!("refs/heads/{branch}"), &sha]),
            "update-ref",
        )?;
        if let Some(remote) = self.cfg.push_remote.as_ref().filter(|_| push) {
            let spec = format!("refs/heads/{branch}:refs/heads/{branch}");
            self.out(&self.git(repo, &["push", remote, &spec]), "push")?;
        }
        Ok(Some(branch))
    }
}

/// The namespace a quiesce snapshot lives in. Not a branch: `git branch` does not list it and no checkout can land on it.
pub const HIDDEN_PREFIX: &str = "refs/ozbox/wip/";

/// An untracked file larger than this is not put in a snapshot (it is reported, never silently dropped).
pub const MAX_UNTRACKED_BYTES: u64 = 50 * 1024 * 1024;
/// A hidden snapshot older than this is removed (only in our own namespace), whatever the number kept.
pub const MAX_AGE_DAYS: u64 = 14;
/// At most this many oversize files are named to `git add`; more than that and the repository is reported, not saved.
const MAX_EXCLUDES: usize = 200;
/// Folders and files that mean "this is somebody's home, or holds credentials": a repository whose top level has one is not
/// snapshotted, whatever its name.
const CREDENTIAL_PATHS: [&str; 12] = [
    ".ssh",
    ".aws",
    ".gnupg",
    ".config/gcloud",
    ".config/gh",
    ".azure",
    ".kube",
    ".docker",
    ".netrc",
    ".git-credentials",
    ".pgpass",
    ".npmrc",
];

/// When the stop of the daemon (a systemd stop for a resize, an upgrade or a shutdown) takes its snapshot, at most this long:
/// well inside systemd's stop timeout (90 s unless set otherwise), so the daemon is never killed in the middle of a git write.
pub const STOP_TOTAL_S: u64 = 40;

/// The flush at the end of a snapshot never takes longer than this, whatever the per-call bound is.
pub const SYNC_S: u64 = 5;
/// A temporary index this old is a leftover of a process that was killed, and is removed.
const STALE_INDEX_AGE: std::time::Duration = std::time::Duration::from_secs(3600);

/// How a quiesce snapshot is bounded.
#[derive(Debug, Clone)]
pub struct HiddenOpts {
    /// Each git call runs under `timeout -k 2 <n>`; `None` runs it unbounded (tests on a system with no `timeout`).
    /// The bound is also cut to what is left of `total`, so no call runs past the deadline.
    pub per_git_s: Option<u64>,
    /// The hard limit on the repositories and their pruning, counted from the start. A repository not started by then is
    /// reported, not silently dropped; the call in progress at the limit is ended; the final flush (at most
    /// [`SYNC_S`] seconds) comes after it.
    pub total: std::time::Duration,
    /// Keep the newest this-many snapshots per repo (at least 1).
    pub keep: usize,
}

impl Default for HiddenOpts {
    fn default() -> Self {
        Self {
            per_git_s: Some(20),
            total: std::time::Duration::from_secs(120),
            keep: 20,
        }
    }
}

/// What is left of the time a snapshot may take.
struct Bound {
    per: Option<u64>,
    deadline: std::time::Instant,
}

impl Bound {
    fn left(&self) -> std::time::Duration {
        self.deadline
            .saturating_duration_since(std::time::Instant::now())
    }
    /// The timeout for the next call: the per-call bound, cut to what is left (at least a second).
    fn secs(&self) -> Option<u64> {
        self.per
            .map(|p| p.min(self.left().as_secs_f64().ceil() as u64).max(1))
    }
    fn alive(&self) -> Result<(), String> {
        if self.left().is_zero() {
            Err("the time limit was reached".into())
        } else {
            Ok(())
        }
    }
}

/// The directory holding a repository's refs and `packed-refs`, read without running git (a plain repository, a submodule
/// whose git directory lives in the parent, or a linked worktree).
fn common_dir_of(repo: &Path) -> Option<PathBuf> {
    let dotgit = repo.join(".git");
    if dotgit.is_dir() {
        return Some(dotgit);
    }
    let text = fs::read_to_string(&dotgit).ok()?;
    let target = text.trim().strip_prefix("gitdir:")?.trim();
    let gitdir = repo.join(target);
    match fs::read_to_string(gitdir.join("commondir")) {
        Ok(c) => Some(gitdir.join(c.trim())),
        Err(_) => Some(gitdir),
    }
}

impl Checkpointer {
    /// The repositories a quiesce snapshot looks at: every git repository under the snapshot root (`/work` on a box), to
    /// the snapshot depth, **including the ones nested inside another** (a submodule, an embedded repository, a linked
    /// worktree), each on its own. Folders starting with a dot and `node_modules` are skipped, and links are not followed.
    pub fn find_snapshot_repos(&self) -> Vec<PathBuf> {
        let mut out = Vec::new();
        let root = self.cfg.snapshot_root.as_ref().unwrap_or(&self.cfg.root);
        walk_all(root, 0, self.cfg.snapshot_depth, &mut out);
        out.sort();
        out
    }

    /// A snapshot of every dirty repository under the snapshot root that touches nothing of the person's: the working tree,
    /// the real index, the current branch, the stash list and the remotes stay as they were. Each snapshot is a commit (HEAD
    /// plus everything uncommitted, untracked files included, ignored files not) built in a temporary index, and a ref under
    /// [`HIDDEN_PREFIX`] named from the clock only. Never pushes, never prunes outside its own namespace, and no hook or
    /// file-system monitor of the repository runs. A repository that fails is reported and the rest go on. The whole call
    /// keeps to [`HiddenOpts::total`]; whatever a killed call created (its temporary index, the lock of its ref) is removed.
    pub fn snapshot_all_hidden(&self, o: &HiddenOpts) -> CheckpointReport {
        let started = std::time::Instant::now();
        let b = Bound {
            per: o.per_git_s,
            deadline: started + o.total,
        };
        let mut rep = CheckpointReport::default();
        for repo in self.find_snapshot_repos() {
            rep.repos_scanned += 1;
            let rel = self.snapshot_rel(&repo);
            if b.alive().is_err() {
                rep.errors
                    .push(format!("{rel}: skipped, the time limit was reached"));
                continue;
            }
            if let Some(why) = self.not_saved_reason(&repo) {
                rep.skipped.push(format!("{rel}: not saved: {why}"));
                continue;
            }
            match self.hidden_repo(&repo, &b, &mut rep.skipped) {
                Ok(Some(name)) => rep.branches.push(CheckpointBranch {
                    repo: rel.clone(),
                    branch: name,
                }),
                Ok(None) => {}
                Err(step) => rep.errors.push(format!("{rel}: {step}")),
            }
            // Retention is the first thing given up when time runs out.
            if b.alive().is_ok() {
                match self.prune_hidden(&repo, &b, o.keep) {
                    Ok(n) => rep.pruned += n,
                    Err(step) => rep.errors.push(format!("{rel}: {step}")),
                }
            }
        }
        let mut sync = CommandSpec::new("sync");
        if let Some(n) = o.per_git_s {
            sync = bound(n.min(SYNC_S), sync);
        }
        if let Err(e) = self.runner.run_ok(&sync) {
            rep.errors.push(format!("sync: {e}"));
        }
        rep
    }

    /// What the daemon does on **every automatic path**: when it is told to stop, when the box has been idle and is about to be
    /// stopped, and when the provider announces an interruption. By default the same hidden snapshot a quiesce takes: nothing
    /// visible is written, nothing is pushed, no hook runs, and it keeps to [`STOP_TOTAL_S`]. With `push_wip` (the explicit
    /// opt-in `checkpoint.push_wip_on_stop`) it is the older checkpoint instead, which writes the branch `wip/<box>/<time>` in
    /// each changed repository and pushes it when a push remote is set. The older checkpoint is otherwise reached only by the
    /// explicit `POST /v1/checkpoint` (and the callers that ask for it by name), never by anything that happens by itself.
    pub fn on_stop(&self, push_wip: bool) -> CheckpointReport {
        self.on_stop_with(push_wip, Some(15))
    }

    /// The idle stop: [`Self::on_stop`] by another name, so that the call site says which path it is.
    pub fn on_idle(&self, push_wip: bool) -> CheckpointReport {
        self.on_stop(push_wip)
    }

    /// The interruption notice (a spot reclaim): [`Self::on_stop`] by another name. The notice gives about two minutes; this
    /// keeps to [`STOP_TOTAL_S`] of them.
    pub fn on_interruption(&self, push_wip: bool) -> CheckpointReport {
        self.on_stop(push_wip)
    }

    /// [`Self::on_stop`] with the per-call bound named (`None` for a system with no `timeout` command, in tests).
    pub fn on_stop_with(&self, push_wip: bool, per_git_s: Option<u64>) -> CheckpointReport {
        if push_wip {
            return self.checkpoint_all();
        }
        self.snapshot_all_hidden(&HiddenOpts {
            per_git_s,
            total: std::time::Duration::from_secs(STOP_TOTAL_S),
            ..HiddenOpts::default()
        })
    }

    /// Why a repository is not snapshotted at all, or `None`: its top level is the box user's home folder, or it holds a
    /// credential folder at its top level.
    fn not_saved_reason(&self, repo: &Path) -> Option<&'static str> {
        let is_home = self.cfg.home_dir.as_ref().is_some_and(|h| {
            match (fs::canonicalize(h), fs::canonicalize(repo)) {
                (Ok(a), Ok(b)) => a == b,
                _ => h == repo,
            }
        });
        if is_home || CREDENTIAL_PATHS.iter().any(|c| repo.join(c).exists()) {
            Some("home/dotfiles repo")
        } else {
            None
        }
    }

    /// The untracked files over [`MAX_UNTRACKED_BYTES`], as repository-relative paths.
    fn oversize_untracked(&self, b: &Bound, repo: &Path) -> Result<Vec<String>, String> {
        let list = self.out(
            &self.hgit(
                b,
                repo,
                &["ls-files", "--others", "--exclude-standard", "-z"],
            ),
            "ls-files",
        )?;
        Ok(list
            .split('\0')
            .filter(|p| !p.is_empty() && !p.ends_with('/'))
            .filter(|p| {
                fs::symlink_metadata(repo.join(p))
                    .is_ok_and(|m| m.is_file() && m.len() > MAX_UNTRACKED_BYTES)
            })
            .map(str::to_string)
            .collect())
    }

    fn snapshot_rel(&self, repo: &Path) -> String {
        let root = self.cfg.snapshot_root.as_ref().unwrap_or(&self.cfg.root);
        repo.strip_prefix(root)
            .unwrap_or(repo)
            .to_string_lossy()
            .into_owned()
    }

    fn hgit(&self, b: &Bound, repo: &Path, args: &[&str]) -> CommandSpec {
        let git = CommandSpec::new("git")
            .arg("--no-optional-locks")
            .arg("-c")
            .arg(format!("safe.directory={}", repo.display()))
            .args([
                "-c",
                "commit.gpgsign=false",
                "-c",
                "core.hooksPath=/dev/null",
                "-c",
                "core.fsmonitor=false",
                "-c",
                "gc.auto=0",
                // a person's own setting must not hide new files from the check below
                "-c",
                "status.showUntrackedFiles=all",
            ])
            .args(args.iter().copied())
            .cwd(repo);
        match b.secs() {
            Some(n) => bound(n, git),
            None => git,
        }
    }

    /// `Ok(Some(ref))` when a snapshot exists for the repository's present state (new, or the newest one already holds it),
    /// `Ok(None)` when there was nothing to save.
    fn hidden_repo(
        &self,
        repo: &Path,
        b: &Bound,
        skipped: &mut Vec<String>,
    ) -> Result<Option<String>, String> {
        let g = |a: &[&str]| self.hgit(b, repo, a);
        // `--untracked-files=all` overrides `status.showUntrackedFiles=no` in the person's own configuration.
        let status = self.out(
            &g(&["status", "--porcelain", "--untracked-files=all"]),
            "status",
        )?;
        if status.is_empty() {
            return Ok(None);
        }
        b.alive()?;
        let gitdir = self.out(
            &g(&["rev-parse", "--absolute-git-dir"]),
            "rev-parse git-dir",
        )?;
        sweep_stale_indexes(Path::new(&gitdir));
        let head = self
            .runner
            .run(&g(&["rev-parse", "--verify", "-q", "HEAD"]))
            .ok()
            .filter(|out| out.status == Some(0))
            .map(|out| out.stdout.trim().to_string())
            .filter(|h| !h.is_empty());
        let ts = compact_utc(self.clock.now_ms());
        let index = Path::new(&gitdir).join(format!("ozbox-wip-index-{ts}-{}", std::process::id()));
        let result = self.hidden_snapshot(repo, b, &index, head.as_deref(), &ts, skipped);
        // Only files this call made: its own temporary index and that index's lock, on every way out (a call ended by its
        // time limit included).
        let _ = fs::remove_file(&index);
        let mut lock = index.clone().into_os_string();
        lock.push(".lock");
        let _ = fs::remove_file(PathBuf::from(lock));
        result
    }

    fn hidden_snapshot(
        &self,
        repo: &Path,
        b: &Bound,
        index: &Path,
        head: Option<&str>,
        ts: &str,
        skipped: &mut Vec<String>,
    ) -> Result<Option<String>, String> {
        let with_index =
            |s: CommandSpec| s.env("GIT_INDEX_FILE", index.to_string_lossy().into_owned());
        let g = |a: &[&str]| self.hgit(b, repo, a);
        if head.is_some() {
            b.alive()?;
            self.out(&with_index(g(&["read-tree", "HEAD"])), "read-tree")?;
        }
        b.alive()?;
        // an untracked file over the cap is left out and counted (never named), not hashed into the git directory
        let big = self.oversize_untracked(b, repo)?;
        if big.len() > MAX_EXCLUDES {
            return Err("too many untracked files over 50 MB to leave out".into());
        }
        if !big.is_empty() {
            let rel = self.snapshot_rel(repo);
            skipped.push(format!(
                "{rel}: {} untracked file(s) larger than 50 MB were not saved",
                big.len()
            ));
        }
        b.alive()?;
        let mut add = g(&["add", "-A"]);
        if !big.is_empty() {
            add.args.push("--".into());
            add.args.push(".".into());
            for f in &big {
                add.args.push(format!(":(exclude,literal){f}"));
            }
        }
        self.out(&with_index(add), "add")?;
        b.alive()?;
        let tree = self.out(&with_index(g(&["write-tree"])), "write-tree")?;
        if let Some(h) = head {
            let head_tree = self.out(
                &g(&["rev-parse", &format!("{h}^{{tree}}")]),
                "rev-parse tree",
            )?;
            if head_tree == tree {
                return Ok(None); // only ignored or empty changes
            }
        }
        // A second quiesce of the same state saves nothing new: the newest snapshot already holds it.
        let newest = self
            .out(
                &g(&[
                    "for-each-ref",
                    "--sort=-refname",
                    "--count=1",
                    "--format=%(refname)",
                    HIDDEN_PREFIX,
                ]),
                "for-each-ref",
            )
            .unwrap_or_default();
        if !newest.is_empty() && newest.starts_with(HIDDEN_PREFIX) {
            let same_tree = self
                .runner
                .run(&g(&["rev-parse", &format!("{newest}^{{tree}}")]))
                .ok()
                .filter(|out| out.status == Some(0))
                .is_some_and(|out| out.stdout.trim() == tree);
            let same_base = match head {
                Some(h) => self
                    .runner
                    .run(&g(&["rev-parse", &format!("{newest}^")]))
                    .ok()
                    .filter(|out| out.status == Some(0))
                    .is_some_and(|out| out.stdout.trim() == h),
                None => true,
            };
            if same_tree && same_base {
                return Ok(Some(newest));
            }
        }
        b.alive()?;
        let message = format!("ozbox quiesce snapshot {ts}");
        let mut commit = g(&["commit-tree", &tree, "-m", &message]);
        if let Some(h) = head {
            commit.args.push("-p".into());
            commit.args.push(h.to_string());
        }
        let commit = commit
            .env("GIT_AUTHOR_NAME", "ozbox")
            .env("GIT_AUTHOR_EMAIL", "ozbox@localhost")
            .env("GIT_COMMITTER_NAME", "ozbox")
            .env("GIT_COMMITTER_EMAIL", "ozbox@localhost");
        let sha = self.out(&commit, "commit-tree")?;
        let base = format!("{HIDDEN_PREFIX}{ts}");
        let mut name = base.clone();
        // Two digits, so that the names sort in the order they were made (`-10` after `-09`).
        for n in 2..=20 {
            let exists = self
                .runner
                .run(&g(&["show-ref", "--verify", "--quiet", &name]))
                .map(|out| out.status == Some(0))
                .unwrap_or(false);
            if !exists {
                break;
            }
            name = format!("{base}-{n:02}");
        }
        // The only ref ever written is under its own namespace. The all-zero old value makes the write refuse to replace.
        if !name.starts_with(HIDDEN_PREFIX) {
            return Err("refusing to write outside refs/ozbox/wip/".into());
        }
        b.alive()?;
        let zero = "0".repeat(sha.len().max(40));
        // The lock of a ref named from our clock is ours alone: if the call was ended while it held it, it is removed.
        let ref_lock = common_dir_of(repo).map(|c| c.join(format!("{name}.lock")));
        let pre_existing = ref_lock.as_ref().is_some_and(|p| p.exists());
        let wrote = self.out(&g(&["update-ref", &name, &sha, &zero]), "update-ref");
        if wrote.is_err() && !pre_existing {
            if let Some(p) = ref_lock {
                let _ = fs::remove_file(p);
            }
        }
        wrote?;
        Ok(Some(name))
    }

    fn prune_hidden(&self, repo: &Path, b: &Bound, keep: usize) -> Result<usize, String> {
        let g = |a: &[&str]| self.hgit(b, repo, a);
        let listing = self.out(
            &g(&[
                "for-each-ref",
                "--sort=-refname",
                "--format=%(refname)",
                HIDDEN_PREFIX,
            ]),
            "for-each-ref",
        )?;
        let mut pruned = 0;
        let now = self.clock.now_ms();
        for (i, r) in listing
            .lines()
            .map(str::trim)
            .filter(|l| !l.is_empty())
            .enumerate()
        {
            // only our own namespace is ever deleted
            let Some(tail) = r.strip_prefix(HIDDEN_PREFIX) else {
                continue;
            };
            // the newest `keep` are kept unless they are too old to keep; an older one than that is removed whatever its rank
            let too_old = hidden_ref_time_ms(tail)
                .is_some_and(|t| now.saturating_sub(t) > MAX_AGE_DAYS * 86_400_000);
            if i < keep.max(1) && !too_old {
                continue;
            }
            if b.alive().is_err() {
                break; // the rest is pruned next time
            }
            // Deleting a ref can rewrite `packed-refs` under git's own lock. That lock is never removed here: this process did
            // not create it (git did), and "it was absent a moment ago" does not make it ours; a person's or an agent's git
            // may hold it now. A git ended by our time limit gets SIGTERM first and removes its lock itself.
            self.out(&g(&["update-ref", "-d", r]), "update-ref -d")?;
            pruned += 1;
        }
        Ok(pruned)
    }
}

/// When a snapshot was taken, from its name (`yyyymmddThhmmssZ`, with an optional `-nn` suffix); `None` for a name this feature
/// did not make.
fn hidden_ref_time_ms(tail: &str) -> Option<u64> {
    let stamp = tail.split('-').next()?;
    let b = stamp.as_bytes();
    if b.len() != 16 || b[8] != b'T' || b[15] != b'Z' {
        return None;
    }
    let n = |r: std::ops::Range<usize>| stamp.get(r)?.parse::<u32>().ok();
    let (y, mo, d) = (n(0..4)?, n(4..6)?, n(6..8)?);
    let (h, mi, sec) = (n(9..11)?, n(11..13)?, n(13..15)?);
    if !(1..=12).contains(&mo) || !(1..=31).contains(&d) || h > 23 || mi > 59 || sec > 60 {
        return None;
    }
    let days = crate::timeutil::days_from_civil(i64::from(y), mo, d);
    let secs = days * 86_400 + i64::from(h) * 3600 + i64::from(mi) * 60 + i64::from(sec);
    u64::try_from(secs).ok().map(|s| s * 1000)
}

/// Remove the temporary indexes (and their locks) that an earlier, killed run left in a git directory. Only names this
/// feature makes, and only when they are old enough that no run can still be using them.
fn sweep_stale_indexes(gitdir: &Path) {
    let Ok(rd) = fs::read_dir(gitdir) else { return };
    for e in rd.flatten() {
        if !e
            .file_name()
            .to_string_lossy()
            .starts_with("ozbox-wip-index-")
        {
            continue;
        }
        let old = e
            .metadata()
            .and_then(|m| m.modified())
            .ok()
            .and_then(|t| t.elapsed().ok())
            .is_some_and(|age| age >= STALE_INDEX_AGE);
        if old && e.file_type().is_ok_and(|t| t.is_file()) {
            let _ = fs::remove_file(e.path());
        }
    }
}

/// Run `spec` under `timeout -k 2 <secs>`: a hung git is ended, never waited for.
fn bound(secs: u64, spec: CommandSpec) -> CommandSpec {
    let mut out = CommandSpec::new("timeout")
        .arg("-k")
        .arg("2")
        .arg(secs.to_string())
        .arg(spec.program.clone())
        .args(spec.args.iter().cloned());
    out.cwd = spec.cwd.clone();
    out.env = spec.env.clone();
    out.stdin = spec.stdin.clone();
    out
}

/// Like [`walk`], but goes on into a repository: a submodule, an embedded repository or a linked worktree is a repository
/// of its own and is found as one.
fn walk_all(dir: &Path, depth: usize, max: usize, out: &mut Vec<PathBuf>) {
    if dir.join(".git").exists() {
        out.push(dir.to_path_buf());
    }
    if depth >= max {
        return;
    }
    let Ok(rd) = fs::read_dir(dir) else { return };
    for e in rd.flatten() {
        let name = e.file_name();
        let name = name.to_string_lossy();
        if name.starts_with('.') || name == "node_modules" {
            continue;
        }
        if e.file_type().is_ok_and(|t| t.is_dir()) {
            walk_all(&e.path(), depth + 1, max, out);
        }
    }
}

fn walk(dir: &Path, depth: usize, max: usize, out: &mut Vec<PathBuf>) {
    if dir.join(".git").exists() {
        out.push(dir.to_path_buf());
        return;
    }
    if depth >= max {
        return;
    }
    let Ok(rd) = fs::read_dir(dir) else { return };
    for e in rd.flatten() {
        let name = e.file_name();
        let name = name.to_string_lossy();
        if name.starts_with('.') || name == "node_modules" {
            continue;
        }
        // file_type() does not follow symlinks: a link out of the root is never walked.
        if e.file_type().is_ok_and(|t| t.is_dir()) {
            walk(&e.path(), depth + 1, max, out);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::timeutil::FakeClock;
    use ozbox_core::{RecordingRunner, SystemRunner};

    const T0: u64 = 1_794_227_696_000; // 2026-11-09T12:34:56Z

    fn git(dir: &Path, args: &[&str]) -> String {
        let o = std::process::Command::new("git")
            .args([
                "-c",
                "user.name=t",
                "-c",
                "user.email=t@example.com",
                "-c",
                "commit.gpgsign=false",
            ])
            .args(args)
            .current_dir(dir)
            .output()
            .unwrap();
        assert!(
            o.status.success(),
            "git {args:?}: {}",
            String::from_utf8_lossy(&o.stderr)
        );
        String::from_utf8_lossy(&o.stdout).trim().to_string()
    }

    fn repo(dir: &Path) {
        fs::create_dir_all(dir).unwrap();
        git(dir, &["init", "-q", "-b", "main"]);
        fs::write(dir.join("a.txt"), "one\n").unwrap();
        fs::write(dir.join("gone.txt"), "bye\n").unwrap();
        fs::write(dir.join(".gitignore"), "ignored.log\n").unwrap();
        git(dir, &["add", "-A"]);
        git(dir, &["commit", "-q", "-m", "init"]);
    }

    fn cp(root: &Path, clock: Arc<FakeClock>) -> Checkpointer {
        Checkpointer::new(
            CheckpointConfig::new(root),
            BoxName::new("dev-1").unwrap(),
            Arc::new(SystemRunner),
            clock,
        )
    }

    #[test]
    fn clean_repo_writes_nothing() {
        let d = tempfile::tempdir().unwrap();
        repo(&d.path().join("p"));
        let rep = cp(d.path(), Arc::new(FakeClock::new(T0))).checkpoint_all();
        assert_eq!((rep.repos_scanned, rep.branches.len()), (1, 0));
        assert!(rep.errors.is_empty(), "{:?}", rep.errors);
        assert_eq!(git(&d.path().join("p"), &["branch", "--list", "wip/*"]), "");
    }

    #[test]
    fn dirty_repo_gets_a_wip_branch_and_nothing_else_changes() {
        let d = tempfile::tempdir().unwrap();
        let p = d.path().join("p");
        repo(&p);
        fs::write(p.join("a.txt"), "one\ntwo\n").unwrap(); // modified
        fs::write(p.join("new.txt"), "new\n").unwrap(); // untracked
        fs::write(p.join("ignored.log"), "noise\n").unwrap(); // ignored
        fs::remove_file(p.join("gone.txt")).unwrap(); // deleted
        fs::write(p.join("staged.txt"), "s\n").unwrap();
        git(&p, &["add", "staged.txt"]); // staged in the REAL index
        let head_before = git(&p, &["rev-parse", "HEAD"]);
        let status_before = git(&p, &["status", "--porcelain"]);

        let rep = cp(d.path(), Arc::new(FakeClock::new(T0))).checkpoint_all();
        assert!(rep.errors.is_empty(), "{:?}", rep.errors);
        assert_eq!(rep.branches.len(), 1);
        let b = &rep.branches[0].branch;
        assert_eq!(b, "wip/dev-1/20261109T123456Z");

        // The snapshot has everything, minus ignored files.
        assert_eq!(git(&p, &["show", &format!("{b}:a.txt")]), "one\ntwo");
        assert_eq!(git(&p, &["show", &format!("{b}:new.txt")]), "new");
        assert_eq!(git(&p, &["show", &format!("{b}:staged.txt")]), "s");
        let files = git(&p, &["ls-tree", "-r", "--name-only", b]);
        assert!(
            !files.contains("gone.txt") && !files.contains("ignored.log"),
            "{files}"
        );
        assert_eq!(git(&p, &["rev-parse", &format!("{b}^")]), head_before);

        // Untouched: current branch, HEAD, working tree, and the real index.
        assert_eq!(git(&p, &["rev-parse", "--abbrev-ref", "HEAD"]), "main");
        assert_eq!(git(&p, &["rev-parse", "HEAD"]), head_before);
        assert_eq!(git(&p, &["status", "--porcelain"]), status_before);
        assert_eq!(fs::read_to_string(p.join("a.txt")).unwrap(), "one\ntwo\n");
        // No temporary index left behind.
        let leftovers: Vec<_> = fs::read_dir(p.join(".git"))
            .unwrap()
            .flatten()
            .filter(|e| {
                e.file_name()
                    .to_string_lossy()
                    .starts_with("ozbox-wip-index")
            })
            .collect();
        assert!(leftovers.is_empty());
    }

    #[test]
    fn same_second_gets_a_suffix_and_unborn_repo_works() {
        let d = tempfile::tempdir().unwrap();
        let p = d.path().join("p");
        repo(&p);
        let c = cp(d.path(), Arc::new(FakeClock::new(T0)));
        fs::write(p.join("x.txt"), "1").unwrap();
        let first = c.checkpoint_repo(&p).unwrap().unwrap();
        let second = c.checkpoint_repo(&p).unwrap().unwrap();
        assert_eq!(second, format!("{first}-2"));

        let q = d.path().join("unborn");
        fs::create_dir_all(&q).unwrap();
        git(&q, &["init", "-q", "-b", "main"]);
        fs::write(q.join("f"), "x").unwrap();
        let b = c.checkpoint_repo(&q).unwrap().unwrap();
        assert_eq!(git(&q, &["show", &format!("{b}:f")]), "x");
    }

    #[test]
    fn finds_nested_repos_but_skips_hidden_and_inside_repos() {
        let d = tempfile::tempdir().unwrap();
        repo(&d.path().join("a"));
        repo(&d.path().join("group").join("b"));
        repo(&d.path().join(".hidden").join("c"));
        repo(&d.path().join("a").join("vendored"));
        let found = cp(d.path(), Arc::new(FakeClock::new(T0))).find_repos();
        let rel: Vec<_> = found
            .iter()
            .map(|p| p.strip_prefix(d.path()).unwrap().to_path_buf())
            .collect();
        assert_eq!(rel, vec![PathBuf::from("a"), PathBuf::from("group/b")]);
    }

    #[test]
    fn push_only_when_configured_and_argv_is_exact() {
        let d = tempfile::tempdir().unwrap();
        let p = d.path().join("p");
        repo(&p);
        fs::write(p.join("n"), "1").unwrap();
        let mut cfg = CheckpointConfig::new(d.path());
        cfg.push_remote = Some("backup".into());
        // Real git for the local steps; a recording wrapper is overkill - check the argv builder with the fake.
        let rec = Arc::new(RecordingRunner::new());
        let c = Checkpointer::new(
            cfg,
            BoxName::new("dev-1").unwrap(),
            rec.clone(),
            Arc::new(FakeClock::new(T0)),
        );
        rec.reply(ozbox_core::Output {
            status: Some(0),
            stdout: " M x\n".into(),
            stderr: String::new(),
        }); // status
        rec.reply(ozbox_core::Output {
            status: Some(0),
            stdout: format!("{}/.git\n", p.display()),
            stderr: String::new(),
        }); // git-dir
        rec.reply(ozbox_core::Output {
            status: Some(0),
            stdout: "headsha\n".into(),
            stderr: String::new(),
        }); // HEAD
        rec.reply(ozbox_core::Output {
            status: Some(0),
            ..Default::default()
        }); // read-tree
        rec.reply(ozbox_core::Output {
            status: Some(0),
            ..Default::default()
        }); // add
        rec.reply(ozbox_core::Output {
            status: Some(0),
            stdout: "tree2\n".into(),
            stderr: String::new(),
        }); // write-tree
        rec.reply(ozbox_core::Output {
            status: Some(0),
            stdout: "tree1\n".into(),
            stderr: String::new(),
        }); // HEAD^{tree}
        rec.reply(ozbox_core::Output {
            status: Some(0),
            stdout: "newsha\n".into(),
            stderr: String::new(),
        }); // commit-tree
        rec.reply(ozbox_core::Output {
            status: Some(1),
            ..Default::default()
        }); // show-ref: absent
        let b = c.checkpoint_repo(&p).unwrap().unwrap();
        assert_eq!(b, "wip/dev-1/20261109T123456Z");
        let calls = rec.calls();
        let last = calls.last().unwrap();
        assert!(
            last.args.ends_with(&[
                "push".into(),
                "backup".into(),
                format!("refs/heads/{b}:refs/heads/{b}")
            ]),
            "{:?}",
            last.args
        );
        // every ref written is under wip/
        let upd = calls
            .iter()
            .find(|c| c.args.contains(&"update-ref".to_string()))
            .unwrap();
        assert!(upd.args.iter().any(|a| a == &format!("refs/heads/{b}")));
    }

    #[test]
    fn prune_keeps_newest_n_local_wip_only() {
        let d = tempfile::tempdir().unwrap();
        let p = d.path().join("p");
        repo(&p);
        let clock = Arc::new(FakeClock::new(T0));
        let mut cfg = CheckpointConfig::new(d.path());
        cfg.keep_wip = 3;
        let c = Checkpointer::new(
            cfg,
            BoxName::new("dev-1").unwrap(),
            Arc::new(SystemRunner),
            clock.clone(),
        );
        let mut made = Vec::new();
        for i in 0..6 {
            fs::write(p.join("x.txt"), format!("{i}")).unwrap();
            made.push(c.checkpoint_repo(&p).unwrap().unwrap());
            clock.advance(1000);
        }
        // a plain branch, another box's WIP, and a remote-tracking ref must survive
        git(&p, &["branch", "feature"]);
        git(&p, &["branch", "wip/other-box/20200101T000000Z"]);
        git(
            &p,
            &[
                "update-ref",
                "refs/remotes/origin/wip/dev-1/20200101T000000Z",
                "HEAD",
            ],
        );
        // the oldest WIP is checked out: it must not be pruned
        let oldest = made[0].clone();
        fs::remove_file(p.join("x.txt")).unwrap();
        git(&p, &["checkout", "-q", &oldest]);

        let rep = c.checkpoint_all();
        assert!(rep.errors.is_empty(), "{:?}", rep.errors);
        let left = git(
            &p,
            &[
                "for-each-ref",
                "--format=%(refname:short)",
                "refs/heads/wip/dev-1/",
            ],
        );
        let mut left: Vec<_> = left.lines().map(str::to_string).collect();
        left.sort();
        // newest 3 kept (+ the checked-out oldest, skipped); the 2 in between are gone
        let mut want = vec![oldest, made[3].clone(), made[4].clone(), made[5].clone()];
        want.sort();
        assert_eq!(left, want);
        assert_eq!(rep.pruned, 2);
        let others = git(&p, &["for-each-ref", "--format=%(refname)"]);
        assert!(others.contains("refs/heads/feature"));
        assert!(others.contains("refs/heads/wip/other-box/20200101T000000Z"));
        assert!(others.contains("refs/remotes/origin/wip/dev-1/20200101T000000Z"));
    }

    // ---- the quiesce snapshot (refs/ozbox/wip) ----------------------------------------------------------------------

    fn hidden_opts() -> HiddenOpts {
        HiddenOpts {
            per_git_s: None,
            ..HiddenOpts::default()
        }
    }

    fn refs(p: &Path) -> Vec<String> {
        git(p, &["for-each-ref", "--format=%(refname)", HIDDEN_PREFIX])
            .lines()
            .map(str::to_string)
            .collect()
    }

    #[test]
    fn a_hidden_snapshot_touches_nothing_of_the_persons() {
        let d = tempfile::tempdir().unwrap();
        let p = d.path().join("p");
        repo(&p);
        fs::write(p.join("a.txt"), "one\ntwo\n").unwrap();
        fs::write(p.join("new.txt"), "new\n").unwrap();
        fs::write(p.join("ignored.log"), "noise\n").unwrap();
        fs::remove_file(p.join("gone.txt")).unwrap();
        fs::write(p.join("staged.txt"), "s\n").unwrap();
        git(&p, &["add", "staged.txt"]);
        git(&p, &["stash", "push", "-q", "-m", "mine", "--", "a.txt"]);
        fs::write(p.join("a.txt"), "one\nthree\n").unwrap();
        git(
            &p,
            &["remote", "add", "origin", "https://example.invalid/x.git"],
        );
        let index_before = fs::read(p.join(".git/index")).unwrap();
        let stash_before = git(&p, &["stash", "list"]);
        let status_before = git(&p, &["status", "--porcelain"]);
        let head_before = git(&p, &["rev-parse", "HEAD"]);
        let remotes_before = git(&p, &["remote", "-v"]);
        let branches_before = git(&p, &["branch", "--list"]);

        let rep = cp(d.path(), Arc::new(FakeClock::new(T0))).snapshot_all_hidden(&hidden_opts());
        assert!(rep.errors.is_empty(), "{:?}", rep.errors);
        assert_eq!(rep.branches.len(), 1);
        let r = &rep.branches[0].branch;
        assert_eq!(r, "refs/ozbox/wip/20261109T123456Z");

        // everything uncommitted, untracked included, ignored not
        assert_eq!(git(&p, &["show", &format!("{r}:a.txt")]), "one\nthree");
        assert_eq!(git(&p, &["show", &format!("{r}:new.txt")]), "new");
        assert_eq!(git(&p, &["show", &format!("{r}:staged.txt")]), "s");
        let files = git(&p, &["ls-tree", "-r", "--name-only", r]);
        assert!(
            !files.contains("gone.txt") && !files.contains("ignored.log"),
            "{files}"
        );
        assert_eq!(git(&p, &["rev-parse", &format!("{r}^")]), head_before);

        // untouched: the real index (byte for byte), stash list, status, HEAD, branches, remotes, working tree
        assert_eq!(fs::read(p.join(".git/index")).unwrap(), index_before);
        assert_eq!(git(&p, &["stash", "list"]), stash_before);
        assert_eq!(git(&p, &["status", "--porcelain"]), status_before);
        assert_eq!(git(&p, &["rev-parse", "HEAD"]), head_before);
        assert_eq!(git(&p, &["remote", "-v"]), remotes_before);
        assert_eq!(git(&p, &["branch", "--list"]), branches_before);
        assert_eq!(fs::read_to_string(p.join("a.txt")).unwrap(), "one\nthree\n");
        assert!(
            !git(&p, &["branch", "-a"]).contains("ozbox"),
            "not a branch"
        );
        let leftovers: Vec<_> = fs::read_dir(p.join(".git"))
            .unwrap()
            .flatten()
            .filter(|e| {
                e.file_name()
                    .to_string_lossy()
                    .starts_with("ozbox-wip-index")
            })
            .collect();
        assert!(leftovers.is_empty());
    }

    /// The restore the docs give does not overwrite anything newer: a copy of the snapshot goes into a separate folder.
    #[test]
    fn the_documented_restore_into_a_separate_folder_never_touches_newer_work() {
        let d = tempfile::tempdir().unwrap();
        let p = d.path().join("p");
        repo(&p);
        fs::write(p.join("a.txt"), "edited\n").unwrap();
        fs::write(p.join("new.txt"), "untracked\n").unwrap();
        fs::remove_file(p.join("gone.txt")).unwrap();
        let rep = cp(d.path(), Arc::new(FakeClock::new(T0))).snapshot_all_hidden(&hidden_opts());
        let r = rep.branches[0].branch.clone();
        // work goes on after the snapshot: a newer edit, the deleted file made again, a new file
        fs::write(p.join("a.txt"), "newer work\n").unwrap();
        fs::write(p.join("gone.txt"), "recreated\n").unwrap();
        fs::write(p.join("later.txt"), "later\n").unwrap();
        let status_before = git(&p, &["status", "--porcelain"]);

        // the commands of the message, as printed (`<ref>` filled in)
        let copy = d.path().join("recovered");
        let sh = std::process::Command::new("sh")
            .arg("-c")
            .arg(format!(
                "mkdir '{c}' && git archive {r} | tar -x -C '{c}'",
                c = copy.display()
            ))
            .current_dir(&p)
            .output()
            .unwrap();
        assert!(
            sh.status.success(),
            "{}",
            String::from_utf8_lossy(&sh.stderr)
        );
        assert_eq!(fs::read_to_string(copy.join("a.txt")).unwrap(), "edited\n");
        assert_eq!(
            fs::read_to_string(copy.join("new.txt")).unwrap(),
            "untracked\n"
        );
        assert!(
            !copy.join("gone.txt").exists(),
            "it was deleted in the snapshot"
        );

        // nothing in the working folder changed
        assert_eq!(fs::read_to_string(p.join("a.txt")).unwrap(), "newer work\n");
        assert_eq!(
            fs::read_to_string(p.join("gone.txt")).unwrap(),
            "recreated\n"
        );
        assert_eq!(fs::read_to_string(p.join("later.txt")).unwrap(), "later\n");
        assert_eq!(git(&p, &["status", "--porcelain"]), status_before);
        // `git diff HEAD <ref>` shows what it holds and `git show <ref>:<file>` prints one file
        assert!(git(&p, &["diff", "--stat", "HEAD", &r]).contains("a.txt"));
        assert_eq!(git(&p, &["show", &format!("{r}:a.txt")]), "edited");
    }

    #[test]
    fn the_restore_message_warns_that_an_in_place_restore_replaces_newer_work() {
        // the message lives in the command's crate; the daemon-side guard is that a restore into place really does
        // destroy newer work, which is why the documented form is a separate folder
        let d = tempfile::tempdir().unwrap();
        let p = d.path().join("p");
        repo(&p);
        fs::write(p.join("a.txt"), "edited\n").unwrap();
        let rep = cp(d.path(), Arc::new(FakeClock::new(T0))).snapshot_all_hidden(&hidden_opts());
        let r = rep.branches[0].branch.clone();
        fs::write(p.join("a.txt"), "newer work\n").unwrap();
        git(
            &p,
            &["restore", &format!("--source={r}"), "--worktree", "--", "."],
        );
        assert_eq!(fs::read_to_string(p.join("a.txt")).unwrap(), "edited\n");
    }

    #[test]
    fn a_repository_in_the_box_users_home_is_covered_and_so_is_a_nested_one() {
        let d = tempfile::tempdir().unwrap();
        // /work/home/ozbox/proj, /work/repos/web with a submodule-like nested repository
        let home_repo = d.path().join("home").join("ozbox").join("proj");
        repo(&home_repo);
        fs::write(home_repo.join("a.txt"), "edited in the home folder\n").unwrap();
        let web = d.path().join("repos").join("web");
        repo(&web);
        let nested = web.join("libs").join("inner");
        repo(&nested);
        fs::write(nested.join("a.txt"), "edited inside the nested repo\n").unwrap();
        // the walk skips dot folders and node_modules
        let hidden = d.path().join("home").join("ozbox").join(".cache").join("c");
        repo(&hidden);
        fs::write(hidden.join("a.txt"), "x").unwrap();

        let mut cfg = CheckpointConfig::new(d.path().join("repos"));
        cfg.snapshot_root = Some(d.path().to_path_buf());
        let c = Checkpointer::new(
            cfg,
            BoxName::new("dev-1").unwrap(),
            Arc::new(SystemRunner),
            Arc::new(FakeClock::new(T0)),
        );
        let rep = c.snapshot_all_hidden(&hidden_opts());
        assert!(rep.errors.is_empty(), "{:?}", rep.errors);
        let names: Vec<_> = rep.branches.iter().map(|b| b.repo.clone()).collect();
        // the parent sees the nested repository as a new folder, so it is saved too (as a link to it); the nested one has
        // its own snapshot of what is inside
        assert_eq!(
            names,
            vec![
                "home/ozbox/proj".to_string(),
                "repos/web".to_string(),
                "repos/web/libs/inner".to_string()
            ]
        );
        let r = &rep.branches[2].branch;
        assert_eq!(
            git(&nested, &["show", &format!("{r}:a.txt")]),
            "edited inside the nested repo"
        );
    }

    #[test]
    fn a_repository_with_only_new_files_is_saved_whatever_the_persons_untracked_setting() {
        let d = tempfile::tempdir().unwrap();
        let p = d.path().join("p");
        repo(&p);
        git(&p, &["config", "status.showUntrackedFiles", "no"]);
        fs::write(p.join("only-new.txt"), "n\n").unwrap();
        assert_eq!(
            git(&p, &["status", "--porcelain"]),
            "",
            "the setting hides it from a plain status"
        );
        let rep = cp(d.path(), Arc::new(FakeClock::new(T0))).snapshot_all_hidden(&hidden_opts());
        assert!(rep.errors.is_empty(), "{:?}", rep.errors);
        assert_eq!(rep.branches.len(), 1, "saved, not 'nothing to save'");
        let r = &rep.branches[0].branch;
        assert_eq!(git(&p, &["show", &format!("{r}:only-new.txt")]), "n");
    }

    #[test]
    fn names_made_in_the_same_second_sort_in_the_order_they_were_made() {
        let d = tempfile::tempdir().unwrap();
        let p = d.path().join("p");
        repo(&p);
        let c = cp(d.path(), Arc::new(FakeClock::new(T0)));
        let mut made = Vec::new();
        for i in 0..12 {
            fs::write(p.join("a.txt"), format!("{i}")).unwrap();
            made.push(
                c.snapshot_all_hidden(&hidden_opts()).branches[0]
                    .branch
                    .clone(),
            );
        }
        let mut sorted = made.clone();
        sorted.sort();
        assert_eq!(made, sorted, "{made:?}");
        assert!(made[10].ends_with("-11") && made[1].ends_with("-02"));
    }

    #[test]
    fn leftover_temporary_indexes_are_swept_only_when_old_and_only_ours() {
        let d = tempfile::tempdir().unwrap();
        let p = d.path().join("p");
        repo(&p);
        let old = p.join(".git/ozbox-wip-index-20200101T000000Z-1");
        let old_lock = p.join(".git/ozbox-wip-index-20200101T000000Z-1.lock");
        let fresh = p.join(".git/ozbox-wip-index-fresh-2");
        let other = p.join(".git/somebody-elses-file");
        for f in [&old, &old_lock, &fresh, &other] {
            fs::write(f, "x").unwrap();
        }
        let long_ago = std::time::SystemTime::now() - std::time::Duration::from_secs(7200);
        for f in [&old, &old_lock, &other] {
            fs::File::options()
                .write(true)
                .open(f)
                .unwrap()
                .set_modified(long_ago)
                .unwrap();
        }
        fs::write(p.join("a.txt"), "edited\n").unwrap();
        let rep = cp(d.path(), Arc::new(FakeClock::new(T0))).snapshot_all_hidden(&hidden_opts());
        assert_eq!(rep.branches.len(), 1);
        assert!(
            !old.exists() && !old_lock.exists(),
            "old leftovers of ours are gone"
        );
        assert!(fresh.exists(), "a recent one may be in use");
        assert!(other.exists(), "never a file that is not ours");
    }

    #[test]
    fn a_ref_lock_that_was_not_ours_is_left_and_the_failure_is_reported() {
        let d = tempfile::tempdir().unwrap();
        let p = d.path().join("p");
        repo(&p);
        fs::write(p.join("a.txt"), "edited\n").unwrap();
        let lock = p.join(".git/refs/ozbox/wip/20261109T123456Z.lock");
        fs::create_dir_all(lock.parent().unwrap()).unwrap();
        fs::write(&lock, "").unwrap();
        let rep = cp(d.path(), Arc::new(FakeClock::new(T0))).snapshot_all_hidden(&hidden_opts());
        assert!(
            rep.errors.iter().any(|e| e.contains("update-ref failed")),
            "{:?}",
            rep.errors
        );
        assert!(
            lock.exists(),
            "a lock that was there before is never removed"
        );
    }

    #[test]
    fn the_git_directory_is_found_without_running_git() {
        let d = tempfile::tempdir().unwrap();
        let p = d.path().join("p");
        repo(&p);
        assert_eq!(common_dir_of(&p), Some(p.join(".git")));
        // a linked worktree: its own git directory names the common one
        let wt = d.path().join("wt");
        git(
            &p,
            &["worktree", "add", "-q", "--detach", &wt.to_string_lossy()],
        );
        let common = common_dir_of(&wt).unwrap();
        assert_eq!(
            fs::canonicalize(&common).unwrap(),
            fs::canonicalize(p.join(".git")).unwrap()
        );
        assert_eq!(common_dir_of(&d.path().join("none")), None);
    }

    #[test]
    fn the_total_limit_covers_the_whole_call_and_a_call_is_cut_to_what_is_left() {
        let b = Bound {
            per: Some(20),
            deadline: std::time::Instant::now() + std::time::Duration::from_secs(3),
        };
        assert_eq!(b.secs(), Some(3), "cut to what is left");
        let b = Bound {
            per: Some(20),
            deadline: std::time::Instant::now(),
        };
        assert!(b.alive().is_err());
        assert_eq!(b.secs(), Some(1), "never less than a second");
        let b = Bound {
            per: None,
            deadline: std::time::Instant::now() + std::time::Duration::from_secs(3),
        };
        assert_eq!(b.secs(), None);
    }

    #[cfg(unix)]
    #[test]
    fn no_hook_and_no_monitor_of_the_repository_runs() {
        use std::os::unix::fs::PermissionsExt;
        let d = tempfile::tempdir().unwrap();
        let p = d.path().join("p");
        repo(&p);
        fs::write(p.join("a.txt"), "edited\n").unwrap();
        let marker = d.path().join("RAN");
        let script = format!("#!/bin/sh\necho ran >> '{}'\nexit 0\n", marker.display());
        let hooks = p.join(".git/hooks");
        fs::create_dir_all(&hooks).unwrap();
        for h in [
            "pre-commit",
            "post-commit",
            "commit-msg",
            "post-index-change",
            "reference-transaction",
            "pre-auto-gc",
            "post-checkout",
        ] {
            let f = hooks.join(h);
            fs::write(&f, &script).unwrap();
            fs::set_permissions(&f, fs::Permissions::from_mode(0o755)).unwrap();
        }
        let fsm = d.path().join("fsm.sh");
        fs::write(&fsm, &script).unwrap();
        fs::set_permissions(&fsm, fs::Permissions::from_mode(0o755)).unwrap();
        git(&p, &["config", "core.fsmonitor", &fsm.to_string_lossy()]);
        // a hooks path the repository's own config sets must not be used either
        git(&p, &["config", "core.hooksPath", &hooks.to_string_lossy()]);
        let rep = cp(d.path(), Arc::new(FakeClock::new(T0))).snapshot_all_hidden(&hidden_opts());
        assert!(rep.errors.is_empty(), "{:?}", rep.errors);
        assert_eq!(rep.branches.len(), 1);
        assert!(!marker.exists(), "something of the repository ran");
    }

    #[test]
    fn a_hidden_snapshot_never_pushes() {
        let d = tempfile::tempdir().unwrap();
        let bare = d.path().join("remote.git");
        fs::create_dir_all(&bare).unwrap();
        git(&bare, &["init", "-q", "--bare"]);
        let p = d.path().join("w").join("p");
        repo(&p);
        git(&p, &["remote", "add", "origin", &bare.to_string_lossy()]);
        let mut cfg = CheckpointConfig::new(d.path().join("w"));
        cfg.push_remote = Some("origin".into()); // the other path's setting must not reach this one
        let c = Checkpointer::new(
            cfg,
            BoxName::new("dev-1").unwrap(),
            Arc::new(SystemRunner),
            Arc::new(FakeClock::new(T0)),
        );
        fs::write(p.join("a.txt"), "edited\n").unwrap();
        let rep = c.snapshot_all_hidden(&hidden_opts());
        assert_eq!(rep.branches.len(), 1);
        assert_eq!(
            git(&bare, &["for-each-ref"]),
            "",
            "nothing reached the remote"
        );
    }

    #[test]
    fn a_second_quiesce_of_the_same_state_saves_nothing_new() {
        let d = tempfile::tempdir().unwrap();
        let p = d.path().join("p");
        repo(&p);
        let clock = Arc::new(FakeClock::new(T0));
        let c = cp(d.path(), clock.clone());
        fs::write(p.join("a.txt"), "edited\n").unwrap();
        let first = c.snapshot_all_hidden(&hidden_opts()).branches[0]
            .branch
            .clone();
        clock.advance(5_000);
        let second = c.snapshot_all_hidden(&hidden_opts()).branches[0]
            .branch
            .clone();
        assert_eq!(first, second);
        assert_eq!(refs(&p).len(), 1);
        fs::write(p.join("a.txt"), "edited again\n").unwrap();
        clock.advance(5_000);
        let third = c.snapshot_all_hidden(&hidden_opts()).branches[0]
            .branch
            .clone();
        assert_ne!(first, third);
        assert_eq!(refs(&p).len(), 2);
        // a clean repo and one with only ignored files write nothing and are not reported
        let q = d.path().join("q");
        repo(&q);
        fs::write(q.join("ignored.log"), "x").unwrap();
        let rep = c.snapshot_all_hidden(&hidden_opts());
        assert_eq!(rep.branches.len(), 1, "only p");
        assert!(refs(&q).is_empty());
    }

    #[test]
    fn hidden_snapshots_are_pruned_in_their_own_namespace_only() {
        let d = tempfile::tempdir().unwrap();
        let p = d.path().join("p");
        repo(&p);
        let clock = Arc::new(FakeClock::new(T0));
        let c = cp(d.path(), clock.clone());
        git(&p, &["branch", "wip/dev-1/20200101T000000Z"]);
        git(&p, &["update-ref", "refs/ozbox/other", "HEAD"]);
        let o = HiddenOpts {
            keep: 2,
            ..hidden_opts()
        };
        for i in 0..4 {
            fs::write(p.join("a.txt"), format!("{i}")).unwrap();
            c.snapshot_all_hidden(&o);
            clock.advance(2_000);
        }
        assert_eq!(refs(&p).len(), 2);
        let all = git(&p, &["for-each-ref", "--format=%(refname)"]);
        assert!(
            all.contains("refs/ozbox/other")
                && all.contains("refs/heads/wip/dev-1/20200101T000000Z")
        );
    }

    #[test]
    fn the_stop_takes_the_hidden_snapshot_and_pushes_nothing_unless_the_pushing_checkpoint_is_asked_for(
    ) {
        let d = tempfile::tempdir().unwrap();
        let bare = d.path().join("remote.git");
        fs::create_dir_all(&bare).unwrap();
        git(&bare, &["init", "-q", "--bare"]);
        let p = d.path().join("w").join("p");
        repo(&p);
        git(&p, &["remote", "add", "origin", &bare.to_string_lossy()]);
        let mut cfg = CheckpointConfig::new(d.path().join("w"));
        cfg.push_remote = Some("origin".into());
        let c = Checkpointer::new(
            cfg,
            BoxName::new("dev-1").unwrap(),
            Arc::new(SystemRunner),
            Arc::new(FakeClock::new(T0)),
        );
        fs::write(p.join("a.txt"), "edited\n").unwrap();
        // the default: a hidden ref, no visible branch, nothing at the remote
        let rep = c.on_stop_with(false, None);
        assert_eq!(rep.branches.len(), 1, "{:?}", rep.errors);
        assert!(rep.branches[0].branch.starts_with(HIDDEN_PREFIX));
        assert_eq!(refs(&p).len(), 1);
        assert_eq!(
            git(&p, &["branch", "--list", "wip/*"]),
            "",
            "no visible branch"
        );
        assert_eq!(git(&bare, &["for-each-ref"]), "", "nothing was pushed");
        assert_eq!(
            git(&p, &["status", "--porcelain"]),
            "M a.txt",
            "the tree is as it was"
        );
        // the explicit opt-in is the old one: a visible branch, pushed
        let rep = c.on_stop_with(true, None);
        assert_eq!(rep.branches.len(), 1, "{:?}", rep.errors);
        assert!(git(&p, &["branch", "--list", "wip/*"]).contains("wip/dev-1/"));
        assert!(git(&bare, &["for-each-ref"]).contains("refs/heads/wip/dev-1/"));
    }

    #[test]
    fn a_runs_pause_writes_the_local_branch_and_pushes_only_on_the_opt_in() {
        let d = tempfile::tempdir().unwrap();
        let bare = d.path().join("remote.git");
        fs::create_dir_all(&bare).unwrap();
        git(&bare, &["init", "-q", "--bare"]);
        let p = d.path().join("w").join("p");
        repo(&p);
        git(&p, &["remote", "add", "origin", &bare.to_string_lossy()]);
        let mut cfg = CheckpointConfig::new(d.path().join("w"));
        cfg.push_remote = Some("origin".into());
        let c = Checkpointer::new(
            cfg,
            BoxName::new("dev-1").unwrap(),
            Arc::new(SystemRunner),
            Arc::new(FakeClock::new(T0)),
        );
        fs::write(p.join("a.txt"), "edited\n").unwrap();
        let rep = c.checkpoint_all_for_run(false);
        assert_eq!(rep.branches.len(), 1, "{:?}", rep.errors);
        let branch = rep.branches[0].branch.clone();
        assert!(branch.starts_with("wip/dev-1/"));
        assert!(git(&p, &["branch", "--list", "wip/*"]).contains("wip/dev-1/"));
        assert_eq!(git(&bare, &["for-each-ref"]), "", "nothing was pushed");
        // the resume works from the local branch alone
        assert_eq!(
            git(&p, &["show", &format!("{branch}:a.txt")]).trim(),
            "edited"
        );
        // the opt-in pushes
        fs::write(p.join("a.txt"), "edited again\n").unwrap();
        let rep = c.checkpoint_all_for_run(true);
        assert_eq!(rep.branches.len(), 1, "{:?}", rep.errors);
        assert!(git(&bare, &["for-each-ref"]).contains("refs/heads/wip/dev-1/"));
    }

    #[test]
    fn idle_and_interruption_paths_take_the_hidden_snapshot_and_the_opt_in_pushes() {
        for path in ["idle", "interruption"] {
            let d = tempfile::tempdir().unwrap();
            let bare = d.path().join("remote.git");
            fs::create_dir_all(&bare).unwrap();
            git(&bare, &["init", "-q", "--bare"]);
            let p = d.path().join("w").join("p");
            repo(&p);
            git(&p, &["remote", "add", "origin", &bare.to_string_lossy()]);
            let mut cfg = CheckpointConfig::new(d.path().join("w"));
            cfg.push_remote = Some("origin".into());
            let c = Checkpointer::new(
                cfg,
                BoxName::new("dev-1").unwrap(),
                Arc::new(SystemRunner),
                Arc::new(FakeClock::new(T0)),
            );
            fs::write(p.join("a.txt"), "edited\n").unwrap();
            // the same bound as the stop, without the per-call `timeout` command a test host may lack
            let run = |push: bool| {
                if push {
                    // the named entry points reach the pushing checkpoint only through this flag
                    match path {
                        "idle" => c.on_idle(true),
                        _ => c.on_interruption(true),
                    }
                } else {
                    c.on_stop_with(false, None)
                }
            };
            let rep = run(false);
            assert_eq!(rep.branches.len(), 1, "{path}: {:?}", rep.errors);
            assert!(rep.branches[0].branch.starts_with(HIDDEN_PREFIX));
            assert_eq!(refs(&p).len(), 1, "{path}: one hidden ref");
            assert_eq!(git(&p, &["branch", "--list", "wip/*"]), "", "{path}");
            assert_eq!(git(&bare, &["for-each-ref"]), "", "{path}: nothing pushed");
            let rep = run(true);
            assert_eq!(rep.branches.len(), 1, "{path}: {:?}", rep.errors);
            assert!(git(&bare, &["for-each-ref"]).contains("refs/heads/wip/dev-1/"));
        }
        // the shapes of the two automatic call sites: neither calls the pushing checkpoint directly
        let main = include_str!("main.rs");
        assert_eq!(
            main.matches("cp.checkpoint_all()").count(),
            0,
            "an automatic path must go through on_idle / on_interruption / on_stop"
        );
        assert!(main.contains("cp.on_idle(") && main.contains("cp.on_interruption("));
    }

    #[test]
    fn a_lock_that_git_holds_is_never_removed_by_the_prune() {
        let d = tempfile::tempdir().unwrap();
        let p = d.path().join("p");
        repo(&p);
        let c = cp(d.path(), Arc::new(FakeClock::new(T0)));
        for n in 1..=3 {
            git(
                &p,
                &[
                    "update-ref",
                    &format!("refs/ozbox/wip/2026110{n}T000000Z"),
                    "HEAD",
                ],
            );
        }
        git(&p, &["pack-refs", "--all"]);
        // another git (a person's, or an agent's) holds the packed-refs lock while the prune runs
        let lock = p.join(".git").join("packed-refs.lock");
        fs::write(&lock, "someone else's\n").unwrap();
        let b = Bound {
            per: None,
            deadline: std::time::Instant::now() + std::time::Duration::from_secs(60),
        };
        let res = c.prune_hidden(&p, &b, 1);
        assert!(res.is_err(), "the delete could not take the lock");
        assert_eq!(
            fs::read_to_string(&lock).unwrap(),
            "someone else's\n",
            "their lock is untouched"
        );
    }

    #[test]
    fn a_hidden_snapshot_older_than_fourteen_days_is_removed_in_our_namespace_only() {
        let d = tempfile::tempdir().unwrap();
        let p = d.path().join("p");
        repo(&p);
        let c = cp(d.path(), Arc::new(FakeClock::new(T0))); // 2026-11-09
        for r in [
            "refs/ozbox/wip/20260101T000000Z",    // far too old
            "refs/ozbox/wip/20261020T000000Z-02", // 20 days old
            "refs/ozbox/wip/20261101T000000Z",    // 8 days old
            "refs/ozbox/wip/20261108T000000Z",    // yesterday
            "refs/ozbox/wip/not-ours",            // a name this feature did not make
            "refs/ozbox/other",
            "refs/heads/wip/dev-1/20200101T000000Z",
        ] {
            git(&p, &["update-ref", r, "HEAD"]);
        }
        let b = Bound {
            per: None,
            deadline: std::time::Instant::now() + std::time::Duration::from_secs(60),
        };
        // plenty of room by count: only age removes
        assert_eq!(c.prune_hidden(&p, &b, 20).unwrap(), 2);
        let left = refs(&p);
        assert!(
            left.contains(&"refs/ozbox/wip/20261101T000000Z".to_string())
                && left.contains(&"refs/ozbox/wip/20261108T000000Z".to_string())
                && left.contains(&"refs/ozbox/wip/not-ours".to_string())
                && !left
                    .iter()
                    .any(|r| r.contains("20260101") || r.contains("20261020")),
            "{left:?}"
        );
        let all = git(&p, &["for-each-ref", "--format=%(refname)"]);
        assert!(all.contains("refs/ozbox/other") && all.contains("refs/heads/wip/dev-1/2020"));
    }

    #[test]
    fn a_home_or_credential_repository_is_not_saved_and_says_so_and_a_huge_new_file_is_left_out() {
        let d = tempfile::tempdir().unwrap();
        // the box user's home is a dotfiles repository
        let home = d.path().join("home").join("ozbox");
        repo(&home);
        fs::create_dir_all(home.join(".ssh")).unwrap();
        fs::write(home.join(".ssh").join("id_ed25519"), "PRIVATE KEY\n").unwrap();
        fs::write(home.join("a.txt"), "edited\n").unwrap();
        // another repository with a credentials folder at its top
        let odd = d.path().join("repos").join("odd");
        repo(&odd);
        fs::create_dir_all(odd.join(".aws")).unwrap();
        fs::write(odd.join(".aws").join("credentials"), "secret\n").unwrap();
        fs::write(odd.join("a.txt"), "edited\n").unwrap();
        // an ordinary repository with a new file over the cap (sparse: it costs no disk)
        let web = d.path().join("repos").join("web");
        repo(&web);
        fs::write(web.join("a.txt"), "edited\n").unwrap();
        let big = fs::File::create(web.join("huge.bin")).unwrap();
        big.set_len(MAX_UNTRACKED_BYTES + 1).unwrap();
        fs::write(web.join("small.txt"), "fine\n").unwrap();
        let mut cfg = CheckpointConfig::new(d.path().join("repos"));
        cfg.snapshot_root = Some(d.path().to_path_buf());
        cfg.home_dir = Some(home.clone());
        let c = Checkpointer::new(
            cfg,
            BoxName::new("dev-1").unwrap(),
            Arc::new(SystemRunner),
            Arc::new(FakeClock::new(T0)),
        );
        let rep = c.snapshot_all_hidden(&hidden_opts());
        assert!(rep.errors.is_empty(), "{:?}", rep.errors);
        assert!(
            refs(&home).is_empty() && refs(&odd).is_empty(),
            "nothing was written there"
        );
        assert!(
            rep.skipped
                .iter()
                .any(|s| s == "home/ozbox: not saved: home/dotfiles repo"),
            "{:?}",
            rep.skipped
        );
        assert!(
            rep.skipped
                .iter()
                .any(|s| s == "repos/odd: not saved: home/dotfiles repo"),
            "{:?}",
            rep.skipped
        );
        assert!(
            rep.skipped
                .iter()
                .any(|s| s == "repos/web: 1 untracked file(s) larger than 50 MB were not saved"),
            "{:?}",
            rep.skipped
        );
        assert!(
            rep.skipped.iter().all(|s| !s.contains("huge.bin")),
            "no file names are reported"
        );
        let r = refs(&web);
        assert_eq!(r.len(), 1);
        let tree = git(&web, &["ls-tree", "-r", "--name-only", &r[0]]);
        assert!(
            tree.contains("small.txt") && !tree.contains("huge.bin"),
            "{tree}"
        );
        assert_eq!(git(&web, &["show", &format!("{}:a.txt", r[0])]), "edited");
    }

    #[test]
    fn an_unborn_repo_and_a_time_limit_are_handled() {
        let d = tempfile::tempdir().unwrap();
        let q = d.path().join("unborn");
        fs::create_dir_all(&q).unwrap();
        git(&q, &["init", "-q", "-b", "main"]);
        fs::write(q.join("f"), "x").unwrap();
        let c = cp(d.path(), Arc::new(FakeClock::new(T0)));
        let rep = c.snapshot_all_hidden(&hidden_opts());
        assert_eq!(
            git(&q, &["show", &format!("{}:f", rep.branches[0].branch)]),
            "x"
        );
        let o = HiddenOpts {
            total: std::time::Duration::ZERO,
            ..hidden_opts()
        };
        let rep = c.snapshot_all_hidden(&o);
        assert!(
            rep.errors.iter().any(|e| e.contains("time limit")),
            "{:?}",
            rep.errors
        );
    }

    #[test]
    fn every_git_call_of_a_hidden_snapshot_is_bounded_and_hardened() {
        let d = tempfile::tempdir().unwrap();
        let p = d.path().join("p");
        repo(&p);
        let rec = Arc::new(RecordingRunner::new());
        let c = Checkpointer::new(
            CheckpointConfig::new(d.path()),
            BoxName::new("dev-1").unwrap(),
            rec.clone(),
            Arc::new(FakeClock::new(T0)),
        );
        rec.reply(ozbox_core::Output {
            status: Some(0),
            ..Default::default()
        }); // status: clean, so one git call and then the final sync
        c.snapshot_all_hidden(&HiddenOpts::default());
        let calls = rec.calls();
        let first = &calls[0];
        assert_eq!(first.program, "timeout");
        assert_eq!(&first.args[..4], ["-k", "2", "20", "git"]);
        assert!(first.args.iter().any(|a| a == "core.hooksPath=/dev/null"));
        assert!(first.args.iter().any(|a| a == "core.fsmonitor=false"));
        assert_eq!(
            calls.last().unwrap().program,
            "timeout",
            "the final sync is bounded too"
        );
        assert!(calls.iter().all(|c| !c.args.iter().any(|a| a == "push")));
    }
}
