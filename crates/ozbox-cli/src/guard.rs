//! The commit barrier (ADR 0023): a commit or a push that contains a key does not leave the box.
//!
//! Three git hooks call `ozbox guard hook <name>`. The hook reads what is being committed or pushed (the lines a change adds, the
//! names of its files, and the messages of its commits and tags; `guard_diff` says how git's output is read), looks for the
//! shapes real keys have (a private key block, a cloud or payment provider's prefix, a signed token, a password in a connection
//! address) and asks the box's secrets service whether any stored value appears in it, in any of the forms a value gets hidden
//! in. The service answers with the names of the secrets it matched, never a value, and the hook prints only a file, a line
//! number and a rule. Nothing the hook prints, logs or sends back holds a matched value.
//!
//! The hook is the box user's, so it is a barrier against accident and against an agent that was told to commit a key, not
//! against one that is determined: `git commit --no-verify` skips `pre-commit` and a repository's own config can point
//! git elsewhere. So it does not stand alone. `post-commit` is not skipped by `--no-verify`, so it checks what was
//! committed and, finding a key, takes the commit back (`reset --soft`) and says that the barrier was skipped. A key
//! that is sent anyway meets the runner's closed network (`egress`), GitHub's own push protection, and `pre-push`, which reads
//! every commit the target remote is not known to have (what git says it has, and the tracking refs of a remote that is fetched
//! from and pushed to the same address). What the hooks do not read is listed in ADR 0041 (UTF-16 files, Git LFS objects,
//! archives, ref names, `core.hooksPath` and `push --no-verify`).
//!
//! The one way past it is a reviewed override: an approval from the dashboard (`guard-override` scope, spent once) given
//! to the commit in `OZBOX_GUARD_APPROVAL`. The service records it.

use std::io::Read;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

/// A place a key was found. Never the key.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Finding {
    /// The commit it was found in (a push); empty for a staged change.
    pub commit: String,
    pub file: String,
    pub line: u32,
    pub rule: String,
}

fn is_b64url(c: char) -> bool {
    c.is_ascii_alphanumeric() || c == '-' || c == '_'
}

/// Whether text that ends here is the start of a new word: the last character is not a letter or digit (an underscore is not, so
/// `task_AKIA...` holds a key), or it is the end of an escape (`\n`, `\t`, `\r` as two characters, `%3D`, `\u003d` or `\x3d`)
/// that a key in a JSON string, a JavaScript string or an address sits behind.
fn word_boundary(before: &str) -> bool {
    let b = before.as_bytes();
    let Some(&last) = b.last() else { return true };
    if !last.is_ascii_alphanumeric() {
        return true;
    }
    if b.len() >= 2 && matches!(last, b'n' | b't' | b'r') && b[b.len() - 2] == b'\\' {
        return true;
    }
    let hex = |n: usize| b.len() >= n && b[b.len() - n..].iter().all(u8::is_ascii_hexdigit);
    (hex(2) && b.len() >= 3 && b[b.len() - 3] == b'%')
        || (hex(2) && b.len() >= 4 && b[b.len() - 3] == b'x' && b[b.len() - 4] == b'\\')
        || (hex(4) && b.len() >= 6 && b[b.len() - 5] == b'u' && b[b.len() - 6] == b'\\')
}

/// Whether `prefix` occurs in `line` at a word boundary (the character before it is not a letter or a digit), followed by at
/// least `min` characters that satisfy `ok`. `risk-assessment-...` holds no `sk-` key, and `taskAKIA...` no AWS one: a prefix
/// inside a word is not the start of a key.
fn after(line: &str, prefix: &str, min: usize, ok: fn(char) -> bool) -> bool {
    after_where(line, prefix, min, ok, |_| true)
}

/// [`after`], and the characters that follow the prefix (the whole run that satisfies `ok`) must also pass `tail`.
fn after_where(
    line: &str,
    prefix: &str,
    min: usize,
    ok: fn(char) -> bool,
    tail: impl Fn(&str) -> bool,
) -> bool {
    let mut from = 0;
    while let Some(i) = line[from..].find(prefix) {
        let at = from + i;
        let start = at + prefix.len();
        let boundary = word_boundary(&line[..at]);
        let run: &str = {
            let n: usize = line[start..]
                .chars()
                .take_while(|c| ok(*c))
                .map(char::len_utf8)
                .sum();
            &line[start..start + n]
        };
        if boundary && run.chars().count() >= min && tail(run) {
            return true;
        }
        from = start;
    }
    false
}

/// The rules a line trips. Short names a person can act on.
pub fn shape_rules(line: &str) -> Vec<&'static str> {
    let mut v = Vec::new();
    if line.contains("-----BEGIN ") && line.contains("PRIVATE KEY-----") {
        v.push("private-key");
    }
    let upper_digit = |c: char| c.is_ascii_uppercase() || c.is_ascii_digit();
    if after(line, "AKIA", 16, upper_digit) || after(line, "ASIA", 16, upper_digit) {
        v.push("aws-access-key");
    }
    for p in ["sk_live_", "rk_live_", "whsec_"] {
        if after(line, p, 16, |c| c.is_ascii_alphanumeric()) {
            v.push("payment-provider-key");
            break;
        }
    }
    // a real `sk-` key mixes cases or holds digits; a long kebab-case word after "sk-" is text
    let mixed = |t: &str| {
        t.chars()
            .any(|c| c.is_ascii_digit() || c.is_ascii_uppercase())
    };
    if after(line, "sk-ant-", 20, is_b64url) || after_where(line, "sk-", 32, is_b64url, mixed) {
        v.push("model-provider-key");
    }
    for p in ["ghp_", "gho_", "ghu_", "ghs_", "ghr_", "github_pat_"] {
        if after(line, p, 30, is_b64url) {
            v.push("github-token");
            break;
        }
    }
    for p in ["xoxb-", "xoxa-", "xoxp-", "xoxr-", "xoxs-"] {
        if after(line, p, 20, |c| c.is_ascii_alphanumeric() || c == '-') {
            v.push("slack-token");
            break;
        }
    }
    if after(line, "AIza", 35, is_b64url) {
        v.push("google-api-key");
    }
    if signed_token(line) {
        v.push("signed-token");
    }
    if url_password(line) {
        v.push("password-in-address");
    }
    v
}

/// `eyJ…​.eyJ…​.…` : three long dot-separated parts, the first two starting as base64 of `{"`.
fn signed_token(line: &str) -> bool {
    let mut from = 0;
    while let Some(i) = line[from..].find("eyJ") {
        let rest = &line[from + i..];
        let mut parts = rest.splitn(3, '.');
        let (a, b, c) = (parts.next(), parts.next(), parts.next());
        if let (Some(a), Some(b), Some(c)) = (a, b, c) {
            let n = |s: &str| s.chars().take_while(|c| is_b64url(*c)).count();
            if n(a) == a.len()
                && a.len() >= 10
                && b.starts_with("eyJ")
                && n(b) == b.len()
                && b.len() >= 10
                && n(c) >= 10
            {
                return true;
            }
        }
        from += i + 3;
    }
    false
}

/// `scheme://user:password@host` for a database or queue scheme, with a password that is not a placeholder.
fn url_password(line: &str) -> bool {
    const SCHEMES: [&str; 8] = [
        "postgres",
        "postgresql",
        "mysql",
        "mongodb",
        "mongodb+srv",
        "redis",
        "rediss",
        "amqp",
    ];
    let mut from = 0;
    while let Some(i) = line[from..].find("://") {
        let before = &line[..from + i];
        let scheme: String = before
            .chars()
            .rev()
            .take_while(|c| c.is_ascii_alphanumeric() || *c == '+')
            .collect::<Vec<_>>()
            .into_iter()
            .rev()
            .collect();
        let rest = &line[from + i + 3..];
        let auth: &str = rest.split(['/', '?', ' ', '"', '\'']).next().unwrap_or("");
        if SCHEMES.contains(&scheme.to_ascii_lowercase().as_str()) {
            if let Some((cred, _)) = auth.rsplit_once('@') {
                if let Some((_, pw)) = cred.split_once(':') {
                    let placeholder = pw.contains(['$', '{', '<', '*', '%'])
                        || pw.chars().all(|c| c == 'x' || c == 'X');
                    if pw.len() >= 8 && !placeholder {
                        return true;
                    }
                }
            }
        }
        from += i + 3;
    }
    false
}

/// A line that sets a variable of a known public kind (`NEXT_PUBLIC_X=...`, `"VITE_X": "..."`) to a JWT that is an anonymous
/// (client-side) key, and carries no other signed token. That is configuration the page ships on purpose, so the signed-token rule
/// does not apply to it. It is the same judgement a person's public mark gets (`workload_policy::public_mark_refusal`): a token of
/// any other role (a service-role key included), or one that cannot be read, is still a key, whatever the variable is called.
pub fn public_jwt_line(line: &str) -> bool {
    let bytes = line.as_bytes();
    let mut name: Option<&str> = None;
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i].is_ascii_alphanumeric() || bytes[i] == b'_' {
            let start = i;
            while i < bytes.len() && (bytes[i].is_ascii_alphanumeric() || bytes[i] == b'_') {
                i += 1;
            }
            let tok = &line[start..i];
            let mut j = i;
            while j < bytes.len() && matches!(bytes[j], b' ' | b'"' | b'\'' | b'`') {
                j += 1;
            }
            if j < bytes.len()
                && matches!(bytes[j], b'=' | b':')
                && crate::workload_policy::is_public_kind_name(tok)
            {
                name = Some(tok);
            }
        } else {
            i += 1;
        }
    }
    let Some(name) = name else { return false };
    let tokens: Vec<&str> = line
        .split(|c: char| !(is_b64url(c) || c == '.'))
        .filter(|t| t.starts_with("eyJ"))
        .collect();
    !tokens.is_empty()
        && tokens
            .iter()
            .all(|t| crate::workload_policy::public_mark_refusal(name, t, false).is_none())
}

/// A file that is an environment file. The examples people commit on purpose are not.
pub fn is_env_file(path: &str) -> bool {
    let name = path.rsplit('/').next().unwrap_or(path);
    (name == ".env" || name.starts_with(".env."))
        && !["example", "sample", "template", "dist", "defaults"]
            .iter()
            .any(|s| name.ends_with(s))
}

/// What a person's stored secrets are checked by. The real one asks the box's secrets service; a test gives its own.
pub trait Scanner {
    /// Names of the stored secrets whose value is in `text`.
    fn scan(&self, text: &str) -> Result<Vec<String>, String>;
    /// Spend a guard-override approval code, for exactly the change it names (ADR 0041).
    fn override_ok(&self, code: &str, bind: &Binding) -> Result<(), String>;
}

pub use crate::guard_scan::{Checker, Verdict};

/// What a guard-override code is bound to: the repository and the change. A code minted for one tree, or one range of commits,
/// does not pass another.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Binding {
    /// The first 16 hex digits of the hash of the repository's path.
    pub project: String,
    /// The first 16 hex digits of the hash of what is being let through (see `guard_hold`).
    pub change: String,
}

/// Check a diff: the shapes line by line, the stored values over the added text, the names of the files, and any environment file.
/// A diff that cannot be read, or that holds a file git did not print as text, is an error, which holds the change.
pub fn check_diff(diff: &str, scanner: Option<&dyn Scanner>) -> Result<Verdict, String> {
    let mut c = Checker::new(scanner);
    add_diff(&mut c, diff, "", &|_| {
        Err("a file git did not show as text could not be read".to_string())
    })?;
    c.finish()
}

/// Add what `diff` adds, and its paths, to `c`.
fn add_diff(
    c: &mut Checker,
    diff: &str,
    commit: &str,
    binary: &dyn Fn(&str) -> Result<String, String>,
) -> Result<(), String> {
    let (lines, paths) = crate::guard_scan::read_diff(diff, commit, binary)?;
    c.add(lines)?;
    c.add_paths(commit, &paths)
}

/// The words printed for a blocked commit. A file, a line and a rule; never a value and never the name of a stored secret
/// (a stored name is for the person who decides, not for the box user).
pub fn report(v: &Verdict) -> String {
    let mut s =
        String::from("ozbox: this change contains what looks like a key, so it was stopped.\n");
    let at = |commit: &str, file: &str, line: u32| {
        let place = if line == 0 {
            file.to_string()
        } else {
            format!("{file}:{line}")
        };
        if commit.is_empty() {
            place
        } else {
            format!("{place} in {commit}")
        }
    };
    for f in &v.findings {
        s.push_str(&format!(
            "  {}  ({})\n",
            at(&f.commit, &f.file, f.line),
            f.rule
        ));
    }
    for h in &v.stored {
        s.push_str(&format!(
            "  {}  (holds a value this box stores as a secret)\n",
            at(&h.commit, &h.file, h.line)
        ));
    }
    s.push_str("If it is a public value (a web address, a key meant for the browser), say so when you import it: `ozbox secrets import --public NAME`. Otherwise remove the key and rotate it if it was ever real.\n");
    s
}

// ---- git ------------------------------------------------------------------------------------------------------------

/// The most one git command's output is read. More is an error, never a quiet cut: what was not read was not checked.
const GIT_OUT_MAX: usize = 64 * 1024 * 1024;

pub(crate) fn git(dir: &Path, args: &[&str]) -> Result<String, String> {
    git_max(dir, args, GIT_OUT_MAX)
}

pub(crate) fn git_max(dir: &Path, args: &[&str], max: usize) -> Result<String, String> {
    let mut c = Command::new("git")
        .arg("-C")
        .arg(dir)
        .args(args)
        // read the objects a push sends, not the ones `git replace` or a graft file say are there instead
        .env("GIT_NO_REPLACE_OBJECTS", "1")
        .env_remove("GIT_GRAFT_FILE")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .map_err(|_| "git could not be started".to_string())?;
    let mut out = Vec::new();
    if let Some(mut o) = c.stdout.take() {
        let _ = (&mut o).take(max as u64 + 1).read_to_end(&mut out);
    }
    if out.len() > max {
        let _ = c.kill();
        let _ = c.wait();
        return Err(format!(
            "that is more than {} MB of change to read in one piece; split it into smaller commits",
            max / (1024 * 1024)
        ));
    }
    let st = c.wait().map_err(|_| "git failed".to_string())?;
    if !st.success() {
        return Err("git refused".into());
    }
    Ok(String::from_utf8_lossy(&out).to_string())
}

fn is_hex(s: &str) -> bool {
    !s.is_empty() && s.bytes().all(|b| b.is_ascii_hexdigit())
}

/// The one command and flag set every hook reads a change with (see `guard_diff`): `git diff-tree` with [`DIFF_FLAGS`] and
/// [`DIFF_FILTER`], then the trees or the commit.
fn diff_tree(repo: &Path, rest: &[&str]) -> Result<String, String> {
    let mut args = vec!["diff-tree"];
    args.extend(crate::guard_diff::DIFF_FLAGS);
    args.push(crate::guard_diff::DIFF_FILTER);
    args.extend(rest);
    git(repo, &args)
}

/// The tree the staged change would commit (`git write-tree`). The tree, not `git diff` output, is what an override is bound to.
pub fn staged_tree(repo: &Path) -> Result<String, String> {
    let t = git(repo, &["write-tree"])?;
    let t = t.trim().to_string();
    if !is_hex(&t) {
        return Err("the staged tree could not be read".into());
    }
    Ok(t)
}

/// What `tree` adds on top of `HEAD` (or on top of nothing in a repository with no commit yet), read from the tree itself so the
/// text and the tree it is bound to cannot differ.
pub fn tree_diff(repo: &Path, tree: &str) -> Result<String, String> {
    if !is_hex(tree) {
        return Err("that is not a tree".into());
    }
    let base = match git(repo, &["rev-parse", "--verify", "-q", "HEAD^{commit}"]) {
        Ok(h) => h.trim().to_string(),
        Err(_) => git(repo, &["hash-object", "-t", "tree", "/dev/null"])?
            .trim()
            .to_string(),
    };
    diff_tree(repo, &[base.as_str(), tree])
}

/// What `pre-commit` checks: the staged additions.
#[cfg(test)]
pub fn staged_diff(repo: &Path) -> Result<String, String> {
    tree_diff(repo, &staged_tree(repo)?)
}

/// What one commit adds (a merge: what the person who merged wrote, from the combined diff). The same command as the staged
/// change, so what `pre-commit` read is what `post-commit` and `pre-push` read.
pub fn commit_diff(repo: &Path, sha: &str) -> Result<String, String> {
    if !is_hex(sha) {
        return Err("that is not a commit".into());
    }
    diff_tree(repo, &[sha])
}

fn head_sha(repo: &Path) -> Result<String, String> {
    let h = git(repo, &["rev-parse", "--verify", "-q", "HEAD^{commit}"])?;
    let h = h.trim().to_string();
    if is_hex(&h) {
        Ok(h)
    } else {
        Err("HEAD could not be read".into())
    }
}

/// A commit's message: everything after the headers.
pub fn commit_message(repo: &Path, sha: &str) -> Result<String, String> {
    if !is_hex(sha) {
        return Err("that is not a commit".into());
    }
    let obj = git(repo, &["cat-file", "commit", sha])?;
    Ok(obj
        .split_once("\n\n")
        .map(|(_, m)| m.to_string())
        .unwrap_or_default())
}

/// A commit's headers other than `tree` and `parent`: the author and committer, an `encoding`, a signature, and the
/// `mergetag` header that `git merge <signed tag>` writes, which holds the whole tag, its message included. A header's
/// continuation lines (they start with a space) go with it.
pub fn commit_headers(repo: &Path, sha: &str) -> Result<String, String> {
    if !is_hex(sha) {
        return Err("that is not a commit".into());
    }
    let obj = git(repo, &["cat-file", "commit", sha])?;
    let head = obj.split_once("\n\n").map_or(obj.as_str(), |(h, _)| h);
    let mut out = String::new();
    let mut keep = false;
    for l in head.lines() {
        if l.starts_with(' ') {
            // a continuation belongs to the header before it
        } else {
            keep = !(l.starts_with("tree ") || l.starts_with("parent "));
        }
        if keep {
            out.push_str(l);
            out.push('\n');
        }
    }
    Ok(out)
}

/// Read a commit's added lines into `c`: its diff (a merge's binary file whole, from the commit), its file names and, when
/// `message` is set, its message. Returns how much text git printed for the diff. A failure names the commit, because trying
/// again will not help.
fn add_commit(c: &mut Checker, repo: &Path, sha: &str, message: bool) -> Result<usize, String> {
    let label = sha[..sha.len().min(12)].to_string();
    let commit = if message { label.as_str() } else { "" };
    let named = |e: String| format!("{e}; in commit {label}");
    let blob = |path: &str| git(repo, &["cat-file", "blob", &format!("{sha}:{path}")]);
    let diff = commit_diff(repo, sha).map_err(named)?;
    add_diff(c, &diff, commit, &blob).map_err(named)?;
    if message {
        let m = commit_message(repo, sha).map_err(named)?;
        c.add_text(commit, "<commit message>", &m)?;
        let h = commit_headers(repo, sha).map_err(named)?;
        c.add_text(commit, "<commit header>", &h)?;
    }
    Ok(diff.len())
}

/// What `post-commit` checks of the commit just made: its diff and file names (`.0`), and its message (`.1`). They are two
/// verdicts because an approval covers the tree and nothing else.
pub fn check_head(
    repo: &Path,
    scanner: Option<&dyn Scanner>,
) -> Result<(Verdict, Verdict), String> {
    let sha = head_sha(repo)?;
    let mut d = Checker::new(scanner);
    let _ = add_commit(&mut d, repo, &sha, false)?;
    let mut m = Checker::new(scanner);
    m.add_text("", "<commit message>", &commit_message(repo, &sha)?)?;
    m.add_text("", "<commit header>", &commit_headers(repo, &sha)?)?;
    Ok((d.finish()?, m.finish()?))
}

/// Which of this repository's remotes a push goes to, and only when `url` (the address git passes the hook second, after every
/// `insteadOf` and `pushInsteadOf` rewrite) is a push address of that remote (`git remote get-url --push --all`) **and** is also
/// an address it fetches from (`git remote get-url --all`). `arg0` is what git passes first: a remote's name, or the address when
/// the push was by address.
///
/// A remote's tracking refs (`refs/remotes/<name>/*`) record what its *fetch* address has. A remote whose `pushurl` differs, or
/// whose push address a `pushInsteadOf` rewrites, sends somewhere its tracking refs say nothing about (the triangular workflow:
/// fetch from upstream, push to a fork). So `None` there, and `None` when no configured remote matches: nothing is taken as
/// already sent.
pub fn remote_name(repo: &Path, arg0: &str, url: &str) -> Option<String> {
    let names = git(repo, &["remote"]).ok()?;
    let names: Vec<&str> = names.lines().filter(|n| !n.is_empty()).collect();
    let want = crate::guard_hold::normalise_remote(url);
    if want.is_empty() {
        return None;
    }
    let has = |args: &[&str]| -> bool {
        git(repo, args)
            .map(|o| {
                o.lines()
                    .any(|l| crate::guard_hold::normalise_remote(l) == want)
            })
            .unwrap_or(false)
    };
    let same_place = |name: &str| -> bool {
        has(&["remote", "get-url", "--push", "--all", name])
            && has(&["remote", "get-url", "--all", name])
    };
    if names.contains(&arg0) {
        return same_place(arg0).then(|| arg0.to_string());
    }
    names
        .into_iter()
        .find(|n| same_place(n))
        .map(str::to_string)
}

/// The commits a push would send: those the target remote does not have, oldest first. What it has is what git says it has
/// (`olds`, the remote's own shas from the hook's input) and what this repository last saw of *that* remote
/// (`refs/remotes/<remote>/*`). Another remote's tracking branches, which a fetch from elsewhere or one `git update-ref` can set,
/// say nothing about this one.
pub fn push_commits(
    repo: &Path,
    local_sha: &str,
    olds: &[String],
    remote: Option<&str>,
) -> Result<Vec<String>, String> {
    if !is_hex(local_sha) {
        return Err("that is not a commit".into());
    }
    let mut args: Vec<String> = vec![
        "rev-list".into(),
        "--reverse".into(),
        "--topo-order".into(),
        local_sha.into(),
        "--not".into(),
    ];
    args.extend(olds.iter().cloned());
    if let Some(r) = remote.filter(|r| !r.is_empty() && !r.contains(['*', '?', '[', '\\'])) {
        // `--remotes=origin` is the glob `refs/remotes/origin/*`, and its `*` crosses `/`: a remote named `origin/fork` has its
        // refs under it too, and says nothing about `origin`
        let prefix = format!("{r}/");
        for other in git(repo, &["remote"])?
            .lines()
            .filter(|o| o.starts_with(&prefix))
        {
            // the pattern is relative to `refs/remotes/`, which git adds itself for `--remotes`
            args.push(format!("--exclude={other}/*"));
        }
        args.push(format!("--remotes={r}"));
    }
    let args: Vec<&str> = args.iter().map(String::as_str).collect();
    let out = git(repo, &args)?;
    Ok(out.lines().map(str::to_string).collect())
}

/// What a push is held to: more commits than this, or more change, is not read in one go (and says so).
pub const PUSH_MAX_COMMITS: usize = 5000;
/// A push is read in batches of [`crate::guard_scan::CHUNK`] (900 KiB), the service allows about 120 scans a minute, and an approved
/// request lives 15 minutes (ADR 0041): a held push is read again after its approval, so the whole of it must be readable well
/// inside that. 768 MiB is about 870 batches, about 8 minutes at the full budget (a third of the life spare); the old 2 GiB needed about 20 and a held push
/// that size could never be spent.
pub const PUSH_MAX_BYTES: usize = 768 * 1024 * 1024;
/// The most tags, trees and the like a pushed ref may be peeled through, and the most files of a pushed tree that is read.
const PEEL_MAX: usize = 8;
const TREE_FILES_MAX: usize = 20_000;

/// One ref being pushed: what the remote has (zeros for a new one) and what is sent.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Sent {
    pub old: String,
    pub new: String,
}

fn object_type(repo: &Path, sha: &str) -> Result<String, String> {
    if !is_hex(sha) {
        return Err("that is not an object".into());
    }
    Ok(git(repo, &["cat-file", "-t", sha])?.trim().to_string())
}

/// A tree pushed on its own (a ref that points at a tree): every file of it is read, with its name.
fn add_tree(c: &mut Checker, repo: &Path, sha: &str, total: &mut usize) -> Result<(), String> {
    let label = sha[..sha.len().min(12)].to_string();
    let listing = git(repo, &["ls-tree", "-r", "-z", sha])?;
    let mut paths = Vec::new();
    for (n, entry) in listing.split('\0').filter(|e| !e.is_empty()).enumerate() {
        if n >= TREE_FILES_MAX {
            return Err(format!(
                "a pushed tree with more than {TREE_FILES_MAX} files is not read; push a commit instead"
            ));
        }
        let Some((meta, path)) = entry.split_once('\t') else {
            return Err("a pushed tree could not be read".into());
        };
        let f: Vec<&str> = meta.split(' ').collect();
        if f.len() != 3 || f[1] != "blob" {
            continue; // a submodule's commit is not this repository's content
        }
        let text = git(repo, &["cat-file", "blob", f[2]])?;
        *total += text.len();
        if *total > PUSH_MAX_BYTES {
            return Err("this push holds more change than is read together".into());
        }
        let path: String = path
            .chars()
            .map(|ch| if ch.is_control() { '?' } else { ch })
            .collect();
        for (i, l) in text.split('\n').enumerate() {
            c.add(vec![crate::guard_scan::Added {
                commit: label.clone(),
                file: path.clone(),
                line: u32::try_from(i + 1).unwrap_or(u32::MAX),
                text: l.to_string(),
            }])?;
        }
        paths.push(path);
    }
    c.add_paths(&label, &paths)
}

/// What `pre-push` checks for the refs being pushed: every commit the target remote does not have, read commit by commit in
/// batches (diff, file names and message), and every other kind of object a ref can point at: a tag is read and peeled, a blob
/// and a tree are read whole. Nothing is passed without being read. A push too big to read at all is an error that says how to
/// push it in pieces.
pub fn check_push(
    repo: &Path,
    refs: &[Sent],
    remote: Option<&str>,
    scanner: Option<&dyn Scanner>,
) -> Result<Verdict, String> {
    check_push_cap(repo, refs, remote, scanner, PUSH_MAX_COMMITS)
}

fn check_push_cap(
    repo: &Path,
    refs: &[Sent],
    remote: Option<&str>,
    scanner: Option<&dyn Scanner>,
    cap: usize,
) -> Result<Verdict, String> {
    // what the remote has, when this repository still has it: a missing object is not a failure, it only reads more
    let olds: Vec<String> = refs
        .iter()
        .map(|r| r.old.clone())
        .filter(|o| is_hex(o) && !o.bytes().all(|b| b == b'0'))
        .filter(|o| git(repo, &["cat-file", "-e", &format!("{o}^{{commit}}")]).is_ok())
        .collect();
    let mut c = Checker::new(scanner);
    let mut total = 0usize;
    let mut commits: Vec<String> = Vec::new();
    let mut seen = std::collections::BTreeSet::new();
    for r in refs {
        let mut sha = r.new.clone();
        let mut peeled = 0usize;
        loop {
            let label = sha[..sha.len().min(12)].to_string();
            match object_type(repo, &sha)?.as_str() {
                "commit" => {
                    for cmt in push_commits(repo, &sha, &olds, remote)? {
                        if seen.insert(cmt.clone()) {
                            commits.push(cmt);
                        }
                    }
                    break;
                }
                "tag" => {
                    peeled += 1;
                    if peeled > PEEL_MAX {
                        return Err("a pushed tag points through too many tags to read".into());
                    }
                    let t = git(repo, &["cat-file", "tag", &sha])?;
                    total += t.len();
                    c.add_text(&label, "<tag>", &t)?;
                    sha = t
                        .lines()
                        .find_map(|l| l.strip_prefix("object "))
                        .map(|o| o.trim().to_string())
                        .ok_or("a pushed tag could not be read")?;
                }
                "blob" => {
                    let t = git(repo, &["cat-file", "blob", &sha])?;
                    total += t.len();
                    c.add_text(&label, "<blob>", &t)?;
                    break;
                }
                "tree" => {
                    add_tree(&mut c, repo, &sha, &mut total)?;
                    break;
                }
                other => return Err(format!("a pushed {other} object cannot be read")),
            }
        }
    }
    if commits.len() > cap {
        return Err(format!(
            "this push is {} commits that the remote does not have, more than the {cap} that are read together. Push an earlier commit first (`git push <remote> <commit>:<branch>`), then the rest, or fetch the remote first (`git fetch <remote>`) so what it already has is not read again; a push to an address that is not a configured remote reads everything (`git remote add <name> <address>`)",
            commits.len()
        ));
    }
    for sha in &commits {
        // a commit is counted by what git printed for it; the cap is a refusal, never a quiet cut
        total += add_commit(&mut c, repo, sha, true)?;
        if total > PUSH_MAX_BYTES {
            return Err("this push holds more change than is read together: push an earlier commit first (`git push <remote> <commit>:<branch>`), then the rest".into());
        }
    }
    c.finish()
}

// ---- installing the hooks ---------------------------------------------------------------------------------------------

pub const HOOKS: [&str; 3] = ["pre-commit", "post-commit", "pre-push"];
pub const MARKER: &str = "# ozbox-guard (managed)";

/// The hook looks for `ozbox` at the box's own path first, then on PATH. On a box the first always exists, so the fallback
/// never runs; on a laptop it finds a Homebrew install. Both the hook file and PATH belong to whoever works in the
/// repository, so neither is a boundary: the post-commit check is what catches a skipped barrier.
fn wrapper(name: &str) -> String {
    format!(
        "#!/bin/sh\n{MARKER}\n\
         OZBOX=/usr/local/bin/ozbox\n[ -x \"$OZBOX\" ] || OZBOX=$(command -v ozbox || true)\n\
         if [ -n \"$OZBOX\" ]; then \"$OZBOX\" guard hook {name} \"$@\" || exit $?; fi\n\
         [ -x \"$0.ozbox-prev\" ] && exec \"$0.ozbox-prev\" \"$@\"\nexit 0\n"
    )
}

#[derive(Debug, Default, PartialEq, Eq)]
pub struct Install {
    pub repos: usize,
    pub written: usize,
    /// Hooks that were missing from a repository that had them before: someone removed them.
    pub healed: usize,
}

fn hooks_dir(repo: &Path) -> Option<PathBuf> {
    let p = git(repo, &["rev-parse", "--git-path", "hooks"]).ok()?;
    let p = PathBuf::from(p.trim());
    Some(if p.is_absolute() { p } else { repo.join(p) })
}

/// Put the wrappers in one repository. A hook that was already there and is not ours is kept and runs after.
pub fn install_repo(repo: &Path) -> Result<(usize, usize), String> {
    use std::os::unix::fs::PermissionsExt;
    let dir = hooks_dir(repo).ok_or("not a git repository")?;
    std::fs::create_dir_all(&dir).map_err(|_| "the hooks folder could not be made".to_string())?;
    let (mut written, mut healed) = (0, 0);
    let had_any = HOOKS
        .iter()
        .any(|h| dir.join(format!("{h}.ozbox-prev")).exists())
        || HOOKS
            .iter()
            .any(|h| std::fs::read_to_string(dir.join(h)).is_ok_and(|t| t.contains(MARKER)));
    for h in HOOKS {
        let path = dir.join(h);
        let cur = std::fs::read_to_string(&path).ok();
        let want = wrapper(h);
        if cur.as_deref() == Some(want.as_str()) {
            continue;
        }
        if let Some(c) = &cur {
            if !c.contains(MARKER) {
                let prev = dir.join(format!("{h}.ozbox-prev"));
                if !prev.exists() {
                    let _ = std::fs::rename(&path, &prev);
                }
            }
        } else if had_any {
            healed += 1;
        }
        std::fs::write(&path, want).map_err(|_| "a hook could not be written".to_string())?;
        let _ = std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755));
        written += 1;
    }
    Ok((written, healed))
}

/// Whether `p` is the `.git` file of a submodule or a linked worktree (`gitdir: <path>`).
fn is_git_file(p: &Path) -> bool {
    p.is_file() && std::fs::read_to_string(p).is_ok_and(|t| t.trim_start().starts_with("gitdir:"))
}

/// Every repository under `root`, to a depth that finds projects and their worktrees and not the world.
pub fn find_repos(root: &Path, depth: usize) -> Vec<PathBuf> {
    let mut out = Vec::new();
    fn walk(d: &Path, left: usize, out: &mut Vec<PathBuf>) {
        let Ok(rd) = std::fs::read_dir(d) else { return };
        for e in rd.flatten() {
            let p = e.path();
            let name = e.file_name();
            let name = name.to_string_lossy();
            if name == ".git" {
                // a repository's `.git` is a folder; a submodule's or a linked worktree's is a file that says where it is
                if p.is_dir() || is_git_file(&p) {
                    out.push(d.to_path_buf());
                }
                continue;
            }
            if left > 0
                && p.is_dir()
                && !p.is_symlink()
                && name != "node_modules"
                && !name.starts_with('.')
            {
                walk(&p, left - 1, out);
            }
        }
    }
    walk(root, depth, &mut out);
    out.sort();
    out
}

pub fn install_all(root: &Path) -> Install {
    let mut r = Install::default();
    for repo in find_repos(root, 4) {
        if let Ok((w, h)) = install_repo(&repo) {
            r.repos += 1;
            r.written += w;
            r.healed += h;
        }
    }
    r
}

// ---- the real scanner ---------------------------------------------------------------------------------------------------

#[cfg(unix)]
pub struct ServiceScanner {
    svc: crate::secrets_service::SocketSecrets,
}

/// The file the box image writes, root-owned and world-readable, when it is built (`provision.sh`: the image's release record). A
/// machine that has it is a box: its socket paths are the box's, and no environment variable moves them (a process of the box
/// user could point the hooks at a service of its own that answers "clean"). It is not where the binary is: Homebrew on an Intel
/// Mac and `install.sh --prefix /usr/local` both put `ozbox` in `/usr/local/bin`, and a laptop is not a box.
pub const BOX_MARKER: &str = "/etc/ozbox/image-release";

/// Whether this machine is a box.
pub fn on_box() -> bool {
    on_box_at(Path::new(BOX_MARKER))
}

/// [`on_box`], for a marker at `marker`.
pub fn on_box_at(marker: &Path) -> bool {
    marker.is_file()
}

/// How the error for a box whose secrets service has no socket begins (see [`service_outage`]).
pub const OUTAGE_PREFIX: &str = "this box's secrets service is not answering";

/// Whether a scanner's error says the secrets service is not running: its socket is missing, or the connection to it was refused
/// (nothing is listening). That is an outage, the one failure the hooks degrade for (ADR 0029 Amendment 15). A service that is
/// there but did not answer (a timeout, a reply that is not one, a socket that refuses this user), a refusal, a busy minute, a
/// file that could not be read and every other error stay what they were: the change is held.
pub fn service_outage(e: &str) -> bool {
    e == crate::secrets_service::SERVICE_DOWN || e.starts_with(OUTAGE_PREFIX)
}

/// The socket to use: the box's own on a box; elsewhere (a laptop, a test) the environment's, when it names one.
pub fn socket_path(on_box: bool, from_env: Option<String>, default: &str) -> PathBuf {
    if on_box {
        return PathBuf::from(default);
    }
    PathBuf::from(
        from_env
            .filter(|p| !p.is_empty())
            .unwrap_or_else(|| default.to_string()),
    )
}

#[cfg(unix)]
impl ServiceScanner {
    /// The box's import socket. `Ok(None)` on a laptop with none, where only the shapes are checked. On a box a missing socket is
    /// said out loud and holds the change: a quiet shapes-only check is not the barrier a person was promised.
    pub fn connect() -> Result<Option<Self>, String> {
        Self::connect_with(on_box(), std::env::var("OZBOX_IMPORT_SOCKET").ok())
    }

    pub fn connect_with(on_box: bool, from_env: Option<String>) -> Result<Option<Self>, String> {
        let p = socket_path(on_box, from_env, crate::workload_cli::IMPORT_SOCKET);
        if p.exists() {
            return Ok(Some(Self {
                svc: crate::secrets_service::SocketSecrets::new(p),
            }));
        }
        if on_box {
            return Err(format!("{OUTAGE_PREFIX} (its socket is missing), so stored keys cannot be checked; start it with `ozbox secrets serve` or restart the box's services, then try again"));
        }
        Ok(None)
    }
}

#[cfg(unix)]
impl Scanner for ServiceScanner {
    fn scan(&self, text: &str) -> Result<Vec<String>, String> {
        // The service allows a number of scans a minute. A big push is waited for, in the open, rather than held for it: the
        // person sees why it is slow, and nothing is skipped (a wait that runs out is an error, which holds the change).
        let mut waited = 0u32;
        loop {
            let req = serde_json::json!({"op": "scan", "text": text});
            // measured, not assumed: a request the service would refuse for its size is a bug here, said as one
            if req.to_string().len() as u64 + 1 > crate::secrets_ingress::MAX_LINE_BYTES {
                return Err(
                    "a batch was larger than the service reads in one request (this is a bug in the barrier)"
                        .into(),
                );
            }
            match self.svc.call(req) {
                Ok(v) => {
                    return Ok(v["names"]
                        .as_array()
                        .map(|a| {
                            a.iter()
                                .filter_map(|n| n.as_str().map(str::to_string))
                                .collect()
                        })
                        .unwrap_or_default())
                }
                Err(e) if e.0.starts_with("too many scans") && waited < SCAN_WAITS => {
                    if waited == 0 {
                        eprintln!("ozbox: reading a large change; the box allows a limited number of checks a minute, waiting for room");
                    }
                    waited += 1;
                    std::thread::sleep(std::time::Duration::from_secs(SCAN_WAIT_SECS));
                }
                Err(e) => return Err(e.0),
            }
        }
    }
    fn override_ok(&self, code: &str, bind: &Binding) -> Result<(), String> {
        self.svc
            .call(serde_json::json!({
                "op": "override", "approval": code,
                "project": bind.project, "env": bind.change,
            }))
            .map(|_| ())
            .map_err(|e| e.0)
    }
}

/// How long, and how many times, a scan that was refused for the minute's budget is waited for: about ten minutes in all.
#[cfg(unix)]
const SCAN_WAITS: u32 = 40;
#[cfg(unix)]
const SCAN_WAIT_SECS: u64 = 15;

/// Git for tests: a clean environment, so a runner's (or a laptop's) git configuration cannot change what a test sees, and a
/// failed command says what it printed instead of only that it failed.
#[cfg(test)]
#[allow(clippy::unwrap_used)]
pub(crate) mod testgit {
    use std::process::Command;

    /// `git` with no global or system configuration, a throwaway HOME, no prompts, and fixed identity and defaults.
    pub(crate) fn git() -> Command {
        let home = std::env::temp_dir().join("ozbox-guard-test-home");
        let _ = std::fs::create_dir_all(&home);
        let mut c = Command::new("git");
        c.args([
            "-c",
            "user.name=t",
            "-c",
            "user.email=t@example.com",
            "-c",
            "init.defaultBranch=main",
            "-c",
            "commit.gpgsign=false",
        ])
        .env("GIT_CONFIG_GLOBAL", "/dev/null")
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .env("GIT_TERMINAL_PROMPT", "0")
        .env("HOME", home)
        .env_remove("GIT_DIR")
        .env_remove("GIT_WORK_TREE")
        .env_remove("GIT_INDEX_FILE");
        c
    }

    /// Runs the command and fails with its status, stdout and stderr when it did not succeed.
    pub(crate) fn must(c: &mut Command) {
        let o = c.output().unwrap();
        assert!(
            o.status.success(),
            "{c:?} failed with {}\nstdout: {}\nstderr: {}",
            o.status,
            String::from_utf8_lossy(&o.stdout),
            String::from_utf8_lossy(&o.stderr)
        );
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::testgit::{self, must};
    use super::*;
    use std::cell::RefCell;

    const SENTINEL: &str = "SENTINEL-guard-0123456789abcdef";

    struct Fake {
        value: &'static str,
        spent: RefCell<Vec<String>>,
        good_code: &'static str,
        /// When set, the one change the code was made for.
        bound_to: RefCell<Option<Binding>>,
    }
    impl Scanner for Fake {
        fn scan(&self, text: &str) -> Result<Vec<String>, String> {
            Ok(if text.contains(self.value) {
                vec!["workload.app.staging.API_KEY".into()]
            } else {
                vec![]
            })
        }
        fn override_ok(&self, code: &str, bind: &Binding) -> Result<(), String> {
            // a code names one change; it is spent once
            if code == self.good_code
                && self.spent.borrow().is_empty()
                && self.bound_to.borrow().as_ref().is_none_or(|b| b == bind)
            {
                self.spent.borrow_mut().push(code.into());
                Ok(())
            } else {
                Err("no".into())
            }
        }
    }
    fn fake() -> Fake {
        Fake {
            value: SENTINEL,
            spent: RefCell::default(),
            good_code: "AAAA-BBBB",
            bound_to: RefCell::default(),
        }
    }

    // Built by concatenation so this file holds no key-shaped literal itself.
    fn k(prefix: &str, tail: &str) -> String {
        format!("{prefix}{tail}")
    }

    #[test]
    fn the_shapes_of_real_keys_are_found_and_ordinary_text_is_not() {
        let t32 = "a1B2c3D4e5F6g7H8i9J0k1L2m3N4o5P6";
        let cases: Vec<(String, &str)> = vec![
            (k("-----BEGIN RSA PRIV", "ATE KEY-----"), "private-key"),
            (k("AKI", "AIOSFODNN7EXAMPLE"), "aws-access-key"),
            (k("sk_li", &format!("ve_{t32}")), "payment-provider-key"),
            (k("sk-an", &format!("t-api03-{t32}")), "model-provider-key"),
            (k("sk-pr", &format!("oj-{t32}")), "model-provider-key"),
            (k("gh", &format!("p_{t32}")), "github-token"),
            (k("xo", "xb-123456789012-abcdefghijklmnop"), "slack-token"),
            (k("AI", &format!("za{t32}abc")), "google-api-key"),
            (
                format!(
                    "{}.{}.abcdefghijkl",
                    k("ey", "JhbGciOiJIUzI1NiJ9"),
                    k("ey", "Jyb2xlIjoic2VydmljZSJ9")
                ),
                "signed-token",
            ),
            (
                k("postgres://app:", "s3cretPassw0rd@db.example.com:5432/x"),
                "password-in-address",
            ),
        ];
        for (text, rule) in &cases {
            assert!(
                shape_rules(&format!("const x = \"{text}\"")).contains(rule),
                "{rule}"
            );
        }
        for ok in [
            "let sk = 1;",
            "postgres://user:${DB_PASSWORD}@localhost/db",
            "postgres://user:xxxxxxxx@localhost/db",
            "https://example.com/a:b@c",
            "fn akia() {}",
            "eyJ is a prefix",
            "const ghost = 'ghp_short'",
            // G10: the review's own sentence, and other words that end in a prefix
            "see risk-assessment-for-the-turn-server-configuration for the plan",
            "[desk-setup-instructions-for-the-new-clinic-staff-members](#x)",
            "disk-usage-report-for-the-whole-month-of-november-2026",
            "task-list-for-the-quarterly-planning-and-review-meeting",
        ] {
            assert!(shape_rules(ok).is_empty(), "{ok}");
        }
        assert!(
            is_env_file(".env")
                && is_env_file("app/.env.local")
                && !is_env_file(".env.example")
                && !is_env_file("env.ts")
        );
    }

    #[test]
    fn a_prefix_inside_a_word_is_not_a_key_and_the_same_key_standing_alone_is() {
        let t32 = "a1B2c3D4e5F6g7H8i9J0k1L2m3N4o5P6";
        let aws = k("AKI", "AIOSFODNN7EXAMPLE");
        let sk = k("sk-pr", &format!("oj-{t32}"));
        // in a word: not a key
        assert!(shape_rules(&format!("my{aws}")).is_empty());
        assert!(shape_rules(&format!("task{sk}")).is_empty());
        // after punctuation or a space: a key
        for pre in [" ", "=", "\"", "(", "/", "_", ":"] {
            assert!(
                shape_rules(&format!("x{pre}{aws}")).contains(&"aws-access-key"),
                "{pre}"
            );
            assert!(
                shape_rules(&format!("x{pre}{sk}")).contains(&"model-provider-key"),
                "{pre}"
            );
        }
        // behind an escape (a key in a JSON string, in an address) it is a key again
        assert!(shape_rules(&format!("\"line\\n{aws}\"")).contains(&"aws-access-key"));
        assert!(shape_rules(&format!("a=%3D{sk}")).contains(&"model-provider-key"));
        // a long all-lowercase kebab word after `sk-` standing alone is text, not a key
        assert!(shape_rules(&format!(" sk-{}", "abcdefgh-".repeat(6))).is_empty());
    }

    #[test]
    fn only_added_lines_are_read_and_they_are_placed() {
        let d = "diff --git a/x b/x\n--- a/x\n+++ b/x\n@@ -1,2 +10,2 @@\n-old secret\n-old two\n+new one\n+second\n--- a/y\n+++ /dev/null\n@@ -1 +0,0 @@\n-gone\n";
        assert_eq!(
            crate::guard_diff::parse(d).unwrap().added,
            vec![
                ("x".to_string(), 10, "new one".to_string()),
                ("x".to_string(), 11, "second".to_string())
            ]
        );
    }

    #[test]
    fn a_stored_value_is_found_by_the_service_and_the_report_holds_no_value() {
        let diff = format!(
            "--- a/c.ts\n+++ b/c.ts\n@@ -0,0 +1,2 @@\n+const a = 1;\n+const k = \"{SENTINEL}\";\n"
        );
        let v = check_diff(&diff, Some(&fake())).unwrap();
        assert_eq!(v.stored.len(), 1);
        assert_eq!(
            (
                v.stored[0].name.as_str(),
                v.stored[0].file.as_str(),
                v.stored[0].line
            ),
            ("workload.app.staging.API_KEY", "c.ts", 2)
        );
        // the hold says where (file:line) and what kind, and names neither the value nor the secret
        let text = report(&v);
        assert!(text.contains("c.ts:2") && !text.contains("API_KEY") && !text.contains(SENTINEL));
        assert!(
            check_diff("--- a/c\n+++ b/c\n@@ -0,0 +1 @@\n+fine\n", Some(&fake()))
                .unwrap()
                .clean()
        );
        // an env file is stopped by its name even if every line is harmless
        let env = check_diff("--- /dev/null\n+++ b/.env\n@@ -0,0 +1 @@\n+A=1\n", None).unwrap();
        assert_eq!(env.findings[0].rule, "env-file");
    }

    #[test]
    fn a_public_variable_holding_an_anonymous_client_key_passes_and_every_real_key_shape_is_still_held(
    ) {
        let b = |t: &str| crate::serve::auth::b64::encode_url(t.as_bytes());
        let jwt = |role: &str| {
            format!(
                "{}.{}.abcdefghijklmnop",
                b("{\"alg\":\"HS256\",\"typ\":\"JWT\"}"),
                b(&format!("{{\"role\":\"{role}\"}}"))
            )
        };
        let diff = |line: &str| format!("--- /dev/null\n+++ b/c.ts\n@@ -0,0 +1 @@\n+{line}\n");
        let clean = |line: &str| check_diff(&diff(line), None).unwrap().clean();
        let anon = jwt("anon");
        assert!(clean(&format!("NEXT_PUBLIC_SUPABASE_ANON_KEY={anon}")));
        assert!(clean(&format!("  \"VITE_SUPABASE_KEY\": \"{anon}\",")));
        // the same token under a name that is not a public kind, or of another role, or with a real key beside it: held
        assert!(!clean(&format!("SUPABASE_ANON_KEY={anon}")));
        assert!(!clean(&format!(
            "NEXT_PUBLIC_SUPABASE_ANON_KEY={}",
            jwt("service_role")
        )));
        let live = k("sk_li", "ve_a1B2c3D4e5F6g7H8i9J0k1L2m3N4");
        assert!(!clean(&format!("NEXT_PUBLIC_X={live}")));
        assert!(!clean(&format!("NEXT_PUBLIC_X={anon} {live}")));
        // naming a public variable, in code or in docs, is never a hold
        assert!(clean("const u = process.env.NEXT_PUBLIC_TURN_USERNAME;"));
        assert!(clean(
            "Set `NEXT_PUBLIC_TURN_USERNAME` and `VITE_API_BASE` in your environment."
        ));
        // and where a real key is held, the hold names file:line and the rule, never the value
        let v = check_diff(&diff(&format!("NEXT_PUBLIC_X={live}")), None).unwrap();
        let text = report(&v);
        assert!(
            text.contains("c.ts:1")
                && text.contains("payment-provider-key")
                && !text.contains(&live)
        );
    }

    fn repo(dir: &Path) {
        for a in [
            &["init", "-q"][..],
            &["config", "user.email", "t@example.com"],
            &["config", "user.name", "t"],
            &["config", "commit.gpgsign", "false"],
        ] {
            must(testgit::git().arg("-C").arg(dir).args(a));
        }
    }
    fn commit(dir: &Path, extra: &[&str]) -> bool {
        testgit::git()
            .arg("-C")
            .arg(dir)
            .args(["add", "-A"])
            .status()
            .unwrap();
        testgit::git()
            .arg("-C")
            .arg(dir)
            .args(["commit", "-q", "-m", "m"])
            .args(extra)
            .env("HOME", dir)
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .unwrap()
            .success()
    }

    /// A ref of a new branch: the remote has nothing (zeros), and this is sent.
    fn sent(sha: &str) -> Sent {
        Sent {
            old: "0".repeat(40),
            new: sha.trim().to_string(),
        }
    }

    fn stage(r: &Path) {
        testgit::git()
            .arg("-C")
            .arg(r)
            .args(["add", "-A"])
            .status()
            .unwrap();
    }

    #[test]
    fn a_real_repository_is_checked_staged_and_after_the_commit_and_a_code_is_for_one_tree() {
        use crate::guard_hold::{post_commit, pre_commit};
        let d = tempfile::tempdir().unwrap();
        let r = d.path();
        repo(r);
        std::fs::write(r.join("a.txt"), "hello\n").unwrap();
        assert!(commit(r, &[]));
        // staged: a key in a new file stops pre-commit
        std::fs::write(
            r.join("b.ts"),
            format!("export const k = \"{SENTINEL}\";\n"),
        )
        .unwrap();
        stage(r);
        let s = fake();
        let msg = pre_commit(r, Some(&s), "", None).unwrap().unwrap();
        assert!(msg.contains("b.ts:1") && !msg.contains("API_KEY") && !msg.contains(SENTINEL));
        // the hold tells the person exactly what to mint the code for
        let tree = staged_tree(r).unwrap();
        let held = crate::guard_hold::commit_held(
            r,
            &tree,
            &check_diff(&staged_diff(r).unwrap(), Some(&s)).unwrap(),
        );
        assert!(msg.contains(&held.binding.change) || msg.contains("guard-override"));
        // a wrong code changes nothing; the right one, for this tree, passes once
        assert!(pre_commit(r, Some(&s), "WRONG", None)
            .unwrap()
            .unwrap()
            .contains("not accepted"));
        *s.bound_to.borrow_mut() = Some(held.binding.clone());
        assert!(pre_commit(r, Some(&s), "AAAA-BBBB", None)
            .unwrap()
            .is_none());
        assert!(pre_commit(r, Some(&s), "AAAA-BBBB", None)
            .unwrap()
            .is_some());
        // N3: a code made for tree A does not pass tree B, whatever else is true of it
        let s2 = fake();
        *s2.bound_to.borrow_mut() = Some(held.binding.clone());
        std::fs::write(
            r.join("c.ts"),
            format!("export const other = \"{SENTINEL}\";\n"),
        )
        .unwrap();
        stage(r);
        let other = pre_commit(r, Some(&s2), "AAAA-BBBB", None)
            .unwrap()
            .unwrap();
        assert!(other.contains("not accepted"), "{other}");
        assert!(
            s2.spent.borrow().is_empty(),
            "a code for another tree must not be spent"
        );
        std::fs::remove_file(r.join("c.ts")).unwrap();
        stage(r);
        // the commit the override let through stands; the same tree committed again after --no-verify is checked
        let s3 = fake();
        assert!(pre_commit(r, Some(&s3), "", None).unwrap().is_some());
        let s4 = fake();
        *s4.bound_to.borrow_mut() = Some(held.binding.clone());
        assert!(pre_commit(r, Some(&s4), "AAAA-BBBB", None)
            .unwrap()
            .is_none());
        assert!(commit(r, &[]));
        assert!(
            post_commit(r, Some(&fake())).unwrap().is_none(),
            "a commit whose tree was let through stands"
        );
        // the barrier is skipped (--no-verify) on a different tree: post-commit takes the commit back and says so
        std::fs::write(
            r.join("d.ts"),
            format!("export const third = \"{SENTINEL}\";\n"),
        )
        .unwrap();
        assert!(commit(r, &["--no-verify"]));
        assert_eq!(
            git(r, &["rev-list", "--count", "HEAD"]).unwrap().trim(),
            "3"
        );
        let said = post_commit(r, Some(&fake())).unwrap().unwrap();
        assert!(said.contains("taken back") && !said.contains(SENTINEL));
        assert_eq!(
            git(r, &["rev-list", "--count", "HEAD"]).unwrap().trim(),
            "2"
        );
        assert!(git(r, &["diff", "--cached", "--name-only"])
            .unwrap()
            .contains("d.ts"));
        // a push of commits with a key is checked as well, commit by commit
        assert!(commit(r, &["--no-verify"]));
        let sha = git(r, &["rev-parse", "HEAD"]).unwrap();
        let v = check_push(r, &[sent(&sha)], None, Some(&fake())).unwrap();
        assert!(!v.clean() && v.stored.iter().any(|h| h.file == "d.ts" && h.line == 1));
        assert!(push_commits(r, "not a sha; rm -rf", &[], None).is_err());
    }

    #[test]
    fn a_two_hundred_and_fifty_commit_push_is_read_and_passes_when_clean_and_a_key_in_the_middle_is_held_at_file_and_line(
    ) {
        let d = tempfile::tempdir().unwrap();
        let r = d.path();
        repo(r);
        std::fs::write(r.join("a.txt"), "hello\n").unwrap();
        assert!(commit(r, &[]));
        for i in 0..250 {
            let body = if i == 117 {
                format!("line one\nexport const k = \"{SENTINEL}\";\n")
            } else {
                format!("// change {i}\nconst v{i} = {i};\n")
            };
            std::fs::write(r.join(format!("f{}.ts", i % 9)), body).unwrap();
            must(testgit::git().arg("-C").arg(r).args(["add", "-A"]));
            must(
                testgit::git()
                    .arg("-C")
                    .arg(r)
                    .args(["commit", "-q", "--no-verify", "-m", "m"]),
            );
        }
        let sha = git(r, &["rev-parse", "HEAD"]).unwrap().trim().to_string();
        let held = check_push(r, &[sent(&sha)], None, Some(&fake())).unwrap();
        // the commit-by-commit check finds it: the 118th change, in f1.ts (117 % 9 == 0 is f0.ts), at line 2
        assert_eq!(held.stored.len(), 1, "{:?}", held.stored);
        assert_eq!(held.stored[0].file, "f0.ts");
        assert_eq!(held.stored[0].line, 2);
        assert_eq!(held.stored[0].commit.len(), 12);
        assert!(!report(&held).contains(SENTINEL));
        // the same push with nothing in it is clean, in a handful of service calls
        let clean = Fake {
            value: "NOT-IN-ANY-FILE-xyz",
            ..fake()
        };
        let v = check_push(r, &[sent(&sha)], None, Some(&clean)).unwrap();
        assert!(v.clean());
    }

    // ---- through real git ----------------------------------------------------------------------------------

    fn g(r: &Path, a: &[&str]) {
        must(testgit::git().arg("-C").arg(r).args(a));
    }
    fn put(r: &Path, name: &str, body: &[u8]) {
        std::fs::write(r.join(name), body).unwrap();
    }
    fn head(r: &Path) -> String {
        git(r, &["rev-parse", "HEAD"]).unwrap().trim().to_string()
    }
    fn fresh() -> tempfile::TempDir {
        let d = tempfile::tempdir().unwrap();
        repo(d.path());
        put(d.path(), "a.txt", b"hello\n");
        assert!(commit(d.path(), &[]));
        d
    }

    /// What is in the working tree is held by what `pre-commit` reads and, committed with the hook skipped, by what `post-commit`
    /// reads and by what `pre-push` reads: one command and one flag set, so the three cannot disagree.
    fn held_by_all_three(r: &Path, what: &str) -> Verdict {
        stage(r);
        let s = fake();
        let staged = check_diff(&staged_diff(r).unwrap(), Some(&s)).unwrap();
        assert!(!staged.clean(), "pre-commit: {what}");
        assert!(commit(r, &["--no-verify"]), "{what}");
        let (d, _) = check_head(r, Some(&s)).unwrap();
        assert!(!d.clean(), "post-commit: {what}");
        let p = check_push(r, &[sent(&head(r))], None, Some(&s)).unwrap();
        assert!(!p.clean(), "pre-push: {what}");
        p
    }

    #[test]
    fn g1_an_added_line_that_looks_like_a_diff_header_does_not_hide_what_follows() {
        for fake_header in [
            "++ /dev/null",
            "++ b/other.ts",
            "+ /dev/null",
            "++ a/x",
            "@ not a header",
        ] {
            let d = fresh();
            let body = format!("ok\n{fake_header}\nconst k = \"{SENTINEL}\";\nlast\n");
            put(d.path(), "c.ts", body.as_bytes());
            held_by_all_three(d.path(), fake_header);
        }
    }

    #[test]
    fn g2_a_file_with_a_nul_byte_and_a_file_marked_no_diff_are_read() {
        let d = fresh();
        let mut bin = b"a\0b\n".to_vec();
        bin.extend_from_slice(SENTINEL.as_bytes());
        put(d.path(), "blob.dat", &bin);
        let v = held_by_all_three(d.path(), "a NUL byte");
        assert!(v.stored.iter().any(|h| h.file == "blob.dat"));
        // the attribute that says "do not diff" arrives in the same commit as the key
        let d = fresh();
        put(d.path(), ".gitattributes", b"*.ts -diff\n");
        put(
            d.path(),
            "c.ts",
            format!("const k = \"{SENTINEL}\";\n").as_bytes(),
        );
        let v = held_by_all_three(d.path(), "-diff");
        assert!(v.stored.iter().any(|h| h.file == "c.ts" && h.line == 1));
    }

    #[cfg(unix)]
    #[test]
    fn g3_a_symlink_turned_into_a_file_and_a_rename_with_an_edit_are_read() {
        let d = fresh();
        std::os::unix::fs::symlink("target", d.path().join("lnk")).unwrap();
        assert!(commit(d.path(), &[]));
        std::fs::remove_file(d.path().join("lnk")).unwrap();
        put(d.path(), "lnk", format!("{SENTINEL}\n").as_bytes());
        let v = held_by_all_three(d.path(), "a symlink turned into a file");
        assert!(v.stored.iter().any(|h| h.file == "lnk"));
        // a rename with an edit: the new file is read whole, through post-commit and pre-push as well
        let d = fresh();
        put(d.path(), "r.txt", b"one\ntwo\nthree\nfour\nfive\nsix\n");
        assert!(commit(d.path(), &[]));
        g(d.path(), &["mv", "r.txt", "r2.txt"]);
        put(
            d.path(),
            "r2.txt",
            format!("one\ntwo\nthree\nfour\nfive\nsix\n{SENTINEL}\n").as_bytes(),
        );
        let v = held_by_all_three(d.path(), "a rename with an edit");
        assert!(v.stored.iter().any(|h| h.file == "r2.txt" && h.line == 7));
    }

    fn base_branch(r: &Path) -> String {
        git(r, &["rev-parse", "--abbrev-ref", "HEAD"])
            .unwrap()
            .trim()
            .to_string()
    }

    #[test]
    fn a_conflict_resolution_merge_that_adds_a_line_is_read_and_a_clean_merge_passes() {
        // conflict: both sides edit line 3; the person who resolves it adds a key
        let d = fresh();
        let r = d.path();
        put(r, "f", b"a\nb\nc\n");
        assert!(commit(r, &[]));
        let base = base_branch(r);
        g(r, &["checkout", "-q", "-b", "side"]);
        put(r, "f", b"a\nb\nSIDE\n");
        assert!(commit(r, &[]));
        g(r, &["checkout", "-q", &base]);
        put(r, "f", b"a\nb\nMAIN\n");
        assert!(commit(r, &[]));
        let merged = testgit::git()
            .arg("-C")
            .arg(r)
            .args(["merge", "side"])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .unwrap();
        assert!(!merged.success(), "the merge must conflict");
        put(
            r,
            "f",
            format!("a\nb\nRESOLVED\nconst k = \"{SENTINEL}\";\n").as_bytes(),
        );
        let v = held_by_all_three(r, "a conflict resolution");
        assert!(
            v.stored.iter().any(|h| h.file == "f" && h.line == 4),
            "{:?}",
            v.stored
        );
        // the diff git printed for it is the combined form
        assert!(commit_diff(r, &head(r)).unwrap().contains("@@@"));

        // clean: the two sides touch different files, and the merge adds nothing of its own
        let d = fresh();
        let r = d.path();
        let base = base_branch(r);
        g(r, &["checkout", "-q", "-b", "side"]);
        put(r, "s.txt", b"side\n++ /dev/null\n");
        assert!(commit(r, &[]));
        g(r, &["checkout", "-q", &base]);
        put(r, "m.txt", b"main\n");
        assert!(commit(r, &[]));
        g(r, &["merge", "-q", "side", "-m", "merge"]);
        assert_eq!(commit_diff(r, &head(r)).unwrap(), "");
        let (dv, mv) = check_head(r, Some(&fake())).unwrap();
        assert!(dv.clean() && mv.clean());
        assert!(check_push(r, &[sent(&head(r))], None, Some(&fake()))
            .unwrap()
            .clean());
    }

    #[test]
    fn g6_a_key_in_a_commit_message_a_tag_message_or_a_file_name_is_found() {
        // a message
        let d = fresh();
        let r = d.path();
        put(r, "ok.txt", b"fine\n");
        assert!(commit(r, &["--no-verify", "-m", SENTINEL]));
        let (dv, mv) = check_head(r, Some(&fake())).unwrap();
        assert!(dv.clean() && !mv.clean());
        assert!(mv.stored.iter().any(|h| h.file == "<commit message>"));
        let p = check_push(r, &[sent(&head(r))], None, Some(&fake())).unwrap();
        assert!(p
            .stored
            .iter()
            .any(|h| h.file == "<commit message>" && h.commit.len() == 12));
        assert!(!report(&p).contains(SENTINEL));
        // post-commit takes a commit whose message holds a key back
        let said = crate::guard_hold::post_commit(r, Some(&fake()))
            .unwrap()
            .unwrap();
        assert!(said.contains("taken back") && !said.contains(SENTINEL));
        // a tag's message
        let d = fresh();
        let r = d.path();
        g(r, &["tag", "-a", "-m", SENTINEL, "t1", "HEAD"]);
        let tag = git(r, &["rev-parse", "t1"]).unwrap().trim().to_string();
        let p = check_push(r, &[sent(&tag)], None, Some(&fake())).unwrap();
        assert!(p.stored.iter().any(|h| h.file == "<tag>"), "{:?}", p.stored);
        // a file name
        let d = fresh();
        let r = d.path();
        put(r, &format!("{SENTINEL}.txt"), b"x\n");
        stage(r);
        let v = check_diff(&staged_diff(r).unwrap(), Some(&fake())).unwrap();
        assert!(v.stored.iter().any(|h| h.file == "<file name>"));
        assert!(!report(&v).contains(SENTINEL));
        // an empty file named .env is held by its name
        let d = fresh();
        put(d.path(), ".env", b"");
        stage(d.path());
        let v = check_diff(&staged_diff(d.path()).unwrap(), None).unwrap();
        assert!(v.findings.iter().any(|f| f.rule == "env-file"));
    }

    #[test]
    fn g4_a_push_is_read_unless_the_target_remote_has_it_and_another_remotes_branch_says_nothing() {
        let d = fresh();
        let r = d.path();
        let a = head(r);
        put(
            r,
            "k.ts",
            format!("export const k = \"{SENTINEL}\";\n").as_bytes(),
        );
        assert!(commit(r, &["--no-verify"]));
        let b = head(r);
        g(r, &["remote", "add", "origin", "/nowhere/origin.git"]);
        g(r, &["remote", "add", "x", "/nowhere/x.git"]);
        // one `git update-ref` of another remote's branch no longer empties the scan
        g(r, &["update-ref", "refs/remotes/x/y", &b]);
        let to = |remote: Option<&str>, olds: &str| {
            check_push(
                r,
                &[Sent {
                    old: olds.to_string(),
                    new: b.clone(),
                }],
                remote,
                Some(&fake()),
            )
        };
        let zeros = "0".repeat(40);
        assert!(
            !to(Some("origin"), &zeros).unwrap().clean(),
            "origin has nothing"
        );
        assert!(to(Some("x"), &zeros).unwrap().clean(), "x has it");
        assert!(
            !to(None, &zeros).unwrap().clean(),
            "an unknown address reads everything"
        );
        // what the remote says it has, when this repository has it
        assert!(!to(Some("origin"), &a).unwrap().clean());
        assert!(to(Some("origin"), &b).unwrap().clean());
        // an old sha this repository does not have is not a failure: it only reads more
        assert!(!to(Some("origin"), &"1".repeat(40)).unwrap().clean());
        // a push by address resolves to the configured remote that fetches from it and pushes to it
        assert_eq!(
            remote_name(r, "origin", "/nowhere/origin.git").as_deref(),
            Some("origin")
        );
        assert_eq!(
            remote_name(r, "/nowhere/origin.git", "/nowhere/origin.git").as_deref(),
            Some("origin")
        );
        g(r, &["config", "remote.origin.pushurl", "/nowhere/push.git"]);
        // a `pushurl` somewhere else: the tracking refs describe the fetch address, so this push is to no known remote
        assert_eq!(
            remote_name(r, "/nowhere/push.git", "/nowhere/push.git"),
            None
        );
        assert_eq!(remote_name(r, "origin", "/nowhere/push.git"), None);
        assert_eq!(remote_name(r, "/elsewhere.git", "/elsewhere.git"), None);
        // a push over the cap says how to get through it
        let e = check_push_cap(r, &[sent(&b)], Some("origin"), Some(&fake()), 1).unwrap_err();
        assert!(
            e.contains("git fetch") && e.contains("<commit>:<branch>"),
            "{e}"
        );
    }

    /// What a real `git push` hands the `pre-push` hook: its lines on standard input (`local_ref local_sha remote_ref remote_sha`).
    fn pushed(r: &Path, remote: &Path, spec: &str) -> Option<Vec<String>> {
        let cap = r.join("captured-stdin");
        let _ = std::fs::remove_file(&cap);
        let hook = r.join(".git/hooks/pre-push");
        std::fs::write(&hook, "#!/bin/sh\ncat > \"$CAPTURE\"\n").unwrap();
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&hook, std::fs::Permissions::from_mode(0o755)).unwrap();
        }
        let _ = testgit::git()
            .arg("-C")
            .arg(r)
            .args(["push", "-q", remote.to_str().unwrap(), spec])
            .env("CAPTURE", &cap)
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status();
        let t = std::fs::read_to_string(&cap).ok()?;
        Some(t.lines().map(str::to_string).collect())
    }

    #[cfg(unix)]
    #[test]
    fn g5_a_ref_that_points_at_a_blob_a_tree_or_a_tag_of_either_is_read() {
        let bare = tempfile::tempdir().unwrap();
        must(
            testgit::git()
                .args(["init", "-q", "--bare"])
                .arg(bare.path()),
        );
        let d = fresh();
        let r = d.path();
        put(r, "secret.txt", format!("{SENTINEL}\n").as_bytes());
        let blob = git(r, &["hash-object", "-w", "secret.txt"])
            .unwrap()
            .trim()
            .to_string();
        let tree = {
            let mut c = testgit::git()
                .arg("-C")
                .arg(r)
                .arg("mktree")
                .stdin(Stdio::piped())
                .stdout(Stdio::piped())
                .spawn()
                .unwrap();
            use std::io::Write;
            c.stdin
                .take()
                .unwrap()
                .write_all(format!("100644 blob {blob}\tk.txt\n").as_bytes())
                .unwrap();
            let o = c.wait_with_output().unwrap();
            String::from_utf8(o.stdout).unwrap().trim().to_string()
        };
        g(r, &["tag", "-a", "-m", "m", "tag-of-blob", &blob]);
        let tag_of_blob = git(r, &["rev-parse", "tag-of-blob"])
            .unwrap()
            .trim()
            .to_string();
        for (what, sha, spec) in [
            ("a blob", blob.clone(), format!("{blob}:refs/tags/b")),
            ("a tree", tree.clone(), format!("{tree}:refs/tags/t")),
            (
                "a tag of a blob",
                tag_of_blob.clone(),
                "refs/tags/tag-of-blob:refs/tags/tb".to_string(),
            ),
        ] {
            // the sha git really hands the hook, from a real push to a real bare remote when git gets as far as the hook
            let lines = pushed(r, bare.path(), &spec);
            let (old, new) = match lines.as_deref().and_then(|l| l.first()) {
                Some(l) => {
                    let f: Vec<&str> = l.split_whitespace().collect();
                    assert_eq!(f[1], sha, "{what}");
                    (f[3].to_string(), f[1].to_string())
                }
                None => ("0".repeat(40), sha.clone()),
            };
            let v = check_push(r, &[Sent { old, new }], None, Some(&fake())).unwrap();
            assert!(!v.clean(), "{what} must be read");
            assert!(!report(&v).contains(SENTINEL));
        }
        // a clean blob passes
        let clean = git(r, &["rev-parse", "HEAD:a.txt"])
            .unwrap()
            .trim()
            .to_string();
        assert!(check_push(r, &[sent(&clean)], None, Some(&fake()))
            .unwrap()
            .clean());
    }

    #[test]
    fn g7_a_submodule_and_a_linked_worktree_get_the_hooks_through_their_git_file() {
        let d = tempfile::tempdir().unwrap();
        let src = d.path().join("src");
        let main = d.path().join("work/m");
        std::fs::create_dir_all(&src).unwrap();
        std::fs::create_dir_all(&main).unwrap();
        repo(&src);
        put(&src, "s.txt", b"s\n");
        assert!(commit(&src, &[]));
        repo(&main);
        put(&main, "a.txt", b"a\n");
        assert!(commit(&main, &[]));
        g(
            &main,
            &[
                "-c",
                "protocol.file.allow=always",
                "submodule",
                "add",
                "-q",
                src.to_str().unwrap(),
                "sub",
            ],
        );
        assert!(
            main.join("sub/.git").is_file(),
            "a submodule's .git is a file"
        );
        let r = install_all(&d.path().join("work"));
        assert_eq!(r.repos, 2);
        let hooks = git(&main.join("sub"), &["rev-parse", "--git-path", "hooks"]).unwrap();
        let hooks = {
            let p = PathBuf::from(hooks.trim());
            if p.is_absolute() {
                p
            } else {
                main.join("sub").join(p)
            }
        };
        let pre = std::fs::read_to_string(hooks.join("pre-commit")).unwrap();
        assert!(
            pre.contains(MARKER),
            "the submodule's own hooks folder has the guard"
        );
        // a plain folder with a .git file that is not a gitdir pointer is not a repository
        let junk = d.path().join("work/junk");
        std::fs::create_dir_all(&junk).unwrap();
        std::fs::write(junk.join(".git"), "not a pointer").unwrap();
        assert_eq!(find_repos(&d.path().join("work"), 4).len(), 2);
    }

    #[test]
    fn g13_a_marker_stands_for_one_tree_on_one_parent_for_a_while_and_an_aborted_commit_leaves_none(
    ) {
        use crate::guard_hold::{clear_marker, take_marker_for_head_at, MARKER_TTL_SECS};
        let d = fresh();
        let r = d.path();
        put(r, "b.txt", b"b\n");
        assert!(commit(r, &[]));
        let tree = git(r, &["rev-parse", "HEAD^{tree}"])
            .unwrap()
            .trim()
            .to_string();
        let parent = git(r, &["rev-parse", "HEAD~1"]).unwrap().trim().to_string();
        let path = {
            let p = git(r, &["rev-parse", "--git-path", "ozbox-guard-approved"]).unwrap();
            let p = PathBuf::from(p.trim());
            if p.is_absolute() {
                p
            } else {
                r.join(p)
            }
        };
        let now = 1_000_000u64;
        let mark = |tree: &str, head: &str, at: u64| {
            std::fs::write(&path, format!("{tree} {head} {at}")).unwrap();
        };
        mark(&tree, &parent, now);
        assert!(
            take_marker_for_head_at(r, now + 600),
            "a long message does not lose an approved commit"
        );
        assert!(
            !path.exists() && !take_marker_for_head_at(r, now + 600),
            "taken once"
        );
        // a different parent (an amend, or a reset onto another commit) does not stand
        mark(&tree, &"1".repeat(40), now);
        assert!(!take_marker_for_head_at(r, now + 1));
        // an old one does not stand, and neither does one from the future
        mark(&tree, &parent, now);
        assert!(!take_marker_for_head_at(r, now + MARKER_TTL_SECS + 1));
        mark(&tree, &parent, now + 10_000);
        assert!(!take_marker_for_head_at(r, now));
        // another tree does not stand
        mark(&"2".repeat(40), &parent, now);
        assert!(!take_marker_for_head_at(r, now + 1));
        // every pre-commit clears what an aborted commit left, before it decides anything
        mark(&tree, &parent, now);
        assert!(crate::guard_hold::pre_commit(r, None, "", None)
            .unwrap()
            .is_none());
        assert!(!path.exists());
        mark(&tree, &parent, now);
        clear_marker(r);
        assert!(!path.exists());
    }

    #[test]
    fn g14_on_a_box_the_sockets_are_the_boxs_own_and_a_missing_service_is_an_error_not_a_quiet_skip(
    ) {
        let default = "/run/ozbox-secrets/import/import.sock";
        // on a box, no environment variable moves the socket
        assert_eq!(
            socket_path(true, Some("/tmp/fake.sock".into()), default),
            PathBuf::from(default)
        );
        // elsewhere the environment may name one (tests, the dashboard's fixture), and an empty one is ignored
        assert_eq!(
            socket_path(false, Some("/tmp/fake.sock".into()), default),
            PathBuf::from("/tmp/fake.sock")
        );
        assert_eq!(
            socket_path(false, Some(String::new()), default),
            PathBuf::from(default)
        );
        #[cfg(unix)]
        {
            let e = ServiceScanner::connect_with(true, Some("/tmp/fake.sock".into()))
                .err()
                .unwrap();
            assert!(e.contains("not answering"), "{e}");
            // a laptop with no service: only the shapes are checked, and that is allowed there
            assert!(ServiceScanner::connect_with(false, None).unwrap().is_none());
            // the environment's socket, when it exists, is used off a box
            let d = tempfile::tempdir().unwrap();
            let p = d.path().join("s.sock");
            std::fs::write(&p, "").unwrap();
            assert!(
                ServiceScanner::connect_with(false, Some(p.display().to_string()))
                    .unwrap()
                    .is_some()
            );
        }
    }

    #[test]
    fn hooks_are_installed_once_keep_a_repositorys_own_hook_and_are_put_back_when_removed() {
        let d = tempfile::tempdir().unwrap();
        let a = d.path().join("projects/a");
        let b = d.path().join("projects/b");
        std::fs::create_dir_all(&a).unwrap();
        std::fs::create_dir_all(&b).unwrap();
        repo(&a);
        repo(&b);
        std::fs::write(a.join(".git/hooks/pre-commit"), "#!/bin/sh\necho theirs\n").unwrap();
        let r = install_all(d.path());
        assert_eq!((r.repos, r.written), (2, 6));
        let pre = std::fs::read_to_string(a.join(".git/hooks/pre-commit")).unwrap();
        assert!(pre.contains(MARKER) && pre.contains("guard hook pre-commit"));
        assert_eq!(
            std::fs::read_to_string(a.join(".git/hooks/pre-commit.ozbox-prev")).unwrap(),
            "#!/bin/sh\necho theirs\n"
        );
        // again: nothing to do
        assert_eq!(
            install_all(d.path()),
            Install {
                repos: 2,
                written: 0,
                healed: 0
            }
        );
        // an agent removes one: it is put back and counted
        std::fs::remove_file(b.join(".git/hooks/post-commit")).unwrap();
        let r = install_all(d.path());
        assert_eq!((r.written, r.healed), (1, 1));
        assert!(find_repos(d.path(), 4).len() == 2);
    }

    // ---- the review of 2026-11-13 (V1 to V11), with real git ----------------------------------------------------------

    /// What a real `git push <args>` hands the `pre-push` hook: its arguments and its lines on standard input.
    fn hook_input(r: &Path, push: &[&str]) -> (Vec<String>, Vec<String>) {
        let (cap_in, cap_args) = (r.join("captured-stdin"), r.join("captured-args"));
        let _ = std::fs::remove_file(&cap_in);
        let _ = std::fs::remove_file(&cap_args);
        let hook = r.join(".git/hooks/pre-push");
        std::fs::write(
            &hook,
            "#!/bin/sh\nfor a in \"$@\"; do echo \"$a\"; done > \"$CAPARGS\"\ncat > \"$CAPIN\"\n",
        )
        .unwrap();
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&hook, std::fs::Permissions::from_mode(0o755)).unwrap();
        }
        let _ = testgit::git()
            .arg("-C")
            .arg(r)
            .arg("push")
            .arg("-q")
            .args(push)
            .env("CAPIN", &cap_in)
            .env("CAPARGS", &cap_args)
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status();
        let lines = |p: &Path| {
            std::fs::read_to_string(p)
                .unwrap_or_default()
                .lines()
                .map(str::to_string)
                .collect::<Vec<_>>()
        };
        (lines(&cap_args), lines(&cap_in))
    }

    fn bare(d: &Path, name: &str) -> String {
        let p = d.join(name);
        must(testgit::git().args(["init", "-q", "--bare"]).arg(&p));
        p.to_str().unwrap().to_string()
    }

    /// What `pre-push` makes of a real push: the remote it resolves, and whether the push is held.
    fn judged(r: &Path, push: &[&str]) -> (Option<String>, bool) {
        let (args, stdin) = hook_input(r, push);
        assert_eq!(
            args.len(),
            2,
            "git hands the hook a name and an address: {args:?}"
        );
        let refs: Vec<Sent> = stdin
            .iter()
            .filter_map(|l| {
                let f: Vec<&str> = l.split_whitespace().collect();
                Some(Sent {
                    old: (*f.get(3)?).to_string(),
                    new: (*f.get(1)?).to_string(),
                })
            })
            .collect();
        assert!(!refs.is_empty(), "the hook was given no refs");
        let remote = remote_name(r, &args[0], &args[1]);
        let v = check_push(r, &refs, remote.as_deref(), Some(&fake())).unwrap();
        (remote, !v.clean())
    }

    /// A repository whose `origin` was fetched from (and given a key commit by) `private`, with a clean commit on top.
    fn triangular(d: &Path) -> (String, String) {
        let private = bare(d, "private.git");
        let public = bare(d, "public.git");
        let r = d.join("work");
        std::fs::create_dir_all(&r).unwrap();
        repo(&r);
        put(&r, "a.txt", b"hello\n");
        assert!(commit(&r, &[]));
        put(&r, "key.txt", format!("k = \"{SENTINEL}\"\n").as_bytes());
        assert!(commit(&r, &["--no-verify"]));
        g(&r, &["remote", "add", "origin", &private]);
        g(&r, &["push", "-q", "origin", "HEAD:refs/heads/main"]);
        g(&r, &["fetch", "-q", "origin"]);
        put(&r, "b.txt", b"clean\n");
        assert!(commit(&r, &[]));
        (private, public)
    }

    #[cfg(unix)]
    #[test]
    fn v1_a_push_to_a_pushurl_or_a_rewritten_address_does_not_skip_what_the_fetch_address_has() {
        // the plain case: the push address is the fetch address, so the tracking refs say what the remote has
        let d = tempfile::tempdir().unwrap();
        let (_, _) = triangular(d.path());
        let r = d.path().join("work");
        let (remote, held) = judged(&r, &["origin", "HEAD:refs/heads/main"]);
        assert_eq!(remote.as_deref(), Some("origin"));
        assert!(
            !held,
            "the remote already has the key commit, and this push adds a clean one"
        );

        // a `pushurl` somewhere else: the key commit came from the private address and goes to the public one
        let d = tempfile::tempdir().unwrap();
        let (_, public) = triangular(d.path());
        let r = d.path().join("work");
        g(&r, &["config", "remote.origin.pushurl", &public]);
        let (remote, held) = judged(&r, &["origin", "HEAD:refs/heads/main"]);
        assert_eq!(remote, None);
        assert!(
            held,
            "pushurl: the key commit goes to a place that does not have it"
        );

        // the same, by `pushInsteadOf` and no `pushurl` key at all
        let d = tempfile::tempdir().unwrap();
        let (private, public) = triangular(d.path());
        let r = d.path().join("work");
        g(
            &r,
            &["config", &format!("url.{public}.pushInsteadOf"), &private],
        );
        let (remote, held) = judged(&r, &["origin", "HEAD:refs/heads/main"]);
        assert_eq!(remote, None);
        assert!(
            held,
            "pushInsteadOf: the key commit goes to a place that does not have it"
        );
    }

    #[test]
    fn v2_a_name_git_quotes_is_read_in_all_three_hooks() {
        // an EMPTY file has no `+++` line, so the `diff --git` line is the only place its name is
        for (name, what) in [
            (format!("\u{e9}-{SENTINEL}.txt"), "a non-ASCII name"),
            (format!("tab\t{SENTINEL}"), "a name with a tab"),
        ] {
            let d = fresh();
            put(d.path(), &name, b"");
            held_by_all_three(d.path(), what);
        }
        // an empty `.env` under a folder whose name is quoted
        let d = fresh();
        std::fs::create_dir_all(d.path().join("\u{e9} dir")).unwrap();
        put(d.path(), "\u{e9} dir/.env", b"");
        let v = held_by_all_three(d.path(), "an empty .env under a quoted folder");
        assert!(
            v.findings.iter().any(|f| f.rule.contains("env")),
            "{:?}",
            v.findings
        );
    }

    #[cfg(unix)]
    #[test]
    fn v4_a_replace_ref_does_not_change_what_pre_push_reads() {
        let d = fresh();
        let r = d.path();
        put(r, "key.txt", format!("k = \"{SENTINEL}\"\n").as_bytes());
        assert!(commit(r, &["--no-verify"]));
        let key = head(r);
        let clean_tree = git(r, &["rev-parse", "HEAD~1^{tree}"])
            .unwrap()
            .trim()
            .to_string();
        let clean = git(
            r,
            &["commit-tree", &clean_tree, "-p", "HEAD~1", "-m", "clean"],
        )
        .unwrap()
        .trim()
        .to_string();
        g(r, &["replace", &key, &clean]);
        // the replacement is real: git without the guard's setting sees the clean tree under the key commit's name
        let raw = testgit::git()
            .arg("-C")
            .arg(r)
            .args(["rev-parse", &format!("{key}^{{tree}}")])
            .output()
            .unwrap();
        assert_eq!(String::from_utf8_lossy(&raw.stdout).trim(), clean_tree);
        let p = check_push(r, &[sent(&key)], None, Some(&fake())).unwrap();
        assert!(
            !p.clean(),
            "the commit that is sent is the one read, not its replacement"
        );

        // a blob
        let d = fresh();
        let r = d.path();
        put(r, "k.txt", format!("{SENTINEL}\n").as_bytes());
        let blob = git(r, &["hash-object", "-w", "k.txt"])
            .unwrap()
            .trim()
            .to_string();
        put(r, "c.txt", b"nothing here\n");
        let cb = git(r, &["hash-object", "-w", "c.txt"])
            .unwrap()
            .trim()
            .to_string();
        g(r, &["replace", &blob, &cb]);
        let p = check_push(r, &[sent(&blob)], None, Some(&fake())).unwrap();
        assert!(!p.clean(), "a replaced blob");
    }

    #[test]
    fn v5_a_remote_named_origin_slash_x_is_not_origin() {
        let d = fresh();
        let r = d.path();
        put(r, "key.txt", format!("k = \"{SENTINEL}\"\n").as_bytes());
        assert!(commit(r, &["--no-verify"]));
        let b = head(r);
        g(r, &["remote", "add", "origin", "/nowhere/origin.git"]);
        // Written as config, not `git remote add`: newer git (CI runs 2.56) refuses a remote name that nests under an existing
        // remote ("is a subset of existing remote"), and this test needs exactly that name to exist.
        g(
            r,
            &["config", "remote.origin/fork.url", "/nowhere/fork.git"],
        );
        g(
            r,
            &[
                "config",
                "remote.origin/fork.fetch",
                "+refs/heads/*:refs/remotes/origin/fork/*",
            ],
        );
        g(r, &["update-ref", "refs/remotes/origin/fork/main", &b]);
        let zeros = "0".repeat(40);
        let to = |remote: &str| {
            check_push(
                r,
                &[Sent {
                    old: zeros.clone(),
                    new: b.clone(),
                }],
                Some(remote),
                Some(&fake()),
            )
            .unwrap()
        };
        assert!(
            !to("origin").clean(),
            "a key that only origin/fork has is read for origin"
        );
        assert!(to("origin/fork").clean(), "and origin/fork does have it");
        // origin's own tracking branches still count, whatever they are called
        g(r, &["update-ref", "refs/remotes/origin/feature/x", &b]);
        assert!(to("origin").clean());
    }

    #[test]
    fn v6_with_the_service_down_post_commit_still_checks_the_shapes_and_says_what_it_did_not_check()
    {
        let d = fresh();
        let r = d.path();
        put(
            r,
            "c.ts",
            format!("const k = \"{}\";\n", k("AKI", "AIOSFODNN7EXAMPLE")).as_bytes(),
        );
        assert!(commit(r, &["--no-verify"]));
        let said = crate::guard_cli::post_commit_unscanned(r, "the service is down");
        assert!(said.contains("taken back"), "{said}");
        assert!(said.contains("stored keys were not checked"), "{said}");
        assert!(!said.contains("AKIA"), "{said}");
        assert_eq!(
            git(r, &["rev-list", "--count", "HEAD"]).unwrap().trim(),
            "1"
        );
        // a clean commit: only the statement
        // the taken-back change is still staged: drop it, so the next commit is only the clean file
        g(r, &["rm", "-q", "-f", "--cached", "c.ts"]);
        std::fs::remove_file(r.join("c.ts")).unwrap();
        put(r, "ok.txt", b"fine\n");
        assert!(commit(r, &["--no-verify"]));
        let said = crate::guard_cli::post_commit_unscanned(r, "the service is down");
        assert!(
            said.starts_with("ozbox: stored keys were not checked"),
            "{said}"
        );
        assert_eq!(
            git(r, &["rev-list", "--count", "HEAD"]).unwrap().trim(),
            "2"
        );
    }

    #[test]
    fn v7_a_box_is_known_by_the_file_its_image_writes_and_not_by_where_the_binary_is() {
        let d = tempfile::tempdir().unwrap();
        let marker = d.path().join("image-release");
        assert!(!on_box_at(&marker));
        std::fs::write(&marker, "image-version=1\n").unwrap();
        assert!(on_box_at(&marker));
        assert!(!on_box_at(d.path()), "a folder is not the marker");
        // the marker is what the image build writes
        let provision = include_str!("../../../infra/packer/ozbox-image/scripts/provision.sh");
        assert!(
            provision.contains(BOX_MARKER),
            "{BOX_MARKER} is not written by provision.sh"
        );
        assert_ne!(BOX_MARKER, "/usr/local/bin/ozbox");
    }

    #[test]
    fn v8_a_key_behind_a_json_or_javascript_escape_is_found_and_a_word_is_not_a_boundary() {
        let aws = k("AKI", "AIOSFODNN7EXAMPLE");
        for before in [
            "k=%3D", "k\\u003d", "k\\x3d", "k\\n", "task_", "k=", "\\u00",
        ] {
            // `\u00` + `AKIA...`: four hex digits are needed for an escape, so this one is a word
            let hit = shape_rules(&format!("{before}{aws}")).contains(&"aws-access-key");
            assert_eq!(hit, before != "\\u00", "{before}");
        }
        assert!(!shape_rules(&format!("task{aws}")).contains(&"aws-access-key"));
        assert!(!shape_rules(&format!("k=x{aws}")).contains(&"aws-access-key"));
    }

    #[test]
    fn v10_a_commit_header_is_read_and_a_tree_or_a_parent_line_is_not_text_to_scan() {
        let d = fresh();
        let r = d.path();
        let tree = git(r, &["rev-parse", "HEAD^{tree}"])
            .unwrap()
            .trim()
            .to_string();
        let parent = head(r);
        let obj = format!(
            "tree {tree}\nparent {parent}\nauthor t <t@t> 1 +0000\ncommitter t <t@t> 1 +0000\nmergetag object {parent}\n type commit\n tag v1\n tagger t <t@t> 1 +0000\n \n {SENTINEL}\n\nmerge\n"
        );
        let mut c = testgit::git()
            .arg("-C")
            .arg(r)
            .args([
                "hash-object",
                "-t",
                "commit",
                "-w",
                "--stdin",
                "--literally",
            ])
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .spawn()
            .unwrap();
        use std::io::Write;
        c.stdin.take().unwrap().write_all(obj.as_bytes()).unwrap();
        let out = c.wait_with_output().unwrap();
        let sha = String::from_utf8_lossy(&out.stdout).trim().to_string();
        let h = commit_headers(r, &sha).unwrap();
        assert!(h.contains("mergetag") && h.contains(SENTINEL));
        assert!(!h.contains("tree ") && !h.contains("parent "), "{h}");
        let p = check_push(r, &[sent(&sha)], None, Some(&fake())).unwrap();
        assert!(
            p.stored.iter().any(|h| h.file == "<commit header>"),
            "{:?}",
            p.stored
        );
        assert!(!report(&p).contains(SENTINEL));
    }

    #[test]
    fn v11_a_push_that_may_be_held_can_be_read_again_inside_an_approved_requests_life() {
        // about 120 scans a minute, one per batch; the re-read must take well under the approval's life
        let batches = PUSH_MAX_BYTES.div_ceil(crate::guard_scan::CHUNK) as u64;
        let minutes = batches.div_ceil(120);
        let lives = ozbox_core::approval::APPROVED_MS / 60_000;
        assert!(
            minutes * 3 <= lives * 2,
            "{minutes} minutes to re-read, {lives} minutes of life"
        );
    }
}
