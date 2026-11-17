//! What happens to a change the barrier holds (ADR 0041 phase 3, ADR 0023).
//!
//! A held commit or push is **bound** to what was read: for a commit, the staged tree; for a push, the remote's address and every
//! `ref old..new`; and in both, the hash of the held lines. Two ways past, both bound the same way:
//!
//! 1. **A request** the box files and a person decides on the dashboard (or the laptop). The hook files it with the held lines, the
//!    service scans them itself and derives the matches the person is shown, the hook waits, and on approval it reads the change
//!    **again from the tree it is about to accept** and spends the approval with that text. A change edited after it was approved
//!    is another digest, and is refused.
//! 2. **A code** (`OZBOX_GUARD_APPROVAL`), kept for a box whose request operations are not on and as the break-glass. The code names
//!    the repository and the change (`--project`, `--env`), so a code made for one tree does not pass another, and it is spent once.
//!
//! The hook is the box user's, so neither stops a hostile box user: that is ADR 0041's stated limit. What they stop is an honest
//! tool, and an accident, and they make the person's card true for the request that was filed.

use std::path::{Path, PathBuf};
use std::sync::atomic::AtomicBool;

use serde_json::{json, Value};

use crate::approval_wait::{wait_for_decision, Waited};
use crate::guard::{
    check_diff, check_head, check_push, git, remote_name, report, staged_tree, tree_diff, Binding,
    Scanner, Sent, Verdict,
};
use crate::guard_scan::{held_text, REQUEST_MAX};
use crate::messages::t;

/// What a held change is bound to, ready to file or spend.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Held {
    /// The `guard-override` subject (the service adds the matches and the hash of the text itself).
    pub subject: Value,
    pub binding: Binding,
    /// The unified diff the service scans: the held lines.
    pub text: String,
    /// What the person is told this is (for the request's reason).
    pub label: String,
}

const DOMAIN: &str = "ozbox-guard-override-v1";

fn hex16(material: &str) -> String {
    ozbox_core::approval_subject::sha256_hex(material)[..16].to_string()
}

/// The repository, by the hash of where it is: the same repository is the same word on every call, and the box user cannot make it
/// stand for another.
pub fn repo_hash(repo: &Path) -> String {
    let top = git(repo, &["rev-parse", "--show-toplevel"])
        .map(|t| t.trim().to_string())
        .unwrap_or_else(|_| repo.display().to_string());
    ozbox_core::approval_subject::sha256_hex(&top)
}

/// A remote's address without what must not be bound or shown: the credentials in it, a trailing `.git` or `/`, and the case of
/// its scheme and host.
pub fn normalise_remote(url: &str) -> String {
    let u = url.trim();
    let (scheme, rest) = match u.split_once("://") {
        Some((s, r)) => (format!("{}://", s.to_ascii_lowercase()), r),
        None => (String::new(), u),
    };
    let rest = match rest.split_once('/') {
        Some((auth, path)) => {
            let host = auth.rsplit('@').next().unwrap_or(auth).to_ascii_lowercase();
            format!("{host}/{path}")
        }
        None => rest.rsplit('@').next().unwrap_or(rest).to_ascii_lowercase(),
    };
    let rest = rest.trim_end_matches('/');
    let rest = rest.strip_suffix(".git").unwrap_or(rest);
    format!("{scheme}{rest}")
}

/// A commit held: bound to the staged `tree`.
pub fn commit_held(repo: &Path, tree: &str, v: &Verdict) -> Held {
    let text = held_text(&v.held);
    let hash = ozbox_core::approval_subject::sha256_hex(&text);
    let rh = repo_hash(repo);
    Held {
        subject: json!({
            "scope": "guard-override", "hook": "commit",
            "repo_path_hash": rh, "hook_kind": "pre-commit", "tree_id": tree,
        }),
        binding: Binding {
            project: rh[..16].to_string(),
            change: hex16(&format!("{DOMAIN}\0commit\0{tree}\0{hash}")),
        },
        text,
        label: "a commit".into(),
    }
}

/// One pushed ref: the remote's name for it, what the remote has (zeros for a new one) and what is being sent.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PushedRef {
    pub remote_ref: String,
    pub old: String,
    pub new: String,
}

/// A push held: bound to the remote's address and every `ref old..new`.
pub fn push_held(repo: &Path, remote_url: &str, refs: &[PushedRef], v: &Verdict) -> Held {
    let url = normalise_remote(remote_url);
    let text = held_text(&v.held);
    let hash = ozbox_core::approval_subject::sha256_hex(&text);
    let rh = repo_hash(repo);
    let mut sorted: Vec<&PushedRef> = refs.iter().collect();
    sorted.sort_by(|a, b| (&a.remote_ref, &a.new).cmp(&(&b.remote_ref, &b.new)));
    let material: String = sorted
        .iter()
        .map(|r| format!("{} {} {}", r.remote_ref, r.old, r.new))
        .collect::<Vec<_>>()
        .join("\n");
    Held {
        subject: json!({
            "scope": "guard-override", "hook": "push",
            "repo_path_hash": rh, "remote_url": url,
            "refs": sorted.iter().map(|r| json!({"ref_name": r.remote_ref, "old": r.old, "new": r.new})).collect::<Vec<_>>(),
        }),
        binding: Binding {
            project: rh[..16].to_string(),
            change: hex16(&format!("{DOMAIN}\0push\0{url}\0{material}\0{hash}")),
        },
        text,
        label: "a push".into(),
    }
}

/// The request side of a hook: the service's calls, the clock, where to say things, and the Ctrl-C flag.
pub struct Flow<'a> {
    pub call: &'a mut dyn FnMut(&Value) -> Result<Value, String>,
    pub elapsed_ms: &'a dyn Fn() -> u64,
    pub say: &'a mut dyn FnMut(&str),
    pub stop: &'a AtomicBool,
    /// Wait this many milliseconds (a test waits for none).
    pub pause: &'a dyn Fn(u64),
}

/// How long, and how many times, a request that the service refused for the minute's scan budget is tried again: about ten
/// minutes in all, the same as a scan.
const BUDGET_WAITS: u32 = 40;
const BUDGET_WAIT_MS: u64 = 15_000;

/// Send one request, waiting out the service's scan budget. Filing and spending each take a scan slot, and a big push has just
/// used the minute's up reading itself again, so "too many scans" is waited for in the open and never taken for a refusal of the
/// change: the approval a person gave must not be wasted by a busy minute.
fn call_waiting(flow: &mut Flow<'_>, req: &Value) -> Result<Value, String> {
    let mut waited = 0u32;
    loop {
        match (flow.call)(req) {
            Err(e)
                if e.starts_with("too many scans")
                    && waited < BUDGET_WAITS
                    && !flow.stop.load(std::sync::atomic::Ordering::SeqCst) =>
            {
                if waited == 0 {
                    (flow.say)("ozbox: the box is busy checking other changes; waiting for room");
                }
                waited += 1;
                (flow.pause)(BUDGET_WAIT_MS);
            }
            r => return r,
        }
    }
}

/// Whether a request line is too big for the box socket (measured as it is sent, not estimated).
fn too_big(req: &Value) -> bool {
    req.to_string().len() + 1 > REQUEST_MAX
}

/// What the hook does with a held change.
#[derive(Debug, PartialEq, Eq)]
pub enum Outcome {
    /// Let it through (an approval was spent).
    Let,
    /// Stop it, with this message.
    Stop(String),
}

fn how_to_go_ahead(h: &Held, requests: bool) -> String {
    let code = format!(
        "To go ahead with a code instead: `ozbox secrets approve --scope guard-override --project {} --env {}` on a computer with an enrolled key (or the dashboard's Approvals page, Advanced), then set OZBOX_GUARD_APPROVAL to the code for this change only.",
        h.binding.project, h.binding.change
    );
    let enrol = "A box with no second factor enrolled refuses both: enrol a passkey in the dashboard, or make the box with `ozbox create` from a computer with a keychain, then try again.";
    if requests {
        format!("{code} {enrol}")
    } else {
        format!("Ask for a guard-override approval for this change. {code} {enrol}")
    }
}

/// Decide a held change. `again` reads the change a second time, from the tree (or the commits) about to be accepted, and says
/// what it holds now: an approval is spent with **that** text, never the text that was filed.
pub fn decide(
    held: &Held,
    v: &Verdict,
    scanner: Option<&dyn Scanner>,
    code: &str,
    flow: Option<&mut Flow<'_>>,
    again: &dyn Fn() -> Result<Held, String>,
) -> Result<Outcome, String> {
    let said = report(v);
    if !code.is_empty() {
        let mut why = String::new();
        if let Some(s) = scanner {
            match s.override_ok(code, &held.binding) {
                Ok(()) => return Ok(Outcome::Let),
                Err(e) => why = e,
            }
        }
        // the service's own reason (no second factor enrolled, a code for another change) is a sentence for the person
        let why = if why.is_empty() || why == "no" {
            String::new()
        } else {
            format!(" ({why})")
        };
        return Ok(Outcome::Stop(format!(
            "{said}ozbox: that override was not accepted{why}. A code is for one change, is single-use and lasts five minutes. {}\n",
            how_to_go_ahead(held, false)
        )));
    }
    let Some(flow) = flow else {
        return Ok(Outcome::Stop(format!(
            "{said}{}\n",
            how_to_go_ahead(held, false)
        )));
    };
    let ops = (flow.call)(&json!({"op": "areq_capabilities"}))
        .ok()
        .is_some_and(|r| r["request_ops"].as_bool() == Some(true));
    if !ops {
        return Ok(Outcome::Stop(format!(
            "{said}{}\n",
            how_to_go_ahead(held, false)
        )));
    }
    if v.held_overflow {
        return Ok(Outcome::Stop(format!(
            "{said}ozbox: there is more held here than one request can show a person. Remove the keys, or push in smaller pieces. {}\n",
            how_to_go_ahead(held, true)
        )));
    }
    let filing = json!({
        "op": "areq_file",
        "subject": held.subject,
        "scanned_text": held.text,
        "reason": format!("{} was held by the barrier", held.label),
    });
    // measured as it will be sent: the box socket reads a short line, and a request it would refuse is not filed
    if too_big(&filing) {
        return Ok(Outcome::Stop(format!(
            "{said}ozbox: there is more held here than one request can show a person. Remove the keys, or push in smaller pieces. {}\n",
            how_to_go_ahead(held, true)
        )));
    }
    (flow.say)(said.trim_end());
    let id = match call_waiting(flow, &filing) {
        Ok(r) => match r["request"]["id"].as_str() {
            Some(i) => i.to_string(),
            None => return Ok(Outcome::Stop("ozbox: the service answered badly.\n".into())),
        },
        Err(e) => {
            return Ok(Outcome::Stop(format!(
                "{said}ozbox: a request could not be filed ({e}). {}\n",
                how_to_go_ahead(held, true)
            )))
        }
    };
    match wait_for_decision(flow.call, &id, flow.elapsed_ms, flow.say, flow.stop) {
        Waited::Approved { .. } => {}
        Waited::Refused(m) | Waited::GaveUp(m) => {
            return Ok(Outcome::Stop(format!("ozbox: {m}; nothing was let through.\n")))
        }
        // this wait has no limit of its own beyond the request's life, so it never times out early
        Waited::TimedOut => {
            return Ok(Outcome::Stop(
                "ozbox: the wait ran out; nothing was let through.\n".into(),
            ))
        }
        Waited::Stopped => {
            return Ok(Outcome::Stop(
                "ozbox: stopped waiting; the request stays for 30 minutes, and nothing was let through.\n".into(),
            ))
        }
    }
    // read the change again, from what is about to be accepted; spend with that text
    let now = match again() {
        Ok(h) => h,
        Err(e) => {
            return Ok(Outcome::Stop(format!(
                "ozbox: the change could not be read again after the approval ({e}); nothing was let through.\n"
            )))
        }
    };
    if now.subject != held.subject {
        return Ok(Outcome::Stop(
            "ozbox: the change is not the one that was approved (it was edited while waiting); nothing was let through.\n".into(),
        ));
    }
    let spend = json!({
        "op": "areq_spend", "id": id, "subject": now.subject, "scanned_text": now.text,
    });
    if too_big(&spend) {
        return Ok(Outcome::Stop(
            "ozbox: the change, read again after the approval, is more than one request can carry; nothing was let through.\n".into(),
        ));
    }
    match call_waiting(flow, &spend) {
        Ok(_) => {
            // the effect is the hook returning yes; closing the request now keeps the record whole
            let _ = (flow.call)(&json!({"op": "areq_finish", "id": id}));
            Ok(Outcome::Let)
        }
        // say what the service said: "does not match" is one reason among others (the box was busy, the request ran out)
        Err(e) if e.starts_with("too many scans") => Ok(Outcome::Stop(
            "ozbox: the box stayed too busy to check the approval in time; nothing was let through. Run the command again.\n".into(),
        )),
        Err(e) => Ok(Outcome::Stop(format!(
            "ozbox: the service did not accept the approval for this change ({e}); nothing was let through.\n"
        ))),
    }
}

// ---- the marker a commit leaves for post-commit ---------------------------------------------------------------------------

fn marker_path(repo: &Path) -> Option<PathBuf> {
    let p = git(repo, &["rev-parse", "--git-path", "ozbox-guard-approved"]).ok()?;
    let p = PathBuf::from(p.trim());
    Some(if p.is_absolute() { p } else { repo.join(p) })
}

/// How long a marker is good for. `pre-commit` runs before the message editor opens, so a person writing a long message must
/// not lose an approved commit: the binding to the tree and to the commit it was made on does the real work, and the age only
/// stops a marker left by an aborted commit from standing for a commit made much later.
pub const MARKER_TTL_SECS: u64 = 3600;

fn now_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_secs())
}

/// A change that was let through says which tree, which commit it was made on and when, so `post-commit` lets exactly that tree
/// stand, on that parent, soon after, and nothing else. (It used to let any commit made while an override was set stand; a code
/// for one commit then covered whatever came next.)
pub fn write_marker(repo: &Path, tree: &str) {
    write_marker_at(repo, tree, now_secs());
}

fn write_marker_at(repo: &Path, tree: &str, now: u64) {
    if let Some(p) = marker_path(repo) {
        let head = git(repo, &["rev-parse", "--verify", "-q", "HEAD^{commit}"])
            .map(|h| h.trim().to_string())
            .unwrap_or_default();
        let _ = std::fs::write(p, format!("{tree} {head} {now}"));
    }
}

/// Take away any marker. Run at the start of every `pre-commit` and when a change is stopped, so an aborted commit leaves none.
pub fn clear_marker(repo: &Path) {
    if let Some(p) = marker_path(repo) {
        let _ = std::fs::remove_file(p);
    }
}

/// Whether `HEAD` is the commit a marker was written for: its tree is the marker's, it was made on the commit the marker saw as
/// `HEAD` (or, for an amend, that commit is the one before it in the reflog), and the marker is not older than
/// [`MARKER_TTL_SECS`]. Take the marker away either way.
pub fn take_marker_for_head(repo: &Path) -> bool {
    take_marker_for_head_at(repo, now_secs())
}

pub(crate) fn take_marker_for_head_at(repo: &Path, now: u64) -> bool {
    let Some(p) = marker_path(repo) else {
        return false;
    };
    let text = std::fs::read_to_string(&p).unwrap_or_default();
    let _ = std::fs::remove_file(&p);
    let f: Vec<&str> = text.split_whitespace().collect();
    let (tree, head, at) = match f.as_slice() {
        [t, h, a] => (*t, *h, a.parse::<u64>().unwrap_or(0)),
        [t, a] => (*t, "", a.parse::<u64>().unwrap_or(0)),
        _ => return false,
    };
    if at == 0 || now.saturating_sub(at) > MARKER_TTL_SECS || at > now + 60 {
        return false;
    }
    let git1 = |a: &[&str]| {
        git(repo, a)
            .map(|t| t.trim().to_string())
            .unwrap_or_default()
    };
    if tree.is_empty() || tree != git1(&["rev-parse", "HEAD^{tree}"]) {
        return false;
    }
    // the commit it was made on: HEAD's parent, or (an amend) the commit HEAD replaced
    let parent = git1(&["rev-parse", "--verify", "-q", "HEAD~1"]);
    let before = git1(&["rev-parse", "--verify", "-q", "HEAD@{1}"]);
    head == parent || (!head.is_empty() && head == before)
}

// ---- the hooks ---------------------------------------------------------------------------------------------------------------

/// `pre-commit`: `Ok(None)` allows the commit; `Ok(Some(text))` stops it with that message.
pub fn pre_commit(
    repo: &Path,
    scanner: Option<&dyn Scanner>,
    code: &str,
    flow: Option<&mut Flow<'_>>,
) -> Result<Option<String>, String> {
    // whatever an earlier, aborted commit left is gone before anything is decided
    clear_marker(repo);
    let tree = staged_tree(repo)?;
    let v = check_diff(&tree_diff(repo, &tree)?, scanner)?;
    if v.clean() {
        return Ok(None);
    }
    let held = commit_held(repo, &tree, &v);
    let again = || -> Result<Held, String> {
        let t2 = staged_tree(repo)?;
        if t2 != tree {
            return Err("the staged change changed".into());
        }
        let v2 = check_diff(&tree_diff(repo, &t2)?, scanner)?;
        Ok(commit_held(repo, &t2, &v2))
    };
    match decide(&held, &v, scanner, code, flow, &again)? {
        Outcome::Let => {
            write_marker(repo, &tree);
            Ok(None)
        }
        Outcome::Stop(m) => Ok(Some(m)),
    }
}

/// `post-commit`: a commit that got past `pre-commit` (it was skipped, or hooks were pointed elsewhere) with a key in it is taken
/// back, staged, and the bypass is described. A commit whose tree a `pre-commit` let through is left alone: the approval covered
/// that tree. Its message was not part of what was approved, so a key in the message takes the commit back all the same.
/// Returns the message when it acted.
pub fn post_commit(repo: &Path, scanner: Option<&dyn Scanner>) -> Result<Option<String>, String> {
    let (diff, msg) = check_head(repo, scanner)?;
    let approved = take_marker_for_head(repo);
    let diff_ok = diff.clean() || approved;
    if diff_ok && msg.clean() {
        return Ok(None);
    }
    let has_parent = git(repo, &["rev-parse", "--verify", "-q", "HEAD~1"]).is_ok();
    let undone = if has_parent {
        git(repo, &["reset", "--soft", "HEAD~1"]).is_ok()
    } else {
        git(repo, &["update-ref", "-d", "HEAD"]).is_ok()
    };
    let mut said = String::new();
    if !diff_ok {
        said.push_str(&report(&diff));
    }
    if !msg.clean() {
        said.push_str(&report(&msg));
    }
    Ok(Some(format!(
        "{said}ozbox: the barrier was skipped for this commit, so it has been taken back (your changes are still staged).{}\n",
        if undone { "" } else { " It could not be undone: do not push it." }
    )))
}

/// `pre-push`, for every ref being pushed together. `remote` and `url` are what git passes the hook: the remote's name (or its
/// address, for a push by address) and its address.
pub fn pre_push(
    repo: &Path,
    remote: &str,
    remote_url: &str,
    refs: &[PushedRef],
    scanner: Option<&dyn Scanner>,
    code: &str,
    flow: Option<&mut Flow<'_>>,
) -> Result<Option<String>, String> {
    let target = remote_name(repo, remote, remote_url);
    let sent: Vec<Sent> = refs
        .iter()
        .map(|r| Sent {
            old: r.old.clone(),
            new: r.new.clone(),
        })
        .collect();
    let read = || -> Result<(Verdict, Held), String> {
        let v = check_push(repo, &sent, target.as_deref(), scanner)?;
        let h = push_held(repo, remote_url, refs, &v);
        Ok((v, h))
    };
    let (v, held) = read()?;
    if v.clean() {
        return Ok(None);
    }
    let again = || read().map(|(_, h)| h);
    match decide(&held, &v, scanner, code, flow, &again)? {
        Outcome::Let => Ok(None),
        Outcome::Stop(m) => Ok(Some(m)),
    }
}

// ---- when the secrets service cannot be reached (ADR 0029 Amendment 15) -------------------------------------------------------

/// What a hook decided while the box's secrets service could not be reached.
#[derive(Debug, PartialEq, Eq)]
pub enum Degraded {
    /// Let it through. The text is printed first when there is any: what was not checked, and that nothing was lost.
    Pass(Option<String>),
    /// Stop it, with this message.
    Stop(String),
}

/// The line that says what to do about the service itself (see `commit_guard.fix` in the message catalogue). Whoever runs the box
/// does it from their computer: the box user can neither read the service's log nor restart it.
fn outage_fix() -> String {
    t("commit_guard.fix", &[])
}

/// `pre-commit` while the service cannot be asked. Everything that does not need it still runs: the shapes of keys, the names of
/// files and `.env` files. A commit that holds one is stopped, and no approval can be given while the service that records approvals
/// is down. A clean commit is let through and says what was not checked: it stays on this box, and `pre-push`, which stays closed
/// until the service is back, reads every commit again against the stored values before anything leaves.
pub fn pre_commit_degraded(repo: &Path, why: &str) -> Result<Degraded, String> {
    clear_marker(repo);
    let tree = staged_tree(repo)?;
    let v = check_diff(&tree_diff(repo, &tree)?, None)?;
    if !v.clean() {
        return Ok(Degraded::Stop(format!(
            "{}{}",
            report(&v),
            t(
                "commit_guard.commit_stopped",
                &[("why", why), ("fix", &outage_fix())]
            )
        )));
    }
    Ok(Degraded::Pass(Some(t(
        "commit_guard.commit_passed",
        &[("why", why), ("fix", &outage_fix())],
    ))))
}

/// `pre-push` while the service cannot be asked: always stopped, because a push is what leaves the box and the stored values
/// cannot be compared. The shapes are still read, so a person who has to fix something hears all of it at once.
pub fn pre_push_degraded(
    repo: &Path,
    remote: &str,
    remote_url: &str,
    refs: &[PushedRef],
    why: &str,
) -> String {
    let target = remote_name(repo, remote, remote_url);
    let sent: Vec<Sent> = refs
        .iter()
        .map(|r| Sent {
            old: r.old.clone(),
            new: r.new.clone(),
        })
        .collect();
    let said = match check_push(repo, &sent, target.as_deref(), None) {
        Ok(v) if !v.clean() => report(&v),
        _ => String::new(),
    };
    format!(
        "{said}{}",
        t(
            "commit_guard.push_stopped",
            &[("why", why), ("fix", &outage_fix())]
        )
    )
}

/// `pre-commit` as the hook runs it: with the service, and when it cannot be reached (`scanner` is that error, or the check fails
/// for it half way), without. Only an outage degrades; every other failure holds the change as before.
pub fn pre_commit_or_degrade(
    repo: &Path,
    scanner: Result<Option<&dyn Scanner>, String>,
    code: &str,
    flow: Option<&mut Flow<'_>>,
) -> Result<Degraded, String> {
    let first = match scanner {
        Ok(sc) => pre_commit(repo, sc, code, flow),
        Err(e) => Err(e),
    };
    match first {
        Ok(None) => Ok(Degraded::Pass(None)),
        Ok(Some(m)) => Ok(Degraded::Stop(m)),
        Err(e) if crate::guard::service_outage(&e) => pre_commit_degraded(repo, &outage_reason(&e)),
        Err(e) => Err(e),
    }
}

/// `pre-push` as the hook runs it: see [`pre_commit_or_degrade`].
pub fn pre_push_or_degrade(
    repo: &Path,
    remote: &str,
    remote_url: &str,
    refs: &[PushedRef],
    scanner: Result<Option<&dyn Scanner>, String>,
    code: &str,
    flow: Option<&mut Flow<'_>>,
) -> Result<Degraded, String> {
    let first = match scanner {
        Ok(sc) => pre_push(repo, remote, remote_url, refs, sc, code, flow),
        Err(e) => Err(e),
    };
    match first {
        Ok(None) => Ok(Degraded::Pass(None)),
        Ok(Some(m)) => Ok(Degraded::Stop(m)),
        Err(e) if crate::guard::service_outage(&e) => Ok(Degraded::Stop(pre_push_degraded(
            repo,
            remote,
            remote_url,
            refs,
            &outage_reason(&e),
        ))),
        Err(e) => Err(e),
    }
}

/// The short reason for a message. Only an outage reaches here (see [`crate::guard::service_outage`]), and both of its causes are
/// a service that is not running: its socket is missing, or the socket is there and nothing is listening on it. A service that
/// is running but "did not answer" is not an outage and never reaches this: its change is held, with that error as it is.
fn outage_reason(e: &str) -> String {
    if e.starts_with(crate::guard::OUTAGE_PREFIX) {
        t("commit_guard.reason_no_socket", &[])
    } else {
        t("commit_guard.reason_not_listening", &[])
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use std::cell::{Cell, RefCell};

    #[test]
    fn a_request_the_service_refuses_for_its_scan_budget_is_waited_for_and_never_taken_for_a_refusal(
    ) {
        let stop = AtomicBool::new(false);
        let calls = Cell::new(0u32);
        let pauses = RefCell::new(Vec::<u64>::new());
        let said = RefCell::new(Vec::<String>::new());
        let mut call = |_: &Value| -> Result<Value, String> {
            calls.set(calls.get() + 1);
            if calls.get() <= 3 {
                Err("too many scans: wait a minute".into())
            } else {
                Ok(json!({"request": {"id": "r1"}}))
            }
        };
        let mut say = |l: &str| said.borrow_mut().push(l.to_string());
        let pause = |ms: u64| pauses.borrow_mut().push(ms);
        let mut flow = Flow {
            call: &mut call,
            elapsed_ms: &|| 0,
            say: &mut say,
            stop: &stop,
            pause: &pause,
        };
        let r = call_waiting(&mut flow, &json!({"op": "areq_spend"})).unwrap();
        assert_eq!(r["request"]["id"], "r1");
        assert_eq!(calls.get(), 4);
        assert_eq!(*pauses.borrow(), vec![BUDGET_WAIT_MS; 3]);
        assert_eq!(said.borrow().len(), 1, "said once, in the open");
        // a different refusal is an answer: not waited for
        let calls2 = Cell::new(0u32);
        let mut call2 = |_: &Value| -> Result<Value, String> {
            calls2.set(calls2.get() + 1);
            Err("no request with that id".into())
        };
        let mut say2 = |_: &str| {};
        let mut flow2 = Flow {
            call: &mut call2,
            elapsed_ms: &|| 0,
            say: &mut say2,
            stop: &stop,
            pause: &|_| {},
        };
        assert!(call_waiting(&mut flow2, &json!({})).is_err());
        assert_eq!(calls2.get(), 1);
        // a budget that never frees gives up after about ten minutes with the service's own words, and Ctrl-C ends the wait at once
        let calls3 = Cell::new(0u32);
        let mut call3 = |_: &Value| -> Result<Value, String> {
            calls3.set(calls3.get() + 1);
            Err("too many scans: wait a minute".into())
        };
        let mut say3 = |_: &str| {};
        let mut flow3 = Flow {
            call: &mut call3,
            elapsed_ms: &|| 0,
            say: &mut say3,
            stop: &stop,
            pause: &|_| {},
        };
        let e = call_waiting(&mut flow3, &json!({})).unwrap_err();
        assert!(e.starts_with("too many scans"));
        assert_eq!(calls3.get(), BUDGET_WAITS + 1);
        let stopped = AtomicBool::new(true);
        let calls4 = Cell::new(0u32);
        let mut call4 = |_: &Value| -> Result<Value, String> {
            calls4.set(calls4.get() + 1);
            Err("too many scans: wait a minute".into())
        };
        let mut say4 = |_: &str| {};
        let mut flow4 = Flow {
            call: &mut call4,
            elapsed_ms: &|| 0,
            say: &mut say4,
            stop: &stopped,
            pause: &|_| {},
        };
        assert!(call_waiting(&mut flow4, &json!({})).is_err());
        assert_eq!(calls4.get(), 1);
    }

    #[test]
    fn a_request_over_what_the_box_socket_reads_is_measured_as_sent() {
        assert!(!too_big(
            &json!({"op": "areq_file", "scanned_text": "x".repeat(1000)})
        ));
        assert!(too_big(
            &json!({"op": "areq_file", "scanned_text": "x".repeat(REQUEST_MAX)})
        ));
        // escaping counts: quotes are two bytes each
        assert!(too_big(
            &json!({"scanned_text": "\"".repeat(REQUEST_MAX / 2)})
        ));
    }

    struct Refusing(String);
    impl Scanner for Refusing {
        fn scan(&self, _: &str) -> Result<Vec<String>, String> {
            Ok(vec![])
        }
        fn override_ok(&self, _: &str, _: &Binding) -> Result<(), String> {
            Err(self.0.clone())
        }
    }

    // ---- the secrets service is down (ADR 0029 Amendment 15) ----------------------------------------------------------

    /// A scanner whose service does not answer: every call is the "not reachable" error.
    struct Down;
    impl Scanner for Down {
        fn scan(&self, _: &str) -> Result<Vec<String>, String> {
            Err(crate::secrets_service::SERVICE_DOWN.into())
        }
        fn override_ok(&self, _: &str, _: &Binding) -> Result<(), String> {
            Err(crate::secrets_service::SERVICE_DOWN.into())
        }
    }

    /// A service that answers with a stored name for one value, and nothing for the rest.
    struct Up(&'static str);
    impl Scanner for Up {
        fn scan(&self, text: &str) -> Result<Vec<String>, String> {
            Ok(if text.contains(self.0) {
                vec!["workload.app.staging.API_KEY".into()]
            } else {
                vec![]
            })
        }
        fn override_ok(&self, _: &str, _: &Binding) -> Result<(), String> {
            Err("no".into())
        }
    }

    /// The error a box with no socket gives (see `ServiceScanner::connect_with`).
    fn no_socket() -> String {
        format!(
            "{} (its socket is missing), so stored keys cannot be checked",
            crate::guard::OUTAGE_PREFIX
        )
    }

    /// A repository with one committed file, and `files` written and staged. Returns the repository's folder.
    fn staged(files: &[(&str, &str)]) -> tempfile::TempDir {
        use crate::guard::testgit::{git, must};
        let d = tempfile::tempdir().unwrap();
        for a in [
            &["init", "-q"][..],
            &["config", "user.email", "t@example.com"],
            &["config", "user.name", "t"],
            &["config", "commit.gpgsign", "false"],
        ] {
            must(git().arg("-C").arg(d.path()).args(a));
        }
        std::fs::write(d.path().join("seed.txt"), "seed\n").unwrap();
        must(git().arg("-C").arg(d.path()).args(["add", "-A"]));
        must(
            git()
                .arg("-C")
                .arg(d.path())
                .args(["commit", "-q", "-m", "seed"]),
        );
        for (f, c) in files {
            std::fs::write(d.path().join(f), c).unwrap();
        }
        must(git().arg("-C").arg(d.path()).args(["add", "-A"]));
        d
    }

    /// Built by concatenation, so this file holds no key-shaped literal.
    fn payment_key() -> String {
        format!("{}{}", "sk_li", "ve_0123456789abcdefABCDEF0123")
    }

    fn pushed(r: &Path) -> Vec<PushedRef> {
        must_commit(r);
        let head = git(r, &["rev-parse", "HEAD"]).unwrap();
        vec![PushedRef {
            remote_ref: "refs/heads/main".into(),
            old: "0".repeat(40),
            new: head.trim().to_string(),
        }]
    }

    fn must_commit(r: &Path) {
        use crate::guard::testgit::{git, must};
        must(git().arg("-C").arg(r).args(["commit", "-q", "-m", "work"]));
    }

    const URL: &str = "https://example.com/r.git";

    #[test]
    fn a_commit_with_the_service_down_is_still_read_for_key_shapes_and_a_planted_key_is_stopped() {
        let key = payment_key();
        for scanner in [
            Err(no_socket()),
            Err(crate::secrets_service::SERVICE_DOWN.to_string()),
        ] {
            let d = staged(&[("config.txt", &format!("token = {key}\n"))]);
            let out = pre_commit_or_degrade(d.path(), scanner, "", None).unwrap();
            let Degraded::Stop(m) = out else {
                panic!("a key shape must be stopped while the service is down")
            };
            assert!(
                m.contains("config.txt:1") && m.contains("payment-provider-key"),
                "{m}"
            );
            // what is wrong, that nothing was lost, and what to do, in plain words; never the key
            assert!(m.contains("secrets service is not running"), "{m}");
            assert!(
                m.contains("Nothing was lost") && m.contains("still staged"),
                "{m}"
            );
            assert!(
                m.contains("collect-logs") && m.contains("restart-services"),
                "{m}"
            );
            assert!(!m.contains(&key), "{m}");
        }
        // the service up but dying half way through the check is the same outage
        let d = staged(&[("config.txt", &format!("token = {key}\n"))]);
        let out = pre_commit_or_degrade(d.path(), Ok(Some(&Down)), "", None).unwrap();
        assert!(matches!(out, Degraded::Stop(m) if m.contains("payment-provider-key")));
        // an environment file is stopped by its name, with no service
        let d = staged(&[(".env", "A=1\n")]);
        let out = pre_commit_or_degrade(d.path(), Err(no_socket()), "", None).unwrap();
        assert!(matches!(out, Degraded::Stop(m) if m.contains(".env")));
    }

    #[test]
    fn a_clean_commit_with_the_service_down_goes_through_and_says_what_was_not_checked() {
        for scanner in [Err(no_socket()), Ok(Some(&Down as &dyn Scanner))] {
            let d = staged(&[("notes.txt", "nothing secret here\n")]);
            let out = pre_commit_or_degrade(d.path(), scanner, "", None).unwrap();
            let Degraded::Pass(Some(note)) = out else {
                panic!("a clean commit is let through, with a note")
            };
            assert!(note.contains("NOT against the secrets stored"), "{note}");
            assert!(note.contains("Nothing was lost"), "{note}");
            assert!(note.contains("push is held"), "{note}");
            assert!(note.contains("collect-logs"), "{note}");
        }
    }

    #[test]
    fn only_an_outage_degrades_every_other_failure_still_holds_the_change() {
        struct Failing(&'static str);
        impl Scanner for Failing {
            fn scan(&self, _: &str) -> Result<Vec<String>, String> {
                Err(self.0.into())
            }
            fn override_ok(&self, _: &str, _: &Binding) -> Result<(), String> {
                Err(self.0.into())
            }
        }
        for why in [
            "too many scans: wait a minute",
            "a batch was larger than the service reads in one request (this is a bug in the barrier)",
            "the request was refused",
        ] {
            let d = staged(&[("notes.txt", "clean\n")]);
            let e = pre_commit_or_degrade(d.path(), Ok(Some(&Failing(why))), "", None)
                .unwrap_err();
            assert_eq!(e, why);
        }
        assert!(crate::guard::service_outage(
            crate::secrets_service::SERVICE_DOWN
        ));
        assert!(crate::guard::service_outage(&no_socket()));
        assert!(!crate::guard::service_outage(
            "too many scans: wait a minute"
        ));
    }

    /// A service that is THERE but did not answer (a read that timed out, a reply that was not one, a socket that refuses this
    /// user) is not an outage: the change is held, exactly as it was before the outage rule. Before the connection failure was
    /// told apart from the rest, every one of these degraded and let a clean commit through unscanned.
    #[test]
    fn a_service_that_is_there_but_did_not_answer_holds_the_change_and_is_never_an_outage() {
        let no_answer = crate::secrets_service::SERVICE_NO_ANSWER;
        assert!(!crate::guard::service_outage(no_answer));
        assert_ne!(no_answer, crate::secrets_service::SERVICE_DOWN);
        let d = staged(&[("notes.txt", "clean\n")]);
        let e = pre_commit_or_degrade(d.path(), Err(no_answer.to_string()), "", None).unwrap_err();
        assert_eq!(e, no_answer);
        struct Silent;
        impl Scanner for Silent {
            fn scan(&self, _: &str) -> Result<Vec<String>, String> {
                Err(crate::secrets_service::SERVICE_NO_ANSWER.into())
            }
            fn override_ok(&self, _: &str, _: &Binding) -> Result<(), String> {
                Err(crate::secrets_service::SERVICE_NO_ANSWER.into())
            }
        }
        // half way through a check, too
        let e = pre_commit_or_degrade(d.path(), Ok(Some(&Silent)), "", None).unwrap_err();
        assert_eq!(e, no_answer);
        // and a push is not "stopped as an outage": it fails as a barrier failure, the error as it was
        let refs = [];
        let e = pre_push_or_degrade(
            d.path(),
            "origin",
            URL,
            &refs,
            Err(no_answer.to_string()),
            "",
            None,
        );
        assert_eq!(e.unwrap_err(), no_answer);
    }

    #[test]
    fn the_reason_says_not_running_for_both_outages_and_never_claims_a_silence() {
        for e in [
            no_socket(),
            crate::secrets_service::SERVICE_DOWN.to_string(),
        ] {
            let why = outage_reason(&e);
            assert!(
                why.contains("socket") && !why.contains("did not answer"),
                "{why}"
            );
            let note = match pre_commit_degraded(staged(&[("a.txt", "x\n")]).path(), &why).unwrap()
            {
                Degraded::Pass(Some(n)) => n,
                o => panic!("{o:?}"),
            };
            assert!(
                note.contains("is not running") && !note.contains("did not answer"),
                "{note}"
            );
        }
        assert_eq!(
            outage_reason(&no_socket()),
            crate::messages::t("commit_guard.reason_no_socket", &[])
        );
        assert_ne!(
            outage_reason(crate::secrets_service::SERVICE_DOWN),
            outage_reason(&no_socket())
        );
    }

    #[test]
    fn with_the_service_up_a_commit_is_decided_as_before() {
        let key = payment_key();
        // clean: through, with no note
        let d = staged(&[("notes.txt", "clean\n")]);
        assert_eq!(
            pre_commit_or_degrade(d.path(), Ok(Some(&Up("STORED-VALUE-123"))), "", None).unwrap(),
            Degraded::Pass(None)
        );
        // a stored value: stopped with the usual words, which do not mention an outage
        let d = staged(&[("a.txt", "x = STORED-VALUE-123\n")]);
        let Degraded::Stop(m) =
            pre_commit_or_degrade(d.path(), Ok(Some(&Up("STORED-VALUE-123"))), "", None).unwrap()
        else {
            panic!("a stored value must be stopped")
        };
        assert!(
            m.contains("holds a value this box stores as a secret"),
            "{m}"
        );
        assert!(
            !m.contains("not running") && !m.contains("STORED-VALUE-123"),
            "{m}"
        );
        // a key shape: stopped as before
        let d = staged(&[("a.txt", &format!("{key}\n"))]);
        let Degraded::Stop(m) =
            pre_commit_or_degrade(d.path(), Ok(Some(&Up("STORED-VALUE-123"))), "", None).unwrap()
        else {
            panic!("a key shape must be stopped")
        };
        assert!(
            m.contains("payment-provider-key") && !m.contains("not running"),
            "{m}"
        );
        // no service at all off a box (a laptop): the shapes only, no outage words
        let d = staged(&[("notes.txt", "clean\n")]);
        assert_eq!(
            pre_commit_or_degrade(d.path(), Ok(None), "", None).unwrap(),
            Degraded::Pass(None)
        );
    }

    #[test]
    fn a_push_with_the_service_down_is_always_stopped_and_nothing_leaves() {
        let d = staged(&[("notes.txt", "clean\n")]);
        let refs = pushed(d.path());
        for scanner in [Err(no_socket()), Ok(Some(&Down as &dyn Scanner))] {
            let out =
                pre_push_or_degrade(d.path(), "origin", URL, &refs, scanner, "", None).unwrap();
            let Degraded::Stop(m) = out else {
                panic!("a push is stopped while the stored values cannot be checked")
            };
            assert!(m.contains("secrets service is not running"), "{m}");
            assert!(
                m.contains("Nothing was lost and nothing left the box"),
                "{m}"
            );
            assert!(m.contains("Push again once the service is back"), "{m}");
            assert!(m.contains("recover-secrets"), "{m}");
        }
        // a code cannot get a push past an outage either: the service that spends it is the one that is down
        let out = pre_push_or_degrade(
            d.path(),
            "origin",
            URL,
            &refs,
            Err(no_socket()),
            "AAAA-BBBB",
            None,
        )
        .unwrap();
        assert!(matches!(out, Degraded::Stop(_)));
        // a key shape in an unpushed commit is named in the same message
        let key = payment_key();
        let d = staged(&[("config.txt", &format!("{key}\n"))]);
        let refs = pushed(d.path());
        let Degraded::Stop(m) =
            pre_push_or_degrade(d.path(), "origin", URL, &refs, Err(no_socket()), "", None)
                .unwrap()
        else {
            panic!("stop")
        };
        assert!(
            m.contains("config.txt") && m.contains("payment-provider-key"),
            "{m}"
        );
        assert!(!m.contains(&key), "{m}");
    }

    /// ADR 0029 Amendment 18: no approval of any kind gets a push past an outage. Not a code signed on the owner's laptop (the
    /// service that would check and spend it is the one that is down), and not a request decided elsewhere: the request side is
    /// never even asked, so an answer from anywhere (a socket that says "approved") cannot matter.
    #[test]
    fn a_laptop_signed_code_or_an_approved_request_never_lets_a_push_through_an_outage() {
        let key = payment_key();
        for files in [
            vec![("notes.txt", "clean\n".to_string())],
            vec![("config.txt", format!("{key}\n"))],
        ] {
            let f: Vec<(&str, &str)> = files.iter().map(|(a, b)| (*a, b.as_str())).collect();
            let d = staged(&f);
            let refs = pushed(d.path());
            for scanner in [Err(no_socket()), Ok(Some(&Down as &dyn Scanner))] {
                let stop = AtomicBool::new(false);
                let asked = std::cell::Cell::new(0u32);
                let mut call = |_: &Value| -> Result<Value, String> {
                    asked.set(asked.get() + 1);
                    Ok(
                        json!({"request": {"id": "r1", "state": "approved"}, "approval": "ABCD-EFGH-JKMN-PQRS"}),
                    )
                };
                let mut say = |_: &str| {};
                let mut flow = Flow {
                    call: &mut call,
                    elapsed_ms: &|| 0,
                    say: &mut say,
                    stop: &stop,
                    pause: &|_| {},
                };
                let out = pre_push_or_degrade(
                    d.path(),
                    "origin",
                    URL,
                    &refs,
                    scanner,
                    // the shape of a code `ozbox secrets approve` signs with the laptop's pinned key
                    "ABCD-EFGH-JKMN-PQRS",
                    Some(&mut flow),
                )
                .unwrap();
                let Degraded::Stop(m) = out else {
                    panic!("a push must be stopped during an outage, whatever approval is offered")
                };
                assert!(
                    m.contains("not even one signed on the owner's own computer"),
                    "{m}"
                );
                assert_eq!(
                    asked.get(),
                    0,
                    "no request is filed or read during an outage"
                );
            }
        }
    }

    #[test]
    fn with_the_service_up_a_clean_push_goes_through() {
        let d = staged(&[("notes.txt", "clean\n")]);
        let refs = pushed(d.path());
        assert_eq!(
            pre_push_or_degrade(
                d.path(),
                "origin",
                URL,
                &refs,
                Ok(Some(&Up("STORED-VALUE-123"))),
                "",
                None
            )
            .unwrap(),
            Degraded::Pass(None)
        );
    }

    #[test]
    fn a_code_on_a_box_with_no_second_factor_is_refused_with_the_words_for_enrolling() {
        let held = Held {
            subject: json!({}),
            binding: Binding {
                project: "0123456789abcdef".into(),
                change: "fedcba9876543210".into(),
            },
            text: String::new(),
            label: "a commit".into(),
        };
        let reason = crate::secrets_approval::bootstrap_refusal("guard-override");
        let out = decide(
            &held,
            &Verdict::default(),
            Some(&Refusing(reason)),
            "ABCD-EFGH-JKMN-PQRS",
            None,
            &|| Err("unused".into()),
        )
        .unwrap();
        let Outcome::Stop(m) = out else {
            panic!("a code with no second factor enrolled must not let a change through")
        };
        assert!(
            m.contains("no second factor enrolled") && m.contains("Enrol a passkey"),
            "{m}"
        );
        assert!(m.contains("not accepted"), "{m}");
        // with no service answer at all, the generic words still say how to enrol
        let Outcome::Stop(m) = decide(&held, &Verdict::default(), None, "X", None, &|| {
            Err("u".into())
        })
        .unwrap() else {
            panic!("stop")
        };
        assert!(
            m.contains("Enrol a passkey") || m.contains("enrol a passkey"),
            "{m}"
        );
    }
}
