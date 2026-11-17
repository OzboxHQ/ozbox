//! Commits made while the box's secrets service was down, recorded on the box and added to the audit chain once it is back
//! (ADR 0029 Amendment 18).
//!
//! While the service is down a clean commit goes through with a note (Amendment 15): stored values could not be compared. The
//! service is also what writes the audit chain, so nothing could record that commit there at the time. `post-commit` therefore
//! writes one line for it in a small journal of the box user's (`~/.local/state/ozbox/commit-guard-outage.jsonl`), each line
//! hash-chained to the one before it, and the next hook that reaches the service hands the lines to the audit chain, in the
//! order they were written, flagged as made in an outage window. Then the journal is emptied.
//!
//! * **Ordering.** Lines are numbered from 1 and sent in that order, as one batch; the chain keeps the order it is given.
//! * **Replay.** Each event carries its journal's id and number as its source (`src`), and the chain skips a source it already
//!   has: a hook that dies between the append and emptying the journal sends nothing twice when it runs again.
//! * **Damage.** A line that does not read, a number out of order or a broken link is not dropped: what reads is sent, every
//!   event says `journal=damaged`, and one event before them says how many lines could not be read.
//!
//! What this is not: the journal is the box user's file, so a hostile box user (or an agent) can delete it before it is sent.
//! It is a record against accident and for the owner's review, like the hooks themselves (ADR 0041). What leaves the box is
//! still decided by `pre-push`, which stays closed for the whole outage and reads every unpushed commit once the service is
//! back; no approval of any kind, including one signed on the owner's laptop, lets a push through while the service is down.

use std::io::Write;
use std::path::{Path, PathBuf};

use ozbox_core::audit::NewEvent;
use serde::{Deserialize, Serialize};

/// Moves the journal (tests, and a box whose home is elsewhere).
pub const JOURNAL_ENV: &str = "OZBOX_GUARD_OUTAGE_JOURNAL";
/// The action word in the audit chain. Not one of the service's own words (`secrets.`, `audit.`), so the box socket takes it.
pub const ACTION: &str = "guard.commit-unscanned";
/// The word before the count of unreadable lines, when the journal was damaged.
pub const DAMAGED_ACTION: &str = "guard.outage-journal-damaged";
const DOMAIN: &str = "ozbox-guard-outage-v1";
const GENESIS: &str = ozbox_core::audit::GENESIS;
/// A journal that has grown past this many lines (a service down for a very long time, or a loop) is not read whole into one
/// request: the newest lines past it are still kept, and sent the next time.
const MAX_SEND: usize = 180;

/// Why the stored values could not be compared for this commit.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Window {
    /// The service's socket is missing.
    NoSocket,
    /// The socket is there and nothing is listening.
    NotListening,
}

impl Window {
    pub fn word(self) -> &'static str {
        match self {
            Window::NoSocket => "no-socket",
            Window::NotListening => "not-listening",
        }
    }

    /// The window an outage error stands for (see [`crate::guard::service_outage`]); `None` for any other error.
    pub fn of(e: &str) -> Option<Window> {
        if !crate::guard::service_outage(e) {
            return None;
        }
        Some(if e.starts_with(crate::guard::OUTAGE_PREFIX) {
            Window::NoSocket
        } else {
            Window::NotListening
        })
    }
}

/// One line of the journal.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Entry {
    /// The journal's id: random, made with its first line. Together with `n` it is the event's source in the audit chain.
    pub journal: String,
    /// 1, 2, 3 ... in the order the commits were made.
    pub n: u64,
    pub ts_ms: u64,
    /// The repository, by the hash of where it is (16 hex digits; never the path).
    pub repo: String,
    pub commit: String,
    pub tree: String,
    pub window: Window,
    /// The hash of the line before (`GENESIS` for the first).
    pub prev: String,
    pub hash: String,
}

fn entry_hash(e: &Entry) -> String {
    let material = serde_json::json!([
        DOMAIN,
        e.journal,
        e.n,
        e.ts_ms,
        e.repo,
        e.commit,
        e.tree,
        e.window.word(),
        e.prev
    ])
    .to_string();
    ozbox_core::approval_subject::sha256_hex(&material)
}

/// Where the journal is: `OZBOX_GUARD_OUTAGE_JOURNAL`, else the box user's state folder.
pub fn journal_path() -> Option<PathBuf> {
    if let Some(p) = std::env::var_os(JOURNAL_ENV).filter(|p| !p.is_empty()) {
        return Some(PathBuf::from(p));
    }
    dirs::state_dir()
        .or_else(|| dirs::home_dir().map(|h| h.join(".local/state")))
        .map(|d| d.join("ozbox/commit-guard-outage.jsonl"))
}

/// An exclusive lock on the journal for the length of a record or a replay (the kernel frees it if the hook dies).
struct Lock(#[allow(dead_code)] std::fs::File);

fn lock(path: &Path) -> Result<Lock, String> {
    if let Some(d) = path.parent() {
        create_private_dir(d)?;
    }
    let lp = path.with_extension("lock");
    let f = std::fs::OpenOptions::new()
        .create(true)
        .truncate(false)
        .write(true)
        .open(&lp)
        .map_err(|_| "the outage journal's lock could not be opened".to_string())?;
    #[cfg(unix)]
    rustix::fs::flock(&f, rustix::fs::FlockOperation::LockExclusive)
        .map_err(|_| "the outage journal could not be locked".to_string())?;
    Ok(Lock(f))
}

fn create_private_dir(d: &Path) -> Result<(), String> {
    let mut b = std::fs::DirBuilder::new();
    b.recursive(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt;
        b.mode(0o700);
    }
    b.create(d)
        .map_err(|_| "the outage journal's folder could not be made".to_string())
}

/// What the journal holds, and whether every line read and linked to the one before.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Read {
    pub entries: Vec<Entry>,
    /// Lines that did not read as an entry.
    pub unreadable: usize,
    pub intact: bool,
}

/// Read the journal. A missing journal is an empty one.
pub fn read(path: &Path) -> Result<Read, String> {
    let text = match std::fs::read_to_string(path) {
        Ok(t) => t,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => String::new(),
        Err(_) => return Err("the outage journal could not be read".into()),
    };
    Ok(parse(&text))
}

/// Read the journal's text. Pure.
pub fn parse(text: &str) -> Read {
    let mut entries = Vec::new();
    let mut unreadable = 0usize;
    for line in text.lines().filter(|l| !l.trim().is_empty()) {
        match serde_json::from_str::<Entry>(line) {
            Ok(e) => entries.push(e),
            Err(_) => unreadable += 1,
        }
    }
    let mut intact = unreadable == 0;
    let mut prev = GENESIS.to_string();
    for (i, e) in entries.iter().enumerate() {
        let n_ok = e.n == i as u64 + 1;
        let same = entries.first().is_some_and(|f| f.journal == e.journal);
        if !n_ok || !same || e.prev != prev || e.hash != entry_hash(e) {
            intact = false;
        }
        prev = e.hash.clone();
    }
    Read {
        entries,
        unreadable,
        intact,
    }
}

fn new_journal_id() -> Result<String, String> {
    let mut raw = [0u8; 8];
    getrandom::getrandom(&mut raw).map_err(|_| "no random numbers are available".to_string())?;
    Ok(raw.iter().map(|b| format!("{b:02x}")).collect())
}

/// Write the line for the commit just made in `repo` (its HEAD). Called by `post-commit` when the stored values could not be
/// compared because the service is down. Returns the line written.
pub fn record(path: &Path, repo: &Path, window: Window, now_ms: u64) -> Result<Entry, String> {
    let commit = crate::guard::git(repo, &["rev-parse", "HEAD"])?
        .trim()
        .to_string();
    let tree = crate::guard::git(repo, &["rev-parse", "HEAD^{tree}"])?
        .trim()
        .to_string();
    let repo_id = crate::guard_hold::repo_hash(repo)[..16].to_string();
    record_entry(path, &repo_id, &commit, &tree, window, now_ms)
}

/// [`record`] for a commit already named (tests, and anything that knows it).
pub fn record_entry(
    path: &Path,
    repo_id: &str,
    commit: &str,
    tree: &str,
    window: Window,
    now_ms: u64,
) -> Result<Entry, String> {
    let _l = lock(path)?;
    let r = read(path)?;
    let last = r.entries.last();
    let mut e = Entry {
        journal: match r.entries.first() {
            Some(f) => f.journal.clone(),
            None => new_journal_id()?,
        },
        n: last.map_or(0, |l| l.n) + 1,
        ts_ms: now_ms,
        repo: repo_id.to_string(),
        commit: commit.to_string(),
        tree: tree.to_string(),
        window,
        prev: last.map_or_else(|| GENESIS.to_string(), |l| l.hash.clone()),
        hash: String::new(),
    };
    e.hash = entry_hash(&e);
    let mut line = serde_json::to_string(&e).map_err(|_| "the line could not be written")?;
    line.push('\n');
    let mut o = std::fs::OpenOptions::new();
    o.create(true).append(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        o.mode(0o600);
    }
    let mut f = o
        .open(path)
        .map_err(|_| "the outage journal could not be opened".to_string())?;
    f.write_all(line.as_bytes())
        .and_then(|()| f.sync_all())
        .map_err(|_| "the outage journal could not be written".to_string())?;
    Ok(e)
}

/// Where the events go: the box's audit service (see [`ServiceSink`]), or a fake in tests.
pub trait Sink {
    /// The source of the last event in the chain that had one.
    fn last_src(&self) -> Result<Option<(String, u64)>, String>;
    fn append(&self, events: Vec<NewEvent>) -> Result<(), String>;
}

/// The source word of a journal's events in the audit chain.
pub fn epoch(journal: &str) -> String {
    format!("guard-outage-{journal}")
}

/// The events for what the journal holds, in order, skipping what the chain already has (`last`). Pure.
pub fn events(r: &Read, last: Option<&(String, u64)>) -> Vec<NewEvent> {
    let Some(first) = r.entries.first() else {
        return Vec::new();
    };
    let ep = epoch(&first.journal);
    let done = match last {
        Some((e, n)) if *e == ep => Some(*n),
        _ => None,
    };
    let fresh = |n: u64| done.is_none_or(|d| n > d);
    let damaged = if r.intact { "" } else { " journal=damaged" };
    let mut out = Vec::new();
    if !r.intact && fresh(0) {
        out.push(NewEvent {
            ts_ms: first.ts_ms,
            actor: "commit-guard".into(),
            action: DAMAGED_ACTION.into(),
            subject: None,
            detail: format!(
                "outage-window lines-unreadable={} lines-read={}",
                r.unreadable,
                r.entries.len()
            ),
            src: Some((ep.clone(), 0)),
        });
    }
    // numbered by place, not by what a line says: a damaged journal cannot reorder or repeat what is sent
    for (i, e) in r.entries.iter().enumerate().take(MAX_SEND) {
        let n = i as u64 + 1;
        if !fresh(n) {
            continue;
        }
        out.push(NewEvent {
            ts_ms: e.ts_ms,
            actor: "commit-guard".into(),
            action: ACTION.into(),
            subject: Some(e.commit.chars().take(64).collect()),
            detail: format!(
                "outage-window window={} repo={} tree={} n={n}{damaged}",
                e.window.word(),
                e.repo.chars().take(16).collect::<String>(),
                e.tree.chars().take(40).collect::<String>(),
            ),
            src: Some((ep.clone(), n)),
        });
    }
    out
}

/// What a replay did.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Replayed {
    /// Events added to the chain.
    pub sent: usize,
    /// Commits the journal held.
    pub commits: usize,
    pub intact: bool,
}

/// Hand what the journal holds to the audit chain, then empty it. A sink that cannot be reached leaves the journal as it was,
/// to be sent next time. Nothing to send is `Ok` with nothing sent.
pub fn replay(path: &Path, sink: &dyn Sink) -> Result<Replayed, String> {
    if !path.exists() {
        return Ok(Replayed {
            intact: true,
            ..Replayed::default()
        });
    }
    let _l = lock(path)?;
    let r = read(path)?;
    if r.entries.is_empty() && r.unreadable == 0 {
        let _ = std::fs::remove_file(path);
        return Ok(Replayed {
            intact: true,
            ..Replayed::default()
        });
    }
    let last = sink.last_src()?;
    let ev = events(&r, last.as_ref());
    let sent = ev.len();
    if !ev.is_empty() {
        sink.append(ev)?;
    }
    if r.entries.len() > MAX_SEND {
        // keep what was not sent, renumbered as a journal of its own (a new id, so its sources are new to the chain)
        let rest = r.entries[MAX_SEND..].to_vec();
        let id = new_journal_id()?;
        let tmp = path.with_extension("next");
        let _ = std::fs::remove_file(&tmp);
        let mut prev = GENESIS.to_string();
        for (i, mut e) in rest.into_iter().enumerate() {
            e.journal = id.clone();
            e.n = i as u64 + 1;
            e.prev = prev;
            e.hash = entry_hash(&e);
            prev = e.hash.clone();
            let mut line =
                serde_json::to_string(&e).map_err(|_| "the line could not be written")?;
            line.push('\n');
            let mut f = std::fs::OpenOptions::new()
                .create(true)
                .append(true)
                .open(&tmp)
                .map_err(|_| "the outage journal could not be written".to_string())?;
            f.write_all(line.as_bytes())
                .map_err(|_| "the outage journal could not be written".to_string())?;
        }
        std::fs::rename(&tmp, path)
            .map_err(|_| "the outage journal could not be written".to_string())?;
    } else {
        std::fs::remove_file(path)
            .map_err(|_| "the outage journal could not be emptied".to_string())?;
    }
    Ok(Replayed {
        sent,
        commits: r.entries.len().min(MAX_SEND),
        intact: r.intact,
    })
}

/// The box's audit service, through the box socket (the box user's; the service records the kernel's word for who sent it).
#[cfg(unix)]
pub struct ServiceSink(pub ozbox_core::audit_remote::Remote);

#[cfg(unix)]
impl ServiceSink {
    pub fn on_box(socket: PathBuf) -> Self {
        ServiceSink(ozbox_core::audit_remote::Remote::with_socket(
            socket,
            "tasks",
            PathBuf::from(ozbox_core::audit_remote::DEFAULT_DIR),
            PathBuf::new(),
        ))
    }
}

#[cfg(unix)]
impl Sink for ServiceSink {
    fn last_src(&self) -> Result<Option<(String, u64)>, String> {
        self.0.last_src().map_err(|e| e.to_string())
    }
    fn append(&self, events: Vec<NewEvent>) -> Result<(), String> {
        self.0
            .append_many(events)
            .map(|_| ())
            .map_err(|e| e.to_string())
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use std::cell::RefCell;

    /// A chain that keeps what it is given and dedupes by source the way the real one does (only the last source counts).
    #[derive(Default)]
    struct Chain {
        events: RefCell<Vec<NewEvent>>,
        down: std::cell::Cell<bool>,
    }
    impl Sink for Chain {
        fn last_src(&self) -> Result<Option<(String, u64)>, String> {
            if self.down.get() {
                return Err(crate::secrets_service::SERVICE_DOWN.into());
            }
            Ok(self
                .events
                .borrow()
                .iter()
                .rev()
                .find_map(|e| e.src.clone()))
        }
        fn append(&self, events: Vec<NewEvent>) -> Result<(), String> {
            if self.down.get() {
                return Err(crate::secrets_service::SERVICE_DOWN.into());
            }
            let mut have = self.events.borrow_mut();
            for e in events {
                let last = have.iter().rev().find_map(|x| x.src.clone());
                if let (Some((ep, n)), Some((lep, ln))) = (&e.src, &last) {
                    if ep == lep && n <= ln {
                        continue;
                    }
                }
                have.push(e);
            }
            Ok(())
        }
    }

    fn sha(c: char) -> String {
        c.to_string().repeat(40)
    }

    #[test]
    fn outage_commits_are_journalled_in_order_and_sent_once_in_that_order_flagged_as_outage_window()
    {
        let d = tempfile::tempdir().unwrap();
        let j = d.path().join("j.jsonl");
        for (i, c) in ['a', 'b', 'c'].iter().enumerate() {
            record_entry(
                &j,
                "0123456789abcdef",
                &sha(*c),
                &sha('t'),
                Window::NotListening,
                1000 + i as u64,
            )
            .unwrap();
        }
        let r = read(&j).unwrap();
        assert!(r.intact, "{r:?}");
        assert_eq!(
            r.entries.iter().map(|e| e.n).collect::<Vec<_>>(),
            vec![1, 2, 3]
        );
        // the service is still down: nothing is lost, the journal is kept as it was
        let chain = Chain::default();
        chain.down.set(true);
        assert!(replay(&j, &chain).is_err());
        assert_eq!(read(&j).unwrap(), r);
        // it is back: three events, in the order the commits were made, each flagged
        chain.down.set(false);
        let done = replay(&j, &chain).unwrap();
        assert_eq!((done.sent, done.commits, done.intact), (3, 3, true));
        let ev = chain.events.borrow().clone();
        assert_eq!(
            ev.iter()
                .map(|e| e.subject.clone().unwrap())
                .collect::<Vec<_>>(),
            vec![sha('a'), sha('b'), sha('c')]
        );
        for (i, e) in ev.iter().enumerate() {
            assert_eq!(e.action, ACTION);
            assert!(
                e.detail.starts_with("outage-window window=not-listening"),
                "{}",
                e.detail
            );
            assert!(e.detail.contains(&format!("n={}", i + 1)));
            assert!(!e.detail.contains("damaged"));
            assert!(e.detail.len() <= 160, "{}", e.detail);
            assert!(!crate::audit_service::reserved(&e.action));
        }
        assert!(!j.exists(), "the journal is emptied once the chain has it");
        // nothing more to send
        assert_eq!(replay(&j, &chain).unwrap().sent, 0);
        assert_eq!(chain.events.borrow().len(), 3);
    }

    #[test]
    fn a_replay_that_died_after_the_append_sends_nothing_twice() {
        let d = tempfile::tempdir().unwrap();
        let j = d.path().join("j.jsonl");
        for c in ['a', 'b'] {
            record_entry(&j, "r", &sha(c), &sha('t'), Window::NoSocket, 5).unwrap();
        }
        let text = std::fs::read_to_string(&j).unwrap();
        let chain = Chain::default();
        replay(&j, &chain).unwrap();
        // the hook died before the journal was emptied: the same journal is there again
        std::fs::write(&j, &text).unwrap();
        let again = replay(&j, &chain).unwrap();
        assert_eq!(again.sent, 0);
        assert_eq!(chain.events.borrow().len(), 2);
        // and a commit made after that, in a new outage, is a new journal whose events are new to the chain
        record_entry(&j, "r", &sha('c'), &sha('t'), Window::NoSocket, 9).unwrap();
        assert_eq!(replay(&j, &chain).unwrap().sent, 1);
        assert_eq!(chain.events.borrow().len(), 3);
        assert_eq!(
            chain.events.borrow()[2].subject.as_deref(),
            Some(sha('c').as_str())
        );
    }

    #[test]
    fn a_damaged_or_reordered_journal_is_sent_as_it_reads_in_its_written_order_and_says_so() {
        let d = tempfile::tempdir().unwrap();
        let j = d.path().join("j.jsonl");
        for c in ['a', 'b', 'c'] {
            record_entry(&j, "r", &sha(c), &sha('t'), Window::NoSocket, 5).unwrap();
        }
        // an edit: a line swapped, one changed, one that does not read
        let mut lines: Vec<String> = std::fs::read_to_string(&j)
            .unwrap()
            .lines()
            .map(str::to_string)
            .collect();
        lines.swap(0, 1);
        lines[2] = lines[2].replace(&sha('c'), &sha('d'));
        lines.push("not a line".into());
        std::fs::write(&j, lines.join("\n")).unwrap();
        let r = read(&j).unwrap();
        assert!(!r.intact);
        assert_eq!(r.unreadable, 1);
        let chain = Chain::default();
        let done = replay(&j, &chain).unwrap();
        assert!(!done.intact);
        let ev = chain.events.borrow().clone();
        assert_eq!(ev[0].action, DAMAGED_ACTION);
        assert!(
            ev[0].detail.contains("lines-unreadable=1"),
            "{}",
            ev[0].detail
        );
        // the order is the journal's as it reads now, numbered by place, each flagged
        let subjects: Vec<_> = ev[1..].iter().map(|e| e.subject.clone().unwrap()).collect();
        assert_eq!(subjects, vec![sha('b'), sha('a'), sha('d')]);
        assert!(ev[1..].iter().all(|e| e.detail.contains("journal=damaged")));
        let srcs: Vec<u64> = ev.iter().map(|e| e.src.as_ref().unwrap().1).collect();
        assert_eq!(srcs, vec![0, 1, 2, 3]);
    }

    #[test]
    fn the_window_is_only_an_outage_and_nothing_else_is_journalled() {
        assert_eq!(
            Window::of(crate::secrets_service::SERVICE_DOWN),
            Some(Window::NotListening)
        );
        assert_eq!(
            Window::of(&format!(
                "{} (its socket is missing)",
                crate::guard::OUTAGE_PREFIX
            )),
            Some(Window::NoSocket)
        );
        for other in [
            crate::secrets_service::SERVICE_NO_ANSWER,
            "too many scans: wait a minute",
            "the request was refused",
        ] {
            assert_eq!(Window::of(other), None, "{other}");
        }
    }

    #[test]
    fn the_journal_is_private_to_the_box_user_and_holds_no_path_or_value() {
        let d = tempfile::tempdir().unwrap();
        let j = d.path().join("state/ozbox/j.jsonl");
        record_entry(
            &j,
            "0123456789abcdef",
            &sha('a'),
            &sha('t'),
            Window::NoSocket,
            1,
        )
        .unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(&j).unwrap().permissions().mode() & 0o777;
            assert_eq!(mode, 0o600);
            let dmode = std::fs::metadata(j.parent().unwrap())
                .unwrap()
                .permissions()
                .mode()
                & 0o777;
            assert_eq!(dmode, 0o700);
        }
        let text = std::fs::read_to_string(&j).unwrap();
        assert!(!text.contains(d.path().to_str().unwrap()));
    }
}
