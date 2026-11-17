//! What the box's secrets service says about itself, in one small file other users of the machine can read
//! (`/run/ozbox-secrets/state`, written by the service only, mode 0644 in a folder only the service can write).
//!
//! The first line is for a person (`ready`, `ready: <a note>` or `not-ready: <the reason>`), as it always was. The lines
//! after it are for programs, so nothing has to read a sentence to decide anything:
//!
//! ```text
//! not-ready: the store's key is not on this disk ...
//! kek=file
//! escrow=none
//! code=no-escrow
//! ```
//!
//! * `kek`: what protects the store's key (`kms`, `tpm2`, `keychain`, `passphrase` or `file`).
//! * `escrow`: for a file-kept key, whether a copy is escrowed off the box (`vault`) or not (`none`).
//! * `store`: with `code=kind-mismatch`, what sealed the store the service found (`file`): not the kind in `kek`.
//! * `failing_since`: unix seconds when the service first stopped being ready, kept across the unit's restarts (it is carried
//!   over while the file before said not-ready too, and left out once ready). The box's self-test reads it to tell a failure
//!   that has lasted from one that is only starting; a file from an older service has no such line.
//! * `code`: why the service is not ready: `no-escrow` (the store is there, its key is not, and nothing holds a copy) or
//!   `kind-mismatch` (the store is sealed by a key kept in a file, the service is configured for another kind, and the file
//!   key is gone with no copy): the only two states in which `recover-store` may set the store aside, both meaning the store
//!   can never be opened. `config` (anything else a person must change) or `transient` (the service is trying again).
//!
//! `ozbox upgrade` reads it before it replaces a system disk, to say what happens to the store; the root helper's
//! `recover-secrets` reads it, as root, to refuse every state but `no-escrow`.

/// The service's state as written.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct State {
    pub ready: bool,
    /// The person's words: a note when ready, the reason when not.
    pub text: String,
    pub kek: Option<String>,
    /// `Some(true)`: a copy of a file-kept key is escrowed; `Some(false)`: it is not.
    pub escrow: Option<bool>,
    pub code: Option<String>,
    /// With `code=kind-mismatch`: what sealed the store (`kek` is what the service is configured for).
    pub store_kek: Option<String>,
    /// The service that wrote this can move a store sealed by a file key to the fleet's KMS key in place (`ozbox
    /// adopt-fleet-key`); a file from an older service has no such line. `ozbox adopt-fleet-key` asks for it before it
    /// changes anything about the box, so a box whose program is older is never left half-moved.
    pub adopt: bool,
    /// How many secrets the owner or an agent put in the store (the service's own keys and records are not counted). `Some(0)`:
    /// the store holds nothing a new one would lose, so a box may move to another key without losing anything. `None`: not said.
    pub names: Option<u32>,
    /// Unix seconds when the service first stopped being ready, carried across restarts while it stays not ready. `None`: ready,
    /// or written by a service that does not say.
    pub failing_since: Option<u64>,
}

/// The one not-ready code under which a store may be set aside.
pub const NO_ESCROW_CODE: &str = "no-escrow";
/// The other not-ready code under which a store may be set aside: sealed by a file-kept key that is gone, while the service
/// is configured for another kind of key (a box moved to the fleet's KMS key over a store the disk's key sealed).
pub const KIND_MISMATCH_CODE: &str = "kind-mismatch";
const KEKS: [&str; 5] = ["kms", "tpm2", "keychain", "passphrase", "file"];
const CODES: [&str; 4] = [NO_ESCROW_CODE, KIND_MISMATCH_CODE, "config", "transient"];

impl State {
    pub fn ready(note: &str, kek: &str, escrow: Option<bool>) -> Self {
        Self {
            ready: true,
            text: note.to_string(),
            kek: Some(kek.to_string()),
            escrow,
            code: None,
            store_kek: None,
            adopt: true,
            names: None,
            failing_since: None,
        }
    }

    pub fn not_ready(reason: &str, code: &str, kek: Option<&str>, escrow: Option<bool>) -> Self {
        Self {
            ready: false,
            text: reason.to_string(),
            kek: kek.map(str::to_string),
            escrow,
            code: Some(code.to_string()),
            store_kek: None,
            adopt: true,
            names: None,
            failing_since: None,
        }
    }

    /// What sealed the store the service found (said with `kind-mismatch`).
    pub fn with_store_kek(mut self, kind: &str) -> Self {
        self.store_kek = Some(kind.to_string());
        self
    }

    pub fn with_failing_since(mut self, unix_secs: u64) -> Self {
        self.failing_since = Some(unix_secs);
        self
    }

    pub fn with_names(mut self, n: u32) -> Self {
        self.names = Some(n);
        self
    }

    /// The file's text.
    pub fn render(&self) -> String {
        let one_line = |s: &str| s.replace(['\n', '\r'], " ");
        let mut out = match (self.ready, self.text.is_empty()) {
            (true, true) => "ready".to_string(),
            (true, false) => format!("ready: {}", one_line(&self.text)),
            (false, _) => format!("not-ready: {}", one_line(&self.text)),
        };
        out.push('\n');
        if let Some(k) = &self.kek {
            out.push_str(&format!("kek={k}\n"));
        }
        if let Some(e) = self.escrow {
            out.push_str(if e { "escrow=vault\n" } else { "escrow=none\n" });
        }
        if let Some(c) = &self.code {
            out.push_str(&format!("code={c}\n"));
        }
        if let Some(k) = &self.store_kek {
            out.push_str(&format!("store={k}\n"));
        }
        if self.adopt {
            out.push_str("adopt=kms\n");
        }
        if let Some(n) = self.names {
            out.push_str(&format!("names={n}\n"));
        }
        if let Some(t) = self.failing_since {
            out.push_str(&format!("failing_since={t}\n"));
        }
        out
    }

    /// Read the file's text. `None` when the first line is not one the service writes. A value outside the known words is
    /// dropped (so an older or garbled file says less, never something it did not mean). A file written before the lines
    /// after the first existed reads with no `kek`, `escrow` or `code`.
    pub fn parse(text: &str) -> Option<Self> {
        let mut lines = text.lines();
        let first = lines.next()?.trim();
        let mut s = match first {
            "ready" => Self {
                ready: true,
                ..Self::default()
            },
            l if l.starts_with("ready: ") => Self {
                ready: true,
                text: l["ready: ".len()..].to_string(),
                ..Self::default()
            },
            l if l.starts_with("not-ready: ") => Self {
                ready: false,
                text: l["not-ready: ".len()..].to_string(),
                ..Self::default()
            },
            _ => return None,
        };
        for l in lines {
            match l.trim().split_once('=') {
                Some(("kek", v)) if KEKS.contains(&v) => s.kek = Some(v.to_string()),
                Some(("escrow", "vault")) => s.escrow = Some(true),
                Some(("escrow", "none")) => s.escrow = Some(false),
                Some(("code", v)) if CODES.contains(&v) => s.code = Some(v.to_string()),
                Some(("store", v)) if KEKS.contains(&v) => s.store_kek = Some(v.to_string()),
                Some(("adopt", "kms")) => s.adopt = true,
                Some(("names", v)) => s.names = v.parse().ok(),
                Some(("failing_since", v)) => s.failing_since = v.parse().ok(),
                _ => {}
            }
        }
        Some(s)
    }

    /// The store's key is kept in a file and no copy of it is escrowed: a replaced system disk starts a new store.
    pub fn file_kek_without_escrow(&self) -> bool {
        self.kek.as_deref() == Some("file") && self.escrow == Some(false)
    }

    /// The service stopped because its store's key is gone and nothing holds a copy (and only that).
    pub fn is_no_escrow(&self) -> bool {
        !self.ready && self.code.as_deref() == Some(NO_ESCROW_CODE)
    }

    /// The service stopped because the store is sealed by a file-kept key (`store`) that is gone with no copy, and the
    /// service is configured for another kind (`kek`): the store cannot be opened by anything on this box.
    pub fn is_kind_mismatch(&self) -> bool {
        !self.ready
            && self.code.as_deref() == Some(KIND_MISMATCH_CODE)
            && self.store_kek.as_deref() == Some("file")
            && self.kek.is_some()
            && self.kek.as_deref() != Some("file")
    }

    /// The store can never be opened (a lost key, or a key kind it was not sealed with): the states a store may be set aside in.
    pub fn is_unopenable(&self) -> bool {
        self.is_no_escrow() || self.is_kind_mismatch()
    }
}

/// The time a not-ready service first failed, from the state file as it was before this start: carried over while that file said
/// not-ready and named a time (a restart is not a new failure). `None` when it was ready, absent, or from a service that does
/// not say, and the new failure then starts now.
pub fn previous_failing_since(previous: &str) -> Option<u64> {
    State::parse(previous)
        .filter(|p| !p.ready)
        .and_then(|p| p.failing_since)
}

/// Read the state file as root would trust it: a plain file (not a link), owned by `owner` (the secrets user), that no one
/// else may write, in a folder owned by `owner` or root that no one else may write either. Anything else is refused with
/// the reason, so a file someone else placed is never taken for the service's word.
#[cfg(unix)]
pub fn read_trusted(path: &std::path::Path, owner: u32) -> Result<State, String> {
    use std::io::Read;
    use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
    let dir = path
        .parent()
        .ok_or_else(|| "the secrets service's state file has no folder".to_string())?;
    let dm = std::fs::symlink_metadata(dir).map_err(|e| {
        format!(
            "the secrets service's folder could not be read ({})",
            e.kind()
        )
    })?;
    if !dm.is_dir() || (dm.uid() != owner && dm.uid() != 0) || dm.mode() & 0o022 != 0 {
        return Err("the secrets service's folder is not the service's own (it is not owned by the service or root, or others may write in it), so its state is not trusted".into());
    }
    let mut f = std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC)
        .open(path)
        .map_err(|e| match e.kind() {
            std::io::ErrorKind::NotFound => {
                "the secrets service has not written its state".to_string()
            }
            k => format!(
                "the secrets service's state could not be read ({k}); a link is never followed"
            ),
        })?;
    let m = f.metadata().map_err(|e| {
        format!(
            "the secrets service's state could not be read ({})",
            e.kind()
        )
    })?;
    if !m.is_file() || m.uid() != owner || m.mode() & 0o022 != 0 {
        return Err("the secrets service's state file is not one the service wrote (another owner, or others may write it), so it is not trusted".into());
    }
    let mut text = String::new();
    f.by_ref()
        .take(16 * 1024)
        .read_to_string(&mut text)
        .map_err(|e| {
            format!(
                "the secrets service's state could not be read ({})",
                e.kind()
            )
        })?;
    State::parse(&text)
        .ok_or_else(|| "the secrets service's state is not in a shape it writes".into())
}

/// The fixed command `ozbox upgrade` runs on a box to read its secrets state (no input from anywhere).
pub const STATE_COMMAND: &str =
    "cat /run/ozbox-secrets/state 2>/dev/null; echo ozbox-secrets-active=$(systemctl is-active ozbox-secrets.service 2>/dev/null)";

/// Read the answer of [`STATE_COMMAND`]: the state, when there was one, and whether the unit is active.
pub fn parse_remote(out: &str) -> (Option<State>, bool) {
    let mut active = false;
    let mut body = String::new();
    for l in out.lines() {
        match l.trim().strip_prefix("ozbox-secrets-active=") {
            Some(v) => active = v.trim() == "active",
            None => {
                body.push_str(l);
                body.push('\n');
            }
        }
    }
    (State::parse(&body), active)
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn failing_since_is_kept_across_restarts_and_cleared_when_ready() {
        let first = State::not_ready("x (trying again in 2 s)", "transient", Some("kms"), None)
            .with_failing_since(100);
        let text = first.render();
        assert!(text.contains("failing_since=100\n"));
        assert_eq!(State::parse(&text).unwrap().failing_since, Some(100));
        // the next process carries it over while the file before said not-ready
        assert_eq!(previous_failing_since(&text), Some(100));
        // ready leaves it out, so the next failure starts a new clock
        let ready = State::ready("", "kms", None).render();
        assert!(!ready.contains("failing_since"));
        assert_eq!(previous_failing_since(&ready), None);
        // a file from an older service, a ready file that still names a time, and garbage carry nothing
        assert_eq!(previous_failing_since("not-ready: x\nkek=kms\n"), None);
        assert_eq!(previous_failing_since("ready\nfailing_since=5\n"), None);
        assert_eq!(
            previous_failing_since("not-ready: x\nfailing_since=abc\n"),
            None
        );
    }

    #[test]
    fn a_state_round_trips_and_says_what_protects_the_store() {
        for s in [
            State::ready("", "kms", None),
            State::ready("the key is not escrowed", "file", Some(false)),
            State::not_ready("no key here", NO_ESCROW_CODE, Some("file"), Some(false)),
            State::not_ready(
                "the TPM is busy (trying again in 4 s)",
                "transient",
                Some("tpm2"),
                None,
            ),
        ] {
            assert_eq!(State::parse(&s.render()).unwrap(), s);
        }
        let lost = State::not_ready("x", NO_ESCROW_CODE, Some("file"), Some(false));
        assert!(lost.is_no_escrow() && lost.file_kek_without_escrow());
        // the words a person reads are never what decides
        let prose = State::parse("not-ready: the store's key ... has no escrow for it\n").unwrap();
        assert!(!prose.is_no_escrow());
        assert!(!State::ready("", "kms", None).file_kek_without_escrow());
    }

    #[test]
    fn a_kind_mismatch_is_recorded_apart_from_a_restart_and_from_a_lost_key() {
        let m = State::not_ready("x", KIND_MISMATCH_CODE, Some("kms"), None).with_store_kek("file");
        assert_eq!(State::parse(&m.render()).unwrap(), m);
        assert!(m.is_kind_mismatch() && m.is_unopenable() && !m.is_no_escrow());
        // a restart, a configuration state and a store whose kinds match are not it
        for other in [
            State::not_ready("x", "transient", Some("kms"), None).with_store_kek("file"),
            State::not_ready("x", "config", Some("kms"), None).with_store_kek("file"),
            State::not_ready("x", KIND_MISMATCH_CODE, Some("file"), None).with_store_kek("file"),
            State::not_ready("x", KIND_MISMATCH_CODE, Some("kms"), None),
            State::ready("", "kms", None).with_store_kek("file"),
        ] {
            assert!(!other.is_unopenable(), "{other:?}");
        }
        // a lost key is unopenable too
        assert!(State::not_ready("x", NO_ESCROW_CODE, Some("file"), Some(false)).is_unopenable());
    }

    #[test]
    fn an_older_or_garbled_file_says_less_never_something_else() {
        let old = State::parse("ready: the store's key is kept in a file ...\n").unwrap();
        assert!(old.ready && old.kek.is_none() && old.escrow.is_none());
        let odd = State::parse("not-ready: x\nkek=floppy\ncode=whatever\nescrow=maybe\n").unwrap();
        assert_eq!((odd.kek, odd.code, odd.escrow), (None, None, None));
        assert!(State::parse("").is_none());
        assert!(State::parse("hello\n").is_none());
        // a newline in a reason cannot add a line of its own
        let sneaky = State::not_ready("x\ncode=no-escrow", "transient", None, None);
        assert!(!State::parse(&sneaky.render()).unwrap().is_no_escrow());
    }

    #[test]
    fn the_remote_answer_carries_the_state_and_whether_the_unit_runs() {
        let (s, active) =
            parse_remote("ready\nkek=file\nescrow=none\nozbox-secrets-active=active\n");
        assert!(active && s.unwrap().file_kek_without_escrow());
        let (s, active) = parse_remote("ozbox-secrets-active=failed\n");
        assert!(!active && s.is_none());
    }

    #[cfg(unix)]
    #[test]
    fn the_number_of_stored_secrets_is_written_read_back_and_not_taken_from_garbage() {
        let st = State::ready("", "file", Some(false)).with_names(0);
        let text = st.render();
        assert!(text.contains("names=0\n"));
        assert_eq!(State::parse(&text).unwrap().names, Some(0));
        assert_eq!(State::parse("ready\nnames=x\n").unwrap().names, None);
        // an older file says nothing about it
        assert_eq!(State::parse("ready\nkek=file\n").unwrap().names, None);
    }

    #[test]
    fn root_trusts_only_a_file_the_service_wrote() {
        use std::os::unix::fs::{MetadataExt, PermissionsExt};
        let d = tempfile::tempdir().unwrap();
        let dir = d.path().join("run");
        std::fs::create_dir(&dir).unwrap();
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o755)).unwrap();
        let me = std::fs::metadata(&dir).unwrap().uid();
        let p = dir.join("state");
        let lost = State::not_ready("x", NO_ESCROW_CODE, Some("file"), Some(false));
        std::fs::write(&p, lost.render()).unwrap();
        std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o644)).unwrap();
        assert!(read_trusted(&p, me).unwrap().is_no_escrow());
        // the service is another user: this file is not its word
        assert!(read_trusted(&p, me + 1)
            .unwrap_err()
            .contains("not trusted"));
        // others may write it
        std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o666)).unwrap();
        assert!(read_trusted(&p, me).is_err());
        std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o644)).unwrap();
        // a link to a file that says the right words is never followed
        let elsewhere = d.path().join("forged");
        std::fs::write(&elsewhere, lost.render()).unwrap();
        std::fs::remove_file(&p).unwrap();
        std::os::unix::fs::symlink(&elsewhere, &p).unwrap();
        assert!(read_trusted(&p, me).unwrap_err().contains("link"));
        std::fs::remove_file(&p).unwrap();
        // a folder others may write in: anyone could have put the file there
        std::fs::write(&p, lost.render()).unwrap();
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o777)).unwrap();
        assert!(read_trusted(&p, me).unwrap_err().contains("folder"));
    }
}
