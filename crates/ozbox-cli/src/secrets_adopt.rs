//! Moving a box's secrets store from a file-kept key to the fleet's KMS key, on the box (ADR 0029 Amendment 11).
//!
//! A box made before the fleet key existed keeps its store's key in a file on the system disk, which an upgrade replaces.
//! `ozbox adopt-fleet-key <box>` (on the laptop) lets the box's role use the fleet's key and puts the key's ARN on the box
//! as an **instance tag** (`ozbox-secrets-adopt`), a thing nothing on the box can set. This step runs as root where the
//! box already reads its instance tags (`ozbox secrets configure-box`, at boot and every 15 minutes), sees the tag, and
//! re-wraps the store's keys under KMS **in place**, so what the store holds is kept.
//!
//! The order is the point, because every step can fail and the store is what a person cannot get back:
//!
//! 0. **One lock, one mark.** Everything here runs under one lock (a kernel `flock` on a file under `/run`, root-only), so a move and a cancel
//!    can never run at the same time, and a cancel leaves a root-owned **mark** that no move starts or finishes past. The mark
//!    is the compare-and-set: it is written under the lock, before the grant is taken away, and only a box that says it is
//!    back on its file key with the mark in place may lose the grant.
//! 1. **Reconcile first.** A run that was killed between two writes (a reboot, an OOM kill) leaves the store and the settings
//!    disagreeing, which the service refuses. Both disagreements are decided from the files themselves, deterministically
//!    (see [`reconcile`]), before anything else.
//! 2. Refuse unless the tag is a KMS key ARN, the service itself says it is ready on a **file** key (never a TPM, never an
//!    already-lost store), the settings still name no KMS key, and the key file is there. A different KMS key than the tag's
//!    is never swapped in silently.
//! 3. **Probe KMS** as the secrets user with the box's own encryption context. A grant that has not reached the instance yet
//!    (IAM takes a little while) costs nothing.
//! 4. **Re-wrap a side copy while the service keeps serving.** The store is copied (as the secrets user) beside itself, and the
//!    copy is re-wrapped, opening with the file key **explicitly** and giving every data key back through KMS before its file
//!    is replaced (`rotate_kek`). This is the slow part (one KMS call per secret, twice), and nothing is stopped for it.
//! 5. **A short stop.** The service stops, the live store is compared (SHA-256) with the bytes the copy was made from (a secret
//!    written meanwhile is not lost: the move starts over on the next run), the copy is renamed over the store, the settings
//!    are written (the KMS key and region in, the "a file key is allowed" line out), and the service starts. Every file is
//!    written to a temporary file, fsynced and renamed, so a crash never leaves a partial one.
//! 6. The service must say `kek=kms` and ready. If it does not, the old store and settings are put back and it is started on
//!    the file key it had.
//! 7. **Nothing is destroyed yet.** The key file and the copy beside the store stay until the laptop has *committed*: it has
//!    seen (as root, through Systems Manager) that the service, the store and the `/work` copy are all on KMS, and it has
//!    written the real label `ozbox-secrets-key`. Only a box carrying that label, and no longer the pending one, destroys the
//!    key file (zeroed, then removed) and the copy. Until then a cancel puts the store back under the file key by re-wrapping
//!    it again (so a secret written in the meantime is kept) and the key file was never gone.
//!
//! Nothing here reads a secret's value: the re-wrap handles data keys inside the store code, not this module.

use std::path::{Path, PathBuf};

use crate::box_config::{TagRead, Tags};
use crate::secrets_adopt_facts::{Facts, Kek, Probe};
use crate::secrets_recover::Paths;
use crate::secrets_state::State;

/// The instance tag the laptop sets (`ozbox adopt-fleet-key`): the fleet key's ARN. A tag nothing on the box can write.
pub const TAG_ADOPT: &str = "ozbox-secrets-adopt";
/// The label the laptop writes once the box has been seen to be on KMS: "this store is wrapped by that key".
pub const TAG_KEY: &str = "ozbox-secrets-key";

const SECRETS_UNIT: &str = "ozbox-secrets.service";
/// Units that read `/etc/ozbox/secrets.env`; they are started again once it changes.
const DEPENDENT_UNITS: [&str; 2] = ["ozbox-cloudflared.service", "ozbox-code-connector.service"];
/// The copy of the store kept beside it until the move is committed.
pub const BACKUP: &str = "secrets.json.pre-kms";
/// The side copy that is re-wrapped while the service runs. Its name is chosen so the store's own temporary file
/// (`with_extension("tmp")` of this name is `secrets-kms.tmp`) can never be the service's `secrets.tmp`.
pub const SIDE: &str = "secrets-kms.json";
/// The cancel mark, beside the settings (a root-owned folder, kept across a reboot).
const MARKER: &str = "secrets-adopt-cancelled";
/// How long the service gets to say it is ready on the new key (2 s each), and how long the `/work` copy gets to follow.
const READY_POLLS: u32 = 30;
/// Extra polls per secret: every secret the service unwraps at start-up is one KMS call.
const READY_POLLS_PER_SECRET: u32 = 2;
const COPY_POLLS: u32 = 8;
/// A move that cannot finish because the store keeps changing (N6) waits before it tries again, longer each time: none after
/// the first abort, then 15 minutes, 30, 60, 120, and never more than 4 hours.
const BACKOFF_BASE_SECS: u64 = 15 * 60;
const BACKOFF_CAP_SECS: u64 = 4 * 60 * 60;

/// What the machine does for this step, so a test can say anything.
pub trait Machine {
    /// `systemctl <verb> <unit>`; `Err` carries the words for a person.
    fn unit(&self, verb: &str, unit: &str) -> Result<(), String>;
    /// Whether the unit is running.
    fn active(&self, unit: &str) -> bool;
    /// Check, as the secrets user and with the box's own encryption context, that the KMS key wraps and unwraps a throwaway
    /// key: the grant has reached the machine and the context matches. Nothing is stopped or read.
    fn probe_kms(&self, scope: &str, key_id: &str, region: &str) -> Result<(), String>;
    /// Copy the store file to another file in its folder, as the secrets user (so the copy is the secrets user's and root
    /// never follows a link the secrets user planted).
    fn copy_store(&self, from: &Path, to: &Path) -> Result<(), String>;
    /// Re-wrap the store file `file` from the key kind `from` (`file` or `kms`) to `to`, as the secrets user (see the
    /// module's step 4). Returns how many secrets.
    fn rotate(
        &self,
        file: &Path,
        from: &str,
        to: &str,
        scope: &str,
        key_id: &str,
        region: &str,
    ) -> Result<usize, String>;
    /// The service's own state, as root trusts it.
    fn state(&self) -> Option<State>;
    fn pause(&self, secs: u64);
    /// Whether the metadata guard's table (`inet ozbox_metadata`) is loaded in the kernel: with it the box user cannot reach
    /// the instance role's credentials. Said to the laptop so Begin can refuse a box without it (L5).
    fn metadata_guard_loaded(&self) -> bool;
}

/// What a run did.
#[derive(Debug, PartialEq, Eq)]
pub enum Outcome {
    /// The tag is not on this box (or there is no metadata service): nothing to do.
    NotRequested,
    /// Another run (or a cancel) holds the lock.
    Busy,
    /// The store was re-wrapped and the service is on KMS. The key file and the copy beside the store are KEPT until the
    /// laptop commits (writes the real label), so the move can still be taken back.
    MovedAwaitingCommit(usize),
    /// Already on KMS and waiting for the laptop's commit.
    AwaitingCommit,
    /// The move was committed and the key file is gone.
    Moved(usize),
    /// The move was committed and the service is on KMS; the `/work` copy has not caught up, so the key file stays until the
    /// next run.
    MovedKeyFileStays(usize),
    /// An earlier run did the move; this one removed what it had left (the key file).
    Finished,
    /// Already done and clean.
    AlreadyDone,
    /// A run that was killed half way was put right (the store and the settings agree again).
    Reconciled(String),
    /// A recorded cancel: the box is on its file key and will not move.
    Cancelled,
}

impl Outcome {
    pub fn says(&self) -> String {
        match self {
            Self::NotRequested => "no move to the fleet key was asked for".into(),
            Self::Busy => "another run is moving or cancelling the store; nothing was done".into(),
            Self::MovedAwaitingCommit(n) => format!(
                "the secrets store now keeps its key in the fleet's KMS key ({n} secrets re-wrapped); the key file is KEPT until the move is committed from your computer, so it can still be taken back"
            ),
            Self::AwaitingCommit => {
                "the secrets store is on the fleet's KMS key; the key file is kept until the move is committed from your computer".into()
            }
            Self::Moved(n) => format!(
                "the secrets store now keeps its key in the fleet's KMS key ({n} secrets re-wrapped); the key file is gone"
            ),
            Self::MovedKeyFileStays(n) => format!(
                "the secrets store now keeps its key in the fleet's KMS key ({n} secrets re-wrapped); the key file is removed on the next run, once the copy on /work follows"
            ),
            Self::Finished => "the move to the fleet key was finished: the key file is gone".into(),
            Self::AlreadyDone => {
                "the secrets store already keeps its key in the fleet's KMS key".into()
            }
            Self::Reconciled(how) => format!("a move that was cut short was put right: {how}"),
            Self::Cancelled => "the move to the fleet key was cancelled; the store keeps its file key and no move will start".into(),
        }
    }
}

/// The region of a KMS key ARN, when `arn` is one (`arn:aws:kms:<region>:<account>:key/<id>`).
pub fn arn_region(arn: &str) -> Option<&str> {
    let mut parts = arn.split(':');
    let (a, partition, svc, region, account, rest) = (
        parts.next()?,
        parts.next()?,
        parts.next()?,
        parts.next()?,
        parts.next()?,
        parts.next()?,
    );
    let key = rest.strip_prefix("key/")?;
    let ok = a == "arn"
        && partition.starts_with("aws")
        && partition
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b == b'-')
        && svc == "kms"
        && !region.is_empty()
        && region.len() <= 20
        && region
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
        && account.len() == 12
        && account.bytes().all(|b| b.is_ascii_digit())
        && !key.is_empty()
        && key.len() <= 64
        && key.bytes().all(|b| b.is_ascii_hexdigit() || b == b'-')
        && parts.next().is_none();
    ok.then_some(region)
}

fn without_keys(text: &str, drop: &[&str]) -> Vec<String> {
    text.lines()
        .filter(|l| {
            let key = l
                .trim()
                .split_once('=')
                .map(|(k, _)| k.trim())
                .unwrap_or("");
            !drop.contains(&key)
        })
        .map(str::to_string)
        .collect()
}

fn joined(out: Vec<String>) -> String {
    let mut s = out.join("\n");
    s.push('\n');
    s
}

/// `text` (a settings file) with the KMS key and region set and the file-key allowance removed. Every other line is kept.
pub fn settings_with_kms(text: &str, arn: &str, region: &str) -> String {
    let mut out = without_keys(
        text,
        &[
            "OZBOX_KMS_KEY_ID",
            "OZBOX_KMS_REGION",
            "OZBOX_SECRET_ALLOW_FILE_KEK",
        ],
    );
    out.push(format!("OZBOX_KMS_KEY_ID={arn}"));
    out.push(format!("OZBOX_KMS_REGION={region}"));
    joined(out)
}

/// `text` with the KMS key and region removed and a file-kept key allowed again: the settings a file-keyed box had.
pub fn settings_with_file(text: &str) -> String {
    let mut out = without_keys(
        text,
        &[
            "OZBOX_KMS_KEY_ID",
            "OZBOX_KMS_REGION",
            "OZBOX_SECRET_ALLOW_FILE_KEK",
        ],
    );
    out.push("OZBOX_SECRET_ALLOW_FILE_KEK=1".into());
    joined(out)
}

fn key_file(p: &Paths) -> PathBuf {
    p.store.with_file_name(crate::secrets_persist::KEY_FILE)
}

fn backup_file(p: &Paths) -> PathBuf {
    p.store.with_file_name(BACKUP)
}

fn side_file(p: &Paths) -> PathBuf {
    p.store.with_file_name(SIDE)
}

/// What a busy store leaves to count (tmpfs, beside the lock: a reboot starts the count again).
fn aborts_file(p: &Paths) -> PathBuf {
    p.adopt_lock.with_file_name("move-aborts")
}

fn now_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// How many moves in a row were abandoned because the store changed, and when the last was.
fn read_aborts(p: &Paths) -> (u32, u64) {
    std::fs::read_to_string(aborts_file(p))
        .ok()
        .and_then(|t| {
            let mut it = t.split_whitespace();
            Some((it.next()?.parse().ok()?, it.next()?.parse().ok()?))
        })
        .unwrap_or((0, 0))
}

/// The wait after `count` aborts in a row: none for the first, then doubling from 15 minutes, to a cap.
pub fn backoff_secs(count: u32) -> u64 {
    if count < 2 {
        0
    } else {
        BACKOFF_BASE_SECS
            .saturating_mul(1u64 << (count - 2).min(20))
            .min(BACKOFF_CAP_SECS)
    }
}

/// Seconds still to wait before a move may start again (0: none).
pub fn backoff_left(p: &Paths, now: u64) -> u64 {
    let (count, last) = read_aborts(p);
    (last + backoff_secs(count)).saturating_sub(now)
}

fn note_abort(p: &Paths) {
    let (count, _) = read_aborts(p);
    if let Some(dir) = aborts_file(p).parent() {
        let _ = std::fs::create_dir_all(dir);
    }
    let _ = std::fs::write(
        aborts_file(p),
        format!("{} {}\n", count.saturating_add(1), now_secs()),
    );
}

fn clear_aborts(p: &Paths) {
    let _ = std::fs::remove_file(aborts_file(p));
}

fn marker_file(p: &Paths) -> PathBuf {
    p.settings.with_file_name(MARKER)
}

fn lock_file(p: &Paths) -> PathBuf {
    p.adopt_lock.clone()
}

/// What the `kek` label inside a store file says it is wrapped by, when it has one.
fn kek_label(file: &Path) -> Option<String> {
    let text = std::fs::read_to_string(file).ok()?;
    let v: serde_json::Value = serde_json::from_str(&text).ok()?;
    v.get("kek")?.as_str().map(str::to_string)
}

/// The label of the copy of the store on `/work`, when it has one.
fn persisted_kek(p: &Paths) -> Option<String> {
    kek_label(&p.persist.join(p.store.file_name()?))
}

/// Read a regular file as root without following a link (the folder belongs to the secrets user, who could plant one).
#[cfg(unix)]
fn read_regular(path: &Path) -> std::io::Result<Vec<u8>> {
    use std::io::Read;
    use std::os::unix::fs::OpenOptionsExt;
    let mut f = std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW)
        .open(path)?;
    if !f.metadata()?.is_file() {
        return Err(std::io::ErrorKind::InvalidInput.into());
    }
    let mut v = Vec::new();
    f.read_to_end(&mut v)?;
    Ok(v)
}

fn sha256(bytes: &[u8]) -> Vec<u8> {
    ring::digest::digest(&ring::digest::SHA256, bytes)
        .as_ref()
        .to_vec()
}

/// Write `bytes` to `path` so a crash leaves either the old file or the whole new one: a temporary file made fresh in the
/// same folder (never following a link, never reusing a name), written, fsynced, given the owner and mode, renamed over
/// `path`, and the folder fsynced. `owner` is `(uid, gid)`; `None` leaves root.
#[cfg(unix)]
fn write_atomic_via(
    path: &Path,
    bytes: &[u8],
    mode: u32,
    owner: Option<(u32, u32)>,
    put: &dyn Fn(&mut std::fs::File, &[u8]) -> std::io::Result<()>,
) -> std::io::Result<()> {
    use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
    let dir = path.parent().ok_or(std::io::ErrorKind::InvalidInput)?;
    let name = path
        .file_name()
        .ok_or(std::io::ErrorKind::InvalidInput)?
        .to_string_lossy()
        .into_owned();
    let tmp = dir.join(format!(".{name}.adopt-new"));
    // a leftover from a run that was killed: removed (a link is removed, never followed)
    match std::fs::remove_file(&tmp) {
        Ok(()) => {}
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
        Err(e) => return Err(e),
    }
    let result = (|| {
        let mut f = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .custom_flags(libc::O_NOFOLLOW)
            .mode(0o600)
            .open(&tmp)?;
        put(&mut f, bytes)?;
        if let Some((uid, gid)) = owner {
            std::os::unix::fs::fchown(&f, Some(uid), Some(gid))?;
        }
        f.set_permissions(std::fs::Permissions::from_mode(mode))?;
        f.sync_all()?;
        drop(f);
        std::fs::rename(&tmp, path)?;
        std::fs::File::open(dir)?.sync_all()
    })();
    if result.is_err() {
        let _ = std::fs::remove_file(&tmp);
    }
    result
}

#[cfg(unix)]
fn write_atomic(
    path: &Path,
    bytes: &[u8],
    mode: u32,
    owner: Option<(u32, u32)>,
) -> std::io::Result<()> {
    use std::io::Write;
    write_atomic_via(path, bytes, mode, owner, &|f, b| f.write_all(b))
}

/// The owner and group of an existing file, so a rewritten store keeps them (the secrets user's).
#[cfg(unix)]
fn owner_of(path: &Path) -> Option<(u32, u32)> {
    use std::os::unix::fs::MetadataExt;
    std::fs::symlink_metadata(path)
        .ok()
        .map(|m| (m.uid(), m.gid()))
}

#[cfg(unix)]
fn write_settings(path: &Path, text: &str) -> std::io::Result<()> {
    write_atomic(path, text.as_bytes(), 0o644, None)
}

fn ready_on(m: &dyn Machine, kek: &str) -> bool {
    m.state()
        .is_some_and(|s| s.ready && s.kek.as_deref() == Some(kek))
}

fn wait_ready(m: &dyn Machine, kek: &str, polls: u32) -> bool {
    for _ in 0..polls {
        if ready_on(m, kek) {
            return true;
        }
        m.pause(2);
    }
    false
}

/// A secrets service that is stopped is started again, and given the time to say it is ready on `kek`. `systemctl stop` does
/// not trigger `Restart=on-failure`, so a run cut short between the stop and the start would otherwise leave it down, with
/// its last state file still saying "ready" (N5).
fn ensure_running(m: &dyn Machine, kek: &str, polls: u32) {
    if !m.active(SECRETS_UNIT) {
        let _ = m.unit("start", SECRETS_UNIT);
        let _ = wait_ready(m, kek, polls);
    }
}

/// Put the whole store back after the service did not come up on the new key: the copy of the store (atomically, keeping its
/// owner), the old settings, then start the service on the key it had.
#[cfg(unix)]
fn put_back(p: &Paths, m: &dyn Machine, old_settings: &str, copy: &[u8]) -> String {
    let _ = m.unit("stop", SECRETS_UNIT);
    let owner = owner_of(&p.store);
    // skipped when the bytes already match: a good store is never rewritten for nothing
    let store_ok = read_regular(&p.store).is_ok_and(|now| now == copy)
        || write_atomic(&p.store, copy, 0o600, owner).is_ok();
    let settings_ok = write_settings(&p.settings, old_settings).is_ok();
    let started = m.unit("start", SECRETS_UNIT).is_ok();
    if store_ok && settings_ok && started {
        crate::secrets_persist::destroy(&backup_file(p));
        "the old store and settings were put back and the service was started on the file key it had"
            .into()
    } else {
        format!(
            "putting the old store back did not fully work (store {}, settings {}, service {}); the copy is at {}",
            if store_ok { "restored" } else { "NOT restored" },
            if settings_ok { "restored" } else { "NOT restored" },
            if started { "started" } else { "NOT started" },
            backup_file(p).display()
        )
    }
}

/// The key the tags name for this box: the pending one, else the committed one.
fn tag_arn(tags: &dyn Tags) -> Option<String> {
    tags.get(TAG_ADOPT).or_else(|| tags.get(TAG_KEY))
}

/// Whether the store file and the settings disagree, which only a run killed between two writes leaves (see [`reconcile`]).
fn disagree(p: &Paths) -> bool {
    let settings = crate::secrets_file::env_file(&p.settings);
    let named = settings
        .get("OZBOX_KMS_KEY_ID")
        .is_some_and(|v| !v.is_empty());
    match kek_label(&p.store).as_deref() {
        Some("kms") => !named,
        Some("file") => named && key_file(p).exists(),
        _ => false,
    }
}

/// Whether this box has work to do: a move to start, a commit to finish, a cancel to carry out, or a run to put right. A
/// cheap look, so the root step that reads the tags starts the unit only when there is something to do. A box whose lock is
/// held has a run going already.
#[cfg(unix)]
pub fn pending(p: &Paths, tags: &dyn Tags) -> bool {
    // A half-made move in the file direction is work whatever the tags say (`adopt` settles it before it asks for them), so
    // the unit that runs `adopt` must start for it even when the tags cannot be read (S8).
    if !marker_file(p).exists() && kek_label(&p.store).as_deref() == Some("file") && disagree(p) {
        return true;
    }
    if !tags.available() {
        return false;
    }
    let settings = crate::secrets_file::env_file(&p.settings);
    let named = settings
        .get("OZBOX_KMS_KEY_ID")
        .filter(|v| !v.is_empty())
        .cloned();
    let leftovers = key_file(p).exists() || backup_file(p).exists();
    if marker_file(p).exists() {
        // a recorded cancel: work only while the store is still on KMS (or half way)
        return named.is_some() && leftovers || disagree(p);
    }
    if disagree(p) {
        return true;
    }
    match (tags.get(TAG_ADOPT), tags.get(TAG_KEY)) {
        // asked for: work until the settings name the key; after that it waits for the laptop's commit
        (Some(a), _) => named.as_ref() != Some(&a),
        // committed: work while anything is left to remove, or while the store is still under a file key (a label written
        // before the box moved)
        (None, Some(k)) => {
            leftovers
                || (named.as_ref() != Some(&k) && kek_label(&p.store).as_deref() == Some("file"))
        }
        // neither tag: nothing is asked for. A stranded box is only REPORTED (see [`stranded`] and the facts); nothing here
        // puts a store back on its own, because that loses secrets and only a person may choose it.
        (None, None) => false,
    }
}

/// The unit the move runs as, so the box-secrets unit's start timeout (systemd kills a pre-start step after 90 seconds) cannot
/// stop it half way and leave the secrets service down. Started without waiting; a second start while one runs is refused by
/// systemd, which is the guard against two at once.
pub const UNIT: &str = "ozbox-adopt-fleet-key";

pub fn start_unit(runner: &dyn ozbox_core::CommandRunner) -> Result<(), String> {
    runner
        .run_ok(&ozbox_core::CommandSpec::new("systemd-run").args([
            format!("--unit={UNIT}"),
            "--collect".to_string(),
            "--quiet".to_string(),
            "--description=Oz Box: move the secrets store to the fleet's KMS key".to_string(),
            "/usr/local/bin/ozbox".to_string(),
            "secrets".to_string(),
            "adopt-kms".to_string(),
        ]))
        .map(|_| ())
        .map_err(|e| format!("systemd-run failed ({e}); it is likely running already"))
}

/// Hold the box's adopt lock while `f` runs. `Ok(None)` when another run holds it.
///
/// The lock is a `flock` on a file under `/run` (tmpfs). The kernel owns it: it is released when the holder's file is
/// closed, which happens when the run ends, is killed, or the box reboots, so no state can be left behind and there is no
/// takeover to get wrong. The file is never removed (removing it would let a second run lock a new file while the first
/// still holds the old one). Benchmark effect: none (a one-off, off the measured paths).
#[cfg(unix)]
pub fn with_lock<T>(p: &Paths, f: impl FnOnce() -> T) -> Result<Option<T>, String> {
    use rustix::fs::{flock, FlockOperation};
    match open_lock(p)? {
        None => Ok(None),
        Some(file) => match flock(&file, FlockOperation::NonBlockingLockExclusive) {
            Ok(()) => {
                let out = f();
                drop(file); // closing the file releases the lock
                Ok(Some(out))
            }
            Err(e) if e == rustix::io::Errno::WOULDBLOCK => Ok(None),
            Err(e) => Err(format!("the lock could not be taken ({e})")),
        },
    }
}

/// The lock file, made if needed (its folder root-only), opened without following a link.
#[cfg(unix)]
fn open_lock(p: &Paths) -> Result<Option<std::fs::File>, String> {
    use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt};
    let path = lock_file(p);
    if let Some(dir) = path.parent() {
        if !dir.exists() {
            let _ = std::fs::DirBuilder::new()
                .recursive(true)
                .mode(0o700)
                .create(dir);
        }
    }
    std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .custom_flags(libc::O_NOFOLLOW)
        .mode(0o600)
        .open(&path)
        .map(Some)
        .map_err(|e| format!("the lock could not be opened ({})", e.kind()))
}

/// Whether another run holds the lock right now. A look only: a shared, non-blocking lock that is let go at once.
#[cfg(unix)]
pub fn lock_busy(p: &Paths) -> bool {
    use rustix::fs::{flock, FlockOperation};
    match open_lock(p) {
        Ok(Some(file)) => matches!(
            flock(&file, FlockOperation::NonBlockingLockShared),
            Err(e) if e == rustix::io::Errno::WOULDBLOCK
        ),
        _ => false,
    }
}

/// The step, as root, under the box's lock.
#[cfg(unix)]
pub fn adopt_locked(p: &Paths, m: &dyn Machine, tags: &dyn Tags) -> Result<Outcome, String> {
    match with_lock(p, || adopt(p, m, tags))? {
        Some(r) => r,
        None => Ok(Outcome::Busy),
    }
}

/// Put a run that was killed half way right, from the files themselves (see the module's step 1). `Ok(None)`: they agree.
///
/// * The store says `kms` and the settings choose the file key: the re-wrap landed and the settings did not. KMS must work
///   (the probe), then the settings are written and the service started.
/// * The store says `file`, the settings name KMS and the key file is there: the settings landed and the store did not (or a
///   put-back was cut short). The file settings are written back and the service started.
#[cfg(unix)]
fn reconcile(p: &Paths, m: &dyn Machine, arn: Option<&str>) -> Result<Option<Outcome>, String> {
    if !disagree(p) {
        return Ok(None);
    }
    let old = std::fs::read_to_string(&p.settings)
        .map_err(|_| "the secrets settings could not be read; nothing was changed".to_string())?;
    let settings = crate::secrets_file::env_file(&p.settings);
    let scope = settings
        .get("OZBOX_SECRET_SCOPE")
        .filter(|v| !v.is_empty())
        .cloned()
        .unwrap_or_else(|| "local".into());
    if kek_label(&p.store).as_deref() == Some("kms") {
        let arn = arn.ok_or("the store is wrapped by KMS but the settings do not name the key, and this box's tags name none either, so nothing was changed; run `ozbox adopt-fleet-key` again")?;
        let region = arn_region(arn).ok_or(
            "the key in this box's instance tags is not a KMS key ARN; nothing was changed",
        )?;
        m.probe_kms(&scope, arn, region).map_err(|e| {
            format!("the store is wrapped by KMS but KMS cannot be used yet ({e}); nothing was changed, and this is tried again on the next run")
        })?;
        let _ = m.unit("stop", SECRETS_UNIT);
        write_settings(&p.settings, &settings_with_kms(&old, arn, region))
            .map_err(|_| "the new settings could not be written".to_string())?;
        m.unit("start", SECRETS_UNIT)?;
        if !wait_ready(m, "kms", READY_POLLS) {
            return Err("the settings were put right but the service did not say it was ready on the KMS key in time; the next run looks again".into());
        }
        for u in DEPENDENT_UNITS {
            let _ = m.unit("try-restart", u);
        }
        return Ok(Some(Outcome::Reconciled(
            "the store was already on KMS, and the settings now say so".into(),
        )));
    }
    let _ = m.unit("stop", SECRETS_UNIT);
    write_settings(&p.settings, &settings_with_file(&old))
        .map_err(|_| "the old settings could not be written back".to_string())?;
    m.unit("start", SECRETS_UNIT)?;
    if !wait_ready(m, "file", READY_POLLS) {
        return Err("the file-key settings were put back but the service did not say it was ready in time; the next run looks again".into());
    }
    for u in DEPENDENT_UNITS {
        let _ = m.unit("try-restart", u);
    }
    Ok(Some(Outcome::Reconciled(
        "the store is still under the file key, and the settings now say so".into(),
    )))
}

/// The step, as root. Call it through [`adopt_locked`].
#[cfg(unix)]
pub fn adopt(p: &Paths, m: &dyn Machine, tags: &dyn Tags) -> Result<Outcome, String> {
    // A run cut short in the file direction (the settings name KMS, the store is still file-wrapped, the key file is there) is put
    // right from the files alone, BEFORE the tags are asked for: it depends on no tag, and a run killed here must not leave the
    // service down until the metadata service answers cleanly (S8). With a cancel recorded, the cancel is the run to finish.
    if !marker_file(p).exists() && kek_label(&p.store).as_deref() == Some("file") && disagree(p) {
        if let Some(done) = reconcile(p, m, None)? {
            return Ok(done);
        }
    }
    if !tags.available() {
        return Ok(Outcome::NotRequested);
    }
    // A tag that could not be READ is not a tag that is not there: nothing is decided from it, and nothing changes.
    let (adopt_tag, key_tag) = match (tags.read(TAG_ADOPT), tags.read(TAG_KEY)) {
        (TagRead::Unreadable, _) | (_, TagRead::Unreadable) => {
            return Err("this box's instance tags could not be read just now (the metadata service did not answer cleanly); nothing was changed and the next run tries again".into())
        }
        (a, k) => (
            match a {
                TagRead::Present(v) => Some(v),
                _ => None,
            },
            match k {
                TagRead::Present(v) => Some(v),
                _ => None,
            },
        ),
    };
    for t in [&adopt_tag, &key_tag].into_iter().flatten() {
        if arn_region(t).is_none() {
            return Err(
                "the key in this box's instance tags is not a KMS key ARN; nothing was changed"
                    .into(),
            );
        }
    }
    // A recorded cancel: no move starts or finishes past it.
    if marker_file(p).exists() {
        return cancel_run(p, m, tags);
    }
    let Some(arn) = adopt_tag.clone().or_else(|| key_tag.clone()) else {
        // Neither tag: nothing is asked for, and nothing changes (the laptop swaps its tags when it finishes). A box that
        // stays like that over a moved store is REPORTED as stranded in its facts; it is never put back from here.
        return Ok(Outcome::NotRequested);
    };
    let region = arn_region(&arn)
        .ok_or("the key in this box's instance tags is not a KMS key ARN; nothing was changed")?
        .to_string();
    let named = |p: &Paths| {
        crate::secrets_file::env_file(&p.settings)
            .get("OZBOX_KMS_KEY_ID")
            .filter(|v| !v.is_empty())
            .cloned()
    };
    if let Some(id) = named(p) {
        if id != arn {
            return Err("this box's store already uses a different KMS key than the one its tags name; it is never switched silently, and nothing was changed".into());
        }
    }
    if let Some(done) = reconcile(p, m, Some(&arn))? {
        return Ok(done);
    }
    let settings = crate::secrets_file::env_file(&p.settings);
    let setting = |k: &str| settings.get(k).filter(|v| !v.is_empty()).cloned();
    // already on KMS: the move was made. Commit it, or wait for the commit.
    if setting("OZBOX_KMS_KEY_ID").is_some() {
        if adopt_tag.is_some() {
            ensure_running(m, "kms", READY_POLLS);
            if !ready_on(m, "kms") {
                return Err("the store's settings name the KMS key, but the secrets service is not ready on it yet; nothing is removed".into());
            }
            return Ok(Outcome::AwaitingCommit);
        }
        return finish(p, m, 0);
    }
    let old_settings = std::fs::read_to_string(&p.settings)
        .map_err(|_| "the secrets settings could not be read; nothing was changed".to_string())?;

    // A service a run cut short left stopped is started before anything is asked of it (R7).
    ensure_running(m, "file", READY_POLLS);
    // What it is moving from: a file key, which the service itself must say.
    let state = m
        .state()
        .ok_or("the secrets service has not said what protects its store; nothing was changed")?;
    if !state.ready {
        return Err(format!(
            "the secrets service is not ready ({}), so the store cannot be moved; nothing was changed. If its key was lost with an earlier system disk, `ozbox admin <box> -- recover-secrets` comes first",
            state.text
        ));
    }
    if state.kek.as_deref() != Some("file") {
        return Err(format!(
            "this box's store is kept by {} and not by a file key, so there is nothing to move; nothing was changed",
            state.kek.as_deref().unwrap_or("a key it does not name")
        ));
    }
    if setting("OZBOX_SECRET_ALLOW_FILE_KEK").as_deref() != Some("1")
        || !matches!(setting("OZBOX_SECRET_KEK").as_deref(), None | Some("file"))
    {
        return Err("the secrets settings do not choose a file-kept key, so ozbox will not guess how to move the store; nothing was changed".into());
    }
    let key = key_file(p);
    if !p.store.is_file() || !key.is_file() {
        return Err(
            "the store or its key file is not where it should be; nothing was changed".into(),
        );
    }
    let scope = setting("OZBOX_SECRET_SCOPE").unwrap_or_else(|| "local".into());

    // Can KMS do its part? Found out BEFORE anything is stopped: a grant that has not reached the machine yet (the likeliest
    // first answer), or a context that does not match, must not cost the service anything on every attempt.
    m.probe_kms(&scope, &arn, &region).map_err(|e| {
        format!(
            "KMS cannot be used for this box's secrets yet ({e}); nothing was stopped or changed. A grant on the role takes a few minutes to reach the machine; this is tried again on the next run"
        )
    })?;

    // A store that keeps changing during the re-wrap has made earlier runs give up; each wait is longer than the last (N6).
    let left = backoff_left(p, now_secs());
    if left > 0 {
        return Err(format!(
            "the store was written to while it was being re-wrapped, {} times in a row, so the move waits before it tries again (about {} more minutes; it costs the secrets service a short stop each time). Nothing was stopped or changed",
            read_aborts(p).0,
            left.div_ceil(60)
        ));
    }
    let count = move_store(p, m, &scope, &arn, &region, &old_settings)?;
    clear_aborts(p);
    if adopt_tag.is_some() {
        return Ok(Outcome::MovedAwaitingCommit(count));
    }
    // The real label was already there (written before the box moved): commit at once.
    finish(p, m, count)
}

/// Steps 4 to 6 of the module: the side copy re-wrapped while the service runs, then a short stop. Returns how many secrets.
#[cfg(unix)]
fn move_store(
    p: &Paths,
    m: &dyn Machine,
    scope: &str,
    arn: &str,
    region: &str,
    old_settings: &str,
) -> Result<usize, String> {
    let owner_err = || "a copy of the store could not be made; nothing was changed".to_string();
    let side = side_file(p);
    let cleanup = |side: &Path| {
        let _ = std::fs::remove_file(side);
    };
    let first = read_regular(&p.store)
        .map_err(|_| "the store could not be read; nothing was changed".to_string())?;
    let first_hash = sha256(&first);
    write_atomic(&backup_file(p), &first, 0o600, None).map_err(|_| owner_err())?;
    cleanup(&side);
    if let Err(e) = m.copy_store(&p.store, &side) {
        cleanup(&side);
        crate::secrets_persist::destroy(&backup_file(p));
        return Err(format!("{e}; nothing was changed"));
    }
    // The slow part, while the service keeps serving: one KMS call per secret, twice.
    let count = match m.rotate(&side, "file", "kms", scope, arn, region) {
        Ok(n) => n,
        Err(e) => {
            cleanup(&side);
            crate::secrets_persist::destroy(&backup_file(p));
            return Err(format!(
                "the store was not moved: {e}. It is as it was, and the service was not stopped. A grant on the role takes a few minutes to reach the machine; this is tried again on the next run"
            ));
        }
    };
    // The lock keeps a cancel out of this run: a cancel waits for it, records its mark, and takes the store back.

    // Look once more BEFORE the stop: a store that already changed would only cost a stop and a start to find out (N6).
    if !read_regular(&p.store).is_ok_and(|now| sha256(&now) == first_hash) {
        cleanup(&side);
        crate::secrets_persist::destroy(&backup_file(p));
        note_abort(p);
        return Err("the store changed while it was being re-wrapped, so the swap was not made, nothing was lost and the service was not stopped. This is tried again on a later run, with longer waits if it keeps happening".into());
    }
    // The short stop.
    if let Err(e) = m.unit("stop", SECRETS_UNIT) {
        cleanup(&side);
        crate::secrets_persist::destroy(&backup_file(p));
        return Err(format!(
            "the service could not be stopped ({e}); nothing was changed"
        ));
    }
    let unchanged = read_regular(&p.store).is_ok_and(|now| sha256(&now) == first_hash);
    if !unchanged {
        // a secret was written while the copy was re-wrapped: it would be lost by the swap. Start over on the next run.
        cleanup(&side);
        crate::secrets_persist::destroy(&backup_file(p));
        note_abort(p);
        let back = m.unit("start", SECRETS_UNIT).is_ok();
        return Err(format!(
            "the store changed while it was being re-wrapped, so the swap was not made and nothing was lost; the service {}. This is tried again on a later run, with longer waits if it keeps happening",
            if back { "was started again" } else { "could NOT be started again" }
        ));
    }
    if std::fs::rename(&side, &p.store).is_err()
        || std::fs::File::open(p.store.parent().unwrap_or(Path::new("/")))
            .and_then(|d| d.sync_all())
            .is_err()
    {
        cleanup(&side);
        let how = put_back(p, m, old_settings, &first);
        return Err(format!(
            "the re-wrapped store could not be put in place; {how}"
        ));
    }
    if write_settings(&p.settings, &settings_with_kms(old_settings, arn, region)).is_err() {
        let how = put_back(p, m, old_settings, &first);
        return Err(format!(
            "the new settings could not be written; the store was put back: {how}"
        ));
    }
    if let Err(e) = m.unit("start", SECRETS_UNIT) {
        let how = put_back(p, m, old_settings, &first);
        return Err(format!(
            "the service did not start on the new key ({e}); {how}"
        ));
    }
    // every secret the service unwraps at start-up is a KMS call, so the wait grows with the store
    let polls = READY_POLLS
        + READY_POLLS_PER_SECRET * u32::try_from(count).unwrap_or(u32::MAX / 4).min(1000);
    if !wait_ready(m, "kms", polls) {
        let how = put_back(p, m, old_settings, &first);
        return Err(format!(
            "the service did not say it was ready on the KMS key in time; {how}"
        ));
    }
    // The units that read the settings pick the change up.
    for u in DEPENDENT_UNITS {
        let _ = m.unit("try-restart", u);
    }
    Ok(count)
}

/// The end of a COMMITTED move: once the copy of the store on `/work` is wrapped by KMS too, the key file and the copy beside
/// the store go. `moved` is how many secrets this run re-wrapped (0 when it only finishes an earlier run).
#[cfg(unix)]
fn finish(p: &Paths, m: &dyn Machine, moved: usize) -> Result<Outcome, String> {
    let key = key_file(p);
    let backup = backup_file(p);
    ensure_running(m, "kms", READY_POLLS);
    if !ready_on(m, "kms") {
        return Err("the store's settings name the KMS key, but the secrets service is not ready on it yet; the key file is kept until it is".into());
    }
    if !key.exists() && !backup.exists() {
        return Ok(if moved > 0 {
            Outcome::Moved(moved)
        } else {
            Outcome::AlreadyDone
        });
    }
    let mut followed = false;
    for _ in 0..COPY_POLLS {
        if persisted_kek(p).as_deref() == Some("kms") {
            followed = true;
            break;
        }
        m.pause(5);
    }
    if !followed {
        if moved > 0 {
            return Ok(Outcome::MovedKeyFileStays(moved));
        }
        return Err("the copy of the store on /work is not wrapped by the KMS key yet; the key file is kept until it is".into());
    }
    crate::secrets_persist::destroy(&key);
    crate::secrets_persist::destroy(&backup);
    Ok(if moved > 0 {
        Outcome::Moved(moved)
    } else {
        Outcome::Finished
    })
}

/// Record a cancel (the mark, under the lock the caller holds) and carry it out: a box still on the file key is left alone; a
/// box that already moved (and kept its key file, awaiting the commit) is re-wrapped back under the file key, from the store
/// as it is now, so a secret written since the move is kept. The grant must still work for that (the laptop takes it back
/// only after this says it is done).
#[cfg(unix)]
pub fn cancel(p: &Paths, m: &dyn Machine, tags: &dyn Tags) -> Result<Outcome, String> {
    write_atomic(&marker_file(p), b"cancelled\n", 0o600, None).map_err(|_| {
        "the cancel could not be recorded on the box; nothing was changed".to_string()
    })?;
    cancel_run(p, m, tags)
}

/// [`cancel`] under the lock.
#[cfg(unix)]
pub fn cancel_locked(p: &Paths, m: &dyn Machine, tags: &dyn Tags) -> Result<Outcome, String> {
    match with_lock(p, || cancel(p, m, tags))? {
        Some(r) => r,
        None => Ok(Outcome::Busy),
    }
}

/// Make a move possible again: the cancel mark is taken away (under the lock). The laptop does this before it sets the tag.
#[cfg(unix)]
pub fn arm_locked(p: &Paths) -> Result<Outcome, String> {
    match with_lock(p, || match std::fs::remove_file(marker_file(p)) {
        Ok(()) => Ok(()),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(_) => Err("the cancel mark could not be removed".to_string()),
    })? {
        Some(r) => r.map(|()| Outcome::NotRequested),
        None => Ok(Outcome::Busy),
    }
}

/// The store is on KMS, its settings name the key, the key file and the copy beside the store are still there, and no cancel is
/// recorded: the state of a box between its move and the laptop's commit, and the state a laptop that lost a race (two
/// operators, or a delayed command) leaves after it removed the tag and the grant. Whether the box really is stranded needs
/// two things the laptop confirms from the cloud (the tags are gone) and the box reports (KMS answers "access denied", see
/// [`Facts::kms_probe`]); the box alone never acts on it.
#[cfg(unix)]
fn moved_and_kept(p: &Paths) -> bool {
    let named = crate::secrets_file::env_file(&p.settings)
        .get("OZBOX_KMS_KEY_ID")
        .is_some_and(|v| !v.is_empty());
    named
        && kek_label(&p.store).as_deref() == Some("kms")
        && key_file(p).exists()
        && backup_file(p).exists()
        && !marker_file(p).exists()
}

/// Whether a probe error is the key service's own refusal (an access-denied answer), and not a timeout, a network fault or a
/// tool that would not start: only the first says the grant is gone.
pub fn kms_denied(why: &str) -> bool {
    why.contains(crate::secrets_enc::KEK_DENIED)
}

/// The copy of the store made before the move, when it can be put back: it is itself file-wrapped, and the key file is beside it.
#[cfg(unix)]
fn restorable_copy(p: &Paths) -> Result<Vec<u8>, String> {
    let copy = read_regular(&backup_file(p)).map_err(|_| {
        "the copy of the store made before the move could not be read; nothing was changed"
            .to_string()
    })?;
    let label_is_file = serde_json::from_slice::<serde_json::Value>(&copy)
        .ok()
        .and_then(|v| v.get("kek").and_then(|k| k.as_str().map(str::to_string)))
        .as_deref()
        == Some("file");
    if !label_is_file || !key_file(p).exists() {
        return Err("the copy of the store made before the move is not a file-wrapped store, or the key file is gone; nothing was changed".into());
    }
    Ok(copy)
}

/// Put the copy of the store made before the move back, with the file-key settings, and start the service on it (the copy is
/// from [`restorable_copy`]). Only [`cancel_from_copy`] calls this: a person asked for it.
#[cfg(unix)]
fn restore_from_copy(p: &Paths, m: &dyn Machine, copy: &[u8]) -> Result<String, String> {
    let old = std::fs::read_to_string(&p.settings)
        .map_err(|_| "the secrets settings could not be read; nothing was changed".to_string())?;
    let how = put_back(p, m, &settings_with_file(&old), copy);
    if !wait_ready(m, "file", READY_POLLS) {
        return Err(format!("{how}; the service did not say it was ready on the file key in time; run the cancel again"));
    }
    for u in DEPENDENT_UNITS {
        let _ = m.unit("try-restart", u);
    }
    Ok(how)
}

/// A cancel that puts the copy made before the move back, for a store whose grant is really gone (`adopt-cancel --from-copy`).
/// The person asked for it, and the laptop confirmed from the cloud first: it loses what was saved since the move. It
/// refuses, BEFORE the cancel mark is written, unless the key service itself answers "access denied" (KMS that still answers
/// is a plain cancel, which loses nothing; a timeout or a network fault proves nothing about the grant) and the copy can be
/// put back.
#[cfg(unix)]
pub fn cancel_from_copy_locked(
    p: &Paths,
    m: &dyn Machine,
    tags: &dyn Tags,
) -> Result<Outcome, String> {
    match with_lock(p, || cancel_from_copy(p, m, tags))? {
        Some(r) => r,
        None => Ok(Outcome::Busy),
    }
}

#[cfg(unix)]
fn cancel_from_copy(p: &Paths, m: &dyn Machine, tags: &dyn Tags) -> Result<Outcome, String> {
    let settings = crate::secrets_file::env_file(&p.settings);
    let named = settings
        .get("OZBOX_KMS_KEY_ID")
        .filter(|v| !v.is_empty())
        .cloned();
    if kek_label(&p.store).as_deref() != Some("kms") {
        // nothing to restore: the plain cancel records the mark and says what there is to do
        return cancel(p, m, tags);
    }
    let arn = named
        .or_else(|| tag_arn(tags))
        .ok_or("the store is on KMS but neither the settings nor the tags name the key; nothing was changed")?;
    let region = arn_region(&arn)
        .ok_or("the KMS key is not an ARN; nothing was changed")?
        .to_string();
    let scope = settings
        .get("OZBOX_SECRET_SCOPE")
        .filter(|v| !v.is_empty())
        .cloned()
        .unwrap_or_else(|| "local".into());
    match m.probe_kms(&scope, &arn, &region) {
        Ok(()) => return Err("KMS still answers for this box, so the plain cancel takes the store back without losing anything; use that. Nothing was changed".into()),
        Err(why) if !kms_denied(&why) => return Err("KMS could not be checked cleanly just now (a timeout or a network fault says nothing about the grant), so the copy is not put back. Nothing was changed; try again".into()),
        Err(_) => {}
    }
    // everything that can refuse has refused before anything is written: the mark is the first change
    let copy = restorable_copy(p)?;
    write_atomic(&marker_file(p), b"cancelled\n", 0o600, None).map_err(|_| {
        "the cancel could not be recorded on the box; nothing was changed".to_string()
    })?;
    let how = restore_from_copy(p, m, &copy)?;
    let mut followed = false;
    for _ in 0..COPY_POLLS {
        if persisted_kek(p).as_deref() != Some("kms") {
            followed = true;
            break;
        }
        m.pause(5);
    }
    if !followed {
        return Err(format!(
            "{how}, but the copy on /work is not wrapped by the file key yet; run the cancel again"
        ));
    }
    Ok(Outcome::Cancelled)
}

#[cfg(unix)]
fn cancel_run(p: &Paths, m: &dyn Machine, tags: &dyn Tags) -> Result<Outcome, String> {
    let settings = crate::secrets_file::env_file(&p.settings);
    let named = settings
        .get("OZBOX_KMS_KEY_ID")
        .filter(|v| !v.is_empty())
        .cloned();
    let store = kek_label(&p.store);
    let moved = named.is_some() || store.as_deref() == Some("kms");
    if !moved {
        // never moved (or put right already): the mark is all there is to do
        let _ = std::fs::remove_file(side_file(p));
        crate::secrets_persist::destroy(&backup_file(p));
        // a run cut short between the stop and the start leaves the service down (R7)
        ensure_running(m, "file", READY_POLLS);
        return Ok(Outcome::Cancelled);
    }
    // a service left stopped by a run that was cut short is started first (on whichever key the settings name)
    ensure_running(m, if named.is_some() { "kms" } else { "file" }, READY_POLLS);
    if !key_file(p).exists() {
        return Err("this box's store is on KMS and its key file is gone, so it cannot be taken back to a file key; the grant must stay (nothing was changed). It is committed, not cancelled: run `ozbox adopt-fleet-key` again".into());
    }
    let old = std::fs::read_to_string(&p.settings)
        .map_err(|_| "the secrets settings could not be read; nothing was changed".to_string())?;
    let scope = settings
        .get("OZBOX_SECRET_SCOPE")
        .filter(|v| !v.is_empty())
        .cloned()
        .unwrap_or_else(|| "local".into());
    if store.as_deref() == Some("kms") {
        let arn = named
            .or_else(|| tag_arn(tags))
            .ok_or("the store is on KMS but neither the settings nor the tags name the key; nothing was changed")?;
        let region = arn_region(&arn)
            .ok_or("the KMS key is not an ARN; nothing was changed")?
            .to_string();
        m.probe_kms(&scope, &arn, &region).map_err(|e| {
            format!("KMS cannot be used to take the store back yet ({e}); nothing was changed and the grant must stay{}", if backup_file(p).exists() { ". The copy of the store made before the move is still here: `adopt-fleet-key --cancel` offers to put it back, which loses the secrets saved since the move" } else { "" })
        })?;
        let side = side_file(p);
        let _ = std::fs::remove_file(&side);
        let first = read_regular(&p.store)
            .map_err(|_| "the store could not be read; nothing was changed".to_string())?;
        let first_hash = sha256(&first);
        m.copy_store(&p.store, &side)
            .map_err(|e| format!("{e}; nothing was changed"))?;
        if let Err(e) = m.rotate(&side, "kms", "file", &scope, &arn, &region) {
            let _ = std::fs::remove_file(&side);
            return Err(format!("the store could not be taken back to the file key: {e}; it is as it was, and the grant must stay"));
        }
        m.unit("stop", SECRETS_UNIT)?;
        let unchanged = read_regular(&p.store).is_ok_and(|now| sha256(&now) == first_hash);
        if !unchanged {
            let _ = std::fs::remove_file(&side);
            let _ = m.unit("start", SECRETS_UNIT);
            return Err("the store changed while it was being taken back; nothing was lost, and this is tried again".into());
        }
        if std::fs::rename(&side, &p.store).is_err() {
            let _ = std::fs::remove_file(&side);
            let _ = m.unit("start", SECRETS_UNIT);
            return Err(
                "the re-wrapped store could not be put in place; nothing was changed".into(),
            );
        }
        let _ = std::fs::File::open(p.store.parent().unwrap_or(Path::new("/")))
            .and_then(|d| d.sync_all());
    } else {
        // the store is already under the file key (a run was cut short): only the settings are wrong
        let _ = m.unit("stop", SECRETS_UNIT);
    }
    write_settings(&p.settings, &settings_with_file(&old))
        .map_err(|_| "the file-key settings could not be written back".to_string())?;
    m.unit("start", SECRETS_UNIT)?;
    if !wait_ready(m, "file", READY_POLLS) {
        return Err("the store was taken back to the file key but the service did not say it was ready on it in time; the grant must stay and the next run looks again".into());
    }
    for u in DEPENDENT_UNITS {
        let _ = m.unit("try-restart", u);
    }
    // the copy beside the store has done its job
    crate::secrets_persist::destroy(&backup_file(p));
    // The service's saver refreshes the /work copy every 30 s; until it is file-wrapped again, an upgrade rebuilt from /work
    // would find a KMS-wrapped copy and no grant. So the cancel is not done until it follows.
    let mut followed = false;
    for _ in 0..COPY_POLLS {
        if persisted_kek(p).as_deref() != Some("kms") {
            followed = true;
            break;
        }
        m.pause(5);
    }
    if !followed {
        return Err("the store is back under the file key, but the copy on /work is not wrapped by it yet; the grant must stay until it is (run the cancel again)".into());
    }
    Ok(Outcome::Cancelled)
}

/// What root can see, for the laptop (`ozbox secrets adopt-status`): the same files and the same reading the move uses.
#[cfg(unix)]
pub fn facts(p: &Paths, m: &dyn Machine, tags: &dyn Tags) -> Facts {
    let st = m.state();
    let settings = crate::secrets_file::env_file(&p.settings);
    let valid = |v: Option<String>| v.filter(|a| arn_region(a).is_some());
    // "Ready" is a live answer: the state file keeps saying `ready` after the unit is stopped, so it counts only while the
    // unit is running (R7).
    let running = m.active(SECRETS_UNIT);
    // Only a box that carries what a stranded move leaves is asked about its grant (a KMS call each time), and only the key
    // service's own refusal counts as "denied".
    let kms_probe = match (
        moved_and_kept(p),
        settings
            .get("OZBOX_KMS_KEY_ID")
            .filter(|v| !v.is_empty())
            .and_then(|a| arn_region(a).map(|r| (a.clone(), r.to_string()))),
    ) {
        (true, Some((arn, region))) => {
            let scope = settings
                .get("OZBOX_SECRET_SCOPE")
                .filter(|v| !v.is_empty())
                .cloned()
                .unwrap_or_else(|| "local".into());
            match m.probe_kms(&scope, &arn, &region) {
                Ok(()) => Probe::Ok,
                Err(why) if kms_denied(&why) => Probe::Denied,
                Err(_) => Probe::Failed,
            }
        }
        _ => Probe::Na,
    };
    Facts {
        kms_probe,
        service_ready: running && st.as_ref().is_some_and(|s| s.ready),
        service_kek: Kek::of(st.as_ref().and_then(|s| s.kek.as_deref())),
        store_kek: Kek::of(kek_label(&p.store).as_deref()),
        persist_kek: Kek::of(persisted_kek(p).as_deref()),
        settings_key: valid(
            settings
                .get("OZBOX_KMS_KEY_ID")
                .filter(|v| !v.is_empty())
                .cloned(),
        ),
        key_file: key_file(p).exists(),
        backup: backup_file(p).exists(),
        cancelled: marker_file(p).exists(),
        busy: lock_busy(p) || m.active(UNIT),
        service_escrow: st.as_ref().and_then(|s| s.escrow),
        service_no_escrow: st.as_ref().is_some_and(State::is_no_escrow),
        names: st.as_ref().and_then(|s| s.names),
        metadata_guard: m.metadata_guard_loaded(),
        // a clock that moved back must not make the facts unreadable: the wait is never more than the cap
        move_backoff_mins: u32::try_from(
            backoff_left(p, now_secs())
                .min(BACKOFF_CAP_SECS)
                .div_ceil(60),
        )
        .unwrap_or(0),
        tag_adopt: if tags.available() {
            valid(tags.get(TAG_ADOPT))
        } else {
            None
        },
        tag_key: if tags.available() {
            valid(tags.get(TAG_KEY))
        } else {
            None
        },
    }
}

/// The machine, as it is: `systemctl`, `runuser` to the secrets user for the re-wrap, and the service's state file.
pub struct SystemMachine<'a> {
    pub runner: &'a dyn ozbox_core::CommandRunner,
    pub paths: &'a Paths,
}

impl Machine for SystemMachine<'_> {
    fn unit(&self, verb: &str, unit: &str) -> Result<(), String> {
        self.runner
            .run_ok(&ozbox_core::CommandSpec::new("systemctl").args([verb, unit]))
            .map(|_| ())
            .map_err(|e| format!("systemctl {verb} {unit} failed ({e})"))
    }

    fn active(&self, unit: &str) -> bool {
        self.runner
            .run(&ozbox_core::CommandSpec::new("systemctl").args(["is-active", "--quiet", unit]))
            .is_ok_and(|o| o.status == Some(0))
    }

    fn metadata_guard_loaded(&self) -> bool {
        self.runner
            .run(&ozbox_core::CommandSpec::new("nft").args([
                "list",
                "table",
                "inet",
                "ozbox_metadata",
            ]))
            .is_ok_and(|o| o.status == Some(0))
    }

    fn probe_kms(&self, scope: &str, key_id: &str, region: &str) -> Result<(), String> {
        let spec = ozbox_core::CommandSpec::new("runuser").args([
            "-u".to_string(),
            "ozbox-secrets".to_string(),
            "--".to_string(),
            "env".to_string(),
            format!("OZBOX_SECRET_SCOPE={scope}"),
            format!("OZBOX_KMS_KEY_ID={key_id}"),
            format!("OZBOX_KMS_REGION={region}"),
            "/usr/local/bin/ozbox".to_string(),
            "secrets".to_string(),
            "probe-kms".to_string(),
        ]);
        let out = self
            .runner
            .run(&spec)
            .map_err(|e| format!("the check could not be started ({e})"))?;
        if out.status == Some(0) {
            return Ok(());
        }
        let why: String = out.stderr.trim().chars().take(300).collect();
        Err(if why.is_empty() {
            "the check failed".into()
        } else {
            format!("the check failed ({why})")
        })
    }

    fn copy_store(&self, from: &Path, to: &Path) -> Result<(), String> {
        let spec = ozbox_core::CommandSpec::new("runuser").args([
            "-u".to_string(),
            "ozbox-secrets".to_string(),
            "--".to_string(),
            "cp".to_string(),
            "-f".to_string(),
            "--".to_string(),
            from.display().to_string(),
            to.display().to_string(),
        ]);
        let out = self
            .runner
            .run(&spec)
            .map_err(|e| format!("a copy of the store could not be made ({e})"))?;
        if out.status == Some(0) {
            Ok(())
        } else {
            Err("a copy of the store could not be made".into())
        }
    }

    fn rotate(
        &self,
        file: &Path,
        from: &str,
        to: &str,
        scope: &str,
        key_id: &str,
        region: &str,
    ) -> Result<usize, String> {
        // `env` carries the settings: the old key is chosen explicitly (a KMS key id alone would make KMS the default), and
        // the new one is named for `rotate-kek --to`.
        let spec = ozbox_core::CommandSpec::new("runuser").args([
            "-u".to_string(),
            "ozbox-secrets".to_string(),
            "--".to_string(),
            "env".to_string(),
            format!("OZBOX_SECRET_FILE={}", file.display()),
            format!("OZBOX_SECRET_SCOPE={scope}"),
            format!("OZBOX_SECRET_KEK={from}"),
            format!("OZBOX_KMS_KEY_ID={key_id}"),
            format!("OZBOX_KMS_REGION={region}"),
            "/usr/local/bin/ozbox".to_string(),
            "secrets".to_string(),
            "rotate-kek".to_string(),
            "--to".to_string(),
            to.to_string(),
        ]);
        let out = self
            .runner
            .run(&spec)
            .map_err(|e| format!("the re-wrap could not be started ({e})"))?;
        if out.status != Some(0) {
            let why: String = out.stderr.trim().chars().take(300).collect();
            return Err(if why.is_empty() {
                "the re-wrap failed".into()
            } else {
                format!("the re-wrap failed ({why})")
            });
        }
        Ok(out
            .stdout
            .split_whitespace()
            .find_map(|w| w.parse::<usize>().ok())
            .unwrap_or(0))
    }

    #[cfg(unix)]
    fn state(&self) -> Option<State> {
        let uid: u32 = self
            .runner
            .run(&ozbox_core::CommandSpec::new("id").args(["-u", "ozbox-secrets"]))
            .ok()?
            .stdout
            .trim()
            .parse()
            .ok()?;
        crate::secrets_state::read_trusted(&self.paths.state, uid).ok()
    }

    #[cfg(not(unix))]
    fn state(&self) -> Option<State> {
        None
    }

    fn pause(&self, secs: u64) {
        std::thread::sleep(std::time::Duration::from_secs(secs));
    }
}

#[cfg(all(test, unix))]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    /// True once nobody holds the lock. A `flock` belongs to the open file, and a child another test's thread is
    /// starting (`git`, a command) holds a copy of every descriptor open at that moment until it has exec'd. So the
    /// instant after a holder let go, a look can still see the lock held on a loaded machine. Assertions that the lock
    /// is FREE wait for that to pass (bounded); assertions that it is HELD need no wait.
    fn lock_freed(p: &Paths) -> bool {
        let end = std::time::Instant::now() + std::time::Duration::from_secs(10);
        while lock_busy(p) {
            if std::time::Instant::now() >= end {
                return false;
            }
            std::thread::sleep(std::time::Duration::from_millis(10));
        }
        true
    }

    /// Takes the lock once it is free (same reason as [`lock_freed`]) and says whether `f` ran.
    fn ran_when_free(p: &Paths) -> bool {
        let end = std::time::Instant::now() + std::time::Duration::from_secs(10);
        loop {
            if with_lock(p, || ()).unwrap().is_some() {
                return true;
            }
            if std::time::Instant::now() >= end {
                return false;
            }
            std::thread::sleep(std::time::Duration::from_millis(10));
        }
    }
    /// Runs a locked call again while it answers `Busy`, for up to 10 s. The lock is a kernel `flock` on an open file, and a
    /// child another test's thread is starting holds a copy of that descriptor until it has exec'd, so a call made right after
    /// a holder let go can see `Busy` on a loaded machine. Only tests whose point is NOT the lock use this.
    fn unbusy(f: impl Fn() -> Result<Outcome, String>) -> Result<Outcome, String> {
        let end = std::time::Instant::now() + std::time::Duration::from_secs(10);
        loop {
            let r = f();
            if !matches!(r, Ok(Outcome::Busy)) || std::time::Instant::now() >= end {
                return r;
            }
            std::thread::sleep(std::time::Duration::from_millis(10));
        }
    }
    use std::cell::RefCell;
    use std::collections::HashMap;

    const ARN: &str = "arn:aws:kms:us-east-1:123456789012:key/0f0f0f0f-0000-4000-8000-000000000000";
    const FILE_SETTINGS: &str = "OZBOX_SECRET_SCOPE=main\nOZBOX_KMS_KEY_ID=\nOZBOX_KMS_REGION=\nOZBOX_SECRET_ALLOW_FILE_KEK=1\n";

    struct Tg(HashMap<&'static str, String>, bool);
    impl Tags for Tg {
        fn available(&self) -> bool {
            self.1
        }
        fn get(&self, k: &str) -> Option<String> {
            self.0.get(k).cloned()
        }
    }
    /// The move is asked for (the pending tag).
    fn tagged(arn: &str) -> Tg {
        Tg(HashMap::from([(TAG_ADOPT, arn.to_string())]), true)
    }
    /// The laptop has committed (the real label, the pending one gone).
    fn committed(arn: &str) -> Tg {
        Tg(HashMap::from([(TAG_KEY, arn.to_string())]), true)
    }
    fn untagged() -> Tg {
        Tg(HashMap::new(), true)
    }

    /// A machine that records what was done to it and answers as scripted. The re-wrap really changes the file it is given
    /// the way the real one does (the store's `kek` label), so the steps after it see what they would see.
    struct Fake<'a> {
        p: &'a Paths,
        log: RefCell<Vec<String>>,
        /// what the service says after it is started with KMS settings
        after_start: RefCell<Option<State>>,
        state_now: RefCell<Option<State>>,
        rotate: RefCell<Result<usize, String>>,
        probe: RefCell<Result<(), String>>,
        start_fails: bool,
        /// the `/work` copy follows (the service's saver copies the store) after this many pauses, with this label
        copy_follows: Option<(u32, &'static str)>,
        pauses: RefCell<u32>,
        /// a secret is written to the live store while the copy is being re-wrapped
        writes_during_rewrap: bool,
        /// a secret is written at the moment the service is stopped
        writes_at_stop: bool,
        guard: std::cell::Cell<bool>,
    }
    impl Machine for Fake<'_> {
        fn unit(&self, verb: &str, unit: &str) -> Result<(), String> {
            self.log.borrow_mut().push(format!("{verb} {unit}"));
            if verb == "start" && unit == SECRETS_UNIT {
                if self.start_fails {
                    return Err("start failed".into());
                }
                let settings = crate::secrets_file::env_file(&self.p.settings);
                let kms = settings
                    .get("OZBOX_KMS_KEY_ID")
                    .is_some_and(|v| !v.is_empty());
                *self.state_now.borrow_mut() = if kms {
                    self.after_start.borrow().clone()
                } else {
                    Some(State::ready("", "file", Some(false)))
                };
            }
            if verb == "stop" && unit == SECRETS_UNIT {
                if self.writes_at_stop {
                    std::fs::write(&self.p.store, "{\"kek\":\"file\",\"new\":2}").unwrap();
                }
                *self.state_now.borrow_mut() = None;
            }
            Ok(())
        }
        fn active(&self, unit: &str) -> bool {
            // the secrets service runs while it has a state; no other unit does
            unit == SECRETS_UNIT && self.state_now.borrow().is_some()
        }
        fn metadata_guard_loaded(&self) -> bool {
            self.guard.get()
        }
        fn probe_kms(&self, _: &str, _: &str, _: &str) -> Result<(), String> {
            self.log.borrow_mut().push("probe".into());
            self.probe.borrow().clone()
        }
        fn copy_store(&self, from: &Path, to: &Path) -> Result<(), String> {
            self.log.borrow_mut().push("copy".into());
            std::fs::copy(from, to)
                .map(|_| ())
                .map_err(|e| e.to_string())
        }
        fn rotate(
            &self,
            file: &Path,
            from: &str,
            to: &str,
            scope: &str,
            key_id: &str,
            region: &str,
        ) -> Result<usize, String> {
            self.log.borrow_mut().push(format!(
                "rotate {} {from}->{to} {scope} {key_id} {region}",
                file.file_name().unwrap().to_string_lossy()
            ));
            let r = self.rotate.borrow().clone();
            if r.is_ok() {
                std::fs::write(file, format!("{{\"kek\":\"{to}\"}}")).unwrap();
                if self.writes_during_rewrap {
                    std::fs::write(&self.p.store, "{\"kek\":\"file\",\"new\":1}").unwrap();
                }
            }
            r
        }
        fn state(&self) -> Option<State> {
            self.state_now.borrow().clone()
        }
        fn pause(&self, _: u64) {
            let mut n = self.pauses.borrow_mut();
            *n += 1;
            if let Some((k, label)) = self.copy_follows {
                if *n >= k {
                    std::fs::write(
                        self.p.persist.join("secrets.json"),
                        format!("{{\"kek\":\"{label}\"}}"),
                    )
                    .unwrap();
                }
            }
        }
    }

    struct Rig {
        _d: tempfile::TempDir,
        p: Paths,
    }
    fn rig(settings: &str) -> Rig {
        let d = tempfile::tempdir().unwrap();
        let r = d.path();
        for dir in ["lib", "work", "etc"] {
            std::fs::create_dir(r.join(dir)).unwrap();
        }
        let p = Paths {
            store: r.join("lib/secrets.json"),
            persist: r.join("work"),
            state: r.join("lib/state"),
            settings: r.join("etc/secrets.env"),
            pin: r.join("etc/approval-keys"),
            challenge: r.join("lib/challenge"),
            adopt_lock: r.join("run/adopt/lock"),
        };
        std::fs::write(&p.store, "{\"kek\":\"file\"}").unwrap();
        std::fs::write(p.persist.join("secrets.json"), "{\"kek\":\"file\"}").unwrap();
        std::fs::write(key_file(&p), "key-bytes").unwrap();
        std::fs::write(&p.settings, settings).unwrap();
        Rig { _d: d, p }
    }
    fn machine(p: &Paths) -> Fake<'_> {
        Fake {
            p,
            log: RefCell::new(Vec::new()),
            after_start: RefCell::new(Some(State::ready("", "kms", None))),
            state_now: RefCell::new(Some(State::ready("", "file", Some(false)))),
            rotate: RefCell::new(Ok(3)),
            probe: RefCell::new(Ok(())),
            start_fails: false,
            copy_follows: Some((1, "kms")),
            pauses: RefCell::new(0),
            writes_during_rewrap: false,
            writes_at_stop: false,
            guard: std::cell::Cell::new(true),
        }
    }
    fn did(m: &Fake<'_>) -> Vec<String> {
        m.log.borrow().clone()
    }
    fn at(log: &[String], needle: &str) -> usize {
        log.iter()
            .position(|l| l.starts_with(needle))
            .unwrap_or_else(|| panic!("{needle} not in {log:?}"))
    }
    /// A box that has moved and waits for the laptop's word.
    fn moved(r: &Rig) {
        let m = machine(&r.p);
        assert_eq!(
            adopt(&r.p, &m, &tagged(ARN)).unwrap(),
            Outcome::MovedAwaitingCommit(3)
        );
    }

    #[test]
    fn a_file_keyed_store_is_rewrapped_on_a_side_copy_while_the_service_runs_and_nothing_is_destroyed_until_the_commit(
    ) {
        let r = rig(FILE_SETTINGS);
        let m = machine(&r.p);
        assert_eq!(
            adopt(&r.p, &m, &tagged(ARN)).unwrap(),
            Outcome::MovedAwaitingCommit(3)
        );
        let log = did(&m);
        // M3: the slow re-wrap is on the side copy and happens BEFORE the service is stopped; the stop is short
        assert!(at(&log, "probe") < at(&log, "copy"), "{log:?}");
        assert!(
            at(&log, "copy") < at(&log, "rotate secrets-kms.json file->kms"),
            "{log:?}"
        );
        assert!(
            at(&log, "rotate") < at(&log, "stop ozbox-secrets"),
            "{log:?}"
        );
        assert!(
            at(&log, "stop ozbox-secrets") < at(&log, "start ozbox-secrets"),
            "{log:?}"
        );
        assert!(
            at(&log, "start ozbox-secrets") < at(&log, "try-restart ozbox-cloudflared"),
            "{log:?}"
        );
        assert!(log
            .iter()
            .any(|l| l == &format!("rotate secrets-kms.json file->kms main {ARN} us-east-1")));
        // the settings name the key and no longer allow a file key; the rest is kept
        let s = std::fs::read_to_string(&r.p.settings).unwrap();
        assert!(s.contains(&format!("OZBOX_KMS_KEY_ID={ARN}\n")), "{s}");
        assert!(
            s.contains("OZBOX_KMS_REGION=us-east-1\n") && s.contains("OZBOX_SECRET_SCOPE=main\n"),
            "{s}"
        );
        assert!(
            !s.contains("ALLOW_FILE_KEK") && s.matches("OZBOX_KMS_KEY_ID").count() == 1,
            "{s}"
        );
        // H1: the key file and the copy beside the store are KEPT: the laptop has not committed
        assert!(key_file(&r.p).exists() && backup_file(&r.p).exists());
        assert!(!side_file(&r.p).exists());
        assert!(std::fs::read_to_string(&r.p.store).unwrap().contains("kms"));
        // a second run, the tag still pending: it waits, and destroys nothing
        let again = machine(&r.p);
        *again.state_now.borrow_mut() = Some(State::ready("", "kms", None));
        assert_eq!(
            adopt(&r.p, &again, &tagged(ARN)).unwrap(),
            Outcome::AwaitingCommit
        );
        assert!(did(&again).is_empty());
        assert!(key_file(&r.p).exists() && backup_file(&r.p).exists());
        // the commit (the real label, the pending one gone): only now do they go
        let last = machine(&r.p);
        *last.state_now.borrow_mut() = Some(State::ready("", "kms", None));
        assert_eq!(
            adopt(&r.p, &last, &committed(ARN)).unwrap(),
            Outcome::Finished
        );
        assert!(!key_file(&r.p).exists() && !backup_file(&r.p).exists());
        assert!(
            did(&last).is_empty(),
            "finishing touches no service: {:?}",
            did(&last)
        );
        // and a box that is finished and committed has nothing left
        assert_eq!(
            adopt(&r.p, &last, &committed(ARN)).unwrap(),
            Outcome::AlreadyDone
        );
    }

    #[test]
    fn no_tag_no_metadata_or_a_tag_that_is_not_a_kms_arn_changes_nothing() {
        let r = rig(FILE_SETTINGS);
        let m = machine(&r.p);
        let before = std::fs::read_to_string(&r.p.settings).unwrap();
        assert_eq!(adopt(&r.p, &m, &untagged()).unwrap(), Outcome::NotRequested);
        assert_eq!(
            adopt(&r.p, &m, &Tg(HashMap::new(), false)).unwrap(),
            Outcome::NotRequested
        );
        for bad in [
            "not-an-arn",
            "arn:aws:s3:::bucket",
            "arn:aws:kms:us-east-1:123:key/abc",
            "arn:aws:kms:us east:123456789012:key/abc",
            "arn:aws:kms:us-east-1:123456789012:alias/x",
            "arn:aws:kms:us-east-1:123456789012:key/abc\nOZBOX_X=1",
        ] {
            assert!(adopt(&r.p, &m, &tagged(bad)).is_err(), "{bad}");
        }
        assert!(did(&m).is_empty(), "{:?}", did(&m));
        assert_eq!(std::fs::read_to_string(&r.p.settings).unwrap(), before);
        assert!(key_file(&r.p).exists());
    }

    #[test]
    fn only_a_ready_file_keyed_store_is_moved() {
        // a TPM, an already-KMS store, a service that is down or says nothing, a key file that is not there
        for (state, why) in [
            (Some(State::ready("", "tpm2", None)), "tpm2"),
            (Some(State::ready("", "kms", None)), "kms"),
            (
                Some(State::not_ready(
                    "the key is gone",
                    crate::secrets_state::NO_ESCROW_CODE,
                    Some("file"),
                    Some(false),
                )),
                "not ready",
            ),
            (None, "no state"),
        ] {
            let r = rig(FILE_SETTINGS);
            // a service that is down is started first (R7); one that will not start says nothing, so nothing is moved
            let m = Fake {
                start_fails: why == "no state",
                ..machine(&r.p)
            };
            *m.state_now.borrow_mut() = state;
            let e = adopt(&r.p, &m, &tagged(ARN)).unwrap_err();
            assert!(e.contains("nothing was changed"), "{why}: {e}");
            let moved_something = did(&m).iter().any(|l| !l.starts_with("start "));
            assert!(!moved_something, "{why}: {:?}", did(&m));
            assert!(key_file(&r.p).exists());
        }
        let r = rig(FILE_SETTINGS);
        std::fs::remove_file(key_file(&r.p)).unwrap();
        assert!(adopt(&r.p, &machine(&r.p), &tagged(ARN)).is_err());
        // settings that do not choose a file key are not guessed at
        let r = rig("OZBOX_SECRET_SCOPE=main\nOZBOX_KMS_KEY_ID=\n");
        let m = machine(&r.p);
        assert!(adopt(&r.p, &m, &tagged(ARN))
            .unwrap_err()
            .contains("do not choose a file-kept key"));
        assert!(did(&m).is_empty());
    }

    #[test]
    fn a_store_on_a_different_kms_key_is_never_switched_silently() {
        let other = "arn:aws:kms:us-east-1:123456789012:key/11111111-1111-4111-8111-111111111111";
        let r = rig(&format!(
            "OZBOX_SECRET_SCOPE=main\nOZBOX_KMS_KEY_ID={other}\n"
        ));
        // a store that really is wrapped by that other key is never switched
        std::fs::write(&r.p.store, "{\"kek\":\"kms\"}").unwrap();
        let m = machine(&r.p);
        let e = adopt(&r.p, &m, &tagged(ARN)).unwrap_err();
        assert!(e.contains("different KMS key"), "{e}");
        assert!(did(&m).is_empty());
    }

    /// A grant that has not reached the machine (the likeliest first answer) costs the service nothing: the probe fails before
    /// anything is copied or stopped, however many times the next runs try.
    #[test]
    fn a_kms_that_cannot_be_used_yet_is_found_before_anything_is_touched() {
        let r = rig(FILE_SETTINGS);
        let m = machine(&r.p);
        *m.probe.borrow_mut() = Err("the check failed (AccessDeniedException)".into());
        for _ in 0..3 {
            let e = adopt(&r.p, &m, &tagged(ARN)).unwrap_err();
            assert!(
                e.contains("nothing was stopped") && e.contains("AccessDenied"),
                "{e}"
            );
        }
        assert_eq!(did(&m), ["probe", "probe", "probe"]);
        assert_eq!(
            std::fs::read_to_string(&r.p.settings).unwrap(),
            FILE_SETTINGS
        );
        assert!(key_file(&r.p).exists() && !backup_file(&r.p).exists());
    }

    /// The grant has not reached the instance yet, or the key's context does not match: the re-wrap of the side copy fails with
    /// the store untouched and the service NEVER stopped; the next run tries again.
    #[test]
    fn a_failed_rewrap_never_stops_the_service_and_is_tried_again() {
        let r = rig(FILE_SETTINGS);
        let m = machine(&r.p);
        *m.rotate.borrow_mut() = Err("the re-wrap failed (AccessDeniedException)".into());
        let e = adopt(&r.p, &m, &tagged(ARN)).unwrap_err();
        assert!(
            e.contains("AccessDenied")
                && e.contains("was not stopped")
                && e.contains("tried again"),
            "{e}"
        );
        assert_eq!(
            std::fs::read_to_string(&r.p.settings).unwrap(),
            FILE_SETTINGS
        );
        assert_eq!(
            std::fs::read_to_string(&r.p.store).unwrap(),
            "{\"kek\":\"file\"}"
        );
        assert!(
            key_file(&r.p).exists() && !side_file(&r.p).exists() && !backup_file(&r.p).exists()
        );
        assert!(
            !did(&m).iter().any(|l| l.starts_with("stop")),
            "{:?}",
            did(&m)
        );
        // and then it works
        *m.rotate.borrow_mut() = Ok(2);
        assert_eq!(
            adopt(&r.p, &m, &tagged(ARN)).unwrap(),
            Outcome::MovedAwaitingCommit(2)
        );
    }

    /// L4: a secret written while the copy was being re-wrapped would be lost by the swap. The swap is not made.
    #[test]
    fn a_secret_written_during_the_rewrap_is_never_lost() {
        let r = rig(FILE_SETTINGS);
        let mut m = machine(&r.p);
        m.writes_during_rewrap = true;
        let e = adopt(&r.p, &m, &tagged(ARN)).unwrap_err();
        assert!(
            e.contains("changed while") && e.contains("nothing was lost"),
            "{e}"
        );
        assert_eq!(
            std::fs::read_to_string(&r.p.store).unwrap(),
            "{\"kek\":\"file\",\"new\":1}",
            "the live store, with the new secret, is what stays"
        );
        assert_eq!(
            std::fs::read_to_string(&r.p.settings).unwrap(),
            FILE_SETTINGS
        );
        assert!(!side_file(&r.p).exists() && !backup_file(&r.p).exists());
        // N6: seen BEFORE the stop, so the abort costs the service nothing
        let log = did(&m);
        assert!(!log.iter().any(|l| l.starts_with("stop")), "{log:?}");
    }

    /// A secret written at the very moment of the stop is caught by the check after it, and the service is started again.
    #[test]
    fn a_secret_written_at_the_stop_is_never_lost() {
        let r = rig(FILE_SETTINGS);
        let mut m = machine(&r.p);
        m.writes_at_stop = true;
        let e = adopt(&r.p, &m, &tagged(ARN)).unwrap_err();
        assert!(
            e.contains("changed while")
                && e.contains("nothing was lost")
                && e.contains("was started again"),
            "{e}"
        );
        assert_eq!(
            std::fs::read_to_string(&r.p.store).unwrap(),
            "{\"kek\":\"file\",\"new\":2}"
        );
        let log = did(&m);
        assert!(
            at(&log, "stop ozbox-secrets") < at(&log, "start ozbox-secrets"),
            "{log:?}"
        );
        assert_eq!(log.last().unwrap(), "start ozbox-secrets.service");
        assert_eq!(read_aborts(&r.p).0, 1);
    }

    /// N6: a store that keeps changing is not retried every run. The wait grows (15, 30, 60, 120 minutes) and is capped, a
    /// move that waits touches nothing, adopt-status says how long, and a move that works clears the count.
    #[test]
    fn a_busy_store_backs_off_with_a_growing_wait_and_says_so() {
        assert_eq!(
            [0, 1, 2, 3, 4, 5, 6, 30].map(backoff_secs),
            [
                0,
                0,
                15 * 60,
                30 * 60,
                60 * 60,
                120 * 60,
                240 * 60,
                240 * 60
            ]
        );
        let r = rig(FILE_SETTINGS);
        for _ in 0..2 {
            let mut m = machine(&r.p);
            m.writes_during_rewrap = true;
            std::fs::write(&r.p.store, "{\"kek\":\"file\"}").unwrap();
            assert!(adopt(&r.p, &m, &tagged(ARN))
                .unwrap_err()
                .contains("changed while"));
        }
        assert_eq!(read_aborts(&r.p).0, 2);
        // the third run waits: nothing is copied, re-wrapped or stopped
        std::fs::write(&r.p.store, "{\"kek\":\"file\"}").unwrap();
        let m = machine(&r.p);
        let e = adopt(&r.p, &m, &tagged(ARN)).unwrap_err();
        assert!(
            e.contains("2 times in a row") && e.contains("waits before it tries again"),
            "{e}"
        );
        assert!(
            !did(&m)
                .iter()
                .any(|l| l.starts_with("copy") || l.starts_with("rotate") || l.starts_with("stop")),
            "{:?}",
            did(&m)
        );
        let f = facts(&r.p, &m, &tagged(ARN));
        assert!((1..=15).contains(&f.move_backoff_mins), "{f:?}");
        // after the wait it tries again, and a success forgets the count
        std::fs::write(aborts_file(&r.p), format!("2 {}\n", now_secs() - 16 * 60)).unwrap();
        assert_eq!(facts(&r.p, &m, &tagged(ARN)).move_backoff_mins, 0);
        assert_eq!(
            adopt(&r.p, &m, &tagged(ARN)).unwrap(),
            Outcome::MovedAwaitingCommit(3)
        );
        assert!(!aborts_file(&r.p).exists());
    }

    /// N5: a secrets service left stopped (a run cut short between the stop and the start) is started again on the paths that
    /// wait for the laptop, and by a cancel; its stale "ready" in the state file is not believed.
    #[test]
    fn a_stopped_service_is_started_on_the_resume_paths() {
        let r = rig(FILE_SETTINGS);
        moved(&r);
        // awaiting the laptop's commit, the service stopped
        let m = machine(&r.p);
        *m.state_now.borrow_mut() = None;
        assert_eq!(
            adopt(&r.p, &m, &tagged(ARN)).unwrap(),
            Outcome::AwaitingCommit
        );
        assert!(
            did(&m).iter().any(|l| l == "start ozbox-secrets.service"),
            "{:?}",
            did(&m)
        );
        // committed, the service stopped: finishing starts it first
        let m = machine(&r.p);
        *m.state_now.borrow_mut() = None;
        assert!(adopt(&r.p, &m, &committed(ARN)).is_ok());
        assert!(
            did(&m).iter().any(|l| l == "start ozbox-secrets.service"),
            "{:?}",
            did(&m)
        );
        // a running service is left alone
        let m = machine(&r.p);
        *m.state_now.borrow_mut() = Some(State::ready("", "kms", None));
        assert!(adopt(&r.p, &m, &committed(ARN)).is_ok());
        assert!(
            !did(&m).iter().any(|l| l.starts_with("start")),
            "{:?}",
            did(&m)
        );
    }

    /// R2: a box that moved and then lost both tags and its grant (a laptop that lost a race) is REPORTED, never put back by
    /// itself: no run, however often and however it is started, restores the copy, because that loses secrets and only a person
    /// (through the laptop's confirmed `--cancel`) may choose it.
    #[test]
    fn a_stranded_box_is_reported_and_never_put_back_by_itself() {
        let r = rig(FILE_SETTINGS);
        // the state a lost race leaves: moved, settings name KMS, key file and the copy there, no tag
        std::fs::write(&r.p.store, "{\"kek\":\"kms\"}").unwrap();
        std::fs::write(r.p.persist.join("secrets.json"), "{\"kek\":\"kms\"}").unwrap();
        std::fs::write(
            &r.p.settings,
            settings_with_kms(FILE_SETTINGS, ARN, "us-east-1"),
        )
        .unwrap();
        std::fs::write(backup_file(&r.p), "{\"kek\":\"file\",\"old\":1}").unwrap();
        assert!(
            !pending(&r.p, &untagged()),
            "nothing is asked for, so the timer starts no unit"
        );
        let denied = crate::secrets_enc::KEK_DENIED;
        for probe in [
            Err(denied.to_string()),
            Err("the check failed (Connect timeout)".to_string()),
            Ok(()),
        ] {
            let m = machine(&r.p);
            *m.probe.borrow_mut() = probe;
            // many runs, spread over any time: the store, the settings and the copy never move
            for _ in 0..4 {
                assert_eq!(adopt(&r.p, &m, &untagged()).unwrap(), Outcome::NotRequested);
            }
            assert!(std::fs::read_to_string(&r.p.store).unwrap().contains("kms"));
            assert!(backup_file(&r.p).exists() && !marker_file(&r.p).exists());
            assert!(
                !did(&m).iter().any(|l| l.starts_with("stop")
                    || l.starts_with("start")
                    || l.starts_with("rotate")),
                "{:?}",
                did(&m)
            );
            assert!(!r.p.adopt_lock.with_file_name("stranded-seen").exists());
        }
        // what the box REPORTS: only the key service's own refusal is "denied"; a timeout and a working KMS are not
        for (probe, want) in [
            (Err(denied.to_string()), Probe::Denied),
            (
                Err("the check failed (Connect timeout)".to_string()),
                Probe::Failed,
            ),
            (
                Err("the check could not be started (no such file)".to_string()),
                Probe::Failed,
            ),
            (Ok(()), Probe::Ok),
        ] {
            let m = machine(&r.p);
            *m.probe.borrow_mut() = probe;
            let f = facts(&r.p, &m, &untagged());
            assert_eq!(f.kms_probe, want, "{f:?}");
            assert_eq!(f.copy_restore_justified(), want == Probe::Denied, "{f:?}");
        }
        // a box that is not in that state is not probed at all
        std::fs::remove_file(backup_file(&r.p)).unwrap();
        let m = machine(&r.p);
        assert_eq!(facts(&r.p, &m, &untagged()).kms_probe, Probe::Na);
        assert!(!did(&m).iter().any(|l| l == "probe"));
    }

    /// R2: a tag that could not be read (a timeout, a throttle, a server error) is not a tag that is not there.
    #[test]
    fn a_tag_read_that_fails_is_never_read_as_no_tag() {
        struct Flaky;
        impl Tags for Flaky {
            fn available(&self) -> bool {
                true
            }
            fn get(&self, _: &str) -> Option<String> {
                None
            }
            fn read(&self, _: &str) -> TagRead {
                TagRead::Unreadable
            }
        }
        let r = rig(FILE_SETTINGS);
        moved(&r);
        let before = std::fs::read_to_string(&r.p.store).unwrap();
        let m = machine(&r.p);
        let e = adopt(&r.p, &m, &Flaky).unwrap_err();
        assert!(
            e.contains("could not be read") && e.contains("nothing was changed"),
            "{e}"
        );
        assert_eq!(std::fs::read_to_string(&r.p.store).unwrap(), before);
        assert!(did(&m).is_empty(), "{:?}", did(&m));
        // while a clean 'no such tag' (the default reader) is an ordinary run with neither
        assert_eq!(
            adopt(&r.p, &machine(&r.p), &untagged()).unwrap(),
            Outcome::NotRequested
        );
    }

    /// N3: a run cut short in the file direction (settings name KMS, the store is still file-wrapped, the key file is there)
    /// is put right even with no tag on the box.
    #[test]
    fn the_file_direction_is_settled_before_the_tags_are_looked_at() {
        let r = rig(FILE_SETTINGS);
        std::fs::write(
            &r.p.settings,
            settings_with_kms(FILE_SETTINGS, ARN, "us-east-1"),
        )
        .unwrap();
        let m = machine(&r.p);
        let out = adopt(&r.p, &m, &untagged()).unwrap();
        assert!(matches!(out, Outcome::Reconciled(_)), "{out:?}");
        assert!(std::fs::read_to_string(&r.p.settings)
            .unwrap()
            .contains("ALLOW_FILE_KEK"));
    }

    /// S8: the same, with the tags NOT AVAILABLE or UNREADABLE: the file direction is settled before they are asked for.
    #[test]
    fn the_file_direction_is_settled_even_when_the_tags_cannot_be_read() {
        struct Flaky;
        impl Tags for Flaky {
            fn available(&self) -> bool {
                true
            }
            fn get(&self, _: &str) -> Option<String> {
                None
            }
            fn read(&self, _: &str) -> TagRead {
                TagRead::Unreadable
            }
        }
        let tags: [&dyn Tags; 2] = [&Tg(HashMap::new(), false), &Flaky];
        for tags in tags {
            let r = rig(FILE_SETTINGS);
            std::fs::write(
                &r.p.settings,
                settings_with_kms(FILE_SETTINGS, ARN, "us-east-1"),
            )
            .unwrap();
            let m = machine(&r.p);
            let out = adopt(&r.p, &m, tags).unwrap();
            assert!(matches!(out, Outcome::Reconciled(_)), "{out:?}");
        }
    }

    /// S8: the unit that runs `adopt` starts for a half-made move in the file direction even with no tags to read.
    #[test]
    fn a_half_made_move_starts_the_unit_even_when_the_tags_cannot_be_read() {
        let r = rig(FILE_SETTINGS);
        assert!(!pending(&r.p, &Tg(HashMap::new(), false)));
        std::fs::write(
            &r.p.settings,
            settings_with_kms(FILE_SETTINGS, ARN, "us-east-1"),
        )
        .unwrap();
        assert!(pending(&r.p, &Tg(HashMap::new(), false)));
        assert!(pending(&r.p, &untagged()));
    }

    /// N3: a cancel falls back to the copy made before the move only when it is asked to by name and KMS no longer answers.
    #[test]
    fn a_cancel_can_fall_back_to_the_copy_when_kms_no_longer_answers() {
        let r = rig(FILE_SETTINGS);
        moved(&r);
        std::fs::write(backup_file(&r.p), "{\"kek\":\"file\",\"old\":1}").unwrap();
        // the plain cancel says the copy exists and what using it costs
        let m = machine(&r.p);
        *m.probe.borrow_mut() = Err(crate::secrets_enc::KEK_DENIED.into());
        let e = unbusy(|| cancel_locked(&r.p, &m, &tagged(ARN))).unwrap_err();
        assert!(
            e.contains("copy of the store made before the move")
                && e.contains("loses the secrets saved since"),
            "{e}"
        );
        // KMS answering: the lossless cancel is the right one, and this refuses
        let m = machine(&r.p);
        assert!(unbusy(|| cancel_from_copy_locked(&r.p, &m, &tagged(ARN)))
            .unwrap_err()
            .contains("still answers"));
        assert!(std::fs::read_to_string(&r.p.store).unwrap().contains("kms"));
        // KMS gone: the copy goes back
        let m = Fake {
            copy_follows: Some((1, "file")),
            ..machine(&r.p)
        };
        *m.probe.borrow_mut() = Err(crate::secrets_enc::KEK_DENIED.into());
        assert_eq!(
            unbusy(|| cancel_from_copy_locked(&r.p, &m, &tagged(ARN))).unwrap(),
            Outcome::Cancelled
        );
        assert_eq!(
            std::fs::read_to_string(&r.p.store).unwrap(),
            "{\"kek\":\"file\",\"old\":1}"
        );
        assert!(!backup_file(&r.p).exists() && marker_file(&r.p).exists());
        let s = std::fs::read_to_string(&r.p.settings).unwrap();
        assert!(
            s.contains("OZBOX_SECRET_ALLOW_FILE_KEK=1") && !s.contains("OZBOX_KMS_KEY_ID"),
            "{s}"
        );
        // a copy that is not file-wrapped is never used
        let r = rig(FILE_SETTINGS);
        moved(&r);
        std::fs::write(backup_file(&r.p), "{\"kek\":\"kms\"}").unwrap();
        let m = machine(&r.p);
        *m.probe.borrow_mut() = Err(crate::secrets_enc::KEK_DENIED.into());
        assert!(unbusy(|| cancel_from_copy_locked(&r.p, &m, &tagged(ARN))).is_err());
        assert!(std::fs::read_to_string(&r.p.store).unwrap().contains("kms"));
        assert!(
            !marker_file(&r.p).exists(),
            "a refusal leaves no cancel mark"
        );
    }

    /// R2 and R8: the copy goes back only when the key service ITSELF refuses (not on a timeout, a spawn failure or any other
    /// error), and every refusal comes before the cancel mark is written, so "nothing was changed" is true.
    #[test]
    fn the_copy_is_put_back_only_on_the_key_services_own_refusal_and_a_refusal_writes_nothing() {
        for (probe, expect) in [
            (Ok(()), "still answers"),
            (
                Err("the check failed (Connect timeout on endpoint URL)".to_string()),
                "could not be checked cleanly",
            ),
            (
                Err("the check could not be started (no such file)".to_string()),
                "could not be checked cleanly",
            ),
            (Err(String::new()), "could not be checked cleanly"),
        ] {
            let r = rig(FILE_SETTINGS);
            moved(&r);
            std::fs::write(backup_file(&r.p), "{\"kek\":\"file\",\"old\":1}").unwrap();
            let m = machine(&r.p);
            *m.probe.borrow_mut() = probe;
            let e = unbusy(|| cancel_from_copy_locked(&r.p, &m, &tagged(ARN))).unwrap_err();
            assert!(
                e.contains(expect) && e.contains("Nothing was changed"),
                "{e}"
            );
            assert!(!marker_file(&r.p).exists(), "{e}");
            assert!(std::fs::read_to_string(&r.p.store).unwrap().contains("kms"));
            assert!(backup_file(&r.p).exists());
            assert!(
                !did(&m).iter().any(|l| l.starts_with("stop")),
                "{:?}",
                did(&m)
            );
        }
    }

    /// L5 and N2: the facts carry whether the metadata guard is loaded, and what the service says about a file key's escrow.
    #[test]
    fn the_facts_carry_the_metadata_guard_and_the_escrow() {
        let r = rig(FILE_SETTINGS);
        let m = machine(&r.p);
        m.guard.set(false);
        *m.state_now.borrow_mut() = Some(State::ready("", "file", Some(true)));
        let f = facts(&r.p, &m, &tagged(ARN));
        assert!(
            !f.metadata_guard && f.service_escrow == Some(true) && !f.service_no_escrow,
            "{f:?}"
        );
        *m.state_now.borrow_mut() = Some(State::not_ready(
            "no key",
            crate::secrets_state::NO_ESCROW_CODE,
            Some("file"),
            Some(false),
        ));
        assert!(facts(&r.p, &m, &tagged(ARN)).service_no_escrow);
    }

    /// The service does not come up on KMS: the copy of the store and the old settings go back and the service starts on the
    /// file key it had. The key file was never touched.
    #[test]
    fn a_service_that_does_not_come_up_on_kms_is_put_back_on_the_file_key() {
        for start_fails in [false, true] {
            let r = rig(FILE_SETTINGS);
            let mut m = machine(&r.p);
            m.start_fails = start_fails;
            *m.after_start.borrow_mut() = Some(State::not_ready(
                "the key service did not answer",
                "transient",
                Some("kms"),
                None,
            ));
            let e = adopt(&r.p, &m, &tagged(ARN)).unwrap_err();
            if start_fails {
                assert!(
                    e.contains("did not start") && e.contains("NOT started"),
                    "{e}"
                );
            } else {
                assert!(e.contains("put back"), "{e}");
            }
            assert_eq!(
                std::fs::read_to_string(&r.p.settings).unwrap(),
                FILE_SETTINGS
            );
            assert_eq!(
                std::fs::read_to_string(&r.p.store).unwrap(),
                "{\"kek\":\"file\"}"
            );
            assert!(
                key_file(&r.p).exists(),
                "the key file is never touched before the commit"
            );
        }
    }

    /// M3: the wait for the service on the new key grows with the store (every secret it unwraps at start-up is a KMS call), so
    /// a big store is not rolled back for being slow.
    #[test]
    fn the_wait_for_the_service_on_kms_scales_with_the_store() {
        for (secrets, want) in [(0usize, 30u32), (10, 50)] {
            let r = rig(FILE_SETTINGS);
            let m = machine(&r.p);
            *m.rotate.borrow_mut() = Ok(secrets);
            *m.after_start.borrow_mut() =
                Some(State::not_ready("slow", "transient", Some("kms"), None));
            m.copy_follows.as_ref();
            let _ = adopt(&r.p, &m, &tagged(ARN)).unwrap_err();
            assert_eq!(*m.pauses.borrow(), want, "{secrets} secrets");
        }
    }

    /// H1: a cancel records a mark under the lock; past it NO move starts or finishes, whatever the tags still say, and a box
    /// that had already moved is taken back under its file key from the store as it is now (so nothing written since is lost).
    #[test]
    fn a_cancel_leaves_a_mark_no_move_passes_and_takes_a_moved_store_back() {
        let r = rig(FILE_SETTINGS);
        moved(&r);
        let m = machine(&r.p);
        *m.state_now.borrow_mut() = Some(State::ready("", "kms", None));
        m.copy_follows.as_ref();
        let m = Fake {
            copy_follows: Some((1, "file")),
            ..m
        };
        assert_eq!(
            unbusy(|| cancel_locked(&r.p, &m, &tagged(ARN))).unwrap(),
            Outcome::Cancelled
        );
        let log = did(&m);
        assert!(
            log.iter()
                .any(|l| l == &format!("rotate secrets-kms.json kms->file main {ARN} us-east-1")),
            "{log:?}"
        );
        assert!(
            at(&log, "rotate") < at(&log, "stop ozbox-secrets"),
            "{log:?}"
        );
        // back on the file key: the settings, the store, the copy on /work, and the key file never left
        let s = std::fs::read_to_string(&r.p.settings).unwrap();
        assert!(
            s.contains("OZBOX_SECRET_ALLOW_FILE_KEK=1") && !s.contains("OZBOX_KMS_KEY_ID"),
            "{s}"
        );
        assert!(std::fs::read_to_string(&r.p.store)
            .unwrap()
            .contains("file"));
        assert!(
            key_file(&r.p).exists() && !backup_file(&r.p).exists() && marker_file(&r.p).exists()
        );
        let facts = facts(&r.p, &m, &tagged(ARN));
        assert!(facts.cancel_confirmed(), "{facts:?}");
        // the pending tag is still on the box (the laptop has not applied it yet), and a run does NOTHING: not even a probe
        let later = machine(&r.p);
        assert_eq!(
            adopt(&r.p, &later, &tagged(ARN)).unwrap(),
            Outcome::Cancelled
        );
        assert!(did(&later).is_empty(), "{:?}", did(&later));
        // nor does a committed label start one
        assert_eq!(
            adopt(&r.p, &later, &committed(ARN)).unwrap(),
            Outcome::Cancelled
        );
        assert!(did(&later).is_empty());
        assert!(std::fs::read_to_string(&r.p.store)
            .unwrap()
            .contains("file"));
        // arming takes the mark away and a move can start again
        assert_eq!(unbusy(|| arm_locked(&r.p)).unwrap(), Outcome::NotRequested);
        assert!(!marker_file(&r.p).exists());
        let again = machine(&r.p);
        assert_eq!(
            adopt(&r.p, &again, &tagged(ARN)).unwrap(),
            Outcome::MovedAwaitingCommit(3)
        );
    }

    /// A cancel on a box that never moved is only the mark; the grant can then go.
    #[test]
    fn a_cancel_on_a_box_that_never_moved_only_records_the_mark() {
        let r = rig(FILE_SETTINGS);
        let m = machine(&r.p);
        assert_eq!(
            unbusy(|| cancel_locked(&r.p, &m, &tagged(ARN))).unwrap(),
            Outcome::Cancelled
        );
        assert!(did(&m).is_empty(), "{:?}", did(&m));
        assert!(marker_file(&r.p).exists() && key_file(&r.p).exists());
        assert!(facts(&r.p, &m, &tagged(ARN)).cancel_confirmed());
        // a cancel whose store cannot be taken back (its key file gone) refuses, and the grant must stay
        let r = rig(FILE_SETTINGS);
        moved(&r);
        std::fs::remove_file(key_file(&r.p)).unwrap();
        let m = machine(&r.p);
        *m.state_now.borrow_mut() = Some(State::ready("", "kms", None));
        assert!(unbusy(|| cancel_locked(&r.p, &m, &tagged(ARN)))
            .unwrap_err()
            .contains("grant must stay"));
        // and a KMS that cannot be used leaves the box as it was
        let r = rig(FILE_SETTINGS);
        moved(&r);
        let m = machine(&r.p);
        *m.probe.borrow_mut() = Err("the check failed (AccessDeniedException)".into());
        assert!(unbusy(|| cancel_locked(&r.p, &m, &tagged(ARN)))
            .unwrap_err()
            .contains("grant must stay"));
        assert!(std::fs::read_to_string(&r.p.store).unwrap().contains("kms"));
    }

    /// H1: a move and a cancel exclude each other: whoever holds the lock, the other says busy and does nothing.
    #[test]
    fn a_move_and_a_cancel_cannot_run_at_the_same_time() {
        let r = rig(FILE_SETTINGS);
        let m = machine(&r.p);
        let inner = with_lock(&r.p, || {
            (
                adopt_locked(&r.p, &m, &tagged(ARN)).unwrap(),
                cancel_locked(&r.p, &m, &tagged(ARN)).unwrap(),
                arm_locked(&r.p).unwrap(),
                lock_busy(&r.p),
            )
        })
        .unwrap()
        .unwrap();
        assert_eq!(inner, (Outcome::Busy, Outcome::Busy, Outcome::Busy, true));
        assert!(did(&m).is_empty());
        assert!(!marker_file(&r.p).exists());
        assert!(lock_freed(&r.p));
    }

    /// M1, crash point 1: killed after the re-wrap landed and before the settings were written. The store says KMS, the
    /// settings still choose the file key. The next run puts the settings right, from the files, and the service comes up.
    #[test]
    fn a_run_killed_after_the_swap_and_before_the_settings_is_put_right() {
        let r = rig(FILE_SETTINGS);
        std::fs::write(&r.p.store, "{\"kek\":\"kms\"}").unwrap();
        assert!(pending(&r.p, &tagged(ARN)), "a box in this state has work");
        let m = machine(&r.p);
        *m.state_now.borrow_mut() = None;
        let out = adopt(&r.p, &m, &tagged(ARN)).unwrap();
        assert!(matches!(out, Outcome::Reconciled(_)), "{out:?}");
        let s = std::fs::read_to_string(&r.p.settings).unwrap();
        assert!(
            s.contains(&format!("OZBOX_KMS_KEY_ID={ARN}")) && !s.contains("ALLOW_FILE_KEK"),
            "{s}"
        );
        let log = did(&m);
        assert!(
            at(&log, "probe") < at(&log, "start ozbox-secrets"),
            "{log:?}"
        );
        assert!(
            key_file(&r.p).exists(),
            "nothing is destroyed by putting the settings right"
        );
        // and the next run is the ordinary one: waiting for the commit
        assert!(adopt(&r.p, &machine(&r.p), &tagged(ARN))
            .unwrap_err()
            .contains("not ready"));
        let ready = machine(&r.p);
        *ready.state_now.borrow_mut() = Some(State::ready("", "kms", None));
        assert_eq!(
            adopt(&r.p, &ready, &tagged(ARN)).unwrap(),
            Outcome::AwaitingCommit
        );
    }

    /// M1, crash point 2: killed inside a put-back, after the store was written back and before the settings. The store says
    /// file, the settings name KMS and the key file is there. The next run writes the file settings back.
    #[test]
    fn a_run_killed_inside_a_put_back_is_put_right() {
        let r = rig(&format!(
            "OZBOX_SECRET_SCOPE=main\nOZBOX_KMS_KEY_ID={ARN}\nOZBOX_KMS_REGION=us-east-1\n"
        ));
        assert!(pending(&r.p, &tagged(ARN)));
        let m = machine(&r.p);
        *m.state_now.borrow_mut() = None;
        let out = adopt(&r.p, &m, &tagged(ARN)).unwrap();
        assert!(matches!(out, Outcome::Reconciled(_)), "{out:?}");
        let s = std::fs::read_to_string(&r.p.settings).unwrap();
        assert!(
            s.contains("OZBOX_SECRET_ALLOW_FILE_KEK=1") && !s.contains("OZBOX_KMS_KEY_ID"),
            "{s}"
        );
        assert_eq!(
            std::fs::read_to_string(&r.p.store).unwrap(),
            "{\"kek\":\"file\"}"
        );
        assert!(!pending(&r.p, &untagged()) && !disagree(&r.p));
    }

    /// M2: the store is replaced whole or not at all. A writer that fails half way leaves the old file, and no temporary file.
    #[test]
    fn a_rewrite_that_fails_half_way_leaves_the_old_file_and_nothing_else() {
        use std::io::Write;
        use std::os::unix::fs::MetadataExt;
        let d = tempfile::tempdir().unwrap();
        let path = d.path().join("secrets.json");
        std::fs::write(&path, "old").unwrap();
        let me = std::fs::metadata(&path).unwrap();
        let half = |f: &mut std::fs::File, b: &[u8]| -> std::io::Result<()> {
            f.write_all(&b[..b.len() / 2])?;
            Err(std::io::Error::other("disk full"))
        };
        assert!(write_atomic_via(&path, b"new-bytes", 0o600, None, &half).is_err());
        assert_eq!(std::fs::read_to_string(&path).unwrap(), "old");
        assert_eq!(
            std::fs::read_dir(d.path()).unwrap().count(),
            1,
            "no temporary file is left"
        );
        // a whole write replaces it, keeps the mode and the owner asked for, and leaves no temporary file
        write_atomic(&path, b"new-bytes", 0o600, Some((me.uid(), me.gid()))).unwrap();
        assert_eq!(std::fs::read_to_string(&path).unwrap(), "new-bytes");
        let m = std::fs::metadata(&path).unwrap();
        assert_eq!((m.mode() & 0o777, m.uid()), (0o600, me.uid()));
        assert_eq!(std::fs::read_dir(d.path()).unwrap().count(), 1);
        // a temporary name planted as a link is removed, never followed
        let elsewhere = d.path().join("elsewhere");
        std::fs::write(&elsewhere, "mine").unwrap();
        std::os::unix::fs::symlink(&elsewhere, d.path().join(".secrets.json.adopt-new")).unwrap();
        write_atomic(&path, b"third", 0o644, None).unwrap();
        assert_eq!(std::fs::read_to_string(&elsewhere).unwrap(), "mine");
        assert_eq!(std::fs::metadata(&path).unwrap().mode() & 0o777, 0o644);
    }

    /// H2: a label written before the box moved (a forged answer led the laptop to write it) only speeds the move up: the box
    /// moves, and it commits at once, because the label is already there.
    #[test]
    fn a_label_written_before_the_box_moved_does_not_strand_it() {
        let r = rig(FILE_SETTINGS);
        assert!(pending(&r.p, &committed(ARN)));
        let m = machine(&r.p);
        assert_eq!(adopt(&r.p, &m, &committed(ARN)).unwrap(), Outcome::Moved(3));
        assert!(!key_file(&r.p).exists() && !backup_file(&r.p).exists());
        assert!(std::fs::read_to_string(&r.p.store).unwrap().contains("kms"));
    }

    /// A moment with neither tag (the laptop swaps its tags) is not a reason to change anything.
    #[test]
    fn a_moment_with_neither_tag_changes_nothing() {
        let r = rig(FILE_SETTINGS);
        moved(&r);
        let m = machine(&r.p);
        assert_eq!(adopt(&r.p, &m, &untagged()).unwrap(), Outcome::NotRequested);
        // (it only looks: KMS answers, so it is not a stranded box)
        assert!(did(&m).iter().all(|l| l == "probe"), "{:?}", did(&m));
        assert!(key_file(&r.p).exists() && backup_file(&r.p).exists());
        assert!(std::fs::read_to_string(&r.p.store).unwrap().contains("kms"));
    }

    /// The `/work` copy has not been refreshed when the committed box is finished: the key file stays and the next run
    /// removes it once the copy says `kms`.
    #[test]
    fn the_key_file_stays_until_the_copy_on_work_is_wrapped_by_kms_too() {
        let r = rig(FILE_SETTINGS);
        moved(&r);
        std::fs::write(r.p.persist.join("secrets.json"), "{\"kek\":\"file\"}").unwrap();
        let mut m = machine(&r.p);
        m.copy_follows = None;
        *m.state_now.borrow_mut() = Some(State::ready("", "kms", None));
        assert!(adopt(&r.p, &m, &committed(ARN))
            .unwrap_err()
            .contains("kept until"));
        assert!(key_file(&r.p).exists());
        let last = machine(&r.p);
        *last.state_now.borrow_mut() = Some(State::ready("", "kms", None));
        assert_eq!(
            adopt(&r.p, &last, &committed(ARN)).unwrap(),
            Outcome::Finished
        );
        assert!(!key_file(&r.p).exists() && !backup_file(&r.p).exists());
    }

    #[test]
    fn the_settings_keep_every_other_line_and_never_duplicate_the_key() {
        let t = settings_with_kms(
            "OZBOX_SECRET_SCOPE=a\n# a note\nOZBOX_KMS_KEY_ID=\nOZBOX_KMS_REGION=old\nOZBOX_SECRET_ALLOW_FILE_KEK=1\nOTHER=1\n",
            ARN,
            "us-east-1",
        );
        assert_eq!(
            t,
            format!("OZBOX_SECRET_SCOPE=a\n# a note\nOTHER=1\nOZBOX_KMS_KEY_ID={ARN}\nOZBOX_KMS_REGION=us-east-1\n")
        );
        // and back: the file settings a file-keyed box had
        let back = settings_with_file(&t);
        assert_eq!(
            back,
            "OZBOX_SECRET_SCOPE=a\n# a note\nOTHER=1\nOZBOX_SECRET_ALLOW_FILE_KEK=1\n"
        );
        assert_eq!(arn_region(ARN), Some("us-east-1"));
        assert_eq!(
            arn_region("arn:aws-us-gov:kms:us-gov-west-1:123456789012:key/ab-12"),
            Some("us-gov-west-1")
        );
    }

    #[test]
    fn the_unit_is_started_only_when_there_is_work_and_as_a_unit_of_its_own() {
        let r = rig(FILE_SETTINGS);
        assert!(!pending(&r.p, &untagged()), "no tag");
        assert!(!pending(&r.p, &Tg(HashMap::new(), false)), "no metadata");
        assert!(pending(&r.p, &tagged(ARN)), "tag and a file key");
        // moved and waiting for the commit: nothing to do until the laptop writes the label
        moved(&r);
        assert!(!pending(&r.p, &tagged(ARN)), "waiting for the commit");
        // committed: finishing is work while the key file is there, and not after
        assert!(pending(&r.p, &committed(ARN)));
        let rest = machine(&r.p);
        *rest.state_now.borrow_mut() = Some(State::ready("", "kms", None));
        assert_eq!(
            adopt(&r.p, &rest, &committed(ARN)).unwrap(),
            Outcome::Finished
        );
        assert!(!pending(&r.p, &committed(ARN)));
        // a recorded cancel is work only while the store is still on KMS
        let c = rig(FILE_SETTINGS);
        std::fs::write(marker_file(&c.p), "cancelled\n").unwrap();
        assert!(!pending(&c.p, &tagged(ARN)));
        // started as a transient unit, not as a pre-start step of another one
        let runner = ozbox_core::RecordingRunner::new();
        start_unit(&runner).unwrap();
        let calls = runner.calls();
        assert_eq!(calls.len(), 1);
        let line = format!("{} {}", calls[0].program, calls[0].args.join(" "));
        assert!(
            line.starts_with("systemd-run --unit=ozbox-adopt-fleet-key --collect")
                && line.ends_with("/usr/local/bin/ozbox secrets adopt-kms"),
            "{line}"
        );
    }

    /// The facts the laptop reads are what root sees in the files.
    #[test]
    fn the_facts_say_what_the_files_say() {
        let r = rig(FILE_SETTINGS);
        let m = machine(&r.p);
        let f = facts(&r.p, &m, &tagged(ARN));
        assert_eq!(
            f,
            Facts {
                service_ready: true,
                service_kek: Kek::File,
                store_kek: Kek::File,
                persist_kek: Kek::File,
                settings_key: None,
                key_file: true,
                backup: false,
                cancelled: false,
                busy: false,
                tag_adopt: Some(ARN.into()),
                tag_key: None,
                service_escrow: Some(false),
                service_no_escrow: false,
                metadata_guard: true,
                move_backoff_mins: 0,
                kms_probe: Probe::Na,
                names: None,
            }
        );
        moved(&r);
        let on_kms = machine(&r.p);
        *on_kms.state_now.borrow_mut() = Some(State::ready("", "kms", None));
        // until the service's saver has copied the store to /work the move is not committable
        assert!(!facts(&r.p, &on_kms, &tagged(ARN)).committable(ARN));
        std::fs::write(r.p.persist.join("secrets.json"), "{\"kek\":\"kms\"}").unwrap();
        assert!(facts(&r.p, &on_kms, &tagged(ARN)).committable(ARN));
        // the box's own look at its tags: none on a machine with no metadata service
        assert_eq!(
            facts(&r.p, &on_kms, &Tg(HashMap::new(), false)).tag_adopt,
            None
        );
    }

    /// N1: the lock is a kernel `flock`. Left-over bytes in the file (an old PID, an empty file, junk) never make it busy,
    /// and a real flock on a second open file contends on macOS and Linux alike.
    #[test]
    fn the_lock_is_a_real_flock_and_leftovers_in_the_file_do_not_matter() {
        let r = rig(FILE_SETTINGS);
        for left in ["", "4000000", &std::process::id().to_string(), "junk\u{0}"] {
            std::fs::create_dir_all(lock_file(&r.p).parent().unwrap()).unwrap();
            std::fs::write(lock_file(&r.p), left).unwrap();
            // nobody holds the flock, so it is free whatever the file says (even our own PID)
            assert!(lock_freed(&r.p));
            assert!(ran_when_free(&r.p));
        }
        // a holder makes it busy, for a second take and for a look
        let held = with_lock(&r.p, || {
            (with_lock(&r.p, || ()).unwrap().is_none(), lock_busy(&r.p))
        })
        .unwrap()
        .unwrap();
        assert_eq!(held, (true, true));
        // the file is never removed (a lock on a deleted file would let a second run lock a new one)
        assert!(lock_file(&r.p).exists());
        assert!(lock_freed(&r.p));
    }

    /// N1: many runs started together are never inside the lock at the same time, and exactly the ones that got it ran.
    #[test]
    fn racing_runs_never_hold_the_lock_together() {
        use std::sync::atomic::{AtomicUsize, Ordering};
        use std::sync::{Arc, Barrier};
        let r = rig(FILE_SETTINGS);
        let inside = Arc::new(AtomicUsize::new(0));
        let max = Arc::new(AtomicUsize::new(0));
        let got = Arc::new(AtomicUsize::new(0));
        let start = Arc::new(Barrier::new(8));
        let mut hs = Vec::new();
        for _ in 0..8 {
            let (p, inside, max, got, start) = (
                r.p.clone(),
                inside.clone(),
                max.clone(),
                got.clone(),
                start.clone(),
            );
            hs.push(std::thread::spawn(move || {
                start.wait();
                for _ in 0..20 {
                    let ran = with_lock(&p, || {
                        let n = inside.fetch_add(1, Ordering::SeqCst) + 1;
                        max.fetch_max(n, Ordering::SeqCst);
                        std::thread::sleep(std::time::Duration::from_millis(1));
                        inside.fetch_sub(1, Ordering::SeqCst);
                    })
                    .unwrap();
                    if ran.is_some() {
                        got.fetch_add(1, Ordering::SeqCst);
                    }
                }
            }));
        }
        for h in hs {
            h.join().unwrap();
        }
        assert_eq!(
            max.load(Ordering::SeqCst),
            1,
            "two runs held the lock at once"
        );
        assert!(got.load(Ordering::SeqCst) >= 1);
        assert!(lock_freed(&r.p));
    }

    /// N1: a run that panics (or ends any way) frees the lock; one run ending never frees another's.
    #[test]
    fn a_run_that_dies_frees_the_lock_and_an_ending_run_never_frees_anothers() {
        let r = rig(FILE_SETTINGS);
        let p = r.p.clone();
        let died = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let _ = with_lock(&p, || panic!("killed"));
        }));
        assert!(died.is_err());
        assert!(lock_freed(&r.p), "a run that died left the lock held");
        // run B holds it; run A fails to get it and ends; B still holds it afterwards
        let still = with_lock(&r.p, || {
            let a = with_lock(&r.p, || ()).unwrap();
            (a.is_none(), lock_busy(&r.p))
        })
        .unwrap()
        .unwrap();
        assert_eq!(still, (true, true));
    }

    /// L2: a store that is a link (planted by the secrets user) is never read or followed by root.
    #[test]
    fn a_store_that_is_a_link_is_refused() {
        let r = rig(FILE_SETTINGS);
        let elsewhere = r.p.store.with_file_name("elsewhere");
        std::fs::write(&elsewhere, "{\"kek\":\"file\"}").unwrap();
        std::fs::remove_file(&r.p.store).unwrap();
        std::os::unix::fs::symlink(&elsewhere, &r.p.store).unwrap();
        let m = machine(&r.p);
        assert!(adopt(&r.p, &m, &tagged(ARN))
            .unwrap_err()
            .contains("could not be read"));
        assert!(!did(&m)
            .iter()
            .any(|l| l.starts_with("stop") || l.starts_with("rotate")));
    }

    /// The re-wrap runs as the secrets user, opens with the key kind it is told EXPLICITLY (a KMS key id in the environment
    /// would make KMS the default and the old store would not open), and names the new one for `rotate-kek --to`. No shell.
    #[test]
    fn the_rewrap_is_run_as_the_secrets_user_with_the_old_key_chosen_explicitly() {
        let r = rig(FILE_SETTINGS);
        let runner = ozbox_core::RecordingRunner::new();
        runner.reply(ozbox_core::Output {
            status: Some(0),
            stdout: "Moved 3 secrets to the new key-encryption key.\n".into(),
            stderr: String::new(),
        });
        let m = SystemMachine {
            runner: &runner,
            paths: &r.p,
        };
        let side = side_file(&r.p);
        assert_eq!(
            m.rotate(&side, "file", "kms", "main", ARN, "us-east-1")
                .unwrap(),
            3
        );
        let c = &runner.calls()[0];
        assert_eq!(c.program, "runuser");
        let args = c.args.join(" ");
        assert!(args.starts_with("-u ozbox-secrets -- env "), "{args}");
        for want in [
            &format!("OZBOX_SECRET_FILE={}", side.display()),
            "OZBOX_SECRET_KEK=file",
            "OZBOX_SECRET_SCOPE=main",
            &format!("OZBOX_KMS_KEY_ID={ARN}"),
            "OZBOX_KMS_REGION=us-east-1",
            "/usr/local/bin/ozbox secrets rotate-kek --to kms",
        ] {
            assert!(args.contains(want), "{want} not in {args}");
        }
        // taking it back opens with KMS and writes the file key
        let back = ozbox_core::RecordingRunner::new();
        back.reply(ozbox_core::Output {
            status: Some(0),
            stdout: "2".into(),
            stderr: String::new(),
        });
        let m = SystemMachine {
            runner: &back,
            paths: &r.p,
        };
        m.rotate(&side, "kms", "file", "main", ARN, "us-east-1")
            .unwrap();
        let args = back.calls()[0].args.join(" ");
        assert!(
            args.contains("OZBOX_SECRET_KEK=kms") && args.ends_with("rotate-kek --to file"),
            "{args}"
        );
        // the copy is made by the secrets user, with no shell
        let copying = ozbox_core::RecordingRunner::new();
        let m = SystemMachine {
            runner: &copying,
            paths: &r.p,
        };
        m.copy_store(&r.p.store, &side).unwrap();
        let c = &copying.calls()[0];
        assert_eq!(
            (c.program.as_str(), c.args[..4].join(" ")),
            ("runuser", "-u ozbox-secrets -- cp".into())
        );
        // the probe runs the same way (as the secrets user, with the box's scope and no old key to open)
        let probing = ozbox_core::RecordingRunner::new();
        let m = SystemMachine {
            runner: &probing,
            paths: &r.p,
        };
        m.probe_kms("main", ARN, "us-east-1").unwrap();
        let args = probing.calls()[0].args.join(" ");
        assert!(
            args.starts_with("-u ozbox-secrets -- env OZBOX_SECRET_SCOPE=main ")
                && args.ends_with("/usr/local/bin/ozbox secrets probe-kms")
                && !args.contains("OZBOX_SECRET_FILE"),
            "{args}"
        );
        // a failed re-wrap says why (trimmed)
        let failing = ozbox_core::RecordingRunner::new();
        failing.reply(ozbox_core::Output {
            status: Some(1),
            stdout: String::new(),
            stderr: "AccessDeniedException: not authorized to perform kms:Decrypt".into(),
        });
        let m = SystemMachine {
            runner: &failing,
            paths: &r.p,
        };
        let e = m
            .rotate(&side, "file", "kms", "main", ARN, "us-east-1")
            .unwrap_err();
        assert!(e.contains("AccessDenied"), "{e}");
    }

    /// The program that moves the store is the one that reads the box's tags, so the tag names are one string on both sides.
    #[test]
    fn the_tags_the_laptop_sets_are_the_tags_the_box_reads() {
        assert_eq!(TAG_ADOPT, ozbox_provider_aws::SECRETS_ADOPT_LABEL);
        assert_eq!(TAG_KEY, ozbox_provider_aws::SECRETS_KEY_LABEL);
    }
}
