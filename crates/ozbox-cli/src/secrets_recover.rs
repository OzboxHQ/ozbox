//! Setting aside a secrets store that can no longer be opened, so the service can start a new one (ADR 0029 Amendment 7,
//! as amended after a security review, 2026-11-11).
//!
//! A box that keeps its store's key in a file, with no copy escrowed off the box, loses the key when its system disk is
//! replaced. The store comes back from `/work` and cannot be opened; the service stops `not-ready` with the code
//! `no-escrow` (see `secrets_state`). The root helper's `recover-secrets` renames that store aside. It is a destructive
//! step for everything the store held, so it is allowed only when **both** of these hold:
//!
//! 1. **The service itself said so.** The state file is read as root and trusted only as the service's own (owner, mode,
//!    no link, a folder nobody else can write); it must carry `code=no-escrow`, `kek=file`, `escrow=none`. The service's
//!    settings must choose a file-kept key, the key file must be absent, and the unit must have stopped with the exit code
//!    the service uses for that (78), not be starting or running. A KMS or TPM box never writes `no-escrow` (its failures
//!    are retried and exit 1), so a box between restarts, or one whose key service is down, is refused.
//! 2. **The owner approved it, from outside the box.** The service is down, so it cannot spend an approval; the root helper
//!    checks one itself. The approval is a signature by the key pinned when the box was made (`/etc/ozbox/approval-keys`,
//!    root-owned) over a one-time challenge bound to this box and to the digest of the exact store being set aside. The
//!    box user cannot make that signature. A pinned key the owner revoked (the record of that is kept on `/work`, beside the
//!    store, where a new store does not reset it) cannot approve. A box with no pin can be recovered only from the
//!    machine's own console, as root (`--console`).
//!
//! Nothing is deleted: the store and its `/work` copy are renamed, never opened again.

use std::path::{Path, PathBuf};

use crate::secrets_state::{read_trusted, State};

/// Where everything is (overridable for tests).
#[derive(Debug, Clone)]
pub struct Paths {
    pub store: PathBuf,
    pub persist: PathBuf,
    pub state: PathBuf,
    pub settings: PathBuf,
    pub pin: PathBuf,
    pub challenge: PathBuf,
    /// The adopt lock (a `flock` file on tmpfs, so a reboot frees it).
    pub adopt_lock: PathBuf,
}

impl Default for Paths {
    fn default() -> Self {
        let var = |k: &str, d: &str| PathBuf::from(std::env::var(k).unwrap_or_else(|_| d.into()));
        Self {
            store: var("OZBOX_SECRET_FILE", "/var/lib/ozbox-secrets/secrets.json"),
            persist: var("OZBOX_SECRETS_PERSIST", "/work/ozbox-secrets-private"),
            state: var("OZBOX_SECRETS_STATE", crate::secrets_cli::STATE_FILE),
            settings: var("OZBOX_SECRETS_ENV", "/etc/ozbox/secrets.env"),
            pin: var("OZBOX_PINNED_APPROVERS", crate::approval_key::PIN_FILE),
            challenge: var("OZBOX_RECOVER_CHALLENGE", "/run/ozbox-recover-challenge"),
            adopt_lock: var("OZBOX_ADOPT_LOCK", "/run/ozbox-adopt/lock"),
        }
    }
}

/// What the machine says, gathered by the caller (so a test can say anything).
#[derive(Debug, Clone)]
pub struct Facts {
    /// The secrets user's uid: the only owner its state file may have.
    pub service_uid: u32,
    /// The unit is starting or running.
    pub unit_active: bool,
    /// The unit's main process's last exit code, when it has one.
    pub unit_exit: Option<i32>,
    /// The machine has a TPM the service would use.
    pub tpm: bool,
    /// The owner of the pin file (root on a box).
    pub pin_owner: u32,
}

/// The exit code the service stops with for a configuration state (`secrets_cli`).
pub const NOT_READY_EXIT: i32 = 78;
const CHALLENGE_TTL_MS: u64 = 5 * 60_000;
/// The approval scope the signed message names. Not a scope the service mints: recovery is checked here, with it down.
pub const SCOPE: &str = "recover-secrets";
/// The record, on `/work` beside the store's copy, of the pinned keys the owner revoked (see `approval_key::apply_pin`).
pub const PIN_RECORD: &str = "pin-record";

/// The pin's digest as the pin record writes it.
pub fn pin_digest(id: &str, pk_hex: &str) -> String {
    ozbox_core::audit::hex(
        ring::digest::digest(&ring::digest::SHA256, format!("{id} {pk_hex}").as_bytes()).as_ref(),
    )
}

/// Whether the pin record on `/work` says this pin was revoked.
pub fn pin_revoked(persist: &Path, digest: &str) -> bool {
    std::fs::read_to_string(persist.join(PIN_RECORD))
        .unwrap_or_default()
        .lines()
        .any(|l| l.trim() == format!("revoked {digest}"))
}

/// Add a line to the pin record (the service's own file on `/work`; best effort: the store keeps its own record too).
pub fn record_pin(persist: &Path, what: &str, digest: &str) {
    use std::io::Write;
    let line = format!("{what} {digest}");
    if std::fs::read_to_string(persist.join(PIN_RECORD))
        .unwrap_or_default()
        .lines()
        .any(|l| l.trim() == line)
    {
        return;
    }
    let _ = std::fs::create_dir_all(persist);
    if let Ok(mut f) = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(persist.join(PIN_RECORD))
    {
        let _ = writeln!(f, "{line}");
    }
}

/// The digest of the store that would be set aside: what an approval is bound to (sixteen hex digits of its sha256).
fn store_digest(p: &Paths) -> Result<String, String> {
    let bytes = std::fs::read(&p.store)
        .or_else(|_| std::fs::read(p.persist.join("secrets.json")))
        .map_err(|_| "there is no store on this box to set aside".to_string())?;
    let d = ring::digest::digest(&ring::digest::SHA256, &bytes);
    Ok(ozbox_core::audit::hex(&d.as_ref()[..8]))
}

/// Everything that must hold before a store is set aside, said as the first thing that does not. `Ok` is the store's digest.
pub fn preconditions(p: &Paths, f: &Facts) -> Result<String, String> {
    let refuse = |why: &str| Err(format!("refused: {why}; nothing was changed"));
    if p.store
        .with_file_name(crate::secrets_persist::KEY_FILE)
        .exists()
    {
        return refuse("the store's key file is on this disk, so the store can be opened");
    }
    let settings = crate::secrets_file::env_file(&p.settings);
    let kind = crate::secrets_file::kek_kind_with(&|k| settings.get(k).cloned(), f.tpm);
    if kind != Some("file") {
        return refuse(&format!(
            "this box keeps its store's key with {} rather than in a file, so a missing key is the key service's to fix, not a lost store",
            kind.unwrap_or("nothing configured")
        ));
    }
    if f.unit_active {
        return refuse("the secrets service is starting or running");
    }
    if f.unit_exit != Some(NOT_READY_EXIT) {
        return refuse("the secrets service did not stop because its store's key is lost (it is between restarts, or stopped for another reason); look at `ozbox admin <box> -- collect-logs`");
    }
    let state: State = match read_trusted(&p.state, f.service_uid) {
        Ok(s) => s,
        Err(e) => return refuse(&e),
    };
    if !(state.is_no_escrow() && state.file_kek_without_escrow()) {
        return refuse("the secrets service did not record that its store's key is lost with no escrow; only that state may be recovered");
    }
    store_digest(p)
}

/// The challenge a person's computer signs, as the words the root helper prints.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Challenge {
    pub nonce: String,
    pub expires_ms: u64,
    pub store: String,
    pub key_id: String,
}

impl Challenge {
    /// What the pinned key signs (the same message shape as every laptop approval: `approval_key::message`).
    pub fn message(&self) -> String {
        crate::approval_key::message(
            SCOPE,
            &self.store,
            "",
            &self.key_id,
            &self.nonce,
            self.expires_ms,
        )
    }

    pub fn words(&self) -> String {
        format!(
            "challenge {} {} {} {}",
            self.nonce, self.expires_ms, self.store, self.key_id
        )
    }

    /// Read the root helper's answer to `recover-secrets challenge`.
    pub fn from_output(out: &str) -> Option<Self> {
        let line = out
            .lines()
            .find_map(|l| l.trim().strip_prefix("challenge "))?;
        let w: Vec<&str> = line.split_whitespace().collect();
        let [nonce, exp, store, key] = w.as_slice() else {
            return None;
        };
        let hex = |s: &str, n: usize| s.len() == n && s.bytes().all(|b| b.is_ascii_hexdigit());
        let expires_ms = exp.parse().ok()?;
        (hex(nonce, 32) && hex(store, 16) && crate::approval_key::id_ok(key)).then(|| Self {
            nonce: nonce.to_string(),
            expires_ms,
            store: store.to_string(),
            key_id: key.to_string(),
        })
    }
}

/// The pinned key, or why recovery cannot be approved from a computer.
fn pinned(p: &Paths, f: &Facts) -> Result<(String, String), String> {
    let pin = crate::approval_key::read_pin_owned_by(&p.pin, f.pin_owner)
        .map_err(|e| format!("refused: {e}; nothing was changed"))?
        .ok_or_else(|| "refused: no approval key was pinned when this box was made, so nothing outside the box can approve a recovery. From the machine's own console, as root: ozbox secrets recover-store --console. Nothing was changed".to_string())?;
    if pin_revoked(&p.persist, &pin_digest(&pin.0, &pin.1)) {
        return Err("refused: the key pinned when this box was made was revoked by its owner, so it cannot approve a recovery. From the machine's own console, as root: ozbox secrets recover-store --console. Nothing was changed".into());
    }
    Ok(pin)
}

/// Issue a one-time challenge (root only; the file is root's, 0600). Refused unless the store may be recovered.
pub fn challenge(p: &Paths, f: &Facts, now_ms: u64) -> Result<Challenge, String> {
    let store = preconditions(p, f)?;
    let (key_id, _) = pinned(p, f)?;
    let mut raw = [0u8; 16];
    getrandom::getrandom(&mut raw).map_err(|_| "no random numbers are available".to_string())?;
    let c = Challenge {
        nonce: ozbox_core::audit::hex(&raw),
        expires_ms: now_ms + CHALLENGE_TTL_MS,
        store,
        key_id,
    };
    write_private(&p.challenge, &c.words())
        .map_err(|e| format!("the challenge could not be kept ({})", e.kind()))?;
    Ok(c)
}

#[cfg(unix)]
fn write_private(path: &Path, text: &str) -> std::io::Result<()> {
    use std::io::Write;
    use std::os::unix::fs::OpenOptionsExt;
    let tmp = path.with_extension("tmp");
    let _ = std::fs::remove_file(&tmp);
    std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&tmp)
        .and_then(|mut f| f.write_all(text.as_bytes()))?;
    std::fs::rename(&tmp, path)
}

#[cfg(not(unix))]
fn write_private(path: &Path, text: &str) -> std::io::Result<()> {
    std::fs::write(path, text)
}

/// Check a signed challenge and, when it is good, set the store aside. The challenge is spent whatever happens.
pub fn redeem(
    p: &Paths,
    f: &Facts,
    nonce: &str,
    expires_ms: u64,
    signature: &str,
    now_ms: u64,
) -> Result<usize, String> {
    let kept = std::fs::read_to_string(&p.challenge).ok();
    let _ = std::fs::remove_file(&p.challenge);
    let refuse = |why: &str| {
        Err(format!(
            "refused: {why}; nothing was changed. Ask for a new challenge"
        ))
    };
    let Some(c) = kept.as_deref().and_then(Challenge::from_output) else {
        return refuse("there is no challenge waiting");
    };
    if c.nonce != nonce || c.expires_ms != expires_ms {
        return refuse("that is not the challenge this box issued");
    }
    if now_ms > c.expires_ms {
        return refuse("the challenge expired");
    }
    // the store must still be the one the approval names, in a state that may be recovered
    let store = preconditions(p, f)?;
    if store != c.store {
        return refuse("the store changed after the challenge was issued");
    }
    let (key_id, pk) = pinned(p, f)?;
    if key_id != c.key_id || !crate::approval_key::verify(&pk, &c.message(), signature) {
        return refuse("the signature is not the pinned key's");
    }
    set_aside(p)
}

/// The machine's own console, as root: no signature, the same state checks.
pub fn console(p: &Paths, f: &Facts) -> Result<usize, String> {
    preconditions(p, f)?;
    set_aside(p)
}

fn set_aside(p: &Paths) -> Result<usize, String> {
    let stamp = crate::tokenmac::now_ms();
    let mut moved = 0;
    for f in [p.store.clone(), p.persist.join("secrets.json")] {
        if f.is_file() {
            let aside = f.with_extension(format!("json.lost-{stamp}"));
            std::fs::rename(&f, &aside)
                .map_err(|e| format!("the old store could not be set aside ({})", e.kind()))?;
            moved += 1;
        }
    }
    Ok(moved)
}

/// The machine's facts, as root sees them.
pub fn facts(runner: &dyn ozbox_core::CommandRunner) -> Facts {
    use ozbox_core::CommandSpec;
    let out = |c: CommandSpec| runner.run(&c).map(|o| o.stdout).unwrap_or_default();
    let service_uid = out(CommandSpec::new("id").args(["-u", "ozbox-secrets"]))
        .trim()
        .parse()
        .unwrap_or(u32::MAX);
    let show = out(CommandSpec::new("systemctl").args([
        "show",
        "-p",
        "ActiveState",
        "-p",
        "ExecMainStatus",
        "ozbox-secrets.service",
    ]));
    let (unit_active, unit_exit) = parse_show(&show);
    Facts {
        service_uid,
        unit_active,
        unit_exit,
        tpm: crate::secrets_enc::TpmKek::available(),
        pin_owner: 0,
    }
}

/// `systemctl show -p ActiveState -p ExecMainStatus`: whether the unit is starting or running, and its last exit code.
pub fn parse_show(text: &str) -> (bool, Option<i32>) {
    let mut active = true; // unknown is treated as running: nothing is set aside while that is not known
    let mut exit = None;
    for l in text.lines() {
        match l.trim().split_once('=') {
            Some(("ActiveState", v)) => active = !matches!(v, "failed" | "inactive"),
            Some(("ExecMainStatus", v)) => exit = v.parse().ok(),
            _ => {}
        }
    }
    (active, exit)
}

#[cfg(all(test, unix))]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use std::os::unix::fs::{MetadataExt, PermissionsExt};

    struct Rig {
        _d: tempfile::TempDir,
        p: Paths,
        f: Facts,
        seed: String,
    }

    const LOST: &str =
        "not-ready: the store's key is not on this disk\nkek=file\nescrow=none\ncode=no-escrow\n";

    fn rig(settings: &str, state: &str) -> Rig {
        let d = tempfile::tempdir().unwrap();
        let r = d.path();
        for dir in ["lib", "work", "run", "etc"] {
            std::fs::create_dir(r.join(dir)).unwrap();
            std::fs::set_permissions(r.join(dir), std::fs::Permissions::from_mode(0o755)).unwrap();
        }
        let p = Paths {
            store: r.join("lib/secrets.json"),
            persist: r.join("work"),
            state: r.join("run/state"),
            settings: r.join("etc/secrets.env"),
            pin: r.join("etc/approval-keys"),
            challenge: r.join("run/challenge"),
            adopt_lock: r.join("run/adopt/lock"),
        };
        std::fs::write(&p.store, "{\"sealed\":true}").unwrap();
        std::fs::write(p.persist.join("secrets.json"), "{\"sealed\":true}").unwrap();
        std::fs::write(&p.settings, settings).unwrap();
        std::fs::write(&p.state, state).unwrap();
        std::fs::set_permissions(&p.state, std::fs::Permissions::from_mode(0o644)).unwrap();
        let (seed, pk) = crate::approval_key::generate().unwrap();
        let label = crate::approval_key::pin_label(&pk).unwrap();
        std::fs::write(&p.pin, format!("laptop {label}\n")).unwrap();
        std::fs::set_permissions(&p.pin, std::fs::Permissions::from_mode(0o644)).unwrap();
        let me = std::fs::metadata(r).unwrap().uid();
        let f = Facts {
            service_uid: me,
            unit_active: false,
            unit_exit: Some(NOT_READY_EXIT),
            tpm: false,
            pin_owner: me,
        };
        Rig {
            _d: d,
            p,
            f,
            seed: seed.to_string(),
        }
    }

    const FILE_BOX: &str =
        "OZBOX_SECRET_SCOPE=dev\nOZBOX_KMS_KEY_ID=\nOZBOX_SECRET_ALLOW_FILE_KEK=1\n";
    const KMS_BOX: &str =
        "OZBOX_SECRET_SCOPE=dev\nOZBOX_KMS_KEY_ID=arn:aws:kms:us-east-1:123456789012:key/x\n";

    fn sign(r: &Rig, c: &Challenge) -> String {
        crate::approval_key::sign(&r.seed, &c.message()).unwrap()
    }

    fn kept(r: &Rig) -> bool {
        r.p.store.exists() && r.p.persist.join("secrets.json").exists()
    }

    #[test]
    fn a_lost_store_is_set_aside_only_with_the_pinned_keys_signature_once() {
        if cfg!(target_os = "macos") {
            return; // a file-kept key is not chosen on macOS (the keychain is)
        }
        let r = rig(FILE_BOX, LOST);
        let c = challenge(&r.p, &r.f, 1_000).unwrap();
        // the box user cannot sign: any other key's signature is refused, and the challenge is spent
        let (other, _) = crate::approval_key::generate().unwrap();
        let forged = crate::approval_key::sign(&other, &c.message()).unwrap();
        assert!(redeem(&r.p, &r.f, &c.nonce, c.expires_ms, &forged, 2_000)
            .unwrap_err()
            .contains("not the pinned key"));
        assert!(kept(&r));
        let good = sign(&r, &c);
        assert!(redeem(&r.p, &r.f, &c.nonce, c.expires_ms, &good, 2_000)
            .unwrap_err()
            .contains("no challenge waiting"));
        // a fresh challenge, signed by the pinned key, sets both copies aside (renamed, not deleted)
        let c = challenge(&r.p, &r.f, 3_000).unwrap();
        let sig = sign(&r, &c);
        assert_eq!(
            redeem(&r.p, &r.f, &c.nonce, c.expires_ms, &sig, 4_000).unwrap(),
            2
        );
        assert!(!r.p.store.exists());
        let aside = std::fs::read_dir(r.p.persist.as_path())
            .unwrap()
            .flatten()
            .any(|e| e.file_name().to_string_lossy().contains(".json.lost-"));
        assert!(aside);
    }

    /// The race the review found: a KMS or TPM box whose key service failed long enough for the service to stop. It never
    /// writes `no-escrow`, and even a state file that said so would not be enough on a box that does not keep its key in a
    /// file, or whose unit is between restarts.
    #[test]
    fn a_kms_or_tpm_box_or_a_service_between_restarts_is_refused() {
        let r = rig(KMS_BOX, "not-ready: the key service could not be reached (starting again)\nkek=kms\ncode=transient\n");
        let e = challenge(&r.p, &r.f, 1).unwrap_err();
        assert!(e.contains("rather than in a file"), "{e}");
        // the same state words on a KMS box: still refused, on what the box's settings say
        let r = rig(KMS_BOX, LOST);
        assert!(challenge(&r.p, &r.f, 1)
            .unwrap_err()
            .contains("rather than in a file"));
        // a TPM is chosen before a file-kept key
        let mut r = rig(FILE_BOX, LOST);
        r.f.tpm = true;
        assert!(challenge(&r.p, &r.f, 1).unwrap_err().contains("tpm2"));
        if cfg!(target_os = "macos") {
            return;
        }
        // between restarts: the unit is activating again, or it last exited 1 (a transient failure)
        let mut r = rig(FILE_BOX, LOST);
        r.f.unit_active = true;
        assert!(challenge(&r.p, &r.f, 1)
            .unwrap_err()
            .contains("starting or running"));
        r.f.unit_active = false;
        r.f.unit_exit = Some(1);
        assert!(challenge(&r.p, &r.f, 1)
            .unwrap_err()
            .contains("between restarts"));
        // a transient state, even with the right exit code, is not a lost store
        let r = rig(FILE_BOX, "not-ready: the vault did not answer (starting again)\nkek=file\nescrow=vault\ncode=transient\n");
        assert!(challenge(&r.p, &r.f, 1)
            .unwrap_err()
            .contains("did not record"));
        // the key file is here: the store can be opened
        let r = rig(FILE_BOX, LOST);
        std::fs::write(
            r.p.store.with_file_name(crate::secrets_persist::KEY_FILE),
            "k",
        )
        .unwrap();
        assert!(challenge(&r.p, &r.f, 1)
            .unwrap_err()
            .contains("can be opened"));
        assert!(kept(&r));
    }

    #[test]
    fn a_forged_state_file_is_never_the_services_word() {
        if cfg!(target_os = "macos") {
            return;
        }
        // the right words, written by someone who is not the service
        let mut r = rig(FILE_BOX, LOST);
        r.f.service_uid += 1;
        let e = challenge(&r.p, &r.f, 1).unwrap_err();
        assert!(e.contains("refused") && e.contains("service"), "{e}");
        // the right words, in a file others may write
        let r = rig(FILE_BOX, LOST);
        std::fs::set_permissions(&r.p.state, std::fs::Permissions::from_mode(0o666)).unwrap();
        assert!(challenge(&r.p, &r.f, 1).is_err());
        // the right words, reached through a link
        let r = rig(FILE_BOX, "ready\nkek=file\nescrow=none\n");
        let forged = r.p.persist.join("forged");
        std::fs::write(&forged, LOST).unwrap();
        std::fs::remove_file(&r.p.state).unwrap();
        std::os::unix::fs::symlink(&forged, &r.p.state).unwrap();
        assert!(challenge(&r.p, &r.f, 1).unwrap_err().contains("link"));
        // the person's sentence, without the service's code, is not enough
        let r = rig(
            FILE_BOX,
            "not-ready: the store's key is not on this disk and this box has no escrow for it\n",
        );
        assert!(challenge(&r.p, &r.f, 1)
            .unwrap_err()
            .contains("did not record"));
        assert!(kept(&r));
    }

    #[test]
    fn an_approval_is_bound_to_the_store_and_expires_and_a_revoked_pin_cannot_give_one() {
        if cfg!(target_os = "macos") {
            return;
        }
        let r = rig(FILE_BOX, LOST);
        let c = challenge(&r.p, &r.f, 1_000).unwrap();
        let sig = sign(&r, &c);
        // the store was swapped after the challenge
        std::fs::write(&r.p.store, "{\"another\":1}").unwrap();
        assert!(redeem(&r.p, &r.f, &c.nonce, c.expires_ms, &sig, 2_000)
            .unwrap_err()
            .contains("store changed"));
        let c = challenge(&r.p, &r.f, 1_000).unwrap();
        let sig = sign(&r, &c);
        assert!(
            redeem(&r.p, &r.f, &c.nonce, c.expires_ms, &sig, c.expires_ms + 1)
                .unwrap_err()
                .contains("expired")
        );
        // the owner revoked the pinned key: recorded on /work, so neither a new store nor a recovery brings it back
        let (id, pk) = crate::approval_key::read_pin_owned_by(&r.p.pin, r.f.pin_owner)
            .unwrap()
            .unwrap();
        record_pin(&r.p.persist, "revoked", &pin_digest(&id, &pk));
        assert!(challenge(&r.p, &r.f, 1).unwrap_err().contains("revoked"));
        // no pin at all: only the console
        let r = rig(FILE_BOX, LOST);
        std::fs::remove_file(&r.p.pin).unwrap();
        assert!(challenge(&r.p, &r.f, 1).unwrap_err().contains("--console"));
        assert_eq!(console(&r.p, &r.f).unwrap(), 2);
    }

    #[test]
    fn the_units_state_is_read_strictly() {
        assert_eq!(
            parse_show("ActiveState=failed\nExecMainStatus=78\n"),
            (false, Some(78))
        );
        assert_eq!(
            parse_show("ActiveState=activating\nExecMainStatus=1\n"),
            (true, Some(1))
        );
        // nothing said: treated as running
        assert_eq!(parse_show(""), (true, None));
        let c = Challenge {
            nonce: "0".repeat(32),
            expires_ms: 5,
            store: "a".repeat(16),
            key_id: "laptop".into(),
        };
        assert_eq!(
            Challenge::from_output(&format!("x\n{}\n", c.words())),
            Some(c)
        );
        assert_eq!(Challenge::from_output("challenge ; rm 1 2"), None);
    }
}
