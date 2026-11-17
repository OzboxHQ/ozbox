//! The credential holder and the apply unit (ADR 0040 §1, §2, §6; Amendment 2).
//!
//! The holder is a service identity of its own (`ozbox-fleetcred`: no shell, no box group, no listener but one Unix socket). It
//! is the only process on a box that may hold a fleet credential. It does four things and nothing else:
//!
//! 1. **The read session.** It takes the instance's own credentials (the cloud CLI reads them, because this user alone passes
//!    the metadata guard), assumes `obx-fleet-read` for 15 minutes with a `SourceIdentity`, and hands that session to the
//!    dashboard over the socket. A read session lists the fleet and changes nothing.
//! 2. **The window.** The owner's computer makes a change session for ONE plan (`ozbox fleet window`: it assumes
//!    `obx-fleet-change` with a plan-scoped session policy, because only the owner's own sign-in is in that role's trust; `main`
//!    is not) and seals it to this holder's key. The holder opens it, checks the owner's signature over its metadata, and
//!    keeps it **in memory only**, until the window's expiry or its first use.
//! 3. **The check.** Before a window is used, the holder itself verifies the owner's passkey assertion over
//!    `H("ozbox-fleet-apply-v1", box id, store id, "plan", plan id, plan hash)` against the **approver set the owner's computer
//!    signed** ([`ozbox_core::fleet_approvers`]), not against the dashboard's own list. It refuses a plan id it has spent
//!    (kept in a durable ledger it fsyncs BEFORE the apply starts, so a crash never allows a second apply), a window opened for
//!    another plan or another box, an expired window and anything the dashboard may not do.
//! 4. **The hand-off.** The change session goes to the apply unit (a transient uid of its own) through its standard input, never
//!    its arguments, environment, a file or a log. The unit applies the plan once and exits.
//!
//! What a credential is made of ([`SessionCreds`]) zeroizes on drop and prints as `<redacted>`. Nothing here writes one to disk.
//! The peer's user id is the kernel's word (`SO_PEERCRED`); a connection from any other user, the box user and every agent
//! included, gets the same refusal for every operation, and nothing about the credential.

// Built and tested; the unit that runs it on a box and the dashboard's route to it are the next slice (ADR 0040, Amendment 2).
#![cfg_attr(not(test), allow(dead_code))]

use std::collections::{HashMap, HashSet};
use std::io::Write as _;
use std::path::{Path, PathBuf};

use ozbox_core::approval::PasskeyEvidence;
use ozbox_core::fleet_approvers::{ApproverSet, SignedApproverSet};
use ozbox_core::{CommandRunner, CommandSpec, Plan, Provider};
use ozbox_seal::ServiceKey;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use zeroize::{Zeroize, Zeroizing};

use crate::fleet_gate::{challenge, operation_refusal, plan_hash, WindowStatus};
use crate::messages::t;

/// The domain tag of the owner's signature over a window's metadata.
pub const WINDOW_TAG: &str = "ozbox-fleet-window-v1";
/// The sealing purpose (the `info` string): a message made for another use cannot be opened as a window.
pub const WINDOW_PURPOSE: &str = "fleet_window";
/// The longest a window may be open, whatever it says (the change role's own maximum session).
pub const MAX_WINDOW_MS: u64 = 3_600_000;
/// A read session is renewed when less than this is left.
const READ_RENEW_MS: u64 = 120_000;

// ---------------------------------------------------------------------------------------------------------------------------
// credentials

/// A short-lived cloud session. Memory only; the secret parts zeroize on drop; never printed. It is serialized only to be
/// sealed to the holder or written to the apply unit's standard input.
#[derive(Clone, Deserialize, Serialize)]
#[serde(from = "CredsWire", into = "CredsWire")]
pub struct SessionCreds {
    pub access_key_id: String,
    secret_access_key: Zeroizing<String>,
    session_token: Zeroizing<String>,
    /// When the cloud ends it, in Unix milliseconds.
    pub expires_at_ms: u64,
}

#[derive(Deserialize, Serialize, Zeroize)]
#[zeroize(drop)]
struct CredsWire {
    access_key_id: String,
    secret_access_key: String,
    session_token: String,
    expires_at_ms: u64,
}

impl From<CredsWire> for SessionCreds {
    fn from(w: CredsWire) -> Self {
        SessionCreds::new(
            &w.access_key_id,
            &w.secret_access_key,
            &w.session_token,
            w.expires_at_ms,
        )
    }
}

impl From<SessionCreds> for CredsWire {
    fn from(c: SessionCreds) -> Self {
        CredsWire {
            access_key_id: c.access_key_id.clone(),
            secret_access_key: c.secret().to_string(),
            session_token: c.token().to_string(),
            expires_at_ms: c.expires_at_ms,
        }
    }
}

impl SessionCreds {
    pub fn new(access_key_id: &str, secret: &str, token: &str, expires_at_ms: u64) -> Self {
        SessionCreds {
            access_key_id: access_key_id.into(),
            secret_access_key: Zeroizing::new(secret.into()),
            session_token: Zeroizing::new(token.into()),
            expires_at_ms,
        }
    }

    pub fn secret(&self) -> &str {
        &self.secret_access_key
    }

    pub fn token(&self) -> &str {
        &self.session_token
    }

    /// The environment a cloud CLI reads. Only for a child's [`CommandSpec`] (whose values are never logged).
    pub fn env(&self) -> Vec<(String, String)> {
        vec![
            ("AWS_ACCESS_KEY_ID".into(), self.access_key_id.clone()),
            ("AWS_SECRET_ACCESS_KEY".into(), self.secret().to_string()),
            ("AWS_SESSION_TOKEN".into(), self.token().to_string()),
        ]
    }

    /// Parse `aws sts assume-role --output json`.
    pub fn from_sts_json(text: &str) -> Result<SessionCreds, String> {
        let v: Value = serde_json::from_str(text).map_err(|_| "the cloud's answer is not JSON")?;
        let c = &v["Credentials"];
        let f = |k: &str| c[k].as_str().filter(|s| !s.is_empty());
        let (Some(a), Some(s), Some(t), Some(e)) = (
            f("AccessKeyId"),
            f("SecretAccessKey"),
            f("SessionToken"),
            f("Expiration"),
        ) else {
            return Err("the cloud's answer carries no session".into());
        };
        let expires = parse_rfc3339_ms(e).ok_or("the session's expiry is not a time")?;
        Ok(SessionCreds::new(a, s, t, expires))
    }
}

impl std::fmt::Debug for SessionCreds {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "SessionCreds(<redacted>, expires {})",
            self.expires_at_ms
        )
    }
}

/// `2026-11-17T08:00:00Z` (or with fractional seconds, or `+00:00`) as Unix milliseconds.
pub fn parse_rfc3339_ms(s: &str) -> Option<u64> {
    let s = s.trim();
    let (date, rest) = s.split_once('T')?;
    let mut d = date.split('-');
    let (y, m, dd): (i64, i64, i64) = (
        d.next()?.parse().ok()?,
        d.next()?.parse().ok()?,
        d.next()?.parse().ok()?,
    );
    let time = rest
        .trim_end_matches('Z')
        .split(['+', '-'])
        .next()
        .unwrap_or("");
    let mut tp = time.split(':');
    let (hh, mm): (u64, u64) = (tp.next()?.parse().ok()?, tp.next()?.parse().ok()?);
    let sec_text = tp.next()?;
    let (sec, frac) = sec_text.split_once('.').unwrap_or((sec_text, "0"));
    let sec: u64 = sec.parse().ok()?;
    let ms: u64 = format!("{frac:0<3}").get(..3)?.parse().ok()?;
    // days from civil (Howard Hinnant)
    let yy = if m <= 2 { y - 1 } else { y };
    let era = yy.div_euclid(400);
    let yoe = yy.rem_euclid(400);
    let doy = (153 * (if m > 2 { m - 3 } else { m + 9 }) + 2) / 5 + dd - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    let days = era * 146_097 + doe - 719_468;
    let days = u64::try_from(days).ok()?;
    Some(((days * 86_400 + hh * 3600 + mm * 60 + sec) * 1000) + ms)
}

/// Where the holder gets its read session. The real one asks the cloud CLI; a test gives a fixed one.
pub trait ReadSessionSource: Send + Sync {
    fn assume_read(&self, now_ms: u64) -> Result<SessionCreds, String>;
}

/// `aws sts assume-role` for `obx-fleet-read`, run by the holder's own user (the cloud CLI reads the instance credentials from
/// the metadata service itself; this user alone passes the guard). 15 minutes, `SourceIdentity` set.
pub struct AwsCliReadSource<'a> {
    pub runner: &'a dyn CommandRunner,
    pub role_arn: String,
    pub box_name: String,
}

impl ReadSessionSource for AwsCliReadSource<'_> {
    fn assume_read(&self, _now_ms: u64) -> Result<SessionCreds, String> {
        let cmd = CommandSpec::new("aws").args([
            "sts".to_string(),
            "assume-role".into(),
            "--role-arn".into(),
            self.role_arn.clone(),
            "--role-session-name".into(),
            format!("read-{}", self.box_name),
            "--source-identity".into(),
            format!("ozbox-holder-{}", self.box_name),
            "--duration-seconds".into(),
            "900".into(),
            "--output".into(),
            "json".into(),
        ]);
        let out = self
            .runner
            .run(&cmd)
            .map_err(|_| "the cloud CLI could not be run".to_string())?;
        if out.status != Some(0) {
            // stderr can name the role, never a credential; still not repeated
            return Err("the cloud refused the read session".into());
        }
        SessionCreds::from_sts_json(&out.stdout)
    }
}

// ---------------------------------------------------------------------------------------------------------------------------
// the window the owner's computer makes

/// What the owner's computer signs about a window, so `main` cannot relabel one (the session inside is the cloud's own proof).
pub fn window_message(
    box_id: &str,
    store_id: &str,
    plan_id: &str,
    plan_hash_hex: &str,
    window_box: &str,
    expires_at_ms: u64,
) -> String {
    format!(
        "{WINDOW_TAG}\n{box_id}\n{store_id}\n{plan_id}\n{plan_hash_hex}\n{window_box}\n{expires_at_ms}"
    )
}

/// The sealed payload: the window's metadata, the owner's signature over it, and the session.
#[derive(Deserialize, Serialize)]
pub struct WindowPayload {
    pub plan_id: String,
    pub plan_hash: String,
    pub window_box: String,
    pub expires_at_ms: u64,
    pub signature: String,
    pub session: SessionCreds,
}

/// The authenticated data of a sealed window: the box, the store, the plan and its hash. A window cannot be moved to another
/// box, store or plan.
pub fn window_aad(box_id: &str, store_id: &str, plan_id: &str, plan_hash_hex: &str) -> Vec<u8> {
    ozbox_seal::aad(&[box_id, store_id, plan_id, plan_hash_hex])
}

/// The owner's computer: seal a window to the holder's pinned public key. `sign` signs [`window_message`] with the owner's
/// approval key.
pub fn seal_window(
    holder_public: &[u8; 32],
    box_id: &str,
    store_id: &str,
    payload: &WindowPayload,
) -> Result<(Vec<u8>, Vec<u8>), String> {
    let mut plain = serde_json::to_vec(payload).map_err(|_| "the window cannot be written")?;
    let r = ozbox_seal::seal(
        holder_public,
        &ozbox_seal::info(WINDOW_PURPOSE, box_id),
        &window_aad(box_id, store_id, &payload.plan_id, &payload.plan_hash),
        &plain,
    )
    .map_err(|e| e.to_string());
    plain.zeroize();
    r
}

struct Window {
    plan_hash: String,
    window_box: String,
    expires_at_ms: u64,
    session: SessionCreds,
}

// ---------------------------------------------------------------------------------------------------------------------------
// the durable spent ledger

/// Plan ids that were used up. One id a line, appended and fsynced BEFORE the apply starts: if the write fails the apply does
/// not start (fail closed), and a crash after it never allows a second apply of the same plan. Not secret.
pub struct SpentLedger {
    path: PathBuf,
    ids: HashSet<String>,
}

impl SpentLedger {
    pub fn open(path: &Path) -> Result<SpentLedger, String> {
        let ids = match std::fs::read_to_string(path) {
            Ok(text) => text
                .lines()
                .filter(|l| !l.is_empty())
                .map(str::to_string)
                .collect(),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => HashSet::new(),
            Err(_) => return Err("the spent-plan ledger cannot be read".into()),
        };
        Ok(SpentLedger {
            path: path.to_path_buf(),
            ids,
        })
    }

    pub fn contains(&self, id: &str) -> bool {
        self.ids.contains(id)
    }

    /// Record a plan id as spent. `Ok(false)` if it already was; `Err` if it could not be made durable.
    pub fn spend(&mut self, id: &str) -> Result<bool, String> {
        if self.ids.contains(id) {
            return Ok(false);
        }
        if id.is_empty() || id.contains(['\n', '\r']) {
            return Err("that plan id cannot be recorded".into());
        }
        let mut f = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.path)
            .map_err(|_| "the spent-plan ledger cannot be written".to_string())?;
        f.write_all(format!("{id}\n").as_bytes())
            .and_then(|()| f.sync_all())
            .map_err(|_| "the spent-plan ledger cannot be written".to_string())?;
        self.ids.insert(id.to_string());
        Ok(true)
    }
}

// ---------------------------------------------------------------------------------------------------------------------------
// the holder

/// Why the holder said no: a stable code and a sentence. Never a credential, a signature or an argument.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HolderRefusal {
    pub code: &'static str,
    pub message: String,
}

fn no(code: &'static str, key: &str) -> HolderRefusal {
    HolderRefusal {
        code,
        message: t(key, &[]),
    }
}

/// What the apply unit is handed, once.
pub struct ApplyTicket {
    pub plan_id: String,
    pub plan: Plan,
    pub person: String,
    pub session: SessionCreds,
}

impl std::fmt::Debug for ApplyTicket {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "ApplyTicket(plan {})", self.plan_id)
    }
}

pub struct HolderConfig {
    pub box_id: String,
    pub store_id: String,
    /// The box this holder runs on (never changed from its own dashboard).
    pub this_box: String,
    /// The owner's computer's approval key (Ed25519, hex), pinned once. It signs windows and approver sets.
    pub laptop_public_hex: String,
    /// The holder's own folder: the spent ledger and the accepted approver set.
    pub dir: PathBuf,
}

pub struct Holder {
    cfg: HolderConfig,
    key: ServiceKey,
    ledger: SpentLedger,
    approvers: Option<ApproverSet>,
    windows: HashMap<String, Window>,
    counters: HashMap<String, u32>,
    read: Option<SessionCreds>,
    source: Box<dyn ReadSessionSource>,
}

impl std::fmt::Debug for Holder {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Holder")
            .field("box", &self.cfg.this_box)
            .field("windows", &self.windows.len())
            .finish_non_exhaustive()
    }
}

fn verify_laptop_sig(public_hex: &str, message: &str, sig_hex: &str) -> bool {
    crate::approval_key::verify(public_hex, message, sig_hex)
}

impl Holder {
    pub fn new(
        cfg: HolderConfig,
        key: ServiceKey,
        source: Box<dyn ReadSessionSource>,
    ) -> Result<Holder, String> {
        std::fs::create_dir_all(&cfg.dir).map_err(|_| "the holder's folder cannot be made")?;
        let ledger = SpentLedger::open(&cfg.dir.join("spent"))?;
        let mut h = Holder {
            cfg,
            key,
            ledger,
            approvers: None,
            windows: HashMap::new(),
            counters: HashMap::new(),
            read: None,
            source,
        };
        // the set accepted before a restart is read again and checked again, never taken on trust from the file
        if let Ok(text) = std::fs::read_to_string(h.cfg.dir.join("approvers.json")) {
            if let Ok(signed) = serde_json::from_str::<SignedApproverSet>(&text) {
                if let Ok(set) =
                    signed.verify(&h.cfg.laptop_public_hex, &h.cfg.box_id, &h.cfg.store_id)
                {
                    h.approvers = Some(set);
                }
            }
        }
        Ok(h)
    }

    /// The key the owner's computer pins and seals windows to.
    pub fn public_key(&self) -> [u8; 32] {
        self.key.public()
    }

    /// Take a newer approver set. Never an older or equal one (a rollback to a list that still holds a removed passkey).
    pub fn accept_approvers(&mut self, signed: &SignedApproverSet) -> Result<u64, HolderRefusal> {
        let set = signed
            .verify(
                &self.cfg.laptop_public_hex,
                &self.cfg.box_id,
                &self.cfg.store_id,
            )
            .map_err(|_| no("approvers_refused", "fleet.holder_approvers_refused"))?;
        if self
            .approvers
            .as_ref()
            .is_some_and(|have| set.version <= have.version)
        {
            return Err(no("approvers_old", "fleet.holder_approvers_old"));
        }
        let text = serde_json::to_string(signed)
            .map_err(|_| no("approvers_refused", "fleet.holder_approvers_refused"))?;
        let tmp = self.cfg.dir.join("approvers.json.tmp");
        std::fs::write(&tmp, text)
            .and_then(|()| std::fs::rename(&tmp, self.cfg.dir.join("approvers.json")))
            .map_err(|_| no("holder_storage", "fleet.holder_storage"))?;
        let v = set.version;
        self.approvers = Some(set);
        Ok(v)
    }

    /// Drop every window that has ended (its session is zeroized as it goes).
    pub fn sweep(&mut self, now_ms: u64) {
        self.windows.retain(|_, w| w.expires_at_ms > now_ms);
    }

    /// Take a window the owner's computer sealed. Opens it, checks the owner's signature over its metadata, and keeps the
    /// session in memory only.
    pub fn receive_window(
        &mut self,
        plan_id: &str,
        plan_hash_hex: &str,
        enc: &[u8],
        ct: &[u8],
        now_ms: u64,
    ) -> Result<(), HolderRefusal> {
        self.sweep(now_ms);
        let bad = || no("window_refused", "fleet.holder_window_refused");
        let plain = self
            .key
            .open(
                &ozbox_seal::info(WINDOW_PURPOSE, &self.cfg.box_id),
                &window_aad(&self.cfg.box_id, &self.cfg.store_id, plan_id, plan_hash_hex),
                enc,
                ct,
            )
            .map_err(|_| bad())?;
        let p: WindowPayload = serde_json::from_slice(&plain).map_err(|_| bad())?;
        if p.plan_id != plan_id || p.plan_hash != plan_hash_hex {
            return Err(bad());
        }
        let msg = window_message(
            &self.cfg.box_id,
            &self.cfg.store_id,
            &p.plan_id,
            &p.plan_hash,
            &p.window_box,
            p.expires_at_ms,
        );
        if !verify_laptop_sig(&self.cfg.laptop_public_hex, &msg, &p.signature) {
            return Err(bad());
        }
        if p.expires_at_ms <= now_ms {
            return Err(no("window_expired", "fleet.window_expired"));
        }
        // whatever the message says, a window is never open longer than the role's own maximum session
        if p.expires_at_ms > now_ms + MAX_WINDOW_MS || p.session.expires_at_ms <= now_ms {
            return Err(bad());
        }
        if self.ledger.contains(plan_id) {
            return Err(no("plan_spent", "fleet.plan_spent"));
        }
        self.windows.insert(
            plan_id.to_string(),
            Window {
                plan_hash: p.plan_hash.clone(),
                window_box: p.window_box.clone(),
                expires_at_ms: p.expires_at_ms,
                session: p.session.clone(),
            },
        );
        Ok(())
    }

    pub fn window_for(&self, plan_id: &str, now_ms: u64) -> Option<WindowStatus> {
        self.windows
            .get(plan_id)
            .filter(|w| w.expires_at_ms > now_ms)
            .map(|w| WindowStatus {
                session_name: format!("plan-{plan_id}"),
                expires_at_ms: w.expires_at_ms,
            })
    }

    pub fn is_spent(&self, plan_id: &str) -> bool {
        self.ledger.contains(plan_id)
    }

    /// The read session, renewed when it is about to end.
    pub fn read_session(&mut self, now_ms: u64) -> Result<SessionCreds, HolderRefusal> {
        if let Some(s) = &self.read {
            if s.expires_at_ms > now_ms + READ_RENEW_MS {
                return Ok(s.clone());
            }
        }
        let s = self
            .source
            .assume_read(now_ms)
            .map_err(|_| no("read_session", "fleet.holder_read_failed"))?;
        self.read = Some(s.clone());
        Ok(s)
    }

    /// Everything that must hold before a window is used. On success the plan id is spent (durably), the window is taken out
    /// (a window is used once), and the ticket carries the change session to the apply unit.
    pub fn authorize_apply(
        &mut self,
        plan_id: &str,
        plan: &Plan,
        evidence: &PasskeyEvidence,
        now_ms: u64,
    ) -> Result<ApplyTicket, HolderRefusal> {
        self.sweep(now_ms);
        if let Err(r) = operation_refusal(&plan.operation, &self.cfg.this_box) {
            return Err(HolderRefusal {
                code: r.code,
                message: r.message,
            });
        }
        if self.ledger.contains(plan_id) {
            return Err(no("fleet_plan_spent", "fleet.plan_spent"));
        }
        let hash = plan_hash(plan);
        let hash_hex = ozbox_core::audit::hex(&hash);
        let w = self
            .windows
            .get(plan_id)
            .ok_or_else(|| no("change_window_required", "fleet.window_required"))?;
        // a window opened for this plan id but another plan's content, or another box, is no window for this plan
        if w.plan_hash != hash_hex || w.window_box != plan.operation.box_name().as_str() {
            return Err(no("change_window_required", "fleet.window_required"));
        }
        let set = self
            .approvers
            .as_ref()
            .ok_or_else(|| no("fleet_passkey_required", "fleet.holder_no_approvers"))?;
        let ch = challenge(&self.cfg.box_id, &self.cfg.store_id, plan_id, &hash);
        let ok = set
            .check_assertion(&ch, evidence)
            .map_err(|_| no("fleet_passkey_required", "fleet.passkey_required"))?;
        // an authenticator's counter never goes back (a cloned key); a key that keeps no counter stays at zero
        let last = self.counters.get(&ok.credential_id).copied().unwrap_or(0);
        if (ok.counter != 0 || last != 0) && ok.counter <= last {
            return Err(no("fleet_passkey_required", "fleet.passkey_required"));
        }
        // fail closed: no durable record, no apply
        match self.ledger.spend(plan_id) {
            Ok(true) => {}
            Ok(false) => return Err(no("fleet_plan_spent", "fleet.plan_spent")),
            Err(_) => return Err(no("holder_storage", "fleet.holder_storage")),
        }
        self.counters.insert(ok.credential_id.clone(), ok.counter);
        let w = self
            .windows
            .remove(plan_id)
            .ok_or_else(|| no("change_window_required", "fleet.window_required"))?;
        Ok(ApplyTicket {
            plan_id: plan_id.to_string(),
            plan: plan.clone(),
            person: ok.person,
            session: w.session.clone(),
        })
    }
}

// ---------------------------------------------------------------------------------------------------------------------------
// the apply unit

/// What runs a plan with a change session. The real one is a transient uid; a test uses the fake provider.
pub trait ApplyUnit: Send + Sync {
    fn run(&self, ticket: ApplyTicket) -> Result<Value, String>;
}

/// The input of the apply process, on its standard input. Never an argument, a variable or a file.
#[derive(Serialize, Deserialize)]
pub struct ApplyInput {
    pub plan: Plan,
    pub session: SessionCreds,
    pub region: Option<String>,
}

/// Runs the apply as `ozbox fleet apply-unit` under a transient uid of its own, with the input on its standard input.
pub struct ProcessApplyUnit<'a> {
    pub runner: &'a dyn CommandRunner,
    pub uid: String,
    pub program: String,
    pub region: Option<String>,
}

impl ApplyUnit for ProcessApplyUnit<'_> {
    fn run(&self, ticket: ApplyTicket) -> Result<Value, String> {
        let input = ApplyInput {
            plan: ticket.plan,
            session: ticket.session,
            region: self.region.clone(),
        };
        let mut body = serde_json::to_vec(&input).map_err(|_| "the apply cannot be started")?;
        let mut cmd = CommandSpec::new("systemd-run").args([
            "--quiet".to_string(),
            "--wait".into(),
            "--pipe".into(),
            format!("--uid={}", self.uid),
            "--property=PrivateTmp=yes".into(),
            "--property=NoNewPrivileges=yes".into(),
            self.program.clone(),
            "fleet".into(),
            "apply-unit".into(),
        ]);
        cmd.stdin = Some(body.clone());
        body.zeroize();
        let out = self
            .runner
            .run(&cmd)
            .map_err(|_| "the apply could not be run".to_string())?;
        if out.status != Some(0) {
            return Err("the apply did not finish".into());
        }
        serde_json::from_str(&out.stdout).map_err(|_| "the apply's answer is not readable".into())
    }
}

/// Runs a command with a session's variables added to every call: how the apply unit gives a provider its credentials without
/// the provider knowing.
pub struct SessionEnvRunner<'a> {
    pub inner: &'a dyn CommandRunner,
    pub session: &'a SessionCreds,
}

impl CommandRunner for SessionEnvRunner<'_> {
    fn run(&self, cmd: &CommandSpec) -> ozbox_core::Result<ozbox_core::Output> {
        let mut c = cmd.clone();
        for (k, v) in self.session.env() {
            c.env.insert(k, v);
        }
        self.inner.run(&c)
    }
}

/// How the apply unit makes the provider it applies through.
pub type ProviderFactory<'a> = &'a dyn Fn(&ApplyInput) -> Result<Box<dyn Provider>, String>;

/// The apply unit's own work: read the input, apply the plan once through a provider made for it, answer with the result.
pub fn run_apply_unit(stdin: &[u8], make: ProviderFactory<'_>) -> Result<Value, String> {
    let input: ApplyInput =
        serde_json::from_slice(stdin).map_err(|_| "the apply's input is not readable")?;
    let provider = make(&input)?;
    let rec = provider
        .apply(&input.plan)
        .map_err(|e| format!("the change was refused: {e}"))?;
    Ok(json!({ "applied": true, "record": rec }))
}

// ---------------------------------------------------------------------------------------------------------------------------
// the socket: who may ask what

/// The users the holder serves, by the kernel's word. Everyone else, the box user and every agent included, is refused every
/// operation the same way.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Peers {
    /// The dashboard's user: the read session, a window's status and an apply.
    pub dashboard_uid: u32,
    /// The sealed route's user (the secrets service's ingress): windows and approver sets arrive here, sealed.
    pub ingress_uid: u32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Who {
    Dashboard,
    Ingress,
}

fn who(peers: &Peers, uid: Option<u32>) -> Option<Who> {
    let uid = uid?;
    // an uid of 0 (root) is not special: root reaches the holder's key by other means, never by being named here
    if uid == peers.dashboard_uid {
        Some(Who::Dashboard)
    } else if uid == peers.ingress_uid {
        Some(Who::Ingress)
    } else {
        None
    }
}

fn refusal_json(r: &HolderRefusal) -> Value {
    json!({ "ok": false, "code": r.code, "message": r.message })
}

fn unhex(v: &Value) -> Option<Vec<u8>> {
    ozbox_core::approval_subject::from_hex(v.as_str()?)
}

/// One request, from a peer the kernel named. The answer never carries a change session. (The read session goes only to the
/// dashboard, by design: it reads and changes nothing.)
pub fn handle(
    h: &mut Holder,
    peers: &Peers,
    peer_uid: Option<u32>,
    unit: &dyn ApplyUnit,
    req: &Value,
    now_ms: u64,
) -> Value {
    let denied = || refusal_json(&no("not_you", "fleet.holder_not_you"));
    let Some(who) = who(peers, peer_uid) else {
        return denied();
    };
    let op = req["op"].as_str().unwrap_or("");
    match (op, who) {
        ("read_session", Who::Dashboard) => match h.read_session(now_ms) {
            Ok(s) => json!({
                "ok": true,
                "access_key_id": s.access_key_id,
                "secret_access_key": s.secret(),
                "session_token": s.token(),
                "expires_at_ms": s.expires_at_ms,
            }),
            Err(r) => refusal_json(&r),
        },
        ("window_for", Who::Dashboard) => {
            let id = req["plan_id"].as_str().unwrap_or("");
            json!({
                "ok": true,
                "spent": h.is_spent(id),
                "window": h.window_for(id, now_ms).map(|w| json!({"session_name": w.session_name, "expires_at_ms": w.expires_at_ms})),
            })
        }
        ("apply", Who::Dashboard) => {
            let id = req["plan_id"].as_str().unwrap_or("");
            let (Ok(plan), Ok(ev)) = (
                serde_json::from_value::<Plan>(req["plan"].clone()),
                serde_json::from_value::<PasskeyEvidence>(req["evidence"].clone()),
            ) else {
                return refusal_json(&no("bad_request", "fleet.holder_bad_request"));
            };
            match h.authorize_apply(id, &plan, &ev, now_ms) {
                Ok(ticket) => {
                    // who confirmed it, for the dashboard's audit chain
                    let person = ticket.person.clone();
                    let ran = unit.run(ticket).map(|r| (person, r));
                    match ran {
                        Ok((person, result)) => {
                            json!({ "ok": true, "result": result, "person": person })
                        }
                        // the plan is spent either way: a half-done change is never retried under the same assertion
                        Err(_) => refusal_json(&no("apply_failed", "fleet.holder_apply_failed")),
                    }
                }
                Err(r) => refusal_json(&r),
            }
        }
        ("window", Who::Ingress) => {
            let (Some(id), Some(hash), Some(enc), Some(ct)) = (
                req["plan_id"].as_str(),
                req["plan_hash"].as_str(),
                unhex(&req["enc"]),
                unhex(&req["ct"]),
            ) else {
                return refusal_json(&no("bad_request", "fleet.holder_bad_request"));
            };
            match h.receive_window(id, hash, &enc, &ct, now_ms) {
                Ok(()) => json!({ "ok": true }),
                Err(r) => refusal_json(&r),
            }
        }
        ("approvers", Who::Ingress) => {
            match serde_json::from_value::<SignedApproverSet>(req["signed"].clone()) {
                Ok(s) => match h.accept_approvers(&s) {
                    Ok(v) => json!({ "ok": true, "version": v }),
                    Err(r) => refusal_json(&r),
                },
                Err(_) => refusal_json(&no("bad_request", "fleet.holder_bad_request")),
            }
        }
        // the right user asking for the wrong thing is refused the same way a stranger is
        _ => denied(),
    }
}

/// The kernel's word for who is on the other end of a connection. Only Linux can say; elsewhere nobody is served.
#[cfg(target_os = "linux")]
pub fn peer_uid(s: &std::os::unix::net::UnixStream) -> Option<u32> {
    rustix::net::sockopt::socket_peercred(s)
        .ok()
        .map(|c| c.uid.as_raw())
}

#[cfg(not(target_os = "linux"))]
pub fn peer_uid(_s: &std::os::unix::net::UnixStream) -> Option<u32> {
    None
}

/// One JSON frame: a four-byte big-endian length, then the JSON. Bounded, so a peer cannot make the holder allocate.
pub const MAX_FRAME: usize = 1 << 20;

pub fn write_frame(w: &mut impl std::io::Write, v: &Value) -> std::io::Result<()> {
    let body =
        serde_json::to_vec(v).map_err(|_| std::io::Error::from(std::io::ErrorKind::InvalidData))?;
    if body.len() > MAX_FRAME {
        return Err(std::io::ErrorKind::InvalidData.into());
    }
    w.write_all(&(body.len() as u32).to_be_bytes())?;
    w.write_all(&body)?;
    w.flush()
}

pub fn read_frame(r: &mut impl std::io::Read) -> std::io::Result<Value> {
    let mut len = [0u8; 4];
    r.read_exact(&mut len)?;
    let n = u32::from_be_bytes(len) as usize;
    if n > MAX_FRAME {
        return Err(std::io::ErrorKind::InvalidData.into());
    }
    let mut body = vec![0u8; n];
    r.read_exact(&mut body)?;
    serde_json::from_slice(&body).map_err(|_| std::io::ErrorKind::InvalidData.into())
}

/// Answer connections on the holder's socket, one at a time (a fleet change is rare and slow; one at a time is also what keeps
/// two applies from overlapping). The peer's user is read before anything is.
pub fn serve(
    h: &mut Holder,
    peers: &Peers,
    unit: &dyn ApplyUnit,
    listener: &std::os::unix::net::UnixListener,
    now: &dyn Fn() -> u64,
    stop: &dyn Fn() -> bool,
) {
    for conn in listener.incoming() {
        if stop() {
            return;
        }
        let Ok(mut s) = conn else { continue };
        let _ = s.set_read_timeout(Some(std::time::Duration::from_secs(5)));
        let uid = peer_uid(&s);
        let reply = match read_frame(&mut s) {
            Ok(req) => handle(h, peers, uid, unit, &req, now()),
            Err(_) => refusal_json(&no("bad_request", "fleet.holder_bad_request")),
        };
        let _ = write_frame(&mut s, &reply);
    }
}

/// The dashboard's side: asks the holder about a window and hands it a plan to apply. It never receives a change session.
pub struct HolderClient {
    pub sock: PathBuf,
}

impl HolderClient {
    fn call(&self, req: &Value) -> Result<Value, String> {
        let mut s = std::os::unix::net::UnixStream::connect(&self.sock)
            .map_err(|_| "the credential holder is not running".to_string())?;
        s.set_read_timeout(Some(std::time::Duration::from_secs(900)))
            .map_err(|_| "the credential holder did not answer".to_string())?;
        write_frame(&mut s, req).map_err(|_| "the credential holder did not answer".to_string())?;
        read_frame(&mut s).map_err(|_| "the credential holder did not answer".to_string())
    }

    /// Apply one plan through the holder, with the passkey assertion the person gave for it.
    pub fn apply(
        &self,
        plan_id: &str,
        plan: &Plan,
        evidence: &PasskeyEvidence,
    ) -> Result<Value, HolderRefusal> {
        let r = self
            .call(&json!({"op": "apply", "plan_id": plan_id, "plan": plan, "evidence": evidence}))
            .map_err(|m| HolderRefusal {
                code: "holder_unreachable",
                message: m,
            })?;
        if r["ok"] == true {
            Ok(r["result"].clone())
        } else {
            Err(HolderRefusal {
                code: "holder_refused",
                message: r["message"].as_str().unwrap_or("").to_string(),
            })
        }
    }
}

impl crate::fleet_gate::FleetCredentials for HolderClient {
    fn window_for(&self, plan_id: &str) -> Option<WindowStatus> {
        let r = self
            .call(&json!({"op": "window_for", "plan_id": plan_id}))
            .ok()?;
        let w = r.get("window")?.as_object()?;
        Some(WindowStatus {
            session_name: w.get("session_name")?.as_str()?.to_string(),
            expires_at_ms: w.get("expires_at_ms")?.as_u64()?,
        })
    }

    fn is_spent(&self, plan_id: &str) -> bool {
        self.call(&json!({"op": "window_for", "plan_id": plan_id}))
            .map(|r| r["spent"] == true)
            .unwrap_or(false)
    }
}

/// The group-and-mode a socket gets: only the holder and the dashboard's group may even open it (the peer check is the wall).
pub const SOCKET_MODE: u32 = 0o660;

#[cfg(test)]
mod tests;
