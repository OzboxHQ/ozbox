//! The issuer's decisions: a box asks, an approver answers, the issuer releases one use sealed to the box's service key.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

use crate::state::StateStore;
use crate::verify::{verify_ed25519, verify_passkey, Assertion};
use crate::{CHALLENGE_TTL_MS, MAX_WINDOW_SECS};

/// How many uses one approval may cover.
pub const MAX_USES: u32 = 10;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Kind {
    /// A WebAuthn passkey (ES256, uncompressed P-256 public key).
    Passkey,
    /// A laptop key (Ed25519). Whether it asks the person (Secure Enclave, a security key) is recorded when it is pinned.
    Laptop,
    /// The offline recovery key (Ed25519).
    Recovery,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Approver {
    pub id: String,
    pub kind: Kind,
    /// Raw public key bytes.
    pub public: Vec<u8>,
    /// For a laptop key: it needs the person present (a Secure Enclave or a security key with user verification). A software
    /// key in the keychain does not, and is refused for Production unless the owner allows it.
    #[serde(default)]
    pub user_presence: bool,
}

/// What the issuer pins about a box when the owner connects it: its store and its service key (public).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BoxPin {
    pub store_id: String,
    pub service_key: [u8; 32],
    /// The AWS principal (the instance role's session) the adapter sees calling for this box. A request or a release by any
    /// other caller is refused, whatever the box id inside it says: one box cannot ask for another's secrets or spend another's
    /// uses. Empty means no caller is allowed (the issuer is not configured for this box yet).
    #[serde(default)]
    pub caller: String,
    /// The secrets this box may ask for: an exact name, or a prefix ending in `/*`. Empty: none. A box that is connected asks
    /// only for what the owner allocated to it.
    #[serde(default)]
    pub allowed: Vec<String>,
    /// What this box is, as the owner classified it (ADR 0042 section 5). **A pin is a worker unless it positively says
    /// `main`**: `None` (an older pin, or one nobody classified) is refused Production exactly like a worker, so a missing
    /// value can never open the door. The class is exactly as trusted as the approver list beside it: both are the owner's
    /// own edit of this config, and enrolment becomes its only writer later. The cost, stated: every pin written before this
    /// field existed (including `main`'s) is refused Production at the issuer until it is classified once.
    #[serde(default)]
    pub class: Option<BoxClass>,
}

/// The owner's classification of a pinned box.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BoxClass {
    /// `main`: may be given Production, through the approval the scope asks for.
    Main,
    /// A worker: never given Production (decision D2).
    Worker,
}

impl BoxPin {
    /// Refused Production as a worker: everything not positively classified `main`.
    fn counts_as_worker(&self) -> bool {
        self.class != Some(BoxClass::Main)
    }

    fn allows(&self, secret: &str) -> bool {
        self.allowed.iter().any(|a| {
            a == secret
                || a.strip_suffix('*')
                    .is_some_and(|p| p.ends_with('/') && secret.starts_with(p))
        })
    }
}

/// How many approvals one run may ask for in all (Amendment 6 section 5, request hygiene): a run that keeps asking is stuck
/// or hostile, and each ask is an approval request a person has to look at.
pub const MAX_REQUESTS_PER_RUN: u32 = 5;

/// How many approvals one box may ask for in an hour, whatever run ids it picks (the box chooses them, so the per-run cap
/// alone does not bound a hostile box).
pub const MAX_REQUESTS_PER_BOX_HOUR: u32 = 20;

/// Everything the issuer is configured with. All of it is public.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Config {
    pub boxes: BTreeMap<String, BoxPin>,
    pub approvers: Vec<Approver>,
    /// The passkeys' relying party and the exact origin of the dashboard they sign in on.
    pub rp_id: String,
    pub origin: String,
    #[serde(default)]
    pub allow_laptop_without_presence: bool,
    /// Origins the owner has established are **not served by the box**: a page the box cannot render. A passkey assertion is
    /// accepted only when `origin` is in this list. The dashboard the box serves is not an approval surface for Production:
    /// root on the box (or the supervisor) renders that page and could show any text above the passkey prompt (
    /// ADR 0042 D1). Default empty: no passkey approves Production until an origin the box does not serve exists, and until
    /// then Production approvals are a laptop key that needs the person present (or the recovery key). Phase 2.
    #[serde(default)]
    pub independent_approval_origins: Vec<String>,
}

/// What an approval covers: one secret version, for one run of one exact command, in one project and environment, at one commit
/// and directory content, on one box, for one caller. Signed as a whole (a change of any field is a different message), and
/// shown to the approver from the issuer's own record, never from anything the box says about it ([`Scope::card`]).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Scope {
    pub box_id: String,
    pub store_id: String,
    pub service_key_fp: String,
    pub project: String,
    pub env: String,
    pub secret: String,
    pub version: String,
    /// SHA-256 of the exact argv, in hex.
    pub argv_digest: String,
    /// The git commit the command runs at (40 or 64 hex characters). A renewal is bound to the commit of the run, so a new
    /// commit is a new approval.
    pub commit: String,
    /// SHA-256, in hex, of the directory's content the command runs in.
    pub dir_digest: String,
    /// The AWS principal the adapter saw. The adapter sets it from the signed call; a value the box sent is overwritten.
    pub caller: String,
    pub run_id: String,
    pub uses: u32,
    pub window_secs: u64,
}

impl Scope {
    /// The bytes an approver signs. Every field, length-prefixed, with the nonce and expiry: nothing the box sends is signed
    /// in place of it, and the box's id, store and key fingerprint are in it, so a signature cannot move to another box.
    pub fn message(&self, request_id: &str, nonce: &str, expires_ms: u64) -> Vec<u8> {
        ozbox_seal::aad(&[
            "ozbox-issuer-challenge/1",
            request_id,
            &self.box_id,
            &self.store_id,
            &self.service_key_fp,
            &self.project,
            &self.env,
            &self.secret,
            &self.version,
            &self.argv_digest,
            &self.commit,
            &self.dir_digest,
            &self.caller,
            &self.run_id,
            &self.uses.to_string(),
            &self.window_secs.to_string(),
            nonce,
            &expires_ms.to_string(),
        ])
    }

    /// What the approver is shown, from the issuer's own record of the request. The page that asks for a passkey or a laptop
    /// signature renders this, and nothing the box supplies: a card drawn by the box could say one thing and ask for a
    /// signature over another. Every field the signature covers is on it.
    pub fn card(&self) -> Vec<(&'static str, String)> {
        vec![
            ("Box", self.box_id.clone()),
            ("Project", self.project.clone()),
            ("Environment", self.env.clone()),
            ("Secret", format!("{} ({})", self.secret, self.version)),
            ("Command (SHA-256)", self.argv_digest.clone()),
            ("Commit", self.commit.clone()),
            ("Directory (SHA-256)", self.dir_digest.clone()),
            ("Asked by", self.caller.clone()),
            ("Run", self.run_id.clone()),
            (
                "Uses",
                format!("{} within {} seconds", self.uses, self.window_secs),
            ),
        ]
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "state", rename_all = "snake_case")]
enum Record {
    Pending {
        scope: Scope,
        nonce: String,
        expires_ms: u64,
    },
    Approved {
        scope: Scope,
        approver: String,
        expires_ms: u64,
        uses_left: u32,
        used: u32,
    },
}

/// What the box is given to relay to the approver.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Challenge {
    pub request_id: String,
    pub nonce: String,
    pub expires_ms: u64,
    /// The message to sign (a passkey signs its SHA-256 as the challenge).
    pub message: Vec<u8>,
}

/// An approver's answer.
pub enum Proof<'a> {
    Signature(&'a [u8]),
    Assertion(Assertion<'a>),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Status {
    Unknown,
    Pending { expires_ms: u64 },
    Approved { expires_ms: u64, uses_left: u32 },
    Expired,
    Spent,
}

/// A sealed release.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Released {
    pub use_no: u32,
    pub enc: Vec<u8>,
    pub ct: Vec<u8>,
}

#[derive(Debug, PartialEq, Eq)]
pub enum Error {
    BadRequest(&'static str),
    UnknownBox,
    StoreMismatch,
    KeyMismatch,
    WrongCaller,
    NotAllocated,
    TooManyRequests,
    NoSuchRequest,
    NotPending,
    NotApproved,
    Expired,
    Spent,
    UnknownApprover,
    WrongKind,
    NoUserPresence,
    OriginServedByBox,
    BadProof(String),
    Busy,
    Audit,
    Reader(String),
    Seal,
    /// Decision D2: a worker box is never given Production in this release.
    ProductionToWorker,
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Error::BadRequest(m) => write!(f, "that request is not valid: {m}"),
            Error::UnknownBox => f.write_str("that box is not connected to this issuer"),
            Error::StoreMismatch => {
                f.write_str("that is not the store this box was connected with")
            }
            Error::KeyMismatch => {
                f.write_str("that is not the service key this box was connected with")
            }
            Error::WrongCaller => f.write_str("that caller is not the one connected for this box"),
            Error::NotAllocated => f.write_str("that secret is not allocated to this box"),
            Error::TooManyRequests => f.write_str("that run has asked for too many approvals"),
            Error::NoSuchRequest => f.write_str("there is no such request"),
            Error::NotPending => f.write_str("that request is not waiting for an answer"),
            Error::NotApproved => f.write_str("that request has not been approved"),
            Error::Expired => f.write_str("that request has expired"),
            Error::Spent => f.write_str("every use of that approval has been spent"),
            Error::UnknownApprover => f.write_str("that approver is not pinned"),
            Error::WrongKind => f.write_str("that proof is not the kind this approver gives"),
            Error::NoUserPresence => f.write_str(
                "that laptop key does not ask the person, so it cannot approve Production",
            ),
            Error::OriginServedByBox => f.write_str(
                "a passkey on a page this box serves cannot approve Production: approve with a laptop key that asks the person",
            ),
            Error::BadProof(why) => write!(f, "that proof was refused ({why})"),
            Error::Busy => f.write_str("another answer arrived first: ask again"),
            Error::Audit => {
                f.write_str("the issuer's own record could not be written, so nothing was done")
            }
            Error::Reader(_) => f.write_str("the secret could not be read"),
            Error::Seal => f.write_str("the release could not be sealed to the box"),
            Error::ProductionToWorker => f.write_str(
                "a worker box, or a box the owner has not classified, is never given a Production value in this release: run the step on `main` with its own approval, or classify main once in the issuer's config (`\"class\": \"main\"` beside the approver list)",
            ),
        }
    }
}

impl std::error::Error for Error {}

/// Reads one secret version with a session that names only that version, for at most `seconds`. The real one assumes a role
/// with a session policy; the issuer's own role cannot read secrets at all.
pub trait SecretReader {
    fn read_one(
        &self,
        secret: &str,
        version: &str,
        seconds: u64,
    ) -> Result<Zeroizing<Vec<u8>>, String>;
}

/// The issuer's own append-only record. Never a value, a code or a signature in `detail`.
pub trait Audit {
    fn record(&self, event: &str, request_id: &str, detail: &str) -> Result<(), String>;
}

pub struct Issuer<'a> {
    pub config: &'a Config,
    pub state: &'a dyn StateStore,
    pub reader: &'a dyn SecretReader,
    pub audit: &'a dyn Audit,
    /// A fresh random identifier (32 hex characters), for requests and nonces.
    pub random: &'a dyn Fn() -> String,
}

fn word_ok(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= 200
        && s.bytes().all(|b| {
            b.is_ascii_alphanumeric()
                || matches!(b, b'-' | b'_' | b'.' | b'/' | b'=' | b'+' | b'@' | b':')
        })
}

impl Issuer<'_> {
    fn load(&self, request_id: &str) -> Result<(u64, Record), Error> {
        let (v, text) = self
            .state
            .get(&format!("req/{request_id}"))
            .ok_or(Error::NoSuchRequest)?;
        serde_json::from_str(&text)
            .map(|r| (v, r))
            .map_err(|_| Error::NoSuchRequest)
    }

    fn audit(&self, event: &str, request_id: &str, detail: &str) -> Result<(), Error> {
        self.audit
            .record(event, request_id, detail)
            .map_err(|_| Error::Audit)
    }

    /// A box asks for an approval. The issuer checks the box, its store and its key against what it pinned, makes the
    /// challenge itself, and keeps it. Nothing is approved here. `caller` is the verified identity of the call, from the
    /// adapter's signature check (as `release` takes it); whatever `scope.caller` the box sent is overwritten by it, so the
    /// scope an approver signs names the principal that actually asked.
    pub fn request(&self, mut scope: Scope, caller: &str, now_ms: u64) -> Result<Challenge, Error> {
        for w in [
            &scope.box_id,
            &scope.store_id,
            &scope.project,
            &scope.env,
            &scope.secret,
            &scope.version,
            &scope.caller,
            &scope.run_id,
        ] {
            if !word_ok(w) {
                return Err(Error::BadRequest(
                    "a name has characters that are not allowed",
                ));
            }
        }
        if scope.argv_digest.len() != 64
            || !scope.argv_digest.bytes().all(|b| b.is_ascii_hexdigit())
        {
            return Err(Error::BadRequest("the command's digest is not a SHA-256"));
        }
        let hex = |h: &str, ok: &[usize]| {
            ok.contains(&h.len()) && h.bytes().all(|b| b.is_ascii_hexdigit())
        };
        if !hex(&scope.commit, &[40, 64]) || !hex(&scope.dir_digest, &[64]) {
            return Err(Error::BadRequest(
                "the commit or the directory's digest is not a hash",
            ));
        }
        if scope.uses == 0 || scope.uses > MAX_USES {
            return Err(Error::BadRequest("the number of uses is out of range"));
        }
        // the window is capped here, so the approver signs the window the issuer will actually give
        scope.window_secs = scope.window_secs.clamp(1, MAX_WINDOW_SECS);
        let pin = self
            .config
            .boxes
            .get(&scope.box_id)
            .ok_or(Error::UnknownBox)?;
        if pin.store_id != scope.store_id {
            return Err(Error::StoreMismatch);
        }
        if ozbox_seal::fingerprint(&pin.service_key) != scope.service_key_fp {
            return Err(Error::KeyMismatch);
        }
        // who is asking: the call's own identity, which must be the one connected for this box
        scope.caller = caller.to_string();
        if !word_ok(&scope.caller) {
            return Err(Error::WrongCaller);
        }
        if pin.caller.is_empty() || pin.caller != caller {
            return Err(Error::WrongCaller);
        }
        // the worker check comes after the caller check, so only the box's own caller can write this audit line or learn that
        // a box is classified as a worker; it still runs before anything is allocated or read
        if pin.counts_as_worker() {
            self.audit(
                "refused-worker",
                "-",
                &format!(
                    "box={} secret={} run={}",
                    scope.box_id, scope.secret, scope.run_id
                ),
            )?;
            return Err(Error::ProductionToWorker);
        }
        if !pin.allows(&scope.secret) {
            return Err(Error::NotAllocated);
        }
        // at most a few asks per run, counted for good
        let ckey = format!("runreq/{}", scope.run_id);
        let (cv, asked) = match self.state.get(&ckey) {
            Some((v, t)) => (Some(v), t.trim().parse::<u32>().unwrap_or(u32::MAX)),
            None => (None, 0),
        };
        if asked >= MAX_REQUESTS_PER_RUN {
            return Err(Error::TooManyRequests);
        }
        // and a cap per box, because the run id is the box's own to choose: a box that mints a new run id for every ask would
        // otherwise never reach the per-run cap. Counted per hour.
        let bkey = format!("boxreq/{}/{}", scope.box_id, now_ms / 3_600_000);
        let (bv, box_asked) = match self.state.get(&bkey) {
            Some((v, t)) => (Some(v), t.trim().parse::<u32>().unwrap_or(u32::MAX)),
            None => (None, 0),
        };
        if box_asked >= MAX_REQUESTS_PER_BOX_HOUR {
            return Err(Error::TooManyRequests);
        }
        self.state
            .put_if(&ckey, cv, &(asked + 1).to_string())
            .map_err(|_| Error::Busy)?;
        self.state
            .put_if(&bkey, bv, &(box_asked + 1).to_string())
            .map_err(|_| Error::Busy)?;
        let (request_id, nonce) = ((self.random)(), (self.random)());
        let expires_ms = now_ms + CHALLENGE_TTL_MS;
        let message = scope.message(&request_id, &nonce, expires_ms);
        self.audit(
            "requested",
            &request_id,
            &format!(
                "box={} secret={} uses={}",
                scope.box_id, scope.secret, scope.uses
            ),
        )?;
        let rec = Record::Pending {
            scope,
            nonce: nonce.clone(),
            expires_ms,
        };
        self.state
            .put_if(
                &format!("req/{request_id}"),
                None,
                &serde_json::to_string(&rec).map_err(|_| Error::Busy)?,
            )
            .map_err(|_| Error::Busy)?;
        Ok(Challenge {
            request_id,
            nonce,
            expires_ms,
            message,
        })
    }

    /// An approver answers. The issuer checks the proof against the key it pinned and the message it made, and records the
    /// approval in its own state. The box is not asked and cannot make an approval.
    pub fn approve(
        &self,
        request_id: &str,
        approver_id: &str,
        proof: Proof<'_>,
        now_ms: u64,
    ) -> Result<(), Error> {
        let (version, rec) = self.load(request_id)?;
        let Record::Pending {
            scope,
            nonce,
            expires_ms,
        } = rec
        else {
            return Err(Error::NotPending);
        };
        if now_ms >= expires_ms {
            return Err(Error::Expired);
        }
        let ap = self
            .config
            .approvers
            .iter()
            .find(|a| a.id == approver_id)
            .ok_or(Error::UnknownApprover)?;
        let message = scope.message(request_id, &nonce, expires_ms);
        let refuse = |why: String| {
            let _ = self.audit(
                "refused",
                request_id,
                &format!("approver={approver_id} why={why}"),
            );
            Error::BadProof(why)
        };
        match (ap.kind, proof) {
            (Kind::Laptop | Kind::Recovery, Proof::Signature(sig)) => {
                if ap.kind == Kind::Laptop
                    && !ap.user_presence
                    && !self.config.allow_laptop_without_presence
                {
                    let _ = self.audit(
                        "refused",
                        request_id,
                        &format!("approver={approver_id} why=no-presence"),
                    );
                    return Err(Error::NoUserPresence);
                }
                if !verify_ed25519(&ap.public, &message, sig) {
                    return Err(refuse("signature".into()));
                }
            }
            (Kind::Passkey, Proof::Assertion(a)) => {
                if !self
                    .config
                    .independent_approval_origins
                    .iter()
                    .any(|o| o == &self.config.origin)
                {
                    let _ = self.audit(
                        "refused",
                        request_id,
                        &format!("approver={approver_id} why=origin-served-by-box"),
                    );
                    return Err(Error::OriginServedByBox);
                }
                let ckey = format!("counter/{approver_id}");
                let (cv, last) = match self.state.get(&ckey) {
                    Some((v, t)) => (Some(v), t.trim().parse().unwrap_or(0)),
                    None => (None, 0),
                };
                let counter = verify_passkey(
                    &ap.public,
                    &self.config.rp_id,
                    &self.config.origin,
                    &message,
                    &a,
                    last,
                )
                .map_err(|r| refuse(format!("{r:?}").to_lowercase()))?;
                self.state
                    .put_if(&ckey, cv, &counter.to_string())
                    .map_err(|_| Error::Busy)?;
            }
            _ => return Err(Error::WrongKind),
        }
        let approved = Record::Approved {
            expires_ms: now_ms + scope.window_secs * 1000,
            uses_left: scope.uses,
            used: 0,
            scope,
            approver: approver_id.to_string(),
        };
        self.audit("approved", request_id, &format!("approver={approver_id}"))?;
        self.state
            .put_if(
                &format!("req/{request_id}"),
                Some(version),
                &serde_json::to_string(&approved).map_err(|_| Error::Busy)?,
            )
            .map_err(|_| Error::Busy)?;
        Ok(())
    }

    /// What to show the approver for a request that is waiting, from the issuer's own record of it. Nothing the box says about
    /// the request is in it, and the approval page must render this (and the laptop client show the same), never a card the
    /// box drew.
    pub fn card(
        &self,
        request_id: &str,
        now_ms: u64,
    ) -> Result<Vec<(&'static str, String)>, Error> {
        match self.load(request_id)?.1 {
            Record::Pending {
                scope, expires_ms, ..
            } => {
                if now_ms >= expires_ms {
                    Err(Error::Expired)
                } else {
                    Ok(scope.card())
                }
            }
            Record::Approved { .. } => Err(Error::NotPending),
        }
    }

    pub fn status(&self, request_id: &str, now_ms: u64) -> Status {
        match self.load(request_id) {
            Err(_) => Status::Unknown,
            Ok((_, Record::Pending { expires_ms, .. })) if now_ms < expires_ms => {
                Status::Pending { expires_ms }
            }
            Ok((_, Record::Pending { .. })) => Status::Expired,
            Ok((_, Record::Approved { expires_ms, .. })) if now_ms >= expires_ms => Status::Expired,
            Ok((_, Record::Approved { uses_left: 0, .. })) => Status::Spent,
            Ok((
                _,
                Record::Approved {
                    expires_ms,
                    uses_left,
                    ..
                },
            )) => Status::Approved {
                expires_ms,
                uses_left,
            },
        }
    }

    /// Release one use: check the approval and the window, spend a use with a compare-and-set (so two releases cannot spend
    /// the same one), read the one secret with a session that names only it, and seal the value to the box's service key.
    /// The issuer's record of the release is written first, and a release it cannot record does not happen.
    pub fn release(&self, request_id: &str, caller: &str, now_ms: u64) -> Result<Released, Error> {
        let (version, rec) = self.load(request_id)?;
        let Record::Approved {
            scope,
            approver,
            expires_ms,
            uses_left,
            used,
        } = rec
        else {
            return Err(Error::NotApproved);
        };
        // only the caller that asked can release: another box's role cannot spend this box's uses (the value is sealed to this
        // box's key, so it could not read it, but it could use the approval up)
        if caller != scope.caller {
            return Err(Error::WrongCaller);
        }
        if now_ms >= expires_ms {
            return Err(Error::Expired);
        }
        if uses_left == 0 {
            return Err(Error::Spent);
        }
        let pin = self
            .config
            .boxes
            .get(&scope.box_id)
            .ok_or(Error::UnknownBox)?;
        if pin.counts_as_worker() {
            // an approval filed before the box was marked a worker is not honoured for it either
            self.audit(
                "refused-worker",
                request_id,
                &format!("box={} secret={}", scope.box_id, scope.secret),
            )?;
            return Err(Error::ProductionToWorker);
        }
        let use_no = used + 1;
        self.audit(
            "release",
            request_id,
            &format!(
                "box={} secret={} use={use_no} approver={approver}",
                scope.box_id, scope.secret
            ),
        )?;
        let spent = Record::Approved {
            scope: scope.clone(),
            approver,
            expires_ms,
            uses_left: uses_left - 1,
            used: use_no,
        };
        self.state
            .put_if(
                &format!("req/{request_id}"),
                Some(version),
                &serde_json::to_string(&spent).map_err(|_| Error::Busy)?,
            )
            .map_err(|_| Error::Busy)?;
        // a use that fails after this point stays spent: the safe side
        let value = self
            .reader
            .read_one(&scope.secret, &scope.version, MAX_WINDOW_SECS)
            .map_err(|e| {
                let _ = self.audit("release.failed", request_id, "read");
                Error::Reader(e)
            })?;
        let (enc, ct) = ozbox_seal::seal(
            &pin.service_key,
            &release_info(&scope.box_id),
            &release_aad(&scope, request_id, use_no),
            &value,
        )
        .map_err(|_| Error::Seal)?;
        Ok(Released { use_no, enc, ct })
    }
}

/// The `info` of a release: the purpose and the box.
pub fn release_info(box_id: &str) -> Vec<u8> {
    ozbox_seal::info("release", box_id)
}

/// The authenticated data of a release: the box, store, key, project, environment, secret, version, commit, directory, run,
/// request and which use it is.
pub fn release_aad(scope: &Scope, request_id: &str, use_no: u32) -> Vec<u8> {
    ozbox_seal::aad(&[
        "release/2",
        &scope.box_id,
        &scope.store_id,
        &scope.service_key_fp,
        &scope.project,
        &scope.env,
        &scope.secret,
        &scope.version,
        &scope.commit,
        &scope.dir_digest,
        &scope.run_id,
        request_id,
        &use_no.to_string(),
    ])
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use crate::state::MemoryState;
    use crate::verify::tests::{assert_for, ed25519, passkey};
    use std::cell::{Cell, RefCell};

    const NOW: u64 = 1_800_000_000_000;
    const SENTINEL: &[u8] = b"SENTINEL-prod-0123456789abcdef";
    const CALLER: &str = "arn:aws:sts::123456789012:assumed-role/ozbox-dev-role/i-0abc";

    struct Reader {
        calls: RefCell<Vec<(String, String, u64)>>,
        fail: Cell<bool>,
    }
    impl SecretReader for Reader {
        fn read_one(&self, s: &str, v: &str, secs: u64) -> Result<Zeroizing<Vec<u8>>, String> {
            self.calls.borrow_mut().push((s.into(), v.into(), secs));
            if self.fail.get() {
                Err("denied".into())
            } else {
                Ok(Zeroizing::new(SENTINEL.to_vec()))
            }
        }
    }
    struct Log {
        lines: RefCell<Vec<String>>,
        fail: Cell<bool>,
    }
    impl Audit for Log {
        fn record(&self, e: &str, r: &str, d: &str) -> Result<(), String> {
            if self.fail.get() {
                return Err("full".into());
            }
            self.lines.borrow_mut().push(format!("{e} {r} {d}"));
            Ok(())
        }
    }

    struct World {
        cfg: Config,
        state: MemoryState,
        reader: Reader,
        log: Log,
        key: ozbox_seal::ServiceKey,
        laptop: ring::signature::Ed25519KeyPair,
        recovery: ring::signature::Ed25519KeyPair,
        pk: crate::verify::tests::Passkey,
        n: Cell<u64>,
    }

    fn world() -> World {
        let key = ozbox_seal::ServiceKey::generate().unwrap();
        let (laptop, lpub) = ed25519();
        let (recovery, rpub) = ed25519();
        let pk = passkey();
        let mut cfg = Config {
            rp_id: "dash.example.com".into(),
            origin: "https://dash.example.com".into(),
            // most tests exercise the passkey path itself, so the origin counts as independent here; the tests of M5 clear it
            independent_approval_origins: vec!["https://dash.example.com".into()],
            ..Config::default()
        };
        cfg.boxes.insert(
            "dev".into(),
            BoxPin {
                store_id: "store-1".into(),
                service_key: key.public(),
                caller: CALLER.into(),
                allowed: vec!["prod/*".into()],
                class: Some(BoxClass::Main),
            },
        );
        cfg.approvers = vec![
            Approver {
                id: "mac".into(),
                kind: Kind::Laptop,
                public: lpub,
                user_presence: true,
            },
            Approver {
                id: "soft".into(),
                kind: Kind::Laptop,
                public: ed25519().1,
                user_presence: false,
            },
            Approver {
                id: "rec".into(),
                kind: Kind::Recovery,
                public: rpub,
                user_presence: false,
            },
            Approver {
                id: "phone".into(),
                kind: Kind::Passkey,
                public: pk.public.clone(),
                user_presence: true,
            },
        ];
        World {
            cfg,
            state: MemoryState::default(),
            reader: Reader {
                calls: RefCell::new(vec![]),
                fail: Cell::new(false),
            },
            log: Log {
                lines: RefCell::new(vec![]),
                fail: Cell::new(false),
            },
            key,
            laptop,
            recovery,
            pk,
            n: Cell::new(0),
        }
    }

    impl World {
        fn issuer<'a>(&'a self, rand: &'a dyn Fn() -> String) -> Issuer<'a> {
            Issuer {
                config: &self.cfg,
                state: &self.state,
                reader: &self.reader,
                audit: &self.log,
                random: rand,
            }
        }
        fn rand(&self) -> impl Fn() -> String + '_ {
            move || {
                self.n.set(self.n.get() + 1);
                format!("{:032x}", self.n.get())
            }
        }
        fn scope(&self) -> Scope {
            Scope {
                box_id: "dev".into(),
                store_id: "store-1".into(),
                service_key_fp: self.key.fingerprint(),
                project: "app".into(),
                env: "production".into(),
                secret: "prod/db-url".into(),
                version: "v3".into(),
                argv_digest: "a".repeat(64),
                commit: "c".repeat(40),
                dir_digest: "d".repeat(64),
                caller: CALLER.into(),
                run_id: "run-1".into(),
                uses: 2,
                window_secs: 600,
            }
        }
    }

    #[test]
    fn a_request_is_approved_by_a_laptop_key_and_released_sealed_to_the_boxs_key() {
        let w = world();
        let r = w.rand();
        let i = w.issuer(&r);
        let ch = i.request(w.scope(), CALLER, NOW).unwrap();
        assert_eq!(
            i.status(&ch.request_id, NOW),
            Status::Pending {
                expires_ms: ch.expires_ms
            }
        );
        i.approve(
            &ch.request_id,
            "mac",
            Proof::Signature(w.laptop.sign(&ch.message).as_ref()),
            NOW + 1000,
        )
        .unwrap();
        assert_eq!(
            i.status(&ch.request_id, NOW + 1000),
            Status::Approved {
                expires_ms: NOW + 1000 + 600_000,
                uses_left: 2
            }
        );
        let rel = i.release(&ch.request_id, CALLER, NOW + 2000).unwrap();
        assert_eq!(rel.use_no, 1);
        // only ciphertext leaves; the box's key opens it with the release's own labels
        assert!(!rel.ct.windows(SENTINEL.len()).any(|x| x == SENTINEL));
        let plain = w
            .key
            .open(
                &release_info("dev"),
                &release_aad(&w.scope(), &ch.request_id, 1),
                &rel.enc,
                &rel.ct,
            )
            .unwrap();
        assert_eq!(&plain[..], SENTINEL);
        // another use number, another box or another request cannot open it
        assert!(w
            .key
            .open(
                &release_info("dev"),
                &release_aad(&w.scope(), &ch.request_id, 2),
                &rel.enc,
                &rel.ct
            )
            .is_err());
        assert!(w
            .key
            .open(
                &release_info("other"),
                &release_aad(&w.scope(), &ch.request_id, 1),
                &rel.enc,
                &rel.ct
            )
            .is_err());
        // the reader was asked for one secret and one version, for at most 900 seconds
        assert_eq!(
            w.reader.calls.borrow().as_slice(),
            [("prod/db-url".to_string(), "v3".to_string(), 900)]
        );
        // the record names the steps, and never a value
        let log = w.log.lines.borrow().join("\n");
        assert!(log.contains("requested") && log.contains("approved") && log.contains("release"));
        assert!(!log.contains("SENTINEL"));
    }

    #[test]
    fn uses_are_counted_per_use_and_the_window_ends() {
        let w = world();
        let r = w.rand();
        let i = w.issuer(&r);
        let ch = i.request(w.scope(), CALLER, NOW).unwrap();
        i.approve(
            &ch.request_id,
            "mac",
            Proof::Signature(w.laptop.sign(&ch.message).as_ref()),
            NOW,
        )
        .unwrap();
        assert_eq!(
            i.release(&ch.request_id, CALLER, NOW + 1).unwrap().use_no,
            1
        );
        assert_eq!(
            i.release(&ch.request_id, CALLER, NOW + 2).unwrap().use_no,
            2
        );
        assert_eq!(
            i.release(&ch.request_id, CALLER, NOW + 3),
            Err(Error::Spent)
        );
        assert_eq!(i.status(&ch.request_id, NOW + 3), Status::Spent);
        // a new approval for a new request: and its window ends
        let ch = i.request(w.scope(), CALLER, NOW).unwrap();
        i.approve(
            &ch.request_id,
            "mac",
            Proof::Signature(w.laptop.sign(&ch.message).as_ref()),
            NOW,
        )
        .unwrap();
        assert_eq!(
            i.release(&ch.request_id, CALLER, NOW + 600_000),
            Err(Error::Expired)
        );
        assert_eq!(i.status(&ch.request_id, NOW + 600_000), Status::Expired);
    }

    #[test]
    fn the_window_is_capped_at_fifteen_minutes_and_that_is_what_the_approver_signs() {
        let w = world();
        let r = w.rand();
        let i = w.issuer(&r);
        let mut s = w.scope();
        s.window_secs = 86_400;
        let ch = i.request(s.clone(), CALLER, NOW).unwrap();
        // a signature over a message with the asked-for window is not the message the issuer made
        s.window_secs = 900;
        assert_eq!(
            ch.message,
            s.message(&ch.request_id, &ch.nonce, ch.expires_ms)
        );
        i.approve(
            &ch.request_id,
            "mac",
            Proof::Signature(w.laptop.sign(&ch.message).as_ref()),
            NOW,
        )
        .unwrap();
        assert_eq!(
            i.status(&ch.request_id, NOW),
            Status::Approved {
                expires_ms: NOW + 900_000,
                uses_left: 2
            }
        );
    }

    #[test]
    fn a_box_cannot_make_an_approval_or_move_one_to_another_box_store_or_key() {
        let w = world();
        let r = w.rand();
        let i = w.issuer(&r);
        // not approved: nothing is released
        let ch = i.request(w.scope(), CALLER, NOW).unwrap();
        assert_eq!(
            i.release(&ch.request_id, CALLER, NOW),
            Err(Error::NotApproved)
        );
        assert!(w.reader.calls.borrow().is_empty());
        // a box that is not pinned, a store that is not its, a key that is not its
        let mut s = w.scope();
        s.box_id = "other".into();
        assert_eq!(i.request(s, CALLER, NOW), Err(Error::UnknownBox));
        let mut s = w.scope();
        s.store_id = "store-2".into();
        assert_eq!(i.request(s, CALLER, NOW), Err(Error::StoreMismatch));
        let mut s = w.scope();
        s.service_key_fp = ozbox_seal::ServiceKey::generate().unwrap().fingerprint();
        assert_eq!(i.request(s, CALLER, NOW), Err(Error::KeyMismatch));
        // a signature for one request is not valid for another
        let ch2 = i.request(w.scope(), CALLER, NOW).unwrap();
        let sig = w.laptop.sign(&ch.message);
        assert!(matches!(
            i.approve(&ch2.request_id, "mac", Proof::Signature(sig.as_ref()), NOW),
            Err(Error::BadProof(_))
        ));
        // nobody pinned, the wrong kind of proof, an expired challenge, and a request answered twice
        assert_eq!(
            i.approve(
                &ch.request_id,
                "nobody",
                Proof::Signature(sig.as_ref()),
                NOW
            ),
            Err(Error::UnknownApprover)
        );
        assert_eq!(
            i.approve(&ch.request_id, "phone", Proof::Signature(sig.as_ref()), NOW),
            Err(Error::WrongKind)
        );
        assert_eq!(
            i.approve(
                &ch.request_id,
                "mac",
                Proof::Signature(sig.as_ref()),
                NOW + CHALLENGE_TTL_MS
            ),
            Err(Error::Expired)
        );
        i.approve(&ch.request_id, "mac", Proof::Signature(sig.as_ref()), NOW)
            .unwrap();
        assert_eq!(
            i.approve(&ch.request_id, "mac", Proof::Signature(sig.as_ref()), NOW),
            Err(Error::NotPending)
        );
        // a request that does not exist
        assert_eq!(i.release("nope", CALLER, NOW), Err(Error::NoSuchRequest));
        assert_eq!(i.status("nope", NOW), Status::Unknown);
    }

    #[test]
    fn a_request_with_a_bad_shape_is_refused() {
        let w = world();
        let r = w.rand();
        let i = w.issuer(&r);
        let mut cases = vec![];
        let mut s = w.scope();
        s.secret = "has space".into();
        cases.push(s);
        let mut s = w.scope();
        s.argv_digest = "short".into();
        cases.push(s);
        let mut s = w.scope();
        s.uses = 0;
        cases.push(s);
        let mut s = w.scope();
        s.uses = MAX_USES + 1;
        cases.push(s);
        let mut s = w.scope();
        s.run_id = String::new();
        cases.push(s);
        for s in cases {
            assert!(matches!(
                i.request(s, CALLER, NOW),
                Err(Error::BadRequest(_))
            ));
        }
    }

    #[test]
    fn a_software_laptop_key_is_refused_for_production_unless_the_owner_allows_it() {
        let mut w = world();
        let (soft, spub) = ed25519();
        w.cfg.approvers[1].public = spub;
        let n = Cell::new(100u64);
        let r = || {
            n.set(n.get() + 1);
            format!("{:032x}", n.get())
        };
        let (ch, sig) = {
            let ch = w.issuer(&r).request(w.scope(), CALLER, NOW).unwrap();
            let sig = soft.sign(&ch.message);
            assert_eq!(
                w.issuer(&r)
                    .approve(&ch.request_id, "soft", Proof::Signature(sig.as_ref()), NOW),
                Err(Error::NoUserPresence)
            );
            (ch, sig)
        };
        w.cfg.allow_laptop_without_presence = true;
        w.issuer(&r)
            .approve(&ch.request_id, "soft", Proof::Signature(sig.as_ref()), NOW)
            .unwrap();
    }

    #[test]
    fn the_recovery_key_and_a_passkey_can_approve_and_a_passkey_cannot_go_backwards() {
        let w = world();
        let r = w.rand();
        let i = w.issuer(&r);
        let ch = i.request(w.scope(), CALLER, NOW).unwrap();
        i.approve(
            &ch.request_id,
            "rec",
            Proof::Signature(w.recovery.sign(&ch.message).as_ref()),
            NOW,
        )
        .unwrap();
        let go = |counter: u32| {
            let ch = i.request(w.scope(), CALLER, NOW).unwrap();
            let (ad, cd, sig) = assert_for(
                &w.pk,
                "dash.example.com",
                "https://dash.example.com",
                &ch.message,
                0x05,
                counter,
            );
            i.approve(
                &ch.request_id,
                "phone",
                Proof::Assertion(Assertion {
                    authenticator_data: &ad,
                    client_data_json: &cd,
                    signature: &sig,
                }),
                NOW,
            )
        };
        assert_eq!(go(5), Ok(()));
        assert!(
            matches!(go(5), Err(Error::BadProof(_))),
            "a replayed counter"
        );
        assert!(
            matches!(go(4), Err(Error::BadProof(_))),
            "a counter that went back"
        );
        assert_eq!(go(6), Ok(()));
    }

    #[test]
    fn a_release_the_issuer_cannot_record_does_not_happen_and_a_failed_read_stays_spent() {
        let w = world();
        let r = w.rand();
        let i = w.issuer(&r);
        let ch = i.request(w.scope(), CALLER, NOW).unwrap();
        i.approve(
            &ch.request_id,
            "mac",
            Proof::Signature(w.laptop.sign(&ch.message).as_ref()),
            NOW,
        )
        .unwrap();
        w.log.fail.set(true);
        assert_eq!(
            i.release(&ch.request_id, CALLER, NOW + 1),
            Err(Error::Audit)
        );
        assert!(
            w.reader.calls.borrow().is_empty(),
            "no read without a record"
        );
        assert_eq!(
            i.status(&ch.request_id, NOW + 1),
            Status::Approved {
                expires_ms: NOW + 600_000,
                uses_left: 2
            }
        );
        w.log.fail.set(false);
        w.reader.fail.set(true);
        assert!(matches!(
            i.release(&ch.request_id, CALLER, NOW + 2),
            Err(Error::Reader(_))
        ));
        assert_eq!(
            i.status(&ch.request_id, NOW + 2),
            Status::Approved {
                expires_ms: NOW + 600_000,
                uses_left: 1
            }
        );
        // the error text a caller shows has no reason from the reader in it
        assert!(!Error::Reader("denied".into())
            .to_string()
            .contains("denied"));
    }

    #[test]
    fn two_releases_cannot_spend_the_same_use() {
        let w = world();
        let r = w.rand();
        let i = w.issuer(&r);
        let mut s = w.scope();
        s.uses = 1;
        let ch = i.request(s, CALLER, NOW).unwrap();
        i.approve(
            &ch.request_id,
            "mac",
            Proof::Signature(w.laptop.sign(&ch.message).as_ref()),
            NOW,
        )
        .unwrap();
        // a writer that read the record before another release wrote loses its compare-and-set
        let (stale, _) = w.state.get(&format!("req/{}", ch.request_id)).unwrap();
        assert!(i.release(&ch.request_id, CALLER, NOW + 1).is_ok());
        assert!(w
            .state
            .put_if(&format!("req/{}", ch.request_id), Some(stale), "{}")
            .is_err());
        assert_eq!(
            i.release(&ch.request_id, CALLER, NOW + 2),
            Err(Error::Spent)
        );
        assert_eq!(w.reader.calls.borrow().len(), 1);
    }

    // ---- ----

    #[test]
    fn every_field_of_what_is_approved_is_in_what_is_signed_and_in_what_the_approver_is_shown() {
        let w = world();
        let base = w.scope();
        let m = |s: &Scope| s.message("req", "nonce", 1);
        let base_msg = m(&base);
        let card_text = |s: &Scope| {
            s.card()
                .into_iter()
                .map(|(k, v)| format!("{k}={v}"))
                .collect::<Vec<_>>()
                .join("|")
        };
        let mut changed: Vec<(&str, Scope)> = Vec::new();
        for (name, f) in [
            (
                "box_id",
                (|s: &mut Scope| s.box_id = "other".into()) as fn(&mut Scope),
            ),
            ("store_id", |s| s.store_id = "store-2".into()),
            ("project", |s| s.project = "other-app".into()),
            ("env", |s| s.env = "staging".into()),
            ("secret", |s| s.secret = "prod/other".into()),
            ("version", |s| s.version = "v4".into()),
            ("argv_digest", |s| s.argv_digest = "b".repeat(64)),
            ("commit", |s| s.commit = "e".repeat(40)),
            ("dir_digest", |s| s.dir_digest = "f".repeat(64)),
            ("caller", |s| {
                s.caller = "arn:aws:sts::1:assumed-role/x/y".into()
            }),
            ("run_id", |s| s.run_id = "run-2".into()),
            ("uses", |s| s.uses = 3),
            ("window_secs", |s| s.window_secs = 60),
        ] {
            let mut s = base.clone();
            f(&mut s);
            changed.push((name, s));
        }
        for (name, s) in &changed {
            assert_ne!(m(s), base_msg, "{name} is not signed");
            // and what the approver sees changes with it, so a card cannot say one thing while the signature covers another
            if *name != "store_id" {
                assert_ne!(card_text(s), card_text(&base), "{name} is not on the card");
            }
        }
    }

    #[test]
    fn the_card_comes_from_the_issuers_record_and_only_while_the_request_waits() {
        let w = world();
        let r = w.rand();
        let i = w.issuer(&r);
        let ch = i.request(w.scope(), CALLER, NOW).unwrap();
        let card = i.card(&ch.request_id, NOW).unwrap();
        assert!(card
            .iter()
            .any(|(k, v)| *k == "Commit" && v == &"c".repeat(40)));
        assert!(card.iter().any(|(k, v)| *k == "Project" && v == "app"));
        assert_eq!(i.card("nope", NOW), Err(Error::NoSuchRequest));
        assert_eq!(
            i.card(&ch.request_id, NOW + CHALLENGE_TTL_MS),
            Err(Error::Expired)
        );
        i.approve(
            &ch.request_id,
            "mac",
            Proof::Signature(w.laptop.sign(&ch.message).as_ref()),
            NOW + 1,
        )
        .unwrap();
        assert_eq!(i.card(&ch.request_id, NOW + 2), Err(Error::NotPending));
    }

    #[test]
    fn a_caller_that_is_not_the_boxs_is_refused_on_a_request_and_on_a_release() {
        let w = world();
        let r = w.rand();
        let i = w.issuer(&r);
        let other = "arn:aws:sts::123456789012:assumed-role/ozbox-other-role/i-0def";
        // the verified caller decides; what the box put in the scope is not consulted
        assert_eq!(i.request(w.scope(), other, NOW), Err(Error::WrongCaller));
        let mut s = w.scope();
        s.caller = other.into();
        let ch = i.request(s, CALLER, NOW).unwrap();
        match i.load(&ch.request_id).unwrap().1 {
            Record::Pending { scope, .. } => {
                assert_eq!(scope.caller, CALLER, "overwritten by the verified caller")
            }
            Record::Approved { .. } => panic!("not approved yet"),
        }
        let ch = i.request(w.scope(), CALLER, NOW).unwrap();
        i.approve(
            &ch.request_id,
            "mac",
            Proof::Signature(w.laptop.sign(&ch.message).as_ref()),
            NOW + 1,
        )
        .unwrap();
        // another box's role cannot spend this box's uses
        assert_eq!(
            i.release(
                &ch.request_id,
                "arn:aws:sts::123456789012:assumed-role/ozbox-other-role/i-0def",
                NOW + 2
            ),
            Err(Error::WrongCaller)
        );
        assert_eq!(
            i.status(&ch.request_id, NOW + 2),
            Status::Approved {
                expires_ms: NOW + 1 + 600_000,
                uses_left: 2
            }
        );
        assert!(w.reader.calls.borrow().is_empty());
        // a box with no caller connected asks for nothing
        let mut w2 = world();
        w2.cfg.boxes.get_mut("dev").unwrap().caller = String::new();
        let r2 = w2.rand();
        let mut s = w2.scope();
        s.caller = String::new();
        assert_eq!(
            w2.issuer(&r2).request(s, CALLER, NOW),
            Err(Error::BadRequest(
                "a name has characters that are not allowed"
            ))
        );
    }

    #[test]
    fn a_box_asks_only_for_the_secrets_allocated_to_it() {
        let w = world();
        let r = w.rand();
        let i = w.issuer(&r);
        let mut s = w.scope();
        s.secret = "staging/db-url".into();
        assert_eq!(i.request(s, CALLER, NOW), Err(Error::NotAllocated));
        // a prefix names a folder, never a half-word: prod/* does not allow prod-other/x
        let mut s = w.scope();
        s.secret = "prod-other/x".into();
        assert_eq!(i.request(s, CALLER, NOW), Err(Error::NotAllocated));
        let mut w2 = world();
        w2.cfg.boxes.get_mut("dev").unwrap().allowed = vec![];
        let r2 = w2.rand();
        assert_eq!(
            w2.issuer(&r2).request(w2.scope(), CALLER, NOW),
            Err(Error::NotAllocated)
        );
        let mut w3 = world();
        w3.cfg.boxes.get_mut("dev").unwrap().allowed = vec!["prod/db-url".into()];
        let r3 = w3.rand();
        assert!(w3.issuer(&r3).request(w3.scope(), CALLER, NOW).is_ok());
    }

    #[test]
    fn a_worker_box_is_refused_production_on_a_request_and_on_a_release_and_it_is_audited() {
        // decision D2 (ADR 0042): hard-coded, no setting. The pin says what the box is; the refusal does not depend on anything else.
        let mut w = world();
        // an approval made while the box was an ordinary box...
        let request_id = {
            let r = w.rand();
            let i = w.issuer(&r);
            let ch = i.request(w.scope(), CALLER, NOW).unwrap();
            i.approve(
                &ch.request_id,
                "mac",
                Proof::Signature(w.laptop.sign(&ch.message).as_ref()),
                NOW + 1,
            )
            .unwrap();
            ch.request_id
        };
        // ...is not honoured once the box is enrolled as a worker
        w.cfg.boxes.get_mut("dev").unwrap().class = Some(BoxClass::Worker);
        let r = w.rand();
        let i = w.issuer(&r);
        assert_eq!(
            i.release(&request_id, CALLER, NOW + 2),
            Err(Error::ProductionToWorker)
        );
        assert_eq!(
            i.request(w.scope(), CALLER, NOW + 3),
            Err(Error::ProductionToWorker)
        );
        let log = w.log.lines.borrow();
        assert_eq!(
            log.iter()
                .filter(|l| l.starts_with("refused-worker"))
                .count(),
            2
        );
        assert!(
            !log.iter().any(|l| l.starts_with("release ")),
            "nothing was released"
        );
        assert!(w.reader.calls.borrow().is_empty(), "no value was read");
    }

    #[test]
    fn a_pin_is_a_worker_unless_it_positively_says_main() {
        for (class, refused) in [
            (None, true),
            (Some(BoxClass::Worker), true),
            (Some(BoxClass::Main), false),
        ] {
            let mut w = world();
            w.cfg.boxes.get_mut("dev").unwrap().class = class;
            let r = w.rand();
            let got = w.issuer(&r).request(w.scope(), CALLER, NOW);
            assert_eq!(
                matches!(got, Err(Error::ProductionToWorker)),
                refused,
                "class={class:?}"
            );
        }
    }

    #[test]
    fn an_old_pin_with_no_class_is_refused_and_the_error_names_the_one_edit_that_fixes_it() {
        let pin: BoxPin = serde_json::from_str(
            r#"{"store_id":"s","service_key":[0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0]}"#,
        )
        .unwrap();
        assert_eq!(pin.class, None);
        assert!(pin.counts_as_worker());
        let msg = Error::ProductionToWorker.to_string();
        assert!(msg.contains("class") && msg.contains("main") && msg.contains("approver list"));
    }

    #[test]
    fn a_wrong_caller_cannot_write_the_worker_refusal_or_learn_a_box_is_a_worker() {
        let mut w = world();
        w.cfg.boxes.get_mut("dev").unwrap().class = Some(BoxClass::Worker);
        let r = w.rand();
        let got = w.issuer(&r).request(w.scope(), "someone-else", NOW);
        assert_eq!(got, Err(Error::WrongCaller));
        assert!(!w
            .log
            .lines
            .borrow()
            .iter()
            .any(|l| l.starts_with("refused-worker")));
    }

    #[test]
    fn a_run_may_ask_for_a_few_approvals_and_no_more() {
        let w = world();
        let r = w.rand();
        let i = w.issuer(&r);
        for _ in 0..MAX_REQUESTS_PER_RUN {
            i.request(w.scope(), CALLER, NOW).unwrap();
        }
        assert_eq!(
            i.request(w.scope(), CALLER, NOW),
            Err(Error::TooManyRequests)
        );
        // another run is not affected
        let mut s = w.scope();
        s.run_id = "run-2".into();
        assert!(i.request(s, CALLER, NOW).is_ok());
    }

    #[test]
    fn a_commit_or_directory_that_is_not_a_hash_is_refused() {
        let w = world();
        let r = w.rand();
        let i = w.issuer(&r);
        for f in [
            (|s: &mut Scope| s.commit = "main".into()) as fn(&mut Scope),
            |s| s.commit = "c".repeat(41),
            |s| s.dir_digest = "d".repeat(63),
            |s| s.dir_digest = "z".repeat(64),
        ] {
            let mut s = w.scope();
            f(&mut s);
            assert!(matches!(
                i.request(s, CALLER, NOW),
                Err(Error::BadRequest(_))
            ));
        }
    }

    #[test]
    fn a_passkey_on_a_page_the_box_serves_cannot_approve_production_but_a_present_laptop_key_can() {
        let mut w = world();
        w.cfg.independent_approval_origins.clear(); // the default: no origin the box does not serve is known
        let n = Cell::new(500u64);
        let r = || {
            n.set(n.get() + 1);
            format!("{:032x}", n.get())
        };
        let i = w.issuer(&r);
        let ch = i.request(w.scope(), CALLER, NOW).unwrap();
        let (ad, cd, sig) = assert_for(
            &w.pk,
            "dash.example.com",
            "https://dash.example.com",
            &ch.message,
            0x05,
            1,
        );
        assert_eq!(
            i.approve(
                &ch.request_id,
                "phone",
                Proof::Assertion(Assertion {
                    authenticator_data: &ad,
                    client_data_json: &cd,
                    signature: &sig
                }),
                NOW
            ),
            Err(Error::OriginServedByBox)
        );
        assert_eq!(
            i.status(&ch.request_id, NOW),
            Status::Pending {
                expires_ms: NOW + CHALLENGE_TTL_MS
            }
        );
        // a laptop key that asks the person still approves
        i.approve(
            &ch.request_id,
            "mac",
            Proof::Signature(w.laptop.sign(&ch.message).as_ref()),
            NOW,
        )
        .unwrap();
        // and once the owner lists an origin the box does not serve, the same passkey is accepted
        w.cfg.independent_approval_origins = vec!["https://dash.example.com".into()];
        let i = w.issuer(&r);
        let ch = i.request(w.scope(), CALLER, NOW).unwrap();
        let (ad, cd, sig) = assert_for(
            &w.pk,
            "dash.example.com",
            "https://dash.example.com",
            &ch.message,
            0x05,
            2,
        );
        i.approve(
            &ch.request_id,
            "phone",
            Proof::Assertion(Assertion {
                authenticator_data: &ad,
                client_data_json: &cd,
                signature: &sig,
            }),
            NOW,
        )
        .unwrap();
    }

    #[test]
    fn a_box_that_picks_a_new_run_id_for_every_ask_still_meets_a_cap() {
        let w = world();
        let r = w.rand();
        let i = w.issuer(&r);
        for k in 0..MAX_REQUESTS_PER_BOX_HOUR {
            let mut s = w.scope();
            s.run_id = format!("run-{k}");
            i.request(s, CALLER, NOW).unwrap();
        }
        let mut s = w.scope();
        s.run_id = "run-fresh".into();
        assert_eq!(
            i.request(s.clone(), CALLER, NOW),
            Err(Error::TooManyRequests)
        );
        // the next hour is a new count
        assert!(i.request(s, CALLER, NOW + 3_600_000).is_ok());
    }
}
