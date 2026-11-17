//! `ozbox-hubd`: the hub's daemon on `main` (ADR 0042 sections 1 and 2), user `ozbox-hub`.
//!
//! What it does, and only this:
//!
//! * **Terminates the worker side.** A message from a worker is checked here before anything else sees it: the envelope's shape,
//!   that the sender is an enrolled worker, that it was sealed for this hub's key, and the sender's signature against the key its
//!   enrolment attested. A message that passes is written to the **inbound spool** (fsynced) and only then accepted. A body is
//!   never opened here: this process has no operation that opens one or signs one.
//! * **Spools for the supervisor.** The hub's logic (`ozbox serve`) takes the inbound spool and puts what it sends to workers on
//!   the **outbound spool**, over this daemon's own Unix socket. The transport (H3) moves the outbound spool to the workers.
//! * **Enrols workers.** Invites, requests, plans and applies ([`crate::enrol`]); the roster is the keys that enrolment attested.
//! * **Answers the handshake.** Its one private operation, asked of the secrets service on a socket only its user may enter.
//!
//! The process binds no TCP port and opens no connection of its own: the supervisor reaches it on a Unix socket (handed over
//! by systemd, or bound in a directory whose mode decides who may connect), and the network side is a transport that dials out
//! (ADR 0005). Its state is one file, written atomically and fsynced, under an advisory lock ([`Store`]).

use std::collections::{BTreeMap, VecDeque};
use std::io::{BufRead, BufReader, Read, Write};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread::JoinHandle;

use ozbox_core::approval_subject::Encoder;
use ozbox_core::audit::NewEvent;
use ozbox_core::channel::store::Store;
use ozbox_core::channel::wire::{
    hex, unhex, word_ok, Sealed, Verifier, MAX_SKEW_MS, TRANSPORT_CAP,
};
use ozbox_core::hub::wire::PROFILE;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::crypto::{verify_ed25519, Directory, DirectoryVerifier};
use crate::enrol::{
    Ctx, EnrolPlan, EnrolRequest, EnrolState, InvitePlan, InviteSpec, Refusal, Registrars,
    RosterRecord,
};
use crate::identity::{Identity, HANDSHAKE_TAG};
use crate::keys::SignPurpose;
use crate::ops::KeyOps;

/// The state file's version.
pub const STATE_VERSION: u32 = 1;
/// The most messages one worker may have waiting in either spool. Beyond it a worker's messages are refused, not buffered.
pub const MAX_SPOOL_PER_WORKER: usize = 256;
/// The most audit events kept for the supervisor to take.
pub const MAX_AUDIT: usize = 4096;
/// A refusal of the same kind is audited at most once per this long, with the count since the last.
pub const REFUSAL_AUDIT_EVERY_MS: u64 = 60_000;

/// Where the daemon keeps things and how it is named.
#[derive(Debug, Clone)]
pub struct Config {
    /// The state directory (mode 0700, owned by `ozbox-hub`).
    pub dir: PathBuf,
    /// The supervisor-facing socket.
    pub socket: PathBuf,
    /// The registrars file: written by root, read here.
    pub registrars: PathBuf,
    /// `main`'s box id: never one of its own workers.
    pub box_id: String,
    /// The hub's name on the channel (the envelopes' `from` and `to`).
    pub name: String,
}

/// Everything the daemon keeps. Public keys, sealed messages and counts only.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct HubdState {
    pub version: u32,
    pub enrol: EnrolState,
    /// From workers, verified, for the supervisor.
    pub inbound: VecDeque<Sealed>,
    /// From the supervisor, for each worker.
    pub outbound: BTreeMap<String, VecDeque<Sealed>>,
    /// Audit events not yet taken by the supervisor, numbered from `audit_n`.
    pub audit: Vec<NewEvent>,
    pub audit_n: u64,
    pub store_id: String,
    /// Refusals per code since the last one was audited, and when that was.
    pub refused: BTreeMap<String, (u64, u64)>,
}

/// Why a message from a worker or the supervisor was not spooled. The code is the audit word.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Rejected(pub &'static str);

impl std::fmt::Display for Rejected {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "the message was refused: {}", self.0)
    }
}

/// The handshake the daemon answers: the hub's identity and a signature over the worker's challenge, a time and that identity.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Handshake {
    pub identity: Identity,
    pub ts_ms: u64,
    /// Hex.
    pub sig: String,
}

/// The bytes the handshake key signs.
pub fn handshake_bytes(identity_fp: &str, challenge: &[u8], ts_ms: u64) -> Vec<u8> {
    let mut e = Encoder::new(HANDSHAKE_TAG);
    e.text(identity_fp).field(challenge).u64(ts_ms);
    e.bytes().to_vec()
}

/// The worker's check of a handshake: the identity is the one it pinned (by identity fingerprint), the signature is the
/// identity's handshake key over the worker's own challenge, and the time is current. Returns the hub's identity, whose keys
/// the worker then seals to and verifies with.
pub fn verify_handshake(
    pinned_identity_fp: &str,
    challenge: &[u8],
    h: &Handshake,
    now: u64,
) -> Option<Identity> {
    let id = h.identity.checked()?;
    if id.identity_fp() != pinned_identity_fp || h.ts_ms.abs_diff(now) > MAX_SKEW_MS {
        return None;
    }
    let sig = unhex(&h.sig)?;
    verify_ed25519(
        &id.handshake_public,
        &handshake_bytes(pinned_identity_fp, challenge, h.ts_ms),
        &sig,
    )
    .then_some(id)
}

fn fresh_id() -> String {
    let mut b = [0u8; 8];
    let _ = getrandom::getrandom(&mut b);
    hex(&b)
}

fn sealed_bytes(m: &Sealed) -> usize {
    m.envelope.body.len() + m.envelope.ext.len() + m.signature.len()
}

/// The daemon: its config, its own secrets service (as `ozbox-hubd`'s user reaches it), its state and the directory of
/// attested keys.
pub struct Hubd {
    cfg: Config,
    ops: Arc<dyn KeyOps>,
    identity: Identity,
    store: Store<HubdState>,
    dir: Directory,
}

impl std::fmt::Debug for Hubd {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Hubd({})", self.identity.identity_fp())
    }
}

impl Hubd {
    /// Open the daemon: its identity from the secrets service, its state from the directory (made the first time).
    pub fn open(cfg: Config, ops: Arc<dyn KeyOps>) -> Result<Arc<Hubd>, String> {
        if !word_ok(&cfg.name) || !word_ok(&cfg.box_id) {
            return Err("the hub's name and box id must be plain names".into());
        }
        let identity = ops
            .identity()
            .map_err(|e| format!("the secrets service did not give the hub's identity: {e}"))?;
        std::fs::create_dir_all(&cfg.dir)
            .map_err(|_| "the state directory could not be made".to_string())?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&cfg.dir, std::fs::Permissions::from_mode(0o700))
                .map_err(|_| "the state directory's mode could not be set".to_string())?;
        }
        let store: Store<HubdState> = Store::new(&cfg.dir);
        if !store.exists() {
            store
                .create(&HubdState {
                    version: STATE_VERSION,
                    store_id: fresh_id(),
                    ..HubdState::default()
                })
                .map_err(|_| "the state could not be written".to_string())?;
        }
        let st = store
            .read()
            .map_err(|_| "the state could not be read".to_string())?;
        if st.version != STATE_VERSION {
            return Err("the state was written by another version of the hub".into());
        }
        let dir = Directory::default();
        for r in st.enrol.roster.values() {
            dir.insert(&r.identity);
        }
        Ok(Arc::new(Hubd {
            cfg,
            ops,
            identity,
            store,
            dir,
        }))
    }

    pub fn identity(&self) -> &Identity {
        &self.identity
    }

    pub fn config(&self) -> &Config {
        &self.cfg
    }

    /// The attested keys of every enrolled worker, by channel fingerprint.
    pub fn directory(&self) -> Directory {
        self.dir.clone()
    }

    /// The registrars, read fresh: root may change the pins at any time, and a removed pin stops counting at once.
    pub fn registrars(&self) -> Result<Registrars, String> {
        read_registrars(&self.cfg.registrars)
    }

    fn update<R>(&self, f: impl FnOnce(&mut HubdState) -> R) -> Result<R, String> {
        self.store
            .update(f)
            .map_err(|_| "the hub's state could not be written".to_string())
    }

    pub fn state(&self) -> Result<HubdState, String> {
        self.store
            .read()
            .map_err(|_| "the hub's state could not be read".to_string())
    }

    // ---- the worker side (the transport calls these) -----------------------------------------------------------------

    /// Answer a worker's handshake challenge (16 to 64 bytes) with the hub's identity, signed by its handshake key.
    pub fn handshake(&self, challenge: &[u8], now: u64) -> Result<Handshake, String> {
        if !(16..=64).contains(&challenge.len()) {
            return Err("the challenge is not valid".into());
        }
        let bytes = handshake_bytes(&self.identity.identity_fp(), challenge, now);
        let sig = self
            .ops
            .sign(SignPurpose::Handshake, &bytes)
            .map_err(|e| e.to_string())?;
        Ok(Handshake {
            identity: self.identity.clone(),
            ts_ms: now,
            sig: hex(&sig),
        })
    }

    /// A worker's enrolment request: screened, and held as pending. Audited either way, by code and worker only.
    pub fn receive_enrolment(&self, req: &EnrolRequest, now: u64) -> Result<(), Refusal> {
        let regs = self.registrars().map_err(|m| Refusal {
            code: crate::enrol::CODE_UNKNOWN_REGISTRAR,
            message: m,
        })?;
        let fp = self.identity.identity_fp();
        let worker = if word_ok(&req.worker) {
            req.worker.clone()
        } else {
            "-".into()
        };
        let out = self.update(|st| {
            let cx = Ctx {
                ops: self.ops.as_ref(),
                registrars: &regs,
                hub_identity_fp: &fp,
                hub_box_id: &self.cfg.box_id,
                now,
            };
            let r = st.enrol.receive(&cx, req);
            match &r {
                Ok(()) => note(st, now, "hub.enrol.pending", Some(&worker), String::new()),
                Err(e) => note(
                    st,
                    now,
                    "hub.enrol.refused",
                    Some(&worker),
                    format!("code={}", e.code),
                ),
            }
            r
        });
        out.map_err(|m| Refusal {
            code: crate::enrol::CODE_SERVICE,
            message: m,
        })?
    }

    /// A message from a worker. Verified before it is spooled; spooled (fsynced) before this returns `Ok`.
    pub fn accept(&self, msg: Sealed, now: u64) -> Result<(), Rejected> {
        let code = self.check_inbound(&msg);
        let r = self.update(|st| {
            if let Err(Rejected(c)) = code {
                refused(st, now, c);
                return Err(Rejected(c));
            }
            let from = &msg.envelope.from;
            let n = st
                .inbound
                .iter()
                .filter(|m| &m.envelope.from == from)
                .count();
            if n >= MAX_SPOOL_PER_WORKER {
                refused(st, now, "spool-full");
                return Err(Rejected("spool-full"));
            }
            if st.inbound.iter().any(|m| m == &msg) {
                // the same signed message twice: already spooled, so this is not an error
                return Ok(());
            }
            st.inbound.push_back(msg);
            Ok(())
        });
        r.map_err(|_| Rejected("state"))?
    }

    fn check_inbound(&self, msg: &Sealed) -> Result<(), Rejected> {
        let e = &msg.envelope;
        if sealed_bytes(msg) > TRANSPORT_CAP {
            return Err(Rejected("too-big"));
        }
        // the conversation fabric rides the same spool under `<box>.fabric` endpoints, with its own profile (ADR 0057)
        let fabric = e.to == format!("{}.fabric", self.cfg.name);
        let profile = if fabric {
            &ozbox_core::fabric::wire::PROFILE
        } else {
            &PROFILE
        };
        e.check(profile).map_err(|_| Rejected("shape"))?;
        if !fabric && e.to != self.cfg.name {
            return Err(Rejected("not-for-this-hub"));
        }
        if e.receiver_fp != self.identity.channel_fp() {
            return Err(Rejected("sealed-for-another-key"));
        }
        let worker = if fabric {
            e.from.strip_suffix(".fabric").unwrap_or_default()
        } else {
            e.from.as_str()
        };
        let st = self.state().map_err(|_| Rejected("state"))?;
        let Some(rec) = st.enrol.roster.get(worker) else {
            return Err(Rejected("not-enrolled"));
        };
        let v = DirectoryVerifier {
            dir: self.dir.clone(),
        };
        if !v.verify(&rec.channel_fp, &e.canonical(profile), &msg.signature) {
            return Err(Rejected("bad-signature"));
        }
        Ok(())
    }

    /// What is waiting for one worker, taken (the transport sends it; the supervisor's channel resends what is not
    /// acknowledged, so a message lost after this is not lost for good).
    pub fn take_outbound(&self, worker: &str) -> Vec<Sealed> {
        self.update(|st| {
            st.outbound
                .get_mut(worker)
                .map(|q| q.drain(..).collect())
                .unwrap_or_default()
        })
        .unwrap_or_default()
    }

    // ---- the supervisor side ------------------------------------------------------------------------------------------

    /// Everything the workers sent since the last call, in order.
    pub fn take_inbound(&self) -> Result<Vec<Sealed>, String> {
        self.update(|st| st.inbound.drain(..).collect())
    }

    /// Queue messages for a worker. Each must be from this hub, addressed to that worker and sealed to its attested key.
    pub fn put_outbound(&self, to: &str, msgs: Vec<Sealed>, now: u64) -> Result<usize, Rejected> {
        let st = self.state().map_err(|_| Rejected("state"))?;
        let Some(rec) = st.enrol.roster.get(to) else {
            return Err(Rejected("not-enrolled"));
        };
        let fabric_to = format!("{to}.fabric");
        let fabric_from = format!("{}.fabric", self.cfg.name);
        for m in &msgs {
            let e = &m.envelope;
            let shaped = if e.to == fabric_to {
                e.from == fabric_from && e.check(&ozbox_core::fabric::wire::PROFILE).is_ok()
            } else {
                e.from == self.cfg.name && e.to == to && e.check(&PROFILE).is_ok()
            };
            if !shaped || e.receiver_fp != rec.channel_fp || sealed_bytes(m) > TRANSPORT_CAP {
                let _ = self.update(|st| refused(st, now, "outbound-misaddressed"));
                return Err(Rejected("outbound-misaddressed"));
            }
        }
        let n = msgs.len();
        let r = self.update(|st| {
            let q = st.outbound.entry(to.to_string()).or_default();
            if q.len() + n > MAX_SPOOL_PER_WORKER {
                return Err(Rejected("spool-full"));
            }
            q.extend(msgs);
            Ok(n)
        });
        r.map_err(|_| Rejected("state"))?
    }

    pub fn plan_invite(&self, spec: &InviteSpec) -> Result<InvitePlan, Refusal> {
        let st = self.state().map_err(service)?;
        st.enrol.plan_invite(spec, &self.cfg.box_id)
    }

    /// Apply a planned invite. The token is returned once and is in no state, log or audit line.
    pub fn apply_invite(
        &self,
        plan: &InvitePlan,
        now: u64,
    ) -> Result<zeroize::Zeroizing<String>, Refusal> {
        self.update(|st| {
            let r = st.enrol.apply_invite(plan, self.ops.as_ref(), now);
            match &r {
                Ok(_) => note(
                    st,
                    now,
                    "hub.invite",
                    Some(&plan.worker),
                    format!("box={} provider={}", plan.box_id, plan.provider.word()),
                ),
                Err(e) => note(
                    st,
                    now,
                    "hub.invite.refused",
                    Some(&plan.worker),
                    format!("code={}", e.code),
                ),
            }
            r
        })
        .map_err(service)?
    }

    pub fn plan_enrol(&self, worker: &str) -> Result<EnrolPlan, Refusal> {
        self.state().map_err(service)?.enrol.plan_enrol(worker)
    }

    /// Apply a planned enrolment. On success the worker's attested keys are in the roster and the directory.
    pub fn apply_enrol(&self, plan: &EnrolPlan, now: u64) -> Result<RosterRecord, Refusal> {
        let regs = self.registrars().map_err(service)?;
        let fp = self.identity.identity_fp();
        let rec = self
            .update(|st| {
                let cx = Ctx {
                    ops: self.ops.as_ref(),
                    registrars: &regs,
                    hub_identity_fp: &fp,
                    hub_box_id: &self.cfg.box_id,
                    now,
                };
                let r = st.enrol.apply_enrol(&cx, plan);
                match &r {
                    Ok(rec) => note(
                        st,
                        now,
                        "hub.enrol",
                        Some(&plan.worker),
                        format!(
                            "box={} key={} registrar={}",
                            rec.box_id, rec.channel_fp, rec.registrar_fp
                        ),
                    ),
                    Err(e) => note(
                        st,
                        now,
                        "hub.enrol.refused",
                        Some(&plan.worker),
                        format!("code={}", e.code),
                    ),
                }
                r
            })
            .map_err(service)??;
        self.dir.insert(&rec.identity);
        Ok(rec)
    }

    /// Take a worker out of the roster; its spooled messages go with it.
    pub fn remove_worker(&self, worker: &str, now: u64) -> Result<bool, String> {
        let (gone, fp) = self.update(|st| {
            let fp = st.enrol.roster.get(worker).map(|r| r.channel_fp.clone());
            let gone = st.enrol.remove(worker, now);
            if gone {
                st.outbound.remove(worker);
                st.inbound.retain(|m| {
                    m.envelope.from != worker
                        && m.envelope.from.strip_suffix(".fabric") != Some(worker)
                });
                note(st, now, "hub.worker.removed", Some(worker), String::new());
            }
            (gone, fp)
        })?;
        if let Some(fp) = fp {
            self.dir.remove(&fp);
        }
        Ok(gone)
    }

    /// The roster, as the supervisor's hub logic needs it: public keys only.
    pub fn roster(&self) -> Result<Vec<RosterRecord>, String> {
        Ok(self.state()?.enrol.roster.into_values().collect())
    }

    /// Hand over the audit events after `after` (the number of the last one the caller holds) and forget those up to it.
    pub fn audit_since(&self, after: u64) -> Result<Vec<NewEvent>, String> {
        self.update(|st| {
            st.audit
                .retain(|e| e.src.as_ref().is_some_and(|(_, n)| *n > after));
            st.audit.clone()
        })
    }

    // ---- the socket ---------------------------------------------------------------------------------------------------

    /// Answer one request line from the supervisor. Pure apart from the state; a socket calls this.
    pub fn handle_line(&self, line: &str, now: u64) -> String {
        let v: Value = match serde_json::from_str(line) {
            Ok(v) => v,
            Err(_) => return fail("that request is not valid"),
        };
        let op = v["op"].as_str().unwrap_or_default();
        let ok = |r: Value| json!({"ok": true, "result": r}).to_string();
        let refusal =
            |e: Refusal| json!({"ok": false, "code": e.code, "error": e.message}).to_string();
        match op {
            "status" => match self.state() {
                Ok(st) => ok(json!({
                    "identity_fp": self.identity.identity_fp(),
                    "channel_fp": self.identity.channel_fp(),
                    "workers": st.enrol.roster.len(),
                    "pending": st.enrol.pending.len(),
                    "invites": st.enrol.invites.len(),
                    "inbound": st.inbound.len(),
                    "outbound": st.outbound.values().map(VecDeque::len).sum::<usize>(),
                })),
                Err(e) => fail(&e),
            },
            "identity" => ok(json!({
                "identity": self.identity,
                "identity_fp": self.identity.identity_fp(),
                "channel_fp": self.identity.channel_fp(),
            })),
            "roster" => match self.roster() {
                Ok(r) => ok(json!({ "workers": r })),
                Err(e) => fail(&e),
            },
            "invite_plan" => match serde_json::from_value::<InviteSpec>(v["spec"].clone()) {
                Ok(s) => match self.plan_invite(&s) {
                    Ok(p) => ok(json!({ "plan": p })),
                    Err(e) => refusal(e),
                },
                Err(_) => fail("that request is not valid"),
            },
            "invite_apply" => match serde_json::from_value::<InvitePlan>(v["plan"].clone()) {
                Ok(p) => match self.apply_invite(&p, now) {
                    Ok(token) => ok(json!({ "worker": p.worker, "token": token.as_str() })),
                    Err(e) => refusal(e),
                },
                Err(_) => fail("that request is not valid"),
            },
            "enrol_pending" => match self.state() {
                Ok(st) => ok(json!({ "pending": st.enrol.pending.values().map(|p| json!({
                    "worker": p.worker,
                    "box_id": p.attestation.box_id,
                    "provider": p.attestation.provider,
                    "channel_fp": p.identity.channel_fp(),
                    "registrar_fp": p.attestation.registrar_fp,
                })).collect::<Vec<_>>() })),
                Err(e) => fail(&e),
            },
            "enrol_plan" => match self.plan_enrol(v["worker"].as_str().unwrap_or_default()) {
                Ok(p) => ok(json!({ "plan": p })),
                Err(e) => refusal(e),
            },
            "enrol_apply" => match serde_json::from_value::<EnrolPlan>(v["plan"].clone()) {
                Ok(p) => match self.apply_enrol(&p, now) {
                    Ok(r) => ok(json!({ "worker": r })),
                    Err(e) => refusal(e),
                },
                Err(_) => fail("that request is not valid"),
            },
            "worker_remove" => {
                match self.remove_worker(v["worker"].as_str().unwrap_or_default(), now) {
                    Ok(gone) => ok(json!({ "removed": gone })),
                    Err(e) => fail(&e),
                }
            }
            "spool_take" => match self.take_inbound() {
                Ok(m) => ok(json!({ "messages": m })),
                Err(e) => fail(&e),
            },
            "spool_put" => {
                let to = v["to"].as_str().unwrap_or_default();
                match serde_json::from_value::<Vec<Sealed>>(v["messages"].clone()) {
                    Ok(m) => match self.put_outbound(to, m, now) {
                        Ok(n) => ok(json!({ "queued": n })),
                        Err(Rejected(c)) => {
                            json!({"ok": false, "code": c, "error": "the messages were refused"})
                                .to_string()
                        }
                    },
                    Err(_) => fail("that request is not valid"),
                }
            }
            "audit_since" => match self.audit_since(v["after"].as_u64().unwrap_or(0)) {
                Ok(evs) => ok(json!({ "events": evs })),
                Err(e) => fail(&e),
            },
            _ => fail("that operation is not known"),
        }
    }

    /// Serve the supervisor socket until [`Running::stop`]. One short-lived thread per connection, one request per connection.
    pub fn serve(
        self: &Arc<Self>,
        listener: UnixListener,
        socket: Option<PathBuf>,
    ) -> Result<Running, String> {
        let stop = Arc::new(AtomicBool::new(false));
        let (me, flag) = (self.clone(), stop.clone());
        let thread = std::thread::Builder::new()
            .name("ozbox-hubd-socket".into())
            .spawn(move || {
                for c in listener.incoming() {
                    if flag.load(Ordering::SeqCst) {
                        break;
                    }
                    let Ok(c) = c else { continue };
                    let me = me.clone();
                    let _ = std::thread::Builder::new().spawn(move || me.serve_one(c));
                }
            })
            .map_err(|_| "the socket thread could not start".to_string())?;
        Ok(Running {
            stop,
            thread: Some(thread),
            socket,
        })
    }

    fn serve_one(&self, s: UnixStream) {
        let _ = s.set_read_timeout(Some(std::time::Duration::from_secs(30)));
        let mut line = String::new();
        let limit = u64::try_from(TRANSPORT_CAP * 2 + 4096).unwrap_or(u64::MAX);
        if BufReader::new((&s).take(limit))
            .read_line(&mut line)
            .is_err()
            || line.is_empty()
        {
            return;
        }
        let out = self.handle_line(line.trim_end(), now_ms());
        let mut w = &s;
        let _ = w.write_all(out.as_bytes());
        let _ = w.write_all(b"\n");
    }
}

fn service(m: String) -> Refusal {
    Refusal {
        code: crate::enrol::CODE_SERVICE,
        message: m,
    }
}

fn fail(m: &str) -> String {
    json!({"ok": false, "error": m}).to_string()
}

fn note(st: &mut HubdState, now: u64, action: &str, subject: Option<&str>, detail: String) {
    st.audit_n += 1;
    st.audit.push(NewEvent {
        ts_ms: now,
        actor: "hubd".into(),
        action: action.into(),
        subject: subject.map(str::to_string),
        detail,
        src: Some((st.store_id.clone(), st.audit_n)),
    });
    if st.audit.len() > MAX_AUDIT {
        let extra = st.audit.len() - MAX_AUDIT;
        st.audit.drain(..extra);
    }
}

/// Count a refusal; audit it at most once a minute per code, with the count since the last time.
fn refused(st: &mut HubdState, now: u64, code: &'static str) {
    let e = st.refused.entry(code.to_string()).or_insert((0, 0));
    e.0 += 1;
    if now.saturating_sub(e.1) >= REFUSAL_AUDIT_EVERY_MS || e.1 == 0 {
        let n = e.0;
        *e = (0, now);
        note(
            st,
            now,
            "hub.refused",
            None,
            format!("code={code} count={n}"),
        );
    }
}

/// The daemon's socket, running.
pub struct Running {
    stop: Arc<AtomicBool>,
    thread: Option<JoinHandle<()>>,
    socket: Option<PathBuf>,
}

impl Running {
    /// Serve until the process is stopped (systemd's stop ends it).
    pub fn wait(mut self) {
        if let Some(t) = self.thread.take() {
            let _ = t.join();
        }
    }

    /// Stop accepting and wait for the socket's thread. A request already being answered finishes.
    pub fn stop(mut self) {
        self.stop.store(true, Ordering::SeqCst);
        if let Some(p) = &self.socket {
            // wake the accept loop so it sees the flag
            let _ = UnixStream::connect(p);
        }
        if let Some(t) = self.thread.take() {
            let _ = t.join();
        }
    }
}

pub fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| u64::try_from(d.as_millis()).unwrap_or(u64::MAX))
        .unwrap_or(0)
}

/// Read the registrars file. A missing file is no registrar (nothing enrols), never an error that stops the daemon.
pub fn read_registrars(path: &Path) -> Result<Registrars, String> {
    match std::fs::read(path) {
        Ok(b) => serde_json::from_slice::<Registrars>(&b)
            .map_err(|_| "the registrars file is not valid".to_string()),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(Registrars::default()),
        Err(_) => Err("the registrars file could not be read".into()),
    }
}

/// Bind the supervisor socket in a directory of `dir_mode` (what decides who may connect), the socket itself 0660 in the
/// directory's group. Used when systemd did not hand one over.
pub fn bind(path: &Path, dir_mode: u32) -> std::io::Result<UnixListener> {
    use std::os::unix::fs::{MetadataExt, PermissionsExt};
    let dir = path
        .parent()
        .ok_or_else(|| std::io::Error::other("a socket path needs a directory"))?;
    std::fs::create_dir_all(dir)?;
    std::fs::set_permissions(dir, std::fs::Permissions::from_mode(dir_mode))?;
    let gid = std::fs::metadata(dir)?.gid();
    let _ = std::fs::remove_file(path);
    let l = UnixListener::bind(path)?;
    // a group the process may not give it is left as is: the directory's mode still decides who reaches it
    let _ = std::os::unix::fs::chown(path, None, Some(gid));
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o660))?;
    Ok(l)
}

/// A request to the daemon's socket, as the supervisor (or a test) makes it.
pub fn ask(path: &Path, req: &Value) -> Result<Value, String> {
    let mut s =
        UnixStream::connect(path).map_err(|_| "the hub daemon could not be reached".to_string())?;
    let _ = s.set_read_timeout(Some(std::time::Duration::from_secs(30)));
    let mut line = req.to_string();
    line.push('\n');
    s.write_all(line.as_bytes())
        .map_err(|_| "the hub daemon could not be reached".to_string())?;
    let mut out = String::new();
    let limit = u64::try_from(TRANSPORT_CAP * 2 + 4096).unwrap_or(u64::MAX);
    BufReader::new((&s).take(limit))
        .read_line(&mut out)
        .map_err(|_| "the hub daemon could not be reached".to_string())?;
    serde_json::from_str(out.trim_end())
        .map_err(|_| "the hub daemon's answer is not valid".to_string())
}

/// The supervisor's transport to the daemon: what the hub logic sends goes to the outbound spool, what it receives comes from
/// the inbound one. Implements the hub's [`ozbox_core::hub::wire::Transport`], so `HubService` runs over it unchanged.
pub struct SpoolTransport {
    pub socket: PathBuf,
    buf: std::sync::Mutex<VecDeque<Sealed>>,
}

impl SpoolTransport {
    pub fn new(socket: impl Into<PathBuf>) -> SpoolTransport {
        SpoolTransport {
            socket: socket.into(),
            buf: std::sync::Mutex::new(VecDeque::new()),
        }
    }
}

impl ozbox_core::hub::wire::Transport for SpoolTransport {
    fn send(&self, to: &str, msg: Sealed) -> Result<(), ozbox_core::hub::wire::WireError> {
        let v = ask(
            &self.socket,
            &json!({"op": "spool_put", "to": to.strip_suffix(".fabric").unwrap_or(to), "messages": [msg]}),
        )
        .map_err(|_| ozbox_core::hub::wire::WireError::SendFailed)?;
        if v["ok"].as_bool() == Some(true) {
            Ok(())
        } else {
            Err(ozbox_core::hub::wire::WireError::SendFailed)
        }
    }

    fn recv(&self, who: &str) -> Option<Sealed> {
        // the worker channel's endpoint and the fabric's (`<hub>.fabric`) share one spool; each takes only what is addressed to it
        let mut b = self.buf.lock().ok()?;
        if !b.iter().any(|m| m.envelope.to == who) {
            let v = ask(&self.socket, &json!({"op": "spool_take"})).ok()?;
            let msgs: Vec<Sealed> = serde_json::from_value(v["result"]["messages"].clone()).ok()?;
            b.extend(msgs);
        }
        let at = b.iter().position(|m| m.envelope.to == who)?;
        b.remove(at)
    }
}
