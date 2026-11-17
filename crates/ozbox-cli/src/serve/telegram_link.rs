//! Linking a Telegram account and delegating to it (ADR 0050 §2, §6 and decision 2): the dashboard's side.
//!
//! **Pairing is reversed.** A person opens a *pairing window* in the dashboard with a fresh passkey (ten minutes). The bot
//! answers `/link` in a private chat only while a window is open, with a short code. The person types that code into the
//! dashboard; the dashboard shows the account it bound (the tail of the numeric id and the first name the bot saw), and one
//! more passkey assertion confirms the link and, when the person wants it, enables converse in the same step: its challenge is
//! the digest of the link record **and** the delegation record, so neither can be swapped after the touch.
//!
//! Every act here is "challenge, then assertion": the server builds the record, keeps it as a draft, hands the browser the
//! WebAuthn options over the record's digest, and checks the assertion against **that** digest. Nothing is taken from the
//! browser but the assertion. A link or a delegation row is real only while its stored assertion still verifies against a
//! passkey the person still has (`TgStore::link_is_genuine`); a hand-edited file grants nothing.
//!
//! What only makes Telegram less able needs no passkey: lock, unlink, revoke a delegation, lock every link.
//!
//! Nothing in this file can decide an approval, stop a run, raise a limit or touch a secret.

use std::collections::BTreeMap;

use ozbox_core::approval_subject::{from_hex, to_hex};
use ozbox_core::chat_policy::decide::{DelegationFacts, LinkFacts, LinkStatus};
use ozbox_core::chat_policy::records::{
    confirm_digest, cosign_digest, renew_digest, unlock_digest, Caps, DelegatedAct,
    DelegationRecord, LinkRecord, WindowRecord, DELEGATION_DEFAULT_MS, DELEGATION_MAX_MS,
    LINK_TTL_MS, WINDOW_MS,
};
use ozbox_core::roles::Role;
use serde::Deserialize;
use serde_json::{json, Value};

use super::{unix_ms, App, Req, Resp};
use crate::chat::code;
use crate::messages::t;
use crate::notify::{Alert, Severity};
use crate::serve::auth::approval::{SignedApproval, SignedEvidence};
use crate::state::TelegramChat;
use crate::telegram::{ApiBase, Bot, BotInfo};
use crate::telegram_store::{
    BotRef, Counters, Halt, LinkState, Renewal, TgDelegation, TgLink, TgStore,
};
use crate::telegram_transcript::Transcript;

/// How long a draft (a record waiting for its assertion) lives.
const DRAFT_MS: u64 = 10 * 60_000;

/// The window a person opened, with the passkey that opened it.
pub(super) struct OpenWindow {
    pub record: WindowRecord,
    #[allow(dead_code)]
    pub evidence: SignedEvidence,
    /// What the bot answered to `/link`, while a person has not typed it in yet.
    pub offer: Option<Offer>,
    /// A code the dashboard accepted: the account it is for.
    pub candidate: Option<Candidate>,
    pub tries: u32,
}

/// An account that sent `/link` inside the window, and the code the bot answered with (kept as a keyed hash).
pub(super) struct Offer {
    pub from_id: i64,
    pub chat_id: i64,
    pub first_name: String,
    pub tag: String,
}

pub(super) struct Candidate {
    pub from_id: i64,
    pub chat_id: i64,
    pub first_name: String,
}

pub(super) enum DraftKind {
    Window(WindowRecord),
    Link {
        link: LinkRecord,
        delegation: Option<DelegationRecord>,
    },
    Delegation(DelegationRecord),
    Renew {
        new_expires_ms: u64,
    },
    Unlock,
    Cosign,
}

pub(super) struct Draft {
    pub kind: DraftKind,
    pub digest: [u8; 32],
    pub expires_ms: u64,
}

/// The bridge's runtime: what is persisted, what was verified this run, and what is waiting for a passkey.
pub(super) struct TgRt {
    pub store: TgStore,
    pub store_error: Option<String>,
    pub transcript: Option<Transcript>,
    pub transcript_error: Option<String>,
    pub transcript_path: Option<std::path::PathBuf>,
    /// The bot as the vendor described it this run, when its settings were found acceptable.
    pub bot: Option<BotInfo>,
    pub api_base: ApiBase,
    pub window: Option<OpenWindow>,
    pub drafts: BTreeMap<String, Draft>,
    /// The next poll must not start before this (a rate limit or a failure's backoff).
    pub backoff_until_ms: u64,
    pub backoff_step: u32,
    /// How many answers in a row did not parse: the next poll asks for one update.
    pub parse_failures: u32,
    /// Messages carrying a pointer link, to be deleted when it lapses: (chat, message id, expires).
    pub handoff_msgs: Vec<(i64, i64, u64)>,
    /// What the bridge said, as structured messages (catalogue key and arguments), newest last and bounded. The rendering of a
    /// key may change; what was said does not. Tests and the transcript view read it.
    pub said: std::collections::VecDeque<super::telegram_acts::Said>,
    /// Box changes started from a chat, waiting for their job to finish so the chat can be told.
    pub power_jobs: Vec<super::telegram_acts::PowerJob>,
    /// Messages addressed to boxes and sessions, and where each copy stands.
    pub deliveries: Vec<super::telegram_acts::Tracked>,
    /// The folder `ozbox chat lock` and `ozbox chat unlink` leave their requests in (the state's own folder).
    pub requests_dir: Option<std::path::PathBuf>,
}

impl TgRt {
    pub fn in_memory() -> Self {
        TgRt {
            store: TgStore::in_memory(),
            store_error: None,
            transcript: None,
            transcript_error: None,
            transcript_path: None,
            bot: None,
            api_base: ApiBase::from_env(std::env::var("OZBOX_TELEGRAM_API_BASE").ok().as_deref()),
            window: None,
            drafts: BTreeMap::new(),
            backoff_until_ms: 0,
            backoff_step: 0,
            parse_failures: 0,
            handoff_msgs: Vec::new(),
            said: std::collections::VecDeque::new(),
            power_jobs: Vec::new(),
            deliveries: Vec::new(),
            requests_dir: None,
        }
    }

    /// The store and the transcript live beside the server's state file.
    pub fn beside(state: &std::path::Path) -> Self {
        let mut rt = Self::in_memory();
        match TgStore::open(state.with_file_name("telegram.json")) {
            Ok(s) => rt.store = s,
            Err(e) => rt.store_error = Some(e),
        }
        rt.transcript_path = Some(state.with_file_name("telegram-transcript.jsonl"));
        rt.requests_dir = state.parent().map(std::path::Path::to_path_buf);
        rt
    }
}

fn random_hex(n: usize) -> Result<String, String> {
    super::random_hex(n)
}

fn tail4(id: i64) -> String {
    let s = id.to_string();
    let t: String = s
        .chars()
        .rev()
        .take(4)
        .collect::<Vec<_>>()
        .into_iter()
        .rev()
        .collect();
    format!("…{t}")
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Assertion {
    assertion: Value,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct CodeBody {
    code: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ConverseWish {
    boxes: Vec<String>,
    #[serde(default)]
    days: Option<u64>,
    #[serde(default)]
    hub_ack: bool,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct LinkWish {
    label: String,
    #[serde(default)]
    converse: Option<ConverseWish>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct DelegationWish {
    acts: Vec<String>,
    boxes: Vec<String>,
    #[serde(default)]
    days: Option<u64>,
    #[serde(default)]
    hub_ack: bool,
    /// The caps of a power delegation (ADR 0050 §3); left out, the defaults ($10 a day, no create or resize).
    #[serde(default)]
    caps: Option<CapsWish>,
}

#[derive(Deserialize, Default)]
#[serde(deny_unknown_fields)]
struct CapsWish {
    #[serde(default)]
    max_size: Option<String>,
    #[serde(default)]
    daily_usd: Option<u32>,
    #[serde(default)]
    creates_per_day: Option<u32>,
    #[serde(default)]
    resumes_per_day: Option<u32>,
    #[serde(default)]
    running: Option<u32>,
}

fn parse<T: for<'de> Deserialize<'de>>(req: &Req) -> Result<T, Resp> {
    serde_json::from_slice(&req.body)
        .map_err(|e| Resp::error(400, "bad_request", &format!("invalid request: {e}")))
}

impl App {
    // ---------- who, and what is genuine ----------

    /// The signed-in person and their role. Linking Telegram needs a sign-in with a passkey: there is nobody to bind to, and
    /// nothing to sign with, on a dashboard that has neither.
    fn tg_who(&self, req: &Req) -> Result<(String, Role), Resp> {
        let Some(auth) = self.auth.as_ref() else {
            return Err(Resp::error(
                403,
                "no_sign_in",
                "linking Telegram needs a dashboard with a sign-in and a passkey: the passkey is what makes a link and a delegation yours",
            ));
        };
        auth.who_and_role(req)
            .ok_or_else(|| Resp::error(403, "no_sign_in", "sign in first"))
    }

    pub(super) fn tg_ready(&self) -> Result<(), Resp> {
        if let Some(e) = &self.tg.store_error {
            return Err(Resp::error(503, "telegram_store", e));
        }
        Ok(())
    }

    /// Whether a link's own record and its confirming assertion are real, as of now.
    pub(super) fn tg_link_genuine(&self, l: &TgLink) -> bool {
        let Some(auth) = self.auth.as_ref() else {
            return false;
        };
        self.tg
            .store
            .link_is_genuine(l, &|ev, ch| auth.verify_evidence(ev, ch))
    }

    /// The end of a link: its own, or a renewal's when the renewal is real.
    pub(super) fn tg_link_expires(&self, l: &TgLink) -> u64 {
        let own = l.record.expires_ms;
        let (Some(r), Some(auth)) = (&l.renewed, self.auth.as_ref()) else {
            return own;
        };
        match renew_digest(&l.record, r.expires_ms) {
            Ok(d) if r.signed.person == l.record.person && auth.verify_evidence(&r.signed, &d) => {
                r.expires_ms.max(own)
            }
            _ => own,
        }
    }

    /// Whether a delegation row is real, and (when `owner_needed`) has an owner's assertion behind it as well.
    fn tg_delegation_backed(&self, d: &TgDelegation, owner_needed: bool) -> bool {
        let Some(auth) = self.auth.as_ref() else {
            return false;
        };
        self.tg.store.delegation_is_genuine(
            d,
            owner_needed,
            &|ev, ch| auth.verify_evidence(ev, ch),
            &|p| auth.role_opt(p) == Some(Role::Owner),
        )
    }

    /// A delegation the person's own passkey stands behind. Whether it also needs an owner's is a separate question
    /// (`owner_cosigned` in the facts), so a member's delegation that waits for an owner says so instead of looking absent.
    pub(super) fn tg_delegation_genuine(&self, d: &TgDelegation) -> bool {
        self.tg_delegation_backed(d, false)
    }

    /// The facts the policy needs about one link: its state, and the delegations whose signatures verify now.
    pub(super) fn tg_facts(&self, l: &TgLink) -> (LinkFacts, Vec<DelegationFacts>) {
        let status = match l.state {
            LinkState::Active => LinkStatus::Active,
            LinkState::Locked => LinkStatus::Locked,
            LinkState::Revoked => LinkStatus::Revoked,
        };
        let facts = LinkFacts {
            status,
            created_ms: l.record.created_ms,
            expires_ms: self.tg_link_expires(l),
        };
        let delegations = self
            .tg
            .store
            .delegations_of(&l.record.id)
            .filter(|d| self.tg_delegation_genuine(d))
            .map(|d| DelegationFacts {
                digest: d.digest.clone(),
                acts: d.record.acts.clone(),
                boxes: d.record.boxes.clone(),
                not_before_ms: d.record.not_before_ms,
                expires_ms: d.record.expires_ms,
                issued_ms: d.issued_ms,
                last_used_ms: d.last_used_ms,
                hub_ack: d.record.hub_ack,
                with_link: d.record.with_link,
                owner_cosigned: self.tg_delegation_backed(d, true),
            })
            .collect();
        (facts, delegations)
    }

    // ---------- the chain, the transcript, the people ----------

    pub(super) fn tg_chain(&self, person: &str, action: &str, subject: Option<&str>, detail: &str) {
        self.chain_event(
            &format!("person:{person}:chat:telegram"),
            action,
            subject,
            detail,
        );
    }

    /// The transcript, opened the first time it is needed. `None` (with the reason kept) when the secret store cannot hold its
    /// key: the bridge then does nothing it cannot record.
    pub(super) fn tg_transcript(&mut self, now: u64) -> Option<&Transcript> {
        if self.tg.transcript.is_none() {
            match Transcript::open(self.tg.transcript_path.clone(), self.secrets.as_ref(), now) {
                Ok(t) => {
                    self.tg.transcript = Some(t);
                    self.tg.transcript_error = None;
                }
                Err(e) => self.tg.transcript_error = Some(e),
            }
        }
        self.tg.transcript.as_ref()
    }

    /// Whether a person may act on a link: their own, or any when they are an owner.
    fn tg_may_touch(&self, req: &Req, link: &TgLink) -> Result<(String, Role), Resp> {
        let (who, role) = self.tg_who(req)?;
        if link.record.person == who || role == Role::Owner {
            Ok((who, role))
        } else {
            // absent and not-permitted read alike
            Err(Resp::error(404, "not_found", "no such link"))
        }
    }

    /// Put the bot's reachable state in `tg` once: who it is, and that its settings are acceptable.
    fn tg_bot_now(&mut self) -> Result<BotInfo, Resp> {
        if let Some(b) = &self.tg.bot {
            return Ok(b.clone());
        }
        let token = match self.secrets.get("telegram-bot-token") {
            Ok(Some(t)) => t,
            _ => {
                return Err(Resp::error(
                    409,
                    "no_token",
                    "paste the bot token first (Settings, Apps)",
                ))
            }
        };
        let info = Bot::new(self.http.as_ref(), &token, &self.tg.api_base)
            .get_me()
            .map_err(|e| {
                Resp::error(
                    502,
                    "telegram_unavailable",
                    &crate::telegram::redact(&e.to_string(), &token),
                )
            })?;
        let problems = info.problems();
        if !problems.is_empty() {
            return Err(Resp::error(
                409,
                "bot_settings",
                &t("tg.halted_bot_settings", &[("what", &problems.join(", "))]),
            ));
        }
        self.tg.store.data.bot = Some(BotRef {
            id: info.id,
            username: info.username.clone(),
        });
        self.tg.bot = Some(info.clone());
        Ok(info)
    }

    fn tg_draft_take(&mut self, key: &str, now: u64) -> Result<Draft, Resp> {
        self.tg.drafts.retain(|_, d| d.expires_ms > now);
        self.tg.drafts.remove(key).ok_or_else(|| {
            Resp::error(
                409,
                "no_pending",
                "that step has lapsed or was already done: start it again",
            )
        })
    }

    /// Offer the browser a passkey check over `digest`.
    fn tg_options(&self, req: &Req, digest: &[u8; 32]) -> Result<Value, Resp> {
        let Some(auth) = self.auth.as_ref() else {
            return Err(Resp::error(403, "no_sign_in", "sign in first"));
        };
        auth.approval_options(req, digest)
            .map_err(|(s, c, m)| Resp::error(s, c, &m))
    }

    fn tg_assert(
        &self,
        req: &Req,
        digest: &[u8; 32],
        assertion: &Value,
    ) -> Result<SignedApproval, Resp> {
        let Some(auth) = self.auth.as_ref() else {
            return Err(Resp::error(403, "no_sign_in", "sign in first"));
        };
        auth.approval_assertion(req, digest, assertion)
            .map_err(|(s, c, m)| Resp::error(s, c, &m))
    }

    fn tg_alert(&mut self, key: &str, title: &str, body: &str, severity: Severity, now: u64) {
        let alert = Alert {
            key: key.to_string(),
            kind: "telegram".into(),
            severity,
            box_name: None,
            title: title.to_string(),
            body: body.to_string(),
            ts_ms: now,
        };
        self.route_alerts(vec![alert], now);
    }

    // ---------- routes ----------

    pub(super) fn telegram_route(&mut self, req: &Req, rest: &[&str]) -> Resp {
        let now = unix_ms();
        let post = req.method == "POST";
        let get = req.method == "GET";
        let del = req.method == "DELETE";
        match rest {
            [] if get => self.tg_status(req, now),
            ["window", "challenge"] if post => self.tg_window_challenge(req, now),
            ["window"] if post => self.tg_window_open(req, now),
            ["window"] if del => self.tg_window_close(req),
            ["link", "candidate"] if post => self.tg_candidate(req, now),
            ["link", "challenge"] if post => self.tg_link_challenge(req, now),
            ["link"] if post => self.tg_link_confirm(req, now),
            ["links", id, "lock"] if post => self.tg_link_lock(req, id, now),
            ["links", id, "unlock", "challenge"] if post => self.tg_unlock_challenge(req, id, now),
            ["links", id, "unlock"] if post => self.tg_unlock(req, id, now),
            ["links", id, "renew", "challenge"] if post => self.tg_renew_challenge(req, id, now),
            ["links", id, "renew"] if post => self.tg_renew(req, id, now),
            ["links", id, "delegations", "challenge"] if post => {
                self.tg_delegation_challenge(req, id, now)
            }
            ["links", id, "delegations"] if post => self.tg_delegation_create(req, id, now),
            ["links", id, "transcript"] if get => self.tg_transcript_route(req, id, now),
            ["links", id] if del => self.tg_link_unlink(req, id, now),
            ["delegations", id] if del => self.tg_delegation_revoke(req, id, now),
            ["delegations", id, "cosign", "challenge"] if post => {
                self.tg_cosign_challenge(req, id, now)
            }
            ["delegations", id, "cosign"] if post => self.tg_cosign(req, id, now),
            ["lock-all"] if post => self.tg_lock_all(req, now),
            ["resume"] if post => self.tg_resume(req, now),
            ["marks"] if req.method == "PUT" => self.tg_marks(req),
            _ => Resp::error(404, "not_found", "no such endpoint"),
        }
    }

    fn tg_link_view(&self, l: &TgLink, now: u64) -> Value {
        let genuine = self.tg_link_genuine(l);
        let delegations: Vec<Value> = self
            .tg
            .store
            .data
            .delegations
            .iter()
            .filter(|d| d.record.link_id == l.record.id)
            .map(|d| self.tg_delegation_view(d, l, now))
            .collect();
        json!({
            "id": l.record.id, "person": l.record.person, "label": l.record.label,
            "account": tail4(l.record.telegram_id),
            "state": if genuine { match l.state { LinkState::Active => "active", LinkState::Locked => "locked", LinkState::Revoked => "revoked" } } else { "not_genuine" },
            "created_ms": l.record.created_ms, "expires_ms": self.tg_link_expires(l),
            "last_seen_ms": l.last_seen_ms, "ended": l.ended,
            "delegations": delegations,
        })
    }

    fn tg_delegation_view(&self, d: &TgDelegation, l: &TgLink, now: u64) -> Value {
        let genuine = self.tg_delegation_genuine(d);
        let role = self
            .auth
            .as_ref()
            .and_then(|a| a.role_opt(&d.record.person));
        let pending_owner = role == Some(Role::Member) && d.owner.is_none();
        let last = d.last_used_ms.max(d.issued_ms);
        let state = if d.revoked {
            "revoked"
        } else if pending_owner {
            "pending_owner"
        } else if !genuine {
            "not_genuine"
        } else if now >= d.record.expires_ms {
            "expired"
        } else if now.saturating_sub(last)
            > ozbox_core::chat_policy::records::DELEGATION_UNUSED_LAPSE_MS
        {
            "lapsed"
        } else if now < d.record.not_before_ms {
            "not_yet"
        } else if !d.record.with_link
            && now < l.record.created_ms + ozbox_core::chat_policy::records::NEW_LINK_WAIT_MS
        {
            "waiting"
        } else {
            "active"
        };
        json!({
            "id": d.record.id, "acts": d.record.acts.iter().map(|a| a.name()).collect::<Vec<_>>(),
            "boxes": d.record.boxes, "issued_ms": d.issued_ms, "expires_ms": d.record.expires_ms,
            "last_used_ms": d.last_used_ms, "state": state, "hub_ack": d.record.hub_ack,
            "with_link": d.record.with_link,
        })
    }

    fn tg_status(&mut self, req: &Req, now: u64) -> Resp {
        let who = self.auth.as_ref().and_then(|a| a.who_and_role(req));
        let (person, role) = match &who {
            Some((p, r)) => (p.clone(), *r),
            None => ("owner".to_string(), Role::Owner),
        };
        let a = &self.settings.apps.telegram;
        let links: Vec<Value> = self
            .tg
            .store
            .data
            .links
            .iter()
            .filter(|l| role == Role::Owner || l.record.person == person)
            .map(|l| self.tg_link_view(l, now))
            .collect();
        let pending: Vec<Value> = if role == Role::Owner {
            self.tg
                .store
                .data
                .delegations
                .iter()
                .filter(|d| !d.revoked && d.owner.is_none())
                .filter(|d| self.auth.as_ref().and_then(|x| x.role_opt(&d.record.person)) == Some(Role::Member))
                .map(|d| json!({ "id": d.record.id, "person": d.record.person, "boxes": d.record.boxes, "acts": d.record.acts.iter().map(|a| a.name()).collect::<Vec<_>>(), "expires_ms": d.record.expires_ms }))
                .collect()
        } else {
            Vec::new()
        };
        let window = self.tg.window.as_ref().filter(|w| w.record.expires_ms > now).map(|w| {
            json!({
                "person": w.record.person, "expires_in_s": w.record.expires_ms.saturating_sub(now) / 1000,
                "code_offered": w.offer.is_some(), "account_found": w.candidate.is_some(),
                "account": w.candidate.as_ref().map(|c| json!({ "id_tail": tail4(c.from_id), "first_name": c.first_name })),
            })
        });
        let halted =
            self.tg.store.data.halted.as_ref().map(
                |h| json!({ "code": h.code, "since_ms": h.since_ms, "message": halt_message(h) }),
            );
        let legacy: Vec<Value> = self
            .state
            .telegram
            .chats
            .iter()
            .filter(|c| {
                !self
                    .tg
                    .store
                    .data
                    .links
                    .iter()
                    .any(|l| l.record.chat_id == c.id)
            })
            .filter(|c| role == Role::Owner || c.person.as_deref().unwrap_or("owner") == person)
            .map(|c| json!({ "id": c.id, "name": c.name, "person": c.person }))
            .collect();
        Resp::json(
            200,
            &json!({
                "me": person,
                "enabled": a.enabled,
                "signed_in": who.is_some(),
                "needs_sign_in": self.auth.is_none(),
                "public_address": self.chat_public_base().is_some(),
                "bot": self.tg.store.data.bot.as_ref().map(|b| format!("@{}", b.username)),
                "running": a.enabled && self.tg.bot.is_some() && self.tg.store.data.halted.is_none(),
                "halted": halted,
                "store_error": self.tg.store_error,
                "transcript_error": self.tg.transcript_error,
                "window": window,
                "links": links,
                "legacy_chats": legacy,
                "pending_owner": pending,
                "counters": counters_json(&self.tg.store.data.counters),
                "marks": self.tg.store.data.marks,
                "wait_hours": ozbox_core::chat_policy::records::NEW_LINK_WAIT_MS / 3_600_000,
            }),
        )
    }

    // ---------- the pairing window ----------

    fn tg_window_challenge(&mut self, req: &Req, now: u64) -> Resp {
        if let Err(r) = self.tg_ready() {
            return r;
        }
        let (person, _) = match self.tg_who(req) {
            Ok(x) => x,
            Err(r) => return r,
        };
        if !self.settings.apps.telegram.enabled {
            return Resp::error(
                409,
                "telegram_off",
                "turn Telegram on first (Settings, Apps)",
            );
        }
        let bot = match self.tg_bot_now() {
            Ok(b) => b,
            Err(r) => return r,
        };
        let nonce = match random_hex(8) {
            Ok(n) => n,
            Err(e) => return Resp::error(500, "internal", &e),
        };
        let record = WindowRecord {
            person: person.clone(),
            bot_id: bot.id,
            nonce,
            opened_ms: now,
            expires_ms: now + WINDOW_MS,
        };
        let Ok(digest) = record.digest() else {
            return Resp::error(500, "internal", "the window could not be made");
        };
        let options = match self.tg_options(req, &digest) {
            Ok(o) => o,
            Err(r) => return r,
        };
        self.tg.drafts.insert(
            format!("{person}:window"),
            Draft {
                kind: DraftKind::Window(record),
                digest,
                expires_ms: now + DRAFT_MS,
            },
        );
        Resp::json(
            200,
            &json!({ "options": options, "bot": format!("@{}", bot.username), "window_minutes": WINDOW_MS / 60_000 }),
        )
    }

    fn tg_window_open(&mut self, req: &Req, now: u64) -> Resp {
        let b: Assertion = match parse(req) {
            Ok(b) => b,
            Err(r) => return r,
        };
        let (person, _) = match self.tg_who(req) {
            Ok(x) => x,
            Err(r) => return r,
        };
        let draft = match self.tg_draft_take(&format!("{person}:window"), now) {
            Ok(d) => d,
            Err(r) => return r,
        };
        let DraftKind::Window(record) = draft.kind else {
            return Resp::error(409, "no_pending", "start again");
        };
        let signed = match self.tg_assert(req, &draft.digest, &b.assertion) {
            Ok(s) => s,
            Err(r) => return r,
        };
        let bot = self.tg.bot.as_ref().map(|b| format!("@{}", b.username));
        self.tg.window = Some(OpenWindow {
            record,
            evidence: signed.evidence(now),
            offer: None,
            candidate: None,
            tries: 0,
        });
        self.schedule.next_telegram_ms = 0;
        self.tg_chain(
            &person,
            "telegram.window_open",
            None,
            "pairing window open, ten minutes, passkey",
        );
        self.log_activity("open telegram pairing window", "-", None, "opened");
        Resp::json(
            200,
            &json!({ "bot": bot, "expires_in_s": WINDOW_MS / 1000 }),
        )
    }

    fn tg_window_close(&mut self, req: &Req) -> Resp {
        let (person, _) = match self.tg_who(req) {
            Ok(x) => x,
            Err(r) => return r,
        };
        if self
            .tg
            .window
            .as_ref()
            .is_some_and(|w| w.record.person == person)
        {
            self.tg.window = None;
        }
        Resp::json(200, &json!({ "closed": true }))
    }

    /// The bot heard `/link` in a private chat while a window is open: answer with a code (kept as a keyed hash).
    pub(super) fn tg_offer_code(
        &mut self,
        from_id: i64,
        chat_id: i64,
        first_name: &str,
        sent_ms: u64,
        now: u64,
    ) -> Option<String> {
        let w = self.tg.window.as_mut()?;
        if now >= w.record.expires_ms {
            self.tg.window = None;
            return None;
        }
        // a message written before the window opened is not pairing traffic: the bot answers only while a window is open
        // (Telegram dates a message to the second)
        if sent_ms + 1_000 < w.record.opened_ms {
            return None;
        }
        // the first account to ask holds the offer until it is used or lapses; the same account may ask again
        if w.offer.as_ref().is_some_and(|o| o.from_id != from_id) || w.candidate.is_some() {
            return None;
        }
        let p = code::new_pairing(now).ok()?;
        let tag =
            crate::tokenmac::key_of(&format!("tg-pair\u{0}{}\u{0}{}", w.record.nonce, p.code));
        let text = t("tg.link_code", &[("code", &p.code)]);
        w.offer = Some(Offer {
            from_id,
            chat_id,
            first_name: first_name.to_string(),
            tag,
        });
        Some(text)
    }

    fn tg_candidate(&mut self, req: &Req, now: u64) -> Resp {
        let b: CodeBody = match parse(req) {
            Ok(b) => b,
            Err(r) => return r,
        };
        let (person, _) = match self.tg_who(req) {
            Ok(x) => x,
            Err(r) => return r,
        };
        let Some(w) = self
            .tg
            .window
            .as_mut()
            .filter(|w| w.record.person == person && w.record.expires_ms > now)
        else {
            return Resp::error(409, "no_window", "open a pairing window first");
        };
        let Some(offer) = w.offer.as_ref() else {
            return Resp::error(
                409,
                "no_code",
                "send /link to the bot first: it answers with the code",
            );
        };
        w.tries += 1;
        let guess = b.code.trim().to_ascii_uppercase();
        let tag = crate::tokenmac::key_of(&format!("tg-pair\u{0}{}\u{0}{guess}", w.record.nonce));
        if tag.len() != offer.tag.len()
            || tag
                .bytes()
                .zip(offer.tag.bytes())
                .fold(0u8, |a, (x, y)| a | (x ^ y))
                != 0
        {
            if w.tries >= code::MAX_TRIES {
                self.tg.window = None;
                return Resp::error(
                    429,
                    "window_closed",
                    "too many wrong codes: the pairing window is closed. Open a new one",
                );
            }
            return Resp::error(400, "bad_code", "that code did not work");
        }
        let cand = Candidate {
            from_id: offer.from_id,
            chat_id: offer.chat_id,
            first_name: offer.first_name.clone(),
        };
        let view = json!({ "id_tail": tail4(cand.from_id), "first_name": cand.first_name });
        w.candidate = Some(cand);
        w.offer = None;
        Resp::json(200, &json!({ "account": view }))
    }

    // ---------- the link ----------

    fn tg_boxes_ok(&self, boxes: &[String]) -> Result<Vec<String>, Resp> {
        let mut v: Vec<String> = boxes.iter().map(|b| b.trim().to_string()).collect();
        v.sort();
        v.dedup();
        let known: Vec<String> = self
            .provider
            .list()
            .map(|r| r.iter().map(|b| b.spec.name.to_string()).collect::<Vec<_>>())
            .unwrap_or_default()
            .into_iter()
            // a worker box of a hub, reached over the hub's channel, may be delegated too
            .chain(self.remote_agents.workers().into_iter().map(|w| w.name))
            .collect();
        if v.is_empty() || v.len() > ozbox_core::chat_policy::records::MAX_DELEGATED_BOXES {
            return Err(Resp::error(
                400,
                "bad_request",
                "pick between 1 and 32 boxes",
            ));
        }
        for b in &v {
            if !ozbox_core::chat_policy::acts::box_name_ok(b) || !known.contains(b) {
                return Err(Resp::error(
                    400,
                    "bad_request",
                    &format!("there is no box called {b}"),
                ));
            }
        }
        Ok(v)
    }

    fn tg_days_ms(days: Option<u64>) -> Result<u64, Resp> {
        match days {
            None => Ok(DELEGATION_DEFAULT_MS),
            Some(d) if (1..=30).contains(&d) => Ok(d * 24 * 3_600_000),
            Some(_) => Err(Resp::error(
                400,
                "bad_request",
                "a delegation lasts between 1 and 30 days",
            )),
        }
    }

    fn tg_need_address(&self) -> Result<(), Resp> {
        if self.chat_public_base().is_some() {
            Ok(())
        } else {
            Err(Resp::error(
                409,
                "no_address",
                "no address: Telegram cannot hand you to the dashboard, so nothing beyond reading can be delegated until this dashboard has a public address",
            ))
        }
    }

    fn tg_link_challenge(&mut self, req: &Req, now: u64) -> Resp {
        if let Err(r) = self.tg_ready() {
            return r;
        }
        let b: LinkWish = match parse(req) {
            Ok(b) => b,
            Err(r) => return r,
        };
        let (person, role) = match self.tg_who(req) {
            Ok(x) => x,
            Err(r) => return r,
        };
        if role == Role::Viewer {
            return Resp::error(403, "forbidden", "a viewer cannot link a chat");
        }
        let Some(bot) = self.tg.bot.clone() else {
            return Resp::error(409, "no_window", "open a pairing window first");
        };
        let Some(cand) = self
            .tg
            .window
            .as_ref()
            .filter(|w| w.record.person == person && w.record.expires_ms > now)
            .and_then(|w| w.candidate.as_ref())
        else {
            return Resp::error(409, "no_candidate", "type the code the bot sent first");
        };
        let (from_id, chat_id) = (cand.from_id, cand.chat_id);
        let label: String = b.label.trim().chars().take(40).collect();
        let id = match random_hex(6) {
            Ok(i) => i,
            Err(e) => return Resp::error(500, "internal", &e),
        };
        let link = LinkRecord {
            id: id.clone(),
            person: person.clone(),
            telegram_id: from_id,
            chat_id,
            bot_id: bot.id,
            label: if label.is_empty() {
                "my phone".into()
            } else {
                label
            },
            created_ms: now,
            expires_ms: now + LINK_TTL_MS,
        };
        let delegation = match &b.converse {
            None => None,
            Some(c) => {
                if let Err(r) = self.tg_need_address() {
                    return r;
                }
                let boxes = match self.tg_boxes_ok(&c.boxes) {
                    Ok(v) => v,
                    Err(r) => return r,
                };
                let life = match Self::tg_days_ms(c.days) {
                    Ok(l) => l,
                    Err(r) => return r,
                };
                Some(DelegationRecord {
                    id: match random_hex(6) {
                        Ok(i) => i,
                        Err(e) => return Resp::error(500, "internal", &e),
                    },
                    link_id: id,
                    person: person.clone(),
                    telegram_id: from_id,
                    bot_id: bot.id,
                    boxes,
                    acts: vec![DelegatedAct::Converse],
                    caps: Caps::default(),
                    not_before_ms: now,
                    expires_ms: now + life,
                    hub_ack: c.hub_ack,
                    with_link: true,
                })
            }
        };
        let digest = match confirm_digest(&link, delegation.as_ref()) {
            Ok(d) => d,
            Err(e) => return Resp::error(400, "bad_request", &e.to_string()),
        };
        let options = match self.tg_options(req, &digest) {
            Ok(o) => o,
            Err(r) => return r,
        };
        let summary = json!({
            "account": tail4(from_id), "label": link.label, "expires_ms": link.expires_ms,
            "converse": delegation.as_ref().map(|d| json!({ "boxes": d.boxes, "expires_ms": d.expires_ms })),
            "needs_owner": delegation.is_some() && role == Role::Member,
        });
        self.tg.drafts.insert(
            format!("{person}:link"),
            Draft {
                kind: DraftKind::Link { link, delegation },
                digest,
                expires_ms: now + DRAFT_MS,
            },
        );
        Resp::json(200, &json!({ "options": options, "summary": summary }))
    }

    fn tg_link_confirm(&mut self, req: &Req, now: u64) -> Resp {
        let b: Assertion = match parse(req) {
            Ok(b) => b,
            Err(r) => return r,
        };
        let (person, _) = match self.tg_who(req) {
            Ok(x) => x,
            Err(r) => return r,
        };
        let draft = match self.tg_draft_take(&format!("{person}:link"), now) {
            Ok(d) => d,
            Err(r) => return r,
        };
        let DraftKind::Link { link, delegation } = draft.kind else {
            return Resp::error(409, "no_pending", "start again");
        };
        let signed = match self.tg_assert(req, &draft.digest, &b.assertion) {
            Ok(s) => s,
            Err(r) => return r,
        };
        let evidence = signed.evidence(now);
        let (Ok(ld), dd) = (link.digest(), delegation.as_ref().map(|d| d.digest())) else {
            return Resp::error(500, "internal", "the link could not be made");
        };
        let dd = match dd {
            Some(Ok(d)) => Some(d),
            Some(Err(e)) => return Resp::error(400, "bad_request", &e.to_string()),
            None => None,
        };
        // replace an older link of the same account on this bot: one account, one link
        let before = self.tg.store.data.clone();
        for old in self.tg.store.data.links.iter_mut().filter(|l| {
            l.record.bot_id == link.bot_id
                && l.record.telegram_id == link.telegram_id
                && l.state != LinkState::Revoked
        }) {
            old.state = LinkState::Revoked;
            old.changed_ms = Some(now);
            old.ended = Some("replaced".into());
        }
        let lid = link.id.clone();
        self.tg.store.data.links.push(TgLink {
            record: link.clone(),
            digest: to_hex(&ld),
            signed: evidence,
            confirm_with: dd.as_ref().map(|d| to_hex(d)),
            state: LinkState::Active,
            last_seen_ms: now,
            changed_ms: None,
            renewed: None,
            unlocked_ms: None,
            ended: None,
        });
        if let (Some(d), Some(dd)) = (delegation, dd) {
            self.tg.store.data.delegations.push(TgDelegation {
                record: d,
                digest: to_hex(&dd),
                signed: None,
                owner: None,
                issued_ms: now,
                last_used_ms: 0,
                revoked: false,
            });
        }
        if let Err(e) = self.tg.store.save() {
            self.tg.store.data = before;
            return Resp::error(500, "telegram_store", &e);
        }
        // the chat now receives the alerts a person's rules send to Telegram
        self.state.telegram.chats.retain(|c| c.id != link.chat_id);
        self.state.telegram.chats.push(TelegramChat {
            id: link.chat_id,
            name: link.label.clone(),
            person: Some(person.clone()),
        });
        self.save_state();
        self.tg.window = None;
        self.tg_chain(
            &person,
            "telegram.link",
            Some(&lid),
            &format!("linked, passkey, acct={}", tail4(link.telegram_id)),
        );
        self.log_activity("link telegram chat", "-", None, "linked with a passkey");
        self.tg_alert(
            &format!("tg-link:{lid}"),
            "A Telegram account was linked",
            &format!(
                "{person} linked Telegram account {} as {}.",
                tail4(link.telegram_id),
                link.label
            ),
            Severity::Normal,
            now,
        );
        self.tg_say(link.chat_id, t("tg.linked", &[("label", &link.label)]), now);
        let view = self.tg.store.link(&lid).map(|l| self.tg_link_view(l, now));
        Resp::json(200, &json!({ "link": view }))
    }

    // ---------- lock, unlock, unlink, renew ----------

    /// Lock a link: it reads and nothing else until a passkey lifts it. Needs no passkey: it only makes Telegram less able.
    pub(super) fn tg_do_lock(&mut self, id: &str, by: &str, now: u64) -> bool {
        let Some(l) = self.tg.store.link_mut(id) else {
            return false;
        };
        if l.state == LinkState::Revoked {
            return false;
        }
        l.state = LinkState::Locked;
        l.changed_ms = Some(now);
        let person = l.record.person.clone();
        let _ = self.tg.store.save();
        self.tg_chain(
            &person,
            "telegram.lock",
            Some(id),
            &format!("locked by {by}"),
        );
        true
    }

    /// End a link and everything delegated to it. Takes effect on the next message.
    pub(super) fn tg_do_revoke(&mut self, id: &str, why: &str, now: u64) -> bool {
        let Some(l) = self.tg.store.link_mut(id) else {
            return false;
        };
        if l.state == LinkState::Revoked {
            return false;
        }
        l.state = LinkState::Revoked;
        l.changed_ms = Some(now);
        l.ended = Some(why.to_string());
        let (person, chat_id) = (l.record.person.clone(), l.record.chat_id);
        for d in self
            .tg
            .store
            .data
            .delegations
            .iter_mut()
            .filter(|d| d.record.link_id == id)
        {
            d.revoked = true;
        }
        let _ = self.tg.store.save();
        // the chat stops receiving alerts, and forgets what it followed
        self.state.telegram.chats.retain(|c| c.id != chat_id);
        self.state
            .chat
            .binds
            .remove(&crate::chat::gateway::conv_key(
                crate::chat::gateway::Channel::Telegram,
                &chat_id.to_string(),
            ));
        self.save_state();
        // a pending link, a pairing and a queued message for it are void
        self.tg
            .drafts
            .retain(|k, _| !k.starts_with(&format!("{person}:")));
        self.tg_forget_handoffs(chat_id, now);
        self.tg_chain(&person, "telegram.unlink", Some(id), why);
        self.log_activity("unlink telegram chat", "-", None, why);
        true
    }

    fn tg_link_lock(&mut self, req: &Req, id: &str, now: u64) -> Resp {
        let Some(l) = self.tg.store.link(id).cloned() else {
            return Resp::error(404, "not_found", "no such link");
        };
        let (who, _) = match self.tg_may_touch(req, &l) {
            Ok(x) => x,
            Err(r) => return r,
        };
        if !self.tg_do_lock(id, &who, now) {
            return Resp::error(404, "not_found", "no such link");
        }
        Resp::json(
            200,
            &json!({ "link": self.tg.store.link(id).map(|l| self.tg_link_view(l, now)) }),
        )
    }

    fn tg_link_unlink(&mut self, req: &Req, id: &str, now: u64) -> Resp {
        let Some(l) = self.tg.store.link(id).cloned() else {
            return Resp::error(404, "not_found", "no such link");
        };
        let (who, _) = match self.tg_may_touch(req, &l) {
            Ok(x) => x,
            Err(r) => return r,
        };
        let why = if who == l.record.person {
            "revoked_by_person"
        } else {
            "revoked_by_owner"
        };
        if !self.tg_do_revoke(id, why, now) {
            return Resp::error(404, "not_found", "no such link");
        }
        Resp::json(200, &json!({ "removed": true }))
    }

    fn tg_lock_all(&mut self, req: &Req, now: u64) -> Resp {
        let (who, role) = match self.tg_who(req) {
            Ok(x) => x,
            Err(r) => return r,
        };
        if role != Role::Owner {
            return Resp::error(403, "forbidden", "only an owner can lock every link");
        }
        let ids: Vec<String> = self
            .tg
            .store
            .data
            .links
            .iter()
            .filter(|l| l.state == LinkState::Active)
            .map(|l| l.record.id.clone())
            .collect();
        for id in &ids {
            self.tg_do_lock(id, &who, now);
        }
        self.log_activity(
            "lock every telegram link",
            "-",
            None,
            &format!("{} locked", ids.len()),
        );
        Resp::json(200, &json!({ "locked": ids.len() }))
    }

    fn tg_unlock_challenge(&mut self, req: &Req, id: &str, now: u64) -> Resp {
        let Some(l) = self.tg.store.link(id).cloned() else {
            return Resp::error(404, "not_found", "no such link");
        };
        let (who, _) = match self.tg_who(req) {
            Ok(x) => x,
            Err(r) => return r,
        };
        if l.record.person != who || l.state != LinkState::Locked {
            return Resp::error(404, "not_found", "no such locked link");
        }
        let Ok(digest) = unlock_digest(&l.record, now) else {
            return Resp::error(500, "internal", "the unlock could not be made");
        };
        let options = match self.tg_options(req, &digest) {
            Ok(o) => o,
            Err(r) => return r,
        };
        self.tg.drafts.insert(
            format!("{who}:unlock:{id}"),
            Draft {
                kind: DraftKind::Unlock,
                digest,
                expires_ms: now + DRAFT_MS,
            },
        );
        Resp::json(200, &json!({ "options": options }))
    }

    fn tg_unlock(&mut self, req: &Req, id: &str, now: u64) -> Resp {
        let b: Assertion = match parse(req) {
            Ok(b) => b,
            Err(r) => return r,
        };
        let (who, _) = match self.tg_who(req) {
            Ok(x) => x,
            Err(r) => return r,
        };
        let draft = match self.tg_draft_take(&format!("{who}:unlock:{id}"), now) {
            Ok(d) => d,
            Err(r) => return r,
        };
        if let Err(r) = self.tg_assert(req, &draft.digest, &b.assertion) {
            return r;
        }
        let Some(l) = self.tg.store.link_mut(id) else {
            return Resp::error(404, "not_found", "no such link");
        };
        if l.state != LinkState::Locked {
            return Resp::error(409, "not_locked", "that link is not locked");
        }
        l.state = LinkState::Active;
        l.unlocked_ms = Some(now);
        if let Err(e) = self.tg.store.save() {
            return Resp::error(500, "telegram_store", &e);
        }
        self.tg_chain(&who, "telegram.unlock", Some(id), "lock lifted, passkey");
        Resp::json(
            200,
            &json!({ "link": self.tg.store.link(id).map(|l| self.tg_link_view(l, now)) }),
        )
    }

    fn tg_renew_challenge(&mut self, req: &Req, id: &str, now: u64) -> Resp {
        let Some(l) = self.tg.store.link(id).cloned() else {
            return Resp::error(404, "not_found", "no such link");
        };
        let (who, _) = match self.tg_who(req) {
            Ok(x) => x,
            Err(r) => return r,
        };
        if l.record.person != who || l.state == LinkState::Revoked {
            return Resp::error(404, "not_found", "no such link");
        }
        let new_exp = now + LINK_TTL_MS;
        let Ok(digest) = renew_digest(&l.record, new_exp) else {
            return Resp::error(500, "internal", "the renewal could not be made");
        };
        let options = match self.tg_options(req, &digest) {
            Ok(o) => o,
            Err(r) => return r,
        };
        self.tg.drafts.insert(
            format!("{who}:renew:{id}"),
            Draft {
                kind: DraftKind::Renew {
                    new_expires_ms: new_exp,
                },
                digest,
                expires_ms: now + DRAFT_MS,
            },
        );
        Resp::json(200, &json!({ "options": options, "expires_ms": new_exp }))
    }

    fn tg_renew(&mut self, req: &Req, id: &str, now: u64) -> Resp {
        let b: Assertion = match parse(req) {
            Ok(b) => b,
            Err(r) => return r,
        };
        let (who, _) = match self.tg_who(req) {
            Ok(x) => x,
            Err(r) => return r,
        };
        let draft = match self.tg_draft_take(&format!("{who}:renew:{id}"), now) {
            Ok(d) => d,
            Err(r) => return r,
        };
        let DraftKind::Renew { new_expires_ms, .. } = draft.kind else {
            return Resp::error(409, "no_pending", "start again");
        };
        let signed = match self.tg_assert(req, &draft.digest, &b.assertion) {
            Ok(s) => s,
            Err(r) => return r,
        };
        let Some(l) = self.tg.store.link_mut(id) else {
            return Resp::error(404, "not_found", "no such link");
        };
        l.renewed = Some(Renewal {
            expires_ms: new_expires_ms,
            signed: signed.evidence(now),
        });
        if let Err(e) = self.tg.store.save() {
            return Resp::error(500, "telegram_store", &e);
        }
        self.tg_chain(
            &who,
            "telegram.renew",
            Some(id),
            "renewed thirty days, passkey",
        );
        Resp::json(
            200,
            &json!({ "link": self.tg.store.link(id).map(|l| self.tg_link_view(l, now)) }),
        )
    }

    // ---------- delegations ----------

    fn tg_delegation_record(
        &self,
        req_person: &str,
        link: &TgLink,
        w: &DelegationWish,
        now: u64,
    ) -> Result<DelegationRecord, Resp> {
        let mut acts: Vec<DelegatedAct> = Vec::new();
        for a in &w.acts {
            acts.push(match a.as_str() {
                "converse" => DelegatedAct::Converse,
                "power" => DelegatedAct::Power,
                "run" => {
                    return Err(Resp::error(
                        409,
                        "not_available",
                        "/run arrives in a later release: talking to coding agents and box power can be delegated now",
                    ))
                }
                _ => return Err(Resp::error(400, "bad_request", "an act is converse, power or run")),
            });
        }
        acts.sort();
        acts.dedup();
        self.tg_need_address()?;
        let boxes = self.tg_boxes_ok(&w.boxes)?;
        let life = Self::tg_days_ms(w.days)?;
        if life > DELEGATION_MAX_MS {
            return Err(Resp::error(
                400,
                "bad_request",
                "a delegation lasts at most thirty days",
            ));
        }
        Ok(DelegationRecord {
            id: random_hex(6).map_err(|e| Resp::error(500, "internal", &e))?,
            link_id: link.record.id.clone(),
            person: req_person.to_string(),
            telegram_id: link.record.telegram_id,
            bot_id: link.record.bot_id,
            boxes,
            acts,
            caps: {
                let mut c = Caps::default();
                if let Some(cw) = &w.caps {
                    if cw.max_size.is_some() {
                        c.max_size = cw
                            .max_size
                            .as_ref()
                            .and_then(|m| m.parse::<ozbox_core::Size>().ok())
                            .map(|m| m.to_string());
                    }
                    c.daily_usd = cw.daily_usd.unwrap_or(c.daily_usd);
                    c.creates_per_day = cw.creates_per_day.unwrap_or(c.creates_per_day);
                    c.resumes_per_day = cw.resumes_per_day.unwrap_or(c.resumes_per_day);
                    c.running = cw.running.unwrap_or(c.running);
                }
                c
            },
            not_before_ms: now,
            expires_ms: now + life,
            hub_ack: w.hub_ack,
            with_link: false,
        })
        .and_then(|r: DelegationRecord| {
            r.validate()
                .map(|_| r)
                .map_err(|e| Resp::error(400, "bad_request", &e.to_string()))
        })
    }

    fn tg_delegation_challenge(&mut self, req: &Req, link_id: &str, now: u64) -> Resp {
        if let Err(r) = self.tg_ready() {
            return r;
        }
        let w: DelegationWish = match parse(req) {
            Ok(b) => b,
            Err(r) => return r,
        };
        let (who, role) = match self.tg_who(req) {
            Ok(x) => x,
            Err(r) => return r,
        };
        let Some(link) = self.tg.store.link(link_id).cloned() else {
            return Resp::error(404, "not_found", "no such link");
        };
        if link.record.person != who || link.state == LinkState::Revoked {
            return Resp::error(404, "not_found", "no such link");
        }
        if role == Role::Viewer {
            return Resp::error(403, "forbidden", "a viewer cannot delegate");
        }
        if !self.tg_link_genuine(&link) {
            return Resp::error(
                409,
                "not_genuine",
                "that link is not backed by a passkey assertion: link again",
            );
        }
        let record = match self.tg_delegation_record(&who, &link, &w, now) {
            Ok(r) => r,
            Err(r) => return r,
        };
        let Ok(digest) = record.digest() else {
            return Resp::error(400, "bad_request", "that delegation is not valid");
        };
        let options = match self.tg_options(req, &digest) {
            Ok(o) => o,
            Err(r) => return r,
        };
        let summary = json!({ "boxes": record.boxes, "acts": record.acts.iter().map(|a| a.name()).collect::<Vec<_>>(), "expires_ms": record.expires_ms, "needs_owner": role == Role::Member });
        self.tg.drafts.insert(
            format!("{who}:delegation:{link_id}"),
            Draft {
                kind: DraftKind::Delegation(record),
                digest,
                expires_ms: now + DRAFT_MS,
            },
        );
        Resp::json(200, &json!({ "options": options, "summary": summary }))
    }

    fn tg_delegation_create(&mut self, req: &Req, link_id: &str, now: u64) -> Resp {
        let b: Assertion = match parse(req) {
            Ok(b) => b,
            Err(r) => return r,
        };
        let (who, _) = match self.tg_who(req) {
            Ok(x) => x,
            Err(r) => return r,
        };
        let draft = match self.tg_draft_take(&format!("{who}:delegation:{link_id}"), now) {
            Ok(d) => d,
            Err(r) => return r,
        };
        let DraftKind::Delegation(record) = draft.kind else {
            return Resp::error(409, "no_pending", "start again");
        };
        let signed = match self.tg_assert(req, &draft.digest, &b.assertion) {
            Ok(s) => s,
            Err(r) => return r,
        };
        let id = record.id.clone();
        let boxes = record.boxes.join(",");
        self.tg.store.data.delegations.push(TgDelegation {
            record,
            digest: to_hex(&draft.digest),
            signed: Some(signed.evidence(now)),
            owner: None,
            issued_ms: now,
            last_used_ms: 0,
            revoked: false,
        });
        if let Err(e) = self.tg.store.save() {
            self.tg.store.data.delegations.retain(|d| d.record.id != id);
            return Resp::error(500, "telegram_store", &e);
        }
        let detail: String = format!("converse on {boxes}, passkey")
            .chars()
            .take(120)
            .collect();
        self.tg_chain(&who, "telegram.delegate", Some(&id), &detail);
        self.tg_alert(
            &format!("tg-delegation:{id}"),
            "Telegram was allowed to talk to coding agents",
            &format!("{who} delegated converse to a Telegram link on: {boxes}."),
            Severity::Normal,
            now,
        );
        let view = self
            .tg
            .store
            .link(link_id)
            .map(|l| self.tg_link_view(l, now));
        Resp::json(200, &json!({ "link": view }))
    }

    fn tg_delegation_revoke(&mut self, req: &Req, id: &str, now: u64) -> Resp {
        let Some(d) = self
            .tg
            .store
            .data
            .delegations
            .iter()
            .find(|d| d.record.id == id)
            .cloned()
        else {
            return Resp::error(404, "not_found", "no such delegation");
        };
        let (who, role) = match self.tg_who(req) {
            Ok(x) => x,
            Err(r) => return r,
        };
        if d.record.person != who && role != Role::Owner {
            return Resp::error(404, "not_found", "no such delegation");
        }
        if let Some(x) = self
            .tg
            .store
            .data
            .delegations
            .iter_mut()
            .find(|x| x.record.id == id)
        {
            x.revoked = true;
        }
        if let Err(e) = self.tg.store.save() {
            return Resp::error(500, "telegram_store", &e);
        }
        self.tg_chain(&who, "telegram.undelegate", Some(id), "delegation revoked");
        let view = self
            .tg
            .store
            .link(&d.record.link_id)
            .map(|l| self.tg_link_view(l, now));
        Resp::json(200, &json!({ "link": view }))
    }

    fn tg_cosign_target(&self, req: &Req, id: &str) -> Result<(String, TgDelegation), Resp> {
        let (who, role) = self.tg_who(req)?;
        if role != Role::Owner {
            return Err(Resp::error(
                403,
                "forbidden",
                "only an owner can stand behind a member's delegation",
            ));
        }
        let d = self
            .tg
            .store
            .data
            .delegations
            .iter()
            .find(|d| d.record.id == id && !d.revoked)
            .cloned()
            .ok_or_else(|| Resp::error(404, "not_found", "no such delegation"))?;
        if d.record.person == who {
            return Err(Resp::error(
                409,
                "own_delegation",
                "an owner does not need to co-sign their own delegation",
            ));
        }
        Ok((who, d))
    }

    fn tg_cosign_challenge(&mut self, req: &Req, id: &str, now: u64) -> Resp {
        let (who, d) = match self.tg_cosign_target(req, id) {
            Ok(x) => x,
            Err(r) => return r,
        };
        let Some(dd) = from_hex(&d.digest).and_then(|b| <[u8; 32]>::try_from(b).ok()) else {
            return Resp::error(500, "internal", "that delegation is not valid");
        };
        let Ok(digest) = cosign_digest(&dd, &d.record.person) else {
            return Resp::error(500, "internal", "that delegation is not valid");
        };
        let options = match self.tg_options(req, &digest) {
            Ok(o) => o,
            Err(r) => return r,
        };
        self.tg.drafts.insert(
            format!("{who}:cosign:{id}"),
            Draft {
                kind: DraftKind::Cosign,
                digest,
                expires_ms: now + DRAFT_MS,
            },
        );
        Resp::json(
            200,
            &json!({ "options": options, "person": d.record.person, "boxes": d.record.boxes }),
        )
    }

    fn tg_cosign(&mut self, req: &Req, id: &str, now: u64) -> Resp {
        let b: Assertion = match parse(req) {
            Ok(b) => b,
            Err(r) => return r,
        };
        let (who, _) = match self.tg_cosign_target(req, id) {
            Ok(x) => x,
            Err(r) => return r,
        };
        let draft = match self.tg_draft_take(&format!("{who}:cosign:{id}"), now) {
            Ok(d) => d,
            Err(r) => return r,
        };
        let signed = match self.tg_assert(req, &draft.digest, &b.assertion) {
            Ok(s) => s,
            Err(r) => return r,
        };
        let Some(d) = self
            .tg
            .store
            .data
            .delegations
            .iter_mut()
            .find(|d| d.record.id == id)
        else {
            return Resp::error(404, "not_found", "no such delegation");
        };
        d.owner = Some(signed.evidence(now));
        let person = d.record.person.clone();
        if let Err(e) = self.tg.store.save() {
            return Resp::error(500, "telegram_store", &e);
        }
        self.tg_chain(
            &who,
            "telegram.cosign",
            Some(id),
            &format!("owner stands behind {person}'s delegation, passkey"),
        );
        Resp::json(200, &json!({ "cosigned": true }))
    }

    /// An owner marks which boxes are Production and which is the hub. Changing what a chat may reach is a change to who can
    /// do what, so it needs a passkey shown a moment ago.
    fn tg_marks(&mut self, req: &Req) -> Resp {
        #[derive(Deserialize)]
        #[serde(deny_unknown_fields)]
        struct B {
            production: Vec<String>,
            #[serde(default)]
            hub: Option<String>,
            /// Named groups a chat may address as `@<group>`. Left out: kept as they are.
            #[serde(default)]
            groups: Option<std::collections::BTreeMap<String, Vec<String>>>,
            /// Per-box detail level for agent replies (`full`, `summary`, `metadata`). Left out: kept as they are.
            #[serde(default)]
            detail: Option<std::collections::BTreeMap<String, String>>,
        }
        let b: B = match parse(req) {
            Ok(b) => b,
            Err(r) => return r,
        };
        let (who, role) = match self.tg_who(req) {
            Ok(x) => x,
            Err(r) => return r,
        };
        if role != Role::Owner {
            return Resp::error(
                403,
                "forbidden",
                "only an owner marks Production boxes and the hub",
            );
        }
        if let Some(r) = super::roles::step_up_refusal(
            self.step_up_state(req),
            "marking Production boxes and the hub",
        ) {
            return r;
        }
        let ok = |n: &String| ozbox_core::chat_policy::acts::box_name_ok(n);
        if !b.production.iter().all(ok)
            || b.hub.as_ref().is_some_and(|h| !ok(h))
            || b.production.len() > 200
        {
            return Resp::error(400, "bad_request", "those are not box names");
        }
        let mut production = b.production;
        production.sort();
        production.dedup();
        let old = std::mem::take(&mut self.tg.store.data.marks);
        let groups = match b.groups {
            None => old.groups.clone(),
            Some(g) => {
                let boxes: Vec<String> = self
                    .provider
                    .list()
                    .map(|r| r.iter().map(|x| x.spec.name.to_string()).collect())
                    .unwrap_or_default();
                let bad = g.len() > 50
                    || g.iter().any(|(name, members)| {
                        !ok(name)
                            || name.eq_ignore_ascii_case(ozbox_core::chat_policy::address::FLEET)
                            || boxes.contains(name)
                            || members.is_empty()
                            || members.len() > 200
                            || !members.iter().all(ok)
                    });
                if bad {
                    self.tg.store.data.marks = old;
                    return Resp::error(
                        400,
                        "bad_request",
                        "a group has a name that is not a box's or `fleet`, and 1 to 200 box names",
                    );
                }
                g
            }
        };
        let detail = match b.detail {
            None => old.detail.clone(),
            Some(d) => {
                if !d.iter().all(|(k, v)| {
                    ok(k) && ozbox_core::chat_policy::reply::Detail::from_name(v).is_some()
                }) {
                    self.tg.store.data.marks = old;
                    return Resp::error(
                        400,
                        "bad_request",
                        "a detail level is full, summary or metadata",
                    );
                }
                d
            }
        };
        self.tg.store.data.marks = crate::telegram_store::Marks {
            production,
            hub: b.hub,
            groups,
            detail,
        };
        if let Err(e) = self.tg.store.save() {
            return Resp::error(500, "telegram_store", &e);
        }
        let m = &self.tg.store.data.marks;
        let detail: String = format!(
            "production={} hub={}",
            m.production.len(),
            m.hub.as_deref().unwrap_or("-")
        )
        .chars()
        .take(120)
        .collect();
        self.tg_chain(&who, "telegram.marks", None, &detail);
        Resp::json(200, &json!({ "marks": self.tg.store.data.marks }))
    }

    // ---------- the transcript, and going on after a stop ----------

    fn tg_transcript_route(&mut self, req: &Req, id: &str, now: u64) -> Resp {
        let (who, role) = match self.tg_who(req) {
            Ok(x) => x,
            Err(r) => return r,
        };
        if role != Role::Owner {
            return Resp::error(403, "forbidden", "only an owner reads the transcript");
        }
        if self.tg.store.link(id).is_none() {
            return Resp::error(404, "not_found", "no such link");
        }
        let lines = self
            .tg_transcript(now)
            .map(|t| t.read(id, now))
            .unwrap_or_default();
        // reading what people said is itself recorded
        self.tg_chain(
            &who,
            "telegram.transcript_read",
            Some(id),
            &format!("{} lines", lines.len()),
        );
        Resp::json(200, &json!({ "link": id, "lines": lines, "kept_days": 30 }))
    }

    fn tg_resume(&mut self, req: &Req, now: u64) -> Resp {
        let (who, role) = match self.tg_who(req) {
            Ok(x) => x,
            Err(r) => return r,
        };
        if role != Role::Owner {
            return Resp::error(403, "forbidden", "only an owner can start the bridge again");
        }
        self.tg.store.data.halted = None;
        self.tg.bot = None;
        self.tg.backoff_until_ms = 0;
        self.tg.parse_failures = 0;
        let _ = self.tg.store.save();
        self.schedule.next_telegram_ms = 0;
        self.tg_chain(
            &who,
            "telegram.resume",
            None,
            "owner confirmed: the bridge checks the bot again",
        );
        let _ = now;
        Resp::json(200, &json!({ "resumed": true }))
    }

    /// Stop the bridge and say why. It stays stopped across a restart until an owner confirms (ADR 0050 §7).
    pub(super) fn tg_halt(&mut self, code: &str, detail: &str, urgent: bool, now: u64) {
        if self
            .tg
            .store
            .data
            .halted
            .as_ref()
            .is_some_and(|h| h.code == code)
        {
            return;
        }
        self.tg.store.data.halted = Some(Halt {
            code: code.to_string(),
            since_ms: now,
            detail: detail.chars().take(160).collect(),
        });
        let _ = self.tg.store.save();
        self.tg.bot = None;
        self.tg_chain(
            "supervisor",
            "telegram.halt",
            None,
            &format!("{code}: {detail}")
                .chars()
                .take(150)
                .collect::<String>(),
        );
        self.tg_alert(
            &format!("tg-halt:{code}"),
            "The Telegram bridge stopped",
            &halt_message(self.tg.store.data.halted.as_ref().unwrap_or(&Halt {
                code: code.into(),
                since_ms: now,
                detail: detail.into(),
            })),
            if urgent {
                Severity::Urgent
            } else {
                Severity::Normal
            },
            now,
        );
    }
}

fn counters_json(c: &Counters) -> Value {
    json!({ "unlinked": c.unlinked, "unlinked_last_ms": c.unlinked_last_ms, "too_old": c.too_old, "replays": c.replays })
}

/// The words for a stop, from its code.
pub(super) fn halt_message(h: &Halt) -> String {
    match h.code.as_str() {
        "conflict" => t("tg.halted_conflict", &[]),
        "webhook_set" => t("tg.halted_webhook", &[("what", &h.detail)]),
        "bot_settings" => t("tg.halted_bot_settings", &[("what", &h.detail)]),
        "bad_token" => t("tg.halted_bad_token", &[]),
        "store" => t("tg.halted_store", &[]),
        "transcript" => t("tg.halted_transcript", &[]),
        _ => h.detail.clone(),
    }
}
