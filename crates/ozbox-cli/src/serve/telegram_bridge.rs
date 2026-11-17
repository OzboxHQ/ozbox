//! The Telegram bridge (ADR 0050 §7 to §9): one poll, one update, one act, one decision.
//!
//! The order for every update is fixed, and each step can only make the update less able:
//!
//! 1. **Admission** (`ozbox_core::chat_policy::admit`): a plain private text message from a person, nothing else.
//! 2. **Replay**: the `(bot id, update_id)` is put in the durable set and the set is written to disk **before** anything is
//!    done for it. If it cannot be written, the bridge stops rather than act on what it cannot record.
//! 3. **Identity**: the sender's numeric id must have a live link on **this** bot, and the link must be genuine (its stored
//!    passkey assertion still verifies). Anyone else is counted and never answered; a bot that answers a stranger tells them it
//!    is there. The one exception is `/link` while a person has a pairing window open.
//! 4. **Reading**: one `ChatAct` by `parse_act`; a forwarded or quoted message is data, never read as a command.
//! 5. **Freshness and rate**: five minutes (two for power and run), twenty messages a minute.
//! 6. **The transcript**: the message is sealed in the link's transcript first; no transcript, no act.
//! 7. **The decision**: `ozbox_core::chat_policy::decide`, from facts read just now. `Allow`, `Handoff` or `Refuse`.
//! 8. **The act**, only after the decision is asked again with fresh facts (`Allowed::confirm`): a link revoked or locked
//!    between the record and the act refuses it.
//!
//! What an allowed converse act does is the chat gateway's own code (`chat_inbound`), unchanged: the same refusals of approve,
//! deny, stop and budget, and the same typing rules. This module adds the identity and the authority in front of it.

use std::sync::Arc;

use ozbox_core::chat_policy::acts::{parse_act, ChatAct, Tier};
use ozbox_core::chat_policy::admit::{admit, freshness, Admitted, Freshness};
use ozbox_core::chat_policy::decide::{
    decide, BoxFacts, ChatChannel, Context, Decision, DelegationFacts, HandoffReason, LinkFacts,
    LinkStatus, Refusal,
};
use ozbox_core::roles::Role;
use serde_json::Value;

use super::worker::{Done, Job, Polled};
use super::App;
use crate::chat::gateway::{conv_key, Bind, Channel};
use crate::messages::t;
use crate::telegram::{ApiError, Bot, BotInfo, POLL_BATCH};
use crate::telegram_store::{LinkState, TgLink};
use crate::telegram_transcript::Dir;

/// Silence this long (five days) makes the next poll start from offset 0: Telegram may restart its update numbers after a week.
const SILENCE_RESETS_OFFSET_MS: u64 = 5 * 24 * 3_600_000;

/// The sender of an update, as the bridge sees them once identity is settled.
pub(super) struct Sender {
    /// The link's id, or `legacy:<chat>` for a chat linked before passkey links.
    pub link_id: String,
    pub person: String,
    pub chat_id: i64,
    pub legacy: bool,
}

/// What `decide` said, kept so the act can be asked again just before it is done.
pub(super) struct Planned {
    pub act: ChatAct,
    pub decision: Decision,
}

/// The audit entry for one act, in at most 160 characters (the chain keeps no more, and cuts silently).
pub(super) fn audit_detail(
    act: &ChatAct,
    decision: &Decision,
    upd: i64,
    delegation: Option<&str>,
    mac: &str,
    out: &str,
) -> String {
    let row = act.row();
    let boxed = act
        .box_name()
        .map(|b| format!(" box={}", b.chars().take(24).collect::<String>()))
        .unwrap_or_default();
    let del = delegation.map_or("-".to_string(), |d| d.chars().take(12).collect());
    format!(
        "act={} tier={} d={} r={} upd={upd} del={del} msg={}{boxed} out={out}",
        row.id,
        row.tier.number(),
        decision.word(),
        decision.code(),
        mac.chars().take(16).collect::<String>(),
    )
    .chars()
    .take(160)
    .collect()
}

impl App {
    // ---------- polling ----------

    /// Ask Telegram for messages, on a thread of its own: a poll waits up to thirty seconds, and the shared worker has alerts
    /// and prices to run.
    pub(super) fn start_telegram(&mut self) {
        if !self.settings.apps.telegram.enabled || self.tg.store_error.is_some() {
            return;
        }
        if self.tg.store.data.halted.is_some() {
            return;
        }
        let audience = !self.state.telegram.chats.is_empty()
            || self
                .tg
                .store
                .data
                .links
                .iter()
                .any(|l| l.state != LinkState::Revoked)
            || self.tg.window.is_some();
        if !audience {
            return;
        }
        let Ok(Some(token)) = self.secrets.get("telegram-bot-token") else {
            return;
        };
        let now = super::unix_ms();
        if now < self.tg.backoff_until_ms {
            return;
        }
        let http = Arc::clone(&self.http);
        let base = self.tg.api_base.clone();
        let need_me = self.tg.bot.is_none();
        let silent_for = now.saturating_sub(self.tg.store.data.last_update_ms);
        let offset =
            if self.tg.store.data.last_update_ms > 0 && silent_for > SILENCE_RESETS_OFFSET_MS {
                0
            } else {
                self.tg.store.data.offset
            };
        let limit = if self.tg.parse_failures > 0 {
            1
        } else {
            POLL_BATCH
        };
        let job: Job = Box::new(move || {
            let bot = Bot::new(http.as_ref(), &token, &base);
            let mut p = Polled {
                token: String::new(),
                me: None,
                webhook: None,
                polled: None,
            };
            if need_me {
                let me = bot.get_me();
                let ok = me.as_ref().is_ok_and(|m| m.problems().is_empty());
                p.me = Some(me);
                if !ok {
                    p.token = token;
                    return Done::TelegramPoll(Box::new(p));
                }
                p.webhook = bot.webhook_host().ok();
                if matches!(p.webhook, Some(Some(_))) {
                    p.token = token;
                    return Done::TelegramPoll(Box::new(p));
                }
            }
            let r = bot.get_updates(offset, limit);
            if matches!(r, Err(ApiError::Conflict)) {
                p.webhook = bot.webhook_host().ok();
            }
            p.polled = Some(r);
            p.token = token;
            Done::TelegramPoll(Box::new(p))
        });
        if self.worker.submit_detached(job) {
            self.schedule.telegram_busy = true;
        }
    }

    fn tg_backoff(&mut self, e: &ApiError, now: u64) {
        let wait_ms = match e {
            ApiError::RateLimited(s) => s * 1000,
            _ => {
                self.tg.backoff_step = (self.tg.backoff_step + 1).min(6);
                1000u64 << self.tg.backoff_step
            }
        };
        self.tg.backoff_until_ms = now + wait_ms.min(60_000);
    }

    /// A poll finished. Updates are applied here, on the server's own thread, in order.
    pub(super) fn tg_polled(&mut self, p: Polled, now: u64) {
        self.schedule.telegram_busy = false;
        if let Some(me) = p.me {
            match me {
                Err(ApiError::BadToken) => return self.tg_halt("bad_token", "", false, now),
                Err(e) => return self.tg_backoff(&e, now),
                Ok(info) => {
                    let problems = info.problems();
                    if !problems.is_empty() {
                        return self.tg_halt("bot_settings", &problems.join(", "), true, now);
                    }
                    self.tg.store.data.bot = Some(crate::telegram_store::BotRef {
                        id: info.id,
                        username: info.username.clone(),
                    });
                    self.tg.bot = Some(info);
                }
            }
        }
        if let Some(Some(host)) = &p.webhook {
            return self.tg_halt("webhook_set", host, true, now);
        }
        let Some(bot) = self.tg.bot.clone() else {
            return;
        };
        match p.polled {
            None => {}
            Some(Err(ApiError::Conflict)) => self.tg_halt("conflict", "", true, now),
            Some(Err(ApiError::BadToken)) => self.tg_halt("bad_token", "", false, now),
            Some(Err(ApiError::NotUnderstood)) => {
                self.tg.parse_failures += 1;
                self.tg_backoff(&ApiError::NotUnderstood, now);
            }
            Some(Err(e)) => self.tg_backoff(&e, now),
            Some(Ok((updates, next))) => {
                if !updates.is_empty() {
                    self.tg.store.data.last_update_ms = now;
                }
                self.tg.parse_failures = 0;
                self.tg.backoff_step = 0;
                self.tg.backoff_until_ms = 0;
                self.tg_apply(&bot, updates, next, now);
                self.schedule.next_telegram_ms = 0;
            }
        }
        self.tg_sweep(now);
    }

    /// Record, then act, update by update; the offset moves only when every update before it is on the disk.
    fn tg_apply(&mut self, bot: &BotInfo, updates: Vec<Value>, next: i64, now: u64) {
        for u in &updates {
            let Ok(a) = admit(u) else {
                continue;
            };
            if !self.tg.store.data.seen.insert(bot.id, a.update_id, now) {
                self.tg.store.data.counters.replays += 1;
                continue;
            }
            // durable before anything is done for it: a crash must not run the same command twice
            if let Err(e) = self.tg.store.save() {
                self.tg_halt("store", &e, true, now);
                return;
            }
            self.tg_message(bot, a, now);
        }
        self.tg.store.data.offset = next;
        if let Err(e) = self.tg.store.save() {
            self.tg_halt("store", &e, true, now);
        }
        self.version
            .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
    }

    // ---------- identity ----------

    fn tg_message(&mut self, bot: &BotInfo, a: Admitted, now: u64) {
        if let Some(l) = self.tg.store.live_link_of(bot.id, a.from_id).cloned() {
            if !self.tg_link_genuine(&l) {
                // a row with no assertion that matches it grants nothing, and is not answered
                self.tg.store.data.counters.unlinked += 1;
                if self.tg.store.refusal_audit_allowed(&l.record.id, now) {
                    self.tg_chain(
                        &l.record.person,
                        "telegram.refuse",
                        Some(&l.record.id),
                        "r=link_not_genuine",
                    );
                }
                return;
            }
            if let Some(x) = self.tg.store.link_mut(&l.record.id) {
                x.last_seen_ms = now;
            }
            let who = Sender {
                link_id: l.record.id.clone(),
                person: l.record.person.clone(),
                chat_id: l.record.chat_id,
                legacy: false,
            };
            return self.tg_act(bot, &who, Some(&l), a, now);
        }
        if let Some(c) = self
            .state
            .telegram
            .chats
            .iter()
            .find(|c| c.id == a.chat_id)
            .cloned()
        {
            let who = Sender {
                link_id: format!("legacy:{}", c.id),
                person: c.person.clone().unwrap_or_else(|| "owner".into()),
                chat_id: c.id,
                legacy: true,
            };
            return self.tg_act(bot, &who, None, a, now);
        }
        // a stranger: only `/link` while a window is open is heard, and it is the code that proves anything
        if !a.data_only && matches!(parse_act(&a.text, Some(&bot.username)), ChatAct::Link) {
            if let Some(text) =
                self.tg_offer_code(a.from_id, a.chat_id, &a.first_name, a.date_ms, now)
            {
                self.tg_send_plain(a.chat_id, text);
                return;
            }
        }
        let c = &mut self.tg.store.data.counters;
        c.unlinked += 1;
        c.unlinked_last_ms = now;
    }

    // ---------- one act ----------

    fn tg_role(&self, person: &str) -> Option<Role> {
        match &self.auth {
            Some(a) => a.role_opt(person),
            None => Some(Role::Owner),
        }
    }

    /// The box an act is about, with what the fleet record says about it.
    fn tg_target(&self, act: &ChatAct, conv: &str) -> Option<(String, BoxFacts)> {
        let name = match act {
            // a group or the fleet is judged box by box when it is expanded, not as one box here
            ChatAct::Address {
                to: ozbox_core::chat_policy::address::Address::Fleet,
                ..
            } => return None,
            ChatAct::Address {
                to: ozbox_core::chat_policy::address::Address::Name(n),
                ..
            } if self.tg.store.data.marks.groups.contains_key(n) => return None,
            ChatAct::Converse(_) if self.tg_sticky_fans_out(conv) => return None,
            ChatAct::Converse(_) if self.tg_sticky_box(conv).is_some() => self.tg_sticky_box(conv),
            ChatAct::Switch(id) => self
                .chat_book()
                .and_then(|b| b.task(id).map(|t| t.spec.box_name.to_string())),
            ChatAct::Attach { session, .. } | ChatAct::Adopt(session) => {
                crate::chat::gateway::split_session(session).map(|(b, _)| b)
            }
            _ => act.box_name().map(str::to_string).or_else(|| {
                match self.state.chat.binds.get(conv) {
                    Some(Bind::Task { id }) => self
                        .chat_book()
                        .and_then(|b| b.task(id).map(|t| t.spec.box_name.to_string())),
                    Some(Bind::Terminal { box_name, .. }) => Some(box_name.clone()),
                    None => {
                        let boxes = self.chat_boxes();
                        (boxes.len() == 1).then(|| boxes[0].clone())
                    }
                }
            }),
        }?;
        let marks = &self.tg.store.data.marks;
        let facts = BoxFacts {
            production: marks.production.contains(&name),
            hub: marks.hub.as_deref() == Some(name.as_str()),
            hosts_bot: marks.hub.as_deref() == Some(name.as_str()),
        };
        Some((name, facts))
    }

    /// The facts of this moment, for `decide` and again for `confirm`.
    pub(super) fn tg_context<'a>(
        &self,
        who: &Sender,
        link: Option<&TgLink>,
        target: Option<&'a (String, BoxFacts)>,
        delegations: &'a [DelegationFacts],
        now: u64,
    ) -> (Option<LinkFacts>, Context<'a>) {
        // read the link again: it may have been locked or revoked since the message arrived
        let fresh = link.and_then(|l| self.tg.store.link(&l.record.id));
        let link_facts = match fresh {
            Some(l) => Some(self.tg_facts(l).0),
            None if who.legacy => Some(LinkFacts {
                status: LinkStatus::Active,
                created_ms: 0,
                expires_ms: u64::MAX,
            }),
            None => None,
        };
        let ctx = Context {
            channel: ChatChannel::Telegram,
            role: self.tg_role(&who.person),
            link: link_facts,
            target_box: target.map(|(n, f)| (n.as_str(), *f)),
            delegations,
            pairing_open: self
                .tg
                .window
                .as_ref()
                .is_some_and(|w| w.record.expires_ms > now),
            now_ms: now,
        };
        (link_facts, ctx)
    }

    pub(super) fn tg_delegations(&self, link: Option<&TgLink>) -> Vec<DelegationFacts> {
        link.and_then(|l| self.tg.store.link(&l.record.id))
            .map(|l| self.tg_facts(l).1)
            .unwrap_or_default()
    }

    fn tg_act(
        &mut self,
        bot: &BotInfo,
        who: &Sender,
        link: Option<&TgLink>,
        a: Admitted,
        now: u64,
    ) {
        if let Some((planned, mac)) = self.tg_plan(bot, who, link, &a, now) {
            self.tg_run(who, link, planned, &a, &mac, now);
        }
    }

    /// Read, check and decide one message. `None` when the message was answered here (someone else's words, too old, too fast,
    /// or it could not be recorded) and nothing is left to do. Recording comes before the decision is acted on.
    pub(super) fn tg_plan(
        &mut self,
        bot: &BotInfo,
        who: &Sender,
        link: Option<&TgLink>,
        a: &Admitted,
        now: u64,
    ) -> Option<(Planned, String)> {
        let conv = conv_key(Channel::Telegram, &a.chat_id.to_string());
        let act = parse_act(&a.text, Some(&bot.username));
        // someone else's words are data, never a command
        if a.data_only {
            self.tg_record_in(who, a, now);
            self.tg_reply(who, t("tg.data_only", &[]), now);
            return None;
        }
        match freshness(a.date_ms, now, act.row().tier) {
            Freshness::Fresh => {}
            Freshness::TooOld => {
                self.tg.store.data.counters.too_old += 1;
                self.tg_reply(who, t("tg.too_old", &[]), now);
                return None;
            }
            Freshness::FromTheFuture => return None,
        }
        if !self.chat.rate.allow(&conv, now) {
            self.tg_reply(who, t("chat.slow_down", &[]), now);
            return None;
        }
        // sealed first: nothing is done that cannot be recorded
        let Some(mac) = self.tg_record_in(who, a, now) else {
            self.tg_reply(who, t("tg.cannot_record", &[]), now);
            return None;
        };
        let target = self.tg_target(&act, &conv);
        let delegations = self.tg_delegations(link);
        let (_, ctx) = self.tg_context(who, link, target.as_ref(), &delegations, now);
        let decision = decide(&act, &ctx);
        Some((Planned { act, decision }, mac))
    }

    /// Do what was decided, after asking again. Split from the decision so a revoke between the two can be tested.
    pub(super) fn tg_run(
        &mut self,
        who: &Sender,
        link: Option<&TgLink>,
        planned: Planned,
        a: &Admitted,
        mac: &str,
        now: u64,
    ) {
        let conv = conv_key(Channel::Telegram, &a.chat_id.to_string());
        let Planned { act, decision, .. } = planned;
        match decision {
            Decision::Refuse(r) => {
                self.tg_audit_decision(
                    who,
                    &act,
                    &Decision::Refuse(r),
                    a.update_id,
                    mac,
                    "refused",
                    now,
                );
                if !r.silent() {
                    let text = match r {
                        Refusal::PersonRemoved => t(r.message(), &[]),
                        _ => t(r.message(), &[]),
                    };
                    self.tg_reply(who, text, now);
                }
                if matches!(r, Refusal::PersonRemoved) {
                    self.tg_do_revoke(&who.link_id, "person_removed", now);
                }
            }
            Decision::Handoff(h) => {
                self.tg_audit_decision(
                    who,
                    &act,
                    &Decision::Handoff(h),
                    a.update_id,
                    mac,
                    "handoff",
                    now,
                );
                self.tg_handoff(who, h, now);
            }
            Decision::Allow(allowed) => {
                // ask again with the facts of this moment: a revoke, a lock or a lapse since the record refuses
                let target = self.tg_target(&act, &conv);
                let delegations = self.tg_delegations(link);
                let (_, ctx) = self.tg_context(who, link, target.as_ref(), &delegations, now);
                if let Err(now_decision) = allowed.confirm(&act, &ctx) {
                    self.tg_audit_decision(
                        who,
                        &act,
                        &now_decision,
                        a.update_id,
                        mac,
                        "changed_before_run",
                        now,
                    );
                    match now_decision {
                        Decision::Refuse(r) if !r.silent() => {
                            self.tg_reply(who, t(r.message(), &[]), now)
                        }
                        Decision::Handoff(h) => self.tg_handoff(who, h, now),
                        _ => {}
                    }
                    return;
                }
                if act.row().tier > Tier::Read || act.row().safe {
                    self.tg_audit_decision(
                        who,
                        &act,
                        &Decision::Allow(allowed.clone()),
                        a.update_id,
                        mac,
                        "recorded",
                        now,
                    );
                }
                self.tg_execute(who, link, &act, allowed.delegation(), a, now);
                self.tg_audit_decision(
                    who,
                    &act,
                    &Decision::Allow(allowed),
                    a.update_id,
                    mac,
                    "done",
                    now,
                );
            }
        }
    }

    fn tg_execute(
        &mut self,
        who: &Sender,
        link: Option<&TgLink>,
        act: &ChatAct,
        delegation: Option<&str>,
        a: &Admitted,
        now: u64,
    ) {
        match act {
            ChatAct::Lock => {
                if who.legacy {
                    self.tg_reply(who, t("tg.legacy", &[]), now);
                } else if self.tg_do_lock(&who.link_id, &who.person, now) {
                    self.tg_reply(who, t("tg.locked_now", &[]), now);
                }
            }
            ChatAct::Unlink => {
                if who.legacy {
                    self.state.telegram.chats.retain(|c| c.id != who.chat_id);
                    self.save_state();
                    self.tg_chain(
                        &who.person,
                        "telegram.unlink",
                        Some(&who.link_id),
                        "legacy chat unlinked from chat",
                    );
                } else {
                    self.tg_do_revoke(&who.link_id, "unlinked", now);
                }
                // the reply is sent directly: the link is gone, and so is the right to be answered through it
                self.tg_send_plain(who.chat_id, t("tg.unlinked", &[]));
            }
            ChatAct::Link => self.tg_reply(who, t("tg.already_linked", &[]), now),
            ChatAct::Help => {
                let mut s = t("tg.help", &[]);
                if who.legacy {
                    s = format!("{s}\n{}", t("tg.legacy", &[]));
                }
                self.tg_reply(who, s, now);
            }
            ChatAct::Whoami => {
                let text = self.tg_whoami(who, link, now);
                self.tg_reply(who, text, now);
            }
            ChatAct::Usage(key) => self.tg_reply(who, t(key, &[]), now),
            ChatAct::BoxResume(_)
            | ChatAct::BoxPause(_)
            | ChatAct::BoxExtend { .. }
            | ChatAct::BoxCreate { .. }
            | ChatAct::BoxResize { .. } => self.tg_power(who, act, delegation, a.update_id, now),
            ChatAct::Who => self.tg_show_to(who, now),
            ChatAct::Boxes => self.tg_boxes(who, link, now),
            ChatAct::Fleets => self.tg_fleets(who, link, now),
            ChatAct::To(to) => self.tg_set_to(who, to, now),
            ChatAct::Address { to, text } => {
                self.tg_address(who, link, to, text, delegation, now)
            }
            // a plain message goes to the address set with /to, when one is set and no session is followed
            ChatAct::Converse(text)
                if self.tg_sticky(who.chat_id).is_some()
                    && !self
                        .state
                        .chat
                        .binds
                        .contains_key(&conv_key(Channel::Telegram, &who.chat_id.to_string())) =>
            {
                if let Some(to) = self.tg_sticky(who.chat_id) {
                    self.tg_address(who, link, &to, text, delegation, now);
                }
            }
            ChatAct::Fleet | ChatAct::BoxList => {
                let s = self.fleet_summary();
                self.tg_reply(who, s, now);
            }
            ChatAct::Status
                if !self
                    .state
                    .chat
                    .binds
                    .contains_key(&conv_key(Channel::Telegram, &who.chat_id.to_string())) =>
            {
                let s = self.fleet_summary();
                self.tg_reply(who, s, now);
            }
            // everything else that is allowed is the chat gateway's own code, unchanged
            other => {
                if let Some(d) = delegation {
                    self.tg_mark_used(d, now);
                }
                let text = gateway_text(other, &a.text);
                self.chat_inbound(
                    Channel::Telegram,
                    &who.chat_id.to_string(),
                    &who.person,
                    &text,
                    false,
                    now,
                );
            }
        }
    }

    pub(super) fn tg_mark_used(&mut self, digest: &str, now: u64) {
        if let Some(d) = self
            .tg
            .store
            .data
            .delegations
            .iter_mut()
            .find(|d| d.digest == digest)
        {
            d.last_used_ms = now;
            let _ = self.tg.store.save();
        }
    }

    fn tg_whoami(&self, who: &Sender, link: Option<&TgLink>, now: u64) -> String {
        let role = self
            .tg_role(&who.person)
            .map_or("person removed", Role::name);
        let (state, ends) = match link {
            Some(l) => (
                match l.state {
                    LinkState::Active => "active",
                    LinkState::Locked => "locked",
                    LinkState::Revoked => "revoked",
                },
                format!(
                    "in {} days",
                    self.tg_link_expires(l).saturating_sub(now) / 86_400_000
                ),
            ),
            None => (
                "an old-style link",
                "never (link again to do more)".to_string(),
            ),
        };
        let boxes: Vec<String> = self
            .tg_delegations(link)
            .iter()
            .filter(|d| now < d.expires_ms && now >= d.not_before_ms)
            .flat_map(|d| d.boxes.clone())
            .collect();
        let delegations = if boxes.is_empty() {
            t("tg.whoami_none", &[])
        } else {
            t("tg.whoami_some", &[("boxes", &boxes.join(", "))])
        };
        t(
            "tg.whoami",
            &[
                ("person", &who.person),
                ("role", role),
                ("state", state),
                ("ends", &ends),
                ("delegations", &delegations),
            ],
        )
    }

    // ---------- audit, transcript, replies ----------

    /// Seal an incoming line. `None` when it could not be kept: the caller does nothing.
    fn tg_record_in(&mut self, who: &Sender, a: &Admitted, now: u64) -> Option<String> {
        let text = redact_for_record(&a.text);
        let r = self
            .tg_transcript(now)
            .map(|t| t.append(&who.link_id, now, Dir::In, &text));
        match r {
            Some(Ok(mac)) => Some(mac),
            Some(Err(_)) | None => {
                self.tg_halt("transcript", "", true, now);
                None
            }
        }
    }

    /// A line the bot sent, sealed under the link it went to. Best effort: a failure is not a reason to refuse to reply.
    pub(super) fn tg_record_out(&mut self, chat_id: i64, text: &str, now: u64) {
        let id = self
            .tg
            .store
            .data
            .links
            .iter()
            .find(|l| l.record.chat_id == chat_id && l.state != LinkState::Revoked)
            .map(|l| l.record.id.clone())
            .unwrap_or_else(|| format!("legacy:{chat_id}"));
        let text = redact_for_record(text);
        if let Some(t) = self.tg_transcript(now) {
            let _ = t.append(&id, now, Dir::Out, &text);
        }
    }

    #[allow(clippy::too_many_arguments)]
    fn tg_audit_decision(
        &mut self,
        who: &Sender,
        act: &ChatAct,
        d: &Decision,
        upd: i64,
        mac: &str,
        out: &str,
        now: u64,
    ) {
        let refusal = matches!(d, Decision::Refuse(_));
        if refusal && !self.tg.store.refusal_audit_allowed(&who.link_id, now) {
            return;
        }
        let del = match d {
            Decision::Allow(a) => a.delegation().map(str::to_string),
            _ => None,
        };
        let word = match d {
            Decision::Allow(_) => "telegram.act",
            Decision::Handoff(_) => "telegram.handoff",
            Decision::Refuse(_) => "telegram.refuse",
        };
        let detail = audit_detail(act, d, upd, del.as_deref(), mac, out);
        self.tg_chain(&who.person, word, Some(&who.link_id), &detail);
    }

    /// Answer in the chat the message came from (sealed on the way out by `chat_deliver`).
    pub(super) fn tg_reply(&mut self, who: &Sender, text: String, now: u64) {
        self.chat_say(
            vec![super::chat_routes::Out {
                announce: None,
                notice: None,
                channel: Channel::Telegram,
                id: who.chat_id.to_string(),
                text,
                buttons: Vec::new(),
            }],
            now,
        );
    }

    /// Say something to a chat with no link behind it (the code, "unlinked"). Sent from the worker; nothing waits on it.
    fn tg_send_plain(&mut self, chat_id: i64, text: String) {
        let Ok(Some(token)) = self.secrets.get("telegram-bot-token") else {
            return;
        };
        let http = Arc::clone(&self.http);
        let base = self.tg.api_base.clone();
        let job: Job = Box::new(move || {
            let _ = Bot::new(http.as_ref(), &token, &base).send(chat_id, &text);
            Done::Nothing
        });
        let _ = self.submit(job);
    }

    /// Say something to a chat from the server's own thread, as the record needs it (`/link` ack, the linked notice).
    pub(super) fn tg_say(&mut self, chat_id: i64, text: String, now: u64) {
        let who = Sender {
            link_id: String::new(),
            person: String::new(),
            chat_id,
            legacy: false,
        };
        self.tg_reply(&who, text, now);
    }

    // ---------- the pointer link ----------

    /// What a refused-but-possible act says: the reason, and one link to the dashboard that opens nothing and decides nothing.
    fn tg_handoff(&mut self, who: &Sender, h: HandoffReason, now: u64) {
        self.tg_tell_where(who, h.message(), &[], "/chat", now);
    }

    /// The `{where}` part of a message: one pointer link to the dashboard page at `path`, with the host named, or words when
    /// the dashboard has no public address. `true` when a link was made (so the message is deleted when it lapses).
    pub(super) fn tg_where(&mut self, person: &str, path: &str, now: u64) -> (String, bool) {
        match self.chat_public_base() {
            None => (t("tg.where_none", &[]), false),
            Some(base) => {
                let token = self.tg_pointer(person, path, now);
                let host = base
                    .split("://")
                    .nth(1)
                    .unwrap_or(&base)
                    .split('/')
                    .next()
                    .unwrap_or("")
                    .to_string();
                match token {
                    Some(tok) => (
                        t(
                            "tg.where",
                            &[("host", &host), ("url", &format!("{base}/go#{tok}"))],
                        ),
                        true,
                    ),
                    None => (t("tg.where_none", &[]), false),
                }
            }
        }
    }

    /// A pointer link: 24 random bytes held only as a keyed hash, bound to the person and a path the server chose, ten minutes.
    /// Opening it asks for nothing and consumes nothing.
    pub(super) fn tg_pointer(&mut self, person: &str, path: &str, now: u64) -> Option<String> {
        if self.chat.links.is_none() {
            self.chat.links = crate::chat::links::Links::new().ok();
        }
        self.chat
            .links
            .as_mut()?
            .issue(&format!("path:{path}"), person, now)
            .ok()
    }

    /// Send a message that carries a pointer link, remember its id, and delete it when the link lapses.
    pub(super) fn tg_send_tracked(&mut self, who: &Sender, text: String, now: u64) {
        // the sealed copy never holds the token
        self.tg_record_out(who.chat_id, &text, now);
        let Ok(Some(token)) = self.secrets.get("telegram-bot-token") else {
            return;
        };
        let http = Arc::clone(&self.http);
        let base = self.tg.api_base.clone();
        let chat_id = who.chat_id;
        let expires = now + crate::chat::links::TTL_MS;
        let job: Job =
            Box::new(
                move || match Bot::new(http.as_ref(), &token, &base).send(chat_id, &text) {
                    Ok(id) => Done::TelegramSent {
                        chat_id,
                        message_id: id,
                        expires_ms: expires,
                    },
                    Err(_) => Done::Nothing,
                },
            );
        let _ = self.submit(job);
    }

    pub(super) fn tg_note_sent(&mut self, chat_id: i64, message_id: i64, expires_ms: u64) {
        if message_id > 0 {
            self.tg.handoff_msgs.push((chat_id, message_id, expires_ms));
            if self.tg.handoff_msgs.len() > 200 {
                self.tg.handoff_msgs.remove(0);
            }
        }
    }

    /// Delete every pointer-link message of a chat now (the link was revoked).
    pub(super) fn tg_forget_handoffs(&mut self, chat_id: i64, now: u64) {
        for m in self.tg.handoff_msgs.iter_mut().filter(|m| m.0 == chat_id) {
            m.2 = now;
        }
        self.tg_sweep(now);
    }

    /// Delete the messages whose link has lapsed (best effort: a bot can delete its own message for 48 hours), and close a
    /// pairing window that ran out.
    /// Apply what `ozbox chat lock` and `ozbox chat unlink` asked for. Only those two acts are read: a request can make a link
    /// less able, never more.
    fn tg_cli_requests(&mut self, now: u64) {
        let Some(dir) = self.tg.requests_dir.clone() else {
            return;
        };
        for r in crate::chat_cli::take_requests(&dir) {
            match r.act {
                crate::chat_cli::RequestAct::Lock => {
                    self.tg_do_lock(&r.link, "the command line", now);
                }
                crate::chat_cli::RequestAct::Unlink => {
                    self.tg_do_revoke(&r.link, "revoked_from_cli", now);
                }
            }
        }
    }

    pub(super) fn tg_sweep(&mut self, now: u64) {
        self.tg_cli_requests(now);
        if self
            .tg
            .window
            .as_ref()
            .is_some_and(|w| w.record.expires_ms <= now)
        {
            self.tg.window = None;
        }
        let (due, keep): (Vec<_>, Vec<_>) = std::mem::take(&mut self.tg.handoff_msgs)
            .into_iter()
            .partition(|m| m.2 <= now);
        self.tg.handoff_msgs = keep;
        if due.is_empty() {
            return;
        }
        let Ok(Some(token)) = self.secrets.get("telegram-bot-token") else {
            return;
        };
        let http = Arc::clone(&self.http);
        let base = self.tg.api_base.clone();
        let job: Job = Box::new(move || {
            let bot = Bot::new(http.as_ref(), &token, &base);
            for (chat, id, _) in due {
                let _ = bot.delete(chat, id);
            }
            Done::Nothing
        });
        let _ = self.submit(job);
    }

    /// `POST /v1/chat/links/open`: what a pointer link names, for the person it was made for. It changes nothing and consumes
    /// nothing: the dashboard page that opens it asks for a passkey for anything that needs one.
    pub(super) fn tg_open_pointer(
        &mut self,
        token: &str,
        person: &str,
        now: u64,
    ) -> Result<String, crate::chat::links::LinkError> {
        use crate::chat::links::LinkError;
        let links = self.chat.links.as_mut().ok_or(LinkError::Invalid)?;
        links.peek(token, person, now).and_then(|t| {
            t.strip_prefix("path:")
                .map(str::to_string)
                .ok_or(LinkError::Invalid)
        })
    }

    /// Every pointer link to `path` is used: what it names was decided.
    pub(super) fn retire_pointers(&mut self, path: &str) {
        if let Some(l) = self.chat.links.as_mut() {
            l.retire(&format!("path:{path}"));
        }
    }
}

/// What the chat gateway reads for an act the policy allowed: its own syntax for the commands the bridge renamed.
fn gateway_text(act: &ChatAct, original: &str) -> String {
    match act {
        ChatAct::SessionPause => "/pause".to_string(),
        ChatAct::SessionResume => "/resume".to_string(),
        _ => original.to_string(),
    }
}

/// Take from a line anything that looks like a pointer-link token or a bot token before it is sealed: the sealed copy is the
/// record of what was asked, not a place a credential should survive.
pub(super) fn redact_for_record(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    let mut rest = text;
    // a pointer link (`/go#<token>`) and a chat page link (`?link=<token>`) alike
    while let Some((i, n)) = [
        rest.find("/go#").map(|i| (i, 4)),
        rest.find("?link=").map(|i| (i, 6)),
    ]
    .into_iter()
    .flatten()
    .min()
    {
        out.push_str(&rest[..i + n]);
        out.push_str("<link>");
        let tail = &rest[i + n..];
        let end = tail
            .find(|c: char| !c.is_ascii_alphanumeric())
            .unwrap_or(tail.len());
        rest = &tail[end..];
    }
    out.push_str(rest);
    out
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod table_copy {
    #[test]
    fn the_dashboards_copy_of_the_act_table_is_the_generated_one() {
        let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../packages/dashboard/src/api/chat-acts.ts");
        let want = ozbox_core::chat_policy::acts::act_table_ts();
        if std::env::var("OZBOX_WRITE_CHAT_ACTS").is_ok() {
            std::fs::write(&path, &want).unwrap();
        }
        let have = std::fs::read_to_string(&path).unwrap_or_default();
        assert_eq!(
            have, want,
            "packages/dashboard/src/api/chat-acts.ts is out of date: regenerate with OZBOX_WRITE_CHAT_ACTS=1 cargo test -p ozbox-cli the_dashboards_copy_of_the_act_table"
        );
    }
}
