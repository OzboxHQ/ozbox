//! The mailboxes: the participant registry, one ordered mailbox per recipient, the sender's record of each message's delivery,
//! rate limits and retention. Plain data, so it serialises into the channel's store; every rule is here once, and both the hub and
//! a worker's replica run it.

use std::collections::{BTreeMap, BTreeSet, VecDeque};

use serde::{Deserialize, Serialize};

use super::addr::{Address, Participant};
use super::model::{
    id_ok, Attribution, Batch, DeliveryState, Message, ParticipantView, Post, PostReceipt,
    KEEP_READ_MS, KEEP_UNREAD_MS, MAX_FANOUT, MAX_GET, MAX_MAILBOX, MAX_TEXT, PER_DAY, PER_MINUTE,
};
use super::policy::Reach;
use super::FabricError;
use crate::agent_mesh::{printable, Screen};

/// The most participants one registry holds.
pub const MAX_PARTICIPANTS: usize = 2_000;

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Mailbox {
    pub last_seq: u64,
    pub msgs: VecDeque<Message>,
}

/// What the sender keeps about a message it sent: the message as sent and each recipient's state.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Sent {
    pub msg: Message,
    pub recipients: BTreeMap<Address, DeliveryState>,
    /// Why the hub refused it, for a post queued on a worker.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub refused: Option<String>,
    /// Raised on every change, so a worker is told only what changed.
    #[serde(default)]
    pub version: u64,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Rate {
    pub minute: u64,
    pub in_minute: u32,
    pub day: u64,
    pub in_day: u32,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Mailboxes {
    pub participants: BTreeMap<Address, Participant>,
    pub boxes: BTreeMap<Address, Mailbox>,
    pub sent: BTreeMap<String, Sent>,
    pub rates: BTreeMap<Address, Rate>,
}

fn not_found() -> FabricError {
    FabricError::NotFound("there is no such participant, or it is not in your reach".into())
}

/// The text as it is stored: control and format characters dropped, trimmed, bounded, and screened. A key-shaped text is refused by
/// the kind of thing it looks like, never echoed.
pub fn clean_text(screen: &dyn Screen, text: &str) -> Result<String, FabricError> {
    let t = printable(text).trim().to_string();
    if t.is_empty() {
        return Err(FabricError::Invalid("a message needs text".into()));
    }
    if t.len() > MAX_TEXT {
        return Err(FabricError::Limit(format!(
            "a message is at most {MAX_TEXT} bytes; put long output in a file and point at it"
        )));
    }
    if let Some(kind) = screen.find(&t) {
        return Err(FabricError::Refused(format!(
            "the message looks like it holds {kind}, so it was not sent; never put a secret in a message"
        )));
    }
    Ok(t)
}

impl Mailboxes {
    pub fn register(&mut self, p: Participant) -> Result<(), FabricError> {
        let p = p.checked()?;
        if !self.participants.contains_key(&p.address)
            && self.participants.len() >= MAX_PARTICIPANTS
        {
            return Err(FabricError::Limit("the registry is full".into()));
        }
        self.participants.insert(p.address.clone(), p);
        Ok(())
    }

    /// The reach a caller really has: a registered agent's own record (what it claims beyond that is ignored) plus what its
    /// person delegated; a person as themselves.
    pub fn reach_of(&self, by: &Reach) -> Result<Reach, FabricError> {
        let reg = self.participants.get(&by.me).ok_or_else(|| {
            FabricError::Refused(format!("{} is not registered on the fabric", by.me))
        })?;
        if reg.person != by.person {
            return Err(FabricError::Refused(
                "a caller acts only for its own person".into(),
            ));
        }
        let mut r = match &by.me {
            Address::Person { id } => Reach::person(id),
            Address::Agent { .. } => Reach::of(reg),
            _ => {
                return Err(FabricError::Refused(
                    "a group or a fleet never sends".into(),
                ))
            }
        };
        r.delegated = by.delegated.clone();
        Ok(r)
    }

    /// Who a post reaches: each address seen, groups and fleets expanded to members the sender also sees, never the sender itself.
    pub fn expand(&self, r: &Reach, to: &[Address]) -> Result<Vec<Address>, FabricError> {
        if to.is_empty() {
            return Err(FabricError::Invalid("name at least one recipient".into()));
        }
        let mut out = BTreeSet::new();
        for a in to {
            let p = self
                .participants
                .get(a)
                .filter(|p| r.sees(p))
                .ok_or_else(not_found)?;
            if a.is_many() {
                for m in &p.members {
                    if m != &r.me && self.participants.get(m).is_some_and(|q| r.sees(q)) {
                        out.insert(m.clone());
                    }
                }
            } else if a != &r.me {
                out.insert(a.clone());
            }
        }
        if out.is_empty() {
            return Err(FabricError::Invalid(
                "nobody in your reach is left to receive it".into(),
            ));
        }
        if out.len() > MAX_FANOUT {
            return Err(FabricError::Limit(format!(
                "one message reaches at most {MAX_FANOUT} participants"
            )));
        }
        Ok(out.into_iter().collect())
    }

    fn rate(&mut self, who: &Address, now: u64) -> Result<(), FabricError> {
        let r = self.rates.entry(who.clone()).or_default();
        let (minute, day) = (now / 60_000, now / 86_400_000);
        if r.minute != minute {
            r.minute = minute;
            r.in_minute = 0;
        }
        if r.day != day {
            r.day = day;
            r.in_day = 0;
        }
        if r.in_minute >= PER_MINUTE || r.in_day >= PER_DAY {
            return Err(FabricError::Limit(format!(
                "at most {PER_MINUTE} messages a minute and {PER_DAY} a day; wait and send again"
            )));
        }
        r.in_minute += 1;
        r.in_day += 1;
        Ok(())
    }

    /// Everything a post must pass before it is stored, on a worker and again on the hub: the caller's real reach, the text
    /// cleaned and screened, the recipients expanded and seen, and the rate. Returns the reach, the text and the recipients.
    pub fn check(
        &mut self,
        screen: &dyn Screen,
        by: &Reach,
        post: &Post,
        now: u64,
    ) -> Result<(Reach, String, Vec<Address>), FabricError> {
        let r = self.reach_of(by)?;
        let text = clean_text(screen, &post.text)?;
        let recipients = self.expand(&r, &post.to)?;
        if let Some(t) = &post.thread {
            if !id_ok(t) {
                return Err(FabricError::Invalid("a thread id is a short word".into()));
            }
        }
        if let Some(pid) = &post.reply_to {
            if self.find_own(&r.me, pid).is_none() {
                return Err(FabricError::NotFound(
                    "you have no message with that id".into(),
                ));
            }
        }
        for a in &recipients {
            let unread = self.boxes.get(a).map_or(0, |b| {
                b.msgs
                    .iter()
                    .filter(|m| m.state != DeliveryState::Read)
                    .count()
            });
            if unread >= MAX_MAILBOX {
                return Err(FabricError::Limit(format!(
                    "{a} has {MAX_MAILBOX} unread messages; it must read some first"
                )));
            }
        }
        self.rate(&r.me, now)?;
        Ok((r, text, recipients))
    }

    /// The thread of a message the caller received or sent.
    pub fn thread_of(&self, me: &Address, id: &str) -> Option<String> {
        self.find_own(me, id).map(|m| m.thread.clone())
    }

    /// Store a post. `id` is the sender's (a worker makes it when the post is queued), so a post that arrives twice is stored once.
    pub fn post(
        &mut self,
        screen: &dyn Screen,
        by: &Reach,
        post: Post,
        id: String,
        now: u64,
    ) -> Result<PostReceipt, FabricError> {
        if let Some(s) = self.sent.get(&id) {
            if s.msg.from != by.me {
                return Err(FabricError::Invalid("that message id is taken".into()));
            }
            return Ok(receipt(s));
        }
        if !id_ok(&id) {
            return Err(FabricError::Invalid("a message id is a short word".into()));
        }
        let (r, text, recipients) = self.check(screen, by, &post, now)?;
        let first = post.to.first().cloned().ok_or_else(not_found)?;
        let thread = match (post.thread, &post.reply_to) {
            (Some(t), _) => t,
            (None, Some(pid)) => self.thread_of(&r.me, pid).unwrap_or_else(|| id.clone()),
            (None, None) => id.clone(),
        };
        let from = self
            .participants
            .get(&r.me)
            .map(Attribution::of)
            .ok_or_else(not_found)?;
        let msg = Message {
            id: id.clone(),
            thread,
            reply_to: post.reply_to,
            from: r.me.clone(),
            // several addresses: the sender's record names the first, and each copy names its own recipient (below)
            to: first,
            recipient: r.me.clone(),
            text,
            sent_ms: now,
            seq: 0,
            attribution: from,
            state: DeliveryState::Accepted,
        };
        let multi = post.to.len() > 1;
        let mut states = BTreeMap::new();
        for a in recipients {
            let b = self.boxes.entry(a.clone()).or_default();
            // a full mailbox drops its oldest read message
            if b.msgs.len() >= MAX_MAILBOX {
                if let Some(i) = b.msgs.iter().position(|m| m.state == DeliveryState::Read) {
                    b.msgs.remove(i);
                }
            }
            b.last_seq += 1;
            let mut copy = msg.clone();
            copy.recipient = a.clone();
            if multi {
                copy.to = a.clone();
            }
            copy.seq = b.last_seq;
            b.msgs.push_back(copy);
            states.insert(a, DeliveryState::Accepted);
        }
        let s = Sent {
            msg,
            recipients: states,
            refused: None,
            version: 1,
        };
        let out = receipt(&s);
        self.sent.insert(id, s);
        Ok(out)
    }

    fn find_own(&self, me: &Address, id: &str) -> Option<&Message> {
        self.boxes
            .get(me)
            .and_then(|b| b.msgs.iter().find(|m| m.id == id))
            .or_else(|| {
                self.sent
                    .get(id)
                    .filter(|s| &s.msg.from == me)
                    .map(|s| &s.msg)
            })
    }

    /// The caller's mailbox after `after`, oldest first. Marks what it returns delivered.
    pub fn get(&mut self, by: &Reach, after: u64, limit: usize) -> Batch {
        let Some(b) = self.boxes.get_mut(&by.me) else {
            return Batch {
                messages: Vec::new(),
                next: after,
                more: false,
            };
        };
        let limit = limit.clamp(1, MAX_GET);
        let mut out = Vec::new();
        let mut more = false;
        for m in b.msgs.iter_mut().filter(|m| m.seq > after) {
            if out.len() >= limit {
                more = true;
                break;
            }
            if m.state == DeliveryState::Accepted {
                m.state = DeliveryState::Delivered;
            }
            out.push(m.clone());
        }
        let next = out.last().map_or(after, |m| m.seq);
        let ids: Vec<String> = out
            .iter()
            .filter(|m| m.state == DeliveryState::Delivered)
            .map(|m| m.id.clone())
            .collect();
        for id in ids {
            self.set_state(&by.me, &id, DeliveryState::Delivered);
        }
        Batch {
            messages: out,
            next,
            more,
        }
    }

    /// Record a recipient's state on the sender's record, only ever forward.
    pub fn set_state(&mut self, recipient: &Address, id: &str, st: DeliveryState) -> bool {
        let Some(s) = self.sent.get_mut(id) else {
            return false;
        };
        match s.recipients.get_mut(recipient) {
            Some(cur) if *cur < st => {
                *cur = st;
                s.version += 1;
                true
            }
            _ => false,
        }
    }

    pub fn ack(&mut self, by: &Reach, ids: &[String]) -> usize {
        let mut changed = Vec::new();
        if let Some(b) = self.boxes.get_mut(&by.me) {
            for m in b.msgs.iter_mut() {
                if ids.contains(&m.id) && m.state != DeliveryState::Read {
                    m.state = DeliveryState::Read;
                    changed.push(m.id.clone());
                }
            }
        }
        for id in &changed {
            self.set_state(&by.me, id, DeliveryState::Read);
        }
        changed.len()
    }

    /// The thread as the caller sees it: the copies in its mailbox and the messages it sent, in time order.
    pub fn thread(&self, by: &Reach, thread: &str) -> Vec<Message> {
        let mut v: Vec<Message> = self
            .boxes
            .get(&by.me)
            .map(|b| {
                b.msgs
                    .iter()
                    .filter(|m| m.thread == thread)
                    .cloned()
                    .collect()
            })
            .unwrap_or_default();
        v.extend(
            self.sent
                .values()
                .filter(|s| s.msg.from == by.me && s.msg.thread == thread)
                .map(|s| {
                    // what the sender sees of its own message: the least advanced of its recipients' states
                    let mut m = s.msg.clone();
                    if let Some(st) = s.recipients.values().min() {
                        m.state = *st;
                    }
                    m
                }),
        );
        v.sort_by(|a, b| (a.sent_ms, &a.id).cmp(&(b.sent_ms, &b.id)));
        v.dedup_by(|a, b| a.id == b.id);
        v
    }

    pub fn participants(&self, by: &Reach) -> Vec<ParticipantView> {
        self.participants
            .values()
            .filter(|p| by.sees(p))
            .map(ParticipantView::of)
            .collect()
    }

    pub fn sent_states(
        &self,
        by: &Reach,
        id: &str,
    ) -> Result<Vec<(Address, DeliveryState)>, FabricError> {
        self.sent
            .get(id)
            .filter(|s| s.msg.from == by.me)
            .map(|s| s.recipients.clone().into_iter().collect())
            .ok_or_else(|| FabricError::NotFound("you sent no message with that id".into()))
    }

    /// Retention: read messages after 30 days, unread after 90 (their senders see `expired`), and the sender's records once every
    /// copy is gone. Returns how many copies went.
    pub fn sweep(&mut self, now: u64) -> usize {
        let mut expired = Vec::new();
        let mut gone = 0;
        for (addr, b) in self.boxes.iter_mut() {
            b.msgs.retain(|m| {
                let keep = if m.state == DeliveryState::Read {
                    now < m.sent_ms.saturating_add(KEEP_READ_MS)
                } else {
                    now < m.sent_ms.saturating_add(KEEP_UNREAD_MS)
                };
                if !keep {
                    gone += 1;
                    if m.state != DeliveryState::Read {
                        expired.push((addr.clone(), m.id.clone()));
                    }
                }
                keep
            });
        }
        for (a, id) in expired {
            self.set_state(&a, &id, DeliveryState::Expired);
        }
        // the sender's record outlives the copies by the read period, so an expiry can still be told
        self.sent
            .retain(|_, s| now < s.msg.sent_ms.saturating_add(KEEP_UNREAD_MS + KEEP_READ_MS));
        gone
    }
}

pub fn receipt(s: &Sent) -> PostReceipt {
    PostReceipt {
        id: s.msg.id.clone(),
        thread: s.msg.thread.clone(),
        recipients: s.recipients.clone().into_iter().collect(),
    }
}
