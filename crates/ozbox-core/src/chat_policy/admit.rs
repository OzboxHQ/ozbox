//! Which Telegram updates are heard at all, and which are fresh and new (ADR 0050 §7: forwarded, quoted, group, channel,
//! business and scheduled messages; replay).
//!
//! [`admit`] reads one `getUpdates` entry and either returns the one thing the bridge may act on (a plain private message
//! from a person, as text) or says why it is not heard. It never reads a button: the bridge subscribes to `message` alone, and
//! this filters by type as well because Telegram's filter does not apply to updates created before it was set.
//!
//! [`SeenSet`] is the replay guard. It is a **set** of `(bot id, update_id)` with a lifetime longer than the freshness
//! window, not a watermark: after a week with no updates Telegram picks the next `update_id` at random, so a lower number is
//! not an old one.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};
use serde_json::Value;

use super::acts::Tier;

/// A message older than this is dropped with "too old, send it again".
pub const FRESH_MS: u64 = 5 * 60_000;
/// For box power and a command run.
pub const FRESH_POWER_MS: u64 = 2 * 60_000;
/// A message dated further ahead than this is not believed.
pub const MAX_FUTURE_MS: u64 = 60_000;
/// How long an `update_id` is remembered: Telegram keeps an update for 24 hours, and this is longer than that.
pub const SEEN_LIFETIME_MS: u64 = 48 * 3_600_000;
/// The longest set kept, so a flood cannot grow the file without bound.
pub const SEEN_MAX: usize = 50_000;

/// Why an update is not heard. None of these gets an answer: a bot that answers a stranger reveals that it is there.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Skip {
    /// Not a plain `message` update: an edit, a button, a channel post, a business or reaction update, a membership change.
    NotAMessage,
    /// A group, supergroup or channel chat.
    NotPrivate,
    /// The sender is not the chat: a message in a private chat is from the person whose chat it is.
    SenderMismatch,
    FromBot,
    /// Sent on behalf of a channel or a chat.
    SenderChat,
    BusinessAccount,
    /// A photo, a sticker, a voice note, a location: only text is read.
    NoText,
}

impl Skip {
    pub const fn code(self) -> &'static str {
        match self {
            Skip::NotAMessage => "not_a_message",
            Skip::NotPrivate => "not_private",
            Skip::SenderMismatch => "sender_mismatch",
            Skip::FromBot => "from_bot",
            Skip::SenderChat => "sender_chat",
            Skip::BusinessAccount => "business",
            Skip::NoText => "no_text",
        }
    }
}

/// A private text message from a person, ready to be matched to a link.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Admitted {
    pub update_id: i64,
    /// Telegram's numeric user id (needs up to 52 bits): equal to the chat id in a private chat.
    pub from_id: i64,
    pub chat_id: i64,
    /// What Telegram calls the person: shown once when pairing, never stored.
    pub first_name: String,
    pub text: String,
    pub date_ms: u64,
    /// Forwarded, quoted, replied to, sent through a bot or delivered from offline: someone else's words, or words whose
    /// moment is not the person's, so they are data and never a command.
    pub data_only: bool,
}

const DATA_ONLY_KEYS: [&str; 9] = [
    "forward_origin",
    "forward_date",
    "forward_from",
    "forward_from_chat",
    "reply_to_message",
    "external_reply",
    "quote",
    "via_bot",
    "is_from_offline",
];

/// Read one update. `Err` says why it is not heard.
pub fn admit(update: &Value) -> Result<Admitted, Skip> {
    let obj = update.as_object().ok_or(Skip::NotAMessage)?;
    let update_id = obj
        .get("update_id")
        .and_then(Value::as_i64)
        .ok_or(Skip::NotAMessage)?;
    // exactly a `message`: any other kind of update next to `update_id` is not heard
    if obj.keys().any(|k| k != "update_id" && k != "message") {
        return Err(Skip::NotAMessage);
    }
    let msg = obj
        .get("message")
        .and_then(Value::as_object)
        .ok_or(Skip::NotAMessage)?;
    let chat = msg
        .get("chat")
        .and_then(Value::as_object)
        .ok_or(Skip::NotPrivate)?;
    if chat.get("type").and_then(Value::as_str) != Some("private") {
        return Err(Skip::NotPrivate);
    }
    let chat_id = chat
        .get("id")
        .and_then(Value::as_i64)
        .ok_or(Skip::NotPrivate)?;
    if msg.contains_key("sender_chat") {
        return Err(Skip::SenderChat);
    }
    if msg.contains_key("business_connection_id") || msg.contains_key("sender_business_bot") {
        return Err(Skip::BusinessAccount);
    }
    let from = msg
        .get("from")
        .and_then(Value::as_object)
        .ok_or(Skip::SenderMismatch)?;
    if from.get("is_bot").and_then(Value::as_bool) == Some(true) {
        return Err(Skip::FromBot);
    }
    let from_id = from
        .get("id")
        .and_then(Value::as_i64)
        .ok_or(Skip::SenderMismatch)?;
    if from_id != chat_id || from_id <= 0 {
        return Err(Skip::SenderMismatch);
    }
    let text = msg
        .get("text")
        .and_then(Value::as_str)
        .ok_or(Skip::NoText)?
        .to_string();
    let date_ms = msg
        .get("date")
        .and_then(Value::as_u64)
        .map_or(0, |s| s.saturating_mul(1000));
    let first_name: String = from
        .get("first_name")
        .and_then(Value::as_str)
        .unwrap_or("")
        .chars()
        .filter(|c| !c.is_control())
        .take(40)
        .collect();
    Ok(Admitted {
        update_id,
        from_id,
        chat_id,
        first_name,
        text,
        date_ms,
        data_only: DATA_ONLY_KEYS.iter().any(|k| msg.contains_key(*k)),
    })
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Freshness {
    Fresh,
    /// Older than the window: dropped with "too old, send it again".
    TooOld,
    /// Dated in the future beyond the allowance: not believed.
    FromTheFuture,
}

/// How old an act may be: two minutes for box power and a command run, five for the rest. `message.date` is Telegram's, not
/// the sender's.
pub fn freshness(date_ms: u64, now_ms: u64, tier: Tier) -> Freshness {
    let window = if matches!(tier, Tier::Power | Tier::Run) {
        FRESH_POWER_MS
    } else {
        FRESH_MS
    };
    if date_ms == 0 {
        return Freshness::TooOld;
    }
    if date_ms > now_ms.saturating_add(MAX_FUTURE_MS) {
        return Freshness::FromTheFuture;
    }
    if now_ms.saturating_sub(date_ms) > window {
        return Freshness::TooOld;
    }
    Freshness::Fresh
}

/// The replay guard: a set of `(bot id, update_id)`.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct SeenSet {
    /// `"<bot id>:<update id>"` to the time it was first seen.
    entries: BTreeMap<String, u64>,
    /// When the set was last pruned: a prune walks the whole set, so it is done at most once a minute.
    #[serde(skip)]
    pruned_ms: u64,
}

fn key(bot_id: i64, update_id: i64) -> String {
    format!("{bot_id}:{update_id}")
}

impl SeenSet {
    pub fn contains(&self, bot_id: i64, update_id: i64) -> bool {
        self.entries.contains_key(&key(bot_id, update_id))
    }

    /// Record an update. `false` when it was already there (a replay): nothing is recorded and nothing may be done.
    pub fn insert(&mut self, bot_id: i64, update_id: i64, now_ms: u64) -> bool {
        if now_ms.saturating_sub(self.pruned_ms) > 60_000 {
            self.prune(now_ms);
        }
        let k = key(bot_id, update_id);
        if self.entries.contains_key(&k) {
            return false;
        }
        if self.entries.len() >= SEEN_MAX {
            // keep the newest: drop the oldest tenth
            let mut by_time: Vec<(&String, &u64)> = self.entries.iter().collect();
            by_time.sort_by_key(|(_, t)| **t);
            let drop: Vec<String> = by_time
                .iter()
                .take(SEEN_MAX / 10)
                .map(|(k, _)| (*k).clone())
                .collect();
            for k in drop {
                self.entries.remove(&k);
            }
        }
        self.entries.insert(k, now_ms);
        true
    }

    /// Forget what is older than the lifetime.
    pub fn prune(&mut self, now_ms: u64) {
        self.pruned_ms = now_ms;
        self.entries
            .retain(|_, t| now_ms.saturating_sub(*t) <= SEEN_LIFETIME_MS);
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use serde_json::json;

    fn msg(extra: Value) -> Value {
        let mut m = json!({
            "message_id": 5, "date": 1_000, "text": "/status",
            "chat": { "id": 4_000_000_001_i64, "type": "private", "first_name": "Ada" },
            "from": { "id": 4_000_000_001_i64, "is_bot": false, "first_name": "Ada" }
        });
        if let (Some(o), Some(e)) = (m.as_object_mut(), extra.as_object()) {
            for (k, v) in e {
                o.insert(k.clone(), v.clone());
            }
        }
        json!({ "update_id": 9, "message": m })
    }

    #[test]
    fn a_plain_private_text_message_is_heard() {
        let a = admit(&msg(json!({}))).unwrap();
        assert_eq!(a.update_id, 9);
        assert_eq!((a.from_id, a.chat_id), (4_000_000_001, 4_000_000_001));
        assert_eq!(a.text, "/status");
        assert_eq!(a.date_ms, 1_000_000);
        assert!(!a.data_only);
        assert_eq!(a.first_name, "Ada");
    }

    #[test]
    fn group_channel_bot_business_sender_chat_and_non_text_are_not_heard() {
        let mut g = msg(json!({}));
        g["message"]["chat"]["type"] = json!("supergroup");
        assert_eq!(admit(&g), Err(Skip::NotPrivate));
        let mut c = msg(json!({}));
        c["message"]["chat"]["type"] = json!("channel");
        assert_eq!(admit(&c), Err(Skip::NotPrivate));
        assert_eq!(
            admit(&msg(
                json!({ "sender_chat": { "id": -5, "type": "channel" } })
            )),
            Err(Skip::SenderChat)
        );
        assert_eq!(
            admit(&msg(json!({ "business_connection_id": "b1" }))),
            Err(Skip::BusinessAccount)
        );
        let mut bot = msg(json!({}));
        bot["message"]["from"]["is_bot"] = json!(true);
        assert_eq!(admit(&bot), Err(Skip::FromBot));
        let mut other = msg(json!({}));
        other["message"]["from"]["id"] = json!(4_000_000_002_i64);
        assert_eq!(admit(&other), Err(Skip::SenderMismatch));
        let mut photo = msg(json!({}));
        photo["message"].as_object_mut().unwrap().remove("text");
        assert_eq!(admit(&photo), Err(Skip::NoText));
        let mut anon = msg(json!({}));
        anon["message"].as_object_mut().unwrap().remove("from");
        assert_eq!(admit(&anon), Err(Skip::SenderMismatch));
    }

    #[test]
    fn only_a_message_update_is_heard_an_edit_or_a_button_or_a_post_is_not() {
        for kind in [
            "edited_message",
            "callback_query",
            "channel_post",
            "edited_channel_post",
            "business_message",
            "my_chat_member",
            "message_reaction",
            "inline_query",
        ] {
            let m = msg(json!({}));
            let body = m["message"].clone();
            let u = json!({ "update_id": 9, (kind): body });
            assert_eq!(admit(&u), Err(Skip::NotAMessage), "{kind}");
        }
        // a message update that carries another update's key beside it is not trusted either
        let mut both = msg(json!({}));
        both["callback_query"] = json!({ "id": "c", "data": "approve:1" });
        assert_eq!(admit(&both), Err(Skip::NotAMessage));
        assert_eq!(admit(&json!("x")), Err(Skip::NotAMessage));
        assert_eq!(admit(&json!({ "message": {} })), Err(Skip::NotAMessage));
    }

    #[test]
    fn forwarded_quoted_replied_and_via_bot_text_is_data() {
        for k in [
            "forward_origin",
            "forward_date",
            "forward_from",
            "reply_to_message",
            "external_reply",
            "quote",
            "via_bot",
            "is_from_offline",
        ] {
            let a = admit(&msg(json!({ (k): { "x": 1 } }))).unwrap();
            assert!(a.data_only, "{k}");
        }
    }

    #[test]
    fn freshness_is_five_minutes_and_two_for_power_and_run_by_telegrams_date() {
        let now = 1_000_000 + 10 * 60_000;
        assert_eq!(freshness(now - 60_000, now, Tier::Read), Freshness::Fresh);
        assert_eq!(freshness(now - 301_000, now, Tier::Read), Freshness::TooOld);
        assert_eq!(freshness(now - 119_000, now, Tier::Power), Freshness::Fresh);
        assert_eq!(
            freshness(now - 121_000, now, Tier::Power),
            Freshness::TooOld
        );
        assert_eq!(freshness(now - 121_000, now, Tier::Run), Freshness::TooOld);
        assert_eq!(
            freshness(now - 121_000, now, Tier::Converse),
            Freshness::Fresh
        );
        assert_eq!(freshness(now + 30_000, now, Tier::Read), Freshness::Fresh);
        assert_eq!(
            freshness(now + 90_000, now, Tier::Read),
            Freshness::FromTheFuture
        );
        assert_eq!(freshness(0, now, Tier::Read), Freshness::TooOld);
    }

    #[test]
    fn replay_is_a_set_so_a_random_update_id_after_a_long_gap_is_new_and_a_seen_one_is_never() {
        let mut s = SeenSet::default();
        let t0 = 1_000;
        assert!(s.insert(7, 100, t0));
        assert!(!s.insert(7, 100, t0 + 1), "the same update again");
        assert!(
            s.insert(8, 100, t0 + 1),
            "another bot's update_id is another update"
        );
        // a week with no updates: Telegram's next update_id is random, here far below the earlier one
        let week = t0 + 7 * 24 * 3_600_000;
        assert!(s.insert(7, 5, week), "a lower number is not an old one");
        assert!(
            s.insert(7, 3_000_000_000, week + 1),
            "and a far higher one is not a replay"
        );
        assert!(
            s.insert(7, 100, week + 2),
            "the old entry aged out and the id is unseen now"
        );
        // within the lifetime a seen id stays seen, even when it is lower than everything after it
        assert!(s.insert(7, 6, week + 3));
        assert!(!s.insert(7, 5, week + 4));
        assert!(s.contains(7, 3_000_000_000));
    }

    #[test]
    fn the_set_has_a_bound_and_prunes_what_is_older_than_its_lifetime() {
        let mut s = SeenSet::default();
        for i in 0..(SEEN_MAX as i64 + 10) {
            s.insert(1, i, 5_000 + i as u64);
        }
        assert!(s.len() <= SEEN_MAX);
        assert!(s.contains(1, SEEN_MAX as i64 + 9), "the newest is kept");
        s.prune(5_000 + SEEN_LIFETIME_MS + 100_000);
        assert!(s.is_empty());
        let json = serde_json::to_string(&s).unwrap();
        assert_eq!(
            serde_json::from_str::<SeenSet>(&json).unwrap().len(),
            s.len()
        );
    }
}
