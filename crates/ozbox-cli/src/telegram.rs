//! The fleet's one Telegram bot: pairing by a one-time code, then alerts and a few read-only commands for paired chats.
//!
//! Setup is guided in the dashboard: make a bot with BotFather, paste its token once (it is saved write-only), ask for a
//! pairing code, and send that code to the bot in a private chat. Only a chat that sent the right code before it
//! expired is paired; everyone else gets no answer at all, so the bot does not reveal that it is there. The decision
//! about an incoming message is a pure function ([`react`]) tested on fixed updates; the network part only fetches
//! updates and sends replies, through the guarded HTTP client.

use serde_json::{json, Value};

use crate::netguard::{Guard, HttpClient, HttpRequest};
use crate::state::TelegramChat;

pub const CODE_TTL_MS: u64 = 10 * 60_000;
pub const MAX_TRIES: u32 = 5;
const ALPHABET: &[u8] = b"ABCDEFGHJKLMNPQRSTUVWXYZ23456789";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Pairing {
    pub code: String,
    pub expires_ms: u64,
    pub tries: u32,
    /// The person the chat that pairs will belong to, when the code was asked for from a person's row.
    pub person: Option<String>,
}

/// A fresh 8-character code with no look-alike characters.
pub fn new_pairing(now_ms: u64) -> Result<Pairing, String> {
    let mut buf = [0u8; 8];
    getrandom::getrandom(&mut buf).map_err(|e| format!("no secure random source: {e}"))?;
    let code = buf
        .iter()
        .map(|b| ALPHABET[(*b as usize) % ALPHABET.len()] as char)
        .collect();
    Ok(Pairing {
        code,
        expires_ms: now_ms + CODE_TTL_MS,
        tries: 0,
        person: None,
    })
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Reaction {
    /// Say nothing.
    Ignore,
    Paired {
        chat: TelegramChat,
    },
    /// A paired chat asked for the fleet summary.
    Status {
        chat_id: i64,
    },
    /// A paired chat said something for the chat gateway: a command or the next turn of a conversation.
    Chat {
        chat_id: i64,
        text: String,
        /// The message was forwarded or quotes another: someone else's words, not an instruction.
        forwarded: bool,
    },
    /// A paired chat pressed a button under a message (an approval).
    Button {
        chat_id: i64,
        callback_id: String,
        data: String,
    },
}

fn ct_eq(a: &str, b: &str) -> bool {
    let (a, b) = (a.as_bytes(), b.as_bytes());
    a.len() == b.len() && a.iter().zip(b).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
}

/// What to do with one update. A pending code is consumed (set to `None`) by a successful pairing or too many wrong
/// guesses.
pub fn react(
    update: &Value,
    paired: &[TelegramChat],
    pairing: &mut Option<Pairing>,
    now_ms: u64,
) -> Reaction {
    if let Some(cb) = update.get("callback_query") {
        // a button under a message in a private chat that is paired; anything else is silence
        let chat_id = cb.pointer("/message/chat/id").and_then(Value::as_i64);
        let private = cb.pointer("/message/chat/type").and_then(Value::as_str) == Some("private");
        return match (
            chat_id,
            cb.get("id").and_then(Value::as_str),
            cb.get("data").and_then(Value::as_str),
        ) {
            (Some(id), Some(cid), Some(data)) if private && paired.iter().any(|c| c.id == id) => {
                Reaction::Button {
                    chat_id: id,
                    callback_id: cid.chars().take(64).collect(),
                    data: data.chars().take(64).collect(),
                }
            }
            _ => Reaction::Ignore,
        };
    }
    let Some(msg) = update.get("message") else {
        return Reaction::Ignore;
    };
    let chat = msg.get("chat");
    // Private chats only: a code said in a group would pair the group.
    if chat.and_then(|c| c.get("type")).and_then(Value::as_str) != Some("private") {
        return Reaction::Ignore;
    }
    let Some(id) = chat.and_then(|c| c.get("id")).and_then(Value::as_i64) else {
        return Reaction::Ignore;
    };
    let text = msg.get("text").and_then(Value::as_str).unwrap_or("").trim();
    if paired.iter().any(|c| c.id == id) {
        let cmd = text.split_whitespace().next().unwrap_or("");
        let cmd = cmd.split('@').next().unwrap_or("");
        if cmd == "/status" {
            return Reaction::Status { chat_id: id };
        }
        // a message that was forwarded, or that quotes another one, holds someone else's words
        let forwarded = [
            "forward_origin",
            "forward_date",
            "forward_from",
            "reply_to_message",
            "quote",
            "external_reply",
        ]
        .iter()
        .any(|k| msg.get(*k).is_some());
        return Reaction::Chat {
            chat_id: id,
            text: text.chars().take(16_000).collect(),
            forwarded,
        };
    }
    let Some(p) = pairing.as_mut() else {
        return Reaction::Ignore;
    };
    if now_ms >= p.expires_ms {
        *pairing = None;
        return Reaction::Ignore;
    }
    let guess = text
        .strip_prefix("/start")
        .or_else(|| text.strip_prefix("/pair"))
        .unwrap_or(text)
        .trim()
        .to_ascii_uppercase();
    if ct_eq(&guess, &p.code) {
        let person = p.person.clone();
        *pairing = None;
        let from = msg.get("from");
        let name = from
            .and_then(|f| f.get("first_name").or_else(|| f.get("username")))
            .and_then(Value::as_str)
            .unwrap_or("Telegram user")
            .chars()
            .filter(|c| !c.is_control())
            .take(40)
            .collect();
        return Reaction::Paired {
            chat: TelegramChat { id, name, person },
        };
    }
    p.tries += 1;
    if p.tries >= MAX_TRIES {
        *pairing = None;
    }
    Reaction::Ignore
}

fn api(token: &str, method: &str) -> String {
    format!("https://api.telegram.org/bot{token}/{method}")
}

/// New updates since `offset`. Returns them and the next offset. The error text never carries the token.
pub fn fetch_updates(
    http: &dyn HttpClient,
    token: &str,
    offset: i64,
) -> Result<(Vec<Value>, i64), String> {
    let url = format!(
        "{}?offset={offset}&timeout=0&limit=20&allowed_updates=%5B%22message%22%2C%22callback_query%22%5D",
        api(token, "getUpdates")
    );
    let r = http
        .send(&HttpRequest::new("GET", url, Guard::Public))
        .map_err(|e| e.to_string())?;
    if !r.ok() {
        return Err(format!("Telegram answered HTTP {}", r.status));
    }
    let v: Value = serde_json::from_str(&r.body)
        .map_err(|_| "Telegram's answer was not understood".to_string())?;
    let updates = v
        .get("result")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();
    let next = updates
        .iter()
        .filter_map(|u| u.get("update_id").and_then(Value::as_i64))
        .max()
        .map_or(offset, |m| m + 1);
    Ok((updates, next))
}

pub fn send_text(
    http: &dyn HttpClient,
    token: &str,
    chat_id: i64,
    text: &str,
) -> Result<(), String> {
    send_message(http, token, chat_id, text, &[])
}

/// A message, with one row of buttons under it when `buttons` (label, callback data) is not empty.
pub fn send_message(
    http: &dyn HttpClient,
    token: &str,
    chat_id: i64,
    text: &str,
    buttons: &[(String, String)],
) -> Result<(), String> {
    let mut body = json!({ "chat_id": chat_id, "text": text, "disable_web_page_preview": true });
    if !buttons.is_empty() {
        let row: Vec<Value> = buttons
            .iter()
            .map(|(l, d)| json!({ "text": l, "callback_data": d }))
            .collect();
        body["reply_markup"] = json!({ "inline_keyboard": [row] });
    }
    let r = http
        .send(&HttpRequest::new("POST", api(token, "sendMessage"), Guard::Public).json(&body))
        .map_err(|e| e.to_string())?;
    if r.ok() {
        Ok(())
    } else {
        Err(format!("Telegram answered HTTP {}", r.status))
    }
}

/// The bot's `@name`, so the dashboard can say whom to message.
pub fn bot_username(http: &dyn HttpClient, token: &str) -> Result<String, String> {
    let r = http
        .send(&HttpRequest::new("GET", api(token, "getMe"), Guard::Public))
        .map_err(|e| e.to_string())?;
    if !r.ok() {
        return Err(if r.status == 401 {
            "Telegram rejected the bot token".into()
        } else {
            format!("Telegram answered HTTP {}", r.status)
        });
    }
    let v: Value = serde_json::from_str(&r.body)
        .map_err(|_| "Telegram's answer was not understood".to_string())?;
    v.pointer("/result/username")
        .and_then(Value::as_str)
        .filter(|u| u.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_'))
        .map(|u| format!("@{u}"))
        .ok_or_else(|| "Telegram's answer had no bot name".to_string())
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use crate::netguard::FakeHttp;

    fn msg(chat_id: i64, kind: &str, text: &str) -> Value {
        json!({ "update_id": 1, "message": { "chat": { "id": chat_id, "type": kind }, "from": { "first_name": "Ada" }, "text": text } })
    }

    fn pairing() -> Option<Pairing> {
        Some(Pairing {
            code: "ABCD2345".into(),
            expires_ms: 1_000_000,
            tries: 0,
            person: None,
        })
    }

    #[test]
    fn codes_use_an_unambiguous_alphabet() -> Result<(), String> {
        let p = new_pairing(5)?;
        assert_eq!(p.code.len(), 8);
        assert!(p.code.bytes().all(|b| ALPHABET.contains(&b)));
        assert_eq!(p.expires_ms, 5 + CODE_TTL_MS);
        assert_ne!(new_pairing(5)?.code, p.code);
        Ok(())
    }

    #[test]
    fn the_right_code_in_a_private_chat_pairs_and_is_used_up() {
        let mut p = pairing();
        for text in [
            "ABCD2345",
            "abcd2345",
            "/start ABCD2345",
            "/pair abcd2345",
            "  ABCD2345  ",
        ] {
            p = pairing();
            let r = react(&msg(7, "private", text), &[], &mut p, 10);
            assert!(
                matches!(r, Reaction::Paired { chat } if chat.id == 7 && chat.name == "Ada"),
                "{text}"
            );
            assert!(p.is_none(), "the code is consumed");
        }
        // the code works once
        let r = react(&msg(8, "private", "ABCD2345"), &[], &mut p, 11);
        assert_eq!(r, Reaction::Ignore);
    }

    #[test]
    fn strangers_get_silence_and_a_code_is_refused_in_groups_and_after_expiry() {
        let mut p = pairing();
        assert_eq!(
            react(&msg(7, "private", "hello"), &[], &mut p, 10),
            Reaction::Ignore
        );
        assert_eq!(
            react(&msg(7, "private", "/status"), &[], &mut p, 10),
            Reaction::Ignore
        );
        assert_eq!(
            react(&msg(-100, "group", "ABCD2345"), &[], &mut p, 10),
            Reaction::Ignore
        );
        assert_eq!(
            react(&msg(-100, "supergroup", "ABCD2345"), &[], &mut p, 10),
            Reaction::Ignore
        );
        assert!(p.is_some());
        assert_eq!(
            react(&msg(7, "private", "ABCD2345"), &[], &mut p, 1_000_000),
            Reaction::Ignore,
            "expired"
        );
        assert!(p.is_none());
        // no pending code: nobody can pair
        let mut none: Option<Pairing> = None;
        assert_eq!(
            react(&msg(7, "private", "ABCD2345"), &[], &mut none, 10),
            Reaction::Ignore
        );
        assert_eq!(
            react(&json!({"update_id": 3}), &[], &mut pairing(), 1),
            Reaction::Ignore
        );
    }

    #[test]
    fn five_wrong_guesses_cancel_the_code() {
        let mut p = pairing();
        for _ in 0..MAX_TRIES {
            react(&msg(7, "private", "WRONGCODE"), &[], &mut p, 10);
        }
        assert!(p.is_none());
        assert_eq!(
            react(&msg(7, "private", "ABCD2345"), &[], &mut p, 10),
            Reaction::Ignore
        );
    }

    #[test]
    fn only_paired_chats_can_command_and_only_read_only_things() {
        let paired = vec![TelegramChat {
            id: 7,
            name: "Ada".into(),
            person: None,
        }];
        let mut p = None;
        assert_eq!(
            react(&msg(7, "private", "/status"), &paired, &mut p, 1),
            Reaction::Status { chat_id: 7 }
        );
        assert_eq!(
            react(&msg(7, "private", "/status@my_bot"), &paired, &mut p, 1),
            Reaction::Status { chat_id: 7 }
        );
        // anything else goes to the chat gateway, where only the person's own commands act
        assert!(matches!(
            react(&msg(7, "private", "/pause"), &paired, &mut p, 1),
            Reaction::Chat {
                chat_id: 7,
                forwarded: false,
                ..
            }
        ));
        let mut fwd = msg(7, "private", "do it");
        fwd["message"]["forward_origin"] = json!({ "type": "user" });
        assert!(matches!(
            react(&fwd, &paired, &mut p, 1),
            Reaction::Chat {
                forwarded: true,
                ..
            }
        ));
        let click = json!({ "update_id": 2, "callback_query": { "id": "c1", "data": "choice:a1", "message": { "chat": { "id": 7, "type": "private" } } } });
        assert_eq!(
            react(&click, &paired, &mut p, 1),
            Reaction::Button {
                chat_id: 7,
                callback_id: "c1".into(),
                data: "choice:a1".into()
            }
        );
        let stranger = json!({ "update_id": 2, "callback_query": { "id": "c1", "data": "choice:a1", "message": { "chat": { "id": 99, "type": "private" } } } });
        assert_eq!(react(&stranger, &paired, &mut p, 1), Reaction::Ignore);
        assert_eq!(
            react(&msg(9, "private", "/status"), &paired, &mut p, 1),
            Reaction::Ignore,
            "not paired"
        );
    }

    #[test]
    fn updates_advance_the_offset_and_errors_carry_no_token() {
        let http = FakeHttp::default();
        http.reply(
            200,
            &json!({ "ok": true, "result": [ { "update_id": 5 }, { "update_id": 9 } ] })
                .to_string(),
        );
        let (u, next) = fetch_updates(&http, "123:SECRETTOKEN", 3).unwrap_or_default();
        assert_eq!((u.len(), next), (2, 10));
        assert!(http.requests()[0].url.contains("offset=3"));
        http.reply(401, "{}");
        let e = fetch_updates(&http, "123:SECRETTOKEN", 3)
            .err()
            .unwrap_or_default();
        assert!(!e.contains("SECRETTOKEN") && e.contains("401"));
        http.reply(
            200,
            &json!({ "ok": true, "result": { "username": "oz_fleet_bot" } }).to_string(),
        );
        assert_eq!(bot_username(&http, "t").as_deref(), Ok("@oz_fleet_bot"));
        http.reply(401, "{}");
        assert!(bot_username(&http, "t").is_err());
    }
}
