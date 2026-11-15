//! A stand-in for Telegram, for the simulated (fake-provider) server in browser tests and demos.
//!
//! Pairing needs a bot and a person with a phone, so nothing about it could be tried without a real account. Here the
//! bot's address is answered locally: `getMe` names a demo bot, `getUpdates` returns what a test "sent" to it, and
//! `sendMessage` is accepted and remembered. Everything else about pairing runs the real code: the code, the one-time
//! check, the chat list and the linking to a person all go through [`crate::telegram`] unchanged.
//!
//! `POST /v1/demo/telegram/fail` makes the next few `sendMessage` calls answer HTTP 503, and sets how long the server
//! waits between tries, so a browser test can watch an alert go from "retrying" to "delivered", or run out of tries.
//!
//! The same switch also allows `POST /v1/demo/alerts`, which raises one alert through the real routing path.
//!
//! It exists only when the server runs the fake provider AND `OZBOX_DEMO_TELEGRAM=1` is set (see [`enabled`]); with a
//! real provider, or without that variable, the server talks to the real Telegram and the demo route does not exist.

use std::sync::{Arc, Mutex};

use serde::Deserialize;
use serde_json::{json, Value};

use super::{App, Resp};
use crate::netguard::{HttpClient, HttpError, HttpRequest, HttpResponse, UreqClient};

const BOT_PREFIX: &str = "https://api.telegram.org/bot";
/// How many remembered messages the demo keeps.
const KEEP: usize = 200;

/// Whether the demo Telegram is on: only for the simulated server, and only when asked for by name.
pub fn enabled(simulated: bool, var: Option<&str>) -> bool {
    simulated && var == Some("1")
}

#[derive(Debug, Default)]
pub struct State {
    updates: Vec<Value>,
    next_id: i64,
    /// (chat, the first words, the data of the buttons under it).
    sent: Vec<(i64, String, Vec<String>)>,
    /// How many of the next `sendMessage` calls still answer 503.
    fail_sends: u32,
    /// The pause between tries of a failed delivery, in milliseconds (0: the default below).
    retry_ms: u64,
    /// How many of the next `getUpdates` calls answer 409 (another reader, or a webhook), and 429 with `retry_after`.
    conflicts: u32,
    rate_limited: u32,
    /// A webhook "somebody set": `getWebhookInfo` names it.
    webhook: Option<String>,
    /// The flags `getMe` reports (all off, as the bridge requires, unless a test turns one on).
    can_join_groups: bool,
    can_read_all_group_messages: bool,
    supports_inline_queries: bool,
    /// The ids of the messages the bridge asked to delete.
    deleted: Vec<i64>,
    next_message_id: i64,
}

/// The pause between tries when the demo server is asked for none: long enough for a browser to see "retrying".
const DEFAULT_RETRY_MS: u64 = 3_000;
/// The most failures one request may ask for: the real server stops after four tries.
const MAX_FAILS: u32 = 20;

pub type Shared = Arc<Mutex<State>>;

/// Answers the Telegram bot API locally and hands every other request to the real client.
pub struct DemoTelegram {
    inner: Arc<dyn HttpClient>,
    state: Shared,
}

impl DemoTelegram {
    pub fn new(inner: Arc<dyn HttpClient>, state: Shared) -> Self {
        Self { inner, state }
    }
}

fn json_ok(v: &Value) -> Result<HttpResponse, HttpError> {
    Ok(HttpResponse {
        status: 200,
        body: v.to_string(),
    })
}

impl HttpClient for DemoTelegram {
    fn send(&self, req: &HttpRequest) -> Result<HttpResponse, HttpError> {
        let Some(rest) = req.url.strip_prefix(BOT_PREFIX) else {
            return self.inner.send(req);
        };
        let (_token, call) = rest.split_once('/').unwrap_or((rest, ""));
        let (method, query) = call.split_once('?').unwrap_or((call, ""));
        let Ok(mut st) = self.state.lock() else {
            return Err(HttpError::Transport("the request did not complete"));
        };
        match method {
            "answerCallbackQuery" => json_ok(&json!({ "ok": true, "result": true })),
            "getMe" => json_ok(&json!({ "ok": true, "result": {
                "id": 7_000_000_002_i64, "is_bot": true, "username": "oz_demo_bot",
                "can_join_groups": st.can_join_groups,
                "can_read_all_group_messages": st.can_read_all_group_messages,
                "supports_inline_queries": st.supports_inline_queries,
            } })),
            "getWebhookInfo" => json_ok(
                &json!({ "ok": true, "result": { "url": st.webhook.clone().unwrap_or_default() } }),
            ),
            "deleteMessage" => {
                let body: Value = req
                    .body
                    .as_deref()
                    .and_then(|b| serde_json::from_slice(b).ok())
                    .unwrap_or(Value::Null);
                st.deleted
                    .push(body.get("message_id").and_then(Value::as_i64).unwrap_or(0));
                json_ok(&json!({ "ok": true, "result": true }))
            }
            "getUpdates" => {
                if st.conflicts > 0 {
                    st.conflicts -= 1;
                    return Ok(HttpResponse {
                        status: 409,
                        body: r#"{"ok":false,"error_code":409}"#.into(),
                    });
                }
                if st.rate_limited > 0 {
                    st.rate_limited -= 1;
                    return Ok(HttpResponse {
                        status: 429,
                        body: r#"{"ok":false,"error_code":429,"parameters":{"retry_after":1}}"#
                            .into(),
                    });
                }
                let offset: i64 = query
                    .split('&')
                    .find_map(|p| p.strip_prefix("offset="))
                    .and_then(|v| v.parse().ok())
                    .unwrap_or(0);
                let list: Vec<Value> = st
                    .updates
                    .iter()
                    .filter(|u| u.get("update_id").and_then(Value::as_i64).unwrap_or(0) >= offset)
                    .cloned()
                    .collect();
                json_ok(&json!({ "ok": true, "result": list }))
            }
            "sendMessage" => {
                let body: Value = req
                    .body
                    .as_deref()
                    .and_then(|b| serde_json::from_slice(b).ok())
                    .unwrap_or(Value::Null);
                if st.fail_sends > 0 {
                    st.fail_sends -= 1;
                    return Ok(HttpResponse {
                        status: 503,
                        body: "{}".into(),
                    });
                }
                let chat = body.get("chat_id").and_then(Value::as_i64).unwrap_or(0);
                let text = body.get("text").and_then(Value::as_str).unwrap_or("");
                let buttons: Vec<String> = body
                    .pointer("/reply_markup/inline_keyboard/0")
                    .and_then(Value::as_array)
                    .map(|row| {
                        row.iter()
                            .filter_map(|b| {
                                b.get("callback_data")
                                    .and_then(Value::as_str)
                                    .map(str::to_string)
                            })
                            .collect()
                    })
                    .unwrap_or_default();
                st.sent
                    .push((chat, text.chars().take(400).collect(), buttons));
                let over = st.sent.len().saturating_sub(KEEP);
                st.sent.drain(..over);
                st.next_message_id += 1;
                json_ok(&json!({ "ok": true, "result": { "message_id": st.next_message_id } }))
            }
            _ => Ok(HttpResponse {
                status: 404,
                body: "{}".into(),
            }),
        }
    }
}

impl App {
    /// Turn the demo Telegram on or off to match [`enabled`]. Turning it off puts the real client back.
    pub(super) fn use_demo_telegram(&mut self, on: bool) {
        match (on, self.demo_telegram.is_some()) {
            (true, false) => {
                let state = Shared::default();
                self.http = Arc::new(DemoTelegram::new(
                    Arc::clone(&self.http),
                    Arc::clone(&state),
                ));
                self.demo_telegram = Some(state);
            }
            (false, true) => {
                self.http = Arc::new(UreqClient);
                self.demo_telegram = None;
            }
            _ => {}
        }
    }

    /// `POST /v1/demo/telegram/message`: a person writes to the demo bot, as Telegram would deliver it.
    pub(super) fn demo_telegram_say(&mut self, body: &[u8]) -> Resp {
        #[derive(Deserialize)]
        #[serde(deny_unknown_fields)]
        struct B {
            chat_id: i64,
            #[serde(default)]
            text: String,
            #[serde(default)]
            name: Option<String>,
            /// Press a button (its data) instead of writing.
            #[serde(default)]
            callback: Option<String>,
            /// The message arrives as a forward.
            #[serde(default)]
            forwarded: bool,
        }
        let Some(state) = self.demo_telegram.clone() else {
            return Resp::error(404, "not_found", "no such endpoint");
        };
        let b: B = match serde_json::from_slice(body) {
            Ok(b) => b,
            Err(e) => return Resp::error(400, "bad_request", &format!("invalid request: {e}")),
        };
        let Ok(mut st) = state.lock() else {
            return Resp::error(500, "internal", "the demo bot is unavailable");
        };
        st.next_id += 1;
        let id = st.next_id;
        let update = if let Some(data) = &b.callback {
            json!({ "update_id": id, "callback_query": { "id": format!("cb{id}"), "data": data,
                "message": { "chat": { "id": b.chat_id, "type": "private" } } } })
        } else {
            let mut m = json!({
                "message_id": id,
                "date": super::unix_ms() / 1000,
                "chat": { "id": b.chat_id, "type": "private" },
                "from": { "id": b.chat_id, "is_bot": false, "first_name": b.name.unwrap_or_else(|| "Demo user".into()) },
                "text": b.text,
            });
            if b.forwarded {
                m["forward_origin"] = json!({ "type": "user" });
            }
            json!({ "update_id": id, "message": m })
        };
        st.updates.push(update);
        let over = st.updates.len().saturating_sub(KEEP);
        st.updates.drain(..over);
        drop(st);
        // Look for it soon rather than at the idle rate.
        self.schedule.next_telegram_ms = 0;
        Resp::json(202, &json!({ "update_id": id }))
    }

    /// `POST /v1/demo/alerts`: raise one alert as the engine would, through the hourly limit, the routing rules and the
    /// delivery worker, so a browser test can see what becomes of an alert without waiting for a real condition.
    pub(super) fn demo_raise_alert(&mut self, body: &[u8]) -> Resp {
        #[derive(Deserialize)]
        #[serde(deny_unknown_fields)]
        struct B {
            title: String,
            #[serde(default)]
            urgent: bool,
        }
        if self.demo_telegram.is_none() {
            return Resp::error(404, "not_found", "no such endpoint");
        }
        let b: B = match serde_json::from_slice(body) {
            Ok(b) => b,
            Err(e) => return Resp::error(400, "bad_request", &format!("invalid request: {e}")),
        };
        let now = super::unix_ms();
        let alert = crate::notify::Alert {
            key: format!("demo:{now}:{}", b.title.len()),
            kind: "demo".into(),
            severity: if b.urgent {
                crate::notify::Severity::Urgent
            } else {
                crate::notify::Severity::Normal
            },
            box_name: None,
            title: b.title.chars().take(80).collect(),
            body: "A demo alert.".into(),
            ts_ms: now,
        };
        self.route_alerts(vec![alert], now);
        Resp::json(202, &json!({ "raised": true }))
    }

    /// The pause between tries the demo server uses instead of the real backoff, or `None` on a real server.
    pub(super) fn demo_retry_pause(&self) -> Option<u64> {
        let state = self.demo_telegram.as_ref()?;
        let ms = state.lock().map(|s| s.retry_ms).unwrap_or(0);
        Some(if ms == 0 { DEFAULT_RETRY_MS } else { ms })
    }

    /// `POST /v1/demo/telegram/fail`: the next `count` messages to the demo bot answer HTTP 503 (a failure worth
    /// retrying), and failed deliveries wait `retry_ms` between tries. Absent on a real server.
    pub(super) fn demo_telegram_fail(&mut self, body: &[u8]) -> Resp {
        #[derive(Deserialize)]
        #[serde(deny_unknown_fields)]
        struct B {
            count: u32,
            #[serde(default)]
            retry_ms: Option<u64>,
        }
        let Some(state) = self.demo_telegram.clone() else {
            return Resp::error(404, "not_found", "no such endpoint");
        };
        let b: B = match serde_json::from_slice(body) {
            Ok(b) => b,
            Err(e) => return Resp::error(400, "bad_request", &format!("invalid request: {e}")),
        };
        if b.count > MAX_FAILS || b.retry_ms.is_some_and(|m| !(200..=10_000).contains(&m)) {
            return Resp::error(
                400,
                "bad_request",
                "count is at most 20 and retry_ms 200 to 10000",
            );
        }
        let Ok(mut st) = state.lock() else {
            return Resp::error(500, "internal", "the demo bot is unavailable");
        };
        st.fail_sends = b.count;
        if let Some(m) = b.retry_ms {
            st.retry_ms = m;
        }
        Resp::json(200, &json!({ "failing": b.count }))
    }

    /// `POST /v1/demo/telegram/legacy-chat`: put a chat on the list that receives alerts, the way a chat linked before passkey
    /// links was. Linking a real account needs a signed-in person and a passkey, which a token-mode demo does not have; this is
    /// how a browser test gets a chat that is told things. Such a chat reads and is notified, and nothing more. Absent on a real
    /// server.
    pub(super) fn demo_telegram_legacy_chat(&mut self, body: &[u8]) -> Resp {
        #[derive(Deserialize)]
        #[serde(deny_unknown_fields)]
        struct B {
            chat_id: i64,
            #[serde(default)]
            name: Option<String>,
            #[serde(default)]
            person: Option<String>,
        }
        if self.demo_telegram.is_none() {
            return Resp::error(404, "not_found", "no such endpoint");
        }
        let b: B = match serde_json::from_slice(body) {
            Ok(b) => b,
            Err(e) => return Resp::error(400, "bad_request", &format!("invalid request: {e}")),
        };
        self.state.telegram.chats.retain(|c| c.id != b.chat_id);
        self.state.telegram.chats.push(crate::state::TelegramChat {
            id: b.chat_id,
            name: b
                .name
                .unwrap_or_else(|| "Demo user".into())
                .chars()
                .take(40)
                .collect(),
            person: b.person,
        });
        self.save_state();
        self.schedule.next_telegram_ms = 0;
        Resp::json(200, &json!({ "chats": self.state.telegram.chats }))
    }

    /// `POST /v1/demo/telegram/script`: make the demo bot misbehave the way the real one can, so the bridge's stops can be tried:
    /// answer 409 or 429 to the next polls, say a webhook is set, or report a bot flag as on. Absent on a real server.
    pub(super) fn demo_telegram_script(&mut self, body: &[u8]) -> Resp {
        #[derive(Deserialize, Default)]
        #[serde(deny_unknown_fields, default)]
        struct B {
            conflicts: Option<u32>,
            rate_limited: Option<u32>,
            webhook: Option<String>,
            clear_webhook: bool,
            can_join_groups: Option<bool>,
            can_read_all_group_messages: Option<bool>,
            supports_inline_queries: Option<bool>,
        }
        let Some(state) = self.demo_telegram.clone() else {
            return Resp::error(404, "not_found", "no such endpoint");
        };
        let b: B = match serde_json::from_slice(body) {
            Ok(b) => b,
            Err(e) => return Resp::error(400, "bad_request", &format!("invalid request: {e}")),
        };
        let Ok(mut st) = state.lock() else {
            return Resp::error(500, "internal", "the demo bot is unavailable");
        };
        if let Some(c) = b.conflicts {
            st.conflicts = c.min(MAX_FAILS);
        }
        if let Some(c) = b.rate_limited {
            st.rate_limited = c.min(MAX_FAILS);
        }
        if b.clear_webhook {
            st.webhook = None;
        }
        if let Some(w) = b.webhook {
            st.webhook = Some(w.chars().take(200).collect());
        }
        if let Some(v) = b.can_join_groups {
            st.can_join_groups = v;
        }
        if let Some(v) = b.can_read_all_group_messages {
            st.can_read_all_group_messages = v;
        }
        if let Some(v) = b.supports_inline_queries {
            st.supports_inline_queries = v;
        }
        drop(st);
        self.schedule.next_telegram_ms = 0;
        Resp::json(200, &json!({ "scripted": true }))
    }

    /// `GET /v1/demo/telegram/sent`: what the server sent to the demo bot's chats (a count and the first words).
    pub(super) fn demo_telegram_sent(&self) -> Resp {
        let Some(state) = &self.demo_telegram else {
            return Resp::error(404, "not_found", "no such endpoint");
        };
        let sent: Vec<Value> = state
            .lock()
            .map(|s| {
                s.sent
                    .iter()
                    .map(|(c, t, b)| json!({ "chat_id": c, "text": t, "buttons": b }))
                    .collect()
            })
            .unwrap_or_default();
        Resp::json(200, &json!({ "sent": sent }))
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn the_demo_bot_needs_the_fake_provider_and_its_own_switch() {
        assert!(enabled(true, Some("1")));
        assert!(
            !enabled(true, None),
            "the simulated server alone is not enough"
        );
        assert!(!enabled(true, Some("0")));
        assert!(!enabled(true, Some("true")));
        assert!(!enabled(false, Some("1")), "a real provider never gets it");
        assert!(!enabled(false, None));
    }

    fn post(path: &str, body: &str) -> crate::serve::Req {
        crate::serve::Req {
            method: "POST".into(),
            path: path.into(),
            query: String::new(),
            headers: [
                ("host".to_string(), "127.0.0.1:7878".to_string()),
                ("authorization".to_string(), "Bearer t".to_string()),
            ]
            .into_iter()
            .collect(),
            body: body.as_bytes().to_vec(),
        }
    }

    fn demo_app(on: bool) -> (App, tempfile::TempDir) {
        let dir = tempfile::tempdir().unwrap();
        let mut app = App::new(
            Box::new(ozbox_provider_fake::open(dir.path())),
            true,
            std::net::SocketAddr::from(([127, 0, 0, 1], 7878)),
            "t".into(),
        );
        app.use_demo_telegram(on);
        (app, dir)
    }

    fn send(app: &App, url_tail: &str) -> u16 {
        app.http
            .send(
                &HttpRequest::new(
                    "POST",
                    format!("{BOT_PREFIX}123:T/{url_tail}"),
                    crate::netguard::Guard::Public,
                )
                .json(&json!({"chat_id": 1, "text": "hi"})),
            )
            .unwrap()
            .status
    }

    #[test]
    fn the_switch_makes_the_next_sends_fail_with_503_then_lets_them_through_and_sets_the_pause() {
        let (mut app, _d) = demo_app(true);
        assert_eq!(app.demo_retry_pause(), Some(DEFAULT_RETRY_MS));
        let r = app.handle(&post(
            "/v1/demo/telegram/fail",
            r#"{"count":2,"retry_ms":500}"#,
        ));
        assert_eq!(r.status, 200);
        assert_eq!(app.demo_retry_pause(), Some(500));
        assert_eq!(send(&app, "sendMessage"), 503);
        assert_eq!(send(&app, "sendMessage"), 503);
        assert_eq!(send(&app, "sendMessage"), 200);
        // a failed send is not remembered as sent
        assert_eq!(app.demo_telegram_sent().status, 200);
        assert_eq!(
            serde_json::from_slice::<Value>(&app.demo_telegram_sent().body).unwrap()["sent"]
                .as_array()
                .unwrap()
                .len(),
            1
        );
        // bounded, and strict about what it is told
        for bad in [
            r#"{"count":21}"#,
            r#"{"count":1,"retry_ms":5}"#,
            r#"{"count":1,"x":1}"#,
            "nope",
        ] {
            assert_eq!(
                app.handle(&post("/v1/demo/telegram/fail", bad)).status,
                400,
                "{bad}"
            );
        }
    }

    #[test]
    fn without_the_demo_switch_the_route_and_the_short_pause_do_not_exist() {
        let (mut app, _d) = demo_app(false);
        assert_eq!(app.demo_retry_pause(), None);
        assert_eq!(
            app.handle(&post("/v1/demo/telegram/fail", r#"{"count":1}"#))
                .status,
            404
        );
    }
}
