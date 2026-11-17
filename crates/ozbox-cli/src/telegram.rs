//! The Telegram Bot API, as far as Oz Box uses it: long polling for messages, sending a plain text reply, deleting one of our
//! own messages and asking who the bot is (ADR 0050 §8).
//!
//! * **One place builds a request address** ([`Bot::url`]), and one function ([`redact`]) takes the token out of anything
//!   that might be shown. An address holds the token (`/bot<token>/method`), so it is never logged, never put in an error and
//!   never printed: errors here are words made from a status code.
//! * **Polling only.** `getUpdates` asks for `message` updates alone (no buttons, no edits), waits up to 30 seconds on the
//!   vendor's side and takes a few updates at a time, so one answer always fits in the client's size limit.
//! * **Nothing here decides anything.** What an update means and what it may do is `ozbox_core::chat_policy` and
//!   `serve::telegram_bridge`; this module only talks to the vendor.
//!
//! The bot's own address is the vendor's, over `https`, through the guarded HTTP client. A test or a demo may point it at a
//! loopback server with `OZBOX_TELEGRAM_API_BASE` (a loopback address only: a token must never be sent to anywhere else).

use std::time::Duration;

use serde_json::{json, Value};

use crate::netguard::{Guard, HttpClient, HttpRequest};

/// What the vendor is asked to wait for a message, in seconds.
pub const POLL_TIMEOUT_S: u64 = 30;
/// The client's own bound on one poll: the vendor's wait, plus time to answer.
pub const POLL_REQUEST_TIMEOUT: Duration = Duration::from_secs(POLL_TIMEOUT_S + 15);
/// Updates taken at a time. The client keeps at most 64 KiB of an answer and a message may be 4,096 characters, so a few at a
/// time always fit; one at a time is the fallback after an answer that did not parse.
pub const POLL_BATCH: u32 = 3;
const DEFAULT_BASE: &str = "https://api.telegram.org";

/// Where the Bot API is, and how to reach it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ApiBase {
    base: String,
    guard: Guard,
}

impl ApiBase {
    pub fn vendor() -> Self {
        ApiBase {
            base: DEFAULT_BASE.to_string(),
            guard: Guard::Public,
        }
    }

    /// The vendor's address, unless `OZBOX_TELEGRAM_API_BASE` names a loopback server (a test double). Anything else in the
    /// variable is ignored, so the token can never be sent to another host by an environment that was set carelessly.
    pub fn from_env(var: Option<&str>) -> Self {
        let Some(v) = var.map(str::trim).filter(|v| !v.is_empty()) else {
            return Self::vendor();
        };
        Self::loopback(v).unwrap_or_else(Self::vendor)
    }

    fn loopback(v: &str) -> Option<ApiBase> {
        let rest = v.strip_prefix("http://")?;
        let host_port = rest.trim_end_matches('/');
        let host = host_port
            .strip_prefix('[')
            .map(|r| r.split(']').next().unwrap_or(""))
            .unwrap_or_else(|| host_port.split(':').next().unwrap_or(""));
        let ok = matches!(host, "127.0.0.1" | "localhost" | "::1")
            && !host_port.contains('/')
            && !host_port.contains('@');
        ok.then(|| ApiBase {
            base: format!("http://{host_port}"),
            guard: Guard::Private,
        })
    }

    /// Whether this is the vendor's own address.
    #[cfg(test)]
    pub fn is_vendor(&self) -> bool {
        self.base == DEFAULT_BASE
    }
}

/// The bot, as the vendor says it is.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BotInfo {
    pub id: i64,
    /// Without the `@`.
    pub username: String,
    pub can_join_groups: Option<bool>,
    pub can_read_all_group_messages: Option<bool>,
    pub supports_inline_queries: Option<bool>,
}

impl BotInfo {
    /// What is wrong with the bot's settings, as permanent codes. The bridge refuses to run while this is not empty: a bot
    /// that can be added to a group, that reads every group message or that answers inline queries is a bigger surface than
    /// a private chat, and a flag the vendor did not report cannot be shown to be off.
    pub fn problems(&self) -> Vec<&'static str> {
        let mut v = Vec::new();
        if self.can_join_groups != Some(false) {
            v.push("can_join_groups");
        }
        if self.can_read_all_group_messages != Some(false) {
            v.push("can_read_all_group_messages");
        }
        if self.supports_inline_queries != Some(false) {
            v.push("supports_inline_queries");
        }
        v
    }
}

/// Why a poll or a send did not work.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ApiError {
    /// 401: the vendor does not know this token.
    BadToken,
    /// 409: another consumer is polling this bot, or a webhook is set (ADR 0050 §7).
    Conflict,
    /// 429: wait this many seconds.
    RateLimited(u64),
    /// Any other status.
    Http(u16),
    /// The request did not complete.
    Transport,
    /// The answer was not the shape the vendor documents.
    NotUnderstood,
}

impl std::fmt::Display for ApiError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ApiError::BadToken => f.write_str("Telegram rejected the bot token"),
            ApiError::Conflict => f.write_str(
                "Telegram says another program is reading this bot's messages, or a webhook is set for it",
            ),
            ApiError::RateLimited(s) => write!(f, "Telegram asked to wait {s} seconds"),
            ApiError::Http(c) => write!(f, "Telegram answered HTTP {c}"),
            ApiError::Transport => f.write_str("Telegram could not be reached"),
            ApiError::NotUnderstood => f.write_str("Telegram's answer was not understood"),
        }
    }
}

/// Take the token, and anything shaped like a bot address, out of text that may be shown. A last defence: no message here is
/// built from an address, a body or a header in the first place.
pub fn redact(text: &str, token: &str) -> String {
    let mut out = if token.is_empty() {
        text.to_string()
    } else {
        text.replace(token, "<token>")
    };
    let mut from = 0;
    while let Some(i) = out[from..].find("/bot") {
        let start = from + i + 4;
        let rest = &out[start..];
        let end = rest.find('/').unwrap_or(rest.len());
        // a bot token is `<digits>:<secret>`
        if rest[..end].contains(':') {
            out.replace_range(start..start + end, "<token>");
            from = start + "<token>".len();
        } else {
            from = start;
        }
    }
    out
}

/// A connection to the bot API for one token. Cheap: it borrows everything.
pub struct Bot<'a> {
    pub http: &'a dyn HttpClient,
    pub token: &'a str,
    pub base: &'a ApiBase,
}

impl<'a> Bot<'a> {
    pub fn new(http: &'a dyn HttpClient, token: &'a str, base: &'a ApiBase) -> Self {
        Bot { http, token, base }
    }

    /// The only place an address is made.
    fn url(&self, method: &str) -> String {
        format!("{}/bot{}/{method}", self.base.base, self.token)
    }

    fn call(
        &self,
        method: &str,
        query: &str,
        body: Option<&Value>,
        timeout: Duration,
    ) -> Result<Value, ApiError> {
        let mut url = self.url(method);
        if !query.is_empty() {
            url.push('?');
            url.push_str(query);
        }
        let verb = if body.is_some() { "POST" } else { "GET" };
        let mut req = HttpRequest::new(verb, url, self.base.guard);
        req.timeout = timeout;
        if let Some(b) = body {
            req = req.json(b);
        }
        let r = self.http.send(&req).map_err(|_| ApiError::Transport)?;
        let parsed: Option<Value> = serde_json::from_str(&r.body).ok();
        match r.status {
            200..=299 => {}
            401 | 404 => return Err(ApiError::BadToken),
            409 => return Err(ApiError::Conflict),
            429 => {
                let secs = parsed
                    .as_ref()
                    .and_then(|v| v.pointer("/parameters/retry_after"))
                    .and_then(Value::as_u64)
                    .unwrap_or(5)
                    .clamp(1, 3600);
                return Err(ApiError::RateLimited(secs));
            }
            s => return Err(ApiError::Http(s)),
        }
        let v = parsed.ok_or(ApiError::NotUnderstood)?;
        if v.get("ok").and_then(Value::as_bool) != Some(true) {
            return Err(ApiError::NotUnderstood);
        }
        Ok(v.get("result").cloned().unwrap_or(Value::Null))
    }

    /// Who the bot is, and how it is set up.
    pub fn get_me(&self) -> Result<BotInfo, ApiError> {
        let v = self.call("getMe", "", None, Duration::from_secs(10))?;
        let flag = |k: &str| v.get(k).and_then(Value::as_bool);
        let username = v
            .get("username")
            .and_then(Value::as_str)
            .filter(|u| !u.is_empty() && u.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_'))
            .ok_or(ApiError::NotUnderstood)?;
        Ok(BotInfo {
            id: v
                .get("id")
                .and_then(Value::as_i64)
                .filter(|i| *i > 0)
                .ok_or(ApiError::NotUnderstood)?,
            username: username.to_string(),
            can_join_groups: flag("can_join_groups"),
            can_read_all_group_messages: flag("can_read_all_group_messages"),
            supports_inline_queries: flag("supports_inline_queries"),
        })
    }

    /// New messages since `offset`, waiting up to [`POLL_TIMEOUT_S`] seconds on the vendor's side. Returns the updates and the
    /// offset after the last of them; the caller moves its own offset only once an update is durably recorded.
    pub fn get_updates(&self, offset: i64, limit: u32) -> Result<(Vec<Value>, i64), ApiError> {
        let query = format!(
            "offset={offset}&timeout={POLL_TIMEOUT_S}&limit={limit}&allowed_updates=%5B%22message%22%5D"
        );
        let v = self.call("getUpdates", &query, None, POLL_REQUEST_TIMEOUT)?;
        let updates = v.as_array().cloned().ok_or(ApiError::NotUnderstood)?;
        let next = updates
            .iter()
            .filter_map(|u| u.get("update_id").and_then(Value::as_i64))
            .max()
            .map_or(offset, |m| m + 1);
        Ok((updates, next))
    }

    /// The host of a webhook somebody set for this bot, when there is one. Only the host: the address of a webhook can carry
    /// a secret.
    pub fn webhook_host(&self) -> Result<Option<String>, ApiError> {
        let v = self.call("getWebhookInfo", "", None, Duration::from_secs(10))?;
        let url = v.get("url").and_then(Value::as_str).unwrap_or("");
        if url.is_empty() {
            return Ok(None);
        }
        let host = url
            .split("://")
            .nth(1)
            .and_then(|r| r.split(['/', '?', ':']).next())
            .unwrap_or("")
            .chars()
            .take(80)
            .collect::<String>();
        Ok(Some(if host.is_empty() {
            "an unknown host".into()
        } else {
            host
        }))
    }

    /// A plain-text message (a reply) with no buttons, no preview and nothing to forward or copy. Returns its id, so a
    /// message that carried a link can be deleted when the link is used.
    pub fn send(&self, chat_id: i64, text: &str) -> Result<i64, ApiError> {
        self.send_notice(chat_id, &crate::notice::Notice::reply(text))
    }

    /// A notice as Telegram shows it (`notice::render::Telegram`): HTML with every value escaped, previews off, content
    /// protected, and at most one URL button that only opens the dashboard.
    pub fn send_notice(&self, chat_id: i64, n: &crate::notice::Notice) -> Result<i64, ApiError> {
        use crate::notice::render::{Renderer, Telegram};
        let mut body = Telegram::render(n);
        body["chat_id"] = json!(chat_id);
        let v = self.call("sendMessage", "", Some(&body), Duration::from_secs(10))?;
        Ok(v.get("message_id").and_then(Value::as_i64).unwrap_or(0))
    }

    /// Delete one of our own messages. Best effort: a bot can delete its own message in a private chat for 48 hours, and a
    /// person can delete the chat for both sides, so the record of what was asked is never the chat.
    pub fn delete(&self, chat_id: i64, message_id: i64) -> Result<(), ApiError> {
        let body = json!({ "chat_id": chat_id, "message_id": message_id });
        self.call("deleteMessage", "", Some(&body), Duration::from_secs(10))
            .map(|_| ())
    }
}

/// A notice (a reply, or a structured message with its link button), for the places that only need "did it go". The error
/// never carries the token.
pub fn send_notice(
    http: &dyn HttpClient,
    token: &str,
    chat_id: i64,
    n: &crate::notice::Notice,
) -> Result<(), String> {
    let base = ApiBase::from_env(std::env::var("OZBOX_TELEGRAM_API_BASE").ok().as_deref());
    Bot::new(http, token, &base)
        .send_notice(chat_id, n)
        .map(|_| ())
        .map_err(|e| redact(&e.to_string(), token))
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use crate::netguard::FakeHttp;

    const TOKEN: &str = "7000000002:FAKE-sentinel-token-not-real";

    fn bot<'a>(http: &'a FakeHttp, base: &'a ApiBase) -> Bot<'a> {
        Bot::new(http, TOKEN, base)
    }

    #[test]
    fn the_address_base_is_the_vendors_unless_a_loopback_server_is_named() {
        assert!(ApiBase::from_env(None).is_vendor());
        assert!(ApiBase::from_env(Some("")).is_vendor());
        let lb = ApiBase::from_env(Some("http://127.0.0.1:4010"));
        assert_eq!(
            (lb.base.as_str(), lb.guard),
            ("http://127.0.0.1:4010", Guard::Private)
        );
        assert!(!lb.is_vendor());
        assert_eq!(
            ApiBase::from_env(Some("http://localhost:4010/")).base,
            "http://localhost:4010"
        );
        assert!(ApiBase::from_env(Some("http://[::1]:4010"))
            .base
            .contains("::1"));
        // anything that is not loopback is ignored: the token never goes to another host
        for bad in [
            "https://api.telegram.org.evil.example",
            "http://evil.example",
            "http://127.0.0.1.evil.example:80",
            "http://10.0.0.5:4010",
            "http://127.0.0.1:4010/path",
            "http://user@127.0.0.1:4010",
            "https://127.0.0.1:4010",
            "ftp://127.0.0.1",
        ] {
            assert!(ApiBase::from_env(Some(bad)).is_vendor(), "{bad}");
        }
    }

    #[test]
    fn a_poll_asks_for_messages_only_waits_thirty_seconds_and_advances_the_offset() {
        let http = FakeHttp::default();
        let base = ApiBase::vendor();
        http.reply(
            200,
            &json!({ "ok": true, "result": [ { "update_id": 5 }, { "update_id": 9 } ] })
                .to_string(),
        );
        let (u, next) = bot(&http, &base).get_updates(3, POLL_BATCH).unwrap();
        assert_eq!((u.len(), next), (2, 10));
        let r = &http.requests()[0];
        assert!(
            r.url.contains("offset=3") && r.url.contains("timeout=30") && r.url.contains("limit=3")
        );
        assert!(r.url.contains("allowed_updates=%5B%22message%22%5D"));
        assert!(!r.url.contains("callback_query"));
        assert_eq!(r.timeout, POLL_REQUEST_TIMEOUT);
        assert!(r.timeout > Duration::from_secs(POLL_TIMEOUT_S));
        assert_eq!(r.guard, Guard::Public);
    }

    #[test]
    fn statuses_map_to_the_errors_the_bridge_acts_on() {
        let http = FakeHttp::default();
        let base = ApiBase::vendor();
        let b = bot(&http, &base);
        http.reply(409, r#"{"ok":false,"error_code":409}"#);
        assert_eq!(b.get_updates(0, 1), Err(ApiError::Conflict));
        http.reply(401, "{}");
        assert_eq!(b.get_updates(0, 1), Err(ApiError::BadToken));
        http.reply(429, r#"{"ok":false,"parameters":{"retry_after":7}}"#);
        assert_eq!(b.send(1, "x"), Err(ApiError::RateLimited(7)));
        http.reply(429, "not json");
        assert_eq!(b.send(1, "x"), Err(ApiError::RateLimited(5)));
        http.reply(429, r#"{"parameters":{"retry_after":999999}}"#);
        assert_eq!(b.send(1, "x"), Err(ApiError::RateLimited(3600)));
        http.reply(502, "<html>");
        assert_eq!(b.get_updates(0, 1), Err(ApiError::Http(502)));
        http.reply(200, "{ truncated");
        assert_eq!(b.get_updates(0, 1), Err(ApiError::NotUnderstood));
        http.reply(200, r#"{"ok":false}"#);
        assert_eq!(b.get_updates(0, 1), Err(ApiError::NotUnderstood));
    }

    #[test]
    fn get_me_reads_the_id_and_the_three_flags_and_a_flag_that_is_not_off_is_a_problem() {
        let http = FakeHttp::default();
        let base = ApiBase::vendor();
        let b = bot(&http, &base);
        http.reply(
            200,
            &json!({ "ok": true, "result": { "id": 7_000_000_002_i64, "username": "oz_fleet_bot",
                "can_join_groups": false, "can_read_all_group_messages": false, "supports_inline_queries": false } })
            .to_string(),
        );
        let me = b.get_me().unwrap();
        assert_eq!(
            (me.id, me.username.as_str()),
            (7_000_000_002, "oz_fleet_bot")
        );
        assert!(me.problems().is_empty());
        for (k, code) in [
            ("can_join_groups", "can_join_groups"),
            ("can_read_all_group_messages", "can_read_all_group_messages"),
            ("supports_inline_queries", "supports_inline_queries"),
        ] {
            let mut r = json!({ "id": 7, "username": "b", "can_join_groups": false,
                "can_read_all_group_messages": false, "supports_inline_queries": false });
            r[k] = json!(true);
            http.reply(200, &json!({ "ok": true, "result": r }).to_string());
            assert_eq!(b.get_me().unwrap().problems(), vec![code]);
        }
        // a flag the vendor did not report cannot be shown to be off
        http.reply(
            200,
            &json!({ "ok": true, "result": { "id": 7, "username": "b" } }).to_string(),
        );
        assert_eq!(b.get_me().unwrap().problems().len(), 3);
        http.reply(
            200,
            &json!({ "ok": true, "result": { "username": "b" } }).to_string(),
        );
        assert_eq!(b.get_me(), Err(ApiError::NotUnderstood));
        http.reply(
            200,
            &json!({ "ok": true, "result": { "id": 7, "username": "has space" } }).to_string(),
        );
        assert_eq!(b.get_me(), Err(ApiError::NotUnderstood));
    }

    #[test]
    fn a_message_carries_no_button_no_preview_and_cannot_be_copied_on() {
        let http = FakeHttp::default();
        let base = ApiBase::vendor();
        http.reply(200, r#"{"ok":true,"result":{"message_id":42}}"#);
        assert_eq!(bot(&http, &base).send(5, "hello"), Ok(42));
        let r = &http.requests()[0];
        assert_eq!(r.method, "POST");
        let body: Value = serde_json::from_slice(r.body.as_deref().unwrap()).unwrap();
        assert_eq!(body["protect_content"], json!(true));
        assert_eq!(body["disable_web_page_preview"], json!(true));
        assert!(body.get("reply_markup").is_none());
    }

    #[test]
    fn a_webhook_somebody_set_is_named_by_host_only() {
        let http = FakeHttp::default();
        let base = ApiBase::vendor();
        let b = bot(&http, &base);
        http.reply(200, r#"{"ok":true,"result":{"url":""}}"#);
        assert_eq!(b.webhook_host(), Ok(None));
        http.reply(
            200,
            r#"{"ok":true,"result":{"url":"https://hooks.example.com/path/with-secret?k=v"}}"#,
        );
        assert_eq!(b.webhook_host(), Ok(Some("hooks.example.com".into())));
    }

    #[test]
    fn no_error_and_no_redaction_leaves_the_token_or_a_bot_address() {
        let http = FakeHttp::default();
        let base = ApiBase::vendor();
        let b = bot(&http, &base);
        for (status, body) in [
            (401, format!("Unauthorized {TOKEN}")),
            (409, format!("{{\"description\":\"{TOKEN}\"}}")),
            (
                500,
                format!("https://api.telegram.org/bot{TOKEN}/getUpdates failed"),
            ),
            (200, format!("{TOKEN} not json")),
        ] {
            http.reply(status, &body);
            let e = b.get_updates(0, 1).unwrap_err().to_string();
            assert!(!e.contains(TOKEN) && !e.contains("FAKE-sentinel"), "{e}");
            assert!(!e.contains("/bot"));
        }
        let text = format!("failed at https://api.telegram.org/bot{TOKEN}/getUpdates and {TOKEN}");
        let clean = redact(&text, TOKEN);
        assert!(!clean.contains("FAKE-sentinel"), "{clean}");
        assert!(redact("see /bot/docs and /bottle", TOKEN).contains("/bot/docs"));
        // the request's Debug form never prints the address either
        let dbg = format!("{:?}", http.requests().last().unwrap());
        assert!(!dbg.contains("FAKE-sentinel"), "{dbg}");
        // the one-call helpers refuse in words
        http.reply(401, "{}");
        assert!(
            !send_notice(&http, TOKEN, 5, &crate::notice::Notice::reply("x"))
                .unwrap_err()
                .contains(TOKEN)
        );
    }
}

/// A fake Telegram for tests: the Bot API's `getMe`, `getUpdates`, `getWebhookInfo`, `sendMessage` and `deleteMessage`, with
/// scripted updates and scripted 409 and 429 answers. It is an `HttpClient`, so the code under test runs exactly as it does
/// against the vendor, address building and error handling included. It never sees a real token.
#[cfg(test)]
pub mod fake {
    use std::sync::{Arc, Mutex};

    use serde_json::{json, Value};

    use crate::netguard::{HttpClient, HttpError, HttpRequest, HttpResponse};

    pub const BOT_ID: i64 = 7_000_000_002;

    pub struct State {
        pub updates: Vec<Value>,
        pub next_update_id: i64,
        pub next_message_id: i64,
        /// (chat id, text, message id)
        pub sent: Vec<(i64, String, i64)>,
        /// The whole `sendMessage` body of each send, beside `sent` (a reply thread, a URL button).
        pub bodies: Vec<Value>,
        pub deleted: Vec<i64>,
        /// Every call's method and query (never the token).
        pub calls: Vec<String>,
        pub conflicts: u32,
        pub rate_limited: u32,
        pub webhook: Option<String>,
        pub can_join_groups: bool,
        pub can_read_all_group_messages: bool,
        pub supports_inline_queries: bool,
        pub fail_sends: u32,
        /// Called each time a message is sent, so a test can look at the world at that instant.
        pub on_send: Option<Arc<dyn Fn() + Send + Sync>>,
    }

    #[derive(Clone)]
    pub struct FakeTelegram {
        pub state: Arc<Mutex<State>>,
    }

    fn now_s() -> u64 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |d| d.as_secs())
    }

    impl FakeTelegram {
        pub fn new() -> Self {
            FakeTelegram {
                state: Arc::new(Mutex::new(State {
                    updates: Vec::new(),
                    next_update_id: 100,
                    next_message_id: 1000,
                    sent: Vec::new(),
                    bodies: Vec::new(),
                    deleted: Vec::new(),
                    calls: Vec::new(),
                    conflicts: 0,
                    rate_limited: 0,
                    webhook: None,
                    can_join_groups: false,
                    can_read_all_group_messages: false,
                    supports_inline_queries: false,
                    fail_sends: 0,
                    on_send: None,
                })),
            }
        }

        /// A person with Telegram user id `from` writes to the bot in a private chat. Returns the update id.
        pub fn say(&self, from: i64, text: &str) -> i64 {
            self.say_at(from, text, now_s())
        }

        pub fn say_at(&self, from: i64, text: &str, date_s: u64) -> i64 {
            self.push(|id| {
                json!({ "update_id": id, "message": {
                    "message_id": id, "date": date_s, "text": text,
                    "chat": { "id": from, "type": "private", "first_name": "Ada" },
                    "from": { "id": from, "is_bot": false, "first_name": "Ada" } } })
            })
        }

        /// Any update, as written (`update_id` is filled in).
        pub fn raw(&self, mut update: Value) -> i64 {
            self.push(|id| {
                update["update_id"] = json!(id);
                update
            })
        }

        /// An update with a chosen number, for the replay tests.
        pub fn say_with_id(&self, id: i64, from: i64, text: &str) {
            if let Ok(mut s) = self.state.lock() {
                s.updates.push(json!({ "update_id": id, "message": {
                    "message_id": id, "date": now_s(), "text": text,
                    "chat": { "id": from, "type": "private" },
                    "from": { "id": from, "is_bot": false, "first_name": "Ada" } } }));
            }
        }

        fn push(&self, f: impl FnOnce(i64) -> Value) -> i64 {
            let Ok(mut s) = self.state.lock() else {
                return 0;
            };
            let id = s.next_update_id;
            s.next_update_id += 1;
            let u = f(id);
            s.updates.push(u);
            id
        }

        pub fn texts_to(&self, chat: i64) -> Vec<String> {
            self.state
                .lock()
                .map(|s| {
                    s.sent
                        .iter()
                        .filter(|m| m.0 == chat)
                        .map(|m| m.1.clone())
                        .collect()
                })
                .unwrap_or_default()
        }

        pub fn all_sent(&self) -> Vec<(i64, String, i64)> {
            self.state
                .lock()
                .map(|s| s.sent.clone())
                .unwrap_or_default()
        }

        pub fn sent_count(&self) -> usize {
            self.state.lock().map(|s| s.sent.len()).unwrap_or(0)
        }

        pub fn deleted(&self) -> Vec<i64> {
            self.state
                .lock()
                .map(|s| s.deleted.clone())
                .unwrap_or_default()
        }

        pub fn calls(&self) -> Vec<String> {
            self.state
                .lock()
                .map(|s| s.calls.clone())
                .unwrap_or_default()
        }

        pub fn with<R>(&self, f: impl FnOnce(&mut State) -> R) -> R {
            let mut g = self.state.lock().unwrap_or_else(|e| e.into_inner());
            f(&mut g)
        }
    }

    fn ok(v: &Value) -> Result<HttpResponse, HttpError> {
        Ok(HttpResponse {
            status: 200,
            body: v.to_string(),
        })
    }

    fn status(code: u16, body: &str) -> Result<HttpResponse, HttpError> {
        Ok(HttpResponse {
            status: code,
            body: body.into(),
        })
    }

    impl HttpClient for FakeTelegram {
        fn send(&self, req: &HttpRequest) -> Result<HttpResponse, HttpError> {
            let url = req.url.as_str();
            let Some(after) = url.split("/bot").nth(1) else {
                return status(404, "{}");
            };
            let (_token, call) = after.split_once('/').unwrap_or((after, ""));
            let (method, query) = call.split_once('?').unwrap_or((call, ""));
            let body: Value = req
                .body
                .as_deref()
                .and_then(|b| serde_json::from_slice(b).ok())
                .unwrap_or(Value::Null);
            let on_send;
            let reply = {
                let mut s = self.state.lock().unwrap_or_else(|e| e.into_inner());
                s.calls.push(format!("{method}?{query}"));
                on_send = if method == "sendMessage" {
                    s.on_send.clone()
                } else {
                    None
                };
                match method {
                    "getMe" => ok(&json!({ "ok": true, "result": {
                        "id": BOT_ID, "is_bot": true, "username": "oz_fleet_bot",
                        "can_join_groups": s.can_join_groups,
                        "can_read_all_group_messages": s.can_read_all_group_messages,
                        "supports_inline_queries": s.supports_inline_queries } })),
                    "getWebhookInfo" => ok(
                        &json!({ "ok": true, "result": { "url": s.webhook.clone().unwrap_or_default() } }),
                    ),
                    "getUpdates" => {
                        if s.conflicts > 0 {
                            s.conflicts -= 1;
                            return status(409, r#"{"ok":false,"error_code":409}"#);
                        }
                        if s.rate_limited > 0 {
                            s.rate_limited -= 1;
                            return status(
                                429,
                                r#"{"ok":false,"error_code":429,"parameters":{"retry_after":2}}"#,
                            );
                        }
                        let q = |k: &str| {
                            query
                                .split('&')
                                .find_map(|p| p.strip_prefix(&format!("{k}=")))
                                .and_then(|v| v.parse::<i64>().ok())
                        };
                        let offset = q("offset").unwrap_or(0);
                        let limit = q("limit").unwrap_or(100).clamp(1, 100) as usize;
                        // Telegram forgets what is below the offset
                        s.updates
                            .retain(|u| u["update_id"].as_i64().unwrap_or(0) >= offset);
                        let list: Vec<Value> = s.updates.iter().take(limit).cloned().collect();
                        ok(&json!({ "ok": true, "result": list }))
                    }
                    "sendMessage" => {
                        if s.fail_sends > 0 {
                            s.fail_sends -= 1;
                            return status(503, "{}");
                        }
                        let chat = body["chat_id"].as_i64().unwrap_or(0);
                        // what the person sees: the words, and the address of a URL button under them
                        let mut text = body["text"].as_str().unwrap_or("").to_string();
                        if let Some(url) =
                            body["reply_markup"]["inline_keyboard"][0][0]["url"].as_str()
                        {
                            text.push_str(&format!("\n[button] {url}"));
                        }
                        s.next_message_id += 1;
                        let id = s.next_message_id;
                        s.sent.push((chat, text, id));
                        s.bodies.push(body.clone());
                        ok(&json!({ "ok": true, "result": { "message_id": id } }))
                    }
                    "deleteMessage" => {
                        s.deleted.push(body["message_id"].as_i64().unwrap_or(0));
                        ok(&json!({ "ok": true, "result": true }))
                    }
                    _ => status(404, "{}"),
                }
            };
            if let Some(f) = on_send {
                f();
            }
            reply
        }
    }
}
