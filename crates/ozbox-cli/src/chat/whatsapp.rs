//! WhatsApp through the Cloud API: the person's own WhatsApp Business app and number. Messages arrive as signed webhook
//! calls on this server (`/hooks/chat/whatsapp`), replies go out through the Graph API.
//!
//! * A call is accepted only with a valid `X-Hub-Signature-256` (HMAC-SHA256 of the raw body with the app secret). A message
//!   is acted on once (its id is remembered) and only while it is fresh.
//! * Only linked numbers are heard. A forwarded message is data, not an instruction.
//! * WhatsApp allows a free-form reply only within 24 hours of the person's last message. Outside that window only an
//!   approved template can be sent; with none configured, the message is held back and the person is told on their next
//!   message that the window was closed.
//!
//! Reference: <https://developers.facebook.com/docs/whatsapp/cloud-api/webhooks> and `/guides/send-messages`.

use ring::hmac;

use super::text::ct_eq;
use serde_json::{json, Value};

pub const WINDOW_MS: u64 = 24 * 60 * 60 * 1000;
/// A message older than this when it arrives is not acted on.
pub const FRESH_MS: u64 = 15 * 60 * 1000;
pub const API_VERSION: &str = "v21.0";
/// The most ids remembered to refuse a replay.
const SEEN: usize = 500;

pub fn verify_signature(app_secret: &str, body: &[u8], header: &str) -> bool {
    let Some(hexsig) = header.trim().strip_prefix("sha256=") else {
        return false;
    };
    if hexsig.len() != 64 || !hexsig.bytes().all(|b| b.is_ascii_hexdigit()) {
        return false;
    }
    let sig: Vec<u8> = (0..32)
        .filter_map(|i| u8::from_str_radix(&hexsig[i * 2..i * 2 + 2], 16).ok())
        .collect();
    let key = hmac::Key::new(hmac::HMAC_SHA256, app_secret.as_bytes());
    hmac::verify(&key, body, &sig).is_ok()
}

/// The webhook's one-time check: Meta calls with `hub.mode=subscribe`, our verify token and a challenge to echo.
pub fn verify_challenge(
    expected_token: &str,
    mode: &str,
    token: &str,
    challenge: &str,
) -> Option<String> {
    let ok = mode == "subscribe"
        && !expected_token.is_empty()
        && ct_eq(expected_token.as_bytes(), token.as_bytes())
        && challenge.len() <= 40
        && challenge.bytes().all(|b| b.is_ascii_alphanumeric());
    ok.then(|| challenge.to_string())
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Incoming {
    pub from: String,
    pub id: String,
    pub ts_ms: u64,
    pub text: String,
    pub forwarded: bool,
    /// The value of a button the person pressed, instead of text.
    pub button: Option<String>,
}

/// The messages in one webhook call. Anything that is not a text or a button press is dropped.
pub fn parse_webhook(body: &[u8]) -> Vec<Incoming> {
    let Ok(v) = serde_json::from_slice::<Value>(body) else {
        return Vec::new();
    };
    let mut out = Vec::new();
    for entry in v["entry"].as_array().into_iter().flatten() {
        for ch in entry["changes"].as_array().into_iter().flatten() {
            for m in ch["value"]["messages"].as_array().into_iter().flatten() {
                let g = |k: &str| m.get(k).and_then(Value::as_str).unwrap_or("").to_string();
                let ctx = &m["context"];
                // a message that quotes another, or was forwarded, carries someone else's words
                let forwarded = ctx.get("forwarded").is_some()
                    || ctx.get("frequently_forwarded").is_some()
                    || ctx.get("id").is_some();
                let ts_ms = g("timestamp").parse::<u64>().unwrap_or(0) * 1000;
                let (text, button) = match m["type"].as_str() {
                    Some("text") => (m["text"]["body"].as_str().unwrap_or("").to_string(), None),
                    Some("interactive") => (
                        String::new(),
                        m["interactive"]["button_reply"]["id"]
                            .as_str()
                            .map(|s| s.chars().take(80).collect()),
                    ),
                    _ => continue,
                };
                out.push(Incoming {
                    from: g("from"),
                    id: g("id"),
                    ts_ms,
                    text,
                    forwarded,
                    button,
                });
            }
        }
    }
    out
}

/// Remembers message ids so a replayed call is not acted on twice.
#[derive(Debug, Default)]
pub struct Seen(Vec<String>);

impl Seen {
    /// True the first time an id is seen, and only while the message is fresh.
    pub fn first(&mut self, id: &str, ts_ms: u64, now_ms: u64) -> bool {
        if id.is_empty()
            || now_ms.saturating_sub(ts_ms) > FRESH_MS
            || self.0.iter().any(|x| x == id)
        {
            return false;
        }
        self.0.push(id.to_string());
        if self.0.len() > SEEN {
            self.0.remove(0);
        }
        true
    }
}

/// Whether a free-form message may be sent to a number now.
pub fn in_window(last_inbound_ms: Option<u64>, now_ms: u64) -> bool {
    last_inbound_ms.is_some_and(|t| now_ms.saturating_sub(t) < WINDOW_MS)
}

pub fn messages_url(phone_number_id: &str) -> Option<String> {
    (!phone_number_id.is_empty()
        && phone_number_id.len() <= 30
        && phone_number_id.bytes().all(|b| b.is_ascii_digit()))
    .then(|| format!("https://graph.facebook.com/{API_VERSION}/{phone_number_id}/messages"))
}

/// A free-form text, or a message with up to three reply buttons `(id, title)` (titles are cut to WhatsApp's 20 characters).
pub fn text_body(to: &str, text: &str, buttons: &[(String, String)]) -> Value {
    let text: String = text.chars().take(1000).collect();
    if buttons.is_empty() {
        return json!({ "messaging_product": "whatsapp", "to": to, "type": "text", "text": { "body": text, "preview_url": false } });
    }
    let bs: Vec<Value> = buttons.iter().take(3).map(|(id, title)| json!({ "type": "reply", "reply": { "id": id, "title": title.chars().take(20).collect::<String>() } })).collect();
    json!({ "messaging_product": "whatsapp", "to": to, "type": "interactive",
        "interactive": { "type": "button", "body": { "text": text }, "action": { "buttons": bs } } })
}

/// A template message, the only kind allowed outside the 24-hour window.
pub fn template_body(to: &str, template: &str) -> Value {
    json!({ "messaging_product": "whatsapp", "to": to, "type": "template", "template": { "name": template, "language": { "code": "en" } } })
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    fn sign(secret: &str, body: &[u8]) -> String {
        let key = hmac::Key::new(hmac::HMAC_SHA256, secret.as_bytes());
        let tag = hmac::sign(&key, body);
        format!(
            "sha256={}",
            tag.as_ref()
                .iter()
                .map(|b| format!("{b:02x}"))
                .collect::<String>()
        )
    }

    #[test]
    fn only_a_correctly_signed_call_is_accepted() {
        let body = br#"{"entry":[]}"#;
        let good = sign("secret", body);
        assert!(verify_signature("secret", body, &good));
        assert!(!verify_signature("other", body, &good));
        assert!(!verify_signature("secret", b"{}", &good));
        for bad in ["", "sha256=", "sha256=zz", "md5=abc", &good[7..]] {
            assert!(!verify_signature("secret", body, bad), "{bad}");
        }
    }

    #[test]
    fn the_subscribe_check_needs_the_token_and_echoes_only_a_plain_challenge() {
        assert_eq!(
            verify_challenge("tok", "subscribe", "tok", "12345").as_deref(),
            Some("12345")
        );
        assert_eq!(verify_challenge("tok", "subscribe", "bad", "12345"), None);
        assert_eq!(
            verify_challenge("", "subscribe", "", "12345"),
            None,
            "no token configured: never answers"
        );
        assert_eq!(verify_challenge("tok", "unsubscribe", "tok", "1"), None);
        assert_eq!(
            verify_challenge("tok", "subscribe", "tok", "<script>"),
            None,
            "the challenge is echoed, so it must be plain"
        );
    }

    fn call(m: Value) -> Vec<u8> {
        json!({ "entry": [{ "changes": [{ "value": { "messages": [m] } }] }] })
            .to_string()
            .into_bytes()
    }

    #[test]
    fn text_buttons_and_forwards_are_read_and_other_kinds_dropped() {
        let t = parse_webhook(&call(
            json!({ "from": "2348000000000", "id": "w1", "timestamp": "1700000000", "type": "text", "text": { "body": "hi" } }),
        ));
        assert_eq!(
            (
                t[0].from.as_str(),
                t[0].text.as_str(),
                t[0].ts_ms,
                t[0].forwarded
            ),
            ("2348000000000", "hi", 1_700_000_000_000, false)
        );
        let f = parse_webhook(&call(
            json!({ "from": "1", "id": "w2", "timestamp": "1", "type": "text", "text": { "body": "x" }, "context": { "forwarded": true } }),
        ));
        assert!(f[0].forwarded);
        let q = parse_webhook(&call(
            json!({ "from": "1", "id": "w3", "timestamp": "1", "type": "text", "text": { "body": "x" }, "context": { "id": "wamid.x" } }),
        ));
        assert!(q[0].forwarded, "a reply that quotes another message");
        let b = parse_webhook(&call(
            json!({ "from": "1", "id": "w4", "timestamp": "1", "type": "interactive", "interactive": { "button_reply": { "id": "choice:a1" } } }),
        ));
        assert_eq!(b[0].button.as_deref(), Some("choice:a1"));
        assert!(
            parse_webhook(&call(json!({ "from": "1", "id": "w5", "type": "image" }))).is_empty()
        );
        assert!(parse_webhook(b"junk").is_empty());
    }

    #[test]
    fn a_message_is_acted_on_once_and_only_while_fresh() {
        let mut s = Seen::default();
        assert!(s.first("w1", 1_000_000, 1_001_000));
        assert!(!s.first("w1", 1_000_000, 1_002_000), "a replay");
        assert!(
            !s.first("w2", 1_000_000, 1_000_000 + FRESH_MS + 1),
            "too old"
        );
        assert!(!s.first("", 1_000_000, 1_000_001));
    }

    #[test]
    fn free_form_replies_only_inside_the_24_hour_window_and_buttons_are_bounded() {
        assert!(in_window(Some(1_000), 1_000 + WINDOW_MS - 1));
        assert!(!in_window(Some(1_000), 1_000 + WINDOW_MS));
        assert!(!in_window(None, 5));
        let b = text_body(
            "234",
            "Choose?",
            &[
                ("choice:a1".into(), "Choose this one now please".into()),
                ("other:a1".into(), "Second".into()),
                ("x".into(), "3".into()),
                ("y".into(), "4".into()),
            ],
        );
        assert_eq!(
            b["interactive"]["action"]["buttons"]
                .as_array()
                .unwrap()
                .len(),
            3
        );
        assert_eq!(
            b["interactive"]["action"]["buttons"][0]["reply"]["title"]
                .as_str()
                .unwrap()
                .chars()
                .count(),
            20
        );
        assert_eq!(text_body("234", "hi", &[])["type"], "text");
        assert_eq!(
            template_body("234", "oz_update")["template"]["name"],
            "oz_update"
        );
        assert!(
            messages_url("123456789").is_some()
                && messages_url("12/../x").is_none()
                && messages_url("").is_none()
        );
    }
}
