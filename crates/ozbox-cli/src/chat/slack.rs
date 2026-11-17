//! Slack through Socket Mode: the server opens one outbound websocket to Slack and Slack sends events down it, so nothing
//! listens for Slack. Setup is the person's own Slack app: an app-level token (`xapp-`, to open the socket) and a bot token
//! (`xoxb-`, to reply), both kept in the secret store and read at the moment of use.
//!
//! Only direct messages to the bot from a linked person are heard; channel chatter, bot messages and edits are ignored.
//! A forwarded or shared message is data, not an instruction. Every event is acknowledged with its `envelope_id`.
//!
//! Protocol: <https://api.slack.com/apis/socket-mode>. The parsing, acknowledging and reply shapes are pure and tested on
//! fixed events; the connection is a thread that only moves events to the server's tick and replies out.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::Sender;
use std::sync::Arc;
use std::time::Duration;

use serde_json::{json, Value};

use super::ws::{self, Msg, WsError};
use crate::netguard::{Guard, HttpClient, HttpRequest};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Event {
    /// A direct message from a person.
    Message {
        user: String,
        channel: String,
        text: String,
        forwarded: bool,
    },
    /// A button the person pressed: its value (for example `choice:a1`; nothing in Oz Box decides anything from one).
    Button {
        user: String,
        channel: String,
        value: String,
    },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Frame {
    Hello,
    /// Slack asks the app to reconnect.
    Disconnect,
    /// An event to act on and the envelope id to acknowledge.
    Event {
        envelope: String,
        event: Event,
    },
    /// Acknowledge, but there is nothing to act on.
    Ignore {
        envelope: String,
    },
    Other,
}

fn s<'a>(v: &'a Value, k: &str) -> &'a str {
    v.get(k).and_then(Value::as_str).unwrap_or("")
}

/// What one Socket Mode message means.
pub fn parse_frame(text: &str) -> Frame {
    let Ok(v) = serde_json::from_str::<Value>(text) else {
        return Frame::Other;
    };
    match s(&v, "type") {
        "hello" => return Frame::Hello,
        "disconnect" => return Frame::Disconnect,
        _ => {}
    }
    let envelope = s(&v, "envelope_id").to_string();
    if envelope.is_empty() {
        return Frame::Other;
    }
    let p = &v["payload"];
    match s(&v, "type") {
        "events_api" => {
            let e = &p["event"];
            // direct messages only; never a bot's, never an edit or a join (those carry a subtype)
            let dm = s(e, "type") == "message" && s(e, "channel_type") == "im";
            if !dm || e.get("subtype").is_some() || e.get("bot_id").is_some() {
                return Frame::Ignore { envelope };
            }
            let forwarded = e["attachments"].as_array().is_some_and(|a| {
                a.iter().any(|x| {
                    x.get("is_share").is_some()
                        || x.get("is_msg_unfurl").is_some()
                        || x.get("from_url").is_some()
                })
            });
            Frame::Event {
                envelope,
                event: Event::Message {
                    user: s(e, "user").into(),
                    channel: s(e, "channel").into(),
                    text: s(e, "text").into(),
                    forwarded,
                },
            }
        }
        "interactive" if s(p, "type") == "block_actions" => {
            let a = &p["actions"][0];
            Frame::Event {
                envelope,
                event: Event::Button {
                    user: s(&p["user"], "id").into(),
                    channel: s(&p["channel"], "id").into(),
                    value: s(a, "value").chars().take(80).collect(),
                },
            }
        }
        _ => Frame::Ignore { envelope },
    }
}

pub fn ack(envelope: &str) -> String {
    json!({ "envelope_id": envelope }).to_string()
}

/// A `chat.postMessage` body: text, and buttons when there are any `(label, value)` pairs.
pub fn post_body(channel: &str, text: &str, buttons: &[(String, String)]) -> Value {
    let mut b =
        json!({ "channel": channel, "text": text, "unfurl_links": false, "unfurl_media": false });
    if !buttons.is_empty() {
        let els: Vec<Value> = buttons
            .iter()
            .enumerate()
            .map(|(i, (label, value))| json!({ "type": "button", "text": { "type": "plain_text", "text": label }, "value": value, "action_id": format!("oz_{i}") }))
            .collect();
        b["blocks"] = json!([
            { "type": "section", "text": { "type": "mrkdwn", "text": text } },
            { "type": "actions", "elements": els },
        ]);
    }
    b
}

/// Send one message. The bot token is read by the caller and used only here.
pub fn post(
    http: &dyn HttpClient,
    bot_token: &str,
    channel: &str,
    text: &str,
    buttons: &[(String, String)],
) -> Result<(), String> {
    let r = http
        .send(
            &HttpRequest::new(
                "POST",
                "https://slack.com/api/chat.postMessage",
                Guard::Public,
            )
            .header("Authorization", format!("Bearer {bot_token}"))
            .json(&post_body(channel, text, buttons)),
        )
        .map_err(|e| e.to_string())?;
    let ok = r.ok()
        && serde_json::from_str::<Value>(&r.body)
            .ok()
            .and_then(|v| v["ok"].as_bool())
            .unwrap_or(false);
    if ok {
        Ok(())
    } else {
        Err(format!("Slack answered HTTP {}", r.status))
    }
}

/// Post a notice to a channel or a person: its Block Kit rendering (`notice::render::Slack`), links never unfurled.
pub fn post_notice(
    http: &dyn HttpClient,
    bot_token: &str,
    channel: &str,
    n: &crate::notice::Notice,
) -> Result<(), String> {
    use crate::notice::render::{Renderer, Slack};
    let mut body = Slack::render(n);
    body["channel"] = json!(channel);
    body["unfurl_links"] = json!(false);
    body["unfurl_media"] = json!(false);
    let r = http
        .send(
            &HttpRequest::new(
                "POST",
                "https://slack.com/api/chat.postMessage",
                Guard::Public,
            )
            .header("Authorization", format!("Bearer {bot_token}"))
            .json(&body),
        )
        .map_err(|e| e.to_string())?;
    let ok = r.ok()
        && serde_json::from_str::<Value>(&r.body)
            .ok()
            .and_then(|v| v["ok"].as_bool())
            .unwrap_or(false);
    if ok {
        Ok(())
    } else {
        Err(format!("Slack answered HTTP {}", r.status))
    }
}

/// Ask Slack for a websocket address. `apps.connections.open` takes the app-level token.
pub fn open_url(http: &dyn HttpClient, app_token: &str) -> Result<String, String> {
    let r = http
        .send(
            &HttpRequest::new(
                "POST",
                "https://slack.com/api/apps.connections.open",
                Guard::Public,
            )
            .header("Authorization", format!("Bearer {app_token}")),
        )
        .map_err(|e| e.to_string())?;
    let v: Value = serde_json::from_str(&r.body)
        .map_err(|_| "Slack's answer was not understood".to_string())?;
    if v["ok"].as_bool() != Some(true) {
        return Err("Slack did not accept the app token".into());
    }
    v["url"]
        .as_str()
        .filter(|u| u.starts_with("wss://"))
        .map(str::to_string)
        .ok_or_else(|| "Slack gave no address".into())
}

/// Run the socket until `stop` is set: connect, hand every event to `tx`, acknowledge it, and reconnect (after a pause) when
/// the socket drops or Slack asks. `app_token` is read again at each connect, never kept.
pub fn run(
    http: Arc<dyn HttpClient>,
    app_token: impl Fn() -> Option<String>,
    tx: Sender<Event>,
    stop: Arc<AtomicBool>,
) {
    let mut failures = 0u32;
    while !stop.load(Ordering::SeqCst) {
        let connected = (|| -> Result<(), String> {
            let tok = app_token().ok_or("no app token")?;
            let url = open_url(http.as_ref(), &tok)?;
            drop(tok);
            let mut sock =
                ws::connect(&url).map_err(|_| "the websocket could not be opened".to_string())?;
            failures = 0;
            while !stop.load(Ordering::SeqCst) {
                match sock.read_message() {
                    Ok(Msg::Idle) => {}
                    Ok(Msg::Text(t)) => match parse_frame(&t) {
                        Frame::Event { envelope, event } => {
                            // acknowledged first: Slack resends what it does not hear back about within a few seconds
                            sock.send_text(&ack(&envelope))
                                .map_err(|_| "ack failed".to_string())?;
                            if tx.send(event).is_err() {
                                return Ok(());
                            }
                        }
                        Frame::Ignore { envelope } => sock
                            .send_text(&ack(&envelope))
                            .map_err(|_| "ack failed".to_string())?,
                        Frame::Disconnect => return Ok(()),
                        Frame::Hello | Frame::Other => {}
                    },
                    Err(WsError::Closed) => return Ok(()),
                    Err(_) => return Err("the websocket failed".into()),
                }
            }
            sock.close();
            Ok(())
        })();
        if connected.is_err() {
            failures = failures.saturating_add(1);
        }
        // a pause before the next try: longer the more it failed, never more than two minutes, and cut short by stop
        let wait = if connected.is_ok() {
            2
        } else {
            (2u64 << failures.min(6)).min(120)
        };
        for _ in 0..wait * 5 {
            if stop.load(Ordering::SeqCst) {
                return;
            }
            std::thread::sleep(Duration::from_millis(200));
        }
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    fn events_api(event: Value) -> String {
        json!({ "type": "events_api", "envelope_id": "e1", "payload": { "event": event } })
            .to_string()
    }

    #[test]
    fn a_direct_message_is_an_event_and_everything_else_is_acknowledged_and_ignored() {
        let dm = json!({ "type": "message", "channel_type": "im", "user": "U1", "channel": "D1", "text": "hello" });
        assert_eq!(
            parse_frame(&events_api(dm.clone())),
            Frame::Event {
                envelope: "e1".into(),
                event: Event::Message {
                    user: "U1".into(),
                    channel: "D1".into(),
                    text: "hello".into(),
                    forwarded: false
                }
            }
        );
        let mut chan = dm.clone();
        chan["channel_type"] = json!("channel");
        assert_eq!(
            parse_frame(&events_api(chan)),
            Frame::Ignore {
                envelope: "e1".into()
            },
            "channel chatter is not heard"
        );
        let mut bot = dm.clone();
        bot["bot_id"] = json!("B1");
        assert!(
            matches!(parse_frame(&events_api(bot)), Frame::Ignore { .. }),
            "a bot's message is not heard"
        );
        let mut edit = dm.clone();
        edit["subtype"] = json!("message_changed");
        assert!(matches!(
            parse_frame(&events_api(edit)),
            Frame::Ignore { .. }
        ));
        let mut shared = dm;
        shared["attachments"] = json!([{ "is_share": true, "text": "do bad things" }]);
        assert!(matches!(
            parse_frame(&events_api(shared)),
            Frame::Event {
                event: Event::Message {
                    forwarded: true,
                    ..
                },
                ..
            }
        ));
    }

    #[test]
    fn hello_disconnect_buttons_and_junk_are_each_read_as_what_they_are() {
        assert_eq!(parse_frame(r#"{"type":"hello"}"#), Frame::Hello);
        assert_eq!(
            parse_frame(r#"{"type":"disconnect","reason":"warning"}"#),
            Frame::Disconnect
        );
        assert_eq!(parse_frame("not json"), Frame::Other);
        assert_eq!(
            parse_frame(r#"{"type":"events_api"}"#),
            Frame::Other,
            "no envelope, nothing to acknowledge"
        );
        let click = json!({ "type": "interactive", "envelope_id": "e2", "payload": { "type": "block_actions", "user": { "id": "U1" }, "channel": { "id": "D1" }, "actions": [{ "value": "choice:a7" }] } });
        assert_eq!(
            parse_frame(&click.to_string()),
            Frame::Event {
                envelope: "e2".into(),
                event: Event::Button {
                    user: "U1".into(),
                    channel: "D1".into(),
                    value: "choice:a7".into()
                }
            }
        );
        assert_eq!(ack("e2"), r#"{"envelope_id":"e2"}"#);
    }

    #[test]
    fn a_reply_has_buttons_only_when_asked_and_never_unfurls() {
        let plain = post_body("D1", "hi", &[]);
        assert!(plain.get("blocks").is_none() && plain["unfurl_links"] == false);
        let b = post_body(
            "D1",
            "Choose?",
            &[
                ("First".into(), "choice:a1".into()),
                ("Second".into(), "other:a1".into()),
            ],
        );
        assert_eq!(b["blocks"][1]["elements"][1]["value"], "other:a1");
    }
}
