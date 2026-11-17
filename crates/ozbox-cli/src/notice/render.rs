//! A [`Notice`] as each channel shows it: one layout, each channel's own conventions and escaping.
//!
//! * Telegram: HTML parse mode (only `<b>`, `<i>`, `<code>`; every value escaped), previews off, content protected, and an
//!   inline-keyboard **URL** button that only opens the dashboard (a URL button sends nothing back to the bot).
//! * Slack: Block Kit (a header, the summary, the facts as fields, a context line, one link button); untrusted values are
//!   `plain_text`, so nothing in them is formatting.
//! * Discord: one embed (title linked to the item, fields, the reference in the footer), markdown escaped, no mentions.
//! * Teams: an Adaptive Card with a fact set and one `Action.OpenUrl`.
//! * WhatsApp: a template's two text parameters (the title, then the rest on one line with the link), or plain text inside
//!   the 24-hour window.
//! * Email: a subject, a plain-text part and an HTML part.
//! * SMS: one short line with the link, folded to plain ASCII so it fits one 160-character part.
//! * Push: a title, a short body and the address the notification opens.
//! * Webhook: the structured fields, for a program.
//!
//! A channel adapter sends what these return and builds no message text of its own (a guard test holds that).

use serde_json::{json, Value};

use super::{
    clean, span, Action, Notice, NoticeKind, DETAILS_MAX, LINK_MINUTES, SUMMARY_MAX, VALUE_MAX,
};
use crate::messages::t;

/// One channel's way of showing a notice.
pub trait Renderer {
    type Out;
    fn render(n: &Notice) -> Self::Out;
}

pub struct Telegram;
pub struct Slack;
pub struct Discord;
pub struct Teams;
pub struct WhatsappTemplate;
pub struct Text;
pub struct Email;
pub struct Sms;
pub struct Push;
pub struct Webhook;

/// The one layout every channel draws, with every text field cleaned and bounded.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Layout {
    pub kind: NoticeKind,
    pub urgent: bool,
    pub production: bool,
    pub title: String,
    pub summary: String,
    /// Box, project, environment.
    pub context: Vec<(String, String)>,
    pub details: Vec<(String, String)>,
    /// How many details were left out.
    pub more: usize,
    /// Asked by, why.
    pub people: Vec<(String, String)>,
    pub risk: Option<String>,
    pub expiry: Option<String>,
    pub note: Option<String>,
    pub action: Option<ActionView>,
    pub reference: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ActionView {
    /// What to do, naming the host (so a lookalike is recognisable) or the page.
    pub sentence: String,
    /// The link, when there is one.
    pub url: Option<String>,
    pub button: String,
    pub one_time: bool,
}

pub fn layout(n: &Notice) -> Layout {
    let mut context = Vec::new();
    for (key, v) in [
        ("notice.box", &n.box_name),
        ("notice.project", &n.project),
        ("notice.environment", &n.environment),
    ] {
        if let Some(v) = v
            .as_deref()
            .map(|v| clean(v, VALUE_MAX))
            .filter(|v| !v.is_empty())
        {
            context.push((t(key, &[]), v));
        }
    }
    let details: Vec<(String, String)> = n
        .details
        .iter()
        .take(DETAILS_MAX)
        .map(|f| (clean(&f.label, 60), clean(&f.value, VALUE_MAX)))
        .collect();
    let mut people = Vec::new();
    for (key, v) in [("notice.asked_by", &n.asked_by), ("notice.why", &n.why)] {
        if let Some(v) = v
            .as_deref()
            .map(|v| clean(v, VALUE_MAX))
            .filter(|v| !v.is_empty())
        {
            people.push((t(key, &[]), v));
        }
    }
    let expiry = n.expires_ms.map(|e| {
        if e <= n.created_ms {
            t("notice.expired", &[])
        } else {
            t("notice.expires", &[("span", &span(e - n.created_ms))])
        }
    });
    let place = clean(&n.place(), 60);
    let action = n.action.as_ref().map(|a| match a {
        Action::OneTime { url, host } => ActionView {
            sentence: t(
                "notice.open_once",
                &[
                    ("host", host),
                    ("minutes", &LINK_MINUTES.to_string()),
                    ("place", &place),
                ],
            ),
            url: Some(url.clone()),
            button: t("notice.button", &[]),
            one_time: true,
        },
        Action::Page { url, host } => ActionView {
            sentence: t("notice.open_page", &[("host", host), ("place", &place)]),
            url: Some(url.clone()),
            button: t("notice.button", &[]),
            one_time: false,
        },
        Action::Words => ActionView {
            sentence: t("notice.open_words", &[("place", &place)]),
            url: None,
            button: t("notice.button", &[]),
            one_time: false,
        },
    });
    Layout {
        kind: n.kind,
        urgent: n.urgent,
        production: n.production,
        title: clean(&n.title, 120),
        summary: clean(&n.summary, SUMMARY_MAX),
        context,
        more: n.details.len().saturating_sub(DETAILS_MAX),
        details,
        people,
        risk: n
            .risk
            .as_deref()
            .map(|r| clean(r, VALUE_MAX))
            .filter(|r| !r.is_empty()),
        expiry,
        note: n.only_tells.then(|| t("notice.only_tells", &[])),
        action,
        reference: n
            .reference
            .as_deref()
            .map(super::reference)
            .filter(|r| !r.is_empty())
            .map(|r| t("notice.reference", &[("ref", &r)])),
    }
}

/// A reply's words: control characters out (line breaks kept), bounded.
fn reply_text(n: &Notice, max: usize) -> String {
    let s: String = n
        .summary
        .chars()
        .filter(|c| !c.is_control() || *c == '\n' || *c == '\t')
        .collect();
    crate::channels::clip(&s, max)
}

fn emoji(l: &Layout) -> &'static str {
    if l.urgent {
        return "\u{1f6a8}";
    }
    match l.kind {
        NoticeKind::ApprovalRequest => "\u{1f510}",
        NoticeKind::AgentAsks => "\u{1f916}",
        NoticeKind::Budget => "\u{1f4b8}",
        NoticeKind::Test => "\u{2705}",
        NoticeKind::Digest => "\u{1f5d2}",
        NoticeKind::Alert | NoticeKind::Reply => "\u{1f514}",
    }
}

// ---------- escaping ----------

/// Telegram HTML: `&`, `<`, `>` and `"` (attribute values) as entities.
pub fn html(s: &str) -> String {
    let mut o = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '&' => o.push_str("&amp;"),
            '<' => o.push_str("&lt;"),
            '>' => o.push_str("&gt;"),
            '"' => o.push_str("&quot;"),
            '\'' => o.push_str("&#39;"),
            c => o.push(c),
        }
    }
    o
}

/// Markdown (Discord, Teams): every character that formats, quotes or links, behind a backslash.
pub fn md(s: &str) -> String {
    let mut o = String::with_capacity(s.len());
    for c in s.chars() {
        if matches!(
            c,
            '\\' | '*'
                | '_'
                | '~'
                | '`'
                | '|'
                | '>'
                | '#'
                | '['
                | ']'
                | '('
                | ')'
                | '-'
                | '+'
                | '!'
                | '<'
                | '@'
        ) {
            o.push('\\');
        }
        o.push(c);
    }
    o
}

/// Slack mrkdwn: only `&`, `<` and `>` are escaped by Slack's rules.
pub fn slack_escape(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
}

// ---------- plain text ----------

impl Renderer for Text {
    type Out = String;
    fn render(n: &Notice) -> String {
        if n.kind == NoticeKind::Reply {
            return reply_text(n, crate::chat::text::MESSAGE_CHARS);
        }
        text(&layout(n))
    }
}

fn joined(v: &[(String, String)], sep: &str) -> String {
    v.iter()
        .map(|(k, v)| format!("{k}: {v}"))
        .collect::<Vec<_>>()
        .join(sep)
}

fn text(l: &Layout) -> String {
    let mut out = Vec::new();
    let badge = if l.production {
        format!(" [{}]", t("notice.production", &[]))
    } else {
        String::new()
    };
    out.push(format!("{}{badge}", l.title));
    if !l.summary.is_empty() {
        out.push(l.summary.clone());
    }
    let mut facts = Vec::new();
    if !l.context.is_empty() {
        facts.push(joined(&l.context, " · "));
    }
    facts.extend(l.details.iter().map(|(k, v)| format!("{k}: {v}")));
    if l.more > 0 {
        facts.push(t("notice.more", &[("n", &l.more.to_string())]));
    }
    facts.extend(l.people.iter().map(|(k, v)| format!("{k}: {v}")));
    if let Some(r) = &l.risk {
        facts.push(format!("{}: {r}", t("notice.risk", &[])));
    }
    if let Some(e) = &l.expiry {
        facts.push(e.clone());
    }
    if !facts.is_empty() {
        out.push(String::new());
        out.extend(facts);
    }
    let mut tail = Vec::new();
    if let Some(n) = &l.note {
        tail.push(n.clone());
    }
    if let Some(a) = &l.action {
        tail.push(a.sentence.clone());
        if let Some(u) = &a.url {
            tail.push(u.clone());
        }
    }
    if let Some(r) = &l.reference {
        tail.push(r.clone());
    }
    if !tail.is_empty() {
        out.push(String::new());
        out.extend(tail);
    }
    out.join("\n")
}

// ---------- Telegram ----------

impl Renderer for Telegram {
    /// The `sendMessage` body, without `chat_id`.
    type Out = Value;
    fn render(n: &Notice) -> Value {
        let base = json!({
            "disable_web_page_preview": true,
            "link_preview_options": { "is_disabled": true },
            "protect_content": true,
        });
        let mut v = base;
        // a reply to a message sent to several boxes answers it in Telegram's own thread
        if let Some(id) = n.thread.as_deref().and_then(|t| t.parse::<i64>().ok()) {
            v["reply_parameters"] =
                json!({ "message_id": id, "allow_sending_without_reply": true });
        }
        if n.kind == NoticeKind::Reply {
            v["text"] = json!(reply_text(n, 4000));
            return v;
        }
        let l = layout(n);
        v["text"] = json!(telegram_html(&l));
        v["parse_mode"] = json!("HTML");
        if let Some(url) = l.action.as_ref().and_then(|a| a.url.clone()) {
            // a URL button opens the address and sends nothing back: it cannot approve anything
            v["reply_markup"] = json!({ "inline_keyboard": [[{ "text": l.action.as_ref().map(|a| a.button.clone()).unwrap_or_default(), "url": url }]] });
        }
        v
    }
}

fn telegram_html(l: &Layout) -> String {
    let mut out = Vec::new();
    let mut head = format!("{} <b>{}</b>", emoji(l), html(&l.title));
    if l.production {
        head.push_str(&format!(
            " · \u{1f534} <b>{}</b>",
            html(&t("notice.production", &[]))
        ));
    }
    out.push(head);
    if !l.summary.is_empty() {
        out.push(html(&l.summary));
    }
    let mut facts = Vec::new();
    if !l.context.is_empty() {
        facts.push(
            l.context
                .iter()
                .map(|(k, v)| format!("<b>{}</b> {}", html(k), html(v)))
                .collect::<Vec<_>>()
                .join(" · "),
        );
    }
    for (k, v) in l.details.iter().chain(l.people.iter()) {
        facts.push(format!("<b>{}</b>: {}", html(k), html(v)));
    }
    if l.more > 0 {
        facts.push(html(&t("notice.more", &[("n", &l.more.to_string())])));
    }
    if let Some(r) = &l.risk {
        facts.push(format!(
            "\u{26a0}\u{fe0f} <b>{}</b>: {}",
            html(&t("notice.risk", &[])),
            html(r)
        ));
    }
    if let Some(e) = &l.expiry {
        facts.push(format!("\u{23f3} {}", html(e)));
    }
    if !facts.is_empty() {
        out.push(String::new());
        out.extend(facts);
    }
    let mut tail = Vec::new();
    if let Some(n) = &l.note {
        tail.push(format!("<i>{}</i>", html(n)));
    }
    if let Some(a) = &l.action {
        tail.push(html(&a.sentence));
    }
    if let Some(r) = &l.reference {
        tail.push(format!("<code>{}</code>", html(r)));
    }
    if !tail.is_empty() {
        out.push(String::new());
        out.extend(tail);
    }
    out.join("\n")
}

// ---------- Slack ----------

impl Renderer for Slack {
    /// A message payload: `text` (the notification fallback) and `blocks`.
    type Out = Value;
    fn render(n: &Notice) -> Value {
        let mut v = Self::render_unthreaded(n);
        // a reply to a message sent to several boxes goes in the thread of that message
        if let Some(ts) = n.thread.as_deref().filter(|t| slack_ts_ok(t)) {
            v["thread_ts"] = json!(ts);
        }
        v
    }
}

/// A Slack message timestamp: digits, one dot, digits.
fn slack_ts_ok(t: &str) -> bool {
    t.len() <= 32
        && t.split_once('.').is_some_and(|(a, b)| {
            !a.is_empty()
                && !b.is_empty()
                && a.bytes().all(|c| c.is_ascii_digit())
                && b.bytes().all(|c| c.is_ascii_digit())
        })
}

impl Slack {
    fn render_unthreaded(n: &Notice) -> Value {
        if n.kind == NoticeKind::Reply {
            return json!({ "text": slack_escape(&reply_text(n, 3000)) });
        }
        let l = layout(n);
        let plain = |s: &str| json!({ "type": "plain_text", "text": s, "emoji": true });
        let mut head = format!("{} {}", emoji(&l), l.title);
        if l.production {
            head.push_str(&format!(" \u{1f534} {}", t("notice.production", &[])));
        }
        let mut blocks =
            vec![json!({ "type": "header", "text": plain(&crate::channels::clip(&head, 150)) })];
        if !l.summary.is_empty() {
            blocks.push(json!({ "type": "section", "text": plain(&l.summary) }));
        }
        let mut fields: Vec<Value> = l
            .context
            .iter()
            .chain(l.details.iter())
            .chain(l.people.iter())
            .map(|(k, v)| plain(&format!("{k}: {v}")))
            .collect();
        if let Some(r) = &l.risk {
            fields.push(plain(&format!("{}: {r}", t("notice.risk", &[]))));
        }
        for chunk in fields.chunks(10) {
            blocks.push(json!({ "type": "section", "fields": chunk }));
        }
        let mut ctx: Vec<String> = Vec::new();
        if let Some(e) = &l.expiry {
            ctx.push(e.clone());
        }
        if let Some(n) = &l.note {
            ctx.push(n.clone());
        }
        if let Some(r) = &l.reference {
            ctx.push(r.clone());
        }
        if !ctx.is_empty() {
            blocks.push(json!({ "type": "context", "elements": ctx.iter().map(|c| plain(c)).collect::<Vec<_>>() }));
        }
        if let Some(a) = &l.action {
            match &a.url {
                Some(url) => {
                    blocks.push(json!({ "type": "section", "text": plain(&a.sentence) }));
                    blocks.push(json!({ "type": "actions", "elements": [{
                        "type": "button",
                        "text": plain(&a.button),
                        "url": url,
                        "style": "primary",
                        "action_id": "open_dashboard",
                    }]}));
                }
                None => blocks.push(json!({ "type": "section", "text": plain(&a.sentence) })),
            }
        }
        json!({ "text": slack_escape(&l.title), "blocks": blocks })
    }
}

// ---------- Discord ----------

impl Renderer for Discord {
    /// An execute-webhook body.
    type Out = Value;
    fn render(n: &Notice) -> Value {
        if n.kind == NoticeKind::Reply {
            return json!({ "content": md(&reply_text(n, 1900)), "allowed_mentions": { "parse": [] }, "username": "Oz Box" });
        }
        let l = layout(n);
        let mut title = format!("{} {}", emoji(&l), l.title);
        if l.production {
            title.push_str(&format!(" \u{1f534} {}", t("notice.production", &[])));
        }
        let mut desc = vec![md(&l.summary)];
        if let Some(n) = &l.note {
            desc.push(format!("*{}*", md(n)));
        }
        if let Some(a) = &l.action {
            match &a.url {
                Some(u) => desc.push(format!("[{}]({u})\n{}", md(&a.button), md(&a.sentence))),
                None => desc.push(md(&a.sentence)),
            }
        }
        let mut fields: Vec<Value> = l
            .context
            .iter()
            .map(|(k, v)| json!({ "name": md(k), "value": md(v), "inline": true }))
            .collect();
        fields.extend(
            l.details
                .iter()
                .chain(l.people.iter())
                .map(|(k, v)| json!({ "name": md(k), "value": md(v), "inline": false })),
        );
        if let Some(r) = &l.risk {
            fields.push(
                json!({ "name": md(&t("notice.risk", &[])), "value": md(r), "inline": false }),
            );
        }
        if let Some(e) = &l.expiry {
            fields.push(json!({ "name": "\u{23f3}", "value": md(e), "inline": false }));
        }
        fields.truncate(25);
        let mut embed = json!({
            "title": crate::channels::clip(&md(&title), 256),
            "description": crate::channels::clip(&desc.join("\n\n"), 3500),
            "color": if l.urgent || l.production { 0xd0_30_30 } else { 0x2f_6f_d0 },
            "fields": fields,
        });
        if let Some(u) = l.action.as_ref().and_then(|a| a.url.clone()) {
            embed["url"] = json!(u);
        }
        if let Some(r) = &l.reference {
            embed["footer"] = json!({ "text": r });
        }
        json!({ "embeds": [embed], "allowed_mentions": { "parse": [] }, "username": "Oz Box" })
    }
}

// ---------- Teams ----------

impl Renderer for Teams {
    /// A Workflows message carrying one Adaptive Card.
    type Out = Value;
    fn render(n: &Notice) -> Value {
        let card = if n.kind == NoticeKind::Reply {
            json!({ "body": [{ "type": "TextBlock", "text": md(&reply_text(n, 3000)), "wrap": true }] })
        } else {
            let l = layout(n);
            let mut title = l.title.clone();
            if l.production {
                title.push_str(&format!(" \u{1f534} {}", t("notice.production", &[])));
            }
            let mut body = vec![
                json!({ "type": "TextBlock", "text": md(&title), "weight": "Bolder", "size": "Medium", "wrap": true, "color": if l.urgent || l.production { "Attention" } else { "Default" } }),
            ];
            if !l.summary.is_empty() {
                body.push(json!({ "type": "TextBlock", "text": md(&l.summary), "wrap": true }));
            }
            let mut facts: Vec<Value> = l
                .context
                .iter()
                .chain(l.details.iter())
                .chain(l.people.iter())
                .map(|(k, v)| json!({ "title": md(k), "value": md(v) }))
                .collect();
            if let Some(r) = &l.risk {
                facts.push(json!({ "title": md(&t("notice.risk", &[])), "value": md(r) }));
            }
            if !facts.is_empty() {
                body.push(json!({ "type": "FactSet", "facts": facts }));
            }
            let small: Vec<String> = [
                l.expiry.clone(),
                l.note.clone(),
                l.action.as_ref().map(|a| a.sentence.clone()),
                l.reference.clone(),
            ]
            .into_iter()
            .flatten()
            .collect();
            for s in small {
                body.push(json!({ "type": "TextBlock", "text": md(&s), "wrap": true, "isSubtle": true, "size": "Small" }));
            }
            let mut card = json!({ "body": body });
            if let Some(a) = &l.action {
                if let Some(u) = &a.url {
                    card["actions"] =
                        json!([{ "type": "Action.OpenUrl", "title": a.button, "url": u }]);
                }
            }
            card
        };
        let mut content = json!({
            "$schema": "http://adaptivecards.io/schemas/adaptive-card.json",
            "type": "AdaptiveCard",
            "version": "1.4",
        });
        content["body"] = card["body"].clone();
        if card.get("actions").is_some() {
            content["actions"] = card["actions"].clone();
        }
        json!({
            "type": "message",
            "attachments": [{ "contentType": "application/vnd.microsoft.card.adaptive", "contentUrl": null, "content": content }],
        })
    }
}

// ---------- WhatsApp ----------

impl Renderer for WhatsappTemplate {
    /// The template's two text parameters: the title, then everything else on one line, link included.
    type Out = (String, String);
    fn render(n: &Notice) -> (String, String) {
        if n.kind == NoticeKind::Reply {
            return ("Oz Box".to_string(), clean(&n.summary, 900));
        }
        let l = layout(n);
        let mut title = l.title.clone();
        if l.production {
            title.push_str(&format!(" [{}]", t("notice.production", &[])));
        }
        let mut rest = Vec::new();
        if !l.summary.is_empty() {
            rest.push(l.summary.clone());
        }
        if !l.context.is_empty() {
            rest.push(joined(&l.context, " · "));
        }
        rest.extend(
            l.details
                .iter()
                .chain(l.people.iter())
                .map(|(k, v)| format!("{k}: {v}")),
        );
        if let Some(r) = &l.risk {
            rest.push(format!("{}: {r}", t("notice.risk", &[])));
        }
        rest.extend(l.expiry.clone());
        rest.extend(l.note.clone());
        if let Some(a) = &l.action {
            rest.push(a.sentence.clone());
            rest.extend(a.url.clone());
        }
        rest.extend(l.reference.clone());
        // the link goes last but must never be cut: what is cut is the text before it
        let tail: String = l
            .action
            .as_ref()
            .and_then(|a| a.url.clone())
            .map(|u| format!(" {u}"))
            .unwrap_or_default();
        let joined = rest.join(" | ");
        let body = if joined.chars().count() > 900 {
            let head: String = rest
                .iter()
                .filter(|s| Some(s.as_str()) != l.action.as_ref().and_then(|a| a.url.as_deref()))
                .cloned()
                .collect::<Vec<_>>()
                .join(" | ");
            format!(
                "{}{tail}",
                crate::channels::clip(&head, 900 - tail.chars().count())
            )
        } else {
            joined
        };
        (crate::channels::clip(&title, 200), body)
    }
}

// ---------- Email ----------

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EmailParts {
    pub subject: String,
    pub text: String,
    pub html: String,
}

impl Renderer for Email {
    type Out = EmailParts;
    fn render(n: &Notice) -> EmailParts {
        let l = layout(n);
        let mut subject = format!("[Oz Box] {}", l.title);
        if l.production {
            subject.push_str(&format!(" [{}]", t("notice.production", &[])));
        }
        let text_part = Text::render(n);
        let html_part = if n.kind == NoticeKind::Reply {
            format!(
                "<p>{}</p>",
                html(&reply_text(n, 20_000)).replace('\n', "<br>")
            )
        } else {
            email_html(&l)
        };
        EmailParts {
            subject: crate::channels::one_line(&subject),
            text: text_part,
            html: html_part,
        }
    }
}

fn email_html(l: &Layout) -> String {
    let mut o = String::new();
    o.push_str("<div style=\"font-family:-apple-system,Segoe UI,Roboto,Helvetica,Arial,sans-serif;font-size:15px;line-height:1.5;color:#111;max-width:600px\">");
    o.push_str(&format!(
        "<h2 style=\"font-size:18px;margin:0 0 8px\">{}",
        html(&l.title)
    ));
    if l.production {
        o.push_str(&format!(
            " <span style=\"background:#b00020;color:#fff;border-radius:4px;padding:1px 6px;font-size:12px\">{}</span>",
            html(&t("notice.production", &[]))
        ));
    }
    o.push_str("</h2>");
    if !l.summary.is_empty() {
        o.push_str(&format!(
            "<p style=\"margin:0 0 12px\">{}</p>",
            html(&l.summary)
        ));
    }
    let rows: Vec<&(String, String)> = l
        .context
        .iter()
        .chain(l.details.iter())
        .chain(l.people.iter())
        .collect();
    let risk = l.risk.as_ref().map(|r| (t("notice.risk", &[]), r.clone()));
    if !rows.is_empty() || risk.is_some() {
        o.push_str(
            "<table role=\"presentation\" style=\"border-collapse:collapse;margin:0 0 12px\">",
        );
        for (k, v) in rows.into_iter().chain(risk.iter()) {
            o.push_str(&format!(
                "<tr><td style=\"padding:2px 12px 2px 0;color:#555;vertical-align:top\">{}</td><td style=\"padding:2px 0\">{}</td></tr>",
                html(k),
                html(v)
            ));
        }
        o.push_str("</table>");
    }
    if l.more > 0 {
        o.push_str(&format!(
            "<p style=\"margin:0 0 12px;color:#555\">{}</p>",
            html(&t("notice.more", &[("n", &l.more.to_string())]))
        ));
    }
    if let Some(e) = &l.expiry {
        o.push_str(&format!("<p style=\"margin:0 0 12px\">{}</p>", html(e)));
    }
    if let Some(a) = &l.action {
        if let Some(u) = &a.url {
            o.push_str(&format!(
                "<p style=\"margin:16px 0\"><a href=\"{}\" style=\"background:#1f4fd0;color:#fff;text-decoration:none;border-radius:6px;padding:10px 16px;display:inline-block\">{}</a></p>",
                html(u),
                html(&a.button)
            ));
        }
        o.push_str(&format!(
            "<p style=\"margin:0 0 12px;color:#333\">{}</p>",
            html(&a.sentence)
        ));
    }
    if let Some(n) = &l.note {
        o.push_str(&format!(
            "<p style=\"margin:0 0 12px;color:#555\"><em>{}</em></p>",
            html(n)
        ));
    }
    if let Some(r) = &l.reference {
        o.push_str(&format!(
            "<p style=\"margin:0;color:#777;font-size:13px\">{}</p>",
            html(r)
        ));
    }
    o.push_str("</div>");
    o
}

// ---------- SMS ----------

/// One part of plain seven-bit text.
pub const SMS_PART: usize = 160;

/// Plain ASCII, so the text stays in the 160-character encoding: arrows, dots and dashes become their ASCII look-alikes,
/// and any other character a `?`.
pub fn ascii_fold(s: &str) -> String {
    let mut o = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            c if c.is_ascii() && !c.is_ascii_control() => o.push(c),
            '\u{2192}' => o.push('>'),
            '\u{00b7}' | '\u{2022}' => o.push('-'),
            '\u{2026}' => o.push_str("..."),
            '\u{2013}' | '\u{2014}' => o.push('-'),
            '\u{2018}' | '\u{2019}' => o.push('\''),
            '\u{201c}' | '\u{201d}' => o.push('"'),
            c if c.is_whitespace() || c.is_control() => o.push(' '),
            _ => o.push('?'),
        }
    }
    o
}

impl Renderer for Sms {
    /// One line: "Oz Box: <title> (<box>, PRODUCTION). Open: <link> Ref <id>", in one part whenever the link allows.
    type Out = String;
    fn render(n: &Notice) -> String {
        if n.kind == NoticeKind::Reply {
            return crate::channels::clip(
                &ascii_fold(&clean(&n.summary, 400)),
                crate::channels::sms::MAX_ASCII,
            );
        }
        let l = layout(n);
        let mut where_ = Vec::new();
        if let Some((_, b)) = l
            .context
            .first()
            .filter(|(k, _)| *k == t("notice.box", &[]))
        {
            where_.push(b.clone());
        }
        if l.production {
            where_.push(t("notice.production", &[]));
        }
        let place = clean(&n.place(), 40);
        let open = match l.action.as_ref() {
            Some(a) => match &a.url {
                Some(u) => format!(" {}", t("notice.sms_open", &[("url", u)])),
                None => format!(" {}.", t("notice.sms_words", &[("place", &place)])),
            },
            None => String::new(),
        };
        let reference = l
            .reference
            .as_ref()
            .map(|r| format!(" {r}"))
            .unwrap_or_default();
        let ctx = if where_.is_empty() {
            String::new()
        } else {
            format!(" ({})", where_.join(", "))
        };
        let fixed = ascii_fold(&format!("{ctx}.{open}{reference}"));
        let lead = "Oz Box: ";
        let room = SMS_PART.saturating_sub(lead.len() + fixed.chars().count());
        let title = ascii_fold(&l.title);
        let title = if room >= 12 {
            crate::channels::clip(&title, room).replace('\u{2026}', ".")
        } else {
            // the link alone does not leave room in one part: allow more parts rather than cut the link
            crate::channels::clip(&title, 60).replace('\u{2026}', ".")
        };
        crate::channels::clip(
            &format!("{lead}{title}{fixed}"),
            crate::channels::sms::MAX_ASCII,
        )
    }
}

// ---------- push ----------

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PushParts {
    pub title: String,
    pub body: String,
    /// A same-origin path the notification opens (`/go#<token>` or the item's path).
    pub path: String,
}

impl Renderer for Push {
    type Out = PushParts;
    fn render(n: &Notice) -> PushParts {
        if n.kind == NoticeKind::Reply {
            return PushParts {
                title: "Oz Box".into(),
                body: clean(&n.summary, 160),
                path: "/chat".into(),
            };
        }
        let l = layout(n);
        let mut title = l.title.clone();
        if l.production {
            title = format!("[{}] {title}", t("notice.production", &[]));
        }
        let mut body = Vec::new();
        if let Some((_, b)) = l.context.first() {
            body.push(b.clone());
        }
        if !l.summary.is_empty() {
            body.push(l.summary.clone());
        }
        body.extend(l.expiry.clone());
        body.extend(l.reference.clone());
        // a notification opens the dashboard it came from, so only the path part of the address is kept
        let path = match n.action.as_ref().and_then(Action::url) {
            Some(url) => url
                .split("://")
                .nth(1)
                .and_then(|r| r.find('/').map(|i| r[i..].to_string()))
                .unwrap_or_else(|| "/".into()),
            None => n
                .open
                .as_ref()
                .map_or_else(|| "/activity".to_string(), |o| o.path.clone()),
        };
        PushParts {
            title: crate::channels::clip(&title, 60),
            body: crate::channels::clip(&body.join(" · "), 160),
            path,
        }
    }
}

// ---------- webhook ----------

impl Renderer for Webhook {
    /// The structured fields for a program. A webhook has no one person behind it, so it never carries a one-time link.
    type Out = Value;
    fn render(n: &Notice) -> Value {
        let l = layout(n);
        let url = match &n.action {
            Some(Action::Page { url, .. }) => Some(url.clone()),
            _ => None,
        };
        json!({
            "kind": n.kind,
            "title": l.title,
            "summary": l.summary,
            "box": n.box_name.as_deref().map(|b| clean(b, VALUE_MAX)),
            "project": n.project.as_deref().map(|b| clean(b, VALUE_MAX)),
            "environment": n.environment.as_deref().map(|b| clean(b, VALUE_MAX)),
            "production": n.production,
            "expires_ms": n.expires_ms,
            "reference": n.reference.as_deref().map(super::reference),
            "url": url,
            "path": n.open.as_ref().map(|o| o.path.clone()),
        })
    }
}

#[cfg(test)]
mod thread_tests {
    use super::*;

    #[test]
    fn a_threaded_reply_carries_the_apps_own_thread_field_and_a_bad_id_is_dropped() {
        let n = Notice::reply("hi").in_thread(Some("41".into()));
        assert_eq!(Telegram::render(&n)["reply_parameters"]["message_id"], 41);
        let n = Notice::reply("hi").in_thread(Some("1700000000.000300".into()));
        assert_eq!(Slack::render(&n)["thread_ts"], "1700000000.000300");
        let n = Notice::reply("hi").in_thread(Some("x<y".into()));
        assert!(Telegram::render(&n).get("reply_parameters").is_none());
        assert!(Slack::render(&n).get("thread_ts").is_none());
        assert!(Slack::render(&Notice::reply("hi"))
            .get("thread_ts")
            .is_none());
    }
}
