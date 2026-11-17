//! Golden renderings of every notice kind on every channel, escaping, lengths and the sentinel.
//!
//! Regenerate the golden files after an intended change with
//! `OZBOX_WRITE_NOTICE_GOLDEN=1 cargo test -p ozbox-cli notice::tests`, and read the diff.

#![allow(clippy::unwrap_used)]

use serde_json::Value;

use super::render::{
    ascii_fold, Discord, Email, Push, Renderer, Slack, Sms, Teams, Telegram, Text, Webhook,
    WhatsappTemplate, SMS_PART,
};
use super::*;

const BASE: &str = "https://dash.example.com";
const TOKEN: &str = "0123456789abcdef0123456789abcdef0123456789abcdef";
const T0: u64 = 1_700_000_000_000;

pub(crate) fn approval() -> Notice {
    let mut n = Notice::new(
        NoticeKind::ApprovalRequest,
        t("notice.approval_title", &[("what", "guard override")]),
        t("notice.approval_summary", &[]),
    );
    n.box_name = Some("main".into());
    n.project = Some("shop".into());
    n.environment = Some("staging".into());
    n.asked_by = Some("box-user (uid 1000)".into());
    n.details = vec![
        Fact {
            label: "Hook".into(),
            value: "commit (pre-commit)".into(),
        },
        Fact {
            label: "Repository".into(),
            value: "/work/shop".into(),
        },
    ];
    n.risk = Some("Skips the secret scan for one commit.".into());
    n.created_ms = T0;
    n.expires_ms = Some(T0 + 2 * 3_600_000 + 5 * 60_000);
    n.reference = Some("R1a2b3c4".into());
    n.only_tells = true;
    n.opens(
        "/approvals?request=R1a2b3c4",
        t("notice.place_approvals", &[]),
    )
}

fn agent_asks() -> Notice {
    let mut n = Notice::new(
        NoticeKind::AgentAsks,
        t("notice.agent_title", &[("action", "push to main")]),
        t("notice.agent_summary", &[("task", "t-42")]),
    );
    n.box_name = Some("api".into());
    n.environment = Some("production".into());
    n.production = true;
    n.asked_by = Some("Claude Code".into());
    n.why = Some("open a pull request".into());
    n.risk = Some(t("notice.agent_risky", &[]));
    n.created_ms = T0;
    n.reference = Some("a-7".into());
    n.only_tells = true;
    n.opens("/chat", t("notice.place_chat", &[]))
}

fn disk() -> Notice {
    let a = crate::notify::Alert {
        key: "disk:main".into(),
        kind: "disk".into(),
        severity: crate::notify::Severity::Urgent,
        box_name: Some("main".into()),
        title: "Box main: the work disk is 96% full".into(),
        body: "Grow the work disk, or clear space, before it fills.".into(),
        ts_ms: T0,
        notice: None,
        reach: Default::default(),
    };
    a.notice()
}

fn budget() -> Notice {
    let mut n = Notice::new(
        NoticeKind::Budget,
        "Budget: 80% of the monthly budget is estimated spent",
        "About 80 USD of 100 USD this month.",
    );
    n.created_ms = T0;
    n.opens("/usage", t("notice.place_usage", &[]))
}

/// Every case: a name, and the notice with the action its recipient gets.
fn cases() -> Vec<(&'static str, Notice)> {
    let one_time = |n: Notice| {
        let a = n.action_for(Some(BASE), Some(TOKEN));
        n.with_action(a)
    };
    let page = |n: Notice| {
        let a = n.action_for(Some(BASE), None);
        n.with_action(a)
    };
    let words = |n: Notice| {
        let a = n.action_for(None, Some(TOKEN));
        n.with_action(a)
    };
    vec![
        ("approval", one_time(approval())),
        ("approval-shared", page(approval())),
        ("approval-no-address", words(approval())),
        ("agent-asks", one_time(agent_asks())),
        ("disk", one_time(disk())),
        ("budget", page(budget())),
        (
            "reply",
            Notice::reply("Done: 3 files changed.\nTests pass."),
        ),
    ]
}

fn pretty(v: &Value) -> String {
    serde_json::to_string_pretty(v).unwrap()
}

/// Every channel's rendering of a notice, as text to compare.
fn renderings(n: &Notice) -> Vec<(&'static str, String)> {
    let e = Email::render(n);
    let (wt, wb) = WhatsappTemplate::render(n);
    let p = Push::render(n);
    vec![
        ("telegram", pretty(&Telegram::render(n))),
        ("slack", pretty(&Slack::render(n))),
        ("discord", pretty(&Discord::render(n))),
        ("teams", pretty(&Teams::render(n))),
        ("whatsapp", format!("{wt}\n---\n{wb}")),
        (
            "email",
            format!("Subject: {}\n---\n{}\n---\n{}", e.subject, e.text, e.html),
        ),
        ("sms", Sms::render(n)),
        ("push", format!("{}\n{}\n{}", p.title, p.body, p.path)),
        ("webhook", pretty(&Webhook::render(n))),
        ("text", Text::render(n)),
    ]
}

#[test]
fn every_kind_on_every_channel_matches_its_golden_file() {
    let dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src/notice/golden");
    let write = std::env::var("OZBOX_WRITE_NOTICE_GOLDEN").is_ok();
    let mut wrong = Vec::new();
    for (case, n) in cases() {
        for (channel, got) in renderings(&n) {
            let path = dir.join(format!("{case}.{channel}.txt"));
            let got = format!("{got}\n");
            if write {
                std::fs::create_dir_all(&dir).unwrap();
                std::fs::write(&path, &got).unwrap();
                continue;
            }
            let want = std::fs::read_to_string(&path).unwrap_or_default();
            if want != got {
                wrong.push(format!("{case}.{channel}:\n{got}"));
            }
        }
    }
    assert!(
        wrong.is_empty(),
        "these renderings changed (regenerate with OZBOX_WRITE_NOTICE_GOLDEN=1 if intended):\n{}",
        wrong.join("\n")
    );
}

#[test]
fn every_actionable_rendering_carries_the_link_or_says_where_to_go() {
    let url = format!("{BASE}/go#{TOKEN}");
    for (case, n) in cases() {
        if n.kind == NoticeKind::Reply {
            continue;
        }
        let r = renderings(&n);
        let get = |c: &str| r.iter().find(|(ch, _)| *ch == c).unwrap().1.clone();
        match n.action.as_ref().unwrap() {
            Action::OneTime { .. } => {
                for ch in [
                    "telegram", "slack", "discord", "teams", "whatsapp", "email", "sms", "text",
                ] {
                    assert!(
                        get(ch).contains(&url),
                        "{case} on {ch} has no link:\n{}",
                        get(ch)
                    );
                }
                assert!(get("push").ends_with(&format!("/go#{TOKEN}")), "{case}");
                // a program gets no link made for a person
                assert!(!get("webhook").contains(TOKEN), "{case}");
                // and the message names the host, so a lookalike stands out
                assert!(get("telegram").contains("dash.example.com"), "{case}");
            }
            Action::Page { url, .. } => {
                for ch in [
                    "telegram", "slack", "discord", "teams", "whatsapp", "email", "sms", "text",
                    "webhook",
                ] {
                    assert!(get(ch).contains(url.as_str()), "{case} on {ch}");
                }
            }
            Action::Words => {
                for ch in [
                    "telegram", "slack", "discord", "teams", "whatsapp", "email", "text",
                ] {
                    let s = get(ch);
                    assert!(
                        s.contains("no public address") && s.contains("Approvals"),
                        "{case} on {ch}:\n{s}"
                    );
                    assert!(!s.contains("/go#"), "{case} on {ch}");
                }
                assert!(
                    get("sms").contains("Open your dashboard > Approvals"),
                    "{}",
                    get("sms")
                );
            }
        }
    }
}

#[test]
fn telegram_uses_html_and_a_url_button_that_only_opens() {
    let n = &cases()[0].1;
    let v = Telegram::render(n);
    assert_eq!(v["parse_mode"], "HTML");
    assert_eq!(v["protect_content"], true);
    assert_eq!(v["disable_web_page_preview"], true);
    let kb = &v["reply_markup"]["inline_keyboard"];
    assert_eq!(kb.as_array().unwrap().len(), 1, "one row");
    let b = &kb[0][0];
    assert_eq!(b["url"], format!("{BASE}/go#{TOKEN}"));
    // a URL button: never a callback a chat could answer with
    assert!(b.get("callback_data").is_none() && b.get("switch_inline_query").is_none());
    // the text names the verb first and says the chat decides nothing
    let text = v["text"].as_str().unwrap();
    assert!(
        text.contains("<b>Approve or deny: guard override</b>"),
        "{text}"
    );
    assert!(text.contains("Nothing in a chat approves"));
    // no button at all when there is no address
    assert!(Telegram::render(&cases()[2].1)
        .get("reply_markup")
        .is_none());
    // a reply is plain text: no parse mode, so nothing in it is markup
    let r = Telegram::render(&Notice::reply("a <b>bold</b> & claim"));
    assert!(r.get("parse_mode").is_none() && r["text"] == "a <b>bold</b> & claim");
}

/// A notice whose every field holds markup and lookalike characters.
fn hostile() -> Notice {
    let nasty = "<b>x</b> & _y_ *z* `c` [a](https://evil.example) @everyone \u{1f525} </code>";
    let mut n = approval();
    n.title = format!("Approve or deny: {nasty}");
    n.summary = nasty.into();
    n.box_name = Some(nasty.into());
    n.asked_by = Some(nasty.into());
    n.details = vec![Fact {
        label: nasty.into(),
        value: nasty.into(),
    }];
    n.reference = Some("R<1>&".into());
    let a = n.action_for(Some(BASE), Some(TOKEN));
    n.with_action(a)
}

#[test]
fn every_channel_escapes_names_with_markup_and_emoji() {
    let n = hostile();
    // Telegram HTML: only our own tags survive, balanced
    let tg = Telegram::render(&n)["text"].as_str().unwrap().to_string();
    assert!(
        !tg.contains("<b>x</b>") && tg.contains("&lt;b&gt;x&lt;/b&gt;") && tg.contains("&amp;"),
        "{tg}"
    );
    assert!(tg.contains("\u{1f525}"), "{tg}");
    assert_eq!(tg.matches("<b>").count(), tg.matches("</b>").count());
    assert_eq!(tg.matches("<code>").count(), tg.matches("</code>").count());
    assert_eq!(tg.matches("<i>").count(), tg.matches("</i>").count());
    // Slack: untrusted values are plain_text, and the fallback is escaped
    let sl = Slack::render(&n);
    assert!(sl["text"].as_str().unwrap().contains("&lt;b&gt;"));
    for b in sl["blocks"].as_array().unwrap() {
        if let Some(t) = b.get("text") {
            assert_eq!(t["type"], "plain_text", "{b}");
        }
        for f in b["fields"].as_array().into_iter().flatten() {
            assert_eq!(f["type"], "plain_text");
        }
    }
    // Discord: markdown is escaped and nobody is pinged
    let dc = Discord::render(&n);
    let d = dc["embeds"][0]["description"].as_str().unwrap();
    assert!(
        d.contains("\\_y\\_") && d.contains("\\*z\\*") && d.contains("\\@everyone"),
        "{d}"
    );
    assert!(!d.contains("[a](https://evil"), "{d}");
    assert_eq!(dc["allowed_mentions"]["parse"], serde_json::json!([]));
    // Teams: markdown escaped
    let tm = Teams::render(&n)["attachments"][0]["content"]["body"][1]["text"]
        .as_str()
        .unwrap()
        .to_string();
    assert!(tm.contains("\\_y\\_"), "{tm}");
    // email HTML: escaped, our link the only anchor
    let em = Email::render(&n).html;
    assert!(
        !em.contains("<b>x</b>") && em.matches("<a ").count() == 1,
        "{em}"
    );
    // SMS stays plain ASCII
    let s = Sms::render(&n);
    assert!(s.is_ascii(), "{s}");
}

#[test]
fn sms_fits_one_part_and_push_stays_short() {
    for (case, n) in cases() {
        let s = Sms::render(&n);
        assert!(s.is_ascii(), "{case}: {s}");
        assert!(
            s.chars().count() <= SMS_PART,
            "{case} is {} characters: {s}",
            s.chars().count()
        );
        let p = Push::render(&n);
        assert!(
            p.title.chars().count() <= 60 && p.body.chars().count() <= 160,
            "{case}"
        );
    }
    // a long title is cut, never the link
    let mut n = approval();
    n.title = "Approve or deny: ".to_string() + &"very long words ".repeat(30);
    let a = n.action_for(Some(BASE), Some(TOKEN));
    let s = Sms::render(&n.with_action(a));
    assert!(
        s.chars().count() <= SMS_PART && s.contains(&format!("{BASE}/go#{TOKEN}")),
        "{s}"
    );
    assert_eq!(ascii_fold("a \u{2192} b \u{00b7} \u{e9}"), "a > b - ?");
}

#[test]
fn no_secret_value_or_long_agent_output_leaves_in_any_channel() {
    // built from parts so the file itself never holds a key-shaped word
    let sentinel = format!("{}-{}-{}", "sk", "ant-api03", "SENTINELSENTINELSENTINEL");
    let sentinel = sentinel.as_str();
    let mut n = approval();
    n.summary = format!(
        "{} the key is {sentinel} and TOKEN=abc123",
        "x ".repeat(2000)
    );
    n.why = Some(format!("API_KEY={sentinel}"));
    n.details = vec![Fact {
        label: "Value".into(),
        value: sentinel.into(),
    }];
    let a = n.action_for(Some(BASE), Some(TOKEN));
    let n = n.with_action(a);
    for (ch, s) in renderings(&n) {
        assert!(
            !s.contains("SENTINELSENTINEL") && !s.contains("abc123"),
            "{ch}:\n{s}"
        );
        assert!(s.chars().count() < 8_000, "{ch} is long");
    }
    // the one-time link is never stored with the notice or the alert, and never printed
    let stored = serde_json::to_string(&n).unwrap();
    assert!(!stored.contains(TOKEN), "{stored}");
    let mut alert = crate::notify::test_alert(1);
    alert.reach.tokens.insert("ada".into(), TOKEN.into());
    alert.reach.base = Some(BASE.into());
    assert!(!serde_json::to_string(&alert).unwrap().contains(TOKEN));
    assert!(
        !format!("{alert:?}").contains(TOKEN),
        "Debug never shows a token"
    );
}

#[test]
fn every_catalogue_key_a_notice_uses_exists() {
    let src = [include_str!("mod.rs"), include_str!("render.rs")].join("\n");
    let keys: Vec<&str> = crate::messages_notice::EN.iter().map(|(k, _)| *k).collect();
    let mut i = 0;
    while let Some(j) = src[i..].find("\"notice.") {
        let start = i + j + 1;
        let end = start + src[start..].find('"').unwrap();
        let key = &src[start..end];
        assert!(keys.contains(&key), "{key} is not in the catalogue");
        i = end;
    }
}

#[test]
fn a_span_reads_in_words() {
    assert_eq!(span(30_000), "less than a minute");
    assert_eq!(span(5 * 60_000), "5 min");
    assert_eq!(span(125 * 60_000), "2 h 5 min");
    assert_eq!(span(72 * 3_600_000), "3 d");
}

/// The code of a file before its tests, without comment lines.
fn code_of(src: &str) -> String {
    let code = src.split("#[cfg(test)]").next().unwrap_or("");
    code.lines()
        .filter(|l| !l.trim_start().starts_with("//"))
        .collect::<Vec<_>>()
        .join("\n")
}

/// A channel adapter sends what `notice::render` made and builds no message text of its own: no alert title or body
/// pasted into a request, no message body shape of its own.
#[test]
fn no_channel_adapter_formats_a_message_itself() {
    let files: &[(&str, &str, &[&str])] = &[
        (
            "notify.rs",
            include_str!("../notify.rs"),
            &["\"text\":", "a.title)", "a.body)", "&a.title", "&a.body"],
        ),
        (
            "telegram.rs",
            include_str!("../telegram.rs"),
            &["\"text\":", "parse_mode"],
        ),
        (
            "channels/chat.rs",
            include_str!("../channels/chat.rs"),
            &[
                "\"content\":",
                "TextBlock",
                "a.title",
                "a.body",
                "\"embeds\"",
            ],
        ),
        (
            "channels/sms.rs",
            include_str!("../channels/sms.rs"),
            &["[Oz Box]", "a.title", "a.body"],
        ),
        (
            "channels/push.rs",
            include_str!("../channels/push.rs"),
            &["a.title", "a.body"],
        ),
        (
            "channels/mail.rs",
            include_str!("../channels/mail.rs"),
            &["[Oz Box]", "a.title", "a.body"],
        ),
        (
            "channels/routing.rs",
            include_str!("../channels/routing.rs"),
            &["&a.title", "&a.body"],
        ),
        (
            "chat/slack.rs",
            include_str!("../chat/slack.rs"),
            &["a.title", "a.body"],
        ),
        (
            "chat/whatsapp.rs",
            include_str!("../chat/whatsapp.rs"),
            &["a.title", "a.body"],
        ),
    ];
    for (name, src, banned) in files {
        let code = code_of(src);
        for b in *banned {
            assert!(
                !code.contains(b),
                "{name} formats a message itself ({b}): render it through notice::render"
            );
        }
    }
    // and the chat gateway's agent question goes out as a notice, not a sentence of its own
    let chat_routes = code_of(include_str!("../serve/chat_routes.rs"));
    assert!(
        chat_routes.contains("NoticeKind::AgentAsks") && !chat_routes.contains("\"chat.approval")
    );
    let areq = code_of(include_str!("../serve/approval_requests.rs"));
    assert!(areq.contains("NoticeKind::ApprovalRequest"));
}
