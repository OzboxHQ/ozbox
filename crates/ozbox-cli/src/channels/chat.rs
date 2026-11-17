//! Chat apps: WhatsApp (Meta's Cloud API), Discord and Microsoft Teams, each the owner's own account.
//!
//! * WhatsApp Cloud API, send messages: <https://developers.facebook.com/docs/whatsapp/cloud-api/reference/messages>
//!   and templates: <https://developers.facebook.com/docs/whatsapp/cloud-api/guides/send-message-templates>.
//!   A business may only start a conversation with a **template** message the owner has created and Meta has approved,
//!   so an alert is sent as the parameters of that template, never as free text.
//! * Discord, execute webhook: <https://discord.com/developers/docs/resources/webhook#execute-webhook>
//! * Microsoft Teams, incoming webhook / Workflows: <https://learn.microsoft.com/en-us/microsoftteams/platform/webhooks-and-connectors/how-to/add-incoming-webhook>
//!   (a Workflows address expects an Adaptive Card inside a `message` envelope).
//!
//! The Discord and Teams addresses are secrets (anyone holding one can post), saved write-only; only the address of a
//! genuine Discord or Microsoft host is accepted.

use serde_json::{json, Value};

use super::{clip, http_detail, one_line, Ctx, SendResult};
use crate::netguard::{Guard, HttpRequest};
use crate::notice::render::{Discord, Renderer, Teams, WhatsappTemplate};
use crate::notice::Notice;
use crate::notify_config::{e164_ok, WhatsappConfig};

/// The Graph API version the request is written against.
pub const GRAPH_VERSION: &str = "v21.0";

// ---------- WhatsApp ----------

/// A template parameter may not hold line breaks, tabs or runs of spaces, and is at most 1024 characters.
fn template_param(s: &str) -> String {
    let t = clip(&one_line(s), 900);
    if t.is_empty() {
        "-".into()
    } else {
        t
    }
}

pub fn whatsapp_request(
    token: &str,
    cfg: &WhatsappConfig,
    to: &str,
    title: &str,
    body: &str,
) -> HttpRequest {
    HttpRequest::new(
        "POST",
        format!(
            "https://graph.facebook.com/{GRAPH_VERSION}/{}/messages",
            cfg.phone_number_id
        ),
        Guard::Public,
    )
    .header("Authorization", format!("Bearer {token}"))
    .json(&json!({
        "messaging_product": "whatsapp",
        "to": to.trim_start_matches('+'),
        "type": "template",
        "template": {
            "name": cfg.template,
            "language": { "code": cfg.language },
            "components": [{
                "type": "body",
                "parameters": [
                    { "type": "text", "text": template_param(title) },
                    { "type": "text", "text": template_param(body) },
                ],
            }],
        },
    }))
}

/// Meta's error codes, in words. The body is never echoed: it can hold the recipient's number.
pub fn whatsapp_result(status: u16, body: &str) -> SendResult {
    let v: Value = serde_json::from_str(body).unwrap_or(Value::Null);
    if (200..300).contains(&status) && v["messages"][0]["id"].is_string() {
        return Ok("sent".into());
    }
    match v["error"]["code"].as_i64() {
        Some(190) => Err("WhatsApp refused the access token (it may have expired)".into()),
        Some(131_030) => Err("that number is not on the allowed list of the WhatsApp test account".into()),
        Some(131_026) => Err("WhatsApp could not deliver to that number".into()),
        Some(131_047 | 131_051) => Err("WhatsApp only allows an approved template to start a conversation".into()),
        Some(132_000 | 132_001 | 132_005 | 132_012) => Err(
            "WhatsApp does not accept the template: check its name, language and that it takes two text parameters"
                .into(),
        ),
        Some(130_429 | 80_007) => Err("WhatsApp is rate limiting this account (try again)".into()),
        Some(100) => Err("WhatsApp refused the request: check the phone number id".into()),
        _ => Err(http_detail(status)),
    }
}

pub fn whatsapp(ctx: &Ctx, cfg: &WhatsappConfig, to: &str, n: &Notice) -> SendResult {
    let token = ctx.need("whatsapp-token", "WhatsApp access token")?;
    if cfg.phone_number_id.is_empty() || cfg.template.is_empty() || cfg.language.is_empty() {
        return Err("the phone number id, the template or its language is not set".into());
    }
    if !e164_ok(to) {
        return Err("the WhatsApp number is not in international format".into());
    }
    let (title, body) = WhatsappTemplate::render(n);
    ctx.call(
        whatsapp_request(&token, cfg, to, &title, &body),
        whatsapp_result,
    )
}

// ---------- Discord ----------

/// Only Discord's own hosts.
pub fn discord_host_ok(url: &str) -> bool {
    host_of(url).is_some_and(|h| {
        [
            "discord.com",
            "discordapp.com",
            "ptb.discord.com",
            "canary.discord.com",
        ]
        .contains(&h.as_str())
    }) && url.contains("/api/webhooks/")
}

/// The message is the notice's Discord rendering; a message from an alert never pings anyone by itself.
pub fn discord_request(url: &str, n: &Notice) -> HttpRequest {
    HttpRequest::new("POST", url, Guard::Public).json(&Discord::render(n))
}

pub fn discord_result(status: u16, _body: &str) -> SendResult {
    match status {
        200..=299 => Ok("sent".into()),
        401 | 404 => Err("Discord does not know that webhook: it may have been deleted".into()),
        429 => Err(http_detail(429)),
        s => Err(http_detail(s)),
    }
}

pub fn discord(ctx: &Ctx, n: &Notice) -> SendResult {
    let url = ctx.need("discord-webhook-url", "Discord webhook address")?;
    ctx.call(discord_request(&url, n), discord_result)
}

// ---------- Microsoft Teams ----------

pub fn teams_host_ok(url: &str) -> bool {
    host_of(url).is_some_and(|h| {
        [
            ".webhook.office.com",
            ".logic.azure.com",
            ".powerplatform.com",
            ".environment.api.powerplatform.com",
        ]
        .iter()
        .any(|s| h.ends_with(s))
    })
}

/// The message is the notice's Adaptive Card.
pub fn teams_request(url: &str, n: &Notice) -> HttpRequest {
    HttpRequest::new("POST", url, Guard::Public).json(&Teams::render(n))
}

pub fn teams_result(status: u16, _body: &str) -> SendResult {
    match status {
        200..=299 => Ok("sent".into()),
        400 | 404 => Err("Teams does not accept that webhook: check that it is a Workflows or incoming webhook address".into()),
        s => Err(http_detail(s)),
    }
}

pub fn teams(ctx: &Ctx, n: &Notice) -> SendResult {
    let url = ctx.need("teams-webhook-url", "Teams webhook address")?;
    ctx.call(teams_request(&url, n), teams_result)
}

fn host_of(url: &str) -> Option<String> {
    let rest = url.strip_prefix("https://")?;
    let auth = rest.split(['/', '?', '#']).next()?;
    if auth.contains('@') || auth.contains(':') {
        return None;
    }
    Some(auth.to_ascii_lowercase())
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use crate::channels::testing::rig;
    use crate::notify::test_alert;
    use crate::secrets::SecretStore;

    fn wa() -> WhatsappConfig {
        WhatsappConfig {
            enabled: true,
            phone_number_id: "106540352242922".into(),
            template: "ozbox_alert".into(),
            language: "en_US".into(),
        }
    }

    fn json_body(r: &HttpRequest) -> Value {
        serde_json::from_slice(r.body.as_ref().unwrap()).unwrap()
    }

    #[test]
    fn whatsapp_sends_a_template_message_never_free_text() {
        let r = whatsapp_request(
            "TOK",
            &wa(),
            "+2348012345678",
            "Disk\nfull",
            "line one\n\n   line two",
        );
        assert_eq!(
            r.url,
            "https://graph.facebook.com/v21.0/106540352242922/messages"
        );
        assert!(r
            .headers
            .iter()
            .any(|(k, v)| k == "Authorization" && v == "Bearer TOK"));
        let v = json_body(&r);
        assert_eq!(v["type"], "template");
        assert_eq!(v["to"], "2348012345678");
        assert_eq!(v["template"]["name"], "ozbox_alert");
        assert_eq!(v["template"]["language"]["code"], "en_US");
        let p = &v["template"]["components"][0]["parameters"];
        assert_eq!(p[0]["text"], "Disk full");
        assert_eq!(p[1]["text"], "line one line two");
        assert!(v.get("text").is_none());
    }

    #[test]
    fn whatsapp_answers_are_read_in_words_without_echoing_the_body() {
        assert_eq!(
            whatsapp_result(
                200,
                r#"{"messaging_product":"whatsapp","contacts":[{"input":"2348012345678","wa_id":"2348012345678"}],"messages":[{"id":"wamid.HBg"}]}"#
            ),
            Ok("sent".into())
        );
        let e = whatsapp_result(401, r#"{"error":{"message":"Error validating access token for 2348012345678","type":"OAuthException","code":190}}"#).unwrap_err();
        assert!(e.contains("token") && !e.contains("2348"));
        assert!(whatsapp_result(400, r#"{"error":{"code":132001}}"#)
            .unwrap_err()
            .contains("template"));
        assert!(whatsapp_result(400, r#"{"error":{"code":131047}}"#)
            .unwrap_err()
            .contains("template"));
        assert!(crate::channels::retryable(
            &whatsapp_result(503, "").unwrap_err()
        ));
    }

    #[test]
    fn whatsapp_needs_its_settings_and_a_valid_number_before_it_sends() {
        let g = rig();
        let a = test_alert(1).notice_for(None);
        assert!(whatsapp(&g.ctx, &wa(), "+2348012345678", &a)
            .unwrap_err()
            .contains("token"));
        g.secrets.set("whatsapp-token", "T").unwrap();
        let mut c = wa();
        c.template.clear();
        assert!(whatsapp(&g.ctx, &c, "+2348012345678", &a)
            .unwrap_err()
            .contains("template"));
        assert!(whatsapp(&g.ctx, &wa(), "08012345678", &a)
            .unwrap_err()
            .contains("international"));
        assert!(g.http.requests().is_empty());
    }

    #[test]
    fn discord_never_pings_and_only_discord_hosts_are_accepted() {
        let a = test_alert(1).notice_for(None);
        let r = discord_request("https://discord.com/api/webhooks/1/abc", &a);
        let v = json_body(&r);
        assert_eq!(v["allowed_mentions"]["parse"], json!([]));
        assert!(v["embeds"][0]["title"]
            .as_str()
            .unwrap()
            .contains("Test alert"));
        assert!(discord_host_ok("https://discord.com/api/webhooks/1/abc"));
        assert!(discord_host_ok("https://discordapp.com/api/webhooks/1/abc"));
        for bad in [
            "https://evil.example/api/webhooks/1/abc",
            "http://discord.com/api/webhooks/1/abc",
            "https://discord.com.evil.example/api/webhooks/1/a",
            "https://discord.com@evil.example/api/webhooks/1/a",
            "https://discord.com/other",
            "https://169.254.169.254/api/webhooks/1/a",
        ] {
            assert!(!discord_host_ok(bad), "{bad}");
        }
        assert_eq!(discord_result(204, ""), Ok("sent".into()));
        assert!(discord_result(404, "").unwrap_err().contains("deleted"));
        assert!(crate::channels::retryable(
            &discord_result(429, "").unwrap_err()
        ));
    }

    #[test]
    fn teams_gets_an_adaptive_card_in_a_message_envelope() {
        let a = test_alert(1).notice_for(None);
        let r = teams_request("https://prod-12.westus.logic.azure.com/workflows/abc", &a);
        let v = json_body(&r);
        assert_eq!(v["type"], "message");
        assert_eq!(
            v["attachments"][0]["contentType"],
            "application/vnd.microsoft.card.adaptive"
        );
        assert_eq!(v["attachments"][0]["content"]["type"], "AdaptiveCard");
        assert_eq!(
            v["attachments"][0]["content"]["body"][0]["text"],
            "Test alert from Oz Box"
        );
        assert!(teams_host_ok(
            "https://contoso.webhook.office.com/webhookb2/x"
        ));
        assert!(teams_host_ok(
            "https://prod-12.westus.logic.azure.com/workflows/abc"
        ));
        assert!(teams_host_ok(
            "https://x.environment.api.powerplatform.com/powerautomate/x"
        ));
        assert!(!teams_host_ok("https://logic.azure.com.evil.example/x"));
        assert!(!teams_host_ok("https://evil.example/x"));
        assert_eq!(teams_result(202, ""), Ok("sent".into()));
        assert!(teams_result(400, "").is_err());
    }

    #[test]
    fn each_chat_channel_goes_through_the_guarded_client_and_keeps_secrets_out_of_errors() {
        let g = rig();
        let a = test_alert(1).notice_for(None);
        g.secrets
            .set(
                "discord-webhook-url",
                "https://discord.com/api/webhooks/1/SENTINELTOKEN",
            )
            .unwrap();
        g.secrets
            .set(
                "teams-webhook-url",
                "https://x.logic.azure.com/workflows/SENTINELTOKEN",
            )
            .unwrap();
        g.secrets.set("whatsapp-token", "SENTINELTOKEN").unwrap();
        for _ in 0..3 {
            g.http.reply(500, "SENTINELTOKEN");
        }
        let errs = [
            discord(&g.ctx, &a).unwrap_err(),
            teams(&g.ctx, &a).unwrap_err(),
            whatsapp(&g.ctx, &wa(), "+2348012345678", &a).unwrap_err(),
        ];
        assert!(errs.iter().all(|e| !e.contains("SENTINEL")));
        assert!(g.http.requests().iter().all(|r| r.guard == Guard::Public));
    }
}
