//! Email through the owner's own account: Resend, Postmark, SendGrid, Amazon SES or any SMTP server. One message goes
//! to a list of recipients; addresses on the unsubscribed list are removed first, and the footer of every message
//! says why it was sent and how to stop it.
//!
//! Provider documentation:
//! * Resend: <https://resend.com/docs/api-reference/emails/send-email>
//! * Postmark: <https://postmarkapp.com/developer/api/email-api>
//! * SendGrid: <https://www.twilio.com/docs/sendgrid/api-reference/mail-send/mail-send>
//! * Amazon SES (v2 CLI): <https://docs.aws.amazon.com/cli/latest/reference/sesv2/send-email.html>
//! * SMTP: RFC 5321 with STARTTLS (RFC 3207) or implicit TLS (RFC 8314).

use ozbox_core::CommandSpec;
use serde_json::{json, Value};

use super::{http_detail, one_line, sms::aws_failure, Ctx, SendResult};
use crate::netguard::{Guard, HttpRequest};
use crate::notify_config::{EmailProviderKind, SmtpSecurity};
use crate::settings::EmailConfig;

pub const FOOTER: &str = "You get this because email alerts are on in the Oz Box dashboard (Settings > Apps and alerts). Turn them off there.";

/// The recipients that may be mailed: not on the unsubscribed list, no repeats.
pub fn allowed(cfg: &EmailConfig, to: &[String]) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    for t in to {
        let lower = t.to_ascii_lowercase();
        if cfg
            .unsubscribed
            .iter()
            .any(|u| u.eq_ignore_ascii_case(&lower))
        {
            continue;
        }
        if !out.iter().any(|o| o.eq_ignore_ascii_case(&lower)) {
            out.push(t.clone());
        }
    }
    out
}

pub fn subject(title: &str) -> String {
    format!("[Oz Box] {}", one_line(title))
}

pub fn body(text: &str) -> String {
    format!("{text}\n\n{FOOTER}")
}

pub struct Mail<'a> {
    pub cfg: &'a EmailConfig,
    pub to: &'a [String],
    pub subject: &'a str,
    pub text: &'a str,
    pub now_secs: u64,
}

pub fn send(ctx: &Ctx, m: &Mail<'_>) -> SendResult {
    let cfg = m.cfg;
    if cfg.from.is_empty() {
        return Err("the sender address is not set".into());
    }
    let to = allowed(cfg, m.to);
    if to.is_empty() {
        return Err("every recipient has unsubscribed or none is set".into());
    }
    match cfg.provider {
        EmailProviderKind::Resend => {
            let key = ctx.need("email-api-key", "email API key")?;
            ctx.call(resend(&key, cfg, &to, m.subject, m.text), super::by_status)
        }
        EmailProviderKind::Postmark => {
            let key = ctx.need("email-api-key", "Postmark server token")?;
            ctx.call(postmark(&key, cfg, &to, m.subject, m.text), postmark_result)
        }
        EmailProviderKind::Sendgrid => {
            let key = ctx.need("email-api-key", "SendGrid API key")?;
            ctx.call(sendgrid(&key, cfg, &to, m.subject, m.text), sendgrid_result)
        }
        EmailProviderKind::Ses => {
            let cmd = ses_command(ctx.aws_profile.as_deref(), cfg, &to, m.subject, m.text);
            match ctx.runner.run(&cmd) {
                Ok(o) if o.status == Some(0) => ses_result(&o.stdout),
                Ok(o) => Err(aws_failure(&o.stderr)),
                Err(_) => Err("the aws command could not be run".into()),
            }
        }
        EmailProviderKind::Smtp => smtp(ctx, cfg, &to, m),
    }
}

// ---------- Resend ----------

pub fn resend(
    key: &str,
    cfg: &EmailConfig,
    to: &[String],
    subject: &str,
    text: &str,
) -> HttpRequest {
    let mut v = json!({ "from": cfg.from, "to": to, "subject": subject, "text": body(text) });
    if !cfg.reply_to.is_empty() {
        v["reply_to"] = json!(cfg.reply_to);
    }
    HttpRequest::new("POST", "https://api.resend.com/emails", Guard::Public)
        .header("Authorization", format!("Bearer {key}"))
        .json(&v)
}

// ---------- Postmark ----------

pub fn postmark(
    key: &str,
    cfg: &EmailConfig,
    to: &[String],
    subject: &str,
    text: &str,
) -> HttpRequest {
    let mut v = json!({
        "From": cfg.from,
        "To": to.join(","),
        "Subject": subject,
        "TextBody": body(text),
        "MessageStream": "outbound",
    });
    if !cfg.reply_to.is_empty() {
        v["ReplyTo"] = json!(cfg.reply_to);
    }
    HttpRequest::new("POST", "https://api.postmarkapp.com/email", Guard::Public)
        .header("X-Postmark-Server-Token", key)
        .header("Accept", "application/json")
        .json(&v)
}

/// Postmark answers `ErrorCode: 0` when it accepted the message.
pub fn postmark_result(status: u16, body: &str) -> SendResult {
    let v: Value = serde_json::from_str(body).unwrap_or(Value::Null);
    match (status, v["ErrorCode"].as_i64()) {
        (200, Some(0)) => Ok("sent".into()),
        (401, _) => Err("Postmark refused the server token".into()),
        (422, Some(300)) => Err("Postmark says an address is not valid".into()),
        (422, Some(400 | 401)) => Err(
            "Postmark does not know that sender: add and confirm it as a sender signature".into(),
        ),
        (422, Some(402 | 403)) => Err("Postmark could not read the message".into()),
        (422, Some(405)) => Err("the Postmark account cannot send mail yet".into()),
        (422, Some(406)) => {
            Err("Postmark will not send to that address: it was marked inactive".into())
        }
        (s, _) => Err(http_detail(s)),
    }
}

// ---------- SendGrid ----------

pub fn sendgrid(
    key: &str,
    cfg: &EmailConfig,
    to: &[String],
    subject: &str,
    text: &str,
) -> HttpRequest {
    let mut v = json!({
        "personalizations": [{ "to": to.iter().map(|t| json!({ "email": t })).collect::<Vec<_>>() }],
        "from": { "email": cfg.from },
        "subject": subject,
        "content": [{ "type": "text/plain", "value": body(text) }],
    });
    if !cfg.reply_to.is_empty() {
        v["reply_to"] = json!({ "email": cfg.reply_to });
    }
    HttpRequest::new(
        "POST",
        "https://api.sendgrid.com/v3/mail/send",
        Guard::Public,
    )
    .header("Authorization", format!("Bearer {key}"))
    .json(&v)
}

/// SendGrid answers 202 with an empty body.
pub fn sendgrid_result(status: u16, _body: &str) -> SendResult {
    match status {
        200..=299 => Ok("sent".into()),
        401 | 403 => Err("SendGrid refused the API key, or the sender is not verified".into()),
        s => Err(http_detail(s)),
    }
}

// ---------- Amazon SES ----------

pub fn ses_command(
    profile: Option<&str>,
    cfg: &EmailConfig,
    to: &[String],
    subject: &str,
    text: &str,
) -> CommandSpec {
    let content = json!({
        "Simple": {
            "Subject": { "Data": subject, "Charset": "UTF-8" },
            "Body": { "Text": { "Data": body(text), "Charset": "UTF-8" } }
        }
    });
    let dest = json!({ "ToAddresses": to });
    let mut c = CommandSpec::new("aws").args([
        "sesv2",
        "send-email",
        "--from-email-address",
        &cfg.from,
        "--destination",
        &dest.to_string(),
        "--content",
        &content.to_string(),
    ]);
    if !cfg.reply_to.is_empty() {
        c = c.args(["--reply-to-addresses", &cfg.reply_to]);
    }
    if let Some(r) = &cfg.region {
        c = c.args(["--region", r]);
    }
    if let Some(p) = profile {
        c = c.args(["--profile", p]);
    }
    c.args(["--output", "json"])
}

pub fn ses_result(stdout: &str) -> SendResult {
    let v: Value = serde_json::from_str(stdout).unwrap_or(Value::Null);
    if v["MessageId"].is_string() {
        Ok("sent".into())
    } else {
        Err("Amazon SES answered without a message id".into())
    }
}

// ---------- SMTP ----------

fn smtp(ctx: &Ctx, cfg: &EmailConfig, to: &[String], m: &Mail<'_>) -> SendResult {
    let c = &cfg.smtp;
    if c.host.is_empty() {
        return Err("the SMTP server is not set".into());
    }
    let password = if c.username.is_empty() {
        String::new()
    } else {
        ctx.need("smtp-password", "SMTP password")?
    };
    let port = if c.port == 0 {
        c.security.default_port()
    } else {
        c.port
    };
    let domain = cfg.from.split_once('@').map_or("localhost", |(_, d)| d);
    let seed = super::smtp_seed(m.now_secs, m.subject);
    let message = super::smtp::build_message(&super::smtp::Message {
        from: &cfg.from,
        reply_to: &cfg.reply_to,
        to,
        subject: m.subject,
        text: &body(m.text),
        now_secs: m.now_secs,
        id_seed: &seed,
        domain,
    });
    let plan = super::smtp::Plan {
        security: c.security,
        helo: domain,
        username: &c.username,
        password: &password,
        from: &cfg.from,
        to,
        message: &message,
    };
    let _: SmtpSecurity = c.security;
    super::smtp::send_over_network(&c.host, port, &plan)
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use crate::channels::testing::rig;
    use crate::secrets::SecretStore;
    use ozbox_core::Output;

    fn cfg(kind: EmailProviderKind) -> EmailConfig {
        EmailConfig {
            enabled: true,
            from: "alerts@example.com".into(),
            to: vec!["me@example.com".into()],
            provider: kind,
            reply_to: "help@example.com".into(),
            ..Default::default()
        }
    }

    fn mail<'a>(c: &'a EmailConfig, to: &'a [String]) -> Mail<'a> {
        Mail {
            cfg: c,
            to,
            subject: "[Oz Box] Test",
            text: "hello",
            now_secs: 1,
        }
    }

    fn json_body(r: &HttpRequest) -> Value {
        serde_json::from_slice(r.body.as_ref().unwrap()).unwrap()
    }

    #[test]
    fn unsubscribed_addresses_are_never_mailed_and_repeats_collapse() {
        let mut c = cfg(EmailProviderKind::Resend);
        c.unsubscribed = vec!["Gone@Example.com".into()];
        let to = vec![
            "gone@example.com".to_string(),
            "a@example.com".into(),
            "A@example.com".into(),
        ];
        assert_eq!(allowed(&c, &to), ["a@example.com"]);
        let g = rig();
        g.secrets.set("email-api-key", "k").unwrap();
        let only = vec!["gone@example.com".to_string()];
        assert!(send(&g.ctx, &mail(&c, &only))
            .unwrap_err()
            .contains("unsubscribed"));
        assert!(g.http.requests().is_empty());
    }

    #[test]
    fn resend_postmark_and_sendgrid_requests_follow_their_documentation() {
        let to = vec!["me@example.com".to_string()];
        let c = cfg(EmailProviderKind::Resend);
        let r = resend("KEY", &c, &to, "S", "t");
        assert_eq!(r.url, "https://api.resend.com/emails");
        let v = json_body(&r);
        assert_eq!(v["reply_to"], "help@example.com");
        assert!(v["text"].as_str().unwrap().ends_with(FOOTER));

        let r = postmark("TOK", &c, &to, "S", "t");
        assert_eq!(r.url, "https://api.postmarkapp.com/email");
        assert!(r
            .headers
            .iter()
            .any(|(k, v)| k == "X-Postmark-Server-Token" && v == "TOK"));
        let v = json_body(&r);
        assert_eq!(
            (v["From"].as_str(), v["To"].as_str(), v["ReplyTo"].as_str()),
            (
                Some("alerts@example.com"),
                Some("me@example.com"),
                Some("help@example.com")
            )
        );

        let r = sendgrid("SG", &c, &to, "S", "t");
        assert_eq!(r.url, "https://api.sendgrid.com/v3/mail/send");
        let v = json_body(&r);
        assert_eq!(v["personalizations"][0]["to"][0]["email"], "me@example.com");
        assert_eq!(v["content"][0]["type"], "text/plain");
        assert_eq!(v["reply_to"]["email"], "help@example.com");
    }

    #[test]
    fn every_email_request_goes_through_the_guarded_client_over_https() {
        let to = vec!["me@example.com".to_string()];
        let c = cfg(EmailProviderKind::Resend);
        for r in [
            resend("K", &c, &to, "S", "t"),
            postmark("K", &c, &to, "S", "t"),
            sendgrid("K", &c, &to, "S", "t"),
        ] {
            assert_eq!(r.guard, Guard::Public);
            assert!(r.url.starts_with("https://"));
            assert!(!r.url.contains('K'), "no key in a URL");
        }
    }

    #[test]
    fn provider_answers_are_read_in_words() {
        assert_eq!(
            postmark_result(
                200,
                r#"{"To":"a@example.com","SubmittedAt":"2026-01-01T00:00:00Z","MessageID":"x","ErrorCode":0,"Message":"OK"}"#
            ),
            Ok("sent".into())
        );
        assert!(postmark_result(
            422,
            r#"{"ErrorCode":300,"Message":"Invalid email request"}"#
        )
        .unwrap_err()
        .contains("not valid"));
        assert!(postmark_result(401, "{}").unwrap_err().contains("token"));
        assert_eq!(sendgrid_result(202, ""), Ok("sent".into()));
        assert!(sendgrid_result(403, r#"{"errors":[{"message":"The from address does not match a verified Sender Identity"}]}"#).unwrap_err().contains("verified"));
        assert!(crate::channels::retryable(
            &sendgrid_result(503, "").unwrap_err()
        ));
    }

    #[test]
    fn ses_uses_json_arguments_so_text_cannot_become_options() {
        let g = rig();
        let mut c = cfg(EmailProviderKind::Ses);
        c.region = Some("eu-west-1".into());
        let to = vec!["me@example.com".to_string()];
        g.runner.reply(Output {
            status: Some(0),
            stdout: r#"{"MessageId":"0100"}"#.into(),
            stderr: String::new(),
        });
        let mut m = mail(&c, &to);
        m.text = "--profile evil";
        assert_eq!(send(&g.ctx, &m), Ok("sent".into()));
        let call = &g.runner.calls()[0];
        assert_eq!(&call.args[..2], ["sesv2", "send-email"]);
        assert!(call.args.windows(2).any(|w| w == ["--region", "eu-west-1"]));
        assert!(call
            .args
            .windows(2)
            .any(|w| w[0] == "--reply-to-addresses" && w[1] == "help@example.com"));
        let content = call
            .args
            .iter()
            .find(|a| a.starts_with("{\"Simple\""))
            .unwrap();
        assert!(
            content.contains("--profile evil"),
            "inside the JSON, never its own argument"
        );
        assert!(!call.args.contains(&"--profile".to_string()));
        g.runner.reply(Output {
            status: Some(254),
            stdout: String::new(),
            stderr: "AccessDenied for arn:aws:iam::123456789012:user/x".into(),
        });
        let e = send(&g.ctx, &m).unwrap_err();
        assert!(e.contains("not allowed") && !e.contains("123456789012"));
    }

    #[test]
    fn a_missing_key_or_sender_is_said_without_sending() {
        let g = rig();
        let to = vec!["me@example.com".to_string()];
        let c = cfg(EmailProviderKind::Postmark);
        assert!(send(&g.ctx, &mail(&c, &to))
            .unwrap_err()
            .contains("Postmark"));
        let mut c = cfg(EmailProviderKind::Resend);
        c.from.clear();
        assert!(send(&g.ctx, &mail(&c, &to)).unwrap_err().contains("sender"));
        assert!(g.http.requests().is_empty());
    }

    #[test]
    fn an_smtp_server_on_a_private_address_is_refused_and_the_password_stays_out_of_the_error() {
        let g = rig();
        g.secrets.set("smtp-password", "SENTINELPASSWORD").unwrap();
        let mut c = cfg(EmailProviderKind::Smtp);
        c.smtp.host = "127.0.0.1".into();
        c.smtp.username = "alerts".into();
        let to = vec!["me@example.com".to_string()];
        let e = send(&g.ctx, &mail(&c, &to)).unwrap_err();
        assert!(
            e.contains("private or reserved")
                && !e.contains("SENTINEL")
                && !e.contains("127.0.0.1")
        );
        c.smtp.host.clear();
        assert!(send(&g.ctx, &mail(&c, &to))
            .unwrap_err()
            .contains("not set"));
    }
}
