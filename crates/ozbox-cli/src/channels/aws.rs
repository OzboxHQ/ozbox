//! Sending through the fleet's own AWS account, natively: Amazon SES (email, API v2 `SendEmail`) and Amazon SNS (text
//! messages, `Publish`). The request is built here, signed with SigV4 by [`crate::aws_native`] with the credentials of the
//! environment (`AWS_ACCESS_KEY_ID` and friends) or, on a box, the box's own role, and sent through the guarded client like
//! every other channel. No `aws` command is needed, which matters on a box: its image does not carry one.
//!
//! A computer that names an AWS profile (`profile` under `[aws]`), and one with no credentials in the environment or from a
//! role (a laptop using its default profile or single sign-on), still sends through the `aws` command, as before: profiles are
//! not read here.
//!
//! Provider documentation:
//! * SES v2 `SendEmail`: <https://docs.aws.amazon.com/ses/latest/APIReference-V2/API_SendEmail.html>
//! * SNS `Publish`: <https://docs.aws.amazon.com/sns/latest/api/API_Publish.html>

use serde_json::{json, Value};

use super::{e164_ok, http_detail, Ctx, SendResult};
use crate::aws_native::{service_base, valid_region};
use crate::netguard::{Guard, HttpRequest};

/// What a native send needs to fall back to the `aws` command for: there were no credentials to sign with.
pub enum Native {
    Sent(SendResult),
    NoCredentials,
}

pub const NO_REGION: &str = "no AWS region is set for this channel, and this computer does not say which it is in: set the region in the channel's settings";

fn region(ctx: &Ctx, setting: Option<&str>) -> Result<String, String> {
    match setting.filter(|r| !r.is_empty()) {
        Some(r) if valid_region(r) => Ok(r.to_string()),
        Some(_) => Err("the AWS region is not a region name".into()),
        None => ctx
            .aws
            .region_or_default(None)
            .ok_or_else(|| NO_REGION.into()),
    }
}

/// Sign `req` for `service` and send it; `interpret` reads the answer. Never puts a credential in a result.
fn send_signed(
    ctx: &Ctx,
    mut req: HttpRequest,
    region: &str,
    service: &str,
    interpret: impl Fn(u16, &str) -> SendResult,
) -> Native {
    let Ok(signed) = ctx.aws.sign(&req, region, service) else {
        return Native::NoCredentials;
    };
    req.headers.extend(signed);
    Native::Sent(ctx.call(req, interpret))
}

// ---------- Amazon SES ----------

/// The SES v2 `SendEmail` request (REST JSON): the text is inside the JSON, never an argument of anything.
pub fn ses_request(
    region: &str,
    from: &str,
    reply_to: &str,
    to: &[String],
    subject: &str,
    text: &str,
) -> HttpRequest {
    let mut v = json!({
        "FromEmailAddress": from,
        "Destination": { "ToAddresses": to },
        "Content": { "Simple": {
            "Subject": { "Data": subject, "Charset": "UTF-8" },
            "Body": { "Text": { "Data": text, "Charset": "UTF-8" } }
        } },
    });
    if !reply_to.is_empty() {
        v["ReplyToAddresses"] = json!([reply_to]);
    }
    HttpRequest::new(
        "POST",
        format!("{}/v2/email/outbound-emails", service_base("email", region)),
        Guard::Public,
    )
    .json(&v)
}

/// What SES answered, in words. The body can name addresses and the account, so only known words in it are looked for.
pub fn ses_answer(status: u16, body: &str) -> SendResult {
    let v: Value = serde_json::from_str(body).unwrap_or(Value::Null);
    match status {
        200..=299 if v["MessageId"].is_string() => Ok("sent".into()),
        200..=299 => Err("Amazon SES answered without a message id".into()),
        403 => Err("the AWS credentials are not allowed to send with Amazon SES (ses:SendEmail), or were refused".into()),
        400 if body.contains("MessageRejected") || body.contains("not verified") => Err(
            "Amazon SES refused the message: the sender (or, in the SES sandbox, a recipient) is not verified".into(),
        ),
        400 if body.contains("AccountSuspended") || body.contains("SendingPaused") => {
            Err("the Amazon SES account cannot send right now".into())
        }
        400 => Err("AWS refused the request: a parameter is not valid".into()),
        s => Err(http_detail(s)),
    }
}

pub fn ses(
    ctx: &Ctx,
    region_setting: Option<&str>,
    from: &str,
    reply_to: &str,
    to: &[String],
    subject: &str,
    text: &str,
) -> Result<Native, String> {
    let region = region(ctx, region_setting)?;
    Ok(send_signed(
        ctx,
        ses_request(&region, from, reply_to, to, subject, text),
        &region,
        "ses",
        ses_answer,
    ))
}

// ---------- Amazon SNS ----------

/// The SNS `Publish` request (the query protocol, a form body): the number and the text are form values, never arguments.
pub fn sns_request(region: &str, from: &str, to: &str, text: &str) -> HttpRequest {
    let mut pairs: Vec<(&str, &str)> = vec![
        ("Action", "Publish"),
        ("Version", "2010-03-31"),
        ("PhoneNumber", to),
        ("Message", text),
    ];
    // a sender name (where the country allows one); a number is not a sender id
    if !from.is_empty() && !e164_ok(from) {
        pairs.extend([
            ("MessageAttributes.entry.1.Name", "AWS.SNS.SMS.SenderID"),
            ("MessageAttributes.entry.1.Value.DataType", "String"),
            ("MessageAttributes.entry.1.Value.StringValue", from),
        ]);
    }
    HttpRequest::new(
        "POST",
        format!("{}/", service_base("sns", region)),
        Guard::Public,
    )
    .form(&pairs)
}

fn xml_code(body: &str) -> Option<&str> {
    let start = body.find("<Code>")? + "<Code>".len();
    let len = body[start..].find("</Code>")?;
    Some(&body[start..start + len])
}

/// What SNS answered (XML), in words. Only the error code is read; the message can hold the number or the account.
pub fn sns_answer(status: u16, body: &str) -> SendResult {
    if (200..300).contains(&status) {
        return if body.contains("<MessageId>") {
            Ok("sent".into())
        } else {
            Err("AWS SNS answered without a message id".into())
        };
    }
    match xml_code(body) {
        Some("AuthorizationError" | "AccessDenied" | "AccessDeniedException") => {
            Err("the AWS credentials are not allowed to do that".into())
        }
        Some(
            "InvalidClientTokenId"
            | "SignatureDoesNotMatch"
            | "ExpiredToken"
            | "IncompleteSignature"
            | "UnrecognizedClientException",
        ) => Err("the AWS credentials on this computer are missing or expired".into()),
        Some("Throttling" | "ThrottlingException" | "ThrottledException") => {
            Err("AWS is busy or unreachable (try again)".into())
        }
        Some("InvalidParameter" | "InvalidParameterValue") => {
            Err("AWS refused the request: a parameter is not valid".into())
        }
        Some("OptedOut") => {
            Err("that number has opted out of text messages from this account".into())
        }
        _ => Err(http_detail(status)),
    }
}

pub fn sns(
    ctx: &Ctx,
    region_setting: Option<&str>,
    from: &str,
    to: &str,
    text: &str,
) -> Result<Native, String> {
    let region = region(ctx, region_setting)?;
    Ok(send_signed(
        ctx,
        sns_request(&region, from, to, text),
        &region,
        "sns",
        sns_answer,
    ))
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use crate::aws_native::fakes::{self, verify_sigv4_with, Fake, Seen};
    use crate::channels::testing::rig_with_aws;

    /// What AWS would receive: the request the guarded client was given, with the `Host` its transport adds.
    fn arrived(req: &HttpRequest) -> Seen {
        let rest = req.url.strip_prefix("https://").unwrap();
        let (host, path) = rest.split_once('/').unwrap();
        let mut headers = req.headers.clone();
        headers.push(("Host".into(), host.into()));
        Seen {
            method: req.method.into(),
            url: format!("/{path}"),
            headers,
            body: String::from_utf8(req.body.clone().unwrap_or_default()).unwrap(),
        }
    }

    #[test]
    fn ses_is_a_signed_v2_send_email_with_the_text_inside_the_json() {
        let f = Fake::start();
        let g = rig_with_aws(&f.imds);
        g.http.reply(200, r#"{"MessageId":"0100"}"#);
        let to = vec!["me@example.com".to_string()];
        let r = ses(
            &g.ctx,
            Some("eu-west-1"),
            "alerts@example.com",
            "help@example.com",
            &to,
            "S",
            "--profile evil",
        )
        .unwrap();
        assert!(matches!(r, Native::Sent(Ok(ref s)) if s == "sent"));
        let req = &g.http.requests()[0];
        assert_eq!(
            req.url,
            "https://email.eu-west-1.amazonaws.com/v2/email/outbound-emails"
        );
        assert_eq!(req.guard, Guard::Public);
        let s = arrived(req);
        assert_eq!(
            verify_sigv4_with(&s, "/v2/email/outbound-emails", &["content-type"]),
            Ok(())
        );
        assert!(s
            .header("authorization")
            .unwrap()
            .contains("/eu-west-1/ses/aws4_request"));
        let body: Value = serde_json::from_str(&s.body).unwrap();
        assert_eq!(body["FromEmailAddress"], "alerts@example.com");
        assert_eq!(body["Destination"]["ToAddresses"][0], "me@example.com");
        assert_eq!(body["ReplyToAddresses"][0], "help@example.com");
        assert_eq!(
            body["Content"]["Simple"]["Body"]["Text"]["Data"],
            "--profile evil"
        );
        // the secret key is never sent, and no program is started
        assert!(!format!("{:?}", req.headers).contains(fakes::SECRET_KEY));
        assert!(g.runner.calls().is_empty());
    }

    #[test]
    fn sns_is_a_signed_publish_form_with_the_sender_name_as_an_attribute() {
        let f = Fake::start();
        let g = rig_with_aws(&f.imds);
        g.http.reply(
            200,
            "<PublishResponse><PublishResult><MessageId>x-1</MessageId></PublishResult></PublishResponse>",
        );
        let r = sns(&g.ctx, Some("us-east-1"), "OzBox", "+15005550009", "T b").unwrap();
        assert!(matches!(r, Native::Sent(Ok(_))));
        let req = &g.http.requests()[0];
        assert_eq!(req.url, "https://sns.us-east-1.amazonaws.com/");
        let s = arrived(req);
        assert_eq!(verify_sigv4_with(&s, "/", &["content-type"]), Ok(()));
        assert!(s
            .header("authorization")
            .unwrap()
            .contains("/us-east-1/sns/aws4_request"));
        for part in [
            "Action=Publish",
            "Version=2010-03-31",
            "PhoneNumber=%2B15005550009",
            "Message=T+b",
            "AWS.SNS.SMS.SenderID",
            "StringValue=OzBox",
        ] {
            assert!(s.body.contains(part), "{part}: {}", s.body);
        }
        // a sender that is a number is not a sender id
        let g = rig_with_aws(&f.imds);
        sns(
            &g.ctx,
            Some("us-east-1"),
            "+15005550006",
            "+15005550009",
            "x",
        )
        .unwrap();
        let b = String::from_utf8(g.http.requests()[0].body.clone().unwrap()).unwrap();
        assert!(!b.contains("SenderID"));
    }

    #[test]
    fn the_region_comes_from_the_setting_else_this_machine_and_a_bad_one_sends_nothing() {
        let f = Fake::start();
        let g = rig_with_aws(&f.imds);
        assert!(
            ses(&g.ctx, Some("EU WEST"), "a@example.com", "", &[], "s", "t")
                .err()
                .unwrap()
                .contains("region")
        );
        assert!(g.http.requests().is_empty());
        if std::env::var("AWS_REGION").is_err() && std::env::var("AWS_DEFAULT_REGION").is_err() {
            sns(&g.ctx, None, "", "+15005550009", "x").unwrap();
            // the fake metadata service says eu-west-2
            assert_eq!(
                g.http.requests()[0].url,
                "https://sns.eu-west-2.amazonaws.com/"
            );
        }
    }

    #[test]
    fn no_credentials_is_said_as_such_and_nothing_is_sent() {
        let dead = {
            let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
            format!("http://{}", l.local_addr().unwrap())
        };
        let g = rig_with_aws(&dead);
        let r = sns(&g.ctx, Some("us-east-1"), "", "+15005550009", "x").unwrap();
        assert!(matches!(r, Native::NoCredentials));
        assert!(g.http.requests().is_empty());
    }

    #[test]
    fn the_channels_send_natively_unless_a_profile_is_named_or_there_are_no_credentials() {
        use crate::notify_config::{EmailProviderKind, SmsConfig, SmsProviderKind};
        use crate::settings::EmailConfig;
        use ozbox_core::Output;
        let f = Fake::start();
        let cfg = EmailConfig {
            enabled: true,
            from: "alerts@example.com".into(),
            to: vec!["me@example.com".into()],
            provider: EmailProviderKind::Ses,
            region: Some("us-east-1".into()),
            ..Default::default()
        };
        let to = vec!["me@example.com".to_string()];
        let mail = |g: &crate::channels::testing::Rig| {
            crate::channels::mail::send(
                &g.ctx,
                &crate::channels::mail::Mail {
                    cfg: &cfg,
                    to: &to,
                    subject: "s",
                    text: "t",
                    now_secs: 0,
                },
            )
        };
        let sms = SmsConfig {
            enabled: true,
            provider: SmsProviderKind::Sns,
            region: Some("us-east-1".into()),
            ..Default::default()
        };
        // a box: credentials from its role, so natively, and no program is started
        let g = rig_with_aws(&f.imds);
        g.http.reply(200, r#"{"MessageId":"m"}"#);
        g.http.reply(200, "<MessageId>x</MessageId>");
        assert_eq!(mail(&g), Ok("sent".into()));
        assert_eq!(
            crate::channels::sms::send(&g.ctx, &sms, "+15005550009", "T", "b"),
            Ok("sent".into())
        );
        assert_eq!(g.http.requests().len(), 2);
        assert!(g.runner.calls().is_empty());
        // a named profile: the aws command, which reads it, even with a role to hand
        let mut g = rig_with_aws(&f.imds);
        g.ctx.aws_profile = Some("work".into());
        g.runner.reply(Output {
            status: Some(0),
            stdout: r#"{"MessageId":"m"}"#.into(),
            stderr: String::new(),
        });
        assert_eq!(mail(&g), Ok("sent".into()));
        assert!(g.http.requests().is_empty());
        assert!(g.runner.calls()[0]
            .args
            .windows(2)
            .any(|w| w == ["--profile", "work"]));
        // no credentials to sign with (a laptop on its default profile): the aws command is tried, nothing is sent natively
        let g = crate::channels::testing::rig();
        let _ = crate::channels::sms::send(&g.ctx, &sms, "+15005550009", "T", "b");
        assert!(g.http.requests().is_empty());
        assert_eq!(g.runner.calls()[0].program, "aws");
    }

    #[test]
    fn answers_are_read_in_words_with_nothing_of_the_body_in_them() {
        const SENTINEL: &str = "+15005550009 arn:aws:iam::123456789012:user/x";
        assert_eq!(ses_answer(200, r#"{"MessageId":"m"}"#), Ok("sent".into()));
        assert!(ses_answer(200, "{}").is_err());
        for (status, body, want) in [
            (403, format!(r#"{{"message":"{SENTINEL}"}}"#), "not allowed"),
            (
                400,
                format!(r#"{{"message":"Email address is not verified. {SENTINEL}"}}"#),
                "not verified",
            ),
            (400, format!("AccountSuspended {SENTINEL}"), "cannot send"),
            (400, SENTINEL.to_string(), "not valid"),
        ] {
            let e = ses_answer(status, &body).unwrap_err();
            assert!(
                e.contains(want) && !e.contains("123456789012") && !e.contains("+1500"),
                "{e}"
            );
        }
        assert!(crate::channels::retryable(
            &ses_answer(503, "").unwrap_err()
        ));
        assert!(crate::channels::retryable(
            &ses_answer(429, "").unwrap_err()
        ));
        let xml = |code: &str| {
            format!("<ErrorResponse><Error><Type>Sender</Type><Code>{code}</Code><Message>{SENTINEL}</Message></Error></ErrorResponse>")
        };
        for (status, code, want) in [
            (403, "AuthorizationError", "not allowed"),
            (403, "InvalidClientTokenId", "missing or expired"),
            (403, "SignatureDoesNotMatch", "missing or expired"),
            (400, "Throttling", "try again"),
            (400, "InvalidParameter", "not valid"),
            (400, "OptedOut", "opted out"),
        ] {
            let e = sns_answer(status, &xml(code)).unwrap_err();
            assert!(
                e.contains(want) && !e.contains("123456789012") && !e.contains("+1500"),
                "{code}: {e}"
            );
        }
        assert!(crate::channels::retryable(
            &sns_answer(400, &xml("Throttling")).unwrap_err()
        ));
        assert!(crate::channels::retryable(
            &sns_answer(500, "").unwrap_err()
        ));
        assert!(sns_answer(200, "<PublishResponse/>").is_err());
    }
}
