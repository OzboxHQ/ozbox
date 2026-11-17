//! Text messages through the owner's own account at one of five providers. Each provider is an adapter behind
//! [`SmsProvider`]: it builds the request its documentation describes and reads the answer in words, so an
//! unreachable number, a refused credential and a busy service each read differently.
//!
//! Provider documentation:
//! * Twilio: <https://www.twilio.com/docs/messaging/api/message-resource#create-a-message-resource>
//! * Vonage SMS API: <https://developer.vonage.com/en/api/sms>
//! * AWS SNS (`Publish`, natively; the CLI where an AWS profile is named): <https://docs.aws.amazon.com/sns/latest/api/API_Publish.html>
//! * Africa's Talking: <https://developers.africastalking.com/docs/sms/sending/bulk>
//! * Telnyx: <https://developers.telnyx.com/api/messaging/send-message>
//!
//! Credentials: two write-only secrets, `sms-account` (the account id, user name or key id) and `sms-secret` (the token,
//! secret or key). AWS SNS needs neither: it sends through the fleet's own AWS credentials.

use ozbox_core::CommandSpec;
use serde_json::{json, Value};

use super::{b64_std, clip, e164_ok, http_detail, Ctx, SendResult};
use crate::netguard::{Guard, HttpRequest};
use crate::notify_config::{SmsConfig, SmsProviderKind};

/// Characters in one text: seven-bit text carries 160, and long texts are split into parts of 153, so this caps the
/// cost of one alert at three parts. Anything outside plain ASCII switches the phone to a 70-character encoding, so
/// such a text is cut shorter.
pub const MAX_ASCII: usize = 459;
pub const MAX_UNICODE: usize = 201;

/// What one person may receive in an hour, across every alert.
pub const PER_RECIPIENT_PER_HOUR: usize = 6;

pub trait SmsProvider {
    fn send(&self, ctx: &Ctx, cfg: &SmsConfig, to: &str, text: &str) -> SendResult;
}

/// The text of one message: short, one line of headline then the detail, cut to what the phone can carry.
pub fn fit(title: &str, body: &str) -> String {
    let full = format!(
        "[Oz Box] {}\n{}",
        super::one_line(title),
        super::one_line(body)
    );
    let max = if full.is_ascii() {
        MAX_ASCII
    } else {
        MAX_UNICODE
    };
    clip(&full, max)
}

pub fn provider(kind: SmsProviderKind) -> Box<dyn SmsProvider> {
    match kind {
        SmsProviderKind::Twilio => Box::new(Twilio),
        SmsProviderKind::Vonage => Box::new(Vonage),
        SmsProviderKind::Sns => Box::new(Sns),
        SmsProviderKind::AfricasTalking => Box::new(AfricasTalking),
        SmsProviderKind::Telnyx => Box::new(Telnyx),
    }
}

/// Send one text through the provider that is set up.
pub fn send(ctx: &Ctx, cfg: &SmsConfig, to: &str, title: &str, body: &str) -> SendResult {
    if !e164_ok(to) {
        return Err("the phone number is not in international format".into());
    }
    provider(cfg.provider).send(ctx, cfg, to, &fit(title, body))
}

fn json_of(body: &str) -> Value {
    serde_json::from_str(body).unwrap_or(Value::Null)
}

fn need_from(cfg: &SmsConfig) -> Result<&str, String> {
    if cfg.from.is_empty() {
        Err("the sender number or name is not set".into())
    } else {
        Ok(&cfg.from)
    }
}

// ---------- Twilio ----------

pub struct Twilio;

impl Twilio {
    pub fn request(sid: &str, token: &str, from: &str, to: &str, text: &str) -> HttpRequest {
        let sender = if from.starts_with("MG") {
            ("MessagingServiceSid", from)
        } else {
            ("From", from)
        };
        HttpRequest::new(
            "POST",
            format!("https://api.twilio.com/2010-04-01/Accounts/{sid}/Messages.json"),
            Guard::Public,
        )
        .header(
            "Authorization",
            format!("Basic {}", b64_std(format!("{sid}:{token}").as_bytes())),
        )
        .form(&[("To", to), sender, ("Body", text)])
    }

    pub fn interpret(status: u16, body: &str) -> SendResult {
        if status == 201 || status == 200 {
            return Ok("sent".into());
        }
        let code = json_of(body)["code"].as_u64().unwrap_or(0);
        Err(match (status, code) {
            (401, _) => "Twilio refused the account id or the token".into(),
            (_, 21211 | 21614) => "Twilio says the phone number is not valid".into(),
            (_, 21608) => "Twilio will only text numbers verified on a trial account".into(),
            (_, 21610) => "the person replied STOP, so Twilio will not text this number".into(),
            (_, 21408) => "the account may not text that country".into(),
            (_, 21606 | 21212) => "Twilio does not accept that sender number".into(),
            (s, _) => http_detail(s),
        })
    }
}

impl SmsProvider for Twilio {
    fn send(&self, ctx: &Ctx, cfg: &SmsConfig, to: &str, text: &str) -> SendResult {
        let sid = ctx.need("sms-account", "Twilio account SID")?;
        let token = ctx.need("sms-secret", "Twilio auth token")?;
        let from = need_from(cfg)?;
        ctx.call(Self::request(&sid, &token, from, to, text), Self::interpret)
    }
}

// ---------- Vonage ----------

pub struct Vonage;

impl Vonage {
    pub fn request(key: &str, secret: &str, from: &str, to: &str, text: &str) -> HttpRequest {
        // The API wants the number without the plus sign.
        let to = to.trim_start_matches('+');
        let from = from.trim_start_matches('+');
        HttpRequest::new("POST", "https://rest.nexmo.com/sms/json", Guard::Public).form(&[
            ("api_key", key),
            ("api_secret", secret),
            ("to", to),
            ("from", from),
            ("text", text),
            ("type", if text.is_ascii() { "text" } else { "unicode" }),
        ])
    }

    /// Vonage answers HTTP 200 even when it refuses a message: the verdict is `messages[0].status`.
    pub fn interpret(status: u16, body: &str) -> SendResult {
        if status != 200 {
            return Err(http_detail(status));
        }
        let v = json_of(body);
        let code = v["messages"][0]["status"]
            .as_str()
            .map(str::to_string)
            .or_else(|| v["messages"][0]["status"].as_u64().map(|n| n.to_string()));
        match code.as_deref() {
            Some("0") => Ok("sent".into()),
            Some("1") => Err("Vonage is throttling this account (try again)".into()),
            Some("4" | "2") => Err("Vonage refused the API key or the secret".into()),
            Some("6" | "7") => Err("Vonage cannot deliver to that number".into()),
            Some("9") => Err("the Vonage account has no balance left".into()),
            Some("15") => Err("Vonage does not accept that sender".into()),
            Some("29") => Err("the Vonage account may only text numbers it has approved".into()),
            Some(_) => Err("Vonage refused the message".into()),
            None => Err("Vonage sent an answer that could not be read".into()),
        }
    }
}

impl SmsProvider for Vonage {
    fn send(&self, ctx: &Ctx, cfg: &SmsConfig, to: &str, text: &str) -> SendResult {
        let key = ctx.need("sms-account", "Vonage API key")?;
        let secret = ctx.need("sms-secret", "Vonage API secret")?;
        let from = need_from(cfg)?;
        ctx.call(
            Self::request(&key, &secret, from, to, text),
            Self::interpret,
        )
    }
}

// ---------- Africa's Talking ----------

pub struct AfricasTalking;

impl AfricasTalking {
    pub fn request(
        username: &str,
        key: &str,
        sandbox: bool,
        from: &str,
        to: &str,
        text: &str,
    ) -> HttpRequest {
        let host = if sandbox {
            "api.sandbox.africastalking.com"
        } else {
            "api.africastalking.com"
        };
        let mut pairs = vec![("username", username), ("to", to), ("message", text)];
        if !from.is_empty() {
            pairs.push(("from", from));
        }
        HttpRequest::new(
            "POST",
            format!("https://{host}/version1/messaging"),
            Guard::Public,
        )
        .header("apiKey", key)
        .header("Accept", "application/json")
        .form(&pairs)
    }

    /// HTTP 201 carries a per-recipient `statusCode`: 100 processed, 101 sent, 102 queued are all accepted.
    pub fn interpret(status: u16, body: &str) -> SendResult {
        if status == 401 {
            return Err("Africa's Talking refused the user name or the API key".into());
        }
        if status != 201 && status != 200 {
            return Err(http_detail(status));
        }
        let v = json_of(body);
        match v["SMSMessageData"]["Recipients"][0]["statusCode"].as_u64() {
            Some(100..=102) => Ok("sent".into()),
            Some(403) => Err("Africa's Talking says the phone number is not valid".into()),
            Some(405) => Err("the Africa's Talking account has no balance left".into()),
            Some(406) => Err("that number is on Africa's Talking's block list".into()),
            Some(_) => Err("Africa's Talking refused the message".into()),
            None => Err("Africa's Talking sent no recipient result".into()),
        }
    }
}

impl SmsProvider for AfricasTalking {
    fn send(&self, ctx: &Ctx, cfg: &SmsConfig, to: &str, text: &str) -> SendResult {
        let user = ctx.need("sms-account", "Africa's Talking user name")?;
        let key = ctx.need("sms-secret", "Africa's Talking API key")?;
        ctx.call(
            Self::request(&user, &key, cfg.sandbox, &cfg.from, to, text),
            Self::interpret,
        )
    }
}

// ---------- Telnyx ----------

pub struct Telnyx;

impl Telnyx {
    pub fn request(key: &str, from: &str, to: &str, text: &str) -> HttpRequest {
        HttpRequest::new("POST", "https://api.telnyx.com/v2/messages", Guard::Public)
            .header("Authorization", format!("Bearer {key}"))
            .json(&json!({ "from": from, "to": to, "text": text }))
    }

    pub fn interpret(status: u16, body: &str) -> SendResult {
        match status {
            200 | 202 if json_of(body)["data"]["id"].is_string() => Ok("sent".into()),
            200 | 202 => Err("Telnyx sent an answer that could not be read".into()),
            401 | 403 => Err("Telnyx refused the API key".into()),
            422 => Err("Telnyx refused the message or the number".into()),
            s => Err(http_detail(s)),
        }
    }
}

impl SmsProvider for Telnyx {
    fn send(&self, ctx: &Ctx, cfg: &SmsConfig, to: &str, text: &str) -> SendResult {
        let key = ctx.need("sms-secret", "Telnyx API key")?;
        let from = need_from(cfg)?;
        ctx.call(Self::request(&key, from, to, text), by_status_telnyx)
    }
}

fn by_status_telnyx(status: u16, body: &str) -> SendResult {
    Telnyx::interpret(status, body)
}

// ---------- AWS SNS ----------

pub struct Sns;

impl Sns {
    pub fn command(
        profile: Option<&str>,
        region: Option<&str>,
        from: &str,
        to: &str,
        text: &str,
    ) -> CommandSpec {
        let mut c = CommandSpec::new("aws").args([
            "sns",
            "publish",
            "--phone-number",
            to,
            "--message",
            text,
        ]);
        if !from.is_empty() && !e164_ok(from) {
            c = c.args([
                "--message-attributes",
                &json!({ "AWS.SNS.SMS.SenderID": { "DataType": "String", "StringValue": from } })
                    .to_string(),
            ]);
        }
        if let Some(r) = region {
            c = c.args(["--region", r]);
        }
        if let Some(p) = profile {
            c = c.args(["--profile", p]);
        }
        c.args(["--output", "json"])
    }

    pub fn interpret(stdout: &str) -> SendResult {
        if json_of(stdout)["MessageId"].is_string() {
            Ok("sent".into())
        } else {
            Err("AWS SNS answered without a message id".into())
        }
    }
}

/// What a person is told when neither a native send nor the `aws` command had credentials to use.
pub const NO_AWS_CREDENTIALS: &str = "the AWS credentials on this computer are missing or expired (on a box: its role; elsewhere: AWS_ACCESS_KEY_ID and AWS_SECRET_ACCESS_KEY, or a profile under [aws] with the aws command installed)";

impl SmsProvider for Sns {
    fn send(&self, ctx: &Ctx, cfg: &SmsConfig, to: &str, text: &str) -> SendResult {
        // natively, unless this computer names an AWS profile (only the aws command reads profiles), or has no credentials
        // of its own to sign with (a laptop on its default profile)
        if ctx.aws_profile.is_none() {
            match super::aws::sns(ctx, cfg.region.as_deref(), &cfg.from, to, text)? {
                super::aws::Native::Sent(r) => return r,
                super::aws::Native::NoCredentials => {}
            }
        }
        let cmd = Self::command(
            ctx.aws_profile.as_deref(),
            cfg.region.as_deref(),
            &cfg.from,
            to,
            text,
        );
        match ctx.runner.run(&cmd) {
            Ok(o) if o.status == Some(0) => Self::interpret(&o.stdout),
            Ok(o) => Err(aws_failure(&o.stderr)),
            Err(_) => Err(NO_AWS_CREDENTIALS.into()),
        }
    }
}

/// What a failed `aws` call means for a person; the raw text can hold account ids and numbers, so it is not shown.
pub fn aws_failure(stderr: &str) -> String {
    let s = stderr.to_ascii_lowercase();
    if s.contains("unable to locate credentials")
        || s.contains("expiredtoken")
        || s.contains("could not be found")
    {
        "the AWS credentials on this computer are missing or expired".into()
    } else if s.contains("accessdenied") || s.contains("not authorized") {
        "the AWS credentials are not allowed to do that".into()
    } else if s.contains("throttl") || s.contains("timed out") || s.contains("could not connect") {
        "AWS is busy or unreachable (try again)".into()
    } else if s.contains("invalidparameter") || s.contains("invalid parameter") {
        "AWS refused the request: a parameter is not valid".into()
    } else {
        "the aws command failed".into()
    }
}

/// Whether this provider needs the two stored secrets, for the dashboard's "configured" flag.
pub fn needs_secrets(kind: SmsProviderKind) -> &'static [&'static str] {
    match kind {
        SmsProviderKind::Sns => &[],
        SmsProviderKind::Telnyx => &["sms-secret"],
        _ => &["sms-account", "sms-secret"],
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use crate::channels::testing::rig;
    use crate::secrets::SecretStore;
    use ozbox_core::Output;

    fn cfg(kind: SmsProviderKind) -> SmsConfig {
        SmsConfig {
            enabled: true,
            provider: kind,
            from: "+15005550006".into(),
            ..Default::default()
        }
    }

    fn body(r: &HttpRequest) -> String {
        String::from_utf8(r.body.clone().unwrap()).unwrap()
    }

    #[test]
    fn long_and_unicode_texts_are_cut_to_what_a_phone_carries() {
        let t = fit("Disk full", &"x".repeat(2000));
        assert_eq!(t.chars().count(), MAX_ASCII);
        assert!(t.starts_with("[Oz Box] Disk full\n"));
        let u = fit("Disque", &"\u{e9}".repeat(2000));
        assert_eq!(u.chars().count(), MAX_UNICODE);
        assert!(!fit("a\r\nb", "c\nd").contains("\r"));
    }

    #[test]
    fn twilio_request_and_answers_follow_the_documentation() {
        let r = Twilio::request("ACtest", "tok", "+15005550006", "+15005550009", "hi there");
        assert_eq!(
            r.url,
            "https://api.twilio.com/2010-04-01/Accounts/ACtest/Messages.json"
        );
        assert!(r
            .headers
            .iter()
            .any(|(k, v)| k == "Authorization" && v == "Basic QUN0ZXN0OnRvaw=="));
        assert_eq!(
            body(&r),
            "To=%2B15005550009&From=%2B15005550006&Body=hi+there"
        );
        let m = Twilio::request("AC", "t", "MG123", "+15005550009", "x");
        assert!(body(&m).contains("MessagingServiceSid=MG123"));
        assert_eq!(
            Twilio::interpret(201, r#"{"sid":"SM1","status":"queued"}"#),
            Ok("sent".into())
        );
        let e = Twilio::interpret(
            400,
            r#"{"code":21211,"message":"The 'To' number +1 is not valid","status":400}"#,
        )
        .unwrap_err();
        assert!(e.contains("not valid") && !e.contains("+1"));
        assert!(Twilio::interpret(401, r#"{"code":20003}"#)
            .unwrap_err()
            .contains("refused"));
        assert!(Twilio::interpret(400, r#"{"code":21610}"#)
            .unwrap_err()
            .contains("STOP"));
        assert!(crate::channels::retryable(
            &Twilio::interpret(503, "").unwrap_err()
        ));
    }

    #[test]
    fn vonage_reads_the_status_inside_a_200() {
        let r = Vonage::request("key", "sec", "OzBox", "+15005550009", "hi");
        assert_eq!(r.url, "https://rest.nexmo.com/sms/json");
        assert!(body(&r).contains("to=15005550009"));
        assert!(
            body(&r).contains("type=text"),
            "plain text is one cheap segment"
        );
        let u = Vonage::request("key", "sec", "OzBox", "+15005550009", "h\u{e9}");
        assert!(body(&u).contains("type=unicode"));
        assert_eq!(
            Vonage::interpret(
                200,
                r#"{"message-count":"1","messages":[{"to":"15005550009","message-id":"1","status":"0","remaining-balance":"3.1","message-price":"0.03","network":"1"}]}"#
            ),
            Ok("sent".into())
        );
        let e = Vonage::interpret(
            200,
            r#"{"message-count":"1","messages":[{"status":"4","error-text":"Bad Credentials"}]}"#,
        )
        .unwrap_err();
        assert!(e.contains("refused") && !e.contains("Bad Credentials"));
        assert!(crate::channels::retryable(
            &Vonage::interpret(200, r#"{"messages":[{"status":"1"}]}"#).unwrap_err()
        ));
        assert!(Vonage::interpret(200, "not json").is_err());
    }

    #[test]
    fn africas_talking_uses_its_header_and_the_sandbox_host() {
        let r = AfricasTalking::request("sandbox", "k", true, "", "+254711000000", "hi");
        assert_eq!(
            r.url,
            "https://api.sandbox.africastalking.com/version1/messaging"
        );
        assert!(r.headers.iter().any(|(k, v)| k == "apiKey" && v == "k"));
        assert!(r
            .headers
            .iter()
            .any(|(k, v)| k == "Accept" && v == "application/json"));
        assert_eq!(body(&r), "username=sandbox&to=%2B254711000000&message=hi");
        let live = AfricasTalking::request("u", "k", false, "OzBox", "+234", "hi");
        assert_eq!(
            live.url,
            "https://api.africastalking.com/version1/messaging"
        );
        assert!(body(&live).ends_with("&from=OzBox"));
        let ok = r#"{"SMSMessageData":{"Message":"Sent to 1/1 Total Cost: KES 0.8000","Recipients":[{"statusCode":101,"number":"+254711000000","status":"Success","cost":"KES 0.8000","messageId":"ATPid_1"}]}}"#;
        assert_eq!(AfricasTalking::interpret(201, ok), Ok("sent".into()));
        let bad = r#"{"SMSMessageData":{"Message":"Sent to 0/1","Recipients":[{"statusCode":403,"number":"+254","status":"InvalidPhoneNumber"}]}}"#;
        assert!(AfricasTalking::interpret(201, bad)
            .unwrap_err()
            .contains("not valid"));
        assert!(AfricasTalking::interpret(401, "")
            .unwrap_err()
            .contains("refused"));
    }

    #[test]
    fn telnyx_sends_json_with_a_bearer_key() {
        let r = Telnyx::request("KEY", "+15005550006", "+15005550009", "hi");
        assert_eq!(r.url, "https://api.telnyx.com/v2/messages");
        assert!(r
            .headers
            .iter()
            .any(|(k, v)| k == "Authorization" && v == "Bearer KEY"));
        assert!(body(&r).contains(r#""text":"hi""#));
        assert_eq!(
            Telnyx::interpret(200, r#"{"data":{"id":"abc","record_type":"message"}}"#),
            Ok("sent".into())
        );
        assert!(Telnyx::interpret(200, "{}").is_err());
        assert!(Telnyx::interpret(401, r#"{"errors":[{"code":"10009"}]}"#)
            .unwrap_err()
            .contains("refused"));
        assert!(Telnyx::interpret(422, "{}").is_err());
    }

    #[test]
    fn sns_runs_the_aws_cli_with_an_argument_list() {
        let g = rig();
        g.runner.reply(Output {
            status: Some(0),
            stdout: r#"{"MessageId":"x-1"}"#.into(),
            stderr: String::new(),
        });
        let mut c = cfg(SmsProviderKind::Sns);
        c.from = "OzBox".into();
        c.region = Some("us-east-1".into());
        assert_eq!(
            send(&g.ctx, &c, "+15005550009", "T", "b"),
            Ok("sent".into())
        );
        let call = &g.runner.calls()[0];
        assert_eq!(call.program, "aws");
        assert_eq!(
            &call.args[..4],
            ["sns", "publish", "--phone-number", "+15005550009"]
        );
        assert!(call.args.iter().any(|a| a.contains("AWS.SNS.SMS.SenderID")));
        assert!(call.args.windows(2).any(|w| w == ["--region", "us-east-1"]));
        g.runner.reply(Output {
            status: Some(254),
            stdout: String::new(),
            stderr: "Unable to locate credentials for +15005550009".into(),
        });
        let e = send(&g.ctx, &c, "+15005550009", "T", "b").unwrap_err();
        assert!(e.contains("credentials") && !e.contains("+1500"));
    }

    #[test]
    fn every_provider_goes_through_the_guarded_client_and_never_echoes_a_credential() {
        for kind in [
            SmsProviderKind::Twilio,
            SmsProviderKind::Vonage,
            SmsProviderKind::AfricasTalking,
            SmsProviderKind::Telnyx,
        ] {
            let g = rig();
            g.secrets.set("sms-account", "ACSENTINELACCOUNT").unwrap();
            g.secrets.set("sms-secret", "SENTINELSECRET").unwrap();
            g.http
                .reply(500, r#"{"echo":"SENTINELSECRET +15005550009"}"#);
            let e = send(&g.ctx, &cfg(kind), "+15005550009", "T", "b").unwrap_err();
            assert!(
                !e.contains("SENTINEL") && !e.contains("+1500"),
                "{kind:?}: {e}"
            );
            let r = &g.http.requests()[0];
            assert_eq!(r.guard, Guard::Public);
            assert!(r.url.starts_with("https://"));
        }
    }

    #[test]
    fn a_missing_credential_a_missing_sender_and_a_bad_number_say_so_without_sending() {
        let g = rig();
        assert!(send(
            &g.ctx,
            &cfg(SmsProviderKind::Twilio),
            "+15005550009",
            "T",
            "b"
        )
        .unwrap_err()
        .contains("no Twilio"));
        g.secrets.set("sms-account", "AC1").unwrap();
        g.secrets.set("sms-secret", "s").unwrap();
        let mut c = cfg(SmsProviderKind::Twilio);
        c.from.clear();
        assert!(send(&g.ctx, &c, "+15005550009", "T", "b")
            .unwrap_err()
            .contains("sender"));
        assert!(
            send(&g.ctx, &cfg(SmsProviderKind::Twilio), "0801", "T", "b")
                .unwrap_err()
                .contains("international")
        );
        assert!(g.http.requests().is_empty());
    }
}
