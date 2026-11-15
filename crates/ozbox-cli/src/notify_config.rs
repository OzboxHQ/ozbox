//! The settings of the notification channels and of the per-person routing rules. The secrets of every channel (API
//! keys, tokens, passwords, webhook addresses, push keys) are not here: they live in the secret store and are never
//! returned. Everything in this file is additive to the settings file: an older file without these sections keeps
//! working, and every field has a default.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

/// A person may route to at most this many addresses and devices.
pub const MAX_EMAILS: usize = 5;
pub const MAX_DEVICES: usize = 8;

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EmailProviderKind {
    #[default]
    Resend,
    Smtp,
    Ses,
    Postmark,
    Sendgrid,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SmtpSecurity {
    /// Implicit TLS, normally port 465.
    Tls,
    /// A plain connection upgraded with STARTTLS before anything is sent, normally port 587. Never optional.
    #[default]
    Starttls,
}

impl SmtpSecurity {
    pub fn default_port(self) -> u16 {
        match self {
            SmtpSecurity::Tls => 465,
            SmtpSecurity::Starttls => 587,
        }
    }
}

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct SmtpConfig {
    pub host: String,
    /// 0 means the usual port for the chosen security.
    pub port: u16,
    pub security: SmtpSecurity,
    pub username: String,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SmsProviderKind {
    #[default]
    Twilio,
    Vonage,
    Sns,
    AfricasTalking,
    Telnyx,
}

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct SmsConfig {
    pub enabled: bool,
    pub provider: SmsProviderKind,
    /// The sender: a number in international format, or a sender name where the provider and country allow one.
    pub from: String,
    /// AWS SNS only: the region to publish from (blank: the profile's own).
    pub region: Option<String>,
    /// Africa's Talking only: use the sandbox host.
    pub sandbox: bool,
}

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct WhatsappConfig {
    pub enabled: bool,
    /// The Cloud API phone number id (not the number itself).
    pub phone_number_id: String,
    /// An approved message template with two body parameters: the title and the text of the alert.
    pub template: String,
    /// The template's language code, such as `en_US`.
    pub language: String,
}

/// One push-enabled browser or installed app of a person. The endpoint and the keys are secrets; only the host is here.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PushDevice {
    pub id: String,
    pub label: String,
    pub host: String,
}

/// What a severity does for a person: which channels, and whether it may break through quiet hours.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct Route {
    pub channels: Vec<String>,
    pub bypass_quiet: bool,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct DigestRoute {
    pub enabled: bool,
    /// The person's local time of day, `08:00`.
    pub time: String,
    pub channels: Vec<String>,
}

impl Default for DigestRoute {
    fn default() -> Self {
        Self {
            enabled: true,
            time: "08:00".into(),
            channels: vec!["email".into()],
        }
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct PersonRouting {
    /// The person's own time zone; the fleet's when unset.
    pub time_zone: Option<String>,
    /// Quiet hours in the person's time zone; the fleet's when unset.
    pub quiet_from: Option<String>,
    pub quiet_to: Option<String>,
    /// International format, `+2348012345678`.
    pub phone: Option<String>,
    pub whatsapp: Option<String>,
    pub emails: Vec<String>,
    pub push: Vec<PushDevice>,
    pub urgent: Route,
    pub normal: Route,
    pub digest: DigestRoute,
    /// A rule for one kind of alert, by kind (`schedule`): which route it follows for this person (`urgent` or `normal`),
    /// or `off` to not be told. A kind with no entry follows the alert's own severity. Additive.
    pub kind_routes: std::collections::BTreeMap<String, String>,
}

/// The alert kinds a person can give their own rule, and the choices a rule can make.
pub const RULE_KINDS: &[&str] = &["schedule"];
pub const RULE_CHOICES: &[&str] = &["urgent", "normal", "off"];

impl Default for PersonRouting {
    fn default() -> Self {
        Self {
            time_zone: None,
            quiet_from: None,
            quiet_to: None,
            phone: None,
            whatsapp: None,
            emails: Vec::new(),
            push: Vec::new(),
            urgent: Route {
                channels: vec!["sms".into(), "telegram".into(), "push".into()],
                bypass_quiet: true,
            },
            normal: Route {
                channels: vec!["telegram".into(), "slack".into()],
                bypass_quiet: false,
            },
            digest: DigestRoute::default(),
            kind_routes: std::collections::BTreeMap::new(),
        }
    }
}

/// Routing rules per person, keyed by the sign-in person's id. With no one listed the older behaviour holds: every
/// channel that is switched on gets every alert.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct RoutingConfig {
    pub people: BTreeMap<String, PersonRouting>,
}

pub fn channel_name_ok(c: &str) -> bool {
    matches!(
        c,
        "sms" | "email" | "telegram" | "slack" | "whatsapp" | "discord" | "teams" | "push"
    ) || c
        .strip_prefix("webhook:")
        .is_some_and(|id| crate::settings::valid_id(id, 24))
}

/// `+` and 7 to 15 digits, the first not zero.
pub fn e164_ok(s: &str) -> bool {
    let Some(d) = s.strip_prefix('+') else {
        return false;
    };
    (7..=15).contains(&d.len()) && d.bytes().all(|b| b.is_ascii_digit()) && !d.starts_with('0')
}

fn zone_ok(z: &Option<String>) -> bool {
    z.as_deref().is_none_or(crate::timezone::valid_zone)
}

/// The checks for everything in this file; `Settings::validate` calls it.
pub fn validate(s: &crate::settings::Settings) -> ozbox_core::Result<()> {
    use crate::settings::{bad, email_ok, hhmm, plain_text};
    let a = &s.apps;
    let e = &a.email;
    if !e.reply_to.is_empty() && !email_ok(&e.reply_to) {
        return Err(bad("the reply-to address is not a valid address"));
    }
    if e.unsubscribed.len() > 200 || e.unsubscribed.iter().any(|u| !email_ok(u)) {
        return Err(bad("the unsubscribed list holds valid addresses only"));
    }
    if e.provider == EmailProviderKind::Smtp {
        let m = &e.smtp;
        let host_ok = !m.host.is_empty()
            && m.host.len() <= 253
            && m.host
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'.' || b == b'-');
        if e.enabled && !host_ok {
            return Err(bad(
                "the SMTP server must be a host name such as smtp.example.com",
            ));
        }
        if !m.host.is_empty() && !host_ok {
            return Err(bad(
                "the SMTP server must be a host name such as smtp.example.com",
            ));
        }
        if !plain_text_or_empty(&m.username, 254) {
            return Err(bad(
                "the SMTP user name has characters that are not allowed",
            ));
        }
    }
    if e.region.as_deref().is_some_and(|r| !region_ok(r)) {
        return Err(bad("the Amazon SES region must look like us-east-1"));
    }
    let sms = &a.sms;
    if sms.region.as_deref().is_some_and(|r| !region_ok(r)) {
        return Err(bad("the AWS region must look like us-east-1"));
    }
    if !sms.from.is_empty()
        && !(e164_ok(&sms.from) || sender_name_ok(&sms.from) || messaging_service_ok(&sms.from))
    {
        return Err(bad(
            "the SMS sender is a number like +15005550006 or a sender name of up to 11 letters and digits",
        ));
    }
    let w = &a.whatsapp;
    if !w.phone_number_id.is_empty()
        && !(w.phone_number_id.len() <= 24 && w.phone_number_id.bytes().all(|b| b.is_ascii_digit()))
    {
        return Err(bad("the WhatsApp phone number id is digits only"));
    }
    if !w.template.is_empty()
        && !(w.template.len() <= 512
            && w.template
                .bytes()
                .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_'))
    {
        return Err(bad(
            "a WhatsApp template name uses lower-case letters, digits and underscores",
        ));
    }
    if !w.language.is_empty()
        && !(w.language.len() <= 8
            && w.language
                .bytes()
                .all(|b| b.is_ascii_alphabetic() || b == b'_'))
    {
        return Err(bad("the WhatsApp template language looks like en_US"));
    }
    if s.routing.people.len() > 50 {
        return Err(bad("routing rules for at most 50 people"));
    }
    for (id, p) in &s.routing.people {
        if !crate::settings::valid_id(id, 24) {
            return Err(bad(
                "a person id uses lower-case letters, digits and dashes",
            ));
        }
        if !zone_ok(&p.time_zone) {
            return Err(bad(
                "a person's time zone must be a name such as Africa/Lagos",
            ));
        }
        for t in [&p.quiet_from, &p.quiet_to].into_iter().flatten() {
            if !hhmm(t) {
                return Err(bad("quiet hours must look like 22:00"));
            }
        }
        if p.quiet_from.is_some() != p.quiet_to.is_some() {
            return Err(bad("set both ends of a person's quiet hours, or neither"));
        }
        for n in [&p.phone, &p.whatsapp].into_iter().flatten() {
            if !e164_ok(n) {
                return Err(bad(
                    "a phone number is in international format, +2348012345678",
                ));
            }
        }
        if p.emails.len() > MAX_EMAILS || p.emails.iter().any(|m| !email_ok(m)) {
            return Err(bad("a person has at most 5 valid email addresses"));
        }
        if p.push.len() > MAX_DEVICES
            || p.push
                .iter()
                .any(|d| !crate::settings::valid_id(&d.id, 12) || !plain_text(&d.label, 40))
        {
            return Err(bad(
                "a person has at most 8 push devices, each with a short label",
            ));
        }
        if !hhmm(&p.digest.time) {
            return Err(bad("the daily summary time must look like 08:00"));
        }
        if p.kind_routes
            .iter()
            .any(|(k, v)| !RULE_KINDS.contains(&k.as_str()) || !RULE_CHOICES.contains(&v.as_str()))
        {
            return Err(bad(
                "a rule for one kind of alert is for schedule alerts, and says urgent, normal or off",
            ));
        }
        for (name, chans) in [
            ("urgent", &p.urgent.channels),
            ("normal", &p.normal.channels),
            ("daily summary", &p.digest.channels),
        ] {
            if chans.len() > 12 || chans.iter().any(|c| !channel_name_ok(c)) {
                return Err(bad(format!(
                    "the {name} route lists channels that do not exist"
                )));
            }
            let mut seen = std::collections::BTreeSet::new();
            if !chans.iter().all(|c| seen.insert(c.as_str())) {
                return Err(bad(format!("the {name} route lists a channel twice")));
            }
        }
    }
    Ok(())
}

fn plain_text_or_empty(s: &str, max: usize) -> bool {
    s.is_empty() || (s.chars().count() <= max && !s.chars().any(char::is_control))
}

fn region_ok(r: &str) -> bool {
    !r.is_empty()
        && r.len() <= 20
        && r.bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
}

/// A Twilio Messaging Service id: `MG` and 32 hex digits.
fn messaging_service_ok(s: &str) -> bool {
    s.len() == 34 && s.starts_with("MG") && s[2..].bytes().all(|b| b.is_ascii_hexdigit())
}

fn sender_name_ok(s: &str) -> bool {
    (1..=11).contains(&s.len()) && s.bytes().all(|b| b.is_ascii_alphanumeric())
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use crate::settings::Settings;

    #[test]
    fn phone_numbers_are_international() {
        assert!(e164_ok("+2348012345678"));
        assert!(e164_ok("+15005550006"));
        for b in [
            "2348012345678",
            "+0123456789",
            "+12",
            "+1234567890123456",
            "+12a4567890",
            "",
            "+",
        ] {
            assert!(!e164_ok(b), "{b}");
        }
    }

    #[test]
    fn an_old_settings_file_still_loads_and_defaults_are_the_documented_ones() {
        let s: Settings = serde_json::from_str("{}").unwrap();
        assert!(s.validate().is_ok());
        assert!(s.routing.people.is_empty());
        let p = PersonRouting::default();
        assert_eq!(p.urgent.channels, ["sms", "telegram", "push"]);
        assert!(p.urgent.bypass_quiet);
        assert_eq!(p.normal.channels, ["telegram", "slack"]);
        assert!(!p.normal.bypass_quiet);
        assert_eq!(p.digest.channels, ["email"]);
    }

    #[test]
    fn routing_is_validated() {
        let mut s = Settings::default();
        let mut p = PersonRouting::default();
        s.routing.people.insert("ada".into(), p.clone());
        assert!(s.validate().is_ok());
        for mutate in [
            (|p: &mut PersonRouting| p.phone = Some("0801".into())) as fn(&mut PersonRouting),
            |p| p.time_zone = Some("Mars/Base".into()),
            |p| p.urgent.channels = vec!["fax".into()],
            |p| p.urgent.channels = vec!["sms".into(), "sms".into()],
            |p| p.digest.time = "8am".into(),
            |p| p.quiet_from = Some("22:00".into()),
            |p| p.emails = vec!["a b@example.com".into()],
        ] {
            let mut q = p.clone();
            mutate(&mut q);
            s.routing.people.insert("ada".into(), q);
            assert!(s.validate().is_err());
        }
        p.urgent.channels = vec!["webhook:ci".into()];
        s.routing.people.insert("ada".into(), p);
        assert!(s.validate().is_ok());
        s.routing
            .people
            .insert("Bad Id".into(), PersonRouting::default());
        assert!(s.validate().is_err());
    }

    #[test]
    fn channel_settings_are_validated() {
        let mut s = Settings::default();
        s.apps.sms.from = "+15005550006".into();
        assert!(s.validate().is_ok());
        s.apps.sms.from = "Oz Box!".into();
        assert!(s.validate().is_err());
        s.apps.sms.from = "MG01234567890123456789012345678901".into();
        assert!(s.validate().is_ok(), "a Twilio Messaging Service id");
        s.apps.sms.from = "MG0123456789abcdef0123456789abcdeZ".into();
        assert!(s.validate().is_err());
        s.apps.sms.from = "MG0123456789abcdef0123456789ABCDEF".into();
        assert!(s.validate().is_ok());
        s.apps.sms.from = "OzBox".into();
        s.apps.email.provider = EmailProviderKind::Smtp;
        s.apps.email.smtp.host = "smtp.example.com".into();
        assert!(s.validate().is_ok());
        s.apps.email.smtp.host = "smtp.example.com:25/x".into();
        assert!(s.validate().is_err());
    }
}
