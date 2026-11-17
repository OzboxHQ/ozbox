//! The ways an alert can leave this computer: text messages, email, chat apps and push to the installed dashboard.
//! Every channel is the owner's own account (nothing is shared), every credential is read from the secret store at the
//! moment of sending and never returned or logged, and every outbound address goes through `netguard`.
//!
//! A channel returns `Ok(detail)` or `Err(detail)`. A detail is a sentence for a person: it never holds a credential,
//! an address, a phone number or a response body.

pub mod aws;
pub mod chat;
pub mod mail;
pub mod push;
pub mod routing;
pub mod sms;
pub mod smtp;

use std::sync::Arc;

use ozbox_core::CommandRunner;

use crate::netguard::{HttpClient, HttpRequest};
use crate::secrets::SecretStore;

pub type SendResult = Result<String, String>;

/// Everything a channel needs to send. Cloned cheaply into a worker job.
#[derive(Clone)]
pub struct Ctx {
    pub secrets: Arc<dyn SecretStore>,
    pub http: Arc<dyn HttpClient>,
    pub runner: Arc<dyn CommandRunner>,
    /// The AWS profile for the channels that use the fleet's own AWS credentials. When set, those channels send through the
    /// `aws` command (which reads profiles); when not, natively with [`Ctx::aws`].
    pub aws_profile: Option<String>,
    /// The native AWS signer (credentials from the environment, or the box's role).
    pub aws: Arc<crate::aws_native::AwsJson>,
}

impl Ctx {
    pub fn secret(&self, name: &str) -> Result<Option<String>, String> {
        self.secrets.get(name).map_err(|e| e.to_string())
    }

    pub fn need(&self, name: &str, what: &str) -> Result<String, String> {
        self.secret(name)?
            .ok_or_else(|| format!("no {what} is saved"))
    }

    /// Send one request and say what happened in words. `interpret` reads the status and the body, which a few
    /// services use to report a refusal inside an HTTP 200.
    pub fn call(
        &self,
        req: HttpRequest,
        interpret: impl Fn(u16, &str) -> SendResult,
    ) -> SendResult {
        match self.http.send(&req) {
            Ok(r) => interpret(r.status, &r.body),
            Err(e) => Err(e.to_string()),
        }
    }
}

pub fn http_detail(status: u16) -> String {
    format!("the service answered HTTP {status}")
}

/// The usual reading of a status when the body says nothing more.
pub fn by_status(status: u16, _body: &str) -> SendResult {
    if (200..300).contains(&status) {
        Ok("sent".into())
    } else {
        Err(http_detail(status))
    }
}

/// Whether a failed delivery is worth trying again: the service or the network had a bad moment. A refusal (bad
/// credentials, a wrong number, a blocked address) never is.
pub fn retryable(detail: &str) -> bool {
    if detail == "the request did not complete" {
        return true;
    }
    detail
        .strip_prefix("the service answered HTTP ")
        .and_then(|s| s.parse::<u16>().ok())
        .is_some_and(|c| c == 429 || c == 408 || (500..600).contains(&c))
        || detail.ends_with("(try again)")
}

pub use crate::notify_config::e164_ok;

/// Cut a text to at most `max` characters, ending in an ellipsis when something was removed.
pub fn clip(text: &str, max: usize) -> String {
    if text.chars().count() <= max {
        return text.to_string();
    }
    let mut out: String = text.chars().take(max.saturating_sub(1)).collect();
    out.push('\u{2026}');
    out
}

/// No line breaks or other control characters: for anything that becomes a header or a subject.
pub fn one_line(text: &str) -> String {
    text.chars()
        .map(|c| if c.is_control() { ' ' } else { c })
        .collect::<String>()
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ")
}

/// `application/x-www-form-urlencoded` encoding of key/value pairs.
pub fn form_encode(pairs: &[(&str, &str)]) -> String {
    fn enc(s: &str, out: &mut String) {
        for b in s.bytes() {
            match b {
                b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                    out.push(b as char)
                }
                b' ' => out.push('+'),
                _ => out.push_str(&format!("%{b:02X}")),
            }
        }
    }
    let mut out = String::new();
    for (i, (k, v)) in pairs.iter().enumerate() {
        if i > 0 {
            out.push('&');
        }
        enc(k, &mut out);
        out.push('=');
        enc(v, &mut out);
    }
    out
}

/// Standard base64 with padding (for HTTP basic authentication).
pub fn b64_std(data: &[u8]) -> String {
    const T: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::with_capacity(data.len().div_ceil(3) * 4);
    for chunk in data.chunks(3) {
        let n = (u32::from(chunk[0]) << 16)
            | (u32::from(*chunk.get(1).unwrap_or(&0)) << 8)
            | u32::from(*chunk.get(2).unwrap_or(&0));
        for i in 0..4 {
            if i <= chunk.len() {
                out.push(T[((n >> (18 - 6 * i)) & 63) as usize] as char);
            } else {
                out.push('=');
            }
        }
    }
    out
}

/// A short unique-looking seed for a Message-ID, from the time and the subject.
pub fn smtp_seed(now_secs: u64, subject: &str) -> String {
    let d = ring::digest::digest(
        &ring::digest::SHA256,
        format!("{now_secs}:{subject}").as_bytes(),
    );
    crate::notify::hex(&d.as_ref()[..8])
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
pub mod testing {
    use super::*;
    use crate::netguard::FakeHttp;
    use crate::secrets::MemorySecrets;
    use ozbox_core::RecordingRunner;

    pub struct Rig {
        pub ctx: Ctx,
        pub http: Arc<FakeHttp>,
        pub secrets: Arc<MemorySecrets>,
        pub runner: Arc<RecordingRunner>,
    }

    /// A rig whose AWS credentials come from no metadata service at all (nothing listens on the address).
    pub fn rig() -> Rig {
        rig_with_aws("http://127.0.0.1:9")
    }

    /// A rig whose AWS credentials come from the fake metadata service at `imds`.
    pub fn rig_with_aws(imds: &str) -> Rig {
        let http = Arc::new(FakeHttp::default());
        let secrets = Arc::new(MemorySecrets::default());
        let runner = Arc::new(RecordingRunner::new());
        Rig {
            ctx: Ctx {
                secrets: secrets.clone(),
                http: http.clone(),
                runner: runner.clone(),
                aws_profile: None,
                aws: Arc::new(crate::aws_native::AwsJson::with_imds(imds)),
            },
            http,
            secrets,
            runner,
        }
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn form_encoding_escapes_everything_that_matters() {
        assert_eq!(
            form_encode(&[("To", "+15005550006"), ("Body", "a&b=c d\u{e9}")]),
            "To=%2B15005550006&Body=a%26b%3Dc+d%C3%A9"
        );
    }

    #[test]
    fn base64_matches_the_standard_vectors() {
        assert_eq!(b64_std(b""), "");
        assert_eq!(b64_std(b"f"), "Zg==");
        assert_eq!(b64_std(b"fo"), "Zm8=");
        assert_eq!(b64_std(b"foo"), "Zm9v");
        assert_eq!(b64_std(b"foobar"), "Zm9vYmFy");
    }

    #[test]
    fn only_a_bad_moment_is_retried() {
        assert!(retryable("the request did not complete"));
        assert!(retryable("the service answered HTTP 503"));
        assert!(retryable("the service answered HTTP 429"));
        assert!(!retryable("the service answered HTTP 401"));
        assert!(!retryable(
            "that address resolves to a private or reserved network and is refused"
        ));
        assert!(!retryable("no key is saved"));
    }

    #[test]
    fn clipping_counts_characters_and_one_line_removes_breaks() {
        assert_eq!(clip("abcdef", 4), "abc\u{2026}");
        assert_eq!(clip("abc", 4), "abc");
        assert_eq!(clip("\u{e9}\u{e9}\u{e9}\u{e9}", 3), "\u{e9}\u{e9}\u{2026}");
        assert_eq!(one_line("a\r\nBcc: x\tb"), "a Bcc: x b");
    }
}
