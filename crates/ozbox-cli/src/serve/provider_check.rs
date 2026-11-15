//! `GET /v1/provider/check`: whether the provider this dashboard is connected to answers, asked now.
//!
//! The Providers page used to show "Connected" whenever the server had answered `/v1/info`, which says nothing about the
//! provider (the fake one always "answers"). This asks the provider a read-only question (list the
//! boxes it sees) and reports what came back, in words a person can act on. Nothing is changed, and nothing from the
//! provider's account is returned beyond how many boxes it listed and where it looked: a failure comes back as a reason
//! class and the provider's words with ARNs, account numbers, key ids, addresses and host names removed. The answer is
//! reused for ten seconds, so a viewer pressing Check now cannot run the listing on the server loop again and again.

use serde_json::json;

use super::{unix_ms, App, FleetMode, Resp};

/// An error from a provider can carry a long command line's output; a person needs the start of it.
const MAX_ERROR_CHARS: usize = 300;

/// How long the last check is reused: "Check now" pressed again and again must not run the full listing each time.
const REUSE: std::time::Duration = std::time::Duration::from_secs(10);

/// An account number is twelve digits; an access key id is `AKIA`/`ASIA` and sixteen more characters.
fn scrub_ids(t: &str) -> String {
    let c: Vec<char> = t.chars().collect();
    let mut out = String::new();
    let mut i = 0;
    while i < c.len() {
        if c[i].is_ascii_digit() {
            let mut j = i;
            while j < c.len() && c[j].is_ascii_digit() {
                j += 1;
            }
            if j - i == 12 {
                out.push_str("<account>");
            } else {
                out.push_str(&t_slice(&c, i, j));
            }
            i = j;
            continue;
        }
        if c[i].is_ascii_uppercase() {
            let mut j = i;
            while j < c.len() && (c[j].is_ascii_uppercase() || c[j].is_ascii_digit()) {
                j += 1;
            }
            let w = t_slice(&c, i, j);
            let key = j - i == 20 && (w.starts_with("AKIA") || w.starts_with("ASIA"));
            out.push_str(if key { "<key>" } else { w.as_str() });
            i = j;
            continue;
        }
        out.push(c[i]);
        i += 1;
    }
    out
}

fn t_slice(c: &[char], a: usize, b: usize) -> String {
    c[a..b].iter().collect()
}

/// A word that is a host name (`ec2.us-east-1.amazonaws.com`, optionally with a port).
fn is_host(w: &str) -> bool {
    let w = w.split(':').next().unwrap_or(w);
    let parts: Vec<&str> = w.split('.').collect();
    parts.len() >= 2
        && parts
            .iter()
            .all(|p| !p.is_empty() && p.chars().all(|c| c.is_ascii_alphanumeric() || c == '-'))
        && parts
            .last()
            .is_some_and(|t| t.len() >= 2 && t.chars().all(|c| c.is_ascii_alphabetic()))
        && w.len() >= 6
}

/// What a viewer may be told about a provider's failure: ARNs, account numbers, access key ids, addresses and host names
/// are replaced, because the provider's own words name the account and the identity that was refused.
pub(super) fn redact(s: &str) -> String {
    s.split_whitespace()
        .map(|w| {
            let lead: String = w.chars().take_while(|c| !c.is_alphanumeric()).collect();
            let core = w[lead.len()..].trim_end_matches(|c: char| !c.is_alphanumeric());
            let tail = &w[lead.len() + core.len()..];
            let body = if let Some(i) = core.find("arn:") {
                format!("{}arn:…", &core[..i])
            } else if core.contains("://") {
                "<url>".to_string()
            } else if is_host(core) {
                "<host>".to_string()
            } else {
                scrub_ids(core)
            };
            format!("{lead}{body}{tail}")
        })
        .collect::<Vec<_>>()
        .join(" ")
}

/// A short, redacted reason for a viewer.
pub(super) fn safe_error(s: &str) -> String {
    let one_line = redact(s);
    if one_line.chars().count() <= MAX_ERROR_CHARS {
        return one_line;
    }
    let cut: String = one_line.chars().take(MAX_ERROR_CHARS).collect();
    format!("{cut}…")
}

/// The class of a failure, from the provider's own words, so the page can say what to do without showing them.
fn reason_class(s: &str) -> &'static str {
    let l = s.to_lowercase();
    let has = |ws: &[&str]| ws.iter().any(|w| l.contains(w));
    if has(&["expired", "sso session", "token has expired"]) {
        "credentials_expired"
    } else if has(&[
        "accessdenied",
        "not authorized",
        "unauthorizedoperation",
        "forbidden",
        "permission",
    ]) {
        "not_permitted"
    } else if has(&[
        "invalidclienttokenid",
        "signaturedoesnotmatch",
        "unable to locate credentials",
        "security token",
        "credentials",
        "unauthenticated",
    ]) {
        "credentials_refused"
    } else if has(&[
        "timed out",
        "timeout",
        "could not connect",
        "connection",
        "dns",
        "network",
        "resolve",
    ]) {
        "network"
    } else {
        "other"
    }
}

impl App {
    pub(super) fn provider_check(&mut self) -> Resp {
        if let Some((at, body)) = &self.provider_check_last {
            if at.elapsed() < REUSE {
                return Resp::json(200, body);
            }
        }
        let mode = match self.fleet_mode() {
            FleetMode::Connected => "connected",
            FleetMode::ThisBox => "this_box",
            FleetMode::Demo => "demo",
        };
        let started = std::time::Instant::now();
        let listed = self.provider.list();
        let (ok, boxes, error, reason) = match &listed {
            Ok(v) => (true, Some(v.len()), None, None),
            Err(e) => {
                let raw = e.to_string();
                (
                    false,
                    None,
                    Some(safe_error(&raw)),
                    Some(reason_class(&raw)),
                )
            }
        };
        let body = json!({
            "mode": mode,
            "provider": self.provider_id,
            // a demo "answers" too: the mode says it is not real
            "ok": ok,
            "boxes": boxes,
            "searched": self.provider.searched(),
            "error": error,
            "reason": reason,
            "checked_ms": unix_ms(),
            "took_ms": u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX),
        });
        self.provider_check_last = Some((std::time::Instant::now(), body.clone()));
        Resp::json(200, &body)
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use crate::serve::Req;
    use ozbox_core::{BoxName, BoxRecord, Error, Operation, Plan, Provider};
    use serde_json::Value;
    use std::collections::HashMap;
    use std::net::{IpAddr, Ipv4Addr, SocketAddr};

    const TOKEN: &str = "test-token";

    fn get(a: &mut App, path: &str) -> (u16, Value) {
        let mut headers = HashMap::new();
        headers.insert("host".to_string(), "127.0.0.1:7878".to_string());
        headers.insert("authorization".to_string(), format!("Bearer {TOKEN}"));
        let r = a.handle(&Req {
            method: "GET".into(),
            path: path.into(),
            query: String::new(),
            headers,
            body: Vec::new(),
        });
        (r.status, serde_json::from_slice(&r.body).unwrap())
    }

    /// A provider whose account refuses the question, as an expired credential does.
    struct Refusing {
        inner: ozbox_core::Engine<ozbox_provider_fake::FakeBackend>,
        msg: String,
    }

    impl Provider for Refusing {
        fn id(&self) -> &str {
            "aws"
        }
        fn capabilities(&self) -> ozbox_core::Capabilities {
            self.inner.capabilities()
        }
        fn list(&self) -> ozbox_core::Result<Vec<BoxRecord>> {
            Err(Error::Provider(self.msg.clone()))
        }
        fn searched(&self) -> Vec<String> {
            vec!["eu-west-1".into()]
        }
        fn get(&self, n: &BoxName) -> ozbox_core::Result<Option<BoxRecord>> {
            self.inner.get(n)
        }
        fn plan(&self, op: &Operation) -> ozbox_core::Result<Plan> {
            self.inner.plan(op)
        }
        fn apply(&self, plan: &Plan) -> ozbox_core::Result<Option<BoxRecord>> {
            self.inner.apply(plan)
        }
    }

    fn addr() -> SocketAddr {
        SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 7878)
    }

    #[test]
    fn the_demo_answers_but_says_it_is_the_demo() {
        let dir = tempfile::tempdir().unwrap();
        let mut a = App::new(
            Box::new(ozbox_provider_fake::open(dir.path())),
            true,
            addr(),
            TOKEN.into(),
        );
        let (st, v) = get(&mut a, "/v1/provider/check");
        assert_eq!(st, 200);
        assert_eq!(v["mode"], "demo");
        assert_eq!(v["ok"], true);
        assert!(v["error"].is_null());
    }

    #[test]
    fn a_box_checks_itself_and_says_so() {
        let facts = crate::this_box::Facts {
            hostname: Some("main".into()),
            vcpus: Some(8),
            memory_gb: Some(32),
            work_disk_gb: Some(300),
            image_release: None,
        };
        let mut a = App::new(
            Box::new(crate::this_box::ThisBoxProvider::from_facts(&facts)),
            false,
            addr(),
            TOKEN.into(),
        );
        let (_, v) = get(&mut a, "/v1/provider/check");
        assert_eq!(v["mode"], "this_box");
        assert_eq!(v["ok"], true);
        assert_eq!(v["boxes"], 1);
    }

    #[test]
    fn a_provider_that_refuses_is_reported_as_failed_with_a_short_reason() {
        let dir = tempfile::tempdir().unwrap();
        let mut a = App::new(
            Box::new(Refusing {
                inner: ozbox_provider_fake::open(dir.path()),
                msg: format!("the credentials were refused {}", "x".repeat(600)),
            }),
            false,
            addr(),
            TOKEN.into(),
        );
        let (st, v) = get(&mut a, "/v1/provider/check");
        assert_eq!(st, 200, "a failed check is an answer, not a server error");
        assert_eq!(v["mode"], "connected");
        assert_eq!(v["provider"], "aws");
        assert_eq!(v["ok"], false);
        assert!(v["boxes"].is_null());
        let e = v["error"].as_str().unwrap();
        assert!(e.contains("credentials were refused"));
        assert!(e.chars().count() <= 301, "the reason is cut short");
        assert_eq!(v["searched"][0], "eu-west-1");
    }

    #[test]
    fn an_aws_access_denied_names_no_account_identity_key_or_address() {
        let dir = tempfile::tempdir().unwrap();
        let raw = format!("An error occurred (UnauthorizedOperation): User: arn:aws:iam::123456789012:user/x is not authorized to perform: \
            ec2:DescribeInstances on resource: arn:aws:ec2:eu-west-1:123456789012:instance/* (key AKIA{}) \
            see https://d-123.awsapps.com/start via ec2.eu-west-1.amazonaws.com",
            "ABCDEFGHIJKLMNOP"
        );
        let mut a = App::new(
            Box::new(Refusing {
                inner: ozbox_provider_fake::open(dir.path()),
                msg: raw,
            }),
            false,
            addr(),
            TOKEN.into(),
        );
        let (_, v) = get(&mut a, "/v1/provider/check");
        let e = v["error"].as_str().unwrap();
        for leak in [
            "123456789012",
            "arn:aws",
            "iam::",
            "AKIA",
            "awsapps",
            "amazonaws",
        ] {
            assert!(!e.contains(leak), "{leak} leaked: {e}");
        }
        assert!(e.contains("not authorized"), "{e}");
        assert_eq!(v["reason"], "not_permitted");
        // the same text through the boxes list
        let (st, b) = get(&mut a, "/v1/boxes");
        assert_eq!(st, 502);
        let m = b.to_string();
        assert!(!m.contains("123456789012") && !m.contains("arn:aws"), "{m}");
    }

    #[test]
    fn a_second_check_within_ten_seconds_is_the_first_answer() {
        let dir = tempfile::tempdir().unwrap();
        let mut a = App::new(
            Box::new(ozbox_provider_fake::open(dir.path())),
            true,
            addr(),
            TOKEN.into(),
        );
        let (_, one) = get(&mut a, "/v1/provider/check");
        let (_, two) = get(&mut a, "/v1/provider/check");
        assert_eq!(
            one["checked_ms"], two["checked_ms"],
            "reused, not asked again"
        );
    }
}
