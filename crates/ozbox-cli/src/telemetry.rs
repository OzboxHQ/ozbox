//! Opt-in usage telemetry (ADR 0029). Off until the person runs `ozbox telemetry on --endpoint <https address>`, to an
//! address the person chooses: Oz Box hosts no collector. Nothing is read, written or sent while it is off.
//!
//! The whole event is [`Event`]: a schema number, the program's version, the operating system and CPU family, the day
//! (UTC), the provider's kind (`fake`, `hcloud`, `aws`) and a bucket for the number of boxes. No box name, host name,
//! path, prompt, key, account or address is in it, and there is no identifier of this installation. `ozbox telemetry
//! preview` prints the exact bytes `send` posts, built by the same function.

use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::netguard::{Guard, HttpClient, HttpRequest};

/// The event's shape version. A field is only ever added; a new meaning is a new number.
pub const SCHEMA: u32 = 1;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(default, deny_unknown_fields)]
pub struct Settings {
    pub enabled: bool,
    pub endpoint: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Event {
    pub schema: u32,
    pub ozbox_version: String,
    pub os: String,
    pub arch: String,
    pub day: String,
    pub provider: String,
    pub boxes: String,
}

/// 0, 1, 2-5, 6-20 or 21+: a count, but never an exact one.
pub fn bucket(n: usize) -> &'static str {
    match n {
        0 => "0",
        1 => "1",
        2..=5 => "2-5",
        6..=20 => "6-20",
        _ => "21+",
    }
}

fn provider_word(p: &str) -> &'static str {
    match p {
        "fake" => "fake",
        "hcloud" => "hcloud",
        "aws" => "aws",
        "plugin" => "plugin",
        _ => "unset",
    }
}

fn bucket_word(b: &str) -> &'static str {
    ["0", "1", "2-5", "6-20", "21+"]
        .into_iter()
        .find(|x| *x == b)
        .unwrap_or("unknown")
}

impl Event {
    /// `now_ms` is only used for the day. `provider` and `boxes` are matched against fixed word lists, so a value that
    /// is not one of them (a plugin's own name, a typo) becomes `unset` or `unknown` rather than being sent.
    pub fn build(
        version: &str,
        os: &str,
        arch: &str,
        now_ms: u64,
        provider: &str,
        boxes: &str,
    ) -> Event {
        Event {
            schema: SCHEMA,
            ozbox_version: version
                .chars()
                .take_while(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '-' | '+'))
                .take(40)
                .collect(),
            os: os
                .chars()
                .take_while(char::is_ascii_alphanumeric)
                .take(16)
                .collect(),
            arch: arch
                .chars()
                .take_while(|c| c.is_ascii_alphanumeric() || *c == '_')
                .take(16)
                .collect(),
            day: crate::state::format_rfc3339(now_ms)
                .chars()
                .take(10)
                .collect(),
            provider: provider_word(provider).into(),
            boxes: bucket_word(boxes).into(),
        }
    }

    /// The exact request body.
    pub fn body(&self) -> String {
        serde_json::to_string(self).unwrap_or_default()
    }
}

/// What the person's own `telemetry.toml` and the small facts file say. Both sit beside the main configuration.
pub struct Paths {
    pub settings: PathBuf,
    pub facts: PathBuf,
}

impl Paths {
    pub fn detect() -> Option<Paths> {
        let base = crate::config::Config::path()?;
        Some(Paths {
            settings: base.with_file_name("telemetry.toml"),
            facts: base.with_file_name("telemetry-facts.json"),
        })
    }
}

pub fn load(path: &Path) -> Settings {
    std::fs::read_to_string(path)
        .ok()
        .and_then(|t| toml::from_str(&t).ok())
        .unwrap_or_default()
}

pub fn save(path: &Path, s: &Settings) -> Result<(), String> {
    if let Some(dir) = path.parent() {
        let _ = std::fs::create_dir_all(dir);
    }
    let text = toml::to_string_pretty(s).map_err(|e| e.to_string())?;
    std::fs::write(path, text)
        .map_err(|_| "the telemetry settings could not be written".to_string())
}

pub fn endpoint_ok(url: &str) -> bool {
    crate::tunnel::public_host(url.trim_end_matches('/')).is_ok() || {
        // a path is allowed on a collector address (https://host/path); the host is checked the same way
        url.strip_prefix("https://")
            .and_then(|r| r.split('/').next())
            .is_some_and(|h| crate::tunnel::public_host(&format!("https://{h}")).is_ok())
            && !url.contains(['?', '#', '@', ' '])
    }
}

#[derive(Debug, Default, Serialize, Deserialize)]
#[serde(default)]
struct Facts {
    boxes: String,
    provider: String,
    last_sent_day: String,
}

fn load_facts(p: &Path) -> Facts {
    std::fs::read_to_string(p)
        .ok()
        .and_then(|t| serde_json::from_str(&t).ok())
        .unwrap_or_default()
}

fn save_facts(p: &Path, f: &Facts) {
    if let Ok(t) = serde_json::to_string(f) {
        let _ = std::fs::write(p, t);
    }
}

/// Remember the size of the fleet, as a bucket, for the next event. Does nothing (not even a read of a file other than
/// the settings) while telemetry is off.
pub fn note_boxes(paths: &Paths, count: usize, provider: &str) {
    if !load(&paths.settings).enabled {
        return;
    }
    let mut f = load_facts(&paths.facts);
    f.boxes = bucket(count).to_string();
    f.provider = provider.to_string();
    save_facts(&paths.facts, &f);
}

/// The event as it would be sent now.
pub fn current_event(paths: &Paths, now_ms: u64) -> Event {
    let f = load_facts(&paths.facts);
    Event::build(
        env!("CARGO_PKG_VERSION"),
        std::env::consts::OS,
        std::env::consts::ARCH,
        now_ms,
        &f.provider,
        &f.boxes,
    )
}

#[derive(Debug, PartialEq, Eq)]
pub enum Outcome {
    /// Telemetry is off: nothing was read from the network side, nothing was sent.
    Off,
    /// Already sent today.
    Today,
    Delivered,
    Failed,
}

/// Send the event if telemetry is on and none went today. Never an error the caller must handle: a failure is a
/// `Failed` and the command that was running is unaffected. `force` is `ozbox telemetry send` (still needs `on`).
pub fn send(paths: &Paths, http: &dyn HttpClient, now_ms: u64, force: bool) -> Outcome {
    let s = load(&paths.settings);
    if !s.enabled || !endpoint_ok(&s.endpoint) {
        return Outcome::Off;
    }
    let ev = current_event(paths, now_ms);
    let mut facts = load_facts(&paths.facts);
    if !force && facts.last_sent_day == ev.day {
        return Outcome::Today;
    }
    let mut req = HttpRequest::new("POST", s.endpoint.clone(), Guard::Public)
        .header("content-type", "application/json");
    req.body = Some(ev.body().into_bytes());
    req.timeout = std::time::Duration::from_secs(2);
    match http.send(&req) {
        Ok(r) if (200..300).contains(&r.status) => {
            facts.last_sent_day = ev.day;
            save_facts(&paths.facts, &facts);
            Outcome::Delivered
        }
        _ => Outcome::Failed,
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use crate::netguard::{HttpError, HttpResponse};
    use std::sync::Mutex;

    #[derive(Default)]
    struct Fake {
        seen: Mutex<Vec<HttpRequest>>,
        status: u16,
    }

    impl HttpClient for Fake {
        fn send(&self, req: &HttpRequest) -> Result<HttpResponse, HttpError> {
            self.seen.lock().unwrap().push(req.clone());
            Ok(HttpResponse {
                status: self.status,
                body: String::new(),
            })
        }
    }

    fn paths() -> (tempfile::TempDir, Paths) {
        let d = tempfile::tempdir().unwrap();
        let p = Paths {
            settings: d.path().join("telemetry.toml"),
            facts: d.path().join("facts.json"),
        };
        (d, p)
    }

    fn on(p: &Paths) {
        save(
            &p.settings,
            &Settings {
                enabled: true,
                endpoint: "https://collect.example.com/ozbox".into(),
            },
        )
        .unwrap();
    }

    const NOW: u64 = 1_794_000_000_000;

    #[test]
    fn nothing_is_sent_and_no_file_is_written_while_it_is_off() {
        let (d, p) = paths();
        let http = Fake {
            status: 200,
            ..Default::default()
        };
        assert_eq!(send(&p, &http, NOW, false), Outcome::Off);
        assert_eq!(send(&p, &http, NOW, true), Outcome::Off);
        note_boxes(&p, 3, "aws");
        assert!(http.seen.lock().unwrap().is_empty());
        assert_eq!(std::fs::read_dir(d.path()).unwrap().count(), 0);
        // on, but no usable address: still nothing
        save(
            &p.settings,
            &Settings {
                enabled: true,
                endpoint: String::new(),
            },
        )
        .unwrap();
        assert_eq!(send(&p, &http, NOW, true), Outcome::Off);
        assert!(http.seen.lock().unwrap().is_empty());
    }

    #[test]
    fn the_preview_is_the_body_that_is_sent() {
        let (_d, p) = paths();
        on(&p);
        note_boxes(&p, 4, "aws");
        let http = Fake {
            status: 204,
            ..Default::default()
        };
        let preview = current_event(&p, NOW).body();
        assert_eq!(send(&p, &http, NOW, false), Outcome::Delivered);
        let seen = http.seen.lock().unwrap();
        assert_eq!(seen[0].body.as_deref(), Some(preview.as_bytes()));
        assert_eq!(seen[0].method, "POST");
        assert_eq!(seen[0].guard, Guard::Public);
    }

    #[test]
    fn the_event_has_only_the_documented_fields_and_no_identifier() {
        let ev = Event::build("0.1.0", "linux", "x86_64", NOW, "aws", "2-5");
        let v: serde_json::Value = serde_json::from_str(&ev.body()).unwrap();
        let mut keys: Vec<_> = v.as_object().unwrap().keys().cloned().collect();
        keys.sort();
        assert_eq!(
            keys,
            [
                "arch",
                "boxes",
                "day",
                "os",
                "ozbox_version",
                "provider",
                "schema"
            ]
        );
        assert_eq!(v["day"].as_str().unwrap().len(), 10);
    }

    #[test]
    fn free_text_cannot_get_into_an_event() {
        let ev = Event::build(
            "1.0 /home/alice",
            "linux; rm",
            "x86 /home/alice",
            NOW,
            "my-secret-plugin",
            "37 boxes named x",
        );
        assert_eq!(ev.provider, "unset");
        assert_eq!(ev.boxes, "unknown");
        assert!(!ev.body().contains("alice") && !ev.body().contains('/'));
    }

    #[test]
    fn at_most_one_event_a_day_and_a_failure_is_retried() {
        let (_d, p) = paths();
        on(&p);
        let bad = Fake {
            status: 500,
            ..Default::default()
        };
        assert_eq!(send(&p, &bad, NOW, false), Outcome::Failed);
        let ok = Fake {
            status: 200,
            ..Default::default()
        };
        assert_eq!(send(&p, &ok, NOW, false), Outcome::Delivered);
        assert_eq!(send(&p, &ok, NOW + 3_600_000, false), Outcome::Today);
        assert_eq!(send(&p, &ok, NOW + 86_400_000, false), Outcome::Delivered);
    }

    #[test]
    fn buckets_never_give_an_exact_count() {
        assert_eq!(
            [bucket(0), bucket(1), bucket(3), bucket(20), bucket(21)],
            ["0", "1", "2-5", "6-20", "21+"]
        );
    }

    #[test]
    fn an_address_must_be_https_on_a_real_host() {
        assert!(endpoint_ok("https://collect.example.com"));
        assert!(endpoint_ok("https://collect.example.com/v1/ozbox"));
        assert!(!endpoint_ok("http://collect.example.com"));
        assert!(!endpoint_ok("https://127.0.0.1/x"));
        assert!(!endpoint_ok("https://user@collect.example.com"));
        assert!(!endpoint_ok("https://collect.example.com/x?a=b"));
    }
}
