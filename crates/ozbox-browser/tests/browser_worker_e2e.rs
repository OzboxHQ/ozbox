//! The worker against a real Chromium and the local test site: approvals pause, refusals hold, a challenge is handed to a
//! person, take-over blocks the agent, downloads are sorted, extraction follows its schema, robots.txt is honoured, the
//! recording holds no typed value, a limit pauses the task cleanly and it resumes.
//!
//! Skips (with a message) when no Chromium is installed, unless `OZBOX_REQUIRE_BROWSER=1`, which is how CI runs it.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::path::Path;

use ozbox_browser::channel::{Channel, SessionKey};
use ozbox_browser::policy::{BrowserPolicy, Device};
use ozbox_browser::protocol::{Action, Grant, Op, Request, Start};
use ozbox_browser::testsite;
use ozbox_browser::worker::Worker;
use serde_json::{json, Value};

fn have_browser() -> bool {
    if ozbox_browser::cdp::find_chromium().is_some() {
        return true;
    }
    assert!(
        std::env::var("OZBOX_REQUIRE_BROWSER").is_err(),
        "OZBOX_REQUIRE_BROWSER is set but no Chromium is installed"
    );
    eprintln!("skipped: no Chromium on this machine");
    false
}

struct H {
    w: Worker,
    n: u64,
    /// The tool host's end of the channel: what mints a person's grant in these tests.
    host: Channel,
}

impl H {
    fn open(
        root: &Path,
        session: &str,
        device: Device,
        policy: BrowserPolicy,
        allowed: &[&str],
    ) -> Self {
        Self::open_in(root, None, session, device, policy, allowed)
    }

    /// With a private root: the layout of a worker that runs as a user of its own (ADR 0037, amendment 4).
    fn open_in(
        root: &Path,
        private_root: Option<&Path>,
        session: &str,
        device: Device,
        policy: BrowserPolicy,
        allowed: &[&str],
    ) -> Self {
        std::env::set_var("OZBOX_BROWSER_NO_SANDBOX", "1");
        let key = SessionKey::generate().unwrap();
        let host = Channel::host(&key, session).unwrap();
        let start = Start {
            session: session.into(),
            key,
            root: root.to_string_lossy().into(),
            work: root.to_string_lossy().into(),
            device,
            policy,
            allowed_hosts: allowed.iter().map(|s| (*s).to_string()).collect(),
            run: None,
            private_root: private_root.map(|p| p.to_string_lossy().into()),
            memory_max_bytes: None,
            max_runtime_s: None,
        };
        Self {
            w: Worker::open(start).expect("the worker opens"),
            n: 0,
            host,
        }
    }
    fn op(&mut self, op: Op) -> ozbox_browser::protocol::Reply {
        self.n += 1;
        self.w.handle(Request { id: self.n, op }).0
    }
    fn preview(&mut self, a: Action) -> ozbox_browser::protocol::Reply {
        self.op(Op::Preview { action: a })
    }
    /// Act; with `approved`, as a person who approved what the preview showed (a fresh approval id each time).
    fn act(&mut self, a: Action, approved: bool) -> ozbox_browser::protocol::Reply {
        let grant = if approved {
            let p = self.preview(a.clone());
            Some(self.grant(&a, &p.result, &format!("a{}", self.n)))
        } else {
            None
        };
        self.op(Op::Act { action: a, grant })
    }
    fn grant(&self, a: &Action, preview: &Value, approval: &str) -> Grant {
        let fp = preview["fingerprint"].as_str().unwrap_or("").to_string();
        let risk = preview["risk"].as_str().unwrap_or("").to_string();
        Grant {
            mac: self.host.grant(approval, &fp, &risk, &a.grant_bytes()),
            approval: approval.into(),
            fingerprint: fp,
            risk,
        }
    }
    fn ok(&mut self, a: Action) -> Value {
        let r = self.act(a.clone(), false);
        assert!(r.ok, "{a:?} failed: {:?} {:?}", r.code, r.error);
        r.result
    }
    fn snap(&mut self) -> String {
        self.ok(Action::Snapshot)["snapshot"]
            .as_str()
            .unwrap_or("")
            .to_string()
    }
    /// The element name of the first line that has `needle`.
    fn r#ref(&mut self, needle: &str) -> String {
        let s = self.snap();
        s.lines()
            .find(|l| l.contains(needle))
            .and_then(|l| l.strip_prefix('[')?.split(' ').next())
            .unwrap_or_else(|| panic!("no element with {needle} in:\n{s}"))
            .to_string()
    }
}

fn url(port: u16, host: &str, p: &str) -> String {
    format!("http://{host}:{port}{p}")
}

fn read_all(dir: &Path, out: &mut String) {
    for e in std::fs::read_dir(dir).into_iter().flatten().flatten() {
        let p = e.path();
        if p.is_dir() {
            read_all(&p, out);
        } else if let Ok(b) = std::fs::read(&p) {
            out.push_str(&String::from_utf8_lossy(&b));
        }
    }
}

#[test]
fn the_desktop_session_end_to_end() {
    desktop_session(false);
}

/// The same session with a private root (a worker that runs as a user of its own): downloads, held-back files and the
/// recording end up where ADR 0037 amendment 4 says.
#[cfg(unix)]
#[test]
fn the_desktop_session_with_a_private_root() {
    desktop_session(true);
}

fn desktop_session(private: bool) {
    if !have_browser() {
        return;
    }
    let site = testsite::start(0).unwrap();
    let port = site.port;
    let dir = tempfile::tempdir().unwrap();
    let (root, private_root) = if private {
        (dir.path().join("shared"), Some(dir.path().join("private")))
    } else {
        (dir.path().to_path_buf(), None)
    };
    std::fs::create_dir_all(&root).unwrap();
    if let Some(p) = &private_root {
        std::fs::create_dir_all(p).unwrap();
        // as the setup makes the shared root: setgid, in the group the box's other users are in
        #[cfg(unix)]
        make_group_shared(&root);
    }
    let policy = BrowserPolicy {
        min_gap_ms: 0,
        ..BrowserPolicy::default()
    };
    let mut h = H::open_in(
        &root,
        private_root.as_deref(),
        "desk",
        Device::Desktop,
        policy,
        &["blocked.localhost"],
    );
    let local = "127.0.0.1";

    // --- a login: typing is free, the password never shows, the submit asks
    h.ok(Action::Navigate {
        url: url(port, local, "/login"),
    });
    let user = h.r#ref("\"Username\"");
    let pass = h.r#ref("\"Password\"");
    h.ok(Action::Type {
        target: user,
        text: "ada".into(),
        submit: false,
        clear: true,
    });
    h.ok(Action::Type {
        target: pass,
        text: "SENTINEL-pw1".into(),
        submit: false,
        clear: true,
    });
    let s = h.snap();
    assert!(!s.contains("SENTINEL"), "{s}");
    assert!(s.contains("value=\"[masked]\""), "{s}");
    assert!(s.contains("value=\"ada\""), "{s}");
    let sign = h.r#ref("\"Sign in\"");
    let p = h.preview(Action::Click {
        target: sign.clone(),
    });
    assert_eq!(p.result["gate"], "ask", "{:?}", p.result);
    assert_eq!(p.result["risk"], "submit");
    let masked: Vec<String> = p.result["fields"]
        .as_array()
        .unwrap()
        .iter()
        .map(|f| f["value"].as_str().unwrap().to_string())
        .collect();
    assert!(
        masked.contains(&"[masked]".to_string()) && masked.contains(&"ada".to_string()),
        "{masked:?}"
    );
    assert!(!p.result.to_string().contains("SENTINEL"));
    let refused = h.act(
        Action::Click {
            target: sign.clone(),
        },
        false,
    );
    assert!(!refused.ok && refused.code.as_deref() == Some("risk"));
    assert!(
        site.posts.0.lock().unwrap().is_empty(),
        "nothing is sent before approval"
    );
    let sent = h.act(Action::Click { target: sign }, true);
    assert!(sent.ok, "{:?}", sent.error);
    assert_eq!(site.posts.0.lock().unwrap().len(), 1);
    assert!(h.snap().contains("Signed in"));

    // --- a checkout is refused for the agent even when approval is offered
    h.ok(Action::Navigate {
        url: url(port, local, "/checkout"),
    });
    let card = h.r#ref("\"Card number\"");
    h.ok(Action::Type {
        target: card,
        text: "4111 1111 1111 1111".into(),
        submit: false,
        clear: true,
    });
    let place = h.r#ref("\"Place order\"");
    let p = h.preview(Action::Click {
        target: place.clone(),
    });
    assert_eq!(p.result["risk"], "payment");
    assert_eq!(p.result["gate"], "refuse");
    let r = h.act(Action::Click { target: place }, true);
    assert!(!r.ok && r.code.as_deref() == Some("risk"), "{r:?}");
    assert!(!site
        .posts
        .0
        .lock()
        .unwrap()
        .iter()
        .any(|(p, _)| p == "/pay"));

    // --- posting a message asks, and a page-initiated non-GET is not let through without approval
    h.ok(Action::Navigate {
        url: url(port, local, "/post"),
    });
    let post = h.r#ref("\"Post reply\"");
    assert_eq!(
        h.preview(Action::Click { target: post }).result["risk"],
        "send"
    );

    // --- a new domain asks first
    let p = h.preview(Action::Navigate {
        url: "https://elsewhere.invalid/".into(),
    });
    assert_eq!(p.result["risk"], "new_domain");
    assert_eq!(p.result["gate"], "ask");

    // --- robots.txt is honoured on a site that is not the box's own, and a page it allows opens
    let r = h.act(
        Action::Navigate {
            url: url(port, "blocked.localhost", "/secret/page"),
        },
        true,
    );
    assert!(!r.ok && r.code.as_deref() == Some("robots"), "{r:?}");
    let r = h.act(
        Action::Navigate {
            url: url(port, "blocked.localhost", "/"),
        },
        true,
    );
    assert!(r.ok, "{:?}", r.error);

    // --- extraction to a schema, and what does not fit is refused
    h.ok(Action::Navigate {
        url: url(port, local, "/data"),
    });
    let schema = json!({
        "type": "object", "required": ["title", "price", "tags", "rows"],
        "properties": {
            "title": { "type": "string", "x-selector": "h1" },
            "price": { "type": "number", "x-selector": ".price" },
            "tags": { "type": "array", "x-selector": ".tag", "items": { "type": "string" } },
            "rows": { "type": "array", "x-selector": ".row", "items": { "type": "object", "properties": {
                "name": { "type": "string", "x-selector": ".n" }, "qty": { "type": "integer", "x-selector": ".q" } } } },
            "note": { "type": "string", "x-selector": "p:last-of-type" }
        }
    });
    let d = h.ok(Action::Extract {
        schema: schema.clone(),
    });
    assert_eq!(d["data"]["title"], "Blue mug");
    assert_eq!(d["data"]["price"], 12.5);
    assert_eq!(d["data"]["tags"], json!(["ceramic", "blue"]));
    assert_eq!(
        d["data"]["rows"],
        json!([{ "name": "Alpha", "qty": 3 }, { "name": "Beta", "qty": 5 }])
    );
    assert!(
        d["data"]["note"].as_str().unwrap().contains("[masked]") && !d.to_string().contains("4111"),
        "{d}"
    );
    let mut bad = schema;
    bad["properties"]["title"]["type"] = json!("integer");
    let r = h.act(Action::Extract { schema: bad }, false);
    assert!(!r.ok && r.code.as_deref() == Some("schema"));

    // --- downloads: documents open, programs and disguised programs are held
    h.ok(Action::Navigate {
        url: url(port, local, "/downloads"),
    });
    for name in ["\"Report\"", "\"Tool\"", "\"Disguised\""] {
        let t = h.r#ref(name);
        h.ok(Action::Click { target: t });
        std::thread::sleep(std::time::Duration::from_millis(600));
    }
    let mut list = h.ok(Action::Downloads);
    for _ in 0..60 {
        if list["downloads"].as_array().map_or(0, Vec::len) >= 3 {
            break;
        }
        std::thread::sleep(std::time::Duration::from_millis(300));
        list = h.ok(Action::Downloads);
    }
    let class = |n: &str| {
        list["downloads"]
            .as_array()
            .unwrap()
            .iter()
            .find(|d| d["name"] == n)
            .map(|d| d["class"]["class"].as_str().unwrap().to_string())
    };
    assert_eq!(class("report.pdf").as_deref(), Some("document"), "{list}");
    assert_eq!(class("tool.sh").as_deref(), Some("quarantine"), "{list}");
    assert_eq!(
        class("disguised.pdf").as_deref(),
        Some("quarantine"),
        "{list}"
    );
    let p = h.preview(Action::OpenDownload {
        name: "tool.sh".into(),
    });
    assert_eq!(
        (p.result["risk"].as_str(), p.result["gate"].as_str()),
        (Some("program"), Some("ask"))
    );
    assert_eq!(
        h.preview(Action::OpenDownload {
            name: "report.pdf".into()
        })
        .result["gate"],
        "allow"
    );
    let released = root.join("sessions/desk/downloads/report.pdf");
    assert!(released.is_file());
    assert_eq!(
        ozbox_browser::record::load_meta(&root, "desk")
            .unwrap()
            .isolated,
        private,
        "the recording says which posture the session had"
    );
    if private {
        // the held-back program is in the private root, in a folder only the worker opens, and not in the shared recording;
        // the released document is readable by the box's group
        #[cfg(unix)]
        {
            let held = dir.path().join("private/held/desk");
            assert!(held.join("tool.sh").is_file() && held.join("disguised.pdf").is_file());
            assert_eq!(mode(&held), 0o700);
            assert_eq!(mode(&released), 0o640);
            assert_eq!(mode(&root.join("sessions/desk")), 0o750);
            assert_eq!(mode(&root.join("sessions/desk/downloads")), 0o750);
            // The group is what lets the dashboard and the agent read what the worker wrote: every file the worker made, and
            // the released document, has the group of the shared root, and the setgid bit that gives it is still on the folders
            // (a `chmod` to 0750 clears it, and a rename keeps the file's old group).
            let g = gid(&root);
            for f in [
                root.join("sessions/desk/meta.json"),
                root.join("sessions/desk/steps.jsonl"),
                released.clone(),
                root.join("sessions/desk"),
                root.join("sessions/desk/downloads"),
                root.join("sessions/desk/shots"),
            ] {
                assert_eq!(gid(&f), g, "{}", f.display());
            }
            assert!(raw_mode(&root) & 0o2000 != 0);
            // (a folder made inside a setgid one inherits the bit on Linux; on macOS the group is inherited without it)
            #[cfg(target_os = "linux")]
            for d in [
                &root.join("sessions/desk"),
                &root.join("sessions/desk/downloads"),
            ] {
                assert!(
                    raw_mode(d) & 0o2000 != 0,
                    "setgid is kept on {}",
                    d.display()
                );
            }
        }
        assert!(!root.join("sessions/desk/downloads/.quarantine").exists());
        assert!(!root.join("sessions/desk/downloads/tool.sh").exists());
        // opening the held-back file (approved) releases it into the shared downloads, readable by the group
    } else {
        assert!(root
            .join("sessions/desk/downloads/.quarantine/tool.sh")
            .is_file());
    }

    // --- a challenge goes to a person: the agent is refused while they hold it
    let r = h.act(
        Action::Navigate {
            url: url(port, local, "/captcha"),
        },
        false,
    );
    assert!(r.ok, "{:?}", r.error);
    assert!(r.result["handoff"]["reason"].is_string(), "{:?}", r.result);
    let blocked = h.act(Action::Snapshot, false);
    assert!(
        !blocked.ok && blocked.code.as_deref() == Some("person_holds"),
        "{blocked:?}"
    );
    assert_eq!(
        h.preview(Action::Snapshot).code.as_deref(),
        Some("person_holds")
    );
    assert_eq!(h.op(Op::Status).result["control"], "person");
    // handing back while the check is still showing is refused
    let r = h.op(Op::Handback);
    assert!(!r.ok && r.code.as_deref() == Some("challenge"), "{r:?}");
    // the person does the check and continues: Tab to the link, Enter
    for k in ["Tab", "Tab", "Enter"] {
        let r = h.op(Op::Input {
            event: json!({ "t": "key", "kind": "press", "key": k }),
        });
        assert!(r.ok, "{:?}", r.error);
    }
    std::thread::sleep(std::time::Duration::from_millis(800));
    let r = h.op(Op::Handback);
    assert!(r.ok, "{:?}", r.error);
    assert_eq!(h.op(Op::Status).result["control"], "agent");
    assert!(h.snap().contains("Test site"));
    // the agent cannot send input as a person
    assert_eq!(
        h.op(Op::Input {
            event: json!({ "t": "key", "kind": "press", "key": "a" })
        })
        .code
        .as_deref(),
        Some("not_taken_over")
    );

    // --- the live view is a picture
    let f = h.op(Op::Frame);
    assert!(f.ok && f.result["jpeg"].as_str().unwrap().len() > 200);

    // --- the recording: steps and screenshots exist, and no typed value is anywhere in it
    let steps = ozbox_browser::record::load_steps(&root, "desk").unwrap();
    assert!(steps.len() > 15 && steps.iter().all(|s| !s.page.contains('?')));
    assert!(steps
        .iter()
        .any(|s| s.action == "type" && s.names.contains(&"password".to_string())));
    assert!(
        steps.iter().any(|s| s.outcome == "handoff") && steps.iter().any(|s| s.actor == "person")
    );
    assert!(steps.iter().filter(|s| s.shot.is_some()).count() > 10);
    let mut all = String::new();
    read_all(&root.join("sessions/desk"), &mut all);
    assert!(
        !all.contains("SENTINEL") && !all.contains("4111 1111"),
        "a typed value reached the recording"
    );
    h.op(Op::Close);
}

#[test]
fn the_phone_preset_and_the_task_limit() {
    if !have_browser() {
        return;
    }
    let site = testsite::start(0).unwrap();
    let port = site.port;
    let dir = tempfile::tempdir().unwrap();
    let policy = BrowserPolicy {
        min_gap_ms: 0,
        max_actions: 4,
        ..BrowserPolicy::default()
    };
    let mut h = H::open(dir.path(), "phone", Device::Phone, policy.clone(), &[]);
    h.ok(Action::Navigate {
        url: url(port, "127.0.0.1", "/device"),
    });
    let s = h.snap();
    assert!(s.contains("width=390 touch=true ua=true mobile"), "{s}");
    // the limit: the fourth counted action is the last; the next is refused as a limit, cleanly
    h.ok(Action::Snapshot);
    h.ok(Action::Snapshot);
    let r = h.act(Action::Snapshot, false);
    assert!(!r.ok && r.code.as_deref() == Some("limit"), "{r:?}");
    // pausing saves where it was, between actions, and the task resumes from there
    let r = h.op(Op::Pause {
        reason: "action limit".into(),
    });
    assert!(r.ok, "{:?}", r.error);
    assert_eq!(
        ozbox_browser::record::load_meta(dir.path(), "phone")
            .unwrap()
            .state,
        "paused"
    );
    assert!(dir.path().join("sessions/phone/resume.json").is_file());
    drop(h);
    let mut h2 = H::open(
        dir.path(),
        "phone",
        Device::Phone,
        BrowserPolicy {
            min_gap_ms: 0,
            max_actions: 10,
            ..policy
        },
        &[],
    );
    assert_eq!(h2.op(Op::Status).result["actions"], 4);
    assert!(
        h2.snap().contains("Device"),
        "the page it was on is open again"
    );
    assert!(!dir.path().join("sessions/phone/resume.json").exists());
    h2.op(Op::Close);
}

#[cfg(unix)]
fn raw_mode(p: &Path) -> u32 {
    use std::os::unix::fs::PermissionsExt;
    std::fs::metadata(p).unwrap().permissions().mode()
}

#[cfg(unix)]
fn gid(p: &Path) -> u32 {
    use std::os::unix::fs::MetadataExt;
    std::fs::metadata(p).unwrap().gid()
}

/// Make `dir` setgid and, where the runner has a group besides its own, give it that group, so a file made in it can be told
/// from one that took the maker's own group.
#[cfg(unix)]
fn make_group_shared(dir: &Path) {
    use std::os::unix::fs::PermissionsExt;
    let id = |a: &str| {
        String::from_utf8(
            std::process::Command::new("id")
                .arg(a)
                .output()
                .unwrap()
                .stdout,
        )
        .unwrap()
    };
    let own: u32 = id("-g").trim().parse().unwrap();
    if let Some(other) = id("-G")
        .split_whitespace()
        .filter_map(|g| g.parse::<u32>().ok())
        .find(|g| *g != own)
    {
        std::os::unix::fs::chown(dir, None, Some(other)).unwrap();
    }
    std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o2750)).unwrap();
}

#[cfg(unix)]
fn mode(p: &Path) -> u32 {
    use std::os::unix::fs::PermissionsExt;
    std::fs::metadata(p).unwrap().permissions().mode() & 0o777
}

/// A named profile, and a paused session's saved place, are in the private root and not in the recording the box's other users
/// read; the recording itself is readable by the group.
#[cfg(unix)]
#[test]
fn a_named_profile_and_a_saved_place_are_private_and_the_recording_is_shared() {
    if !have_browser() {
        return;
    }
    let site = testsite::start(0).unwrap();
    let port = site.port;
    let dir = tempfile::tempdir().unwrap();
    let shared = dir.path().join("shared");
    let private = dir.path().join("private");
    std::fs::create_dir_all(&shared).unwrap();
    std::fs::create_dir_all(&private).unwrap();
    let policy = BrowserPolicy {
        min_gap_ms: 0,
        profile: Some("work".into()),
        ..BrowserPolicy::default()
    };
    let mut h = H::open_in(
        &shared,
        Some(&private),
        "priv",
        Device::Desktop,
        policy,
        &[],
    );
    h.ok(Action::Navigate {
        url: url(port, "127.0.0.1", "/login"),
    });
    // the profile is the private root's, and 0700
    assert!(private.join("profiles/work").is_dir());
    assert_eq!(mode(&private.join("profiles/work")), 0o700);
    assert!(!shared.join("profiles").exists() && !shared.join("tmp").exists());
    // the recording is where the box's group reads it
    let session = shared.join("sessions/priv");
    assert_eq!(mode(&session), 0o750);
    assert!(session.join("meta.json").is_file());
    // a paused session's saved place (the tabs' addresses) is private, and not beside the recording
    let r = h.op(Op::Pause {
        reason: "limit".into(),
    });
    assert!(r.ok, "{:?}", r.error);
    assert!(private.join("resume/priv.json").is_file());
    assert_eq!(mode(&private.join("resume")), 0o700);
    assert!(!session.join("resume.json").exists());
    let steps = ozbox_browser::record::load_steps(&shared, "priv").unwrap();
    assert!(steps.iter().any(|s| s.action == "navigate"));
    drop(h);
    // and the session picks up where it was, from the private place
    let mut h2 = H::open_in(
        &shared,
        Some(&private),
        "priv",
        Device::Desktop,
        BrowserPolicy {
            min_gap_ms: 0,
            profile: Some("work".into()),
            ..BrowserPolicy::default()
        },
        &[],
    );
    assert!(
        !private.join("resume/priv.json").exists(),
        "the saved place was used once"
    );
    assert!(h2.snap().contains("Log in") || h2.snap().contains("Username"));
    h2.op(Op::Close);
}

/// A clean session (no named profile) with a private root keeps its temporary profile in the private root and removes it on close.
#[cfg(unix)]
#[test]
fn a_clean_session_with_a_private_root_keeps_its_temporary_profile_private_and_removes_it() {
    if !have_browser() {
        return;
    }
    let dir = tempfile::tempdir().unwrap();
    let shared = dir.path().join("shared");
    let private = dir.path().join("private");
    std::fs::create_dir_all(&shared).unwrap();
    std::fs::create_dir_all(&private).unwrap();
    let mut h = H::open_in(
        &shared,
        Some(&private),
        "clean",
        Device::Desktop,
        BrowserPolicy::default(),
        &[],
    );
    assert!(private.join("tmp/clean").is_dir());
    assert!(!shared.join("tmp").exists());
    h.op(Op::Close);
    assert!(!private.join("tmp/clean").exists());
}

/// The sealed channel's input ending is how a session is stopped across Unix users (nothing can signal the worker): the worker
/// closes its browser, records the end and returns, and a clean session's profile is gone.
#[test]
fn the_end_of_the_workers_input_closes_the_session_cleanly() {
    if !have_browser() {
        return;
    }
    std::env::set_var("OZBOX_BROWSER_NO_SANDBOX", "1");
    let dir = tempfile::tempdir().unwrap();
    let key = SessionKey::generate().unwrap();
    let start = Start {
        session: "eof".into(),
        key,
        root: dir.path().to_string_lossy().into(),
        work: dir.path().to_string_lossy().into(),
        device: Device::Desktop,
        policy: BrowserPolicy::default(),
        allowed_hosts: vec![],
        run: None,
        private_root: None,
        memory_max_bytes: None,
        max_runtime_s: None,
    };
    let (tx, rx) = std::sync::mpsc::channel::<u8>();
    drop(tx);
    // an input that ends at once
    struct Ends(std::sync::mpsc::Receiver<u8>);
    impl std::io::Read for Ends {
        fn read(&mut self, b: &mut [u8]) -> std::io::Result<usize> {
            match self.0.recv_timeout(std::time::Duration::from_millis(200)) {
                Ok(x) => {
                    b[0] = x;
                    Ok(1)
                }
                Err(_) => Ok(0),
            }
        }
    }
    let mut out: Vec<u8> = Vec::new();
    ozbox_browser::worker::run(start, std::io::BufReader::new(Ends(rx)), &mut out).unwrap();
    let first = String::from_utf8(out).unwrap();
    assert!(!first.is_empty(), "the worker said it was ready");
    assert_eq!(
        ozbox_browser::record::load_meta(dir.path(), "eof")
            .unwrap()
            .state,
        "closed"
    );
    assert!(!dir.path().join("tmp/eof").exists());
}
