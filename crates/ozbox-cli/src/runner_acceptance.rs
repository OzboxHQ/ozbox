//! The acceptance test for a project that runs a web app's tests on a box, with a fake machine (no real box): the shape a
//! real project declares. Names are generic (`app`, a mint script, a build, a service on 3100, a test run).

#![allow(clippy::unwrap_used)]

use std::cell::{Cell, RefCell};

use serde_json::{json, Value};
use zeroize::Zeroizing;

use crate::runner::{launch, Backend, Collected};
use crate::workload_policy::Policy;

const KEY: &str = "SENTINEL-service-key-0123456789abcdef";
const URL: &str = "SENTINEL-public-url-0123456789abcdef";
const MINT: &str = "tests/_helpers/mint-storage-state.mjs";
const RETRY: &str = "tests/_helpers/mint-retry.mjs";
const PKG: &str = "node_modules/@vendor/client";
/// What the minter is: it imports a sibling, a package and a built-in, like the real session minter this feature is for.
const MINT_SRC: &str = "import { retry } from './mint-retry.mjs'\nimport { client } from '@vendor/client'\nimport fs from 'node:fs'\nexport const mint = [retry, client, fs]\n";

fn declaration(dir: &str) -> Policy {
    let text = json!({
        "dir": "/work/projects/app",
        "writable": [".next", ".auth", "test-results"],
        "tools": [{"name": "node", "sha256": "a".repeat(64)}],
        "browsers": ["chromium"],
        "browser_digests": {"chromium-1169": "b".repeat(64), "chromium_headless_shell-1169": "b".repeat(64), "ffmpeg-1011": "b".repeat(64)},
        "commands": {
            "e2e-mint": {
                "allow": ["SUPABASE_SERVICE_ROLE_KEY", "NEXT_PUBLIC_SUPABASE_URL"],
                "env": [{"name": "SUPABASE_SERVICE_ROLE_KEY", "as": "E2E_SUPABASE_SERVICE_ROLE_KEY"}, "NEXT_PUBLIC_SUPABASE_URL"],
                "argv": ["node", MINT],
                "envs": ["staging"],
                "pin": [{"file": MINT, "sha256": "0".repeat(64)}, {"file": RETRY, "sha256": "0".repeat(64)}],
                "pin_tree": [{"path": PKG, "sha256": "0".repeat(64)}],
                "vars": {"E2E_USER_EMAIL": "e2e-staff@example.com"}
            },
            "app-build": {
                "allow": ["NEXT_PUBLIC_SUPABASE_URL"],
                "env": ["NEXT_PUBLIC_SUPABASE_URL"],
                "argv": ["npm", "run", "build"],
                "vars": {"NEXT_PUBLIC_APP_URL": "http://localhost:3100"}
            },
            "app-start": {
                "allow": [], "service": true, "port": 3100, "health": "/",
                "argv": ["npm", "run", "start"],
                "vars": {"PORT": "3100", "NEXT_PUBLIC_APP_URL": "http://localhost:3100"}
            },
            "e2e-run": {
                "allow": [], "browser": true, "argv": ["npx", "playwright", "test"],
                "vars": {"E2E_STORAGE_STATE": ".auth/staff.json", "E2E_CLINIC_ID": "45715198-88e4-498c-8271-57e652c60246", "E2E_ALLOW_WRITES": "1"},
                "pass": ["E2E_SPEC"]
            }
        }
    });
    let mut p = Policy::parse(&text.to_string()).unwrap();
    p.dir = dir.to_string(); // the real folder of this test, which is not under /work
    p
}

struct Machine {
    policy: RefCell<Policy>,
    pins_root: std::path::PathBuf,
    seen: RefCell<Vec<Vec<String>>>,
    stdin: RefCell<Vec<String>>,
    resolved: RefCell<Vec<String>>,
    state: RefCell<String>,
    listening: Cell<bool>,
    healthy: Cell<bool>,
    log: String,
}

impl Backend for Machine {
    fn policy(&self, _: &str) -> Result<Option<Policy>, String> {
        Ok(Some(self.policy.borrow().clone()))
    }
    fn resolve(
        &self,
        _: &str,
        _: &str,
        name: &str,
        allowed: &[String],
    ) -> Result<Zeroizing<String>, String> {
        if !allowed.iter().any(|a| a == name) {
            return Err(format!("{name} is not allowed for this command"));
        }
        self.resolved.borrow_mut().push(name.to_string());
        Ok(Zeroizing::new(
            if name == "SUPABASE_SERVICE_ROLE_KEY" {
                KEY
            } else {
                URL
            }
            .to_string(),
        ))
    }
    fn known(&self, _: &str) -> Result<Vec<Zeroizing<String>>, String> {
        Ok(vec![Zeroizing::new(KEY.into()), Zeroizing::new(URL.into())])
    }
    fn runner_ready(&self, _: &str) -> bool {
        true
    }
    fn exec(&self, argv: &[String], stdin: &[u8]) -> Result<Collected, String> {
        self.seen.borrow_mut().push(argv.to_vec());
        self.stdin
            .borrow_mut()
            .push(String::from_utf8(stdin.to_vec()).unwrap());
        if argv[0] == "systemd-run" && argv.iter().any(|a| a == "--no-block") {
            *self.state.borrow_mut() = "active".into();
            self.listening.set(true);
            self.healthy.set(true);
        }
        if argv[0] == "systemctl" && argv[1] == "stop" {
            *self.state.borrow_mut() = "inactive".into();
            self.listening.set(false);
        }
        Ok((
            Some(0),
            format!("ran with {KEY}\n").into_bytes(),
            Vec::new(),
        ))
    }
    fn audit(&self, _: &str) {}
    fn pins(&self) -> crate::runner_pins::PinStore {
        crate::runner_pins::PinStore::new(&self.pins_root)
    }
    fn unit_state(&self, _: &str) -> String {
        self.state.borrow().clone()
    }
    fn port_open(&self, _: u16) -> bool {
        self.listening.get() && *self.state.borrow() != "active"
    }
    fn http_status(&self, _: u16, _: &str) -> Option<u16> {
        self.healthy.get().then_some(200)
    }
    fn unit_log(&self, _: &str) -> String {
        self.log.clone()
    }
    fn sleep_ms(&self, _: u64) {}
}

struct Fixture {
    _d: tempfile::TempDir,
    m: Machine,
    dir: std::path::PathBuf,
}

fn fixture() -> Fixture {
    let d = tempfile::tempdir().unwrap();
    // the launcher refuses a folder reached through a link, and a temporary folder can be one (macOS: /var -> /private/var)
    let dir = std::fs::canonicalize(d.path()).unwrap().join("app");
    std::fs::create_dir_all(dir.join("tests/_helpers")).unwrap();
    std::fs::write(dir.join(MINT), MINT_SRC).unwrap();
    std::fs::write(dir.join(RETRY), "export const retry = 1\n").unwrap();
    std::fs::create_dir_all(dir.join(PKG)).unwrap();
    std::fs::write(dir.join(PKG).join("index.js"), "exports.client = 1\n").unwrap();
    std::fs::write(dir.join(PKG).join("package.json"), "{}").unwrap();
    let mut p = declaration(dir.to_str().unwrap());
    let c = p.commands.get_mut("e2e-mint").unwrap();
    c.pin[0].sha256 = crate::runner_pins::sha256_hex(MINT_SRC.as_bytes());
    c.pin[1].sha256 = crate::runner_pins::sha256_hex(b"export const retry = 1\n");
    c.pin_tree[0].sha256 = crate::runner_setup::tree_digest(&dir.join(PKG)).unwrap();
    Fixture {
        m: Machine {
            policy: RefCell::new(p),
            pins_root: d.path().join("pins"),
            seen: RefCell::default(),
            stdin: RefCell::default(),
            resolved: RefCell::default(),
            state: RefCell::new("inactive".into()),
            listening: Cell::new(false),
            healthy: Cell::new(false),
            log: format!("listening on 3100 with {KEY}\n"),
        },
        dir,
        _d: d,
    }
}

fn ask(f: &Fixture, command: &str, argv: &[&str], extra: Value) -> Value {
    let mut r = json!({"project": "app", "env": "staging", "command": command, "argv": argv});
    if let Value::Object(m) = extra {
        for (k, v) in m {
            r[k] = v;
        }
    }
    launch(&f.m, "id000001", &r.to_string())
}

fn env_of(line: &str) -> Vec<(String, String)> {
    let v: Value = serde_json::from_str(line.trim_end()).unwrap();
    v["env"]
        .as_array()
        .unwrap()
        .iter()
        .map(|p| {
            (
                p[0].as_str().unwrap().to_string(),
                p[1].as_str().unwrap().to_string(),
            )
        })
        .collect()
}

#[test]
fn the_pinned_minter_receives_the_renamed_key_and_the_public_values_and_runs_from_the_approved_copy(
) {
    let f = fixture();
    let r = ask(&f, "e2e-mint", &["node", MINT], json!({}));
    assert_eq!(r["ok"], true, "{r}");
    // the stored name stays what it is; the command sees the other one; no copy of the key under another stored name
    assert_eq!(
        r["resolved"],
        json!([
            "SUPABASE_SERVICE_ROLE_KEY->E2E_SUPABASE_SERVICE_ROLE_KEY",
            "NEXT_PUBLIC_SUPABASE_URL"
        ])
    );
    let env = env_of(&f.m.stdin.borrow()[0]);
    assert!(env.contains(&("E2E_SUPABASE_SERVICE_ROLE_KEY".into(), KEY.into())));
    assert!(!env.iter().any(|(k, _)| k == "SUPABASE_SERVICE_ROLE_KEY"));
    assert!(env.contains(&("NEXT_PUBLIC_SUPABASE_URL".into(), URL.into())));
    assert!(env.contains(&("E2E_USER_EMAIL".into(), "e2e-staff@example.com".into())));
    // the unit: tools first on PATH, the browser cache, and the verified copy bound read-only over the minter
    let argv = f.m.seen.borrow()[0].join(" ");
    assert!(
        argv.contains("Environment=PATH=/opt/ozbox-run-tools/bin/app:/usr/local/bin:/usr/bin:/bin")
    );
    // a command that receives a secret is told of no browser, runs as a user of its own, and has no swap
    assert!(!argv.contains("PLAYWRIGHT"), "{argv}");
    assert!(
        argv.contains("--uid=ozrc-") && !argv.contains("--uid=ozbox-run-app"),
        "{argv}"
    );
    assert!(argv.contains("MemorySwapMax=0") && argv.contains("LimitCORE=0"));
    // the folder of the package is bound too, from its verified copy
    assert!(
        argv.contains(&format!(
            "{}/{PKG}",
            std::fs::canonicalize(&f.dir).unwrap().display()
        )),
        "{argv}"
    );
    assert!(
        argv.contains("BindReadOnlyPaths=")
            && argv.contains(&format!(
                "{}/{MINT}",
                std::fs::canonicalize(&f.dir).unwrap().display()
            ))
    );
    assert!(argv.ends_with(&format!("secrets exec-env -- node {MINT}")));
    // the key is in no argument and not in what comes back
    assert!(!argv.contains(KEY) && !r.to_string().contains(KEY));
}

#[test]
fn a_changed_minter_is_refused_by_name_and_nothing_starts_or_receives_the_key() {
    let f = fixture();
    std::fs::write(f.dir.join(MINT), "steal(process.env)\n").unwrap();
    let r = ask(&f, "e2e-mint", &["node", MINT], json!({}));
    assert_eq!(r["ok"], false);
    let e = r["error"].as_str().unwrap();
    assert!(
        e.contains(MINT) && e.contains("has changed") && e.contains("not started"),
        "{e}"
    );
    assert!(f.m.seen.borrow().is_empty(), "nothing was started");
    assert!(
        f.m.resolved.borrow().is_empty(),
        "no secret was looked up for it"
    );
    assert!(!r.to_string().contains(KEY));
    // a pinned command takes exactly its declared words: an extra argument is refused
    std::fs::write(f.dir.join(MINT), MINT_SRC).unwrap();
    let r = ask(&f, "e2e-mint", &["node", MINT, "--out", "x"], json!({}));
    assert_eq!(r["ok"], false);
    assert!(f.m.seen.borrow().is_empty());
}

#[test]
fn the_service_starts_on_loopback_without_secrets_and_the_test_run_reaches_it_there() {
    let f = fixture();
    // a service is never "run"
    let r = ask(&f, "app-start", &["npm", "run", "start"], json!({}));
    assert!(r["error"].as_str().unwrap().contains("--start"));
    let r = ask(&f, "app-start", &[], json!({"action": "start"}));
    assert_eq!(r["ok"], true, "{r}");
    assert_eq!(r["port"], 3100);
    let start = f.m.seen.borrow().last().unwrap().clone();
    let j = start.join(" ");
    for want in [
        "--no-block",
        "--unit=ozbox-svc-app_app-start",
        "IPAddressDeny=any",
        "IPAddressAllow=127.0.0.1 ::1",
        "Environment=PORT=3100",
        "Environment=NEXT_PUBLIC_APP_URL=http://localhost:3100",
        "RuntimeMaxSec=14400",
        "StandardInput=null",
        "/usr/bin/env -- npm run start",
    ] {
        assert!(j.contains(want), "{want} in {j}");
    }
    assert!(
        !j.contains("--pipe") && !j.contains("PrivateNetwork") && !j.contains("TimeoutRunSec"),
        "{j}"
    );
    assert!(
        !j.contains(KEY) && !j.contains(URL),
        "a service carries no secret"
    );
    assert_eq!(f.m.stdin.borrow().last().unwrap(), "");
    // the same project's test run is on the same machine's loopback and nothing else: it can reach the service, and only it
    let r = ask(
        &f,
        "e2e-run",
        &["npx", "playwright", "test"],
        json!({"pass": {"E2E_SPEC": "tests/a.spec.ts"}}),
    );
    assert_eq!(r["ok"], true, "{r}");
    let run = f.m.seen.borrow().last().unwrap().join(" ");
    assert!(
        run.contains("IPAddressDeny=any")
            && run.contains("IPAddressAllow=127.0.0.1 ::1")
            && !run.contains("PrivateNetwork")
    );
    let env = env_of(f.m.stdin.borrow().last().unwrap());
    for (k, v) in [
        ("E2E_STORAGE_STATE", ".auth/staff.json"),
        ("E2E_ALLOW_WRITES", "1"),
        ("E2E_SPEC", "tests/a.spec.ts"),
        ("E2E_CLINIC_ID", "45715198-88e4-498c-8271-57e652c60246"),
    ] {
        assert!(env.contains(&(k.to_string(), v.to_string())), "{k}");
    }
    assert!(
        !env.iter().any(|(_, v)| v == KEY || v == URL),
        "the test run receives no secret"
    );
    // a second start is refused, status says healthy with the log scrubbed, stop ends it
    assert_eq!(
        ask(&f, "app-start", &[], json!({"action": "start"}))["ok"],
        false
    );
    let s = ask(&f, "app-start", &[], json!({"action": "status"}));
    assert_eq!(s["state"], "active");
    assert_eq!(s["healthy"], true);
    assert!(
        !s.to_string().contains(KEY) && s["log"].as_str().unwrap().contains("[redacted"),
        "{s}"
    );
    let st = ask(&f, "app-start", &[], json!({"action": "stop"}));
    assert_eq!(st["state"], "stopped");
    assert_eq!(
        ask(&f, "app-start", &[], json!({"action": "status"}))["state"],
        "inactive"
    );
}

#[test]
fn a_service_that_never_answers_is_stopped_and_says_so() {
    let f = fixture();
    // starts, but the health check never answers
    struct Dead(Fixture);
    impl Backend for Dead {
        fn policy(&self, p: &str) -> Result<Option<Policy>, String> {
            self.0.m.policy(p)
        }
        fn resolve(
            &self,
            a: &str,
            b: &str,
            c: &str,
            d: &[String],
        ) -> Result<Zeroizing<String>, String> {
            self.0.m.resolve(a, b, c, d)
        }
        fn known(&self, p: &str) -> Result<Vec<Zeroizing<String>>, String> {
            self.0.m.known(p)
        }
        fn runner_ready(&self, _: &str) -> bool {
            true
        }
        fn exec(&self, argv: &[String], stdin: &[u8]) -> Result<Collected, String> {
            self.0.m.exec(argv, stdin)
        }
        fn audit(&self, l: &str) {
            self.0.m.audit(l)
        }
        fn unit_state(&self, u: &str) -> String {
            self.0.m.unit_state(u)
        }
        fn port_open(&self, _: u16) -> bool {
            false
        }
        fn http_status(&self, _: u16, _: &str) -> Option<u16> {
            None
        }
        fn unit_log(&self, u: &str) -> String {
            self.0.m.unit_log(u)
        }
        fn sleep_ms(&self, _: u64) {}
    }
    let d = Dead(f);
    let r = launch(
        &d,
        "id000002",
        &json!({"project":"app","env":"staging","command":"app-start","argv":[],"action":"start"})
            .to_string(),
    );
    assert_eq!(r["ok"], false);
    let e = r["error"].as_str().unwrap();
    assert!(
        e.contains("health check") && e.contains("stopped") && !e.contains(KEY),
        "{e}"
    );
    assert!(d
        .0
        .m
        .seen
        .borrow()
        .iter()
        .any(|a| a[0] == "systemctl" && a[1] == "stop"));
}

#[test]
fn what_a_caller_may_pass_is_plain_declared_and_never_a_secret() {
    let f = fixture();
    let go = |extra: Value| ask(&f, "e2e-run", &["npx", "playwright", "test"], extra);
    for (what, extra) in [
        (
            "a name the command did not declare",
            json!({"pass": {"OTHER": "x"}}),
        ),
        (
            "a key-shaped value",
            json!({"pass": {"E2E_SPEC": format!("sk_{}_abcdefghijklmnop", "live")}}),
        ),
        ("a stored secret", json!({"pass": {"E2E_SPEC": KEY}})),
        (
            "a long token",
            json!({"pass": {"E2E_SPEC": "a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8"}}),
        ),
        (
            "a value with a space or a newline",
            json!({"pass": {"E2E_SPEC": "a b\nPATH=/x"}}),
        ),
        ("not an object", json!({"pass": ["E2E_SPEC=x"]})),
    ] {
        let r = go(extra);
        assert_eq!(r["ok"], false, "{what}: {r}");
    }
    assert!(
        f.m.seen.borrow().is_empty(),
        "nothing started for any of them"
    );
    // an ordinary value is taken
    assert_eq!(
        go(json!({"pass": {"E2E_SPEC": "tests/a.spec.ts"}}))["ok"],
        true
    );
}

/// the command that receives the key, the service and the browser run share no uid, at every unit the launcher starts.
#[test]
fn the_key_command_the_service_and_the_browser_command_never_share_a_user() {
    let f = fixture();
    assert_eq!(ask(&f, "e2e-mint", &["node", MINT], json!({}))["ok"], true);
    assert_eq!(
        ask(&f, "app-start", &[], json!({"action": "start"}))["ok"],
        true
    );
    assert_eq!(
        ask(&f, "e2e-run", &["npx", "playwright", "test"], json!({}))["ok"],
        true
    );
    let uid = |a: &Vec<String>| a.iter().find(|x| x.starts_with("--uid=")).cloned().unwrap();
    let seen = f.m.seen.borrow();
    let units: Vec<&Vec<String>> = seen.iter().filter(|a| a[0] == "systemd-run").collect();
    assert_eq!(units.len(), 3);
    let (mint, svc, run) = (uid(units[0]), uid(units[1]), uid(units[2]));
    assert!(mint.starts_with("--uid=ozrc-"));
    assert_eq!(svc, "--uid=ozbox-run-app");
    assert_eq!(
        run, "--uid=ozbox-run-app",
        "plain commands and the service are the project's runner"
    );
    assert_ne!(mint, svc);
    assert_ne!(mint, run);
    // only the command marked `browser` is told where the browsers are
    assert!(units[2]
        .iter()
        .any(|a| a == "Environment=PLAYWRIGHT_BROWSERS_PATH=/opt/ozbox-run-browsers/app"));
    assert!(!units[1].iter().any(|a| a.contains("PLAYWRIGHT")));
}

/// At the launch: pins that do not cover what the minter loads stop it before the key is looked up.
#[test]
fn a_minter_whose_imports_are_not_all_pinned_is_refused_before_the_key_is_looked_up() {
    let f = fixture();
    // drop the package pin: the minter imports it
    f.m.policy
        .borrow_mut()
        .commands
        .get_mut("e2e-mint")
        .unwrap()
        .pin_tree
        .clear();
    let r = ask(&f, "e2e-mint", &["node", MINT], json!({}));
    assert_eq!(r["ok"], false);
    let e = r["error"].as_str().unwrap();
    assert!(
        e.contains("not everything it loads is pinned") && e.contains("@vendor/client"),
        "{e}"
    );
    assert!(f.m.seen.borrow().is_empty() && f.m.resolved.borrow().is_empty());
    // an agent adds a sibling the minter would load: it is not pinned
    f.m.policy
        .borrow_mut()
        .commands
        .get_mut("e2e-mint")
        .unwrap()
        .pin
        .pop();
    let r = ask(&f, "e2e-mint", &["node", MINT], json!({}));
    assert_eq!(r["ok"], false);
    assert!(f.m.resolved.borrow().is_empty());
}

/// G5 second review, N-H3 and the benchmark: once the approved copies exist the unit gets a private view and the launcher reads nothing
/// of the live folder. An agent that changes a pinned file, adds a `package.json` or an optional peer, or swaps a folder for a link
/// after the first run changes nothing the unit can see.
#[test]
fn after_the_first_run_the_unit_sees_only_the_approved_copies_whatever_the_live_folder_becomes() {
    let f = fixture();
    assert_eq!(ask(&f, "e2e-mint", &["node", MINT], json!({}))["ok"], true);
    let first = f.m.seen.borrow()[0].join(" ");
    let dir = f.dir.display().to_string();
    // G5 third round, NV-H1: the view is rooted at /work, never at the project folder
    assert!(first.contains("TemporaryFileSystem=/work:ro"), "{first}");
    assert!(
        !first.contains(&format!("TemporaryFileSystem={dir}")),
        "{first}"
    );
    for w in [".next", ".auth", "test-results"] {
        assert!(
            first.contains(&format!("BindPaths={dir}/{w}:{dir}/{w}")),
            "{w}"
        );
    }
    // the agent now rewrites the minter, plants a package.json that redirects a package, an optional peer, and swaps tests/ for a link
    std::fs::write(f.dir.join(MINT), "steal(process.env)\n").unwrap();
    std::fs::write(
        f.dir.join("package.json"),
        r#"{"name":"@vendor/client","exports":"./evil.mjs"}"#,
    )
    .unwrap();
    std::fs::create_dir_all(f.dir.join("node_modules/bufferutil")).unwrap();
    std::fs::write(f.dir.join("node_modules/bufferutil/index.js"), "steal()").unwrap();
    std::fs::remove_dir_all(f.dir.join("tests")).unwrap();
    std::os::unix::fs::symlink("/tmp", f.dir.join("tests")).unwrap();
    f.m.seen.borrow_mut().clear();
    let r = ask(&f, "e2e-mint", &["node", MINT], json!({}));
    assert_eq!(
        r["ok"], true,
        "the approved copies still run, and the live folder was never read: {r}"
    );
    let argv = f.m.seen.borrow()[0].clone();
    let binds: Vec<&String> = argv
        .iter()
        .filter(|a| a.starts_with("BindReadOnlyPaths="))
        .collect();
    // exactly the approved things are in the view: the two files and the package folder, from root-owned copies
    assert_eq!(binds.len(), 3, "{binds:?}");
    for absent in ["package.json", "bufferutil", "evil"] {
        assert!(
            !argv.join(" ").contains(absent),
            "{absent} is not in the unit's view"
        );
    }
}

/// G5 second review, N-C1 through the launcher: nothing starts for a secret command when the declaration is a squat's (unpinned).
#[test]
fn an_unpinned_secret_command_never_starts_even_if_it_is_stored() {
    let f = fixture();
    let r = ask(&f, "app-build", &["npm", "run", "build"], json!({}));
    assert_eq!(r["ok"], false, "{r}");
    assert!(r["error"].as_str().unwrap().contains("pins no file"), "{r}");
    assert!(f.m.seen.borrow().is_empty() && f.m.resolved.borrow().is_empty());
}
