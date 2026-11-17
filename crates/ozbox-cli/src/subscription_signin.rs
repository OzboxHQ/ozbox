//! A subscription sign-in that an engine must read itself, handed to that engine's runs only after the owner opted that
//! engine in (ADR 0055, which amends rule 4 of ADR 0054).
//!
//! Today one engine qualifies: Codex CLI with a ChatGPT plan. Its vendor documents a device-code sign-in
//! (`codex login --device-auth`), the sign-in file (`auth.json` under `CODEX_HOME`, kept there when
//! `cli_auth_credentials_store = "file"`), and keeping that file in a secrets manager and restoring it for a run on a
//! trusted private machine, one run at a time. Every other engine stays as ADR 0054 marks it, and the opt-in is not
//! offered for it.
//!
//! What this module holds, and where:
//!
//! - **The opt-in** (`subscription-optin-<id>`) and **the sign-in** (`subscription-login-<id>`, base64 in parts of at most
//!   [`PART`] characters) live in the secrets store only. On a box the box user's socket can neither read, write, delete,
//!   ask about nor list these names; the dashboard's own user (the supervisor) can. A dashboard that runs as the box user
//!   cannot store them at all, so it cannot turn the opt-in on (see `secrets_service::supervisor_only`).
//! - **The sign-in itself** is the vendor's own command, run by the dashboard's user in a private temporary folder
//!   (`0700`, removed afterwards), with its output read for the vendor's link and one-time code. Nothing is typed into the
//!   box's shell, and a sign-in already on a computer is never copied.
//! - **The hand-off** is [`files_for_run`]: the file's text for ONE run of the opted-in engine, which the box daemon writes
//!   into that run's own folder and removes when it ends (`ozboxd::run_files`).
//!
//! The text never appears in a log, a plan, an error, an API answer or the audit chain: those carry names and ids only.

use std::collections::BTreeMap;
use std::io::{BufRead, BufReader};
use std::path::Path;
use std::sync::{mpsc, Arc, Mutex};
use std::time::{Duration, Instant};

use ozbox_core::agent_engine::RunFile;
use zeroize::Zeroizing;

use crate::secrets::{SecretError, SecretStore};
use crate::serve::auth::b64::{decode_std, encode_std};

pub const OPTIN_PREFIX: &str = "subscription-optin-";
pub const LOGIN_PREFIX: &str = "subscription-login-";
/// The characters one stored part holds (under the store's plain-value limit).
pub const PART: usize = 4000;
/// The most parts a sign-in may take (about 24 KB of sign-in file).
pub const MAX_PARTS: usize = 8;
/// How long a device sign-in may wait for the person before it is ended. Vendors' codes expire within this.
pub const SIGN_IN_WAIT: Duration = Duration::from_secs(15 * 60);
/// The largest sign-in file accepted from the vendor's command.
pub const MAX_LOGIN_BYTES: usize = PART * MAX_PARTS * 3 / 4;

/// An engine whose own sign-in may be handed to its runs, on the owner's opt-in.
#[derive(Debug)]
pub struct Adapter {
    /// The row of `model_subscriptions::SUBSCRIPTIONS`.
    pub sub_id: &'static str,
    /// The agent engine whose runs get it, and no other.
    pub engine: &'static str,
    /// The vendor's own device sign-in, as an argv array.
    pub sign_in_argv: &'static [&'static str],
    /// The engine's documented variable for its home folder.
    pub dir_env: &'static str,
    /// The sign-in file in that folder.
    pub login_path: &'static str,
    /// Files the engine needs beside it so it reads the sign-in from the file (never the system keyring).
    pub beside: &'static [(&'static str, &'static str)],
    /// The hosts a link printed by the sign-in may point at (the vendor's own).
    pub link_hosts: &'static [&'static str],
    /// Where the person revokes the sign-in at the vendor.
    pub revoke_at: &'static str,
    /// What the person must type to turn the opt-in on.
    pub confirm: &'static str,
}

pub const ADAPTERS: &[Adapter] = &[Adapter {
    sub_id: "codex-chatgpt",
    engine: "codex",
    sign_in_argv: &["codex", "login", "--device-auth"],
    dir_env: "CODEX_HOME",
    login_path: "auth.json",
    beside: &[("config.toml", "cli_auth_credentials_store = \"file\"\n")],
    link_hosts: &["openai.com", "chatgpt.com"],
    revoke_at: "https://chatgpt.com/#settings/Security",
    confirm: "codex-chatgpt",
}];

pub fn adapter(sub_id: &str) -> Option<&'static Adapter> {
    ADAPTERS.iter().find(|a| a.sub_id == sub_id)
}

fn optin_name(id: &str) -> String {
    format!("{OPTIN_PREFIX}{id}")
}
fn login_name(id: &str) -> String {
    format!("{LOGIN_PREFIX}{id}")
}
fn part_name(id: &str, k: usize) -> String {
    format!("{LOGIN_PREFIX}{id}-{k}")
}

/// Whether the owner turned this engine's opt-in on.
pub fn opted_in(store: &dyn SecretStore, id: &str) -> bool {
    store.exists(&optin_name(id)).unwrap_or(false)
}

/// Turn the opt-in on (the value is when, in ms). A store that refuses (a dashboard running as the box user) says so.
pub fn set_opt_in(store: &dyn SecretStore, id: &str, now_ms: u64) -> Result<(), SecretError> {
    store.set(&optin_name(id), &now_ms.to_string())
}

/// Whether a sign-in is stored for this engine.
pub fn signed_in(store: &dyn SecretStore, id: &str) -> bool {
    store.exists(&login_name(id)).unwrap_or(false)
}

/// Keep a sign-in file's text, in parts, replacing any stored before.
pub fn store_login(store: &dyn SecretStore, id: &str, text: &str) -> Result<(), SecretError> {
    if text.is_empty() || text.len() > MAX_LOGIN_BYTES {
        return Err(SecretError("the sign-in is empty or too large".into()));
    }
    let b64 = Zeroizing::new(encode_std(text.as_bytes()));
    let parts: Vec<&str> = b64
        .as_bytes()
        .chunks(PART)
        .map(|c| std::str::from_utf8(c).unwrap_or(""))
        .collect();
    if parts.len() > MAX_PARTS {
        return Err(SecretError("the sign-in is too large".into()));
    }
    for (k, p) in parts.iter().enumerate() {
        store.set(&part_name(id, k), p)?;
    }
    for k in parts.len()..MAX_PARTS {
        let _ = store.delete(&part_name(id, k));
    }
    // the count goes last: a sign-in is there only once all its parts are
    store.set(&login_name(id), &parts.len().to_string())
}

/// The stored sign-in file's text, if there is one.
pub fn load_login(store: &dyn SecretStore, id: &str) -> Result<Option<Zeroizing<String>>, String> {
    let Some(n) = store
        .get(&login_name(id))
        .map_err(|_| "the secrets store did not answer".to_string())?
    else {
        return Ok(None);
    };
    let n: usize = n
        .parse()
        .ok()
        .filter(|n| (1..=MAX_PARTS).contains(n))
        .ok_or("the stored sign-in is damaged; sign in again")?;
    let mut b64 = Zeroizing::new(String::new());
    for k in 0..n {
        let p = store
            .get(&part_name(id, k))
            .map_err(|_| "the secrets store did not answer".to_string())?
            .ok_or("the stored sign-in is damaged; sign in again")?;
        b64.push_str(&p);
    }
    let bytes =
        Zeroizing::new(decode_std(&b64).ok_or("the stored sign-in is damaged; sign in again")?);
    let text =
        std::str::from_utf8(&bytes).map_err(|_| "the stored sign-in is damaged; sign in again")?;
    Ok(Some(Zeroizing::new(text.to_string())))
}

/// Delete the sign-in and the opt-in. What could not be deleted is said, by name only.
pub fn revoke(store: &dyn SecretStore, id: &str) -> Result<(), String> {
    let mut failed = Vec::new();
    for name in std::iter::once(login_name(id))
        .chain((0..MAX_PARTS).map(|k| part_name(id, k)))
        .chain(std::iter::once(optin_name(id)))
    {
        if store.exists(&name).unwrap_or(true) && store.delete(&name).is_err() {
            failed.push(name);
        }
    }
    if failed.is_empty() {
        Ok(())
    } else {
        Err(format!("could not delete {}", failed.join(", ")))
    }
}

/// The adapter whose sign-in a run of `engine` is to be handed: only when the owner opted it in and a sign-in is stored.
pub fn for_engine(store: &dyn SecretStore, engine: &str) -> Option<&'static Adapter> {
    ADAPTERS
        .iter()
        .find(|a| a.engine == engine && opted_in(store, a.sub_id) && signed_in(store, a.sub_id))
}

/// The files for one run of the adapter's engine.
pub fn files_for_run(store: &dyn SecretStore, a: &Adapter) -> Result<Vec<RunFile>, String> {
    let login = load_login(store, a.sub_id)?.ok_or("there is no stored sign-in; sign in again")?;
    let mut out = vec![RunFile {
        dir_env: a.dir_env.to_string(),
        path: a.login_path.to_string(),
        contents: login.to_string(),
    }];
    for (path, text) in a.beside {
        out.push(RunFile {
            dir_env: a.dir_env.to_string(),
            path: (*path).to_string(),
            contents: (*text).to_string(),
        });
    }
    Ok(out)
}

// ---------- the device sign-in ----------

/// Where a device sign-in stands. Names and the vendor's public link and short code only; never the sign-in.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Phase {
    Starting,
    /// The person opens `link` and types `code` there.
    Waiting {
        link: String,
        code: String,
    },
    Done,
    /// Why, as a stable code (`models.signin_failed_<code>` in the dashboard's catalogue).
    Failed(&'static str),
}

impl Phase {
    pub fn word(&self) -> &'static str {
        match self {
            Phase::Starting => "starting",
            Phase::Waiting { .. } => "waiting",
            Phase::Done => "done",
            Phase::Failed(_) => "failed",
        }
    }
}

/// One sign-in in progress or just ended.
#[derive(Debug, Clone)]
pub struct Flow {
    pub phase: Phase,
    pub started_ms: u64,
    /// Its outcome has been written to the audit chain.
    pub audited: bool,
}

/// The sign-ins of this dashboard, by subscription id.
pub type Flows = Arc<Mutex<BTreeMap<String, Flow>>>;

fn lock<T>(m: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    m.lock().unwrap_or_else(std::sync::PoisonError::into_inner)
}

/// Runs the vendor's sign-in command. The real one starts a process; tests and the demo use a stand-in.
pub trait DeviceSignIn: Send + Sync {
    /// Run `argv` with `env` (and nothing else from this process's environment but `PATH` and a locale), feeding each line
    /// of its output to `line`, until it ends or `deadline` passes. `Ok(true)` when it ended well.
    fn run(
        &self,
        argv: &[&str],
        env: &[(String, String)],
        deadline: Instant,
        line: &mut dyn FnMut(&str),
    ) -> Result<bool, &'static str>;
}

/// The vendor's own program, started from its argv array with a fixed `PATH` (never the box user's).
pub struct ProcessSignIn;

impl DeviceSignIn for ProcessSignIn {
    fn run(
        &self,
        argv: &[&str],
        env: &[(String, String)],
        deadline: Instant,
        line: &mut dyn FnMut(&str),
    ) -> Result<bool, &'static str> {
        let (prog, args) = argv.split_first().ok_or("not_installed")?;
        let mut c = std::process::Command::new(prog);
        c.args(args)
            .env_clear()
            .env("PATH", "/usr/local/bin:/usr/bin:/bin")
            .env("LANG", "C.UTF-8")
            .env("NO_COLOR", "1")
            .envs(env.iter().map(|(k, v)| (k.as_str(), v.as_str())))
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped());
        let mut child = c.spawn().map_err(|_| "not_installed")?;
        let (tx, rx) = mpsc::channel::<String>();
        let mut readers = Vec::new();
        if let Some(o) = child.stdout.take() {
            let tx = tx.clone();
            readers.push(std::thread::spawn(move || {
                for l in BufReader::new(o).lines().map_while(Result::ok).take(500) {
                    let _ = tx.send(l);
                }
            }));
        }
        if let Some(e) = child.stderr.take() {
            let tx = tx.clone();
            readers.push(std::thread::spawn(move || {
                for l in BufReader::new(e).lines().map_while(Result::ok).take(500) {
                    let _ = tx.send(l);
                }
            }));
        }
        drop(tx);
        loop {
            let left = deadline.saturating_duration_since(Instant::now());
            if left.is_zero() {
                let _ = child.kill();
                let _ = child.wait();
                return Err("expired");
            }
            match rx.recv_timeout(left.min(Duration::from_millis(500))) {
                Ok(l) => line(&l),
                Err(mpsc::RecvTimeoutError::Timeout) => {
                    if let Ok(Some(st)) = child.try_wait() {
                        for l in rx.try_iter() {
                            line(&l);
                        }
                        return Ok(st.success());
                    }
                }
                Err(mpsc::RecvTimeoutError::Disconnected) => {
                    let st = child.wait().map_err(|_| "failed")?;
                    for r in readers {
                        let _ = r.join();
                    }
                    return Ok(st.success());
                }
            }
        }
    }
}

/// A stand-in for the demo and the tests: prints a link and a code, waits `wait`, then writes a made-up sign-in file.
pub struct DemoSignIn {
    pub wait: Duration,
}

impl DeviceSignIn for DemoSignIn {
    fn run(
        &self,
        _argv: &[&str],
        env: &[(String, String)],
        _deadline: Instant,
        line: &mut dyn FnMut(&str),
    ) -> Result<bool, &'static str> {
        line("Follow these steps to sign in:");
        line("1. Open this link in your browser: https://auth.openai.com/codex/device");
        line("2. Enter this one-time code: DEMO-0042");
        std::thread::sleep(self.wait);
        let home = env
            .iter()
            .find(|(k, _)| k.ends_with("_HOME") && k != "HOME")
            .map(|(_, v)| v.clone())
            .ok_or("failed")?;
        std::fs::write(
            Path::new(&home).join("auth.json"),
            "{\"demo\":\"a made-up sign-in for the demo dashboard\"}",
        )
        .map_err(|_| "failed")?;
        Ok(true)
    }
}

/// Remove terminal colour codes from a line.
fn plain(line: &str) -> String {
    let mut out = String::with_capacity(line.len());
    let mut it = line.chars().peekable();
    while let Some(c) = it.next() {
        if c == '\u{1b}' {
            if it.peek() == Some(&'[') {
                it.next();
                for d in it.by_ref() {
                    if d.is_ascii_alphabetic() {
                        break;
                    }
                }
            }
            continue;
        }
        if !c.is_control() {
            out.push(c);
        }
    }
    out
}

/// The vendor's link, if `line` shows one on an allowed host (https only).
pub fn find_link(line: &str, hosts: &[&str]) -> Option<String> {
    plain(line).split_whitespace().find_map(|w| {
        let w = w.trim_end_matches(['.', ',', ')']);
        let rest = w.strip_prefix("https://")?;
        let host = rest.split(['/', '?', '#']).next()?;
        let ok = hosts
            .iter()
            .any(|h| host == *h || host.ends_with(&format!(".{h}")));
        (ok && w.len() <= 300 && w.chars().all(|c| c.is_ascii_graphic())).then(|| w.to_string())
    })
}

/// A one-time code such as `ABCD-1234`, if `line` shows one.
pub fn find_code(line: &str) -> Option<String> {
    plain(line).split_whitespace().find_map(|w| {
        let w = w.trim_end_matches(['.', ',']);
        let parts: Vec<&str> = w.split('-').collect();
        (parts.len() >= 2
            && w.len() <= 20
            && parts.iter().all(|p| {
                p.len() >= 4
                    && p.bytes()
                        .all(|b| b.is_ascii_uppercase() || b.is_ascii_digit())
            }))
        .then(|| w.to_string())
    })
}

/// Start the vendor's device sign-in for `a` in the background. Its progress is in `flows`; when it ends well the sign-in
/// file is moved into `store` and the private folder is removed. Refused while one is going for the same engine.
pub fn start(
    flows: &Flows,
    a: &'static Adapter,
    runner: Arc<dyn DeviceSignIn>,
    store: Arc<dyn SecretStore>,
    now_ms: u64,
) -> Result<(), &'static str> {
    {
        let mut f = lock(flows);
        if f.get(a.sub_id)
            .is_some_and(|x| matches!(x.phase, Phase::Starting | Phase::Waiting { .. }))
        {
            return Err("in_progress");
        }
        f.insert(
            a.sub_id.to_string(),
            Flow {
                phase: Phase::Starting,
                started_ms: now_ms,
                audited: false,
            },
        );
    }
    let flows = Arc::clone(flows);
    std::thread::spawn(move || {
        let end = run_sign_in(&flows, a, runner.as_ref(), store.as_ref());
        let mut f = lock(&flows);
        if let Some(x) = f.get_mut(a.sub_id) {
            x.phase = end;
        }
    });
    Ok(())
}

/// A folder only this process's user may enter, made so from the start (never widened, then narrowed).
fn private_dir() -> std::io::Result<tempfile::TempDir> {
    let mut b = tempfile::Builder::new();
    b.prefix("ozbox-signin-");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        b.permissions(std::fs::Permissions::from_mode(0o700));
    }
    let d = b.tempdir()?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        // the umask can only narrow it; checked anyway, so a folder anyone else could enter is never used
        let mode = std::fs::metadata(d.path())?.permissions().mode() & 0o777;
        if mode != 0o700 {
            return Err(std::io::Error::other("the sign-in folder is not private"));
        }
    }
    Ok(d)
}

/// One sign-in, start to end: what [`start`] runs in the background. Returns the last phase.
pub fn run_sign_in(
    flows: &Flows,
    a: &Adapter,
    runner: &dyn DeviceSignIn,
    store: &dyn SecretStore,
) -> Phase {
    // a private folder of the dashboard's own user (0700): the box user cannot enter it, and it is removed when this ends
    let Ok(home) = private_dir() else {
        return Phase::Failed("no_private_folder");
    };
    for (path, text) in a.beside {
        if std::fs::write(home.path().join(path), text).is_err() {
            return Phase::Failed("no_private_folder");
        }
    }
    let dir = home.path().to_string_lossy().into_owned();
    // the engine's home and the process's own home are both the private folder, so nothing is read from or left in any other
    let env = vec![
        (a.dir_env.to_string(), dir.clone()),
        ("HOME".to_string(), dir),
    ];
    let (mut link, mut code) = (None::<String>, None::<String>);
    let mut on_line = |l: &str| {
        if link.is_none() {
            link = find_link(l, a.link_hosts);
        }
        if code.is_none() {
            code = find_code(l);
        }
        if let (Some(k), Some(c)) = (&link, &code) {
            let mut f = lock(flows);
            if let Some(x) = f.get_mut(a.sub_id) {
                if matches!(x.phase, Phase::Starting) {
                    x.phase = Phase::Waiting {
                        link: k.clone(),
                        code: c.clone(),
                    };
                }
            }
        }
    };
    let ended = runner.run(
        a.sign_in_argv,
        &env,
        Instant::now() + SIGN_IN_WAIT,
        &mut on_line,
    );
    match ended {
        Ok(true) => {}
        Ok(false) => return Phase::Failed("vendor_refused"),
        Err(code) => return Phase::Failed(code),
    }
    let path = home.path().join(a.login_path);
    let text = match std::fs::metadata(&path) {
        Ok(m) if m.is_file() && (m.len() as usize) <= MAX_LOGIN_BYTES => {
            match std::fs::read_to_string(&path) {
                Ok(t) => Zeroizing::new(t),
                Err(_) => return Phase::Failed("no_login_file"),
            }
        }
        _ => return Phase::Failed("no_login_file"),
    };
    let stored = store_login(store, a.sub_id, &text);
    drop(text);
    drop(home);
    match stored {
        Ok(()) => Phase::Done,
        Err(_) => Phase::Failed("store_refused"),
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use crate::secrets::MemorySecrets;

    const SENTINEL: &str = "{\"tokens\":{\"refresh_token\":\"SENTINEL-refresh-7f3a\"}}";

    fn codex() -> &'static Adapter {
        adapter("codex-chatgpt").unwrap()
    }

    #[test]
    fn only_codex_with_a_chatgpt_plan_has_an_opt_in_and_never_a_forbidden_vendor() {
        let ids: Vec<&str> = ADAPTERS.iter().map(|a| a.sub_id).collect();
        assert_eq!(ids, vec!["codex-chatgpt"]);
        for forbidden in [
            "claude-code-claude",
            "opencode-claude",
            "opencode-google",
            "gemini-cli-google",
            "aider-none",
        ] {
            assert!(adapter(forbidden).is_none(), "{forbidden}");
        }
        for a in ADAPTERS {
            let row = crate::model_subscriptions::SUBSCRIPTIONS
                .iter()
                .find(|s| s.id == a.sub_id)
                .unwrap();
            assert_eq!(row.engine, a.engine);
            assert!(a.revoke_at.starts_with("https://"));
            assert_eq!(a.sign_in_argv.first(), Some(&a.engine));
        }
    }

    #[test]
    fn stored_in_parts_read_back_whole_and_revoked_entirely() {
        let s = MemorySecrets::default();
        let big = format!("{{\"x\":\"{}\",\"s\":{SENTINEL}}}", "a".repeat(9000));
        store_login(&s, "codex-chatgpt", &big).unwrap();
        assert!(signed_in(&s, "codex-chatgpt"));
        assert_eq!(
            load_login(&s, "codex-chatgpt").unwrap().unwrap().as_str(),
            big
        );
        // a shorter one replaces it, and the parts it no longer needs go
        store_login(&s, "codex-chatgpt", SENTINEL).unwrap();
        assert!(!s.exists(&part_name("codex-chatgpt", 1)).unwrap());
        assert_eq!(
            load_login(&s, "codex-chatgpt").unwrap().unwrap().as_str(),
            SENTINEL
        );
        set_opt_in(&s, "codex-chatgpt", 1).unwrap();
        revoke(&s, "codex-chatgpt").unwrap();
        assert!(!signed_in(&s, "codex-chatgpt") && !opted_in(&s, "codex-chatgpt"));
        assert!(s
            .all_names()
            .iter()
            .all(|n| !n.starts_with("subscription-")));
        assert!(load_login(&s, "codex-chatgpt").unwrap().is_none());
    }

    #[test]
    fn a_run_gets_the_sign_in_only_when_opted_in_and_signed_in_and_only_for_its_engine() {
        let s = MemorySecrets::default();
        assert!(for_engine(&s, "codex").is_none());
        store_login(&s, "codex-chatgpt", SENTINEL).unwrap();
        assert!(
            for_engine(&s, "codex").is_none(),
            "signed in but not opted in"
        );
        set_opt_in(&s, "codex-chatgpt", 1).unwrap();
        let a = for_engine(&s, "codex").unwrap();
        for other in ["claude-code", "opencode", "gemini-cli", "aider", "fake"] {
            assert!(for_engine(&s, other).is_none(), "{other}");
        }
        let files = files_for_run(&s, a).unwrap();
        assert_eq!(files[0].path, "auth.json");
        assert_eq!(files[0].contents, SENTINEL);
        assert!(files.iter().all(|f| f.dir_env == "CODEX_HOME"));
        assert!(files
            .iter()
            .any(|f| f.contents.contains("cli_auth_credentials_store = \"file\"")));
        assert!(!format!("{files:?}").contains("SENTINEL"));
    }

    #[test]
    fn the_link_must_be_the_vendors_and_the_code_a_short_code() {
        let h = codex().link_hosts;
        assert_eq!(
            find_link(
                "\u{1b}[1mOpen https://auth.openai.com/codex/device\u{1b}[0m.",
                h
            ),
            Some("https://auth.openai.com/codex/device".to_string())
        );
        assert_eq!(find_link("go to http://auth.openai.com/x", h), None);
        assert_eq!(
            find_link("go to https://auth.openai.com.evil.example/x", h),
            None
        );
        assert_eq!(find_link("go to https://evil.example/openai.com", h), None);
        assert_eq!(
            find_code("Enter this code: ABCD-1234"),
            Some("ABCD-1234".into())
        );
        assert_eq!(find_code("code: abcd-1234 or AB-12"), None);
    }

    struct Fake {
        print: Vec<String>,
        write: Option<&'static str>,
        result: Result<bool, &'static str>,
    }

    impl DeviceSignIn for Fake {
        fn run(
            &self,
            argv: &[&str],
            env: &[(String, String)],
            _: Instant,
            line: &mut dyn FnMut(&str),
        ) -> Result<bool, &'static str> {
            assert_eq!(argv, ["codex", "login", "--device-auth"]);
            let home = &env.iter().find(|(k, _)| k == "CODEX_HOME").unwrap().1;
            assert_eq!(
                env.iter().find(|(k, _)| k == "HOME").map(|(_, v)| v),
                Some(home)
            );
            // the engine is told to keep its sign-in in the file, not the keyring
            assert!(std::fs::read_to_string(Path::new(home).join("config.toml"))
                .unwrap()
                .contains("\"file\""));
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                let mode = std::fs::metadata(home).unwrap().permissions().mode() & 0o777;
                assert_eq!(
                    mode, 0o700,
                    "the sign-in folder is the dashboard user's alone"
                );
            }
            for l in &self.print {
                line(l);
            }
            if let Some(t) = self.write {
                std::fs::write(Path::new(home).join("auth.json"), t).unwrap();
            }
            HOMES.with(|h| h.borrow_mut().push(home.clone()));
            self.result
        }
    }

    thread_local! {
        static HOMES: std::cell::RefCell<Vec<String>> = const { std::cell::RefCell::new(Vec::new()) };
    }

    fn flows_with(id: &str) -> Flows {
        let f: Flows = Arc::default();
        lock(&f).insert(
            id.into(),
            Flow {
                phase: Phase::Starting,
                started_ms: 0,
                audited: false,
            },
        );
        f
    }

    #[test]
    fn a_sign_in_shows_the_vendors_code_stores_the_file_and_leaves_no_folder() {
        let s = MemorySecrets::default();
        let flows = flows_with("codex-chatgpt");
        let fake = Fake {
            print: vec![
                "Open https://auth.openai.com/codex/device".into(),
                "then enter WXYZ-9876".into(),
            ],
            write: Some(SENTINEL),
            result: Ok(true),
        };
        let end = run_sign_in(&flows, codex(), &fake, &s);
        assert_eq!(end, Phase::Done);
        assert_eq!(
            load_login(&s, "codex-chatgpt").unwrap().unwrap().as_str(),
            SENTINEL
        );
        let home = HOMES.with(|h| h.borrow().last().cloned().unwrap());
        assert!(!Path::new(&home).exists(), "the private folder is removed");
        // the phase a person saw carried only the vendor's link and code
        let shown = format!("{:?}", lock(&flows).get("codex-chatgpt").unwrap().phase);
        assert!(shown.contains("WXYZ-9876") && !shown.contains("SENTINEL"));
    }

    #[test]
    fn a_refused_or_empty_sign_in_stores_nothing_and_leaves_no_folder() {
        for (write, result, want) in [
            (None, Ok(true), Phase::Failed("no_login_file")),
            (Some(SENTINEL), Ok(false), Phase::Failed("vendor_refused")),
            (Some(SENTINEL), Err("expired"), Phase::Failed("expired")),
        ] {
            let s = MemorySecrets::default();
            let flows = flows_with("codex-chatgpt");
            let fake = Fake {
                print: vec![],
                write,
                result,
            };
            assert_eq!(run_sign_in(&flows, codex(), &fake, &s), want);
            assert!(s.all_names().is_empty());
            let home = HOMES.with(|h| h.borrow().last().cloned().unwrap());
            assert!(!Path::new(&home).exists());
        }
    }

    #[test]
    fn the_real_runner_reports_a_missing_program() {
        let r = ProcessSignIn.run(
            &["ozbox-no-such-engine-program"],
            &[],
            Instant::now() + Duration::from_secs(5),
            &mut |_| {},
        );
        assert_eq!(r, Err("not_installed"));
    }

    #[cfg(unix)]
    #[test]
    fn the_real_runner_reads_lines_and_the_exit_status_and_gets_no_inherited_environment() {
        std::env::set_var("OZBOX_SIGNIN_TEST_LEAK", "SENTINEL-env");
        let mut lines = Vec::new();
        let r = ProcessSignIn.run(
            &[
                "sh",
                "-c",
                "echo \"x=$OZBOX_SIGNIN_TEST_LEAK y=$CODEX_HOME\"; echo err >&2; exit 0",
            ],
            &[("CODEX_HOME".into(), "/h".into())],
            Instant::now() + Duration::from_secs(10),
            &mut |l| lines.push(l.to_string()),
        );
        assert_eq!(r, Ok(true));
        assert!(lines.contains(&"x= y=/h".to_string()), "{lines:?}");
        assert!(lines.contains(&"err".to_string()));
        let r = ProcessSignIn.run(
            &["sh", "-c", "sleep 5"],
            &[],
            Instant::now() + Duration::from_millis(300),
            &mut |_| {},
        );
        assert_eq!(r, Err("expired"));
    }
}
