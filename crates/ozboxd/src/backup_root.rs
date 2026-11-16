//! Putting backup credentials on the box, without giving the daemon a way to write as root and without leaving a
//! credential where the box user can read it.
//!
//! The daemon runs as an ordinary user. New repository credentials reach the box through the same hand-off the tool
//! installer uses: the daemon leaves a request file in a sticky directory and a root one-shot (`ozboxd backup-root`,
//! started by a systemd path unit) takes it. The helper takes no command and no path from a request: it knows which keys
//! it accepts and checks every value. It does not write the credentials to a file. It hands them to the secrets service
//! over its admin socket (`restic-env` and `restic-password`), where they are encrypted and where restic is run as the
//! secrets user; the box user can neither read them nor look into that process. A credentials file left by an older
//! version is moved into the store and removed (`migrate`).
//!
//! Nothing here puts a value in an answer, a log line or an error.

use std::collections::BTreeMap;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};

pub const ROOT_DIR: &str = "/run/ozbox-backup";
pub const ENV_FILE: &str = "/etc/ozbox/restic.env";
pub const PASS_FILE: &str = "/etc/ozbox/restic.pass";
const MAX_REQUEST: u64 = 16 * 1024;

/// The only keys an env file may carry, and what each is for.
pub const ALLOWED_KEYS: [&str; 6] = [
    "RESTIC_REPOSITORY",
    "AWS_ACCESS_KEY_ID",
    "AWS_SECRET_ACCESS_KEY",
    "AWS_DEFAULT_REGION",
    "B2_ACCOUNT_ID",
    "B2_ACCOUNT_KEY",
];

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Action {
    Set,
    Clear,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Request {
    pub id: String,
    pub action: Action,
    #[serde(default)]
    pub env: BTreeMap<String, String>,
    #[serde(default)]
    pub password: String,
}

/// A request id is a short word of letters, digits and dashes: it becomes a file name.
pub fn valid_id(id: &str) -> bool {
    !id.is_empty() && id.len() <= 40 && id.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-')
}

fn plain(v: &str, max: usize) -> bool {
    !v.is_empty()
        && v.len() <= max
        && v.bytes()
            .all(|b| (0x21..=0x7e).contains(&b) && b != b'"' && b != b'\'' && b != b'\\')
}

/// Whether a repository location is one of the forms restic is given here. A local path is absolute and has no `..`.
pub fn repository_ok(r: &str) -> bool {
    if !plain(r, 512) {
        return false;
    }
    if let Some(rest) = r.strip_prefix("s3:") {
        return rest.starts_with("https://") && rest.len() > "https://".len();
    }
    if let Some(rest) = r.strip_prefix("b2:") {
        return rest.contains(':') || !rest.is_empty();
    }
    if let Some(rest) = r.strip_prefix("sftp:") {
        return rest.contains('@') || rest.contains(':');
    }
    r.starts_with('/') && !r.split('/').any(|s| s == "..")
}

/// Check a request before anything is written. The error says which field, never what it held.
pub fn validate(req: &Request) -> Result<(), String> {
    if !valid_id(&req.id) {
        return Err("the request id is not valid".into());
    }
    if req.action == Action::Clear {
        return Ok(());
    }
    for (k, v) in &req.env {
        if !ALLOWED_KEYS.contains(&k.as_str()) {
            return Err(format!("{k} is not a setting a backup repository uses"));
        }
        if !plain(v, 1024) {
            return Err(format!(
                "the value of {k} has characters that are not allowed"
            ));
        }
    }
    match req.env.get("RESTIC_REPOSITORY") {
        Some(r) if repository_ok(r) => {}
        Some(_) => {
            return Err("RESTIC_REPOSITORY is not a repository location this box accepts".into())
        }
        None => return Err("RESTIC_REPOSITORY is required".into()),
    }
    if !plain(&req.password, 256) || req.password.len() < 8 {
        return Err(
            "the repository password must be 8 to 256 plain characters without spaces".into(),
        );
    }
    Ok(())
}

/// Where the helper hands the credentials. Fields so a test can point it at a fake service.
#[derive(Debug, Clone)]
pub struct Target {
    /// The secrets service's admin socket (root and the secrets user only).
    pub admin_socket: PathBuf,
    /// Where an older version left a credentials file; moved into the store and removed.
    pub legacy_env_file: PathBuf,
    pub legacy_pass_file: PathBuf,
    /// Root's own box config, read (never written) for the settings to carry across an upgrade.
    pub etc_config: PathBuf,
    /// Where the record that backups were set up, and the settings kept with it, live on `/work` (see `backup_state`).
    pub state_dir: PathBuf,
    /// Whose folder and file the record must be (root's, 0, on a box).
    pub trusted_uid: u32,
}

impl Default for Target {
    fn default() -> Self {
        Self {
            admin_socket: PathBuf::from(crate::secrets_link::ADMIN_SOCKET),
            legacy_env_file: PathBuf::from(ENV_FILE),
            legacy_pass_file: PathBuf::from(PASS_FILE),
            etc_config: PathBuf::from(crate::config::DEFAULT_CONFIG_PATH),
            state_dir: crate::backup_state::dir_for(Path::new("/work")),
            trusted_uid: 0,
        }
    }
}

fn store_set(t: &Target, name: &str, value: &str) -> Result<(), String> {
    crate::secrets_link::call(
        &t.admin_socket,
        &serde_json::json!({"op": "set", "name": name, "value": value}),
        Some(Duration::from_secs(20)),
    )
    .map(|_| ())
}

fn store_delete(t: &Target, name: &str) -> Result<(), String> {
    crate::secrets_link::call(
        &t.admin_socket,
        &serde_json::json!({"op": "delete", "name": name}),
        Some(Duration::from_secs(20)),
    )
    .map(|_| ())
}

fn remove_legacy(t: &Target) {
    for p in [&t.legacy_env_file, &t.legacy_pass_file] {
        let _ = std::fs::remove_file(p);
    }
}

/// The settings as the lines the secrets service reads back: `KEY=VALUE`, no password line.
pub fn render_settings(env: &BTreeMap<String, String>) -> String {
    let mut out = String::new();
    for (k, v) in env {
        out.push_str(&format!("{k}={v}\n"));
    }
    out
}

/// Hand the credentials of one validated request to the secrets service (or remove them), then remove any file an older
/// version left.
pub fn apply(req: &Request, t: &Target) -> Result<(), String> {
    validate(req)?;
    match req.action {
        Action::Clear => {
            store_delete(t, crate::secrets_link::RESTIC_ENV)?;
            store_delete(t, crate::secrets_link::RESTIC_PASSWORD)?;
            remove_legacy(t);
            // removed on purpose: the self-test must not call that a loss
            crate::backup_state::remove(&t.state_dir)
        }
        Action::Set => {
            store_set(t, crate::secrets_link::RESTIC_PASSWORD, &req.password)?;
            if let Err(e) = store_set(
                t,
                crate::secrets_link::RESTIC_ENV,
                &crate::secrets_link::hex_encode(&render_settings(&req.env)),
            ) {
                let _ = store_delete(t, crate::secrets_link::RESTIC_PASSWORD);
                return Err(e);
            }
            remove_legacy(t);
            remember(t)
        }
    }
}

/// Keep what an upgrade must not lose, now that the credentials are in the store: the record that backups were set up, and
/// the non-secret settings root's `/etc/ozbox/ozboxd.toml` holds (see `backup_state`). It reads only root's own file, so the
/// box user, who asked for the credentials, chooses none of it. The credentials are already stored when this fails, so the
/// error says what is not kept rather than that the credentials failed.
fn remember(t: &Target) -> Result<(), String> {
    let etc = std::fs::read_to_string(&t.etc_config)
        .ok()
        .and_then(|text| crate::config::Config::from_toml(&text).ok())
        .map(|c| c.backup)
        .unwrap_or_default();
    // an untrusted or unreadable earlier record is replaced by the record of what root's own config says now
    let before = crate::backup_state::read(&t.state_dir, t.trusted_uid)
        .ok()
        .flatten();
    crate::backup_state::write(&t.state_dir, &crate::backup_state::merge(before.as_ref(), &etc))
        .map_err(|_| {
            "the repository credentials were stored, but the record that keeps backups through an upgrade could not be written; \
             send the credentials again, and if that fails look at the folder /work/ozbox-backup"
                .to_string()
        })
}

/// Move a credentials file written by an older version into the store, then remove it. `Ok(false)` when there is none.
pub fn migrate(t: &Target) -> Result<bool, String> {
    let Ok(text) = std::fs::read_to_string(&t.legacy_env_file) else {
        return Ok(false);
    };
    let mut env = crate::backup::parse_env_file(&text);
    let pass_path = env
        .remove("RESTIC_PASSWORD_FILE")
        .map(PathBuf::from)
        .unwrap_or_else(|| t.legacy_pass_file.clone());
    let password = std::fs::read_to_string(&pass_path)
        .map_err(|_| "the old password file could not be read".to_string())?;
    env.retain(|k, _| ALLOWED_KEYS.contains(&k.as_str()));
    store_set(t, crate::secrets_link::RESTIC_PASSWORD, password.trim_end())?;
    store_set(
        t,
        crate::secrets_link::RESTIC_ENV,
        &crate::secrets_link::hex_encode(&render_settings(&env)),
    )?;
    remove_legacy(t);
    let _ = std::fs::remove_file(&pass_path);
    Ok(true)
}

#[derive(Serialize, Deserialize)]
struct Answer {
    ok: bool,
    #[serde(default)]
    error: Option<String>,
}

/// The privileged side: handle every waiting request, then return how many were handled.
pub fn serve_requests(dir: &Path, t: &Target) -> usize {
    let requests = dir.join("requests");
    let results = dir.join("results");
    let Ok(entries) = std::fs::read_dir(&requests) else {
        return 0;
    };
    let mut handled = 0;
    for e in entries.flatten() {
        let path = e.path();
        let Some(stem) = path
            .file_name()
            .and_then(|n| n.to_str())
            .and_then(|n| n.strip_suffix(".json"))
            .filter(|s| valid_id(s))
            .map(str::to_string)
        else {
            continue;
        };
        use std::io::Read;
        let mut text = String::new();
        let read = std::fs::File::open(&path)
            .and_then(|f| f.take(MAX_REQUEST + 1).read_to_string(&mut text))
            .is_ok()
            && text.len() as u64 <= MAX_REQUEST;
        let outcome = if !read {
            Err("the request could not be read".to_string())
        } else {
            match serde_json::from_str::<Request>(&text) {
                Ok(r) if r.id == stem => apply(&r, t),
                Ok(_) => Err("the request id does not match its file".to_string()),
                Err(_) => Err("the request is not valid".to_string()),
            }
        };
        let answer = Answer {
            ok: outcome.is_ok(),
            error: outcome.err(),
        };
        // The answer is written where only root can change it; the request is always removed, so a secret does not
        // outlive the call. It appears whole or not at all: the waiting side reads it as soon as the name exists.
        let _ = std::fs::create_dir_all(&results);
        let _ = write_whole(
            &results.join(format!("{stem}.result")),
            &serde_json::to_vec(&answer).unwrap_or_default(),
        );
        let _ = std::fs::remove_file(&path);
        handled += 1;
    }
    handled
}

/// Write `bytes` to `path` so that a reader polling for the name never sees part of it: the text goes to a hidden name in
/// the same folder first (a name no reader looks for: it starts with a dot and has no `.json` or `.result` ending), and is
/// renamed into place when complete. Both sides of the hand-off poll for a name, so a plain write let either one read a
/// file that was still being written and take it for a bad request or an unclear answer.
fn write_whole(path: &Path, bytes: &[u8]) -> std::io::Result<()> {
    use std::os::unix::fs::OpenOptionsExt;
    let name = path
        .file_name()
        .and_then(|n| n.to_str())
        .ok_or_else(|| std::io::Error::from(std::io::ErrorKind::InvalidInput))?;
    let tmp = path.with_file_name(format!(".{name}.tmp"));
    let _ = std::fs::remove_file(&tmp);
    std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&tmp)
        .and_then(|mut f| f.write_all(bytes).and_then(|()| f.sync_all()))
        .and_then(|()| std::fs::rename(&tmp, path))
        .inspect_err(|_| {
            let _ = std::fs::remove_file(&tmp);
        })
}

/// The unprivileged side: leaves a request and waits for the answer.
pub struct FileBridge {
    pub dir: PathBuf,
    pub timeout: Duration,
    pub poll: Duration,
}

impl FileBridge {
    pub fn new(dir: impl Into<PathBuf>) -> Self {
        Self {
            dir: dir.into(),
            timeout: Duration::from_secs(30),
            poll: Duration::from_millis(250),
        }
    }

    pub fn send(&self, req: &Request) -> Result<(), String> {
        validate(req)?;
        let req_path = self.dir.join("requests").join(format!("{}.json", req.id));
        let result_path = self.dir.join("results").join(format!("{}.result", req.id));
        let _ = std::fs::remove_file(&result_path);
        let body =
            serde_json::to_vec(req).map_err(|_| "the request could not be written".to_string())?;
        if req_path.exists() {
            return Err("a request with that id is already waiting".into());
        }
        write_whole(&req_path, &body)
            .map_err(|e| format!("cannot reach the credentials helper: {}", e.kind()))?;
        let start = Instant::now();
        loop {
            if let Ok(bytes) = std::fs::read(&result_path) {
                let _ = std::fs::remove_file(&result_path);
                let a: Answer = serde_json::from_slice(&bytes).unwrap_or(Answer {
                    ok: false,
                    error: Some("the credentials helper gave no clear answer".into()),
                });
                return if a.ok {
                    Ok(())
                } else {
                    Err(a
                        .error
                        .unwrap_or_else(|| "the credentials helper failed".into()))
                };
            }
            if start.elapsed() > self.timeout {
                let _ = std::fs::remove_file(&req_path);
                return Err(
                    "the credentials helper did not answer in time; is it installed on this box?"
                        .into(),
                );
            }
            std::thread::sleep(self.poll);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn req(id: &str) -> Request {
        Request {
            id: id.into(),
            action: Action::Set,
            env: BTreeMap::from([
                (
                    "RESTIC_REPOSITORY".to_string(),
                    "s3:https://objects.example.com/bucket/boxes".to_string(),
                ),
                ("AWS_ACCESS_KEY_ID".to_string(), "AKIAEXAMPLE".to_string()),
                (
                    "AWS_SECRET_ACCESS_KEY".to_string(),
                    "sekrit-key".to_string(),
                ),
            ]),
            password: "correct-horse-battery".into(),
        }
    }

    fn me() -> u32 {
        use std::os::unix::fs::MetadataExt;
        std::fs::metadata(".").unwrap().uid()
    }

    type Store = std::sync::Arc<std::sync::Mutex<BTreeMap<String, String>>>;

    /// A stand-in for the secrets service's admin socket that keeps what it is given in memory.
    fn fake_service(dir: &Path) -> (Target, Store) {
        use std::io::{BufRead, BufReader};
        let sock = dir.join("admin.sock");
        let l = std::os::unix::net::UnixListener::bind(&sock).unwrap();
        let store: Store = Default::default();
        let st = store.clone();
        std::thread::spawn(move || {
            for c in l.incoming().flatten() {
                let mut line = String::new();
                BufReader::new(&c).read_line(&mut line).unwrap();
                let v: serde_json::Value = serde_json::from_str(&line).unwrap();
                let name = v["name"].as_str().unwrap_or("").to_string();
                match v["op"].as_str() {
                    Some("set") => {
                        st.lock()
                            .unwrap()
                            .insert(name, v["value"].as_str().unwrap().into());
                    }
                    Some("delete") => {
                        st.lock().unwrap().remove(&name);
                    }
                    _ => {}
                }
                let mut w = &c;
                w.write_all(b"{\"ok\":true}\n").unwrap();
            }
        });
        (
            Target {
                admin_socket: sock,
                legacy_env_file: dir.join("restic.env"),
                legacy_pass_file: dir.join("restic.pass"),
                etc_config: dir.join("etc-ozboxd.toml"),
                state_dir: dir.join("state").join("ozbox-backup"),
                trusted_uid: me(),
            },
            store,
        )
    }

    fn target(dir: &Path) -> Target {
        fake_service(dir).0
    }

    #[test]
    fn the_credentials_go_to_the_secrets_service_and_no_file_holds_them() {
        let dir = tempfile::tempdir().unwrap();
        let (t, store) = fake_service(dir.path());
        apply(&req("a1"), &t).unwrap();
        let mut held = store.lock().unwrap().clone();
        if let Some(h) = held.get("restic-env").cloned() {
            held.insert(
                "restic-env".into(),
                crate::secrets_link::hex_decode(&h).unwrap(),
            );
        }
        assert_eq!(held["restic-password"], "correct-horse-battery");
        assert!(held["restic-env"]
            .contains("RESTIC_REPOSITORY=s3:https://objects.example.com/bucket/boxes\n"));
        assert!(held["restic-env"].contains("AWS_SECRET_ACCESS_KEY=sekrit-key\n"));
        assert!(!held["restic-env"].contains("correct-horse-battery"));
        // nothing was written beside it: the box user would be able to read a file
        assert!(!t.legacy_env_file.exists() && !t.legacy_pass_file.exists());
        // the only other thing written is the record root keeps on /work (no credential in it)
        assert!(std::fs::read_dir(dir.path())
            .unwrap()
            .flatten()
            .all(|e| e.file_name() == "admin.sock" || e.file_name() == "state"));
    }

    #[test]
    fn a_credentials_file_from_an_older_version_is_moved_into_the_store_and_removed() {
        let dir = tempfile::tempdir().unwrap();
        let (t, store) = fake_service(dir.path());
        assert!(!migrate(&t).unwrap(), "nothing to move");
        std::fs::write(
            &t.legacy_env_file,
            format!("RESTIC_REPOSITORY=s3:https://objects.example.com/b\nAWS_SECRET_ACCESS_KEY=old-sekrit\nLD_PRELOAD=/tmp/x.so\nRESTIC_PASSWORD_FILE={}\n", t.legacy_pass_file.display()),
        )
        .unwrap();
        std::fs::write(&t.legacy_pass_file, "old-password-value\n").unwrap();
        assert!(migrate(&t).unwrap());
        let mut held = store.lock().unwrap().clone();
        if let Some(h) = held.get("restic-env").cloned() {
            held.insert(
                "restic-env".into(),
                crate::secrets_link::hex_decode(&h).unwrap(),
            );
        }
        assert_eq!(held["restic-password"], "old-password-value");
        assert!(held["restic-env"].contains("AWS_SECRET_ACCESS_KEY=old-sekrit"));
        assert!(
            !held["restic-env"].contains("LD_PRELOAD")
                && !held["restic-env"].contains("PASSWORD_FILE")
        );
        assert!(!t.legacy_env_file.exists() && !t.legacy_pass_file.exists());
    }

    #[test]
    fn without_the_service_nothing_is_written_anywhere() {
        let dir = tempfile::tempdir().unwrap();
        let t = Target {
            admin_socket: dir.path().join("none.sock"),
            legacy_env_file: dir.path().join("restic.env"),
            legacy_pass_file: dir.path().join("restic.pass"),
            etc_config: dir.path().join("etc-ozboxd.toml"),
            state_dir: dir.path().join("state").join("ozbox-backup"),
            trusted_uid: me(),
        };
        let e = apply(&req("n1"), &t).unwrap_err();
        assert!(e.contains("secrets service") && !e.contains("sekrit"));
        assert_eq!(std::fs::read_dir(dir.path()).unwrap().count(), 0);
    }

    #[test]
    fn a_bad_request_writes_nothing_and_its_error_never_holds_a_value() {
        let dir = tempfile::tempdir().unwrap();
        let t = target(dir.path());
        let mut cases = Vec::new();
        let mut r = req("b1");
        r.env.insert("LD_PRELOAD".into(), "/tmp/evil.so".into());
        cases.push(r);
        let mut r = req("b2");
        r.env
            .insert("AWS_SECRET_ACCESS_KEY".into(), "line\nbreak".into());
        cases.push(r);
        let mut r = req("b3");
        r.env
            .insert("RESTIC_REPOSITORY".into(), "/etc/../shadow".into());
        cases.push(r);
        let mut r = req("b4");
        r.env.insert(
            "RESTIC_REPOSITORY".into(),
            "s3:http://plain.example.com/b".into(),
        );
        cases.push(r);
        let mut r = req("b5");
        r.password = "short".into();
        cases.push(r);
        cases.push(req("../x"));
        for c in cases {
            let e = apply(&c, &t).unwrap_err();
            assert!(
                !e.contains("evil")
                    && !e.contains("sekrit")
                    && !e.contains("shadow")
                    && !e.contains("short"),
                "{e}"
            );
        }
        assert!(std::fs::read_dir(dir.path())
            .unwrap()
            .flatten()
            .all(|e| e.file_name() == "admin.sock"));
    }

    #[test]
    fn clearing_removes_both_from_the_store_and_is_safe_to_repeat() {
        let dir = tempfile::tempdir().unwrap();
        let (t, store) = fake_service(dir.path());
        apply(&req("c1"), &t).unwrap();
        assert_eq!(store.lock().unwrap().len(), 2);
        let clear = Request {
            id: "c2".into(),
            action: Action::Clear,
            env: BTreeMap::new(),
            password: String::new(),
        };
        apply(&clear, &t).unwrap();
        apply(&clear, &t).unwrap();
        assert!(store.lock().unwrap().is_empty());
    }

    #[test]
    fn the_helper_answers_each_request_and_always_removes_it() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().join("spool");
        std::fs::create_dir_all(root.join("requests")).unwrap();
        let (t, store) = fake_service(dir.path());
        std::fs::write(
            root.join("requests/ok1.json"),
            serde_json::to_vec(&req("ok1")).unwrap(),
        )
        .unwrap();
        std::fs::write(root.join("requests/bad1.json"), b"not json").unwrap();
        std::fs::write(
            root.join("requests/mismatch.json"),
            serde_json::to_vec(&req("other")).unwrap(),
        )
        .unwrap();
        std::fs::write(root.join("requests/..evil.json"), b"{}").unwrap();
        assert_eq!(serve_requests(&root, &t), 3);
        let ans = |id: &str| -> serde_json::Value {
            serde_json::from_slice(
                &std::fs::read(root.join(format!("results/{id}.result"))).unwrap(),
            )
            .unwrap()
        };
        assert_eq!(ans("ok1")["ok"], true);
        assert_eq!(ans("bad1")["ok"], false);
        assert_eq!(ans("mismatch")["ok"], false);
        assert!(std::fs::read_dir(root.join("requests"))
            .unwrap()
            .flatten()
            .all(|e| e.file_name() == "..evil.json"));
        assert!(store.lock().unwrap().contains_key("restic-env"));
    }

    #[test]
    fn the_bridge_leaves_a_private_request_and_returns_the_helpers_answer() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().join("spool");
        std::fs::create_dir_all(root.join("requests")).unwrap();
        std::fs::create_dir_all(root.join("results")).unwrap();
        let t = target(dir.path());
        let helper_root = root.clone();
        // The helper keeps looking for as long as the bridge keeps waiting (and stops when told), so a loaded machine
        // slows the test down rather than failing it.
        let done = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
        let stop = done.clone();
        let helper = std::thread::spawn(move || {
            while !stop.load(std::sync::atomic::Ordering::SeqCst) {
                if serve_requests(&helper_root, &t) > 0 {
                    return;
                }
                std::thread::sleep(Duration::from_millis(10));
            }
        });
        let mut bridge = FileBridge::new(&root);
        bridge.poll = Duration::from_millis(10);
        let sent = bridge.send(&req("br1"));
        done.store(true, std::sync::atomic::Ordering::SeqCst);
        helper.join().unwrap();
        sent.unwrap();
        // no helper: a clear error and the request is withdrawn
        let mut lonely = FileBridge::new(&root);
        lonely.poll = Duration::from_millis(5);
        lonely.timeout = Duration::from_millis(30);
        let e = lonely.send(&req("br2")).unwrap_err();
        assert!(e.contains("did not answer"));
        assert!(!root.join("requests/br2.json").exists());
    }

    /// The cause of a failure seen only under load: each side polls for a name, and each wrote its file in place, so the
    /// other could read it half written ("the credentials helper gave no clear answer"). Every request and answer a
    /// watcher can see by name is now complete.
    #[test]
    fn a_request_or_an_answer_is_never_seen_half_written() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().join("spool");
        std::fs::create_dir_all(root.join("requests")).unwrap();
        std::fs::create_dir_all(root.join("results")).unwrap();
        let stop = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
        let (s2, r2) = (stop.clone(), root.clone());
        let watcher = std::thread::spawn(move || {
            let mut seen = 0;
            while !s2.load(std::sync::atomic::Ordering::SeqCst) {
                for (sub, end) in [("requests", ".json"), ("results", ".result")] {
                    for e in std::fs::read_dir(r2.join(sub)).unwrap().flatten() {
                        let n = e.file_name().to_string_lossy().to_string();
                        if !n.ends_with(end) {
                            continue;
                        }
                        // gone already is fine; there and not whole is the bug
                        if let Ok(b) = std::fs::read(e.path()) {
                            assert!(
                                serde_json::from_slice::<serde_json::Value>(&b).is_ok(),
                                "{n} was seen half written"
                            );
                            seen += 1;
                        }
                    }
                }
            }
            seen
        });
        let t = target(dir.path());
        for i in 0..40 {
            let r = req(&format!("hw{i}"));
            let body = serde_json::to_vec(&r).unwrap();
            write_whole(&root.join(format!("requests/hw{i}.json")), &body).unwrap();
            serve_requests(&root, &t);
        }
        stop.store(true, std::sync::atomic::Ordering::SeqCst);
        watcher.join().unwrap();
        // nothing hidden is left behind
        for sub in ["requests", "results"] {
            for e in std::fs::read_dir(root.join(sub)).unwrap().flatten() {
                assert!(!e.file_name().to_string_lossy().ends_with(".tmp"));
            }
        }
    }

    fn etc_with(t: &Target, backup: &str) {
        std::fs::write(
            &t.etc_config,
            format!("[backup]\nenabled = false\n{backup}"),
        )
        .unwrap();
    }

    #[test]
    fn setting_credentials_records_that_backups_exist_and_carries_root_settings_only() {
        use crate::backup_state::{read, Carried};
        let dir = tempfile::tempdir().unwrap();
        let (t, _store) = fake_service(dir.path());
        etc_with(
            &t,
            "service_socket = \"/run/ozbox-secrets/broker/broker.sock\"\nexcludes = [\"/work/.ozbox/metrics\", \"/work/scratch\"]\ninterval_hours = 6\n",
        );
        assert_eq!(read(&t.state_dir, me()), Ok(None));
        apply(&req("r1"), &t).unwrap();
        let kept: Carried = read(&t.state_dir, me()).unwrap().unwrap();
        assert!(kept.configured);
        assert_eq!(kept.interval_hours, Some(6));
        assert_eq!(
            kept.excludes,
            Some(vec!["/work/.ozbox/metrics".into(), "/work/scratch".into()])
        );
        assert_eq!(kept.paths, None, "a default is not a choice");
        let text = std::fs::read_to_string(t.state_dir.join("backup.toml")).unwrap();
        for secret in ["correct-horse-battery", "sekrit-key", "objects.example.com"] {
            assert!(!text.contains(secret), "{secret}");
        }
    }

    #[test]
    fn the_record_survives_a_new_system_disk_and_is_not_overwritten_by_its_defaults() {
        use crate::backup_state::read;
        let dir = tempfile::tempdir().unwrap();
        let (t, _store) = fake_service(dir.path());
        etc_with(&t, "interval_hours = 6\n");
        apply(&req("u1"), &t).unwrap();
        // the upgrade: /etc starts again from the first-boot file, /work (the record) stays
        etc_with(&t, "");
        apply(&req("u2"), &t).unwrap();
        let kept = read(&t.state_dir, me()).unwrap().unwrap();
        assert_eq!(kept.interval_hours, Some(6));
    }

    #[test]
    fn clearing_the_credentials_removes_the_record_so_a_deliberate_removal_is_not_a_loss() {
        use crate::backup_state::read;
        let dir = tempfile::tempdir().unwrap();
        let (t, _store) = fake_service(dir.path());
        apply(&req("k1"), &t).unwrap();
        assert!(read(&t.state_dir, me()).unwrap().is_some());
        let clear = Request {
            id: "k2".into(),
            action: Action::Clear,
            env: BTreeMap::new(),
            password: String::new(),
        };
        apply(&clear, &t).unwrap();
        assert_eq!(read(&t.state_dir, me()), Ok(None));
    }

    #[test]
    fn a_record_that_cannot_be_written_says_so_without_failing_the_credentials_silently() {
        let dir = tempfile::tempdir().unwrap();
        let (mut t, store) = fake_service(dir.path());
        // a file where the folder must go
        std::fs::write(dir.path().join("blocked"), "x").unwrap();
        t.state_dir = dir.path().join("blocked").join("ozbox-backup");
        let e = apply(&req("w1"), &t).unwrap_err();
        assert!(e.contains("stored") && e.contains("upgrade"), "{e}");
        assert!(!e.contains("sekrit") && !e.contains("correct-horse"));
        assert!(store.lock().unwrap().contains_key("restic-env"));
    }
}
