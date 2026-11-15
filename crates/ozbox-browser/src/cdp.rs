//! A small DevTools-protocol client over Chromium's `--remote-debugging-pipe`: JSON messages separated by a NUL byte, on a
//! pipe the worker owns. There is no port and no WebSocket, so there is nothing for anything else on the box to connect to.
//!
//! Chromium reads commands from file descriptor 3 and writes replies and events to 4. A process in Rust without `unsafe`
//! cannot hand a child descriptors 3 and 4 directly, so [`launch`] starts it through `sh`, which can: the child's standard
//! input and output become 3 and 4, and its own are closed.

use std::collections::{HashMap, HashSet, VecDeque};
use std::io::{Read, Write};
use std::process::{Child, Command, Stdio};
use std::sync::mpsc::{self, Receiver, RecvTimeoutError};
use std::time::{Duration, Instant};

use serde_json::{json, Value};

/// Cut a byte stream into messages at NUL. Pure, so it is tested on any OS.
#[derive(Default)]
pub struct Framer {
    buf: Vec<u8>,
}

impl Framer {
    pub fn push(&mut self, bytes: &[u8]) -> Vec<String> {
        let mut out = Vec::new();
        for b in bytes {
            if *b == 0 {
                if !self.buf.is_empty() {
                    out.push(String::from_utf8_lossy(&self.buf).into_owned());
                }
                self.buf.clear();
            } else {
                self.buf.push(*b);
            }
        }
        out
    }
}

/// What a hook does with one event: commands to send straight back (in order, without waiting for their replies), and
/// whether the event is also kept for [`Cdp::take_events`].
#[derive(Debug, Default)]
pub struct HookOut {
    pub send: Vec<(Option<String>, String, Value)>,
    pub keep: bool,
    /// The commands set up a target that just appeared. Their replies are followed (see [`Cdp::setup_state`]), so the
    /// target is not used before the browser has done all of them, and not at all when it refused one.
    pub setup: bool,
    /// Sent once the browser has done every setup command for that session, and never when it refused one: the command
    /// that lets a target held paused run (session, method, params). A target whose requests could not be put under
    /// judgement stays paused, so it sends nothing.
    pub release: Option<(String, String, Value)>,
}

impl HookOut {
    pub fn keep() -> Self {
        Self {
            keep: true,
            ..Self::default()
        }
    }
    pub fn answer(session: Option<String>, method: &str, params: Value) -> Self {
        Self {
            send: vec![(session, method.to_string(), params)],
            ..Self::default()
        }
    }
}

/// Where the commands that set up a target stand.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Setup {
    /// The browser has not answered all of them yet.
    Pending,
    /// The browser did every one.
    Ready,
    /// The browser refused one: the target is not set up as it must be.
    Failed,
}

/// Answers an event the moment it arrives, with commands to send straight back. Needed because a paused request blocks the
/// very call that is waiting for the page to load, and a new tab or frame waits paused until it is set up: the answer
/// cannot wait for the caller to get round to it. A hook never waits for a reply itself.
pub type Hook = Box<dyn FnMut(&Value) -> HookOut + Send>;

pub struct Cdp {
    tx: Box<dyn Write + Send>,
    hook: Option<Hook>,
    rx: Receiver<Value>,
    next: u64,
    events: VecDeque<Value>,
    /// Setup commands sent for a session and not answered yet, by id.
    setup_wait: HashMap<u64, String>,
    /// Sessions whose setup the browser refused.
    setup_failed: HashSet<String>,
    /// Sessions whose page crashed and has not been opened again.
    crashed: HashSet<String>,
    /// The command that lets a session's target run, held until its setup is done.
    release_wait: HashMap<String, (String, Value)>,
    /// Chromium may send a message that is not JSON, or one that is not ours: it is dropped.
    pub timeout: Duration,
}

const MAX_EVENTS: usize = 4000;

/// What a command on a tab whose page crashed says.
pub const CRASHED: &str =
    "the page in this tab crashed (the browser stopped it): navigate to open a page in it again";

impl Cdp {
    pub fn new(tx: Box<dyn Write + Send>, rx_stream: Box<dyn Read + Send>) -> Self {
        let (s, rx) = mpsc::channel();
        std::thread::spawn(move || {
            let mut r = rx_stream;
            let mut f = Framer::default();
            let mut chunk = [0u8; 65536];
            loop {
                match r.read(&mut chunk) {
                    Ok(0) | Err(_) => break,
                    Ok(n) => {
                        for m in f.push(&chunk[..n]) {
                            if let Ok(v) = serde_json::from_str::<Value>(&m) {
                                if s.send(v).is_err() {
                                    return;
                                }
                            }
                        }
                    }
                }
            }
        });
        Self {
            tx,
            hook: None,
            rx,
            next: 0,
            events: VecDeque::new(),
            setup_wait: HashMap::new(),
            setup_failed: HashSet::new(),
            crashed: HashSet::new(),
            release_wait: HashMap::new(),
            timeout: Duration::from_secs(30),
        }
    }

    pub fn set_hook(&mut self, h: Hook) {
        self.hook = Some(h);
    }

    fn fire(&mut self, session: Option<&str>, method: &str, params: Value) -> u64 {
        self.next += 1;
        let mut msg = json!({ "id": self.next, "method": method, "params": params });
        if let Some(s) = session {
            msg["sessionId"] = json!(s);
        }
        if let Ok(mut b) = serde_json::to_vec(&msg) {
            b.push(0);
            let _ = self.tx.write_all(&b).and_then(|()| self.tx.flush());
        }
        self.next
    }

    /// Whether a session's page crashed (its renderer is gone) and has not been opened again since.
    pub fn crashed(&self, session: &str) -> bool {
        self.crashed.contains(session)
    }

    /// Whether the browser has done the commands that set up a session's target. A session nothing set up is ready.
    pub fn setup_state(&self, session: &str) -> Setup {
        if self.setup_failed.contains(session) {
            Setup::Failed
        } else if self.setup_wait.values().any(|s| s == session) {
            Setup::Pending
        } else {
            Setup::Ready
        }
    }

    fn keep(&mut self, v: Value) {
        // the reply to a command sent without waiting is not an event
        if v.get("id").is_some() && v.get("method").is_none() {
            if let Some(s) = v["id"].as_u64().and_then(|id| self.setup_wait.remove(&id)) {
                if v.get("error").is_some() {
                    self.setup_failed.insert(s.clone());
                    self.release_wait.remove(&s);
                } else if !self.setup_wait.values().any(|x| *x == s) {
                    if let Some((m, p)) = self.release_wait.remove(&s) {
                        self.fire(Some(&s), &m, p);
                    }
                }
            }
            return;
        }
        if v["method"] == "Target.detachedFromTarget" {
            if let Some(gone) = v["params"]["sessionId"].as_str() {
                self.setup_wait.retain(|_, s| s != gone);
                self.setup_failed.remove(gone);
                self.crashed.remove(gone);
                self.release_wait.remove(gone);
            }
        }
        if let Some(s) = v["sessionId"].as_str() {
            if v["method"] == "Inspector.targetCrashed" {
                self.crashed.insert(s.to_string());
            } else if v["method"] == "Page.frameNavigated"
                && v["params"]["frame"]
                    .get("parentId")
                    .is_none_or(Value::is_null)
            {
                // a page committed in the tab again: it has a renderer once more
                self.crashed.remove(s);
            }
        }
        if let Some(h) = self.hook.as_mut() {
            let out = h(&v);
            for (s, m, p) in out.send {
                let id = self.fire(s.as_deref(), &m, p);
                if let (true, Some(s)) = (out.setup, s) {
                    self.setup_wait.insert(id, s);
                }
            }
            if let Some((s, m, p)) = out.release {
                if self.setup_failed.contains(&s) {
                    // refused: the target stays paused
                } else if self.setup_wait.values().any(|x| *x == s) {
                    self.release_wait.insert(s, (m, p));
                } else {
                    self.fire(Some(&s), &m, p);
                }
            }
            if !out.keep {
                return;
            }
        }
        if self.events.len() >= MAX_EVENTS {
            self.events.pop_front();
        }
        self.events.push_back(v);
    }

    /// Send a command and wait for its reply. Events that arrive meanwhile are kept for [`Cdp::take_events`].
    ///
    /// On a session whose page crashed, a command the dead page would have to answer is refused at once, and one in
    /// flight when the page crashes ends then: it would otherwise wait out [`Cdp::timeout`] for a reply that never comes.
    /// Opening a page in the tab again (`Page.navigate`) is what brings it back.
    pub fn call(
        &mut self,
        session: Option<&str>,
        method: &str,
        params: Value,
    ) -> Result<Value, String> {
        let needs_page = method != "Page.navigate" && !method.starts_with("Target.");
        let dead = |c: &Self| needs_page && session.is_some_and(|s| c.crashed.contains(s));
        if dead(self) {
            return Err(CRASHED.into());
        }
        self.next += 1;
        let id = self.next;
        let mut msg = json!({ "id": id, "method": method, "params": params });
        if let Some(s) = session {
            msg["sessionId"] = json!(s);
        }
        let mut bytes = serde_json::to_vec(&msg).map_err(|e| e.to_string())?;
        bytes.push(0);
        self.tx
            .write_all(&bytes)
            .and_then(|()| self.tx.flush())
            .map_err(|_| "the browser is gone".to_string())?;
        let deadline = Instant::now() + self.timeout;
        loop {
            let left = deadline.saturating_duration_since(Instant::now());
            match self.rx.recv_timeout(left) {
                Ok(v) if v.get("id").and_then(Value::as_u64) == Some(id) => {
                    return match v.get("error") {
                        Some(e) => Err(e
                            .get("message")
                            .and_then(Value::as_str)
                            .unwrap_or("the browser refused")
                            .to_string()),
                        None => Ok(v.get("result").cloned().unwrap_or(Value::Null)),
                    };
                }
                Ok(v) => {
                    self.keep(v);
                    if dead(self) {
                        return Err(CRASHED.into());
                    }
                }
                Err(RecvTimeoutError::Timeout) => {
                    return Err(format!("the browser did not answer {method} in time"))
                }
                Err(RecvTimeoutError::Disconnected) => return Err("the browser is gone".into()),
            }
        }
    }

    /// The browser's first call, with the window a starting browser needs rather than the per-call timeout: a loaded
    /// machine can take far longer than an ordinary command to get Chromium to answer on its pipe. Waits up to `window`
    /// for the answer, then puts the ordinary per-call timeout back, and says which phase failed: the browser exiting
    /// while it starts is a launch failure, one that is up but silent is a first-call timeout. Every later call keeps
    /// the ordinary timeout.
    pub fn await_ready(&mut self, window: Duration) -> Result<Value, String> {
        let ordinary = self.timeout;
        self.timeout = window;
        let r = self.call(None, "Browser.getVersion", json!({}));
        self.timeout = ordinary;
        r.map_err(|e| {
            if e.contains("did not answer") {
                format!(
                    "the browser did not start: no answer on its DevTools pipe within {}s (first call)",
                    window.as_secs().max(1)
                )
            } else if e == "the browser is gone" {
                "the browser did not start: it exited before it answered (launch)".to_string()
            } else {
                e
            }
        })
    }

    /// Pull in whatever the browser has said, waiting at most `wait` for the first message.
    pub fn pump(&mut self, wait: Duration) -> bool {
        let mut got = false;
        let mut wait = wait;
        while let Ok(v) = self.rx.recv_timeout(wait) {
            self.keep(v);
            got = true;
            wait = Duration::ZERO;
        }
        got
    }

    pub fn take_events(&mut self) -> Vec<Value> {
        self.events.drain(..).collect()
    }

    /// Wait for an event the predicate accepts, keeping the others.
    pub fn wait_event(
        &mut self,
        timeout: Duration,
        pred: impl Fn(&Value) -> bool,
    ) -> Option<Value> {
        if let Some(i) = self.events.iter().position(&pred) {
            return self.events.remove(i);
        }
        let deadline = Instant::now() + timeout;
        loop {
            let left = deadline.saturating_duration_since(Instant::now());
            match self.rx.recv_timeout(left) {
                Ok(v) if pred(&v) => return Some(v),
                Ok(v) => self.keep(v),
                Err(_) => return None,
            }
        }
    }
}

/// Stops the browser and every helper it started. The browser leads its own process group (see [`launch`]), so one signal to the
/// group reaches the helpers a plain `Child::kill` leaves behind. Call it before `wait`, while the leader still holds the group id.
pub fn kill_browser(child: &mut Child) {
    #[cfg(unix)]
    {
        let _ = Command::new("kill")
            .args(["-KILL", "--", &format!("-{}", child.id())])
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status();
    }
    let _ = child.kill();
    let _ = child.wait();
}

pub struct Launched {
    pub child: Child,
    pub cdp: Cdp,
}

pub struct LaunchOpts {
    pub binary: String,
    pub profile_dir: String,
    pub width: u32,
    pub height: u32,
    pub proxy: Option<String>,
    pub no_sandbox: bool,
    pub max_old_space_mb: u32,
}

pub fn find_chromium() -> Option<String> {
    if let Ok(p) = std::env::var("OZBOX_CHROMIUM") {
        if !p.is_empty() {
            return Some(p);
        }
    }
    let names = [
        "chromium",
        "chromium-browser",
        "google-chrome",
        "google-chrome-stable",
    ];
    let path = std::env::var("PATH").unwrap_or_default();
    for n in names {
        for d in path.split(':') {
            let p = std::path::Path::new(d).join(n);
            if p.is_file() {
                return Some(p.to_string_lossy().into_owned());
            }
        }
    }
    let mac = "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome";
    std::path::Path::new(mac).is_file().then(|| mac.to_string())
}

/// The arguments Chromium starts with. Pure, so a test can hold them: headless, one isolated profile, no extensions, no
/// first-run pages, and the only way in is the pipe.
pub fn chromium_args(o: &LaunchOpts) -> Vec<String> {
    let mut a: Vec<String> = [
        "--headless=new",
        "--remote-debugging-pipe",
        "--no-first-run",
        "--no-default-browser-check",
        "--disable-extensions",
        "--disable-gpu",
        "--disable-dev-shm-usage",
        "--disable-background-networking",
        "--disable-sync",
        "--mute-audio",
        "--hide-scrollbars",
        "--password-store=basic",
        "--use-mock-keychain",
        // a page may not open a window: the browser refuses it before anything is made, and the worker reports where it
        // would have gone (`Page.windowOpen`)
        "--block-new-web-contents",
    ]
    .iter()
    .map(|s| (*s).to_string())
    .collect();
    a.push(format!("--user-data-dir={}", o.profile_dir));
    a.push(format!("--window-size={},{}", o.width, o.height));
    a.push(format!(
        "--js-flags=--max-old-space-size={}",
        o.max_old_space_mb
    ));
    if o.no_sandbox {
        a.push("--no-sandbox".into());
    }
    if let Some(p) = &o.proxy {
        a.push(format!("--proxy-server={p}"));
    }
    a.push("about:blank".into());
    a
}

/// How long a starting browser has to answer its first call.
pub const START_WINDOW: Duration = Duration::from_secs(90);

pub fn launch(o: &LaunchOpts) -> Result<Launched, String> {
    let mut argv = vec![
        "-c".to_string(),
        // fd 3 = what we write, fd 4 = what we read; the browser's own stdin and stdout are closed
        r#"exec "$@" 3<&0 4>&1 0</dev/null 1>/dev/null"#.to_string(),
        "sh".to_string(),
        o.binary.clone(),
    ];
    argv.extend(chromium_args(o));
    let mut cmd = Command::new("sh");
    cmd.args(&argv)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null());
    // Its own process group, so closing the session can stop every helper the browser started (renderer, GPU, network
    // service), not only the main process: a helper left running keeps writing into the profile folder.
    #[cfg(unix)]
    std::os::unix::process::CommandExt::process_group(&mut cmd, 0);
    let mut child = cmd
        .spawn()
        .map_err(|e| format!("the browser could not be started: {e}"))?;
    let stdin = child.stdin.take().ok_or("no pipe to the browser")?;
    let stdout = child.stdout.take().ok_or("no pipe from the browser")?;
    Ok(Launched {
        child,
        cdp: Cdp::new(Box::new(stdin), Box::new(stdout)),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(unix)]
    #[test]
    fn closing_stops_the_helpers_the_browser_started_not_only_its_main_process() {
        use std::io::Read;
        let mut cmd = Command::new("sh");
        cmd.args(["-c", "sleep 60 & echo $!; wait"])
            .stdout(Stdio::piped())
            .stderr(Stdio::null());
        std::os::unix::process::CommandExt::process_group(&mut cmd, 0);
        let mut child = cmd.spawn().unwrap();
        let mut out = child.stdout.take().unwrap();
        let mut buf = [0u8; 32];
        let n = out.read(&mut buf).unwrap();
        let helper: u32 = String::from_utf8_lossy(&buf[..n]).trim().parse().unwrap();
        kill_browser(&mut child);
        let mut gone = false;
        for _ in 0..50 {
            let alive = Command::new("kill")
                .args(["-0", &helper.to_string()])
                .stderr(Stdio::null())
                .status()
                .unwrap()
                .success();
            if !alive {
                gone = true;
                break;
            }
            std::thread::sleep(Duration::from_millis(100));
        }
        assert!(gone, "the helper outlived the browser's close");
    }

    #[test]
    fn messages_are_cut_at_nul_across_reads() {
        let mut f = Framer::default();
        assert_eq!(f.push(b"{\"id\":1}\0{\"id"), vec!["{\"id\":1}"]);
        assert_eq!(f.push(b"\":2}\0\0"), vec!["{\"id\":2}"]);
        assert!(f.push(b"partial").is_empty());
    }

    #[test]
    fn the_browser_starts_isolated_with_only_the_pipe() {
        let o = LaunchOpts {
            binary: "chromium".into(),
            profile_dir: "/p".into(),
            width: 390,
            height: 844,
            proxy: None,
            no_sandbox: false,
            max_old_space_mb: 512,
        };
        let a = chromium_args(&o);
        assert!(a.contains(&"--remote-debugging-pipe".to_string()));
        assert!(a.contains(&"--block-new-web-contents".to_string()));
        assert!(!a
            .iter()
            .any(|x| x.starts_with("--remote-debugging-port")
                || x.starts_with("--remote-allow-origins")));
        assert!(a.contains(&"--user-data-dir=/p".to_string()));
        assert!(a.contains(&"--window-size=390,844".to_string()));
        assert!(
            !a.contains(&"--no-sandbox".to_string())
                && !a.iter().any(|x| x.starts_with("--proxy-server"))
        );
        let o2 = LaunchOpts {
            no_sandbox: true,
            proxy: Some("http://p:1".into()),
            ..o
        };
        let a = chromium_args(&o2);
        assert!(
            a.contains(&"--no-sandbox".to_string())
                && a.contains(&"--proxy-server=http://p:1".to_string())
        );
    }

    #[test]
    fn a_target_is_ready_only_once_the_browser_did_every_command_that_set_it_up() {
        let attach = |s: &str| {
            format!(
                "{{\"method\":\"Target.attachedToTarget\",\"params\":{{\"sessionId\":\"{s}\"}}}}\0"
            )
        };
        // two targets appear; the hook sends two setup commands for each (ids 1, 2 then 3, 4). The browser does 1 and 2,
        // and refuses 3
        let wire = format!(
            "{}{}{{\"id\":1,\"result\":{{}}}}\0{{\"id\":2,\"result\":{{}}}}\0{{\"id\":3,\"error\":{{\"message\":\"no\"}}}}\0",
            attach("A"),
            attach("B")
        );
        let mut c = Cdp::new(
            Box::new(Vec::<u8>::new()),
            Box::new(std::io::Cursor::new(wire.into_bytes())),
        );
        c.set_hook(Box::new(|ev: &Value| {
            let s = ev["params"]["sessionId"].as_str().map(String::from);
            HookOut {
                send: vec![
                    (s.clone(), "Page.enable".into(), json!({})),
                    (s, "Fetch.enable".into(), json!({})),
                ],
                keep: false,
                setup: true,
                release: None,
            }
        }));
        c.pump(Duration::from_secs(2));
        while c.pump(Duration::from_millis(50)) {}
        assert_eq!(c.setup_state("A"), Setup::Ready);
        assert_eq!(c.setup_state("B"), Setup::Failed);
        assert_eq!(c.setup_state("unknown"), Setup::Ready);
        // a command answered is not waited for again, and one never answered keeps its target pending
        let mut d = Cdp::new(
            Box::new(Vec::<u8>::new()),
            Box::new(std::io::Cursor::new(attach("C").into_bytes())),
        );
        d.set_hook(Box::new(|ev: &Value| HookOut {
            send: vec![(
                ev["params"]["sessionId"].as_str().map(String::from),
                "Page.enable".into(),
                json!({}),
            )],
            keep: false,
            setup: true,
            release: None,
        }));
        d.pump(Duration::from_secs(2));
        assert_eq!(d.setup_state("C"), Setup::Pending);
    }

    /// What the client wrote, readable after it is handed to the client.
    #[derive(Clone, Default)]
    struct Wrote(std::sync::Arc<std::sync::Mutex<Vec<u8>>>);
    impl Write for Wrote {
        fn write(&mut self, b: &[u8]) -> std::io::Result<usize> {
            self.0.lock().unwrap().extend_from_slice(b);
            Ok(b.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    #[test]
    fn a_target_runs_only_after_its_setup_is_done_and_never_when_the_browser_refused_it() {
        let attach = |s: &str| {
            format!(
                "{{\"method\":\"Target.attachedToTarget\",\"params\":{{\"sessionId\":\"{s}\"}}}}\0"
            )
        };
        // A's setup (id 1) is done; B's (id 2) is refused
        let wire = format!(
            "{}{}{{\"id\":1,\"result\":{{}}}}\0{{\"id\":2,\"error\":{{\"message\":\"no\"}}}}\0",
            attach("A"),
            attach("B")
        );
        let out = Wrote::default();
        let mut c = Cdp::new(
            Box::new(out.clone()),
            Box::new(std::io::Cursor::new(wire.into_bytes())),
        );
        c.set_hook(Box::new(|ev: &Value| {
            let s = ev["params"]["sessionId"].as_str().unwrap_or("").to_string();
            HookOut {
                send: vec![(Some(s.clone()), "Fetch.enable".into(), json!({}))],
                setup: true,
                release: Some((s, "Runtime.runIfWaitingForDebugger".into(), json!({}))),
                ..HookOut::default()
            }
        }));
        c.pump(Duration::from_secs(2));
        while c.pump(Duration::from_millis(50)) {}
        let sent = String::from_utf8(out.0.lock().unwrap().clone()).unwrap();
        let runs: Vec<&str> = sent
            .split('\0')
            .filter(|m| m.contains("runIfWaitingForDebugger"))
            .collect();
        assert_eq!(runs.len(), 1, "{sent}");
        assert!(runs[0].contains("\"sessionId\":\"A\""), "{sent}");
        // and it went after A's setup, not with it
        let first_run = sent.find("runIfWaitingForDebugger").unwrap();
        assert!(sent[..first_run].matches("Fetch.enable").count() == 2);
    }

    #[test]
    fn a_call_on_a_page_that_crashed_ends_at_once_and_a_new_page_brings_the_tab_back() {
        // the page crashes while a command waits for it; the reply never comes
        let wire = b"{\"method\":\"Inspector.targetCrashed\",\"sessionId\":\"T\",\"params\":{}}\0{\"id\":2,\"result\":{}}\0{\"method\":\"Page.frameNavigated\",\"sessionId\":\"T\",\"params\":{\"frame\":{\"id\":\"F\"}}}\0".to_vec();
        let mut c = Cdp::new(
            Box::new(Vec::<u8>::new()),
            Box::new(std::io::Cursor::new(wire)),
        );
        c.timeout = Duration::from_secs(5);
        let started = Instant::now();
        assert_eq!(
            c.call(Some("T"), "Runtime.evaluate", json!({}))
                .unwrap_err(),
            CRASHED
        );
        assert!(started.elapsed() < Duration::from_secs(2));
        assert!(c.crashed("T"));
        // refused before it is sent, while the page is gone
        assert_eq!(
            c.call(Some("T"), "Page.captureScreenshot", json!({}))
                .unwrap_err(),
            CRASHED
        );
        // opening a page in it again is allowed (id 2: the refused command was never sent), and once a page commits the tab is usable
        assert!(c.call(Some("T"), "Page.navigate", json!({})).is_ok());
        c.pump(Duration::from_secs(2));
        assert!(!c.crashed("T"));
    }

    #[test]
    fn a_call_gets_its_own_reply_and_keeps_events_for_later() {
        // a fake browser: sends an event, then the reply to id 1
        let bytes = b"{\"method\":\"Page.loadEventFired\",\"params\":{}}\0{\"id\":1,\"result\":{\"ok\":true}}\0".to_vec();
        let mut c = Cdp::new(
            Box::new(Vec::<u8>::new()),
            Box::new(std::io::Cursor::new(bytes)),
        );
        let r = c.call(None, "Page.enable", json!({})).unwrap();
        assert_eq!(r["ok"], true);
        let ev = c.take_events();
        assert_eq!(ev.len(), 1);
        assert_eq!(ev[0]["method"], "Page.loadEventFired");
    }

    /// A pipe that hands over its bytes only after a delay, like a browser that is slow to start.
    struct Late {
        wait: Duration,
        data: Option<Vec<u8>>,
    }
    impl Read for Late {
        fn read(&mut self, b: &mut [u8]) -> std::io::Result<usize> {
            std::thread::sleep(self.wait);
            match self.data.take() {
                Some(d) => {
                    b[..d.len()].copy_from_slice(&d);
                    Ok(d.len())
                }
                None => {
                    // then silence, until the test ends
                    std::thread::sleep(Duration::from_secs(30));
                    Ok(0)
                }
            }
        }
    }

    #[test]
    fn a_browser_slow_to_start_is_waited_for_beyond_the_ordinary_timeout() {
        let reply = b"{\"id\":1,\"result\":{\"userAgent\":\"X\"}}\0".to_vec();
        let mut c = Cdp::new(
            Box::new(Vec::<u8>::new()),
            Box::new(Late {
                wait: Duration::from_millis(600),
                data: Some(reply),
            }),
        );
        // the ordinary timeout would have given up; the start window waits
        c.timeout = Duration::from_millis(100);
        let v = c.await_ready(Duration::from_secs(10)).unwrap();
        assert_eq!(v["userAgent"], "X");
        // and the ordinary timeout is back for every later call
        assert_eq!(c.timeout, Duration::from_millis(100));
    }

    #[test]
    fn a_browser_that_never_starts_fails_within_the_window_and_names_the_phase() {
        let mut c = Cdp::new(
            Box::new(Vec::<u8>::new()),
            Box::new(Late {
                wait: Duration::from_millis(0),
                data: None,
            }),
        );
        let t = Instant::now();
        let e = c.await_ready(Duration::from_millis(400)).unwrap_err();
        assert!(t.elapsed() < Duration::from_secs(5));
        assert!(
            e.contains("first call") && e.contains("DevTools pipe"),
            "{e}"
        );
        // one that exits while starting is a launch failure
        let mut g = Cdp::new(
            Box::new(Vec::<u8>::new()),
            Box::new(std::io::Cursor::new(Vec::<u8>::new())),
        );
        let e = g.await_ready(Duration::from_secs(5)).unwrap_err();
        assert!(e.contains("(launch)"), "{e}");
    }
}
