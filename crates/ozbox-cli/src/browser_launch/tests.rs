#![allow(clippy::unwrap_used)]
//! The browser launcher's decisions and its glue, with a stand-in for `systemd-run`. What only a Linux box can show (the
//! user, the sandbox, what the kernel refuses across users) is not here; see ADR 0037, amendment 4.

use std::io::Cursor;
use std::os::unix::fs::PermissionsExt;
use std::os::unix::net::{UnixListener, UnixStream};
use std::sync::{Arc, Mutex};

use ozbox_browser::channel::SessionKey;
use ozbox_browser::policy::BrowserPolicy;

use super::*;

fn start(session: &str) -> Start {
    Start {
        session: session.into(),
        key: SessionKey::generate().unwrap(),
        root: SHARED_ROOT.into(),
        work: WORK.into(),
        device: Default::default(),
        policy: BrowserPolicy::default(),
        allowed_hosts: vec![],
        run: None,
        private_root: Some(PRIVATE_ROOT.into()),
        memory_max_bytes: Some(1536 * 1024 * 1024),
        max_runtime_s: Some(3600),
    }
}

fn line(s: &Start) -> String {
    format!("{}\n", serde_json::to_string(s).unwrap())
}

#[test]
fn the_launcher_accepts_what_the_browser_tools_send() {
    assert!(check_start(&start("s1")).is_ok());
}

#[test]
fn the_launcher_never_lets_the_host_name_another_folder() {
    let mut s = start("s1");
    s.root = "/work/home/ozbox".into();
    assert!(check_start(&s).unwrap_err().contains("recording folder"));
    let mut s = start("s1");
    s.private_root = None;
    assert!(check_start(&s).unwrap_err().contains("private folder"));
    let mut s = start("s1");
    s.private_root = Some("/work/ozbox-supervisor".into());
    assert!(check_start(&s).is_err());
    let mut s = start("s1");
    s.work = "/".into();
    assert!(check_start(&s).unwrap_err().contains("work folder"));
    let mut s = start("../x");
    s.session = "../x".into();
    assert!(check_start(&s).is_err());
    let mut s = start("s1");
    s.session = "a".repeat(65);
    assert!(check_start(&s).is_err());
}

#[test]
fn the_launcher_bounds_memory_and_time() {
    for m in [None, Some(0), Some(1024), Some(33 * 1024 * 1024 * 1024)] {
        let mut s = start("s1");
        s.memory_max_bytes = m;
        assert!(check_start(&s).unwrap_err().contains("memory"), "{m:?}");
    }
    for t in [None, Some(0), Some(4 * 24 * 3600)] {
        let mut s = start("s1");
        s.max_runtime_s = t;
        assert!(check_start(&s).unwrap_err().contains("time"), "{t:?}");
    }
    let mut s = start("s1");
    s.policy.max_minutes = 0;
    assert!(
        check_start(&s).is_err(),
        "the policy's own limits still apply"
    );
}

#[test]
fn the_worker_runs_as_the_browser_user_in_its_sandbox_and_the_key_is_not_in_the_arguments() {
    let s = start("sess-1");
    let a = systemd_run_argv(&s);
    let all = a.join(" ");
    assert_eq!(a[0], "systemd-run");
    for must in [
        "--pipe",
        "--wait",
        "--unit=ozbox-browser-sess-1",
        "--uid=ozbox-browser",
        "--gid=ozbox-browser",
        "--working-directory=/work/ozbox-browser/private",
        "ProtectSystem=strict",
        "ProtectHome=yes",
        "ProtectProc=invisible",
        "PrivateTmp=yes",
        "UMask=0027",
        "MemoryMax=1610612736",
        "MemorySwapMax=0",
        "RuntimeMaxSec=3900",
        "ReadWritePaths=/work/ozbox-browser",
        "IPAddressDeny=169.254.169.254/32 fd00:ec2::254/128",
    ] {
        assert!(all.contains(must), "missing {must}: {all}");
    }
    // the only writable place is the browser's own tree, and the box user's home, the other accounts' folders and the box's
    // sockets are out of its view
    assert_eq!(all.matches("ReadWritePaths").count(), 1);
    for hidden in [
        "/work/home",
        "/work/ozbox-supervisor",
        "/run/ozbox-secrets",
        "/run/ozboxd",
        "/run/ozbox-browser",
        "/etc/ozbox",
    ] {
        assert!(all.contains(hidden), "{hidden} must be out of view");
    }
    // no supplementary group: it cannot open the box daemon's socket
    assert!(!all.contains("SupplementaryGroups") && !all.contains("--property=Group"));
    // nothing that is secret is an argument: the key travels on standard input
    let key = serde_json::to_string(&s).unwrap();
    let key_value = key
        .split("\"key\":\"")
        .nth(1)
        .unwrap()
        .split('"')
        .next()
        .unwrap();
    assert!(!all.contains(key_value));
    assert!(a.ends_with(&[
        "--".to_string(),
        "/usr/local/bin/ozbox".to_string(),
        "browser-worker".to_string()
    ]));
}

#[test]
fn the_first_line_is_read_to_its_end_and_what_follows_it_is_kept() {
    let mut r = BufReader::new(Cursor::new(b"hello\nsecond\n".to_vec()));
    assert_eq!(read_first_line(&mut r, 100).as_deref(), Some("hello\n"));
    let mut rest = String::new();
    r.read_to_string(&mut rest).unwrap();
    assert_eq!(rest, "second\n");
    let mut long = BufReader::new(Cursor::new(vec![b'a'; 500]));
    assert_eq!(read_first_line(&mut long, 100), None, "too long");
    let mut none = BufReader::new(Cursor::new(b"no newline".to_vec()));
    assert_eq!(read_first_line(&mut none, 100), None, "ended first");
}

/// A stand-in for `systemd-run`: it records its arguments and its standard input's first line, then echoes standard input.
fn fake_systemd_run(dir: &Path) -> PathBuf {
    let p = dir.join("systemd-run");
    std::fs::write(
        &p,
        format!(
            "#!/bin/sh\nprintf '%s\\n' \"$@\" > {}/args\ncat\n",
            dir.display()
        ),
    )
    .unwrap();
    std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o755)).unwrap();
    p
}

/// A writer a test can read afterwards.
#[derive(Clone, Default)]
struct Sink(Arc<Mutex<Vec<u8>>>);
impl Write for Sink {
    fn write(&mut self, b: &[u8]) -> std::io::Result<usize> {
        self.0.lock().unwrap().extend_from_slice(b);
        Ok(b.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

#[test]
fn a_session_is_started_through_systemd_run_and_the_connection_is_the_workers_input_and_output() {
    let d = tempfile::tempdir().unwrap();
    let prog = fake_systemd_run(d.path());
    let s = start("sess-2");
    let input = format!("{}{{\"later\":1}}\n", line(&s));
    let sink = Sink::default();
    let started = serve(
        prog.to_str().unwrap(),
        Cursor::new(input.clone().into_bytes()),
        sink.clone(),
    );
    assert!(started);
    // the stand-in echoed everything it was given: the first line, then what came after it
    assert_eq!(
        String::from_utf8(sink.0.lock().unwrap().clone()).unwrap(),
        input
    );
    let args = std::fs::read_to_string(d.path().join("args")).unwrap();
    assert!(args.contains("--uid=ozbox-browser") && args.contains("--unit=ozbox-browser-sess-2"));
    assert!(!args.contains("browser-worker\nsystemd-run"), "{args}");
    assert!(
        !args.contains(&serde_json::to_string(&s.key).unwrap().replace('"', "")),
        "the key is never an argument"
    );
}

#[test]
fn a_refused_start_is_answered_sealed_so_the_tool_host_can_read_why_and_nothing_is_started() {
    let d = tempfile::tempdir().unwrap();
    let prog = fake_systemd_run(d.path());
    let mut s = start("sess-3");
    s.root = "/etc".into();
    let sink = Sink::default();
    assert!(!serve(
        prog.to_str().unwrap(),
        Cursor::new(line(&s).into_bytes()),
        sink.clone()
    ));
    assert!(
        !d.path().join("args").exists(),
        "systemd-run was never called"
    );
    let out = String::from_utf8(sink.0.lock().unwrap().clone()).unwrap();
    let mut host = Channel::host(&s.key, "sess-3").unwrap();
    // sealed with the session's own key, so the tool host can open it
    let (_, plain) = host.open(out.trim()).unwrap();
    let r: Reply = serde_json::from_slice(&plain).unwrap();
    assert!(!r.ok && r.error.unwrap().contains("recording folder"));
}

#[test]
fn nonsense_on_the_socket_starts_nothing_and_answers_nothing() {
    let d = tempfile::tempdir().unwrap();
    let prog = fake_systemd_run(d.path());
    for input in [&b"not json\n"[..], b"{}\n", b"", b"no newline"] {
        let sink = Sink::default();
        assert!(!serve(
            prog.to_str().unwrap(),
            Cursor::new(input.to_vec()),
            sink.clone()
        ));
        assert!(sink.0.lock().unwrap().is_empty());
    }
    assert!(!d.path().join("args").exists());
}

#[test]
fn a_launcher_that_cannot_start_the_worker_says_so_sealed() {
    let s = start("sess-4");
    let sink = Sink::default();
    assert!(!serve(
        "/nonexistent/systemd-run",
        Cursor::new(line(&s).into_bytes()),
        sink.clone()
    ));
    let out = String::from_utf8(sink.0.lock().unwrap().clone()).unwrap();
    let mut host = Channel::host(&s.key, "sess-4").unwrap();
    let (_, plain) = host.open(out.trim()).unwrap();
    let r: Reply = serde_json::from_slice(&plain).unwrap();
    assert!(!r.ok);
}

#[test]
fn the_box_name_is_its_host_name() {
    assert_eq!(local_box_name("dev-1\n").as_deref(), Some("dev-1"));
    assert_eq!(local_box_name("  \n"), None);
    assert_eq!(local_box_name(&"a".repeat(64)), None);
}

// ---- the dashboard's end ---------------------------------------------------------------------------------------------------

#[derive(Default)]
struct Other {
    calls: Mutex<Vec<String>>,
}
impl BrowserBackend for Other {
    fn start(&self, b: &str, _f: &str, _r: &WorkerRun) -> Result<String, String> {
        self.calls.lock().unwrap().push(format!("start {b}"));
        Ok("run-1".into())
    }
    fn send(&self, b: &str, h: &str, _l: &str) -> Result<(), String> {
        self.calls.lock().unwrap().push(format!("send {b} {h}"));
        Ok(())
    }
    fn next_line(&self, b: &str, h: &str, _d: Instant) -> Result<Option<String>, String> {
        self.calls.lock().unwrap().push(format!("next {b} {h}"));
        Ok(None)
    }
    fn stop(&self, b: &str, h: &str) {
        self.calls.lock().unwrap().push(format!("stop {b} {h}"));
    }
    fn roots(&self, _b: &str) -> (String, String) {
        ("/other/browser".into(), "/other".into())
    }
    fn list_sessions(&self, _b: &str) -> Result<Vec<Meta>, String> {
        Ok(vec![])
    }
    fn steps(&self, _b: &str, _s: &str) -> Result<Vec<Step>, String> {
        Ok(vec![])
    }
    fn shot(&self, _b: &str, _s: &str, _n: &str) -> Result<Vec<u8>, String> {
        Err("other".into())
    }
}

fn wr() -> WorkerRun {
    WorkerRun {
        max_runtime_s: 60,
        memory_bytes: 1 << 30,
    }
}

#[test]
fn this_boxs_sessions_go_through_the_socket_and_other_boxes_through_the_daemon() {
    let d = tempfile::tempdir().unwrap();
    let sock = d.path().join("launch.sock");
    let listener = UnixListener::bind(&sock).unwrap();
    // a launcher stand-in: echoes each line back with a prefix
    std::thread::spawn(move || {
        let (c, _) = listener.accept().unwrap();
        let mut w = c.try_clone().unwrap();
        for l in BufReader::new(c).lines().map_while(Result::ok) {
            let _ = writeln!(w, "echo:{l}");
        }
    });
    let other = Arc::new(Other::default());
    let b = LauncherBrowserBackend::new(&sock, "alpha", d.path(), other.clone());
    let h = b.start("alpha", "first", &wr()).unwrap();
    assert!(h.starts_with("sock-"));
    let deadline = || Instant::now() + Duration::from_secs(5);
    assert_eq!(
        b.next_line("alpha", &h, deadline()).unwrap().as_deref(),
        Some("echo:first")
    );
    b.send("alpha", &h, "second").unwrap();
    assert_eq!(
        b.next_line("alpha", &h, deadline()).unwrap().as_deref(),
        Some("echo:second")
    );
    // nothing came: a timeout, not an error
    assert_eq!(
        b.next_line("alpha", &h, Instant::now() + Duration::from_millis(100))
            .unwrap(),
        None
    );
    b.stop("alpha", &h);
    assert!(
        b.send("alpha", &h, "x").is_err(),
        "a stopped session is gone"
    );
    // another box, and a handle that is the daemon's, never touch the socket
    let h2 = b.start("beta", "first", &wr()).unwrap();
    assert_eq!(h2, "run-1");
    b.send("beta", &h2, "x").unwrap();
    b.stop("beta", &h2);
    let calls = other.calls.lock().unwrap().clone();
    assert_eq!(
        calls,
        vec!["start beta", "send beta run-1", "stop beta run-1"]
    );
}

#[test]
fn a_launcher_that_goes_away_ends_the_session_and_does_not_hang() {
    let d = tempfile::tempdir().unwrap();
    let sock = d.path().join("launch.sock");
    let listener = UnixListener::bind(&sock).unwrap();
    std::thread::spawn(move || {
        let (c, _) = listener.accept().unwrap();
        drop(c);
    });
    let b = LauncherBrowserBackend::new(&sock, "alpha", d.path(), Arc::new(Other::default()));
    // the launcher may already be gone when the first line is written (the start says so), or the session ends on the first read
    match b.start("alpha", "first", &wr()) {
        Err(_) => {}
        Ok(h) => {
            let r = b.next_line("alpha", &h, Instant::now() + Duration::from_secs(5));
            assert!(r.unwrap_err().contains("ended"));
        }
    }
}

#[test]
fn with_no_launcher_the_start_says_what_to_do() {
    let d = tempfile::tempdir().unwrap();
    let b = LauncherBrowserBackend::new(
        d.path().join("none.sock"),
        "alpha",
        d.path(),
        Arc::new(Other::default()),
    );
    let e = b.start("alpha", "first", &wr()).unwrap_err();
    assert!(e.contains("browser-setup"), "{e}");
}

#[test]
fn this_boxs_roots_are_the_fixed_ones_and_a_session_is_told_where_its_private_folder_is() {
    let d = tempfile::tempdir().unwrap();
    let b = LauncherBrowserBackend::new(
        d.path().join("s"),
        "alpha",
        d.path(),
        Arc::new(Other::default()),
    );
    assert_eq!(
        b.roots("alpha"),
        (SHARED_ROOT.to_string(), WORK.to_string())
    );
    assert_eq!(b.private_root("alpha").as_deref(), Some(PRIVATE_ROOT));
    assert_eq!(b.roots("beta").0, "/other/browser");
    assert_eq!(b.private_root("beta"), None);
}

#[test]
fn recordings_of_this_box_are_read_from_the_shared_folder_and_a_name_cannot_leave_it() {
    let d = tempfile::tempdir().unwrap();
    let shots = d.path().join("sessions/s1/shots");
    std::fs::create_dir_all(&shots).unwrap();
    std::fs::write(shots.join("0001.jpg"), b"jpeg").unwrap();
    let b = LauncherBrowserBackend::new(
        d.path().join("s"),
        "alpha",
        d.path(),
        Arc::new(Other::default()),
    );
    assert_eq!(b.shot("alpha", "s1", "0001.jpg").unwrap(), b"jpeg");
    assert!(b.shot("alpha", "../x", "0001.jpg").is_err());
    assert!(b.shot("alpha", "s1", "../../meta.json").is_err());
    assert!(b.list_sessions("alpha").unwrap().is_empty());
    assert!(b.steps("alpha", "s1").unwrap().is_empty());
}

#[test]
fn the_launcher_is_used_where_the_setup_ran_and_the_box_knows_its_name() {
    let d = tempfile::tempdir().unwrap();
    let sock = d.path().join("launch.sock");
    let unit = d.path().join("ozbox-browser.socket");
    let host = d.path().join("hostname");
    std::fs::write(&host, "alpha\n").unwrap();
    let other: Arc<dyn BrowserBackend> = Arc::new(Other::default());
    let det = |s: &Path, u: &Path| {
        LauncherBrowserBackend::detect_at(s, u, &host, d.path(), other.clone())
    };
    assert!(det(&sock, &unit).is_none(), "nothing set up: the daemon");
    let _l = UnixListener::bind(&sock).unwrap();
    assert!(det(&sock, &unit).is_some());
    std::fs::write(&host, "\n").unwrap();
    assert!(det(&sock, &unit).is_none(), "no name");
    std::fs::write(&host, "alpha\n").unwrap();
    // a plain file where the socket should be is not a socket, and nothing else says it was set up
    let plain = d.path().join("plain");
    std::fs::write(&plain, "x").unwrap();
    assert!(det(&plain, &unit).is_none());
}

#[test]
fn a_box_that_was_set_up_never_falls_back_to_the_box_users_browser_when_its_launcher_is_not_there()
{
    let d = tempfile::tempdir().unwrap();
    let unit = d.path().join("ozbox-browser.socket");
    std::fs::write(&unit, "[Socket]\n").unwrap();
    let host = d.path().join("hostname");
    std::fs::write(&host, "alpha\n").unwrap();
    let other = Arc::new(Other::default());
    // the socket cannot be reached (its folder is root's, as on a first boot that did not apply the entry), the unit is there
    let b = LauncherBrowserBackend::detect_at(
        &d.path().join("no/launch.sock"),
        &unit,
        &host,
        d.path(),
        other.clone(),
    );
    let b = b.unwrap();
    let e = b.start("alpha", "first", &wr()).unwrap_err();
    assert!(e.contains("never started as the box user"), "{e}");
    assert!(
        other.calls.lock().unwrap().is_empty(),
        "the daemon was never asked to run the session"
    );
}

#[test]
fn a_session_is_admitted_only_when_its_memory_is_free() {
    let m = "MemTotal: 8000000 kB\nMemFree: 100 kB\nMemAvailable:    2097152 kB\n";
    assert!(fits(m, 2 * 1024 * 1024 * 1024));
    assert!(!fits(m, 2 * 1024 * 1024 * 1024 + 1));
    assert!(
        fits("nothing useful\n", u64::MAX),
        "unknown: the slice's own ceiling applies"
    );
}

#[test]
fn a_session_that_does_not_fit_is_refused_sealed_and_nothing_is_started() {
    let d = tempfile::tempdir().unwrap();
    let prog = fake_systemd_run(d.path());
    let mem = d.path().join("meminfo");
    std::fs::write(&mem, "MemAvailable: 1024 kB\n").unwrap();
    let s = start("sess-m");
    let sink = Sink::default();
    assert!(!serve_with(
        prog.to_str().unwrap(),
        "true",
        Duration::from_millis(50),
        Some(&mem),
        Cursor::new(line(&s).into_bytes()),
        sink.clone()
    ));
    assert!(!d.path().join("args").exists());
    let out = String::from_utf8(sink.0.lock().unwrap().clone()).unwrap();
    let mut host = Channel::host(&s.key, "sess-m").unwrap();
    let (_, plain) = host.open(out.trim()).unwrap();
    let r: Reply = serde_json::from_slice(&plain).unwrap();
    assert!(!r.ok && r.error.unwrap().contains("memory"));
}

#[test]
fn every_session_is_in_the_browsers_slice() {
    let a = systemd_run_argv(&start("sess-s"));
    assert!(
        a.contains(&"--slice=ozbox-browser.slice".to_string()),
        "{a:?}"
    );
}

#[test]
fn a_worker_that_ends_by_itself_ends_the_launcher_while_the_hosts_connection_is_still_open() {
    let d = tempfile::tempdir().unwrap();
    let p = d.path().join("systemd-run");
    std::fs::write(&p, "#!/bin/sh\necho gone\n").unwrap();
    std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o755)).unwrap();
    let (host_end, launcher_end) = UnixStream::pair().unwrap();
    let mut host_w = host_end.try_clone().unwrap();
    let s = start("sess-e");
    host_w.write_all(line(&s).as_bytes()).unwrap();
    let sink = Sink::default();
    let t = Instant::now();
    assert!(serve_with(
        p.to_str().unwrap(),
        "true",
        Duration::from_secs(30),
        None,
        launcher_end,
        sink.clone()
    ));
    assert!(
        t.elapsed() < Duration::from_secs(60),
        "it did not wait for the host to say something"
    );
    assert!(String::from_utf8(sink.0.lock().unwrap().clone())
        .unwrap()
        .contains("gone"));
    drop(host_end);
}

#[test]
fn a_worker_that_ignores_the_end_of_its_input_is_stopped_after_the_grace() {
    let d = tempfile::tempdir().unwrap();
    let stopped = d.path().join("stopped");
    let p = d.path().join("systemd-run");
    std::fs::write(
        &p,
        format!(
            "#!/bin/sh\nwhile [ ! -f '{}' ]; do sleep 0.05; done\n",
            stopped.display()
        ),
    )
    .unwrap();
    std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o755)).unwrap();
    let stopper = d.path().join("systemctl");
    std::fs::write(
        &stopper,
        format!("#!/bin/sh\nprintf '%s ' \"$@\" > '{}'\n", stopped.display()),
    )
    .unwrap();
    std::fs::set_permissions(&stopper, std::fs::Permissions::from_mode(0o755)).unwrap();
    let s = start("sess-w");
    // the host's connection ends right after the first line
    let t = Instant::now();
    assert!(serve_with(
        p.to_str().unwrap(),
        stopper.to_str().unwrap(),
        Duration::from_millis(200),
        None,
        Cursor::new(line(&s).into_bytes()),
        Sink::default()
    ));
    assert!(t.elapsed() < Duration::from_secs(60));
    let said = std::fs::read_to_string(&stopped).unwrap();
    assert_eq!(said.trim(), "stop ozbox-browser-sess-w.service");
}

/// The browser worker's unit uses only properties systemd defines (a misspelt one makes `systemd-run` refuse the unit).
#[test]
fn every_property_of_the_browser_unit_is_a_systemd_property() {
    crate::systemd_props_guard::assert_known(&systemd_run_argv(&start("sess-p")), "browser worker");
}
