//! Where a tool's work happens: the box. [`HostBackend`] is the seam. [`DaemonBackend`] does everything through the box
//! daemon's run API (ADR 0019), one short run per operation, so nothing new listens on the box and nothing is a second
//! way in. [`LocalBackend`] does the same on this computer under one directory per box, for the demo provider and tests:
//! it runs a command with an empty environment and no secrets, and it is never chosen for a real box.

use std::collections::BTreeSet;
use std::io::{Read, Write};
use std::os::unix::process::CommandExt;
use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::sync::Mutex;
use std::time::{Duration, Instant};

use ozbox_core::claude_code::{Launch, RunTransport};

use super::paths::{self, WORK};

#[derive(Debug, Clone)]
pub struct ExecReq {
    pub argv: Vec<String>,
    /// An absolute path from [`HostBackend::resolve`].
    pub cwd: String,
    pub timeout: Duration,
    /// The most output kept, in bytes.
    pub cap: usize,
    /// Text for the program's standard input.
    pub stdin: Option<String>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ExecOut {
    pub code: Option<i32>,
    pub output: String,
    /// Standard error, when the backend keeps it apart (the daemon merges it into `output`).
    pub stderr: String,
    pub truncated: bool,
    pub timed_out: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Resolved {
    /// What to hand back to the other methods.
    pub abs: String,
    /// Relative to `/work`, `""` for `/work` itself: what the agent is shown.
    pub rel: String,
    pub parts: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Entry {
    pub name: String,
    /// `file`, `dir` or `link`.
    pub kind: &'static str,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Hit {
    pub path: String,
    pub line: u32,
    pub text: String,
}

pub trait HostBackend: Send + Sync {
    /// Turn a requested path into one inside `/work`, following symlinks: a path whose real place is elsewhere is refused.
    fn resolve(&self, box_name: &str, requested: &str) -> Result<Resolved, String>;
    fn exec(&self, box_name: &str, req: &ExecReq) -> Result<ExecOut, String>;
    /// At most `max` bytes of a file, and whether there was more.
    fn read(&self, box_name: &str, abs: &str, max: usize) -> Result<(Vec<u8>, bool), String>;
    fn write(&self, box_name: &str, abs: &str, data: &[u8], make_dirs: bool) -> Result<(), String>;
    fn list(&self, box_name: &str, abs: &str, max: usize) -> Result<Vec<Entry>, String>;
    /// Lines containing `needle` (plain text, not a pattern) under a directory or in one file.
    fn search(
        &self,
        box_name: &str,
        abs: &str,
        needle: &str,
        max: usize,
    ) -> Result<Vec<Hit>, String>;
}

fn lossy(b: &[u8]) -> String {
    String::from_utf8_lossy(b)
        .chars()
        .filter(|c| !c.is_control() || matches!(c, '\n' | '\t'))
        .collect()
}

// ---- the box, through its daemon -------------------------------------------------------------------------------------

/// How long between looks at a run's log.
const POLL: Duration = Duration::from_millis(150);

pub struct DaemonBackend {
    transport: Mutex<Box<dyn RunTransport>>,
    poll: Duration,
}

impl DaemonBackend {
    pub fn new(transport: Box<dyn RunTransport>) -> Self {
        Self {
            transport: Mutex::new(transport),
            poll: POLL,
        }
    }

    #[cfg(test)]
    pub fn with_poll(mut self, p: Duration) -> Self {
        self.poll = p;
        self
    }

    fn run(
        &self,
        box_name: &str,
        argv: Vec<String>,
        cwd: &str,
        timeout: Duration,
        cap: usize,
        stdin: Option<String>,
    ) -> Result<ExecOut, String> {
        let launch = Launch {
            argv,
            cwd: Some(cwd.to_string()),
            env: Default::default(),
            labels: [("ozbox.tool".to_string(), "1".to_string())].into(),
            max_runtime_s: Some(timeout.as_secs().max(1)),
            memory_request_bytes: 0,
            stdin,
            keep_stdin_open: false,
            memory_max_bytes: None,
            require_capability: false,
        };
        // locked for one call at a time, never for a whole command: a long run must not hold up the others
        let lock = || {
            self.transport
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
        };
        let id = lock().launch(box_name, &launch)?;
        // the daemon enforces the limit itself; this is the wait for it to say so, with a little room
        let deadline = Instant::now() + timeout + Duration::from_secs(5);
        let (mut from, mut out, mut truncated) = (0u64, Vec::new(), false);
        loop {
            let chunk = lock().read_log(box_name, &id, from)?;
            from = chunk.next;
            let room = cap.saturating_sub(out.len());
            if chunk.bytes.len() > room {
                truncated = true;
            }
            out.extend_from_slice(&chunk.bytes[..chunk.bytes.len().min(room)]);
            if let Some(code) = chunk.exited {
                return Ok(ExecOut {
                    code: Some(code),
                    output: lossy(&out),
                    stderr: String::new(),
                    truncated,
                    timed_out: false,
                });
            }
            if Instant::now() >= deadline {
                let _ = lock().stop(box_name, &id);
                return Ok(ExecOut {
                    code: None,
                    output: lossy(&out),
                    stderr: String::new(),
                    truncated,
                    timed_out: true,
                });
            }
            std::thread::sleep(self.poll);
        }
    }

    fn quick(
        &self,
        box_name: &str,
        argv: &[&str],
        stdin: Option<String>,
        cap: usize,
    ) -> Result<ExecOut, String> {
        self.run(
            box_name,
            argv.iter().map(|s| (*s).to_string()).collect(),
            WORK,
            Duration::from_secs(30),
            cap,
            stdin,
        )
    }
}

impl HostBackend for DaemonBackend {
    fn resolve(&self, box_name: &str, requested: &str) -> Result<Resolved, String> {
        let parts = paths::normalize(requested)?;
        let lexical = paths::join(&parts);
        // symlinks are the box's to resolve: `realpath -m` follows what exists and keeps the rest as written
        let o = self.quick(box_name, &["realpath", "-m", "--", &lexical], None, 4096)?;
        let real = o.output.trim();
        if o.code != Some(0) || !(real == WORK || real.starts_with("/work/")) {
            return Err("that path is not inside /work".into());
        }
        let real_parts = paths::normalize(real)?;
        Ok(Resolved {
            abs: real.to_string(),
            rel: paths::rel(&real_parts),
            parts: real_parts,
        })
    }

    fn exec(&self, box_name: &str, req: &ExecReq) -> Result<ExecOut, String> {
        self.run(
            box_name,
            req.argv.clone(),
            &req.cwd,
            req.timeout,
            req.cap,
            req.stdin.clone(),
        )
    }

    fn read(&self, box_name: &str, abs: &str, max: usize) -> Result<(Vec<u8>, bool), String> {
        let o = self.quick(
            box_name,
            &["head", "-c", &(max + 1).to_string(), "--", abs],
            None,
            max + 1,
        )?;
        if o.code != Some(0) {
            return Err("that file could not be read".into());
        }
        let truncated = o.output.len() > max || o.truncated;
        let mut b = o.output.into_bytes();
        b.truncate(max);
        Ok((b, truncated))
    }

    fn write(&self, box_name: &str, abs: &str, data: &[u8], make_dirs: bool) -> Result<(), String> {
        let text =
            String::from_utf8(data.to_vec()).map_err(|_| "only text can be written".to_string())?;
        let script = if make_dirs {
            r#"mkdir -p -- "$(dirname -- "$1")" && cat > "$1""#
        } else {
            r#"cat > "$1""#
        };
        let o = self.run(
            box_name,
            vec![
                "sh".into(),
                "-c".into(),
                script.into(),
                "sh".into(),
                abs.into(),
            ],
            WORK,
            Duration::from_secs(30),
            4096,
            Some(text),
        )?;
        if o.code == Some(0) {
            Ok(())
        } else {
            Err("the file could not be written".into())
        }
    }

    fn list(&self, box_name: &str, abs: &str, max: usize) -> Result<Vec<Entry>, String> {
        let o = self.quick(box_name, &["ls", "-1Ap", "--", abs], None, 256 * 1024)?;
        if o.code != Some(0) {
            return Err("that folder could not be listed".into());
        }
        Ok(o.output
            .lines()
            .take(max)
            .map(|l| match l.strip_suffix('/') {
                Some(d) => Entry {
                    name: d.into(),
                    kind: "dir",
                },
                None => Entry {
                    name: l.into(),
                    kind: "file",
                },
            })
            .collect())
    }

    fn search(
        &self,
        box_name: &str,
        abs: &str,
        needle: &str,
        max: usize,
    ) -> Result<Vec<Hit>, String> {
        let o = self.quick(
            box_name,
            &[
                "grep",
                "-rInF",
                "--exclude-dir=.git",
                "-m",
                "50",
                "-e",
                needle,
                "--",
                abs,
            ],
            None,
            512 * 1024,
        )?;
        // grep exits 1 for no match
        if !matches!(o.code, Some(0 | 1)) {
            return Err("the search could not be done".into());
        }
        let strip = format!("{abs}/");
        Ok(o.output
            .lines()
            .filter_map(|l| {
                let mut it = l.splitn(3, ':');
                let (p, n, t) = (it.next()?, it.next()?, it.next()?);
                Some(Hit {
                    path: p.strip_prefix(&strip).unwrap_or(p).to_string(),
                    line: n.parse().ok()?,
                    text: t.chars().take(300).collect(),
                })
            })
            .take(max)
            .collect())
    }
}

// ---- a directory on this computer, for the demo provider and tests ---------------------------------------------------

pub struct LocalBackend {
    base: PathBuf,
}

impl LocalBackend {
    pub fn new(base: impl Into<PathBuf>) -> Self {
        Self { base: base.into() }
    }

    fn root(&self, box_name: &str) -> Result<PathBuf, String> {
        if box_name.is_empty() || box_name.contains(['/', '\\']) || box_name.starts_with('.') {
            return Err("that is not a box name".into());
        }
        let r = self.base.join(box_name);
        std::fs::create_dir_all(&r)
            .map_err(|_| "the box's work folder could not be made".to_string())?;
        r.canonicalize()
            .map_err(|_| "the box's work folder could not be opened".to_string())
    }

    fn inside(&self, box_name: &str, abs: &str) -> Result<PathBuf, String> {
        let root = self.root(box_name)?;
        let p = PathBuf::from(abs);
        let c = p.canonicalize().unwrap_or(p);
        if c.starts_with(&root) {
            Ok(c)
        } else {
            Err("that path is not inside /work".into())
        }
    }
}

/// What a reader thread has collected so far, readable at any moment: a program's grandchild can hold a pipe open long
/// after the program is gone, and the caller must not wait for it.
#[derive(Default)]
struct Collected {
    bytes: Vec<u8>,
    cut: bool,
}

type Shared = std::sync::Arc<Mutex<Collected>>;

fn collect_into(
    mut r: impl Read + Send + 'static,
    cap: usize,
) -> (Shared, std::sync::mpsc::Receiver<()>) {
    let shared: Shared = Shared::default();
    let (tx, rx) = std::sync::mpsc::channel();
    let s = std::sync::Arc::clone(&shared);
    std::thread::spawn(move || {
        let mut buf = [0u8; 8192];
        while let Ok(n) = r.read(&mut buf) {
            if n == 0 {
                break;
            }
            let mut g = s.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
            let room = cap.saturating_sub(g.bytes.len());
            if n > room {
                g.cut = true;
            }
            g.bytes.extend_from_slice(&buf[..n.min(room)]);
        }
        let _ = tx.send(());
    });
    (shared, rx)
}

/// Read a reader to its end, keeping at most `cap` bytes (a file: it ends).
fn drain(mut r: impl Read, cap: usize) -> (Vec<u8>, bool) {
    let (mut out, mut buf, mut cut) = (Vec::new(), [0u8; 8192], false);
    while let Ok(n) = r.read(&mut buf) {
        if n == 0 {
            break;
        }
        let room = cap.saturating_sub(out.len());
        if n > room {
            cut = true;
        }
        out.extend_from_slice(&buf[..n.min(room)]);
    }
    (out, cut)
}

fn snapshot(s: &Shared) -> (Vec<u8>, bool) {
    let g = s.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
    (g.bytes.clone(), g.cut)
}

impl HostBackend for LocalBackend {
    fn resolve(&self, box_name: &str, requested: &str) -> Result<Resolved, String> {
        let parts = paths::normalize(requested)?;
        let root = self.root(box_name)?;
        let mut cur = root.clone();
        let mut real_parts: Vec<String> = Vec::new();
        for p in &parts {
            cur.push(p);
            if cur.symlink_metadata().is_ok() {
                cur = cur
                    .canonicalize()
                    .map_err(|_| "that path could not be followed".to_string())?;
                if !cur.starts_with(&root) {
                    return Err("that path is not inside /work".into());
                }
            }
        }
        if let Ok(r) = cur.strip_prefix(&root) {
            real_parts = r
                .components()
                .map(|c| c.as_os_str().to_string_lossy().into_owned())
                .collect();
        }
        Ok(Resolved {
            abs: cur.to_string_lossy().into_owned(),
            rel: paths::rel(&real_parts),
            parts: real_parts,
        })
    }

    fn exec(&self, box_name: &str, req: &ExecReq) -> Result<ExecOut, String> {
        let cwd = self.inside(box_name, &req.cwd)?;
        let root = self.root(box_name)?;
        let (prog, args) = req.argv.split_first().ok_or("there is no command to run")?;
        // its own process group, so a timeout can stop the whole tree and not just the shell
        let mut child = Command::new(prog)
            .args(args)
            .process_group(0)
            .current_dir(&cwd)
            .env_clear()
            .env("PATH", "/usr/local/bin:/usr/bin:/bin:/opt/homebrew/bin")
            .env("HOME", &root)
            .env("LANG", "C.UTF-8")
            .stdin(if req.stdin.is_some() {
                Stdio::piped()
            } else {
                Stdio::null()
            })
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .map_err(|_| "the command could not be started".to_string())?;
        if let (Some(text), Some(mut si)) = (req.stdin.clone(), child.stdin.take()) {
            std::thread::spawn(move || {
                let _ = si.write_all(text.as_bytes());
            });
        }
        let cap = req.cap;
        let so = child.stdout.take().map(|s| collect_into(s, cap));
        let se = child.stderr.take().map(|s| collect_into(s, cap));
        let start = Instant::now();
        let (mut code, mut timed_out) = (None, false);
        loop {
            match child.try_wait() {
                Ok(Some(st)) => {
                    code = st.code();
                    break;
                }
                Ok(None) if start.elapsed() >= req.timeout => {
                    // the group first (a grandchild holds the pipes open), then the child itself
                    let _ = Command::new("kill")
                        .args(["-KILL", "--", &format!("-{}", child.id())])
                        .stdout(Stdio::null())
                        .stderr(Stdio::null())
                        .status();
                    let _ = child.kill();
                    let _ = child.wait();
                    timed_out = true;
                    break;
                }
                Ok(None) => std::thread::sleep(Duration::from_millis(10)),
                Err(_) => break,
            }
        }
        // Whatever is left to read arrives at once once the program is gone; a pipe a stray grandchild still holds is not waited
        // for beyond a moment.
        let grace = Duration::from_millis(1500);
        let take = |c: Option<(Shared, std::sync::mpsc::Receiver<()>)>| match c {
            Some((s, rx)) => {
                let _ = rx.recv_timeout(grace);
                snapshot(&s)
            }
            None => (Vec::new(), false),
        };
        let (o, c1) = take(so);
        let (e, c2) = take(se);
        Ok(ExecOut {
            code,
            output: lossy(&o),
            stderr: lossy(&e),
            truncated: c1 || c2,
            timed_out,
        })
    }

    fn read(&self, box_name: &str, abs: &str, max: usize) -> Result<(Vec<u8>, bool), String> {
        let p = self.inside(box_name, abs)?;
        let f = std::fs::File::open(&p).map_err(|_| "that file could not be read".to_string())?;
        if !f.metadata().map(|m| m.is_file()).unwrap_or(false) {
            return Err("that is not a file".into());
        }
        let (b, cut) = drain(f.take(max as u64 + 1), max);
        Ok((b, cut))
    }

    fn write(&self, box_name: &str, abs: &str, data: &[u8], make_dirs: bool) -> Result<(), String> {
        let root = self.root(box_name)?;
        let p = PathBuf::from(abs);
        if !p.starts_with(&root) {
            return Err("that path is not inside /work".into());
        }
        if make_dirs {
            if let Some(d) = p.parent() {
                std::fs::create_dir_all(d)
                    .map_err(|_| "the folder could not be made".to_string())?;
            }
        }
        // the parent must also really be inside (a symlinked folder is followed by resolve before this)
        if let Some(d) = p.parent() {
            let real = d
                .canonicalize()
                .map_err(|_| "the folder does not exist".to_string())?;
            if !real.starts_with(&root) {
                return Err("that path is not inside /work".into());
            }
        }
        std::fs::write(&p, data).map_err(|_| "the file could not be written".to_string())
    }

    fn list(&self, box_name: &str, abs: &str, max: usize) -> Result<Vec<Entry>, String> {
        let p = self.inside(box_name, abs)?;
        let mut v: Vec<Entry> = std::fs::read_dir(&p)
            .map_err(|_| "that folder could not be listed".to_string())?
            .filter_map(Result::ok)
            .map(|e| {
                let kind = match e.file_type() {
                    Ok(t) if t.is_dir() => "dir",
                    Ok(t) if t.is_symlink() => "link",
                    _ => "file",
                };
                Entry {
                    name: e.file_name().to_string_lossy().into_owned(),
                    kind,
                }
            })
            .collect();
        v.sort_by(|a, b| a.name.cmp(&b.name));
        v.truncate(max);
        Ok(v)
    }

    fn search(
        &self,
        box_name: &str,
        abs: &str,
        needle: &str,
        max: usize,
    ) -> Result<Vec<Hit>, String> {
        let root = self.inside(box_name, abs)?;
        let mut hits = Vec::new();
        let mut seen = BTreeSet::new();
        let mut stack = vec![(root.clone(), 0usize)];
        while let Some((dir, depth)) = stack.pop() {
            let entries: Vec<PathBuf> = if dir.is_dir() {
                match std::fs::read_dir(&dir) {
                    Ok(r) => r.filter_map(Result::ok).map(|e| e.path()).collect(),
                    Err(_) => continue,
                }
            } else {
                vec![dir.clone()]
            };
            let mut entries = entries;
            entries.sort();
            for p in entries {
                let Ok(m) = p.symlink_metadata() else {
                    continue;
                };
                if m.is_dir() {
                    if depth < 12 && p.file_name().is_some_and(|n| n != ".git") {
                        stack.push((p, depth + 1));
                    }
                } else if m.is_file() && m.len() <= 1_000_000 && seen.insert(p.clone()) {
                    let Ok(data) = std::fs::read(&p) else {
                        continue;
                    };
                    if data.iter().take(8192).any(|b| *b == 0) {
                        continue;
                    }
                    let text = String::from_utf8_lossy(&data);
                    for (i, l) in text.lines().enumerate() {
                        if l.contains(needle) {
                            let rel = p
                                .strip_prefix(&root)
                                .unwrap_or(&p)
                                .to_string_lossy()
                                .into_owned();
                            hits.push(Hit {
                                path: rel,
                                line: (i + 1) as u32,
                                text: l.chars().take(300).collect(),
                            });
                            if hits.len() >= max {
                                return Ok(hits);
                            }
                        }
                    }
                }
            }
        }
        Ok(hits)
    }
}
