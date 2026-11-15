//! The few operating-system operations the tool installer needs, behind a trait so every step is tested on any OS
//! with a scripted fake and a temporary directory.

use std::fs::{File, OpenOptions};
use std::io::{self, BufRead, BufReader, Write};
use std::path::Path;
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

/// A bounded log file. Lines are plain text; control characters are dropped and long lines are cut, so a noisy tool
/// cannot flood it and nothing can forge a line.
pub struct Log {
    file: Mutex<File>,
    cap: u64,
    written: AtomicU64,
    /// Set when a line says a program could not change to another user (`seteuid 42 failed - seteuid (1: Operation not
    /// permitted)`, the way apt reports being unable to drop to its `_apt` user). Read by the apt steps to decide whether a
    /// retry without that user switch is warranted.
    privilege_drop_refused: std::sync::atomic::AtomicBool,
}

impl Log {
    pub fn open(path: &Path, cap_bytes: u64) -> io::Result<Log> {
        let file = OpenOptions::new().create(true).append(true).open(path)?;
        let written = file.metadata().map(|m| m.len()).unwrap_or(0);
        Ok(Log {
            file: Mutex::new(file),
            cap: cap_bytes,
            written: AtomicU64::new(written),
            privilege_drop_refused: std::sync::atomic::AtomicBool::new(false),
        })
    }

    /// Whether a line since the last [`Log::clear_privilege_drop_refusal`] said a user switch was refused.
    pub fn saw_privilege_drop_refusal(&self) -> bool {
        self.privilege_drop_refused.load(Ordering::Relaxed)
    }

    pub fn clear_privilege_drop_refusal(&self) {
        self.privilege_drop_refused.store(false, Ordering::Relaxed);
    }

    pub fn line(&self, text: &str) {
        // looked at before the size cap, so a full log still lets a step see what happened
        if is_privilege_drop_refusal(text) {
            self.privilege_drop_refused.store(true, Ordering::Relaxed);
        }
        let clean: String = text
            .chars()
            .filter(|c| !c.is_control() || *c == '\t')
            .take(400)
            .collect();
        let n = clean.len() as u64 + 1;
        if self.written.load(Ordering::Relaxed) + n > self.cap {
            return;
        }
        self.written.fetch_add(n, Ordering::Relaxed);
        if let Ok(mut f) = self.file.lock() {
            let _ = writeln!(f, "{clean}");
        }
    }
}

/// Whether a line is apt (or another program) saying it could not switch to another user: `seteuid`, `setresuid` or
/// `setegid` followed by "Operation not permitted". Pure.
pub fn is_privilege_drop_refusal(line: &str) -> bool {
    let l = line.to_ascii_lowercase();
    ["seteuid", "setresuid", "setegid", "setgroups"]
        .iter()
        .any(|k| l.contains(k))
        && l.contains("operation not permitted")
}

pub trait Sys: Send + Sync {
    /// Run a program (argv, never a shell), streaming its output into the log. Returns the exit code.
    fn exec(&self, argv: &[String], env: &[(String, String)], log: &Log) -> Result<i32, String>;
    /// Run a short program and return its exit code and standard output.
    fn capture(&self, argv: &[String], env: &[(String, String)]) -> Result<(i32, String), String>;
    fn read_file(&self, p: &Path) -> io::Result<Vec<u8>>;
    /// The SHA-256 of a file, as lower-case hex. The real one reads it in pieces: a vendor archive can be larger than the
    /// memory an install job is given.
    fn sha256_file(&self, p: &Path) -> io::Result<String> {
        Ok(ozbox_catalog::verify::sha256_hex(&self.read_file(p)?))
    }
    fn write_file(&self, p: &Path, data: &[u8], mode: u32) -> io::Result<()>;
    fn create_dir_all(&self, p: &Path) -> io::Result<()>;
    /// Remove a file, a symlink (never what it points at) or a directory tree. Absent is fine.
    fn remove_path(&self, p: &Path) -> io::Result<()>;
    fn symlink(&self, target: &Path, link: &Path) -> io::Result<()>;
    fn exists(&self, p: &Path) -> bool;
    fn is_executable(&self, p: &Path) -> bool;
}

pub struct RealSys;

fn spawn_argv(argv: &[String], env: &[(String, String)]) -> Result<Command, String> {
    let (prog, args) = argv.split_first().ok_or("empty command")?;
    let mut c = Command::new(prog);
    c.args(args).stdin(Stdio::null());
    for (k, v) in env {
        c.env(k, v);
    }
    Ok(c)
}

/// An install step is a workload (a package install or a build), and the daemon is protected from the OOM killer (ADR 0045):
/// the step puts its own score back up before it runs, which a process may do and never undo.
pub fn workload_argv(argv: &[String]) -> Vec<String> {
    let raise = ozbox_core::memory_plan::raise_score_snippet(
        ozbox_core::memory_plan::TERMINAL_OOM_SCORE_ADJ,
    );
    let mut v = vec![
        "sh".to_string(),
        "-c".into(),
        format!("{raise}; exec \"$@\""),
        "ozbox-install".into(),
    ];
    v.extend(argv.iter().cloned());
    v
}

impl Sys for RealSys {
    fn exec(&self, argv: &[String], env: &[(String, String)], log: &Log) -> Result<i32, String> {
        if argv.is_empty() {
            return Err("empty command".into());
        }
        let mut c = spawn_argv(&workload_argv(argv), env)?;
        c.stdout(Stdio::piped()).stderr(Stdio::piped());
        let mut child = c
            .spawn()
            .map_err(|e| format!("cannot start {}: {}", argv[0], e.kind()))?;
        let log = Arc::new(log);
        std::thread::scope(|s| {
            for stream in [
                child
                    .stdout
                    .take()
                    .map(|o| Box::new(o) as Box<dyn std::io::Read + Send>),
                child
                    .stderr
                    .take()
                    .map(|o| Box::new(o) as Box<dyn std::io::Read + Send>),
            ]
            .into_iter()
            .flatten()
            {
                let log = Arc::clone(&log);
                s.spawn(move || {
                    for l in BufReader::new(stream).lines().map_while(Result::ok) {
                        log.line(&l);
                    }
                });
            }
        });
        let status = child.wait().map_err(|e| e.kind().to_string())?;
        Ok(status.code().unwrap_or(-1))
    }

    fn capture(&self, argv: &[String], env: &[(String, String)]) -> Result<(i32, String), String> {
        let mut c = spawn_argv(argv, env)?;
        let out = c
            .stderr(Stdio::piped())
            .output()
            .map_err(|e| format!("cannot start {}: {}", argv[0], e.kind()))?;
        let mut text = String::from_utf8_lossy(&out.stdout).into_owned();
        text.push_str(&String::from_utf8_lossy(&out.stderr));
        Ok((out.status.code().unwrap_or(-1), text))
    }

    fn read_file(&self, p: &Path) -> io::Result<Vec<u8>> {
        std::fs::read(p)
    }

    fn sha256_file(&self, p: &Path) -> io::Result<String> {
        use std::io::Read;
        let mut f = File::open(p)?;
        let mut ctx = ring::digest::Context::new(&ring::digest::SHA256);
        let mut buf = vec![0u8; 1 << 20];
        loop {
            let n = f.read(&mut buf)?;
            if n == 0 {
                break;
            }
            ctx.update(&buf[..n]);
        }
        Ok(ctx
            .finish()
            .as_ref()
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect())
    }

    fn write_file(&self, p: &Path, data: &[u8], mode: u32) -> io::Result<()> {
        let tmp = p.with_extension("ozbox-tmp");
        {
            let mut f = OpenOptions::new()
                .create(true)
                .truncate(true)
                .write(true)
                .open(&tmp)?;
            f.write_all(data)?;
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&tmp, std::fs::Permissions::from_mode(mode))?;
        }
        #[cfg(not(unix))]
        let _ = mode;
        std::fs::rename(&tmp, p)
    }

    fn create_dir_all(&self, p: &Path) -> io::Result<()> {
        std::fs::create_dir_all(p)
    }

    fn remove_path(&self, p: &Path) -> io::Result<()> {
        match std::fs::symlink_metadata(p) {
            Ok(m) if m.is_dir() => std::fs::remove_dir_all(p),
            Ok(_) => std::fs::remove_file(p),
            Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(()),
            Err(e) => Err(e),
        }
    }

    #[cfg(unix)]
    fn symlink(&self, target: &Path, link: &Path) -> io::Result<()> {
        std::os::unix::fs::symlink(target, link)
    }

    #[cfg(not(unix))]
    fn symlink(&self, _target: &Path, _link: &Path) -> io::Result<()> {
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "symlinks need Unix",
        ))
    }

    fn exists(&self, p: &Path) -> bool {
        std::fs::symlink_metadata(p).is_ok() && std::fs::metadata(p).is_ok()
    }

    fn is_executable(&self, p: &Path) -> bool {
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::metadata(p)
                .map(|m| m.is_file() && m.permissions().mode() & 0o111 != 0)
                .unwrap_or(false)
        }
        #[cfg(not(unix))]
        {
            p.is_file()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::workload_argv;

    #[test]
    fn an_install_step_puts_its_own_oom_score_up_and_its_words_stay_arguments() {
        let step = vec!["npm".to_string(), "install".into(), "a;b $(id)".into()];
        let v = workload_argv(&step);
        assert_eq!(&v[..2], ["sh", "-c"]);
        assert_eq!(
            v[2],
            "{ echo 200 >/proc/self/oom_score_adj; } 2>/dev/null; exec \"$@\""
        );
        assert_eq!(&v[4..], step.as_slice());
    }
}
