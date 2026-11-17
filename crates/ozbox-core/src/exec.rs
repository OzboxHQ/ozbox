//! Running external programs (`tofu`, `aws`, `ssh` over a tunnel).
//!
//! Commands are always an argv array — never a shell string — so nothing a person or a provider returns can
//! be interpreted by a shell. Adapters take a [`CommandRunner`] so tests can record calls instead of running them.

use std::collections::BTreeMap;
use std::path::PathBuf;
use std::process::Command;
use std::sync::Mutex;
use std::time::Duration;

use serde::{Deserialize, Serialize};

use crate::{Error, Result};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CommandSpec {
    pub program: String,
    pub args: Vec<String>,
    pub cwd: Option<PathBuf>,
    /// Extra environment. Values may be secrets: they are never logged, recorded or included in errors.
    #[serde(skip)]
    pub env: BTreeMap<String, String>,
    /// Bytes written to the program's standard input, then closed. May hold a secret: never logged or serialized.
    #[serde(skip)]
    pub stdin: Option<Vec<u8>>,
    /// A runner that can (the box's secrets service) kills the program when it runs longer than this. `None`: no limit. A
    /// runner that cannot ignores it, so a caller never relies on it for anything but not waiting forever.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub timeout_secs: Option<u64>,
}

impl CommandSpec {
    pub fn new(program: impl Into<String>) -> Self {
        Self {
            program: program.into(),
            args: Vec::new(),
            cwd: None,
            env: BTreeMap::new(),
            stdin: None,
            timeout_secs: None,
        }
    }

    pub fn arg(mut self, a: impl Into<String>) -> Self {
        self.args.push(a.into());
        self
    }

    pub fn args<I, S>(mut self, items: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        self.args.extend(items.into_iter().map(Into::into));
        self
    }

    pub fn cwd(mut self, dir: impl Into<PathBuf>) -> Self {
        self.cwd = Some(dir.into());
        self
    }

    pub fn env(mut self, k: impl Into<String>, v: impl Into<String>) -> Self {
        self.env.insert(k.into(), v.into());
        self
    }

    /// Stop the program after this long (see [`CommandSpec::timeout_secs`]).
    pub fn timeout(mut self, d: std::time::Duration) -> Self {
        self.timeout_secs = Some(d.as_secs().max(1));
        self
    }

    /// Standard input for the program (a script or a secret that must not appear in the argument list).
    pub fn stdin(mut self, bytes: impl Into<Vec<u8>>) -> Self {
        self.stdin = Some(bytes.into());
        self
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Output {
    pub status: Option<i32>,
    pub stdout: String,
    pub stderr: String,
}

pub trait CommandRunner: Send + Sync {
    fn run(&self, cmd: &CommandSpec) -> Result<Output>;

    /// Run with a **time limit** and a **cap on standard output**, for a command whose answer is read by a program and whose far end may
    /// hang or flood (a transport over `ssh`). A command that outlasts `timeout` is killed and the call fails; one that writes more than
    /// `max_stdout` bytes fails without the rest being read into memory. The default runs the command as [`CommandRunner::run`] does
    /// (a recording runner has nothing to wait for), and [`SystemRunner`] enforces both.
    fn run_limited(
        &self,
        cmd: &CommandSpec,
        timeout: Duration,
        max_stdout: usize,
    ) -> Result<Output> {
        let _ = (timeout, max_stdout);
        self.run(cmd)
    }

    /// Run and fail on a non-zero exit. stderr is truncated so a noisy tool cannot flood an error message.
    fn run_ok(&self, cmd: &CommandSpec) -> Result<Output> {
        let out = self.run(cmd)?;
        if out.status == Some(0) {
            Ok(out)
        } else {
            let mut stderr = out.stderr.trim().to_string();
            if stderr.len() > 2000 {
                let mut cut = 2000;
                while !stderr.is_char_boundary(cut) {
                    cut -= 1;
                }
                stderr.truncate(cut);
                stderr.push_str(" …");
            }
            Err(Error::Command {
                program: cmd.program.clone(),
                code: out.status,
                stderr,
            })
        }
    }
}

/// Runs commands for real.
#[derive(Debug, Default, Clone, Copy)]
pub struct SystemRunner;

impl CommandRunner for SystemRunner {
    fn run(&self, cmd: &CommandSpec) -> Result<Output> {
        let mut c = Command::new(&cmd.program);
        c.args(&cmd.args);
        if let Some(dir) = &cmd.cwd {
            c.current_dir(dir);
        }
        c.envs(&cmd.env);
        let out = match &cmd.stdin {
            None => c.output()?,
            Some(bytes) => {
                use std::io::Write;
                use std::process::Stdio;
                let mut child = c
                    .stdin(Stdio::piped())
                    .stdout(Stdio::piped())
                    .stderr(Stdio::piped())
                    .spawn()?;
                if let Some(mut input) = child.stdin.take() {
                    // A program that exits before reading everything is not an error here: its status says so.
                    let _ = input.write_all(bytes);
                }
                child.wait_with_output()?
            }
        };
        Ok(Output {
            status: out.status.code(),
            stdout: String::from_utf8_lossy(&out.stdout).into_owned(),
            stderr: String::from_utf8_lossy(&out.stderr).into_owned(),
        })
    }

    fn run_limited(
        &self,
        cmd: &CommandSpec,
        timeout: Duration,
        max_stdout: usize,
    ) -> Result<Output> {
        use std::io::Write;
        let mut child = Self::spawn_limited(cmd)?;
        let writer = child.stdin.take().map(|mut input| {
            let bytes = cmd.stdin.clone().unwrap_or_default();
            // a program that exits before reading everything is not an error here: its status says so
            std::thread::spawn(move || {
                let _ = input.write_all(&bytes);
            })
        });
        let out_t = read_capped(child.stdout.take(), max_stdout);
        let err_t = read_capped(child.stderr.take(), 64 * 1024);
        let start = std::time::Instant::now();
        let mut closed_at: Option<std::time::Instant> = None;
        let closed_at = &mut closed_at;
        let status = loop {
            if let Some(s) = child.try_wait()? {
                break Some(s);
            }
            // output that ended (EOF, or the cap was reached) while the program still runs: give it a moment to exit, then stop it
            let drained = out_t.is_finished();
            let grace_over = drained
                && *closed_at.get_or_insert_with(std::time::Instant::now) + Duration::from_secs(2)
                    <= std::time::Instant::now();
            if start.elapsed() >= timeout || grace_over {
                let _ = child.kill();
                let _ = child.wait();
                break None;
            }
            std::thread::sleep(Duration::from_millis(15));
        };
        // never wait forever for the pipes: a descendant of the program (an `ssh` master that kept a descriptor) can hold them open
        // after the program itself is gone or killed. What has not finished within the wait is detached and its output is empty.
        if let Some(w) = writer {
            let _ = join_within(w, PIPE_WAIT);
        }
        let stdout = join_within(out_t, PIPE_WAIT).unwrap_or_default();
        let stderr = join_within(err_t, PIPE_WAIT).unwrap_or_default();
        if stdout.len() > max_stdout {
            return Err(Error::Config(format!(
                "`{}` wrote more than {max_stdout} bytes; the answer was not taken",
                cmd.program
            )));
        }
        if status.is_none() && stdout.len() <= max_stdout && start.elapsed() < timeout {
            // the program closed its output and then did not exit: the output is complete, so it is taken as the answer
            return Ok(Output {
                status: Some(0),
                stdout: String::from_utf8_lossy(&stdout).into_owned(),
                stderr: String::from_utf8_lossy(&stderr).into_owned(),
            });
        }
        let Some(status) = status else {
            return Err(Error::Config(format!(
                "`{}` did not finish within {} seconds and was stopped",
                cmd.program,
                timeout.as_secs()
            )));
        };
        Ok(Output {
            status: status.code(),
            stdout: String::from_utf8_lossy(&stdout).into_owned(),
            stderr: String::from_utf8_lossy(&stderr).into_owned(),
        })
    }
}

impl SystemRunner {
    fn spawn_limited(cmd: &CommandSpec) -> std::io::Result<std::process::Child> {
        use std::process::Stdio;
        let mut c = Command::new(&cmd.program);
        c.args(&cmd.args);
        if let Some(dir) = &cmd.cwd {
            c.current_dir(dir);
        }
        c.envs(&cmd.env);
        c.stdin(if cmd.stdin.is_some() {
            Stdio::piped()
        } else {
            Stdio::null()
        })
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
    }
}

/// How long to wait for a reader thread once the program is gone.
const PIPE_WAIT: Duration = Duration::from_secs(2);

/// Join a thread, but only if it ends within `wait`; otherwise leave it running and return `None`.
fn join_within<T>(h: std::thread::JoinHandle<T>, wait: Duration) -> Option<T> {
    let until = std::time::Instant::now() + wait;
    while !h.is_finished() && std::time::Instant::now() < until {
        std::thread::sleep(Duration::from_millis(10));
    }
    if h.is_finished() {
        h.join().ok()
    } else {
        None
    }
}

fn read_capped(
    pipe: Option<impl std::io::Read + Send + 'static>,
    cap: usize,
) -> std::thread::JoinHandle<Vec<u8>> {
    std::thread::spawn(move || {
        use std::io::Read;
        let mut buf = Vec::new();
        if let Some(p) = pipe {
            // one byte past the cap is read, so "exactly the cap" and "more than the cap" can be told apart
            let _ = p.take(cap as u64 + 1).read_to_end(&mut buf);
        }
        buf
    })
}

/// Records every command and answers from a queue of canned outputs (default: success, empty output).
#[derive(Debug, Default)]
pub struct RecordingRunner {
    calls: Mutex<Vec<CommandSpec>>,
    replies: Mutex<Vec<Output>>,
}

impl RecordingRunner {
    pub fn new() -> Self {
        Self::default()
    }

    /// Queue a reply for the next call (first queued, first used).
    pub fn reply(&self, out: Output) {
        if let Ok(mut r) = self.replies.lock() {
            r.push(out);
        }
    }

    pub fn calls(&self) -> Vec<CommandSpec> {
        self.calls.lock().map(|c| c.clone()).unwrap_or_default()
    }
}

impl CommandRunner for RecordingRunner {
    fn run(&self, cmd: &CommandSpec) -> Result<Output> {
        if let Ok(mut c) = self.calls.lock() {
            c.push(cmd.clone());
        }
        let next = self.replies.lock().ok().and_then(|mut r| {
            if r.is_empty() {
                None
            } else {
                Some(r.remove(0))
            }
        });
        Ok(next.unwrap_or(Output {
            status: Some(0),
            ..Output::default()
        }))
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn failures_carry_exit_code_but_not_env() {
        let r = RecordingRunner::new();
        r.reply(Output {
            status: Some(2),
            stdout: String::new(),
            stderr: "boom".into(),
        });
        let cmd = CommandSpec::new("tofu").arg("apply").env("TOKEN", "s3cr3t");
        let err = match r.run_ok(&cmd) {
            Err(e) => e.to_string(),
            Ok(_) => panic!("should fail"),
        };
        assert!(err.contains("exit Some(2)") && err.contains("boom"));
        assert!(!err.contains("s3cr3t"));
        // env is never serialized either
        let json = serde_json::to_string(&r.calls()[0]).unwrap_or_default();
        assert!(!json.contains("s3cr3t"));
    }

    /// A descendant of the program keeps its output open after the program is gone (the way an `ssh` master can): the call still
    /// returns, because the readers are not waited for forever.
    #[cfg(unix)]
    #[test]
    fn a_descendant_holding_the_pipe_cannot_hang_a_limited_run() {
        let cmd = CommandSpec::new("sh")
            .arg("-c")
            .arg("sleep 6 & echo hello; exit 0");
        let t = std::time::Instant::now();
        let r = SystemRunner.run_limited(&cmd, Duration::from_secs(30), 1024);
        assert!(
            t.elapsed() < Duration::from_secs(5),
            "it waited for the descendant"
        );
        assert_eq!(r.unwrap().status, Some(0));
    }
}
