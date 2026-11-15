//! Running external programs (`tofu`, `aws`, `ssh` over a tunnel).
//!
//! Commands are always an argv array — never a shell string — so nothing a person or a provider returns can
//! be interpreted by a shell. Adapters take a [`CommandRunner`] so tests can record calls instead of running them.

use std::collections::BTreeMap;
use std::path::PathBuf;
use std::process::Command;
use std::sync::Mutex;

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
}

impl CommandSpec {
    pub fn new(program: impl Into<String>) -> Self {
        Self {
            program: program.into(),
            args: Vec::new(),
            cwd: None,
            env: BTreeMap::new(),
            stdin: None,
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
}
