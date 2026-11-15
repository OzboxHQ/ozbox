//! Version 1 of the AWS CLI has no `aws sso login`, so signing in with it fails with "Invalid choice". It can do the rest
//! the SSH route needs (the key push and `ssm start-session`, with the SSO token a version 2 sign-in cached). So the
//! check is made only where something has already failed (`init`, and the ProxyCommand after a failed connection), never
//! as a gate before a command that would work, and the sentence says only what is true.

use std::path::PathBuf;

use ozbox_core::{CommandRunner, CommandSpec};

pub const INSTALL_URL: &str =
    "https://docs.aws.amazon.com/cli/latest/userguide/getting-started-install.html";

/// The major version in the output of `aws --version` ("aws-cli/2.15.0 Python/3.11 ..."; v1 prints it on stderr).
pub fn major_version(output: &str) -> Option<u32> {
    let rest = output.split("aws-cli/").nth(1)?;
    rest.split('.').next()?.trim().parse().ok()
}

/// The first `aws` on `path` (a PATH-style string), the one a bare `aws` would run.
pub fn first_on_path(path: &str) -> Option<PathBuf> {
    std::env::split_paths(path)
        .map(|d| d.join("aws"))
        .find(|p| p.is_file())
}

/// A version 1 CLI that comes first on this computer, with where it was found. `None` when it is v2, or when it cannot be
/// told (a missing or odd `aws` is reported by the check that needs it, not here).
pub fn v1_in_the_way(
    runner: &dyn CommandRunner,
    path: Option<&str>,
) -> Option<(String, Option<PathBuf>)> {
    let out = runner.run(&CommandSpec::new("aws").arg("--version")).ok()?;
    let text = format!("{}{}", out.stdout, out.stderr);
    let major = major_version(&text)?;
    if major >= 2 {
        return None;
    }
    let version = text
        .split("aws-cli/")
        .nth(1)
        .and_then(|r| r.split_whitespace().next())
        .unwrap_or("1")
        .to_string();
    Some((version, path.and_then(first_on_path)))
}

/// The sentence shown to a person.
pub fn v1_message(version: &str, found: Option<&PathBuf>) -> String {
    let at = found
        .map(|p| format!(" It is the one at {}.", p.display()))
        .unwrap_or_default();
    format!(
        "The AWS CLI on this computer is version {version}, and version 1 cannot run `aws sso login`.{at} Sign in with version 2 (install it from {INSTALL_URL}), then run `aws --version` to check which one comes first on your PATH."
    )
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use ozbox_core::{Output, RecordingRunner};

    fn runner(stdout: &str, stderr: &str) -> RecordingRunner {
        let r = RecordingRunner::new();
        r.reply(Output {
            status: Some(0),
            stdout: stdout.into(),
            stderr: stderr.into(),
        });
        r
    }

    #[test]
    fn the_major_version_is_read_from_either_stream() {
        assert_eq!(
            major_version("aws-cli/2.15.30 Python/3.11.8 Linux/x"),
            Some(2)
        );
        assert_eq!(
            major_version("aws-cli/1.18.69 Python/3.8.10 Linux/5 botocore/1.16.19"),
            Some(1)
        );
        assert_eq!(major_version("something else"), None);
    }

    #[test]
    fn a_v1_is_named_with_where_it_was_found_and_a_v2_is_left_alone() {
        let d = tempfile::tempdir().unwrap();
        let bin = d.path().join("bin");
        std::fs::create_dir(&bin).unwrap();
        std::fs::write(bin.join("aws"), "").unwrap();
        let path = format!("/nonexistent:{}", bin.display());
        let (v, at) =
            v1_in_the_way(&runner("", "aws-cli/1.18.69 Python/3.8.10"), Some(&path)).unwrap();
        assert_eq!(v, "1.18.69");
        assert_eq!(at.as_deref(), Some(bin.join("aws").as_path()));
        let m = v1_message(&v, at.as_ref());
        assert!(m.contains("cannot run `aws sso login`") && m.contains(&bin.display().to_string()));
        assert!(!m.contains("cannot open the connection"));
        assert!(v1_in_the_way(&runner("aws-cli/2.15.30 Python/3.11", ""), Some(&path)).is_none());
        // a CLI that cannot be run or read is not called a v1
        assert!(v1_in_the_way(&runner("", ""), Some(&path)).is_none());
    }
}
