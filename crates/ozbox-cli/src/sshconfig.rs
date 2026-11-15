//! The SSH config entry that reaches a box. A box's sshd listens on loopback only (ADR 0005), so every route runs a
//! tunnel client as a ProxyCommand instead of pointing at an address.
//!
//! Two routes exist. On AWS the documented route is Session Manager's `AWS-StartSSHSession` document, which needs no
//! domain and no tunnel of our own. The Cloudflare route is offered only where a domain is configured.

use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};

use ozbox_core::{BoxRecord, CommandRunner, CommandSpec, Error, Result};

/// `ozbox-<name>`: the alias people type (`ssh ozbox-dev`) and desktop apps list as a remote host.
pub fn host_alias(name: &str) -> String {
    format!("ozbox-{name}")
}

/// The account a person's computer uses to reach a box's secrets service (see `ingress_guard`).
pub const INGRESS_USER: &str = "ozbox-ingress";

/// `ozbox-<name>-ingress`: the same route as [`host_alias`], logging in as the ingress account.
pub fn ingress_alias(name: &str) -> String {
    format!("ozbox-{name}-ingress")
}

/// The ingress account's own key (private file; the public one has `.pub` appended). Never the box user's key: a key the box
/// user's route offers, or an agent that holds it, must not also open the account that carries the secrets (ADR 0029,
/// Amendment 9).
pub const INGRESS_KEY_NAME: &str = "ozbox_ingress_ed25519";

/// The ingress account's `Host` block, made from the box user's block for the same route: the same machine and route, a
/// different alias, account and key (and, on AWS, that key is pushed for that account). The key is named, only that key is
/// offered, and the agent is never forwarded, on every route. Pure.
pub fn ingress_block(box_block: &str, name: &str) -> String {
    let mut out = String::new();
    for line in box_block.lines() {
        let t = line.trim_start();
        if t.starts_with("IdentityFile ")
            || t.starts_with("IdentitiesOnly ")
            || t.starts_with("ForwardAgent ")
        {
            continue;
        }
        let new = if t.starts_with("Host ") && !line.starts_with(' ') {
            format!("Host {}", ingress_alias(name))
        } else if t.starts_with("User ") {
            format!(
                "    User {INGRESS_USER}\n    IdentityFile ~/.ssh/{INGRESS_KEY_NAME}\n    IdentitiesOnly yes\n    ForwardAgent no"
            )
        } else {
            line.replace(
                &format!("--instance-os-user {OS_USER} "),
                &format!("--instance-os-user {INGRESS_USER} "),
            )
            .replace(
                &format!("file://$HOME/.ssh/{KEY_NAME}.pub"),
                &format!("file://$HOME/.ssh/{INGRESS_KEY_NAME}.pub"),
            )
        };
        out.push_str(&new);
        out.push('\n');
    }
    out
}

/// The tunnel hostname of a box's SSH service: one label under the configured domain.
pub fn tunnel_host(name: &str, domain: &str) -> String {
    format!("ssh-{name}.{domain}")
}

/// How the SSH connection reaches the box.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Route {
    /// AWS Systems Manager Session Manager. `instance` is the EC2 instance id.
    AwsSsm {
        instance: String,
        region: String,
        profile: Option<String>,
    },
    /// A tailnet of your own (Headscale). `host` is the box's name on the tailnet; the client forwards port 22 to the
    /// box's own loopback SSH server (see `mesh`).
    Mesh { host: String, user: String },
    /// A Cloudflare tunnel under a configured domain.
    Cloudflare { domain: String },
}

impl Route {
    pub fn id(&self) -> &'static str {
        match self {
            Route::AwsSsm { .. } => "aws-ssm",
            Route::Mesh { .. } => "mesh",
            Route::Cloudflare { .. } => "cloudflare",
        }
    }

    pub fn label(&self) -> &'static str {
        match self {
            Route::AwsSsm { .. } => "AWS Session Manager",
            Route::Mesh { .. } => "Your own tailnet (Headscale)",
            Route::Cloudflare { .. } => "Cloudflare tunnel (needs your own domain and tunnel)",
        }
    }

    /// What must already be true for the route to work.
    pub fn requirements(&self) -> &'static str {
        match self {
            Route::AwsSsm { .. } => "The AWS CLI and the Session Manager plugin on this computer, and AWS sign-in with permission to start an SSH session and to send a public key to the instance (EC2 Instance Connect). A dedicated key, ~/.ssh/ozbox_ed25519, is created for you and pushed for 60 seconds at each connection; your main key is never used.",
            Route::Mesh { .. } => "This computer signed in to your Headscale server with a Tailscale client, and the box joined with `ozbox mesh join`. Your dedicated key, ~/.ssh/ozbox_ed25519, is added to the box by that command.",
            Route::Cloudflare { .. } => "cloudflared on this computer and a tunnel for this box under your domain. Oz Box does not provision that tunnel yet.",
        }
    }
}

/// A complete `Host` block. Pure text: nothing is written or run.
pub fn block(name: &str, route: &Route) -> String {
    let alias = host_alias(name);
    match route {
        Route::AwsSsm {
            instance,
            region,
            profile,
        } => {
            let profile = profile
                .as_deref()
                .map(|p| format!(" --profile {p}"))
                .unwrap_or_default();
            // Before each connection the dedicated public key is pushed through EC2 Instance Connect: the box keeps it
            // for 60 seconds and nothing is stored. Its output goes to /dev/null because a ProxyCommand's stdout is
            // the SSH data stream; a failed push does not stop the session (the box may already trust the key).
            format!(
                "Host {alias}\n    HostName {instance}\n    User {OS_USER}\n    IdentityFile ~/.ssh/{KEY_NAME}\n    IdentitiesOnly yes\n    ForwardAgent no\n    ProxyCommand sh -c \"PATH=$HOME/.local/bin:$HOME/.local/aws-cli:/usr/local/bin:/opt/homebrew/bin:/usr/bin:/bin; export PATH; aws ec2-instance-connect send-ssh-public-key --instance-id %h --instance-os-user {OS_USER} --ssh-public-key file://$HOME/.ssh/{KEY_NAME}.pub --region {region}{profile} >/dev/null || true; aws ssm start-session --target %h --document-name AWS-StartSSHSession --parameters 'portNumber=%p' --region {region}{profile} || {{ rc=\\$?; case \\\"\\$(aws --version 2>&1)\\\" in *aws-cli/1.*) echo \\\"ozbox: the connection failed. The AWS CLI used here (\\$(command -v aws)) is version 1. Version 1 can open a connection but cannot run 'aws sso login', so if your sign-in has expired, sign in with version 2 (install it from https://docs.aws.amazon.com/cli/latest/userguide/getting-started-install.html).\\\" >&2;; esac; exit \\$rc; }}\"\n    ServerAliveInterval 30\n    ServerAliveCountMax 4\n"
            )
        }
        Route::Mesh { host, user } => format!(
            "Host {alias}\n    HostName {host}\n    User {user}\n    IdentityFile ~/.ssh/{KEY_NAME}\n    IdentitiesOnly yes\n    ForwardAgent no\n    ServerAliveInterval 30\n    ServerAliveCountMax 4\n"
        ),
        Route::Cloudflare { domain } => format!(
            "Host {alias}\n    HostName {host}\n    User ozbox\n    ForwardAgent no\n    ProxyCommand cloudflared access ssh --hostname %h\n    ServerAliveInterval 30\n    ServerAliveCountMax 4\n",
            host = tunnel_host(name, domain),
        ),
    }
}

/// What the SSH routes are built from.
#[derive(Debug, Default, Clone)]
pub struct RouteInputs {
    pub aws_region: Option<String>,
    pub aws_profile: Option<String>,
    pub domain: Option<String>,
    /// Set when `mesh.toml` exists: the account on a box, and the tailnet's base domain (empty for the short name).
    pub mesh: Option<(String, String)>,
}

/// The routes that can reach this box, most direct first. AWS Session Manager only for an AWS box with a known
/// instance id; Cloudflare only where a domain is configured.
pub fn routes(rec: &BoxRecord, inp: &RouteInputs) -> Vec<Route> {
    let mut out = Vec::new();
    if rec.provider == "aws" {
        let region = rec.spec.region.clone().or_else(|| inp.aws_region.clone());
        if let (Some(instance), Some(region)) = (rec.provider_id.as_deref(), region) {
            let profile_ok = inp.aws_profile.as_deref().is_none_or(safe_word);
            if safe_word(instance) && safe_word(&region) && profile_ok {
                out.push(Route::AwsSsm {
                    instance: instance.to_string(),
                    region,
                    profile: inp.aws_profile.clone(),
                });
            }
        }
    }
    if let Some((user, base)) = inp
        .mesh
        .as_ref()
        .filter(|(u, b)| safe_word(u) && (b.is_empty() || safe_word(b)))
    {
        let name = rec.spec.name.as_str();
        out.push(Route::Mesh {
            host: if base.is_empty() {
                name.to_string()
            } else {
                format!("{name}.{base}")
            },
            user: user.clone(),
        });
    }
    if let Some(d) = inp
        .domain
        .as_deref()
        .filter(|d| !d.is_empty() && safe_word(d))
    {
        out.push(Route::Cloudflare {
            domain: d.to_string(),
        });
    }
    out
}

/// The only account SSH logs in as.
pub const OS_USER: &str = "ozbox";
/// The dedicated key (private file; the public one has `.pub` appended). Never the person's main key.
pub const KEY_NAME: &str = "ozbox_ed25519";

/// Make sure the dedicated key pair exists under `ssh_dir`; returns the public key path and whether it was created.
/// An existing private key is never replaced. Commands run as argv arrays through `runner`.
pub fn ensure_key(runner: &dyn CommandRunner, ssh_dir: &Path) -> Result<(PathBuf, bool)> {
    ensure_named_key(runner, ssh_dir, KEY_NAME)
}

/// [`ensure_key`] for any of this program's dedicated keys ([`KEY_NAME`] or [`INGRESS_KEY_NAME`]).
pub fn ensure_named_key(
    runner: &dyn CommandRunner,
    ssh_dir: &Path,
    key_name: &str,
) -> Result<(PathBuf, bool)> {
    let private = ssh_dir.join(key_name);
    let public = ssh_dir.join(format!("{key_name}.pub"));
    if private.exists() {
        if !public.exists() {
            let out = runner.run_ok(&CommandSpec::new("ssh-keygen").args([
                "-y",
                "-f",
                &private.to_string_lossy(),
            ]))?;
            write_private(&public, out.stdout.trim())?;
        }
        return Ok((public, false));
    }
    fs::create_dir_all(ssh_dir)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = fs::set_permissions(ssh_dir, fs::Permissions::from_mode(0o700));
    }
    runner.run_ok(&CommandSpec::new("ssh-keygen").args([
        "-q",
        "-t",
        "ed25519",
        "-N",
        "",
        "-C",
        "ozbox",
        "-f",
        &private.to_string_lossy(),
    ]))?;
    Ok((public, true))
}

/// The call that makes the box accept `public_key` for the next 60 seconds. Nothing is stored on the box.
pub fn push_key_command(
    instance: &str,
    region: &str,
    profile: Option<&str>,
    public_key: &Path,
) -> CommandSpec {
    let mut c = CommandSpec::new("aws").args([
        "ec2-instance-connect",
        "send-ssh-public-key",
        "--instance-id",
        instance,
        "--instance-os-user",
        OS_USER,
        "--ssh-public-key",
    ]);
    c = c.arg(format!("file://{}", public_key.display()));
    c = c.args(["--region", region]);
    if let Some(p) = profile {
        c = c.args(["--profile", p]);
    }
    c
}

/// Values that go into a ProxyCommand must be plain words; anything else is refused rather than quoted.
pub fn safe_word(s: &str) -> bool {
    !s.is_empty()
        && s.chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.' | '@'))
}

pub const INCLUDE_LINE: &str = "Include ~/.ssh/ozbox/config";
const BEGIN: &str = "# ozbox:begin ";
const END: &str = "# ozbox:end ";

/// Replace (or append) the block for `alias` in `existing` managed-file text. Other aliases are untouched.
pub fn upsert_block(existing: &str, alias: &str, block: &str) -> String {
    let begin = format!("{BEGIN}{alias}");
    let end = format!("{END}{alias}");
    let wrapped = format!("{begin}\n{block}{end}\n");
    let mut out = String::new();
    let mut skipping = false;
    let mut replaced = false;
    for line in existing.lines() {
        if line == begin {
            skipping = true;
            if !replaced {
                out.push_str(&wrapped);
                replaced = true;
            }
            continue;
        }
        if skipping {
            if line == end {
                skipping = false;
            }
            continue;
        }
        out.push_str(line);
        out.push('\n');
    }
    if !replaced {
        if !out.is_empty() && !out.ends_with("\n\n") {
            out.push('\n');
        }
        out.push_str(&wrapped);
    }
    out
}

#[derive(Debug, PartialEq, Eq)]
pub struct WriteReport {
    pub included_file: PathBuf,
    pub main_config: PathBuf,
    /// Set when the main config was changed (one `Include` line added); the copy made first.
    pub backup: Option<PathBuf>,
    pub include_added: bool,
}

/// Write `block` for `name` into `<ssh_dir>/ozbox/config` and make sure `<ssh_dir>/config` includes that file.
/// The main config is only ever changed by prepending one `Include` line (an `Include` must come before any `Host`).
pub fn write_config(ssh_dir: &Path, name: &str, block: &str, now_unix: u64) -> Result<WriteReport> {
    let dir = ssh_dir.join("ozbox");
    fs::create_dir_all(&dir)?;
    let included = dir.join("config");
    let current = match fs::read_to_string(&included) {
        Ok(t) => t,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => String::new(),
        Err(e) => return Err(e.into()),
    };
    let updated = upsert_block(&current, &host_alias(name), block);
    let updated = upsert_block(&updated, &ingress_alias(name), &ingress_block(block, name));
    write_private(&included, &updated)?;

    let main = ssh_dir.join("config");
    let text = match fs::read_to_string(&main) {
        Ok(t) => Some(t),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => None,
        Err(e) => return Err(e.into()),
    };
    let has = text
        .as_deref()
        .is_some_and(|t| t.lines().any(|l| l.trim() == INCLUDE_LINE));
    if has {
        return Ok(WriteReport {
            included_file: included,
            main_config: main,
            backup: None,
            include_added: false,
        });
    }
    let mut backup = None;
    if let Some(t) = &text {
        let b = ssh_dir.join(format!("config.ozbox-backup-{now_unix}"));
        fs::write(&b, t)?;
        backup = Some(b);
    }
    let new = format!(
        "# Added by ozbox: boxes are listed in ~/.ssh/ozbox/config\n{INCLUDE_LINE}\n\n{}",
        text.unwrap_or_default()
    );
    write_private(&main, &new)?;
    Ok(WriteReport {
        included_file: included,
        main_config: main,
        backup,
        include_added: true,
    })
}

/// What [`refresh_entry`] did.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct Refresh {
    /// The box's block in `<ssh_dir>/ozbox/config` was out of date and was rewritten.
    pub rewritten: bool,
    /// Machine ids whose host keys were removed from `<ssh_dir>/known_hosts`.
    pub forgotten: Vec<String>,
}

/// The `HostName` of the block for `alias` in managed-file text.
pub fn host_name_in(existing: &str, alias: &str) -> Option<String> {
    let begin = format!("{BEGIN}{alias}");
    let end = format!("{END}{alias}");
    let mut inside = false;
    for line in existing.lines() {
        if line == begin {
            inside = true;
        } else if line == end {
            inside = false;
        } else if inside {
            if let Some(rest) = line.trim().strip_prefix("HostName ") {
                return Some(rest.trim().to_string());
            }
        }
    }
    None
}

/// After a box's machine was replaced (an upgrade, or finishing an interrupted one): bring the box's entry in
/// `<ssh_dir>/ozbox/config` up to date and forget the old machine's host key. The block is only rewritten when it
/// already exists (nothing is added for a person who never asked for one) and the main config is never touched.
/// `previous` is the old machine's id when the caller knows it; the id in the existing block is forgotten too. A host
/// key belongs to one machine, so the new machine's own entry is never removed.
pub fn refresh_entry(
    runner: &dyn CommandRunner,
    ssh_dir: &Path,
    name: &str,
    route: Option<&Route>,
    previous: Option<&str>,
) -> Result<Refresh> {
    let alias = host_alias(name);
    let included = ssh_dir.join("ozbox").join("config");
    let current = fs::read_to_string(&included).unwrap_or_default();
    let in_file = host_name_in(&current, &alias);
    let mut out = Refresh::default();
    if let (Some(route), Some(_)) = (route, &in_file) {
        let b = block(name, route);
        let updated = upsert_block(&current, &alias, &b);
        let updated = upsert_block(&updated, &ingress_alias(name), &ingress_block(&b, name));
        if updated != current {
            write_private(&included, &updated)?;
            out.rewritten = true;
        }
    }
    let new_host = match route {
        Some(Route::AwsSsm { instance, .. }) => Some(instance.as_str()),
        _ => None,
    };
    let known = ssh_dir.join("known_hosts");
    if !known.exists() {
        return Ok(out);
    }
    let mut old: Vec<String> = Vec::new();
    for h in in_file.iter().map(String::as_str).chain(previous) {
        if safe_word(h) && Some(h) != new_host && !old.iter().any(|o| o == h) {
            old.push(h.to_string());
        }
    }
    for h in old {
        let spec = CommandSpec::new("ssh-keygen").args(["-R", &h, "-f", &known.to_string_lossy()]);
        if runner.run_ok(&spec).is_ok() {
            out.forgotten.push(h);
        }
    }
    Ok(out)
}

/// Drop the block for `alias` from managed-file text. Other aliases are untouched; text without the block is returned
/// unchanged.
pub fn remove_block(existing: &str, alias: &str) -> String {
    let begin = format!("{BEGIN}{alias}");
    let end = format!("{END}{alias}");
    let mut out = String::new();
    let mut skipping = false;
    for line in existing.lines() {
        if line == begin {
            skipping = true;
            continue;
        }
        if skipping {
            if line == end {
                skipping = false;
            }
            continue;
        }
        out.push_str(line);
        out.push('\n');
    }
    out
}

/// After a box is destroyed: remove its entry from `<ssh_dir>/ozbox/config` and forget its machine's host key. The
/// main config is never touched. Never an error for a box that had no entry.
pub fn remove_entry(runner: &dyn CommandRunner, ssh_dir: &Path, name: &str) -> Result<Refresh> {
    let alias = host_alias(name);
    let included = ssh_dir.join("ozbox").join("config");
    let current = fs::read_to_string(&included).unwrap_or_default();
    let host = host_name_in(&current, &alias);
    let mut out = Refresh::default();
    let updated = remove_block(&remove_block(&current, &alias), &ingress_alias(name));
    if updated != current {
        write_private(&included, &updated)?;
        out.rewritten = true;
    }
    let known = ssh_dir.join("known_hosts");
    if let Some(h) = host.filter(|h| safe_word(h)) {
        if known.exists() {
            let spec =
                CommandSpec::new("ssh-keygen").args(["-R", &h, "-f", &known.to_string_lossy()]);
            if runner.run_ok(&spec).is_ok() {
                out.forgotten.push(h);
            }
        }
    }
    Ok(out)
}

fn write_private(path: &Path, text: &str) -> Result<()> {
    let tmp = path.with_extension("ozbox-tmp");
    {
        let mut f = fs::File::create(&tmp)?;
        f.write_all(text.as_bytes())?;
        f.sync_all()?;
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&tmp, fs::Permissions::from_mode(0o600))?;
    }
    fs::rename(&tmp, path).map_err(Error::from)
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use ozbox_core::SystemRunner;

    type R = std::result::Result<(), Box<dyn std::error::Error>>;
    type Result<T> = std::result::Result<T, Box<dyn std::error::Error>>;

    fn aws() -> Route {
        Route::AwsSsm {
            instance: "i-0123456789abcdef0".into(),
            region: "us-east-1".into(),
            profile: Some("work".into()),
        }
    }

    #[test]
    fn the_aws_block_uses_the_documented_session_manager_command() {
        let b = block("dev", &aws());
        assert!(b.starts_with("Host ozbox-dev\n"));
        assert!(b.contains("HostName i-0123456789abcdef0"));
        assert!(b.contains("User ozbox"));
        assert!(b.contains("IdentityFile ~/.ssh/ozbox_ed25519\n    IdentitiesOnly yes"));
        assert!(b.contains("PATH=$HOME/.local/bin:$HOME/.local/aws-cli:/usr/local/bin:/opt/homebrew/bin:/usr/bin:/bin; export PATH; "));
        assert!(b.contains("; aws ec2-instance-connect send-ssh-public-key --instance-id %h --instance-os-user ozbox --ssh-public-key file://$HOME/.ssh/ozbox_ed25519.pub --region us-east-1 --profile work >/dev/null || true;"));
        assert!(b.contains("aws ssm start-session --target %h --document-name AWS-StartSSHSession --parameters 'portNumber=%p' --region us-east-1 --profile work"));
        assert!(!b.contains("cloudflared"));
        assert!(!b.contains("Port "));
    }

    /// Run the ProxyCommand the way ssh does (`sh -c <value>`), with a fake `aws` first on its PATH. The fake prints
    /// `version_out` for `--version` (and logs that it was asked), and fails `ssm` with `ssm_exit`.
    #[cfg(unix)]
    fn run_proxy(version_out: &str, ssm_exit: i32) -> (Option<i32>, String, String, String) {
        use std::os::unix::fs::PermissionsExt;
        let d = tempfile::tempdir().unwrap();
        let bin = d.path().join(".local/bin");
        std::fs::create_dir_all(&bin).unwrap();
        let calls = d.path().join("calls");
        let versions = d.path().join("versions");
        let fake = format!(
            "#!/bin/sh\nif [ \"$1\" = --version ]; then echo asked >> {}; printf '%b\\n' '{version_out}' >&2; exit 0; fi\necho \"$@\" >> {}\nif [ \"$1\" = ssm ]; then exit {ssm_exit}; fi\n",
            versions.display(),
            calls.display()
        );
        let p = bin.join("aws");
        std::fs::write(&p, fake).unwrap();
        std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o755)).unwrap();
        let b = block("dev", &aws());
        let line = b.lines().find(|l| l.contains("ProxyCommand")).unwrap();
        let cmd = line.trim().strip_prefix("ProxyCommand ").unwrap();
        let cmd = cmd.replace("%h", "i-0123456789abcdef0").replace("%p", "22");
        let out = std::process::Command::new("sh")
            .arg("-c")
            .arg(&cmd)
            .env("HOME", d.path())
            .output()
            .unwrap();
        (
            out.status.code(),
            String::from_utf8_lossy(&out.stderr).into_owned(),
            std::fs::read_to_string(&calls).unwrap_or_default(),
            std::fs::read_to_string(&versions).unwrap_or_default(),
        )
    }

    #[cfg(unix)]
    #[test]
    fn a_working_connection_costs_no_version_check_and_a_v1_that_works_is_left_alone() {
        for v in [
            "aws-cli/2.15.30 Python/3.11.8 Linux/6.1",
            "aws-cli/1.46.1 Python/3.11 Darwin/22",
        ] {
            let (code, err, seen, asked) = run_proxy(v, 0);
            assert_eq!(code, Some(0), "{v}: {err}");
            assert!(seen.contains("ssm start-session"), "{seen}");
            assert!(err.is_empty(), "nothing is said when it works: {err}");
            assert!(
                asked.is_empty(),
                "no extra CLI start on a good connection: {asked}"
            );
        }
    }

    #[cfg(unix)]
    #[test]
    fn a_failed_connection_names_the_aws_used_when_it_is_version_1_and_keeps_the_exit_code() {
        // a v1 that printed a deprecation warning first still counts as a v1
        let (code, err, seen, asked) = run_proxy(
            "DeprecationWarning: this is old\\naws-cli/1.18.69 Python/3.8.10 Linux/5.4",
            7,
        );
        assert_eq!(code, Some(7));
        assert!(
            err.contains("version 1") && err.contains("aws sso login"),
            "{err}"
        );
        assert!(
            err.contains(".local/bin/aws"),
            "it names the aws it used: {err}"
        );
        assert!(
            seen.contains("ssm start-session") && asked == "asked\n",
            "{seen} {asked}"
        );
        // a v2 that fails says nothing about versions
        let (code, err, _, _) = run_proxy("aws-cli/2.15.30 Python/3.11.8 Linux/6.1", 3);
        assert_eq!(code, Some(3));
        assert!(!err.contains("version 1"), "{err}");
    }

    /// `ssh -G` reads the generated block the way ssh will: the ProxyCommand comes out whole, with no stray quote.
    #[cfg(unix)]
    #[test]
    fn ssh_parses_the_generated_block() {
        if std::process::Command::new("ssh")
            .arg("-V")
            .output()
            .is_err()
        {
            return;
        }
        let d = tempfile::tempdir().unwrap();
        let cfg = d.path().join("config");
        std::fs::write(&cfg, block("dev", &aws())).unwrap();
        let out = std::process::Command::new("ssh")
            .args(["-G", "-F"])
            .arg(&cfg)
            .arg("ozbox-dev")
            .output()
            .unwrap();
        let text = String::from_utf8_lossy(&out.stdout).into_owned();
        let pc = text
            .lines()
            .find(|l| l.starts_with("proxycommand "))
            .unwrap_or("");
        assert!(
            pc.contains("start-session") && pc.contains("exit \\$rc; }"),
            "{pc}"
        );
        assert!(text.contains("hostname i-0123456789abcdef0"));
    }

    #[test]
    fn the_key_push_is_one_argv_for_the_dedicated_key_and_the_ozbox_user() {
        let c = push_key_command(
            "i-0123456789abcdef0",
            "us-east-1",
            Some("work"),
            Path::new("/home/a/.ssh/ozbox_ed25519.pub"),
        );
        assert_eq!(c.program, "aws");
        assert_eq!(
            c.args,
            [
                "ec2-instance-connect",
                "send-ssh-public-key",
                "--instance-id",
                "i-0123456789abcdef0",
                "--instance-os-user",
                "ozbox",
                "--ssh-public-key",
                "file:///home/a/.ssh/ozbox_ed25519.pub",
                "--region",
                "us-east-1",
                "--profile",
                "work"
            ]
        );
    }

    #[test]
    fn a_key_is_generated_once_and_never_replaced() -> R {
        use ozbox_core::RecordingRunner;
        let d = tempfile::tempdir()?;
        let r = RecordingRunner::new();
        let (public, created) = ensure_key(&r, d.path())?;
        assert!(created && public.ends_with("ozbox_ed25519.pub"));
        let calls = r.calls();
        assert_eq!(calls.len(), 1);
        assert_eq!(calls[0].program, "ssh-keygen");
        assert!(calls[0].args.windows(2).any(|w| w == ["-t", "ed25519"]));
        assert!(calls[0].args.windows(2).any(|w| w == ["-N", ""]));
        assert!(calls[0]
            .args
            .last()
            .is_some_and(|a| a.ends_with("/ozbox_ed25519")));
        // the private key already exists: no new key, and a missing public half is derived, not regenerated
        fs::write(d.path().join("ozbox_ed25519"), "PRIVATE")?;
        r.reply(ozbox_core::Output {
            status: Some(0),
            stdout: "ssh-ed25519 AAAA ozbox\n".into(),
            stderr: String::new(),
        });
        let (_, created) = ensure_key(&r, d.path())?;
        assert!(!created);
        assert_eq!(r.calls()[1].args[..2], ["-y", "-f"]);
        assert_eq!(fs::read_to_string(&public)?, "ssh-ed25519 AAAA ozbox");
        assert_eq!(
            fs::read_to_string(d.path().join("ozbox_ed25519"))?,
            "PRIVATE"
        );
        // both present: nothing runs
        let (_, created) = ensure_key(&r, d.path())?;
        assert!(!created && r.calls().len() == 2);
        Ok(())
    }

    #[test]
    fn the_cloudflare_block_names_the_tunnel_host_and_no_ip() {
        let b = block(
            "dev",
            &Route::Cloudflare {
                domain: "example.com".into(),
            },
        );
        assert!(b.contains("HostName ssh-dev.example.com"));
        assert!(b.contains("ProxyCommand cloudflared access ssh --hostname %h"));
        assert!(!b.contains("Port "));
    }

    fn rec(provider: &str, id: Option<&str>) -> Result<BoxRecord> {
        Ok(BoxRecord {
            spec: ozbox_core::BoxSpec::new(ozbox_core::BoxName::new("dev")?, ozbox_core::Size::M),
            state: ozbox_core::BoxState::Running,
            provider: provider.into(),
            provider_id: id.map(String::from),
            machine_type: None,
            snapshots: vec![],
            created_at: None,
            last_activity_at: None,
        })
    }

    #[test]
    fn routes_follow_the_provider_and_the_config() -> R {
        let inp = RouteInputs {
            aws_region: Some("us-east-1".into()),
            aws_profile: None,
            domain: Some("example.com".into()),
            mesh: None,
        };
        let r = routes(&rec("aws", Some("i-1"))?, &inp);
        assert_eq!(
            r.iter().map(Route::id).collect::<Vec<_>>(),
            ["aws-ssm", "cloudflare"]
        );
        let r = routes(&rec("aws", Some("i-1"))?, &RouteInputs::default());
        assert!(r.is_empty());
        let only_cf = routes(&rec("hcloud", Some("42"))?, &inp);
        assert_eq!(
            only_cf.iter().map(Route::id).collect::<Vec<_>>(),
            ["cloudflare"]
        );
        let bad = RouteInputs {
            aws_profile: Some("a; b".into()),
            ..inp
        };
        assert_eq!(routes(&rec("aws", Some("i-1"))?, &bad).len(), 1);
        Ok(())
    }

    #[test]
    fn aliases_are_stable_and_words_are_checked() {
        assert_eq!(host_alias("a-b"), "ozbox-a-b");
        assert_eq!(tunnel_host("a-b", "x.org"), "ssh-a-b.x.org");
        assert!(safe_word("us-east-1"));
        assert!(!safe_word("x; rm -rf"));
        assert!(!safe_word("a b"));
        assert!(!safe_word(""));
    }

    #[test]
    fn upsert_replaces_only_its_own_block() {
        let a = upsert_block("", "ozbox-a", "Host ozbox-a\n    User x\n");
        let both = upsert_block(&a, "ozbox-b", "Host ozbox-b\n    User y\n");
        let again = upsert_block(&both, "ozbox-a", "Host ozbox-a\n    User z\n");
        assert!(again.contains("User z"));
        assert!(!again.contains("User x"));
        assert!(again.contains("User y"));
        assert_eq!(again.matches("ozbox:begin ozbox-a").count(), 1);
    }

    #[test]
    fn writing_adds_one_include_line_with_a_backup_and_is_idempotent() -> R {
        let d = tempfile::tempdir()?;
        let main = d.path().join("config");
        fs::write(&main, "Host work\n    User me\n")?;
        let blk = block("dev", &aws());
        let r = write_config(d.path(), "dev", &blk, 100)?;
        assert!(r.include_added);
        let backup = r.backup.ok_or("no backup")?;
        assert_eq!(fs::read_to_string(backup)?, "Host work\n    User me\n");
        let text = fs::read_to_string(&main)?;
        // the Include comes before the user's own Host (an Include after a Host would be scoped to it)
        let inc = text.find(INCLUDE_LINE).ok_or("no include")?;
        assert!(inc < text.find("Host work").ok_or("lost config")?);
        assert!(text.ends_with("Host work\n    User me\n"));
        let included = fs::read_to_string(d.path().join("ozbox/config"))?;
        assert!(included.contains("Host ozbox-dev"));

        let r2 = write_config(d.path(), "dev", &blk, 200)?;
        assert!(!r2.include_added);
        assert!(r2.backup.is_none());
        assert_eq!(fs::read_to_string(&main)?.matches(INCLUDE_LINE).count(), 1);
        assert_eq!(
            fs::read_to_string(d.path().join("ozbox/config"))?
                .matches("Host ozbox-dev\n")
                .count(),
            1
        );
        // and the ingress account's entry beside it, once
        assert_eq!(
            fs::read_to_string(d.path().join("ozbox/config"))?
                .matches("Host ozbox-dev-ingress\n")
                .count(),
            1
        );
        Ok(())
    }

    #[test]
    fn a_missing_main_config_is_created_without_a_backup() -> R {
        let d = tempfile::tempdir()?;
        let r = write_config(d.path(), "dev", "Host ozbox-dev\n", 1)?;
        assert!(r.include_added && r.backup.is_none());
        assert!(fs::read_to_string(d.path().join("config"))?.contains(INCLUDE_LINE));
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = fs::metadata(d.path().join("ozbox/config"))?
                .permissions()
                .mode();
            assert_eq!(mode & 0o777, 0o600);
        }
        Ok(())
    }
    fn aws_for(instance: &str) -> Route {
        Route::AwsSsm {
            instance: instance.into(),
            region: "us-east-1".into(),
            profile: None,
        }
    }

    /// A known_hosts file with one real entry per host, made with the system's ssh-keygen.
    fn known_hosts(dir: &Path, hosts: &[&str]) -> Result<String> {
        let mut text = String::new();
        for (i, h) in hosts.iter().enumerate() {
            let key = dir.join(format!("k{i}"));
            let status = std::process::Command::new("ssh-keygen")
                .args(["-q", "-t", "ed25519", "-N", "", "-f"])
                .arg(&key)
                .status()?;
            assert!(status.success());
            let public = fs::read_to_string(dir.join(format!("k{i}.pub")))?;
            let mut parts = public.split_whitespace();
            text.push_str(&format!(
                "{h} {} {}\n",
                parts.next().unwrap_or(""),
                parts.next().unwrap_or("")
            ));
        }
        fs::write(dir.join("known_hosts"), &text)?;
        Ok(text)
    }

    #[test]
    fn an_upgrade_rewrites_the_boxs_entry_and_forgets_the_old_machines_host_key() -> R {
        let d = tempfile::tempdir()?;
        let old = aws_for("i-0aaaaaaaaaaaaaaaa");
        let new = aws_for("i-0bbbbbbbbbbbbbbbb");
        write_config(d.path(), "dev", &block("dev", &old), 1)?;
        write_config(
            d.path(),
            "other",
            &block("other", &aws_for("i-0cccccccccccccccc")),
            2,
        )?;
        known_hosts(
            d.path(),
            &[
                "i-0aaaaaaaaaaaaaaaa",
                "i-0cccccccccccccccc",
                "unrelated.example.com",
            ],
        )?;

        let r = refresh_entry(&SystemRunner, d.path(), "dev", Some(&new), None)?;
        assert!(r.rewritten);
        assert_eq!(r.forgotten, vec!["i-0aaaaaaaaaaaaaaaa".to_string()]);

        let conf = fs::read_to_string(d.path().join("ozbox/config"))?;
        assert_eq!(
            host_name_in(&conf, "ozbox-dev").as_deref(),
            Some("i-0bbbbbbbbbbbbbbbb")
        );
        assert!(!conf.contains("i-0aaaaaaaaaaaaaaaa"));
        // another box's entry is untouched
        assert_eq!(
            host_name_in(&conf, "ozbox-other").as_deref(),
            Some("i-0cccccccccccccccc")
        );
        let known = fs::read_to_string(d.path().join("known_hosts"))?;
        assert!(!known.contains("i-0aaaaaaaaaaaaaaaa"));
        assert!(known.contains("i-0cccccccccccccccc") && known.contains("unrelated.example.com"));

        // run again: nothing left to do
        let again = refresh_entry(&SystemRunner, d.path(), "dev", Some(&new), None)?;
        assert_eq!(again, Refresh::default());
        Ok(())
    }

    #[test]
    fn a_box_with_no_entry_gets_none_added_but_a_known_old_machine_is_still_forgotten() -> R {
        let d = tempfile::tempdir()?;
        known_hosts(d.path(), &["i-0aaaaaaaaaaaaaaaa", "i-0bbbbbbbbbbbbbbbb"])?;
        let new = aws_for("i-0bbbbbbbbbbbbbbbb");
        let r = refresh_entry(
            &SystemRunner,
            d.path(),
            "dev",
            Some(&new),
            Some("i-0aaaaaaaaaaaaaaaa"),
        )?;
        assert!(!r.rewritten);
        assert!(!d.path().join("ozbox/config").exists() && !d.path().join("config").exists());
        assert_eq!(r.forgotten, vec!["i-0aaaaaaaaaaaaaaaa".to_string()]);
        // the new machine's own key is never removed
        assert!(fs::read_to_string(d.path().join("known_hosts"))?.contains("i-0bbbbbbbbbbbbbbbb"));
        Ok(())
    }

    #[test]
    fn a_box_whose_machine_is_missing_is_finished_from_what_the_entry_says() -> R {
        // finishing an interrupted upgrade: the record has no machine yet, the old id comes from the entry
        let d = tempfile::tempdir()?;
        write_config(
            d.path(),
            "dev",
            &block("dev", &aws_for("i-0aaaaaaaaaaaaaaaa")),
            1,
        )?;
        known_hosts(d.path(), &["i-0aaaaaaaaaaaaaaaa"])?;
        let r = refresh_entry(
            &SystemRunner,
            d.path(),
            "dev",
            Some(&aws_for("i-0bbbbbbbbbbbbbbbb")),
            None,
        )?;
        assert!(r.rewritten);
        assert_eq!(r.forgotten.len(), 1);
        Ok(())
    }

    #[test]
    fn destroying_a_box_removes_only_its_entry_and_its_host_key() -> R {
        use ozbox_core::RecordingRunner;
        let d = tempfile::tempdir()?;
        let dir = d.path().join("ozbox");
        fs::create_dir_all(&dir)?;
        let one = upsert_block(
            "",
            &host_alias("keep"),
            "Host ozbox-keep\n    HostName i-0aaa\n",
        );
        let two = upsert_block(
            &one,
            &host_alias("gone"),
            "Host ozbox-gone\n    HostName i-0bbb\n",
        );
        fs::write(dir.join("config"), &two)?;
        fs::write(
            d.path().join("known_hosts"),
            "i-0aaa ssh-ed25519 AAAA\ni-0bbb ssh-ed25519 BBBB\n",
        )?;
        let r = RecordingRunner::new();
        let out = remove_entry(&r, d.path(), "gone")?;
        let left = fs::read_to_string(dir.join("config"))?;
        assert!(out.rewritten);
        assert!(
            left.contains("ozbox-keep") && !left.contains("ozbox-gone") && !left.contains("i-0bbb")
        );
        assert_eq!(out.forgotten, vec!["i-0bbb".to_string()]);
        let calls = r.calls();
        assert_eq!(calls.len(), 1);
        assert!(calls[0].args.iter().any(|a| a == "i-0bbb"));
        // a box with no entry is not an error and runs nothing
        let r2 = RecordingRunner::new();
        let none = remove_entry(&r2, d.path(), "never")?;
        assert!(!none.rewritten && none.forgotten.is_empty() && r2.calls().is_empty());
        Ok(())
    }

    #[test]
    fn the_ingress_block_is_the_same_route_as_another_host_and_account() -> R {
        let routes = [
            aws(),
            Route::Mesh {
                host: "dev".into(),
                user: "ozbox".into(),
            },
            Route::Cloudflare {
                domain: "example.com".into(),
            },
        ];
        for r in routes {
            let b = block("dev", &r);
            let i = ingress_block(&b, "dev");
            assert!(i.starts_with("Host ozbox-dev-ingress\n"));
            assert!(i.contains("    User ozbox-ingress\n"));
            assert!(!i.contains("    User ozbox\n"));
            // the same machine and route, line for line, apart from the alias, the account and the key
            let strip = |t: &str| {
                t.lines()
                    .filter(|l| {
                        let l = l.trim_start();
                        !(l.starts_with("User ")
                            || l.starts_with("Host ")
                            || l.starts_with("IdentityFile ")
                            || l.starts_with("IdentitiesOnly ")
                            || l.starts_with("ForwardAgent "))
                    })
                    .map(|l| {
                        l.replace(
                            "--instance-os-user ozbox-ingress ",
                            "--instance-os-user ozbox ",
                        )
                        .replace("ozbox_ingress_ed25519", "ozbox_ed25519")
                    })
                    .collect::<Vec<_>>()
            };
            assert_eq!(strip(&b), strip(&i));
            // on every route (the Cloudflare one included) the account's own key is the only one offered, and the agent is
            // never forwarded, in this block and in the box user's
            assert!(
                i.contains("    IdentityFile ~/.ssh/ozbox_ingress_ed25519\n"),
                "{i}"
            );
            assert!(i.contains("    IdentitiesOnly yes\n") && i.contains("    ForwardAgent no\n"));
            assert!(!i.contains("IdentityFile ~/.ssh/ozbox_ed25519"));
            assert!(b.contains("    ForwardAgent no\n"), "{b}");
        }
        // on AWS the key is pushed for the ingress account, not the box user
        let i = ingress_block(&block("dev", &aws()), "dev");
        assert!(i.contains("--instance-os-user ozbox-ingress --ssh-public-key file://$HOME/.ssh/ozbox_ingress_ed25519.pub"));
        assert!(!i.contains("--instance-os-user ozbox --ssh"));
        Ok(())
    }

    #[test]
    fn writing_refreshing_and_removing_a_box_handle_both_blocks() -> R {
        let d = tempfile::tempdir()?;
        write_config(d.path(), "dev", &block("dev", &aws()), 1)?;
        let file = d.path().join("ozbox/config");
        let text = fs::read_to_string(&file)?;
        assert!(text.contains("Host ozbox-dev\n") && text.contains("Host ozbox-dev-ingress\n"));
        // another box's blocks are untouched by either
        write_config(d.path(), "other", &block("other", &aws()), 2)?;
        let moved = Route::AwsSsm {
            instance: "i-0fedcba9876543210".into(),
            region: "us-east-1".into(),
            profile: None,
        };
        let r = refresh_entry(&SystemRunner, d.path(), "dev", Some(&moved), None)?;
        assert!(r.rewritten);
        let text = fs::read_to_string(&file)?;
        assert_eq!(text.matches("i-0fedcba9876543210").count(), 2);
        assert!(text.contains("Host ozbox-other-ingress"));
        remove_entry(&SystemRunner, d.path(), "dev")?;
        let text = fs::read_to_string(&file)?;
        assert!(!text.contains("ozbox-dev\n") && !text.contains("ozbox-dev-ingress"));
        assert!(text.contains("Host ozbox-other\n") && text.contains("Host ozbox-other-ingress"));
        Ok(())
    }
}
