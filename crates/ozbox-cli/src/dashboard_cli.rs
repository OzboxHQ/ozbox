//! `ozbox dashboard install <box>`: run the dashboard as a service on a box, with its tunnel. Plan, then apply
//! (ADR 0002): the plan is printed first, `--dry-run` stops there, and a change needs confirmation or `--yes`.
//!
//! The installer is sent to the box over its own SSH route (`ssh ozbox-<name>`, nothing new is opened) on standard
//! input. A token is part of that input too, never of a command line, so it appears in no process list on either side.

use std::io::{BufRead, IsTerminal, Write};

use std::sync::Arc;

use ozbox_core::{
    BoxName, CommandRunner, CommandSpec, ReleaseKind, ReleaseVerifier, SystemRunner,
    DEFAULT_RELEASE_REPO,
};
use serde_json::json;

use crate::cli::DashboardCommand;
use crate::messages::t;
use crate::run::CliError;
use crate::serve::auth::config::{AccessCfg, AuthConfig, AuthFile, ClientCfg};
use crate::tunnel::unit::{dashboard_unit, HOME_DIR};
use crate::tunnel::{public_host, CaddyCfg, Kind, TunnelFile, DEFAULT_PORT};

const SCRIPT: &str = include_str!("../../../infra/box/dashboard-setup.sh");
const EOF_MARK: &str = "__OZBOX_EOF__";

/// Where a program sent from this computer waits on the box: in the box user's own home on `/work` (`/work` itself is
/// root's), so no root is needed to receive it. The installer checks its sha256 again and removes it.
pub const UPLOAD_PATH: &str = "/work/home/ozbox/.ozbox-upload";
/// The biggest program accepted from a release.
const MAX_PROGRAM_BYTES: u64 = 200 * 1024 * 1024;

pub struct Install {
    pub name: BoxName,
    pub public_url: String,
    pub kind: Option<Kind>,
    pub binary_url: String,
    pub binary_sha256: String,
    /// Where on the box a program sent from this computer waits for the installer (see [`UPLOAD_PATH`]).
    pub binary_file: Option<String>,
    /// The program the box's image already carries (checked on the box against `binary_sha256`): nothing is downloaded.
    pub box_program: Option<String>,
    /// One plan line saying which program is used and where it comes from, when the person did not name an address.
    pub source_line: Option<String>,
    pub auth_toml: String,
    pub caddy: Option<CaddyCfg>,
    /// A single-use approval code for the tunnel-token change, for a box whose dashboard has a second factor (from
    /// `ozbox secrets approve --scope tunnel-token` on this computer). It goes in the script's body, never a command line.
    pub approval: Option<String>,
}

fn url_ok(u: &str) -> bool {
    u.starts_with("https://")
        && u.len() <= 1024
        && u.bytes().all(|b| {
            b.is_ascii_alphanumeric()
                || matches!(
                    b,
                    b'.' | b'_'
                        | b'~'
                        | b':'
                        | b'/'
                        | b'?'
                        | b'#'
                        | b'@'
                        | b'!'
                        | b'$'
                        | b'&'
                        | b'('
                        | b')'
                        | b'*'
                        | b'+'
                        | b','
                        | b';'
                        | b'='
                        | b'%'
                        | b'-'
                )
        })
}

impl Install {
    /// Check every input and build what the box will be told to do.
    pub fn new(
        name: BoxName,
        public_url: &str,
        tunnel: Option<&str>,
        binary_url: &str,
        binary_sha256: &str,
        auth_file: AuthFile,
        caddy: Option<CaddyCfg>,
    ) -> Result<Self, String> {
        let public_url = public_url.trim().trim_end_matches('/').to_string();
        public_host(&public_url).map_err(|k| t(k, &[]))?;
        let kind = match tunnel {
            Some(p) => Some(Kind::parse(p).ok_or_else(|| t("tunnel.bad_provider", &[]))?),
            None => None,
        };
        // An empty address means the program is sent from this computer ([`Install::with_binary_file`]).
        if !binary_url.is_empty() && !url_ok(binary_url) {
            return Err(t("dashboard.need_https_url", &[]));
        }
        if binary_sha256.len() != 64 || !binary_sha256.bytes().all(|b| b.is_ascii_hexdigit()) {
            return Err(t("dashboard.bad_sha", &[]));
        }
        // The sign-in settings are checked exactly as the server will check them.
        let mut file = auth_file;
        file.public_origin = public_url.clone();
        let cfg = AuthConfig::new(file)?;
        let auth_toml = toml::to_string_pretty(&cfg.file).map_err(|e| e.to_string())?;
        if auth_toml.lines().any(|l| l == EOF_MARK) {
            return Err(t("tunnel.caddy_bad", &[]));
        }
        if let Some(k) = kind {
            TunnelFile {
                provider: k.id().into(),
                public_url: public_url.clone(),
                caddy: caddy.clone().map(|mut c| {
                    c.key_file = format!("{HOME_DIR}/tunnel_ed25519");
                    c
                }),
            }
            .validate()
            .map_err(|k| t(k, &[]))?;
        }
        Ok(Self {
            name,
            public_url,
            kind,
            binary_url: binary_url.to_string(),
            binary_sha256: binary_sha256.to_ascii_lowercase(),
            binary_file: None,
            box_program: None,
            source_line: None,
            auth_toml,
            caddy,
            approval: None,
        })
    }

    /// The program is on the box already (sent from this computer) at `path`: the box does not download anything.
    pub fn with_binary_file(mut self, path: &str) -> Self {
        self.binary_file = Some(path.to_string());
        self
    }

    /// Use the program the box's image carries at `path`; nothing is downloaded or sent.
    pub fn with_box_program(mut self, path: &str) -> Self {
        self.box_program = Some(path.to_string());
        self
    }

    /// Say, in the plan, where the program comes from.
    pub fn with_source_line(mut self, line: String) -> Self {
        self.source_line = Some(line);
        self
    }

    fn key_file() -> String {
        format!("{HOME_DIR}/tunnel_ed25519")
    }

    fn tunnel_args(&self, token: bool) -> Vec<String> {
        let Some(kind) = self.kind else {
            return Vec::new();
        };
        let mut a = vec![
            kind.id().to_string(),
            "--public-url".to_string(),
            self.public_url.clone(),
        ];
        if token && kind.token_secret().is_some() {
            a.push("--token-stdin".into());
        }
        if let (Kind::Caddy, Some(c)) = (kind, &self.caddy) {
            a.extend([
                "--ssh-host".into(),
                c.host.clone(),
                "--ssh-user".into(),
                c.user.clone(),
                "--ssh-port".into(),
                c.ssh_port.to_string(),
                "--ssh-key".into(),
                Self::key_file(),
                "--remote-port".into(),
                c.remote_port.to_string(),
            ]);
        }
        a
    }

    /// The text sent to `bash -s` on the box: assignments, then the installer. Contains the token when there is one.
    pub fn script(&self, token: Option<&str>) -> Result<String, String> {
        let unit =
            dashboard_unit(&self.public_url, self.kind, DEFAULT_PORT).map_err(|k| t(k, &[]))?;
        if let Some(tk) = token {
            crate::secrets::check_value(tk).map_err(|e| e.to_string())?;
            if tk.contains('\'') {
                return Err(t("dashboard.bad_token", &[]));
            }
        }
        let quote = |s: &str| format!("'{s}'");
        let args = self
            .tunnel_args(token.is_some())
            .iter()
            .map(|a| quote(a))
            .collect::<Vec<_>>()
            .join(" ");
        let heredoc = |name: &str, body: &str| {
            format!(
                "{name}=$(cat <<'{EOF_MARK}'\n{}\n{EOF_MARK}\n)\n",
                body.trim_end()
            )
        };
        let mut out = String::from("set -euo pipefail\n");
        if self.binary_url.is_empty() && self.binary_file.is_none() && self.box_program.is_none() {
            return Err(t("dashboard.need_https_url", &[]));
        }
        out.push_str(&format!("BINARY_URL={}\n", quote(&self.binary_url)));
        out.push_str(&format!(
            "BOX_PROGRAM={}\n",
            quote(self.box_program.as_deref().unwrap_or(""))
        ));
        out.push_str(&format!(
            "BINARY_FILE={}\n",
            quote(self.binary_file.as_deref().unwrap_or(""))
        ));
        out.push_str(&format!("BINARY_SHA256={}\n", quote(&self.binary_sha256)));
        out.push_str(&format!("PUBLIC_URL={}\n", quote(&self.public_url)));
        out.push_str(&format!("TUNNEL_ARGS=({args})\n"));
        out.push_str(&format!("TUNNEL_TOKEN={}\n", quote(token.unwrap_or(""))));
        if let Some(code) = &self.approval {
            // only something shaped like a code (letters, digits, dashes) is ever written, so the quoting holds
            if !crate::secrets_approval::is_code_shape(code) {
                return Err(t("tunnel.bad_approval", &[]));
            }
        }
        out.push_str(&format!(
            "TUNNEL_APPROVAL={}\n",
            quote(self.approval.as_deref().unwrap_or(""))
        ));
        out.push_str(&format!(
            "TOOL={}\n",
            quote(match self.kind {
                Some(Kind::Cloudflare) => "cloudflared",
                Some(Kind::TailscaleFunnel | Kind::TailscaleServe) => "tailscale",
                Some(Kind::Ngrok) => "ngrok",
                _ => "",
            })
        ));
        let key_file = if self.kind == Some(Kind::Caddy) {
            Self::key_file()
        } else {
            String::new()
        };
        out.push_str(&format!("KEY_FILE={}\n", quote(&key_file)));
        out.push_str(&heredoc("UNIT_BODY", &unit));
        out.push_str(&heredoc("AUTH_TOML", &self.auth_toml));
        if out.matches(EOF_MARK).count() != 4 {
            return Err(t("tunnel.caddy_bad", &[]));
        }
        // The installer's own header comments are skipped; its commands follow the assignments.
        out.push_str(
            SCRIPT
                .split_once("set -euo pipefail\n")
                .map_or(SCRIPT, |(_, rest)| rest),
        );
        Ok(out)
    }

    pub fn plan(&self) -> Vec<String> {
        let mut p = vec![
            t(
                "dashboard.plan_head",
                &[("box", self.name.as_str()), ("address", &self.public_url)],
            ),
            match &self.source_line {
                Some(l) => l.clone(),
                None => t(
                    if self.binary_file.is_some() {
                        "dashboard.plan_binary_local"
                    } else {
                        "dashboard.plan_binary"
                    },
                    &[],
                ),
            },
            t("dashboard.plan_files", &[]),
        ];
        if self.kind.is_some_and(|k| k.token_secret().is_some()) {
            p.push(t("dashboard.plan_token", &[]));
        }
        if let Some(k) = self.kind {
            let tool = match k {
                Kind::Cloudflare => "cloudflared",
                Kind::Ngrok => "ngrok",
                Kind::TailscaleFunnel | Kind::TailscaleServe => "tailscale",
                Kind::Caddy => "",
            };
            if !tool.is_empty() && k != Kind::Cloudflare {
                p.push(t("dashboard.plan_tool", &[("tool", tool)]));
            }
        }
        let tunnel = self
            .kind
            .map(|k| format!(" with the {} tunnel", k.id()))
            .unwrap_or_default();
        p.push(t("dashboard.plan_start", &[("tunnel", &tunnel)]));
        p.push(t("dashboard.warn_down", &[("box", self.name.as_str())]));
        p
    }

    /// The command that puts a program on the box: it arrives on standard input, never as an argument.
    pub fn upload_command(&self, program: Vec<u8>) -> CommandSpec {
        CommandSpec::new("ssh")
            .args([
                "-o".to_string(),
                "BatchMode=yes".to_string(),
                crate::sshconfig::host_alias(self.name.as_str()),
                format!("umask 077 && cat > {UPLOAD_PATH}"),
            ])
            .stdin(program)
    }

    /// The sha256 of the sign-in settings exactly as the installer writes them on the box (`printf '%s\n'` of the text
    /// the heredoc carries, which drops trailing newlines). The root helper compares the staged file with it before it
    /// moves the dashboard to its own user, so a change the box user made in between is refused.
    pub fn auth_sha256(&self) -> String {
        sha256_hex(format!("{}\n", self.auth_toml.trim_end()).as_bytes())
    }

    /// One request to the box's root helper (`ozbox-admin-request`), over the same route.
    pub fn admin_command(&self, request: &str) -> CommandSpec {
        CommandSpec::new("ssh").args([
            "-o".to_string(),
            "BatchMode=yes".to_string(),
            crate::sshconfig::host_alias(self.name.as_str()),
            format!("/usr/local/bin/ozbox-admin-request {request}"),
        ])
    }

    /// Ask the box, over the same route, whether the dashboard stayed up (`sh`, so it is not taken for the installer's script).
    fn health_command(&self) -> CommandSpec {
        CommandSpec::new("ssh")
            .args([
                "-o".to_string(),
                "BatchMode=yes".to_string(),
                crate::sshconfig::host_alias(self.name.as_str()),
                "sh".to_string(),
                "-s".to_string(),
            ])
            .stdin(HEALTH_SCRIPT.as_bytes().to_vec())
    }

    pub fn command(&self, script: String) -> CommandSpec {
        CommandSpec::new("ssh")
            .args([
                "-o".to_string(),
                "BatchMode=yes".to_string(),
                crate::sshconfig::host_alias(self.name.as_str()),
                "bash".to_string(),
                "-s".to_string(),
            ])
            .stdin(script.into_bytes())
    }
}

pub fn run(
    cmd: &DashboardCommand,
    yes: bool,
    dry_run: bool,
    json_out: bool,
) -> Result<(), CliError> {
    run_with(
        cmd,
        yes,
        dry_run,
        json_out,
        &ozbox_core::SystemRunner,
        &mut std::io::stdin().lock(),
        std::io::stdin().is_terminal(),
    )
}

pub fn run_with(
    cmd: &DashboardCommand,
    yes: bool,
    dry_run: bool,
    json_out: bool,
    runner: &dyn CommandRunner,
    input: &mut dyn BufRead,
    tty: bool,
) -> Result<(), CliError> {
    let DashboardCommand::Install { release_repo, .. } = cmd;
    let repo = release_repo.as_deref().unwrap_or(DEFAULT_RELEASE_REPO);
    if !ozbox_core::release::is_repo_slug(repo) {
        return Err(CliError::Msg(t("dashboard.bad_repo", &[])));
    }
    let verifier = ReleaseVerifier::new(Arc::new(SystemRunner), repo);
    run_with_release(
        cmd,
        yes,
        dry_run,
        json_out,
        runner,
        &verifier,
        &VerifierAssets {
            verifier: &verifier,
        },
        input,
        tty,
    )
}

/// Where the program of a release comes from, as bytes. Separate so a test needs no network and no files.
pub trait AssetSource {
    /// The file `asset` of the release `version` of that kind (not yet trusted: the caller checks its sha256).
    fn fetch(&self, kind: ReleaseKind, version: &str, asset: &str) -> Result<Vec<u8>, String>;
}

/// The real source: the release's file, downloaded here with the person's own sign-in (so a private repository works: the
/// token stays on this computer and the box is sent only the checked program).
pub struct VerifierAssets<'a> {
    pub verifier: &'a ReleaseVerifier,
}

impl AssetSource for VerifierAssets<'_> {
    fn fetch(&self, kind: ReleaseKind, version: &str, asset: &str) -> Result<Vec<u8>, String> {
        let mut rnd = [0u8; 8];
        getrandom::getrandom(&mut rnd).map_err(|e| e.to_string())?;
        let dir = std::env::temp_dir().join(format!(
            "ozbox-program-{}",
            rnd.iter().map(|b| format!("{b:02x}")).collect::<String>()
        ));
        let mut builder = std::fs::DirBuilder::new();
        #[cfg(unix)]
        {
            use std::os::unix::fs::DirBuilderExt;
            builder.mode(0o700);
        }
        builder.create(&dir).map_err(|e| e.to_string())?;
        let dest = dir.join("program");
        let got = self
            .verifier
            .download_asset(kind, version, asset, &dest, MAX_PROGRAM_BYTES)
            .map_err(|v| v.detail)
            .and_then(|()| std::fs::read(&dest).map_err(|e| e.to_string()));
        let _ = std::fs::remove_dir_all(&dir);
        got
    }
}

fn sha256_hex(bytes: &[u8]) -> String {
    ring::digest::digest(&ring::digest::SHA256, bytes)
        .as_ref()
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}

/// Where the program the dashboard will run comes from. Each source is verified against a signed manifest first.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Source {
    /// The `ozbox` program the box's own image carries, found to match the image release's signed list: nothing is
    /// downloaded or sent.
    BoxImage,
    /// The image release's signed `ozbox-linux-<arch>` asset: downloaded here, checked, sent to the box.
    ImageRelease,
    /// A CLI release's signed asset: downloaded here, checked, sent to the box.
    CliRelease,
}

impl Source {
    pub fn id(self) -> &'static str {
        match self {
            Source::BoxImage => "box_image",
            Source::ImageRelease => "image_release",
            Source::CliRelease => "cli_release",
        }
    }
}

/// The program chosen: its source, the release it was verified against, its file name and the sha256 the box must see.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Chosen {
    pub source: Source,
    pub version: String,
    pub asset: String,
    pub sha256: String,
}

/// The program an Oz image installs, which `ozbox dashboard install` prefers.
pub const BOX_PROGRAM_PATH: &str = "/usr/local/bin/ozbox";

/// One fixed question to the box: which image release it is from (the whole record, read by the shared parser
/// [`ozbox_core::release::parse_image_release`], so a key added to the record never hides the version), its machine type,
/// and the hash of its `ozbox` program as it is now. It runs in a fresh `sh` with an empty environment and absolute paths,
/// as [`crate::serve::agent::IMAGE_AGENT_COMMAND`] does. The `sh` it starts is clean, but the command still travels through
/// the box user's own shell (its rc files are on /work), so the answer is a convenience, never a proof.
pub(crate) const PROBE_COMMAND: &str = "exec /usr/bin/env -i PATH=/usr/bin:/bin /bin/sh -c 'cat /etc/ozbox/image-release 2>/dev/null; echo arch=$(uname -m); echo sha=$(sha256sum /usr/local/bin/ozbox 2>/dev/null | cut -d\" \" -f1)'";

#[derive(Debug, Default, PartialEq, Eq)]
struct BoxFacts {
    image_release: Option<String>,
    machine: String,
    program_sha: Option<String>,
}

fn parse_probe(out: &str) -> BoxFacts {
    let mut f = BoxFacts {
        image_release: ozbox_core::release::parse_image_release(out).version,
        ..BoxFacts::default()
    };
    for l in out.lines() {
        if let Some(v) = l.strip_prefix("release=") {
            // the answer to the probe of a program from before the shared parser (`head -n1` of a one-line record)
            let v = v.trim();
            if f.image_release.is_none() && ozbox_core::release::is_release_version(v) {
                f.image_release = Some(v.to_string());
            }
        } else if let Some(v) = l.strip_prefix("arch=") {
            f.machine = v.trim().to_string();
        } else if let Some(v) = l.strip_prefix("sha=") {
            let v = v.trim().to_ascii_lowercase();
            if v.len() == 64 && v.bytes().all(|b| b.is_ascii_hexdigit()) {
                f.program_sha = Some(v);
            }
        }
    }
    f
}

fn probe_box(runner: &dyn CommandRunner, name: &BoxName) -> Result<BoxFacts, String> {
    let unreachable = || t("dashboard.reach_failed", &[("box", name.as_str())]);
    let out = runner
        .run(&CommandSpec::new("ssh").args([
            "-o".to_string(),
            "BatchMode=yes".to_string(),
            crate::sshconfig::host_alias(name.as_str()),
            PROBE_COMMAND.to_string(),
        ]))
        .map_err(|_| unreachable())?;
    if out.status != Some(0) {
        return Err(unreachable());
    }
    Ok(parse_probe(&out.stdout))
}

/// The marker the box's root helper carries when it checks a tunnel-token approval against the token (code, not a comment:
/// the helper's comments are stripped when it is installed).
pub(crate) const HELPER_BINDS_MARKER: &str = "bind-token-stdin";

/// One fixed question: does this box's root helper tie a tunnel-token approval to the token? The answer is a convenience for
/// the hint that follows a refusal, never a proof (it travels through the box user's shell, like the probe above): `None`
/// when the box could not say.
fn helper_binds_approval(runner: &dyn CommandRunner, name: &BoxName) -> Option<bool> {
    let out = runner
        .run(&CommandSpec::new("ssh").args([
            "-o".to_string(),
            "BatchMode=yes".to_string(),
            crate::sshconfig::host_alias(name.as_str()),
            format!("exec /usr/bin/env -i PATH=/usr/bin:/bin /bin/sh -c 'grep -c {HELPER_BINDS_MARKER} /usr/local/sbin/ozbox-admin.sh 2>/dev/null; true'"),
        ]))
        .ok()?;
    if out.status != Some(0) {
        return None;
    }
    match out.stdout.trim().lines().last()?.trim() {
        "0" => Some(false),
        n if n.parse::<u32>().is_ok() => Some(true),
        _ => None,
    }
}

fn unverified(version: &str, why: &str) -> String {
    t(
        "dashboard.binary_unverified",
        &[("version", version), ("why", why)],
    )
}

/// The image release's signed manifest, and what it lists for this machine. When the box's own program has the listed
/// hash, that program is used; otherwise the release's signed asset is.
fn image_choice(
    verifier: &ReleaseVerifier,
    version: &str,
    arch: ozbox_core::release::MachineArch,
    facts: &BoxFacts,
) -> Result<Chosen, String> {
    let tag = format!("image-v{version}");
    let manifest = verifier
        .signed_manifest(ReleaseKind::Image, version)
        .map_err(|v| unverified(&tag, &v.detail))?;
    let entry = ozbox_core::release::image_program(&manifest, version, arch)
        .map_err(|why| unverified(&tag, &why))?;
    let source = if facts.program_sha.as_deref() == Some(entry.sha256.as_str()) {
        Source::BoxImage
    } else {
        Source::ImageRelease
    };
    Ok(Chosen {
        source,
        version: version.to_string(),
        asset: entry.asset,
        sha256: entry.sha256,
    })
}

fn cli_choice(
    verifier: &ReleaseVerifier,
    version: &str,
    arch: ozbox_core::release::MachineArch,
) -> Result<Chosen, String> {
    let tag = format!("v{version}");
    let manifest = verifier
        .signed_manifest(ReleaseKind::Cli, version)
        .map_err(|v| unverified(&tag, &v.detail))?;
    let entry = ozbox_core::release::cli_program(&manifest, version, arch)
        .map_err(|why| unverified(&tag, &why))?;
    Ok(Chosen {
        source: Source::CliRelease,
        version: version.to_string(),
        asset: entry.asset,
        sha256: entry.sha256,
    })
}

/// The program to install when none was named, in this order, never an unverified one:
///
/// 1. the `ozbox` program the box's image carries, when its sha256 is the one the image release's signed manifest lists;
/// 2. that image release's signed asset (downloaded here, checked here, sent to the box, checked there);
/// 3. a CLI release of the same version, if one was published.
///
/// `release` is `2026.11.10-1`, `image-v0.3.0` or `v0.3.0`; by default it is the box's own image release. An
/// `image-v…` or `v…` argument limits the search to that kind of release.
fn choose_program(
    runner: &dyn CommandRunner,
    verifier: &ReleaseVerifier,
    name: &BoxName,
    release: Option<&str>,
) -> Result<Chosen, String> {
    let facts = probe_box(runner, name)?;
    let arch = ozbox_core::release::machine_arch(&facts.machine)
        .ok_or_else(|| t("dashboard.binary_arch", &[("arch", &facts.machine)]))?;
    let (kind, version) = match release {
        Some(r) => ozbox_core::release::parse_release_arg(r)
            .ok_or_else(|| t("dashboard.bad_release", &[("value", r)]))?,
        None => (
            None,
            facts
                .image_release
                .clone()
                .ok_or_else(|| t("dashboard.no_image_release", &[]))?,
        ),
    };
    let mut tried: Vec<String> = Vec::new();
    if kind != Some(ReleaseKind::Cli) {
        match image_choice(verifier, &version, arch, &facts) {
            Ok(c) => return Ok(c),
            Err(e) if kind == Some(ReleaseKind::Image) => return Err(e),
            Err(e) => tried.push(e),
        }
    }
    match cli_choice(verifier, &version, arch) {
        Ok(c) => Ok(c),
        Err(e) if tried.is_empty() => Err(e),
        Err(e) => {
            tried.push(e);
            Err(t(
                "dashboard.nothing_verified",
                &[("tried", &tried.join("\n  "))],
            ))
        }
    }
}

fn source_line(c: &Chosen) -> String {
    t(
        match c.source {
            Source::BoxImage => "dashboard.source_box_image",
            Source::ImageRelease => "dashboard.source_image_release",
            Source::CliRelease => "dashboard.source_cli_release",
        },
        &[
            ("version", &c.version),
            ("asset", &c.asset),
            ("sha", &c.sha256[..12]),
            ("path", BOX_PROGRAM_PATH),
        ],
    )
}

#[allow(clippy::too_many_arguments)]
pub fn run_with_release(
    cmd: &DashboardCommand,
    yes: bool,
    dry_run: bool,
    json_out: bool,
    runner: &dyn CommandRunner,
    verifier: &ReleaseVerifier,
    assets: &dyn AssetSource,
    input: &mut dyn BufRead,
    tty: bool,
) -> Result<(), CliError> {
    let DashboardCommand::Install {
        name,
        public_url,
        tunnel,
        binary_url,
        binary_sha256,
        release,
        release_repo: _,
        people,
        access_team,
        access_audience,
        token_stdin,
        ssh_host,
        ssh_user,
        ssh_port,
        remote_port,
        approval,
        approval_stdin,
    } = cmd;
    if let Some(code) = approval {
        if !crate::secrets_approval::is_code_shape(code) {
            return Err(CliError::Msg(t("tunnel.bad_approval", &[])));
        }
    }
    // Either the box downloads the program from an address given here, or (the default) it is the signed release of
    // this version: downloaded and checked on this computer, then sent to the box.
    let (binary_url, binary_sha256, chosen) = match (binary_url, binary_sha256) {
        (Some(u), Some(h)) => (u.clone(), h.clone(), None),
        (None, None) => {
            let c = choose_program(runner, verifier, name, release.as_deref())
                .map_err(CliError::Msg)?;
            (String::new(), c.sha256.clone(), Some(c))
        }
        _ => return Err(CliError::Msg(t("dashboard.binary_both", &[]))),
    };
    let users = people
        .iter()
        .map(|p| crate::auth_cli::parse_person(p))
        .collect::<Result<Vec<_>, _>>()
        .map_err(CliError::Msg)?;
    let auth = AuthFile {
        users,
        github: ClientCfg::default(),
        google: ClientCfg::default(),
        access: access_team.as_ref().map(|team| AccessCfg {
            team_domain: team.clone(),
            audience: access_audience.clone().unwrap_or_default(),
        }),
        ..Default::default()
    };
    let caddy = (tunnel.as_deref() == Some("caddy")).then(|| CaddyCfg {
        host: ssh_host.clone().unwrap_or_default(),
        user: ssh_user.clone().unwrap_or_default(),
        ssh_port: *ssh_port,
        key_file: String::new(),
        remote_port: *remote_port,
    });
    let install = Install::new(
        name.clone(),
        public_url,
        tunnel.as_deref(),
        &binary_url,
        &binary_sha256,
        auth,
        caddy,
    )
    .map_err(CliError::Msg)?;
    let install = match &chosen {
        Some(c) => {
            let i = install.with_source_line(source_line(c));
            if c.source == Source::BoxImage {
                i.with_box_program(BOX_PROGRAM_PATH)
            } else {
                i.with_binary_file(UPLOAD_PATH)
            }
        }
        None => install,
    };
    let mut install = Install {
        approval: approval
            .as_deref()
            .map(|c| crate::secrets_approval::canonical_code(c).unwrap_or_else(|| c.to_string())),
        ..install
    };
    let plan = install.plan();
    if json_out {
        println!(
            "{}",
            json!({
                "box": name.as_str(),
                "public_url": install.public_url,
                "tunnel": install.kind.map(Kind::id),
                "program_source": chosen.as_ref().map(|c| c.source.id()).unwrap_or("binary_url"),
                "program_release": chosen.as_ref().map(|c| c.version.clone()),
                "program_sha256": install.binary_sha256,
                "steps": plan[1..plan.len() - 1],
                "warning": plan[plan.len() - 1],
                "dry_run": dry_run,
            })
        );
    } else {
        for l in &plan {
            println!("{l}");
        }
    }
    if dry_run {
        if !json_out {
            println!("{}", t("dashboard.dry_run", &[]));
        }
        return Ok(());
    }
    // The token comes from standard input only after the plan has been shown, and before any confirmation prompt
    // reads a line, so a person who passes --token-stdin also passes --yes.
    let mut token = None;
    if *token_stdin {
        let mut line = String::new();
        input
            .read_line(&mut line)
            .map_err(|_| CliError::Msg(t("tunnel.token_unreadable", &[])))?;
        token = Some(line.trim().to_string());
        // the code may follow the token on its own line: it is then in no command line and no shell history
        if *approval_stdin {
            let mut code = String::new();
            input
                .read_line(&mut code)
                .map_err(|_| CliError::Msg(t("tunnel.token_unreadable", &[])))?;
            match crate::secrets_approval::canonical_code(&code) {
                Some(c) => install.approval = Some(c),
                None => return Err(CliError::Msg(t("tunnel.bad_approval", &[]))),
            }
        }
    }
    if !yes {
        if !tty || token.is_some() {
            return Err(CliError::Msg(t(
                "dashboard.refuse_no_tty",
                &[("box", name.as_str())],
            )));
        }
        print!("{}", t("dashboard.prompt", &[]));
        let _ = std::io::stdout().flush();
        let mut line = String::new();
        let _ = input.read_line(&mut line);
        if !matches!(line.trim().to_ascii_lowercase().as_str(), "y" | "yes") {
            println!("{}", t("dashboard.aborted", &[]));
            return Ok(());
        }
    }
    if let Some(c) = chosen.as_ref().filter(|c| c.source != Source::BoxImage) {
        let (version, asset, sha) = (&c.version, &c.asset, &c.sha256);
        let kind = if c.source == Source::CliRelease {
            ReleaseKind::Cli
        } else {
            ReleaseKind::Image
        };
        let program = assets
            .fetch(kind, version, asset)
            .map_err(|why| CliError::Msg(t("dashboard.download_failed", &[("why", &why)])))?;
        // What was downloaded must be what the signed manifest lists, before one byte leaves this computer.
        if sha256_hex(&program) != *sha {
            return Err(CliError::Msg(t("dashboard.hash_mismatch", &[])));
        }
        match runner.run(&install.upload_command(program)) {
            Ok(o) if o.status == Some(0) => {}
            _ => {
                return Err(CliError::Msg(t(
                    "dashboard.upload_failed",
                    &[("box", name.as_str())],
                )))
            }
        }
    }
    let script = install.script(token.as_deref()).map_err(CliError::Msg)?;
    match runner.run(&install.command(script)) {
        Ok(o) if o.status == Some(0) => {
            if !json_out {
                print!("{}", o.stdout);
            }
            // The box user's side only staged it. The root helper starts it as its own user (ADR 0023), checking first
            // that the staged sign-in settings are the ones sent from here, then destroys the copies the box user could
            // read. Success is reported only once the dashboard runs that way; it never runs as the box user.
            let already = o.stdout.contains("dashboard-setup: supervisor-present");
            let token_stored = o.stdout.contains("dashboard-setup: tunnel-token-stored");
            // On a box that already has a supervisor the settings are staged too, and the helper decides: it installs them
            // when the dashboard has none to read (after an upgrade), and keeps the ones it has otherwise.
            let moved = start_as_supervisor(runner, &install)?;
            let kept = matches!(moved, Moved::Kept(_));
            if !json_out {
                let (Moved::Started(m) | Moved::Kept(m)) = &moved;
                println!("{m}");
                println!(
                    "{}",
                    t(
                        if kept {
                            "dashboard.already_supervisor"
                        } else {
                            "dashboard.installed"
                        },
                        &[("box", name.as_str()), ("address", &install.public_url)]
                    )
                );
                if already && token_stored {
                    println!("{}", t("dashboard.token_stored", &[("box", name.as_str())]));
                }
            } else {
                println!(
                    "{}",
                    json!({ "installed": !kept, "box": name.as_str(), "runs_as": "ozbox-supervisor",
                        "settings_changed": !kept, "tunnel_token_stored": token_stored || (!kept && token.is_some()) })
                );
            }
            Ok(())
        }
        Ok(o) if o.status == Some(255) => Err(CliError::Msg(t(
            "dashboard.reach_failed",
            &[("box", name.as_str())],
        ))),
        Ok(o) => {
            // The installer's own words (it prints no secret); the SSH line for a refused connection is `255`.
            let said = o.stderr.trim().lines().last().unwrap_or("").to_string();
            let mut m = format!("{} {said}", t("dashboard.install_failed", &[]))
                .trim()
                .to_string();
            // The box wants an approval for the token change (or refused the one given): say how to get one here, on the
            // computer that made the box. Which kind of code works depends on the box's root helper, so it is asked.
            if said.to_ascii_lowercase().contains("approval") {
                let args = [
                    ("box", name.as_str()),
                    (
                        "provider",
                        install.kind.map(|k| k.id()).unwrap_or("cloudflare"),
                    ),
                ];
                m.push('\n');
                match helper_binds_approval(runner, name) {
                    Some(true) => m.push_str(&t("dashboard.need_approval", &args)),
                    Some(false) => m.push_str(&t("dashboard.need_approval_older", &args)),
                    None => {
                        m.push_str(&t("dashboard.need_approval", &args));
                        m.push(' ');
                        m.push_str(&t("dashboard.need_approval_unsure", &[]));
                    }
                }
                m.push(' ');
                m.push_str(&t("dashboard.need_approval_ingress", &args));
            }
            Err(CliError::Msg(m))
        }
        Err(_) => Err(CliError::Msg(t(
            "dashboard.reach_failed",
            &[("box", name.as_str())],
        ))),
    }
}

/// Ask the box's root helper to start the staged dashboard as its own user, then to destroy the box user's copies. An error
/// says what happened; in every case nothing runs as the box user (the helper starts no box-user copy of a staged one).
fn start_as_supervisor(runner: &dyn CommandRunner, install: &Install) -> Result<Moved, CliError> {
    let box_name = install.name.as_str();
    let ask = |request: &str| -> Result<String, CliError> {
        let o = runner
            .run(&install.admin_command(request))
            .map_err(|_| CliError::Msg(t("dashboard.reach_failed", &[("box", box_name)])))?;
        let mut lines = o.stdout.lines();
        let ok = lines.next() == Some("status=ok");
        let said: String = lines.collect::<Vec<_>>().join(" ");
        if ok {
            Ok(said)
        } else {
            Err(CliError::Msg(t(
                "dashboard.supervisor_failed",
                &[("box", box_name), ("why", said.trim())],
            )))
        }
    };
    let moved = ask(&format!(
        "ensure-supervisor expect {}",
        install.auth_sha256()
    ))?;
    // The dashboard already has sign-in settings of its own: the helper kept them (it cannot replace them on a request the box
    // user could have made) and changed nothing, so there is nothing to finish or check.
    if moved.contains("already has sign-in settings of its own") {
        return Ok(Moved::Kept(moved));
    }
    if !moved.contains("runs as ozbox-supervisor") {
        return Err(CliError::Msg(t(
            "dashboard.supervisor_failed",
            &[("box", box_name), ("why", moved.trim())],
        )));
    }
    // A helper from an earlier program says "runs" as soon as the process forks, so a dashboard that exits at once (settings
    // it cannot read) was reported as running. Ask the box, after the restart delay, whether it stayed up.
    let health = runner
        .run(&install.health_command())
        .map_err(|_| CliError::Msg(t("dashboard.reach_failed", &[("box", box_name)])))?;
    if !health.stdout.contains("dashboard-health: ok") {
        let state = health
            .stdout
            .lines()
            .find_map(|l| l.strip_prefix("dashboard-health: "))
            .unwrap_or("unknown")
            .trim()
            .to_string();
        return Err(CliError::Msg(t(
            "dashboard.not_running",
            &[("box", box_name), ("state", &state)],
        )));
    }
    let finished = ask("ensure-supervisor finish")?;
    Ok(Moved::Started(format!("{moved}\n{finished}")))
}

/// What the root helper did with the staged dashboard.
enum Moved {
    /// It runs as its own user with the settings sent from here.
    Started(String),
    /// It already had sign-in settings of its own and kept them.
    Kept(String),
}

/// Run on the box, after the helper: is the dashboard still up once its restart delay (5 s) has passed, and has it not been
/// restarted by systemd on its own?
const HEALTH_SCRIPT: &str = "sleep 8
s=$(systemctl is-active ozbox-dashboard.service 2>/dev/null || true)
n=$(systemctl show -p NRestarts --value ozbox-dashboard.service 2>/dev/null || echo 0)
if [ \"$s\" = active ] && [ \"${n:-0}\" = 0 ]; then echo 'dashboard-health: ok'; else echo \"dashboard-health: ${s:-unknown}, restarted ${n:-0} times\"; fi
";

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use crate::serve::auth::config::UserEntry;
    use ozbox_core::RecordingRunner;

    fn auth() -> AuthFile {
        AuthFile {
            users: vec![UserEntry {
                id: "owner".into(),
                ..Default::default()
            }],
            ..Default::default()
        }
    }

    fn install(tunnel: Option<&str>) -> Install {
        Install::new(
            BoxName::new("dash").unwrap(),
            "https://ozbox.example.com",
            tunnel,
            "https://downloads.example.com/ozbox-linux-amd64",
            &"ab".repeat(32),
            auth(),
            (tunnel == Some("caddy")).then(|| CaddyCfg {
                host: "vps.example.com".into(),
                user: "ozbox-tunnel".into(),
                ssh_port: 22,
                key_file: String::new(),
                remote_port: 7878,
            }),
        )
        .unwrap()
    }

    #[test]
    fn the_script_carries_the_unit_the_settings_and_the_installer_and_the_token_only_in_the_body() {
        let i = install(Some("cloudflare"));
        let s = i.script(Some("SENTINEL-TOKEN")).unwrap();
        assert!(s.contains("TUNNEL_TOKEN='SENTINEL-TOKEN'"));
        assert!(s.contains(
            "TUNNEL_ARGS=('cloudflare' '--public-url' 'https://ozbox.example.com' '--token-stdin')"
        ));
        assert!(s.contains("ExecStart=/work/home/ozbox/ozbox-dashboard/bin/ozbox serve --bind 127.0.0.1 --port 7878 --public-url https://ozbox.example.com --tunnel cloudflare"));
        assert!(s.contains("public_origin = \"https://ozbox.example.com\""));
        // the box user's side stages the service and never starts it: the root helper runs it as its own user
        assert!(!s.contains("systemctl --user enable") && !s.contains("systemctl --user restart"));
        assert!(s.contains("dashboard-setup: staged"));
        // no root anywhere: the box user has no sudo (ADR 0011)
        for line in SCRIPT
            .lines()
            .filter(|l| !l.trim_start().starts_with('#') && !l.contains("echo "))
        {
            for banned in [
                "sudo",
                "runuser",
                "chown",
                "-o ozbox",
                "/etc/systemd/system/ozbox-dashboard.service\"",
            ] {
                assert!(!line.contains(banned), "{banned} in {line}");
            }
        }
        // no box-user service manager is needed any more: nothing lingers as the box user
        assert!(!s.contains("loginctl enable-linger") && s.contains("WantedBy=default.target"));
        assert!(!s.contains("0.0.0.0"));
        // the installer's header, which names its own inputs, is not repeated
        assert_eq!(s.matches("set -euo pipefail").count(), 1);
        // no token: the flag is not sent either
        let n = i.script(None).unwrap();
        assert!(!n.contains("--token-stdin") && n.contains("TUNNEL_TOKEN=''"));
        // the plan and the command line never hold it
        assert!(!i.plan().join("\n").contains("SENTINEL"));
        let c = i.command(s);
        assert!(!c.args.join(" ").contains("SENTINEL"));
        assert_eq!(c.args.last().map(String::as_str), Some("-s"));
        assert!(
            !c.args.iter().any(|a| a == "sudo"),
            "the box user has no sudo"
        );
        assert_eq!(c.args[3], "bash");
        assert_eq!(c.args[2], "ozbox-dash");
    }

    #[test]
    fn caddy_gets_its_key_and_server_and_a_token_with_a_quote_is_refused() {
        let i = install(Some("caddy"));
        let s = i.script(None).unwrap();
        assert!(
            s.contains("'--ssh-host' 'vps.example.com'")
                && s.contains("'--ssh-key' '/work/home/ozbox/ozbox-dashboard/tunnel_ed25519'")
        );
        assert!(s.contains("KEY_FILE='/work/home/ozbox/ozbox-dashboard/tunnel_ed25519'"));
        assert!(install(Some("cloudflare")).script(Some("a'b")).is_err());
        assert!(install(Some("cloudflare")).script(Some("a b")).is_err());
    }

    #[test]
    fn every_input_is_checked_before_anything_is_sent() {
        let name = || BoxName::new("dash").unwrap();
        let mk = |url: &str, bin: &str, sha: &str, t: Option<&str>| {
            Install::new(name(), url, t, bin, sha, auth(), None)
        };
        let sha = "ab".repeat(32);
        assert!(mk(
            "https://ozbox.example.com",
            "https://x.example.com/o",
            &sha,
            None
        )
        .is_ok());
        assert!(mk(
            "http://ozbox.example.com",
            "https://x.example.com/o",
            &sha,
            None
        )
        .is_err());
        assert!(mk(
            "https://ozbox.example.com",
            "http://x.example.com/o",
            &sha,
            None
        )
        .is_err());
        assert!(mk(
            "https://ozbox.example.com",
            "https://x.example.com/o'; id",
            &sha,
            None
        )
        .is_err());
        assert!(mk(
            "https://ozbox.example.com",
            "https://x.example.com/o",
            "short",
            None
        )
        .is_err());
        assert!(mk(
            "https://ozbox.example.com",
            "https://x.example.com/o",
            &sha,
            Some("nope")
        )
        .is_err());
        assert!(
            mk(
                "https://ozbox.example.com",
                "https://x.example.com/o",
                &sha,
                Some("caddy")
            )
            .is_err(),
            "caddy needs a server"
        );
    }

    #[test]
    fn a_dry_run_sends_nothing_and_a_yes_sends_the_script_on_standard_input() {
        let cmd = |tok: bool| DashboardCommand::Install {
            name: BoxName::new("dash").unwrap(),
            public_url: "https://ozbox.example.com".into(),
            tunnel: Some("cloudflare".into()),
            binary_url: Some("https://downloads.example.com/ozbox".into()),
            binary_sha256: Some("ab".repeat(32)),
            release: None,
            release_repo: None,
            people: vec!["owner".into()],
            access_team: None,
            access_audience: None,
            token_stdin: tok,
            ssh_host: None,
            ssh_user: None,
            ssh_port: 22,
            remote_port: 7878,
            approval: None,
            approval_stdin: false,
        };
        let r = RecordingRunner::new();
        run_with(
            &cmd(false),
            true,
            true,
            false,
            &r,
            &mut std::io::empty(),
            false,
        )
        .unwrap();
        assert!(r.calls().is_empty());
        // without a terminal and without --yes: refused
        assert!(run_with(
            &cmd(false),
            false,
            false,
            false,
            &r,
            &mut std::io::empty(),
            false
        )
        .is_err());
        assert!(r.calls().is_empty());
        let mut stdin = std::io::Cursor::new(b"SENTINEL-TOKEN\n".to_vec());
        queue_installed(&r);
        run_with(&cmd(true), true, false, false, &r, &mut stdin, false).unwrap();
        let calls = r.calls();
        // the installer, then the root helper starting it as its own user, the box asked whether it stayed up, and the finish
        assert_eq!(calls.len(), 4);
        assert_eq!(calls[0].program, "ssh");
        assert!(calls[1]
            .args
            .last()
            .unwrap()
            .starts_with("/usr/local/bin/ozbox-admin-request ensure-supervisor expect "));
        assert!(calls[3]
            .args
            .last()
            .unwrap()
            .ends_with("ensure-supervisor finish"));
        assert!(calls[1..]
            .iter()
            .all(|c| !serde_json::to_string(c).unwrap().contains("SENTINEL")));
        let body = String::from_utf8(calls[0].stdin.clone().unwrap()).unwrap();
        assert!(body.contains("TUNNEL_TOKEN='SENTINEL-TOKEN'"));
        assert!(!calls[0].args.join(" ").contains("SENTINEL"));
        // the token is also kept out of the serialized command
        assert!(!serde_json::to_string(&calls[0])
            .unwrap()
            .contains("SENTINEL"));
    }

    fn release_cmd(url: Option<&str>, sha: Option<&str>) -> DashboardCommand {
        cmd_with(url, sha, None)
    }

    fn cmd_with(url: Option<&str>, sha: Option<&str>, release: Option<&str>) -> DashboardCommand {
        DashboardCommand::Install {
            name: BoxName::new("dash").unwrap(),
            public_url: "https://ozbox.example.com".into(),
            tunnel: None,
            binary_url: url.map(String::from),
            binary_sha256: sha.map(String::from),
            release: release.map(String::from),
            release_repo: None,
            people: vec!["owner".into()],
            access_team: None,
            access_audience: None,
            token_stdin: false,
            ssh_host: None,
            ssh_user: None,
            ssh_port: 22,
            remote_port: 7878,
            approval: None,
            approval_stdin: false,
        }
    }

    fn ok_out(stdout: &str) -> ozbox_core::Output {
        ozbox_core::Output {
            status: Some(0),
            stdout: stdout.into(),
            stderr: String::new(),
        }
    }

    /// The installer's answer, then the root helper's two (it started the dashboard as its own user, then finished).
    fn queue_installed(r: &RecordingRunner) {
        r.reply(ok_out("installed\ndashboard-setup: staged"));
        r.reply(ok_out(
            "status=ok\nozbox-supervisor-setup: the dashboard runs as ozbox-supervisor (port 7878)",
        ));
        r.reply(ok_out("dashboard-health: ok"));
        r.reply(ok_out(
            "status=ok\nozbox-supervisor-setup: the old dashboard state is destroyed",
        ));
    }

    /// The installer's script: the call whose standard input is the script (the root helper's requests come after it).
    fn installer_call(r: &RecordingRunner) -> CommandSpec {
        r.calls()
            .into_iter()
            .rev()
            .find(|c| c.args.iter().any(|a| a == "bash"))
            .unwrap()
    }

    fn curl_ok(body: &str) -> ozbox_core::Output {
        ok_out(&format!("{body}\n200"))
    }

    /// Queue what verifying one signed manifest asks of the tools: `gh auth token` (not signed in), the manifest, its
    /// signature and certificate, `cosign version` and the verification (`verify_status` 0 = verified).
    fn queue_manifest(r: &Arc<RecordingRunner>, manifest: &str, verify_status: i32) {
        r.reply(ozbox_core::Output {
            status: Some(1),
            ..Default::default()
        });
        r.reply(curl_ok(manifest));
        r.reply(curl_ok("sig"));
        r.reply(curl_ok("pem"));
        r.reply(ok_out("GitVersion:    v2.4.1"));
        r.reply(ozbox_core::Output {
            status: Some(verify_status),
            ..Default::default()
        });
    }

    fn verifier(r: &Arc<RecordingRunner>) -> ReleaseVerifier {
        ReleaseVerifier::with_env(r.clone(), DEFAULT_RELEASE_REPO, |_| None)
    }

    const PROGRAM: &[u8] = b"a program, as the release built it";
    const ARM: &[u8] = b"the arm program";
    const RELEASE: &str = "2026.11.10-1";

    /// What the box answers to the probe: its image release, machine type and the hash of the program it carries.
    fn probe(release: Option<&str>, uname: &str, program: Option<&[u8]>) -> String {
        format!(
            "release={}\narch={uname}\nsha={}\n",
            release.unwrap_or(""),
            program.map(sha256_hex).unwrap_or_default()
        )
    }

    /// An image release's signed manifest: the hash of the `ozbox` program per machine type.
    fn image_manifest(version: &str) -> String {
        format!(
            r#"{{"version":"{version}","images":[],"ozbox":{{"amd64":"{}","arm64":"{}"}}}}"#,
            sha256_hex(PROGRAM),
            sha256_hex(ARM)
        )
    }

    fn cli_manifest() -> String {
        format!(
            r#"{{"version":"0.1.0","binaries":[
      {{"arch":"x86_64","asset":"ozbox-linux-x86_64","sha256":"{}"}},
      {{"arch":"aarch64","asset":"ozbox-linux-aarch64","sha256":"{}"}}]}}"#,
            sha256_hex(PROGRAM),
            sha256_hex(ARM)
        )
    }

    /// Serves bytes by (kind, asset name), and remembers what was asked for.
    struct FakeAssets {
        files: Vec<(String, Vec<u8>)>,
        asked: std::sync::Mutex<Vec<(ReleaseKind, String)>>,
    }

    impl FakeAssets {
        fn ok() -> Self {
            Self {
                files: vec![
                    ("ozbox-linux-x86_64".into(), PROGRAM.to_vec()),
                    ("ozbox-linux-aarch64".into(), ARM.to_vec()),
                    ("ozbox-linux-amd64".into(), PROGRAM.to_vec()),
                    ("ozbox-linux-arm64".into(), ARM.to_vec()),
                ],
                asked: Default::default(),
            }
        }
        fn with(name: &str, bytes: &[u8]) -> Self {
            Self {
                files: vec![(name.into(), bytes.to_vec())],
                asked: Default::default(),
            }
        }
        fn asked(&self) -> Vec<(ReleaseKind, String)> {
            self.asked.lock().unwrap().clone()
        }
    }

    impl AssetSource for FakeAssets {
        fn fetch(&self, kind: ReleaseKind, _version: &str, asset: &str) -> Result<Vec<u8>, String> {
            self.asked.lock().unwrap().push((kind, asset.to_string()));
            self.files
                .iter()
                .find(|(n, _)| n == asset)
                .map(|(_, b)| b.clone())
                .ok_or_else(|| "not found".to_string())
        }
    }

    fn install_with(
        r: &Arc<RecordingRunner>,
        cmd: &DashboardCommand,
        assets: &FakeAssets,
    ) -> Result<(), CliError> {
        run_with_release(
            cmd,
            true,
            false,
            false,
            r.as_ref(),
            &verifier(r),
            assets,
            &mut std::io::empty(),
            false,
        )
    }

    fn script_of(r: &RecordingRunner) -> String {
        String::from_utf8(installer_call(r).stdin.clone().unwrap()).unwrap()
    }

    #[test]
    fn a_box_that_carries_the_listed_program_uses_it_and_nothing_is_downloaded_or_sent() {
        let r = Arc::new(RecordingRunner::new());
        r.reply(ok_out(&probe(Some(RELEASE), "x86_64", Some(PROGRAM))));
        queue_manifest(&r, &image_manifest(RELEASE), 0);
        queue_installed(&r);
        let assets = FakeAssets::ok();
        install_with(&r, &release_cmd(None, None), &assets).unwrap();
        assert!(assets.asked().is_empty(), "no download");
        let calls = r.calls();
        // the probe, the verification tools, then only the installer: no upload of a program
        assert!(!calls.iter().any(|c| c
            .args
            .iter()
            .any(|a| a.contains("cat >") && a.contains(UPLOAD_PATH))));
        let script = script_of(&r);
        assert!(
            script.contains("BOX_PROGRAM='/usr/local/bin/ozbox'"),
            "{script}"
        );
        assert!(script.contains("BINARY_FILE=''") && script.contains("BINARY_URL=''"));
        assert!(script.contains(&format!("BINARY_SHA256='{}'", sha256_hex(PROGRAM))));
        // the manifest asked for was the box's own image release, by its image tag
        assert!(calls.iter().any(|c| c
            .args
            .iter()
            .any(|a| a.ends_with(&format!("image-v{RELEASE}/ozbox-image-manifest.json")))));
    }

    #[test]
    fn the_choice_says_which_source_it_used() {
        let r = Arc::new(RecordingRunner::new());
        r.reply(ok_out(&probe(Some(RELEASE), "x86_64", Some(PROGRAM))));
        queue_manifest(&r, &image_manifest(RELEASE), 0);
        let c = choose_program(
            r.as_ref(),
            &verifier(&r),
            &BoxName::new("dash").unwrap(),
            None,
        )
        .unwrap();
        assert_eq!(
            (c.source, c.version.as_str(), c.asset.as_str()),
            (Source::BoxImage, RELEASE, "ozbox-linux-amd64")
        );
        let line = source_line(&c);
        assert!(
            line.contains("already has")
                && line.contains(RELEASE)
                && line.contains("nothing is downloaded"),
            "{line}"
        );
        let line = source_line(&Chosen {
            source: Source::ImageRelease,
            ..c.clone()
        });
        assert!(
            line.contains("image release") && line.contains("ozbox-linux-amd64"),
            "{line}"
        );
        let line = source_line(&Chosen {
            source: Source::CliRelease,
            ..c
        });
        assert!(line.contains("CLI release"), "{line}");
        // and the installer's plan carries that line
        let plan = install(None)
            .with_source_line("  SOURCE-LINE".into())
            .plan();
        assert!(plan.iter().any(|l| l == "  SOURCE-LINE"));
    }

    #[test]
    fn a_program_that_is_not_the_listed_one_is_replaced_by_the_signed_asset_for_either_machine_type(
    ) {
        for (uname, asset, bytes) in [
            ("x86_64", "ozbox-linux-amd64", PROGRAM),
            ("aarch64", "ozbox-linux-arm64", ARM),
        ] {
            let r = Arc::new(RecordingRunner::new());
            // the box's own program is some other build
            r.reply(ok_out(&probe(
                Some(RELEASE),
                uname,
                Some(b"some other build"),
            )));
            queue_manifest(&r, &image_manifest(RELEASE), 0);
            r.reply(ok_out("")); // the upload
            queue_installed(&r);
            let assets = FakeAssets::ok();
            install_with(&r, &release_cmd(None, None), &assets).unwrap();
            assert_eq!(assets.asked(), [(ReleaseKind::Image, asset.to_string())]);
            let calls = r.calls();
            // the program reaches the box on standard input of its own command, never in an argument
            let upload = &calls[calls.len() - 5];
            assert!(upload
                .args
                .iter()
                .any(|a| a == &format!("umask 077 && cat > {UPLOAD_PATH}")));
            assert_eq!(upload.stdin.clone().unwrap(), bytes.to_vec());
            assert!(upload.args.iter().all(|a| a.len() < 200));
            // the installer is told to use that file and the hash it must have: the box checks again
            let script = script_of(&r);
            assert!(
                script.contains(&format!("BINARY_FILE='{UPLOAD_PATH}'")),
                "{script}"
            );
            assert!(script.contains("BOX_PROGRAM=''"));
            assert!(script.contains(&format!("BINARY_SHA256='{}'", sha256_hex(bytes))));
        }
    }

    #[test]
    fn a_box_that_has_no_program_still_gets_the_signed_asset() {
        let r = Arc::new(RecordingRunner::new());
        r.reply(ok_out(&probe(Some(RELEASE), "x86_64", None)));
        queue_manifest(&r, &image_manifest(RELEASE), 0);
        r.reply(ok_out(""));
        queue_installed(&r);
        let assets = FakeAssets::ok();
        install_with(&r, &release_cmd(None, None), &assets).unwrap();
        assert_eq!(assets.asked().len(), 1);
    }

    #[test]
    fn a_downloaded_program_that_is_not_the_signed_one_never_leaves_this_computer() {
        let r = Arc::new(RecordingRunner::new());
        r.reply(ok_out(&probe(Some(RELEASE), "x86_64", Some(b"other"))));
        queue_manifest(&r, &image_manifest(RELEASE), 0);
        let e = install_with(
            &r,
            &release_cmd(None, None),
            &FakeAssets::with("ozbox-linux-amd64", b"something else"),
        )
        .unwrap_err();
        assert!(e.to_string().contains("does not match"), "{e}");
        assert!(
            r.calls().iter().all(|c| c.stdin.is_none()),
            "nothing was sent"
        );
        // a download that fails says why and sends nothing either
        let r = Arc::new(RecordingRunner::new());
        r.reply(ok_out(&probe(Some(RELEASE), "x86_64", Some(b"other"))));
        queue_manifest(&r, &image_manifest(RELEASE), 0);
        let e = install_with(
            &r,
            &release_cmd(None, None),
            &FakeAssets::with("another", b"x"),
        )
        .unwrap_err();
        assert!(e.to_string().contains("could not be downloaded"), "{e}");
        assert!(r.calls().iter().all(|c| c.stdin.is_none()));
    }

    #[test]
    fn an_unverified_image_release_falls_back_to_a_cli_release_and_says_what_it_tried() {
        // the image manifest's signature fails, the CLI release of that version is signed
        let r = Arc::new(RecordingRunner::new());
        r.reply(ok_out(&probe(Some("0.1.0"), "x86_64", Some(PROGRAM))));
        queue_manifest(&r, &image_manifest("0.1.0"), 1);
        queue_manifest(&r, &cli_manifest(), 0);
        r.reply(ok_out(""));
        queue_installed(&r);
        let assets = FakeAssets::ok();
        install_with(&r, &release_cmd(None, None), &assets).unwrap();
        assert_eq!(
            assets.asked(),
            [(ReleaseKind::Cli, "ozbox-linux-x86_64".to_string())]
        );
        // neither verifies: both reasons are shown, nothing is sent
        let r = Arc::new(RecordingRunner::new());
        r.reply(ok_out(&probe(Some("0.1.0"), "x86_64", Some(PROGRAM))));
        queue_manifest(&r, &image_manifest("0.1.0"), 1);
        queue_manifest(&r, &cli_manifest(), 1);
        let e = install_with(&r, &release_cmd(None, None), &FakeAssets::ok())
            .unwrap_err()
            .to_string();
        assert!(
            e.contains("Tried, in order") && e.contains("image-v0.1.0") && e.contains("v0.1.0"),
            "{e}"
        );
        assert!(r.calls().iter().all(|c| c.stdin.is_none()));
    }

    #[test]
    fn an_explicit_kind_does_not_fall_back_to_the_other() {
        // image-v…: a failing image manifest is the answer; the CLI release is never asked about
        let r = Arc::new(RecordingRunner::new());
        r.reply(ok_out(&probe(Some(RELEASE), "x86_64", Some(PROGRAM))));
        queue_manifest(&r, &image_manifest(RELEASE), 1);
        let e = install_with(
            &r,
            &cmd_with(None, None, Some(&format!("image-v{RELEASE}"))),
            &FakeAssets::ok(),
        )
        .unwrap_err()
        .to_string();
        assert!(e.contains("did not verify") && !e.contains("Tried"), "{e}");
        assert!(!r.calls().iter().any(|c| c
            .args
            .iter()
            .any(|a| a.contains("/v0.1.0/") || a.contains("tags/v"))));
        // cli-v…: only the CLI release is looked at, even though the box is from an image release
        let r = Arc::new(RecordingRunner::new());
        r.reply(ok_out(&probe(Some(RELEASE), "x86_64", Some(PROGRAM))));
        queue_manifest(&r, &cli_manifest(), 0);
        r.reply(ok_out(""));
        queue_installed(&r);
        let assets = FakeAssets::ok();
        install_with(&r, &cmd_with(None, None, Some("v0.1.0")), &assets).unwrap();
        assert!(!r
            .calls()
            .iter()
            .any(|c| c.args.iter().any(|a| a.contains("image-v"))));
        assert_eq!(assets.asked()[0].0, ReleaseKind::Cli);
    }

    #[test]
    fn every_way_of_naming_a_release_works_and_the_default_is_the_boxs_own() {
        for arg in [
            RELEASE.to_string(),
            format!("image-v{RELEASE}"),
            // (`v<version>` names the program's own release now, and is tested with the CLI release cases below)
        ] {
            let r = Arc::new(RecordingRunner::new());
            r.reply(ok_out(&probe(Some("2026.01.01"), "x86_64", Some(PROGRAM))));
            queue_manifest(&r, &image_manifest(RELEASE), 0);
            let c = choose_program(
                r.as_ref(),
                &verifier(&r),
                &BoxName::new("dash").unwrap(),
                Some(&arg),
            )
            .unwrap();
            assert_eq!(
                (c.source, c.version.as_str()),
                (Source::BoxImage, RELEASE),
                "{arg}"
            );
        }
        // no argument: the box's own release, not this program's version
        let r = Arc::new(RecordingRunner::new());
        r.reply(ok_out(&probe(Some("2026.01.01"), "x86_64", Some(PROGRAM))));
        queue_manifest(&r, &image_manifest("2026.01.01"), 0);
        let c = choose_program(
            r.as_ref(),
            &verifier(&r),
            &BoxName::new("dash").unwrap(),
            None,
        )
        .unwrap();
        assert_eq!(c.version, "2026.01.01");
        assert_ne!(c.version, env!("CARGO_PKG_VERSION"));
        // a box that does not say, and no argument: a plain instruction, and nothing is downloaded
        let r = Arc::new(RecordingRunner::new());
        r.reply(ok_out(&probe(None, "x86_64", Some(PROGRAM))));
        let e = choose_program(
            r.as_ref(),
            &verifier(&r),
            &BoxName::new("dash").unwrap(),
            None,
        )
        .unwrap_err();
        assert!(e.contains("--release") && e.contains("--binary-url"), "{e}");
        assert_eq!(r.calls().len(), 1);
        // something that is not a release
        let r = Arc::new(RecordingRunner::new());
        r.reply(ok_out(&probe(Some(RELEASE), "x86_64", None)));
        let e = choose_program(
            r.as_ref(),
            &verifier(&r),
            &BoxName::new("dash").unwrap(),
            Some("latest"),
        )
        .unwrap_err();
        assert!(e.contains("latest") && e.contains("image-v0.3.0"), "{e}");
    }

    #[test]
    fn a_manifest_for_another_release_or_a_bad_hash_or_an_unknown_machine_is_refused() {
        let go = |uname: &str, manifest: String, status: i32| {
            let r = Arc::new(RecordingRunner::new());
            r.reply(ok_out(&probe(Some(RELEASE), uname, Some(PROGRAM))));
            if uname != "riscv64" {
                queue_manifest(&r, &manifest, status);
            }
            let e = install_with(
                &r,
                &cmd_with(None, None, Some(&format!("image-v{RELEASE}"))),
                &FakeAssets::ok(),
            )
            .unwrap_err()
            .to_string();
            assert!(r.calls().iter().all(|c| c.stdin.is_none()), "{e}");
            e
        };
        assert!(go("x86_64", image_manifest("2025.01.01"), 0).contains("not 2026.11.10-1"));
        assert!(go(
            "x86_64",
            format!(r#"{{"version":"{RELEASE}","ozbox":{{"amd64":"nothex"}}}}"#),
            0
        )
        .contains("not a sha256"));
        assert!(go(
            "x86_64",
            format!(r#"{{"version":"{RELEASE}","ozbox":{{}}}}"#),
            0
        )
        .contains("lists no ozbox program"));
        assert!(go("riscv64", String::new(), 0).contains("riscv64"));
    }

    #[test]
    fn the_probe_is_read_strictly() {
        let f = parse_probe("release=2026.11.10-1\narch=aarch64\nsha=ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789\n");
        assert_eq!(f.image_release.as_deref(), Some("2026.11.10-1"));
        assert_eq!(f.machine, "aarch64");
        assert_eq!(
            f.program_sha.as_deref(),
            Some("abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789")
        );
        // an empty answer, a malformed release and a short hash are "not known", never guessed
        let f = parse_probe("release=latest; rm -rf /\narch=x86_64\nsha=1234\n");
        assert_eq!((f.image_release, f.program_sha), (None, None));
        assert_eq!(parse_probe("release=\narch=\nsha=\n"), BoxFacts::default());
    }

    /// The record an image writes today (`key=value` lines, `image_version=` first, then hashes and the browser's
    /// version), as the box answers the probe. `head -n1` of it was `image_version=…`, which is not a version, so the
    /// installer said the box had no record at all.
    #[test]
    fn the_probe_reads_the_record_every_image_writes() {
        let sha = "a".repeat(64);
        let b = "b".repeat(64);
        let answer = format!(
            "image_version=0.1.1-alpha.0\nozboxd_sha256={b}\nozbox_sha256={b}\nsource_commit=339e501\nchrome_version=142.0.1-1\nchrome_deb_sha256={b}\narch=x86_64\nsha={sha}\n"
        );
        let f = parse_probe(&answer);
        assert_eq!(f.image_release.as_deref(), Some("0.1.1-alpha.0"));
        // the measured hash (`sha=`), never the one the record claims (`ozbox_sha256=`)
        assert_eq!(f.program_sha.as_deref(), Some(sha.as_str()));
        assert_eq!(f.machine, "x86_64");
        // the first images' one-line record
        assert_eq!(
            parse_probe("2026.11.10-1\narch=x86_64\n")
                .image_release
                .as_deref(),
            Some("2026.11.10-1")
        );
        // no record: none, never a guess
        assert_eq!(parse_probe("arch=x86_64\nsha=\n").image_release, None);
        // the whole file, read outside the login shell
        assert!(PROBE_COMMAND.contains("cat /etc/ozbox/image-release"));
        assert!(!PROBE_COMMAND.contains("head -n1"));
        assert!(PROBE_COMMAND.starts_with("exec /usr/bin/env -i "));
    }

    #[test]
    fn a_release_repository_must_look_like_owner_and_name() {
        let r = RecordingRunner::new();
        let mut cmd = release_cmd(None, None);
        let DashboardCommand::Install { release_repo, .. } = &mut cmd;
        *release_repo = Some("not a repo".into());
        let e = run_with(&cmd, true, true, false, &r, &mut std::io::empty(), false).unwrap_err();
        assert!(e.to_string().contains("owner/name"), "{e}");
        assert!(r.calls().is_empty());
    }

    #[test]
    fn an_address_given_by_hand_is_still_downloaded_by_the_box() {
        let r = Arc::new(RecordingRunner::new());
        queue_installed(&r);
        install_with(
            &r,
            &release_cmd(
                Some("https://downloads.example.com/ozbox"),
                Some(&"ab".repeat(32)),
            ),
            &FakeAssets::ok(),
        )
        .unwrap();
        let calls = r.calls();
        assert_eq!(calls.len(), 4, "no probe, no upload, no download here");
        let script = String::from_utf8(calls[0].stdin.clone().unwrap()).unwrap();
        assert!(script.contains("BINARY_URL='https://downloads.example.com/ozbox'"));
        assert!(script.contains("BINARY_FILE=''") && script.contains("BOX_PROGRAM=''"));
    }

    fn by_hand() -> DashboardCommand {
        release_cmd(
            Some("https://downloads.example.com/ozbox"),
            Some(&"ab".repeat(32)),
        )
    }

    /// A security review (2026-11-11): `ozbox dashboard install` ran the dashboard as the box user until a reboot moved it,
    /// so every agent could read its sign-in state and keys meanwhile. The installer now only stages it; success is
    /// reported only once the root helper runs it as its own user, and the request names the sha256 of the sign-in
    /// settings sent from here, which the helper checks against the staged file.
    #[test]
    fn install_succeeds_only_once_the_dashboard_runs_as_its_own_user() {
        let r = Arc::new(RecordingRunner::new());
        queue_installed(&r);
        install_with(&r, &by_hand(), &FakeAssets::ok()).unwrap();
        let script = script_of(&r);
        // the installer never starts a service of the box user's
        assert!(
            !script.contains("systemctl --user enable")
                && !script.contains("systemctl --user restart")
        );
        let calls = r.calls();
        let expect = calls[1].args.last().unwrap();
        let auth = script
            .split("AUTH_TOML=$(cat <<'__OZBOX_EOF__'\n")
            .nth(1)
            .and_then(|r| r.split("\n__OZBOX_EOF__").next())
            .unwrap();
        let sha = sha256_hex(format!("{auth}\n").as_bytes());
        assert_eq!(
            expect,
            &format!("/usr/local/bin/ozbox-admin-request ensure-supervisor expect {sha}")
        );

        // the helper refused (a changed sign-in file, say): an error, never a success, and no finish is asked for
        let r = Arc::new(RecordingRunner::new());
        r.reply(ok_out("dashboard-setup: staged"));
        r.reply(ok_out("status=failed\nozbox-supervisor-setup: the staged sign-in settings are not the ones your computer sent"));
        let e = install_with(&r, &by_hand(), &FakeAssets::ok())
            .unwrap_err()
            .to_string();
        assert!(
            e.contains("Nothing runs as the box user")
                && e.contains("not the ones your computer sent"),
            "{e}"
        );
        assert_eq!(r.calls().len(), 2);
        // a helper that says ok without saying the dashboard runs as its own user is not a success either
        let r = Arc::new(RecordingRunner::new());
        r.reply(ok_out("dashboard-setup: staged"));
        r.reply(ok_out(
            "status=ok\nozbox-supervisor-setup: no dashboard is installed on this box",
        ));
        assert!(install_with(&r, &by_hand(), &FakeAssets::ok()).is_err());

        // a box whose dashboard already has sign-in settings of its own keeps them, and that is said: the helper is asked,
        // and answers that it changed nothing, so there is nothing to finish
        let r = Arc::new(RecordingRunner::new());
        r.reply(ok_out("dashboard-setup: supervisor-present"));
        r.reply(ok_out("status=ok\nozbox-supervisor-setup: the dashboard on this box already has sign-in settings of its own, so the ones sent from your computer were not applied"));
        install_with(&r, &by_hand(), &FakeAssets::ok()).unwrap();
        assert_eq!(r.calls().len(), 2);
    }

    /// Found on a real box (2026-11-15): after an upgrade the supervisor's folder (kept on /work) had no sign-in settings, the
    /// installer said "supervisor-present" and stopped, and the dashboard crash-looped. On a box with a supervisor the staged
    /// settings are now handed to the root helper with their sha256, exactly as on any other box.
    #[test]
    fn on_a_box_with_a_supervisor_the_settings_are_handed_to_the_root_helper() {
        let r = Arc::new(RecordingRunner::new());
        r.reply(ok_out("dashboard-setup: supervisor-present"));
        r.reply(ok_out(
            "status=ok\nozbox-supervisor-setup: the dashboard runs as ozbox-supervisor (port 7878)",
        ));
        r.reply(ok_out("dashboard-health: ok"));
        r.reply(ok_out("status=ok\nozbox-supervisor-setup: done"));
        install_with(&r, &by_hand(), &FakeAssets::ok()).unwrap();
        let calls = r.calls();
        assert_eq!(calls.len(), 4);
        assert!(calls[1]
            .args
            .last()
            .unwrap()
            .starts_with("/usr/local/bin/ozbox-admin-request ensure-supervisor expect "));
        assert!(calls[3]
            .args
            .last()
            .unwrap()
            .ends_with("ensure-supervisor finish"));
    }

    /// The same real box: the helper said "ok" while the service died and restarted. Whatever the helper says, the box is
    /// asked whether the dashboard stayed up, and a dashboard that did not is an error that names what to do.
    #[test]
    fn a_dashboard_that_does_not_stay_up_is_an_error_not_a_success() {
        let r = Arc::new(RecordingRunner::new());
        r.reply(ok_out("dashboard-setup: staged"));
        r.reply(ok_out(
            "status=ok\nozbox-supervisor-setup: the dashboard runs as ozbox-supervisor (port 7878)",
        ));
        r.reply(ok_out("dashboard-health: activating, restarted 3 times"));
        let e = install_with(&r, &by_hand(), &FakeAssets::ok())
            .unwrap_err()
            .to_string();
        assert!(
            e.contains("not staying up")
                && e.contains("restarted 3 times")
                && e.contains("reinstall-ozboxd"),
            "{e}"
        );
        // no finish: the old copies are kept while the dashboard is not running
        assert_eq!(r.calls().len(), 3);
    }

    /// Found on a real box (2026-11-12): once the dashboard ran as its own user, running the installer again with a new
    /// token skipped the token, and nothing else could set it on a box with a second factor.
    #[test]
    fn on_a_box_whose_dashboard_runs_as_its_own_user_a_new_token_is_still_handed_over_with_the_approval(
    ) {
        let s = include_str!("../../../infra/box/dashboard-setup.sh");
        let branch = s
            .split("if [ -e /etc/systemd/system/ozbox-dashboard.service ]; then")
            .nth(1)
            .unwrap()
            .split("\nfi\n")
            .next()
            .unwrap();
        // the hand-over goes through the root helper (the image's own `ozbox` program may be older than the flag), before the
        // early exit, with the code on standard input and the token in a private file
        let hand_over = branch.find("replace-tunnel-token").unwrap();
        assert!(
            hand_over < branch.find("exit 0").unwrap(),
            "before the early exit"
        );
        assert!(!branch.contains("/usr/local/bin/ozbox tunnel setup"));
        assert!(branch.contains("--approval-stdin"));
        assert!(branch.contains("/usr/local/bin/ozbox-admin-request"));
        // the code is in no environment of the box and no argument of the new request program
        assert!(!s.contains("OZBOX_TUNNEL_APPROVAL"));
        assert!(!branch.contains("OZBOX_TUNNEL_APPROVAL"));
        // the first install passes it on standard input to the sent program, after the token
        assert!(s.contains("tunnel setup \"${TUNNEL_ARGS[@]}\" --approval-stdin"));
    }

    #[test]
    fn an_approval_code_goes_in_the_scripts_body_only_when_it_is_shaped_like_one() {
        let mut i = install(Some("cloudflare"));
        assert!(i
            .script(Some("SENTINEL-TOKEN-0123456789"))
            .unwrap()
            .contains("TUNNEL_APPROVAL=''"));
        i.approval = Some("ABCD-EFGH-JKMN-PQRS".into());
        let body = i.script(Some("SENTINEL-TOKEN-0123456789")).unwrap();
        assert!(body.contains("TUNNEL_APPROVAL='ABCD-EFGH-JKMN-PQRS'"));
        // it is never an argument of the command that reaches the box
        assert!(!i.command(body).args.iter().any(|a| a.contains("ABCD-EFGH")));
        i.approval = Some("x'; touch /tmp/p; '".into());
        assert!(i.script(Some("SENTINEL-TOKEN-0123456789")).is_err());
    }

    #[test]
    fn a_box_that_wants_an_approval_is_answered_with_how_to_get_one_here() {
        let r = Arc::new(RecordingRunner::new());
        r.reply(ozbox_core::Output {
            status: Some(1),
            stdout: String::new(),
            stderr: "error: the box's admin helper did not take the tunnel token: this change needs a fresh approval \
                     from the dashboard (your passkey or authenticator code): ask for one there and run the command \
                     again with --approval CODE"
                .into(),
        });
        let e = install_with(&r, &by_hand(), &FakeAssets::ok())
            .unwrap_err()
            .to_string();
        assert!(
            e.contains("ozbox secrets approve --box dash --scope tunnel-token --project"),
            "{e}"
        );
        // a box made before the ingress account cannot make the code: the hint says how to get past that, in a sentence
        assert!(
            e.contains("ozbox upgrade dash") && e.contains("ingress account"),
            "{e}"
        );
    }

    #[test]
    fn a_code_that_is_not_shaped_like_one_is_refused_before_anything_is_sent() {
        let r = Arc::new(RecordingRunner::new());
        let mut cmd = by_hand();
        let DashboardCommand::Install { approval, .. } = &mut cmd;
        *approval = Some("not-a-code".into());
        assert!(install_with(&r, &cmd, &FakeAssets::ok()).is_err());
        assert!(r.calls().is_empty());
    }

    #[test]
    fn a_url_without_a_hash_or_the_reverse_is_refused() {
        let r = Arc::new(RecordingRunner::new());
        for cmd in [
            release_cmd(Some("https://downloads.example.com/ozbox"), None),
            release_cmd(None, Some(&"ab".repeat(32))),
        ] {
            assert!(run_with_release(
                &cmd,
                true,
                true,
                false,
                r.as_ref(),
                &verifier(&r),
                &FakeAssets::ok(),
                &mut std::io::empty(),
                false
            )
            .is_err());
        }
        assert!(r.calls().is_empty());
    }

    #[test]
    fn the_setup_script_can_use_the_boxs_own_program_and_checks_its_hash_there() {
        let s = include_str!("../../../infra/box/dashboard-setup.sh");
        let branch = s.split("elif [ -n \"${BOX_PROGRAM:-}\" ]").nth(1).unwrap();
        let branch = branch
            .split("elif [ -n \"${BINARY_FILE:-}\" ]")
            .next()
            .unwrap();
        assert!(branch.contains("sha256sum --check --strict") && branch.contains("$BOX_PROGRAM"));
        assert!(
            !branch.contains("curl"),
            "nothing is downloaded on this path"
        );
        let i = install(None).with_box_program(BOX_PROGRAM_PATH);
        assert!(i
            .script(None)
            .unwrap()
            .contains("BOX_PROGRAM='/usr/local/bin/ozbox'"));
    }

    #[test]
    fn the_warning_about_upgrades_is_in_the_plan_and_every_message_key_exists() {
        let p = install(None).plan().join("\n");
        assert!(p.contains("takes the dashboard down"));
        let keys = crate::messages::keys();
        for k in [
            "dashboard.warn_down",
            "dashboard.bad_release",
            "dashboard.no_image_release",
            "dashboard.nothing_verified",
            "dashboard.source_box_image",
            "dashboard.source_image_release",
            "dashboard.source_cli_release",
            "dashboard.plan_head",
            "dashboard.installed",
            "tunnel.saved",
            "tunnel.code_funnel_is_on",
            "tunnel.next",
        ] {
            assert!(keys.contains(&k), "{k}");
        }
        for c in crate::tunnel::KNOWN_CODES {
            assert!(keys.contains(&format!("tunnel.code_{c}").as_str()), "{c}");
        }
    }
}
