//! Checking that a machine image is one this project's image workflow built and signed.
//!
//! The image workflow publishes, for every release, a manifest (`ozbox-image-manifest.json`: the version and the image
//! id built in each region) and a keyless Sigstore signature over it (`.sig`, `.pem`), as assets of the release
//! `image-v<version>`. A signature made that way proves WHICH workflow produced the file, so verifying it needs the
//! workflow's identity, not a key somebody has to keep: the certificate must name this repository's image workflow and
//! the GitHub Actions issuer.
//!
//! The check is: fetch the three files over https, run `cosign verify-blob` with that identity, then require the image
//! id to be in the verified manifest for the region it is used in (and the manifest to be for the release the image
//! says it is). Anything short of all of that is `verified: false` with the reason; nothing here ever says verified on a
//! guess. The tools are the system's `curl` and `cosign`, run as argv arrays through the [`CommandRunner`] (ADR 0008).

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use crate::upgrade_kind::{manifest_image_arch, upgrade_record, UpgradeRecord};
use crate::{CommandRunner, CommandSpec, Error};

/// The repository whose image workflow is trusted by default.
pub const DEFAULT_RELEASE_REPO: &str = "OzboxHQ/ozbox";

/// The most a manifest, a signature or GitHub's description of a release may be. A program is not limited by this: it is
/// downloaded by `download_asset` with the limit its caller names (the `ozbox` program is about 21 MB).
pub const MANIFEST_MAX_BYTES: u64 = 5_000_000;
const MANIFEST_MAX_BYTES_ARG: &str = "5000000";

/// How long one `cosign verify-blob` may take (its own default is three minutes), so a caller's deadline holds.
const COSIGN_TIMEOUT: &str = "30s";

const OIDC_ISSUER: &str = "https://token.actions.githubusercontent.com";
/// A failed check is remembered briefly (a flaky download should not make every dashboard poll run curl and cosign);
/// a successful one is remembered for the life of the process, because what it checked cannot change.
const FAILURE_TTL: Duration = Duration::from_secs(120);

/// Which signed release a check is about. Each has its own tag, manifest and workflow, and a signature made by one
/// workflow never vouches for another's files.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReleaseKind {
    /// A machine image: tag `image-v<version>`, built and signed by `image.yml`.
    Image,
    /// The `ozbox` program: tag `v<version>`, built and signed by `cli-release.yml`. The same version number names the
    /// image release of the same product version (`image-v<version>`).
    Cli,
}

impl ReleaseKind {
    /// The release tag's prefix: the tag is this followed by the version.
    pub fn tag_prefix(self) -> &'static str {
        match self {
            ReleaseKind::Image => "image-v",
            ReleaseKind::Cli => "v",
        }
    }

    fn manifest(self) -> &'static str {
        match self {
            ReleaseKind::Image => "ozbox-image-manifest.json",
            ReleaseKind::Cli => "ozbox-cli-manifest.json",
        }
    }

    fn workflow(self) -> &'static str {
        match self {
            ReleaseKind::Image => "image.yml",
            ReleaseKind::Cli => "cli-release.yml",
        }
    }
}

/// What a check found, in words a person reads.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Verdict {
    pub verified: bool,
    pub detail: String,
    /// `true` only when the answer is final about THIS image: its release's signature verified and the signed manifest
    /// does not list the image (or is for another release), or the release (or its manifest or signature) is not
    /// published at all (HTTP 404: a release whose publish step never ran, or a private repository). A download or signature failure is never definitive: it says
    /// nothing about the image, and a caller choosing among images must stop rather than fall back to an older one.
    pub definitive: bool,
}

impl Verdict {
    fn no(detail: impl Into<String>) -> Self {
        Self {
            verified: false,
            detail: detail.into(),
            definitive: false,
        }
    }

    fn refused(detail: impl Into<String>) -> Self {
        Self {
            verified: false,
            detail: detail.into(),
            definitive: true,
        }
    }
}

/// Is `repo` an `owner/name` GitHub slug? Used in an https path and a regular expression, so it is strict.
pub fn is_repo_slug(repo: &str) -> bool {
    let ok = |s: &str| {
        !s.is_empty()
            && s != "."
            && s != ".."
            && s.len() <= 100
            && s.chars()
                .all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.'))
    };
    repo.split_once('/')
        .is_some_and(|(o, n)| ok(o) && ok(n) && !n.contains('/'))
}

/// Is `v` a release version like `2026.11.09` or `0.1.0-rc.1`? The same shape the image workflow accepts.
pub fn is_release_version(v: &str) -> bool {
    let (core, pre) = match v.split_once('-') {
        Some((c, p)) => (c, Some(p)),
        None => (v, None),
    };
    let parts: Vec<&str> = core.split('.').collect();
    (2..=3).contains(&parts.len())
        && parts
            .iter()
            .all(|p| !p.is_empty() && p.chars().all(|c| c.is_ascii_digit()))
        && pre.is_none_or(|p| {
            !p.is_empty()
                && p.chars()
                    .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '.')
        })
}

/// Where an Oz image records which release it is (written by the image build, root-owned, world readable).
pub const IMAGE_RELEASE_PATH: &str = "/etc/ozbox/image-release";

/// What an image's release record says (`/etc/ozbox/image-release`). The image build writes `key=value` lines
/// (`image_version=`, `ozboxd_sha256=`, `ozbox_sha256=`, `source_commit=`, `chrome_version=`, `chrome_deb_sha256=`, `disk_generation=`, and
/// whatever a later image adds); the very first images wrote the bare version on one line. Every reader on the laptop (the
/// dashboard installer, `ozbox upgrade`) goes through [`parse_image_release`], so a new key never hides the version again.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ImageReleaseRecord {
    /// The release version, only when it reads as one (`0.1.1-alpha.0`, `2026.11.10-1`).
    pub version: Option<String>,
    /// The `ozbox` program's sha256 the image build recorded (not a measurement of the file now on the box).
    pub ozbox_sha256: Option<String>,
    /// The box daemon's sha256 the image build recorded.
    pub ozboxd_sha256: Option<String>,
    /// The disk generation the image build recorded (ADR 0038): what an image needs a new system disk for. `None` for
    /// every image built before the field existed, which means "replace". This is the box's own word and is never the
    /// gate: the kind decision reads the signed manifest.
    pub disk_generation: Option<String>,
    /// Any line looked like a record line: the machine came from an Oz image. This is what the machine's own text says: a
    /// stray version-shaped line printed by the box user's shell reads the same, so it is a convenience, never a proof.
    pub present: bool,
}

/// Read the text of an image release record. Lines that are not part of the record (anything a shell printed around
/// it, unknown keys) are ignored; an `image_version` that does not read as a version is not reported as one.
pub fn parse_image_release(text: &str) -> ImageReleaseRecord {
    let mut r = ImageReleaseRecord::default();
    let hex = |v: &str| {
        let v = v.trim().to_ascii_lowercase();
        (v.len() == 64 && v.bytes().all(|b| b.is_ascii_hexdigit())).then_some(v)
    };
    let mut bare = Vec::new();
    for line in text.lines() {
        let line = line.trim();
        match line.split_once('=') {
            Some(("image_version", v)) => {
                r.present = true;
                let v = v.trim();
                if is_release_version(v) {
                    r.version = Some(v.to_string());
                }
            }
            Some(("ozbox_sha256", v)) => {
                r.present = true;
                r.ozbox_sha256 = hex(v);
            }
            Some(("ozboxd_sha256", v)) => {
                r.present = true;
                r.ozboxd_sha256 = hex(v);
            }
            Some(("disk_generation", v)) => {
                r.present = true;
                r.disk_generation = hex(v);
            }
            Some(_) => {}
            None if is_release_version(line) => bare.push(line.to_string()),
            None => {}
        }
    }
    // the first images' one-line record: only when nothing else said the version, and only one such line
    if r.version.is_none() && bare.len() == 1 {
        r.present = true;
        r.version = bare.pop();
    }
    r
}

/// A machine type as `uname -m` prints it, in the two spellings the releases use: the image release names its programs
/// `ozbox-linux-amd64|arm64`, the CLI release `ozbox-linux-x86_64|aarch64`.
pub fn machine_arch(uname: &str) -> Option<MachineArch> {
    match uname.trim() {
        "x86_64" | "amd64" => Some(MachineArch {
            image: "amd64",
            cli: "x86_64",
        }),
        "aarch64" | "arm64" => Some(MachineArch {
            image: "arm64",
            cli: "aarch64",
        }),
        _ => None,
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MachineArch {
    pub image: &'static str,
    pub cli: &'static str,
}

/// The `ozbox` program a signed release lists for one machine type: its file name in the release and its sha256.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProgramEntry {
    pub asset: String,
    pub sha256: String,
}

fn sha_ok(s: &str) -> bool {
    s.len() == 64 && s.bytes().all(|b| b.is_ascii_hexdigit())
}

/// The program an image release's signed manifest lists (`ozbox: {amd64: sha, arm64: sha}`). Only a name and a hash are
/// taken from the manifest, never an address. Pure, tested on fixture JSON.
pub fn image_program(
    manifest_json: &str,
    release: &str,
    arch: MachineArch,
) -> std::result::Result<ProgramEntry, String> {
    let v: serde_json::Value = serde_json::from_str(manifest_json)
        .map_err(|_| "the signed manifest could not be read".to_string())?;
    match v.get("version").and_then(|x| x.as_str()) {
        Some(f) if f == release => {}
        Some(f) => {
            return Err(format!(
                "the signed manifest is for release {f}, not {release}"
            ))
        }
        None => return Err("the signed manifest names no release".into()),
    }
    let sha = v
        .get("ozbox")
        .and_then(|o| o.get(arch.image))
        .and_then(|x| x.as_str())
        .ok_or_else(|| {
            format!(
                "the image release lists no ozbox program for {}",
                arch.image
            )
        })?;
    if !sha_ok(sha) {
        return Err("the signed manifest's program hash is not a sha256".into());
    }
    Ok(ProgramEntry {
        asset: format!("ozbox-linux-{}", arch.image),
        sha256: sha.to_ascii_lowercase(),
    })
}

/// The program a CLI release's signed manifest lists (`binaries: [{arch, asset, sha256}]`).
pub fn cli_program(
    manifest_json: &str,
    release: &str,
    arch: MachineArch,
) -> std::result::Result<ProgramEntry, String> {
    let v: serde_json::Value = serde_json::from_str(manifest_json)
        .map_err(|_| "the signed manifest could not be read".to_string())?;
    if v["version"].as_str() != Some(release) {
        return Err("the signed manifest is for another release".into());
    }
    let wanted = format!("ozbox-linux-{}", arch.cli);
    let entry = v["binaries"]
        .as_array()
        .into_iter()
        .flatten()
        .find(|b| {
            b["arch"].as_str() == Some(arch.cli) && b["asset"].as_str() == Some(wanted.as_str())
        })
        .ok_or_else(|| format!("the CLI release lists no program for {}", arch.cli))?;
    let sha = entry["sha256"].as_str().unwrap_or_default();
    if !sha_ok(sha) {
        return Err("the signed manifest's program hash is not a sha256".into());
    }
    Ok(ProgramEntry {
        asset: wanted,
        sha256: sha.to_ascii_lowercase(),
    })
}

/// What a person typed for a release: `2026.11.10-1`, `image-v2026.11.10-1`, `v0.1.0` (the program's release; `cli-v0.1.0` is still read). The kind
/// is `None` when only a version was given. `None` overall if it is not a release at all.
pub fn parse_release_arg(arg: &str) -> Option<(Option<ReleaseKind>, String)> {
    let a = arg.trim();
    // `cli-v1.2.3` is the tag this project used before the single version scheme; it is still read, as the same kind.
    let (kind, rest) = if let Some(r) = a.strip_prefix(ReleaseKind::Image.tag_prefix()) {
        (Some(ReleaseKind::Image), r)
    } else if let Some(r) = a.strip_prefix("cli-v") {
        (Some(ReleaseKind::Cli), r)
    } else if let Some(r) = a.strip_prefix(ReleaseKind::Cli.tag_prefix()) {
        (Some(ReleaseKind::Cli), r)
    } else {
        (None, a)
    };
    is_release_version(rest).then(|| (kind, rest.to_string()))
}

/// Whether this program and a machine image belong to the same product version.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Compat {
    /// Same major and minor version (the patch may differ: a patch release never breaks).
    Compatible,
    /// The image is from a newer minor version than this program: upgrade the program.
    ProgramOlder,
    /// The image is from an older minor version than this program: use an image of this version.
    ImageOlder,
    /// The image carries a date version, from before the single version scheme: it cannot be compared.
    Legacy,
    /// One of the two is not a version this can read.
    Unknown,
}

fn major_minor(v: &str) -> Option<(u64, u64)> {
    let core = v.trim_start_matches('v').split(['-', '+']).next()?;
    let mut p = core.split('.');
    let major = p.next()?.parse().ok()?;
    let minor = p.next()?.parse().ok()?;
    Some((major, minor))
}

/// One version for the program, the box daemon and the image, `MAJOR.MINOR.PATCH`. Before 1.0 a minor release may break
/// anything and a patch never does, so a program and an image must share the major and minor version; the patch is free.
pub fn compat(program: &str, image: &str) -> Compat {
    let (Some(p), Some(i)) = (major_minor(program), major_minor(image)) else {
        return Compat::Unknown;
    };
    if i.0 >= 2000 {
        return Compat::Legacy;
    }
    match i.cmp(&p) {
        std::cmp::Ordering::Equal => Compat::Compatible,
        std::cmp::Ordering::Greater => Compat::ProgramOlder,
        std::cmp::Ordering::Less => Compat::ImageOlder,
    }
}

/// The certificate identity a release signature must carry: this repository's workflow for that kind of release, run
/// from the main branch or a release tag. A regular expression, with the repository's dots and dashes escaped.
pub fn identity_regexp(repo: &str, kind: ReleaseKind) -> String {
    let escaped: String = repo
        .chars()
        .flat_map(|c| match c {
            '.' => vec!['\\', '.'],
            c => vec![c],
        })
        .collect();
    let workflow = kind.workflow().replace('.', "\\.");
    let tag = kind.tag_prefix();
    format!(
        "^https://github\\.com/{escaped}/\\.github/workflows/{workflow}@refs/(heads/main|tags/{tag}[0-9a-z.-]+)$"
    )
}

/// What a signed manifest says about one image.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Listing {
    /// The manifest is for this release and lists the image for the region.
    Listed,
    /// The manifest is for this release and does NOT list the image for the region: a final answer about the image.
    NotListed(String),
    /// The manifest cannot answer: unreadable, naming no release, or for another release (an old manifest put where a new one
    /// belongs, say). Says nothing about the image, so a caller must stop rather than try an older one.
    Unusable(String),
}

/// What `manifest_json` says about `image_id` in `region`, for `release`. Pure, tested on fixture JSON.
pub fn manifest_listing(
    manifest_json: &str,
    release: &str,
    region: &str,
    image_id: &str,
) -> Listing {
    let Ok(v) = serde_json::from_str::<serde_json::Value>(manifest_json) else {
        return Listing::Unusable("the signed manifest could not be read".into());
    };
    match v.get("version").and_then(|x| x.as_str()) {
        Some(found) if found == release => {}
        Some(found) => {
            return Listing::Unusable(format!(
                "the signed manifest is for release {found}, not {release}"
            ))
        }
        None => return Listing::Unusable("the signed manifest names no release".into()),
    }
    let listed = v
        .get("images")
        .and_then(|i| i.as_array())
        .into_iter()
        .flatten()
        .filter_map(|i| i.get("amis").and_then(|a| a.as_object()))
        .any(|amis| amis.get(region).and_then(|a| a.as_str()) == Some(image_id));
    if listed {
        Listing::Listed
    } else {
        Listing::NotListed(format!(
            "image {image_id} is not in the signed manifest of release {release} for {region}"
        ))
    }
}

/// Is `image_id` in `manifest_json` for `region`, and is the manifest for `release`? Pure, tested on fixture JSON.
pub fn manifest_lists(
    manifest_json: &str,
    release: &str,
    region: &str,
    image_id: &str,
) -> std::result::Result<(), String> {
    match manifest_listing(manifest_json, release, region, image_id) {
        Listing::Listed => Ok(()),
        Listing::NotListed(why) | Listing::Unusable(why) => Err(why),
    }
}

/// Whether a verified manifest says its release is a pre-release: the signed `prerelease` field is true, or its signed
/// `version` carries a pre-release part. Only read from a manifest whose signature was checked.
pub fn manifest_prerelease(manifest_json: &str) -> Option<bool> {
    let v: serde_json::Value = serde_json::from_str(manifest_json).ok()?;
    // the signed field says so, OR the signed version carries a pre-release part (defence in depth: a field that says
    // "stable" cannot make a `-beta` version one)
    let by_version = v.get("version")?.as_str().map(|s| s.contains('-'))?;
    let by_field = matches!(v.get("prerelease"), Some(serde_json::Value::Bool(true)));
    Some(by_field || by_version)
}

/// The first-boot hash an image release's manifest records: `first_boot` (see `crate::infra`), or the same value under
/// `upgrade.disk_parts.first_boot` where a later manifest keeps it. `None` when the manifest records none (every release
/// before the field) or the value is not a SHA-256. Pure, tested on fixture JSON; only read from a manifest whose signature
/// was checked.
pub fn manifest_first_boot(manifest_json: &str) -> Option<String> {
    let v: serde_json::Value = serde_json::from_str(manifest_json).ok()?;
    let found = [&v["first_boot"], &v["upgrade"]["disk_parts"]["first_boot"]]
        .into_iter()
        .find_map(|x| x.as_str())
        .map(str::to_ascii_lowercase)
        .filter(|h| crate::infra::is_sha256(h));
    found
}

/// Why a download failed, so the person can fix the right thing.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Fetch {
    /// `curl` itself is missing.
    NoCurl,
    /// 404: the release or file is not there, or (GitHub answers the same) the repository is private and we are anonymous.
    NotFound,
    /// 401: a token was sent and refused.
    BadToken,
    /// 403: no access, or the rate limit is used up.
    Forbidden,
    /// 429.
    RateLimited,
    /// No usable answer: curl failed (its exit code is kept) or GitHub answered another status (kept).
    Network(NetDetail),
}

/// What is known about a download that failed without a clear answer.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
struct NetDetail {
    curl: Option<i32>,
    http: Option<u16>,
}

impl NetDetail {
    fn curl(code: Option<i32>) -> Fetch {
        Fetch::Network(NetDetail {
            curl: code,
            http: None,
        })
    }

    fn http(code: u16) -> Fetch {
        Fetch::Network(NetDetail {
            curl: None,
            http: Some(code),
        })
    }

    /// In words: curl's exit code means something specific, and "check the network" is rarely the answer to a size limit.
    fn words(self) -> String {
        if let Some(h) = self.http {
            return format!("GitHub answered HTTP {h}");
        }
        match self.curl {
            Some(6) => "curl could not look up github.com (exit code 6: DNS)".into(),
            Some(7) => {
                "curl could not connect (exit code 7: check the network or a firewall)".into()
            }
            Some(22) => "GitHub answered with an error status (curl exit code 22)".into(),
            Some(23) => "curl could not write the file (exit code 23: is the disk full?)".into(),
            Some(28) => "the download timed out (curl exit code 28)".into(),
            Some(35 | 60) => "the secure connection failed (curl exit code 35 or 60: TLS)".into(),
            Some(56) => "the connection dropped during the download (curl exit code 56)".into(),
            Some(63) => {
                "the file is larger than the size limit this program accepts (curl exit code 63)"
                    .into()
            }
            Some(c) => format!("curl failed (exit code {c})"),
            None => "curl ended without an exit code".into(),
        }
    }
}

/// What a download was for, in the words of a failure message.
#[derive(Clone, Copy)]
enum Subject<'a> {
    /// GitHub's description of the release (to find its files).
    Release,
    File(&'a str),
}

type EnvLookup = Box<dyn Fn(&str) -> Option<String> + Send + Sync>;

/// What a verified manifest records about one image, beyond that the image is listed in it.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ManifestFacts {
    /// The first-boot hash (`None` for every release before the field).
    pub first_boot: Option<String>,
    /// The manifest's `upgrade` record for this image (`None` when the check failed, so nothing was read).
    pub upgrade: Option<UpgradeRecord>,
    /// Whether the signed manifest says the release is a pre-release (`None` when the check failed).
    pub prerelease: Option<bool>,
}

/// A cached answer for one release: its verdict, what its manifest records, and when it was checked.
type CachedVerdict = (Verdict, ManifestFacts, Instant);

/// Fetches and verifies release manifests. Cheap to clone-share: hold one per provider.
pub struct ReleaseVerifier {
    runner: Arc<dyn CommandRunner>,
    repo: String,
    env: EnvLookup,
    cache: Mutex<BTreeMap<String, CachedVerdict>>,
}

impl ReleaseVerifier {
    /// `repo` is the `owner/name` whose image workflow signs the releases.
    pub fn new(runner: Arc<dyn CommandRunner>, repo: impl Into<String>) -> Self {
        Self::with_env(runner, repo, |k| std::env::var(k).ok())
    }

    /// Like [`new`](Self::new) with the environment lookup supplied (tests use this so they do not read the real one).
    pub fn with_env(
        runner: Arc<dyn CommandRunner>,
        repo: impl Into<String>,
        env: impl Fn(&str) -> Option<String> + Send + Sync + 'static,
    ) -> Self {
        Self {
            runner,
            repo: repo.into(),
            env: Box::new(env),
            cache: Mutex::new(BTreeMap::new()),
        }
    }

    /// Check that `image_id` (used in `region`) is an image of release `release` built and signed by the workflow.
    pub fn verify(&self, release: &str, region: &str, image_id: &str) -> Verdict {
        self.verify_image(release, region, image_id).0
    }

    /// [`verify`](Self::verify), and what the verified manifest records about the image (nothing when the check failed).
    pub fn verify_image(
        &self,
        release: &str,
        region: &str,
        image_id: &str,
    ) -> (Verdict, ManifestFacts) {
        let key = format!("{release}\u{1f}{region}\u{1f}{image_id}");
        if let Ok(cache) = self.cache.lock() {
            if let Some((v, fb, at)) = cache.get(&key) {
                if v.verified || at.elapsed() < FAILURE_TTL {
                    return (v.clone(), fb.clone());
                }
            }
        }
        let (verdict, first_boot) = self.check(release, region, image_id);
        if let Ok(mut cache) = self.cache.lock() {
            cache.insert(key, (verdict.clone(), first_boot.clone(), Instant::now()));
        }
        (verdict, first_boot)
    }

    /// A GitHub token, if there is one: `GH_TOKEN` / `GITHUB_TOKEN`, else what `gh auth token` prints. Read at call time
    /// and never kept; it goes to curl on standard input, never in an argument.
    fn token(&self) -> Option<String> {
        for k in ["GH_TOKEN", "GITHUB_TOKEN"] {
            if let Some(t) = (self.env)(k) {
                let t = t.trim().to_string();
                if !t.is_empty() {
                    return Some(t);
                }
            }
        }
        let out = self
            .runner
            .run(&CommandSpec::new("gh").args(["auth", "token"]))
            .ok()?;
        let t = out.stdout.trim().to_string();
        (out.status == Some(0) && !t.is_empty() && !t.contains(char::is_whitespace)).then_some(t)
    }

    /// One download. `accept` is the `Accept` header; the token (if any) is sent as a header read from stdin.
    fn get(
        &self,
        url: &str,
        accept: &str,
        token: Option<&str>,
    ) -> std::result::Result<String, Fetch> {
        let mut cmd = CommandSpec::new("curl").args([
            "--silent",
            "--show-error",
            "--location",
            "--proto",
            "=https",
            "--proto-redir",
            "=https",
            "--tlsv1.2",
            "--max-time",
            "60",
            "--max-filesize",
            MANIFEST_MAX_BYTES_ARG,
            "--write-out",
            "\n%{http_code}",
            "--header",
            &format!("Accept: {accept}"),
            "--header",
            "X-GitHub-Api-Version: 2022-11-28",
        ]);
        if let Some(t) = token {
            cmd = cmd.args(["--header", "@-"]);
            cmd.stdin = Some(format!("Authorization: Bearer {t}\n").into_bytes());
        }
        cmd = cmd.arg(url);
        let out = match self.runner.run(&cmd) {
            Ok(o) => o,
            Err(_) => return Err(Fetch::NoCurl),
        };
        if out.status != Some(0) {
            return Err(NetDetail::curl(out.status));
        }
        let (body, code) = out
            .stdout
            .rsplit_once('\n')
            .ok_or_else(|| NetDetail::curl(None))?;
        match code.trim().parse::<u16>() {
            Ok(200) => Ok(body.to_string()),
            Ok(404) => Err(Fetch::NotFound),
            Ok(401) => Err(Fetch::BadToken),
            Ok(403) => Err(Fetch::Forbidden),
            Ok(429) => Err(Fetch::RateLimited),
            Ok(other) => Err(NetDetail::http(other)),
            Err(_) => Err(NetDetail::curl(None)),
        }
    }

    fn why(
        &self,
        f: Fetch,
        kind: ReleaseKind,
        release: &str,
        subject: Subject<'_>,
        with_token: bool,
    ) -> Verdict {
        let repo = &self.repo;
        let tag = format!("{}{release}", kind.tag_prefix());
        // "the release image-v1" or "ozbox-linux-amd64 of release image-v1": the file that failed, named
        let what = match subject {
            Subject::Release => format!("the release {tag}"),
            Subject::File(n) => format!("{n} of release {tag}"),
        };
        let verdict = if f == Fetch::NotFound {
            Verdict::refused
        } else {
            Verdict::no
        };
        verdict(match f {
            Fetch::NoCurl => "curl is not installed, so the release could not be downloaded".to_string(),
            Fetch::NotFound if with_token => format!(
                "{what} was not found in {repo}, or the GitHub token cannot see that repository"
            ),
            Fetch::NotFound => format!(
                "{what} was not found in {repo} without signing in; if the repository is private, run `gh auth login` or set GH_TOKEN"
            ),
            Fetch::BadToken => "GitHub refused the token (expired or wrong), so the release could not be downloaded; run `gh auth login` again or fix GH_TOKEN".to_string(),
            Fetch::Forbidden => format!(
                "GitHub refused the download of {what} from {repo}: the token has no access to it, or the rate limit is used up; sign in with `gh auth login` or wait and retry"
            ),
            Fetch::RateLimited => "GitHub is rate-limiting these downloads; sign in with `gh auth login` (or set GH_TOKEN) or wait and retry".to_string(),
            Fetch::Network(d) => format!("{what} could not be downloaded from {repo}: {}", d.words()),
        })
    }

    /// The download URL of each wanted file: through the API (with the token) when there is one, direct otherwise.
    fn resolve(
        &self,
        kind: ReleaseKind,
        release: &str,
        token: Option<&str>,
        names: &[String],
    ) -> std::result::Result<Vec<(String, Option<String>)>, Verdict> {
        match token {
            None => Ok(names
                .iter()
                .map(|n| {
                    (
                        n.clone(),
                        Some(format!(
                            "https://github.com/{}/releases/download/{}{release}/{n}",
                            self.repo,
                            kind.tag_prefix()
                        )),
                    )
                })
                .collect()),
            Some(t) => {
                let url = format!(
                    "https://api.github.com/repos/{}/releases/tags/{}{release}",
                    self.repo,
                    kind.tag_prefix()
                );
                let body = self
                    .get(&url, "application/vnd.github+json", Some(t))
                    .map_err(|f| self.why(f, kind, release, Subject::Release, true))?;
                let v: serde_json::Value = serde_json::from_str(&body).map_err(|_| {
                    Verdict::no("GitHub's answer about the release could not be read")
                })?;
                let prefix = format!(
                    "https://api.github.com/repos/{}/releases/assets/",
                    self.repo
                );
                let assets = v.get("assets").and_then(|a| a.as_array());
                Ok(names
                    .iter()
                    .map(|n| {
                        let url = assets
                            .into_iter()
                            .flatten()
                            .find(|a| a.get("name").and_then(|x| x.as_str()) == Some(n))
                            .and_then(|a| a.get("url").and_then(|x| x.as_str()))
                            // The token only ever goes to this repository's asset endpoint.
                            .filter(|u| u.starts_with(&prefix))
                            .map(str::to_string);
                        (n.clone(), url)
                    })
                    .collect())
            }
        }
    }

    fn download(
        &self,
        entry: &(String, Option<String>),
        kind: ReleaseKind,
        release: &str,
        token: Option<&str>,
    ) -> std::result::Result<String, Verdict> {
        let (name, url) = entry;
        let Some(url) = url else {
            return Err(self.why(
                Fetch::NotFound,
                kind,
                release,
                Subject::File(name),
                token.is_some(),
            ));
        };
        self.get(url, "application/octet-stream", token)
            .map_err(|f| self.why(f, kind, release, Subject::File(name), token.is_some()))
    }

    /// Download one file of a release (a program, not text) into `dest`, with the token when one is set (it goes to curl on
    /// standard input, never in an argument), so a private repository works. The file is NOT trusted: the caller checks
    /// it against the hash a verified manifest lists.
    pub fn download_asset(
        &self,
        kind: ReleaseKind,
        release: &str,
        name: &str,
        dest: &Path,
        max_bytes: u64,
    ) -> std::result::Result<(), Verdict> {
        if !is_repo_slug(&self.repo) || !is_release_version(release) {
            return Err(Verdict::no(
                "the release repository or version is not valid, so nothing was downloaded",
            ));
        }
        if name.is_empty()
            || !name
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.'))
        {
            return Err(Verdict::no("the file name is not a plain file name"));
        }
        let token = self.token();
        let t = token.as_deref();
        let entries = self.resolve(kind, release, t, &[name.to_string()])?;
        let (_, url) = &entries[0];
        let Some(url) = url else {
            return Err(self.why(
                Fetch::NotFound,
                kind,
                release,
                Subject::File(name),
                t.is_some(),
            ));
        };
        let mut cmd = CommandSpec::new("curl").args([
            "--silent",
            "--show-error",
            "--location",
            "--proto",
            "=https",
            "--proto-redir",
            "=https",
            "--tlsv1.2",
            "--max-time",
            "600",
            "--max-filesize",
            &max_bytes.to_string(),
            "--write-out",
            "\n%{http_code}",
            "--header",
            "Accept: application/octet-stream",
            "--header",
            "X-GitHub-Api-Version: 2022-11-28",
            "--output",
            &dest.display().to_string(),
        ]);
        if let Some(t) = t {
            cmd = cmd.args(["--header", "@-"]);
            cmd.stdin = Some(format!("Authorization: Bearer {t}\n").into_bytes());
        }
        cmd = cmd.arg(url);
        let fail = |f: Fetch| self.why(f, kind, release, Subject::File(name), t.is_some());
        let out = self.runner.run(&cmd).map_err(|_| fail(Fetch::NoCurl))?;
        if out.status != Some(0) {
            return Err(fail(NetDetail::curl(out.status)));
        }
        match out.stdout.trim().parse::<u16>() {
            Ok(200) => Ok(()),
            Ok(404) => Err(fail(Fetch::NotFound)),
            Ok(401) => Err(fail(Fetch::BadToken)),
            Ok(403) => Err(fail(Fetch::Forbidden)),
            Ok(429) => Err(fail(Fetch::RateLimited)),
            Ok(other) => Err(fail(NetDetail::http(other))),
            Err(_) => Err(fail(NetDetail::curl(None))),
        }
    }

    /// cosign's major version, if it can be read (`cosign version` prints a `GitVersion:` line).
    fn cosign_major(&self) -> std::result::Result<Option<u32>, Verdict> {
        match self.runner.run(&CommandSpec::new("cosign").arg("version")) {
            Err(_) => Err(Verdict::no(
                "cosign is not installed, so the release signature could not be checked (install it from https://docs.sigstore.dev/)",
            )),
            Ok(o) => Ok(parse_cosign_major(&format!("{}\n{}", o.stdout, o.stderr))),
        }
    }

    fn check(&self, release: &str, region: &str, image_id: &str) -> (Verdict, ManifestFacts) {
        if !is_repo_slug(&self.repo) {
            return (Verdict::no(format!(
                "the release repository {:?} is not an owner/name pair, so signatures cannot be checked (set `release_repo` under [aws])",
                self.repo
            )), ManifestFacts::default());
        }
        if !is_release_version(release) {
            return (Verdict::no(format!(
                "the image's release tag {release:?} is not a version, so no signed manifest can be found for it"
            )), ManifestFacts::default());
        }
        let manifest = match self.signed_manifest(ReleaseKind::Image, release) {
            Ok(m) => m,
            Err(v) => return (v, ManifestFacts::default()),
        };
        match manifest_listing(&manifest, release, region, image_id) {
            Listing::Listed => (
                Verdict {
                    verified: true,
                    detail: format!(
                        "verified: release {release} is signed by {}'s image workflow and lists this image for {region}",
                        self.repo
                    ),
                    definitive: true,
                },
                ManifestFacts {
                    first_boot: manifest_first_boot(&manifest),
                    upgrade: Some(upgrade_record(
                        &manifest,
                        manifest_image_arch(&manifest, region, image_id).as_deref(),
                    )),
                    prerelease: manifest_prerelease(&manifest),
                },
            ),
            Listing::NotListed(why) => (Verdict::refused(why), ManifestFacts::default()),
            Listing::Unusable(why) => (Verdict::no(why), ManifestFacts::default()),
        }
    }

    /// Download the manifest of a release with its signature and check the signature against this repository's
    /// workflow for that kind of release. Returns the manifest text only when it verified; anything else is a
    /// [`Verdict`] saying why not. The caller still has to check what the manifest says.
    pub fn signed_manifest(
        &self,
        kind: ReleaseKind,
        release: &str,
    ) -> std::result::Result<String, Verdict> {
        if !is_repo_slug(&self.repo) {
            return Err(Verdict::no(format!(
                "the release repository {:?} is not an owner/name pair, so signatures cannot be checked",
                self.repo
            )));
        }
        if !is_release_version(release) {
            return Err(Verdict::no(format!(
                "the release tag {release:?} is not a version, so no signed manifest can be found for it"
            )));
        }
        let manifest = kind.manifest();
        let token = self.token();
        let t = token.as_deref();
        let names = vec![
            manifest.to_string(),
            format!("{manifest}.sig"),
            format!("{manifest}.pem"),
            format!("{manifest}.sigstore.json"),
        ];
        let entries = self.resolve(kind, release, t, &names)?;
        // One at a time: a release with no manifest costs one download, not three.
        let mut bodies = Vec::new();
        for e in &entries[..3] {
            bodies.push(self.download(e, kind, release, t)?);
        }
        let major = self.cosign_major()?;
        // cosign 3 prefers one sigstore bundle to a separate signature and certificate; releases carry both.
        let bundle = if major.is_some_and(|m| m >= 3) {
            self.download(&entries[3], kind, release, t).ok()
        } else {
            None
        };
        let dir = match Scratch::new() {
            Ok(d) => d,
            Err(_) => {
                return Err(Verdict::no(
                    "a scratch directory for the signature check could not be made",
                ))
            }
        };
        let mut files = vec![
            (manifest, &bodies[0]),
            ("manifest.sig", &bodies[1]),
            ("manifest.pem", &bodies[2]),
        ];
        if let Some(b) = &bundle {
            files.push(("manifest.sigstore.json", b));
        }
        for (name, body) in files {
            if std::fs::write(dir.path.join(name), body).is_err() {
                return Err(Verdict::no(
                    "the signature files could not be written for checking",
                ));
            }
        }
        let p = |n: &str| dir.path.join(n).display().to_string();
        let identity = [
            "--certificate-identity-regexp".to_string(),
            identity_regexp(&self.repo, kind),
            "--certificate-oidc-issuer".into(),
            OIDC_ISSUER.into(),
        ];
        let mut ok = false;
        if bundle.is_some() {
            let cmd = CommandSpec::new("cosign")
                .args([
                    "verify-blob".to_string(),
                    "--timeout".into(),
                    COSIGN_TIMEOUT.into(),
                    "--bundle".into(),
                    p("manifest.sigstore.json"),
                ])
                .args(identity.clone())
                .arg(p(manifest));
            ok = self.runner.run_ok(&cmd).is_ok();
        }
        if !ok {
            // The signature and certificate form works on cosign 2 and 3 (3 only warns that `--certificate` is deprecated).
            let cmd = CommandSpec::new("cosign")
                .args([
                    "verify-blob".to_string(),
                    "--timeout".into(),
                    COSIGN_TIMEOUT.into(),
                    "--certificate".into(),
                    p("manifest.pem"),
                    "--signature".into(),
                    p("manifest.sig"),
                ])
                .args(identity)
                .arg(p(manifest));
            match self.runner.run_ok(&cmd) {
                Ok(_) => {}
                Err(Error::Io(_)) => {
                    return Err(Verdict::no(
                        "cosign is not installed, so the release signature could not be checked (install it from https://docs.sigstore.dev/)",
                    ))
                }
                Err(_) => {
                    return Err(Verdict::no(format!(
                        "the signature on the manifest of release {release} did not verify against {}'s {} workflow",
                        self.repo,
                        kind.workflow()
                    )))
                }
            }
        }
        Ok(bodies.swap_remove(0))
    }
}

/// The major version in `cosign version` output (`GitVersion:    v3.0.2`).
fn parse_cosign_major(text: &str) -> Option<u32> {
    let line = text
        .lines()
        .find_map(|l| l.trim().strip_prefix("GitVersion:"))?;
    line.trim()
        .trim_start_matches('v')
        .split('.')
        .next()?
        .parse()
        .ok()
}

/// A private scratch directory, removed when dropped.
struct Scratch {
    path: PathBuf,
}

static SCRATCH_SEQ: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

impl Scratch {
    fn new() -> std::io::Result<Self> {
        let path = std::env::temp_dir().join(format!(
            "ozbox-verify-{}-{}",
            std::process::id(),
            SCRATCH_SEQ.fetch_add(1, std::sync::atomic::Ordering::SeqCst)
        ));
        std::fs::create_dir(&path)?;
        Ok(Self { path })
    }
}

impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.path);
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    use super::*;
    use crate::{Output, RecordingRunner};

    const MANIFEST_JSON: &str = r#"{"version":"2026.11.09","source_commit":"abc","images":[
        {"arch":"amd64","amis":{"us-east-1":"ami-0123456789abcdef0","us-west-2":"ami-0aaaaaaaaaaaaaaaa"}},
        {"arch":"arm64","amis":{"us-east-1":"ami-0bbbbbbbbbbbbbbbb"}}]}"#;

    #[test]
    fn the_first_boot_hash_is_read_from_the_manifest_or_not_at_all() {
        let h = "ab".repeat(32);
        assert_eq!(
            manifest_first_boot(&format!(r#"{{"version":"0.1.1","first_boot":"{h}"}}"#)),
            Some(h.clone())
        );
        assert_eq!(
            manifest_first_boot(&format!(
                r#"{{"upgrade":{{"disk_parts":{{"first_boot":"{}"}}}}}}"#,
                h.to_uppercase()
            )),
            Some(h)
        );
        // every release before the field, and anything that is not a hash
        assert_eq!(manifest_first_boot(MANIFEST_JSON), None);
        assert_eq!(manifest_first_boot(r#"{"first_boot":"abc"}"#), None);
        assert_eq!(manifest_first_boot("not json"), None);
    }

    fn reply(r: &RecordingRunner, status: i32, stdout: &str) {
        r.reply(Output {
            status: Some(status),
            stdout: stdout.into(),
            stderr: "boom".into(),
        });
    }

    fn verifier(r: &Arc<RecordingRunner>) -> ReleaseVerifier {
        ReleaseVerifier::with_env(r.clone(), "example-org/example-repo", |_| None)
    }

    /// A download answer: the body, then the status line curl's `--write-out` adds.
    fn http(r: &RecordingRunner, code: u16, body: &str) {
        reply(r, 0, &format!("{body}\n{code}"));
    }

    /// No token from `gh` either (not signed in).
    fn no_gh(r: &RecordingRunner) {
        reply(r, 1, "");
    }

    const COSIGN2: &str = "GitVersion:    v2.4.1\nGitCommit: x";
    const COSIGN3: &str = "GitVersion:    v3.0.2\nGitCommit: x";

    #[test]
    fn slugs_and_versions_are_strict() {
        assert!(is_repo_slug("example-org/example.repo"));
        for bad in [
            "", "a", "a/b/c", "/b", "a/", "a b/c", "a/b;rm", "a/..", "../b", "a/b$",
        ] {
            assert!(!is_repo_slug(bad), "{bad}");
        }
        assert!(is_release_version("2026.11.09"));
        assert!(is_release_version("0.1.0-rc.1"));
        for bad in [
            "", "1", "latest", "1.2.3.4", "1..2", "../1.2", "1.2-", "1.2-UP", "1.2/3",
        ] {
            assert!(!is_release_version(bad), "{bad}");
        }
    }

    #[test]
    fn the_identity_names_this_repositorys_image_workflow_only() {
        let re = identity_regexp("example-org/example.repo", ReleaseKind::Image);
        assert!(re.starts_with(
            "^https://github\\.com/example-org/example\\.repo/\\.github/workflows/image\\.yml@"
        ));
        assert!(re.ends_with('$'));
    }

    #[test]
    fn the_manifest_must_be_for_the_release_and_list_the_image_for_the_region() {
        assert!(manifest_lists(
            MANIFEST_JSON,
            "2026.11.09",
            "us-east-1",
            "ami-0123456789abcdef0"
        )
        .is_ok());
        assert!(manifest_lists(
            MANIFEST_JSON,
            "2026.11.09",
            "us-west-2",
            "ami-0aaaaaaaaaaaaaaaa"
        )
        .is_ok());
        // right id, wrong region
        assert!(manifest_lists(
            MANIFEST_JSON,
            "2026.11.09",
            "us-west-2",
            "ami-0123456789abcdef0"
        )
        .is_err());
        // unknown id
        assert!(manifest_lists(
            MANIFEST_JSON,
            "2026.11.09",
            "us-east-1",
            "ami-0ffffffffffffffff"
        )
        .is_err());
        // a manifest of another release cannot vouch for this one
        let e = manifest_lists(
            MANIFEST_JSON,
            "2026.10.01",
            "us-east-1",
            "ami-0123456789abcdef0",
        )
        .err()
        .unwrap_or_default();
        assert!(e.contains("2026.11.09"), "{e}");
        assert!(manifest_lists("not json", "x", "y", "z").is_err());
        assert!(manifest_lists("{}", "x", "y", "z").is_err());
    }

    #[test]
    fn a_verified_manifest_hands_over_its_upgrade_record_for_the_images_architecture() {
        let g = |c: char| c.to_string().repeat(64);
        let manifest = format!(
            r#"{{"version":"0.3.2","first_boot":"{f}","images":[
            {{"arch":"amd64","amis":{{"us-east-1":"ami-1"}}}},{{"arch":"arm64","amis":{{"us-east-1":"ami-2"}}}}],
            "upgrade":{{"disk_generation":{{"amd64":"{a}","arm64":"{b}"}},"disk_parts":{{"first_boot":"{f}"}},"work_format":1,"work_format_reads":[1]}}}}"#,
            f = g('f'),
            a = g('a'),
            b = g('b')
        );
        for (ami, want) in [("ami-1", g('a')), ("ami-2", g('b'))] {
            let r = Arc::new(RecordingRunner::new());
            no_gh(&r);
            http(&r, 200, &manifest);
            http(&r, 200, "c2ln");
            http(&r, 200, "cGVt");
            reply(&r, 0, COSIGN2);
            reply(&r, 0, "");
            let (v, facts) = verifier(&r).verify_image("0.3.2", "us-east-1", ami);
            assert!(v.verified, "{}", v.detail);
            assert_eq!(facts.first_boot, Some(g('f')));
            let Some(UpgradeRecord::Present(b)) = facts.upgrade else {
                panic!("no upgrade record")
            };
            assert_eq!(b.disk_generation, want);
        }
        // a manifest from before the record: verified, and the record is absent (not missing)
        let r = Arc::new(RecordingRunner::new());
        no_gh(&r);
        http(&r, 200, MANIFEST_JSON);
        http(&r, 200, "c2ln");
        http(&r, 200, "cGVt");
        reply(&r, 0, COSIGN2);
        reply(&r, 0, "");
        let (v, facts) =
            verifier(&r).verify_image("2026.11.09", "us-east-1", "ami-0123456789abcdef0");
        assert!(v.verified);
        assert_eq!(facts.upgrade, Some(UpgradeRecord::Absent));
        // an unverified image hands over nothing
        let r = Arc::new(RecordingRunner::new());
        no_gh(&r);
        http(&r, 404, "");
        let (v, facts) = verifier(&r).verify_image("2026.11.09", "us-east-1", "ami-1");
        assert!(!v.verified);
        assert_eq!(facts, ManifestFacts::default());
    }

    #[test]
    fn an_anonymous_check_downloads_directly_and_verifies_with_cosign_2() {
        let r = Arc::new(RecordingRunner::new());
        no_gh(&r);
        http(&r, 200, MANIFEST_JSON);
        http(&r, 200, "c2ln");
        http(&r, 200, "cGVt");
        reply(&r, 0, COSIGN2);
        reply(&r, 0, "");
        let v = verifier(&r).verify("2026.11.09", "us-east-1", "ami-0123456789abcdef0");
        assert!(v.verified, "{}", v.detail);
        let calls = r.calls();
        assert_eq!(calls.len(), 6);
        assert_eq!(calls[0].program, "gh");
        assert!(calls[1..4].iter().all(|c| c.program == "curl"
            && c.args.contains(&"=https".to_string())
            && !c.args.iter().any(|a| a.contains("Authorization"))
            && c.stdin.is_none()));
        assert!(calls[1].args.last().is_some_and(|u| u
            == "https://github.com/example-org/example-repo/releases/download/image-v2026.11.09/ozbox-image-manifest.json"));
        assert_eq!(calls[4].args, ["version"]);
        let cosign = &calls[5];
        assert_eq!(cosign.args[0], "verify-blob");
        assert!(cosign.args.contains(&"--certificate".to_string()));
        assert!(!cosign.args.contains(&"--bundle".to_string()));
        assert!(cosign
            .args
            .contains(&"--certificate-identity-regexp".to_string()));
        assert!(cosign.args.contains(&OIDC_ISSUER.to_string()));
    }

    #[test]
    fn a_token_goes_through_the_api_on_stdin_and_never_in_an_argument() {
        let r = Arc::new(RecordingRunner::new());
        // the token comes from the environment, so `gh` is not asked
        let api = r#"{"assets":[
          {"name":"ozbox-image-manifest.json","url":"https://api.github.com/repos/example-org/example-repo/releases/assets/1"},
          {"name":"ozbox-image-manifest.json.sig","url":"https://api.github.com/repos/example-org/example-repo/releases/assets/2"},
          {"name":"ozbox-image-manifest.json.pem","url":"https://evil.example/steal"}]}"#;
        http(&r, 200, api);
        http(&r, 200, MANIFEST_JSON);
        http(&r, 200, "c2ln");
        let v = ReleaseVerifier::with_env(r.clone(), "example-org/example-repo", |k| {
            (k == "GH_TOKEN").then(|| "tok-secret".to_string())
        })
        .verify("2026.11.09", "us-east-1", "ami-0123456789abcdef0");
        // an asset URL that is not this repository's endpoint is never fetched with the token
        assert!(
            !v.verified && v.detail.contains("not found"),
            "{}",
            v.detail
        );
        let calls = r.calls();
        assert_eq!(calls.len(), 3, "{calls:?}");
        for c in &calls {
            assert_eq!(c.program, "curl");
            assert!(!c.args.iter().any(|a| a.contains("tok-secret")));
            assert!(c.args.contains(&"@-".to_string()));
            assert_eq!(
                c.stdin.as_deref(),
                Some(&b"Authorization: Bearer tok-secret\n"[..])
            );
        }
        assert!(calls[0].args.last().is_some_and(|u| u
            == "https://api.github.com/repos/example-org/example-repo/releases/tags/image-v2026.11.09"));
        assert!(calls[1]
            .args
            .last()
            .is_some_and(|u| u.ends_with("/releases/assets/1")));
        assert!(!v.detail.contains("tok-secret"));
    }

    #[test]
    fn the_gh_token_is_used_when_the_environment_has_none_and_a_full_run_verifies() {
        let r = Arc::new(RecordingRunner::new());
        reply(&r, 0, "gho_abc123\n"); // gh auth token
        http(
            &r,
            200,
            r#"{"assets":[
              {"name":"ozbox-image-manifest.json","url":"https://api.github.com/repos/example-org/example-repo/releases/assets/1"},
              {"name":"ozbox-image-manifest.json.sig","url":"https://api.github.com/repos/example-org/example-repo/releases/assets/2"},
              {"name":"ozbox-image-manifest.json.pem","url":"https://api.github.com/repos/example-org/example-repo/releases/assets/3"}]}"#,
        );
        http(&r, 200, MANIFEST_JSON);
        http(&r, 200, "c2ln");
        http(&r, 200, "cGVt");
        reply(&r, 0, COSIGN2);
        reply(&r, 0, "");
        let v = verifier(&r).verify("2026.11.09", "us-east-1", "ami-0123456789abcdef0");
        assert!(v.verified, "{}", v.detail);
        let calls = r.calls();
        assert_eq!(calls[0].args, ["auth", "token"]);
        assert!(calls[1].stdin.is_some());
        assert!(calls
            .iter()
            .all(|c| !c.args.iter().any(|a| a.contains("gho_abc123"))));
    }

    #[test]
    fn cosign_3_uses_the_bundle_and_falls_back_to_the_signature_pair() {
        // bundle verifies
        let r = Arc::new(RecordingRunner::new());
        no_gh(&r);
        http(&r, 200, MANIFEST_JSON);
        http(&r, 200, "s");
        http(&r, 200, "p");
        reply(&r, 0, COSIGN3);
        http(&r, 200, "{}"); // the bundle
        reply(&r, 0, "");
        let v = verifier(&r).verify("2026.11.09", "us-east-1", "ami-0123456789abcdef0");
        assert!(v.verified, "{}", v.detail);
        let calls = r.calls();
        assert_eq!(calls.len(), 7);
        assert!(calls[6].args.contains(&"--bundle".to_string()));
        assert!(!calls[6].args.contains(&"--certificate".to_string()));

        // an older release with no bundle still verifies, through the pair
        let r = Arc::new(RecordingRunner::new());
        no_gh(&r);
        http(&r, 200, MANIFEST_JSON);
        http(&r, 200, "s");
        http(&r, 200, "p");
        reply(&r, 0, COSIGN3);
        http(&r, 404, "");
        reply(&r, 0, "");
        let v = verifier(&r).verify("2026.11.09", "us-east-1", "ami-0123456789abcdef0");
        assert!(v.verified, "{}", v.detail);
        assert!(r.calls()[6].args.contains(&"--certificate".to_string()));

        // a bundle cosign rejects falls back to the pair, and both failing is unverified
        let r = Arc::new(RecordingRunner::new());
        no_gh(&r);
        http(&r, 200, MANIFEST_JSON);
        http(&r, 200, "s");
        http(&r, 200, "p");
        reply(&r, 0, COSIGN3);
        http(&r, 200, "{}");
        reply(&r, 1, "");
        reply(&r, 1, "");
        let v = verifier(&r).verify("2026.11.09", "us-east-1", "ami-0123456789abcdef0");
        assert!(
            !v.verified && v.detail.contains("did not verify"),
            "{}",
            v.detail
        );
    }

    #[test]
    fn cosign_versions_are_read_from_its_output() {
        assert_eq!(parse_cosign_major(COSIGN2), Some(2));
        assert_eq!(parse_cosign_major(COSIGN3), Some(3));
        assert_eq!(parse_cosign_major("GitVersion:    v10.1.0"), Some(10));
        assert_eq!(parse_cosign_major("nothing useful"), None);
    }

    #[test]
    fn every_way_to_fail_says_unverified_with_a_reason() {
        // the signature does not verify
        let r = Arc::new(RecordingRunner::new());
        no_gh(&r);
        http(&r, 200, MANIFEST_JSON);
        http(&r, 200, "s");
        http(&r, 200, "p");
        reply(&r, 0, COSIGN2);
        reply(&r, 1, "");
        let v = verifier(&r).verify("2026.11.09", "us-east-1", "ami-0123456789abcdef0");
        assert!(
            !v.verified && v.detail.contains("did not verify"),
            "{}",
            v.detail
        );

        // a valid signature that does not list the image
        let r = Arc::new(RecordingRunner::new());
        no_gh(&r);
        http(&r, 200, MANIFEST_JSON);
        http(&r, 200, "s");
        http(&r, 200, "p");
        reply(&r, 0, COSIGN2);
        reply(&r, 0, "");
        let v = verifier(&r).verify("2026.11.09", "us-east-1", "ami-0ffffffffffffffff");
        assert!(
            !v.verified && v.detail.contains("not in the signed manifest"),
            "{}",
            v.detail
        );

        // a tag that is not a version never reaches a URL
        let r = Arc::new(RecordingRunner::new());
        let v = verifier(&r).verify("../etc", "us-east-1", "ami-0123456789abcdef0");
        assert!(!v.verified);
        assert!(r.calls().is_empty());
        let bad_repo = ReleaseVerifier::with_env(r.clone(), "nonsense", |_| None);
        assert!(!bad_repo.verify("2026.11.09", "us-east-1", "ami-1").verified);
        assert!(r.calls().is_empty());
    }

    #[test]
    fn a_download_failure_says_which_kind_it_was() {
        let case = |reply_with: Option<(i32, String)>, token: bool| -> String {
            let r = Arc::new(RecordingRunner::new());
            if !token {
                no_gh(&r);
            }
            if let Some((st, out)) = reply_with {
                reply(&r, st, &out);
            }
            let env_token = token;
            let v = ReleaseVerifier::with_env(r.clone(), "example-org/example-repo", move |k| {
                (env_token && k == "GH_TOKEN").then(|| "t".to_string())
            })
            .verify("2026.11.09", "us-east-1", "ami-0123456789abcdef0");
            assert!(!v.verified);
            assert_eq!(
                r.calls().iter().filter(|c| c.program == "cosign").count(),
                0,
                "cosign is not run on nothing"
            );
            v.detail
        };
        let d = case(Some((0, "\n404".into())), false);
        assert!(
            d.contains("not found") && d.contains("gh auth login"),
            "{d}"
        );
        let d = case(Some((0, "\n404".into())), true);
        assert!(d.contains("cannot see that repository"), "{d}");
        let d = case(Some((0, "{}\n401".into())), true);
        assert!(d.contains("refused the token"), "{d}");
        let d = case(Some((0, "{}\n403".into())), true);
        assert!(d.contains("no access") && d.contains("rate limit"), "{d}");
        let d = case(Some((0, "x\n429".into())), false);
        assert!(d.contains("rate-limiting"), "{d}");
        let d = case(Some((6, "".into())), false);
        assert!(
            d.contains("DNS") && d.contains("ozbox-image-manifest.json"),
            "{d}"
        );
        let d = case(Some((0, "x\n500".into())), false);
        assert!(d.contains("HTTP 500"), "{d}");
    }

    #[test]
    fn a_result_is_remembered_so_polling_does_not_run_the_tools_each_time() {
        let r = Arc::new(RecordingRunner::new());
        no_gh(&r);
        http(&r, 200, MANIFEST_JSON);
        http(&r, 200, "s");
        http(&r, 200, "p");
        reply(&r, 0, COSIGN2);
        reply(&r, 0, "");
        let v = verifier(&r);
        assert!(
            v.verify("2026.11.09", "us-east-1", "ami-0123456789abcdef0")
                .verified
        );
        assert!(
            v.verify("2026.11.09", "us-east-1", "ami-0123456789abcdef0")
                .verified
        );
        assert_eq!(r.calls().len(), 6);
    }

    #[test]
    fn a_program_release_is_checked_against_its_own_workflow_and_tag() {
        let re = identity_regexp("example-org/example-repo", ReleaseKind::Cli);
        assert!(re.contains("workflows/cli-release\\.yml@"), "{re}");
        assert!(re.contains("tags/v["), "{re}");
        assert!(!re.contains("image"), "{re}");
        let r = Arc::new(RecordingRunner::new());
        no_gh(&r);
        http(&r, 200, r#"{"version":"0.1.0"}"#);
        http(&r, 200, "s");
        http(&r, 200, "p");
        reply(&r, 0, COSIGN2);
        reply(&r, 0, "");
        let m = verifier(&r)
            .signed_manifest(ReleaseKind::Cli, "0.1.0")
            .map_err(|v| v.detail)
            .unwrap_or_default();
        assert!(m.contains("0.1.0"), "{m}");
        let calls = r.calls();
        assert!(calls[1].args.last().is_some_and(|u| u
            == "https://github.com/example-org/example-repo/releases/download/v0.1.0/ozbox-cli-manifest.json"));
        assert!(calls[5].args.iter().any(|a| a.contains("cli-release")));
        // the image workflow's signature is not accepted for a program release: the identity differs
        assert!(calls[5].args.iter().all(|a| !a.contains("image\\.yml")));
    }

    #[test]
    #[allow(clippy::expect_used, clippy::unwrap_used)]
    fn a_program_is_downloaded_to_a_file_with_the_token_on_standard_input_only() {
        let r = Arc::new(RecordingRunner::new());
        // private repository: the asset's API address comes from the release listing
        http(
            &r,
            200,
            r#"{"assets":[{"name":"ozbox-linux-x86_64","url":"https://api.github.com/repos/example-org/example-repo/releases/assets/7"}]}"#,
        );
        r.reply(Output {
            status: Some(0),
            stdout: "\n200".into(),
            stderr: String::new(),
        });
        let v = ReleaseVerifier::with_env(r.clone(), "example-org/example-repo", |k| {
            (k == "GH_TOKEN").then(|| "tok-secret".to_string())
        });
        let dest = Path::new("/tmp/ozbox-test-dest");
        v.download_asset(ReleaseKind::Cli, "0.1.0", "ozbox-linux-x86_64", dest, 1000)
            .expect("downloaded");
        let calls = r.calls();
        let last = calls.last().expect("a call");
        assert!(last.args.iter().any(|a| a == "--output"));
        assert!(last.args.iter().any(|a| a == "/tmp/ozbox-test-dest"));
        assert!(last.args.iter().any(|a| a.ends_with("/releases/assets/7")));
        assert!(calls
            .iter()
            .all(|c| c.args.iter().all(|a| !a.contains("tok-secret"))));
        assert!(
            String::from_utf8_lossy(last.stdin.as_deref().unwrap_or_default())
                .contains("tok-secret")
        );
    }

    #[test]
    #[allow(clippy::expect_used, clippy::unwrap_used)]
    fn a_download_that_is_refused_says_why_and_a_bad_file_name_is_never_sent() {
        let r = Arc::new(RecordingRunner::new());
        r.reply(Output {
            status: Some(1),
            ..Default::default()
        }); // gh: not signed in
        r.reply(Output {
            status: Some(0),
            stdout: "\n404".into(),
            stderr: String::new(),
        });
        let v = verifier(&r);
        let e = v
            .download_asset(
                ReleaseKind::Cli,
                "0.1.0",
                "ozbox-linux-x86_64",
                Path::new("/tmp/x"),
                10,
            )
            .expect_err("refused");
        assert!(e.detail.contains("without signing in"), "{}", e.detail);
        let before = r.calls().len();
        assert!(v
            .download_asset(ReleaseKind::Cli, "0.1.0", "../x", Path::new("/tmp/x"), 10)
            .is_err());
        assert_eq!(r.calls().len(), before);
    }

    // ---- the image release as the source of the `ozbox` program ---------------------------------------------------------

    const SHA_A: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    const SHA_B: &str = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";

    #[test]
    fn every_way_of_naming_a_release_is_read_and_nothing_else() {
        let img = |v: &str| Some((Some(ReleaseKind::Image), v.to_string()));
        assert_eq!(
            parse_release_arg("image-v2026.11.10-1"),
            img("2026.11.10-1")
        );
        assert_eq!(
            parse_release_arg(" cli-v0.1.0 "),
            Some((Some(ReleaseKind::Cli), "0.1.0".to_string()))
        );
        assert_eq!(
            parse_release_arg("2026.11.10-1"),
            Some((None, "2026.11.10-1".to_string()))
        );
        assert_eq!(
            parse_release_arg("v0.3.0"),
            Some((Some(ReleaseKind::Cli), "0.3.0".to_string()))
        );
        for bad in [
            "",
            "latest",
            "image-v",
            "cli-vlatest",
            "image-v../x",
            "2026.11.10-1; rm",
            "image-vv1.2",
            "1",
            "release-2026.11.10",
        ] {
            assert_eq!(parse_release_arg(bad), None, "{bad:?}");
        }
    }

    #[test]
    fn a_program_and_an_image_must_share_major_and_minor() {
        assert_eq!(compat("0.3.0", "0.3.0"), Compat::Compatible);
        assert_eq!(
            compat("0.3.0", "0.3.7"),
            Compat::Compatible,
            "a patch never breaks"
        );
        assert_eq!(compat("0.3.4", "0.3.0-rc.1"), Compat::Compatible);
        assert_eq!(compat("0.3.0", "0.4.0"), Compat::ProgramOlder);
        assert_eq!(compat("0.3.0", "0.2.9"), Compat::ImageOlder);
        assert_eq!(compat("1.0.0", "0.9.0"), Compat::ImageOlder);
        assert_eq!(compat("0.9.0", "1.0.0"), Compat::ProgramOlder);
        assert_eq!(compat("0.1.0-alpha.0", "0.1.3"), Compat::Compatible);
        assert_eq!(compat("0.3.0", "2026.11.10-1"), Compat::Legacy);
        assert_eq!(compat("0.3.0", "latest"), Compat::Unknown);
        assert_eq!(compat("x", "0.3.0"), Compat::Unknown);
        assert_eq!(compat("0.3.0", "v0.3.2"), Compat::Compatible);
    }

    #[test]
    fn the_old_cli_tag_is_still_read_as_the_same_kind() {
        assert_eq!(
            parse_release_arg("cli-v0.1.0"),
            Some((Some(ReleaseKind::Cli), "0.1.0".to_string()))
        );
        assert_eq!(
            ReleaseKind::Cli.tag_prefix(),
            "v",
            "the program's release tag is v<version>"
        );
    }

    #[test]
    fn machine_types_map_to_both_spellings() {
        assert_eq!(
            machine_arch("x86_64"),
            Some(MachineArch {
                image: "amd64",
                cli: "x86_64"
            })
        );
        assert_eq!(
            machine_arch("amd64\n"),
            Some(MachineArch {
                image: "amd64",
                cli: "x86_64"
            })
        );
        assert_eq!(
            machine_arch("aarch64"),
            Some(MachineArch {
                image: "arm64",
                cli: "aarch64"
            })
        );
        assert_eq!(
            machine_arch("arm64"),
            Some(MachineArch {
                image: "arm64",
                cli: "aarch64"
            })
        );
        assert_eq!(machine_arch("armv7l"), None);
    }

    #[test]
    fn the_image_manifest_lists_the_program_per_machine_and_only_a_name_and_a_hash_are_taken() {
        let m = format!(
            r#"{{"version":"2026.11.10-1","images":[],"ozbox":{{"amd64":"{SHA_A}","arm64":"{SHA_B}"}},"url":"https://evil.example/x"}}"#
        );
        let amd = MachineArch {
            image: "amd64",
            cli: "x86_64",
        };
        let arm = MachineArch {
            image: "arm64",
            cli: "aarch64",
        };
        assert_eq!(
            image_program(&m, "2026.11.10-1", amd),
            Ok(ProgramEntry {
                asset: "ozbox-linux-amd64".into(),
                sha256: SHA_A.into()
            })
        );
        assert_eq!(
            image_program(&m, "2026.11.10-1", arm).unwrap().sha256,
            SHA_B
        );
        assert!(image_program(&m, "2026.11.09", amd)
            .unwrap_err()
            .contains("not 2026.11.09"));
        assert!(image_program(&m.replace(SHA_A, "zz"), "2026.11.10-1", amd)
            .unwrap_err()
            .contains("not a sha256"));
        assert!(
            image_program(r#"{"version":"2026.11.10-1"}"#, "2026.11.10-1", amd)
                .unwrap_err()
                .contains("lists no ozbox program")
        );
        assert!(image_program("nope", "x", amd).is_err());
        // a CLI manifest has its own shape and its own spellings
        let c = format!(
            r#"{{"version":"0.1.0","binaries":[{{"arch":"x86_64","asset":"ozbox-linux-x86_64","sha256":"{SHA_A}"}}]}}"#
        );
        assert_eq!(
            cli_program(&c, "0.1.0", amd).unwrap().asset,
            "ozbox-linux-x86_64"
        );
        assert!(cli_program(&c, "0.1.0", arm)
            .unwrap_err()
            .contains("aarch64"));
        assert!(cli_program(&c, "0.2.0", amd).is_err());
    }

    #[test]
    #[allow(clippy::expect_used, clippy::unwrap_used)]
    fn an_image_release_program_is_downloaded_from_a_private_repository_with_the_token_on_the_laptop_only(
    ) {
        let r = Arc::new(RecordingRunner::new());
        http(
            &r,
            200,
            r#"{"assets":[{"name":"ozbox-linux-amd64","url":"https://api.github.com/repos/example-org/example-repo/releases/assets/9"}]}"#,
        );
        r.reply(Output {
            status: Some(0),
            stdout: "\n200".into(),
            stderr: String::new(),
        });
        let v = ReleaseVerifier::with_env(r.clone(), "example-org/example-repo", |k| {
            (k == "GH_TOKEN").then(|| "tok-secret".to_string())
        });
        v.download_asset(
            ReleaseKind::Image,
            "2026.11.10-1",
            "ozbox-linux-amd64",
            Path::new("/tmp/ozbox-test-img"),
            30_000_000,
        )
        .expect("downloaded");
        let calls = r.calls();
        // the release is looked up by its image tag, and the file comes from the API address GitHub gave
        assert!(
            calls[0]
                .args
                .iter()
                .any(|a| a.ends_with("/releases/tags/image-v2026.11.10-1")),
            "{:?}",
            calls[0].args
        );
        let last = calls.last().unwrap();
        assert!(last.args.iter().any(|a| a.ends_with("/releases/assets/9")));
        // the program is limited by the size its caller names (about 21 MB, not the 5 MB of a manifest)
        assert!(last
            .args
            .windows(2)
            .any(|w| w[0] == "--max-filesize" && w[1] == "30000000"));
        // the token is on standard input only, in no argument of any call
        assert!(calls
            .iter()
            .all(|c| c.args.iter().all(|a| !a.contains("tok-secret"))));
        assert!(
            String::from_utf8_lossy(last.stdin.as_deref().unwrap_or_default())
                .contains("tok-secret")
        );
    }

    #[test]
    #[allow(clippy::expect_used, clippy::unwrap_used)]
    fn a_manifest_download_keeps_its_own_five_megabyte_limit() {
        let r = Arc::new(RecordingRunner::new());
        r.reply(Output {
            status: Some(1),
            ..Default::default()
        });
        r.reply(Output {
            status: Some(0),
            stdout: "{}\n200".into(),
            stderr: String::new(),
        });
        let _ = verifier(&r).signed_manifest(ReleaseKind::Image, "2026.11.10-1");
        let calls = r.calls();
        assert!(calls[1]
            .args
            .windows(2)
            .any(|w| w[0] == "--max-filesize" && w[1] == MANIFEST_MAX_BYTES.to_string()));
    }

    // ---- what a failure says ----------------------------------------------------------------------------------------------

    fn failing_get(status: Option<i32>, stdout: &str) -> Verdict {
        let r = Arc::new(RecordingRunner::new());
        r.reply(Output {
            status: Some(1),
            ..Default::default()
        }); // gh: not signed in
        r.reply(Output {
            status,
            stdout: stdout.into(),
            stderr: String::new(),
        });
        verifier(&r)
            .signed_manifest(ReleaseKind::Image, "2026.11.10-1")
            .map(|_| ())
            .unwrap_err()
    }

    #[test]
    fn a_failed_download_names_the_file_the_release_and_what_curl_meant() {
        let d = failing_get(Some(63), "").detail;
        assert!(
            d.contains("ozbox-image-manifest.json of release image-v2026.11.10-1"),
            "{d}"
        );
        assert!(d.contains("size limit") && d.contains("63"), "{d}");
        assert!(failing_get(Some(6), "").detail.contains("DNS"));
        assert!(failing_get(Some(28), "").detail.contains("timed out"));
        assert!(failing_get(Some(23), "").detail.contains("disk"));
        assert!(failing_get(Some(99), "").detail.contains("exit code 99"));
        // another HTTP status is shown as it came
        assert!(failing_get(Some(0), "x\n502").detail.contains("HTTP 502"));
        // none of them is the old "check the network" guess
        assert!(!failing_get(Some(63), "")
            .detail
            .contains("check the network"));
    }

    #[test]
    #[allow(clippy::expect_used, clippy::unwrap_used)]
    fn a_release_that_cannot_be_looked_up_says_which_release_not_the_release_of_release() {
        let r = Arc::new(RecordingRunner::new());
        http(&r, 404, "");
        let v = ReleaseVerifier::with_env(r.clone(), "example-org/example-repo", |k| {
            (k == "GH_TOKEN").then(|| "t".to_string())
        });
        let e = v
            .signed_manifest(ReleaseKind::Image, "2026.11.10-1")
            .unwrap_err();
        assert!(
            e.detail.starts_with(
                "the release image-v2026.11.10-1 was not found in example-org/example-repo"
            ),
            "{}",
            e.detail
        );
        assert!(
            !e.detail.contains("release of release") && !e.detail.contains("the release of"),
            "{}",
            e.detail
        );
        // and a CLI release is named as one
        let r = Arc::new(RecordingRunner::new());
        http(&r, 404, "");
        let v = ReleaseVerifier::with_env(r.clone(), "example-org/example-repo", |k| {
            (k == "GH_TOKEN").then(|| "t".to_string())
        });
        let e = v.signed_manifest(ReleaseKind::Cli, "0.1.0").unwrap_err();
        assert!(e.detail.contains("v0.1.0"), "{}", e.detail);
    }

    #[test]
    #[allow(clippy::expect_used, clippy::unwrap_used)]
    fn a_program_download_that_fails_names_the_program_and_its_release() {
        let r = Arc::new(RecordingRunner::new());
        r.reply(Output {
            status: Some(1),
            ..Default::default()
        }); // gh
        r.reply(Output {
            status: Some(63),
            stdout: String::new(),
            stderr: "maximum file size exceeded".into(),
        });
        let v = verifier(&r);
        let e = v
            .download_asset(
                ReleaseKind::Image,
                "2026.11.10-1",
                "ozbox-linux-amd64",
                Path::new("/tmp/x"),
                1000,
            )
            .unwrap_err();
        assert!(
            e.detail
                .contains("ozbox-linux-amd64 of release image-v2026.11.10-1")
                && e.detail.contains("size limit"),
            "{}",
            e.detail
        );
    }
}
