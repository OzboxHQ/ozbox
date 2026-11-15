//! The catalog's data model, its parser and its validator.

use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};

pub const CATALOG_SCHEMA: u32 = 1;

/// The machine architectures a box can have.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Arch {
    Amd64,
    Arm64,
}

impl Arch {
    pub fn as_str(self) -> &'static str {
        match self {
            Arch::Amd64 => "amd64",
            Arch::Arm64 => "arm64",
        }
    }

    /// The architecture this binary runs on, if it is one a box can have.
    pub fn host() -> Option<Arch> {
        match std::env::consts::ARCH {
            "x86_64" => Some(Arch::Amd64),
            "aarch64" => Some(Arch::Arm64),
            _ => None,
        }
    }
}

/// How the source of a tool is checked before anything from it is used.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Verification {
    /// A package from the operating system's own signed archive.
    AptArchive,
    /// A vendor apt repository whose signing key is accepted only if its fingerprint matches the one the vendor
    /// publishes in its own documentation.
    AptKeyFingerprint,
    /// A download whose SHA-256 is read from a checksum file the vendor publishes, or is pinned in this catalog from the
    /// digest the vendor publishes on the release itself.
    VendorChecksum,
    /// A package registry (npm, PyPI, crates.io) that checks the package's own integrity hash.
    RegistryIntegrity,
    /// Nothing is installed on the box; the client that needs it installs it.
    ClientManaged,
    /// Could not be verified. Never installed.
    Unverified,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum UpdateHow {
    /// The tool updates itself (its own updater, or its package manager inside the user's home).
    SelfUpdate,
    /// System updates: unattended upgrades on the box, for the repository's origin.
    Apt,
    /// Only when the person installs it again from the Tools page.
    Manual,
    /// The client that installed it keeps it current.
    Client,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Updates {
    pub how: UpdateHow,
    /// One sentence a person can read: how it updates and what they can do.
    pub detail: String,
}

impl Default for Updates {
    fn default() -> Self {
        Updates {
            how: UpdateHow::Manual,
            detail: "Not installable yet, so there is nothing to update.".into(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Group {
    pub id: String,
    pub name: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Bundle {
    pub id: String,
    pub name: String,
    pub description: String,
    pub tools: Vec<String>,
}

/// How to tell whether a tool is present, and which version.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Detect {
    /// A program name looked for in the usual directories (never executed to find it).
    pub bin: String,
    /// argv that prints the version; the first dotted number in its output is the version.
    #[serde(default)]
    pub version_cmd: Vec<String>,
}

/// A file a downloaded archive provides, linked into `~/.local/bin`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Bin {
    pub name: String,
    /// Path inside the extracted directory.
    pub path: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Extract {
    /// The download is the program itself.
    None,
    TarXz,
    TarGz,
    /// A zstd-compressed tar archive. Unpacked by `tar` with the box's own `zstd` program, which the tool installs from the
    /// operating system's signed archive first.
    TarZst,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ChecksumFormat {
    /// `<sha256>  <file name>` lines, as `sha256sum` writes them.
    #[default]
    Sums,
    /// The file holds just the hash.
    Single,
}

/// One thing to do to install or remove a tool. The `arch` filter (empty = every architecture) is how a tool has a
/// different method per architecture.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StepDef {
    #[serde(default)]
    pub arch: Vec<Arch>,
    #[serde(flatten)]
    pub step: Step,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum Step {
    /// Packages from the operating system's archive.
    AptInstall {
        packages: Vec<String>,
    },
    AptRemove {
        packages: Vec<String>,
    },
    /// A vendor apt repository, accepted only if every key in its key file is one the vendor publishes a fingerprint for,
    /// then packages from it.
    AptRepo {
        name: String,
        key_url: String,
        key_fingerprints: Vec<String>,
        uri: String,
        suite: String,
        components: Vec<String>,
        packages: Vec<String>,
    },
    AptRepoRemove {
        name: String,
        packages: Vec<String>,
    },
    /// `npm install -g` into the box user's home (no root).
    Npm {
        package: String,
    },
    NpmRemove {
        package: String,
    },
    /// `pipx install` into the box user's home.
    Pipx {
        package: String,
    },
    PipxRemove {
        package: String,
    },
    /// `uv tool install` into the box user's home.
    Uv {
        package: String,
        #[serde(default)]
        python: Option<String>,
        #[serde(default)]
        with: Vec<String>,
    },
    UvRemove {
        package: String,
    },
    /// `cargo install` into the box user's home.
    Cargo {
        packages: Vec<String>,
        #[serde(default = "yes")]
        locked: bool,
    },
    CargoRemove {
        packages: Vec<String>,
    },
    /// A fixed command run as the box user (for example choosing a default toolchain). Never takes input.
    Run {
        argv: Vec<String>,
        title: String,
    },
    /// A vendor download, checked against a checksum file the vendor publishes, extracted into the box user's home.
    Release {
        /// A text file whose first line is the version, e.g. `v1.2.3`. Absent: the version comes from the asset name.
        #[serde(default)]
        version_url: Option<String>,
        /// Directory URL; may contain `{version}` and `{arch}`.
        base_url: String,
        /// Asset file name; may contain `{version}` and `{arch}`, and one `*` to be matched in the checksum file.
        asset: String,
        /// Checksum file URL; may contain `{version}`, `{arch}` and `{asset}`. Empty when `pinned_sha256` covers every
        /// architecture.
        #[serde(default)]
        checksum_url: String,
        #[serde(default)]
        checksum_format: ChecksumFormat,
        /// The SHA-256 of this exact file for each architecture, pinned here from the vendor's published release. When
        /// set it is the checksum, instead of a file fetched from the same place as the download.
        #[serde(default)]
        pinned_sha256: BTreeMap<Arch, String>,
        extract: Extract,
        /// How many leading path components to drop when extracting.
        #[serde(default)]
        strip: u8,
        /// What the vendor's naming calls each architecture (`x64`, `amd64`, ...).
        arch_names: BTreeMap<Arch, String>,
        #[serde(default)]
        bins: Vec<Bin>,
    },
    /// Delete these paths under the box user's home (relative, no `..`).
    UserRemove {
        paths: Vec<String>,
    },
    /// Nothing to do on the box; the note says why.
    ClientManaged {
        note: String,
    },
}

fn yes() -> bool {
    true
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Tool {
    pub id: String,
    pub name: String,
    pub group: String,
    pub description: String,
    /// The vendor's own page for the tool.
    pub homepage: String,
    /// Where the install steps were taken from: the vendor documentation page.
    pub source: String,
    pub verified: bool,
    /// Part of the small base every box ships with (it is in the image). Checklists show it ticked and it can be removed.
    #[serde(default)]
    pub default: bool,
    /// Required when `verified` is false: what could not be verified.
    #[serde(default)]
    pub unverified_reason: Option<String>,
    pub verification: Verification,
    pub size_mb: u32,
    #[serde(default)]
    pub updates: Updates,
    #[serde(default)]
    pub requires: Vec<String>,
    /// Architectures this tool is offered for (empty = both).
    #[serde(default)]
    pub arch: Vec<Arch>,
    #[serde(default)]
    pub detect: Option<Detect>,
    #[serde(default)]
    pub post_install: Option<String>,
    #[serde(default)]
    pub install: Vec<StepDef>,
    #[serde(default)]
    pub remove: Vec<StepDef>,
}

impl Tool {
    pub fn supports(&self, arch: Arch) -> bool {
        self.arch.is_empty() || self.arch.contains(&arch)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Catalog {
    pub schema: u32,
    pub version: String,
    #[serde(default, rename(serialize = "groups", deserialize = "group"))]
    pub groups: Vec<Group>,
    #[serde(default, rename(serialize = "bundles", deserialize = "bundle"))]
    pub bundles: Vec<Bundle>,
    #[serde(default, rename(serialize = "tools", deserialize = "tool"))]
    pub tools: Vec<Tool>,
}

pub const BUNDLE_PREFIX: &str = "bundle:";

impl Catalog {
    pub fn parse(text: &str) -> Result<Catalog, String> {
        let c: Catalog = toml::from_str(text).map_err(|e| format!("catalog: {e}"))?;
        c.validate()?;
        Ok(c)
    }

    pub fn tool(&self, id: &str) -> Option<&Tool> {
        self.tools.iter().find(|t| t.id == id)
    }

    pub fn bundle(&self, id: &str) -> Option<&Bundle> {
        self.bundles.iter().find(|b| b.id == id)
    }

    /// Tool ids and `bundle:<id>` names to a flat, de-duplicated list of tool ids, in the order given.
    pub fn expand(&self, items: &[String]) -> Result<Vec<String>, String> {
        let mut out: Vec<String> = Vec::new();
        for item in items {
            let ids: Vec<String> = match item.strip_prefix(BUNDLE_PREFIX) {
                Some(b) => self
                    .bundle(b)
                    .ok_or_else(|| format!("no bundle named {b}"))?
                    .tools
                    .clone(),
                None => vec![item.clone()],
            };
            for id in ids {
                if self.tool(&id).is_none() {
                    return Err(format!("no tool named {id}"));
                }
                if !out.contains(&id) {
                    out.push(id);
                }
            }
        }
        Ok(out)
    }

    /// Every rule the catalog must keep. Run on load, so a broken catalog never reaches an installer.
    pub fn validate(&self) -> Result<(), String> {
        if self.schema != CATALOG_SCHEMA {
            return Err(format!("catalog schema {} is not supported", self.schema));
        }
        let mut ids = BTreeSet::new();
        let group_ids: BTreeSet<&str> = self.groups.iter().map(|g| g.id.as_str()).collect();
        if group_ids.len() != self.groups.len() {
            return Err("catalog: duplicate group id".into());
        }
        for t in &self.tools {
            if !is_id(&t.id) {
                return Err(format!(
                    "tool id {:?} must be lowercase letters, digits and hyphens",
                    t.id
                ));
            }
            if !ids.insert(t.id.as_str()) {
                return Err(format!("duplicate tool id {}", t.id));
            }
            if !group_ids.contains(t.group.as_str()) {
                return Err(format!("{}: unknown group {}", t.id, t.group));
            }
            if t.name.trim().is_empty() || t.description.trim().is_empty() {
                return Err(format!("{}: name and description are required", t.id));
            }
            if !t.homepage.starts_with("https://") || !t.source.starts_with("https://") {
                return Err(format!("{}: homepage and source must be https URLs", t.id));
            }
            if t.verified && t.updates.detail.trim().is_empty() {
                return Err(format!("{}: say how it updates", t.id));
            }
            if t.default && !t.verified {
                return Err(format!("{}: a default tool must be verified", t.id));
            }
            if t.verified {
                if t.verification == Verification::Unverified {
                    return Err(format!(
                        "{}: verified tools need a verification method",
                        t.id
                    ));
                }
                if t.install.is_empty() {
                    return Err(format!("{}: a verified tool needs install steps", t.id));
                }
                if t.remove.is_empty() {
                    return Err(format!("{}: a verified tool needs remove steps", t.id));
                }
                if t.detect.is_none() && t.verification != Verification::ClientManaged {
                    return Err(format!("{}: a verified tool needs a detect program", t.id));
                }
            } else {
                if t.verification != Verification::Unverified {
                    return Err(format!(
                        "{}: unverified tools must say so in `verification`",
                        t.id
                    ));
                }
                if t.unverified_reason
                    .as_deref()
                    .unwrap_or("")
                    .trim()
                    .is_empty()
                {
                    return Err(format!("{}: an unverified tool needs a reason", t.id));
                }
                if !t.install.is_empty() {
                    return Err(format!(
                        "{}: an unverified tool carries no install steps",
                        t.id
                    ));
                }
            }
            if let Some(d) = &t.detect {
                if !is_program(&d.bin) {
                    return Err(format!("{}: bad detect program", t.id));
                }
                check_argv(&t.id, &d.version_cmd)?;
            }
            for r in &t.requires {
                if self.tool(r).is_none() {
                    return Err(format!("{}: requires unknown tool {r}", t.id));
                }
                if *r == t.id {
                    return Err(format!("{}: requires itself", t.id));
                }
            }
            for s in t.install.iter().chain(&t.remove) {
                check_step(&t.id, &s.step)?;
            }
            // Every supported architecture must have a way to install.
            for arch in [Arch::Amd64, Arch::Arm64] {
                if t.verified
                    && t.supports(arch)
                    && !t
                        .install
                        .iter()
                        .any(|s| s.arch.is_empty() || s.arch.contains(&arch))
                {
                    return Err(format!("{}: no install step for {}", t.id, arch.as_str()));
                }
            }
        }
        // Dependency cycles.
        for t in &self.tools {
            let mut seen = BTreeSet::new();
            let mut stack: Vec<&str> = t.requires.iter().map(String::as_str).collect();
            while let Some(n) = stack.pop() {
                if n == t.id {
                    return Err(format!("{}: dependency cycle", t.id));
                }
                if seen.insert(n) {
                    if let Some(d) = self.tool(n) {
                        stack.extend(d.requires.iter().map(String::as_str));
                    }
                }
            }
        }
        let mut bundle_ids = BTreeSet::new();
        for b in &self.bundles {
            if !is_id(&b.id) || !bundle_ids.insert(b.id.as_str()) {
                return Err(format!("bundle id {:?} is invalid or duplicated", b.id));
            }
            if b.tools.is_empty() {
                return Err(format!("bundle {} is empty", b.id));
            }
            for m in &b.tools {
                let Some(t) = self.tool(m) else {
                    return Err(format!("bundle {}: no tool named {m}", b.id));
                };
                if !t.verified {
                    return Err(format!("bundle {}: {m} is not verified", b.id));
                }
            }
        }
        Ok(())
    }
}

pub fn is_id(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= 40
        && s.bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
        && !s.starts_with('-')
        && !s.ends_with('-')
}

fn is_program(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= 64
        && s.bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.' | b'+'))
}

/// A Debian package name.
pub fn is_apt_name(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= 100
        && s.as_bytes()[0].is_ascii_alphanumeric()
        && s.bytes().all(|b| {
            b.is_ascii_lowercase() || b.is_ascii_digit() || matches!(b, b'+' | b'-' | b'.')
        })
}

/// A registry package name (npm scoped or not, PyPI, crates.io).
pub fn is_package_name(s: &str) -> bool {
    let body = s.strip_prefix('@').unwrap_or(s);
    !s.is_empty()
        && s.len() <= 100
        && !s.contains("..")
        && body
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.' | b'/' | b'~'))
        && s.matches('/').count() <= usize::from(s.starts_with('@'))
}

pub fn is_https_url(s: &str) -> bool {
    let Some(rest) = s.strip_prefix("https://") else {
        return false;
    };
    let host = rest.split('/').next().unwrap_or("");
    !host.is_empty()
        && !host.contains('@')
        && host
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'-' | b':'))
        && s.bytes().all(|b| (0x21..0x7f).contains(&b))
}

fn check_argv(tool: &str, argv: &[String]) -> Result<(), String> {
    if argv
        .iter()
        .any(|a| a.is_empty() || a.contains('\0') || a.len() > 400)
    {
        return Err(format!("{tool}: bad command line"));
    }
    Ok(())
}

fn check_pkgs(tool: &str, pkgs: &[String]) -> Result<(), String> {
    if pkgs.is_empty() {
        return Err(format!("{tool}: an empty package list"));
    }
    if let Some(bad) = pkgs.iter().find(|p| !is_apt_name(p)) {
        return Err(format!("{tool}: {bad:?} is not a package name"));
    }
    Ok(())
}

fn check_reg(tool: &str, p: &str) -> Result<(), String> {
    if is_package_name(p) {
        Ok(())
    } else {
        Err(format!("{tool}: {p:?} is not a package name"))
    }
}

fn check_step(tool: &str, s: &Step) -> Result<(), String> {
    match s {
        Step::AptInstall { packages } | Step::AptRemove { packages } => check_pkgs(tool, packages),
        Step::AptRepo {
            name,
            key_url,
            key_fingerprints,
            uri,
            suite,
            components,
            packages,
        } => {
            if !is_id(name) {
                return Err(format!("{tool}: bad repository name"));
            }
            if !is_https_url(key_url) || !is_https_url(uri) {
                return Err(format!("{tool}: repository URLs must be https"));
            }
            if key_fingerprints.is_empty()
                || key_fingerprints.iter().any(|f| {
                    f.len() != 40
                        || !f
                            .bytes()
                            .all(|b| b.is_ascii_digit() || (b'A'..=b'F').contains(&b))
                })
            {
                return Err(format!(
                    "{tool}: the key fingerprint must be 40 uppercase hex digits"
                ));
            }
            if suite.is_empty()
                || !suite
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'.'))
            {
                return Err(format!("{tool}: bad suite"));
            }
            if components.is_empty()
                || components.iter().any(|c| {
                    c.is_empty() || !c.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-')
                })
            {
                return Err(format!("{tool}: bad components"));
            }
            check_pkgs(tool, packages)
        }
        Step::AptRepoRemove { name, packages } => {
            if !is_id(name) {
                return Err(format!("{tool}: bad repository name"));
            }
            check_pkgs(tool, packages)
        }
        Step::Npm { package }
        | Step::NpmRemove { package }
        | Step::Pipx { package }
        | Step::PipxRemove { package }
        | Step::UvRemove { package } => check_reg(tool, package),
        Step::Uv {
            package,
            python,
            with,
        } => {
            check_reg(tool, package)?;
            if let Some(p) = python {
                if !is_program(p) {
                    return Err(format!("{tool}: bad python name"));
                }
            }
            with.iter().try_for_each(|w| check_reg(tool, w))
        }
        Step::Cargo { packages, .. } | Step::CargoRemove { packages } => {
            if packages.is_empty() {
                return Err(format!("{tool}: an empty crate list"));
            }
            packages.iter().try_for_each(|p| check_reg(tool, p))
        }
        Step::Run { argv, title } => {
            if argv.is_empty() || title.is_empty() {
                return Err(format!("{tool}: a run step needs a command and a title"));
            }
            check_argv(tool, argv)
        }
        Step::Release {
            version_url,
            base_url,
            asset,
            checksum_url,
            arch_names,
            bins,
            extract,
            pinned_sha256,
            ..
        } => {
            // Either a checksum file, or a digest pinned for every architecture the release names.
            let pinned_all = !pinned_sha256.is_empty()
                && arch_names.keys().all(|a| pinned_sha256.contains_key(a));
            if !pinned_sha256.is_empty() {
                if !pinned_all {
                    return Err(format!("{tool}: pin a checksum for every architecture"));
                }
                if pinned_sha256
                    .values()
                    .any(|d| d.len() != 64 || !d.bytes().all(|b| b.is_ascii_hexdigit()))
                {
                    return Err(format!("{tool}: a pinned checksum is 64 hex digits"));
                }
                if asset.contains('*') || version_url.is_some() {
                    return Err(format!(
                        "{tool}: a pinned checksum names one exact file, with no wildcard"
                    ));
                }
            } else if checksum_url.is_empty() {
                return Err(format!(
                    "{tool}: a release needs a checksum file or pinned checksums"
                ));
            }
            let urls = [base_url]
                .into_iter()
                .chain((!checksum_url.is_empty()).then_some(checksum_url))
                .chain(version_url.iter());
            for u in urls {
                if !is_https_url(u) {
                    return Err(format!("{tool}: release URLs must be https"));
                }
            }
            if asset.is_empty()
                || asset.contains('/')
                || asset.matches('*').count() > 1
                || !asset.bytes().all(|b| (0x21..0x7f).contains(&b))
            {
                return Err(format!("{tool}: bad asset name"));
            }
            if arch_names.is_empty() {
                return Err(format!("{tool}: a release needs its architecture names"));
            }
            if bins.is_empty() {
                return Err(format!(
                    "{tool}: a release needs at least one program to link"
                ));
            }
            for b in bins {
                if !is_program(&b.name) || !safe_rel(&b.path) {
                    return Err(format!("{tool}: bad program link"));
                }
            }
            if *extract == Extract::None && bins.len() != 1 {
                return Err(format!(
                    "{tool}: a single-file download links exactly one program"
                ));
            }
            Ok(())
        }
        Step::UserRemove { paths } => {
            if paths.is_empty() || paths.iter().any(|p| !safe_rel(p)) {
                return Err(format!(
                    "{tool}: paths to remove must be relative and stay inside the home"
                ));
            }
            Ok(())
        }
        Step::ClientManaged { note } => {
            if note.is_empty() {
                Err(format!("{tool}: say why nothing is installed"))
            } else {
                Ok(())
            }
        }
    }
}

/// A relative path with no `..`, no absolute start and no odd characters.
pub fn safe_rel(p: &str) -> bool {
    !p.is_empty()
        && !p.starts_with('/')
        && p.len() <= 200
        && p.split('/').all(|c| !c.is_empty() && c != "..")
        && p.bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.' | b'/' | b'+'))
}
