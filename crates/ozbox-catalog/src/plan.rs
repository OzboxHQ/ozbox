//! Turning "install these, remove those" into a plan: an ordered list of concrete steps.
//!
//! Planning never mutates anything and never touches the network. The executor (in the box daemon) runs exactly what is
//! in the plan, and a privileged helper recomputes the same plan from the catalog compiled into its own binary, so what
//! runs as root can only ever be a catalog step.

use std::collections::BTreeSet;

use serde::{Deserialize, Serialize};

use crate::model::{Arch, Bin, Catalog, ChecksumFormat, Extract, Step, StepDef};
use crate::verify::sha256_hex;

/// Replaced with the box user's home directory when a step runs.
pub const HOME_TOKEN: &str = "{home}";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Op {
    Install,
    Remove,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Privilege {
    /// Runs through the narrow privileged helper (package manager steps only).
    Root,
    /// Runs as the box user, inside a capped run.
    User,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum Action {
    AptUpdate,
    AptInstall {
        packages: Vec<String>,
    },
    AptRemove {
        packages: Vec<String>,
    },
    /// Fetch the key, accept it only if every key in it is a pinned one, write the keyring and the source, allow
    /// unattended upgrades for that origin, and update the package lists.
    AptRepo {
        name: String,
        key_url: String,
        fingerprints: Vec<String>,
        uri: String,
        suite: String,
        components: Vec<String>,
    },
    AptRepoRemove {
        name: String,
    },
    Exec {
        argv: Vec<String>,
    },
    Release {
        tool: String,
        version_url: Option<String>,
        base_url: String,
        asset: String,
        checksum_url: String,
        checksum_format: ChecksumFormat,
        /// The digest pinned in the catalog for this machine's architecture: when set it is the checksum.
        #[serde(default)]
        pinned_sha256: Option<String>,
        extract: Extract,
        strip: u8,
        /// The vendor's name for this machine's architecture.
        arch_name: String,
        bins: Vec<Bin>,
    },
    UserRemove {
        paths: Vec<String>,
    },
    Note {
        text: String,
    },
}

impl Action {
    pub fn privilege(&self) -> Privilege {
        match self {
            Action::AptUpdate
            | Action::AptInstall { .. }
            | Action::AptRemove { .. }
            | Action::AptRepo { .. }
            | Action::AptRepoRemove { .. } => Privilege::Root,
            _ => Privilege::User,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PlanStep {
    pub index: usize,
    pub tool: String,
    pub op: Op,
    pub title: String,
    pub privilege: Privilege,
    pub action: Action,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PlanTool {
    pub id: String,
    pub name: String,
    pub op: Op,
    pub size_mb: u32,
    /// `requested`, or `required_by:<id>` for a dependency added to the plan.
    pub reason: String,
    pub post_install: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Plan {
    pub catalog_version: String,
    pub arch: Arch,
    pub tools: Vec<PlanTool>,
    pub steps: Vec<PlanStep>,
    /// Requested installs that were already present and are left alone.
    pub already_installed: Vec<String>,
    /// Requested removals of tools that are not installed.
    pub not_installed: Vec<String>,
    /// Installed (counted against this plan): the download size of what will be added.
    pub total_size_mb: u32,
    pub needs_root: bool,
    /// Identifies this plan; `apply` refuses one that no longer matches.
    pub hash: String,
}

impl Plan {
    pub fn is_noop(&self) -> bool {
        self.steps.is_empty()
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PlanRequest {
    #[serde(default)]
    pub install: Vec<String>,
    #[serde(default)]
    pub remove: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PlanError {
    Unknown(String),
    /// A tool whose source could not be verified is never planned.
    Unverified {
        id: String,
        reason: String,
    },
    UnsupportedArch {
        id: String,
        arch: Arch,
    },
    StillRequired {
        id: String,
        by: String,
    },
    Conflict(String),
    Empty,
}

impl PlanError {
    /// A stable machine code for the API.
    pub fn code(&self) -> &'static str {
        match self {
            PlanError::Unknown(_) => "unknown_tool",
            PlanError::Unverified { .. } => "unverified_tool",
            PlanError::UnsupportedArch { .. } => "unsupported_arch",
            PlanError::StillRequired { .. } => "still_required",
            PlanError::Conflict(_) => "conflict",
            PlanError::Empty => "bad_request",
        }
    }
}

impl std::fmt::Display for PlanError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            PlanError::Unknown(id) => write!(f, "there is no tool named {id}"),
            PlanError::Unverified { id, reason } => write!(
                f,
                "{id} cannot be installed yet because its source is not verified: {reason}"
            ),
            PlanError::UnsupportedArch { id, arch } => {
                write!(f, "{id} is not available for {} boxes", arch.as_str())
            }
            PlanError::StillRequired { id, by } => {
                write!(
                    f,
                    "{id} is needed by {by}; remove {by} as well to remove it"
                )
            }
            PlanError::Conflict(id) => write!(f, "{id} is both installed and removed in one plan"),
            PlanError::Empty => write!(f, "choose at least one tool"),
        }
    }
}

impl std::error::Error for PlanError {}

fn applies(def: &StepDef, arch: Arch) -> bool {
    def.arch.is_empty() || def.arch.contains(&arch)
}

fn join(items: &[String]) -> String {
    items.join(", ")
}

/// The concrete actions for one catalog step.
fn expand(tool: &str, step: &Step, arch: Arch) -> Result<Vec<(String, Action)>, PlanError> {
    let home_local = format!("{HOME_TOKEN}/.local");
    let exec = |title: String, argv: Vec<String>| vec![(title, Action::Exec { argv })];
    let s = |x: &str| x.to_string();
    Ok(match step {
        Step::AptInstall { packages } => vec![
            ("Update the package lists".to_string(), Action::AptUpdate),
            (
                format!("Install {} from the system packages", join(packages)),
                Action::AptInstall {
                    packages: packages.clone(),
                },
            ),
        ],
        Step::AptRemove { packages } => vec![(
            format!("Remove {}", join(packages)),
            Action::AptRemove {
                packages: packages.clone(),
            },
        )],
        Step::AptRepo {
            name,
            key_url,
            key_fingerprints,
            uri,
            suite,
            components,
            packages,
        } => vec![
            (
                format!(
                    "Add the {name} package source (key checked against its published fingerprint)"
                ),
                Action::AptRepo {
                    name: name.clone(),
                    key_url: key_url.clone(),
                    fingerprints: key_fingerprints.clone(),
                    uri: uri.clone(),
                    suite: suite.clone(),
                    components: components.clone(),
                },
            ),
            (
                format!("Install {} from {name}", join(packages)),
                Action::AptInstall {
                    packages: packages.clone(),
                },
            ),
        ],
        Step::AptRepoRemove { name, packages } => vec![
            (
                format!("Remove {}", join(packages)),
                Action::AptRemove {
                    packages: packages.clone(),
                },
            ),
            (
                format!("Remove the {name} package source"),
                Action::AptRepoRemove { name: name.clone() },
            ),
        ],
        Step::Npm { package } => exec(
            format!("Install {package} with npm"),
            vec![
                s("npm"),
                s("install"),
                s("-g"),
                s("--prefix"),
                home_local,
                package.clone(),
            ],
        ),
        Step::NpmRemove { package } => exec(
            format!("Remove {package} with npm"),
            vec![
                s("npm"),
                s("uninstall"),
                s("-g"),
                s("--prefix"),
                home_local,
                package.clone(),
            ],
        ),
        Step::Pipx { package } => exec(
            format!("Install {package} with pipx"),
            vec![s("pipx"), s("install"), package.clone()],
        ),
        Step::PipxRemove { package } => exec(
            format!("Remove {package} with pipx"),
            vec![s("pipx"), s("uninstall"), package.clone()],
        ),
        Step::Uv {
            package,
            python,
            with,
        } => {
            let mut argv = vec![s("uv"), s("tool"), s("install")];
            if let Some(p) = python {
                argv.extend([s("--python"), p.clone()]);
            }
            for w in with {
                argv.extend([s("--with"), w.clone()]);
            }
            argv.push(package.clone());
            exec(format!("Install {package} with uv"), argv)
        }
        Step::UvRemove { package } => exec(
            format!("Remove {package} with uv"),
            vec![s("uv"), s("tool"), s("uninstall"), package.clone()],
        ),
        Step::Cargo { packages, locked } => {
            let mut argv = vec![s("cargo"), s("install")];
            if *locked {
                argv.push(s("--locked"));
            }
            argv.extend(packages.iter().cloned());
            exec(
                format!(
                    "Build and install {} with cargo (this can take several minutes)",
                    join(packages)
                ),
                argv,
            )
        }
        Step::CargoRemove { packages } => {
            let mut argv = vec![s("cargo"), s("uninstall")];
            argv.extend(packages.iter().cloned());
            exec(format!("Remove {} with cargo", join(packages)), argv)
        }
        Step::Run { argv, title } => exec(title.clone(), argv.clone()),
        Step::Release {
            version_url,
            base_url,
            asset,
            checksum_url,
            checksum_format,
            pinned_sha256,
            extract,
            strip,
            arch_names,
            bins,
        } => {
            let arch_name =
                arch_names
                    .get(&arch)
                    .cloned()
                    .ok_or_else(|| PlanError::UnsupportedArch {
                        id: tool.to_string(),
                        arch,
                    })?;
            vec![(
                format!("Download {tool} from its vendor, check its checksum, and unpack it"),
                Action::Release {
                    tool: tool.to_string(),
                    version_url: version_url.clone(),
                    base_url: base_url.clone(),
                    asset: asset.clone(),
                    checksum_url: checksum_url.clone(),
                    checksum_format: *checksum_format,
                    pinned_sha256: pinned_sha256.get(&arch).cloned(),
                    extract: *extract,
                    strip: *strip,
                    arch_name,
                    bins: bins.clone(),
                },
            )]
        }
        Step::UserRemove { paths } => vec![(
            format!("Delete {}", join(paths)),
            Action::UserRemove {
                paths: paths.clone(),
            },
        )],
        Step::ClientManaged { note } => vec![(note.clone(), Action::Note { text: note.clone() })],
    })
}

fn push_tool_steps(
    steps: &mut Vec<PlanStep>,
    tool: &str,
    op: Op,
    defs: &[StepDef],
    arch: Arch,
) -> Result<(), PlanError> {
    for def in defs.iter().filter(|d| applies(d, arch)) {
        for (title, action) in expand(tool, &def.step, arch)? {
            // An update right after a repository was added (it updates the lists itself), or twice in a row, is noise.
            if matches!(action, Action::AptUpdate) {
                if let Some(prev) = steps.last() {
                    if matches!(prev.action, Action::AptUpdate | Action::AptRepo { .. }) {
                        continue;
                    }
                }
            }
            let privilege = action.privilege();
            steps.push(PlanStep {
                index: steps.len(),
                tool: tool.to_string(),
                op,
                title,
                privilege,
                action,
            });
        }
    }
    Ok(())
}

/// Plan an installation and/or a removal. `installed` is what is on the box now (the caller detects it).
pub fn build_plan(
    catalog: &Catalog,
    arch: Arch,
    installed: &BTreeSet<String>,
    req: &PlanRequest,
) -> Result<Plan, PlanError> {
    if req.install.is_empty() && req.remove.is_empty() {
        return Err(PlanError::Empty);
    }
    for id in req.install.iter().chain(&req.remove) {
        if catalog.tool(id).is_none() {
            return Err(PlanError::Unknown(id.clone()));
        }
    }
    if let Some(c) = req.install.iter().find(|i| req.remove.contains(i)) {
        return Err(PlanError::Conflict(c.clone()));
    }

    let mut tools: Vec<PlanTool> = Vec::new();
    let mut steps: Vec<PlanStep> = Vec::new();
    let mut already = Vec::new();
    let mut not_installed = Vec::new();

    // Installs: dependencies first, each tool once.
    let mut order: Vec<(String, String)> = Vec::new(); // (id, reason)
    fn visit(
        catalog: &Catalog,
        id: &str,
        reason: &str,
        order: &mut Vec<(String, String)>,
        arch: Arch,
    ) -> Result<(), PlanError> {
        if order.iter().any(|(i, _)| i == id) {
            return Ok(());
        }
        let t = catalog
            .tool(id)
            .ok_or_else(|| PlanError::Unknown(id.to_string()))?;
        if !t.verified {
            return Err(PlanError::Unverified {
                id: id.to_string(),
                reason: t.unverified_reason.clone().unwrap_or_default(),
            });
        }
        if !t.supports(arch) {
            return Err(PlanError::UnsupportedArch {
                id: id.to_string(),
                arch,
            });
        }
        for r in &t.requires {
            visit(catalog, r, &format!("required_by:{id}"), order, arch)?;
        }
        order.push((id.to_string(), reason.to_string()));
        Ok(())
    }
    for id in &req.install {
        visit(catalog, id, "requested", &mut order, arch)?;
    }
    for (id, reason) in &order {
        let t = catalog
            .tool(id)
            .ok_or_else(|| PlanError::Unknown(id.clone()))?;
        if installed.contains(id) {
            if reason == "requested" {
                already.push(id.clone());
            }
            continue;
        }
        push_tool_steps(&mut steps, id, Op::Install, &t.install, arch)?;
        tools.push(PlanTool {
            id: id.clone(),
            name: t.name.clone(),
            op: Op::Install,
            size_mb: t.size_mb,
            reason: reason.clone(),
            post_install: t.post_install.clone(),
        });
    }

    // Removals: a tool another installed tool needs stays unless that one goes too.
    let removing: BTreeSet<&String> = req.remove.iter().collect();
    for id in &req.remove {
        for other in catalog.tools.iter().filter(|o| installed.contains(&o.id)) {
            if other.requires.contains(id) && !removing.contains(&other.id) {
                return Err(PlanError::StillRequired {
                    id: id.clone(),
                    by: other.id.clone(),
                });
            }
        }
    }
    // Dependents are removed before what they need.
    let mut remove_order: Vec<&String> = req.remove.iter().collect();
    remove_order.sort_by_key(|id| {
        std::cmp::Reverse(
            catalog
                .tool(id)
                .map(|t| t.requires.len())
                .unwrap_or_default(),
        )
    });
    for id in remove_order {
        let t = catalog
            .tool(id)
            .ok_or_else(|| PlanError::Unknown(id.clone()))?;
        if !installed.contains(id) {
            not_installed.push(id.clone());
            continue;
        }
        push_tool_steps(&mut steps, id, Op::Remove, &t.remove, arch)?;
        tools.push(PlanTool {
            id: id.clone(),
            name: t.name.clone(),
            op: Op::Remove,
            size_mb: 0,
            reason: "requested".into(),
            post_install: None,
        });
    }

    let total_size_mb = tools
        .iter()
        .filter(|t| t.op == Op::Install)
        .map(|t| t.size_mb)
        .sum();
    let needs_root = steps.iter().any(|s| s.privilege == Privilege::Root);
    let hash = {
        let body = serde_json::to_string(&(&catalog.version, arch, &steps)).unwrap_or_default();
        sha256_hex(body.as_bytes())[..16].to_string()
    };
    Ok(Plan {
        catalog_version: catalog.version.clone(),
        arch,
        tools,
        steps,
        already_installed: already,
        not_installed,
        total_size_mb,
        needs_root,
        hash,
    })
}
