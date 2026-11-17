//! `ozbox admin <box> -- <action>`: the narrow, audited root path onto a box.
//!
//! The box user has no sudo and no port is open, so a person who must fix a box has no root of their own. Instead the box
//! runs a small helper as root that accepts a short, fixed list of actions (see ADR 0011) and records every request:
//!
//! * `reown [--from-uid N] [--from-gid N]`: put the box user's files on `/work` back under the box user.
//! * `reinstall-ozboxd [--sha256 HEX]`: install the box agent again from the signed image release, then restart it.
//! * `restart-services [NAME ...]`: restart the box agent and its helpers.
//! * `collect-logs`: the recent log lines of the box agent.
//! * `enable-linger`: let the box user's own services start at boot and keep running after logout.
//! * `ensure-supervisor [finish|rollback]`: give the dashboard a user of its own (ADR 0023).
//! * `configure-box-secrets`: read the box's secrets declaration again.
//! * `replace-tunnel-token`: a flow of this computer's rather than one request (see `tunnel_rotate`): a new tunnel token is handed
//!   over, watched, and the old one put back if the new tunnel is not healthy.
//!
//! There is no way through here to a shell, a path or a command. It is a change to a machine, so it is shown first and
//! confirmed like every other change (`--dry-run` stops after the description, `--yes` skips the question).

use std::io::{BufRead, IsTerminal, Write};
use std::sync::Arc;

use ozbox_core::{BoxName, BoxState, Provider, ReleaseKind, ReleaseVerifier, SystemRunner};
use serde::Serialize;

use super::{print_json, CliError, Flags, Result};
use crate::messages::t;
use crate::serve::agent::BoxAgent;

/// The services `restart-services` may restart: the same list the box's helper enforces.
pub const RESTARTABLE: [&str; 5] = [
    "ozboxd",
    "ozbox-tools.path",
    "ozbox-backup.path",
    "ozbox-growfs.timer",
    "ozbox-dashboard",
];

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AdminAction {
    Reown {
        from_uid: Option<u32>,
        from_gid: Option<u32>,
    },
    ReinstallOzboxd {
        sha256: Option<String>,
    },
    RestartServices {
        units: Vec<String>,
    },
    CollectLogs,
    EnableLinger,
    /// Give the dashboard a user of its own (ADR 0023); `finish` destroys the old copies, `rollback` puts the old one back.
    EnsureSupervisor {
        mode: Option<String>,
    },
    /// Read this box's secrets declaration (its instance tags) again and write the loader's settings.
    ConfigureBoxSecrets,
    /// Start a new secrets store on a box whose store can no longer be opened: its system disk was replaced and its key had
    /// no escrow (ADR 0028 Amendment 1). The box refuses while the service runs or the key is still there; nothing is deleted.
    RecoverSecrets,
    /// The box's own guards (ADR 0034, 0035): the egress list and the restart-after-patches rule. The words are checked
    /// here as they are on the box.
    HostGuard {
        what: HostGuard,
        /// A fresh approval for a change that lets the box do more than its rule in force (the box refuses one without).
        approval: Option<String>,
    },
}

/// One request to the box's guards.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HostGuard {
    EgressSet(crate::box_egress::Declaration),
    EgressRefresh,
    EgressReport,
    EgressMode,
    PatchSet(crate::patch_guard::Rule),
    PatchCheck,
    PatchStatus,
    /// Let only the machine's own services reach the instance metadata service (ADR 0029). Only ever tightens.
    MetadataInstall,
    /// Swap in compressed RAM, protected scores for the box's own services and soft limits for terminals (ADR 0045). Only ever
    /// tightens, restarts nothing.
    MemoryInstall,
    /// What the memory guard has in force.
    MemoryStatus,
}

impl HostGuard {
    /// `egress set|refresh|report|mode ...` or `patch set|check|status ...`, as words.
    pub fn parse(rest: &[String]) -> std::result::Result<Self, String> {
        let words: Vec<&str> = rest.iter().map(String::as_str).collect();
        match words.as_slice() {
            ["egress", "set", opts @ ..] => {
                let o: Vec<String> = opts.iter().map(|s| s.to_string()).collect();
                Ok(Self::EgressSet(crate::box_egress::Declaration::from_words(
                    &o,
                )?))
            }
            ["egress", "refresh"] => Ok(Self::EgressRefresh),
            ["egress", "report"] => Ok(Self::EgressReport),
            ["egress", "mode"] => Ok(Self::EgressMode),
            ["patch", "set", opts @ ..] => {
                let o: Vec<String> = opts.iter().map(|s| s.to_string()).collect();
                Ok(Self::PatchSet(crate::patch_guard::Rule::from_words(&o)?))
            }
            ["patch", "check"] => Ok(Self::PatchCheck),
            ["patch", "status"] => Ok(Self::PatchStatus),
            ["metadata", "install"] => Ok(Self::MetadataInstall),
            ["memory", "install"] => Ok(Self::MemoryInstall),
            ["memory", "status"] => Ok(Self::MemoryStatus),
            _ => Err(t("guard.err_words", &[])),
        }
    }

    pub fn words(&self) -> Vec<String> {
        let mut w: Vec<String> = Vec::new();
        match self {
            Self::EgressSet(d) => {
                w.extend(["egress".to_string(), "set".into()]);
                w.extend(d.to_words());
            }
            Self::EgressRefresh => w.extend(["egress".to_string(), "refresh".into()]),
            Self::EgressReport => w.extend(["egress".to_string(), "report".into()]),
            Self::EgressMode => w.extend(["egress".to_string(), "mode".into()]),
            Self::PatchSet(r) => {
                w.extend(["patch".to_string(), "set".into()]);
                w.extend(r.to_words());
            }
            Self::PatchCheck => w.extend(["patch".to_string(), "check".into()]),
            Self::PatchStatus => w.extend(["patch".to_string(), "status".into()]),
            Self::MetadataInstall => w.extend(["metadata".to_string(), "install".into()]),
            Self::MemoryInstall => w.extend(["memory".to_string(), "install".into()]),
            Self::MemoryStatus => w.extend(["memory".to_string(), "status".into()]),
        }
        w
    }

    fn describe(&self, name: &str) -> String {
        use crate::box_egress::Mode;
        match self {
            Self::EgressSet(d) => t(
                match d.mode {
                    Mode::Off => "guard.plan_egress_off",
                    Mode::Log => "guard.plan_egress_log",
                    Mode::Enforce => "guard.plan_egress_enforce",
                },
                &[
                    ("box", name),
                    ("presets", &d.presets.len().to_string()),
                    ("hosts", &d.hosts.len().to_string()),
                ],
            ),
            Self::EgressRefresh => t("guard.plan_egress_refresh", &[("box", name)]),
            Self::EgressReport | Self::EgressMode => {
                t("guard.plan_egress_report", &[("box", name)])
            }
            Self::PatchSet(_) => t("guard.plan_patch_set", &[("box", name)]),
            Self::PatchCheck | Self::PatchStatus => t("guard.plan_patch_read", &[("box", name)]),
            Self::MetadataInstall => t("guard.plan_metadata", &[("box", name)]),
            Self::MemoryInstall => t("guard.plan_memory", &[("box", name)]),
            Self::MemoryStatus => t("guard.plan_memory_status", &[("box", name)]),
        }
    }

    /// For a change: the approval project and the digest an approval for it is bound to (see `host_guard_cli`).
    pub fn approval_binding(&self) -> Option<(&'static str, String)> {
        match self {
            Self::EgressSet(_) => Some((
                "egress",
                crate::host_guard_cli::change_digest(&self.words()),
            )),
            Self::PatchSet(_) => {
                Some(("patch", crate::host_guard_cli::change_digest(&self.words())))
            }
            _ => None,
        }
    }
}

fn is_sha256(s: &str) -> bool {
    s.len() == 64 && s.chars().all(|c| matches!(c, '0'..='9' | 'a'..='f'))
}

fn old_id(flag: &str, v: Option<&String>) -> std::result::Result<u32, String> {
    match v.and_then(|v| v.parse::<u32>().ok()) {
        Some(n) if n != 0 => Ok(n),
        _ => Err(t("admin.err_old_id", &[("flag", flag)])),
    }
}

impl AdminAction {
    /// Read the words after `--`. Anything that is not on the list is refused here, before the box is contacted.
    pub fn parse(words: &[String]) -> std::result::Result<Self, String> {
        let (action, rest) = words
            .split_first()
            .ok_or_else(|| t("admin.err_none", &[]))?;
        match action.as_str() {
            "reown" => {
                let (mut from_uid, mut from_gid) = (None, None);
                let mut it = rest.iter();
                while let Some(flag) = it.next() {
                    match flag.as_str() {
                        "--from-uid" => from_uid = Some(old_id("--from-uid", it.next())?),
                        "--from-gid" => from_gid = Some(old_id("--from-gid", it.next())?),
                        other => {
                            return Err(t("admin.err_arg", &[("action", "reown"), ("arg", other)]))
                        }
                    }
                }
                Ok(Self::Reown { from_uid, from_gid })
            }
            "reinstall-ozboxd" => match rest {
                [] => Ok(Self::ReinstallOzboxd { sha256: None }),
                [flag, hex] if flag == "--sha256" && is_sha256(hex) => Ok(Self::ReinstallOzboxd {
                    sha256: Some(hex.clone()),
                }),
                _ => Err(t("admin.err_sha", &[])),
            },
            "restart-services" => {
                for u in rest {
                    if !RESTARTABLE.contains(&u.as_str()) {
                        return Err(t(
                            "admin.err_unit",
                            &[("unit", u), ("allowed", &RESTARTABLE.join(", "))],
                        ));
                    }
                }
                Ok(Self::RestartServices {
                    units: rest.to_vec(),
                })
            }
            "collect-logs" if rest.is_empty() => Ok(Self::CollectLogs),
            "enable-linger" if rest.is_empty() => Ok(Self::EnableLinger),
            "ensure-supervisor" => match rest {
                [] => Ok(Self::EnsureSupervisor { mode: None }),
                [m] if m == "finish" || m == "rollback" => Ok(Self::EnsureSupervisor {
                    mode: Some(m.clone()),
                }),
                _ => Err(t(
                    "admin.err_arg",
                    &[
                        ("action", "ensure-supervisor"),
                        ("arg", rest.first().map_or("", |s| s.as_str())),
                    ],
                )),
            },
            "host-guard" => {
                let (rest, approval) = crate::host_guard_cli::take_approval(rest)?;
                let what = HostGuard::parse(&rest)?;
                if approval.is_some() && what.approval_binding().is_none() {
                    return Err(t("guard.err_approval_read", &[]));
                }
                Ok(Self::HostGuard { what, approval })
            }
            "configure-box-secrets" if rest.is_empty() => Ok(Self::ConfigureBoxSecrets),
            "recover-secrets" if rest.is_empty() => Ok(Self::RecoverSecrets),
            "recover-secrets" => Err(t(
                "admin.err_arg",
                &[("action", "recover-secrets"), ("arg", &rest[0])],
            )),
            "configure-box-secrets" => Err(t(
                "admin.err_arg",
                &[("action", "configure-box-secrets"), ("arg", &rest[0])],
            )),
            "enable-linger" => Err(t(
                "admin.err_arg",
                &[("action", "enable-linger"), ("arg", &rest[0])],
            )),
            "collect-logs" => Err(t(
                "admin.err_arg",
                &[("action", "collect-logs"), ("arg", &rest[0])],
            )),
            other => Err(t("admin.err_unknown", &[("action", other)])),
        }
    }

    /// Whether the box's root helper needs an approval for this action (the helper's own table says the same).
    pub fn gate(&self) -> HelperGate {
        HELPER_ACTIONS
            .iter()
            .find(|(n, _)| *n == self.name())
            .map_or(HelperGate::Gated, |(_, g)| *g)
    }

    pub fn name(&self) -> &'static str {
        match self {
            Self::Reown { .. } => "reown",
            Self::ReinstallOzboxd { .. } => "reinstall-ozboxd",
            Self::RestartServices { .. } => "restart-services",
            Self::CollectLogs => "collect-logs",
            Self::EnableLinger => "enable-linger",
            Self::EnsureSupervisor { .. } => "ensure-supervisor",
            Self::ConfigureBoxSecrets => "configure-box-secrets",
            Self::RecoverSecrets => "recover-secrets",
            Self::HostGuard { .. } => "host-guard",
        }
    }

    /// The request as the box's helper reads it: plain words on one line.
    pub fn request_line(&self) -> String {
        match self {
            Self::Reown { from_uid, from_gid } => {
                let mut l = "reown".to_string();
                if let Some(u) = from_uid {
                    l.push_str(&format!(" --from-uid {u}"));
                }
                if let Some(g) = from_gid {
                    l.push_str(&format!(" --from-gid {g}"));
                }
                l
            }
            Self::ReinstallOzboxd { sha256 } => match sha256 {
                // the helper takes the hash as its one argument
                Some(h) => format!("reinstall-ozboxd {h}"),
                None => "reinstall-ozboxd".into(),
            },
            Self::RestartServices { units } => {
                if units.is_empty() {
                    "restart-services".into()
                } else {
                    format!("restart-services {}", units.join(" "))
                }
            }
            Self::CollectLogs => "collect-logs".into(),
            Self::EnableLinger => "enable-linger".into(),
            Self::EnsureSupervisor { mode: None } => "ensure-supervisor".into(),
            Self::EnsureSupervisor { mode: Some(m) } => format!("ensure-supervisor {m}"),
            Self::ConfigureBoxSecrets => "configure-box-secrets".into(),
            Self::RecoverSecrets => "recover-secrets".into(),
            Self::HostGuard { what, approval } => {
                let mut l = format!("host-guard {}", what.words().join(" "));
                if let Some(a) = approval {
                    l.push_str(&format!(" --approval {a}"));
                }
                l
            }
        }
    }

    /// What will happen, in words a person reads, before anything is done.
    pub fn describe(&self, name: &str) -> String {
        match self {
            Self::Reown { from_uid, from_gid } => t(
                "admin.plan_reown",
                &[
                    ("box", name),
                    (
                        "ids",
                        &match (from_uid, from_gid) {
                            (None, None) => {
                                "the one old owner it finds (it stops if there is more than one)"
                                    .to_string()
                            }
                            (u, g) => format!(
                                "owner {} and group {}",
                                u.map_or("as found".into(), |u| u.to_string()),
                                g.map_or("as found".into(), |g| g.to_string())
                            ),
                        },
                    ),
                ],
            ),
            Self::ReinstallOzboxd { .. } => t("admin.plan_reinstall", &[("box", name)]),
            Self::RestartServices { units } => t(
                "admin.plan_restart",
                &[
                    ("box", name),
                    (
                        "units",
                        &if units.is_empty() {
                            RESTARTABLE.join(", ")
                        } else {
                            units.join(", ")
                        },
                    ),
                ],
            ),
            Self::CollectLogs => t("admin.plan_logs", &[("box", name)]),
            Self::EnableLinger => t("admin.plan_linger", &[("box", name)]),
            Self::EnsureSupervisor { mode } => t(
                match mode.as_deref() {
                    Some("finish") => "admin.plan_supervisor_finish",
                    Some("rollback") => "admin.plan_supervisor_rollback",
                    _ => "admin.plan_supervisor",
                },
                &[("box", name)],
            ),
            Self::ConfigureBoxSecrets => t("admin.plan_box_secrets", &[("box", name)]),
            Self::RecoverSecrets => t("admin.plan_recover_secrets", &[("box", name)]),
            Self::HostGuard { what, approval } => {
                let mut d = what.describe(name);
                if let (Some((project, digest)), None) = (what.approval_binding(), approval) {
                    d.push(' ');
                    d.push_str(&t(
                        "guard.plan_needs_approval",
                        &[("box", name), ("project", project), ("digest", &digest)],
                    ));
                }
                d
            }
        }
    }
}

/// Whether one of the box's root-helper actions needs an approval the box user cannot make.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HelperGate {
    /// It cannot let the box do more than its owner set.
    Ungated,
    /// It needs an approval the box user cannot make; the box's program checks it before anything changes.
    Gated,
}

/// Every action the box's root helper takes, and its gate. The helper keeps the same table (`action_gates` in
/// `infra/cloud-init/scripts/ozbox-admin.sh`, with the reason for each) and refuses an action that is not in it; a test
/// compares the two, so a new action has to say which it is on both sides.
pub const HELPER_ACTIONS: &[(&str, HelperGate)] = &[
    ("reown", HelperGate::Ungated),
    ("reinstall-ozboxd", HelperGate::Ungated),
    ("restart-services", HelperGate::Ungated),
    ("collect-logs", HelperGate::Ungated),
    ("replace-tunnel-token", HelperGate::Gated),
    ("clear-tunnel-token", HelperGate::Gated),
    ("ensure-runner", HelperGate::Ungated),
    ("migrate-legacy-tunnel", HelperGate::Ungated),
    ("ensure-supervisor", HelperGate::Ungated),
    ("configure-box-secrets", HelperGate::Ungated),
    ("recover-secrets", HelperGate::Gated),
    ("host-guard", HelperGate::Gated),
    ("write-box-secrets", HelperGate::Gated),
    ("clear-box-secrets", HelperGate::Gated),
    ("place-bao-token", HelperGate::Gated),
    ("enable-linger", HelperGate::Ungated),
];

/// What a box's root helper from before the `kind-mismatch` state says to a service that is looping on one.
const OLD_HELPER_REFUSAL: &str = "the secrets service is running, so its store can be opened";

/// Why a recovery did not happen.
#[derive(Debug)]
pub enum RecoverError {
    Unreachable(crate::serve::agent::AgentError),
    /// The box refused (its words), or this computer cannot sign.
    Refused(String),
}

/// Set aside a box's secrets store that can no longer be opened (see `secrets_recover`): ask the box's root helper for a
/// one-time challenge, sign it with the key pinned when the box was made (this computer's keychain holds its private half),
/// and send the signature. The box checks everything else. Used by `ozbox admin <box> -- recover-secrets` and by
/// `ozbox upgrade` after a system-disk replacement the person accepted.
pub fn recover_secrets(
    agent: &dyn BoxAgent,
    rec: &ozbox_core::BoxRecord,
    keys: &dyn crate::secrets::SecretStore,
) -> std::result::Result<String, RecoverError> {
    use crate::secrets_recover::Challenge;
    let (ok, out) = agent
        .admin(rec, "recover-secrets challenge")
        .map_err(RecoverError::Unreachable)?;
    if !ok {
        // A box whose helper predates the mismatch state refuses a service that is only looping on it as "running, so its
        // store can be opened". Its program records nothing a person can act on, so say what to run instead.
        if out.contains(OLD_HELPER_REFUSAL)
            && matches!(agent.secrets_state(rec), Ok((Some(s), _))
                if s.text.contains(crate::secrets_enc::KEK_KIND_MISMATCH))
        {
            return Err(RecoverError::Refused(t(
                "admin.recover_old_helper",
                &[("box", rec.spec.name.as_str())],
            )));
        }
        return Err(RecoverError::Refused(out));
    }
    let c = Challenge::from_output(&out).ok_or_else(|| {
        RecoverError::Refused("the box did not answer with a challenge; nothing was changed".into())
    })?;
    let seed = keys
        .get(&format!(
            "{}{}",
            crate::approval_key::KEYCHAIN_PREFIX,
            c.key_id
        ))
        .ok()
        .flatten()
        .map(zeroize::Zeroizing::new)
        .ok_or_else(|| {
            RecoverError::Refused(format!(
                "this computer does not hold the key `{}` that was pinned when the box was made, so it cannot approve the recovery; run this from the computer that made the box. Nothing was changed",
                c.key_id
            ))
        })?;
    let sig = crate::approval_key::sign(&seed, &c.message()).map_err(RecoverError::Refused)?;
    let (ok, out) = agent
        .admin(
            rec,
            &format!("recover-secrets {} {} {sig}", c.nonce, c.expires_ms),
        )
        .map_err(RecoverError::Unreachable)?;
    if ok {
        Ok(out)
    } else {
        Err(RecoverError::Refused(out))
    }
}

/// The SHA-256 a signed image manifest lists for the box agent on `arch` (the manifest's additive key `ozboxd`).
pub fn agent_sha256(manifest_json: &str, arch: &str) -> Option<String> {
    let v: serde_json::Value = serde_json::from_str(manifest_json).ok()?;
    let hash = v.get("ozboxd")?.get(arch)?.as_str()?;
    is_sha256(hash).then(|| hash.to_string())
}

#[derive(Serialize)]
struct Outcome<'a> {
    #[serde(rename = "box")]
    box_name: &'a str,
    action: &'a str,
    applied: bool,
    dry_run: bool,
    ok: Option<bool>,
    output: Option<&'a str>,
    notes: &'a [String],
    /// The action needs an approval the box user cannot make (see [`HELPER_ACTIONS`]). Additive.
    gated: bool,
}

pub(super) fn ask(f: &Flags, name: &str) -> Result<()> {
    if f.yes {
        return Ok(());
    }
    if !std::io::stdin().is_terminal() {
        return Err(CliError::Msg(t("admin.err_confirm", &[("box", name)])));
    }
    let mut err = std::io::stderr();
    let _ = write!(err, "Proceed? [y/N] ");
    let _ = err.flush();
    let mut line = String::new();
    std::io::stdin()
        .lock()
        .read_line(&mut line)
        .map_err(|e| CliError::Core(e.into()))?;
    if matches!(line.trim().to_ascii_lowercase().as_str(), "y" | "yes") {
        Ok(())
    } else {
        Err(CliError::Msg("aborted; nothing was changed".into()))
    }
}

/// The consent for a step that loses data: the person types the box's NAME. `--yes` never stands for it (a script that passes
/// `--yes` to every prompt must not be able to say it), and anything but the exact name, an empty line or no terminal refuses.
pub(super) fn ask_name(f: &Flags, name: &str) -> Result<()> {
    let _ = f;
    if !std::io::stdin().is_terminal() {
        return Err(CliError::Msg(t("admin.err_confirm_name", &[("box", name)])));
    }
    let mut err = std::io::stderr();
    let _ = write!(
        err,
        "This loses data. Type the box's name ({name}) to go on: "
    );
    let _ = err.flush();
    let mut line = String::new();
    std::io::stdin()
        .lock()
        .read_line(&mut line)
        .map_err(|e| CliError::Core(e.into()))?;
    if name_confirms(&line, name) {
        Ok(())
    } else {
        Err(CliError::Msg(
            "the name did not match; aborted, nothing was changed".into(),
        ))
    }
}

/// Whether what was typed is exactly the box's name (surrounding space and the newline aside). Pure.
fn name_confirms(typed: &str, name: &str) -> bool {
    !name.is_empty() && typed.trim() == name
}

/// For `reinstall-ozboxd` without a hash: check the signed manifest of the box's image here, and hand the box the
/// hash it lists, so the box does not have to trust a download for it. Not being able to is a note, not a refusal: the
/// box then checks the release itself (signature when it has cosign, always the hash).
fn verified_hash(
    agent: &dyn BoxAgent,
    rec: &ozbox_core::BoxRecord,
    repo: &str,
) -> (Option<String>, Vec<String>) {
    let img = match agent.image_agent(rec) {
        Ok(i) => i,
        Err(e) => {
            return (
                None,
                vec![t("admin.note_unverified", &[("why", &e.to_string())])],
            )
        }
    };
    let (Some(version), Some(arch)) = (img.image_version, img.arch) else {
        return (
            None,
            vec![t(
                "admin.note_unverified",
                &[("why", "the box does not say which image release it is")],
            )],
        );
    };
    let verifier = ReleaseVerifier::new(Arc::new(SystemRunner), repo);
    match verifier.signed_manifest(ReleaseKind::Image, &version) {
        Ok(manifest) => match agent_sha256(&manifest, &arch) {
            Some(h) => (
                Some(h),
                vec![t("admin.note_verified", &[("version", &version)])],
            ),
            None => (
                None,
                vec![t(
                    "admin.note_unverified",
                    &[(
                        "why",
                        &format!("the signed manifest of {version} lists no ozboxd for {arch}"),
                    )],
                )],
            ),
        },
        Err(v) => (
            None,
            vec![t("admin.note_unverified", &[("why", &v.detail)])],
        ),
    }
}

pub(super) fn command(
    p: &dyn Provider,
    agent: &dyn BoxAgent,
    repo: &str,
    name: BoxName,
    words: Vec<String>,
    f: &Flags,
) -> Result<()> {
    let mut action = AdminAction::parse(&words).map_err(CliError::Msg)?;
    let rec = p
        .get(&name)?
        .ok_or_else(|| ozbox_core::Error::NotFound(name.to_string()))?;
    if rec.state != BoxState::Running {
        return Err(CliError::Msg(t(
            "admin.err_not_running",
            &[("box", name.as_str()), ("state", &rec.state.to_string())],
        )));
    }
    let mut notes: Vec<String> = Vec::new();
    if let AdminAction::ReinstallOzboxd { sha256: None } = &action {
        let (hash, n) = verified_hash(agent, &rec, repo);
        notes = n;
        action = AdminAction::ReinstallOzboxd { sha256: hash };
    }
    if !f.json {
        println!("{}", action.describe(name.as_str()));
        for n in &notes {
            println!("{n}");
        }
    }
    if f.dry_run {
        if !f.json {
            println!("{}", t("admin.dry_run", &[]));
        }
        return finish(f, &name, &action, false, true, None, None, &notes);
    }
    ask(f, name.as_str())?;
    let unreachable = |e: crate::serve::agent::AgentError| {
        CliError::Msg(t(
            "admin.err_unreachable",
            &[("box", name.as_str()), ("why", &e.to_string())],
        ))
    };
    let (ok, out) = if action == AdminAction::RecoverSecrets {
        // two requests: a challenge from the box, then this computer's pinned key's signature of it
        match recover_secrets(agent, &rec, crate::approval_key_cli::keychain().as_ref()) {
            Ok(out) => (true, out),
            Err(RecoverError::Unreachable(e)) => return Err(unreachable(e)),
            Err(RecoverError::Refused(out)) => (false, out),
        }
    } else {
        agent
            .admin(&rec, &action.request_line())
            .map_err(unreachable)?
    };
    if !f.json {
        println!("{out}");
    }
    finish(f, &name, &action, true, false, Some(ok), Some(&out), &notes)?;
    if ok {
        Ok(())
    } else {
        Err(CliError::Msg(t(
            "admin.err_failed",
            &[("box", name.as_str()), ("action", action.name())],
        )))
    }
}

#[allow(clippy::too_many_arguments)]
fn finish(
    f: &Flags,
    name: &BoxName,
    action: &AdminAction,
    applied: bool,
    dry_run: bool,
    ok: Option<bool>,
    output: Option<&str>,
    notes: &[String],
) -> Result<()> {
    if f.json {
        return print_json(&Outcome {
            box_name: name.as_str(),
            action: action.name(),
            applied,
            dry_run,
            ok,
            output,
            notes,
            gated: action.gate() == HelperGate::Gated,
        });
    }
    Ok(())
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    fn w(s: &str) -> Vec<String> {
        s.split_whitespace().map(str::to_string).collect()
    }

    /// R8: the consent for a step that loses data is the box's NAME, not "y".
    #[test]
    fn only_the_exact_box_name_confirms_a_step_that_loses_data() {
        assert!(name_confirms("main\n", "main"));
        assert!(name_confirms("  main \r\n", "main"));
        for typed in [
            "",
            "\n",
            "y",
            "yes",
            "Y",
            "Main",
            "main2",
            "ma",
            "main main",
        ] {
            assert!(!name_confirms(typed, "main"), "{typed:?}");
        }
        assert!(!name_confirms("", ""));
    }

    /// The box's root helper and this program keep one list of the helper's actions and whether each needs an approval
    /// (a security review, 2026-11-11: an action added after the gates were built went ungated). Every `case` arm of the
    /// helper is in its table, the table matches this one, and every action this command sends is in it.
    #[test]
    fn every_root_helper_action_says_whether_it_needs_an_approval_on_both_sides() {
        let script = include_str!("../../../../infra/cloud-init/scripts/ozbox-admin.sh");
        let table = script
            .split("action_gates=\"")
            .nth(1)
            .and_then(|r| r.split('"').next())
            .expect("the helper has its table");
        let theirs: Vec<(String, String)> = table
            .lines()
            .filter_map(|l| {
                let mut w = l.split_whitespace();
                Some((w.next()?.to_string(), w.next()?.to_string()))
            })
            .collect();
        let ours: Vec<(String, String)> = HELPER_ACTIONS
            .iter()
            .map(|(a, g)| {
                (
                    a.to_string(),
                    match g {
                        HelperGate::Gated => "gated",
                        HelperGate::Ungated => "ungated",
                    }
                    .to_string(),
                )
            })
            .collect();
        assert_eq!(theirs, ours);
        // the `case` arms of run_action: every one is in the table, and the table names no action without one
        let body = script
            .split("run_action() {")
            .nth(1)
            .and_then(|r| r.split("\nprocess_one()").next())
            .unwrap();
        let mut arms: Vec<String> = Vec::new();
        for l in body.lines() {
            let t = l.trim_start();
            if l.starts_with("    ")
                && !l.starts_with("     ")
                && t.ends_with(')')
                && !t.starts_with('*')
            {
                for a in t.trim_end_matches(')').split('|') {
                    arms.push(a.to_string());
                }
            }
        }
        let mut names: Vec<String> = ours.iter().map(|(a, _)| a.clone()).collect();
        arms.sort();
        names.sort();
        assert_eq!(arms, names, "the helper's case arms");
        // what this command can send
        let sent = [
            "reown",
            "reinstall-ozboxd",
            "restart-services",
            "collect-logs",
            "enable-linger",
            "ensure-supervisor",
            "configure-box-secrets",
            "recover-secrets",
            "host-guard egress report",
        ];
        for s in sent {
            let a = AdminAction::parse(&w(s)).unwrap();
            assert!(
                HELPER_ACTIONS.iter().any(|(n, _)| *n == a.name()),
                "{}",
                a.name()
            );
        }
        assert_eq!(
            HELPER_ACTIONS
                .iter()
                .find(|(n, _)| *n == "recover-secrets")
                .map(|(_, g)| *g),
            Some(HelperGate::Gated)
        );
    }

    #[test]
    fn only_the_listed_actions_parse() {
        assert_eq!(
            AdminAction::parse(&w("reown --from-uid 1000 --from-gid 1000")),
            Ok(AdminAction::Reown {
                from_uid: Some(1000),
                from_gid: Some(1000)
            })
        );
        assert_eq!(
            AdminAction::parse(&w("collect-logs")),
            Ok(AdminAction::CollectLogs)
        );
        assert_eq!(
            AdminAction::parse(&w("enable-linger")),
            Ok(AdminAction::EnableLinger)
        );
        for bad in [
            "bash -c id",
            "reown --from-uid 0",
            "reown --from-uid abc",
            "reown --path /etc",
            "restart-services ssh",
            "reinstall-ozboxd --sha256 nothex",
            "collect-logs extra",
            "enable-linger root",
            "",
        ] {
            assert!(
                AdminAction::parse(&w(bad)).is_err(),
                "{bad} must be refused"
            );
        }
    }

    #[test]
    fn the_request_is_plain_words_the_box_helper_accepts() {
        let line = AdminAction::Reown {
            from_uid: Some(1000),
            from_gid: None,
        }
        .request_line();
        assert_eq!(line, "reown --from-uid 1000");
        let h = "a".repeat(64);
        assert_eq!(
            AdminAction::ReinstallOzboxd {
                sha256: Some(h.clone())
            }
            .request_line(),
            format!("reinstall-ozboxd {h}")
        );
        for a in [
            AdminAction::CollectLogs,
            AdminAction::RestartServices {
                units: vec!["ozboxd".into()],
            },
        ] {
            assert!(a
                .request_line()
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || matches!(c, ' ' | '.' | '_' | '-')));
        }
    }

    #[test]
    fn the_signed_manifest_lists_the_agent_hash_per_architecture() {
        let h = "b".repeat(64);
        let m = format!(
            r#"{{"version":"2026.11.09","images":[],"ozboxd":{{"amd64":"{h}","arm64":"{}"}}}}"#,
            "c".repeat(64)
        );
        assert_eq!(agent_sha256(&m, "amd64"), Some(h));
        assert_eq!(agent_sha256(&m, "arm64"), Some("c".repeat(64)));
        assert_eq!(agent_sha256(&m, "riscv"), None);
        // an older manifest has no such key, and a malformed hash is not a hash
        assert_eq!(agent_sha256(r#"{"version":"x"}"#, "amd64"), None);
        assert_eq!(agent_sha256(r#"{"ozboxd":{"amd64":"zz"}}"#, "amd64"), None);
        assert_eq!(agent_sha256("not json", "amd64"), None);
    }
}
