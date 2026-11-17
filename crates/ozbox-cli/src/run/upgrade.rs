//! `ozbox upgrade`: replace a box's system disk from a newer image, keep `/work`, then wait for the box to answer and
//! show its own self-test.
//!
//! The provider part (stop, replace, reattach, start) is the shared engine's `Operation::Upgrade`, so it is planned,
//! confirmed and applied like every other change. Two steps need the box's own agent, which the engine does not have,
//! so they live here and in the dashboard server: saving work in progress before the stop (best effort, and said
//! plainly when it could not be done) and, afterwards, waiting for the agent and running the self-test.

use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use ozbox_core::{BoxName, BoxRecord, BoxState, ImageInfo, Operation, Plan, Provider};
use serde::Serialize;

use super::{confirm, finish_with, guard_rails, load_settings, CliError, Flags, Result};
use crate::messages::t;
use crate::serve::agent::{AgentError, BoxAgent, BoxFirstBoot, Outcome, SelfTest};
use crate::sshconfig::{self, RouteInputs};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum StepOutcome {
    Done,
    /// Not done, and that is fine (nothing to do, or it cannot be done from here). The detail says why.
    Skipped,
    Failed,
}

/// One thing the command did around the provider's change, in words a person reads.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Step {
    pub outcome: StepOutcome,
    pub detail: String,
}

impl Step {
    pub(crate) fn new(outcome: StepOutcome, detail: impl Into<String>) -> Self {
        Self {
            outcome,
            detail: detail.into(),
        }
    }
}

fn report_ready(ready: &Step) -> bool {
    ready.outcome != StepOutcome::Failed
}

/// What happened around the provider's change. Additive to the plan's own JSON shape.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Report {
    /// The image the box was upgraded to.
    pub image: String,
    pub checkpoint: Step,
    /// Whether the box's agent answered after the upgrade.
    pub ready: Step,
    pub selftest: Option<SelfTest>,
    /// Backup settings and credentials live on the system disk. With a repository set up in Settings -> Backups they are
    /// put back after the self-test (`done`); otherwise, or if that fails, this says exactly what to put back.
    pub backup_credentials: Step,
    /// The web IDE, the desktop and the IDE's tunnel connector you had set up through ozbox: their units and files live on
    /// `/work` and come back by themselves, but a service that is not running after the upgrade is set up again from the
    /// passwords and the tunnel token kept in this computer's secret store. Additive.
    pub services: Step,
    /// The hosted dashboard (`ozbox dashboard install`): its tunnel token and install settings are kept on this computer, and an
    /// upgrade puts it back from them. `done` when it runs again, `failed` when it needs you (the step says the one command),
    /// `skipped` when no dashboard is kept for this box. Additive.
    pub dashboard: Step,
    /// The box memory guard (ADR 0045): swap in compressed RAM, protected scores for the box's own services and soft limits for
    /// terminals, put on the box live, with nothing restarted. Additive.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub memory_guard: Option<Step>,
    /// Your SSH entry for the box (`~/.ssh/ozbox/config`) and the old machine's host key: an upgrade gives the box a new
    /// machine, so both are brought up to date. Additive.
    pub ssh_entry: Step,
    /// What happened to the box's secrets store, as the plan said it would (see [`StoreCheck`]). Additive.
    pub secrets_store: StoreCheck,
    /// When the person accepted a new store: the old one set aside on the new machine and a new one started. Additive.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub secrets_recovery: Option<Step>,
    /// Laptop keys the box trusts that may have been enrolled by the box user under older rules (see
    /// [`review_signers`]). Additive.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub approvers: Option<Step>,
    /// The copy of the old system disk the upgrade kept because the store's key could not be shown to survive (see
    /// [`OldDisk`]), or the statement that none was. Additive.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub old_system_disk: Option<Step>,
    /// The id of that copy (an EBS snapshot on AWS). Additive.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub old_system_disk_snapshot: Option<String>,
}

/// What an upgrade does to the box's secrets store. Its system disk is replaced and `/work` is kept, so the store's copy
/// on `/work` comes back; whether the new machine can open it depends on where the store's key is.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum StoreFate {
    /// The key is in KMS, a TPM or a passphrase: the store opens on the new machine.
    Kept,
    /// A file-kept key with a copy escrowed in the box's vault: the service fetches it back.
    KeptByEscrow,
    /// A file-kept key with a copy in this computer's keychain (`ozbox secrets ingress escrow`): the upgrade puts it back
    /// through the ingress route after the machine is replaced.
    KeptByLaptop,
    /// The box's secrets service is older and does not say. Boxes from before this release keep a copy of a file-kept key
    /// on /work, which this upgrade uses once and then removes; after it, the box says.
    NotSaid,
    /// A file-kept key with no copy anywhere: the new machine cannot open the store and starts a new one.
    Lost,
    /// The store already cannot be opened (the service stopped for that): the upgrade loses nothing more.
    AlreadyLost,
    /// The box could not be asked.
    Unknown,
    /// No real box behind this provider (the simulated one).
    NotApplicable,
    /// The box is moving its store to the fleet's KMS key (`ozbox adopt-fleet-key`) and has not said it finished: a new
    /// machine configured for KMS over a store the file key still seals would never open it. Never accepted: finish or
    /// cancel the move first.
    MovingKey,
    /// The store cannot be opened where it is, but a copy of its file key IS held (this computer's keychain or the box's vault),
    /// so the old store is not lost: setting it aside (renamed, never deleted) leaves the key where it is, and the store can be
    /// reopened later (see "Recovering an old secrets store" in the keeping-boxes-healthy use case). Refused without
    /// `--accept-new-secrets-store`; with it the upgrade sets the old store aside and starts a new one on the fleet's key, which is the
    /// only path that works from here (`adopt-fleet-key` refuses a box whose service is not ready). Additive.
    KeyHeld,
}

/// The `Err` a root-facts reader gives when the box answered in a shape this program does not know.
pub const ROOT_OLDER: &str = "the box's answer is in a shape this ozbox does not know";

/// What the plan says about the store, and why.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct StoreCheck {
    pub fate: StoreFate,
    pub detail: String,
}

/// What a person must enter again when a box starts a new secrets store.
const NEW_STORE_LOSES: &str = "the tunnel tokens, the backup repository credentials, project keys imported with `ozbox secrets import`, model and channel keys saved in the dashboard, laptop keys enrolled after the box was made, and the record that a passkey is enrolled (the dashboard asks for one again). Kept: /work, the box's own secrets in its vault, and the approval key pinned when the box was made. This upgrade puts back, from this computer, the backup credentials, the web IDE's tunnel token and the hosted dashboard (its install settings and tunnel token) when this computer holds them. If it does not hold the backup credentials, backups on the box STOP: the self-test fails and the report gives the command that sends them (`ozbox backup credentials <box>`). The dashboard's token can need your approval first, and the report then says the one command";

/// What the box's ROOT says about its store, read through the cloud's root channel (AWS Systems Manager). `Err` is why it
/// could not be read. Only an AWS box has one.
pub type RootFacts<'a> =
    &'a dyn Fn(&BoxRecord) -> std::result::Result<crate::secrets_adopt_facts::Facts, String>;

/// The store's fate from what the box's root said. The SSH answer decides nothing here: the box user can make it say `kept` or
/// `escrowed` about a store a replaced system disk would lose.
fn store_fate_from_root(
    name: &str,
    f: &crate::secrets_adopt_facts::Facts,
    laptop_escrow: bool,
) -> StoreCheck {
    use crate::secrets_adopt_facts::Kek;
    let check = |fate, detail: String| StoreCheck { fate, detail };
    if f.service_no_escrow {
        return check(
            StoreFate::AlreadyLost,
            t("upgrade.store_already_lost", &[("box", name)]),
        );
    }
    // A box that answers the root facts is not a legacy box, and has no copy of a file-kept key on /work: what its service does
    // not say is never "kept" (`NotSaid` is for the SSH answer of a service so old it has no state at all). So a service that is
    // not ready, or does not say what keeps its store or whether a copy is escrowed, is UNKNOWN, which an upgrade refuses
    // without `--accept-new-secrets-store`.
    let unknown = |key: &str| check(StoreFate::Unknown, t(key, &[("box", name)]));
    if !f.service_ready {
        return unknown("upgrade.store_root_not_ready");
    }
    match (f.service_kek, f.service_escrow) {
        // this computer's keychain holds a copy of the file-kept key (the box's ingress escrow): the store is kept, whatever the
        // box says about its own copy (that is its word, and this is a fact of this computer)
        (Kek::File, Some(false) | None) if laptop_escrow => check(
            StoreFate::KeptByLaptop,
            t("upgrade.store_laptop", &[("box", name)]),
        ),
        (Kek::File, Some(false)) => check(
            StoreFate::Lost,
            t(
                "upgrade.store_lost",
                &[("box", name), ("lost", NEW_STORE_LOSES)],
            ),
        ),
        (Kek::File, Some(true)) => check(
            StoreFate::KeptByEscrow,
            t("upgrade.store_escrowed", &[("box", name)]),
        ),
        // the fleet's KMS key is a fact of the cloud's own record (the label, checked before this), not of a box's word
        (Kek::Kms, _) => check(
            StoreFate::Unknown,
            t("upgrade.store_kms_unlabelled", &[("box", name)]),
        ),
        (Kek::Other, _) => check(
            StoreFate::Kept,
            t(
                "upgrade.store_kept",
                &[
                    ("box", name),
                    ("key", "a key that is not a file on the system disk"),
                ],
            ),
        ),
        (Kek::File, None) | (Kek::None, _) => unknown("upgrade.store_root_unsaid"),
    }
}

/// Whether the box's root says its store is sealed by a file key that is gone, under a configuration for another kind of key:
/// nothing on the box can open it (the service's `kind-mismatch` and `no-escrow` states, and the same facts when an older program
/// recorded no state for them). Read from what root reports, so it holds whichever program wrote the state.
fn store_cannot_open(f: &crate::secrets_adopt_facts::Facts) -> bool {
    use crate::secrets_adopt_facts::Kek;
    f.service_no_escrow
        || (!f.service_ready
            && f.store_kek == Kek::File
            && !f.key_file
            && (f.settings_key.is_some() || f.service_kek == Kek::Kms))
}

/// The store's fate for a box whose record carries the fleet's KMS key (`arn`): "kept" only when the box's root says the service is
/// ready on that key and the store and its copy on `/work` are sealed by it. `facts` is `None` when there is no root channel
/// (the label alone never decides) and `Some(Err)` when the box could not be asked.
fn kms_labelled_store_check(
    name: &str,
    arn: &str,
    facts: Option<std::result::Result<crate::secrets_adopt_facts::Facts, String>>,
    laptop_escrow: bool,
) -> StoreCheck {
    use crate::secrets_adopt_facts::Kek;
    let check = |fate, detail: String| StoreCheck { fate, detail };
    let unknown =
        |key: &str, why: &str| check(StoreFate::Unknown, t(key, &[("box", name), ("why", why)]));
    let f = match facts {
        None => return unknown("upgrade.store_kms_no_root", ""),
        Some(Err(why)) if why == ROOT_OLDER => {
            return check(
                StoreFate::Unknown,
                t("upgrade.store_root_older", &[("box", name)]),
            )
        }
        Some(Err(why)) => return unknown("upgrade.store_kms_unasked", &why),
        Some(Ok(f)) => f,
    };
    if store_cannot_open(&f) {
        // "no copy held anywhere" is a claim about two places the facts name: this computer's keychain and the box's vault.
        // Either holding the key means the store is NOT lost, so it is never called lost and never offered to be set aside.
        let held = if laptop_escrow {
            Some("in this computer's keychain")
        } else if f.service_escrow == Some(true) {
            Some("in the box's vault")
        } else {
            None
        };
        if let Some(held) = held {
            return check(
                StoreFate::KeyHeld,
                t(
                    "upgrade.store_kms_key_held",
                    &[("box", name), ("held", held)],
                ),
            );
        }
        return check(
            StoreFate::AlreadyLost,
            t("upgrade.store_kms_unopenable", &[("box", name)]),
        );
    }
    if !f.service_ready {
        return unknown("upgrade.store_kms_not_ready", "");
    }
    if f.store_kek == Kek::File || f.persist_kek == Kek::File || f.service_kek == Kek::File {
        return check(
            StoreFate::Lost,
            t(
                "upgrade.store_kms_file_sealed",
                &[("box", name), ("lost", NEW_STORE_LOSES)],
            ),
        );
    }
    let on_this_key = f.service_kek == Kek::Kms
        && f.store_kek == Kek::Kms
        && f.persist_kek == Kek::Kms
        && f.settings_key.as_deref() == Some(arn)
        && !f.busy
        && !f.cancelled;
    if on_this_key {
        return check(
            StoreFate::Kept,
            t("upgrade.store_kms", &[("box", name), ("key", arn)]),
        );
    }
    unknown("upgrade.store_kms_unconfirmed", "")
}

/// Ask the box, before anything is replaced, where its secrets store's key is (see `secrets_state`). On AWS (`root` is
/// `Some`) the answer comes from the box's root through Systems Manager, and when that cannot answer the store is "unknown",
/// never "kept"; elsewhere it is the box user's SSH answer, which is all there is. `laptop_escrow` is whether this computer's
/// keychain holds a copy of the box's file-kept store key (on either path, it keeps a file-kept store).
pub fn store_check(
    agent: &dyn BoxAgent,
    rec: &BoxRecord,
    simulated: bool,
    laptop_escrow: bool,
    root: Option<RootFacts<'_>>,
) -> StoreCheck {
    let name = rec.spec.name.as_str();
    let check = |fate, detail: String| StoreCheck { fate, detail };
    if simulated {
        return check(StoreFate::NotApplicable, t("upgrade.store_simulated", &[]));
    }
    // a box in the middle of moving its store to the fleet's key (the pending mark): neither fate is true yet
    if rec
        .spec
        .labels
        .contains_key(ozbox_provider_aws::SECRETS_ADOPT_LABEL)
    {
        return check(
            StoreFate::MovingKey,
            t("upgrade.store_moving", &[("box", name)]),
        );
    }
    if rec.state != BoxState::Running {
        return check(
            StoreFate::Unknown,
            t(
                "upgrade.store_not_running",
                &[("box", name), ("state", &rec.state.to_string())],
            ),
        );
    }
    // A box made with, or moved to, the fleet's KMS key carries it in its labels, and its upgrade gives the new machine that key.
    // The label says which key the NEW machine gets; it does not say that the store opens under it. A store sealed by a file key
    // that is gone, or a service that is not ready, behind a correct label is what a person was told was "kept" on 2026-11-16, so
    // the verdict is read from the box's root, never from the label alone.
    if let Some(arn) = rec.spec.labels.get(ozbox_provider_aws::SECRETS_KEY_LABEL) {
        return kms_labelled_store_check(name, arn, root.map(|r| r(rec)), laptop_escrow);
    }
    if let Some(root) = root {
        return match root(rec) {
            Ok(f) => store_fate_from_root(name, &f, laptop_escrow),
            // The copy in this computer's keychain is a fact of this computer, as it was before the root channel existed (every box
            // made since the ingress route has one, and every such box is older than the root read): when the root cannot answer,
            // the store is still kept by this computer, and the upgrade puts it back. Without a copy the store is unknown.
            Err(_) if laptop_escrow => check(
                StoreFate::KeptByLaptop,
                t("upgrade.store_laptop_root_unconfirmed", &[("box", name)]),
            ),
            Err(why) if why == ROOT_OLDER => check(
                StoreFate::Unknown,
                t("upgrade.store_root_older", &[("box", name)]),
            ),
            Err(why) => check(
                StoreFate::Unknown,
                t(
                    "upgrade.store_root_unreachable",
                    &[("box", name), ("why", &why)],
                ),
            ),
        };
    }
    match agent.secrets_state(rec) {
        Err(AgentError::Unsupported(_)) => {
            check(StoreFate::NotApplicable, t("upgrade.store_simulated", &[]))
        }
        Err(AgentError::Unreachable(why)) => check(
            StoreFate::Unknown,
            t("upgrade.store_unreachable", &[("box", name), ("why", &why)]),
        ),
        Ok((None, _)) => check(
            StoreFate::NotSaid,
            t("upgrade.store_not_said", &[("box", name)]),
        ),
        Ok((Some(st), _)) if st.is_unopenable() => check(
            StoreFate::AlreadyLost,
            t("upgrade.store_already_lost", &[("box", name)]),
        ),
        // The box user can make this answer say anything. A box whose store is on the fleet's KMS key carries its label (checked
        // above, from the cloud's own record), so an UNLABELLED box saying "kms" is not believed: it may be forging it to be
        // reported as kept while its key is a file. It is "unknown", which an upgrade refuses without `--accept-new-secrets-store`.
        Ok((Some(st), _)) if st.kek.as_deref() == Some("kms") => check(
            StoreFate::Unknown,
            t("upgrade.store_kms_unlabelled", &[("box", name)]),
        ),
        Ok((Some(st), _)) => match (st.kek.as_deref(), st.escrow) {
            (Some("file"), Some(false)) if laptop_escrow => check(
                StoreFate::KeptByLaptop,
                t("upgrade.store_laptop", &[("box", name)]),
            ),
            (Some("file"), Some(false)) => check(
                StoreFate::Lost,
                t(
                    "upgrade.store_lost",
                    &[("box", name), ("lost", NEW_STORE_LOSES)],
                ),
            ),
            (Some("file"), Some(true)) => check(
                StoreFate::KeptByEscrow,
                t("upgrade.store_escrowed", &[("box", name)]),
            ),
            (Some("file"), None) | (None, _) => check(
                StoreFate::NotSaid,
                t("upgrade.store_not_said", &[("box", name)]),
            ),
            (Some(k), _) => check(
                StoreFate::Kept,
                t("upgrade.store_kept", &[("box", name), ("key", k)]),
            ),
        },
    }
}

/// The error code the dashboard's API answers an upgrade refused for the store's sake with. A box that is moving its store gets
/// a code of its own: the dashboard offers "accept a new store" for `secrets_store_lost`, which does not apply to it.
pub fn store_refusal_code(fate: StoreFate) -> &'static str {
    match fate {
        StoreFate::MovingKey => "secrets_key_moving",
        StoreFate::KeyHeld => "secrets_key_held",
        _ => "secrets_store_lost",
    }
}

/// `ozbox upgrade --use-fleet-key`: a box moves from a key kept in a file to the fleet's KMS key only if its store holds
/// nothing (so nothing is lost), the box said so itself, and it is not already on a key. `Err` is the refusal, in words.
pub fn fleet_key_gate(
    agent: &dyn BoxAgent,
    rec: &BoxRecord,
    simulated: bool,
    root: Option<RootFacts<'_>>,
) -> std::result::Result<(), String> {
    let name = rec.spec.name.as_str();
    if simulated {
        return Err(t("upgrade.fleet_key_simulated", &[]));
    }
    // a move that is under way is neither "a file key" nor "on KMS": it is checked before anything else
    if rec
        .spec
        .labels
        .contains_key(ozbox_provider_aws::SECRETS_ADOPT_LABEL)
    {
        return Err(t("upgrade.store_moving", &[("box", name)]));
    }
    if rec
        .spec
        .labels
        .contains_key(ozbox_provider_aws::SECRETS_KEY_LABEL)
    {
        return Err(t("upgrade.fleet_key_already", &[("box", name)]));
    }
    if rec.state != BoxState::Running {
        return Err(t("upgrade.fleet_key_not_running", &[("box", name)]));
    }
    let unknown = || Err(t("upgrade.fleet_key_unknown", &[("box", name)]));
    // On AWS the answer is the box's ROOT's (Systems Manager), never the box user's SSH answer: a forged `names=0` would make an
    // upgrade replace a store that is not empty.
    if let Some(root) = root {
        use crate::secrets_adopt_facts::Kek;
        return match root(rec) {
            Err(why) if why == ROOT_OLDER => Err(t("upgrade.fleet_key_older", &[("box", name)])),
            Err(_) => unknown(),
            Ok(f) if !f.service_ready => unknown(),
            Ok(f) if f.service_kek != Kek::File => Err(t(
                "upgrade.fleet_key_not_file",
                &[("box", name), ("kek", "another key")],
            )),
            Ok(f) => match f.names {
                Some(0) => Ok(()),
                Some(n) => Err(t(
                    "upgrade.fleet_key_not_empty",
                    &[("box", name), ("n", &n.to_string())],
                )),
                None => unknown(),
            },
        };
    }
    match agent.secrets_state(rec) {
        Ok((Some(st), _)) if st.kek.as_deref() == Some("file") && st.names == Some(0) => Ok(()),
        Ok((Some(st), _)) if st.kek.as_deref() != Some("file") => Err(t(
            "upgrade.fleet_key_not_file",
            &[
                ("box", name),
                ("kek", st.kek.as_deref().unwrap_or("unknown")),
            ],
        )),
        Ok((Some(st), _)) if st.names.is_some() => Err(t(
            "upgrade.fleet_key_not_empty",
            &[("box", name), ("n", &st.names.unwrap_or(0).to_string())],
        )),
        _ => unknown(),
    }
}

/// What an upgrade does about a copy of the OLD system disk, which holds the store's key when that key is a file. The key
/// is destroyed with the disk, so when the plan cannot show that the store's key survives, a copy is kept by default.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OldDisk {
    /// Keep a copy when the store's fate calls for it (this provider can, and the person did not opt out).
    Keep,
    /// The person turned it off (`--no-pre-upgrade-snapshot`).
    OptedOut,
    /// This provider cannot keep one.
    NotOffered,
    /// The store is known to be empty (`--use-fleet-key`): there is no key worth keeping.
    StoreEmpty,
}

impl OldDisk {
    /// The choice for one upgrade: only the AWS provider keeps a copy of a system disk.
    pub fn choose(provider_id: &str, opted_out: bool, store_empty: bool) -> Self {
        if store_empty {
            Self::StoreEmpty
        } else if opted_out {
            Self::OptedOut
        } else if provider_id == ozbox_provider_aws::PROVIDER_ID {
            Self::Keep
        } else {
            Self::NotOffered
        }
    }
}

/// Whether the plan takes a copy of the old system disk: the store's key is a file on that disk, or ozbox cannot tell where
/// it is. A store that is kept (by KMS, escrow or this computer's keychain), or already lost, needs none.
pub fn old_disk_copy_wanted(fate: StoreFate, old_disk: OldDisk) -> bool {
    old_disk == OldDisk::Keep && matches!(fate, StoreFate::Lost | StoreFate::Unknown)
}

/// The block printed BEFORE the confirmation (never only a plan note) when the upgrade cannot keep the store: what is lost,
/// what is kept of the old disk and what to run afterwards. `None` when nothing is lost by this upgrade or the store is empty.
pub fn store_loss_warning(check: &StoreCheck, box_name: &str, old_disk: OldDisk) -> Option<String> {
    let head = match (check.fate, old_disk) {
        (_, OldDisk::StoreEmpty) => return None,
        (StoreFate::Lost, _) => "old_disk.head_lost",
        (StoreFate::Unknown, _) => "old_disk.head_unknown",
        _ => return None,
    };
    let args = [("box", box_name), ("lost", NEW_STORE_LOSES)];
    let copy = match old_disk {
        OldDisk::Keep => "old_disk.kept",
        OldDisk::OptedOut => "old_disk.opted_out",
        _ => "old_disk.unavailable",
    };
    Some(format!(
        "{}\n{}\n{}",
        t(head, &args),
        t(copy, &args),
        t("old_disk.afterwards", &args)
    ))
}

/// The same plan with the copy of the old system disk added: planned again (a plan is read-only) from the operation with the
/// choice set. The notes the caller added since the provider's own (`base_notes` of them) are kept. An `Err` is the provider's
/// refusal, which names the opt-out.
pub fn with_old_disk_copy(
    p: &dyn Provider,
    plan: Plan,
    base_notes: usize,
) -> ozbox_core::Result<Plan> {
    let mut op = plan.operation.clone();
    if let Operation::Upgrade {
        keep_old_system_disk,
        ..
    } = &mut op
    {
        *keep_old_system_disk = true;
    }
    let mut fresh = p.plan(&op)?;
    fresh.notes.extend(plan.notes.into_iter().skip(base_notes));
    Ok(fresh)
}

/// The same plan with the copy of the old system disk taken already: the copy is made now, waiting as long as the provider allows,
/// and the upgrade is planned again WITHOUT it, so the apply does not make a second. Done after the person confirmed and BEFORE the
/// box is made ready for its stop: the hold on new runs lasts ten minutes from the start of that, and a slow copy must not eat it.
/// An `Err` is the copy's failure; nothing has been changed.
pub fn take_old_disk_copy_first(
    p: &dyn Provider,
    plan: &Plan,
) -> ozbox_core::Result<(Plan, String)> {
    let Operation::Upgrade { name, image, .. } = &plan.operation else {
        return Err(ozbox_core::Error::Provider(
            "only an upgrade keeps a copy of the old system disk".into(),
        ));
    };
    let id = p.keep_old_system_disk(name, image)?;
    let mut op = plan.operation.clone();
    if let Operation::Upgrade {
        keep_old_system_disk,
        ..
    } = &mut op
    {
        *keep_old_system_disk = false;
    }
    Ok((p.plan(&op)?, id))
}

/// Whether a plan takes the copy of the old system disk.
pub fn plan_keeps_old_disk(plan: &Plan) -> bool {
    plan.changes
        .iter()
        .any(|c| c.kind == "snapshot.old_system_disk")
}

/// The id of the copy this upgrade took of the old system disk, as the apply itself reported it (the record it returned carries
/// the id of the snapshot it made). Never read back from a listing: a listing is unordered and holds the copies of earlier
/// upgrades too, and the wrong id here would send a person to delete, or to recover from, the wrong disk.
pub fn kept_copy_id(applied: Option<&BoxRecord>) -> std::result::Result<String, String> {
    applied
        .and_then(|r| r.spec.labels.get(ozbox_core::PRE_UPGRADE_COPY_LABEL))
        .cloned()
        .ok_or_else(|| "the apply did not say which snapshot it took".to_string())
}

/// What the report says about the copy of the old system disk: `None` when the plan had no reason to talk about one.
pub fn old_disk_report(
    taken_first: Option<&str>,
    applied: Option<&BoxRecord>,
    name: &BoxName,
    kept: bool,
    warned: bool,
) -> (Option<Step>, Option<String>) {
    let n = name.as_str();
    if kept {
        return match taken_first
            .map(str::to_string)
            .ok_or(())
            .or_else(|()| kept_copy_id(applied))
        {
            Ok(id) => (
                Some(Step::new(
                    StepOutcome::Done,
                    t("old_disk.taken", &[("box", n), ("id", &id)]),
                )),
                Some(id),
            ),
            Err(why) => (
                Some(Step::new(
                    StepOutcome::Failed,
                    t("old_disk.not_found", &[("box", n), ("why", &why)]),
                )),
                None,
            ),
        };
    }
    (
        warned.then(|| Step::new(StepOutcome::Skipped, t("old_disk.not_taken", &[("box", n)]))),
        None,
    )
}

/// What the plan says about the store when the upgrade also moves the box to the fleet's KMS key (`--use-fleet-key`, which
/// is allowed only for a store that holds nothing). Whatever the old key was (a file with or without a copy, unsaid, or
/// already lost), the new machine is configured for KMS and cannot open a file-sealed store, so the old store is set aside
/// after the replace (renamed, never deleted) and a new one is started on the fleet's key: it is a "new store", accepted by
/// the flag, and the plan says so. A store already on a key that is not a file, or a box that is moving its key, is left to
/// its own text.
pub fn fleet_key_store_check(check: StoreCheck, box_name: &str) -> StoreCheck {
    match check.fate {
        StoreFate::Lost
        | StoreFate::Unknown
        | StoreFate::AlreadyLost
        | StoreFate::KeptByLaptop
        | StoreFate::KeptByEscrow
        | StoreFate::NotSaid => StoreCheck {
            fate: StoreFate::Lost,
            detail: t("upgrade.store_fleet_key_plan", &[("box", box_name)]),
        },
        _ => check,
    }
}

/// Whether, after the machine is replaced, the upgrade sets the old store aside (`recover_store_step`): the person accepted a new
/// store, and the store is one that would be lost, could not be asked about, cannot be opened, or is held by a key kept elsewhere.
pub fn sets_store_aside(accept_new_store: bool, fate: StoreFate) -> bool {
    accept_new_store
        && matches!(
            fate,
            StoreFate::Lost | StoreFate::Unknown | StoreFate::AlreadyLost | StoreFate::KeyHeld
        )
}

/// Whether the upgrade may go ahead, given what happens to the store. `Ok` carries the plan's note (the store's fate is
/// always in the plan); `Err` is the refusal: a store that would be lost, or a box that could not be asked, needs the
/// person's explicit acceptance (`--accept-new-secrets-store`).
pub fn store_gate(
    check: &StoreCheck,
    box_name: &str,
    accept: bool,
) -> std::result::Result<String, String> {
    match check.fate {
        // not even with --accept-new-secrets-store: a new machine on the KMS key over a file-sealed store never opens it
        StoreFate::MovingKey => Err(check.detail.clone()),
        // the old store is set aside, never deleted, and its key stays where it is held: accepting loses nothing for good
        StoreFate::KeyHeld if accept => Ok(format!(
            "{} {}",
            check.detail,
            t(
                "upgrade.store_accepted",
                &[("box", box_name), ("lost", NEW_STORE_LOSES)]
            )
        )),
        StoreFate::KeyHeld => Err(format!(
            "{} {}",
            check.detail,
            t("upgrade.err_key_held", &[("box", box_name)])
        )),
        StoreFate::Lost | StoreFate::Unknown | StoreFate::AlreadyLost if accept => Ok(format!(
            "{} {}",
            check.detail,
            t(
                "upgrade.store_accepted",
                &[("box", box_name), ("lost", NEW_STORE_LOSES)]
            )
        )),
        StoreFate::Lost | StoreFate::Unknown | StoreFate::AlreadyLost => Err(format!(
            "{} {}",
            check.detail,
            t("upgrade.err_store", &[("box", box_name)])
        )),
        _ => Ok(check.detail.clone()),
    }
}

/// After the reboot of a box whose store key is escrowed in this computer's keychain: when the service stopped because its
/// key is gone, put the key back through the ingress route (it waits for the service to start with it and checks that it does).
pub(crate) fn place_escrow_step(
    agent: &dyn BoxAgent,
    rec: &BoxRecord,
    keys: &dyn crate::secrets::SecretStore,
    waits: Waits,
) -> Step {
    let name = rec.spec.name.as_str();
    let started = Instant::now();
    // the service decides in seconds; wait a little while it is still trying
    let state = loop {
        let got = agent.secrets_state(rec);
        let settled = match &got {
            Ok((Some(s), _)) => s.ready || s.code.as_deref() != Some("transient"),
            _ => false,
        };
        if settled || started.elapsed() >= waits.timeout.min(Duration::from_secs(120)) {
            break got;
        }
        std::thread::sleep(waits.poll);
    };
    match state {
        Ok((Some(s), _)) if s.is_no_escrow() => {
            let Some(kek) = keys
                .get(&crate::ingress_cli::escrow_name(name))
                .ok()
                .flatten()
                .map(zeroize::Zeroizing::new)
            else {
                return Step::new(
                    StepOutcome::Failed,
                    t("upgrade.escrow_missing", &[("box", name)]),
                );
            };
            if let Err(e) = crate::ingress_client::place_kek(&ozbox_core::SystemRunner, name, &kek)
            {
                return Step::new(
                    StepOutcome::Failed,
                    t("upgrade.escrow_failed", &[("box", name), ("why", &e)]),
                );
            }
            // the box's path unit starts the service again with the key; wait for it to say it is ready
            let started = Instant::now();
            loop {
                if let Ok((Some(s), _)) = agent.secrets_state(rec) {
                    if s.ready {
                        return Step::new(
                            StepOutcome::Done,
                            t("upgrade.escrow_done", &[("box", name)]),
                        );
                    }
                }
                if started.elapsed() >= waits.timeout.min(Duration::from_secs(120)) {
                    return Step::new(
                        StepOutcome::Failed,
                        t("upgrade.escrow_not_ready", &[("box", name)]),
                    );
                }
                std::thread::sleep(waits.poll);
            }
        }
        Ok((Some(s), _)) if s.ready => Step::new(
            StepOutcome::Skipped,
            t("upgrade.escrow_not_needed", &[("box", name)]),
        ),
        Ok((Some(s), _)) => Step::new(
            StepOutcome::Failed,
            t("upgrade.recover_other", &[("box", name), ("why", &s.text)]),
        ),
        Ok((None, _)) => Step::new(
            StepOutcome::Skipped,
            t("upgrade.recover_silent", &[("box", name)]),
        ),
        Err(e) => Step::new(
            StepOutcome::Failed,
            t(
                "upgrade.escrow_failed",
                &[("box", name), ("why", &e.to_string())],
            ),
        ),
    }
}

/// After the reboot of a box whose person accepted a new store: when the service stopped because the store's key is gone,
/// set the old store aside through the box's root helper, approved by this computer's pinned key (`ozbox admin <box> --
/// recover-secrets`). Anything else is said and left alone.
pub(crate) fn recover_store_step(
    agent: &dyn BoxAgent,
    rec: &BoxRecord,
    keys: &dyn crate::secrets::SecretStore,
    waits: Waits,
) -> Step {
    let name = rec.spec.name.as_str();
    // the service decides in seconds; wait a little while it is still trying (a /work mount, a vault that has not answered)
    let started = Instant::now();
    let state = loop {
        let got = agent.secrets_state(rec);
        let settled = match &got {
            Ok((Some(s), _)) => s.ready || s.code.as_deref() != Some("transient"),
            _ => false,
        };
        if settled || started.elapsed() >= waits.timeout.min(Duration::from_secs(120)) {
            break got;
        }
        std::thread::sleep(waits.poll);
    };
    match state {
        Ok((Some(s), _)) if s.is_unopenable() => {
            match super::admin::recover_secrets(agent, rec, keys) {
                Ok(_) => Step::new(
                    StepOutcome::Done,
                    t("upgrade.recover_done", &[("box", name)]),
                ),
                Err(super::admin::RecoverError::Refused(why))
                | Err(super::admin::RecoverError::Unreachable(
                    crate::serve::agent::AgentError::Unreachable(why),
                ))
                | Err(super::admin::RecoverError::Unreachable(
                    crate::serve::agent::AgentError::Unsupported(why),
                )) => Step::new(
                    StepOutcome::Failed,
                    t("upgrade.recover_failed", &[("box", name), ("why", &why)]),
                ),
            }
        }
        Ok((Some(s), _)) if s.ready => Step::new(
            StepOutcome::Skipped,
            t("upgrade.recover_not_needed", &[("box", name)]),
        ),
        // a box whose program is older than the one that records this: its service loops on the mismatch and says nothing a
        // program can act on, so the person is told what to run
        Ok((Some(s), _)) if s.text.contains(crate::secrets_enc::KEK_KIND_MISMATCH) => Step::new(
            StepOutcome::Failed,
            t("upgrade.recover_old_service", &[("box", name)]),
        ),
        Ok((Some(s), _)) => Step::new(
            StepOutcome::Failed,
            t("upgrade.recover_other", &[("box", name), ("why", &s.text)]),
        ),
        Ok((None, _)) => Step::new(
            StepOutcome::Skipped,
            t("upgrade.recover_silent", &[("box", name)]),
        ),
        Err(e) => Step::new(
            StepOutcome::Failed,
            t(
                "upgrade.recover_failed",
                &[("box", name), ("why", &e.to_string())],
            ),
        ),
    }
}

/// How long to wait, and how often to look, for a box to answer after it starts.
#[derive(Debug, Clone, Copy)]
pub struct Waits {
    pub timeout: Duration,
    pub poll: Duration,
}

impl Default for Waits {
    fn default() -> Self {
        Self {
            timeout: Duration::from_secs(600),
            poll: Duration::from_secs(5),
        }
    }
}

fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_millis() as u64)
}

/// The step for a change that does not stop the machine: nothing is at risk, so nothing is saved, and above all nothing is
/// pushed (the box's own checkpoint writes a visible branch and pushes it when a remote is set up). Only an explicit
/// `--legacy-checkpoint` on a box with an older agent still asks for that checkpoint.
pub fn no_save_needed(rec: &BoxRecord) -> Step {
    Step::new(
        StepOutcome::Skipped,
        t(
            "upgrade.checkpoint_not_needed",
            &[("box", rec.spec.name.as_str())],
        ),
    )
}

/// Ask a running box to save its work in progress before it is stopped. Never fails the upgrade: `/work` is not
/// touched by an upgrade, so a checkpoint that could not be taken loses nothing, and the step says so.
pub fn checkpoint_before(agent: &dyn BoxAgent, rec: &BoxRecord) -> Step {
    if rec.state != BoxState::Running {
        return Step::new(
            StepOutcome::Skipped,
            t(
                "upgrade.checkpoint_stopped",
                &[("box", rec.spec.name.as_str())],
            ),
        );
    }
    match agent.checkpoint(rec) {
        Ok(o) if o.errors.is_empty() => Step::new(
            StepOutcome::Done,
            t(
                "upgrade.checkpoint_done",
                &[("repos", &o.repos_scanned.to_string())],
            ),
        ),
        Ok(o) => Step::new(
            StepOutcome::Failed,
            t(
                "upgrade.checkpoint_partial",
                &[("failed", &o.errors.len().to_string())],
            ),
        ),
        Err(e) => Step::new(
            StepOutcome::Skipped,
            t(
                "upgrade.checkpoint_skipped",
                &[("why", &e.to_string()), ("box", rec.spec.name.as_str())],
            ),
        ),
    }
}

/// After the upgrade: wait for the box to be running and its agent to answer, then take the self-test it ran.
pub fn verify_after(
    p: &dyn Provider,
    agent: &dyn BoxAgent,
    name: &BoxName,
    waits: Waits,
) -> (Step, Option<SelfTest>) {
    let started = Instant::now();
    loop {
        let last = match p.get(name) {
            Ok(Some(rec)) if rec.state == BoxState::Running => {
                match agent.selftest(&rec, now_ms()) {
                    Ok(test) => {
                        return (
                            Step::new(StepOutcome::Done, t("upgrade.ready_done", &[])),
                            Some(test),
                        )
                    }
                    Err(AgentError::Unsupported(why)) => {
                        return (
                            Step::new(
                                StepOutcome::Skipped,
                                t("upgrade.ready_skipped", &[("why", &why)]),
                            ),
                            None,
                        )
                    }
                    Err(AgentError::Unreachable(why)) => {
                        // Not answering is not always waiting: an image built without the agent program never will.
                        // The box's own files say so at once, over the same SSH route.
                        if let Ok(img) = agent.image_agent(&rec) {
                            if !img.agent_present {
                                return (
                                    Step::new(
                                        StepOutcome::Failed,
                                        t(
                                            "upgrade.image_no_agent",
                                            &[
                                                ("box", name.as_str()),
                                                (
                                                    "image",
                                                    img.image_version
                                                        .as_deref()
                                                        .unwrap_or("this machine"),
                                                ),
                                            ],
                                        ),
                                    ),
                                    None,
                                );
                            }
                        }
                        why
                    }
                }
            }
            Ok(Some(rec)) => format!("the box is {}", rec.state),
            Ok(None) => "the box is not listed".to_string(),
            Err(e) => e.to_string(),
        };
        if started.elapsed() >= waits.timeout {
            return (
                Step::new(
                    StepOutcome::Failed,
                    t(
                        "upgrade.ready_failed",
                        &[
                            ("secs", &waits.timeout.as_secs().to_string()),
                            ("why", &last),
                        ],
                    ),
                ),
                None,
            );
        }
        std::thread::sleep(waits.poll);
    }
}

/// The self-test as lines a person reads: one per check, then a verdict.
pub fn describe_selftest(test: &SelfTest) -> Vec<String> {
    let mut lines: Vec<String> = test
        .checks
        .iter()
        .map(|c| match &c.outcome {
            Outcome::Pass => format!("  pass     {}", c.name),
            Outcome::Fail { reason, .. } => format!("  FAILED   {}: {reason}", c.name),
            Outcome::Unknown { reason } => format!("  unknown  {}: {reason}", c.name),
        })
        .collect();
    lines.push(if !test.ok {
        t("upgrade.selftest_failed", &[])
    } else if !test.all_verified {
        t("upgrade.selftest_partial", &[])
    } else {
        t("upgrade.selftest_passed", &[])
    });
    lines
}

/// What counts against the fleet cap and budget: an upgrade starts a stopped box, so it is held to what resuming it
/// would be; on a running box it adds nothing.
pub fn budget_view(op: &Operation, rec: &BoxRecord) -> Operation {
    match op {
        Operation::Upgrade { name, .. }
            if matches!(rec.state, BoxState::Paused | BoxState::InstanceMissing) =>
        {
            Operation::Resume { name: name.clone() }
        }
        other => Operation::Snapshot {
            name: other.box_name().clone(),
        },
    }
}

/// An upgrade that stopped after the old machine was removed and before the new one started. Additive to the
/// outcome's JSON shape.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Interrupted {
    pub box_name: String,
    /// The box's state now: `instance_missing`.
    pub state: String,
    /// `/work` was not touched.
    pub work_kept: bool,
    pub image: String,
    /// The command that finishes it.
    pub rerun: String,
    pub reason: String,
}

#[derive(Serialize)]
struct Outcome2<'a> {
    plan: &'a Plan,
    applied: bool,
    dry_run: bool,
    result: Option<&'a BoxRecord>,
    upgrade: Option<&'a Report>,
    #[serde(skip_serializing_if = "Option::is_none")]
    interrupted: Option<&'a Interrupted>,
    /// A box with nothing to upgrade still gets the memory guard, live (ADR 0045). Additive.
    #[serde(skip_serializing_if = "Option::is_none")]
    memory_guard: Option<&'a Step>,
    /// Which kind of upgrade the two signed releases call for, and which one is carried out (ADR 0038). The two are
    /// separate names on purpose: a reader must never take "called for live" as "done live".
    #[serde(skip_serializing_if = "Option::is_none")]
    upgrade_kind: Option<&'a KindReport>,
    /// The words printed before the confirmation when the upgrade cannot keep the box's secrets store: what is lost, what is
    /// kept of the old system disk and what to run afterwards. Additive.
    #[serde(skip_serializing_if = "Option::is_none")]
    secrets_store_warning: Option<&'a str>,
}

/// What every upgrade does today (ADR 0038): the box stops, its system disk is replaced and `/work` is kept.
const CARRIED_OUT: &str = "replace";

/// The kind of upgrade the releases call for, and why, as the plan reports it (`--json`: `upgrade_kind`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct KindReport {
    /// What the two signed releases call for: `live`, `replace`, `in_place`, or `undecided` (a damaged upgrade record in
    /// a signed manifest).
    pub called_for: &'static str,
    /// What this version of ozbox does: always `replace` (the box's system disk is replaced), whatever is called for.
    /// This changes only in the release that carries out a live update, and a reader keys on it, never on `called_for`.
    pub carried_out: &'static str,
    pub reason: String,
}

impl KindReport {
    /// The plan's line for it.
    pub fn line(&self) -> String {
        let key = match self.called_for {
            "live" => "upgrade.kind_live",
            "replace" => "upgrade.kind_replace",
            "in_place" => "upgrade.kind_in_place",
            _ => "upgrade.kind_undecided",
        };
        t(key, &[("reason", &self.reason)])
    }
}

/// Decide the kind of upgrade from the box's state and the signed manifests of the release it runs and of the target
/// (ADR 0038). Pure: the caller fetches `current` (the box's image) and `target`. Nothing here is acted on yet; a
/// refusal of a damaged record is reported as `undecided` and does not stop today's upgrade.
pub fn kind_report(
    running: bool,
    current: Option<&ImageInfo>,
    target: Option<&ImageInfo>,
) -> KindReport {
    use ozbox_core::upgrade_kind::{decide, Side};
    use ozbox_core::UpgradeKind;
    let side = |i: Option<&ImageInfo>| -> (Option<String>, Option<ozbox_core::UpgradeRecord>) {
        (
            i.and_then(|i| i.release.clone()),
            i.and_then(|i| i.upgrade.clone()),
        )
    };
    let (cr, cu) = side(current);
    let (tr, tu) = side(target);
    match decide(
        running,
        Side {
            release: cr.as_deref(),
            record: cu.as_ref(),
        },
        Side {
            release: tr.as_deref(),
            record: tu.as_ref(),
        },
    ) {
        Ok(d) => KindReport {
            carried_out: CARRIED_OUT,
            called_for: match d.kind {
                UpgradeKind::Live => "live",
                UpgradeKind::Replace => "replace",
                UpgradeKind::InPlace => "in_place",
            },
            reason: d.reason,
        },
        Err(why) => KindReport {
            carried_out: CARRIED_OUT,
            called_for: "undecided",
            reason: why,
        },
    }
}

/// Decide whether an image may be upgraded to, from what is known about where it came from. `Ok` carries lines for the
/// plan's notes (what was verified, or the warning when an unverified image is used on request); `Err` is a refusal in
/// words a person reads. Only an image whose signature COULD be checked and was not is refused: a provider that has no
/// signed releases (the sandbox) or cannot tell says so in a note and is not blocked.
pub fn trust_gate(
    info: Option<&ImageInfo>,
    image: &str,
    allow_unverified: bool,
) -> std::result::Result<Vec<String>, String> {
    let Some(info) = info else {
        return Ok(vec![t("upgrade.trust_unknown", &[("image", image)])]);
    };
    // One version for the program, the box daemon and the image: a different minor version is refused whatever the
    // signature says, and `--allow-unverified` does not lift it (it is about compatibility, not trust).
    let mut notes = Vec::new();
    // An image that names no release, or one that does not read as a version, cannot be compared either: say so, as for a
    // date version, rather than pass it in silence.
    let Some(release) = info.release.as_deref().filter(|r| !r.trim().is_empty()) else {
        notes.push(t("upgrade.note_no_version", &[]));
        return signature_notes(info, image, allow_unverified, notes);
    };
    {
        use ozbox_core::release::{compat, Compat};
        match compat(env!("CARGO_PKG_VERSION"), release) {
            Compat::Compatible => {}
            Compat::Unknown => {
                notes.push(t("upgrade.note_unknown_version", &[("release", release)]))
            }
            Compat::ProgramOlder => {
                return Err(t(
                    "upgrade.err_program_older",
                    &[
                        ("image", image),
                        ("release", release),
                        ("program", env!("CARGO_PKG_VERSION")),
                    ],
                ))
            }
            Compat::ImageOlder => {
                return Err(t(
                    "upgrade.err_image_older",
                    &[
                        ("image", image),
                        ("release", release),
                        ("program", env!("CARGO_PKG_VERSION")),
                    ],
                ))
            }
            Compat::Legacy => notes.push(t("upgrade.note_legacy_version", &[("release", release)])),
        }
    }
    signature_notes(info, image, allow_unverified, notes)
}

/// One plan note for each candidate `latest` passed over, newest first: the image, its release and why (see
/// [`ozbox_core::ImageInfo::skipped`]).
pub fn latest_skipped_notes(info: Option<&ImageInfo>) -> Vec<String> {
    info.map(|i| {
        i.skipped
            .iter()
            .map(|line| t("upgrade.latest_skipped", &[("line", line)]))
            .collect()
    })
    .unwrap_or_default()
}

/// `latest` found no image whose signed release verifies: the refusal, naming every candidate passed over and the two ways
/// forward. `None` when the chosen image verifies, the provider has no signed releases, or the person asked for
/// unverified images.
pub fn latest_unverified(info: Option<&ImageInfo>, allow_unverified: bool) -> Option<String> {
    let info = info?;
    if info.signature_verified || !info.signature_applicable || allow_unverified {
        return None;
    }
    let detail = info
        .signature_detail
        .as_deref()
        .unwrap_or("no reason was given");
    let skipped: String = info
        .skipped
        .iter()
        .map(|l| t("upgrade.latest_none_line", &[("line", l)]))
        .collect();
    Some(t(
        "upgrade.err_latest_none",
        &[
            ("image", &info.id),
            ("detail", detail),
            ("skipped", &skipped),
        ],
    ))
}

/// The part of [`trust_gate`] about the image's signature, after its version has been looked at.
fn signature_notes(
    info: &ImageInfo,
    image: &str,
    allow_unverified: bool,
    mut notes: Vec<String>,
) -> std::result::Result<Vec<String>, String> {
    let detail = info
        .signature_detail
        .as_deref()
        .unwrap_or("no reason was given");
    if info.signature_verified {
        notes.push(t("upgrade.trust_verified", &[("detail", detail)]));
        return Ok(notes);
    }
    if !info.signature_applicable {
        notes.push(t("upgrade.trust_not_applicable", &[("detail", detail)]));
        return Ok(notes);
    }
    if allow_unverified {
        notes.push(t(
            "upgrade.trust_overridden",
            &[("image", image), ("detail", detail)],
        ));
        return Ok(notes);
    }
    Err(t(
        "upgrade.err_unverified",
        &[("image", image), ("detail", detail)],
    ))
}

/// The image an interrupted upgrade of a box with no machine was going to: what finishing it defaults to.
pub fn finishing_image(rec: &BoxRecord) -> Option<String> {
    (rec.state == BoxState::InstanceMissing)
        .then(|| rec.spec.labels.get(ozbox_core::UPGRADE_TO_LABEL).cloned())
        .flatten()
}

/// What a failed apply left behind. When the box has no machine (the old one was removed, the new one refused), say
/// so plainly: `/work` is safe, nothing is running, and the exact command that finishes the job.
pub fn describe_failure(
    p: &dyn Provider,
    name: &BoxName,
    image: &str,
    cause: &ozbox_core::Error,
) -> Option<Interrupted> {
    let rec = p.get(name).ok().flatten()?;
    (rec.state == BoxState::InstanceMissing).then(|| Interrupted {
        box_name: name.to_string(),
        state: "instance_missing".into(),
        work_kept: true,
        image: image.to_string(),
        rerun: format!("ozbox upgrade {name}"),
        reason: cause.to_string(),
    })
}

#[allow(clippy::too_many_arguments)]
pub(super) fn command(
    p: &dyn Provider,
    simulated: bool,
    inputs: RouteInputs,
    name: BoxName,
    image: Option<String>,
    allow_unverified: bool,
    accept_new_store: bool,
    no_old_disk_snapshot: bool,
    first_boot: FirstBootOpts,
    quiesce_mode: crate::quiesce::Mode,
    use_fleet_key: bool,
    root: Option<RootFacts<'_>>,
    f: &Flags,
) -> Result<()> {
    let for_ssh = inputs.clone();
    let agent = crate::serve::agent_for(simulated, inputs);
    // moving to the fleet key is allowed only for a store that holds nothing, and it is checked before anything is planned
    let accept_new_store = if use_fleet_key {
        let rec = p
            .get(&name)?
            .ok_or_else(|| ozbox_core::Error::NotFound(name.to_string()))?;
        fleet_key_gate(agent.as_ref(), &rec, simulated, root).map_err(CliError::Msg)?;
        true
    } else {
        accept_new_store
    };
    let keys = crate::approval_key_cli::keychain();
    let waits = Waits::default();
    execute(
        p,
        agent.as_ref(),
        name,
        image,
        allow_unverified,
        f,
        waits,
        &Around {
            store_check: &|ag, rec| {
                let escrowed = !simulated
                    && keys
                        .get(&crate::ingress_cli::escrow_name(rec.spec.name.as_str()))
                        .ok()
                        .flatten()
                        .is_some();
                let check = store_check(ag, rec, simulated, escrowed, root);
                if use_fleet_key {
                    fleet_key_store_check(check, rec.spec.name.as_str())
                } else {
                    check
                }
            },
            accept_new_store,
            old_disk: OldDisk::choose(p.id(), no_old_disk_snapshot, use_fleet_key),
            place_escrow: &|ag, rec| Some(place_escrow_step(ag, rec, keys.as_ref(), waits)),
            recover: &|ag, rec| Some(recover_store_step(ag, rec, keys.as_ref(), waits)),
            restore_backups: &restore_backup_credentials,
            restore_services: &restore_managed_services,
            restore_dashboard: &|_, rec| {
                if simulated {
                    return None;
                }
                let secrets = crate::serve::secret_store();
                let verifier = ozbox_core::ReleaseVerifier::new(
                    std::sync::Arc::new(ozbox_core::SystemRunner),
                    ozbox_core::DEFAULT_RELEASE_REPO,
                );
                restore_dashboard_with(
                    rec,
                    &crate::dashboard_cli::Stores {
                        secrets: secrets.as_ref(),
                        keys: keys.as_ref(),
                    },
                    &ozbox_core::SystemRunner,
                    &verifier,
                    &crate::dashboard_cli::VerifierAssets {
                        verifier: &verifier,
                    },
                )
            },
            memory_guard: &memory_guard_step,
            refresh_ssh: &|previous, after| refresh_ssh_entry(&for_ssh, previous, after),
            review_signers: &|rec| {
                if simulated {
                    return None;
                }
                let name = rec.spec.name.as_str();
                match crate::workload_cli::ssh_receive(
                    &ozbox_core::SystemRunner,
                    name,
                    &serde_json::json!({"op": "approval_keys"}),
                ) {
                    Ok(v) => review_signers(name, &v["result"]),
                    Err(_) => None,
                }
            },
            first_boot,
            strict_checkpoint: quiesce_mode.strict,
            legacy_checkpoint: quiesce_mode.legacy,
            no_checkpoint: quiesce_mode.none,
        },
    )
}

/// The steps around the provider's change, each a function so the command, the dashboard and the tests can supply their
/// own.
pub(super) struct Around<'a> {
    /// Before the plan is confirmed: what happens to the box's secrets store.
    pub store_check: &'a dyn Fn(&dyn BoxAgent, &BoxRecord) -> StoreCheck,
    /// The person accepted a new store (`--accept-new-secrets-store`).
    pub accept_new_store: bool,
    /// Whether a copy of the old system disk is kept when the store's key cannot be shown to survive.
    pub old_disk: OldDisk,
    /// After the reboot, for a store kept by this computer's keychain: put the key back through the ingress route.
    pub place_escrow: &'a dyn Fn(&dyn BoxAgent, &BoxRecord) -> Option<Step>,
    /// After the reboot, when a new store was accepted: set the old one aside.
    pub recover: &'a dyn Fn(&dyn BoxAgent, &BoxRecord) -> Option<Step>,
    pub restore_backups: &'a dyn Fn(&dyn BoxAgent, &BoxRecord) -> Option<Step>,
    pub restore_services: &'a dyn Fn(&dyn BoxAgent, &BoxRecord) -> Option<Step>,
    /// After the machine was replaced: put the hosted dashboard back from what this computer kept (`None`: none is kept).
    pub restore_dashboard: &'a dyn Fn(&dyn BoxAgent, &BoxRecord) -> Option<Step>,
    /// Put the memory guard on the running box, live (`None`: nothing to say, as on a box that cannot be asked).
    pub memory_guard: &'a dyn Fn(&dyn BoxAgent, &BoxRecord) -> Option<Step>,
    pub refresh_ssh: &'a dyn Fn(Option<&str>, &BoxRecord) -> Step,
    /// After everything: laptop keys the box trusts with no record of how they were enrolled.
    pub review_signers: &'a dyn Fn(&BoxRecord) -> Option<Step>,
    /// What this program renders at first boot, and what the person asked about it.
    pub first_boot: FirstBootOpts,
    /// `--strict-checkpoint`: do not stop the box unless it was fully quiesced first.
    pub strict_checkpoint: bool,
    /// `--legacy-checkpoint`: on a box whose agent is older, use its own checkpoint (a visible branch that may be pushed).
    pub legacy_checkpoint: bool,
    /// `--no-checkpoint`: on a box whose agent is older, go on with no checkpoint (named, so it is never assumed).
    pub no_checkpoint: bool,
}

/// The first-boot side of an upgrade: the hash this program renders (its own copy, or developer modules), `--reprovision`
/// and `--allow-first-boot-mismatch`.
#[derive(Debug, Clone, Default)]
pub struct FirstBootOpts {
    pub ours: String,
    pub reprovision: bool,
    pub allow_mismatch: bool,
    /// Look at the first boot of a box already on the target image at all (off in the sandbox, whose machines are
    /// simulated and carry no first boot).
    pub enabled: bool,
}

/// Is the target image's release built with the first-boot configuration this program renders? `Ok` carries a line for
/// the plan; `Err` refuses (unless `allow`). A release that records nothing (every release before 0.1.1, or an image whose
/// signature was not verified) cannot be compared and is allowed with a note, so a box made by an older program can still
/// be repaired from its own image.
pub fn first_boot_gate(
    info: Option<&ImageInfo>,
    image: &str,
    ours: &str,
    allow: bool,
) -> std::result::Result<Vec<String>, String> {
    let short = crate::infra_cli::short;
    let Some(theirs) = info.and_then(|i| i.first_boot_sha256.as_deref()) else {
        return Ok(vec![t(
            "upgrade.first_boot_unrecorded",
            &[("hash", &short(ours))],
        )]);
    };
    if theirs == ours {
        return Ok(vec![t(
            "upgrade.first_boot_match",
            &[("hash", &short(ours))],
        )]);
    }
    let release = info.and_then(|i| i.release.as_deref()).unwrap_or("unknown");
    let args = [
        ("image", image),
        ("release", release),
        ("theirs", &short(theirs)),
        ("ours", &short(ours)),
    ];
    if allow {
        Ok(vec![t("upgrade.first_boot_overridden", &args)])
    } else {
        Err(t("upgrade.err_first_boot_mismatch", &args))
    }
}

/// What decides whether a box already on the target image needs its machine replaced to boot with this program's
/// first-boot configuration.
pub struct FirstBootCheck<'a> {
    pub name: &'a str,
    pub image: &'a str,
    /// The hash this program renders.
    pub ours: &'a str,
    /// `--reprovision`.
    pub asked: bool,
    /// The provider's record of the machine's first boot ([`ozbox_core::FIRST_BOOT_LABEL`]): the authority. The box
    /// cannot change it (on AWS a tag set when the machine is created).
    pub authority: Option<&'a str>,
    /// Whether the provider can replace a machine from the image it already runs (`Err` says why not, and what to do).
    pub can_replace: std::result::Result<(), String>,
}

/// The line for a `--reprovision` that an unfinished upgrade postpones: finishing is done first, the replace is the next run's.
pub fn unfinished_reprovision_note(unfinished: bool, asked: bool, name: &str) -> Option<String> {
    (unfinished && asked).then(|| t("upgrade.reprovision_after_finish", &[("box", name)]))
}

/// The decision, and the lines the plan carries about it. `Ok(true)`: replace the machine from the same image. `Err`
/// refuses (only when `--reprovision` asks for what the provider cannot do).
///
/// The provider's record is the authority. What the box says about itself (`probe`, `/etc/ozbox/first-boot`) travels
/// through the box user's shell, so it is only ever used to ask for MORE: a box whose answer disagrees with the record, is
/// missing or is malformed is repaired; a box can never talk itself out of a repair. `probe` is called only when the record
/// already says the box is current.
pub fn first_boot_decision(
    c: &FirstBootCheck<'_>,
    probe: &dyn Fn() -> std::result::Result<BoxFirstBoot, String>,
) -> std::result::Result<(bool, Vec<String>), String> {
    let short = crate::infra_cli::short;
    let ours = short(c.ours);
    if let Err(why) = &c.can_replace {
        if c.asked {
            return Err(t(
                "upgrade.err_reprovision_unsupported",
                &[("box", c.name), ("why", why)],
            ));
        }
        return Ok((
            false,
            vec![t(
                "upgrade.first_boot_unrepairable",
                &[("box", c.name), ("why", why)],
            )],
        ));
    }
    let replace = |key: &str, theirs: &str| -> (bool, Vec<String>) {
        (
            true,
            vec![t(
                key,
                &[
                    ("box", c.name),
                    ("image", c.image),
                    ("theirs", theirs),
                    ("ours", &ours),
                ],
            )],
        )
    };
    if c.asked {
        return Ok(replace("upgrade.reprovision_asked", ""));
    }
    match c.authority {
        None => Ok(replace("upgrade.stale_unrecorded", "")),
        Some(h) if h != c.ours => Ok(replace("upgrade.stale_box", &short(h))),
        Some(_) => match probe() {
            Ok(BoxFirstBoot::Recorded(h)) if h == c.ours => Ok((
                false,
                vec![t(
                    "upgrade.first_boot_current",
                    &[("box", c.name), ("ours", &ours)],
                )],
            )),
            Ok(BoxFirstBoot::Recorded(h)) => Ok(replace("upgrade.stale_disagrees", &short(&h))),
            Ok(BoxFirstBoot::Unrecorded) => Ok(replace(
                "upgrade.stale_disagrees",
                &t("upgrade.unrecorded", &[]),
            )),
            Ok(BoxFirstBoot::Malformed) => Ok(replace("upgrade.stale_malformed", "")),
            Err(why) => Ok((
                false,
                vec![t(
                    "upgrade.first_boot_current_unconfirmed",
                    &[("box", c.name), ("ours", &ours), ("why", &why)],
                )],
            )),
        },
    }
}

/// After the machine was replaced: point the person's SSH entry for the box at the new machine and forget the old
/// machine's host key. Never fails the upgrade: it is a convenience for connecting from this computer.
fn refresh_ssh_entry(inputs: &RouteInputs, previous: Option<&str>, after: &BoxRecord) -> Step {
    let name = after.spec.name.as_str();
    let Some(dir) = super::ssh_dir() else {
        return Step::new(
            StepOutcome::Skipped,
            t("upgrade.ssh_none", &[("box", name)]),
        );
    };
    ssh_entry_step(&ozbox_core::SystemRunner, &dir, inputs, previous, after)
}

fn ssh_entry_step(
    runner: &dyn ozbox_core::CommandRunner,
    dir: &std::path::Path,
    inputs: &RouteInputs,
    previous: Option<&str>,
    after: &BoxRecord,
) -> Step {
    let name = after.spec.name.as_str();
    let route = sshconfig::routes(after, inputs).into_iter().next();
    match sshconfig::refresh_entry(runner, dir, name, route.as_ref(), previous) {
        Ok(r) if r.rewritten || !r.forgotten.is_empty() => Step::new(
            StepOutcome::Done,
            t(
                if r.rewritten {
                    "upgrade.ssh_rewritten"
                } else {
                    "upgrade.ssh_forgot"
                },
                &[("box", name), ("forgotten", &r.forgotten.len().to_string())],
            ),
        ),
        Ok(_) => Step::new(
            StepOutcome::Skipped,
            t("upgrade.ssh_nothing", &[("box", name)]),
        ),
        Err(e) => Step::new(
            StepOutcome::Failed,
            t(
                "upgrade.ssh_failed",
                &[("box", name), ("why", &e.to_string())],
            ),
        ),
    }
}

/// After the self-test: a box that backs up to a repository lost its credentials with the system disk, so they are put
/// back from the secret store (never from `/work`). `None` when no repository is set up or the box is switched off, in
/// which case the plan's note about backups is all there is to say.
fn restore_backup_credentials(agent: &dyn BoxAgent, rec: &BoxRecord) -> Option<Step> {
    let settings = super::load_settings().ok()?;
    restore_with(&settings, agent, rec, crate::serve::secret_store().as_ref())
}

fn restore_managed_services(agent: &dyn BoxAgent, rec: &BoxRecord) -> Option<Step> {
    restore_services_with(agent, rec, crate::serve::secret_store().as_ref())
}

/// What the person set up through ozbox on this box (the IDE and the desktop have a password here, the IDE's tunnel
/// connector has its token) and is not running now, is set up again. Services that are running are left alone. `None`
/// when nothing was ever set up through ozbox, so there is nothing to say. The secrets are only handed to the box's own
/// setup command, never printed.
pub(crate) fn restore_services_with(
    agent: &dyn BoxAgent,
    rec: &BoxRecord,
    secrets: &dyn crate::secrets::SecretStore,
) -> Option<Step> {
    use crate::code::{Change, Service};
    let name = rec.spec.name.as_str();
    let wanted: Vec<(Service, String)> = [Service::Ide, Service::Desktop]
        .into_iter()
        .filter_map(|s| {
            secrets
                .get(&s.secret_name(name))
                .ok()
                .flatten()
                .map(|p| (s, p))
        })
        .collect();
    let token = secrets
        .get(&Service::connector_secret_name(name))
        .ok()
        .flatten();
    if wanted.is_empty() && token.is_none() {
        return None;
    }
    let status = match agent.code_status(rec) {
        Ok(s) => s,
        Err(e) => {
            return Some(Step::new(
                StepOutcome::Failed,
                t(
                    "upgrade.services_unknown",
                    &[("box", name), ("why", &e.to_string())],
                ),
            ))
        }
    };
    let (mut put_back, mut running, mut failed): (Vec<&str>, Vec<&str>, Vec<String>) =
        (Vec::new(), Vec::new(), Vec::new());
    for (s, password) in wanted {
        let label = match s {
            Service::Ide => "web IDE",
            Service::Desktop => "desktop",
        };
        if status.of(s).active {
            running.push(label);
        } else {
            match agent.code_change(
                rec,
                &Change::Enable {
                    service: s,
                    password,
                },
            ) {
                Ok(()) => put_back.push(label),
                Err(e) => failed.push(format!("{label} ({e})")),
            }
        }
    }
    if let Some(token) = token {
        if status.connector.active {
            running.push("tunnel connector");
        } else {
            match agent.code_change(rec, &Change::Connector { token }) {
                Ok(()) => put_back.push("tunnel connector"),
                Err(e) => failed.push(format!("tunnel connector ({e})")),
            }
        }
    }
    Some(if failed.is_empty() {
        let what = if put_back.is_empty() {
            format!("already running: {}", running.join(", "))
        } else {
            format!("set up again: {}", put_back.join(", "))
        };
        Step::new(
            StepOutcome::Done,
            t("upgrade.services_done", &[("box", name), ("what", &what)]),
        )
    } else {
        Step::new(
            StepOutcome::Failed,
            t(
                "upgrade.services_failed",
                &[("box", name), ("what", &failed.join("; "))],
            ),
        )
    })
}

/// After the machine was replaced: the hosted dashboard, from what this computer kept when it was installed (the token in the
/// keychain, the install settings beside it). `None` when none is kept for this box.
///
/// It goes through the very install the owner runs by hand, with the same checks, so the box's own gate decides: the web IDE's
/// token is put back the same way (the box's root helper takes it, and asks for an approval once a second factor is enrolled).
/// **Nothing here makes an approval.** A box that asks for one gets the outcome `failed` and the one command that makes it with
/// the owner's pinned key at the owner's asking (`ozbox dashboard restore <box> --approve-with-laptop-key`).
pub(crate) fn restore_dashboard_with(
    rec: &BoxRecord,
    stores: &crate::dashboard_cli::Stores<'_>,
    runner: &dyn ozbox_core::CommandRunner,
    verifier: &ozbox_core::ReleaseVerifier,
    assets: &dyn crate::dashboard_cli::AssetSource,
) -> Option<Step> {
    use crate::dashboard_cli::restore_kept;
    step_for_dashboard(
        rec.spec.name.as_str(),
        restore_kept(runner, verifier, assets, stores, &rec.spec.name),
    )
}

/// The words for what putting the dashboard back came to; `None` when nothing is kept (there is nothing to say).
pub(crate) fn step_for_dashboard(
    me: &str,
    outcome: crate::dashboard_cli::Restored,
) -> Option<Step> {
    use crate::dashboard_cli::Restored;
    Some(match outcome {
        Restored::NoneKept => return None,
        Restored::Absent => Step::new(
            StepOutcome::Skipped,
            t("upgrade.dashboard_absent", &[("box", me)]),
        ),
        Restored::Running => Step::new(
            StepOutcome::Done,
            t("upgrade.dashboard_running", &[("box", me)]),
        ),
        Restored::Done { address, token } => {
            let token = if token {
                t("upgrade.dashboard_token_part", &[])
            } else {
                String::new()
            };
            Step::new(
                StepOutcome::Done,
                t(
                    "upgrade.dashboard_restored",
                    &[("box", me), ("address", &address), ("token", &token)],
                ),
            )
        }
        Restored::NeedsApproval => Step::new(
            StepOutcome::Failed,
            t("upgrade.dashboard_needs_approval", &[("box", me)]),
        ),
        Restored::Failed(why) => Step::new(
            StepOutcome::Failed,
            t("upgrade.dashboard_failed", &[("box", me), ("why", &why)]),
        ),
    })
}

/// Put the box memory guard on a running box (ADR 0045), over the same root helper `ozbox admin` uses: swap in compressed RAM
/// (never a disk), the box's own services protected from the OOM killer, and a soft limit for interactive terminals. It is the
/// live path: nothing is restarted, so the tunnel, the web IDE and every terminal and run carry on, and a box that already has
/// it is left as it is. `None` for a box that is not running or cannot be asked; a failure is a step that says so, never an
/// error of the upgrade.
///
/// First the root helper is replaced by the one the program on the box carries, when that is a strictly newer revision
/// (`host-guard helper refresh`; never a downgrade), so a helper addition the installed program already has reaches a box
/// without a machine replace. A box made BEFORE this release has a helper (and maybe a program) that
/// does not know that word: it cannot take the guard live, and says so in the helper's own refusal. That is not a failure of the
/// box: it gets the guard through the machine replace of its upgrade, and the step says exactly that instead of advice that
/// would fail the same way.
pub(crate) fn memory_guard_step(agent: &dyn BoxAgent, rec: &BoxRecord) -> Option<Step> {
    if rec.state != BoxState::Running {
        return None;
    }
    let name = rec.spec.name.as_str();
    let failed = |why: &str| {
        Some(Step::new(
            StepOutcome::Failed,
            t("upgrade.memory_failed", &[("box", name), ("why", why)]),
        ))
    };
    match agent.admin(rec, "host-guard helper refresh") {
        Ok((true, _)) => {}
        // the helper on the box is already as new as (or newer than) the program's: it is kept, never rolled back, and the
        // guard is installed by it as usual (the refusal is in the box's own log)
        Ok((false, said)) if said.contains(crate::helper_refresh::KEPT) => {}
        // the box's helper or program predates the word: the guard comes with the machine replace
        Ok((false, said))
            if said.contains("host-guard takes") || said.contains("unknown action") =>
        {
            return Some(Step::new(
                StepOutcome::Skipped,
                t("upgrade.memory_old_helper", &[("box", name)]),
            ));
        }
        Ok((false, said)) => return failed(said.lines().next().unwrap_or("refused")),
        Err(AgentError::Unsupported(_)) => return None,
        Err(e) => return failed(&e.to_string()),
    }
    match agent.admin(rec, "host-guard memory install") {
        Ok((true, said)) => Some(Step::new(
            StepOutcome::Done,
            t(
                "upgrade.memory_done",
                &[
                    ("box", name),
                    ("what", said.lines().next().unwrap_or("done")),
                ],
            ),
        )),
        Ok((false, said)) => failed(said.lines().next().unwrap_or("refused")),
        Err(AgentError::Unsupported(_)) => None,
        Err(e) => failed(&e.to_string()),
    }
}

pub(crate) fn restore_with(
    settings: &crate::settings::Settings,
    agent: &dyn BoxAgent,
    rec: &BoxRecord,
    secrets: &dyn crate::secrets::SecretStore,
) -> Option<Step> {
    let target = settings.backups.restic.clone()?;
    let name = rec.spec.name.as_str();
    if settings.backups.overrides.get(name).and_then(|o| o.enabled) == Some(false) {
        // the person turned this box's backups off on this computer: said as a choice, never as backups that stopped
        return Some(Step::new(
            StepOutcome::Skipped,
            t("upgrade.backup_opted_out", &[("box", name)]),
        ));
    }
    // Never overwrite what the box already holds: a box whose secrets store came through the upgrade keeps its own
    // credentials, which are the ones its backups were made with. Only a box without them is given them.
    Some(
        match crate::backup_ops::ensure_credentials(agent, rec, &target, secrets, false) {
            Ok(false) => return None,
            Ok(true) => Step::new(
                StepOutcome::Done,
                t("upgrade.backup_restored", &[("box", name)]),
            ),
            Err(why) => Step::new(
                StepOutcome::Failed,
                t(
                    "upgrade.backup_restore_failed",
                    &[("box", name), ("why", &why)],
                ),
            ),
        },
    )
}

/// After an upgrade: the laptop keys the box trusts whose enrolment was never recorded (enrolled by a version from before
/// the box recorded how a key came to be trusted, when the import socket let the box user enrol one before any second
/// factor existed). They may be the agent's own; the step names them and the command that revokes one. `keys` is the
/// box's answer to `approval_keys` (its `keys` and `via`).
pub fn review_signers(name: &str, answer: &serde_json::Value) -> Option<Step> {
    let ids: Vec<&str> = answer["keys"]
        .as_array()?
        .iter()
        .filter_map(|v| v.as_str())
        .collect();
    let unrecorded: Vec<&str> = ids
        .iter()
        .copied()
        .filter(|i| answer["via"][*i].is_null())
        .collect();
    Some(if unrecorded.is_empty() {
        Step::new(
            StepOutcome::Done,
            t(
                "upgrade.signers_ok",
                &[("box", name), ("count", &ids.len().to_string())],
            ),
        )
    } else {
        Step::new(
            StepOutcome::Failed,
            t(
                "upgrade.signers_unrecorded",
                &[
                    ("box", name),
                    ("keys", &unrecorded.join(", ")),
                    ("first", unrecorded[0]),
                ],
            ),
        )
    })
}

/// After a box's machine was replaced: wait for it to answer and run its self-test, then (when it answered) put its
/// repository credentials back. The command and the dashboard server both finish an upgrade with exactly this, so the
/// two can never differ on what an upgraded box is left with.
pub(crate) fn settle_after_replace(
    p: &dyn Provider,
    agent: &dyn BoxAgent,
    name: &BoxName,
    waits: Waits,
    recover: &dyn Fn(&dyn BoxAgent, &BoxRecord) -> Option<Step>,
    restore_backups: &dyn Fn(&dyn BoxAgent, &BoxRecord) -> Option<Step>,
    backups_before: bool,
) -> Settled {
    let (ready, mut selftest) = verify_after(p, agent, name, waits);
    // A new store the person accepted is started before anything is put back into it; the self-test then runs again, so
    // the report describes the box as it is left.
    let recovery = (ready.outcome != StepOutcome::Failed)
        .then(|| p.get(name).ok().flatten())
        .flatten()
        .and_then(|after| recover(agent, &after));
    if recovery
        .as_ref()
        .is_some_and(|s| s.outcome == StepOutcome::Done)
    {
        if let Some(after) = p.get(name).ok().flatten() {
            if let Ok(again) = agent.selftest(&after, now_ms()) {
                selftest = Some(again);
            }
        }
    }
    // The box is running again with a new system disk: put its repository credentials back when it lacks them, then check
    // that backups that were set up work (never a silent stop).
    let after = (ready.outcome != StepOutcome::Failed)
        .then(|| p.get(name).ok().flatten())
        .flatten();
    let restored = after.as_ref().and_then(|a| restore_backups(agent, a));
    let put_back = restored
        .as_ref()
        .is_some_and(|s| s.outcome == StepOutcome::Done);
    let backup = match &after {
        Some(a) => verify_backups(agent, a, backups_before, restored),
        // the box did not come back ready (or cannot be read), so nothing could be asked of it
        None => restored.unwrap_or_else(|| {
            Step::new(
                StepOutcome::Skipped,
                if backups_before {
                    t("upgrade.backup_unchecked", &[("box", name.as_str())])
                } else {
                    t("upgrade.backup_after", &[("box", name.as_str())])
                },
            )
        }),
    };
    // credentials just put back change what the box's own self-test says about backups: it runs again, so the report
    // describes the box as it is left
    if put_back {
        if let Some(a) = &after {
            if let Ok(again) = agent.selftest(a, now_ms()) {
                selftest = Some(again);
            }
        }
    }
    Settled {
        ready,
        selftest,
        backup,
        recovery,
    }
}

/// Whether the box says its repository credentials are on it, and whether backups were ever set up on it: `(configured,
/// expected)`. `expected` is the box's own durable record (kept on `/work`, so it outlives the system disk) or what this
/// program saw before the upgrade. `None` when the box cannot be asked, or answers in a shape that says nothing.
fn backup_state(agent: &dyn BoxAgent, rec: &BoxRecord) -> Option<(bool, bool)> {
    backup_state_ready(agent, rec).map(|(c, e, _)| (c, e))
}

/// As [`backup_state`], and whether the box's secrets service answered: `(configured, expected, ready)`. A box that has just
/// started reports `ready = false`, and its `configured = false` then means "not known", not "none".
fn backup_state_ready(agent: &dyn BoxAgent, rec: &BoxRecord) -> Option<(bool, bool, bool)> {
    let (status, v) =
        crate::backup_ops::call(agent, rec, "GET", "/status", &serde_json::Value::Null).ok()?;
    let configured = v.get("configured").and_then(serde_json::Value::as_bool);
    (status == 200 && configured.is_some()).then(|| {
        (
            configured == Some(true),
            v.get("expected").and_then(serde_json::Value::as_bool) == Some(true),
            !crate::backup_ops::status_not_ready(&v),
        )
    })
}

/// Before the upgrade: does the running box back up to a repository? (`false` when it cannot be asked: the box's own record
/// still says so afterwards, for a box that has one.)
pub(crate) fn backups_configured_now(agent: &dyn BoxAgent, rec: &BoxRecord) -> bool {
    rec.state == BoxState::Running && backup_state(agent, rec).is_some_and(|(c, e)| c || e)
}

/// After the replace: backups that were set up must still be configured AND working. `restored` is what putting the
/// credentials back from this computer said. A box that never had backups says nothing here (the old advice stays, as a
/// skipped step); one that had them and has them no more is a FAILURE with the command, never a quiet skip.
fn verify_backups(
    agent: &dyn BoxAgent,
    rec: &BoxRecord,
    before: bool,
    restored: Option<Step>,
) -> Step {
    let name = rec.spec.name.as_str();
    let nothing = |restored: Option<Step>| {
        restored.unwrap_or_else(|| {
            Step::new(
                StepOutcome::Skipped,
                t("upgrade.backup_after", &[("box", name)]),
            )
        })
    };
    let Some((configured, recorded, ready)) = backup_state_ready(agent, rec) else {
        // the box cannot say; a failure to put credentials back is still reported, and when it was set up before, say so
        return match restored {
            Some(s) => s,
            None if before => Step::new(
                StepOutcome::Failed,
                t(
                    "upgrade.backup_stopped",
                    &[
                        ("box", name),
                        ("why", "The box could not be asked about its backups."),
                    ],
                ),
            ),
            None => nothing(None),
        };
    };
    if !configured && !ready {
        // the secrets service is not up yet: "no credentials" is "not known". Said as that, never as backups that stopped
        // (the box's own self-test says the same), and nothing was sent to it.
        return Step::new(
            StepOutcome::Skipped,
            t("upgrade.backup_not_ready", &[("box", name)]),
        );
    }
    if !configured {
        // turned off for this box on this computer: a choice, not a stop (the step says so)
        if restored
            .as_ref()
            .is_some_and(|s| s.outcome == StepOutcome::Skipped)
        {
            return restored.unwrap_or_else(|| nothing(None));
        }
        if before || recorded || restored.is_some() {
            let why = restored.map(|s| s.detail).unwrap_or_default();
            return Step::new(
                StepOutcome::Failed,
                t("upgrade.backup_stopped", &[("box", name), ("why", &why)]),
            );
        }
        return nothing(None);
    }
    // credentials are on the box: the repository must answer
    let put_back = restored
        .as_ref()
        .is_some_and(|s| s.outcome == StepOutcome::Done);
    let checked =
        match crate::backup_ops::call(agent, rec, "GET", "/snapshots", &serde_json::Value::Null) {
            Ok((200, v)) => {
                let count = v["items"].as_array().map_or(0, Vec::len).to_string();
                Step::new(
                    StepOutcome::Done,
                    t(
                        if put_back {
                            "upgrade.backup_working"
                        } else {
                            "upgrade.backup_kept"
                        },
                        &[("box", name), ("count", &count)],
                    ),
                )
            }
            // an operation holds the repository (a prune): it is working, and it was not listed
            Ok((409, v)) if v.get("code").and_then(serde_json::Value::as_str) == Some("busy") => {
                Step::new(
                    StepOutcome::Skipped,
                    t("upgrade.backup_busy", &[("box", name)]),
                )
            }
            Ok((_, v)) => Step::new(
                StepOutcome::Failed,
                t(
                    "upgrade.backup_unreachable",
                    &[
                        ("box", name),
                        ("why", &crate::backup_ops::reason(&v, "no answer")),
                    ],
                ),
            ),
            Err(e) => Step::new(
                StepOutcome::Failed,
                t("upgrade.backup_unreachable", &[("box", name), ("why", &e)]),
            ),
        };
    // Putting the credentials back failed, yet the box holds some (the helper stored them and then refused, say): that
    // failure is part of the report, never dropped behind a repository that happens to answer.
    match restored {
        Some(r) if r.outcome == StepOutcome::Failed => Step::new(
            StepOutcome::Failed,
            format!("{} {}", r.detail, checked.detail),
        ),
        _ => checked,
    }
}

/// What [`settle_after_replace`] found.
pub(crate) struct Settled {
    pub ready: Step,
    pub selftest: Option<SelfTest>,
    pub backup: Step,
    pub recovery: Option<Step>,
}

#[allow(clippy::too_many_arguments)]
pub(super) fn execute(
    p: &dyn Provider,
    agent: &dyn BoxAgent,
    name: BoxName,
    image: Option<String>,
    allow_unverified: bool,
    f: &Flags,
    waits: Waits,
    around: &Around<'_>,
) -> Result<()> {
    let (restore_services, refresh_ssh) = (around.restore_services, around.refresh_ssh);
    let rec = p
        .get(&name)?
        .ok_or_else(|| ozbox_core::Error::NotFound(name.to_string()))?;
    // Finishing an interrupted upgrade goes to the image it was marked with, not to whatever is newest today: that is
    // the image that was checked, and the one the person agreed to.
    let marked = finishing_image(&rec);
    let requested = match (image.as_deref().map(str::trim), &marked) {
        (None | Some("" | "latest"), Some(m)) => m.as_str(),
        (None | Some(""), None) => "latest",
        (Some(r), _) => r,
    };
    if marked.as_deref() == Some(requested) && !f.json {
        println!(
            "{}",
            t(
                "upgrade.finishing",
                &[("box", name.as_str()), ("image", requested)]
            )
        );
    }
    let (target, info) = if requested == "latest" {
        let info = p.latest_image(rec.spec.region.as_deref())?;
        if !f.json {
            let release = info
                .release
                .as_deref()
                .map(|r| format!(" (release {r})"))
                .unwrap_or_default();
            println!(
                "{}",
                t("upgrade.latest", &[("id", &info.id), ("release", &release)])
            );
        }
        (info.id.clone(), Some(info))
    } else {
        // What is known about a named image, when the provider can say. An image that cannot be inspected is left to
        // the plan, which refuses a missing or unusable one with its own reason.
        (
            requested.to_string(),
            p.image_info(requested, rec.spec.region.as_deref()).ok(),
        )
    };
    // A box already on the target image may still have booted with another first-boot configuration (made by an older
    // program, or from a stale copy of the modules): it is asked, and its machine replaced from the same image when it
    // differs, so a stale first boot can be repaired without a new image. Every check below applies to that replace too.
    // An unfinished upgrade to this very image is finished first (the cheap, expected step); the first boot is looked at
    // on the next run. A provider that cannot replace a machine from the same image keeps "Nothing to do", with a note.
    let mut first_boot_notes = Vec::new();
    let unfinished = rec.spec.labels.get(ozbox_core::UPGRADE_TO_LABEL) == Some(&target);
    let reprovision = if around.first_boot.enabled
        && rec.state != BoxState::InstanceMissing
        && rec.spec.image.as_deref() == Some(target.as_str())
        && !unfinished
    {
        let check = FirstBootCheck {
            name: name.as_str(),
            image: &target,
            ours: &around.first_boot.ours,
            asked: around.first_boot.reprovision,
            authority: rec
                .spec
                .labels
                .get(ozbox_core::FIRST_BOOT_LABEL)
                .map(String::as_str),
            can_replace: p
                .check_reprovision(&rec)
                .map(|_| ())
                .map_err(|e| e.to_string()),
        };
        let probe = || {
            agent
                .image_agent(&rec)
                .map(|a| a.first_boot)
                .map_err(|e| e.to_string())
        };
        let (stale, notes) = first_boot_decision(&check, &probe).map_err(CliError::Msg)?;
        first_boot_notes = notes;
        stale
    } else {
        // `--reprovision` on an unfinished upgrade is not dropped without a word: the engine is not told to replace (it would
        // finish first and say so itself), so the command says it here
        first_boot_notes.extend(unfinished_reprovision_note(
            around.first_boot.enabled && unfinished,
            around.first_boot.reprovision,
            name.as_str(),
        ));
        false
    };
    let op = Operation::Upgrade {
        name: name.clone(),
        image: target.clone(),
        reprovision,
        keep_old_system_disk: false,
    };
    guard_rails(p, &op)?;
    crate::settings::enforce(&load_settings()?, p, &budget_view(&op, &rec))?;
    let mut plan = p.plan(&op)?;
    // what the provider itself said; the replan that adds the copy of the old system disk keeps what is added after it
    let base_notes = plan.notes.len();
    plan.notes.extend(first_boot_notes);
    if requested == "latest" {
        plan.notes.extend(latest_skipped_notes(info.as_ref()));
    }
    plan.notes.extend(crate::infra_cli::plan_notes());
    // Which kind of upgrade the two signed releases call for, and why (ADR 0038, informational: this version of ozbox
    // carries out every upgrade as a replace). Only asked when there is something to do, and never an error: a manifest
    // that cannot be fetched is a "replace" with that reason.
    let kind = if plan.is_noop() {
        None
    } else {
        let running = rec.state == BoxState::Running;
        let current = if running {
            rec.spec
                .image
                .as_deref()
                .and_then(|i| p.image_info(i, rec.spec.region.as_deref()).ok())
        } else {
            None
        };
        let report = kind_report(running, current.as_ref(), info.as_ref());
        plan.notes.push(report.line());
        Some(report)
    };
    let mut store = None;
    let mut backups_before = false;
    let mut loud: Option<String> = None;
    if !plan.is_noop() {
        // An image whose release signature could be checked and was not is refused before anything is confirmed,
        // unless the person asks for it by name; the plan then carries the warning.
        if requested == "latest" {
            if let Some(refusal) = latest_unverified(info.as_ref(), allow_unverified) {
                return Err(CliError::Msg(refusal));
            }
        }
        match trust_gate(info.as_ref(), &target, allow_unverified) {
            Ok(notes) => plan.notes.extend(notes),
            Err(refusal) => return Err(CliError::Msg(refusal)),
        }
        // The image and this program must render the same first boot (one version, ADR 0036).
        match first_boot_gate(
            info.as_ref(),
            &target,
            &around.first_boot.ours,
            around.first_boot.allow_mismatch,
        ) {
            Ok(notes) => plan.notes.extend(notes),
            Err(refusal) => return Err(CliError::Msg(refusal)),
        }
        // The store's fate is in every plan; a store that would be lost, or a box that could not be asked, is refused
        // before anything is confirmed unless the person accepts it by name.
        let check = (around.store_check)(agent, &rec);
        match store_gate(&check, name.as_str(), around.accept_new_store) {
            Ok(note) => {
                // The key may be destroyed with the old system disk: the plan then keeps a copy of it first (planned again,
                // so the step is in the plan and `apply` compares it), and the warning below says it in words.
                if old_disk_copy_wanted(check.fate, around.old_disk) {
                    plan = with_old_disk_copy(p, plan, base_notes)?;
                }
                plan.notes.push(note);
                loud = store_loss_warning(&check, name.as_str(), around.old_disk);
            }
            Err(refusal) => return Err(CliError::Msg(refusal)),
        }
        store = Some(check);
        // does it back up to a repository? Read now (a running box answers), so the report afterwards can tell a box whose
        // backups stopped from one that never had any, and the plan says what will be checked
        backups_before = backups_configured_now(agent, &rec);
        if backups_before {
            plan.notes
                .push(t("upgrade.backups_planned", &[("box", name.as_str())]));
        }
    }
    // nothing to do asks nothing of the box
    let store = store.unwrap_or_else(|| StoreCheck {
        fate: StoreFate::NotApplicable,
        detail: String::new(),
    });
    // what will end when the box stops, read (never changed) before the plan shows
    let stopping = crate::quiesce::needed(&plan, &rec);
    let mode = crate::quiesce::Mode {
        strict: around.strict_checkpoint,
        legacy: around.legacy_checkpoint,
        none: around.no_checkpoint,
    };
    // a box whose agent is older needs the person to choose its checkpoint by name; refused after the plan is shown
    let mut older_refusal = None;
    if stopping {
        let preview = crate::quiesce::preview(agent, &rec);
        plan.notes.extend(preview.notes(name.as_str()));
        match crate::quiesce::older_choice(&preview.service, mode, name.as_str()) {
            Ok(note) => plan.notes.extend(note),
            Err(refusal) => older_refusal = Some(refusal),
        }
    }
    if !f.json {
        print!("{plan}");
        if let Some(w) = &loud {
            println!("\n{w}\n");
        }
    }
    if plan.is_noop() {
        // Nothing to upgrade, but a box without the memory guard is put in order: live, nothing restarted, never on a dry run.
        let memory = (!f.dry_run && rec.state == BoxState::Running)
            .then(|| (around.memory_guard)(agent, &rec))
            .flatten();
        if let (Some(m), false) = (&memory, f.json) {
            println!("{}", m.detail);
        }
        return finish_with(
            f,
            &Outcome2 {
                plan: &plan,
                applied: false,
                dry_run: f.dry_run,
                result: None,
                upgrade: None,
                interrupted: None,
                memory_guard: memory.as_ref(),
                upgrade_kind: kind.as_ref(),
                secrets_store_warning: loud.as_deref(),
            },
        );
    }
    if f.dry_run {
        if !f.json {
            println!("{}", t("upgrade.dry_run", &[]));
        }
        return finish_with(
            f,
            &Outcome2 {
                plan: &plan,
                applied: false,
                dry_run: true,
                result: None,
                upgrade: None,
                interrupted: None,
                memory_guard: None,
                upgrade_kind: kind.as_ref(),
                secrets_store_warning: loud.as_deref(),
            },
        );
    }
    if let Some(refusal) = older_refusal {
        return Err(CliError::Msg(refusal));
    }
    confirm(&plan, f)?;

    // The copy of the old system disk is taken NOW, before the box is made ready for its stop: the hold the box puts on new runs
    // lasts ten minutes from the start of that, and the provider may need longer than that for a first copy. A failure here has
    // changed nothing. What is applied below is the same upgrade planned again without the step that is already done.
    let mut copy_taken_first: Option<String> = None;
    let apply_plan = if plan_keeps_old_disk(&plan) {
        if !f.json {
            println!("{}", t("old_disk.taking", &[("box", name.as_str())]));
        }
        let (again, id) = take_old_disk_copy_first(p, &plan)?;
        copy_taken_first = Some(id);
        again
    } else {
        plan.clone()
    };

    // Quiesce replaces the plain checkpoint when the plan stops the machine (runs end cleanly, uncommitted work is
    // snapshotted without touching anything); otherwise the old step reports that there is nothing to save.
    // The hold on new runs is lifted on every way out until the change is applied (a refusal, a declined question, a
    // failed apply), and ends by itself after ten minutes if even that is not reached.
    let mut hold = None;
    let checkpoint = if stopping {
        // Ctrl-C during the wait or the question lifts the hold before the process exits
        crate::quiesce::guard_interrupt(agent, &rec, || -> Result<Step> {
            let q = crate::quiesce::perform(
                agent,
                &rec,
                &crate::quiesce::Opts::command(mode),
                &crate::quiesce::RealPace::new(),
            );
            hold = Some(crate::quiesce::Hold::new(agent, &rec));
            if !f.json {
                println!("{}", q.step.detail);
            }
            if !q.proceed {
                return Err(CliError::Msg(crate::quiesce::strict_refusal(
                    name.as_str(),
                    q.touched,
                )));
            }
            if q.reconfirm {
                super::confirm_unsaved(name.as_str(), f)?;
            }
            Ok(q.step)
        })?
    } else {
        let c = no_save_needed(&rec);
        if !f.json {
            println!("{}", c.detail);
        }
        c
    };
    let result = match p.apply(&apply_plan) {
        Ok(r) => r,
        Err(cause) => {
            let Some(stopped) = describe_failure(p, &name, &target, &cause) else {
                return Err(cause.into());
            };
            // the change got as far as stopping the box: there is no agent left to release anything on
            if let Some(h) = hold.as_mut() {
                h.disarm();
            }
            let message = t(
                "upgrade.err_interrupted",
                &[("box", name.as_str()), ("why", &stopped.reason)],
            );
            finish_with(
                f,
                &Outcome2 {
                    plan: &plan,
                    applied: false,
                    dry_run: false,
                    result: None,
                    upgrade: None,
                    interrupted: Some(&stopped),
                    memory_guard: None,
                    upgrade_kind: kind.as_ref(),
                    secrets_store_warning: loud.as_deref(),
                },
            )?;
            return Err(CliError::Msg(message));
        }
    };
    if let Some(h) = hold.as_mut() {
        h.disarm();
    }
    if !f.json {
        if let Some(r) = &result {
            println!(
                "{}",
                t(
                    "upgrade.done",
                    &[
                        ("box", r.spec.name.as_str()),
                        ("state", &r.state.to_string()),
                        ("image", r.spec.image.as_deref().unwrap_or("unknown")),
                    ]
                )
            );
        }
        println!("{}", t("upgrade.waiting", &[]));
    }
    // The new machine has a new id: the SSH entry and the old host key are brought up to date before anything reaches
    // for the box, and the check below reads the box's record again, so it asks the new machine.
    let after = match result.clone() {
        Some(r) => Some(r),
        None => p.get(&name).ok().flatten(),
    };
    let ssh_entry = after.as_ref().map_or_else(
        || {
            Step::new(
                StepOutcome::Skipped,
                t("upgrade.ssh_nothing", &[("box", name.as_str())]),
            )
        },
        |after| refresh_ssh(rec.provider_id.as_deref(), after),
    );
    let kept_by_laptop = store.fate == StoreFate::KeptByLaptop;
    let accepted = sets_store_aside(around.accept_new_store, store.fate);
    let settled = settle_after_replace(
        p,
        agent,
        &name,
        waits,
        &|ag, rec| {
            if accepted {
                (around.recover)(ag, rec)
            } else if kept_by_laptop {
                (around.place_escrow)(ag, rec)
            } else {
                None
            }
        },
        around.restore_backups,
        backups_before,
    );
    let (ready, selftest, backup_credentials, secrets_recovery) = (
        settled.ready,
        settled.selftest,
        settled.backup,
        settled.recovery,
    );
    // Only when the box answered: a box that did not cannot be asked what is running.
    let services = (ready.outcome != StepOutcome::Failed)
        .then(|| p.get(&name).ok().flatten())
        .flatten()
        .and_then(|after| restore_services(agent, &after))
        .unwrap_or_else(|| {
            Step::new(
                StepOutcome::Skipped,
                t("upgrade.services_none", &[("box", name.as_str())]),
            )
        });
    // After the services, so the box's new secrets store and its SSH entry are in place before the dashboard's token goes in.
    let dashboard = (ready.outcome != StepOutcome::Failed)
        .then(|| p.get(&name).ok().flatten())
        .flatten()
        .and_then(|after| (around.restore_dashboard)(agent, &after))
        .unwrap_or_else(|| {
            Step::new(
                StepOutcome::Skipped,
                t("upgrade.dashboard_none", &[("box", name.as_str())]),
            )
        });
    let memory_guard = (ready.outcome != StepOutcome::Failed)
        .then(|| p.get(&name).ok().flatten())
        .flatten()
        .and_then(|after| (around.memory_guard)(agent, &after));
    let approvers = (report_ready(&ready))
        .then(|| p.get(&name).ok().flatten())
        .flatten()
        .and_then(|after| (around.review_signers)(&after));
    let (old_system_disk, old_system_disk_snapshot) = old_disk_report(
        copy_taken_first.as_deref(),
        result.as_ref(),
        &name,
        plan_keeps_old_disk(&plan),
        loud.is_some(),
    );
    let report = Report {
        image: target,
        checkpoint,
        ready,
        selftest,
        ssh_entry,
        backup_credentials,
        services,
        dashboard,
        memory_guard,
        secrets_store: store,
        secrets_recovery,
        approvers,
        old_system_disk,
        old_system_disk_snapshot,
    };
    if !f.json {
        if let Some(c) = &report.old_system_disk {
            println!("{}", c.detail);
        }
        println!("{}", report.ready.detail);
        if let Some(r) = &report.secrets_recovery {
            println!("{}", r.detail);
        }
        if let Some(a) = &report.approvers {
            println!("{}", a.detail);
        }
        println!("{}", report.backup_credentials.detail);
        println!("{}", report.services.detail);
        println!("{}", report.dashboard.detail);
        if let Some(m) = &report.memory_guard {
            println!("{}", m.detail);
        }
        println!("{}", report.ssh_entry.detail);
        if let Some(test) = &report.selftest {
            for line in describe_selftest(test) {
                println!("{line}");
            }
        }
    }
    finish_with(
        f,
        &Outcome2 {
            plan: &plan,
            applied: true,
            dry_run: false,
            result: result.as_ref(),
            upgrade: Some(&report),
            interrupted: None,
            memory_guard: None,
            upgrade_kind: kind.as_ref(),
            secrets_store_warning: loud.as_deref(),
        },
    )?;
    // The change is made either way; a box that does not check out is a failure the person must not miss.
    if report.ready.outcome == StepOutcome::Failed {
        return Err(CliError::Msg(t(
            "upgrade.err_not_ready",
            &[("box", name.as_str())],
        )));
    }
    if report.selftest.as_ref().is_some_and(|s| !s.ok) {
        return Err(CliError::Msg(t(
            "upgrade.err_selftest",
            &[("box", name.as_str())],
        )));
    }
    // backups that were set up and are not working are never a quiet success
    if report.backup_credentials.outcome == StepOutcome::Failed {
        return Err(CliError::Msg(t(
            "upgrade.err_backups",
            &[("box", name.as_str())],
        )));
    }
    Ok(())
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
#[path = "upgrade_backups_tests.rs"]
mod backups_tests;

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use std::sync::atomic::{AtomicU32, Ordering};

    use ozbox_core::{BoxSpec, MetricsSample, Size};

    use super::*;
    use crate::serve::agent::{Check, CheckpointOutcome, Incident};

    type TestResult = std::result::Result<(), Box<dyn std::error::Error>>;

    /// A box that answers only what it recorded about its first boot (or cannot be asked). Its answer is whatever the
    /// test says, including a forged one: the box user's shell is where it comes from.
    struct FirstBootBox {
        record: std::result::Result<BoxFirstBoot, String>,
    }

    impl BoxAgent for FirstBootBox {
        fn metrics_now(
            &self,
            _: &BoxRecord,
            _: u64,
        ) -> std::result::Result<MetricsSample, AgentError> {
            Err(AgentError::Unsupported("none".into()))
        }
        fn metrics_series(
            &self,
            _: &BoxRecord,
            _: u64,
            _: u64,
            _: u64,
        ) -> std::result::Result<Vec<MetricsSample>, AgentError> {
            Err(AgentError::Unsupported("none".into()))
        }
        fn selftest(&self, _: &BoxRecord, _: u64) -> std::result::Result<SelfTest, AgentError> {
            Err(AgentError::Unsupported("none".into()))
        }
        fn incidents(
            &self,
            _: &BoxRecord,
            _: u64,
            _: u64,
        ) -> std::result::Result<Vec<Incident>, AgentError> {
            Ok(vec![])
        }
        fn image_agent(
            &self,
            _: &BoxRecord,
        ) -> std::result::Result<crate::serve::agent::ImageAgent, AgentError> {
            match &self.record {
                Ok(first_boot) => Ok(crate::serve::agent::ImageAgent {
                    from_image: true,
                    image_version: Some("0.1.0-alpha.0".into()),
                    agent_present: true,
                    arch: None,
                    first_boot: first_boot.clone(),
                }),
                Err(why) => Err(AgentError::Unreachable(why.clone())),
            }
        }
    }

    fn ours() -> String {
        "a".repeat(64)
    }

    fn forged_ours() -> std::result::Result<BoxFirstBoot, String> {
        Ok(BoxFirstBoot::Recorded(ours()))
    }

    /// Run the upgrade command's flow to the plan (a dry run) to `image`. The secrets store is reported lost, so a plan
    /// that reaches the store gate is refused: `asked` with that refusal proves a replace was planned AND that the gate
    /// still applies to it; `Ok` with no store check means "Nothing to do".
    fn run_upgrade(
        p: &dyn Provider,
        name: &BoxName,
        image: &str,
        record: std::result::Result<BoxFirstBoot, String>,
        reprovision: bool,
    ) -> (Result<()>, bool) {
        run_upgrade_with(p, name, image, record, reprovision, StoreFate::Lost)
    }

    /// [`run_upgrade`] with the secrets store's fate chosen: `Kept` lets a planned change through the store gate.
    fn run_upgrade_with(
        p: &dyn Provider,
        name: &BoxName,
        image: &str,
        record: std::result::Result<BoxFirstBoot, String>,
        reprovision: bool,
        fate: StoreFate,
    ) -> (Result<()>, bool) {
        let asked = std::sync::atomic::AtomicBool::new(false);
        let store = |_: &dyn BoxAgent, _: &BoxRecord| {
            asked.store(true, Ordering::SeqCst);
            StoreCheck {
                fate,
                detail: "the store's key is in a file on the system disk".into(),
            }
        };
        let r = execute(
            p,
            &FirstBootBox { record },
            name.clone(),
            Some(image.into()),
            false,
            &Flags {
                yes: true,
                dry_run: true,
                json: true,
            },
            Waits::default(),
            &Around {
                store_check: &store,
                accept_new_store: false,
                old_disk: OldDisk::NotOffered,
                recover: &|_, _| None,
                restore_backups: &|_, _| None,
                restore_services: &|_, _| None,
                restore_dashboard: &|_, _| None,
                memory_guard: &|_, _| None,
                refresh_ssh: &|_, _| Step::new(StepOutcome::Skipped, String::new()),
                review_signers: &|_| None,
                place_escrow: &|_, _| None,
                first_boot: FirstBootOpts {
                    ours: ours(),
                    reprovision,
                    allow_mismatch: false,
                    enabled: true,
                },
                strict_checkpoint: false,
                legacy_checkpoint: false,
                no_checkpoint: false,
            },
        );
        (r, asked.load(Ordering::SeqCst))
    }

    /// A sandbox box already on `fake-image-2`, whose machine the provider records as made with `authority` (`None`: no
    /// record, a machine from before 0.1.1).
    fn sandbox_box(
        dir: &std::path::Path,
        authority: Option<String>,
    ) -> std::result::Result<
        (
            ozbox_core::Engine<ozbox_provider_fake::FakeBackend>,
            BoxName,
        ),
        Box<dyn std::error::Error>,
    > {
        let p = ozbox_provider_fake::open(dir);
        let n = BoxName::new("main")?;
        let mut spec = BoxSpec::new(n.clone(), Size::S);
        if let Some(h) = authority {
            spec.labels.insert(ozbox_core::FIRST_BOOT_LABEL.into(), h);
        }
        p.apply(&p.plan(&Operation::Create { spec })?)?;
        p.apply(&p.plan(&Operation::Upgrade {
            name: n.clone(),
            image: "fake-image-2".into(),
            reprovision: false,
            keep_old_system_disk: false,
        })?)?;
        Ok((p, n))
    }

    /// A box on the sandbox's first image, planned and run through the command's own flow with the store's fate chosen: the
    /// store check says `fate`, the person did (or did not) accept a new store, and `old_disk` is the copy policy.
    fn run_keeping(
        p: &dyn Provider,
        name: &BoxName,
        fate: StoreFate,
        accept: bool,
        old_disk: OldDisk,
        dry_run: bool,
    ) -> Result<()> {
        run_keeping_asking(
            &FirstBootBox {
                record: Err("no route".into()),
            },
            p,
            name,
            fate,
            accept,
            old_disk,
            dry_run,
        )
    }

    fn run_keeping_asking(
        agent: &dyn BoxAgent,
        p: &dyn Provider,
        name: &BoxName,
        fate: StoreFate,
        accept: bool,
        old_disk: OldDisk,
        dry_run: bool,
    ) -> Result<()> {
        execute(
            p,
            agent,
            name.clone(),
            Some("fake-image-2".into()),
            false,
            &Flags {
                yes: true,
                dry_run,
                json: true,
            },
            Waits::default(),
            &Around {
                store_check: &|_, _| StoreCheck {
                    fate,
                    detail: "the store's key is in a file on the system disk".into(),
                },
                accept_new_store: accept,
                old_disk,
                recover: &|_, _| None,
                restore_backups: &|_, _| None,
                restore_services: &|_, _| None,
                restore_dashboard: &|_, _| None,
                memory_guard: &|_, _| None,
                refresh_ssh: &|_, _| Step::new(StepOutcome::Skipped, String::new()),
                review_signers: &|_| None,
                place_escrow: &|_, _| None,
                first_boot: FirstBootOpts::default(),
                strict_checkpoint: false,
                legacy_checkpoint: false,
                no_checkpoint: false,
            },
        )
    }

    fn fresh_box(
        dir: &std::path::Path,
    ) -> std::result::Result<
        (
            ozbox_core::Engine<ozbox_provider_fake::FakeBackend>,
            BoxName,
        ),
        Box<dyn std::error::Error>,
    > {
        let p = ozbox_provider_fake::open(dir);
        let n = BoxName::new("main")?;
        p.apply(&p.plan(&Operation::Create {
            spec: BoxSpec::new(n.clone(), Size::S),
        })?)?;
        Ok((p, n))
    }

    fn old_disk_copies(
        p: &dyn Provider,
        n: &BoxName,
    ) -> std::result::Result<Vec<ozbox_core::SnapshotInfo>, Box<dyn std::error::Error>> {
        Ok(p.snapshots(n)?
            .into_iter()
            .filter(|s| s.labels.contains_key(ozbox_provider_aws::PURPOSE_TAG))
            .collect())
    }

    /// The incident: a store whose key is a file on the system disk (or that cannot be told) was lost with the disk, and the
    /// upgrade kept nothing. Now the copy is taken for exactly those fates, and only when the person did not opt out.
    #[test]
    fn a_copy_of_the_old_system_disk_is_wanted_exactly_when_the_stores_key_may_be_lost() {
        use StoreFate::*;
        for fate in [Lost, Unknown] {
            assert!(old_disk_copy_wanted(fate, OldDisk::Keep), "{fate:?}");
            for off in [OldDisk::OptedOut, OldDisk::NotOffered, OldDisk::StoreEmpty] {
                assert!(!old_disk_copy_wanted(fate, off), "{fate:?} {off:?}");
            }
        }
        for fate in [
            Kept,
            KeptByEscrow,
            KeptByLaptop,
            NotSaid,
            AlreadyLost,
            NotApplicable,
            MovingKey,
        ] {
            assert!(!old_disk_copy_wanted(fate, OldDisk::Keep), "{fate:?}");
        }
        assert_eq!(OldDisk::choose("aws", false, false), OldDisk::Keep);
        assert_eq!(OldDisk::choose("aws", true, false), OldDisk::OptedOut);
        assert_eq!(OldDisk::choose("aws", false, true), OldDisk::StoreEmpty);
        assert_eq!(OldDisk::choose("hcloud", false, false), OldDisk::NotOffered);
    }

    /// The plan carries the step (first) and keeps what the caller added after the provider's own notes.
    #[test]
    fn a_replanned_upgrade_lists_the_copy_first_and_keeps_the_notes_added_since() -> TestResult {
        let dir = tempfile::tempdir()?;
        let (p, n) = fresh_box(dir.path())?;
        let op = Operation::Upgrade {
            name: n.clone(),
            image: "fake-image-2".into(),
            reprovision: false,
            keep_old_system_disk: false,
        };
        let mut plan = p.plan(&op)?;
        let base = plan.notes.len();
        plan.notes.push("added by the command".into());
        let kinds = |pl: &Plan| {
            pl.changes
                .iter()
                .map(|c| c.kind.clone())
                .collect::<Vec<_>>()
        };
        assert!(!plan_keeps_old_disk(&plan));
        let fresh = with_old_disk_copy(&p, plan, base)?;
        assert!(plan_keeps_old_disk(&fresh));
        assert_eq!(
            kinds(&fresh)[0],
            "snapshot.old_system_disk",
            "{:?}",
            kinds(&fresh)
        );
        assert_eq!(
            fresh.notes.last().map(String::as_str),
            Some("added by the command")
        );
        Ok(())
    }

    /// An upgrade the plan cannot show keeps the store's key is applied only after the old system disk is copied, and the
    /// report names the copy.
    #[test]
    fn an_accepted_upgrade_of_a_store_that_may_be_lost_keeps_a_copy_and_names_it() -> TestResult {
        for fate in [StoreFate::Lost, StoreFate::Unknown] {
            let dir = tempfile::tempdir()?;
            let (p, n) = fresh_box(dir.path())?;
            run_keeping(&p, &n, fate, true, OldDisk::Keep, false).map_err(|e| e.to_string())?;
            let copies = old_disk_copies(&p, &n)?;
            assert_eq!(copies.len(), 1, "{fate:?}: {copies:?}");
            assert!(!copies[0].includes_work);
            assert_eq!(
                p.get(&n)?.ok_or("gone")?.spec.image.as_deref(),
                Some("fake-image-2"),
                "the upgrade itself went ahead"
            );
            // and it is deletable like any snapshot
            p.apply(&p.plan(&Operation::DeleteSnapshot {
                name: n.clone(),
                snapshot: copies[0].id.clone(),
            })?)?;
            assert!(old_disk_copies(&p, &n)?.is_empty());
        }
        Ok(())
    }

    /// A box that notes, when it is first asked to get ready for its stop, how many copies of old system disks the provider holds.
    struct ReadyAsker {
        inner: FirstBootBox,
        dir: std::path::PathBuf,
        copies_when_asked: std::sync::Mutex<Vec<usize>>,
    }

    impl BoxAgent for ReadyAsker {
        fn metrics_now(
            &self,
            r: &BoxRecord,
            t: u64,
        ) -> std::result::Result<MetricsSample, AgentError> {
            self.inner.metrics_now(r, t)
        }
        fn metrics_series(
            &self,
            r: &BoxRecord,
            a: u64,
            b: u64,
            c: u64,
        ) -> std::result::Result<Vec<MetricsSample>, AgentError> {
            self.inner.metrics_series(r, a, b, c)
        }
        fn selftest(&self, r: &BoxRecord, t: u64) -> std::result::Result<SelfTest, AgentError> {
            self.inner.selftest(r, t)
        }
        fn incidents(
            &self,
            r: &BoxRecord,
            a: u64,
            b: u64,
        ) -> std::result::Result<Vec<Incident>, AgentError> {
            self.inner.incidents(r, a, b)
        }
        fn image_agent(
            &self,
            r: &BoxRecord,
        ) -> std::result::Result<crate::serve::agent::ImageAgent, AgentError> {
            self.inner.image_agent(r)
        }
        fn quiesce_call(
            &self,
            rec: &BoxRecord,
            method: &str,
            _: &[u8],
        ) -> std::result::Result<(u16, serde_json::Value), AgentError> {
            if method == "POST" {
                // the provider as it is right now (the sandbox keeps its state in the folder)
                let p = ozbox_provider_fake::open(&self.dir);
                let n = p
                    .snapshots(&rec.spec.name)
                    .map(|l| l.iter().filter(|s| s.is_old_system_disk_copy()).count())
                    .unwrap_or(usize::MAX);
                if let Ok(mut g) = self.copies_when_asked.lock() {
                    g.push(n);
                }
            }
            Err(AgentError::Unsupported("none".into()))
        }
    }

    /// A box whose agent predates the quiesce service (it answers 404), and counts what it was asked.
    struct OlderAgent {
        inner: FirstBootBox,
        calls: std::sync::Mutex<Vec<String>>,
    }

    impl BoxAgent for OlderAgent {
        fn metrics_now(
            &self,
            r: &BoxRecord,
            t: u64,
        ) -> std::result::Result<MetricsSample, AgentError> {
            self.inner.metrics_now(r, t)
        }
        fn metrics_series(
            &self,
            r: &BoxRecord,
            a: u64,
            b: u64,
            c: u64,
        ) -> std::result::Result<Vec<MetricsSample>, AgentError> {
            self.inner.metrics_series(r, a, b, c)
        }
        fn selftest(&self, r: &BoxRecord, t: u64) -> std::result::Result<SelfTest, AgentError> {
            self.inner.selftest(r, t)
        }
        fn incidents(
            &self,
            r: &BoxRecord,
            a: u64,
            b: u64,
        ) -> std::result::Result<Vec<Incident>, AgentError> {
            self.inner.incidents(r, a, b)
        }
        fn quiesce_call(
            &self,
            _: &BoxRecord,
            method: &str,
            _: &[u8],
        ) -> std::result::Result<(u16, serde_json::Value), AgentError> {
            if let Ok(mut g) = self.calls.lock() {
                g.push(format!("quiesce {method}"));
            }
            Ok((404, serde_json::json!({})))
        }
        fn checkpoint(
            &self,
            _: &BoxRecord,
        ) -> std::result::Result<crate::serve::agent::CheckpointOutcome, AgentError> {
            if let Ok(mut g) = self.calls.lock() {
                g.push("checkpoint".into());
            }
            Err(AgentError::Unsupported("none".into()))
        }
    }

    fn upgrade_older(
        agent: &OlderAgent,
        p: &dyn Provider,
        name: &BoxName,
        legacy: bool,
        none: bool,
        dry_run: bool,
    ) -> Result<()> {
        execute(
            p,
            agent,
            name.clone(),
            Some("fake-image-2".into()),
            false,
            &Flags {
                yes: true,
                dry_run,
                json: true,
            },
            Waits {
                timeout: Duration::from_millis(1),
                poll: Duration::from_millis(1),
            },
            &Around {
                store_check: &|_, _| StoreCheck {
                    fate: StoreFate::Kept,
                    detail: "kept".into(),
                },
                accept_new_store: false,
                old_disk: OldDisk::NotOffered,
                recover: &|_, _| None,
                restore_backups: &|_, _| None,
                restore_services: &|_, _| None,
                restore_dashboard: &|_, _| None,
                memory_guard: &|_, _| None,
                refresh_ssh: &|_, _| Step::new(StepOutcome::Skipped, String::new()),
                review_signers: &|_| None,
                place_escrow: &|_, _| None,
                first_boot: FirstBootOpts::default(),
                strict_checkpoint: false,
                legacy_checkpoint: legacy,
                no_checkpoint: none,
            },
        )
    }

    /// B4-18 item 7: on a box whose agent is older, neither checkpoint is chosen for the person, not even with --yes. The
    /// command is refused before anything changes until --legacy-checkpoint or --no-checkpoint is named; a dry run shows
    /// the plan and is never refused.
    #[test]
    fn an_older_agent_needs_its_checkpoint_chosen_by_name_even_with_yes() -> TestResult {
        let dir = tempfile::tempdir()?;
        let (p, n) = fresh_box(dir.path())?;
        let older = || OlderAgent {
            inner: FirstBootBox {
                record: Err("no route".into()),
            },
            calls: std::sync::Mutex::new(Vec::new()),
        };
        let image = |p: &dyn Provider| -> std::result::Result<Option<String>, String> {
            Ok(p.get(&n)
                .map_err(|e| e.to_string())?
                .ok_or("gone")?
                .spec
                .image)
        };
        let before = image(&p)?;

        // a dry run is not refused
        let a = older();
        upgrade_older(&a, &p, &n, false, false, true).map_err(|e| e.to_string())?;
        assert_eq!(image(&p)?, before);

        // --yes alone: refused, nothing changed, the box was never asked to get ready or to checkpoint
        let a = older();
        let e = upgrade_older(&a, &p, &n, false, false, false)
            .err()
            .ok_or("an older agent with no choice went on")?
            .to_string();
        assert!(
            e.contains("--legacy-checkpoint")
                && e.contains("--no-checkpoint")
                && e.contains("Nothing was changed"),
            "{e}"
        );
        assert_eq!(image(&p)?, before, "nothing changed");
        let calls = a.calls.lock().map_err(|e| e.to_string())?.clone();
        assert_eq!(
            calls,
            vec!["quiesce GET".to_string()],
            "only the read-only preview"
        );

        // --no-checkpoint: goes on, with no checkpoint and no POST
        let a = older();
        upgrade_older(&a, &p, &n, false, true, false).map_err(|e| e.to_string())?;
        assert_eq!(image(&p)?.as_deref(), Some("fake-image-2"));
        let calls = a.calls.lock().map_err(|e| e.to_string())?.clone();
        assert!(!calls.contains(&"checkpoint".to_string()), "{calls:?}");
        Ok(())
    }

    #[test]
    fn an_older_agent_with_legacy_checkpoint_uses_its_checkpoint() -> TestResult {
        let dir = tempfile::tempdir()?;
        let (p, n) = fresh_box(dir.path())?;
        let a = OlderAgent {
            inner: FirstBootBox {
                record: Err("no route".into()),
            },
            calls: std::sync::Mutex::new(Vec::new()),
        };
        upgrade_older(&a, &p, &n, true, false, false).map_err(|e| e.to_string())?;
        let calls = a.calls.lock().map_err(|e| e.to_string())?.clone();
        assert!(calls.contains(&"checkpoint".to_string()), "{calls:?}");
        Ok(())
    }

    /// The hold the box puts on new runs lasts ten minutes from the start of its preparation for the stop, and a first copy of a
    /// disk can take longer: so the copy is complete BEFORE the box is asked to get ready, and the apply does not take a second.
    #[test]
    fn the_copy_is_taken_before_the_box_is_asked_to_get_ready_for_its_stop() -> TestResult {
        let dir = tempfile::tempdir()?;
        let (p, n) = fresh_box(dir.path())?;
        let agent = ReadyAsker {
            inner: FirstBootBox {
                record: Err("no route".into()),
            },
            dir: dir.path().to_path_buf(),
            copies_when_asked: std::sync::Mutex::new(Vec::new()),
        };
        run_keeping_asking(&agent, &p, &n, StoreFate::Lost, true, OldDisk::Keep, false)
            .map_err(|e| e.to_string())?;
        let asked = agent
            .copies_when_asked
            .lock()
            .map_err(|e| e.to_string())?
            .clone();
        assert_eq!(
            asked,
            vec![1],
            "the copy existed when the box was asked to get ready"
        );
        assert_eq!(
            old_disk_copies(&p, &n)?.len(),
            1,
            "and the apply took no second one"
        );
        assert_eq!(
            p.get(&n)?.ok_or("gone")?.spec.image.as_deref(),
            Some("fake-image-2")
        );
        Ok(())
    }

    /// The report names the snapshot THIS apply took, said by the apply itself, even when the box already holds the copies of
    /// earlier upgrades (a retried upgrade takes another copy): never one picked out of a listing.
    #[test]
    fn the_report_names_the_copy_this_apply_took_and_never_guesses() -> TestResult {
        let dir = tempfile::tempdir()?;
        let (p, n) = fresh_box(dir.path())?;
        let op = |reprovision: bool| Operation::Upgrade {
            name: n.clone(),
            image: "fake-image-2".into(),
            reprovision,
            keep_old_system_disk: true,
        };
        let mut said = Vec::new();
        for reprovision in [false, true, true] {
            let rec = p.apply(&p.plan(&op(reprovision))?)?.ok_or("no record")?;
            let (step, id) = old_disk_report(None, Some(&rec), &n, true, true);
            let step = step.ok_or("no step")?;
            let id = id.ok_or("no id")?;
            assert_eq!(step.outcome, StepOutcome::Done);
            assert!(step.detail.contains(&id) && step.detail.contains("ozbox backup delete main"));
            said.push(id);
        }
        // every apply took its own copy, each report named its own, and the listing holds all of them
        let held: Vec<String> = old_disk_copies(&p, &n)?.into_iter().map(|c| c.id).collect();
        assert_eq!(said.len(), 3);
        let mut distinct = said.clone();
        distinct.sort();
        distinct.dedup();
        assert_eq!(distinct.len(), 3, "{said:?}");
        for id in &said {
            assert!(held.contains(id), "{id} not in {held:?}");
        }
        // an apply that did not say which snapshot it took is reported as a failure, not guessed from the listing
        let (step, id) = old_disk_report(None, None, &n, true, true);
        assert_eq!(step.ok_or("no step")?.outcome, StepOutcome::Failed);
        assert!(id.is_none());
        Ok(())
    }

    /// Opting out, a provider that cannot, a known-empty store, and a store that is kept: no copy, and nothing else changes.
    #[test]
    fn no_copy_is_kept_when_opted_out_unavailable_empty_or_the_store_is_kept() -> TestResult {
        let cases = [
            (StoreFate::Unknown, OldDisk::OptedOut),
            (StoreFate::Lost, OldDisk::NotOffered),
            (StoreFate::Lost, OldDisk::StoreEmpty),
            (StoreFate::Kept, OldDisk::Keep),
            (StoreFate::KeptByEscrow, OldDisk::Keep),
            (StoreFate::KeptByLaptop, OldDisk::Keep),
        ];
        for (fate, old_disk) in cases {
            let dir = tempfile::tempdir()?;
            let (p, n) = fresh_box(dir.path())?;
            let accept = matches!(fate, StoreFate::Lost | StoreFate::Unknown);
            run_keeping(&p, &n, fate, accept, old_disk, false).map_err(|e| e.to_string())?;
            assert!(old_disk_copies(&p, &n)?.is_empty(), "{fate:?} {old_disk:?}");
            assert_eq!(
                p.get(&n)?.ok_or("gone")?.spec.image.as_deref(),
                Some("fake-image-2")
            );
        }
        Ok(())
    }

    /// A refused upgrade (no acceptance) changes nothing, takes no copy, and says what accepting does.
    #[test]
    fn a_refused_upgrade_takes_no_copy_and_says_what_accepting_would_keep() -> TestResult {
        let dir = tempfile::tempdir()?;
        let (p, n) = fresh_box(dir.path())?;
        let e = run_keeping(&p, &n, StoreFate::Unknown, false, OldDisk::Keep, false)
            .err()
            .ok_or("expected a refusal")?
            .to_string();
        assert!(
            e.contains("--accept-new-secrets-store") && e.contains("--no-pre-upgrade-snapshot"),
            "{e}"
        );
        assert!(old_disk_copies(&p, &n)?.is_empty());
        assert_ne!(
            p.get(&n)?.ok_or("gone")?.spec.image.as_deref(),
            Some("fake-image-2")
        );
        Ok(())
    }

    /// A dry run plans the copy (so the person sees it) and takes none.
    #[test]
    fn a_dry_run_plans_the_copy_and_takes_none() -> TestResult {
        let dir = tempfile::tempdir()?;
        let (p, n) = fresh_box(dir.path())?;
        run_keeping(&p, &n, StoreFate::Unknown, true, OldDisk::Keep, true)
            .map_err(|e| e.to_string())?;
        assert!(old_disk_copies(&p, &n)?.is_empty());
        Ok(())
    }

    /// The warning is its own block with what is lost, what is kept, and the exact commands afterwards (never only a note).
    #[test]
    fn the_warning_says_what_is_lost_what_is_kept_and_what_to_run_afterwards() {
        let lost = StoreCheck {
            fate: StoreFate::Lost,
            detail: String::new(),
        };
        let w = store_loss_warning(&lost, "main", OldDisk::Keep).unwrap_or_default();
        for want in [
            "WILL BE LOST",
            "file on its system disk",
            "ozbox-purpose=pre-upgrade-root",
            "ozbox backup delete main <snapshot id>",
            "ozbox secrets import",
            "--box",
            "ozbox adopt-fleet-key main",
            "imported with `ozbox secrets import`",
        ] {
            assert!(w.contains(want), "{want}: {w}");
        }
        let unknown = StoreCheck {
            fate: StoreFate::Unknown,
            detail: String::new(),
        };
        let w = store_loss_warning(&unknown, "main", OldDisk::Keep).unwrap_or_default();
        assert!(
            w.contains("MAY BE LOST") && w.contains("ozbox adopt-fleet-key main"),
            "{w}"
        );
        let off = store_loss_warning(&unknown, "main", OldDisk::OptedOut).unwrap_or_default();
        assert!(
            off.contains("--no-pre-upgrade-snapshot") && off.contains("can never be opened"),
            "{off}"
        );
        let none = store_loss_warning(&lost, "main", OldDisk::NotOffered).unwrap_or_default();
        assert!(none.contains("kept on this provider"), "{none}");
        for quiet in [
            StoreFate::Kept,
            StoreFate::KeptByEscrow,
            StoreFate::AlreadyLost,
        ] {
            let c = StoreCheck {
                fate: quiet,
                detail: String::new(),
            };
            assert!(
                store_loss_warning(&c, "main", OldDisk::Keep).is_none(),
                "{quiet:?}"
            );
        }
        assert!(store_loss_warning(&lost, "main", OldDisk::StoreEmpty).is_none());
    }

    fn replaced_with_the_store_gate(r: &Result<()>, asked: bool) -> bool {
        let e = r.as_ref().err().map(|e| e.to_string()).unwrap_or_default();
        asked && e.contains("--accept-new-secrets-store")
    }

    /// The incident: a box on the right image whose first boot came from a stale copy of the modules. Before, "Nothing to
    /// do"; now a replace from the same image, with every upgrade check (here the secrets store's) still in force.
    #[test]
    fn a_box_on_the_target_image_with_a_stale_first_boot_is_replaced_not_left() -> TestResult {
        for authority in [None, Some("b".repeat(64))] {
            let dir = tempfile::tempdir()?;
            let (p, n) = sandbox_box(dir.path(), authority.clone())?;
            let (r, asked) =
                run_upgrade(&p, &n, "fake-image-2", Ok(BoxFirstBoot::Unrecorded), false);
            assert!(
                replaced_with_the_store_gate(&r, asked),
                "{authority:?}: {r:?}"
            );
        }
        Ok(())
    }

    /// H1: the box's answer travels through its user's shell, whose rc files are on /work, so it can say anything. A box
    /// that prints this program's hash is repaired all the same when the provider's record says otherwise (or nothing).
    #[test]
    fn a_forged_answer_from_the_box_cannot_skip_the_repair() -> TestResult {
        for authority in [None, Some("b".repeat(64))] {
            let dir = tempfile::tempdir()?;
            let (p, n) = sandbox_box(dir.path(), authority.clone())?;
            let (r, asked) = run_upgrade(&p, &n, "fake-image-2", forged_ours(), false);
            assert!(
                replaced_with_the_store_gate(&r, asked),
                "{authority:?}: {r:?}"
            );
        }
        Ok(())
    }

    #[test]
    fn a_box_whose_record_and_answer_are_this_programs_has_nothing_to_do() -> TestResult {
        let dir = tempfile::tempdir()?;
        let (p, n) = sandbox_box(dir.path(), Some(ours()))?;
        let (r, asked) = run_upgrade(&p, &n, "fake-image-2", forged_ours(), false);
        assert!(r.is_ok() && !asked, "{r:?}");
        Ok(())
    }

    /// The box's answer can only ask for more: when it disagrees with a current record, is missing or malformed, the
    /// machine is replaced.
    #[test]
    fn a_box_that_disagrees_with_a_current_record_is_repaired() -> TestResult {
        for answer in [
            BoxFirstBoot::Unrecorded,
            BoxFirstBoot::Malformed,
            BoxFirstBoot::Recorded("b".repeat(64)),
        ] {
            let dir = tempfile::tempdir()?;
            let (p, n) = sandbox_box(dir.path(), Some(ours()))?;
            let (r, asked) = run_upgrade(&p, &n, "fake-image-2", Ok(answer.clone()), false);
            assert!(replaced_with_the_store_gate(&r, asked), "{answer:?}: {r:?}");
        }
        Ok(())
    }

    #[test]
    fn a_box_that_cannot_be_asked_follows_the_record_and_reprovision_always_replaces() -> TestResult
    {
        let dir = tempfile::tempdir()?;
        let (p, n) = sandbox_box(dir.path(), Some(ours()))?;
        let (r, asked) = run_upgrade(&p, &n, "fake-image-2", Err("no route".into()), false);
        assert!(r.is_ok() && !asked, "{r:?}");
        let (r, asked) = run_upgrade(&p, &n, "fake-image-2", Err("no route".into()), true);
        assert!(replaced_with_the_store_gate(&r, asked), "{r:?}");
        // and with no record, the box need not be reachable at all for the repair to be planned
        let dir = tempfile::tempdir()?;
        let (p, n) = sandbox_box(dir.path(), None)?;
        let (r, asked) = run_upgrade(&p, &n, "fake-image-2", Err("no route".into()), false);
        assert!(replaced_with_the_store_gate(&r, asked), "{r:?}");
        Ok(())
    }

    /// An unfinished upgrade to this very image is finished, never replaced again or refused, whatever the box says.
    #[test]
    fn an_unfinished_upgrade_is_finished_first_in_the_sandbox() -> TestResult {
        let dir = tempfile::tempdir()?;
        let (p, n) = sandbox_box(dir.path(), None)?;
        let rec = p.get(&n)?.ok_or("gone")?;
        ozbox_core::Backend::set_upgrade_mark(p.backend(), &rec, Some("fake-image-2"))?;
        let plan = p.plan(&Operation::Upgrade {
            name: n.clone(),
            image: "fake-image-2".into(),
            reprovision: true,
            keep_old_system_disk: false,
        })?;
        let kinds: Vec<_> = plan.changes.iter().map(|c| c.kind.as_str()).collect();
        assert_eq!(
            kinds,
            ["upgrade.finish"],
            "the engine finishes first even when a replace is asked"
        );
        for reprovision in [false, true] {
            // through the command the finish is planned (it passes the store gate, as any change does), never refused
            let (r, _) = run_upgrade_with(
                &p,
                &n,
                "fake-image-2",
                Ok(BoxFirstBoot::Unrecorded),
                reprovision,
                StoreFate::Kept,
            );
            assert!(r.is_ok(), "reprovision={reprovision}: {r:?}");
        }
        Ok(())
    }

    fn hetzner() -> (
        std::sync::Arc<ozbox_provider_hcloud::testing::Sim>,
        ozbox_core::Engine<ozbox_provider_hcloud::HcloudBackend>,
    ) {
        use ozbox_provider_hcloud::testing::{Sim, SimRunner};
        let sim = std::sync::Arc::new(Sim::new());
        let cfg = ozbox_provider_hcloud::HcloudConfig {
            region: Some("fsn1".into()),
            image: Some("img-1".into()),
            poll_interval: Duration::ZERO,
            ..ozbox_provider_hcloud::HcloudConfig::default()
        };
        let p = ozbox_core::Engine::new(ozbox_provider_hcloud::HcloudBackend::new(
            sim.clone(),
            std::sync::Arc::new(SimRunner::new(sim.clone())),
            cfg,
        ));
        (sim, p)
    }

    /// H2: a Hetzner box has no record of its first boot, so a server already on the image is not replaced to repair it. The
    /// upgrade must say "Nothing to do" with an honest note, never fail, and never forge a repair it cannot make.
    #[test]
    fn on_hetzner_a_box_with_no_record_has_nothing_to_do_and_is_told_why() -> TestResult {
        let (_sim, p) = hetzner();
        let n = BoxName::new("old")?;
        p.apply(&p.plan(&Operation::Create {
            spec: BoxSpec::new(n.clone(), Size::S),
        })?)?;
        let rec = p.get(&n)?.ok_or("gone")?;
        let image = rec.spec.image.clone().ok_or("no image")?;
        let (r, asked) = run_upgrade(&p, &n, &image, Ok(BoxFirstBoot::Unrecorded), false);
        assert!(r.is_ok() && !asked, "{r:?}");
        // the note itself, as the plan carries it
        let check = FirstBootCheck {
            name: "old",
            image: &image,
            ours: &ours(),
            asked: false,
            authority: None,
            can_replace: p
                .check_reprovision(&rec)
                .map(|_| ())
                .map_err(|e| e.to_string()),
        };
        let (replace, notes) = first_boot_decision(&check, &|| Ok(BoxFirstBoot::Unrecorded))?;
        assert!(!replace);
        let note = notes.join(" ");
        assert!(
            note.contains("cannot be checked or repaired")
                && note.contains("upgrade to a newer image"),
            "{note}"
        );
        // asking for the replace by name is refused with what to do instead, and changes nothing
        let (r, asked) = run_upgrade(&p, &n, &image, Ok(BoxFirstBoot::Unrecorded), true);
        let e = r.err().map(|e| e.to_string()).unwrap_or_default();
        assert!(
            !asked && e.contains("Refusing --reprovision") && e.contains("without --reprovision"),
            "{e}"
        );
        Ok(())
    }

    #[test]
    fn on_hetzner_an_interrupted_upgrade_is_finished_from_the_command() -> TestResult {
        let (sim, p) = hetzner();
        let n = BoxName::new("half")?;
        p.apply(&p.plan(&Operation::Create {
            spec: BoxSpec::new(n.clone(), Size::S),
        })?)?;
        p.apply(&p.plan(&Operation::Upgrade {
            name: n.clone(),
            image: "img-2".into(),
            reprovision: false,
            keep_old_system_disk: false,
        })?)?;
        // stopped after the rebuild, before the mark was cleared: running on the image, still marked
        sim.mark_upgrade(&n, "img-2")?;
        let plan = p.plan(&Operation::Upgrade {
            name: n.clone(),
            image: "img-2".into(),
            reprovision: false,
            keep_old_system_disk: false,
        })?;
        assert!(
            plan.changes.iter().any(|c| c.kind == "upgrade.finish"),
            "{:?}",
            plan.changes
        );
        for reprovision in [false, true] {
            // finished through the command, never refused as a same-image replace Hetzner cannot do
            let (r, _) = run_upgrade_with(
                &p,
                &n,
                "img-2",
                Ok(BoxFirstBoot::Unrecorded),
                reprovision,
                StoreFate::Kept,
            );
            assert!(r.is_ok(), "reprovision={reprovision}: {r:?}");
        }
        // and run for real, it clears the mark
        let rec = p.apply(&plan)?.ok_or("no record")?;
        assert!(!rec.spec.labels.contains_key(ozbox_core::UPGRADE_TO_LABEL));
        Ok(())
    }

    #[test]
    fn the_first_boot_decision() -> TestResult {
        let o = ours();
        let check = |authority: Option<&'static str>, asked: bool| FirstBootCheck {
            name: "main",
            image: "ami-1",
            ours: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            asked,
            authority,
            can_replace: Ok(()),
        };
        let current: &'static str =
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
        let other: &'static str =
            "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
        let never = || -> std::result::Result<BoxFirstBoot, String> {
            panic!("the box is not asked when the record decides")
        };
        // the record decides on its own when it says stale or says nothing; the box is not even asked
        let (yes, n) = first_boot_decision(&check(None, false), &never)?;
        assert!(yes && n.join(" ").contains("no record"), "{n:?}");
        let (yes, _) = first_boot_decision(&check(Some(other), false), &never)?;
        assert!(yes);
        // a current record is cross-checked
        let (yes, n) = first_boot_decision(&check(Some(current), false), &|| {
            Ok(BoxFirstBoot::Recorded(o.clone()))
        })?;
        assert!(!yes && n.join(" ").contains("confirms"), "{n:?}");
        let (yes, _) = first_boot_decision(&check(Some(current), false), &|| {
            Ok(BoxFirstBoot::Malformed)
        })?;
        assert!(yes);
        let (yes, n) =
            first_boot_decision(&check(Some(current), false), &|| Err("no route".into()))?;
        assert!(!yes && n.join(" ").contains("--reprovision"), "{n:?}");
        // --reprovision always replaces where the provider can
        let (yes, _) = first_boot_decision(&check(Some(current), true), &never)?;
        assert!(yes);
        Ok(())
    }

    /// N1: `--reprovision` on an unfinished upgrade says it is postponed; nothing else prints that line.
    #[test]
    fn a_reprovision_asked_during_an_unfinished_upgrade_is_said_to_wait() {
        let n = unfinished_reprovision_note(true, true, "main").expect("a note");
        assert!(
            n.contains("main") && n.contains("--reprovision") && n.contains("again"),
            "{n}"
        );
        assert_eq!(unfinished_reprovision_note(true, false, "main"), None);
        assert_eq!(unfinished_reprovision_note(false, true, "main"), None);
    }

    /// A stale or newer laptop cannot pair its first boot with an image built for another.
    #[test]
    fn an_image_built_for_another_first_boot_is_refused_unless_overridden() {
        let ours = "a".repeat(64);
        let image = |fb: Option<String>| ImageInfo {
            release: Some("0.1.1".into()),
            first_boot_sha256: fb,
            ..info(true, true)
        };
        let e =
            first_boot_gate(Some(&image(Some("b".repeat(64)))), "ami-1", &ours, false).unwrap_err();
        assert!(
            e.contains("--allow-first-boot-mismatch")
                && e.contains("bbbbbbbbbbbb")
                && e.contains("aaaaaaaaaaaa"),
            "{e}"
        );
        let n = first_boot_gate(Some(&image(Some("b".repeat(64)))), "ami-1", &ours, true).unwrap();
        assert!(n.iter().any(|l| l.starts_with("WARNING")), "{n:?}");
        let n = first_boot_gate(Some(&image(Some(ours.clone()))), "ami-1", &ours, false).unwrap();
        assert!(n.iter().any(|l| l.contains("same first-boot")), "{n:?}");
        // older releases record nothing: allowed, and said
        let n = first_boot_gate(Some(&image(None)), "ami-1", &ours, false).unwrap();
        assert!(n.iter().any(|l| l.contains("does not record")), "{n:?}");
        assert!(first_boot_gate(None, "ami-1", &ours, false).is_ok());
    }

    /// An agent that fails to answer a set number of times, then answers; its checkpoint is scripted.
    struct Scripted {
        unreachable_first: AtomicU32,
        checkpoint: std::result::Result<CheckpointOutcome, AgentError>,
        selftest: std::result::Result<SelfTest, AgentError>,
    }

    impl BoxAgent for Scripted {
        fn metrics_now(
            &self,
            _: &BoxRecord,
            _: u64,
        ) -> std::result::Result<MetricsSample, AgentError> {
            Err(AgentError::Unsupported("none".into()))
        }
        fn metrics_series(
            &self,
            _: &BoxRecord,
            _: u64,
            _: u64,
            _: u64,
        ) -> std::result::Result<Vec<MetricsSample>, AgentError> {
            Err(AgentError::Unsupported("none".into()))
        }
        fn selftest(&self, _: &BoxRecord, _: u64) -> std::result::Result<SelfTest, AgentError> {
            if self.unreachable_first.load(Ordering::SeqCst) > 0 {
                self.unreachable_first.fetch_sub(1, Ordering::SeqCst);
                return Err(AgentError::Unreachable(
                    "the agent is still starting".into(),
                ));
            }
            self.selftest.clone()
        }
        fn checkpoint(&self, _: &BoxRecord) -> std::result::Result<CheckpointOutcome, AgentError> {
            self.checkpoint.clone()
        }
        fn incidents(
            &self,
            _: &BoxRecord,
            _: u64,
            _: u64,
        ) -> std::result::Result<Vec<Incident>, AgentError> {
            Ok(Vec::new())
        }
    }

    fn passing() -> SelfTest {
        SelfTest {
            ts_ms: 1,
            ok: true,
            all_verified: true,
            checks: vec![Check {
                name: "work disk mounted".into(),
                outcome: Outcome::Pass,
            }],
        }
    }

    fn agent() -> Scripted {
        Scripted {
            unreachable_first: AtomicU32::new(0),
            checkpoint: Ok(CheckpointOutcome {
                repos_scanned: 3,
                errors: Vec::new(),
                ..Default::default()
            }),
            selftest: Ok(passing()),
        }
    }

    fn quick() -> Waits {
        Waits {
            timeout: Duration::from_millis(300),
            poll: Duration::from_millis(1),
        }
    }

    fn running_box(
        dir: &std::path::Path,
        name: &str,
    ) -> std::result::Result<(Box<dyn Provider>, BoxRecord), Box<dyn std::error::Error>> {
        let p = ozbox_provider_fake::open(dir);
        let spec = BoxSpec::new(BoxName::new(name)?, Size::S);
        let rec = p
            .apply(&p.plan(&Operation::Create { spec })?)?
            .ok_or("no record")?;
        Ok((Box::new(p), rec))
    }

    fn info(verified: bool, applicable: bool) -> ImageInfo {
        ImageInfo {
            id: "ami-1".into(),
            release: Some("2026.11.0".into()),
            created: None,
            signature_verified: verified,
            signature_detail: Some("the reason".into()),
            signature_applicable: applicable,
            first_boot_sha256: None,
            upgrade: None,
            skipped: Vec::new(),
        }
    }

    fn with_release(release: &str) -> ImageInfo {
        ImageInfo {
            release: Some(release.into()),
            ..info(true, true)
        }
    }

    #[test]
    fn an_image_from_a_different_minor_version_is_refused_and_a_different_patch_is_not() {
        let me = env!("CARGO_PKG_VERSION");
        let (major, rest) = me.split_once('.').unwrap_or(("0", "1"));
        let minor: u64 = rest
            .split('.')
            .next()
            .and_then(|m| m.parse().ok())
            .unwrap_or(1);
        let same = format!("{major}.{minor}.9");
        assert!(trust_gate(Some(&with_release(&same)), "ami-1", false).is_ok());
        let newer = format!("{major}.{}.0", minor + 1);
        let e = trust_gate(Some(&with_release(&newer)), "ami-1", false).unwrap_err();
        assert!(e.contains("Upgrade the ozbox program"), "{e}");
        // the unverified-image override does not lift a compatibility refusal
        assert!(trust_gate(Some(&with_release(&newer)), "ami-1", true).is_err());
        if minor > 0 {
            let older = format!("{major}.{}.0", minor - 1);
            let e = trust_gate(Some(&with_release(&older)), "ami-1", false).unwrap_err();
            assert!(e.contains("older than this ozbox program"), "{e}");
        }
        // a date-versioned image from before the scheme cannot be compared: allowed, with a note
        let legacy = trust_gate(Some(&with_release("2026.11.0")), "ami-1", false).unwrap();
        assert!(
            legacy.iter().any(|n| n.contains("date version")),
            "{legacy:?}"
        );
        // no release at all, or one that is not a version: allowed, and said, never silently
        for r in [None, Some(""), Some("latest")] {
            let i = ImageInfo {
                release: r.map(str::to_string),
                ..info(true, true)
            };
            let notes = trust_gate(Some(&i), "ami-1", false).unwrap();
            assert!(
                notes.iter().any(|n| n.contains("cannot be checked")),
                "{r:?}: {notes:?}"
            );
        }
    }

    #[test]
    fn latest_with_nothing_verified_is_refused_naming_what_was_passed_over_and_both_ways_forward() {
        let mut none = info(false, true);
        none.skipped = vec!["ami-0b (release 0.2.0-beta.1): not found".into()];
        let refusal = latest_unverified(Some(&none), false).unwrap_or_default();
        for want in [
            "ami-1",
            "ami-0b (release 0.2.0-beta.1)",
            "--image",
            "--allow-unverified-image",
        ] {
            assert!(refusal.contains(want), "{want}: {refusal}");
        }
        // verified, unsigned-by-design (sandbox), or asked for: not refused here
        assert!(latest_unverified(Some(&info(true, true)), false).is_none());
        assert!(latest_unverified(Some(&info(false, false)), false).is_none());
        assert!(latest_unverified(Some(&none), true).is_none());
        assert!(latest_unverified(None, false).is_none());
    }

    #[test]
    fn what_latest_passed_over_is_a_plan_note_each() {
        let mut i = info(true, true);
        i.skipped = vec!["ami-1 (release 1): a".into(), "ami-2 (release 2): b".into()];
        let notes = latest_skipped_notes(Some(&i));
        assert_eq!(notes.len(), 2);
        assert!(notes[0].contains("ami-1") && notes[1].contains("ami-2"));
        assert!(latest_skipped_notes(Some(&info(true, true))).is_empty());
    }

    #[test]
    fn only_an_image_whose_signature_could_be_checked_and_was_not_is_refused() {
        // verified: allowed, and the notes say how
        let ok = trust_gate(Some(&info(true, true)), "ami-1", false).unwrap_or_default();
        assert!(ok.iter().any(|n| n.contains("the reason")), "{ok:?}");
        // unverified on a provider that has signed releases: refused, with the reason and the way out
        let refusal = trust_gate(Some(&info(false, true)), "ami-1", false)
            .err()
            .unwrap_or_default();
        assert!(
            refusal.contains("the reason") && refusal.contains("--allow-unverified-image"),
            "{refusal}"
        );
        // ... unless asked for, and then the plan carries a warning
        let warned = trust_gate(Some(&info(false, true)), "ami-1", true).unwrap_or_default();
        assert!(
            warned.iter().any(|n| n.starts_with("WARNING")),
            "{warned:?}"
        );
        // a provider with nothing to check, or nothing to say, is not blocked
        assert!(trust_gate(Some(&info(false, false)), "x", false).is_ok());
        assert!(trust_gate(None, "x", false).is_ok());
        // and the override never turns an unverified image into a verified one in the notes
        assert!(!warned.iter().any(|n| n.starts_with("Release signature: ")));
    }

    fn with_record(release: &str, gen: char, live_from: Option<&str>) -> ImageInfo {
        ImageInfo {
            upgrade: Some(ozbox_core::UpgradeRecord::Present(
                ozbox_core::upgrade_kind::UpgradeBlock {
                    disk_generation: gen.to_string().repeat(64),
                    live_from: live_from.map(str::to_string),
                    work_format: Some(1),
                    work_format_reads: vec![1],
                },
            )),
            ..with_release(release)
        }
    }

    /// ADR 0038, phase 1: the plan names the kind the two signed releases call for and why, and says what is still done.
    #[test]
    fn the_plan_says_which_kind_of_upgrade_the_releases_call_for_and_why() {
        let (a, same, other) = (
            with_record("0.3.0", 'a', Some("0.3.0")),
            with_record("0.3.2", 'a', Some("0.3.0")),
            with_record("0.3.2", 'b', Some("0.3.0")),
        );
        let live = kind_report(true, Some(&a), Some(&same));
        assert_eq!(live.called_for, "live");
        let line = live.line();
        assert!(
            line.contains("live update")
                && line.contains("0.3.2")
                && line.contains("same system disk"),
            "{line}"
        );
        // it does not promise a live update this version cannot carry out
        assert!(
            line.contains("does not carry out a live update yet"),
            "{line}"
        );
        let replace = kind_report(true, Some(&a), Some(&other));
        assert_eq!(replace.called_for, "replace");
        assert!(
            replace.line().contains("new system disk"),
            "{}",
            replace.line()
        );
        // whatever is called for, what is carried out is a replace, and the JSON names the two apart
        for r in [&live, &replace, &kind_report(false, Some(&a), Some(&other))] {
            assert_eq!(r.carried_out, "replace");
        }
        let j = serde_json::to_value(&live).unwrap();
        assert_eq!(j["called_for"], "live");
        assert_eq!(j["carried_out"], "replace");
        assert!(j.get("kind").is_none());
        // a stopped box, whatever the manifests say
        assert_eq!(
            kind_report(false, Some(&a), Some(&other)).called_for,
            "in_place"
        );
        // a manifest that could not be fetched, or has no record: a replace with that reason, never an error
        assert_eq!(kind_report(true, None, Some(&same)).called_for, "replace");
        assert!(kind_report(true, None, Some(&same))
            .reason
            .contains("could not be read"));
        assert_eq!(
            kind_report(true, Some(&a), Some(&with_release("0.3.2"))).called_for,
            "replace"
        );
        // a damaged record is "not decided", and says so; the upgrade is not blocked by it
        let bad = ImageInfo {
            upgrade: Some(ozbox_core::UpgradeRecord::Malformed("no".into())),
            ..with_release("0.3.2")
        };
        let r = kind_report(true, Some(&a), Some(&bad));
        assert_eq!(r.called_for, "undecided");
        assert!(
            r.line().contains("not decided") && r.line().contains("as before"),
            "{}",
            r.line()
        );
    }

    #[test]
    fn a_change_that_keeps_the_box_running_saves_and_pushes_nothing() -> TestResult {
        let dir = tempfile::tempdir()?;
        let (_p, rec) = running_box(dir.path(), "dev")?;
        let step = no_save_needed(&rec);
        assert_eq!(step.outcome, StepOutcome::Skipped);
        assert!(step.detail.contains("nothing is pushed"), "{}", step.detail);
        Ok(())
    }

    #[test]
    fn the_checkpoint_step_says_what_happened_and_never_fails_the_upgrade() -> TestResult {
        let dir = tempfile::tempdir()?;
        let (_p, rec) = running_box(dir.path(), "dev")?;
        let step = checkpoint_before(&agent(), &rec);
        assert_eq!(step.outcome, StepOutcome::Done);
        assert!(step.detail.contains("3 repositories"));

        let mut partial = agent();
        partial.checkpoint = Ok(CheckpointOutcome {
            repos_scanned: 3,
            errors: vec!["repo-a: commit".into()],
            ..Default::default()
        });
        let step = checkpoint_before(&partial, &rec);
        assert_eq!(step.outcome, StepOutcome::Failed);
        assert!(step.detail.contains("nothing is lost"), "{}", step.detail);
        assert!(
            !step.detail.contains("repo-a"),
            "no repo names in the report"
        );

        let mut gone = agent();
        gone.checkpoint = Err(AgentError::Unreachable("no route to the box".into()));
        let step = checkpoint_before(&gone, &rec);
        assert_eq!(step.outcome, StepOutcome::Skipped);
        assert!(
            step.detail.contains("no route to the box") && step.detail.contains("nothing is lost")
        );

        let mut stopped = rec.clone();
        stopped.state = BoxState::Paused;
        assert_eq!(
            checkpoint_before(&agent(), &stopped).outcome,
            StepOutcome::Skipped
        );
        Ok(())
    }

    #[test]
    fn verification_waits_for_the_agent_then_reports_its_self_test() -> TestResult {
        let dir = tempfile::tempdir()?;
        let (p, rec) = running_box(dir.path(), "dev")?;
        let slow = agent();
        slow.unreachable_first.store(3, Ordering::SeqCst);
        let (ready, test) = verify_after(p.as_ref(), &slow, &rec.spec.name, quick());
        assert_eq!(ready.outcome, StepOutcome::Done);
        assert!(test.is_some_and(|t| t.ok));
        assert_eq!(
            slow.unreachable_first.load(Ordering::SeqCst),
            0,
            "it looked until the agent answered"
        );
        Ok(())
    }

    #[test]
    fn verification_gives_up_with_the_reason_and_never_reports_a_pass() -> TestResult {
        let dir = tempfile::tempdir()?;
        let (p, rec) = running_box(dir.path(), "dev")?;
        let dead = agent();
        dead.unreachable_first.store(u32::MAX, Ordering::SeqCst);
        let (ready, test) = verify_after(p.as_ref(), &dead, &rec.spec.name, quick());
        assert_eq!(ready.outcome, StepOutcome::Failed);
        assert!(ready.detail.contains("still starting"), "{}", ready.detail);
        assert!(test.is_none());
        // a box that is not running is not asked
        p.apply(&p.plan(&Operation::Pause {
            name: rec.spec.name.clone(),
        })?)?;
        let (ready, test) = verify_after(p.as_ref(), &agent(), &rec.spec.name, quick());
        assert_eq!(ready.outcome, StepOutcome::Failed);
        assert!(ready.detail.contains("paused"), "{}", ready.detail);
        assert!(test.is_none());
        Ok(())
    }

    #[test]
    fn a_system_that_cannot_reach_agents_says_so_instead_of_waiting() -> TestResult {
        let dir = tempfile::tempdir()?;
        let (p, rec) = running_box(dir.path(), "dev")?;
        let mut none = agent();
        none.selftest = Err(AgentError::Unsupported("no SSH here".into()));
        let started = Instant::now();
        let (ready, test) = verify_after(
            p.as_ref(),
            &none,
            &rec.spec.name,
            Waits {
                timeout: Duration::from_secs(30),
                poll: Duration::from_secs(5),
            },
        );
        assert_eq!(ready.outcome, StepOutcome::Skipped);
        assert!(ready.detail.contains("no SSH here"));
        assert!(test.is_none());
        assert!(started.elapsed() < Duration::from_secs(2));
        Ok(())
    }

    #[test]
    fn the_self_test_is_described_check_by_check_and_an_unknown_is_never_a_pass() {
        let mut t = passing();
        t.checks.push(Check {
            name: "work disk encrypted".into(),
            outcome: Outcome::Unknown {
                reason: "not visible from inside".into(),
            },
        });
        t.all_verified = false;
        let lines = describe_selftest(&t);
        assert!(lines[0].contains("pass"));
        assert!(lines[1].contains("unknown") && lines[1].contains("not visible"));
        assert!(lines
            .last()
            .is_some_and(|l| l.contains("could not be verified")));
        t.ok = false;
        t.checks.push(Check {
            name: "tunnels up".into(),
            outcome: Outcome::Fail {
                step: "tunnels up".into(),
                reason: "the tunnel service is not running".into(),
            },
        });
        let lines = describe_selftest(&t);
        assert!(lines
            .iter()
            .any(|l| l.contains("FAILED") && l.contains("tunnel service")));
        assert!(lines.last().is_some_and(|l| l.contains("FAILED")));
    }

    #[test]
    fn an_upgrade_counts_against_the_fleet_cap_only_when_it_starts_a_stopped_box() -> TestResult {
        let dir = tempfile::tempdir()?;
        let (_p, rec) = running_box(dir.path(), "dev")?;
        let op = Operation::Upgrade {
            name: rec.spec.name.clone(),
            image: "img".into(),
            reprovision: false,
            keep_old_system_disk: false,
        };
        assert!(matches!(budget_view(&op, &rec), Operation::Snapshot { .. }));
        let mut stopped = rec;
        stopped.state = BoxState::Paused;
        assert!(matches!(
            budget_view(&op, &stopped),
            Operation::Resume { .. }
        ));
        Ok(())
    }

    #[test]
    fn a_box_that_backs_up_to_a_repository_gets_its_credentials_back_and_nothing_else_is_said(
    ) -> TestResult {
        use crate::backups::{BoxOverride, ResticKind, ResticTarget};
        use crate::secrets::{MemorySecrets, SecretStore};
        use crate::serve::agent::SimulatedAgent;

        let dir = tempfile::tempdir()?;
        let p = ozbox_provider_fake::open(dir.path());
        let n = BoxName::new("dev")?;
        p.apply(&p.plan(&Operation::Create {
            spec: BoxSpec::new(n.clone(), Size::S),
        })?)?;
        let rec = p.get(&n)?.ok_or("no box")?;
        let agent = SimulatedAgent::default();
        let mut settings = crate::settings::Settings::default();
        let secrets = MemorySecrets::default();

        // no repository set up: nothing to put back, and the plan's note is all there is to say
        assert!(restore_with(&settings, &agent, &rec, &secrets).is_none());

        settings.backups.restic = Some(ResticTarget {
            kind: ResticKind::S3,
            location: "https://objects.example.com/bucket".into(),
        });
        // a repository whose secrets are not in the store: the step fails, names what is missing, keeps the manual way
        let failed = restore_with(&settings, &agent, &rec, &secrets).ok_or("no step")?;
        assert_eq!(failed.outcome, StepOutcome::Failed);
        assert!(
            failed.detail.contains("restic-password") && failed.detail.contains("Send credentials"),
            "{}",
            failed.detail
        );

        secrets.set("restic-password", "correct-horse-battery")?;
        secrets.set("restic-access-key", "AKIAEXAMPLE")?;
        secrets.set("restic-secret-key", "sekrit-key-value")?;
        let done = restore_with(&settings, &agent, &rec, &secrets).ok_or("no step")?;
        assert_eq!(done.outcome, StepOutcome::Done, "{}", done.detail);
        for secret in ["correct-horse-battery", "AKIAEXAMPLE", "sekrit-key-value"] {
            assert!(!done.detail.contains(secret));
        }
        // the box now holds them
        let (status, v) =
            crate::backup_ops::call(&agent, &rec, "GET", "/status", &serde_json::Value::Null)?;
        assert_eq!((status, &v["configured"]), (200, &serde_json::json!(true)));

        // a box switched off for backups is left alone, and the report says that is a choice (never "backups stopped")
        settings.backups.overrides.insert(
            "dev".into(),
            BoxOverride {
                enabled: Some(false),
                schedule: None,
            },
        );
        let off = restore_with(&settings, &agent, &rec, &secrets).ok_or("no step")?;
        assert_eq!(off.outcome, StepOutcome::Skipped);
        assert!(off.detail.contains("turned off"), "{}", off.detail);
        Ok(())
    }

    #[test]
    fn after_an_upgrade_the_ssh_entry_points_at_the_new_machine_and_the_old_host_key_goes(
    ) -> TestResult {
        let dir = tempfile::tempdir()?; // stands in for the home's .ssh
        let inputs = RouteInputs {
            aws_region: Some("us-east-1".into()),
            ..RouteInputs::default()
        };
        let mut before = BoxRecord {
            spec: BoxSpec::new(BoxName::new("dev")?, Size::S),
            state: BoxState::Running,
            provider: "aws".into(),
            provider_id: Some("i-0aaaaaaaaaaaaaaaa".into()),
            machine_type: None,
            snapshots: vec![],
            created_at: None,
            last_activity_at: None,
        };
        before.spec.region = Some("us-east-1".into());
        let old_route = sshconfig::routes(&before, &inputs)
            .into_iter()
            .next()
            .ok_or("route")?;
        sshconfig::write_config(dir.path(), "dev", &sshconfig::block("dev", &old_route), 1)?;
        std::fs::write(
            dir.path().join("known_hosts"),
            "i-0aaaaaaaaaaaaaaaa ssh-ed25519 AAAA\n",
        )?;

        let mut after = before.clone();
        after.provider_id = Some("i-0bbbbbbbbbbbbbbbb".into());
        let runner = ozbox_core::RecordingRunner::new();
        let step = ssh_entry_step(
            &runner,
            dir.path(),
            &inputs,
            before.provider_id.as_deref(),
            &after,
        );
        assert_eq!(step.outcome, StepOutcome::Done, "{}", step.detail);
        let conf = std::fs::read_to_string(dir.path().join("ozbox/config"))?;
        assert!(
            conf.contains("HostName i-0bbbbbbbbbbbbbbbb") && !conf.contains("i-0aaaaaaaaaaaaaaaa")
        );
        let calls = runner.calls();
        assert_eq!(calls.len(), 1);
        assert_eq!(calls[0].program, "ssh-keygen");
        assert_eq!(
            calls[0].args[..2],
            ["-R".to_string(), "i-0aaaaaaaaaaaaaaaa".to_string()]
        );

        // a box with no entry and no known_hosts: nothing to say
        let empty = tempfile::tempdir()?;
        let step = ssh_entry_step(&runner, empty.path(), &inputs, None, &after);
        assert_eq!(step.outcome, StepOutcome::Skipped);
        assert!(!empty.path().join("ozbox").exists());
        Ok(())
    }

    /// A box whose files say it has no agent program.
    struct NoAgentOnImage {
        present: bool,
    }

    impl BoxAgent for NoAgentOnImage {
        fn metrics_now(
            &self,
            _: &BoxRecord,
            _: u64,
        ) -> std::result::Result<MetricsSample, AgentError> {
            Err(AgentError::Unsupported("none".into()))
        }
        fn metrics_series(
            &self,
            _: &BoxRecord,
            _: u64,
            _: u64,
            _: u64,
        ) -> std::result::Result<Vec<MetricsSample>, AgentError> {
            Err(AgentError::Unsupported("none".into()))
        }
        fn selftest(&self, _: &BoxRecord, _: u64) -> std::result::Result<SelfTest, AgentError> {
            Err(AgentError::Unreachable("the socket is not there".into()))
        }
        fn incidents(
            &self,
            _: &BoxRecord,
            _: u64,
            _: u64,
        ) -> std::result::Result<Vec<Incident>, AgentError> {
            Ok(vec![])
        }
        fn image_agent(
            &self,
            _: &BoxRecord,
        ) -> std::result::Result<crate::serve::agent::ImageAgent, AgentError> {
            Ok(crate::serve::agent::ImageAgent {
                from_image: true,
                image_version: Some("2026.11.09".into()),
                agent_present: self.present,
                arch: None,
                first_boot: BoxFirstBoot::Unrecorded,
            })
        }
    }

    #[test]
    fn an_image_with_no_agent_is_reported_at_once_not_after_the_whole_wait() -> TestResult {
        let dir = tempfile::tempdir()?;
        let p = ozbox_provider_fake::open(dir.path());
        let n = BoxName::new("dev")?;
        p.apply(&p.plan(&Operation::Create {
            spec: BoxSpec::new(n.clone(), Size::S),
        })?)?;
        let waits = Waits {
            timeout: Duration::from_secs(600),
            poll: Duration::from_millis(5),
        };
        let started = Instant::now();
        let (step, test) = verify_after(&p, &NoAgentOnImage { present: false }, &n, waits);
        assert!(started.elapsed() < Duration::from_secs(5), "did not wait");
        assert_eq!(step.outcome, StepOutcome::Failed);
        assert!(test.is_none());
        assert!(
            step.detail.contains("no ozboxd") && step.detail.contains("reinstall-ozboxd"),
            "{}",
            step.detail
        );
        // an agent that IS installed but not answering yet keeps waiting, until the timeout
        let short = Waits {
            timeout: Duration::from_millis(30),
            poll: Duration::from_millis(5),
        };
        let (step, _) = verify_after(&p, &NoAgentOnImage { present: true }, &n, short);
        assert!(step.detail.contains("did not answer"), "{}", step.detail);
        Ok(())
    }

    /// An agent that knows what is running on the box and records what it was asked to set up.
    struct Services {
        status: crate::code::BoxCode,
        changes: std::sync::Mutex<Vec<String>>,
        refuse: bool,
    }

    impl BoxAgent for Services {
        fn metrics_now(
            &self,
            _: &BoxRecord,
            _: u64,
        ) -> std::result::Result<MetricsSample, AgentError> {
            Err(AgentError::Unsupported("none".into()))
        }
        fn metrics_series(
            &self,
            _: &BoxRecord,
            _: u64,
            _: u64,
            _: u64,
        ) -> std::result::Result<Vec<MetricsSample>, AgentError> {
            Err(AgentError::Unsupported("none".into()))
        }
        fn selftest(&self, _: &BoxRecord, _: u64) -> std::result::Result<SelfTest, AgentError> {
            Err(AgentError::Unsupported("none".into()))
        }
        fn checkpoint(&self, _: &BoxRecord) -> std::result::Result<CheckpointOutcome, AgentError> {
            Err(AgentError::Unsupported("none".into()))
        }
        fn incidents(
            &self,
            _: &BoxRecord,
            _: u64,
            _: u64,
        ) -> std::result::Result<Vec<Incident>, AgentError> {
            Ok(Vec::new())
        }
        fn code_status(
            &self,
            _: &BoxRecord,
        ) -> std::result::Result<crate::code::BoxCode, AgentError> {
            Ok(self.status)
        }
        fn code_change(
            &self,
            _: &BoxRecord,
            c: &crate::code::Change,
        ) -> std::result::Result<(), AgentError> {
            if self.refuse {
                return Err(AgentError::Unreachable("the box said no".into()));
            }
            let what = match c {
                crate::code::Change::Enable { service, .. } => format!("enable {}", service.id()),
                crate::code::Change::Connector { .. } => "connector".to_string(),
                _ => "other".to_string(),
            };
            self.changes.lock().unwrap().push(what);
            Ok(())
        }
    }

    /// A box that answers only the root helper, as scripted, and records what it was asked.
    struct HelperBox {
        answer: std::result::Result<(bool, String), AgentError>,
        asked: std::sync::Mutex<Vec<String>>,
    }

    impl BoxAgent for HelperBox {
        fn metrics_now(
            &self,
            _: &BoxRecord,
            _: u64,
        ) -> std::result::Result<MetricsSample, AgentError> {
            Err(AgentError::Unsupported("none".into()))
        }
        fn metrics_series(
            &self,
            _: &BoxRecord,
            _: u64,
            _: u64,
            _: u64,
        ) -> std::result::Result<Vec<MetricsSample>, AgentError> {
            Err(AgentError::Unsupported("none".into()))
        }
        fn selftest(&self, _: &BoxRecord, _: u64) -> std::result::Result<SelfTest, AgentError> {
            Err(AgentError::Unsupported("none".into()))
        }
        fn incidents(
            &self,
            _: &BoxRecord,
            _: u64,
            _: u64,
        ) -> std::result::Result<Vec<Incident>, AgentError> {
            Ok(Vec::new())
        }
        fn admin(
            &self,
            _: &BoxRecord,
            request: &str,
        ) -> std::result::Result<(bool, String), AgentError> {
            self.asked.lock().unwrap().push(request.to_string());
            self.answer.clone()
        }
    }

    #[test]
    fn the_memory_guard_goes_on_a_running_box_live_through_the_root_helper_and_a_failure_is_a_step_not_an_error(
    ) -> TestResult {
        let (_d, rec) = services_box()?;
        let box_with = |answer| HelperBox {
            answer,
            asked: Default::default(),
        };
        // it asks for the one install action, and says what the box said
        let ok = box_with(Ok((
            true,
            "Memory guard in place: swap is compressed RAM. Nothing restarted\nmore".into(),
        )));
        let step = memory_guard_step(&ok, &rec).ok_or("a step")?;
        assert_eq!(step.outcome, StepOutcome::Done);
        assert!(
            step.detail.contains("live and with nothing restarted")
                && step.detail.contains("compressed RAM"),
            "{}",
            step.detail
        );
        assert!(!step.detail.contains("more"), "only the first line");
        // the helper is put in step with the installed release first, then the guard is asked for
        assert_eq!(
            *ok.asked.lock().unwrap(),
            ["host-guard helper refresh", "host-guard memory install"]
        );
        // the box refused: a failed step that says how to try again, the upgrade itself is not failed by it
        let no = box_with(Ok((false, "nft missing".into())));
        let step = memory_guard_step(&no, &rec).ok_or("a step")?;
        assert_eq!(step.outcome, StepOutcome::Failed);
        assert!(
            step.detail.contains("host-guard memory install")
                && step.detail.contains("nft missing"),
            "{}",
            step.detail
        );
        let down = box_with(Err(AgentError::Unreachable("timed out".into())));
        assert_eq!(
            memory_guard_step(&down, &rec).ok_or("a step")?.outcome,
            StepOutcome::Failed
        );
        // M2: a box made before this release has a helper that does not know the refresh. That is not a failure and the retry
        // advice would fail the same way: the step says the guard comes with the machine replace of its upgrade
        let old = box_with(Ok((
            false,
            "host-guard takes egress, patch, metadata or memory".into(),
        )));
        let step = memory_guard_step(&old, &rec).ok_or("a step")?;
        assert_eq!(step.outcome, StepOutcome::Skipped);
        assert!(
            step.detail.contains("replaces its machine")
                && !step.detail.contains("host-guard memory install"),
            "{}",
            step.detail
        );
        assert_eq!(*old.asked.lock().unwrap(), ["host-guard helper refresh"]);
        // N2: a helper that is already as new as the program's is kept (never rolled back): that refusal is not an end of the
        // step, the guard is still asked for
        let kept = box_with(Ok((
            false,
            format!("{}: it is revision 3", crate::helper_refresh::KEPT),
        )));
        let _ = memory_guard_step(&kept, &rec).ok_or("a step")?;
        assert_eq!(
            *kept.asked.lock().unwrap(),
            ["host-guard helper refresh", "host-guard memory install"]
        );
        // a box that cannot be asked at all says nothing
        let none = box_with(Err(AgentError::Unsupported("no route".into())));
        assert!(memory_guard_step(&none, &rec).is_none());
        // a box that is not running is not asked
        let mut stopped = rec.clone();
        stopped.state = BoxState::Paused;
        let quiet = box_with(Ok((true, "x".into())));
        assert!(memory_guard_step(&quiet, &stopped).is_none());
        assert!(quiet.asked.lock().unwrap().is_empty());
        Ok(())
    }

    #[test]
    fn nothing_to_upgrade_still_puts_the_memory_guard_on_a_running_box_but_never_on_a_dry_run(
    ) -> TestResult {
        let d = tempfile::tempdir()?;
        let (p, name) = sandbox_box(d.path(), Some(ours()))?;
        let calls = AtomicU32::new(0);
        let go = |dry_run: bool| {
            execute(
                &p,
                &FirstBootBox {
                    record: forged_ours(),
                },
                name.clone(),
                Some("fake-image-2".into()),
                false,
                &Flags {
                    yes: true,
                    dry_run,
                    json: true,
                },
                Waits::default(),
                &Around {
                    store_check: &|_, _| StoreCheck {
                        fate: StoreFate::NotApplicable,
                        detail: String::new(),
                    },
                    accept_new_store: false,
                    old_disk: OldDisk::NotOffered,
                    recover: &|_, _| None,
                    restore_backups: &|_, _| None,
                    restore_services: &|_, _| None,
                    restore_dashboard: &|_, _| None,
                    memory_guard: &|_, _| {
                        calls.fetch_add(1, Ordering::SeqCst);
                        Some(Step::new(StepOutcome::Done, "in place"))
                    },
                    refresh_ssh: &|_, _| Step::new(StepOutcome::Skipped, String::new()),
                    review_signers: &|_| None,
                    place_escrow: &|_, _| None,
                    first_boot: FirstBootOpts {
                        ours: ours(),
                        reprovision: false,
                        allow_mismatch: false,
                        enabled: true,
                    },
                    strict_checkpoint: false,
                    legacy_checkpoint: false,
                    no_checkpoint: false,
                },
            )
        };
        go(true).map_err(|e| e.to_string())?;
        assert_eq!(
            calls.load(Ordering::SeqCst),
            0,
            "a dry run changes nothing on the box"
        );
        go(false).map_err(|e| e.to_string())?;
        assert_eq!(
            calls.load(Ordering::SeqCst),
            1,
            "a box with nothing to upgrade is still put in order"
        );
        Ok(())
    }

    fn services_box(
    ) -> std::result::Result<(tempfile::TempDir, BoxRecord), Box<dyn std::error::Error>> {
        let dir = tempfile::tempdir()?;
        let (_p, rec) = running_box(dir.path(), "dev")?;
        Ok((dir, rec))
    }

    /// The report states the dashboard's outcome in one of three ways, and the step that needs the owner names the one command
    /// and says nothing is approved for them.
    #[test]
    fn the_dashboard_line_says_put_back_needs_your_approval_or_not_installed() {
        use crate::dashboard_cli::Restored;
        assert!(step_for_dashboard("dev", Restored::NoneKept).is_none());
        let done = step_for_dashboard(
            "dev",
            Restored::Done {
                address: "https://ozbox.example.com".into(),
                token: true,
            },
        )
        .unwrap();
        assert_eq!(done.outcome, StepOutcome::Done);
        assert!(
            done.detail
                .contains("put back on dev at https://ozbox.example.com")
                && done.detail.contains("keychain"),
            "{}",
            done.detail
        );
        let needs = step_for_dashboard("dev", Restored::NeedsApproval).unwrap();
        assert_eq!(needs.outcome, StepOutcome::Failed);
        assert!(
            needs
                .detail
                .contains("ozbox dashboard restore dev --approve-with-laptop-key")
                && needs.detail.contains("nothing here makes that approval"),
            "{}",
            needs.detail
        );
        let absent = step_for_dashboard("dev", Restored::Absent).unwrap();
        assert_eq!(absent.outcome, StepOutcome::Skipped);
        assert!(absent.detail.contains("ozbox dashboard forget dev"));
        assert_eq!(
            step_for_dashboard("dev", Restored::Running)
                .unwrap()
                .outcome,
            StepOutcome::Done
        );
        let failed =
            step_for_dashboard("dev", Restored::Failed("it did not start".into())).unwrap();
        assert!(
            failed.detail.contains("ozbox dashboard restore dev")
                && failed.detail.contains("it did not start")
        );
    }

    #[test]
    fn after_an_upgrade_the_ide_and_connector_that_are_not_running_are_set_up_again_from_this_computers_secrets(
    ) -> TestResult {
        use crate::code::{BoxCode, Service, ServiceState};
        use crate::secrets::{MemorySecrets, SecretStore};
        let (_d, rec) = services_box()?;
        let secrets = MemorySecrets::default();
        // nothing was ever set up through ozbox: nothing to say
        let none = Services {
            status: BoxCode::default(),
            changes: Default::default(),
            refuse: false,
        };
        assert!(restore_services_with(&none, &rec, &secrets).is_none());
        secrets.set(
            &Service::Ide.secret_name("dev"),
            "abcdef0123456789abcdef0123456789",
        )?;
        secrets.set(
            &Service::connector_secret_name("dev"),
            "eyJhIjoiYWJjZGVmZ2hpamtsbW5vcCJ9abcd",
        )?;
        // everything is down on the new system disk: both come back
        let down = Services {
            status: BoxCode::default(),
            changes: Default::default(),
            refuse: false,
        };
        let step = restore_services_with(&down, &rec, &secrets).ok_or("a step")?;
        assert_eq!(step.outcome, StepOutcome::Done);
        assert!(
            step.detail.contains("set up again")
                && step.detail.contains("web IDE")
                && step.detail.contains("tunnel connector"),
            "{}",
            step.detail
        );
        assert_eq!(*down.changes.lock().unwrap(), ["enable ide", "connector"]);
        assert!(
            !step.detail.contains("eyJ") && !step.detail.contains("abcdef0123"),
            "no secret in the words"
        );
        // already running (the units on /work came back by themselves): left alone
        let up = ServiceState {
            program: true,
            unit_current: true,
            active: true,
        };
        let running = Services {
            status: BoxCode {
                ide: up,
                connector: up,
                ..BoxCode::default()
            },
            changes: Default::default(),
            refuse: false,
        };
        let step = restore_services_with(&running, &rec, &secrets).ok_or("a step")?;
        assert!(step.detail.contains("already running"), "{}", step.detail);
        assert!(running.changes.lock().unwrap().is_empty());
        // the box refuses: said plainly, with what to run, and it is a failed step, not a failed upgrade
        let no = Services {
            status: BoxCode::default(),
            changes: Default::default(),
            refuse: true,
        };
        let step = restore_services_with(&no, &rec, &secrets).ok_or("a step")?;
        assert_eq!(step.outcome, StepOutcome::Failed);
        assert!(
            step.detail.contains("ozbox ide dev")
                && step.detail.contains("tunnel setup cloudflare --on-box dev")
                && step.detail.contains("/work is untouched"),
            "{}",
            step.detail
        );
        Ok(())
    }

    #[test]
    fn the_ide_connector_and_its_boot_wiring_survive_a_system_disk_replacement() {
        // What an upgrade replaces is the system disk. These are the facts that make the IDE and tunnel come back on a new
        // one: the box user's home (where the IDE's user unit, password file and workspace live) is on /work, the box user is
        // set to linger at every boot, and the connector's unit can be enabled.
        let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
        let tpl = std::fs::read_to_string(root.join("infra/cloud-init/box.yaml.tftpl")).unwrap();
        assert!(tpl.contains("homedir: /work/home/ozbox"));
        assert!(tpl.contains("loginctl enable-linger ozbox"));
        let ide = crate::code::unit_text(crate::code::Service::Ide);
        assert!(
            ide.contains("%h/.config/ozbox/ide.env") && ide.contains("WantedBy=default.target")
        );
        let connector = crate::code::connector_unit_text();
        assert!(
            connector.contains("[Install]") && connector.contains("WantedBy=multi-user.target")
        );
        // the admin action that stores the token also enables the unit, so it starts at the next boot
        let admin =
            std::fs::read_to_string(root.join("infra/cloud-init/scripts/ozbox-admin.sh")).unwrap();
        assert!(admin.contains("enable --now ozbox-code-connector.service"));
    }

    #[test]
    fn an_unreachable_agent_at_checkpoint_time_says_what_it_means_and_what_to_do() -> TestResult {
        let dir = tempfile::tempdir()?;
        let (_p, rec) = running_box(dir.path(), "dev")?;
        let mut a = agent();
        a.checkpoint = Err(AgentError::Unreachable(
            "the box did not answer over SSH in time".into(),
        ));
        let step = checkpoint_before(&a, &rec);
        assert_eq!(step.outcome, StepOutcome::Skipped, "never a failed upgrade");
        let d = &step.detail;
        assert!(
            d.contains("agent could not be reached")
                && d.contains("did not answer over SSH in time"),
            "{d}"
        );
        assert!(
            d.contains("uncommitted changes were not copied") && d.contains("nothing is lost"),
            "{d}"
        );
        assert!(
            d.contains("ozbox ps dev") && d.contains("run the upgrade again"),
            "{d}"
        );
        Ok(())
    }

    /// A box whose secrets state is scripted, and whose root helper answers a recovery the way the box does.
    struct StateAgent {
        state: std::result::Result<(Option<crate::secrets_state::State>, bool), AgentError>,
        admin: std::sync::Mutex<Vec<String>>,
        challenge: crate::secrets_recover::Challenge,
        pinned: String,
    }

    impl BoxAgent for StateAgent {
        fn metrics_now(
            &self,
            _: &BoxRecord,
            _: u64,
        ) -> std::result::Result<MetricsSample, AgentError> {
            Err(AgentError::Unsupported("none".into()))
        }
        fn metrics_series(
            &self,
            _: &BoxRecord,
            _: u64,
            _: u64,
            _: u64,
        ) -> std::result::Result<Vec<MetricsSample>, AgentError> {
            Err(AgentError::Unsupported("none".into()))
        }
        fn selftest(&self, _: &BoxRecord, _: u64) -> std::result::Result<SelfTest, AgentError> {
            Ok(passing())
        }
        fn incidents(
            &self,
            _: &BoxRecord,
            _: u64,
            _: u64,
        ) -> std::result::Result<Vec<Incident>, AgentError> {
            Ok(Vec::new())
        }
        fn secrets_state(
            &self,
            _: &BoxRecord,
        ) -> std::result::Result<(Option<crate::secrets_state::State>, bool), AgentError> {
            self.state.clone()
        }
        fn admin(
            &self,
            _: &BoxRecord,
            request: &str,
        ) -> std::result::Result<(bool, String), AgentError> {
            self.admin.lock().unwrap().push(request.to_string());
            if request == "recover-secrets challenge" {
                return Ok((true, self.challenge.words()));
            }
            // the box checks the pinned key's signature of its challenge
            let w: Vec<&str> = request.split_whitespace().collect();
            let good = w.len() == 4
                && w[1] == self.challenge.nonce
                && crate::approval_key::verify(&self.pinned, &self.challenge.message(), w[3]);
            Ok((
                good,
                if good {
                    "a new secrets store was started".into()
                } else {
                    "refused".into()
                },
            ))
        }
    }

    fn state_agent(
        state: std::result::Result<(Option<crate::secrets_state::State>, bool), AgentError>,
        pinned: &str,
    ) -> StateAgent {
        StateAgent {
            state,
            admin: std::sync::Mutex::new(Vec::new()),
            challenge: crate::secrets_recover::Challenge {
                nonce: "ab".repeat(16),
                expires_ms: 99,
                store: "cd".repeat(8),
                key_id: "laptop".into(),
            },
            pinned: pinned.to_string(),
        }
    }

    fn lost() -> crate::secrets_state::State {
        crate::secrets_state::State::ready(
            crate::secrets_cli::FILE_KEK_NOT_ESCROWED,
            "file",
            Some(false),
        )
    }

    /// The finding (a security review, 2026-11-11): the second upgrade of a default box (a file-kept key, no escrow)
    /// started a new store, and nothing said so before. The plan now names the loss and is refused without the person's
    /// acceptance, with the two ways forward.
    #[test]
    fn a_box_whose_store_would_be_lost_is_refused_unless_the_person_accepts_a_new_one() -> TestResult
    {
        let dir = tempfile::tempdir()?;
        let (_, rec) = running_box(dir.path(), "dev")?;
        let check = store_check(
            &state_agent(Ok((Some(lost()), true)), ""),
            &rec,
            false,
            false,
            None,
        );
        assert_eq!(check.fate, StoreFate::Lost);
        let refusal = store_gate(&check, "dev", false).unwrap_err();
        for words in [
            "LOST",
            "tunnel tokens",
            "Nothing was changed",
            "OpenBao",
            "--accept-new-secrets-store",
        ] {
            assert!(refusal.contains(words), "{words}: {refusal}");
        }
        let note = store_gate(&check, "dev", true)?;
        assert!(
            note.contains("Accepted") && note.contains("Enter again"),
            "{note}"
        );
        Ok(())
    }

    /// `--use-fleet-key` moves only a store that holds nothing: nothing the owner entered is lost by the new key.
    #[test]
    fn a_box_moves_to_the_fleet_key_only_with_an_empty_store_that_the_box_itself_reported(
    ) -> TestResult {
        use crate::secrets_state::State;
        let dir = tempfile::tempdir()?;
        let (_, rec) = running_box(dir.path(), "dev")?;
        let gate = |st, r: &BoxRecord, sim| fleet_key_gate(&state_agent(st, ""), r, sim, None);
        let file = |n: Option<u32>| {
            let mut st = State::ready("", "file", Some(false));
            st.names = n;
            Ok((Some(st), true))
        };
        assert!(gate(file(Some(0)), &rec, false).is_ok());
        // a store that holds anything, or a box that did not say, is refused and says what to do
        let e = gate(file(Some(3)), &rec, false).unwrap_err();
        assert!(
            e.contains("holds 3") && e.contains("Nothing was changed"),
            "{e}"
        );
        assert!(gate(file(None), &rec, false)
            .unwrap_err()
            .contains("could not say"));
        assert!(gate(Err(AgentError::Unreachable("no".into())), &rec, false)
            .unwrap_err()
            .contains("could not say"));
        // a box on another key, already on KMS, stopped, or simulated: refused
        assert!(gate(
            Ok((Some(State::ready("", "tpm2", None).with_names(0)), true)),
            &rec,
            false
        )
        .unwrap_err()
        .contains("not keep its store's key in a file"));
        let mut kms = rec.clone();
        kms.spec.labels.insert(
            ozbox_provider_aws::SECRETS_KEY_LABEL.into(),
            "arn:aws:kms:us-east-1:123456789012:key/x".into(),
        );
        assert!(gate(file(Some(0)), &kms, false)
            .unwrap_err()
            .contains("already keeps"));
        let mut paused = rec.clone();
        paused.state = BoxState::Paused;
        assert!(gate(file(Some(0)), &paused, false)
            .unwrap_err()
            .contains("must be running"));
        assert!(gate(file(Some(0)), &rec, true).is_err());
        Ok(())
    }

    /// S3: on AWS `--use-fleet-key` is decided from the box's ROOT facts (a forged `names=0` over SSH would make an upgrade
    /// replace a store that is not empty), and the laptop's keychain copy keeps a file-kept store on the root path too.
    #[test]
    fn on_aws_the_fleet_key_gate_and_the_laptops_copy_rest_on_the_roots_facts() -> TestResult {
        use crate::secrets_adopt_facts::{tests::on_file, Facts, Kek};
        use crate::secrets_state::State;
        let dir = tempfile::tempdir()?;
        let (_, rec) = running_box(dir.path(), "dev")?;
        // the box user's answer says the store is empty; the root says otherwise: the root wins
        let liar = state_agent(
            Ok((
                Some(State::ready("", "file", Some(false)).with_names(0)),
                true,
            )),
            "",
        );
        let gate = |f: std::result::Result<Facts, String>, r: &BoxRecord| {
            let root = move |_: &BoxRecord| f.clone();
            fleet_key_gate(&liar, r, false, Some(&root))
        };
        let file = |n: Option<u32>| Facts {
            names: n,
            ..on_file()
        };
        assert!(gate(Ok(file(Some(0))), &rec).is_ok());
        let e = gate(Ok(file(Some(3))), &rec).unwrap_err();
        assert!(
            e.contains("holds 3") && e.contains("Nothing was changed"),
            "{e}"
        );
        for unsaid in [
            gate(Ok(file(None)), &rec),
            gate(
                Ok(Facts {
                    service_ready: false,
                    ..file(Some(0))
                }),
                &rec,
            ),
            gate(Err("TargetNotConnected".into()), &rec),
        ] {
            assert!(unsaid.unwrap_err().contains("could not say"));
        }
        // an older program is said to be older, and is not blamed on the policy
        assert!(gate(Err(ROOT_OLDER.into()), &rec)
            .unwrap_err()
            .contains("older"));
        assert!(gate(
            Ok(Facts {
                service_kek: Kek::Kms,
                ..file(Some(0))
            }),
            &rec
        )
        .unwrap_err()
        .contains("does not keep its store's key in a file"));
        // a move under way is refused first, whatever the root says
        let mut moving = rec.clone();
        moving.spec.labels.insert(
            ozbox_provider_aws::SECRETS_ADOPT_LABEL.into(),
            "arn:aws:kms:us-east-1:123456789012:key/x".into(),
        );
        assert!(gate(Ok(file(Some(0))), &moving)
            .unwrap_err()
            .contains("moving"));

        // the laptop's copy: a file-kept store whose key is also in this computer's keychain is KEPT, on the root path as on SSH
        let fate = |f: Facts, laptop: bool| {
            let root = move |_: &BoxRecord| Ok(f.clone());
            store_check(&agent(), &rec, false, laptop, Some(&root)).fate
        };
        let no_copy = Facts {
            service_escrow: Some(false),
            ..on_file()
        };
        assert_eq!(fate(no_copy.clone(), false), StoreFate::Lost);
        assert_eq!(fate(no_copy, true), StoreFate::KeptByLaptop);
        let unsaid = Facts {
            service_escrow: None,
            ..on_file()
        };
        assert_eq!(fate(unsaid.clone(), false), StoreFate::Unknown);
        assert_eq!(fate(unsaid, true), StoreFate::KeptByLaptop);
        // a service that is not ready is unknown whatever the keychain holds
        assert_eq!(
            fate(
                Facts {
                    service_ready: false,
                    service_escrow: Some(false),
                    ..on_file()
                },
                true
            ),
            StoreFate::Unknown
        );
        // N2: a box whose root cannot answer (older program, or Systems Manager unreachable) is still KEPT when this computer's
        // keychain holds its key, as before the root channel existed; with no copy it stays unknown, and the detail never sends
        // the person to `--accept-new-secrets-store` when a copy exists
        let from_err = |why: &str, laptop: bool| {
            let why = why.to_string();
            let root =
                move |_: &BoxRecord| -> std::result::Result<Facts, String> { Err(why.clone()) };
            store_check(&agent(), &rec, false, laptop, Some(&root))
        };
        for why in [ROOT_OLDER, "TargetNotConnected"] {
            let with = from_err(why, true);
            assert_eq!(with.fate, StoreFate::KeptByLaptop, "{why}");
            assert!(
                !with.detail.contains("--accept-new-secrets-store")
                    && with.detail.contains("keychain"),
                "{}",
                with.detail
            );
            assert!(store_gate(&with, "dev", false).is_ok());
            let without = from_err(why, false);
            assert_eq!(without.fate, StoreFate::Unknown, "{why}");
            assert!(store_gate(&without, "dev", false).is_err());
        }
        Ok(())
    }

    const FLEET_ARN: &str =
        "arn:aws:kms:us-east-1:123456789012:key/0f0f0f0f-0000-4000-8000-000000000000";

    /// A box whose record names the fleet's KMS key, asked through a root reader that answers `facts`.
    fn kms_labelled_fate(
        facts: std::result::Result<crate::secrets_adopt_facts::Facts, String>,
    ) -> std::result::Result<StoreCheck, Box<dyn std::error::Error>> {
        kms_labelled_fate_with(facts, false)
    }

    fn kms_labelled_fate_with(
        facts: std::result::Result<crate::secrets_adopt_facts::Facts, String>,
        laptop_escrow: bool,
    ) -> std::result::Result<StoreCheck, Box<dyn std::error::Error>> {
        let dir = tempfile::tempdir()?;
        let (_, mut rec) = running_box(dir.path(), "main")?;
        rec.spec.labels.insert(
            ozbox_provider_aws::SECRETS_KEY_LABEL.into(),
            FLEET_ARN.into(),
        );
        let root = move |_: &BoxRecord| facts.clone();
        Ok(store_check(
            &agent(),
            &rec,
            false,
            laptop_escrow,
            Some(&root),
        ))
    }

    /// The 2026-11-16 finding: `ozbox upgrade main --dry-run` said "kept" from the box's label while its secrets service was
    /// failing on a store sealed by a key kept in a file. Every verdict now comes from what the box's root says.
    #[test]
    fn a_kms_labelled_box_is_kept_only_when_its_root_shows_the_store_open_under_that_key(
    ) -> TestResult {
        use crate::secrets_adopt_facts::{tests::on_kms, Facts, Kek};
        // the healthy box: kept, and the plan says root confirmed it
        let kept = kms_labelled_fate(Ok(on_kms()))?;
        assert_eq!(kept.fate, StoreFate::Kept);
        assert!(kept.detail.contains("root confirms"), "{}", kept.detail);
        assert!(store_gate(&kept, "main", false).is_ok());

        // the incident: the service cannot start, the store is sealed by a key kept in a file that is gone, the box is configured
        // for KMS (`kind-mismatch`). The label is correct and the plan must still not say kept
        let incident = Facts {
            service_ready: false,
            service_kek: Kek::Kms,
            store_kek: Kek::File,
            persist_kek: Kek::File,
            key_file: false,
            backup: false,
            ..on_kms()
        };
        let gone = kms_labelled_fate(Ok(incident.clone()))?;
        assert_eq!(gone.fate, StoreFate::AlreadyLost);
        let refusal = store_gate(&gone, "main", false).unwrap_err();
        for words in [
            "ALREADY UNOPENABLE",
            "recover-secrets",
            "--accept-new-secrets-store",
            "Nothing was changed",
        ] {
            assert!(refusal.contains(words), "{words}: {refusal}");
        }
        assert!(!refusal.contains("kept."), "{refusal}");
        // accepted, the upgrade sets the old store aside afterwards (the `recover` step)
        assert!(store_gate(&gone, "main", true)?.contains("set aside"));
        // an older program that recorded no state for it says the same facts, and is read the same way
        let no_state = Facts {
            service_kek: Kek::None,
            ..incident.clone()
        };
        assert_eq!(
            kms_labelled_fate(Ok(no_state))?.fate,
            StoreFate::AlreadyLost
        );
        // the service's own "its key is lost and nothing holds a copy" state
        let no_escrow = Facts {
            service_no_escrow: true,
            ..on_kms()
        };
        assert_eq!(
            kms_labelled_fate(Ok(no_escrow))?.fate,
            StoreFate::AlreadyLost
        );

        // a file-sealed store whose key is still on the disk and whose service is up: the new machine would not open it
        let file_sealed = Facts {
            store_kek: Kek::File,
            persist_kek: Kek::File,
            ..on_kms()
        };
        let lost = kms_labelled_fate(Ok(file_sealed))?;
        assert_eq!(lost.fate, StoreFate::Lost);
        assert!(store_gate(&lost, "main", false)
            .unwrap_err()
            .contains("adopt-fleet-key main"));

        // a service that is not ready (restarting) is not "kept", and neither is a copy on /work that is not sealed by the key,
        // another key, or a move under way
        for f in [
            Facts {
                service_ready: false,
                ..on_kms()
            },
            Facts {
                persist_kek: Kek::None,
                ..on_kms()
            },
            Facts {
                settings_key: Some(
                    "arn:aws:kms:us-east-1:123456789012:key/ffffffff-0000-4000-8000-000000000000"
                        .into(),
                ),
                ..on_kms()
            },
            Facts {
                busy: true,
                ..on_kms()
            },
            Facts {
                cancelled: true,
                ..on_kms()
            },
        ] {
            let c = kms_labelled_fate(Ok(f))?;
            assert_eq!(c.fate, StoreFate::Unknown, "{}", c.detail);
            assert!(store_gate(&c, "main", false).is_err());
        }
        Ok(())
    }

    /// A plan must never say "no copy held anywhere" while a copy is held: this computer's keychain, or the box's vault, holding
    /// the file key means the store is not lost, so it is neither called already lost nor offered to be set aside.
    #[test]
    fn a_kms_labelled_box_whose_file_key_is_held_somewhere_is_never_called_lost() -> TestResult {
        use crate::secrets_adopt_facts::{tests::on_kms, Facts, Kek};
        let incident = Facts {
            service_ready: false,
            service_kek: Kek::Kms,
            store_kek: Kek::File,
            persist_kek: Kek::File,
            key_file: false,
            backup: false,
            ..on_kms()
        };
        let cases = [
            // this computer's keychain holds the key
            (incident.clone(), true, "keychain"),
            // the box's vault holds it
            (
                Facts {
                    service_escrow: Some(true),
                    ..incident.clone()
                },
                false,
                "vault",
            ),
            // the service's own "lost" state, while the vault says it holds a copy
            (
                Facts {
                    service_no_escrow: true,
                    service_escrow: Some(true),
                    ..on_kms()
                },
                false,
                "vault",
            ),
        ];
        for (f, laptop, place) in cases {
            let c = kms_labelled_fate_with(Ok(f), laptop)?;
            assert_eq!(c.fate, StoreFate::KeyHeld, "{}", c.detail);
            assert!(c.detail.contains(place), "{}", c.detail);
            assert!(!c.detail.contains("adopt-fleet-key"), "{}", c.detail);
            assert!(
                !c.detail.contains("ALREADY UNOPENABLE") && !c.detail.contains("no copy held"),
                "{}",
                c.detail
            );
            // refused without the person's acceptance, in words that name the way forward (the flag, and where the old store can be
            // reopened from), and never with the advice that cannot work (`adopt-fleet-key` refuses a box whose service is not ready)
            let refusal = store_gate(&c, "main", false).unwrap_err();
            assert!(refusal.contains("IS held"), "{refusal}");
            assert!(refusal.contains("--accept-new-secrets-store"), "{refusal}");
            assert!(
                refusal.contains("Recovering an old secrets store"),
                "{refusal}"
            );
            assert!(refusal.contains("never deleted"), "{refusal}");
            assert!(!refusal.contains("adopt-fleet-key"), "{refusal}");
            assert!(!refusal.contains("Two ways forward"), "{refusal}");
            // with it the upgrade goes ahead, sets the old store aside after the replace, and says so
            let note = store_gate(&c, "main", true)?;
            assert!(
                note.contains("set aside") && note.contains("Accepted"),
                "{note}"
            );
            assert!(!note.contains("adopt-fleet-key"), "{note}");
            assert!(sets_store_aside(true, c.fate));
            assert!(!sets_store_aside(false, c.fate));
            assert_eq!(store_refusal_code(c.fate), "secrets_key_held");
        }
        // and with no copy anywhere it is still said to be lost
        assert_eq!(
            kms_labelled_fate_with(Ok(incident), false)?.fate,
            StoreFate::AlreadyLost
        );
        Ok(())
    }

    /// Before the upgrade the plan's connection to the box failed, and it still said "kept". A box that could not be asked, or
    /// that cannot be asked from here, is unknown, however its record is labelled.
    #[test]
    fn a_kms_labelled_box_that_could_not_be_asked_is_never_kept() -> TestResult {
        for why in ["TargetNotConnected", "ssh: connection reset", ROOT_OLDER] {
            let c = kms_labelled_fate(Err(why.to_string()))?;
            assert_eq!(c.fate, StoreFate::Unknown, "{why}");
            assert!(!c.detail.contains("kept."), "{}", c.detail);
            let refusal = store_gate(&c, "main", false).unwrap_err();
            assert!(refusal.contains("--accept-new-secrets-store"), "{refusal}");
            assert!(store_gate(&c, "main", true).is_ok());
        }
        // no root channel at all (not AWS, or a caller that has none): the label alone still decides nothing
        let dir = tempfile::tempdir()?;
        let (_, mut rec) = running_box(dir.path(), "main")?;
        rec.spec.labels.insert(
            ozbox_provider_aws::SECRETS_KEY_LABEL.into(),
            FLEET_ARN.into(),
        );
        let c = store_check(&agent(), &rec, false, false, None);
        assert_eq!(c.fate, StoreFate::Unknown);
        assert!(store_gate(&c, "main", false).is_err());
        Ok(())
    }

    #[test]
    fn the_stores_fate_is_in_every_plan_and_only_a_loss_or_a_box_that_cannot_be_asked_is_refused(
    ) -> TestResult {
        use crate::secrets_state::State;
        let dir = tempfile::tempdir()?;
        let (_, rec) = running_box(dir.path(), "dev")?;
        let fate = |st| store_check(&state_agent(st, ""), &rec, false, false, None);
        // an unlabelled box that says "kms" is not believed (the box user can say anything): unknown, refused unless accepted
        let unlabelled = fate(Ok((Some(State::ready("", "kms", None)), true)));
        assert_eq!(unlabelled.fate, StoreFate::Unknown);
        assert!(store_gate(&unlabelled, "dev", false).is_err());
        assert!(store_gate(&unlabelled, "dev", true).is_ok());
        let tpm = fate(Ok((Some(State::ready("", "tpm2", None)), true)));
        assert_eq!(tpm.fate, StoreFate::Kept);
        let escrowed = fate(Ok((Some(State::ready("", "file", Some(true))), true)));
        assert_eq!(escrowed.fate, StoreFate::KeptByEscrow);
        assert!(store_gate(&escrowed, "dev", false).is_ok());
        // an older service that writes no key line: the box's /work copy keeps it this once; said, not refused
        let older = fate(Ok((
            Some(State::ready("", "", None)).map(|mut s| {
                s.kek = None;
                s
            }),
            true,
        )));
        assert_eq!(older.fate, StoreFate::NotSaid);
        assert!(store_gate(&older, "dev", false)?.contains("older"));
        assert_eq!(fate(Ok((None, false))).fate, StoreFate::NotSaid);
        // already lost: nothing more to lose, so not refused, and the way to a new store is named
        let gone = fate(Ok((
            Some(State::not_ready(
                "x",
                crate::secrets_state::NO_ESCROW_CODE,
                Some("file"),
                Some(false),
            )),
            false,
        )));
        assert_eq!(gone.fate, StoreFate::AlreadyLost);
        // refused like a loss: accepting it gets the recovery after the reboot, not a box that cannot open its store
        assert!(store_gate(&gone, "dev", false)
            .unwrap_err()
            .contains("--accept-new-secrets-store"));
        assert!(store_gate(&gone, "dev", true)?.contains("Accepted"));
        // could not be asked: refused, and starting the box is offered
        let unknown = fate(Err(AgentError::Unreachable("ssh said no".into())));
        assert_eq!(unknown.fate, StoreFate::Unknown);
        assert!(store_gate(&unknown, "dev", false)
            .unwrap_err()
            .contains("ozbox resume dev"));
        // a stopped box cannot be asked, and a label naming the fleet's KMS key does not change that: the label says which key the
        // new machine gets, not that the store opens under it (2026-11-16)
        let mut paused = rec.clone();
        paused.state = BoxState::Paused;
        assert_eq!(fate(Ok((Some(lost()), true))).fate, StoreFate::Lost);
        assert_eq!(
            store_check(&agent(), &paused, false, false, None).fate,
            StoreFate::Unknown
        );
        paused.spec.labels.insert(
            ozbox_provider_aws::SECRETS_KEY_LABEL.into(),
            "arn:aws:kms:us-east-1:123456789012:key/x".into(),
        );
        let still = store_check(&agent(), &paused, false, false, None);
        assert_eq!(still.fate, StoreFate::Unknown);
        assert!(store_gate(&still, "dev", false).is_err());
        // a box moving its store to the fleet key: neither "kept" nor "lost" is true yet, so the upgrade is refused, and
        // --accept-new-secrets-store does not make it go ahead (a KMS-configured machine over a file-sealed store never opens)
        let mut moving = rec.clone();
        moving.spec.labels.insert(
            ozbox_provider_aws::SECRETS_ADOPT_LABEL.into(),
            "arn:aws:kms:us-east-1:123456789012:key/x".into(),
        );
        let m = store_check(&agent(), &moving, false, false, None);
        assert_eq!(m.fate, StoreFate::MovingKey);
        assert_eq!(store_refusal_code(m.fate), "secrets_key_moving");
        assert_eq!(store_refusal_code(StoreFate::Lost), "secrets_store_lost");
        for accept in [false, true] {
            let refusal = store_gate(&m, "dev", accept).unwrap_err();
            assert!(
                refusal.contains("ozbox adopt-fleet-key dev") && refusal.contains("--cancel"),
                "{refusal}"
            );
        }
        // no real box at all
        assert_eq!(
            store_check(&agent(), &rec, true, false, None).fate,
            StoreFate::NotApplicable
        );
        assert_eq!(
            store_check(&agent(), &rec, false, false, None).fate,
            StoreFate::NotApplicable
        );
        Ok(())
    }

    /// N2: on AWS the store's fate comes from the box's ROOT. A box user that makes the SSH answer say `tpm2`, or `file` with an
    /// escrow, changes nothing; and when the root channel cannot answer, the store is never "kept".
    #[test]
    fn on_aws_the_stores_fate_is_the_roots_word_and_never_the_ssh_answer() -> TestResult {
        use crate::secrets_adopt_facts::{tests::on_file, Facts, Kek};
        use crate::secrets_state::State;
        let dir = tempfile::tempdir()?;
        let (_, rec) = running_box(dir.path(), "dev")?;
        // what a box user can make the SSH answer say
        let lies = [
            Ok((Some(State::ready("", "tpm2", None)), true)),
            Ok((Some(State::ready("", "file", Some(true))), true)),
            Ok((Some(State::ready("", "kms", None)), true)),
        ];
        let root_says = |f: std::result::Result<Facts, String>| {
            let root = move |_: &BoxRecord| f.clone();
            lies.iter()
                .map(|l| {
                    store_check(&state_agent(l.clone(), ""), &rec, false, false, Some(&root)).fate
                })
                .collect::<Vec<_>>()
        };
        let file = |escrow| Facts {
            service_escrow: escrow,
            ..on_file()
        };
        // the root says the key is a file with no copy: lost, whatever the SSH answer claims
        assert_eq!(root_says(Ok(file(Some(false)))), vec![StoreFate::Lost; 3]);
        // the root says escrowed: kept by escrow, and only then
        assert_eq!(
            root_says(Ok(file(Some(true)))),
            vec![StoreFate::KeptByEscrow; 3]
        );
        // R1: a service that does not say whether a copy is escrowed is UNKNOWN on the root path, never the legacy "not said"
        // (which an upgrade lets through with no consent): the key may be a file with no copy
        assert_eq!(root_says(Ok(file(None))), vec![StoreFate::Unknown; 3]);
        assert_eq!(
            root_says(Ok(Facts {
                service_kek: Kek::None,
                ..file(Some(true))
            })),
            vec![StoreFate::Unknown; 3]
        );
        // the root says the service is down for want of its key
        assert_eq!(
            root_says(Ok(Facts {
                service_ready: false,
                service_no_escrow: true,
                ..file(Some(false))
            })),
            vec![StoreFate::AlreadyLost; 3]
        );
        // the root says KMS but the record carries no label: not believed
        assert_eq!(
            root_says(Ok(Facts {
                service_kek: Kek::Kms,
                ..file(None)
            })),
            vec![StoreFate::Unknown; 3]
        );
        // R1: a service that is not ready says nothing (a restart, a late /work mount, a stopped unit): UNKNOWN, even when its
        // state still names a file key with no escrow, which the SSH path refused too
        for f in [
            Facts {
                service_ready: false,
                ..file(Some(true))
            },
            Facts {
                service_ready: false,
                ..file(Some(false))
            },
            Facts {
                service_ready: false,
                ..file(None)
            },
        ] {
            assert_eq!(root_says(Ok(f)), vec![StoreFate::Unknown; 3]);
        }
        // and the gate refuses every one of them without the person's acceptance, and accepts a store kept by escrow with none
        let gate = |f: Facts| {
            let root = move |_: &BoxRecord| Ok(f.clone());
            store_check(&agent(), &rec, false, false, Some(&root))
        };
        for f in [
            file(None),
            Facts {
                service_ready: false,
                ..file(Some(false))
            },
        ] {
            let c = gate(f);
            assert_eq!(c.fate, StoreFate::Unknown);
            assert!(store_gate(&c, "dev", false).is_err(), "{c:?}");
            assert!(c.detail.contains("Secrets store: unknown"), "{}", c.detail);
        }
        let escrowed = gate(file(Some(true)));
        assert_eq!(escrowed.fate, StoreFate::KeptByEscrow);
        assert!(
            store_gate(&escrowed, "dev", false).is_ok(),
            "an escrowed store on a box that reports facts never needs --accept-new-secrets-store"
        );
        // the root channel cannot answer (or answers in a shape not known): unknown, refused unless accepted, never kept
        for why in ["AccessDeniedException", ROOT_OLDER] {
            let fates = root_says(Err(why.into()));
            assert_eq!(fates, vec![StoreFate::Unknown; 3], "{why}");
        }
        // R4: a box whose own program is older than the root check is said to be OLDER, and the words do not blame the policy
        let older = store_check(
            &agent(),
            &rec,
            false,
            false,
            Some(&|_: &BoxRecord| Err(ROOT_OLDER.to_string())),
        );
        assert_eq!(older.fate, StoreFate::Unknown);
        assert!(
            older.detail.contains("older")
                && !older.detail.contains("operator_adopt_policy_json")
                && !older.detail.contains("IAM")
                && older.detail.contains("--accept-new-secrets-store"),
            "{}",
            older.detail
        );
        let unknown = store_check(
            &state_agent(Ok((Some(State::ready("", "file", Some(true))), true)), ""),
            &rec,
            false,
            false,
            Some(&|_: &BoxRecord| Err("TargetNotConnected".to_string())),
        );
        assert!(
            unknown.detail.contains("TargetNotConnected")
                && unknown.detail.contains("operator_adopt_policy_json")
        );
        assert!(store_gate(&unknown, "dev", false).is_err());
        assert!(store_gate(&unknown, "dev", true).is_ok());
        // the cloud's own label no longer decides alone (2026-11-16: it said "kept" about a store the box could not open), and a
        // pending move still refuses
        let mut labelled = rec.clone();
        labelled.spec.labels.insert(
            ozbox_provider_aws::SECRETS_KEY_LABEL.into(),
            "arn:aws:kms:us-east-1:123456789012:key/0f0f0f0f-0000-4000-8000-000000000000".into(),
        );
        let down = |_: &BoxRecord| Err("down".to_string());
        assert_eq!(
            store_check(&agent(), &labelled, false, false, Some(&down)).fate,
            StoreFate::Unknown
        );
        Ok(())
    }

    #[test]
    fn after_the_reboot_an_accepted_new_store_is_started_with_this_computers_pinned_key(
    ) -> TestResult {
        use crate::secrets::SecretStore;
        use crate::secrets_state::State;
        let dir = tempfile::tempdir()?;
        let (_, rec) = running_box(dir.path(), "dev")?;
        let (seed, pk) = crate::approval_key::generate()?;
        let keys = crate::secrets::MemorySecrets::default();
        keys.set("approval-key-laptop", &seed)?;
        let no_escrow = State::not_ready(
            "x",
            crate::secrets_state::NO_ESCROW_CODE,
            Some("file"),
            Some(false),
        );
        let a = state_agent(Ok((Some(no_escrow.clone()), false)), &pk);
        let step = recover_store_step(&a, &rec, &keys, quick());
        assert_eq!(step.outcome, StepOutcome::Done, "{}", step.detail);
        let sent = a.admin.lock().unwrap().clone();
        assert_eq!(sent[0], "recover-secrets challenge");
        assert!(sent[1].starts_with(&format!("recover-secrets {} 99 ", "ab".repeat(16))));
        // without the pinned key this computer cannot approve, and says why
        let empty = crate::secrets::MemorySecrets::default();
        let step = recover_store_step(
            &state_agent(Ok((Some(no_escrow), false)), &pk),
            &rec,
            &empty,
            quick(),
        );
        assert_eq!(step.outcome, StepOutcome::Failed);
        assert!(
            step.detail.contains("does not hold the key"),
            "{}",
            step.detail
        );
        // a store that opened is left alone
        let fine = state_agent(Ok((Some(State::ready("", "kms", None)), true)), &pk);
        assert_eq!(
            recover_store_step(&fine, &rec, &keys, quick()).outcome,
            StepOutcome::Skipped
        );
        assert!(fine.admin.lock().unwrap().is_empty());
        Ok(())
    }

    /// The 2026-11-16 upgrade of `main` (0.2.0-beta.0 to beta.1, `--accept-new-secrets-store --use-fleet-key`): the new machine
    /// is configured for KMS over a store the old disk's file key sealed. The service now records that as unopenable, and the
    /// step after the replace sets the old store aside, with the pinned key's approval, instead of reporting "nothing was set
    /// aside" while the service loops.
    #[test]
    fn a_new_store_on_the_fleet_key_sets_the_old_file_sealed_store_aside_after_the_replace(
    ) -> TestResult {
        use crate::secrets::SecretStore;
        use crate::secrets_state::{State, KIND_MISMATCH_CODE};
        let dir = tempfile::tempdir()?;
        let (p, name) = sandbox_box(dir.path(), None)?;
        let (seed, pk) = crate::approval_key::generate()?;
        let keys = crate::secrets::MemorySecrets::default();
        keys.set("approval-key-laptop", &seed)?;
        let mismatch = State::not_ready(
            "sealed by a file key, configured for kms",
            KIND_MISMATCH_CODE,
            Some("kms"),
            None,
        )
        .with_store_kek("file");
        let a = state_agent(Ok((Some(mismatch), false)), &pk);
        let settled = settle_after_replace(
            &p,
            &a,
            &name,
            quick(),
            &|ag, rec| Some(recover_store_step(ag, rec, &keys, quick())),
            &|_, _| None,
            false,
        );
        let r = settled.recovery.expect("the old store was dealt with");
        assert_eq!(r.outcome, StepOutcome::Done, "{}", r.detail);
        assert!(
            r.detail.contains("set aside") && r.detail.contains("new one started"),
            "{}",
            r.detail
        );
        let sent = a.admin.lock().unwrap().clone();
        assert_eq!(sent[0], "recover-secrets challenge");
        assert!(sent[1].starts_with("recover-secrets "), "{sent:?}");
        Ok(())
    }

    /// A box whose own program predates the record (the real `main` on beta.1) still loops with the mismatch as a restart. The
    /// upgrade must not say "for another reason than a lost key"; it says what to run, and sets nothing aside by guesswork.
    #[test]
    fn a_service_still_looping_on_the_mismatch_is_told_apart_and_the_person_is_told_what_to_run(
    ) -> TestResult {
        use crate::secrets_state::State;
        let dir = tempfile::tempdir()?;
        let (_, rec) = running_box(dir.path(), "dev")?;
        let keys = crate::secrets::MemorySecrets::default();
        let looping = State::not_ready(
            &format!(
                "{} (trying again in 2 s)",
                crate::secrets_enc::KEK_KIND_MISMATCH
            ),
            "transient",
            Some("kms"),
            None,
        );
        let a = state_agent(Ok((Some(looping), true)), "");
        let step = recover_store_step(&a, &rec, &keys, quick());
        assert_eq!(step.outcome, StepOutcome::Failed);
        assert!(
            step.detail.contains("0.2.0-beta.2")
                && step.detail.contains("--accept-new-secrets-store"),
            "{}",
            step.detail
        );
        assert!(!step.detail.contains("another reason"), "{}", step.detail);
        assert!(a.admin.lock().unwrap().is_empty(), "nothing is guessed");
        Ok(())
    }

    /// The plan for `--use-fleet-key` with `--accept-new-secrets-store`: whatever the file key's copies, the old store is set
    /// aside and the new one starts on the fleet's KMS key, and the apply does it (the fate is the accepted new-store one).
    #[test]
    fn the_plan_for_the_fleet_key_with_a_new_store_says_the_old_store_is_set_aside_and_the_new_one_starts_on_kms(
    ) {
        for fate in [
            StoreFate::Lost,
            StoreFate::Unknown,
            StoreFate::AlreadyLost,
            StoreFate::KeptByLaptop,
            StoreFate::KeptByEscrow,
            StoreFate::NotSaid,
        ] {
            let c = fleet_key_store_check(
                StoreCheck {
                    fate,
                    detail: "the old text".into(),
                },
                "main",
            );
            assert_eq!(c.fate, StoreFate::Lost, "{fate:?}");
            for w in [
                "--use-fleet-key",
                "KMS",
                "set aside",
                "never deleted",
                "new store",
            ] {
                assert!(c.detail.contains(w), "{fate:?} {w}: {}", c.detail);
            }
            // accepted, so the apply runs the recovery after the replace
            let note = store_gate(&c, "main", true).unwrap();
            assert!(note.contains("Accepted"), "{note}");
        }
        // a store already on a key that is not a file, and a box mid-move, keep their own text
        for fate in [
            StoreFate::Kept,
            StoreFate::MovingKey,
            StoreFate::NotApplicable,
        ] {
            let c = fleet_key_store_check(
                StoreCheck {
                    fate,
                    detail: "own".into(),
                },
                "main",
            );
            assert_eq!(c.detail, "own");
        }
    }

    #[test]
    fn keys_enrolled_with_no_record_of_how_are_named_with_the_command_that_revokes_them() {
        let v = serde_json::json!({"keys": ["laptop", "old"], "via": {"laptop": "pinned", "old": null}});
        let step = review_signers("dev", &v).unwrap();
        assert_eq!(step.outcome, StepOutcome::Failed);
        assert!(
            step.detail.contains("(old)")
                && step
                    .detail
                    .contains("approval-key revoke --box dev --key old")
        );
        let ok = serde_json::json!({"keys": ["laptop"], "via": {"laptop": "pinned"}});
        assert_eq!(
            review_signers("dev", &ok).unwrap().outcome,
            StepOutcome::Done
        );
    }
}
