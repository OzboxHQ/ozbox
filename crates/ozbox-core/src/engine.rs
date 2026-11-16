//! One planner for every provider.
//!
//! A provider adapter implements [`Backend`]: a handful of *primitive* actions (stop, start, change type, grow
//! the disk, snapshot, create, destroy) plus a size mapping. [`Engine`] turns a [`Backend`] into a [`Provider`]
//! that keeps the whole contract (ADR 0003) in one place: plans never mutate, an already-satisfied request plans
//! to nothing, impossible requests fail while planning, `apply` refuses a stale plan, transitional states block.
//! That way the fake, Hetzner and AWS cannot drift apart on behaviour; they differ only in how a primitive runs.

use crate::{
    BoxName, BoxRecord, BoxSpec, BoxState, Capabilities, Change, DiskGb, Error, ImageInfo,
    OldWorkDisk, Operation, Plan, Provider, Result, Risk, Size, SnapshotInfo, SnapshotKind,
};

/// Label/tag a resize sets on a running box BEFORE it stops it, and clears once the box is started again.
/// A box that is stopped and carries it was interrupted mid-resize: the next `resize` or `resume` finishes
/// the job and starts it. Providers must round-trip it through [`BoxRecord`]'s `spec.labels`.
pub const RESUME_AFTER_LABEL: &str = "ozbox-resume-after";
/// The box's first approval key (an Ed25519 public key in lowercase base32), pinned by the computer that made the box. The
/// module writes it to a root-owned file at first boot; providers read it back like a person's label, so an upgrade
/// renders the same first-boot configuration.
pub const APPROVER_LABEL: &str = "ozbox-approver";
/// The label that carries the SSH public key of the computer that reaches the box's secrets service (the ingress account),
/// from `ozbox create` to first boot (Ed25519, lowercase base32).
pub const INGRESS_LABEL: &str = "ozbox-ingress";

/// Label/tag an upgrade sets (to the target image id) BEFORE it stops the box, and clears once the box runs the new
/// image. A box that carries it was interrupted mid-upgrade: running `upgrade` again finishes the job. It must live
/// on something the replacement does not touch: on AWS that is the `/work` volume (the instance is replaced), on
/// Hetzner and the fake the machine. Providers round-trip it through [`BoxRecord`]'s `spec.labels`.
pub const UPGRADE_TO_LABEL: &str = "ozbox-upgrade-to";

/// The first-boot hash a box's machine was made with, as the PROVIDER records it (on AWS an instance tag the module sets
/// when it creates the machine, never changed in place and not writable from the box). It is the authority on whether a
/// box's first boot is this program's; what the box says about itself (`/etc/ozbox/first-boot`) is only a cross-check.
/// Providers that record it put it in [`BoxRecord`]'s `spec.labels`; they never pass it back as a label to set.
pub const FIRST_BOOT_LABEL: &str = "ozbox-first-boot";

/// Said in every upgrade plan: what an upgrade does to a box's restic backups.
pub const UPGRADE_BACKUP_NOTE: &str = "Backups: if this box backs up /work with restic, the repository credentials stay in the box's encrypted secrets store, which an upgrade keeps on /work when the store can be opened on the new machine, and the non-secret settings (what is backed up, and how often) are kept by root on /work. After the self-test the upgrade checks that backups are still configured and that the repository answers, and says plainly if they are not. If the secrets store starts again (a new store), backups STOP until the credentials are sent again: the report then gives the command, `ozbox backup credentials <box>`, and the self-test fails until it is done. Credentials are never stored on /work in plain text.";

/// A size mapped to a provider machine type, with an optional note a person should read in the plan
/// (for example when the nearest type is larger than the size promises).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MachineChoice {
    pub machine_type: String,
    pub note: Option<String>,
}

impl MachineChoice {
    pub fn new(machine_type: impl Into<String>) -> Self {
        Self {
            machine_type: machine_type.into(),
            note: None,
        }
    }

    pub fn with_note(machine_type: impl Into<String>, note: impl Into<String>) -> Self {
        Self {
            machine_type: machine_type.into(),
            note: Some(note.into()),
        }
    }
}

/// A machine the plan is about to start.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CapacityRequest {
    /// The machine type that will run.
    pub machine_type: String,
    /// The machine type of this same box that the plan stops first (and so frees), when it is running.
    pub freed_machine_type: Option<String>,
    pub region: Option<String>,
}

/// The primitive actions of one provider. Each is a single step that has already been planned and
/// confirmed; none of them decides anything. Implementations must not put secret values in errors.
pub trait Backend: Send + Sync {
    fn id(&self) -> &str;
    fn capabilities(&self) -> Capabilities;

    /// Map a size to a machine type, or `Error::Unsupported` (for example a GPU size the provider has no type for).
    fn machine_choice(&self, size: Size) -> Result<MachineChoice>;

    /// Anything else about a create that can be known to be impossible without calling the provider
    /// (a missing image, say). Called while planning.
    fn check_create(&self, _spec: &BoxSpec) -> Result<()> {
        Ok(())
    }

    /// Whether the provider's account has room to run `req` (a vCPU quota, say). Called while planning, before
    /// anything is stopped, so a start that would be refused is refused up front. `Err` refuses the plan; the notes
    /// returned are shown in it (for example, that the quota could not be checked).
    fn check_capacity(&self, _req: &CapacityRequest) -> Result<Vec<String>> {
        Ok(Vec::new())
    }

    /// Extra notes for a plan of this operation (for example a limitation of the provider's snapshots).
    fn plan_notes(&self, _op: &Operation) -> Vec<String> {
        Vec::new()
    }

    /// Every box this provider manages.
    fn list(&self) -> Result<Vec<BoxRecord>>;

    /// Create the box (machine, `/work` disk, restore from `spec.from_snapshot`). Returns its record.
    fn create(&self, spec: &BoxSpec, machine_type: &str) -> Result<BoxRecord>;
    /// Delete the box and its work disk. Snapshots are independent and stay.
    fn destroy(&self, rec: &BoxRecord) -> Result<()>;
    /// Stop the machine and wait until it is stopped.
    fn power_off(&self, rec: &BoxRecord) -> Result<()>;
    /// Start the machine and wait until it is running.
    fn power_on(&self, rec: &BoxRecord) -> Result<()>;
    /// Change the machine type. Called only while the machine is stopped (or when `machine_type` is
    /// unchanged and only the recorded size differs).
    fn set_size(&self, rec: &BoxRecord, size: Size, machine_type: &str) -> Result<()>;
    /// Enlarge the `/work` disk to `gb`.
    fn grow_disk(&self, rec: &BoxRecord, gb: DiskGb) -> Result<()>;
    /// Snapshot `/work` and return the snapshot id once it exists.
    fn snapshot(&self, rec: &BoxRecord) -> Result<String>;
    /// Set (`true`) or clear (`false`) [`RESUME_AFTER_LABEL`] on the box, durably.
    fn set_resume_after(&self, rec: &BoxRecord, on: bool) -> Result<()>;

    /// Where this provider looks for boxes (regions, locations), for `list` to say so. Empty = not applicable.
    fn searched(&self) -> Vec<String> {
        Vec::new()
    }

    /// The newest Oz image this account can see, for `upgrade --image latest`. Read-only.
    fn latest_image(&self, _region: Option<&str>) -> Result<ImageInfo> {
        Err(self.upgrade_unsupported("find the latest image"))
    }

    /// What is known about one image, for `upgrade --image <id>`. Read-only.
    fn image_info(&self, _image: &str, _region: Option<&str>) -> Result<ImageInfo> {
        Err(self.upgrade_unsupported("inspect an image"))
    }

    /// Everything that can be known to make an upgrade of `rec` to `image` impossible or risky, without changing
    /// anything: the image exists and is usable, its architecture fits the machine, `/work` would survive. `Err`
    /// refuses the plan; the notes returned are shown in it. Called while planning (and again before apply).
    fn check_upgrade(&self, _rec: &BoxRecord, _image: &str) -> Result<Vec<String>> {
        Err(self.upgrade_unsupported("upgrade a box"))
    }

    /// Replace the system disk of the (stopped) machine from `image`, keeping `/work` attached and unchanged. May
    /// leave the machine running or stopped; the engine starts it if needed. Must be safe to repeat.
    fn replace_image(&self, _rec: &BoxRecord, _image: &str) -> Result<()> {
        Err(self.upgrade_unsupported("upgrade a box"))
    }

    /// Whether replacing the machine of `rec` from the image it already runs gives it a fresh first boot (the first-boot
    /// configuration rendered now). `Err` refuses a reprovision with the reason; the notes returned are shown in the plan.
    /// The default refuses: a provider must say that its replace renders first boot again.
    fn check_reprovision(&self, _rec: &BoxRecord) -> Result<Vec<String>> {
        Err(Error::Unsupported {
            provider: self.id().to_string(),
            what: "replace a machine from the image it already runs".into(),
            why: "this provider's upgrade keeps the first-boot configuration the machine was made with; to give a box this program's first boot, create a new box (or `ozbox clone` this one) and move to it".into(),
        })
    }

    /// Set (`Some(image)`) or clear (`None`) [`UPGRADE_TO_LABEL`], durably, on something the replacement keeps.
    fn set_upgrade_mark(&self, _rec: &BoxRecord, _image: Option<&str>) -> Result<()> {
        Err(self.upgrade_unsupported("upgrade a box"))
    }

    #[doc(hidden)]
    fn upgrade_unsupported(&self, what: &str) -> Error {
        Error::Unsupported {
            provider: self.id().to_string(),
            what: what.to_string(),
            why: "this provider cannot replace a system disk from a new image".into(),
        }
    }

    /// Whether, and how, a box whose machine is gone (an interrupted upgrade) can be destroyed: only its `/work`
    /// volume (and its OpenTofu state, when this computer has it) is left to remove. `Err` refuses the plan; the notes
    /// returned are shown in it. Read-only.
    fn check_destroy_missing(&self, rec: &BoxRecord) -> Result<Vec<String>> {
        Err(Error::Unsupported {
            provider: self.id().to_string(),
            what: format!("destroy {}", rec.spec.name),
            why: "this provider never leaves a box without its machine, so there is nothing to clean up".into(),
        })
    }

    /// Whether a FINAL snapshot can be taken of a box whose machine is gone (asked of a destroy that wants one). The default
    /// says yes; a provider whose snapshots are of the machine's own disk, and which cannot snapshot the `/work` volume,
    /// refuses here, so the plan says so instead of failing after it was confirmed. Read-only.
    fn check_final_snapshot_of_missing(&self, _rec: &BoxRecord) -> Result<()> {
        Ok(())
    }

    /// The snapshots of this box with what is known about each, oldest first. The default knows only the ids the
    /// record carries; a provider that can say more overrides it.
    fn list_snapshots(&self, rec: &BoxRecord) -> Result<Vec<SnapshotInfo>> {
        Ok(rec
            .snapshots
            .iter()
            .map(|id| SnapshotInfo {
                id: id.clone(),
                kind: SnapshotKind::Provider,
                created_at: None,
                size_bytes: None,
                status: "completed".into(),
                includes_work: true,
                labels: Default::default(),
            })
            .collect())
    }

    /// Delete one snapshot of this box. Must refuse (not guess) anything that is not a snapshot of this box that
    /// Oz Box made.
    fn delete_snapshot(&self, rec: &BoxRecord, _id: &str) -> Result<()> {
        Err(Error::Unsupported {
            provider: self.id().to_string(),
            what: format!("delete a snapshot of {}", rec.spec.name),
            why: "this provider cannot delete snapshots from here".into(),
        })
    }

    /// Whether `/work` of this (stopped) box can be replaced from `snap`, and what a person should know first. `Err`
    /// refuses the plan. Read-only.
    fn check_restore_work(&self, rec: &BoxRecord, _snap: &SnapshotInfo) -> Result<Vec<String>> {
        Err(Error::Unsupported {
            provider: self.id().to_string(),
            what: format!("replace /work of {} from a snapshot", rec.spec.name),
            why: "this provider cannot swap the /work disk of an existing box; restore to a new box (clone) instead".into(),
        })
    }

    /// Replace the `/work` disk of the (stopped) box with a new one made from the snapshot. Must be safe to repeat.
    fn replace_work(&self, rec: &BoxRecord, _id: &str) -> Result<()> {
        Err(Error::Unsupported {
            provider: self.id().to_string(),
            what: format!("replace /work of {} from a snapshot", rec.spec.name),
            why: "this provider cannot swap the /work disk of an existing box".into(),
        })
    }

    /// The old `/work` disks this box's restores kept. The default has none.
    fn list_old_work(&self, _rec: &BoxRecord) -> Result<Vec<OldWorkDisk>> {
        Ok(Vec::new())
    }

    /// Delete one old `/work` disk. Must refuse (not guess) anything that is not a disk a restore of THIS box retired.
    fn delete_old_work(&self, rec: &BoxRecord, _id: &str) -> Result<()> {
        Err(Error::Unsupported {
            provider: self.id().to_string(),
            what: format!("delete an old /work disk of {}", rec.spec.name),
            why: "this provider keeps no old /work disks".into(),
        })
    }

    /// What a snapshot captures, as a person reads it in a plan. Say so plainly when it is not `/work`.
    fn snapshot_subject(&self) -> String {
        "/work".to_string()
    }
}

pub struct Engine<B: Backend> {
    backend: B,
}

impl<B: Backend> Engine<B> {
    pub fn new(backend: B) -> Self {
        Self { backend }
    }

    pub fn backend(&self) -> &B {
        &self.backend
    }

    fn find(records: &[BoxRecord], name: &BoxName) -> Option<BoxRecord> {
        records.iter().find(|r| &r.spec.name == name).cloned()
    }

    fn require(records: &[BoxRecord], name: &BoxName) -> Result<BoxRecord> {
        Self::find(records, name).ok_or_else(|| Error::NotFound(name.to_string()))
    }

    /// Stopped by an interrupted resize, which promised to start it again.
    fn resume_pending(rec: &BoxRecord) -> bool {
        rec.state == BoxState::Paused
            && rec.spec.labels.get(RESUME_AFTER_LABEL).map(String::as_str) == Some("true")
    }

    fn settled(rec: &BoxRecord, action: &'static str) -> Result<()> {
        if rec.state.is_settled() {
            Ok(())
        } else {
            Err(Error::InvalidState {
                name: rec.spec.name.to_string(),
                state: rec.state,
                action,
            })
        }
    }

    fn invalid(rec: &BoxRecord, action: &'static str) -> Error {
        Error::InvalidState {
            name: rec.spec.name.to_string(),
            state: rec.state,
            action,
        }
    }

    /// The snapshot `id` of `rec`, provided it is finished and holds `/work`: the only kind a restore or a clone can use.
    fn usable_snapshot(&self, rec: &BoxRecord, id: &str) -> Result<SnapshotInfo> {
        let all = self.backend.list_snapshots(rec)?;
        let Some(found) = all.into_iter().find(|s| s.id == id) else {
            return Err(Error::NotFound(format!(
                "snapshot {id} of {}",
                rec.spec.name
            )));
        };
        if found.status != "completed" {
            return Err(Error::Config(format!(
                "snapshot {id} is {}, not finished; wait for it to complete",
                found.status
            )));
        }
        if !found.includes_work {
            return Err(Error::Unsupported {
                provider: self.backend.id().to_string(),
                what: format!("restore /work from snapshot {id}"),
                why: format!(
                    "this snapshot does not contain /work ({})",
                    self.backend.snapshot_subject()
                ),
            });
        }
        Ok(found)
    }

    /// The records a plan for `op` depends on, in a fixed order.
    fn relevant(records: &[BoxRecord], op: &Operation) -> Vec<Option<BoxRecord>> {
        match op {
            Operation::Clone { from, to, .. } => {
                vec![Self::find(records, from), Self::find(records, to)]
            }
            other => vec![Self::find(records, other.box_name())],
        }
    }

    fn plan_from(&self, op: &Operation, records: &[BoxRecord]) -> Result<Plan> {
        let caps = self.backend.capabilities();
        let mut changes: Vec<Change> = Vec::new();
        let mut notes: Vec<String> = Vec::new();

        match op {
            Operation::Create { spec } => {
                if spec.work_disk_gb < BoxSpec::MIN_WORK_DISK_GB {
                    return Err(Error::Config(format!(
                        "the work disk must be at least {} GB (asked for {} GB)",
                        BoxSpec::MIN_WORK_DISK_GB,
                        spec.work_disk_gb
                    )));
                }
                let choice = self.backend.machine_choice(spec.size)?;
                self.backend.check_create(spec)?;
                match Self::find(records, &spec.name) {
                    Some(existing) => {
                        // Idempotent when the existing box is what was asked for; a different box of that
                        // name is a conflict the person must resolve (resize it, or pick another name).
                        if existing.spec.size != spec.size
                            || existing.spec.work_disk_gb != spec.work_disk_gb
                        {
                            return Err(Error::AlreadyExists(spec.name.to_string()));
                        }
                    }
                    None => {
                        let restore = match &spec.from_snapshot {
                            Some(s) => format!(", restoring /work from snapshot {s}"),
                            None => String::new(),
                        };
                        changes.push(Change::new(
                            "box.create",
                            format!(
                                "Create box {} (size {}, machine type {}) with a {} GB /work disk{restore}",
                                spec.name, spec.size, choice.machine_type, spec.work_disk_gb
                            ),
                            Risk::Medium,
                        ));
                        notes.extend(self.backend.check_capacity(&CapacityRequest {
                            machine_type: choice.machine_type.clone(),
                            freed_machine_type: None,
                            region: spec.region.clone(),
                        })?);
                        notes.extend(choice.note);
                    }
                }
            }
            Operation::Pause { name } => {
                let rec = Self::require(records, name)?;
                Self::settled(&rec, "paused")?;
                if rec.state == BoxState::Running {
                    changes.push(Change::new(
                        "instance.stop",
                        format!("Stop {name} (/work stays on its disk; you pay only for storage)"),
                        Risk::Low,
                    ));
                } else if Self::resume_pending(&rec) {
                    changes.push(Change::new(
                        "instance.clear_restart",
                        format!("Clear the pending restart of {name} (an interrupted resize meant to start it; it stays stopped)"),
                        Risk::Low,
                    ));
                }
            }
            Operation::Resume { name } => {
                let rec = Self::require(records, name)?;
                Self::settled(&rec, "resumed")?;
                if rec.state == BoxState::Paused {
                    if let Some(m) = rec.spec.labels.get(UPGRADE_TO_LABEL) {
                        notes.push(format!(
                            "An upgrade of {name} to image {m} did not finish. Resuming starts the box as it is and drops that mark; run `upgrade` again to finish it."
                        ));
                    }
                    if let Some(t) = rec.machine_type.clone() {
                        notes.extend(self.backend.check_capacity(&CapacityRequest {
                            machine_type: t,
                            freed_machine_type: None,
                            region: rec.spec.region.clone(),
                        })?);
                    }
                    changes.push(Change::new(
                        "instance.start",
                        format!("Start {name}"),
                        Risk::Low,
                    ));
                }
            }
            Operation::Resize {
                name,
                size,
                work_disk_gb,
            } => {
                let rec = Self::require(records, name)?;
                Self::settled(&rec, "resized")?;
                if size.is_none() && work_disk_gb.is_none() {
                    return Err(Error::Config(
                        "resize needs a new size, a larger disk, or both".into(),
                    ));
                }
                let running = rec.state == BoxState::Running;
                let pending = Self::resume_pending(&rec);

                let mut grow: Option<DiskGb> = None;
                if let Some(d) = work_disk_gb {
                    let cur = rec.spec.work_disk_gb;
                    if *d < cur {
                        return Err(Error::Unsupported {
                            provider: self.backend.id().to_string(),
                            what: format!("shrink the work disk of {name} from {cur} GB to {d} GB"),
                            why: "disks cannot shrink in place; create a new box with the smaller disk and copy /work over"
                                .into(),
                        });
                    }
                    if *d > cur {
                        grow = Some(*d);
                    }
                }

                // None = nothing to do; Some(true) = the machine type changes; Some(false) = only the label.
                let mut new_size: Option<(Size, String, bool)> = None;
                if let Some(s) = size {
                    if *s != rec.spec.size {
                        let choice = self.backend.machine_choice(*s)?;
                        let type_changes =
                            rec.machine_type.as_deref() != Some(&choice.machine_type);
                        notes.extend(choice.note.clone());
                        new_size = Some((*s, choice.machine_type, type_changes));
                    }
                }

                let type_changes = new_size.as_ref().is_some_and(|(_, _, t)| *t);
                let needs_stop =
                    running && (type_changes || (grow.is_some() && !caps.online_disk_grow));
                if pending {
                    notes.push(format!(
                        "An earlier resize stopped {name} and did not finish; this finishes it and starts it again."
                    ));
                }
                // The machine that will start again after this resize, and what stopping frees first.
                let will_start = needs_stop || pending;
                if will_start {
                    let target = match &new_size {
                        Some((_, t, true)) => Some(t.clone()),
                        _ => rec.machine_type.clone(),
                    };
                    if let Some(machine_type) = target {
                        notes.extend(self.backend.check_capacity(&CapacityRequest {
                            machine_type,
                            freed_machine_type: if running {
                                rec.machine_type.clone()
                            } else {
                                None
                            },
                            region: rec.spec.region.clone(),
                        })?);
                    }
                }
                if needs_stop {
                    changes.push(Change::new(
                        "instance.stop",
                        format!("Stop {name} (it was running; it is started again afterwards)"),
                        Risk::Medium,
                    ));
                    notes.push(format!(
                        "{name} is running: resizing stops it and starts it again, so anything running in it is interrupted."
                    ));
                }
                if let Some((s, t, true)) = &new_size {
                    changes.push(Change::new(
                        "instance.resize",
                        format!(
                            "Change {name} from size {} to {s} (machine type {} -> {t})",
                            rec.spec.size,
                            rec.machine_type.as_deref().unwrap_or("unknown")
                        ),
                        Risk::Medium,
                    ));
                } else if let Some((s, t, false)) = &new_size {
                    changes.push(Change::new(
                        "box.relabel",
                        format!(
                            "Record {name} as size {s} (same machine type {t}; nothing restarts)"
                        ),
                        Risk::Low,
                    ));
                }
                if let Some(d) = grow {
                    changes.push(Change::new(
                        "volume.grow",
                        format!(
                            "Grow the /work disk of {name} from {} GB to {d} GB (it cannot be shrunk again; the filesystem grows by itself within a minute, by the box daemon)",
                            rec.spec.work_disk_gb
                        ),
                        Risk::Medium,
                    ));
                }
                if needs_stop || pending {
                    changes.push(Change::new(
                        "instance.start",
                        format!("Start {name}"),
                        Risk::Medium,
                    ));
                }
            }
            Operation::Snapshot { name } => {
                let rec = Self::require(records, name)?;
                Self::settled(&rec, "snapshotted")?;
                changes.push(Change::new(
                    "snapshot.create",
                    format!("Snapshot {} of {name}", self.backend.snapshot_subject()),
                    Risk::Low,
                ));
            }
            Operation::Clone { from, to, snapshot } => {
                let src = Self::require(records, from)?;
                Self::settled(&src, "cloned")?;
                if Self::find(records, to).is_some() {
                    return Err(Error::AlreadyExists(to.to_string()));
                }
                if let Some(id) = snapshot {
                    self.usable_snapshot(&src, id)?;
                }
                let choice = self.backend.machine_choice(src.spec.size)?;
                let mut spec = src.spec.clone();
                spec.name = to.clone();
                spec.labels.remove(RESUME_AFTER_LABEL);
                spec.labels.remove(UPGRADE_TO_LABEL);
                spec.from_snapshot = snapshot.clone().or_else(|| src.snapshots.last().cloned());
                // A clone always restores /work from a snapshot (an existing one or the one it takes), so a
                // provider that cannot restore refuses here, while planning.
                let mut checked = spec.clone();
                checked
                    .from_snapshot
                    .get_or_insert_with(|| "(new snapshot)".to_string());
                self.backend.check_create(&checked)?;
                if spec.from_snapshot.is_none() {
                    changes.push(Change::new(
                        "snapshot.create",
                        format!(
                            "Snapshot {} of {from} (it has no snapshot to clone from)",
                            self.backend.snapshot_subject()
                        ),
                        Risk::Low,
                    ));
                }
                let source = match &spec.from_snapshot {
                    Some(s) => format!("snapshot {s}"),
                    None => "that new snapshot".to_string(),
                };
                changes.push(Change::new(
                    "box.create",
                    format!(
                        "Create box {to} (size {}, machine type {}) with a {} GB /work disk restored from {source}",
                        spec.size, choice.machine_type, spec.work_disk_gb
                    ),
                    Risk::Medium,
                ));
                notes.extend(self.backend.check_capacity(&CapacityRequest {
                    machine_type: choice.machine_type.clone(),
                    freed_machine_type: None,
                    region: spec.region.clone(),
                })?);
                notes.extend(choice.note);
            }
            Operation::DeleteSnapshot { name, snapshot } => {
                let rec = Self::require(records, name)?;
                if rec.state == BoxState::Destroying {
                    return Err(Self::invalid(&rec, "have a snapshot deleted"));
                }
                let all = self.backend.list_snapshots(&rec)?;
                let Some(found) = all.iter().find(|x| &x.id == snapshot) else {
                    // Already gone: nothing to do, which is what a repeat of this request should say.
                    return Ok(Plan {
                        operation: op.clone(),
                        provider: self.backend.id().to_string(),
                        changes: Vec::new(),
                        notes: vec![format!(
                            "{snapshot} is not a snapshot of {name} (any more)."
                        )],
                        based_on: fingerprint(&Self::relevant(records, op)),
                    });
                };
                let taken = found
                    .created_at
                    .as_deref()
                    .map(|t| format!(", taken {t}"))
                    .unwrap_or_default();
                changes.push(Change::new(
                    "snapshot.delete",
                    format!(
                        "Delete snapshot {snapshot} of {name}{taken}. It cannot be brought back."
                    ),
                    Risk::High,
                ));
                if all.len() == 1 {
                    notes.push(format!(
                        "This is the only snapshot of {name}: after it is deleted there is no backup of /work from this provider."
                    ));
                }
            }
            Operation::DeleteOldWork { name, volume } => {
                let rec = Self::require(records, name)?;
                if rec.state == BoxState::Destroying {
                    return Err(Self::invalid(&rec, "have an old disk deleted"));
                }
                let all = self.backend.list_old_work(&rec)?;
                let Some(found) = all.iter().find(|d| &d.id == volume) else {
                    return Ok(Plan {
                        operation: op.clone(),
                        provider: self.backend.id().to_string(),
                        changes: Vec::new(),
                        notes: vec![format!(
                            "{volume} is not an old /work disk of {name} (any more)."
                        )],
                        based_on: fingerprint(&Self::relevant(records, op)),
                    });
                };
                if found.state != "kept" {
                    return Err(Error::Config(format!(
                        "{volume} belongs to a restore of {name} that was interrupted; finish it by restoring again before deleting the disk"
                    )));
                }
                changes.push(Change::new(
                    "volume.delete",
                    format!(
                        "Delete the old /work disk {volume} of {name}, kept when /work was restored. Everything on it is lost; it cannot be brought back."
                    ),
                    Risk::High,
                ));
            }
            Operation::RestoreWork { name, snapshot } => {
                let rec = Self::require(records, name)?;
                Self::settled(&rec, "restored")?;
                let found = self.usable_snapshot(&rec, snapshot)?;
                notes.extend(self.backend.check_restore_work(&rec, &found)?);
                changes.push(Change::new(
                    "snapshot.create",
                    format!(
                        "Snapshot {} of {name} as it is now, so this restore can itself be undone",
                        self.backend.snapshot_subject()
                    ),
                    Risk::Low,
                ));
                if rec.state == BoxState::Running {
                    changes.push(Change::new(
                        "instance.stop",
                        format!("Stop {name} (work is checkpointed first)"),
                        Risk::Medium,
                    ));
                }
                changes.push(Change::new(
                    "volume.replace",
                    format!(
                        "Replace the /work disk of {name} with a new one made from snapshot {snapshot}. Everything written to /work since then is no longer on the box (the snapshot taken first keeps it)."
                    ),
                    Risk::High,
                ));
                if rec.state == BoxState::Running {
                    changes.push(Change::new(
                        "instance.start",
                        format!("Start {name}"),
                        Risk::Medium,
                    ));
                }
            }
            Operation::ResticBackup { .. }
            | Operation::ResticForget { .. }
            | Operation::ResticRestore { .. }
            | Operation::RestoreToNewBox { .. } => {
                return Err(Error::Unsupported {
                    provider: self.backend.id().to_string(),
                    what: op.verb().to_string(),
                    why: "backups to a restic repository are run through the box's agent, not by the provider".into(),
                });
            }
            Operation::Upgrade {
                name,
                image,
                reprovision,
            } => {
                let rec = Self::require(records, name)?;
                // A box whose machine is gone is exactly what an interrupted upgrade leaves behind: it is the one
                // unsettled state an upgrade accepts, because finishing the upgrade is how it is recovered.
                let missing = rec.state == BoxState::InstanceMissing;
                if !missing {
                    Self::settled(&rec, "upgraded")?;
                }
                if image.trim().is_empty() || image == "latest" {
                    return Err(Error::Config(
                        "upgrade needs a concrete image id (the word `latest` is resolved before planning)"
                            .into(),
                    ));
                }
                let running = rec.state == BoxState::Running;
                let on_target = rec.spec.image.as_deref() == Some(image.as_str());
                let mark = rec.spec.labels.get(UPGRADE_TO_LABEL).map(String::as_str);
                if let Some(m) = mark {
                    if m != image {
                        notes.push(format!(
                            "An earlier upgrade of {name} to image {m} did not finish; this upgrade to {image} replaces that mark."
                        ));
                    } else if on_target {
                        notes.push(format!(
                            "An earlier upgrade of {name} to this image replaced the system disk and did not finish; this finishes it."
                        ));
                    } else {
                        notes.push(format!(
                            "An earlier upgrade of {name} to this image did not finish; this finishes it."
                        ));
                    }
                }
                let capacity = |backend: &B| -> Result<Vec<String>> {
                    match rec.machine_type.clone() {
                        Some(machine_type) => backend.check_capacity(&CapacityRequest {
                            machine_type,
                            freed_machine_type: if running {
                                rec.machine_type.clone()
                            } else {
                                None
                            },
                            region: rec.spec.region.clone(),
                        }),
                        None => Ok(Vec::new()),
                    }
                };
                if missing {
                    // Nothing to stop and nothing to replace: create the machine from the image and attach the
                    // kept /work disk. The cheap, decisive check first, as below.
                    notes.extend(capacity(&self.backend)?);
                    notes.extend(self.backend.check_upgrade(&rec, image)?);
                    notes.push(format!(
                        "{name} has no machine: an upgrade removed the old one and could not create the new one. Its /work disk is kept untouched. This creates the machine from image {image} and attaches that disk."
                    ));
                    changes.push(Change::new(
                        "instance.create",
                        format!(
                            "Create a new machine for {name} from image {image} (the /work disk is NOT touched)"
                        ),
                        Risk::Medium,
                    ));
                    changes.push(Change::new(
                        "volume.reattach",
                        format!(
                            "Keep the /work disk of {name} ({} GB) and attach it to the new machine, unchanged",
                            rec.spec.work_disk_gb
                        ),
                        Risk::Low,
                    ));
                    changes.push(Change::new(
                        "instance.start",
                        format!("Start {name} on the new image"),
                        Risk::Medium,
                    ));
                    notes.push(
                        "What lived on the old system disk is gone: system packages, files under /etc, and the box's SSH host key."
                            .into(),
                    );
                    notes.push(UPGRADE_BACKUP_NOTE.into());
                    notes.push(
                        "After the box starts, wait for its agent and run its self-test (the command and the dashboard do this and report the result)."
                            .into(),
                    );
                } else if on_target && (!*reprovision || mark == Some(image.as_str())) {
                    // Already on the image. Only an unfinished upgrade has anything left to do. An unfinished upgrade to
                    // this image is finished first, even when a same-image replace was asked: finishing is cheap and is
                    // what the box is waiting for; a replace, if still wanted, is the next run's.
                    if *reprovision {
                        notes.push(format!(
                            "An unfinished upgrade of {name} to this image is finished first; replacing its machine from the same image is not done in the same run (run the upgrade again afterwards if it is still needed)."
                        ));
                    }
                    if mark == Some(image.as_str()) {
                        if !running {
                            notes.extend(capacity(&self.backend)?);
                            changes.push(Change::new(
                                "instance.start",
                                format!("Start {name}"),
                                Risk::Medium,
                            ));
                        }
                        changes.push(Change::new(
                            "upgrade.finish",
                            format!("Mark the upgrade of {name} to image {image} as finished"),
                            Risk::Low,
                        ));
                    }
                } else {
                    if on_target {
                        // Same image, fresh first boot: only a provider whose replace renders it again can do this.
                        notes.extend(self.backend.check_reprovision(&rec)?);
                        notes.push(format!(
                            "{name} is already on image {image}: its machine is replaced from the same image so that it boots with the first-boot configuration this program renders."
                        ));
                    }
                    // The cheap, decisive check first: a start the account would refuse needs no further work.
                    notes.extend(capacity(&self.backend)?);
                    notes.extend(self.backend.check_upgrade(&rec, image)?);
                    let current = rec.spec.image.as_deref().unwrap_or("unknown");
                    if running {
                        notes.push(format!(
                            "{name} is running: its agent is asked to checkpoint work in progress first when it can be reached (the plan cannot promise it), then the box is stopped, so anything running in it is interrupted."
                        ));
                        changes.push(Change::new(
                            "instance.stop",
                            format!("Stop {name} (it is started again afterwards)"),
                            Risk::Medium,
                        ));
                    } else {
                        notes.push(format!(
                            "{name} is stopped. An upgrade leaves it running, so its self-test can check it."
                        ));
                    }
                    changes.push(Change::new(
                        "instance.replace_image",
                        format!(
                            "Replace the system disk of {name} (image {current}) with image {image}: the machine is rebuilt; the /work disk is NOT touched"
                        ),
                        Risk::Medium,
                    ));
                    changes.push(Change::new(
                        "volume.reattach",
                        format!(
                            "Keep the /work disk of {name} ({} GB) and attach it to the rebuilt machine, unchanged",
                            rec.spec.work_disk_gb
                        ),
                        Risk::Low,
                    ));
                    changes.push(Change::new(
                        "instance.start",
                        format!("Start {name} on the new image"),
                        Risk::Medium,
                    ));
                    notes.push(
                        "Everything on /work stays, including the box user's home. What lives on the system disk is replaced: system packages, files under /etc, and the box's SSH host key."
                            .into(),
                    );
                    notes.push(UPGRADE_BACKUP_NOTE.into());
                    notes.push(
                        "After the box starts, wait for its agent and run its self-test (the command and the dashboard do this and report the result)."
                            .into(),
                    );
                }
            }
            Operation::Destroy {
                name,
                final_snapshot,
            } => {
                if let Some(rec) = Self::find(records, name) {
                    let missing = rec.state == BoxState::InstanceMissing;
                    if missing {
                        // The one unsettled state a destroy accepts: the machine is already gone, only /work is left.
                        notes.extend(self.backend.check_destroy_missing(&rec)?);
                        if *final_snapshot {
                            self.backend.check_final_snapshot_of_missing(&rec)?;
                        }
                        notes.push(format!(
                            "The machine of {name} is already missing; this removes what is left of it, including the /work volume."
                        ));
                    } else {
                        Self::settled(&rec, "destroyed")?;
                    }
                    if *final_snapshot {
                        changes.push(Change::new(
                            "snapshot.create",
                            format!("Take a final snapshot of {name}: {} (kept after the box is deleted)", self.backend.snapshot_subject()),
                            Risk::Low,
                        ));
                    } else {
                        notes.push(
                            if missing {
                                "No final snapshot: the /work disk and everything on it will be lost. Ask for a final snapshot to keep a copy first."
                            } else {
                                "No final snapshot: the /work disk and everything on it will be lost."
                            }
                            .into(),
                        );
                    }
                    changes.push(Change::new(
                        "box.delete",
                        if missing {
                            format!("Delete the /work volume of {name} (its machine is already missing) and the box's remaining resources")
                        } else {
                            format!("Delete box {name} and its /work disk")
                        },
                        Risk::High,
                    ));
                    if !rec.snapshots.is_empty() {
                        notes.push(format!(
                            "{} existing snapshot(s) are kept.",
                            rec.snapshots.len()
                        ));
                    }
                }
            }
        }

        if !changes.is_empty() {
            notes.extend(self.backend.plan_notes(op));
        }
        Ok(Plan {
            operation: op.clone(),
            provider: self.backend.id().to_string(),
            changes,
            notes,
            based_on: fingerprint(&Self::relevant(records, op)),
        })
    }

    fn run(&self, op: &Operation, records: &[BoxRecord]) -> Result<()> {
        match op {
            Operation::Create { spec } => {
                let choice = self.backend.machine_choice(spec.size)?;
                self.backend.create(spec, &choice.machine_type)?;
            }
            Operation::Pause { name } => {
                let rec = Self::require(records, name)?;
                if Self::resume_pending(&rec) {
                    self.backend.set_resume_after(&rec, false)?;
                } else {
                    self.backend.power_off(&rec)?;
                }
            }
            Operation::Resume { name } => {
                let rec = Self::require(records, name)?;
                self.backend.power_on(&rec)?;
                if rec.spec.labels.contains_key(RESUME_AFTER_LABEL) {
                    self.backend.set_resume_after(&rec, false)?;
                }
                if rec.spec.labels.contains_key(UPGRADE_TO_LABEL) {
                    self.backend.set_upgrade_mark(&rec, None)?;
                }
            }
            Operation::Resize {
                name,
                size,
                work_disk_gb,
            } => {
                let rec = Self::require(records, name)?;
                let running = rec.state == BoxState::Running;
                let pending = Self::resume_pending(&rec);
                let caps = self.backend.capabilities();
                let grow = work_disk_gb.filter(|d| *d > rec.spec.work_disk_gb);
                let new_size = match size {
                    Some(s) if *s != rec.spec.size => {
                        let c = self.backend.machine_choice(*s)?;
                        let type_changes = rec.machine_type.as_deref() != Some(&c.machine_type);
                        Some((*s, c.machine_type, type_changes))
                    }
                    _ => None,
                };
                let type_changes = new_size.as_ref().is_some_and(|(_, _, t)| *t);
                let needs_stop =
                    running && (type_changes || (grow.is_some() && !caps.online_disk_grow));
                if needs_stop {
                    // Durable BEFORE the stop: if anything below fails, the box says it must be started again.
                    self.backend.set_resume_after(&rec, true)?;
                    self.backend.power_off(&rec)?;
                }
                if let Some((s, t, _)) = &new_size {
                    self.backend.set_size(&rec, *s, t)?;
                }
                if let Some(d) = grow {
                    self.backend.grow_disk(&rec, d)?;
                }
                if needs_stop || pending {
                    self.backend.power_on(&rec)?;
                    self.backend.set_resume_after(&rec, false)?;
                }
            }
            Operation::Snapshot { name } => {
                let rec = Self::require(records, name)?;
                self.backend.snapshot(&rec)?;
            }
            Operation::Clone { from, to, snapshot } => {
                let src = Self::require(records, from)?;
                let snap = match snapshot.as_ref().or_else(|| src.snapshots.last()) {
                    Some(s) => s.clone(),
                    None => self.backend.snapshot(&src)?,
                };
                let mut spec = src.spec.clone();
                spec.name = to.clone();
                spec.labels.remove(RESUME_AFTER_LABEL);
                spec.labels.remove(UPGRADE_TO_LABEL);
                spec.from_snapshot = Some(snap);
                let choice = self.backend.machine_choice(spec.size)?;
                self.backend.create(&spec, &choice.machine_type)?;
            }
            Operation::DeleteSnapshot { name, snapshot } => {
                let rec = Self::require(records, name)?;
                self.backend.delete_snapshot(&rec, snapshot)?;
            }
            Operation::DeleteOldWork { name, volume } => {
                let rec = Self::require(records, name)?;
                self.backend.delete_old_work(&rec, volume)?;
            }
            Operation::RestoreWork { name, snapshot } => {
                let rec = Self::require(records, name)?;
                // The way back is made BEFORE anything is replaced.
                self.backend.snapshot(&rec)?;
                let running = rec.state == BoxState::Running;
                if running {
                    self.backend.power_off(&rec)?;
                }
                self.backend.replace_work(&rec, snapshot)?;
                if running {
                    let after = Self::require(&self.backend.list()?, name)?;
                    if after.state != BoxState::Running {
                        self.backend.power_on(&after)?;
                    }
                }
            }
            Operation::ResticBackup { .. }
            | Operation::ResticForget { .. }
            | Operation::ResticRestore { .. }
            | Operation::RestoreToNewBox { .. } => {
                return Err(Error::Unsupported {
                    provider: self.backend.id().to_string(),
                    what: op.verb().to_string(),
                    why: "backups to a restic repository are run through the box's agent".into(),
                });
            }
            Operation::Upgrade {
                name,
                image,
                reprovision,
            } => {
                let rec = Self::require(records, name)?;
                if rec.state == BoxState::InstanceMissing {
                    // The machine is already gone; only the new one is left to make. A different image than the
                    // one marked replaces the mark first, so a further interruption finishes the right upgrade.
                    if rec.spec.labels.get(UPGRADE_TO_LABEL).map(String::as_str)
                        != Some(image.as_str())
                    {
                        self.backend.set_upgrade_mark(&rec, Some(image))?;
                    }
                    self.backend.replace_image(&rec, image)?;
                } else if rec.spec.image.as_deref() != Some(image.as_str()) || *reprovision {
                    // Everything that must survive an interruption is durable BEFORE the stop; a repeat of this
                    // operation finds the mark and finishes the job. (`apply` has just re-planned, which ran the
                    // provider's `check_upgrade` against the state it is about to change.)
                    self.backend.set_upgrade_mark(&rec, Some(image))?;
                    if rec.state == BoxState::Running {
                        self.backend.power_off(&rec)?;
                    }
                    self.backend.replace_image(&rec, image)?;
                }
                // The machine may have a new id now: read it again rather than trust `rec`.
                let after = Self::require(&self.backend.list()?, name)?;
                if after.state != BoxState::Running {
                    self.backend.power_on(&after)?;
                }
                if after.spec.labels.contains_key(UPGRADE_TO_LABEL) {
                    self.backend.set_upgrade_mark(&after, None)?;
                }
            }
            Operation::Destroy {
                name,
                final_snapshot,
            } => {
                let rec = Self::require(records, name)?;
                if *final_snapshot {
                    self.backend.snapshot(&rec)?;
                }
                self.backend.destroy(&rec)?;
            }
        }
        Ok(())
    }
}

impl<B: Backend> Provider for Engine<B> {
    fn id(&self) -> &str {
        self.backend.id()
    }

    fn capabilities(&self) -> Capabilities {
        self.backend.capabilities()
    }

    fn list(&self) -> Result<Vec<BoxRecord>> {
        self.backend.list()
    }

    fn searched(&self) -> Vec<String> {
        self.backend.searched()
    }

    fn get(&self, name: &BoxName) -> Result<Option<BoxRecord>> {
        Ok(Self::find(&self.backend.list()?, name))
    }

    fn snapshots(&self, name: &BoxName) -> Result<Vec<SnapshotInfo>> {
        let rec = Self::require(&self.backend.list()?, name)?;
        self.backend.list_snapshots(&rec)
    }

    fn old_work_disks(&self, name: &BoxName) -> Result<Vec<OldWorkDisk>> {
        let rec = Self::require(&self.backend.list()?, name)?;
        self.backend.list_old_work(&rec)
    }

    fn latest_image(&self, region: Option<&str>) -> Result<ImageInfo> {
        self.backend.latest_image(region)
    }

    fn check_reprovision(&self, rec: &BoxRecord) -> Result<Vec<String>> {
        self.backend.check_reprovision(rec)
    }

    fn image_info(&self, image: &str, region: Option<&str>) -> Result<ImageInfo> {
        self.backend.image_info(image, region)
    }

    fn plan(&self, op: &Operation) -> Result<Plan> {
        let records = self.backend.list()?;
        self.plan_from(op, &records)
    }

    fn apply(&self, plan: &Plan) -> Result<Option<BoxRecord>> {
        if plan.provider != self.backend.id() {
            return Err(Error::Provider(format!(
                "this plan was made for provider {:?}, not {:?}",
                plan.provider,
                self.backend.id()
            )));
        }
        let records = self.backend.list()?;
        let name = plan.operation.box_name().clone();
        let now = fingerprint(&Self::relevant(&records, &plan.operation));
        if now != plan.based_on {
            return Err(Error::StalePlan(format!(
                "box {name} changed after the plan was made"
            )));
        }
        let fresh = self.plan_from(&plan.operation, &records)?;
        if fresh.changes != plan.changes {
            return Err(Error::StalePlan(
                "the plan no longer matches what would be done".into(),
            ));
        }
        if !fresh.is_noop() {
            self.run(&plan.operation, &records)?;
        }
        self.get(&name)
    }
}

/// A stable fingerprint (FNV-1a 64) of the records a plan depends on. `last_activity_at` is left out:
/// it moves on its own and must not make every plan stale.
pub fn fingerprint(records: &[Option<BoxRecord>]) -> String {
    if records.iter().all(Option::is_none) {
        return "absent".to_string();
    }
    let mut h: u64 = 0xcbf2_9ce4_8422_2325;
    let mut feed = |bytes: &[u8]| {
        for b in bytes {
            h ^= u64::from(*b);
            h = h.wrapping_mul(0x0000_0100_0000_01b3);
        }
    };
    for r in records {
        match r {
            None => feed(b"\x00absent\x00"),
            Some(rec) => {
                let mut rec = rec.clone();
                rec.last_activity_at = None;
                // Serialising a BoxRecord cannot fail; fall back to the Debug form rather than panic.
                let bytes =
                    serde_json::to_vec(&rec).unwrap_or_else(|_| format!("{rec:?}").into_bytes());
                feed(&bytes);
                feed(b"\x01");
            }
        }
    }
    format!("{h:016x}")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rec(state: BoxState, last: Option<&str>) -> Result<BoxRecord> {
        Ok(BoxRecord {
            spec: BoxSpec::new(BoxName::new("main")?, Size::S),
            state,
            provider: "x".into(),
            provider_id: None,
            machine_type: None,
            snapshots: vec![],
            created_at: None,
            last_activity_at: last.map(str::to_string),
        })
    }

    #[test]
    fn fingerprint_ignores_activity_but_not_state() -> Result<()> {
        let a = fingerprint(&[Some(rec(BoxState::Running, None)?)]);
        let b = fingerprint(&[Some(rec(BoxState::Running, Some("2026-01-01T00:00:00Z"))?)]);
        let c = fingerprint(&[Some(rec(BoxState::Paused, None)?)]);
        assert_eq!(a, b);
        assert_ne!(a, c);
        assert_eq!(fingerprint(&[None]), "absent");
        Ok(())
    }
}
