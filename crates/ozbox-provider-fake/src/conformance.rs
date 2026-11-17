//! The provider conformance suite: the six-point contract of [`ozbox_core::Provider`], checked against any
//! implementation. Every provider crate runs [`run_all`] in its own tests, with its own fake cloud behind it.
//!
//! Each check returns `Err(description)` for the first violation, so a failing provider says which point of the
//! contract it broke. The checks leave their boxes behind (use a fresh state per run).
//!
//! # Choices the suite pins down
//!
//! * **Create of an existing box** is a no-op when the box already has the requested size and disk, and
//!   [`Error::AlreadyExists`] when it differs. Either way nothing is changed.
//! * **Destroy of a missing box** is a no-op (the box is already gone).
//! * **Snapshot** is deliberately not idempotent: every snapshot is a new snapshot.
//! * **Stale** is checked before anything else in `apply`, so a plan made against an older state of the box
//!   fails with `StalePlan` even if the box has meanwhile moved into a transitional state.

use ozbox_core::{
    BoxName, BoxRecord, BoxSpec, BoxState, Error, Operation, Plan, Provider, Size, UPGRADE_TO_LABEL,
};

type Check = Result<(), String>;

/// What the upgrade checks need besides the provider: a newer image to move to, and eyes on `/work`.
pub struct UpgradeKit<'a> {
    /// A newer image the provider accepts for the boxes the suite creates.
    pub image: String,
    /// An image the provider must refuse because its architecture does not fit the machine, when it can tell.
    pub wrong_arch_image: Option<String>,
    /// The identity of a box's `/work` disk (a volume id). An upgrade must not change it.
    pub work_id: &'a dyn Fn(&BoxName) -> ozbox_core::Result<String>,
    /// Leave a box the way an upgrade interrupted after the stop leaves it: stopped, still on its old image, carrying
    /// the upgrade mark for the given image.
    pub interrupt: &'a dyn Fn(&BoxName, &str) -> ozbox_core::Result<()>,
    /// Make the next machine an upgrade creates fail the way an account refuses one (a quota, no capacity), AFTER the
    /// old machine was removed. `/work` must be kept.
    /// `None` for a provider that rebuilds the machine in place (no gap in which the machine does not exist).
    pub refuse_next_create: Option<&'a dyn Fn() -> ozbox_core::Result<()>>,
    /// For a provider that never leaves a box without its machine: asks it what it would do for a record in the
    /// `instance_missing` state (the backend's `check_destroy_missing`). It must answer with a clean `Unsupported`.
    pub no_machine_probe: Option<&'a NoMachineProbe<'a>>,
    /// For a provider that cannot take a final snapshot of a box whose machine is gone (its snapshots are of the machine's
    /// own disk, and `/work` cannot be snapshotted): the plan must say so with `Unsupported` and a reason, instead of
    /// planning a snapshot that cannot be taken. The destroy without a snapshot is still checked.
    pub no_final_snapshot_without_machine: bool,
}

/// Asks a backend what it would do for a box record whose machine is missing.
pub type NoMachineProbe<'a> =
    dyn Fn(&ozbox_core::BoxRecord) -> ozbox_core::Result<Vec<String>> + 'a;

/// What the suite needs besides the provider itself.
pub struct Harness<'a> {
    pub provider: &'a dyn Provider,
    /// Put an existing box into a state (used to test that transitional states are refused). For a real
    /// provider's test double this flips the simulated machine's status.
    pub force_state: &'a dyn Fn(&BoxName, BoxState) -> ozbox_core::Result<()>,
    /// Secret values the provider was configured with (tokens). They must not appear in any error or record.
    pub secrets: Vec<String>,
    /// An image to create boxes from, for providers that require one.
    pub image: Option<String>,
    /// Present when the provider can upgrade a box to a new image (all of them in v0.x).
    pub upgrade: Option<UpgradeKit<'a>>,
}

fn name(s: &str) -> Result<BoxName, String> {
    BoxName::new(s).map_err(|e| e.to_string())
}

fn spec(h: &Harness<'_>, n: &str, size: Size) -> Result<BoxSpec, String> {
    let mut s = BoxSpec::new(name(n)?, size);
    s.image = h.image.clone();
    Ok(s)
}

fn plan(h: &Harness<'_>, op: &Operation) -> Result<Plan, Error> {
    h.provider.plan(op)
}

fn run(h: &Harness<'_>, op: &Operation) -> Result<Option<BoxRecord>, String> {
    let p = plan(h, op).map_err(|e| format!("planning {} failed: {e}", op.verb()))?;
    h.provider
        .apply(&p)
        .map_err(|e| format!("applying {} failed: {e}", op.verb()))
}

fn create(h: &Harness<'_>, n: &str, size: Size) -> Result<BoxRecord, String> {
    run(
        h,
        &Operation::Create {
            spec: spec(h, n, size)?,
        },
    )?
    .ok_or_else(|| format!("create of {n} returned no record"))
}

fn state_of(h: &Harness<'_>, n: &str) -> Result<BoxState, String> {
    h.provider
        .get(&name(n)?)
        .map_err(|e| e.to_string())?
        .map(|r| r.state)
        .ok_or_else(|| format!("{n} is missing"))
}

fn listing(h: &Harness<'_>) -> Result<String, String> {
    let l = h.provider.list().map_err(|e| e.to_string())?;
    serde_json::to_string(&l).map_err(|e| e.to_string())
}

fn ensure(cond: bool, msg: impl Into<String>) -> Check {
    if cond {
        Ok(())
    } else {
        Err(msg.into())
    }
}

/// Run every check.
pub fn run_all(h: &Harness<'_>) -> Check {
    plan_never_mutates(h)?;
    idempotence(h)?;
    unsupported_fails_at_plan(h)?;
    stale_plan_refused(h)?;
    transitional_state_refused(h)?;
    no_secret_in_errors_or_records(h)?;
    upgrade_contract(h)?;
    interrupted_create_is_recoverable(h)?;
    destroy_of_a_box_with_no_machine(h)?;
    snapshot_management(h)?;
    destroy_can_delete_its_snapshots(h)?;
    Ok(())
}

fn upgrade_op(n: &str, image: &str) -> Result<Operation, String> {
    Ok(Operation::Upgrade {
        name: name(n)?,
        image: image.to_string(),
        reprovision: false,
        keep_old_system_disk: false,
    })
}

fn record(h: &Harness<'_>, n: &str) -> Result<BoxRecord, String> {
    h.provider
        .get(&name(n)?)
        .map_err(|e| e.to_string())?
        .ok_or_else(|| format!("{n} is missing"))
}

/// Upgrade (replace the system disk, keep `/work`): planning is read-only, the same image is a no-op, `/work` and its
/// snapshots survive, a wrong-architecture image is refused while planning, a stale plan is refused, and an upgrade
/// interrupted after the stop is finished by running it again.
pub fn upgrade_contract(h: &Harness<'_>) -> Check {
    let Some(kit) = &h.upgrade else {
        return Ok(());
    };
    let n = name("conf-up")?;
    create(h, "conf-up", Size::S)?;
    run(h, &Operation::Snapshot { name: n.clone() })?;
    let before = record(h, "conf-up")?;
    let work_before = (kit.work_id)(&n).map_err(|e| e.to_string())?;

    // Planning changes nothing, and says what will happen.
    let listing_before = listing(h)?;
    let op = upgrade_op("conf-up", &kit.image)?;
    let p = plan(h, &op).map_err(|e| format!("planning an upgrade failed: {e}"))?;
    ensure(
        !p.is_noop(),
        "upgrading to a different image must plan changes",
    )?;
    ensure(
        p.changes.iter().any(|c| c.kind == "instance.replace_image"),
        "an upgrade plan must list the system-disk replacement",
    )?;
    ensure(
        p.changes.iter().all(|c| !c.description.contains("Delete")),
        "an upgrade plan must not delete anything",
    )?;
    ensure(
        listing(h)? == listing_before,
        "planning an upgrade changed state",
    )?;

    // A wrong-architecture image is refused while planning.
    if let Some(bad) = &kit.wrong_arch_image {
        match plan(h, &upgrade_op("conf-up", bad)?) {
            Err(Error::Unsupported { .. }) => {}
            other => {
                return Err(format!(
                "an image for another architecture must be Unsupported at plan time, got {other:?}"
            ))
            }
        }
        ensure(
            listing(h)? == listing_before,
            "a refused upgrade plan changed state",
        )?;
    }

    // A box that is not there.
    match plan(h, &upgrade_op("conf-up-missing", &kit.image)?) {
        Err(Error::NotFound(_)) => {}
        other => {
            return Err(format!(
                "upgrading a missing box must be NotFound, got {other:?}"
            ))
        }
    }

    // A stale plan is refused.
    let second = plan(h, &op).map_err(|e| e.to_string())?;
    let done = h
        .provider
        .apply(&p)
        .map_err(|e| format!("applying an upgrade failed: {e}"))?
        .ok_or("an upgrade returned no record")?;
    match h.provider.apply(&second) {
        Err(Error::StalePlan(_)) => {}
        other => {
            return Err(format!(
                "an upgrade plan applied after the box changed must be StalePlan, got {other:?}"
            ))
        }
    }

    // After: running, on the new image, /work untouched, nothing left marked.
    ensure(
        done.state == BoxState::Running,
        "an upgraded box must be running",
    )?;
    let after = record(h, "conf-up")?;
    ensure(
        after.spec.image.as_deref() == Some(kit.image.as_str()),
        "the box must report the image it was upgraded to",
    )?;
    ensure(
        (kit.work_id)(&n).map_err(|e| e.to_string())? == work_before,
        "an upgrade replaced the /work disk",
    )?;
    ensure(
        after.spec.work_disk_gb == before.spec.work_disk_gb && after.snapshots == before.snapshots,
        "an upgrade changed the /work disk size or its snapshots",
    )?;
    ensure(
        !after.spec.labels.contains_key(UPGRADE_TO_LABEL),
        "a finished upgrade must not leave its mark",
    )?;
    ensure(
        after.machine_type == before.machine_type && after.spec.size == before.spec.size,
        "an upgrade changed the size",
    )?;

    // The same image again is nothing to do.
    let again = plan(h, &op).map_err(|e| e.to_string())?;
    ensure(
        again.is_noop(),
        "upgrading to the image the box already runs must plan to nothing",
    )?;

    // Interrupted after the stop: running it again finishes the job.
    let r = name("conf-up-resume")?;
    create(h, "conf-up-resume", Size::S)?;
    let work_r = (kit.work_id)(&r).map_err(|e| e.to_string())?;
    (kit.interrupt)(&r, &kit.image).map_err(|e| e.to_string())?;
    ensure(
        state_of(h, "conf-up-resume")? == BoxState::Paused,
        "the interrupted box should be stopped",
    )?;
    let finish = plan(h, &upgrade_op("conf-up-resume", &kit.image)?).map_err(|e| e.to_string())?;
    ensure(
        !finish.is_noop(),
        "an interrupted upgrade must plan the rest of the job",
    )?;
    let finished = h
        .provider
        .apply(&finish)
        .map_err(|e| format!("finishing an interrupted upgrade failed: {e}"))?
        .ok_or("no record")?;
    ensure(
        finished.state == BoxState::Running
            && finished.spec.image.as_deref() == Some(kit.image.as_str())
            && !finished.spec.labels.contains_key(UPGRADE_TO_LABEL),
        "an interrupted upgrade, run again, must end running on the new image with no mark",
    )?;
    ensure(
        (kit.work_id)(&r).map_err(|e| e.to_string())? == work_r,
        "finishing an upgrade replaced the /work disk",
    )?;
    ensure(
        plan(h, &upgrade_op("conf-up-resume", &kit.image)?)
            .map_err(|e| e.to_string())?
            .is_noop(),
        "a finished upgrade must plan to nothing",
    )?;
    Ok(())
}

/// The old machine was removed and the new one could not be created. The box must still be listed, in a state that
/// says so, with its `/work` disk untouched; every operation but `upgrade` refuses it; `upgrade` plans only the
/// creation and the reattachment (never a delete or a replacement of `/work`) and finishes the job.
pub fn interrupted_create_is_recoverable(h: &Harness<'_>) -> Check {
    let Some(kit) = &h.upgrade else {
        return Ok(());
    };
    let Some(refuse_next_create) = kit.refuse_next_create else {
        return Ok(());
    };
    let n = name("conf-up-gap")?;
    create(h, "conf-up-gap", Size::S)?;
    let work = (kit.work_id)(&n).map_err(|e| e.to_string())?;
    let before = record(h, "conf-up-gap")?;
    refuse_next_create().map_err(|e| e.to_string())?;
    let op = upgrade_op("conf-up-gap", &kit.image)?;
    let p = plan(h, &op).map_err(|e| e.to_string())?;
    match h.provider.apply(&p) {
        Err(_) => {}
        Ok(_) => return Err("an upgrade whose new machine was refused must fail".into()),
    }

    // Still listed, and plainly so.
    let stuck = record(h, "conf-up-gap")?;
    ensure(
        stuck.state == BoxState::InstanceMissing,
        format!(
            "a box whose machine is gone must be listed as instance missing, not {}",
            stuck.state
        ),
    )?;
    ensure(
        stuck.spec.labels.get(UPGRADE_TO_LABEL).map(String::as_str) == Some(kit.image.as_str()),
        "the interrupted upgrade must still be marked with its image",
    )?;
    ensure(
        (kit.work_id)(&n).map_err(|e| e.to_string())? == work,
        "a refused machine replaced or lost the /work disk",
    )?;
    ensure(
        stuck.spec.work_disk_gb == before.spec.work_disk_gb
            && stuck.machine_type == before.machine_type
            && stuck.spec.size == before.spec.size,
        "the stranded box must keep its disk size and machine type",
    )?;

    // Nothing but `upgrade` acts on it.
    let n_ref = n.clone();
    for refused in [
        Operation::Pause {
            name: n_ref.clone(),
        },
        Operation::Resume {
            name: n_ref.clone(),
        },
        Operation::Snapshot {
            name: n_ref.clone(),
        },
        Operation::Resize {
            name: n_ref.clone(),
            size: Some(Size::M),
            work_disk_gb: None,
        },
    ] {
        match plan(h, &refused) {
            Err(Error::InvalidState { .. }) => {}
            other => {
                return Err(format!(
                    "{} on a box with no machine must be InvalidState, got {other:?}",
                    refused.verb()
                ))
            }
        }
    }

    // Finishing: planning is pure; the plan creates and reattaches and never deletes or replaces anything.
    let listing_before = listing(h)?;
    let finish = plan(h, &op).map_err(|e| format!("planning the finish failed: {e}"))?;
    ensure(
        listing(h)? == listing_before,
        "planning the finish of an upgrade changed state",
    )?;
    let kinds: Vec<&str> = finish.changes.iter().map(|c| c.kind.as_str()).collect();
    ensure(
        kinds.contains(&"instance.create") && kinds.contains(&"volume.reattach"),
        format!("finishing must create the machine and reattach /work, got {kinds:?}"),
    )?;
    ensure(
        finish.changes.iter().all(|c| {
            !c.kind.contains("delete")
                && !c.kind.contains("replace")
                && !c.description.contains("Delete")
        }),
        "finishing an interrupted upgrade must not delete or replace anything",
    )?;
    ensure(
        finish.max_risk() != Some(ozbox_core::Risk::High),
        "finishing an interrupted upgrade must not be a high-risk change",
    )?;

    let done = h
        .provider
        .apply(&finish)
        .map_err(|e| format!("finishing the interrupted upgrade failed: {e}"))?
        .ok_or("no record")?;
    ensure(
        done.state == BoxState::Running
            && done.spec.image.as_deref() == Some(kit.image.as_str())
            && !done.spec.labels.contains_key(UPGRADE_TO_LABEL),
        "a finished upgrade must run on the new image with no mark",
    )?;
    ensure(
        (kit.work_id)(&n).map_err(|e| e.to_string())? == work,
        "finishing the upgrade replaced the /work disk",
    )?;
    ensure(
        plan(h, &op).map_err(|e| e.to_string())?.is_noop(),
        "a finished upgrade must plan to nothing",
    )?;
    Ok(())
}

/// A provider that rebuilds machines in place cannot be put in the `instance_missing` state. Given a record that says
/// so anyway, it must answer with `Unsupported` and a reason a person can read: no panic, no half-made plan.
fn a_provider_without_a_gap_refuses_cleanly(h: &Harness<'_>, kit: &UpgradeKit<'_>) -> Check {
    let Some(probe) = kit.no_machine_probe else {
        return Ok(());
    };
    create(h, "conf-nogap", Size::S)?;
    let mut rec = record(h, "conf-nogap")?;
    rec.state = BoxState::InstanceMissing;
    match probe(&rec) {
        Err(Error::Unsupported { why, .. }) => {
            ensure(!why.trim().is_empty(), "the refusal must say why in words")
        }
        Err(e) => Err(format!("expected Unsupported, got: {e}")),
        Ok(_) => Err("a provider that never loses a machine accepted a missing one".into()),
    }
}

/// A box whose machine is gone can still be destroyed, by the ordinary plan-then-apply rules: it is high risk, says it
/// deletes `/work`, offers the final snapshot, and afterwards the box is not listed.
pub fn destroy_of_a_box_with_no_machine(h: &Harness<'_>) -> Check {
    let Some(kit) = &h.upgrade else {
        return Ok(());
    };
    let Some(refuse_next_create) = kit.refuse_next_create else {
        return a_provider_without_a_gap_refuses_cleanly(h, kit);
    };
    for (label, snapshot) in [("conf-gap-destroy", false), ("conf-gap-snap", true)] {
        let n = name(label)?;
        create(h, label, Size::S)?;
        refuse_next_create().map_err(|e| e.to_string())?;
        let up = plan(h, &upgrade_op(label, &kit.image)?).map_err(|e| e.to_string())?;
        ensure(
            h.provider.apply(&up).is_err(),
            "an upgrade whose new machine was refused must fail",
        )?;
        ensure(
            record(h, label)?.state == BoxState::InstanceMissing,
            "the box must be listed as instance missing",
        )?;
        let op = Operation::Destroy {
            name: n.clone(),
            final_snapshot: snapshot,
            keep_old_system_disks: false,
            delete_snapshots: false,
        };
        if snapshot && kit.no_final_snapshot_without_machine {
            match plan(h, &op) {
                Err(Error::Unsupported { why, .. }) => {
                    ensure(!why.trim().is_empty(), "the refusal must say why in words")?;
                    continue;
                }
                other => {
                    return Err(format!(
                        "a final snapshot of a box with no machine must be refused as Unsupported here, got {other:?}"
                    ))
                }
            }
        }
        let before = listing(h)?;
        let p = plan(h, &op)
            .map_err(|e| format!("destroy of a box with no machine was refused: {e}"))?;
        ensure(listing(h)? == before, "planning the destroy changed state")?;
        ensure(
            p.max_risk() == Some(ozbox_core::Risk::High),
            "destroying a box with no machine is high risk",
        )?;
        ensure(
            p.changes
                .iter()
                .any(|c| c.kind == "box.delete" && c.description.contains("/work")),
            "the plan must say it deletes the /work volume",
        )?;
        ensure(
            p.changes.iter().any(|c| c.kind == "snapshot.create") == snapshot,
            "the final snapshot is in the plan exactly when asked for",
        )?;
        ensure(
            snapshot || p.notes.iter().any(|x| x.contains("final snapshot")),
            "without a final snapshot the plan must say /work is lost",
        )?;
        h.provider
            .apply(&p)
            .map_err(|e| format!("destroying a box with no machine failed: {e}"))?;
        ensure(
            h.provider.get(&n).map_err(|e| e.to_string())?.is_none(),
            "a destroyed box must not be listed",
        )?;
    }
    Ok(())
}

/// Contract 1: planning changes nothing, for every operation.
pub fn plan_never_mutates(h: &Harness<'_>) -> Check {
    create(h, "conf-plan", Size::S)?;
    let before = listing(h)?;
    let ops = [
        Operation::Create {
            spec: spec(h, "conf-plan-new", Size::M)?,
        },
        Operation::Pause {
            name: name("conf-plan")?,
        },
        Operation::Resume {
            name: name("conf-plan")?,
        },
        Operation::Resize {
            name: name("conf-plan")?,
            size: Some(Size::M),
            work_disk_gb: Some(300),
        },
        Operation::Snapshot {
            name: name("conf-plan")?,
        },
        Operation::Upgrade {
            name: name("conf-plan")?,
            image: h
                .upgrade
                .as_ref()
                .map_or_else(|| "conformance-image".to_string(), |k| k.image.clone()),
            reprovision: false,
            keep_old_system_disk: false,
        },
        Operation::Clone {
            from: name("conf-plan")?,
            to: name("conf-plan-copy")?,
            snapshot: None,
        },
        Operation::Destroy {
            name: name("conf-plan")?,
            final_snapshot: true,
            keep_old_system_disks: false,
            delete_snapshots: false,
        },
    ];
    for op in &ops {
        match plan(h, op) {
            Ok(_) => {}
            // A provider may not be able to clone (no restore from snapshot); that is allowed, but only here.
            Err(Error::Unsupported { .. }) if matches!(op, Operation::Clone { .. }) => {}
            Err(e) => return Err(format!("planning {} failed: {e}", op.verb())),
        }
        ensure(
            listing(h)? == before,
            format!("planning {} changed the provider's state", op.verb()),
        )?;
    }
    Ok(())
}

/// Contract 2: an already-satisfied request plans to nothing, and applying that plan changes nothing.
pub fn idempotence(h: &Harness<'_>) -> Check {
    create(h, "conf-idem", Size::S)?;
    let n = name("conf-idem")?;

    run(h, &Operation::Pause { name: n.clone() })?;
    let again = plan(h, &Operation::Pause { name: n.clone() }).map_err(|e| e.to_string())?;
    ensure(again.is_noop(), "pausing a paused box must plan to nothing")?;
    let before = listing(h)?;
    h.provider
        .apply(&again)
        .map_err(|e| format!("applying a no-op plan failed: {e}"))?;
    ensure(listing(h)? == before, "applying a no-op plan changed state")?;

    run(h, &Operation::Resume { name: n.clone() })?;
    let again = plan(h, &Operation::Resume { name: n.clone() }).map_err(|e| e.to_string())?;
    ensure(
        again.is_noop(),
        "resuming a running box must plan to nothing",
    )?;

    // Create of an existing box: same size and disk is a no-op; a different one is a conflict.
    let same = plan(
        h,
        &Operation::Create {
            spec: spec(h, "conf-idem", Size::S)?,
        },
    )
    .map_err(|e| e.to_string())?;
    ensure(
        same.is_noop(),
        "creating the box that already exists must plan to nothing",
    )?;
    match plan(
        h,
        &Operation::Create {
            spec: spec(h, "conf-idem", Size::XL)?,
        },
    ) {
        Err(Error::AlreadyExists(_)) => {}
        other => {
            return Err(format!(
            "creating a different box under an existing name must be AlreadyExists, got {other:?}"
        ))
        }
    }

    // Resizing to the size it already is.
    let same = plan(
        h,
        &Operation::Resize {
            name: n.clone(),
            size: Some(Size::S),
            work_disk_gb: None,
        },
    )
    .map_err(|e| e.to_string())?;
    ensure(
        same.is_noop(),
        "resizing to the current size must plan to nothing",
    )?;

    // Destroying a box that is not there.
    let gone = plan(
        h,
        &Operation::Destroy {
            name: name("conf-never-existed")?,
            final_snapshot: true,
            keep_old_system_disks: false,
            delete_snapshots: false,
        },
    )
    .map_err(|e| e.to_string())?;
    ensure(
        gone.is_noop(),
        "destroying a missing box must plan to nothing",
    )?;
    Ok(())
}

/// Contract 3: what the provider cannot do fails while planning, and nothing changed.
pub fn unsupported_fails_at_plan(h: &Harness<'_>) -> Check {
    create(h, "conf-unsup", Size::S)?;
    let before = listing(h)?;
    match plan(
        h,
        &Operation::Resize {
            name: name("conf-unsup")?,
            size: None,
            work_disk_gb: Some(50),
        },
    ) {
        Err(Error::Unsupported { .. }) => {}
        other => {
            return Err(format!(
                "shrinking the disk must be Unsupported at plan time, got {other:?}"
            ))
        }
    }
    ensure(listing(h)? == before, "a refused plan changed state")?;
    ensure(
        !h.provider.capabilities().disk_shrink,
        "no provider supports disk shrink in v0.1",
    )?;
    Ok(())
}

/// Contract 4: a plan made before the box changed is refused.
pub fn stale_plan_refused(h: &Harness<'_>) -> Check {
    create(h, "conf-stale", Size::S)?;
    let n = name("conf-stale")?;
    let old = plan(h, &Operation::Pause { name: n.clone() }).map_err(|e| e.to_string())?;
    let newer = plan(h, &Operation::Pause { name: n.clone() }).map_err(|e| e.to_string())?;
    h.provider
        .apply(&newer)
        .map_err(|e| format!("applying a fresh plan failed: {e}"))?;
    match h.provider.apply(&old) {
        Err(Error::StalePlan(_)) => {}
        other => {
            return Err(format!(
                "a stale plan must be refused with StalePlan, got {other:?}"
            ))
        }
    }
    ensure(
        state_of(h, "conf-stale")? == BoxState::Paused,
        "a stale plan changed the box",
    )?;

    // A plan for a box that did not exist, applied after it was created by someone else.
    let create_op = Operation::Create {
        spec: spec(h, "conf-stale-2", Size::S)?,
    };
    let first = plan(h, &create_op).map_err(|e| e.to_string())?;
    let second = plan(h, &create_op).map_err(|e| e.to_string())?;
    h.provider.apply(&first).map_err(|e| e.to_string())?;
    match h.provider.apply(&second) {
        Err(Error::StalePlan(_)) => Ok(()),
        other => Err(format!(
            "a create plan applied twice must be StalePlan, got {other:?}"
        )),
    }
}

/// Contract 5: a mutating operation on a box in a transitional state is refused.
pub fn transitional_state_refused(h: &Harness<'_>) -> Check {
    create(h, "conf-trans", Size::S)?;
    let n = name("conf-trans")?;
    (h.force_state)(&n, BoxState::Pausing).map_err(|e| e.to_string())?;
    let ops = [
        Operation::Pause { name: n.clone() },
        Operation::Resume { name: n.clone() },
        Operation::Resize {
            name: n.clone(),
            size: Some(Size::M),
            work_disk_gb: None,
        },
        Operation::Snapshot { name: n.clone() },
        Operation::Clone {
            from: n.clone(),
            to: name("conf-trans-copy")?,
            snapshot: None,
        },
        Operation::Destroy {
            name: n.clone(),
            final_snapshot: true,
            keep_old_system_disks: false,
            delete_snapshots: false,
        },
        Operation::Upgrade {
            name: n.clone(),
            image: h
                .upgrade
                .as_ref()
                .map_or_else(|| "conformance-image".to_string(), |k| k.image.clone()),
            reprovision: false,
            keep_old_system_disk: false,
        },
    ];
    for op in &ops {
        match plan(h, op) {
            Err(Error::InvalidState { .. }) => {}
            other => {
                return Err(format!(
                    "{} on a box in a transitional state must be InvalidState, got {other:?}",
                    op.verb()
                ))
            }
        }
    }
    Ok(())
}

/// Contract 6: no secret value appears in an error, a plan or a record.
pub fn no_secret_in_errors_or_records(h: &Harness<'_>) -> Check {
    create(h, "conf-secret", Size::S)?;
    let mut seen: Vec<String> = Vec::new();
    for r in h.provider.list().map_err(|e| e.to_string())? {
        seen.push(serde_json::to_string(&r).map_err(|e| e.to_string())?);
        seen.push(format!("{r:?}"));
    }
    let n = name("conf-secret")?;
    let missing = name("conf-secret-missing")?;
    let failing = [
        Operation::Pause {
            name: missing.clone(),
        },
        Operation::Snapshot { name: missing },
        Operation::Create {
            spec: spec(h, "conf-secret", Size::XL)?,
        },
        Operation::Resize {
            name: n.clone(),
            size: None,
            work_disk_gb: Some(40),
        },
        Operation::Resize {
            name: n.clone(),
            size: None,
            work_disk_gb: None,
        },
    ];
    for op in &failing {
        if let Err(e) = plan(h, op) {
            seen.push(e.to_string());
            seen.push(format!("{e:?}"));
        }
    }
    let p = plan(
        h,
        &Operation::Resize {
            name: n,
            size: Some(Size::M),
            work_disk_gb: None,
        },
    )
    .map_err(|e| e.to_string())?;
    seen.push(serde_json::to_string(&p).map_err(|e| e.to_string())?);
    for text in &seen {
        for secret in &h.secrets {
            ensure(
                !secret.is_empty() && !text.contains(secret.as_str()),
                "a secret value appeared in an error, plan or record",
            )?;
        }
    }
    Ok(())
}

/// Snapshots are listed with what is known about each, deleted only by a high-risk plan that a repeat turns into
/// nothing, and a restore of `/work` is either planned as high risk with the way back made first, or refused cleanly.
pub fn snapshot_management(h: &Harness<'_>) -> Check {
    let n = name("conf-snaps")?;
    create(h, "conf-snaps", Size::S)?;
    run(h, &Operation::Snapshot { name: n.clone() })?;
    run(h, &Operation::Snapshot { name: n.clone() })?;
    let rec = record(h, "conf-snaps")?;
    let listed = match h.provider.snapshots(&n) {
        Ok(l) => l,
        // A provider may be unable to list snapshots; then it must say so rather than list nothing.
        Err(Error::Unsupported { .. }) => return Ok(()),
        Err(e) => return Err(format!("listing snapshots failed: {e}")),
    };
    ensure(
        listed.len() == rec.snapshots.len() && listed.len() == 2,
        "the list must show exactly the snapshots the record carries",
    )?;
    ensure(
        listed.iter().zip(&rec.snapshots).all(|(a, b)| &a.id == b),
        "the list must be oldest first and match the record's ids",
    )?;
    ensure(
        listed.iter().all(|s| s.status == "completed"),
        "a snapshot the apply waited for is finished",
    )?;
    let before = listing(h)?;

    // A restore of /work: high risk with the current state snapshotted first, or a clean refusal.
    let first = listed[0].id.clone();
    let restore = Operation::RestoreWork {
        name: n.clone(),
        snapshot: first.clone(),
    };
    match plan(h, &restore) {
        Ok(p) => {
            ensure(listing(h)? == before, "planning a restore changed state")?;
            ensure(
                p.max_risk() == Some(ozbox_core::Risk::High),
                "replacing /work is high risk",
            )?;
            ensure(
                p.changes.first().map(|c| c.kind.as_str()) == Some("snapshot.create"),
                "the current state is snapshotted before /work is replaced",
            )?;
            h.provider
                .apply(&p)
                .map_err(|e| format!("restoring /work failed: {e}"))?;
            let after = record(h, "conf-snaps")?;
            ensure(
                after.snapshots.len() == 3,
                "a restore keeps the old snapshots and adds the one it took first",
            )?;
            ensure(
                after.state == rec.state,
                "a restore leaves the box as it found it (running stays running)",
            )?;
            old_work_disks_are_kept_until_deleted(h, &n)?;
        }
        Err(Error::Unsupported { why, .. }) => {
            ensure(!why.trim().is_empty(), "a refused restore says why")?;
        }
        Err(e) => return Err(format!("planning a restore failed: {e}")),
    }
    // A snapshot that does not exist is not restorable.
    let ghost = Operation::RestoreWork {
        name: n.clone(),
        snapshot: "no-such-snapshot".into(),
    };
    ensure(
        plan(h, &ghost).is_err(),
        "restoring a snapshot that does not exist must be refused",
    )?;

    // Delete: planning is read-only and high risk, applying removes exactly that snapshot, and a repeat is nothing.
    let rec = record(h, "conf-snaps")?;
    let victim = rec.snapshots[0].clone();
    let keep: Vec<String> = rec.snapshots[1..].to_vec();
    let del = Operation::DeleteSnapshot {
        name: n.clone(),
        snapshot: victim.clone(),
    };
    let before = listing(h)?;
    let p = match plan(h, &del) {
        Ok(p) => p,
        Err(Error::Unsupported { .. }) => return Ok(()),
        Err(e) => return Err(format!("planning a snapshot delete failed: {e}")),
    };
    ensure(listing(h)? == before, "planning a delete changed state")?;
    ensure(
        p.max_risk() == Some(ozbox_core::Risk::High),
        "deleting a snapshot cannot be undone",
    )?;
    h.provider
        .apply(&p)
        .map_err(|e| format!("deleting a snapshot failed: {e}"))?;
    let after = record(h, "conf-snaps")?;
    ensure(
        after.snapshots == keep,
        "only the named snapshot is deleted",
    )?;
    ensure(
        plan(h, &del).map_err(|e| e.to_string())?.is_noop(),
        "deleting it again plans to nothing",
    )?;
    Ok(())
}

/// `destroy --delete-snapshots` (opt-in): without it the plan carries no snapshot deletion; with it the plan names every snapshot
/// of THAT box in one high-risk change, planning changes nothing, applying removes the box and leaves another box's snapshots
/// alone, and a snapshot another box was cloned from is refused while planning. A provider that cannot says `Unsupported`.
fn destroy_can_delete_its_snapshots(h: &Harness<'_>) -> Check {
    let (a, b) = (name("conf-dsn-a")?, name("conf-dsn-b")?);
    create(h, "conf-dsn-a", Size::S)?;
    create(h, "conf-dsn-b", Size::S)?;
    for n in [&a, &b] {
        run(h, &Operation::Snapshot { name: n.clone() })?;
    }
    let destroy = |delete: bool| Operation::Destroy {
        name: a.clone(),
        final_snapshot: false,
        keep_old_system_disks: false,
        delete_snapshots: delete,
    };
    let kept = plan(h, &destroy(false)).map_err(|e| e.to_string())?;
    ensure(
        kept.changes.iter().all(|c| c.kind != "snapshot.delete"),
        "by default a destroy deletes no snapshot",
    )?;
    let mine: Vec<String> = record(h, "conf-dsn-a")?.snapshots;
    let theirs = record(h, "conf-dsn-b")?.snapshots;
    let before = listing(h)?;
    let p = match plan(h, &destroy(true)) {
        Ok(p) => p,
        Err(Error::Unsupported { why, .. }) => {
            return ensure(!why.trim().is_empty(), "a refusal says why");
        }
        Err(e) => return Err(format!("planning destroy --delete-snapshots failed: {e}")),
    };
    ensure(
        listing(h)? == before,
        "planning changed the provider's state",
    )?;
    ensure(
        p.max_risk() == Some(ozbox_core::Risk::High),
        "destroying is high risk",
    )?;
    let del = p
        .changes
        .iter()
        .find(|c| c.kind == "snapshot.delete")
        .ok_or("the plan must list the snapshot deletion")?;
    ensure(
        mine.iter().all(|id| del.description.contains(id.as_str()))
            && theirs
                .iter()
                .all(|id| !del.description.contains(id.as_str())),
        "the plan names exactly this box's snapshots",
    )?;
    h.provider
        .apply(&p)
        .map_err(|e| format!("destroying with its snapshots failed: {e}"))?;
    ensure(
        h.provider.get(&a).map_err(|e| e.to_string())?.is_none(),
        "the box is gone",
    )?;
    ensure(
        record(h, "conf-dsn-b")?.snapshots == theirs,
        "another box's snapshots are not touched",
    )
}

/// A restore that replaced the disk keeps the old one: it is listed, deleting it is a high-risk plan that touches only
/// that disk, and a repeat is nothing. A provider that keeps none lists none.
fn old_work_disks_are_kept_until_deleted(
    h: &Harness,
    n: &BoxName,
) -> std::result::Result<(), String> {
    let kept = h
        .provider
        .old_work_disks(n)
        .map_err(|e| format!("listing old /work disks failed: {e}"))?;
    let Some(first) = kept.first() else {
        return Ok(());
    };
    ensure(
        kept.iter().all(|d| d.state == "kept"),
        "a finished restore leaves only finished old disks",
    )?;
    let ghost = Operation::DeleteOldWork {
        name: n.clone(),
        volume: "not-a-disk-of-this-box".into(),
    };
    ensure(
        plan(h, &ghost).map_err(|e| e.to_string())?.is_noop(),
        "deleting an id that is not an old disk of this box plans to nothing",
    )?;
    let del = Operation::DeleteOldWork {
        name: n.clone(),
        volume: first.id.clone(),
    };
    let before = listing(h)?;
    let p = plan(h, &del).map_err(|e| format!("planning an old-disk delete failed: {e}"))?;
    ensure(
        listing(h)? == before,
        "planning an old-disk delete changed state",
    )?;
    ensure(
        p.max_risk() == Some(ozbox_core::Risk::High),
        "deleting an old /work disk cannot be undone",
    )?;
    h.provider
        .apply(&p)
        .map_err(|e| format!("deleting an old disk failed: {e}"))?;
    let after = h.provider.old_work_disks(n).map_err(|e| e.to_string())?;
    ensure(
        after.len() + 1 == kept.len() && after.iter().all(|d| d.id != first.id),
        "only the named old disk is deleted",
    )?;
    ensure(
        plan(h, &del).map_err(|e| e.to_string())?.is_noop(),
        "deleting it again plans to nothing",
    )?;
    Ok(())
}
