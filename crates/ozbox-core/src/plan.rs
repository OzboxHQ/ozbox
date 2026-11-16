use std::fmt;

use serde::{Deserialize, Serialize};

use crate::{BoxName, BoxSpec, DiskGb, Size};

/// What a person asked for. A provider turns an operation into a [`Plan`] without changing anything.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "op", rename_all = "snake_case")]
pub enum Operation {
    Create {
        spec: BoxSpec,
    },
    Pause {
        name: BoxName,
    },
    Resume {
        name: BoxName,
    },
    Resize {
        name: BoxName,
        size: Option<Size>,
        work_disk_gb: Option<DiskGb>,
    },
    Snapshot {
        name: BoxName,
    },
    Clone {
        from: BoxName,
        to: BoxName,
        /// Restore `/work` from this snapshot of `from` instead of its newest one. Additive: absent means the newest.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        snapshot: Option<String>,
    },
    /// Delete one snapshot of a box's `/work` (the box and its other snapshots stay).
    DeleteSnapshot {
        name: BoxName,
        snapshot: String,
    },
    /// Delete the old `/work` disk a restore kept (detached, tagged, still costing storage). Only ever a disk a restore
    /// of this box retired.
    DeleteOldWork {
        name: BoxName,
        volume: String,
    },
    /// Replace the `/work` disk of a box with the contents of one of its provider snapshots. The current state is
    /// snapshotted first.
    RestoreWork {
        name: BoxName,
        snapshot: String,
    },
    /// Back up `/work` into the restic repository through the box's agent. Not something a provider does itself:
    /// the server plans and applies it.
    ResticBackup {
        name: BoxName,
    },
    /// Forget one snapshot in the restic repository and prune what only it held.
    ResticForget {
        name: BoxName,
        snapshot: String,
    },
    /// Restore a restic snapshot through the box's agent: into a folder beside the box's files, or (`in_place`) over
    /// `/work` itself. `from_box` names the box the snapshot was taken from when it is not this one.
    ResticRestore {
        name: BoxName,
        snapshot: String,
        in_place: bool,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        from_box: Option<BoxName>,
    },
    /// Restore a repository (restic) backup of `from` into a NEW box `to`: create it, wait for its agent, hand it the
    /// repository credentials, restore over its empty `/work` and check it. One plan; planned and followed by the
    /// server or the command, never by a provider.
    RestoreToNewBox {
        from: BoxName,
        to: BoxName,
        snapshot: String,
    },
    Destroy {
        name: BoxName,
        /// Keep a final snapshot of `/work` (default true; the CLI's `--no-final-snapshot` turns it off).
        final_snapshot: bool,
    },
    /// Replace the system disk from a newer image and keep `/work`. `image` is always a concrete image id: the
    /// words `latest` are resolved by the caller before the operation is built, so a plan stays reproducible.
    Upgrade {
        name: BoxName,
        image: String,
        /// Replace the machine even when the box is already on `image`: its first boot was rendered from another
        /// first-boot configuration (made by an older program, or from a stale copy of the modules). `/work` is kept as in
        /// any upgrade. Additive: absent means false.
        #[serde(default, skip_serializing_if = "std::ops::Not::not")]
        reprovision: bool,
        /// Keep a copy of the OLD system disk before it is replaced (an encrypted snapshot the provider tags, named in the
        /// plan and the report), so a store key that lived only on that disk can still be read afterwards. Asked for when the
        /// plan cannot show that the store's key survives. It is part of the operation so the plan lists the step and `apply`
        /// compares it. Additive: absent means false.
        #[serde(default, skip_serializing_if = "std::ops::Not::not")]
        keep_old_system_disk: bool,
    },
}

impl Operation {
    pub fn box_name(&self) -> &BoxName {
        match self {
            Operation::Create { spec } => &spec.name,
            Operation::Pause { name }
            | Operation::Resume { name }
            | Operation::Resize { name, .. }
            | Operation::Snapshot { name }
            | Operation::Upgrade { name, .. }
            | Operation::DeleteSnapshot { name, .. }
            | Operation::DeleteOldWork { name, .. }
            | Operation::RestoreWork { name, .. }
            | Operation::ResticBackup { name }
            | Operation::ResticForget { name, .. }
            | Operation::ResticRestore { name, .. }
            | Operation::Destroy { name, .. } => name,
            Operation::Clone { to, .. } | Operation::RestoreToNewBox { to, .. } => to,
        }
    }

    pub fn verb(&self) -> &'static str {
        match self {
            Operation::Create { .. } => "create",
            Operation::Pause { .. } => "pause",
            Operation::Resume { .. } => "resume",
            Operation::Resize { .. } => "resize",
            Operation::Snapshot { .. } => "snapshot",
            Operation::Clone { .. } => "clone",
            Operation::RestoreToNewBox { .. } => "restore a backup into the new box",
            Operation::Destroy { .. } => "destroy",
            Operation::Upgrade { .. } => "upgrade",
            Operation::DeleteSnapshot { .. } => "delete the snapshot of",
            Operation::DeleteOldWork { .. } => "delete the old /work disk of",
            Operation::RestoreWork { .. } => "restore /work of",
            Operation::ResticBackup { .. } => "back up",
            Operation::ResticForget { .. } => "delete a backup of",
            Operation::ResticRestore { .. } => "restore a backup into",
        }
    }
}

/// How much a change matters, so the CLI can ask for confirmation proportionately.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Risk {
    /// Reversible and cheap (start, stop, snapshot).
    Low,
    /// Costs money or interrupts work (create, resize, a restart).
    Medium,
    /// Loses data or cannot be undone (destroy, delete a snapshot).
    High,
}

/// One concrete step. Every change a provider will make appears here, in order, before it is made.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Change {
    /// A short machine-friendly kind, e.g. `instance.stop`, `volume.grow`, `snapshot.create`.
    pub kind: String,
    /// What a person reads, e.g. "Stop the machine (work is checkpointed first)".
    pub description: String,
    pub risk: Risk,
}

impl Change {
    pub fn new(kind: impl Into<String>, description: impl Into<String>, risk: Risk) -> Self {
        Self {
            kind: kind.into(),
            description: description.into(),
            risk,
        }
    }
}

/// The result of planning. An empty plan means "already done" — applying it changes nothing.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Plan {
    pub operation: Operation,
    pub provider: String,
    pub changes: Vec<Change>,
    /// Things the person should know that are not changes (e.g. "the disk cannot shrink on this provider").
    pub notes: Vec<String>,
    /// A fingerprint of the state the plan was computed from. `apply` refuses if the state moved since.
    pub based_on: String,
}

impl Plan {
    pub fn is_noop(&self) -> bool {
        self.changes.is_empty()
    }

    pub fn max_risk(&self) -> Option<Risk> {
        self.changes.iter().map(|c| c.risk).max()
    }
}

impl fmt::Display for Plan {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let name = self.operation.box_name();
        if self.is_noop() {
            writeln!(
                f,
                "Nothing to do: {} {name} is already in the requested state.",
                self.operation.verb()
            )?;
        } else {
            writeln!(
                f,
                "Plan to {} {name} on {} ({} change{}):",
                self.operation.verb(),
                self.provider,
                self.changes.len(),
                if self.changes.len() == 1 { "" } else { "s" }
            )?;
            for (i, c) in self.changes.iter().enumerate() {
                let tag = match c.risk {
                    Risk::Low => "",
                    Risk::Medium => " [costs or interrupts]",
                    Risk::High => " [CANNOT BE UNDONE]",
                };
                writeln!(f, "  {}. {}{tag}", i + 1, c.description)?;
            }
        }
        for n in &self.notes {
            writeln!(f, "  note: {n}")?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn name() -> BoxName {
        match BoxName::new("main") {
            Ok(n) => n,
            Err(e) => panic!("{e}"),
        }
    }

    #[test]
    fn an_empty_plan_says_nothing_to_do() {
        let p = Plan {
            operation: Operation::Pause { name: name() },
            provider: "fake".into(),
            changes: vec![],
            notes: vec![],
            based_on: "x".into(),
        };
        assert!(p.is_noop());
        assert!(p.to_string().starts_with("Nothing to do"));
    }

    #[test]
    fn destructive_changes_are_flagged() {
        let p = Plan {
            operation: Operation::Destroy {
                name: name(),
                final_snapshot: false,
            },
            provider: "fake".into(),
            changes: vec![Change::new(
                "box.delete",
                "Delete the box and its work disk",
                Risk::High,
            )],
            notes: vec![],
            based_on: "x".into(),
        };
        assert_eq!(p.max_risk(), Some(Risk::High));
        assert!(p.to_string().contains("CANNOT BE UNDONE"));
    }
}
