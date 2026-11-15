use std::collections::BTreeMap;
use std::fmt;

use serde::{Deserialize, Serialize};

use crate::{BoxName, Size};

/// Disk size in gigabytes.
pub type DiskGb = u32;

/// What a person asks for. Desired state: providers reconcile toward it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BoxSpec {
    pub name: BoxName,
    pub size: Size,
    /// The persistent `/work` disk. It survives pause, resize, upgrade and image rebuilds.
    pub work_disk_gb: DiskGb,
    /// The image release the root disk is built from (e.g. `2026.11.0`). `None` = the provider's latest.
    pub image: Option<String>,
    /// Provider region or location (e.g. `us-east-1`, `fsn1`). `None` = the provider's configured default.
    pub region: Option<String>,
    /// Restore `/work` from this snapshot instead of starting empty (used by clone).
    pub from_snapshot: Option<String>,
    /// Free-form labels: purpose, owner, project. Used by the scheduler and shown by `ozbox list`.
    pub labels: BTreeMap<String, String>,
}

impl BoxSpec {
    pub const DEFAULT_WORK_DISK_GB: DiskGb = 200;
    pub const MIN_WORK_DISK_GB: DiskGb = 20;

    pub fn new(name: BoxName, size: Size) -> Self {
        Self {
            name,
            size,
            work_disk_gb: Self::DEFAULT_WORK_DISK_GB,
            image: None,
            region: None,
            from_snapshot: None,
            labels: BTreeMap::new(),
        }
    }
}

/// Where a box is in its lifecycle.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BoxState {
    Creating,
    Running,
    Pausing,
    /// Stopped: the person pays only for storage.
    Paused,
    Resuming,
    Resizing,
    Destroying,
    /// The machine is gone but `/work` and everything needed to rebuild the machine are kept: an upgrade was
    /// interrupted after the old machine was removed and before the new one came up (typically a quota or capacity
    /// refusal in between). Only `upgrade` acts on it: it creates the machine from the marked image and reattaches
    /// `/work`. Nothing is running, so nothing is billed for compute.
    InstanceMissing,
    /// The provider reported something Oz Box does not understand. Never acted on automatically.
    Unknown,
}

impl BoxState {
    /// States in which a mutating command may start. Transitional states block, so two commands never race.
    pub fn is_settled(self) -> bool {
        matches!(self, BoxState::Running | BoxState::Paused)
    }
}

impl fmt::Display for BoxState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            BoxState::Creating => "creating",
            BoxState::Running => "running",
            BoxState::Pausing => "pausing",
            BoxState::Paused => "paused",
            BoxState::Resuming => "resuming",
            BoxState::Resizing => "resizing",
            BoxState::Destroying => "destroying",
            BoxState::InstanceMissing => "instance missing",
            BoxState::Unknown => "unknown",
        };
        f.write_str(s)
    }
}

/// What a provider reports about a box that exists.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BoxRecord {
    pub spec: BoxSpec,
    pub state: BoxState,
    pub provider: String,
    /// The provider's own id for the machine (instance id, server id). Opaque to everything above the adapter.
    pub provider_id: Option<String>,
    /// The provider's machine type the size was mapped to (e.g. `m7i.4xlarge`, `ccx43`).
    pub machine_type: Option<String>,
    /// Snapshot ids of `/work`, oldest first.
    pub snapshots: Vec<String>,
    /// RFC 3339 timestamps, as reported by the provider.
    pub created_at: Option<String>,
    pub last_activity_at: Option<String>,
}
