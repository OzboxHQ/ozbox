use serde::{Deserialize, Serialize};

use crate::{BoxName, BoxRecord, Error, Operation, Plan, Result, Size};

/// How a provider changes a machine's size.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ResizeMethod {
    /// Stop, change the type, start (AWS, GCP).
    StopChangeStart,
    /// Power off and resize (most VPS hosts).
    PowerOffResize,
    /// In place when the provider allows it, otherwise stop and redeploy (Azure).
    InPlaceOrRedeploy,
}

/// An image a box can be built from or upgraded to.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ImageInfo {
    /// The provider's id for it (an AMI id, a snapshot id).
    pub id: String,
    /// The release it carries, when the image says so (for example `2026.11.0`).
    pub release: Option<String>,
    /// RFC 3339, as the provider reports it.
    pub created: Option<String>,
    /// Whether the release signature was checked by this tool: the image is one the project's image workflow built
    /// and signed. `false` is the honest answer whenever that could not be shown, with the reason in
    /// `signature_detail`: nothing here claims a verification that did not happen.
    pub signature_verified: bool,
    /// Why the signature is, or is not, verified, in words a person reads. Additive: absent in older output.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub signature_detail: Option<String>,
    /// Whether this provider has signed releases to check at all. `false` only for the sandbox, whose images are
    /// simulated; an upgrade to an unverified image is refused unless the signature is not applicable.
    #[serde(default = "signature_applies")]
    pub signature_applicable: bool,
    /// The hash of the first-boot configuration the image's release was built with, from its signed manifest (see
    /// `ozbox_core::infra`). `None` when the signature was not verified or the release does not record one. Additive.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub first_boot_sha256: Option<String>,
    /// The `upgrade` record of the image's signed manifest (ADR 0038), read only from a verified manifest. `None` when the
    /// manifest could not be verified or the provider has none. Additive.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub upgrade: Option<crate::UpgradeRecord>,
}

fn signature_applies() -> bool {
    true
}

/// Where a backup lives.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SnapshotKind {
    /// A snapshot kept by the provider (an EBS snapshot, a Hetzner image).
    Provider,
    /// A restic snapshot in a repository the person owns.
    Restic,
}

/// One backup of a box, as a person reads it in a list. Additive: new fields get a default.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SnapshotInfo {
    /// The provider's id (`snap-0abc…`, an image id) or the restic snapshot id.
    pub id: String,
    pub kind: SnapshotKind,
    /// RFC 3339, as the source reports it.
    pub created_at: Option<String>,
    /// Size in bytes when the source knows it (a provider's snapshot reports its volume's size, not what it holds).
    pub size_bytes: Option<u64>,
    /// `completed`, `pending` or `error`.
    pub status: String,
    /// Whether `/work` is in it. False for a Hetzner snapshot, which can only capture the machine's root disk.
    pub includes_work: bool,
    pub labels: std::collections::BTreeMap<String, String>,
}

impl SnapshotInfo {
    /// Whether this is the copy an upgrade kept of an OLD SYSTEM disk (it holds a store key, never `/work`).
    pub fn is_old_system_disk_copy(&self) -> bool {
        self.labels
            .get(crate::engine::PURPOSE_LABEL)
            .is_some_and(|p| p == crate::engine::PRE_UPGRADE_ROOT_PURPOSE)
    }

    /// Whether this is a backup of the box (anything but a copy of an old system disk). Not the same as `includes_work`: a
    /// Hetzner snapshot is a backup of the box and does not include `/work`.
    pub fn is_work_backup(&self) -> bool {
        !self.is_old_system_disk_copy()
    }
}

/// The `/work` disk a restore replaced and kept, until the person deletes it. Additive: new fields get a default.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OldWorkDisk {
    pub id: String,
    pub size_gb: Option<u32>,
    /// The snapshot the box's `/work` was restored from when this disk was retired.
    pub restored_from: Option<String>,
    /// `kept` once the restore finished; `pending` while a restore is interrupted (it is finished by restoring again).
    pub state: String,
}

/// What a provider can and cannot do. Planning consults this so an impossible request fails BEFORE any change.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Capabilities {
    pub resize: ResizeMethod,
    /// The `/work` disk can grow while the box runs.
    pub online_disk_grow: bool,
    /// Disks can never shrink in place on any provider we support; shrinking is a migration to a new box.
    pub disk_shrink: bool,
    pub snapshots: bool,
    /// Sizes this provider can map to a machine type in its configured region.
    pub sizes: Vec<Size>,
}

/// A place boxes run: a cloud, a VPS host, or the fake used by tests.
///
/// Contract every implementation must keep (the shared conformance tests check it):
/// 1. [`Provider::plan`] never changes anything, anywhere.
/// 2. Planning an operation that is already satisfied returns an empty plan (idempotence).
/// 3. Anything the provider cannot do is an [`crate::Error::Unsupported`] from `plan`, never a half-applied `apply`.
/// 4. [`Provider::apply`] refuses a plan whose `based_on` no longer matches current state ([`crate::Error::StalePlan`]).
/// 5. A mutating operation on a box in a transitional state is refused ([`crate::Error::InvalidState`]).
/// 6. Errors and records never contain secret values.
pub trait Provider: Send + Sync {
    /// A short stable id: `fake`, `hcloud`, `aws`.
    fn id(&self) -> &str;

    fn capabilities(&self) -> Capabilities;

    fn list(&self) -> Result<Vec<BoxRecord>>;

    /// Where `list` looks (regions or locations), so a person can tell why a box is missing. Empty = n/a.
    fn searched(&self) -> Vec<String> {
        Vec::new()
    }

    fn get(&self, name: &BoxName) -> Result<Option<BoxRecord>>;

    /// The newest Oz image this account can see (read-only). `Unsupported` where the provider cannot tell.
    fn latest_image(&self, _region: Option<&str>) -> Result<ImageInfo> {
        Err(Error::Unsupported {
            provider: self.id().to_string(),
            what: "find the latest image".into(),
            why: "this provider has no list of Oz images; name one with --image".into(),
        })
    }

    /// Whether this provider can replace a box's machine from the image it already runs, so that it boots with the
    /// first-boot configuration rendered now (`Operation::Upgrade { reprovision: true }`). `Ok` carries notes for the
    /// plan; `Err` says why not and what to do instead. Read-only. The default refuses.
    fn check_reprovision(&self, _rec: &BoxRecord) -> Result<Vec<String>> {
        Err(Error::Unsupported {
            provider: self.id().to_string(),
            what: "replace a machine from the image it already runs".into(),
            why: "this provider cannot give a box a new first boot; create a new box (or `ozbox clone` this one) and move to it".into(),
        })
    }

    /// What is known about one image (its release and whether its signature verifies), for an explicit
    /// `upgrade --image <id>`. `Unsupported` where the provider cannot tell. Read-only.
    fn image_info(&self, _image: &str, _region: Option<&str>) -> Result<ImageInfo> {
        Err(Error::Unsupported {
            provider: self.id().to_string(),
            what: "inspect an image".into(),
            why: "this provider cannot tell where an image came from".into(),
        })
    }

    /// The snapshots of one box, oldest first, with what is known about each. Read-only. `Unsupported` where a
    /// provider cannot list them.
    fn snapshots(&self, name: &BoxName) -> Result<Vec<SnapshotInfo>> {
        let _ = name;
        Err(Error::Unsupported {
            provider: self.id().to_string(),
            what: "list snapshots".into(),
            why: "this provider cannot list the snapshots of a box".into(),
        })
    }

    /// The old `/work` disks of a box that restores kept. Read-only; none where a provider keeps none.
    fn old_work_disks(&self, name: &BoxName) -> Result<Vec<OldWorkDisk>> {
        let _ = name;
        Ok(Vec::new())
    }

    /// Take the copy of the OLD system disk that an upgrade asked to keep (`Operation::Upgrade { keep_old_system_disk }`), now,
    /// waiting as long as the provider allows for it to complete, and return its id. A caller that stops the box afterwards
    /// takes it BEFORE it makes the box ready for the stop, so a slow copy cannot outlast the hold on new runs, and then plans
    /// the upgrade again without the flag (the copy is done). A failure changes nothing. The default cannot keep one.
    fn keep_old_system_disk(&self, name: &BoxName, image: &str) -> Result<String> {
        let _ = image;
        Err(Error::Unsupported {
            provider: self.id().to_string(),
            what: format!("keep a copy of the old system disk of {name}"),
            why: "this provider cannot".into(),
        })
    }

    /// Work out what `op` would change. Read-only.
    fn plan(&self, op: &Operation) -> Result<Plan>;

    /// Carry out a plan produced by [`Provider::plan`]. Returns the box's record afterwards
    /// (`None` after a destroy).
    fn apply(&self, plan: &Plan) -> Result<Option<BoxRecord>>;
}

/// Turn what a person typed for an image into a concrete id: `latest` asks the provider, anything else is itself.
pub fn resolve_image(p: &dyn Provider, requested: &str, region: Option<&str>) -> Result<String> {
    if requested.trim() == "latest" {
        Ok(p.latest_image(region)?.id)
    } else {
        Ok(requested.trim().to_string())
    }
}
