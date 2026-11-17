//! AWS provider.
//!
//! * **Lifecycle** (create, destroy, clone's create) runs the `aws-box` OpenTofu module, one workspace per box
//!   (the box-module contract: `infra/tofu/modules/aws-box/variables.tf`).
//! * **Runtime** actions (stop, start, change type, grow the volume, snapshot, list) run the `aws` CLI with
//!   `--output json` through the argv-only command runner. There is no AWS SDK here (ADR 0008).
//!
//! Credentials are the CLI's own (profile, environment, role); this crate never reads or keeps them.
//! Planning is the shared [`ozbox_core::Engine`]; this crate supplies the primitives and the size mapping.
//!
//! The `/work` volume of an instance is the EBS volume attached to it that is not the root device.

pub mod adopt;
mod capacity;
pub mod fleet_policy;
pub mod init_actions;
pub mod operator_policy;
pub mod public_images;
#[cfg(test)]
mod testing;

use std::path::PathBuf;
use std::sync::Arc;

use ozbox_core::{
    Backend, BoxName, BoxRecord, BoxSpec, BoxState, Capabilities, CapacityRequest, CommandRunner,
    CommandSpec, DiskGb, Engine, Error, GpuKind, ImageInfo, MachineChoice, ModuleVars, OldWorkDisk,
    Operation, ReleaseVerifier, ResizeMethod, Result, Size, SnapshotInfo, SnapshotKind, TofuModule,
    RESUME_AFTER_LABEL, UPGRADE_TO_LABEL,
};
use serde::Deserialize;

pub const PROVIDER_ID: &str = "aws";
pub const DEFAULT_MODULE_DIR: &str = "infra/tofu/modules/aws-box";

const TAG_BOX: &str = "ozbox-box";
/// What a snapshot Oz Box took is for. A snapshot with no such tag is a backup of `/work`.
pub const PURPOSE_TAG: &str = ozbox_core::PURPOSE_LABEL;
/// The purpose of the snapshot an upgrade takes of the OLD system disk before replacing it (`ozbox upgrade`, when the plan
/// cannot show that the secrets store's key survives). It holds a disk, not `/work`: it is never a restore or clone source.
pub const PRE_UPGRADE_ROOT: &str = ozbox_core::PRE_UPGRADE_ROOT_PURPOSE;
/// The volume a pre-upgrade snapshot was taken of (a tag on it).
pub const SOURCE_VOLUME_TAG: &str = "ozbox-source-volume";
/// Tag an Oz image carries (its release), and the one `--image latest` looks for.
const TAG_IMAGE: &str = "ozbox-image";
/// The labels that carry a box's secrets key (a KMS key ARN) and its fleet, set when the box is created with one, so an
/// upgrade gives the new machine the same key the store was sealed with whatever the configuration says today.
pub const SECRETS_KEY_LABEL: &str = "ozbox-secrets-key";
pub const SECRETS_FLEET_LABEL: &str = "ozbox-secrets-fleet";
/// A box that is MOVING its store's key from a file to the fleet's KMS key (`ozbox adopt-fleet-key`) carries the key here,
/// not in [`SECRETS_KEY_LABEL`]. The real label means "this store is wrapped by that key" and an upgrade reads it as
/// "kept"; it is written only once the box itself has said so. While this one is on a box, the role may use the key (so the
/// box can finish) and an upgrade is refused (a new machine configured for KMS over a store still wrapped by a file key
/// would never start).
pub const SECRETS_ADOPT_LABEL: &str = "ozbox-secrets-adopt";

/// Where a box's secrets store's key stands, from the box's labels.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SecretsKeyStage {
    /// No fleet key: the store's key is a file on the system disk (or a TPM).
    File,
    /// Moving: the role may use this key and the box has been asked to re-wrap its store with it; not yet confirmed.
    Pending(String),
    /// The box says its store is wrapped by this key; upgrades give the new machine the same one.
    Fleet(String),
}

/// One in-place step of moving a store to the fleet key (see [`AwsBackend::plan_secrets_key_step`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SecretsKeyStep {
    Begin,
    Finish,
    Cancel,
}

/// A fixed program the laptop may run as root on a box through AWS Systems Manager Run Command. Never user input: each is a
/// word from a fixed set, sent as the one enum parameter of the fleet's own SSM document (`ozbox-adopt-<fleet>`, defined in
/// the `aws-adopt-command` OpenTofu module), which maps it to a fixed `ozbox` program by absolute path. The stock
/// `AWS-RunShellScript` is never used: permission to send it is a root shell on every box.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RootCommand {
    /// Print the box's secrets-store facts (`ozbox secrets adopt-status`).
    AdoptStatus,
    /// Take a recorded cancel away, under the box's lock (`ozbox secrets adopt-arm`).
    AdoptArm,
    /// Record a cancel and take a moved store back to its file key (`ozbox secrets adopt-cancel`).
    AdoptCancel,
    /// Record a cancel and put the copy of the store made before the move back (`ozbox secrets adopt-cancel --from-copy`):
    /// for a store that cannot be re-wrapped because KMS no longer answers. Secrets saved since the move are lost.
    AdoptCancelFromCopy,
}

impl RootCommand {
    /// How many polls the laptop waits for this command: the full window for a cancel (it re-wraps a whole store, and the
    /// document's own timeout is what ends it), a short one for a read or a mark.
    fn polls(self) -> u32 {
        match self {
            Self::AdoptStatus | Self::AdoptArm => ROOT_READ_POLLS,
            Self::AdoptCancel | Self::AdoptCancelFromCopy => ROOT_POLLS,
        }
    }

    /// The value of the document's `action` enum.
    pub fn action(self) -> &'static str {
        match self {
            Self::AdoptStatus => "status",
            Self::AdoptArm => "arm",
            Self::AdoptCancel => "cancel",
            Self::AdoptCancelFromCopy => "cancel-from-copy",
        }
    }
}

/// The name of the fleet's adopt document (the `aws-adopt-command` module creates it as `ozbox-adopt-<fleet>`).
pub fn adopt_document_name(fleet: &str) -> String {
    format!("ozbox-adopt-{fleet}")
}

/// The document the `aws-adopt-command` module creates (`ozbox-adopt-<fleet>`), carried here from the same file. The laptop sends
/// the SHA-256 of THIS text with every command, so a document someone in the shared account replaced (`ssm:UpdateDocument`)
/// is never run as root on a box, as long as Systems Manager enforces the pinned hash. Whether it does is unproven (the API reference
/// does not say so); real-box check 1 settles it, and nothing here relies on it for anything but this defence.
const ADOPT_DOCUMENT: &str =
    include_str!("../../../infra/tofu/modules/aws-adopt-command/adopt-document.yaml");

/// How long the document lets its program RUN (its `timeoutSeconds`, pinned by the module's test), and how long SSM may take to
/// START a command (its delivery timeout, shorter than the wait below, so a command the laptop gave up on never starts late).
/// The laptop waits for both and a margin, so it never gives up on a command that is still running: a cancel the laptop
/// stopped watching is never killed part way (nothing here sends `cancel-command`).
const ROOT_EXEC_SECS: u64 = 900;
const ROOT_DELIVERY: u64 = 120;
const ROOT_DELIVERY_SECS: &str = "120";
const ROOT_POLL_SECS: u64 = 3;
/// The wait: delivery, then the whole execution timeout, then 2 minutes of margin (1140 s), polled every 3 seconds.
const ROOT_POLLS: u32 = ((ROOT_DELIVERY + ROOT_EXEC_SECS + 120) / ROOT_POLL_SECS) as u32;
/// The wait for a command that only reads or flips a mark (`status`, `arm`): delivery plus 2 minutes (240 s). A dashboard plan
/// request waits inside an HTTP request, and a blocked key service must not make it wait the full 19 minutes of a cancel.
const ROOT_READ_POLLS: u32 = ((ROOT_DELIVERY + 120) / ROOT_POLL_SECS) as u32;

/// What `root_command` reports when the box's own program does not know the root check at all (a box from before this
/// release): the upgrade says the BOX is older, not that the operator's policy is wrong.
pub const ROOT_PROGRAM_OLDER: &str =
    "the program on the box is older than the root check and does not know it";

/// A Failed invocation of a program the box does not have: the box's program is older than the root check. The document's
/// `exec` of a subcommand the program does not know ends with the program's own "unrecognized subcommand" (exit code 2).
fn program_unknown(v: &serde_json::Value) -> bool {
    let err = v
        .get("StandardErrorContent")
        .and_then(|x| x.as_str())
        .unwrap_or("")
        .to_ascii_lowercase();
    let code = v.get("ResponseCode").and_then(|c| c.as_i64());
    err.contains("unrecognized subcommand")
        || err.contains("unexpected argument")
        || err.contains("no such file or directory") && err.contains("/usr/local/bin/ozbox")
        || (code == Some(2) && err.contains("usage:"))
}

/// A refused `send-command`, said for a person. A refusal that names a hash or an invalid document is read as the document not
/// being this ozbox's (applied from another release of the aws-adopt-command module, or changed in the account); whether Systems
/// Manager enforces the pinned hash at all is unproven (real-box check 1). A refusal for an operator whose policy does not allow
/// the document is a different thing and is reported as it was; the CLI's own text says neither. A hash or document refusal gets
/// the lockstep sentence.
fn send_refused(e: Error, document: &str) -> Error {
    let text = e.to_string();
    let low = text.to_ascii_lowercase();
    if low.contains("invaliddocument") || low.contains("hash") {
        return Error::Provider(format!(
            "Systems Manager refused the command because the document {document} is not the one this ozbox carries (its text differs from the one ozbox pins by SHA-256, or the document does not exist). Apply the aws-adopt-command module from the same release as this ozbox (or update ozbox so they match), then try again. Nothing was changed on the box. Systems Manager said: {}",
            text.chars().filter(|c| !c.is_control()).take(240).collect::<String>()
        ));
    }
    e
}

/// The exit code and the first line of what a failed program wrote to its error output, for a person (nothing from a box that
/// could carry a secret is in it: the program prints plain sentences).
fn failure_hint(v: &serde_json::Value) -> String {
    let code = v.get("ResponseCode").and_then(|c| c.as_i64());
    let first: String = v
        .get("StandardErrorContent")
        .and_then(|x| x.as_str())
        .and_then(|e| e.lines().find(|l| !l.trim().is_empty()))
        .map(|l| l.chars().filter(|c| !c.is_control()).take(160).collect())
        .unwrap_or_default();
    match (code, first.is_empty()) {
        (Some(c), false) => format!(", exit {c}: {first}"),
        (Some(c), true) => format!(", exit {c}"),
        (None, false) => format!(": {first}"),
        (None, true) => String::new(),
    }
}

/// The only resources an upgrade may destroy and recreate: the machine and the attachment that depends on it. The
/// `/work` volume is not on this list, so a plan that would replace it is refused.
/// Resource types the daily operator role cannot apply on purpose (`infra/aws/operator-policy.json` denies it every way to
/// create or change an IAM policy or a credential). A plan that needs one is refused before the box is stopped.
const UNAPPLIABLE_TYPES: &[&str] = &[
    "aws_iam_role_policy",
    "aws_iam_policy",
    "aws_iam_policy_attachment",
    "aws_iam_user",
    "aws_iam_user_policy",
    "aws_iam_user_policy_attachment",
    "aws_iam_access_key",
    "aws_iam_group",
    "aws_iam_group_policy",
    "aws_iam_group_policy_attachment",
];

const UPGRADE_REPLACES: &str = "aws_instance.box";
// The role's Session Manager attachment is swapped, in a box made before ADR 0029 Amendment 9, from AWS's managed policy
// (which reads every parameter in the account) to the account's own `ozbox-box-session-manager`.
const UPGRADE_MAY_ALSO_REPLACE: &[&str] = &[
    "aws_volume_attachment.work",
    "aws_iam_role_policy_attachment.ssm_core",
];
/// The one resource no upgrade may delete, replace or newly create: it is the person's `/work`.
const UPGRADE_PROTECTED: &[&str] = &["aws_ebs_volume.work"];
/// An in-place change of a box's secrets key: the role's ATTACHMENT of the account's fleet-key policy is the one thing that may be created (or taken
/// back); the machine, its attachment and `/work` may be updated (tags) and never created, destroyed or replaced.
const ADOPT_ROLE_POLICY: &str = "aws_iam_role_policy_attachment.fleet_key[0]";
const IN_PLACE_PROTECTED: &[&str] = &[
    "aws_ebs_volume.work",
    "aws_instance.box",
    "aws_volume_attachment.work",
];
/// The two resources a `/work` restore puts in place, in the module.
const RESTORE_VOLUME: &str = "aws_ebs_volume.work";
const RESTORE_ATTACHMENT: &str = "aws_volume_attachment.work";
const RESTORE_CREATES: &[&str] = &[RESTORE_VOLUME, RESTORE_ATTACHMENT];
/// What a restore writes on the disk it retires: its role stops being `work` (so nothing mistakes it for the box's
/// disk), the snapshot the restore was for, and whether the restore finished.
const RETIRED_ROLE: &str = "work-retired";
const RETIRED_FROM: &str = "ozbox-retired-from";
const RESTORE_STATE: &str = "ozbox-restore";
/// Tag the CLI writes on the `/work` volume with the machine type the box ran, next to [`UPGRADE_TO_LABEL`]. The
/// machine is gone when an upgrade is interrupted between destroy and create, and this is what remains of it.
const UPGRADE_MACHINE_TAG: &str = "ozbox-upgrade-machine";
/// Said in every upgrade plan: what happens in the window between removing the old machine and creating the new one.
const UPGRADE_GAP_NOTE: &str = "The old machine is removed before the new one is created. If the account cannot start the new machine then (a vCPU quota another workload took, or no capacity), the create is retried a few times with a pause. If it still fails, /work stays safe, the box has no running machine and shows as `instance missing`, and running this same `upgrade` again finishes the job.";

/// Whether an apply failed because the account could not start the machine right now (a vCPU quota, no capacity), the
/// one failure that is worth trying again. Pure, so it is tested on fixture text.
pub fn is_capacity_error(message: &str) -> bool {
    const SIGNS: &[&str] = &[
        "VcpuLimitExceeded",
        "InsufficientInstanceCapacity",
        "InstanceLimitExceeded",
        "MaxSpotInstanceCountExceeded",
        "more vCPU capacity than your current vCPU limit",
    ];
    SIGNS.iter().any(|s| message.contains(s))
}

/// The CPU architecture an EC2 instance type runs. Graviton families end in `g` after their generation digit
/// (`m7g`, `c7gd`, `g5g`); everything this adapter maps to a size is x86.
fn arch_of_instance_type(machine_type: &str) -> &'static str {
    let family = machine_type.split('.').next().unwrap_or("");
    let chars: Vec<char> = family.chars().collect();
    let graviton = chars
        .windows(2)
        .any(|w| w[0].is_ascii_digit() && w[1] == 'g');
    if graviton {
        "arm64"
    } else {
        "x86_64"
    }
}

// TODO(arch): images are amd64 and arm64; this mapping is amd64 (m7i/r7i/g6) only for v0.1. Add an `arch`
// argument (Graviton m7g/r7g/g5g types for arm64) when the arm64 image ships.
/// Size to EC2 instance type. Every type has at least the size's vCPUs and memory.
///
/// GPU-L (one ~80 GB GPU) is not offered: AWS sells 80 GB GPUs only in eight-GPU instances (`p5.48xlarge`:
/// 8 x H100, 192 vCPUs), which is a different product from one large GPU and a very different bill.
pub fn machine_choice(size: Size) -> Result<MachineChoice> {
    let t = match size {
        // XS is 4 vCPU / 8 GiB, the benchmark shape. `c7i.xlarge` is the only 4/8 type in the Intel general-purpose line
        // that S, M and XL use; it is compute-optimised, which suits a benchmark and a lighter project alike.
        Size::XS => "c7i.xlarge",
        Size::S => "m7i.xlarge",
        Size::M => "m7i.2xlarge",
        Size::L => "r7i.2xlarge",
        Size::XL => "m7i.4xlarge",
        Size::XXL => "m7i.8xlarge",
        Size::Gpu(GpuKind::Small) => "g6.2xlarge",
        Size::Gpu(GpuKind::Large) => {
            return Err(Error::Unsupported {
                provider: PROVIDER_ID.into(),
                what: "create a GPU-L box".into(),
                why: "AWS has no instance with a single 80 GB GPU (the p5 family is eight GPUs and 192 vCPUs); not offered in v0.1".into(),
            })
        }
    };
    Ok(MachineChoice::new(t))
}

pub fn capabilities() -> Capabilities {
    Capabilities {
        resize: ResizeMethod::StopChangeStart,
        online_disk_grow: true,
        disk_shrink: false,
        snapshots: true,
        sizes: Size::STANDARD
            .iter()
            .copied()
            .chain([Size::Gpu(GpuKind::Small)])
            .collect(),
    }
}

#[derive(Debug, Clone)]
pub struct AwsConfig {
    /// The `aws-box` module directory.
    pub module_dir: PathBuf,
    /// Region for every `aws` call and the module's `region` variable. `None` = the CLI's own default.
    pub region: Option<String>,
    /// Regions `list` searches. Empty = just `region` (or the CLI's default region).
    pub regions: Vec<String>,
    /// AMI to boot from when a box does not name one.
    pub image: Option<String>,
    /// A PRIVATE subnet for the box (the module's required `subnet_id`). Creating without one is refused.
    pub subnet_id: Option<String>,
    /// Customer-managed KMS key for the volumes; `None` = the AWS-managed key.
    pub kms_key_arn: Option<String>,
    /// The fleet's secrets key (the `aws-secrets-key` module's `key_arn`) and its fleet name: a box created while this is
    /// set keeps its secrets store's key in KMS (no key file on the box at all, so a replaced system disk keeps the store),
    /// and carries the key in its labels so every later upgrade keeps the same one. `None`: the store's key is kept in a
    /// file on the system disk, which an upgrade replaces (the plan says so).
    pub secrets_key_arn: Option<String>,
    pub fleet: Option<String>,
    /// For `upgrade` only: this computer's approval key (the label value), pinned on a box that has none, as `create`
    /// pins it. `None` leaves the box as it is.
    pub upgrade_pin: Option<String>,
    /// For `upgrade` only: this computer's SSH key for the box's ingress account (the label value), pinned on a box that has
    /// none, so a box made before the ingress account existed can be reached through it. `None` leaves the box as it is.
    pub upgrade_ingress_pin: Option<String>,
    /// For `upgrade` only: move a box that keeps its secrets store's key in a file to the fleet's KMS key (`secrets_key_arn`),
    /// by giving the new machine the key's labels. The caller has checked that the store holds nothing.
    pub upgrade_use_fleet_key: bool,
    /// Root disk size in GB; `None` = the module's default (60).
    pub root_disk_gb: Option<u32>,
    /// The locked session-log bucket, when session logging is on: the box's role may write session logs there.
    pub session_log_bucket: Option<String>,
    /// The Patch Manager patch group the box joins (the `Patch Group` tag), when patching is on.
    pub patch_group: Option<String>,
    /// How often, and how many times, to look at a growing volume before giving up.
    pub poll_interval: std::time::Duration,
    pub volume_wait_polls: u32,
    /// How many times (one `poll_interval` apart) to look at the copy of the old system disk an upgrade takes before giving up
    /// on it: thirty minutes by default (`snapshot_wait_minutes` under `[aws]`). The upgrade stops the machine only after the copy
    /// is complete. `ozbox upgrade` takes the copy before it makes the box ready for the stop, so it may wait this long; a copy
    /// taken inside an apply (the dashboard's) is limited to [`ozbox_core::HOLD_SAFE_COPY_WAIT`], because the box holds new runs
    /// back for only ten minutes from the start of that preparation. A copy not complete in time ends the upgrade with the box
    /// untouched, and the copy finishes by itself.
    pub snapshot_wait_polls: u32,
    /// How many more times to try creating the machine when the account refuses it for lack of capacity or quota, and
    /// the pause before the first retry (it doubles each time, to at most five minutes).
    pub create_retries: u32,
    pub create_backoff: std::time::Duration,
    /// The `owner/name` GitHub repository whose image workflow signs the Oz images (see [`ozbox_core::release`]).
    pub release_repo: String,
    /// The AWS account whose public Oz images `latest` may use when the caller's own account has none (ADR 0052). `None`
    /// is the project's own publisher account ([`public_images::PUBLISHER_ACCOUNT_ID`]); `Some("none")` turns the public
    /// images off; any other 12-digit account id is trusted INSTEAD of the project's (a fork that publishes its own).
    pub image_publisher: Option<String>,
    /// The most time the lookup of a public image may take in all (each candidate is a manifest download and a signature
    /// check). `None` is [`public_images::LOOKUP_DEADLINE`].
    pub public_lookup_deadline: Option<std::time::Duration>,
    /// The version this program is (tests set it; `None` is this crate's, the product version).
    pub program_version: Option<String>,
    /// Where the OpenTofu state of the boxes lives, apart from the module checkout (see [`ozbox_core::tofu::StateLayout`]).
    /// `None` keeps the state beside the module, as a bare `tofu` run would.
    pub state_dir: Option<PathBuf>,
    /// Keep the state in the encrypted bucket instead (needs `state_dir`: the generated module copy and the backups live
    /// there). `None` keeps it in `state_dir`.
    pub state_s3: Option<ozbox_core::tofu::S3State>,
    /// The first-boot hash of the modules in `module_dir` (see [`ozbox_core::infra`]), passed to the module so a new
    /// machine records which first-boot configuration it was made with. `None` passes nothing (the module's default).
    pub first_boot_sha256: Option<String>,
}

impl Default for AwsConfig {
    fn default() -> Self {
        Self {
            module_dir: PathBuf::from(DEFAULT_MODULE_DIR),
            region: None,
            regions: Vec::new(),
            image: None,
            subnet_id: None,
            kms_key_arn: None,
            secrets_key_arn: None,
            fleet: None,
            upgrade_pin: None,
            upgrade_ingress_pin: None,
            upgrade_use_fleet_key: false,
            root_disk_gb: None,
            session_log_bucket: None,
            patch_group: None,
            poll_interval: std::time::Duration::from_secs(5),
            volume_wait_polls: 60,
            snapshot_wait_polls: 360,
            create_retries: 4,
            create_backoff: std::time::Duration::from_secs(30),
            release_repo: ozbox_core::DEFAULT_RELEASE_REPO.to_string(),
            image_publisher: None,
            public_lookup_deadline: None,
            program_version: None,
            state_dir: None,
            state_s3: None,
            first_boot_sha256: None,
        }
    }
}

pub fn open(config: AwsConfig) -> Engine<AwsBackend> {
    Engine::new(AwsBackend::new(Arc::new(ozbox_core::SystemRunner), config))
}

pub struct AwsBackend {
    runner: Arc<dyn CommandRunner>,
    tofu: TofuModule,
    cfg: AwsConfig,
    releases: ReleaseVerifier,
}

#[derive(Deserialize, Clone)]
#[serde(rename_all = "PascalCase")]
struct Tag {
    key: String,
    value: String,
}

#[derive(Deserialize, Default)]
#[serde(rename_all = "PascalCase")]
struct InstanceState {
    name: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "PascalCase")]
struct Ebs {
    volume_id: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "PascalCase")]
struct Mapping {
    device_name: String,
    ebs: Option<Ebs>,
}

#[derive(Deserialize)]
#[serde(rename_all = "PascalCase")]
struct Instance {
    instance_id: String,
    instance_type: String,
    #[serde(default)]
    state: InstanceState,
    #[serde(default)]
    launch_time: Option<String>,
    #[serde(default)]
    tags: Vec<Tag>,
    #[serde(default)]
    root_device_name: Option<String>,
    #[serde(default)]
    block_device_mappings: Vec<Mapping>,
    /// The image the machine was launched from.
    #[serde(default)]
    image_id: Option<String>,
    #[serde(default)]
    subnet_id: Option<String>,
}

#[derive(Deserialize)]
#[serde(rename_all = "PascalCase")]
struct Reservation {
    #[serde(default)]
    instances: Vec<Instance>,
}

#[derive(Deserialize)]
#[serde(rename_all = "PascalCase")]
struct Reservations {
    #[serde(default)]
    reservations: Vec<Reservation>,
}

#[derive(Deserialize, Clone)]
#[serde(rename_all = "PascalCase")]
struct Volume {
    volume_id: String,
    size: u32,
    #[serde(default)]
    state: Option<String>,
    #[serde(default)]
    tags: Vec<Tag>,
    #[serde(default)]
    kms_key_id: Option<String>,
    #[serde(default)]
    snapshot_id: Option<String>,
    #[serde(default)]
    encrypted: Option<bool>,
}

#[derive(Deserialize)]
#[serde(rename_all = "PascalCase")]
struct Image {
    image_id: String,
    #[serde(default)]
    name: Option<String>,
    #[serde(default)]
    owner_id: Option<String>,
    #[serde(default)]
    architecture: Option<String>,
    #[serde(default)]
    state: Option<String>,
    #[serde(default)]
    creation_date: Option<String>,
    #[serde(default)]
    tags: Vec<Tag>,
}

#[derive(Deserialize)]
#[serde(rename_all = "PascalCase")]
struct Images {
    #[serde(default)]
    images: Vec<Image>,
}

#[derive(Deserialize)]
#[serde(rename_all = "PascalCase")]
struct Volumes {
    #[serde(default)]
    volumes: Vec<Volume>,
}

#[derive(Deserialize)]
#[serde(rename_all = "PascalCase")]
struct Snapshot {
    snapshot_id: String,
    #[serde(default)]
    start_time: Option<String>,
    #[serde(default)]
    state: Option<String>,
    #[serde(default)]
    volume_size: Option<u64>,
    #[serde(default)]
    tags: Vec<Tag>,
    #[serde(default)]
    encrypted: Option<bool>,
    #[serde(default)]
    kms_key_id: Option<String>,
}

#[derive(Deserialize)]
#[serde(rename_all = "PascalCase")]
struct Snapshots {
    #[serde(default)]
    snapshots: Vec<Snapshot>,
}

/// One line saying why `latest` passed over a candidate: `<image> (release <r>): <why>`.
fn skip_line(info: &ImageInfo, why: &str) -> String {
    format!(
        "{} (release {}): {why}",
        info.id,
        info.release.as_deref().unwrap_or("unknown")
    )
}

/// The skip lines other than the one about `id` itself: an image that is returned is not also "passed over".
fn without_own_line(lines: Vec<String>, id: &str) -> Vec<String> {
    let own = format!("{id} ");
    lines.into_iter().filter(|l| !l.starts_with(&own)).collect()
}

fn tag<'a>(tags: &'a [Tag], key: &str) -> Option<&'a str> {
    tags.iter().find(|t| t.key == key).map(|t| t.value.as_str())
}

fn state_of(name: &str) -> BoxState {
    match name {
        "running" => BoxState::Running,
        "stopped" => BoxState::Paused,
        "pending" => BoxState::Resuming,
        "stopping" => BoxState::Pausing,
        "shutting-down" => BoxState::Destroying,
        _ => BoxState::Unknown,
    }
}

fn size_of(machine_type: &str) -> Option<Size> {
    [
        Size::XS,
        Size::S,
        Size::M,
        Size::L,
        Size::XL,
        Size::XXL,
        Size::Gpu(GpuKind::Small),
    ]
    .into_iter()
    .find(|s| machine_choice(*s).is_ok_and(|c| c.machine_type == machine_type))
}

/// The machine's system disk: the volume mapped at its root device.
fn root_volume_of(i: &Instance) -> Option<&str> {
    i.block_device_mappings
        .iter()
        .filter(|m| Some(&m.device_name) == i.root_device_name.as_ref())
        .find_map(|m| m.ebs.as_ref().map(|e| e.volume_id.as_str()))
}

/// Whether a snapshot is the copy of an old system disk an upgrade kept (see [`PRE_UPGRADE_ROOT`]).
fn is_pre_upgrade_root(tags: &[Tag]) -> bool {
    tag(tags, PURPOSE_TAG) == Some(PRE_UPGRADE_ROOT)
}

/// Where the module (and a restore, and an adoption) attaches a box's `/work` volume.
const WORK_DEVICE: &str = "/dev/sdf";

/// The `/work` volume of a machine: the disk at [`WORK_DEVICE`]. Another disk someone attached (a recovered system disk, for
/// instance) is never taken for it, however it is ordered; only a machine with a single non-system disk and nothing at
/// [`WORK_DEVICE`] falls back to that one disk.
fn work_volume_of(i: &Instance) -> Option<&str> {
    let others: Vec<(&str, &str)> = i
        .block_device_mappings
        .iter()
        .filter(|m| Some(&m.device_name) != i.root_device_name.as_ref())
        .filter_map(|m| {
            m.ebs
                .as_ref()
                .map(|e| (m.device_name.as_str(), e.volume_id.as_str()))
        })
        .collect();
    others
        .iter()
        .find(|(d, _)| *d == WORK_DEVICE)
        .map(|(_, v)| *v)
        .or(match others.as_slice() {
            [(_, only)] => Some(*only),
            _ => None,
        })
}

struct Scoped<'a> {
    b: &'a AwsBackend,
    region: Option<String>,
}

impl Scoped<'_> {
    /// `aws <args> [--region R]`, JSON output unless it is a `wait`.
    fn aws(&self, args: &[&str]) -> CommandSpec {
        let mut c = CommandSpec::new("aws").args(args.iter().copied());
        if args.get(1) != Some(&"wait") {
            c = c.args(["--output", "json"]);
        }
        if let Some(r) = &self.region {
            c = c.args(["--region", r.as_str()]);
        }
        c
    }

    fn run(&self, args: &[&str]) -> Result<ozbox_core::Output> {
        self.b.runner.run_ok(&self.aws(args))
    }

    fn run_json<T: for<'de> Deserialize<'de>>(&self, args: &[&str]) -> Result<T> {
        Ok(serde_json::from_str(&self.run(args)?.stdout)?)
    }
}

impl AwsBackend {
    pub fn new(runner: Arc<dyn CommandRunner>, cfg: AwsConfig) -> Self {
        Self::with_env(runner, cfg, |k| std::env::var(k).ok())
    }

    /// For tests: no GitHub token from the environment, whatever the machine has set.
    #[cfg(test)]
    pub(crate) fn with_env_none(runner: Arc<dyn CommandRunner>, cfg: AwsConfig) -> Self {
        Self::with_env(runner, cfg, |_| None)
    }

    /// Like [`new`](Self::new) with the environment lookup (where a GitHub token may come from) supplied, so a test does
    /// not read the real one.
    pub fn with_env(
        runner: Arc<dyn CommandRunner>,
        cfg: AwsConfig,
        env: impl Fn(&str) -> Option<String> + Send + Sync + 'static,
    ) -> Self {
        let mut tofu = TofuModule::new(runner.clone(), cfg.module_dir.clone())
            .with_unappliable_types(UNAPPLIABLE_TYPES);
        if let Some(d) = &cfg.state_dir {
            tofu = tofu.with_state_root(d);
        }
        if let Some(s3) = &cfg.state_s3 {
            tofu = tofu.with_s3_state(s3.clone());
        }
        let releases = ReleaseVerifier::with_env(runner.clone(), cfg.release_repo.clone(), env);
        Self {
            runner,
            tofu,
            cfg,
            releases,
        }
    }

    fn search_regions(&self) -> Vec<String> {
        if !self.cfg.regions.is_empty() {
            return self.cfg.regions.clone();
        }
        self.cfg.region.iter().cloned().collect()
    }

    /// A view of the backend that runs `aws` in one region.
    fn at<'a>(&'a self, region: Option<&str>) -> Scoped<'a> {
        Scoped {
            b: self,
            region: region.map(str::to_string),
        }
    }

    /// The region a box's runtime calls go to: its own, else the configured one.
    fn at_rec<'a>(&'a self, rec: &BoxRecord) -> Scoped<'a> {
        self.at(rec.spec.region.as_deref().or(self.cfg.region.as_deref()))
    }

    /// Every managed box in `region` (else the CLI's default region).
    fn list_in(&self, region: Option<&str>) -> Result<Vec<BoxRecord>> {
        let s = self.at(region);
        let found: Reservations = s.run_json(&[
            "ec2",
            "describe-instances",
            "--filters",
            "Name=tag:ozbox-managed,Values=true",
            "Name=instance-state-name,Values=pending,running,stopping,stopped,shutting-down",
        ])?;
        let instances: Vec<Instance> = found
            .reservations
            .into_iter()
            .flat_map(|r| r.instances)
            .collect();
        let vols: Volumes = s.run_json(&[
            "ec2",
            "describe-volumes",
            "--filters",
            "Name=tag:ozbox-managed,Values=true",
        ])?;
        let orphans = Self::stranded_volumes(&instances, &vols.volumes);
        if instances.is_empty() && orphans.is_empty() {
            return Ok(Vec::new());
        }
        let snaps: Snapshots = s.run_json(&[
            "ec2",
            "describe-snapshots",
            "--owner-ids",
            "self",
            "--filters",
            "Name=tag:ozbox-managed,Values=true",
        ])?;
        let mut snaps = snaps.snapshots;
        snaps.sort_by(|a, b| (&a.start_time, &a.snapshot_id).cmp(&(&b.start_time, &b.snapshot_id)));

        let mut out = Vec::new();
        for i in instances {
            let Some(raw) = tag(&i.tags, TAG_BOX) else {
                continue;
            };
            let Ok(name) = BoxName::new(raw) else {
                continue;
            };
            let known_size = size_of(&i.instance_type);
            let mut spec = BoxSpec::new(name, known_size.unwrap_or(Size::S));
            spec.image = i.image_id.clone();
            let work =
                work_volume_of(&i).and_then(|id| vols.volumes.iter().find(|v| v.volume_id == id));
            spec.work_disk_gb = work.map_or(0, |v| v.size);
            spec.region = tag(&i.tags, "ozbox-region")
                .map(str::to_string)
                .or_else(|| region.map(str::to_string));
            // (The secrets-key labels are in the record too: `ozbox upgrade` and `ozbox adopt-fleet-key` read them from it.)
            spec.labels = Self::labels_of(&i.tags);
            // The first-boot hash the machine was created with: a tag the module sets only at creation and the box
            // cannot change. `ozbox upgrade` trusts this, not the box's own answer.
            if let Some(fb) = tag(&i.tags, ozbox_core::FIRST_BOOT_LABEL) {
                spec.labels
                    .insert(ozbox_core::FIRST_BOOT_LABEL.to_string(), fb.to_string());
            }
            // An unfinished upgrade is marked on the /work volume, because the machine it marks gets replaced.
            if let Some(to) = work.and_then(|v| tag(&v.tags, UPGRADE_TO_LABEL)) {
                spec.labels
                    .insert(UPGRADE_TO_LABEL.to_string(), to.to_string());
            }
            // A copy of an old system disk is not a backup of `/work`: it must never become `ozbox clone`'s default source.
            let snapshots = snaps
                .iter()
                .filter(|s| tag(&s.tags, TAG_BOX) == Some(raw) && !is_pre_upgrade_root(&s.tags))
                .map(|s| s.snapshot_id.clone())
                .collect();
            // A machine type Oz Box does not map to a size is never acted on.
            let state = if known_size.is_none() {
                BoxState::Unknown
            } else {
                state_of(&i.state.name)
            };
            out.push(BoxRecord {
                spec,
                state,
                provider: PROVIDER_ID.into(),
                provider_id: Some(i.instance_id.clone()),
                machine_type: Some(i.instance_type.clone()),
                snapshots,
                created_at: i.launch_time.clone(),
                last_activity_at: None,
            });
        }
        for v in orphans {
            let Some(raw) = tag(&v.tags, TAG_BOX) else {
                continue;
            };
            let Ok(name) = BoxName::new(raw) else {
                continue;
            };
            let machine_type = tag(&v.tags, UPGRADE_MACHINE_TAG).map(str::to_string);
            let mut spec = BoxSpec::new(
                name,
                machine_type.as_deref().and_then(size_of).unwrap_or(Size::S),
            );
            spec.work_disk_gb = v.size;
            spec.region = tag(&v.tags, "ozbox-region")
                .map(str::to_string)
                .or_else(|| region.map(str::to_string));
            spec.labels = Self::labels_of(&v.tags);
            if let Some(to) = tag(&v.tags, UPGRADE_TO_LABEL) {
                spec.labels
                    .insert(UPGRADE_TO_LABEL.to_string(), to.to_string());
            }
            let snapshots = snaps
                .iter()
                .filter(|sn| tag(&sn.tags, TAG_BOX) == Some(raw) && !is_pre_upgrade_root(&sn.tags))
                .map(|sn| sn.snapshot_id.clone())
                .collect();
            out.push(BoxRecord {
                spec,
                state: BoxState::InstanceMissing,
                provider: PROVIDER_ID.into(),
                provider_id: None,
                machine_type,
                snapshots,
                created_at: None,
                last_activity_at: None,
            });
        }
        out.sort_by(|a, b| a.spec.name.cmp(&b.spec.name));
        Ok(out)
    }

    /// `/work` volumes whose machine is gone: managed, tagged as a work volume with a box name nothing still runs,
    /// free (not attached), and carrying the upgrade mark. The mark is what makes a missing machine an interrupted
    /// upgrade rather than a box someone removed on purpose.
    fn stranded_volumes<'v>(instances: &[Instance], volumes: &'v [Volume]) -> Vec<&'v Volume> {
        let attached: Vec<&str> = instances.iter().filter_map(work_volume_of).collect();
        let live: Vec<&str> = instances
            .iter()
            .filter_map(|i| tag(&i.tags, TAG_BOX))
            .collect();
        volumes
            .iter()
            .filter(|v| tag(&v.tags, "ozbox-role") == Some("work"))
            .filter(|v| !attached.contains(&v.volume_id.as_str()))
            .filter(|v| v.state.as_deref().is_none_or(|st| st == "available"))
            .filter(|v| tag(&v.tags, UPGRADE_TO_LABEL).is_some())
            .filter(|v| tag(&v.tags, TAG_BOX).is_some_and(|b| !live.contains(&b)))
            .collect()
    }

    /// A box's own labels from the tags of one of its resources: what the module sets itself and the marks are left out.
    fn labels_of(tags: &[Tag]) -> std::collections::BTreeMap<String, String> {
        tags.iter()
            .filter(|t| {
                (!t.key.starts_with("ozbox-")
                    || t.key == RESUME_AFTER_LABEL
                    || t.key == ozbox_core::APPROVER_LABEL
                    || t.key == ozbox_core::INGRESS_LABEL
                    || t.key == SECRETS_KEY_LABEL
                    || t.key == SECRETS_ADOPT_LABEL
                    || t.key == SECRETS_FLEET_LABEL)
                    && !t.key.starts_with("aws:")
                    && t.key != "Name"
            })
            .map(|t| (t.key.clone(), t.value.clone()))
            .collect()
    }

    fn instance_id(rec: &BoxRecord) -> Result<&str> {
        rec.provider_id
            .as_deref()
            .ok_or_else(|| Error::Provider(format!("box {} has no instance id", rec.spec.name)))
    }

    /// The `/work` volume of a box whose machine is gone, found by the tags the module put on it.
    fn stranded_volume(&self, rec: &BoxRecord) -> Result<Volume> {
        let name_filter = format!("Name=tag:{TAG_BOX},Values={}", rec.spec.name);
        let found: Volumes = self.at_rec(rec).run_json(&[
            "ec2",
            "describe-volumes",
            "--filters",
            "Name=tag:ozbox-managed,Values=true",
            "Name=tag:ozbox-role,Values=work",
            &name_filter,
        ])?;
        let mut vols = found.volumes;
        match vols.len() {
            1 => Ok(vols.remove(0)),
            0 => Err(Error::Provider(format!(
                "the /work volume of {} was not found",
                rec.spec.name
            ))),
            _ => Err(Error::Provider(format!(
                "more than one volume claims to be the /work disk of {}; nothing was changed, check them by hand",
                rec.spec.name
            ))),
        }
    }

    /// The system disk of a box whose machine exists.
    fn root_volume(&self, rec: &BoxRecord) -> Result<Volume> {
        let id = Self::instance_id(rec)?;
        let s = self.at_rec(rec);
        let r: Reservations = s.run_json(&["ec2", "describe-instances", "--instance-ids", id])?;
        let vol_id = r
            .reservations
            .iter()
            .flat_map(|r| &r.instances)
            .find_map(|i| root_volume_of(i).map(str::to_string))
            .ok_or_else(|| {
                Error::Provider(format!(
                    "the machine of {} does not say which disk is its system disk",
                    rec.spec.name
                ))
            })?;
        let found: Volumes = s.run_json(&["ec2", "describe-volumes", "--volume-ids", &vol_id])?;
        found
            .volumes
            .into_iter()
            .find(|v| v.volume_id == vol_id)
            .ok_or_else(|| {
                Error::Provider(format!(
                    "the system disk {vol_id} of {} was not found",
                    rec.spec.name
                ))
            })
    }

    fn work_volume(&self, rec: &BoxRecord) -> Result<String> {
        if rec.state == BoxState::InstanceMissing {
            return Ok(self.stranded_volume(rec)?.volume_id);
        }
        let id = Self::instance_id(rec)?;
        let r: Reservations =
            self.at_rec(rec)
                .run_json(&["ec2", "describe-instances", "--instance-ids", id])?;
        if let Some(found) = r
            .reservations
            .iter()
            .flat_map(|r| &r.instances)
            .find_map(|i| work_volume_of(i).map(str::to_string))
        {
            return Ok(found);
        }
        // Detached by a restore that was interrupted: the disk it retired is still this box's /work.
        if let Some(v) = self
            .box_volumes(rec)?
            .into_iter()
            .find(Self::is_pending_restore)
        {
            return Ok(v.volume_id);
        }
        Err(Error::Provider(format!(
            "box {} has no /work volume",
            rec.spec.name
        )))
    }

    /// Every managed volume of this box (the system disk, the `/work` disk, retired disks).
    fn box_volumes(&self, rec: &BoxRecord) -> Result<Vec<Volume>> {
        let found: Volumes = self.at_rec(rec).run_json(&[
            "ec2",
            "describe-volumes",
            "--filters",
            "Name=tag:ozbox-managed,Values=true",
            &format!("Name=tag:{TAG_BOX},Values={}", rec.spec.name),
        ])?;
        Ok(found.volumes)
    }

    fn is_retired(v: &Volume) -> bool {
        tag(&v.tags, "ozbox-role") == Some(RETIRED_ROLE)
    }

    fn is_pending_restore(v: &Volume) -> bool {
        Self::is_retired(v) && tag(&v.tags, RESTORE_STATE) == Some("pending")
    }

    /// The module variables for a restore: the box exactly as it is now (so nothing but the volume changes), the
    /// snapshot, a size that holds both the current disk and the snapshot, the current disk's encryption key, and the
    /// subnet the machine really runs in (so the new disk is in the same zone).
    fn restore_vars(
        &self,
        rec: &BoxRecord,
        snapshot: &str,
        current: &Volume,
    ) -> Result<ModuleVars> {
        let image = rec.spec.image.clone().ok_or_else(|| {
            Error::Config(format!(
                "box {} does not say which image it runs, so ozbox cannot rebuild its plan safely; nothing was changed",
                rec.spec.name
            ))
        })?;
        let mut vars = self.upgrade_vars(rec, &image)?;
        let snap_gb = self
            .list_snapshots(rec)?
            .into_iter()
            .find(|s| s.id == snapshot)
            .and_then(|s| s.size_bytes)
            .map_or(0, |b| {
                u32::try_from(b.div_ceil(1_073_741_824)).unwrap_or(u32::MAX)
            });
        vars.work_snapshot_id = Some(snapshot.to_string());
        vars.work_disk_gb = current.size.max(snap_gb);
        if let Some(k) = &current.kms_key_id {
            vars.extra.insert("kms_key_arn".to_string(), k.clone());
        }
        let id = Self::instance_id(rec)?;
        let r: Reservations =
            self.at_rec(rec)
                .run_json(&["ec2", "describe-instances", "--instance-ids", id])?;
        if let Some(subnet) = r
            .reservations
            .iter()
            .flat_map(|r| &r.instances)
            .find_map(|i| i.subnet_id.clone())
        {
            vars.extra.insert("subnet_id".to_string(), subnet);
        }
        Ok(vars)
    }

    /// Put the box back the way it was before a restore changed anything: reattach the retired disk, give it its role
    /// back, and import both resources into the state again. Best effort; the error says what is left to do by hand.
    fn undo_restore(
        &self,
        rec: &BoxRecord,
        vars: &ModuleVars,
        old: &str,
        removed: &[&str],
    ) -> String {
        let s = self.at_rec(rec);
        let Ok(instance) = Self::instance_id(rec) else {
            return format!("the old disk {old} is kept");
        };
        let steps: Result<()> = (|| {
            s.run(&[
                "ec2",
                "attach-volume",
                "--volume-id",
                old,
                "--instance-id",
                instance,
                "--device",
                "/dev/sdf",
            ])?;
            s.run(&["ec2", "wait", "volume-in-use", "--volume-ids", old])?;
            s.run(&[
                "ec2",
                "create-tags",
                "--resources",
                old,
                "--tags",
                "Key=ozbox-role,Value=work",
            ])?;
            s.run(&[
                "ec2",
                "delete-tags",
                "--resources",
                old,
                "--tags",
                &format!("Key={RETIRED_FROM}"),
                &format!("Key={RESTORE_STATE}"),
            ])?;
            if removed.contains(&RESTORE_VOLUME) {
                self.tofu.state_import(vars, RESTORE_VOLUME, old)?;
            }
            if removed.contains(&RESTORE_ATTACHMENT) {
                self.tofu.state_import(
                    vars,
                    RESTORE_ATTACHMENT,
                    &format!("/dev/sdf:{old}:{instance}"),
                )?;
            }
            Ok(())
        })();
        match steps {
            Ok(()) => "the disk was put back and nothing was changed".to_string(),
            Err(e) => format!(
                "putting the old disk {old} back failed ({e}); it is kept and still holds /work, run `ozbox backup restore` again to finish"
            ),
        }
    }

    /// The version of this program (ADR 0036): the release an image must be compatible with.
    fn program(&self) -> String {
        self.cfg
            .program_version
            .clone()
            .unwrap_or_else(|| env!("CARGO_PKG_VERSION").to_string())
    }

    /// The account whose public images are trusted, if any (see [`AwsConfig::image_publisher`]).
    fn publisher(&self) -> Option<String> {
        match self.cfg.image_publisher.as_deref().map(str::trim) {
            None | Some("") => Some(public_images::PUBLISHER_ACCOUNT_ID.to_string()),
            Some(public_images::NO_PUBLISHER) => None,
            Some(id) if public_images::is_account_id(id) => Some(id.to_string()),
            // anything else is not an account: trust nobody rather than guess
            Some(_) => None,
        }
    }

    /// The release an image claims. An image in this account says so in its `ozbox-image` tag. An image of the publisher
    /// account is seen by everyone else without its tags (AWS shows tags only to the owner), so its name says it
    /// (`ozbox-<version>-<timestamp>`). Either way it only chooses which signed manifest to fetch: whether the image is
    /// trusted is decided by that manifest listing this exact image id for the region.
    fn release_of(&self, img: &Image) -> Option<String> {
        tag(&img.tags, TAG_IMAGE)
            .filter(|v| !v.is_empty())
            .map(str::to_string)
            .or_else(|| {
                let publisher = self.publisher()?;
                (img.owner_id.as_deref() == Some(publisher.as_str()))
                    .then(|| img.name.as_deref().and_then(public_images::release_of_name))
                    .flatten()
            })
    }

    /// What is known about an image, including whether it is one the project's image workflow built and signed.
    fn inspect(&self, img: &Image, region: Option<&str>) -> ImageInfo {
        self.inspect_full(img, region).0
    }

    /// [`inspect`](Self::inspect), and whether an unverified answer is final about this image (see
    /// [`ozbox_core::Verdict::definitive`]).
    fn inspect_full(&self, img: &Image, region: Option<&str>) -> (ImageInfo, bool) {
        let release = self.release_of(img);
        let (verdict, facts) = match (&release, region) {
            (Some(r), Some(region)) => self.releases.verify_image(r, region, &img.image_id),
            (None, _) => (ozbox_core::Verdict {
                verified: false,
                detail: format!(
                    "image {} carries no {TAG_IMAGE} release tag, so it is not a signed Oz release",
                    img.image_id
                ),
                definitive: false,
            }, Default::default()),
            (Some(_), None) => (ozbox_core::Verdict {
                verified: false,
                detail:
                    "no region is configured, so the image cannot be matched to the signed manifest"
                        .into(),
                definitive: false,
            }, Default::default()),
        };
        let definitive = verdict.definitive;
        (
            ImageInfo {
                id: img.image_id.clone(),
                release,
                created: img.creation_date.clone(),
                signature_verified: verdict.verified,
                signature_detail: Some(verdict.detail),
                signature_applicable: true,
                first_boot_sha256: facts.first_boot.filter(|_| verdict.verified),
                upgrade: facts.upgrade.filter(|_| verdict.verified),
                skipped: Vec::new(),
            },
            definitive,
        )
    }

    /// A new box's spec with the fleet's secrets key in its labels, when the configuration names one (and the spec does
    /// not already carry one).
    fn with_secrets_key(&self, spec: &BoxSpec) -> BoxSpec {
        let mut spec = spec.clone();
        // A new box (a clone of a box that is moving its store, say) never starts with the pending mark: it has no store to
        // move, and the mark would make it refuse upgrades until someone cancelled a move that never began.
        spec.labels.remove(SECRETS_ADOPT_LABEL);
        if let Some(arn) = self.cfg.secrets_key_arn.as_ref().filter(|a| !a.is_empty()) {
            if !spec.labels.contains_key(SECRETS_KEY_LABEL) {
                spec.labels.insert(SECRETS_KEY_LABEL.into(), arn.clone());
                spec.labels.insert(
                    SECRETS_FLEET_LABEL.into(),
                    self.cfg.fleet.clone().unwrap_or_else(|| "ozbox".into()),
                );
            }
        }
        spec
    }

    /// Whether an image id is still there (read-only). A failed call other than "not found" is an error, never "gone".
    fn image_exists(&self, image: &str, region: Option<&str>) -> Result<bool> {
        match self
            .at(region)
            .run_json::<Images>(&["ec2", "describe-images", "--image-ids", image])
        {
            Ok(found) => Ok(found
                .images
                .iter()
                .any(|i| i.state.as_deref() == Some("available"))),
            Err(e) if e.to_string().contains("InvalidAMIID") => Ok(false),
            Err(e) => Err(e),
        }
    }

    fn image_still_exists(&self, image: &str, region: Option<&str>) -> Result<()> {
        if image.starts_with("ami-") && !self.image_exists(image, region)? {
            return Err(Error::Config(format!(
                "image {image} no longer exists in {} (images outside the retention window are retired). For a box on a retired image, run `ozbox upgrade <box>` first; for a new box, name a current image with --image or leave it out to use the newest.",
                region.unwrap_or("the default region")
            )));
        }
        Ok(())
    }

    /// The image to use among the caller's own Oz images: walked like the public path, the newest release this program can
    /// use first, and the first that verifies wins (a pre-release is skipped by a stable program, by the signed manifest's
    /// own field). When the best candidate's check FAILED (a download, the signature), it is returned unverified and no older
    /// one is tried; the same when time runs out. When every candidate was definitively refused, the newest is returned
    /// unverified, as before (the caller refuses it unless told otherwise).
    fn pick_own(&self, images: &[Image], region: Option<&str>) -> ImageInfo {
        let program = self.program();
        let rel = |i: &Image| tag(&i.tags, TAG_IMAGE).unwrap_or("").to_string();
        let fits = |i: &Image| {
            ozbox_core::release::compat(&program, &rel(i))
                == ozbox_core::release::Compat::Compatible
        };
        let mut order: Vec<&Image> = images.iter().collect();
        order.sort_by(|a, b| {
            fits(b)
                .cmp(&fits(a))
                .then_with(|| public_images::version_order(&rel(b), &rel(a)))
                .then_with(|| (&b.creation_date, &b.image_id).cmp(&(&a.creation_date, &a.image_id)))
        });
        order.truncate(public_images::MAX_PUBLIC_CANDIDATES);
        let started = std::time::Instant::now();
        let deadline = self
            .cfg
            .public_lookup_deadline
            .unwrap_or(public_images::LOOKUP_DEADLINE);
        let mut first = None;
        let mut skipped: Vec<String> = Vec::new();
        for img in order {
            if first.is_some() && started.elapsed() >= deadline {
                break;
            }
            let (info, definitive) = self.inspect_full(img, region);
            if info.signature_verified {
                if self.is_prerelease_for_stable_program(&program, img, region) {
                    skipped.push(skip_line(
                        &info,
                        "a pre-release, which a stable program does not use",
                    ));
                    // kept only as an UNVERIFIED answer: a stable program is never handed a pre-release as a verified image
                    first.get_or_insert(ImageInfo {
                        signature_verified: false,
                        signature_detail: Some(
                            "pre-release, not used by a stable program".to_string(),
                        ),
                        first_boot_sha256: None,
                        upgrade: None,
                        ..info
                    });
                    continue;
                }
                return ImageInfo { skipped, ..info };
            }
            if !definitive {
                // The check itself failed: no older image is tried in its place.
                let mut answer = first.unwrap_or(info);
                answer.skipped = without_own_line(skipped, &answer.id);
                return answer;
            }
            skipped.push(skip_line(
                &info,
                info.signature_detail
                    .as_deref()
                    .unwrap_or("its signed release could not be verified"),
            ));
            first.get_or_insert(info);
        }
        // `images` is not empty, so there is a first (every verified pre-release in it was stored unverified)
        let mut answer = first.unwrap_or_else(|| self.inspect(&images[0], region));
        answer.skipped = without_own_line(skipped, &answer.id);
        answer
    }

    /// A stable program never boots a pre-release by default. Decided from the verified manifest's own field.
    fn is_prerelease_for_stable_program(
        &self,
        program: &str,
        img: &Image,
        region: Option<&str>,
    ) -> bool {
        if program.contains('-') {
            return false;
        }
        let (Some(release), Some(region)) = (self.release_of(img), region) else {
            return false;
        };
        let (_, facts) = self.releases.verify_image(&release, region, &img.image_id);
        facts.prerelease == Some(true)
    }

    /// The newest public image of `publisher` that this program can use and the signed manifest vouches for. Never returns
    /// an image that is not verified: a public image is a stranger's machine until the signed manifest says otherwise.
    fn latest_public(&self, publisher: &str, region: Option<&str>) -> Result<ImageInfo> {
        let where_ = region.unwrap_or("the default region");
        let found: Images = self.at(region).run_json(&[
            "ec2",
            "describe-images",
            "--owners",
            publisher,
            "--filters",
            "Name=state,Values=available",
            "Name=architecture,Values=x86_64",
            "Name=name,Values=ozbox-*",
        ])?;
        let candidates: Vec<public_images::PublicCandidate> = found
            .images
            .iter()
            .map(|i| public_images::PublicCandidate {
                id: i.image_id.clone(),
                // an image with no owner in the answer is never trusted
                owner: i.owner_id.clone().unwrap_or_default(),
                name: i.name.clone().unwrap_or_default(),
                created: i.creation_date.clone(),
            })
            .collect();
        let (ranked, mut refused) = public_images::rank(&candidates, publisher, &self.program());
        if ranked.is_empty() {
            let regions = public_images::PUBLIC_IMAGE_REGIONS.join(", ");
            let mut msg = format!(
                "no Oz image found in {where_}: this account has none, and the Oz Box publisher (account {publisher}) has no public image here. The public images are in {regions}; use one of those regions, or build your own image (infra/README.md), or pass --image with an image id."
            );
            for r in &refused {
                msg.push_str(&format!(" Refused: {r}."));
            }
            return Err(Error::Config(msg));
        }
        let Some(region) = region else {
            return Err(Error::Config(
                "no region is configured, so a public image cannot be matched to the signed manifest: pass --region or set `region` under [aws]".into(),
            ));
        };
        let started = std::time::Instant::now();
        let deadline = self
            .cfg
            .public_lookup_deadline
            .unwrap_or(public_images::LOOKUP_DEADLINE);
        let mut skipped: Vec<String> = Vec::new();
        for r in &ranked {
            if started.elapsed() >= deadline {
                return Err(Error::Config(format!(
                    "looking for a public Oz image in {where_} took longer than {} seconds, so it was given up and nothing was created. Try again, or pass --image with an image id you trust.",
                    deadline.as_secs()
                )));
            }
            let img = found
                .images
                .iter()
                .find(|i| i.image_id == r.candidate.id)
                .ok_or_else(|| Error::Config("an image vanished from the answer".into()))?;
            let (verdict, facts) = self
                .releases
                .verify_image(&r.release, region, &img.image_id);
            if verdict.verified && facts.prerelease == Some(true) && !self.program().contains('-') {
                // A stable program is not handed a pre-release: the signed manifest says it is one (the name is not asked).
                skipped.push(format!(
                    "{} (release {}): a pre-release, which a stable program does not use",
                    img.image_id, r.release
                ));
                continue;
            }
            if verdict.verified {
                return Ok(ImageInfo {
                    id: img.image_id.clone(),
                    release: Some(r.release.clone()),
                    created: img.creation_date.clone(),
                    signature_verified: true,
                    signature_detail: Some(verdict.detail),
                    signature_applicable: true,
                    first_boot_sha256: facts.first_boot,
                    upgrade: facts.upgrade,
                    skipped,
                });
            }
            if !verdict.definitive {
                // The check itself failed (a download, or the signature): that says nothing about this image, so an older one
                // is not tried in its place. A better release must not be skipped for a worse one on a bad day.
                return Err(Error::Config(format!(
                    "the newest public Oz image for this program, {} (release {}), could not be checked, so nothing was created and no older image was tried: {}. Try again, or pass --image with an image id you trust (the check needs curl and cosign).",
                    img.image_id, r.release, verdict.detail
                )));
            }
            skipped.push(format!(
                "{} (release {}): {}",
                img.image_id, r.release, verdict.detail
            ));
        }
        refused.extend(skipped);
        Err(Error::Config(format!(
            "no public Oz image in {where_} could be verified, so none was used. {} Nothing was created. Pass --image with the id of an image you trust (an upgrade also needs --allow-unverified-image for one that is not a signed release), or fix the signature check (it needs curl and cosign).",
            refused
                .iter()
                .map(|r| format!("Refused: {r}."))
                .collect::<Vec<_>>()
                .join(" ")
        )))
    }

    fn image_for(&self, spec: &BoxSpec) -> Option<String> {
        spec.image.clone().or_else(|| self.cfg.image.clone())
    }

    /// The labels the box carries now, as the module must be given them again so an apply changes nothing it does not mean to:
    /// every tag but the ones the module sets itself and the bookkeeping marks.
    fn current_labels(
        &self,
        rec: &BoxRecord,
    ) -> Result<std::collections::BTreeMap<String, String>> {
        Ok(if rec.state == BoxState::InstanceMissing {
            // The machine is gone: what the module set on it survives on the /work volume it also tagged.
            let v = self.stranded_volume(rec)?;
            Self::labels_of(&v.tags)
        } else {
            let id = Self::instance_id(rec)?;
            let r: Reservations =
                self.at_rec(rec)
                    .run_json(&["ec2", "describe-instances", "--instance-ids", id])?;
            r.reservations
                .iter()
                .flat_map(|r| &r.instances)
                .flat_map(|i| &i.tags)
                .filter(|t| {
                    // The module sets these itself; the marks are bookkeeping and must not be copied onto new
                    // resources.
                    !matches!(
                        t.key.as_str(),
                        "ozbox-box"
                            | "ozbox-managed"
                            | "ozbox-region"
                            | "ozbox-role"
                            | "Name"
                            | RESUME_AFTER_LABEL
                            | UPGRADE_TO_LABEL
                            | UPGRADE_MACHINE_TAG
                            | ozbox_core::FIRST_BOOT_LABEL
                    ) && !t.key.starts_with("aws:")
                })
                .map(|t| (t.key.clone(), t.value.clone()))
                .collect()
        })
    }

    /// The module variables for replacing a box's machine: everything as the box is NOW (its type after any resize,
    /// its disk after any growth, every tag it carries), with only the image changed. Anything else would make the
    /// apply change more than the image.
    fn upgrade_vars(&self, rec: &BoxRecord, image: &str) -> Result<ModuleVars> {
        let labels = self.current_labels(rec)?;
        let mut spec = rec.spec.clone();
        spec.image = Some(image.to_string());
        spec.from_snapshot = None;
        spec.labels = labels;
        // A box made with no pinned approver gets this computer's key, in its new first-boot configuration, as `create`
        // pins one. A box that has one keeps it (the instance tag is not the box's to change).
        if let Some(pin) = &self.cfg.upgrade_pin {
            spec.labels
                .entry(ozbox_core::APPROVER_LABEL.to_string())
                .or_insert_with(|| pin.clone());
        }
        // a box moved to the fleet key (the caller checked its store is empty): the new machine carries the key's labels, which
        // is where every later upgrade reads it from. A box already on a key keeps it.
        if self.cfg.upgrade_use_fleet_key && !spec.labels.contains_key(SECRETS_KEY_LABEL) {
            spec = self.with_secrets_key(&spec);
        }
        // the same for the ingress account's key: a box with the label keeps its own
        if let Some(pin) = &self.cfg.upgrade_ingress_pin {
            spec.labels
                .entry(ozbox_core::INGRESS_LABEL.to_string())
                .or_insert_with(|| pin.clone());
        }
        let Some(machine_type) = rec.machine_type.clone() else {
            return Err(Error::Config(format!(
                "{} has no machine and its /work disk does not say which machine type it ran, so ozbox cannot rebuild it safely. Nothing was changed; the disk is kept.",
                rec.spec.name
            )));
        };
        Ok(self.vars(&spec, &machine_type))
    }

    /// Where a box's secrets key stands, from its labels.
    pub fn secrets_key_stage(rec: &BoxRecord) -> SecretsKeyStage {
        if let Some(k) = rec.spec.labels.get(SECRETS_KEY_LABEL) {
            SecretsKeyStage::Fleet(k.clone())
        } else if let Some(k) = rec.spec.labels.get(SECRETS_ADOPT_LABEL) {
            SecretsKeyStage::Pending(k.clone())
        } else {
            SecretsKeyStage::File
        }
    }

    /// The fleet key this computer is configured with, and its fleet name; `None` when the configuration names none.
    pub fn configured_fleet_key(&self) -> Option<(String, String)> {
        let arn = self
            .cfg
            .secrets_key_arn
            .as_ref()
            .filter(|a| !a.is_empty())?;
        Some((
            arn.clone(),
            self.cfg.fleet.clone().unwrap_or_else(|| "ozbox".into()),
        ))
    }

    /// Plan, with the guard, one in-place step of moving a box's secrets store to the fleet key: `Begin` grants the box's
    /// role the key and marks the box as moving (the pending label); `Finish` writes the real label (and takes the pending
    /// one off) once the box has said its store is wrapped by the key; `Cancel` takes the pending mark and the grant back.
    /// Nothing is replaced: OpenTofu's plan may update tags and create (or, for `Cancel`, destroy) the role's fleet-key policy attachment and
    /// nothing else, and `/work` is never created or destroyed. Apply the result with [`AwsBackend::apply_secrets_key_step`].
    pub fn plan_secrets_key_step(
        &self,
        rec: &BoxRecord,
        step: SecretsKeyStep,
    ) -> Result<ozbox_core::ReplacePlan> {
        if rec.state == BoxState::InstanceMissing {
            return Err(Error::Config(format!(
                "{} has no machine, so there is nothing to move to the fleet key; finish its upgrade first.",
                rec.spec.name
            )));
        }
        let stage = Self::secrets_key_stage(rec);
        let mut labels = self.current_labels(rec)?;
        match (step, &stage) {
            (SecretsKeyStep::Begin, SecretsKeyStage::File | SecretsKeyStage::Pending(_)) => {
                let (arn, fleet) = match &stage {
                    // keep moving to the key the box already carries, never to a different one
                    SecretsKeyStage::Pending(k) => (
                        k.clone(),
                        // The fleet decides whether the role may use the key (the key policy matches its tag), so a guess
                        // would leave the box probing a key it is never allowed to use. The box's own label, else the
                        // configured fleet when it names this very key; otherwise refuse.
                        labels
                            .get(SECRETS_FLEET_LABEL)
                            .cloned()
                            .or_else(|| {
                                self.configured_fleet_key()
                                    .filter(|(arn, _)| arn == k)
                                    .map(|(_, fleet)| fleet)
                            })
                            .ok_or_else(|| {
                                Error::Config(format!(
                                    "{} is moving to a fleet key but carries no fleet name, and the fleet configured here does not name that key, so ozbox cannot tell which fleet's key policy applies. Nothing was changed. Configure that fleet under [aws] (secrets_key_arn and fleet) or cancel the move.",
                                    rec.spec.name
                                ))
                            })?,
                    ),
                    _ => self.configured_fleet_key().ok_or_else(|| {
                        Error::Config(
                            "no fleet key is configured: set secrets_key_arn and fleet under [aws] (from the aws-secrets-key module)"
                                .into(),
                        )
                    })?,
                };
                labels.insert(SECRETS_ADOPT_LABEL.into(), arn);
                labels.insert(SECRETS_FLEET_LABEL.into(), fleet);
            }
            (SecretsKeyStep::Finish, SecretsKeyStage::Pending(arn)) => {
                labels.remove(SECRETS_ADOPT_LABEL);
                labels.insert(SECRETS_KEY_LABEL.into(), arn.clone());
            }
            (SecretsKeyStep::Cancel, SecretsKeyStage::Pending(_)) => {
                labels.remove(SECRETS_ADOPT_LABEL);
                labels.remove(SECRETS_FLEET_LABEL);
            }
            (_, SecretsKeyStage::Fleet(_)) => {
                return Err(Error::Config(format!(
                    "{} already keeps its secrets store's key in the fleet's KMS key; there is nothing to move.",
                    rec.spec.name
                )))
            }
            (SecretsKeyStep::Finish | SecretsKeyStep::Cancel, _) => {
                return Err(Error::Config(format!(
                    "{} is not moving to the fleet key (it carries no pending mark).",
                    rec.spec.name
                )))
            }
        }
        let Some(machine_type) = rec.machine_type.clone() else {
            return Err(Error::Config(format!(
                "{} does not say which machine type it runs, so ozbox cannot plan a change to it safely. Nothing was changed.",
                rec.spec.name
            )));
        };
        let mut spec = rec.spec.clone();
        // the image the machine runs now (a different one would replace it), and no snapshot (that is for creating a disk)
        spec.from_snapshot = None;
        spec.labels = labels;
        let vars = self.vars(&spec, &machine_type);
        let may_delete: &[&str] = if step == SecretsKeyStep::Cancel {
            &[ADOPT_ROLE_POLICY]
        } else {
            &[]
        };
        // the role's fleet tag may take the fleet this step is for and no other (none at all for a cancel: it is only taken away)
        let fleet = vars.extra.get("fleet").cloned();
        self.tofu.plan_in_place(
            &vars,
            &[ADOPT_ROLE_POLICY],
            may_delete,
            IN_PLACE_PROTECTED,
            ozbox_core::tofu::FleetTag::Is(fleet.as_deref()),
        )
    }

    /// Run one fixed program as root on the box through AWS Systems Manager Run Command and return what it printed.
    ///
    /// This is the channel for facts a decision rests on: the output is made by the SSM agent running that program as root,
    /// and the box user is not in the path, unlike SSH as that user, whose answer it can forge. It needs the operator's AWS
    /// sign-in to hold the policy the `aws-adopt-command` module outputs (`operator_adopt_policy_json`: `ssm:SendCommand` on the fleet's
    /// adopt document only, to boxes tagged `ozbox-managed`, plus reading a command's result); the box's role already
    /// carries the account's `ozbox-box-session-manager` policy (made once by `ozbox init`: the Run Command agent's registration,
    /// document fetch and reply, and nothing that reads a value). Anything but a clean `Success` is an error and nothing is decided from it.
    pub fn root_command(&self, rec: &BoxRecord, which: RootCommand) -> Result<String> {
        let id = Self::instance_id(rec)?;
        let s = self.at_rec(rec);
        let (_, fleet) = self.configured_fleet_key().ok_or_else(|| {
            Error::Config(
                "this computer has no fleet key configured, so it does not know which Systems Manager document reaches the box's root (the one the aws-adopt-command module makes, ozbox-adopt-<fleet>)".into(),
            )
        })?;
        let document = adopt_document_name(&fleet);
        let hash = ozbox_catalog::verify::sha256_hex(ADOPT_DOCUMENT.as_bytes());
        let params = format!("{{\"action\":[\"{}\"]}}", which.action());
        let sent: serde_json::Value = s
            .run_json(&[
                "ssm",
                "send-command",
                "--instance-ids",
                id,
                "--document-name",
                &document,
                "--document-hash",
                &hash,
                "--document-hash-type",
                "Sha256",
                "--comment",
                "ozbox adopt-fleet-key",
                "--timeout-seconds",
                ROOT_DELIVERY_SECS,
                "--parameters",
                &params,
            ])
            .map_err(|e| send_refused(e, &document))?;
        let command_id = sent
            .pointer("/Command/CommandId")
            .and_then(|v| v.as_str())
            .filter(|c| !c.is_empty() && c.bytes().all(|b| b.is_ascii_hexdigit() || b == b'-'))
            .ok_or_else(|| Error::Config("Systems Manager did not return a command id".into()))?
            .to_string();
        let polls = which.polls();
        for poll in 0..polls {
            // the invocation can take a moment to exist after the send, which is not an answer yet; a REFUSAL is, and it is
            // reported at once instead of being waited out
            let out = self
                .runner
                .run(&s.aws(&[
                    "ssm",
                    "get-command-invocation",
                    "--command-id",
                    &command_id,
                    "--instance-id",
                    id,
                ]))
                .map_err(|e| Error::Config(format!("Systems Manager could not be asked ({e})")))?;
            if out.status != Some(0) {
                let low = out.stderr.to_ascii_lowercase();
                if low.contains("accessdenied")
                    || low.contains("not authorized")
                    || low.contains("unauthorizedoperation")
                {
                    return Err(Error::Config(
                        "Systems Manager refused to show this computer the command's result (AccessDeniedException: the AWS sign-in needs ssm:GetCommandInvocation, which the aws-adopt-command module's operator policy carries)".into(),
                    ));
                }
            } else if let Ok(v) = serde_json::from_str::<serde_json::Value>(&out.stdout) {
                match v.get("Status").and_then(|x| x.as_str()) {
                    Some("Success") => {
                        let text = v
                            .get("StandardOutputContent")
                            .and_then(|x| x.as_str())
                            .unwrap_or("");
                        return Ok(text.chars().take(16 * 1024).collect());
                    }
                    Some("Failed") if program_unknown(&v) => {
                        return Err(Error::Config(ROOT_PROGRAM_OLDER.into()));
                    }
                    Some(st @ ("Failed" | "TimedOut" | "Cancelled" | "Cancelling")) => {
                        return Err(Error::Config(format!(
                            "the box's root helper did not finish ({st}{})",
                            failure_hint(&v)
                        )));
                    }
                    _ => {}
                }
            }
            if poll + 1 < polls {
                // (no wait under test: the poll count is what a test pins)
                if !cfg!(test) {
                    std::thread::sleep(std::time::Duration::from_secs(ROOT_POLL_SECS));
                }
            }
        }
        // The command is NOT cancelled. A command that has not started is dropped by Systems Manager at its delivery timeout
        // (which is shorter than this wait), and one that is running is a move or a cancel that must not be killed part way.
        Err(Error::Config(
            "the box's root helper did not answer in time (it may still be running: ask for the box's facts again before anything else)".into(),
        ))
    }

    /// Whether the cloud's own record shows NO key label on the box's instance: a read of its tags that succeeded and listed none
    /// of the two. `Ok(false)` when one is there; `Err` when the read did not work or was not understood, which is never
    /// "no tag". The laptop's offer to put a pre-move copy back rests on this (the box's own read of its tags is not enough).
    pub fn secrets_tags_absent(&self, rec: &BoxRecord) -> Result<bool> {
        let id = Self::instance_id(rec)?;
        let s = self.at_rec(rec);
        let filter_id = format!("Name=resource-id,Values={id}");
        let filter_key = format!("Name=key,Values={SECRETS_ADOPT_LABEL},{SECRETS_KEY_LABEL}");
        let v: serde_json::Value =
            s.run_json(&["ec2", "describe-tags", "--filters", &filter_id, &filter_key])?;
        let tags = v.get("Tags").and_then(|t| t.as_array()).ok_or_else(|| {
            Error::Config(
                "the cloud's list of the box's tags was not in a shape this program knows".into(),
            )
        })?;
        Ok(tags.is_empty())
    }

    /// Apply a plan from [`AwsBackend::plan_secrets_key_step`].
    pub fn apply_secrets_key_step(&self, plan: &ozbox_core::ReplacePlan) -> Result<()> {
        self.tofu.apply_replace(plan).map(|_| ())
    }

    /// Plan, with the guard, what this upgrade is about to apply: a replacement while the machine exists, the creation
    /// of the machine when it is already gone. Either way the `/work` volume may not be deleted, replaced or created.
    fn guarded_plan(
        &self,
        vars: &ModuleVars,
        machine_gone: bool,
    ) -> Result<ozbox_core::ReplacePlan> {
        if machine_gone {
            self.tofu.plan_finish(
                vars,
                UPGRADE_REPLACES,
                UPGRADE_MAY_ALSO_REPLACE,
                UPGRADE_PROTECTED,
            )
        } else {
            self.tofu.plan_replace(
                vars,
                UPGRADE_REPLACES,
                UPGRADE_MAY_ALSO_REPLACE,
                UPGRADE_PROTECTED,
            )
        }
    }

    fn vars(&self, spec: &BoxSpec, machine_type: &str) -> ModuleVars {
        let mut extra = std::collections::BTreeMap::new();
        if let Some(s) = &self.cfg.subnet_id {
            extra.insert("subnet_id".to_string(), s.clone());
        }
        if let Some(k) = &self.cfg.kms_key_arn {
            extra.insert("kms_key_arn".to_string(), k.clone());
        }
        // The secrets key is the box's own (its label), never today's configuration: a store sealed with a file-kept key
        // must not come back on a machine told to use KMS, and the reverse.
        // (A box that is moving to the fleet key has the key under the pending label: the role keeps its grant while it does.)
        if let Some(k) = spec
            .labels
            .get(SECRETS_KEY_LABEL)
            .or_else(|| spec.labels.get(SECRETS_ADOPT_LABEL))
        {
            extra.insert("secrets_key_arn".to_string(), k.clone());
            extra.insert(
                "fleet".to_string(),
                spec.labels
                    .get(SECRETS_FLEET_LABEL)
                    .cloned()
                    .unwrap_or_else(|| "ozbox".into()),
            );
        }
        if let Some(g) = self.cfg.root_disk_gb {
            extra.insert("root_disk_gb".to_string(), g.to_string());
        }
        // the opt-in security services (see the aws-security-baseline module): a box joins them through these two
        if let Some(b) = &self.cfg.session_log_bucket {
            extra.insert("session_log_bucket".to_string(), b.clone());
        }
        if let Some(g) = &self.cfg.patch_group {
            extra.insert("patch_group".to_string(), g.clone());
        }
        // how many agent runs the box daemon runs at once: the same cap the dashboard's supervisor applies for the size
        extra.insert(
            "runs_max_active".to_string(),
            ozbox_core::supervisor::size_cap(spec.size).to_string(),
        );
        // which first-boot configuration the machine is made with, recorded on the box (`/etc/ozbox/first-boot`)
        if let Some(h) = &self.cfg.first_boot_sha256 {
            extra.insert("first_boot_sha256".to_string(), h.clone());
        }
        ModuleVars {
            box_name: spec.name.clone(),
            machine_type: machine_type.to_string(),
            work_disk_gb: spec.work_disk_gb,
            image_id: self.image_for(spec).unwrap_or_default(),
            region: spec.region.clone().or_else(|| self.cfg.region.clone()),
            // the provider's own record of a machine's first boot is the module's to set, never a label passed back
            labels: spec
                .labels
                .iter()
                .filter(|(k, _)| k.as_str() != ozbox_core::FIRST_BOOT_LABEL)
                .map(|(k, v)| (k.clone(), v.clone()))
                .collect(),
            work_snapshot_id: spec.from_snapshot.clone(),
            extra,
        }
    }
}

impl Backend for AwsBackend {
    fn id(&self) -> &str {
        PROVIDER_ID
    }

    fn capabilities(&self) -> Capabilities {
        capabilities()
    }

    fn machine_choice(&self, size: Size) -> Result<MachineChoice> {
        machine_choice(size)
    }

    fn check_create(&self, spec: &BoxSpec) -> Result<()> {
        if self.cfg.subnet_id.as_deref().is_none_or(str::is_empty) {
            return Err(Error::Config(
                "no subnet: set `subnet_id` (a private subnet) under [aws] in the config".into(),
            ));
        }
        let Some(region) = spec.region.as_deref().or(self.cfg.region.as_deref()) else {
            return Err(Error::Config(
                "no region: pass --region or set `region` under [aws] in the config".into(),
            ));
        };
        // A box ozbox cannot find again is a box nobody pays attention to: refuse to create it outside
        // the regions `list` searches.
        let searched = self.search_regions();
        if !searched.is_empty() && !searched.iter().any(|r| r == region) {
            return Err(Error::Config(format!(
                "region {region} is not one ozbox searches ({}): add it to `regions` under [aws] first",
                searched.join(", ")
            )));
        }
        let Some(image) = self.image_for(spec) else {
            return Err(Error::Config(
                "no image to boot from: pass --image or set `image` under [aws] in the config"
                    .into(),
            ));
        };
        // An image outside the retention window is retired. A clone (and a create from a stale configuration) names
        // it: say so now, before anything is planned, rather than letting the cloud refuse it half way through.
        self.image_still_exists(&image, Some(region))?;
        Ok(())
    }

    fn check_capacity(&self, req: &CapacityRequest) -> Result<Vec<String>> {
        self.vcpu_capacity(req)
    }

    fn latest_image(&self, region: Option<&str>) -> Result<ImageInfo> {
        let region = region.or(self.cfg.region.as_deref());
        // 1. An Oz image in the caller's own account: one this account built (or copied and tagged), which is a deliberate
        //    choice, so it wins over anything public.
        let found: Images = self.at(region).run_json(&[
            "ec2",
            "describe-images",
            "--owners",
            "self",
            "--filters",
            "Name=tag-key,Values=ozbox-image",
            "Name=tag:ozbox-managed,Values=true",
            "Name=state,Values=available",
            "Name=architecture,Values=x86_64",
        ])?;
        if !found.images.is_empty() {
            return Ok(self.pick_own(&found.images, region));
        }
        // 2. The project's public images, only those the publisher account owns and the signed manifest lists.
        let Some(publisher) = self.publisher() else {
            return Err(Error::Config(format!(
                "no Oz image found in {}: this account has no available image tagged {TAG_IMAGE}, and public images are turned off (`image_publisher = \"none\"`); pass --image with an image id",
                region.unwrap_or("the default region")
            )));
        };
        self.latest_public(&publisher, region)
    }

    fn image_info(&self, image: &str, region: Option<&str>) -> Result<ImageInfo> {
        let region = region.or(self.cfg.region.as_deref());
        let found: Images = self
            .at(region)
            .run_json(&["ec2", "describe-images", "--image-ids", image])
            .map_err(|_| {
                Error::Config(format!(
                    "image {image} was not found in {}: images belong to one region, so use the id from the box's own region",
                    region.unwrap_or("the default region")
                ))
            })?;
        let img = found.images.first().ok_or_else(|| {
            Error::Config(format!(
                "image {image} was not found in {}",
                region.unwrap_or("the default region")
            ))
        })?;
        Ok(self.inspect(img, region))
    }

    /// An upgrade replaces the machine (`-replace=aws_instance.box`) with user data rendered now, so the same image
    /// gets a fresh first boot.
    fn check_reprovision(&self, rec: &BoxRecord) -> Result<Vec<String>> {
        // The same image is used again: it has to still exist (images outside the retention window are retired).
        if let Some(image) = rec.spec.image.as_deref().filter(|i| i.starts_with("ami-")) {
            let region = rec.spec.region.as_deref().or(self.cfg.region.as_deref());
            if !self.image_exists(image, region)? {
                return Err(Error::Config(format!(
                    "{0} runs image {image}, which no longer exists (images outside the retention window are retired), so its machine cannot be rebuilt from it. Run `ozbox upgrade {0}` to move it to a current image; /work is kept.",
                    rec.spec.name
                )));
            }
        }
        Ok(Vec::new())
    }

    fn check_upgrade(&self, rec: &BoxRecord, image: &str) -> Result<Vec<String>> {
        // A replacement machine is configured from the box's labels: with the key on them it would start on KMS over a
        // store still wrapped by a file key, which never opens (and recovery refuses a KMS box). So not while moving.
        if let SecretsKeyStage::Pending(_) = Self::secrets_key_stage(rec) {
            return Err(Error::Config(format!(
                "{0} is moving its secrets store to the fleet's KMS key and the box has not said it finished, so its system disk cannot be replaced yet (the new machine would start on the new key over a store still sealed by the old one). Nothing was changed. Run `ozbox adopt-fleet-key {0}` again to finish it (or `ozbox adopt-fleet-key {0} --cancel` to leave the box as it was).",
                rec.spec.name
            )));
        }
        if !image.starts_with("ami-") {
            return Err(Error::Config(format!(
                "{image:?} is not an AWS image id (they look like ami-0123456789abcdef0)"
            )));
        }
        let s = self.at_rec(rec);
        let region = rec.spec.region.as_deref().or(self.cfg.region.as_deref());
        let found: Images = s
            .run_json(&["ec2", "describe-images", "--image-ids", image])
            .map_err(|_| {
                Error::Config(format!(
                    "image {image} was not found in {}: images belong to one region, so use the id from the box's own region",
                    region.unwrap_or("the default region")
                ))
            })?;
        let img = found.images.first().ok_or_else(|| {
            Error::Config(format!(
                "image {image} was not found in {}",
                region.unwrap_or("the default region")
            ))
        })?;
        if img.state.as_deref().is_some_and(|st| st != "available") {
            return Err(Error::Config(format!(
                "image {image} is {}, not available yet; try again when it is",
                img.state.as_deref().unwrap_or("not ready")
            )));
        }
        let mut notes = Vec::new();
        let machine = rec.machine_type.clone().unwrap_or_default();
        let want = arch_of_instance_type(&machine);
        match img.architecture.as_deref() {
            Some(a) if a == want => {}
            Some(a) => {
                return Err(Error::Unsupported {
                    provider: PROVIDER_ID.into(),
                    what: format!("upgrade {} to image {image}", rec.spec.name),
                    why: format!(
                        "the image is for {a} machines and this box runs on {machine} ({want}); resize the box to a matching size first, or choose another image"
                    ),
                })
            }
            None => notes.push(format!(
                "AWS did not say which architecture image {image} is for, so it could not be checked against {machine}."
            )),
        }
        if self.release_of(img).is_none() {
            notes.push(format!(
                "Image {image} does not carry the {TAG_IMAGE} tag, so it may not be an Oz image."
            ));
        }
        if self.cfg.upgrade_pin.is_some()
            && !rec.spec.labels.contains_key(ozbox_core::APPROVER_LABEL)
        {
            notes.push(
                "This box has no pinned approver: its new first-boot configuration pins this computer's approval key, as `ozbox create` does (the box user cannot change it), so the box can be approved from here and is no longer in bootstrap."
                    .into(),
            );
        }
        if self.configured_fleet_key().is_some()
            && !self.cfg.upgrade_use_fleet_key
            && Self::secrets_key_stage(rec) == SecretsKeyStage::File
        {
            notes.push(format!(
                "A fleet KMS key is configured, and {} does not use it: its secrets store's key is in a file (or a TPM) on the system disk. This upgrade does not change that (starting the new machine on KMS over a store the file key still seals would leave the store unopenable). After it, `ozbox adopt-fleet-key {}` moves the store to the fleet's KMS key in place, keeping what the store holds, so every later upgrade keeps it.",
                rec.spec.name, rec.spec.name
            ));
        }
        if self.cfg.upgrade_use_fleet_key && !rec.spec.labels.contains_key(SECRETS_KEY_LABEL) {
            notes.push(
                "This upgrade moves the box's secrets store from a key kept in a file to the fleet's KMS key (--use-fleet-key). It is allowed because the store holds nothing; every later upgrade then keeps the store. The box's role may use that key only for this box's own secrets."
                    .into(),
            );
        }
        if self.cfg.upgrade_ingress_pin.is_some()
            && !rec.spec.labels.contains_key(ozbox_core::INGRESS_LABEL)
        {
            notes.push(
                "This box has no pinned key for its ingress account: its new first-boot configuration pins this computer's SSH key for it, so `ozbox secrets import --box` can reach the box's secrets service (the box user cannot change it)."
                    .into(),
            );
        }
        // The /work volume must survive: ask OpenTofu what it would do, read-only, before anything is stopped.
        let vars = self.upgrade_vars(rec, image)?;
        let gone = rec.state == BoxState::InstanceMissing;
        let plan = self.guarded_plan(&vars, gone)?;
        notes.push(format!(
            "OpenTofu checked the change first and it {} only the machine and its /work attachment; the /work volume is kept ({}).",
            if gone { "creates" } else { "replaces" },
            plan.summary.join("; ")
        ));
        Ok(notes)
    }

    fn replace_image(&self, rec: &BoxRecord, image: &str) -> Result<()> {
        let vars = self.upgrade_vars(rec, image)?;
        let mut gone = rec.state == BoxState::InstanceMissing;
        let mut attempt: u32 = 0;
        loop {
            // Planned again right before each apply (a saved plan is stale once an apply has run), so what is
            // applied is exactly what was just checked.
            let plan = self.guarded_plan(&vars, gone)?;
            let failed = match self.tofu.apply_replace(&plan) {
                Ok(_) => return Ok(()),
                Err(e) => e,
            };
            // Only a refusal for lack of capacity or quota is worth another try, and only a few of them.
            if !is_capacity_error(&failed.to_string()) || attempt >= self.cfg.create_retries {
                return Err(failed);
            }
            let pause = self
                .cfg
                .create_backoff
                .saturating_mul(1u32 << attempt.min(16))
                .min(std::time::Duration::from_secs(300));
            attempt += 1;
            std::thread::sleep(pause);
            // The old machine is normally gone by now (the create is what failed): look, rather than assume.
            let region = rec.spec.region.as_deref().or(self.cfg.region.as_deref());
            gone = !self
                .list_in(region)?
                .iter()
                .any(|r| r.spec.name == rec.spec.name && r.state != BoxState::InstanceMissing);
        }
    }

    fn check_system_disk_snapshot(&self, rec: &BoxRecord) -> Result<Option<String>> {
        let name = &rec.spec.name;
        let vol = self.root_volume(rec)?;
        if tag(&vol.tags, "ozbox-managed") != Some("true") {
            return Err(Error::Config(format!(
                "the system disk of {name} ({}) is not tagged ozbox-managed, so this program's AWS permissions cannot snapshot it. Nothing was changed. Pass --no-pre-upgrade-snapshot to go on without a copy of the old system disk, or snapshot it yourself first and keep the id.",
                vol.volume_id
            )));
        }
        // Fail closed: a disk the provider does not say is encrypted is treated as not (an answer without the field is not a yes).
        if vol.encrypted != Some(true) {
            return Err(Error::Config(format!(
                "the system disk of {name} ({}) is not confirmed encrypted, so a copy of it would not be either, and it holds the secrets store's key. Nothing was changed. Pass --no-pre-upgrade-snapshot to go on without a copy.",
                vol.volume_id
            )));
        }
        Ok(Some(format!(
            "Keep a copy of the OLD system disk of {name} (volume {}): an encrypted snapshot tagged {PURPOSE_TAG}={PRE_UPGRADE_ROOT}, taken first, before anything is stopped. It holds the secrets store's key, so it is kept only while you need it (`ozbox backup delete {name} <snapshot id>`); its id is in the report",
            vol.volume_id
        )))
    }

    fn snapshot_system_disk(
        &self,
        rec: &BoxRecord,
        image: &str,
        max_wait: Option<std::time::Duration>,
    ) -> Result<String> {
        let name = &rec.spec.name;
        let vol = self.root_volume(rec)?;
        let s = self.at_rec(rec);
        #[derive(Deserialize)]
        #[serde(rename_all = "PascalCase")]
        struct Created {
            snapshot_id: String,
        }
        let created: Created = s.run_json(&[
            "ec2",
            "create-snapshot",
            "--volume-id",
            &vol.volume_id,
            "--description",
            &format!("ozbox {name} system disk before upgrade (holds the secrets store key; delete when no longer needed)"),
            "--tag-specifications",
            &format!(
                "ResourceType=snapshot,Tags=[{{Key=ozbox-managed,Value=true}},{{Key={TAG_BOX},Value={name}}},{{Key={PURPOSE_TAG},Value={PRE_UPGRADE_ROOT}}},{{Key={UPGRADE_TO_LABEL},Value={image}}},{{Key={SOURCE_VOLUME_TAG},Value={}}}]",
                vol.volume_id
            ),
        ])?;
        // Waited for here, one look at a time, rather than with `aws ec2 wait` (which gives up after about ten minutes and says
        // nothing about which snapshot): nothing has been stopped yet, and the box holds new runs back for ten minutes from the
        // start of the checkpoint that came first, so the copy must be complete well inside that. A copy that is not is named, and
        // finishes by itself.
        let id = &created.snapshot_id;
        let mut seen: Option<Snapshot> = None;
        let mut polls = self.cfg.snapshot_wait_polls.max(1);
        if let Some(d) = max_wait {
            let every = self.cfg.poll_interval.as_secs().max(1);
            polls = polls.min(
                u32::try_from(d.as_secs() / every)
                    .unwrap_or(u32::MAX)
                    .max(1),
            );
        }
        for attempt in 0..polls {
            let listed: Snapshots = s
                .run_json(&["ec2", "describe-snapshots", "--snapshot-ids", id])
                .map_err(|e| {
                    Error::Provider(format!(
                        "snapshot {id} of the system disk of {name} was started but could not be read ({e}); nothing else was changed. It may finish: check it with `aws ec2 describe-snapshots --snapshot-ids {id}`, then delete it with `ozbox backup delete {name} {id}` or use it"
                    ))
                })?;
            let Some(snap) = listed.snapshots.into_iter().find(|x| &x.snapshot_id == id) else {
                return Err(Error::Provider(format!(
                    "snapshot {id} of the system disk of {name} was made but cannot be read back; nothing else was changed"
                )));
            };
            match snap.state.as_deref() {
                Some("completed") => {
                    seen = Some(snap);
                    break;
                }
                Some("pending") | None => {}
                Some(other) => {
                    return Err(Error::Provider(format!(
                        "snapshot {id} of the system disk of {name} ended as {other}; nothing else was changed. Delete it with `ozbox backup delete {name} {id}` and run the upgrade again"
                    )));
                }
            }
            if attempt + 1 < polls {
                std::thread::sleep(self.cfg.poll_interval);
            }
        }
        let Some(snap) = seen else {
            return Err(Error::Provider(format!(
                "snapshot {id} of the system disk of {name} is still being made after {} minutes, so the upgrade stopped before touching anything. The snapshot keeps going by itself and can be used once `aws ec2 describe-snapshots --snapshot-ids {id}` says completed. Run the upgrade again when it has (it takes another copy: delete the older one with `ozbox backup delete {name} {id}` when you do not need it)",
                (u64::from(polls) * self.cfg.poll_interval.as_secs()).div_ceil(60).max(1)
            )));
        };
        // Said by the provider, not assumed: the copy is encrypted, under the key the disk has. Both must be stated and equal; an
        // answer that leaves either out is not a pass. Nothing has been stopped yet, so a copy that is not is refused here and the
        // box is as it was.
        let same_key = matches!((&snap.kms_key_id, &vol.kms_key_id), (Some(a), Some(b)) if a == b);
        if snap.encrypted != Some(true) || !same_key {
            return Err(Error::Provider(format!(
                "snapshot {id} of the system disk of {name} is not confirmed encrypted under the disk's own key, so it is not a safe place for the secrets store's key. Nothing else was changed; delete it with `ozbox backup delete {name} {id}`"
            )));
        }
        Ok(created.snapshot_id)
    }

    fn set_upgrade_mark(&self, rec: &BoxRecord, image: Option<&str>) -> Result<()> {
        let vol = self.work_volume(rec)?;
        let s = self.at_rec(rec);
        match image {
            Some(i) => {
                let mark = format!("Key={UPGRADE_TO_LABEL},Value={i}");
                let machine = rec
                    .machine_type
                    .as_deref()
                    .map(|m| format!("Key={UPGRADE_MACHINE_TAG},Value={m}"));
                let mut args = vec!["ec2", "create-tags", "--resources", &vol, "--tags", &mark];
                if let Some(m) = &machine {
                    args.push(m);
                }
                s.run(&args)?
            }
            None => s.run(&[
                "ec2",
                "delete-tags",
                "--resources",
                &vol,
                "--tags",
                &format!("Key={UPGRADE_TO_LABEL}"),
                &format!("Key={UPGRADE_MACHINE_TAG}"),
            ])?,
        };
        Ok(())
    }

    fn plan_notes(&self, op: &Operation) -> Vec<String> {
        match op {
            Operation::Create { spec } => vec![match self.with_secrets_key(spec).labels.get(SECRETS_KEY_LABEL) {
                Some(arn) => format!("The box's secrets store keeps its key in the fleet's KMS key ({arn}), so an upgrade keeps the store; the box's role may use that key only for this box's own secrets."),
                None => "The box's secrets store keeps its key in a file on the system disk (no KMS key is configured: set secrets_key_arn and fleet under [aws], from the aws-secrets-key module, to use one). An upgrade replaces that disk, so `ozbox upgrade` will ask before it starts a new store, unless the key is escrowed in a vault (box secrets on OpenBao).".to_string(),
            }],
            Operation::Upgrade { .. } => vec![UPGRADE_GAP_NOTE.to_string()],
            Operation::Destroy { name, .. } => vec![format!(
                "Old /work disks that restores of {name} kept are not removed with the box; list them with `ozbox backup list {name}` and delete them first if you do not want them."
            )],
            _ => Vec::new(),
        }
    }

    fn list(&self) -> Result<Vec<BoxRecord>> {
        let regions = self.search_regions();
        if regions.is_empty() {
            return self.list_in(None);
        }
        let mut all = Vec::new();
        for r in &regions {
            all.extend(self.list_in(Some(r))?);
        }
        all.sort_by(|a, b| a.spec.name.cmp(&b.spec.name));
        Ok(all)
    }

    fn searched(&self) -> Vec<String> {
        self.search_regions()
    }

    fn create(&self, spec: &BoxSpec, machine_type: &str) -> Result<BoxRecord> {
        let spec = &self.with_secrets_key(spec);
        self.tofu.apply(&self.vars(spec, machine_type))?;
        let region = spec.region.as_deref().or(self.cfg.region.as_deref());
        self.list_in(region)?
            .into_iter()
            .find(|r| r.spec.name == spec.name)
            .ok_or_else(|| {
                Error::Provider(format!(
                    "box {} was created but is not listed yet; run `ozbox list` again shortly",
                    spec.name
                ))
            })
    }

    fn check_destroy_missing(&self, rec: &BoxRecord) -> Result<Vec<String>> {
        // The /work volume must be exactly one, free, managed volume of this box: the same check every other
        // action on a stranded box makes.
        let vol = self.stranded_volume(rec)?;
        let how = if self.tofu.has_workspace(&rec.spec.name)? {
            "OpenTofu will destroy what its state still holds, including the /work volume, and the box's workspace is removed"
        } else {
            "this computer holds no OpenTofu state for the box, so the /work volume is deleted directly"
        };
        Ok(vec![format!(
            "Volume {} (/work of {}) is deleted for good: {how}. Snapshots of the box are kept.",
            vol.volume_id, rec.spec.name
        )])
    }

    fn destroy(&self, rec: &BoxRecord) -> Result<()> {
        let machine_type = rec.machine_type.clone().unwrap_or_default();
        if rec.state == BoxState::InstanceMissing {
            // Look again right before deleting: the volume is the one thing that cannot be brought back.
            let vol = self.stranded_volume(rec)?.volume_id;
            if self.tofu.has_workspace(&rec.spec.name)? {
                self.tofu.destroy(&self.vars(&rec.spec, &machine_type))?;
            }
            // `tofu destroy` removes the volume when the state holds it; a state that never did (or none) leaves it.
            let region = rec.spec.region.as_deref().or(self.cfg.region.as_deref());
            let left = self
                .list_in(region)?
                .iter()
                .any(|r| r.spec.name == rec.spec.name);
            if left {
                self.at_rec(rec)
                    .run(&["ec2", "delete-volume", "--volume-id", &vol])?;
            }
            return Ok(());
        }
        self.tofu.destroy(&self.vars(&rec.spec, &machine_type))
    }

    fn power_off(&self, rec: &BoxRecord) -> Result<()> {
        let id = Self::instance_id(rec)?;
        let s = self.at_rec(rec);
        s.run(&["ec2", "stop-instances", "--instance-ids", id])?;
        s.run(&["ec2", "wait", "instance-stopped", "--instance-ids", id])?;
        Ok(())
    }

    fn power_on(&self, rec: &BoxRecord) -> Result<()> {
        let id = Self::instance_id(rec)?;
        let s = self.at_rec(rec);
        s.run(&["ec2", "start-instances", "--instance-ids", id])?;
        s.run(&["ec2", "wait", "instance-running", "--instance-ids", id])?;
        Ok(())
    }

    fn set_size(&self, rec: &BoxRecord, _size: Size, machine_type: &str) -> Result<()> {
        let id = Self::instance_id(rec)?;
        self.at_rec(rec).run(&[
            "ec2",
            "modify-instance-attribute",
            "--instance-id",
            id,
            "--instance-type",
            &format!("Value={machine_type}"),
        ])?;
        Ok(())
    }

    fn grow_disk(&self, rec: &BoxRecord, gb: DiskGb) -> Result<()> {
        let vol = self.work_volume(rec)?;
        let s = self.at_rec(rec);
        s.run(&[
            "ec2",
            "modify-volume",
            "--volume-id",
            &vol,
            "--size",
            &gb.to_string(),
        ])?;
        // The new size is usable once the modification reaches `optimizing` (or `completed`).
        #[derive(Deserialize)]
        #[serde(rename_all = "PascalCase")]
        struct Mod {
            modification_state: String,
        }
        #[derive(Deserialize)]
        #[serde(rename_all = "PascalCase")]
        struct Mods {
            #[serde(default)]
            volumes_modifications: Vec<Mod>,
        }
        for attempt in 0..self.cfg.volume_wait_polls {
            let mods: Mods = s.run_json(&[
                "ec2",
                "describe-volumes-modifications",
                "--volume-ids",
                &vol,
            ])?;
            match mods
                .volumes_modifications
                .first()
                .map(|m| m.modification_state.as_str())
            {
                Some("optimizing" | "completed") => return Ok(()),
                Some("failed") => {
                    return Err(Error::Provider(format!(
                        "growing the /work volume of {} failed",
                        rec.spec.name
                    )))
                }
                _ => {}
            }
            if attempt + 1 < self.cfg.volume_wait_polls {
                std::thread::sleep(self.cfg.poll_interval);
            }
        }
        Err(Error::Provider(format!(
            "the /work volume of {} did not finish growing in time; check it with `aws ec2 describe-volumes-modifications`",
            rec.spec.name
        )))
    }

    fn set_resume_after(&self, rec: &BoxRecord, on: bool) -> Result<()> {
        let id = Self::instance_id(rec)?;
        let s = self.at_rec(rec);
        if on {
            s.run(&[
                "ec2",
                "create-tags",
                "--resources",
                id,
                "--tags",
                &format!("Key={RESUME_AFTER_LABEL},Value=true"),
            ])?;
        } else {
            s.run(&[
                "ec2",
                "delete-tags",
                "--resources",
                id,
                "--tags",
                &format!("Key={RESUME_AFTER_LABEL}"),
            ])?;
        }
        Ok(())
    }

    fn snapshot(&self, rec: &BoxRecord) -> Result<String> {
        let vol = self.work_volume(rec)?;
        let s = self.at_rec(rec);
        #[derive(Deserialize)]
        #[serde(rename_all = "PascalCase")]
        struct Created {
            snapshot_id: String,
        }
        let created: Created = s.run_json(&[
            "ec2",
            "create-snapshot",
            "--volume-id",
            &vol,
            "--description",
            &format!("ozbox {} /work", rec.spec.name),
            "--tag-specifications",
            &format!(
                "ResourceType=snapshot,Tags=[{{Key=ozbox-managed,Value=true}},{{Key={TAG_BOX},Value={}}}]",
                rec.spec.name
            ),
        ])?;
        // A restore (clone) needs a completed snapshot, so wait for it.
        s.run(&[
            "ec2",
            "wait",
            "snapshot-completed",
            "--snapshot-ids",
            &created.snapshot_id,
        ])?;
        Ok(created.snapshot_id)
    }

    fn list_snapshots(&self, rec: &BoxRecord) -> Result<Vec<SnapshotInfo>> {
        let snaps: Snapshots = self.at_rec(rec).run_json(&[
            "ec2",
            "describe-snapshots",
            "--owner-ids",
            "self",
            "--filters",
            "Name=tag:ozbox-managed,Values=true",
            &format!("Name=tag:{TAG_BOX},Values={}", rec.spec.name),
        ])?;
        let mut snaps = snaps.snapshots;
        snaps.sort_by(|a, b| (&a.start_time, &a.snapshot_id).cmp(&(&b.start_time, &b.snapshot_id)));
        Ok(snaps
            .into_iter()
            .map(|s| SnapshotInfo {
                id: s.snapshot_id,
                kind: SnapshotKind::Provider,
                created_at: s.start_time,
                // An EBS snapshot reports the size of its volume, not what it holds (it is incremental).
                size_bytes: s.volume_size.map(|g| g * 1_073_741_824),
                status: match s.state.as_deref() {
                    Some("completed") | None => "completed".into(),
                    Some("pending") => "pending".into(),
                    Some(_) => "error".into(),
                },
                // a copy of an old system disk holds no `/work`: it is listed (and can be deleted) but never restored from
                includes_work: !is_pre_upgrade_root(&s.tags),
                labels: s
                    .tags
                    .iter()
                    .filter(|t| t.key.starts_with("ozbox-"))
                    .map(|t| (t.key.clone(), t.value.clone()))
                    .collect(),
            })
            .collect())
    }

    fn delete_snapshot(&self, rec: &BoxRecord, id: &str) -> Result<()> {
        // Only a snapshot Oz Box made for THIS box is ever deleted: look at its tags first, never trust the id.
        let found = self.list_snapshots(rec)?;
        if !found.iter().any(|s| s.id == id) {
            return Err(Error::NotFound(format!(
                "snapshot {id} of {}",
                rec.spec.name
            )));
        }
        self.at_rec(rec)
            .run(&["ec2", "delete-snapshot", "--snapshot-id", id])?;
        Ok(())
    }

    fn check_restore_work(&self, rec: &BoxRecord, snap: &SnapshotInfo) -> Result<Vec<String>> {
        if rec.state == BoxState::InstanceMissing || rec.provider_id.is_none() {
            return Err(Error::Config(format!(
                "box {} has no machine; finish its upgrade first (`ozbox upgrade {}`), then restore /work",
                rec.spec.name, rec.spec.name
            )));
        }
        let vols = self.box_volumes(rec)?;
        let pending = vols.iter().find(|v| Self::is_pending_restore(v));
        let mut notes = Vec::new();
        let current = match pending {
            Some(p) => {
                let from = tag(&p.tags, RETIRED_FROM).unwrap_or("");
                if from != snap.id {
                    return Err(Error::Config(format!(
                        "an earlier restore of {} from snapshot {from} was interrupted; finish it first by restoring from {from} again",
                        rec.spec.name
                    )));
                }
                notes.push(format!(
                    "An earlier restore from this snapshot was interrupted after the old /work disk ({}) was set aside; this finishes it.",
                    p.volume_id
                ));
                (*p).clone()
            }
            None => {
                let id = self.work_volume(rec)?;
                vols.iter()
                    .find(|v| v.volume_id == id)
                    .cloned()
                    .ok_or_else(|| {
                        Error::Provider(format!(
                            "the /work volume of {} was not found",
                            rec.spec.name
                        ))
                    })?
            }
        };
        let vars = self.restore_vars(rec, &snap.id, &current)?;
        if pending.is_none() {
            // Read-only, and before anything is stopped, detached or taken out of the state: would OpenTofu change
            // anything besides the volume and its attachment?
            let seen = self
                .tofu
                .preview_restore(&vars, RESTORE_VOLUME, &[RESTORE_ATTACHMENT])?;
            notes.push(format!(
                "OpenTofu checked the change first and it replaces only the /work disk and its attachment; the machine is not touched ({}).",
                seen.join("; ")
            ));
        }
        notes.push(format!(
            "The new /work disk is made from {} in the same zone, with the same type and encryption{}.",
            snap.id,
            if vars.work_disk_gb > snap.size_bytes.map_or(0, |b| u32::try_from(b / 1_073_741_824).unwrap_or(0)) {
                format!(" and keeps its current size of {} GB (the filesystem is grown to fill it on the next start)", vars.work_disk_gb)
            } else {
                String::new()
            }
        ));
        notes.push(format!(
            "The /work disk it replaces ({}) is kept, detached and tagged, not deleted: it keeps costing storage until you delete it with `ozbox backup delete {} <disk id>`.",
            current.volume_id, rec.spec.name
        ));
        Ok(notes)
    }

    fn replace_work(&self, rec: &BoxRecord, snapshot: &str) -> Result<()> {
        let name = &rec.spec.name;
        let instance = Self::instance_id(rec)?.to_string();
        let vols = self.box_volumes(rec)?;
        let pending = vols.iter().find(|v| Self::is_pending_restore(v));
        let old_id = match pending {
            Some(p) => {
                if tag(&p.tags, RETIRED_FROM) != Some(snapshot) {
                    return Err(Error::Config(format!(
                        "an earlier restore of {name} from another snapshot was interrupted; restore from that one again to finish it"
                    )));
                }
                p.volume_id.clone()
            }
            None => self.work_volume(rec)?,
        };
        let old = vols
            .iter()
            .find(|v| v.volume_id == old_id)
            .ok_or_else(|| Error::Provider(format!("the /work volume of {name} was not found")))?;
        let vars = self.restore_vars(rec, snapshot, old)?;
        let s = self.at_rec(rec);

        // 1. Set the old disk aside, durably, BEFORE anything else: this is what a repeat of the restore finds.
        if pending.is_none() {
            s.run(&[
                "ec2",
                "create-tags",
                "--resources",
                &old_id,
                "--tags",
                &format!("Key=ozbox-role,Value={RETIRED_ROLE}"),
                &format!("Key={RETIRED_FROM},Value={snapshot}"),
                &format!("Key={RESTORE_STATE},Value=pending"),
            ])?;
        }
        // 2. Detach it (the machine is stopped), unless a previous run already did.
        let r: Reservations =
            s.run_json(&["ec2", "describe-instances", "--instance-ids", &instance])?;
        let attached = r
            .reservations
            .iter()
            .flat_map(|r| &r.instances)
            .any(|i| work_volume_of(i) == Some(old_id.as_str()));
        if attached {
            s.run(&[
                "ec2",
                "detach-volume",
                "--volume-id",
                &old_id,
                "--instance-id",
                &instance,
            ])?;
            s.run(&["ec2", "wait", "volume-available", "--volume-ids", &old_id])?;
        }
        // 3. Forget the old disk and its attachment in the state (never delete them): only what still points at the
        //    old disk, so a restore that got further than this is not undone by a repeat.
        let in_state = self.tofu.state_list(name)?;
        let mut removed: Vec<&str> = Vec::new();
        if in_state.iter().any(|a| a == RESTORE_VOLUME)
            && self
                .tofu
                .state_attribute(name, RESTORE_VOLUME, "id")?
                .as_deref()
                == Some(old_id.as_str())
        {
            removed.push(RESTORE_VOLUME);
        }
        if in_state.iter().any(|a| a == RESTORE_ATTACHMENT)
            && self
                .tofu
                .state_attribute(name, RESTORE_ATTACHMENT, "volume_id")?
                .as_deref()
                == Some(old_id.as_str())
        {
            removed.push(RESTORE_ATTACHMENT);
        }
        if !removed.is_empty() {
            self.tofu.state_rm(name, &removed)?;
        }
        // 4. The guarded plan: it may only create the new disk and its attachment.
        let plan = match self.tofu.plan_restore(&vars, RESTORE_CREATES) {
            Ok(p) => p,
            Err(e) if pending.is_none() => {
                let undone = self.undo_restore(rec, &vars, &old_id, &removed);
                return Err(Error::Provider(format!("{e} ({undone})")));
            }
            Err(e) => {
                return Err(Error::Provider(format!(
                    "{e} The old /work disk {old_id} is kept; running this restore again tries once more"
                )))
            }
        };
        if let Err(e) = self.tofu.apply_replace(&plan) {
            return Err(Error::Provider(format!(
                "{e}. The old /work disk {old_id} is kept; running this same restore again finishes it"
            )));
        }
        // 5. Check what is there now, rather than trust the apply: a /work disk made from this snapshot is attached.
        let after = self.box_volumes(rec)?;
        let r: Reservations =
            s.run_json(&["ec2", "describe-instances", "--instance-ids", &instance])?;
        let attached_now = r
            .reservations
            .iter()
            .flat_map(|r| &r.instances)
            .find_map(|i| work_volume_of(i).map(str::to_string));
        let restored = after.iter().any(|v| {
            Some(v.volume_id.as_str()) == attached_now.as_deref()
                && v.volume_id != old_id
                && v.snapshot_id.as_deref() == Some(snapshot)
        });
        if !restored {
            return Err(Error::Provider(format!(
                "the restore ran but no /work disk made from {snapshot} is attached to {name}; the old disk {old_id} is kept, nothing was deleted"
            )));
        }
        // 6. Finished: the retired disk is now a plain old disk the person may delete.
        s.run(&[
            "ec2",
            "create-tags",
            "--resources",
            &old_id,
            "--tags",
            &format!("Key={RESTORE_STATE},Value=done"),
        ])?;
        Ok(())
    }

    fn list_old_work(&self, rec: &BoxRecord) -> Result<Vec<OldWorkDisk>> {
        Ok(self
            .box_volumes(rec)?
            .iter()
            .filter(|v| Self::is_retired(v))
            .map(|v| OldWorkDisk {
                id: v.volume_id.clone(),
                size_gb: Some(v.size),
                restored_from: tag(&v.tags, RETIRED_FROM).map(str::to_string),
                state: if Self::is_pending_restore(v) {
                    "pending".into()
                } else {
                    "kept".into()
                },
            })
            .collect())
    }

    fn delete_old_work(&self, rec: &BoxRecord, id: &str) -> Result<()> {
        // Only a disk a restore of THIS box retired, and only one that is free: look at the tags and the state first.
        let vols = self.box_volumes(rec)?;
        let Some(v) = vols
            .iter()
            .find(|v| v.volume_id == id && Self::is_retired(v))
        else {
            return Err(Error::NotFound(format!(
                "old /work disk {id} of {}",
                rec.spec.name
            )));
        };
        if Self::is_pending_restore(v) || v.state.as_deref().is_some_and(|st| st != "available") {
            return Err(Error::Config(format!(
                "{id} is still part of a restore or attached to a machine, so it is not deleted"
            )));
        }
        self.at_rec(rec)
            .run(&["ec2", "delete-volume", "--volume-id", id])?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testing::FakeAws;
    use ozbox_core::{Operation, Provider, RecordingRunner};
    use ozbox_provider_fake::conformance::{self, Harness};

    type TestResult = std::result::Result<(), Box<dyn std::error::Error>>;

    fn provider(aws: &Arc<FakeAws>) -> Engine<AwsBackend> {
        let cfg = AwsConfig {
            region: Some("us-east-1".into()),
            image: Some("ami-0123456789abcdef0".into()),
            subnet_id: Some("subnet-0123456789abcdef0".into()),
            // A refused machine is not retried unless a test asks for it, and never with a real pause.
            create_retries: 0,
            create_backoff: std::time::Duration::ZERO,
            ..AwsConfig::default()
        };
        Engine::new(AwsBackend::with_env_none(aws.clone(), cfg))
    }

    fn provider_retrying(aws: &Arc<FakeAws>, retries: u32) -> Engine<AwsBackend> {
        let cfg = AwsConfig {
            region: Some("us-east-1".into()),
            image: Some("ami-0123456789abcdef0".into()),
            subnet_id: Some("subnet-0123456789abcdef0".into()),
            create_retries: retries,
            create_backoff: std::time::Duration::from_millis(1),
            ..AwsConfig::default()
        };
        Engine::new(AwsBackend::with_env_none(aws.clone(), cfg))
    }

    #[test]
    fn size_mapping_meets_or_exceeds_each_size() -> TestResult {
        let specs = |t: &str| match t {
            "c7i.xlarge" => (4, 8),
            "m7i.xlarge" => (4, 16),
            "m7i.2xlarge" => (8, 32),
            "r7i.2xlarge" => (8, 64),
            "m7i.4xlarge" => (16, 64),
            "m7i.8xlarge" => (32, 128),
            "g6.2xlarge" => (8, 32),
            other => panic!("unexpected {other}"),
        };
        for s in [
            Size::XS,
            Size::S,
            Size::M,
            Size::L,
            Size::XL,
            Size::XXL,
            Size::Gpu(GpuKind::Small),
        ] {
            let c = machine_choice(s)?;
            let (v, m) = specs(&c.machine_type);
            assert!(v >= s.spec().vcpus && m >= s.spec().memory_gb, "{s}");
            assert_eq!(size_of(&c.machine_type), Some(s));
        }
        assert!(matches!(
            machine_choice(Size::Gpu(GpuKind::Large)),
            Err(Error::Unsupported { .. })
        ));
        Ok(())
    }

    #[test]
    fn passes_the_conformance_suite() -> TestResult {
        let aws = Arc::new(FakeAws::new());
        let p = provider(&aws);
        let hook = aws.clone();
        let force = move |n: &BoxName, s: BoxState| hook.force_state(n, s);
        let work_hook = aws.clone();
        // By the volume's own tags, so it also answers for a box whose machine is gone.
        let work_id = move |n: &BoxName| -> Result<String> { work_hook.work_volume_of_box(n) };
        let interrupt_hook = aws.clone();
        let interrupt = move |n: &BoxName, image: &str| interrupt_hook.interrupt_upgrade(n, image);
        let refuse_hook = aws.clone();
        let refuse_next_create = move || -> Result<()> {
            refuse_hook.fail_creates(1, QUOTA_ERROR);
            Ok(())
        };
        conformance::run_all(&Harness {
            provider: &p,
            force_state: &force,
            secrets: vec!["AKIAS3NTINELKEY".into()],
            image: Some("ami-0123456789abcdef0".into()),
            upgrade: Some(conformance::UpgradeKit {
                image: "ami-0fedcba9876543210".into(),
                wrong_arch_image: Some("ami-0aaaaaaaaaaaaaaaa".into()),
                work_id: &work_id,
                interrupt: &interrupt,
                refuse_next_create: Some(&refuse_next_create),
                no_machine_probe: None,
                no_final_snapshot_without_machine: false,
            }),
        })?;
        Ok(())
    }

    fn running(
        aws: &Arc<FakeAws>,
        p: &Engine<AwsBackend>,
        name: &str,
        size: Size,
    ) -> Result<BoxRecord> {
        let n = BoxName::new(name)?;
        let mut spec = BoxSpec::new(n, size);
        spec.labels.insert("ozbox-always-on".into(), "true".into());
        let _ = aws;
        p.apply(&p.plan(&Operation::Create { spec })?)?
            .ok_or_else(|| Error::Provider("no record".into()))
    }

    fn provider_with(aws: &Arc<FakeAws>, f: impl FnOnce(&mut AwsConfig)) -> Engine<AwsBackend> {
        let mut cfg = AwsConfig {
            region: Some("us-east-1".into()),
            image: Some("ami-0123456789abcdef0".into()),
            subnet_id: Some("subnet-0123456789abcdef0".into()),
            create_retries: 0,
            create_backoff: std::time::Duration::ZERO,
            ..AwsConfig::default()
        };
        f(&mut cfg);
        Engine::new(AwsBackend::with_env_none(aws.clone(), cfg))
    }

    /// The `-var` words of the last tofu apply or plan.
    fn last_tofu_vars(aws: &FakeAws) -> String {
        aws.calls()
            .iter()
            .rev()
            .find(|c| c.program == "tofu" && c.args.iter().any(|a| a == "apply" || a == "plan"))
            .map(|c| c.args.join(" "))
            .unwrap_or_default()
    }

    const KEY_ARN: &str =
        "arn:aws:kms:us-east-1:123456789012:key/0f0f0f0f-0000-4000-8000-000000000000";
    const PIN: &str = "abcdefghijklmnopqrstuvwxyz234567abcdefghijklmnopqrst";

    /// A security review (2026-11-11): a default box kept its store's key in a file, which an upgrade replaces. With the
    /// fleet's KMS key configured, a new box uses it (no key file at all), carries it in its labels, and the plan says so.
    #[test]
    fn a_box_made_with_the_fleets_key_keeps_it_and_says_so() -> TestResult {
        let aws = Arc::new(FakeAws::new());
        let p = provider_with(&aws, |c| {
            c.secrets_key_arn = Some(KEY_ARN.into());
            c.fleet = Some("dev".into());
        });
        let spec = BoxSpec::new(BoxName::new("main")?, Size::S);
        let plan = p.plan(&Operation::Create { spec: spec.clone() })?;
        assert!(
            plan.notes
                .iter()
                .any(|n| n.contains("fleet's KMS key") && n.contains(KEY_ARN)),
            "{:?}",
            plan.notes
        );
        let rec = p.apply(&plan)?.ok_or("no record")?;
        let v = last_tofu_vars(&aws);
        assert!(
            v.contains(&format!("secrets_key_arn={KEY_ARN}")) && v.contains("fleet=dev"),
            "{v}"
        );
        // the key rides the box's own labels (its instance tags), so every later upgrade renders the same one
        assert!(
            v.contains(&format!("\"{SECRETS_KEY_LABEL}\"=\"{KEY_ARN}\"")),
            "{v}"
        );
        let _ = rec;
        // without one, the plan says the key is kept in a file and what an upgrade then does
        let plain = provider(&aws);
        let plan = plain.plan(&Operation::Create {
            spec: BoxSpec::new(BoxName::new("other")?, Size::S),
        })?;
        assert!(plan
            .notes
            .iter()
            .any(|n| n.contains("in a file on the system disk")));
        Ok(())
    }

    /// An upgrade gives the new machine the key the store was sealed with, whatever today's configuration says: a store
    /// sealed with a file-kept key must not come back on a machine told to use KMS, and the reverse.
    #[test]
    fn an_upgrade_keeps_the_boxs_own_store_key_and_pins_an_approver_only_where_there_is_none(
    ) -> TestResult {
        let aws = Arc::new(FakeAws::new());
        // made with no fleet key; the configuration names one now, and this computer has an approval key
        let before = running(&aws, &provider(&aws), "main", Size::S)?;
        let later = provider_with(&aws, |c| {
            c.secrets_key_arn = Some(KEY_ARN.into());
            c.fleet = Some("dev".into());
            c.upgrade_pin = Some(PIN.into());
        });
        let plan = later.plan(&Operation::Upgrade {
            name: before.spec.name.clone(),
            image: NEW_IMAGE.into(),
            reprovision: false,
            keep_old_system_disk: false,
        })?;
        let v = last_tofu_vars(&aws);
        assert!(
            !v.contains("secrets_key_arn="),
            "a file-key box must stay one: {v}"
        );
        assert!(
            v.contains(PIN),
            "the box had no pin: this computer's key is pinned in its new configuration: {v}"
        );
        assert!(plan.notes.iter().any(|n| n.contains("no pinned approver")));
        // a box that already has a pin keeps its own
        let aws = Arc::new(FakeAws::new());
        let p = provider(&aws);
        let mut spec = BoxSpec::new(BoxName::new("main")?, Size::S);
        let theirs = "zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz";
        spec.labels
            .insert(ozbox_core::APPROVER_LABEL.into(), theirs.into());
        let rec = p
            .apply(&p.plan(&Operation::Create { spec })?)?
            .ok_or("no record")?;
        let later = provider_with(&aws, |c| c.upgrade_pin = Some(PIN.into()));
        let plan = later.plan(&Operation::Upgrade {
            name: rec.spec.name.clone(),
            image: NEW_IMAGE.into(),
            reprovision: false,
            keep_old_system_disk: false,
        })?;
        let v = last_tofu_vars(&aws);
        assert!(v.contains(theirs) && !v.contains(PIN), "{v}");
        assert!(!plan.notes.iter().any(|n| n.contains("no pinned approver")));
        Ok(())
    }

    /// The document's hash is pinned as a literal here and in the module's tests (the mock of what Systems Manager reports), so a
    /// change to adopt-document.yaml is a deliberate edit of all three, and an old ozbox against a new module is never a surprise.
    #[test]
    fn the_documents_sha256_is_pinned_where_the_module_tests_expect_it() -> TestResult {
        const PINNED: &str = "3ee210517c2bf7941619126b5e18829ff71f14e43a4d177ba1bb0788c1527fa7";
        assert_eq!(
            ozbox_catalog::verify::sha256_hex(ADOPT_DOCUMENT.as_bytes()),
            PINNED
        );
        let tests = std::fs::read_to_string(
            std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
                .join("../../infra/tofu/modules/aws-adopt-command/tests/invariants.tftest.hcl"),
        )?;
        assert!(tests.contains(PINNED));
        Ok(())
    }

    /// The document is hashed by bytes on both sides, so its line endings are pinned (the .gitattributes line), and a refused
    /// send names the document and the release lockstep instead of "your sign-in needs the policy".
    #[test]
    fn the_document_has_one_set_of_bytes_and_a_refused_send_says_why() -> TestResult {
        assert!(!ADOPT_DOCUMENT.contains('\r'));
        let attrs = std::fs::read_to_string(
            std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../.gitattributes"),
        )?;
        assert!(attrs
            .lines()
            .any(|l| l == "infra/tofu/modules/aws-adopt-command/adopt-document.yaml text eol=lf"));
        let e = send_refused(
            Error::Provider(
                "An error occurred (InvalidDocument) when calling the SendCommand operation".into(),
            ),
            "ozbox-adopt-dev",
        );
        let m = e.to_string();
        assert!(
            m.contains("ozbox-adopt-dev")
                && m.contains("same release")
                && m.contains("aws-adopt-command module")
                && !m.contains("secrets-key")
                && m.contains("Nothing was changed"),
            "{m}"
        );
        let other = send_refused(
            Error::Provider("AccessDeniedException".into()),
            "ozbox-adopt-dev",
        );
        assert!(!other.to_string().contains("same release"));
        Ok(())
    }

    /// The grant is main's managed-policy ATTACHMENT, not an inline role policy: the daily operator role is denied
    /// `iam:PutRolePolicy` (and the plan guard refuses an inline policy), and may attach and detach exactly the account's
    /// `ozbox-box-fleet-key-*` policy. A module or a guard that drifted back to an inline policy fails here, in CI, and not after a
    /// box was already marked as moving.
    #[test]
    fn the_grant_a_move_makes_is_an_attachment_the_daily_operator_role_may_apply() -> TestResult {
        assert!(ADOPT_ROLE_POLICY.starts_with("aws_iam_role_policy_attachment.fleet_key"));
        assert!(!UNAPPLIABLE_TYPES.contains(&"aws_iam_role_policy_attachment"));
        assert!(UNAPPLIABLE_TYPES.contains(&"aws_iam_role_policy"));
        let policy = std::fs::read_to_string(
            std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
                .join("../../infra/aws/operator-policy.json"),
        )?;
        let v: serde_json::Value = serde_json::from_str(&policy)?;
        let statements = v["Statement"].as_array().ok_or("no statements")?;
        let attach = statements
            .iter()
            .find(|s| s["Sid"] == "AttachTheFleetKeyPolicy")
            .ok_or("the operator may not attach the fleet-key policy")?;
        assert_eq!(attach["Action"], "iam:AttachRolePolicy");
        assert!(attach.to_string().contains("policy/ozbox-box-fleet-key-*"));
        // the cancel takes the attachment back: DetachRolePolicy on a managed role
        assert!(statements
            .iter()
            .any(|s| s["Effect"] == "Allow"
                && s["Action"].to_string().contains("iam:DetachRolePolicy")));
        // and nothing grants PutRolePolicy
        assert!(!statements.iter().any(
            |s| s["Effect"] == "Allow" && s["Action"].to_string().contains("iam:PutRolePolicy")
        ));
        Ok(())
    }

    /// Moving an existing box's store to the fleet key, in place (`ozbox adopt-fleet-key`): the role gets the grant and the
    /// box a PENDING mark (never the real label, which an upgrade reads as "kept"); nothing is replaced; the real label comes
    /// only with the finish step; a cancel takes everything back.
    #[test]
    fn a_box_moves_to_the_fleet_key_in_place_and_the_real_label_comes_last() -> TestResult {
        let aws = Arc::new(FakeAws::new());
        let before = running(&aws, &provider(&aws), "main", Size::S)?;
        let p = provider_with(&aws, |c| {
            c.secrets_key_arn = Some(KEY_ARN.into());
            c.fleet = Some("dev".into());
        });
        let b = p.backend();
        let name = before.spec.name.clone();
        assert_eq!(
            AwsBackend::secrets_key_stage(&before),
            SecretsKeyStage::File
        );
        // begin: the grant and the pending mark; the machine and /work are updated at most, never replaced
        let plan = b.plan_secrets_key_step(&before, SecretsKeyStep::Begin)?;
        assert!(
            plan.summary
                .iter()
                .any(|l| l.contains("aws_iam_role_policy_attachment.fleet_key[0]: create")),
            "{:?}",
            plan.summary
        );
        assert!(!plan.summary.iter().any(|l| l.contains("delete")));
        b.apply_secrets_key_step(&plan)?;
        assert_eq!(aws.role_grant(&name).as_deref(), Some(KEY_ARN));
        let pending = p.get(&name)?.ok_or("no record")?;
        assert_eq!(
            AwsBackend::secrets_key_stage(&pending),
            SecretsKeyStage::Pending(KEY_ARN.into())
        );
        assert!(!pending.spec.labels.contains_key(SECRETS_KEY_LABEL));
        assert_eq!(
            pending
                .spec
                .labels
                .get(SECRETS_FLEET_LABEL)
                .map(String::as_str),
            Some("dev")
        );
        // while pending: an upgrade is refused (a KMS-configured machine over a file-sealed store never opens) ...
        let refused = p
            .plan(&Operation::Upgrade {
                name: name.clone(),
                image: NEW_IMAGE.into(),
                reprovision: false,
                keep_old_system_disk: false,
            })
            .err()
            .ok_or("expected a refusal")?
            .to_string();
        assert!(
            refused.contains("adopt-fleet-key") && refused.contains("--cancel"),
            "{refused}"
        );
        // ... and any later change keeps the grant (the module is given the key under the pending label too)
        let again = b.plan_secrets_key_step(&pending, SecretsKeyStep::Begin)?;
        assert!(last_tofu_vars(&aws).contains(&format!("secrets_key_arn={KEY_ARN}")));
        drop(again);
        // finish: the real label, the pending one gone
        let plan = b.plan_secrets_key_step(&pending, SecretsKeyStep::Finish)?;
        b.apply_secrets_key_step(&plan)?;
        let done = p.get(&name)?.ok_or("no record")?;
        assert_eq!(
            AwsBackend::secrets_key_stage(&done),
            SecretsKeyStage::Fleet(KEY_ARN.into())
        );
        assert!(!done.spec.labels.contains_key(SECRETS_ADOPT_LABEL));
        assert_eq!(aws.role_grant(&name).as_deref(), Some(KEY_ARN));
        // a box on the fleet key has nothing to move, and its upgrade is the ordinary kept-store one
        assert!(b
            .plan_secrets_key_step(&done, SecretsKeyStep::Begin)
            .is_err());
        assert!(p
            .plan(&Operation::Upgrade {
                name,
                image: NEW_IMAGE.into(),
                reprovision: false,
                keep_old_system_disk: false,
            })
            .is_ok());
        Ok(())
    }

    #[test]
    fn cancelling_a_move_takes_the_grant_and_the_mark_back() -> TestResult {
        let aws = Arc::new(FakeAws::new());
        let before = running(&aws, &provider(&aws), "main", Size::S)?;
        let p = provider_with(&aws, |c| {
            c.secrets_key_arn = Some(KEY_ARN.into());
            c.fleet = Some("dev".into());
        });
        let b = p.backend();
        // nothing to cancel on a box that is not moving
        assert!(b
            .plan_secrets_key_step(&before, SecretsKeyStep::Cancel)
            .is_err());
        b.apply_secrets_key_step(&b.plan_secrets_key_step(&before, SecretsKeyStep::Begin)?)?;
        let pending = p.get(&before.spec.name)?.ok_or("no record")?;
        let plan = b.plan_secrets_key_step(&pending, SecretsKeyStep::Cancel)?;
        assert!(
            plan.summary
                .iter()
                .any(|l| l.contains("aws_iam_role_policy_attachment.fleet_key[0]: delete")),
            "{:?}",
            plan.summary
        );
        b.apply_secrets_key_step(&plan)?;
        assert_eq!(aws.role_grant(&before.spec.name), None);
        let back = p.get(&before.spec.name)?.ok_or("no record")?;
        assert_eq!(AwsBackend::secrets_key_stage(&back), SecretsKeyStage::File);
        assert!(!back.spec.labels.contains_key(SECRETS_FLEET_LABEL));
        // and the box can be upgraded again
        assert!(p
            .plan(&Operation::Upgrade {
                name: back.spec.name.clone(),
                image: NEW_IMAGE.into(),
                reprovision: false,
                keep_old_system_disk: false,
            })
            .is_ok());
        Ok(())
    }

    /// Never a silent switch: with no fleet key configured there is nothing to move to, a move already begun continues to the
    /// key the box carries (not whatever the configuration says today), and a plan that would replace the machine is refused.
    #[test]
    fn a_move_to_the_fleet_key_needs_one_configured_and_never_replaces_anything() -> TestResult {
        let aws = Arc::new(FakeAws::new());
        let before = running(&aws, &provider(&aws), "main", Size::S)?;
        let plain = provider(&aws);
        let refusal = plain
            .backend()
            .plan_secrets_key_step(&before, SecretsKeyStep::Begin)
            .err()
            .ok_or("expected a refusal")?
            .to_string();
        assert!(refusal.contains("secrets_key_arn"), "{refusal}");
        let other = "arn:aws:kms:us-east-1:123456789012:key/11111111-1111-4111-8111-111111111111";
        let p = provider_with(&aws, |c| {
            c.secrets_key_arn = Some(KEY_ARN.into());
            c.fleet = Some("dev".into());
        });
        p.backend().apply_secrets_key_step(
            &p.backend()
                .plan_secrets_key_step(&before, SecretsKeyStep::Begin)?,
        )?;
        let pending = p.get(&before.spec.name)?.ok_or("no record")?;
        let changed = provider_with(&aws, |c| {
            c.secrets_key_arn = Some(other.into());
            c.fleet = Some("dev".into());
        });
        changed
            .backend()
            .plan_secrets_key_step(&pending, SecretsKeyStep::Begin)?;
        let v = last_tofu_vars(&aws);
        assert!(
            v.contains(&format!("secrets_key_arn={KEY_ARN}")) && !v.contains(other),
            "{v}"
        );
        // a module or state that does not match the box would replace the machine: refused, and nothing was applied
        aws.inplace_replaces_instance();
        let refusal = p
            .backend()
            .plan_secrets_key_step(&pending, SecretsKeyStep::Finish)
            .err()
            .ok_or("expected a refusal")?
            .to_string();
        assert!(refusal.contains("aws_instance.box"), "{refusal}");
        let still = p.get(&before.spec.name)?.ok_or("no record")?;
        assert!(matches!(
            AwsBackend::secrets_key_stage(&still),
            SecretsKeyStage::Pending(_)
        ));
        Ok(())
    }

    /// A box made by an earlier version has an UNTAGGED system disk, and the operator's AWS role can put a first tag on a disk only
    /// when the disk is created. The move to the fleet key used to plan that tag along with the grant and the pending mark, and
    /// the tag call was refused after the other two had been applied: a box left half moved. Now the plan refuses, before anything
    /// is applied, names the disk and the one command an administrator runs, and the move goes through once they have.
    #[test]
    fn an_untagged_system_disk_stops_the_move_before_anything_is_applied() -> TestResult {
        let aws = Arc::new(FakeAws::new());
        let before = running(&aws, &provider(&aws), "main", Size::S)?;
        let name = before.spec.name.clone();
        let p = provider_with(&aws, |c| {
            c.secrets_key_arn = Some(KEY_ARN.into());
            c.fleet = Some("dev".into());
        });
        let b = p.backend();
        aws.untag_root_volume(&name);
        let applies = |aws: &FakeAws| {
            aws.calls()
                .iter()
                .filter(|c| c.args.iter().any(|a| a == "apply"))
                .count()
        };
        let applied = applies(&aws);
        let refusal = b
            .plan_secrets_key_step(&before, SecretsKeyStep::Begin)
            .err()
            .ok_or("an untagged system disk must stop the plan")?
            .to_string();
        assert!(
            refusal.contains("no ozbox-managed tag")
                && refusal.contains("aws ec2 create-tags --resources vol-root")
                && refusal.contains("Key=ozbox-managed,Value=true Key=ozbox-box,Value=main")
                && refusal.contains("describe-volumes")
                && refusal.contains("Nothing was changed"),
            "{refusal}"
        );
        // nothing was applied: no apply, no grant, no pending mark, and the disk is as it was
        assert_eq!(applies(&aws), applied);
        assert_eq!(aws.role_grant(&name), None);
        assert!(aws.root_volume_tags(&name).is_empty());
        let again = p.get(&name)?.ok_or("no record")?;
        assert_eq!(AwsBackend::secrets_key_stage(&again), SecretsKeyStage::File);
        // the administrator runs the command once; the same move then goes through, in place
        aws.admin_tags_root_volume(&name);
        let plan = b.plan_secrets_key_step(&before, SecretsKeyStep::Begin)?;
        b.apply_secrets_key_step(&plan)?;
        assert_eq!(aws.role_grant(&name).as_deref(), Some(KEY_ARN));
        assert_eq!(
            aws.root_volume_tags(&name)
                .get("ozbox-role")
                .map(String::as_str),
            Some("root")
        );
        Ok(())
    }

    /// The same refusal holds at every step of the move, so a box an older program half moved (marked, granted, disk never tagged)
    /// is stopped at plan time too, on the way to finishing or cancelling, and nothing is applied.
    #[test]
    fn finishing_or_cancelling_a_move_is_stopped_too_when_the_disk_is_untagged() -> TestResult {
        let aws = Arc::new(FakeAws::new());
        let before = running(&aws, &provider(&aws), "main", Size::S)?;
        let name = before.spec.name.clone();
        let p = provider_with(&aws, |c| {
            c.secrets_key_arn = Some(KEY_ARN.into());
            c.fleet = Some("dev".into());
        });
        let b = p.backend();
        b.apply_secrets_key_step(&b.plan_secrets_key_step(&before, SecretsKeyStep::Begin)?)?;
        let pending = p.get(&name)?.ok_or("no record")?;
        aws.untag_root_volume(&name);
        let applies = |aws: &FakeAws| {
            aws.calls()
                .iter()
                .filter(|c| c.args.iter().any(|a| a == "apply"))
                .count()
        };
        let applied = applies(&aws);
        for step in [SecretsKeyStep::Finish, SecretsKeyStep::Cancel] {
            let refusal = b
                .plan_secrets_key_step(&pending, step)
                .err()
                .ok_or("expected a refusal")?
                .to_string();
            assert!(refusal.contains("create-tags"), "{step:?}: {refusal}");
        }
        assert_eq!(applies(&aws), applied);
        assert_eq!(aws.role_grant(&name).as_deref(), Some(KEY_ARN));
        Ok(())
    }

    /// H2: what a decision rests on is read through Systems Manager, as a fixed program run as root, and only a clean
    /// `Success` is an answer. The program text is one of three fixed strings; nothing a box says reaches a command.
    #[test]
    #[allow(clippy::unwrap_used)]
    fn a_root_command_goes_through_run_command_and_only_a_success_is_an_answer() -> TestResult {
        use ozbox_core::{Output, RecordingRunner};
        let reply = |stdout: &str| Output {
            status: Some(0),
            stdout: stdout.into(),
            stderr: String::new(),
        };
        let rec = |id: &str| {
            let mut r = BoxRecord {
                spec: BoxSpec::new(BoxName::new("main").unwrap(), Size::S),
                state: BoxState::Running,
                provider: "aws".into(),
                provider_id: Some(id.into()),
                machine_type: Some("m7i.xlarge".into()),
                snapshots: vec![],
                created_at: None,
                last_activity_at: None,
            };
            r.spec.region = Some("us-east-1".into());
            r
        };
        let backend = |runner: Arc<RecordingRunner>| {
            let cfg = AwsConfig {
                secrets_key_arn: Some(KEY_ARN.into()),
                fleet: Some("dev".into()),
                ..AwsConfig::default()
            };
            AwsBackend::with_env_none(runner, cfg)
        };
        // a success: sent, polled, the output returned
        let runner = Arc::new(RecordingRunner::new());
        runner.reply(reply(
            r#"{"Command":{"CommandId":"0a1b2c3d-0000-4000-8000-000000000000"}}"#,
        ));
        runner.reply(reply(r#"{"Status":"InProgress"}"#));
        runner.reply(reply(
            r#"{"Status":"Success","StandardOutputContent":"ozbox-adopt-status=1\n"}"#,
        ));
        let out = backend(runner.clone())
            .root_command(&rec("i-0123456789abcdef0"), RootCommand::AdoptStatus)?;
        assert_eq!(out, "ozbox-adopt-status=1\n");
        let calls = runner.calls();
        let send = calls[0].args.join(" ");
        assert!(
            send.starts_with("ssm send-command --instance-ids i-0123456789abcdef0 --document-name ozbox-adopt-dev")
                && send.contains(r#"{"action":["status"]}"#)
                && send.contains("--timeout-seconds 120")
                && send.contains("--region us-east-1"),
            "{send}"
        );
        // never the stock shell document, never a command line: an enum word and nothing else
        assert!(
            !send.contains("AWS-RunShellScript") && !send.contains("commands"),
            "{send}"
        );
        for (which, word) in [
            (RootCommand::AdoptStatus, "status"),
            (RootCommand::AdoptArm, "arm"),
            (RootCommand::AdoptCancel, "cancel"),
            (RootCommand::AdoptCancelFromCopy, "cancel-from-copy"),
        ] {
            assert_eq!(which.action(), word);
        }
        // the laptop waits at least as long as delivery plus the document's execution timeout (R3), so it never gives up on a
        // cancel that is still running; and the constants agree with each other and with the document's own text
        assert!(
            u64::from(ROOT_POLLS) * ROOT_POLL_SECS >= ROOT_DELIVERY + ROOT_EXEC_SECS,
            "the wait must outlast the document's timeout"
        );
        // a cancel gets the full window, a status or an arm the short one (S5), and neither is shorter than delivery
        assert_eq!(RootCommand::AdoptCancel.polls(), ROOT_POLLS);
        assert_eq!(RootCommand::AdoptCancelFromCopy.polls(), ROOT_POLLS);
        assert_eq!(RootCommand::AdoptStatus.polls(), ROOT_READ_POLLS);
        assert_eq!(RootCommand::AdoptArm.polls(), ROOT_READ_POLLS);
        assert!(u64::from(ROOT_READ_POLLS) * ROOT_POLL_SECS > ROOT_DELIVERY);
        const { assert!(ROOT_READ_POLLS < ROOT_POLLS / 3) };
        assert_eq!(ROOT_DELIVERY_SECS, ROOT_DELIVERY.to_string());
        assert!(
            ADOPT_DOCUMENT.contains(&format!("timeoutSeconds: \"{ROOT_EXEC_SECS}\"")),
            "the document's execution timeout is what the wait is built on"
        );
        // the command is sent with the hash of the document this program carries (R6), and no version guess
        assert!(
            send.contains("--document-hash-type Sha256")
                && send.contains(&format!(
                    "--document-hash {}",
                    ozbox_catalog::verify::sha256_hex(ADOPT_DOCUMENT.as_bytes())
                )),
            "{send}"
        );
        assert!(calls[1]
            .args
            .join(" ")
            .starts_with("ssm get-command-invocation --command-id 0a1b2c3d-"));
        // a failed or timed-out run is an error, not an answer
        for status in ["Failed", "TimedOut", "Cancelled"] {
            let runner = Arc::new(RecordingRunner::new());
            runner.reply(reply(
                r#"{"Command":{"CommandId":"0a1b2c3d-0000-4000-8000-000000000000"}}"#,
            ));
            runner.reply(reply(&format!(
                r#"{{"Status":"{status}","StandardOutputContent":"cancel=ok\n"}}"#
            )));
            assert!(backend(runner)
                .root_command(&rec("i-0123456789abcdef0"), RootCommand::AdoptCancel)
                .is_err());
        }
        // an id that is not an id is never put in a command
        let runner = Arc::new(RecordingRunner::new());
        runner.reply(reply(r#"{"Command":{"CommandId":"x; reboot"}}"#));
        assert!(backend(runner.clone())
            .root_command(&rec("i-0123456789abcdef0"), RootCommand::AdoptArm)
            .is_err());
        assert_eq!(runner.calls().len(), 1);
        // no fleet configured: no document to send, and nothing is sent
        let runner = Arc::new(RecordingRunner::new());
        assert!(
            AwsBackend::with_env_none(runner.clone(), AwsConfig::default())
                .root_command(&rec("i-0123456789abcdef0"), RootCommand::AdoptStatus)
                .is_err()
        );
        assert!(runner.calls().is_empty());
        Ok(())
    }

    /// R3: a command the laptop stopped waiting for is NOT cancelled. The delivery timeout stops one that never started, and
    /// a running move or cancel must not be killed part way. The wait itself says so and tells the person to ask again.
    #[test]
    #[allow(clippy::unwrap_used)]
    fn a_command_that_is_given_up_on_is_never_cancelled() -> TestResult {
        use ozbox_core::{Output, RecordingRunner};
        let reply = |stdout: &str| Output {
            status: Some(0),
            stdout: stdout.into(),
            stderr: String::new(),
        };
        let runner = Arc::new(RecordingRunner::new());
        runner.reply(reply(
            r#"{"Command":{"CommandId":"0a1b2c3d-0000-4000-8000-000000000000"}}"#,
        ));
        for _ in 0..ROOT_POLLS {
            runner.reply(reply(r#"{"Status":"InProgress"}"#));
        }
        let cfg = AwsConfig {
            secrets_key_arn: Some(KEY_ARN.into()),
            ..AwsConfig::default()
        };
        let mut r = BoxRecord {
            spec: BoxSpec::new(BoxName::new("main").unwrap(), Size::S),
            state: BoxState::Running,
            provider: "aws".into(),
            provider_id: Some("i-0123456789abcdef0".into()),
            machine_type: Some("m7i.xlarge".into()),
            snapshots: vec![],
            created_at: None,
            last_activity_at: None,
        };
        r.spec.region = Some("us-east-1".into());
        let err = AwsBackend::with_env_none(runner.clone(), cfg)
            .root_command(&r, RootCommand::AdoptCancel)
            .err()
            .ok_or("expected a timeout")?
            .to_string();
        assert!(
            err.contains("did not answer in time") && err.contains("may still be running"),
            "{err}"
        );
        let calls = runner.calls();
        assert!(
            !calls
                .iter()
                .any(|c| c.args.iter().any(|a| a.contains("cancel-command"))),
            "nothing may stop a command that is running"
        );
        assert_eq!(calls.len(), 1 + ROOT_POLLS as usize);
        Ok(())
    }

    /// R3: an access-denied answer to reading the result is reported at once, not waited out for the whole window and then
    /// called a timeout; "no such invocation yet" is waited on; and a program the box does not have is said to be OLDER.
    #[test]
    #[allow(clippy::unwrap_used)]
    fn a_refused_read_is_reported_at_once_and_an_older_program_is_named() -> TestResult {
        use ozbox_core::{Output, RecordingRunner};
        let ok = |stdout: &str| Output {
            status: Some(0),
            stdout: stdout.into(),
            stderr: String::new(),
        };
        let fail = |stderr: &str| Output {
            status: Some(254),
            stdout: String::new(),
            stderr: stderr.into(),
        };
        let rec = {
            let mut r = BoxRecord {
                spec: BoxSpec::new(BoxName::new("main").unwrap(), Size::S),
                state: BoxState::Running,
                provider: "aws".into(),
                provider_id: Some("i-0123456789abcdef0".into()),
                machine_type: Some("m7i.xlarge".into()),
                snapshots: vec![],
                created_at: None,
                last_activity_at: None,
            };
            r.spec.region = Some("us-east-1".into());
            r
        };
        let backend = |runner: Arc<RecordingRunner>| {
            AwsBackend::with_env_none(
                runner,
                AwsConfig {
                    secrets_key_arn: Some(KEY_ARN.into()),
                    fleet: Some("dev".into()),
                    ..AwsConfig::default()
                },
            )
        };
        let sent = r#"{"Command":{"CommandId":"0a1b2c3d-0000-4000-8000-000000000000"}}"#;
        // refused: reported at once (send + one read), and the words name the missing permission
        let runner = Arc::new(RecordingRunner::new());
        runner.reply(ok(sent));
        runner.reply(fail(
            "An error occurred (AccessDeniedException) when calling the GetCommandInvocation operation: User is not authorized",
        ));
        let e = backend(runner.clone())
            .root_command(&rec, RootCommand::AdoptStatus)
            .err()
            .ok_or("expected a refusal")?
            .to_string();
        assert!(e.contains("ssm:GetCommandInvocation"), "{e}");
        assert_eq!(runner.calls().len(), 2);
        // not there yet: waited on, then answered
        let runner = Arc::new(RecordingRunner::new());
        runner.reply(ok(sent));
        runner.reply(fail("An error occurred (InvocationDoesNotExist)"));
        runner.reply(ok(
            r#"{"Status":"Success","StandardOutputContent":"ozbox-adopt-status=2\n"}"#,
        ));
        assert_eq!(
            backend(runner).root_command(&rec, RootCommand::AdoptStatus)?,
            "ozbox-adopt-status=2
"
        );
        // a box whose program does not know the subcommand is older (not a policy problem)
        for (err, code) in [
            (
                "error: unrecognized subcommand 'adopt-status'

Usage: ozbox secrets <COMMAND>",
                2,
            ),
            ("error: unexpected argument 'adopt-status' found", 2),
            (
                "/bin/sh: 5: exec: /usr/local/bin/ozbox: not found
/usr/local/bin/ozbox: No such file or directory",
                127,
            ),
        ] {
            let runner = Arc::new(RecordingRunner::new());
            runner.reply(ok(sent));
            runner.reply(ok(&format!(
                r#"{{"Status":"Failed","ResponseCode":{code},"StandardErrorContent":{}}}"#,
                serde_json::to_string(err)?
            )));
            let e = backend(runner)
                .root_command(&rec, RootCommand::AdoptStatus)
                .err()
                .ok_or("expected a failure")?;
            assert!(
                matches!(&e, Error::Config(m) if m == ROOT_PROGRAM_OLDER),
                "{err}: {e}"
            );
        }
        // any other failure says its exit code and first line
        let runner = Arc::new(RecordingRunner::new());
        runner.reply(ok(sent));
        runner.reply(ok(
            r#"{"Status":"Failed","ResponseCode":1,"StandardErrorContent":"the secrets service is down\n"}"#,
        ));
        let e = backend(runner)
            .root_command(&rec, RootCommand::AdoptStatus)
            .err()
            .ok_or("expected a failure")?
            .to_string();
        assert!(e.contains("exit 1: the secrets service is down"), "{e}");
        Ok(())
    }

    /// R2: "no label" is the cloud's own tag list, read successfully; a read that failed, or came back in a shape this program
    /// does not know, is an error and never "no label".
    #[test]
    #[allow(clippy::unwrap_used)]
    fn the_cloud_says_no_label_only_from_a_tag_list_that_was_read() -> TestResult {
        use ozbox_core::{Output, RecordingRunner};
        let rec = BoxRecord {
            spec: BoxSpec::new(BoxName::new("main").unwrap(), Size::S),
            state: BoxState::Running,
            provider: "aws".into(),
            provider_id: Some("i-0123456789abcdef0".into()),
            machine_type: Some("m7i.xlarge".into()),
            snapshots: vec![],
            created_at: None,
            last_activity_at: None,
        };
        let reply = |status: i32, out: &str| Output {
            status: Some(status),
            stdout: out.into(),
            stderr: "Throttling".into(),
        };
        let ask = |o: Output| {
            let runner = Arc::new(RecordingRunner::new());
            runner.reply(o);
            let b = AwsBackend::with_env_none(runner.clone(), AwsConfig::default());
            (b.secrets_tags_absent(&rec), runner)
        };
        let (none, runner) = ask(reply(0, r#"{"Tags":[]}"#));
        assert!(none?);
        let args = runner.calls()[0].args.join(" ");
        assert!(
            args.contains("ec2 describe-tags")
                && args.contains("Name=resource-id,Values=i-0123456789abcdef0")
                && args.contains("Name=key,Values=ozbox-secrets-adopt,ozbox-secrets-key"),
            "{args}"
        );
        let (one, _) = ask(reply(
            0,
            r#"{"Tags":[{"Key":"ozbox-secrets-key","Value":"x","ResourceId":"i-0123456789abcdef0","ResourceType":"instance"}]}"#,
        ));
        assert!(!one?);
        for bad in [
            reply(254, ""),
            reply(0, "not json"),
            reply(0, "{}"),
            reply(0, r#"{"Tags":null}"#),
        ] {
            assert!(ask(bad).0.is_err());
        }
        Ok(())
    }

    /// R5: the tag keys the in-place guard lets change are exactly the labels this crate writes.
    #[test]
    fn the_in_place_guard_allows_exactly_the_labels_this_crate_writes() {
        let allowed = ozbox_core::tofu::IN_PLACE_TAG_KEYS;
        for l in [SECRETS_KEY_LABEL, SECRETS_ADOPT_LABEL, SECRETS_FLEET_LABEL] {
            assert!(allowed.contains(&l), "{l}");
        }
        assert!(!allowed.contains(&"ozbox-managed") && !allowed.contains(&"ozbox-box"));
    }

    /// A box made from another box's record (a clone) never inherits the pending mark of a move that has not finished.
    #[test]
    fn a_new_box_never_starts_with_a_pending_move() -> TestResult {
        let aws = Arc::new(FakeAws::new());
        let p = provider(&aws);
        let mut spec = BoxSpec::new(BoxName::new("copy")?, Size::S);
        spec.labels
            .insert(SECRETS_ADOPT_LABEL.into(), KEY_ARN.into());
        p.apply(&p.plan(&Operation::Create { spec })?)?;
        let v = last_tofu_vars(&aws);
        assert!(
            !v.contains(SECRETS_ADOPT_LABEL) && !v.contains("secrets_key_arn="),
            "{v}"
        );
        Ok(())
    }

    /// An upgrade of a file-keyed box under a configured fleet key does not move the key (the new machine would start on KMS
    /// over a file-sealed store) and the plan says what to run after it.
    #[test]
    fn an_upgrade_plan_points_a_file_keyed_box_at_the_adopt_command() -> TestResult {
        let aws = Arc::new(FakeAws::new());
        let before = running(&aws, &provider(&aws), "main", Size::S)?;
        let p = provider_with(&aws, |c| {
            c.secrets_key_arn = Some(KEY_ARN.into());
            c.fleet = Some("dev".into());
        });
        let plan = p.plan(&Operation::Upgrade {
            name: before.spec.name.clone(),
            image: NEW_IMAGE.into(),
            reprovision: false,
            keep_old_system_disk: false,
        })?;
        assert!(
            plan.notes
                .iter()
                .any(|n| n.contains("ozbox adopt-fleet-key main")),
            "{:?}",
            plan.notes
        );
        assert!(!last_tofu_vars(&aws).contains("secrets_key_arn="));
        // no fleet key configured: nothing to suggest
        let plan = provider(&aws).plan(&Operation::Upgrade {
            name: before.spec.name.clone(),
            image: NEW_IMAGE.into(),
            reprovision: false,
            keep_old_system_disk: false,
        })?;
        assert!(!plan.notes.iter().any(|n| n.contains("adopt-fleet-key")));
        Ok(())
    }

    /// The record `ozbox upgrade` trusts: the first-boot hash the machine was CREATED with, read from its tag. A same-image
    /// replace gives the new machine this program's hash; the hash is never passed back as a label to set.
    #[test]
    fn the_machine_records_its_first_boot_and_a_same_image_replace_renews_it() -> TestResult {
        let (old, new) = ("1".repeat(64), "2".repeat(64));
        let aws = Arc::new(FakeAws::new());
        let first = provider_with(&aws, |c| c.first_boot_sha256 = Some(old.clone()));
        let rec = running(&aws, &first, "main", Size::S)?;
        assert_eq!(
            rec.spec.labels.get(ozbox_core::FIRST_BOOT_LABEL),
            Some(&old),
            "the machine's tag is read into the record"
        );
        let later = provider_with(&aws, |c| c.first_boot_sha256 = Some(new.clone()));
        let image = rec.spec.image.clone().ok_or("no image")?;
        let op = Operation::Upgrade {
            name: rec.spec.name.clone(),
            image: image.clone(),
            reprovision: true,
            keep_old_system_disk: false,
        };
        assert!(later.check_reprovision(&rec).is_ok());
        let plan = later.plan(&op)?;
        assert!(plan
            .changes
            .iter()
            .any(|c| c.kind == "instance.replace_image"));
        let v = last_tofu_vars(&aws);
        assert!(
            v.contains(&format!("first_boot_sha256={new}")) && !v.contains(&old),
            "the replace renders this program's first boot and never passes the old record back: {v}"
        );
        let after = later.apply(&plan)?.ok_or("no record")?;
        assert_eq!(after.spec.image.as_deref(), Some(image.as_str()));
        assert_ne!(after.provider_id, rec.provider_id, "a new machine");
        assert_eq!(
            after.spec.labels.get(ozbox_core::FIRST_BOOT_LABEL),
            Some(&new)
        );
        Ok(())
    }

    /// A box made before the ingress account existed has no pinned key for it; its upgrade pins this computer's, and a box that
    /// already has one keeps its own.
    #[test]
    fn an_upgrade_pins_the_ingress_key_on_a_box_that_has_none_and_keeps_an_existing_one(
    ) -> TestResult {
        let ingress = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
        let aws = Arc::new(FakeAws::new());
        let before = running(&aws, &provider(&aws), "main", Size::S)?;
        let later = provider_with(&aws, |c| c.upgrade_ingress_pin = Some(ingress.into()));
        let plan = later.plan(&Operation::Upgrade {
            name: before.spec.name.clone(),
            image: NEW_IMAGE.into(),
            reprovision: false,
            keep_old_system_disk: false,
        })?;
        let v = last_tofu_vars(&aws);
        assert!(
            v.contains(ingress),
            "the label reaches the new user data: {v}"
        );
        assert!(plan.notes.iter().any(|n| n.contains("ingress account")));
        let aws = Arc::new(FakeAws::new());
        let p = provider(&aws);
        let mut spec = BoxSpec::new(BoxName::new("main")?, Size::S);
        let theirs = "zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz";
        spec.labels
            .insert(ozbox_core::INGRESS_LABEL.into(), theirs.into());
        let rec = p
            .apply(&p.plan(&Operation::Create { spec })?)?
            .ok_or("no record")?;
        let later = provider_with(&aws, |c| c.upgrade_ingress_pin = Some(ingress.into()));
        later.plan(&Operation::Upgrade {
            name: rec.spec.name.clone(),
            image: NEW_IMAGE.into(),
            reprovision: false,
            keep_old_system_disk: false,
        })?;
        let v = last_tofu_vars(&aws);
        assert!(v.contains(theirs) && !v.contains(ingress), "{v}");
        Ok(())
    }

    const NEW_IMAGE: &str = "ami-0fedcba9876543210";
    /// What OpenTofu prints when RunInstances is refused for a full vCPU quota.
    const QUOTA_ERROR: &str = "Error: creating EC2 Instance: operation error EC2: RunInstances, api error VcpuLimitExceeded: You have requested more vCPU capacity than your current vCPU limit of 32 allows for the instance bucket that the specified instance type belongs to.";

    #[test]
    fn an_upgrade_plans_and_runs_a_checked_replace_that_keeps_the_work_volume() -> TestResult {
        let aws = Arc::new(FakeAws::new());
        let p = provider(&aws);
        let before = running(&aws, &p, "main", Size::S)?;
        assert_eq!(before.spec.image.as_deref(), Some("ami-0123456789abcdef0"));
        let work_before = aws
            .work_volume_of(before.provider_id.as_deref().ok_or("no id")?)
            .ok_or("no work volume")?;
        // grown and resized by hand before: the upgrade must keep both
        let op = Operation::Upgrade {
            name: before.spec.name.clone(),
            image: NEW_IMAGE.into(),
            reprovision: false,
            keep_old_system_disk: false,
        };
        aws.clear_calls();
        let plan = p.plan(&op)?;
        let kinds: Vec<_> = plan.changes.iter().map(|c| c.kind.as_str()).collect();
        assert_eq!(
            kinds,
            [
                "instance.stop",
                "instance.replace_image",
                "volume.reattach",
                "instance.start"
            ]
        );
        assert!(plan
            .notes
            .iter()
            .any(|n| n.contains("OpenTofu checked the change first")));
        // planning stopped and tagged nothing, and applied nothing
        let mutating: Vec<String> = aws
            .calls()
            .iter()
            .filter(|c| {
                c.args.iter().any(|a| {
                    matches!(
                        a.as_str(),
                        "stop-instances" | "create-tags" | "apply" | "delete-tags"
                    )
                })
            })
            .map(|c| c.args.join(" "))
            .collect();
        assert!(mutating.is_empty(), "{mutating:?}");

        aws.clear_calls();
        let after = p.apply(&plan)?.ok_or("no record")?;
        assert_eq!(after.state, BoxState::Running);
        assert_eq!(after.spec.image.as_deref(), Some(NEW_IMAGE));
        assert_ne!(after.provider_id, before.provider_id, "a new machine");
        assert_eq!(
            aws.work_volume_of(after.provider_id.as_deref().ok_or("no id")?),
            Some(work_before.clone()),
            "the same /work volume is attached to the new machine"
        );
        assert!(!after.spec.labels.contains_key(UPGRADE_TO_LABEL));
        assert_eq!(
            aws.volume_tags(&work_before).get(UPGRADE_TO_LABEL),
            None,
            "the mark is cleared"
        );
        // what was run, in order: mark on the VOLUME, stop, checked plan, apply of that plan
        let calls: Vec<String> = aws
            .calls()
            .iter()
            .filter(|c| {
                c.program == "tofu"
                    || c.args
                        .get(1)
                        .is_some_and(|s| s.contains("tags") || s.starts_with("stop"))
            })
            .map(|c| {
                if c.program == "tofu" {
                    c.args
                        .iter()
                        .skip(1)
                        .take(2)
                        .cloned()
                        .collect::<Vec<_>>()
                        .join(" ")
                } else {
                    c.args[..c.args.len().min(4)].join(" ")
                }
            })
            .collect();
        let pos = |needle: &str| calls.iter().position(|c| c.contains(needle));
        let mark = pos("create-tags --resources vol-").ok_or("no mark")?;
        let stop = pos("stop-instances").ok_or("no stop")?;
        let plan_at = calls
            .iter()
            .rposition(|c| c.starts_with("plan"))
            .ok_or("no tofu plan")?;
        let apply_at = calls
            .iter()
            .rposition(|c| c.starts_with("apply"))
            .ok_or("no tofu apply")?;
        assert!(
            mark < stop && stop < plan_at && plan_at < apply_at,
            "{calls:?}"
        );
        let plan_cmd = aws
            .calls()
            .into_iter()
            .rev()
            .find(|c| c.args.iter().any(|a| a == "plan"))
            .ok_or("no plan call")?;
        for want in [
            "-replace=aws_instance.box",
            "image_id=ami-0fedcba9876543210",
            "machine_type=m7i.xlarge",
            "box_name=main",
        ] {
            assert!(plan_cmd.args.iter().any(|a| a == want), "missing {want}");
        }
        let labels = plan_cmd
            .args
            .iter()
            .find(|a| a.starts_with("labels="))
            .ok_or("no labels")?;
        assert!(labels.contains("ozbox-always-on"), "{labels}");
        assert!(!labels.contains(UPGRADE_TO_LABEL), "{labels}");
        // the plan file never outlives the run
        assert!(plan_cmd
            .args
            .iter()
            .any(|a| a.starts_with("-out=") && a.ends_with(".tfplan")));
        // and the same image again is nothing to do
        assert!(p.plan(&op)?.is_noop());
        Ok(())
    }

    fn upgrade_op(name: &BoxName) -> Operation {
        Operation::Upgrade {
            name: name.clone(),
            image: NEW_IMAGE.into(),
            reprovision: false,
            keep_old_system_disk: false,
        }
    }

    /// `tofu apply` runs, and the `tofu plan` runs that asked for a replacement.
    fn applies_and_replace_plans(aws: &FakeAws) -> (usize, usize) {
        let calls = aws.calls();
        let tofu =
            |c: &&CommandSpec, word: &str| c.program == "tofu" && c.args.iter().any(|a| a == word);
        (
            calls.iter().filter(|c| tofu(c, "apply")).count(),
            calls
                .iter()
                .filter(|c| tofu(c, "plan") && c.args.iter().any(|a| a.starts_with("-replace=")))
                .count(),
        )
    }

    fn stranded(aws: &Arc<FakeAws>, p: &Engine<AwsBackend>) -> TestResult2 {
        let rec = running(aws, p, "main", Size::S)?;
        let work = aws
            .work_volume_of(rec.provider_id.as_deref().ok_or("no id")?)
            .ok_or("no work volume")?;
        aws.fail_creates(1, QUOTA_ERROR);
        let plan = p.plan(&upgrade_op(&rec.spec.name))?;
        p.apply(&plan).err().ok_or("the apply should fail")?;
        Ok((rec.spec.name, work))
    }
    type TestResult2 = std::result::Result<(BoxName, String), Box<dyn std::error::Error>>;

    #[test]
    fn destroying_a_box_with_no_machine_runs_tofu_destroy_in_its_workspace() -> TestResult {
        let aws = Arc::new(FakeAws::new());
        let p = provider(&aws);
        let (name, work) = stranded(&aws, &p)?;
        let plan = p.plan(&Operation::Destroy {
            name: name.clone(),
            final_snapshot: false,
            keep_old_system_disks: false,
        })?;
        assert_eq!(plan.max_risk(), Some(ozbox_core::Risk::High));
        assert!(plan
            .changes
            .iter()
            .any(|c| c.description.contains("/work volume")));
        assert!(plan
            .notes
            .iter()
            .any(|n| n.contains(&work) && n.contains("OpenTofu will destroy")));
        assert!(plan.notes.iter().any(|n| n.contains("final snapshot")));
        p.apply(&plan)?;
        assert!(p.get(&name)?.is_none(), "the box is gone");
        assert!(aws.volume_tags(&work).is_empty(), "the volume is gone");
        let calls = aws.calls();
        assert!(calls
            .iter()
            .any(|c| c.program == "tofu" && c.args.iter().any(|a| a == "destroy")));
        assert!(!calls
            .iter()
            .any(|c| c.args.get(1).map(String::as_str) == Some("delete-volume")));
        Ok(())
    }

    #[test]
    fn destroying_a_box_with_no_machine_and_no_state_deletes_the_volume_directly() -> TestResult {
        let aws = Arc::new(FakeAws::new());
        let p = provider(&aws);
        let (name, work) = stranded(&aws, &p)?;
        aws.forget_workspace("main");
        let plan = p.plan(&Operation::Destroy {
            name: name.clone(),
            final_snapshot: true,
            keep_old_system_disks: false,
        })?;
        assert!(plan.changes.iter().any(|c| c.kind == "snapshot.create"));
        assert!(plan.notes.iter().any(|n| n.contains("deleted directly")));
        p.apply(&plan)?;
        assert!(p.get(&name)?.is_none());
        assert!(aws.volume_tags(&work).is_empty());
        let calls = aws.calls();
        assert!(!calls
            .iter()
            .any(|c| c.program == "tofu" && c.args.iter().any(|a| a == "destroy")));
        assert!(calls
            .iter()
            .any(|c| c.args.get(1).map(String::as_str) == Some("delete-volume")));
        Ok(())
    }

    #[test]
    fn a_machine_refused_after_the_old_one_was_removed_is_listed_and_finished_by_upgrade(
    ) -> TestResult {
        let aws = Arc::new(FakeAws::new());
        let p = provider(&aws);
        let mut spec = BoxSpec::new(BoxName::new("main")?, Size::S);
        spec.labels.insert("purpose".into(), "demo".into());
        let before = p
            .apply(&p.plan(&Operation::Create { spec })?)?
            .ok_or("no record")?;
        let work = aws
            .work_volume_of(before.provider_id.as_deref().ok_or("no id")?)
            .ok_or("no work volume")?;
        aws.fail_creates(1, QUOTA_ERROR);
        let plan = p.plan(&upgrade_op(&before.spec.name))?;
        let failed = p.apply(&plan).err().ok_or("the apply should fail")?;
        assert!(failed.to_string().contains("VcpuLimitExceeded"), "{failed}");
        assert_eq!(aws.machines_of(&before.spec.name), 0, "the old one is gone");

        // Listed, plainly, with everything needed to rebuild it.
        let stuck = p.get(&before.spec.name)?.ok_or("the box vanished")?;
        assert_eq!(stuck.state, BoxState::InstanceMissing);
        assert_eq!(stuck.provider_id, None);
        assert_eq!(stuck.machine_type.as_deref(), Some("m7i.xlarge"));
        assert_eq!(stuck.spec.size, Size::S);
        assert_eq!(stuck.spec.work_disk_gb, before.spec.work_disk_gb);
        assert_eq!(
            stuck.spec.labels.get(UPGRADE_TO_LABEL).map(String::as_str),
            Some(NEW_IMAGE)
        );
        assert_eq!(
            stuck.spec.labels.get("purpose").map(String::as_str),
            Some("demo"),
            "the box's own labels come back from the volume"
        );
        assert_eq!(
            aws.volume_tags(&work)
                .get(UPGRADE_TO_LABEL)
                .map(String::as_str),
            Some(NEW_IMAGE)
        );

        // Nothing but upgrade acts on it.
        for op in [
            Operation::Pause {
                name: stuck.spec.name.clone(),
            },
            Operation::Resume {
                name: stuck.spec.name.clone(),
            },
            Operation::Snapshot {
                name: stuck.spec.name.clone(),
            },
        ] {
            assert!(
                matches!(p.plan(&op), Err(Error::InvalidState { .. })),
                "{op:?}"
            );
        }

        // Finishing: create and reattach, the volume untouched, planned through the same guard.
        aws.clear_calls();
        let finish = p.plan(&upgrade_op(&stuck.spec.name))?;
        let kinds: Vec<&str> = finish.changes.iter().map(|c| c.kind.as_str()).collect();
        assert_eq!(
            kinds,
            ["instance.create", "volume.reattach", "instance.start"]
        );
        assert!(
            aws.calls()
                .iter()
                .all(|c| !c.args.iter().any(|a| a.starts_with("-replace="))),
            "a machine that is gone is created, not replaced"
        );
        let done = p.apply(&finish)?.ok_or("no record")?;
        assert_eq!(done.state, BoxState::Running);
        assert_eq!(done.spec.image.as_deref(), Some(NEW_IMAGE));
        assert_eq!(
            aws.work_volume_of(done.provider_id.as_deref().ok_or("no id")?)
                .as_deref(),
            Some(work.as_str()),
            "the very same /work volume is attached again"
        );
        let tags = aws.volume_tags(&work);
        assert!(
            !tags.contains_key(UPGRADE_TO_LABEL) && !tags.contains_key(UPGRADE_MACHINE_TAG),
            "{tags:?}"
        );
        assert!(!done.spec.labels.contains_key(UPGRADE_TO_LABEL));
        assert!(p.plan(&upgrade_op(&done.spec.name))?.is_noop());
        Ok(())
    }

    #[test]
    fn a_refused_create_is_retried_with_a_pause_only_when_the_account_is_out_of_room() -> TestResult
    {
        // quota, twice, then room: one replacement and two creations
        let aws = Arc::new(FakeAws::new());
        let p = provider_retrying(&aws, 3);
        let b = running(&aws, &p, "main", Size::S)?;
        aws.fail_creates(2, QUOTA_ERROR);
        aws.clear_calls();
        let done = p
            .apply(&p.plan(&upgrade_op(&b.spec.name))?)?
            .ok_or("no record")?;
        assert_eq!(done.state, BoxState::Running);
        assert_eq!(done.spec.image.as_deref(), Some(NEW_IMAGE));
        let (applies, replace_plans) = applies_and_replace_plans(&aws);
        assert_eq!(applies, 3);
        // the plan, apply's re-plan and the apply's own plan each check the replacement once; the retries ask for none
        assert_eq!(
            replace_plans, 3,
            "retries are plain creations, not replacements"
        );

        // an error that is not about room stops at once
        let aws = Arc::new(FakeAws::new());
        let p = provider_retrying(&aws, 3);
        let b = running(&aws, &p, "main", Size::S)?;
        aws.fail_creates(
            5,
            "Error: UnauthorizedOperation: You are not authorized to perform this operation.",
        );
        aws.clear_calls();
        assert!(p.apply(&p.plan(&upgrade_op(&b.spec.name))?).is_err());
        assert_eq!(applies_and_replace_plans(&aws).0, 1);
        assert_eq!(
            p.get(&b.spec.name)?.map(|r| r.state),
            Some(BoxState::InstanceMissing)
        );

        // room never comes back: it gives up after the retries and leaves the box recoverable
        let aws = Arc::new(FakeAws::new());
        let p = provider_retrying(&aws, 2);
        let b = running(&aws, &p, "main", Size::S)?;
        aws.fail_creates(50, QUOTA_ERROR);
        aws.clear_calls();
        assert!(p.apply(&p.plan(&upgrade_op(&b.spec.name))?).is_err());
        assert_eq!(
            applies_and_replace_plans(&aws).0,
            3,
            "the first try and two retries"
        );
        assert_eq!(
            p.get(&b.spec.name)?.map(|r| r.state),
            Some(BoxState::InstanceMissing)
        );
        Ok(())
    }

    #[test]
    fn finishing_never_applies_a_plan_that_would_delete_replace_or_create_the_work_volume(
    ) -> TestResult {
        for (hook, what) in [
            (FakeAws::plan_replaces_volume as fn(&FakeAws), "replaces"),
            (FakeAws::plan_creates_volume as fn(&FakeAws), "creates"),
        ] {
            let aws = Arc::new(FakeAws::new());
            let p = provider(&aws);
            let b = running(&aws, &p, "main", Size::S)?;
            aws.strand_upgrade(&b.spec.name, NEW_IMAGE)?;
            hook(&aws);
            aws.clear_calls();
            match p.plan(&upgrade_op(&b.spec.name)) {
                Err(Error::Provider(m)) => {
                    assert!(m.contains("aws_ebs_volume.work"), "{what}: {m}")
                }
                other => panic!("{what}: expected a refusal, got {other:?}"),
            }
            assert!(
                aws.calls()
                    .iter()
                    .all(|c| !c.args.iter().any(|a| a == "apply")),
                "{what}: nothing was applied"
            );
            assert_eq!(aws.machines_of(&b.spec.name), 0);
        }
        Ok(())
    }

    #[test]
    fn only_a_marked_work_volume_with_its_state_and_machine_type_is_offered_for_recovery(
    ) -> TestResult {
        let aws = Arc::new(FakeAws::new());
        let p = provider(&aws);
        let b = running(&aws, &p, "main", Size::S)?;
        let work = aws
            .work_volume_of(b.provider_id.as_deref().ok_or("no id")?)
            .ok_or("no work volume")?;
        let tag_call = |verb: &str, tags: &[&str]| {
            let mut c =
                CommandSpec::new("aws").args(["ec2", verb, "--resources", work.as_str(), "--tags"]);
            c = c.args(tags.iter().copied());
            c
        };
        aws.strand_upgrade(&b.spec.name, NEW_IMAGE)?;
        assert_eq!(
            p.get(&b.spec.name)?.map(|r| r.state),
            Some(BoxState::InstanceMissing)
        );

        // no machine type on the disk: still listed, but not rebuilt on a guess
        aws.run(&tag_call("delete-tags", &["Key=ozbox-upgrade-machine"]))?;
        match p.plan(&upgrade_op(&b.spec.name)) {
            Err(Error::Config(m)) => assert!(m.contains("machine type"), "{m}"),
            other => panic!("expected a refusal, got {other:?}"),
        }

        // no OpenTofu state here: said so, nothing guessed
        aws.run(&tag_call(
            "create-tags",
            &["Key=ozbox-upgrade-machine,Value=m7i.xlarge"],
        ))?;
        aws.forget_workspace("main");
        match p.plan(&upgrade_op(&b.spec.name)) {
            Err(Error::Provider(m)) => assert!(m.contains("no OpenTofu state"), "{m}"),
            other => panic!("expected a refusal, got {other:?}"),
        }

        // without the upgrade mark a volume with no machine is just a volume: not a box
        aws.run(&tag_call("delete-tags", &["Key=ozbox-upgrade-to"]))?;
        assert!(p.get(&b.spec.name)?.is_none());
        Ok(())
    }

    #[test]
    fn capacity_and_quota_refusals_are_told_apart_from_every_other_failure() {
        assert!(is_capacity_error(QUOTA_ERROR));
        assert!(is_capacity_error("api error InsufficientInstanceCapacity: We currently do not have sufficient m7i.xlarge capacity"));
        assert!(is_capacity_error(
            "InstanceLimitExceeded: You have requested more instances"
        ));
        assert!(!is_capacity_error("UnauthorizedOperation: not allowed"));
        assert!(!is_capacity_error("InvalidAMIID.NotFound"));
        assert!(!is_capacity_error(""));
    }

    #[test]
    fn latest_is_verified_only_when_the_signed_manifest_lists_the_image_for_the_region(
    ) -> TestResult {
        // published for this region, signature good: verified
        let aws = Arc::new(FakeAws::new());
        aws.publish_release("2026.11.0", "us-east-1");
        let p = provider(&aws);
        let latest = p.latest_image(None)?;
        assert!(latest.signature_verified, "{:?}", latest.signature_detail);
        assert!(latest.signature_applicable);
        assert!(latest
            .signature_detail
            .as_deref()
            .is_some_and(|d| d.contains("2026.11.0")));
        // the tools were run with the pinned identity
        let cosign = aws
            .calls()
            .into_iter()
            .find(|c| c.program == "cosign" && c.args.first().is_some_and(|a| a == "verify-blob"))
            .ok_or("cosign never ran")?;
        assert!(cosign.args.iter().any(|a| a.contains("image\\.yml")));

        // a manifest for another region cannot vouch for this one
        let aws = Arc::new(FakeAws::new());
        aws.publish_release("2026.11.0", "us-west-2");
        let latest = provider(&aws).latest_image(None)?;
        assert!(!latest.signature_verified);
        assert!(latest
            .signature_detail
            .is_some_and(|d| d.contains("not in the signed manifest")));

        // a signature that does not verify
        let aws = Arc::new(FakeAws::new());
        aws.publish_release("2026.11.0", "us-east-1");
        aws.refuse_signatures();
        let latest = provider(&aws).latest_image(None)?;
        assert!(!latest.signature_verified);
        assert!(latest
            .signature_detail
            .is_some_and(|d| d.contains("did not verify")));

        // nothing published for the release
        let aws = Arc::new(FakeAws::new());
        let latest = provider(&aws).latest_image(None)?;
        assert!(!latest.signature_verified);
        assert!(latest
            .signature_detail
            .is_some_and(|d| d.contains("not found")));
        Ok(())
    }

    #[test]
    fn an_explicit_image_is_inspected_the_same_way_and_an_untagged_one_is_unverified() -> TestResult
    {
        let aws = Arc::new(FakeAws::new());
        aws.publish_release("2026.10.0", "us-east-1");
        let p = provider(&aws);
        let tagged = p.image_info("ami-0123456789abcdef0", None)?;
        assert!(tagged.signature_verified, "{:?}", tagged.signature_detail);
        assert_eq!(tagged.release.as_deref(), Some("2026.10.0"));
        // an image the account built without the release tag has nothing to verify against
        let untagged = p.image_info("ami-0cccccccccccccccc", None)?;
        assert!(!untagged.signature_verified);
        assert!(untagged
            .signature_detail
            .is_some_and(|d| d.contains("release tag")));
        // an id that is not there is a refusal with a reason, not a guess
        assert!(matches!(
            p.image_info("ami-0eeeeeeeeeeeeeeee", None),
            Err(Error::Config(_))
        ));
        Ok(())
    }

    #[test]
    fn an_upgrade_keeps_a_size_and_disk_changed_since_creation() -> TestResult {
        let aws = Arc::new(FakeAws::new());
        let p = provider(&aws);
        let n = BoxName::new("grown")?;
        running(&aws, &p, "grown", Size::S)?;
        p.apply(&p.plan(&Operation::Resize {
            name: n.clone(),
            size: Some(Size::M),
            work_disk_gb: Some(300),
        })?)?;
        let plan = p.plan(&Operation::Upgrade {
            name: n.clone(),
            image: NEW_IMAGE.into(),
            reprovision: false,
            keep_old_system_disk: false,
        })?;
        let after = p.apply(&plan)?.ok_or("no record")?;
        assert_eq!(after.machine_type.as_deref(), Some("m7i.2xlarge"));
        assert_eq!(after.spec.work_disk_gb, 300);
        assert_eq!(after.spec.size, Size::M);
        Ok(())
    }

    #[test]
    fn a_plan_that_would_replace_the_work_volume_is_refused_before_anything_stops() -> TestResult {
        let aws = Arc::new(FakeAws::new());
        let p = provider(&aws);
        let rec = running(&aws, &p, "danger", Size::S)?;
        aws.plan_replaces_volume();
        aws.clear_calls();
        let err = p
            .plan(&Operation::Upgrade {
                name: rec.spec.name.clone(),
                image: NEW_IMAGE.into(),
                reprovision: false,
                keep_old_system_disk: false,
            })
            .err()
            .ok_or("must refuse")?
            .to_string();
        assert!(
            err.contains("aws_ebs_volume.work") && err.contains("Nothing was changed"),
            "{err}"
        );
        assert!(aws.calls().iter().all(|c| !c
            .args
            .iter()
            .any(|a| matches!(a.as_str(), "stop-instances" | "create-tags" | "apply"))));
        assert_eq!(
            p.get(&rec.spec.name)?.ok_or("gone")?.state,
            BoxState::Running
        );
        Ok(())
    }

    #[test]
    fn bad_images_are_refused_while_planning_with_a_reason() -> TestResult {
        let aws = Arc::new(FakeAws::new());
        let p = provider(&aws);
        let rec = running(&aws, &p, "picky", Size::S)?;
        let why = |image: &str| -> Result<String> {
            Ok(p.plan(&Operation::Upgrade {
                name: rec.spec.name.clone(),
                image: image.into(),
                reprovision: false,
                keep_old_system_disk: false,
            })
            .err()
            .ok_or_else(|| Error::Provider(format!("{image} must be refused")))?
            .to_string())
        };
        assert!(why("ami-0aaaaaaaaaaaaaaaa")?.contains("arm64"));
        assert!(why("ami-0bbbbbbbbbbbbbbbb")?.contains("not available yet"));
        assert!(why("ami-0dddddddddddddddd")?.contains("was not found"));
        assert!(why("not-an-image")?.contains("not an AWS image id"));
        assert!(why("latest")?.contains("concrete image id"));
        // an image that is not tagged as an Oz image is allowed, with a warning
        let plan = p.plan(&Operation::Upgrade {
            name: rec.spec.name.clone(),
            image: "ami-0cccccccccccccccc".into(),
            reprovision: false,
            keep_old_system_disk: false,
        })?;
        assert!(plan
            .notes
            .iter()
            .any(|n| n.contains("may not be an Oz image")));
        Ok(())
    }

    #[test]
    fn a_paused_box_over_the_quota_is_refused_before_the_module_is_even_planned() -> TestResult {
        let aws = Arc::new(FakeAws::new());
        let p = provider(&aws);
        let rec = running(&aws, &p, "waiting", Size::S)?;
        p.apply(&p.plan(&Operation::Pause {
            name: rec.spec.name.clone(),
        })?)?;
        aws.set_vcpu_quota(2.0);
        aws.clear_calls();
        let err = p
            .plan(&Operation::Upgrade {
                name: rec.spec.name.clone(),
                image: NEW_IMAGE.into(),
                reprovision: false,
                keep_old_system_disk: false,
            })
            .err()
            .ok_or("must refuse")?;
        assert!(err.to_string().contains("2 vCPUs"), "{err}");
        assert!(
            aws.calls().iter().all(|c| c.program != "tofu"),
            "the quota is checked first; no module work for a start that would be refused"
        );
        Ok(())
    }

    #[test]
    fn an_apply_that_dies_after_the_stop_is_finished_by_running_upgrade_again() -> TestResult {
        let aws = Arc::new(FakeAws::new());
        let p = provider(&aws);
        let rec = running(&aws, &p, "half", Size::S)?;
        let work = aws
            .work_volume_of(rec.provider_id.as_deref().ok_or("no id")?)
            .ok_or("no work volume")?;
        let op = Operation::Upgrade {
            name: rec.spec.name.clone(),
            image: NEW_IMAGE.into(),
            reprovision: false,
            keep_old_system_disk: false,
        };
        let plan = p.plan(&op)?;
        aws.fail_next_replace_apply();
        assert!(p.apply(&plan).is_err());
        let stuck = p.get(&rec.spec.name)?.ok_or("gone")?;
        assert_eq!(stuck.state, BoxState::Paused);
        assert_eq!(stuck.spec.image.as_deref(), Some("ami-0123456789abcdef0"));
        assert_eq!(
            stuck.spec.labels.get(UPGRADE_TO_LABEL).map(String::as_str),
            Some(NEW_IMAGE),
            "the mark lives on the /work volume, which the replacement does not touch"
        );
        let again = p.plan(&op)?;
        assert!(again.changes.iter().all(|c| c.kind != "instance.stop"));
        let done = p.apply(&again)?.ok_or("no record")?;
        assert_eq!(done.state, BoxState::Running);
        assert_eq!(done.spec.image.as_deref(), Some(NEW_IMAGE));
        assert!(!done.spec.labels.contains_key(UPGRADE_TO_LABEL));
        assert_eq!(
            aws.work_volume_of(done.provider_id.as_deref().ok_or("no id")?),
            Some(work)
        );
        Ok(())
    }

    #[test]
    fn a_box_with_no_tofu_state_is_refused_not_guessed_at() -> TestResult {
        let aws = Arc::new(FakeAws::new());
        let p = provider(&aws);
        let rec = running(&aws, &p, "orphan", Size::S)?;
        // someone else removed the module's workspace
        aws.forget_workspace("orphan");
        let err = p
            .plan(&Operation::Upgrade {
                name: rec.spec.name.clone(),
                image: NEW_IMAGE.into(),
                reprovision: false,
                keep_old_system_disk: false,
            })
            .err()
            .ok_or("must refuse")?;
        assert!(err.to_string().contains("no OpenTofu state"), "{err}");
        Ok(())
    }

    #[test]
    fn latest_image_is_the_newest_available_oz_image_for_the_machine_architecture() -> TestResult {
        let aws = Arc::new(FakeAws::new());
        let p = provider(&aws);
        let latest = p.latest_image(None)?;
        // not the arm64 one, the one still pending, or the one without the tag, though those are newer
        assert_eq!(latest.id, NEW_IMAGE);
        assert_eq!(latest.release.as_deref(), Some("2026.11.0"));
        assert!(
            !latest.signature_verified,
            "no signed release is published for it, so nothing is claimed"
        );
        let call = aws
            .calls()
            .into_iter()
            .find(|c| c.args.get(1).map(String::as_str) == Some("describe-images"))
            .ok_or("no call")?;
        assert!(call
            .args
            .iter()
            .any(|a| a == "Name=tag-key,Values=ozbox-image"));
        assert!(call.args.iter().any(|a| a == "self"));
        assert_eq!(ozbox_core::resolve_image(&p, "latest", None)?, NEW_IMAGE);
        let empty = FakeAws::new();
        empty.remove_images();
        let q = provider(&Arc::new(empty));
        assert!(q.latest_image(None).is_err());
        Ok(())
    }

    fn provider_publisher(aws: &Arc<FakeAws>, publisher: Option<&str>) -> Engine<AwsBackend> {
        let cfg = AwsConfig {
            region: Some("us-east-1".into()),
            subnet_id: Some("subnet-0123456789abcdef0".into()),
            image_publisher: publisher.map(str::to_string),
            ..AwsConfig::default()
        };
        Engine::new(AwsBackend::with_env_none(aws.clone(), cfg))
    }

    /// An account with no Oz image of its own, which sees these public ones.
    fn public_only(aws: &FakeAws) {
        aws.remove_own_images();
    }

    fn release_name(stamp: &str) -> String {
        format!("ozbox-{}-{stamp}", env!("CARGO_PKG_VERSION"))
    }

    const V: &str = env!("CARGO_PKG_VERSION");

    fn provider_program(aws: &Arc<FakeAws>, program: &str) -> Engine<AwsBackend> {
        let cfg = AwsConfig {
            region: Some("us-east-1".into()),
            subnet_id: Some("subnet-0123456789abcdef0".into()),
            program_version: Some(program.into()),
            ..AwsConfig::default()
        };
        Engine::new(AwsBackend::with_env_none(aws.clone(), cfg))
    }

    #[test]
    fn latest_prefers_the_callers_own_image_over_a_newer_public_one() -> TestResult {
        let aws = Arc::new(FakeAws::new());
        aws.add_public_image(
            "ami-0pub",
            public_images::PUBLISHER_ACCOUNT_ID,
            &release_name("20261201000000"),
            "2026-12-01T00:00:00.000Z",
        );
        aws.publish_release_of(V, "us-east-1", &["ami-0pub"]);
        let latest = provider_publisher(&aws, None).latest_image(None)?;
        assert_eq!(
            latest.id, NEW_IMAGE,
            "the account's own image is a deliberate choice"
        );
        assert!(
            aws.calls().iter().all(|c| c
                .args
                .iter()
                .all(|a| a != public_images::PUBLISHER_ACCOUNT_ID)),
            "the public images are not even looked at"
        );
        Ok(())
    }

    #[test]
    fn without_an_image_of_its_own_latest_is_the_publishers_verified_public_image() -> TestResult {
        let aws = Arc::new(FakeAws::new());
        public_only(&aws);
        aws.add_public_image(
            "ami-0pub",
            public_images::PUBLISHER_ACCOUNT_ID,
            &release_name("20261201000000"),
            "2026-12-01T00:00:00.000Z",
        );
        aws.publish_release_of(V, "us-east-1", &["ami-0pub"]);
        let latest = provider_publisher(&aws, None).latest_image(None)?;
        assert_eq!(latest.id, "ami-0pub");
        assert_eq!(latest.release.as_deref(), Some(V));
        assert!(latest.signature_verified);
        let ask = aws
            .calls()
            .into_iter()
            .rfind(|c| c.args.get(1).map(String::as_str) == Some("describe-images"))
            .ok_or("no describe-images call")?;
        // the owner is asked for by id, server side: not a search of every public image
        let at = ask
            .args
            .iter()
            .position(|a| a == "--owners")
            .ok_or("no owners")?;
        assert_eq!(ask.args[at + 1], public_images::PUBLISHER_ACCOUNT_ID);
        // and the signature check is the one every release goes through
        assert!(aws
            .calls()
            .iter()
            .any(|c| c.program == "cosign" && c.args.first().is_some_and(|a| a == "verify-blob")));
        Ok(())
    }

    #[test]
    fn a_look_alike_from_another_account_is_never_chosen_even_if_newer_and_listed() -> TestResult {
        let aws = Arc::new(FakeAws::new());
        public_only(&aws);
        aws.add_public_image(
            "ami-0evil",
            "999999999999",
            &release_name("20261230000000"),
            "2026-12-30T00:00:00.000Z",
        );
        // even a manifest that lists it cannot make it the publisher's
        aws.publish_release_of(V, "us-east-1", &["ami-0evil"]);
        let err = provider_publisher(&aws, None)
            .latest_image(None)
            .err()
            .ok_or("must refuse")?
            .to_string();
        assert!(err.contains("no public image here"), "{err}");
        assert!(
            err.contains("us-east-1, eu-west-1, ap-southeast-1"),
            "{err}"
        );
        // and if the cloud's owner filter did not hold (or a bug asked for every public image), the client's own check does
        aws.ignore_owner_filter();
        let err = provider_publisher(&aws, None)
            .latest_image(None)
            .err()
            .ok_or("must refuse")?
            .to_string();
        assert!(
            err.contains("ami-0evil") && err.contains("another account"),
            "{err}"
        );
        Ok(())
    }

    #[test]
    fn a_publisher_image_missing_from_the_signed_manifest_is_refused_and_an_older_listed_one_is_used(
    ) -> TestResult {
        let aws = Arc::new(FakeAws::new());
        public_only(&aws);
        aws.add_public_image(
            "ami-0new",
            public_images::PUBLISHER_ACCOUNT_ID,
            &release_name("20261201000000"),
            "2026-12-01T00:00:00.000Z",
        );
        aws.add_public_image(
            "ami-0old",
            public_images::PUBLISHER_ACCOUNT_ID,
            &release_name("20261101000000"),
            "2026-11-01T00:00:00.000Z",
        );
        // the manifest lists only the older build (the newer was made public, then its release failed to sign)
        aws.publish_release_of(V, "us-east-1", &["ami-0old"]);
        let latest = provider_publisher(&aws, None).latest_image(None)?;
        assert_eq!(latest.id, "ami-0old");
        assert!(latest.signature_verified);
        Ok(())
    }

    #[test]
    fn when_nothing_public_verifies_nothing_is_returned_and_the_reasons_are_given() -> TestResult {
        for refuse in [false, true] {
            let aws = Arc::new(FakeAws::new());
            public_only(&aws);
            aws.add_public_image(
                "ami-0pub",
                public_images::PUBLISHER_ACCOUNT_ID,
                &release_name("20261201000000"),
                "2026-12-01T00:00:00.000Z",
            );
            if refuse {
                aws.publish_release_of(V, "us-east-1", &["ami-0pub"]);
                aws.refuse_signatures();
            }
            let err = provider_publisher(&aws, None)
                .latest_image(None)
                .err()
                .ok_or("must refuse")?
                .to_string();
            assert!(
                err.contains("ami-0pub") && err.to_lowercase().contains("nothing was created"),
                "{err}"
            );
            assert!(err.contains("--image"), "{err}");
        }
        Ok(())
    }

    #[test]
    fn a_region_the_publisher_does_not_publish_in_says_which_ones_it_does() -> TestResult {
        let aws = Arc::new(FakeAws::new());
        public_only(&aws);
        let err = provider_publisher(&aws, None)
            .latest_image(None)
            .err()
            .ok_or("must refuse")?
            .to_string();
        assert!(
            err.contains("us-east-1, eu-west-1, ap-southeast-1") && err.contains("build your own")
        );
        Ok(())
    }

    #[test]
    fn public_images_can_be_turned_off_or_pointed_at_a_fork_publishers_account() -> TestResult {
        let aws = Arc::new(FakeAws::new());
        public_only(&aws);
        aws.add_public_image(
            "ami-0pub",
            public_images::PUBLISHER_ACCOUNT_ID,
            &release_name("20261201000000"),
            "2026-12-01T00:00:00.000Z",
        );
        aws.publish_release_of(V, "us-east-1", &["ami-0pub"]);
        let err = provider_publisher(&aws, Some("none"))
            .latest_image(None)
            .err()
            .ok_or("off means off")?
            .to_string();
        assert!(err.contains("public images are turned off"), "{err}");
        // another publisher: the project's own account is no longer trusted
        let err = provider_publisher(&aws, Some("210987654321"))
            .latest_image(None)
            .err()
            .ok_or("the project's account is not trusted by a fork's setting")?
            .to_string();
        assert!(
            err.contains("no public image here") && err.contains("210987654321"),
            "{err}"
        );
        Ok(())
    }

    #[test]
    fn a_failed_check_of_the_best_candidate_stops_and_never_falls_back_to_an_older_image(
    ) -> TestResult {
        let aws = Arc::new(FakeAws::new());
        public_only(&aws);
        // two releases this program can use, both published; but the network is down, so no download can be made. That says
        // nothing about the newer image, so the older one is not tried in its place (unlike a release that is not published).
        let newer = "ozbox-0.2.0-beta.1-20261201000000".to_string();
        aws.add_public_image(
            "ami-0new",
            public_images::PUBLISHER_ACCOUNT_ID,
            &newer,
            "2026-12-01T00:00:00.000Z",
        );
        aws.add_public_image(
            "ami-0old",
            public_images::PUBLISHER_ACCOUNT_ID,
            "ozbox-0.2.0-beta.0-20261101000000",
            "2026-11-01T00:00:00.000Z",
        );
        aws.publish_release_with(
            "0.2.0-beta.1",
            "0.2.0-beta.1",
            "us-east-1",
            &["ami-0new"],
            None,
        );
        aws.publish_release_with(
            "0.2.0-beta.0",
            "0.2.0-beta.0",
            "us-east-1",
            &["ami-0old"],
            None,
        );
        aws.make_releases_unreachable();
        let err = provider_program(&aws, "0.2.0-beta.0")
            .latest_image(None)
            .err()
            .ok_or("must stop")?
            .to_string();
        assert!(
            err.contains("ami-0new") && err.contains("no older image was tried"),
            "{err}"
        );
        Ok(())
    }

    #[test]
    fn a_swapped_old_manifest_stops_the_lookup_instead_of_falling_back_to_the_previous_release(
    ) -> TestResult {
        let aws = Arc::new(FakeAws::new());
        public_only(&aws);
        aws.add_public_image(
            "ami-020",
            public_images::PUBLISHER_ACCOUNT_ID,
            "ozbox-0.2.0-20261201000000",
            "2026-12-01T00:00:00.000Z",
        );
        aws.add_public_image(
            "ami-010",
            public_images::PUBLISHER_ACCOUNT_ID,
            "ozbox-0.2.0-20261101000000",
            "2026-11-01T00:00:00.000Z",
        );
        // release 0.2.0 is served release 0.1.9's validly signed manifest (it lists only the old image)
        aws.publish_release_with("0.2.0", "0.1.9", "us-east-1", &["ami-010"], None);
        let err = provider_program(&aws, "0.2.0")
            .latest_image(None)
            .err()
            .ok_or("must stop")?
            .to_string();
        assert!(
            err.contains("for release 0.1.9, not 0.2.0")
                && err.contains("no older image was tried"),
            "{err}"
        );
        Ok(())
    }

    // `latest` is the newest image whose SIGNED release verifies: an image of a release that was never published (its
    // publish step failed), or that was made private after a newer release, is passed over for the previous signed one.

    #[test]
    fn latest_passes_over_a_newest_image_whose_release_was_never_published_and_names_it(
    ) -> TestResult {
        let aws = Arc::new(FakeAws::new());
        public_only(&aws);
        let publisher = public_images::PUBLISHER_ACCOUNT_ID;
        aws.add_public_image(
            "ami-beta2",
            publisher,
            "ozbox-0.2.0-beta.2-20261116000000",
            "2026-11-16T00:00:00.000Z",
        );
        aws.add_public_image(
            "ami-beta1",
            publisher,
            "ozbox-0.2.0-beta.1-20261110000000",
            "2026-11-10T00:00:00.000Z",
        );
        // beta.2's release was never published (no manifest: a 404); beta.1's is, and lists its image
        aws.publish_release_with(
            "0.2.0-beta.1",
            "0.2.0-beta.1",
            "us-east-1",
            &["ami-beta1"],
            Some(true),
        );
        let got = provider_program(&aws, "0.2.0-beta.2").latest_image(None)?;
        assert_eq!(got.id, "ami-beta1");
        assert!(got.signature_verified);
        assert_eq!(got.skipped.len(), 1, "{:?}", got.skipped);
        assert!(
            got.skipped[0].contains("ami-beta2") && got.skipped[0].contains("0.2.0-beta.2"),
            "{:?}",
            got.skipped
        );
        Ok(())
    }

    #[test]
    fn latest_picks_the_newest_when_it_verifies_and_skips_nothing() -> TestResult {
        let aws = Arc::new(FakeAws::new());
        public_only(&aws);
        let publisher = public_images::PUBLISHER_ACCOUNT_ID;
        aws.add_public_image(
            "ami-beta2",
            publisher,
            "ozbox-0.2.0-beta.2-20261116000000",
            "2026-11-16T00:00:00.000Z",
        );
        aws.add_public_image(
            "ami-beta1",
            publisher,
            "ozbox-0.2.0-beta.1-20261110000000",
            "2026-11-10T00:00:00.000Z",
        );
        aws.publish_release_with(
            "0.2.0-beta.2",
            "0.2.0-beta.2",
            "us-east-1",
            &["ami-beta2"],
            Some(true),
        );
        aws.publish_release_with(
            "0.2.0-beta.1",
            "0.2.0-beta.1",
            "us-east-1",
            &["ami-beta1"],
            Some(true),
        );
        let got = provider_program(&aws, "0.2.0-beta.2").latest_image(None)?;
        assert_eq!(got.id, "ami-beta2");
        assert!(got.skipped.is_empty());
        Ok(())
    }

    #[test]
    fn latest_passes_over_a_signed_release_that_does_not_list_the_image_for_this_region(
    ) -> TestResult {
        let aws = Arc::new(FakeAws::new());
        public_only(&aws);
        let publisher = public_images::PUBLISHER_ACCOUNT_ID;
        aws.add_public_image(
            "ami-new",
            publisher,
            "ozbox-0.2.0-beta.2-20261116000000",
            "2026-11-16T00:00:00.000Z",
        );
        aws.add_public_image(
            "ami-old",
            publisher,
            "ozbox-0.2.0-beta.1-20261110000000",
            "2026-11-10T00:00:00.000Z",
        );
        aws.publish_release_with(
            "0.2.0-beta.2",
            "0.2.0-beta.2",
            "us-east-1",
            &["ami-other"],
            Some(true),
        );
        aws.publish_release_with(
            "0.2.0-beta.1",
            "0.2.0-beta.1",
            "us-east-1",
            &["ami-old"],
            Some(true),
        );
        let got = provider_program(&aws, "0.2.0-beta.2").latest_image(None)?;
        assert_eq!(got.id, "ami-old");
        assert!(
            got.skipped[0].contains("ami-new")
                && got.skipped[0].contains("not in the signed manifest")
        );
        Ok(())
    }

    #[test]
    fn latest_in_the_callers_own_account_walks_back_to_the_newest_signed_release() -> TestResult {
        let aws = Arc::new(FakeAws::new());
        aws.remove_images();
        aws.add_image(
            "ami-0new",
            "x86_64",
            "available",
            "2026-11-16T00:00:00.000Z",
            Some("0.2.0-beta.2"),
        );
        aws.add_image(
            "ami-0old",
            "x86_64",
            "available",
            "2026-11-10T00:00:00.000Z",
            Some("0.2.0-beta.1"),
        );
        aws.publish_release_with(
            "0.2.0-beta.1",
            "0.2.0-beta.1",
            "us-east-1",
            &["ami-0old"],
            Some(true),
        );
        let got = provider_program(&aws, "0.2.0-beta.2").latest_image(None)?;
        assert_eq!(got.id, "ami-0old");
        assert!(got.signature_verified);
        assert!(
            got.skipped.len() == 1 && got.skipped[0].contains("ami-0new"),
            "{:?}",
            got.skipped
        );
        Ok(())
    }

    #[test]
    fn latest_with_no_verifiable_release_returns_the_newest_unverified_with_every_reason(
    ) -> TestResult {
        let aws = Arc::new(FakeAws::new());
        aws.remove_images();
        aws.add_image(
            "ami-0new",
            "x86_64",
            "available",
            "2026-11-16T00:00:00.000Z",
            Some("0.2.0-beta.2"),
        );
        aws.add_image(
            "ami-0old",
            "x86_64",
            "available",
            "2026-11-10T00:00:00.000Z",
            Some("0.2.0-beta.1"),
        );
        let got = provider_program(&aws, "0.2.0-beta.2").latest_image(None)?;
        assert_eq!(got.id, "ami-0new");
        assert!(!got.signature_verified);
        // the newest is the one returned (unverified); the other candidate is the one named as passed over
        assert!(
            got.skipped.len() == 1 && got.skipped[0].contains("ami-0old"),
            "{:?}",
            got.skipped
        );
        Ok(())
    }

    #[test]
    fn an_image_named_explicitly_is_inspected_as_before_and_never_walked_back() -> TestResult {
        let aws = Arc::new(FakeAws::new());
        aws.remove_images();
        aws.add_image(
            "ami-0new",
            "x86_64",
            "available",
            "2026-11-16T00:00:00.000Z",
            Some("0.2.0-beta.2"),
        );
        aws.add_image(
            "ami-0old",
            "x86_64",
            "available",
            "2026-11-10T00:00:00.000Z",
            Some("0.2.0-beta.1"),
        );
        aws.publish_release_with(
            "0.2.0-beta.1",
            "0.2.0-beta.1",
            "us-east-1",
            &["ami-0old"],
            Some(true),
        );
        let got = provider_program(&aws, "0.2.0-beta.2").image_info("ami-0new", None)?;
        assert_eq!(got.id, "ami-0new");
        assert!(!got.signature_verified && got.skipped.is_empty(), "{got:?}");
        Ok(())
    }

    #[test]
    fn latest_in_the_public_path_with_no_verifiable_release_refuses_naming_the_ways_forward(
    ) -> TestResult {
        let aws = Arc::new(FakeAws::new());
        public_only(&aws);
        let publisher = public_images::PUBLISHER_ACCOUNT_ID;
        aws.add_public_image(
            "ami-beta2",
            publisher,
            "ozbox-0.2.0-beta.2-20261116000000",
            "2026-11-16T00:00:00.000Z",
        );
        aws.add_public_image(
            "ami-beta1",
            publisher,
            "ozbox-0.2.0-beta.1-20261110000000",
            "2026-11-10T00:00:00.000Z",
        );
        let err = provider_program(&aws, "0.2.0-beta.2")
            .latest_image(None)
            .err()
            .ok_or("must refuse")?
            .to_string();
        assert!(
            err.contains("ami-beta2") && err.contains("ami-beta1"),
            "{err}"
        );
        assert!(
            err.contains("--image") && err.contains("--allow-unverified-image"),
            "{err}"
        );
        Ok(())
    }

    #[test]
    fn a_stable_program_skips_a_pre_release_by_the_signed_field_and_a_beta_program_is_moved_to_the_stable_image(
    ) -> TestResult {
        let aws = Arc::new(FakeAws::new());
        public_only(&aws);
        // the NAME says stable, the SIGNED manifest says pre-release: the signed field decides
        aws.add_public_image(
            "ami-new",
            public_images::PUBLISHER_ACCOUNT_ID,
            "ozbox-0.2.0-20261201000000",
            "2026-12-01T00:00:00.000Z",
        );
        aws.add_public_image(
            "ami-old",
            public_images::PUBLISHER_ACCOUNT_ID,
            "ozbox-0.1.0-20261101000000",
            "2026-11-01T00:00:00.000Z",
        );
        aws.publish_release_with("0.2.0", "0.2.0", "us-east-1", &["ami-new"], Some(true));
        aws.publish_release_with("0.1.0", "0.1.0", "us-east-1", &["ami-old"], Some(false));
        // a stable 0.2 program refuses the 0.2 pre-release (the signed manifest says so) and uses nothing else
        let aws2 = Arc::new(FakeAws::new());
        public_only(&aws2);
        aws2.add_public_image(
            "ami-new",
            public_images::PUBLISHER_ACCOUNT_ID,
            "ozbox-0.2.0-20261201000000",
            "2026-12-01T00:00:00.000Z",
        );
        aws2.publish_release_with("0.2.0", "0.2.0", "us-east-1", &["ami-new"], Some(true));
        let got = provider_program(&aws2, "0.2.0").latest_image(None);
        assert!(got.is_err(), "{got:?}");
        assert!(got
            .err()
            .map(|e| e.to_string())
            .unwrap_or_default()
            .contains("pre-release"));
        // a pre-release program may take it
        let got = provider_program(&aws, "0.2.0-beta.1").latest_image(None)?;
        assert_eq!(got.id, "ami-new");
        // and once the stable 0.2.0 ships, the beta program is moved to it (same minor, newer)
        let aws = Arc::new(FakeAws::new());
        public_only(&aws);
        aws.add_public_image(
            "ami-beta",
            public_images::PUBLISHER_ACCOUNT_ID,
            "ozbox-0.2.0-beta.0-20261110000000",
            "2026-11-10T00:00:00.000Z",
        );
        aws.add_public_image(
            "ami-020",
            public_images::PUBLISHER_ACCOUNT_ID,
            "ozbox-0.2.0-20261201000000",
            "2026-12-01T00:00:00.000Z",
        );
        aws.publish_release_with(
            "0.2.0-beta.0",
            "0.2.0-beta.0",
            "us-east-1",
            &["ami-beta"],
            Some(true),
        );
        aws.publish_release_with("0.2.0", "0.2.0", "us-east-1", &["ami-020"], Some(false));
        let got = provider_program(&aws, "0.2.0-beta.0").latest_image(None)?;
        assert_eq!(got.id, "ami-020");
        Ok(())
    }

    #[test]
    fn a_stable_program_is_never_handed_a_verified_pre_release_from_its_own_account() -> TestResult
    {
        let aws = Arc::new(FakeAws::new());
        aws.remove_images();
        aws.add_image(
            "ami-0beta",
            "x86_64",
            "available",
            "2026-12-01T00:00:00.000Z",
            Some("0.2.0-beta.0"),
        );
        aws.publish_release_with(
            "0.2.0-beta.0",
            "0.2.0-beta.0",
            "us-east-1",
            &["ami-0beta"],
            Some(true),
        );
        let got = provider_program(&aws, "0.2.0").latest_image(None)?;
        assert!(!got.signature_verified, "{got:?}");
        assert!(got
            .signature_detail
            .is_some_and(|d| d.contains("pre-release")));
        // a pre-release program takes it as verified
        let got = provider_program(&aws, "0.2.0-beta.1").latest_image(None)?;
        assert!(got.signature_verified);
        Ok(())
    }

    #[test]
    fn a_public_lookup_that_runs_out_of_time_gives_up_and_creates_nothing() -> TestResult {
        let aws = Arc::new(FakeAws::new());
        public_only(&aws);
        aws.add_public_image(
            "ami-0pub",
            public_images::PUBLISHER_ACCOUNT_ID,
            &release_name("20261201000000"),
            "2026-12-01T00:00:00.000Z",
        );
        aws.publish_release_of(V, "us-east-1", &["ami-0pub"]);
        let cfg = AwsConfig {
            region: Some("us-east-1".into()),
            public_lookup_deadline: Some(std::time::Duration::ZERO),
            ..AwsConfig::default()
        };
        let p = Engine::new(AwsBackend::with_env_none(aws.clone(), cfg));
        let err = p
            .latest_image(None)
            .err()
            .ok_or("must give up")?
            .to_string();
        assert!(err.contains("took longer than 0 seconds"), "{err}");
        Ok(())
    }

    #[test]
    fn a_publisher_setting_that_is_not_an_account_trusts_nobody() -> TestResult {
        let aws = Arc::new(FakeAws::new());
        public_only(&aws);
        for bad in ["arn:aws:iam::1", "37211581245", "abc"] {
            let err = provider_publisher(&aws, Some(bad))
                .latest_image(None)
                .err()
                .ok_or("must refuse")?
                .to_string();
            assert!(err.contains("turned off"), "{bad}: {err}");
        }
        Ok(())
    }

    #[test]
    fn a_retired_image_is_refused_up_front_for_a_clone_and_a_rebuild_with_the_way_forward(
    ) -> TestResult {
        let aws = Arc::new(FakeAws::new());
        let p = provider(&aws);
        let b = running(&aws, &p, "main", Size::S)?;
        aws.remove_images();
        let e = p
            .check_reprovision(&b)
            .err()
            .ok_or("a rebuild from a retired image is refused")?
            .to_string();
        assert!(
            e.contains("ozbox upgrade main") && e.contains("no longer exists"),
            "{e}"
        );
        let e = p
            .plan(&Operation::Clone {
                from: b.spec.name.clone(),
                to: BoxName::new("copy")?,
                snapshot: None,
            })
            .err()
            .ok_or("a clone of a box on a retired image is refused")?
            .to_string();
        assert!(
            e.contains("no longer exists") && e.contains("ozbox upgrade"),
            "{e}"
        );
        Ok(())
    }

    #[test]
    fn a_public_image_named_by_id_is_known_by_its_name_and_needs_no_tag_note() -> TestResult {
        let aws = Arc::new(FakeAws::new());
        public_only(&aws);
        aws.add_public_image(
            "ami-0pub",
            public_images::PUBLISHER_ACCOUNT_ID,
            &release_name("20261201000000"),
            "2026-12-01T00:00:00.000Z",
        );
        aws.publish_release_of(V, "us-east-1", &["ami-0pub"]);
        let info = provider_publisher(&aws, None).image_info("ami-0pub", None)?;
        assert!(info.signature_verified && info.release.as_deref() == Some(V));
        // the same name from another account's image is not believed
        aws.add_public_image(
            "ami-0fake",
            "999999999999",
            &release_name("20261201000001"),
            "2026-12-01T00:00:01.000Z",
        );
        aws.publish_release_of(V, "us-east-1", &["ami-0fake"]);
        let info = provider_publisher(&aws, None).image_info("ami-0fake", None)?;
        assert!(!info.signature_verified && info.release.is_none());
        Ok(())
    }

    #[test]
    fn instance_types_are_matched_to_the_image_architecture() {
        for t in [
            "m7i.xlarge",
            "r7i.2xlarge",
            "g6.2xlarge",
            "g4dn.xlarge",
            "m7i.8xlarge",
        ] {
            assert_eq!(arch_of_instance_type(t), "x86_64", "{t}");
        }
        for t in ["m7g.large", "c7gd.xlarge", "g5g.xlarge", "t4g.micro"] {
            assert_eq!(arch_of_instance_type(t), "arm64", "{t}");
        }
    }

    #[test]
    fn exact_argv_for_stop_resize_grow_start() -> TestResult {
        let aws = Arc::new(FakeAws::new());
        let p = provider(&aws);
        let n = BoxName::new("dev")?;
        p.apply(&p.plan(&Operation::Create {
            spec: BoxSpec::new(n.clone(), Size::S),
        })?)?;
        aws.clear_calls();
        let plan = p.plan(&Operation::Resize {
            name: n.clone(),
            size: Some(Size::M),
            work_disk_gb: Some(300),
        })?;
        p.apply(&plan)?;
        let calls: Vec<Vec<String>> = aws
            .calls()
            .into_iter()
            .filter(|c| {
                c.program == "aws"
                    && c.args.get(1).is_some_and(|s| {
                        s.starts_with("stop")
                            || s.starts_with("start")
                            || s.starts_with("modify")
                            || s == "wait"
                    })
            })
            .map(|c| c.args)
            .collect();
        let id = p.get(&n)?.and_then(|r| r.provider_id).ok_or("no id")?;
        let region = ["--region", "us-east-1"];
        let mk = |a: &[&str], json: bool| -> Vec<String> {
            let mut v: Vec<String> = a.iter().map(|s| s.to_string()).collect();
            if json {
                v.extend(["--output".into(), "json".into()]);
            }
            v.extend(region.iter().map(|s| s.to_string()));
            v
        };
        let vol = aws.work_volume_of(&id).ok_or("no work volume")?;
        assert_eq!(
            calls,
            vec![
                mk(&["ec2", "stop-instances", "--instance-ids", &id], true),
                mk(
                    &["ec2", "wait", "instance-stopped", "--instance-ids", &id],
                    false
                ),
                mk(
                    &[
                        "ec2",
                        "modify-instance-attribute",
                        "--instance-id",
                        &id,
                        "--instance-type",
                        "Value=m7i.2xlarge"
                    ],
                    true
                ),
                mk(
                    &["ec2", "modify-volume", "--volume-id", &vol, "--size", "300"],
                    true
                ),
                mk(&["ec2", "start-instances", "--instance-ids", &id], true),
                mk(
                    &["ec2", "wait", "instance-running", "--instance-ids", &id],
                    false
                ),
            ]
        );
        Ok(())
    }

    #[test]
    fn snapshot_tags_the_snapshot_and_waits_for_it() -> TestResult {
        let aws = Arc::new(FakeAws::new());
        let p = provider(&aws);
        let n = BoxName::new("snap")?;
        p.apply(&p.plan(&Operation::Create {
            spec: BoxSpec::new(n.clone(), Size::S),
        })?)?;
        aws.clear_calls();
        let rec = p
            .apply(&p.plan(&Operation::Snapshot { name: n.clone() })?)?
            .ok_or("no record")?;
        assert_eq!(rec.snapshots.len(), 1);
        let calls = aws.calls();
        let create = calls
            .iter()
            .find(|c| c.args.get(1).map(String::as_str) == Some("create-snapshot"))
            .ok_or("no create-snapshot")?;
        assert!(create.args.contains(
            &"ResourceType=snapshot,Tags=[{Key=ozbox-managed,Value=true},{Key=ozbox-box,Value=snap}]".to_string()
        ));
        assert!(calls
            .iter()
            .any(|c| c.args.get(2).map(String::as_str) == Some("snapshot-completed")));
        Ok(())
    }

    fn two_snaps(aws: &Arc<FakeAws>, p: &Engine<AwsBackend>, name: &str) -> TestResult {
        let n = BoxName::new(name)?;
        p.apply(&p.plan(&Operation::Create {
            spec: BoxSpec::new(n.clone(), Size::S),
        })?)?;
        for _ in 0..2 {
            p.apply(&p.plan(&Operation::Snapshot { name: n.clone() })?)?;
        }
        aws.clear_calls();
        Ok(())
    }

    #[test]
    fn snapshots_are_listed_with_time_size_state_and_labels_of_this_box_only() -> TestResult {
        let aws = Arc::new(FakeAws::new());
        let p = provider(&aws);
        two_snaps(&aws, &p, "one")?;
        two_snaps(&aws, &p, "two")?;
        aws.add_foreign_snapshot("snap-foreign");
        let list = p.snapshots(&BoxName::new("one")?)?;
        assert_eq!(list.len(), 2, "{list:?}");
        assert!(list.iter().all(|s| s.kind == SnapshotKind::Provider
            && s.status == "completed"
            && s.includes_work
            && s.created_at.is_some()
            && s.size_bytes.is_some()));
        assert!(list
            .iter()
            .all(|s| s.labels.get("ozbox-box").map(String::as_str) == Some("one")));
        assert!(!list.iter().any(|s| s.id == "snap-foreign"));
        // listing only reads
        assert!(aws.calls().iter().all(|c| !c
            .args
            .iter()
            .any(|a| a.starts_with("create-") || a.starts_with("delete-"))));
        Ok(())
    }

    #[test]
    fn a_snapshot_is_deleted_by_id_and_only_one_oz_box_made_for_that_box() -> TestResult {
        let aws = Arc::new(FakeAws::new());
        let p = provider(&aws);
        two_snaps(&aws, &p, "one")?;
        two_snaps(&aws, &p, "two")?;
        aws.add_foreign_snapshot("snap-foreign");
        let one = BoxName::new("one")?;
        let mine = p.snapshots(&one)?[0].id.clone();
        let theirs = p.snapshots(&BoxName::new("two")?)?[0].id.clone();
        // another box's snapshot and one nobody tagged are refused while planning; nothing is called
        for id in [theirs.as_str(), "snap-foreign"] {
            let plan = p.plan(&Operation::DeleteSnapshot {
                name: one.clone(),
                snapshot: id.to_string(),
            })?;
            assert!(plan.is_noop(), "{id} is not a snapshot of one");
        }
        let plan = p.plan(&Operation::DeleteSnapshot {
            name: one.clone(),
            snapshot: mine.clone(),
        })?;
        assert_eq!(plan.max_risk(), Some(ozbox_core::Risk::High));
        aws.clear_calls();
        p.apply(&plan)?;
        let calls = aws.calls();
        let del = calls
            .iter()
            .find(|c| c.args.get(1).map(String::as_str) == Some("delete-snapshot"))
            .ok_or("no delete-snapshot")?;
        assert!(del.args.windows(2).any(|w| w == ["--snapshot-id", &mine]));
        assert_eq!(p.snapshots(&one)?.len(), 1);
        assert_eq!(
            p.snapshots(&BoxName::new("two")?)?.len(),
            2,
            "the other box is untouched"
        );
        Ok(())
    }

    #[test]
    fn a_snapshot_that_is_not_finished_cannot_be_restored_or_cloned() -> TestResult {
        let aws = Arc::new(FakeAws::new());
        let p = provider(&aws);
        two_snaps(&aws, &p, "one")?;
        let one = BoxName::new("one")?;
        let id = p.snapshots(&one)?[0].id.clone();
        aws.set_snapshot_state(&id, "pending");
        let clone = p.plan(&Operation::Clone {
            from: one.clone(),
            to: BoxName::new("copy")?,
            snapshot: Some(id.clone()),
        });
        assert!(matches!(clone, Err(Error::Config(m)) if m.contains("pending")));
        let listed = p.snapshots(&one)?;
        assert_eq!(listed[0].status, "pending");
        // the other one is fine, and the clone names it
        let ok = p.snapshots(&one)?[1].id.clone();
        let plan = p.plan(&Operation::Clone {
            from: one,
            to: BoxName::new("copy")?,
            snapshot: Some(ok.clone()),
        })?;
        assert!(plan.changes.iter().any(|c| c.description.contains(&ok)));
        p.apply(&plan)?;
        let tofu_apply: Vec<_> = aws
            .calls()
            .into_iter()
            .filter(|c| c.program == "tofu" && c.args.iter().any(|x| x == "apply"))
            .collect();
        assert!(tofu_apply
            .last()
            .ok_or("no apply")?
            .args
            .contains(&format!("work_snapshot_id={ok}")));
        Ok(())
    }

    fn restore_op(name: &BoxName, snapshot: &str) -> Operation {
        Operation::RestoreWork {
            name: name.clone(),
            snapshot: snapshot.to_string(),
        }
    }

    fn work_volumes(aws: &FakeAws, name: &BoxName) -> (Vec<String>, Vec<String>) {
        let all = aws.volumes_of(name);
        let pick = |role: &str| {
            all.iter()
                .filter(|(_, r, _)| r == role)
                .map(|(id, _, _)| id.clone())
                .collect::<Vec<_>>()
        };
        (pick("work"), pick("work-retired"))
    }

    fn tofu_calls(aws: &FakeAws) -> Vec<Vec<String>> {
        aws.calls()
            .into_iter()
            .filter(|c| c.program == "tofu")
            .map(|c| c.args)
            .collect()
    }

    #[test]
    fn a_restore_swaps_only_the_work_disk_and_keeps_the_old_one() -> TestResult {
        let aws = Arc::new(FakeAws::new());
        let p = provider(&aws);
        two_snaps(&aws, &p, "one")?;
        let one = BoxName::new("one")?;
        let machine = p.get(&one)?.ok_or("no box")?.provider_id;
        let (before, _) = work_volumes(&aws, &one);
        let snap = p.snapshots(&one)?[0].id.clone();

        let plan = p.plan(&restore_op(&one, &snap))?;
        assert_eq!(plan.max_risk(), Some(ozbox_core::Risk::High));
        let kinds: Vec<_> = plan.changes.iter().map(|c| c.kind.as_str()).collect();
        assert_eq!(
            kinds,
            [
                "snapshot.create",
                "instance.stop",
                "volume.replace",
                "instance.start"
            ]
        );
        let notes = plan.notes.join(" ");
        assert!(
            notes.contains("kept") && notes.contains("not deleted") && notes.contains("same zone"),
            "{notes}"
        );
        // Planning changed nothing: no detach, no state surgery, no tag written.
        assert!(aws.calls().iter().all(|c| !c.args.iter().any(|a| {
            ["detach-volume", "create-tags", "stop-instances", "rm"].contains(&a.as_str())
        })));

        aws.clear_calls();
        let done = p.apply(&plan)?.ok_or("no record")?;
        assert_eq!(done.state, BoxState::Running);
        assert_eq!(
            done.provider_id, machine,
            "the machine is the same one: only the /work disk was swapped"
        );
        let (now, retired) = work_volumes(&aws, &one);
        assert_eq!(now.len(), 1, "exactly one disk is /work");
        assert_ne!(now, before, "it is a new disk");
        assert_eq!(retired, before, "the old disk is kept, retagged");
        let all = aws.volumes_of(&one);
        assert!(all
            .iter()
            .any(|(id, _, snap_of)| id == &now[0] && snap_of.as_deref() == Some(snap.as_str())));

        // The order: the way back first, then stop, retire, detach, state surgery, a guarded plan, the apply.
        let calls: Vec<String> = aws
            .calls()
            .iter()
            .map(|c| {
                c.args
                    .iter()
                    .find(|a| {
                        [
                            "create-snapshot",
                            "stop-instances",
                            "create-tags",
                            "detach-volume",
                            "rm",
                            "plan",
                            "apply",
                            "start-instances",
                            "delete-volume",
                        ]
                        .contains(&a.as_str())
                            || a.starts_with("-replace")
                    })
                    .cloned()
                    .unwrap_or_default()
            })
            .collect();
        let at = |what: &str| calls.iter().position(|c| c == what);
        let order = [
            "create-snapshot",
            "stop-instances",
            "create-tags",
            "detach-volume",
            "rm",
            "apply",
            "start-instances",
        ];
        let positions: Vec<usize> = order
            .iter()
            .map(|w| at(w).unwrap_or_else(|| panic!("{w} never ran: {calls:?}")))
            .collect();
        assert!(positions.windows(2).all(|w| w[0] < w[1]), "{calls:?}");
        assert!(
            !calls.iter().any(|c| c == "delete-volume"),
            "no disk is deleted by a restore"
        );
        let rm = tofu_calls(&aws)
            .into_iter()
            .find(|a| a.iter().any(|x| x == "rm"))
            .ok_or("no state rm")?;
        assert!(
            rm.iter().any(|x| x == "aws_ebs_volume.work")
                && rm.iter().any(|x| x == "aws_volume_attachment.work")
        );
        // The apply carries the snapshot and never a replace of the machine.
        assert!(tofu_calls(&aws)
            .iter()
            .all(|a| !a.iter().any(|x| x == "-replace=aws_instance.box")));
        let planned = tofu_calls(&aws)
            .into_iter()
            .rfind(|a| a.iter().any(|x| x == "plan"))
            .ok_or("no plan")?;
        assert!(planned
            .iter()
            .any(|x| x == &format!("work_snapshot_id={snap}")));

        // The old disk is listed, kept, and a repeat of the restore is a new restore (it is not mistaken for the
        // finished one).
        let old = p.old_work_disks(&one)?;
        assert_eq!(old.len(), 1);
        assert_eq!(old[0].id, before[0]);
        assert_eq!(old[0].state, "kept");
        assert_eq!(old[0].restored_from.as_deref(), Some(snap.as_str()));
        Ok(())
    }

    #[test]
    fn a_restore_that_would_replace_the_machine_is_refused_before_anything_changes() -> TestResult {
        let aws = Arc::new(FakeAws::new());
        let p = provider(&aws);
        two_snaps(&aws, &p, "one")?;
        let one = BoxName::new("one")?;
        let (before, _) = work_volumes(&aws, &one);
        let snap = p.snapshots(&one)?[0].id.clone();
        aws.plan_replaces_instance();
        match p.plan(&restore_op(&one, &snap)) {
            Err(Error::Provider(m)) => assert!(m.contains("aws_instance.box"), "{m}"),
            other => panic!("expected a refusal, got {other:?}"),
        }
        assert!(aws.calls().iter().all(|c| !c.args.iter().any(|a| {
            [
                "detach-volume",
                "create-tags",
                "stop-instances",
                "rm",
                "apply",
            ]
            .contains(&a.as_str())
        })));
        let (now, retired) = work_volumes(&aws, &one);
        assert_eq!((now, retired.len()), (before, 0));
        Ok(())
    }

    #[test]
    fn a_guard_refusal_after_the_state_was_changed_puts_everything_back() -> TestResult {
        let aws = Arc::new(FakeAws::new());
        let p = provider(&aws);
        two_snaps(&aws, &p, "one")?;
        let one = BoxName::new("one")?;
        let (before, _) = work_volumes(&aws, &one);
        let snap = p.snapshots(&one)?[0].id.clone();
        let plan = p.plan(&restore_op(&one, &snap))?;
        // The preview was fine; the plan made after the old disk left the state is not.
        aws.plan_replaces_instance_after_rm();
        match p.apply(&plan) {
            Err(Error::Provider(m)) => {
                assert!(
                    m.contains("aws_instance.box") && m.contains("nothing was changed"),
                    "{m}"
                )
            }
            other => panic!("expected a refusal, got {other:?}"),
        }
        let (now, retired) = work_volumes(&aws, &one);
        assert_eq!(now, before, "the old disk is the /work disk again");
        assert!(retired.is_empty());
        assert!(
            aws.work_volume_of_box(&one).is_ok_and(|v| v == before[0]),
            "and it is attached again"
        );
        assert!(
            tofu_calls(&aws)
                .iter()
                .filter(|a| a.iter().any(|x| x == "import"))
                .count()
                == 2,
            "both resources were imported back into the state"
        );
        assert!(p.old_work_disks(&one)?.is_empty());
        Ok(())
    }

    #[test]
    fn an_interrupted_restore_is_finished_by_running_it_again() -> TestResult {
        let aws = Arc::new(FakeAws::new());
        let p = provider(&aws);
        two_snaps(&aws, &p, "one")?;
        let one = BoxName::new("one")?;
        let (before, _) = work_volumes(&aws, &one);
        let snap = p.snapshots(&one)?[0].id.clone();
        let plan = p.plan(&restore_op(&one, &snap))?;
        aws.fail_next_replace_apply();
        match p.apply(&plan) {
            Err(Error::Provider(m)) => assert!(m.contains("same restore again"), "{m}"),
            other => panic!("expected the interruption, got {other:?}"),
        }
        // The old disk is set aside and marked as part of an unfinished restore: it is not deletable yet, and it is
        // still found as this box's /work (so the way back can be taken again).
        let old = p.old_work_disks(&one)?;
        assert_eq!(old.len(), 1);
        assert_eq!(old[0].state, "pending");
        let del = Operation::DeleteOldWork {
            name: one.clone(),
            volume: before[0].clone(),
        };
        assert!(
            p.plan(&del).is_err(),
            "an unfinished restore's disk is not deletable"
        );
        // Another snapshot's restore is refused until this one is finished.
        let other = p.snapshots(&one)?[1].id.clone();
        match p.plan(&restore_op(&one, &other)) {
            Err(Error::Config(m)) => assert!(m.contains("interrupted"), "{m}"),
            other => panic!("expected a refusal, got {other:?}"),
        }
        // The same restore again finishes it.
        let again = p.plan(&restore_op(&one, &snap))?;
        assert!(again.notes.join(" ").contains("interrupted"));
        p.apply(&again)?;
        let (now, retired) = work_volumes(&aws, &one);
        assert_eq!(now.len(), 1);
        assert_ne!(now, before);
        assert_eq!(retired, before);
        assert_eq!(p.old_work_disks(&one)?[0].state, "kept");
        Ok(())
    }

    #[test]
    fn an_old_work_disk_is_deleted_only_by_its_own_confirmed_action() -> TestResult {
        let aws = Arc::new(FakeAws::new());
        let p = provider(&aws);
        two_snaps(&aws, &p, "one")?;
        let one = BoxName::new("one")?;
        let (before, _) = work_volumes(&aws, &one);
        let snap = p.snapshots(&one)?[0].id.clone();
        p.apply(&p.plan(&restore_op(&one, &snap))?)?;
        let (current, _) = work_volumes(&aws, &one);
        aws.clear_calls();
        // The disk the box is using is never an "old disk".
        let live = p.plan(&Operation::DeleteOldWork {
            name: one.clone(),
            volume: current[0].clone(),
        })?;
        assert!(live.is_noop());
        let del = Operation::DeleteOldWork {
            name: one.clone(),
            volume: before[0].clone(),
        };
        let plan = p.plan(&del)?;
        assert_eq!(plan.max_risk(), Some(ozbox_core::Risk::High));
        assert!(aws
            .calls()
            .iter()
            .all(|c| !c.args.iter().any(|a| a == "delete-volume")));
        p.apply(&plan)?;
        let ran: Vec<_> = aws
            .calls()
            .into_iter()
            .filter(|c| c.args.iter().any(|a| a == "delete-volume"))
            .collect();
        assert_eq!(ran.len(), 1);
        assert!(ran[0].args.iter().any(|a| a == &before[0]));
        let (now, retired) = work_volumes(&aws, &one);
        assert_eq!((now, retired.len()), (current, 0));
        assert!(p.plan(&del)?.is_noop(), "a repeat is nothing");
        Ok(())
    }

    #[test]
    fn create_and_clone_use_the_module_with_the_snapshot() -> TestResult {
        let aws = Arc::new(FakeAws::new());
        let p = provider(&aws);
        let a = BoxName::new("src")?;
        let b = BoxName::new("copy")?;
        p.apply(&p.plan(&Operation::Create {
            spec: BoxSpec::new(a.clone(), Size::Gpu(GpuKind::Small)),
        })?)?;
        let rec = p
            .apply(&p.plan(&Operation::Clone {
                from: a.clone(),
                to: b.clone(),
                snapshot: None,
            })?)?
            .ok_or("no record")?;
        assert_eq!(rec.machine_type.as_deref(), Some("g6.2xlarge"));
        let snap = p
            .get(&a)?
            .and_then(|r| r.snapshots.last().cloned())
            .ok_or("no snapshot")?;
        let tofu_apply: Vec<_> = aws
            .calls()
            .into_iter()
            .filter(|c| c.program == "tofu" && c.args.iter().any(|x| x == "apply"))
            .collect();
        assert_eq!(tofu_apply.len(), 2);
        assert!(tofu_apply[1]
            .args
            .contains(&format!("work_snapshot_id={snap}")));
        assert!(tofu_apply[1].args.contains(&"region=us-east-1".to_string()));
        assert!(tofu_apply[1]
            .args
            .contains(&"image_id=ami-0123456789abcdef0".to_string()));
        Ok(())
    }

    #[test]
    fn create_without_a_subnet_is_refused_while_planning_and_runs_nothing() -> TestResult {
        let runner = Arc::new(RecordingRunner::new());
        let cfg = AwsConfig {
            image: Some("ami-0123456789abcdef0".into()),
            ..AwsConfig::default()
        };
        let p = Engine::new(AwsBackend::with_env_none(runner.clone(), cfg));
        runner.reply(ozbox_core::Output {
            status: Some(0),
            stdout: r#"{"Reservations":[]}"#.into(),
            stderr: String::new(),
        });
        runner.reply(ozbox_core::Output {
            status: Some(0),
            stdout: r#"{"Volumes":[]}"#.into(),
            stderr: String::new(),
        });
        let res = p.plan(&Operation::Create {
            spec: BoxSpec::new(BoxName::new("x")?, Size::S),
        });
        assert!(matches!(res, Err(Error::Config(m)) if m.contains("subnet")));
        assert!(
            runner.calls().iter().all(|c| c.program == "aws"),
            "only the read-only listing ran"
        );
        Ok(())
    }

    #[test]
    fn the_module_gets_subnet_kms_and_root_disk() -> TestResult {
        let aws = Arc::new(FakeAws::new());
        let cfg = AwsConfig {
            image: Some("ami-0123456789abcdef0".into()),
            subnet_id: Some("subnet-0123456789abcdef0".into()),
            kms_key_arn: Some("arn:aws:kms:us-east-1:123456789012:key/abc".into()),
            root_disk_gb: Some(80),
            region: Some("us-east-1".into()),
            ..AwsConfig::default()
        };
        let p = Engine::new(AwsBackend::with_env_none(aws.clone(), cfg));
        p.apply(&p.plan(&Operation::Create {
            spec: BoxSpec::new(BoxName::new("k")?, Size::S),
        })?)?;
        let apply = aws
            .calls()
            .into_iter()
            .find(|c| c.args.iter().any(|a| a == "apply"))
            .ok_or("no apply")?;
        for want in [
            "subnet_id=subnet-0123456789abcdef0",
            "kms_key_arn=arn:aws:kms:us-east-1:123456789012:key/abc",
            "root_disk_gb=80",
            // size S: two agent runs at once
            "runs_max_active=2",
        ] {
            assert!(apply.args.iter().any(|a| a == want), "missing {want}");
        }
        Ok(())
    }

    #[test]
    fn gpu_large_is_unsupported_at_plan_time() -> TestResult {
        let aws = Arc::new(FakeAws::new());
        let p = provider(&aws);
        let res = p.plan(&Operation::Create {
            spec: BoxSpec::new(BoxName::new("g")?, Size::Gpu(GpuKind::Large)),
        });
        assert!(matches!(res, Err(Error::Unsupported { .. })));
        Ok(())
    }

    #[test]
    fn listing_uses_the_tag_filter_and_ignores_unmanaged_instances() -> TestResult {
        let runner = Arc::new(RecordingRunner::new());
        runner.reply(ozbox_core::Output {
            status: Some(0),
            stdout: r#"{"Reservations":[]}"#.into(),
            stderr: String::new(),
        });
        // Even with no machine anywhere the volumes are read: a box whose machine is gone is found by its /work disk.
        runner.reply(ozbox_core::Output {
            status: Some(0),
            stdout: r#"{"Volumes":[]}"#.into(),
            stderr: String::new(),
        });
        let b = AwsBackend::with_env_none(runner.clone(), AwsConfig::default());
        assert!(b.list()?.is_empty());
        let calls = runner.calls();
        assert_eq!(calls.len(), 2);
        assert_eq!(calls[1].args[..2], ["ec2", "describe-volumes"]);
        assert_eq!(
            calls[0].args,
            [
                "ec2",
                "describe-instances",
                "--filters",
                "Name=tag:ozbox-managed,Values=true",
                "Name=instance-state-name,Values=pending,running,stopping,stopped,shutting-down",
                "--output",
                "json"
            ]
        );
        Ok(())
    }

    #[test]
    fn a_failing_cli_surfaces_its_message_as_a_command_error() -> TestResult {
        let runner = Arc::new(RecordingRunner::new());
        runner.reply(ozbox_core::Output {
            status: Some(255),
            stdout: String::new(),
            stderr: "An error occurred (UnauthorizedOperation)".into(),
        });
        let b = AwsBackend::with_env_none(runner, AwsConfig::default());
        let err = b.list().err().ok_or("expected an error")?;
        let text = format!("{err} {err:?}");
        assert!(text.contains("UnauthorizedOperation"));
        Ok(())
    }

    #[test]
    fn runtime_calls_go_to_the_boxs_own_region() -> TestResult {
        let aws = Arc::new(FakeAws::new());
        let p = Engine::new(AwsBackend::with_env_none(
            aws.clone(),
            AwsConfig {
                region: Some("us-east-1".into()),
                regions: vec!["us-east-1".into(), "eu-west-1".into()],
                image: Some("ami-0123456789abcdef0".into()),
                subnet_id: Some("subnet-0123456789abcdef0".into()),
                ..AwsConfig::default()
            },
        )); // default region us-east-1
        let n = BoxName::new("eu")?;
        let mut spec = BoxSpec::new(n.clone(), Size::S);
        spec.region = Some("eu-west-1".into());
        p.apply(&p.plan(&Operation::Create { spec })?)?;
        let rec = p.get(&n)?.ok_or("missing")?;
        assert_eq!(rec.spec.region.as_deref(), Some("eu-west-1"));
        aws.clear_calls();
        p.apply(&p.plan(&Operation::Pause { name: n.clone() })?)?;
        let runtime: Vec<_> = aws
            .calls()
            .into_iter()
            .filter(|c| {
                c.program == "aws"
                    && c.args
                        .get(1)
                        .is_some_and(|a| a.starts_with("stop") || a == "wait")
            })
            .collect();
        assert_eq!(runtime.len(), 2, "stop, wait");
        for c in runtime {
            assert!(
                c.args.windows(2).any(|w| w == ["--region", "eu-west-1"]),
                "{:?} did not use the box's region",
                c.args
            );
        }
        // The tofu module is also told the region.
        assert!(aws
            .calls()
            .iter()
            .all(|c| c.program != "tofu" || !c.args.iter().any(|a| a == "region=us-east-1")));
        Ok(())
    }

    #[test]
    fn growing_waits_for_the_modification_to_reach_optimizing() -> TestResult {
        let runner = Arc::new(RecordingRunner::new());
        let ok = |stdout: &str| ozbox_core::Output {
            status: Some(0),
            stdout: stdout.into(),
            stderr: String::new(),
        };
        let inst = r#"{"Reservations":[{"Instances":[{"InstanceId":"i-1","InstanceType":"m7i.xlarge","State":{"Name":"running"},"RootDeviceName":"/dev/xvda","BlockDeviceMappings":[{"DeviceName":"/dev/xvda","Ebs":{"VolumeId":"vol-root"}},{"DeviceName":"/dev/sdf","Ebs":{"VolumeId":"vol-work"}}]}]}]}"#;
        runner.reply(ok(inst));
        runner.reply(ok("{}")); // modify-volume
        runner.reply(ok(
            r#"{"VolumesModifications":[{"ModificationState":"modifying"}]}"#,
        ));
        runner.reply(ok(
            r#"{"VolumesModifications":[{"ModificationState":"modifying"}]}"#,
        ));
        runner.reply(ok(
            r#"{"VolumesModifications":[{"ModificationState":"optimizing"}]}"#,
        ));
        let cfg = AwsConfig {
            region: Some("us-east-1".into()),
            poll_interval: std::time::Duration::ZERO,
            ..AwsConfig::default()
        };
        let b = AwsBackend::with_env_none(runner.clone(), cfg);
        let mut spec = BoxSpec::new(BoxName::new("g")?, Size::S);
        spec.work_disk_gb = 100;
        let rec = BoxRecord {
            spec,
            state: BoxState::Running,
            provider: "aws".into(),
            provider_id: Some("i-1".into()),
            machine_type: Some("m7i.xlarge".into()),
            snapshots: vec![],
            created_at: None,
            last_activity_at: None,
        };
        b.grow_disk(&rec, 200)?;
        let calls = runner.calls();
        let subs: Vec<&str> = calls.iter().map(|c| c.args[1].as_str()).collect();
        assert_eq!(
            subs,
            [
                "describe-instances",
                "modify-volume",
                "describe-volumes-modifications",
                "describe-volumes-modifications",
                "describe-volumes-modifications"
            ]
        );
        assert!(calls[1].args.contains(&"vol-work".to_string()));
        Ok(())
    }

    #[test]
    fn a_volume_that_never_optimizes_or_fails_is_an_error() -> TestResult {
        for state in ["failed", "modifying"] {
            let runner = Arc::new(RecordingRunner::new());
            let ok = |stdout: String| ozbox_core::Output {
                status: Some(0),
                stdout,
                stderr: String::new(),
            };
            runner.reply(ok(r#"{"Reservations":[{"Instances":[{"InstanceId":"i-1","InstanceType":"m7i.xlarge","State":{"Name":"running"},"RootDeviceName":"/dev/xvda","BlockDeviceMappings":[{"DeviceName":"/dev/xvda","Ebs":{"VolumeId":"r"}},{"DeviceName":"/dev/sdf","Ebs":{"VolumeId":"w"}}]}]}]}"#.into()));
            runner.reply(ok("{}".into()));
            for _ in 0..3 {
                runner.reply(ok(format!(
                    r#"{{"VolumesModifications":[{{"ModificationState":"{state}"}}]}}"#
                )));
            }
            let cfg = AwsConfig {
                poll_interval: std::time::Duration::ZERO,
                volume_wait_polls: 3,
                ..AwsConfig::default()
            };
            let b = AwsBackend::with_env_none(runner, cfg);
            let rec = BoxRecord {
                spec: BoxSpec::new(BoxName::new("g")?, Size::S),
                state: BoxState::Running,
                provider: "aws".into(),
                provider_id: Some("i-1".into()),
                machine_type: None,
                snapshots: vec![],
                created_at: None,
                last_activity_at: None,
            };
            assert!(b.grow_disk(&rec, 200).is_err(), "{state}");
        }
        Ok(())
    }

    #[test]
    fn a_resize_marks_the_box_before_stopping_and_clears_it_after_starting() -> TestResult {
        let aws = Arc::new(FakeAws::new());
        let p = provider(&aws);
        let n = BoxName::new("mark")?;
        p.apply(&p.plan(&Operation::Create {
            spec: BoxSpec::new(n.clone(), Size::S),
        })?)?;
        aws.clear_calls();
        p.apply(&p.plan(&Operation::Resize {
            name: n.clone(),
            size: Some(Size::M),
            work_disk_gb: None,
        })?)?;
        let subs: Vec<String> = aws
            .calls()
            .into_iter()
            .filter(|c| c.program == "aws")
            .map(|c| c.args[1].clone())
            .filter(|s| {
                [
                    "create-tags",
                    "stop-instances",
                    "start-instances",
                    "delete-tags",
                ]
                .contains(&s.as_str())
            })
            .collect();
        assert_eq!(
            subs,
            [
                "create-tags",
                "stop-instances",
                "start-instances",
                "delete-tags"
            ]
        );
        assert!(!p
            .get(&n)?
            .ok_or("missing")?
            .spec
            .labels
            .contains_key(RESUME_AFTER_LABEL));
        Ok(())
    }

    fn module_variables() -> std::result::Result<Vec<(String, bool)>, Box<dyn std::error::Error>> {
        let path = concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../infra/tofu/modules/aws-box/variables.tf"
        );
        let text = std::fs::read_to_string(path)?;
        let mut out: Vec<(String, bool)> = Vec::new();
        for line in text.lines() {
            if let Some(rest) = line.strip_prefix("variable \"") {
                if let Some((name, _)) = rest.split_once('"') {
                    out.push((name.to_string(), false));
                }
            } else if line.starts_with("  default") {
                if let Some(last) = out.last_mut() {
                    last.1 = true;
                }
            }
        }
        Ok(out)
    }

    fn passed(vars: &ModuleVars) -> Vec<String> {
        TofuModule::var_args(vars)
            .iter()
            .filter(|a| *a != "-var")
            .filter_map(|a| a.split_once('=').map(|(k, _)| k.to_string()))
            .collect()
    }

    #[test]
    fn the_variables_passed_match_the_module() -> TestResult {
        let declared = module_variables()?;
        assert!(
            declared.len() >= 10,
            "parsed too few variables: {declared:?}"
        );
        let mk = |full: bool| {
            AwsBackend::with_env_none(
                Arc::new(FakeAws::new()),
                AwsConfig {
                    region: Some("us-east-1".into()),
                    image: Some("ami-0123456789abcdef0".into()),
                    subnet_id: Some("subnet-0123456789abcdef0".into()),
                    kms_key_arn: full
                        .then(|| "arn:aws:kms:us-east-1:123456789012:key/abc".to_string()),
                    root_disk_gb: full.then_some(80),
                    ..AwsConfig::default()
                },
            )
        };
        let mut spec = BoxSpec::new(BoxName::new("v")?, Size::S);
        spec.from_snapshot = Some("snap-1".into());
        let all = passed(&mk(true).vars(&spec, "m7i.xlarge"));
        let always =
            passed(&mk(false).vars(&BoxSpec::new(BoxName::new("v")?, Size::S), "m7i.xlarge"));
        for v in &all {
            assert!(
                declared.iter().any(|(d, _)| d == v),
                "adapter passes {v}, which the module does not declare"
            );
        }
        for (d, has_default) in &declared {
            assert!(
                *has_default || always.contains(d),
                "module variable {d} has no default and is not passed"
            );
        }
        Ok(())
    }

    #[test]
    fn create_without_a_region_is_refused_while_planning() -> TestResult {
        let aws = Arc::new(FakeAws::new());
        let cfg = AwsConfig {
            image: Some("ami-0123456789abcdef0".into()),
            subnet_id: Some("subnet-0123456789abcdef0".into()),
            ..AwsConfig::default()
        };
        let p = Engine::new(AwsBackend::with_env_none(aws, cfg));
        let res = p.plan(&Operation::Create {
            spec: BoxSpec::new(BoxName::new("x")?, Size::S),
        });
        assert!(matches!(res, Err(Error::Config(m)) if m.contains("--region")));
        Ok(())
    }

    #[test]
    fn create_outside_the_searched_regions_is_refused_while_planning() -> TestResult {
        let aws = Arc::new(FakeAws::new());
        let cfg = AwsConfig {
            region: Some("us-east-1".into()),
            image: Some("ami-0123456789abcdef0".into()),
            subnet_id: Some("subnet-0123456789abcdef0".into()),
            ..AwsConfig::default()
        };
        let p = Engine::new(AwsBackend::with_env_none(aws.clone(), cfg));
        let mut spec = BoxSpec::new(BoxName::new("x")?, Size::S);
        spec.region = Some("ap-south-1".into());
        let res = p.plan(&Operation::Create { spec });
        assert!(
            matches!(res, Err(Error::Config(m)) if m.contains("ap-south-1") && m.contains("regions"))
        );
        assert!(
            aws.calls().iter().all(|c| c.program != "tofu"),
            "nothing ran"
        );
        Ok(())
    }

    #[test]
    fn list_searches_every_configured_region_and_says_which() -> TestResult {
        let aws = Arc::new(FakeAws::new());
        let cfg = |regions: &[&str]| AwsConfig {
            region: Some("us-east-1".into()),
            regions: regions.iter().map(|r| r.to_string()).collect(),
            image: Some("ami-0123456789abcdef0".into()),
            subnet_id: Some("subnet-0123456789abcdef0".into()),
            ..AwsConfig::default()
        };
        let both = Engine::new(AwsBackend::with_env_none(
            aws.clone(),
            cfg(&["us-east-1", "eu-west-1"]),
        ));
        for (name, region) in [("us-box", "us-east-1"), ("eu-box", "eu-west-1")] {
            let mut spec = BoxSpec::new(BoxName::new(name)?, Size::S);
            spec.region = Some(region.into());
            both.apply(&both.plan(&Operation::Create { spec })?)?;
        }
        let names: Vec<String> = both
            .list()?
            .iter()
            .map(|r| r.spec.name.to_string())
            .collect();
        assert_eq!(names, ["eu-box", "us-box"]);
        assert_eq!(both.searched(), ["us-east-1", "eu-west-1"]);
        aws.clear_calls();
        both.list()?;
        let regions: Vec<String> = aws
            .calls()
            .iter()
            .filter(|c| c.args.get(1).map(String::as_str) == Some("describe-instances"))
            .filter_map(|c| {
                c.args
                    .windows(2)
                    .find(|w| w[0] == "--region")
                    .map(|w| w[1].clone())
            })
            .collect();
        assert_eq!(regions, ["us-east-1", "eu-west-1"]);
        // Default: just the one region.
        let one = Engine::new(AwsBackend::with_env_none(aws, cfg(&[])));
        assert_eq!(one.searched(), ["us-east-1"]);
        assert_eq!(one.list()?.len(), 1);
        Ok(())
    }

    #[test]
    fn pausing_a_box_with_a_pending_restart_clears_the_mark() -> TestResult {
        let aws = Arc::new(FakeAws::new());
        let p = provider(&aws);
        let n = BoxName::new("pend")?;
        p.apply(&p.plan(&Operation::Create {
            spec: BoxSpec::new(n.clone(), Size::S),
        })?)?;
        p.apply(&p.plan(&Operation::Pause { name: n.clone() })?)?;
        let rec = p.get(&n)?.ok_or("missing")?;
        p.backend().set_resume_after(&rec, true)?;
        let plan = p.plan(&Operation::Pause { name: n.clone() })?;
        let kinds: Vec<_> = plan.changes.iter().map(|c| c.kind.as_str()).collect();
        assert_eq!(kinds, ["instance.clear_restart"]);
        assert_eq!(plan.max_risk(), Some(ozbox_core::Risk::Low));
        let after = p.apply(&plan)?.ok_or("missing")?;
        assert_eq!(after.state, BoxState::Paused);
        assert!(!after.spec.labels.contains_key(RESUME_AFTER_LABEL));
        assert!(p.plan(&Operation::Pause { name: n })?.is_noop());
        Ok(())
    }
    #[test]
    fn a_resize_over_the_vcpu_quota_is_refused_while_planning_and_nothing_stops() -> TestResult {
        let aws = Arc::new(FakeAws::new());
        let p = provider(&aws);
        let n = BoxName::new("quota")?;
        p.apply(&p.plan(&Operation::Create {
            spec: BoxSpec::new(n.clone(), Size::S),
        })?)?;
        // another running S box: 8 of 8 vCPUs in use
        p.apply(&p.plan(&Operation::Create {
            spec: BoxSpec::new(BoxName::new("other")?, Size::S),
        })?)?;
        aws.set_vcpu_quota(8.0);
        aws.clear_calls();
        let err = p
            .plan(&Operation::Resize {
                name: n.clone(),
                size: Some(Size::M),
                work_disk_gb: None,
            })
            .err()
            .ok_or("must refuse")?
            .to_string();
        assert!(
            err.contains("L-1216C47A") && err.contains("8 are in use"),
            "{err}"
        );
        let stopped = aws.calls().iter().any(|c| {
            matches!(
                c.args.get(1).map(String::as_str),
                Some("stop-instances" | "modify-instance-attribute")
            )
        });
        assert!(!stopped, "nothing may stop before the refusal");
        assert_eq!(p.get(&n)?.ok_or("missing")?.state, BoxState::Running);
        // a disk-only resize and a pause never need capacity
        aws.clear_calls();
        p.plan(&Operation::Resize {
            name: n.clone(),
            size: None,
            work_disk_gb: Some(300),
        })?;
        p.plan(&Operation::Pause { name: n.clone() })?;
        assert!(aws
            .calls()
            .iter()
            .all(|c| c.args.first().map(String::as_str) != Some("service-quotas")));
        Ok(())
    }

    #[test]
    fn resume_and_create_also_check_the_quota_and_a_denied_read_only_adds_a_note() -> TestResult {
        let aws = Arc::new(FakeAws::new());
        let p = provider(&aws);
        let n = BoxName::new("res")?;
        p.apply(&p.plan(&Operation::Create {
            spec: BoxSpec::new(n.clone(), Size::S),
        })?)?;
        p.apply(&p.plan(&Operation::Pause { name: n.clone() })?)?;
        aws.set_vcpu_quota(2.0);
        let err = p
            .plan(&Operation::Resume { name: n.clone() })
            .err()
            .ok_or("must refuse")?;
        assert!(err.to_string().contains("2 vCPUs"), "{err}");
        let err = p
            .plan(&Operation::Create {
                spec: BoxSpec::new(BoxName::new("fresh")?, Size::S),
            })
            .err()
            .ok_or("must refuse")?;
        assert!(
            err.to_string().contains("request-service-quota-increase"),
            "{err}"
        );
        aws.deny_quota_reads();
        let plan = p.plan(&Operation::Resume { name: n })?;
        assert!(
            plan.notes
                .iter()
                .any(|x| x.contains("Could not check the vCPU quota")),
            "{:?}",
            plan.notes
        );
        Ok(())
    }

    fn upgrade_keeping_the_old_disk(name: &BoxName, keep: bool) -> Operation {
        Operation::Upgrade {
            name: name.clone(),
            image: NEW_IMAGE.into(),
            reprovision: false,
            keep_old_system_disk: keep,
        }
    }

    fn root_volume_id(aws: &FakeAws, name: &BoxName) -> Result<String> {
        aws.volumes_of(name)
            .into_iter()
            .find(|v| v.1 == "root")
            .map(|v| v.0)
            .ok_or_else(|| Error::NotFound("root volume".into()))
    }

    /// The incident: a box whose store's key was a file on the system disk lost it with the disk. When the plan asks for a copy
    /// of the old system disk it is the FIRST change, named by its volume; it is taken before the mark, the stop and the replace,
    /// tagged so it is never taken for a backup of /work, and it is never the default clone source.
    #[test]
    fn an_upgrade_that_keeps_the_old_system_disk_snapshots_it_before_anything_else() -> TestResult {
        let aws = Arc::new(FakeAws::new());
        let p = provider(&aws);
        let before = running(&aws, &p, "main", Size::S)?;
        let name = before.spec.name.clone();
        let root = root_volume_id(&aws, &name)?;
        let plan = p.plan(&upgrade_keeping_the_old_disk(&name, true))?;
        let kinds: Vec<_> = plan.changes.iter().map(|c| c.kind.as_str()).collect();
        assert_eq!(
            kinds,
            [
                "snapshot.old_system_disk",
                "instance.stop",
                "instance.replace_image",
                "volume.reattach",
                "instance.start"
            ]
        );
        let said = &plan.changes[0].description;
        assert!(
            said.contains(&root) && said.contains("ozbox-purpose=pre-upgrade-root"),
            "{said}"
        );
        aws.clear_calls();
        let applied = p.apply(&plan)?.ok_or("no record")?;
        let calls = aws.calls();
        let at = |f: &dyn Fn(&CommandSpec) -> bool| calls.iter().position(f);
        let snap_at = at(&|c| c.args.get(1).is_some_and(|s| s == "create-snapshot"))
            .ok_or("no snapshot was taken")?;
        let mark_at = at(&|c| {
            c.args.get(1).is_some_and(|s| s == "create-tags")
                && c.args.iter().any(|a| a.starts_with("Key=ozbox-upgrade-to"))
        })
        .ok_or("no mark")?;
        let stop_at =
            at(&|c| c.args.get(1).is_some_and(|s| s.starts_with("stop"))).ok_or("no stop")?;
        let replace_at = at(&|c| c.program == "tofu" && c.args.iter().any(|a| a == "apply"))
            .ok_or("no replace")?;
        assert!(
            snap_at < mark_at && snap_at < stop_at && stop_at < replace_at,
            "snapshot {snap_at}, mark {mark_at}, stop {stop_at}, replace {replace_at}"
        );
        // the snapshot is of the SYSTEM disk, waited for, and carries the tags that keep it apart from a /work backup
        let snap_call = &calls[snap_at];
        assert!(
            snap_call
                .args
                .windows(2)
                .any(|w| w[0] == "--volume-id" && w[1] == root),
            "{:?}",
            snap_call.args
        );
        // and it was looked at until it was complete (and its encryption read) before anything was marked
        assert!(calls[snap_at..mark_at].iter().any(|c| {
            c.args.get(1).is_some_and(|s| s == "describe-snapshots")
                && c.args.iter().any(|a| a == "--snapshot-ids")
        }));
        let kept = aws.system_disk_snapshots(&name);
        assert_eq!(kept.len(), 1, "{kept:?}");
        // the apply itself says which snapshot it took, so a report never has to guess one from a listing
        assert_eq!(
            applied.spec.labels.get(ozbox_core::PRE_UPGRADE_COPY_LABEL),
            Some(&kept[0].0),
            "{:?}",
            applied.spec.labels
        );
        assert!(
            !p.get(&name)?
                .ok_or("gone")?
                .spec
                .labels
                .contains_key(ozbox_core::PRE_UPGRADE_COPY_LABEL),
            "the id is the answer of one apply, never written to the provider"
        );
        let tags = &kept[0].1;
        for (k, v) in [
            ("ozbox-managed", "true"),
            ("ozbox-box", "main"),
            ("ozbox-purpose", "pre-upgrade-root"),
            ("ozbox-upgrade-to", NEW_IMAGE),
            ("ozbox-source-volume", root.as_str()),
        ] {
            assert_eq!(tags.get(k).map(String::as_str), Some(v), "{k}: {tags:?}");
        }
        // it is listed (so it can be found and deleted) but is not a /work backup, and no clone or restore defaults to it
        let listed = p.snapshots(&name)?;
        let copy = listed
            .iter()
            .find(|s| s.id == kept[0].0)
            .ok_or("not listed")?;
        assert!(!copy.includes_work);
        let after = p.get(&name)?.ok_or("gone")?;
        assert!(after.snapshots.is_empty(), "{:?}", after.snapshots);
        let restore = p.plan(&Operation::RestoreWork {
            name: name.clone(),
            snapshot: kept[0].0.clone(),
        });
        assert!(restore.is_err(), "a system disk is never restored as /work");
        Ok(())
    }

    /// The opt-out is the operation's: with no copy asked for, nothing is snapshotted.
    #[test]
    fn an_upgrade_that_does_not_ask_for_the_old_disk_takes_no_snapshot() -> TestResult {
        let aws = Arc::new(FakeAws::new());
        let p = provider(&aws);
        let before = running(&aws, &p, "main", Size::S)?;
        let plan = p.plan(&upgrade_keeping_the_old_disk(&before.spec.name, false))?;
        assert!(!plan.changes.iter().any(|c| c.kind.contains("snapshot")));
        aws.clear_calls();
        p.apply(&plan)?;
        assert!(!aws
            .calls()
            .iter()
            .any(|c| c.args.get(1).is_some_and(|s| s == "create-snapshot")));
        assert!(aws.system_disk_snapshots(&before.spec.name).is_empty());
        Ok(())
    }

    /// A copy that cannot be made safely refuses the plan, before anything is stopped, and names the opt-out.
    #[test]
    fn a_system_disk_that_cannot_be_copied_safely_refuses_the_plan_and_names_the_opt_out(
    ) -> TestResult {
        for plain in [false, true] {
            let aws = Arc::new(FakeAws::new());
            let p = provider(&aws);
            let before = running(&aws, &p, "main", Size::S)?;
            if plain {
                aws.unencrypted_system_disks();
            } else {
                aws.untag_system_disk(&before.spec.name);
            }
            let why = p
                .plan(&upgrade_keeping_the_old_disk(&before.spec.name, true))
                .err()
                .ok_or("expected a refusal")?
                .to_string();
            assert!(why.contains("--no-pre-upgrade-snapshot"), "{plain}: {why}");
            // asking for no copy still plans
            assert!(p
                .plan(&upgrade_keeping_the_old_disk(&before.spec.name, false))
                .is_ok());
        }
        Ok(())
    }

    /// A provider's snapshot listing marks only the system-disk copies as not holding /work.
    #[test]
    fn only_a_pre_upgrade_copy_is_marked_as_not_holding_work() -> TestResult {
        let aws = Arc::new(FakeAws::new());
        let p = provider(&aws);
        let before = running(&aws, &p, "main", Size::S)?;
        p.apply(&p.plan(&Operation::Snapshot {
            name: before.spec.name.clone(),
        })?)?;
        let work = p
            .get(&before.spec.name)?
            .and_then(|r| r.snapshots.last().cloned())
            .ok_or("no /work snapshot")?;
        let listed = p.snapshots(&before.spec.name)?;
        assert!(
            listed
                .iter()
                .find(|s| s.id == work)
                .ok_or("missing")?
                .includes_work
        );
        Ok(())
    }

    /// Nothing was marked, stopped or replaced: no stop, no upgrade mark, no OpenTofu run, and the box is as it was.
    fn assert_untouched(aws: &FakeAws, p: &Engine<AwsBackend>, before: &BoxRecord, what: &str) {
        let calls = aws.calls();
        let touched: Vec<String> = calls
            .iter()
            .filter(|c| {
                (c.program == "tofu" && c.args.iter().any(|a| a == "apply" || a == "destroy"))
                    || c.args.get(1).is_some_and(|a| a.starts_with("stop"))
                    || c.args.iter().any(|a| a.starts_with("Key=ozbox-upgrade-to"))
            })
            .map(|c| c.args.join(" "))
            .collect();
        assert!(touched.is_empty(), "{what}: {touched:?}");
        let after = p.get(&before.spec.name).ok().flatten();
        assert_eq!(after.as_ref(), Some(before), "{what}: the box changed");
    }

    /// A security review (2026-11-16): the engine ignoring the result of the copy changed no test. A copy that fails at ANY step
    /// (made, looked at, finished, encrypted, under the disk's key) ends the upgrade with nothing stopped, marked or replaced.
    #[test]
    fn a_copy_that_fails_at_any_step_ends_the_upgrade_before_anything_changes() -> TestResult {
        type Setup = fn(&FakeAws);
        let cases: [(&str, Setup, &str); 8] = [
            (
                "the snapshot cannot be made",
                |a| a.fail_calls("create-snapshot"),
                "could not create",
            ),
            (
                "the snapshot cannot be read",
                |a| a.fail_calls("describe-snapshots"),
                "could not be read",
            ),
            (
                "the snapshot never finishes",
                |a| a.new_snapshots_report("pending"),
                "still being made",
            ),
            (
                "the snapshot ends in error",
                |a| a.new_snapshots_report("error"),
                "ended as error",
            ),
            (
                "the copy is not encrypted",
                |a| {
                    a.copies_report_encryption(
                        Some(false),
                        Some("arn:aws:kms:us-east-1:123456789012:key/fake"),
                    )
                },
                "not confirmed encrypted",
            ),
            (
                "the copy does not say it is encrypted",
                |a| {
                    a.copies_report_encryption(
                        None,
                        Some("arn:aws:kms:us-east-1:123456789012:key/fake"),
                    )
                },
                "not confirmed encrypted",
            ),
            (
                "the copy is under another key",
                |a| {
                    a.copies_report_encryption(
                        Some(true),
                        Some("arn:aws:kms:us-east-1:123456789012:key/other"),
                    )
                },
                "not confirmed encrypted",
            ),
            (
                "the copy does not say its key",
                |a| a.copies_report_encryption(Some(true), None),
                "not confirmed encrypted",
            ),
        ];
        for (what, setup, says) in cases {
            let aws = Arc::new(FakeAws::new());
            let p = provider_with(&aws, |c| {
                c.poll_interval = std::time::Duration::ZERO;
                c.snapshot_wait_polls = 3;
            });
            let before = running(&aws, &p, "main", Size::S)?;
            let name = before.spec.name.clone();
            let plan = p.plan(&upgrade_keeping_the_old_disk(&name, true))?;
            setup(&aws);
            aws.clear_calls();
            let err = p
                .apply(&plan)
                .err()
                .ok_or_else(|| format!("{what}: the upgrade went ahead"))?
                .to_string();
            assert!(err.contains(says), "{what}: {err}");
            assert_untouched(&aws, &p, &before, what);
        }
        Ok(())
    }

    /// A copy still being made names the snapshot, says it will finish by itself and can be used, and the upgrade did not start.
    #[test]
    fn a_copy_that_is_slow_is_named_and_the_upgrade_has_not_started() -> TestResult {
        let aws = Arc::new(FakeAws::new());
        let p = provider_with(&aws, |c| {
            c.poll_interval = std::time::Duration::ZERO;
            c.snapshot_wait_polls = 2;
        });
        let before = running(&aws, &p, "main", Size::S)?;
        let plan = p.plan(&upgrade_keeping_the_old_disk(&before.spec.name, true))?;
        aws.new_snapshots_report("pending");
        let err = p.apply(&plan).err().ok_or("went ahead")?.to_string();
        let id = aws
            .system_disk_snapshots(&before.spec.name)
            .first()
            .map(|s| s.0.clone())
            .ok_or("no snapshot")?;
        assert!(
            err.contains(&id) && err.contains("keeps going") && err.contains("can be used"),
            "{err}"
        );
        Ok(())
    }

    /// The plan fails closed too: a system disk that does not SAY it is encrypted is not assumed to be.
    #[test]
    fn a_system_disk_that_does_not_say_it_is_encrypted_refuses_the_plan() -> TestResult {
        for (enc, kms) in [
            (None, Some("arn:aws:kms:us-east-1:123456789012:key/fake")),
            (Some(false), None),
        ] {
            let aws = Arc::new(FakeAws::new());
            let p = provider(&aws);
            let before = running(&aws, &p, "main", Size::S)?;
            aws.system_disks_report_encryption(enc, kms);
            let why = p
                .plan(&upgrade_keeping_the_old_disk(&before.spec.name, true))
                .err()
                .ok_or("expected a refusal")?
                .to_string();
            assert!(
                why.contains("not confirmed encrypted")
                    && why.contains("--no-pre-upgrade-snapshot"),
                "{enc:?}: {why}"
            );
        }
        Ok(())
    }

    fn destroy_op(name: &BoxName, keep: bool) -> Operation {
        Operation::Destroy {
            name: name.clone(),
            final_snapshot: false,
            keep_old_system_disks: keep,
        }
    }

    /// The copy holds the old store's key and is only reachable through the box: destroying the box deletes it, the plan says so,
    /// and the opt-out keeps it and says what that costs.
    #[test]
    fn destroying_a_box_deletes_its_copies_of_old_system_disks_unless_asked_to_keep_them(
    ) -> TestResult {
        for keep in [false, true] {
            let aws = Arc::new(FakeAws::new());
            let p = provider(&aws);
            let before = running(&aws, &p, "main", Size::S)?;
            let name = before.spec.name.clone();
            p.apply(&p.plan(&upgrade_keeping_the_old_disk(&name, true))?)?;
            let copies = aws.system_disk_snapshots(&name);
            assert_eq!(copies.len(), 1);
            let plan = p.plan(&destroy_op(&name, keep))?;
            let kinds: Vec<_> = plan.changes.iter().map(|c| c.kind.as_str()).collect();
            if keep {
                assert_eq!(kinds, ["box.delete"], "{plan}");
                assert!(
                    plan.notes
                        .iter()
                        .any(|n| n.contains(&copies[0].0) && n.contains("KEPT")),
                    "{:?}",
                    plan.notes
                );
            } else {
                assert_eq!(
                    kinds,
                    ["snapshot.delete_old_system_disks", "box.delete"],
                    "{plan}"
                );
                let said = &plan.changes[0].description;
                assert!(
                    said.contains(&copies[0].0) && said.contains("--keep-old-system-disks"),
                    "{said}"
                );
            }
            p.apply(&plan)?;
            assert!(p.get(&name)?.is_none(), "the box is gone");
            assert_eq!(
                aws.system_disk_snapshots(&name).len(),
                usize::from(keep),
                "keep={keep}"
            );
        }
        Ok(())
    }

    /// A copy that cannot be deleted stops the destroy with the box whole, rather than leaving a key with nothing to list it.
    #[test]
    fn a_copy_that_cannot_be_deleted_stops_the_destroy_before_the_box_goes() -> TestResult {
        let aws = Arc::new(FakeAws::new());
        let p = provider(&aws);
        let before = running(&aws, &p, "main", Size::S)?;
        let name = before.spec.name.clone();
        p.apply(&p.plan(&upgrade_keeping_the_old_disk(&name, true))?)?;
        let plan = p.plan(&destroy_op(&name, false))?;
        aws.fail_calls("delete-snapshot");
        aws.clear_calls();
        assert!(p.apply(&plan).is_err());
        assert!(p.get(&name)?.is_some(), "the box is still there");
        assert!(
            !aws.calls().iter().any(|c| c.program == "tofu"),
            "nothing was destroyed"
        );
        Ok(())
    }

    /// A box with no copy plans a destroy exactly as before.
    #[test]
    fn destroying_a_box_with_no_copies_plans_no_copy_step() -> TestResult {
        let aws = Arc::new(FakeAws::new());
        let p = provider(&aws);
        let before = running(&aws, &p, "main", Size::S)?;
        let plan = p.plan(&destroy_op(&before.spec.name, false))?;
        assert!(
            plan.changes.iter().all(|c| !c.kind.contains("old_system")),
            "{plan}"
        );
        Ok(())
    }

    fn instance_with(disks: &[(&str, &str)]) -> Result<Instance> {
        let maps: Vec<serde_json::Value> = disks
            .iter()
            .map(|(d, v)| serde_json::json!({"DeviceName": d, "Ebs": {"VolumeId": v}}))
            .collect();
        Ok(serde_json::from_value(serde_json::json!({
            "InstanceId": "i-0", "InstanceType": "m7i.large", "State": {"Name": "running"},
            "RootDeviceName": "/dev/xvda", "BlockDeviceMappings": maps
        }))?)
    }

    /// A disk someone attached (a recovered system disk) is never taken for /work, whatever order the machine lists its disks in.
    #[test]
    fn an_extra_attached_disk_is_never_taken_for_the_work_volume() -> TestResult {
        let both = instance_with(&[
            ("/dev/xvda", "vol-root"),
            ("/dev/sdg", "vol-recovered"),
            ("/dev/sdf", "vol-work"),
        ])?;
        assert_eq!(work_volume_of(&both), Some("vol-work"));
        let single = instance_with(&[("/dev/xvda", "vol-root"), ("/dev/xvdb", "vol-only")])?;
        assert_eq!(work_volume_of(&single), Some("vol-only"));
        let ambiguous = instance_with(&[
            ("/dev/xvda", "vol-root"),
            ("/dev/sdg", "vol-a"),
            ("/dev/sdh", "vol-b"),
        ])?;
        assert_eq!(work_volume_of(&ambiguous), None);
        Ok(())
    }

    /// A pre-upgrade copy is never counted as a /work backup in the box's own record, and never lists as one.
    #[test]
    fn a_copy_of_an_old_system_disk_is_not_a_work_snapshot_in_the_record() -> TestResult {
        let aws = Arc::new(FakeAws::new());
        let p = provider(&aws);
        let before = running(&aws, &p, "main", Size::S)?;
        p.apply(&p.plan(&upgrade_keeping_the_old_disk(&before.spec.name, true))?)?;
        assert!(p
            .get(&before.spec.name)?
            .ok_or("gone")?
            .snapshots
            .is_empty());
        assert!(p
            .snapshots(&before.spec.name)?
            .iter()
            .all(|s| !s.includes_work));
        Ok(())
    }

    fn describe_by_id_calls(aws: &FakeAws) -> usize {
        aws.calls()
            .iter()
            .filter(|c| {
                c.args.get(1).is_some_and(|a| a == "describe-snapshots")
                    && c.args.iter().any(|a| a == "--snapshot-ids")
            })
            .count()
    }

    /// The copy `ozbox upgrade` takes before it makes the box ready waits as long as the provider allows; one taken inside an apply
    /// (while the box may be holding new runs back for its stop) waits only [`ozbox_core::HOLD_SAFE_COPY_WAIT`]. Neither stops
    /// anything when the copy is slow.
    #[test]
    fn the_copy_taken_ahead_waits_long_and_the_one_inside_an_apply_waits_within_the_hold(
    ) -> TestResult {
        let polls = |ahead: bool| -> Result<usize> {
            let aws = Arc::new(FakeAws::new());
            let p = provider_with(&aws, |c| {
                c.poll_interval = std::time::Duration::ZERO;
                c.snapshot_wait_polls = 1000;
            });
            let before = running(&aws, &p, "main", Size::S)?;
            let name = before.spec.name.clone();
            let plan = p.plan(&upgrade_keeping_the_old_disk(&name, true))?;
            aws.new_snapshots_report("pending");
            aws.clear_calls();
            let slow = if ahead {
                p.keep_old_system_disk(&name, NEW_IMAGE).err()
            } else {
                p.apply(&plan).err()
            };
            assert!(slow.is_some(), "a copy that never finishes is an error");
            assert_untouched(&aws, &p, &before, "slow copy");
            Ok(describe_by_id_calls(&aws))
        };
        assert_eq!(polls(true)?, 1000);
        assert_eq!(polls(false)?, 300);
        Ok(())
    }

    /// `ozbox upgrade` takes the copy ahead and plans again without it: the copy is made once, and what is applied makes no second.
    #[test]
    fn a_copy_taken_ahead_is_not_taken_again_by_the_apply() -> TestResult {
        let aws = Arc::new(FakeAws::new());
        let p = provider(&aws);
        let before = running(&aws, &p, "main", Size::S)?;
        let name = before.spec.name.clone();
        let id = p.keep_old_system_disk(&name, NEW_IMAGE)?;
        let held = aws.system_disk_snapshots(&name);
        assert_eq!(held.iter().map(|s| s.0.clone()).collect::<Vec<_>>(), [id]);
        p.apply(&p.plan(&upgrade_keeping_the_old_disk(&name, false))?)?;
        assert_eq!(aws.system_disk_snapshots(&name).len(), 1);
        Ok(())
    }
}
