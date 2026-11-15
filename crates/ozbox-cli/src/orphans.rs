//! Resources in the account that look like Oz Box's but are not tagged `ozbox-managed`, and disks, snapshots and images
//! Oz Box made that no box uses any more, with what each costs a month.
//!
//! Finding them is read-only (`aws ec2 describe-*`, no tag filter, so what is *not* tagged is visible). Deleting is a
//! plan, then an apply with a typed confirmation, and it only ever touches a volume or a snapshot that **carries the
//! `ozbox-managed=true` tag and is still unused when the apply runs** (it is looked at again first). An untagged
//! resource is listed so the person can look at it and is never deleted from here: it may not be ours.

use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;

use ozbox_core::{CommandRunner, CommandSpec};
use serde::{Deserialize, Serialize};

use crate::bill::{BOX_TAG, MANAGED_TAG};
use crate::messages::t;
use crate::pricing::{PriceBook, HOURS_PER_MONTH};

const UPGRADE_TO: &str = "ozbox-upgrade-to";
const ROLE_TAG: &str = "ozbox-role";
const RESTORE_TAG: &str = "ozbox-restore";
const IMAGE_TAG: &str = "ozbox-image";
const RETIRED_ROLE: &str = "work-retired";

/// Why a resource is listed. The dashboard words each one.
pub mod reason {
    pub const NO_MANAGED_TAG: &str = "no_managed_tag";
    pub const RETIRED_WORK_DISK: &str = "retired_work_disk";
    pub const WORK_DISK_NO_BOX: &str = "work_disk_no_box";
    pub const UNATTACHED_VOLUME: &str = "unattached_volume";
    pub const SNAPSHOT_NO_BOX: &str = "snapshot_no_box";
    pub const SNAPSHOT_BOX_GONE: &str = "snapshot_box_gone";
    pub const UNSIGNED_IMAGE: &str = "unsigned_image";
    pub const FAILED_IMAGE: &str = "failed_image";
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct OrphanItem {
    pub id: String,
    /// `instance`, `volume`, `snapshot` or `image`.
    pub kind: String,
    pub region: String,
    /// `untagged` (looks like ours, is not tagged) or `unused` (ours, and no box uses it).
    pub class: String,
    pub reason: String,
    pub box_name: Option<String>,
    pub name: Option<String>,
    pub size_gb: Option<u64>,
    pub created: Option<String>,
    /// What it costs a month, from the public price list. `None` when no price is known: never a guess.
    pub month_cost: Option<f64>,
    /// A snapshot is billed for what changed, not its size, so its figure is the most it can cost.
    pub cost_is_most: bool,
    /// Whether Oz Box may delete it: only a tagged volume or snapshot.
    pub deletable: bool,
}

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct OrphanScan {
    pub scanned_at_ms: u64,
    pub regions: Vec<String>,
    pub currency: Option<String>,
    pub items: Vec<OrphanItem>,
    /// Set when the scan could not be done; `items` is then what an earlier scan found.
    pub error: Option<String>,
    /// This provider cannot be searched yet (only AWS is).
    pub unsupported: bool,
}

// ---------- reading ec2 ----------

#[derive(Deserialize, Default, Clone)]
#[serde(rename_all = "PascalCase")]
struct Tag {
    key: String,
    value: String,
}

#[derive(Deserialize, Default)]
#[serde(rename_all = "PascalCase", default)]
struct Ebs {
    volume_id: Option<String>,
    snapshot_id: Option<String>,
}

#[derive(Deserialize, Default)]
#[serde(rename_all = "PascalCase", default)]
struct Mapping {
    ebs: Option<Ebs>,
}

#[derive(Deserialize, Default)]
#[serde(rename_all = "PascalCase", default)]
struct InstanceState {
    name: String,
}

#[derive(Deserialize, Default)]
#[serde(rename_all = "PascalCase", default)]
struct Instance {
    instance_id: String,
    instance_type: String,
    image_id: Option<String>,
    state: InstanceState,
    launch_time: Option<String>,
    tags: Vec<Tag>,
    block_device_mappings: Vec<Mapping>,
}

#[derive(Deserialize, Default)]
#[serde(rename_all = "PascalCase", default)]
struct Reservation {
    instances: Vec<Instance>,
}

#[derive(Deserialize, Default)]
#[serde(rename_all = "PascalCase", default)]
struct Reservations {
    reservations: Vec<Reservation>,
}

#[derive(Deserialize, Default)]
#[serde(rename_all = "PascalCase", default)]
struct Volume {
    volume_id: String,
    size: u64,
    state: Option<String>,
    create_time: Option<String>,
    tags: Vec<Tag>,
    attachments: Vec<serde_json::Value>,
}

#[derive(Deserialize, Default)]
#[serde(rename_all = "PascalCase", default)]
struct Volumes {
    volumes: Vec<Volume>,
}

#[derive(Deserialize, Default)]
#[serde(rename_all = "PascalCase", default)]
struct Snapshot {
    snapshot_id: String,
    volume_size: u64,
    start_time: Option<String>,
    tags: Vec<Tag>,
}

#[derive(Deserialize, Default)]
#[serde(rename_all = "PascalCase", default)]
struct Snapshots {
    snapshots: Vec<Snapshot>,
}

#[derive(Deserialize, Default)]
#[serde(rename_all = "PascalCase", default)]
struct Image {
    image_id: String,
    state: Option<String>,
    creation_date: Option<String>,
    tags: Vec<Tag>,
    block_device_mappings: Vec<Mapping>,
}

#[derive(Deserialize, Default)]
#[serde(rename_all = "PascalCase", default)]
struct Images {
    images: Vec<Image>,
}

fn tag<'a>(tags: &'a [Tag], key: &str) -> Option<&'a str> {
    tags.iter().find(|t| t.key == key).map(|t| t.value.as_str())
}

fn managed(tags: &[Tag]) -> bool {
    tag(tags, MANAGED_TAG) == Some("true")
}

/// Whether a resource that is not tagged managed still looks like one of ours: a tag key from Oz Box, or its name.
fn looks_like_ozbox(tags: &[Tag]) -> bool {
    tags.iter().any(|t| {
        let k = t.key.to_ascii_lowercase();
        let managed_false = k == MANAGED_TAG && t.value != "true";
        (k.starts_with("ozbox-") && k != MANAGED_TAG)
            || managed_false
            || (k == "name" && t.value.to_ascii_lowercase().starts_with("ozbox-"))
    })
}

fn name_of(tags: &[Tag]) -> Option<String> {
    tag(tags, "Name").map(str::to_string)
}

/// Everything one region holds that is relevant, as the CLI printed it.
pub struct RegionData {
    pub region: String,
    pub instances: String,
    pub volumes: String,
    pub snapshots: String,
    pub images: String,
}

/// Classify one region's resources. Pure: the same JSON gives the same list.
pub fn classify(d: &RegionData, prices: Option<&PriceBook>) -> Result<Vec<OrphanItem>, String> {
    let parse = |what: &str| format!("the {what} list had an unexpected shape");
    let instances: Reservations =
        serde_json::from_str(&d.instances).map_err(|_| parse("machine"))?;
    let volumes: Volumes = serde_json::from_str(&d.volumes).map_err(|_| parse("disk"))?;
    let snapshots: Snapshots = serde_json::from_str(&d.snapshots).map_err(|_| parse("snapshot"))?;
    let images: Images = serde_json::from_str(&d.images).map_err(|_| parse("image"))?;
    let instances: Vec<&Instance> = instances
        .reservations
        .iter()
        .flat_map(|r| &r.instances)
        .filter(|i| !matches!(i.state.name.as_str(), "terminated" | "shutting-down"))
        .collect();

    let live_boxes: BTreeSet<&str> = instances
        .iter()
        .filter_map(|i| tag(&i.tags, BOX_TAG))
        .collect();
    let attached: BTreeSet<&str> = instances
        .iter()
        .flat_map(|i| &i.block_device_mappings)
        .filter_map(|m| m.ebs.as_ref().and_then(|e| e.volume_id.as_deref()))
        .collect();
    let used_images: BTreeSet<&str> = instances
        .iter()
        .filter_map(|i| i.image_id.as_deref())
        .collect();
    let image_snapshots: BTreeSet<&str> = images
        .images
        .iter()
        .flat_map(|i| &i.block_device_mappings)
        .filter_map(|m| m.ebs.as_ref().and_then(|e| e.snapshot_id.as_deref()))
        .collect();
    let snapshot_size: BTreeMap<&str, u64> = snapshots
        .snapshots
        .iter()
        .map(|s| (s.snapshot_id.as_str(), s.volume_size))
        .collect();

    let disk_gb = prices.and_then(|p| p.disk_gb_month);
    let snap_gb = prices.and_then(|p| p.snapshot_gb_month);
    let mut out = Vec::new();
    let mut push = |id: &str,
                    kind: &str,
                    class: &str,
                    why: &str,
                    tags: &[Tag],
                    size: Option<u64>,
                    created: Option<String>,
                    cost: Option<f64>,
                    most: bool,
                    deletable: bool| {
        out.push(OrphanItem {
            id: id.to_string(),
            kind: kind.to_string(),
            region: d.region.clone(),
            class: class.to_string(),
            reason: why.to_string(),
            box_name: tag(tags, BOX_TAG).map(str::to_string),
            name: name_of(tags),
            size_gb: size,
            created,
            month_cost: cost,
            cost_is_most: most,
            deletable,
        });
    };

    for i in &instances {
        if !managed(&i.tags) && looks_like_ozbox(&i.tags) {
            let cost = (i.state.name == "running")
                .then(|| prices.and_then(|p| p.machine(&i.instance_type, Some(&d.region))))
                .flatten()
                .map(|h| h * HOURS_PER_MONTH);
            push(
                &i.instance_id,
                "instance",
                "untagged",
                reason::NO_MANAGED_TAG,
                &i.tags,
                None,
                i.launch_time.clone(),
                cost,
                false,
                false,
            );
        }
    }

    for v in &volumes.volumes {
        let cost = disk_gb.map(|g| g * v.size as f64);
        let free = v.state.as_deref().is_none_or(|s| s == "available")
            && v.attachments.is_empty()
            && !attached.contains(v.volume_id.as_str());
        if !managed(&v.tags) {
            if looks_like_ozbox(&v.tags) {
                push(
                    &v.volume_id,
                    "volume",
                    "untagged",
                    reason::NO_MANAGED_TAG,
                    &v.tags,
                    Some(v.size),
                    v.create_time.clone(),
                    cost,
                    false,
                    false,
                );
            }
            continue;
        }
        if !free {
            continue;
        }
        // An interrupted upgrade and a restore still waiting for its answer are not forgotten disks: they are the
        // thing the person is about to come back for.
        if tag(&v.tags, UPGRADE_TO).is_some() || tag(&v.tags, RESTORE_TAG) == Some("pending") {
            continue;
        }
        let boxed = tag(&v.tags, BOX_TAG);
        let role = tag(&v.tags, ROLE_TAG);
        let why = if role == Some(RETIRED_ROLE) {
            reason::RETIRED_WORK_DISK
        } else if role == Some("work") && boxed.is_some_and(|b| !live_boxes.contains(b)) {
            reason::WORK_DISK_NO_BOX
        } else if role == Some("work") {
            // the box still has a machine: this is its own disk, momentarily free; not ours to call forgotten
            continue;
        } else {
            reason::UNATTACHED_VOLUME
        };
        push(
            &v.volume_id,
            "volume",
            "unused",
            why,
            &v.tags,
            Some(v.size),
            v.create_time.clone(),
            cost,
            false,
            true,
        );
    }

    for s in &snapshots.snapshots {
        let cost = snap_gb.map(|g| g * s.volume_size as f64);
        if !managed(&s.tags) {
            if looks_like_ozbox(&s.tags) {
                push(
                    &s.snapshot_id,
                    "snapshot",
                    "untagged",
                    reason::NO_MANAGED_TAG,
                    &s.tags,
                    Some(s.volume_size),
                    s.start_time.clone(),
                    cost,
                    true,
                    false,
                );
            }
            continue;
        }
        // A snapshot an image is made of cannot be deleted while the image exists; the image is what is listed.
        if image_snapshots.contains(s.snapshot_id.as_str()) {
            continue;
        }
        let why = match tag(&s.tags, BOX_TAG) {
            None => reason::SNAPSHOT_NO_BOX,
            Some(b) if !live_boxes.contains(b) => reason::SNAPSHOT_BOX_GONE,
            Some(_) => continue,
        };
        push(
            &s.snapshot_id,
            "snapshot",
            "unused",
            why,
            &s.tags,
            Some(s.volume_size),
            s.start_time.clone(),
            cost,
            true,
            true,
        );
    }

    for im in &images.images {
        let size: u64 = im
            .block_device_mappings
            .iter()
            .filter_map(|m| m.ebs.as_ref().and_then(|e| e.snapshot_id.as_deref()))
            .filter_map(|id| snapshot_size.get(id))
            .sum();
        let cost = snap_gb.filter(|_| size > 0).map(|g| g * size as f64);
        if !managed(&im.tags) {
            if looks_like_ozbox(&im.tags) {
                push(
                    &im.image_id,
                    "image",
                    "untagged",
                    reason::NO_MANAGED_TAG,
                    &im.tags,
                    (size > 0).then_some(size),
                    im.creation_date.clone(),
                    cost,
                    true,
                    false,
                );
            }
            continue;
        }
        if used_images.contains(im.image_id.as_str()) {
            continue;
        }
        let state = im.state.as_deref().unwrap_or("available");
        let why = if matches!(state, "failed" | "error" | "invalid") {
            reason::FAILED_IMAGE
        } else if tag(&im.tags, IMAGE_TAG).is_none() {
            reason::UNSIGNED_IMAGE
        } else {
            continue;
        };
        // Images are made and retired by the image build, not here: listed, never deleted from this page.
        push(
            &im.image_id,
            "image",
            "unused",
            why,
            &im.tags,
            (size > 0).then_some(size),
            im.creation_date.clone(),
            cost,
            true,
            false,
        );
    }
    out.sort_by(|a, b| {
        a.class
            .cmp(&b.class)
            .then(a.kind.cmp(&b.kind))
            .then(a.id.cmp(&b.id))
    });
    Ok(out)
}

/// Where the account's resources come from. The server and the CLI use the provider's; the demo has its own.
pub trait OrphanSource: Send + Sync {
    fn scan(&self, regions: &[String], prices: Option<&PriceBook>, now_ms: u64) -> OrphanScan;
    fn delete(&self, item: &OrphanItem) -> Result<(), String>;
}

/// A provider this cannot look into yet.
pub struct NoOrphans;

impl OrphanSource for NoOrphans {
    fn scan(&self, regions: &[String], _prices: Option<&PriceBook>, now_ms: u64) -> OrphanScan {
        OrphanScan {
            scanned_at_ms: now_ms,
            regions: regions.to_vec(),
            unsupported: true,
            error: Some(t("cost.orphans.unsupported", &[])),
            ..OrphanScan::default()
        }
    }

    fn delete(&self, item: &OrphanItem) -> Result<(), String> {
        Err(t("cost.orphans.err_not_ours", &[("id", &item.id)]))
    }
}

impl OrphanSource for AwsOrphans {
    fn scan(&self, regions: &[String], prices: Option<&PriceBook>, now_ms: u64) -> OrphanScan {
        AwsOrphans::scan(self, regions, prices, now_ms)
    }

    fn delete(&self, item: &OrphanItem) -> Result<(), String> {
        AwsOrphans::delete(self, item)
    }
}

pub struct AwsOrphans {
    pub runner: Arc<dyn CommandRunner>,
    pub profile: Option<String>,
}

impl AwsOrphans {
    fn call(&self, region: &str, args: &[&str]) -> Result<String, String> {
        let mut c = CommandSpec::new("aws")
            .arg("ec2")
            .args(args.iter().copied());
        c = c.args(["--region", region, "--output", "json"]);
        if let Some(p) = &self.profile {
            c = c.args(["--profile", p]);
        }
        self.runner
            .run_ok(&c)
            .map(|o| o.stdout)
            .map_err(|e| match e {
                ozbox_core::Error::Command { stderr, .. } => t(
                    "cost.orphans.err_read",
                    &[(
                        "why",
                        &stderr
                            .lines()
                            .find(|l| !l.trim().is_empty())
                            .unwrap_or("")
                            .chars()
                            .take(200)
                            .collect::<String>(),
                    )],
                ),
                other => other.to_string(),
            })
    }

    /// Every region asked for, read-only.
    pub fn scan(&self, regions: &[String], prices: Option<&PriceBook>, now_ms: u64) -> OrphanScan {
        let mut items = Vec::new();
        let mut error = None;
        if regions.is_empty() {
            // Nothing to look in is not "nothing found": say so.
            error = Some(t("cost.orphans.no_region", &[]));
        }
        for r in regions {
            let read = || -> Result<RegionData, String> {
                Ok(RegionData {
                    region: r.clone(),
                    instances: self.call(
                        r,
                        &[
                            "describe-instances",
                            "--filters",
                            "Name=instance-state-name,Values=pending,running,stopping,stopped",
                        ],
                    )?,
                    volumes: self.call(r, &["describe-volumes"])?,
                    snapshots: self.call(r, &["describe-snapshots", "--owner-ids", "self"])?,
                    images: self.call(r, &["describe-images", "--owners", "self"])?,
                })
            };
            match read().and_then(|d| classify(&d, prices)) {
                Ok(mut found) => items.append(&mut found),
                Err(e) => error = Some(e),
            }
        }
        OrphanScan {
            scanned_at_ms: now_ms,
            regions: regions.to_vec(),
            currency: prices.map(|p| p.currency.clone()),
            items,
            error,
            unsupported: false,
        }
    }

    /// Look at the resource again and delete it only if it is still tagged and still unused.
    pub fn delete(&self, item: &OrphanItem) -> Result<(), String> {
        if !item.deletable {
            return Err(t("cost.orphans.err_not_ours", &[("id", &item.id)]));
        }
        match item.kind.as_str() {
            "volume" => {
                let out = self.call(
                    &item.region,
                    &["describe-volumes", "--volume-ids", &item.id],
                )?;
                let v: Volumes = serde_json::from_str(&out)
                    .map_err(|_| t("cost.orphans.err_changed", &[("id", &item.id)]))?;
                let ok = v.volumes.first().is_some_and(|v| {
                    managed(&v.tags)
                        && v.attachments.is_empty()
                        && v.state.as_deref().is_none_or(|s| s == "available")
                        && tag(&v.tags, UPGRADE_TO).is_none()
                        && tag(&v.tags, RESTORE_TAG) != Some("pending")
                });
                if !ok {
                    return Err(t("cost.orphans.err_changed", &[("id", &item.id)]));
                }
                self.call(&item.region, &["delete-volume", "--volume-id", &item.id])
                    .map(|_| ())
            }
            "snapshot" => {
                let out = self.call(
                    &item.region,
                    &[
                        "describe-snapshots",
                        "--snapshot-ids",
                        &item.id,
                        "--owner-ids",
                        "self",
                    ],
                )?;
                let s: Snapshots = serde_json::from_str(&out)
                    .map_err(|_| t("cost.orphans.err_changed", &[("id", &item.id)]))?;
                let imgs = self.call(
                    &item.region,
                    &[
                        "describe-images",
                        "--owners",
                        "self",
                        "--filters",
                        &format!("Name=block-device-mapping.snapshot-id,Values={}", item.id),
                    ],
                )?;
                let used: Images = serde_json::from_str(&imgs)
                    .map_err(|_| t("cost.orphans.err_changed", &[("id", &item.id)]))?;
                if !s.snapshots.first().is_some_and(|s| managed(&s.tags)) || !used.images.is_empty()
                {
                    return Err(t("cost.orphans.err_changed", &[("id", &item.id)]));
                }
                self.call(
                    &item.region,
                    &["delete-snapshot", "--snapshot-id", &item.id],
                )
                .map(|_| ())
            }
            _ => Err(t("cost.orphans.err_not_ours", &[("id", &item.id)])),
        }
    }
}

// ---------- plan, then apply ----------

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct OrphanPlan {
    pub items: Vec<OrphanItem>,
    /// What must be typed to apply: the id when there is one resource, else `delete-N`.
    pub confirm_text: String,
    pub month_cost: Option<f64>,
    pub currency: Option<String>,
    /// The scan the plan was made from.
    pub based_on_ms: u64,
}

pub fn confirm_text(items: &[OrphanItem]) -> String {
    match items {
        [one] => one.id.clone(),
        many => format!("delete-{}", many.len()),
    }
}

/// A plan to delete the chosen resources. Refuses an id that was not found, and anything Oz Box may not delete.
pub fn plan(scan: &OrphanScan, ids: &[String]) -> Result<OrphanPlan, String> {
    if ids.is_empty() {
        return Err(t("cost.orphans.err_none_chosen", &[]));
    }
    let mut items = Vec::new();
    for id in ids {
        let Some(it) = scan.items.iter().find(|i| &i.id == id) else {
            return Err(t("cost.orphans.err_unknown", &[("id", id)]));
        };
        if !it.deletable {
            return Err(t("cost.orphans.err_not_ours", &[("id", id)]));
        }
        if !items.iter().any(|x: &OrphanItem| x.id == it.id) {
            items.push(it.clone());
        }
    }
    let costs: Vec<Option<f64>> = items.iter().map(|i| i.month_cost).collect();
    let month_cost = costs
        .iter()
        .copied()
        .collect::<Option<Vec<f64>>>()
        .map(|v| v.iter().sum());
    Ok(OrphanPlan {
        confirm_text: confirm_text(&items),
        items,
        month_cost,
        currency: scan.currency.clone(),
        based_on_ms: scan.scanned_at_ms,
    })
}

#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct ItemResult {
    pub id: String,
    pub ok: bool,
    pub message: Option<String>,
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use serde_json::json;
    use std::sync::Mutex;

    fn tags(pairs: &[(&str, &str)]) -> serde_json::Value {
        json!(pairs
            .iter()
            .map(|(k, v)| json!({"Key": k, "Value": v}))
            .collect::<Vec<_>>())
    }

    fn book() -> PriceBook {
        PriceBook {
            provider: "aws".into(),
            currency: "USD".into(),
            source: "test".into(),
            region: "us-east-1".into(),
            fetched_at_ms: 1,
            machine_hourly: [("m7i.large".to_string(), 0.1)].into(),
            disk_gb_month: Some(0.08),
            snapshot_gb_month: Some(0.05),
        }
    }

    fn data() -> RegionData {
        RegionData {
            region: "us-east-1".into(),
            instances: json!({"Reservations": [{"Instances": [
                // alpha: tagged, running, its work disk attached, on image ami-live
                {"InstanceId": "i-alpha", "InstanceType": "m7i.large", "ImageId": "ami-live", "State": {"Name": "running"},
                 "Tags": tags(&[("ozbox-managed","true"),("ozbox-box","alpha")]),
                 "BlockDeviceMappings": [{"Ebs": {"VolumeId": "vol-alpha-work"}}]},
                // a machine that looks like ours and is not tagged managed
                {"InstanceId": "i-stray", "InstanceType": "m7i.large", "State": {"Name": "running"},
                 "Tags": tags(&[("Name","ozbox-test-box")])},
                {"InstanceId": "i-gone", "InstanceType": "m7i.large", "State": {"Name": "terminated"},
                 "Tags": tags(&[("Name","ozbox-old")])},
                // someone else's machine: never listed
                {"InstanceId": "i-other", "InstanceType": "t3.micro", "State": {"Name": "running"}, "Tags": tags(&[("Name","web")])}
            ]}]}).to_string(),
            volumes: json!({"Volumes": [
                {"VolumeId": "vol-alpha-work", "Size": 100, "State": "in-use", "Attachments": [{"InstanceId": "i-alpha"}],
                 "Tags": tags(&[("ozbox-managed","true"),("ozbox-box","alpha"),("ozbox-role","work")])},
                {"VolumeId": "vol-retired", "Size": 200, "State": "available", "CreateTime": "2026-10-01T00:00:00Z",
                 "Tags": tags(&[("ozbox-managed","true"),("ozbox-box","alpha"),("ozbox-role","work-retired")])},
                {"VolumeId": "vol-pending", "Size": 50, "State": "available",
                 "Tags": tags(&[("ozbox-managed","true"),("ozbox-box","alpha"),("ozbox-role","work-retired"),("ozbox-restore","pending")])},
                {"VolumeId": "vol-upgrading", "Size": 50, "State": "available",
                 "Tags": tags(&[("ozbox-managed","true"),("ozbox-box","ghost"),("ozbox-role","work"),("ozbox-upgrade-to","ami-new")])},
                {"VolumeId": "vol-ghost-work", "Size": 40, "State": "available",
                 "Tags": tags(&[("ozbox-managed","true"),("ozbox-box","ghost"),("ozbox-role","work")])},
                {"VolumeId": "vol-alpha-free", "Size": 40, "State": "available",
                 "Tags": tags(&[("ozbox-managed","true"),("ozbox-box","alpha"),("ozbox-role","work")])},
                {"VolumeId": "vol-loose", "Size": 10, "State": "available", "Tags": tags(&[("ozbox-managed","true")])},
                {"VolumeId": "vol-lookalike", "Size": 30, "State": "available", "Tags": tags(&[("ozbox-box","delta")])},
                {"VolumeId": "vol-unrelated", "Size": 500, "State": "available", "Tags": tags(&[("Name","db")])}
            ]}).to_string(),
            snapshots: json!({"Snapshots": [
                {"SnapshotId": "snap-ghost", "VolumeSize": 40, "StartTime": "2026-09-01T00:00:00Z",
                 "Tags": tags(&[("ozbox-managed","true"),("ozbox-box","ghost")])},
                {"SnapshotId": "snap-alpha", "VolumeSize": 100,
                 "Tags": tags(&[("ozbox-managed","true"),("ozbox-box","alpha")])},
                {"SnapshotId": "snap-nobox", "VolumeSize": 20, "Tags": tags(&[("ozbox-managed","true")])},
                {"SnapshotId": "snap-image", "VolumeSize": 30, "Tags": tags(&[("ozbox-managed","true")])},
                {"SnapshotId": "snap-lookalike", "VolumeSize": 20, "Tags": tags(&[("ozbox-box","beta")])},
                {"SnapshotId": "snap-theirs", "VolumeSize": 900, "Tags": tags(&[("Name","backup")])}
            ]}).to_string(),
            images: json!({"Images": [
                {"ImageId": "ami-live", "State": "available", "Tags": tags(&[("ozbox-managed","true"),("ozbox-image","2026.11.09-3")])},
                {"ImageId": "ami-signed", "State": "available", "Tags": tags(&[("ozbox-managed","true"),("ozbox-image","2026.11.01-1")])},
                {"ImageId": "ami-unsigned", "State": "available", "CreationDate": "2026-11-02T00:00:00Z",
                 "Tags": tags(&[("ozbox-managed","true")]),
                 "BlockDeviceMappings": [{"Ebs": {"SnapshotId": "snap-image"}}]},
                {"ImageId": "ami-failed", "State": "failed", "Tags": tags(&[("ozbox-managed","true"),("ozbox-image","x")])}
            ]}).to_string(),
        }
    }

    fn ids(items: &[OrphanItem]) -> Vec<&str> {
        items.iter().map(|i| i.id.as_str()).collect()
    }

    #[test]
    fn what_looks_like_ours_but_is_not_tagged_is_listed_and_never_deletable() {
        let items = classify(&data(), Some(&book())).unwrap();
        let untagged: Vec<&OrphanItem> = items.iter().filter(|i| i.class == "untagged").collect();
        let mut got: Vec<&str> = untagged.iter().map(|i| i.id.as_str()).collect();
        got.sort_unstable();
        assert_eq!(got, vec!["i-stray", "snap-lookalike", "vol-lookalike"]);
        assert!(untagged
            .iter()
            .all(|i| !i.deletable && i.reason == reason::NO_MANAGED_TAG));
        // a running machine is priced from the price list: 0.1 an hour for a month
        let stray = items.iter().find(|i| i.id == "i-stray").unwrap();
        assert!((stray.month_cost.unwrap() - 73.0).abs() < 1e-9);
        // other people's resources and terminated machines are not ours to list
        assert!(!ids(&items).contains(&"i-other") && !ids(&items).contains(&"i-gone"));
        assert!(!ids(&items).contains(&"vol-unrelated") && !ids(&items).contains(&"snap-theirs"));
    }

    #[test]
    fn unused_volumes_are_the_forgotten_ones_and_never_a_disk_still_needed() {
        let items = classify(&data(), Some(&book())).unwrap();
        let unused = |id: &str| items.iter().find(|i| i.id == id);
        assert_eq!(
            unused("vol-retired").map(|i| i.reason.as_str()),
            Some(reason::RETIRED_WORK_DISK)
        );
        assert_eq!(
            unused("vol-ghost-work").map(|i| i.reason.as_str()),
            Some(reason::WORK_DISK_NO_BOX)
        );
        assert_eq!(
            unused("vol-loose").map(|i| i.reason.as_str()),
            Some(reason::UNATTACHED_VOLUME)
        );
        for kept in [
            "vol-alpha-work",
            "vol-pending",
            "vol-upgrading",
            "vol-alpha-free",
        ] {
            assert!(unused(kept).is_none(), "{kept} is not forgotten");
        }
        let r = unused("vol-retired").unwrap();
        assert!(r.deletable && r.class == "unused" && r.size_gb == Some(200));
        assert!((r.month_cost.unwrap() - 16.0).abs() < 1e-9);
        assert!(!r.cost_is_most);
    }

    #[test]
    fn snapshots_of_a_box_that_is_gone_are_unused_and_an_images_snapshot_is_not_listed_on_its_own()
    {
        let items = classify(&data(), Some(&book())).unwrap();
        let s = |id: &str| items.iter().find(|i| i.id == id);
        assert_eq!(
            s("snap-ghost").map(|i| i.reason.as_str()),
            Some(reason::SNAPSHOT_BOX_GONE)
        );
        assert_eq!(
            s("snap-nobox").map(|i| i.reason.as_str()),
            Some(reason::SNAPSHOT_NO_BOX)
        );
        assert!(s("snap-alpha").is_none(), "alpha still has a machine");
        assert!(s("snap-image").is_none(), "an image needs it");
        let g = s("snap-ghost").unwrap();
        assert!(g.cost_is_most && (g.month_cost.unwrap() - 2.0).abs() < 1e-9);
    }

    #[test]
    fn images_that_are_unsigned_or_failed_are_listed_with_their_snapshot_cost_but_not_deletable_here(
    ) {
        let items = classify(&data(), Some(&book())).unwrap();
        let s = |id: &str| items.iter().find(|i| i.id == id);
        let u = s("ami-unsigned").unwrap();
        assert_eq!(u.reason, reason::UNSIGNED_IMAGE);
        assert!(!u.deletable);
        assert_eq!(u.size_gb, Some(30));
        assert!((u.month_cost.unwrap() - 1.5).abs() < 1e-9);
        assert_eq!(
            s("ami-failed").map(|i| i.reason.as_str()),
            Some(reason::FAILED_IMAGE)
        );
        assert!(s("ami-live").is_none() && s("ami-signed").is_none());
    }

    #[test]
    fn without_a_price_the_cost_is_absent_not_zero() {
        let items = classify(&data(), None).unwrap();
        assert!(items.iter().all(|i| i.month_cost.is_none()));
        let bad = RegionData {
            instances: "x".into(),
            ..data()
        };
        assert!(classify(&bad, None).is_err());
    }

    #[test]
    fn a_plan_names_only_tagged_unused_things_and_asks_for_the_right_words() {
        let scan = OrphanScan {
            scanned_at_ms: 5,
            regions: vec!["us-east-1".into()],
            currency: Some("USD".into()),
            items: classify(&data(), Some(&book())).unwrap(),
            error: None,
            unsupported: false,
        };
        let one = plan(&scan, &["vol-retired".to_string()]).unwrap();
        assert_eq!(one.confirm_text, "vol-retired");
        assert_eq!(one.based_on_ms, 5);
        let two = plan(
            &scan,
            &[
                "vol-retired".to_string(),
                "snap-ghost".to_string(),
                "vol-retired".to_string(),
            ],
        )
        .unwrap();
        assert_eq!(two.items.len(), 2);
        assert_eq!(two.confirm_text, "delete-2");
        assert!((two.month_cost.unwrap() - 18.0).abs() < 1e-9);
        assert!(plan(&scan, &["i-stray".to_string()])
            .unwrap_err()
            .contains("i-stray"));
        assert!(plan(&scan, &["ami-unsigned".to_string()]).is_err());
        assert!(plan(&scan, &["vol-nowhere".to_string()]).is_err());
        assert!(plan(&scan, &[]).is_err());
    }

    struct Fake {
        calls: Mutex<Vec<Vec<String>>>,
        answers: Mutex<Vec<String>>,
    }

    impl CommandRunner for Fake {
        fn run(&self, cmd: &CommandSpec) -> ozbox_core::Result<ozbox_core::Output> {
            self.calls.lock().unwrap().push(cmd.args.clone());
            let out = self.answers.lock().unwrap().remove(0);
            Ok(ozbox_core::Output {
                status: Some(0),
                stdout: out,
                stderr: String::new(),
            })
        }
    }

    fn item(id: &str, kind: &str) -> OrphanItem {
        OrphanItem {
            id: id.into(),
            kind: kind.into(),
            region: "us-east-1".into(),
            class: "unused".into(),
            reason: reason::RETIRED_WORK_DISK.into(),
            box_name: None,
            name: None,
            size_gb: Some(1),
            created: None,
            month_cost: None,
            cost_is_most: false,
            deletable: true,
        }
    }

    #[test]
    fn a_delete_looks_again_and_stops_if_the_resource_is_no_longer_tagged_or_is_attached() {
        let tagged = json!({"Volumes": [{"VolumeId": "vol-a", "Size": 1, "State": "available", "Tags": tags(&[("ozbox-managed","true")])}]}).to_string();
        let fake = Arc::new(Fake {
            calls: Mutex::new(vec![]),
            answers: Mutex::new(vec![tagged, "{}".into()]),
        });
        let ops = AwsOrphans {
            runner: fake.clone(),
            profile: Some("ozbox".into()),
        };
        ops.delete(&item("vol-a", "volume")).unwrap();
        let calls = fake.calls.lock().unwrap();
        assert_eq!(
            calls[0][..2],
            ["ec2".to_string(), "describe-volumes".to_string()]
        );
        assert_eq!(
            calls[1][..2],
            ["ec2".to_string(), "delete-volume".to_string()]
        );
        assert!(calls[1].iter().any(|a| a == "vol-a"));
        drop(calls);

        let untagged = json!({"Volumes": [{"VolumeId": "vol-a", "State": "available", "Tags": tags(&[("Name","ozbox-x")])}]}).to_string();
        let fake = Arc::new(Fake {
            calls: Mutex::new(vec![]),
            answers: Mutex::new(vec![untagged]),
        });
        let e = AwsOrphans {
            runner: fake.clone(),
            profile: None,
        }
        .delete(&item("vol-a", "volume"))
        .unwrap_err();
        assert!(e.contains("vol-a"));
        assert_eq!(fake.calls.lock().unwrap().len(), 1, "nothing was deleted");

        let attached = json!({"Volumes": [{"VolumeId": "vol-a", "State": "in-use", "Attachments": [{"InstanceId": "i-1"}], "Tags": tags(&[("ozbox-managed","true")])}]}).to_string();
        let fake = Arc::new(Fake {
            calls: Mutex::new(vec![]),
            answers: Mutex::new(vec![attached]),
        });
        assert!(AwsOrphans {
            runner: fake.clone(),
            profile: None
        }
        .delete(&item("vol-a", "volume"))
        .is_err());
        assert_eq!(fake.calls.lock().unwrap().len(), 1);
    }

    #[test]
    fn a_snapshot_an_image_uses_is_not_deleted_and_an_image_or_untagged_item_never_is() {
        let snap = json!({"Snapshots": [{"SnapshotId": "snap-a", "VolumeSize": 1, "Tags": tags(&[("ozbox-managed","true")])}]}).to_string();
        let used = json!({"Images": [{"ImageId": "ami-1"}]}).to_string();
        let fake = Arc::new(Fake {
            calls: Mutex::new(vec![]),
            answers: Mutex::new(vec![snap, used]),
        });
        assert!(AwsOrphans {
            runner: fake.clone(),
            profile: None
        }
        .delete(&item("snap-a", "snapshot"))
        .is_err());
        assert_eq!(
            fake.calls.lock().unwrap().len(),
            2,
            "looked, did not delete"
        );
        let fake = Arc::new(Fake {
            calls: Mutex::new(vec![]),
            answers: Mutex::new(vec![]),
        });
        let ops = AwsOrphans {
            runner: fake.clone(),
            profile: None,
        };
        assert!(ops.delete(&item("ami-1", "image")).is_err());
        let mut not_ours = item("vol-z", "volume");
        not_ours.deletable = false;
        assert!(ops.delete(&not_ours).is_err());
        assert!(fake.calls.lock().unwrap().is_empty(), "no call was made");
    }

    #[test]
    fn a_scan_with_no_region_says_so_and_never_reads_as_nothing_found() {
        let fake = Arc::new(Fake {
            calls: Mutex::new(vec![]),
            answers: Mutex::new(vec![]),
        });
        let scan = AwsOrphans {
            runner: fake.clone(),
            profile: None,
        }
        .scan(&[], None, 3);
        assert!(scan.items.is_empty());
        assert!(
            scan.error
                .as_deref()
                .is_some_and(|e| e.contains("No region")),
            "{:?}",
            scan.error
        );
        assert!(fake.calls.lock().unwrap().is_empty());
    }

    #[test]
    fn a_scan_asks_every_region_with_read_verbs_only_and_reports_a_failure_without_losing_the_rest()
    {
        let empty_res = json!({"Reservations": []}).to_string();
        let answers = vec![
            empty_res,
            json!({"Volumes": []}).to_string(),
            json!({"Snapshots": []}).to_string(),
            json!({"Images": []}).to_string(),
        ];
        let fake = Arc::new(Fake {
            calls: Mutex::new(vec![]),
            answers: Mutex::new(answers),
        });
        let scan = AwsOrphans {
            runner: fake.clone(),
            profile: None,
        }
        .scan(&["us-east-1".to_string()], None, 9);
        assert_eq!(scan.scanned_at_ms, 9);
        assert!(scan.error.is_none() && scan.items.is_empty());
        let calls = fake.calls.lock().unwrap();
        assert_eq!(calls.len(), 4);
        assert!(calls.iter().all(|c| c[1].starts_with("describe-")));
        assert!(calls.iter().all(|c| c.iter().any(|a| a == "us-east-1")));
    }
}
