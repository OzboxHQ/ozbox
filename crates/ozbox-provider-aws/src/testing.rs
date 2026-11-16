//! A stateful stand-in for the `aws` CLI and `tofu`: it answers the exact commands the adapter runs, from an
//! in-memory account, and records every call so tests can assert argv.

use std::collections::BTreeMap;
use std::sync::Mutex;

use ozbox_core::{BoxName, BoxState, CommandRunner, CommandSpec, Error, Output, Result};
use serde_json::{json, Value};

struct Inst {
    id: String,
    itype: String,
    image: String,
    state: String,
    tags: BTreeMap<String, String>,
    /// (device, volume id); the first is the root device.
    vols: Vec<(String, String)>,
}

struct Vol {
    id: String,
    size: u32,
    tags: BTreeMap<String, String>,
    /// The snapshot the volume was made from.
    snapshot: Option<String>,
}

struct Img {
    id: String,
    arch: String,
    state: String,
    created: String,
    tags: BTreeMap<String, String>,
    /// The account that owns it: `None` is the caller's own account. AWS shows tags only to the owner.
    owner: Option<String>,
    name: String,
}

struct Snap {
    id: String,
    start: String,
    tags: BTreeMap<String, String>,
    size: u32,
    state: String,
}

#[derive(Default)]
struct Account {
    next: u64,
    instances: Vec<Inst>,
    volumes: Vec<Vol>,
    snapshots: Vec<Snap>,
    calls: Vec<CommandSpec>,
    workspace: String,
    /// The vCPU quota the fake account reports; `None` = a roomy default. `quota_denied` simulates a missing permission.
    quota: Option<f64>,
    quota_denied: bool,
    outputs: BTreeMap<String, String>,
    images: Vec<Img>,
    /// Answer `--owners` as if it were not there (what the client must survive: its own owner check is the defence).
    ignore_owners: bool,
    /// OpenTofu workspaces that exist (a box this fake created).
    workspaces: Vec<String>,
    /// `tofu plan -out=<file>` results: the variables the plan was made with.
    plans: BTreeMap<String, BTreeMap<String, String>>,
    /// Make the next `tofu apply` of a saved plan fail before it changes anything (an interrupted replace).
    fail_next_replace_apply: bool,
    /// The secrets key the box's instance role may use, by box name (what the account's fleet-key policy, attached by the module, allows).
    role_grants: BTreeMap<String, String>,
    /// Make an in-place plan also replace the machine (a module or state that does not match the box).
    inplace_replaces_instance: bool,
    /// Make `tofu plan -replace` report the /work volume as replaced too.
    plan_replaces_volume: bool,
    /// Make a plan that replaces the /work volume (the restore preview) also replace the machine.
    plan_replaces_instance: bool,
    /// Make the plan made AFTER the old /work volume left the state also replace the machine.
    plan_replaces_instance_after_rm: bool,
    /// What the box's state says the `/work` volume and its attachment are, by workspace. `Some(None)` is removed;
    /// absent means they are the disk the machine has.
    tf_volume: BTreeMap<String, Option<String>>,
    tf_attach: BTreeMap<String, Option<String>>,
    /// Make a plan report the /work volume as newly created (OpenTofu's state lost it).
    plan_creates_volume: bool,
    /// Make the next N creates of a machine fail the way an account refuses one (after the old machine, if any, was
    /// already removed): the interrupted-replacement case.
    create_failures: u32,
    create_failure_message: String,
    /// Published releases: version to the manifest the image workflow would have signed.
    releases: BTreeMap<String, String>,
    /// Make `cosign verify-blob` refuse the signature.
    cosign_refuses: bool,
    /// Report system disks (and so their snapshots) as not encrypted.
    plain_system_disks: bool,
    /// Calls that fail, by what they are: `create-snapshot`, or `describe-snapshots` read by id (the look at a snapshot just made).
    failing: Vec<String>,
    /// The state a new snapshot reports instead of `completed` (`pending` forever, or `error`).
    new_snapshot_state: Option<String>,
    /// What a copy of an old system disk reports about its encryption instead of the truth: `(Encrypted, KmsKeyId)`, either left
    /// out of the answer when `None`.
    copy_encryption: Option<(Option<bool>, Option<String>)>,
    /// What a system disk reports about its key instead of the truth: left out of the answer when `None`.
    system_disk_encryption: Option<(Option<bool>, Option<String>)>,
}

#[derive(Default)]
pub struct FakeAws {
    a: Mutex<Account>,
}

fn ok(stdout: String) -> Output {
    Output {
        status: Some(0),
        stdout,
        stderr: String::new(),
    }
}

fn fail(msg: &str) -> Output {
    Output {
        status: Some(254),
        stdout: String::new(),
        stderr: msg.to_string(),
    }
}

fn flag<'a>(args: &'a [String], name: &str) -> Option<&'a str> {
    args.iter()
        .position(|a| a == name)
        .and_then(|i| args.get(i + 1))
        .map(String::as_str)
}

/// The values after `name` up to the next `--option` (the aws CLI takes several tags after one `--tags`).
fn values_after<'a>(args: &'a [String], name: &str) -> Vec<&'a str> {
    args.iter()
        .position(|a| a == name)
        .map(|i| {
            args[i + 1..]
                .iter()
                .take_while(|a| !a.starts_with("--"))
                .map(String::as_str)
                .collect()
        })
        .unwrap_or_default()
}

/// `--filters Name=tag:k,Values=v ...` as `(name, value)` pairs.
fn filters(args: &[String]) -> Vec<(String, String)> {
    values_after(args, "--filters")
        .into_iter()
        .filter_map(|f| {
            let (n, v) = f.split_once(",Values=")?;
            Some((n.trim_start_matches("Name=").to_string(), v.to_string()))
        })
        .collect()
}

fn tags_json(t: &BTreeMap<String, String>) -> Value {
    Value::Array(
        t.iter()
            .map(|(k, v)| json!({"Key": k, "Value": v}))
            .collect(),
    )
}

/// `{Key=a,Value=b},{Key=c,Value=d}` inside `Tags=[...]`.
fn parse_tag_spec(spec: &str) -> BTreeMap<String, String> {
    let mut out = BTreeMap::new();
    let inner = spec
        .split_once("Tags=[")
        .map_or("", |(_, r)| r)
        .trim_end_matches(']');
    for item in inner.split("},{") {
        let item = item.trim_matches(|c| c == '{' || c == '}');
        if let Some((k, v)) = item.split_once(",Value=") {
            out.insert(k.trim_start_matches("Key=").to_string(), v.to_string());
        }
    }
    out
}

fn parse_vars(args: &[String]) -> BTreeMap<String, String> {
    let mut out = BTreeMap::new();
    let mut it = args.iter();
    while let Some(a) = it.next() {
        if a == "-var" {
            if let Some((k, v)) = it.next().and_then(|kv| kv.split_once('=')) {
                out.insert(k.to_string(), v.to_string());
            }
        }
    }
    out
}

/// A new machine's tags, as the module sets them: the box's tags and, when the program passed one, the first-boot hash
/// it was made with (on the machine only, set at creation).
fn machine_tags(
    mut tags: BTreeMap<String, String>,
    vars: &BTreeMap<String, String>,
) -> BTreeMap<String, String> {
    if let Some(fb) = vars.get("first_boot_sha256").filter(|v| !v.is_empty()) {
        tags.insert("ozbox-first-boot".into(), fb.clone());
    }
    tags
}

fn parse_labels(raw: &str) -> BTreeMap<String, String> {
    let inner = raw.trim_start_matches('{').trim_end_matches('}');
    inner
        .split(',')
        .filter_map(|p| p.split_once("\"=\""))
        .map(|(k, v)| {
            (
                k.trim_matches('"').to_string(),
                v.trim_matches('"').to_string(),
            )
        })
        .collect()
}

/// What the box's state says `/work` is (`attach`: its attachment), when it still holds it.
fn tf_work(a: &Account, attach: bool) -> Option<String> {
    let ws = a.workspace.clone();
    let map = if attach { &a.tf_attach } else { &a.tf_volume };
    if let Some(v) = map.get(&ws) {
        return v.clone();
    }
    // Not changed by a restore: the disk the machine has (or, with no machine, a disk the state holds all the same).
    Some(
        a.instances
            .iter()
            .find(|i| i.tags.get("ozbox-box") == Some(&ws) && i.state != "terminated")
            .and_then(|i| i.vols.get(1).map(|v| v.1.clone()))
            .unwrap_or_else(|| "vol-in-state".into()),
    )
}

impl FakeAws {
    /// An account that already owns a few images: the one boxes are created from, a newer one, one for another
    /// architecture, one still being built, and one that is not an Oz image.
    pub fn new() -> Self {
        let fake = Self::default();
        fake.add_image(
            "ami-0123456789abcdef0",
            "x86_64",
            "available",
            "2026-10-01T00:00:00.000Z",
            Some("2026.10.0"),
        );
        fake.add_image(
            "ami-0fedcba9876543210",
            "x86_64",
            "available",
            "2026-11-01T00:00:00.000Z",
            Some("2026.11.0"),
        );
        fake.add_image(
            "ami-0aaaaaaaaaaaaaaaa",
            "arm64",
            "available",
            "2026-11-02T00:00:00.000Z",
            Some("2026.11.0"),
        );
        fake.add_image(
            "ami-0bbbbbbbbbbbbbbbb",
            "x86_64",
            "pending",
            "2026-11-03T00:00:00.000Z",
            Some("2026.12.0"),
        );
        fake.add_image(
            "ami-0cccccccccccccccc",
            "x86_64",
            "available",
            "2026-11-04T00:00:00.000Z",
            None,
        );
        fake
    }

    fn with<T>(&self, f: impl FnOnce(&mut Account) -> T) -> T {
        match self.a.lock() {
            Ok(mut g) => f(&mut g),
            Err(p) => f(&mut p.into_inner()),
        }
    }

    pub fn calls(&self) -> Vec<CommandSpec> {
        self.with(|a| a.calls.clone())
    }

    pub fn set_vcpu_quota(&self, q: f64) {
        self.with(|a| a.quota = Some(q));
    }

    pub fn deny_quota_reads(&self) {
        self.with(|a| a.quota_denied = true);
    }

    /// An image this account owns. `release` becomes the `ozbox-image` tag when given.
    pub fn add_image(
        &self,
        id: &str,
        arch: &str,
        state: &str,
        created: &str,
        release: Option<&str>,
    ) {
        let mut tags = BTreeMap::new();
        if let Some(r) = release {
            tags.insert("ozbox-image".to_string(), r.to_string());
            tags.insert("ozbox-managed".to_string(), "true".to_string());
        }
        self.with(|a| {
            a.images.push(Img {
                id: id.to_string(),
                arch: arch.to_string(),
                state: state.to_string(),
                created: created.to_string(),
                tags,
                owner: None,
                name: format!("ozbox-{}", release.unwrap_or("other")),
            });
        });
    }

    /// An image owned by another account (a public one): its tags are not visible to the caller, only its name.
    pub fn add_public_image(&self, id: &str, owner: &str, name: &str, created: &str) {
        self.with(|a| {
            a.images.push(Img {
                id: id.to_string(),
                arch: "x86_64".to_string(),
                state: "available".to_string(),
                created: created.to_string(),
                tags: BTreeMap::new(),
                owner: Some(owner.to_string()),
                name: name.to_string(),
            });
        });
    }

    /// Make `describe-images` ignore `--owners`, so images of other accounts come back among the publisher's.
    pub fn ignore_owner_filter(&self) {
        self.with(|a| a.ignore_owners = true);
    }

    /// Make the caller's own account's images disappear (so only public ones are left).
    pub fn remove_own_images(&self) {
        self.with(|a| a.images.retain(|i| i.owner.is_some()));
    }

    /// Forget the OpenTofu workspace of a box (its state is gone, the machine is not).
    pub fn forget_workspace(&self, name: &str) {
        self.with(|a| a.workspaces.retain(|w| w != name));
    }

    pub fn remove_images(&self) {
        self.with(|a| a.images.clear());
    }

    pub fn fail_next_replace_apply(&self) {
        self.with(|a| a.fail_next_replace_apply = true);
    }

    pub fn plan_replaces_volume(&self) {
        self.with(|a| a.plan_replaces_volume = true);
    }

    pub fn plan_replaces_instance(&self) {
        self.with(|a| a.plan_replaces_instance = true);
    }

    /// The secrets key the box's instance role may use (what its module policy holds), if any.
    pub fn role_grant(&self, name: &BoxName) -> Option<String> {
        self.with(|a| a.role_grants.get(name.as_str()).cloned())
    }

    /// Make an in-place plan also replace the machine (the module or state does not match the box).
    pub fn inplace_replaces_instance(&self) {
        self.with(|a| a.inplace_replaces_instance = true);
    }

    pub fn plan_replaces_instance_after_rm(&self) {
        self.with(|a| a.plan_replaces_instance_after_rm = true);
    }

    /// Make the system disk of a box the way a box made by an earlier version has it: no tags at all.
    pub fn untag_root_volume(&self, name: &BoxName) {
        self.with(|a| {
            let root = a
                .instances
                .iter()
                .find(|i| {
                    i.tags.get("ozbox-box").map(String::as_str) == Some(name.as_str())
                        && i.state != "terminated"
                })
                .and_then(|i| i.vols.first().map(|(_, v)| v.clone()));
            if let Some(v) = a.volumes.iter_mut().find(|v| Some(&v.id) == root.as_ref()) {
                v.tags.clear();
            }
        });
    }

    /// What an account administrator's `create-tags` does: the disk gets its first tags.
    pub fn admin_tags_root_volume(&self, name: &BoxName) {
        self.with(|a| {
            let root = a
                .instances
                .iter()
                .find(|i| {
                    i.tags.get("ozbox-box").map(String::as_str) == Some(name.as_str())
                        && i.state != "terminated"
                })
                .and_then(|i| i.vols.first().map(|(_, v)| v.clone()));
            if let Some(v) = a.volumes.iter_mut().find(|v| Some(&v.id) == root.as_ref()) {
                v.tags.insert("ozbox-managed".into(), "true".into());
                v.tags.insert("ozbox-box".into(), name.as_str().to_string());
            }
        });
    }

    /// The tags on the system disk of a box.
    pub fn root_volume_tags(&self, name: &BoxName) -> BTreeMap<String, String> {
        self.with(|a| {
            let root = a
                .instances
                .iter()
                .find(|i| {
                    i.tags.get("ozbox-box").map(String::as_str) == Some(name.as_str())
                        && i.state != "terminated"
                })
                .and_then(|i| i.vols.first().map(|(_, v)| v.clone()));
            a.volumes
                .iter()
                .find(|v| Some(&v.id) == root.as_ref())
                .map(|v| v.tags.clone())
                .unwrap_or_default()
        })
    }

    /// The volumes of a box with their role tag and the snapshot each was made from: `(id, role, snapshot)`.
    pub fn volumes_of(&self, name: &BoxName) -> Vec<(String, String, Option<String>)> {
        self.with(|a| {
            a.volumes
                .iter()
                .filter(|v| v.tags.get("ozbox-box").map(String::as_str) == Some(name.as_str()))
                .map(|v| {
                    (
                        v.id.clone(),
                        v.tags.get("ozbox-role").cloned().unwrap_or_default(),
                        v.snapshot.clone(),
                    )
                })
                .collect()
        })
    }

    pub fn plan_creates_volume(&self) {
        self.with(|a| a.plan_creates_volume = true);
    }

    /// Set what the account says about a snapshot (`pending`, `error`, `completed`).
    pub fn set_snapshot_state(&self, id: &str, state: &str) {
        self.with(|a| {
            if let Some(s) = a.snapshots.iter_mut().find(|s| s.id == id) {
                s.state = state.to_string();
            }
        });
    }

    /// A snapshot Oz Box did not make (tagged for nobody), which it must never delete.
    pub fn add_foreign_snapshot(&self, id: &str) {
        self.with(|a| {
            a.snapshots.push(Snap {
                id: id.to_string(),
                start: "2025-12-31T00:00:00+00:00".into(),
                tags: BTreeMap::new(),
                size: 8,
                state: "completed".into(),
            });
        });
    }

    /// The next `n` creations of a machine fail with `message` (a replacement has removed the old machine by then).
    pub fn fail_creates(&self, n: u32, message: &str) {
        self.with(|a| {
            a.create_failures = n;
            a.create_failure_message = message.to_string();
        });
    }

    /// Publish the signed manifest of `version` listing, for `region`, the images this account tags with that release.
    pub fn publish_release(&self, version: &str, region: &str) {
        self.with(|a| {
            let images: Vec<Value> = a
                .images
                .iter()
                .filter(|i| i.tags.get("ozbox-image").map(String::as_str) == Some(version))
                .map(|i| json!({"arch": i.arch, "amis": {region: i.id}}))
                .collect();
            let manifest = json!({"version": version, "images": images});
            a.releases.insert(version.to_string(), manifest.to_string());
        });
    }

    /// A signed manifest for `version` that lists exactly these image ids for `region` (public images carry no tags in
    /// this account, so `publish_release` cannot find them).
    pub fn publish_release_of(&self, version: &str, region: &str, ids: &[&str]) {
        self.with(|a| {
            let images: Vec<Value> = ids
                .iter()
                .map(|id| json!({"arch": "amd64", "amis": {region: id}}))
                .collect();
            let manifest = json!({"version": version, "images": images});
            a.releases.insert(version.to_string(), manifest.to_string());
        });
    }

    /// The release `serve_as` is served a manifest that says it is for `manifest_version` (an old manifest swapped in), listing
    /// these ids, with the signed `prerelease` field if given.
    pub fn publish_release_with(
        &self,
        serve_as: &str,
        manifest_version: &str,
        region: &str,
        ids: &[&str],
        prerelease: Option<bool>,
    ) {
        self.with(|a| {
            let images: Vec<Value> = ids
                .iter()
                .map(|id| json!({"arch": "amd64", "amis": {region: id}}))
                .collect();
            let mut manifest = json!({"version": manifest_version, "images": images});
            if let Some(p) = prerelease {
                manifest["prerelease"] = json!(p);
            }
            a.releases
                .insert(serve_as.to_string(), manifest.to_string());
        });
    }

    /// `cosign verify-blob` refuses what it is given.
    pub fn refuse_signatures(&self) {
        self.with(|a| a.cosign_refuses = true);
    }

    /// How many machines this account runs for a box (any state but terminated).
    pub fn machines_of(&self, name: &BoxName) -> usize {
        self.with(|a| {
            a.instances
                .iter()
                .filter(|i| {
                    i.tags.get("ozbox-box").map(String::as_str) == Some(name.as_str())
                        && i.state != "terminated"
                })
                .count()
        })
    }

    /// Leave a box the way an upgrade does when the old machine was removed and the new one could not be created:
    /// no machine, the /work volume kept and marked with the image and the machine type.
    pub fn strand_upgrade(&self, name: &BoxName, image: &str) -> Result<()> {
        self.with(|a| {
            let at = a
                .instances
                .iter()
                .position(|i| i.tags.get("ozbox-box").map(String::as_str) == Some(name.as_str()))
                .ok_or_else(|| Error::NotFound(name.to_string()))?;
            let old = a.instances.remove(at);
            let root = old.vols.first().map(|v| v.1.clone()).unwrap_or_default();
            a.volumes.retain(|v| v.id != root);
            if let Some(w) = old.vols.get(1).map(|v| v.1.clone()) {
                if let Some(v) = a.volumes.iter_mut().find(|v| v.id == w) {
                    v.tags.insert("ozbox-upgrade-to".into(), image.to_string());
                    v.tags
                        .insert("ozbox-upgrade-machine".into(), old.itype.clone());
                }
            }
            Ok(())
        })
    }

    /// The tags on a volume.
    pub fn volume_tags(&self, volume_id: &str) -> BTreeMap<String, String> {
        self.with(|a| {
            a.volumes
                .iter()
                .find(|v| v.id == volume_id)
                .map(|v| v.tags.clone())
                .unwrap_or_default()
        })
    }

    /// Leave a box the way an upgrade interrupted after the stop leaves it: marked on the volume, machine stopped.
    pub fn interrupt_upgrade(&self, name: &BoxName, image: &str) -> Result<()> {
        self.with(|a| {
            let i = a
                .instances
                .iter_mut()
                .find(|i| i.tags.get("ozbox-box").map(String::as_str) == Some(name.as_str()))
                .ok_or_else(|| Error::NotFound(name.to_string()))?;
            i.state = "stopped".into();
            let work = i.vols.get(1).map(|v| v.1.clone());
            if let Some(w) = work {
                if let Some(v) = a.volumes.iter_mut().find(|v| v.id == w) {
                    v.tags.insert("ozbox-upgrade-to".into(), image.to_string());
                }
            }
            Ok(())
        })
    }

    /// Report every system disk as not encrypted (a box made outside Oz Box's module).
    pub fn unencrypted_system_disks(&self) {
        self.with(|a| a.plain_system_disks = true);
    }

    /// Make one kind of call fail: `create-snapshot`, `delete-snapshot`, or `describe-snapshots` when it asks for snapshots by id
    /// (what an upgrade does to look at the copy it just made).
    pub fn fail_calls(&self, what: &str) {
        let what = what.to_string();
        self.with(|a| a.failing.push(what));
    }

    /// Every snapshot made from now on reports this state instead of `completed` (`pending` never finishes).
    pub fn new_snapshots_report(&self, state: &str) {
        let state = state.to_string();
        self.with(|a| a.new_snapshot_state = Some(state));
    }

    /// What a copy of a system disk says about its encryption, in place of the truth; a `None` is left out of the answer.
    pub fn copies_report_encryption(&self, encrypted: Option<bool>, kms: Option<&str>) {
        let kms = kms.map(str::to_string);
        self.with(|a| a.copy_encryption = Some((encrypted, kms)));
    }

    /// What a system disk says about its encryption, in place of the truth; a `None` is left out of the answer.
    pub fn system_disks_report_encryption(&self, encrypted: Option<bool>, kms: Option<&str>) {
        let kms = kms.map(str::to_string);
        self.with(|a| a.system_disk_encryption = Some((encrypted, kms)));
    }

    /// Take the `ozbox-managed` tag off a box's system disk (what a box from before the module tagged it would look like).
    pub fn untag_system_disk(&self, name: &BoxName) {
        self.with(|a| {
            for v in a.volumes.iter_mut().filter(|v| {
                v.tags.get("ozbox-box").map(String::as_str) == Some(name.as_str())
                    && v.tags.get("ozbox-role").map(String::as_str) == Some("root")
            }) {
                v.tags.remove("ozbox-managed");
            }
        });
    }

    /// The ids and tags of the snapshots of a box's system disk that an upgrade kept, oldest first.
    pub fn system_disk_snapshots(&self, name: &BoxName) -> Vec<(String, BTreeMap<String, String>)> {
        self.with(|a| {
            a.snapshots
                .iter()
                .filter(|s| {
                    s.tags.get("ozbox-box").map(String::as_str) == Some(name.as_str())
                        && s.tags.get("ozbox-purpose").map(String::as_str)
                            == Some("pre-upgrade-root")
                })
                .map(|s| (s.id.clone(), s.tags.clone()))
                .collect()
        })
    }

    pub fn clear_calls(&self) {
        self.with(|a| a.calls.clear());
    }

    /// The `/work` volume of a box, found by its tags, whether or not a machine is attached.
    pub fn work_volume_of_box(&self, name: &BoxName) -> Result<String> {
        self.with(|a| {
            a.volumes
                .iter()
                .find(|v| {
                    v.tags.get("ozbox-box").map(String::as_str) == Some(name.as_str())
                        && v.tags.get("ozbox-role").map(String::as_str) == Some("work")
                })
                .map(|v| v.id.clone())
                .ok_or_else(|| Error::NotFound(name.to_string()))
        })
    }

    /// The non-root volume of an instance.
    pub fn work_volume_of(&self, instance_id: &str) -> Option<String> {
        self.with(|a| {
            a.instances
                .iter()
                .find(|i| i.id == instance_id)
                .and_then(|i| i.vols.get(1).map(|v| v.1.clone()))
        })
    }

    pub fn force_state(&self, name: &BoxName, state: BoxState) -> Result<()> {
        let s = match state {
            BoxState::Running => "running",
            BoxState::Paused => "stopped",
            BoxState::Pausing => "stopping",
            BoxState::Resuming | BoxState::Creating => "pending",
            BoxState::Destroying => "shutting-down",
            BoxState::Resizing | BoxState::Unknown => "rebooting",
            BoxState::InstanceMissing => {
                return Err(Error::Provider(
                    "a missing machine is made with strand_upgrade, not a forced state".into(),
                ))
            }
        };
        self.with(|a| {
            let i = a
                .instances
                .iter_mut()
                .find(|i| i.tags.get("ozbox-box").map(String::as_str) == Some(name.as_str()))
                .ok_or_else(|| Error::NotFound(name.to_string()))?;
            i.state = s.to_string();
            Ok(())
        })
    }

    fn vcpus(t: &str) -> u32 {
        match t {
            "m7i.xlarge" => 4,
            "m7i.2xlarge" | "r7i.2xlarge" | "g6.2xlarge" => 8,
            "m7i.4xlarge" => 16,
            "m7i.8xlarge" => 32,
            _ => 2,
        }
    }

    fn aws(a: &mut Account, args: &[String]) -> Output {
        if args.first().map(String::as_str) == Some("service-quotas") {
            return if a.quota_denied {
                fail("AccessDeniedException: not authorized to perform servicequotas:GetServiceQuota")
            } else {
                ok(json!({"Quota": {"Value": a.quota.unwrap_or(256.0)}}).to_string())
            };
        }
        let Some(sub) = args.get(1).map(String::as_str) else {
            return fail("no subcommand");
        };
        match sub {
            "describe-instances" => {
                let by_id = flag(args, "--instance-ids");
                let region = flag(args, "--region");
                let list: Vec<Value> = a
                    .instances
                    .iter()
                    .filter(|i| by_id.map_or(i.state != "terminated", |id| i.id == id))
                    .filter(|i| {
                        region.is_none_or(|r| {
                            i.tags.get("ozbox-region").map(String::as_str) == Some(r)
                        })
                    })
                    .map(|i| {
                        let maps: Vec<Value> = i
                            .vols
                            .iter()
                            .map(|(d, v)| json!({"DeviceName": d, "Ebs": {"VolumeId": v}}))
                            .collect();
                        let mut tags = i.tags.clone();
                        tags.insert("Name".into(), format!("ozbox-{}", i.id));
                        json!({
                            "InstanceId": i.id,
                            "InstanceType": i.itype,
                            "ImageId": i.image,
                            "State": {"Name": i.state},
                            "LaunchTime": "2026-01-01T00:00:00+00:00",
                            "Tags": tags_json(&tags),
                            "RootDeviceName": i.vols.first().map(|v| v.0.clone()),
                            "BlockDeviceMappings": maps,
                        })
                    })
                    .collect();
                ok(json!({"Reservations": [{"Instances": list}]}).to_string())
            }
            "describe-images" => {
                let by_id = flag(args, "--image-ids");
                if let Some(id) = by_id {
                    if !a.images.iter().any(|i| i.id == id) {
                        return fail("InvalidAMIID.NotFound: The image id does not exist");
                    }
                }
                let latest_query = args.iter().any(|x| x == "Name=tag-key,Values=ozbox-image");
                let owners = flag(args, "--owners").filter(|_| !a.ignore_owners);
                let list: Vec<Value> = a
                    .images
                    .iter()
                    .filter(|i| by_id.is_none_or(|id| i.id == id))
                    .filter(|i| match owners {
                        None => true,
                        Some("self") => i.owner.is_none(),
                        Some(o) => i.owner.as_deref() == Some(o),
                    })
                    .filter(|i| {
                        !args.iter().any(|x| x == "Name=state,Values=available")
                            || i.state == "available"
                    })
                    .filter(|i| {
                        !args.iter().any(|x| x == "Name=architecture,Values=x86_64")
                            || i.arch == "x86_64"
                    })
                    .filter(|i| {
                        !args.iter().any(|x| x == "Name=name,Values=ozbox-*")
                            || i.name.starts_with("ozbox-")
                    })
                    .filter(|i| {
                        !latest_query
                            || (i.state == "available"
                                && i.arch == "x86_64"
                                && i.tags.contains_key("ozbox-image")
                                && i.tags.get("ozbox-managed").map(String::as_str) == Some("true"))
                    })
                    .map(|i| {
                        json!({
                            "ImageId": i.id,
                            "Name": i.name,
                            "OwnerId": i.owner.clone().unwrap_or_else(|| "123456789012".to_string()),
                            "Architecture": i.arch,
                            "State": i.state,
                            "CreationDate": i.created,
                            "Tags": tags_json(&i.tags),
                        })
                    })
                    .collect();
                ok(json!({"Images": list}).to_string())
            }
            "describe-instance-types" => {
                let at = args
                    .iter()
                    .position(|x| x == "--instance-types")
                    .map_or(args.len(), |i| i + 1);
                let list: Vec<Value> = args[at..]
                    .iter()
                    .take_while(|x| !x.starts_with("--"))
                    .map(|t| json!({"InstanceType": t, "VCpuInfo": {"DefaultVCpus": Self::vcpus(t)}}))
                    .collect();
                ok(json!({"InstanceTypes": list}).to_string())
            }
            "describe-volumes" => {
                let wanted = filters(args);
                let wanted_ids = values_after(args, "--volume-ids");
                let plain = a.plain_system_disks;
                let in_use = |id: &str| {
                    a.instances
                        .iter()
                        .any(|i| i.state != "terminated" && i.vols.iter().any(|v| v.1 == id))
                };
                let list: Vec<Value> = a
                    .volumes
                    .iter()
                    .filter(|v| wanted_ids.is_empty() || wanted_ids.contains(&v.id.as_str()))
                    .filter(|v| {
                        wanted.iter().all(|(k, val)| match k.strip_prefix("tag:") {
                            Some(t) => v.tags.get(t).map(String::as_str) == Some(val.as_str()),
                            None => k != "status" || (val == "available") != in_use(&v.id),
                        })
                    })
                    .map(|v| {
                        let root = v.tags.get("ozbox-role").map(String::as_str) == Some("root");
                        let mut j = json!({
                            "VolumeId": v.id,
                            "Size": v.size,
                            "State": if in_use(&v.id) { "in-use" } else { "available" },
                            "SnapshotId": v.snapshot,
                            "Encrypted": !(plain && root),
                            "KmsKeyId": root.then_some("arn:aws:kms:us-east-1:123456789012:key/fake"),
                            "Tags": tags_json(&v.tags),
                        });
                        if let (Some((enc, kms)), true) = (&a.system_disk_encryption, root) {
                            match enc {
                                Some(e) => j["Encrypted"] = json!(e),
                                None => {
                                    j.as_object_mut().map(|o| o.remove("Encrypted"));
                                }
                            }
                            match kms {
                                Some(k) => j["KmsKeyId"] = json!(k),
                                None => {
                                    j.as_object_mut().map(|o| o.remove("KmsKeyId"));
                                }
                            }
                        }
                        j
                    })
                    .collect();
                ok(json!({"Volumes": list}).to_string())
            }
            "describe-snapshots" => {
                // The filters the adapter uses: a tag's value, and specific ids.
                let wanted_ids = values_after(args, "--snapshot-ids");
                if !wanted_ids.is_empty() && a.failing.iter().any(|f| f == "describe-snapshots") {
                    return fail("InternalError: could not read the snapshot");
                }
                let tag_filters: Vec<(String, String)> = values_after(args, "--filters")
                    .iter()
                    .filter_map(|f| {
                        let key = f.strip_prefix("Name=tag:")?;
                        let (k, v) = key.split_once(",Values=")?;
                        Some((k.to_string(), v.to_string()))
                    })
                    .collect();
                let list: Vec<Value> = a
                    .snapshots
                    .iter()
                    .filter(|s| wanted_ids.is_empty() || wanted_ids.contains(&s.id.as_str()))
                    .filter(|s| {
                        tag_filters
                            .iter()
                            .all(|(k, v)| s.tags.get(k).map(String::as_str) == Some(v.as_str()))
                    })
                    .map(|s| {
                        // a snapshot of a disk is encrypted when the disk is
                        let plain_disk = a.plain_system_disks
                            && s.tags.get("ozbox-purpose").map(String::as_str) == Some("pre-upgrade-root");
                        let mut v = json!({"SnapshotId": s.id, "StartTime": s.start, "State": s.state, "VolumeSize": s.size, "Encrypted": !plain_disk, "KmsKeyId": s.tags.contains_key("ozbox-purpose").then_some("arn:aws:kms:us-east-1:123456789012:key/fake"), "Tags": tags_json(&s.tags)});
                        if let (Some((enc, kms)), true) = (&a.copy_encryption, s.tags.contains_key("ozbox-purpose")) {
                            match enc {
                                Some(e) => v["Encrypted"] = json!(e),
                                None => {
                                    v.as_object_mut().map(|o| o.remove("Encrypted"));
                                }
                            }
                            match kms {
                                Some(k) => v["KmsKeyId"] = json!(k),
                                None => {
                                    v.as_object_mut().map(|o| o.remove("KmsKeyId"));
                                }
                            }
                        }
                        v
                    })
                    .collect();
                ok(json!({"Snapshots": list}).to_string())
            }
            "delete-snapshot" => {
                if a.failing.iter().any(|f| f == "delete-snapshot") {
                    return fail("InternalError: could not delete the snapshot");
                }
                let Some(id) = flag(args, "--snapshot-id") else {
                    return fail("--snapshot-id required");
                };
                let before = a.snapshots.len();
                a.snapshots.retain(|s| s.id != id);
                if a.snapshots.len() == before {
                    return fail("InvalidSnapshot.NotFound");
                }
                ok("{}".into())
            }
            "stop-instances" | "start-instances" => {
                let Some(id) = flag(args, "--instance-ids") else {
                    return fail("--instance-ids required");
                };
                let Some(i) = a.instances.iter_mut().find(|i| i.id == id) else {
                    return fail("InvalidInstanceID.NotFound");
                };
                i.state = if sub == "stop-instances" {
                    "stopped"
                } else {
                    "running"
                }
                .into();
                ok("{}".into())
            }
            "wait" => ok(String::new()),
            "create-tags" | "delete-tags" => {
                let (Some(id), specs) = (flag(args, "--resources"), values_after(args, "--tags"))
                else {
                    return fail("missing arguments");
                };
                if specs.is_empty() {
                    return fail("missing arguments");
                }
                let tags = if id.starts_with("vol-") {
                    match a.volumes.iter_mut().find(|v| v.id == id) {
                        Some(vol) => &mut vol.tags,
                        None => return fail("InvalidVolume.NotFound"),
                    }
                } else {
                    match a.instances.iter_mut().find(|i| i.id == id) {
                        Some(i) => &mut i.tags,
                        None => return fail("InvalidInstanceID.NotFound"),
                    }
                };
                for spec in specs {
                    let (k, v) = spec.split_once(",Value=").unwrap_or((spec, ""));
                    let k = k.trim_start_matches("Key=").to_string();
                    if sub == "create-tags" {
                        tags.insert(k, v.to_string());
                    } else {
                        tags.remove(&k);
                    }
                }
                ok(String::new())
            }
            "describe-volumes-modifications" => {
                let Some(id) = flag(args, "--volume-ids") else {
                    return fail("--volume-ids required");
                };
                ok(json!({"VolumesModifications": [{"VolumeId": id, "ModificationState": "optimizing"}]}).to_string())
            }
            "modify-instance-attribute" => {
                let (Some(id), Some(v)) =
                    (flag(args, "--instance-id"), flag(args, "--instance-type"))
                else {
                    return fail("missing arguments");
                };
                let Some(i) = a.instances.iter_mut().find(|i| i.id == id) else {
                    return fail("InvalidInstanceID.NotFound");
                };
                if i.state != "stopped" {
                    return fail("IncorrectInstanceState: the instance must be stopped");
                }
                i.itype = v.trim_start_matches("Value=").to_string();
                ok(String::new())
            }
            "modify-volume" => {
                let (Some(id), Some(size)) = (
                    flag(args, "--volume-id"),
                    flag(args, "--size").and_then(|s| s.parse::<u32>().ok()),
                ) else {
                    return fail("missing arguments");
                };
                let Some(v) = a.volumes.iter_mut().find(|v| v.id == id) else {
                    return fail("InvalidVolume.NotFound");
                };
                if size < v.size {
                    return fail("InvalidParameterValue: a volume cannot shrink");
                }
                v.size = size;
                ok("{}".into())
            }
            "create-snapshot" => {
                if a.failing.iter().any(|f| f == "create-snapshot") {
                    return fail("InternalError: could not create the snapshot");
                }
                let Some(vol) = flag(args, "--volume-id") else {
                    return fail("--volume-id required");
                };
                let Some(size) = a.volumes.iter().find(|v| v.id == vol).map(|v| v.size) else {
                    return fail("InvalidVolume.NotFound");
                };
                a.next += 1;
                let id = format!("snap-{:08x}", a.next);
                let tags = flag(args, "--tag-specifications")
                    .map(parse_tag_spec)
                    .unwrap_or_default();
                a.snapshots.push(Snap {
                    id: id.clone(),
                    start: format!("2026-01-01T00:00:{:02}+00:00", a.next % 60),
                    tags,
                    size,
                    state: a
                        .new_snapshot_state
                        .clone()
                        .unwrap_or_else(|| "completed".into()),
                });
                ok(json!({"SnapshotId": id}).to_string())
            }
            "detach-volume" | "attach-volume" => {
                let (Some(vol), Some(inst)) =
                    (flag(args, "--volume-id"), flag(args, "--instance-id"))
                else {
                    return fail("missing arguments");
                };
                let Some(i) = a.instances.iter_mut().find(|i| i.id == inst) else {
                    return fail("InvalidInstanceID.NotFound");
                };
                if i.state != "stopped" {
                    return fail("IncorrectInstanceState: the instance must be stopped");
                }
                if sub == "detach-volume" {
                    // What the state holds is now no longer derivable from the machine: remember it.
                    let ws = i.tags.get("ozbox-box").cloned().unwrap_or_default();
                    a.tf_volume
                        .entry(ws.clone())
                        .or_insert(Some(vol.to_string()));
                    a.tf_attach.entry(ws).or_insert(Some(vol.to_string()));
                    let before = i.vols.len();
                    i.vols.retain(|v| v.1 != vol);
                    if i.vols.len() == before {
                        return fail("IncorrectState: the volume is not attached");
                    }
                } else {
                    let Some(device) = flag(args, "--device") else {
                        return fail("--device required");
                    };
                    i.vols.push((device.to_string(), vol.to_string()));
                }
                ok("{}".into())
            }
            "delete-volume" => {
                let Some(vol) = flag(args, "--volume-id") else {
                    return fail("--volume-id required");
                };
                let attached = a
                    .instances
                    .iter()
                    .any(|i| i.state != "terminated" && i.vols.iter().any(|v| v.1 == vol));
                if attached {
                    return fail("VolumeInUse");
                }
                let before = a.volumes.len();
                a.volumes.retain(|v| v.id != vol);
                if a.volumes.len() == before {
                    return fail("InvalidVolume.NotFound");
                }
                ok(String::new())
            }
            other => fail(&format!("unsimulated aws command {other}")),
        }
    }

    /// A release asset download: `.../releases/download/image-v<version>/<file>`.
    fn curl(a: &Account, args: &[String]) -> Output {
        let Some(url) = args.last() else {
            return fail("no url");
        };
        let Some((_, rest)) = url.split_once("/releases/download/image-v") else {
            return fail("unsimulated url");
        };
        let Some((version, file)) = rest.split_once('/') else {
            return fail("unsimulated url");
        };
        match a.releases.get(version) {
            // curl's `--write-out "\n%{http_code}"` puts the status on the last line
            Some(manifest) if file == "ozbox-image-manifest.json" => ok(format!("{manifest}\n200")),
            Some(_) if file.ends_with(".sig") => ok("c2ln\n200".into()),
            Some(_) if file.ends_with(".pem") => ok("cGVt\n200".into()),
            _ => ok("\n404".into()),
        }
    }

    fn tofu(a: &mut Account, cmd: &CommandSpec) -> Output {
        let args: Vec<&str> = cmd.args.iter().map(String::as_str).skip(1).collect();
        match args.as_slice() {
            ["init", ..] => ok(String::new()),
            ["workspace", "delete", w] => {
                a.workspaces.retain(|x| x != w);
                ok(String::new())
            }
            ["workspace", "list"] => {
                let mut out = String::from("  default\n");
                for w in &a.workspaces {
                    out.push_str(&format!(
                        "{} {w}\n",
                        if *w == a.workspace { "*" } else { " " }
                    ));
                }
                ok(out)
            }
            ["workspace", "select", rest @ ..] => {
                let name = rest.last().copied().unwrap_or("default").to_string();
                let create = rest.contains(&"-or-create");
                if !create && name != "default" && !a.workspaces.contains(&name) {
                    return fail(&format!("Workspace {name:?} doesn't exist."));
                }
                if create && !a.workspaces.contains(&name) {
                    a.workspaces.push(name.clone());
                }
                a.workspace = name;
                ok(String::new())
            }
            ["plan", rest @ ..] => {
                let Some(file) = rest.iter().find_map(|x| x.strip_prefix("-out=")) else {
                    return fail("plan without -out is not simulated");
                };
                let mut vars = parse_vars(&cmd.args);
                if let Some(r) = rest.iter().find_map(|x| x.strip_prefix("-replace=")) {
                    vars.insert("__replace".into(), r.to_string());
                }
                // A plan made while the state has lost the /work volume or its attachment creates them again.
                let restore = !vars.contains_key("__replace")
                    && (tf_work(a, false).is_none() || tf_work(a, true).is_none());
                if restore {
                    vars.insert("__mode".into(), "restore".into());
                } else if !vars.contains_key("__replace") {
                    let name = vars.get("box_name").cloned().unwrap_or_default();
                    let exists = a.instances.iter().any(|i| {
                        i.tags.get("ozbox-box") == Some(&name) && i.state != "terminated"
                    });
                    if exists {
                        vars.insert("__mode".into(), "inplace".into());
                    }
                }
                a.plans.insert(file.to_string(), vars);
                ok(String::new())
            }
            ["show", "-json", file] => {
                let Some(vars) = a.plans.get(*file) else {
                    return fail("no such plan file");
                };
                let name = vars.get("box_name").cloned().unwrap_or_default();
                if vars.get("__replace").map(String::as_str) == Some("aws_ebs_volume.work") {
                    let machine = if a.plan_replaces_instance {
                        json!(["delete", "create"])
                    } else {
                        json!(["no-op"])
                    };
                    return ok(json!({"resource_changes": [
                        {"address": "aws_instance.box", "change": {"actions": machine}},
                        {"address": "aws_volume_attachment.work", "change": {"actions": ["delete", "create"]}},
                        {"address": "aws_ebs_volume.work", "change": {"actions": ["delete", "create"]}},
                        {"address": "aws_security_group.box", "change": {"actions": ["no-op"]}},
                    ]})
                    .to_string());
                }
                if vars.get("__mode").map(String::as_str) == Some("inplace") {
                    let granted = a.role_grants.contains_key(&name);
                    let wanted = vars.contains_key("secrets_key_arn");
                    let policy = match (granted, wanted) {
                        (false, true) => json!(["create"]),
                        (true, false) => json!(["delete"]),
                        _ => json!(["no-op"]),
                    };
                    // an in-place update as a real plan shows it: tags change, nothing else
                    let tags_update = json!({
                        "actions": ["update"],
                        "before": {"tags": {"ozbox-secrets-adopt": "a"}},
                        "after": {"tags": {"ozbox-secrets-adopt": "b"}},
                        "after_unknown": {"tags_all": true},
                    });
                    // The machine's system disk as the module wants it tagged (made, owned, in this box and region, root). A disk that
                    // already carries all of that shows no change; one a version before the module tagged it shows tags `{}`.
                    let root = a
                        .instances
                        .iter()
                        .find(|i| {
                            i.tags.get("ozbox-box") == Some(&name) && i.state != "terminated"
                        })
                        .and_then(|i| i.vols.first().map(|(_, v)| (i.id.clone(), v.clone())));
                    let (instance_id, root_id) = root.clone().unwrap_or_default();
                    let root_before = a
                        .volumes
                        .iter()
                        .find(|v| v.id == root_id)
                        .map(|v| v.tags.clone())
                        .unwrap_or_default();
                    let mut root_after = root_before.clone();
                    root_after.insert("ozbox-managed".into(), "true".into());
                    root_after.insert("ozbox-box".into(), name.clone());
                    root_after.insert("ozbox-role".into(), "root".into());
                    if let Some(r) = vars.get("region") {
                        root_after.insert("ozbox-region".into(), r.clone());
                    }
                    let machine = if a.inplace_replaces_instance {
                        json!({"actions": ["delete", "create"]})
                    } else {
                        json!({
                            "actions": ["update"],
                            "before": {
                                "id": instance_id,
                                "tags": {"ozbox-secrets-adopt": "a"},
                                "root_block_device": [{"volume_id": root_id, "volume_size": 30, "tags": root_before}],
                            },
                            "after": {
                                "id": instance_id,
                                "tags": {"ozbox-secrets-adopt": "b"},
                                "root_block_device": [{"volume_id": root_id, "volume_size": 30, "tags": root_after}],
                            },
                            "after_unknown": {"tags_all": true},
                        })
                    };
                    return ok(json!({"resource_changes": [
                        {"address": "aws_iam_role_policy_attachment.fleet_key[0]", "change": {"actions": policy}},
                        {"address": "aws_iam_role.box", "change": tags_update.clone()},
                        {"address": "aws_instance.box", "change": machine},
                        {"address": "aws_ebs_volume.work", "change": tags_update},
                        {"address": "aws_volume_attachment.work", "change": {"actions": ["no-op"]}},
                    ]})
                    .to_string());
                }
                if vars.get("__mode").map(String::as_str) == Some("restore") {
                    let machine = if a.plan_replaces_instance_after_rm {
                        json!(["delete", "create"])
                    } else {
                        json!(["no-op"])
                    };
                    let act = |missing: bool| if missing { json!(["create"]) } else { json!(["no-op"]) };
                    return ok(json!({"resource_changes": [
                        {"address": "aws_instance.box", "change": {"actions": machine}},
                        {"address": "aws_volume_attachment.work", "change": {"actions": act(tf_work(a, true).is_none())}},
                        {"address": "aws_ebs_volume.work", "change": {"actions": act(tf_work(a, false).is_none())}},
                    ]})
                    .to_string());
                }
                let exists = a
                    .instances
                    .iter()
                    .any(|i| i.tags.get("ozbox-box") == Some(&name) && i.state != "terminated");
                let replace = if exists {
                    json!(["delete", "create"])
                } else {
                    json!(["create"])
                };
                let volume = if a.plan_replaces_volume {
                    json!(["delete", "create"])
                } else if a.plan_creates_volume {
                    json!(["create"])
                } else {
                    json!(["no-op"])
                };
                ok(json!({"resource_changes": [
                    {"address": "aws_instance.box", "change": {"actions": replace}},
                    {"address": "aws_volume_attachment.work", "change": {"actions": replace}},
                    {"address": "aws_ebs_volume.work", "change": {"actions": volume}},
                    {"address": "aws_security_group.box", "change": {"actions": ["no-op"]}},
                ]})
                .to_string())
            }
            ["apply", .., file] if a.plans.contains_key(*file) => {
                if a.fail_next_replace_apply {
                    a.fail_next_replace_apply = false;
                    return fail("injected: the apply was interrupted before it changed anything");
                }
                let vars = a.plans.get(*file).cloned().unwrap_or_default();
                let name = vars.get("box_name").cloned().unwrap_or_default();
                if vars.get("__mode").map(String::as_str) == Some("inplace") {
                    // tags change and the role's fleet-key attachment is made or taken back; nothing is replaced
                    match vars.get("secrets_key_arn") {
                        Some(k) => a.role_grants.insert(name.clone(), k.clone()),
                        None => a.role_grants.remove(&name),
                    };
                    let labels = vars
                        .get("labels")
                        .map(|l| parse_labels(l))
                        .unwrap_or_default();
                    let Some(inst) = a.instances.iter_mut().find(|i| {
                        i.tags.get("ozbox-box") == Some(&name) && i.state != "terminated"
                    }) else {
                        return fail("no machine to change");
                    };
                    inst.tags.retain(|k, _| {
                        !matches!(
                            k.as_str(),
                            "ozbox-secrets-key" | "ozbox-secrets-adopt" | "ozbox-secrets-fleet"
                        )
                    });
                    inst.tags.extend(labels);
                    // the system disk takes the tags the module gives it (the plan showed them)
                    let root_id = inst.vols.first().map(|(_, v)| v.clone()).unwrap_or_default();
                    if let Some(v) = a.volumes.iter_mut().find(|v| v.id == root_id) {
                        v.tags.insert("ozbox-managed".into(), "true".into());
                        v.tags.insert("ozbox-box".into(), name.clone());
                        v.tags.insert("ozbox-role".into(), "root".into());
                    }
                    return ok(String::new());
                }
                if vars.get("__mode").map(String::as_str) == Some("restore") {
                    let ws = a.workspace.clone();
                    let new_volume = if tf_work(a, false).is_none() {
                        let snap = vars.get("work_snapshot_id").cloned();
                        if !snap
                            .as_ref()
                            .is_some_and(|sn| a.snapshots.iter().any(|x| &x.id == sn))
                        {
                            return fail("InvalidSnapshot.NotFound");
                        }
                        a.next += 1;
                        let id = format!("vol-work{:04x}", a.next);
                        let mut tags = vars
                            .get("labels")
                            .map(|l| parse_labels(l))
                            .unwrap_or_default();
                        tags.insert("ozbox-managed".into(), "true".into());
                        tags.insert("ozbox-box".into(), name.clone());
                        tags.insert("ozbox-role".into(), "work".into());
                        a.volumes.push(Vol {
                            id: id.clone(),
                            size: vars
                                .get("work_disk_gb")
                                .and_then(|v| v.parse().ok())
                                .unwrap_or(0),
                            tags,
                            snapshot: snap,
                        });
                        a.tf_volume.insert(ws.clone(), Some(id.clone()));
                        id
                    } else {
                        tf_work(a, false).unwrap_or_default()
                    };
                    let Some(inst) = a.instances.iter_mut().find(|i| {
                        i.tags.get("ozbox-box") == Some(&name) && i.state != "terminated"
                    }) else {
                        return fail("no machine to attach to");
                    };
                    inst.vols.retain(|v| v.0 != "/dev/sdf");
                    inst.vols.push(("/dev/sdf".into(), new_volume.clone()));
                    let iid = inst.id.clone();
                    a.tf_attach.insert(ws.clone(), Some(new_volume.clone()));
                    a.outputs.insert(
                        ws,
                        json!({
                            "machine_id": {"value": iid},
                            "work_volume_id": {"value": new_volume},
                            "machine_type": {"value": vars.get("machine_type")}
                        })
                        .to_string(),
                    );
                    return ok(String::new());
                }
                let existing = a.instances.iter().position(|i| {
                    i.tags.get("ozbox-box") == Some(&name) && i.state != "terminated"
                });
                let work = match existing {
                    Some(at) => {
                        let old = a.instances.remove(at);
                        let old_root = old.vols.first().map(|v| v.1.clone()).unwrap_or_default();
                        a.volumes.retain(|v| v.id != old_root);
                        old.vols.get(1).map(|v| v.1.clone()).unwrap_or_default()
                    }
                    // No machine: this is the creation that finishes an interrupted replacement, onto the kept disk.
                    None => match a.volumes.iter().find(|v| {
                        v.tags.get("ozbox-box") == Some(&name)
                            && v.tags.get("ozbox-role").map(String::as_str) == Some("work")
                    }) {
                        Some(v) => v.id.clone(),
                        None => return fail("nothing to replace"),
                    },
                };
                if a.create_failures > 0 {
                    a.create_failures -= 1;
                    return fail(&a.create_failure_message.clone());
                }
                let size: u32 = vars
                    .get("work_disk_gb")
                    .and_then(|v| v.parse().ok())
                    .unwrap_or(0);
                if let Some(v) = a.volumes.iter_mut().find(|v| v.id == work) {
                    // The volume may grow in place; it is never replaced or shrunk.
                    v.size = v.size.max(size);
                }
                let mut tags = vars
                    .get("labels")
                    .map(|l| parse_labels(l))
                    .unwrap_or_default();
                tags.insert("ozbox-managed".into(), "true".into());
                tags.insert("ozbox-box".into(), name);
                if let Some(r) = vars.get("region") {
                    tags.insert("ozbox-region".into(), r.clone());
                }
                a.next += 1;
                let (iid, root) = (
                    format!("i-{:017x}", a.next),
                    format!("vol-root{:04x}", a.next),
                );
                let mut root_tags = tags.clone();
                root_tags.insert("ozbox-role".into(), "root".into());
                a.volumes.push(Vol {
                    id: root.clone(),
                    size: 30,
                    tags: root_tags,
                    snapshot: None,
                });
                a.instances.push(Inst {
                    id: iid.clone(),
                    itype: vars.get("machine_type").cloned().unwrap_or_default(),
                    image: vars.get("image_id").cloned().unwrap_or_default(),
                    state: "running".into(),
                    tags: machine_tags(tags, &vars),
                    vols: vec![
                        ("/dev/xvda".into(), root),
                        ("/dev/sdf".into(), work.clone()),
                    ],
                });
                let ws = a.workspace.clone();
                a.outputs.insert(
                    ws,
                    json!({
                        "machine_id": {"value": iid},
                        "work_volume_id": {"value": work},
                        "machine_type": {"value": vars.get("machine_type")}
                    })
                    .to_string(),
                );
                ok(String::new())
            }
            ["apply", ..] => {
                let vars = parse_vars(&cmd.args);
                let name = vars.get("box_name").cloned().unwrap_or_default();
                if let Some(k) = vars.get("secrets_key_arn") {
                    a.role_grants.insert(name.clone(), k.clone());
                }
                let size: u32 = vars
                    .get("work_disk_gb")
                    .and_then(|v| v.parse().ok())
                    .unwrap_or(0);
                if let Some(snap) = vars.get("work_snapshot_id") {
                    if !a.snapshots.iter().any(|s| &s.id == snap) {
                        return fail("InvalidSnapshot.NotFound");
                    }
                }
                let mut tags = vars
                    .get("labels")
                    .map(|l| parse_labels(l))
                    .unwrap_or_default();
                tags.insert("ozbox-managed".into(), "true".into());
                tags.insert("ozbox-box".into(), name);
                if let Some(r) = vars.get("region") {
                    tags.insert("ozbox-region".into(), r.clone());
                }
                a.next += 1;
                let (iid, root, work) = (
                    format!("i-{:017x}", a.next),
                    format!("vol-root{:04x}", a.next),
                    format!("vol-work{:04x}", a.next),
                );
                let mut root_tags = tags.clone();
                root_tags.insert("ozbox-role".into(), "root".into());
                let mut work_tags = tags.clone();
                work_tags.insert("ozbox-role".into(), "work".into());
                a.volumes.push(Vol {
                    id: root.clone(),
                    size: 30,
                    tags: root_tags,
                    snapshot: None,
                });
                a.volumes.push(Vol {
                    id: work.clone(),
                    size,
                    tags: work_tags,
                    snapshot: vars.get("work_snapshot_id").cloned(),
                });
                a.instances.push(Inst {
                    id: iid.clone(),
                    itype: vars.get("machine_type").cloned().unwrap_or_default(),
                    image: vars.get("image_id").cloned().unwrap_or_default(),
                    state: "running".into(),
                    tags: machine_tags(tags, &vars),
                    vols: vec![
                        ("/dev/xvda".into(), root),
                        ("/dev/sdf".into(), work.clone()),
                    ],
                });
                let ws = a.workspace.clone();
                a.outputs.insert(
                    ws,
                    json!({
                        "machine_id": {"value": iid},
                        "work_volume_id": {"value": work},
                        "machine_type": {"value": vars.get("machine_type")}
                    })
                    .to_string(),
                );
                ok(String::new())
            }
            ["state", "list"] => {
                let mut out = String::from("aws_instance.box\naws_security_group.box\n");
                if tf_work(a, false).is_some() {
                    out.push_str("aws_ebs_volume.work\n");
                }
                if tf_work(a, true).is_some() {
                    out.push_str("aws_volume_attachment.work\n");
                }
                ok(out)
            }
            ["state", "show", "-no-color", addr] => match *addr {
                "aws_ebs_volume.work" => match tf_work(a, false) {
                    Some(v) => ok(format!("# {addr}:\nresource \"aws_ebs_volume\" \"work\" {{\n    id = \"{v}\"\n}}\n")),
                    None => fail("No such resource instance"),
                },
                "aws_volume_attachment.work" => match tf_work(a, true) {
                    Some(v) => ok(format!("# {addr}:\nresource \"aws_volume_attachment\" \"work\" {{\n    volume_id = \"{v}\"\n}}\n")),
                    None => fail("No such resource instance"),
                },
                _ => ok(String::new()),
            },
            ["state", "rm", addrs @ ..] => {
                let ws = a.workspace.clone();
                for addr in addrs {
                    match *addr {
                        "aws_ebs_volume.work" => {
                            a.tf_volume.insert(ws.clone(), None);
                        }
                        "aws_volume_attachment.work" => {
                            a.tf_attach.insert(ws.clone(), None);
                        }
                        other => return fail(&format!("the fake cannot remove {other} from state")),
                    }
                }
                ok(String::new())
            }
            ["import", .., addr, id] => {
                let ws = a.workspace.clone();
                match *addr {
                    "aws_ebs_volume.work" => {
                        a.tf_volume.insert(ws, Some((*id).to_string()));
                    }
                    "aws_volume_attachment.work" => {
                        let vol = id.split(':').nth(1).unwrap_or(id).to_string();
                        a.tf_attach.insert(ws, Some(vol));
                    }
                    other => return fail(&format!("the fake cannot import {other}")),
                }
                ok(String::new())
            }
            ["output", "-json"] => ok(a
                .outputs
                .get(&a.workspace)
                .cloned()
                .unwrap_or_else(|| "{}".into())),
            ["destroy", ..] => {
                let vars = parse_vars(&cmd.args);
                let name = vars.get("box_name").cloned().unwrap_or_default();
                let mine = |t: &BTreeMap<String, String>| t.get("ozbox-box") == Some(&name);
                a.instances.retain(|i| !mine(&i.tags));
                a.volumes.retain(|v| !mine(&v.tags));
                ok(String::new())
            }
            other => fail(&format!("unsimulated tofu command {other:?}")),
        }
    }
}

impl CommandRunner for FakeAws {
    fn run(&self, cmd: &CommandSpec) -> Result<Output> {
        Ok(self.with(|a| {
            a.calls.push(cmd.clone());
            match cmd.program.as_str() {
                "aws" => Self::aws(a, &cmd.args),
                "tofu" => Self::tofu(a, cmd),
                "curl" => Self::curl(a, &cmd.args),
                // Not signed in to GitHub: the checks go anonymously, as they would for a public repository.
                "gh" => fail("gh: not logged in"),
                "cosign" if cmd.args.first().map(String::as_str) == Some("version") => {
                    ok("GitVersion:    v2.4.1\n".into())
                }
                "cosign" => {
                    if a.cosign_refuses {
                        fail("error verifying the signature: none of the expected identities matched")
                    } else {
                        ok(String::new())
                    }
                }
                other => fail(&format!("unsimulated program {other}")),
            }
        }))
    }
}
