//! Hetzner Cloud provider.
//!
//! * **Lifecycle** (create and destroy) runs the `hcloud-box` OpenTofu module, one workspace per
//!   box, through the argv-only command runner (the box-module contract: `infra/tofu/modules/hcloud-box/variables.tf`).
//! * **Runtime** actions (stop, start, change type, grow the volume, snapshot, list) call the Hetzner REST API
//!   through [`api::HcloudApi`]. The token comes from `HCLOUD_TOKEN` at call time and is never kept or printed.
//!
//! Planning is the shared [`ozbox_core::Engine`]; this crate supplies the primitives and the size mapping.
//!
//! **Clone is not supported:** Hetzner cannot create a volume from a snapshot (the module rejects one), so
//! `clone` plans as `Unsupported` rather than pretending. (A copy-based clone is future work.)
//!
//! **Known limit:** Hetzner Cloud cannot snapshot volumes. A snapshot made here is an image of the machine's root
//! disk; it does not contain `/work`. Every plan that takes a snapshot says so.

pub mod adopt;
pub mod api;
/// In-memory Hetzner doubles, for this crate's tests and (with the `testing` feature) the CLI's.
#[cfg(any(test, feature = "testing"))]
pub mod testing;

use std::collections::BTreeMap;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration, Instant};

use ozbox_core::{
    Backend, BoxName, BoxRecord, BoxSpec, BoxState, Capabilities, CommandRunner, DiskGb, Engine,
    Error, ImageInfo, MachineChoice, ModuleVars, Operation, ResizeMethod, Result, Size,
    SnapshotInfo, SnapshotKind, SnapshotPrice, TofuModule, RESUME_AFTER_LABEL, UPGRADE_TO_LABEL,
};

use api::{ApiServer, HcloudApi};

pub const PROVIDER_ID: &str = "hcloud";
pub const DEFAULT_MODULE_DIR: &str = "infra/tofu/modules/hcloud-box";

/// Said in every upgrade plan: what replacing the server means. Hetzner keeps a server's user data for its life and a rebuild
/// takes only an image, so a rebuild could never deliver a release's first-boot configuration; a replacement builds the new
/// server from the current module, and the address is not kept.
pub const UPGRADE_REPLACES_SERVER: &str = "Hetzner has no way to give a server new first-boot configuration, so the upgrade replaces the server (OpenTofu `-replace`) instead of rebuilding its disk: the new server is made from the new image and this release's first-boot configuration (the root helper, the setup scripts and units, the pinned approver). The /work volume is a separate volume and is kept and attached to the new server. The server gets a NEW address (it belongs to the server); nothing connects in, so only an allow-list on the other side of an outbound connection would notice. What lived on the old system disk is gone, including a vault token placed by hand (`ozbox admin <box> -- place-bao-token` puts it back).";
/// Said in every upgrade plan: what happens in the window between removing the old server and creating the new one.
pub const UPGRADE_GAP_NOTE: &str = "The old server is removed before the new one is created. If Hetzner cannot create the new one then (a server type out of stock in the location, a project limit), the create is retried a few times with a pause. If it still fails, /work stays safe, the box has no server and shows as `instance missing`, and running this same `upgrade` again finishes the job.";

/// The only resources an upgrade may destroy and recreate: the server and the attachment that depends on it. The `/work`
/// volume is not on this list, so a plan that would replace it is refused.
const UPGRADE_REPLACES: &str = "hcloud_server.box";
const UPGRADE_MAY_ALSO_REPLACE: &[&str] = &["hcloud_volume_attachment.work"];
/// The one resource no upgrade may delete, replace or newly create: it is the person's `/work`.
const UPGRADE_PROTECTED: &[&str] = &["hcloud_volume.work"];

const LABEL_MANAGED: &str = "ozbox-managed";
const LABEL_BOX: &str = "ozbox-box";
const LABEL_SIZE: &str = "ozbox-size";
const LABEL_ROLE: &str = "ozbox-role";
/// The label the CLI writes on the `/work` volume with the server type the box ran, next to [`UPGRADE_TO_LABEL`]. The server
/// is gone when an upgrade is interrupted between destroy and create, and this is what remains of it.
const UPGRADE_MACHINE_LABEL: &str = "ozbox-upgrade-machine";

/// Whether an apply failed because Hetzner could not create the server right now (a type out of stock in the location, a
/// project limit), the one failure that is worth trying again. Pure, so it is tested on fixture text.
pub fn is_capacity_error(message: &str) -> bool {
    const SIGNS: &[&str] = &[
        "resource_unavailable",
        "placement_error",
        "error during placement",
        "resource_limit_exceeded",
        "server limit",
    ];
    let m = message.to_ascii_lowercase();
    SIGNS.iter().any(|s| m.contains(s))
}

// TODO(arch): images are amd64 and arm64; this mapping is amd64 (CCX) only for v0.1. Add an `arch`
// argument (CAX types for arm64) when the arm64 image ships.
/// Size to Hetzner dedicated-vCPU (CCX) server type. Every type has at least the size's vCPUs and memory.
/// Size L asks for 8 vCPU / 64 GB, which no CCX type has, so it gets the smallest type with at least that: `ccx43`.
pub fn machine_choice(size: Size) -> Result<MachineChoice> {
    match size {
        Size::XS => Ok(MachineChoice::with_note(
            "ccx23",
            "Hetzner has no dedicated type with 4 vCPU and 8 GB; size XS uses ccx23 (4 vCPU, 16 GB), the same machine as S. It has twice the memory of XS, so a Hetzner XS box is not the 4 vCPU / 8 GiB shape the benchmark measures.",
        )),
        Size::S => Ok(MachineChoice::new("ccx23")),
        Size::M => Ok(MachineChoice::new("ccx33")),
        Size::L => Ok(MachineChoice::with_note(
            "ccx43",
            "Hetzner has no dedicated type with 8 vCPU and 64 GB; size L uses ccx43 (16 vCPU, 64 GB), which has twice the vCPUs of size L.",
        )),
        Size::XL => Ok(MachineChoice::new("ccx43")),
        Size::XXL => Ok(MachineChoice::new("ccx53")),
        Size::Gpu(_) => Err(Error::Unsupported {
            provider: PROVIDER_ID.into(),
            what: format!("create a {size} box"),
            why: "Hetzner Cloud has no GPU server types".into(),
        }),
    }
}

pub fn capabilities() -> Capabilities {
    Capabilities {
        resize: ResizeMethod::PowerOffResize,
        online_disk_grow: true,
        disk_shrink: false,
        snapshots: true,
        sizes: Size::STANDARD.to_vec(),
    }
}

#[derive(Debug, Clone)]
pub struct HcloudConfig {
    /// The `hcloud-box` module directory.
    pub module_dir: PathBuf,
    /// Location used when a box does not name one (e.g. `fsn1`). `None` leaves it to the module's default.
    pub region: Option<String>,
    /// Image to boot from when a box does not name one.
    pub image: Option<String>,
    /// How long to wait for a machine to reach a state, and how often to look.
    pub wait_timeout: Duration,
    pub poll_interval: Duration,
    /// Where the OpenTofu state of the boxes lives, apart from the module checkout. `None` keeps it beside the module.
    pub state_dir: Option<PathBuf>,
    /// Keep the state in the encrypted bucket instead (needs `state_dir`). `None` keeps it in `state_dir`.
    pub state_s3: Option<ozbox_core::tofu::S3State>,
    /// For `upgrade` only: this computer's approval key (the label value), pinned on a box that has none, as `create` pins one
    /// in the first-boot configuration. A box that has one keeps it.
    pub upgrade_pin: Option<String>,
    /// For `upgrade` only: this computer's SSH key for the box's ingress account (the label value), pinned on a box that has
    /// none, so a box made before the ingress account existed can be reached through it once its server is replaced. A box that
    /// has one keeps it. `None` leaves the box as it is.
    pub upgrade_ingress_pin: Option<String>,
    /// How many times an upgrade tries again to create the new server when Hetzner cannot right now, and the pause before the
    /// first retry (doubled each time, at most five minutes).
    pub create_retries: u32,
    pub create_backoff: Duration,
    /// The first-boot hash of the modules in `module_dir` (see [`ozbox_core::infra`]), recorded on a new machine.
    /// `None` passes nothing (the module's default).
    pub first_boot_sha256: Option<String>,
}

impl Default for HcloudConfig {
    fn default() -> Self {
        Self {
            module_dir: PathBuf::from(DEFAULT_MODULE_DIR),
            region: None,
            image: None,
            wait_timeout: Duration::from_secs(120),
            poll_interval: Duration::from_secs(2),
            state_dir: None,
            state_s3: None,
            upgrade_pin: None,
            upgrade_ingress_pin: None,
            create_retries: 4,
            create_backoff: Duration::from_secs(30),
            first_boot_sha256: None,
        }
    }
}

/// Open the provider with the real API and the real command runner.
pub fn open(config: HcloudConfig) -> Engine<HcloudBackend> {
    Engine::new(HcloudBackend::new(
        Arc::new(api::UreqApi::from_env()),
        Arc::new(ozbox_core::SystemRunner),
        config,
    ))
}

pub struct HcloudBackend {
    api: Arc<dyn HcloudApi>,
    tofu: TofuModule,
    cfg: HcloudConfig,
}

impl HcloudBackend {
    pub fn new(api: Arc<dyn HcloudApi>, runner: Arc<dyn CommandRunner>, cfg: HcloudConfig) -> Self {
        let mut tofu = TofuModule::new(runner, cfg.module_dir.clone());
        if let Some(d) = &cfg.state_dir {
            tofu = tofu.with_state_root(d);
        }
        if let Some(s3) = &cfg.state_s3 {
            tofu = tofu.with_s3_state(s3.clone());
        }
        Self { api, tofu, cfg }
    }

    fn server_id(rec: &BoxRecord) -> Result<u64> {
        rec.provider_id
            .as_deref()
            .and_then(|s| s.parse().ok())
            .ok_or_else(|| Error::Provider(format!("box {} has no server id", rec.spec.name)))
    }

    fn image_for(&self, spec: &BoxSpec) -> Option<String> {
        spec.image.clone().or_else(|| self.cfg.image.clone())
    }

    fn vars(&self, spec: &BoxSpec, machine_type: &str) -> ModuleVars {
        let mut labels = spec.labels.clone();
        labels.insert(LABEL_SIZE.into(), spec.size.to_string());
        ModuleVars {
            box_name: spec.name.clone(),
            machine_type: machine_type.to_string(),
            work_disk_gb: spec.work_disk_gb,
            image_id: self.image_for(spec).unwrap_or_default(),
            region: spec.region.clone().or_else(|| self.cfg.region.clone()),
            labels,
            // The module rejects a snapshot to restore from: Hetzner cannot create a volume from one.
            work_snapshot_id: None,
            // how many agent runs the box daemon runs at once: the same cap the dashboard's supervisor applies for the size
            extra: {
                let mut extra = BTreeMap::from([(
                    "runs_max_active".to_string(),
                    ozbox_core::supervisor::size_cap(spec.size).to_string(),
                )]);
                // which first-boot configuration the machine is made with, recorded on the box
                if let Some(h) = &self.cfg.first_boot_sha256 {
                    extra.insert("first_boot_sha256".to_string(), h.clone());
                }
                extra
            },
        }
    }

    fn wait_for(&self, id: u64, want: &str) -> Result<()> {
        let started = Instant::now();
        loop {
            if self.api.get_server(id)?.status == want {
                return Ok(());
            }
            if started.elapsed() >= self.cfg.wait_timeout {
                return Err(Error::Provider(format!(
                    "server {id} did not reach status {want:?} in time"
                )));
            }
            std::thread::sleep(self.cfg.poll_interval);
        }
    }

    /// The `/work` volume of a box, found by its labels (so it also answers for a box whose server is gone).
    fn work_volume(&self, name: &BoxName) -> Result<api::ApiVolume> {
        let volumes = self.api.list_volumes()?;
        let mine: Vec<&api::ApiVolume> = volumes
            .iter()
            .filter(|v| {
                v.labels.get(LABEL_BOX).map(String::as_str) == Some(name.as_str())
                    && v.labels.get(LABEL_ROLE).map(String::as_str) == Some("work")
            })
            .collect();
        match mine.as_slice() {
            [v] => Ok((*v).clone()),
            [] => Err(Error::Provider(format!(
                "the /work volume of {name} was not found"
            ))),
            _ => Err(Error::Provider(format!(
                "more than one volume claims to be the /work disk of {name}; nothing was changed, check them by hand"
            ))),
        }
    }

    /// The module variables for replacing a box's server: everything as the box is NOW (its type after any resize, its disk
    /// after any growth, its location, every label it carries), with only the image changed. Anything else would make the
    /// apply change more than the image.
    fn upgrade_vars(&self, rec: &BoxRecord, image: &str) -> Result<ModuleVars> {
        let Some(machine_type) = rec.machine_type.clone() else {
            return Err(Error::Config(format!(
                "{} has no server and its /work volume does not say which server type it ran, so ozbox cannot rebuild it safely. Nothing was changed; the volume is kept.",
                rec.spec.name
            )));
        };
        let mut spec = rec.spec.clone();
        spec.image = Some(image.to_string());
        spec.from_snapshot = None;
        // The marks are bookkeeping and must not be copied onto the new server.
        spec.labels.remove(UPGRADE_TO_LABEL);
        spec.labels.remove(RESUME_AFTER_LABEL);
        // A box made with no pinned approver gets this computer's key, in its new first-boot configuration, as `create` pins
        // one. A box that has one keeps it.
        if let Some(pin) = &self.cfg.upgrade_pin {
            spec.labels
                .entry(ozbox_core::APPROVER_LABEL.to_string())
                .or_insert_with(|| pin.clone());
        }
        // the same for the ingress account's key: a box with the label keeps its own
        if let Some(pin) = &self.cfg.upgrade_ingress_pin {
            spec.labels
                .entry(ozbox_core::INGRESS_LABEL.to_string())
                .or_insert_with(|| pin.clone());
        }
        Ok(self.vars(&spec, &machine_type))
    }

    /// Plan, with the guard, what this upgrade is about to apply: a replacement while the server exists, the creation of the
    /// server when it is already gone. Either way the `/work` volume may not be deleted, replaced or created.
    fn guarded_plan(
        &self,
        vars: &ModuleVars,
        server_gone: bool,
    ) -> Result<ozbox_core::ReplacePlan> {
        if server_gone {
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

    /// After a replacement: the `/work` volume must be attached to the box's (new) server. Anything else is not a finished
    /// upgrade, and the mark stays so the next `upgrade` completes it.
    fn require_work_attached(&self, name: &BoxName) -> Result<()> {
        let vol = self.work_volume(name)?;
        let server = self
            .api
            .list_servers()?
            .into_iter()
            .find(|s| s.labels.get(LABEL_BOX).map(String::as_str) == Some(name.as_str()));
        match (server, vol.server) {
            (Some(s), Some(v)) if s.id == v => Ok(()),
            _ => Err(Error::Provider(format!(
                "{name}'s new server was made but its /work volume is not attached to it. Nothing of /work was changed or removed. Run `ozbox upgrade` again: it replaces the server again and attaches /work, and the upgrade is not marked finished until it is attached"
            ))),
        }
    }

    fn work_volume_id(&self, name: &BoxName) -> Result<u64> {
        self.api
            .list_volumes()?
            .into_iter()
            .find(|v| v.labels.get(LABEL_BOX).map(String::as_str) == Some(name.as_str()))
            .map(|v| v.id)
            .ok_or_else(|| Error::Provider(format!("box {name} has no /work volume")))
    }
}

/// The architecture a Hetzner server type runs (`x86` or `arm`). The CAX family is Arm; every other type is x86.
fn arch_of_server_type(server_type: &str) -> &'static str {
    if server_type.to_ascii_lowercase().starts_with("cax") {
        "arm"
    } else {
        "x86"
    }
}

fn state_of(status: &str) -> BoxState {
    match status {
        "running" => BoxState::Running,
        "off" => BoxState::Paused,
        "initializing" => BoxState::Creating,
        "starting" => BoxState::Resuming,
        "stopping" => BoxState::Pausing,
        "migrating" | "rebuilding" => BoxState::Resizing,
        "deleting" => BoxState::Destroying,
        _ => BoxState::Unknown,
    }
}

/// The sizes in the order an unlabelled machine type is matched to one. XS shares `ccx23` with S, and S was there
/// first, so XS comes last: an unlabelled `ccx23` stays S.
fn sizes_by_type_priority() -> [Size; 6] {
    [Size::S, Size::M, Size::L, Size::XL, Size::XXL, Size::XS]
}

/// The size a server was created as (its label), else the first size that maps to its type. `None` when
/// Oz Box does not map the type to any size: such a box is reported as `Unknown` and never acted on.
fn size_of(server: &ApiServer) -> Option<Size> {
    if let Some(s) = server.labels.get(LABEL_SIZE).and_then(|s| s.parse().ok()) {
        return Some(s);
    }
    sizes_by_type_priority()
        .into_iter()
        .find(|s| machine_choice(*s).is_ok_and(|c| c.machine_type == server.server_type))
}

/// A box's `/work` volume among a project's volumes: the one with its box label and the work role, else any with its label.
fn work_of<'v>(volumes: &'v [api::ApiVolume], name: &str) -> Option<&'v api::ApiVolume> {
    let mine = |v: &&api::ApiVolume| v.labels.get(LABEL_BOX).map(String::as_str) == Some(name);
    volumes
        .iter()
        .filter(mine)
        .find(|v| v.labels.get(LABEL_ROLE).map(String::as_str) == Some("work"))
        .or_else(|| volumes.iter().find(mine))
}

/// The labels a box carries as its own: what the module sets itself and the bookkeeping marks are left out, except the marks a
/// plan reads.
fn own_labels(labels: &BTreeMap<String, String>) -> BTreeMap<String, String> {
    labels
        .iter()
        .filter(|(k, _)| {
            !k.starts_with("ozbox-")
                || k.as_str() == RESUME_AFTER_LABEL
                || k.as_str() == UPGRADE_TO_LABEL
                || k.as_str() == ozbox_core::APPROVER_LABEL
                || k.as_str() == ozbox_core::INGRESS_LABEL
        })
        .map(|(k, v)| (k.clone(), v.clone()))
        .collect()
}

/// `/work` volumes whose server is gone: managed, labelled as a work volume with a box name no server still carries, free (not
/// attached), and carrying the upgrade mark. The mark is what makes a missing server an interrupted upgrade rather than a
/// box someone removed on purpose.
fn stranded_volumes<'v>(
    servers: &[ApiServer],
    volumes: &'v [api::ApiVolume],
) -> Vec<&'v api::ApiVolume> {
    let live: Vec<&str> = servers
        .iter()
        .filter_map(|s| s.labels.get(LABEL_BOX).map(String::as_str))
        .collect();
    volumes
        .iter()
        .filter(|v| v.labels.get(LABEL_ROLE).map(String::as_str) == Some("work"))
        .filter(|v| v.server.is_none())
        .filter(|v| v.labels.contains_key(UPGRADE_TO_LABEL))
        .filter(|v| {
            v.labels
                .get(LABEL_BOX)
                .is_some_and(|b| !live.contains(&b.as_str()))
        })
        .collect()
}

impl Backend for HcloudBackend {
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
        if self.image_for(spec).is_none() {
            return Err(Error::Config(
                "no image to boot from: pass --image or set `image` under [hcloud] in the config"
                    .into(),
            ));
        }
        if spec
            .region
            .as_deref()
            .or(self.cfg.region.as_deref())
            .is_none()
        {
            return Err(Error::Config(
                "no location: pass --region or set `region` under [hcloud] in the config".into(),
            ));
        }
        if spec.from_snapshot.is_some() {
            return Err(Error::Unsupported {
                provider: PROVIDER_ID.into(),
                what: format!("clone into {}", spec.name),
                why: "Hetzner Cloud cannot create a volume from a snapshot, so /work cannot be restored into a new box; create a new box and copy the data over".into(),
            });
        }
        Ok(())
    }

    fn plan_notes(&self, op: &Operation) -> Vec<String> {
        let takes_snapshot = matches!(
            op,
            Operation::Snapshot { .. }
                | Operation::Clone { .. }
                | Operation::Destroy {
                    final_snapshot: true,
                    ..
                }
        );
        if takes_snapshot {
            vec![
                "/work is NOT included in this snapshot. Hetzner Cloud cannot snapshot volumes, so it captures only the machine's root disk."
                    .into(),
            ]
        } else {
            Vec::new()
        }
    }

    fn list(&self) -> Result<Vec<BoxRecord>> {
        let servers = self.api.list_servers()?;
        let volumes = self.api.list_volumes()?;
        if servers.is_empty() && volumes.is_empty() {
            return Ok(Vec::new());
        }
        let mut images = self.api.list_snapshots()?;
        images.sort_by(|a, b| (&a.created, a.id).cmp(&(&b.created, b.id)));
        let snapshots_of = |raw_name: &str| -> Vec<String> {
            images
                .iter()
                .filter(|i| i.labels.get(LABEL_BOX).map(String::as_str) == Some(raw_name))
                .map(|i| i.id.to_string())
                .collect()
        };

        let mut out = Vec::new();
        for s in &servers {
            let Some(raw_name) = s.labels.get(LABEL_BOX) else {
                continue;
            };
            let Ok(name) = BoxName::new(raw_name.clone()) else {
                continue;
            };
            let work = work_of(&volumes, raw_name);
            let known_size = size_of(s);
            let mut spec = BoxSpec::new(name, known_size.unwrap_or(Size::S));
            spec.work_disk_gb = work.map_or(0, |v| v.size_gb);
            // where the box really is, so an upgrade rebuilds it where it is and never plans to move its volume
            spec.region = work.and_then(|v| v.location.clone());
            spec.image = s.image.clone();
            spec.labels = own_labels(&s.labels);
            // An unfinished upgrade is marked on the /work volume, because the server it marks gets replaced. (A mark an
            // older rebuild left on the server is still read.)
            if let Some(to) = work.and_then(|v| v.labels.get(UPGRADE_TO_LABEL)) {
                spec.labels.insert(UPGRADE_TO_LABEL.to_string(), to.clone());
                // A server of the new image whose /work is not attached to it is not a finished upgrade: the apply made the
                // server and stopped before the attachment. It is shown as not on the image, so a second `upgrade` plans the
                // replacement again (checked, with /work protected) instead of marking the box finished without its data.
                if work.is_some_and(|v| v.server != Some(s.id)) {
                    spec.image = None;
                }
            }
            out.push(BoxRecord {
                spec,
                state: if known_size.is_none() {
                    BoxState::Unknown
                } else {
                    state_of(&s.status)
                },
                provider: PROVIDER_ID.into(),
                provider_id: Some(s.id.to_string()),
                machine_type: Some(s.server_type.clone()),
                snapshots: snapshots_of(raw_name),
                created_at: s.created.clone(),
                last_activity_at: None,
            });
        }
        for v in stranded_volumes(&servers, &volumes) {
            let Some(raw_name) = v.labels.get(LABEL_BOX) else {
                continue;
            };
            let Ok(name) = BoxName::new(raw_name.clone()) else {
                continue;
            };
            let machine_type = v.labels.get(UPGRADE_MACHINE_LABEL).cloned();
            let size = v
                .labels
                .get(LABEL_SIZE)
                .and_then(|s| s.parse().ok())
                .or_else(|| {
                    sizes_by_type_priority().into_iter().find(|s| {
                        machine_choice(*s)
                            .is_ok_and(|c| Some(&c.machine_type) == machine_type.as_ref())
                    })
                })
                .unwrap_or(Size::S);
            let mut spec = BoxSpec::new(name, size);
            spec.work_disk_gb = v.size_gb;
            spec.region = v.location.clone();
            spec.labels = own_labels(&v.labels);
            out.push(BoxRecord {
                spec,
                state: BoxState::InstanceMissing,
                provider: PROVIDER_ID.into(),
                provider_id: None,
                machine_type,
                snapshots: snapshots_of(raw_name),
                created_at: None,
                last_activity_at: None,
            });
        }
        out.sort_by(|a, b| a.spec.name.cmp(&b.spec.name));
        Ok(out)
    }

    fn create(&self, spec: &BoxSpec, machine_type: &str) -> Result<BoxRecord> {
        self.tofu.apply(&self.vars(spec, machine_type))?;
        self.list()?
            .into_iter()
            .find(|r| r.spec.name == spec.name)
            .ok_or_else(|| {
                Error::Provider(format!(
                    "box {} was created but the Hetzner API does not list it yet; run `ozbox list` again shortly",
                    spec.name
                ))
            })
    }

    fn check_final_snapshot_of_missing(&self, rec: &BoxRecord) -> Result<()> {
        Err(Error::Unsupported {
            provider: PROVIDER_ID.into(),
            what: format!("take a final snapshot of {}", rec.spec.name),
            why: "its server is gone, and a snapshot on Hetzner Cloud is an image of a server's own disk (the /work volume cannot be snapshotted), so there is nothing to snapshot. Finish the upgrade first (`ozbox upgrade`) if you want a snapshot of the system disk, or destroy it without a final snapshot".into(),
        })
    }

    fn destroy(&self, rec: &BoxRecord) -> Result<()> {
        let machine_type = rec.machine_type.clone().unwrap_or_default();
        if rec.state == BoxState::InstanceMissing {
            // Look again right before deleting: the volume is the one thing that cannot be brought back.
            let vol = self.work_volume(&rec.spec.name)?;
            if vol.server.is_some() {
                return Err(Error::Provider(format!(
                    "the /work volume of {} is attached to a server; nothing was changed",
                    rec.spec.name
                )));
            }
            if self.tofu.has_workspace(&rec.spec.name)? {
                self.tofu.destroy(&self.vars(&rec.spec, &machine_type))?;
            }
            // `tofu destroy` removes the volume when the state holds it; a state that never did (or none) leaves it.
            let left = self.api.list_volumes()?.iter().any(|v| v.id == vol.id);
            if left {
                self.api.delete_volume(vol.id)?;
            }
            return Ok(());
        }
        self.tofu.destroy(&self.vars(&rec.spec, &machine_type))
    }

    fn power_off(&self, rec: &BoxRecord) -> Result<()> {
        let id = Self::server_id(rec)?;
        // Graceful first: /work is a mounted volume and a hard power-off risks its filesystem.
        self.api.server_action(id, "shutdown")?;
        if self.wait_for(id, "off").is_err() {
            self.api.server_action(id, "poweroff")?;
            self.wait_for(id, "off")?;
        }
        Ok(())
    }

    fn power_on(&self, rec: &BoxRecord) -> Result<()> {
        let id = Self::server_id(rec)?;
        self.api.server_action(id, "poweron")?;
        self.wait_for(id, "running")
    }

    fn set_size(&self, rec: &BoxRecord, size: Size, machine_type: &str) -> Result<()> {
        let id = Self::server_id(rec)?;
        if rec.machine_type.as_deref() != Some(machine_type) {
            self.api.change_type(id, machine_type)?;
        }
        // L and XL share a machine type, so the size is also recorded as a label.
        let mut labels: BTreeMap<String, String> = self.api.get_server(id)?.labels;
        labels.insert(LABEL_SIZE.into(), size.to_string());
        labels.insert(LABEL_MANAGED.into(), "true".into());
        self.api.set_server_labels(id, &labels)
    }

    fn grow_disk(&self, rec: &BoxRecord, gb: DiskGb) -> Result<()> {
        let vol = self.work_volume_id(&rec.spec.name)?;
        self.api.resize_volume(vol, gb)
    }

    fn set_resume_after(&self, rec: &BoxRecord, on: bool) -> Result<()> {
        let id = Self::server_id(rec)?;
        let mut labels = self.api.get_server(id)?.labels;
        if on {
            labels.insert(RESUME_AFTER_LABEL.into(), "true".into());
        } else {
            labels.remove(RESUME_AFTER_LABEL);
        }
        self.api.set_server_labels(id, &labels)
    }

    fn latest_image(&self, _region: Option<&str>) -> Result<ImageInfo> {
        Err(Error::Unsupported {
            provider: PROVIDER_ID.into(),
            what: "find the latest image".into(),
            why: "Hetzner images are named by id or name and carry no release list here; pass --image with the image id".into(),
        })
    }

    /// A Hetzner upgrade to a NEWER image replaces the server with the first-boot configuration rendered now. A server already on
    /// the image it is asked to move to is not replaced to repair its first boot: Hetzner keeps no record of which first boot
    /// a server was made with that this program can compare (a label value holds 63 characters and the hash is 64), and
    /// without that record every upgrade to the same image would replace the server again.
    fn check_reprovision(&self, _rec: &BoxRecord) -> Result<Vec<String>> {
        Err(Error::Unsupported {
            provider: PROVIDER_ID.into(),
            what: "replace a server from the image it already runs".into(),
            why: "Hetzner keeps no record of which first-boot configuration a server was made with, so a server already on the image cannot be checked or repaired in place; upgrade to a newer image, which replaces the server with the first boot this program renders now".into(),
        })
    }

    fn check_upgrade(&self, rec: &BoxRecord, image: &str) -> Result<Vec<String>> {
        let found = self.api.get_image(image)?.ok_or_else(|| {
            Error::Config(format!(
                "image {image} was not found in this Hetzner project"
            ))
        })?;
        if found.status != "available" {
            return Err(Error::Config(format!(
                "image {image} is {}, not available yet; try again when it is",
                found.status
            )));
        }
        let Some(machine) = rec.machine_type.clone() else {
            return Err(Error::Config(format!(
                "{} has no server and its /work volume does not say which server type it ran, so ozbox cannot rebuild it safely. Nothing was changed; the volume is kept.",
                rec.spec.name
            )));
        };
        let want = arch_of_server_type(&machine);
        if found.architecture != want {
            return Err(Error::Unsupported {
                provider: PROVIDER_ID.into(),
                what: format!("upgrade {} to image {image}", rec.spec.name),
                why: format!(
                    "the image is for {} machines and this box runs on {machine} ({want}); resize the box to a matching size first, or choose another image",
                    found.architecture
                ),
            });
        }
        let mut notes = vec![
            UPGRADE_REPLACES_SERVER.to_string(),
            UPGRADE_GAP_NOTE.to_string(),
        ];
        if self.cfg.upgrade_pin.is_some()
            && !rec.spec.labels.contains_key(ozbox_core::APPROVER_LABEL)
        {
            notes.push(
                "This box has no pinned approver: its new first-boot configuration pins this computer's approval key, as `ozbox create` does (the box user cannot change it), so the box can be approved from here and is no longer in bootstrap."
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
            "OpenTofu checked the change first and it {} only the server and its /work attachment; the /work volume is kept ({}).",
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
            // Planned again right before each apply (a saved plan is stale once an apply has run), so what is applied is
            // exactly what was just checked.
            let plan = self.guarded_plan(&vars, gone)?;
            let failed = match self.tofu.apply_replace(&plan) {
                Ok(_) => return self.require_work_attached(&rec.spec.name),
                Err(e) => e,
            };
            // Only a refusal for lack of capacity or a limit is worth another try, and only a few of them.
            if !is_capacity_error(&failed.to_string()) || attempt >= self.cfg.create_retries {
                return Err(failed);
            }
            let pause = self
                .cfg
                .create_backoff
                .saturating_mul(1u32 << attempt.min(16))
                .min(Duration::from_secs(300));
            attempt += 1;
            std::thread::sleep(pause);
            // The old server is normally gone by now (the create is what failed): look, rather than assume.
            gone = !self
                .list()?
                .iter()
                .any(|r| r.spec.name == rec.spec.name && r.state != BoxState::InstanceMissing);
        }
    }

    fn set_upgrade_mark(&self, rec: &BoxRecord, image: Option<&str>) -> Result<()> {
        // The mark lives on the /work volume, because the server it would mark is the thing an upgrade replaces.
        let vol = self.work_volume(&rec.spec.name)?;
        let mut labels = vol.labels.clone();
        match image {
            Some(i) => {
                labels.insert(UPGRADE_TO_LABEL.into(), i.into());
                if let Some(m) = &rec.machine_type {
                    labels.insert(UPGRADE_MACHINE_LABEL.into(), m.clone());
                }
            }
            None => {
                labels.remove(UPGRADE_TO_LABEL);
                labels.remove(UPGRADE_MACHINE_LABEL);
            }
        }
        if labels != vol.labels {
            self.api.set_volume_labels(vol.id, &labels)?;
        }
        // A mark an older rebuild put on the server goes too.
        if image.is_none() {
            if let Ok(id) = Self::server_id(rec) {
                let mut s = self.api.get_server(id)?.labels;
                if s.remove(UPGRADE_TO_LABEL).is_some() {
                    self.api.set_server_labels(id, &s)?;
                }
            }
        }
        Ok(())
    }

    fn check_destroy_missing(&self, rec: &BoxRecord) -> Result<Vec<String>> {
        // The /work volume must be exactly one managed volume of this box, with no server: the same check every other
        // action on a stranded box makes.
        let vol = self.work_volume(&rec.spec.name)?;
        if vol.server.is_some() {
            return Err(Error::Provider(format!(
                "the /work volume of {} is attached to a server; nothing was changed",
                rec.spec.name
            )));
        }
        let how = if self.tofu.has_workspace(&rec.spec.name)? {
            "OpenTofu will destroy what its state still holds, including the /work volume and the firewall, and the box's workspace is removed"
        } else {
            "this computer holds no OpenTofu state for the box, so the /work volume is deleted directly (the box's firewall is left; delete it in the Hetzner console)"
        };
        Ok(vec![format!(
            "Volume {} (/work of {}) is deleted for good: {how}. Snapshots of the box are kept.",
            vol.id, rec.spec.name
        )])
    }

    fn snapshot_subject(&self) -> String {
        "the machine's root disk (NOT /work: Hetzner Cloud cannot snapshot volumes)".into()
    }

    fn snapshot(&self, rec: &BoxRecord) -> Result<String> {
        let id = Self::server_id(rec)?;
        let mut labels = BTreeMap::new();
        labels.insert(LABEL_MANAGED.to_string(), "true".to_string());
        labels.insert(LABEL_BOX.to_string(), rec.spec.name.to_string());
        let image = self
            .api
            .create_snapshot(id, &format!("ozbox {}", rec.spec.name), &labels)?;
        Ok(image.to_string())
    }

    fn list_snapshots(&self, rec: &BoxRecord) -> Result<Vec<SnapshotInfo>> {
        let mut images: Vec<_> = self
            .api
            .list_snapshots()?
            .into_iter()
            .filter(|i| i.labels.get(LABEL_BOX).map(String::as_str) == Some(rec.spec.name.as_str()))
            .collect();
        images.sort_by(|a, b| (&a.created, a.id).cmp(&(&b.created, b.id)));
        Ok(images
            .into_iter()
            .map(|i| SnapshotInfo {
                id: i.id.to_string(),
                kind: SnapshotKind::Provider,
                created_at: i.created,
                // Hetzner reports the size in GB (decimal); the figure is the root disk's, never /work's.
                size_bytes: i.image_size_gb.map(|g| (g * 1_000_000_000.0) as u64),
                status: match i.status.as_str() {
                    "available" => "completed".into(),
                    "creating" => "pending".into(),
                    _ => "error".into(),
                },
                // Hetzner Cloud cannot snapshot volumes: this is the machine's root disk only.
                includes_work: false,
                labels: i.labels,
            })
            .collect())
    }

    fn check_delete_snapshots(&self, _rec: &BoxRecord) -> Result<()> {
        Ok(())
    }

    fn snapshot_price(&self) -> Option<SnapshotPrice> {
        // Hetzner bills a snapshot per GB (decimal) of its size, in euros; the rate is the list price and can change.
        Some(SnapshotPrice {
            per_gb_month: 0.012,
            currency_prefix: "EUR ",
            bytes_per_gb: 1_000_000_000,
        })
    }

    fn delete_snapshot(&self, rec: &BoxRecord, id: &str) -> Result<()> {
        // Only an image Oz Box labelled for THIS box is deleted; the id alone proves nothing.
        let found = self.list_snapshots(rec)?;
        let Some(snap) = found.iter().find(|s| s.id == id) else {
            return Err(Error::NotFound(format!(
                "snapshot {id} of {}",
                rec.spec.name
            )));
        };
        let numeric: u64 = snap
            .id
            .parse()
            .map_err(|_| Error::Provider("a snapshot id from Hetzner is not a number".into()))?;
        self.api.delete_image(numeric)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::api::HcloudApi as Api;
    use crate::testing::{Sim, SimRunner};
    use ozbox_core::{Provider, RecordingRunner};
    use ozbox_provider_fake::conformance::{self, Harness};

    type TestResult = std::result::Result<(), Box<dyn std::error::Error>>;

    fn provider(sim: &Arc<Sim>) -> Engine<HcloudBackend> {
        let cfg = HcloudConfig {
            region: Some("fsn1".into()),
            image: Some("img-1".into()),
            poll_interval: Duration::ZERO,
            create_retries: 0,
            create_backoff: Duration::ZERO,
            ..HcloudConfig::default()
        };
        Engine::new(HcloudBackend::new(
            sim.clone(),
            Arc::new(SimRunner::new(sim.clone())),
            cfg,
        ))
    }

    fn provider_with(sim: &Arc<Sim>, f: impl FnOnce(&mut HcloudConfig)) -> Engine<HcloudBackend> {
        let mut cfg = HcloudConfig {
            region: Some("fsn1".into()),
            image: Some("img-1".into()),
            poll_interval: Duration::ZERO,
            create_retries: 0,
            create_backoff: Duration::ZERO,
            ..HcloudConfig::default()
        };
        f(&mut cfg);
        Engine::new(HcloudBackend::new(
            sim.clone(),
            Arc::new(SimRunner::new(sim.clone())),
            cfg,
        ))
    }

    const NO_CAPACITY: &str =
        "Hetzner API POST /servers: HTTP 412: error during placement (resource_unavailable)";

    #[test]
    fn size_mapping_meets_or_exceeds_each_size() -> TestResult {
        // vCPU / GB of the CCX types we map to.
        let ccx = |t: &str| match t {
            "ccx23" => (4, 16),
            "ccx33" => (8, 32),
            "ccx43" => (16, 64),
            "ccx53" => (32, 128),
            other => panic!("unexpected type {other}"),
        };
        for s in Size::STANDARD {
            let c = machine_choice(s)?;
            let (v, m) = ccx(&c.machine_type);
            assert!(v >= s.spec().vcpus && m >= s.spec().memory_gb, "{s}");
        }
        assert!(machine_choice(Size::L)?.note.is_some());
        assert!(machine_choice(Size::XL)?.note.is_none());
        // XS has no 4/8 dedicated type here: it says so, and an unlabelled ccx23 stays S.
        assert!(machine_choice(Size::XS)?.note.is_some());
        assert_eq!(machine_choice(Size::XS)?.machine_type, "ccx23");
        assert_eq!(sizes_by_type_priority().len(), Size::STANDARD.len());
        for s in Size::STANDARD {
            assert!(sizes_by_type_priority().contains(&s));
        }
        Ok(())
    }

    #[test]
    fn gpu_sizes_are_unsupported_with_a_reason() {
        for s in ["GPU-S", "GPU-L"] {
            let size: Size = s.parse().unwrap_or(Size::S);
            match machine_choice(size) {
                Err(Error::Unsupported { why, .. }) => assert!(why.contains("GPU")),
                other => panic!("expected Unsupported, got {other:?}"),
            }
        }
    }

    #[test]
    fn passes_the_conformance_suite() -> TestResult {
        let sim = Arc::new(Sim::new());
        let p = provider(&sim);
        let hook = sim.clone();
        let force = move |n: &BoxName, s: BoxState| hook.force_state(n, s);
        let work_hook = sim.clone();
        let work_id = move |n: &BoxName| -> Result<String> {
            work_hook
                .work_volume_of(n)
                .map(|v| v.to_string())
                .ok_or_else(|| Error::NotFound(n.to_string()))
        };
        let interrupt_hook = sim.clone();
        let interrupt = move |n: &BoxName, image: &str| interrupt_hook.interrupt_upgrade(n, image);
        let refuse_hook = sim.clone();
        let refuse_next_create = move || -> Result<()> {
            refuse_hook.fail_creates(1, NO_CAPACITY);
            Ok(())
        };
        conformance::run_all(&Harness {
            provider: &p,
            force_state: &force,
            secrets: vec!["hc-s3ntinel-token".into()],
            image: Some("img-1".into()),
            upgrade: Some(conformance::UpgradeKit {
                image: "img-2".into(),
                wrong_arch_image: Some("img-arm".into()),
                work_id: &work_id,
                interrupt: &interrupt,
                // The old server is removed before the new one is created: there is a moment in which it does not exist.
                refuse_next_create: Some(&refuse_next_create),
                no_machine_probe: None,
                no_final_snapshot_without_machine: true,
            }),
        })?;
        Ok(())
    }

    fn box_with_snaps(
        sim: &Arc<Sim>,
        p: &Engine<HcloudBackend>,
        name: &str,
        n: usize,
    ) -> TestResult {
        let b = BoxName::new(name)?;
        p.apply(&p.plan(&Operation::Create {
            spec: BoxSpec::new(b.clone(), Size::S),
        })?)?;
        for _ in 0..n {
            p.apply(&p.plan(&Operation::Snapshot { name: b.clone() })?)?;
        }
        sim.clear_api_log();
        Ok(())
    }

    #[test]
    fn snapshots_are_listed_as_root_disk_images_that_do_not_hold_work() -> TestResult {
        let sim = Arc::new(Sim::new());
        let p = provider(&sim);
        box_with_snaps(&sim, &p, "one", 2)?;
        box_with_snaps(&sim, &p, "two", 1)?;
        sim.add_foreign_image(777);
        let list = p.snapshots(&BoxName::new("one")?)?;
        assert_eq!(list.len(), 2);
        assert!(list.iter().all(|s| s.kind == SnapshotKind::Provider
            && !s.includes_work
            && s.status == "completed"
            && s.size_bytes == Some(2_500_000_000)));
        assert!(!list.iter().any(|s| s.id == "777"));
        Ok(())
    }

    #[test]
    fn a_snapshot_without_work_is_never_a_restore_source_and_never_a_clone_source() -> TestResult {
        let sim = Arc::new(Sim::new());
        let p = provider(&sim);
        box_with_snaps(&sim, &p, "one", 1)?;
        let one = BoxName::new("one")?;
        let id = p.snapshots(&one)?[0].id.clone();
        match p.plan(&Operation::RestoreWork {
            name: one.clone(),
            snapshot: id.clone(),
        }) {
            Err(Error::Unsupported { why, .. }) => {
                assert!(why.contains("does not contain /work"), "{why}");
            }
            other => panic!("expected Unsupported, got {other:?}"),
        }
        assert!(matches!(
            p.plan(&Operation::Clone {
                from: one,
                to: BoxName::new("copy")?,
                snapshot: Some(id),
            }),
            Err(Error::Unsupported { .. })
        ));
        Ok(())
    }

    #[test]
    fn deleting_a_snapshot_removes_only_that_image_and_refuses_one_that_is_not_the_boxs(
    ) -> TestResult {
        let sim = Arc::new(Sim::new());
        let p = provider(&sim);
        box_with_snaps(&sim, &p, "one", 2)?;
        box_with_snaps(&sim, &p, "two", 1)?;
        sim.add_foreign_image(777);
        let one = BoxName::new("one")?;
        let mine = p.snapshots(&one)?[0].id.clone();
        let theirs = p.snapshots(&BoxName::new("two")?)?[0].id.clone();
        for id in [theirs.as_str(), "777"] {
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
        sim.clear_api_log();
        p.apply(&plan)?;
        assert!(sim
            .api_log()
            .iter()
            .any(|l| l == &format!("delete_image {mine}")));
        assert_eq!(p.snapshots(&one)?.len(), 1);
        assert_eq!(p.snapshots(&BoxName::new("two")?)?.len(), 1);
        Ok(())
    }

    #[test]
    fn an_image_still_being_made_is_listed_as_pending() -> TestResult {
        let sim = Arc::new(Sim::new());
        let p = provider(&sim);
        box_with_snaps(&sim, &p, "one", 1)?;
        let one = BoxName::new("one")?;
        let id: u64 = p.snapshots(&one)?[0].id.parse()?;
        sim.set_image_status(id, "creating");
        assert_eq!(p.snapshots(&one)?[0].status, "pending");
        Ok(())
    }

    fn created(
        p: &Engine<HcloudBackend>,
        name: &str,
    ) -> std::result::Result<BoxRecord, Box<dyn std::error::Error>> {
        let mut spec = BoxSpec::new(BoxName::new(name)?, Size::S);
        spec.labels.insert("team".into(), "example".into());
        Ok(p.apply(&p.plan(&Operation::Create { spec })?)?
            .ok_or("no record")?)
    }

    fn upgrade_op(name: &BoxName, image: &str) -> Operation {
        Operation::Upgrade {
            name: name.clone(),
            image: image.into(),
            reprovision: false,
            keep_old_system_disk: false,
        }
    }

    /// The `tofu plan` calls that asked for a replacement, and the `tofu apply` calls of a saved plan.
    fn replace_plans_and_applies(sim: &Sim) -> (usize, usize) {
        let calls = sim.tofu_calls();
        let tofu = |c: &ozbox_core::CommandSpec, w: &str| c.args.iter().any(|a| a == w);
        (
            calls
                .iter()
                .filter(|c| tofu(c, "plan") && c.args.iter().any(|a| a.starts_with("-replace=")))
                .count(),
            calls
                .iter()
                .filter(|c| tofu(c, "apply") && c.args.iter().any(|a| a.ends_with(".tfplan")))
                .count(),
        )
    }

    /// A server an upgrade makes records the first-boot configuration this program renders, as a server made by `create` does:
    /// the hash is in the variables of the plan that replaces it. (Main's first-boot record, kept through this branch's replace.)
    #[test]
    fn the_replacement_server_records_the_programs_first_boot_hash() -> TestResult {
        let sim = Arc::new(Sim::new());
        let hash = "ab".repeat(32);
        let p = provider_with(&sim, |c| c.first_boot_sha256 = Some(hash.clone()));
        let n = created(&p, "main")?.spec.name;
        let made = format!("first_boot_sha256={hash}");
        assert!(
            sim.tofu_calls().iter().any(|c| c.args.contains(&made)),
            "create passes it"
        );
        let before = sim.tofu_calls().len();
        p.apply(&p.plan(&upgrade_op(&n, "img-2"))?)?;
        let replace_plans: Vec<_> = sim
            .tofu_calls()
            .into_iter()
            .skip(before)
            .filter(|c| {
                c.args.iter().any(|a| a == "plan")
                    && c.args.iter().any(|a| a.starts_with("-replace="))
            })
            .collect();
        assert!(!replace_plans.is_empty());
        assert!(
            replace_plans.iter().all(|c| c.args.contains(&made)),
            "the replace is planned with the program's first-boot hash, so an upgraded box is not stale: {replace_plans:?}"
        );
        Ok(())
    }

    /// The decision (kept from main, with this branch's replace): a server already on the image is not replaced "to repair its
    /// first boot", because Hetzner has no record to compare; an upgrade to another image replaces it.
    #[test]
    fn a_same_image_reprovision_stays_refused_on_hetzner_and_a_new_image_replaces_the_server(
    ) -> TestResult {
        let sim = Arc::new(Sim::new());
        let p = provider(&sim);
        let n = created(&p, "main")?.spec.name;
        let rec = p.get(&n)?.ok_or("no box")?;
        assert!(matches!(
            p.check_reprovision(&rec),
            Err(Error::Unsupported { .. })
        ));
        let old = sim.server_of(&n);
        p.apply(&p.plan(&upgrade_op(&n, "img-2"))?)?;
        assert_ne!(sim.server_of(&n), old, "a new server");
        assert!(p.plan(&upgrade_op(&n, "img-2"))?.is_noop());
        Ok(())
    }

    #[test]
    fn a_server_made_without_its_work_attachment_is_not_a_finished_upgrade_and_running_upgrade_again_attaches_it(
    ) -> TestResult {
        let sim = Arc::new(Sim::new());
        let p = provider(&sim);
        let before = created(&p, "main")?;
        let n = before.spec.name.clone();
        let volume = sim.work_volume_of(&n);
        // the apply creates the new server and fails before /work is attached to it
        sim.fail_attach(true);
        let plan = p.plan(&upgrade_op(&n, "img-2"))?;
        let err = p
            .apply(&plan)
            .err()
            .ok_or("the apply was meant to fail")?
            .to_string();
        assert!(err.contains("attachment"), "{err}");
        let stuck = p
            .list()?
            .into_iter()
            .find(|r| r.spec.name == n)
            .ok_or("gone")?;
        assert_eq!(
            stuck.spec.labels.get(UPGRADE_TO_LABEL).map(String::as_str),
            Some("img-2"),
            "the mark stays until /work is attached"
        );
        assert_eq!(stuck.spec.image, None, "not shown as on the new image");
        // upgrading again plans the replacement again (not just 'mark it finished') and attaches /work
        let again = p.plan(&upgrade_op(&n, "img-2"))?;
        assert!(
            again
                .changes
                .iter()
                .any(|c| c.kind == "instance.replace_image"),
            "{:?}",
            again.changes
        );
        let done = p.apply(&again)?.ok_or("no record")?;
        assert_eq!(done.spec.image.as_deref(), Some("img-2"));
        assert_eq!(sim.work_volume_of(&n), volume, "the same /work volume");
        assert_eq!(sim.work_attached_to(&n), sim.server_of(&n));
        assert!(!done.spec.labels.contains_key(UPGRADE_TO_LABEL), "finished");
        Ok(())
    }

    #[test]
    fn an_apply_that_reports_success_without_attaching_work_is_an_error_and_keeps_the_mark(
    ) -> TestResult {
        let sim = Arc::new(Sim::new());
        let p = provider(&sim);
        let n = created(&p, "main")?.spec.name;
        sim.fail_attach(false);
        let plan = p.plan(&upgrade_op(&n, "img-2"))?;
        let err = p
            .apply(&plan)
            .err()
            .ok_or("the apply was meant to fail")?
            .to_string();
        assert!(err.contains("not attached"), "{err}");
        let r = p
            .list()?
            .into_iter()
            .find(|r| r.spec.name == n)
            .ok_or("gone")?;
        assert!(r.spec.labels.contains_key(UPGRADE_TO_LABEL));
        Ok(())
    }

    #[test]
    fn an_upgrade_replaces_the_server_through_a_checked_plan_and_keeps_the_work_volume(
    ) -> TestResult {
        let sim = Arc::new(Sim::new());
        let p = provider(&sim);
        let before = created(&p, "main")?;
        let n = before.spec.name.clone();
        assert_eq!(before.spec.image.as_deref(), Some("img-1"));
        let volume = sim.work_volume_of(&n);
        let old_server = sim.server_of(&n);
        sim.clear_api_log();
        let plan = p.plan(&upgrade_op(&n, "img-2"))?;
        // the plan says what replacing means: the first-boot configuration is delivered, the address is not kept
        assert!(
            plan.notes
                .iter()
                .any(|x| x == UPGRADE_REPLACES_SERVER && x.contains("NEW address")),
            "{:?}",
            plan.notes
        );
        assert!(plan.notes.iter().any(|x| x == UPGRADE_GAP_NOTE));
        assert!(
            plan.notes
                .iter()
                .any(|x| x
                    .contains("OpenTofu checked the change first and it replaces only the server")),
            "{:?}",
            plan.notes
        );
        assert!(
            sim.api_log()
                .iter()
                .all(|l| !l.starts_with("action") && !l.starts_with("set_")),
            "planning only reads: {:?}",
            sim.api_log()
        );
        // the plan itself was read-only: OpenTofu planned, and nothing was applied
        assert_eq!(replace_plans_and_applies(&sim), (1, 0));
        let after = p.apply(&plan)?.ok_or("no record")?;
        assert_eq!(after.state, BoxState::Running);
        assert_eq!(after.spec.image.as_deref(), Some("img-2"));
        assert_ne!(after.provider_id, before.provider_id, "a new server");
        assert_ne!(sim.server_of(&n), old_server);
        assert_eq!(sim.work_volume_of(&n), volume, "the same /work volume");
        assert_eq!(after.spec.work_disk_gb, before.spec.work_disk_gb);
        assert_eq!(after.spec.region.as_deref(), Some("fsn1"));
        // planned again right before the apply, and the apply was of the saved plan
        let (plans, applies) = replace_plans_and_applies(&sim);
        assert_eq!(
            (plans, applies),
            (3, 1),
            "check, then plan again, then apply: {plans} {applies}"
        );
        // the box's own labels came through; the marks did not stay on anything
        assert_eq!(
            after.spec.labels.get("team").map(String::as_str),
            Some("example")
        );
        assert!(!after.spec.labels.contains_key(UPGRADE_TO_LABEL));
        let marks = sim.volume_labels(&n).ok_or("no volume")?;
        assert!(
            !marks.contains_key("ozbox-upgrade-to") && !marks.contains_key("ozbox-upgrade-machine")
        );
        // the mark was durable before the old server went (the engine marks, stops, then replaces)
        let log = sim.api_log();
        let at = |needle: &str| log.iter().position(|l| l.starts_with(needle));
        let mark = at("set_volume_labels").ok_or("no mark on the volume")?;
        let off = at("action shutdown").ok_or("no stop")?;
        assert!(mark < off, "{log:?}");
        assert!(sim.api_log().iter().all(|l| !l.starts_with("rebuild")));
        // a finished upgrade plans to nothing
        assert!(p.plan(&upgrade_op(&n, "img-2"))?.is_noop());
        Ok(())
    }

    #[test]
    fn the_replacement_is_passed_the_box_as_it_is_now_where_it_really_is() -> TestResult {
        let sim = Arc::new(Sim::new());
        // the configuration names another location than the one the box is in
        let p = provider_with(&sim, |c| c.region = Some("fsn1".into()));
        let before = created(&p, "main")?;
        let n = before.spec.name.clone();
        let q = provider_with(&sim, |c| c.region = Some("nbg1".into()));
        let b = q.get(&n)?.ok_or("no box")?;
        assert_eq!(
            b.spec.region.as_deref(),
            Some("fsn1"),
            "the box's own location"
        );
        sim.clear_api_log();
        let plan = q.plan(&upgrade_op(&n, "img-2"))?;
        q.apply(&plan)?;
        let calls = sim.tofu_calls();
        let applied: Vec<_> = calls
            .iter()
            .filter(|c| {
                c.args.iter().any(|a| a == "plan")
                    && c.args.iter().any(|a| a.starts_with("-replace="))
            })
            .collect();
        assert!(!applied.is_empty());
        for c in applied {
            assert!(c.args.contains(&"region=fsn1".to_string()), "{:?}", c.args);
            assert!(c.args.contains(&"image_id=img-2".to_string()));
            assert!(c.args.contains(&"machine_type=ccx23".to_string()));
            assert!(
                c.args.iter().any(|a| a.starts_with("labels=")
                    && a.contains("\"team\"=\"example\"")
                    && !a.contains("ozbox-upgrade")),
                "{:?}",
                c.args
            );
            assert!(c.args.iter().any(|a| a == "-replace=hcloud_server.box"));
        }
        Ok(())
    }

    #[test]
    fn a_plan_that_would_touch_the_work_volume_is_refused_before_anything_is_stopped() -> TestResult
    {
        let sim = Arc::new(Sim::new());
        let p = provider(&sim);
        let n = created(&p, "main")?.spec.name;
        sim.plan_replaces_volume();
        sim.clear_api_log();
        let e = p
            .plan(&upgrade_op(&n, "img-2"))
            .err()
            .ok_or("must be refused")?;
        assert!(e.to_string().contains("hcloud_volume.work"), "{e}");
        assert!(
            sim.api_log()
                .iter()
                .all(|l| !l.starts_with("action") && !l.starts_with("set_")),
            "{:?}",
            sim.api_log()
        );
        assert_eq!(replace_plans_and_applies(&sim).1, 0);
        Ok(())
    }

    #[test]
    fn a_box_this_computer_has_no_state_for_is_pointed_at_adopt() -> TestResult {
        let sim = Arc::new(Sim::new());
        let p = provider(&sim);
        let n = created(&p, "main")?.spec.name;
        sim.forget_workspace(&n);
        let e = p
            .plan(&upgrade_op(&n, "img-2"))
            .err()
            .ok_or("must be refused")?;
        assert!(e.to_string().contains("ozbox adopt main"), "{e}");
        Ok(())
    }

    #[test]
    fn a_box_with_no_pinned_approver_gets_this_computers_key_and_the_plan_says_so() -> TestResult {
        const PIN: &str = "abcdefghijklmnopqrstuvwxyz234567abcdefghijklmnopqrst";
        let sim = Arc::new(Sim::new());
        let p = provider(&sim);
        let n = created(&p, "main")?.spec.name;
        let pinned = provider_with(&sim, |c| c.upgrade_pin = Some(PIN.into()));
        let plan = pinned.plan(&upgrade_op(&n, "img-2"))?;
        assert!(
            plan.notes.iter().any(|x| x.contains("no pinned approver")),
            "{:?}",
            plan.notes
        );
        pinned.apply(&plan)?;
        let tofu_labels = sim
            .tofu_calls()
            .into_iter()
            .filter(|c| c.args.iter().any(|a| a.starts_with("-replace=")))
            .flat_map(|c| c.args)
            .filter(|a| a.starts_with("labels="))
            .collect::<Vec<_>>();
        assert!(
            tofu_labels.iter().all(|l| l.contains(PIN)),
            "{tofu_labels:?}"
        );
        // a box that already has one keeps it, and the plan stays quiet about it
        let mut spec = BoxSpec::new(BoxName::new("keeps")?, Size::S);
        spec.labels.insert(
            ozbox_core::APPROVER_LABEL.into(),
            "zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz".into(),
        );
        let k = p
            .apply(&p.plan(&Operation::Create { spec })?)?
            .ok_or("no record")?;
        let plan = pinned.plan(&upgrade_op(&k.spec.name, "img-2"))?;
        assert!(!plan.notes.iter().any(|x| x.contains("no pinned approver")));
        Ok(())
    }

    #[test]
    fn a_box_with_no_ingress_key_gets_this_computers_and_a_box_with_one_keeps_its_own() -> TestResult
    {
        const PIN: &str = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
        const THEIRS: &str = "cccccccccccccccccccccccccccccccccccccccccccccccccccc";
        let sim = Arc::new(Sim::new());
        let p = provider(&sim);
        let n = created(&p, "main")?.spec.name;
        let pinned = provider_with(&sim, |c| c.upgrade_ingress_pin = Some(PIN.into()));
        let plan = pinned.plan(&upgrade_op(&n, "img-2"))?;
        assert!(
            plan.notes.iter().any(|x| x.contains("ingress account")),
            "{:?}",
            plan.notes
        );
        pinned.apply(&plan)?;
        let labels = sim
            .tofu_calls()
            .into_iter()
            .filter(|c| c.args.iter().any(|a| a.starts_with("-replace=")))
            .flat_map(|c| c.args)
            .filter(|a| a.starts_with("labels="))
            .collect::<Vec<_>>();
        assert!(
            !labels.is_empty() && labels.iter().all(|l| l.contains(PIN)),
            "{labels:?}"
        );
        let mut spec = BoxSpec::new(BoxName::new("keeps")?, Size::S);
        spec.labels
            .insert(ozbox_core::INGRESS_LABEL.into(), THEIRS.into());
        let k = p
            .apply(&p.plan(&Operation::Create { spec })?)?
            .ok_or("no record")?;
        let plan = pinned.plan(&upgrade_op(&k.spec.name, "img-2"))?;
        assert!(!plan.notes.iter().any(|x| x.contains("ingress account")));
        Ok(())
    }

    #[test]
    fn a_server_that_cannot_be_created_right_now_is_tried_again_and_other_failures_are_not(
    ) -> TestResult {
        let sim = Arc::new(Sim::new());
        let p = provider_with(&sim, |c| {
            c.create_retries = 3;
            c.create_backoff = Duration::from_millis(1);
        });
        let n = created(&p, "main")?.spec.name;
        // out of stock twice, then it works: one upgrade, three applies of a saved plan
        sim.fail_creates(2, NO_CAPACITY);
        let plan = p.plan(&upgrade_op(&n, "img-2"))?;
        let after = p.apply(&plan)?.ok_or("no record")?;
        assert_eq!(after.state, BoxState::Running);
        assert_eq!(after.spec.image.as_deref(), Some("img-2"));
        assert_eq!(replace_plans_and_applies(&sim).1, 3);
        // an error that is not about capacity is not retried
        let other = created(&p, "second")?.spec.name;
        let before = replace_plans_and_applies(&sim).1;
        sim.fail_next_replace_apply();
        let plan = p.plan(&upgrade_op(&other, "img-2"))?;
        assert!(p.apply(&plan).is_err());
        assert_eq!(
            replace_plans_and_applies(&sim).1,
            before + 1,
            "one try, no retry"
        );
        Ok(())
    }

    #[test]
    fn capacity_errors_are_told_from_other_failures_by_the_text_hetzner_returns() {
        assert!(is_capacity_error(NO_CAPACITY));
        assert!(is_capacity_error(
            "Error: resource_limit_exceeded: server limit reached"
        ));
        assert!(is_capacity_error("placement_error"));
        assert!(!is_capacity_error("HTTP 401: unauthorized"));
        assert!(!is_capacity_error("name is already used"));
    }

    #[test]
    fn a_box_whose_server_is_gone_is_listed_as_missing_from_its_volume_and_destroyed_with_it(
    ) -> TestResult {
        let sim = Arc::new(Sim::new());
        let p = provider(&sim);
        let n = created(&p, "gone")?.spec.name;
        let volume = sim.work_volume_of(&n);
        sim.fail_creates(1, NO_CAPACITY);
        assert!(p.apply(&p.plan(&upgrade_op(&n, "img-2"))?).is_err());
        let stuck = p.get(&n)?.ok_or("not listed")?;
        assert_eq!(stuck.state, BoxState::InstanceMissing);
        assert_eq!(stuck.provider_id, None);
        assert_eq!(stuck.machine_type.as_deref(), Some("ccx23"));
        assert_eq!(stuck.spec.size, Size::S);
        assert_eq!(stuck.spec.region.as_deref(), Some("fsn1"));
        assert_eq!(
            stuck.spec.labels.get(UPGRADE_TO_LABEL).map(String::as_str),
            Some("img-2")
        );
        assert_eq!(sim.work_volume_of(&n), volume);
        // the finish plans only a creation, with the guard, and never a replacement of the volume
        let finish = p.plan(&upgrade_op(&n, "img-2"))?;
        assert!(
            finish
                .notes
                .iter()
                .any(|x| x
                    .contains("OpenTofu checked the change first and it creates only the server")),
            "{:?}",
            finish.notes
        );
        assert!(finish.changes.iter().any(|c| c.kind == "instance.create"));
        // destroying it goes through OpenTofu when its state is here, and directly through the API when it is not
        // a final snapshot has nothing to capture (the server is gone and a volume cannot be snapshotted), and the plan says so
        match p.plan(&Operation::Destroy {
            name: n.clone(),
            final_snapshot: true,
            keep_old_system_disks: false,
            delete_snapshots: false,
        }) {
            Err(Error::Unsupported { why, .. }) => {
                assert!(why.contains("cannot be snapshotted"), "{why}")
            }
            other => panic!("expected Unsupported, got {other:?}"),
        }
        sim.forget_workspace(&n);
        let destroy = p.plan(&Operation::Destroy {
            name: n.clone(),
            final_snapshot: false,
            keep_old_system_disks: false,
            delete_snapshots: false,
        })?;
        assert!(
            destroy
                .notes
                .iter()
                .any(|x| x.contains("holds no OpenTofu state") && x.contains("deleted directly")),
            "{:?}",
            destroy.notes
        );
        sim.clear_api_log();
        p.apply(&destroy)?;
        assert!(
            sim.api_log().iter().any(|l| l.starts_with("delete_volume")),
            "{:?}",
            sim.api_log()
        );
        assert!(p.get(&n)?.is_none());
        Ok(())
    }

    #[test]
    fn a_stranded_volume_that_is_not_marked_is_not_a_box() -> TestResult {
        let sim = Arc::new(Sim::new());
        let p = provider(&sim);
        let n = created(&p, "plain")?.spec.name;
        // a volume with no server and no upgrade mark is something a person removed on purpose, not an interrupted upgrade
        sim.fail_creates(1, NO_CAPACITY);
        assert!(p.apply(&p.plan(&upgrade_op(&n, "img-2"))?).is_err());
        let v = sim.work_volume_of(&n).ok_or("no volume")?;
        let mut labels = sim.volume_labels(&n).ok_or("no labels")?;
        labels.remove("ozbox-upgrade-to");
        Api::set_volume_labels(&*sim, v, &labels)?;
        assert!(p.get(&n)?.is_none());
        Ok(())
    }

    #[test]
    fn hetzner_images_are_refused_while_planning_when_missing_unavailable_or_for_arm() -> TestResult
    {
        let sim = Arc::new(Sim::new());
        let p = provider(&sim);
        let n = BoxName::new("picky")?;
        p.apply(&p.plan(&Operation::Create {
            spec: BoxSpec::new(n.clone(), Size::S),
        })?)?;
        let why = |image: &str| -> Result<String> {
            Ok(p.plan(&Operation::Upgrade {
                name: n.clone(),
                image: image.into(),
                reprovision: false,
                keep_old_system_disk: false,
            })
            .err()
            .ok_or_else(|| Error::Provider(format!("{image} must be refused")))?
            .to_string())
        };
        assert!(why("img-arm")?.contains("arm machines") || why("img-arm")?.contains("for arm"));
        assert!(why("img-pending")?.contains("not available yet"));
        assert!(why("img-nope")?.contains("was not found"));
        assert!(matches!(
            p.latest_image(None),
            Err(Error::Unsupported { .. })
        ));
        Ok(())
    }

    #[test]
    fn instance_architecture_follows_the_server_type_family() {
        assert_eq!(arch_of_server_type("ccx33"), "x86");
        assert_eq!(arch_of_server_type("cax21"), "arm");
    }

    #[test]
    fn create_runs_the_module_with_the_mapped_type_and_reads_the_record_back() -> TestResult {
        let sim = Arc::new(Sim::new());
        let p = provider(&sim);
        let mut spec = BoxSpec::new(BoxName::new("dev")?, Size::L);
        spec.work_disk_gb = 120;
        spec.labels.insert("purpose".into(), "review".into());
        let plan = p.plan(&Operation::Create { spec })?;
        assert!(plan.notes.iter().any(|n| n.contains("ccx43")));
        let rec = p.apply(&plan)?.ok_or("no record")?;
        assert_eq!(rec.machine_type.as_deref(), Some("ccx43"));
        assert_eq!(rec.spec.size, Size::L);
        assert_eq!(rec.spec.work_disk_gb, 120);
        assert_eq!(rec.state, BoxState::Running);
        assert_eq!(
            rec.spec.labels.get("purpose").map(String::as_str),
            Some("review")
        );
        let calls = sim.tofu_calls();
        let apply = calls
            .iter()
            .find(|c| c.args.iter().any(|a| a == "apply"))
            .ok_or("no tofu apply")?;
        assert_eq!(apply.program, "tofu");
        for want in [
            "box_name=dev",
            "machine_type=ccx43",
            "work_disk_gb=120",
            "image_id=img-1",
            "region=fsn1",
            // size L: six agent runs at once
            "runs_max_active=6",
        ] {
            assert!(apply.args.iter().any(|a| a == want), "missing {want}");
        }
        assert!(apply
            .args
            .iter()
            .any(|a| a.starts_with("labels=") && a.contains("\"ozbox-size\"=\"L\"")));
        Ok(())
    }

    #[test]
    fn l_and_xl_share_a_type_so_resizing_between_them_only_relabels() -> TestResult {
        let sim = Arc::new(Sim::new());
        let p = provider(&sim);
        let n = BoxName::new("lx")?;
        p.apply(&p.plan(&Operation::Create {
            spec: BoxSpec::new(n.clone(), Size::L),
        })?)?;
        let plan = p.plan(&Operation::Resize {
            name: n.clone(),
            size: Some(Size::XL),
            work_disk_gb: None,
        })?;
        let kinds: Vec<_> = plan.changes.iter().map(|c| c.kind.as_str()).collect();
        assert_eq!(kinds, ["box.relabel"]);
        let rec = p.apply(&plan)?.ok_or("no record")?;
        assert_eq!(rec.spec.size, Size::XL);
        assert_eq!(rec.state, BoxState::Running, "nothing restarted");
        Ok(())
    }

    #[test]
    fn resize_stops_changes_type_grows_the_volume_and_starts() -> TestResult {
        let sim = Arc::new(Sim::new());
        let p = provider(&sim);
        let n = BoxName::new("grow")?;
        p.apply(&p.plan(&Operation::Create {
            spec: BoxSpec::new(n.clone(), Size::S),
        })?)?;
        sim.clear_api_log();
        let plan = p.plan(&Operation::Resize {
            name: n.clone(),
            size: Some(Size::M),
            work_disk_gb: Some(400),
        })?;
        let rec = p.apply(&plan)?.ok_or("no record")?;
        assert_eq!(rec.machine_type.as_deref(), Some("ccx33"));
        assert_eq!(rec.spec.work_disk_gb, 400);
        let log = sim.api_log();
        let pos = |s: &str| log.iter().position(|l| l.starts_with(s));
        let (off, ty, vol, on) = (
            pos("action shutdown"),
            pos("change_type"),
            pos("resize_volume"),
            pos("action poweron"),
        );
        assert!(
            off.is_some() && ty.is_some() && vol.is_some() && on.is_some(),
            "{log:?}"
        );
        assert!(off < ty && ty < on && vol < on, "{log:?}");
        assert!(log.iter().any(|l| l.contains("ccx33")));
        Ok(())
    }

    #[test]
    fn snapshots_carry_the_volume_limitation_note() -> TestResult {
        let sim = Arc::new(Sim::new());
        let p = provider(&sim);
        let n = BoxName::new("snap")?;
        p.apply(&p.plan(&Operation::Create {
            spec: BoxSpec::new(n.clone(), Size::S),
        })?)?;
        let plan = p.plan(&Operation::Snapshot { name: n.clone() })?;
        assert!(plan
            .notes
            .iter()
            .any(|x| x.contains("cannot snapshot volumes")));
        let rec = p.apply(&plan)?.ok_or("no record")?;
        assert_eq!(rec.snapshots.len(), 1);
        Ok(())
    }

    #[test]
    fn destroy_runs_tofu_destroy_in_the_boxs_workspace() -> TestResult {
        let sim = Arc::new(Sim::new());
        let p = provider(&sim);
        let n = BoxName::new("bye")?;
        p.apply(&p.plan(&Operation::Create {
            spec: BoxSpec::new(n.clone(), Size::S),
        })?)?;
        let plan = p.plan(&Operation::Destroy {
            name: n.clone(),
            final_snapshot: false,
            keep_old_system_disks: false,
            delete_snapshots: false,
        })?;
        assert!(p.apply(&plan)?.is_none());
        let calls = sim.tofu_calls();
        assert!(calls.iter().any(|c| c.args.iter().any(|a| a == "destroy")
            && c.args.iter().any(|a| a == "-auto-approve")));
        assert!(calls.iter().any(|c| c
            .args
            .windows(3)
            .any(|w| w == ["workspace", "select", "bye"])));
        assert!(p.get(&n)?.is_none());
        Ok(())
    }

    #[test]
    fn clone_is_unsupported_at_plan_time_and_runs_nothing() -> TestResult {
        let sim = Arc::new(Sim::new());
        let p = provider(&sim);
        let a = BoxName::new("src")?;
        p.apply(&p.plan(&Operation::Create {
            spec: BoxSpec::new(a.clone(), Size::S),
        })?)?;
        let before = sim.tofu_calls().len();
        let res = p.plan(&Operation::Clone {
            from: a,
            to: BoxName::new("copy")?,
            snapshot: None,
        });
        assert!(matches!(res, Err(Error::Unsupported { why, .. }) if why.contains("snapshot")));
        assert_eq!(sim.tofu_calls().len(), before);
        Ok(())
    }

    #[test]
    fn a_server_type_oz_box_does_not_map_is_unknown_and_never_acted_on() -> TestResult {
        let sim = Arc::new(Sim::new());
        sim.add_server("odd", "cx22", "running");
        let p = provider(&sim);
        let n = BoxName::new("odd")?;
        let rec = p.get(&n)?.ok_or("missing")?;
        assert_eq!(rec.state, BoxState::Unknown);
        for op in [
            Operation::Pause { name: n.clone() },
            Operation::Resume { name: n.clone() },
            Operation::Snapshot { name: n.clone() },
            Operation::Destroy {
                name: n.clone(),
                final_snapshot: true,
                keep_old_system_disks: false,
                delete_snapshots: false,
            },
        ] {
            assert!(
                matches!(p.plan(&op), Err(Error::InvalidState { .. })),
                "{} on an unmapped box",
                op.verb()
            );
        }
        Ok(())
    }

    #[test]
    fn every_snapshot_plan_says_work_is_not_included() -> TestResult {
        let sim = Arc::new(Sim::new());
        let p = provider(&sim);
        let n = BoxName::new("note")?;
        p.apply(&p.plan(&Operation::Create {
            spec: BoxSpec::new(n.clone(), Size::S),
        })?)?;
        for op in [
            Operation::Snapshot { name: n.clone() },
            Operation::Destroy {
                name: n.clone(),
                final_snapshot: true,
                keep_old_system_disks: false,
                delete_snapshots: false,
            },
        ] {
            let plan = p.plan(&op)?;
            assert!(
                plan.notes
                    .iter()
                    .any(|x| x.contains("/work is NOT included")),
                "{}",
                op.verb()
            );
            let snap = plan
                .changes
                .iter()
                .find(|c| c.kind == "snapshot.create")
                .ok_or("no snapshot change")?;
            assert!(
                snap.description.contains("NOT /work"),
                "{}",
                snap.description
            );
        }
        Ok(())
    }

    /// Variable names in the module's variables.tf, and which have a default.
    fn module_variables() -> std::result::Result<Vec<(String, bool)>, Box<dyn std::error::Error>> {
        let path = concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../infra/tofu/modules/hcloud-box/variables.tf"
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
            declared.len() >= 7,
            "parsed too few variables: {declared:?}"
        );
        let sim = Arc::new(Sim::new());
        let mk = |region: Option<&str>| {
            let cfg = HcloudConfig {
                region: region.map(str::to_string),
                image: Some("img-1".into()),
                ..HcloudConfig::default()
            };
            HcloudBackend::new(sim.clone(), Arc::new(SimRunner::new(sim.clone())), cfg)
        };
        let mut spec = BoxSpec::new(BoxName::new("v")?, Size::S);
        spec.labels.insert("a".into(), "b".into());
        // The most the adapter ever passes (it still never passes a snapshot).
        spec.from_snapshot = Some("123".into());
        let all = passed(&mk(Some("fsn1")).vars(&spec, "ccx23"));
        // The least it passes after check_create has accepted the request.
        let always =
            passed(&mk(Some("fsn1")).vars(&BoxSpec::new(BoxName::new("v")?, Size::S), "ccx23"));
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
        assert!(!all.iter().any(|v| v == "work_snapshot_id"));
        Ok(())
    }

    #[test]
    fn create_without_a_location_is_refused_while_planning() -> TestResult {
        let sim = Arc::new(Sim::new());
        let cfg = HcloudConfig {
            image: Some("img-1".into()),
            ..HcloudConfig::default()
        };
        let p = Engine::new(HcloudBackend::new(
            sim.clone(),
            Arc::new(SimRunner::new(sim.clone())),
            cfg,
        ));
        let res = p.plan(&Operation::Create {
            spec: BoxSpec::new(BoxName::new("x")?, Size::S),
        });
        assert!(matches!(res, Err(Error::Config(m)) if m.contains("--region")));
        Ok(())
    }

    #[test]
    fn the_resume_mark_round_trips_through_labels() -> TestResult {
        let sim = Arc::new(Sim::new());
        let p = provider(&sim);
        let n = BoxName::new("mark")?;
        p.apply(&p.plan(&Operation::Create {
            spec: BoxSpec::new(n.clone(), Size::S),
        })?)?;
        let rec = p.get(&n)?.ok_or("missing")?;
        p.backend().set_resume_after(&rec, true)?;
        let marked = p.get(&n)?.ok_or("missing")?;
        assert_eq!(
            marked
                .spec
                .labels
                .get(RESUME_AFTER_LABEL)
                .map(String::as_str),
            Some("true")
        );
        p.backend().set_resume_after(&marked, false)?;
        assert!(!p
            .get(&n)?
            .ok_or("missing")?
            .spec
            .labels
            .contains_key(RESUME_AFTER_LABEL));
        Ok(())
    }

    #[test]
    fn the_module_is_never_given_a_snapshot_to_restore() -> TestResult {
        let sim = Arc::new(Sim::new());
        let p = provider(&sim);
        p.apply(&p.plan(&Operation::Create {
            spec: BoxSpec::new(BoxName::new("plain")?, Size::S),
        })?)?;
        assert!(!sim
            .tofu_calls()
            .iter()
            .any(|c| c.args.iter().any(|a| a.starts_with("work_snapshot_id"))));
        Ok(())
    }

    #[test]
    fn create_without_any_image_is_refused_while_planning() -> TestResult {
        let sim = Arc::new(Sim::new());
        let cfg = HcloudConfig::default();
        let rec_runner = Arc::new(RecordingRunner::new());
        let p = Engine::new(HcloudBackend::new(sim, rec_runner.clone(), cfg));
        let res = p.plan(&Operation::Create {
            spec: BoxSpec::new(BoxName::new("x")?, Size::S),
        });
        assert!(matches!(res, Err(Error::Config(m)) if m.contains("--image")));
        assert!(rec_runner.calls().is_empty(), "planning ran a command");
        Ok(())
    }

    #[test]
    fn gpu_create_is_unsupported_at_plan_time() -> TestResult {
        let sim = Arc::new(Sim::new());
        let p = provider(&sim);
        let size: Size = "GPU-S".parse()?;
        let res = p.plan(&Operation::Create {
            spec: BoxSpec::new(BoxName::new("g")?, size),
        });
        assert!(matches!(res, Err(Error::Unsupported { .. })));
        Ok(())
    }

    #[test]
    fn api_failures_do_not_leak_the_token_through_the_provider() -> TestResult {
        let sim = Arc::new(Sim::new());
        sim.fail_with("HTTP 500: boom");
        let p = provider(&sim);
        let err = p.list().err().ok_or("expected an error")?;
        assert!(err.to_string().contains("boom"));
        assert!(!err.to_string().contains("hc-s3ntinel-token"));
        Ok(())
    }

    #[test]
    fn pausing_a_box_with_a_pending_restart_clears_the_mark() -> TestResult {
        let sim = Arc::new(Sim::new());
        let p = provider(&sim);
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
}
