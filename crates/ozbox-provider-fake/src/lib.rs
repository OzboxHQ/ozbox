//! A provider whose "cloud" is one JSON file in a directory.
//!
//! It exists so the CLI and the test suite run end to end without credentials or money (ADR 0003), and so the
//! shared [`conformance`] suite has a reference implementation to prove against. Planning is shared with every
//! other provider through [`ozbox_core::Engine`]; this crate only supplies the primitive actions.
//!
//! State lives in `<dir>/state.json` and is written atomically (temp file + rename).

pub mod conformance;

use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use ozbox_core::{
    Backend, BoxName, BoxRecord, BoxSpec, BoxState, Capabilities, DiskGb, Engine, Error, ImageInfo,
    MachineChoice, OldWorkDisk, ResizeMethod, Result, Size, SnapshotInfo, SnapshotKind,
    RESUME_AFTER_LABEL, UPGRADE_TO_LABEL,
};
use serde::{Deserialize, Serialize};

pub const PROVIDER_ID: &str = "fake";

/// The newest image the fake's imaginary account can see (`upgrade --image latest`).
pub const LATEST_IMAGE: &str = "fake-image-2026.12.0";

/// The fake's capabilities (no I/O): usable for `ozbox providers` without a state directory.
pub fn capabilities() -> Capabilities {
    Capabilities {
        resize: ResizeMethod::StopChangeStart,
        online_disk_grow: true,
        disk_shrink: false,
        snapshots: true,
        sizes: Size::STANDARD
            .iter()
            .copied()
            .chain([
                Size::Gpu(ozbox_core::GpuKind::Small),
                Size::Gpu(ozbox_core::GpuKind::Large),
            ])
            .collect(),
    }
}

/// The fake's machine type for a size, e.g. `fake-8vcpu-32gb`. Never fails.
pub fn machine_type_for(size: Size) -> String {
    let s = size.spec();
    if s.gpus > 0 {
        format!("fake-{}vcpu-{}gb-{}gpu", s.vcpus, s.memory_gb, s.gpus)
    } else {
        format!("fake-{}vcpu-{}gb", s.vcpus, s.memory_gb)
    }
}

/// Open the fake provider over a state directory (created on first write).
pub fn open(dir: impl Into<PathBuf>) -> Engine<FakeBackend> {
    Engine::new(FakeBackend::new(dir))
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct Retained {
    id: String,
    from_box: String,
}

#[derive(Debug, Default, Serialize, Deserialize)]
struct State {
    next_id: u64,
    boxes: BTreeMap<String, BoxRecord>,
    /// Snapshots whose box was destroyed. Snapshots are independent of the box, as on a real cloud.
    retained_snapshots: Vec<Retained>,
    /// The identity of each box's `/work` disk, fixed at create. An upgrade replaces the machine, never this.
    #[serde(default)]
    works: BTreeMap<String, u64>,
    /// The `/work` disks restores replaced and kept, by box name.
    #[serde(default)]
    old_works: BTreeMap<String, Vec<OldWorkDisk>>,
    /// Make the next machine an upgrade creates fail, after the old one is gone (the account refused it).
    #[serde(default)]
    refuse_next_create: bool,
    /// Make the sandbox's newest image report an unverified signature (for testing the refusal).
    #[serde(default)]
    unsigned_images: bool,
    /// Lines the sandbox's `latest` reports as candidates it passed over (for testing that a plan names them).
    #[serde(default)]
    latest_skipped: Vec<String>,
    /// When each snapshot was taken and how large its disk was, by snapshot id.
    #[serde(default)]
    snapshot_meta: BTreeMap<String, SnapMeta>,
    /// Copies of old system disks that upgrades kept; never `/work` backups.
    #[serde(default)]
    system_copies: Vec<SystemCopy>,
}

/// A copy of a machine's system disk an upgrade kept (the sandbox's stand-in for a provider snapshot of it).
#[derive(Debug, Clone, Serialize, Deserialize)]
struct SystemCopy {
    id: String,
    box_name: String,
    /// The image the upgrade that took it was going to.
    image: String,
    created_at: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct SnapMeta {
    created_at: String,
    size_bytes: u64,
}

#[derive(Debug, Clone)]
pub struct FakeBackend {
    dir: PathBuf,
}

impl FakeBackend {
    pub fn new(dir: impl Into<PathBuf>) -> Self {
        Self { dir: dir.into() }
    }

    /// The identity of a box's `/work` disk (changes only if the disk itself is replaced, which no operation does).
    pub fn work_id(&self, name: &BoxName) -> Result<String> {
        let state = self.load()?;
        state
            .works
            .get(name.as_str())
            .map(|w| format!("fake-work-{w}"))
            .ok_or_else(|| Error::NotFound(name.to_string()))
    }

    pub fn state_file(&self) -> PathBuf {
        self.dir.join("state.json")
    }

    fn load(&self) -> Result<State> {
        match fs::read_to_string(self.state_file()) {
            Ok(text) => Ok(serde_json::from_str(&text)?),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(State::default()),
            Err(e) => Err(e.into()),
        }
    }

    fn save(&self, state: &State) -> Result<()> {
        fs::create_dir_all(&self.dir)?;
        let tmp = self
            .dir
            .join(format!("state.json.tmp.{}", std::process::id()));
        fs::write(&tmp, serde_json::to_vec_pretty(state)?)?;
        fs::rename(&tmp, self.state_file())?;
        Ok(())
    }

    /// Run `f` on the loaded state and save it. A failed `f` saves nothing.
    fn mutate<T>(&self, f: impl FnOnce(&mut State) -> Result<T>) -> Result<T> {
        let mut state = self.load()?;
        let out = f(&mut state)?;
        self.save(&state)?;
        Ok(out)
    }

    /// The next machine an upgrade creates is refused (a quota or capacity error), after the old machine was removed:
    /// the box is left with no machine and its `/work` disk. Not part of any contract.
    pub fn refuse_next_create(&self) -> Result<()> {
        self.mutate(|s| {
            s.refuse_next_create = true;
            Ok(())
        })
    }

    /// The sandbox's newest image reports that its signature could not be verified. Not part of any contract.
    pub fn mark_images_unsigned(&self) -> Result<()> {
        self.mutate(|s| {
            s.unsigned_images = true;
            Ok(())
        })
    }

    /// Force a box into a state (for tests: how a box ends up mid-transition). Not part of any contract.
    pub fn force_state(&self, name: &BoxName, to: BoxState) -> Result<()> {
        self.mutate(|s| {
            let rec = s
                .boxes
                .get_mut(name.as_str())
                .ok_or_else(|| Error::NotFound(name.to_string()))?;
            rec.state = to;
            Ok(())
        })
    }
}

fn entry<'a>(state: &'a mut State, rec: &BoxRecord) -> Result<&'a mut BoxRecord> {
    state
        .boxes
        .get_mut(rec.spec.name.as_str())
        .ok_or_else(|| Error::NotFound(rec.spec.name.to_string()))
}

fn require_state(rec: &BoxRecord, want: BoxState, action: &'static str) -> Result<()> {
    if rec.state == want {
        Ok(())
    } else {
        Err(Error::InvalidState {
            name: rec.spec.name.to_string(),
            state: rec.state,
            action,
        })
    }
}

impl Backend for FakeBackend {
    fn id(&self) -> &str {
        PROVIDER_ID
    }

    fn capabilities(&self) -> Capabilities {
        capabilities()
    }

    fn machine_choice(&self, size: Size) -> Result<MachineChoice> {
        Ok(MachineChoice::new(machine_type_for(size)))
    }

    fn list(&self) -> Result<Vec<BoxRecord>> {
        Ok(self.load()?.boxes.into_values().collect())
    }

    fn create(&self, spec: &BoxSpec, machine_type: &str) -> Result<BoxRecord> {
        self.mutate(|s| {
            if s.boxes.contains_key(spec.name.as_str()) {
                return Err(Error::AlreadyExists(spec.name.to_string()));
            }
            if let Some(snap) = &spec.from_snapshot {
                let known = s.retained_snapshots.iter().any(|r| &r.id == snap)
                    || s.boxes.values().any(|b| b.snapshots.contains(snap));
                if !known {
                    return Err(Error::Provider(format!(
                        "no snapshot {snap:?} to restore from"
                    )));
                }
            }
            s.next_id += 1;
            s.works.insert(spec.name.to_string(), s.next_id);
            let rec = BoxRecord {
                spec: spec.clone(),
                state: BoxState::Running,
                provider: PROVIDER_ID.into(),
                provider_id: Some(format!("fake-{}", s.next_id)),
                machine_type: Some(machine_type.to_string()),
                snapshots: Vec::new(),
                created_at: Some(now_rfc3339()),
                last_activity_at: None,
            };
            s.boxes.insert(spec.name.to_string(), rec.clone());
            Ok(rec)
        })
    }

    fn destroy(&self, rec: &BoxRecord) -> Result<()> {
        self.mutate(|s| {
            let gone = s
                .boxes
                .remove(rec.spec.name.as_str())
                .ok_or_else(|| Error::NotFound(rec.spec.name.to_string()))?;
            s.works.remove(rec.spec.name.as_str());
            s.old_works.remove(rec.spec.name.as_str());
            for id in gone.snapshots {
                s.retained_snapshots.push(Retained {
                    id,
                    from_box: gone.spec.name.to_string(),
                });
            }
            Ok(())
        })
    }

    fn power_off(&self, rec: &BoxRecord) -> Result<()> {
        self.mutate(|s| {
            let e = entry(s, rec)?;
            require_state(e, BoxState::Running, "paused")?;
            e.state = BoxState::Paused;
            Ok(())
        })
    }

    fn power_on(&self, rec: &BoxRecord) -> Result<()> {
        self.mutate(|s| {
            let e = entry(s, rec)?;
            require_state(e, BoxState::Paused, "resumed")?;
            e.state = BoxState::Running;
            Ok(())
        })
    }

    fn set_size(&self, rec: &BoxRecord, size: Size, machine_type: &str) -> Result<()> {
        self.mutate(|s| {
            let e = entry(s, rec)?;
            e.spec.size = size;
            e.machine_type = Some(machine_type.to_string());
            Ok(())
        })
    }

    fn grow_disk(&self, rec: &BoxRecord, gb: DiskGb) -> Result<()> {
        self.mutate(|s| {
            let e = entry(s, rec)?;
            if gb < e.spec.work_disk_gb {
                return Err(Error::Provider("a disk cannot shrink".into()));
            }
            e.spec.work_disk_gb = gb;
            Ok(())
        })
    }

    fn set_resume_after(&self, rec: &BoxRecord, on: bool) -> Result<()> {
        self.mutate(|s| {
            let e = entry(s, rec)?;
            if on {
                e.spec
                    .labels
                    .insert(RESUME_AFTER_LABEL.to_string(), "true".to_string());
            } else {
                e.spec.labels.remove(RESUME_AFTER_LABEL);
            }
            Ok(())
        })
    }

    fn latest_image(&self, _region: Option<&str>) -> Result<ImageInfo> {
        let state = self.load()?;
        let (unsigned, latest_skipped) = (state.unsigned_images, state.latest_skipped);
        Ok(ImageInfo {
            id: LATEST_IMAGE.to_string(),
            release: Some("2026.12.0".into()),
            created: Some("2026-12-01T00:00:00Z".into()),
            // The sandbox's images are simulated: there is no workflow that signed them, so nothing was checked and
            // nothing is claimed. `signature_applicable: false` tells the upgrade gate there is nothing to refuse on.
            // (The real check is `ozbox_core::ReleaseVerifier`, tested on its own and through the AWS adapter.)
            signature_verified: false,
            signature_detail: Some(if unsigned {
                "the sandbox's newest image is marked unsigned".to_string()
            } else {
                "simulated: the sandbox has no signed releases to check".to_string()
            }),
            signature_applicable: unsigned,
            first_boot_sha256: None,
            upgrade: None,
            skipped: latest_skipped,
        })
    }

    /// The sandbox's machines are simulated: a replace on the same image is as good as any other.
    fn check_reprovision(&self, _rec: &BoxRecord) -> Result<Vec<String>> {
        Ok(Vec::new())
    }

    fn check_upgrade(&self, _rec: &BoxRecord, image: &str) -> Result<Vec<String>> {
        // The fake's machines are amd64; an image id that says arm64 cannot boot on them.
        if image.contains("arm64") {
            return Err(Error::Unsupported {
                provider: PROVIDER_ID.into(),
                what: format!("upgrade to image {image}"),
                why: "the image is for arm64 machines and this box is amd64".into(),
            });
        }
        Ok(Vec::new())
    }

    fn check_destroy_missing(&self, _rec: &BoxRecord) -> Result<Vec<String>> {
        Ok(vec![
            "The fake provider keeps no machine for this box; only its /work disk is deleted."
                .into(),
        ])
    }

    fn replace_image(&self, rec: &BoxRecord, image: &str) -> Result<()> {
        let refused = self.mutate(|s| {
            let refuse = std::mem::take(&mut s.refuse_next_create);
            s.next_id += 1;
            let new_id = format!("fake-{}", s.next_id);
            let e = entry(s, rec)?;
            if e.state != BoxState::InstanceMissing {
                require_state(e, BoxState::Paused, "rebuilt")?;
            }
            if refuse {
                // The old machine is gone; the new one was refused. /work and the upgrade mark stay.
                e.state = BoxState::InstanceMissing;
                e.provider_id = None;
                return Ok(true);
            }
            // The machine is replaced (a new id); the /work disk, snapshots and labels carry over untouched.
            e.spec.image = Some(image.to_string());
            if e.state == BoxState::InstanceMissing {
                e.state = BoxState::Running;
                e.provider_id = Some(new_id);
            }
            Ok(false)
        })?;
        if refused {
            return Err(Error::Provider(
                "the account refused the new machine (VcpuLimitExceeded: injected)".into(),
            ));
        }
        Ok(())
    }

    fn set_upgrade_mark(&self, rec: &BoxRecord, image: Option<&str>) -> Result<()> {
        self.mutate(|s| {
            let e = entry(s, rec)?;
            match image {
                Some(i) => {
                    e.spec
                        .labels
                        .insert(UPGRADE_TO_LABEL.to_string(), i.to_string());
                }
                None => {
                    e.spec.labels.remove(UPGRADE_TO_LABEL);
                }
            }
            Ok(())
        })
    }

    fn snapshot(&self, rec: &BoxRecord) -> Result<String> {
        self.mutate(|s| {
            s.next_id += 1;
            let id = format!("fake-snap-{}", s.next_id);
            let e = entry(s, rec)?;
            e.snapshots.push(id.clone());
            let size_bytes = u64::from(e.spec.work_disk_gb) * 1_000_000_000 / 10;
            s.snapshot_meta.insert(
                id.clone(),
                SnapMeta {
                    created_at: now_rfc3339(),
                    size_bytes,
                },
            );
            Ok(id)
        })
    }

    fn check_system_disk_snapshot(&self, rec: &BoxRecord) -> Result<Option<String>> {
        Ok(Some(format!(
            "Keep a copy of the OLD system disk of {} (the sandbox keeps a simulated one)",
            rec.spec.name
        )))
    }

    fn snapshot_system_disk(
        &self,
        rec: &BoxRecord,
        image: &str,
        _max_wait: Option<std::time::Duration>,
    ) -> Result<String> {
        self.mutate(|s| {
            s.next_id += 1;
            let id = format!("fake-root-snap-{}", s.next_id);
            let box_name = entry(s, rec)?.spec.name.to_string();
            s.system_copies.push(SystemCopy {
                id: id.clone(),
                box_name,
                image: image.to_string(),
                created_at: now_rfc3339(),
            });
            Ok(id)
        })
    }

    fn list_snapshots(&self, rec: &BoxRecord) -> Result<Vec<SnapshotInfo>> {
        let state = self.load()?;
        let e = state
            .boxes
            .get(rec.spec.name.as_str())
            .ok_or_else(|| Error::NotFound(rec.spec.name.to_string()))?;
        let work = e.snapshots.iter().map(|id| {
            let meta = state.snapshot_meta.get(id);
            SnapshotInfo {
                id: id.clone(),
                kind: SnapshotKind::Provider,
                created_at: meta.map(|m| m.created_at.clone()),
                size_bytes: meta.map(|m| m.size_bytes),
                status: "completed".into(),
                includes_work: true,
                labels: BTreeMap::from([("ozbox-box".to_string(), e.spec.name.to_string())]),
            }
        });
        let copies = state
            .system_copies
            .iter()
            .filter(|c| c.box_name == rec.spec.name.as_str())
            .map(|c| SnapshotInfo {
                id: c.id.clone(),
                kind: SnapshotKind::Provider,
                created_at: Some(c.created_at.clone()),
                size_bytes: None,
                status: "completed".into(),
                includes_work: false,
                labels: BTreeMap::from([
                    ("ozbox-box".to_string(), c.box_name.clone()),
                    ("ozbox-purpose".to_string(), "pre-upgrade-root".to_string()),
                    (UPGRADE_TO_LABEL.to_string(), c.image.clone()),
                ]),
            });
        Ok(work.chain(copies).collect())
    }

    fn delete_snapshot(&self, rec: &BoxRecord, id: &str) -> Result<()> {
        self.mutate(|s| {
            let e = entry(s, rec)?;
            let before = e.snapshots.len();
            e.snapshots.retain(|x| x != id);
            if e.snapshots.len() == before {
                // a copy of an old system disk is deleted the same way
                let copies = s.system_copies.len();
                s.system_copies
                    .retain(|c| !(c.id == id && c.box_name == rec.spec.name.as_str()));
                if s.system_copies.len() == copies {
                    return Err(Error::NotFound(format!("snapshot {id}")));
                }
                return Ok(());
            }
            s.snapshot_meta.remove(id);
            Ok(())
        })
    }

    fn check_restore_work(&self, _rec: &BoxRecord, _snap: &SnapshotInfo) -> Result<Vec<String>> {
        Ok(vec![
            "The sandbox swaps a simulated disk; nothing real is replaced.".into(),
        ])
    }

    fn replace_work(&self, rec: &BoxRecord, id: &str) -> Result<()> {
        self.mutate(|s| {
            let e = entry(s, rec)?;
            require_state(e, BoxState::Paused, "restored")?;
            if !e.snapshots.iter().any(|x| x == id) {
                return Err(Error::NotFound(format!("snapshot {id}")));
            }
            let name = rec.spec.name.to_string();
            let old = s.works.get(&name).copied().unwrap_or(0);
            s.next_id += 1;
            s.works.insert(name.clone(), s.next_id);
            // The replaced disk is kept, not deleted: a person removes it with a separate, confirmed action.
            s.old_works.entry(name).or_default().push(OldWorkDisk {
                id: format!("fake-disk-{old}"),
                size_gb: Some(rec.spec.work_disk_gb),
                restored_from: Some(id.to_string()),
                state: "kept".into(),
            });
            Ok(())
        })
    }

    fn list_old_work(&self, rec: &BoxRecord) -> Result<Vec<OldWorkDisk>> {
        Ok(self
            .load()?
            .old_works
            .get(rec.spec.name.as_str())
            .cloned()
            .unwrap_or_default())
    }

    fn delete_old_work(&self, rec: &BoxRecord, id: &str) -> Result<()> {
        self.mutate(|s| {
            let list = s.old_works.entry(rec.spec.name.to_string()).or_default();
            let before = list.len();
            list.retain(|d| d.id != id);
            if list.len() == before {
                return Err(Error::NotFound(format!("old /work disk {id}")));
            }
            Ok(())
        })
    }
}

/// Seconds since the epoch as an RFC 3339 UTC timestamp, without a date crate.
fn now_rfc3339() -> String {
    let secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    rfc3339_from_unix(secs)
}

fn rfc3339_from_unix(secs: u64) -> String {
    let days = (secs / 86_400) as i64;
    let rem = secs % 86_400;
    // Howard Hinnant's civil-from-days.
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1_460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = if m <= 2 { y + 1 } else { y };
    format!(
        "{y:04}-{m:02}-{d:02}T{:02}:{:02}:{:02}Z",
        rem / 3600,
        (rem % 3600) / 60,
        rem % 60
    )
}

/// Where the CLI keeps fake state when `OZBOX_STATE_DIR` is not set.
pub fn default_state_dir(home: &Path) -> PathBuf {
    home.join(".local/share/ozbox/fake")
}

#[cfg(test)]
mod tests {
    use super::*;
    use conformance::Harness;
    use ozbox_core::{Operation, Plan, Provider};

    type TestResult = std::result::Result<(), Box<dyn std::error::Error>>;

    #[test]
    fn timestamps_are_rfc3339() {
        assert_eq!(rfc3339_from_unix(0), "1970-01-01T00:00:00Z");
        assert_eq!(rfc3339_from_unix(1_782_864_000), "2026-07-01T00:00:00Z");
    }

    #[test]
    fn passes_the_conformance_suite() -> TestResult {
        let dir = tempfile::tempdir()?;
        let backend = FakeBackend::new(dir.path());
        let hook = backend.clone();
        let provider = Engine::new(backend);
        let force = move |n: &BoxName, s: BoxState| hook.force_state(n, s);
        let work_hook = provider.backend().clone();
        let work_id = move |n: &BoxName| work_hook.work_id(n);
        let refuse_hook = provider.backend().clone();
        let refuse_next_create = move || refuse_hook.refuse_next_create();
        let interrupt_hook = provider.backend().clone();
        let interrupt = move |n: &BoxName, image: &str| -> Result<()> {
            // What an upgrade leaves behind when it dies right after the stop.
            let rec = interrupt_hook
                .list()?
                .into_iter()
                .find(|r| &r.spec.name == n)
                .ok_or_else(|| Error::NotFound(n.to_string()))?;
            interrupt_hook.set_upgrade_mark(&rec, Some(image))?;
            interrupt_hook.power_off(&rec)
        };
        let h = Harness {
            provider: &provider,
            force_state: &force,
            secrets: vec!["s3ntinel-secret".into()],
            image: None,
            upgrade: Some(conformance::UpgradeKit {
                image: "fake-image-2".into(),
                wrong_arch_image: Some("fake-image-arm64".into()),
                work_id: &work_id,
                interrupt: &interrupt,
                refuse_next_create: Some(&refuse_next_create),
                no_machine_probe: None,
                no_final_snapshot_without_machine: false,
            }),
        };
        conformance::run_all(&h)?;
        Ok(())
    }

    #[test]
    fn state_survives_a_new_handle_and_is_one_file() -> TestResult {
        let dir = tempfile::tempdir()?;
        let name = BoxName::new("keeper")?;
        {
            let p = open(dir.path());
            let plan = p.plan(&Operation::Create {
                spec: BoxSpec::new(name.clone(), Size::M),
            })?;
            p.apply(&plan)?;
        }
        let p = open(dir.path());
        let rec = p.get(&name)?.ok_or("box missing after reopen")?;
        assert_eq!(rec.state, BoxState::Running);
        assert_eq!(rec.machine_type.as_deref(), Some("fake-8vcpu-32gb"));
        let files: Vec<_> = fs::read_dir(dir.path())?.collect::<std::io::Result<_>>()?;
        assert_eq!(files.len(), 1, "no temp files left behind");
        Ok(())
    }

    #[test]
    fn a_restore_replaces_the_work_disk_after_taking_the_way_back_and_restarts_the_box(
    ) -> TestResult {
        let dir = tempfile::tempdir()?;
        let p = open(dir.path());
        let n = BoxName::new("main")?;
        p.apply(&p.plan(&Operation::Create {
            spec: BoxSpec::new(n.clone(), Size::S),
        })?)?;
        p.apply(&p.plan(&Operation::Snapshot { name: n.clone() })?)?;
        let first = p.snapshots(&n)?[0].id.clone();
        let before = p.backend().work_id(&n)?;
        let plan = p.plan(&Operation::RestoreWork {
            name: n.clone(),
            snapshot: first.clone(),
        })?;
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
        let rec = p.apply(&plan)?.ok_or("no record")?;
        assert_eq!(rec.state, BoxState::Running);
        assert_ne!(p.backend().work_id(&n)?, before, "a new /work disk");
        assert_eq!(rec.snapshots.len(), 2, "the way back was taken first");
        // a paused box stays paused
        p.apply(&p.plan(&Operation::Pause { name: n.clone() })?)?;
        let plan = p.plan(&Operation::RestoreWork {
            name: n.clone(),
            snapshot: first,
        })?;
        assert!(!plan.changes.iter().any(|c| c.kind == "instance.stop"));
        assert_eq!(p.apply(&plan)?.ok_or("no record")?.state, BoxState::Paused);
        Ok(())
    }

    #[test]
    fn a_clone_can_name_the_snapshot_it_restores_from() -> TestResult {
        let dir = tempfile::tempdir()?;
        let p = open(dir.path());
        let (a, b) = (BoxName::new("src")?, BoxName::new("copy")?);
        p.apply(&p.plan(&Operation::Create {
            spec: BoxSpec::new(a.clone(), Size::S),
        })?)?;
        for _ in 0..2 {
            p.apply(&p.plan(&Operation::Snapshot { name: a.clone() })?)?;
        }
        let first = p.snapshots(&a)?[0].id.clone();
        let plan = p.plan(&Operation::Clone {
            from: a.clone(),
            to: b.clone(),
            snapshot: Some(first.clone()),
        })?;
        assert!(plan.changes.iter().any(|c| c.description.contains(&first)));
        let rec = p.apply(&plan)?.ok_or("no record")?;
        assert_eq!(rec.spec.from_snapshot.as_deref(), Some(first.as_str()));
        assert_eq!(
            p.get(&a)?.ok_or("gone")?.snapshots.len(),
            2,
            "no new snapshot was taken"
        );
        let ghost = p.plan(&Operation::Clone {
            from: a,
            to: BoxName::new("other")?,
            snapshot: Some("nope".into()),
        });
        assert!(matches!(ghost, Err(Error::NotFound(_))));
        Ok(())
    }

    #[test]
    fn clone_without_a_snapshot_shows_the_snapshot_as_a_change() -> TestResult {
        let dir = tempfile::tempdir()?;
        let p = open(dir.path());
        let a = BoxName::new("src")?;
        let b = BoxName::new("copy")?;
        p.apply(&p.plan(&Operation::Create {
            spec: BoxSpec::new(a.clone(), Size::S),
        })?)?;
        let plan = p.plan(&Operation::Clone {
            from: a.clone(),
            to: b.clone(),
            snapshot: None,
        })?;
        let kinds: Vec<_> = plan.changes.iter().map(|c| c.kind.as_str()).collect();
        assert_eq!(kinds, ["snapshot.create", "box.create"]);
        let rec = p.apply(&plan)?.ok_or("no record")?;
        assert!(rec.spec.from_snapshot.is_some());
        assert_eq!(p.get(&a)?.ok_or("src gone")?.snapshots.len(), 1);
        Ok(())
    }

    #[test]
    fn resize_rules() -> TestResult {
        let dir = tempfile::tempdir()?;
        let p = open(dir.path());
        let a = BoxName::new("grow")?;
        p.apply(&p.plan(&Operation::Create {
            spec: BoxSpec::new(a.clone(), Size::S),
        })?)?;
        let plan = p.plan(&Operation::Resize {
            name: a.clone(),
            size: Some(Size::L),
            work_disk_gb: Some(300),
        })?;
        let kinds: Vec<_> = plan.changes.iter().map(|c| c.kind.as_str()).collect();
        assert_eq!(
            kinds,
            [
                "instance.stop",
                "instance.resize",
                "volume.grow",
                "instance.start"
            ]
        );
        assert!(plan.notes.iter().any(|n| n.contains("stops it")));
        let rec = p.apply(&plan)?.ok_or("no record")?;
        assert_eq!(rec.state, BoxState::Running);
        assert_eq!(rec.spec.size, Size::L);
        assert_eq!(rec.spec.work_disk_gb, 300);
        let shrink = p.plan(&Operation::Resize {
            name: a,
            size: None,
            work_disk_gb: Some(100),
        });
        assert!(matches!(shrink, Err(Error::Unsupported { .. })));
        Ok(())
    }

    use std::sync::atomic::{AtomicBool, Ordering};

    /// Delegates to the fake but fails `set_size` once, after the box has been stopped.
    struct Flaky {
        inner: FakeBackend,
        fail_next_set_size: AtomicBool,
        fail_next_replace: AtomicBool,
    }

    impl Backend for Flaky {
        fn id(&self) -> &str {
            self.inner.id()
        }
        fn capabilities(&self) -> Capabilities {
            self.inner.capabilities()
        }
        fn machine_choice(&self, size: Size) -> Result<MachineChoice> {
            self.inner.machine_choice(size)
        }
        fn list(&self) -> Result<Vec<BoxRecord>> {
            self.inner.list()
        }
        fn create(&self, spec: &BoxSpec, mt: &str) -> Result<BoxRecord> {
            self.inner.create(spec, mt)
        }
        fn destroy(&self, rec: &BoxRecord) -> Result<()> {
            self.inner.destroy(rec)
        }
        fn power_off(&self, rec: &BoxRecord) -> Result<()> {
            self.inner.power_off(rec)
        }
        fn power_on(&self, rec: &BoxRecord) -> Result<()> {
            self.inner.power_on(rec)
        }
        fn set_size(&self, rec: &BoxRecord, size: Size, mt: &str) -> Result<()> {
            if self.fail_next_set_size.swap(false, Ordering::SeqCst) {
                return Err(Error::Provider("injected failure after stop".into()));
            }
            self.inner.set_size(rec, size, mt)
        }
        fn grow_disk(&self, rec: &BoxRecord, gb: DiskGb) -> Result<()> {
            self.inner.grow_disk(rec, gb)
        }
        fn snapshot(&self, rec: &BoxRecord) -> Result<String> {
            self.inner.snapshot(rec)
        }
        fn set_resume_after(&self, rec: &BoxRecord, on: bool) -> Result<()> {
            self.inner.set_resume_after(rec, on)
        }
        fn check_upgrade(&self, rec: &BoxRecord, image: &str) -> Result<Vec<String>> {
            self.inner.check_upgrade(rec, image)
        }
        fn replace_image(&self, rec: &BoxRecord, image: &str) -> Result<()> {
            if self.fail_next_replace.swap(false, Ordering::SeqCst) {
                return Err(Error::Provider("injected failure after stop".into()));
            }
            self.inner.replace_image(rec, image)
        }
        fn set_upgrade_mark(&self, rec: &BoxRecord, image: Option<&str>) -> Result<()> {
            self.inner.set_upgrade_mark(rec, image)
        }
    }

    fn flaky(dir: &Path) -> Engine<Flaky> {
        Engine::new(Flaky {
            inner: FakeBackend::new(dir),
            fail_next_set_size: AtomicBool::new(false),
            fail_next_replace: AtomicBool::new(false),
        })
    }

    #[test]
    fn a_real_interruption_after_the_stop_is_finished_by_running_upgrade_again() -> TestResult {
        let dir = tempfile::tempdir()?;
        let p = flaky(dir.path());
        let n = BoxName::new("half-up")?;
        p.apply(&p.plan(&Operation::Create {
            spec: BoxSpec::new(n.clone(), Size::S),
        })?)?;
        let work = p.backend().inner.work_id(&n)?;
        let op = Operation::Upgrade {
            name: n.clone(),
            image: "fake-image-2".into(),
            reprovision: false,
            keep_old_system_disk: false,
        };
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
        assert_eq!(plan.max_risk(), Some(ozbox_core::Risk::Medium));
        assert!(plan
            .changes
            .iter()
            .any(|c| c.description.contains("/work disk is NOT touched")));
        p.backend().fail_next_replace.store(true, Ordering::SeqCst);
        assert!(p.apply(&plan).is_err());
        // Left stopped, on the old image, marked: the state a person finds after a crash.
        let rec = p.get(&n)?.ok_or("gone")?;
        assert_eq!(rec.state, BoxState::Paused);
        assert_eq!(rec.spec.image, None);
        assert_eq!(
            rec.spec.labels.get(UPGRADE_TO_LABEL).map(String::as_str),
            Some("fake-image-2")
        );
        let again = p.plan(&op)?;
        let kinds: Vec<_> = again.changes.iter().map(|c| c.kind.as_str()).collect();
        assert_eq!(
            kinds,
            [
                "instance.replace_image",
                "volume.reattach",
                "instance.start"
            ],
            "already stopped: nothing to stop"
        );
        assert!(again.notes.iter().any(|n| n.contains("did not finish")));
        let rec = p.apply(&again)?.ok_or("no record")?;
        assert_eq!(rec.state, BoxState::Running);
        assert_eq!(rec.spec.image.as_deref(), Some("fake-image-2"));
        assert!(!rec.spec.labels.contains_key(UPGRADE_TO_LABEL));
        assert_eq!(p.backend().inner.work_id(&n)?, work);
        Ok(())
    }

    #[test]
    fn upgrade_finishes_when_the_disk_was_replaced_but_the_mark_was_left() -> TestResult {
        let dir = tempfile::tempdir()?;
        let p = open(dir.path());
        let n = BoxName::new("tail")?;
        p.apply(&p.plan(&Operation::Create {
            spec: BoxSpec::new(n.clone(), Size::S),
        })?)?;
        let rec = p.get(&n)?.ok_or("gone")?;
        // Replaced and running, but the mark is still there (the process died before clearing it).
        p.backend().set_upgrade_mark(&rec, Some("fake-image-2"))?;
        p.backend().power_off(&rec)?;
        p.backend().replace_image(&rec, "fake-image-2")?;
        let op = Operation::Upgrade {
            name: n.clone(),
            image: "fake-image-2".into(),
            reprovision: false,
            keep_old_system_disk: false,
        };
        let plan = p.plan(&op)?;
        let kinds: Vec<_> = plan.changes.iter().map(|c| c.kind.as_str()).collect();
        assert_eq!(kinds, ["instance.start", "upgrade.finish"]);
        let rec = p.apply(&plan)?.ok_or("no record")?;
        assert_eq!(rec.state, BoxState::Running);
        assert!(!rec.spec.labels.contains_key(UPGRADE_TO_LABEL));
        assert!(p.plan(&op)?.is_noop());
        Ok(())
    }

    #[test]
    fn resume_drops_an_unfinished_upgrade_mark_and_says_so() -> TestResult {
        let dir = tempfile::tempdir()?;
        let p = open(dir.path());
        let n = BoxName::new("abandon")?;
        p.apply(&p.plan(&Operation::Create {
            spec: BoxSpec::new(n.clone(), Size::S),
        })?)?;
        let rec = p.get(&n)?.ok_or("gone")?;
        p.backend().set_upgrade_mark(&rec, Some("fake-image-2"))?;
        p.backend().power_off(&rec)?;
        let plan = p.plan(&Operation::Resume { name: n.clone() })?;
        assert!(plan.notes.iter().any(|t| t.contains("did not finish")));
        let rec = p.apply(&plan)?.ok_or("no record")?;
        assert_eq!(rec.state, BoxState::Running);
        assert!(!rec.spec.labels.contains_key(UPGRADE_TO_LABEL));
        Ok(())
    }

    #[test]
    fn upgrading_a_stopped_box_says_it_leaves_it_running() -> TestResult {
        let dir = tempfile::tempdir()?;
        let p = open(dir.path());
        let n = BoxName::new("cold")?;
        p.apply(&p.plan(&Operation::Create {
            spec: BoxSpec::new(n.clone(), Size::S),
        })?)?;
        p.apply(&p.plan(&Operation::Pause { name: n.clone() })?)?;
        let plan = p.plan(&Operation::Upgrade {
            name: n.clone(),
            image: "fake-image-2".into(),
            reprovision: false,
            keep_old_system_disk: false,
        })?;
        assert!(plan.notes.iter().any(|t| t.contains("leaves it running")));
        assert!(plan.changes.iter().all(|c| c.kind != "instance.stop"));
        Ok(())
    }

    /// A box already on the image is left alone, unless it is to be reprovisioned: then the machine is replaced from the
    /// same image (a fresh first boot) and /work is kept, exactly as in an upgrade.
    #[test]
    fn reprovisioning_replaces_the_machine_from_the_same_image() -> TestResult {
        let dir = tempfile::tempdir()?;
        let p = open(dir.path());
        let n = BoxName::new("same")?;
        p.apply(&p.plan(&Operation::Create {
            spec: BoxSpec::new(n.clone(), Size::S),
        })?)?;
        let to = |reprovision| Operation::Upgrade {
            name: n.clone(),
            image: "fake-image-2".into(),
            reprovision,
            keep_old_system_disk: false,
        };
        p.apply(&p.plan(&to(false))?)?;
        assert!(p.plan(&to(false))?.is_noop(), "already on the image");
        let work = p.backend().work_id(&n)?;
        let plan = p.plan(&to(true))?;
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
        assert!(plan.notes.iter().any(|t| t.contains("same image")));
        let rec = p.apply(&plan)?.ok_or("no record")?;
        assert_eq!(rec.state, BoxState::Running);
        assert_eq!(rec.spec.image.as_deref(), Some("fake-image-2"));
        assert_eq!(p.backend().work_id(&n)?, work, "/work is kept");
        Ok(())
    }

    #[test]
    fn latest_image_is_what_the_provider_reports_and_never_claims_a_verified_signature(
    ) -> TestResult {
        let dir = tempfile::tempdir()?;
        let p = open(dir.path());
        let latest = p.latest_image(None)?;
        assert_eq!(latest.id, LATEST_IMAGE);
        assert!(
            !latest.signature_verified,
            "nothing was checked, so nothing is claimed"
        );
        assert!(!latest.signature_applicable);
        assert_eq!(ozbox_core::resolve_image(&p, "latest", None)?, LATEST_IMAGE);
        assert_eq!(ozbox_core::resolve_image(&p, " img-9 ", None)?, "img-9");
        Ok(())
    }

    #[test]
    fn an_interrupted_resize_is_finished_and_restarted_by_running_it_again() -> TestResult {
        let dir = tempfile::tempdir()?;
        let p = flaky(dir.path());
        let n = BoxName::new("half")?;
        p.apply(&p.plan(&Operation::Create {
            spec: BoxSpec::new(n.clone(), Size::S),
        })?)?;
        let op = Operation::Resize {
            name: n.clone(),
            size: Some(Size::M),
            work_disk_gb: Some(300),
        };
        p.backend().fail_next_set_size.store(true, Ordering::SeqCst);
        let plan = p.plan(&op)?;
        assert!(p.apply(&plan).is_err());
        // Stopped, still the old size, and it remembers it was running.
        let mid = p.get(&n)?.ok_or("missing")?;
        assert_eq!(mid.state, BoxState::Paused);
        assert_eq!(mid.spec.size, Size::S);
        assert_eq!(
            mid.spec.labels.get(RESUME_AFTER_LABEL).map(String::as_str),
            Some("true")
        );
        // Re-running the resize finishes it and starts the box.
        let again = p.plan(&op)?;
        let kinds: Vec<_> = again.changes.iter().map(|c| c.kind.as_str()).collect();
        assert_eq!(kinds, ["instance.resize", "volume.grow", "instance.start"]);
        let rec = p.apply(&again)?.ok_or("no record")?;
        assert_eq!(rec.state, BoxState::Running);
        assert_eq!(rec.spec.size, Size::M);
        assert_eq!(rec.spec.work_disk_gb, 300);
        assert!(!rec.spec.labels.contains_key(RESUME_AFTER_LABEL));
        Ok(())
    }

    #[test]
    fn resume_also_finishes_an_interrupted_resize_and_clears_the_mark() -> TestResult {
        let dir = tempfile::tempdir()?;
        let p = flaky(dir.path());
        let n = BoxName::new("half2")?;
        p.apply(&p.plan(&Operation::Create {
            spec: BoxSpec::new(n.clone(), Size::S),
        })?)?;
        p.backend().fail_next_set_size.store(true, Ordering::SeqCst);
        let plan = p.plan(&Operation::Resize {
            name: n.clone(),
            size: Some(Size::M),
            work_disk_gb: None,
        })?;
        assert!(p.apply(&plan).is_err());
        let rec = p
            .apply(&p.plan(&Operation::Resume { name: n.clone() })?)?
            .ok_or("no record")?;
        assert_eq!(rec.state, BoxState::Running);
        assert!(!rec.spec.labels.contains_key(RESUME_AFTER_LABEL));
        Ok(())
    }

    #[test]
    fn pausing_a_box_with_a_pending_restart_clears_the_mark() -> TestResult {
        let dir = tempfile::tempdir()?;
        let p = flaky(dir.path());
        let n = BoxName::new("pend")?;
        p.apply(&p.plan(&Operation::Create {
            spec: BoxSpec::new(n.clone(), Size::S),
        })?)?;
        p.backend().fail_next_set_size.store(true, Ordering::SeqCst);
        let resize = p.plan(&Operation::Resize {
            name: n.clone(),
            size: Some(Size::M),
            work_disk_gb: None,
        })?;
        assert!(p.apply(&resize).is_err());
        // The person now says they want it stopped.
        let plan = p.plan(&Operation::Pause { name: n.clone() })?;
        let kinds: Vec<_> = plan.changes.iter().map(|c| c.kind.as_str()).collect();
        assert_eq!(kinds, ["instance.clear_restart"]);
        assert_eq!(plan.max_risk(), Some(ozbox_core::Risk::Low));
        let after = p.apply(&plan)?.ok_or("no record")?;
        assert_eq!(after.state, BoxState::Paused);
        assert!(!after.spec.labels.contains_key(RESUME_AFTER_LABEL));
        assert!(p.plan(&Operation::Pause { name: n })?.is_noop());
        Ok(())
    }

    // ---- the suite must catch a provider that breaks the contract ----

    #[derive(Clone, Copy, PartialEq)]
    enum Flaw {
        PlanMutates,
        NotIdempotent,
        IgnoresStale,
        LeaksSecret,
    }

    struct Broken {
        inner: Engine<FakeBackend>,
        flaw: Flaw,
    }

    impl Provider for Broken {
        fn id(&self) -> &str {
            self.inner.id()
        }
        fn capabilities(&self) -> Capabilities {
            self.inner.capabilities()
        }
        fn list(&self) -> Result<Vec<BoxRecord>> {
            self.inner.list()
        }
        fn get(&self, n: &BoxName) -> Result<Option<BoxRecord>> {
            self.inner.get(n)
        }
        fn plan(&self, op: &Operation) -> Result<Plan> {
            let planned = self.inner.plan(op);
            match self.flaw {
                Flaw::PlanMutates => {
                    // "Planning" a pause really pauses.
                    if let (Operation::Pause { .. }, Ok(p)) = (op, &planned) {
                        self.inner.apply(p)?;
                    }
                    planned
                }
                Flaw::NotIdempotent => planned.map(|mut p| {
                    if matches!(op, Operation::Pause { .. }) && p.is_noop() {
                        p.changes.push(ozbox_core::Change::new(
                            "instance.stop",
                            "Stop it again",
                            ozbox_core::Risk::Low,
                        ));
                    }
                    p
                }),
                Flaw::LeaksSecret => {
                    planned.map_err(|e| Error::Provider(format!("{e} (token s3ntinel-secret)")))
                }
                Flaw::IgnoresStale => planned,
            }
        }
        fn apply(&self, plan: &Plan) -> Result<Option<BoxRecord>> {
            if self.flaw == Flaw::IgnoresStale {
                // Re-plan and apply whatever is true now, never refusing.
                let fresh = self.inner.plan(&plan.operation)?;
                return self.inner.apply(&fresh);
            }
            self.inner.apply(plan)
        }
    }

    #[test]
    fn the_suite_fails_a_provider_that_breaks_the_contract() -> TestResult {
        for (flaw, label) in [
            (Flaw::PlanMutates, "plan mutates"),
            (Flaw::NotIdempotent, "not idempotent"),
            (Flaw::IgnoresStale, "ignores stale plans"),
            (Flaw::LeaksSecret, "leaks a secret"),
        ] {
            let dir = tempfile::tempdir()?;
            let backend = FakeBackend::new(dir.path());
            let hook = backend.clone();
            let p = Broken {
                inner: Engine::new(backend),
                flaw,
            };
            let force = move |n: &BoxName, s: BoxState| hook.force_state(n, s);
            let res = conformance::run_all(&Harness {
                provider: &p,
                force_state: &force,
                secrets: vec!["s3ntinel-secret".into()],
                image: None,
                upgrade: None,
            });
            assert!(res.is_err(), "the suite passed a provider that {label}");
        }
        Ok(())
    }

    /// The box, its name, the id of its backup of /work and the id of the copy of its old system disk.
    type Kept = (Engine<FakeBackend>, BoxName, String, String);

    fn made_box_with_a_backup_and_a_copy(
        dir: &std::path::Path,
    ) -> std::result::Result<Kept, Box<dyn std::error::Error>> {
        let p = Engine::new(FakeBackend::new(dir));
        let n = BoxName::new("kept")?;
        p.apply(&p.plan(&Operation::Create {
            spec: BoxSpec::new(n.clone(), Size::S),
        })?)?;
        p.apply(&p.plan(&Operation::Snapshot { name: n.clone() })?)?;
        p.apply(&p.plan(&Operation::Upgrade {
            name: n.clone(),
            image: "fake-image-2".into(),
            reprovision: false,
            keep_old_system_disk: true,
        })?)?;
        let all = p.snapshots(&n)?;
        let work = all
            .iter()
            .find(|s| s.is_work_backup())
            .ok_or("no backup")?
            .id
            .clone();
        let copy = all
            .iter()
            .find(|s| s.is_old_system_disk_copy())
            .ok_or("no copy")?
            .id
            .clone();
        Ok((p, n, work, copy))
    }

    /// A copy of an old system disk is not a backup of /work: it does not stop the one real backup being "the only snapshot", and
    /// deleting the copy is never said to leave no backup.
    #[test]
    fn the_only_snapshot_note_counts_backups_and_not_copies_of_old_system_disks() -> TestResult {
        let dir = tempfile::tempdir()?;
        let (p, n, work, copy) = made_box_with_a_backup_and_a_copy(dir.path())?;
        let only = |plan: &Plan| plan.notes.iter().any(|t| t.contains("only snapshot"));
        let del = |id: &str| Operation::DeleteSnapshot {
            name: n.clone(),
            snapshot: id.to_string(),
        };
        assert!(
            only(&p.plan(&del(&work))?),
            "the one backup is the only one"
        );
        assert!(!only(&p.plan(&del(&copy))?), "a copy is not a backup");
        Ok(())
    }

    /// The copy holds the old store's key and cannot be reached once the box is gone: destroying the box removes it (the plan
    /// says so) unless the person keeps it, and a backup of /work is kept as before.
    #[test]
    fn destroying_a_box_removes_its_copies_of_old_system_disks_by_default() -> TestResult {
        for keep in [false, true] {
            let dir = tempfile::tempdir()?;
            let (p, n, _work, copy) = made_box_with_a_backup_and_a_copy(dir.path())?;
            let plan = p.plan(&Operation::Destroy {
                name: n.clone(),
                final_snapshot: false,
                keep_old_system_disks: keep,
            })?;
            let kinds: Vec<_> = plan.changes.iter().map(|c| c.kind.as_str()).collect();
            if keep {
                assert_eq!(kinds, ["box.delete"]);
                assert!(plan
                    .notes
                    .iter()
                    .any(|t| t.contains(&copy) && t.contains("KEPT")));
            } else {
                assert_eq!(kinds, ["snapshot.delete_old_system_disks", "box.delete"]);
                assert!(plan.changes[0].description.contains(&copy));
            }
            p.apply(&plan)?;
            let left = p.backend().load()?;
            assert_eq!(
                left.system_copies.iter().filter(|c| c.id == copy).count(),
                usize::from(keep),
                "keep={keep}"
            );
        }
        Ok(())
    }
}
