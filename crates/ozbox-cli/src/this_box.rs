//! A dashboard that runs on a box shows that box, never invented ones.
//!
//! `ozbox serve` used to fall back to the simulated provider whenever no provider was configured. On a box that is wrong
//! in the worst way: the owner signs in and sees demo boxes that look like a fleet. Boxes hold no cloud credentials by
//! design (only a person's computer drives the fleet), so a box's dashboard has no provider of its own, and the honest
//! answer is "this box, and the fleet is not connected".
//!
//! * [`choose`] is the one place that decides which provider `serve` uses.
//! * [`ThisBoxProvider`] lists exactly one box (this one), from what the machine says about itself, with no call to any
//!   cloud and no call to the daemon, so the first paint costs what the simulated provider cost.
//! * Everything that would change or price a fleet answers [`FLEET_NOT_CONNECTED`], a typed error (see `serve`).

use std::path::Path;

use ozbox_core::{
    BoxName, BoxRecord, BoxSpec, BoxState, Capabilities, Error, Operation, Plan, Provider,
    ResizeMethod, Result, Size,
};

use crate::cli::ProviderKind;

/// The provider id a box's own dashboard reports.
pub const PROVIDER_ID: &str = "thisbox";

/// The error code every fleet-only endpoint answers on a box.
pub const FLEET_NOT_CONNECTED: &str = "fleet_not_connected";

/// What the dashboard says, in a person's words, wherever the fleet would be.
pub const FLEET_NOT_CONNECTED_MESSAGE: &str =
    "Fleet not connected: this dashboard sees only this box. Creating, resizing, pausing, cloning or destroying boxes is done from your own computer with the ozbox command line.";

/// Test and diagnostics switch: treat this computer as a box for the provider choice (the dashboard's end-to-end tests
/// start a server on a laptop). It can only make the dashboard more honest, never less.
pub const FORCE_BOX_ENV: &str = "OZBOX_FORCE_BOX";

/// Where the box's daemon listens, overridable for tests.
pub const DAEMON_SOCKET_ENV: &str = "OZBOX_DAEMON_SOCKET";

/// Which provider `ozbox serve` runs on.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Choice {
    /// A provider that was asked for (`--provider`, or `provider = ` in the config). `Configured(Fake)` is the demo,
    /// chosen on purpose.
    Configured(ProviderKind),
    /// This is a box and nothing was configured: show this box only.
    ThisBox,
    /// Not a box and nothing configured: the first-run demo, as before.
    Demo,
}

impl Choice {
    /// The kind `build_provider` is given for everything that is not `ThisBox`.
    pub fn kind(self) -> ProviderKind {
        match self {
            Choice::Configured(k) => k,
            Choice::ThisBox | Choice::Demo => ProviderKind::Fake,
        }
    }

    pub fn is_demo(self) -> bool {
        matches!(self, Choice::Demo | Choice::Configured(ProviderKind::Fake))
    }
}

/// An explicit provider always wins. With none, a box never gets the simulated one.
pub fn choose(cli: Option<ProviderKind>, config: Option<ProviderKind>, on_box: bool) -> Choice {
    match (cli, config) {
        (Some(k), _) | (None, Some(k)) => Choice::Configured(k),
        (None, None) if on_box => Choice::ThisBox,
        (None, None) => Choice::Demo,
    }
}

/// Whether this computer is a box (its own markers), or the test switch says so.
pub fn on_a_box() -> bool {
    // The secrets service's own markers, or the image's release record: any of them is something only a box has.
    let markers = ozbox_core::audit_remote::on_a_box()
        || Path::new(ozbox_core::release::IMAGE_RELEASE_PATH).exists();
    on_a_box_with(markers, |k| std::env::var(k).ok())
}

pub fn on_a_box_with(markers: bool, env: impl Fn(&str) -> Option<String>) -> bool {
    markers || env(FORCE_BOX_ENV).is_some_and(|v| v == "1")
}

/// Everything this machine says about itself that the box's record needs.
#[derive(Debug, Clone, Default)]
pub struct Facts {
    pub hostname: Option<String>,
    pub vcpus: Option<u32>,
    pub memory_gb: Option<u32>,
    pub work_disk_gb: Option<u32>,
    pub image_release: Option<String>,
}

impl Facts {
    pub fn detect() -> Self {
        let hostname = std::env::var("OZBOX_BOX_NAME")
            .ok()
            .or_else(|| std::fs::read_to_string("/etc/hostname").ok());
        Facts {
            hostname,
            vcpus: std::thread::available_parallelism()
                .ok()
                .and_then(|n| u32::try_from(n.get()).ok()),
            memory_gb: std::fs::read_to_string("/proc/meminfo")
                .ok()
                .and_then(|t| mem_gb(&t)),
            work_disk_gb: work_disk_gb(Path::new("/work")),
            image_release: std::fs::read_to_string(ozbox_core::release::IMAGE_RELEASE_PATH)
                .ok()
                .and_then(|t| ozbox_core::release::parse_image_release(&t).version),
        }
    }
}

/// `MemTotal` of `/proc/meminfo` in whole GiB, rounded to the nearest.
pub fn mem_gb(meminfo: &str) -> Option<u32> {
    let kb: u64 = meminfo
        .lines()
        .find_map(|l| l.strip_prefix("MemTotal:"))?
        .split_whitespace()
        .next()?
        .parse()
        .ok()?;
    u32::try_from((kb + 512 * 1024) / (1024 * 1024)).ok()
}

/// The size of `/work` in whole GiB, from `df -Pk` (POSIX output: a header, then `fs 1K-blocks used avail ...`). Run once,
/// when the dashboard starts; `None` when it cannot be read.
fn work_disk_gb(path: &Path) -> Option<u32> {
    let out = std::process::Command::new("df")
        .args(["-Pk"])
        .arg(path)
        .output()
        .ok()
        .filter(|o| o.status.success())?;
    parse_df(&String::from_utf8_lossy(&out.stdout))
}

pub fn parse_df(text: &str) -> Option<u32> {
    let kb: u64 = text
        .lines()
        .nth(1)?
        .split_whitespace()
        .nth(1)?
        .parse()
        .ok()?;
    u32::try_from(kb / (1024 * 1024)).ok()
}

/// The largest catalogue size the machine meets. Approximate on purpose: the machine does not know which size it was
/// created as, and nothing here acts on it.
pub fn size_for(vcpus: Option<u32>, memory_gb: Option<u32>) -> Size {
    let (Some(c), Some(m)) = (vcpus, memory_gb) else {
        return Size::S;
    };
    Size::STANDARD
        .iter()
        .rev()
        .copied()
        .find(|s| s.spec().vcpus <= c && s.spec().memory_gb <= m + 1)
        .unwrap_or(Size::S)
}

/// A hostname as a box name; anything that is not one becomes `this-box`.
pub fn box_name(raw: Option<&str>) -> BoxName {
    raw.map(|r| r.trim().to_ascii_lowercase())
        .and_then(|r| BoxName::new(r).ok())
        .or_else(|| BoxName::new("this-box").ok())
        .unwrap_or_else(fallback_name)
}

#[allow(clippy::expect_used)]
fn fallback_name() -> BoxName {
    BoxName::new("box").expect("`box` is a valid box name")
}

/// The one box this dashboard runs on.
pub struct ThisBoxProvider {
    record: BoxRecord,
}

impl ThisBoxProvider {
    pub fn detect() -> Self {
        Self::from_facts(&Facts::detect())
    }

    pub fn from_facts(f: &Facts) -> Self {
        let mut spec = BoxSpec::new(
            box_name(f.hostname.as_deref()),
            size_for(f.vcpus, f.memory_gb),
        );
        if let Some(d) = f.work_disk_gb.filter(|d| *d > 0) {
            spec.work_disk_gb = d;
        }
        spec.image = f.image_release.clone();
        spec.labels
            .insert("this_box".to_string(), "true".to_string());
        Self {
            record: BoxRecord {
                spec,
                // The dashboard is answering, so the machine is running.
                state: BoxState::Running,
                provider: PROVIDER_ID.to_string(),
                provider_id: None,
                machine_type: None,
                snapshots: Vec::new(),
                created_at: None,
                last_activity_at: None,
            },
        }
    }

    fn refusal(&self, what: &str) -> Error {
        Error::Unsupported {
            provider: PROVIDER_ID.to_string(),
            what: what.to_string(),
            why: FLEET_NOT_CONNECTED_MESSAGE.to_string(),
        }
    }
}

impl Provider for ThisBoxProvider {
    fn id(&self) -> &str {
        PROVIDER_ID
    }

    fn capabilities(&self) -> Capabilities {
        Capabilities {
            resize: ResizeMethod::StopChangeStart,
            online_disk_grow: false,
            disk_shrink: false,
            snapshots: false,
            // No size can be chosen from here: nothing can be created.
            sizes: Vec::new(),
        }
    }

    fn list(&self) -> Result<Vec<BoxRecord>> {
        Ok(vec![self.record.clone()])
    }

    fn get(&self, name: &BoxName) -> Result<Option<BoxRecord>> {
        Ok((name == &self.record.spec.name).then(|| self.record.clone()))
    }

    fn plan(&self, op: &Operation) -> Result<Plan> {
        Err(self.refusal(match op {
            Operation::Create { .. } => "create a box",
            Operation::Pause { .. } => "pause a box",
            Operation::Resume { .. } => "resume a box",
            Operation::Resize { .. } => "resize a box",
            Operation::Snapshot { .. } => "snapshot a box",
            Operation::Clone { .. } => "clone a box",
            _ => "change a box",
        }))
    }

    fn apply(&self, _plan: &Plan) -> Result<Option<BoxRecord>> {
        Err(self.refusal("change a box"))
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn a_box_with_no_provider_never_gets_the_simulated_one() {
        let c = choose(None, None, true);
        assert_eq!(c, Choice::ThisBox);
        assert!(!c.is_demo());
    }

    #[test]
    fn a_computer_that_is_not_a_box_keeps_the_first_run_demo() {
        let c = choose(None, None, false);
        assert_eq!(c, Choice::Demo);
        assert!(c.is_demo());
        assert_eq!(c.kind(), ProviderKind::Fake);
    }

    #[test]
    fn an_explicit_fake_on_a_box_is_the_demo_and_says_so() {
        for (cli, cfg) in [
            (Some(ProviderKind::Fake), None),
            (None, Some(ProviderKind::Fake)),
        ] {
            let c = choose(cli, cfg, true);
            assert_eq!(c, Choice::Configured(ProviderKind::Fake));
            assert!(c.is_demo());
        }
    }

    #[test]
    fn a_configured_cloud_provider_wins_on_a_box_and_is_not_a_demo() {
        let c = choose(None, Some(ProviderKind::Aws), true);
        assert_eq!(c, Choice::Configured(ProviderKind::Aws));
        assert!(!c.is_demo());
        // the command line beats the config file
        assert_eq!(
            choose(Some(ProviderKind::Hcloud), Some(ProviderKind::Aws), true).kind(),
            ProviderKind::Hcloud
        );
    }

    #[test]
    fn the_test_switch_only_ever_makes_a_computer_a_box() {
        let on = |k: &str| (k == FORCE_BOX_ENV).then(|| "1".to_string());
        let off = |_: &str| None;
        assert!(on_a_box_with(false, on));
        assert!(!on_a_box_with(false, off));
        assert!(on_a_box_with(true, off));
    }

    #[test]
    fn this_box_lists_itself_only_and_describes_itself_from_the_machine() {
        let p = ThisBoxProvider::from_facts(&Facts {
            hostname: Some("Main\n".into()),
            vcpus: Some(8),
            memory_gb: Some(32),
            work_disk_gb: Some(300),
            image_release: Some("0.1.1-alpha.0".into()),
        });
        let all = p.list().unwrap();
        assert_eq!(all.len(), 1);
        let r = &all[0];
        assert_eq!(r.spec.name.as_str(), "main");
        assert_eq!(r.spec.size, Size::M);
        assert_eq!(r.spec.work_disk_gb, 300);
        assert_eq!(r.spec.image.as_deref(), Some("0.1.1-alpha.0"));
        assert_eq!(r.state, BoxState::Running);
        assert_eq!(r.provider, PROVIDER_ID);
        assert!(p.get(&BoxName::new("main").unwrap()).unwrap().is_some());
        assert!(p.get(&BoxName::new("other").unwrap()).unwrap().is_none());
    }

    #[test]
    fn a_hostname_that_is_not_a_box_name_and_missing_facts_still_give_a_record() {
        let p = ThisBoxProvider::from_facts(&Facts {
            hostname: Some("Not_A_Name!".into()),
            ..Facts::default()
        });
        let r = &p.list().unwrap()[0];
        assert_eq!(r.spec.name.as_str(), "this-box");
        assert_eq!(r.spec.size, Size::S);
    }

    #[test]
    fn df_output_is_read_in_whole_gib() {
        let df = "Filesystem 1024-blocks Used Available Capacity Mounted on\n/dev/nvme1n1 314572800 1 2 1% /work\n";
        assert_eq!(parse_df(df), Some(300));
        assert_eq!(parse_df("df: /work: No such file"), None);
    }

    #[test]
    fn meminfo_is_read_in_whole_gib() {
        assert_eq!(
            mem_gb("MemTotal:       16384000 kB\nMemFree: 1 kB\n"),
            Some(16)
        );
        assert_eq!(mem_gb("nothing"), None);
    }

    #[test]
    fn nothing_can_be_planned_or_applied_from_a_box() {
        let p = ThisBoxProvider::from_facts(&Facts::default());
        let name = BoxName::new("main").unwrap();
        let err = p.plan(&Operation::Pause { name }).unwrap_err().to_string();
        assert!(err.contains("Fleet not connected"), "{err}");
        assert!(p.capabilities().sizes.is_empty());
    }
}
