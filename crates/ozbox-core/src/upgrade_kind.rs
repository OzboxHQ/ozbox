//! Which kind of upgrade a release calls for (ADR 0038): a live update, a blue-green replace, or an upgrade in place.
//!
//! The decision is computed from two SIGNED manifests (the release the box's disk came from, and the target release) and
//! the box's state, never from what the box says about itself. This module is only the reading of the manifests' `upgrade`
//! record and the pure decision over it. Nothing here changes how an upgrade is carried out: today every upgrade is still
//! the replace. The plan says which kind the releases call for, and why.
//!
//! The `upgrade` record of the image manifest, as the image workflow writes it:
//!
//! ```json
//! "upgrade": {
//!   "disk_generation": {"amd64": "<sha256>", "arm64": "<sha256>"},
//!   "disk_parts": {"first_boot": "<sha256>", "kernel": {...}, "packages": {...}, "units": {...}, "accounts": {...}, "sshd": {...}},
//!   "live_from": "0.3.0",
//!   "work_format": 1,
//!   "work_format_reads": [1]
//! }
//! ```
//!
//! `disk_generation` is one hash for each machine type, because the package map and the kernel of an image are what the
//! build installed for that architecture; a single string is read as the value for every architecture. A manifest that
//! was written before the record existed has none: that is `Absent`, and it means "replace". A record that is there but
//! cannot be read is `Malformed`, which the decision refuses rather than guesses at.

use std::cmp::Ordering;

use serde::{Deserialize, Serialize};

use crate::infra::is_sha256;

/// What a signed manifest's `upgrade` record says for one image (the generation is already the one for the image's
/// architecture).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct UpgradeBlock {
    /// The hash of everything that cannot change on a running machine, lower-case hex.
    pub disk_generation: String,
    /// The first release a live update may start from, when the manifest says one.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub live_from: Option<String>,
    /// The version of what Oz Box keeps on `/work`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub work_format: Option<u64>,
    /// The `/work` formats this release reads (it must include its own).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub work_format_reads: Vec<u64>,
}

/// The `upgrade` record of one signed manifest.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "state", content = "block", rename_all = "snake_case")]
pub enum UpgradeRecord {
    /// The manifest has no `upgrade` record (every release before ADR 0038).
    Absent,
    Present(UpgradeBlock),
    /// There is a record and it cannot be trusted as one; the reason is for a person.
    Malformed(String),
}

fn arch_value<'a>(v: &'a serde_json::Value, arch: Option<&str>) -> Option<&'a str> {
    match v {
        serde_json::Value::String(s) => Some(s.as_str()),
        serde_json::Value::Object(m) => arch.and_then(|a| m.get(a)).and_then(|x| x.as_str()),
        _ => None,
    }
}

/// Read the `upgrade` record of an image manifest for the image of machine type `arch` (`amd64`, `arm64`). Only call it
/// on a manifest whose signature was checked. `arch` may be `None` only when the manifest's generation is one string.
pub fn upgrade_record(manifest_json: &str, arch: Option<&str>) -> UpgradeRecord {
    let Ok(v) = serde_json::from_str::<serde_json::Value>(manifest_json) else {
        return UpgradeRecord::Malformed("the manifest could not be read".into());
    };
    let Some(u) = v.get("upgrade") else {
        return UpgradeRecord::Absent;
    };
    if !u.is_object() {
        return UpgradeRecord::Malformed("the upgrade record is not an object".into());
    }
    let Some(gen) = u.get("disk_generation") else {
        return UpgradeRecord::Malformed("the upgrade record has no disk generation".into());
    };
    let Some(gen) = arch_value(gen, arch) else {
        return UpgradeRecord::Malformed(match arch {
            Some(a) => format!("the upgrade record has no disk generation for {a}"),
            None => "the upgrade record has no disk generation for this image".into(),
        });
    };
    let gen = gen.to_ascii_lowercase();
    if !is_sha256(&gen) {
        return UpgradeRecord::Malformed("the disk generation is not a SHA-256".into());
    }
    let live_from = match u.get("live_from") {
        None | Some(serde_json::Value::Null) => None,
        Some(serde_json::Value::String(s)) if Version::parse(s).is_some() => Some(s.clone()),
        Some(_) => return UpgradeRecord::Malformed("live_from is not a release version".into()),
    };
    let work_format = match u.get("work_format") {
        None | Some(serde_json::Value::Null) => None,
        Some(x) => match x.as_u64() {
            Some(n) => Some(n),
            None => return UpgradeRecord::Malformed("work_format is not a number".into()),
        },
    };
    let mut reads = Vec::new();
    match u.get("work_format_reads") {
        None | Some(serde_json::Value::Null) => {}
        Some(serde_json::Value::Array(a)) => {
            for x in a {
                match x.as_u64() {
                    Some(n) => reads.push(n),
                    None => {
                        return UpgradeRecord::Malformed(
                            "work_format_reads holds something that is not a number".into(),
                        )
                    }
                }
            }
        }
        Some(_) => return UpgradeRecord::Malformed("work_format_reads is not a list".into()),
    }
    // a release that raises the format must list the formats it reads, and read its own
    if let Some(f) = work_format {
        if !reads.contains(&f) {
            return UpgradeRecord::Malformed(
                "work_format_reads does not include the release's own work_format".into(),
            );
        }
    } else if !reads.is_empty() {
        return UpgradeRecord::Malformed("work_format_reads is set without a work_format".into());
    }
    UpgradeRecord::Present(UpgradeBlock {
        disk_generation: gen,
        live_from,
        work_format,
        work_format_reads: reads,
    })
}

/// The machine type of the image `image_id` in `region`, from the manifest's image list.
pub fn manifest_image_arch(manifest_json: &str, region: &str, image_id: &str) -> Option<String> {
    let v: serde_json::Value = serde_json::from_str(manifest_json).ok()?;
    v.get("images")?.as_array()?.iter().find_map(|i| {
        let listed = i.get("amis")?.get(region)?.as_str()? == image_id;
        listed
            .then(|| i.get("arch").and_then(|a| a.as_str()).map(str::to_string))
            .flatten()
    })
}

/// A release version, `MAJOR.MINOR[.PATCH][-pre]`, ordered the way semantic versions are (a pre-release is older than its
/// release).
///
/// One exception, for the dated image tags (`2026.11.10-2`): when the first number is a calendar year (1000 or more), a
/// suffix of digits only is a rebuild of that day, not a pre-release, so `2026.11.10-2` is NEWER than `2026.11.10` and
/// than `2026.11.10-1`. A dated tag with any other suffix (`2026.11.10-rc.1`) is a pre-release as usual.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Version {
    pub major: u64,
    pub minor: u64,
    pub patch: u64,
    pre: Option<String>,
    /// The rebuild number of a dated tag (`-N`), `None` for the day's first build.
    rebuild: Option<u64>,
}

impl Version {
    pub fn parse(v: &str) -> Option<Self> {
        if !crate::release::is_release_version(v) {
            return None;
        }
        let (core, pre) = match v.split_once('-') {
            Some((c, p)) => (c, Some(p.to_string())),
            None => (v, None),
        };
        let mut n = core.split('.').map(|p| p.parse::<u64>().ok());
        let major = n.next()??;
        let minor = n.next()??;
        let patch = match n.next() {
            Some(p) => p?,
            None => 0,
        };
        // a dated tag's `-N` is a rebuild of that day, which is newer; `-N` after a small major is a pre-release
        let rebuild = match &pre {
            Some(p) if major >= 1000 && p.bytes().all(|b| b.is_ascii_digit()) => {
                p.parse::<u64>().ok()
            }
            _ => None,
        };
        let pre = if rebuild.is_some() { None } else { pre };
        Some(Self {
            major,
            minor,
            patch,
            pre,
            rebuild,
        })
    }

    fn same_minor(&self, o: &Self) -> bool {
        (self.major, self.minor) == (o.major, o.minor)
    }
}

fn cmp_pre(a: &str, b: &str) -> Ordering {
    let (mut a, mut b) = (a.split('.'), b.split('.'));
    loop {
        match (a.next(), b.next()) {
            (None, None) => return Ordering::Equal,
            (None, Some(_)) => return Ordering::Less,
            (Some(_), None) => return Ordering::Greater,
            (Some(x), Some(y)) => {
                let o = match (x.parse::<u64>(), y.parse::<u64>()) {
                    (Ok(p), Ok(q)) => p.cmp(&q),
                    (Ok(_), Err(_)) => Ordering::Less,
                    (Err(_), Ok(_)) => Ordering::Greater,
                    (Err(_), Err(_)) => x.cmp(y),
                };
                if o != Ordering::Equal {
                    return o;
                }
            }
        }
    }
}

impl Ord for Version {
    fn cmp(&self, o: &Self) -> Ordering {
        (self.major, self.minor, self.patch)
            .cmp(&(o.major, o.minor, o.patch))
            .then_with(|| self.rebuild.cmp(&o.rebuild))
            .then_with(|| match (&self.pre, &o.pre) {
                (None, None) => Ordering::Equal,
                (None, Some(_)) => Ordering::Greater,
                (Some(_), None) => Ordering::Less,
                (Some(a), Some(b)) => cmp_pre(a, b),
            })
    }
}

impl PartialOrd for Version {
    fn partial_cmp(&self, o: &Self) -> Option<Ordering> {
        Some(self.cmp(o))
    }
}

/// The kind of upgrade a pair of releases calls for.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum UpgradeKind {
    /// The signed programs are swapped on the running machine; the system disk stays.
    Live,
    /// A new system disk is needed: a second machine is made and `/work` moves to it.
    Replace,
    /// The box is stopped: nothing is running, so it is upgraded in place, as today.
    InPlace,
}

impl UpgradeKind {
    pub fn word(self) -> &'static str {
        match self {
            UpgradeKind::Live => "live update",
            UpgradeKind::Replace => "replace",
            UpgradeKind::InPlace => "in place",
        }
    }
}

/// What one side of the decision knows: the release and what its signed manifest's `upgrade` record says. `record` is
/// `None` when the manifest could not be fetched or verified at all (a different thing from `Absent`).
#[derive(Debug, Clone, Copy)]
pub struct Side<'a> {
    pub release: Option<&'a str>,
    pub record: Option<&'a UpgradeRecord>,
}

/// Why the decision came out as it did, one value per branch so a test can pin each.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Why {
    BoxStopped,
    SameDisk,
    DiskChanged,
    /// The signed manifest of the release the box runs could not be fetched or verified.
    CurrentUnreadable,
    TargetUnreadable,
    /// A manifest from before the upgrade record: `current` says which side.
    CurrentNoRecord,
    TargetNoRecord,
    ReleaseUnknown,
    OtherMinor,
    NotNewer,
    NoLiveFrom,
    LiveFromAhead,
}

/// The answer, with the reason in words a person reads.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Decision {
    pub kind: UpgradeKind,
    pub why: Why,
    pub reason: String,
}

fn d(kind: UpgradeKind, why: Why, reason: impl Into<String>) -> Result<Decision, String> {
    Ok(Decision {
        kind,
        why,
        reason: reason.into(),
    })
}

/// Decide the kind of upgrade from the box's state and the two signed manifests (ADR 0038, section 1).
///
/// - A stopped box (or one with no machine) is upgraded **in place**: there is nothing to keep up.
/// - **Live** only when every condition holds: both manifests carry an `upgrade` record; the target is in the same minor
///   and strictly newer; its `live_from` is at or below the release the box runs; and the disk generations are equal.
/// - Anything else is a **replace**, including a manifest with no record (every release before the field), another
///   minor, and a release that is not newer (the step backwards is refused by the helper, never by this decision).
/// - A record that is present and cannot be read is a refusal (`Err`), never a guess.
///
/// `current` is the release the box's system disk came from (its applied release, until a box records one of its own).
pub fn decide(running: bool, current: Side<'_>, target: Side<'_>) -> Result<Decision, String> {
    use UpgradeKind::{InPlace, Live, Replace};
    if !running {
        return d(
            InPlace,
            Why::BoxStopped,
            "the box is stopped, so nothing is running that an upgrade would interrupt",
        );
    }
    for (side, name) in [(&current, "running"), (&target, "target")] {
        if let Some(UpgradeRecord::Malformed(m)) = side.record {
            return Err(format!(
                "the signed manifest of the {name} release has an upgrade record that cannot be read ({m}), so the kind of upgrade is not decided"
            ));
        }
    }
    let cur = match block_of(
        current,
        Why::CurrentUnreadable,
        Why::CurrentNoRecord,
        "the release the box runs",
        "the box runs",
    ) {
        Ok(b) => b,
        Err(done) => return Ok(done),
    };
    let tgt = match block_of(
        target,
        Why::TargetUnreadable,
        Why::TargetNoRecord,
        "the target release",
        "the target",
    ) {
        Ok(b) => b,
        Err(done) => return Ok(done),
    };
    let (Some(cv), Some(tv)) = (
        current.release.and_then(Version::parse),
        target.release.and_then(Version::parse),
    ) else {
        return d(
            Replace,
            Why::ReleaseUnknown,
            "one of the two releases does not read as a version, so they cannot be compared",
        );
    };
    let (cr, tr) = (
        current.release.unwrap_or_default(),
        target.release.unwrap_or_default(),
    );
    if !cv.same_minor(&tv) {
        return d(
            Replace,
            Why::OtherMinor,
            format!("release {tr} is in another minor version than {cr}, and live updates do not cross one"),
        );
    }
    if tv <= cv {
        return d(
            Replace,
            Why::NotNewer,
            format!("release {tr} is not newer than {cr}"),
        );
    }
    let Some(from) = tgt.live_from.as_deref() else {
        return d(
            Replace,
            Why::NoLiveFrom,
            format!("release {tr} does not offer a live update"),
        );
    };
    match Version::parse(from) {
        Some(f) if f <= cv => {}
        _ => {
            return d(
                Replace,
                Why::LiveFromAhead,
                format!(
                "release {tr} offers live updates only from release {from}, and the box runs {cr}"
            ),
            )
        }
    }
    if cur.disk_generation == tgt.disk_generation {
        d(
            Live,
            Why::SameDisk,
            format!(
                "release {tr} needs the same system disk as {cr}: only the signed programs differ"
            ),
        )
    } else {
        d(
            Replace,
            Why::DiskChanged,
            format!("release {tr} needs a new system disk (the kernel, the packages, the first boot, the units, the accounts or ssh changed since {cr})"),
        )
    }
}

/// The record of one side, or the replace decision its absence calls for. A damaged record never gets here (`decide`
/// refuses it first); treating it as unreadable keeps this total.
fn block_of<'a>(
    side: Side<'a>,
    unreadable: Why,
    no_record: Why,
    who: &str,
    what: &str,
) -> Result<&'a UpgradeBlock, Decision> {
    let replace = |why, reason: String| Decision {
        kind: UpgradeKind::Replace,
        why,
        reason,
    };
    match side.record {
        Some(UpgradeRecord::Present(b)) => Ok(b),
        Some(UpgradeRecord::Absent) => Err(replace(
            no_record,
            format!("{who} was built before releases recorded what a new system disk needs"),
        )),
        Some(UpgradeRecord::Malformed(_)) | None => Err(replace(
            unreadable,
            format!("the signed manifest of the release {what} could not be read, so a replace is the only kind that can be shown to be right"),
        )),
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    use super::*;

    fn h(c: char) -> String {
        c.to_string().repeat(64)
    }

    fn block(gen: char, live_from: Option<&str>) -> UpgradeRecord {
        UpgradeRecord::Present(UpgradeBlock {
            disk_generation: h(gen),
            live_from: live_from.map(str::to_string),
            work_format: Some(1),
            work_format_reads: vec![1],
        })
    }

    fn run(
        running: bool,
        cur: (&str, &UpgradeRecord),
        tgt: (&str, &UpgradeRecord),
    ) -> Result<Decision, String> {
        decide(
            running,
            Side {
                release: Some(cur.0),
                record: Some(cur.1),
            },
            Side {
                release: Some(tgt.0),
                record: Some(tgt.1),
            },
        )
    }

    #[test]
    fn the_same_disk_generation_in_the_same_minor_is_live() {
        let (a, b) = (block('a', Some("0.3.0")), block('a', Some("0.3.0")));
        let r = run(true, ("0.3.0", &a), ("0.3.2", &b)).unwrap();
        assert_eq!((r.kind, r.why), (UpgradeKind::Live, Why::SameDisk));
        assert!(r.reason.contains("0.3.2") && r.reason.contains("0.3.0"));
    }

    #[test]
    fn a_changed_disk_generation_is_a_replace() {
        let (a, b) = (block('a', Some("0.3.0")), block('b', Some("0.3.0")));
        let r = run(true, ("0.3.0", &a), ("0.3.2", &b)).unwrap();
        assert_eq!((r.kind, r.why), (UpgradeKind::Replace, Why::DiskChanged));
    }

    #[test]
    fn a_manifest_without_the_record_is_a_replace_on_either_side() {
        let (a, none) = (block('a', Some("0.3.0")), UpgradeRecord::Absent);
        let r = run(true, ("0.3.0", &none), ("0.3.2", &a)).unwrap();
        assert_eq!(
            (r.kind, r.why),
            (UpgradeKind::Replace, Why::CurrentNoRecord)
        );
        let r = run(true, ("0.3.0", &a), ("0.3.2", &none)).unwrap();
        assert_eq!((r.kind, r.why), (UpgradeKind::Replace, Why::TargetNoRecord));
    }

    #[test]
    fn a_manifest_that_could_not_be_fetched_is_a_replace_and_never_live() {
        let a = block('a', Some("0.3.0"));
        let r = decide(
            true,
            Side {
                release: Some("0.3.0"),
                record: None,
            },
            Side {
                release: Some("0.3.2"),
                record: Some(&a),
            },
        )
        .unwrap();
        assert_eq!(
            (r.kind, r.why),
            (UpgradeKind::Replace, Why::CurrentUnreadable)
        );
        let r = decide(
            true,
            Side {
                release: Some("0.3.0"),
                record: Some(&a),
            },
            Side {
                release: Some("0.3.2"),
                record: None,
            },
        )
        .unwrap();
        assert_eq!(r.why, Why::TargetUnreadable);
    }

    #[test]
    fn a_stopped_box_is_upgraded_in_place_whatever_the_manifests_say() {
        let (a, b) = (block('a', Some("0.3.0")), block('b', Some("0.3.0")));
        let r = run(false, ("0.3.0", &a), ("0.3.2", &b)).unwrap();
        assert_eq!((r.kind, r.why), (UpgradeKind::InPlace, Why::BoxStopped));
        // even with nothing readable, and even with a damaged record: nothing is running to keep up
        let bad = UpgradeRecord::Malformed("x".into());
        let r = run(false, ("0.3.0", &bad), ("0.3.2", &UpgradeRecord::Absent)).unwrap();
        assert_eq!(r.kind, UpgradeKind::InPlace);
    }

    #[test]
    fn a_damaged_record_is_refused_not_guessed_at() {
        let (a, bad) = (
            block('a', Some("0.3.0")),
            UpgradeRecord::Malformed("no".into()),
        );
        let e = run(true, ("0.3.0", &a), ("0.3.2", &bad)).unwrap_err();
        assert!(e.contains("target") && e.contains("no"), "{e}");
        let e = run(true, ("0.3.0", &bad), ("0.3.2", &a)).unwrap_err();
        assert!(e.contains("running"), "{e}");
    }

    #[test]
    fn another_minor_is_a_replace_even_on_the_same_disk() {
        let (a, b) = (block('a', Some("0.3.0")), block('a', Some("0.3.0")));
        let r = run(true, ("0.3.4", &a), ("0.4.0", &b)).unwrap();
        assert_eq!((r.kind, r.why), (UpgradeKind::Replace, Why::OtherMinor));
        let r = run(true, ("0.4.0", &a), ("0.3.9", &b)).unwrap();
        assert_eq!(r.why, Why::OtherMinor);
    }

    #[test]
    fn a_release_that_is_not_newer_is_a_replace_and_the_decision_does_not_refuse_it() {
        let (a, b) = (block('a', Some("0.3.0")), block('a', Some("0.3.0")));
        let r = run(true, ("0.3.2", &a), ("0.3.1", &b)).unwrap();
        assert_eq!((r.kind, r.why), (UpgradeKind::Replace, Why::NotNewer));
        let r = run(true, ("0.3.2", &a), ("0.3.2", &b)).unwrap();
        assert_eq!(r.why, Why::NotNewer);
        // a pre-release is older than its release
        let r = run(true, ("0.3.2", &a), ("0.3.2-rc.1", &b)).unwrap();
        assert_eq!(r.why, Why::NotNewer);
        let r = run(true, ("0.3.2-rc.1", &a), ("0.3.2", &b)).unwrap();
        assert_eq!(r.kind, UpgradeKind::Live);
    }

    #[test]
    fn live_from_must_be_at_or_below_the_release_the_box_runs() {
        let a = block('a', Some("0.3.0"));
        // the box runs 0.3.0, the target says live updates start from 0.3.1
        let ahead = block('a', Some("0.3.1"));
        let r = run(true, ("0.3.0", &a), ("0.3.2", &ahead)).unwrap();
        assert_eq!((r.kind, r.why), (UpgradeKind::Replace, Why::LiveFromAhead));
        // exactly at the box's release is allowed
        let exact = block('a', Some("0.3.0"));
        assert_eq!(
            run(true, ("0.3.0", &a), ("0.3.2", &exact)).unwrap().kind,
            UpgradeKind::Live
        );
        // no live_from at all: the release does not offer it
        let none = block('a', None);
        let r = run(true, ("0.3.0", &a), ("0.3.2", &none)).unwrap();
        assert_eq!((r.kind, r.why), (UpgradeKind::Replace, Why::NoLiveFrom));
    }

    #[test]
    fn a_release_that_is_not_a_version_cannot_be_compared() {
        let a = block('a', Some("0.3.0"));
        let r = decide(
            true,
            Side {
                release: None,
                record: Some(&a),
            },
            Side {
                release: Some("0.3.2"),
                record: Some(&a),
            },
        )
        .unwrap();
        assert_eq!(r.why, Why::ReleaseUnknown);
    }

    fn manifest(upgrade: &str) -> String {
        format!(
            r#"{{"version":"0.3.2","images":[{{"arch":"amd64","amis":{{"us-east-1":"ami-1"}}}},{{"arch":"arm64","amis":{{"us-east-1":"ami-2"}}}}],{upgrade}"x":1}}"#
        )
    }

    #[test]
    fn the_record_is_read_for_the_images_architecture() {
        let m = manifest(&format!(
            r#""upgrade":{{"disk_generation":{{"amd64":"{}","arm64":"{}"}},"disk_parts":{{"first_boot":"{}"}},"live_from":"0.3.0","work_format":2,"work_format_reads":[1,2]}},"#,
            h('a'),
            h('b'),
            h('c')
        ));
        assert_eq!(
            manifest_image_arch(&m, "us-east-1", "ami-2").as_deref(),
            Some("arm64")
        );
        assert_eq!(manifest_image_arch(&m, "us-east-1", "ami-9"), None);
        let UpgradeRecord::Present(b) = upgrade_record(&m, Some("arm64")) else {
            panic!("record")
        };
        assert_eq!(b.disk_generation, h('b'));
        assert_eq!(b.live_from.as_deref(), Some("0.3.0"));
        assert_eq!((b.work_format, b.work_format_reads), (Some(2), vec![1, 2]));
        // an architecture the record has no value for is not guessed
        assert!(matches!(
            upgrade_record(&m, Some("riscv")),
            UpgradeRecord::Malformed(_)
        ));
        assert!(matches!(
            upgrade_record(&m, None),
            UpgradeRecord::Malformed(_)
        ));
    }

    #[test]
    fn a_single_string_generation_is_read_for_every_architecture() {
        let m = manifest(&format!(r#""upgrade":{{"disk_generation":"{}"}},"#, h('D')));
        let UpgradeRecord::Present(b) = upgrade_record(&m, None) else {
            panic!("record")
        };
        assert_eq!(b.disk_generation, h('d'));
        assert!(upgrade_record(&m, Some("arm64")) != UpgradeRecord::Absent);
    }

    #[test]
    fn a_manifest_with_no_upgrade_key_is_absent() {
        assert_eq!(
            upgrade_record(&manifest(""), Some("amd64")),
            UpgradeRecord::Absent
        );
    }

    #[test]
    fn damaged_records_are_malformed() {
        let bad = |u: &str| {
            matches!(
                upgrade_record(&manifest(u), Some("amd64")),
                UpgradeRecord::Malformed(_)
            )
        };
        assert!(bad(r#""upgrade":"x","#));
        assert!(bad(r#""upgrade":{},"#));
        assert!(bad(r#""upgrade":{"disk_generation":"abc"},"#));
        assert!(bad(r#""upgrade":{"disk_generation":7},"#));
        let g = h('a');
        assert!(bad(&format!(
            r#""upgrade":{{"disk_generation":"{g}","live_from":"soon"}},"#
        )));
        assert!(bad(&format!(
            r#""upgrade":{{"disk_generation":"{g}","work_format":"2"}},"#
        )));
        assert!(bad(&format!(
            r#""upgrade":{{"disk_generation":"{g}","work_format":2,"work_format_reads":[1]}},"#
        )));
        assert!(bad(&format!(
            r#""upgrade":{{"disk_generation":"{g}","work_format_reads":[1]}},"#
        )));
        assert!(bad(&format!(
            r#""upgrade":{{"disk_generation":"{g}","work_format":1,"work_format_reads":"1"}},"#
        )));
        assert_eq!(
            upgrade_record("not json", Some("amd64")),
            UpgradeRecord::Malformed("the manifest could not be read".into())
        );
    }

    #[test]
    fn versions_order_like_semantic_versions() {
        let v = |s: &str| Version::parse(s).unwrap();
        assert!(v("0.3.10") > v("0.3.9"));
        assert!(v("0.3.0") > v("0.3.0-alpha.1"));
        assert!(v("0.3.0-alpha.2") > v("0.3.0-alpha.1"));
        assert!(v("0.3.0-alpha.10") > v("0.3.0-alpha.9"));
        assert!(v("0.3") == v("0.3.0"));
        assert!(Version::parse("latest").is_none());
    }

    /// Z16: dated image tags used `-N` for a rebuild of the day, which is newer, not a pre-release.
    #[test]
    fn a_dated_tags_rebuild_number_orders_after_the_day_it_rebuilds() {
        let v = |s: &str| Version::parse(s).unwrap();
        assert!(v("2026.11.10-1") > v("2026.11.10"));
        assert!(v("2026.11.10-2") > v("2026.11.10-1"));
        assert!(v("2026.11.10-10") > v("2026.11.10-9"));
        assert!(v("2026.11.10") > v("2026.11.09-3"));
        assert!(v("2026.11.10-3") < v("2026.11.11"));
        // another suffix on a dated tag is still a pre-release, and a small major's `-N` is still a pre-release
        assert!(v("2026.11.10-rc.1") < v("2026.11.10"));
        assert!(v("0.3.0-2") < v("0.3.0"));
        assert!(v("0.3.0-2") > v("0.3.0-1"));
    }
}
