//! The bill and the forgotten resources for the demo provider, so the Bill page can be seen and tested without a cloud
//! account. Everything is made up from the boxes the demo has and the clock, and is the same for the same inputs: a few
//! days that match the estimate closely and a handful that do not, each for a different reason.

use std::collections::{BTreeMap, BTreeSet};
use std::sync::Mutex;

use crate::bill::{
    BillDay, BillError, BillLine, BillReport, BillSource, SVC_COMPUTE, SVC_EC2_OTHER,
};
use crate::orphans::{reason, OrphanItem, OrphanScan, OrphanSource};
use crate::pricing::PriceBook;
use crate::state::{day_key, DayBox, DayEstimate};

const DAY_MS: u64 = 86_400_000;
/// How many days back the demo bill goes.
const DAYS: u64 = 14;
const VPC: &str = "Amazon Virtual Private Cloud";

/// A demo box's hourly machine and disk price: just enough variety.
fn rates(index: usize) -> (f64, f64) {
    (0.40 + 0.20 * index as f64, 0.014 + 0.004 * index as f64)
}

/// The demo's estimate by day, and the bill it is compared with.
pub fn fixture(now_ms: u64, boxes: &[String]) -> (BillReport, BTreeMap<String, DayEstimate>) {
    // Sorted, so the same boxes give the same prices whatever order they were listed in.
    let mut sorted = boxes.to_vec();
    sorted.sort();
    sorted.dedup();
    let boxes = sorted.as_slice();
    let mut estimate = BTreeMap::new();
    let mut days = Vec::new();
    for back in 0..=DAYS {
        let date = day_key(now_ms.saturating_sub(back * DAY_MS));
        let mut est = DayEstimate {
            watched_ms: DAY_MS,
            currency: Some("USD".into()),
            boxes: BTreeMap::new(),
        };
        let mut lines = Vec::new();
        for (i, name) in boxes.iter().enumerate() {
            let (m, d) = rates(i);
            let (em, ed) = (m * 24.0, d * 24.0);
            est.boxes.insert(
                name.clone(),
                DayBox {
                    machine_cost: em,
                    disk_cost: ed,
                },
            );
            // within two percent either way, in a pattern that repeats but does not look like one
            let wobble = 1.0 + ((i as u64 * 7 + back * 3) % 5) as f64 / 100.0 - 0.02;
            let mut machine = em * wobble;
            // one box's day has a service the estimate does not model
            if i == 0 && back == 3 {
                lines.push(line(Some(name), VPC, 12.0));
            }
            // another box was watched for only part of a day, so its estimate is short
            if i == 1 && back == 5 {
                est.boxes.insert(
                    name.clone(),
                    DayBox {
                        machine_cost: em / 4.0,
                        disk_cost: ed,
                    },
                );
                machine = em;
            }
            lines.push(line(Some(name), SVC_COMPUTE, machine));
            lines.push(line(Some(name), SVC_EC2_OTHER, ed * 1.02));
        }
        // spend that carries the managed tag but no box name
        if back == 2 || back == 4 {
            lines.push(line(None, SVC_EC2_OTHER, 4.5));
        }
        if back == 5 && boxes.len() > 1 {
            est.watched_ms = 6 * 3_600_000;
        }
        days.push(BillDay {
            date: date.clone(),
            // today is the provider's own estimate
            estimated: back == 0,
            lines,
        });
        estimate.insert(date, est);
    }
    (
        BillReport {
            provider: "demo".into(),
            currency: "USD".into(),
            source: "Demo data, made up for this page".into(),
            fetched_at_ms: now_ms,
            days,
        },
        estimate,
    )
}

fn line(b: Option<&String>, service: &str, amount: f64) -> BillLine {
    BillLine {
        box_name: b.cloned(),
        service: service.into(),
        amount: (amount * 100.0).round() / 100.0,
    }
}

/// The demo's bill for the boxes it has.
pub struct DemoBill {
    pub boxes: Vec<String>,
}

impl BillSource for DemoBill {
    fn fetch(&self, now_ms: u64) -> Result<BillReport, BillError> {
        Ok(fixture(now_ms, &self.boxes).0)
    }
}

fn item(
    id: &str,
    kind: &str,
    class: &str,
    why: &str,
    size: Option<u64>,
    cost: f64,
    deletable: bool,
) -> OrphanItem {
    OrphanItem {
        id: id.into(),
        kind: kind.into(),
        region: "demo-region-1".into(),
        class: class.into(),
        reason: why.into(),
        box_name: (class == "unused").then(|| "alpha".to_string()),
        name: None,
        size_gb: size,
        created: Some("2026-10-01T00:00:00Z".into()),
        month_cost: Some(cost),
        cost_is_most: kind == "snapshot" || kind == "image",
        deletable,
    }
}

/// A made-up account: two things to delete, one image, and two lookalikes that are never deleted.
pub struct DemoOrphans {
    deleted: Mutex<BTreeSet<String>>,
}

impl Default for DemoOrphans {
    fn default() -> Self {
        Self {
            deleted: Mutex::new(BTreeSet::new()),
        }
    }
}

impl OrphanSource for DemoOrphans {
    fn scan(&self, regions: &[String], _prices: Option<&PriceBook>, now_ms: u64) -> OrphanScan {
        let gone = self.deleted.lock().map(|g| g.clone()).unwrap_or_default();
        let all = vec![
            item(
                "vol-0demo000retired",
                "volume",
                "unused",
                reason::RETIRED_WORK_DISK,
                Some(200),
                16.0,
                true,
            ),
            item(
                "snap-0demo000gone",
                "snapshot",
                "unused",
                reason::SNAPSHOT_BOX_GONE,
                Some(40),
                2.0,
                true,
            ),
            item(
                "ami-0demo000unsigned",
                "image",
                "unused",
                reason::UNSIGNED_IMAGE,
                Some(30),
                1.5,
                false,
            ),
            item(
                "i-0demo000stray",
                "instance",
                "untagged",
                reason::NO_MANAGED_TAG,
                None,
                73.0,
                false,
            ),
            item(
                "vol-0demo000lookalike",
                "volume",
                "untagged",
                reason::NO_MANAGED_TAG,
                Some(30),
                2.4,
                false,
            ),
        ];
        OrphanScan {
            scanned_at_ms: now_ms,
            regions: if regions.is_empty() {
                vec!["demo-region-1".into()]
            } else {
                regions.to_vec()
            },
            currency: Some("USD".into()),
            items: all.into_iter().filter(|i| !gone.contains(&i.id)).collect(),
            error: None,
            unsupported: false,
        }
    }

    fn delete(&self, item: &OrphanItem) -> Result<(), String> {
        if !item.deletable {
            return Err(crate::messages::t(
                "cost.orphans.err_not_ours",
                &[("id", &item.id)],
            ));
        }
        if let Ok(mut g) = self.deleted.lock() {
            g.insert(item.id.clone());
        }
        Ok(())
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use crate::bill::{reconcile, Tuning};

    const NOW: u64 = 1_794_182_400_000 + 12 * 3_600_000;

    #[test]
    fn the_demo_is_the_same_every_time_and_flags_exactly_its_three_stories() {
        let boxes = vec!["alpha".to_string(), "beta".to_string()];
        let (bill, est) = fixture(NOW, &boxes);
        assert_eq!(fixture(NOW, &boxes).0, bill);
        let r = reconcile(
            &est,
            &bill,
            NOW,
            Tuning {
                pct: 25.0,
                min: 2.0,
                prices_uncertain: false,
            },
        );
        let kinds: Vec<(Option<&str>, &str)> = r
            .drift
            .iter()
            .flat_map(|d| {
                d.causes
                    .iter()
                    .map(move |c| (d.box_name.as_deref(), c.kind))
            })
            .collect();
        assert!(
            kinds.contains(&(Some("alpha"), "unmodelled_service")),
            "{kinds:?}"
        );
        assert!(
            kinds.contains(&(Some("beta"), "partly_watched")),
            "{kinds:?}"
        );
        assert!(kinds.contains(&(None, "untagged_box")), "{kinds:?}");
        assert_eq!(
            r.drift.len(),
            4,
            "alpha once, beta once and the unnamed spend on two days: {:?}",
            r.drift
        );
        assert!(
            bill.days.iter().any(|d| d.estimated),
            "today is the provider's own estimate"
        );
    }

    #[test]
    fn four_boxes_flag_the_same_four_stories() {
        let boxes: Vec<String> = ["alpha", "bravo", "charlie", "delta"]
            .map(String::from)
            .to_vec();
        let (bill, est) = fixture(NOW, &boxes);
        let r = reconcile(
            &est,
            &bill,
            NOW,
            Tuning {
                pct: 25.0,
                min: 2.0,
                prices_uncertain: false,
            },
        );
        assert_eq!(
            r.drift.len(),
            4,
            "{:?}",
            r.drift
                .iter()
                .map(|d| (&d.date, &d.box_name, d.estimate, d.real))
                .collect::<Vec<_>>()
        );
    }

    #[test]
    fn the_demo_account_loses_what_is_deleted_and_never_a_lookalike() {
        let d = DemoOrphans::default();
        let first = d.scan(&[], None, NOW);
        assert_eq!(first.items.len(), 5);
        let vol = first
            .items
            .iter()
            .find(|i| i.id == "vol-0demo000retired")
            .unwrap();
        d.delete(vol).unwrap();
        assert_eq!(d.scan(&[], None, NOW).items.len(), 4);
        let stray = first.items.iter().find(|i| i.kind == "instance").unwrap();
        assert!(d.delete(stray).is_err());
        assert_eq!(d.scan(&[], None, NOW).items.len(), 4);
    }
}
