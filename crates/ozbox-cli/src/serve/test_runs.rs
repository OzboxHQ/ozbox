//! Test sends that run in the background: the dashboard starts one, gets an id at once and reads each channel's outcome
//! as it arrives. The delivery job writes into this table while the request loop keeps answering.

use std::collections::{BTreeMap, VecDeque};

use serde::Serialize;
use serde_json::{json, Value};

use crate::notify::Delivery;

/// How many finished or running test sends are remembered; the oldest is forgotten first.
const KEEP: usize = 20;

#[derive(Debug, Clone, Serialize)]
pub struct Item {
    pub channel: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub person: Option<String>,
    /// `pending`, `sent` or `failed`.
    pub status: &'static str,
    /// What happened, in words; absent while pending. Never holds a secret, an address or a response body.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub detail: Option<String>,
}

#[derive(Debug, Clone)]
struct Run {
    done: bool,
    items: Vec<Item>,
}

#[derive(Debug, Default)]
pub struct TestRuns {
    runs: BTreeMap<String, Run>,
    order: VecDeque<String>,
}

impl TestRuns {
    pub fn begin(&mut self, id: &str, items: Vec<Item>, done: bool) {
        self.runs.insert(id.to_string(), Run { done, items });
        self.order.push_back(id.to_string());
        while self.order.len() > KEEP {
            if let Some(old) = self.order.pop_front() {
                self.runs.remove(&old);
            }
        }
    }

    pub fn forget(&mut self, id: &str) {
        self.runs.remove(id);
        self.order.retain(|x| x != id);
    }

    /// One channel finished.
    pub fn set(&mut self, id: &str, index: usize, d: &Delivery) {
        if let Some(item) = self.runs.get_mut(id).and_then(|r| r.items.get_mut(index)) {
            item.status = if d.ok { "sent" } else { "failed" };
            item.detail = Some(d.detail.clone());
        }
    }

    pub fn finish(&mut self, id: &str) {
        if let Some(r) = self.runs.get_mut(id) {
            r.done = true;
            // A channel nobody reported (it cannot happen today) must not stay pending for ever.
            for i in r.items.iter_mut().filter(|i| i.status == "pending") {
                i.status = "failed";
                i.detail = Some("no answer was received".into());
            }
        }
    }

    pub fn get(&self, id: &str) -> Option<Value> {
        self.runs.get(id).map(|r| view(id, r))
    }
}

fn view(id: &str, r: &Run) -> Value {
    json!({ "id": id, "state": if r.done { "done" } else { "running" }, "items": r.items })
}

pub fn pending(channel: &str, person: Option<&str>) -> Item {
    Item {
        channel: channel.to_string(),
        person: person.map(str::to_string),
        status: "pending",
        detail: None,
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn a_run_reports_each_channel_as_it_finishes_and_forgets_the_oldest() {
        let mut t = TestRuns::default();
        t.begin(
            "a",
            vec![pending("sms", Some("ada")), pending("slack", None)],
            false,
        );
        assert_eq!(t.get("a").unwrap()["state"], "running");
        t.set("a", 1, &Delivery::new("slack", true, "sent"));
        let v = t.get("a").unwrap();
        assert_eq!(v["items"][0]["status"], "pending");
        assert_eq!(v["items"][1]["status"], "sent");
        t.set("a", 0, &Delivery::new("sms", false, "no key is saved"));
        t.finish("a");
        let v = t.get("a").unwrap();
        assert_eq!(v["state"], "done");
        assert_eq!(v["items"][0]["detail"], "no key is saved");
        for i in 0..KEEP {
            t.begin(&format!("r{i}"), Vec::new(), true);
        }
        assert!(t.get("a").is_none(), "the oldest is dropped");
        assert!(t.get("r0").is_some());
    }
}
