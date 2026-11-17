//! Test lanes over the worker channel (ADR 0042 section 7): a declared suite split across N workers, run on one exact commit, its
//! results gathered on `main`.
//!
//! What is here is the pure part: the split (by shard, or by weight with resource groups kept whole on one worker), the
//! `shard.assign` / `shard.result` bodies, the hub's bookkeeping of a run, the re-run of a lost worker's unfinished specs (a whole
//! resource group when it held one), and the verdict. **A lane never reports a partial run as green**: every spec must have passed
//! (a spec that failed and then passed on its retry passes and is recorded as flaky), and a lane that cannot finish says so. A green
//! lane is a test result, not a security gate: the person's merge approval is the gate.
//!
//! The command a shard runs is a **declared command id** (G5), never an argument list from a message; the worker runs it through
//! its own `ozbox env run` with typed slots. Running it is the worker's service's job and is not here.

use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};

use super::engine::{Hub, HubError, HubState};
use super::wire::{Ext, Kind, PROFILE};

/// A worker that has not been heard from for this long is "not answering" (3 heartbeats; ADR 0042 section 6).
pub const LOST_AFTER_MS: u64 = 90_000;
/// The most specs one lane run takes, and the longest spec name.
pub const MAX_SPECS: usize = 5_000;
const MAX_SPEC_LEN: usize = 300;

pub const AUDIT_LANE_START: &str = "hub.lane.started";
pub const AUDIT_LANE_RERUN: &str = "hub.lane.rerun";
pub const AUDIT_LANE_RESULT: &str = "hub.lane.result";
pub const AUDIT_LANE_REJECTED: &str = "hub.lane.rejected";

/// How the suite is split (the declaration's `split`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Split {
    /// Playwright's `--shard=i/N`. Over the channel the hub still plans the files itself and sends them (so it can re-run a lost
    /// worker's part on another); the worker passes `--shard` only as a label. Said in ADR 0042's "what is not covered".
    Shard,
    /// The hub assigns spec files by their duration in earlier runs, longest first.
    Weight,
}

/// One spec file as the declared `list` command printed it, with its resource key and its duration from the lane's history.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Spec {
    pub file: String,
    /// The sandbox account or fixture it writes. Every spec with one key runs on one worker, in order.
    #[serde(default)]
    pub resource: Option<String>,
    /// Milliseconds from earlier runs; `None` takes the median.
    #[serde(default)]
    pub weight_ms: Option<u64>,
}

/// The body of `shard.assign`. Names a declared command; carries no argv, no key and no value.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ShardAssign {
    pub run: String,
    pub lane: String,
    /// The candidate's exact commit, which the worker checks out.
    pub commit: String,
    /// The declared command id (G5); the worker resolves it from the approved declaration, never from this message.
    pub command: String,
    pub split: Split,
    pub shard: u32,
    pub total: u32,
    /// The files this shard runs, in order (a resource group in its listed order).
    pub specs: Vec<String>,
}

/// The body of `shard.result`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ShardResult {
    pub run: String,
    pub shard: u32,
    pub passed: Vec<String>,
    pub failed: Vec<String>,
    /// Failed, then passed on the one retry.
    #[serde(default)]
    pub flaky: Vec<String>,
    /// The worker's runner finished the shard (it may report results before it has).
    pub finished: bool,
}

/// One shard of a run, as the hub keeps it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ShardState {
    pub shard: u32,
    pub worker: String,
    pub specs: Vec<String>,
    pub passed: BTreeSet<String>,
    pub failed: BTreeSet<String>,
    pub flaky: BTreeSet<String>,
    pub finished: bool,
    /// The worker stopped answering; its unfinished specs went to another shard.
    pub lost: bool,
    pub assigned_ms: u64,
}

/// One lane run on one commit.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LaneRun {
    pub id: String,
    pub lane: String,
    pub commit: String,
    pub command: String,
    pub split: Split,
    pub specs: Vec<Spec>,
    pub shards: Vec<ShardState>,
    pub workers: Vec<String>,
    pub started_ms: u64,
    /// Set when the run cannot finish: no worker left to take a lost one's specs.
    pub cannot_finish: Option<String>,
}

/// What a lane run says.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "verdict", rename_all = "snake_case")]
pub enum Verdict {
    Running { done: usize, total: usize },
    Pass { flaky: Vec<String> },
    Fail { failed: Vec<String> },
    CannotFinish { why: String, missing: Vec<String> },
}

fn spec_ok(s: &str) -> bool {
    !s.is_empty() && s.len() <= MAX_SPEC_LEN && !s.chars().any(char::is_control)
}

/// Split specs across `n` workers. Specs sharing a resource key form one group that lands on one worker, in its listed order; a key
/// that is not in `known_keys` is a refusal before anything starts. Groups go longest first to the least-loaded worker.
pub fn plan(specs: &[Spec], n: usize, known_keys: &[String]) -> Result<Vec<Vec<String>>, String> {
    if n == 0 {
        return Err("a lane needs at least one worker".into());
    }
    if specs.is_empty() || specs.len() > MAX_SPECS {
        return Err("a lane needs between one and 5000 specs".into());
    }
    let mut seen = BTreeSet::new();
    for s in specs {
        if !spec_ok(&s.file) || !seen.insert(s.file.as_str()) {
            return Err(
                "a spec name is empty, too long, repeated or has control characters".into(),
            );
        }
        if let Some(k) = &s.resource {
            if !known_keys.contains(k) {
                return Err(format!(
                    "the resource key {k} is not one this hub knows, so the lane was not started"
                ));
            }
        }
    }
    let mut known: Vec<u64> = specs.iter().filter_map(|s| s.weight_ms).collect();
    known.sort_unstable();
    let median = known.get(known.len() / 2).copied().unwrap_or(1000);
    // groups in first-seen order
    let mut order: Vec<String> = Vec::new();
    let mut groups: BTreeMap<String, (u64, Vec<String>)> = BTreeMap::new();
    for s in specs {
        let key = s
            .resource
            .clone()
            .map_or_else(|| format!("\u{0}{}", s.file), |k| format!("k:{k}"));
        if !groups.contains_key(&key) {
            order.push(key.clone());
        }
        let g = groups.entry(key).or_default();
        g.0 = g.0.saturating_add(s.weight_ms.unwrap_or(median));
        g.1.push(s.file.clone());
    }
    let mut list: Vec<(u64, usize, Vec<String>)> = order
        .iter()
        .enumerate()
        .filter_map(|(i, k)| groups.remove(k).map(|(w, f)| (w, i, f)))
        .collect();
    // longest first; ties keep the listed order, so the plan is the same every time
    list.sort_by(|a, b| b.0.cmp(&a.0).then(a.1.cmp(&b.1)));
    let mut bins: Vec<(u64, Vec<String>)> = vec![(0, Vec::new()); n];
    for (w, _, files) in list {
        let i = bins
            .iter()
            .enumerate()
            .min_by_key(|(i, b)| (b.0, *i))
            .map_or(0, |(i, _)| i);
        bins[i].0 = bins[i].0.saturating_add(w);
        bins[i].1.extend(files);
    }
    Ok(bins.into_iter().map(|b| b.1).collect())
}

impl LaneRun {
    /// The verdict, never green while any spec has no passing result.
    pub fn verdict(&self) -> Verdict {
        let all: Vec<&str> = self.specs.iter().map(|s| s.file.as_str()).collect();
        let passed: BTreeSet<&str> = self
            .shards
            .iter()
            .filter(|s| !s.lost)
            .flat_map(|s| s.passed.iter().chain(s.flaky.iter()).map(String::as_str))
            .collect();
        let failed: BTreeSet<&str> = self
            .shards
            .iter()
            .filter(|s| !s.lost && s.finished)
            .flat_map(|s| s.failed.iter().map(String::as_str))
            .filter(|f| !passed.contains(f))
            .collect();
        let missing: Vec<String> = all
            .iter()
            .filter(|f| !passed.contains(*f) && !failed.contains(*f))
            .map(|f| (*f).to_string())
            .collect();
        if let Some(why) = &self.cannot_finish {
            return Verdict::CannotFinish {
                why: why.clone(),
                missing,
            };
        }
        let live_done = self.shards.iter().filter(|s| !s.lost).all(|s| s.finished);
        if !missing.is_empty() || !live_done {
            return Verdict::Running {
                done: passed.len() + failed.len(),
                total: all.len(),
            };
        }
        if !failed.is_empty() {
            return Verdict::Fail {
                failed: failed.into_iter().map(str::to_string).collect(),
            };
        }
        Verdict::Pass {
            flaky: self
                .shards
                .iter()
                .flat_map(|s| s.flaky.iter().cloned())
                .collect(),
        }
    }

    /// Specs a lost shard had not returned, widened to every spec of any resource group it held that is not wholly done: a spec that
    /// half-wrote a sandbox must not race its own re-run, so the group re-runs in order on one worker from a reset fixture.
    fn to_rerun(&self, lost: &ShardState) -> Vec<String> {
        let done: BTreeSet<&String> = lost
            .passed
            .iter()
            .chain(lost.failed.iter())
            .chain(lost.flaky.iter())
            .collect();
        let resource = |f: &str| {
            self.specs
                .iter()
                .find(|s| s.file == f)
                .and_then(|s| s.resource.clone())
        };
        let mut groups_open: BTreeSet<String> = BTreeSet::new();
        for f in &lost.specs {
            if !done.contains(f) {
                if let Some(k) = resource(f) {
                    groups_open.insert(k);
                }
            }
        }
        lost.specs
            .iter()
            .filter(|f| !done.contains(f) || resource(f).is_some_and(|k| groups_open.contains(&k)))
            .cloned()
            .collect()
    }
}

impl Hub<'_> {
    fn send_shard(&self, st: &mut HubState, worker: &str, a: &ShardAssign) -> Result<(), HubError> {
        let body = serde_json::to_vec(a)
            .map_err(|_| HubError::Wire(super::wire::WireError::SendFailed))?;
        st.core
            .enqueue(
                &PROFILE,
                worker,
                Kind::ShardAssign.name(),
                Ext::at(0).encode(),
                body,
            )
            .map_err(HubError::Backlog)?;
        Ok(())
    }

    /// Start a lane run on `commit` across `workers`. Plans first; a refusal starts nothing.
    #[allow(clippy::too_many_arguments)]
    pub fn lane_start(
        &self,
        st: &mut HubState,
        run: &str,
        lane: &str,
        commit: &str,
        command: &str,
        split: Split,
        specs: &[Spec],
        workers: &[String],
        known_keys: &[String],
        now: u64,
    ) -> Result<(), HubError> {
        let refuse = |m: String| {
            Err(HubError::Refused(super::refusal::Refusal {
                code: "lane-refused",
                message: m,
            }))
        };
        if st.lanes.contains_key(run) {
            return refuse(format!("a lane run named {run} exists already"));
        }
        if commit.len() != 40 || !commit.bytes().all(|b| b.is_ascii_hexdigit()) {
            return refuse("a lane runs on a full commit id".into());
        }
        for w in workers {
            if !self.roster.contains_key(w) {
                return Err(HubError::NotAWorker(w.clone()));
            }
            if st.peers.get(w).is_some_and(|p| p.quarantined.is_some()) {
                return Err(HubError::Quarantined(w.clone()));
            }
        }
        let parts = match plan(specs, workers.len(), known_keys) {
            Ok(p) => p,
            Err(m) => return refuse(m),
        };
        let total = u32::try_from(workers.len()).unwrap_or(u32::MAX);
        let mut shards = Vec::new();
        for (i, (w, files)) in workers.iter().zip(parts).enumerate() {
            let shard = u32::try_from(i + 1).unwrap_or(u32::MAX);
            let a = ShardAssign {
                run: run.to_string(),
                lane: lane.to_string(),
                commit: commit.to_string(),
                command: command.to_string(),
                split,
                shard,
                total,
                specs: files.clone(),
            };
            self.send_shard(st, w, &a)?;
            shards.push(ShardState {
                shard,
                worker: w.clone(),
                specs: files,
                passed: BTreeSet::new(),
                failed: BTreeSet::new(),
                flaky: BTreeSet::new(),
                finished: false,
                lost: false,
                assigned_ms: now,
            });
        }
        st.lanes.insert(
            run.to_string(),
            LaneRun {
                id: run.to_string(),
                lane: lane.to_string(),
                commit: commit.to_string(),
                command: command.to_string(),
                split,
                specs: specs.to_vec(),
                shards,
                workers: workers.to_vec(),
                started_ms: now,
                cannot_finish: None,
            },
        );
        st.note(
            now,
            AUDIT_LANE_START,
            format!(
                "run={run} lane={lane} commit={} workers={} specs={}",
                &commit[..12],
                workers.len(),
                specs.len()
            ),
        );
        if !self.deferred {
            self.flush_all(st, now);
        }
        Ok(())
    }

    /// Look at a run: a shard whose worker has gone quiet is lost, and its unfinished specs (a whole resource group when it held
    /// one) go to a worker of the run that still answers. With none left, the run cannot finish and says so.
    pub fn lane_tick(&self, st: &mut HubState, run: &str, now: u64) -> Option<Verdict> {
        let r = st.lanes.get(run)?.clone();
        let seen = |st: &HubState, w: &str| st.peers.get(w).map_or(0, |p| p.report.last_seen_ms);
        let alive = |st: &HubState, w: &str| {
            st.peers.get(w).is_none_or(|p| p.quarantined.is_none())
                && now.saturating_sub(seen(st, w).max(r.started_ms)) < LOST_AFTER_MS
        };
        let mut updated = r.clone();
        let mut next_shard = u32::try_from(updated.shards.len()).unwrap_or(u32::MAX);
        for i in 0..r.shards.len() {
            let s = &r.shards[i];
            if s.lost || s.finished || alive(st, &s.worker) {
                continue;
            }
            let rerun = updated.to_rerun(s);
            updated.shards[i].lost = true;
            if rerun.is_empty() {
                continue;
            }
            let Some(to) = r
                .workers
                .iter()
                .find(|w| **w != s.worker && alive(st, w))
                .cloned()
            else {
                updated.cannot_finish = Some(format!(
                    "{} stopped answering and no other worker of this lane is left to run its specs",
                    s.worker
                ));
                continue;
            };
            next_shard = next_shard.saturating_add(1);
            let a = ShardAssign {
                run: r.id.clone(),
                lane: r.lane.clone(),
                commit: r.commit.clone(),
                command: r.command.clone(),
                split: r.split,
                shard: next_shard,
                total: r.shards.len() as u32,
                specs: rerun.clone(),
            };
            if self.send_shard(st, &to, &a).is_err() {
                updated.cannot_finish = Some("the re-run could not be queued".into());
                continue;
            }
            st.note(
                now,
                AUDIT_LANE_RERUN,
                format!("run={run} from={} to={to} specs={}", s.worker, rerun.len()),
            );
            updated.shards.push(ShardState {
                shard: next_shard,
                worker: to,
                specs: rerun,
                passed: BTreeSet::new(),
                failed: BTreeSet::new(),
                flaky: BTreeSet::new(),
                finished: false,
                lost: false,
                assigned_ms: now,
            });
        }
        let v = updated.verdict();
        st.lanes.insert(run.to_string(), updated);
        if !self.deferred {
            self.flush_all(st, now);
        }
        Some(v)
    }
}

/// Take a `shard.result` (called by the hub's receive path once the channel's checks have passed). Only the worker that holds the
/// shard may report it, and only for the specs it was given.
pub(crate) fn take_result(st: &mut HubState, from: &str, plain: &[u8], now: u64) {
    let Ok(res) = serde_json::from_slice::<ShardResult>(plain) else {
        st.note(
            now,
            AUDIT_LANE_REJECTED,
            format!("worker={from} reason=malformed"),
        );
        return;
    };
    let Some(run) = st.lanes.get_mut(&res.run) else {
        st.note(
            now,
            AUDIT_LANE_REJECTED,
            format!("worker={from} reason=unknown-run"),
        );
        return;
    };
    let Some(s) = run.shards.iter_mut().find(|s| s.shard == res.shard) else {
        st.note(
            now,
            AUDIT_LANE_REJECTED,
            format!("worker={from} reason=unknown-shard"),
        );
        return;
    };
    if s.worker != from {
        st.note(
            now,
            AUDIT_LANE_REJECTED,
            format!("worker={from} reason=not-its-shard"),
        );
        return;
    }
    if s.lost {
        // its specs were handed on; a late answer from the lost worker does not count twice
        st.note(
            now,
            AUDIT_LANE_REJECTED,
            format!("worker={from} reason=shard-lost"),
        );
        return;
    }
    let mine: BTreeSet<&str> = s.specs.iter().map(String::as_str).collect();
    if res
        .passed
        .iter()
        .chain(res.failed.iter())
        .chain(res.flaky.iter())
        .any(|f| !mine.contains(f.as_str()))
    {
        st.note(
            now,
            AUDIT_LANE_REJECTED,
            format!("worker={from} reason=spec-not-assigned"),
        );
        return;
    }
    s.passed.extend(res.passed);
    s.failed.extend(res.failed);
    s.flaky.extend(res.flaky);
    s.finished |= res.finished;
    let (p, f, run_id, shard) = (s.passed.len(), s.failed.len(), run.id.clone(), s.shard);
    st.note(
        now,
        AUDIT_LANE_RESULT,
        format!("run={run_id} shard={shard} worker={from} passed={p} failed={f}"),
    );
}
