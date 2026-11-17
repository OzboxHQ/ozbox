//! The merge queue over the worker channel (ADR 0020 section 6, ADR 0042 sections 5 and 7).
//!
//! A worker's `result` names the **exact commit** it finished. [`admit_results`] takes it into the orchestration: the feature
//! records the commit and joins the merge queue on `main`, which rebases, tests (through a test lane across workers when one is
//! declared) and asks for the merge approval as it always has. What the queue finds goes back to the worker that owns the
//! feature as an `answer` ([`return_to_worker`]): the conflicting files, the failing specs, or a lane that could not finish, said
//! as it is. A result never merges anything by itself, and the person's merge approval is unchanged.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use super::engine::{Hub, HubError, HubState};
use super::lane::{Spec, Split, Verdict};
use super::wire::{Ext, Kind, PROFILE};
use crate::orch::{FeatureState, MergeState, Transport};
use crate::orch_merge::{MergeOutcome, MergeStep, Merger, RebaseOutcome, TestOutcome};
use crate::run::Book;

/// What the hub tells a worker about one of its features (the body of `answer`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AnswerBody {
    pub orchestration: String,
    pub feature: String,
    /// `answer`, `conflict`, `tests-failed`, `lane-unfinished`, `merged`, `not-approved`.
    pub kind: String,
    pub text: String,
}

/// A full commit id: 40 hex digits (SHA-1) or 64 (SHA-256).
pub fn commit_ok(c: &str) -> bool {
    matches!(c.len(), 40 | 64) && c.bytes().all(|b| b.is_ascii_hexdigit())
}

impl Hub<'_> {
    /// Tell a worker something about its feature. Only a feature this hub handed it.
    pub fn answer(
        &self,
        st: &mut HubState,
        worker: &str,
        a: &AnswerBody,
        now: u64,
    ) -> Result<(), HubError> {
        if !self.roster.contains_key(worker) {
            return Err(HubError::NotAWorker(worker.to_string()));
        }
        let assigned = st.peers.get(worker).is_some_and(|p| {
            p.assigned
                .iter()
                .any(|(o, f)| *o == a.orchestration && *f == a.feature)
        });
        if !assigned {
            return Err(HubError::NotAWorker(format!(
                "{worker} does not hold {}",
                a.feature
            )));
        }
        let body = serde_json::to_vec(a)
            .map_err(|_| HubError::Wire(super::wire::WireError::SendFailed))?;
        st.core
            .enqueue(
                &PROFILE,
                worker,
                Kind::Answer.name(),
                Ext::at(0).encode(),
                body,
            )
            .map_err(HubError::Backlog)?;
        st.note(
            now,
            "hub.answer",
            format!("worker={worker} task={} kind={}", a.feature, a.kind),
        );
        if !self.deferred {
            self.flush(st, worker, now).map_err(HubError::Wire)?;
        }
        Ok(())
    }
}

/// Bring what the hub's workers reported into the orchestrations: a hub-route feature whose worker said `accepted` or `working` is
/// Working, and one that reported a `result` with a full commit joins the merge queue with that commit. A result from a worker that
/// does not hold the feature now, or with no full commit id, is not taken (and the second is said to the conductor). Returns the
/// features queued.
pub fn admit_results(book: &mut Book, st: &HubState, now: u64) -> Vec<(String, String)> {
    let mut queued = Vec::new();
    let mut records: Vec<(String, String)> = Vec::new();
    for o in &mut book.orchestrations {
        let oid = o.id.clone();
        let ids: Vec<String> = o
            .features
            .iter()
            .filter(|f| f.transport == Transport::Hub)
            .map(|f| f.id.clone())
            .collect();
        for fid in ids {
            let Some(f) = o.feature(&fid).cloned() else {
                continue;
            };
            let Some(peer) = st.peers.get(&f.box_name) else {
                continue;
            };
            if peer.quarantined.is_some() {
                continue;
            }
            if let Some(s) = peer.report.status.get(&oid).and_then(|m| m.get(&fid)) {
                if f.state == FeatureState::Starting
                    && matches!(s.state.as_str(), "accepted" | "working")
                {
                    if let Some(fm) = o.feature_mut(&fid) {
                        fm.state = FeatureState::Working;
                    }
                }
                if s.state == "refused"
                    && matches!(f.state, FeatureState::Starting | FeatureState::Working)
                {
                    if let Some(fm) = o.feature_mut(&fid) {
                        fm.state = FeatureState::Failed;
                    }
                    records.push(("orchestration.hub_refused".into(), format!("{oid}/{fid}")));
                }
            }
            let Some(r) = peer.report.results.get(&oid).and_then(|m| m.get(&fid)) else {
                continue;
            };
            if f.commit.as_deref() == Some(r.commit.as_str()) {
                continue;
            }
            if !matches!(
                f.state,
                FeatureState::Starting
                    | FeatureState::Working
                    | FeatureState::Blocked
                    | FeatureState::ConflictReturned
                    | FeatureState::ReadyToMerge
            ) {
                continue;
            }
            if !commit_ok(&r.commit) {
                let _ = o.post(
                    now,
                    "system",
                    "conductor",
                    crate::orch::MsgKind::Status,
                    &format!(
                        "{fid} reported a result without a full commit id, so it was not queued"
                    ),
                    None,
                    false,
                );
                continue;
            }
            if let Some(fm) = o.feature_mut(&fid) {
                fm.commit = Some(r.commit.clone());
                fm.state = FeatureState::ReadyToMerge;
                fm.resume_pending = false;
            }
            if o.enqueue_merge(&fid, now).is_ok() {
                queued.push((oid.clone(), fid.clone()));
                records.push((
                    "orchestration.hub_result".into(),
                    format!("{oid}/{fid} commit={}", &r.commit[..12]),
                ));
            }
        }
    }
    for (action, detail) in records {
        book.record(now, "supervisor", &action, None, &detail);
    }
    queued
}

/// After a merge step, tell a hub-route feature's worker what the queue found, in plain words.
pub fn return_to_worker(
    hub: &Hub<'_>,
    st: &mut HubState,
    book: &Book,
    orch_id: &str,
    step: &MergeStep,
    now: u64,
) -> Result<bool, HubError> {
    let Some(o) = book.orchestration(orch_id) else {
        return Ok(false);
    };
    let Some(f) = o.feature(&step.feature_id) else {
        return Ok(false);
    };
    if f.transport != Transport::Hub {
        return Ok(false);
    }
    let (kind, text) = match step.state {
        MergeState::Conflict => (
            "conflict",
            format!(
                "Your branch conflicts with {} in: {}. Rebase onto it, resolve the conflicts inside your own claims, run the tests and finish again.",
                o.policy.base_branch, step.detail
            ),
        ),
        MergeState::TestsFailed => (
            if step.detail.starts_with("the lane could not finish") {
                "lane-unfinished"
            } else {
                "tests-failed"
            },
            format!("The tests did not pass on your commit: {}. Fix them and finish again.", step.detail),
        ),
        MergeState::Merged => ("merged", format!("Merged into {}.", o.policy.base_branch)),
        MergeState::Failed => ("not-approved", format!("Not merged: {}.", step.detail)),
        _ => return Ok(false),
    };
    hub.answer(
        st,
        &f.box_name,
        &AnswerBody {
            orchestration: orch_id.to_string(),
            feature: step.feature_id.clone(),
            kind: kind.to_string(),
            text,
        },
        now,
    )?;
    Ok(true)
}

/// A declared lane (`[lane.<name>]` in the project's approved declaration), as the hub runs it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LaneDecl {
    pub name: String,
    /// The declared shard command id (G5).
    pub command: String,
    pub split: Split,
    pub specs: Vec<Spec>,
    pub workers: Vec<String>,
    pub known_keys: Vec<String>,
}

/// The merge queue's [`Merger`] on a box with a hub: rebase and merge are the conductor box's own (`inner`); the test, when the
/// orchestration's lane is `hub:<name>`, runs as a lane across workers on the feature's **reported commit**, and is never green
/// while any spec has no passing result.
pub struct HubMerger<'a, 'h> {
    pub inner: &'a mut dyn Merger,
    pub hub: &'a Hub<'h>,
    pub st: &'a mut HubState,
    pub lanes: &'a BTreeMap<String, LaneDecl>,
    /// The commit each branch's worker reported, from the orchestration.
    pub commits: BTreeMap<String, String>,
    pub now: u64,
}

impl Merger for HubMerger<'_, '_> {
    fn rebase(
        &mut self,
        repo: Option<&str>,
        branch: &str,
        onto: &str,
    ) -> Result<RebaseOutcome, String> {
        self.inner.rebase(repo, branch, onto)
    }

    fn test(
        &mut self,
        repo: Option<&str>,
        branch: &str,
        argv: &[String],
        lane: Option<&str>,
    ) -> Result<TestOutcome, String> {
        let Some(name) = lane.and_then(|l| l.strip_prefix("hub:")) else {
            return self.inner.test(repo, branch, argv, lane);
        };
        let decl = self
            .lanes
            .get(name)
            .ok_or_else(|| format!("there is no declared lane named {name}"))?;
        let commit = self
            .commits
            .get(branch)
            .ok_or(
                "no worker reported a commit for that branch, so there is nothing exact to test",
            )?
            .clone();
        let run = format!("{name}-{}", &commit[..12.min(commit.len())]);
        if !self.st.lanes.contains_key(&run) {
            self.hub
                .lane_start(
                    self.st,
                    &run,
                    name,
                    &commit,
                    &decl.command,
                    decl.split,
                    &decl.specs,
                    &decl.workers,
                    &decl.known_keys,
                    self.now,
                )
                .map_err(|e| e.to_string())?;
            return Ok(TestOutcome::Pending);
        }
        match self.hub.lane_tick(self.st, &run, self.now) {
            None | Some(Verdict::Running { .. }) => Ok(TestOutcome::Pending),
            Some(Verdict::Pass { .. }) => {
                // what passed is this exact commit: the merge is allowed only while the branch still points at it
                self.st.tested.insert(branch.to_string(), commit);
                Ok(TestOutcome::Pass)
            }
            Some(Verdict::Fail { failed }) => {
                let list: Vec<String> = failed.into_iter().take(20).collect();
                Ok(TestOutcome::Fail(format!(
                    "failing specs: {}",
                    list.join(", ")
                )))
            }
            Some(Verdict::CannotFinish { why, missing }) => Ok(TestOutcome::Fail(format!(
                "the lane could not finish ({why}); {} specs have no result",
                missing.len()
            ))),
        }
    }

    fn merge(
        &mut self,
        repo: Option<&str>,
        branch: &str,
        into: &str,
    ) -> Result<MergeOutcome, String> {
        if let Some(tested) = self.st.tested.get(branch).cloned() {
            // a worker that reported a newer commit since the lane passed, or a branch the conductor's side sees elsewhere, was not
            // what the lane tested: it goes back through the lane, never merged on the old verdict
            let reported = self.commits.get(branch);
            let head = self.inner.head(repo, branch)?;
            if reported.is_some_and(|c| *c != tested) || head.is_some_and(|h| h != tested) {
                self.st.tested.remove(branch);
                return Err(format!(
                    "the branch no longer points at the commit the lane tested ({}): it is tested again",
                    &tested[..12.min(tested.len())]
                ));
            }
        }
        let out = self.inner.merge(repo, branch, into);
        if out.is_ok() {
            self.st.tested.remove(branch);
        }
        out
    }
}

/// The commits the hub-route features of an orchestration reported, by branch: what [`HubMerger`] tests.
pub fn reported_commits(book: &Book, orch_id: &str) -> BTreeMap<String, String> {
    book.orchestration(orch_id)
        .map(|o| {
            o.features
                .iter()
                .filter(|f| f.transport == Transport::Hub)
                .filter_map(|f| f.commit.clone().map(|c| (f.branch.clone(), c)))
                .collect()
        })
        .unwrap_or_default()
}
