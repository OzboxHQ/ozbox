//! The merge queue: features go into the base branch one at a time, each rebased onto what the one before it left.
//!
//! The decisions are pure and run over a [`Merger`] (the real one runs `git` through the conductor box's agent as an
//! argv list; tests use a fake). One call to [`merge_step`] does one thing to the head of the queue, so a slow test run
//! never blocks the server loop and every step is a record:
//!
//! 1. **Rebase** the feature's branch onto the base. A conflict returns the work to the owning worker with the file
//!    names; the next feature in the queue goes on.
//! 2. **Test** with the project's command (on a test-lane box when one is set). Failing tests go back to the worker.
//! 3. **Approval** as the policy requires: nothing, the conductor, or the person. It is an ordinary approval request
//!    (so chat, the dashboard and the passkey step-up all apply); a request the person must decide needs a second
//!    factor and the conductor can never decide it.
//! 4. **Merge**, and the feature is `Merged`; its worker box is paused by [`crate::orch::Orchestration::sweep_boxes`].

use serde::{Deserialize, Serialize};

use crate::orch::{FeatureState, MergeEntry, MergeState, MsgKind, OrchError, Orchestration};
use crate::orch_rules::MergeApproval;
use crate::run::{ActionKind, ApprovalRequest, ApprovalState, Book};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RebaseOutcome {
    Clean,
    /// The files that conflict.
    Conflict(Vec<String>),
    /// Still working on the box: ask again on the next tick.
    Pending,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TestOutcome {
    Pass,
    /// The last lines of the output, with no secret.
    Fail(String),
    Pending,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MergeOutcome {
    Done,
    Pending,
}

/// What the queue needs from the conductor's box. Every method is one argv-array command there, never a shell string.
pub trait Merger {
    fn rebase(
        &mut self,
        repo: Option<&str>,
        branch: &str,
        onto: &str,
    ) -> Result<RebaseOutcome, String>;
    fn test(
        &mut self,
        repo: Option<&str>,
        branch: &str,
        argv: &[String],
        lane: Option<&str>,
    ) -> Result<TestOutcome, String>;
    fn merge(
        &mut self,
        repo: Option<&str>,
        branch: &str,
        into: &str,
    ) -> Result<MergeOutcome, String>;
    /// The commit `branch` points at on the conductor's side right now, when this merger can say. The merge queue over the hub
    /// refuses to merge a branch that moved after its lane tested it. The default says nothing, and the check then rests on the
    /// commit the worker reported.
    fn head(&mut self, _repo: Option<&str>, _branch: &str) -> Result<Option<String>, String> {
        Ok(None)
    }

    /// [`Merger::head`] for a merger whose reads take time (the conductor's box reads the remote through its daemon, a step at a
    /// time): `Pending` until it can say. The default answers at once with [`Merger::head`].
    fn head_step(&mut self, repo: Option<&str>, branch: &str) -> Result<HeadRead, String> {
        Ok(HeadRead::Known(self.head(repo, branch)?))
    }
}

/// What a read of a branch's head came back with.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HeadRead {
    /// Still being read: ask again on the next tick.
    Pending,
    /// The commit the branch points at on the conductor's side, or `None` when this merger cannot say.
    Known(Option<String>),
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MergeStep {
    pub feature_id: String,
    pub state: MergeState,
    pub detail: String,
}

/// The approval id a merge request is filed under: it belongs to no task, so the supervisor never tries to resume an
/// engine for it.
pub fn merge_task_id(orch_id: &str) -> String {
    format!("orch:{orch_id}")
}

impl Orchestration {
    /// Put a finished feature at the back of the queue.
    pub fn enqueue_merge(&mut self, feature_id: &str, now_ms: u64) -> Result<usize, OrchError> {
        let f = self.feature(feature_id).ok_or(OrchError::NoFeature)?;
        if !matches!(
            f.state,
            FeatureState::ReadyToMerge | FeatureState::ConflictReturned | FeatureState::Working
        ) {
            return Err(OrchError::Conflict(
                "only a feature that has finished its work can join the merge queue".into(),
            ));
        }
        if self
            .merge_queue
            .iter()
            .any(|e| e.feature_id == feature_id && !e.state.is_finished())
        {
            return Err(OrchError::Conflict(
                "that feature is already in the merge queue".into(),
            ));
        }
        self.merge_queue.retain(|e| e.feature_id != feature_id);
        self.merge_queue.push(MergeEntry {
            feature_id: feature_id.to_string(),
            queued_ms: now_ms,
            state: MergeState::Waiting,
            detail: String::new(),
            approval_id: None,
        });
        if let Some(f) = self.feature_mut(feature_id) {
            f.state = FeatureState::InQueue;
        }
        self.updated_ms = now_ms;
        Ok(self
            .merge_queue
            .iter()
            .filter(|e| !e.state.is_finished())
            .count())
    }

    /// Whether the conductor may decide this approval: only a merge the policy lets it approve, never one that needs a
    /// second factor or touches production.
    pub fn conductor_may_decide(&self, a: &ApprovalRequest) -> bool {
        if a.needs_step_up || a.production {
            return false;
        }
        if a.task_id == merge_task_id(&self.id) {
            return self.policy.merge_approval == MergeApproval::Conductor;
        }
        let owned = self
            .features
            .iter()
            .any(|f| f.task_id.as_deref() == Some(a.task_id.as_str()));
        owned && self.policy.conductor_may.contains(&a.kind) && !is_risky(a.kind)
    }
}

/// Kinds the conductor can never decide, whatever the settings say.
pub fn is_risky(k: ActionKind) -> bool {
    matches!(
        k,
        ActionKind::PushProtectedBranch
            | ActionKind::OpenPrToMain
            | ActionKind::OutboundMessage
            | ActionKind::SpendAboveThreshold
            | ActionKind::ProductionResource
            | ActionKind::ToolCall
    )
}

fn say(o: &mut Orchestration, now_ms: u64, feature: &str, kind: MsgKind, text: &str) {
    let _ = o.post(
        now_ms,
        "system",
        &format!("feature:{feature}"),
        kind,
        text,
        None,
        false,
    );
}

/// Advance the head of an orchestration's merge queue by one step. Returns what happened, or `None` when there is
/// nothing to do (the queue is empty or the head waits for an answer).
pub fn merge_step(
    book: &mut Book,
    orch_id: &str,
    merger: &mut dyn Merger,
    now_ms: u64,
) -> Option<MergeStep> {
    let o = book.orchestration(orch_id)?;
    if o.state != crate::orch::OrchState::Active {
        return None;
    }
    let idx = o.merge_queue.iter().position(|e| !e.state.is_finished())?;
    let entry = o.merge_queue[idx].clone();
    let (repo, base, test, lane) = {
        let f = o.feature(&entry.feature_id)?;
        (
            f.repo.clone(),
            o.policy.base_branch.clone(),
            o.policy.test_command.clone(),
            o.policy.test_lane_box.clone(),
        )
    };
    let branch = o.feature(&entry.feature_id)?.branch.clone();
    let fid = entry.feature_id.clone();
    let set = |book: &mut Book, state: MergeState, detail: &str| {
        if let Some(o) = book.orchestration_mut(orch_id) {
            if let Some(e) = o
                .merge_queue
                .iter_mut()
                .find(|e| e.feature_id == fid && !e.state.is_finished())
            {
                e.state = state;
                e.detail = detail.chars().take(300).collect();
            }
            o.updated_ms = now_ms;
        }
    };
    let step = |state: MergeState, detail: &str| MergeStep {
        feature_id: fid.clone(),
        state,
        detail: detail.to_string(),
    };
    match entry.state {
        MergeState::Waiting | MergeState::Rebasing => {
            set(book, MergeState::Rebasing, "");
            match merger.rebase(repo.as_deref(), &branch, &base) {
                Err(e) => {
                    // the box could not be asked: stay waiting and say why; nothing was changed
                    set(book, MergeState::Waiting, &e);
                    Some(step(MergeState::Waiting, &e))
                }
                Ok(RebaseOutcome::Conflict(files)) => {
                    let list = files
                        .iter()
                        .take(20)
                        .cloned()
                        .collect::<Vec<_>>()
                        .join(", ");
                    set(book, MergeState::Conflict, &list);
                    if let Some(o) = book.orchestration_mut(orch_id) {
                        if let Some(f) = o.feature_mut(&fid) {
                            f.state = FeatureState::ConflictReturned;
                            f.resume_pending = true;
                        }
                        say(
                            o,
                            now_ms,
                            &fid,
                            MsgKind::Blocked,
                            &format!("Your branch conflicts with {base} in: {list}. Rebase onto {base}, resolve the conflicts inside your own claims, run the tests and say when it is ready again."),
                        );
                    }
                    book.record(
                        now_ms,
                        "supervisor",
                        "orchestration.merge_conflict",
                        None,
                        &format!("{orch_id}/{fid}"),
                    );
                    Some(step(MergeState::Conflict, &list))
                }
                Ok(RebaseOutcome::Pending) => Some(step(MergeState::Rebasing, "working")),
                Ok(RebaseOutcome::Clean) => {
                    set(book, MergeState::Testing, "");
                    Some(step(MergeState::Testing, "rebased"))
                }
            }
        }
        MergeState::Testing => {
            if !test.is_empty() {
                match merger.test(repo.as_deref(), &branch, &test, lane.as_deref()) {
                    Err(e) => {
                        set(book, MergeState::Testing, &e);
                        return Some(step(MergeState::Testing, &e));
                    }
                    Ok(TestOutcome::Fail(tail)) => {
                        set(book, MergeState::TestsFailed, &tail);
                        if let Some(o) = book.orchestration_mut(orch_id) {
                            if let Some(f) = o.feature_mut(&fid) {
                                f.state = FeatureState::ConflictReturned;
                                f.resume_pending = true;
                            }
                            say(o, now_ms, &fid, MsgKind::Blocked, &format!("The tests failed after rebasing. Fix them and say when it is ready again. The end of the output:\n{tail}"));
                        }
                        return Some(step(MergeState::TestsFailed, &tail));
                    }
                    Ok(TestOutcome::Pending) => return Some(step(MergeState::Testing, "working")),
                    Ok(TestOutcome::Pass) => {}
                }
            }
            let need = book.orchestration(orch_id)?.policy.merge_approval;
            if need == MergeApproval::None {
                set(book, MergeState::Merging, "tests passed");
                return Some(step(MergeState::Merging, "tests passed"));
            }
            book.next_seq += 1;
            let aid = format!("a{}", book.next_seq);
            let (boxn, expiry) = (
                book.orchestration(orch_id)?.conductor_box.clone(),
                book.policy.expiry_s * 1000,
            );
            book.approvals.push(ApprovalRequest {
                id: aid.clone(),
                task_id: merge_task_id(orch_id),
                kind: ActionKind::PushProtectedBranch,
                action: format!("merge {branch} into {base}"),
                box_name: boxn,
                asked_by: format!("orchestration {orch_id}"),
                production: false,
                needs_step_up: need == MergeApproval::Person,
                state: ApprovalState::Pending,
                created_ms: now_ms,
                expires_ms: now_ms + expiry,
                reminders: 0,
                decided_by: None,
                decided_ms: None,
                decided_with_step_up: false,
                delivered: true,
                used: false,
            });
            book.record(
                now_ms,
                "supervisor",
                "approval.requested",
                None,
                &format!("merge {branch} into {base}"),
            );
            if let Some(o) = book.orchestration_mut(orch_id) {
                if let Some(e) = o
                    .merge_queue
                    .iter_mut()
                    .find(|e| e.feature_id == fid && !e.state.is_finished())
                {
                    e.state = MergeState::AwaitingApproval;
                    e.approval_id = Some(aid.clone());
                    e.detail = "waiting for approval".into();
                }
                let to = if need == MergeApproval::Person {
                    "person"
                } else {
                    "conductor"
                };
                let _ = o.post(
                    now_ms,
                    "system",
                    to,
                    MsgKind::Approval,
                    &format!("Approve merging {branch} into {base}? Tests passed."),
                    None,
                    need == MergeApproval::Person,
                );
                if let Some(m) = o.messages.last_mut() {
                    m.approval_id = Some(aid);
                }
            }
            Some(step(MergeState::AwaitingApproval, "waiting for approval"))
        }
        MergeState::AwaitingApproval => {
            let aid = entry.approval_id.clone()?;
            let st = book.approval(&aid).map(|a| a.state)?;
            match st {
                ApprovalState::Pending => None,
                ApprovalState::Approved => {
                    set(book, MergeState::Merging, "approved");
                    Some(step(MergeState::Merging, "approved"))
                }
                ApprovalState::Denied | ApprovalState::Expired => {
                    let why = if st == ApprovalState::Denied {
                        "the merge was not approved"
                    } else {
                        "the approval expired"
                    };
                    set(book, MergeState::Failed, why);
                    if let Some(o) = book.orchestration_mut(orch_id) {
                        if let Some(f) = o.feature_mut(&fid) {
                            f.state = FeatureState::ReadyToMerge;
                        }
                        say(o, now_ms, &fid, MsgKind::Status, &format!("{why}. The feature stays ready; ask the conductor to queue it again."));
                    }
                    Some(step(MergeState::Failed, why))
                }
            }
        }
        MergeState::Merging => match merger.merge(repo.as_deref(), &branch, &base) {
            Err(e) => {
                set(book, MergeState::Failed, &e);
                if let Some(o) = book.orchestration_mut(orch_id) {
                    if let Some(f) = o.feature_mut(&fid) {
                        f.state = FeatureState::ReadyToMerge;
                    }
                }
                Some(step(MergeState::Failed, &e))
            }
            Ok(MergeOutcome::Pending) => Some(step(MergeState::Merging, "working")),
            Ok(MergeOutcome::Done) => {
                set(book, MergeState::Merged, "");
                if let Some(o) = book.orchestration_mut(orch_id) {
                    if let Some(f) = o.feature_mut(&fid) {
                        f.state = FeatureState::Merged;
                        f.merged_ms = Some(now_ms);
                    }
                    if o.features
                        .iter()
                        .all(|f| !f.state.is_open() || f.state == FeatureState::Merged)
                        && !o.features.is_empty()
                        && o.features.iter().all(|f| f.state == FeatureState::Merged)
                    {
                        o.state = crate::orch::OrchState::Done;
                    }
                }
                book.record(
                    now_ms,
                    "supervisor",
                    "orchestration.merged",
                    None,
                    &format!("{orch_id}/{fid}"),
                );
                Some(step(MergeState::Merged, ""))
            }
        },
        _ => None,
    }
}
