//! The scheduler's decisions: what is due, what is skipped, what is made up, and what fires.
//!
//! Three phases, so nothing that waits on the network runs while the store is locked or on the request thread:
//!
//! 1. [`decide`] (fast, under the store lock): take the lease, read each schedule's slots, claim the ones that fire
//!    (fenced by the epoch), write the run records and say what to start.
//! 2. [`execute`] (may wait: wakes a paused box, starts the run): returns an [`Outcome`].
//! 3. [`settle`] and [`poll_open`] (fast): write what happened; follow runs already going.
//!
//! Rules, each with a test: a missed slot is made up once if it is still inside the catch-up window and otherwise
//! skipped with a notice, never replayed as a burst; a schedule whose last run is still going skips the new slot
//! (Forbid); a paused target box is woken, and left for its own auto-pause to put back to sleep.

use std::io;

use ozbox_core::BoxState;

use super::cron::Cron;
use super::model::*;
use super::runner::{BoxControl, Poll, RunRequest, RunStarter};
use super::store::{self, ClaimError, Store};
use crate::messages::t;

/// How long a `Starting` run may sit before it is called lost (the dashboard stopped between claiming and starting).
const STARTING_LOST_MS: u64 = 10 * 60_000;
/// At most this many slots are looked at in one tick.
const MAX_SLOTS: usize = 64;

/// Something for a person to be told (routed like any alert).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Notice {
    pub key: String,
    pub title: String,
    pub body: String,
    pub box_name: Option<String>,
}

/// A run to start now.
#[derive(Debug, Clone, PartialEq)]
pub struct Fire {
    pub run_id: String,
    pub req: RunRequest,
    /// The box to use, or the profile to choose one from.
    pub target: Target,
}

#[derive(Debug, Default)]
pub struct Decided {
    /// This process holds the lease.
    pub holder: bool,
    pub epoch: u64,
    pub fires: Vec<Fire>,
    pub notices: Vec<Notice>,
}

#[derive(Debug, Clone, PartialEq)]
pub enum Outcome {
    Started {
        run_id: String,
        run_ref: String,
        box_name: String,
        woke: bool,
    },
    Failed {
        run_id: String,
        reason: String,
        detail: String,
        box_name: Option<String>,
        woke: bool,
    },
}

pub fn new_id(prefix: &str) -> String {
    let mut b = [0u8; 5];
    let _ = getrandom::getrandom(&mut b);
    let hex: String = b.iter().map(|x| format!("{x:02x}")).collect();
    format!("{prefix}-{hex}")
}

/// The slots of a schedule in `(cursor, now]`, ascending.
pub fn slots(s: &Schedule, st: &SchedState, now_ms: u64) -> Vec<u64> {
    let cursor = st.armed_ms.max(st.last_slot_ms.unwrap_or(0));
    match &s.when {
        When::Cron { expr } => Cron::parse(expr)
            .map(|c| c.between(&s.time_zone, cursor, now_ms, MAX_SLOTS))
            .unwrap_or_default(),
        When::Every { minutes } => {
            let step = u64::from(*minutes).max(1) * 60_000;
            let base = st.armed_ms;
            if now_ms <= base {
                return Vec::new();
            }
            let first = (cursor.saturating_sub(base)) / step + 1;
            let last = (now_ms - base) / step;
            if last < first {
                return Vec::new();
            }
            let first = first.max(last.saturating_sub(MAX_SLOTS as u64 - 1));
            (first..=last).map(|k| base + k * step).collect()
        }
    }
}

/// The next fire after `after_ms`.
pub fn next_after(s: &Schedule, st: &SchedState, after_ms: u64) -> Option<u64> {
    match &s.when {
        When::Cron { expr } => Cron::parse(expr).ok()?.next_after(&s.time_zone, after_ms),
        When::Every { minutes } => {
            let step = u64::from(*minutes).max(1) * 60_000;
            let base = st.armed_ms;
            let k = after_ms.saturating_sub(base) / step + 1;
            Some(base + k * step)
        }
    }
}

fn rec(id: &str, owner: &str, source: &str, slot: Option<u64>, now: u64) -> RunRec {
    RunRec {
        id: id.to_string(),
        owner_id: owner.to_string(),
        source: source.to_string(),
        slot_ms: slot,
        started_ms: now,
        ..Default::default()
    }
}

fn request(s: &Schedule, run_id: &str, source: &str) -> RunRequest {
    let prompt = s
        .prompt
        .clone()
        .filter(|p| !p.trim().is_empty())
        .unwrap_or_else(|| t("sched.heartbeat_prompt", &[]));
    RunRequest {
        run_id: run_id.to_string(),
        source: source.to_string(),
        owner_id: s.id.clone(),
        engine: s.engine.clone(),
        prompt,
        skill: s.skill.clone().filter(|k| !k.is_empty()),
        box_name: String::new(),
        caps: s.caps.clone(),
        results_to: s.results_to.clone(),
    }
}

fn open_run_for(doc: &Doc, schedule_id: &str) -> Option<String> {
    let running = doc.state.get(schedule_id)?.running.clone()?;
    doc.runs
        .iter()
        .find(|r| r.id == running && r.status.is_open())
        .map(|r| r.id.clone())
}

/// Phase 1. `me` is this process's id; the same id must be used for every call.
pub fn decide(store: &Store, me: &str, now_ms: u64) -> io::Result<Decided> {
    store.update_retry(|doc| decide_in(doc, me, now_ms))
}

pub fn decide_in(doc: &mut Doc, me: &str, now_ms: u64) -> Decided {
    let mut out = Decided::default();
    let Some(epoch) = store::acquire(doc, me, now_ms) else {
        return out;
    };
    out.holder = true;
    out.epoch = epoch;

    // Runs that were claimed but never started (the dashboard stopped in between) are lost, not "running" forever.
    let mut lost = Vec::new();
    for r in doc.runs.iter_mut() {
        if r.status == RunStatus::Starting && now_ms.saturating_sub(r.started_ms) > STARTING_LOST_MS
        {
            r.status = RunStatus::Failed;
            r.finished_ms = Some(now_ms);
            r.reason = "lost".into();
            r.detail = t("sched.run_lost", &[]);
            lost.push((r.id.clone(), r.owner_id.clone()));
        }
    }
    for (id, owner) in lost {
        if let Some(st) = doc.state.get_mut(&owner) {
            if st.running.as_deref() == Some(id.as_str()) {
                st.running = None;
            }
        }
    }

    let ids: Vec<String> = doc.schedules.iter().map(|s| s.id.clone()).collect();
    for id in ids {
        let Some(s) = doc.schedule(&id).cloned() else {
            continue;
        };
        if !s.enabled {
            continue;
        }
        let st = doc.state.entry(id.clone()).or_insert_with(|| SchedState {
            armed_ms: now_ms,
            ..Default::default()
        });
        if st.running.is_some() && open_run_for_ro(&doc.runs, st).is_none() {
            st.running = None;
        }

        // A manual run, asked for from outside the server.
        let mine: Vec<RunNow> = doc
            .run_now
            .iter()
            .filter(|r| r.schedule_id == id)
            .cloned()
            .collect();
        doc.run_now.retain(|r| r.schedule_id != id);
        for m in mine {
            fire_or_skip(
                doc,
                &s,
                "manual",
                None,
                0,
                now_ms,
                me,
                epoch,
                &mut out,
                Some(&m.by),
            );
        }

        let st = doc.state.get(&id).cloned().unwrap_or_default();
        let due = slots(&s, &st, now_ms);
        let Some(&latest) = due.last() else {
            continue;
        };
        let dropped = due.len() - 1;
        let late = now_ms.saturating_sub(latest);
        let window = u64::from(s.catch_up_minutes) * 60_000;
        if let Some(stm) = doc.state.get_mut(&id) {
            stm.last_slot_ms = Some(latest);
        }
        if late > window {
            let run_id = new_id("run");
            let mut r = rec(&run_id, &id, "schedule", Some(latest), now_ms);
            r.status = RunStatus::Missed;
            r.finished_ms = Some(now_ms);
            r.reason = "missed".into();
            r.detail = t(
                "sched.run_missed",
                &[
                    ("minutes", &(late / 60_000).to_string()),
                    ("window", &s.catch_up_minutes.to_string()),
                ],
            );
            doc.runs.push(r);
            out.notices.push(Notice {
                key: format!("schedule:{id}:missed:{latest}"),
                title: t("sched.notice_missed_title", &[("name", &s.name)]),
                body: t(
                    "sched.notice_missed_body",
                    &[("minutes", &(late / 60_000).to_string())],
                ),
                box_name: s.target.box_name.clone(),
            });
            continue;
        }
        fire_or_skip(
            doc,
            &s,
            "schedule",
            Some(latest),
            late,
            now_ms,
            me,
            epoch,
            &mut out,
            None,
        );
        if dropped > 0 {
            if let Some(r) = doc.runs.last_mut() {
                let extra = t("sched.also_skipped", &[("count", &dropped.to_string())]);
                r.detail = if r.detail.is_empty() {
                    extra
                } else {
                    format!("{} {extra}", r.detail)
                };
                r.args.insert("skipped_earlier".into(), dropped.to_string());
            }
        }
    }
    doc.trim(now_ms);
    out
}

fn open_run_for_ro<'a>(runs: &'a [RunRec], st: &SchedState) -> Option<&'a RunRec> {
    let id = st.running.as_deref()?;
    runs.iter().find(|r| r.id == id && r.status.is_open())
}

#[allow(clippy::too_many_arguments)]
fn fire_or_skip(
    doc: &mut Doc,
    s: &Schedule,
    source: &str,
    slot: Option<u64>,
    late_ms: u64,
    now_ms: u64,
    me: &str,
    epoch: u64,
    out: &mut Decided,
    by: Option<&str>,
) {
    let run_id = new_id("run");
    let mut r = rec(&run_id, &s.id, source, slot, now_ms);
    if let Some(open) = open_run_for(doc, &s.id) {
        r.status = RunStatus::Skipped;
        r.finished_ms = Some(now_ms);
        r.reason = "overlap".into();
        r.detail = t("sched.run_skipped_overlap", &[("run", &open)]);
        r.args.insert("run".into(), open);
        doc.runs.push(r);
        return;
    }
    if let Some(slot) = slot {
        match store::claim(doc, &s.id, slot, me, epoch, now_ms) {
            Ok(()) => {}
            Err(ClaimError::Taken | ClaimError::Fenced) => return,
        }
    }
    r.epoch = epoch;
    if late_ms > 90_000 {
        r.reason = "caught_up".into();
        r.detail = t(
            "sched.run_caught_up",
            &[("minutes", &(late_ms / 60_000).to_string())],
        );
        r.args
            .insert("late_minutes".into(), (late_ms / 60_000).to_string());
    }
    if let Some(by) = by {
        r.args.insert("by".into(), by.to_string());
    }
    doc.runs.push(r);
    if let Some(st) = doc.state.get_mut(&s.id) {
        st.running = Some(run_id.clone());
    }
    out.fires.push(Fire {
        run_id: run_id.clone(),
        req: request(s, &run_id, source),
        target: s.target.clone(),
    });
}

/// Phase 2: wake a paused box if needed, then start the run. Blocks; never call it under the store lock.
pub fn execute(fire: &Fire, boxes: &dyn BoxControl, runs: &dyn RunStarter) -> Outcome {
    let failed =
        |reason: &str, detail: String, box_name: Option<String>, woke: bool| Outcome::Failed {
            run_id: fire.run_id.clone(),
            reason: reason.into(),
            detail,
            box_name,
            woke,
        };
    let name = match (&fire.target.box_name, &fire.target.profile) {
        (Some(b), _) => b.clone(),
        (None, Some(p)) => match boxes.pick(p) {
            Ok(Some(b)) => b,
            Ok(None) => {
                return failed(
                    "no_box",
                    t("sched.no_box_for_profile", &[("profile", p)]),
                    None,
                    false,
                )
            }
            Err(e) => return failed("box_error", e, None, false),
        },
        (None, None) => return failed("no_box", t("sched.need_target", &[]), None, false),
    };
    let mut woke = false;
    match boxes.state(&name) {
        Ok(Some(BoxState::Running)) => {}
        Ok(Some(BoxState::Paused)) => {
            if let Err(e) = boxes.resume(&name) {
                return failed(
                    "resume_failed",
                    t("sched.resume_failed", &[("box", &name), ("error", &e)]),
                    Some(name),
                    false,
                );
            }
            woke = true;
        }
        Ok(Some(other)) => {
            return failed(
                "box_busy",
                t(
                    "sched.box_busy",
                    &[
                        ("box", &name),
                        ("state", &format!("{other:?}").to_lowercase()),
                    ],
                ),
                Some(name),
                false,
            )
        }
        Ok(None) => {
            return failed(
                "box_missing",
                t("sched.box_missing", &[("box", &name)]),
                Some(name),
                false,
            )
        }
        Err(e) => return failed("box_error", e, Some(name), false),
    }
    let mut req = fire.req.clone();
    req.box_name = name.clone();
    match runs.start(&req) {
        Ok(run_ref) => Outcome::Started {
            run_id: fire.run_id.clone(),
            run_ref,
            box_name: name,
            woke,
        },
        Err(e) => failed(&e.reason, e.detail, Some(name), woke),
    }
}

fn failure_notice(
    s: Option<&Schedule>,
    owner: &str,
    run_id: &str,
    box_name: Option<String>,
    detail: &str,
) -> Notice {
    let name = s.map_or(owner.to_string(), |s| s.name.clone());
    Notice {
        key: format!("schedule:{owner}:failed:{run_id}"),
        title: t("sched.notice_failed_title", &[("name", &name)]),
        body: detail.to_string(),
        box_name,
    }
}

/// Phase 3: record what [`execute`] did.
pub fn settle(store: &Store, outcome: &Outcome, now_ms: u64) -> io::Result<Vec<Notice>> {
    store.update_retry(|doc| {
        let mut notices = Vec::new();
        let (run_id, ok, woke, box_name, reason, detail, run_ref) = match outcome {
            Outcome::Started {
                run_id,
                run_ref,
                box_name,
                woke,
            } => (
                run_id,
                true,
                *woke,
                Some(box_name.clone()),
                String::new(),
                String::new(),
                Some(run_ref.clone()),
            ),
            Outcome::Failed {
                run_id,
                reason,
                detail,
                box_name,
                woke,
            } => (
                run_id,
                false,
                *woke,
                box_name.clone(),
                reason.clone(),
                detail.clone(),
                None,
            ),
        };
        let Some(i) = doc.runs.iter().position(|r| &r.id == run_id) else {
            return notices;
        };
        let owner = doc.runs[i].owner_id.clone();
        let source = doc.runs[i].source.clone();
        {
            let r = &mut doc.runs[i];
            r.box_name = box_name.clone();
            r.woke_box = woke;
            if ok {
                r.status = RunStatus::Running;
                r.run_ref = run_ref;
            } else {
                r.status = RunStatus::Failed;
                r.finished_ms = Some(now_ms);
                r.reason = reason;
                r.detail = detail.clone();
            }
        }
        if !ok {
            if let Some(st) = doc.state.get_mut(&owner) {
                if st.running.as_deref() == Some(run_id.as_str()) {
                    st.running = None;
                }
            }
            if source != "trigger" || doc.trigger(&owner).is_some() {
                let s = doc.schedule(&owner).cloned();
                notices.push(failure_notice(
                    s.as_ref(),
                    &owner,
                    run_id,
                    box_name,
                    &detail,
                ));
            }
        }
        notices
    })
}

/// Runs being followed: `(run id, reference)`.
pub fn open_runs(doc: &Doc) -> Vec<(String, String)> {
    doc.runs
        .iter()
        .filter(|r| r.status == RunStatus::Running)
        .filter_map(|r| r.run_ref.clone().map(|f| (r.id.clone(), f)))
        .collect()
}

/// Phase 3b: apply what the run system said about the runs in flight.
pub fn settle_polls(
    store: &Store,
    polls: &[(String, Poll)],
    now_ms: u64,
) -> io::Result<Vec<Notice>> {
    store.update_retry(|doc| {
        let mut notices = Vec::new();
        for (run_id, poll) in polls {
            let Some(i) = doc.runs.iter().position(|r| &r.id == run_id) else {
                continue;
            };
            if doc.runs[i].status != RunStatus::Running {
                continue;
            }
            let (ok, detail, cost, url, reason) = match poll {
                Poll::Running => continue,
                Poll::Finished {
                    ok,
                    detail,
                    cost,
                    result_url,
                } => (
                    *ok,
                    detail.clone(),
                    *cost,
                    result_url.clone(),
                    if *ok { "" } else { "run_failed" },
                ),
                Poll::Unknown => (false, t("sched.run_unknown", &[]), None, None, "lost"),
            };
            let owner = doc.runs[i].owner_id.clone();
            let box_name = doc.runs[i].box_name.clone();
            {
                let r = &mut doc.runs[i];
                r.status = if ok {
                    RunStatus::Succeeded
                } else {
                    RunStatus::Failed
                };
                r.finished_ms = Some(now_ms);
                r.cost = cost;
                r.result_url = url;
                r.reason = reason.to_string();
                if !detail.is_empty() {
                    r.detail = detail.clone();
                }
            }
            if let Some(st) = doc.state.get_mut(&owner) {
                if st.running.as_deref() == Some(run_id.as_str()) {
                    st.running = None;
                }
            }
            if !ok {
                let s = doc.schedule(&owner).cloned();
                notices.push(failure_notice(
                    s.as_ref(),
                    &owner,
                    run_id,
                    box_name,
                    &detail,
                ));
            }
        }
        notices
    })
}

/// Everything in one go, for tests: decide, execute, settle, poll.
#[cfg(test)]
pub fn tick_blocking(
    store: &Store,
    me: &str,
    now_ms: u64,
    boxes: &dyn BoxControl,
    runs: &dyn RunStarter,
) -> io::Result<Vec<Notice>> {
    let d = decide(store, me, now_ms)?;
    let mut notices = d.notices;
    for f in &d.fires {
        let o = execute(f, boxes, runs);
        notices.extend(settle(store, &o, now_ms)?);
    }
    let polls: Vec<(String, Poll)> = open_runs(&store.read())
        .into_iter()
        .map(|(id, r)| (id, runs.poll(&r)))
        .collect();
    notices.extend(settle_polls(store, &polls, now_ms)?);
    Ok(notices)
}
