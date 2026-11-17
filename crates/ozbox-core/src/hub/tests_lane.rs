//! Test lanes and the merge queue over the channel: a split that keeps resource groups whole, results gathered honestly (never a
//! partial green), a worker lost mid-shard, and a worker's finished commit going through `main`'s merge queue with what it finds
//! said back to the worker.

#![allow(clippy::unwrap_used)]

use super::engine::{Hub, HubState};
use super::lane::{plan, ShardResult, Spec, Split, Verdict, LOST_AFTER_MS};
use super::mem::TestSealer;
use super::merge::{admit_results, reported_commits, return_to_worker, HubMerger, LaneDecl};
use super::tests::{assign, fx, Fx, HUB_FP, W2_FP};
use super::worker::{WorkerEnd, WorkerState};
use crate::orch::{FeatureReq, FeatureState, MergeState};
use crate::orch_merge::{merge_step, MergeOutcome, Merger, RebaseOutcome, TestOutcome};
use crate::orch_rules::MergeApproval;
use crate::run::{ApprovalState, Book};

const SHA: &str = "0123456789abcdef0123456789abcdef01234567";

fn spec(file: &str, res: Option<&str>, w: Option<u64>) -> Spec {
    Spec {
        file: file.into(),
        resource: res.map(str::to_string),
        weight_ms: w,
    }
}

fn suite() -> Vec<Spec> {
    vec![
        spec("a.spec.ts", None, Some(9_000)),
        spec("b.spec.ts", Some("sandbox-1"), Some(2_000)),
        spec("c.spec.ts", Some("sandbox-1"), Some(2_000)),
        spec("d.spec.ts", None, Some(3_000)),
        spec("e.spec.ts", None, None),
    ]
}

fn keys() -> Vec<String> {
    vec!["sandbox-1".to_string()]
}

#[test]
fn the_split_keeps_a_resource_group_on_one_worker_in_order_and_refuses_an_unknown_key() {
    let p = plan(&suite(), 2, &keys()).unwrap();
    assert_eq!(p.len(), 2);
    let with_b = p
        .iter()
        .find(|s| s.contains(&"b.spec.ts".to_string()))
        .unwrap();
    let bi = with_b.iter().position(|f| f == "b.spec.ts").unwrap();
    assert_eq!(with_b.get(bi + 1).map(String::as_str), Some("c.spec.ts"));
    // longest first: the heaviest spec sits alone against the rest
    assert!(p.iter().any(|s| s == &vec!["a.spec.ts".to_string()]));
    // every spec exactly once
    let mut all: Vec<String> = p.concat();
    all.sort();
    assert_eq!(all.len(), 5);
    assert!(plan(&[spec("x", Some("stranger"), None)], 1, &keys())
        .unwrap_err()
        .contains("not one this hub knows"));
    assert!(plan(&suite(), 0, &keys()).is_err());
    assert!(plan(&[spec("x", None, None), spec("x", None, None)], 1, &keys()).is_err());
    // the same input, the same plan
    assert_eq!(plan(&suite(), 2, &keys()).unwrap(), p);
}

/// The wires and keys of main and two workers.
struct Net {
    f: Fx,
    w2_sealer: TestSealer,
}

impl Net {
    fn hub(&self) -> Hub<'_> {
        self.f.hub()
    }

    fn w1(&self) -> WorkerEnd<'_> {
        self.f.worker()
    }

    fn w2(&self) -> WorkerEnd<'_> {
        WorkerEnd {
            me: "worker-2",
            hub: "main",
            signer: &self.f.signers["worker-2"],
            verifier: &self.f.roster_keys,
            sealer: &self.w2_sealer,
            net: &self.f.net,
        }
    }
}

/// What each end keeps.
struct States {
    hs: HubState,
    ws1: WorkerState,
    ws2: WorkerState,
}

/// Main and two workers, both with a session.
struct Two {
    n: Net,
    s: States,
}

impl Two {
    fn new(now: u64) -> Two {
        let f = fx();
        let mut t = Two {
            s: States {
                hs: f.hub_state(),
                ws1: f.worker_state(),
                ws2: WorkerState::new("worker-2", W2_FP, "main", HUB_FP, 7),
            },
            n: Net {
                f,
                w2_sealer: TestSealer {
                    my_fp: W2_FP.into(),
                },
            },
        };
        let (n, s) = (&t.n, &mut t.s);
        n.w1().hello(&mut s.ws1, now);
        n.w2().hello(&mut s.ws2, now);
        for _ in 0..6 {
            n.hub().poll(&mut s.hs, now);
            n.w1().poll(&mut s.ws1, now);
            n.w2().poll(&mut s.ws2, now);
        }
        assert_eq!(t.s.hs.peer_inc("worker-2"), t.s.ws2.inc());
        t
    }

    /// Each worker takes what it was sent.
    fn workers_poll(&mut self, now: u64) {
        self.n.w1().poll(&mut self.s.ws1, now);
        self.n.w2().poll(&mut self.s.ws2, now);
    }

    /// A worker runs every shard it holds: the specs in `fail` fail, every other passes.
    fn run_shards(&mut self, which: u8, fail: &[&str], now: u64) {
        let (ws, end) = if which == 1 {
            (&mut self.s.ws1, self.n.w1())
        } else {
            (&mut self.s.ws2, self.n.w2())
        };
        for a in std::mem::take(&mut ws.shards) {
            let (failed, passed): (Vec<String>, Vec<String>) = a
                .specs
                .iter()
                .cloned()
                .partition(|s| fail.contains(&s.as_str()));
            end.shard_result(
                ws,
                now,
                &ShardResult {
                    run: a.run.clone(),
                    shard: a.shard,
                    passed,
                    failed,
                    flaky: Vec::new(),
                    finished: true,
                },
            );
        }
    }

    fn workers(&self) -> Vec<String> {
        vec!["worker-1".into(), "worker-2".into()]
    }
}

#[test]
fn a_lane_runs_across_two_workers_and_is_green_only_when_every_spec_passed() {
    let mut t = Two::new(10);
    let workers = t.workers();
    t.n.hub()
        .lane_start(
            &mut t.s.hs,
            "run-1",
            "browser",
            SHA,
            "browser-shard",
            Split::Weight,
            &suite(),
            &workers,
            &keys(),
            20,
        )
        .unwrap();
    t.workers_poll(21);
    assert_eq!(t.s.ws1.shards.len() + t.s.ws2.shards.len(), 2);
    assert!(t
        .s
        .ws1
        .shards
        .iter()
        .chain(&t.s.ws2.shards)
        .all(|a| a.commit == SHA && a.command == "browser-shard"));
    // only one worker has answered: running, never green
    t.run_shards(1, &[], 22);
    t.n.hub().poll(&mut t.s.hs, 23);
    assert!(matches!(
        t.n.hub().lane_tick(&mut t.s.hs, "run-1", 24),
        Some(Verdict::Running { .. })
    ));
    t.run_shards(2, &[], 25);
    t.n.hub().poll(&mut t.s.hs, 26);
    assert!(matches!(
        t.n.hub().lane_tick(&mut t.s.hs, "run-1", 27),
        Some(Verdict::Pass { .. })
    ));
}

#[test]
fn a_failing_spec_fails_the_lane_and_is_named() {
    let mut t = Two::new(10);
    let workers = t.workers();
    t.n.hub()
        .lane_start(
            &mut t.s.hs,
            "run-1",
            "browser",
            SHA,
            "browser-shard",
            Split::Weight,
            &suite(),
            &workers,
            &keys(),
            20,
        )
        .unwrap();
    t.workers_poll(21);
    t.run_shards(1, &["c.spec.ts", "a.spec.ts"], 22);
    t.run_shards(2, &["c.spec.ts", "a.spec.ts"], 22);
    t.n.hub().poll(&mut t.s.hs, 23);
    match t.n.hub().lane_tick(&mut t.s.hs, "run-1", 24) {
        Some(Verdict::Fail { failed }) => {
            assert_eq!(
                failed,
                vec!["a.spec.ts".to_string(), "c.spec.ts".to_string()]
            );
        }
        v => panic!("{v:?}"),
    }
}

#[test]
fn a_worker_lost_mid_shard_has_its_unfinished_specs_and_whole_resource_group_rerun_elsewhere() {
    let mut t = Two::new(10);
    let workers = t.workers();
    t.n.hub()
        .lane_start(
            &mut t.s.hs,
            "run-1",
            "browser",
            SHA,
            "browser-shard",
            Split::Weight,
            &suite(),
            &workers,
            &keys(),
            20,
        )
        .unwrap();
    t.workers_poll(21);
    // worker-2 holds the sandbox group; it reports b (half the group) and then goes silent
    let (w2_has_group, w2_shard) = {
        let a = &t.s.ws2.shards[0];
        (a.specs.contains(&"b.spec.ts".to_string()), a.clone())
    };
    let (lose_ws, lose_end_is_2) = if w2_has_group {
        (&mut t.s.ws2, true)
    } else {
        (&mut t.s.ws1, false)
    };
    let shard = if w2_has_group {
        w2_shard
    } else {
        lose_ws.shards[0].clone()
    };
    lose_ws.shards.clear();
    let partial = ShardResult {
        run: "run-1".into(),
        shard: shard.shard,
        passed: vec!["b.spec.ts".into()],
        failed: Vec::new(),
        flaky: Vec::new(),
        finished: false,
    };
    if lose_end_is_2 {
        let e = t.n.w2();
        e.shard_result(&mut t.s.ws2, 22, &partial);
    } else {
        let e = t.n.w1();
        e.shard_result(&mut t.s.ws1, 22, &partial);
    }
    let (other, lost_name) = if lose_end_is_2 {
        (1u8, "worker-2")
    } else {
        (2u8, "worker-1")
    };
    t.run_shards(other, &[], 22);
    t.n.hub().poll(&mut t.s.hs, 23);
    // the other worker keeps answering; the lost one does not
    let later = 23 + LOST_AFTER_MS + 1;
    if other == 1 {
        t.n.w1().report(&mut t.s.ws1, later - 5, "-", "-", "alive");
    } else {
        let e = t.n.w2();
        e.report(&mut t.s.ws2, later - 5, "-", "-", "alive");
    }
    t.n.hub().poll(&mut t.s.hs, later - 4);
    assert!(matches!(
        t.n.hub().lane_tick(&mut t.s.hs, "run-1", later),
        Some(Verdict::Running { .. })
    ));
    let a = t.s.hs.take_audit();
    assert!(a
        .iter()
        .any(|e| e.action == "hub.lane.rerun" && e.detail.contains(&format!("from={lost_name}"))));
    // the whole group re-runs, b included, in order, on the other worker
    t.workers_poll(later + 1);
    let rerun = if other == 1 {
        &t.s.ws1.shards
    } else {
        &t.s.ws2.shards
    };
    assert_eq!(rerun.len(), 1);
    let bi = rerun[0]
        .specs
        .iter()
        .position(|f| f == "b.spec.ts")
        .unwrap();
    assert_eq!(rerun[0].specs[bi + 1], "c.spec.ts");
    // a late answer from the lost worker does not count
    let late = ShardResult {
        finished: true,
        passed: shard.specs.clone(),
        ..partial.clone()
    };
    if lose_end_is_2 {
        let e = t.n.w2();
        e.shard_result(&mut t.s.ws2, later + 2, &late);
    } else {
        let e = t.n.w1();
        e.shard_result(&mut t.s.ws1, later + 2, &late);
    }
    t.run_shards(other, &[], later + 2);
    t.n.hub().poll(&mut t.s.hs, later + 3);
    assert!(t
        .s
        .hs
        .take_audit()
        .iter()
        .any(|e| e.detail.contains("shard-lost")));
    assert!(matches!(
        t.n.hub().lane_tick(&mut t.s.hs, "run-1", later + 4),
        Some(Verdict::Pass { .. })
    ));
}

#[test]
fn a_lane_with_no_worker_left_says_it_cannot_finish_and_is_never_green() {
    let mut t = Two::new(10);
    let workers = t.workers();
    t.n.hub()
        .lane_start(
            &mut t.s.hs,
            "run-1",
            "browser",
            SHA,
            "browser-shard",
            Split::Weight,
            &suite(),
            &workers,
            &keys(),
            20,
        )
        .unwrap();
    t.workers_poll(21);
    // nobody answers again
    let v =
        t.n.hub()
            .lane_tick(&mut t.s.hs, "run-1", 20 + LOST_AFTER_MS + 1)
            .unwrap();
    match v {
        Verdict::CannotFinish { missing, .. } => assert_eq!(missing.len(), 5),
        v => panic!("{v:?}"),
    }
}

#[test]
fn a_result_for_a_shard_or_spec_a_worker_was_not_given_is_rejected() {
    let mut t = Two::new(10);
    let workers = t.workers();
    t.n.hub()
        .lane_start(
            &mut t.s.hs,
            "run-1",
            "browser",
            SHA,
            "browser-shard",
            Split::Weight,
            &suite(),
            &workers,
            &keys(),
            20,
        )
        .unwrap();
    t.workers_poll(21);
    let theirs = t.s.ws2.shards[0].shard;
    let mine = t.s.ws1.shards[0].clone();
    let other_spec = t.s.ws2.shards[0].specs[0].clone();
    let e = t.n.w1();
    // worker-1 reports worker-2's shard, then a spec it was not given
    e.shard_result(
        &mut t.s.ws1,
        22,
        &ShardResult {
            run: "run-1".into(),
            shard: theirs,
            passed: vec![other_spec.clone()],
            failed: vec![],
            flaky: vec![],
            finished: true,
        },
    );
    e.shard_result(
        &mut t.s.ws1,
        22,
        &ShardResult {
            run: "run-1".into(),
            shard: mine.shard,
            passed: vec![other_spec],
            failed: vec![],
            flaky: vec![],
            finished: true,
        },
    );
    t.n.hub().poll(&mut t.s.hs, 23);
    let a = t.s.hs.take_audit();
    assert!(a.iter().any(|e| e.detail.contains("not-its-shard")));
    assert!(a.iter().any(|e| e.detail.contains("spec-not-assigned")));
    assert!(matches!(
        t.n.hub().lane_tick(&mut t.s.hs, "run-1", 24),
        Some(Verdict::Running { .. })
    ));
    // a lane on something that is not a full commit, or on a worker not in the roster, starts nothing
    assert!(t
        .n
        .hub()
        .lane_start(
            &mut t.s.hs,
            "run-2",
            "browser",
            "main",
            "browser-shard",
            Split::Weight,
            &suite(),
            &workers,
            &keys(),
            25
        )
        .is_err());
    assert!(t
        .n
        .hub()
        .lane_start(
            &mut t.s.hs,
            "run-3",
            "browser",
            SHA,
            "browser-shard",
            Split::Weight,
            &suite(),
            &["stranger".to_string()],
            &keys(),
            25
        )
        .is_err());
}

// ---- the merge queue over the channel ------------------------------------------------------------------------------

struct GitOnMain {
    conflict: bool,
    log: Vec<String>,
}

impl Merger for GitOnMain {
    fn rebase(&mut self, _: Option<&str>, branch: &str, _: &str) -> Result<RebaseOutcome, String> {
        self.log.push(format!("rebase {branch}"));
        Ok(if self.conflict {
            RebaseOutcome::Conflict(vec!["src/shared.rs".into()])
        } else {
            RebaseOutcome::Clean
        })
    }
    fn test(
        &mut self,
        _: Option<&str>,
        _: &str,
        _: &[String],
        _: Option<&str>,
    ) -> Result<TestOutcome, String> {
        Err("the lane, not main, runs the tests here".into())
    }
    fn merge(&mut self, _: Option<&str>, branch: &str, _: &str) -> Result<MergeOutcome, String> {
        self.log.push(format!("merge {branch}"));
        Ok(MergeOutcome::Done)
    }
}

/// An orchestration with one hub-route feature handed to worker-1.
fn orch_with_hub_feature(t: &mut Two) -> (Book, String, String) {
    let mut b = Book::default();
    let id = b
        .start_orchestration("ship it", "ada", "main", &[], 1000)
        .unwrap();
    let o = b.orchestration_mut(&id).unwrap();
    o.policy.test_command = vec!["npx".into(), "playwright".into(), "test".into()];
    o.policy.test_lane_box = Some("hub:browser".into());
    o.policy.merge_approval = MergeApproval::Person;
    let fid = o
        .add_feature(
            &FeatureReq {
                title: "thing".into(),
                brief: "build it".into(),
                box_name: Some("worker-1".into()),
                ..Default::default()
            },
            1001,
        )
        .unwrap();
    let f = o.feature_mut(&fid).unwrap();
    f.transport = crate::orch::Transport::Hub;
    f.state = FeatureState::Starting;
    let mut a = assign(&fid, Default::default());
    a.orchestration = id.clone();
    a.branch = f.branch.clone();
    t.n.hub().assign(&mut t.s.hs, "worker-1", &a, 30).unwrap();
    t.workers_poll(31);
    (b, id, fid)
}

#[test]
fn a_workers_commit_goes_through_mains_merge_queue_with_the_lane_and_the_person_and_the_worker_is_told(
) {
    let mut t = Two::new(10);
    let (mut book, id, fid) = orch_with_hub_feature(&mut t);
    // the worker finishes with its exact commit
    t.n.w1().finish(&mut t.s.ws1, 40, &id, &fid, SHA, "done");
    t.n.hub().poll(&mut t.s.hs, 41);
    assert_eq!(
        admit_results(&mut book, &t.s.hs, 42),
        vec![(id.clone(), fid.clone())]
    );
    let f = book
        .orchestration(&id)
        .unwrap()
        .feature(&fid)
        .unwrap()
        .clone();
    assert_eq!(
        (f.state, f.commit.as_deref()),
        (FeatureState::InQueue, Some(SHA))
    );
    // the same result again queues nothing twice
    assert!(admit_results(&mut book, &t.s.hs, 43).is_empty());
    let lanes = [(
        "browser".to_string(),
        LaneDecl {
            name: "browser".into(),
            command: "browser-shard".into(),
            split: Split::Weight,
            specs: suite(),
            workers: t.workers(),
            known_keys: keys(),
        },
    )]
    .into_iter()
    .collect();
    let mut git = GitOnMain {
        conflict: false,
        log: vec![],
    };
    let mut now = 50;
    let step = |t: &mut Two, book: &mut Book, now: u64, git: &mut GitOnMain| {
        let hub = t.n.hub();
        let commits = reported_commits(book, &id);
        let mut m = HubMerger {
            inner: git,
            hub: &hub,
            st: &mut t.s.hs,
            lanes: &lanes,
            commits,
            now,
        };
        let s = merge_step(book, &id, &mut m, now);
        if let Some(s) = &s {
            return_to_worker(&hub, &mut t.s.hs, book, &id, s, now).unwrap();
        }
        s
    };
    assert_eq!(
        step(&mut t, &mut book, now, &mut git).unwrap().state,
        MergeState::Testing
    ); // rebased
    now += 1;
    assert_eq!(
        step(&mut t, &mut book, now, &mut git).unwrap().state,
        MergeState::Testing
    ); // the lane starts
    t.workers_poll(now);
    t.run_shards(1, &[], now);
    t.run_shards(2, &[], now);
    t.n.hub().poll(&mut t.s.hs, now + 1);
    now += 2;
    let s = step(&mut t, &mut book, now, &mut git).unwrap();
    assert_eq!(s.state, MergeState::AwaitingApproval, "{s:?}");
    // the lane's green is a test result, not the gate: the person decides the merge
    let aid = book.orchestration(&id).unwrap().merge_queue[0]
        .approval_id
        .clone()
        .unwrap();
    assert!(book.approval(&aid).unwrap().needs_step_up);
    now += 1;
    assert!(step(&mut t, &mut book, now, &mut git).is_none());
    book.approvals
        .iter_mut()
        .find(|a| a.id == aid)
        .unwrap()
        .state = ApprovalState::Approved;
    now += 1;
    assert_eq!(
        step(&mut t, &mut book, now, &mut git).unwrap().state,
        MergeState::Merging
    );
    now += 1;
    assert_eq!(
        step(&mut t, &mut book, now, &mut git).unwrap().state,
        MergeState::Merged
    );
    assert_eq!(
        git.log.last().map(String::as_str),
        Some(format!("merge {}", f.branch).as_str())
    );
    // the worker is told
    t.workers_poll(now + 1);
    assert_eq!(t.s.ws1.answers.last().unwrap().kind, "merged");
}

#[test]
fn a_conflict_and_a_failing_lane_go_back_to_the_worker_that_owns_the_feature() {
    let mut t = Two::new(10);
    let (mut book, id, fid) = orch_with_hub_feature(&mut t);
    t.n.w1().finish(&mut t.s.ws1, 40, &id, &fid, SHA, "done");
    t.n.hub().poll(&mut t.s.hs, 41);
    admit_results(&mut book, &t.s.hs, 42);
    let lanes = [(
        "browser".to_string(),
        LaneDecl {
            name: "browser".into(),
            command: "browser-shard".into(),
            split: Split::Weight,
            specs: suite(),
            workers: t.workers(),
            known_keys: keys(),
        },
    )]
    .into_iter()
    .collect();
    // a conflict
    let mut git = GitOnMain {
        conflict: true,
        log: vec![],
    };
    {
        let hub = t.n.hub();
        let commits = reported_commits(&book, &id);
        let mut m = HubMerger {
            inner: &mut git,
            hub: &hub,
            st: &mut t.s.hs,
            lanes: &lanes,
            commits,
            now: 50,
        };
        let s = merge_step(&mut book, &id, &mut m, 50).unwrap();
        assert_eq!(s.state, MergeState::Conflict);
        return_to_worker(&hub, &mut t.s.hs, &book, &id, &s, 50).unwrap();
    }
    t.workers_poll(51);
    let ans = t.s.ws1.answers.last().unwrap().clone();
    assert_eq!(ans.kind, "conflict");
    assert!(ans.text.contains("src/shared.rs"));
    assert_eq!(
        book.orchestration(&id)
            .unwrap()
            .feature(&fid)
            .unwrap()
            .state,
        FeatureState::ConflictReturned
    );
    // the worker fixes it and finishes a new commit; the lane fails one spec and the worker is told which
    let sha2 = "1123456789abcdef0123456789abcdef01234567";
    t.n.w1().finish(&mut t.s.ws1, 60, &id, &fid, sha2, "fixed");
    t.n.hub().poll(&mut t.s.hs, 61);
    assert_eq!(admit_results(&mut book, &t.s.hs, 62).len(), 1);
    git.conflict = false;
    let mut now = 70;
    for _ in 0..2 {
        let hub = t.n.hub();
        let commits = reported_commits(&book, &id);
        let mut m = HubMerger {
            inner: &mut git,
            hub: &hub,
            st: &mut t.s.hs,
            lanes: &lanes,
            commits,
            now,
        };
        merge_step(&mut book, &id, &mut m, now);
        now += 1;
    }
    t.workers_poll(now);
    assert!(t
        .s
        .ws1
        .shards
        .iter()
        .chain(&t.s.ws2.shards)
        .all(|a| a.commit == sha2));
    t.run_shards(1, &["d.spec.ts"], now);
    t.run_shards(2, &["d.spec.ts"], now);
    t.n.hub().poll(&mut t.s.hs, now + 1);
    now += 2;
    let hub = t.n.hub();
    let commits = reported_commits(&book, &id);
    let mut m = HubMerger {
        inner: &mut git,
        hub: &hub,
        st: &mut t.s.hs,
        lanes: &lanes,
        commits,
        now,
    };
    let s = merge_step(&mut book, &id, &mut m, now).unwrap();
    assert_eq!(s.state, MergeState::TestsFailed);
    assert!(s.detail.contains("d.spec.ts"));
    return_to_worker(&hub, &mut t.s.hs, &book, &id, &s, now).unwrap();
    t.workers_poll(now + 1);
    let ans = t.s.ws1.answers.last().unwrap();
    assert_eq!(ans.kind, "tests-failed");
    assert!(ans.text.contains("d.spec.ts"));
}

#[test]
fn a_result_from_a_worker_that_does_not_hold_the_feature_or_without_a_full_commit_is_not_queued() {
    let mut t = Two::new(10);
    let (mut book, id, fid) = orch_with_hub_feature(&mut t);
    // worker-2 was never handed the feature: the hub refuses its result before the book sees it
    let e = t.n.w2();
    e.finish(&mut t.s.ws2, 40, &id, &fid, SHA, "mine now");
    // worker-1 reports a branch name, not a commit
    t.n.w1().finish(&mut t.s.ws1, 40, &id, &fid, "main", "done");
    t.n.hub().poll(&mut t.s.hs, 41);
    assert!(admit_results(&mut book, &t.s.hs, 42).is_empty());
    let o = book.orchestration(&id).unwrap();
    assert!(o.merge_queue.is_empty());
    assert!(o
        .messages
        .iter()
        .any(|m| m.text.contains("without a full commit id")));
}
