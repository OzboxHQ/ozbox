#![allow(clippy::unwrap_used)]

use super::*;
use crate::orch_merge::{merge_step, MergeOutcome, MergeStep, Merger, RebaseOutcome, TestOutcome};
use crate::run::{ActionKind, ApprovalRequest, ApprovalState, RunOrigin, RunSpec};

fn book() -> (Book, String) {
    let mut b = Book::default();
    let id = b
        .start_orchestration("ship the thing", "ada", "main-box", &[], 1000)
        .unwrap();
    (b, id)
}

fn req(title: &str, claims: &[&str]) -> FeatureReq {
    FeatureReq {
        title: title.into(),
        brief: format!("build {title}"),
        claims: claims.iter().map(|s| s.to_string()).collect(),
        ..Default::default()
    }
}

#[test]
fn defaults_are_three_workers_three_sub_agents_and_one_cap() {
    let (b, id) = book();
    let p = &b.orchestration(&id).unwrap().policy;
    assert_eq!((p.max_workers, p.max_sub_agents), (3, 3));
    assert_eq!(p.spend_cap_cents, Some(5000));
    assert_eq!(p.worker.kind, WorkerKind::Clone);
    assert_eq!(p.merge_approval, MergeApproval::Person);
}

#[test]
fn the_fourth_worker_box_and_the_fourth_sub_agent_are_refused() {
    let (mut b, id) = book();
    let o = b.orchestration_mut(&id).unwrap();
    for n in ["a", "b", "c"] {
        o.add_feature(&req(n, &[]), 1).unwrap();
    }
    assert!(matches!(
        o.add_feature(&req("d", &[]), 1),
        Err(OrchError::Limit(_))
    ));
    let mut r = req("e", &[]);
    r.sub_agents = Some(4);
    assert!(matches!(o.add_feature(&r, 1), Err(OrchError::Limit(_))));
    // a finished feature frees its box
    o.set_feature_state("f1", FeatureState::Stopped, 2).unwrap();
    assert!(o.add_feature(&req("d", &[]), 3).is_ok());
}

#[test]
fn claims_overlap_is_generous_and_exact_paths_do_not_collide() {
    assert!(claims_overlap("src/api", "src/api/users.rs"));
    assert!(claims_overlap("src/**", "src/api/users.rs"));
    assert!(claims_overlap("src/*.rs", "src/api"));
    assert!(claims_overlap("**", "anything"));
    assert!(!claims_overlap("src/api", "src/apis"));
    assert!(!claims_overlap("src/api", "src/web"));
    assert!(claim_covers("src/api", "src/api/a/b.rs"));
    assert!(claim_covers("src/*.rs", "src/lib.rs"));
    assert!(!claim_covers("src/*.rs", "src/a/lib.rs"));
    assert!(claim_covers("src/**", "src/a/b/c.rs"));
    assert!(normalize_pattern("../x").is_err());
    assert_eq!(normalize_pattern("./a//b/").unwrap(), "a/b");
}

#[test]
fn an_overlapping_claim_is_refused_by_default_and_sequenced_when_the_rule_says() {
    let (mut b, id) = book();
    let o = b.orchestration_mut(&id).unwrap();
    let a = o.add_feature(&req("a", &["src/api"]), 1).unwrap();
    let err = o.add_feature(&req("b", &["src/api/users"]), 1).unwrap_err();
    assert!(matches!(err, OrchError::Conflict(_)), "{err}");
    assert_eq!(
        o.features.len(),
        1,
        "a refused feature leaves nothing behind"
    );
    o.policy.on_overlap = OverlapRule::Sequence;
    let bf = o.add_feature(&req("b", &["src/api/users"]), 1).unwrap();
    assert_eq!(o.feature(&bf).unwrap().after, vec![a.clone()]);
    assert!(o.startable().contains(&a));
    assert!(!o.startable().contains(&bf), "the later feature waits");
    o.feature_mut(&a).unwrap().state = FeatureState::Merged;
    assert!(o.startable().contains(&bf));
}

#[test]
fn check_path_names_the_owner_and_wants_a_claim_for_the_rest() {
    let (mut b, id) = book();
    let o = b.orchestration_mut(&id).unwrap();
    let a = o.add_feature(&req("a", &["src/api"]), 1).unwrap();
    let c = o.add_feature(&req("c", &["src/web"]), 1).unwrap();
    assert!(o.check_path(&a, "src/api/x.rs").is_ok());
    let e = o.check_path(&a, "src/web/x.rs").unwrap_err().to_string();
    assert!(e.contains(&c), "{e}");
    assert!(o
        .check_path(&a, "README.md")
        .unwrap_err()
        .to_string()
        .contains("not claimed"));
    o.policy.strict_claims = false;
    assert!(o.check_path(&a, "README.md").is_ok());
    assert!(o.check_path(&a, "../etc/passwd").is_err());
}

#[test]
fn a_contract_is_versioned_and_a_change_is_broadcast_once() {
    let (mut b, id) = book();
    let o = b.orchestration_mut(&id).unwrap();
    let (cid, v) = o
        .publish_contract(
            "conductor",
            "Users API",
            "api",
            "GET /users",
            &["api/users.yaml".into()],
            true,
            5,
        )
        .unwrap();
    assert_eq!((cid.as_str(), v), ("users-api", 1));
    let mut r = req("a", &["src/a"]);
    r.contracts = vec!["users-api".into()];
    let a = o.add_feature(&r, 6).unwrap();
    // the same text again changes nothing and tells no one
    assert_eq!(
        o.publish_contract(
            "conductor",
            "Users API",
            "api",
            "GET /users",
            &["api/users.yaml".into()],
            true,
            7
        )
        .unwrap()
        .1,
        1
    );
    assert!(o.messages.is_empty());
    let (_, v2) = o
        .publish_contract(
            "conductor",
            "Users API",
            "api",
            "GET /users?limit",
            &["api/users.yaml".into()],
            true,
            8,
        )
        .unwrap();
    assert_eq!(v2, 2);
    let heard = o.inbox(&format!("feature:{a}"), 0);
    assert_eq!(heard.len(), 1);
    assert_eq!(heard[0].kind, MsgKind::ContractChanged);
    assert_eq!(o.contract("users-api").unwrap().history.len(), 2);
    assert_eq!(o.ack_contract(&a, "users-api").unwrap(), 2);
    // a worker may not claim the contract's files; a draft cannot be built against
    assert!(o.declare_claims(&a, &["api/users.yaml".into()], 9).is_err());
    o.publish_contract("conductor", "Draft", "doc", "x", &[], false, 9)
        .unwrap();
    let mut r = req("b", &["src/b"]);
    r.contracts = vec!["draft".into()];
    assert!(matches!(o.add_feature(&r, 10), Err(OrchError::Conflict(_))));
}

#[test]
fn a_worker_that_asks_waits_until_the_conductor_answers_inside_policy() {
    let (mut b, id) = book();
    let o = b.orchestration_mut(&id).unwrap();
    let a = o.add_feature(&req("a", &["src/a"]), 1).unwrap();
    o.mark_started(&a, "t1", 2).unwrap();
    o.feature_mut(&a).unwrap().state = FeatureState::Working;
    let q = o
        .post(
            3,
            &format!("feature:{a}"),
            "conductor",
            MsgKind::Question,
            "tabs or spaces?",
            None,
            false,
        )
        .unwrap();
    assert_eq!(o.feature(&a).unwrap().state, FeatureState::Blocked);
    assert_eq!(o.open_questions().len(), 1);
    o.answer(4, q, false, "spaces").unwrap();
    let f = o.feature(&a).unwrap();
    assert_eq!(f.state, FeatureState::Working);
    assert!(f.resume_pending);
    assert!(o.open_questions().is_empty());
    assert!(matches!(
        o.answer(5, q, false, "again"),
        Err(OrchError::Conflict(_))
    ));
    assert_eq!(o.inbox(&format!("feature:{a}"), 0)[0].kind, MsgKind::Answer);
}

#[test]
fn a_question_for_the_person_cannot_be_answered_by_the_conductor() {
    let (mut b, id) = book();
    let o = b.orchestration_mut(&id).unwrap();
    let a = o.add_feature(&req("a", &["src/a"]), 1).unwrap();
    o.feature_mut(&a).unwrap().state = FeatureState::Working;
    let q = o
        .post(
            3,
            &format!("feature:{a}"),
            "conductor",
            MsgKind::Question,
            "may I drop the table?",
            None,
            false,
        )
        .unwrap();
    o.escalate(q, 4).unwrap();
    assert!(matches!(
        o.answer(5, q, false, "yes"),
        Err(OrchError::NotAllowed(_))
    ));
    assert_eq!(
        o.feature(&a).unwrap().state,
        FeatureState::Blocked,
        "still waiting"
    );
    o.answer(6, q, true, "no").unwrap();
    assert_eq!(o.feature(&a).unwrap().state, FeatureState::Working);
}

#[test]
fn a_rules_file_can_only_tighten_the_settings() {
    let settings = OrchSettings::default();
    let rules = parse_rules(
        "---\nmax_workers: 2\nmax_sub_agents: 9\nspend_cap: $20\nmerge_approval: none\nconductor_may: ask_command, production_resource\ntest_command: cargo test --workspace\non_overlap: sequence\n---\nPrefer small commits.\n",
    )
    .unwrap();
    let p = effective(&settings, &[&rules]);
    assert_eq!(p.max_workers, 2, "lower is taken");
    assert_eq!(p.max_sub_agents, 3, "higher is ignored");
    assert_eq!(p.spend_cap_cents, Some(2000));
    assert_eq!(
        p.merge_approval,
        MergeApproval::Person,
        "a looser approval is ignored"
    );
    assert_eq!(
        p.conductor_may.len(),
        1,
        "a kind the settings do not allow is dropped"
    );
    assert_eq!(p.test_command, vec!["cargo", "test", "--workspace"]);
    assert_eq!(p.on_overlap, OverlapRule::Sequence);
    assert!(p.guidance.contains("small commits"));
    assert!(p.notes.len() >= 3, "{:?}", p.notes);
    // the other direction: stricter is taken, and a request cannot undo a rules file
    let stricter = parse_rules("---\nmerge_approval: person\nconductor_may: none\nmay_create_boxes: false\nworker: create\n---\n").unwrap();
    let loose = Overrides {
        may_create_boxes: Some(true),
        max_workers: Some(3),
        ..Default::default()
    };
    let s2 = OrchSettings {
        merge_approval: MergeApproval::Conductor,
        ..Default::default()
    };
    let p = effective(&s2, &[&stricter, &loose]);
    assert_eq!(p.merge_approval, MergeApproval::Person);
    assert!(p.conductor_may.is_empty());
    assert!(!p.may_create_boxes);
    assert_eq!(
        p.worker.kind,
        WorkerKind::Clone,
        "no new boxes means clones only"
    );
    assert_eq!(p.max_workers, 3, "the request kept the settings' own limit");
}

#[test]
fn the_rules_file_is_parsed_not_run_and_a_typo_is_an_error() {
    assert!(parse_rules("---\nmax_workerz: 2\n---\n").is_err());
    assert!(parse_rules("---\nmax_workers: two\n---\n").is_err());
    assert!(
        parse_rules("---\nmax_workers: 2\n").is_err(),
        "no closing line"
    );
    assert!(parse_rules("---\nconductor_may: rm_rf\n---\n").is_err());
    let o = parse_rules("just words, no front matter").unwrap();
    assert_eq!(o.guidance.as_deref(), Some("just words, no front matter"));
    // a test command is words, so a shell string is just odd arguments, never evaluated
    let o = parse_rules("---\ntest_command: make test; rm -rf /\n---\n").unwrap();
    assert_eq!(o.test_command.unwrap()[1], "test;");
}

#[derive(Default)]
struct FakeMerger {
    conflicts: Vec<String>,
    fail_tests: Vec<String>,
    log: Vec<String>,
}

impl Merger for FakeMerger {
    fn rebase(&mut self, _: Option<&str>, branch: &str, _: &str) -> Result<RebaseOutcome, String> {
        self.log.push(format!("rebase {branch}"));
        if self.conflicts.iter().any(|c| branch.ends_with(c.as_str())) {
            Ok(RebaseOutcome::Conflict(vec!["src/shared.rs".into()]))
        } else {
            Ok(RebaseOutcome::Clean)
        }
    }
    fn test(
        &mut self,
        _: Option<&str>,
        branch: &str,
        _: &[String],
        _: Option<&str>,
    ) -> Result<TestOutcome, String> {
        self.log.push(format!("test {branch}"));
        if self.fail_tests.iter().any(|c| branch.ends_with(c.as_str())) {
            Ok(TestOutcome::Fail("1 failed".into()))
        } else {
            Ok(TestOutcome::Pass)
        }
    }
    fn merge(&mut self, _: Option<&str>, branch: &str, _: &str) -> Result<MergeOutcome, String> {
        self.log.push(format!("merge {branch}"));
        Ok(MergeOutcome::Done)
    }
}

fn run_queue(b: &mut Book, id: &str, m: &mut dyn Merger, now: &mut u64) -> Vec<MergeStep> {
    let mut out = Vec::new();
    for _ in 0..40 {
        *now += 1;
        match merge_step(b, id, m, *now) {
            Some(s) => out.push(s),
            None => break,
        }
    }
    out
}

fn ready_book(policy: MergeApproval) -> (Book, String) {
    let mut b = Book::default();
    b.orch_settings.merge_approval = policy;
    let id = b
        .start_orchestration(
            "g",
            "ada",
            "main-box",
            &[&Overrides {
                test_command: Some(vec!["t".into()]),
                ..Default::default()
            }],
            1,
        )
        .unwrap();
    let o = b.orchestration_mut(&id).unwrap();
    for n in ["a", "b", "c"] {
        let f = o.add_feature(&req(n, &[&format!("src/{n}")]), 1).unwrap();
        o.feature_mut(&f).unwrap().state = FeatureState::ReadyToMerge;
    }
    (b, id)
}

#[test]
fn the_queue_merges_in_order_and_a_conflict_goes_back_to_its_worker() {
    let (mut b, id) = ready_book(MergeApproval::None);
    {
        let o = b.orchestration_mut(&id).unwrap();
        for f in ["f1", "f2", "f3"] {
            o.enqueue_merge(f, 5).unwrap();
        }
        assert!(o.enqueue_merge("f1", 5).is_err(), "already queued");
    }
    let mut m = FakeMerger {
        conflicts: vec!["/b".into()],
        ..Default::default()
    };
    let mut now = 10;
    run_queue(&mut b, &id, &mut m, &mut now);
    let merges: Vec<_> = m.log.iter().filter(|l| l.starts_with("merge")).collect();
    assert_eq!(merges.len(), 2, "{:?}", m.log);
    assert!(
        merges[0].ends_with("/a") && merges[1].ends_with("/c"),
        "order kept: {merges:?}"
    );
    let o = b.orchestration(&id).unwrap();
    assert_eq!(o.feature("f1").unwrap().state, FeatureState::Merged);
    let f2 = o.feature("f2").unwrap();
    assert_eq!(f2.state, FeatureState::ConflictReturned);
    assert!(f2.resume_pending);
    let told = o.inbox("feature:f2", 0);
    assert!(told[0].text.contains("src/shared.rs"));
    assert_eq!(
        o.feature("f3").unwrap().state,
        FeatureState::Merged,
        "the queue went on"
    );
    // the worker fixes it and queues again
    let o = b.orchestration_mut(&id).unwrap();
    o.enqueue_merge("f2", 99).unwrap();
}

#[test]
fn failing_tests_go_back_to_the_worker_and_nothing_is_merged() {
    let (mut b, id) = ready_book(MergeApproval::None);
    b.orchestration_mut(&id)
        .unwrap()
        .enqueue_merge("f1", 5)
        .unwrap();
    let mut m = FakeMerger {
        fail_tests: vec!["/a".into()],
        ..Default::default()
    };
    let mut now = 10;
    run_queue(&mut b, &id, &mut m, &mut now);
    assert!(!m.log.iter().any(|l| l.starts_with("merge")));
    let o = b.orchestration(&id).unwrap();
    assert_eq!(
        o.feature("f1").unwrap().state,
        FeatureState::ConflictReturned
    );
}

#[test]
fn a_merge_waits_for_the_person_and_the_conductor_can_never_decide_it() {
    let (mut b, id) = ready_book(MergeApproval::Person);
    b.orchestration_mut(&id)
        .unwrap()
        .enqueue_merge("f1", 5)
        .unwrap();
    let mut m = FakeMerger::default();
    let mut now = 10;
    let steps = run_queue(&mut b, &id, &mut m, &mut now);
    assert_eq!(steps.last().unwrap().state, MergeState::AwaitingApproval);
    assert!(!m.log.iter().any(|l| l.starts_with("merge")));
    let a = b.approvals.last().unwrap().clone();
    assert!(a.needs_step_up);
    assert_eq!(a.kind, ActionKind::PushProtectedBranch);
    assert!(!b.orchestration(&id).unwrap().conductor_may_decide(&a));
    // the person approves; the queue goes on
    crate::supervisor::decide(&mut b, &a.id, true, "ada", true, now).unwrap();
    run_queue(&mut b, &id, &mut m, &mut now);
    assert!(m.log.iter().any(|l| l.starts_with("merge")));
    assert_eq!(
        b.orchestration(&id).unwrap().feature("f1").unwrap().state,
        FeatureState::Merged
    );
}

#[test]
fn a_denied_merge_does_not_merge_and_the_conductor_may_approve_only_when_the_policy_says() {
    let (mut b, id) = ready_book(MergeApproval::Conductor);
    b.orchestration_mut(&id)
        .unwrap()
        .enqueue_merge("f1", 5)
        .unwrap();
    let mut m = FakeMerger::default();
    let mut now = 10;
    run_queue(&mut b, &id, &mut m, &mut now);
    let a = b.approvals.last().unwrap().clone();
    assert!(!a.needs_step_up);
    assert!(b.orchestration(&id).unwrap().conductor_may_decide(&a));
    crate::supervisor::decide(&mut b, &a.id, false, "conductor:o1", false, now).unwrap();
    run_queue(&mut b, &id, &mut m, &mut now);
    assert!(!m.log.iter().any(|l| l.starts_with("merge")));
    assert_eq!(
        b.orchestration(&id).unwrap().feature("f1").unwrap().state,
        FeatureState::ReadyToMerge
    );
}

#[test]
fn the_conductor_decides_only_low_risk_kinds_of_its_own_workers() {
    let (mut b, id) = ready_book(MergeApproval::Person);
    let spec = |origin| RunSpec {
        engine: "fake".into(),
        prompt: "x".into(),
        skill: None,
        box_name: "w".into(),
        repo: None,
        branch: None,
        caps: Default::default(),
        deliver_to: vec![],
        requested_by: "ada".into(),
        origin,
        idempotency_key: None,
        model: None,
        interactive: false,
    };
    let (t, _) = b
        .enqueue(
            spec(RunOrigin::Orchestration {
                id: id.clone(),
                feature: "f1".into(),
            }),
            1,
            None,
        )
        .unwrap();
    b.orchestration_mut(&id)
        .unwrap()
        .feature_mut("f1")
        .unwrap()
        .task_id = Some(t.clone());
    let mk = |kind, step_up, prod, task: &str| ApprovalRequest {
        id: "a1".into(),
        task_id: task.into(),
        kind,
        action: "x".into(),
        box_name: "w".into(),
        asked_by: "x".into(),
        production: prod,
        needs_step_up: step_up,
        state: ApprovalState::Pending,
        created_ms: 0,
        expires_ms: 1,
        reminders: 0,
        decided_by: None,
        decided_ms: None,
        decided_with_step_up: false,
        delivered: false,
        used: false,
    };
    let o = b.orchestration_mut(&id).unwrap();
    assert!(o.conductor_may_decide(&mk(ActionKind::AskCommand, false, false, &t)));
    assert!(
        !o.conductor_may_decide(&mk(ActionKind::AskCommand, true, false, &t)),
        "needs a second factor"
    );
    assert!(
        !o.conductor_may_decide(&mk(ActionKind::AskCommand, false, true, &t)),
        "production"
    );
    assert!(
        !o.conductor_may_decide(&mk(ActionKind::AskCommand, false, false, "t999")),
        "not its worker"
    );
    o.policy.conductor_may.insert(ActionKind::OutboundMessage);
    assert!(
        !o.conductor_may_decide(&mk(ActionKind::OutboundMessage, false, false, &t)),
        "risky kinds never"
    );
    assert!(!o.conductor_may_decide(&mk(ActionKind::PushProtectedBranch, false, false, &t)));
}

#[test]
fn everything_resumes_after_a_restart_from_what_the_file_holds() {
    let (mut b, id) = ready_book(MergeApproval::None);
    {
        let o = b.orchestration_mut(&id).unwrap();
        o.publish_contract("conductor", "api", "api", "x", &[], true, 3)
            .unwrap();
        o.feature_mut("f1").unwrap().wip_branch = Some("wip/x/1".into());
        o.feature_mut("f1").unwrap().session_id = Some("sess-1".into());
        o.enqueue_merge("f1", 5).unwrap();
        o.enqueue_merge("f2", 5).unwrap();
    }
    let json = serde_json::to_vec(&b).unwrap();
    let mut b2: Book = serde_json::from_slice(&json).unwrap();
    assert_eq!(b, b2);
    let mut m = FakeMerger::default();
    let mut now = 10;
    run_queue(&mut b2, &id, &mut m, &mut now);
    let o = b2.orchestration(&id).unwrap();
    assert_eq!(
        o.feature("f1").unwrap().session_id.as_deref(),
        Some("sess-1")
    );
    assert_eq!(o.feature("f1").unwrap().state, FeatureState::Merged);
    assert_eq!(o.feature("f2").unwrap().state, FeatureState::Merged);
    // an old file with no orchestrations at all still loads
    let old: Book = serde_json::from_str(r#"{"rev":3,"tasks":[]}"#).unwrap();
    assert!(old.orchestrations.is_empty());
    assert_eq!(old.orch_settings, OrchSettings::default());
}

#[test]
fn a_merged_workers_box_is_paused_and_destroyed_later_unless_kept() {
    let (mut b, id) = ready_book(MergeApproval::None);
    let o = b.orchestration_mut(&id).unwrap();
    for f in ["f1", "f2"] {
        let x = o.feature_mut(f).unwrap();
        x.state = FeatureState::Merged;
        x.merged_ms = Some(1000);
        x.box_made = true;
    }
    o.feature_mut("f2").unwrap().keep = true;
    let acts = o.sweep_boxes(2000);
    assert_eq!(acts.len(), 2);
    for a in &acts {
        assert!(matches!(a, BoxAction::Pause { .. }));
        let fid = match a {
            BoxAction::Pause { feature, .. } | BoxAction::Destroy { feature, .. } => {
                feature.clone()
            }
        };
        o.box_done(&fid, a);
    }
    assert!(o.sweep_boxes(2000).is_empty(), "not yet due");
    let later = 1000 + 8 * 86_400_000;
    let acts = o.sweep_boxes(later);
    assert_eq!(acts.len(), 1, "the kept box is never destroyed");
    assert!(matches!(&acts[0], BoxAction::Destroy { feature, .. } if feature == "f1"));
}

#[test]
fn the_spend_cap_pauses_the_orchestration_and_caps_each_active_task_at_what_it_spent() {
    let (mut b, id) = book();
    let spec = RunSpec {
        engine: "fake".into(),
        prompt: "x".into(),
        skill: None,
        box_name: "w".into(),
        repo: None,
        branch: None,
        caps: Default::default(),
        deliver_to: vec![],
        requested_by: "ada".into(),
        origin: RunOrigin::Orchestration {
            id: id.clone(),
            feature: "f1".into(),
        },
        idempotency_key: None,
        model: None,
        interactive: false,
    };
    let (t, _) = b.enqueue(spec, 1, None).unwrap();
    let o = b.orchestration_mut(&id).unwrap();
    let f = o.add_feature(&req("a", &["src/a"]), 1).unwrap();
    o.mark_started(&f, &t, 2).unwrap();
    o.policy.spend_cap_cents = Some(100);
    b.task_mut(&t).unwrap().spend_cents = 60;
    assert!(!b.enforce_budget(&id, 5));
    b.task_mut(&t).unwrap().spend_cents = 120;
    assert!(b.enforce_budget(&id, 6));
    assert_eq!(b.task(&t).unwrap().spec.caps.max_spend_cents, Some(120));
    assert_eq!(b.orchestration(&id).unwrap().state, OrchState::Paused);
    assert!(b.orchestration(&id).unwrap().inbox("person", 0)[0].needs_person);
    assert!(!b.enforce_budget(&id, 7), "pauses once");
    assert_eq!(b.add_orch_budget(&id, 500, "ada", 8).unwrap(), 600);
    assert_eq!(b.orchestration(&id).unwrap().state, OrchState::Active);
}

#[test]
fn the_worker_prompt_holds_the_claims_contracts_and_limits_and_no_secret() {
    let (mut b, id) = book();
    let o = b.orchestration_mut(&id).unwrap();
    o.publish_contract("conductor", "Users API", "api", "GET /users", &[], true, 1)
        .unwrap();
    let mut r = req("a", &["src/api"]);
    r.contracts = vec!["users-api".into()];
    r.sub_agents = Some(2);
    let f = o.add_feature(&r, 2).unwrap();
    let p = o.worker_prompt(&f).unwrap();
    for needle in [
        "src/api",
        "Users API",
        "at most 2 sub-agents",
        "worker_ask",
        "orch/o1/a",
        "never merge",
    ] {
        assert!(p.contains(needle), "missing {needle}: {p}");
    }
    assert!(p.chars().count() < crate::run::MAX_PROMPT_CHARS);
    assert!(o.conductor_prompt().contains("at most 3 worker boxes"));
}

#[test]
fn feature_states_follow_their_tasks() {
    let (mut b, id) = book();
    let spec = RunSpec {
        engine: "fake".into(),
        prompt: "x".into(),
        skill: None,
        box_name: "w".into(),
        repo: None,
        branch: None,
        caps: Default::default(),
        deliver_to: vec![],
        requested_by: "ada".into(),
        origin: RunOrigin::Orchestration {
            id: id.clone(),
            feature: "f1".into(),
        },
        idempotency_key: None,
        model: None,
        interactive: false,
    };
    let (t, _) = b.enqueue(spec, 1, None).unwrap();
    let o = b.orchestration_mut(&id).unwrap();
    let f = o.add_feature(&req("a", &["src/a"]), 1).unwrap();
    o.mark_started(&f, &t, 2).unwrap();
    b.task_mut(&t).unwrap().state = crate::run::TaskState::Running;
    b.follow_tasks(3);
    assert_eq!(
        b.orchestration(&id).unwrap().feature(&f).unwrap().state,
        FeatureState::Working
    );
    b.task_mut(&t).unwrap().state = crate::run::TaskState::Review;
    b.follow_tasks(4);
    assert_eq!(
        b.orchestration(&id).unwrap().feature(&f).unwrap().state,
        FeatureState::ReadyToMerge
    );
}

struct Chan(Vec<String>, bool);
impl WorkerChannel for Chan {
    fn send(&mut self, t: &str, text: &str) -> Result<(), String> {
        if self.1 {
            self.0.push(format!("{t}:{text}"));
            Ok(())
        } else {
            Err("no".into())
        }
    }
}

#[test]
fn the_tick_starts_ready_features_and_resumes_a_blocked_worker_from_its_branch() {
    let (mut b, id) = book();
    {
        let o = b.orchestration_mut(&id).unwrap();
        o.add_feature(&req("a", &["src/a"]), 1).unwrap();
        o.add_feature(&req("b", &["src/b"]), 1).unwrap();
    }
    // a box that is not ready yet is not started
    let mut ready = |f: &Feature| f.id == "f1";
    b.tick_orchestrations(&mut NoChannel, &mut ready, 10);
    let o = b.orchestration(&id).unwrap();
    assert!(o.feature("f1").unwrap().task_id.is_some());
    assert!(o.feature("f2").unwrap().task_id.is_none());
    let t1 = o.feature("f1").unwrap().task_id.clone().unwrap();
    let spec = &b.task(&t1).unwrap().spec;
    assert_eq!(spec.branch.as_deref(), Some("orch/o1/a"));
    assert_eq!(
        spec.origin,
        RunOrigin::Orchestration {
            id: id.clone(),
            feature: "f1".into()
        }
    );
    assert!(
        spec.caps.max_spend_cents.is_some(),
        "a worker never runs without the orchestration's cap"
    );
    // the worker asks and ends its turn: it stays blocked, it is not "ready to merge"
    b.task_mut(&t1).unwrap().state = crate::run::TaskState::Running;
    b.follow_tasks(11);
    let q = b
        .orchestration_mut(&id)
        .unwrap()
        .post(
            12,
            "feature:f1",
            "conductor",
            MsgKind::Question,
            "which db?",
            None,
            false,
        )
        .unwrap();
    b.task_mut(&t1).unwrap().state = crate::run::TaskState::Review;
    b.follow_tasks(13);
    assert_eq!(
        b.orchestration(&id).unwrap().feature("f1").unwrap().state,
        FeatureState::Blocked
    );
    // the conductor answers; the engine cannot take a message, so the feature is resumed as a new task
    b.orchestration_mut(&id)
        .unwrap()
        .answer(14, q, false, "postgres")
        .unwrap();
    let mut never = |_: &Feature| false;
    b.tick_orchestrations(&mut NoChannel, &mut never, 15);
    let f = b.orchestration(&id).unwrap().feature("f1").unwrap().clone();
    assert_ne!(f.task_id.as_deref(), Some(t1.as_str()));
    assert!(!f.resume_pending);
    let t2 = b.task(f.task_id.as_deref().unwrap()).unwrap();
    assert!(t2.spec.prompt.contains("postgres"));
    assert_eq!(
        t2.spec.branch.as_deref(),
        Some("orch/o1/a"),
        "same branch, so the saved work continues"
    );
}

#[test]
fn a_running_worker_is_told_through_the_channel_when_the_engine_has_one() {
    let (mut b, id) = book();
    b.orchestration_mut(&id)
        .unwrap()
        .add_feature(&req("a", &["src/a"]), 1)
        .unwrap();
    let mut yes = |_: &Feature| true;
    b.tick_orchestrations(&mut NoChannel, &mut yes, 10);
    let t1 = b
        .orchestration(&id)
        .unwrap()
        .feature("f1")
        .unwrap()
        .task_id
        .clone()
        .unwrap();
    b.task_mut(&t1).unwrap().state = crate::run::TaskState::Running;
    b.follow_tasks(11);
    let o = b.orchestration_mut(&id).unwrap();
    let q = o
        .post(
            12,
            "feature:f1",
            "conductor",
            MsgKind::Question,
            "x?",
            None,
            false,
        )
        .unwrap();
    o.answer(13, q, false, "go on").unwrap();
    let mut chan = Chan(vec![], true);
    b.tick_orchestrations(&mut chan, &mut yes, 14);
    assert_eq!(chan.0.len(), 1);
    assert!(chan.0[0].starts_with(&format!("{t1}:")));
    assert!(
        !b.orchestration(&id)
            .unwrap()
            .feature("f1")
            .unwrap()
            .resume_pending
    );
    assert_eq!(
        b.orchestration(&id)
            .unwrap()
            .feature("f1")
            .unwrap()
            .task_id
            .as_deref(),
        Some(t1.as_str()),
        "no second task"
    );
}

#[test]
fn a_paused_orchestration_starts_nothing() {
    let (mut b, id) = book();
    b.orchestration_mut(&id)
        .unwrap()
        .add_feature(&req("a", &["src/a"]), 1)
        .unwrap();
    b.orchestration_mut(&id).unwrap().state = OrchState::Paused;
    let mut yes = |_: &Feature| true;
    b.tick_orchestrations(&mut NoChannel, &mut yes, 10);
    assert!(b
        .orchestration(&id)
        .unwrap()
        .feature("f1")
        .unwrap()
        .task_id
        .is_none());
    assert!(b.start_conductor(&id, "", 1).is_ok());
}

#[derive(Default)]
struct Slow {
    polls: u32,
}

impl Merger for Slow {
    fn rebase(&mut self, _: Option<&str>, _: &str, _: &str) -> Result<RebaseOutcome, String> {
        self.polls += 1;
        Ok(if self.polls < 3 {
            RebaseOutcome::Pending
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
        Ok(TestOutcome::Pass)
    }
    fn merge(&mut self, _: Option<&str>, _: &str, _: &str) -> Result<MergeOutcome, String> {
        Ok(MergeOutcome::Done)
    }
}

#[test]
fn a_slow_box_keeps_the_head_of_the_queue_waiting_without_losing_its_place() {
    let (mut b, id) = ready_book(MergeApproval::None);
    for f in ["f1", "f2"] {
        b.orchestration_mut(&id)
            .unwrap()
            .enqueue_merge(f, 5)
            .unwrap();
    }
    let mut m = Slow::default();
    let s1 = merge_step(&mut b, &id, &mut m, 10).unwrap();
    assert_eq!(
        (s1.feature_id.as_str(), s1.state),
        ("f1", MergeState::Rebasing)
    );
    let s2 = merge_step(&mut b, &id, &mut m, 11).unwrap();
    assert_eq!(
        (s2.feature_id.as_str(), s2.state),
        ("f1", MergeState::Rebasing)
    );
    let mut now = 12;
    let rest = run_queue(&mut b, &id, &mut m, &mut now);
    assert!(rest
        .iter()
        .any(|s| s.feature_id == "f1" && s.state == MergeState::Merged));
    assert!(rest
        .iter()
        .any(|s| s.feature_id == "f2" && s.state == MergeState::Merged));
    let at = |f: &str| {
        rest.iter()
            .position(|s| s.feature_id == f && s.state == MergeState::Merged)
    };
    assert!(at("f1") < at("f2"), "queue order is kept");
}

#[test]
fn pausing_halts_the_workers_and_resuming_continues_them_from_their_branches() {
    let (mut b, id) = book();
    b.orchestration_mut(&id)
        .unwrap()
        .add_feature(&req("a", &["src/a"]), 1)
        .unwrap();
    let mut yes = |_: &Feature| true;
    b.tick_orchestrations(&mut NoChannel, &mut yes, 10);
    let t1 = b
        .orchestration(&id)
        .unwrap()
        .feature("f1")
        .unwrap()
        .task_id
        .clone()
        .unwrap();
    b.task_mut(&t1).unwrap().state = crate::run::TaskState::Running;
    b.halt_orchestration(&id, false, "ada", 11).unwrap();
    assert!(
        b.task(&t1).unwrap().cancel_requested,
        "the supervisor saves the work, then stops it"
    );
    assert_eq!(b.orchestration(&id).unwrap().state, OrchState::Paused);
    assert_eq!(
        b.orchestration(&id).unwrap().feature("f1").unwrap().state,
        FeatureState::Paused
    );
    b.tick_orchestrations(&mut NoChannel, &mut yes, 12);
    assert_eq!(
        b.orchestration(&id)
            .unwrap()
            .feature("f1")
            .unwrap()
            .task_id
            .as_deref(),
        Some(t1.as_str()),
        "nothing starts while paused"
    );
    b.resume_orchestration(&id, "ada", 13).unwrap();
    let f = b.orchestration(&id).unwrap().feature("f1").unwrap();
    assert_ne!(f.task_id.as_deref(), Some(t1.as_str()));
    assert_eq!(
        b.task(f.task_id.as_deref().unwrap())
            .unwrap()
            .spec
            .branch
            .as_deref(),
        Some("orch/o1/a")
    );
    b.halt_orchestration(&id, true, "ada", 14).unwrap();
    assert!(
        b.resume_orchestration(&id, "ada", 15).is_err(),
        "a stopped orchestration stays stopped"
    );
}
