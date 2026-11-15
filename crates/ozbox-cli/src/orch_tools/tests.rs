#![allow(clippy::unwrap_used)]

use std::sync::Mutex;

use ozbox_core::run::{ActionKind, ApprovalRequest, RunOrigin};
use ozbox_core::{BoxName, Change, Operation, Plan};

use super::*;

#[derive(Default)]
pub struct FakeOps {
    pub boxes: Mutex<Vec<String>>,
    pub applied: Mutex<Vec<String>>,
    pub high: bool,
}

impl BoxOps for FakeOps {
    fn list(&self) -> Result<Vec<Value>, String> {
        Ok(self
            .boxes
            .lock()
            .unwrap()
            .iter()
            .map(|n| json!({ "name": n, "state": "running", "size": "M" }))
            .collect())
    }
    fn plan(&self, op: Value) -> Result<Value, String> {
        let name = BoxName::new(op["to"].as_str().or(op["name"].as_str()).unwrap_or("x")).unwrap();
        let plan = Plan {
            operation: Operation::Pause { name },
            provider: "fake".into(),
            changes: vec![Change::new(
                "instance.create",
                "make a box",
                if self.high { Risk::High } else { Risk::Medium },
            )],
            notes: vec![],
            based_on: "x".into(),
        };
        self.applied
            .lock()
            .unwrap()
            .push(format!("plan {}", op["op"].as_str().unwrap_or("")));
        Ok(json!({ "plan_id": "p1", "plan": plan }))
    }
    fn apply(&self, _: &str, plan: &Value) -> Result<Value, String> {
        let n = plan["operation"]["name"].as_str().unwrap_or("").to_string();
        self.applied.lock().unwrap().push(format!("apply {n}"));
        self.boxes.lock().unwrap().push(n);
        Ok(json!({ "applied": true, "result": { "state": "running" } }))
    }
}

struct Rig {
    tools: Tools,
    ops: Arc<FakeOps>,
    _dir: tempfile::TempDir,
}

fn rig(high: bool) -> Rig {
    let dir = tempfile::tempdir().unwrap();
    let ops = Arc::new(FakeOps {
        boxes: Mutex::new(vec!["main-box".into()]),
        high,
        ..Default::default()
    });
    let store = TaskStore::new(dir.path().join("tasks.json"));
    Rig {
        tools: Tools::new(store, ops.clone()),
        ops,
        _dir: dir,
    }
}

fn person() -> Session {
    Session {
        person: "ada".into(),
        role: Role::Person,
    }
}

fn start(r: &Rig) -> String {
    let v = r
        .tools
        .call(
            &person(),
            "orchestration_start",
            &json!({ "goal": "ship it", "conductor_box": "main-box" }),
            10,
        )
        .unwrap();
    v["id"].as_str().unwrap().to_string()
}

fn cond(id: &str) -> Session {
    Session {
        person: "ada".into(),
        role: Role::Conductor { orch: id.into() },
    }
}

fn worker(id: &str, f: &str) -> Session {
    Session {
        person: "ada".into(),
        role: Role::Worker {
            orch: id.into(),
            feature: f.into(),
        },
    }
}

#[test]
fn the_tool_lists_are_exactly_the_named_sets_and_none_runs_a_command_or_returns_a_key() {
    assert_eq!(tool_names(&Role::Person).len(), 23);
    assert_eq!(tool_names(&Role::Conductor { orch: "o1".into() }).len(), 22);
    assert_eq!(
        tool_names(&Role::Worker {
            orch: "o".into(),
            feature: "f".into()
        })
        .len(),
        11
    );
    for role in [
        Role::Person,
        Role::Worker {
            orch: "o".into(),
            feature: "f".into(),
        },
    ] {
        let defs = tool_defs(&role);
        assert_eq!(defs.len(), tool_names(&role).len());
        for d in defs {
            let n = d["name"].as_str().unwrap();
            for bad in [
                "exec",
                "shell",
                "ssh",
                "secret",
                "key",
                "run_command",
                "token",
            ] {
                assert!(!n.contains(bad), "{n}");
            }
            assert!(d["inputSchema"]["type"] == "object");
            assert!(d["description"].as_str().unwrap().len() > 20);
        }
    }
    for n in ["box_destroy", "box_resize", "shell", "approvals_decide"] {
        assert!(!tool_names(&Role::Worker {
            orch: "o".into(),
            feature: "f".into()
        })
        .contains(&n));
    }
}

#[test]
fn a_worker_has_no_conductor_tool_and_a_conductor_cannot_start_another_orchestration() {
    let r = rig(false);
    let id = start(&r);
    let w = worker(&id, "f1");
    for t in [
        "task_start",
        "box_clone",
        "approvals_decide",
        "merge_queue",
        "orchestration_start",
        "fleet_boxes",
    ] {
        assert!(
            matches!(
                r.tools.call(&w, t, &json!({}), 1),
                Err(ToolError::NotFound(_))
            ),
            "{t}"
        );
    }
    assert!(matches!(
        r.tools.call(
            &cond(&id),
            "orchestration_start",
            &json!({"goal":"x","conductor_box":"main-box"}),
            1
        ),
        Err(ToolError::NotFound(_))
    ));
    assert!(r
        .tools
        .call(&cond(&id), "no_such_tool", &json!({}), 1)
        .is_err());
}

#[test]
fn one_person_cannot_see_or_touch_anothers_orchestration() {
    let r = rig(false);
    let id = start(&r);
    let other = Session {
        person: "bob".into(),
        role: Role::Person,
    };
    let e = r
        .tools
        .call(&other, "task_status", &json!({ "orchestration": id }), 1)
        .unwrap_err();
    assert!(matches!(e, ToolError::NotFound(_)));
    let e = r
        .tools
        .call(&other, "budget_status", &json!({}), 1)
        .unwrap_err();
    assert!(
        matches!(e, ToolError::Invalid(_)),
        "bob has none open, so he must name one"
    );
    let wrong = Session {
        person: "bob".into(),
        role: Role::Conductor { orch: id.clone() },
    };
    assert!(r.tools.call(&wrong, "task_status", &json!({}), 1).is_err());
}

#[test]
fn orchestration_start_applies_the_rules_that_only_tighten_and_needs_a_real_box() {
    let r = rig(false);
    assert!(matches!(
        r.tools.call(
            &person(),
            "orchestration_start",
            &json!({ "goal": "x", "conductor_box": "ghost" }),
            1
        ),
        Err(ToolError::NotFound(_))
    ));
    let v = r
        .tools
        .call(
            &person(),
            "orchestration_start",
            &json!({ "goal": "x", "conductor_box": "main-box", "max_workers": 2, "max_sub_agents": 9,
                     "rules": "---\nmerge_approval: none\ntest_command: cargo test\n---\nSmall commits." }),
            1,
        )
        .unwrap();
    let p = &v["policy"];
    assert_eq!(p["max_workers"], 2);
    assert_eq!(p["max_sub_agents"], 3);
    assert_eq!(p["merge_approval"], "person");
    assert_eq!(p["test_command"], json!(["cargo", "test"]));
    assert!(p["notes"].as_array().unwrap().len() >= 2);
    assert!(r
        .tools
        .call(
            &person(),
            "orchestration_start",
            &json!({ "goal": "x", "conductor_box": "main-box", "rules": "---\nbogus: 1\n---\n" }),
            1
        )
        .is_err());
}

#[test]
fn box_clone_is_plan_then_apply_inside_the_limits() {
    let r = rig(false);
    let id = start(&r);
    let c = cond(&id);
    let dry = r
        .tools
        .call(&c, "box_clone", &json!({ "to": "w-a", "dry_run": true }), 1)
        .unwrap();
    assert_eq!(dry["applied"], false);
    assert!(
        !r.ops
            .applied
            .lock()
            .unwrap()
            .iter()
            .any(|l| l.starts_with("apply")),
        "a dry run applies nothing"
    );
    for n in ["w-a", "w-b", "w-c"] {
        let v = r
            .tools
            .call(&c, "box_clone", &json!({ "to": n }), 2)
            .unwrap();
        assert_eq!(v["applied"], true);
    }
    let e = r
        .tools
        .call(&c, "box_clone", &json!({ "to": "w-d" }), 3)
        .unwrap_err();
    assert!(
        matches!(e, ToolError::Refused(_)),
        "the fourth worker box: {e:?}"
    );
    // it must be new, must not copy a stranger's box, and must be a valid name
    assert!(r
        .tools
        .call(&c, "box_clone", &json!({ "to": "w-a" }), 3)
        .is_err());
    assert!(r
        .tools
        .call(&c, "box_clone", &json!({ "to": "Bad Name" }), 3)
        .is_err());
    r.ops.boxes.lock().unwrap().push("someone-elses".into());
    let e = r
        .tools
        .call(
            &cond(&id),
            "box_clone",
            &json!({ "to": "w-z", "from": "someone-elses" }),
            3,
        )
        .unwrap_err();
    assert!(
        e.message().contains("conductor's box") || e.message().contains("at most"),
        "{e:?}"
    );
    let spare = r.tools.call(&c, "fleet_boxes", &json!({}), 4).unwrap();
    assert_eq!(
        spare["boxes"]
            .as_array()
            .unwrap()
            .iter()
            .filter(|b| b["role"] == "spare")
            .count(),
        3
    );
}

#[test]
fn a_change_that_cannot_be_undone_is_never_applied_by_an_agent() {
    let r = rig(true);
    let id = start(&r);
    let e = r
        .tools
        .call(&cond(&id), "box_clone", &json!({ "to": "w-a" }), 1)
        .unwrap_err();
    assert!(matches!(e, ToolError::Refused(_)));
    assert!(!r
        .ops
        .applied
        .lock()
        .unwrap()
        .iter()
        .any(|l| l.starts_with("apply")));
}

#[test]
fn box_pause_reaches_only_this_orchestrations_workers_never_the_conductor() {
    let r = rig(false);
    let id = start(&r);
    let c = cond(&id);
    r.tools
        .call(&c, "box_clone", &json!({ "to": "w-a" }), 1)
        .unwrap();
    assert!(r
        .tools
        .call(&c, "box_pause", &json!({ "box": "main-box" }), 2)
        .is_err());
    assert!(r
        .tools
        .call(&c, "box_pause", &json!({ "box": "other" }), 2)
        .is_err());
    assert!(r
        .tools
        .call(
            &c,
            "box_pause",
            &json!({ "box": "w-a", "dry_run": true }),
            2
        )
        .is_ok());
}

#[test]
fn box_create_follows_the_may_create_boxes_rule() {
    let r = rig(false);
    let v = r
        .tools
        .call(&person(), "orchestration_start", &json!({ "goal": "x", "conductor_box": "main-box", "rules": "---\nmay_create_boxes: false\n---\n" }), 1)
        .unwrap();
    let id = v["id"].as_str().unwrap().to_string();
    let e = r
        .tools
        .call(&cond(&id), "box_create", &json!({ "name": "fresh" }), 2)
        .unwrap_err();
    assert!(matches!(e, ToolError::Refused(_)));
    // a clone is still allowed
    assert!(r
        .tools
        .call(&cond(&id), "box_clone", &json!({ "to": "w-a" }), 2)
        .is_ok());
}

fn with_worker(r: &Rig, id: &str, title: &str, claims: &[&str]) -> String {
    let c = cond(id);
    let name = format!("w-{}", title);
    r.tools
        .call(&c, "box_clone", &json!({ "to": name }), 2)
        .unwrap();
    let v = r
        .tools
        .call(
            &c,
            "task_start",
            &json!({ "title": title, "brief": "build it", "box": name, "claims": claims }),
            3,
        )
        .unwrap();
    v["feature"].as_str().unwrap().to_string()
}

#[test]
fn task_start_needs_a_real_box_refuses_overlap_and_the_fourth_sub_agent() {
    let r = rig(false);
    let id = start(&r);
    let c = cond(&id);
    assert!(
        r.tools
            .call(&c, "task_start", &json!({ "title": "a", "brief": "b" }), 1)
            .is_err(),
        "no box named or spare"
    );
    assert!(r
        .tools
        .call(
            &c,
            "task_start",
            &json!({ "title": "a", "brief": "b", "box": "ghost" }),
            1
        )
        .is_err());
    let f1 = with_worker(&r, &id, "a", &["src/api"]);
    assert_eq!(f1, "f1");
    r.tools
        .call(&c, "box_clone", &json!({ "to": "w-b" }), 2)
        .unwrap();
    let e = r
        .tools
        .call(
            &c,
            "task_start",
            &json!({ "title": "b", "brief": "x", "box": "w-b", "claims": ["src/api/users"] }),
            3,
        )
        .unwrap_err();
    assert!(matches!(e, ToolError::Refused(_)), "overlap: {e:?}");
    let e = r
        .tools
        .call(
            &c,
            "task_start",
            &json!({ "title": "b", "brief": "x", "box": "w-b", "sub_agents": 4 }),
            3,
        )
        .unwrap_err();
    assert!(matches!(e, ToolError::Refused(_)), "{e:?}");
    // a dry run checks and saves nothing
    let d = r.tools.call(&c, "task_start", &json!({ "title": "b", "brief": "x", "box": "w-b", "claims": ["src/web"], "dry_run": true }), 3).unwrap();
    assert_eq!(d["applied"], false);
    let st = r.tools.call(&c, "task_status", &json!({}), 4).unwrap();
    assert_eq!(st["features"].as_array().unwrap().len(), 1);
}

#[test]
fn a_worker_asks_and_is_blocked_and_the_conductor_answers_unless_it_is_for_the_person() {
    let r = rig(false);
    let id = start(&r);
    let c = cond(&id);
    let f = with_worker(&r, &id, "a", &["src/a"]);
    // let it run, then ask
    r.tools
        .store
        .update(|b| {
            b.orchestration_mut(&id)
                .unwrap()
                .feature_mut(&f)
                .unwrap()
                .state = FeatureState::Working;
        })
        .unwrap();
    let w = worker(&id, &f);
    let q = r
        .tools
        .call(&w, "worker_ask", &json!({ "question": "which db?" }), 5)
        .unwrap();
    assert!(q["next"].as_str().unwrap().contains("end your turn"));
    let st = r.tools.call(&c, "task_status", &json!({}), 6).unwrap();
    assert_eq!(st["features"][0]["state"], "blocked");
    assert_eq!(st["open_questions"].as_array().unwrap().len(), 1);
    assert_eq!(st["messages"].as_array().unwrap().len(), 1);
    let n = q["question"].as_u64().unwrap();
    r.tools
        .call(
            &c,
            "task_message",
            &json!({ "text": "postgres", "answer_to": n }),
            7,
        )
        .unwrap();
    let ws = r
        .tools
        .call(&w, "worker_status", &json!({ "text": "on it" }), 8)
        .unwrap();
    assert_eq!(ws["state"], "working");
    assert_eq!(ws["messages"][0]["text"], "postgres");
    // a question marked for the person is out of the conductor's reach
    let q2 = r
        .tools
        .call(
            &w,
            "worker_ask",
            &json!({ "question": "drop prod?", "for_person": true }),
            9,
        )
        .unwrap();
    let e = r
        .tools
        .call(
            &c,
            "task_message",
            &json!({ "text": "yes", "answer_to": q2["question"] }),
            10,
        )
        .unwrap_err();
    assert!(matches!(e, ToolError::Refused(_)));
    // a worker cannot act on another feature
    let e = r
        .tools
        .call(
            &w,
            "claims_check",
            &json!({ "feature": "f2", "paths": ["x"] }),
            1,
        )
        .unwrap_err();
    assert!(matches!(e, ToolError::Refused(_)));
}

#[test]
fn claims_check_names_the_owner_and_a_worker_cannot_widen_its_own_claims() {
    let r = rig(false);
    let id = start(&r);
    let f1 = with_worker(&r, &id, "a", &["src/a"]);
    let _f2 = with_worker(&r, &id, "b", &["src/b"]);
    let w = worker(&id, &f1);
    let v = r
        .tools
        .call(
            &w,
            "claims_check",
            &json!({ "paths": ["src/a/x.rs", "src/b/y.rs", "README.md"] }),
            4,
        )
        .unwrap();
    assert_eq!(v["allowed"], false);
    assert_eq!(v["paths"][0]["allowed"], true);
    assert!(v["paths"][1]["why"].as_str().unwrap().contains("f2"));
    let e = r
        .tools
        .call(&w, "claims_declare", &json!({ "claims": ["src/b"] }), 5)
        .unwrap_err();
    assert!(matches!(e, ToolError::Refused(_)));
    // a worker with no claims may propose them (still checked for overlap)
    let r2 = rig(false);
    let id2 = start(&r2);
    let f = with_worker(&r2, &id2, "c", &[]);
    let ok = r2
        .tools
        .call(
            &worker(&id2, &f),
            "claims_declare",
            &json!({ "claims": ["src/c"] }),
            5,
        )
        .unwrap();
    assert_eq!(ok["result"], "granted");
}

#[test]
fn a_contract_change_reaches_the_features_that_use_it_and_a_read_acknowledges_it() {
    let r = rig(false);
    let id = start(&r);
    let c = cond(&id);
    r.tools
        .call(
            &c,
            "contract_publish",
            &json!({ "name": "Users API", "kind": "api", "body": "v1" }),
            1,
        )
        .unwrap();
    r.tools
        .call(&c, "box_clone", &json!({ "to": "w-a" }), 2)
        .unwrap();
    let v = r.tools.call(&c, "task_start", &json!({ "title": "a", "brief": "x", "box": "w-a", "claims": ["src/a"], "contracts": ["users-api"] }), 3).unwrap();
    let f = v["feature"].as_str().unwrap();
    let p = r
        .tools
        .call(
            &c,
            "contract_publish",
            &json!({ "name": "Users API", "kind": "api", "body": "v2" }),
            4,
        )
        .unwrap();
    assert_eq!(p["version"], 2);
    let w = worker(&id, f);
    let ws = r.tools.call(&w, "worker_status", &json!({}), 5).unwrap();
    assert_eq!(ws["messages"][0]["kind"], "contract_changed");
    let read = r
        .tools
        .call(&w, "contract_read", &json!({ "id": "users-api" }), 6)
        .unwrap();
    assert_eq!(read["body"], "v2");
    let ws = r.tools.call(&w, "worker_status", &json!({}), 7).unwrap();
    assert_eq!(ws["contracts"][0]["version"], 2);
    assert_eq!(
        r.tools.call(&w, "contract_read", &json!({}), 8).unwrap()["contracts"]
            .as_array()
            .unwrap()
            .len(),
        1
    );
}

fn put_approval(r: &Rig, id: &str, kind: ActionKind, step_up: bool, task: &str) {
    r.tools
        .store
        .update(|b| {
            b.approvals.push(ApprovalRequest {
                id: "a9".into(),
                task_id: task.into(),
                kind,
                action: "x".into(),
                box_name: "w".into(),
                asked_by: "e".into(),
                production: false,
                needs_step_up: step_up,
                state: ozbox_core::run::ApprovalState::Pending,
                created_ms: 0,
                expires_ms: 100_000,
                reminders: 0,
                decided_by: None,
                decided_ms: None,
                decided_with_step_up: false,
                delivered: false,
                used: false,
            });
            let _ = id;
        })
        .unwrap();
}

#[test]
fn approvals_the_conductor_decides_only_low_risk_and_audits_itself() {
    let r = rig(false);
    let id = start(&r);
    let c = cond(&id);
    let f = with_worker(&r, &id, "a", &["src/a"]);
    let task = r
        .tools
        .store
        .load()
        .unwrap()
        .orchestration(&id)
        .unwrap()
        .feature(&f)
        .unwrap()
        .task_id
        .clone()
        .unwrap();
    put_approval(&r, &id, ActionKind::AskCommand, false, &task);
    let list = r
        .tools
        .call(&c, "approvals_pending", &json!({}), 5)
        .unwrap();
    assert_eq!(list["items"][0]["you_may_decide"], true);
    r.tools
        .call(
            &c,
            "approvals_decide",
            &json!({ "id": "a9", "approve": true }),
            6,
        )
        .unwrap();
    let book = r.tools.store.load().unwrap();
    assert_eq!(
        book.approval("a9").unwrap().decided_by.as_deref(),
        Some(&*format!("conductor:{id}"))
    );
    assert!(book
        .audit
        .iter()
        .any(|a| a.action == "approval.approved" && a.actor.starts_with("conductor:")));
    // a risky kind, and one that needs a second factor, are the person's
    r.tools.store.update(|b| b.approvals.clear()).unwrap();
    put_approval(&r, &id, ActionKind::PushProtectedBranch, false, &task);
    let e = r
        .tools
        .call(
            &c,
            "approvals_decide",
            &json!({ "id": "a9", "approve": true }),
            7,
        )
        .unwrap_err();
    assert!(matches!(e, ToolError::Refused(_)));
    assert_eq!(
        r.tools
            .call(&c, "approvals_pending", &json!({}), 8)
            .unwrap()["items"][0]["waiting_for"],
        "the person"
    );
    assert_eq!(
        r.tools.store.load().unwrap().approval("a9").unwrap().state,
        ozbox_core::run::ApprovalState::Pending
    );
    r.tools.store.update(|b| b.approvals.clear()).unwrap();
    put_approval(&r, &id, ActionKind::AskCommand, true, &task);
    assert!(r
        .tools
        .call(
            &c,
            "approvals_decide",
            &json!({ "id": "a9", "approve": true }),
            9
        )
        .is_err());
    // another orchestration's request is not even visible
    r.tools.store.update(|b| b.approvals.clear()).unwrap();
    put_approval(&r, &id, ActionKind::AskCommand, false, "t999");
    assert!(matches!(
        r.tools.call(
            &c,
            "approvals_decide",
            &json!({ "id": "a9", "approve": true }),
            10
        ),
        Err(ToolError::NotFound(_))
    ));
    // a person's own agent is never the person: the same limits apply to it
    r.tools.store.update(|b| b.approvals.clear()).unwrap();
    put_approval(&r, &id, ActionKind::PushProtectedBranch, false, &task);
    assert!(r
        .tools
        .call(
            &person(),
            "approvals_decide",
            &json!({ "orchestration": id, "id": "a9", "approve": true }),
            11
        )
        .is_err());
}

#[test]
fn the_merge_queue_takes_only_a_feature_that_finished_and_done_marks_it_ready() {
    let r = rig(false);
    let id = start(&r);
    let c = cond(&id);
    let f = with_worker(&r, &id, "a", &["src/a"]);
    assert!(
        r.tools
            .call(&c, "merge_queue", &json!({ "feature": f }), 5)
            .is_err(),
        "still starting"
    );
    r.tools
        .store
        .update(|b| {
            b.orchestration_mut(&id)
                .unwrap()
                .feature_mut(&f)
                .unwrap()
                .state = FeatureState::Working;
        })
        .unwrap();
    let w = worker(&id, &f);
    assert_eq!(
        r.tools
            .call(&w, "worker_done", &json!({ "summary": "built" }), 6)
            .unwrap()["state"],
        "ready_to_merge"
    );
    assert!(
        r.tools.call(&w, "worker_done", &json!({}), 7).is_err(),
        "only once"
    );
    let q = r
        .tools
        .call(&c, "merge_queue", &json!({ "feature": f }), 8)
        .unwrap();
    assert_eq!(q["position"], 1);
    let m = r.tools.call(&c, "merge_status", &json!({}), 9).unwrap();
    assert_eq!(m["queue"][0]["state"], "waiting");
    assert_eq!(m["merge_approval"], "person");
}

#[test]
fn task_stop_saves_the_work_by_cancelling_through_the_supervisor_and_frees_the_box() {
    let r = rig(false);
    let id = start(&r);
    let c = cond(&id);
    let f = with_worker(&r, &id, "a", &["src/a"]);
    let task = r
        .tools
        .store
        .load()
        .unwrap()
        .orchestration(&id)
        .unwrap()
        .feature(&f)
        .unwrap()
        .task_id
        .clone()
        .unwrap();
    r.tools
        .call(&c, "task_stop", &json!({ "feature": f }), 5)
        .unwrap();
    let b = r.tools.store.load().unwrap();
    assert!(b.task(&task).unwrap().cancel_requested);
    assert_eq!(
        b.orchestration(&id).unwrap().feature(&f).unwrap().state,
        FeatureState::Stopped
    );
    assert!(matches!(
        b.task(&task).unwrap().spec.origin,
        RunOrigin::Orchestration { .. }
    ));
}

#[test]
fn budget_status_reports_the_one_cap() {
    let r = rig(false);
    let id = start(&r);
    let v = r
        .tools
        .call(&cond(&id), "budget_status", &json!({}), 1)
        .unwrap();
    assert_eq!(v["cap_cents"], 5000);
    assert_eq!(v["spent_cents"], 0);
    assert_eq!(v["remaining_cents"], 5000);
}

fn terminal_scope(key: &str, program: &str, pid: u32, code: &str) -> crate::mcp::HostScope {
    crate::mcp::HostScope {
        box_name: None,
        run_id: None,
        orchestration: None,
        actor: ozbox_core::permissions::ActorKind::Terminal,
        session: Some(key.into()),
        program: Some(program.into()),
        program_pid: Some(pid),
        code: Some(code.into()),
        standing_until_ms: None,
        door_gen: 0,
    }
}

#[test]
fn an_orchestration_tool_asked_from_the_terminal_door_names_the_program_and_its_code() {
    let r = rig(false);
    // a rule that says a person must approve this tool: the mode alone never asks about an orchestration tool
    r.tools
        .store
        .update(|b| {
            use ozbox_core::permissions::{Effect, Mode, PermSettings, Rule, Scope};
            b.perms
                .apply_settings(PermSettings {
                    default_mode: Mode::Ask,
                    modes: vec![],
                    rules: vec![Rule {
                        id: String::new(),
                        effect: Effect::Ask,
                        action: "tool.call".into(),
                        scope: Scope::Person,
                        scope_id: None,
                        path: None,
                        command: None,
                        env: None,
                        tool: Some("box_clone".into()),
                        server: None,
                        note: String::new(),
                    }],
                    browser_hosts: vec![],
                })
                .unwrap()
        })
        .unwrap();
    let a = terminal_scope("terminal-10-1-1", "codex", 10, "K7Q2XA");
    let b = terminal_scope("terminal-20-2-1", "python3", 20, "M3N4PQ");
    let mut waiting = Vec::new();
    for h in [&a, &b] {
        let e = r
            .tools
            .call_as(&person(), Some(h), "box_clone", &json!({ "to": "w-t" }), 5)
            .unwrap_err();
        let ToolError::Refused(msg) = e else {
            panic!("a terminal caller's write waits for a person")
        };
        waiting.push(msg);
    }
    assert!(
        waiting[0].contains("The card names this session K7Q2XA."),
        "{}",
        waiting[0]
    );
    assert!(
        waiting[1].contains("The card names this session M3N4PQ."),
        "{}",
        waiting[1]
    );
    let book = r.tools.store.load().unwrap();
    assert_eq!(
        book.approvals.len(),
        2,
        "one card per program, not one shared"
    );
    let asked: Vec<&str> = book.approvals.iter().map(|x| x.asked_by.as_str()).collect();
    assert!(
        asked[0].contains("calls itself codex") && asked[0].contains("K7Q2XA"),
        "{asked:?}"
    );
    assert!(
        asked[1].contains("calls itself python3") && asked[1].contains("M3N4PQ"),
        "{asked:?}"
    );
    assert_ne!(book.approvals[0].task_id, book.approvals[1].task_id);
    // nothing was made
    assert!(r.ops.applied.lock().unwrap().is_empty());
}
