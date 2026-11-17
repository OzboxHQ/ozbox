#![allow(clippy::unwrap_used)]

use std::collections::BTreeMap;
use std::sync::Mutex;

use ozbox_core::{BoxName, BoxRecord, BoxSpec, BoxState, Size};

use super::super::agent::{AgentError, Incident, SelfTest};
use super::*;

type Script = Box<dyn Fn(&[String]) -> (i32, String) + Send + Sync>;

struct Scripted {
    started: Mutex<Vec<Vec<String>>>,
    polls: Mutex<BTreeMap<String, u32>>,
    script: Script,
    /// Polls that answer "still running" before the exit is reported.
    slow: u32,
}

impl BoxAgent for Scripted {
    fn metrics_now(&self, _: &BoxRecord, _: u64) -> Result<ozbox_core::MetricsSample, AgentError> {
        Err(AgentError::Unsupported("x".into()))
    }
    fn metrics_series(
        &self,
        _: &BoxRecord,
        _: u64,
        _: u64,
        _: u64,
    ) -> Result<Vec<ozbox_core::MetricsSample>, AgentError> {
        Err(AgentError::Unsupported("x".into()))
    }
    fn selftest(&self, _: &BoxRecord, _: u64) -> Result<SelfTest, AgentError> {
        Err(AgentError::Unsupported("x".into()))
    }
    fn incidents(&self, _: &BoxRecord, _: u64, _: u64) -> Result<Vec<Incident>, AgentError> {
        Err(AgentError::Unsupported("x".into()))
    }
    fn runs(
        &self,
        _: &BoxRecord,
        method: &str,
        sub: &str,
        body: &[u8],
    ) -> Result<(u16, serde_json::Value), AgentError> {
        if method == "POST" {
            let v: serde_json::Value = serde_json::from_slice(body).unwrap();
            let argv: Vec<String> = v["argv"]
                .as_array()
                .unwrap()
                .iter()
                .map(|a| a.as_str().unwrap().to_string())
                .collect();
            assert!(
                v["env"].as_object().unwrap().is_empty(),
                "no environment is passed"
            );
            assert!(v.get("stdin").is_none() || v["stdin"].is_null());
            let mut st = self.started.lock().unwrap();
            st.push(argv);
            return Ok((201, json!({ "id": format!("r{}", st.len()) })));
        }
        let id = sub
            .trim_start_matches('/')
            .split('/')
            .next()
            .unwrap()
            .to_string();
        let n: usize = id[1..].parse().unwrap();
        let argv = self.started.lock().unwrap()[n - 1].clone();
        let mut polls = self.polls.lock().unwrap();
        let c = polls.entry(id).or_insert(0);
        *c += 1;
        if *c <= self.slow {
            return Ok((
                200,
                json!({ "log": { "text": "", "next": 0, "exit_code": null } }),
            ));
        }
        let (code, text) = (self.script)(&argv);
        Ok((
            200,
            json!({ "log": { "text": text, "next": 1, "exit_code": code } }),
        ))
    }
}

fn rec() -> BoxRecord {
    BoxRecord {
        spec: BoxSpec::new(BoxName::new("main-box").unwrap(), Size::M),
        state: BoxState::Running,
        provider: "fake".into(),
        provider_id: None,
        machine_type: None,
        snapshots: vec![],
        created_at: None,
        last_activity_at: None,
    }
}

fn merger(slow: u32, script: Script) -> (DaemonMerger, Arc<Scripted>) {
    let a = Arc::new(Scripted {
        started: Mutex::default(),
        polls: Mutex::default(),
        script,
        slow,
    });
    (DaemonMerger::new(a.clone(), Some(rec())), a)
}

fn finish<T>(mut f: impl FnMut() -> Result<T, String>, pending: impl Fn(&T) -> bool) -> T {
    for _ in 0..50 {
        let r = f().unwrap();
        if !pending(&r) {
            return r;
        }
    }
    panic!("never finished");
}

#[test]
fn a_clean_rebase_is_fetch_worktree_rebase_all_argv_and_never_the_persons_tree() {
    let (mut m, a) = merger(1, Box::new(|_| (0, String::new())));
    let r = finish(
        || m.rebase(Some("web"), "orch/o1/a", "main"),
        |r| *r == RebaseOutcome::Pending,
    );
    assert_eq!(r, RebaseOutcome::Clean);
    let calls = a.started.lock().unwrap().clone();
    assert_eq!(calls.len(), 6);
    assert_eq!(
        calls[0],
        ["git", "-C", "/work/repos/web", "fetch", "--prune", "origin"]
    );
    assert_eq!(
        calls[2][4..],
        [
            "add",
            "--detach",
            "/work/orch/orch_o1_a",
            "origin/orch/o1/a"
        ]
    );
    assert_eq!(calls[3][3..], ["rebase", "origin/main"]);
    assert!(calls.iter().all(|c| c[0] == "git"), "{calls:?}");
    assert!(calls
        .iter()
        .all(|c| !c.iter().any(|a| a.contains(';') || a == "sh" || a == "-c")));
}

#[test]
fn a_conflicting_rebase_names_the_files_and_aborts() {
    let (mut m, a) = merger(
        0,
        Box::new(|argv| {
            if argv.iter().any(|x| x == "rebase")
                && argv.last().map(String::as_str) == Some("origin/main")
            {
                (1, "CONFLICT".into())
            } else if argv.iter().any(|x| x == "--diff-filter=U") {
                (0, "src/shared.rs\nsrc/db.rs\n".into())
            } else {
                (0, String::new())
            }
        }),
    );
    let r = finish(
        || m.rebase(Some("web"), "orch/o1/a", "main"),
        |r| *r == RebaseOutcome::Pending,
    );
    assert_eq!(
        r,
        RebaseOutcome::Conflict(vec!["src/shared.rs".into(), "src/db.rs".into()])
    );
    assert!(a
        .started
        .lock()
        .unwrap()
        .last()
        .unwrap()
        .contains(&"--abort".to_string()));
}

#[test]
fn a_step_that_must_succeed_and_fails_is_an_error_with_the_end_of_its_output() {
    let (mut m, _) = merger(
        0,
        Box::new(|argv| {
            if argv.contains(&"fetch".to_string()) {
                (128, "fatal: no remote".into())
            } else {
                (0, String::new())
            }
        }),
    );
    let e = m.rebase(Some("web"), "orch/o1/a", "main").unwrap_err();
    assert!(e.contains("fatal: no remote"), "{e}");
    assert!(m
        .rebase(None, "b", "main")
        .unwrap_err()
        .contains("repository"));
}

#[test]
fn tests_run_in_the_worktree_and_a_failure_returns_the_tail() {
    let (mut m, a) = merger(
        2,
        Box::new(|_| {
            (
                1,
                (1..=40).map(|i| format!("line {i}\n")).collect::<String>(),
            )
        }),
    );
    let r = finish(
        || {
            m.test(
                Some("web"),
                "orch/o1/a",
                &["cargo".into(), "test".into()],
                None,
            )
        },
        |r| *r == TestOutcome::Pending,
    );
    match r {
        TestOutcome::Fail(t) => {
            assert!(t.contains("line 40") && !t.contains("line 5\n"), "{t}");
        }
        o => panic!("{o:?}"),
    }
    assert_eq!(a.started.lock().unwrap()[0], ["cargo", "test"]);
    let (mut m, _) = merger(0, Box::new(|_| (0, String::new())));
    assert_eq!(
        m.test(None, "b", &["t".into()], None).unwrap(),
        TestOutcome::Pass
    );
}

#[test]
fn a_merge_is_a_plain_push_of_the_rebased_head_never_forced() {
    let (mut m, a) = merger(0, Box::new(|_| (0, String::new())));
    assert_eq!(
        m.merge(Some("web"), "orch/o1/a", "main").unwrap(),
        MergeOutcome::Done
    );
    let c = a.started.lock().unwrap()[0].clone();
    assert_eq!(c[3..], ["push", "origin", "HEAD:refs/heads/main"]);
    assert!(!c.iter().any(|x| x.contains("force") || x == "-f"));
    let (mut m, _) = merger(0, Box::new(|_| (1, "rejected".into())));
    assert!(m
        .merge(Some("web"), "b", "main")
        .unwrap_err()
        .contains("rejected"));
}

#[test]
fn a_box_that_cannot_be_reached_waits_and_says_why() {
    let mut m = DaemonMerger::new(Arc::new(super::super::agent::NoTransport), Some(rec()));
    assert!(m.rebase(Some("web"), "b", "main").is_err());
    let mut m = DaemonMerger::new(Arc::new(super::super::agent::NoTransport), None);
    assert!(m
        .merge(Some("web"), "b", "main")
        .unwrap_err()
        .contains("not known"));
}

const SHA: &str = "0123456789abcdef0123456789abcdef01234567";

#[test]
fn the_head_is_read_from_the_remote_after_a_fetch_and_is_pending_while_the_box_works() {
    let (mut m, a) = merger(
        2,
        Box::new(|argv: &[String]| {
            if argv.iter().any(|x| x == "rev-parse") {
                (0, format!("{SHA}\n"))
            } else {
                (0, String::new())
            }
        }),
    );
    // the first asks answer pending (the box is still running a step): the merge is never decided on a guess
    assert_eq!(
        m.head_step(Some("billing"), "feat/x").unwrap(),
        HeadRead::Pending
    );
    let got = finish(
        || m.head_step(Some("billing"), "feat/x"),
        |r| *r == HeadRead::Pending,
    );
    assert_eq!(got, HeadRead::Known(Some(SHA.into())));
    let started = a.started.lock().unwrap().clone();
    assert_eq!(started.len(), 2);
    // a fetch first (the head is the remote's now), then the remote-tracking ref, both as argv arrays
    assert_eq!(started[0][3..], ["fetch", "--prune", "origin"]);
    assert_eq!(started[1][3], "rev-parse");
    assert_eq!(started[1].last().unwrap(), "refs/remotes/origin/feat/x");
}

#[test]
fn a_branch_the_remote_does_not_have_has_no_head_and_is_an_error_not_unknown() {
    let (mut m, _) = merger(
        0,
        Box::new(|argv: &[String]| {
            if argv.iter().any(|x| x == "rev-parse") {
                (1, String::new())
            } else {
                (0, String::new())
            }
        }),
    );
    let e = m.head_step(Some("billing"), "feat/gone").unwrap_err();
    assert!(e.contains("not on the remote"), "{e}");
    // output that is not a commit is not one either
    let (mut m, _) = merger(0, Box::new(|_| (0, "not a sha".to_string())));
    assert!(m.head_step(Some("billing"), "feat/x").is_err());
}
