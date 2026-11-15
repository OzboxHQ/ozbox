#![allow(clippy::unwrap_used)]

use std::sync::{Arc, Mutex};
use std::time::Duration;

use ozbox_core::claude_code::{Launch, LogChunk, RunTransport};
use ozbox_core::permissions::{
    ActorKind, Effect, Mode, NewGrant, PermSettings, Rule, Scope, SecondFactor,
};
use ozbox_core::run::{ApprovalState, TaskStore};
use ozbox_core::supervisor;
use serde_json::{json, Value};

use super::backend::{DaemonBackend, ExecOut, ExecReq, HostBackend, LocalBackend};
use super::*;
use crate::mcp::{HostScope, McpServer};
use crate::orch_tools::{Role, Session, ToolError};

struct Facts(Vec<(&'static str, bool)>);

impl BoxFacts for Facts {
    fn exists(&self, b: &str) -> bool {
        self.0.iter().any(|(n, _)| *n == b)
    }
    fn production(&self, b: &str) -> bool {
        self.0.iter().any(|(n, p)| *n == b && *p)
    }
}

struct Rig {
    dir: tempfile::TempDir,
    tools: HostTools,
}

fn rig_in(dir: tempfile::TempDir, backend: Arc<dyn HostBackend>) -> Rig {
    let store = TaskStore::new(dir.path().join("tasks.json"));
    let mut tools = HostTools::new(
        store,
        backend,
        Arc::new(Facts(vec![("alpha", false), ("prod", true)])),
    );
    tools.ask_wait = Duration::from_millis(60);
    tools.poll = Duration::from_millis(10);
    Rig { dir, tools }
}

fn rig_with(backend: Arc<dyn HostBackend>) -> Rig {
    rig_in(tempfile::tempdir().unwrap(), backend)
}

/// A rig whose work folders and store live in one directory that goes away together.
fn rig() -> Rig {
    let dir = tempfile::tempdir().unwrap();
    let be = Arc::new(LocalBackend::new(dir.path().join("work")));
    rig_in(dir, be)
}

fn agent() -> Session {
    Session {
        person: "ada".into(),
        role: Role::Agent,
    }
}

fn scope(box_name: &str) -> HostScope {
    HostScope {
        box_name: Some(box_name.into()),
        run_id: Some("t1".into()),
        orchestration: None,
        actor: ActorKind::Agent,
        session: None,
        program: None,
        program_pid: None,
        code: None,
        standing_until_ms: None,
        door_gen: 0,
    }
}

fn allow_all(r: &Rig) {
    r.tools
        .store
        .update(|b| b.perms.default_mode = Mode::Auto)
        .unwrap();
}

fn call(r: &Rig, bx: &str, name: &str, a: Value) -> Result<Value, ToolError> {
    r.tools.call(&agent(), Some(&scope(bx)), name, &a, 1_000)
}

fn refused(e: ToolError) -> String {
    match e {
        ToolError::Refused(m) => m,
        other => panic!("expected a refusal, got {other:?}"),
    }
}

fn deny_tool(tool: &str) -> Rule {
    Rule {
        id: String::new(),
        effect: Effect::Deny,
        action: "tool.call".into(),
        scope: Scope::Person,
        scope_id: None,
        path: None,
        command: None,
        env: None,
        tool: Some(tool.into()),
        server: None,
        note: String::new(),
    }
}

// ---- the surface ---------------------------------------------------------------------------------------------------------

#[test]
fn the_host_tools_are_exactly_this_list_and_each_has_a_definition() {
    let names: Vec<&str> = TOOLS.iter().map(|t| t.name).collect();
    assert_eq!(
        names,
        [
            "shell",
            "git_status",
            "git_diff",
            "git_log",
            "git_branch",
            "git_commit",
            "git_push",
            "files_read",
            "files_write",
            "files_list",
            "files_search",
            "browser_fetch",
            "browser_screenshot",
            "ci_status",
            "ci_logs",
            "ci_rerun",
            "staging_read"
        ]
    );
    let defs = tool_defs(false);
    assert_eq!(defs.len(), TOOLS.len());
    for d in &defs {
        assert!(
            d["description"].as_str().is_some_and(|x| !x.is_empty()),
            "{d}"
        );
        assert_eq!(d["inputSchema"]["type"], "object");
        assert!(d["inputSchema"]["properties"]["box"].is_null());
    }
    // a person's own agent names the box in every call
    for d in tool_defs(true) {
        assert!(d["inputSchema"]["required"]
            .as_array()
            .unwrap()
            .iter()
            .any(|x| x == "box"));
    }
    // nothing here returns a key, and no tool takes one
    for d in &defs {
        let props = d["inputSchema"]["properties"].to_string();
        for bad in ["token", "password", "secret", "api_key", "env_values"] {
            assert!(!props.contains(bad), "{} takes {bad}", d["name"]);
        }
    }
}

#[test]
fn an_unknown_tool_is_not_found_and_a_missing_or_unknown_box_is_refused() {
    let r = rig();
    assert!(matches!(
        call(&r, "alpha", "rm_rf", json!({})),
        Err(ToolError::NotFound(_))
    ));
    let person = Session {
        person: "ada".into(),
        role: Role::Person,
    };
    let e = r
        .tools
        .call(&person, None, "files_list", &json!({}), 1)
        .unwrap_err();
    assert!(matches!(e, ToolError::Invalid(m) if m.contains("box")));
    let e = r
        .tools
        .call(&person, None, "files_list", &json!({ "box": "nope" }), 1)
        .unwrap_err();
    assert!(matches!(e, ToolError::NotFound(_)));
    // a run acts only on its own box
    let e = r
        .tools
        .call(
            &agent(),
            Some(&scope("alpha")),
            "files_list",
            &json!({ "box": "prod" }),
            1,
        )
        .unwrap_err();
    assert!(refused(e).contains("own box"));
}

// ---- files ---------------------------------------------------------------------------------------------------------------

#[test]
fn files_write_read_list_and_search_stay_under_work() {
    let r = rig();
    allow_all(&r);
    let w = call(
        &r,
        "alpha",
        "files_write",
        json!({ "path": "src/a.txt", "content": "hello\nneedle here\n", "create_dirs": true }),
    )
    .unwrap();
    assert_eq!(w["path"], "src/a.txt");
    let rd = call(
        &r,
        "alpha",
        "files_read",
        json!({ "path": "/work/src/a.txt" }),
    )
    .unwrap();
    assert_eq!(rd["content"], "hello\nneedle here\n");
    let ls = call(&r, "alpha", "files_list", json!({ "path": "src" })).unwrap();
    assert_eq!(ls["entries"][0]["name"], "a.txt");
    let se = call(&r, "alpha", "files_search", json!({ "text": "needle" })).unwrap();
    assert_eq!(se["matches"][0]["path"], "src/a.txt");
    assert_eq!(se["matches"][0]["line"], 2);
    // another box has its own /work, and a write to production is refused without a grant
    assert!(
        call(&r, "prod", "files_list", json!({})).unwrap()["entries"]
            .as_array()
            .unwrap()
            .is_empty()
    );
    assert!(call(
        &r,
        "prod",
        "files_write",
        json!({ "path": "x", "content": "y" })
    )
    .is_err());
}

#[test]
fn a_path_that_escapes_work_is_refused_lexically_and_through_a_symlink() {
    let r = rig();
    allow_all(&r);
    for p in ["../x", "/etc/passwd", "a/../../x", "~/x"] {
        let e = call(&r, "alpha", "files_read", json!({ "path": p })).unwrap_err();
        assert!(matches!(e, ToolError::Invalid(_)), "{p}");
    }
    // a symlink inside /work that points outside is followed by the backend and refused
    let outside = r.dir.path().join("outside");
    std::fs::create_dir_all(&outside).unwrap();
    std::fs::write(outside.join("secret.txt"), "top secret").unwrap();
    call(&r, "alpha", "files_list", json!({})).unwrap();
    std::os::unix::fs::symlink(&outside, r.dir.path().join("work/alpha/out")).unwrap();
    let e = call(
        &r,
        "alpha",
        "files_read",
        json!({ "path": "out/secret.txt" }),
    )
    .unwrap_err();
    assert!(refused(e).contains("inside /work"));
    let e = call(
        &r,
        "alpha",
        "files_write",
        json!({ "path": "out/new.txt", "content": "x" }),
    )
    .unwrap_err();
    assert!(refused(e).contains("inside /work"));
    assert!(!outside.join("new.txt").exists());
    // and a shell working directory cannot leave either
    let e = call(
        &r,
        "alpha",
        "shell",
        json!({ "command": "pwd", "cwd": "out" }),
    )
    .unwrap_err();
    assert!(refused(e).contains("inside /work"));
}

#[test]
fn secret_files_git_internals_binary_and_long_writes_are_refused() {
    let r = rig();
    allow_all(&r);
    for p in [".env", "app/.env.production", "keys/id_rsa", ".git/config"] {
        assert!(
            matches!(
                call(
                    &r,
                    "alpha",
                    "files_write",
                    json!({ "path": p, "content": "x" })
                ),
                Err(ToolError::Refused(_))
            ),
            "{p}"
        );
        assert!(
            matches!(
                call(&r, "alpha", "files_read", json!({ "path": p })),
                Err(ToolError::Refused(_))
            ),
            "{p}"
        );
    }
    let big = "x".repeat(WRITE_MAX + 1);
    assert!(matches!(
        call(
            &r,
            "alpha",
            "files_write",
            json!({ "path": "big.txt", "content": big })
        ),
        Err(ToolError::Invalid(_))
    ));
    call(&r, "alpha", "files_list", json!({})).unwrap();
    std::fs::write(r.dir.path().join("work/alpha/bin.dat"), [0u8, 1, 2]).unwrap();
    assert!(matches!(
        call(&r, "alpha", "files_read", json!({ "path": "bin.dat" })),
        Err(ToolError::Invalid(_))
    ));
    // a search never reports a hit inside a protected file
    std::fs::write(r.dir.path().join("work/alpha/.env"), "TOKEN=needle\n").unwrap();
    let se = call(&r, "alpha", "files_search", json!({ "text": "needle" })).unwrap();
    assert!(se["matches"].as_array().unwrap().is_empty(), "{se}");
}

#[test]
fn a_read_is_capped() {
    let r = rig();
    allow_all(&r);
    std::fs::create_dir_all(r.dir.path().join("work/alpha")).unwrap();
    std::fs::write(r.dir.path().join("work/alpha/big.txt"), "a".repeat(5000)).unwrap();
    let v = call(
        &r,
        "alpha",
        "files_read",
        json!({ "path": "big.txt", "max_bytes": 100 }),
    )
    .unwrap();
    assert_eq!(v["bytes"], 100);
    assert_eq!(v["truncated"], true);
    assert!(call(
        &r,
        "alpha",
        "files_read",
        json!({ "path": "big.txt", "max_bytes": READ_MAX + 1 })
    )
    .is_err());
}

// ---- shell ---------------------------------------------------------------------------------------------------------------

#[test]
fn the_shell_runs_in_work_with_a_clean_environment_and_returns_the_exit_code() {
    let r = rig();
    allow_all(&r);
    let v = call(
        &r,
        "alpha",
        "shell",
        json!({ "command": "echo hi; echo oops 1>&2; exit 3" }),
    )
    .unwrap();
    assert_eq!(v["exit_code"], 3);
    assert_eq!(v["output"], "hi\n");
    assert_eq!(v["stderr"], "oops\n");
    // the environment is empty of the host's: nothing inherited can leak
    std::env::set_var("OZBOX_TEST_LEAK", "leaked-value");
    let v = call(
        &r,
        "alpha",
        "shell",
        json!({ "command": "echo \"[$OZBOX_TEST_LEAK]\"" }),
    )
    .unwrap();
    assert_eq!(v["output"], "[]\n");
}

#[test]
fn a_command_that_runs_too_long_is_stopped() {
    let r = rig();
    allow_all(&r);
    let t = std::time::Instant::now();
    let v = call(
        &r,
        "alpha",
        "shell",
        json!({ "command": "sleep 20", "timeout_s": 1 }),
    )
    .unwrap();
    assert_eq!(v["timed_out"], true);
    assert!(t.elapsed() < Duration::from_secs(8));
    assert!(call(
        &r,
        "alpha",
        "shell",
        json!({ "command": "true", "timeout_s": SHELL_MAX_TIMEOUT_S + 1 })
    )
    .is_err());
    assert!(call(
        &r,
        "alpha",
        "shell",
        json!({ "command": "true", "timeout_s": 0 })
    )
    .is_err());
}

#[test]
fn output_is_capped() {
    let r = rig();
    allow_all(&r);
    let v = call(
        &r,
        "alpha",
        "shell",
        json!({ "command": "head -c 100000 /dev/zero | tr '\\0' a", "max_output_bytes": 1000 }),
    )
    .unwrap();
    assert_eq!(v["truncated"], true);
    assert!(v["output"].as_str().unwrap().len() <= 1000);
}

#[test]
fn commands_the_policy_asks_about_ask_even_in_auto_and_so_does_what_cannot_be_read() {
    let r = rig();
    allow_all(&r);
    for line in [
        "sudo ls",
        "ls && rm -rf build",
        "FOO=1 env rm -rf x",
        "echo $(id)",
        "sh -c 'ls'",
        "git push --force origin x",
    ] {
        let e = call(&r, "alpha", "shell", json!({ "command": line })).unwrap_err();
        assert!(refused(e).contains("approve this first"), "{line}");
    }
    // each asked once and shows the exact command, secrets removed
    let book = r.tools.store.load().unwrap();
    assert_eq!(book.approvals.len(), 6);
    assert!(book
        .approvals
        .iter()
        .all(|a| a.kind == ozbox_core::run::ActionKind::ToolCall));
    assert!(book.approvals[0].action.contains("sudo ls"));
    // an ordinary line does not ask
    assert!(call(&r, "alpha", "shell", json!({ "command": "ls -la" })).is_ok());
}

#[test]
fn a_deny_rule_on_a_command_in_the_middle_of_a_line_applies_to_the_whole_line() {
    let r = rig();
    allow_all(&r);
    r.tools
        .store
        .update(|b| {
            b.perms
                .apply_settings(PermSettings {
                    default_mode: Mode::Auto,
                    modes: vec![],
                    rules: vec![Rule {
                        tool: Some("shell".into()),
                        command: Some("rm -rf".into()),
                        ..deny_tool("shell")
                    }],
                    browser_hosts: vec![],
                })
                .unwrap()
        })
        .unwrap();
    let e = call(
        &r,
        "alpha",
        "shell",
        json!({ "command": "ls; rm -rf build" }),
    )
    .unwrap_err();
    assert!(refused(e).contains("rule r1"));
    assert!(call(&r, "alpha", "shell", json!({ "command": "ls; echo ok" })).is_ok());
}

// ---- ask, wait, approve, run once ----------------------------------------------------------------------------------------

/// A shared tool host for the two review-T13 tests: a long wait for a person, the store and the work folder in `r.dir`.
fn waiting_host(r: &mut Rig) -> Arc<HostTools> {
    r.tools.ask_wait = Duration::from_secs(10);
    Arc::new(std::mem::replace(
        &mut r.tools,
        HostTools::new(
            TaskStore::new(r.dir.path().join("tasks.json")),
            Arc::new(LocalBackend::new(r.dir.path().join("work"))),
            Arc::new(Facts(vec![("alpha", false)])),
        ),
    ))
}

/// What the door does when it ends what waiting calls asked under: the generation moves (inside its gate), then the sweep.
fn end_terms(tools: &Arc<HostTools>, now: u64) -> usize {
    tools
        .door_gen
        .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
    tools.end_waiting_terminal_approvals(now)
}

fn terminal_scope(actor: ActorKind, standing_until_ms: Option<u64>) -> HostScope {
    HostScope {
        run_id: None,
        actor,
        session: Some("terminal-10-1-1".into()),
        program: Some("claude".into()),
        standing_until_ms,
        // u64::MAX: "the door's generation now" (filled in by `write_call`); a test that wants a stale call sets a number
        door_gen: u64::MAX,
        ..scope("alpha")
    }
}

fn write_call(
    tools: &Arc<HostTools>,
    h: HostScope,
    file: &str,
) -> std::thread::JoinHandle<Result<Value, ToolError>> {
    let t = Arc::clone(tools);
    let file = file.to_string();
    let mut h = h;
    if h.door_gen == u64::MAX {
        h.door_gen = t.door_gen.load(std::sync::atomic::Ordering::SeqCst);
    }
    std::thread::spawn(move || {
        t.call(
            &agent(),
            Some(&h),
            "files_write",
            &json!({ "path": file, "content": "done" }),
            1_000,
        )
    })
}

fn wait_for_pending(tools: &Arc<HostTools>, n: usize) {
    for _ in 0..1000 {
        let b = tools.store.load().unwrap();
        if b.approvals
            .iter()
            .filter(|a| a.state == ApprovalState::Pending)
            .count()
            >= n
        {
            return;
        }
        std::thread::sleep(Duration::from_millis(10));
    }
    panic!("the call never asked");
}

/// When the door changes (turned off, standing ended early, another person), a terminal agent's call that is
/// waiting for a person is ended with its card. An answer given afterwards cannot run it. A run's own waiting call, on the
/// same box, is not the door's and is left alone.
#[test]
fn a_waiting_terminal_call_is_refused_when_the_door_ends_its_card_and_a_runs_call_is_not() {
    let mut r = rig();
    let tools = waiting_host(&mut r);
    let terminal = write_call(&tools, terminal_scope(ActorKind::Terminal, None), "t.txt");
    wait_for_pending(&tools, 1);
    let run = write_call(&tools, scope("alpha"), "run.txt");
    wait_for_pending(&tools, 2);
    assert_eq!(end_terms(&tools, 2_000), 1);
    let e = terminal.join().unwrap().unwrap_err();
    assert!(
        refused(e).contains("withdrawn"),
        "the call is refused by the gate"
    );
    assert!(
        !r.dir.path().join("work/alpha/t.txt").exists(),
        "nothing ran for the ended card"
    );
    // the card a person answers later has nothing left to approve
    let b = tools.store.load().unwrap();
    let card = b
        .approvals
        .iter()
        .find(|a| a.task_id.starts_with("tool:terminal-"))
        .unwrap();
    assert_eq!(card.state, ApprovalState::Denied);
    assert!(
        supervisor::decide(&mut b.clone(), &card.id, true, "ada", false, 3_000).is_err(),
        "an ended card cannot be approved"
    );
    // the run's call is still waiting and still works when answered
    let id = b
        .approvals
        .iter()
        .find(|a| a.state == ApprovalState::Pending)
        .unwrap()
        .id
        .clone();
    tools
        .store
        .update(|b| supervisor::decide(b, &id, true, "ada", false, 2_000))
        .unwrap()
        .unwrap();
    assert_eq!(run.join().unwrap().unwrap()["bytes"], 4);
    assert_eq!(end_terms(&tools, 4_000), 0, "nothing left to end");
}

/// The window after the sweep: a call that was admitted before the door changed but files its card AFTER the
/// sweep has nothing for the sweep to end. Approving that card must not run it; the call is refused and the card ends.
#[test]
fn a_card_filed_after_the_door_changed_is_refused_when_answered() {
    let mut r = rig();
    let tools = waiting_host(&mut r);
    let admitted_under = tools.door_gen.load(std::sync::atomic::Ordering::SeqCst);
    assert_eq!(end_terms(&tools, 1_500), 0, "nothing waiting yet");
    let mut h = terminal_scope(ActorKind::TerminalStanding, Some(1_000_000));
    h.door_gen = admitted_under;
    let late = write_call(&tools, h, "post-sweep.txt");
    wait_for_pending(&tools, 1);
    let id = tools.store.load().unwrap().approvals[0].id.clone();
    tools
        .store
        .update(|b| supervisor::decide(b, &id, true, "ada", false, 2_000))
        .unwrap()
        .unwrap();
    let e = late.join().unwrap().unwrap_err();
    assert!(refused(e).contains("withdrawn"));
    assert!(!r.dir.path().join("work/alpha/post-sweep.txt").exists());
    let b = tools.store.load().unwrap();
    assert_eq!(
        b.approvals[0].state,
        ApprovalState::Denied,
        "the card has a final state"
    );
    assert!(b.approvals[0].used);
}

/// The smaller window: a card answered just before the sweep is Approved, not Pending, so the sweep leaves it; the
/// call must still be refused when it wakes and sees the door has moved.
#[test]
fn a_card_approved_just_before_the_door_changed_does_not_run() {
    let mut r = rig();
    r.tools.poll = Duration::from_millis(400);
    let tools = waiting_host(&mut r);
    let call = write_call(
        &tools,
        terminal_scope(ActorKind::TerminalStanding, Some(1_000_000)),
        "just-before.txt",
    );
    wait_for_pending(&tools, 1);
    let id = tools.store.load().unwrap().approvals[0].id.clone();
    tools
        .store
        .update(|b| supervisor::decide(b, &id, true, "ada", false, 2_000))
        .unwrap()
        .unwrap();
    assert_eq!(
        end_terms(&tools, 2_001),
        0,
        "an approved card is not pending"
    );
    assert!(refused(call.join().unwrap().unwrap_err()).contains("withdrawn"));
    assert!(!r.dir.path().join("work/alpha/just-before.txt").exists());
    assert_eq!(
        tools.store.load().unwrap().approvals[0].state,
        ApprovalState::Denied
    );
}

/// A card approved while an earlier call of the same enrolment was still waiting is spent at the FIRST gate of the
/// next call, with no wait. A call that passed its token check before the door changed must not run on it.
#[test]
fn an_approved_card_spent_at_the_first_gate_does_not_run_for_a_call_the_door_has_outdated() {
    let mut r = rig();
    r.tools.ask_wait = Duration::from_millis(50);
    let tools = Arc::new(std::mem::replace(
        &mut r.tools,
        HostTools::new(
            TaskStore::new(r.dir.path().join("tasks.json")),
            Arc::new(LocalBackend::new(r.dir.path().join("work"))),
            Arc::new(Facts(vec![("alpha", false)])),
        ),
    ));
    let h = || {
        let mut h = terminal_scope(ActorKind::Terminal, None);
        h.door_gen = tools.door_gen.load(std::sync::atomic::Ordering::SeqCst);
        h
    };
    let args = json!({ "path": "first-gate.txt", "content": "done" });
    // the first call asks and gives up waiting ("still waiting"), as an agent's call does
    let first = tools.call(&agent(), Some(&h()), "files_write", &args, 1_000);
    assert!(first.is_err());
    let id = tools.store.load().unwrap().approvals[0].id.clone();
    tools
        .store
        .update(|b| supervisor::decide(b, &id, true, "ada", false, 2_000))
        .unwrap()
        .unwrap();
    // this call passed its token check under the old generation, and then the door changed
    let outdated = h();
    end_terms(&tools, 2_500);
    let e = tools
        .call(&agent(), Some(&outdated), "files_write", &args, 3_000)
        .unwrap_err();
    assert!(refused(e).contains("withdrawn"));
    assert!(!r.dir.path().join("work/alpha/first-gate.txt").exists());
    assert_eq!(
        tools.store.load().unwrap().approvals[0].state,
        ApprovalState::Denied
    );
}

/// The natural end: standing permission that runs out while a call waits is not honoured by a card answered
/// after it. The same card answered inside the window runs.
#[test]
fn a_standing_call_answered_after_the_standing_permission_ended_does_not_run() {
    let mut r = rig();
    let tools = waiting_host(&mut r);
    // the permission ends 50 ms of waiting after the call (the call's clock is 1_000 plus the time it has waited)
    let late = write_call(
        &tools,
        terminal_scope(ActorKind::TerminalStanding, Some(1_050)),
        "late.txt",
    );
    wait_for_pending(&tools, 1);
    std::thread::sleep(Duration::from_millis(120));
    let id = tools.store.load().unwrap().approvals[0].id.clone();
    tools
        .store
        .update(|b| supervisor::decide(b, &id, true, "ada", false, 2_000))
        .unwrap()
        .unwrap();
    let e = late.join().unwrap().unwrap_err();
    assert!(
        refused(e).contains("standing permission"),
        "the answer came after the end"
    );
    assert!(!r.dir.path().join("work/alpha/late.txt").exists());
    let ended = tools.store.load().unwrap().approvals[0].clone();
    assert_eq!(
        ended.state,
        ApprovalState::Denied,
        "the spent card is not left pending"
    );
    assert_eq!(
        ended.decided_by.as_deref(),
        Some(ozbox_core::tool_gate::DOOR_WITHDRAWN)
    );
    // the refused call's card is spent: the same call again, now as a plain terminal agent, asks a new question
    let again = write_call(
        &tools,
        terminal_scope(ActorKind::Terminal, None),
        "late.txt",
    );
    wait_for_pending(&tools, 1);
    assert!(
        !r.dir.path().join("work/alpha/late.txt").exists(),
        "the old card was not spent"
    );
    assert_eq!(end_terms(&tools, 5_000), 1);
    assert!(again.join().unwrap().is_err());
    // inside the window the same kind of call runs
    let early = write_call(
        &tools,
        terminal_scope(ActorKind::TerminalStanding, Some(1_000_000)),
        "early.txt",
    );
    wait_for_pending(&tools, 1);
    let id = tools
        .store
        .load()
        .unwrap()
        .approvals
        .iter()
        .find(|a| a.state == ApprovalState::Pending)
        .unwrap()
        .id
        .clone();
    tools
        .store
        .update(|b| supervisor::decide(b, &id, true, "ada", false, 2_000))
        .unwrap()
        .unwrap();
    assert_eq!(early.join().unwrap().unwrap()["bytes"], 4);
}

#[test]
fn a_call_that_asks_waits_for_the_person_and_runs_exactly_once() {
    let mut r = rig();
    r.tools.ask_wait = Duration::from_secs(10);
    let tools = Arc::new(std::mem::replace(
        &mut r.tools,
        HostTools::new(
            TaskStore::new(r.dir.path().join("tasks.json")),
            Arc::new(LocalBackend::new(r.dir.path().join("work"))),
            Arc::new(Facts(vec![("alpha", false)])),
        ),
    ));
    let t2 = Arc::clone(&tools);
    let h = std::thread::spawn(move || {
        t2.call(
            &agent(),
            Some(&scope("alpha")),
            "files_write",
            &json!({ "path": "out.txt", "content": "done" }),
            1_000,
        )
    });
    // the request appears in the inbox, naming the call
    let id = loop {
        let b = tools.store.load().unwrap();
        if let Some(a) = b.approvals.first() {
            assert_eq!(a.state, ApprovalState::Pending);
            assert!(a.action.starts_with("files.files_write:"), "{}", a.action);
            break a.id.clone();
        }
        std::thread::sleep(Duration::from_millis(10));
    };
    assert!(
        !r.dir.path().join("work/alpha/out.txt").exists(),
        "nothing happens before the answer"
    );
    tools
        .store
        .update(|b| supervisor::decide(b, &id, true, "ada", false, 2_000))
        .unwrap()
        .unwrap();
    let v = h.join().unwrap().unwrap();
    assert_eq!(v["bytes"], 4);
    assert_eq!(
        std::fs::read_to_string(r.dir.path().join("work/alpha/out.txt")).unwrap(),
        "done"
    );
    // the same call again asks again: an approval covers one call
    let again = tools.call(
        &agent(),
        Some(&scope("alpha")),
        "files_write",
        &json!({ "path": "out.txt", "content": "done" }),
        5_000,
    );
    assert!(again.is_err());
    assert_eq!(tools.store.load().unwrap().approvals.len(), 2);
}

#[test]
fn a_denied_call_is_not_done_and_says_so() {
    let mut r = rig();
    r.tools.ask_wait = Duration::from_secs(10);
    let tools = Arc::new(std::mem::replace(
        &mut r.tools,
        HostTools::new(
            TaskStore::new(r.dir.path().join("tasks.json")),
            Arc::new(LocalBackend::new(r.dir.path().join("work"))),
            Arc::new(Facts(vec![("alpha", false)])),
        ),
    ));
    let t2 = Arc::clone(&tools);
    let h = std::thread::spawn(move || {
        t2.call(
            &agent(),
            Some(&scope("alpha")),
            "git_commit",
            &json!({ "message": "x" }),
            1_000,
        )
    });
    let id = loop {
        if let Some(a) = tools.store.load().unwrap().approvals.first() {
            break a.id.clone();
        }
        std::thread::sleep(Duration::from_millis(10));
    };
    tools
        .store
        .update(|b| supervisor::decide(b, &id, false, "ada", false, 2_000))
        .unwrap()
        .unwrap();
    let e = h.join().unwrap().unwrap_err();
    assert!(refused(e).contains("said no"));
}

#[test]
fn a_call_still_waiting_when_the_wait_ends_tells_the_agent_to_come_back() {
    let r = rig();
    let e = call(
        &r,
        "alpha",
        "files_write",
        json!({ "path": "a.txt", "content": "x" }),
    )
    .unwrap_err();
    let m = refused(e);
    assert!(
        m.contains("call this tool again") && m.contains("a1"),
        "{m}"
    );
    // the repeat waits on the same request rather than asking again
    let e = call(
        &r,
        "alpha",
        "files_write",
        json!({ "path": "a.txt", "content": "x" }),
    )
    .unwrap_err();
    assert!(refused(e).contains("a1"));
    assert_eq!(r.tools.store.load().unwrap().approvals.len(), 1);
}

// ---- git -----------------------------------------------------------------------------------------------------------------

#[test]
fn a_push_to_a_protected_branch_asks_even_in_auto_and_needs_a_rule() {
    let r = rig();
    allow_all(&r);
    let e = call(&r, "alpha", "git_push", json!({ "branch": "main" })).unwrap_err();
    assert!(refused(e).contains("approve this first"));
    let book = r.tools.store.load().unwrap();
    assert!(
        book.approvals[0].action.contains("a protected branch"),
        "{}",
        book.approvals[0].action
    );
    // an ordinary branch goes ahead in auto (git itself fails here: there is no repository, and that is data)
    let v = call(&r, "alpha", "git_push", json!({ "branch": "wip/fix" })).unwrap();
    assert!(v["exit_code"].as_i64().is_some_and(|c| c != 0));
    // a rule that allows main is what lets it through: the most specific rule decides
    r.tools
        .store
        .update(|b| {
            let mut allow = deny_tool("git_push");
            allow.effect = Effect::Allow;
            allow.path = Some("main".into());
            b.perms
                .apply_settings(PermSettings {
                    default_mode: Mode::Ask,
                    modes: vec![],
                    rules: vec![allow],
                    browser_hosts: vec![],
                })
                .unwrap();
        })
        .unwrap();
    let v = call(&r, "alpha", "git_push", json!({ "branch": "main" })).unwrap();
    assert!(v["exit_code"].is_i64());
    // a deny rule on a pattern wins over it
    r.tools
        .store
        .update(|b| {
            let mut allow = deny_tool("git_push");
            allow.effect = Effect::Allow;
            let mut deny = deny_tool("git_push");
            deny.path = Some("release/*".into());
            b.perms
                .apply_settings(PermSettings {
                    default_mode: Mode::Auto,
                    modes: vec![],
                    rules: vec![allow, deny],
                    browser_hosts: vec![],
                })
                .unwrap();
        })
        .unwrap();
    let e = call(&r, "alpha", "git_push", json!({ "branch": "release/1" })).unwrap_err();
    assert!(refused(e).contains("forbids"));
}

#[test]
fn git_reads_run_and_bad_arguments_are_refused() {
    let r = rig();
    allow_all(&r);
    let v = call(&r, "alpha", "shell", json!({ "command": "git init -q . && git config user.email a@b.c && git config user.name a && echo x > f && git add f" })).unwrap();
    assert_eq!(v["exit_code"], 0, "{v}");
    let st = call(&r, "alpha", "git_status", json!({})).unwrap();
    assert!(st["output"].as_str().unwrap().contains("A  f"), "{st}");
    let c = call(&r, "alpha", "git_commit", json!({ "message": "first" })).unwrap();
    assert_eq!(c["exit_code"], 0, "{c}");
    let lg = call(&r, "alpha", "git_log", json!({ "limit": 5 })).unwrap();
    assert!(lg["output"].as_str().unwrap().contains("first"));
    assert!(call(&r, "alpha", "git_branch", json!({})).is_ok());
    assert!(call(&r, "alpha", "git_branch", json!({ "create": "feature/x" })).is_ok());
    for bad in [
        json!({ "create": "-x" }),
        json!({ "create": "a..b" }),
        json!({ "create": "a b" }),
    ] {
        assert!(matches!(
            call(&r, "alpha", "git_branch", bad),
            Err(ToolError::Invalid(_))
        ));
    }
    assert!(matches!(
        call(&r, "alpha", "git_push", json!({ "branch": "--force" })),
        Err(ToolError::Invalid(_))
    ));
    assert!(matches!(
        call(
            &r,
            "alpha",
            "git_push",
            json!({ "branch": "x", "remote": "-o" })
        ),
        Err(ToolError::Invalid(_))
    ));
    assert!(matches!(
        call(&r, "alpha", "git_diff", json!({ "paths": ["../x"] })),
        Err(ToolError::Refused(_))
    ));
    assert!(matches!(
        call(&r, "alpha", "git_log", json!({ "limit": 1000 })),
        Err(ToolError::Invalid(_))
    ));
    assert!(matches!(
        call(&r, "alpha", "git_commit", json!({})),
        Err(ToolError::Invalid(_))
    ));
}

// ---- production ----------------------------------------------------------------------------------------------------------

#[test]
fn production_is_refused_without_a_grant_and_asks_nobody() {
    let r = rig();
    allow_all(&r);
    for (tool, a) in [
        ("shell", json!({ "command": "echo hi" })),
        ("files_write", json!({ "path": "a", "content": "x" })),
        ("git_commit", json!({ "message": "m" })),
    ] {
        let e = call(&r, "prod", tool, a).unwrap_err();
        assert!(refused(e).contains("production"), "{tool}");
    }
    assert!(r.tools.store.load().unwrap().approvals.is_empty());
    // reading production needs no grant
    assert!(call(&r, "prod", "files_list", json!({})).is_ok());
    // a grant for the box lets a write through, counted and recorded
    r.tools
        .store
        .update(|b| {
            b.perms
                .create_grant(
                    NewGrant {
                        granted_by: "ada".into(),
                        scope: Scope::Box,
                        scope_id: "prod".into(),
                        actions: vec!["tool.call".into()],
                        reason: "ship the fix".into(),
                        minutes: 30,
                        factor: SecondFactor::StepUp,
                        allow_unattended: false,
                        max_uses: None,
                    },
                    500,
                )
                .unwrap();
        })
        .unwrap();
    assert!(call(&r, "prod", "shell", json!({ "command": "echo hi" })).is_ok());
    let book = r.tools.store.load().unwrap();
    assert_eq!(book.perms.grants[0].uses, 1);
    // a schedule does not inherit it
    let sched = HostScope {
        actor: ActorKind::Schedule,
        ..scope("prod")
    };
    let e = r
        .tools
        .call(
            &agent(),
            Some(&sched),
            "shell",
            &json!({ "command": "echo hi" }),
            1_000,
        )
        .unwrap_err();
    assert!(refused(e).contains("production"));
}

#[test]
fn plan_only_refuses_writes_and_allows_reads() {
    let r = rig();
    r.tools
        .store
        .update(|b| b.perms.default_mode = Mode::PlanOnly)
        .unwrap();
    assert!(
        refused(call(&r, "alpha", "shell", json!({ "command": "echo hi" })).unwrap_err())
            .contains("plan only")
    );
    assert!(call(&r, "alpha", "files_list", json!({})).is_ok());
}

// ---- audit ---------------------------------------------------------------------------------------------------------------

#[test]
fn every_call_is_in_the_chain_with_tool_server_and_decision_and_never_arguments_or_output() {
    let r = rig();
    allow_all(&r);
    call(
        &r,
        "alpha",
        "files_write",
        json!({ "path": "customers.csv", "content": "ssn,123-45-6789" }),
    )
    .unwrap();
    call(
        &r,
        "alpha",
        "shell",
        json!({ "command": "echo SENTINEL_OUTPUT_9f3 && cat customers.csv" }),
    )
    .unwrap();
    let _ = call(
        &r,
        "alpha",
        "shell",
        json!({ "command": "sudo SENTINEL_ARG_77" }),
    );
    let _ = call(
        &r,
        "prod",
        "shell",
        json!({ "command": "echo SENTINEL_PROD_12" }),
    );
    let log = r.tools.store.audit_log();
    let text = std::fs::read_to_string(log.path()).unwrap();
    for needle in [
        "tool=files_write",
        "server=files",
        "tool=shell",
        "server=shell",
        "writes=yes",
        "permission.allow",
        "permission.ask",
        "permission.deny",
        "tool.completed",
        "production_no_grant",
    ] {
        assert!(text.contains(needle), "missing {needle}");
    }
    for leaked in [
        "SENTINEL_OUTPUT_9f3",
        "SENTINEL_ARG_77",
        "SENTINEL_PROD_12",
        "customers",
        "123-45-6789",
    ] {
        assert!(!text.contains(leaked), "the chain holds {leaked}");
    }
    assert!(log.verify().unwrap().ok);
}

// ---- the browser ---------------------------------------------------------------------------------------------------------

#[test]
fn the_browser_opens_only_loopback_and_listed_hosts() {
    let allowed = vec!["example.com".to_string(), "*.docs.example.org".to_string()];
    for u in [
        "http://localhost:3000/",
        "https://127.0.0.1/x?y=1",
        "http://[::1]:8080/",
        "https://example.com/a",
        "https://a.docs.example.org/",
        "http://LOCALHOST/",
    ] {
        assert!(check_url(u, &allowed).is_ok(), "{u}");
    }
    for u in [
        "http://evil.com/",
        "https://localhost.evil.com/",
        "http://localhost@evil.com/",
        "http://user:pw@localhost/",
        "file:///etc/passwd",
        "ftp://example.com/",
        "javascript:alert(1)",
        "http://169.254.169.254/latest/meta-data",
        "http://10.0.0.5/",
        "https://docs.example.org/",
        "https://example.com.evil.com/",
        "http://localhost /x",
        "",
        "http://",
    ] {
        assert!(check_url(u, &allowed).is_err(), "{u}");
    }
}

// ---- a recording backend: the exact argv of Staging reads, CI and the browser ------------------------------------------

struct Rec {
    seen: Mutex<Vec<Vec<String>>>,
    out: Mutex<Vec<ExecOut>>,
}

impl Rec {
    fn new(out: Vec<ExecOut>) -> Arc<Rec> {
        Arc::new(Rec {
            seen: Mutex::new(vec![]),
            out: Mutex::new(out),
        })
    }
    fn argv(&self) -> Vec<Vec<String>> {
        self.seen.lock().unwrap().clone()
    }
}

impl HostBackend for Rec {
    fn resolve(&self, _: &str, requested: &str) -> Result<backend::Resolved, String> {
        let parts = paths::normalize(requested)?;
        Ok(backend::Resolved {
            abs: paths::join(&parts),
            rel: paths::rel(&parts),
            parts,
        })
    }
    fn exec(&self, _: &str, req: &ExecReq) -> Result<ExecOut, String> {
        self.seen.lock().unwrap().push(req.argv.clone());
        let mut o = self.out.lock().unwrap();
        Ok(if o.is_empty() {
            ExecOut {
                code: Some(0),
                ..Default::default()
            }
        } else {
            o.remove(0)
        })
    }
    fn read(&self, _: &str, _: &str, _: usize) -> Result<(Vec<u8>, bool), String> {
        Err("no".into())
    }
    fn write(&self, _: &str, _: &str, _: &[u8], _: bool) -> Result<(), String> {
        Err("no".into())
    }
    fn list(&self, _: &str, _: &str, _: usize) -> Result<Vec<backend::Entry>, String> {
        Err("no".into())
    }
    fn search(&self, _: &str, _: &str, _: &str, _: usize) -> Result<Vec<backend::Hit>, String> {
        Err("no".into())
    }
}

fn ok(out: &str) -> ExecOut {
    ExecOut {
        code: Some(0),
        output: out.into(),
        ..Default::default()
    }
}

#[test]
fn staging_reads_go_through_a_declared_named_command_and_never_production() {
    let rec = Rec::new(vec![ok("rows: 3")]);
    let r = rig_with(rec.clone());
    allow_all(&r);
    let v = call(
        &r,
        "alpha",
        "staging_read",
        json!({ "project": "shop", "command": "count_orders", "args": ["--since", "1d"] }),
    )
    .unwrap();
    assert_eq!(v["output"], "rows: 3");
    let seen = rec.argv();
    assert_eq!(
        seen[0],
        [
            "ozbox",
            "env",
            "run",
            "--project",
            "shop",
            "--env",
            "staging",
            "--named",
            "count_orders",
            "--",
            "--since",
            "1d"
        ]
    );
    // a production environment is refused by the engine (no grant), whatever the mode
    let e = call(
        &r,
        "alpha",
        "staging_read",
        json!({ "project": "shop", "command": "count_orders", "env": "production" }),
    )
    .unwrap_err();
    assert!(refused(e).contains("production"));
    assert_eq!(rec.argv().len(), 1, "nothing ran");
    for bad in [
        json!({ "project": "../x", "command": "c" }),
        json!({ "project": "p", "command": "c", "env": "qa" }),
        json!({ "project": "p" }),
    ] {
        assert!(matches!(
            call(&r, "alpha", "staging_read", bad),
            Err(ToolError::Invalid(_))
        ));
    }
    // even with a grant for the box, production is still never read through this tool
    r.tools
        .store
        .update(|b| {
            b.perms
                .create_grant(
                    NewGrant {
                        granted_by: "ada".into(),
                        scope: Scope::Box,
                        scope_id: "alpha".into(),
                        actions: vec!["*".into()],
                        reason: "debug the order job".into(),
                        minutes: 30,
                        factor: SecondFactor::StepUp,
                        allow_unattended: false,
                        max_uses: None,
                    },
                    500,
                )
                .unwrap();
        })
        .unwrap();
    let e = call(
        &r,
        "alpha",
        "staging_read",
        json!({ "project": "shop", "command": "c", "env": "production" }),
    )
    .unwrap_err();
    assert!(refused(e).contains("never read"));
}

#[test]
fn ci_uses_the_providers_cli_and_only_for_github_and_a_rerun_is_a_write() {
    let rec = Rec::new(vec![
        ok("git@github.com:o/r.git\n"),
        ok(r#"[{"databaseId":7,"status":"completed","conclusion":"failure"}]"#),
        ok("git@gitlab.com:o/r.git\n"),
    ]);
    let r = rig_with(rec.clone());
    allow_all(&r);
    let v = call(&r, "alpha", "ci_status", json!({ "limit": 3 })).unwrap();
    assert_eq!(v["runs"][0]["databaseId"], 7);
    assert_eq!(rec.argv()[1][..4], ["gh", "run", "list", "--limit"]);
    let e = call(&r, "alpha", "ci_logs", json!({ "run_id": "7" })).unwrap_err();
    assert!(matches!(e, ToolError::Failed(m) if m.contains("GitHub")));
    assert!(matches!(
        call(&r, "alpha", "ci_logs", json!({ "run_id": "7; rm -rf /" })),
        Err(ToolError::Invalid(_))
    ));
    // a re-run is a write: asked about in the default mode, a read is not
    let r2 = rig_with(Rec::new(vec![]));
    assert!(matches!(
        call(&r2, "alpha", "ci_status", json!({})),
        Err(ToolError::Failed(_)) | Ok(_)
    ));
    let e = call(&r2, "alpha", "ci_rerun", json!({ "run_id": "9" })).unwrap_err();
    assert!(refused(e).contains("approve this first"));
}

#[test]
fn the_browser_fetches_with_curl_on_the_box_without_redirects_and_reports_the_status() {
    let rec = Rec::new(vec![ok("<h1>hi</h1>\n200")]);
    let r = rig_with(rec.clone());
    let v = call(
        &r,
        "alpha",
        "browser_fetch",
        json!({ "url": "http://localhost:3000/" }),
    )
    .unwrap();
    assert_eq!(v["status"], 200);
    assert_eq!(v["body"], "<h1>hi</h1>");
    let argv = &rec.argv()[0];
    assert!(
        argv.contains(&"--max-redirs".to_string()) && argv.contains(&"--max-filesize".to_string())
    );
    assert_eq!(argv.last().unwrap(), "http://localhost:3000/");
    assert!(matches!(
        call(
            &r,
            "alpha",
            "browser_fetch",
            json!({ "url": "https://evil.example/" })
        ),
        Err(ToolError::Refused(_))
    ));
    // a host the person added is allowed
    r.tools
        .store
        .update(|b| b.perms.browser_hosts = vec!["example.com".into()])
        .unwrap();
    assert!(call(
        &r,
        "alpha",
        "browser_fetch",
        json!({ "url": "https://example.com/x" })
    )
    .is_ok());
}

// ---- the box, through its daemon ------------------------------------------------------------------------------------------

struct Script {
    launched: Vec<Launch>,
    chunks: Vec<LogChunk>,
    stopped: bool,
}

struct ScriptedTransport(Arc<Mutex<Script>>);

impl RunTransport for ScriptedTransport {
    fn launch(&mut self, _: &str, l: &Launch) -> Result<String, String> {
        self.0.lock().unwrap().launched.push(l.clone());
        Ok("run1".into())
    }
    fn read_log(&mut self, _: &str, _: &str, from: u64) -> Result<LogChunk, String> {
        let mut s = self.0.lock().unwrap();
        Ok(if s.chunks.is_empty() {
            LogChunk {
                bytes: vec![],
                next: from,
                exited: None,
            }
        } else {
            s.chunks.remove(0)
        })
    }
    fn stop(&mut self, _: &str, _: &str) -> Result<(), String> {
        self.0.lock().unwrap().stopped = true;
        Ok(())
    }
    fn send(&mut self, _: &str, _: &str, _: &str, _: bool) -> Result<(), String> {
        Ok(())
    }
}

fn daemon(chunks: Vec<LogChunk>) -> (DaemonBackend, Arc<Mutex<Script>>) {
    let st = Arc::new(Mutex::new(Script {
        launched: vec![],
        chunks,
        stopped: false,
    }));
    (
        DaemonBackend::new(Box::new(ScriptedTransport(Arc::clone(&st))))
            .with_poll(Duration::from_millis(1)),
        st,
    )
}

fn chunk(text: &str, exited: Option<i32>) -> LogChunk {
    LogChunk {
        bytes: text.as_bytes().to_vec(),
        next: 0,
        exited,
    }
}

#[test]
fn the_daemon_backend_runs_one_short_run_per_operation_and_collects_the_log() {
    let (be, st) = daemon(vec![chunk("hel", None), chunk("lo\n", Some(0))]);
    let o = be
        .exec(
            "alpha",
            &ExecReq {
                argv: vec!["echo".into(), "hello".into()],
                cwd: "/work/x".into(),
                timeout: Duration::from_secs(30),
                cap: 100,
                stdin: None,
            },
        )
        .unwrap();
    assert_eq!(
        (o.code, o.output.as_str(), o.timed_out),
        (Some(0), "hello\n", false)
    );
    let l = &st.lock().unwrap().launched[0];
    assert_eq!(l.cwd.as_deref(), Some("/work/x"));
    assert_eq!(l.max_runtime_s, Some(30));
    assert!(l.env.is_empty(), "no environment is handed over");
    assert_eq!(l.labels.get("ozbox.tool").map(String::as_str), Some("1"));
}

#[test]
fn the_daemon_backend_caps_output_and_stops_a_run_that_outlives_its_time() {
    let (be, _) = daemon(vec![chunk(&"a".repeat(500), Some(0))]);
    let o = be
        .exec(
            "alpha",
            &ExecReq {
                argv: vec!["x".into()],
                cwd: "/work".into(),
                timeout: Duration::from_secs(5),
                cap: 100,
                stdin: None,
            },
        )
        .unwrap();
    assert!(o.truncated && o.output.len() == 100);
    // never exits: after the time (plus its allowance) it is stopped and reported as timed out
    let (be, st) = daemon(vec![]);
    let t = std::time::Instant::now();
    let o = be.exec(
        "alpha",
        &ExecReq {
            argv: vec!["x".into()],
            cwd: "/work".into(),
            timeout: Duration::from_millis(1),
            cap: 100,
            stdin: None,
        },
    );
    assert!(t.elapsed() < Duration::from_secs(10));
    let o = o.unwrap();
    assert!(o.timed_out && o.code.is_none());
    assert!(st.lock().unwrap().stopped);
}

#[test]
fn the_daemon_backend_resolves_symlinks_on_the_box_and_refuses_a_path_that_ends_outside_work() {
    let (be, _) = daemon(vec![chunk("/etc/shadow\n", Some(0))]);
    assert!(be
        .resolve("alpha", "link/x")
        .unwrap_err()
        .contains("inside /work"));
    let (be, st) = daemon(vec![chunk("/work/src/a.rs\n", Some(0))]);
    let r = be.resolve("alpha", "./src/../src/a.rs").unwrap();
    assert_eq!(
        (r.abs.as_str(), r.rel.as_str()),
        ("/work/src/a.rs", "src/a.rs")
    );
    assert_eq!(
        st.lock().unwrap().launched[0].argv,
        ["realpath", "-m", "--", "/work/src/a.rs"]
    );
    // a lexical escape never reaches the box
    let (be, st) = daemon(vec![]);
    assert!(be.resolve("alpha", "../x").is_err());
    assert!(st.lock().unwrap().launched.is_empty());
}

#[test]
fn the_daemon_backend_writes_through_standard_input_never_an_argument() {
    let (be, st) = daemon(vec![chunk("", Some(0))]);
    be.write("alpha", "/work/a.txt", b"SENTINEL-CONTENT", false)
        .unwrap();
    let l = &st.lock().unwrap().launched[0];
    assert_eq!(l.stdin.as_deref(), Some("SENTINEL-CONTENT"));
    assert!(!l.argv.iter().any(|a| a.contains("SENTINEL")));
}

// ---- through the MCP server ----------------------------------------------------------------------------------------------

fn mcp_request(port: u16, token: &str, method: &str, params: Value) -> crate::broker::ProxyRequest {
    crate::broker::ProxyRequest {
        method: "POST".into(),
        path: "/mcp".into(),
        headers: vec![
            ("Host".into(), format!("127.0.0.1:{port}")),
            ("Authorization".into(), format!("Bearer {token}")),
        ],
        body: json!({ "jsonrpc": "2.0", "id": 1, "method": method, "params": params })
            .to_string()
            .into_bytes(),
    }
}

#[test]
fn a_run_on_a_box_sees_the_host_tools_over_mcp_and_a_call_is_decided_and_recorded() {
    let r = rig();
    allow_all(&r);
    let store = r.tools.store.clone();
    let be: Arc<dyn HostBackend> = Arc::new(LocalBackend::new(r.dir.path().join("work")));
    let orch = crate::orch_tools::Tools::new(store.clone(), Arc::new(NoOps));
    let host = HostTools::new(store.clone(), be, Arc::new(Facts(vec![("alpha", false)])));
    let server = McpServer::new(Arc::new(crate::mcp::Composite { orch, host }), 7777);
    let token = server
        .issue_host(agent(), Some(scope("alpha")), Some("t1"), 0, 100_000)
        .unwrap()
        .token;
    let list = server.handle(&mcp_request(7777, &token, "tools/list", json!({})), 1);
    let v: Value = serde_json::from_slice(&list.body).unwrap();
    let names: Vec<&str> = v["result"]["tools"]
        .as_array()
        .unwrap()
        .iter()
        .map(|t| t["name"].as_str().unwrap())
        .collect();
    assert!(
        names.contains(&"shell") && names.contains(&"git_push") && names.contains(&"staging_read"),
        "{names:?}"
    );
    assert!(
        !names.contains(&"task_start"),
        "a plain run has no orchestration tools"
    );
    let call = server.handle(
        &mcp_request(
            7777,
            &token,
            "tools/call",
            json!({ "name": "shell", "arguments": { "command": "echo over-mcp" } }),
        ),
        2,
    );
    let v: Value = serde_json::from_slice(&call.body).unwrap();
    assert_eq!(v["result"]["isError"], false, "{v}");
    assert_eq!(v["result"]["structuredContent"]["output"], "over-mcp\n");
    let words: Vec<String> = store
        .load()
        .unwrap()
        .audit
        .iter()
        .map(|a| a.action.clone())
        .collect();
    assert!(
        words.contains(&"permission.allow".to_string())
            && words.contains(&"tool.completed".to_string())
    );
    // an unknown tool is a protocol error, not a quiet success
    let bad = server.handle(
        &mcp_request(
            7777,
            &token,
            "tools/call",
            json!({ "name": "format_disk", "arguments": {} }),
        ),
        3,
    );
    let v: Value = serde_json::from_slice(&bad.body).unwrap();
    assert_eq!(v["error"]["code"], -32602);
    // a refusal is an error result the agent can read
    store
        .update(|b| b.perms.default_mode = Mode::PlanOnly)
        .unwrap();
    let no = server.handle(
        &mcp_request(
            7777,
            &token,
            "tools/call",
            json!({ "name": "shell", "arguments": { "command": "echo x" } }),
        ),
        4,
    );
    let v: Value = serde_json::from_slice(&no.body).unwrap();
    assert_eq!(v["result"]["isError"], true);
    assert!(v["result"]["content"][0]["text"]
        .as_str()
        .unwrap()
        .contains("plan only"));
}

struct NoOps;

impl crate::orch_tools::BoxOps for NoOps {
    fn list(&self) -> Result<Vec<Value>, String> {
        Ok(vec![])
    }
    fn plan(&self, _: Value) -> Result<Value, String> {
        Err("no".into())
    }
    fn apply(&self, _: &str, _: &Value) -> Result<Value, String> {
        Err("no".into())
    }
}

#[test]
fn the_orchestration_tools_are_decided_and_recorded_too_and_a_rule_can_stop_one() {
    let r = rig();
    let store = r.tools.store.clone();
    let orch = crate::orch_tools::Tools::new(store.clone(), Arc::new(NoOps));
    let s = Session {
        person: "ada".into(),
        role: Role::Person,
    };
    // read tool: allowed by default and recorded
    assert!(orch.call(&s, "fleet_boxes", &json!({}), 1).is_ok());
    let book = store.load().unwrap();
    let rec = book
        .audit
        .iter()
        .find(|a| a.action == "permission.allow")
        .unwrap();
    assert!(
        rec.detail.contains("tool=fleet_boxes")
            && rec.detail.contains("server=orchestration")
            && rec.detail.contains("writes=no")
    );
    // a deny rule stops even a built-in tool
    store
        .update(|b| {
            b.perms
                .apply_settings(PermSettings {
                    default_mode: Mode::Ask,
                    modes: vec![],
                    rules: vec![deny_tool("box_pause")],
                    browser_hosts: vec![],
                })
                .unwrap()
        })
        .unwrap();
    let e = orch
        .call(&s, "box_pause", &json!({ "box": "x" }), 2)
        .unwrap_err();
    assert!(refused(e).contains("forbids"));
    // plan-only refuses its writes
    store
        .update(|b| {
            b.perms
                .apply_settings(PermSettings {
                    default_mode: Mode::PlanOnly,
                    modes: vec![],
                    rules: vec![],
                    browser_hosts: vec![],
                })
                .unwrap()
        })
        .unwrap();
    assert!(refused(
        orch.call(&s, "box_clone", &json!({ "to": "y" }), 3)
            .unwrap_err()
    )
    .contains("plan only"));
}
