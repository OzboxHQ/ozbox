//! The engine conformance suite, the cross-provider collaboration over the hub, and the sentinels (ADR 0056).
//!
//! Every adapter is driven by a fake of its program that speaks that program's documented output format, through the same
//! transport seam the box daemon fills. No real model is called and nothing touches a network. One test runs real processes:
//! small shell scripts named `claude`, `codex` and `gemini` that check their own argv, environment and standard input the way
//! the adapters must use them.

#![allow(clippy::unwrap_used)]

use std::collections::{BTreeMap, VecDeque};
use std::sync::{Arc, Mutex};

use super::*;
use crate::agent_engine::FakeEngine;
use crate::claude_code::{ClaudeCodeEngine, Launch, LogChunk, RunTransport, MAX_PROMPT_BYTES};
use crate::hub::engine::{Hub, HubState, RosterEntry};
use crate::hub::mem::{MemTransport, TestKey, TestRoster, TestSealer};
use crate::hub::wire::{Ext, Transport, PROFILE};
use crate::hub::worker::{WorkerEnd, WorkerState};

// ---- a fake of each program --------------------------------------------------------------------------------------------

/// A command line a tool ran. It holds a key shape (built in two pieces so the source holds none) so a test can see that tool
/// input never leaves an adapter.
const TOOL_INPUT: &str = concat!("echo gh", "p_TOOLINPUTSENTINEL0123456789abcd");

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Program {
    Claude,
    Codex,
    Gemini,
}

impl Program {
    fn engine_id(self) -> &'static str {
        match self {
            Program::Claude => "claude-code",
            Program::Codex => "codex",
            Program::Gemini => "gemini-cli",
        }
    }
    fn binary(self) -> &'static str {
        match self {
            Program::Claude => "claude",
            Program::Codex => "codex",
            Program::Gemini => "gemini",
        }
    }
    /// The variable the Models routing hands this engine its per-run token in.
    fn token_var(self) -> &'static str {
        match self {
            Program::Claude => "ANTHROPIC_API_KEY",
            Program::Codex => "OPENAI_API_KEY",
            Program::Gemini => "GEMINI_API_KEY",
        }
    }
    fn session(self) -> &'static str {
        match self {
            Program::Claude => "cc-session-1",
            Program::Codex => "cx-thread-1",
            Program::Gemini => "gm-session-1",
        }
    }
    fn make(self, t: FakeCli) -> Box<dyn AgentEngine> {
        match self {
            Program::Claude => Box::new(ClaudeCodeEngine::new(t)),
            Program::Codex => Box::new(crate::codex_cli::engine(t)),
            Program::Gemini => Box::new(crate::gemini_cli::engine(t)),
        }
    }
}

#[derive(Clone, Debug)]
enum Script {
    /// The turn ends well with this final text.
    Ok(&'static str),
    /// The provider refuses (a rate limit).
    Refused,
    /// The agent fails at its task.
    Failed,
}

/// Output in each program's own format. `conversation` is Claude Code's kept-open mode, where a turn ends without the
/// process ending.
fn transcript(p: Program, s: &Script, conversation: bool) -> (String, Option<i32>) {
    let lines: Vec<String> = match (p, s) {
        (Program::Claude, Script::Ok(text)) => vec![
            format!(r#"{{"type":"system","subtype":"init","session_id":"{}"}}"#, p.session()),
            format!(
                r#"{{"type":"assistant","message":{{"id":"m1","model":"claude-model-x","content":[{{"type":"text","text":"Working on it"}},{{"type":"tool_use","name":"Bash","input":{{"command":"{TOOL_INPUT}"}}}}],"usage":{{"input_tokens":100,"output_tokens":20}}}}}}"#
            ),
            format!(
                r#"{{"type":"result","subtype":"success","is_error":false,"result":"{text}","total_cost_usd":0.05,"session_id":"{}"}}"#,
                p.session()
            ),
        ],
        (Program::Claude, Script::Refused) => vec![
            r#"{"type":"result","subtype":"error_during_execution","is_error":true,"result":"API Error: 429 rate limit"}"#.into(),
        ],
        (Program::Claude, Script::Failed) => vec![
            r#"{"type":"result","subtype":"error_during_execution","is_error":true,"result":"the tests still fail"}"#.into(),
        ],
        (Program::Codex, Script::Ok(text)) => vec![
            format!(r#"{{"type":"thread.started","thread_id":"{}"}}"#, p.session()),
            r#"{"type":"turn.started"}"#.into(),
            format!(
                r#"{{"type":"item.started","item":{{"id":"item_1","type":"command_execution","command":"{TOOL_INPUT}","status":"in_progress"}}}}"#
            ),
            format!(
                r#"{{"type":"item.completed","item":{{"id":"item_1","type":"command_execution","command":"{TOOL_INPUT}","aggregated_output":"{TOOL_INPUT}","exit_code":0,"status":"completed"}}}}"#
            ),
            r#"{"type":"item.completed","item":{"id":"item_2","type":"file_change","status":"completed"}}"#.into(),
            format!(r#"{{"type":"item.completed","item":{{"id":"item_3","type":"agent_message","text":"{text}"}}}}"#),
            r#"{"type":"turn.completed","usage":{"input_tokens":1000,"cached_input_tokens":400,"output_tokens":50,"reasoning_output_tokens":0}}"#.into(),
        ],
        (Program::Codex, Script::Refused) => vec![
            format!(r#"{{"type":"thread.started","thread_id":"{}"}}"#, p.session()),
            r#"{"type":"error","message":"Reconnecting... 1/5"}"#.into(),
            r#"{"type":"turn.failed","error":{"message":"stream error: 429 Too Many Requests"}}"#.into(),
        ],
        (Program::Codex, Script::Failed) => vec![
            r#"{"type":"turn.failed","error":{"message":"the tests still fail"}}"#.into(),
        ],
        (Program::Gemini, Script::Ok(text)) => {
            let (a, b) = text.split_at(text.len() / 2);
            vec![
                format!(
                    r#"{{"type":"init","timestamp":"2026-11-17T00:00:00Z","session_id":"{}","model":"gemini-model-x"}}"#,
                    p.session()
                ),
                r#"{"type":"message","role":"user","content":"the task"}"#.into(),
                format!(
                    r#"{{"type":"tool_use","tool_name":"run_shell_command","tool_id":"t1","parameters":{{"command":"{TOOL_INPUT}"}}}}"#
                ),
                format!(r#"{{"type":"tool_result","tool_id":"t1","status":"success","output":"{TOOL_INPUT}"}}"#),
                format!(r#"{{"type":"message","role":"assistant","content":"{a}","delta":true}}"#),
                format!(r#"{{"type":"message","role":"assistant","content":"{b}","delta":true}}"#),
                r#"{"type":"result","status":"success","stats":{"total_tokens":1050,"input_tokens":1000,"output_tokens":50,"duration_ms":10,"tool_calls":1}}"#.into(),
            ]
        }
        (Program::Gemini, Script::Refused) => vec![
            r#"{"type":"result","status":"error","error":{"type":"API","message":"429 quota exceeded"}}"#.into(),
        ],
        (Program::Gemini, Script::Failed) => vec![
            r#"{"type":"result","status":"error","error":{"type":"Tool","message":"the tests still fail"}}"#.into(),
        ],
    };
    let mut out = lines.join("\n");
    out.push('\n');
    let exit = match (p, s, conversation) {
        (Program::Claude, Script::Ok(_), true) => None,
        (_, Script::Ok(_), _) => Some(0),
        _ => Some(1),
    };
    (out, exit)
}

#[derive(Default)]
struct FakeRun {
    log: Vec<u8>,
    exit: Option<i32>,
    stdin: String,
    keep_open: bool,
}

#[derive(Default)]
struct CliState {
    program: Option<Program>,
    launches: Vec<Launch>,
    runs: Vec<FakeRun>,
    /// What each next turn prints: taken by a launch, or by a new message on a kept-open input.
    scripts: VecDeque<Script>,
    stopped: Vec<String>,
    /// (run, text, close) of every piece sent after the launch.
    sent: Vec<(String, String, bool)>,
}

/// The transport, playing the program: every launch is checked to start the right program and answered with its script.
#[derive(Clone, Default)]
struct FakeCli(Arc<Mutex<CliState>>);

impl FakeCli {
    fn new(p: Program, scripts: &[Script]) -> Self {
        let t = FakeCli::default();
        {
            let mut s = t.0.lock().unwrap();
            s.program = Some(p);
            s.scripts = scripts.iter().cloned().collect();
        }
        t
    }
    fn st(&self) -> std::sync::MutexGuard<'_, CliState> {
        self.0.lock().unwrap()
    }
}

fn run_index(id: &str) -> usize {
    id.trim_start_matches("run-").parse::<usize>().unwrap()
}

impl RunTransport for FakeCli {
    fn launch(&mut self, _box: &str, l: &Launch) -> Result<String, String> {
        let mut s = self.st();
        let p = s.program.unwrap();
        assert_eq!(l.argv[4], p.binary(), "the adapter starts its own program");
        let interactive_claude =
            p == Program::Claude && l.argv.iter().any(|a| a == "--input-format");
        let script = s.scripts.pop_front().unwrap_or(Script::Ok("done"));
        let (log, exit) = transcript(p, &script, interactive_claude);
        s.launches.push(l.clone());
        s.runs.push(FakeRun {
            log: log.into_bytes(),
            exit,
            stdin: l.stdin.clone().unwrap_or_default(),
            keep_open: l.keep_stdin_open,
        });
        Ok(format!("run-{}", s.runs.len() - 1))
    }
    fn read_log(&mut self, _box: &str, run_id: &str, from: u64) -> Result<LogChunk, String> {
        let s = self.st();
        let r = &s.runs[run_index(run_id)];
        Ok(LogChunk {
            bytes: r.log[(from as usize).min(r.log.len())..].to_vec(),
            next: r.log.len() as u64,
            exited: r.exit,
        })
    }
    fn stop(&mut self, _box: &str, run_id: &str) -> Result<(), String> {
        self.st().stopped.push(run_id.to_string());
        Ok(())
    }
    fn send(&mut self, _box: &str, run_id: &str, text: &str, close: bool) -> Result<(), String> {
        let mut s = self.st();
        s.sent.push((run_id.to_string(), text.to_string(), close));
        let p = s.program.unwrap();
        let i = run_index(run_id);
        assert!(
            s.runs[i].keep_open,
            "input is only added to a kept-open run"
        );
        s.runs[i].stdin.push_str(text);
        // a new message in Claude Code's conversation mode: the program answers it on the same output
        if p == Program::Claude && text.contains("\"type\":\"user\"") && !close {
            let script = s.scripts.pop_front().unwrap_or(Script::Ok("done"));
            let (log, _) = transcript(p, &script, true);
            s.runs[i].log.extend_from_slice(log.as_bytes());
        }
        Ok(())
    }
}

// ---- helpers ------------------------------------------------------------------------------------------------------------

const OWN_TOKEN: &str = "ozrt_OWNTOKENSENTINEL0123456789";
const MCP_TOKEN: &str = "ozmcp_MCPTOKENSENTINEL0123456789";
const PROMPT: &str = "TASK-MARKER: fix the parser and keep its tests green.";

/// The run's environment as the Models routing and the broker hand it, plus one variable of every **other** family, which
/// must never reach the run.
fn env_for(p: Program) -> BTreeMap<String, String> {
    let mut e = BTreeMap::new();
    e.insert(p.token_var().to_string(), OWN_TOKEN.to_string());
    match p {
        Program::Claude => e.insert(
            "ANTHROPIC_BASE_URL".into(),
            "http://127.0.0.1:4100/a".into(),
        ),
        Program::Codex => e.insert(
            "OPENAI_BASE_URL".into(),
            "http://127.0.0.1:4100/oa/v1".into(),
        ),
        Program::Gemini => e.insert(
            "GOOGLE_GEMINI_BASE_URL".into(),
            "http://127.0.0.1:4100/g".into(),
        ),
    };
    for (prog, var) in [
        (Program::Claude, "ANTHROPIC_API_KEY"),
        (Program::Codex, "OPENAI_API_KEY"),
        (Program::Gemini, "GEMINI_API_KEY"),
    ] {
        if prog != p {
            e.insert(
                var.to_string(),
                format!("ozrt_FOREIGN{}SENTINEL0123456789", prog.binary()),
            );
        }
    }
    e.insert("OZBOX_MCP_URL".into(), "http://127.0.0.1:4200/mcp".into());
    e.insert("OZBOX_MCP_TOKEN".into(), MCP_TOKEN.into());
    e
}

fn start_req(p: Program, interactive: bool) -> EngineStart {
    EngineStart {
        task_id: "orch-1/parser".into(),
        box_name: "worker-1".into(),
        prompt: PROMPT.into(),
        skill: None,
        repo: Some("app".into()),
        branch: Some("feat/parser".into()),
        resume_from: None,
        secret_env: env_for(p),
        deny_commands: vec!["git push --force".into(), "curl".into()],
        max_runtime_s: Some(600),
        model: Some("model-chosen-by-routing".into()),
        on_fallback: false,
        interactive,
        resume_session: None,
        ask_for_edits: false,
    }
}

fn drain(e: &mut dyn AgentEngine, h: &str) -> Vec<EngineEvent> {
    let mut all = Vec::new();
    for _ in 0..5 {
        let got = e.poll(h).unwrap();
        let end = got.iter().any(|x| {
            matches!(
                x,
                EngineEvent::Finished { .. }
                    | EngineEvent::Failed(_)
                    | EngineEvent::ProviderRefused(_)
                    | EngineEvent::TurnDone(_)
            )
        });
        all.extend(got);
        if end {
            break;
        }
    }
    all
}

const PROGRAMS: [Program; 3] = [Program::Claude, Program::Codex, Program::Gemini];

// ---- the conformance suite: every adapter passes all of it ------------------------------------------------------------

#[test]
fn every_adapter_takes_the_task_on_standard_input_and_only_its_own_credentials() {
    for p in PROGRAMS {
        let cli = FakeCli::new(p, &[Script::Ok("done")]);
        let mut e = p.make(cli.clone());
        e.start(&start_req(p, false)).unwrap();
        let s = cli.st();
        let l = &s.launches[0];
        let argv = l.argv.join("\u{1}");
        assert!(
            !argv.contains("TASK-MARKER"),
            "{p:?}: the task is not an argument"
        );
        assert!(
            s.runs[0].stdin.contains("TASK-MARKER"),
            "{p:?}: the task is standard input"
        );
        assert_eq!(
            l.argv[0..3],
            ["sh", "-c", crate::claude_code::WRAPPER],
            "{p:?}"
        );
        for secret in [OWN_TOKEN, MCP_TOKEN, "FOREIGN"] {
            assert!(!argv.contains(secret), "{p:?}: no secret in argv");
            assert!(
                !format!("{l:?}").contains(secret),
                "{p:?}: Debug hides the environment"
            );
        }
        assert_eq!(
            l.env.get(p.token_var()).map(String::as_str),
            Some(OWN_TOKEN),
            "{p:?}"
        );
        assert!(
            !l.env.values().any(|v| v.contains("FOREIGN")),
            "{p:?}: another engine's credential never reaches this run: {:?}",
            l.env.keys().collect::<Vec<_>>()
        );
        assert_eq!(
            l.labels.get("task").map(String::as_str),
            Some("orch-1/parser")
        );
        assert_eq!(l.cwd.as_deref(), Some("/work/repos/app"));
        // the routing's model is passed by name
        assert!(
            l.argv.windows(2).any(|w| w[1] == "model-chosen-by-routing"),
            "{p:?}: the model chosen by the routing"
        );
    }
}

#[test]
fn every_adapter_turns_its_programs_output_into_the_same_neutral_turns() {
    for p in PROGRAMS {
        let cli = FakeCli::new(p, &[Script::Ok("Parser fixed")]);
        let mut e = p.make(cli.clone());
        let h = e.start(&start_req(p, false)).unwrap();
        let events = drain(e.as_mut(), &h);
        let dump = format!("{events:?}");
        assert!(
            !dump.contains("TOOLINPUTSENTINEL"),
            "{p:?}: a tool's input never leaves the adapter: {dump}"
        );
        assert!(
            events
                .iter()
                .any(|x| matches!(x, EngineEvent::ToolUse { .. })),
            "{p:?}: a tool use is reported by name: {dump}"
        );
        assert!(
            events.iter().any(|x| matches!(x, EngineEvent::TokenUsage { input_tokens, output_tokens, .. } if *input_tokens > 0 && *output_tokens > 0)),
            "{p:?}: tokens are reported: {dump}"
        );
        assert!(
            events.iter().any(
                |x| matches!(x, EngineEvent::Finished { summary, .. } if summary == "Parser fixed")
            ),
            "{p:?}: finished with the agent's own words: {dump}"
        );
        assert!(
            events
                .iter()
                .any(|x| matches!(x, EngineEvent::Session(s) if s == p.session())),
            "{p:?}: the session id is reported to the supervisor"
        );
        // the neutral model: a result and done, and the engine's session id is not in any turn
        let mut n = 0;
        let turns: Vec<Turn> = events
            .into_iter()
            .flat_map(|ev| turns_of(ev, &[OWN_TOKEN.to_string()], &mut n))
            .collect();
        assert!(turns.contains(&Turn::State(RunState::Done, None)), "{p:?}");
        assert!(turns
            .iter()
            .any(|t| matches!(t, Turn::Result(o) if o.summary == "Parser fixed")));
        assert!(
            !format!("{turns:?}").contains(p.session()),
            "{p:?}: no engine session id in a turn"
        );
    }
}

#[test]
fn usage_names_the_model_so_the_one_cap_prices_it_per_provider() {
    let want = [
        (Program::Claude, (100, 20, 0), "claude-model-x"),
        // Codex counts cached tokens inside its input; they are priced apart
        (Program::Codex, (600, 50, 400), "model-chosen-by-routing"),
        (Program::Gemini, (1000, 50, 0), "gemini-model-x"),
    ];
    for (p, (i, o, c), model) in want {
        let cli = FakeCli::new(p, &[Script::Ok("ok")]);
        let mut e = p.make(cli);
        let h = e.start(&start_req(p, false)).unwrap();
        let events = drain(e.as_mut(), &h);
        assert!(
            events.contains(&EngineEvent::TokenUsage {
                input_tokens: i,
                output_tokens: o,
                cached_input_tokens: c,
                model: Some(model.into()),
            }),
            "{p:?}: {events:?}"
        );
    }
}

#[test]
fn every_adapter_says_a_provider_refusal_apart_from_a_failure() {
    for p in PROGRAMS {
        let cli = FakeCli::new(p, &[Script::Refused, Script::Failed]);
        let mut e = p.make(cli.clone());
        let h = e.start(&start_req(p, false)).unwrap();
        let ev = drain(e.as_mut(), &h);
        assert!(
            ev.iter()
                .any(|x| matches!(x, EngineEvent::ProviderRefused(_))),
            "{p:?}: {ev:?}"
        );
        let h2 = e.start(&start_req(p, false)).unwrap();
        let ev2 = drain(e.as_mut(), &h2);
        assert!(
            ev2.iter()
                .any(|x| matches!(x, EngineEvent::Failed(t) if t.contains("tests still fail"))),
            "{p:?}: {ev2:?}"
        );
        let mut n = 0;
        let turns: Vec<Turn> = ev
            .into_iter()
            .flat_map(|x| turns_of(x, &[], &mut n))
            .collect();
        assert!(turns
            .iter()
            .any(|t| matches!(t, Turn::State(RunState::Blocked, _))));
    }
}

#[test]
fn every_adapter_continues_a_conversation_in_the_same_session() {
    for p in PROGRAMS {
        let cli = FakeCli::new(
            p,
            &[
                Script::Ok("Which delimiter?"),
                Script::Ok("Done with commas"),
            ],
        );
        let mut e = p.make(cli.clone());
        let h = e.start(&start_req(p, true)).unwrap();
        let first = drain(e.as_mut(), &h);
        assert!(
            first
                .iter()
                .any(|x| matches!(x, EngineEvent::TurnDone(t) if t == "Which delimiter?")),
            "{p:?}: {first:?}"
        );
        e.send(&h, "Use commas.").unwrap();
        let second = drain(e.as_mut(), &h);
        assert!(
            second
                .iter()
                .any(|x| matches!(x, EngineEvent::TurnDone(t) if t == "Done with commas")),
            "{p:?}: {second:?}"
        );
        let s = cli.st();
        match p {
            // one process, the message on its kept-open input
            Program::Claude => {
                assert_eq!(s.launches.len(), 1);
                assert!(s.runs[0].stdin.contains("Use commas."));
            }
            // a new process that resumes the session the program named, with the message on its standard input
            _ => {
                assert_eq!(s.launches.len(), 2, "{p:?}");
                let argv = &s.launches[1].argv;
                assert!(argv.iter().any(|a| a == p.session()), "{p:?}: {argv:?}");
                assert!(
                    !argv.iter().any(|a| a.contains("Use commas")),
                    "{p:?}: the message is not argv"
                );
                assert_eq!(s.runs[1].stdin, "Use commas.");
            }
        }
        drop(s);
        // and a run that is not a conversation refuses a message rather than pretending
        let h2 = e.start(&start_req(p, false)).unwrap();
        assert!(e.send(&h2, "hello").is_err(), "{p:?}");
    }
}

#[test]
fn what_an_adapter_claims_it_can_do_is_what_it_does() {
    for p in PROGRAMS {
        let caps = capabilities_of(p.engine_id()).unwrap();
        assert!(caps.headless.is_yes(), "{p:?}");
        assert!(caps.docs.starts_with("https://"));
        let cli = FakeCli::new(p, &[Script::Ok("ok")]);
        let mut e = p.make(cli.clone());
        let h = e.start(&start_req(p, false)).unwrap();
        let events = drain(e.as_mut(), &h);
        let argv = cli.st().launches[0].argv.join(" ");
        // the ask list: a per-command list where the engine takes one, and never pretended where it does not
        if caps.per_command_ask_list.is_yes() {
            assert!(
                argv.contains("git push --force") && argv.contains("curl"),
                "{p:?}: {argv}"
            );
        } else {
            assert!(!argv.contains("curl"), "{p:?}: no list is faked: {argv}");
        }
        // the Oz Box tools: the token's NAME on the command line where the engine reaches them, never its value
        if caps.mcp_in_runs.is_yes() {
            assert!(
                argv.contains("http://127.0.0.1:4200/mcp") && argv.contains("OZBOX_MCP_TOKEN"),
                "{p:?}: {argv}"
            );
        } else {
            assert!(!argv.contains("4200"), "{p:?}: {argv}");
        }
        assert!(!argv.contains(MCP_TOKEN));
        // asking: no headless adapter makes up a proposal, and an answer to one is a no-op, not a fault
        if !caps.asks_before_acting.is_yes() {
            assert!(
                !events.iter().any(|x| matches!(x, EngineEvent::Propose(_))),
                "{p:?}"
            );
            assert!(e.resolve(&h, false).is_ok());
        }
        if caps.reported_cost.is_yes() {
            assert!(
                events
                    .iter()
                    .any(|x| matches!(x, EngineEvent::ReportedCost { .. })),
                "{p:?}"
            );
        } else {
            assert!(
                !events
                    .iter()
                    .any(|x| matches!(x, EngineEvent::ReportedCost { .. })),
                "{p:?}"
            );
        }
    }
    // the engines without an adapter are listed honestly, with why
    for id in ["opencode", "aider"] {
        let c = capabilities_of(id).unwrap();
        assert!(
            matches!(c.headless, Support::Unsupported(why) if !why.is_empty()),
            "{id}"
        );
    }
}

#[test]
fn every_adapter_sends_a_long_task_in_pieces_and_refuses_one_past_the_limit() {
    for p in PROGRAMS {
        let cli = FakeCli::new(p, &[Script::Ok("ok")]);
        let mut e = p.make(cli.clone());
        let mut req = start_req(p, false);
        req.prompt = format!("TASK-MARKER {}", "y".repeat(MAX_PROMPT_BYTES + 10));
        e.start(&req).unwrap();
        {
            let s = cli.st();
            assert!(s.launches[0].keep_stdin_open, "{p:?}");
            assert!(
                s.sent.last().unwrap().2,
                "{p:?}: the last piece closes the input"
            );
            assert!(s.runs[0].stdin.len() > MAX_PROMPT_BYTES, "{p:?}");
        }
        req.prompt = "x".repeat(crate::claude_code::MAX_LONG_PROMPT_BYTES + 1);
        assert!(e.start(&req).is_err(), "{p:?}");
    }
}

#[test]
fn stopping_a_run_stops_its_process() {
    for p in PROGRAMS {
        let cli = FakeCli::new(p, &[Script::Ok("ok")]);
        let mut e = p.make(cli.clone());
        let h = e.start(&start_req(p, false)).unwrap();
        e.stop(&h).unwrap();
        assert_eq!(cli.st().stopped, ["run-0"], "{p:?}");
        assert!(matches!(e.poll(&h), Err(EngineError::Unavailable)));
    }
}

#[test]
fn an_unsafe_model_name_or_address_is_refused_not_passed() {
    for p in [Program::Codex, Program::Gemini] {
        let cli = FakeCli::new(p, &[]);
        let mut e = p.make(cli.clone());
        let mut req = start_req(p, false);
        req.model = Some("--dangerously-bypass".into());
        assert!(e.start(&req).is_err(), "{p:?}");
        assert!(cli.st().launches.is_empty());
    }
    let cli = FakeCli::new(Program::Codex, &[]);
    let mut e = Program::Codex.make(cli.clone());
    let mut req = start_req(Program::Codex, false);
    req.secret_env.insert(
        "OPENAI_BASE_URL".into(),
        "http://x\"\nsandbox_mode=\"danger-full-access".into(),
    );
    assert!(e.start(&req).is_err());
    assert!(cli.st().launches.is_empty());
}

#[test]
fn codex_is_sandboxed_and_a_chat_started_run_edits_nothing() {
    let cli = FakeCli::new(Program::Codex, &[Script::Ok("a"), Script::Ok("b")]);
    let mut e = Program::Codex.make(cli.clone());
    e.start(&start_req(Program::Codex, false)).unwrap();
    let mut chat = start_req(Program::Codex, false);
    chat.ask_for_edits = true;
    e.start(&chat).unwrap();
    let s = cli.st();
    let mode = |i: usize| {
        let a = &s.launches[i].argv;
        a.windows(2)
            .find(|w| w[0] == "--sandbox")
            .map(|w| w[1].clone())
    };
    assert_eq!(mode(0).as_deref(), Some("workspace-write"));
    assert_eq!(mode(1).as_deref(), Some("read-only"));
    assert_eq!(s.launches[0].argv.last().map(String::as_str), Some("-"));
    // the token is where `codex exec` reads it
    assert_eq!(
        s.launches[0].env.get("CODEX_API_KEY").map(String::as_str),
        Some(OWN_TOKEN)
    );
}

// ---- the same programs, as real processes ------------------------------------------------------------------------------

/// Runs argv as a real process with a private HOME, feeds standard input and keeps what it printed. For the fake binaries.
struct ProcessTransport {
    home: std::path::PathBuf,
    out: Vec<(Vec<u8>, i32)>,
}

impl RunTransport for ProcessTransport {
    fn launch(&mut self, _: &str, l: &Launch) -> Result<String, String> {
        use std::io::Write;
        let mut cmd = std::process::Command::new(&l.argv[0]);
        cmd.args(&l.argv[1..])
            .env_clear()
            .env("HOME", &self.home)
            .env("PATH", "/usr/bin:/bin")
            .envs(&l.env)
            .current_dir(&self.home)
            .stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped());
        let mut child = cmd.spawn().map_err(|e| e.to_string())?;
        child
            .stdin
            .take()
            .unwrap()
            .write_all(l.stdin.as_deref().unwrap_or("").as_bytes())
            .unwrap();
        let o = child.wait_with_output().map_err(|e| e.to_string())?;
        let mut bytes = o.stdout;
        bytes.extend_from_slice(&o.stderr);
        self.out.push((bytes, o.status.code().unwrap_or(-1)));
        Ok(format!("run-{}", self.out.len() - 1))
    }
    fn read_log(&mut self, _: &str, id: &str, from: u64) -> Result<LogChunk, String> {
        let (b, code) = &self.out[run_index(id)];
        Ok(LogChunk {
            bytes: b[(from as usize).min(b.len())..].to_vec(),
            next: b.len() as u64,
            exited: Some(*code),
        })
    }
    fn stop(&mut self, _: &str, _: &str) -> Result<(), String> {
        Ok(())
    }
    fn send(&mut self, _: &str, _: &str, _: &str, _: bool) -> Result<(), String> {
        Err("not used".into())
    }
}

/// A fake program: checks the task came on standard input and never as an argument, that its own token is set and no other
/// family's is, that its fixed flags are there; then prints `out` in its own format.
fn fake_binary(name: &str, own_var: &str, flags: &[&str], out: &[&str]) -> String {
    let mut s = String::from("#!/bin/sh\nin=$(cat)\n");
    s.push_str("case \"$in\" in *TASK-MARKER*) ;; *) echo 'no task on stdin'; exit 71;; esac\n");
    s.push_str("for a in \"$@\"; do case \"$a\" in *TASK-MARKER*) echo 'task in argv'; exit 72;; esac; done\n");
    s.push_str(&format!(
        "[ -n \"${own_var}\" ] || {{ echo 'no token'; exit 73; }}\n"
    ));
    for v in [
        "ANTHROPIC_API_KEY",
        "OPENAI_API_KEY",
        "CODEX_API_KEY",
        "GEMINI_API_KEY",
    ] {
        if v != own_var && !(name == "codex" && v == "OPENAI_API_KEY") {
            s.push_str(&format!(
                "[ -z \"${v}\" ] || {{ echo 'foreign {v}'; exit 74; }}\n"
            ));
        }
    }
    s.push_str("args=\" $* \"\n");
    for f in flags {
        s.push_str(&format!(
            "case \"$args\" in *\" {f} \"*) ;; *) echo 'missing {f}'; exit 75;; esac\n"
        ));
    }
    for line in out {
        s.push_str(&format!("printf '%s\\n' '{line}'\n"));
    }
    s
}

#[cfg(unix)]
#[test]
fn fake_binaries_on_the_box_users_path_see_the_task_on_stdin_and_only_their_own_token() {
    use std::os::unix::fs::PermissionsExt;
    let home = tempfile::tempdir().unwrap();
    let bin = home.path().join(".local/bin");
    std::fs::create_dir_all(&bin).unwrap();
    let progs = [
        (
            Program::Claude,
            fake_binary(
                "claude",
                "ANTHROPIC_API_KEY",
                &["-p", "stream-json"],
                &[
                    r#"{"type":"result","subtype":"success","is_error":false,"result":"claude done","total_cost_usd":0.01}"#,
                ],
            ),
        ),
        (
            Program::Codex,
            fake_binary(
                "codex",
                "CODEX_API_KEY",
                &["exec", "--json", "-", "--sandbox"],
                &[
                    r#"{"type":"thread.started","thread_id":"t-1"}"#,
                    r#"{"type":"item.completed","item":{"id":"i","type":"agent_message","text":"codex done"}}"#,
                    r#"{"type":"turn.completed","usage":{"input_tokens":10,"cached_input_tokens":0,"output_tokens":2}}"#,
                ],
            ),
        ),
        (
            Program::Gemini,
            fake_binary(
                "gemini",
                "GEMINI_API_KEY",
                &["--output-format", "stream-json", "--prompt"],
                &[
                    r#"{"type":"init","session_id":"s-1","model":"m"}"#,
                    r#"{"type":"message","role":"assistant","content":"gemini done","delta":true}"#,
                    r#"{"type":"result","status":"success","stats":{"input_tokens":10,"output_tokens":2}}"#,
                ],
            ),
        ),
    ];
    for (p, script) in &progs {
        let path = bin.join(p.binary());
        std::fs::write(&path, script).unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755)).unwrap();
    }
    for (p, _) in progs {
        let t = ProcessTransport {
            home: home.path().to_path_buf(),
            out: Vec::new(),
        };
        let mut e: Box<dyn AgentEngine> = match p {
            Program::Claude => Box::new(ClaudeCodeEngine::new(t)),
            Program::Codex => Box::new(crate::codex_cli::engine(t)),
            Program::Gemini => Box::new(crate::gemini_cli::engine(t)),
        };
        let mut req = start_req(p, false);
        req.repo = None;
        let h = e.start(&req).unwrap();
        let ev = e.poll(&h).unwrap();
        let want = format!("{} done", p.binary());
        assert!(
            ev.iter()
                .any(|x| matches!(x, EngineEvent::Finished { summary, .. } if *summary == want)),
            "{p:?}: {ev:?}"
        );
    }
}

// ---- the neutral model on the hub -------------------------------------------------------------------------------------

#[test]
fn a_question_and_an_answer_carry_four_fixed_fields_and_nothing_of_an_engine() {
    let ask = Turn::Ask(Ask {
        id: String::new(),
        kind: AskKind::Question,
        text: "Which delimiter?".into(),
    });
    let HubOut::Send(kind, body) = to_hub("orch-1/parser", &ask).unwrap() else {
        panic!("a question is sent")
    };
    assert_eq!(kind, Kind::Question);
    let v: serde_json::Value = serde_json::from_slice(&body).unwrap();
    let keys: Vec<&str> = v.as_object().unwrap().keys().map(String::as_str).collect();
    // the same four fields as the hub's own answer about a feature
    assert_eq!(keys, ["feature", "kind", "orchestration", "text"]);
    assert_eq!(v["kind"], "question");
    assert_eq!(from_hub(kind, &body), Some(("orch-1/parser".into(), ask)));
    // an unknown field (an engine's, say) is not a turn
    let extra =
        br#"{"orchestration":"o","feature":"f","kind":"answer","text":"t","engine":"codex"}"#;
    assert_eq!(from_hub(Kind::Answer, extra), None);
    // a question as plain words is a question about no task; a body that is JSON but not ours is nothing
    let (t, plain) = from_hub(Kind::Question, b"Is the schema final?").unwrap();
    assert_eq!(t, "-/-");
    assert!(matches!(plain, Turn::Ask(a) if a.text == "Is the schema final?"));
    assert_eq!(from_hub(Kind::Question, br#"{"engine":"codex"}"#), None);
    // the merge queue's answers reach the agent as words, with their kind
    let merged =
        br#"{"orchestration":"o","feature":"f","kind":"tests-failed","text":"2 specs fail"}"#;
    assert!(
        matches!(from_hub(Kind::Answer, merged), Some((_, Turn::Reply(r))) if r.text == "tests-failed: 2 specs fail")
    );
}

#[test]
fn every_turn_maps_to_the_hubs_frozen_kinds_and_back() {
    let t = "orch-1/parser";
    let reply = Turn::Reply(Reply {
        ask_id: String::new(),
        text: "Use commas.".into(),
    });
    let HubOut::Send(k, b) = to_hub(t, &reply).unwrap() else {
        panic!()
    };
    assert_eq!(k, Kind::Answer);
    assert_eq!(from_hub(k, &b), Some((t.into(), reply)));
    let done = Turn::Result(Outcome {
        summary: "Parser fixed".into(),
        commit: Some("0123456789abcdef0123456789abcdef01234567".into()),
        ..Outcome::default()
    });
    let HubOut::Send(k, b) = to_hub(t, &done).unwrap() else {
        panic!()
    };
    assert_eq!(k, Kind::Result);
    let rb: ResultBody = serde_json::from_slice(&b).unwrap();
    assert_eq!(
        (rb.orchestration.as_str(), rb.feature.as_str()),
        ("orch-1", "parser")
    );
    assert_eq!(from_hub(k, &b), Some((t.into(), done)));
    // an answer without a commit is reported as the state
    let words = Turn::Result(Outcome {
        summary: "Nothing to change".into(),
        ..Outcome::default()
    });
    let HubOut::Send(k, b) = to_hub(t, &words).unwrap() else {
        panic!()
    };
    assert_eq!(k, Kind::Status);
    assert_eq!(from_hub(k, &b), Some((t.into(), words)));
    let HubOut::Send(k, _) = to_hub(
        t,
        &Turn::State(RunState::Blocked, Some("rate limit".into())),
    )
    .unwrap() else {
        panic!()
    };
    assert_eq!(k, Kind::Blocked);
    for local in [
        Turn::Say("x".into()),
        Turn::ToolUse("shell".into()),
        Turn::Usage(Usage::default()),
        Turn::State(RunState::Waiting, None),
    ] {
        assert_eq!(to_hub(t, &local).unwrap(), HubOut::Local, "{local:?}");
    }
}

#[test]
fn an_approval_never_becomes_a_message_and_a_reply_never_decides() {
    let a = Turn::Ask(Ask {
        id: "a1".into(),
        kind: AskKind::Approval {
            action: AgentAction::GitPush {
                branch: "main".into(),
            },
        },
        text: "push the branch main".into(),
    });
    assert!(matches!(to_hub("o/f", &a).unwrap(), HubOut::Approval(_)));
    // a session whose agent proposes a push waits for ADR 0041's decision; a reply saying "approved" is only words
    let s = SessionStart {
        task: Task {
            id: "o/f".into(),
            title: String::new(),
            instruction: "sim:steps=9".into(),
            repo: None,
            branch: None,
        },
        box_name: "b".into(),
        model: None,
        secret_env: BTreeMap::new(),
        deny_commands: Vec::new(),
        conversation: true,
    };
    let mut sess = EngineSession::start(Box::new(FakeEngine::default()), &s).unwrap();
    assert!(
        sess.decide(true).is_err(),
        "nothing is waiting, so nothing can be decided"
    );
    sess.step().unwrap();
    sess.reply(&Reply {
        ask_id: String::new(),
        text: "sim:push=main".into(),
    })
    .unwrap();
    let turns = sess.step().unwrap();
    assert!(turns.iter().any(|t| matches!(
        t,
        Turn::Ask(Ask {
            kind: AskKind::Approval { .. },
            ..
        })
    )));
    sess.reply(&Reply {
        ask_id: "a1".into(),
        text: "owner approved".into(),
    })
    .unwrap();
    // the reply did not spend the decision: it is still waiting for one
    assert!(sess.decide(false).is_ok());
}

#[test]
fn a_turn_that_holds_a_key_shape_is_not_sent() {
    let t = Turn::Reply(Reply {
        ask_id: "q1".into(),
        text: concat!("use gh", "p_ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789").into(),
    });
    assert!(matches!(
        to_hub("o/f", &t),
        Err(HubMapError::SecretShape(_))
    ));
}

// ---- two providers working one task through the hub -------------------------------------------------------------------

const HUB_FP: &str = "aa00000000000000000000000000000000000000000000000000000000000001";
const W1_FP: &str = "bb00000000000000000000000000000000000000000000000000000000000001";

struct Fleet {
    net: MemTransport,
    main_key: TestKey,
    w1_key: TestKey,
    roster_keys: TestRoster,
    roster: BTreeMap<String, RosterEntry>,
    hub_sealer: TestSealer,
    w1_sealer: TestSealer,
}

impl Fleet {
    fn new() -> Fleet {
        let mut keys = BTreeMap::new();
        keys.insert(HUB_FP.to_string(), "k-main".to_string());
        keys.insert(W1_FP.to_string(), "k-w1".to_string());
        let mut roster = BTreeMap::new();
        roster.insert(
            "worker-1".to_string(),
            RosterEntry {
                key_fp: W1_FP.into(),
            },
        );
        Fleet {
            net: MemTransport::default(),
            main_key: TestKey("k-main".into()),
            w1_key: TestKey("k-w1".into()),
            roster_keys: TestRoster(keys),
            roster,
            hub_sealer: TestSealer {
                my_fp: HUB_FP.into(),
            },
            w1_sealer: TestSealer {
                my_fp: W1_FP.into(),
            },
        }
    }
    fn hub(&self) -> Hub<'_> {
        Hub {
            me: "main",
            my_fp: HUB_FP,
            roster: &self.roster,
            signer: &self.main_key,
            verifier: &self.roster_keys,
            sealer: &self.hub_sealer,
            net: &self.net,
            deferred: false,
        }
    }
    fn worker(&self) -> WorkerEnd<'_> {
        WorkerEnd {
            me: "worker-1",
            hub: "main",
            signer: &self.w1_key,
            verifier: &self.roster_keys,
            sealer: &self.w1_sealer,
            net: &self.net,
        }
    }
    /// The worker's service reading the kinds its end does not apply yet (an `answer`; the approval path will), at the
    /// channel: verified, opened, in order.
    fn worker_receive(&self, ws: &mut WorkerState, now: u64) -> Vec<(String, Vec<u8>)> {
        let mut msgs = Vec::new();
        while let Some(m) = self.net.recv("worker-1") {
            msgs.push(m);
        }
        let cx = crate::channel::wire::Crypto {
            signer: &self.w1_key,
            verifier: &self.roster_keys,
            sealer: &self.w1_sealer,
        };
        let r = crate::channel::flow::receive_round(
            &mut ws.core,
            &PROFILE,
            &cx,
            &|_, _, _| Ok(()),
            now,
            &msgs,
        );
        r.deliveries
            .into_iter()
            .filter_map(|d| d.body.ok().map(|b| (d.kind, b)))
            .collect()
    }
}

/// Everything that crossed the channel, as the plain bodies the two ends handed it.
#[derive(Default)]
struct Wiretap(Vec<Vec<u8>>);

impl Wiretap {
    fn keep(&mut self, b: &[u8]) -> Vec<u8> {
        self.0.push(b.to_vec());
        b.to_vec()
    }
}

fn session(p: Program, cli: FakeCli, task: Task, token: &str) -> EngineSession {
    let mut env = BTreeMap::new();
    env.insert(p.token_var().to_string(), token.to_string());
    EngineSession::start(
        p.make(cli),
        &SessionStart {
            task,
            box_name: "box".into(),
            model: Some("routed-model".into()),
            secret_env: env,
            deny_commands: vec!["curl".into()],
            conversation: true,
        },
    )
    .unwrap()
}

#[test]
fn claude_code_on_main_and_codex_on_a_worker_work_one_task_through_the_hub() {
    const CLAUDE_TOKEN: &str = "ozrt_CLAUDERUNSENTINEL0123456789";
    const CODEX_TOKEN: &str = "ozrt_CODEXRUNSENTINEL0123456789";
    let f = Fleet::new();
    let (hub, w) = (f.hub(), f.worker());
    let mut hs = HubState::new("main", HUB_FP, 7);
    let mut ws = WorkerState::new("worker-1", W1_FP, "main", HUB_FP, 7);
    w.hello(&mut ws, 9);
    for _ in 0..6 {
        hub.poll(&mut hs, 9);
        w.poll(&mut ws, 9);
    }
    let mut tap = Wiretap::default();

    // main: the conductor is Claude Code. Its first turn splits the work; it waits for what comes back.
    let cc = FakeCli::new(
        Program::Claude,
        &[
            Script::Ok("Plan: a worker builds the parser."),
            Script::Ok("Use commas."),
        ],
    );
    let mut conductor = session(
        Program::Claude,
        cc.clone(),
        Task {
            id: "orch-1/plan".into(),
            title: "Plan the parser".into(),
            instruction: "TASK-MARKER plan it".into(),
            repo: Some("app".into()),
            branch: None,
        },
        CLAUDE_TOKEN,
    );
    assert!(conductor
        .step()
        .unwrap()
        .iter()
        .any(|t| matches!(t, Turn::Ask(_))));

    // the hand-off: a neutral task, carried as the hub's own assignment
    let task = Task {
        id: "orch-1/parser".into(),
        title: "Build the parser".into(),
        instruction: "TASK-MARKER build the CSV parser".into(),
        repo: Some("app".into()),
        branch: Some("feat/parser".into()),
    };
    let assign = assign_of(
        &task,
        KeyDeclaration {
            env: "staging".into(),
            names: Vec::new(),
        },
        9_000_000,
    );
    tap.keep(&serde_json::to_vec(&assign).unwrap());
    hub.assign(&mut hs, "worker-1", &assign, 10).unwrap();
    assert_eq!(w.poll(&mut ws, 11), 1);

    // worker-1: Codex takes the task it was assigned and asks a question
    let got = task_of(&ws.tasks[0]);
    assert_eq!(got, task);
    let cx = FakeCli::new(
        Program::Codex,
        &[
            Script::Ok("Which delimiter should the parser use?"),
            Script::Ok("Parser built."),
        ],
    );
    let mut worker = session(Program::Codex, cx.clone(), got.clone(), CODEX_TOKEN);
    let turns = worker.step().unwrap();
    let question = turns
        .iter()
        .find_map(|t| match t {
            Turn::Ask(a) => Some(Turn::Ask(a.clone())),
            _ => None,
        })
        .unwrap();
    for t in [Turn::State(RunState::Running, None), question.clone()] {
        let HubOut::Send(k, b) = to_hub(&got.id, &t).unwrap() else {
            panic!("{t:?}")
        };
        w.say_raw(&mut ws, 12, k, &tap.keep(&b));
    }
    hub.poll(&mut hs, 13);

    // main reads the question as a neutral ask and hands it to Claude Code, whose answer goes back as a reply
    let q = hs.peers["worker-1"].report.questions[0].clone();
    let (qtask, Turn::Ask(asked)) = from_hub(Kind::Question, q.as_bytes()).unwrap() else {
        panic!()
    };
    assert_eq!(qtask, "orch-1/parser");
    assert_eq!(asked.text, "Which delimiter should the parser use?");
    conductor
        .reply(&Reply {
            ask_id: String::new(),
            text: format!("A worker asks: {}", asked.text),
        })
        .unwrap();
    let answer_text = conductor
        .step()
        .unwrap()
        .into_iter()
        .find_map(|t| match t {
            Turn::Ask(a) => Some(a.text),
            _ => None,
        })
        .unwrap();
    assert_eq!(answer_text, "Use commas.");
    let reply = Turn::Reply(Reply {
        ask_id: asked.id.clone(),
        text: answer_text,
    });
    let HubOut::Send(k, b) = to_hub(&qtask, &reply).unwrap() else {
        panic!()
    };
    hs.core
        .enqueue(
            &PROFILE,
            "worker-1",
            k.name(),
            Ext::at(0).encode(),
            tap.keep(&b),
        )
        .unwrap();
    hub.flush(&mut hs, "worker-1", 14).unwrap();

    // worker-1 receives the reply, hands it to Codex (which resumes its own session), and reports the result
    let delivered = f.worker_receive(&mut ws, 15);
    let (kind, body) = delivered.iter().find(|(k, _)| k == "answer").unwrap();
    let (rtask, Turn::Reply(r)) = from_hub(Kind::parse(kind).unwrap(), body).unwrap() else {
        panic!()
    };
    assert_eq!(
        rtask, got.id,
        "a reply is matched to its question by the task"
    );
    worker.reply(&r).unwrap();
    let last = worker.step().unwrap();
    let summary = last
        .iter()
        .find_map(|t| match t {
            Turn::Ask(a) => Some(a.text.clone()),
            _ => None,
        })
        .unwrap();
    worker.stop().unwrap();
    {
        let s = cx.st();
        assert!(s.launches[1]
            .argv
            .iter()
            .any(|a| a == Program::Codex.session()));
        assert_eq!(s.runs[1].stdin, "Use commas.");
    }
    let result = Turn::Result(Outcome {
        summary,
        commit: Some("0123456789abcdef0123456789abcdef01234567".into()),
        ..Outcome::default()
    });
    let HubOut::Send(k, b) = to_hub(&got.id, &result).unwrap() else {
        panic!()
    };
    w.say_raw(&mut ws, 16, k, &tap.keep(&b));
    hub.poll(&mut hs, 17);
    let rb = &hs.peers["worker-1"].report.results["orch-1"]["parser"];
    assert_eq!(rb.summary, "Parser built.");
    let (_, back) = from_hub(Kind::Result, &serde_json::to_vec(rb).unwrap()).unwrap();
    assert_eq!(back, result);

    // nothing of either engine or provider crossed: no program, vendor, session id, token or tool input
    let mut crossed = tap
        .0
        .iter()
        .map(|b| String::from_utf8_lossy(b).to_string())
        .collect::<Vec<_>>();
    crossed.push(serde_json::to_string(&hs.peers).unwrap());
    crossed.extend(
        hs.core
            .audit
            .iter()
            .map(|e| format!("{} {}", e.action, e.detail)),
    );
    crossed.extend(
        ws.core
            .audit
            .iter()
            .map(|e| format!("{} {}", e.action, e.detail)),
    );
    for c in &crossed {
        let low = c.to_ascii_lowercase();
        for banned in [
            "claude",
            "codex",
            "gemini",
            "anthropic",
            "openai",
            "cc-session",
            "cx-thread",
            "routed-model",
            "sentinel",
        ] {
            assert!(!low.contains(banned), "{banned} crossed the hub: {c}");
        }
    }
    // and each engine held only its own token
    let cc_env = cc.st().launches[0].env.clone();
    let cx_env = cx.st().launches[0].env.clone();
    assert!(
        cc_env.values().any(|v| v == CLAUDE_TOKEN) && !cc_env.values().any(|v| v == CODEX_TOKEN)
    );
    assert!(
        cx_env.values().any(|v| v == CODEX_TOKEN) && !cx_env.values().any(|v| v == CLAUDE_TOKEN)
    );
}

#[test]
fn two_engines_on_one_box_exchange_the_same_bytes_as_across_boxes() {
    // Gemini asks, Claude Code answers, on one box: the bodies are the hub's, so nothing about the pair depends on where
    // they run.
    let gm = FakeCli::new(
        Program::Gemini,
        &[
            Script::Ok("Should dates be UTC?"),
            Script::Ok("Dates are UTC now."),
        ],
    );
    let cc = FakeCli::new(
        Program::Claude,
        &[Script::Ok("ready"), Script::Ok("Yes, UTC.")],
    );
    let t = Task {
        id: "orch-2/dates".into(),
        title: "Dates".into(),
        instruction: "TASK-MARKER fix the dates".into(),
        repo: None,
        branch: None,
    };
    let mut asker = session(
        Program::Gemini,
        gm.clone(),
        t.clone(),
        "ozrt_GEMINISENTINEL0123456789",
    );
    let mut answerer = session(
        Program::Claude,
        cc,
        t.clone(),
        "ozrt_CLAUDESENTINEL0123456789",
    );
    answerer.step().unwrap();
    let ask = asker
        .step()
        .unwrap()
        .into_iter()
        .find(|x| matches!(x, Turn::Ask(_)))
        .unwrap();
    let HubOut::Send(k, b) = to_hub(&t.id, &ask).unwrap() else {
        panic!()
    };
    let (_, Turn::Ask(a)) = from_hub(k, &b).unwrap() else {
        panic!()
    };
    answerer
        .reply(&Reply {
            ask_id: String::new(),
            text: a.text.clone(),
        })
        .unwrap();
    let said = answerer
        .step()
        .unwrap()
        .into_iter()
        .find_map(|x| match x {
            Turn::Ask(q) => Some(q.text),
            _ => None,
        })
        .unwrap();
    let HubOut::Send(k, b) = to_hub(
        &t.id,
        &Turn::Reply(Reply {
            ask_id: a.id,
            text: said,
        }),
    )
    .unwrap() else {
        panic!()
    };
    let (_, Turn::Reply(r)) = from_hub(k, &b).unwrap() else {
        panic!()
    };
    asker.reply(&r).unwrap();
    assert!(asker
        .step()
        .unwrap()
        .iter()
        .any(|x| matches!(x, Turn::Ask(q) if q.text == "Dates are UTC now.")));
    assert_eq!(gm.st().runs[1].stdin, "Yes, UTC.");
}

// ---- sentinels ----------------------------------------------------------------------------------------------------------

#[test]
fn no_provider_token_reaches_another_engines_run_and_an_echo_of_its_own_is_redacted() {
    let tokens = [
        (Program::Claude, "ozrt_SENTINELCLAUDE0123456789"),
        (Program::Codex, "ozrt_SENTINELCODEX01234567890"),
        (Program::Gemini, "ozrt_SENTINELGEMINI012345678"),
    ];
    // every run is handed every family's variable, as a host with a bug would: each keeps only its own
    let mut all = BTreeMap::new();
    for (p, t) in tokens {
        all.insert(p.token_var().to_string(), t.to_string());
    }
    all.insert(
        "ANTHROPIC_AUTH_TOKEN".into(),
        "ozrt_SENTINELCLAUDE0123456789".into(),
    );
    all.insert(
        "GOOGLE_API_KEY".into(),
        "ozrt_SENTINELGEMINI012345678".into(),
    );
    all.insert(
        "CODEX_HOME".into(),
        "/run/user/1000/ozbox-run-files/other".into(),
    );
    for (p, own) in tokens {
        let (id, env) = (p.engine_id(), strip_foreign(p.engine_id(), &all));
        let others: Vec<&str> = tokens
            .iter()
            .filter(|(q, _)| *q != p)
            .map(|(_, t)| *t)
            .collect();
        assert!(env.values().any(|v| v == own), "{id}");
        for o in &others {
            assert!(
                !env.values().any(|v| v == o),
                "{id} holds another engine's token"
            );
        }
        let cli = FakeCli::new(p, &[Script::Ok("ok")]);
        let mut e = p.make(cli.clone());
        let mut req = start_req(p, false);
        req.secret_env = all.clone();
        let h = e.start(&req).unwrap();
        let events = drain(e.as_mut(), &h);
        let l = cli.st().launches[0].clone();
        for (q, t) in tokens {
            if q != p {
                assert!(!l.env.values().any(|v| v == t), "{p:?} got {q:?}'s token");
            }
            assert!(!l.argv.join(" ").contains(t), "{p:?}: a token in argv");
            assert!(
                !format!("{events:?}").contains(t),
                "{p:?}: a token in an event"
            );
        }
        if p != Program::Codex {
            assert!(!l.env.contains_key("CODEX_HOME"), "{p:?}");
        }
    }
    // an agent that prints its own token: the turn says [hidden], and the hub would refuse it anyway
    let mut n = 0;
    let own = "ozrt_SENTINELCODEX01234567890".to_string();
    let turns = turns_of(
        EngineEvent::Log(format!("my key is {own}")),
        std::slice::from_ref(&own),
        &mut n,
    );
    assert!(!format!("{turns:?}").contains(&own));
    let turns = turns_of(
        EngineEvent::TurnDone(format!("the key {own} works")),
        std::slice::from_ref(&own),
        &mut n,
    );
    for t in &turns {
        let _ = to_hub("o/f", t).unwrap();
    }
    assert!(!format!("{turns:?}").contains(&own));
}

#[test]
fn every_engine_of_any_provider_fits_one_list() {
    // the hub's harness keeps a list of engines of any provider
    let engines: Vec<Box<dyn AgentEngine>> = PROGRAMS
        .iter()
        .map(|p| p.make(FakeCli::new(*p, &[])))
        .collect();
    let ids: Vec<&str> = engines.iter().map(|e| e.id()).collect();
    assert_eq!(ids, ["claude-code", "codex", "gemini-cli"]);
}
