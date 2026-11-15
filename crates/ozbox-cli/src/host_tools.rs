//! The tool host: the shell, git, files, a browser, CI and Staging reads that a coding agent on a box reaches over MCP
//! (`crate::mcp`). Every tool is a call the permission engine decides (`ozbox_core::tool_gate`): allow, ask (which becomes a
//! request in the approvals inbox) or deny, and the decision, the tool, its server and whether it reads or writes go in the
//! audit chain. The arguments and the output never do.
//!
//! Where things happen is [`backend::HostBackend`]: the box, through its daemon's run API, or a directory on this
//! computer for the demo provider. What an agent can name is `/work`, nothing else (`paths`). Secrets are never an
//! argument and never output: the Staging tool starts a command the project *declared* with `ozbox env run --named`, so the
//! runner decides what it receives and removes every value from what comes back (ADR 0018); a production environment is
//! refused here and again by the engine.
//!
//! One approval covers one call. A call that asks waits (up to `ask_wait`) for the person, then runs once or is refused.

pub mod backend;
pub mod paths;
pub mod words;

use std::sync::Arc;
use std::time::{Duration, Instant};

use ozbox_core::approvals::{starts_with_words, ApprovalPolicy};
use ozbox_core::permissions::{self, ActorKind, Ctx, Effect, Environment, PermConfig};
use ozbox_core::run::{ApprovalState, TaskStore};
use ozbox_core::tool_gate::{self, ToolCall, Verdict};
use serde_json::{json, Value};

use crate::mcp::HostScope;
use crate::orch_tools::{Role, Session, ToolError};
use backend::{ExecReq, HostBackend};

/// What the tools need to know about boxes: whether one exists and whether it is tagged production.
pub trait BoxFacts: Send + Sync {
    fn exists(&self, box_name: &str) -> bool;
    fn production(&self, box_name: &str) -> bool;
}

/// The boxes as the server lists them, asked for through the same channel the orchestration tools use.
pub struct OpsFacts(pub Arc<dyn crate::orch_tools::BoxOps>);

impl OpsFacts {
    fn find(&self, name: &str) -> Option<Value> {
        self.0.list().ok()?.into_iter().find(|b| b["name"] == name)
    }
}

impl BoxFacts for OpsFacts {
    fn exists(&self, box_name: &str) -> bool {
        self.find(box_name).is_some()
    }
    fn production(&self, box_name: &str) -> bool {
        self.find(box_name).is_some_and(|b| b["production"] == true)
    }
}

/// How a tool is classified before a call is looked at: reads, writes, or it depends on the arguments.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Writes {
    Read,
    Write,
    Depends,
}

pub struct ToolInfo {
    pub name: &'static str,
    pub server: &'static str,
    pub writes: Writes,
    pub summary: &'static str,
}

/// The whole surface of the host tools. A test holds this list: there is nothing else an agent can call here.
pub const TOOLS: [ToolInfo; 17] = [
    ToolInfo { name: "shell", server: "shell", writes: Writes::Write, summary: "Run a command line in a folder under /work, with a time limit and an output cap." },
    ToolInfo { name: "git_status", server: "git", writes: Writes::Read, summary: "The state of a repository: branch, changed and untracked files." },
    ToolInfo { name: "git_diff", server: "git", writes: Writes::Read, summary: "What changed in a repository, or only in some paths." },
    ToolInfo { name: "git_log", server: "git", writes: Writes::Read, summary: "The latest commits, one line each." },
    ToolInfo { name: "git_branch", server: "git", writes: Writes::Depends, summary: "List branches, or make a new one." },
    ToolInfo { name: "git_commit", server: "git", writes: Writes::Write, summary: "Commit the staged changes (or all tracked changes) with a message." },
    ToolInfo { name: "git_push", server: "git", writes: Writes::Write, summary: "Push a branch. A protected branch needs a rule that allows it." },
    ToolInfo { name: "files_read", server: "files", writes: Writes::Read, summary: "Read a text file under /work." },
    ToolInfo { name: "files_write", server: "files", writes: Writes::Write, summary: "Write a text file under /work." },
    ToolInfo { name: "files_list", server: "files", writes: Writes::Read, summary: "List a folder under /work." },
    ToolInfo { name: "files_search", server: "files", writes: Writes::Read, summary: "Find lines that contain some text under a folder." },
    ToolInfo { name: "browser_fetch", server: "browser", writes: Writes::Read, summary: "Fetch a page from this box's own previews or an allowed host (GET only, no redirects)." },
    ToolInfo { name: "browser_screenshot", server: "browser", writes: Writes::Read, summary: "A screenshot of a page from this box's own previews or an allowed host." },
    ToolInfo { name: "ci_status", server: "ci", writes: Writes::Read, summary: "The latest CI runs of a repository (GitHub)." },
    ToolInfo { name: "ci_logs", server: "ci", writes: Writes::Read, summary: "The log of a CI run, failed steps by default." },
    ToolInfo { name: "ci_rerun", server: "ci", writes: Writes::Write, summary: "Run a CI run again." },
    ToolInfo { name: "staging_read", server: "staging", writes: Writes::Read, summary: "Run a command the project declared for Staging (`ozbox env run --named`); never a key, never production." },
];

pub fn tool_info(name: &str) -> Option<&'static ToolInfo> {
    TOOLS.iter().find(|t| t.name == name)
}

pub const SHELL_DEFAULT_TIMEOUT_S: u64 = 60;
pub const SHELL_MAX_TIMEOUT_S: u64 = 600;
pub const OUTPUT_DEFAULT: usize = 64 * 1024;
pub const OUTPUT_MAX: usize = 256 * 1024;
pub const READ_MAX: usize = 200 * 1024;
pub const WRITE_MAX: usize = 32 * 1024;
const MAX_COMMAND: usize = 4000;

fn prop(kind: &str, desc: &str) -> Value {
    json!({ "type": kind, "description": desc })
}

fn schema(name: &str, person_session: bool) -> Value {
    let mut p = serde_json::Map::new();
    let mut required: Vec<&str> = Vec::new();
    let mut add = |k: &str, v: Value, req: bool| {
        p.insert(k.to_string(), v);
        if req {
            required.push(Box::leak(k.to_string().into_boxed_str()));
        }
    };
    let cwd = || prop("string", "A folder under /work (default /work itself).");
    let repo = || {
        prop(
            "string",
            "The repository folder under /work (default /work itself).",
        )
    };
    match name {
        "shell" => {
            add("command", prop("string", "The command line. Commands that ask (sudo, rm -rf, git push --force, curl, ...) wait for a person."), true);
            add("cwd", cwd(), false);
            add(
                "timeout_s",
                prop(
                    "integer",
                    "Seconds before it is stopped (1 to 600, default 60).",
                ),
                false,
            );
            add(
                "max_output_bytes",
                prop("integer", "Most output kept (up to 262144, default 65536)."),
                false,
            );
        }
        "git_status" | "git_log" | "git_branch" => {
            add("repo", repo(), false);
            if name == "git_log" {
                add(
                    "limit",
                    prop("integer", "How many commits (1 to 100, default 20)."),
                    false,
                );
            }
            if name == "git_branch" {
                add(
                    "create",
                    prop("string", "A new branch name. Leave out to list branches."),
                    false,
                );
            }
        }
        "git_diff" => {
            add("repo", repo(), false);
            add(
                "paths",
                json!({"type":"array","items":{"type":"string"},"description":"Only these paths."}),
                false,
            );
            add(
                "staged",
                prop("boolean", "The staged changes instead of the working tree."),
                false,
            );
            add(
                "stat",
                prop("boolean", "A summary instead of the full diff."),
                false,
            );
        }
        "git_commit" => {
            add("repo", repo(), false);
            add("message", prop("string", "The commit message."), true);
            add(
                "all",
                prop(
                    "boolean",
                    "Also commit changes to tracked files that are not staged.",
                ),
                false,
            );
        }
        "git_push" => {
            add("repo", repo(), false);
            add("branch", prop("string", "The branch to push."), true);
            add(
                "remote",
                prop("string", "The remote (default origin)."),
                false,
            );
        }
        "files_read" => {
            add("path", prop("string", "The file."), true);
            add(
                "max_bytes",
                prop("integer", "Most bytes read (up to 204800)."),
                false,
            );
        }
        "files_write" => {
            add("path", prop("string", "The file."), true);
            add(
                "content",
                prop("string", "The whole new text (up to 32768 bytes)."),
                true,
            );
            add(
                "create_dirs",
                prop("boolean", "Make the folders it is in."),
                false,
            );
        }
        "files_list" => add("path", prop("string", "The folder (default /work)."), false),
        "files_search" => {
            add(
                "text",
                prop("string", "The text to find (plain text, not a pattern)."),
                true,
            );
            add(
                "path",
                prop("string", "A folder or file (default /work)."),
                false,
            );
            add(
                "max_matches",
                prop("integer", "Most matches returned (up to 100)."),
                false,
            );
        }
        "browser_fetch" | "browser_screenshot" => {
            add(
                "url",
                prop(
                    "string",
                    "http(s)://localhost:PORT/..., or a host the person allowed.",
                ),
                true,
            );
            if name == "browser_fetch" {
                add(
                    "max_bytes",
                    prop("integer", "Most bytes kept (up to 262144)."),
                    false,
                );
            }
        }
        "ci_status" => {
            add("repo", repo(), false);
            add(
                "limit",
                prop("integer", "How many runs (1 to 20, default 10)."),
                false,
            );
        }
        "ci_logs" => {
            add("repo", repo(), false);
            add("run_id", prop("string", "The run's id."), true);
            add(
                "failed_only",
                prop("boolean", "Only the failed steps (default true)."),
                false,
            );
        }
        "ci_rerun" => {
            add("repo", repo(), false);
            add("run_id", prop("string", "The run's id."), true);
            add(
                "failed_only",
                prop("boolean", "Only the failed jobs."),
                false,
            );
        }
        "staging_read" => {
            add(
                "project",
                prop("string", "The project whose declaration names the command."),
                true,
            );
            add(
                "command",
                prop("string", "The declared command's name."),
                true,
            );
            add(
                "env",
                prop(
                    "string",
                    "staging, dev or test (default staging). Production is refused.",
                ),
                false,
            );
            add(
                "args",
                json!({"type":"array","items":{"type":"string"},"description":"Arguments after the declared program."}),
                false,
            );
        }
        _ => {}
    }
    if person_session {
        p.insert("box".into(), prop("string", "The box the tool acts on."));
        required.push("box");
    }
    let info = tool_info(name);
    json!({
        "name": name,
        "description": info.map(|i| i.summary).unwrap_or(""),
        "inputSchema": { "type": "object", "properties": p, "required": required },
    })
}

/// The definitions `tools/list` returns for the host tools.
pub fn tool_defs(person_session: bool) -> Vec<Value> {
    TOOLS
        .iter()
        .map(|t| schema(t.name, person_session))
        .collect()
}

// ---- arguments ---------------------------------------------------------------------------------------------------------

fn s<'a>(a: &'a Value, k: &str) -> Option<&'a str> {
    a.get(k)
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|v| !v.is_empty())
}

fn need<'a>(a: &'a Value, k: &str) -> Result<&'a str, ToolError> {
    s(a, k).ok_or_else(|| ToolError::Invalid(format!("{k} is required")))
}

fn flag(a: &Value, k: &str) -> bool {
    a.get(k).and_then(Value::as_bool).unwrap_or(false)
}

fn num(a: &Value, k: &str, default: u64, min: u64, max: u64) -> Result<u64, ToolError> {
    match a.get(k) {
        None | Some(Value::Null) => Ok(default),
        Some(v) => match v.as_u64() {
            Some(n) if (min..=max).contains(&n) => Ok(n),
            _ => Err(ToolError::Invalid(format!(
                "{k} must be a whole number from {min} to {max}"
            ))),
        },
    }
}

fn strs(a: &Value, k: &str) -> Result<Vec<String>, ToolError> {
    match a.get(k) {
        None | Some(Value::Null) => Ok(Vec::new()),
        Some(Value::Array(v)) if v.len() <= 50 => v
            .iter()
            .map(|x| {
                x.as_str()
                    .map(str::to_string)
                    .filter(|t| t.len() <= 500 && !t.contains('\0'))
                    .ok_or_else(|| ToolError::Invalid(format!("{k} must be a list of short text")))
            })
            .collect(),
        _ => Err(ToolError::Invalid(format!(
            "{k} must be a list of short text"
        ))),
    }
}

fn path_parts(a: &Value, k: &str) -> Result<Vec<String>, ToolError> {
    paths::normalize(s(a, k).unwrap_or("")).map_err(ToolError::Invalid)
}

fn safe_word(t: &str, max: usize) -> bool {
    !t.is_empty()
        && t.len() <= max
        && !t.starts_with('-')
        && t.chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '/' | '-' | '+'))
}

fn branch_ok(b: &str) -> bool {
    safe_word(b, 120)
        && !b.contains("..")
        && !b.ends_with('/')
        && !b.ends_with(".lock")
        && !b.contains("//")
}

/// A URL the browser tools may open: http or https, no credentials, and a host this box's own loopback or on the list.
pub fn check_url(url: &str, allowed: &[String]) -> Result<String, ToolError> {
    let bad = |m: &str| Err(ToolError::Refused(m.to_string()));
    if url.len() > 2000 || url.chars().any(|c| c.is_control() || c.is_whitespace()) {
        return bad("that is not a usable address");
    }
    let rest = url
        .strip_prefix("http://")
        .or_else(|| url.strip_prefix("https://"))
        .ok_or_else(|| ToolError::Refused("only http and https addresses can be opened".into()))?;
    let authority = rest.split(['/', '?', '#']).next().unwrap_or("");
    if authority.is_empty() || authority.contains('@') || authority.contains('\\') {
        return bad("an address with credentials or no host cannot be opened");
    }
    let host = if let Some(v6) = authority.strip_prefix('[') {
        v6.split(']').next().unwrap_or("").to_string()
    } else {
        authority
            .rsplit_once(':')
            .map_or(authority, |(h, p)| {
                if p.chars().all(|c| c.is_ascii_digit()) {
                    h
                } else {
                    authority
                }
            })
            .to_string()
    }
    .to_ascii_lowercase();
    let loopback = matches!(host.as_str(), "localhost" | "127.0.0.1" | "::1");
    if loopback || permissions::host_allowed(allowed, &host) {
        Ok(host)
    } else {
        bad("that host is not allowed: only this box's own localhost, or a host the person added in Permissions")
    }
}

// ---- one prepared call ---------------------------------------------------------------------------------------------------

pub(crate) type Job = Box<dyn FnOnce(&dyn HostBackend, &str) -> Result<Value, ToolError> + Send>;

pub(crate) struct Prepared {
    pub(crate) writes: Option<bool>,
    pub(crate) path: Option<String>,
    pub(crate) command: Option<Vec<String>>,
    pub(crate) sensitive: bool,
    pub(crate) summary: String,
    pub(crate) env: Option<Environment>,
    pub(crate) job: Job,
}

/// What only the browser tools add to a prepared call.
#[derive(Default)]
pub(crate) struct Extra {
    /// The browser's own policy refuses this call before the engine is asked: a word for the audit chain, and what the
    /// agent is told. The refusal is recorded all the same.
    pub(crate) refuse: Option<(&'static str, String)>,
    /// A call the engine decides by its own rules, not by the mode alone.
    pub(crate) baseline: bool,
    /// The browsing session a call waits on, for the long-wait pause.
    pub(crate) session: Option<String>,
    /// The tool judged that a person must decide this call: the gate asks whatever a rule or the mode says.
    pub(crate) person_required: bool,
    /// Where the gate puts the id of the approval request a person decided, for the job to turn into a grant.
    pub(crate) approval: Option<crate::browser_tools::ApprovalSlot>,
}

fn fail(e: String) -> ToolError {
    ToolError::Failed(e)
}

fn exec_value(o: backend::ExecOut) -> Value {
    json!({
        "exit_code": o.code, "output": o.output, "stderr": o.stderr,
        "truncated": o.truncated, "timed_out": o.timed_out,
    })
}

fn run_in(
    be: &dyn HostBackend,
    bx: &str,
    cwd_parts: &[String],
    argv: Vec<String>,
    timeout: Duration,
    cap: usize,
) -> Result<backend::ExecOut, ToolError> {
    let cwd = be
        .resolve(bx, &paths::join(cwd_parts))
        .map_err(ToolError::Refused)?;
    be.exec(
        bx,
        &ExecReq {
            argv,
            cwd: cwd.abs,
            timeout,
            cap,
            stdin: None,
        },
    )
    .map_err(fail)
}

fn prepare(
    name: &str,
    a: &Value,
    policy: &ApprovalPolicy,
    perms: &PermConfig,
) -> Result<Prepared, ToolError> {
    let git = |verb: &str, extra: Vec<String>| -> Vec<String> {
        let mut v: Vec<String> = [
            "env",
            "GIT_TERMINAL_PROMPT=0",
            "git",
            "-c",
            "core.pager=cat",
            "-c",
            "color.ui=never",
        ]
        .iter()
        .map(|x| (*x).to_string())
        .collect();
        v.push(verb.to_string());
        v.extend(extra);
        v
    };
    let simple = |writes: Option<bool>,
                  summary: String,
                  path: Option<String>,
                  command: Option<Vec<String>>,
                  job: Job| Prepared {
        writes,
        path,
        command,
        sensitive: false,
        summary,
        env: None,
        job,
    };
    match name {
        "shell" => {
            let command = need(a, "command")?.to_string();
            if command.len() > MAX_COMMAND || command.contains('\0') {
                return Err(ToolError::Invalid(
                    "the command is too long or not text".into(),
                ));
            }
            let cwd = path_parts(a, "cwd")?;
            let timeout = Duration::from_secs(num(
                a,
                "timeout_s",
                SHELL_DEFAULT_TIMEOUT_S,
                1,
                SHELL_MAX_TIMEOUT_S,
            )?);
            let cap = num(
                a,
                "max_output_bytes",
                OUTPUT_DEFAULT as u64,
                1,
                OUTPUT_MAX as u64,
            )? as usize;
            let (segs, complex) = words::segments(&command);
            let asks =
                |w: &Vec<String>| policy.ask_commands.iter().any(|p| starts_with_words(w, p));
            let sensitive = complex || segs.iter().any(asks);
            // the engine is asked about the command that matters most: one the policy asks about, else the first
            let shown = segs
                .iter()
                .find(|w| asks(w))
                .or_else(|| segs.first())
                .cloned();
            Ok(Prepared {
                writes: Some(true),
                path: Some(paths::rel(&cwd)),
                command: shown,
                sensitive,
                summary: format!("in /work/{}: {}", paths::rel(&cwd), command),
                env: None,
                job: Box::new(move |be, bx| {
                    run_in(
                        be,
                        bx,
                        &cwd,
                        vec!["sh".into(), "-c".into(), command],
                        timeout,
                        cap,
                    )
                    .map(exec_value)
                }),
            })
        }
        "git_status" | "git_diff" | "git_log" | "git_branch" | "git_commit" | "git_push" => {
            let repo = path_parts(a, "repo")?;
            let rel = paths::rel(&repo);
            let t = Duration::from_secs(60);
            match name {
                "git_status" => Ok(simple(
                    Some(false),
                    format!("git status in /work/{rel}"),
                    Some(rel.clone()),
                    Some(vec!["git".into(), "status".into()]),
                    Box::new(move |be, bx| {
                        run_in(
                            be,
                            bx,
                            &repo,
                            git("status", vec!["--porcelain=v1".into(), "--branch".into()]),
                            t,
                            OUTPUT_DEFAULT,
                        )
                        .map(exec_value)
                    }),
                )),
                "git_diff" => {
                    let mut extra = vec!["--no-color".to_string()];
                    if flag(a, "staged") {
                        extra.push("--cached".into());
                    }
                    if flag(a, "stat") {
                        extra.push("--stat".into());
                    }
                    let ps = strs(a, "paths")?;
                    if ps.iter().any(|p| {
                        p.starts_with('-') || p.starts_with('/') || p.split('/').any(|x| x == "..")
                    }) {
                        return Err(ToolError::Refused(
                            "paths must be inside the repository".into(),
                        ));
                    }
                    if !ps.is_empty() {
                        extra.push("--".into());
                        extra.extend(ps);
                    }
                    Ok(simple(
                        Some(false),
                        format!("git diff in /work/{rel}"),
                        Some(rel.clone()),
                        Some(vec!["git".into(), "diff".into()]),
                        Box::new(move |be, bx| {
                            run_in(be, bx, &repo, git("diff", extra), t, OUTPUT_DEFAULT)
                                .map(exec_value)
                        }),
                    ))
                }
                "git_log" => {
                    let n = num(a, "limit", 20, 1, 100)?;
                    Ok(simple(
                        Some(false),
                        format!("git log in /work/{rel}"),
                        Some(rel.clone()),
                        Some(vec!["git".into(), "log".into()]),
                        Box::new(move |be, bx| {
                            run_in(
                                be,
                                bx,
                                &repo,
                                git(
                                    "log",
                                    vec![
                                        "--oneline".into(),
                                        "--no-color".into(),
                                        "-n".into(),
                                        n.to_string(),
                                    ],
                                ),
                                t,
                                OUTPUT_DEFAULT,
                            )
                            .map(exec_value)
                        }),
                    ))
                }
                "git_branch" => match s(a, "create") {
                    None => Ok(simple(
                        Some(false),
                        format!("list branches in /work/{rel}"),
                        Some(rel.clone()),
                        Some(vec!["git".into(), "branch".into()]),
                        Box::new(move |be, bx| {
                            run_in(
                                be,
                                bx,
                                &repo,
                                git(
                                    "branch",
                                    vec!["--list".into(), "--all".into(), "--no-color".into()],
                                ),
                                t,
                                OUTPUT_DEFAULT,
                            )
                            .map(exec_value)
                        }),
                    )),
                    Some(b) => {
                        if !branch_ok(b) {
                            return Err(ToolError::Invalid(
                                "that is not a usable branch name".into(),
                            ));
                        }
                        let b = b.to_string();
                        Ok(simple(
                            Some(true),
                            format!("create branch {b} in /work/{rel}"),
                            Some(b.clone()),
                            Some(vec!["git".into(), "branch".into()]),
                            Box::new(move |be, bx| {
                                run_in(be, bx, &repo, git("branch", vec![b]), t, OUTPUT_DEFAULT)
                                    .map(exec_value)
                            }),
                        ))
                    }
                },
                "git_commit" => {
                    let msg = need(a, "message")?.to_string();
                    if msg.len() > 2000 || msg.contains('\0') {
                        return Err(ToolError::Invalid("the message is too long".into()));
                    }
                    let all = flag(a, "all");
                    Ok(simple(
                        Some(true),
                        format!("commit in /work/{rel}"),
                        Some(rel.clone()),
                        Some(vec!["git".into(), "commit".into()]),
                        Box::new(move |be, bx| {
                            let mut extra = vec!["-m".to_string(), msg];
                            if all {
                                extra.insert(0, "-a".into());
                            }
                            run_in(be, bx, &repo, git("commit", extra), t, OUTPUT_DEFAULT)
                                .map(exec_value)
                        }),
                    ))
                }
                _ => {
                    let branch = need(a, "branch")?.to_string();
                    let remote = s(a, "remote").unwrap_or("origin").to_string();
                    if !branch_ok(&branch) || !safe_word(&remote, 40) || remote.contains('/') {
                        return Err(ToolError::Invalid(
                            "that is not a usable branch or remote name".into(),
                        ));
                    }
                    let protected = policy.is_protected(&branch);
                    Ok(Prepared {
                        writes: Some(true),
                        path: Some(branch.clone()),
                        command: Some(vec![
                            "git".into(),
                            "push".into(),
                            remote.clone(),
                            branch.clone(),
                        ]),
                        sensitive: protected,
                        summary: format!(
                            "git push {remote} {branch} from /work/{rel}{}",
                            if protected {
                                " (a protected branch)"
                            } else {
                                ""
                            }
                        ),
                        env: None,
                        job: Box::new(move |be, bx| {
                            run_in(
                                be,
                                bx,
                                &repo,
                                git("push", vec![remote, branch]),
                                Duration::from_secs(120),
                                OUTPUT_DEFAULT,
                            )
                            .map(exec_value)
                        }),
                    })
                }
            }
        }
        "files_read" | "files_write" | "files_list" | "files_search" => {
            let parts = path_parts(a, "path")?;
            if name != "files_list" && name != "files_search" || !parts.is_empty() {
                if let Some(why) = paths::protected(&parts) {
                    if name == "files_read" || name == "files_write" {
                        return Err(ToolError::Refused(why.into()));
                    }
                }
            }
            let rel = paths::rel(&parts);
            match name {
                "files_read" => {
                    let max =
                        num(a, "max_bytes", OUTPUT_DEFAULT as u64, 1, READ_MAX as u64)? as usize;
                    Ok(simple(
                        Some(false),
                        format!("read /work/{rel}"),
                        Some(rel.clone()),
                        None,
                        Box::new(move |be, bx| {
                            let r = be
                                .resolve(bx, &paths::join(&parts))
                                .map_err(ToolError::Refused)?;
                            if paths::protected(&r.parts).is_some() {
                                return Err(ToolError::Refused(
                                    "that file is not one an agent may read".into(),
                                ));
                            }
                            let (bytes, truncated) = be.read(bx, &r.abs, max).map_err(fail)?;
                            if bytes.contains(&0) {
                                return Err(ToolError::Invalid("that file is not text".into()));
                            }
                            Ok(
                                json!({ "path": r.rel, "content": String::from_utf8_lossy(&bytes), "truncated": truncated, "bytes": bytes.len() }),
                            )
                        }),
                    ))
                }
                "files_write" => {
                    let content = a
                        .get("content")
                        .and_then(Value::as_str)
                        .ok_or_else(|| ToolError::Invalid("content is required".into()))?
                        .to_string();
                    if content.len() > WRITE_MAX || content.contains('\0') {
                        return Err(ToolError::Invalid("the text is too long (32768 bytes at most) or not text: write a long file in parts".into()));
                    }
                    if parts.is_empty() {
                        return Err(ToolError::Invalid("name a file".into()));
                    }
                    let dirs = flag(a, "create_dirs");
                    let n = content.len();
                    Ok(simple(
                        Some(true),
                        format!("write {n} bytes to /work/{rel}"),
                        Some(rel.clone()),
                        None,
                        Box::new(move |be, bx| {
                            let r = be
                                .resolve(bx, &paths::join(&parts))
                                .map_err(ToolError::Refused)?;
                            if paths::protected(&r.parts).is_some() {
                                return Err(ToolError::Refused(
                                    "that file is not one an agent may write".into(),
                                ));
                            }
                            be.write(bx, &r.abs, content.as_bytes(), dirs)
                                .map_err(fail)?;
                            Ok(json!({ "path": r.rel, "bytes": n }))
                        }),
                    ))
                }
                "files_list" => Ok(simple(
                    Some(false),
                    format!("list /work/{rel}"),
                    Some(rel.clone()),
                    None,
                    Box::new(move |be, bx| {
                        let r = be
                            .resolve(bx, &paths::join(&parts))
                            .map_err(ToolError::Refused)?;
                        let es = be.list(bx, &r.abs, 501).map_err(fail)?;
                        let truncated = es.len() > 500;
                        let entries: Vec<Value> = es
                            .into_iter()
                            .take(500)
                            .map(|e| json!({ "name": e.name, "kind": e.kind }))
                            .collect();
                        Ok(json!({ "path": r.rel, "entries": entries, "truncated": truncated }))
                    }),
                )),
                _ => {
                    let text = need(a, "text")?.to_string();
                    if text.len() > 200 || text.contains(['\0', '\n']) {
                        return Err(ToolError::Invalid(
                            "search for a short piece of one line of text".into(),
                        ));
                    }
                    let max = num(a, "max_matches", 50, 1, 100)? as usize;
                    Ok(simple(
                        Some(false),
                        format!("search /work/{rel}"),
                        Some(rel.clone()),
                        None,
                        Box::new(move |be, bx| {
                            let r = be
                                .resolve(bx, &paths::join(&parts))
                                .map_err(ToolError::Refused)?;
                            let hits = be.search(bx, &r.abs, &text, max + 1).map_err(fail)?;
                            let truncated = hits.len() > max;
                            let matches: Vec<Value> = hits
                                .into_iter()
                                .filter(|h| {
                                    paths::normalize(&h.path)
                                        .map(|p| paths::protected(&p).is_none())
                                        .unwrap_or(false)
                                })
                                .take(max)
                                .map(|h| json!({ "path": h.path, "line": h.line, "text": h.text }))
                                .collect();
                            Ok(json!({ "path": r.rel, "matches": matches, "truncated": truncated }))
                        }),
                    ))
                }
            }
        }
        "browser_fetch" | "browser_screenshot" => {
            let url = need(a, "url")?.to_string();
            let host = check_url(&url, &perms.browser_hosts)?;
            let max = num(a, "max_bytes", OUTPUT_DEFAULT as u64, 1, OUTPUT_MAX as u64)? as usize;
            let shot = name == "browser_screenshot";
            Ok(simple(
                Some(false),
                format!("{} {url}", if shot { "screenshot" } else { "fetch" }),
                Some(host),
                None,
                Box::new(move |be, bx| {
                    if shot {
                        let out = format!("/work/.ozbox/screenshots/{}.png", ring_hex(&url));
                        let script = r#"mkdir -p /work/.ozbox/screenshots; for b in chromium chromium-browser google-chrome; do if command -v "$b" >/dev/null 2>&1; then exec "$b" --headless --disable-gpu --hide-scrollbars --window-size=1280,800 --screenshot="$1" -- "$2"; fi; done; echo "no headless browser is installed on this box" >&2; exit 127"#;
                        let o = run_in(
                            be,
                            bx,
                            &[],
                            vec![
                                "sh".into(),
                                "-c".into(),
                                script.into(),
                                "sh".into(),
                                out.clone(),
                                url,
                            ],
                            Duration::from_secs(60),
                            16 * 1024,
                        )?;
                        if o.code != Some(0) {
                            return Err(ToolError::Failed(format!(
                                "the screenshot could not be taken: {}",
                                first_line(&o.output, &o.stderr)
                            )));
                        }
                        Ok(json!({ "path": out.trim_start_matches("/work/") }))
                    } else {
                        let argv = [
                            "curl",
                            "-sS",
                            "--max-time",
                            "20",
                            "--max-redirs",
                            "0",
                            "--max-filesize",
                            "1000000",
                            "-A",
                            "ozbox-agent",
                            "-w",
                            "\n%{http_code}",
                            "--",
                            &url,
                        ]
                        .iter()
                        .map(|x| (*x).to_string())
                        .collect();
                        let o = run_in(be, bx, &[], argv, Duration::from_secs(30), max + 16)?;
                        if o.code != Some(0) {
                            return Err(ToolError::Failed(format!(
                                "the page could not be fetched: {}",
                                first_line(&o.output, &o.stderr)
                            )));
                        }
                        let (body, status) = o.output.rsplit_once('\n').unwrap_or((&o.output, "0"));
                        let mut body = body.to_string();
                        let truncated = o.truncated || body.len() > max;
                        body.truncate(max);
                        Ok(
                            json!({ "status": status.trim().parse::<u32>().unwrap_or(0), "body": body, "truncated": truncated }),
                        )
                    }
                }),
            ))
        }
        "ci_status" | "ci_logs" | "ci_rerun" => {
            let repo = path_parts(a, "repo")?;
            let rel = paths::rel(&repo);
            let run = if name == "ci_status" {
                None
            } else {
                Some(need(a, "run_id")?.to_string())
            };
            if run.as_deref().is_some_and(|r| {
                r.is_empty() || r.len() > 20 || !r.chars().all(|c| c.is_ascii_digit())
            }) {
                return Err(ToolError::Invalid("run_id is the run's number".into()));
            }
            let limit = num(a, "limit", 10, 1, 20)?;
            let failed = a
                .get("failed_only")
                .and_then(Value::as_bool)
                .unwrap_or(name == "ci_logs");
            let writes = name == "ci_rerun";
            let nm = name.to_string();
            Ok(simple(
                Some(writes),
                format!("{name} in /work/{rel}"),
                Some(rel),
                None,
                Box::new(move |be, bx| {
                    let t = Duration::from_secs(60);
                    let remote = run_in(
                        be,
                        bx,
                        &repo,
                        vec![
                            "git".into(),
                            "remote".into(),
                            "get-url".into(),
                            "origin".into(),
                        ],
                        t,
                        2048,
                    )?;
                    if remote.code != Some(0) || !remote.output.contains("github.com") {
                        return Err(ToolError::Failed(
                            "only repositories on GitHub are supported for CI so far".into(),
                        ));
                    }
                    let mut argv: Vec<String> = vec!["gh".into()];
                    match nm.as_str() {
                        "ci_status" => argv.extend(
                            [
                                "run",
                                "list",
                                "--limit",
                                &limit.to_string(),
                                "--json",
                                "databaseId,status,conclusion,name,headBranch,event,createdAt",
                            ]
                            .map(String::from),
                        ),
                        "ci_logs" => {
                            argv.extend(["run", "view"].map(String::from));
                            argv.push(run.unwrap_or_default());
                            argv.push(if failed {
                                "--log-failed".into()
                            } else {
                                "--log".into()
                            });
                        }
                        _ => {
                            argv.extend(["run", "rerun"].map(String::from));
                            argv.push(run.unwrap_or_default());
                            if failed {
                                argv.push("--failed".into());
                            }
                        }
                    }
                    let o = run_in(be, bx, &repo, argv, Duration::from_secs(90), OUTPUT_DEFAULT)?;
                    if o.code != Some(0) {
                        return Err(ToolError::Failed(format!(
                            "the CI provider's tool said: {}",
                            first_line(&o.output, &o.stderr)
                        )));
                    }
                    Ok(match serde_json::from_str::<Value>(&o.output) {
                        Ok(v) if nm == "ci_status" => json!({ "runs": v }),
                        _ => json!({ "output": o.output, "truncated": o.truncated }),
                    })
                }),
            ))
        }
        "staging_read" => {
            let project = need(a, "project")?.to_string();
            let command = need(a, "command")?.to_string();
            let env = s(a, "env").unwrap_or("staging").to_ascii_lowercase();
            if !safe_word(&project, 64)
                || !safe_word(&command, 64)
                || project.contains('/')
                || command.contains('/')
            {
                return Err(ToolError::Invalid(
                    "project and command are plain names".into(),
                ));
            }
            let production = matches!(env.as_str(), "production" | "prod" | "live");
            if !production
                && !matches!(
                    env.as_str(),
                    "staging" | "stage" | "dev" | "development" | "test"
                )
            {
                return Err(ToolError::Invalid("env is staging, dev or test".into()));
            }
            let args = strs(a, "args")?;
            Ok(Prepared {
                writes: Some(false),
                path: Some(format!("{project}/{env}")),
                command: Some(vec![
                    "ozbox".into(),
                    "env".into(),
                    "run".into(),
                    command.clone(),
                ]),
                sensitive: false,
                summary: format!("run the declared command {command} of {project} on {env}"),
                // a production request is carried to the engine as production, which refuses it without a grant
                env: Some(if production {
                    Environment::Production
                } else {
                    Environment::Staging
                }),
                job: Box::new(move |be, bx| {
                    if production {
                        return Err(ToolError::Refused(
                            "production is never read through a tool".into(),
                        ));
                    }
                    let mut argv: Vec<String> = [
                        "ozbox",
                        "env",
                        "run",
                        "--project",
                        &project,
                        "--env",
                        &env,
                        "--named",
                        &command,
                        "--",
                    ]
                    .map(String::from)
                    .into();
                    if args.is_empty() {
                        argv.push("declared".into());
                    } else {
                        argv.extend(args);
                    }
                    let o = run_in(be, bx, &[], argv, Duration::from_secs(120), OUTPUT_DEFAULT)?;
                    Ok(exec_value(o))
                }),
            })
        }
        _ => Err(ToolError::NotFound(format!("there is no tool {name}"))),
    }
}

fn ring_hex(s: &str) -> String {
    let d = ring::digest::digest(&ring::digest::SHA256, s.as_bytes());
    d.as_ref()
        .iter()
        .take(8)
        .map(|b| format!("{b:02x}"))
        .collect()
}

fn first_line(a: &str, b: &str) -> String {
    let t = if b.trim().is_empty() { a } else { b };
    t.lines()
        .find(|l| !l.trim().is_empty())
        .unwrap_or("")
        .chars()
        .take(200)
        .collect()
}

// ---- the host ------------------------------------------------------------------------------------------------------------

pub struct HostTools {
    pub store: TaskStore,
    pub backend: Arc<dyn HostBackend>,
    pub facts: Arc<dyn BoxFacts>,
    /// How long a call that asks waits for a person before it tells the agent to come back.
    pub ask_wait: Duration,
    pub poll: Duration,
    /// The browser on the box (ADR 0037). Absent, its tools say so.
    pub browser: Option<Arc<crate::browser_tools::BrowserHost>>,
    /// The door's generation: bumped every time the door ends what waiting terminal calls asked under. A call
    /// carries the generation it was admitted with and is refused if it has moved, so a card filed after the sweep, or approved
    /// just before it, cannot run under the old actor.
    pub door_gen: std::sync::atomic::AtomicU64,
}

pub const DEFAULT_ASK_WAIT: Duration = Duration::from_secs(120);

fn store_err(e: std::io::Error) -> ToolError {
    ToolError::Failed(format!("the task store could not be used: {e}"))
}

impl HostTools {
    pub fn new(store: TaskStore, backend: Arc<dyn HostBackend>, facts: Arc<dyn BoxFacts>) -> Self {
        Self {
            store,
            backend,
            facts,
            ask_wait: DEFAULT_ASK_WAIT,
            poll: Duration::from_millis(500),
            browser: None,
            door_gen: std::sync::atomic::AtomicU64::new(0),
        }
    }

    pub fn handles(&self, name: &str) -> bool {
        tool_info(name).is_some() || crate::browser_tools::is_browser_tool(name)
    }

    /// Which of the engine's views of a tool call applies to this session: the box, who is acting, and how the call is keyed.
    #[allow(clippy::type_complexity)]
    fn scope(
        &self,
        s: &Session,
        host: Option<&HostScope>,
        a: &Value,
    ) -> Result<(String, ActorKind, Option<String>, Option<String>, String), ToolError> {
        let named = s_arg(a, "box");
        let (box_name, actor, run_id, orch) = match host {
            Some(h) => {
                if let (Some(n), Some(b)) = (named, h.box_name.as_deref()) {
                    if n != b {
                        return Err(ToolError::Refused(
                            "a run can act only on its own box".into(),
                        ));
                    }
                }
                (
                    h.box_name.clone().or_else(|| named.map(str::to_string)),
                    h.actor,
                    h.run_id.clone(),
                    h.orchestration.clone(),
                )
            }
            None => (named.map(str::to_string), ActorKind::Mcp, None, None),
        };
        let box_name = box_name.ok_or_else(|| ToolError::Invalid("box is required".into()))?;
        if !self.facts.exists(&box_name) {
            return Err(ToolError::NotFound("there is no such box".into()));
        }
        // a run is keyed by its id; a door enrolment (ADR 0043) by its own key, so two programs on the box never share
        // approvals or an audit actor, and neither shares the person's own agent's key
        let key = run_id
            .clone()
            .or_else(|| host.and_then(|h| h.session.clone()))
            .unwrap_or_else(|| format!("person:{}", s.person));
        Ok((box_name, actor, run_id, orch, key))
    }

    /// End every approval that a terminal agent's call is waiting on. Called when the door is turned off, standing
    /// permission is ended early, or another person takes it over: a waiting call finds its card no longer pending, is refused
    /// by the gate, and a card a person answers afterwards has nothing to run. Only the door's own cards (`tool:terminal-`)
    /// are touched; a run's approvals and the supervisor's are not. Returns how many were ended.
    pub fn end_waiting_terminal_approvals(&self, now: u64) -> usize {
        self.store
            .update(|b| {
                let mut ended = Vec::new();
                for a in b.approvals.iter_mut().filter(|a| {
                    a.state == ApprovalState::Pending && a.task_id.starts_with("tool:terminal-")
                }) {
                    a.state = ApprovalState::Denied;
                    a.decided_by = Some(tool_gate::DOOR_WITHDRAWN.into());
                    a.decided_ms = Some(now);
                    a.delivered = true;
                    ended.push(a.id.clone());
                }
                for id in &ended {
                    b.record(now, "door", "approval.withdrawn", None, id);
                }
                ended.len()
            })
            .unwrap_or(0)
    }

    /// Whether the door has changed since this terminal call's token was issued.
    fn door_stale(
        &self,
        actor: ozbox_core::permissions::ActorKind,
        host: Option<&HostScope>,
    ) -> bool {
        actor.is_terminal()
            && host.is_some_and(|h| {
                h.door_gen != self.door_gen.load(std::sync::atomic::Ordering::SeqCst)
            })
    }

    /// Give this call's card a final state when its answer can no longer be honoured: Denied by the door, spent, and said in the
    /// audit trail, so it does not sit in the inbox as pending and cannot be spent later.
    fn withdraw_card(&self, call: &ToolCall, now: u64) {
        let (task, text) = (call.approval_task(), call.approval_text());
        let _ = self.store.update(|b| {
            let mut ended = Vec::new();
            for a in b
                .approvals
                .iter_mut()
                .filter(|a| a.task_id == task && a.action == text && !a.used)
            {
                a.state = ApprovalState::Denied;
                a.decided_by = Some(tool_gate::DOOR_WITHDRAWN.into());
                a.decided_ms = Some(now);
                a.used = true;
                ended.push(a.id.clone());
            }
            for id in &ended {
                b.record(now, "door", "approval.withdrawn", None, id);
            }
        });
    }

    /// Run one tool for a session: validate, decide, wait for a person if asked, run once, record.
    pub fn call(
        &self,
        s: &Session,
        host: Option<&HostScope>,
        name: &str,
        a: &Value,
        now: u64,
    ) -> Result<Value, ToolError> {
        let is_browser = crate::browser_tools::is_browser_tool(name);
        if tool_info(name).is_none() && !is_browser {
            return Err(ToolError::NotFound(format!("there is no tool {name}")));
        }
        if matches!(s.role, Role::Worker { .. } | Role::Conductor { .. }) && host.is_none() {
            return Err(ToolError::Refused("these tools need a run on a box".into()));
        }
        let (box_name, actor, run_id, orchestration, key) = self.scope(s, host, a)?;
        let book = self.store.load().map_err(store_err)?;
        let (mut p, extra) = if is_browser {
            let b = self.browser.as_ref().ok_or_else(|| {
                ToolError::Failed("the browser is not set up on this server".into())
            })?;
            b.prepare(
                name,
                a,
                &box_name,
                crate::browser_tools::Caller {
                    key: &key,
                    actor,
                    production: self.facts.production(&box_name),
                },
                &book.perms,
                now,
            )?
        } else {
            (
                prepare(name, a, &book.policy, &book.perms)?,
                Extra::default(),
            )
        };
        let info = tool_info(name)
            .or_else(|| crate::browser_tools::tool_info(name))
            .ok_or_else(|| ToolError::NotFound(format!("there is no tool {name}")))?;
        let env = p.env.unwrap_or(if self.facts.production(&box_name) {
            Environment::Production
        } else {
            Environment::Sandbox
        });
        let env = if p.env == Some(Environment::Staging) && env == Environment::Production {
            Environment::Production
        } else {
            env
        };
        let mut call = ToolCall {
            session_key: key,
            person: s.person.clone(),
            actor,
            box_name: Some(box_name.clone()),
            run_id,
            orchestration,
            env,
            tool: name.to_string(),
            server: info.server.to_string(),
            writes: p.writes.take(),
            path: p.path.take(),
            command: p.command.take(),
            sensitive: p.sensitive,
            summary: std::mem::take(&mut p.summary),
            baseline_allow: extra.baseline,
            person_required: extra.person_required,
            program: host.and_then(|h| h.program.clone()),
            program_pid: host.and_then(|h| h.program_pid),
            session_code: host.and_then(|h| h.code.clone()),
        };
        if let Some((why, message)) = extra.refuse {
            // the browser's own policy said no: the refusal goes in the chain like any other decision
            let _ = self.store.update(|b| {
                let actor = call.actor_label();
                b.record(
                    now,
                    &actor,
                    "permission.deny",
                    call.run_id.as_deref(),
                    &format!(
                        "tool.call tool={} server={} writes={} why={why}",
                        call.tool,
                        call.server,
                        if call.writes == Some(false) {
                            "read"
                        } else {
                            "write"
                        }
                    ),
                );
            });
            return Err(ToolError::Refused(message));
        }
        // a shell line with several commands is judged by the one that matters most
        if name == "shell" {
            call.command = pick_command(&book.perms, &call, a);
        }
        let started = Instant::now();
        let mut verdict = self
            .store
            .update(|b| tool_gate::gate(b, &call, now))
            .map_err(store_err)?;
        if let Verdict::Wait { approval_id } = &verdict {
            let id = approval_id.clone();
            while started.elapsed() < self.ask_wait {
                std::thread::sleep(self.poll);
                let decided = self
                    .store
                    .load()
                    .map_err(store_err)?
                    .approval(&id)
                    .is_none_or(|x| x.state != ApprovalState::Pending);
                if decided {
                    break;
                }
            }
            let later = now + started.elapsed().as_millis() as u64;
            // the door changed while this call waited (or before its card was filed): whatever the card says, it asked under terms
            // that no longer stand. The card is ended, approved or not, and the call refused
            if self.door_stale(call.actor, host) {
                self.withdraw_card(&call, later);
                if let (Some(b), Some(sess)) = (&self.browser, &extra.session) {
                    b.clear_waiting(sess);
                }
                return Err(ToolError::Refused(tool_gate::Refusal::Withdrawn.message()));
            }
            // the call asked under the terms it was admitted with: if a standing permission it relied on has run out while a
            // person was deciding, a card answered now cannot run it (an early end or a turn-off ends the card
            // itself, see `end_waiting_terminal_approvals`)
            if host
                .and_then(|h| h.standing_until_ms)
                .is_some_and(|until| later >= until)
            {
                self.withdraw_card(&call, later);
                if let (Some(b), Some(sess)) = (&self.browser, &extra.session) {
                    b.clear_waiting(sess);
                }
                return Err(ToolError::Refused(
                    "the standing permission this call asked under has ended while it waited, so the answer cannot run it. Ask again: it will be decided under what the person allows now".into(),
                ));
            }
            verdict = self
                .store
                .update(|b| tool_gate::gate(b, &call, later))
                .map_err(store_err)?;
        }
        match verdict {
            Verdict::Refuse(r) => {
                if let (Some(b), Some(sess)) = (&self.browser, &extra.session) {
                    b.clear_waiting(sess);
                }
                Err(ToolError::Refused(r.message()))
            }
            Verdict::Wait { approval_id } => {
                if let (Some(b), Some(sess)) = (&self.browser, &extra.session) {
                    if let Some(msg) = b.waited_too_long(sess, &box_name) {
                        return Err(ToolError::Refused(msg));
                    }
                }
                // a terminal agent's person reads this in their own engine's transcript, which the program cannot write: the code
                // here is the one to match with the card
                let which = match (call.actor.is_terminal(), call.session_code.as_deref()) {
                    (true, Some(code)) => format!(" The card names this session {code}."),
                    _ => String::new(),
                };
                Err(ToolError::Refused(format!(
                "A person has to approve this first (request {approval_id}, in Approvals).{which} It is still waiting: call this tool again with the same arguments to keep waiting."
                )))
            }
            Verdict::Run { approval } => {
                if let (Some(b), Some(sess)) = (&self.browser, &extra.session) {
                    b.clear_waiting(sess);
                }
                // the last look before anything runs, whichever gate allowed it (an approved card can be spent at the first gate
                // with no wait): if the door changed since this call's token was issued, it does not run, and the card that
                // allowed it is ended
                if self.door_stale(call.actor, host) {
                    if let Some(id) = &approval {
                        let _ = self.store.update(|b| {
                            if let Some(a) = b.approvals.iter_mut().find(|a| &a.id == id) {
                                a.state = ApprovalState::Denied;
                                a.decided_by = Some(tool_gate::DOOR_WITHDRAWN.into());
                                a.decided_ms = Some(now);
                                a.used = true;
                            }
                            b.record(now, "door", "approval.withdrawn", None, id);
                        });
                    }
                    return Err(ToolError::Refused(tool_gate::Refusal::Withdrawn.message()));
                }
                // a person decided this call's request: the job may now say so to the worker, and only with that id
                if let (Some(slot), Some(id)) = (&extra.approval, approval) {
                    *slot
                        .lock()
                        .unwrap_or_else(std::sync::PoisonError::into_inner) = Some(id);
                }
                let out = (p.job)(self.backend.as_ref(), &box_name);
                let outcome = match &out {
                    Ok(v) if v["timed_out"] == true => "timeout",
                    Ok(_) => "ok",
                    Err(ToolError::Refused(_)) => "refused",
                    Err(_) => "error",
                };
                let later = now + started.elapsed().as_millis() as u64;
                let _ = self
                    .store
                    .update(|b| tool_gate::complete(b, &call, outcome, later));
                out
            }
        }
    }
}

fn s_arg<'a>(a: &'a Value, k: &str) -> Option<&'a str> {
    s(a, k)
}

/// For a shell line with several commands, the one the engine is asked about: the strictest answer, so a rule on
/// `rm -rf` applies to `ls && rm -rf x`.
fn pick_command(perms: &PermConfig, call: &ToolCall, a: &Value) -> Option<Vec<String>> {
    let line = a.get("command").and_then(Value::as_str).unwrap_or("");
    let (segs, _) = words::segments(line);
    let rank = |e: Effect| match e {
        Effect::Deny => 2,
        Effect::Ask => 1,
        Effect::Allow => 0,
    };
    let ctx = |w: &Vec<String>| Ctx {
        person: call.person.clone(),
        actor: call.actor,
        box_name: call.box_name.clone(),
        project: None,
        run_id: call.run_id.clone(),
        orchestration: call.orchestration.clone(),
        env: call.env,
        path: call.path.clone(),
        command: Some(w.clone()),
        tool: Some(call.tool.clone()),
        server: Some(call.server.clone()),
        writes: call.writes,
        sensitive: call.sensitive,
    };
    segs.iter()
        .max_by_key(|w| {
            rank(permissions::decide(perms, &ctx(w), permissions::Action::ToolCall, 0).effect)
        })
        .cloned()
        .or_else(|| call.command.clone())
}

#[cfg(test)]
mod tests;
