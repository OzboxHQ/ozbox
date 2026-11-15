//! What the box user has running that is theirs to stop: tmux sessions, coding agents and listening dev servers.
//!
//! * `GET /v1/sessions`  -> `{ "tmux": bool, "sessions": [ { name, created_s, activity_s, attached, command } ] }`
//! * `GET /v1/processes` -> `{ "agents": [ { pid, program, age_s } ], "servers": [ { port, pid, program } ] }`
//! * `POST /v1/sessions/<name>/stop` and `POST /v1/processes/<pid>/stop` -> `{ "stopped": true }`
//!
//! Everything is an argv array through [`CommandRunner`] (no shell). Only the daemon's own user's processes are listed
//! (`ps -u <uid>`, and `ss` shows process names only for the caller's own sockets), and a stop is re-checked against a
//! fresh read: a process is stopped only if it is, right now, one of that user's agents or listening servers, and never the
//! daemon itself. A name or number typed by hand cannot stop anything else. No arguments of any process are ever read.

use std::sync::{Arc, OnceLock};

use ozbox_core::procs::{
    parse_agents, parse_servers, parse_sessions, valid_session_name, Agent, Server, Session,
    TMUX_FORMAT,
};
use ozbox_core::{CommandRunner, CommandSpec, SystemRunner};
use serde::Serialize;

use crate::http::Response;

#[derive(Debug, Serialize)]
pub struct Sessions {
    pub tmux: bool,
    pub sessions: Vec<Session>,
}

#[derive(Debug, Serialize)]
pub struct Processes {
    pub agents: Vec<Agent>,
    pub servers: Vec<Server>,
}

#[derive(Debug, PartialEq, Eq)]
pub enum StopError {
    /// The name or number is not of the right shape.
    Invalid,
    /// Not there (any more), or not the box user's: one answer for both.
    Gone,
    /// There, but not an agent or a server.
    NotStoppable,
    Failed,
}

pub struct ProcService {
    runner: Arc<dyn CommandRunner>,
    uid: OnceLock<Option<String>>,
    own_pid: u32,
}

impl ProcService {
    pub fn new(runner: Arc<dyn CommandRunner>) -> Self {
        Self {
            runner,
            uid: OnceLock::new(),
            own_pid: std::process::id(),
        }
    }

    fn run(&self, program: &str, args: &[&str]) -> Option<String> {
        let spec = CommandSpec::new(program).args(args.iter().map(|a| a.to_string()));
        let out = self.runner.run(&spec).ok()?;
        (out.status == Some(0)).then_some(out.stdout)
    }

    fn uid(&self) -> Option<String> {
        self.uid
            .get_or_init(|| {
                let out = self.run("id", &["-u"])?;
                let u = out.trim();
                (!u.is_empty() && u.bytes().all(|b| b.is_ascii_digit())).then(|| u.to_string())
            })
            .clone()
    }

    pub fn sessions(&self) -> Sessions {
        let tmux = self.run("tmux", &["-V"]).is_some();
        // No server running is a non-zero exit: no sessions, which is not an error.
        let sessions = if tmux {
            self.run("tmux", &["list-sessions", "-F", TMUX_FORMAT])
                .map(|o| parse_sessions(&o))
                .unwrap_or_default()
        } else {
            Vec::new()
        };
        Sessions { tmux, sessions }
    }

    pub fn processes(&self) -> Processes {
        let agents = self
            .uid()
            .and_then(|u| self.run("ps", &["-u", &u, "-o", "pid=,etimes=,comm="]))
            .map(|o| parse_agents(&o))
            .unwrap_or_default();
        let servers = self
            .run("ss", &["-ltnpH"])
            .map(|o| parse_servers(&o))
            .unwrap_or_default();
        Processes { agents, servers }
    }

    pub fn stop_session(&self, name: &str) -> Result<(), StopError> {
        if !valid_session_name(name) {
            return Err(StopError::Invalid);
        }
        if !self.sessions().sessions.iter().any(|s| s.name == name) {
            return Err(StopError::Gone);
        }
        // `=` makes the name exact, never a prefix.
        let target = format!("={name}");
        self.run("tmux", &["kill-session", "-t", &target])
            .map(|_| ())
            .ok_or(StopError::Failed)
    }

    pub fn stop_process(&self, pid: u32) -> Result<(), StopError> {
        if pid <= 1 || pid == self.own_pid {
            return Err(StopError::Invalid);
        }
        let procs = self.processes();
        let listens = procs.servers.iter().any(|s| s.pid == pid);
        let agent = procs.agents.iter().any(|a| a.pid == pid);
        if !listens && !agent {
            // Still the box user's own process? Then it is not one this may stop; otherwise it is gone or not theirs.
            let mine = self.uid().is_some_and(|u| {
                self.run("ps", &["-u", &u, "-o", "pid="])
                    .is_some_and(|o| o.split_whitespace().any(|p| p == pid.to_string()))
            });
            return Err(if mine {
                StopError::NotStoppable
            } else {
                StopError::Gone
            });
        }
        self.run("kill", &["-TERM", &pid.to_string()])
            .map(|_| ())
            .ok_or(StopError::Failed)
    }
}

static GLOBAL: OnceLock<ProcService> = OnceLock::new();

/// The service of this daemon, which runs the real tools.
pub fn global() -> &'static ProcService {
    GLOBAL.get_or_init(|| ProcService::new(Arc::new(SystemRunner)))
}

fn stop_answer(r: Result<(), StopError>) -> Response {
    match r {
        Ok(()) => Response::json(200, &serde_json::json!({ "stopped": true })),
        Err(StopError::Invalid) => Response::error(400, "that is not something this can stop"),
        Err(StopError::Gone) => Response::error(404, "that is not running, or it is not yours"),
        Err(StopError::NotStoppable) => Response::error(
            403,
            "that is not a coding agent or a server, so it was left alone",
        ),
        Err(StopError::Failed) => Response::error(502, "it could not be stopped"),
    }
}

/// `/v1/sessions...` and `/v1/processes...`, for any service (so tests can use a fake runner).
pub fn route(svc: &ProcService, method: &str, path: &str) -> Response {
    let not_allowed = || Response::error(405, "method not allowed");
    let rest = path.trim_end_matches('/');
    match (method, rest) {
        ("GET", "/v1/sessions") => Response::json(200, &svc.sessions()),
        ("GET", "/v1/processes") => Response::json(200, &svc.processes()),
        (_, "/v1/sessions" | "/v1/processes") => not_allowed(),
        _ => {
            let (kind, tail) = if let Some(t) = rest.strip_prefix("/v1/sessions/") {
                ("session", t)
            } else if let Some(t) = rest.strip_prefix("/v1/processes/") {
                ("process", t)
            } else {
                return Response::error(404, "not found");
            };
            let Some(id) = tail.strip_suffix("/stop") else {
                return Response::error(404, "not found");
            };
            if method != "POST" {
                return not_allowed();
            }
            if kind == "session" {
                stop_answer(svc.stop_session(id))
            } else {
                stop_answer(match id.parse::<u32>() {
                    Ok(pid) if id.bytes().all(|b| b.is_ascii_digit()) => svc.stop_process(pid),
                    _ => Err(StopError::Invalid),
                })
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ozbox_core::{Output, RecordingRunner};

    const TMUX_OUT: &str =
        "term-1\t1700000000\t1700000900\t0\tclaude\nterm-2\t1700000100\t1700000950\t1\tbash\n";
    const PS_OUT: &str = " 4242 3600 claude\n 777 20 node\n 900 5 bash\n";
    const SS_OUT: &str = "LISTEN 0 511 127.0.0.1:3000 *:* users:((\"node\",pid=777,fd=19))\n";

    fn ok(stdout: &str) -> Output {
        Output {
            status: Some(0),
            stdout: stdout.into(),
            stderr: String::new(),
        }
    }

    fn svc(replies: Vec<Output>) -> (ProcService, Arc<RecordingRunner>) {
        let r = Arc::new(RecordingRunner::new());
        for o in replies {
            r.reply(o);
        }
        (ProcService::new(r.clone()), r)
    }

    #[test]
    fn sessions_are_read_with_argv_only_and_a_missing_tmux_is_said_not_failed() {
        let (s, r) = svc(vec![ok("tmux 3.4\n"), ok(TMUX_OUT)]);
        let a = s.sessions();
        assert!(a.tmux && a.sessions.len() == 2);
        let calls = r.calls();
        assert_eq!(calls[1].program, "tmux");
        assert_eq!(calls[1].args[0], "list-sessions");
        let none = svc(vec![Output {
            status: Some(127),
            ..Output::default()
        }])
        .0
        .sessions();
        assert!(!none.tmux && none.sessions.is_empty());
        // tmux with no server running exits non-zero: no sessions
        let idle = svc(vec![
            ok("tmux 3.4\n"),
            Output {
                status: Some(1),
                ..Output::default()
            },
        ])
        .0
        .sessions();
        assert!(idle.tmux && idle.sessions.is_empty());
    }

    #[test]
    fn processes_are_the_users_agents_and_listening_servers_only() {
        let (s, r) = svc(vec![ok("1500\n"), ok(PS_OUT), ok(SS_OUT)]);
        let p = s.processes();
        assert_eq!(p.agents.len(), 1);
        assert_eq!(p.agents[0].pid, 4242);
        assert_eq!(p.servers[0].port, 3000);
        let calls = r.calls();
        assert_eq!(calls[1].args, ["-u", "1500", "-o", "pid=,etimes=,comm="]);
        assert!(calls.iter().all(|c| !c
            .args
            .iter()
            .any(|a| a.contains("args") || a.contains("cmd"))));
    }

    #[test]
    fn a_stop_is_checked_against_a_fresh_read_and_never_takes_a_name_from_a_shell() {
        // session: the name must exist now
        let (s, r) = svc(vec![ok("tmux 3.4\n"), ok(TMUX_OUT), ok("")]);
        assert_eq!(s.stop_session("term-1"), Ok(()));
        let last = r.calls().pop().unwrap();
        assert_eq!(last.args, ["kill-session", "-t", "=term-1"]);
        assert_eq!(
            svc(vec![]).0.stop_session("a b;rm"),
            Err(StopError::Invalid)
        );
        let (g, _) = svc(vec![ok("tmux 3.4\n"), ok(TMUX_OUT)]);
        assert_eq!(g.stop_session("nope"), Err(StopError::Gone));
        // process: an agent and a listening server may be stopped, with TERM and the number as one argument
        let (p, r) = svc(vec![ok("1500\n"), ok(PS_OUT), ok(SS_OUT), ok("")]);
        assert_eq!(p.stop_process(777), Ok(()));
        assert_eq!(r.calls().pop().unwrap().args, ["-TERM", "777"]);
    }

    #[test]
    fn a_process_that_is_not_an_agent_or_server_or_not_the_users_is_left_alone() {
        // 900 is the user's bash: refused, and no kill is made
        let (p, r) = svc(vec![
            ok("1500\n"),
            ok(PS_OUT),
            ok(SS_OUT),
            ok(" 900\n 4242\n"),
        ]);
        assert_eq!(p.stop_process(900), Err(StopError::NotStoppable));
        assert!(r.calls().iter().all(|c| c.program != "kill"));
        // 555 is not in the user's list at all
        let (q, r2) = svc(vec![ok("1500\n"), ok(PS_OUT), ok(SS_OUT), ok(" 900\n")]);
        assert_eq!(q.stop_process(555), Err(StopError::Gone));
        assert!(r2.calls().iter().all(|c| c.program != "kill"));
        // pid 1, 0 and the daemon itself are never candidates
        let (z, _) = svc(vec![]);
        for bad in [0u32, 1, std::process::id()] {
            assert_eq!(z.stop_process(bad), Err(StopError::Invalid));
        }
    }

    #[test]
    fn the_routes_answer_with_the_right_statuses() {
        let (s, _) = svc(vec![ok("tmux 3.4\n"), ok(TMUX_OUT)]);
        assert_eq!(route(&s, "GET", "/v1/sessions").status, 200);
        assert_eq!(route(&s, "DELETE", "/v1/sessions").status, 405);
        assert_eq!(route(&s, "GET", "/v1/sessions/term-1/stop").status, 405);
        assert_eq!(route(&s, "POST", "/v1/sessions/a;b/stop").status, 400);
        assert_eq!(route(&s, "POST", "/v1/processes/abc/stop").status, 400);
        assert_eq!(route(&s, "POST", "/v1/processes/-5/stop").status, 400);
        assert_eq!(route(&s, "POST", "/v1/processes/12").status, 404);
        let (fresh, _) = svc(vec![ok("tmux 3.4\n"), ok(TMUX_OUT)]);
        let body = String::from_utf8(route(&fresh, "GET", "/v1/sessions").body).unwrap();
        assert!(body.contains("\"tmux\":true") && body.contains("\"term-1\""));
    }
}
