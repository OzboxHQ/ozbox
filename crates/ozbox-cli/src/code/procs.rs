//! What is running on a box that a person started: tmux sessions (where editor terminals live), coding agents, and
//! listening dev servers. Read with one fixed command and shown on the box page and in `ozbox ps`; stopping one is a
//! change, planned and confirmed like every other.
//!
//! The read prints nothing a person typed: a session's name and the program running in it, an agent's program name (never
//! its arguments, which can hold a prompt or a key), a server's port and program name.

use ozbox_core::procs::{parse_session_line, parse_ss_line, plain};
pub use ozbox_core::procs::{valid_session_name, Agent, Procs, Server, Session, AGENT_PROGRAMS};

/// Fixed text run on the box; writes nothing.
pub fn ps_script() -> String {
    let progs = AGENT_PROGRAMS.join("|");
    format!(
        "command -v tmux >/dev/null 2>&1 && echo tmux=yes || echo tmux=no\n\
         tmux list-sessions -F 'S\t#{{session_name}}\t#{{session_created}}\t#{{session_activity}}\t#{{session_attached}}\t#{{pane_current_command}}' 2>/dev/null || true\n\
         ps -u \"$(id -u)\" -o pid=,etimes=,comm= 2>/dev/null | awk '$3 ~ /^({progs})$/ {{print \"A\\t\"$1\"\\t\"$2\"\\t\"$3}}'\n\
         ss -ltnpH 2>/dev/null | sed 's/^/L\\t/' || true\n\
         echo end\n"
    )
}

pub fn parse_ps(out: &str) -> Option<Procs> {
    let mut p = Procs::default();
    let mut ended = false;
    for line in out.lines() {
        let f: Vec<&str> = line.split('\t').collect();
        match f.as_slice() {
            ["tmux=yes"] => p.tmux = true,
            ["tmux=no"] => p.tmux = false,
            ["end"] => ended = true,
            ["S", name, created, activity, attached, cmd] => {
                let row = format!("{name}\t{created}\t{activity}\t{attached}\t{cmd}");
                p.sessions.extend(parse_session_line(&row));
            }
            ["A", pid, age, prog] => {
                if let Ok(pid) = pid.trim().parse() {
                    p.agents.push(Agent {
                        pid,
                        program: plain(prog),
                        age_s: age.trim().parse().unwrap_or(0),
                    });
                }
            }
            ["L", rest] => {
                if let Some(s) = parse_ss_line(rest) {
                    if !p.servers.iter().any(|o| o.port == s.port && o.pid == s.pid) {
                        p.servers.push(s);
                    }
                }
            }
            _ => {}
        }
    }
    ended.then_some(p)
}

/// What can be stopped, by what the read showed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Stop {
    Session(String),
    Process(u32),
}

impl Stop {
    pub fn session(name: &str) -> Result<Self, String> {
        if valid_session_name(name) {
            Ok(Stop::Session(name.to_string()))
        } else {
            Err("that is not a session name".into())
        }
    }

    pub fn process(pid: u32) -> Result<Self, String> {
        if pid > 1 {
            Ok(Stop::Process(pid))
        } else {
            Err("that is not a process this can stop".into())
        }
    }

    /// The program run on the box. A process is stopped only if it is one of the box user's own agents or servers: the
    /// check is made on the box, against the same lists the read printed, so a number typed by hand cannot stop anything
    /// else.
    pub fn script(&self) -> String {
        match self {
            Stop::Session(n) => format!("tmux kill-session -t '={n}' && echo ok\n"),
            Stop::Process(pid) => {
                let progs = AGENT_PROGRAMS.join("|");
                format!(
                    "pid={pid}\n\
                     mine=$(ps -u \"$(id -u)\" -o pid=,comm= 2>/dev/null | awk -v p=$pid '$1==p {{print $2}}')\n\
                     [ -n \"$mine\" ] || {{ echo 'that process is not yours or is gone' >&2; exit 30; }}\n\
                     listens=$(ss -ltnpH 2>/dev/null | grep -c \"pid=$pid,\" || true)\n\
                     case \"$mine\" in {progs}) ok=1;; *) ok=0;; esac\n\
                     [ \"$ok\" = 1 ] || [ \"$listens\" -gt 0 ] || {{ echo 'that is not an agent or a server' >&2; exit 31; }}\n\
                     kill -TERM $pid && echo ok\n"
                )
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const OUT: &str = "tmux=yes\n\
S\tterm-1\t1700000000\t1700000900\t0\tclaude\n\
S\tterm-2\t1700000100\t1700000950\t1\tbash\n\
S\tevil name;rm\t1\t1\t0\tx\n\
A\t4242\t3600\tclaude\n\
L\tLISTEN 0 511 127.0.0.1:3000 0.0.0.0:* users:((\"node\",pid=777,fd=19))\n\
L\tLISTEN 0 128 0.0.0.0:22 0.0.0.0:* \n\
L\tLISTEN 0 511 127.0.0.1:8443 0.0.0.0:* users:((\"node\",pid=5,fd=3))\n\
L\tLISTEN 0 4096 [::1]:5173 [::]:* users:((\"vite\",pid=901,fd=22))\n\
end\n";

    #[test]
    fn the_read_is_parsed_and_only_plain_names_and_own_dev_servers_get_through() {
        let p = parse_ps(OUT).unwrap();
        assert!(p.tmux);
        assert_eq!(
            p.sessions.len(),
            2,
            "a name with a space or a semicolon is dropped"
        );
        assert_eq!(p.sessions[0].command, "claude");
        assert!(!p.sessions[0].attached && p.sessions[1].attached);
        assert_eq!(
            p.agents,
            vec![Agent {
                pid: 4242,
                program: "claude".into(),
                age_s: 3600
            }]
        );
        assert_eq!(
            p.servers,
            vec![
                Server {
                    port: 3000,
                    pid: 777,
                    program: "node".into()
                },
                Server {
                    port: 5173,
                    pid: 901,
                    program: "vite".into()
                }
            ],
            "ssh and Oz Box's own services are not dev servers"
        );
    }

    #[test]
    fn an_answer_that_never_ended_is_not_trusted_and_no_tmux_is_said() {
        assert!(parse_ps("tmux=no\nA\t1\t1\tclaude\n").is_none());
        let p = parse_ps("tmux=no\nend\n").unwrap();
        assert!(!p.tmux && p.sessions.is_empty());
    }

    #[test]
    fn the_read_writes_nothing_and_never_asks_for_arguments() {
        let s = ps_script();
        for bad in ["kill", " > ", "rm ", "args="] {
            assert!(!s.contains(bad), "{bad}");
        }
    }

    #[test]
    fn stops_take_only_plain_names_and_real_pids_and_check_on_the_box() {
        assert!(Stop::session("term-1").is_ok());
        for bad in ["", "a b", "x;y", "a'b", "../x", &"a".repeat(41)] {
            assert!(Stop::session(bad).is_err(), "{bad}");
        }
        assert!(Stop::process(1).is_err() && Stop::process(0).is_err());
        let s = Stop::process(4242).unwrap().script();
        assert!(s.contains("pid=4242") && s.contains("exit 30") && s.contains("exit 31"));
        assert!(Stop::session("term-1")
            .unwrap()
            .script()
            .contains("kill-session -t '=term-1'"));
    }
}
