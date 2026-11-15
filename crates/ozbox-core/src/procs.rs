//! What is running on a box that its user started: tmux sessions (where editor terminals live), coding agents and
//! listening dev servers. These are the shapes the box daemon answers with (`GET /v1/sessions`, `GET /v1/processes`) and
//! the command line and dashboard show, plus the pure readers for the three tools the daemon asks (tmux, ps, ss).
//!
//! Nothing a person typed is read: a session's name and the program in its active pane, an agent's program name (never its
//! arguments, which can hold a prompt or a key), a server's port and program name. Every field is additive: a new one may
//! be added, none renamed.

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Session {
    pub name: String,
    pub created_s: u64,
    /// Unix time of the last activity in the session.
    pub activity_s: u64,
    pub attached: bool,
    /// The program running in the session's active pane.
    pub command: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Agent {
    pub pid: u32,
    pub program: String,
    pub age_s: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Server {
    pub port: u16,
    pub pid: u32,
    pub program: String,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Procs {
    /// tmux is on the box: without it terminals end with their tab.
    pub tmux: bool,
    pub sessions: Vec<Session>,
    pub agents: Vec<Agent>,
    pub servers: Vec<Server>,
}

/// The programs counted as coding agents.
pub const AGENT_PROGRAMS: [&str; 6] = ["claude", "codex", "gemini", "aider", "opencode", "goose"];

/// Ports that belong to Oz Box's own services or to SSH are not "dev servers".
pub const OWN_PORTS: [u16; 3] = [22, 8443, 8444];

/// The `-F` format `tmux list-sessions` is asked for; [`parse_session_line`] reads it.
pub const TMUX_FORMAT: &str = "#{session_name}\t#{session_created}\t#{session_activity}\t#{session_attached}\t#{pane_current_command}";

/// A tmux session name is plain: letters, digits, `_` and `-`, at most 40 characters.
pub fn valid_session_name(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 40
        && name
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
}

/// A program name as shown: no control characters, at most 60.
pub fn plain(s: &str) -> String {
    s.chars().filter(|c| !c.is_control()).take(60).collect()
}

/// One line of `tmux list-sessions -F TMUX_FORMAT`. A name that is not plain is dropped.
pub fn parse_session_line(line: &str) -> Option<Session> {
    let f: Vec<&str> = line.split('\t').collect();
    let [name, created, activity, attached, cmd] = f.as_slice() else {
        return None;
    };
    valid_session_name(name).then(|| Session {
        name: (*name).into(),
        created_s: created.trim().parse().unwrap_or(0),
        activity_s: activity.trim().parse().unwrap_or(0),
        attached: attached.trim() != "0",
        command: plain(cmd),
    })
}

/// The sessions in the output of `tmux list-sessions -F TMUX_FORMAT`.
pub fn parse_sessions(out: &str) -> Vec<Session> {
    out.lines().filter_map(parse_session_line).collect()
}

/// The coding agents in the output of `ps -u <uid> -o pid=,etimes=,comm=`.
pub fn parse_agents(out: &str) -> Vec<Agent> {
    out.lines()
        .filter_map(|l| {
            let mut it = l.split_whitespace();
            let (pid, age, comm) = (it.next()?, it.next()?, it.next()?);
            if !AGENT_PROGRAMS.contains(&comm) {
                return None;
            }
            Some(Agent {
                pid: pid.parse().ok()?,
                program: plain(comm),
                age_s: age.parse().unwrap_or(0),
            })
        })
        .collect()
}

/// `users:(("node",pid=1234,fd=19))` -> (node, 1234).
fn owner_of(users: &str) -> Option<(String, u32)> {
    let rest = users.split("((\"").nth(1)?;
    let (name, after) = rest.split_once('"')?;
    let pid = after
        .split("pid=")
        .nth(1)?
        .split([',', ')'])
        .next()?
        .parse()
        .ok()?;
    Some((plain(name), pid))
}

/// One line of `ss -ltnpH` (state, recv-q, send-q, local, peer, process).
pub fn parse_ss_line(line: &str) -> Option<Server> {
    let cols: Vec<&str> = line.split_whitespace().collect();
    let (local, users) = (cols.get(3)?, cols.get(5)?);
    let port = local.rsplit(':').next()?.parse::<u16>().ok()?;
    let (program, pid) = owner_of(users)?;
    (!OWN_PORTS.contains(&port)).then_some(Server { port, pid, program })
}

/// The dev servers in the output of `ss -ltnpH`, one per port and process.
pub fn parse_servers(out: &str) -> Vec<Server> {
    let mut v: Vec<Server> = Vec::new();
    for s in out.lines().filter_map(parse_ss_line) {
        if !v.iter().any(|o| o.port == s.port && o.pid == s.pid) {
            v.push(s);
        }
    }
    v
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sessions_agents_and_servers_are_read_and_only_plain_ones_get_through() {
        let s = parse_sessions(
            "term-1\t1700000000\t1700000900\t0\tclaude\nterm-2\t1700000100\t1700000950\t1\tbash\nevil name;rm\t1\t1\t0\tx\nshort\t1\n",
        );
        assert_eq!(s.len(), 2, "a name with a space or a semicolon is dropped");
        assert!(!s[0].attached && s[1].attached);
        assert_eq!(
            (s[0].created_s, s[0].activity_s),
            (1_700_000_000, 1_700_000_900)
        );
        let a = parse_agents("  4242  3600 claude\n  1 5 systemd\n 99 7 node\n");
        assert_eq!(
            a,
            vec![Agent {
                pid: 4242,
                program: "claude".into(),
                age_s: 3600
            }]
        );
        let v = parse_servers(
            "LISTEN 0 511 127.0.0.1:3000 0.0.0.0:* users:((\"node\",pid=777,fd=19))\n\
             LISTEN 0 128 0.0.0.0:22 0.0.0.0:* \n\
             LISTEN 0 511 127.0.0.1:8443 0.0.0.0:* users:((\"node\",pid=5,fd=3))\n\
             LISTEN 0 4096 [::1]:5173 [::]:* users:((\"vite\",pid=901,fd=22))\n\
             LISTEN 0 4096 0.0.0.0:5173 0.0.0.0:* users:((\"vite\",pid=901,fd=22))\n",
        );
        assert_eq!(
            v,
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
                },
            ],
            "ssh and Oz Box's own services are not dev servers; one row per port and process"
        );
    }

    #[test]
    fn session_names_are_checked_the_same_everywhere() {
        assert!(valid_session_name("term-1") && valid_session_name("ozbox_2"));
        for bad in ["", "a b", "x;y", "a'b", "../x", &"a".repeat(41)] {
            assert!(!valid_session_name(bad), "{bad}");
        }
    }
}
