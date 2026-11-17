//! What the dashboard's own socket to the box daemon may ask for (ADR 0040, decision 3).
//!
//! The dashboard runs as `ozbox-supervisor`, not as the box user, and reaches the daemon through a socket of its own that
//! systemd (root) binds in a folder the box user does not own, for the supervisor's group only. The dashboard is **not** a
//! member of the box user's group, so it cannot open the box socket at all: a route that is not on this table is answered
//! "not available on a box's dashboard", never sent to the box socket.
//!
//! This is the one table. The daemon enforces it; the dashboard's local agent reads it. It lives in the shared crate so the
//! two cannot drift.
//!
//! **What the table is, and is not.** It narrows the API surface: fewer routes, fewer parsers, a named audit line for each.
//! It is not a limit on authority. Run start (`POST /v1/runs` takes any command), the terminal and typing into a session
//! already act as the box user, so whoever controls the dashboard has the box user's authority through them. The file
//! writes and the checkpoint below are on the table for that reason: they add no authority that run start and the terminal
//! do not already give, and each is audited. The real protection on this socket points the other way: the box user and its
//! agents cannot reach the dashboard's process or its secrets.
//!
//! Skills on the box's own disk (`/v1/skills`) are on the table: a push writes only into the agents' skills folders, only
//! the files the dashboard sends, re-checked and re-hashed by the daemon (whether a person approved them is the dashboard's
//! check, made before it sends; the daemon cannot see an approval), and is audited. It adds no authority the
//! terminal does not already give.
//!
//! Left off, so "not available on a box's dashboard": backups (`/v1/backup`), the tool installer (`/v1/tools`), local models
//! (`/v1/local-ai`), writing agent events (`POST /v1/agent-events`, the coding agent's own hook), answering an agent's
//! permission request (`POST /v1/agent-events/permission/{id}`: no socket takes it, so no process on the box can approve its
//! own request), download links (`/v1/files/tokens`) and emptying the trash.

/// One allowed route. `path` ends in `/*` when any single-or-deeper tail is allowed under it, and a `{}` segment
/// matches exactly one non-empty segment.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Route {
    /// A stable name for the audit line (never the path itself: paths can carry ids and file names).
    pub name: &'static str,
    pub method: &'static str,
    pub path: &'static str,
}

const fn r(name: &'static str, method: &'static str, path: &'static str) -> Route {
    Route { name, method, path }
}

/// The allow-list. `HEAD` is treated as `GET` by the file API and is matched as such here.
pub const ROUTES: &[Route] = &[
    r("health", "GET", "/v1/health"),
    r("metrics_now", "GET", "/v1/metrics/now"),
    r("metrics", "GET", "/v1/metrics"),
    r("selftest_read", "GET", "/v1/selftest"),
    r("selftest_run", "POST", "/v1/selftest"),
    r("incidents", "GET", "/v1/incidents"),
    r("sessions_list", "GET", "/v1/sessions"),
    r("processes_list", "GET", "/v1/processes"),
    r("session_stop", "POST", "/v1/sessions/{}/stop"),
    r("process_stop", "POST", "/v1/processes/{}/stop"),
    r("agent_sessions_list", "GET", "/v1/agent-sessions"),
    r(
        "agent_session_capture",
        "GET",
        "/v1/agent-sessions/{}/capture",
    ),
    r("agent_session_send", "POST", "/v1/agent-sessions/{}/send"),
    r("agent_events_read", "GET", "/v1/agent-events"),
    r(
        "agent_permission_read",
        "GET",
        "/v1/agent-events/permission/{}",
    ),
    r("runs_list", "GET", "/v1/runs"),
    r("run_start", "POST", "/v1/runs"),
    r("run_log", "GET", "/v1/runs/{}/log"),
    r("run_input", "POST", "/v1/runs/{}/stdin"),
    r("run_cancel", "DELETE", "/v1/runs/{}"),
    r("files_read", "GET", "/v1/files/*"),
    r("files_write", "PUT", "/v1/files/write"),
    r("files_upload", "PUT", "/v1/files/upload"),
    r("files_mkdir", "POST", "/v1/files/mkdir"),
    r("files_rename", "POST", "/v1/files/rename"),
    r("files_delete", "POST", "/v1/files/delete"),
    r("files_restore", "POST", "/v1/files/trash/restore"),
    r("skills_read", "GET", "/v1/skills"),
    r("skill_push", "PUT", "/v1/skills/{}"),
    r("skill_remove", "DELETE", "/v1/skills/{}"),
    r("checkpoint", "POST", "/v1/checkpoint"),
    r("terminal_attach", "GET", "/v1/terminal"),
    r("terminal_audit", "GET", "/v1/terminal/audit"),
];

fn matches(pattern: &str, path: &str) -> bool {
    if let Some(prefix) = pattern.strip_suffix("/*") {
        return path
            .strip_prefix(prefix)
            .is_some_and(|t| t.starts_with('/') && t.len() > 1);
    }
    let mut p = pattern.split('/');
    let mut q = path.split('/');
    loop {
        match (p.next(), q.next()) {
            (None, None) => return true,
            (Some("{}"), Some(seg)) if !seg.is_empty() => {}
            (Some(a), Some(b)) if a == b => {}
            _ => return false,
        }
    }
}

/// The allowed route for this request, or `None` (refuse it). `path` is the path without its query; a trailing slash is
/// ignored. A `..` or empty segment never matches a `{}` or `/*` tail, so a crafted path cannot slip past a prefix.
pub fn allowed(method: &str, path: &str) -> Option<&'static Route> {
    let path = if path.len() > 1 {
        path.trim_end_matches('/')
    } else {
        path
    };
    if path
        .split('/')
        .skip(1)
        .any(|s| s.is_empty() || s == ".." || s == ".")
    {
        return None;
    }
    let method = if method == "HEAD" { "GET" } else { method };
    ROUTES
        .iter()
        .find(|r| r.method == method && matches(r.path, path))
}

/// Whether the peer of the second socket is the one user allowed on it: exactly the supervisor's uid. An unknown peer
/// (the platform cannot say, or the name did not resolve) is refused: this fails closed.
pub fn peer_is_supervisor(peer_uid: Option<u32>, supervisor_uid: Option<u32>) -> bool {
    matches!((peer_uid, supervisor_uid), (Some(p), Some(s)) if p == s)
}

/// The `(uid, gid)` of `name` from the text of an `/etc/passwd`.
pub fn passwd_ids(passwd: &str, name: &str) -> Option<(u32, u32)> {
    passwd.lines().find_map(|l| {
        let mut f = l.split(':');
        if f.next()? != name {
            return None;
        }
        let _pw = f.next()?;
        let uid = f.next()?.parse().ok()?;
        let gid = f.next()?.parse().ok()?;
        Some((uid, gid))
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_dashboards_surface_is_allowed_and_names_a_route() {
        for (m, p, n) in [
            ("GET", "/v1/health", "health"),
            ("POST", "/v1/runs", "run_start"),
            ("GET", "/v1/runs", "runs_list"),
            ("GET", "/v1/runs/abc123/log", "run_log"),
            ("POST", "/v1/runs/abc123/stdin", "run_input"),
            ("DELETE", "/v1/runs/abc123", "run_cancel"),
            ("GET", "/v1/files/list", "files_read"),
            ("HEAD", "/v1/files/download", "files_read"),
            ("GET", "/v1/terminal", "terminal_attach"),
            ("PUT", "/v1/files/upload", "files_upload"),
            ("PUT", "/v1/files/write", "files_write"),
            ("POST", "/v1/files/delete", "files_delete"),
            ("POST", "/v1/checkpoint", "checkpoint"),
            ("GET", "/v1/skills", "skills_read"),
            ("PUT", "/v1/skills/demo", "skill_push"),
            ("DELETE", "/v1/skills/demo", "skill_remove"),
            (
                "GET",
                "/v1/agent-sessions/term-1/capture",
                "agent_session_capture",
            ),
            ("GET", "/v1/metrics/", "metrics"),
        ] {
            assert_eq!(allowed(m, p).map(|r| r.name), Some(n), "{m} {p}");
        }
    }

    #[test]
    fn what_only_the_box_user_may_do_is_refused() {
        for (m, p) in [
            ("GET", "/v1/backup"),
            ("POST", "/v1/backup/run"),
            ("POST", "/v1/tools/install"),
            ("GET", "/v1/tools"),
            ("POST", "/v1/local-ai/pull"),
            ("POST", "/v1/agent-events"),
            ("POST", "/v1/files/trash/empty"),
            ("POST", "/v1/files/tokens"),
            ("DELETE", "/v1/files/tokens/abc"),
            ("POST", "/v1/agent-events/permission/abc"),
            ("DELETE", "/v1/files/trash"),
            ("POST", "/v1/terminal"),
            ("POST", "/v1/skills"),
            ("PUT", "/v1/skills"),
            ("PUT", "/v1/skills/a/b"),
            ("GET", "/v1/skills/demo"),
            ("DELETE", "/v1/runs"),
            ("GET", "/v1/runs/abc"),
            ("GET", "/"),
            ("GET", "/v1"),
            ("GET", "/v1/filesx"),
            ("GET", "/v1/files"),
        ] {
            assert!(allowed(m, p).is_none(), "{m} {p} must be refused");
        }
    }

    #[test]
    fn a_crafted_path_cannot_slip_past_a_prefix_or_a_wildcard_segment() {
        for p in [
            "/v1/files/../backup",
            "/v1/files//x",
            "/v1/runs//log",
            "/v1/runs/../checkpoint",
            "/v1/runs/a/b/log",
            "/v1/sessions//stop",
        ] {
            assert!(
                allowed("GET", p).is_none() && allowed("POST", p).is_none(),
                "{p}"
            );
        }
    }

    #[test]
    fn only_the_supervisors_uid_is_admitted_and_unknown_fails_closed() {
        assert!(peer_is_supervisor(Some(998), Some(998)));
        assert!(!peer_is_supervisor(Some(1500), Some(998)));
        assert!(!peer_is_supervisor(None, Some(998)));
        assert!(!peer_is_supervisor(Some(998), None));
        assert!(!peer_is_supervisor(None, None));
    }

    #[test]
    fn the_supervisors_ids_are_read_from_passwd() {
        let t = "root:x:0:0::/root:/bin/bash\nozbox:x:1500:1500::/work:/bin/bash\nozbox-supervisor:x:996:995::/h:/usr/sbin/nologin\n";
        assert_eq!(passwd_ids(t, "ozbox-supervisor"), Some((996, 995)));
        assert_eq!(passwd_ids(t, "ozbox"), Some((1500, 1500)));
        assert_eq!(passwd_ids(t, "nobody"), None);
        assert_eq!(passwd_ids("garbage", "ozbox"), None);
    }
}
