//! Never simulate on a box (G7, X2).
//!
//! The simulated provider and its agent exist so a laptop can show the dashboard with made-up boxes. Three of its
//! answers are not harmless: its terminal starts a real `/bin/sh`, its files serve a real folder, and its browser and tool
//! backends run real programs, all on the machine that runs `ozbox serve`. On a laptop that machine is the demo's own, so
//! it is fine. On a box that machine is the box, and the user is the supervisor, so the same call would hand a person a
//! shell that is labelled as the box's terminal but is not the box user's, and would skip the browser's own user.
//!
//! The rule, in one place: **on a box, a simulated agent refuses a terminal, files, a browser and a stand-in server, and
//! says why.** Choosing the provider (`this_box::choose`) already keeps a box off the simulator unless its config says
//! `provider = "fake"`; this module is the second wall, for that case and for any path that builds a simulated agent
//! without going through the choice. `tests/` of the dashboard and the guard test below pin both.

use ozbox_browser::record::{Meta, Step};

use crate::browser_tools::{BrowserBackend, WorkerRun};
use crate::host_tools::backend::{Entry, ExecOut, ExecReq, Hit, HostBackend, Resolved};

/// The words a person reads when a simulated thing is refused on a box.
pub fn refusal(what: &str) -> String {
    format!(
        "This is demo data, and a box has no demo {what}. This dashboard is running on a box with the demo provider, so it refuses to start a made-up {what} on the box itself. Remove `provider = \"fake\"` from the configuration to see this box, or run the dashboard on your own computer to see the demo."
    )
}

/// The host tools of a simulated server that is running on a box: every call is refused.
pub struct RefusedHostBackend;

impl HostBackend for RefusedHostBackend {
    fn resolve(&self, _: &str, _: &str) -> Result<Resolved, String> {
        Err(refusal("tools"))
    }
    fn exec(&self, _: &str, _: &ExecReq) -> Result<ExecOut, String> {
        Err(refusal("shell"))
    }
    fn read(&self, _: &str, _: &str, _: usize) -> Result<(Vec<u8>, bool), String> {
        Err(refusal("files"))
    }
    fn write(&self, _: &str, _: &str, _: &[u8], _: bool) -> Result<(), String> {
        Err(refusal("files"))
    }
    fn list(&self, _: &str, _: &str, _: usize) -> Result<Vec<Entry>, String> {
        Err(refusal("files"))
    }
    fn search(&self, _: &str, _: &str, _: &str, _: usize) -> Result<Vec<Hit>, String> {
        Err(refusal("files"))
    }
}

/// The browser of a simulated server that is running on a box: no worker is ever started.
pub struct RefusedBrowserBackend;

impl BrowserBackend for RefusedBrowserBackend {
    fn start(&self, _: &str, _: &str, _: &WorkerRun) -> Result<String, String> {
        Err(refusal("browser"))
    }
    fn send(&self, _: &str, _: &str, _: &str) -> Result<(), String> {
        Err(refusal("browser"))
    }
    fn next_line(&self, _: &str, _: &str, _: std::time::Instant) -> Result<Option<String>, String> {
        Err(refusal("browser"))
    }
    fn stop(&self, _: &str, _: &str) {}
    fn roots(&self, _: &str) -> (String, String) {
        (String::new(), String::new())
    }
    fn list_sessions(&self, _: &str) -> Result<Vec<Meta>, String> {
        Ok(Vec::new())
    }
    fn steps(&self, _: &str, _: &str) -> Result<Vec<Step>, String> {
        Err(refusal("browser"))
    }
    fn shot(&self, _: &str, _: &str, _: &str) -> Result<Vec<u8>, String> {
        Err(refusal("browser"))
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use crate::serve::agent::{AgentError, BoxAgent, FileInput, SimulatedAgent};
    use ozbox_core::{BoxName, BoxRecord, BoxSpec, BoxState, Size};

    fn rec() -> BoxRecord {
        BoxRecord {
            spec: BoxSpec::new(BoxName::new("alpha").unwrap(), Size::S),
            state: BoxState::Running,
            provider: "fake".into(),
            provider_id: None,
            machine_type: None,
            snapshots: Vec::new(),
            created_at: None,
            last_activity_at: None,
        }
    }

    fn unsupported(e: &AgentError) -> &str {
        match e {
            AgentError::Unsupported(m) | AgentError::Unreachable(m) => m,
        }
    }

    #[test]
    fn on_a_box_the_simulated_agent_refuses_a_terminal_files_and_a_stand_in_server() {
        let a = SimulatedAgent::with_host_is_box(true);
        let r = rec();
        #[cfg(unix)]
        {
            let t = a.terminal(&r, 80, 24, None).map(|_| ()).unwrap_err();
            assert!(unsupported(&t).contains("demo terminal"), "{t}");
        }
        let f = a
            .files(
                &r,
                "GET",
                "/v1/files/list",
                &Default::default(),
                FileInput::None,
            )
            .map(|_| ())
            .unwrap_err();
        assert!(unsupported(&f).contains("demo files"), "{f}");
        let c = a.connect_tcp(&r, 8080).map(|_| ()).unwrap_err();
        assert!(unsupported(&c).contains("demo"), "{c}");
        // and nothing was made on this computer: no demo folder exists
        assert!(!a.demo_folder_exists());
    }

    #[test]
    fn off_a_box_the_simulated_agent_still_serves_its_demo() {
        let a = SimulatedAgent::with_host_is_box(false);
        let r = rec();
        assert!(a
            .files(
                &r,
                "GET",
                "/v1/files/list",
                &Default::default(),
                FileInput::None
            )
            .is_ok());
    }

    #[test]
    fn the_refused_backends_run_and_start_nothing() {
        let h = RefusedHostBackend;
        let req = ExecReq {
            argv: vec!["/bin/sh".into()],
            cwd: "/work".into(),
            timeout: std::time::Duration::from_secs(1),
            cap: 10,
            stdin: None,
        };
        assert!(h.exec("alpha", &req).unwrap_err().contains("demo"));
        let b = RefusedBrowserBackend;
        let run = WorkerRun {
            max_runtime_s: 1,
            memory_bytes: 1,
        };
        assert!(b
            .start("alpha", "{}", &run)
            .unwrap_err()
            .contains("demo browser"));
    }

    /// The guard: every place that builds a simulated shell, files or browser must be one of these files, each of which
    /// is already behind the box check. A new one fails here until it is added with its own refusal and test.
    #[test]
    fn nothing_builds_a_simulated_shell_files_or_browser_outside_the_reviewed_places() {
        let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
        let mut found: Vec<String> = Vec::new();
        let mut stack = vec![root.clone()];
        while let Some(d) = stack.pop() {
            for e in std::fs::read_dir(&d).unwrap().flatten() {
                let p = e.path();
                if p.is_dir() {
                    stack.push(p);
                } else if p.extension().is_some_and(|x| x == "rs")
                    && p.file_name().is_some_and(|n| n != "tests.rs")
                {
                    let text = std::fs::read_to_string(&p).unwrap();
                    // production text only: drop the test module, whose helpers build these on purpose
                    let prod = text.split("\nmod tests {").next().unwrap_or("");
                    for needle in [
                        "LocalBackend::new(",
                        "InProcessBackend::new(",
                        "command: vec![\"/bin/sh\"",
                        // `ozbox serve` runs as the supervisor's user: it must never start a shell of its own (G7 R3). A
                        // real box's shell is started by the box's own agent, as the box user; the only shell this program
                        // ever builds is the demo's, and that one is refused on a box first.
                        "TerminalService::new(",
                        "portable_pty",
                        "native_pty_system",
                    ] {
                        if prod.contains(needle) {
                            let rel = p
                                .strip_prefix(&root)
                                .unwrap()
                                .to_string_lossy()
                                .replace('\\', "/");
                            found.push(format!("{rel}: {needle}"));
                        }
                    }
                }
            }
        }
        found.sort();
        let allowed = [
            // behind `host_is_box` (terminal) and refused first
            "serve/agent.rs: TerminalService::new(",
            "serve/agent.rs: command: vec![\"/bin/sh\"",
            // behind `sim_on_a_box()`: the refused backends are chosen first
            "serve/orch_routes.rs: InProcessBackend::new(",
            "serve/orch_routes.rs: LocalBackend::new(",
        ];
        assert_eq!(
            found,
            allowed.iter().map(|s| s.to_string()).collect::<Vec<_>>(),
            "a simulated shell, files or browser is built in a new place: it must refuse on a box (serve/no_simulation.rs)"
        );
    }
}
