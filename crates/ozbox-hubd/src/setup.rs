//! `ozbox-hubd setup <box-id>`: the hub's units and folders, written by the script carried in this program (user data has a
//! hard size limit, so the script is not in it). Run as root, once, on the box that is the hub.

use ozbox_core::{CommandRunner, CommandSpec};

/// The setup script, as shipped in `infra/cloud-init/scripts/ozbox-hub-setup.sh`.
pub const SCRIPT: &str = include_str!("../../../infra/cloud-init/scripts/ozbox-hub-setup.sh");

/// The worker's agent setup script, as shipped in `infra/cloud-init/scripts/ozbox-hub-agent-setup.sh`.
pub const AGENT_SCRIPT: &str =
    include_str!("../../../infra/cloud-init/scripts/ozbox-hub-agent-setup.sh");

/// The command that runs the agent's setup: the same shape, the script on standard input, and the words the script checks again
/// (the optional fourth is the box's task store, the file the agent queues its tasks in).
pub fn agent_spec(
    name: &str,
    addr: &str,
    fp: &str,
    tasks: Option<&str>,
) -> Result<CommandSpec, String> {
    if !ozbox_core::channel::wire::word_ok(name)
        || addr.parse::<std::net::SocketAddr>().is_err()
        || fp.is_empty()
        || !fp.bytes().all(|b| b.is_ascii_hexdigit() || b == b'-')
    {
        return Err("the worker name, the hub's address or the fingerprint is not valid".into());
    }
    let mut args = vec![
        "-s".into(),
        "--".into(),
        name.into(),
        addr.into(),
        fp.into(),
    ];
    if let Some(t) = tasks {
        if !t.starts_with('/')
            || t.contains("..")
            || !t
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"._-/".contains(&b))
        {
            return Err("the tasks file is not an absolute path of plain characters".into());
        }
        args.push(t.into());
    }
    Ok(CommandSpec {
        program: "bash".into(),
        args,
        cwd: None,
        env: Default::default(),
        stdin: Some(AGENT_SCRIPT.as_bytes().to_vec()),
        timeout_secs: Some(120),
    })
}

/// Run the agent's setup (as root, on a worker).
pub fn run_agent(
    runner: &dyn CommandRunner,
    name: &str,
    addr: &str,
    fp: &str,
    tasks: Option<&str>,
) -> Result<(), String> {
    let out = runner
        .run(&agent_spec(name, addr, fp, tasks)?)
        .map_err(|e| e.to_string())?;
    if !out.stdout.is_empty() {
        print!("{}", out.stdout);
    }
    if !out.stderr.is_empty() {
        eprint!("{}", out.stderr);
    }
    if out.status == Some(0) {
        Ok(())
    } else {
        Err("the agent could not be set up; run as root: ozbox-hubd agent-setup <name> <addr:port> <fingerprint> [tasks-file]".into())
    }
}

/// The command that runs it: `bash -s -- <box-id>`, the script on standard input, no environment added. The box id is checked
/// here and again by the script; a word that is not a box id is refused before anything runs.
pub fn spec(box_id: &str, listen: Option<&str>) -> Result<CommandSpec, String> {
    if !ozbox_core::channel::wire::word_ok(box_id) {
        return Err("the box id is not valid".into());
    }
    let mut args = vec!["-s".into(), "--".into(), box_id.to_string()];
    if let Some(l) = listen {
        // the script checks it again and refuses a wildcard or a public address; a word that is not an address is not passed at all
        if l.parse::<std::net::SocketAddr>().is_err() {
            return Err("the listen address is not an IPv4 address and a port".into());
        }
        args.push(l.to_string());
    }
    Ok(CommandSpec {
        program: "bash".into(),
        args,
        cwd: None,
        env: Default::default(),
        stdin: Some(SCRIPT.as_bytes().to_vec()),
        timeout_secs: Some(120),
    })
}

/// Run the setup. Prints what the script said; an error names how to run it again.
pub fn run(runner: &dyn CommandRunner, box_id: &str, listen: Option<&str>) -> Result<(), String> {
    let out = runner
        .run(&spec(box_id, listen)?)
        .map_err(|e| e.to_string())?;
    if !out.stdout.is_empty() {
        print!("{}", out.stdout);
    }
    if !out.stderr.is_empty() {
        eprint!("{}", out.stderr);
    }
    if out.status == Some(0) {
        Ok(())
    } else {
        Err("the hub could not be set up; run as root: ozbox-hubd setup <box-id>".into())
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn the_carried_script_runs_as_an_argv_with_the_script_on_stdin_and_a_checked_box_id() {
        let r = ozbox_core::RecordingRunner::new();
        run(&r, "main-1", None).unwrap();
        let calls = r.calls();
        assert_eq!(calls.len(), 1);
        assert_eq!(calls[0].program, "bash");
        assert_eq!(calls[0].args, ["-s", "--", "main-1"]);
        assert!(calls[0].env.is_empty());
        assert_eq!(calls[0].stdin.as_deref(), Some(SCRIPT.as_bytes()));
        for bad in ["", "a b", "x;rm -rf /", "$(id)", &"a".repeat(65)] {
            assert!(spec(bad, None).is_err(), "{bad}");
        }
        // a listen address rides as the script's second word; one that is not an address is not passed
        assert_eq!(
            spec("main-1", Some("10.0.1.5:7443")).unwrap().args,
            ["-s", "--", "main-1", "10.0.1.5:7443"]
        );
        for bad in ["", "host:1", "10.0.0.1", "$(id):1", "10.0.0.1:1;id"] {
            assert!(spec("main-1", Some(bad)).is_err(), "{bad}");
        }
    }
}
