//! `ozbox-hubd setup <box-id>`: the hub's units and folders, written by the script carried in this program (user data has a
//! hard size limit, so the script is not in it). Run as root, once, on the box that is the hub.

use ozbox_core::{CommandRunner, CommandSpec};

/// The setup script, as shipped in `infra/cloud-init/scripts/ozbox-hub-setup.sh`.
pub const SCRIPT: &str = include_str!("../../../infra/cloud-init/scripts/ozbox-hub-setup.sh");

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
