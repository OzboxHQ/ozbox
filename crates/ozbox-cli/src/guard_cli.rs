//! `ozbox guard install | hook`. The hook half is what git runs; it prints only files, lines and rules.

use std::io::BufRead;
use std::path::Path;

use crate::cli::GuardCommand;
use crate::guard::{self, Scanner};
use crate::guard_hold;
use crate::run::CliError;

/// The stored-value scanner: the box's service, `None` on a laptop that has none, and an error on a box whose service is gone
/// (said out loud, never a quiet shapes-only check).
fn scanner() -> Result<Option<Box<dyn Scanner>>, String> {
    #[cfg(unix)]
    {
        guard::ServiceScanner::connect().map(|o| o.map(|s| Box::new(s) as Box<dyn Scanner>))
    }
    #[cfg(not(unix))]
    {
        Ok(None)
    }
}

/// The box socket the hooks file requests on. A box's is its own, whatever the environment says.
#[cfg(unix)]
fn box_socket() -> std::path::PathBuf {
    guard::socket_path(
        guard::on_box(),
        std::env::var("OZBOX_SECRET_SOCKET").ok(),
        crate::tunnel::unit::SECRET_SOCKET,
    )
}

pub fn run(c: &GuardCommand, json: bool) -> Result<(), CliError> {
    match c {
        GuardCommand::Install { root } => {
            let r = guard::install_all(root);
            if json {
                println!(
                    "{}",
                    serde_json::json!({"repositories": r.repos, "hooks_written": r.written, "hooks_restored": r.healed})
                );
            } else {
                println!(
                    "{} repositories, {} hooks written, {} put back",
                    r.repos, r.written, r.healed
                );
            }
            Ok(())
        }
        GuardCommand::Wait { id } => wait(id, json),
        GuardCommand::Hook { name, args } => hook(name, args),
    }
}

/// One request line to the box socket, waiting out a service that is restarting. A service that is restarting is waited for,
/// with a back-off (1 s, doubling to 10 s) for about a minute, and the wait stays on the failure path: a poll that works costs
/// nothing extra. Only a service that did not answer is waited for: a refusal is an answer, and fails at once.
#[cfg(unix)]
fn box_call<'a>(
    svc: &'a crate::secrets_service::SocketSecrets,
    stop: &'a std::sync::Arc<std::sync::atomic::AtomicBool>,
) -> impl FnMut(&serde_json::Value) -> Result<serde_json::Value, String> + 'a {
    move |v: &serde_json::Value| {
        let mut delay_ms = 1_000u64;
        let mut waited_ms = 0u64;
        loop {
            match svc
                .call(v.clone())
                .map(|r| r["result"].clone())
                .map_err(|e| e.0)
            {
                Ok(r) => return Ok(r),
                Err(e) => {
                    if !worth_waiting(
                        &e,
                        waited_ms,
                        stop.load(std::sync::atomic::Ordering::SeqCst),
                    ) {
                        return Err(e);
                    }
                    let mut slept = 0;
                    while slept < delay_ms && !stop.load(std::sync::atomic::Ordering::SeqCst) {
                        std::thread::sleep(std::time::Duration::from_millis(200));
                        slept += 200;
                    }
                    waited_ms += delay_ms;
                    delay_ms = (delay_ms * 2).min(10_000);
                }
            }
        }
    }
}

/// The box socket's client, with Ctrl-C wired the way `ozbox guard wait` has it (a second one ends the process at once).
#[cfg(unix)]
fn box_client() -> (
    crate::secrets_service::SocketSecrets,
    std::sync::Arc<std::sync::atomic::AtomicBool>,
) {
    use std::sync::atomic::AtomicBool;
    use std::sync::Arc;
    let svc = crate::secrets_service::SocketSecrets::new(box_socket());
    let stop = Arc::new(AtomicBool::new(false));
    let _ = signal_hook::flag::register_conditional_shutdown(
        signal_hook::consts::SIGINT,
        130,
        Arc::clone(&stop),
    );
    let _ = signal_hook::flag::register(signal_hook::consts::SIGINT, Arc::clone(&stop));
    (svc, stop)
}

/// The waiting hook (ADR 0041 §6) on the box socket: wait for `id`, long poll by long poll.
#[cfg(unix)]
fn wait(id: &str, json: bool) -> Result<(), CliError> {
    use crate::approval_wait::{wait_for_decision, Waited};
    let (svc, stop) = box_client();
    let start = std::time::Instant::now();
    let mut call = box_call(&svc, &stop);
    let out = wait_for_decision(
        &mut call,
        id,
        &|| u64::try_from(start.elapsed().as_millis()).unwrap_or(u64::MAX),
        &mut |l| eprintln!("{l}"),
        &stop,
    );
    match out {
        Waited::Approved { digest } => {
            if json {
                println!(
                    "{}",
                    serde_json::json!({"approved": true, "digest": digest})
                );
            } else {
                println!("{digest}");
            }
            Ok(())
        }
        Waited::Refused(m) | Waited::GaveUp(m) => Err(CliError::Msg(m)),
        Waited::Stopped => Err(CliError::Msg(
            "stopped waiting; the request stays for 30 minutes".into(),
        )),
    }
}

/// Whether a failed poll is waited out: only when the service did not answer, within a minute, and nobody pressed Ctrl-C.
#[cfg(unix)]
fn worth_waiting(err: &str, waited_ms: u64, stopped: bool) -> bool {
    crate::secrets_service::is_no_answer(err) && waited_ms < 60_000 && !stopped
}

#[cfg(all(test, unix))]
mod wait_tests {
    use super::worth_waiting;

    #[test]
    fn only_a_service_that_did_not_answer_is_waited_for() {
        for down in [
            crate::secrets_service::SERVICE_DOWN,
            crate::secrets_service::SERVICE_NO_ANSWER,
        ] {
            assert!(worth_waiting(down, 0, false));
            assert!(!worth_waiting(down, 60_000, false));
            assert!(!worth_waiting(down, 0, true));
        }
        let down = crate::secrets_service::SERVICE_DOWN;
        assert!(worth_waiting(down, 0, false));
        assert!(!worth_waiting(down, 60_000, false));
        assert!(!worth_waiting(down, 0, true));
        // a refusal is an answer: it fails at once, not after a minute of back-off
        for refusal in [
            "that is not allowed on this socket",
            "no request with that id",
        ] {
            assert!(!worth_waiting(refusal, 0, false));
        }
    }
}

#[cfg(not(unix))]
fn wait(_: &str, _: bool) -> Result<(), CliError> {
    Err(CliError::Msg("waiting for a request is for a box".into()))
}

fn blocked(msg: String) -> Result<(), CliError> {
    eprint!("{msg}");
    std::process::exit(1);
}

/// What `post-commit` prints when the box's secrets service did not answer (`why`): the check it can still do (shapes, file names,
/// `.env` files), the commit taken back if it fails, and the plain statement that stored values were not looked for.
pub(crate) fn post_commit_unscanned(repo: &Path, why: &str) -> String {
    let mut out = match guard_hold::post_commit(repo, None) {
        Ok(Some(m)) => m,
        Ok(None) => String::new(),
        Err(e) => format!("ozbox: the barrier could not check the commit just made ({e}).\n"),
    };
    out.push_str(&format!(
        "ozbox: stored keys were not checked in the commit just made ({why}); the push will check them again.\n"
    ));
    out
}

fn hook(name: &str, args: &[String]) -> Result<(), CliError> {
    let repo = std::env::current_dir().map_err(|_| CliError::Msg("no working folder".into()))?;
    let code = std::env::var("OZBOX_GUARD_APPROVAL").unwrap_or_default();
    let s = scanner();
    // A box whose secrets service is not there cannot check stored keys. `post-commit` cannot stop a commit, so it still checks
    // what it can (the shapes of keys, the names of files and `.env` files) and says the stored values were not checked; the
    // push will check them again. `pre-commit` and `pre-push` degrade as ADR 0029 Amendment 15 says (see `guard_hold`).
    if let (Err(e), "post-commit") = (&s, name) {
        eprint!("{}", post_commit_unscanned(&repo, e));
        return Ok(());
    }
    // A change the barrier cannot check is stopped rather than let through. A failure names what could not be read when it is a
    // file or a commit (trying again will not help); a service that is busy is a moment's wait.
    let unreachable = |e: String| {
        blocked(format!(
            "ozbox: the barrier could not check this change ({e}), so it was stopped. If a commit or file is named, that is what could not be read; otherwise try again in a moment.\n"
        ))
    };
    let sc: Result<Option<&dyn Scanner>, String> = match &s {
        Ok(o) => Ok(o.as_deref()),
        Err(e) => Err(e.clone()),
    };
    match name {
        "pre-commit" => {
            match with_flow(|flow| guard_hold::pre_commit_or_degrade(&repo, sc, &code, flow)) {
                Ok(guard_hold::Degraded::Pass(note)) => {
                    if let Some(n) = note {
                        eprint!("{n}");
                    }
                    Ok(())
                }
                Ok(guard_hold::Degraded::Stop(m)) => blocked(m),
                Err(e) => unreachable(e),
            }
        }
        // after the commit exists; the exit status no longer matters to git, the message does
        "post-commit" => match guard_hold::post_commit(&repo, sc.ok().flatten()) {
            Ok(Some(m)) => {
                eprint!("{m}");
                Ok(())
            }
            Ok(None) => Ok(()),
            // never a quiet skip: the commit stands, and what could not be read is said (the push reads it again)
            Err(e) => {
                eprintln!("ozbox: the barrier could not check the commit just made ({e}); the push will check it again.");
                Ok(())
            }
        },
        "pre-push" => pre_push(&repo, args, sc, &code),
        _ => Ok(()),
    }
}

/// Run `f` with the request side of the hook: the box socket, the clock, stderr, and Ctrl-C. On a machine with no box socket (a
/// laptop) there is no flow, and a held change is stopped with the words for a code.
fn with_flow<T>(f: impl FnOnce(Option<&mut guard_hold::Flow<'_>>) -> T) -> T {
    #[cfg(unix)]
    {
        let path = box_socket();
        if path.exists() {
            let (svc, stop) = box_client();
            let start = std::time::Instant::now();
            let mut call = box_call(&svc, &stop);
            let elapsed = || u64::try_from(start.elapsed().as_millis()).unwrap_or(u64::MAX);
            let mut say = |l: &str| eprintln!("{l}");
            let stop_ref = &stop;
            let pause = |ms: u64| {
                let mut slept = 0;
                while slept < ms && !stop_ref.load(std::sync::atomic::Ordering::SeqCst) {
                    std::thread::sleep(std::time::Duration::from_millis(200));
                    slept += 200;
                }
            };
            let mut flow = guard_hold::Flow {
                call: &mut call,
                elapsed_ms: &elapsed,
                say: &mut say,
                stop: &stop,
                pause: &pause,
            };
            return f(Some(&mut flow));
        }
        if guard::on_box() {
            eprintln!("ozbox: this box's secrets service is not answering on its request socket, so a held change cannot ask a person.");
        }
    }
    f(None)
}

fn pre_push(
    repo: &Path,
    args: &[String],
    sc: Result<Option<&dyn Scanner>, String>,
    code: &str,
) -> Result<(), CliError> {
    // git gives the remote's name and address as arguments, and one line a ref on standard input:
    // local ref, local sha, remote ref, remote sha; a deletion pushes a zero sha
    let url = args
        .get(1)
        .or_else(|| args.first())
        .cloned()
        .unwrap_or_default();
    let remote = args.first().cloned().unwrap_or_default();
    let mut refs = Vec::new();
    for line in std::io::stdin().lock().lines().map_while(Result::ok) {
        let f: Vec<&str> = line.split_whitespace().collect();
        let (Some(remote_ref), Some(new), Some(old)) = (f.get(2), f.get(1), f.get(3)) else {
            continue;
        };
        if new.bytes().all(|b| b == b'0') {
            continue;
        }
        refs.push(guard_hold::PushedRef {
            remote_ref: (*remote_ref).to_string(),
            old: (*old).to_string(),
            new: (*new).to_string(),
        });
    }
    if refs.is_empty() {
        return Ok(());
    }
    match with_flow(|flow| {
        guard_hold::pre_push_or_degrade(repo, &remote, &url, &refs, sc, code, flow)
    }) {
        Ok(guard_hold::Degraded::Pass(_)) => Ok(()),
        Ok(guard_hold::Degraded::Stop(m)) => blocked(m),
        Err(e) => blocked(format!(
            "ozbox: the barrier could not check this push ({e}).\n"
        )),
    }
}
