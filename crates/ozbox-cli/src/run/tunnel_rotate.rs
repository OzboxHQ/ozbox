//! `ozbox admin <box> -- replace-tunnel-token <cloudflare|ngrok|ide> (--token-stdin | --token-from-store NAME)
//! [--approve-with-laptop-key]`: put a new tunnel token on a box, keep the old one until the new tunnel is healthy, and put the
//! old one back if it is not (ADR 0029 Amendment 19).
//!
//! The token is a secret all the way: it is read from standard input or from this computer's secret store (never an argument),
//! handed to the box the way `ozbox dashboard install` hands it (inside the script on the SSH connection's standard input,
//! written by the box user to a private file the root helper reads once and removes), and kept on this computer only in the
//! secret store, replacing the old one only once the new tunnel is healthy. It is in no argument, plan, report, log or error.
//!
//! "Healthy" is what the box can say without a network test of its own: the tunnel's service is running some seconds after the
//! helper restarted it, and systemd has not had to start it again (a refused token makes the connector exit, and systemd then
//! restarts it). The Cloudflare side is the person's: once this says the new tunnel is healthy, they revoke the old token there
//! (the use case says how). Nothing here holds a Cloudflare credential.

use std::io::BufRead;

use ozbox_core::{BoxName, CommandRunner, CommandSpec};
use zeroize::Zeroizing;

use crate::messages::t;
use crate::secrets::SecretStore;

/// Which tunnel's token.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Which {
    Cloudflare,
    Ngrok,
    Ide,
}

impl Which {
    pub fn id(self) -> &'static str {
        match self {
            Which::Cloudflare => "cloudflare",
            Which::Ngrok => "ngrok",
            Which::Ide => "ide",
        }
    }

    /// The unit the box's root helper restarts after it stores the token.
    pub fn unit(self) -> &'static str {
        match self {
            Which::Ide => "ozbox-code-connector.service",
            Which::Cloudflare | Which::Ngrok => "ozbox-cloudflared.service",
        }
    }

    /// Where this computer keeps the token in use (the same names `ozbox dashboard install` and `ozbox code` keep it under).
    pub fn kept_name(self, box_name: &str) -> String {
        match self {
            Which::Ide => crate::code::Service::connector_secret_name(box_name),
            Which::Cloudflare | Which::Ngrok => crate::dashboard_keep::token_name(box_name),
        }
    }
}

/// Where the new token comes from. Never an argument.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Source {
    Stdin,
    /// A name in this computer's secret store.
    Store(String),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Request {
    pub which: Which,
    pub source: Source,
    pub approve_with_laptop_key: bool,
}

/// Read the words after `replace-tunnel-token`. A word that is not one of the flags is refused, and the refusal never repeats
/// it (it may be a token pasted by mistake).
pub fn parse(rest: &[String]) -> Result<Request, String> {
    let (which, flags) = rest
        .split_first()
        .ok_or_else(|| t("rotate.err_usage", &[]))?;
    let which = match which.as_str() {
        "cloudflare" => Which::Cloudflare,
        "ngrok" => Which::Ngrok,
        "ide" => Which::Ide,
        _ => return Err(t("rotate.err_usage", &[])),
    };
    let mut source = None;
    let mut laptop = false;
    let mut it = flags.iter();
    while let Some(f) = it.next() {
        match f.as_str() {
            "--token-stdin" if source.is_none() => source = Some(Source::Stdin),
            "--token-from-store" if source.is_none() => {
                let name = it
                    .next()
                    .filter(|n| store_name_ok(n))
                    .ok_or_else(|| t("rotate.err_store_name", &[]))?;
                source = Some(Source::Store(name.clone()))
            }
            "--approve-with-laptop-key" => laptop = true,
            "--token-stdin" | "--token-from-store" => return Err(t("rotate.err_one_source", &[])),
            _ => return Err(t("rotate.err_arg", &[])),
        }
    }
    Ok(Request {
        which,
        source: source.ok_or_else(|| t("rotate.err_no_source", &[]))?,
        approve_with_laptop_key: laptop,
    })
}

/// A name in this computer's secret store: lowercase letters, digits, dots, dashes and underscores.
fn store_name_ok(n: &str) -> bool {
    (1..=128).contains(&n.len())
        && n.bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b"._-".contains(&b))
}

/// The shape the box's root helper accepts for a tunnel token (`ozbox-admin.sh`): no quote, space or shell character.
pub fn token_shape_ok(tok: &str) -> bool {
    (20..=2048).contains(&tok.len())
        && tok
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"+/=_.-".contains(&b))
}

/// Read the new token: the first line of standard input, or the named entry of the secret store.
pub fn read_token(
    source: &Source,
    input: &mut dyn BufRead,
    store: &dyn SecretStore,
) -> Result<Zeroizing<String>, String> {
    let tok = match source {
        Source::Stdin => {
            let mut line = Zeroizing::new(String::new());
            input
                .read_line(&mut line)
                .map_err(|_| t("rotate.err_read", &[]))?;
            Zeroizing::new(line.trim().to_string())
        }
        Source::Store(name) => Zeroizing::new(
            store
                .get(name)
                .map_err(|_| t("rotate.err_read", &[]))?
                .ok_or_else(|| t("rotate.err_store_missing", &[("name", name)]))?
                .trim()
                .to_string(),
        ),
    };
    if !token_shape_ok(&tok) {
        return Err(t("rotate.err_shape", &[]));
    }
    Ok(tok)
}

/// What the plan says, in lines. Pure, and holds no token.
pub fn plan_lines(box_name: &str, which: Which, has_old: bool, same: bool) -> Vec<String> {
    let a = [
        ("box", box_name),
        ("tunnel", which.id()),
        ("unit", which.unit()),
    ];
    if same {
        return vec![t("rotate.plan_same", &a)];
    }
    let mut v = vec![t("rotate.plan_send", &a), t("rotate.plan_watch", &a)];
    v.push(if has_old {
        t("rotate.plan_rollback", &a)
    } else {
        t("rotate.plan_no_rollback", &a)
    });
    v.push(t("rotate.plan_keep", &a));
    v.push(t("rotate.plan_revoke", &a));
    v
}

/// How the attempt ended.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Outcome {
    /// The new token is in use, the tunnel is healthy and this computer keeps the new one.
    Replaced,
    /// The box refused the new token (or could not be reached): it still uses the old one. The words are the box's.
    Refused(String),
    /// The new tunnel was not healthy; the old token was put back and that tunnel is healthy again.
    RolledBack(String),
    /// The new tunnel was not healthy and the old token could not be put back (or there was none): the tunnel is down.
    Down(String),
}

/// Run on the box: is the tunnel's service running some seconds after its restart, without systemd starting it again?
fn health_script(unit: &str) -> String {
    format!(
        "sleep 12\ns=$(systemctl is-active {unit} 2>/dev/null || true)\nn=$(systemctl show -p NRestarts --value {unit} 2>/dev/null || echo 0)\nif [ \"$s\" = active ] && [ \"${{n:-0}}\" = 0 ]; then echo 'tunnel-health: ok'; else echo \"tunnel-health: ${{s:-unknown}}, restarted ${{n:-0}} times\"; fi\n"
    )
}

/// Run on the box as the box user, from standard input: hand the token to the root helper exactly as the dashboard installer does.
/// The token and the code are shell words in single quotes; [`token_shape_ok`] keeps a quote out of the token, and a code is
/// letters, digits and dashes.
fn hand_over_script(which: Which, token: &str, code: Option<&str>) -> String {
    format!(
        "set -euo pipefail\nTUNNEL_TOKEN='{token}'\nTUNNEL_APPROVAL='{code}'\nreq=/usr/local/bin/ozbox-admin-request\n[ -x \"$req\" ] || {{ echo 'this box has no admin helper' >&2; exit 1; }}\ntid=\"$(od -An -N8 -tx1 /dev/urandom | tr -d ' \\n')\"\ntokfile=\"/run/ozbox-admin/requests/$tid.tok\"\ntrap 'rm -f \"$tokfile\"' EXIT\n( umask 077; set -o noclobber; printf '%s' \"$TUNNEL_TOKEN\" >\"$tokfile\" ) || {{ echo 'the admin helper is not reachable' >&2; exit 1; }}\nunset TUNNEL_TOKEN\nif [ -n \"$TUNNEL_APPROVAL\" ] && grep -q -- --approval-stdin \"$req\" 2>/dev/null; then\n  answer=\"$(printf '%s\\n' \"$TUNNEL_APPROVAL\" | \"$req\" --approval-stdin replace-tunnel-token {which} \"$tid\" 2>&1)\" && rc=0 || rc=$?\nelif [ -n \"$TUNNEL_APPROVAL\" ]; then\n  answer=\"$(\"$req\" replace-tunnel-token {which} \"$tid\" \"$TUNNEL_APPROVAL\" 2>&1)\" && rc=0 || rc=$?\nelse\n  answer=\"$(\"$req\" replace-tunnel-token {which} \"$tid\" 2>&1)\" && rc=0 || rc=$?\nfi\nif [ \"$rc\" != 0 ]; then printf '%s\\n' \"$answer\" | grep -v '^status=' | tail -n 1 | cut -c1-300 >&2; exit 1; fi\necho 'tunnel-token-stored'\n",
        which = which.id(),
        code = code.unwrap_or(""),
    )
}

fn ssh(box_name: &BoxName, program: &str, stdin: String) -> CommandSpec {
    CommandSpec::new("ssh")
        .args([
            "-o".to_string(),
            "BatchMode=yes".to_string(),
            crate::sshconfig::host_alias(box_name.as_str()),
            program.to_string(),
            "-s".to_string(),
        ])
        .stdin(stdin.into_bytes())
}

/// Everything the apply touches, so a test can stand in for each.
pub struct Deps<'a> {
    pub runner: &'a dyn CommandRunner,
    /// This computer's secret store: where the token in use is kept.
    pub store: &'a dyn SecretStore,
    /// The approval key pinned when the box was made (for `--approve-with-laptop-key`).
    pub keys: &'a dyn SecretStore,
}

/// An approval bound to this token, made with this computer's pinned key, only when asked for and only for a box whose root
/// helper binds a code to the token (Amendment 16, decision 4).
fn approval_for(
    deps: &Deps<'_>,
    name: &BoxName,
    which: Which,
    token: &str,
) -> Result<String, String> {
    if crate::dashboard_cli::helper_binds_approval(deps.runner, name) != Some(true) {
        return Err(t("dashboard.laptop_key_unbound", &[]));
    }
    let binding = crate::secrets_approval::tunnel_token_binding(token);
    let (code, _) = crate::approval_key_cli::obtain(
        deps.runner,
        deps.keys,
        name,
        crate::approval_key::PIN_ID,
        "tunnel-token",
        which.id(),
        &binding,
    )
    .map_err(|e| e.to_string())?;
    crate::secrets_approval::canonical_code(&code).ok_or_else(|| t("dashboard.laptop_key_bad", &[]))
}

/// Hand one token over and say whether the box stored it (the box's own words when not; they never hold the token).
fn hand_over(
    deps: &Deps<'_>,
    name: &BoxName,
    which: Which,
    token: &str,
    laptop: bool,
) -> Result<(), String> {
    let code = if laptop {
        Some(approval_for(deps, name, which, token)?)
    } else {
        None
    };
    let script = Zeroizing::new(hand_over_script(which, token, code.as_deref()));
    match deps.runner.run(&ssh(name, "bash", script.to_string())) {
        Ok(o) if o.status == Some(0) && o.stdout.contains("tunnel-token-stored") => Ok(()),
        Ok(o) if o.status == Some(255) => Err(t("rotate.unreachable", &[("box", name.as_str())])),
        Ok(o) => {
            let said = scrub(o.stderr.trim().lines().last().unwrap_or(""), token);
            Err(if said.to_ascii_lowercase().contains("approval") {
                t(
                    "rotate.needs_approval",
                    &[
                        ("box", name.as_str()),
                        ("why", &said),
                        ("tunnel", which.id()),
                    ],
                )
            } else {
                t("rotate.refused", &[("why", &said)])
            })
        }
        Err(_) => Err(t("rotate.unreachable", &[("box", name.as_str())])),
    }
}

/// A line from the box, with the token taken out should it ever appear (the helper never prints it; this holds if it did).
fn scrub(line: &str, token: &str) -> String {
    let l: String = line.chars().take(300).collect();
    if token.is_empty() {
        l
    } else {
        l.replace(token, "[hidden]")
    }
}

/// Whether the tunnel is healthy, and the box's words when not.
fn healthy(deps: &Deps<'_>, name: &BoxName, which: Which) -> Result<(), String> {
    match deps
        .runner
        .run(&ssh(name, "sh", health_script(which.unit())))
    {
        Ok(o) if o.stdout.contains("tunnel-health: ok") => Ok(()),
        Ok(o) => Err(o
            .stdout
            .lines()
            .find_map(|l| l.strip_prefix("tunnel-health: "))
            .unwrap_or("not known")
            .chars()
            .take(120)
            .collect()),
        Err(_) => Err("the box could not be asked".into()),
    }
}

/// Put `new` in place of `old`, as the plan said. Pure apart from `deps`. `old` is the token this computer keeps for the box
/// (`None`: there is nothing to put back).
pub fn apply(
    deps: &Deps<'_>,
    name: &BoxName,
    req: &Request,
    new: &Zeroizing<String>,
    old: Option<&Zeroizing<String>>,
) -> Outcome {
    let which = req.which;
    if let Err(e) = hand_over(deps, name, which, new, req.approve_with_laptop_key) {
        return Outcome::Refused(e);
    }
    let why = match healthy(deps, name, which) {
        Ok(()) => {
            // only now does the copy kept here change: a failure above leaves the old one, which still works
            if deps
                .store
                .set(&which.kept_name(name.as_str()), new.as_str())
                .is_err()
            {
                return Outcome::Down(t("rotate.not_kept", &[("box", name.as_str())]));
            }
            return Outcome::Replaced;
        }
        Err(why) => why,
    };
    let Some(old) = old else {
        return Outcome::Down(t(
            "rotate.down_no_old",
            &[
                ("box", name.as_str()),
                ("why", &why),
                ("tunnel", which.id()),
            ],
        ));
    };
    if let Err(e) = hand_over(deps, name, which, old, req.approve_with_laptop_key) {
        return Outcome::Down(t(
            "rotate.down_rollback_refused",
            &[
                ("box", name.as_str()),
                ("why", &why),
                ("again", &e),
                ("tunnel", which.id()),
            ],
        ));
    }
    match healthy(deps, name, which) {
        Ok(()) => Outcome::RolledBack(t(
            "rotate.rolled_back",
            &[
                ("box", name.as_str()),
                ("why", &why),
                ("tunnel", which.id()),
            ],
        )),
        Err(again) => Outcome::Down(t(
            "rotate.down_rollback_unhealthy",
            &[
                ("box", name.as_str()),
                ("why", &why),
                ("again", &again),
                ("tunnel", which.id()),
            ],
        )),
    }
}

/// The command: parse, read the token, plan, confirm, apply, report.
pub(super) fn command(
    runner: &dyn CommandRunner,
    simulated: bool,
    name: BoxName,
    rest: &[String],
    f: &super::Flags,
) -> super::Result<()> {
    use super::CliError;
    let req = parse(rest).map_err(CliError::Msg)?;
    if simulated {
        return Err(CliError::Msg(t("rotate.simulated", &[])));
    }
    let store = crate::serve::secret_store();
    let keys = crate::approval_key_cli::keychain();
    let new = read_token(&req.source, &mut std::io::stdin().lock(), store.as_ref())
        .map_err(CliError::Msg)?;
    let old = store
        .get(&req.which.kept_name(name.as_str()))
        .ok()
        .flatten()
        .map(Zeroizing::new);
    let same = old.as_ref().is_some_and(|o| o.as_str() == new.as_str());
    let lines = plan_lines(name.as_str(), req.which, old.is_some(), same);
    if !f.json {
        for l in &lines {
            println!("{l}");
        }
    }
    let report = |applied: bool, outcome: &str, detail: &str| {
        if f.json {
            println!(
                "{}",
                serde_json::json!({
                    "box": name.as_str(), "action": "replace-tunnel-token", "tunnel": req.which.id(),
                    "plan": lines, "applied": applied, "dry_run": f.dry_run, "outcome": outcome,
                    "rollback_available": old.is_some(), "detail": detail,
                })
            );
        } else if !detail.is_empty() {
            println!("{detail}");
        }
    };
    if same {
        report(false, "nothing_to_do", "");
        return Ok(());
    }
    if f.dry_run {
        report(false, "planned", &t("admin.dry_run", &[]));
        return Ok(());
    }
    // with no copy to put back, a failure leaves the tunnel down: the box's name is typed, `--yes` does not stand for it
    // (standard input is the token's when it came from there, so that case needs the store instead)
    if old.is_none() {
        if req.source == Source::Stdin {
            return Err(CliError::Msg(t(
                "rotate.err_no_old_stdin",
                &[("box", name.as_str())],
            )));
        }
        super::admin::ask_name(f, name.as_str())?;
    } else if req.source == Source::Stdin && !f.yes {
        return Err(CliError::Msg(t("rotate.err_stdin_needs_yes", &[])));
    } else {
        super::admin::ask(f, name.as_str())?;
    }
    let deps = Deps {
        runner,
        store: store.as_ref(),
        keys: keys.as_ref(),
    };
    match apply(&deps, &name, &req, &new, old.as_ref()) {
        Outcome::Replaced => {
            let done = t(
                "rotate.done",
                &[("box", name.as_str()), ("tunnel", req.which.id())],
            );
            report(true, "replaced", &done);
            Ok(())
        }
        Outcome::Refused(e) => {
            report(true, "refused", &e);
            Err(CliError::Msg(t(
                "rotate.err_failed",
                &[("box", name.as_str())],
            )))
        }
        Outcome::RolledBack(m) => {
            report(true, "rolled_back", &m);
            Err(CliError::Msg(t(
                "rotate.err_failed",
                &[("box", name.as_str())],
            )))
        }
        Outcome::Down(m) => {
            report(true, "down", &m);
            Err(CliError::Msg(t(
                "rotate.err_failed",
                &[("box", name.as_str())],
            )))
        }
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use crate::secrets::MemorySecrets;
    use ozbox_core::{Output, RecordingRunner};

    /// Built by concatenation, so this file holds no token-shaped literal.
    fn sentinel(tag: &str) -> Zeroizing<String> {
        Zeroizing::new(format!(
            "{}{}{}",
            "eyJh", tag, "TOKEN-SENTINEL-0123456789abcdef"
        ))
    }

    fn ok(stdout: &str) -> Output {
        Output {
            status: Some(0),
            stdout: stdout.into(),
            stderr: String::new(),
        }
    }

    fn refused(stderr: &str) -> Output {
        Output {
            status: Some(1),
            stdout: String::new(),
            stderr: stderr.into(),
        }
    }

    fn words(w: &[&str]) -> Vec<String> {
        w.iter().map(|s| s.to_string()).collect()
    }

    fn name() -> BoxName {
        BoxName::new("dev").unwrap()
    }

    /// Everything a run sent, said or kept, except the store and the one channel the token travels on.
    fn everywhere_but_the_handover(r: &RecordingRunner, outcome: &Outcome) -> String {
        let mut all = format!("{outcome:?}\n");
        for c in r.calls() {
            all.push_str(&c.program);
            all.push_str(&c.args.join(" "));
            all.push_str(&format!("{c:?}"));
            all.push_str(&serde_json::to_string(&c).unwrap());
            let stdin = String::from_utf8(c.stdin.clone().unwrap_or_default()).unwrap();
            if !stdin.contains("replace-tunnel-token") {
                all.push_str(&stdin);
            }
        }
        all.push_str(&plan_lines("dev", Which::Cloudflare, true, false).join("\n"));
        all
    }

    #[test]
    fn the_words_take_a_tunnel_and_one_source_and_never_a_token() {
        let r = parse(&words(&["cloudflare", "--token-stdin"])).unwrap();
        assert_eq!(
            (r.which, r.source, r.approve_with_laptop_key),
            (Which::Cloudflare, Source::Stdin, false)
        );
        let r = parse(&words(&[
            "ide",
            "--token-from-store",
            "new-ide-token",
            "--approve-with-laptop-key",
        ]))
        .unwrap();
        assert_eq!(r.source, Source::Store("new-ide-token".into()));
        assert!(r.approve_with_laptop_key);
        let tok = sentinel("argv");
        for bad in [
            words(&["cloudflare"]),
            words(&["cloudflare", tok.as_str()]),
            words(&["cloudflare", "--token", tok.as_str()]),
            words(&["cloudflare", "--token-stdin", "--token-from-store", "x"]),
            words(&["wireguard", "--token-stdin"]),
            words(&[]),
        ] {
            let e = parse(&bad).unwrap_err();
            assert!(
                !e.contains(tok.as_str()),
                "a refusal never repeats the word: {e}"
            );
        }
    }

    #[test]
    fn a_healthy_new_tunnel_replaces_the_kept_token_and_the_token_appears_nowhere_outside_the_store(
    ) {
        let (new, old) = (sentinel("NEW"), sentinel("OLD"));
        let store = MemorySecrets::default();
        store
            .set(&Which::Cloudflare.kept_name("dev"), old.as_str())
            .unwrap();
        let r = RecordingRunner::new();
        r.reply(ok("tunnel-token-stored\n"));
        r.reply(ok("tunnel-health: ok\n"));
        let deps = Deps {
            runner: &r,
            store: &store,
            keys: &MemorySecrets::default(),
        };
        let req = parse(&words(&["cloudflare", "--token-stdin"])).unwrap();
        let out = apply(&deps, &name(), &req, &new, Some(&old));
        assert_eq!(out, Outcome::Replaced);
        assert_eq!(
            store
                .get(&Which::Cloudflare.kept_name("dev"))
                .unwrap()
                .as_deref(),
            Some(new.as_str())
        );
        let calls = r.calls();
        assert_eq!(calls.len(), 2, "hand over, then health");
        // the sentinel: in no argument, plan, outcome or debug form; only on the hand-over's standard input
        let rest = everywhere_but_the_handover(&r, &out);
        assert!(
            !rest.contains(new.as_str()) && !rest.contains(old.as_str()),
            "{rest}"
        );
        let handover = String::from_utf8(calls[0].stdin.clone().unwrap()).unwrap();
        assert!(handover.contains(new.as_str()) && !handover.contains(old.as_str()));
        assert!(calls[0].args.iter().all(|a| !a.contains(new.as_str())));
        // the box user's copy is a private file the helper removes, and the variable is unset once written
        assert!(handover.contains("umask 077") && handover.contains("unset TUNNEL_TOKEN"));
        assert!(handover.contains("replace-tunnel-token cloudflare"));
    }

    #[test]
    fn an_unhealthy_new_tunnel_puts_the_old_token_back_and_keeps_the_old_copy_here() {
        let (new, old) = (sentinel("NEW"), sentinel("OLD"));
        let store = MemorySecrets::default();
        store
            .set(&Which::Cloudflare.kept_name("dev"), old.as_str())
            .unwrap();
        let r = RecordingRunner::new();
        r.reply(ok("tunnel-token-stored\n"));
        r.reply(ok("tunnel-health: activating, restarted 3 times\n"));
        r.reply(ok("tunnel-token-stored\n"));
        r.reply(ok("tunnel-health: ok\n"));
        let deps = Deps {
            runner: &r,
            store: &store,
            keys: &MemorySecrets::default(),
        };
        let req = parse(&words(&["cloudflare", "--token-from-store", "x"])).unwrap();
        let out = apply(&deps, &name(), &req, &new, Some(&old));
        let Outcome::RolledBack(m) = &out else {
            panic!("{out:?}")
        };
        assert!(
            m.contains("restarted 3 times") && m.contains("put back"),
            "{m}"
        );
        // the old one is still what this computer keeps: the new one never replaced it
        assert_eq!(
            store
                .get(&Which::Cloudflare.kept_name("dev"))
                .unwrap()
                .as_deref(),
            Some(old.as_str())
        );
        let calls = r.calls();
        assert_eq!(calls.len(), 4);
        let second = String::from_utf8(calls[2].stdin.clone().unwrap()).unwrap();
        assert!(second.contains(old.as_str()) && !second.contains(new.as_str()));
        let rest = everywhere_but_the_handover(&r, &out);
        assert!(!rest.contains(new.as_str()) && !rest.contains(old.as_str()));
    }

    #[test]
    fn a_refused_token_changes_nothing_and_a_failed_rollback_says_the_tunnel_is_down() {
        let (new, old) = (sentinel("NEW"), sentinel("OLD"));
        let store = MemorySecrets::default();
        store
            .set(&Which::Ide.kept_name("dev"), old.as_str())
            .unwrap();
        // the box refused it: nothing is restarted, nothing kept
        let r = RecordingRunner::new();
        r.reply(refused(&format!(
            "error: the token has an unexpected shape {}",
            new.as_str()
        )));
        let deps = Deps {
            runner: &r,
            store: &store,
            keys: &MemorySecrets::default(),
        };
        let req = parse(&words(&["ide", "--token-from-store", "x"])).unwrap();
        let out = apply(&deps, &name(), &req, &new, Some(&old));
        let Outcome::Refused(m) = &out else {
            panic!("{out:?}")
        };
        assert!(
            !m.contains(new.as_str()),
            "a line from the box is scrubbed: {m}"
        );
        assert_eq!(r.calls().len(), 1);
        assert_eq!(
            store.get(&Which::Ide.kept_name("dev")).unwrap().as_deref(),
            Some(old.as_str())
        );
        // unhealthy, and the old one would not go back either: down, in words that say what to do
        let r = RecordingRunner::new();
        r.reply(ok("tunnel-token-stored\n"));
        r.reply(ok("tunnel-health: failed, restarted 5 times\n"));
        r.reply(ok("tunnel-token-stored\n"));
        r.reply(ok("tunnel-health: failed, restarted 5 times\n"));
        let deps = Deps {
            runner: &r,
            store: &store,
            keys: &MemorySecrets::default(),
        };
        let out = apply(&deps, &name(), &req, &new, Some(&old));
        let Outcome::Down(m) = &out else {
            panic!("{out:?}")
        };
        assert!(
            m.contains("down") && m.contains("replace-tunnel-token ide"),
            "{m}"
        );
        // with no copy to put back
        let r = RecordingRunner::new();
        r.reply(ok("tunnel-token-stored\n"));
        r.reply(ok("tunnel-health: failed, restarted 1 times\n"));
        let deps = Deps {
            runner: &r,
            store: &store,
            keys: &MemorySecrets::default(),
        };
        assert!(matches!(
            apply(&deps, &name(), &req, &new, None),
            Outcome::Down(_)
        ));
        assert_eq!(r.calls().len(), 2);
    }

    #[test]
    fn the_token_is_read_from_stdin_or_the_store_and_its_shape_is_checked_without_repeating_it() {
        let store = MemorySecrets::default();
        let tok = sentinel("S");
        store.set("new-tok", tok.as_str()).unwrap();
        let got = read_token(
            &Source::Store("new-tok".into()),
            &mut std::io::empty(),
            &store,
        )
        .unwrap();
        assert_eq!(got.as_str(), tok.as_str());
        let mut input = std::io::Cursor::new(format!("{}\n", tok.as_str()).into_bytes());
        let got = read_token(&Source::Stdin, &mut input, &store).unwrap();
        assert_eq!(got.as_str(), tok.as_str());
        for bad in [
            "short",
            "has a space in it that is long enough",
            "quote'token-long-enough-to-pass",
        ] {
            let mut input = std::io::Cursor::new(bad.as_bytes().to_vec());
            let e = read_token(&Source::Stdin, &mut input, &store).unwrap_err();
            assert!(!e.contains(bad), "{e}");
        }
        assert!(read_token(
            &Source::Store("absent".into()),
            &mut std::io::empty(),
            &store
        )
        .is_err());
    }

    #[test]
    fn the_plan_says_every_step_and_the_cloudflare_side_and_holds_no_token() {
        let p = plan_lines("dev", Which::Cloudflare, true, false).join("\n");
        assert!(p.contains("ozbox-cloudflared.service"), "{p}");
        assert!(p.contains("put back"), "{p}");
        assert!(p.contains("Cloudflare"), "{p}");
        let p = plan_lines("dev", Which::Cloudflare, false, false).join("\n");
        assert!(p.contains("no copy"), "{p}");
        assert_eq!(plan_lines("dev", Which::Ide, true, true).len(), 1);
    }
}
