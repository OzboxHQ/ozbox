//! `ozbox host-guard egress|patch|take-file ...`: the box's own guards, run on the box. The root helper runs it from
//! `ozbox admin <box> -- host-guard ...`, and the timers run `egress refresh` and `patch tick`. Everything that changes
//! something needs root (the writes fail without it, in words); the reads (`report`, `mode`, `status`, `check`) need none.
//!
//! The root helper takes any request the box user files, and the box user is also where an agent runs. So a change that
//! lets the box do more than the rule in force (the egress list turned off or widened, the box allowed to restart itself)
//! is made only with a fresh approval the box user cannot make: one minted by the dashboard after a passkey, or signed by
//! an enrolled laptop key, and spent here through the secrets service's admin socket. The approval is bound to a digest of
//! the change's own words, so a code read on its way to the box cannot be spent on a different change. A box with no
//! second factor enrolled refuses such a change outright: there, "approved" would only mean "the box user asked". A change
//! that asks for less is made without one (see `box_egress::loosens` and `patch_guard::loosens`).

use ozbox_core::{CommandRunner, SystemRunner};

use crate::box_egress::Declaration;
use crate::egress_guard::{system_resolve, Guard as EgressGuard, Paths as EgressPaths};
use crate::patch_guard::{Guard as PatchGuard, Paths as PatchPaths, Rule};

/// The approval scope of a change to the box's own guards.
pub const SCOPE: &str = "host-guard";

/// What to print and the exit status.
pub struct Outcome {
    pub text: String,
    pub ok: bool,
}

/// Asks whether a gated change may go ahead: `(scope, project, env, approval)` to how it was allowed, or why not.
pub type Gate<'a> = &'a dyn Fn(&str, &str, &str, &str) -> Result<String, String>;

fn now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

fn done(r: Result<String, String>) -> Outcome {
    match r {
        Ok(text) => Outcome { text, ok: true },
        Err(text) => Outcome { text, ok: false },
    }
}

/// Take `--approval CODE` out of the words, wherever it is. One helper for both ends, so the laptop and the box read a
/// request the same way.
pub fn take_approval(words: &[String]) -> Result<(Vec<String>, Option<String>), String> {
    let mut rest = Vec::with_capacity(words.len());
    let mut approval = None;
    let mut it = words.iter();
    while let Some(w) = it.next() {
        if w == "--approval" {
            let code = it.next().ok_or("--approval needs a code")?;
            if approval.is_some() {
                return Err("give --approval once".into());
            }
            if code.is_empty()
                || code.len() > 40
                || !code.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-')
            {
                return Err("the approval code has characters that are not allowed".into());
            }
            approval = Some(code.clone());
        } else {
            rest.push(w.clone());
        }
    }
    Ok((rest, approval))
}

/// What an approval for a change is bound to: the first 16 hex digits of the SHA-256 of the change's words
/// (`egress set …` or `patch set …`, as `HostGuard::words` writes them). Pure.
pub fn change_digest(words: &[String]) -> String {
    let d = ring::digest::digest(&ring::digest::SHA256, words.join(" ").as_bytes());
    d.as_ref()
        .iter()
        .take(8)
        .map(|b| format!("{b:02x}"))
        .collect()
}

/// Spend the approval for a change that loosens a guard, or say why it cannot go ahead.
pub fn authorize(
    gate: Gate<'_>,
    project: &str,
    digest: &str,
    approval: Option<&str>,
) -> Result<String, String> {
    let how = format!(
        "ask for an approval in the dashboard, or run `ozbox secrets approve --box <box> --scope {SCOPE} --project {project} --env {digest}` on a computer with an enrolled key, then send the same change again with --approval CODE"
    );
    let via = gate(SCOPE, project, digest, approval.unwrap_or("")).map_err(|e| {
        format!("this change lets the box do more than the rule in force, so it needs a fresh approval: {e}. To go ahead, {how}.")
    })?;
    // The scope's rule for a box with no second factor (`secrets_approval::SCOPE_RULES`) is what refuses here; the
    // service applies it too, so a gate that still says "bootstrap" (an older service) is refused the same way.
    let refused_in_bootstrap = crate::secrets_approval::in_bootstrap(SCOPE)
        == crate::secrets_approval::InBootstrap::Refused;
    if via.is_empty() || (via == crate::secrets_approval::VIA_BOOTSTRAP && refused_in_bootstrap) {
        return Err(format!(
            "this change lets the box do more than the rule in force, and this box has no second factor enrolled, so nothing here can approve it (the box user asking is not an approval). Enrol a passkey in the dashboard or a laptop key (`ozbox secrets approval-key enroll`), then {how}."
        ));
    }
    Ok(via)
}

/// Ask the box's secrets service, on the admin socket only root can open, whether a gated change may go ahead.
fn socket_gate(scope: &str, project: &str, env: &str, approval: &str) -> Result<String, String> {
    let path = std::env::var("OZBOX_SECRETS_ADMIN_SOCKET")
        .ok()
        .filter(|p| !p.is_empty())
        .unwrap_or_else(|| "/run/ozbox-secrets/admin/admin.sock".into());
    crate::secrets_service::SocketSecrets::new(path.into())
        .call(
            serde_json::json!({"op": "gate", "scope": scope, "project": project, "env": env,
            "approval": approval}),
        )
        .map(|v| v["value"].as_str().unwrap_or_default().to_string())
        .map_err(|e| e.0)
}

/// Everything the commands touch, so a test can stand in for each.
pub struct Deps<'a> {
    pub runner: &'a dyn CommandRunner,
    pub egress: EgressPaths,
    pub patch: PatchPaths,
    pub now: u64,
    pub resolve: &'a dyn Fn(&str) -> Option<Vec<std::net::IpAddr>>,
    pub gate: Gate<'a>,
    pub metadata: crate::metadata_guard::Paths,
    pub memory: crate::memory_guard::Paths,
    pub helper: crate::helper_refresh::Paths,
}

pub fn run(words: &[String], json: bool) -> Outcome {
    let runner = SystemRunner;
    run_with(
        words,
        json,
        &Deps {
            runner: &runner,
            egress: EgressPaths::default(),
            patch: PatchPaths::default(),
            now: now(),
            resolve: &system_resolve,
            gate: &socket_gate,
            metadata: crate::metadata_guard::Paths::default(),
            memory: crate::memory_guard::Paths::default(),
            helper: crate::helper_refresh::Paths::default(),
        },
    )
}

pub fn run_with(words: &[String], json: bool, d: &Deps) -> Outcome {
    // The root helper's own reader for a file the box user left it (see `request_file`); the line goes to standard output.
    if words.first().map(String::as_str) == Some("take-file") {
        return match crate::request_file::command(&words[1..]) {
            Ok(()) => Outcome {
                text: String::new(),
                ok: true,
            },
            Err(text) => Outcome { text, ok: false },
        };
    }
    let (words, approval) = match take_approval(words) {
        Ok(v) => v,
        Err(e) => return done(Err(e)),
    };
    let rest: Vec<String> = words.iter().skip(2).cloned().collect();
    let sub = (
        words.first().map(String::as_str),
        words.get(1).map(String::as_str),
    );
    if approval.is_some() && sub.1 != Some("set") {
        return done(Err(
            "an approval is only for `egress set` or `patch set`".into()
        ));
    }
    match sub {
        (Some("egress"), Some(sub)) => {
            let g = EgressGuard {
                runner: d.runner,
                paths: d.egress.clone(),
                now: d.now,
                resolve: d.resolve,
            };
            match sub {
                "set" => done(Declaration::from_words(&rest).and_then(|new| {
                    if crate::box_egress::loosens(&g.in_force(), &new) {
                        let mut w = vec!["egress".to_string(), "set".into()];
                        w.extend(new.to_words());
                        authorize(d.gate, "egress", &change_digest(&w), approval.as_deref())?;
                    }
                    g.apply(&new)
                })),
                "refresh" => done(g.refresh()),
                "report" if json => Outcome {
                    text: g.state_json(),
                    ok: true,
                },
                "report" => Outcome {
                    text: g.report(),
                    ok: true,
                },
                "mode" => {
                    let s: crate::box_egress::State =
                        serde_json::from_str(&g.state_json()).unwrap_or_default();
                    let mode = s.mode.map_or("off", |m| m.as_str());
                    Outcome {
                        text: format!("mode={mode} since={}", s.since),
                        ok: true,
                    }
                }
                _ => done(Err("egress takes set, refresh, report or mode".into())),
            }
        }
        (Some("patch"), Some(sub)) => {
            let g = PatchGuard {
                runner: d.runner,
                paths: d.patch.clone(),
                now: d.now,
            };
            match sub {
                "set" => done(Rule::from_words(&rest).and_then(|new| {
                    if crate::patch_guard::loosens(&g.rule(), &new) {
                        let mut w = vec!["patch".to_string(), "set".into()];
                        w.extend(new.to_words());
                        authorize(d.gate, "patch", &change_digest(&w), approval.as_deref())?;
                    }
                    g.set(&new)
                })),
                "check" => {
                    let (idle, text) = g.check();
                    Outcome { text, ok: idle }
                }
                "tick" => Outcome {
                    text: g.tick(((d.now / 3600) % 24) as u8),
                    ok: true,
                },
                "status" => Outcome {
                    text: g.status(),
                    ok: true,
                },
                _ => done(Err("patch takes set, check, tick or status".into())),
            }
        }
        // only ever tightens (who may reach the metadata service), so it needs no approval
        (Some("metadata"), Some("install")) if words.len() <= 3 => done(
            crate::metadata_guard::Guard {
                runner: d.runner,
                paths: d.metadata.clone(),
            }
            .install(words.get(2).map(String::as_str)),
        ),
        // only ever tightens (swap in RAM, protected scores, soft limits), so it needs no approval; `boot` and `apply` are what
        // the box's own units run
        (Some("memory"), Some(sub)) if words.len() == 2 => {
            let g = crate::memory_guard::Guard {
                runner: d.runner,
                paths: d.memory.clone(),
            };
            match sub {
                "install" => done(g.install()),
                "boot" => done(g.boot()),
                "apply" => done(g.apply()),
                "status" => Outcome {
                    text: g.status(),
                    ok: true,
                },
                _ => done(Err("memory takes install, boot, apply or status".into())),
            }
        }
        // puts the root helper in step with this release; the text is this program's own, never the caller's
        (Some("helper"), Some("refresh")) if words.len() == 2 => {
            done(crate::helper_refresh::refresh(d.runner, &d.helper))
        }
        _ => done(Err(
            "host-guard takes egress, patch, metadata install, memory install or helper refresh"
                .into(),
        )),
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use ozbox_core::RecordingRunner;
    use std::cell::RefCell;
    use std::net::IpAddr;
    use std::path::Path;

    fn res(h: &str) -> Option<Vec<IpAddr>> {
        // the key service has an address of its own, so a test can tell it from every other name
        let a = if h.starts_with("kms.") {
            "203.0.113.77"
        } else {
            "203.0.113.5"
        };
        Some(vec![a.parse().unwrap()])
    }

    fn w(s: &str) -> Vec<String> {
        s.split_whitespace().map(str::to_string).collect()
    }

    struct TestBox {
        dir: tempfile::TempDir,
        runner: RecordingRunner,
        /// What the gate was asked, and how it answers.
        asked: RefCell<Vec<(String, String, String, String)>>,
        answer: RefCell<Result<String, String>>,
    }

    impl TestBox {
        fn new(answer: Result<&str, &str>) -> Self {
            Self {
                dir: tempfile::tempdir().unwrap(),
                runner: RecordingRunner::new(),
                asked: RefCell::new(Vec::new()),
                answer: RefCell::new(answer.map(str::to_string).map_err(str::to_string)),
            }
        }
        fn run(&self, words: &str) -> Outcome {
            let d: &Path = self.dir.path();
            let gate = |s: &str, p: &str, e: &str, a: &str| {
                self.asked
                    .borrow_mut()
                    .push((s.into(), p.into(), e.into(), a.into()));
                self.answer.borrow().clone()
            };
            run_with(
                &w(words),
                false,
                &Deps {
                    runner: &self.runner,
                    egress: EgressPaths {
                        etc: d.join("etc"),
                        var: d.join("var"),
                        units: d.join("units"),
                        resolv: vec![],
                    },
                    patch: PatchPaths {
                        etc: d.join("etc"),
                        var: d.join("pvar"),
                        units: d.join("units"),
                        reboot_required: d.join("reboot-required"),
                    },
                    now: 1_000,
                    resolve: &res,
                    gate: &gate,
                    metadata: crate::metadata_guard::Paths {
                        etc: d.join("etc"),
                        units: d.join("units"),
                        dmi_vendor: d.join("vendor"),
                    },
                    memory: crate::memory_guard::Paths {
                        system_units: d.join("etc/system"),
                        unit_dirs: vec![d.join("units")],
                        user_units: d.join("etc/user"),
                        sysctl_d: d.join("etc/sysctl.d"),
                        sys_block: d.join("sys/block"),
                        zram_control: d.join("sys/class/zram-control"),
                        proc: d.join("proc"),
                        cgroup: d.join("cgroup"),
                        root_uid: 0,
                    },
                    helper: crate::helper_refresh::Paths {
                        helper: d.join("sbin/ozbox-admin.sh"),
                        log: d.join("refresh.log"),
                    },
                },
            )
        }
        fn declared(&self) -> String {
            std::fs::read_to_string(self.dir.path().join("etc/box-egress.json")).unwrap_or_default()
        }
    }

    #[test]
    fn the_helper_refresh_installs_this_releases_own_helper_asks_for_no_approval_and_takes_no_text()
    {
        let b = TestBox::new(Err("must not be asked"));
        std::fs::create_dir_all(b.dir.path().join("sbin")).unwrap();
        let o = b.run("helper refresh");
        assert!(o.ok, "{}", o.text);
        // what was written is the program's own helper, byte for byte
        let on_disk = std::fs::read_to_string(b.dir.path().join("sbin/ozbox-admin.sh")).unwrap();
        assert_eq!(on_disk, crate::helper_refresh::HELPER);
        assert!(b.run("helper refresh").text.contains("already"));
        // nothing rides along: no path, no text, no other verb, no approval
        assert!(!b.run("helper refresh /tmp/x").ok);
        assert!(!b.run("helper write").ok);
        assert!(!b.run("helper refresh --approval ABCD-EFGH-JKLM-NPQR").ok);
        assert!(b.asked.borrow().is_empty());
    }

    #[test]
    fn the_memory_guard_needs_no_approval_and_takes_only_its_own_words() {
        let b = TestBox::new(Err("must not be asked"));
        let o = b.run("memory install");
        assert!(o.ok, "{}", o.text);
        assert!(o.text.contains("No service was restarted"), "{}", o.text);
        assert!(b.run("memory status").ok);
        // nothing else rides along, and an approval is only for a change to the egress list or the patch rule
        assert!(!b.run("memory bogus").ok);
        assert!(!b.run("memory install extra").ok);
        assert!(!b.run("memory install --approval ABCD-EFGH-JKLM-NPQR").ok);
        assert!(
            b.asked.borrow().is_empty(),
            "it only tightens, so the gate is never asked"
        );
        // the units were written where the test box's units go
        assert!(b
            .dir
            .path()
            .join("etc/system/ozbox-memory.service")
            .is_file());
    }

    #[test]
    fn tightening_needs_no_approval_and_never_asks_the_gate() {
        let b = TestBox::new(Err("must not be asked"));
        for step in [
            "egress set log --preset github --preset npm",
            "egress set enforce --preset github --preset npm",
            "egress set enforce --preset github",
            "patch set never",
        ] {
            let o = b.run(step);
            assert!(o.ok, "{step}: {}", o.text);
        }
        assert!(b.asked.borrow().is_empty());
        assert!(b.declared().contains("enforce"));
    }

    #[test]
    fn no_request_can_cut_a_moved_store_off_from_its_key_service() {
        // each of these asks for less: no region, another region, no aws-control, only one host. Each starts from a fresh box,
        // so no step is judged against the list another one left in force (a wider list would need an approval).
        for step in [
            "egress set enforce --preset github",
            "egress set enforce --region us-east-1 --preset github",
            "egress set enforce --host api.example.com",
            "egress set log --preset github",
        ] {
            let b = TestBox::new(Err("must not be asked"));
            std::fs::create_dir_all(b.dir.path().join("etc")).unwrap();
            std::fs::write(
                b.dir.path().join("etc/secrets.env"),
                "OZBOX_KMS_KEY_ID=arn:aws:kms:eu-west-1:123456789012:key/0f0f0f0f-0000-4000-8000-000000000000\n",
            )
            .unwrap();
            let o = b.run(step);
            assert!(o.ok, "{step}: {}", o.text);
            let rules =
                std::fs::read_to_string(b.dir.path().join("var/ruleset.nft")).unwrap_or_default();
            assert!(
                rules.contains("203.0.113.77 . tcp . 443"),
                "{step} dropped the key service:\n{rules}"
            );
            assert!(b.asked.borrow().is_empty());
        }
    }

    #[test]
    fn on_a_box_with_no_second_factor_loosening_is_refused_and_nothing_changes() {
        // the service allows anything while no factor is enrolled: that is exactly what must not count here
        let b = TestBox::new(Ok("bootstrap"));
        assert!(b.run("egress set enforce --preset github").ok);
        for step in [
            "egress set off",
            "egress set log --preset github",
            "egress set enforce --preset github --host exfil.example.com",
            "patch set when-idle --from 2 --to 5",
        ] {
            let o = b.run(step);
            assert!(!o.ok, "{step} was allowed");
            assert!(o.text.contains("no second factor enrolled"), "{}", o.text);
        }
        assert!(b.declared().contains("enforce") && !b.declared().contains("exfil"));
        assert!(!b.dir.path().join("etc/patch-rule.json").exists());
    }

    #[test]
    fn loosening_spends_an_approval_bound_to_the_change_itself() {
        let b = TestBox::new(Ok("dashboard-stepup"));
        assert!(b.run("egress set enforce --preset github").ok);
        let o = b.run("egress set off --approval ABCD-EFGH-JKLM-NPQR");
        assert!(o.ok, "{}", o.text);
        let asked = b.asked.borrow().clone();
        assert_eq!(asked.len(), 1);
        let (scope, project, env, code) = &asked[0];
        assert_eq!((scope.as_str(), project.as_str()), ("host-guard", "egress"));
        assert_eq!(code, "ABCD-EFGH-JKLM-NPQR");
        assert_eq!(env, &change_digest(&w("egress set off")));
        // the digest is in the alphabet an approval's fields allow, and differs by change
        assert!(
            env.len() == 16
                && env
                    .bytes()
                    .all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase())
        );
        assert_ne!(
            change_digest(&w("egress set off")),
            change_digest(&w("egress set log"))
        );
        assert!(b.declared().contains("\"off\""));
    }

    #[test]
    fn a_refused_approval_changes_nothing_and_says_how_to_get_one() {
        let b = TestBox::new(Ok("bootstrap"));
        assert!(b.run("egress set enforce --preset github").ok);
        *b.answer.borrow_mut() = Err("that approval is not valid".into());
        let o = b.run("egress set off --approval ABCD-EFGH-JKLM-NPQR");
        assert!(!o.ok);
        assert!(
            o.text
                .contains("--scope host-guard --project egress --env "),
            "{}",
            o.text
        );
        assert!(b.declared().contains("enforce"));
        // the secrets service is down: the same, never an open list
        *b.answer.borrow_mut() = Err("the box's secrets service is not reachable".into());
        assert!(!b.run("egress set off --approval ABCD-EFGH-JKLM-NPQR").ok);
        assert!(b.declared().contains("enforce"));
    }

    #[test]
    fn the_approval_word_is_checked_and_only_rides_on_a_change() {
        let b = TestBox::new(Ok("dashboard-stepup"));
        assert!(!b.run("egress report --approval ABCD").ok);
        assert!(!b.run("egress set off --approval").ok);
        assert!(!b.run("egress set off --approval A --approval B").ok);
        assert!(!b.run("egress set off --approval a.b").ok);
        let (rest, a) = take_approval(&w("egress set log --approval X-Y --preset github")).unwrap();
        assert_eq!(rest, w("egress set log --preset github"));
        assert_eq!(a.as_deref(), Some("X-Y"));
    }
}
