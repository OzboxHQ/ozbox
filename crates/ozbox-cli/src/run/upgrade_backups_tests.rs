//! What an upgrade does to a box's restic backups: the settings and credentials come through, a box whose backups stopped
//! is a loud failure with the command, and nothing a laptop holds overwrites what the box already has.

use std::sync::Mutex;

use ozbox_core::{BoxName, BoxRecord, BoxSpec, MetricsSample, Operation, Provider, Size};
use serde_json::{json, Value};

use super::*;
use crate::backups::{ResticKind, ResticTarget};
use crate::secrets::{MemorySecrets, SecretStore};
use crate::serve::agent::SelfTest;

type TestResult = std::result::Result<(), Box<dyn std::error::Error>>;

/// A box whose backup API answers from a few flags, and which can start its new system disk without the credentials.
struct BackupBox {
    /// Credentials are on the box.
    configured: Mutex<bool>,
    /// The box's durable record that backups were set up (kept on /work).
    expected: bool,
    /// The repository answers.
    reachable: bool,
    /// What the box says once its machine was replaced (its first self-test): a new store starts without credentials.
    configured_after_replace: bool,
    /// `METHOD /sub` of every call, in order.
    calls: Mutex<Vec<String>>,
}

impl BackupBox {
    fn new(configured: bool, expected: bool, reachable: bool, after_replace: bool) -> Self {
        Self {
            configured: Mutex::new(configured),
            expected,
            reachable,
            configured_after_replace: after_replace,
            calls: Mutex::new(Vec::new()),
        }
    }

    fn said(&self, call: &str) -> usize {
        self.calls
            .lock()
            .unwrap()
            .iter()
            .filter(|c| *c == call)
            .count()
    }
}

impl BoxAgent for BackupBox {
    fn metrics_now(&self, _: &BoxRecord, _: u64) -> std::result::Result<MetricsSample, AgentError> {
        Err(AgentError::Unsupported("none".into()))
    }
    fn metrics_series(
        &self,
        _: &BoxRecord,
        _: u64,
        _: u64,
        _: u64,
    ) -> std::result::Result<Vec<MetricsSample>, AgentError> {
        Err(AgentError::Unsupported("none".into()))
    }
    fn incidents(
        &self,
        _: &BoxRecord,
        _: u64,
        _: u64,
    ) -> std::result::Result<Vec<crate::serve::agent::Incident>, AgentError> {
        Ok(Vec::new())
    }
    fn selftest(&self, _: &BoxRecord, _: u64) -> std::result::Result<SelfTest, AgentError> {
        // the new machine answers its first self-test: from here on it is the box after the replace
        if self.said("selftest") == 0 {
            *self.configured.lock().unwrap() = self.configured_after_replace;
        }
        self.calls.lock().unwrap().push("selftest".into());
        Ok(SelfTest {
            ts_ms: 1,
            ok: true,
            all_verified: true,
            checks: Vec::new(),
        })
    }
    fn restic(
        &self,
        _: &BoxRecord,
        method: &str,
        sub: &str,
        _: &[u8],
    ) -> std::result::Result<(u16, Value), AgentError> {
        self.calls.lock().unwrap().push(format!("{method} {sub}"));
        let configured = *self.configured.lock().unwrap();
        Ok(match (method, sub) {
            ("GET", "/status") => (
                200,
                json!({ "configured": configured, "expected": self.expected, "running": null, "last": null }),
            ),
            ("GET", "/snapshots") if !configured => (
                409,
                json!({ "error": "no repository", "code": "not_configured" }),
            ),
            ("GET", "/snapshots") if self.reachable => (
                200,
                json!({ "items": [{ "id": "aabbccdd" }, { "id": "11223344" }] }),
            ),
            ("GET", "/snapshots") => (
                502,
                json!({ "error": "backup failed", "code": "backup_failed" }),
            ),
            ("PUT", "/credentials") => {
                *self.configured.lock().unwrap() = true;
                (200, json!({ "ok": true }))
            }
            _ => (404, json!({ "error": "not found" })),
        })
    }
}

fn laptop(holds: bool) -> (crate::settings::Settings, MemorySecrets) {
    let mut settings = crate::settings::Settings::default();
    let secrets = MemorySecrets::default();
    if holds {
        settings.backups.restic = Some(ResticTarget {
            kind: ResticKind::S3,
            location: "https://objects.example.com/bucket".into(),
        });
        secrets
            .set("restic-password", "correct-horse-battery")
            .unwrap();
        secrets.set("restic-access-key", "AKIAEXAMPLE").unwrap();
        secrets
            .set("restic-secret-key", "sekrit-key-value")
            .unwrap();
    }
    (settings, secrets)
}

/// Run `ozbox upgrade` (the command's own flow, on the fake provider) against `agent`. `accept` is `--accept-new-secrets-store`
/// with the store reported lost; otherwise the store is reported kept.
fn upgrade(agent: &BackupBox, holds: bool, accept: bool) -> std::result::Result<(), String> {
    let dir = tempfile::tempdir().map_err(|e| e.to_string())?;
    let p = ozbox_provider_fake::open(dir.path());
    let n = BoxName::new("dev").map_err(|e| e.to_string())?;
    p.apply(
        &p.plan(&Operation::Create {
            spec: BoxSpec::new(n.clone(), Size::S),
        })
        .map_err(|e| e.to_string())?,
    )
    .map_err(|e| e.to_string())?;
    let (settings, secrets) = laptop(holds);
    let fate = if accept {
        StoreFate::Lost
    } else {
        StoreFate::Kept
    };
    execute(
        &p,
        agent,
        n,
        Some("fake-image-2".into()),
        false,
        &Flags {
            yes: true,
            dry_run: false,
            json: true,
        },
        Waits {
            timeout: Duration::from_secs(2),
            poll: Duration::from_millis(5),
        },
        &Around {
            store_check: &|_, _| StoreCheck {
                fate,
                detail: "test".into(),
            },
            accept_new_store: accept,
            recover: &|_, _| None,
            restore_backups: &|ag, rec| restore_with(&settings, ag, rec, &secrets),
            restore_services: &|_, _| None,
            memory_guard: &|_, _| None,
            refresh_ssh: &|_, _| Step::new(StepOutcome::Skipped, String::new()),
            review_signers: &|_| None,
            place_escrow: &|_, _| None,
            first_boot: FirstBootOpts {
                ours: "a".repeat(64),
                reprovision: false,
                allow_mismatch: false,
                enabled: false,
            },
            strict_checkpoint: false,
            legacy_checkpoint: false,
        },
    )
    .map_err(|e| e.to_string())
}

#[test]
fn a_box_whose_store_came_through_keeps_its_credentials_and_is_checked_even_when_this_computer_holds_none(
) {
    // set up on the box itself: nothing in this computer's settings or secret store
    let agent = BackupBox::new(true, true, true, true);
    upgrade(&agent, false, false).unwrap();
    // asked, not assumed: the repository must answer after the upgrade
    assert_eq!(agent.said("GET /snapshots"), 1);
    assert_eq!(agent.said("PUT /credentials"), 0);
}

#[test]
fn credentials_a_box_already_holds_are_never_overwritten_from_this_computer() {
    // this computer holds a repository too (maybe an older one): the box's own credentials are the ones its backups use
    let agent = BackupBox::new(true, true, true, true);
    upgrade(&agent, true, false).unwrap();
    assert_eq!(agent.said("PUT /credentials"), 0);
    assert_eq!(agent.said("GET /snapshots"), 1);
}

#[test]
fn a_new_store_with_backups_set_up_on_the_box_fails_loudly_and_names_the_command() {
    // the box had backups (its own record says so) and the new store started without them; this computer holds nothing
    let agent = BackupBox::new(true, true, true, false);
    let e = upgrade(&agent, false, true).unwrap_err();
    assert!(e.contains("backups are not working"), "{e}");
    assert_eq!(
        agent.said("PUT /credentials"),
        0,
        "nothing to put back from"
    );
}

#[test]
fn a_box_made_before_the_record_existed_is_still_caught_by_what_the_upgrade_read_before_replacing_it(
) {
    // no record on the box (expected false), but the upgrade saw its credentials before the replace
    let agent = BackupBox::new(true, false, true, false);
    let e = upgrade(&agent, false, true).unwrap_err();
    assert!(e.contains("backups are not working"), "{e}");
}

#[test]
fn a_new_store_whose_credentials_this_computer_holds_gets_them_back_and_backups_work() {
    let agent = BackupBox::new(true, true, true, false);
    upgrade(&agent, true, true).unwrap();
    assert_eq!(agent.said("PUT /credentials"), 1);
    assert_eq!(agent.said("GET /snapshots"), 1);
    // the self-test runs again, so the report describes the box as it is left
    assert_eq!(agent.said("selftest"), 2);
}

#[test]
fn credentials_that_are_back_but_a_repository_that_does_not_answer_is_a_failure() {
    let agent = BackupBox::new(true, true, false, true);
    let e = upgrade(&agent, false, false).unwrap_err();
    assert!(e.contains("backups are not working"), "{e}");
}

#[test]
fn a_box_that_never_had_backups_is_not_failed_for_it() {
    let agent = BackupBox::new(false, false, false, false);
    upgrade(&agent, false, false).unwrap();
    assert_eq!(agent.said("GET /snapshots"), 0);
}

fn running(dir: &std::path::Path) -> std::result::Result<(impl Provider, BoxRecord), String> {
    let p = ozbox_provider_fake::open(dir);
    let n = BoxName::new("dev").map_err(|e| e.to_string())?;
    p.apply(
        &p.plan(&Operation::Create {
            spec: BoxSpec::new(n.clone(), Size::S),
        })
        .map_err(|e| e.to_string())?,
    )
    .map_err(|e| e.to_string())?;
    let rec = p.get(&n).map_err(|e| e.to_string())?.ok_or("no box")?;
    Ok((p, rec))
}

#[test]
fn each_outcome_says_what_happened_and_what_to_run_and_never_a_value() -> TestResult {
    let d = tempfile::tempdir()?;
    let (_p, rec) = running(d.path())?;
    // kept: credentials came through the upgrade, the repository answers
    let kept = verify_backups(&BackupBox::new(true, true, true, true), &rec, false, None);
    assert_eq!(kept.outcome, StepOutcome::Done);
    assert!(
        kept.detail.contains("came through") && kept.detail.contains("2 backups"),
        "{}",
        kept.detail
    );
    // put back from this computer
    let put = Step::new(StepOutcome::Done, "put back");
    let back = verify_backups(
        &BackupBox::new(true, true, true, true),
        &rec,
        false,
        Some(put),
    );
    assert_eq!(back.outcome, StepOutcome::Done);
    assert!(
        back.detail.contains("put back from your secret store"),
        "{}",
        back.detail
    );
    // stopped: the credentials are gone, with the command, whoever knew it was set up (the box, or the upgrade before)
    for (expected, before) in [(true, false), (false, true), (true, true)] {
        let gone = verify_backups(
            &BackupBox::new(false, expected, true, false),
            &rec,
            before,
            None,
        );
        assert_eq!(gone.outcome, StepOutcome::Failed);
        assert!(
            gone.detail.contains("HAVE STOPPED")
                && gone.detail.contains("ozbox backup credentials dev"),
            "{}",
            gone.detail
        );
    }
    // a failed attempt to put them back keeps its own reason in the same failure
    let tried = Step::new(StepOutcome::Failed, "the restic-password is not set");
    let why = verify_backups(
        &BackupBox::new(false, false, true, false),
        &rec,
        false,
        Some(tried),
    );
    assert_eq!(why.outcome, StepOutcome::Failed);
    assert!(why.detail.contains("restic-password"), "{}", why.detail);
    // not working: credentials are there and the repository does not answer
    let down = verify_backups(&BackupBox::new(true, true, false, true), &rec, false, None);
    assert_eq!(down.outcome, StepOutcome::Failed);
    assert!(
        down.detail.contains("ARE NOT WORKING")
            && down.detail.contains("ozbox backup now dev --to restic"),
        "{}",
        down.detail
    );
    // never set up: nothing to check, nothing failed
    let none = verify_backups(
        &BackupBox::new(false, false, false, false),
        &rec,
        false,
        None,
    );
    assert_eq!(none.outcome, StepOutcome::Skipped);
    // a box that cannot be asked, that was set up before: still a failure, never a quiet skip
    struct Mute;
    impl BoxAgent for Mute {
        fn metrics_now(
            &self,
            _: &BoxRecord,
            _: u64,
        ) -> std::result::Result<MetricsSample, AgentError> {
            Err(AgentError::Unsupported("none".into()))
        }
        fn metrics_series(
            &self,
            _: &BoxRecord,
            _: u64,
            _: u64,
            _: u64,
        ) -> std::result::Result<Vec<MetricsSample>, AgentError> {
            Err(AgentError::Unsupported("none".into()))
        }
        fn selftest(&self, _: &BoxRecord, _: u64) -> std::result::Result<SelfTest, AgentError> {
            Err(AgentError::Unsupported("none".into()))
        }
        fn incidents(
            &self,
            _: &BoxRecord,
            _: u64,
            _: u64,
        ) -> std::result::Result<Vec<crate::serve::agent::Incident>, AgentError> {
            Ok(Vec::new())
        }
    }
    assert_eq!(
        verify_backups(&Mute, &rec, true, None).outcome,
        StepOutcome::Failed
    );
    assert_eq!(
        verify_backups(&Mute, &rec, false, None).outcome,
        StepOutcome::Skipped
    );
    Ok(())
}

#[test]
fn sending_credentials_by_command_needs_a_repository_here_and_says_so_otherwise() -> TestResult {
    use crate::run::backup::credentials_with;
    let d = tempfile::tempdir()?;
    let (p, rec) = running(d.path())?;
    let f = Flags {
        yes: true,
        dry_run: false,
        json: true,
    };
    // nothing held here: the message says where to add it
    let (settings, secrets) = laptop(false);
    let agent = BackupBox::new(false, true, true, false);
    let e = credentials_with(&p, &agent, &settings, &rec.spec.name, &f, &secrets).unwrap_err();
    assert!(e.to_string().contains("Settings -> Backups"), "{e}");
    assert_eq!(agent.said("PUT /credentials"), 0);
    // held here: sent, and no value anywhere in what is said
    let (settings, secrets) = laptop(true);
    credentials_with(&p, &agent, &settings, &rec.spec.name, &f, &secrets).unwrap();
    assert_eq!(agent.said("PUT /credentials"), 1);
    Ok(())
}

/// A box that never answers (it did not come back from the replace).
struct Silent;
impl BoxAgent for Silent {
    fn metrics_now(&self, _: &BoxRecord, _: u64) -> std::result::Result<MetricsSample, AgentError> {
        Err(AgentError::Unsupported("none".into()))
    }
    fn metrics_series(
        &self,
        _: &BoxRecord,
        _: u64,
        _: u64,
        _: u64,
    ) -> std::result::Result<Vec<MetricsSample>, AgentError> {
        Err(AgentError::Unsupported("none".into()))
    }
    fn selftest(&self, _: &BoxRecord, _: u64) -> std::result::Result<SelfTest, AgentError> {
        Err(AgentError::Unreachable("no answer".into()))
    }
    fn incidents(
        &self,
        _: &BoxRecord,
        _: u64,
        _: u64,
    ) -> std::result::Result<Vec<crate::serve::agent::Incident>, AgentError> {
        Ok(Vec::new())
    }
}

#[test]
fn a_box_that_did_not_come_back_says_its_backups_were_not_checked_not_that_there_was_nothing_to_verify(
) -> TestResult {
    let d = tempfile::tempdir()?;
    let (p, rec) = running(d.path())?;
    let waits = Waits {
        timeout: Duration::from_millis(60),
        poll: Duration::from_millis(5),
    };
    let none = |_: &dyn BoxAgent, _: &BoxRecord| None;
    // it had backups: the line says they could not be checked, with what to run
    let after = settle_after_replace(&p, &Silent, &rec.spec.name, waits, &none, &none, true);
    assert_eq!(after.ready.outcome, StepOutcome::Failed);
    assert!(
        after.backup.detail.contains("NOT CHECKED")
            && after.backup.detail.contains("ozbox backup list dev"),
        "{}",
        after.backup.detail
    );
    assert!(!after.backup.detail.contains("nothing to verify"));
    // it never had any: the old, quiet line
    let quiet = settle_after_replace(&p, &Silent, &rec.spec.name, waits, &none, &none, false);
    assert!(
        quiet.backup.detail.contains("nothing to verify"),
        "{}",
        quiet.backup.detail
    );
    Ok(())
}

#[test]
fn a_failed_put_back_is_kept_in_the_report_even_when_the_box_holds_credentials_and_answers(
) -> TestResult {
    let d = tempfile::tempdir()?;
    let (_p, rec) = running(d.path())?;
    // the helper stored the credentials and then refused (so the box says configured), and the repository answers
    let tried = Step::new(
        StepOutcome::Failed,
        "the helper refused: it could not keep the record",
    );
    let step = verify_backups(
        &BackupBox::new(true, true, true, true),
        &rec,
        false,
        Some(tried),
    );
    assert_eq!(step.outcome, StepOutcome::Failed);
    assert!(
        step.detail.contains("could not keep the record") && step.detail.contains("2 backups"),
        "{}",
        step.detail
    );
    Ok(())
}

#[test]
fn backups_turned_off_for_a_box_on_this_computer_are_a_choice_never_a_loud_stop() -> TestResult {
    let d = tempfile::tempdir()?;
    let (_p, rec) = running(d.path())?;
    let (mut settings, secrets) = laptop(true);
    settings.backups.overrides.insert(
        "dev".into(),
        crate::backups::BoxOverride {
            enabled: Some(false),
            ..Default::default()
        },
    );
    // the box lost its credentials (a new store); this computer would put them back, but the person turned this box off
    let agent = BackupBox::new(false, true, true, false);
    let restored = restore_with(&settings, &agent, &rec, &secrets);
    assert_eq!(
        agent.said("PUT /credentials"),
        0,
        "nothing is put back for a box turned off"
    );
    assert_eq!(
        restored.as_ref().map(|s| s.outcome),
        Some(StepOutcome::Skipped)
    );
    let step = verify_backups(&agent, &rec, true, restored);
    assert_eq!(step.outcome, StepOutcome::Skipped);
    assert!(
        step.detail.contains("turned off") && !step.detail.contains("STOPPED"),
        "{}",
        step.detail
    );
    Ok(())
}

#[test]
fn a_repository_in_use_is_not_called_unreachable() -> TestResult {
    struct InUse(BackupBox);
    impl BoxAgent for InUse {
        fn metrics_now(
            &self,
            r: &BoxRecord,
            n: u64,
        ) -> std::result::Result<MetricsSample, AgentError> {
            self.0.metrics_now(r, n)
        }
        fn metrics_series(
            &self,
            r: &BoxRecord,
            a: u64,
            b: u64,
            c: u64,
        ) -> std::result::Result<Vec<MetricsSample>, AgentError> {
            self.0.metrics_series(r, a, b, c)
        }
        fn selftest(&self, r: &BoxRecord, n: u64) -> std::result::Result<SelfTest, AgentError> {
            self.0.selftest(r, n)
        }
        fn incidents(
            &self,
            r: &BoxRecord,
            a: u64,
            b: u64,
        ) -> std::result::Result<Vec<crate::serve::agent::Incident>, AgentError> {
            self.0.incidents(r, a, b)
        }
        fn restic(
            &self,
            r: &BoxRecord,
            m: &str,
            sub: &str,
            b: &[u8],
        ) -> std::result::Result<(u16, Value), AgentError> {
            if (m, sub) == ("GET", "/snapshots") {
                return Ok((409, json!({ "error": "in use", "code": "busy" })));
            }
            self.0.restic(r, m, sub, b)
        }
    }
    let d = tempfile::tempdir()?;
    let (_p, rec) = running(d.path())?;
    let step = verify_backups(
        &InUse(BackupBox::new(true, true, true, true)),
        &rec,
        false,
        None,
    );
    assert_eq!(step.outcome, StepOutcome::Skipped, "{}", step.detail);
    assert!(
        step.detail.contains("using the repository") && !step.detail.contains("NOT WORKING"),
        "{}",
        step.detail
    );
    Ok(())
}
