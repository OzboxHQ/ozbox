//! Restoring a repository backup into a NEW box, as one plan shared by the command and the dashboard server.
//!
//! The plan creates the box, then (once its agent answers) hands it the repository credentials, restores the backup
//! over its empty `/work` and checks the box. It is **resumable**: the box carries a [`MARKER_LABEL`] naming the
//! backup it is for, and [`step`] looks at what is true (is the box there and running, does its agent answer, does it
//! hold the credentials, is a restore running or finished) and does only the next thing. Running the same command again,
//! or a restarted server, carries on from wherever it stopped; nothing is repeated that already happened.
//!
//! Credentials are read from the secret store at the moment they are handed over and never kept, logged or returned.

use ozbox_core::{BoxName, BoxRecord, BoxState, Change, Error, Operation, Plan, Provider, Risk};
use serde_json::{json, Value};

use crate::backup_ops::{call, credentials_body, reason, OpError};
use crate::secrets::SecretStore;
use crate::serve::agent::{AgentError, BoxAgent, SelfTest};
use crate::settings::Settings;

/// The label the new box carries: `<source box>.<short backup id>`. It is what tells a box made by this restore (which
/// may be resumed) from one somebody else made (which is never touched).
pub const MARKER_LABEL: &str = "restored-from";

pub fn marker_value(from: &BoxName, snapshot: &str) -> String {
    let short: String = snapshot
        .chars()
        .filter(char::is_ascii_alphanumeric)
        .take(8)
        .collect();
    format!("{from}.{short}")
}

/// The spec of the new box: the source's size, disk, region and image, and the marker. Pure.
pub fn new_spec(src: &BoxRecord, to: &BoxName, snapshot: &str) -> ozbox_core::BoxSpec {
    let mut spec = src.spec.clone();
    spec.name = to.clone();
    spec.from_snapshot = None;
    spec.labels.remove(ozbox_core::RESUME_AFTER_LABEL);
    spec.labels.remove(ozbox_core::UPGRADE_TO_LABEL);
    spec.labels.insert(
        MARKER_LABEL.to_string(),
        marker_value(&src.spec.name, snapshot),
    );
    spec
}

fn refuse(status: u16, code: &'static str, message: impl Into<String>) -> OpError {
    OpError {
        status,
        code,
        message: message.into(),
    }
}

fn mapped(e: &Error) -> OpError {
    match e {
        Error::NotFound(_) => refuse(404, "not_found", e.to_string()),
        Error::Unsupported { .. } => refuse(501, "unsupported", e.to_string()),
        Error::AlreadyExists(_) => refuse(409, "already_exists", e.to_string()),
        _ => refuse(422, "cannot_create", e.to_string()),
    }
}

/// Whether the box `to` is one this restore may carry on with.
fn resumable(existing: &BoxRecord, from: &BoxName, snapshot: &str) -> bool {
    existing.spec.labels.get(MARKER_LABEL).map(String::as_str)
        == Some(marker_value(from, snapshot).as_str())
}

/// Plan the whole restore. Read-only.
pub fn plan(
    settings: &Settings,
    agent: &dyn BoxAgent,
    provider: &dyn Provider,
    from: &BoxName,
    to: &BoxName,
    snapshot: &str,
) -> Result<Plan, OpError> {
    if settings.backups.restic.is_none() {
        return Err(refuse(
            422,
            "no_repository",
            "no backup repository is set up; add one in Settings -> Backups first",
        ));
    }
    if snapshot.trim().is_empty() {
        return Err(refuse(400, "bad_request", "name the backup to restore"));
    }
    let src = provider.get(from).map_err(|e| mapped(&e))?.ok_or_else(|| {
        refuse(
            404,
            "not_found",
            format!("box {from} was not found; the new box copies its size, disk and image"),
        )
    })?;
    let existing = provider.get(to).map_err(|e| mapped(&e))?;
    let mut notes = Vec::new();
    // The backup must be one of the repository's, when the source can say.
    if src.state == BoxState::Running {
        match call(agent, &src, "GET", "/snapshots", &Value::Null) {
            Ok((200, v)) => {
                let present = v["items"]
                    .as_array()
                    .is_some_and(|a| a.iter().any(|i| i["id"].as_str() == Some(snapshot)));
                if !present {
                    return Err(refuse(
                        404,
                        "not_found",
                        format!("{snapshot} is not a backup of {from}"),
                    ));
                }
            }
            _ => notes.push(format!(
                "{from} could not list its backups, so {snapshot} is checked by the new box once it can read the repository."
            )),
        }
    } else {
        notes.push(format!(
            "{from} is not running, so {snapshot} is checked by the new box once it can read the repository."
        ));
    }
    let mut changes = Vec::new();
    match &existing {
        Some(rec) if resumable(rec, from, snapshot) => notes.push(format!(
            "{to} was already made for this restore: it carries on from where it stopped, and nothing done is repeated."
        )),
        Some(_) => {
            return Err(refuse(
                409,
                "already_exists",
                format!("a box named {to} already exists and was not made by this restore; choose another name"),
            ))
        }
        None => {
            let created = provider
                .plan(&Operation::Create {
                    spec: new_spec(&src, to, snapshot),
                })
                .map_err(|e| mapped(&e))?;
            changes.extend(created.changes);
            notes.extend(created.notes);
        }
    }
    changes.push(Change::new(
        "backup.credentials",
        format!(
            "Put the repository credentials on {to} (from the secret store; they are never shown)"
        ),
        Risk::Low,
    ));
    changes.push(Change::new(
        "backup.restore",
        format!("Restore backup {snapshot} of {from} over the empty /work of {to}"),
        Risk::Medium,
    ));
    changes.push(Change::new(
        "box.selftest",
        format!("Run {to}'s self-test and report it"),
        Risk::Low,
    ));
    notes.push("The restore runs on the new box and can take a while; its progress is in Backups and Activity. If it is interrupted, plan and apply the same restore again to carry on.".into());
    Ok(Plan {
        operation: Operation::RestoreToNewBox {
            from: from.clone(),
            to: to.clone(),
            snapshot: snapshot.to_string(),
        },
        provider: provider.id().to_string(),
        changes,
        notes,
        based_on: ozbox_core::engine::fingerprint(&[Some(src), existing]),
    })
}

/// Create the box of a plan made by [`plan`] (nothing when it already exists). Refuses a plan made from an earlier
/// state. This is the only provider change; everything after it goes through the box's agent ([`step`]).
pub fn create_box(provider: &dyn Provider, plan: &Plan) -> Result<Option<BoxRecord>, Error> {
    let Operation::RestoreToNewBox { from, to, snapshot } = &plan.operation else {
        return Err(Error::Config("that is not a restore into a new box".into()));
    };
    let src = provider
        .get(from)?
        .ok_or_else(|| Error::NotFound(from.to_string()))?;
    let existing = provider.get(to)?;
    if ozbox_core::engine::fingerprint(&[Some(src.clone()), existing.clone()]) != plan.based_on {
        return Err(Error::StalePlan(format!(
            "box {from} or {to} changed after the plan was made"
        )));
    }
    if let Some(rec) = existing {
        return Ok(Some(rec));
    }
    let create = provider.plan(&Operation::Create {
        spec: new_spec(&src, to, snapshot),
    })?;
    provider.apply(&create)
}

/// What one look at the new box found.
#[derive(Debug, Clone, PartialEq)]
pub enum Step {
    /// Not there yet; say what is being waited for. The caller looks again later.
    Waiting(String),
    /// Restored. The self-test, when the box could run one.
    Done {
        selftest: Option<SelfTest>,
        detail: String,
    },
    /// Cannot go on; the reason is in words a person reads.
    Failed(String),
}

/// Look at the new box and do the next thing. Every call is safe to repeat. `now_ms` is this computer's clock.
pub fn step(
    provider: &dyn Provider,
    agent: &dyn BoxAgent,
    secrets: &dyn SecretStore,
    settings: &Settings,
    to: &BoxName,
    snapshot: &str,
    now_ms: u64,
) -> Step {
    let Some(target) = settings.backups.restic.as_ref() else {
        return Step::Failed(
            "no backup repository is set up any more (Settings -> Backups)".into(),
        );
    };
    let rec = match provider.get(to) {
        Ok(Some(r)) => r,
        Ok(None) => return Step::Failed(format!("box {to} no longer exists")),
        Err(e) => return Step::Waiting(format!("could not read {to}: {e}")),
    };
    if rec.state != BoxState::Running {
        return Step::Waiting(format!("{to} is {}", rec.state));
    }
    let status = match call(agent, &rec, "GET", "/status", &Value::Null) {
        Ok((200, v)) => v,
        Ok((_, v)) => return Step::Waiting(reason(&v, "the new box is not ready yet")),
        Err(e) => return Step::Waiting(format!("waiting for {to} to answer: {e}")),
    };
    if status["configured"] != json!(true) {
        let body = match credentials_body(target, secrets) {
            Ok(b) => b,
            // A missing secret does not mend itself: stop, and say which.
            Err(why) => return Step::Failed(why),
        };
        return match call(agent, &rec, "PUT", "/credentials", &body) {
            Ok((200, _)) => Step::Waiting("repository credentials handed to the new box".into()),
            Ok((_, v)) => {
                Step::Failed(reason(&v, "the new box refused the repository credentials"))
            }
            Err(e) => Step::Waiting(e),
        };
    }
    if let Some(running) = status["running"].as_str() {
        return Step::Waiting(format!("the new box is running a {running}"));
    }
    match (
        status["last"]["op"].as_str(),
        status["last"]["ok"].as_bool(),
    ) {
        (Some("restore"), Some(true)) => {}
        (Some("restore"), Some(false)) => {
            return Step::Failed(reason(
                &status["last"],
                "the restore failed on the new box; run the same restore again to retry it",
            ))
        }
        // No restore has run on this box yet (it is new, so any restore here is this one): start it.
        _ => {
            return match call(
                agent,
                &rec,
                "POST",
                "/restore",
                &json!({ "snapshot": snapshot, "in_place": true }),
            ) {
                Ok((202, _)) => Step::Waiting("the restore started on the new box".into()),
                Ok((409, _)) => Step::Waiting("the new box is busy; trying again".into()),
                Ok((_, v)) => Step::Failed(reason(&v, "the new box did not start the restore")),
                Err(e) => Step::Waiting(e),
            };
        }
    }
    match agent.selftest(&rec, now_ms) {
        Ok(test) => {
            let detail = if test.ok {
                format!("{to} holds the restored files and its self-test passed")
            } else {
                format!("{to} holds the restored files, but its self-test reported a problem")
            };
            Step::Done {
                selftest: Some(test),
                detail,
            }
        }
        Err(AgentError::Unsupported(why)) => Step::Done {
            selftest: None,
            detail: format!("{to} holds the restored files (self-test skipped: {why})"),
        },
        Err(AgentError::Unreachable(why)) => {
            Step::Waiting(format!("waiting for {to}'s self-test: {why}"))
        }
    }
}

/// How long [`drive`] waits, and how often it looks.
#[derive(Debug, Clone, Copy)]
pub struct Pace {
    pub timeout: std::time::Duration,
    pub poll: std::time::Duration,
}

impl Default for Pace {
    fn default() -> Self {
        Self {
            // A restore moves the whole of /work: give it hours, and say how to carry on if that is not enough.
            timeout: std::time::Duration::from_secs(6 * 3600),
            poll: std::time::Duration::from_secs(5),
        }
    }
}

fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_millis() as u64)
}

/// Call [`step`] until the box is restored or cannot go on, telling `say` about each new thing being waited for.
#[allow(clippy::too_many_arguments)]
pub fn drive(
    provider: &dyn Provider,
    agent: &dyn BoxAgent,
    secrets: &dyn SecretStore,
    settings: &Settings,
    to: &BoxName,
    snapshot: &str,
    pace: Pace,
    say: &mut dyn FnMut(&str),
) -> Step {
    let started = std::time::Instant::now();
    let mut said = String::new();
    loop {
        match step(provider, agent, secrets, settings, to, snapshot, now_ms()) {
            Step::Waiting(detail) => {
                if detail != said {
                    say(&detail);
                    said = detail.clone();
                }
                if started.elapsed() >= pace.timeout {
                    return Step::Failed(format!(
                        "still waiting ({detail}); nothing is lost. Run the same restore again to carry on where it stopped"
                    ));
                }
                std::thread::sleep(pace.poll);
            }
            done => return done,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::backups::{ResticKind, ResticTarget};
    use crate::secrets::MemorySecrets;
    use crate::serve::agent::SimulatedAgent;
    use ozbox_core::{BoxSpec, Size};

    type TestResult = std::result::Result<(), Box<dyn std::error::Error>>;

    fn quick() -> Pace {
        Pace {
            timeout: std::time::Duration::from_secs(5),
            poll: std::time::Duration::from_millis(1),
        }
    }

    struct World {
        _dir: tempfile::TempDir,
        provider: Box<dyn Provider>,
        agent: SimulatedAgent,
        secrets: MemorySecrets,
        settings: Settings,
        from: BoxName,
        to: BoxName,
        snapshot: String,
    }

    /// A source box with one repository backup, a repository set up, and its secrets in the store.
    fn world() -> std::result::Result<World, Box<dyn std::error::Error>> {
        let dir = tempfile::tempdir()?;
        let provider: Box<dyn Provider> = Box::new(ozbox_provider_fake::open(dir.path()));
        let from = BoxName::new("dev")?;
        provider.apply(&provider.plan(&Operation::Create {
            spec: BoxSpec::new(from.clone(), Size::S),
        })?)?;
        let mut settings = Settings::default();
        settings.backups.restic = Some(ResticTarget {
            kind: ResticKind::S3,
            location: "https://objects.example.com/bucket".into(),
        });
        let secrets = MemorySecrets::default();
        secrets.set(crate::backups::SECRET_PASSWORD, "correct-horse")?;
        secrets.set(crate::backups::SECRET_ACCESS_KEY, "AKIAEXAMPLE")?;
        secrets.set(crate::backups::SECRET_SECRET_KEY, "sekrit-value")?;
        let agent = SimulatedAgent::default();
        let rec = provider.get(&from)?.ok_or("no box")?;
        ensure_backup(&agent, &rec, &settings, &secrets)?;
        let snapshot = latest_backup(&agent, &rec)?;
        Ok(World {
            _dir: dir,
            provider,
            agent,
            secrets,
            settings,
            from,
            to: BoxName::new("copy")?,
            snapshot,
        })
    }

    fn ensure_backup(
        agent: &SimulatedAgent,
        rec: &BoxRecord,
        settings: &Settings,
        secrets: &MemorySecrets,
    ) -> TestResult {
        let target = settings.backups.restic.clone().ok_or("no target")?;
        crate::backup_ops::ensure_credentials(agent, rec, &target, secrets, true)?;
        let (s, _) = call(
            agent,
            rec,
            "POST",
            "/run",
            &json!({"keep_daily": 7, "keep_weekly": 4, "keep_monthly": 6}),
        )?;
        assert_eq!(s, 202);
        Ok(())
    }

    fn latest_backup(
        agent: &SimulatedAgent,
        rec: &BoxRecord,
    ) -> std::result::Result<String, Box<dyn std::error::Error>> {
        let (_, v) = call(agent, rec, "GET", "/snapshots", &Value::Null)?;
        Ok(v["items"][0]["id"].as_str().ok_or("no backup")?.to_string())
    }

    fn make_plan(w: &World) -> std::result::Result<Plan, String> {
        plan(
            &w.settings,
            &w.agent,
            w.provider.as_ref(),
            &w.from,
            &w.to,
            &w.snapshot,
        )
        .map_err(|e| e.message)
    }

    #[test]
    fn the_plan_creates_the_box_hands_over_credentials_restores_and_checks_in_one_go() -> TestResult
    {
        let w = world()?;
        let p = make_plan(&w)?;
        let kinds: Vec<&str> = p.changes.iter().map(|c| c.kind.as_str()).collect();
        assert_eq!(kinds.first().copied(), Some("box.create"), "{kinds:?}");
        assert_eq!(
            &kinds[kinds.len() - 3..],
            ["backup.credentials", "backup.restore", "box.selftest"]
        );
        assert!(w.provider.get(&w.to)?.is_none(), "planning created nothing");
        // A backup the repository does not hold is refused, naming it.
        let bad = plan(
            &w.settings,
            &w.agent,
            w.provider.as_ref(),
            &w.from,
            &w.to,
            "deadbeef",
        );
        assert!(matches!(bad, Err(e) if e.status == 404 && e.message.contains("deadbeef")));
        // No repository set up: refused with the way there.
        let mut none = w.settings.clone();
        none.backups.restic = None;
        assert!(matches!(
            plan(&none, &w.agent, w.provider.as_ref(), &w.from, &w.to, &w.snapshot),
            Err(e) if e.code == "no_repository"
        ));
        Ok(())
    }

    #[test]
    fn applying_creates_the_box_with_the_marker_and_following_it_restores_and_checks() -> TestResult
    {
        let w = world()?;
        let p = make_plan(&w)?;
        let rec = create_box(w.provider.as_ref(), &p)?.ok_or("no box")?;
        assert_eq!(
            rec.spec.labels.get(MARKER_LABEL).map(String::as_str),
            Some(marker_value(&w.from, &w.snapshot).as_str())
        );
        let mut said = Vec::new();
        let done = drive(
            w.provider.as_ref(),
            &w.agent,
            &w.secrets,
            &w.settings,
            &w.to,
            &w.snapshot,
            quick(),
            &mut |s| said.push(s.to_string()),
        );
        match done {
            Step::Done { selftest, detail } => {
                assert!(selftest.is_some_and(|t| t.ok), "{detail}");
                assert!(detail.contains("restored files"), "{detail}");
            }
            other => panic!("expected Done, got {other:?} after {said:?}"),
        }
        assert!(said.iter().any(|s| s.contains("credentials")), "{said:?}");
        assert!(said
            .iter()
            .all(|s| !s.contains("sekrit") && !s.contains("correct-horse")));
        Ok(())
    }

    #[test]
    fn a_second_plan_for_the_same_box_resumes_and_a_stranger_box_is_never_touched() -> TestResult {
        let w = world()?;
        let first = make_plan(&w)?;
        create_box(w.provider.as_ref(), &first)?;
        // The command is run again (it was interrupted): the box exists with its marker, so the plan has no create.
        let again = make_plan(&w)?;
        assert!(
            again.changes.iter().all(|c| c.kind != "box.create"),
            "{:?}",
            again.changes
        );
        assert!(again.notes.iter().any(|n| n.contains("carries on")));
        assert!(create_box(w.provider.as_ref(), &again)?.is_some());
        // A box of that name that this restore did not make is refused.
        let other = BoxName::new("other")?;
        w.provider.apply(&w.provider.plan(&Operation::Create {
            spec: BoxSpec::new(other.clone(), Size::S),
        })?)?;
        let clash = plan(
            &w.settings,
            &w.agent,
            w.provider.as_ref(),
            &w.from,
            &other,
            &w.snapshot,
        );
        assert!(matches!(clash, Err(e) if e.status == 409));
        // A plan made before the box changed is refused rather than applied.
        w.provider
            .apply(&w.provider.plan(&Operation::Pause { name: w.to.clone() })?)?;
        assert!(matches!(
            create_box(w.provider.as_ref(), &again),
            Err(Error::StalePlan(_))
        ));
        Ok(())
    }

    #[test]
    fn each_look_does_only_the_next_thing_and_a_missing_secret_stops_it() -> TestResult {
        let w = world()?;
        let p = make_plan(&w)?;
        create_box(w.provider.as_ref(), &p)?;
        let look = |secrets: &MemorySecrets| {
            step(
                w.provider.as_ref(),
                &w.agent,
                secrets,
                &w.settings,
                &w.to,
                &w.snapshot,
                0,
            )
        };
        // First look: the new box has no credentials, so they are handed over and nothing else happens.
        assert!(matches!(look(&w.secrets), Step::Waiting(d) if d.contains("credentials")));
        // Second look: it starts the restore. (The simulated box finishes it at once.)
        assert!(matches!(look(&w.secrets), Step::Waiting(d) if d.contains("restore started")));
        assert!(matches!(look(&w.secrets), Step::Done { .. }));
        // A repeat after it is done is just done again: nothing is restored twice.
        assert!(matches!(look(&w.secrets), Step::Done { .. }));

        // A box whose credentials cannot be found stops at once, naming the secret, never a value.
        let w2 = world()?;
        let p2 = make_plan(&w2)?;
        create_box(w2.provider.as_ref(), &p2)?;
        let empty = MemorySecrets::default();
        match step(
            w2.provider.as_ref(),
            &w2.agent,
            &empty,
            &w2.settings,
            &w2.to,
            &w2.snapshot,
            0,
        ) {
            Step::Failed(why) => assert!(
                why.contains("restic-password") && !why.contains("sekrit"),
                "{why}"
            ),
            other => panic!("expected a refusal, got {other:?}"),
        }
        Ok(())
    }
}
