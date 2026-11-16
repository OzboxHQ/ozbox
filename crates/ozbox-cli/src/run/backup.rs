//! `ozbox backup`: list, back up now, restore, delete and the schedule. Provider snapshots go through the same plan,
//! confirm and apply as every other change; a repository (restic) backup is planned by the same code the dashboard
//! uses and started on the box through its agent.

use ozbox_core::{BoxName, Error, Operation, Plan, Provider, SnapshotInfo};
use serde_json::{json, Value};

use super::{confirm, finish, mutate, print_json, CliError, Flags, Result};
use crate::backup_ops::{apply_restic, call, plan_restic};
use crate::backups::{Backups, Schedule, ScheduleKind};
use crate::cli::{BackupCommand as C, BackupTo, ProviderKind};
use crate::config::Config;
use crate::messages::t;
use crate::settings::Settings;

const DAYS: [&str; 7] = ["mon", "tue", "wed", "thu", "fri", "sat", "sun"];

pub(super) fn command(
    p: &dyn Provider,
    kind: ProviderKind,
    config: &Config,
    command: C,
    f: &Flags,
) -> Result<()> {
    let agent = crate::serve::agent_for(kind == ProviderKind::Fake, super::route_inputs(config));
    let a = agent.as_ref();
    let settings = super::load_settings()?;
    match command {
        C::List { name } => list(p, a, &settings, &name, f),
        C::Now { name, to } => now(p, a, &settings, &name, to, f),
        C::Restore {
            name,
            id,
            new_box,
            in_place,
        } => restore(p, a, &settings, &name, &id, new_box, in_place, f),
        C::Delete { name, id } => delete(p, a, &settings, &name, &id, f),
        C::Schedule {
            r#box,
            every,
            at,
            on,
            keep_daily,
            keep_weekly,
            keep_monthly,
        } => schedule(
            settings,
            r#box,
            every,
            at,
            on,
            [keep_daily, keep_weekly, keep_monthly],
            f,
        ),
    }
}

fn require(p: &dyn Provider, name: &BoxName) -> Result<ozbox_core::BoxRecord> {
    p.get(name)?
        .ok_or_else(|| CliError::Core(Error::NotFound(name.to_string())))
}

fn provider_items(p: &dyn Provider, name: &BoxName) -> (Vec<SnapshotInfo>, Option<String>) {
    match p.snapshots(name) {
        Ok(l) => (l, None),
        Err(Error::Unsupported { why, .. }) => (Vec::new(), Some(why)),
        Err(e) => (Vec::new(), Some(e.to_string())),
    }
}

/// The repository backups of a running box: `(items, why not)`.
fn restic_items(
    a: &dyn crate::serve::BoxAgent,
    settings: &Settings,
    rec: &ozbox_core::BoxRecord,
) -> (Vec<Value>, Option<String>) {
    if settings.backups.restic.is_none() {
        return (Vec::new(), Some(t("backup.restic_off", &[])));
    }
    if rec.state != ozbox_core::BoxState::Running {
        return (Vec::new(), Some(format!("the box is {}", rec.state)));
    }
    match call(a, rec, "GET", "/snapshots", &Value::Null) {
        Ok((200, v)) => (v["items"].as_array().cloned().unwrap_or_default(), None),
        Ok((409, _)) => (Vec::new(), None),
        Ok((_, v)) => (
            Vec::new(),
            Some(crate::backup_ops::reason(
                &v,
                "the box could not list its backups",
            )),
        ),
        Err(e) => (Vec::new(), Some(e)),
    }
}

fn size_text(bytes: Option<u64>) -> String {
    match bytes {
        Some(b) => format!("{:.1} GiB", b as f64 / 1_073_741_824.0),
        None => "-".into(),
    }
}

fn list(
    p: &dyn Provider,
    a: &dyn crate::serve::BoxAgent,
    settings: &Settings,
    name: &BoxName,
    f: &Flags,
) -> Result<()> {
    let rec = require(p, name)?;
    let (snaps, provider_note) = provider_items(p, name);
    let (repo, repo_note) = restic_items(a, settings, &rec);
    let old_disks = p.old_work_disks(name).unwrap_or_default();
    if f.json {
        let mut items: Vec<Value> = snaps
            .iter()
            .map(|s| {
                json!({
                    "id": s.id, "kind": "snapshot", "created_at": s.created_at, "size_bytes": s.size_bytes,
                    "status": s.status, "includes_work": s.includes_work,
                    "purpose": s.labels.get(ozbox_core::PURPOSE_LABEL),
                })
            })
            .collect();
        items.extend(repo.iter().map(|i| {
            json!({
                "id": i["id"], "kind": "restic", "created_at": i["time"], "size_bytes": i["size_bytes"],
                "status": "completed", "includes_work": true,
            })
        }));
        items.sort_by(|x, y| y["created_at"].as_str().cmp(&x["created_at"].as_str()));
        return print_json(&json!({
            "box": name,
            "items": items,
            "provider": { "supported": provider_note.is_none(), "error": provider_note },
            "restic": { "target_set": settings.backups.restic.is_some(), "error": repo_note },
            "old_disks": old_disks,
        }));
    }
    if snaps.is_empty() && repo.is_empty() {
        println!("{}", t("backup.none", &[("box", name.as_str())]));
    } else {
        println!("{}", t("backup.header", &[("box", name.as_str())]));
        let mut rows: Vec<(String, String, String, String, String, bool)> = snaps
            .iter()
            .map(|s| {
                (
                    s.created_at.clone().unwrap_or_default(),
                    s.id.clone(),
                    "snapshot".to_string(),
                    size_text(s.size_bytes),
                    s.status.clone(),
                    !s.includes_work,
                )
            })
            .collect();
        rows.extend(repo.iter().map(|i| {
            (
                i["time"].as_str().unwrap_or_default().to_string(),
                i["id"].as_str().unwrap_or_default().to_string(),
                "restic".to_string(),
                size_text(i["size_bytes"].as_u64()),
                "completed".to_string(),
                false,
            )
        }));
        rows.sort_by(|x, y| y.0.cmp(&x.0));
        for (when, id, kind, size, status, no_work) in rows {
            println!(
                "{}",
                t(
                    "backup.row",
                    &[
                        ("id", &id),
                        ("kind", &kind),
                        ("when", &when),
                        ("size", &size),
                        ("status", &status),
                        (
                            "note",
                            &if no_work {
                                t("backup.note_no_work", &[])
                            } else {
                                String::new()
                            }
                        ),
                    ]
                )
            );
        }
    }
    for d in &old_disks {
        println!(
            "{}",
            t(
                "backup.old_disk",
                &[
                    ("box", name.as_str()),
                    ("id", &d.id),
                    (
                        "size",
                        &d.size_gb
                            .map_or_else(|| "-".to_string(), |g| format!("{g} GB"))
                    ),
                    ("from", d.restored_from.as_deref().unwrap_or("-")),
                    ("state", &d.state),
                ]
            )
        );
    }
    if let Some(why) = provider_note {
        println!("{}", t("backup.provider_unsupported", &[("why", &why)]));
    }
    if let Some(why) = repo_note {
        println!("{}", t("backup.restic_unreachable", &[("why", &why)]));
    }
    Ok(())
}

/// Plan, show, confirm and start a repository operation. The provider is not involved.
fn restic_mutate(
    p: &dyn Provider,
    a: &dyn crate::serve::BoxAgent,
    settings: &Settings,
    op: Operation,
    f: &Flags,
) -> Result<()> {
    let rec = require(p, op.box_name())?;
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0);
    let plan: Plan =
        plan_restic(settings, a, p.id(), &rec, &op, now).map_err(|e| CliError::Msg(e.message))?;
    if !f.json {
        print!("{plan}");
    }
    if plan.is_noop() {
        return finish(f, &plan, false, None);
    }
    if f.dry_run {
        if !f.json {
            println!("Dry run: nothing was changed.");
        }
        return finish(f, &plan, false, None);
    }
    confirm(&plan, f)?;
    let secrets = crate::serve::secret_store();
    apply_restic(settings, a, secrets.as_ref(), &rec, &plan)?;
    if !f.json {
        println!(
            "{}",
            t("backup.repo_started", &[("box", rec.spec.name.as_str())])
        );
    }
    finish(f, &plan, true, Some(&rec))
}

fn now(
    p: &dyn Provider,
    a: &dyn crate::serve::BoxAgent,
    settings: &Settings,
    name: &BoxName,
    to: Option<BackupTo>,
    f: &Flags,
) -> Result<()> {
    let to = to.unwrap_or(
        if settings.backups.provider_snapshots || settings.backups.restic.is_none() {
            BackupTo::Snapshot
        } else {
            BackupTo::Restic
        },
    );
    if to == BackupTo::Both && !f.json {
        println!("{}", t("backup.now_both", &[]));
    }
    if matches!(to, BackupTo::Snapshot | BackupTo::Both) {
        mutate(p, Operation::Snapshot { name: name.clone() }, f)?;
    }
    if matches!(to, BackupTo::Restic | BackupTo::Both) {
        restic_mutate(
            p,
            a,
            settings,
            Operation::ResticBackup { name: name.clone() },
            f,
        )?;
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn restore(
    p: &dyn Provider,
    a: &dyn crate::serve::BoxAgent,
    settings: &Settings,
    name: &BoxName,
    id: &str,
    new_box: Option<BoxName>,
    in_place: bool,
    f: &Flags,
) -> Result<()> {
    let rec = require(p, name)?;
    let (snaps, _) = provider_items(p, name);
    if snaps.iter().any(|s| s.id == id) {
        return match (new_box, in_place) {
            (Some(to), _) => mutate(
                p,
                Operation::Clone {
                    from: name.clone(),
                    to,
                    snapshot: Some(id.to_string()),
                },
                f,
            ),
            (None, true) => {
                mutate(
                    p,
                    Operation::RestoreWork {
                        name: name.clone(),
                        snapshot: id.to_string(),
                    },
                    f,
                )?;
                if !f.dry_run {
                    check_after_restore(p, a, name, f);
                }
                Ok(())
            }
            (None, false) => Err(CliError::Msg(t("backup.in_place_or_new", &[]))),
        };
    }
    let (repo, _) = restic_items(a, settings, &rec);
    if repo.iter().any(|i| i["id"].as_str() == Some(id)) {
        if let Some(to) = new_box {
            return restore_to_new_box(p, a, settings, name, &to, id, f);
        }
        return restic_mutate(
            p,
            a,
            settings,
            Operation::ResticRestore {
                name: name.clone(),
                snapshot: id.to_string(),
                in_place,
                from_box: None,
            },
            f,
        );
    }
    Err(CliError::Msg(t(
        "backup.unknown_id",
        &[("id", id), ("box", name.as_str())],
    )))
}

/// After /work was swapped for a restored disk and the box started: wait for it to answer and show its self-test. Says
/// plainly when the box was left stopped. Never changes anything.
fn check_after_restore(
    p: &dyn Provider,
    a: &dyn crate::serve::BoxAgent,
    name: &BoxName,
    f: &Flags,
) {
    use super::upgrade::{describe_selftest, verify_after, Waits};
    if f.json {
        return;
    }
    let running = matches!(p.get(name), Ok(Some(r)) if r.state == ozbox_core::BoxState::Running);
    if !running {
        println!("{}", t("backup.restore_stopped", &[("box", name.as_str())]));
        return;
    }
    println!(
        "{}",
        t("backup.restore_checking", &[("box", name.as_str())])
    );
    let (ready, test) = verify_after(p, a, name, Waits::default());
    println!("{}", ready.detail);
    if let Some(test) = &test {
        for line in describe_selftest(test) {
            println!("{line}");
        }
    }
}

/// Plan, show, confirm and carry out a restore of a repository backup into a new box: create it, wait for its agent,
/// hand it the credentials, restore, check. Running the same command again carries on where it stopped.
fn restore_to_new_box(
    p: &dyn Provider,
    a: &dyn crate::serve::BoxAgent,
    settings: &Settings,
    from: &BoxName,
    to: &BoxName,
    id: &str,
    f: &Flags,
) -> Result<()> {
    restore_to_new_box_paced(
        p,
        a,
        crate::serve::secret_store().as_ref(),
        settings,
        from,
        to,
        id,
        crate::restore_new::Pace::default(),
        f,
    )
}

#[allow(clippy::too_many_arguments)]
fn restore_to_new_box_paced(
    p: &dyn Provider,
    a: &dyn crate::serve::BoxAgent,
    secrets: &dyn crate::secrets::SecretStore,
    settings: &Settings,
    from: &BoxName,
    to: &BoxName,
    id: &str,
    pace: crate::restore_new::Pace,
    f: &Flags,
) -> Result<()> {
    use crate::restore_new::{self as rn, Step};
    // The same fleet cap, budget and setup rules as any other box that is added.
    let adds = Operation::Clone {
        from: from.clone(),
        to: to.clone(),
        snapshot: None,
    };
    super::guard_rails(
        p,
        &Operation::RestoreToNewBox {
            from: from.clone(),
            to: to.clone(),
            snapshot: id.to_string(),
        },
    )?;
    crate::settings::enforce(settings, p, &adds)?;
    let plan = rn::plan(settings, a, p, from, to, id).map_err(|e| CliError::Msg(e.message))?;
    if !f.json {
        print!("{plan}");
    }
    if f.dry_run {
        if !f.json {
            println!("Dry run: nothing was changed.");
        }
        return finish(f, &plan, false, None);
    }
    confirm(&plan, f)?;
    let created = rn::create_box(p, &plan)?;
    let mut say = |s: &str| {
        if !f.json {
            println!(
                "{}",
                t(
                    "backup.new_box_progress",
                    &[("box", to.as_str()), ("what", s)]
                )
            );
        }
    };
    match rn::drive(p, a, secrets, settings, to, id, pace, &mut say) {
        Step::Done { selftest, detail } => {
            if !f.json {
                println!("{detail}");
            }
            finish(f, &plan, true, created.as_ref())?;
            if selftest.is_some_and(|t| !t.ok) {
                return Err(CliError::Msg(t(
                    "backup.new_box_selftest",
                    &[("box", to.as_str())],
                )));
            }
            Ok(())
        }
        Step::Failed(why) => Err(CliError::Msg(t(
            "backup.new_box_failed",
            &[
                ("box", to.as_str()),
                ("why", &why),
                ("from", from.as_str()),
                ("id", id),
            ],
        ))),
        Step::Waiting(_) => Err(CliError::Msg(t(
            "backup.new_box_waiting",
            &[("box", to.as_str())],
        ))),
    }
}

fn delete(
    p: &dyn Provider,
    a: &dyn crate::serve::BoxAgent,
    settings: &Settings,
    name: &BoxName,
    id: &str,
    f: &Flags,
) -> Result<()> {
    let rec = require(p, name)?;
    let (snaps, _) = provider_items(p, name);
    if p.old_work_disks(name)
        .unwrap_or_default()
        .iter()
        .any(|d| d.id == id)
    {
        return mutate(
            p,
            Operation::DeleteOldWork {
                name: name.clone(),
                volume: id.to_string(),
            },
            f,
        );
    }
    if snaps.iter().any(|s| s.id == id) {
        return mutate(
            p,
            Operation::DeleteSnapshot {
                name: name.clone(),
                snapshot: id.to_string(),
            },
            f,
        );
    }
    let (repo, _) = restic_items(a, settings, &rec);
    if repo.iter().any(|i| i["id"].as_str() == Some(id)) {
        return restic_mutate(
            p,
            a,
            settings,
            Operation::ResticForget {
                name: name.clone(),
                snapshot: id.to_string(),
            },
            f,
        );
    }
    Err(CliError::Msg(t(
        "backup.unknown_id",
        &[("id", id), ("box", name.as_str())],
    )))
}

fn weekday(s: &str) -> Option<u8> {
    DAYS.iter()
        .position(|d| *d == s.to_ascii_lowercase().get(..3).unwrap_or(""))
        .and_then(|i| u8::try_from(i).ok())
}

fn describe(sch: &Schedule) -> String {
    match sch.kind {
        ScheduleKind::Off => t("backup.sched.off", &[]),
        ScheduleKind::Daily => t("backup.sched.daily", &[("time", &sch.time)]),
        ScheduleKind::Weekly => t(
            "backup.sched.weekly",
            &[
                (
                    "day",
                    DAYS.get(usize::from(sch.weekday)).copied().unwrap_or("?"),
                ),
                ("time", &sch.time),
            ],
        ),
    }
}

/// The schedule and retention as one line for a person.
pub(crate) fn schedule_line(b: &Backups, zone: &str, scope: &str) -> String {
    let sch = if scope.is_empty() {
        b.schedule.clone()
    } else {
        b.schedule_for(scope.trim_start_matches(" for "))
    };
    t(
        "backup.sched.line",
        &[
            ("scope", scope),
            ("text", &describe(&sch)),
            ("zone", zone),
            ("d", &b.retention.keep_daily.to_string()),
            ("w", &b.retention.keep_weekly.to_string()),
            ("m", &b.retention.keep_monthly.to_string()),
            ("h", &b.catch_up_hours.to_string()),
        ],
    )
}

fn schedule(
    mut settings: Settings,
    one: Option<BoxName>,
    every: Option<String>,
    at: Option<String>,
    on: Option<String>,
    keep: [Option<u32>; 3],
    f: &Flags,
) -> Result<()> {
    let changing =
        every.is_some() || at.is_some() || on.is_some() || keep.iter().any(Option::is_some);
    if changing {
        let mut sch = one.as_ref().map_or_else(
            || settings.backups.schedule.clone(),
            |n| settings.backups.schedule_for(n.as_str()),
        );
        if let Some(e) = &every {
            sch.kind = match e.as_str() {
                "daily" => ScheduleKind::Daily,
                "weekly" => ScheduleKind::Weekly,
                _ => ScheduleKind::Off,
            };
        }
        if let Some(a) = at {
            sch.time = a;
        }
        if let Some(d) = on {
            sch.weekday = weekday(&d)
                .ok_or_else(|| CliError::Msg(t("backup.sched.bad_day", &[("day", &d)])))?;
        }
        if sch.is_on()
            && every.is_some()
            && !settings.backups.schedule.is_on()
            && sch.time.is_empty()
        {
            return Err(CliError::Msg(t("backup.sched.needs_at", &[])));
        }
        match &one {
            Some(n) => {
                let o = settings.backups.overrides.entry(n.to_string()).or_default();
                o.enabled = Some(sch.is_on());
                o.schedule = Some(sch);
            }
            None => settings.backups.schedule = sch,
        }
        let b = &mut settings.backups.retention;
        if let Some(v) = keep[0] {
            b.keep_daily = v;
        }
        if let Some(v) = keep[1] {
            b.keep_weekly = v;
        }
        if let Some(v) = keep[2] {
            b.keep_monthly = v;
        }
        settings.validate()?;
        if !f.dry_run {
            let path = Settings::path()
                .ok_or_else(|| CliError::Msg(t("backup.sched.no_settings", &[])))?;
            settings.save_to(&path)?;
        }
    }
    let zone = settings.locale.zone().to_string();
    let scope = one
        .as_ref()
        .map(|n| format!(" for {n}"))
        .unwrap_or_default();
    if f.json {
        return print_json(&json!({
            "scope": one,
            "schedule": one.as_ref().map_or_else(|| settings.backups.schedule.clone(), |n| settings.backups.schedule_for(n.as_str())),
            "retention": settings.backups.retention,
            "catch_up_hours": settings.backups.catch_up_hours,
            "zone": zone,
            "saved": changing && !f.dry_run,
            "dry_run": f.dry_run,
        }));
    }
    println!("{}", schedule_line(&settings.backups, &zone, &scope));
    if changing {
        println!(
            "{}",
            t(
                if f.dry_run {
                    "backup.sched.dry"
                } else {
                    "backup.sched.saved"
                },
                &[]
            )
        );
    }
    Ok(())
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use crate::backups::{
        ResticKind, ResticTarget, SECRET_ACCESS_KEY, SECRET_PASSWORD, SECRET_SECRET_KEY,
    };
    use crate::restore_new::Pace;
    use crate::secrets::{MemorySecrets, SecretStore};
    use crate::serve::agent::SimulatedAgent;
    use ozbox_core::{BoxSpec, Size};

    fn quick() -> Pace {
        Pace {
            timeout: std::time::Duration::from_secs(5),
            poll: std::time::Duration::from_millis(1),
        }
    }

    #[test]
    fn a_repository_backup_is_restored_into_a_new_box_by_one_command_and_a_repeat_carries_on() {
        let dir = tempfile::tempdir().unwrap();
        let p = ozbox_provider_fake::open(dir.path());
        let from = BoxName::new("dev").unwrap();
        p.apply(
            &p.plan(&Operation::Create {
                spec: BoxSpec::new(from.clone(), Size::S),
            })
            .unwrap(),
        )
        .unwrap();
        let mut settings = Settings::default();
        settings.backups.restic = Some(ResticTarget {
            kind: ResticKind::S3,
            location: "https://objects.example.com/bucket".into(),
        });
        let secrets = MemorySecrets::default();
        secrets.set(SECRET_PASSWORD, "correct-horse").unwrap();
        secrets.set(SECRET_ACCESS_KEY, "AKIAEXAMPLE").unwrap();
        secrets.set(SECRET_SECRET_KEY, "sekrit-value").unwrap();
        let agent = SimulatedAgent::default();
        let rec = p.get(&from).unwrap().unwrap();
        crate::backup_ops::ensure_credentials(
            &agent,
            &rec,
            settings.backups.restic.as_ref().unwrap(),
            &secrets,
            true,
        )
        .unwrap();
        call(
            &agent,
            &rec,
            "POST",
            "/run",
            &json!({"keep_daily": 7, "keep_weekly": 4, "keep_monthly": 6}),
        )
        .unwrap();
        let (_, v) = call(&agent, &rec, "GET", "/snapshots", &Value::Null).unwrap();
        let id = v["items"][0]["id"].as_str().unwrap().to_string();

        let to = BoxName::new("copy").unwrap();
        let f = Flags {
            yes: true,
            dry_run: false,
            json: true,
        };
        // A dry run plans and changes nothing.
        let dry = Flags {
            dry_run: true,
            ..Flags {
                yes: true,
                dry_run: false,
                json: true,
            }
        };
        restore_to_new_box_paced(
            &p,
            &agent,
            &secrets,
            &settings,
            &from,
            &to,
            &id,
            quick(),
            &dry,
        )
        .unwrap();
        assert!(p.get(&to).unwrap().is_none());
        // The real run creates, restores and checks.
        restore_to_new_box_paced(
            &p,
            &agent,
            &secrets,
            &settings,
            &from,
            &to,
            &id,
            quick(),
            &f,
        )
        .unwrap();
        let made = p.get(&to).unwrap().unwrap();
        assert!(made
            .spec
            .labels
            .contains_key(crate::restore_new::MARKER_LABEL));
        // Running it again (as after an interruption) is fine and creates nothing twice.
        restore_to_new_box_paced(
            &p,
            &agent,
            &secrets,
            &settings,
            &from,
            &to,
            &id,
            quick(),
            &f,
        )
        .unwrap();
        assert_eq!(p.list().unwrap().len(), 2);
        // A name that is somebody else's box is refused.
        let other = BoxName::new("other").unwrap();
        p.apply(
            &p.plan(&Operation::Create {
                spec: BoxSpec::new(other.clone(), Size::S),
            })
            .unwrap(),
        )
        .unwrap();
        assert!(restore_to_new_box_paced(
            &p,
            &agent,
            &secrets,
            &settings,
            &from,
            &other,
            &id,
            quick(),
            &f
        )
        .is_err());
    }
}
