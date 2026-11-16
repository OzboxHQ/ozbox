//! Backups that go through a box's agent, shared by the dashboard server and the command line: reading the repository
//! credentials from the secret store at the moment they are handed over, planning a restic back up, delete or restore,
//! and starting it. Nothing here keeps a credential, logs one, or puts one in an error.

use ozbox_core::{BoxRecord, BoxState, Change, Error, Operation, Plan, Risk};
use serde_json::{json, Value};

use crate::backups::{
    ResticKind, ResticTarget, SECRET_ACCESS_KEY, SECRET_PASSWORD, SECRET_SECRET_KEY,
};
use crate::secrets::SecretStore;
use crate::serve::agent::BoxAgent;
use crate::settings::Settings;

/// A backup this old (or older) is not a way back for a restore over `/work`.
pub const WAY_BACK_MS: u64 = 10 * 60_000;

/// A refusal with the status and code the dashboard server answers with.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OpError {
    pub status: u16,
    pub code: &'static str,
    pub message: String,
}

impl OpError {
    fn new(status: u16, code: &'static str, message: impl Into<String>) -> Self {
        Self {
            status,
            code,
            message: message.into(),
        }
    }
}

/// The body for the box's `PUT /v1/backup/credentials`, read from the secret store at this moment. Errors name what is
/// missing, never a value.
pub fn credentials_body(target: &ResticTarget, secrets: &dyn SecretStore) -> Result<Value, String> {
    let get = |name: &str| -> Result<String, String> {
        secrets
            .get(name)
            .map_err(|e| e.to_string())?
            .ok_or_else(|| format!("the {name} is not set; add it in Settings → Backups"))
    };
    let password = get(SECRET_PASSWORD)?;
    let mut env = serde_json::Map::new();
    env.insert(
        "RESTIC_REPOSITORY".into(),
        Value::String(target.repository()),
    );
    if target.needs_keys() {
        let (id_key, secret_key) = match target.kind {
            ResticKind::B2 => ("B2_ACCOUNT_ID", "B2_ACCOUNT_KEY"),
            _ => ("AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY"),
        };
        env.insert(id_key.into(), Value::String(get(SECRET_ACCESS_KEY)?));
        env.insert(secret_key.into(), Value::String(get(SECRET_SECRET_KEY)?));
    }
    Ok(json!({ "env": env, "password": password }))
}

/// One call to a box's backup API: `(status, json)`.
pub fn call(
    agent: &dyn BoxAgent,
    rec: &BoxRecord,
    method: &str,
    sub: &str,
    body: &Value,
) -> Result<(u16, Value), String> {
    let bytes = if body.is_null() {
        Vec::new()
    } else {
        body.to_string().into_bytes()
    };
    agent
        .restic(rec, method, sub, &bytes)
        .map_err(|e| e.to_string())
}

pub fn reason(v: &Value, fallback: &str) -> String {
    v.get("error")
        .and_then(Value::as_str)
        .unwrap_or(fallback)
        .to_string()
}

/// When the box last finished a backup operation, on its own clock; 0 when it has none or cannot say.
pub fn box_last_finished(agent: &dyn BoxAgent, rec: &BoxRecord) -> u64 {
    call(agent, rec, "GET", "/status", &Value::Null)
        .ok()
        .and_then(|(_, v)| v["last"]["finished_ms"].as_u64())
        .unwrap_or(0)
}

/// Whether a box's `/status` answer says its secrets service was not ready (a box that has just started). An older box's answer
/// has no such field and reads as ready.
pub fn status_not_ready(status: &Value) -> bool {
    status.get("secrets_ready").and_then(Value::as_bool) == Some(false)
}

/// Remove the repository credentials from a box (and, on the box, the record that backups were set up, so its self-test and
/// an upgrade stop expecting them). The one path the dashboard and the command both take.
pub fn remove_credentials(agent: &dyn BoxAgent, rec: &BoxRecord) -> Result<(), String> {
    let (s, v) = call(agent, rec, "DELETE", "/credentials", &Value::Null)?;
    if s == 200 {
        Ok(())
    } else {
        Err(reason(&v, "the box did not remove the credentials"))
    }
}

/// Make sure the box holds the repository credentials, putting them there if it does not (or `force`). `Ok(true)` when
/// they were provisioned now.
pub fn ensure_credentials(
    agent: &dyn BoxAgent,
    rec: &BoxRecord,
    target: &ResticTarget,
    secrets: &dyn SecretStore,
    force: bool,
) -> Result<bool, String> {
    if !force {
        let (s, v) = call(agent, rec, "GET", "/status", &Value::Null)?;
        if s == 200 && v.get("configured").and_then(Value::as_bool) == Some(true) {
            return Ok(false);
        }
        // A box whose secrets service is not up cannot say whether it holds credentials: "not configured" there is "not
        // known", and putting them again would overwrite what it holds. Never send on a guess.
        if s == 200 && status_not_ready(&v) {
            return Err(
                "the box's secrets service is not ready yet, so it could not be asked whether it already holds the repository credentials; nothing was sent. Try again in a moment"
                    .into(),
            );
        }
    }
    let body = credentials_body(target, secrets)?;
    let (s, v) = call(agent, rec, "PUT", "/credentials", &body)?;
    if s == 200 {
        Ok(true)
    } else {
        Err(reason(&v, "the box refused the repository credentials"))
    }
}

/// Plan a restic back up, delete or restore of `rec`. Read-only on the box. `now_ms` is this computer's clock.
pub fn plan_restic(
    settings: &Settings,
    agent: &dyn BoxAgent,
    provider_id: &str,
    rec: &BoxRecord,
    op: &Operation,
    now_ms: u64,
) -> Result<Plan, OpError> {
    let name = rec.spec.name.clone();
    if settings.backups.restic.is_none() {
        return Err(OpError::new(
            422,
            "no_repository",
            "no backup repository is set up; add one in Settings → Backups first",
        ));
    }
    if rec.state != BoxState::Running {
        return Err(OpError::new(
            409,
            "box_not_running",
            format!(
                "box {name} is {}, so its backups cannot be reached",
                rec.state
            ),
        ));
    }
    let (_, status) = call(agent, rec, "GET", "/status", &Value::Null)
        .map_err(|e| OpError::new(502, "agent_unreachable", e))?;
    let configured = status.get("configured").and_then(Value::as_bool) == Some(true);
    let mut changes = Vec::new();
    let mut notes = Vec::new();
    if !configured {
        changes.push(Change::new(
            "backup.credentials",
            format!("Put the repository credentials on {name} (from the secret store; they are never shown)"),
            Risk::Low,
        ));
    }
    match op {
        Operation::ResticBackup { .. } => {
            let k = &settings.backups.retention;
            changes.push(Change::new(
                "backup.run",
                format!(
                    "Back up /work of {name} to the repository, encrypted, then keep {} daily, {} weekly and {} monthly backups",
                    k.keep_daily, k.keep_weekly, k.keep_monthly
                ),
                Risk::Low,
            ));
            notes.push("The backup runs on the box and can take a while; its progress is in Backups and Activity.".into());
        }
        Operation::ResticForget { snapshot, .. } => {
            if !configured {
                return Err(OpError::new(
                    409,
                    "not_configured",
                    "this box has no repository credentials yet; nothing to delete",
                ));
            }
            let (s, v) = call(agent, rec, "GET", "/snapshots", &Value::Null)
                .map_err(|e| OpError::new(502, "agent_unreachable", e))?;
            if s != 200 {
                return Err(OpError::new(
                    502,
                    "backup_failed",
                    reason(&v, "the box could not list its backups"),
                ));
            }
            let present = v["items"]
                .as_array()
                .is_some_and(|a| a.iter().any(|i| i["id"].as_str() == Some(snapshot)));
            changes.clear();
            if present {
                changes.push(Change::new(
                    "backup.delete",
                    format!("Delete backup {snapshot} of {name} from the repository, and remove what only it held. It cannot be brought back."),
                    Risk::High,
                ));
            } else {
                notes.push(format!("{snapshot} is not a backup of {name} (any more)."));
            }
        }
        Operation::ResticRestore {
            snapshot,
            in_place,
            from_box,
            ..
        } => {
            let short: String = snapshot.chars().take(8).collect();
            if let Some(f) = from_box {
                notes.push(format!(
                    "The backup was made on {f}; the repository is shared, so {name} reads it directly."
                ));
            }
            if *in_place {
                // The way back is the box's own newest finished backup (its clock and ours are compared, to the minute).
                let finished = status["last"]["finished_ms"].as_u64().unwrap_or(0);
                let recent = status["last"]["ok"] == json!(true)
                    && status["last"]["op"] == json!("backup")
                    && now_ms.saturating_sub(finished) <= WAY_BACK_MS;
                if !recent {
                    return Err(OpError::new(
                        409,
                        "no_way_back",
                        "restoring over /work needs a backup of its current state made in the last 10 minutes, so the restore can itself be undone: back up now first",
                    ));
                }
                changes.push(Change::new(
                    "backup.restore",
                    format!("Put the files of backup {snapshot} back over /work of {name}. Files in the backup replace the ones on the box; files made since stay. The backup made just now is the way back."),
                    Risk::High,
                ));
            } else {
                changes.push(Change::new(
                    "backup.restore",
                    format!("Restore backup {snapshot} into /work/restored-{short} on {name}, beside the box's own files. Nothing existing is changed."),
                    Risk::Medium,
                ));
            }
        }
        _ => {}
    }
    Ok(Plan {
        operation: op.clone(),
        provider: provider_id.to_string(),
        changes,
        notes,
        based_on: ozbox_core::engine::fingerprint(&[Some(rec.clone())]),
    })
}

/// What starting a restic operation returned.
pub struct Started {
    /// For a back up: when the box last finished an operation before this one (see the dashboard server's follow-up).
    pub baseline_ms: u64,
}

/// Start the operation of a plan made by [`plan_restic`] on the box, after the credentials are on it. `rec` is the
/// box as it is now: a plan made from an earlier state is refused.
pub fn apply_restic(
    settings: &Settings,
    agent: &dyn BoxAgent,
    secrets: &dyn SecretStore,
    rec: &BoxRecord,
    plan: &Plan,
) -> Result<Started, Error> {
    let target = settings
        .backups
        .restic
        .clone()
        .ok_or_else(|| Error::Config("no backup repository is set up".into()))?;
    if ozbox_core::engine::fingerprint(&[Some(rec.clone())]) != plan.based_on {
        return Err(Error::StalePlan(format!(
            "box {} changed after the plan was made",
            rec.spec.name
        )));
    }
    if plan.changes.iter().any(|c| c.kind == "backup.credentials") {
        ensure_credentials(agent, rec, &target, secrets, true).map_err(Error::Provider)?;
    }
    let (sub, body) = match &plan.operation {
        Operation::ResticBackup { .. } => {
            let k = &settings.backups.retention;
            (
                "/run",
                json!({ "keep_daily": k.keep_daily, "keep_weekly": k.keep_weekly, "keep_monthly": k.keep_monthly }),
            )
        }
        Operation::ResticForget { snapshot, .. } => ("/forget", json!({ "snapshot": snapshot })),
        Operation::ResticRestore {
            snapshot, in_place, ..
        } => (
            "/restore",
            json!({ "snapshot": snapshot, "in_place": in_place }),
        ),
        _ => {
            return Err(Error::Config(
                "that is not a backup through the box's agent".into(),
            ))
        }
    };
    let baseline_ms = box_last_finished(agent, rec);
    let (s, v) = call(agent, rec, "POST", sub, &body).map_err(Error::Provider)?;
    if s != 202 {
        return Err(Error::Provider(reason(
            &v,
            "the box did not start the operation",
        )));
    }
    Ok(Started { baseline_ms })
}
