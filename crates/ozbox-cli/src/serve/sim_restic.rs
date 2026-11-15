//! The demo box's restic: the real backup service of the box daemon, run over an in-memory stand-in for the restic
//! program and its repository. The repository is shared by every demo box, as a bring-your-own one is.

use std::path::PathBuf;
use std::sync::{Arc, Mutex};

use ozbox_core::{CommandRunner, CommandSpec, Output};
use ozboxd::backup::BackupConfig;
use ozboxd::backup_root;
use ozboxd::backup_service::BackupService;
use ozboxd::timeutil::{Clock, SystemClock};
use serde_json::{json, Value};

#[derive(Clone)]
struct Snap {
    id: String,
    time_ms: u64,
    tags: Vec<String>,
    bytes: u64,
}

/// What `restic` would print and do, for the four commands the daemon runs.
#[derive(Clone, Default)]
pub struct SimRepo {
    snaps: Arc<Mutex<Vec<Snap>>>,
}

fn tag_arg(args: &[String]) -> Vec<String> {
    args.iter()
        .position(|a| a == "--tag")
        .and_then(|i| args.get(i + 1))
        .map(|t| t.split(',').map(str::to_string).collect())
        .unwrap_or_default()
}

fn ok(stdout: String) -> ozbox_core::Result<Output> {
    Ok(Output {
        status: Some(0),
        stdout,
        stderr: String::new(),
    })
}

impl CommandRunner for SimRepo {
    fn run(&self, cmd: &CommandSpec) -> ozbox_core::Result<Output> {
        let mut snaps = self.snaps.lock().unwrap_or_else(|p| p.into_inner());
        let now = SystemClock.now_ms();
        let first = cmd.args.first().map(String::as_str).unwrap_or("");
        match first {
            "backup" => {
                let mut id = [0u8; 8];
                let _ = getrandom::getrandom(&mut id);
                snaps.push(Snap {
                    id: id.iter().map(|b| format!("{b:02x}")).collect(),
                    time_ms: now,
                    tags: tag_arg(&cmd.args),
                    bytes: 52_428_800,
                });
                ok(String::new())
            }
            "snapshots" => {
                let want = tag_arg(&cmd.args);
                let list: Vec<Value> = snaps
                    .iter()
                    .filter(|s| want.iter().all(|t| s.tags.contains(t)))
                    .map(|s| {
                        json!({
                            "id": s.id,
                            "time": crate::state::format_rfc3339(s.time_ms),
                            "tags": s.tags,
                            "summary": { "total_bytes_processed": s.bytes },
                        })
                    })
                    .collect();
                ok(Value::Array(list).to_string())
            }
            "forget" => {
                // `forget --prune <id>` removes that snapshot; the retention form keeps everything in the sandbox.
                if let Some(id) = cmd.args.iter().skip(1).find(|a| {
                    !a.starts_with("--") && a.len() >= 8 && a.bytes().all(|b| b.is_ascii_hexdigit())
                }) {
                    snaps.retain(|s| &s.id != id);
                }
                ok(String::new())
            }
            _ => ok(String::new()),
        }
    }
}

/// One demo box's service, with its own credentials folder.
pub fn service_for(dir: PathBuf, name: &str, repo: &SimRepo) -> Arc<BackupService> {
    let _ = std::fs::create_dir_all(&dir);
    let cfg = BackupConfig {
        env_file: dir.join("restic.env"),
        box_name: Some(name.to_string()),
        ..BackupConfig::default()
    };
    Arc::new(BackupService::new(cfg, Arc::new(repo.clone()), Arc::new(SystemClock)).inline())
}

/// The same checks the daemon's helper makes, then the demo's credentials folder (a real box hands them to its secrets
/// service instead; a demo has no such service).
pub fn provision(
    dir: &std::path::Path,
) -> impl Fn(&backup_root::Request) -> Result<(), String> + '_ {
    move |r| {
        backup_root::validate(r)?;
        let (env, pass) = (dir.join("restic.env"), dir.join("restic.pass"));
        match r.action {
            backup_root::Action::Clear => {
                let _ = std::fs::remove_file(&env);
                let _ = std::fs::remove_file(&pass);
                Ok(())
            }
            backup_root::Action::Set => {
                let text = format!(
                    "{}RESTIC_PASSWORD_FILE={}\n",
                    backup_root::render_settings(&r.env),
                    pass.display()
                );
                std::fs::write(&pass, &r.password).map_err(|e| e.kind().to_string())?;
                std::fs::write(&env, text).map_err(|e| e.kind().to_string())
            }
        }
    }
}
