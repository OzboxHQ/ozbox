//! The narrow privileged helper.
//!
//! The daemon runs as an ordinary user and has no way to start anything as root. Package-manager steps are handed to a
//! root one-shot (`ozboxd tools-root`, started by a systemd path unit when a request file appears). A request names a
//! job, a step number and the plan hash; the helper rebuilds the plan from the catalog compiled into its own binary and
//! runs that one step only if it is a root-class catalog step. It never runs a command from a request, and nothing it
//! prints back contains the request's text.

use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use ozbox_catalog::{Arch, Catalog};

use super::exec::{Ctx, RootPaths};
use super::job::{is_job_id, run_root_step, write_json, RootBridge, RootRequest};
use super::sys::{Log, Sys};

pub const ROOT_DIR: &str = "/run/ozbox-tools";
const MAX_REQUEST: u64 = 64 * 1024;

fn req_name(job: &str, index: usize) -> String {
    format!("{job}-{index}")
}

/// The unprivileged side: leaves a request and waits for the answer.
pub struct FileBridge {
    pub dir: PathBuf,
    pub timeout: Duration,
    pub poll: Duration,
}

impl FileBridge {
    pub fn new(dir: impl Into<PathBuf>) -> FileBridge {
        FileBridge {
            dir: dir.into(),
            timeout: Duration::from_secs(45 * 60),
            poll: Duration::from_millis(500),
        }
    }
}

impl RootBridge for FileBridge {
    fn run_step(&self, spec: &super::job::JobSpec, index: usize, log: &Log) -> Result<(), String> {
        let name = req_name(&spec.id, index);
        let request = RootRequest {
            job: spec.id.clone(),
            index,
            plan_hash: spec.plan.hash.clone(),
            request: spec.request.clone(),
            installed: spec.installed.clone(),
        };
        let req_path = self.dir.join("requests").join(format!("{name}.json"));
        let result_path = self.dir.join("results").join(format!("{name}.result"));
        let log_path = self.dir.join("results").join(format!("{name}.log"));
        let _ = std::fs::remove_file(&result_path);
        write_json(&req_path, &request)
            .map_err(|e| format!("cannot reach the installer helper: {}", e.kind()))?;
        let start = Instant::now();
        let mut seen = 0usize;
        loop {
            // Relay what the helper has logged so far.
            if let Ok(text) = std::fs::read_to_string(&log_path) {
                for l in text.lines().skip(seen) {
                    log.line(l);
                    seen += 1;
                }
            }
            if let Ok(bytes) = std::fs::read(&result_path) {
                let _ = std::fs::remove_file(&result_path);
                let _ = std::fs::remove_file(&log_path);
                let v: serde_json::Value = serde_json::from_slice(&bytes).unwrap_or_default();
                return if v["ok"] == true {
                    Ok(())
                } else {
                    Err(v["error"]
                        .as_str()
                        .unwrap_or("the installer helper failed")
                        .to_string())
                };
            }
            if start.elapsed() > self.timeout {
                let _ = std::fs::remove_file(&req_path);
                return Err(
                    "the installer helper did not answer in time; is it installed on this box?"
                        .into(),
                );
            }
            std::thread::sleep(self.poll);
        }
    }
}

/// The privileged side: handle every waiting request, then return how many were handled.
pub fn serve_requests(
    dir: &Path,
    catalog: &Catalog,
    arch: Arch,
    sys: &dyn Sys,
    root: &RootPaths,
    max_log: u64,
) -> usize {
    // Answers the unprivileged side has had a day to read are swept (it cannot delete them itself).
    if let Ok(old) = std::fs::read_dir(dir.join("results")) {
        for e in old.filter_map(Result::ok) {
            let aged = e
                .metadata()
                .and_then(|m| m.modified())
                .ok()
                .and_then(|t| t.elapsed().ok())
                .is_some_and(|a| a > Duration::from_secs(86_400));
            if aged {
                let _ = std::fs::remove_file(e.path());
            }
        }
    }
    let Ok(rd) = std::fs::read_dir(dir.join("requests")) else {
        return 0;
    };
    let mut names: Vec<PathBuf> = rd.filter_map(Result::ok).map(|e| e.path()).collect();
    names.sort();
    let mut handled = 0;
    for path in names {
        // A file still being written (`*.tmp`) is left alone; only `.json` names are requests.
        if path.extension().and_then(|e| e.to_str()) != Some("json") {
            continue;
        }
        let Some(stem) = path
            .file_stem()
            .and_then(|s| s.to_str())
            .map(str::to_string)
        else {
            continue;
        };
        // Only files this helper's own naming allows: <job>-<index>.json, as plain files.
        let well_named = path.extension().and_then(|e| e.to_str()) == Some("json")
            && stem.split_once('-').is_some_and(|(j, i)| {
                is_job_id(j) && !i.is_empty() && i.bytes().all(|b| b.is_ascii_digit())
            });
        let plain = std::fs::symlink_metadata(&path)
            .map(|m| m.is_file() && m.len() <= MAX_REQUEST)
            .unwrap_or(false);
        let body = if well_named && plain {
            std::fs::read(&path).ok()
        } else {
            None
        };
        // Taken off the queue before it runs, so it can never run twice.
        let _ = std::fs::remove_file(&path);
        handled += 1;
        let result_path = dir.join("results").join(format!("{stem}.result"));
        let log_path = dir.join("results").join(format!("{stem}.log"));
        let outcome = match body.and_then(|b| serde_json::from_slice::<RootRequest>(&b).ok()) {
            None => Err("the request was not understood".to_string()),
            Some(req) if req_name(&req.job, req.index) != stem => {
                Err("the request does not match its name".to_string())
            }
            Some(req) => match Log::open(&log_path, max_log) {
                Err(e) => Err(format!("cannot open the log: {}", e.kind())),
                Ok(log) => {
                    let work = dir.join("work").join(&stem);
                    let _ = sys.remove_path(&work);
                    let _ = sys.create_dir_all(&work);
                    let ctx = Ctx {
                        sys,
                        log: &log,
                        home: PathBuf::from("/root"),
                        tmp: work.clone(),
                        root: root.clone(),
                    };
                    let r = run_root_step(catalog, arch, &req, &ctx);
                    let _ = sys.remove_path(&work);
                    r
                }
            },
        };
        let body = match &outcome {
            Ok(()) => serde_json::json!({ "ok": true }),
            Err(e) => {
                serde_json::json!({ "ok": false, "error": e.chars().take(300).collect::<String>() })
            }
        };
        let _ = write_json(&result_path, &body);
    }
    handled
}
