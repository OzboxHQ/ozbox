//! Running plugins. A plugin is never run until its program's SHA-256 has been approved, the run has an empty
//! environment (apart from `PATH`), a time limit and a size limit, and nothing a plugin says is trusted: answers are
//! parsed strictly and failures are cut short.

use std::collections::BTreeMap;
use std::io::{BufRead, Read, Write};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use ozbox_core::{
    Backend, BoxRecord, BoxSpec, Capabilities, DiskGb, Error as CoreError, MachineChoice, Size,
};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::protocol::{
    Failure, MachineChoiceWire, Manifest, Request, Response, API_VERSION, MAX_MESSAGE,
};

/// How long one call may take.
pub const CALL_TIMEOUT: Duration = Duration::from_secs(120);

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PluginError {
    /// The folder or its manifest is not usable. The text is plain and holds no plugin output.
    Manifest(String),
    /// The program's hash is not the approved one (or nothing is approved yet).
    NotApproved,
    /// The program could not be started, timed out, wrote too much, or answered with something that is not a response.
    Run(&'static str),
    /// The plugin answered with a failure.
    Failed(Failure),
}

impl std::fmt::Display for PluginError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            PluginError::Manifest(m) => f.write_str(m),
            PluginError::NotApproved => f.write_str("this plugin's program has not been approved (or has changed since): run `ozbox plugin approve`"),
            PluginError::Run(m) => f.write_str(m),
            PluginError::Failed(x) => write!(f, "{}: {}", x.code, x.message),
        }
    }
}

impl std::error::Error for PluginError {}

pub fn sha256_hex(bytes: &[u8]) -> String {
    ring::digest::digest(&ring::digest::SHA256, bytes)
        .as_ref()
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}

/// A plugin folder: `plugin.toml` and the program it names.
#[derive(Debug, Clone)]
pub struct Plugin {
    pub manifest: Manifest,
    pub dir: PathBuf,
}

impl Plugin {
    pub fn load(dir: &Path) -> Result<Plugin, PluginError> {
        let text = std::fs::read_to_string(dir.join("plugin.toml"))
            .map_err(|_| PluginError::Manifest("the folder has no readable plugin.toml".into()))?;
        let manifest: Manifest = toml::from_str(&text).map_err(|e| {
            PluginError::Manifest(format!("plugin.toml is not valid: {}", e.message()))
        })?;
        manifest
            .check()
            .map_err(|m| PluginError::Manifest(m.into()))?;
        Ok(Plugin {
            manifest,
            dir: dir.to_path_buf(),
        })
    }

    fn program(&self) -> PathBuf {
        self.dir.join(&self.manifest.program)
    }

    /// The SHA-256 of the program file, which is what a person approves.
    pub fn program_hash(&self) -> Result<String, PluginError> {
        let bytes = std::fs::read(self.program()).map_err(|_| {
            PluginError::Manifest("the program named in plugin.toml could not be read".into())
        })?;
        Ok(sha256_hex(&bytes))
    }

    /// Make one call. Refuses unless `approvals` holds this program's current hash.
    pub fn call(&self, approvals: &Approvals, op: &str, args: Value) -> Result<Value, PluginError> {
        call_with_limit(self, approvals, op, args, CALL_TIMEOUT)
    }
}

/// [`Plugin::call`] with a time limit of the caller's choosing.
pub fn call_with_limit(
    plugin: &Plugin,
    approvals: &Approvals,
    op: &str,
    args: Value,
    limit: Duration,
) -> Result<Value, PluginError> {
    let hash = plugin.program_hash()?;
    if approvals.get(&plugin.manifest.name) != Some(hash.as_str()) {
        return Err(PluginError::NotApproved);
    }
    run_program(&plugin.program(), &plugin.dir, op, args, limit)
}

fn run_program(
    program: &Path,
    cwd: &Path,
    method: &str,
    params: Value,
    limit: Duration,
) -> Result<Value, PluginError> {
    let init = Request::new(
        1,
        "initialize",
        json!({ "api_version": API_VERSION, "host": "ozbox" }),
    );
    let call = Request::new(2, method, params);
    let call_line = serde_json::to_string(&call)
        .map_err(|_| PluginError::Run("the request could not be built"))?;
    if call_line.len() > MAX_MESSAGE {
        return Err(PluginError::Run("the request is too large"));
    }
    let init_line = serde_json::to_string(&init)
        .map_err(|_| PluginError::Run("the request could not be built"))?;
    let mut child = Command::new(program)
        .current_dir(cwd)
        .env_clear()
        .env("PATH", "/usr/local/bin:/usr/bin:/bin")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .map_err(|_| PluginError::Run("the plugin could not be started"))?;
    let (Some(mut stdin), Some(stdout)) = (child.stdin.take(), child.stdout.take()) else {
        let _ = child.kill();
        return Err(PluginError::Run("the plugin could not be started"));
    };
    // Lines arrive through a channel so that every wait has a deadline. A line longer than the limit ends the read.
    let (tx, rx) = std::sync::mpsc::channel::<Option<String>>();
    std::thread::spawn(move || {
        let mut r = std::io::BufReader::new(stdout);
        loop {
            let mut buf = Vec::new();
            let n = (&mut r)
                .take(MAX_MESSAGE as u64 + 1)
                .read_until(b'\n', &mut buf);
            if matches!(n, Ok(0) | Err(_)) || buf.len() > MAX_MESSAGE {
                let _ = tx.send(None);
                return;
            }
            if tx
                .send(Some(String::from_utf8_lossy(&buf).into_owned()))
                .is_err()
            {
                return;
            }
        }
    });
    let deadline = Instant::now() + limit;
    let outcome = (|| {
        let mut exchange = |line: &str, id: u64| -> Result<Result<Value, Failure>, PluginError> {
            // A plugin that exits without reading is not an error of ours; its answer (or its silence) decides.
            let _ = writeln!(stdin, "{line}");
            let _ = stdin.flush();
            loop {
                let left = deadline.saturating_duration_since(Instant::now());
                match rx.recv_timeout(left) {
                    Ok(Some(l)) if l.trim().is_empty() => continue,
                    Ok(Some(l)) => {
                        let r = Response::from_line(l.trim()).filter(|r| r.id == id);
                        return r
                            .map(|r| r.outcome)
                            .ok_or(PluginError::Run("the plugin's answer is not valid"));
                    }
                    Ok(None) => return Err(PluginError::Run("the plugin ended without answering")),
                    Err(_) => return Err(PluginError::Run("the plugin did not answer in time")),
                }
            }
        };
        let hello = exchange(&init_line, 1)?.map_err(PluginError::Failed)?;
        if hello["api_version"].as_u64() != Some(u64::from(API_VERSION)) {
            return Err(PluginError::Run(
                "the plugin speaks another protocol version",
            ));
        }
        exchange(&call_line, 2)
    })();
    drop(stdin);
    // the plugin sees the end of its input and exits; a laggard is killed
    let end = Instant::now() + Duration::from_millis(500);
    loop {
        match child.try_wait() {
            Ok(Some(_)) => break,
            _ if Instant::now() >= end => {
                let _ = child.kill();
                let _ = child.wait();
                break;
            }
            _ => std::thread::sleep(Duration::from_millis(5)),
        }
    }
    match outcome? {
        Ok(v) => Ok(v),
        Err(mut f) => {
            f.message.truncate(300);
            f.code.truncate(32);
            Err(PluginError::Failed(f))
        }
    }
}

/// Which program hash a person approved for each plugin. `plugins.toml`.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Approvals {
    #[serde(default)]
    approved: BTreeMap<String, String>,
}

impl Approvals {
    pub fn load(path: &Path) -> Approvals {
        std::fs::read_to_string(path)
            .ok()
            .and_then(|t| toml::from_str(&t).ok())
            .unwrap_or_default()
    }
    pub fn save(&self, path: &Path) -> Result<(), String> {
        if let Some(d) = path.parent() {
            let _ = std::fs::create_dir_all(d);
        }
        let t = toml::to_string_pretty(self).map_err(|e| e.to_string())?;
        std::fs::write(path, t).map_err(|_| "the plugin approvals could not be written".to_string())
    }
    pub fn get(&self, name: &str) -> Option<&str> {
        self.approved.get(name).map(String::as_str)
    }
    pub fn approve(&mut self, name: &str, hash: &str) {
        self.approved.insert(name.to_string(), hash.to_string());
    }
    pub fn revoke(&mut self, name: &str) -> bool {
        self.approved.remove(name).is_some()
    }
}

fn core_err(provider: &str, e: PluginError) -> CoreError {
    match e {
        PluginError::Failed(f) => match f.code.as_str() {
            "unsupported" => CoreError::Unsupported {
                provider: provider.to_string(),
                what: "do that".into(),
                why: f.message,
            },
            "not_found" => CoreError::NotFound(f.message),
            "already_exists" => CoreError::AlreadyExists(f.message),
            _ => CoreError::Provider(f.message),
        },
        other => CoreError::Provider(other.to_string()),
    }
}

/// A provider plugin as an `ozbox_core::Backend`: wrap it in `ozbox_core::Engine` and it plans, confirms and fences like
/// a built-in provider.
pub struct PluginBackend {
    plugin: Plugin,
    approvals: Approvals,
    id: String,
    caps: Capabilities,
}

impl PluginBackend {
    /// Loads the plugin and asks it to `describe` itself, so a plugin that does not answer fails here and not later.
    pub fn open(plugin: Plugin, approvals: Approvals) -> Result<PluginBackend, PluginError> {
        if plugin.manifest.kind != crate::protocol::Kind::Provider {
            return Err(PluginError::Manifest(
                "this plugin is not a provider".into(),
            ));
        }
        let v = plugin.call(&approvals, "describe", json!({}))?;
        let id = v["id"]
            .as_str()
            .filter(|s| !s.is_empty() && s.len() <= 32)
            .ok_or(PluginError::Run("the plugin's description has no id"))?
            .to_string();
        let caps: Capabilities = serde_json::from_value(v["capabilities"].clone())
            .map_err(|_| PluginError::Run("the plugin's capabilities are not valid"))?;
        Ok(PluginBackend {
            plugin,
            approvals,
            id,
            caps,
        })
    }

    fn call(&self, op: &str, args: Value) -> ozbox_core::Result<Value> {
        self.plugin
            .call(&self.approvals, op, args)
            .map_err(|e| core_err(&self.id, e))
    }

    fn call_record(&self, v: Value) -> ozbox_core::Result<BoxRecord> {
        serde_json::from_value(v).map_err(|_| {
            CoreError::Provider("the plugin returned a record that is not valid".into())
        })
    }
}

impl Backend for PluginBackend {
    fn id(&self) -> &str {
        &self.id
    }
    fn capabilities(&self) -> Capabilities {
        self.caps.clone()
    }
    fn machine_choice(&self, size: Size) -> ozbox_core::Result<MachineChoice> {
        let v = self.call("machine_choice", json!({ "size": size }))?;
        let w: MachineChoiceWire = serde_json::from_value(v)
            .map_err(|_| CoreError::Provider("the plugin's machine choice is not valid".into()))?;
        Ok(match w.note {
            Some(n) => MachineChoice::with_note(w.machine_type, n),
            None => MachineChoice::new(w.machine_type),
        })
    }
    fn list(&self) -> ozbox_core::Result<Vec<BoxRecord>> {
        serde_json::from_value(self.call("list", json!({}))?)
            .map_err(|_| CoreError::Provider("the plugin's list is not valid".into()))
    }
    fn create(&self, spec: &BoxSpec, machine_type: &str) -> ozbox_core::Result<BoxRecord> {
        let v = self.call(
            "create",
            json!({ "spec": spec, "machine_type": machine_type }),
        )?;
        self.call_record(v)
    }
    fn destroy(&self, rec: &BoxRecord) -> ozbox_core::Result<()> {
        self.call("destroy", json!({ "record": rec })).map(|_| ())
    }
    fn power_off(&self, rec: &BoxRecord) -> ozbox_core::Result<()> {
        self.call("power_off", json!({ "record": rec })).map(|_| ())
    }
    fn power_on(&self, rec: &BoxRecord) -> ozbox_core::Result<()> {
        self.call("power_on", json!({ "record": rec })).map(|_| ())
    }
    fn set_size(&self, rec: &BoxRecord, size: Size, machine_type: &str) -> ozbox_core::Result<()> {
        self.call(
            "set_size",
            json!({ "record": rec, "size": size, "machine_type": machine_type }),
        )
        .map(|_| ())
    }
    fn grow_disk(&self, rec: &BoxRecord, gb: DiskGb) -> ozbox_core::Result<()> {
        self.call("grow_disk", json!({ "record": rec, "gb": gb }))
            .map(|_| ())
    }
    fn snapshot(&self, rec: &BoxRecord) -> ozbox_core::Result<String> {
        let v = self.call("snapshot", json!({ "record": rec }))?;
        v["id"]
            .as_str()
            .filter(|s| !s.is_empty() && s.len() <= 128)
            .map(String::from)
            .ok_or_else(|| CoreError::Provider("the plugin's snapshot has no id".into()))
    }
    fn set_resume_after(&self, rec: &BoxRecord, on: bool) -> ozbox_core::Result<()> {
        self.call("set_resume_after", json!({ "record": rec, "on": on }))
            .map(|_| ())
    }
}

/// A tunnel plugin, called through plain methods (the host's tunnel runner wraps these).
pub struct TunnelPlugin {
    plugin: Plugin,
    approvals: Approvals,
}

impl TunnelPlugin {
    pub fn open(plugin: Plugin, approvals: Approvals) -> Result<TunnelPlugin, PluginError> {
        if plugin.manifest.kind != crate::protocol::Kind::Tunnel {
            return Err(PluginError::Manifest("this plugin is not a tunnel".into()));
        }
        Ok(TunnelPlugin { plugin, approvals })
    }
    pub fn start(&self, port: u16, public_url: &str) -> Result<(), PluginError> {
        self.plugin
            .call(
                &self.approvals,
                "start",
                json!({ "port": port, "public_url": public_url }),
            )
            .map(|_| ())
    }
    pub fn stop(&self) -> Result<(), PluginError> {
        self.plugin
            .call(&self.approvals, "stop", json!({}))
            .map(|_| ())
    }
    /// `(state, code)`: state is `stopped`, `running` or `failed`.
    pub fn status(&self) -> Result<(String, Option<String>), PluginError> {
        let v = self.plugin.call(&self.approvals, "status", json!({}))?;
        let state = v["state"].as_str().unwrap_or("").to_string();
        if !["stopped", "running", "failed"].contains(&state.as_str()) {
            return Err(PluginError::Run("the plugin's status is not valid"));
        }
        Ok((
            state,
            v["code"].as_str().map(|c| c.chars().take(32).collect()),
        ))
    }
}
