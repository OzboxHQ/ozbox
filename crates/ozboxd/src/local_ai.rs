//! Local AI: Ollama or vLLM serving an open-weight model from the box's own disk, on the box's own loopback address.
//!
//! `GET /v1/local-ai` says which runtimes are installed and running, which models each holds, and how any download is
//! going; `POST /v1/local-ai/pull` starts a download and returns at once (a model is gigabytes: the request cannot wait
//! for it); `DELETE /v1/local-ai/<model>?runtime=...` removes one; `POST /v1/local-ai/runtime` starts, stops or restarts
//! the runtime's service.
//!
//! The runtime is a `systemd --user` service of the box user (kept running by linger), listening on 127.0.0.1 only. The
//! daemon writes its unit file, drives it through `systemctl --user`, and talks to the runtime's own HTTP API over the
//! loopback. Every effect is behind [`Host`], so the whole thing is tested with a fake runtime on any OS.
//!
//! A model name is checked against a short list of safe characters before it goes anywhere, and the runtime's answer is
//! reduced to a few figures; nothing from a model download is shown unfiltered.

use std::collections::BTreeMap;
use std::io;
use std::sync::{Arc, Mutex, OnceLock};

use serde::Serialize;
use serde_json::{json, Value};

use crate::timeutil::Clock;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Runtime {
    Ollama,
    Vllm,
}

impl Runtime {
    pub const ALL: [Runtime; 2] = [Runtime::Ollama, Runtime::Vllm];

    pub fn parse(s: &str) -> Option<Runtime> {
        match s {
            "ollama" => Some(Runtime::Ollama),
            "vllm" => Some(Runtime::Vllm),
            _ => None,
        }
    }

    pub fn id(self) -> &'static str {
        match self {
            Runtime::Ollama => "ollama",
            Runtime::Vllm => "vllm",
        }
    }

    pub fn port(self) -> u16 {
        match self {
            Runtime::Ollama => 11434,
            Runtime::Vllm => 8000,
        }
    }

    /// The program the tool installer puts in the box user's `~/.local/bin`.
    pub fn program(self) -> &'static str {
        self.id()
    }

    pub fn unit(self) -> String {
        format!("ozbox-{}.service", self.id())
    }

    fn endpoint(self) -> String {
        format!("http://127.0.0.1:{}/v1", self.port())
    }
}

/// The unit file for a runtime. Both listen on loopback only (ADR 0005).
pub fn unit_text(rt: Runtime) -> String {
    match rt {
        Runtime::Ollama => "\
[Unit]
Description=Ollama (local models, loopback only)
After=network.target

[Service]
ExecStart=%h/.local/bin/ollama serve
Environment=OLLAMA_HOST=127.0.0.1:11434
Environment=OLLAMA_MODELS=%h/.ollama/models
Restart=on-failure
RestartSec=3

[Install]
WantedBy=default.target
"
        .to_string(),
        Runtime::Vllm => "\
[Unit]
Description=vLLM (local model, loopback only)
After=network.target

[Service]
EnvironmentFile=%h/.config/ozbox/vllm.env
ExecStart=%h/.local/bin/vllm serve ${OZBOX_VLLM_MODEL} --host 127.0.0.1 --port 8000
Restart=on-failure
RestartSec=5

[Install]
WantedBy=default.target
"
        .to_string(),
    }
}

/// A model name safe to hand to a runtime and to put in a file: letters, digits and `. _ : / -`, no leading dash, no `..`.
pub fn model_ok(m: &str) -> bool {
    !m.is_empty()
        && m.len() <= 120
        && !m.starts_with('-')
        && !m.starts_with('/')
        && !m.contains("..")
        && m.bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b':' | b'/' | b'-'))
}

fn percent_decode(s: &str) -> Option<String> {
    let b = s.as_bytes();
    let mut out = Vec::with_capacity(b.len());
    let mut i = 0;
    while i < b.len() {
        if b[i] == b'%' {
            let h = std::str::from_utf8(b.get(i + 1..i + 3)?).ok()?;
            out.push(u8::from_str_radix(h, 16).ok()?);
            i += 3;
        } else {
            out.push(b[i]);
            i += 1;
        }
    }
    String::from_utf8(out).ok()
}

// ---- the seam -------------------------------------------------------------------------------------------------

/// Everything that touches the machine.
pub trait Host: Send + Sync {
    /// Whether the runtime's program is installed for the box user.
    fn installed(&self, rt: Runtime) -> bool;
    /// Write a file under the box user's home (`rel` is relative, no `..`), creating its folder.
    fn write_home_file(&self, rel: &str, text: &str) -> io::Result<()>;
    fn remove_home_file(&self, rel: &str) -> io::Result<()>;
    /// `systemctl --user <args>`: the exit code and what it printed.
    fn systemctl(&self, args: &[&str]) -> Result<(i32, String), String>;
    /// One request to the runtime on 127.0.0.1: the status and the body.
    fn http(
        &self,
        port: u16,
        method: &str,
        path: &str,
        body: Option<&str>,
    ) -> Result<(u16, String), String>;
    /// The same, handing each line of the answer to `on_line` as it arrives (a download's progress). `on_line` returns
    /// false to stop reading. Returns the status.
    fn http_lines(
        &self,
        port: u16,
        method: &str,
        path: &str,
        body: Option<&str>,
        on_line: &mut dyn FnMut(&str) -> bool,
    ) -> Result<u16, String>;
}

// ---- state ----------------------------------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct Pull {
    pub runtime: Runtime,
    pub model: String,
    /// `pulling`, `done` or `failed`.
    pub state: &'static str,
    pub percent: Option<u32>,
    /// What the runtime last said (trimmed), or why it failed.
    pub message: String,
    pub started_ms: u64,
    pub ended_ms: Option<u64>,
}

#[derive(Default)]
struct State {
    pulls: BTreeMap<(Runtime, String), Pull>,
}

pub struct LocalAiService {
    host: Arc<dyn Host>,
    clock: Arc<dyn Clock>,
    state: Mutex<State>,
}

static GLOBAL: OnceLock<Arc<LocalAiService>> = OnceLock::new();

pub fn global() -> Option<&'static Arc<LocalAiService>> {
    GLOBAL.get()
}

pub fn install_global(s: Arc<LocalAiService>) {
    let _ = GLOBAL.set(s);
}

fn lock<T>(m: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    m.lock().unwrap_or_else(std::sync::PoisonError::into_inner)
}

fn err(status: u16, code: &str, message: &str) -> (u16, Value) {
    (
        status,
        json!({ "error": message, "code": code, "message": message }),
    )
}

/// Keep the part of a runtime's message that is a short plain sentence.
fn tidy(s: &str) -> String {
    s.chars()
        .filter(|c| !c.is_control())
        .take(160)
        .collect::<String>()
        .trim()
        .to_string()
}

impl LocalAiService {
    pub fn new(host: Arc<dyn Host>, clock: Arc<dyn Clock>) -> Self {
        Self {
            host,
            clock,
            state: Mutex::new(State::default()),
        }
    }

    /// Route `/v1/local-ai/...`. `rest` is what follows `/v1/local-ai` (empty or starting with `/`).
    pub fn route(
        self: &Arc<Self>,
        method: &str,
        rest: &str,
        query: &BTreeMap<String, String>,
        body: &[u8],
    ) -> (u16, Value) {
        let rest = rest.trim_matches('/');
        match (method, rest) {
            ("GET", "") => (200, self.status()),
            ("POST", "pull") => self.pull(body),
            ("POST", "runtime") => self.runtime_action(body),
            ("DELETE", m) if !m.is_empty() => {
                let Some(model) = percent_decode(m) else {
                    return err(400, "bad_model", "that model name is not valid");
                };
                let Some(rt) = query.get("runtime").and_then(|r| Runtime::parse(r)) else {
                    return err(400, "bad_runtime", "the runtime is ollama or vllm");
                };
                self.remove(rt, &model)
            }
            (_, "" | "pull" | "runtime") | ("DELETE", _) => {
                err(405, "method_not_allowed", "method not allowed")
            }
            _ => err(404, "not_found", "no such endpoint"),
        }
    }

    /// The models a runtime holds, or none when it is not answering.
    fn models_of(&self, rt: Runtime) -> Option<Vec<Value>> {
        let (status, body) = self
            .host
            .http(rt.port(), "GET", rt_models_path(rt), None)
            .ok()?;
        if status != 200 {
            return None;
        }
        let v: Value = serde_json::from_str(&body).ok()?;
        let list: Vec<Value> = match rt {
            Runtime::Ollama => v["models"]
                .as_array()?
                .iter()
                .filter_map(|m| {
                    let name = m["name"].as_str()?;
                    model_ok(name)
                        .then(|| json!({ "name": name, "size_bytes": m["size"].as_u64() }))
                })
                .collect(),
            Runtime::Vllm => v["data"]
                .as_array()?
                .iter()
                .filter_map(|m| {
                    let name = m["id"].as_str()?;
                    model_ok(name).then(|| json!({ "name": name, "size_bytes": Value::Null }))
                })
                .collect(),
        };
        Some(list)
    }

    pub fn status(&self) -> Value {
        let runtimes: Vec<Value> = Runtime::ALL
            .iter()
            .map(|rt| {
                let installed = self.host.installed(*rt);
                let models = if installed { self.models_of(*rt) } else { None };
                json!({
                    "id": rt.id(),
                    "installed": installed,
                    "running": models.is_some(),
                    "endpoint": rt.endpoint(),
                    "service": rt.unit(),
                    "models": models.unwrap_or_default(),
                })
            })
            .collect();
        let pulls: Vec<Pull> = lock(&self.state).pulls.values().cloned().collect();
        json!({ "runtimes": runtimes, "pulls": pulls })
    }

    /// Write the unit (the same text every time) and make sure the service is enabled and started.
    fn ensure_service(&self, rt: Runtime) -> Result<(), String> {
        if !self.host.installed(rt) {
            return Err(format!("{} is not installed on this box", rt.id()));
        }
        self.host
            .write_home_file(
                &format!(".config/systemd/user/{}", rt.unit()),
                &unit_text(rt),
            )
            .map_err(|e| format!("could not write the service file: {}", e.kind()))?;
        let unit = rt.unit();
        for args in [
            vec!["daemon-reload"],
            vec!["enable", "--now", unit.as_str()],
        ] {
            let (code, out) = self.host.systemctl(&args)?;
            if code != 0 {
                return Err(format!(
                    "the service could not be started: {}",
                    tidy(out.lines().last().unwrap_or(""))
                ));
            }
        }
        Ok(())
    }

    fn runtime_action(&self, body: &[u8]) -> (u16, Value) {
        let v: Value = match serde_json::from_slice(body) {
            Ok(v) => v,
            Err(_) => return err(400, "bad_request", "invalid JSON body"),
        };
        let Some(rt) = v["runtime"].as_str().and_then(Runtime::parse) else {
            return err(400, "bad_runtime", "the runtime is ollama or vllm");
        };
        let action = v["action"].as_str().unwrap_or("");
        let result = match action {
            "start" => self.ensure_service(rt),
            "stop" | "restart" => {
                if !self.host.installed(rt) {
                    Err(format!("{} is not installed on this box", rt.id()))
                } else {
                    let unit = rt.unit();
                    self.host
                        .systemctl(&[action, unit.as_str()])
                        .and_then(|(c, out)| {
                            if c == 0 {
                                Ok(())
                            } else {
                                Err(tidy(out.lines().last().unwrap_or("it did not work")))
                            }
                        })
                }
            }
            _ => return err(400, "bad_action", "the action is start, stop or restart"),
        };
        match result {
            Ok(()) => (200, json!({ "ok": true })),
            Err(m) => err(409, "runtime_failed", &m),
        }
    }

    fn pull(self: &Arc<Self>, body: &[u8]) -> (u16, Value) {
        let v: Value = match serde_json::from_slice(body) {
            Ok(v) => v,
            Err(_) => return err(400, "bad_request", "invalid JSON body"),
        };
        let Some(rt) = v["runtime"].as_str().and_then(Runtime::parse) else {
            return err(400, "bad_runtime", "the runtime is ollama or vllm");
        };
        let model = v["model"].as_str().unwrap_or("").to_string();
        if !model_ok(&model) {
            return err(
                400,
                "bad_model",
                "that model name has characters that are not allowed",
            );
        }
        let key = (rt, model.clone());
        {
            let st = lock(&self.state);
            if let Some(p) = st.pulls.get(&key) {
                if p.state == "pulling" {
                    return (
                        200,
                        json!({ "ok": true, "state": "pulling", "already": true }),
                    );
                }
            }
        }
        if let Err(m) = self.ensure_service(rt) {
            return err(409, "runtime_unavailable", &m);
        }
        if rt == Runtime::Vllm {
            // vLLM serves one model, chosen when it starts: record the choice and restart it onto that model.
            if let Err(e) = self.host.write_home_file(
                ".config/ozbox/vllm.env",
                &format!("OZBOX_VLLM_MODEL={model}\n"),
            ) {
                return err(
                    500,
                    "write_failed",
                    &format!("could not save the model choice: {}", e.kind()),
                );
            }
            let unit = rt.unit();
            if let Ok((c, _)) = self.host.systemctl(&["restart", unit.as_str()]) {
                if c != 0 {
                    return err(409, "runtime_failed", "vLLM could not be restarted");
                }
            }
        }
        lock(&self.state).pulls.insert(
            key.clone(),
            Pull {
                runtime: rt,
                model: model.clone(),
                state: "pulling",
                percent: None,
                message: "starting".into(),
                started_ms: self.clock.now_ms(),
                ended_ms: None,
            },
        );
        let me = Arc::clone(self);
        let spawned = std::thread::Builder::new()
            .name("ozboxd-pull".into())
            .spawn(move || me.run_pull(rt, &model));
        if spawned.is_err() {
            self.finish(
                rt,
                key.1.as_str(),
                Err("could not start the download".into()),
            );
            return err(500, "no_thread", "could not start the download");
        }
        (
            202,
            json!({ "ok": true, "state": "pulling", "runtime": rt.id(), "model": key.1 }),
        )
    }

    fn update(&self, rt: Runtime, model: &str, f: impl FnOnce(&mut Pull)) {
        if let Some(p) = lock(&self.state).pulls.get_mut(&(rt, model.to_string())) {
            f(p);
        }
    }

    fn finish(&self, rt: Runtime, model: &str, outcome: Result<(), String>) {
        let now = self.clock.now_ms();
        self.update(rt, model, |p| {
            p.ended_ms = Some(now);
            match &outcome {
                Ok(()) => {
                    p.state = "done";
                    p.percent = Some(100);
                    p.message = "downloaded".into();
                }
                Err(m) => {
                    p.state = "failed";
                    p.message = tidy(m);
                }
            }
        });
    }

    fn run_pull(&self, rt: Runtime, model: &str) {
        let outcome = match rt {
            Runtime::Ollama => self.pull_ollama(model),
            Runtime::Vllm => self.wait_for_vllm(model),
        };
        self.finish(rt, model, outcome);
    }

    fn pull_ollama(&self, model: &str) -> Result<(), String> {
        // the service may need a moment to listen after it starts
        let body = json!({ "name": model, "stream": true }).to_string();
        let mut failure: Option<String> = None;
        let mut finished = false;
        let mut last_err = String::new();
        for _ in 0..30 {
            let mut on_line = |line: &str| {
                let Ok(v) = serde_json::from_str::<Value>(line) else {
                    return true;
                };
                if let Some(e) = v["error"].as_str() {
                    failure = Some(tidy(e));
                    return false;
                }
                let status = v["status"].as_str().unwrap_or("").to_string();
                let percent = match (v["completed"].as_u64(), v["total"].as_u64()) {
                    (Some(c), Some(t)) if t > 0 => Some(((c.min(t) * 100) / t) as u32),
                    _ => None,
                };
                if status == "success" {
                    finished = true;
                }
                self.update(Runtime::Ollama, model, |p| {
                    if let Some(pc) = percent {
                        p.percent = Some(pc.min(99));
                    }
                    if !status.is_empty() {
                        p.message = tidy(&status);
                    }
                });
                true
            };
            match self.host.http_lines(
                Runtime::Ollama.port(),
                "POST",
                "/api/pull",
                Some(&body),
                &mut on_line,
            ) {
                Ok(200) => break,
                Ok(code) => {
                    last_err = format!("the runtime answered {code}");
                    break;
                }
                Err(e) => {
                    last_err = e;
                    std::thread::sleep(std::time::Duration::from_millis(if cfg!(test) {
                        5
                    } else {
                        1000
                    }));
                }
            }
        }
        if let Some(f) = failure {
            return Err(f);
        }
        if finished {
            Ok(())
        } else if !last_err.is_empty() {
            Err(last_err)
        } else {
            Err("the download ended before it finished".into())
        }
    }

    fn wait_for_vllm(&self, model: &str) -> Result<(), String> {
        // vLLM fetches the weights while it starts; the model is ready once it lists it.
        for _ in 0..(if cfg!(test) { 20 } else { 1800 }) {
            if let Some(list) = self.models_of(Runtime::Vllm) {
                if list.iter().any(|m| m["name"] == model) {
                    return Ok(());
                }
            }
            std::thread::sleep(std::time::Duration::from_millis(if cfg!(test) {
                5
            } else {
                2000
            }));
        }
        Err("vLLM did not finish loading the model in time".into())
    }

    fn remove(&self, rt: Runtime, model: &str) -> (u16, Value) {
        if !model_ok(model) {
            return err(400, "bad_model", "that model name is not valid");
        }
        if !self.host.installed(rt) {
            return err(
                409,
                "not_installed",
                &format!("{} is not installed on this box", rt.id()),
            );
        }
        let outcome = match rt {
            Runtime::Ollama => {
                let body = json!({ "name": model }).to_string();
                match self
                    .host
                    .http(rt.port(), "DELETE", "/api/delete", Some(&body))
                {
                    Ok((200, _)) => Ok(()),
                    Ok((404, _)) => Err((
                        404,
                        "no_such_model",
                        "that model is not on this box".to_string(),
                    )),
                    Ok(_) => Err((
                        502,
                        "remove_failed",
                        "the runtime would not remove it".into(),
                    )),
                    Err(e) => Err((502, "unreachable", tidy(&e))),
                }
            }
            Runtime::Vllm => {
                // vLLM holds one model while it runs; removing it stops the service and forgets the choice.
                let unit = rt.unit();
                let stopped = self.host.systemctl(&["stop", unit.as_str()]);
                let _ = self.host.remove_home_file(".config/ozbox/vllm.env");
                match stopped {
                    Ok((0, _)) => Ok(()),
                    _ => Err((
                        502,
                        "remove_failed",
                        "the service could not be stopped".into(),
                    )),
                }
            }
        };
        match outcome {
            Ok(()) => {
                lock(&self.state).pulls.remove(&(rt, model.to_string()));
                (200, json!({ "ok": true }))
            }
            Err((s, c, m)) => err(s, c, &m),
        }
    }
}

fn rt_models_path(rt: Runtime) -> &'static str {
    match rt {
        Runtime::Ollama => "/api/tags",
        Runtime::Vllm => "/v1/models",
    }
}

// ---- the real host ----------------------------------------------------------------------------------------------

#[cfg(unix)]
pub use real::RealHost;

#[cfg(unix)]
mod real {
    use super::*;
    use std::io::{BufRead, BufReader, Read, Write};
    use std::path::PathBuf;
    use std::process::{Child, Command, Stdio};
    use std::time::{Duration, Instant};

    pub struct RealHost {
        pub home: PathBuf,
    }

    fn uid() -> Option<u32> {
        let t = std::fs::read_to_string("/proc/self/status").ok()?;
        t.lines()
            .find_map(|l| l.strip_prefix("Uid:"))
            .and_then(|r| r.split_whitespace().next())
            .and_then(|n| n.parse().ok())
    }

    fn safe_rel(rel: &str) -> bool {
        !rel.is_empty()
            && !rel.starts_with('/')
            && rel
                .split('/')
                .all(|c| !c.is_empty() && c != "." && c != "..")
    }

    impl RealHost {
        /// One request to the runtime, made by `curl` on the box's own loopback address. The daemon holds no network
        /// socket of its own (a test enforces it): the request is an argv array, and a body goes in on standard input.
        /// The status is written after the answer, on a line of its own.
        fn curl(
            &self,
            port: u16,
            method: &str,
            path: &str,
            body: Option<&str>,
            max_time_s: u64,
        ) -> Result<Child, String> {
            let mut c = Command::new("curl");
            c.args(["--silent", "--show-error", "--no-buffer"])
                .args(["--connect-timeout", "2"])
                .args(["--max-time", &max_time_s.to_string()])
                .args(["--request", method])
                .args(["--header", "Content-Type: application/json"])
                .args(["--write-out", "\n%{http_code}\n"]);
            if body.is_some() {
                c.args(["--data-binary", "@-"]);
            }
            c.arg(format!("http://127.0.0.1:{port}{path}"))
                .stdin(if body.is_some() {
                    Stdio::piped()
                } else {
                    Stdio::null()
                })
                .stdout(Stdio::piped())
                .stderr(Stdio::null());
            let mut child = c
                .spawn()
                .map_err(|_| "curl could not be started".to_string())?;
            if let (Some(mut i), Some(b)) = (child.stdin.take(), body) {
                let _ = i.write_all(b.as_bytes());
            }
            Ok(child)
        }
    }

    impl Host for RealHost {
        fn installed(&self, rt: Runtime) -> bool {
            use std::os::unix::fs::PermissionsExt;
            std::fs::metadata(self.home.join(".local/bin").join(rt.program()))
                .map(|m| m.permissions().mode() & 0o111 != 0)
                .unwrap_or(false)
        }

        fn write_home_file(&self, rel: &str, text: &str) -> io::Result<()> {
            if !safe_rel(rel) {
                return Err(io::Error::new(io::ErrorKind::InvalidInput, "path"));
            }
            let p = self.home.join(rel);
            if let Some(d) = p.parent() {
                std::fs::create_dir_all(d)?;
            }
            std::fs::write(p, text)
        }

        fn remove_home_file(&self, rel: &str) -> io::Result<()> {
            if !safe_rel(rel) {
                return Err(io::Error::new(io::ErrorKind::InvalidInput, "path"));
            }
            match std::fs::remove_file(self.home.join(rel)) {
                Err(e) if e.kind() != io::ErrorKind::NotFound => Err(e),
                _ => Ok(()),
            }
        }

        fn systemctl(&self, args: &[&str]) -> Result<(i32, String), String> {
            let uid = uid().ok_or("the box user's id is unknown")?;
            let run = format!("/run/user/{uid}");
            let mut child = Command::new("systemctl")
                .arg("--user")
                .args(args)
                .env("XDG_RUNTIME_DIR", &run)
                .env("DBUS_SESSION_BUS_ADDRESS", format!("unix:path={run}/bus"))
                .stdin(Stdio::null())
                .stdout(Stdio::piped())
                .stderr(Stdio::piped())
                .spawn()
                .map_err(|_| "systemctl could not be started".to_string())?;
            let start = Instant::now();
            loop {
                match child.try_wait() {
                    Ok(Some(st)) => {
                        let mut out = String::new();
                        if let Some(mut o) = child.stdout.take() {
                            let _ = o.by_ref().take(4096).read_to_string(&mut out);
                        }
                        if let Some(mut e) = child.stderr.take() {
                            let _ = e.by_ref().take(4096).read_to_string(&mut out);
                        }
                        return Ok((st.code().unwrap_or(1), out));
                    }
                    Ok(None) if start.elapsed() < Duration::from_secs(30) => {
                        std::thread::sleep(Duration::from_millis(50));
                    }
                    _ => {
                        let _ = child.kill();
                        let _ = child.wait();
                        return Err("the service manager did not answer in time".into());
                    }
                }
            }
        }

        fn http(
            &self,
            port: u16,
            method: &str,
            path: &str,
            body: Option<&str>,
        ) -> Result<(u16, String), String> {
            let mut child = self.curl(port, method, path, body, 8)?;
            let mut out = String::new();
            if let Some(o) = child.stdout.take() {
                let _ = o.take(4 * 1024 * 1024).read_to_string(&mut out);
            }
            let ok = child.wait().map(|s| s.success()).unwrap_or(false);
            if !ok {
                return Err("the runtime is not answering".into());
            }
            let trimmed = out.trim_end_matches('\n');
            let (answer, status) = trimmed
                .rsplit_once('\n')
                .ok_or("the runtime did not answer with HTTP")?;
            let status: u16 = status
                .trim()
                .parse()
                .map_err(|_| "the runtime did not answer with HTTP".to_string())?;
            Ok((status, answer.to_string()))
        }

        fn http_lines(
            &self,
            port: u16,
            method: &str,
            path: &str,
            body: Option<&str>,
            on_line: &mut dyn FnMut(&str) -> bool,
        ) -> Result<u16, String> {
            let mut child = self.curl(port, method, path, body, 6 * 3600)?;
            let Some(out) = child.stdout.take() else {
                return Err("the runtime is not answering".into());
            };
            let mut status = 0u16;
            let mut stopped = false;
            for line in BufReader::new(out.take(64 * 1024 * 1024)).lines() {
                let Ok(line) = line else { break };
                let line = line.trim();
                // the status is curl's own last line; the runtime's lines are JSON
                if !line.starts_with('{') && line.len() == 3 {
                    if let Ok(n) = line.parse::<u16>() {
                        status = n;
                        continue;
                    }
                }
                if !on_line(line) {
                    stopped = true;
                    break;
                }
            }
            if stopped {
                let _ = child.kill();
            }
            let ok = child.wait().map(|s| s.success()).unwrap_or(false);
            if status == 0 && !ok && !stopped {
                return Err("the runtime stopped answering".into());
            }
            Ok(if stopped && status == 0 { 200 } else { status })
        }
    }
}

// ---- tests ----------------------------------------------------------------------------------------------------

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use crate::timeutil::FakeClock;

    /// A pretend Ollama and vLLM, and a pretend service manager.
    #[derive(Default)]
    struct Fake {
        installed: Mutex<Vec<Runtime>>,
        files: Mutex<BTreeMap<String, String>>,
        calls: Mutex<Vec<String>>,
        ollama_models: Mutex<Vec<(String, u64)>>,
        ollama_up: Mutex<bool>,
        pull_lines: Mutex<Vec<String>>,
        vllm_model: Mutex<Option<String>>,
    }

    impl Host for Fake {
        fn installed(&self, rt: Runtime) -> bool {
            self.installed.lock().unwrap().contains(&rt)
        }
        fn write_home_file(&self, rel: &str, text: &str) -> io::Result<()> {
            self.files.lock().unwrap().insert(rel.into(), text.into());
            Ok(())
        }
        fn remove_home_file(&self, rel: &str) -> io::Result<()> {
            self.files.lock().unwrap().remove(rel);
            Ok(())
        }
        fn systemctl(&self, args: &[&str]) -> Result<(i32, String), String> {
            self.calls.lock().unwrap().push(args.join(" "));
            if args.first() == Some(&"enable") {
                *self.ollama_up.lock().unwrap() = true;
            }
            if args.first() == Some(&"restart") && args.get(1) == Some(&"ozbox-vllm.service") {
                let m = self
                    .files
                    .lock()
                    .unwrap()
                    .get(".config/ozbox/vllm.env")
                    .and_then(|t| t.trim().strip_prefix("OZBOX_VLLM_MODEL=").map(String::from));
                *self.vllm_model.lock().unwrap() = m;
            }
            Ok((0, String::new()))
        }
        fn http(
            &self,
            port: u16,
            method: &str,
            path: &str,
            body: Option<&str>,
        ) -> Result<(u16, String), String> {
            match (port, method, path) {
                (11434, "GET", "/api/tags") => {
                    if !*self.ollama_up.lock().unwrap() {
                        return Err("the runtime is not answering".into());
                    }
                    let models: Vec<Value> = self
                        .ollama_models
                        .lock()
                        .unwrap()
                        .iter()
                        .map(|(n, s)| json!({ "name": n, "size": s }))
                        .collect();
                    Ok((200, json!({ "models": models }).to_string()))
                }
                (11434, "DELETE", "/api/delete") => {
                    let name = serde_json::from_str::<Value>(body.unwrap_or("{}")).unwrap()["name"]
                        .as_str()
                        .unwrap_or("")
                        .to_string();
                    let mut m = self.ollama_models.lock().unwrap();
                    let before = m.len();
                    m.retain(|(n, _)| *n != name);
                    Ok((if m.len() < before { 200 } else { 404 }, String::new()))
                }
                (8000, "GET", "/v1/models") => match self.vllm_model.lock().unwrap().clone() {
                    Some(m) => Ok((200, json!({ "data": [{ "id": m }] }).to_string())),
                    None => Err("the runtime is not answering".into()),
                },
                _ => Err("no such thing".into()),
            }
        }
        fn http_lines(
            &self,
            _port: u16,
            _method: &str,
            _path: &str,
            body: Option<&str>,
            on_line: &mut dyn FnMut(&str) -> bool,
        ) -> Result<u16, String> {
            let name = serde_json::from_str::<Value>(body.unwrap_or("{}")).unwrap()["name"]
                .as_str()
                .unwrap_or("")
                .to_string();
            for l in self.pull_lines.lock().unwrap().iter() {
                if !on_line(l) {
                    return Ok(200);
                }
                if l.contains("success") {
                    self.ollama_models
                        .lock()
                        .unwrap()
                        .push((name.clone(), 4_700_000_000));
                }
            }
            Ok(200)
        }
    }

    fn rig() -> (Arc<LocalAiService>, Arc<Fake>) {
        let fake = Arc::new(Fake::default());
        fake.installed.lock().unwrap().push(Runtime::Ollama);
        let svc = Arc::new(LocalAiService::new(
            fake.clone(),
            Arc::new(FakeClock::new(1_794_182_400_000)),
        ));
        (svc, fake)
    }

    fn call(
        svc: &Arc<LocalAiService>,
        m: &str,
        rest: &str,
        q: &[(&str, &str)],
        body: &str,
    ) -> (u16, Value) {
        let q = q
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect();
        svc.route(m, rest, &q, body.as_bytes())
    }

    fn wait_for(svc: &Arc<LocalAiService>, state: &str) -> Value {
        for _ in 0..400 {
            let s = svc.status();
            if s["pulls"][0]["state"] == state {
                return s;
            }
            std::thread::sleep(std::time::Duration::from_millis(5));
        }
        panic!("pull never reached {state}: {}", svc.status());
    }

    #[test]
    fn status_says_what_is_installed_running_and_held() {
        let (svc, fake) = rig();
        let (code, v) = call(&svc, "GET", "", &[], "");
        assert_eq!(code, 200);
        assert_eq!(v["runtimes"][0]["id"], "ollama");
        assert_eq!(v["runtimes"][0]["installed"], true);
        assert_eq!(v["runtimes"][0]["running"], false);
        assert_eq!(v["runtimes"][1]["installed"], false);
        assert_eq!(v["runtimes"][0]["endpoint"], "http://127.0.0.1:11434/v1");
        *fake.ollama_up.lock().unwrap() = true;
        fake.ollama_models
            .lock()
            .unwrap()
            .push(("llama3.1:8b".into(), 4_900_000_000));
        let (_, v) = call(&svc, "GET", "", &[], "");
        assert_eq!(v["runtimes"][0]["running"], true);
        assert_eq!(v["runtimes"][0]["models"][0]["name"], "llama3.1:8b");
        assert_eq!(
            v["runtimes"][0]["models"][0]["size_bytes"],
            4_900_000_000u64
        );
    }

    #[test]
    fn a_pull_returns_at_once_shows_progress_and_ends_with_the_model_listed() {
        let (svc, fake) = rig();
        *fake.pull_lines.lock().unwrap() = vec![
            r#"{"status":"pulling manifest"}"#.into(),
            r#"{"status":"pulling abc","total":1000,"completed":250}"#.into(),
            r#"{"status":"pulling abc","total":1000,"completed":1000}"#.into(),
            r#"{"status":"success"}"#.into(),
        ];
        let (code, v) = call(
            &svc,
            "POST",
            "pull",
            &[],
            r#"{"runtime":"ollama","model":"qwen2.5-coder:7b"}"#,
        );
        assert_eq!(code, 202, "{v}");
        wait_for(&svc, "done");
        // read again: the snapshot taken while waiting may have listed the models a moment before the pull ended
        let done = svc.status();
        assert_eq!(done["pulls"][0]["percent"], 100);
        assert_eq!(done["runtimes"][0]["models"][0]["name"], "qwen2.5-coder:7b");
        // the unit was written once, loopback only, and the service enabled
        let files = fake.files.lock().unwrap();
        let unit = &files[".config/systemd/user/ozbox-ollama.service"];
        assert!(unit.contains("OLLAMA_HOST=127.0.0.1:11434") && !unit.contains("0.0.0.0"));
        assert!(fake
            .calls
            .lock()
            .unwrap()
            .iter()
            .any(|c| c == "enable --now ozbox-ollama.service"));
    }

    #[test]
    fn a_failed_download_says_why_and_a_second_pull_is_not_started_while_one_runs() {
        let (svc, fake) = rig();
        *fake.pull_lines.lock().unwrap() =
            vec![r#"{"error":"pull model manifest: file does not exist"}"#.into()];
        call(
            &svc,
            "POST",
            "pull",
            &[],
            r#"{"runtime":"ollama","model":"nope:1b"}"#,
        );
        let s = wait_for(&svc, "failed");
        assert!(s["pulls"][0]["message"]
            .as_str()
            .unwrap()
            .contains("does not exist"));
        // a finished pull may be tried again
        let (code, _) = call(
            &svc,
            "POST",
            "pull",
            &[],
            r#"{"runtime":"ollama","model":"nope:1b"}"#,
        );
        assert_eq!(code, 202);
    }

    #[test]
    fn a_runtime_that_is_not_installed_or_a_bad_name_is_refused_before_anything_is_written() {
        let (svc, fake) = rig();
        for bad in ["", "-x", "a b", "../etc", "a;b", "$(id)"] {
            let body = json!({ "runtime": "ollama", "model": bad }).to_string();
            let (code, _) = call(&svc, "POST", "pull", &[], &body);
            assert_eq!(code, 400, "{bad:?}");
        }
        let (code, v) = call(
            &svc,
            "POST",
            "pull",
            &[],
            r#"{"runtime":"vllm","model":"org/model"}"#,
        );
        assert_eq!(code, 409, "{v}");
        let (code, _) = call(
            &svc,
            "POST",
            "pull",
            &[],
            r#"{"runtime":"nope","model":"x"}"#,
        );
        assert_eq!(code, 400);
        assert!(fake.files.lock().unwrap().is_empty());
        assert!(fake.calls.lock().unwrap().is_empty());
    }

    #[test]
    fn a_model_is_removed_by_its_percent_encoded_name_and_an_absent_one_is_not_found() {
        let (svc, fake) = rig();
        *fake.ollama_up.lock().unwrap() = true;
        fake.ollama_models
            .lock()
            .unwrap()
            .push(("llama3.1:8b".into(), 1));
        let (code, _) = call(
            &svc,
            "DELETE",
            "/llama3.1%3A8b",
            &[("runtime", "ollama")],
            "",
        );
        assert_eq!(code, 200);
        let (code, v) = call(
            &svc,
            "DELETE",
            "/llama3.1%3A8b",
            &[("runtime", "ollama")],
            "",
        );
        assert_eq!(code, 404, "{v}");
        let (code, _) = call(&svc, "DELETE", "/x", &[], "");
        assert_eq!(code, 400);
        let (code, _) = call(&svc, "DELETE", "/%2e%2e%2fx", &[("runtime", "ollama")], "");
        assert_eq!(code, 400, "an encoded path trick is not a model name");
    }

    #[test]
    fn vllm_is_pointed_at_the_chosen_model_and_ready_once_it_lists_it() {
        let (svc, fake) = rig();
        fake.installed.lock().unwrap().push(Runtime::Vllm);
        let (code, v) = call(
            &svc,
            "POST",
            "pull",
            &[],
            r#"{"runtime":"vllm","model":"Qwen/Qwen2.5-Coder-7B-Instruct"}"#,
        );
        assert_eq!(code, 202, "{v}");
        wait_for(&svc, "done");
        let s = svc.status();
        assert_eq!(
            s["runtimes"][1]["models"][0]["name"],
            "Qwen/Qwen2.5-Coder-7B-Instruct"
        );
        let files = fake.files.lock().unwrap();
        assert_eq!(
            files[".config/ozbox/vllm.env"],
            "OZBOX_VLLM_MODEL=Qwen/Qwen2.5-Coder-7B-Instruct\n"
        );
        assert!(files[".config/systemd/user/ozbox-vllm.service"].contains("--host 127.0.0.1"));
    }

    #[test]
    fn the_runtime_can_be_started_stopped_and_an_unknown_action_is_refused() {
        let (svc, fake) = rig();
        let (c, _) = call(
            &svc,
            "POST",
            "runtime",
            &[],
            r#"{"runtime":"ollama","action":"start"}"#,
        );
        assert_eq!(c, 200);
        let (c, _) = call(
            &svc,
            "POST",
            "runtime",
            &[],
            r#"{"runtime":"ollama","action":"stop"}"#,
        );
        assert_eq!(c, 200);
        assert!(fake
            .calls
            .lock()
            .unwrap()
            .iter()
            .any(|c| c == "stop ozbox-ollama.service"));
        let (c, _) = call(
            &svc,
            "POST",
            "runtime",
            &[],
            r#"{"runtime":"ollama","action":"rm -rf"}"#,
        );
        assert_eq!(c, 400);
        let (c, _) = call(&svc, "PATCH", "", &[], "");
        assert_eq!(c, 405);
        let (c, _) = call(&svc, "GET", "nothing/here", &[], "");
        assert_eq!(c, 404);
    }

    #[test]
    fn model_names_allow_the_real_ones_and_nothing_that_could_be_an_option_or_a_path_trick() {
        for ok in [
            "llama3.1:8b",
            "qwen2.5-coder:7b",
            "Qwen/Qwen2.5-Coder-7B-Instruct",
            "a_b-c.d",
        ] {
            assert!(model_ok(ok), "{ok}");
        }
        for bad in [
            "",
            "-rf",
            "/abs",
            "a/../b",
            "a b",
            "a\nb",
            "a;b",
            &"x".repeat(121),
        ] {
            assert!(!model_ok(bad), "{bad:?}");
        }
    }
}
