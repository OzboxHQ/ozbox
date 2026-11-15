//! Test doubles: an in-memory Hetzner API and a `tofu` that creates and destroys servers in it.

use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};

use ozbox_core::{BoxName, BoxState, CommandRunner, CommandSpec, Error, Output, Result};

use crate::api::{ApiFirewall, ApiImage, ApiImageInfo, ApiServer, ApiVolume, HcloudApi};

#[derive(Default)]
struct SimState {
    next_id: u64,
    servers: Vec<ApiServer>,
    volumes: Vec<ApiVolume>,
    firewalls: Vec<ApiFirewall>,
    images: Vec<ApiImage>,
    /// Images a server can be built from: id or name, architecture, status.
    base_images: Vec<(String, String, String)>,
    api_log: Vec<String>,
    tofu_calls: Vec<CommandSpec>,
    workspace: String,
    outputs: BTreeMap<String, String>,
    fail: Option<String>,
    /// OpenTofu workspaces that exist (a box this sim created).
    workspaces: Vec<String>,
    /// `tofu plan -out=<file>` results: the variables the plan was made with, and what it was asked to replace.
    plans: BTreeMap<String, BTreeMap<String, String>>,
    /// Make `tofu plan` report the `/work` volume as replaced too (a plan the guard must refuse).
    plan_replaces_volume: bool,
    /// Make the next N creates of a server fail the way Hetzner refuses one (after the old server, if any, was already
    /// removed): the interrupted-replacement case.
    create_failures: u32,
    create_failure_message: String,
    /// Make the next `tofu apply` of a saved plan fail before it changes anything.
    fail_next_replace_apply: bool,
    /// After the next server create by a saved plan, the attachment of `/work` is not made: `Some(true)` fails the apply with
    /// an error (the server exists), `Some(false)` lets the apply report success without it.
    attach_failure: Option<bool>,
}

#[derive(Default)]
pub struct Sim {
    s: Mutex<SimState>,
}

impl Sim {
    /// What Hetzner says about a snapshot image: `creating`, `available`.
    pub fn set_image_status(&self, id: u64, status: &str) {
        self.with(|s| {
            if let Some(i) = s.images.iter_mut().find(|i| i.id == id) {
                i.status = status.to_string();
            }
        });
    }

    /// A snapshot image that Oz Box did not make for any box (a person's own), which must never be deleted.
    pub fn add_foreign_image(&self, id: u64) {
        self.with(|s| {
            s.images.push(ApiImage {
                id,
                created: Some("2025-01-01T00:00:00Z".into()),
                labels: BTreeMap::new(),
                status: "available".into(),
                image_size_gb: None,
            });
        });
    }

    /// A project that already has a few images: the one boxes are created from, a newer one, one for Arm, and one
    /// still being created.
    pub fn new() -> Self {
        let sim = Self::default();
        for (id, arch, status) in [
            ("img-1", "x86", "available"),
            ("img-2", "x86", "available"),
            ("img-arm", "arm", "available"),
            ("img-pending", "x86", "creating"),
        ] {
            sim.with(|s| {
                s.base_images
                    .push((id.to_string(), arch.to_string(), status.to_string()));
            });
        }
        sim
    }

    /// The id of a box's `/work` volume.
    /// The server the box's `/work` volume is attached to, if any.
    pub fn work_attached_to(&self, name: &BoxName) -> Option<u64> {
        self.with(|s| {
            s.volumes
                .iter()
                .find(|v| v.labels.get("ozbox-box").map(String::as_str) == Some(name.as_str()))
                .and_then(|v| v.server)
        })
    }

    pub fn work_volume_of(&self, name: &BoxName) -> Option<u64> {
        self.with(|s| {
            s.volumes
                .iter()
                .find(|v| v.labels.get("ozbox-box").map(String::as_str) == Some(name.as_str()))
                .map(|v| v.id)
        })
    }

    /// Leave a box the way an upgrade interrupted after the replacement leaves it: running on the new image, still marked (the
    /// mark is on the `/work` volume, because the server it would mark is the thing an upgrade replaces).
    pub fn mark_upgrade(&self, name: &BoxName, image: &str) -> Result<()> {
        self.with(|s| {
            let machine = s
                .servers
                .iter()
                .find(|x| x.labels.get("ozbox-box").map(String::as_str) == Some(name.as_str()))
                .map(|x| x.server_type.clone())
                .ok_or_else(|| Error::NotFound(name.to_string()))?;
            let vol = s
                .volumes
                .iter_mut()
                .find(|v| v.labels.get("ozbox-box").map(String::as_str) == Some(name.as_str()))
                .ok_or_else(|| Error::NotFound(name.to_string()))?;
            vol.labels
                .insert("ozbox-upgrade-to".to_string(), image.to_string());
            vol.labels
                .insert("ozbox-upgrade-machine".to_string(), machine);
            Ok(())
        })
    }

    /// Leave a box the way an upgrade interrupted after the stop leaves it: stopped, still on its old image, and marked on its
    /// `/work` volume (the server it would mark is the thing an upgrade replaces).
    pub fn interrupt_upgrade(&self, name: &BoxName, image: &str) -> Result<()> {
        self.with(|s| {
            let machine = {
                let srv = s
                    .servers
                    .iter_mut()
                    .find(|x| x.labels.get("ozbox-box").map(String::as_str) == Some(name.as_str()))
                    .ok_or_else(|| Error::NotFound(name.to_string()))?;
                srv.status = "off".into();
                srv.server_type.clone()
            };
            let vol = s
                .volumes
                .iter_mut()
                .find(|v| v.labels.get("ozbox-box").map(String::as_str) == Some(name.as_str()))
                .ok_or_else(|| Error::NotFound(name.to_string()))?;
            vol.labels
                .insert("ozbox-upgrade-to".to_string(), image.to_string());
            vol.labels
                .insert("ozbox-upgrade-machine".to_string(), machine);
            Ok(())
        })
    }

    /// Make a volume say nothing about its location (an older account's volume), so a box can be described only from the
    /// configuration.
    pub fn forget_volume_location(&self, volume: u64) {
        self.with(|s| {
            if let Some(v) = s.volumes.iter_mut().find(|v| v.id == volume) {
                v.location = None;
            }
        });
    }

    /// The next `n` server creations by `tofu apply` fail with `message`, after the old server was removed.
    pub fn fail_creates(&self, n: u32, message: &str) {
        self.with(|s| {
            s.create_failures = n;
            s.create_failure_message = message.to_string();
        });
    }

    /// The next saved-plan apply creates the server but not the attachment of `/work`; it reports an error when `report` is true,
    /// and success (a lie) when it is false.
    pub fn fail_attach(&self, report: bool) {
        self.with(|s| s.attach_failure = Some(report));
    }

    /// Make the next `tofu apply` of a saved plan fail before it changes anything.
    pub fn fail_next_replace_apply(&self) {
        self.with(|s| s.fail_next_replace_apply = true);
    }

    /// Make `tofu plan` report the `/work` volume as replaced too.
    pub fn plan_replaces_volume(&self) {
        self.with(|s| s.plan_replaces_volume = true);
    }

    /// Forget a box's OpenTofu workspace (this computer has no state for it).
    pub fn forget_workspace(&self, name: &BoxName) {
        self.with(|s| s.workspaces.retain(|w| w != name.as_str()));
    }

    /// The id of a box's server, when it has one.
    pub fn server_of(&self, name: &BoxName) -> Option<u64> {
        self.with(|s| {
            s.servers
                .iter()
                .find(|x| x.labels.get("ozbox-box").map(String::as_str) == Some(name.as_str()))
                .map(|x| x.id)
        })
    }

    /// The labels on a box's `/work` volume.
    pub fn volume_labels(&self, name: &BoxName) -> Option<BTreeMap<String, String>> {
        self.with(|s| {
            s.volumes
                .iter()
                .find(|v| v.labels.get("ozbox-box").map(String::as_str) == Some(name.as_str()))
                .map(|v| v.labels.clone())
        })
    }

    fn with<T>(&self, f: impl FnOnce(&mut SimState) -> T) -> T {
        match self.s.lock() {
            Ok(mut g) => f(&mut g),
            Err(p) => f(&mut p.into_inner()),
        }
    }

    pub fn fail_with(&self, msg: &str) {
        self.with(|s| s.fail = Some(msg.to_string()));
    }

    /// A managed server created outside Oz Box's mapping (no size label).
    pub fn add_server(&self, name: &str, server_type: &str, status: &str) {
        self.with(|s| {
            s.next_id += 1;
            let id = s.next_id;
            let mut labels = BTreeMap::new();
            labels.insert("ozbox-managed".to_string(), "true".to_string());
            labels.insert("ozbox-box".to_string(), name.to_string());
            s.servers.push(ApiServer {
                id,
                name: name.to_string(),
                status: status.to_string(),
                server_type: server_type.to_string(),
                labels,
                created: None,
                image: None,
                firewall_ids: Vec::new(),
                network_ids: Vec::new(),
            });
        });
    }

    /// A box the way the module makes it, but made outside Oz Box's own state: a managed server, its `/work` volume
    /// attached to it, and its firewall attached to it. Returns `(server, volume, firewall)` ids. For adoption tests.
    pub fn add_box_resources(&self, name: &str, server_type: &str) -> (u64, u64, u64) {
        self.with(|s| {
            let mut labels = BTreeMap::new();
            labels.insert("ozbox-managed".to_string(), "true".to_string());
            labels.insert("ozbox-box".to_string(), name.to_string());
            s.next_id += 1;
            let fw = s.next_id;
            s.firewalls.push(ApiFirewall {
                id: fw,
                name: format!("ozbox-{name}"),
                labels: labels.clone(),
            });
            s.next_id += 1;
            let sid = s.next_id;
            s.servers.push(ApiServer {
                id: sid,
                name: format!("ozbox-{name}"),
                status: "running".into(),
                server_type: server_type.to_string(),
                labels: labels.clone(),
                created: None,
                image: Some("img-1".into()),
                firewall_ids: vec![fw],
                network_ids: Vec::new(),
            });
            s.next_id += 1;
            let vid = s.next_id;
            let mut vl = labels;
            vl.insert("ozbox-role".to_string(), "work".to_string());
            s.volumes.push(ApiVolume {
                id: vid,
                size_gb: 100,
                labels: vl,
                server: Some(sid),
                location: Some("fsn1".into()),
            });
            (sid, vid, fw)
        })
    }

    /// Attach the box's server to a private network (what the module's `network_id` does).
    pub fn attach_network(&self, server: u64, network: u64) {
        self.with(|s| {
            if let Some(x) = s.servers.iter_mut().find(|x| x.id == server) {
                x.network_ids.push(network);
            }
        });
    }

    pub fn api_log(&self) -> Vec<String> {
        self.with(|s| s.api_log.clone())
    }

    pub fn clear_api_log(&self) {
        self.with(|s| s.api_log.clear());
    }

    pub fn tofu_calls(&self) -> Vec<CommandSpec> {
        self.with(|s| s.tofu_calls.clone())
    }

    pub fn force_state(&self, name: &BoxName, state: BoxState) -> Result<()> {
        let status = match state {
            BoxState::Running => "running",
            BoxState::Paused => "off",
            BoxState::Pausing => "stopping",
            BoxState::Resuming => "starting",
            BoxState::Creating => "initializing",
            BoxState::Resizing => "migrating",
            BoxState::Destroying => "deleting",
            BoxState::Unknown => "unknown",
            BoxState::InstanceMissing => {
                return Err(Error::Provider(
                    "a box has no server only after an interrupted upgrade: use fail_creates"
                        .into(),
                ))
            }
        };
        self.with(|s| {
            let srv = s
                .servers
                .iter_mut()
                .find(|x| x.labels.get("ozbox-box").map(String::as_str) == Some(name.as_str()))
                .ok_or_else(|| Error::NotFound(name.to_string()))?;
            srv.status = status.to_string();
            Ok(())
        })
    }

    fn call<T>(&self, log: String, f: impl FnOnce(&mut SimState) -> Result<T>) -> Result<T> {
        self.with(|s| {
            if let Some(m) = &s.fail {
                return Err(Error::Provider(format!("Hetzner API {log}: {m}")));
            }
            s.api_log.push(log);
            f(s)
        })
    }
}

fn find_server(s: &mut SimState, id: u64) -> Result<&mut ApiServer> {
    s.servers
        .iter_mut()
        .find(|x| x.id == id)
        .ok_or_else(|| Error::Provider(format!("server {id} not found")))
}

impl HcloudApi for Sim {
    fn list_servers(&self) -> Result<Vec<ApiServer>> {
        self.call("list_servers".into(), |s| Ok(s.servers.clone()))
    }

    fn get_server(&self, id: u64) -> Result<ApiServer> {
        self.call(format!("get_server {id}"), |s| {
            Ok(find_server(s, id)?.clone())
        })
    }

    fn list_volumes(&self) -> Result<Vec<ApiVolume>> {
        self.call("list_volumes".into(), |s| Ok(s.volumes.clone()))
    }

    fn list_snapshots(&self) -> Result<Vec<ApiImage>> {
        self.call("list_snapshots".into(), |s| Ok(s.images.clone()))
    }

    fn list_firewalls(&self) -> Result<Vec<ApiFirewall>> {
        self.call("list_firewalls".into(), |s| Ok(s.firewalls.clone()))
    }

    fn server_action(&self, id: u64, action: &str) -> Result<()> {
        self.call(format!("action {action} {id}"), |s| {
            let srv = find_server(s, id)?;
            match action {
                "shutdown" | "poweroff" => srv.status = "off".into(),
                "poweron" => srv.status = "running".into(),
                other => return Err(Error::Provider(format!("unknown action {other}"))),
            }
            Ok(())
        })
    }

    fn change_type(&self, id: u64, server_type: &str) -> Result<()> {
        self.call(format!("change_type {id} {server_type}"), |s| {
            let srv = find_server(s, id)?;
            if srv.status != "off" {
                return Err(Error::Provider("server must be off to change type".into()));
            }
            srv.server_type = server_type.to_string();
            Ok(())
        })
    }

    fn get_image(&self, image: &str) -> Result<Option<ApiImageInfo>> {
        self.call(format!("get_image {image}"), |s| {
            Ok(s.base_images
                .iter()
                .find(|(id, _, _)| id == image)
                .map(|(id, arch, status)| ApiImageInfo {
                    id: id.clone(),
                    architecture: arch.clone(),
                    status: status.clone(),
                }))
        })
    }

    fn set_server_labels(&self, id: u64, labels: &BTreeMap<String, String>) -> Result<()> {
        self.call(format!("set_labels {id}"), |s| {
            find_server(s, id)?.labels = labels.clone();
            Ok(())
        })
    }

    fn set_volume_labels(&self, id: u64, labels: &BTreeMap<String, String>) -> Result<()> {
        self.call(format!("set_volume_labels {id}"), |s| {
            let v = s
                .volumes
                .iter_mut()
                .find(|v| v.id == id)
                .ok_or_else(|| Error::Provider(format!("volume {id} not found")))?;
            v.labels = labels.clone();
            Ok(())
        })
    }

    fn delete_volume(&self, id: u64) -> Result<()> {
        self.call(format!("delete_volume {id}"), |s| {
            let v = s
                .volumes
                .iter()
                .find(|v| v.id == id)
                .ok_or_else(|| Error::Provider(format!("volume {id} not found")))?;
            if v.server.is_some() {
                return Err(Error::Provider("the volume is attached to a server".into()));
            }
            s.volumes.retain(|v| v.id != id);
            Ok(())
        })
    }

    fn resize_volume(&self, id: u64, size_gb: u32) -> Result<()> {
        self.call(format!("resize_volume {id} {size_gb}"), |s| {
            let v = s
                .volumes
                .iter_mut()
                .find(|v| v.id == id)
                .ok_or_else(|| Error::Provider(format!("volume {id} not found")))?;
            if size_gb < v.size_gb {
                return Err(Error::Provider("volumes cannot shrink".into()));
            }
            v.size_gb = size_gb;
            Ok(())
        })
    }

    fn create_snapshot(
        &self,
        server_id: u64,
        _description: &str,
        labels: &BTreeMap<String, String>,
    ) -> Result<u64> {
        self.call(format!("create_snapshot {server_id}"), |s| {
            find_server(s, server_id)?;
            s.next_id += 1;
            let id = 9000 + s.next_id;
            let created = format!("2026-01-01T00:00:{:02}Z", s.next_id % 60);
            s.images.push(ApiImage {
                id,
                created: Some(created),
                labels: labels.clone(),
                status: "available".into(),
                image_size_gb: Some(2.5),
            });
            Ok(id)
        })
    }

    fn delete_image(&self, id: u64) -> Result<()> {
        self.call(format!("delete_image {id}"), |s| {
            let before = s.images.len();
            s.images.retain(|i| i.id != id);
            if s.images.len() == before {
                return Err(Error::Provider("image not found".into()));
            }
            Ok(())
        })
    }
}

/// A `tofu` that applies the box module against the [`Sim`].
pub struct SimRunner {
    sim: Arc<Sim>,
}

impl SimRunner {
    pub fn new(sim: Arc<Sim>) -> Self {
        Self { sim }
    }
}

fn ok(stdout: String) -> Output {
    Output {
        status: Some(0),
        stdout,
        stderr: String::new(),
    }
}

fn fail(msg: &str) -> Output {
    Output {
        status: Some(1),
        stdout: String::new(),
        stderr: msg.to_string(),
    }
}

fn parse_vars(args: &[String]) -> BTreeMap<String, String> {
    let mut out = BTreeMap::new();
    let mut it = args.iter();
    while let Some(a) = it.next() {
        if a == "-var" {
            if let Some((k, v)) = it.next().and_then(|kv| kv.split_once('=')) {
                out.insert(k.to_string(), v.to_string());
            }
        }
    }
    out
}

/// `{"k"="v","k2"="v2"}`, no escapes (the tests use plain labels).
fn parse_labels(raw: &str) -> BTreeMap<String, String> {
    let inner = raw.trim_start_matches('{').trim_end_matches('}');
    inner
        .split(',')
        .filter_map(|p| p.split_once("\"=\""))
        .map(|(k, v)| {
            (
                k.trim_matches('"').to_string(),
                v.trim_matches('"').to_string(),
            )
        })
        .collect()
}

impl CommandRunner for SimRunner {
    fn run(&self, cmd: &CommandSpec) -> Result<Output> {
        self.sim.with(|s| s.tofu_calls.push(cmd.clone()));
        if cmd.program != "tofu" {
            return Ok(fail("only tofu is simulated"));
        }
        let args: Vec<&str> = cmd.args.iter().map(String::as_str).skip(1).collect(); // skip -chdir
        match args.as_slice() {
            ["init", ..] => Ok(ok(String::new())),
            ["workspace", "select", rest @ ..] => {
                let name = rest.last().copied().unwrap_or("default").to_string();
                let create = rest.contains(&"-or-create");
                let known = self.sim.with(|s| {
                    if create && !s.workspaces.contains(&name) {
                        s.workspaces.push(name.clone());
                    }
                    name == "default" || s.workspaces.contains(&name)
                });
                if !known {
                    return Ok(fail(&format!("Workspace {name:?} doesn't exist.")));
                }
                self.sim.with(|s| s.workspace = name);
                Ok(ok(String::new()))
            }
            ["workspace", "list"] => Ok(ok(self.sim.with(|s| {
                let mut out = String::from("  default\n");
                for w in &s.workspaces {
                    out.push_str(&format!(
                        "{} {w}\n",
                        if *w == s.workspace { "*" } else { " " }
                    ));
                }
                out
            }))),
            ["workspace", "delete", w] => {
                self.sim.with(|s| s.workspaces.retain(|x| x != w));
                Ok(ok(String::new()))
            }
            ["plan", rest @ ..] => {
                let Some(file) = rest.iter().find_map(|x| x.strip_prefix("-out=")) else {
                    return Ok(fail("plan without -out is not simulated"));
                };
                let mut vars = parse_vars(&cmd.args);
                if let Some(r) = rest.iter().find_map(|x| x.strip_prefix("-replace=")) {
                    vars.insert("__replace".into(), r.to_string());
                }
                self.sim.with(|s| s.plans.insert(file.to_string(), vars));
                Ok(ok(String::new()))
            }
            ["show", "-json", file] => Ok(self.sim.with(|s| {
                let Some(vars) = s.plans.get(*file) else {
                    return fail("no such plan file");
                };
                let name = vars.get("box_name").cloned().unwrap_or_default();
                let exists = s
                    .servers
                    .iter()
                    .any(|x| x.labels.get("ozbox-box") == Some(&name));
                let both = if exists {
                    serde_json::json!(["delete", "create"])
                } else {
                    serde_json::json!(["create"])
                };
                let volume = if s.plan_replaces_volume {
                    serde_json::json!(["delete", "create"])
                } else {
                    serde_json::json!(["no-op"])
                };
                ok(serde_json::json!({"resource_changes": [
                    {"address": "hcloud_server.box", "change": {"actions": both}},
                    {"address": "hcloud_volume_attachment.work", "change": {"actions": both}},
                    {"address": "hcloud_volume.work", "change": {"actions": volume}},
                    {"address": "hcloud_firewall.box", "change": {"actions": ["no-op"]}},
                ]})
                .to_string())
            })),
            ["apply", .., file] if self.sim.with(|s| s.plans.contains_key(*file)) => {
                let result = self.sim.with(|s| {
                    if s.fail_next_replace_apply {
                        s.fail_next_replace_apply = false;
                        return Err("injected: the apply was interrupted before it changed anything".to_string());
                    }
                    let vars = s.plans.get(*file).cloned().unwrap_or_default();
                    let name = vars.get("box_name").cloned().unwrap_or_default();
                    // the old server is removed first (replace is destroy then create), and its attachment with it
                    s.servers.retain(|x| x.labels.get("ozbox-box") != Some(&name));
                    for v in s.volumes.iter_mut().filter(|v| v.labels.get("ozbox-box") == Some(&name)) {
                        v.server = None;
                    }
                    if s.create_failures > 0 {
                        s.create_failures -= 1;
                        return Err(s.create_failure_message.clone());
                    }
                    let mut labels = vars
                        .get("labels")
                        .map(|l| parse_labels(l))
                        .unwrap_or_default();
                    labels.insert("ozbox-managed".into(), "true".into());
                    labels.insert("ozbox-box".into(), name.clone());
                    let machine_type = vars.get("machine_type").cloned().unwrap_or_default();
                    s.next_id += 1;
                    let sid = s.next_id;
                    s.servers.push(ApiServer {
                        id: sid,
                        name: name.clone(),
                        status: "running".into(),
                        server_type: machine_type.clone(),
                        labels,
                        created: Some("2026-02-01T00:00:00Z".into()),
                        image: vars.get("image_id").cloned(),
                        firewall_ids: Vec::new(),
                        network_ids: Vec::new(),
                    });
                    let mut vid = 0;
                    let skip_attach = s.attach_failure.take();
                    if skip_attach == Some(true) {
                        return Err("injected: the attachment of /work could not be created (the server was created)".to_string());
                    }
                    for v in s.volumes.iter_mut().filter(|v| v.labels.get("ozbox-box") == Some(&name)) {
                        if skip_attach.is_none() {
                            v.server = Some(sid);
                        }
                        vid = v.id;
                    }
                    let ws = s.workspace.clone();
                    s.outputs.insert(
                        ws,
                        format!(
                            r#"{{"machine_id":{{"value":"{sid}"}},"work_volume_id":{{"value":"{vid}"}},"machine_type":{{"value":"{machine_type}"}}}}"#
                        ),
                    );
                    Ok(())
                });
                Ok(match result {
                    Ok(()) => ok(String::new()),
                    Err(m) => fail(&m),
                })
            }
            ["apply", ..] => {
                let vars = parse_vars(&cmd.args);
                let name = vars.get("box_name").cloned().unwrap_or_default();
                let size: u32 = vars
                    .get("work_disk_gb")
                    .and_then(|v| v.parse().ok())
                    .unwrap_or(0);
                let snap = vars.get("work_snapshot_id").cloned();
                let mut labels = vars
                    .get("labels")
                    .map(|l| parse_labels(l))
                    .unwrap_or_default();
                labels.insert("ozbox-managed".into(), "true".into());
                labels.insert("ozbox-box".into(), name.clone());
                let machine_type = vars.get("machine_type").cloned().unwrap_or_default();
                let result = self.sim.with(|s| {
                    if let Some(id) = &snap {
                        if !s.images.iter().any(|i| &i.id.to_string() == id) {
                            return Err(format!("snapshot {id} not found"));
                        }
                    }
                    s.next_id += 1;
                    let sid = s.next_id;
                    s.servers.push(ApiServer {
                        id: sid,
                        name: name.clone(),
                        status: "running".into(),
                        server_type: machine_type.clone(),
                        labels: labels.clone(),
                        created: Some("2026-01-01T00:00:00Z".into()),
                        image: vars.get("image_id").cloned(),
                        firewall_ids: Vec::new(),
                        network_ids: Vec::new(),
                    });
                    s.next_id += 1;
                    let vid = s.next_id;
                    let mut volume_labels = labels.clone();
                    volume_labels.insert("ozbox-role".into(), "work".into());
                    s.volumes.push(ApiVolume {
                        id: vid,
                        size_gb: size,
                        labels: volume_labels,
                        server: Some(sid),
                        location: vars.get("region").cloned(),
                    });
                    let ws = s.workspace.clone();
                    s.outputs.insert(
                        ws,
                        format!(
                            r#"{{"machine_id":{{"value":"{sid}"}},"work_volume_id":{{"value":"{vid}"}},"machine_type":{{"value":"{machine_type}"}}}}"#
                        ),
                    );
                    Ok(())
                });
                Ok(match result {
                    Ok(()) => ok(String::new()),
                    Err(m) => fail(&m),
                })
            }
            ["output", "-json"] => {
                let out = self.sim.with(|s| s.outputs.get(&s.workspace).cloned());
                Ok(ok(out.unwrap_or_else(|| "{}".into())))
            }
            ["destroy", ..] => {
                let vars = parse_vars(&cmd.args);
                let name = vars.get("box_name").cloned().unwrap_or_default();
                self.sim.with(|s| {
                    let is_box = |l: &BTreeMap<String, String>| l.get("ozbox-box") == Some(&name);
                    s.servers.retain(|x| !is_box(&x.labels));
                    s.volumes.retain(|x| !is_box(&x.labels));
                });
                Ok(ok(String::new()))
            }
            other => Ok(fail(&format!("unsimulated tofu command {other:?}"))),
        }
    }
}
