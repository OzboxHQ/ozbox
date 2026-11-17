//! What `ozbox-hubd enrol` and `ozbox-hubd agent` do on a worker box (ADR 0042): the first contact, and the long-running hub agent.
//!
//! Both reach the box's own secrets service on its sockets (the supervisor's for envelopes and key deliveries, the hub's for the
//! handshake), pin the hub by the identity fingerprint the owner gave, and dial **out**: nothing on a worker listens.
//!
//! The agent here has no engine transport: a task it is handed is refused by name ("no engine could be started") until the box's
//! own run transport is attached ([`NoEngines`]), and it keeps no approval service. It does connect, take enrolment's keys, take and
//! delete key deliveries, report, and delete every key when the hub is lost. The engine path is proven with fakes
//! (`ozbox_hubd::agent`'s harness); attaching the box's own runs is the remaining step.

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use ozbox_core::agent_engine::AgentEngine;
use ozbox_core::hub::net::{enrol_over_net, NetWorker, TcpDialer, WorkerNetConfig};
use ozbox_core::hub::worker::WorkerState;

use crate::agent::{AgentSeams, EngineFactory, WorkerAgent, Workspace};
use crate::crypto::{HandshakeSigner, HandshakeVerifier};
use crate::daemon::now_ms;
use crate::enrol::{make_request, Attestation};
use crate::fleet::ServiceDeliveryStore;
use crate::identity::Identity;
use crate::ops::{KeyOps, SocketKeyOps};
use crate::seams::worker_seams;

/// No engine on this box yet: every task is refused by name.
pub struct NoEngines;

impl EngineFactory for NoEngines {
    fn make(&mut self, _engine: &str) -> Result<Box<dyn AgentEngine>, String> {
        Err("this box's run transport is not attached to the hub agent yet".into())
    }
}

/// The commit a branch of a repository on this box points at, read with `git` (an argv, never a shell string).
pub struct GitWorkspace {
    pub root: PathBuf,
}

fn word(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= 128
        && !s.starts_with('-')
        && s.bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"._-/".contains(&b))
        && !s.contains("..")
}

impl Workspace for GitWorkspace {
    fn commit_of(&self, repo: Option<&str>, branch: &str) -> Option<String> {
        let repo = repo.filter(|r| word(r) && !r.contains('/'))?;
        if !word(branch) {
            return None;
        }
        let out = std::process::Command::new("git")
            .arg("-C")
            .arg(self.root.join(repo))
            .args(["rev-parse", "--verify", "--quiet"])
            .arg(format!("refs/heads/{branch}"))
            .output()
            .ok()?;
        let c = String::from_utf8(out.stdout).ok()?.trim().to_string();
        (out.status.success() && ozbox_core::hub::merge::commit_ok(&c)).then_some(c)
    }
}

fn flag(argv: &[String], name: &str) -> Result<String, String> {
    argv.windows(2)
        .find(|w| w[0] == name)
        .map(|w| w[1].clone())
        .ok_or_else(|| format!("{name} is needed"))
}

/// The hub's public identity, from a file the owner gave, accepted only if it is the one pinned by its fingerprint.
fn pinned_hub(path: &Path, fp: &str) -> Result<Identity, String> {
    let raw =
        std::fs::read_to_string(path).map_err(|_| "the hub's identity file could not be read")?;
    let id: Identity =
        serde_json::from_str(&raw).map_err(|_| "the hub's identity file is not valid")?;
    let id = id.checked().ok_or("the hub's identity is not valid")?;
    if id.identity_fp() != fp {
        return Err("that identity is not the hub this worker pinned".into());
    }
    Ok(id)
}

pub fn run(argv: &[String]) -> Result<(), String> {
    match argv.first().map(String::as_str) {
        Some("enrol") => enrol(argv),
        Some("agent") => agent(argv),
        _ => Err("usage: ozbox-hubd enrol|agent ...".into()),
    }
}

fn dialer(addr: &str) -> TcpDialer {
    TcpDialer {
        addr: addr.to_string(),
        timeout: Duration::from_secs(10),
    }
}

/// First contact: make the request from this box's own service (the proof is signed there), send it once over the hub's listener.
fn enrol(argv: &[String]) -> Result<(), String> {
    let name = flag(argv, "--name")?;
    let token = std::fs::read_to_string(flag(argv, "--token-file")?)
        .map_err(|_| "the token file could not be read".to_string())?;
    let attestation: Attestation = serde_json::from_str(
        &std::fs::read_to_string(flag(argv, "--attestation")?)
            .map_err(|_| "the attestation could not be read".to_string())?,
    )
    .map_err(|_| "the attestation is not valid".to_string())?;
    let ops = SocketKeyOps::new(flag(argv, "--secrets-socket")?);
    let req = make_request(
        &ops,
        &name,
        token.trim(),
        attestation.clone(),
        &attestation.hub_identity_fp,
        now_ms(),
    )
    .map_err(|e| e.message)?;
    if attestation.hub_identity_fp != flag(argv, "--hub-identity-fp")? {
        return Err("the attestation is for another hub than the one pinned".into());
    }
    let body = serde_json::to_vec(&req).map_err(|_| "the request could not be written")?;
    enrol_over_net(&dialer(&flag(argv, "--hub-addr")?), &body)
        .map_err(|(code, why)| format!("the hub refused it: {code} ({why})"))?;
    println!("the hub holds the request for its owner to confirm");
    Ok(())
}

/// The long-running agent.
fn agent(argv: &[String]) -> Result<(), String> {
    let name = flag(argv, "--name")?;
    let hub_name = flag(argv, "--hub").unwrap_or_else(|_| "main".into());
    let hub = pinned_hub(
        Path::new(&flag(argv, "--hub-identity")?),
        &flag(argv, "--hub-identity-fp")?,
    )?;
    let sup: Arc<dyn KeyOps> = Arc::new(SocketKeyOps::new(flag(argv, "--secrets-socket")?));
    let hubsock: Arc<dyn KeyOps> = Arc::new(SocketKeyOps::new(flag(argv, "--hub-secrets-socket")?));
    let (seams, hub_fp) = worker_seams(sup.clone(), &hub).map_err(|e| e.to_string())?;
    let net = Arc::new(
        NetWorker::start(WorkerNetConfig {
            me: name.clone(),
            hub: hub_name.clone(),
            hub_key: hub_fp.clone(),
            signer: Arc::new(HandshakeSigner { ops: hubsock }),
            verifier: Arc::new(HandshakeVerifier {
                dir: seams.directory.clone(),
            }),
            dialer: Arc::new(dialer(&flag(argv, "--hub-addr")?)),
        })
        .map_err(|e| format!("the transport could not start: {e}"))?,
    );
    let state = WorkerState::new(&name, &seams.my_fp, &hub_name, &hub_fp, 1);
    let reach = net.clone();
    let mut agent = WorkerAgent::new(
        AgentSeams {
            me: name.clone(),
            hub: hub_name,
            box_name: name.clone(),
            signer: seams.signer.clone(),
            verifier: seams.verifier.clone(),
            sealer: seams.sealer.clone(),
            net: net.clone(),
            reach: Arc::new(move || reach.reach()),
            store: Arc::new(ServiceDeliveryStore {
                ops: sup,
                worker: name,
            }),
            approvals: None,
            engines: Box::new(NoEngines),
            workspace: Box::new(GitWorkspace {
                root: PathBuf::from("/work/repos"),
            }),
            lost_after_ms: crate::agent::HUB_LOST_AFTER_MS,
        },
        state,
    );
    eprintln!("ozbox-hubd: agent running (dials out; nothing listens)");
    loop {
        agent.tick(now_ms());
        std::thread::sleep(Duration::from_millis(200));
    }
}
