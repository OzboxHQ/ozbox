#![allow(clippy::unwrap_used, clippy::expect_used)]
//! The hub end to end, in one process, on the real parts: a hub (the daemon, its spool and socket, the listener) and two workers
//! (their agents, the dial-out transport) over a loopback network; the signer and sealer are the secrets service's own operations and
//! HPKE (`ozbox-seal`), each end holding its own keys; the workers are enrolled through the real laptop registrar (a one-use invite,
//! an attestation, the worker's own proof, the owner's plan then apply) and reach the hub over its first-contact endpoint. Only the
//! programs are fakes: a Claude-Code-like and a Codex-like program, each speaking its own output format through the real adapters.
//!
//! Time is the real clock. Every wait is a bounded loop that moves each end a round; a test that cannot reach its goal fails with
//! what it was waiting for.

use std::collections::BTreeMap;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use ozbox_core::agent_engine::AgentEngine;
use ozbox_core::approval::{Requester, RequesterKind, Role as ApprovalRole};
use ozbox_core::approval_subject::{from_hex, GuardHook, Ids, Subject};
use ozbox_core::channel::wire::hex;
use ozbox_core::claude_code::{ClaudeCodeEngine, Launch, LogChunk, RunTransport};
use ozbox_core::fabric::node::{BoxFabric, Seams as FabricSeams};
use ozbox_core::fabric::{CoreScreen, FabricApi};
use ozbox_core::hub::approvals::{Approver, ApproverSet, MemApprovals};
use ozbox_core::hub::net::{enrol_over_net, HubNetConfig, NetWorker, TcpDialer, WorkerNetConfig};
use ozbox_core::hub::testkit::{test_rp, Passkey};
use ozbox_core::hub::worker::WorkerState;
use ozbox_core::permissions::ActorKind;
use ozbox_core::run::{ModelRef, RunSpec, TaskStore};
use ozbox_hubd::agent::{AgentSeams, EngineFactory, WorkerAgent, Workspace};
use ozbox_hubd::crypto::{HandshakeSigner, HandshakeVerifier};
use ozbox_hubd::daemon::{ask, bind, now_ms, Config, Hubd};
use ozbox_hubd::enrol::{make_request, InviteSpec, Provider, Registrar, Registrars, WORKER_CLASS};
use ozbox_hubd::fleet::ServiceDeliveryStore;
use ozbox_hubd::keys::{Caller, HubKeys, KeyStore};
use ozbox_hubd::nethost::NetHost;
use ozbox_hubd::ops::{KeyOps, LocalServiceOps};
use ozbox_hubd::registrar::laptop::{apply, plan, LaptopRequest, Site};
use ozbox_hubd::registrar::{AttestSigner, SeedSigner};
use ozbox_hubd::seams::worker_seams;
use serde_json::{json, Value};
use zeroize::Zeroizing;

use crate::fabric_tools::FabricHost;
use crate::hub_fleet::{AttachConfig, HubAttachment};
use crate::mcp::HostScope;
use crate::memory_tools::MemoryHost;
use crate::orch_tools::{BoxOps, Role, Session, Tools};

// ---- the keys each end holds ---------------------------------------------------------------------------------------

#[derive(Default)]
struct MemStore(Mutex<BTreeMap<String, String>>);

impl KeyStore for MemStore {
    fn get(&self, name: &str) -> Result<Option<Zeroizing<String>>, String> {
        Ok(self
            .0
            .lock()
            .unwrap()
            .get(name)
            .cloned()
            .map(Zeroizing::new))
    }
    fn set(&self, name: &str, value: &str) -> Result<(), String> {
        self.0.lock().unwrap().insert(name.into(), value.into());
        Ok(())
    }
    fn delete(&self, name: &str) -> Result<(), String> {
        self.0.lock().unwrap().remove(name);
        Ok(())
    }
}

impl MemStore {
    fn names(&self) -> Vec<String> {
        self.0.lock().unwrap().keys().cloned().collect()
    }
    fn values(&self) -> Vec<String> {
        self.0.lock().unwrap().values().cloned().collect()
    }
}

/// One box's secrets service: its own store and its own keys.
#[derive(Clone)]
struct End {
    store: Arc<MemStore>,
    keys: Arc<HubKeys>,
}

fn end() -> End {
    let store = Arc::new(MemStore::default());
    let keys = Arc::new(HubKeys::load_or_create(store.as_ref()).unwrap());
    End { store, keys }
}

impl End {
    /// This service as one socket's caller sees it.
    fn ops(&self, caller: Caller) -> Arc<dyn KeyOps> {
        Arc::new(LocalServiceOps {
            keys: self.keys.clone(),
            store: self.store.clone(),
            caller,
        })
    }
}

// ---- the programs: one speaks Claude Code's format, one Codex's ----------------------------------------------------------

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Program {
    Claude,
    Codex,
}

/// A command line a tool ran, holding a key shape built in two pieces: tool input must never cross the hub.
const TOOL_INPUT: &str = concat!("echo gh", "p_TOOLINPUTSENTINEL0123456789abcd");

fn transcript(p: Program, text: &str) -> String {
    let lines: Vec<String> = match p {
        Program::Claude => vec![
            r#"{"type":"system","subtype":"init","session_id":"cc-session-1"}"#.into(),
            format!(
                r#"{{"type":"assistant","message":{{"id":"m1","model":"claude-model-x","content":[{{"type":"text","text":"Working on it"}},{{"type":"tool_use","name":"Bash","input":{{"command":"{TOOL_INPUT}"}}}}],"usage":{{"input_tokens":100,"output_tokens":20}}}}}}"#
            ),
            format!(
                r#"{{"type":"result","subtype":"success","is_error":false,"result":"{text}","total_cost_usd":0.05,"session_id":"cc-session-1"}}"#
            ),
        ],
        Program::Codex => vec![
            r#"{"type":"thread.started","thread_id":"cx-thread-1"}"#.into(),
            r#"{"type":"turn.started"}"#.into(),
            format!(
                r#"{{"type":"item.completed","item":{{"id":"item_1","type":"command_execution","command":"{TOOL_INPUT}","aggregated_output":"","exit_code":0,"status":"completed"}}}}"#
            ),
            format!(
                r#"{{"type":"item.completed","item":{{"id":"item_3","type":"agent_message","text":"{text}"}}}}"#
            ),
            r#"{"type":"turn.completed","usage":{"input_tokens":1000,"cached_input_tokens":400,"output_tokens":50,"reasoning_output_tokens":0}}"#.into(),
        ],
    };
    let mut out = lines.join("\n");
    out.push('\n');
    out
}

#[derive(Default)]
struct CliState {
    launches: Vec<Launch>,
    logs: Vec<Vec<u8>>,
}

/// The transport the adapters fill on a box, playing the program: every launch is answered with that program's own format.
#[derive(Clone)]
struct FakeCli {
    program: Program,
    text: String,
    st: Arc<Mutex<CliState>>,
}

impl RunTransport for FakeCli {
    fn launch(&mut self, _box: &str, l: &Launch) -> Result<String, String> {
        let mut s = self.st.lock().unwrap();
        s.launches.push(l.clone());
        s.logs
            .push(transcript(self.program, &self.text).into_bytes());
        Ok(format!("run-{}", s.logs.len() - 1))
    }
    fn read_log(&mut self, _: &str, run_id: &str, from: u64) -> Result<LogChunk, String> {
        let s = self.st.lock().unwrap();
        let i: usize = run_id.trim_start_matches("run-").parse().unwrap();
        let log = &s.logs[i];
        Ok(LogChunk {
            bytes: log[(from as usize).min(log.len())..].to_vec(),
            next: log.len() as u64,
            exited: Some(0),
        })
    }
    fn stop(&mut self, _: &str, _: &str) -> Result<(), String> {
        Ok(())
    }
    fn send(&mut self, _: &str, _: &str, _: &str, _: bool) -> Result<(), String> {
        Ok(())
    }
}

struct Programs {
    cli: FakeCli,
}

impl EngineFactory for Programs {
    fn make(&mut self, engine: &str) -> Result<Box<dyn AgentEngine>, String> {
        let want = match self.cli.program {
            Program::Claude => "claude-code",
            Program::Codex => ozbox_core::codex_cli::ENGINE,
        };
        if !engine.is_empty() && engine != want {
            return Err(format!("this box runs {want}, not {engine}"));
        }
        Ok(match self.cli.program {
            Program::Claude => Box::new(ClaudeCodeEngine::new(self.cli.clone())),
            Program::Codex => Box::new(ozbox_core::codex_cli::engine(self.cli.clone())),
        })
    }
}

/// A network the test can cut: it closes the connection it gave and refuses to dial until it is healed.
#[derive(Clone)]
struct Cable {
    inner: Arc<TcpDialer>,
    cut: Arc<std::sync::atomic::AtomicBool>,
    last: Arc<Mutex<Option<std::net::TcpStream>>>,
}

impl ozbox_core::hub::net::Dialer for Cable {
    fn dial(&self) -> std::io::Result<std::net::TcpStream> {
        if self.cut.load(std::sync::atomic::Ordering::SeqCst) {
            return Err(std::io::Error::from(std::io::ErrorKind::ConnectionRefused));
        }
        let s = self.inner.dial()?;
        *self.last.lock().unwrap() = s.try_clone().ok();
        Ok(s)
    }
}

impl Cable {
    fn cut(&self) {
        self.cut.store(true, std::sync::atomic::Ordering::SeqCst);
        if let Some(s) = self.last.lock().unwrap().take() {
            let _ = s.shutdown(std::net::Shutdown::Both);
        }
    }
    fn heal(&self) {
        self.cut.store(false, std::sync::atomic::Ordering::SeqCst);
    }
}

struct FixedCommit(String);

impl Workspace for FixedCommit {
    fn commit_of(&self, _: Option<&str>, _: &str) -> Option<String> {
        Some(self.0.clone())
    }
}

// ---- the fleet ----------------------------------------------------------------------------------------------------

const HUB: &str = "main";
pub(super) const SHA_A: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
pub(super) const SHA_B: &str = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";

struct NoFleet;
impl BoxOps for NoFleet {
    fn list(&self) -> Result<Vec<Value>, String> {
        Ok(Vec::new())
    }
    fn plan(&self, _: Value) -> Result<Value, String> {
        Err("no".into())
    }
    fn apply(&self, _: &str, _: &Value) -> Result<Value, String> {
        Err("no".into())
    }
}

struct Worker {
    name: String,
    end: End,
    agent: WorkerAgent,
    net: Arc<NetWorker>,
    fabric: Arc<BoxFabric>,
    tools: Tools,
    approvals: Arc<Mutex<MemApprovals>>,
    owner: Passkey,
    cli: FakeCli,
    cable: Cable,
}

struct Fleet {
    tmp: tempfile::TempDir,
    hub: End,
    hubd: Arc<Hubd>,
    host: NetHost,
    att: Arc<HubAttachment>,
    mem: Arc<MemoryHost>,
    hub_tools: Tools,
    addr: SocketAddr,
    laptop: SeedSigner,
    running: Option<ozbox_hubd::daemon::Running>,
    workers: Vec<Worker>,
    /// How soon a worker deletes its keys when the hub is out of reach (a real box: two minutes).
    lost_after_ms: u64,
}

fn tools(dir: &std::path::Path, fab: Arc<dyn FabricApi>, box_name: &str) -> Tools {
    Tools::new(TaskStore::new(dir.join("tasks.json")), Arc::new(NoFleet))
        .with_fabric(Some(Arc::new(FabricHost::new(fab, box_name))))
}

impl Fleet {
    /// A hub, with its daemon serving its socket and listening on a loopback port, and no workers yet.
    fn new() -> Fleet {
        let tmp = tempfile::tempdir().unwrap();
        let hub = end();
        let (_, laptop) = SeedSigner::generate().unwrap();
        let regs = Registrars {
            registrars: vec![Registrar {
                provider: Provider::Own,
                public: laptop.public_hex(),
            }],
        };
        let regs_path = tmp.path().join("registrars.json");
        std::fs::write(&regs_path, serde_json::to_vec(&regs).unwrap()).unwrap();
        let cfg = Config {
            dir: tmp.path().join("hubd"),
            socket: tmp.path().join("run/hubd.sock"),
            registrars: regs_path,
            box_id: "main-box".into(),
            name: HUB.into(),
        };
        let hubd = Hubd::open(cfg.clone(), hub.ops(Caller::Hub)).unwrap();
        std::fs::create_dir_all(tmp.path().join("run")).unwrap();
        let listener = bind(&cfg.socket, 0o750).unwrap();
        let running = hubd.serve(listener, Some(cfg.socket.clone())).unwrap();
        let host = NetHost::start(
            hubd.clone(),
            hub.ops(Caller::Hub),
            "127.0.0.1:0".parse().unwrap(),
        )
        .unwrap();
        let addr = host.local_addr();
        let mem = Arc::new(MemoryHost::open(&tmp.path().join("mem")).unwrap());
        let att = HubAttachment::connect(AttachConfig {
            hubd_socket: cfg.socket.clone(),
            name: HUB.into(),
            ops: hub.ops(Caller::Supervisor),
            walls: Some(mem.clone() as Arc<dyn ozbox_core::fabric::walls::WallSource>),
            state_dir: None,
        })
        .unwrap();
        std::fs::create_dir_all(tmp.path().join("hub-tools")).unwrap();
        let hub_tools = tools(&tmp.path().join("hub-tools"), att.fabric.clone(), HUB)
            .with_memory(Some(mem.clone()));
        Fleet {
            tmp,
            hub,
            hubd,
            host,
            att,
            mem,
            hub_tools,
            addr,
            laptop,
            running: Some(running),
            workers: Vec::new(),
            lost_after_ms: 120_000,
        }
    }

    fn socket(&self) -> std::path::PathBuf {
        self.tmp.path().join("run/hubd.sock")
    }

    fn dialer(&self) -> TcpDialer {
        TcpDialer {
            addr: self.addr.to_string(),
            timeout: Duration::from_secs(5),
        }
    }

    /// The owner invites a worker, the worker (a box with its own secrets service) is registered by the laptop, sends its first
    /// contact over the network, and the owner confirms the plan: the whole of "a box joins a hub", with no copy by hand.
    fn enrol(&mut self, name: &str, program: Program, text: &str, sha: &str) -> usize {
        let wend = end();
        let now = now_ms();
        let token = {
            let spec = InviteSpec {
                worker: name.into(),
                box_id: format!("box-of-{name}"),
                provider: Provider::Own,
                machine: format!("machine-{name}"),
                private_address: String::new(),
                orchestration: "orch-1".into(),
            };
            let plan = self.hubd.plan_invite(&spec).unwrap();
            self.hubd.apply_invite(&plan, now).unwrap()
        };
        let hub_fp = self.hubd.identity().identity_fp();
        let identity = wend.ops(Caller::Supervisor).identity().unwrap();
        let lreq = LaptopRequest {
            provider: Provider::Own,
            machine: format!("machine-{name}"),
            box_id: format!("box-of-{name}"),
            orchestration: "orch-1".into(),
            hub_identity_fp: hub_fp.clone(),
            private_address: String::new(),
            class: WORKER_CLASS.into(),
            environment: "staging".into(),
            identity,
            creation_proof: String::new(),
        };
        let lplan = plan(&lreq).unwrap();
        let attestation = apply(
            &lplan,
            &lreq,
            &self.laptop,
            None,
            &Site {
                box_markers: Vec::new(),
            },
            now,
        )
        .unwrap();
        let req = make_request(
            wend.ops(Caller::Supervisor).as_ref(),
            name,
            &token,
            attestation,
            &hub_fp,
            now,
        )
        .unwrap();
        // first contact: over the hub's own listener, authenticated by the token, the attestation and the worker's proof
        enrol_over_net(&self.dialer(), &serde_json::to_vec(&req).unwrap()).unwrap();
        let eplan = self.hubd.plan_enrol(name).unwrap();
        self.hubd.apply_enrol(&eplan, now_ms()).unwrap();
        self.host.sync_roster().unwrap();
        self.att.sync_roster().unwrap();
        self.connect(name, wend, program, text, sha)
    }

    fn connect(&mut self, name: &str, wend: End, program: Program, text: &str, sha: &str) -> usize {
        let hub_identity = self.hubd.identity().clone();
        let (seams, hub_fp) = worker_seams(wend.ops(Caller::Supervisor), &hub_identity).unwrap();
        let cable = Cable {
            inner: Arc::new(self.dialer()),
            cut: Arc::new(std::sync::atomic::AtomicBool::new(false)),
            last: Arc::new(Mutex::new(None)),
        };
        let net = Arc::new(
            NetWorker::start(WorkerNetConfig {
                me: name.into(),
                hub: HUB.into(),
                hub_key: hub_fp.clone(),
                signer: Arc::new(HandshakeSigner {
                    ops: wend.ops(Caller::Hub),
                }),
                verifier: Arc::new(HandshakeVerifier {
                    dir: seams.directory.clone(),
                }),
                dialer: Arc::new(cable.clone()),
            })
            .unwrap(),
        );
        let cli = FakeCli {
            program,
            text: text.into(),
            st: Arc::new(Mutex::new(CliState::default())),
        };
        let ids = Ids {
            box_id: name.into(),
            store_id: format!("store-{name}"),
        };
        let mut svc = MemApprovals::new(ids).unwrap();
        let owner = Passkey::new(&format!("cred-owner-{name}")).unwrap();
        svc.approvers = Some(ApproverSet {
            seq: 1,
            expires_ms: u64::MAX,
            rp: test_rp(),
            approvers: vec![Approver {
                credential_id: owner.id.clone(),
                public_key_hex: owner.public_hex(),
                person: "owner".into(),
                role: ApprovalRole::Owner,
            }],
        });
        let approvals = Arc::new(Mutex::new(svc));
        let state = WorkerState::new(name, &seams.my_fp, HUB, &hub_fp, 1);
        let agent = WorkerAgent::new(
            AgentSeams {
                me: name.into(),
                hub: HUB.into(),
                box_name: name.into(),
                signer: seams.signer.clone(),
                verifier: seams.verifier.clone(),
                sealer: seams.sealer.clone(),
                net: net.clone(),
                reach: {
                    let n = net.clone();
                    Arc::new(move || n.reach())
                },
                store: Arc::new(ServiceDeliveryStore {
                    ops: wend.ops(Caller::Supervisor),
                    worker: name.into(),
                }),
                approvals: Some(approvals.clone()),
                engines: Box::new(Programs { cli: cli.clone() }),
                workspace: Box::new(FixedCommit(sha.into())),
                lost_after_ms: self.lost_after_ms,
            },
            state,
        );
        let fabric = Arc::new(BoxFabric::new(
            name,
            &seams.my_fp,
            HUB,
            &hub_fp,
            FabricSeams {
                signer: seams.signer.clone(),
                verifier: seams.verifier.clone(),
                sealer: seams.sealer.clone(),
                net: net.clone(),
                screen: Arc::new(CoreScreen),
                audit: None,
            },
        ));
        let dir = self.tmp.path().join(format!("tools-{name}"));
        std::fs::create_dir_all(&dir).unwrap();
        let tools = tools(&dir, fabric.clone(), name);
        self.workers.push(Worker {
            name: name.into(),
            end: wend,
            agent,
            net,
            fabric,
            tools,
            approvals,
            owner,
            cli,
            cable,
        });
        self.workers.len() - 1
    }

    /// Move every end one round: the daemon's listener, the server's tick, each worker's agent and fabric.
    fn round(&mut self) {
        let now = now_ms();
        self.host.pump(now);
        self.att.tick(now);
        for w in &mut self.workers {
            w.agent.tick(now);
            let _ = w.fabric.pump(now);
        }
    }

    /// Run rounds until `done` says so, or fail naming what was awaited.
    fn until(&mut self, what: &str, mut done: impl FnMut(&mut Fleet) -> bool) {
        for _ in 0..800 {
            self.round();
            if done(self) {
                return;
            }
            std::thread::sleep(Duration::from_millis(25));
        }
        panic!("timed out waiting for: {what}\n{}", self.diag());
    }

    /// What each end says, for a failure: names, counts and audit words only.
    fn diag(&self) -> String {
        let mut out = String::new();
        let st = self.hub_state();
        for e in st.core.audit.iter().rev().take(12) {
            out.push_str(&format!("hub: {} {}\n", e.action, e.detail));
        }
        for (w, p) in &st.peers {
            out.push_str(&format!(
                "hub sees {w}: status={:?} results={:?} questions={}\n",
                p.report.status,
                p.report.results,
                p.report.questions.len()
            ));
        }
        for w in &self.workers {
            out.push_str(&format!(
                "{}: tasks={} running+withheld={:?} launches={} reach={:?} audit={:?}\n",
                w.name,
                w.agent.state.tasks.len(),
                (w.agent.running(), &w.agent.withheld_log),
                w.cli.st.lock().unwrap().launches.len(),
                w.net.reach(),
                w.agent
                    .state
                    .core
                    .audit
                    .iter()
                    .rev()
                    .take(6)
                    .map(|e| format!("{} {}", e.action, e.detail))
                    .collect::<Vec<_>>()
            ));
        }
        out
    }

    /// The hub's view of the worker channel, as plain data.
    fn hub_state(&self) -> ozbox_core::hub::engine::HubState {
        self.att.svc.state.lock().unwrap().clone()
    }

    /// Every worker's connection is up and the hub has taken each one's hello (a session: it knows the incarnation).
    fn all_connected(&self) -> bool {
        let st = self.hub_state();
        self.workers
            .iter()
            .all(|w| st.peer_inc(&w.name) == w.agent.state.inc() && w.agent.state.hub_inc() != 0)
            && self.all_linked()
    }

    fn all_linked(&self) -> bool {
        self.workers
            .iter()
            .all(|w| matches!(w.net.reach(), ozbox_core::hub::net::Reach::Connected { .. }))
            && self.workers.iter().all(|w| {
                matches!(
                    self.host.net.reach(&w.name),
                    Some(ozbox_core::hub::net::Reach::Connected { .. })
                )
            })
    }
}

impl Drop for Fleet {
    fn drop(&mut self) {
        for w in &self.workers {
            w.net.stop();
        }
        self.host.stop();
        if let Some(r) = self.running.take() {
            r.stop();
        }
    }
}

/// A run on `box_name` with its engine, provider and repository, as the task store records it (the fabric builds an agent's address
/// and reach from it, never from the agent's words).
fn run_of(
    t: &Tools,
    box_name: &str,
    engine: &str,
    provider: &str,
    repo: &str,
) -> (Session, HostScope) {
    let spec = RunSpec {
        engine: engine.into(),
        prompt: "work".into(),
        skill: None,
        box_name: box_name.into(),
        repo: Some(repo.into()),
        branch: None,
        caps: Default::default(),
        deliver_to: Vec::new(),
        requested_by: "ada".into(),
        origin: ozbox_core::run::RunOrigin::Manual,
        idempotency_key: None,
        model: Some(ModelRef {
            provider_id: provider.into(),
            model: "m".into(),
        }),
        interactive: false,
    };
    let id = t
        .store
        .update(|b| b.enqueue(spec, 1, None))
        .unwrap()
        .unwrap()
        .0;
    (
        Session {
            person: "ada".into(),
            role: Role::Agent,
        },
        HostScope {
            box_name: Some(box_name.into()),
            run_id: Some(id),
            orchestration: None,
            actor: ActorKind::Agent,
            session: None,
            program: None,
            program_pid: None,
            code: None,
            standing_until_ms: None,
            door_gen: 0,
        },
    )
}

fn call(t: &Tools, s: &(Session, HostScope), name: &str, a: Value) -> Value {
    t.call_as(&s.0, Some(&s.1), name, &a, now_ms()).unwrap()
}

fn assign_to(f: &Fleet, worker: &str, feature: &str, engine: &str, keys: (&str, &[&str])) {
    use ozbox_core::hub::refusal::KeyDeclaration;
    let a = ozbox_core::engine_turn::assign_of(
        &ozbox_core::engine_turn::Task {
            id: format!("orch-1/{feature}"),
            title: format!("Task {feature}"),
            instruction: format!("TASK-MARKER do {feature}"),
            repo: Some("billing".into()),
            branch: Some(format!("feat/{feature}")),
        },
        KeyDeclaration {
            env: keys.0.into(),
            names: keys.1.iter().map(|s| s.to_string()).collect(),
        },
        now_ms() + 3_600_000,
    );
    let mut a = a;
    a.engine = Some(engine.into());
    a.model = Some("routed-model".into());
    let t = now_ms();
    f.att
        .svc
        .with(t, |hub, st| hub.assign(st, worker, &a, t))
        .unwrap()
        .unwrap();
}

// ---- scenarios -----------------------------------------------------------------------------------------------------------

/// Two boxes enrol through the laptop registrar over the hub's first-contact endpoint, connect by dialing out, take their tasks, run
/// them on different engines of different providers, and report; nothing of either program crosses the channel.
#[test]
fn two_workers_enrol_over_the_network_and_a_mixed_pair_runs_their_tasks_to_a_result() {
    let mut f = Fleet::new();
    let a = f.enrol("box-a", Program::Claude, "Parser built.", SHA_A);
    let b = f.enrol("box-b", Program::Codex, "Tests written.", SHA_B);
    assert_eq!((a, b), (0, 1));
    // the roster was never copied by hand: enrolment is what the channel and the transport read
    assert!(f.att.svc.knows("box-a") && f.att.svc.knows("box-b"));
    f.until("both workers connected", |f| f.all_connected());
    assign_to(&f, "box-a", "parser", "claude-code", ("staging", &[]));
    assign_to(&f, "box-b", "tests", "codex", ("staging", &[]));
    f.until("both results at the hub", |f| {
        let st = f.hub_state();
        let got = |w: &str, feat: &str| {
            st.peers
                .get(w)
                .and_then(|p| p.report.results.get("orch-1"))
                .and_then(|m| m.get(feat))
                .map(|r| (r.commit.clone(), r.summary.clone()))
        };
        got("box-a", "parser").is_some_and(|r| r.0 == SHA_A)
            && got("box-b", "tests") == Some((SHA_B.into(), "Tests written.".into()))
    });
    // each program was started once, with its own engine's format, and the task text reached it only as its input
    for (w, p) in f.workers.iter().zip([Program::Claude, Program::Codex]) {
        let s = w.cli.st.lock().unwrap();
        assert_eq!(s.launches.len(), 1, "{p:?}");
        assert!(s.launches[0]
            .stdin
            .as_deref()
            .is_some_and(|i| i.contains("TASK-MARKER")));
        assert!(!s.launches[0].argv.iter().any(|a| a.contains("TASK-MARKER")));
    }
    // nothing of either engine, provider or program crossed: the hub's own record names none of them
    let crossed = format!(
        "{} {}",
        serde_json::to_string(&f.hub_state().peers).unwrap(),
        f.hub_state()
            .core
            .audit
            .iter()
            .map(|e| format!("{} {}", e.action, e.detail))
            .collect::<Vec<_>>()
            .join(" ")
    )
    .to_ascii_lowercase();
    for banned in [
        "claude",
        "codex",
        "anthropic",
        "openai",
        "cc-session",
        "cx-thread",
        "routed-model",
        "toolinputsentinel",
    ] {
        assert!(!crossed.contains(banned), "{banned} crossed the hub");
    }
    // a box that is not enrolled cannot connect: it is closed, and counted, not admitted
    let stranger = end();
    let hub_identity = f.hubd.identity().clone();
    let (sseams, shub_fp) = worker_seams(stranger.ops(Caller::Supervisor), &hub_identity).unwrap();
    let net = NetWorker::start(WorkerNetConfig {
        me: "box-z".into(),
        hub: HUB.into(),
        hub_key: shub_fp,
        signer: Arc::new(HandshakeSigner {
            ops: stranger.ops(Caller::Hub),
        }),
        verifier: Arc::new(HandshakeVerifier {
            dir: sseams.directory.clone(),
        }),
        dialer: Arc::new(f.dialer()),
    })
    .unwrap();
    std::thread::sleep(Duration::from_millis(600));
    assert!(!matches!(
        net.reach(),
        ozbox_core::hub::net::Reach::Connected { .. }
    ));
    assert!(f.host.net.reach("box-z").is_none());
    net.stop();
}

fn pair() -> Fleet {
    let mut f = Fleet::new();
    f.enrol("box-a", Program::Claude, "Parser built.", SHA_A);
    f.enrol("box-b", Program::Codex, "Tests written.", SHA_B);
    f.until("both workers connected", |f| f.all_connected());
    f
}

/// Two agents on two boxes, one on Claude Code and one on Codex, talk through the same five tools over the real channel.
#[test]
fn the_mixed_pair_talks_through_the_fabric_over_the_real_transport() {
    let mut f = pair();
    let alpha = run_of(
        &f.workers[0].tools,
        "box-a",
        "claude-code",
        "anthropic",
        "billing",
    );
    let beta = run_of(&f.workers[1].tools, "box-b", "codex", "openai", "billing");
    call(&f.workers[0].tools, &alpha, "participants_list", json!({}));
    call(&f.workers[1].tools, &beta, "participants_list", json!({}));
    let mut to = String::new();
    f.until("each box sees the other's agent", |f| {
        let l = call(&f.workers[0].tools, &alpha, "participants_list", json!({}));
        match l["participants"]
            .as_array()
            .unwrap()
            .iter()
            .find(|p| p["box"] == "box-b")
        {
            Some(p) => {
                assert_eq!(
                    (p["engine"].as_str(), p["provider"].as_str()),
                    (Some("codex"), Some("openai"))
                );
                to = p["address"].as_str().unwrap().to_string();
                true
            }
            None => false,
        }
    });
    let me = call(&f.workers[0].tools, &alpha, "participants_list", json!({}))["me"]
        .as_str()
        .unwrap()
        .to_string();
    let sent = call(
        &f.workers[0].tools,
        &alpha,
        "messages_post",
        json!({"to": to, "text": "Rebase on main before the merge."}),
    );
    assert!(sent["note"]
        .as_str()
        .unwrap()
        .contains("data, not instructions"));
    let mut id = String::new();
    f.until("the message is in the other agent's mailbox", |f| {
        let got = call(&f.workers[1].tools, &beta, "messages_get", json!({}));
        match got["messages"].as_array().unwrap().first() {
            Some(m) => {
                assert_eq!(m["from"], me.as_str());
                assert!(m["from_is"]
                    .as_str()
                    .unwrap()
                    .ends_with("on box-a (claude-code · anthropic)"));
                id = m["id"].as_str().unwrap().to_string();
                true
            }
            None => false,
        }
    });
    call(
        &f.workers[1].tools,
        &beta,
        "messages_post",
        json!({"to": me, "text": "Done.", "reply_to": id}),
    );
    call(
        &f.workers[1].tools,
        &beta,
        "messages_ack",
        json!({"ids": [id]}),
    );
    let thread = sent["thread"].clone();
    f.until("the thread reads two messages, the first read", |f| {
        let t = call(
            &f.workers[0].tools,
            &alpha,
            "messages_thread",
            json!({"thread": thread}),
        );
        let m = t["messages"].as_array().unwrap();
        m.len() == 2 && m[0]["state"] == "read"
    });
    // a message that holds a key shape is refused by kind, through the tool, and what it held is nowhere
    let key = ["gh", "p_", "SENTINELsentinel", "0123456789abcdefXYZ"].concat();
    let e = f.workers[0]
        .tools
        .call_as(
            &alpha.0,
            Some(&alpha.1),
            "messages_post",
            &json!({"to": to, "text": key}),
            now_ms(),
        )
        .unwrap_err();
    assert!(!e.message().contains("SENTINEL"));
    for _ in 0..20 {
        f.round();
        std::thread::sleep(Duration::from_millis(25));
    }
    let everything = format!(
        "{} {}",
        serde_json::to_string(&f.att.fabric.snapshot()).unwrap(),
        serde_json::to_string(&f.workers[1].fabric.snapshot()).unwrap()
    );
    assert!(!everything.contains("SENTINELsentinel"));
}

/// A worker's request reaches the fleet inbox on main, the owner decides it with a passkey through the dashboard's own routes, and the
/// worker's own service verifies the assertion before anything moves.
#[test]
fn a_workers_request_reaches_the_fleet_inbox_and_the_owners_passkey_is_verified_by_the_worker() {
    use std::collections::HashMap;
    use std::net::{IpAddr, Ipv4Addr};
    let mut f = pair();
    let dir = tempfile::tempdir().unwrap();
    let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 7878);
    let p = ozbox_provider_fake::open(dir.path());
    let mut a = super::App::new(Box::new(p), true, addr, "tok".into())
        .with_task_store(Some(dir.path().join("tasks.json")));
    a.attach_hub_fleet(f.att.clone(), Default::default())
        .unwrap();
    let http = |a: &mut super::App, method: &str, path: &str, body: Value| -> (u16, Value) {
        let mut headers = HashMap::new();
        headers.insert("host".to_string(), "127.0.0.1:7878".to_string());
        headers.insert("authorization".to_string(), "Bearer tok".to_string());
        let r = a.handle(&super::Req {
            method: method.into(),
            path: path.into(),
            query: String::new(),
            headers,
            body: if body.is_null() {
                Vec::new()
            } else {
                body.to_string().into_bytes()
            },
        });
        (
            r.status,
            serde_json::from_slice(&r.body).unwrap_or(Value::Null),
        )
    };
    // the worker's service is pinned by a route its own box cannot write; until it is, a card from it is not shown
    let subject = Subject::GuardOverride(GuardHook::Commit {
        repo_path_hash: "1".repeat(64),
        hook_kind: "pre-commit".into(),
        tree_id: "a".repeat(40),
        matches: Vec::new(),
        scanned_text_hash: "2".repeat(64),
    });
    let digest = f.workers[0]
        .approvals
        .lock()
        .unwrap()
        .file(
            now_ms(),
            "r1",
            subject,
            Requester::new(RequesterKind::BoxUser, Some(1000)),
        )
        .unwrap()
        .subject_digest;
    for _ in 0..30 {
        f.round();
        std::thread::sleep(Duration::from_millis(20));
    }
    assert!(
        http(&mut a, "GET", "/v1/approvals/fleet", Value::Null).1["cards"]
            .as_array()
            .unwrap()
            .is_empty()
    );
    let pin = f.workers[0].approvals.lock().unwrap().pin();
    assert!(f.att.pin_service("box-a", pin, now_ms()));
    let mut card = Value::Null;
    f.until("the card is in the fleet inbox", |f| {
        let _ = f;
        let (_, v) = http(&mut a, "GET", "/v1/approvals/fleet", Value::Null);
        match v["cards"].as_array().and_then(|c| c.first()) {
            Some(c) => {
                card = c.clone();
                true
            }
            None => false,
        }
    });
    assert_eq!(
        (
            card["worker"].as_str(),
            card["request_id"].as_str(),
            card["subject_digest"].as_str()
        ),
        (Some("box-a"), Some("r1"), Some(digest.as_str()))
    );
    // an approval without the person's assertion is refused on main, and nothing reaches the worker as an approval
    let (s, _) = http(
        &mut a,
        "POST",
        "/v1/approvals/fleet/box-a/r1/decide",
        json!({"outcome":"approve","subject_digest": card["subject_digest"]}),
    );
    assert_eq!(s, 409);
    // the owner signs the card's challenge with a passkey; main relays it
    let ch: [u8; 32] = from_hex(card["approve_challenge"].as_str().unwrap())
        .unwrap()
        .try_into()
        .unwrap();
    let ev = f.workers[0].owner.assert(&test_rp(), &ch, 0x05, 3).unwrap();
    let (s, _) = http(
        &mut a,
        "POST",
        "/v1/approvals/fleet/box-a/r1/decide",
        json!({"outcome":"approve","subject_digest": card["subject_digest"], "passkey": ev}),
    );
    assert_eq!(s, 202);
    f.until("the worker's own service approved it", |f| {
        f.workers[0].approvals.lock().unwrap().state_of("r1")
            == Some(ozbox_core::approval::State::Approved)
    });
    // the worker's answer comes back as its own status
    f.until("the worker said so", |f| {
        f.hub_state().peers["box-a"]
            .report
            .status
            .get("-")
            .is_some_and(|m| m.get("-").is_some_and(|s| s.state == "approval"))
    });
}

/// Keys go to a worker by name, sealed to the key its enrolment attested; Production is refused on the hub, in front of the issuer, in
/// the secrets service and on the worker; a value is in no state, spool or log; and a worker deletes its keys on revoke and on loss of
/// the hub.
#[test]
fn keys_go_by_name_sealed_to_the_attested_key_production_is_refused_everywhere_and_keys_end_with_the_task(
) {
    const VALUE: &str = "sk_test_STAGINGVALUESENTINEL0123456789";
    let mut f = pair();
    f.workers[0].agent.set_lost_after(1_500);
    // the owner stages a staging value on main's secrets service (the admin socket), and a Production one is refused there
    let admin = f.hub.ops(Caller::Admin);
    admin
        .call(json!({"op":"hub_release_set","env":"staging","name":"stripe-test","value": VALUE}))
        .unwrap();
    assert!(admin
        .call(
            json!({"op":"hub_release_set","env":"production","name":"stripe-test","value": VALUE})
        )
        .is_err());
    assert!(admin
        .call(json!({"op":"hub_release_set","env":"staging","name":"live-key","value": VALUE}))
        .is_err());
    // the box socket, the hub socket and the supervisor's cannot stage one
    for c in [Caller::Supervisor, Caller::Hub, Caller::Other] {
        assert!(f
            .hub
            .ops(c)
            .call(json!({"op":"hub_release_set","env":"staging","name":"x","value": VALUE}))
            .is_err());
    }
    // Production, by environment or by a name that says so, never reaches a worker: the hub refuses to hand the task over
    for (env, names) in [
        ("production", vec!["stripe-test"]),
        ("staging", vec!["prod-database"]),
        ("staging", vec!["stripe-live"]),
    ] {
        use ozbox_core::hub::refusal::KeyDeclaration;
        let mut a = ozbox_core::engine_turn::assign_of(
            &ozbox_core::engine_turn::Task {
                id: "orch-1/bad".into(),
                title: "t".into(),
                instruction: "x".into(),
                repo: None,
                branch: None,
            },
            KeyDeclaration {
                env: env.into(),
                names: names.iter().map(|s| s.to_string()).collect(),
            },
            now_ms() + 60_000,
        );
        a.engine = None;
        let t = now_ms();
        let r = f
            .att
            .svc
            .with(t, |hub, st| hub.assign(st, "box-a", &a, t))
            .unwrap();
        assert!(r.is_err(), "{env} {names:?}");
    }
    // in front of the issuer and inside the secrets service, once more, each on its own
    let sup = f.hub.ops(Caller::Supervisor);
    let attested = {
        let r = f.hubd.roster().unwrap();
        let rec = r.iter().find(|r| r.worker == "box-a").unwrap();
        (
            rec.identity.delivery_public.clone(),
            rec.identity.delivery_fp(),
        )
    };
    for (env, name) in [
        ("production", "stripe-test"),
        ("staging", "live-key"),
        ("", "stripe-test"),
    ] {
        let r = sup.call(json!({"op":"hub_release","request_id":"r","worker":"box-a","orchestration":"orch-1","feature":"k","env":env,"names":[name],"to_public":attested.0,"to_fp":attested.1}));
        assert!(r.is_err(), "{env} {name}");
    }
    // a staging task that declares a name is handed over; the worker asks for it by name, and gets it sealed
    assign_to(
        &f,
        "box-a",
        "keyed",
        "claude-code",
        ("staging", &["stripe-test"]),
    );
    f.until("the value is in the worker's own secrets service", |f| {
        f.workers[0]
            .end
            .store
            .values()
            .iter()
            .any(|v| v.contains(VALUE))
    });
    // an agent asking by hand: a name the task did not declare, or one that says Production, is refused on the worker before anything is sent
    for name in ["stripe-live", "prod-database", "not-declared"] {
        let r = f.workers[0]
            .agent
            .ask_keys(now_ms(), "orch-1", "keyed", &[name.to_string()]);
        assert!(r.is_err(), "{name}");
    }
    // it is in the worker's reserved store only, and in no state, spool, audit line or fabric record anywhere else
    let held: Vec<String> = f.workers[0]
        .end
        .store
        .names()
        .into_iter()
        .filter(|n| n.starts_with("hub-delivered-"))
        .collect();
    assert!(!held.is_empty());
    let hubd_state = serde_json::to_string(&f.hubd.state().unwrap()).unwrap();
    let hub_state = serde_json::to_string(&f.hub_state()).unwrap();
    let w_state = serde_json::to_string(&f.workers[0].agent.state).unwrap();
    let fabric = serde_json::to_string(&f.att.fabric.snapshot()).unwrap();
    for (what, text) in [
        ("hubd", &hubd_state),
        ("hub", &hub_state),
        ("worker state", &w_state),
        ("fabric", &fabric),
    ] {
        assert!(
            !text.contains("STAGINGVALUESENTINEL"),
            "{what} holds the value"
        );
    }
    assert!(
        !f.hub
            .store
            .names()
            .iter()
            .any(|n| n.starts_with("hub-delivered-")),
        "main holds no delivery"
    );
    // the other worker holds nothing
    assert!(!f.workers[1]
        .end
        .store
        .names()
        .iter()
        .any(|n| n.starts_with("hub-delivered-") && n != "hub-delivered-index"));
    // the task ends: revoke, and the worker's service deletes it
    let t = now_ms();
    f.att
        .svc
        .with(t, |hub, st| {
            hub.revoke_keys(st, "box-a", "orch-1", "keyed", t)
        })
        .unwrap()
        .unwrap();
    f.until("the keys are gone from the worker", |f| {
        !f.workers[0]
            .end
            .store
            .values()
            .iter()
            .any(|v| v.contains(VALUE))
    });
    // loss of the hub: a delivery again, then the hub goes away, and every key is deleted at once
    assign_to(
        &f,
        "box-a",
        "keyed2",
        "claude-code",
        ("staging", &["stripe-test"]),
    );
    f.until("delivered again", |f| {
        f.workers[0]
            .end
            .store
            .values()
            .iter()
            .any(|v| v.contains(VALUE))
    });
    f.workers[0].cable.cut();
    f.until("the worker deleted its keys on losing the hub", |f| {
        !f.workers[0]
            .end
            .store
            .values()
            .iter()
            .any(|v| v.contains(VALUE))
    });
}

/// Project memory proposed on one box is reviewed on main and read by the other agent, with a reviewed skill used by both.
#[test]
fn shared_memory_is_reviewed_before_it_is_read_and_a_reviewed_skill_reaches_both_boxes() {
    use ozbox_memory::memory::{Caller as MemCaller, Filter, State};
    use ozbox_memory::skills::InstallScope;
    let mut f = pair();
    let alpha = run_of(
        &f.workers[0].tools,
        "box-a",
        "claude-code",
        "anthropic",
        "billing",
    );
    let beta = run_of(&f.workers[1].tools, "box-b", "codex", "openai", "billing");
    call(&f.workers[0].tools, &alpha, "participants_list", json!({}));
    call(&f.workers[1].tools, &beta, "participants_list", json!({}));
    let name = ozbox_memory::bundled::bundled()[0].name.clone();
    let v = f
        .mem
        .skills
        .install(&name, &InstallScope::Project("billing".into()), "ada", 1)
        .unwrap();
    f.mem.skills.approve(&name, &v.hash, "ada", 1, &[]).unwrap();
    f.att.fabric.walls_changed();
    for (i, who) in [(0usize, &alpha), (1, &beta)] {
        let nm = name.clone();
        f.until("the reviewed skill reached the box", |f| {
            call(&f.workers[i].tools, who, "skills_list", json!({}))["skills"]
                .as_array()
                .is_some_and(|s| s.first().is_some_and(|k| k["name"] == nm.as_str()))
        });
        let text = call(
            &f.workers[i].tools,
            who,
            "skills_read",
            json!({"name": name}),
        );
        assert!(!text["text"].as_str().unwrap().is_empty());
    }
    // beta proposes; it waits on main for a person
    let p = call(
        &f.workers[1].tools,
        &beta,
        "memory_write",
        json!({"title": "Ledger rounding", "body": "The ledger rounds half-even.", "scope": "project:billing"}),
    );
    assert_eq!(p["state"], "pending");
    let person = MemCaller::Person("ada".into());
    let mut pending = Vec::new();
    f.until("the proposal is on main, pending", |f| {
        pending = f
            .mem
            .memory
            .list(
                &person,
                &Filter {
                    state: Some(State::Pending),
                    ..Filter::default()
                },
                now_ms(),
            )
            .unwrap();
        !pending.is_empty()
    });
    assert_eq!(pending[0].provenance.box_name.as_deref(), Some("box-b"));
    // nothing reads it before a person approves it
    assert!(call(
        &f.workers[0].tools,
        &alpha,
        "memory_search",
        json!({"query": "half-even"})
    )["notes"]
        .as_array()
        .unwrap()
        .is_empty());
    f.mem
        .memory
        .approve(&person, &pending[0].id, now_ms())
        .unwrap();
    f.att.fabric.walls_changed();
    let mut hits = Value::Null;
    f.until("the reviewed note reached the other box", |f| {
        hits = call(
            &f.workers[0].tools,
            &alpha,
            "memory_search",
            json!({"query": "half-even"}),
        );
        !hits["notes"].as_array().unwrap().is_empty()
    });
    assert_eq!(hits["notes"][0]["written_on"], "box-b");
    let full = call(
        &f.workers[0].tools,
        &alpha,
        "memory_read",
        json!({"id": hits["notes"][0]["id"]}),
    );
    assert_eq!(full["reviewed_by"], "ada");
    // a wall this run is not bound to is refused
    assert!(f.workers[0]
        .tools
        .call_as(
            &alpha.0,
            Some(&alpha.1),
            "memory_search",
            &json!({"query": "x", "scope": "project:payroll"}),
            now_ms()
        )
        .is_err());
}

/// A person on Telegram and on WhatsApp messages an agent and a fleet, and the replies come back attributed.
#[test]
fn a_person_on_telegram_and_whatsapp_reaches_agents_and_a_fleet_and_hears_attributed_replies() {
    use ozbox_core::fabric::bridge::{post_from_chat, pull_replies, ChatInbound, Subscriptions};
    use ozbox_core::fabric::Address;
    let mut f = pair();
    let alpha = run_of(
        &f.workers[0].tools,
        "box-a",
        "claude-code",
        "anthropic",
        "billing",
    );
    let beta = run_of(&f.workers[1].tools, "box-b", "codex", "openai", "billing");
    let a_addr = Address::parse(
        call(&f.workers[0].tools, &alpha, "participants_list", json!({}))["me"]
            .as_str()
            .unwrap(),
    )
    .unwrap();
    let b_addr = Address::parse(
        call(&f.workers[1].tools, &beta, "participants_list", json!({}))["me"]
            .as_str()
            .unwrap(),
    )
    .unwrap();
    f.until("both agents are known on main", |f| {
        f.att
            .fabric
            .participants(
                &ozbox_core::fabric::policy::Reach {
                    me: Address::Person { id: "ada".into() },
                    person: "ada".into(),
                    projects: vec![],
                    box_name: None,
                    delegated: vec![],
                },
                now_ms(),
            )
            .map(|v| v.len() >= 2)
            .unwrap_or(false)
    });
    let fleet = ozbox_core::fabric::Participant {
        address: Address::Fleet { name: "ada".into() },
        person: "ada".into(),
        display: "ada's fleet".into(),
        engine: None,
        provider: None,
        projects: Vec::new(),
        box_name: None,
        members: vec![a_addr.clone(), b_addr.clone()],
        home: HUB.into(),
    };
    f.att.fabric.register(fleet.clone(), now_ms()).unwrap();
    let mut subs = Subscriptions::default();
    for (ch, chat, to) in [
        ("telegram", "telegram:7", a_addr.clone()),
        ("whatsapp", "whatsapp:15550100", fleet.address.clone()),
    ] {
        post_from_chat(
            f.att.fabric.as_ref(),
            &mut subs,
            ChatInbound {
                person: "ada".into(),
                channel: ch.into(),
                chat_ref: chat.into(),
                targets: vec![to],
                text: "Where are you?".into(),
                thread: None,
                reply_to: None,
            },
            now_ms(),
        )
        .unwrap();
    }
    f.until("the fleet message reached the other box's agent", |f| {
        call(&f.workers[1].tools, &beta, "messages_get", json!({}))["messages"]
            .as_array()
            .is_some_and(|m| !m.is_empty())
    });
    let at_b = call(&f.workers[1].tools, &beta, "messages_get", json!({}));
    assert_eq!(at_b["messages"][0]["from"], "person:ada");
    call(
        &f.workers[0].tools,
        &alpha,
        "messages_post",
        json!({"to": "person:ada", "text": "Tests are green."}),
    );
    call(
        &f.workers[1].tools,
        &beta,
        "messages_post",
        json!({"to": "person:ada", "text": "Rebasing."}),
    );
    let mut replies = Vec::new();
    f.until("both replies reached the person's chats", |f| {
        let (r, _) = pull_replies(f.att.fabric.as_ref(), &subs, "ada", 0, now_ms()).unwrap();
        replies.extend(r);
        replies.len() >= 2
    });
    assert!(replies.iter().any(|x| x
        .attribution
        .ends_with("on box-a (claude-code · anthropic)")));
    assert!(replies
        .iter()
        .any(|x| x.attribution.ends_with("on box-b (codex · openai)")));
    for x in &replies {
        assert_eq!(x.to_chats.len(), 2);
        assert_eq!(x.project.as_deref(), Some("billing"));
    }
}

/// A worker that goes away mid-task is reported unreachable, and its task, queued on the link, arrives when it comes back.
#[test]
fn a_worker_that_goes_offline_is_reported_unreachable_and_resumes_when_it_returns() {
    use ozbox_core::hub::net::Reach;
    let mut f = pair();
    f.workers[1].cable.cut();
    f.until("the hub reports box-b unreachable", |f| {
        matches!(f.host.net.reach("box-b"), Some(Reach::NotAnswering { .. }))
    });
    // honest: a feature handed to it now is queued, and nothing says it is working
    assign_to(&f, "box-b", "late", "codex", ("staging", &[]));
    for _ in 0..20 {
        f.round();
        std::thread::sleep(Duration::from_millis(25));
    }
    assert!(f.workers[1].agent.state.tasks.is_empty());
    assert!(matches!(
        f.host.net.reach("box-b"),
        Some(Reach::NotAnswering { .. })
    ));
    f.workers[1].cable.heal();
    f.until("the worker came back, took the task and reported", |f| {
        f.hub_state().peers["box-b"]
            .report
            .results
            .get("orch-1")
            .is_some_and(|m| m.contains_key("late"))
    });
    assert!(matches!(
        f.host.net.reach("box-b"),
        Some(Reach::Connected { .. })
    ));
}

/// First contact is authenticated by the one-use token, the registrar's attestation and the worker's own proof; nothing less admits a
/// box, and a refused request leaves no pending enrolment.
#[test]
fn first_contact_is_refused_without_a_valid_token_attestation_and_proof() {
    let f = Fleet::new();
    let wend = end();
    let hub_fp = f.hubd.identity().identity_fp();
    let now = now_ms();
    let invite = |name: &str| {
        let plan = f
            .hubd
            .plan_invite(&InviteSpec {
                worker: name.into(),
                box_id: format!("box-of-{name}"),
                provider: Provider::Own,
                machine: format!("machine-{name}"),
                private_address: String::new(),
                orchestration: "orch-1".into(),
            })
            .unwrap();
        f.hubd.apply_invite(&plan, now).unwrap()
    };
    let attest_for = |name: &str, signer: &SeedSigner| {
        let lreq = LaptopRequest {
            provider: Provider::Own,
            machine: format!("machine-{name}"),
            box_id: format!("box-of-{name}"),
            orchestration: "orch-1".into(),
            hub_identity_fp: hub_fp.clone(),
            private_address: String::new(),
            class: WORKER_CLASS.into(),
            environment: "staging".into(),
            identity: wend.ops(Caller::Supervisor).identity().unwrap(),
            creation_proof: String::new(),
        };
        let p = plan(&lreq).unwrap();
        apply(
            &p,
            &lreq,
            signer,
            None,
            &Site {
                box_markers: Vec::new(),
            },
            now,
        )
        .unwrap()
    };
    let send = |req: &ozbox_hubd::enrol::EnrolRequest| {
        enrol_over_net(&f.dialer(), &serde_json::to_vec(req).unwrap())
    };
    // a wrong token
    let token = invite("w1");
    let good = attest_for("w1", &f.laptop);
    let bad_token = make_request(
        wend.ops(Caller::Supervisor).as_ref(),
        "w1",
        "not-the-token",
        good.clone(),
        &hub_fp,
        now,
    )
    .unwrap();
    assert!(send(&bad_token).is_err());
    // an attestation signed by a key the setup never pinned
    let (_, stranger) = SeedSigner::generate().unwrap();
    let forged = attest_for("w1", &stranger);
    let req = make_request(
        wend.ops(Caller::Supervisor).as_ref(),
        "w1",
        &token,
        forged,
        &hub_fp,
        now,
    )
    .unwrap();
    let e = send(&req).unwrap_err();
    assert_eq!(e.0, "unknown-registrar");
    // garbage on the first-contact path, and a request too large, are refused without a panic
    assert!(enrol_over_net(&f.dialer(), b"{not json").is_err());
    assert!(enrol_over_net(&f.dialer(), &vec![b' '; 20_000]).is_err());
    // nothing is pending, and nobody was enrolled
    assert!(f.hubd.state().unwrap().enrol.pending.is_empty());
    assert!(f.hubd.roster().unwrap().is_empty());
    // the genuine request is taken, once; the token is spent
    let ok = make_request(
        wend.ops(Caller::Supervisor).as_ref(),
        "w1",
        &token,
        good,
        &hub_fp,
        now,
    )
    .unwrap();
    assert!(send(&ok).is_ok());
    // the owner confirms; the same attestation and token then cannot be used again
    let eplan = f.hubd.plan_enrol("w1").unwrap();
    f.hubd.apply_enrol(&eplan, now_ms()).unwrap();
    assert!(send(&ok).is_err());
    let _ = hex(&[]);
    let _ = ask;
    let _ = HubNetConfig {
        listen: "127.0.0.1:0".parse().unwrap(),
        me: String::new(),
        roster: Default::default(),
        signer: Arc::new(HandshakeSigner {
            ops: f.hub.ops(Caller::Hub),
        }),
        verifier: Arc::new(HandshakeVerifier {
            dir: f.hubd.directory(),
        }),
    };
    let _ = (f.socket(), &f.hub_tools, &f.workers);
}

/// What `main`'s merge queue needs of its own box, played by a fake that records its calls and can say where a branch points.
struct GitOnMain {
    log: Vec<String>,
    /// Where the conductor's side sees every branch right now (`None`: it cannot say).
    head: Option<String>,
}

impl ozbox_core::orch_merge::Merger for GitOnMain {
    fn rebase(
        &mut self,
        _: Option<&str>,
        branch: &str,
        _: &str,
    ) -> Result<ozbox_core::orch_merge::RebaseOutcome, String> {
        self.log.push(format!("rebase {branch}"));
        Ok(ozbox_core::orch_merge::RebaseOutcome::Clean)
    }
    fn test(
        &mut self,
        _: Option<&str>,
        _: &str,
        _: &[String],
        _: Option<&str>,
    ) -> Result<ozbox_core::orch_merge::TestOutcome, String> {
        Err("the lane, not main, runs the tests here".into())
    }
    fn merge(
        &mut self,
        _: Option<&str>,
        branch: &str,
        _: &str,
    ) -> Result<ozbox_core::orch_merge::MergeOutcome, String> {
        self.log.push(format!("merge {branch}"));
        Ok(ozbox_core::orch_merge::MergeOutcome::Done)
    }
    fn head(&mut self, _: Option<&str>, _: &str) -> Result<Option<String>, String> {
        Ok(self.head.clone())
    }
}

/// Each worker takes the lane shards it was handed and reports every spec passed (running a shard is the box's own runner's).
fn run_shards(f: &mut Fleet) -> usize {
    let mut n = 0;
    for w in &mut f.workers {
        for sh in w.agent.take_shards() {
            n += 1;
            w.agent.shard_result(
                now_ms(),
                &ozbox_core::hub::lane::ShardResult {
                    run: sh.run.clone(),
                    shard: sh.shard,
                    passed: sh.specs.clone(),
                    failed: vec![],
                    flaky: vec![],
                    finished: true,
                },
            );
        }
    }
    n
}

/// Both workers' results go through `main`'s merge queue with the lane split across the two workers on each exact commit, the person
/// approves, a branch that moved after its lane passed is not merged on the old verdict, and the worker hears what happened.
#[test]
fn both_results_go_through_the_merge_queue_and_lanes_and_a_moved_branch_is_not_merged_on_an_old_verdict(
) {
    use ozbox_core::hub::lane::{Spec, Split};
    use ozbox_core::hub::merge::{
        admit_results, reported_commits, return_to_worker, HubMerger, LaneDecl,
    };
    use ozbox_core::hub::refusal::KeyDeclaration;
    use ozbox_core::orch::{FeatureReq, FeatureState, MergeState, Transport};
    use ozbox_core::orch_merge::merge_step;
    use ozbox_core::orch_rules::MergeApproval;
    use ozbox_core::run::{ApprovalState, Book};

    let mut f = pair();
    let mut book = Book::default();
    let id = book
        .start_orchestration("ship it", "ada", "main", &[], 1000)
        .unwrap();
    {
        let o = book.orchestration_mut(&id).unwrap();
        o.policy.test_command = vec!["npx".into(), "playwright".into(), "test".into()];
        o.policy.test_lane_box = Some("hub:browser".into());
        o.policy.merge_approval = MergeApproval::Person;
    }
    let mut feats = Vec::new();
    for (worker, engine, title) in [
        ("box-a", "claude-code", "parser"),
        ("box-b", "codex", "tests"),
    ] {
        let o = book.orchestration_mut(&id).unwrap();
        let fid = o
            .add_feature(
                &FeatureReq {
                    title: title.into(),
                    brief: format!("build {title}"),
                    box_name: Some(worker.into()),
                    ..Default::default()
                },
                1001,
            )
            .unwrap();
        let fm = o.feature_mut(&fid).unwrap();
        fm.transport = Transport::Hub;
        fm.state = FeatureState::Starting;
        let branch = fm.branch.clone();
        let mut a = ozbox_core::engine_turn::assign_of(
            &ozbox_core::engine_turn::Task {
                id: format!("{id}/{fid}"),
                title: title.into(),
                instruction: format!("TASK-MARKER {title}"),
                repo: Some("billing".into()),
                branch: Some(branch),
            },
            KeyDeclaration {
                env: "staging".into(),
                names: Vec::new(),
            },
            now_ms() + 3_600_000,
        );
        a.engine = Some(engine.into());
        let t = now_ms();
        f.att
            .svc
            .with(t, |hub, st| hub.assign(st, worker, &a, t))
            .unwrap()
            .unwrap();
        feats.push((worker, fid));
    }
    // both workers run their programs and report the exact commit they finished
    f.until("both results are at the hub", |f| {
        let st = f.hub_state();
        feats.iter().all(|(w, fid)| {
            st.peers.get(*w).is_some_and(|p| {
                p.report
                    .results
                    .get(&id)
                    .is_some_and(|m| m.contains_key(fid))
            })
        })
    });
    let queued = admit_results(&mut book, &f.hub_state(), now_ms());
    assert_eq!(queued.len(), 2);
    let commits = reported_commits(&book, &id);
    assert_eq!(commits.len(), 2);
    let suite = vec![
        Spec {
            file: "a.spec.ts".into(),
            resource: None,
            weight_ms: Some(9_000),
        },
        Spec {
            file: "b.spec.ts".into(),
            resource: Some("sandbox-1".into()),
            weight_ms: Some(2_000),
        },
        Spec {
            file: "c.spec.ts".into(),
            resource: Some("sandbox-1".into()),
            weight_ms: Some(2_000),
        },
        Spec {
            file: "d.spec.ts".into(),
            resource: None,
            weight_ms: Some(3_000),
        },
    ];
    let lanes: BTreeMap<String, LaneDecl> = [(
        "browser".to_string(),
        LaneDecl {
            name: "browser".into(),
            command: "browser-shard".into(),
            split: Split::Weight,
            specs: suite,
            workers: vec!["box-a".into(), "box-b".into()],
            known_keys: vec!["sandbox-1".into()],
        },
    )]
    .into_iter()
    .collect();
    let mut git = GitOnMain {
        log: Vec::new(),
        head: None,
    };
    let step = |f: &mut Fleet, book: &mut Book, git: &mut GitOnMain| {
        let now = now_ms();
        let commits = reported_commits(book, &id);
        f.att
            .svc
            .with(now, |hub, st| {
                let mut m = HubMerger {
                    inner: git,
                    hub,
                    st,
                    lanes: &lanes,
                    commits,
                    now,
                };
                let s = merge_step(book, &id, &mut m, now);
                if let Some(s) = &s {
                    let _ = return_to_worker(hub, st, book, &id, s, now);
                }
                s
            })
            .unwrap()
    };
    // the first feature: rebase, a lane on its exact commit split across both workers, never green until every spec passed
    let first = book.orchestration(&id).unwrap().merge_queue[0]
        .feature_id
        .clone();
    let mut state = None;
    for _ in 0..400 {
        f.round();
        run_shards(&mut f);
        if let Some(s) = step(&mut f, &mut book, &mut git) {
            state = Some(s.state);
            if s.state == MergeState::AwaitingApproval {
                break;
            }
        }
        std::thread::sleep(Duration::from_millis(25));
    }
    assert_eq!(state, Some(MergeState::AwaitingApproval), "{}", f.diag());
    assert!(
        f.hub_state().lanes.values().all(|l| l.shards.len() == 2),
        "the lane was split across both workers"
    );
    // the person decides the merge; the lane's green is a test result, not the gate
    let aid = book.orchestration(&id).unwrap().merge_queue[0]
        .approval_id
        .clone()
        .unwrap();
    assert!(book.approval(&aid).unwrap().needs_step_up);
    // ... but the branch moved after the lane passed: it is not merged on the old verdict
    book.approvals
        .iter_mut()
        .find(|a| a.id == aid)
        .unwrap()
        .state = ApprovalState::Approved;
    git.head = Some("c".repeat(40));
    let mut last = None;
    for _ in 0..10 {
        f.round();
        if let Some(s) = step(&mut f, &mut book, &mut git) {
            last = Some(s);
            if last.as_ref().is_some_and(|s| s.state == MergeState::Failed) {
                break;
            }
        }
    }
    let last = last.unwrap();
    assert_eq!(last.state, MergeState::Failed);
    assert!(
        last.detail
            .contains("no longer points at the commit the lane tested"),
        "{}",
        last.detail
    );
    assert!(
        !git.log.iter().any(|l| l.starts_with("merge ")),
        "{:?}",
        git.log
    );
    assert!(f.hub_state().tested.is_empty());
    // the branch is where the lane tested it again: queued again, the lane's verdict for that very commit stands, and it merges
    git.head = None;
    book.orchestration_mut(&id)
        .unwrap()
        .enqueue_merge(&first, now_ms())
        .unwrap();
    let mut merged = false;
    for _ in 0..400 {
        f.round();
        run_shards(&mut f);
        if let Some(s) = step(&mut f, &mut book, &mut git) {
            if s.state == MergeState::AwaitingApproval {
                // the person approves whatever is pending
                for a in book
                    .approvals
                    .iter_mut()
                    .filter(|a| a.state == ApprovalState::Pending)
                {
                    a.state = ApprovalState::Approved;
                }
            }
            if s.state == MergeState::Merged && s.feature_id == first {
                merged = true;
                break;
            }
        }
        std::thread::sleep(Duration::from_millis(25));
    }
    assert!(merged, "{}\n{:?}", f.diag(), git.log);
    // the worker that owns the feature hears it, as said by the queue
    let owner = feats.iter().find(|(_, fid)| *fid == first).unwrap().0;
    let i = f.workers.iter().position(|w| w.name == owner).unwrap();
    f.until("the worker heard the queue's answers", |f| {
        let h = &f.workers[i].agent.heard;
        h.iter().any(|x| x == &format!("{first}:merged"))
            && h.iter().any(|x| x == &format!("{first}:not-approved"))
    });
}
