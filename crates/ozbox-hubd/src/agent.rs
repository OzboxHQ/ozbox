//! The worker's hub agent (ADR 0042 sections 2, 5, 6 and 8): what runs on a worker box to be a worker of a hub.
//!
//! It holds the worker's end of the channel ([`WorkerEnd`]) over a transport the worker dialed out on
//! ([`ozbox_core::hub::net::NetWorker`]; nothing on a worker listens), and on every [`WorkerAgent::tick`]:
//!
//! * **takes what the hub sent**: a task (refused here if it names Production, D2 on the worker), a delivery of keys by name (handed
//!   to the worker's own secrets service, which alone opens it), a revoke or the end of a task (their keys deleted), an answer to
//!   a question, a relayed decision (verified by this box's own approval service), a lane shard;
//! * **runs the task** through [`EngineSession`] with the engine the task names or the box's default, whatever its provider: it sees
//!   only the engine-neutral turn model, never a program's own format;
//! * **relays** the agent's asks, replies, state and result to the hub in the channel's own kinds ([`to_hub`]); a turn whose text
//!   looks like a key is not sent; an approval an agent wants is the box's own ADR 0041 flow's, never a message;
//! * **asks for keys by name** for a task that declared some (never Production, never a value in the ask);
//! * **deletes every key it holds at once** when the hub cannot be reached for [`HUB_LOST_AFTER_MS`] (ADR 0042 section 5.3);
//! * **announces its pending approval requests** and applies each decision its own service verified;
//! * **runs the worker's end of the conversation fabric** (messages, shared memory and skills): it pumps the replica every tick.
//!
//! It stores no secret: a key delivery is sealed to a key only the worker's secrets service holds ([`crate::fleet::ServiceDeliveryStore`]).
//! Its state is disposable: losing it loses only messages the hub has not acknowledged, and the hub resends them.

use std::collections::{BTreeMap, BTreeSet};
use std::sync::{Arc, Mutex};

use ozbox_core::agent_engine::AgentEngine;
use ozbox_core::channel::wire::{Sealer, Signer, Verifier};
use ozbox_core::engine_turn::{
    task_of, to_hub, EngineSession, HubOut, Reply, RunState, SessionStart, Turn,
};
use ozbox_core::fabric::node::BoxFabric;
use ozbox_core::hub::approvals::ApprovalService;
use ozbox_core::hub::engine::Assign;
use ozbox_core::hub::keys::DeliveryStore;
use ozbox_core::hub::net::Reach;
use ozbox_core::hub::wire::{Kind, Transport};
use ozbox_core::hub::worker::{WorkerEnd, WorkerState};

/// How long the hub may be out of reach before the worker deletes every key it holds (a reconnect takes up to 30 seconds, and a
/// connection that hears nothing for three heartbeats is closed: this is a little past both).
pub const HUB_LOST_AFTER_MS: u64 = 120_000;

/// Makes the engine a task asked for. The real one fills in each adapter's transport on this box; a test fills in a fake program.
pub trait EngineFactory: Send {
    /// The engine for `engine` (an engine-neutral id; empty means the box's default). `Err` names why it cannot be started.
    fn make(&mut self, engine: &str) -> Result<Box<dyn AgentEngine>, String>;
    /// The engine for one assigned task. The default is [`EngineFactory::make`] on the engine the task names; the real factory
    /// also reads the task's lease, which is the run's time limit.
    fn make_for(&mut self, a: &Assign) -> Result<Box<dyn AgentEngine>, String> {
        self.make(a.engine.as_deref().unwrap_or(""))
    }
}

/// The box's repository, as far as the agent needs it: the commit a finished task's branch points at, which is what the hub's
/// merge queue merges. `None` when there is none.
pub trait Workspace: Send {
    fn commit_of(&self, repo: Option<&str>, branch: &str) -> Option<String>;
}

/// What a tick did, for the host to act on and for tests.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct TickReport {
    /// Messages the hub sent that were applied.
    pub applied: usize,
    /// Tasks started on an engine this tick (`orchestration/feature`).
    pub started: Vec<String>,
    /// Tasks whose result went to the hub.
    pub finished: Vec<String>,
    /// Turns that were not sent, and why (a key shape in the text): the turn is dropped, never sent redacted-looking.
    pub withheld: Vec<String>,
    /// Actions an agent wants to take that the box's own approval flow decides (ADR 0041). Never a message.
    pub approval_asks: Vec<(String, ozbox_core::approvals::AgentAction)>,
    /// Tasks refused this tick, and why (a Production declaration, an engine this box cannot run): nothing was queued for them.
    pub refused: Vec<(String, String)>,
    /// Tasks whose run was stopped this tick because the hub ended them or their lease ran out.
    pub stopped: Vec<String>,
    /// Whether every key was deleted this tick because the hub was out of reach too long.
    pub keys_deleted: bool,
}

/// What a worker box needs to be a worker.
pub struct AgentSeams {
    pub me: String,
    pub hub: String,
    /// This box's name for engines and the run record.
    pub box_name: String,
    pub signer: Arc<dyn Signer>,
    pub verifier: Arc<dyn Verifier>,
    pub sealer: Arc<dyn Sealer>,
    pub net: Arc<dyn Transport>,
    /// How reachable the hub is (the transport's own account), for the loss rule.
    pub reach: Arc<dyn Fn() -> Reach + Send + Sync>,
    pub store: Arc<dyn DeliveryStore + Send + Sync>,
    /// This box's own approval service; `None` announces nothing and applies nothing.
    pub approvals: Option<Arc<Mutex<dyn ApprovalService + Send>>>,
    pub engines: Box<dyn EngineFactory>,
    pub workspace: Box<dyn Workspace>,
    /// This worker's end of the conversation fabric (ADR 0057): the agent pumps it every tick, so messages and shared memory and skills
    /// move over the channel it dialed out, and serves it to the box's tool host ([`crate::fabricsock`]). `None` carries none.
    pub fabric: Option<Arc<BoxFabric>>,
    /// How long the hub may be out of reach before every key is deleted ([`HUB_LOST_AFTER_MS`] on a real box).
    pub lost_after_ms: u64,
}

/// One worker box's agent.
pub struct WorkerAgent {
    s: AgentSeams,
    pub state: WorkerState,
    sessions: BTreeMap<String, EngineSession>,
    started: BTreeSet<String>,
    done: BTreeSet<String>,
    said_hello: u64,
    lost_since: Option<u64>,
    keys_deleted: bool,
    /// Why turns were not sent, kept for the host to show (the last few; reasons only, never the text).
    pub withheld_log: Vec<String>,
    /// What the hub said back about this worker's features (`<feature>:<kind>`: merged, conflict, tests-failed ...), the last few.
    pub heard: Vec<String>,
}

fn end_of(s: &AgentSeams) -> WorkerEnd<'_> {
    WorkerEnd {
        me: &s.me,
        hub: &s.hub,
        signer: s.signer.as_ref(),
        verifier: s.verifier.as_ref(),
        sealer: s.sealer.as_ref(),
        net: s.net.as_ref(),
    }
}

fn task_id(a: &Assign) -> String {
    format!("{}/{}", a.orchestration, a.feature)
}

impl WorkerAgent {
    /// `state` is made from the keys this worker enrolled with and the hub identity it pinned (`WorkerState::new`).
    pub fn new(seams: AgentSeams, state: WorkerState) -> WorkerAgent {
        WorkerAgent {
            s: seams,
            state,
            sessions: BTreeMap::new(),
            started: BTreeSet::new(),
            done: BTreeSet::new(),
            said_hello: 0,
            lost_since: None,
            keys_deleted: false,
            withheld_log: Vec::new(),
            heard: Vec::new(),
        }
    }

    /// Hand the decision on an action the agent proposed (made by this box's own ADR 0041 flow) to the engine that asked.
    pub fn decide(&mut self, task: &str, approved: bool) -> Result<(), String> {
        self.sessions
            .get_mut(task)
            .ok_or_else(|| "that task is not running here".to_string())?
            .decide(approved)
            .map_err(|e| e.to_string())
    }

    /// The lane shards the hub handed this worker since the last call. Running a shard with the declared command is the box's own
    /// runner's; the agent only carries the assignment in and the result back ([`WorkerAgent::shard_result`]).
    pub fn take_shards(&mut self) -> Vec<ozbox_core::hub::lane::ShardAssign> {
        std::mem::take(&mut self.state.shards)
    }

    /// Report a lane shard's results to the hub.
    pub fn shard_result(&mut self, now: u64, r: &ozbox_core::hub::lane::ShardResult) {
        end_of(&self.s).shard_result(&mut self.state, now, r);
    }

    /// Report that this worker finished a feature on `commit` (the exact commit the merge queue will merge), outside an engine run:
    /// a worker that pushed again.
    pub fn report_finished(
        &mut self,
        now: u64,
        orchestration: &str,
        feature: &str,
        commit: &str,
        summary: &str,
    ) {
        end_of(&self.s).finish(
            &mut self.state,
            now,
            orchestration,
            feature,
            commit,
            summary,
        );
    }

    /// Ask the hub for keys by name for a task this worker holds (an agent that needs one later than at the start). Refused here, before
    /// anything is sent, for a name the task did not declare and for anything that is or looks like Production.
    pub fn ask_keys(
        &mut self,
        now: u64,
        orchestration: &str,
        feature: &str,
        names: &[String],
    ) -> Result<(), String> {
        end_of(&self.s)
            .ask_keys(&mut self.state, now, orchestration, feature, names)
            .map_err(|e| e.code.to_string())
    }

    /// Change how long the hub may be out of reach before every key is deleted (a test shortens it).
    pub fn set_lost_after(&mut self, ms: u64) {
        self.s.lost_after_ms = ms;
    }

    /// The tasks running on an engine here.
    pub fn running(&self) -> Vec<String> {
        self.sessions.keys().cloned().collect()
    }

    /// One round: take what the hub sent, run the tasks, say what happened, ask for keys, delete them when the hub is lost.
    pub fn tick(&mut self, now: u64) -> TickReport {
        let mut rep = TickReport::default();
        // 1. the hub's loss rule (ADR 0042 section 5.3): out of reach too long, every key goes at once
        match (self.s.reach)() {
            Reach::Connected { .. } => {
                self.lost_since = None;
                self.keys_deleted = false;
            }
            Reach::Never | Reach::NotAnswering { .. } => {
                let since = *self.lost_since.get_or_insert(now);
                if now.saturating_sub(since) >= self.s.lost_after_ms && !self.keys_deleted {
                    let end = end_of(&self.s);
                    end.hub_lost(&mut self.state, now, self.s.store.as_ref());
                    self.keys_deleted = true;
                    rep.keys_deleted = true;
                }
            }
        }
        // 1b. the conversation fabric: flush what the box's agents posted, take what the hub delivered (messages and the walls of shared
        // memory and skills). Its own endpoint on the same connection; a failure is the fabric's to retry, never the task's.
        if let Some(f) = &self.s.fabric {
            let _ = f.pump(now);
        }
        // 2. the hub's messages (keys go to this box's own service)
        if now.saturating_sub(self.said_hello) >= 1_000 || self.said_hello == 0 {
            end_of(&self.s).hello(&mut self.state, now);
            self.said_hello = now;
        }
        {
            rep.applied = end_of(&self.s).poll_keys(&mut self.state, now, self.s.store.as_ref());
        }
        // 3. decisions this box's own approval service verifies, and the requests it announces
        if let Some(svc) = self.s.approvals.clone() {
            if let Ok(mut g) = svc.lock() {
                let end = end_of(&self.s);
                end.apply_decisions(&mut self.state, &mut *g, now);
                end.announce_approvals(&mut self.state, &*g, now);
            }
        }
        // 4. new tasks
        let tasks: Vec<Assign> = self.state.tasks.clone();
        for a in tasks {
            let id = task_id(&a);
            if self.started.contains(&id) || a.lease_expiry_ms <= now {
                continue;
            }
            self.started.insert(id.clone());
            match self.start(&a) {
                Ok(()) => rep.started.push(id.clone()),
                Err(why) => {
                    rep.refused.push((id.clone(), why.clone()));
                    self.say_status(now, &a, "refused", &why);
                }
            }
            if !a.keys.names.is_empty() {
                let r = end_of(&self.s).ask_keys(
                    &mut self.state,
                    now,
                    &a.orchestration,
                    &a.feature,
                    &a.keys.names,
                );
                if let Err(e) = r {
                    self.say_status(now, &a, "refused", e.code);
                }
            }
        }
        // 4b. a task the hub ended (`task.end` takes it off this worker) or whose lease ran out stops its run: the run is asked to
        // stop cleanly (the box's supervisor checkpoints and cancels it) and nothing more is reported for it
        let live: BTreeSet<String> = self
            .state
            .tasks
            .iter()
            .filter(|a| a.lease_expiry_ms > now)
            .map(task_id)
            .collect();
        let gone: Vec<String> = self
            .sessions
            .keys()
            .filter(|id| !live.contains(*id))
            .cloned()
            .collect();
        for id in gone {
            if let Some(mut sess) = self.sessions.remove(&id) {
                let _ = sess.stop();
            }
            self.done.insert(id.clone());
            rep.stopped.push(id);
        }
        // 5. answers the hub gave about these tasks go to the agent that asked
        for ans in std::mem::take(&mut self.state.answers) {
            let id = format!("{}/{}", ans.orchestration, ans.feature);
            self.heard.push(format!("{}:{}", ans.feature, ans.kind));
            self.heard.truncate(32);
            if let Some(sess) = self.sessions.get_mut(&id) {
                let text = if ans.kind == "answer" {
                    ans.text
                } else {
                    format!("{}: {}", ans.kind, ans.text)
                };
                let _ = sess.reply(&Reply {
                    ask_id: String::new(),
                    text,
                });
            }
        }
        // 6. what the agents did
        let ids: Vec<String> = self.sessions.keys().cloned().collect();
        for id in ids {
            self.step(&id, now, &mut rep);
        }
        rep
    }

    fn start(&mut self, a: &Assign) -> Result<(), String> {
        // D2 again, at the agent: the worker's screen refused a Production declaration before the task was held, and the agent
        // does not trust that it was the only gate. A worker never runs a task that asks for Production, and never starts an
        // engine for one.
        ozbox_core::hub::refusal::refuse_production(&a.keys).map_err(|r| r.to_string())?;
        let engine = self
            .s
            .engines
            .make_for(a)
            .map_err(|e| format!("no engine could be started: {e}"))?;
        let sess = EngineSession::start(
            engine,
            &SessionStart {
                task: task_of(a),
                box_name: self.s.box_name.clone(),
                model: a.model.clone(),
                // the run's own token comes from the box's broker when the real factory starts it; nothing of a key is in a task
                secret_env: BTreeMap::new(),
                deny_commands: Vec::new(),
                // a task runs to its result; a question an agent asks is a turn of its own (a conversation is a person's, over chat)
                conversation: false,
            },
        )
        .map_err(|e| e.to_string())?;
        self.sessions.insert(task_id(a), sess);
        Ok(())
    }

    fn say_status(&mut self, now: u64, a: &Assign, state: &str, text: &str) {
        let body = ozbox_core::hub::engine::StatusBody {
            orchestration: a.orchestration.clone(),
            feature: a.feature.clone(),
            state: state.to_string(),
            text: text.chars().take(300).collect(),
        };
        if let Ok(b) = serde_json::to_vec(&body) {
            end_of(&self.s).send_body(&mut self.state, now, Kind::Status, &b);
        }
    }

    fn step(&mut self, id: &str, now: u64, rep: &mut TickReport) {
        let Some(sess) = self.sessions.get_mut(id) else {
            return;
        };
        let turns = match sess.step() {
            Ok(t) => t,
            Err(e) => vec![Turn::State(RunState::Failed, Some(e.to_string()))],
        };
        let assign = self.state.tasks.iter().find(|t| task_id(t) == id).cloned();
        for t in turns {
            let mut turn = t;
            // a finished task reports the commit its branch points at: that is what the merge queue merges
            if let (Turn::Result(o), Some(a)) = (&mut turn, &assign) {
                if o.commit.is_none() {
                    o.commit = self.s.workspace.commit_of(a.repo.as_deref(), &a.branch);
                }
            }
            match to_hub(id, &turn) {
                Ok(HubOut::Send(kind, body)) => {
                    end_of(&self.s).send_body(&mut self.state, now, kind, &body);
                    let ends = kind == Kind::Result
                        || matches!(&turn, Turn::State(RunState::Failed, _))
                        || (kind == Kind::Status && matches!(&turn, Turn::Result(_)));
                    if ends && self.done.insert(id.to_string()) {
                        rep.finished.push(id.to_string());
                    }
                }
                Ok(HubOut::Approval(action)) => rep.approval_asks.push((id.to_string(), action)),
                Ok(HubOut::Local) => {}
                Err(e) => {
                    rep.withheld.push(format!("{id}: {e}"));
                    self.withheld_log.push(format!("{id}: {e}"));
                    self.withheld_log.truncate(8);
                }
            }
        }
        if self.done.contains(id) {
            if let Some(mut s) = self.sessions.remove(id) {
                let _ = s.stop();
            }
        }
    }
}
