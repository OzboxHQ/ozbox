//! The worker-box route of a chat message over the agent mesh (ADR 0044): the adapter behind [`super::remote::RemoteAgents`].
//!
//! A chat message for an agent on a worker box becomes a mesh **question** task to that box's endpoint, signed and sealed by the
//! channel, carrying the person's words as text and, as data, the message id, the session it is for and the digest of the
//! signed delegation the worker checks for itself. Each round with the worker sends what is waiting and takes what came back;
//! a message the worker's agent posted on the task is a reply, attributed to the box and the task, and is **untrusted text**
//! (the mesh stamps every peer message untrusted) that the gateway redacts before it reaches a chat.
//!
//! What this does not do: approve or grant anything (a mesh message can ask and never grant), carry a secret (the mesh's own
//! screen refuses key-shaped bodies), or decide whether the worker may act (the worker's chat profile does). A worker that does
//! not answer is unreachable now, and its task stays in the outbox until it does.

use std::collections::BTreeMap;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};

use ozbox_core::agent_mesh::model::{Label, Part, TaskKind};
use ozbox_core::agent_mesh::node::Transport;
use ozbox_core::agent_mesh::state::NewTask;

use super::remote::{RemoteAgents, RemoteError, RemoteReply, Worker};
use crate::secrets::SecretStore;
use crate::tasks_ops::{Ends, KeyHome};

/// The schema of the data part a chat message carries.
pub const CHAT_SCHEMA: &str = "ozbox.chat.v1";

/// Where this endpoint's keys live.
pub enum Keys {
    /// In the channel's own directory (tests; on a box that is the router's, which the dashboard does not open).
    #[cfg(test)]
    RouterFile,
    Store(Arc<dyn SecretStore>),
}

/// The mesh route: this endpoint's channel directory, its keys, and a transport to the workers.
pub struct MeshAgents {
    dir: PathBuf,
    keys: Keys,
    net: Box<dyn Transport + Send + Sync>,
    /// task id -> (box, chat message id, replies already taken)
    pending: Mutex<BTreeMap<String, (String, String, usize)>>,
}

impl MeshAgents {
    pub fn new(dir: PathBuf, keys: Keys, net: Box<dyn Transport + Send + Sync>) -> MeshAgents {
        MeshAgents {
            dir,
            keys,
            net,
            pending: Mutex::new(BTreeMap::new()),
        }
    }

    /// The endpoint, opened for one call: its keys are read when they are needed and dropped after.
    fn ends(&self) -> Result<Ends, RemoteError> {
        let home = match &self.keys {
            #[cfg(test)]
            Keys::RouterFile => KeyHome::RouterFile,
            Keys::Store(s) => KeyHome::Store(s.as_ref()),
        };
        Ends::open(&self.dir, home).map_err(|_| RemoteError::NotConfigured)
    }
}

impl RemoteAgents for MeshAgents {
    fn workers(&self) -> Vec<Worker> {
        let Ok(ends) = self.ends() else {
            return Vec::new();
        };
        let Ok(st) = ends.state() else {
            return Vec::new();
        };
        // whether a worker answers is learned by trying: a worker that does not is reported unreachable for that message
        st.core
            .links
            .keys()
            .map(|name| Worker {
                name: name.clone(),
                online: true,
                production: false,
            })
            .collect()
    }

    fn send(
        &self,
        box_name: &str,
        session: Option<&str>,
        text: &str,
        msg_id: &str,
        delegation: &str,
    ) -> Result<String, RemoteError> {
        if delegation.is_empty() {
            return Err(RemoteError::Refused);
        }
        let ends = self.ends()?;
        let node = ends.node();
        let id = node
            .submit(NewTask {
                to: box_name.to_string(),
                kind: TaskKind::Question,
                title: format!("Chat message {msg_id}"),
                parts: vec![
                    Part::Text {
                        text: text.to_string(),
                    },
                    Part::Data {
                        schema: CHAT_SCHEMA.into(),
                        json: serde_json::json!({
                            "msg": msg_id,
                            "session": session,
                            // a reference to the signed delegation (its digest's first 16 hex), not the record: a long hex
                            // string reads as key-shaped to the mesh's screen, and the worker fetches and checks the record
                            // itself (ADR 0050 decision 4; the worker side is not built in this release)
                            "delegation": delegation.chars().take(16).collect::<String>(),
                        }),
                    },
                ],
                label: Label::Person,
                act: None,
                parent: None,
                deadline_ms: None,
            })
            .map_err(|_| RemoteError::Refused)?;
        if let Ok(mut p) = self.pending.lock() {
            p.insert(id.clone(), (box_name.to_string(), msg_id.to_string(), 0));
        }
        // the task is in the outbox either way; a worker that does not answer now is unreachable now
        node.sync(box_name, self.net.as_ref())
            .map_err(|_| RemoteError::Unreachable)?;
        Ok(id)
    }

    fn take_replies(&self) -> Vec<RemoteReply> {
        let Ok(ends) = self.ends() else {
            return Vec::new();
        };
        let peers: Vec<String> = match self.pending.lock() {
            Ok(p) => {
                let mut v: Vec<String> = p.values().map(|(b, _, _)| b.clone()).collect();
                v.sort();
                v.dedup();
                v
            }
            Err(_) => return Vec::new(),
        };
        for peer in &peers {
            let _ = ends.node().sync(peer, self.net.as_ref());
        }
        let Ok(st) = ends.state() else {
            return Vec::new();
        };
        let Ok(mut pending) = self.pending.lock() else {
            return Vec::new();
        };
        let mut out = Vec::new();
        for (task_id, (box_name, msg_id, taken)) in pending.iter_mut() {
            // a task is kept under its sender and its id
            let key = ozbox_core::agent_mesh::task_key(&st.core.me, task_id);
            let Some(task) = st.tasks.get(&key).or_else(|| st.tasks.get(task_id)) else {
                continue;
            };
            let from_worker: Vec<&ozbox_core::agent_mesh::model::Message> = task
                .messages
                .iter()
                .filter(|m| m.from == *box_name)
                .collect();
            for m in from_worker.iter().skip(*taken) {
                let text: Vec<String> = m
                    .parts
                    .iter()
                    .filter_map(|p| match p {
                        Part::Text { text } => Some(text.clone()),
                        Part::Data { .. } => None,
                    })
                    .collect();
                out.push(RemoteReply {
                    box_name: box_name.clone(),
                    session: task_id.clone(),
                    msg_id: msg_id.clone(),
                    text: text.join("\n"),
                });
            }
            *taken = from_worker.len();
        }
        out
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
pub mod testkit {
    //! Two real mesh endpoints (real signatures and sealing, the channel's own store) joined by a loopback transport: the
    //! worker answers in the same call, as `tasks serve` does.
    use super::*;
    use ozbox_core::agent_mesh::model::State as TState;
    use ozbox_core::channel::wire::Sealed;

    pub fn endpoint(dir: &std::path::Path, name: &str) {
        crate::tasks_ops::init(dir, name, KeyHome::RouterFile).unwrap();
    }

    fn open(dir: &std::path::Path) -> Ends {
        Ends::open(dir, KeyHome::RouterFile).unwrap()
    }

    /// Pin each end to the other.
    pub fn pin(a: &std::path::Path, b: &std::path::Path, now: u64) {
        let (ea, eb) = (open(a), open(b));
        let (sa, sb) = (ea.state().unwrap(), eb.state().unwrap());
        ea.store()
            .update(|s| {
                s.pin(
                    now,
                    &sb.core.me,
                    &sb.core.sign_public,
                    &sb.core.seal_public,
                    1,
                    None,
                )
                .unwrap();
            })
            .unwrap();
        eb.store()
            .update(|s| {
                s.pin(
                    now,
                    &sa.core.me,
                    &sa.core.sign_public,
                    &sa.core.seal_public,
                    1,
                    None,
                )
                .unwrap();
            })
            .unwrap();
    }

    /// A worker whose agent answers every chat question it receives with `answer` and the question's words.
    pub struct Worker {
        pub dir: PathBuf,
        pub caller: String,
        pub answer: String,
        pub down: Mutex<bool>,
        /// What the worker received: (task id, words, data).
        pub got: Mutex<Vec<(String, String, serde_json::Value)>>,
    }

    impl Transport for Worker {
        fn exchange(&self, _peer: &str, outbound: &[Sealed]) -> Result<Vec<Sealed>, String> {
            if self.down.lock().map(|d| *d).unwrap_or(true) {
                return Err("the worker does not answer".into());
            }
            let w = open(&self.dir);
            let (_, _) = w
                .node()
                .serve(&self.caller, outbound)
                .map_err(|e| e.to_string())?;
            // the worker's agent answers what it has not answered yet
            let st = w.state().unwrap();
            for (id, t) in &st.tasks {
                let answered = t.messages.iter().any(|m| m.from == st.core.me);
                if t.from != self.caller || answered {
                    continue;
                }
                let words: String = t
                    .messages
                    .iter()
                    .flat_map(|m| m.parts.iter())
                    .filter_map(|p| match p {
                        Part::Text { text } => Some(text.clone()),
                        Part::Data { .. } => None,
                    })
                    .collect::<Vec<_>>()
                    .join(" ");
                let data = t
                    .messages
                    .iter()
                    .flat_map(|m| m.parts.iter())
                    .find_map(|p| match p {
                        Part::Data { json, .. } => Some(json.clone()),
                        Part::Text { .. } => None,
                    })
                    .unwrap_or_default();
                self.got
                    .lock()
                    .unwrap()
                    .push((id.clone(), words.clone(), data));
                w.node()
                    .reply(
                        id,
                        vec![Part::Text {
                            text: format!("{}{words}", self.answer),
                        }],
                        Some((TState::Working, None)),
                    )
                    .unwrap();
            }
            let (_, back) = w
                .node()
                .serve(&self.caller, &[])
                .map_err(|e| e.to_string())?;
            Ok(back)
        }
    }

    /// The same worker, shared with the test that looks at it.
    pub struct Shared(pub Arc<Worker>);

    impl Transport for Shared {
        fn exchange(&self, peer: &str, outbound: &[Sealed]) -> Result<Vec<Sealed>, String> {
            self.0.exchange(peer, outbound)
        }
    }
}
