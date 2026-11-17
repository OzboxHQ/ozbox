//! How a chat message reaches an agent on a box this dashboard does not run itself: a worker box of a hub (ADR 0042),
//! reached over the hub's sealed channel and the agent mesh (ADR 0044).
//!
//! A box this dashboard manages is reached the way every other screen reaches it (the box's own daemon, through the
//! supervisor's task store), and needs nothing here. A worker box is reached through [`RemoteAgents`]: the chat gateway
//! hands it one message with an id and asks later for the replies. The gateway never trusts what comes back: a reply is
//! untrusted text and goes through the same redaction and attribution as any other.
//!
//! **Status: the interface is built and tested against a fake; the real adapter onto the agent mesh's node is Planned until
//! the hub and the mesh are merged.** Until then [`NoRemote`] says there are no worker boxes, so nothing is ever routed here.

#[cfg(test)]
use std::sync::Mutex;

/// A worker box a hub can reach.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Worker {
    pub name: String,
    /// The worker answered the hub recently. An offline worker is reported as unreachable, never silently skipped.
    pub online: bool,
    /// Marked Production on the worker's own record. Never reached from chat.
    pub production: bool,
}

/// An agent's answer from a worker box, for one message.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RemoteReply {
    pub box_name: String,
    pub session: String,
    pub msg_id: String,
    pub text: String,
}

/// Why a message could not be handed to a worker. A code, never a value.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RemoteError {
    /// No hub channel is set up on this dashboard.
    NotConfigured,
    /// The worker did not answer.
    #[cfg_attr(not(test), allow(dead_code))]
    Unreachable,
    /// The worker refused it (its own chat profile, its own check of the delegation).
    #[cfg_attr(not(test), allow(dead_code))]
    Refused,
}

impl RemoteError {
    pub const fn code(self) -> &'static str {
        match self {
            RemoteError::NotConfigured => "no_hub_channel",
            RemoteError::Unreachable => "worker_unreachable",
            RemoteError::Refused => "worker_refused",
        }
    }
}

/// The delivery of chat messages to agents on worker boxes.
pub trait RemoteAgents: Send + Sync {
    /// The worker boxes this dashboard can reach.
    fn workers(&self) -> Vec<Worker>;
    /// Hand one message to a session on a worker (or, with no session, to the worker's default agent). `delegation` is the
    /// digest of the signed delegation the worker checks for itself (it never trusts the hub's word). The answer is the
    /// session the message went to.
    fn send(
        &self,
        box_name: &str,
        session: Option<&str>,
        text: &str,
        msg_id: &str,
        delegation: &str,
    ) -> Result<String, RemoteError>;
    /// The replies that arrived since the last call.
    fn take_replies(&self) -> Vec<RemoteReply>;
}

/// No hub channel: there are no worker boxes.
pub struct NoRemote;

impl RemoteAgents for NoRemote {
    fn workers(&self) -> Vec<Worker> {
        Vec::new()
    }
    fn send(
        &self,
        _: &str,
        _: Option<&str>,
        _: &str,
        _: &str,
        _: &str,
    ) -> Result<String, RemoteError> {
        Err(RemoteError::NotConfigured)
    }
    fn take_replies(&self) -> Vec<RemoteReply> {
        Vec::new()
    }
}

/// A fake hub channel for tests: workers, what was sent, and an echo agent on each online worker.
#[cfg(test)]
#[derive(Default)]
pub struct FakeMesh {
    pub inner: Mutex<FakeMeshState>,
}

#[cfg(test)]
#[derive(Default)]
pub struct FakeMeshState {
    pub workers: Vec<Worker>,
    /// (box, session, text, msg id, delegation)
    pub sent: Vec<(String, String, String, String, String)>,
    pub replies: Vec<RemoteReply>,
    /// What the echo agent answers, before the text it was sent.
    pub answer: String,
}

#[cfg(test)]
impl RemoteAgents for FakeMesh {
    fn workers(&self) -> Vec<Worker> {
        self.inner
            .lock()
            .map(|s| s.workers.clone())
            .unwrap_or_default()
    }
    fn send(
        &self,
        box_name: &str,
        session: Option<&str>,
        text: &str,
        msg_id: &str,
        delegation: &str,
    ) -> Result<String, RemoteError> {
        let mut s = self.inner.lock().map_err(|_| RemoteError::Unreachable)?;
        let w = s
            .workers
            .iter()
            .find(|w| w.name == box_name)
            .cloned()
            .ok_or(RemoteError::Unreachable)?;
        if !w.online {
            return Err(RemoteError::Unreachable);
        }
        if delegation.is_empty() {
            return Err(RemoteError::Refused);
        }
        let session = session.unwrap_or("w1").to_string();
        s.sent.push((
            box_name.into(),
            session.clone(),
            text.into(),
            msg_id.into(),
            delegation.into(),
        ));
        let answer = format!("{}{text}", s.answer);
        s.replies.push(RemoteReply {
            box_name: box_name.into(),
            session: session.clone(),
            msg_id: msg_id.into(),
            text: answer,
        });
        Ok(session)
    }
    fn take_replies(&self) -> Vec<RemoteReply> {
        self.inner
            .lock()
            .map(|mut s| std::mem::take(&mut s.replies))
            .unwrap_or_default()
    }
}
