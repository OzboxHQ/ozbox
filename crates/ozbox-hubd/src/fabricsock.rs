//! The worker's end of the conversation fabric, run by the hub agent (ADR 0057).
//!
//! The agent owns the worker's [`BoxFabric`]: it holds the replica (mailboxes, the walls of shared memory and skills), queues posts and
//! pushes them over the channel the agent dialed out, and pulls what the hub delivered, every tick. The box's tool host (`ozbox serve`,
//! which answers an agent's `messages_*`, `memory_*` and `skills_*` tools) is another process, so it reaches that one fabric through a
//! **local socket the agent serves**: [`serve`] answers one JSON line per request on a Unix socket, and [`SocketFabric`] is the
//! [`FabricApi`] a tool host builds on it. Nothing here is a second implementation: every call lands on the same `BoxFabric` the tests
//! drive in process, so a worker's messages and memory go through the agent and nothing else.
//!
//! Who may connect is decided by the socket's directory (mode `0750`, the agent's group), exactly like the secrets service's sockets:
//! only the box's own tool host. The caller's [`Reach`] is the tool host's word and is built from the run, never from an agent's text;
//! the fabric re-checks it on the hub as well. The socket carries messages as data; it has no operation that grants anything.

use std::io::{BufRead, BufReader, Read, Write};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::Path;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread::JoinHandle;
use std::time::Duration;

use ozbox_core::fabric::{
    Address, Batch, DeliveryState, FabricApi, FabricError, Message, NewProposal, Participant,
    ParticipantView, Post, PostReceipt, Reach, Walls,
};
use serde::de::DeserializeOwned;
use serde_json::{json, Value};

/// The longest request or answer, in bytes (a batch of 50 messages of 8 KiB, with the JSON around them).
const MAX_LINE: u64 = 2 << 20;
const IO_TIMEOUT: Duration = Duration::from_secs(40);

fn err_json(e: &FabricError) -> Value {
    let kind = match e {
        FabricError::Invalid(_) => "invalid",
        FabricError::Refused(_) => "refused",
        FabricError::NotFound(_) => "not_found",
        FabricError::Limit(_) => "limit",
        FabricError::Unavailable(_) => "unavailable",
    };
    json!({"ok": false, "error": {"kind": kind, "message": e.message()}})
}

fn err_of(v: &Value) -> FabricError {
    let m = v["error"]["message"].as_str().unwrap_or("").to_string();
    match v["error"]["kind"].as_str().unwrap_or("") {
        "invalid" => FabricError::Invalid(m),
        "refused" => FabricError::Refused(m),
        "not_found" => FabricError::NotFound(m),
        "limit" => FabricError::Limit(m),
        _ => FabricError::Unavailable(m),
    }
}

fn arg<T: DeserializeOwned>(v: &Value, k: &str) -> Result<T, FabricError> {
    serde_json::from_value(v[k].clone())
        .map_err(|_| FabricError::Invalid(format!("the request's {k} is not valid")))
}

/// Answer one request on `api`. Public so a test can drive the same dispatch without a socket.
pub fn answer(api: &dyn FabricApi, req: &Value) -> Value {
    let run = || -> Result<Value, FabricError> {
        let now: u64 = arg(req, "now").unwrap_or(0);
        Ok(match req["op"].as_str().unwrap_or("") {
            "register" => {
                api.register(arg::<Participant>(req, "participant")?, now)?;
                json!({})
            }
            "post" => {
                json!({"receipt": api.post(&arg::<Reach>(req, "reach")?, arg::<Post>(req, "post")?, now)?})
            }
            "get" => json!({"batch": api.get(
                &arg::<Reach>(req, "reach")?,
                arg(req, "after")?,
                arg(req, "limit")?,
                arg(req, "wait_ms")?,
                now,
            )?}),
            "thread" => {
                json!({"messages": api.thread(&arg::<Reach>(req, "reach")?, &arg::<String>(req, "thread")?, now)?})
            }
            "ack" => {
                json!({"acked": api.ack(&arg::<Reach>(req, "reach")?, &arg::<Vec<String>>(req, "ids")?, now)?})
            }
            "participants" => {
                json!({"participants": api.participants(&arg::<Reach>(req, "reach")?, now)?})
            }
            "sent" => {
                json!({"states": api.sent(&arg::<Reach>(req, "reach")?, &arg::<String>(req, "id")?)?})
            }
            "walls" => json!({"walls": api.walls()}),
            "propose" => {
                json!({"id": api.propose(&arg::<Reach>(req, "reach")?, arg::<NewProposal>(req, "proposal")?, now)?})
            }
            _ => {
                return Err(FabricError::Invalid(
                    "that operation is not offered here".into(),
                ))
            }
        })
    };
    match run() {
        Ok(mut v) => {
            v["ok"] = Value::Bool(true);
            v
        }
        Err(e) => err_json(&e),
    }
}

fn handle(api: &dyn FabricApi, stream: UnixStream) {
    let _ = stream.set_read_timeout(Some(IO_TIMEOUT));
    let _ = stream.set_write_timeout(Some(IO_TIMEOUT));
    let mut line = String::new();
    let read = BufReader::new((&stream).take(MAX_LINE)).read_line(&mut line);
    let reply = match read {
        Ok(_) if line.ends_with('\n') => match serde_json::from_str::<Value>(line.trim_end()) {
            Ok(v) => answer(api, &v),
            Err(_) => err_json(&FabricError::Invalid("the request is not valid".into())),
        },
        Ok(_) => err_json(&FabricError::Invalid(
            "the request is too large or unfinished".into(),
        )),
        Err(_) => return,
    };
    let mut out = &stream;
    let _ = writeln!(out, "{reply}");
}

/// What serves the socket: stopped by [`Serving::stop`].
pub struct Serving {
    stop: Arc<AtomicBool>,
    thread: Option<JoinHandle<()>>,
    path: std::path::PathBuf,
}

impl Serving {
    pub fn stop(mut self) {
        self.stop.store(true, Ordering::SeqCst);
        let _ = UnixStream::connect(&self.path);
        if let Some(t) = self.thread.take() {
            let _ = t.join();
        }
        let _ = std::fs::remove_file(&self.path);
    }
}

/// Serve `api` on a Unix socket at `path` (its directory of mode `dir_mode` decides who may connect), one thread per connection.
pub fn serve(api: Arc<dyn FabricApi>, path: &Path, dir_mode: u32) -> std::io::Result<Serving> {
    let listener: UnixListener = crate::daemon::bind(path, dir_mode)?;
    let stop = Arc::new(AtomicBool::new(false));
    let flag = stop.clone();
    let thread = std::thread::spawn(move || {
        for conn in listener.incoming() {
            if flag.load(Ordering::SeqCst) {
                break;
            }
            let Ok(c) = conn else { continue };
            let api = api.clone();
            std::thread::spawn(move || handle(api.as_ref(), c));
        }
    });
    Ok(Serving {
        stop,
        thread: Some(thread),
        path: path.to_path_buf(),
    })
}

/// The worker's fabric as the box's tool host reaches it: every call is one request to the agent's socket. A refusal keeps its kind;
/// an agent that cannot be reached is `Unavailable`, never an empty answer.
pub struct SocketFabric {
    path: std::path::PathBuf,
}

impl SocketFabric {
    pub fn new(path: impl Into<std::path::PathBuf>) -> SocketFabric {
        SocketFabric { path: path.into() }
    }

    fn call(&self, mut req: Value, now: u64) -> Result<Value, FabricError> {
        let down = || FabricError::Unavailable("this box's hub agent could not be reached".into());
        req["now"] = json!(now);
        let mut s = UnixStream::connect(&self.path).map_err(|_| down())?;
        let _ = s.set_read_timeout(Some(IO_TIMEOUT));
        let _ = s.set_write_timeout(Some(IO_TIMEOUT));
        let mut line = req.to_string();
        line.push('\n');
        s.write_all(line.as_bytes()).map_err(|_| down())?;
        let mut out = String::new();
        BufReader::new((&s).take(MAX_LINE))
            .read_line(&mut out)
            .map_err(|_| down())?;
        let v: Value = serde_json::from_str(out.trim_end()).map_err(|_| down())?;
        if v["ok"].as_bool() == Some(true) {
            Ok(v)
        } else {
            Err(err_of(&v))
        }
    }
}

fn take<T: DeserializeOwned>(v: &Value, k: &str) -> Result<T, FabricError> {
    serde_json::from_value(v[k].clone())
        .map_err(|_| FabricError::Unavailable("the hub agent's answer is not valid".into()))
}

impl FabricApi for SocketFabric {
    fn register(&self, p: Participant, now: u64) -> Result<(), FabricError> {
        self.call(json!({"op": "register", "participant": p}), now)
            .map(|_| ())
    }

    fn post(&self, by: &Reach, p: Post, now: u64) -> Result<PostReceipt, FabricError> {
        take(
            &self.call(json!({"op": "post", "reach": by, "post": p}), now)?,
            "receipt",
        )
    }

    fn get(
        &self,
        by: &Reach,
        after: u64,
        limit: usize,
        wait_ms: u64,
        now: u64,
    ) -> Result<Batch, FabricError> {
        take(
            &self.call(
                json!({"op": "get", "reach": by, "after": after, "limit": limit, "wait_ms": wait_ms}),
                now,
            )?,
            "batch",
        )
    }

    fn thread(&self, by: &Reach, thread: &str, now: u64) -> Result<Vec<Message>, FabricError> {
        take(
            &self.call(json!({"op": "thread", "reach": by, "thread": thread}), now)?,
            "messages",
        )
    }

    fn ack(&self, by: &Reach, ids: &[String], now: u64) -> Result<usize, FabricError> {
        take(
            &self.call(json!({"op": "ack", "reach": by, "ids": ids}), now)?,
            "acked",
        )
    }

    fn participants(&self, by: &Reach, now: u64) -> Result<Vec<ParticipantView>, FabricError> {
        take(
            &self.call(json!({"op": "participants", "reach": by}), now)?,
            "participants",
        )
    }

    fn sent(&self, by: &Reach, id: &str) -> Result<Vec<(Address, DeliveryState)>, FabricError> {
        take(
            &self.call(json!({"op": "sent", "reach": by, "id": id}), 0)?,
            "states",
        )
    }

    fn walls(&self) -> Option<Walls> {
        self.call(json!({"op": "walls"}), 0)
            .ok()
            .and_then(|v| serde_json::from_value::<Option<Walls>>(v["walls"].clone()).ok())
            .flatten()
    }

    fn propose(&self, by: &Reach, p: NewProposal, now: u64) -> Result<String, FabricError> {
        take(
            &self.call(json!({"op": "propose", "reach": by, "proposal": p}), now)?,
            "id",
        )
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    /// A fabric that records what reached it and refuses what is not its own.
    #[derive(Default)]
    struct Fake {
        seen: Mutex<Vec<String>>,
    }

    fn reach() -> Reach {
        Reach {
            me: Address::agent("box-a", "s1"),
            person: "ada".into(),
            projects: vec!["billing".into()],
            box_name: Some("box-a".into()),
            delegated: Vec::new(),
        }
    }

    impl FabricApi for Fake {
        fn register(&self, _: Participant, _: u64) -> Result<(), FabricError> {
            Ok(())
        }
        fn post(&self, by: &Reach, p: Post, _: u64) -> Result<PostReceipt, FabricError> {
            self.seen
                .lock()
                .unwrap()
                .push(format!("{} {}", by.me, p.text));
            if p.text.contains("refuse") {
                return Err(FabricError::Refused("not for you".into()));
            }
            Ok(PostReceipt {
                id: "m1".into(),
                thread: "t1".into(),
                recipients: Vec::new(),
            })
        }
        fn get(
            &self,
            _: &Reach,
            after: u64,
            _: usize,
            _: u64,
            _: u64,
        ) -> Result<Batch, FabricError> {
            Ok(Batch {
                messages: Vec::new(),
                next: after + 1,
                more: false,
            })
        }
        fn thread(&self, _: &Reach, _: &str, _: u64) -> Result<Vec<Message>, FabricError> {
            Err(FabricError::NotFound("no such thread".into()))
        }
        fn ack(&self, _: &Reach, ids: &[String], _: u64) -> Result<usize, FabricError> {
            Ok(ids.len())
        }
        fn participants(&self, _: &Reach, _: u64) -> Result<Vec<ParticipantView>, FabricError> {
            Ok(Vec::new())
        }
        fn sent(&self, _: &Reach, _: &str) -> Result<Vec<(Address, DeliveryState)>, FabricError> {
            Ok(Vec::new())
        }
    }

    #[test]
    fn every_call_lands_on_the_agents_fabric_and_a_refusal_keeps_its_kind() {
        let d = tempfile::tempdir().unwrap();
        let sock = d.path().join("run/fabric.sock");
        let fake = Arc::new(Fake::default());
        let serving = serve(fake.clone(), &sock, 0o750).unwrap();
        let c = SocketFabric::new(&sock);
        let post = |text: &str| Post {
            to: vec![Address::agent("box-b", "s2")],
            text: text.into(),
            thread: None,
            reply_to: None,
        };
        let r = c.post(&reach(), post("hello"), 5).unwrap();
        assert_eq!((r.id.as_str(), r.thread.as_str()), ("m1", "t1"));
        // the reach is the tool host's word and arrives whole
        assert_eq!(fake.seen.lock().unwrap()[0], "agent:box-a/s1 hello");
        assert!(matches!(
            c.post(&reach(), post("refuse"), 5),
            Err(FabricError::Refused(m)) if m == "not for you"
        ));
        assert!(matches!(
            c.thread(&reach(), "t9", 5),
            Err(FabricError::NotFound(_))
        ));
        assert_eq!(c.get(&reach(), 4, 20, 0, 5).unwrap().next, 5);
        assert_eq!(c.ack(&reach(), &["a".into(), "b".into()], 5).unwrap(), 2);
        // a fabric with no replicated walls (the hub's own) says so
        assert!(c.walls().is_none());
        // an operation this socket does not offer, and a request that is not one, are refused
        let v = answer(fake.as_ref(), &json!({"op": "approve_everything"}));
        assert_eq!(v["ok"], false);
        assert_eq!(v["error"]["kind"], "invalid");
        serving.stop();
        // an agent that is not running is unavailable, never an empty answer
        assert!(matches!(
            c.participants(&reach(), 5),
            Err(FabricError::Unavailable(_))
        ));
    }
}
