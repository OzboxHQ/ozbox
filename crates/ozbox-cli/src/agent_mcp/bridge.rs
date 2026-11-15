//! `ozbox agent-mcp bridge`: the stdio MCP server an engine starts, relaying to the box's agent socket.
//!
//! Engines speak MCP over stdio (newline-delimited JSON-RPC) or over HTTP on a port; none speaks HTTP over a Unix socket.
//! The bridge is the small piece between: each line on stdin goes to `POST /mcp` on the socket with this session's token, and
//! the answer goes back on stdout. The connection stays open between calls, so a call costs one socket write and read.
//!
//! The token is enrolled over the socket (the kernel tells the dashboard who is asking) and held in this process's memory
//! only. It is enrolled again a little before it ends and whenever the dashboard answers 401 (it was restarted, or the
//! setting was turned off and on). When the door is shut (turned off, not the box user, inside a run, no dashboard) the
//! bridge still answers the handshake, offers no tools, and says why in the server's instructions, so the engine shows a
//! server with nothing to call rather than a crash; the same words come back to any tool call.

use std::io::{BufRead, BufReader, Write};
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};

use serde_json::{json, Value};

use super::http;

const MAX_ANSWER: usize = 16 * 1024 * 1024;
/// Enrol again when fewer than this many milliseconds are left.
const RENEW_BEFORE_MS: u64 = 5 * 60 * 1000;

/// The socket the bridge dials.
pub fn socket_path() -> PathBuf {
    if cfg!(debug_assertions) {
        if let Ok(s) = std::env::var(super::SOCKET_ENV) {
            return PathBuf::from(s);
        }
    }
    PathBuf::from(super::SOCKET_PATH)
}

struct Link {
    r: BufReader<UnixStream>,
    w: UnixStream,
}

/// The door is shut or the dashboard is not there; the words are for the person.
struct Shut(String);

pub struct Bridge {
    socket: PathBuf,
    link: Option<Link>,
    /// The token, when it ends, and how long before that it is renewed (a short token, such as one that ends with standing
    /// permission, is renewed late, so a bridge never enrols on every call).
    token: Option<(String, u64, u64)>,
    /// The short code the dashboard gave this session. The person's approval card shows the same code.
    code: Option<String>,
    now: fn() -> u64,
}

impl Bridge {
    pub fn new(socket: &Path, now: fn() -> u64) -> Bridge {
        Bridge {
            socket: socket.to_path_buf(),
            link: None,
            token: None,
            code: None,
            now,
        }
    }

    fn connect(&mut self) -> Result<&mut Link, Shut> {
        if self.link.is_none() {
            let s = UnixStream::connect(&self.socket).map_err(|_| {
                Shut("the Oz Box dashboard on this box is not answering (is it running? `systemctl status ozbox-dashboard`)".into())
            })?;
            let r = s
                .try_clone()
                .map_err(|_| Shut("the Oz Box dashboard's socket could not be used".into()))?;
            self.link = Some(Link {
                r: BufReader::new(r),
                w: s,
            });
        }
        self.link
            .as_mut()
            .ok_or_else(|| Shut("no connection".into()))
    }

    /// One request and its answer on the open connection; a broken connection is made again once.
    fn exchange(
        &mut self,
        path: &str,
        headers: &[(&str, &str)],
        body: &[u8],
    ) -> Result<(u16, Vec<u8>), Shut> {
        for attempt in 0..2 {
            let l = self.connect()?;
            let sent = http::write_request(&mut l.w, "POST", path, headers, body).is_ok();
            let got = if sent {
                http::read_response(&mut l.r, MAX_ANSWER).ok()
            } else {
                None
            };
            match got {
                Some(r) => return Ok(r),
                None => {
                    self.link = None;
                    if attempt == 1 {
                        break;
                    }
                }
            }
        }
        Err(Shut("the Oz Box dashboard on this box stopped answering (it is restarting, or this program is not the box's own user, whose connection is closed without an answer)".into()))
    }

    fn enrol(&mut self) -> Result<(), Shut> {
        let (status, body) =
            self.exchange("/v1/enrol", &[("Content-Type", "application/json")], b"{}")?;
        let v: Value = serde_json::from_slice(&body).unwrap_or(Value::Null);
        if status != 200 {
            let why = v["error"]
                .as_str()
                .unwrap_or("the dashboard did not give this agent a session");
            return Err(Shut(why.to_string()));
        }
        match (v["token"].as_str(), v["expires_ms"].as_u64()) {
            (Some(t), Some(e)) => {
                let renew = RENEW_BEFORE_MS.min(e.saturating_sub((self.now)()) / 4);
                self.token = Some((t.to_string(), e, renew));
                let code = v["code"].as_str().map(str::to_string);
                if code.is_some() && code != self.code {
                    // for the engine's own log, which is the other place a person can read it
                    eprintln!("{}", code_sentence(code.as_deref().unwrap_or("")));
                }
                self.code = code;
                Ok(())
            }
            _ => Err(Shut("the dashboard's answer was not understood".into())),
        }
    }

    fn token(&mut self) -> Result<String, Shut> {
        let fresh = self
            .token
            .as_ref()
            .is_some_and(|(_, exp, renew)| exp.saturating_sub((self.now)()) > *renew);
        if !fresh {
            self.enrol()?;
        }
        self.token
            .as_ref()
            .map(|(t, _, _)| t.clone())
            .ok_or_else(|| Shut("no session".into()))
    }

    /// The handshake's answer with this session's code added to the server's instructions, so the engine can show it.
    fn with_code(&self, body: Vec<u8>) -> Vec<u8> {
        let Some(code) = self.code.as_deref() else {
            return body;
        };
        let Ok(mut v) = serde_json::from_slice::<Value>(&body) else {
            return body;
        };
        let Some(r) = v.get_mut("result").and_then(Value::as_object_mut) else {
            return body;
        };
        let said = r
            .get("instructions")
            .and_then(Value::as_str)
            .unwrap_or("")
            .to_string();
        let joined = if said.is_empty() {
            code_sentence(code)
        } else {
            format!("{said}\n\n{}", code_sentence(code))
        };
        r.insert("instructions".into(), Value::String(joined));
        serde_json::to_vec(&v).unwrap_or(body)
    }

    /// Relay one JSON-RPC message; `Some(body)` is the answer to write, `None` means nothing is written (a notification).
    fn relay(&mut self, msg: &Value, raw: &[u8]) -> Result<Option<Vec<u8>>, Shut> {
        for attempt in 0..2 {
            let token = self.token()?;
            let auth = format!("Bearer {token}");
            let (status, body) = self.exchange(
                "/mcp",
                &[
                    ("Authorization", &auth),
                    ("Content-Type", "application/json"),
                    ("Accept", "application/json"),
                ],
                raw,
            )?;
            match status {
                401 if attempt == 0 => {
                    self.token = None;
                    continue;
                }
                403 => {
                    let v: Value = serde_json::from_slice(&body).unwrap_or(Value::Null);
                    self.token = None;
                    return Err(Shut(
                        v["error"]
                            .as_str()
                            .unwrap_or("this agent may not use the Oz Box tools")
                            .to_string(),
                    ));
                }
                202 => return Ok(None),
                _ => {}
            }
            if msg.get("id").is_none() {
                return Ok(None);
            }
            if status == 200 && msg.get("method").and_then(Value::as_str) == Some("initialize") {
                return Ok(Some(self.with_code(body)));
            }
            return Ok(Some(body));
        }
        Err(Shut(
            "the dashboard would not give this agent a session".into(),
        ))
    }
}

/// What a person is told so they can match their engine with the card that asks them to approve something.
fn code_sentence(code: &str) -> String {
    format!("Oz Box session code {code}: the approval card for a call from this program, and the answer to a call that is waiting for approval, show the same code.")
}

fn rpc_error(id: &Value, code: i64, message: &str) -> Vec<u8> {
    json!({ "jsonrpc": "2.0", "id": id, "error": { "code": code, "message": message } })
        .to_string()
        .into_bytes()
}

/// What the bridge says for itself while the door is shut: the handshake works, there are no tools, and the reason is in
/// the instructions and in the answer to any call.
fn shut_answer(msg: &Value, why: &str) -> Option<Vec<u8>> {
    let id = msg.get("id")?.clone();
    let result = match msg.get("method").and_then(Value::as_str) {
        Some("initialize") => {
            let asked = msg
                .pointer("/params/protocolVersion")
                .and_then(Value::as_str)
                .unwrap_or("");
            let v = if crate::mcp::SUPPORTED.contains(&asked) {
                asked
            } else {
                crate::mcp::SUPPORTED[0]
            };
            json!({ "protocolVersion": v, "capabilities": { "tools": { "listChanged": false } },
                    "serverInfo": { "name": "ozbox", "version": env!("CARGO_PKG_VERSION") },
                    "instructions": format!("The Oz Box tools are not available right now: {why}") })
        }
        Some("tools/list") => json!({ "tools": [] }),
        Some("ping") => json!({}),
        _ => {
            return Some(rpc_error(
                &id,
                -32000,
                &format!("The Oz Box tools are not available right now: {why}"),
            ))
        }
    };
    Some(
        json!({ "jsonrpc": "2.0", "id": id, "result": result })
            .to_string()
            .into_bytes(),
    )
}

/// Run until `input` ends: one message on each line.
pub fn run<R: BufRead, W: Write>(
    socket: &Path,
    now: fn() -> u64,
    input: R,
    mut output: W,
) -> std::io::Result<()> {
    let mut b = Bridge::new(socket, now);
    for line in input.lines() {
        let line = line?;
        let t = line.trim();
        if t.is_empty() {
            continue;
        }
        let answer = match serde_json::from_str::<Value>(t) {
            Ok(msg) if msg.is_object() => match b.relay(&msg, t.as_bytes()) {
                Ok(a) => a,
                Err(Shut(why)) => shut_answer(&msg, &why),
            },
            _ => Some(rpc_error(
                &Value::Null,
                -32700,
                "send one JSON-RPC message per line",
            )),
        };
        if let Some(a) = answer {
            output.write_all(&a)?;
            output.write_all(b"\n")?;
            output.flush()?;
        }
    }
    Ok(())
}
