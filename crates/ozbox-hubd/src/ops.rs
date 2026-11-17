//! The seam to the secrets service: what a channel end may ask of its own service, and two ways of asking.
//!
//! [`SocketKeyOps`] is the real one: one JSON line to the service's socket, one JSON line back (the service's own protocol). Which
//! operations answer depends on which socket it is (see [`crate::keys`]). [`LocalKeyOps`] answers through the very same handler
//! in this process, under a fixed caller: it is what tests use, and it is how a test proves that a socket's gate is the gate.

use std::io::{BufRead, BufReader, Read, Write};
use std::os::unix::net::UnixStream;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use ozbox_core::channel::wire::{hex, unhex};
use serde_json::{json, Value};
use zeroize::Zeroizing;

use crate::identity::Identity;
use crate::keys::{handle, Caller, HubKeys, SignPurpose};

/// Why an operation did not happen. Names what failed; never a value, a key or a plaintext.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OpsError(pub String);

impl std::fmt::Display for OpsError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for OpsError {}

/// What a channel end asks its own secrets service.
pub trait KeyOps: Send + Sync {
    /// This end's public identity.
    fn identity(&self) -> Result<Identity, OpsError>;
    /// A signature over `bytes`, which must begin with the purpose's tag.
    fn sign(&self, purpose: SignPurpose, bytes: &[u8]) -> Result<Vec<u8>, OpsError>;
    /// A body sealed to this end's channel key, opened.
    fn open(&self, aad: &[u8], sealed: &[u8]) -> Result<Zeroizing<Vec<u8>>, OpsError>;
    /// The tag of an enrolment token.
    fn mac(&self, bytes: &[u8]) -> Result<Vec<u8>, OpsError>;
    /// Any other operation the service answers on this socket (`hub_release`, `hub_store_delivery`, ...): the request as one JSON
    /// value, the answer's `result`. A service that does not know the operation says so; no value is in an error.
    fn call(&self, req: Value) -> Result<Value, OpsError>;
}

fn call_result(out: Result<Value, String>) -> Result<Value, OpsError> {
    out.map_err(OpsError)
}

fn field(v: &Value, name: &str) -> Result<Vec<u8>, OpsError> {
    v[name]
        .as_str()
        .and_then(unhex)
        .ok_or_else(|| OpsError("the secrets service's answer is not valid".into()))
}

fn identity_from(v: &Value) -> Result<Identity, OpsError> {
    serde_json::from_value::<Identity>(v["identity"].clone())
        .ok()
        .and_then(|i| i.checked())
        .ok_or_else(|| OpsError("the secrets service's answer is not valid".into()))
}

/// Operations answered by the handler in this process, as one socket's caller would be answered.
pub struct LocalKeyOps {
    pub keys: Arc<HubKeys>,
    pub caller: Caller,
}

impl LocalKeyOps {
    fn ask(&self, req: Value) -> Result<Value, OpsError> {
        call_result(handle(&self.keys, self.caller, &req))
    }
}

impl KeyOps for LocalKeyOps {
    fn identity(&self) -> Result<Identity, OpsError> {
        identity_from(&self.ask(json!({"op": "hub_identity"}))?)
    }
    fn sign(&self, purpose: SignPurpose, bytes: &[u8]) -> Result<Vec<u8>, OpsError> {
        let v =
            self.ask(json!({"op": "hub_sign", "purpose": purpose.word(), "data": hex(bytes)}))?;
        field(&v, "sig")
    }
    fn open(&self, aad: &[u8], sealed: &[u8]) -> Result<Zeroizing<Vec<u8>>, OpsError> {
        let v = self.ask(json!({"op": "hub_open", "aad": hex(aad), "sealed": hex(sealed)}))?;
        field(&v, "plain").map(Zeroizing::new)
    }
    fn mac(&self, bytes: &[u8]) -> Result<Vec<u8>, OpsError> {
        let v = self.ask(json!({"op": "hub_mac", "data": hex(bytes)}))?;
        field(&v, "tag")
    }
    fn call(&self, req: Value) -> Result<Value, OpsError> {
        self.ask(req)
    }
}

/// [`LocalKeyOps`] with the store behind it, so the operations that read or keep values answer too (`handle_with_store`): the
/// way tests, and one process playing both a service and its caller, hold a whole end.
pub struct LocalServiceOps {
    pub keys: Arc<HubKeys>,
    pub store: Arc<dyn crate::keys::KeyStore + Send + Sync>,
    pub caller: Caller,
}

impl LocalServiceOps {
    fn ask(&self, req: Value) -> Result<Value, OpsError> {
        call_result(crate::keys::handle_with_store(
            &self.keys,
            self.store.as_ref(),
            self.caller,
            &req,
        ))
    }
}

impl KeyOps for LocalServiceOps {
    fn identity(&self) -> Result<Identity, OpsError> {
        identity_from(&self.ask(json!({"op": "hub_identity"}))?)
    }
    fn sign(&self, purpose: SignPurpose, bytes: &[u8]) -> Result<Vec<u8>, OpsError> {
        let v =
            self.ask(json!({"op": "hub_sign", "purpose": purpose.word(), "data": hex(bytes)}))?;
        field(&v, "sig")
    }
    fn open(&self, aad: &[u8], sealed: &[u8]) -> Result<Zeroizing<Vec<u8>>, OpsError> {
        let v = self.ask(json!({"op": "hub_open", "aad": hex(aad), "sealed": hex(sealed)}))?;
        field(&v, "plain").map(Zeroizing::new)
    }
    fn mac(&self, bytes: &[u8]) -> Result<Vec<u8>, OpsError> {
        let v = self.ask(json!({"op": "hub_mac", "data": hex(bytes)}))?;
        field(&v, "tag")
    }
    fn call(&self, req: Value) -> Result<Value, OpsError> {
        self.ask(req)
    }
}

/// The real seam: the secrets service's socket. One connection per operation.
pub struct SocketKeyOps {
    pub path: PathBuf,
    pub timeout: Duration,
}

/// The longest answer read from the service.
const MAX_ANSWER: u64 = 2 * 1024 * 1024;

impl SocketKeyOps {
    pub fn new(path: impl Into<PathBuf>) -> SocketKeyOps {
        SocketKeyOps {
            path: path.into(),
            timeout: Duration::from_secs(10),
        }
    }

    fn ask(&self, req: Value) -> Result<Value, OpsError> {
        let unreachable = || OpsError("the secrets service could not be reached".into());
        let mut s = UnixStream::connect(&self.path).map_err(|_| unreachable())?;
        s.set_read_timeout(Some(self.timeout))
            .map_err(|_| unreachable())?;
        s.set_write_timeout(Some(self.timeout))
            .map_err(|_| unreachable())?;
        let mut line = Zeroizing::new(req.to_string());
        line.push('\n');
        s.write_all(line.as_bytes()).map_err(|_| unreachable())?;
        let mut answer = Zeroizing::new(String::new());
        BufReader::new((&s).take(MAX_ANSWER))
            .read_line(&mut answer)
            .map_err(|_| unreachable())?;
        let v: Value = serde_json::from_str(answer.trim_end())
            .map_err(|_| OpsError("the secrets service's answer is not valid".into()))?;
        if v["ok"].as_bool() == Some(true) {
            Ok(v["result"].clone())
        } else {
            // the service's own words, which never carry a value
            Err(OpsError(
                v["error"]
                    .as_str()
                    .unwrap_or("the secrets service refused")
                    .chars()
                    .take(200)
                    .collect(),
            ))
        }
    }
}

impl KeyOps for SocketKeyOps {
    fn identity(&self) -> Result<Identity, OpsError> {
        identity_from(&self.ask(json!({"op": "hub_identity"}))?)
    }
    fn sign(&self, purpose: SignPurpose, bytes: &[u8]) -> Result<Vec<u8>, OpsError> {
        let v =
            self.ask(json!({"op": "hub_sign", "purpose": purpose.word(), "data": hex(bytes)}))?;
        field(&v, "sig")
    }
    fn open(&self, aad: &[u8], sealed: &[u8]) -> Result<Zeroizing<Vec<u8>>, OpsError> {
        let v = self.ask(json!({"op": "hub_open", "aad": hex(aad), "sealed": hex(sealed)}))?;
        field(&v, "plain").map(Zeroizing::new)
    }
    fn mac(&self, bytes: &[u8]) -> Result<Vec<u8>, OpsError> {
        let v = self.ask(json!({"op": "hub_mac", "data": hex(bytes)}))?;
        field(&v, "tag")
    }
    fn call(&self, req: Value) -> Result<Value, OpsError> {
        self.ask(req)
    }
}
