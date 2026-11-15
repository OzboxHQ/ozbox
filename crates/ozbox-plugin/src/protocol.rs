//! The wire types. Within `api_version` 1 a field is only ever added, and an unknown field is ignored on both sides.

use serde::{Deserialize, Serialize};
use serde_json::Value;

/// The protocol version this crate speaks.
pub const API_VERSION: u32 = 1;

/// The most the host reads from a plugin in one line, and the most it sends one.
pub const MAX_MESSAGE: usize = 1 << 20;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Kind {
    Provider,
    Tunnel,
}

/// `plugin.toml`, in the plugin's folder.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Manifest {
    /// Lowercase letters, digits and hyphens, at most 32.
    pub name: String,
    pub kind: Kind,
    pub api_version: u32,
    /// The program's file name inside the folder (no path).
    pub program: String,
    /// The author's licence, an SPDX identifier or expression (`Apache-2.0`, `MIT OR Apache-2.0`). Required: it is shown
    /// before a plugin is added or approved. The author chooses it; the plugins bundled with Oz Box are Apache-2.0.
    pub license: String,
    #[serde(default)]
    pub description: String,
}

impl Manifest {
    pub fn check(&self) -> Result<(), &'static str> {
        let name_ok = !self.name.is_empty()
            && self.name.len() <= 32
            && self.name.starts_with(|c: char| c.is_ascii_lowercase())
            && self
                .name
                .bytes()
                .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-');
        if !name_ok {
            return Err("the plugin name must be lowercase letters, digits and hyphens");
        }
        if self.api_version != API_VERSION {
            return Err("this plugin speaks a protocol version this program does not");
        }
        let prog_ok = !self.program.is_empty()
            && self.program.len() <= 64
            && !self.program.starts_with(['.', '-'])
            && self
                .program
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-'));
        if !prog_ok {
            return Err("the program must be a plain file name inside the plugin's folder");
        }
        let lic = self.license.trim();
        let lic_ok = !lic.is_empty()
            && lic.len() <= 64
            && lic.bytes().all(|b| {
                b.is_ascii_alphanumeric() || matches!(b, b'.' | b'-' | b'+' | b' ' | b'(' | b')')
            });
        if !lic_ok {
            return Err("plugin.toml needs a license: an SPDX identifier such as Apache-2.0");
        }
        Ok(())
    }
}

/// A JSON-RPC 2.0 request, one per line.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Request {
    pub jsonrpc: String,
    pub id: u64,
    pub method: String,
    #[serde(default)]
    pub params: Value,
}

impl Request {
    pub fn new(id: u64, method: &str, params: Value) -> Self {
        Request {
            jsonrpc: "2.0".into(),
            id,
            method: method.to_string(),
            params,
        }
    }
}

/// Why a call failed. `code` is one of `unsupported`, `not_found`, `already_exists`, `invalid_state`, `bad_request` or
/// `failed`; the message is for a person, and must never contain a secret. On the wire it is a JSON-RPC error: the
/// number is the standard one for the kind, and the word is in `data.kind`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Failure {
    pub code: String,
    pub message: String,
}

impl Failure {
    pub fn new(code: &str, message: impl Into<String>) -> Self {
        Failure {
            code: code.to_string(),
            message: message.into(),
        }
    }

    fn number(&self) -> i64 {
        match self.code.as_str() {
            "unsupported" => -32601,
            "bad_request" => -32602,
            "not_found" => -32001,
            "already_exists" => -32002,
            "invalid_state" => -32003,
            _ => -32000,
        }
    }

    fn to_wire(&self) -> Value {
        serde_json::json!({ "code": self.number(), "message": self.message, "data": { "kind": self.code } })
    }

    fn from_wire(v: &Value) -> Failure {
        let kind = v["data"]["kind"]
            .as_str()
            .map(String::from)
            .unwrap_or_else(|| {
                match v["code"].as_i64() {
                    Some(-32601) => "unsupported",
                    Some(-32602) => "bad_request",
                    Some(-32001) => "not_found",
                    Some(-32002) => "already_exists",
                    Some(-32003) => "invalid_state",
                    _ => "failed",
                }
                .to_string()
            });
        Failure {
            code: kind,
            message: v["message"]
                .as_str()
                .unwrap_or("the plugin failed")
                .to_string(),
        }
    }
}

/// A JSON-RPC 2.0 response: exactly one of `result` and `error`.
#[derive(Debug, Clone, PartialEq)]
pub struct Response {
    pub id: u64,
    pub outcome: Result<Value, Failure>,
}

impl Response {
    pub fn success(id: u64, result: Value) -> Self {
        Response {
            id,
            outcome: Ok(result),
        }
    }
    pub fn failure(id: u64, f: Failure) -> Self {
        Response {
            id,
            outcome: Err(f),
        }
    }

    pub fn to_line(&self) -> String {
        let v = match &self.outcome {
            Ok(r) => serde_json::json!({ "jsonrpc": "2.0", "id": self.id, "result": r }),
            Err(f) => serde_json::json!({ "jsonrpc": "2.0", "id": self.id, "error": f.to_wire() }),
        };
        v.to_string()
    }

    pub fn from_line(line: &str) -> Option<Response> {
        let v: Value = serde_json::from_str(line).ok()?;
        if v["jsonrpc"].as_str() != Some("2.0") {
            return None;
        }
        let id = v["id"].as_u64()?;
        let outcome = match (v.get("result"), v.get("error")) {
            (Some(r), None) => Ok(r.clone()),
            (None, Some(e)) => Err(Failure::from_wire(e)),
            _ => return None,
        };
        Some(Response { id, outcome })
    }
}

// ---- Provider operations (kind = provider). Records use the same JSON as `ozbox_core::BoxSpec` / `BoxRecord`. ----
//
// Methods: `initialize` (below) first, then:
//   describe         {}                                        -> { "id": "...", "capabilities": { ... } }
//   machine_choice   { "size": "M" }                           -> { "machine_type": "...", "note": null }
//   list             {}                                        -> [ BoxRecord ]
//   create           { "spec": BoxSpec, "machine_type": "..." } -> BoxRecord
//   destroy          { "record": BoxRecord }                   -> null
//   power_off        { "record": BoxRecord }                   -> null
//   power_on         { "record": BoxRecord }                   -> null
//   set_size         { "record": BoxRecord, "size": "L", "machine_type": "..." } -> null
//   grow_disk        { "record": BoxRecord, "gb": 300 }        -> null
//   snapshot         { "record": BoxRecord }                   -> { "id": "..." }
//   set_resume_after { "record": BoxRecord, "on": true }       -> null
//
// ---- Tunnel operations (kind = tunnel) ----
//
//   describe         {}                                        -> { "program": "...", "public": true }
//   start            { "port": 7878, "public_url": "https://..." } -> null
//   stop             {}                                        -> null
//   status           {}                                        -> { "state": "stopped|running|failed", "code": null }
//   health           { "public_url": "https://..." }           -> { "ok": true, "code": "ok" }

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MachineChoiceWire {
    pub machine_type: String,
    #[serde(default)]
    pub note: Option<String>,
}
