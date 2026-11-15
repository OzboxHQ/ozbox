//! An example tunnel plugin: it only records that it was started, in `state.json` beside the program. A real tunnel plugin
//! would start and supervise an outbound program here (ADR 0031, docs/plugins.md).

use ozbox_plugin::{sdk, Failure};
use serde_json::{json, Value};

fn state() -> String {
    std::fs::read_to_string("state.json").unwrap_or_else(|_| "stopped".into())
}

fn main() {
    sdk::serve(|op, args| match op {
        "describe" => Ok(json!({ "program": "echo-tunnel", "public": false })),
        "start" => {
            if args["port"].as_u64().unwrap_or(0) < 1024 {
                return Err(Failure::new("bad_request", "the port must be 1024 or more"));
            }
            std::fs::write("state.json", "running").map_err(|_| Failure::new("failed", "state"))?;
            Ok(Value::Null)
        }
        "stop" => {
            std::fs::write("state.json", "stopped").map_err(|_| Failure::new("failed", "state"))?;
            Ok(Value::Null)
        }
        "status" => Ok(json!({ "state": state(), "code": null })),
        "health" => Ok(json!({ "ok": state() == "running", "code": "ok" })),
        _ => Err(Failure::new("unsupported", "unknown operation")),
    });
}
