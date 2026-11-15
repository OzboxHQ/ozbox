//! An example provider plugin: boxes are records in `state.json` beside the program. It makes nothing real; it shows the
//! shape of the protocol (ADR 0031, docs/plugins.md). Build it, put it in a folder with `plugin.toml`, and run
//! `ozbox plugin add <folder>`.

use ozbox_plugin::{sdk, Failure};
use serde_json::{json, Value};

const STATE: &str = "state.json";

fn load() -> Vec<Value> {
    std::fs::read_to_string(STATE)
        .ok()
        .and_then(|t| serde_json::from_str(&t).ok())
        .unwrap_or_default()
}

fn save(v: &[Value]) -> Result<(), Failure> {
    std::fs::write(STATE, serde_json::to_string(v).unwrap_or_default())
        .map_err(|_| Failure::new("failed", "the state file could not be written"))
}

fn name_of(rec: &Value) -> String {
    rec["spec"]["name"].as_str().unwrap_or("").to_string()
}

fn set_state(name: &str, f: impl Fn(&mut Value)) -> Result<Value, Failure> {
    let mut all = load();
    let rec = all
        .iter_mut()
        .find(|r| name_of(r) == name)
        .ok_or_else(|| Failure::new("not_found", name.to_string()))?;
    f(rec);
    let out = rec.clone();
    save(&all)?;
    Ok(out)
}

fn main() {
    sdk::serve(|op, args| match op {
        "describe" => Ok(json!({
            "id": "dirfake",
            "capabilities": {
                "resize": "power_off_resize",
                "online_disk_grow": true,
                "disk_shrink": false,
                "snapshots": true,
                "sizes": ["S", "M", "L", "XL", "XXL"]
            }
        })),
        "machine_choice" => Ok(
            json!({ "machine_type": format!("dir-{}", args["size"].as_str().unwrap_or("M")), "note": null }),
        ),
        "list" => Ok(Value::Array(load())),
        "create" => {
            let mut all = load();
            let mut rec = json!({
                "spec": args["spec"],
                "state": "running",
                "provider": "dirfake",
                "provider_id": name_of(&json!({"spec": args["spec"]})),
                "machine_type": args["machine_type"],
                "snapshots": [],
                "created_at": null,
                "last_activity_at": null
            });
            rec["spec"]["labels"] = args["spec"]["labels"].clone();
            all.push(rec.clone());
            save(&all)?;
            Ok(rec)
        }
        "destroy" => {
            let n = name_of(&args["record"]);
            let all: Vec<Value> = load().into_iter().filter(|r| name_of(r) != n).collect();
            save(&all)?;
            Ok(Value::Null)
        }
        "power_off" => set_state(&name_of(&args["record"]), |r| r["state"] = json!("paused"))
            .map(|_| Value::Null),
        "power_on" => set_state(&name_of(&args["record"]), |r| r["state"] = json!("running"))
            .map(|_| Value::Null),
        "set_size" => {
            let (size, mt) = (args["size"].clone(), args["machine_type"].clone());
            set_state(&name_of(&args["record"]), |r| {
                r["spec"]["size"] = size.clone();
                r["machine_type"] = mt.clone();
            })
            .map(|_| Value::Null)
        }
        "grow_disk" => {
            let gb = args["gb"].clone();
            set_state(&name_of(&args["record"]), |r| {
                r["spec"]["work_disk_gb"] = gb.clone()
            })
            .map(|_| Value::Null)
        }
        "snapshot" => {
            let n = name_of(&args["record"]);
            let rec = set_state(&n, |r| {
                let k = r["snapshots"].as_array().map_or(0, Vec::len) + 1;
                if let Some(a) = r["snapshots"].as_array_mut() {
                    a.push(json!(format!("snap-{k}")));
                }
            })?;
            let id = rec["snapshots"]
                .as_array()
                .and_then(|a| a.last())
                .cloned()
                .unwrap_or(Value::Null);
            Ok(json!({ "id": id }))
        }
        "set_resume_after" => {
            let on = args["on"].as_bool().unwrap_or(false);
            set_state(&name_of(&args["record"]), |r| {
                if on {
                    r["spec"]["labels"]["ozbox-resume-after"] = json!("1");
                } else if let Some(l) = r["spec"]["labels"].as_object_mut() {
                    l.remove("ozbox-resume-after");
                }
            })
            .map(|_| Value::Null)
        }
        _ => Err(Failure::new(
            "unsupported",
            format!("operation {op} is not supported"),
        )),
    });
}
