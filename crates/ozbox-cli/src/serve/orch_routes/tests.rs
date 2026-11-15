#![allow(clippy::unwrap_used)]

use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};

use ozbox_core::{BoxName, BoxSpec, Provider, Size};

use super::*;

const TOKEN: &str = "test-token";

fn app(dir: &std::path::Path) -> App {
    let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 7878);
    let p = ozbox_provider_fake::open(dir);
    for (n, size) in [("alpha", Size::S), ("bravo", Size::M), ("charlie", Size::M)] {
        let spec = BoxSpec::new(BoxName::new(n).unwrap(), size);
        let provider: &dyn Provider = &p;
        let plan = provider
            .plan(&ozbox_core::Operation::Create { spec })
            .unwrap();
        provider.apply(&plan).unwrap();
    }
    App::new(Box::new(p), true, addr, TOKEN.into()).with_task_store(Some(dir.join("tasks.json")))
}

fn req(method: &str, path: &str, body: Value) -> Req {
    let (p, q) = path.split_once('?').unwrap_or((path, ""));
    let mut headers = HashMap::new();
    headers.insert("host".to_string(), "127.0.0.1:7878".to_string());
    headers.insert("authorization".to_string(), format!("Bearer {TOKEN}"));
    Req {
        method: method.into(),
        path: p.into(),
        query: q.into(),
        headers,
        body: if body.is_null() {
            Vec::new()
        } else {
            body.to_string().into_bytes()
        },
    }
}

fn call(a: &mut App, method: &str, path: &str, body: Value) -> (u16, Value) {
    let r = a.handle(&req(method, path, body));
    (
        r.status,
        serde_json::from_slice(&r.body).unwrap_or(Value::Null),
    )
}

fn tick(a: &mut App, from: u64, n: u64) {
    for i in 0..n {
        a.orch.next_tick_ms = 0;
        a.runs.next_tick_ms = 0;
        a.tick_orchestrations(from + i * 1000);
        a.tick_runs(from + i * 1000);
    }
}

fn started(a: &mut App, rules: &str) -> String {
    let (st, v) = call(
        a,
        "POST",
        "/v1/orchestrations",
        json!({ "goal": "ship the thing", "conductor_box": "alpha", "rules": rules }),
    );
    assert_eq!(st, 201, "{v}");
    v["id"].as_str().unwrap().to_string()
}

const FAKE: &str =
    "---\nengine: fake\nmerge_approval: person\ntest_command: make test\n---\nSmall commits.";

#[test]
fn start_list_show_and_the_limits_a_request_cannot_loosen() {
    let dir = tempfile::tempdir().unwrap();
    let mut a = app(dir.path());
    assert_eq!(
        call(&mut a, "GET", "/v1/orchestrations", Value::Null).1["items"]
            .as_array()
            .unwrap()
            .len(),
        0
    );
    let (st, _) = call(
        &mut a,
        "POST",
        "/v1/orchestrations",
        json!({ "goal": "x", "conductor_box": "ghost" }),
    );
    assert_eq!(st, 404);
    let (st, _) = call(
        &mut a,
        "POST",
        "/v1/orchestrations",
        json!({ "conductor_box": "alpha" }),
    );
    assert_eq!(st, 400);
    let (st, v) = call(
        &mut a,
        "POST",
        "/v1/orchestrations",
        json!({ "goal": "x", "conductor_box": "alpha", "rules": "---\nnonsense: 1\n---\n" }),
    );
    assert_eq!((st, v["code"].as_str()), (400, Some("bad_request")));
    let id = started(&mut a, FAKE);
    let (_, v) = call(&mut a, "GET", "/v1/orchestrations", Value::Null);
    assert_eq!(v["items"][0]["id"], id.as_str());
    assert_eq!(v["items"][0]["state"], "active");
    let (st, d) = call(
        &mut a,
        "GET",
        &format!("/v1/orchestrations/{id}"),
        Value::Null,
    );
    assert_eq!(st, 200);
    assert_eq!(d["policy"]["max_workers"], 3);
    assert_eq!(d["policy"]["test_command"], json!(["make", "test"]));
    assert_eq!(
        call(&mut a, "GET", "/v1/orchestrations/nope", Value::Null).0,
        404
    );
    // the person's settings are the ceiling
    let (st, s) = call(&mut a, "GET", "/v1/orchestrations/settings", Value::Null);
    assert_eq!((st, s["max_workers"].clone()), (200, json!(3)));
    let (st, _) = call(
        &mut a,
        "PUT",
        "/v1/orchestrations/settings",
        json!({ "max_workers": 0 }),
    );
    assert_eq!(st, 400);
    let (st, c) = call(
        &mut a,
        "POST",
        "/v1/orchestrations/rules/check",
        json!({ "rules": "---\nmax_workers: 9\nmax_sub_agents: 2\n---\n" }),
    );
    assert_eq!(st, 200);
    assert_eq!(
        (c["max_workers"].clone(), c["max_sub_agents"].clone()),
        (json!(3), json!(2))
    );
    assert!(!c["notes"].as_array().unwrap().is_empty());
}

#[test]
fn a_feature_runs_on_its_box_is_merged_after_the_person_approves_and_its_box_is_paused() {
    let dir = tempfile::tempdir().unwrap();
    let mut a = app(dir.path());
    let id = started(&mut a, FAKE);
    // bravo was made for this orchestration (as box_clone does), so it is the orchestration's to pause
    a.runs
        .store
        .clone()
        .unwrap()
        .update(|b| {
            b.orchestration_mut(&id)
                .unwrap()
                .spare_boxes
                .push("bravo".into())
        })
        .unwrap();
    let (st, f) = call(
        &mut a,
        "POST",
        &format!("/v1/orchestrations/{id}/features"),
        json!({ "title": "Users API", "brief": "build it sim:steps=2", "box": "bravo", "claims": ["src/api"] }),
    );
    assert_eq!(st, 200, "{f}");
    assert_eq!(f["feature"], "f1");
    // another feature may not take an overlapping area, or the conductor's own box
    let (st, _) = call(
        &mut a,
        "POST",
        &format!("/v1/orchestrations/{id}/features"),
        json!({ "title": "b", "brief": "x", "box": "charlie", "claims": ["src/api/users"] }),
    );
    assert_eq!(st, 409);
    let (st, _) = call(
        &mut a,
        "POST",
        &format!("/v1/orchestrations/{id}/features"),
        json!({ "title": "b", "brief": "x", "box": "alpha" }),
    );
    assert_eq!(st, 400);
    // the worker's task is queued for bravo, runs and ends; the feature is then ready to merge
    tick(&mut a, 1_000, 12);
    let d = call(
        &mut a,
        "GET",
        &format!("/v1/orchestrations/{id}"),
        Value::Null,
    )
    .1;
    assert_eq!(d["features"][0]["state"], "ready_to_merge", "{d}");
    let tid = d["features"][0]["task_id"].as_str().unwrap().to_string();
    let t = call(&mut a, "GET", &format!("/v1/tasks/{tid}"), Value::Null).1;
    assert_eq!(t["box"], "bravo");
    assert_eq!(t["branch"], "orch/o1/users-api");
    assert_eq!(t["origin"]["kind"], "orchestration");
    // queue it: rebased and tested (simulated), then it waits for the person
    let (st, q) = call(
        &mut a,
        "POST",
        &format!("/v1/orchestrations/{id}/merge/f1"),
        Value::Null,
    );
    assert_eq!((st, q["position"].clone()), (200, json!(1)));
    tick(&mut a, 20_000, 6);
    let d = call(
        &mut a,
        "GET",
        &format!("/v1/orchestrations/{id}"),
        Value::Null,
    )
    .1;
    assert_eq!(d["merge_queue"][0]["state"], "awaiting_approval");
    assert_eq!(d["approvals"][0]["needs_person"], true);
    assert_eq!(
        d["approvals"][0]["action"],
        "merge orch/o1/users-api into main"
    );
    let aid = d["approvals"][0]["id"].as_str().unwrap().to_string();
    let (st, _) = call(
        &mut a,
        "POST",
        &format!("/v1/approval-requests/{aid}/approve"),
        Value::Null,
    );
    assert_eq!(st, 200);
    tick(&mut a, 30_000, 6);
    let d = call(
        &mut a,
        "GET",
        &format!("/v1/orchestrations/{id}"),
        Value::Null,
    )
    .1;
    assert_eq!(d["features"][0]["state"], "merged");
    assert_eq!(d["state"], "done");
    // the merged feature's worker box was paused by plan-then-apply on the server's own provider
    let b = call(&mut a, "GET", "/v1/boxes/bravo", Value::Null).1;
    assert_eq!(b["state"], "paused");
    // the audit trail has the orchestration's steps
    let act = call(&mut a, "GET", "/v1/activity", Value::Null)
        .1
        .to_string();
    assert!(act.contains("orchestration.merged"), "{act}");
}

#[test]
fn the_person_answers_a_question_pauses_and_resumes_and_adds_budget() {
    let dir = tempfile::tempdir().unwrap();
    let mut a = app(dir.path());
    let id = started(&mut a, FAKE);
    call(
        &mut a,
        "POST",
        &format!("/v1/orchestrations/{id}/features"),
        json!({ "title": "a", "brief": "x sim:steps=1000", "box": "bravo", "claims": ["src/a"] }),
    );
    tick(&mut a, 1_000, 3);
    // a worker asks the person
    let store = a.runs.store.clone().unwrap();
    store
        .update(|b| {
            b.orchestration_mut(&id)
                .unwrap()
                .post(
                    5,
                    "feature:f1",
                    "person",
                    ozbox_core::orch::MsgKind::Question,
                    "drop the table?",
                    None,
                    true,
                )
                .unwrap();
        })
        .unwrap();
    let d = call(
        &mut a,
        "GET",
        &format!("/v1/orchestrations/{id}"),
        Value::Null,
    )
    .1;
    assert_eq!(d["open_questions"][0]["needs_person"], true);
    assert_eq!(
        call(&mut a, "GET", "/v1/orchestrations", Value::Null).1["items"][0]["needs_you"],
        true
    );
    let q = d["open_questions"][0]["seq"].as_u64().unwrap();
    let (st, _) = call(
        &mut a,
        "POST",
        &format!("/v1/orchestrations/{id}/answer"),
        json!({ "question": q, "text": "no" }),
    );
    assert_eq!(st, 200);
    assert_eq!(
        call(
            &mut a,
            "POST",
            &format!("/v1/orchestrations/{id}/answer"),
            json!({ "question": q, "text": "no" })
        )
        .0,
        409
    );
    let (st, _) = call(
        &mut a,
        "POST",
        &format!("/v1/orchestrations/{id}/message"),
        json!({ "feature": "f1", "text": "use postgres" }),
    );
    assert_eq!(st, 200);
    // pause: the worker is asked to stop (its work is saved first), and nothing new starts
    assert_eq!(
        call(
            &mut a,
            "POST",
            &format!("/v1/orchestrations/{id}/pause"),
            Value::Null
        )
        .0,
        200
    );
    let d = call(
        &mut a,
        "GET",
        &format!("/v1/orchestrations/{id}"),
        Value::Null,
    )
    .1;
    assert_eq!(
        (d["state"].clone(), d["features"][0]["state"].clone()),
        (json!("paused"), json!("paused"))
    );
    tick(&mut a, 10_000, 4);
    assert_eq!(
        call(
            &mut a,
            "POST",
            &format!("/v1/orchestrations/{id}/resume"),
            Value::Null
        )
        .0,
        200
    );
    let d = call(
        &mut a,
        "GET",
        &format!("/v1/orchestrations/{id}"),
        Value::Null,
    )
    .1;
    assert_eq!(d["state"], "active");
    let t = d["features"][0]["task_id"].as_str().unwrap().to_string();
    let task = call(&mut a, "GET", &format!("/v1/tasks/{t}"), Value::Null).1;
    assert_eq!(
        task["branch"], "orch/o1/a",
        "it continues on its own branch"
    );
    let (st, b) = call(
        &mut a,
        "POST",
        &format!("/v1/orchestrations/{id}/budget"),
        json!({ "add_usd": 10 }),
    );
    assert_eq!((st, b["cap_cents"].clone()), (200, json!(6000)));
    assert_eq!(
        call(
            &mut a,
            "POST",
            &format!("/v1/orchestrations/{id}/budget"),
            json!({ "add_usd": -1 })
        )
        .0,
        400
    );
    assert_eq!(
        call(
            &mut a,
            "POST",
            &format!("/v1/orchestrations/{id}/stop"),
            Value::Null
        )
        .0,
        200
    );
    assert_eq!(
        call(
            &mut a,
            "POST",
            &format!("/v1/orchestrations/{id}/resume"),
            Value::Null
        )
        .0,
        409
    );
}

#[test]
fn the_person_agent_token_reaches_the_tools_over_a_real_loopback_socket_and_runs_get_their_own() {
    use std::io::{Read as _, Write as _};
    let dir = tempfile::tempdir().unwrap();
    let mut a = app(dir.path());
    let id = started(&mut a, FAKE);
    let (st, t) = call(&mut a, "POST", "/v1/orchestrations/mcp-token", Value::Null);
    assert_eq!(st, 200, "{t}");
    let (url, token) = (
        t["url"].as_str().unwrap().to_string(),
        t["token"].as_str().unwrap().to_string(),
    );
    assert!(url.starts_with("http://127.0.0.1:") && token.starts_with("ozmt_"));
    let port: u16 = url
        .trim_start_matches("http://127.0.0.1:")
        .trim_end_matches("/mcp")
        .parse()
        .unwrap();
    let rpc = |a: &mut App, body: Value| -> Value {
        // the tool threads wait for the request loop for box jobs: answer them while the call is in flight
        let b = body.to_string();
        let token = token.clone();
        let h = std::thread::spawn(move || {
            let mut c = std::net::TcpStream::connect(("127.0.0.1", port)).unwrap();
            write!(c, "POST /mcp HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\nAuthorization: Bearer {token}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{b}", b.len()).unwrap();
            let mut out = String::new();
            c.read_to_string(&mut out).unwrap();
            out
        });
        for _ in 0..200 {
            a.orch.next_tick_ms = 0;
            a.tick_orchestrations(5_000);
            if h.is_finished() {
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(20));
        }
        let out = h.join().unwrap();
        serde_json::from_str(out.split("\r\n\r\n").nth(1).unwrap()).unwrap()
    };
    let l = rpc(
        &mut a,
        json!({ "jsonrpc": "2.0", "id": 1, "method": "tools/list" }),
    );
    // the 18 orchestration tools, the 5 memory and skills tools, and the host and browser tools of a person's own agent
    assert_eq!(
        l["result"]["tools"].as_array().unwrap().len(),
        23 + crate::host_tools::TOOLS.len() + crate::browser_tools::BROWSER_TOOLS.len()
    );
    // a box tool goes through the server's own plan-then-apply: a clone is made, inside the limits
    let c = rpc(
        &mut a,
        json!({ "jsonrpc": "2.0", "id": 2, "method": "tools/call", "params": { "name": "box_clone", "arguments": { "orchestration": id, "to": "worker-a" } } }),
    );
    assert_eq!(c["result"]["isError"], false, "{c}");
    let boxes = call(&mut a, "GET", "/v1/boxes", Value::Null).1;
    assert!(boxes
        .as_array()
        .unwrap()
        .iter()
        .any(|b| b["spec"]["name"] == "worker-a"));
    let s = rpc(
        &mut a,
        json!({ "jsonrpc": "2.0", "id": 3, "method": "tools/call", "params": { "name": "task_start", "arguments": { "orchestration": id, "title": "a", "brief": "x", "box": "worker-a", "claims": ["src/a"], "engine": "fake" } } }),
    );
    assert_eq!(s["result"]["isError"], false, "{s}");
    // a worker run is handed an address and a token bound to it, and the token dies with the run
    let m = a.orch.mcp.clone().unwrap();
    tick(&mut a, 6_000, 2);
    let book = a.runs.store.clone().unwrap().load().unwrap();
    let tid = book
        .orchestration(&id)
        .unwrap()
        .feature("f1")
        .unwrap()
        .task_id
        .clone()
        .unwrap();
    assert!(m.holds_token_for(&tid) || book.task(&tid).unwrap().state.is_terminal());
    tick(&mut a, 7_000, 12);
    assert!(
        !m.holds_token_for(&tid),
        "the token is revoked when the run ends"
    );
}

#[test]
fn a_persons_own_agent_can_start_its_first_orchestration_and_list_boxes_when_nothing_is_open() {
    use std::io::{Read as _, Write as _};
    let dir = tempfile::tempdir().unwrap();
    let mut a = app(dir.path());
    // the token is made before any orchestration exists
    let (st, t) = call(&mut a, "POST", "/v1/orchestrations/mcp-token", Value::Null);
    assert_eq!(st, 200, "{t}");
    let (url, token) = (
        t["url"].as_str().unwrap().to_string(),
        t["token"].as_str().unwrap().to_string(),
    );
    let port: u16 = url
        .trim_start_matches("http://127.0.0.1:")
        .trim_end_matches("/mcp")
        .parse()
        .unwrap();
    let rpc = |a: &mut App, body: Value| -> Value {
        let b = body.to_string();
        let token = token.clone();
        let h = std::thread::spawn(move || {
            let mut c = std::net::TcpStream::connect(("127.0.0.1", port)).unwrap();
            write!(c, "POST /mcp HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\nAuthorization: Bearer {token}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{b}", b.len()).unwrap();
            let mut out = String::new();
            c.read_to_string(&mut out).unwrap();
            out
        });
        for _ in 0..200 {
            a.orch.next_tick_ms = 0;
            a.tick_orchestrations(5_000);
            if h.is_finished() {
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(20));
        }
        serde_json::from_str(h.join().unwrap().split("\r\n\r\n").nth(1).unwrap()).unwrap()
    };
    let f = rpc(
        &mut a,
        json!({ "jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": { "name": "fleet_boxes", "arguments": {} } }),
    );
    assert_eq!(f["result"]["isError"], false, "{f}");
    assert_eq!(
        f["result"]["structuredContent"]["boxes"]
            .as_array()
            .unwrap()
            .len(),
        3
    );
    let s = rpc(
        &mut a,
        json!({ "jsonrpc": "2.0", "id": 2, "method": "tools/call", "params": { "name": "orchestration_start", "arguments": { "goal": "ship it", "conductor_box": "alpha" } } }),
    );
    assert_eq!(s["result"]["isError"], false, "{s}");
    assert_eq!(
        call(&mut a, "GET", "/v1/orchestrations", Value::Null).1["items"]
            .as_array()
            .unwrap()
            .len(),
        1
    );
}
