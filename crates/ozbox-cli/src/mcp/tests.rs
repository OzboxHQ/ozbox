#![allow(clippy::unwrap_used)]

use super::*;

struct Echo;

impl ToolRunner for Echo {
    fn run(&self, s: &Session, name: &str, args: &Value, _: u64) -> Result<Value, ToolError> {
        if name == "budget_status" && args.get("fail").is_some() {
            return Err(ToolError::Refused("no".into()));
        }
        Ok(json!({ "tool": name, "role": format!("{:?}", s.role), "args": args }))
    }
}

const PORT: u16 = 4999;

fn server() -> McpServer {
    McpServer::new(Arc::new(Echo), PORT)
}

fn conductor() -> Session {
    Session {
        person: "ada".into(),
        role: Role::Conductor { orch: "o1".into() },
    }
}

fn worker() -> Session {
    Session {
        person: "ada".into(),
        role: Role::Worker {
            orch: "o1".into(),
            feature: "f1".into(),
        },
    }
}

fn post(token: Option<&str>, extra: &[(&str, &str)], body: &Value) -> ProxyRequest {
    let mut headers = vec![
        ("Host".to_string(), format!("127.0.0.1:{PORT}")),
        ("Content-Type".to_string(), "application/json".to_string()),
    ];
    if let Some(t) = token {
        headers.push(("Authorization".into(), format!("Bearer {t}")));
    }
    for (k, v) in extra {
        headers.push((k.to_string(), v.to_string()));
    }
    ProxyRequest {
        method: "POST".into(),
        path: "/mcp".into(),
        headers,
        body: body.to_string().into_bytes(),
    }
}

fn body(r: &ProxyResponse) -> Value {
    serde_json::from_slice(&r.body).unwrap_or(Value::Null)
}

fn rpc(method: &str, params: Value) -> Value {
    json!({ "jsonrpc": "2.0", "id": 1, "method": method, "params": params })
}

fn modern(method: &str, mut params: Value) -> Value {
    params["_meta"] = json!({ "io.modelcontextprotocol/protocolVersion": MODERN });
    rpc(method, params)
}

#[test]
fn initialize_negotiates_a_version_and_the_initialized_notification_is_accepted() {
    let s = server();
    let t = s.issue(conductor(), Some("t1"), 0, 1000).unwrap().token;
    let r = s.handle(
        &post(
            Some(&t),
            &[],
            &rpc("initialize", json!({ "protocolVersion": "2025-06-18" })),
        ),
        1,
    );
    assert_eq!(r.status, 200);
    let v = body(&r);
    assert_eq!(v["result"]["protocolVersion"], "2025-06-18");
    assert_eq!(v["result"]["serverInfo"]["name"], "ozbox");
    assert!(v["result"]["capabilities"]["tools"].is_object());
    // an unknown version is answered with the newest this server speaks
    let v = body(&s.handle(
        &post(
            Some(&t),
            &[],
            &rpc("initialize", json!({ "protocolVersion": "1999-01-01" })),
        ),
        1,
    ));
    assert_eq!(v["result"]["protocolVersion"], MODERN);
    let n = json!({ "jsonrpc": "2.0", "method": "notifications/initialized" });
    let r = s.handle(&post(Some(&t), &[], &n), 2);
    assert_eq!((r.status, r.body.len()), (202, 0));
    assert_eq!(
        body(&s.handle(&post(Some(&t), &[], &rpc("ping", json!({}))), 3))["result"],
        json!({})
    );
}

#[test]
fn tools_list_and_call_work_for_a_conductor_and_return_content_and_structured_content() {
    let s = server();
    let t = s.issue(conductor(), None, 0, 1000).unwrap().token;
    let v = body(&s.handle(&post(Some(&t), &[], &rpc("tools/list", json!({}))), 1));
    let names: Vec<_> = v["result"]["tools"]
        .as_array()
        .unwrap()
        .iter()
        .map(|t| t["name"].as_str().unwrap())
        .collect();
    assert_eq!(names.len(), 22);
    assert!(names.contains(&"task_start") && !names.contains(&"orchestration_start"));
    let r = s.handle(
        &post(
            Some(&t),
            &[],
            &rpc(
                "tools/call",
                json!({ "name": "budget_status", "arguments": { "x": 1 } }),
            ),
        ),
        2,
    );
    let v = body(&r);
    assert_eq!(v["result"]["isError"], false);
    assert_eq!(v["result"]["structuredContent"]["tool"], "budget_status");
    assert!(v["result"]["content"][0]["text"]
        .as_str()
        .unwrap()
        .contains("budget_status"));
    // a refusal is a tool error the model can read, not a protocol error
    let v = body(&s.handle(
        &post(
            Some(&t),
            &[],
            &rpc(
                "tools/call",
                json!({ "name": "budget_status", "arguments": { "fail": true } }),
            ),
        ),
        3,
    ));
    assert_eq!(v["result"]["isError"], true);
    assert_eq!(v["result"]["content"][0]["text"], "no");
}

#[test]
fn a_worker_token_sees_its_tools_and_cannot_call_a_conductor_tool() {
    let s = server();
    let t = s.issue(worker(), None, 0, 1000).unwrap().token;
    let v = body(&s.handle(&post(Some(&t), &[], &rpc("tools/list", json!({}))), 1));
    assert_eq!(v["result"]["tools"].as_array().unwrap().len(), 11);
    let v = body(&s.handle(
        &post(
            Some(&t),
            &[],
            &rpc(
                "tools/call",
                json!({ "name": "task_start", "arguments": {} }),
            ),
        ),
        2,
    ));
    assert_eq!(v["error"]["code"], -32602);
    let v = body(&s.handle(
        &post(
            Some(&t),
            &[],
            &rpc(
                "tools/call",
                json!({ "name": "worker_ask", "arguments": { "question": "x" } }),
            ),
        ),
        3,
    ));
    assert!(v["result"]["structuredContent"]["role"]
        .as_str()
        .unwrap()
        .contains("Worker"));
}

#[test]
fn no_token_a_wrong_token_an_expired_token_and_a_revoked_token_are_refused() {
    let s = server();
    let call = rpc("tools/list", json!({}));
    assert_eq!(s.handle(&post(None, &[], &call), 1).status, 401);
    assert_eq!(
        s.handle(&post(Some("ozmt_nope"), &[], &call), 1).status,
        401
    );
    assert_eq!(
        s.handle(&post(Some("sk-not-ours"), &[], &call), 1).status,
        401
    );
    let t = s.issue(conductor(), Some("t7"), 0, 1000).unwrap().token;
    assert_eq!(s.handle(&post(Some(&t), &[], &call), 500).status, 200);
    assert_eq!(
        s.handle(&post(Some(&t), &[], &call), 1500).status,
        401,
        "expired"
    );
    let t = s.issue(conductor(), Some("t8"), 0, 100_000).unwrap().token;
    assert!(s.holds_token_for("t8"));
    s.revoke_run("t8");
    assert_eq!(
        s.handle(&post(Some(&t), &[], &call), 1).status,
        401,
        "the run ended"
    );
    // a token from another server (another start) is worthless
    let other = server();
    let t = other.issue(conductor(), None, 0, 1000).unwrap().token;
    assert_eq!(s.handle(&post(Some(&t), &[], &call), 1).status, 401);
}

#[test]
fn a_browser_origin_a_foreign_host_and_a_get_are_refused() {
    let s = server();
    let t = s.issue(conductor(), None, 0, 1000).unwrap().token;
    let call = rpc("ping", json!({}));
    assert_eq!(
        s.handle(
            &post(Some(&t), &[("Origin", "https://evil.example")], &call),
            1
        )
        .status,
        403
    );
    let mut r = post(Some(&t), &[], &call);
    r.headers[0].1 = "evil.example".into();
    assert_eq!(s.handle(&r, 1).status, 403);
    let mut r = post(Some(&t), &[], &call);
    r.method = "GET".into();
    assert_eq!(s.handle(&r, 1).status, 405);
    let mut r = post(Some(&t), &[], &call);
    r.path = "/other".into();
    assert_eq!(s.handle(&r, 1).status, 404);
}

#[test]
fn the_current_revision_checks_the_headers_against_the_body() {
    let s = server();
    let t = s.issue(conductor(), None, 0, 100_000).unwrap().token;
    let call = modern(
        "tools/call",
        json!({ "name": "budget_status", "arguments": {} }),
    );
    let ok = [
        ("MCP-Protocol-Version", MODERN),
        ("Mcp-Method", "tools/call"),
        ("Mcp-Name", "budget_status"),
    ];
    assert_eq!(s.handle(&post(Some(&t), &ok, &call), 1).status, 200);
    let bad_method = [
        ("MCP-Protocol-Version", MODERN),
        ("Mcp-Method", "tools/list"),
        ("Mcp-Name", "budget_status"),
    ];
    let r = s.handle(&post(Some(&t), &bad_method, &call), 2);
    assert_eq!(
        (r.status, body(&r)["error"]["code"].clone()),
        (400, json!(-32020))
    );
    let bad_name = [
        ("MCP-Protocol-Version", MODERN),
        ("Mcp-Method", "tools/call"),
        ("Mcp-Name", "task_stop"),
    ];
    assert_eq!(
        body(&s.handle(&post(Some(&t), &bad_name, &call), 3))["error"]["code"],
        -32020
    );
    let no_name = [
        ("MCP-Protocol-Version", MODERN),
        ("Mcp-Method", "tools/call"),
    ];
    assert_eq!(s.handle(&post(Some(&t), &no_name, &call), 4).status, 400);
    // a Base64-sentinel name is decoded before it is compared
    let b64 = [
        ("MCP-Protocol-Version", MODERN),
        ("Mcp-Method", "tools/call"),
        ("Mcp-Name", "=?base64?YnVkZ2V0X3N0YXR1cw==?="),
    ];
    assert_eq!(s.handle(&post(Some(&t), &b64, &call), 5).status, 200);
    // the body's own protocol version must match the header
    let legacy_body = rpc(
        "tools/call",
        json!({ "name": "budget_status", "arguments": {} }),
    );
    assert_eq!(s.handle(&post(Some(&t), &ok, &legacy_body), 6).status, 400);
    let h = [("MCP-Protocol-Version", "2031-01-01")];
    let r = s.handle(&post(Some(&t), &h, &rpc("ping", json!({}))), 7);
    assert_eq!(r.status, 400);
    assert_eq!(body(&r)["error"]["data"]["supported"][0], MODERN);
    // an unknown method on the current revision is a 404 with a JSON-RPC error; on an older one a 200
    let m = [
        ("MCP-Protocol-Version", MODERN),
        ("Mcp-Method", "resources/list"),
    ];
    let r = s.handle(&post(Some(&t), &m, &modern("resources/list", json!({}))), 8);
    assert_eq!(
        (r.status, body(&r)["error"]["code"].clone()),
        (404, json!(-32601))
    );
    let r = s.handle(
        &post(
            Some(&t),
            &[("MCP-Protocol-Version", "2025-06-18")],
            &rpc("resources/list", json!({})),
        ),
        9,
    );
    assert_eq!(
        (r.status, body(&r)["error"]["code"].clone()),
        (200, json!(-32601))
    );
}

#[test]
fn bad_bodies_batches_oversize_and_the_rate_limit_are_refused() {
    let s = server();
    let t = s.issue(conductor(), None, 0, 1_000_000).unwrap().token;
    let mut r = post(Some(&t), &[], &json!(null));
    r.body = b"not json".to_vec();
    assert_eq!(s.handle(&r, 1).status, 400);
    let batch = json!([rpc("ping", json!({}))]);
    assert_eq!(s.handle(&post(Some(&t), &[], &batch), 1).status, 400);
    let big = rpc("ping", json!({ "x": "a".repeat(MAX_BODY + 1) }));
    assert_eq!(s.handle(&post(Some(&t), &[], &big), 1).status, 413);
    let bad_args = rpc(
        "tools/call",
        json!({ "name": "budget_status", "arguments": [1] }),
    );
    assert_eq!(
        body(&s.handle(&post(Some(&t), &[], &bad_args), 1))["error"]["code"],
        -32602
    );
    let s2 = server();
    let t2 = s2.issue(conductor(), None, 0, 1_000_000).unwrap().token;
    let ping = rpc("ping", json!({}));
    for _ in 0..CALLS_PER_MINUTE {
        assert_eq!(s2.handle(&post(Some(&t2), &[], &ping), 10).status, 200);
    }
    assert_eq!(s2.handle(&post(Some(&t2), &[], &ping), 10).status, 429);
    assert_eq!(
        s2.handle(&post(Some(&t2), &[], &ping), 70_000).status,
        200,
        "a minute later"
    );
}

#[test]
fn a_token_is_never_printed_or_returned() {
    let s = server();
    let i = s.issue(conductor(), None, 0, 1000).unwrap();
    assert!(!format!("{i:?}").contains(&i.token));
    let env = env_for(&i);
    assert_eq!(env["OZBOX_MCP_URL"], format!("http://127.0.0.1:{PORT}/mcp"));
    let v =
        body(&s.handle(&post(Some(&i.token), &[], &rpc("tools/list", json!({}))), 1)).to_string();
    assert!(!v.contains(&i.token));
}

#[test]
fn a_run_origin_decides_the_session() {
    use ozbox_core::run::{RunOrigin, RunSpec};
    let spec = |origin| RunSpec {
        engine: "fake".into(),
        prompt: "x".into(),
        skill: None,
        box_name: "b".into(),
        repo: None,
        branch: None,
        caps: Default::default(),
        deliver_to: vec![],
        requested_by: "ada".into(),
        origin,
        idempotency_key: None,
        model: None,
        interactive: false,
    };
    assert_eq!(session_for(&spec(RunOrigin::Manual)), None);
    assert_eq!(
        session_for(&spec(RunOrigin::Orchestration {
            id: "o1".into(),
            feature: "".into()
        }))
        .unwrap()
        .role,
        Role::Conductor { orch: "o1".into() }
    );
    assert_eq!(
        session_for(&spec(RunOrigin::Orchestration {
            id: "o1".into(),
            feature: "f2".into()
        }))
        .unwrap()
        .role,
        Role::Worker {
            orch: "o1".into(),
            feature: "f2".into()
        }
    );
}

#[test]
fn it_answers_over_a_real_loopback_socket() {
    use std::io::{Read as _, Write as _};
    let s = McpServer::start(Arc::new(Echo)).unwrap();
    let t = s
        .issue(conductor(), None, crate::serve::unix_ms(), 100_000)
        .unwrap()
        .token;
    let body = rpc("ping", json!({})).to_string();
    let mut c = std::net::TcpStream::connect(("127.0.0.1", s.port())).unwrap();
    write!(
        c,
        "POST /mcp HTTP/1.1\r\nHost: 127.0.0.1:{}\r\nAuthorization: Bearer {t}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
        s.port(),
        body.len()
    )
    .unwrap();
    let mut out = String::new();
    c.read_to_string(&mut out).unwrap();
    assert!(out.starts_with("HTTP/1.1 200"), "{out}");
    assert!(out.contains("\"result\":{}"));
}
