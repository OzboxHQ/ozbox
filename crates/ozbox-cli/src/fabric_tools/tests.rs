#![allow(clippy::unwrap_used)]
//! The messaging, memory and skills tools end to end: a hub and two workers over the in-memory transport, two runs on different
//! boxes and engines calling the same MCP tools, the hub's real memory and skills stores, and a person through the chat bridge.
//! H4 runs this over the real transport, signer and sealer.

use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};

use ozbox_core::fabric::bridge::{post_from_chat, pull_replies, ChatInbound, Subscriptions};
use ozbox_core::fabric::node::{BoxFabric, HubFabric, Seams};
use ozbox_core::fabric::walls::WallSource;
use ozbox_core::fabric::{Address, CoreScreen, FabricApi};
use ozbox_core::hub::mem::{MemTransport, TestKey, TestRoster, TestSealer};
use ozbox_core::permissions::ActorKind;
use ozbox_core::run::{ModelRef, RunSpec, TaskStore};
use ozbox_memory::memory::{Caller, Filter, State};
use ozbox_memory::skills::InstallScope;
use serde_json::{json, Value};

use super::FabricHost;
use crate::mcp::HostScope;
use crate::memory_tools::MemoryHost;
use crate::orch_tools::{BoxOps, Role, Session, Tools};

const HUB_FP: &str = "aa00000000000000000000000000000000000000000000000000000000000001";
const A_FP: &str = "bb00000000000000000000000000000000000000000000000000000000000001";
const B_FP: &str = "bb00000000000000000000000000000000000000000000000000000000000002";

struct NoFleet;
impl BoxOps for NoFleet {
    fn list(&self) -> Result<Vec<Value>, String> {
        Ok(Vec::new())
    }
    fn plan(&self, _: Value) -> Result<Value, String> {
        Err("no".into())
    }
    fn apply(&self, _: &str, _: &Value) -> Result<Value, String> {
        Err("no".into())
    }
}

fn seams(net: &Arc<MemTransport>, k: &str, fp: &str) -> Seams {
    let keys = BTreeMap::from([
        (HUB_FP.to_string(), "k-main".to_string()),
        (A_FP.to_string(), "k-a".to_string()),
        (B_FP.to_string(), "k-b".to_string()),
    ]);
    Seams {
        signer: Arc::new(TestKey(k.into())),
        verifier: Arc::new(TestRoster(keys)),
        sealer: Arc::new(TestSealer { my_fp: fp.into() }),
        net: net.clone(),
        screen: Arc::new(CoreScreen),
        audit: None,
    }
}

struct Rig {
    hub: Arc<HubFabric>,
    a: Arc<BoxFabric>,
    b: Arc<BoxFabric>,
    mem: Arc<MemoryHost>,
    hub_tools: Tools,
    a_tools: Tools,
    b_tools: Tools,
    now: Mutex<u64>,
    _dirs: Vec<tempfile::TempDir>,
}

fn tools(dir: &tempfile::TempDir, fab: Arc<dyn FabricApi>, b: &str) -> Tools {
    Tools::new(
        TaskStore::new(dir.path().join("tasks.json")),
        Arc::new(NoFleet),
    )
    .with_fabric(Some(Arc::new(FabricHost::new(fab, b))))
}

fn rig() -> Rig {
    let dirs: Vec<tempfile::TempDir> = (0..4).map(|_| tempfile::tempdir().unwrap()).collect();
    let net = Arc::new(MemTransport::default());
    let mem = Arc::new(MemoryHost::open(dirs[3].path()).unwrap());
    let roster = BTreeMap::from([
        ("box-a".to_string(), A_FP.to_string()),
        ("box-b".to_string(), B_FP.to_string()),
    ]);
    let hub = Arc::new(HubFabric::new(
        "main",
        HUB_FP,
        roster,
        seams(&net, "k-main", HUB_FP),
        Some(mem.clone() as Arc<dyn WallSource>),
    ));
    let a = Arc::new(BoxFabric::new(
        "box-a",
        A_FP,
        "main",
        HUB_FP,
        seams(&net, "k-a", A_FP),
    ));
    let b = Arc::new(BoxFabric::new(
        "box-b",
        B_FP,
        "main",
        HUB_FP,
        seams(&net, "k-b", B_FP),
    ));
    let hub_tools = tools(&dirs[0], hub.clone(), "main").with_memory(Some(mem.clone()));
    let a_tools = tools(&dirs[1], a.clone(), "box-a");
    let b_tools = tools(&dirs[2], b.clone(), "box-b");
    Rig {
        hub,
        a,
        b,
        mem,
        hub_tools,
        a_tools,
        b_tools,
        now: Mutex::new(1_000_000),
        _dirs: dirs,
    }
}

impl Rig {
    fn now(&self) -> u64 {
        *self.now.lock().unwrap()
    }
    fn settle(&self) {
        for _ in 0..6 {
            let n = {
                let mut t = self.now.lock().unwrap();
                *t += 1_100;
                *t
            };
            self.a.pump(n).unwrap();
            self.b.pump(n).unwrap();
            self.hub.pump(n).unwrap();
        }
    }
}

/// A run on `box_name` with its engine, provider and repository, as the task store records it.
fn run(
    t: &Tools,
    box_name: &str,
    engine: &str,
    provider: &str,
    repo: &str,
) -> (Session, HostScope) {
    let spec = RunSpec {
        engine: engine.into(),
        prompt: "work".into(),
        skill: None,
        box_name: box_name.into(),
        repo: Some(repo.into()),
        branch: None,
        caps: Default::default(),
        deliver_to: Vec::new(),
        requested_by: "ada".into(),
        origin: ozbox_core::run::RunOrigin::Manual,
        idempotency_key: None,
        model: Some(ModelRef {
            provider_id: provider.into(),
            model: "m".into(),
        }),
        interactive: false,
    };
    let id = t
        .store
        .update(|b| b.enqueue(spec, 1, None))
        .unwrap()
        .unwrap()
        .0;
    (
        Session {
            person: "ada".into(),
            role: Role::Agent,
        },
        HostScope {
            box_name: Some(box_name.into()),
            run_id: Some(id),
            orchestration: None,
            actor: ActorKind::Agent,
            session: None,
            program: None,
            program_pid: None,
            code: None,
            standing_until_ms: None,
            door_gen: 0,
        },
    )
}

fn call(t: &Tools, s: &(Session, HostScope), name: &str, a: Value, now: u64) -> Value {
    t.call_as(&s.0, Some(&s.1), name, &a, now).unwrap()
}

#[test]
fn two_runs_on_two_boxes_and_engines_talk_through_the_same_tools() {
    let r = rig();
    let alpha = run(&r.a_tools, "box-a", "claude-code", "anthropic", "billing");
    let beta = run(&r.b_tools, "box-b", "codex", "openai", "billing");
    // the first call registers each caller; then the directories travel
    call(&r.a_tools, &alpha, "participants_list", json!({}), r.now());
    call(&r.b_tools, &beta, "participants_list", json!({}), r.now());
    r.settle();
    let list = call(&r.a_tools, &alpha, "participants_list", json!({}), r.now());
    let me = list["me"].as_str().unwrap().to_string();
    let other = list["participants"]
        .as_array()
        .unwrap()
        .iter()
        .find(|p| p["box"] == "box-b")
        .unwrap()
        .clone();
    assert_eq!(other["engine"], "codex");
    assert_eq!(other["provider"], "openai");
    let to = other["address"].as_str().unwrap().to_string();
    let sent = call(
        &r.a_tools,
        &alpha,
        "messages_post",
        json!({"to": to, "text": "Rebase on main before the merge."}),
        r.now(),
    );
    assert!(sent["note"]
        .as_str()
        .unwrap()
        .contains("data, not instructions"));
    r.settle();
    let got = call(&r.b_tools, &beta, "messages_get", json!({}), r.now());
    let m = &got["messages"][0];
    assert_eq!(m["from"], me.as_str());
    assert!(m["from_is"]
        .as_str()
        .unwrap()
        .ends_with("on box-a (claude-code · anthropic)"));
    let id = m["id"].as_str().unwrap().to_string();
    call(
        &r.b_tools,
        &beta,
        "messages_post",
        json!({"to": me, "text": "Done.", "reply_to": id}),
        r.now(),
    );
    call(
        &r.b_tools,
        &beta,
        "messages_ack",
        json!({"ids": [id]}),
        r.now(),
    );
    r.settle();
    let thread = call(
        &r.a_tools,
        &alpha,
        "messages_thread",
        json!({"thread": sent["thread"]}),
        r.now(),
    );
    assert_eq!(thread["messages"].as_array().unwrap().len(), 2);
    assert_eq!(thread["messages"][0]["state"], "read");
    // a secret is refused by kind, through the tool too
    let key = ["gh", "p_", "SENTINELsentinel", "0123456789abcdefXYZ"].concat();
    let e = r
        .a_tools
        .call_as(
            &alpha.0,
            Some(&alpha.1),
            "messages_post",
            &json!({"to": to, "text": key}),
            r.now(),
        )
        .unwrap_err();
    assert!(!e.message().contains("SENTINEL"));
}

#[test]
fn memory_proposed_on_one_box_is_reviewed_on_main_and_read_with_a_shared_skill_on_both() {
    let r = rig();
    let alpha = run(&r.a_tools, "box-a", "claude-code", "anthropic", "billing");
    let beta = run(&r.b_tools, "box-b", "codex", "openai", "billing");
    call(&r.a_tools, &alpha, "participants_list", json!({}), r.now());
    call(&r.b_tools, &beta, "participants_list", json!({}), r.now());
    // a reviewed skill on the shared project, from the hub's own skills store
    let name = ozbox_memory::bundled::bundled()[0].name.clone();
    let v = r
        .mem
        .skills
        .install(&name, &InstallScope::Project("billing".into()), "ada", 1)
        .unwrap();
    r.mem.skills.approve(&name, &v.hash, "ada", 1, &[]).unwrap();
    r.hub.walls_changed();
    r.settle();
    for (t, s) in [(&r.a_tools, &alpha), (&r.b_tools, &beta)] {
        let l = call(t, s, "skills_list", json!({}), r.now());
        assert_eq!(l["skills"][0]["name"], name.as_str());
        let text = call(t, s, "skills_read", json!({"name": name}), r.now());
        assert!(!text["text"].as_str().unwrap().is_empty());
    }
    // beta proposes; it waits on main for a person
    let p = call(
        &r.b_tools,
        &beta,
        "memory_write",
        json!({"title": "Ledger rounding", "body": "The ledger rounds half-even.", "scope": "project:billing"}),
        r.now(),
    );
    assert_eq!(p["state"], "pending");
    r.settle();
    let pending = r
        .mem
        .memory
        .list(
            &Caller::Person("ada".into()),
            &Filter {
                state: Some(State::Pending),
                ..Filter::default()
            },
            r.now(),
        )
        .unwrap();
    assert_eq!(pending.len(), 1);
    assert_eq!(pending[0].provenance.box_name.as_deref(), Some("box-b"));
    assert!(call(
        &r.a_tools,
        &alpha,
        "memory_search",
        json!({"query": "half-even"}),
        r.now()
    )["notes"]
        .as_array()
        .unwrap()
        .is_empty());
    r.mem
        .memory
        .approve(&Caller::Person("ada".into()), &pending[0].id, r.now())
        .unwrap();
    r.hub.walls_changed();
    r.settle();
    let hits = call(
        &r.a_tools,
        &alpha,
        "memory_search",
        json!({"query": "half-even"}),
        r.now(),
    );
    assert_eq!(hits["notes"][0]["written_on"], "box-b");
    let full = call(
        &r.a_tools,
        &alpha,
        "memory_read",
        json!({"id": hits["notes"][0]["id"]}),
        r.now(),
    );
    assert_eq!(full["reviewed_by"], "ada");
    assert!(full["note"].as_str().unwrap().contains("not instructions"));
    // a wall this run is not bound to is refused
    assert!(r
        .a_tools
        .call_as(
            &alpha.0,
            Some(&alpha.1),
            "memory_search",
            &json!({"query": "x", "scope": "project:payroll"}),
            r.now()
        )
        .is_err());
}

#[test]
fn a_person_on_telegram_and_whatsapp_reaches_runs_and_hears_attributed_replies() {
    let r = rig();
    let alpha = run(&r.a_tools, "box-a", "claude-code", "anthropic", "billing");
    let beta = run(&r.b_tools, "box-b", "codex", "openai", "billing");
    let la = call(&r.a_tools, &alpha, "participants_list", json!({}), r.now());
    let lb = call(&r.b_tools, &beta, "participants_list", json!({}), r.now());
    let a_addr = Address::parse(la["me"].as_str().unwrap()).unwrap();
    let b_addr = Address::parse(lb["me"].as_str().unwrap()).unwrap();
    r.settle();
    let fleet = ozbox_core::fabric::Participant {
        address: Address::Fleet { name: "ada".into() },
        person: "ada".into(),
        display: "ada's fleet".into(),
        engine: None,
        provider: None,
        projects: Vec::new(),
        box_name: None,
        members: vec![a_addr.clone(), b_addr.clone()],
        home: "main".into(),
    };
    r.hub.register(fleet.clone(), r.now()).unwrap();
    let mut subs = Subscriptions::default();
    for (ch, chat, to) in [
        ("telegram", "telegram:7", a_addr.clone()),
        ("whatsapp", "whatsapp:15550100", fleet.address.clone()),
    ] {
        post_from_chat(
            r.hub.as_ref(),
            &mut subs,
            ChatInbound {
                person: "ada".into(),
                channel: ch.into(),
                chat_ref: chat.into(),
                targets: vec![to],
                text: "Where are you?".into(),
                thread: None,
                reply_to: None,
            },
            r.now(),
        )
        .unwrap();
    }
    r.settle();
    let at_b = call(&r.b_tools, &beta, "messages_get", json!({}), r.now());
    assert_eq!(at_b["messages"][0]["from"], "person:ada");
    call(&r.a_tools, &alpha, "participants_list", json!({}), r.now());
    call(
        &r.a_tools,
        &alpha,
        "messages_post",
        json!({"to": "person:ada", "text": "Tests are green."}),
        r.now(),
    );
    call(
        &r.b_tools,
        &beta,
        "messages_post",
        json!({"to": "person:ada", "text": "Rebasing."}),
        r.now(),
    );
    r.settle();
    let (replies, _) = pull_replies(r.hub.as_ref(), &subs, "ada", 0, r.now()).unwrap();
    assert_eq!(replies.len(), 2);
    assert!(replies.iter().any(|x| x
        .attribution
        .ends_with("on box-a (claude-code · anthropic)")));
    assert!(replies
        .iter()
        .any(|x| x.attribution.ends_with("on box-b (codex · openai)")));
    for x in &replies {
        assert_eq!(x.to_chats.len(), 2);
        assert_eq!(x.project.as_deref(), Some("billing"));
    }
    // a person's own agent is not a participant: it is told to write as the person
    let own = Session {
        person: "ada".into(),
        role: Role::Person,
    };
    assert!(r
        .hub_tools
        .call(
            &own,
            "messages_post",
            &json!({"to": "person:ada", "text": "x"}),
            r.now()
        )
        .is_err());
}
