//! The whole chat path, end to end (ADR 0050, "End-to-end path"): a real update from the fake Telegram over HTTP, the
//! bridge, the policy, the plan, the fake provider or the supervisor and its fake agent engine, and the exact messages that
//! go back. Assertions are on the structured messages ([`Said`]: a catalogue key and its arguments), so the words can change
//! without breaking what is proved here.

use std::sync::Arc;

use ozbox_core::{BoxName, BoxSpec, BoxState, Provider, Size};
use serde_json::json;

use super::{Rig, PHONE};
use crate::chat::remote::{FakeMesh, Worker};
#[allow(unused_imports)]
use crate::secrets::SecretStore;
use crate::serve::telegram_acts::Said;

const HOUR: u64 = 3_600_000;

impl Rig {
    /// Run the server's tick at `now` (the bridge, the runs and the chat all see this moment).
    fn tick_at(&mut self, now: u64) {
        self.now = now;
        self.app.schedule.next_telegram_ms = 0;
        self.app.runs.next_tick_ms = 0;
        self.app.chat.next_tick_ms = 0;
        self.app.tick(now);
        self.app.runs.next_tick_ms = 0;
        self.app.chat.next_tick_ms = 0;
        self.app.tick(now + 1);
    }

    /// A message from the phone written at `now`, then the ticks that handle it.
    fn say_at_ms(&mut self, text: &str, now: u64) {
        self.tg.say_at(PHONE, text, now / 1000);
        self.tick_at(now);
    }

    /// Ticks until the agent engine has answered.
    fn settle(&mut self, from: u64, n: u64) -> u64 {
        let mut t = from;
        for _ in 0..n {
            t += 5_000;
            self.tick_at(t);
        }
        t
    }

    fn said(&self) -> Vec<Said> {
        self.app.tg.said.iter().cloned().collect()
    }

    fn said_keys(&self) -> Vec<&'static str> {
        self.app.tg.said.iter().map(|s| s.key).collect()
    }

    fn last_said(&self, key: &str) -> Option<Said> {
        self.app
            .tg
            .said
            .iter()
            .rev()
            .find(|s| s.key == key)
            .cloned()
    }

    fn add_box(&mut self, name: &str, size: Size, idle: bool) {
        let mut spec = BoxSpec::new(BoxName::new(name).unwrap(), size);
        if idle {
            spec.labels.insert("sim_sessions".into(), "none".into());
        }
        let p: &dyn Provider = self.app.provider.as_ref();
        let plan = p.plan(&ozbox_core::Operation::Create { spec }).unwrap();
        p.apply(&plan).unwrap();
    }

    fn state_of(&self, name: &str) -> Option<BoxState> {
        self.app
            .provider
            .get(&BoxName::new(name).unwrap())
            .unwrap()
            .map(|r| r.state)
    }

    fn price(&mut self, size: &str, monthly_usd: f64) {
        self.app
            .settings
            .budget
            .size_prices_usd
            .insert(size.into(), monthly_usd);
    }

    /// Link the phone with converse on `converse`, and delegate box power on `power` with these caps; returns the moment
    /// a day later, when the new-link wait is over.
    fn link_with_power(
        &mut self,
        converse: &[&str],
        power: &[&str],
        caps: serde_json::Value,
    ) -> u64 {
        let lid = self.link("owner", PHONE, Some(converse));
        let (st, v) = self.passkey_step(
            "owner",
            &format!("/v1/telegram/links/{lid}/delegations"),
            json!({ "acts": ["power"], "boxes": power, "days": 7, "caps": caps }),
            &format!("/v1/telegram/links/{lid}/delegations"),
            "POST",
        );
        assert_eq!(st, 200, "{v}");
        super::unix_ms() + 25 * HOUR
    }
}

// ---------- box power ----------

#[test]
fn box_power_inside_the_delegation_is_planned_shown_and_applied_and_the_chat_is_told() {
    let mut r = Rig::new();
    r.add_box("idle", Size::S, true);
    r.price("S", 73.0); // 10 cents an hour
    r.price("XS", 36.5);
    r.price("M", 146.0);
    let t0 = r.link_with_power(
        &["alpha", "idle"],
        &["alpha", "idle"],
        json!({ "max_size": "M", "daily_usd": 10, "creates_per_day": 1 }),
    );
    // pause an idle box: the plan, then the change, then "done"
    r.say_at_ms("/box pause idle", t0);
    let started = r
        .last_said("tg.power_started_pause")
        .expect("the plan is shown");
    assert_eq!(started.arg("box"), Some("idle"));
    assert!(started
        .arg("where")
        .unwrap()
        .contains("https://box.example.com/go#"));
    assert!(
        r.last_said("tg.power_done").is_some(),
        "{:?}",
        r.said_keys()
    );
    assert_eq!(r.state_of("idle"), Some(BoxState::Paused));
    // a second act within a minute waits: the cooldown, with the dashboard link
    r.say_at_ms("/box resume idle", t0 + 10_000);
    assert!(
        r.last_said("tg.power_cooldown").is_some(),
        "{:?}",
        r.said_keys()
    );
    assert_eq!(r.state_of("idle"), Some(BoxState::Paused));
    // after it, the resume: four hours of S at 10 cents is 40 cents, inside $10
    r.say_at_ms("/box resume idle", t0 + 2 * 60_000);
    let s = r.last_said("tg.power_started").unwrap();
    assert_eq!(s.arg("cost"), Some("$0.40"));
    assert_eq!(r.state_of("idle"), Some(BoxState::Running));
    let bp = r.app.tg.store.data.power.boxes["idle"].clone();
    assert_eq!(bp.deadline_ms, Some(t0 + 2 * 60_000 + 4 * HOUR));
    assert_eq!(r.app.tg.store.data.power.used["owner"].resumes, 1);
    // extend once by two hours, then never again
    r.say_at_ms("/box extend idle 2", t0 + 4 * 60_000);
    assert!(r.last_said("tg.power_extended").is_some());
    r.say_at_ms("/box extend idle 1", t0 + 6 * 60_000);
    assert!(r.last_said("tg.power_extended").is_some());
    assert!(r.said_keys().contains(&"tg.power_extended"));
    assert_eq!(
        r.said_keys()
            .iter()
            .filter(|k| **k == "tg.power_extended")
            .count(),
        1,
        "{:?}",
        r.said_keys()
    );
    // resize at or below the size cap is done; above it is the dashboard's
    r.say_at_ms("/box resize idle xs", t0 + 8 * 60_000);
    assert!(
        r.last_said("tg.power_started_resize").is_some(),
        "{:?}",
        r.said_keys()
    );
    r.say_at_ms("/box resize idle l", t0 + 10 * 60_000);
    let above = r.last_said("tg.power_above_size_cap").unwrap();
    assert!(
        above.arg("plan").is_some_and(|p| !p.is_empty()),
        "the plan is still shown"
    );
    // create a box, once a day
    r.say_at_ms("/box create gamma m", t0 + 12 * 60_000);
    assert!(
        r.last_said("tg.power_started_create").is_some(),
        "{:?}",
        r.said_keys()
    );
    assert_eq!(r.state_of("gamma"), Some(BoxState::Running));
    r.say_at_ms("/box create delta s", t0 + 14 * 60_000);
    assert!(
        r.last_said("tg.power_creates_cap").is_some(),
        "{:?}",
        r.said_keys()
    );
    assert_eq!(r.state_of("delta"), None);
    // every act is in the audit chain under the person, with the update number
    let chain = r.chain_text();
    assert!(chain.contains("telegram.power"), "{chain}");
}

#[test]
fn a_box_started_from_chat_is_paused_at_its_deadline_and_the_chat_is_told() {
    let mut r = Rig::new();
    r.add_box("idle", Size::S, true);
    r.price("S", 73.0);
    let t0 = r.link_with_power(&["idle"], &["idle"], json!({}));
    r.say_at_ms("/box pause idle", t0);
    r.say_at_ms("/box resume idle", t0 + 2 * 60_000);
    assert_eq!(r.state_of("idle"), Some(BoxState::Running));
    r.tick_at(t0 + 2 * 60_000 + 4 * HOUR + 1);
    assert_eq!(r.state_of("idle"), Some(BoxState::Paused));
    assert!(
        r.last_said("tg.power_deadline").is_some(),
        "{:?}",
        r.said_keys()
    );
}

#[test]
fn power_outside_the_table_or_its_limits_production_a_locked_link_and_a_stale_message_are_refused()
{
    let mut r = Rig::new();
    r.add_box("idle", Size::S, true);
    r.price("S", 3_650.0); // $5 an hour: four hours is $20, over $10
    r.app.tg.store.data.marks.production = vec!["bravo".into()];
    let t0 = r.link_with_power(
        &["alpha"],
        &["alpha", "bravo", "idle"],
        json!({ "daily_usd": 10 }),
    );
    // money cap: the plan is shown, nothing is done, and the dashboard link is given
    r.say_at_ms("/box pause idle", t0);
    r.say_at_ms("/box resume idle", t0 + 2 * 60_000);
    let m = r
        .last_said("tg.power_money_cap")
        .expect("over the money cap");
    assert!(m.arg("where").unwrap().contains("/go#"));
    assert_eq!(r.state_of("idle"), Some(BoxState::Paused));
    // no size cap on this delegation: never a create
    r.say_at_ms("/box create zeta xs", t0 + 4 * 60_000);
    assert!(
        r.last_said("tg.power_no_size_cap").is_some()
            || r.last_said("tg.power_price_unknown").is_some(),
        "{:?}",
        r.said_keys()
    );
    assert_eq!(r.state_of("zeta"), None);
    // alpha carries coding sessions: a pause would end them, so it is listed and not done
    r.say_at_ms("/box pause alpha", t0 + 6 * 60_000);
    let ni = r.last_said("tg.power_not_idle").expect("not idle");
    assert!(ni.arg("ends").unwrap().contains("session"), "{ni:?}");
    assert_eq!(r.state_of("alpha"), Some(BoxState::Running));
    // Production: refused in words, always, even with a delegation that names it
    let n = r.tg.texts_to(PHONE).len();
    r.say_at_ms("/box pause bravo", t0 + 8 * 60_000);
    assert!(r.tg.texts_to(PHONE)[n..].join(" ").contains("Production"));
    assert_eq!(r.state_of("bravo"), Some(BoxState::Running));
    // a box not in the delegation: a handoff
    r.add_box("other", Size::S, true);
    let n = r.tg.texts_to(PHONE).len();
    r.say_at_ms("/box pause other", t0 + 10 * 60_000);
    assert!(r.tg.texts_to(PHONE)[n..]
        .join(" ")
        .contains("allow it in the dashboard"));
    // stale: a message written ten minutes ago is not acted on
    let before = r.said().len();
    r.tg.say_at(PHONE, "/box pause idle", (t0 + 12 * 60_000) / 1000 - 600);
    r.tick_at(t0 + 12 * 60_000);
    assert!(r.tg.texts_to(PHONE).last().unwrap().contains("too old"));
    assert_eq!(r.said().len(), before, "nothing was planned for it");
    // a replay of an update already handled does nothing a second time
    let id =
        r.tg.say_at(PHONE, "/box resume idle", (t0 + 14 * 60_000) / 1000);
    r.tick_at(t0 + 14 * 60_000);
    let sent = r.tg.sent_count();
    r.tg.say_with_id(id, PHONE, "/box resume idle");
    r.tick_at(t0 + 14 * 60_000 + 1_000);
    assert_eq!(
        r.tg.sent_count(),
        sent,
        "a replay is not answered or acted on"
    );
    // locked: reads only
    r.say_at_ms("/lock", t0 + 16 * 60_000);
    r.say_at_ms("/box resume idle", t0 + 18 * 60_000);
    assert!(r.tg.texts_to(PHONE).last().unwrap().contains("locked"));
    assert_eq!(r.state_of("idle"), Some(BoxState::Paused));
    // unlinked: nothing at all
    r.say_at_ms("/unlink", t0 + 20 * 60_000);
    let sent = r.tg.sent_count();
    r.say_at_ms("/box resume idle", t0 + 22 * 60_000);
    assert_eq!(r.tg.sent_count(), sent, "an unlinked chat hears nothing");
}

// ---------- talking to agents ----------

#[test]
fn link_address_an_agent_it_asks_for_approval_the_dashboard_decides_and_the_reply_comes_back_attributed(
) {
    let mut r = Rig::new();
    r.link("owner", PHONE, Some(&["alpha"]));
    let t0 = super::unix_ms();
    // start a session on alpha by address; the agent wants to run something that needs a decision
    r.say_at_ms("@alpha install it sim:command=sudo", t0);
    let sent = r.last_said("tg.address_sent").expect("the message is sent");
    assert!(
        sent.arg("states").unwrap().contains("1 delivered"),
        "{sent:?}"
    );
    let msg = sent.arg("msg").unwrap().to_string();
    let book = r.app.chat_book().unwrap();
    let task = book.tasks.last().unwrap().clone();
    assert_eq!(task.spec.box_name.as_str(), "alpha");
    assert_eq!(
        task.spec.origin,
        ozbox_core::run::RunOrigin::Chat,
        "a chat-started session is held to the chat profile (always ask)"
    );
    let t1 = r.settle(t0, 6);
    // the chat is told, with one link to the dashboard and no button
    let notice =
        r.tg.texts_to(PHONE)
            .into_iter()
            .find(|t| t.contains("Decide it in the dashboard") || t.contains("passkey"))
            .expect("the approval notice");
    assert!(notice.contains("sudo"));
    let pending: Vec<String> = r
        .app
        .chat_book()
        .unwrap()
        .approvals
        .iter()
        .filter(|a| a.state == ozbox_core::run::ApprovalState::Pending)
        .map(|a| a.id.clone())
        .collect();
    assert_eq!(pending.len(), 1);
    // words in the chat decide nothing
    r.say_at_ms("approve it", t1 + 1_000);
    assert_eq!(
        r.app
            .chat_book()
            .unwrap()
            .approvals
            .iter()
            .filter(|a| a.state == ozbox_core::run::ApprovalState::Pending)
            .count(),
        1
    );
    // the dashboard decides it
    let (st, v) = r.call(
        "owner",
        "POST",
        &format!("/v1/approval-requests/{}/approve", pending[0]),
        serde_json::Value::Null,
    );
    assert_eq!(st, 200, "{v}");
    r.settle(t1 + 2_000, 8);
    // the agent went on, and its reply is attributed to its box and session, under the message id
    let reply = r
        .said()
        .into_iter()
        .rev()
        .find(|s| s.key.starts_with("tg.reply"))
        .expect("a reply came back");
    assert_eq!(reply.arg("box"), Some("alpha"));
    assert_eq!(reply.arg("session"), Some(task.id.as_str()));
    assert_eq!(reply.arg("msg"), Some(msg.as_str()));
}

#[test]
fn a_fleet_of_three_with_one_offline_and_one_not_delegated_gets_grouped_replies_and_names_what_it_left_out(
) {
    let mut r = Rig::new();
    r.add_box("charlie", Size::S, false);
    r.add_box("delta", Size::S, false);
    // delta is paused: an honest "unreachable", never silence
    let p: &dyn Provider = r.app.provider.as_ref();
    let plan = p
        .plan(&ozbox_core::Operation::Pause {
            name: BoxName::new("delta").unwrap(),
        })
        .unwrap();
    p.apply(&plan).unwrap();
    r.app.tg.store.data.marks.groups.insert(
        "web".into(),
        vec!["alpha".into(), "bravo".into(), "delta".into()],
    );
    // alpha and delta delegated, bravo not
    r.link("owner", PHONE, Some(&["alpha", "delta"]));
    let t0 = super::unix_ms();
    r.say_at_ms("/fleets", t0);
    let f = r.last_said("tg.fleets").unwrap();
    assert!(f.arg("list").unwrap().contains("@web: 2 of 3"), "{f:?}");
    r.say_at_ms("/boxes", t0 + 1_000);
    let b = r.last_said("tg.boxes").unwrap();
    let list = b.arg("list").unwrap();
    assert!(
        list.contains("alpha") && list.contains("delta") && !list.contains("bravo"),
        "{list}"
    );
    r.say_at_ms("@web what is the git status", t0 + 2_000);
    let s = r.last_said("tg.address_fanout").expect("a grouped summary");
    let msg = s.arg("msg").unwrap().to_string();
    assert!(s.arg("states").unwrap().contains("1 delivered"), "{s:?}");
    assert!(s.arg("states").unwrap().contains("1 unreachable"), "{s:?}");
    assert!(
        s.arg("skipped").unwrap().contains("1 not_delegated"),
        "{s:?}"
    );
    let un = r.last_said("tg.address_unreachable").unwrap();
    assert_eq!(un.arg("box"), Some("delta"));
    r.settle(t0 + 3_000, 8);
    let replies: Vec<Said> = r
        .said()
        .into_iter()
        .filter(|s| s.key.starts_with("tg.reply_to") && s.arg("msg") == Some(msg.as_str()))
        .collect();
    assert!(!replies.is_empty(), "{:?}", r.said_keys());
    assert!(replies.iter().all(|s| s.arg("box") == Some("alpha")));
    let done = r
        .last_said("tg.address_done")
        .expect("the fan-out says it finished");
    assert_eq!(done.arg("msg"), Some(msg.as_str()));
}

#[test]
fn a_sticky_target_follows_who_shows_it_and_production_is_never_reached() {
    let mut r = Rig::new();
    r.app.tg.store.data.marks.production = vec!["bravo".into()];
    r.link("owner", PHONE, Some(&["alpha", "bravo"]));
    let t0 = super::unix_ms();
    r.say_at_ms("/who", t0);
    assert!(r.last_said("tg.who_none").is_some());
    r.say_at_ms("/to @alpha", t0 + 1_000);
    assert_eq!(r.last_said("tg.to_set").unwrap().arg("to"), Some("@alpha"));
    r.say_at_ms("look at the parser", t0 + 2_000);
    assert!(
        r.last_said("tg.address_sent").is_some(),
        "{:?}",
        r.said_keys()
    );
    let tasks = r.tasks();
    assert_eq!(tasks, 1);
    // the next plain message goes to the same session, not a new one
    r.settle(t0 + 3_000, 4);
    r.say_at_ms("and the tests", t0 + 30_000);
    assert_eq!(r.tasks(), 1);
    r.say_at_ms("/who", t0 + 31_000);
    let w = r.last_said("tg.who").unwrap();
    assert_eq!(w.arg("to"), Some("@alpha"));
    assert!(w.arg("session").unwrap().starts_with("@alpha/"));
    // a Production box is never reached, by name or in the fleet
    let n = r.tg.texts_to(PHONE).len();
    r.say_at_ms("@bravo hello", t0 + 32_000);
    assert!(r.tg.texts_to(PHONE)[n..].join(" ").contains("Production"));
    r.say_at_ms("@fleet hello all", t0 + 33_000);
    let s = r.last_said("tg.address_fanout").unwrap();
    assert!(s.arg("skipped").unwrap().contains("production"), "{s:?}");
}

#[test]
fn a_worker_box_is_reached_through_the_hubs_channel_and_its_reply_is_attributed_and_redacted() {
    let mesh = Arc::new(FakeMesh::default());
    {
        let mut s = mesh.inner.lock().unwrap();
        s.workers = vec![
            Worker {
                name: "w1".into(),
                online: true,
                production: false,
            },
            Worker {
                name: "w2".into(),
                online: false,
                production: false,
            },
        ];
        // the worker's agent answers with a link and a key-shaped value: neither reaches the chat
        s.answer = format!(
            "see https://evil.example/x {}{} done: ",
            "gh", "p_abcdefghijklmnopqrstuvwxyz0123"
        );
    }
    let mut r = Rig::new();
    r.app.set_remote_agents(mesh.clone());
    r.link("owner", PHONE, Some(&["w1", "w2"]));
    let t0 = super::unix_ms();
    r.say_at_ms("@w1/s9 run the checks", t0);
    let sent = r.last_said("tg.address_sent").unwrap();
    let msg = sent.arg("msg").unwrap().to_string();
    {
        let s = mesh.inner.lock().unwrap();
        assert_eq!(s.sent.len(), 1);
        assert_eq!(s.sent[0].0, "w1");
        assert_eq!(s.sent[0].1, "s9");
        assert_eq!(s.sent[0].3, msg);
        assert!(
            !s.sent[0].4.is_empty(),
            "the worker is handed the signed delegation to check for itself"
        );
    }
    r.tick_at(t0 + 1_000);
    let reply = r.last_said("tg.reply_to").expect("the worker's reply");
    assert_eq!(reply.arg("box"), Some("w1"));
    assert_eq!(reply.arg("session"), Some("s9"));
    let text = reply.arg("text").unwrap();
    assert!(
        !text.contains("https://") && !text.contains("evil.example"),
        "{text}"
    );
    assert!(!text.contains("abcdefghijklmnop"), "{text}");
    // an offline worker is unreachable, said plainly
    r.say_at_ms("@w2 hello", t0 + 2_000);
    let un = r.last_said("tg.address_unreachable").unwrap();
    assert_eq!(un.arg("box"), Some("w2"));
}

#[test]
fn an_agents_reply_is_redacted_capped_and_at_metadata_says_only_that_it_answered() {
    let mut r = Rig::new();
    let secret = super::TOKEN;
    r.link("owner", PHONE, Some(&["alpha"]));
    let t0 = super::unix_ms();
    let shown = r.app.tg_agent_reply(
        PHONE,
        "alpha",
        "t1",
        None,
        &format!("here https://dash.example.com/approve and {secret} \u{1b}[31mred"),
        t0,
    );
    assert!(!shown.contains("https://dash.example.com"), "{shown}");
    assert!(!shown.contains('\u{1b}'));
    assert!(!shown.contains(secret), "{shown}");
    r.app
        .tg
        .store
        .data
        .marks
        .detail
        .insert("alpha".into(), "metadata".into());
    let meta = r
        .app
        .tg_agent_reply(PHONE, "alpha", "t1", None, "anything at all", t0);
    assert!(!meta.contains("anything at all"));
    assert_eq!(
        r.last_said("tg.reply_metadata").unwrap().arg("box"),
        Some("alpha")
    );
}

// ---------- the command line ----------

#[test]
fn ozbox_chat_lock_and_unlink_plan_from_the_store_and_the_dashboard_applies_them_on_its_next_tick()
{
    let mut r = Rig::new();
    let lid = r.link("owner", PHONE, Some(&["alpha"]));
    let dir = r.dir.path().to_path_buf();
    r.app.tg.requests_dir = Some(dir.clone());
    let planned = crate::chat_cli::plan(
        &r.app.tg.store,
        crate::chat_cli::RequestAct::Lock,
        Some(&lid),
        false,
    );
    assert_eq!(planned.len(), 1);
    assert!(crate::chat_cli::plan(
        &r.app.tg.store,
        crate::chat_cli::RequestAct::Lock,
        Some("nope"),
        false
    )
    .is_empty());
    crate::chat_cli::write_requests(&dir, crate::chat_cli::RequestAct::Lock, &planned).unwrap();
    r.tick();
    assert_eq!(
        r.app.tg.store.link(&lid).unwrap().state,
        crate::telegram_store::LinkState::Locked
    );
    // a locked link plans to nothing for a lock, and to one link for an unlink
    assert!(crate::chat_cli::plan(
        &r.app.tg.store,
        crate::chat_cli::RequestAct::Lock,
        None,
        true
    )
    .is_empty());
    let un = crate::chat_cli::plan(
        &r.app.tg.store,
        crate::chat_cli::RequestAct::Unlink,
        None,
        true,
    );
    crate::chat_cli::write_requests(&dir, crate::chat_cli::RequestAct::Unlink, &un).unwrap();
    r.tick();
    assert_eq!(
        r.app.tg.store.link(&lid).unwrap().state,
        crate::telegram_store::LinkState::Revoked
    );
    assert!(r.chain_text().contains("telegram.unlink"));
}
