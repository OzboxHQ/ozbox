//! Who is linked, what each chat is bound to, and what a command does. Pure: no clock, network or store of its own.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use super::command::Command;
use crate::messages::t;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Channel {
    Telegram,
    Dashboard,
    Slack,
    Whatsapp,
}

impl Channel {
    pub fn name(self) -> &'static str {
        match self {
            Channel::Telegram => "telegram",
            Channel::Dashboard => "dashboard",
            Channel::Slack => "slack",
            Channel::Whatsapp => "whatsapp",
        }
    }
}

/// A person's account in a channel that is not Telegram (Telegram chats are in the Telegram state).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ChatLink {
    pub channel: Channel,
    /// The channel's own id for the person: a Slack user id, a WhatsApp number.
    pub id: String,
    pub name: String,
    pub person: String,
}

/// What a chat is bound to.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum Bind {
    Task {
        id: String,
    },
    Terminal {
        box_name: String,
        session: String,
        force: bool,
    },
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct ChatState {
    pub links: Vec<ChatLink>,
    /// `<channel>:<id>` -> what that chat is bound to.
    pub binds: BTreeMap<String, Bind>,
    /// WhatsApp: when each number last wrote to us (free-form replies are allowed for 24 hours after).
    pub wa_inbound: BTreeMap<String, u64>,
    /// `<channel>:<id>` -> the address plain messages go to (`/to @alpha`), until it is changed. Sticky, per conversation.
    pub to: BTreeMap<String, String>,
    /// `<channel>:<id>` -> the other sessions this conversation hears from: the targets of an addressed message or a fan-out,
    /// beside the one it follows.
    pub watch: BTreeMap<String, Vec<Watch>>,
}

/// A session a conversation hears replies from because a message was addressed to it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Watch {
    pub task: String,
    pub box_name: String,
    /// The message id the reply answers (shown with the reply, so a fan-out's replies are grouped under it).
    pub msg_id: String,
    /// The message to thread the reply under, in the chat app's terms (a Telegram message id, a Slack `ts`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub thread: Option<String>,
}

pub fn conv_key(channel: Channel, id: &str) -> String {
    format!("{}:{}", channel.name(), id)
}

impl ChatState {
    /// The person a channel account is linked to.
    pub fn person_of(&self, channel: Channel, id: &str) -> Option<&str> {
        self.links
            .iter()
            .find(|l| l.channel == channel && l.id == id)
            .map(|l| l.person.as_str())
    }

    pub fn link(&mut self, l: ChatLink) {
        self.links
            .retain(|x| !(x.channel == l.channel && x.id == l.id));
        self.links.push(l);
    }

    pub fn unlink(&mut self, channel: Channel, id: &str) {
        self.links.retain(|x| !(x.channel == channel && x.id == id));
        self.binds.remove(&conv_key(channel, id));
    }
}

/// What the rules may read about a session.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TaskInfo {
    pub id: String,
    pub person: String,
    pub box_name: String,
    pub state: String,
    pub awaiting: bool,
    pub interactive: bool,
    pub turns: u32,
    pub spend: String,
    pub prompt: String,
}

pub trait World {
    fn task(&self, id: &str) -> Option<TaskInfo>;
    /// The person's sessions, newest first.
    fn tasks_of(&self, person: &str) -> Vec<TaskInfo>;
    fn has_box(&self, name: &str) -> bool;
    /// The one box there is, when there is exactly one: a fresh chat's plain text starts a session there.
    fn only_box(&self) -> Option<String>;
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Verb {
    Pause,
    Resume,
    Stop,
}

/// What the server must do for a command. Replies are words for the person.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Effect {
    Reply(String),
    Start {
        box_name: String,
        prompt: String,
    },
    Send {
        task: String,
        text: String,
    },
    Verb {
        task: String,
        verb: Verb,
    },
    Budget {
        task: String,
        cents: u64,
    },
    Log {
        task: String,
    },
    Sessions {
        box_name: Option<String>,
    },
    Attach {
        session: String,
        force: bool,
    },
    Adopt {
        session: String,
    },
    Type {
        box_name: String,
        session: String,
        text: String,
        force: bool,
    },
}

fn reply(k: &str, a: &[(&str, &str)]) -> Effect {
    Effect::Reply(t(k, a))
}

/// What one command does in a chat bound to `bind` for `person`. A change to the binding is made in place.
pub fn react(bind: &mut Option<Bind>, cmd: Command, person: &str, w: &dyn World) -> Vec<Effect> {
    let bound_task = |bind: &Option<Bind>| -> Result<TaskInfo, Effect> {
        match bind {
            Some(Bind::Task { id }) => match w.task(id) {
                Some(ti) if ti.person == person => Ok(ti),
                Some(_) => Err(reply("chat.not_yours", &[])),
                None => Err(reply("chat.no_such_task", &[("task", id)])),
            },
            _ => Err(reply("chat.nothing_bound", &[])),
        }
    };
    match cmd {
        Command::Help => vec![reply("chat.help", &[])],
        Command::Pair(_) => vec![reply("chat.paired", &[])],
        Command::Unknown(word) => vec![match word.as_str() {
            "new" => reply("chat.new_usage", &[]),
            "budget" => reply("chat.budget_usage", &[]),
            _ => reply("chat.unknown", &[("word", &word)]),
        }],
        Command::New { box_name, prompt } => {
            if !w.has_box(&box_name) {
                return vec![reply("chat.no_such_box", &[("box", &box_name)])];
            }
            vec![Effect::Start { box_name, prompt }]
        }
        Command::Say(text) => {
            if text.is_empty() {
                return Vec::new();
            }
            match bind.clone() {
                Some(Bind::Terminal {
                    box_name,
                    session,
                    force,
                }) => vec![Effect::Type {
                    box_name,
                    session,
                    text,
                    force,
                }],
                Some(Bind::Task { .. }) => match bound_task(bind) {
                    Ok(ti) if !ti.interactive => {
                        vec![reply("chat.not_a_conversation", &[("task", &ti.id)])]
                    }
                    Ok(ti) => vec![Effect::Send { task: ti.id, text }],
                    Err(e) => vec![e],
                },
                None => match w.only_box() {
                    Some(box_name) => vec![Effect::Start {
                        box_name,
                        prompt: text,
                    }],
                    None => vec![reply("chat.nothing_bound", &[])],
                },
            }
        }
        Command::Status => match bind {
            Some(Bind::Terminal { session, .. }) => {
                vec![reply("chat.attached", &[("session", session)])]
            }
            _ => match bound_task(bind) {
                Ok(ti) => vec![reply(
                    "chat.status",
                    &[
                        ("task", &ti.id),
                        ("box", &ti.box_name),
                        ("state", &ti.state),
                        (
                            "waiting",
                            &if ti.awaiting {
                                t("chat.status_waiting", &[])
                            } else {
                                String::new()
                            },
                        ),
                        ("turns", &ti.turns.to_string()),
                        ("spend", &ti.spend),
                    ],
                )],
                Err(e) => vec![e],
            },
        },
        Command::Log => match bound_task(bind) {
            Ok(ti) => vec![Effect::Log { task: ti.id }],
            Err(e) => vec![e],
        },
        Command::Stop | Command::Pause | Command::Resume => {
            if let (Some(Bind::Terminal { .. }), Command::Stop) = (&*bind, &cmd) {
                *bind = None;
                return vec![reply("chat.detached", &[])];
            }
            let verb = match cmd {
                Command::Pause => Verb::Pause,
                Command::Resume => Verb::Resume,
                _ => Verb::Stop,
            };
            match bound_task(bind) {
                Ok(ti) => vec![Effect::Verb { task: ti.id, verb }],
                Err(e) => vec![e],
            }
        }
        Command::Budget(cents) => match bound_task(bind) {
            Ok(ti) => vec![Effect::Budget { task: ti.id, cents }],
            Err(e) => vec![e],
        },
        Command::Tasks => {
            let list = w.tasks_of(person);
            if list.is_empty() {
                return vec![reply("chat.tasks_none", &[])];
            }
            let lines: Vec<String> = list
                .iter()
                .take(10)
                .map(|ti| {
                    t(
                        "chat.tasks_row",
                        &[
                            ("task", &ti.id),
                            ("state", &ti.state),
                            ("box", &ti.box_name),
                            ("prompt", &ti.prompt),
                        ],
                    )
                })
                .collect();
            vec![Effect::Reply(lines.join("\n"))]
        }
        Command::Switch(id) => match w.task(&id) {
            Some(ti) if ti.person == person => {
                *bind = Some(Bind::Task { id: ti.id.clone() });
                vec![reply("chat.switched", &[("task", &ti.id)])]
            }
            Some(_) => vec![reply("chat.not_yours", &[])],
            None => vec![reply("chat.no_such_task", &[("task", &id)])],
        },
        Command::Sessions(b) => vec![Effect::Sessions { box_name: b }],
        Command::Attach { session, force } => vec![Effect::Attach { session, force }],
        Command::Adopt(session) => vec![Effect::Adopt { session }],
        Command::Detach => {
            *bind = None;
            vec![reply("chat.detached", &[])]
        }
    }
}

/// `<box>:<pane>` -> (box, pane). The pane is a tmux pane id (`%` and digits).
pub fn split_session(s: &str) -> Option<(String, String)> {
    let (b, p) = s.split_once(':')?;
    let pane_ok = p
        .strip_prefix('%')
        .is_some_and(|d| !d.is_empty() && d.len() <= 8 && d.bytes().all(|c| c.is_ascii_digit()));
    let box_ok =
        !b.is_empty() && b.len() <= 63 && b.bytes().all(|c| c.is_ascii_alphanumeric() || c == b'-');
    (pane_ok && box_ok).then(|| (b.to_string(), p.to_string()))
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use crate::chat::command::parse;

    struct W {
        tasks: Vec<TaskInfo>,
        boxes: Vec<&'static str>,
    }
    fn ti(id: &str, person: &str, interactive: bool) -> TaskInfo {
        TaskInfo {
            id: id.into(),
            person: person.into(),
            box_name: "alpha".into(),
            state: "running".into(),
            awaiting: true,
            interactive,
            turns: 2,
            spend: "$0.10".into(),
            prompt: "fix".into(),
        }
    }
    impl World for W {
        fn task(&self, id: &str) -> Option<TaskInfo> {
            self.tasks.iter().find(|t| t.id == id).cloned()
        }
        fn tasks_of(&self, person: &str) -> Vec<TaskInfo> {
            self.tasks
                .iter()
                .filter(|t| t.person == person)
                .cloned()
                .collect()
        }
        fn has_box(&self, n: &str) -> bool {
            self.boxes.contains(&n)
        }
        fn only_box(&self) -> Option<String> {
            (self.boxes.len() == 1).then(|| self.boxes[0].to_string())
        }
    }
    fn world() -> W {
        W {
            tasks: vec![
                ti("t1", "ada", true),
                ti("t2", "bob", true),
                ti("t3", "ada", false),
            ],
            boxes: vec!["alpha"],
        }
    }

    #[test]
    fn new_starts_a_session_only_on_a_box_that_exists_and_plain_text_in_a_fresh_chat_uses_the_only_box(
    ) {
        let w = world();
        let mut b = None;
        assert_eq!(
            react(&mut b, parse("/new alpha fix it"), "ada", &w),
            vec![Effect::Start {
                box_name: "alpha".into(),
                prompt: "fix it".into()
            }]
        );
        assert!(
            matches!(&react(&mut b, parse("/new nope x"), "ada", &w)[0], Effect::Reply(r) if r.contains("nope"))
        );
        assert_eq!(
            react(&mut b, parse("do the thing"), "ada", &w),
            vec![Effect::Start {
                box_name: "alpha".into(),
                prompt: "do the thing".into()
            }]
        );
        let two = W {
            tasks: vec![],
            boxes: vec!["alpha", "bravo"],
        };
        assert!(
            matches!(
                &react(&mut b, parse("do the thing"), "ada", &two)[0],
                Effect::Reply(_)
            ),
            "two boxes: ask which"
        );
    }

    #[test]
    fn text_goes_to_the_bound_conversation_and_only_to_the_person_it_belongs_to() {
        let w = world();
        let mut b = Some(Bind::Task { id: "t1".into() });
        assert_eq!(
            react(&mut b, parse("and the tests"), "ada", &w),
            vec![Effect::Send {
                task: "t1".into(),
                text: "and the tests".into()
            }]
        );
        assert!(
            matches!(&react(&mut b, parse("and the tests"), "bob", &w)[0], Effect::Reply(r) if r.contains("someone else")),
            "another person's session"
        );
        let mut plain = Some(Bind::Task { id: "t3".into() });
        assert!(
            matches!(&react(&mut plain, parse("hi"), "ada", &w)[0], Effect::Reply(r) if r.contains("not a conversation"))
        );
        assert_eq!(
            react(&mut b, parse("/pause"), "ada", &w),
            vec![Effect::Verb {
                task: "t1".into(),
                verb: Verb::Pause
            }]
        );
        assert_eq!(
            react(&mut b, parse("/budget +5"), "ada", &w),
            vec![Effect::Budget {
                task: "t1".into(),
                cents: 500
            }]
        );
        let mut none = None;
        assert!(
            matches!(&react(&mut none, parse("/stop"), "ada", &w)[0], Effect::Reply(r) if r.contains("No session"))
        );
    }

    #[test]
    fn switch_follows_only_your_own_sessions_and_tasks_lists_only_yours() {
        let w = world();
        let mut b = None;
        assert!(
            matches!(&react(&mut b, parse("/switch t2"), "ada", &w)[0], Effect::Reply(r) if r.contains("someone else"))
        );
        assert_eq!(b, None);
        react(&mut b, parse("/switch t1"), "ada", &w);
        assert_eq!(b, Some(Bind::Task { id: "t1".into() }));
        let Effect::Reply(list) = &react(&mut b, parse("/tasks"), "ada", &w)[0] else {
            panic!()
        };
        assert!(list.contains("t1") && list.contains("t3") && !list.contains("t2"));
        react(&mut b, parse("/detach"), "ada", &w);
        assert_eq!(b, None);
    }

    #[test]
    fn a_terminal_binding_types_and_stop_lets_go_of_it() {
        let w = world();
        let mut b = Some(Bind::Terminal {
            box_name: "alpha".into(),
            session: "%3".into(),
            force: false,
        });
        assert_eq!(
            react(&mut b, parse("run the tests"), "ada", &w),
            vec![Effect::Type {
                box_name: "alpha".into(),
                session: "%3".into(),
                text: "run the tests".into(),
                force: false
            }]
        );
        assert!(matches!(
            &react(&mut b, parse("/stop"), "ada", &w)[0],
            Effect::Reply(_)
        ));
        assert_eq!(
            b, None,
            "/stop in a terminal chat detaches; it never kills the person's agent"
        );
    }

    #[test]
    fn a_session_reference_is_a_box_and_a_pane_and_nothing_else() {
        assert_eq!(
            split_session("alpha:%3"),
            Some(("alpha".into(), "%3".into()))
        );
        for bad in [
            "alpha",
            "alpha:3",
            "alpha:%3;ls",
            "al pha:%3",
            ":%3",
            "alpha:%",
        ] {
            assert_eq!(split_session(bad), None, "{bad}");
        }
    }

    #[test]
    fn links_and_binds_are_per_channel_and_unlinking_forgets_the_binding() {
        let mut s = ChatState::default();
        s.link(ChatLink {
            channel: Channel::Slack,
            id: "U1".into(),
            name: "Ada".into(),
            person: "ada".into(),
        });
        s.link(ChatLink {
            channel: Channel::Slack,
            id: "U1".into(),
            name: "Ada B".into(),
            person: "ada".into(),
        });
        assert_eq!(s.links.len(), 1);
        assert_eq!(s.person_of(Channel::Slack, "U1"), Some("ada"));
        assert_eq!(s.person_of(Channel::Whatsapp, "U1"), None);
        s.binds.insert(
            conv_key(Channel::Slack, "U1"),
            Bind::Task { id: "t1".into() },
        );
        s.unlink(Channel::Slack, "U1");
        assert!(s.links.is_empty() && s.binds.is_empty());
    }
}
