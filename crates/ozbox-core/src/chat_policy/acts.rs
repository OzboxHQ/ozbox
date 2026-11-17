//! The closed table of chat acts (ADR 0050 §1) and the one parser that turns a message into exactly one of them.
//!
//! Every message a linked person sends becomes one [`ChatAct`]. The table of acts is data ([`TABLE`]): one row per
//! [`ActId`], generated from a single list by [`acts!`], so an act that is not placed in the table does not compile. The
//! dashboard shows the same table (`act_table_json`) and a test compares its copy with this one.
//!
//! The parser is pure and strict. A word that is not in the table is [`ChatAct::Unknown`] and is refused; a command that
//! carries a bot suffix is accepted only for our own bot; a slash command with a typographic dash or quote in it (the
//! thing a phone keyboard makes of `--`) is refused rather than guessed at; plain text is a [`ChatAct::Converse`] turn and
//! is never read for words.

/// How much can go wrong with an act (ADR 0050 §1). The order is the order of power.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Tier {
    /// Look only.
    Read,
    /// Talk to a coding session.
    Converse,
    /// Start, pause or extend a box.
    Power,
    /// Run one command from the shipped catalogue.
    Run,
    /// Never done from chat: the person is sent to the dashboard.
    Handoff,
    /// Refused in words, always.
    Refused,
}

impl Tier {
    pub const fn name(self) -> &'static str {
        match self {
            Tier::Read => "read",
            Tier::Converse => "converse",
            Tier::Power => "power",
            Tier::Run => "run",
            Tier::Handoff => "handoff",
            Tier::Refused => "refused",
        }
    }

    /// The number the ADR uses (0 read, 1 converse, 2 power, 3 run, 4 handoff, 5 refused).
    pub const fn number(self) -> u8 {
        self as u8
    }
}

/// What a person must have switched on in the dashboard, with a passkey, before an act is allowed (ADR 0050 decision 2).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Needs {
    /// Nothing: a linked person may.
    Nothing,
    Converse,
    Power,
    Run,
}

impl Needs {
    pub const fn name(self) -> &'static str {
        match self {
            Needs::Nothing => "nothing",
            Needs::Converse => "converse",
            Needs::Power => "power",
            Needs::Run => "run",
        }
    }
}

/// One row of the table.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ActRow {
    /// A permanent key: audit records and the dashboard use it. Relabel, never rename.
    pub id: &'static str,
    /// What the person types, for the table in the dashboard.
    pub command: &'static str,
    pub tier: Tier,
    pub needs: Needs,
    /// An act that only makes Telegram less able (`/lock`, `/unlink`): allowed to anyone linked, even a locked link.
    pub safe: bool,
    /// Whether an executor for it exists in this release. An act that is allowed by the policy but has no executor is a
    /// handoff in words, never a bare "allowed" that does nothing.
    pub built: bool,
    /// The act is about one box (so a Production box, the hub and a delegation's box list matter).
    pub box_scoped: bool,
    /// One sentence for the table in the dashboard.
    pub about: &'static str,
}

macro_rules! acts {
    ($( $id:ident { key: $key:expr, cmd: $cmd:expr, tier: $tier:ident, needs: $needs:ident, safe: $safe:expr,
                    built: $built:expr, boxed: $boxed:expr, about: $about:expr } ),+ $(,)?) => {
        /// Every act, one variant each. Adding one adds a row to [`TABLE`]; there is no other place to forget.
        #[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
        pub enum ActId { $($id),+ }

        /// The table, in the order of [`ActId`].
        pub const TABLE: &[ActRow] = &[ $( ActRow {
            id: $key, command: $cmd, tier: Tier::$tier, needs: Needs::$needs, safe: $safe, built: $built,
            box_scoped: $boxed, about: $about,
        } ),+ ];

        impl ActId {
            pub const ALL: &'static [ActId] = &[ $(ActId::$id),+ ];
        }
    };
}

acts! {
    // ---- tier 0: read -------------------------------------------------------------------------------------------
    Status { key: "status", cmd: "/status", tier: Read, needs: Nothing, safe: false, built: true, boxed: false,
        about: "The fleet in one message, or the session this chat follows." },
    Fleet { key: "fleet", cmd: "/fleet", tier: Read, needs: Nothing, safe: false, built: true, boxed: false,
        about: "Every box and its state." },
    BoxList { key: "box.list", cmd: "/box list", tier: Read, needs: Nothing, safe: false, built: true, boxed: false,
        about: "Every box and its state." },
    Tasks { key: "tasks", cmd: "/tasks", tier: Read, needs: Nothing, safe: false, built: true, boxed: false,
        about: "Your sessions." },
    Log { key: "log", cmd: "/log", tier: Read, needs: Nothing, safe: false, built: true, boxed: false,
        about: "The last lines of the session this chat follows." },
    Sessions { key: "sessions", cmd: "/sessions [box]", tier: Read, needs: Nothing, safe: false, built: true, boxed: false,
        about: "Coding agents running in your repos." },
    Help { key: "help", cmd: "/help", tier: Read, needs: Nothing, safe: false, built: true, boxed: false,
        about: "What this chat can do for you." },
    Whoami { key: "whoami", cmd: "/whoami", tier: Read, needs: Nothing, safe: false, built: true, boxed: false,
        about: "Which person, role and delegations this chat is linked to." },
    Usage { key: "usage", cmd: "(a command with a missing or odd argument)", tier: Read, needs: Nothing, safe: false, built: true, boxed: false,
        about: "Says how the command is written; does nothing else." },
    Who { key: "who", cmd: "/who", tier: Read, needs: Nothing, safe: false, built: true, boxed: false,
        about: "Says which box, session or group your plain messages go to now." },
    Boxes { key: "boxes", cmd: "/boxes", tier: Read, needs: Nothing, safe: false, built: true, boxed: false,
        about: "The boxes you may talk to from this chat (never a Production box)." },
    Fleets { key: "fleets", cmd: "/fleets", tier: Read, needs: Nothing, safe: false, built: true, boxed: false,
        about: "The groups of boxes you may address, and how many of their boxes you may reach." },
    To { key: "to", cmd: "/to <@box | @box/session | @group | @fleet>", tier: Read, needs: Nothing, safe: false, built: true, boxed: false,
        about: "Sets where your plain messages go until you change it. Sending is still a converse act on each box." },
    Link { key: "link", cmd: "/link", tier: Read, needs: Nothing, safe: false, built: true, boxed: false,
        about: "Starts linking this Telegram account, only while a person has a pairing window open in the dashboard." },
    // ---- tier 1: converse ---------------------------------------------------------------------------------------
    Converse { key: "converse", cmd: "(plain text)", tier: Converse, needs: Converse, safe: false, built: true, boxed: true,
        about: "The next turn of the session this chat follows, under the chat profile." },
    Address { key: "address", cmd: "@<box> · @<box>/<session> · @<group> · @fleet <message>", tier: Converse, needs: Converse, safe: false, built: true, boxed: true,
        about: "A message to one session, a box's agent, a group or every box you may reach; each box is judged on its own." },
    New { key: "new", cmd: "/new <box> <what to do>", tier: Converse, needs: Converse, safe: false, built: true, boxed: true,
        about: "Starts a session on a running box." },
    SessionPause { key: "session.pause", cmd: "/pause · /session pause", tier: Converse, needs: Converse, safe: false, built: true, boxed: true,
        about: "Pauses the session this chat follows (not a box)." },
    SessionResume { key: "session.resume", cmd: "/resume · /session resume", tier: Converse, needs: Converse, safe: false, built: true, boxed: true,
        about: "Continues the session this chat follows (not a box)." },
    Switch { key: "switch", cmd: "/switch <session>", tier: Converse, needs: Converse, safe: false, built: true, boxed: true,
        about: "Follows another of your sessions." },
    Detach { key: "detach", cmd: "/detach", tier: Converse, needs: Converse, safe: false, built: true, boxed: false,
        about: "Lets go of the session this chat follows." },
    Attach { key: "attach", cmd: "/attach <session>", tier: Converse, needs: Converse, safe: false, built: true, boxed: true,
        about: "Types into a terminal session that is at or below the chat profile." },
    Adopt { key: "adopt", cmd: "/adopt <session>", tier: Converse, needs: Converse, safe: false, built: true, boxed: true,
        about: "Puts a terminal session on the board." },
    // ---- tier 2: power (a plan through the provider, applied only inside the delegation's caps) ---------------------
    BoxResume { key: "box.resume", cmd: "/box resume <box>", tier: Power, needs: Power, safe: false, built: true, boxed: true,
        about: "Starts a box that is paused, inside the caps." },
    BoxPause { key: "box.pause", cmd: "/box pause <box>", tier: Power, needs: Power, safe: false, built: true, boxed: true,
        about: "Pauses a box, only when it is idle." },
    BoxPauseWhenIdle { key: "box.pause.when_idle", cmd: "/box pause <box> when-idle", tier: Power, needs: Power, safe: false, built: false, boxed: true,
        about: "Pauses a box the next time it is idle, for up to two hours." },
    BoxPauseCancel { key: "box.pause.cancel", cmd: "/box pause <box> cancel", tier: Power, needs: Power, safe: false, built: false, boxed: true,
        about: "Cancels a pause that waits for the box to be idle." },
    BoxExtend { key: "box.extend", cmd: "/box extend <box> <hours>", tier: Power, needs: Power, safe: false, built: true, boxed: true,
        about: "Extends the auto-pause deadline of a chat-started box, once." },
    BoxCreate { key: "box.create", cmd: "/box create <name> <size or profile>", tier: Power, needs: Power, safe: false, built: true, boxed: false,
        about: "Creates a box at a size or from a saved profile, inside the caps (owner decision D14)." },
    BoxResize { key: "box.resize", cmd: "/box resize <box> <size>", tier: Power, needs: Power, safe: false, built: true, boxed: true,
        about: "Resizes a box inside the caps (owner decision D14)." },
    // ---- tier 3: run --------------------------------------------------------------------------------------------
    Run { key: "run", cmd: "/run <command from the catalogue>", tier: Run, needs: Run, safe: false, built: false, boxed: true,
        about: "Runs one read-only inspector from the shipped catalogue. Never a free-form command." },
    // ---- tier 4: handoff ----------------------------------------------------------------------------------------
    BoxClone { key: "box.clone", cmd: "/box clone", tier: Handoff, needs: Nothing, safe: false, built: true, boxed: false,
        about: "Sends you to the dashboard." },
    BoxSnapshot { key: "box.snapshot", cmd: "/box snapshot", tier: Handoff, needs: Nothing, safe: false, built: true, boxed: false,
        about: "Sends you to the dashboard." },
    BoxDestroy { key: "box.destroy", cmd: "/box destroy", tier: Handoff, needs: Nothing, safe: false, built: true, boxed: false,
        about: "Sends you to the dashboard." },
    // ---- the safe direction -------------------------------------------------------------------------------------
    Lock { key: "lock", cmd: "/lock", tier: Read, needs: Nothing, safe: true, built: true, boxed: false,
        about: "Refuses every act above reading from this link until a passkey in the dashboard lifts it." },
    Unlink { key: "unlink", cmd: "/unlink", tier: Read, needs: Nothing, safe: true, built: true, boxed: false,
        about: "Cuts this link." },
    // ---- tier 5: refused ----------------------------------------------------------------------------------------
    Approve { key: "refused.approve", cmd: "/approve", tier: Refused, needs: Nothing, safe: false, built: true, boxed: false,
        about: "Chat never approves anything; that is a passkey in the dashboard." },
    Deny { key: "refused.deny", cmd: "/deny", tier: Refused, needs: Nothing, safe: false, built: true, boxed: false,
        about: "Chat never denies or cancels a request." },
    Stop { key: "refused.stop", cmd: "/stop", tier: Refused, needs: Nothing, safe: false, built: true, boxed: false,
        about: "A run is stopped in the dashboard. (A box is paused with /box pause; there is no stop alias.)" },
    Budget { key: "refused.budget", cmd: "/budget", tier: Refused, needs: Nothing, safe: false, built: true, boxed: false,
        about: "A spending limit is raised in the dashboard." },
    Secrets { key: "refused.secrets", cmd: "/secret", tier: Refused, needs: Nothing, safe: false, built: true, boxed: false,
        about: "Secrets are never read, set, imported or exported from chat." },
    Governance { key: "refused.governance", cmd: "/policy · /role · /people · /settings · /allow · /tunnel", tier: Refused, needs: Nothing, safe: false, built: true, boxed: false,
        about: "Policy, roles, people, links of others, delegations, caps, the network allow-list and tunnels are the dashboard's." },
    Outbound { key: "refused.outbound", cmd: "/send · /push · /merge", tier: Refused, needs: Nothing, safe: false, built: true, boxed: false,
        about: "Outbound messages and pushes to a protected branch are never made from chat." },
    NotInTable { key: "refused.not_in_table", cmd: "(anything else)", tier: Refused, needs: Nothing, safe: false, built: true, boxed: false,
        about: "A word that is not in this table is refused." },
    Rejected { key: "refused.rejected", cmd: "(a malformed command)", tier: Refused, needs: Nothing, safe: false, built: true, boxed: false,
        about: "A command with a typographic dash or quote, a foreign bot's name or a control character is refused, not guessed at." },
}

impl ActId {
    pub fn row(self) -> &'static ActRow {
        &TABLE[self as usize]
    }

    pub fn key(self) -> &'static str {
        self.row().id
    }

    pub fn tier(self) -> Tier {
        self.row().tier
    }

    pub fn from_key(key: &str) -> Option<ActId> {
        ActId::ALL.iter().copied().find(|a| a.key() == key)
    }
}

/// Why a command line was refused before it was read as an act.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Reject {
    /// A typographic dash or quote (`—`, `–`, `“ ”`, `‘ ’`) in a slash command: a flag written that way is not the flag.
    NonAsciiPunctuation,
    /// `/run@other_bot`: a command addressed to a bot that is not ours.
    ForeignBot,
    /// A control character in the line.
    ControlCharacter,
    /// Longer than a command may be.
    TooLong,
}

impl Reject {
    pub const fn code(self) -> &'static str {
        match self {
            Reject::NonAsciiPunctuation => "non_ascii_punctuation",
            Reject::ForeignBot => "foreign_bot",
            Reject::ControlCharacter => "control_character",
            Reject::TooLong => "too_long",
        }
    }
}

/// What the person's message means. One value per message.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ChatAct {
    Status,
    Fleet,
    BoxList,
    Tasks,
    Log,
    Sessions(Option<String>),
    Help,
    Whoami,
    /// A command with a missing or odd argument: the key of the sentence that says how it is written.
    Usage(&'static str),
    Link,
    Who,
    Boxes,
    Fleets,
    To(super::address::Address),
    Converse(String),
    Address {
        to: super::address::Address,
        text: String,
    },
    New {
        box_name: String,
        prompt: String,
    },
    SessionPause,
    SessionResume,
    Switch(String),
    Detach,
    Attach {
        session: String,
        force: bool,
    },
    Adopt(String),
    BoxResume(String),
    BoxPause(String),
    BoxPauseWhenIdle(String),
    BoxPauseCancel(String),
    BoxExtend {
        box_name: String,
        hours: u8,
    },
    BoxCreate {
        box_name: String,
        /// A size (`M`) or the name of a saved box profile, which carries a size.
        size: String,
    },
    BoxResize {
        box_name: String,
        size: String,
    },
    /// The text after `/run`, exactly as written. It is not read here: the catalogue's parser (phase 4) is the only reader.
    Run(String),
    BoxClone,
    BoxSnapshot,
    BoxDestroy,
    Lock,
    Unlink,
    Approve,
    Deny,
    Stop,
    Budget,
    Secrets,
    Governance,
    Outbound,
    Unknown(String),
    Rejected(Reject),
}

impl ChatAct {
    pub fn id(&self) -> ActId {
        match self {
            ChatAct::Status => ActId::Status,
            ChatAct::Fleet => ActId::Fleet,
            ChatAct::BoxList => ActId::BoxList,
            ChatAct::Tasks => ActId::Tasks,
            ChatAct::Log => ActId::Log,
            ChatAct::Sessions(_) => ActId::Sessions,
            ChatAct::Help => ActId::Help,
            ChatAct::Whoami => ActId::Whoami,
            ChatAct::Usage(_) => ActId::Usage,
            ChatAct::Link => ActId::Link,
            ChatAct::Who => ActId::Who,
            ChatAct::Boxes => ActId::Boxes,
            ChatAct::Fleets => ActId::Fleets,
            ChatAct::To(_) => ActId::To,
            ChatAct::Converse(_) => ActId::Converse,
            ChatAct::Address { .. } => ActId::Address,
            ChatAct::New { .. } => ActId::New,
            ChatAct::SessionPause => ActId::SessionPause,
            ChatAct::SessionResume => ActId::SessionResume,
            ChatAct::Switch(_) => ActId::Switch,
            ChatAct::Detach => ActId::Detach,
            ChatAct::Attach { .. } => ActId::Attach,
            ChatAct::Adopt(_) => ActId::Adopt,
            ChatAct::BoxResume(_) => ActId::BoxResume,
            ChatAct::BoxPause(_) => ActId::BoxPause,
            ChatAct::BoxPauseWhenIdle(_) => ActId::BoxPauseWhenIdle,
            ChatAct::BoxPauseCancel(_) => ActId::BoxPauseCancel,
            ChatAct::BoxExtend { .. } => ActId::BoxExtend,
            ChatAct::BoxCreate { .. } => ActId::BoxCreate,
            ChatAct::BoxResize { .. } => ActId::BoxResize,
            ChatAct::Run(_) => ActId::Run,
            ChatAct::BoxClone => ActId::BoxClone,
            ChatAct::BoxSnapshot => ActId::BoxSnapshot,
            ChatAct::BoxDestroy => ActId::BoxDestroy,
            ChatAct::Lock => ActId::Lock,
            ChatAct::Unlink => ActId::Unlink,
            ChatAct::Approve => ActId::Approve,
            ChatAct::Deny => ActId::Deny,
            ChatAct::Stop => ActId::Stop,
            ChatAct::Budget => ActId::Budget,
            ChatAct::Secrets => ActId::Secrets,
            ChatAct::Governance => ActId::Governance,
            ChatAct::Outbound => ActId::Outbound,
            ChatAct::Unknown(_) => ActId::NotInTable,
            ChatAct::Rejected(_) => ActId::Rejected,
        }
    }

    pub fn row(&self) -> &'static ActRow {
        self.id().row()
    }

    /// The box the act names, when it names one.
    pub fn box_name(&self) -> Option<&str> {
        match self {
            ChatAct::New { box_name, .. }
            | ChatAct::BoxResume(box_name)
            | ChatAct::BoxPause(box_name)
            | ChatAct::BoxPauseWhenIdle(box_name)
            | ChatAct::BoxPauseCancel(box_name)
            | ChatAct::BoxExtend { box_name, .. }
            | ChatAct::BoxCreate { box_name, .. }
            | ChatAct::BoxResize { box_name, .. } => Some(box_name),
            ChatAct::Address {
                to: super::address::Address::Session { box_name, .. },
                ..
            } => Some(box_name),
            // a name that is a group fans out: each box is judged on its own by the bridge
            ChatAct::Address {
                to: super::address::Address::Name(n),
                ..
            } => Some(n),
            _ => None,
        }
    }
}

/// The longest slash command, in characters. Plain text (a turn for an agent) may be longer.
pub const MAX_COMMAND_CHARS: usize = 4096;
/// The longest plain message, in characters.
pub const MAX_TEXT_CHARS: usize = 16_000;

/// Characters that look like an ASCII dash or quote and are not one. In a slash command they are refused.
fn typographic(c: char) -> bool {
    matches!(
        c,
        '\u{2010}'..='\u{2015}'
            | '\u{2212}'
            | '\u{FE58}'
            | '\u{FE63}'
            | '\u{FF0D}'
            | '\u{2018}'..='\u{201F}'
            | '\u{00AB}'
            | '\u{00BB}'
            | '\u{2039}'
            | '\u{203A}'
            | '\u{FF02}'
            | '\u{FF07}'
    )
}

/// A box name as `ozbox_core::BoxName` takes it, checked cheaply: lowercase letters, digits and `-`, 1 to 63 characters.
pub fn box_name_ok(s: &str) -> bool {
    !s.is_empty() && s.len() <= 63 && s.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-')
}

fn word_ok(s: &str) -> bool {
    !s.is_empty() && s.len() <= 80 && s.bytes().all(|b| b.is_ascii_graphic())
}

/// Parse one message into one act. `own_bot` is our bot's username without the `@` (from `getMe`); a command addressed to
/// another bot, or to ours when it is not known, is refused.
pub fn parse_act(text: &str, own_bot: Option<&str>) -> ChatAct {
    let text = text.trim();
    if text.is_empty() {
        return ChatAct::Usage("chat.usage_empty");
    }
    if text
        .chars()
        .any(|c| c.is_control() && !matches!(c, '\n' | '\t' | '\r'))
    {
        return ChatAct::Rejected(Reject::ControlCharacter);
    }
    if let Some(rest) = text.strip_prefix('@') {
        // an address, then the message: `@alpha fix it`, `@alpha/t1 and then?`, `@fleet git status please`
        let (first, msg) = match rest.split_once(char::is_whitespace) {
            Some((f, m)) => (f, m.trim()),
            None => (rest, ""),
        };
        if first.chars().any(typographic) {
            return ChatAct::Rejected(Reject::NonAsciiPunctuation);
        }
        return match super::address::Address::parse(first) {
            Some(to) if !msg.is_empty() => ChatAct::Address {
                to,
                text: msg.chars().take(MAX_TEXT_CHARS).collect(),
            },
            _ => ChatAct::Usage("chat.usage_address"),
        };
    }
    if !text.starts_with('/') {
        return ChatAct::Converse(text.chars().take(MAX_TEXT_CHARS).collect());
    }
    if text.chars().count() > MAX_COMMAND_CHARS {
        return ChatAct::Rejected(Reject::TooLong);
    }
    if text.chars().any(typographic) {
        return ChatAct::Rejected(Reject::NonAsciiPunctuation);
    }
    let (first, rest) = match text.split_once(char::is_whitespace) {
        Some((f, r)) => (f, r.trim()),
        None => (text, ""),
    };
    let word = first.strip_prefix('/').unwrap_or(first);
    let (word, suffix) = match word.split_once('@') {
        Some((w, s)) => (w, Some(s)),
        None => (word, None),
    };
    if let Some(s) = suffix {
        match own_bot {
            Some(own) if s.eq_ignore_ascii_case(own) => {}
            _ => return ChatAct::Rejected(Reject::ForeignBot),
        }
    }
    let word = word.to_ascii_lowercase();
    let args: Vec<&str> = rest.split_whitespace().collect();
    match word.as_str() {
        "start" | "help" => ChatAct::Help,
        "whoami" => ChatAct::Whoami,
        "status" => ChatAct::Status,
        "fleet" => ChatAct::Fleet,
        "tasks" => ChatAct::Tasks,
        "log" => ChatAct::Log,
        "sessions" => match args.as_slice() {
            [] => ChatAct::Sessions(None),
            [b] if box_name_ok(b) => ChatAct::Sessions(Some((*b).to_string())),
            _ => ChatAct::Usage("chat.usage_sessions"),
        },
        "link" => ChatAct::Link,
        "who" => ChatAct::Who,
        "boxes" => ChatAct::Boxes,
        "fleets" | "groups" => ChatAct::Fleets,
        "to" => match args.as_slice() {
            [a] => super::address::Address::parse(a)
                .map_or(ChatAct::Usage("chat.usage_to"), ChatAct::To),
            _ => ChatAct::Usage("chat.usage_to"),
        },
        "lock" => ChatAct::Lock,
        "unlink" => ChatAct::Unlink,
        "detach" => ChatAct::Detach,
        "pause" => ChatAct::SessionPause,
        "resume" => ChatAct::SessionResume,
        "session" => match args.as_slice() {
            ["pause"] => ChatAct::SessionPause,
            ["resume"] => ChatAct::SessionResume,
            _ => ChatAct::Usage("chat.usage_session"),
        },
        "switch" => match args.as_slice() {
            [t] if word_ok(t) => ChatAct::Switch((*t).to_string()),
            _ => ChatAct::Usage("chat.usage_switch"),
        },
        "attach" => match args.as_slice() {
            [s] if word_ok(s) => ChatAct::Attach {
                session: (*s).to_string(),
                force: false,
            },
            [s, f] if word_ok(s) && f.eq_ignore_ascii_case("force") => ChatAct::Attach {
                session: (*s).to_string(),
                force: true,
            },
            _ => ChatAct::Usage("chat.usage_attach"),
        },
        "adopt" => match args.as_slice() {
            [s] if word_ok(s) => ChatAct::Adopt((*s).to_string()),
            _ => ChatAct::Usage("chat.usage_adopt"),
        },
        "new" => {
            let (b, prompt) = match rest.split_once(char::is_whitespace) {
                Some((b, p)) => (b, p.trim()),
                None => (rest, ""),
            };
            if box_name_ok(b) && !prompt.is_empty() {
                ChatAct::New {
                    box_name: b.to_string(),
                    prompt: prompt.chars().take(MAX_TEXT_CHARS).collect(),
                }
            } else {
                ChatAct::Usage("chat.new_usage")
            }
        }
        "box" => parse_box(&args),
        "run" => {
            if rest.is_empty() {
                ChatAct::Usage("chat.usage_run")
            } else {
                ChatAct::Run(rest.to_string())
            }
        }
        "approve" | "approval" | "approvals" | "grant" | "yes" | "confirm" => ChatAct::Approve,
        "deny" | "decline" | "reject" | "cancel" | "no" => ChatAct::Deny,
        "stop" | "kill" | "abort" => ChatAct::Stop,
        "budget" | "cap" | "limit" | "spend" => ChatAct::Budget,
        "secret" | "secrets" | "env" | "key" | "keys" | "token" | "password" => ChatAct::Secrets,
        "policy" | "role" | "roles" | "people" | "person" | "member" | "members" | "settings"
        | "config" | "delegate" | "delegation" | "tunnel" | "ingress" | "network" | "allow"
        | "allowlist" => ChatAct::Governance,
        "send" | "push" | "merge" | "publish" | "deploy" | "release" | "email" | "message" => {
            ChatAct::Outbound
        }
        other => ChatAct::Unknown(other.chars().take(20).collect()),
    }
}

fn parse_box(args: &[&str]) -> ChatAct {
    let usage = ChatAct::Usage("chat.usage_box");
    let Some((sub, rest)) = args.split_first() else {
        return usage;
    };
    let one_box = |rest: &[&str]| -> Option<String> {
        match rest {
            [b] if box_name_ok(b) => Some((*b).to_string()),
            _ => None,
        }
    };
    match sub.to_ascii_lowercase().as_str() {
        "list" | "ls" if rest.is_empty() => ChatAct::BoxList,
        "resume" | "start" | "wake" => one_box(rest).map_or(usage, ChatAct::BoxResume),
        "pause" => match rest {
            [b, mode] if box_name_ok(b) && mode.eq_ignore_ascii_case("when-idle") => {
                ChatAct::BoxPauseWhenIdle((*b).to_string())
            }
            [b, mode] if box_name_ok(b) && mode.eq_ignore_ascii_case("cancel") => {
                ChatAct::BoxPauseCancel((*b).to_string())
            }
            _ => one_box(rest).map_or(usage, ChatAct::BoxPause),
        },
        "extend" => match rest {
            [b, h] if box_name_ok(b) => match h.parse::<u8>() {
                Ok(hours) if (1..=2).contains(&hours) => ChatAct::BoxExtend {
                    box_name: (*b).to_string(),
                    hours,
                },
                _ => ChatAct::Usage("chat.usage_box_extend"),
            },
            _ => ChatAct::Usage("chat.usage_box_extend"),
        },
        "create" | "new" => match rest {
            [n, sz] if box_name_ok(n) && word_ok(sz) && !sz.starts_with('-') => {
                ChatAct::BoxCreate {
                    box_name: (*n).to_string(),
                    size: (*sz).to_string(),
                }
            }
            _ => ChatAct::Usage("chat.usage_box_create"),
        },
        "resize" => match rest {
            [b, s] if box_name_ok(b) && word_ok(s) && !s.starts_with('-') => ChatAct::BoxResize {
                box_name: (*b).to_string(),
                size: (*s).to_string(),
            },
            _ => ChatAct::Usage("chat.usage_box_resize"),
        },
        "clone" => ChatAct::BoxClone,
        "snapshot" | "backup" => ChatAct::BoxSnapshot,
        "destroy" | "delete" | "remove" | "rm" => ChatAct::BoxDestroy,
        // there is no `stop` alias for a pause: the word means only the refused act
        "stop" | "kill" => ChatAct::Stop,
        _ => usage,
    }
}

/// The table as JSON, for the dashboard (`packages/dashboard/src/api/chat-acts.ts` is generated from it).
pub fn act_table_json() -> serde_json::Value {
    serde_json::Value::Array(
        TABLE
            .iter()
            .map(|r| {
                serde_json::json!({
                    "id": r.id,
                    "command": r.command,
                    "tier": r.tier.name(),
                    "tierNumber": r.tier.number(),
                    "needs": r.needs.name(),
                    "safe": r.safe,
                    "built": r.built,
                    "box": r.box_scoped,
                    "about": r.about,
                })
            })
            .collect(),
    )
}

/// The dashboard's copy of the table, as TypeScript. A test in `ozbox-cli` compares `packages/dashboard/src/api/chat-acts.ts`
/// with this and fails when they differ; regenerate with `OZBOX_WRITE_CHAT_ACTS=1`.
pub fn act_table_ts() -> String {
    let q = |s: &str| serde_json::to_string(s).unwrap_or_default();
    let mut out = String::from(
        "// Generated from crates/ozbox-core/src/chat_policy/acts.rs (TABLE). Do not edit by hand: a Rust test compares this file\n// with the table and fails when they differ. Regenerate with `OZBOX_WRITE_CHAT_ACTS=1 cargo test -p ozbox-cli the_dashboards_copy_of_the_act_table`.\n\n",
    );
    out.push_str("export type ChatTier = 'read' | 'converse' | 'power' | 'run' | 'handoff' | 'refused';\nexport type ChatNeeds = 'nothing' | 'converse' | 'power' | 'run';\n\nexport interface ChatActRow {\n  id: string;\n  command: string;\n  tier: ChatTier;\n  tierNumber: number;\n  needs: ChatNeeds;\n  safe: boolean;\n  built: boolean;\n  box: boolean;\n  about: string;\n}\n\nexport const CHAT_ACTS: readonly ChatActRow[] = [\n");
    for r in TABLE {
        out.push_str(&format!(
            "  {{ id: {}, command: {}, tier: '{}', tierNumber: {}, needs: '{}', safe: {}, built: {}, box: {}, about: {} }},\n",
            q(r.id),
            q(r.command),
            r.tier.name(),
            r.tier.number(),
            r.needs.name(),
            r.safe,
            r.built,
            r.box_scoped,
            q(r.about)
        ));
    }
    out.push_str("] as const;\n");
    out
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn the_table_has_one_row_per_act_with_a_unique_permanent_key() {
        assert_eq!(TABLE.len(), ActId::ALL.len());
        let mut seen = std::collections::BTreeSet::new();
        for (i, a) in ActId::ALL.iter().enumerate() {
            assert_eq!(*a as usize, i, "the table is in the order of the enum");
            assert!(seen.insert(a.key()), "{} twice", a.key());
            assert_eq!(ActId::from_key(a.key()), Some(*a));
        }
    }

    #[test]
    fn every_row_obeys_the_shape_of_its_tier() {
        for a in ActId::ALL {
            let r = a.row();
            match r.tier {
                Tier::Converse => assert_eq!(r.needs, Needs::Converse, "{}", r.id),
                Tier::Power => assert_eq!(r.needs, Needs::Power, "{}", r.id),
                Tier::Run => assert_eq!(r.needs, Needs::Run, "{}", r.id),
                Tier::Read | Tier::Handoff | Tier::Refused => {
                    assert_eq!(r.needs, Needs::Nothing, "{}", r.id)
                }
            }
            if r.safe {
                assert_eq!(r.tier, Tier::Read, "a safe act only reduces power");
            }
            // an act whose executor is not built cannot be one that a person can reach by accident
            if !r.built {
                assert!(matches!(r.tier, Tier::Power | Tier::Run), "{}", r.id);
            }
        }
        for a in [ActId::Run, ActId::BoxPauseWhenIdle, ActId::BoxPauseCancel] {
            assert!(!a.row().built, "{}", a.key());
        }
        for a in [
            ActId::BoxResume,
            ActId::BoxPause,
            ActId::BoxExtend,
            ActId::BoxCreate,
            ActId::BoxResize,
        ] {
            assert!(a.row().built, "{}", a.key());
        }
    }

    #[test]
    fn an_address_then_words_is_a_message_to_that_target_and_to_and_who_set_and_show_it() {
        use super::super::address::Address;
        let own = Some("oz_bot");
        assert_eq!(
            parse_act("@alpha/t1 and then?", own),
            ChatAct::Address {
                to: Address::Session {
                    box_name: "alpha".into(),
                    session: "t1".into()
                },
                text: "and then?".into()
            }
        );
        assert_eq!(
            parse_act("@fleet git status please", own).id(),
            ActId::Address
        );
        assert_eq!(
            parse_act("@alpha", own),
            ChatAct::Usage("chat.usage_address")
        );
        assert_eq!(
            parse_act("@$(id) hi", own),
            ChatAct::Usage("chat.usage_address")
        );
        assert_eq!(
            parse_act("/to @web", own),
            ChatAct::To(Address::Name("web".into()))
        );
        assert_eq!(parse_act("/to", own), ChatAct::Usage("chat.usage_to"));
        assert_eq!(parse_act("/who", own), ChatAct::Who);
        assert_eq!(parse_act("/boxes", own), ChatAct::Boxes);
        assert_eq!(parse_act("/fleets", own), ChatAct::Fleets);
        assert_eq!(
            parse_act("/box create gamma m", own),
            ChatAct::BoxCreate {
                box_name: "gamma".into(),
                size: "m".into()
            }
        );
        assert_eq!(
            parse_act("/box resize alpha -x", own),
            ChatAct::Usage("chat.usage_box_resize")
        );
    }

    #[test]
    fn plain_text_is_a_turn_and_commands_are_read_exactly() {
        let own = Some("oz_bot");
        assert_eq!(
            parse_act("fix the parser", own),
            ChatAct::Converse("fix the parser".into())
        );
        assert_eq!(parse_act("/status@oz_bot", own), ChatAct::Status);
        assert_eq!(parse_act("/STATUS@OZ_BOT", own), ChatAct::Status);
        assert_eq!(
            parse_act("/box resume alpha", own),
            ChatAct::BoxResume("alpha".into())
        );
        assert_eq!(
            parse_act("/box pause alpha when-idle", own),
            ChatAct::BoxPauseWhenIdle("alpha".into())
        );
        assert_eq!(
            parse_act("/box pause alpha cancel", own),
            ChatAct::BoxPauseCancel("alpha".into())
        );
        assert_eq!(
            parse_act("/box extend alpha 2", own),
            ChatAct::BoxExtend {
                box_name: "alpha".into(),
                hours: 2
            }
        );
        assert_eq!(
            parse_act("/box extend alpha 3", own),
            ChatAct::Usage("chat.usage_box_extend")
        );
        assert_eq!(
            parse_act("/new alpha fix it", own),
            ChatAct::New {
                box_name: "alpha".into(),
                prompt: "fix it".into()
            }
        );
        assert_eq!(
            parse_act("/new alpha", own),
            ChatAct::Usage("chat.new_usage")
        );
        assert_eq!(parse_act("/pause", own), ChatAct::SessionPause);
        assert_eq!(
            parse_act("/run git status", own),
            ChatAct::Run("git status".into())
        );
        assert_eq!(parse_act("/lock", own), ChatAct::Lock);
    }

    #[test]
    fn a_command_for_another_bot_or_with_a_typographic_dash_is_refused_not_guessed() {
        let own = Some("oz_bot");
        assert_eq!(
            parse_act("/run@other_bot git status", own),
            ChatAct::Rejected(Reject::ForeignBot)
        );
        assert_eq!(
            parse_act("/status@oz_bot", None),
            ChatAct::Rejected(Reject::ForeignBot),
            "our own name is not known: no suffix is ours"
        );
        for dash in ['\u{2013}', '\u{2014}', '\u{2212}', '\u{2010}', '\u{FF0D}'] {
            let t = format!("/run git log {dash}{dash}oneline");
            assert_eq!(
                parse_act(&t, own),
                ChatAct::Rejected(Reject::NonAsciiPunctuation),
                "{t:?}"
            );
        }
        for q in ['\u{201C}', '\u{201D}', '\u{2018}', '\u{2019}'] {
            let t = format!("/run echo {q}hi{q}");
            assert_eq!(
                parse_act(&t, own),
                ChatAct::Rejected(Reject::NonAsciiPunctuation)
            );
        }
        // plain text is not a command: a typographic dash in a sentence for an agent is just a sentence
        assert!(matches!(
            parse_act("fix it \u{2014} now", own),
            ChatAct::Converse(_)
        ));
        assert_eq!(
            parse_act("/status\u{0007}", own),
            ChatAct::Rejected(Reject::ControlCharacter)
        );
        assert_eq!(
            parse_act(&format!("/run {}", "a".repeat(5000)), own),
            ChatAct::Rejected(Reject::TooLong)
        );
    }

    #[test]
    fn every_refused_word_is_a_refused_act_and_an_unknown_word_is_not_in_the_table() {
        let own = Some("oz_bot");
        for (w, id) in [
            ("/approve", ActId::Approve),
            ("/approve now", ActId::Approve),
            ("/deny", ActId::Deny),
            ("/cancel", ActId::Deny),
            ("/stop", ActId::Stop),
            ("/box stop alpha", ActId::Stop),
            ("/budget +5", ActId::Budget),
            ("/secret list", ActId::Secrets),
            ("/policy", ActId::Governance),
            ("/role bob owner", ActId::Governance),
            ("/tunnel", ActId::Governance),
            ("/send hello", ActId::Outbound),
            ("/push origin main", ActId::Outbound),
            ("/frobnicate", ActId::NotInTable),
        ] {
            let act = parse_act(w, own);
            assert_eq!(act.id(), id, "{w}");
            assert_eq!(act.row().tier, Tier::Refused, "{w}");
        }
    }

    #[test]
    fn no_command_word_parses_to_two_acts_and_the_json_has_every_row() {
        let j = act_table_json();
        assert_eq!(j.as_array().map(Vec::len), Some(TABLE.len()));
        // create and resize are power (owner decision D14); clone, snapshot and destroy are always the dashboard's
        assert_eq!(ActId::BoxCreate.tier(), Tier::Power);
        assert_eq!(ActId::BoxResize.tier(), Tier::Power);
        for a in [ActId::BoxClone, ActId::BoxSnapshot, ActId::BoxDestroy] {
            assert_eq!(a.tier(), Tier::Handoff);
        }
        // `/run` is only ever the catalogue: there is no free-form tier
        assert_eq!(ActId::Run.row().needs, Needs::Run);
    }
}
