//! The permission engine: one place that answers "may this actor do this here, now?".
//!
//! Every actor goes through [`decide`]: the dashboard, the command line, the MCP tools, the chat gateway and the run
//! supervisor. It is a pure function from the configuration ([`PermConfig`]), a description of the situation ([`Ctx`]), an
//! [`Action`] and the clock to a [`Decision`] (allow, ask or deny, with the reason and the rule that decided).
//!
//! The order is fixed, and it is the whole design:
//!
//! 1. **A deny rule that matches wins**, whatever else matches and whatever the mode.
//! 2. **Production needs a grant.** An action on something tagged production, other than a read, is refused unless an
//!    active [`Grant`] covers it: time-boxed, with a reason, bound to one box, project, run or orchestration, never
//!    extended, never inherited by a schedule or trigger unless it says so.
//! 3. **Plan only** refuses everything but reads.
//! 4. **The most specific matching rule decides** (narrower scope, then more conditions, then a longer literal pattern);
//!    at equal specificity `ask` beats `allow`.
//! 5. **No rule: the mode decides.** `ask` (the default) lets routine things through and asks about the rest;
//!    `accept_edits` also lets file edits through; `auto` lets everything through except what always needs a person
//!    (messages out, secrets, settings, destroying a box, granting) and never applies to a schedule or trigger.
//!
//! Nothing here reads a clock, a file or a secret; the callers do, and record the outcome in the audit chain
//! ([`audit_event`]) with ids and words only.

use std::collections::BTreeSet;

use serde::{Deserialize, Serialize};

use crate::approvals::starts_with_words;

/// The longest a Production grant may last, in minutes. Hours, not days.
pub const MAX_GRANT_MINUTES: u64 = 240;
pub const MAX_RULES: usize = 200;
pub const MAX_MODES: usize = 100;
/// Active grants at once.
pub const MAX_ACTIVE_GRANTS: usize = 20;
/// Grants kept in the store (older expired and revoked ones are dropped; the audit chain keeps their record).
pub const MAX_GRANTS_KEPT: usize = 200;
pub const MIN_REASON_CHARS: usize = 8;

/// How much an agent or person may do without being asked.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Mode {
    /// Routine things go through; the rest asks. The default.
    #[default]
    Ask,
    /// Reads only. Anything that changes something is refused.
    PlanOnly,
    /// As `ask`, and file edits go through.
    AcceptEdits,
    /// Everything goes through except what always needs a person. Rules and the Production gate still apply, and a
    /// schedule or trigger is never given this mode.
    Auto,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Effect {
    Allow,
    Ask,
    Deny,
}

#[derive(
    Debug, Clone, Copy, Default, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize,
)]
#[serde(rename_all = "snake_case")]
pub enum Environment {
    #[default]
    Sandbox,
    Staging,
    Production,
}

/// What a rule or a mode setting applies to. A narrower scope outranks a wider one.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Scope {
    /// Everyone (no id) or one person (their id).
    Person,
    Box,
    Project,
    Orchestration,
    Run,
}

impl Scope {
    pub const ALL: [Scope; 5] = [
        Scope::Person,
        Scope::Box,
        Scope::Project,
        Scope::Orchestration,
        Scope::Run,
    ];
}

/// Something an actor wants to do.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
pub enum Action {
    #[serde(rename = "file.read")]
    FileRead,
    #[serde(rename = "file.write")]
    FileWrite,
    #[serde(rename = "command.run")]
    CommandRun,
    #[serde(rename = "git.push")]
    GitPush,
    #[serde(rename = "pr.open")]
    PrOpen,
    #[serde(rename = "message.send")]
    MessageSend,
    #[serde(rename = "spend")]
    Spend,
    #[serde(rename = "resource.touch")]
    ResourceTouch,
    #[serde(rename = "run.start")]
    RunStart,
    #[serde(rename = "run.stop")]
    RunStop,
    #[serde(rename = "box.create")]
    BoxCreate,
    #[serde(rename = "box.change")]
    BoxChange,
    #[serde(rename = "box.destroy")]
    BoxDestroy,
    #[serde(rename = "secret.use")]
    SecretUse,
    #[serde(rename = "secret.write")]
    SecretWrite,
    #[serde(rename = "approval.decide")]
    ApprovalDecide,
    #[serde(rename = "settings.change")]
    SettingsChange,
    #[serde(rename = "grant.create")]
    GrantCreate,
    /// A call to a tool an agent reached over MCP (shell, git, files, browser, CI, a staging read ...). Which tool and
    /// server, and whether it reads or writes, are in the [`Ctx`]; an unknown tool is treated as a write.
    #[serde(rename = "tool.call")]
    ToolCall,
    /// Looking at a browser session, live or recorded (the pictures are what is on a person's screen). A dashboard act: it
    /// is decided by a person's role (`roles`), never by an agent's rules, so it is not in [`Action::ALL`].
    #[serde(rename = "browser.watch")]
    BrowserWatch,
    /// Taking over, resuming, typing into or closing a browser session. A dashboard act, as above.
    #[serde(rename = "browser.control")]
    BrowserControl,
    /// Changing which role a person has. A dashboard act, as above.
    #[serde(rename = "people.manage")]
    PeopleManage,
}

impl Action {
    pub const ALL: [Action; 19] = [
        Action::FileRead,
        Action::FileWrite,
        Action::CommandRun,
        Action::GitPush,
        Action::PrOpen,
        Action::MessageSend,
        Action::Spend,
        Action::ResourceTouch,
        Action::RunStart,
        Action::RunStop,
        Action::BoxCreate,
        Action::BoxChange,
        Action::BoxDestroy,
        Action::SecretUse,
        Action::SecretWrite,
        Action::ApprovalDecide,
        Action::SettingsChange,
        Action::GrantCreate,
        Action::ToolCall,
    ];

    /// The acts only a person at the dashboard does, decided by their role. Not offered to an agent's rules.
    pub const DASHBOARD: [Action; 3] = [
        Action::BrowserWatch,
        Action::BrowserControl,
        Action::PeopleManage,
    ];

    pub fn name(self) -> &'static str {
        match self {
            Action::BrowserWatch => "browser.watch",
            Action::BrowserControl => "browser.control",
            Action::PeopleManage => "people.manage",
            Action::FileRead => "file.read",
            Action::FileWrite => "file.write",
            Action::CommandRun => "command.run",
            Action::GitPush => "git.push",
            Action::PrOpen => "pr.open",
            Action::MessageSend => "message.send",
            Action::Spend => "spend",
            Action::ResourceTouch => "resource.touch",
            Action::RunStart => "run.start",
            Action::RunStop => "run.stop",
            Action::BoxCreate => "box.create",
            Action::BoxChange => "box.change",
            Action::BoxDestroy => "box.destroy",
            Action::SecretUse => "secret.use",
            Action::SecretWrite => "secret.write",
            Action::ApprovalDecide => "approval.decide",
            Action::SettingsChange => "settings.change",
            Action::GrantCreate => "grant.create",
            Action::ToolCall => "tool.call",
        }
    }

    /// Changes something (everything but a read). A tool call is a read only when the tool says so.
    pub fn changes(self, ctx: &Ctx) -> bool {
        match self {
            // Reading changes nothing. Starting or stopping a run, and deciding an approval, are the person's own acts: what
            // the run then does is decided action by action, so plan-only and the production gate act there.
            Action::FileRead
            | Action::RunStart
            | Action::RunStop
            | Action::ApprovalDecide
            | Action::BrowserWatch => false,
            Action::ToolCall => ctx.writes != Some(false),
            _ => true,
        }
    }

    /// Goes through in `ask` mode unless the approval policy singled it out.
    fn routine(self, ctx: &Ctx) -> bool {
        (self == Action::ToolCall && ctx.writes == Some(false))
            || matches!(
                self,
                Action::FileRead
                    | Action::CommandRun
                    | Action::GitPush
                    | Action::PrOpen
                    | Action::RunStart
                    | Action::RunStop
            )
    }

    /// Needs a person even in `auto`.
    fn always_asks(self) -> bool {
        matches!(
            self,
            Action::MessageSend
                | Action::Spend
                | Action::BoxDestroy
                | Action::SecretWrite
                | Action::SecretUse
                | Action::ApprovalDecide
                | Action::SettingsChange
                | Action::GrantCreate
                | Action::ResourceTouch
        )
    }
}

/// Who is acting.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ActorKind {
    /// A person, at the dashboard or the command line.
    #[default]
    Person,
    /// An agent run someone started.
    Agent,
    /// A person writing from a chat app.
    Chat,
    /// An agent connected over MCP.
    Mcp,
    /// A run a schedule started. Nobody is watching.
    Schedule,
    /// A run an event trigger started. Nobody is watching.
    Trigger,
    /// A coding agent in this box's terminal, through the door of ADR 0043. Anything running as the box user can be this
    /// actor, so it gets no standing permission: never `auto`, and no grant covers it. Every risky act asks the person.
    Terminal,
    /// The same door, after the person turned on standing permissions for terminal agents for a short while (the setting
    /// says until when). It is `Mcp`-like then: the mode and the box's grants apply. The setting's end ends it.
    TerminalStanding,
}

impl ActorKind {
    /// Nobody is at the keyboard: `auto` is never granted and a grant must say it covers this.
    pub fn unattended(self) -> bool {
        matches!(self, ActorKind::Schedule | ActorKind::Trigger)
    }

    /// Whatever the person decided in advance (`auto` mode, a box grant) does not apply to this actor: it asks every time.
    pub fn no_standing_permission(self) -> bool {
        self == ActorKind::Terminal
    }

    /// A coding agent that came through the terminal door (with or without standing permission).
    pub fn is_terminal(self) -> bool {
        matches!(self, ActorKind::Terminal | ActorKind::TerminalStanding)
    }
}

/// The situation an action happens in.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Ctx {
    /// The person the action is for (who asked, or who is signed in).
    pub person: String,
    pub actor: ActorKind,
    pub box_name: Option<String>,
    pub project: Option<String>,
    pub run_id: Option<String>,
    pub orchestration: Option<String>,
    pub env: Environment,
    /// A file path inside the box, for a rule on paths.
    pub path: Option<String>,
    /// The program and arguments, for a rule on commands. Never stored.
    pub command: Option<Vec<String>>,
    /// For a tool call: the tool's name (`git_push`, `shell`) and the MCP server that offers it. Names only.
    pub tool: Option<String>,
    pub server: Option<String>,
    /// For a tool call: does it change anything? `None` is unknown, and unknown counts as a change.
    pub writes: Option<bool>,
    /// The approval policy singled this action out (protected branch, ask-list command, spend above the threshold ...).
    pub sensitive: bool,
}

/// One rule. Only the conditions that are set are checked; more conditions make a rule more specific.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Rule {
    #[serde(default)]
    pub id: String,
    pub effect: Effect,
    /// An action name, or a pattern with `*` (`git.*`, `*`).
    pub action: String,
    pub scope: Scope,
    /// The person, box, project, orchestration or run the scope names. Empty for everyone (`person` scope only).
    #[serde(default)]
    pub scope_id: Option<String>,
    /// A path pattern (`*` matches anything).
    #[serde(default)]
    pub path: Option<String>,
    /// The words a command starts with (`git push`, `rm -rf`), in any order after the program.
    #[serde(default)]
    pub command: Option<String>,
    #[serde(default)]
    pub env: Option<Environment>,
    /// A tool-name pattern (`git_*`, `shell`); only tool calls carry one.
    #[serde(default)]
    pub tool: Option<String>,
    /// An MCP server-name pattern.
    #[serde(default)]
    pub server: Option<String>,
    #[serde(default)]
    pub note: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ModeSetting {
    pub scope: Scope,
    #[serde(default)]
    pub scope_id: Option<String>,
    pub mode: Mode,
}

/// How a person confirmed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SecondFactor {
    /// A passkey or authenticator code shown moments ago to the sign-in layer.
    StepUp,
    /// The person typed the name of what they were granting. **Not** a second factor.
    TypedConfirmation,
    /// Signed-out (local) mode: there is no second factor to ask for. **Not** a second factor.
    NoSignIn,
}

impl SecondFactor {
    pub fn is_real(self) -> bool {
        self == SecondFactor::StepUp
    }
}

/// Leave to act on something tagged production, for a short time.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Grant {
    pub id: String,
    /// Who gave it.
    pub granted_by: String,
    /// Box, project, run or orchestration: never wider.
    pub scope: Scope,
    pub scope_id: String,
    /// The actions it covers (names or patterns); `*` for all.
    pub actions: Vec<String>,
    pub reason: String,
    pub created_ms: u64,
    /// Fixed when it is made. Nothing moves it.
    pub expires_ms: u64,
    pub factor: SecondFactor,
    /// Covers runs started by a schedule or a trigger.
    #[serde(default)]
    pub allow_unattended: bool,
    #[serde(default)]
    pub max_uses: Option<u32>,
    #[serde(default)]
    pub uses: u32,
    #[serde(default)]
    pub revoked_ms: Option<u64>,
    #[serde(default)]
    pub revoked_by: Option<String>,
}

impl Grant {
    pub fn is_active(&self, now_ms: u64) -> bool {
        self.revoked_ms.is_none()
            && now_ms < self.expires_ms
            && self.max_uses.is_none_or(|m| self.uses < m)
    }

    pub fn state(&self, now_ms: u64) -> &'static str {
        if self.revoked_ms.is_some() {
            "revoked"
        } else if now_ms >= self.expires_ms {
            "expired"
        } else if self.max_uses.is_some_and(|m| self.uses >= m) {
            "used"
        } else {
            "active"
        }
    }

    fn covers(&self, ctx: &Ctx, action: Action, now_ms: u64) -> bool {
        self.reaches(ctx, now_ms) && self.actions.iter().any(|p| glob(p, action.name()))
    }

    /// Is this grant active and does its scope take in the situation, whatever actions it names? A chat app is never covered
    /// by a standing permission (it is held in the dashboard, by a person), and an unattended run only by a grant that says so.
    fn reaches(&self, ctx: &Ctx, now_ms: u64) -> bool {
        if !self.is_active(now_ms) || ctx.actor == ActorKind::Chat {
            return false;
        }
        if ctx.actor.unattended() && !self.allow_unattended {
            return false;
        }
        // a terminal agent that was not given standing permission is covered by no grant, whatever the grant says
        if ctx.actor.no_standing_permission() {
            return false;
        }
        match self.scope {
            Scope::Box => ctx.box_name.as_deref() == Some(self.scope_id.as_str()),
            Scope::Project => ctx.project.as_deref() == Some(self.scope_id.as_str()),
            Scope::Run => ctx.run_id.as_deref() == Some(self.scope_id.as_str()),
            Scope::Orchestration => ctx.orchestration.as_deref() == Some(self.scope_id.as_str()),
            Scope::Person => false,
        }
    }
}

/// What a person asks for when they make a grant.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NewGrant {
    pub granted_by: String,
    pub scope: Scope,
    pub scope_id: String,
    pub actions: Vec<String>,
    pub reason: String,
    pub minutes: u64,
    pub factor: SecondFactor,
    pub allow_unattended: bool,
    pub max_uses: Option<u32>,
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum PermError {
    #[error("{0}")]
    Invalid(String),
    #[error("no such grant")]
    NoSuchGrant,
    #[error("that grant was already revoked")]
    AlreadyRevoked,
}

/// The whole permission configuration, kept in the task store.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct PermConfig {
    pub default_mode: Mode,
    pub modes: Vec<ModeSetting>,
    pub rules: Vec<Rule>,
    pub grants: Vec<Grant>,
    pub next_id: u64,
    /// Hosts the browser tools may fetch besides this box's own loopback (`example.com`, or `*.example.com`).
    pub browser_hosts: Vec<String>,
}

impl Default for PermConfig {
    fn default() -> Self {
        Self {
            default_mode: Mode::Ask,
            modes: Vec::new(),
            rules: Vec::new(),
            grants: Vec::new(),
            next_id: 0,
            browser_hosts: Vec::new(),
        }
    }
}

/// The part a person edits: modes and rules. Grants are made and revoked one at a time.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PermSettings {
    pub default_mode: Mode,
    #[serde(default)]
    pub modes: Vec<ModeSetting>,
    #[serde(default)]
    pub rules: Vec<Rule>,
    /// Hosts the browser tools may fetch besides this box's own loopback.
    #[serde(default)]
    pub browser_hosts: Vec<String>,
}

/// `*` matches any run of characters, everything else matches itself.
pub fn glob(pattern: &str, text: &str) -> bool {
    let p: Vec<char> = pattern.chars().collect();
    let t: Vec<char> = text.chars().collect();
    let (mut pi, mut ti) = (0usize, 0usize);
    let (mut star, mut mark) = (None::<usize>, 0usize);
    while ti < t.len() {
        if pi < p.len() && p[pi] == '*' {
            star = Some(pi);
            mark = ti;
            pi += 1;
        } else if pi < p.len() && p[pi] == t[ti] {
            pi += 1;
            ti += 1;
        } else if let Some(s) = star {
            pi = s + 1;
            mark += 1;
            ti = mark;
        } else {
            return false;
        }
    }
    while pi < p.len() && p[pi] == '*' {
        pi += 1;
    }
    pi == p.len()
}

fn valid_word(s: &str, max: usize) -> bool {
    !s.is_empty() && s.len() <= max && s.chars().all(|c| c.is_ascii_graphic() || c == ' ')
}

fn valid_id(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= 64
        && s.chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.' | '@' | ':'))
}

impl Rule {
    fn applies(&self, ctx: &Ctx, action: Action) -> bool {
        if !glob(&self.action, action.name()) {
            return false;
        }
        if !scope_matches(self.scope, self.scope_id.as_deref(), ctx) {
            return false;
        }
        if let Some(e) = self.env {
            if ctx.env != e {
                return false;
            }
        }
        if let Some(t) = &self.tool {
            match &ctx.tool {
                Some(tool) if glob(t, tool) => {}
                _ => return false,
            }
        }
        if let Some(sv) = &self.server {
            match &ctx.server {
                Some(server) if glob(sv, server) => {}
                _ => return false,
            }
        }
        if let Some(p) = &self.path {
            match &ctx.path {
                Some(path) if glob(p, path) => {}
                _ => return false,
            }
        }
        if let Some(c) = &self.command {
            match &ctx.command {
                Some(argv) if starts_with_words(argv, c) => {}
                _ => return false,
            }
        }
        true
    }

    /// Higher is more specific: scope first, then how many conditions it sets, then how much of its patterns is literal.
    fn specificity(&self) -> (u8, u8, usize) {
        let scope = Scope::ALL
            .iter()
            .position(|s| *s == self.scope)
            .unwrap_or(0) as u8;
        let mut dims = 0u8;
        let mut literal = 0usize;
        let mut note = |p: &str| literal += p.chars().filter(|c| *c != '*').count();
        if self.action != "*" {
            dims += 1;
            note(&self.action);
        }
        if self.scope_id.is_some() {
            dims += 1;
        }
        if let Some(t) = &self.tool {
            dims += 1;
            note(t);
        }
        if let Some(sv) = &self.server {
            dims += 1;
            note(sv);
        }
        if let Some(p) = &self.path {
            dims += 1;
            note(p);
        }
        if let Some(c) = &self.command {
            dims += 1;
            note(c);
        }
        if self.env.is_some() {
            dims += 1;
        }
        (scope, dims, literal)
    }
}

fn scope_matches(scope: Scope, id: Option<&str>, ctx: &Ctx) -> bool {
    let subject = match scope {
        Scope::Person => Some(ctx.person.as_str()),
        Scope::Box => ctx.box_name.as_deref(),
        Scope::Project => ctx.project.as_deref(),
        Scope::Orchestration => ctx.orchestration.as_deref(),
        Scope::Run => ctx.run_id.as_deref(),
    };
    match id {
        None | Some("") => scope == Scope::Person,
        Some(id) => subject == Some(id),
    }
}

/// Why a decision came out as it did. The code is stable; the sentence is for a person.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Reason {
    /// A deny rule matched.
    RuleDeny,
    RuleAllow,
    RuleAsk,
    /// The mode is plan-only and this changes something.
    PlanOnly,
    /// It is on something tagged production and no active grant covers it.
    ProductionNoGrant,
    /// No rule: the mode's default.
    ModeDefault,
    /// The tool itself judged that a person must decide this one (a browser step that submits, sends, pays, opens a new
    /// site, uploads a file or opens a program): an allow rule or the mode cannot let it run without a person.
    PersonRequired,
}

impl Reason {
    pub fn code(self) -> &'static str {
        match self {
            Reason::RuleDeny => "rule_deny",
            Reason::RuleAllow => "rule_allow",
            Reason::RuleAsk => "rule_ask",
            Reason::PlanOnly => "plan_only",
            Reason::ProductionNoGrant => "production_no_grant",
            Reason::ModeDefault => "mode_default",
            Reason::PersonRequired => "person_required",
        }
    }

    pub fn sentence(self) -> &'static str {
        match self {
            Reason::RuleDeny => "A rule forbids this.",
            Reason::RuleAllow => "A rule allows this.",
            Reason::RuleAsk => "A rule says to ask first.",
            Reason::PlanOnly => "The mode is plan only: nothing may be changed.",
            Reason::ProductionNoGrant => {
                "This is on production and there is no active grant. Grant access for a short time first."
            }
            Reason::ModeDefault => "No rule applies, so the mode decides.",
            Reason::PersonRequired => "A person has to decide this step, whatever the rules allow.",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Decision {
    pub effect: Effect,
    pub reason: Reason,
    pub mode: Mode,
    /// The rule that decided, if one did.
    pub rule: Option<String>,
    /// The grant that let a production action through.
    pub grant: Option<String>,
}

impl Decision {
    pub fn allowed(&self) -> bool {
        self.effect == Effect::Allow
    }
}

impl PermConfig {
    pub fn settings(&self) -> PermSettings {
        PermSettings {
            default_mode: self.default_mode,
            modes: self.modes.clone(),
            rules: self.rules.clone(),
            browser_hosts: self.browser_hosts.clone(),
        }
    }

    /// The mode in force for this situation: the narrowest scope that sets one.
    pub fn mode_for(&self, ctx: &Ctx) -> Mode {
        let set = self
            .modes
            .iter()
            .filter(|m| scope_matches(m.scope, m.scope_id.as_deref(), ctx))
            .max_by_key(|m| {
                (
                    Scope::ALL.iter().position(|s| *s == m.scope).unwrap_or(0),
                    m.scope_id.is_some(),
                )
            })
            .map_or(self.default_mode, |m| m.mode);
        // Nobody is watching a schedule or trigger: never bypass. A chat app is held to `ask` too: its writer is not at the
        // keyboard where the mode was chosen, so a mode that lets more through is not theirs to use. A terminal agent given
        // no standing permission asks every time.
        if ((ctx.actor.unattended() || ctx.actor.no_standing_permission()) && set == Mode::Auto)
            || (ctx.actor == ActorKind::Chat && matches!(set, Mode::Auto | Mode::AcceptEdits))
        {
            Mode::Ask
        } else {
            set
        }
    }

    /// Does what this situation is allowed to do without asking go beyond what a chat app may type into? True when the mode
    /// in force is `auto` or `accept edits`, or an active grant reaches it (a standing permission). Used before a chat app
    /// adds a message to a session: that message runs under this authority. A chat's own runs are held to `ask` and are never
    /// covered by a grant (see [`PermConfig::mode_for`]), so they answer false.
    pub fn broader_than_chat(&self, ctx: &Ctx, now_ms: u64) -> bool {
        matches!(self.mode_for(ctx), Mode::Auto | Mode::AcceptEdits)
            || self.grants.iter().any(|g| g.reaches(ctx, now_ms))
    }

    pub fn active_grants(&self, now_ms: u64) -> impl Iterator<Item = &Grant> {
        self.grants.iter().filter(move |g| g.is_active(now_ms))
    }

    /// Replace the modes and rules. Rules without an id get one.
    pub fn apply_settings(&mut self, s: PermSettings) -> Result<(), PermError> {
        validate_settings(&s)?;
        let mut rules = s.rules;
        let mut used: BTreeSet<String> = rules
            .iter()
            .filter(|r| !r.id.is_empty())
            .map(|r| r.id.clone())
            .collect();
        for r in &mut rules {
            if r.id.is_empty() {
                loop {
                    self.next_id += 1;
                    let id = format!("r{}", self.next_id);
                    if used.insert(id.clone()) {
                        r.id = id;
                        break;
                    }
                }
            }
        }
        self.default_mode = s.default_mode;
        self.modes = s.modes;
        self.rules = rules;
        self.browser_hosts = s
            .browser_hosts
            .into_iter()
            .map(|h| h.trim().to_ascii_lowercase())
            .collect();
        Ok(())
    }

    /// Make a grant. It lasts exactly the minutes asked (at most [`MAX_GRANT_MINUTES`]); nothing extends it later, and a
    /// second grant is a second record.
    pub fn create_grant(&mut self, g: NewGrant, now_ms: u64) -> Result<Grant, PermError> {
        let bad = |m: &str| Err(PermError::Invalid(m.to_string()));
        if g.scope == Scope::Person {
            return bad("a grant is for one box, project, run or orchestration, never everything");
        }
        if !valid_id(&g.scope_id) {
            return bad("say which box, project, run or orchestration the grant is for");
        }
        if g.reason.trim().chars().count() < MIN_REASON_CHARS || g.reason.chars().count() > 300 {
            return bad("give a reason of at least 8 characters");
        }
        if g.minutes == 0 || g.minutes > MAX_GRANT_MINUTES {
            return bad("a grant lasts from 1 minute to 4 hours");
        }
        if g.actions.is_empty()
            || g.actions.len() > 20
            || !g.actions.iter().all(|a| valid_action_pattern(a))
        {
            return bad("name the actions it covers, such as git.* or command.run");
        }
        if g.max_uses == Some(0) {
            return bad("a grant that can be used no times is not a grant");
        }
        if self.active_grants(now_ms).count() >= MAX_ACTIVE_GRANTS {
            return bad("too many active grants; revoke one first");
        }
        self.next_id += 1;
        let grant = Grant {
            id: format!("g{}", self.next_id),
            granted_by: g.granted_by,
            scope: g.scope,
            scope_id: g.scope_id,
            actions: g.actions,
            reason: g.reason.trim().to_string(),
            created_ms: now_ms,
            expires_ms: now_ms + g.minutes * 60_000,
            factor: g.factor,
            allow_unattended: g.allow_unattended,
            max_uses: g.max_uses,
            uses: 0,
            revoked_ms: None,
            revoked_by: None,
        };
        self.grants.push(grant.clone());
        if self.grants.len() > MAX_GRANTS_KEPT {
            let keep_from = self.grants.len() - MAX_GRANTS_KEPT;
            let mut i = 0;
            self.grants.retain(|g| {
                i += 1;
                i > keep_from || g.is_active(now_ms)
            });
        }
        Ok(grant)
    }

    pub fn revoke_grant(&mut self, id: &str, by: &str, now_ms: u64) -> Result<(), PermError> {
        let g = self
            .grants
            .iter_mut()
            .find(|g| g.id == id)
            .ok_or(PermError::NoSuchGrant)?;
        if g.revoked_ms.is_some() {
            return Err(PermError::AlreadyRevoked);
        }
        g.revoked_ms = Some(now_ms);
        g.revoked_by = Some(by.to_string());
        Ok(())
    }

    /// Count one use of a grant (it may be limited to a number of uses).
    pub fn use_grant(&mut self, id: &str) {
        if let Some(g) = self.grants.iter_mut().find(|g| g.id == id) {
            g.uses = g.uses.saturating_add(1);
        }
    }
}

fn valid_action_pattern(a: &str) -> bool {
    valid_word(a, 40) && !a.contains(' ')
}

fn validate_settings(s: &PermSettings) -> Result<(), PermError> {
    let bad = |m: &str| Err(PermError::Invalid(m.to_string()));
    if s.rules.len() > MAX_RULES || s.modes.len() > MAX_MODES {
        return bad("too many rules or modes");
    }
    let mut ids = BTreeSet::new();
    for r in &s.rules {
        if !r.id.is_empty() && (!valid_id(&r.id) || !ids.insert(r.id.as_str())) {
            return bad("rule ids must be unique and plain");
        }
        if !valid_action_pattern(&r.action) {
            return bad("a rule needs an action, such as git.push or file.*");
        }
        if !scope_id_ok(r.scope, r.scope_id.as_deref()) {
            return bad("a rule for a box, project, run or orchestration must name which one");
        }
        if r.path.as_deref().is_some_and(|p| !valid_word(p, 200)) {
            return bad("a path pattern is plain characters and *");
        }
        if r.tool.as_deref().is_some_and(|t| !valid_action_pattern(t))
            || r.server
                .as_deref()
                .is_some_and(|t| !valid_action_pattern(t))
        {
            return bad("a tool or server pattern is plain characters and *");
        }
        if r.command.as_deref().is_some_and(|c| !valid_word(c, 100)) {
            return bad("a command pattern is plain words");
        }
        if r.note.chars().count() > 200 {
            return bad("a rule's note is at most 200 characters");
        }
        if r.effect == Effect::Allow
            && r.action == "*"
            && r.scope == Scope::Person
            && r.scope_id.is_none()
            && r.path.is_none()
            && r.command.is_none()
            && r.env.is_none()
        {
            return bad(
                "a rule that allows everything everywhere is the auto mode: set the mode instead",
            );
        }
    }
    if s.browser_hosts.len() > 50 || !s.browser_hosts.iter().all(|h| valid_host_pattern(h.trim())) {
        return bad("a browser host is a name such as example.com or *.example.com");
    }
    for m in &s.modes {
        if !scope_id_ok(m.scope, m.scope_id.as_deref()) {
            return bad("a mode for a box, project, run or orchestration must name which one");
        }
    }
    Ok(())
}

/// A host an agent's browser may fetch: letters, digits, dots and dashes, with an optional leading `*.`.
pub fn valid_host_pattern(h: &str) -> bool {
    let body = h.strip_prefix("*.").unwrap_or(h);
    !body.is_empty()
        && body.len() <= 253
        && body.contains('.')
        && body.split('.').all(|l| {
            !l.is_empty()
                && l.len() <= 63
                && !l.starts_with('-')
                && !l.ends_with('-')
                && l.chars().all(|c| c.is_ascii_alphanumeric() || c == '-')
        })
}

/// Whether `host` is one of the patterns (`*.example.com` covers every subdomain, not `example.com` itself).
pub fn host_allowed(patterns: &[String], host: &str) -> bool {
    let host = host.to_ascii_lowercase();
    patterns.iter().any(|p| match p.strip_prefix("*.") {
        Some(suffix) => host.len() > suffix.len() + 1 && host.ends_with(&format!(".{suffix}")),
        None => *p == host,
    })
}

fn scope_id_ok(scope: Scope, id: Option<&str>) -> bool {
    match (scope, id) {
        (Scope::Person, None) => true,
        (_, Some(i)) => valid_id(i),
        (_, None) => false,
    }
}

/// The decision. See the module docs for the order.
pub fn decide(cfg: &PermConfig, ctx: &Ctx, action: Action, now_ms: u64) -> Decision {
    let mode = cfg.mode_for(ctx);
    let out = |effect, reason, rule: Option<&Rule>, grant: Option<&Grant>| Decision {
        effect,
        reason,
        mode,
        rule: rule.map(|r| r.id.clone()),
        grant: grant.map(|g| g.id.clone()),
    };
    let matching: Vec<&Rule> = cfg
        .rules
        .iter()
        .filter(|r| r.applies(ctx, action))
        .collect();

    // 1. a deny rule always wins
    if let Some(r) = matching
        .iter()
        .filter(|r| r.effect == Effect::Deny)
        .max_by_key(|r| r.specificity())
    {
        return out(Effect::Deny, Reason::RuleDeny, Some(r), None);
    }

    // 2. production needs a grant that covers this
    let mut used_grant = None;
    if ctx.env == Environment::Production && action.changes(ctx) {
        match cfg.grants.iter().find(|g| g.covers(ctx, action, now_ms)) {
            Some(g) => used_grant = Some(g),
            None => return out(Effect::Deny, Reason::ProductionNoGrant, None, None),
        }
    }

    // 3. plan only changes nothing
    if mode == Mode::PlanOnly && action.changes(ctx) {
        return out(Effect::Deny, Reason::PlanOnly, None, used_grant);
    }

    // 4. the most specific rule; at equal specificity, ask beats allow
    let best = matching
        .iter()
        .max_by_key(|r| (r.specificity(), r.effect == Effect::Ask));
    if let Some(r) = best {
        return match r.effect {
            Effect::Allow => out(Effect::Allow, Reason::RuleAllow, Some(r), used_grant),
            _ => out(Effect::Ask, Reason::RuleAsk, Some(r), used_grant),
        };
    }

    // 5. the mode
    let allow = match mode {
        Mode::PlanOnly => !action.changes(ctx),
        Mode::Ask => action.routine(ctx) && !ctx.sensitive,
        Mode::AcceptEdits => (action == Action::FileWrite || action.routine(ctx)) && !ctx.sensitive,
        Mode::Auto => !action.always_asks() && !ctx.sensitive,
    };
    let effect = if allow { Effect::Allow } else { Effect::Ask };
    out(effect, Reason::ModeDefault, None, used_grant)
}

/// What to write in the audit chain for a decision: an action word, the id it is about and a few words. Never a
/// command line, a path's contents or a value.
pub fn audit_event(
    d: &Decision,
    ctx: &Ctx,
    action: Action,
    actor: &str,
    now_ms: u64,
) -> crate::audit::NewEvent {
    let word = match d.effect {
        Effect::Allow => "permission.allow",
        Effect::Ask => "permission.ask",
        Effect::Deny => "permission.deny",
    };
    let subject = ctx
        .run_id
        .clone()
        .or_else(|| ctx.box_name.clone())
        .or_else(|| ctx.orchestration.clone());
    let mut detail = format!(
        "{} {:?} env={:?} mode={:?} why={}",
        action.name(),
        ctx.actor,
        ctx.env,
        d.mode,
        d.reason.code()
    )
    .to_lowercase();
    if action == Action::ToolCall {
        detail.push_str(&format!(
            " tool={} server={} writes={}",
            ctx.tool.as_deref().unwrap_or("?"),
            ctx.server.as_deref().unwrap_or("?"),
            ctx.writes
                .map_or("unknown", |w| if w { "yes" } else { "no" })
        ));
    }
    if let Some(r) = &d.rule {
        detail.push_str(&format!(" rule={r}"));
    }
    if let Some(g) = &d.grant {
        detail.push_str(&format!(" grant={g}"));
    }
    crate::audit::NewEvent {
        ts_ms: now_ms,
        actor: actor.to_string(),
        action: word.to_string(),
        subject,
        detail,
        src: None,
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::field_reassign_with_default)]
mod tests {
    use super::*;

    const NOW: u64 = 1_000_000;

    fn ctx() -> Ctx {
        Ctx {
            person: "alice".into(),
            actor: ActorKind::Agent,
            box_name: Some("main".into()),
            project: Some("shop".into()),
            run_id: Some("t1".into()),
            ..Ctx::default()
        }
    }

    fn rule(effect: Effect, action: &str, scope: Scope, id: Option<&str>) -> Rule {
        Rule {
            id: String::new(),
            effect,
            action: action.into(),
            scope,
            scope_id: id.map(str::to_string),
            path: None,
            command: None,
            env: None,
            tool: None,
            server: None,
            note: String::new(),
        }
    }

    fn cfg_with(rules: Vec<Rule>) -> PermConfig {
        let mut c = PermConfig::default();
        c.apply_settings(PermSettings {
            default_mode: Mode::Ask,
            modes: vec![],
            rules,
            browser_hosts: vec![],
        })
        .unwrap();
        c
    }

    fn grant(cfg: &mut PermConfig, scope: Scope, id: &str, minutes: u64) -> Grant {
        cfg.create_grant(
            NewGrant {
                granted_by: "alice".into(),
                scope,
                scope_id: id.into(),
                actions: vec!["*".into()],
                reason: "ship the fix".into(),
                minutes,
                factor: SecondFactor::StepUp,
                allow_unattended: false,
                max_uses: None,
            },
            NOW,
        )
        .unwrap()
    }

    fn prod() -> Ctx {
        Ctx {
            env: Environment::Production,
            ..ctx()
        }
    }

    #[test]
    fn the_default_mode_asks_about_what_is_not_routine() {
        let c = PermConfig::default();
        assert_eq!(
            decide(&c, &ctx(), Action::FileRead, NOW).effect,
            Effect::Allow
        );
        assert_eq!(
            decide(&c, &ctx(), Action::CommandRun, NOW).effect,
            Effect::Allow
        );
        for a in [
            Action::MessageSend,
            Action::FileWrite,
            Action::BoxDestroy,
            Action::SecretWrite,
        ] {
            assert_eq!(decide(&c, &ctx(), a, NOW).effect, Effect::Ask, "{a:?}");
        }
    }

    #[test]
    fn what_the_approval_policy_singled_out_still_asks() {
        let c = PermConfig::default();
        let x = Ctx {
            sensitive: true,
            ..ctx()
        };
        assert_eq!(decide(&c, &x, Action::GitPush, NOW).effect, Effect::Ask);
    }

    #[test]
    fn plan_only_refuses_every_change_even_against_an_allow_rule() {
        let mut c = cfg_with(vec![rule(Effect::Allow, "file.write", Scope::Person, None)]);
        c.default_mode = Mode::PlanOnly;
        let d = decide(&c, &ctx(), Action::FileWrite, NOW);
        assert_eq!((d.effect, d.reason), (Effect::Deny, Reason::PlanOnly));
        assert_eq!(
            decide(&c, &ctx(), Action::FileRead, NOW).effect,
            Effect::Allow
        );
    }

    #[test]
    fn accept_edits_lets_edits_through_and_nothing_else_new() {
        let mut c = PermConfig::default();
        c.default_mode = Mode::AcceptEdits;
        assert_eq!(
            decide(&c, &ctx(), Action::FileWrite, NOW).effect,
            Effect::Allow
        );
        assert_eq!(
            decide(&c, &ctx(), Action::MessageSend, NOW).effect,
            Effect::Ask
        );
    }

    #[test]
    fn auto_allows_but_not_what_always_needs_a_person() {
        let mut c = PermConfig::default();
        c.default_mode = Mode::Auto;
        assert_eq!(
            decide(&c, &ctx(), Action::FileWrite, NOW).effect,
            Effect::Allow
        );
        assert_eq!(
            decide(&c, &ctx(), Action::BoxCreate, NOW).effect,
            Effect::Allow
        );
        for a in [
            Action::MessageSend,
            Action::BoxDestroy,
            Action::SecretWrite,
            Action::GrantCreate,
            Action::SettingsChange,
        ] {
            assert_eq!(decide(&c, &ctx(), a, NOW).effect, Effect::Ask, "{a:?}");
        }
        let sens = Ctx {
            sensitive: true,
            ..ctx()
        };
        assert_eq!(decide(&c, &sens, Action::GitPush, NOW).effect, Effect::Ask);
    }

    #[test]
    fn auto_is_never_given_to_a_schedule_or_a_trigger() {
        let mut c = PermConfig::default();
        c.default_mode = Mode::Auto;
        for kind in [ActorKind::Schedule, ActorKind::Trigger] {
            let x = Ctx {
                actor: kind,
                ..ctx()
            };
            let d = decide(&c, &x, Action::FileWrite, NOW);
            assert_eq!((d.mode, d.effect), (Mode::Ask, Effect::Ask), "{kind:?}");
        }
    }

    /// ADR 0043: anything running as the box user can be a terminal agent, so a run that escaped its scope and
    /// came through the door gains nothing: no `auto`, and no grant covers it, unless the person turned standing permission on.
    #[test]
    fn a_terminal_agent_gets_no_auto_mode_and_no_grant_unless_standing_permission_is_on() {
        let mut c = PermConfig::default();
        c.default_mode = Mode::Auto;
        grant(&mut c, Scope::Box, "main", 30);
        for (kind, auto, covered) in [
            (ActorKind::Mcp, true, true),
            (ActorKind::TerminalStanding, true, true),
            (ActorKind::Terminal, false, false),
        ] {
            let x = Ctx {
                actor: kind,
                ..ctx()
            };
            let d = decide(&c, &x, Action::FileWrite, NOW);
            assert_eq!(
                (d.mode == Mode::Auto, d.effect == Effect::Allow),
                (auto, auto),
                "{kind:?}"
            );
            let d = decide(
                &c,
                &Ctx {
                    env: Environment::Production,
                    ..x
                },
                Action::CommandRun,
                NOW,
            );
            assert_eq!(d.grant.is_some(), covered, "{kind:?}");
            assert_eq!(d.effect == Effect::Deny, !covered, "{kind:?}");
        }
        assert!(ActorKind::Terminal.no_standing_permission() && ActorKind::Terminal.is_terminal());
        assert!(
            !ActorKind::TerminalStanding.no_standing_permission()
                && ActorKind::TerminalStanding.is_terminal()
        );
        assert!(!ActorKind::Mcp.is_terminal() && !ActorKind::Terminal.unattended());
    }

    #[test]
    fn deny_wins_over_a_more_specific_allow() {
        let c = cfg_with(vec![
            rule(Effect::Deny, "git.push", Scope::Person, None),
            rule(Effect::Allow, "git.push", Scope::Run, Some("t1")),
        ]);
        let d = decide(&c, &ctx(), Action::GitPush, NOW);
        assert_eq!((d.effect, d.reason), (Effect::Deny, Reason::RuleDeny));
        assert_eq!(d.rule.as_deref(), Some("r1"));
    }

    #[test]
    fn deny_wins_over_auto_and_over_a_production_grant() {
        let mut c = cfg_with(vec![rule(
            Effect::Deny,
            "command.run",
            Scope::Box,
            Some("main"),
        )]);
        c.default_mode = Mode::Auto;
        grant(&mut c, Scope::Box, "main", 30);
        let d = decide(&c, &prod(), Action::CommandRun, NOW);
        assert_eq!(d.effect, Effect::Deny);
        assert_eq!(d.reason, Reason::RuleDeny);
    }

    #[test]
    fn the_narrowest_scope_decides() {
        let c = cfg_with(vec![
            rule(Effect::Ask, "git.push", Scope::Person, None),
            rule(Effect::Allow, "git.push", Scope::Box, Some("main")),
        ]);
        assert_eq!(
            decide(&c, &ctx(), Action::GitPush, NOW).effect,
            Effect::Allow
        );
        let other = Ctx {
            box_name: Some("other".into()),
            ..ctx()
        };
        assert_eq!(decide(&c, &other, Action::GitPush, NOW).effect, Effect::Ask);
    }

    #[test]
    fn more_conditions_make_a_rule_more_specific() {
        let mut wide = rule(Effect::Ask, "git.push", Scope::Box, Some("main"));
        wide.note = "wide".into();
        let mut narrow = rule(Effect::Allow, "git.push", Scope::Box, Some("main"));
        narrow.path = Some("wip/*".into());
        let c = cfg_with(vec![wide, narrow]);
        let x = Ctx {
            path: Some("wip/fix".into()),
            ..ctx()
        };
        assert_eq!(decide(&c, &x, Action::GitPush, NOW).effect, Effect::Allow);
        let y = Ctx {
            path: Some("backend".into()),
            ..ctx()
        };
        assert_eq!(decide(&c, &y, Action::GitPush, NOW).effect, Effect::Ask);
    }

    #[test]
    fn at_equal_specificity_ask_beats_allow() {
        let c = cfg_with(vec![
            rule(Effect::Allow, "message.send", Scope::Box, Some("main")),
            rule(Effect::Ask, "message.send", Scope::Box, Some("main")),
        ]);
        assert_eq!(
            decide(&c, &ctx(), Action::MessageSend, NOW).effect,
            Effect::Ask
        );
    }

    #[test]
    fn a_command_rule_matches_words_in_any_order() {
        let mut r = rule(Effect::Deny, "command.run", Scope::Person, None);
        r.command = Some("git push --force".into());
        let c = cfg_with(vec![r]);
        let x = Ctx {
            command: Some(vec![
                "git".into(),
                "push".into(),
                "origin".into(),
                "--force".into(),
            ]),
            ..ctx()
        };
        assert_eq!(decide(&c, &x, Action::CommandRun, NOW).effect, Effect::Deny);
        let y = Ctx {
            command: Some(vec!["git".into(), "status".into()]),
            ..ctx()
        };
        assert_eq!(
            decide(&c, &y, Action::CommandRun, NOW).effect,
            Effect::Allow
        );
        // a command rule never matches an action that carries no command
        assert_eq!(
            decide(&c, &ctx(), Action::CommandRun, NOW).effect,
            Effect::Allow
        );
    }

    #[test]
    fn an_environment_rule_only_applies_there() {
        let mut r = rule(Effect::Deny, "resource.touch", Scope::Person, None);
        r.env = Some(Environment::Staging);
        let c = cfg_with(vec![r]);
        let stg = Ctx {
            env: Environment::Staging,
            ..ctx()
        };
        assert_eq!(
            decide(&c, &stg, Action::ResourceTouch, NOW).effect,
            Effect::Deny
        );
        assert_eq!(
            decide(&c, &ctx(), Action::ResourceTouch, NOW).effect,
            Effect::Ask
        );
    }

    #[test]
    fn modes_follow_the_narrowest_scope() {
        let mut c = PermConfig::default();
        c.modes = vec![
            ModeSetting {
                scope: Scope::Box,
                scope_id: Some("main".into()),
                mode: Mode::PlanOnly,
            },
            ModeSetting {
                scope: Scope::Run,
                scope_id: Some("t1".into()),
                mode: Mode::AcceptEdits,
            },
        ];
        assert_eq!(c.mode_for(&ctx()), Mode::AcceptEdits);
        let other_run = Ctx {
            run_id: Some("t2".into()),
            ..ctx()
        };
        assert_eq!(c.mode_for(&other_run), Mode::PlanOnly);
        let other_box = Ctx {
            box_name: Some("x".into()),
            run_id: None,
            ..ctx()
        };
        assert_eq!(c.mode_for(&other_box), Mode::Ask);
    }

    // ---- production ----------------------------------------------------------------------------------------------

    #[test]
    fn a_production_action_without_a_grant_is_refused() {
        let c = PermConfig::default();
        let d = decide(&c, &prod(), Action::CommandRun, NOW);
        assert_eq!(
            (d.effect, d.reason),
            (Effect::Deny, Reason::ProductionNoGrant)
        );
        // even in auto mode, even against an allow rule
        let mut c2 = cfg_with(vec![rule(Effect::Allow, "*", Scope::Box, Some("main"))]);
        c2.default_mode = Mode::Auto;
        assert_eq!(
            decide(&c2, &prod(), Action::FileWrite, NOW).reason,
            Reason::ProductionNoGrant
        );
    }

    #[test]
    fn reading_production_needs_no_grant() {
        let c = PermConfig::default();
        assert_eq!(
            decide(&c, &prod(), Action::FileRead, NOW).effect,
            Effect::Allow
        );
    }

    #[test]
    fn a_grant_lets_production_through_until_it_expires() {
        let mut c = PermConfig::default();
        let g = grant(&mut c, Scope::Box, "main", 30);
        let d = decide(&c, &prod(), Action::CommandRun, NOW + 29 * 60_000);
        assert_eq!(d.effect, Effect::Allow);
        assert_eq!(d.grant.as_deref(), Some(g.id.as_str()));
        let late = decide(&c, &prod(), Action::CommandRun, NOW + 30 * 60_000);
        assert_eq!(late.reason, Reason::ProductionNoGrant);
    }

    #[test]
    fn a_grant_does_not_reach_another_box_or_run() {
        let mut c = PermConfig::default();
        grant(&mut c, Scope::Box, "main", 30);
        let other = Ctx {
            box_name: Some("other".into()),
            ..prod()
        };
        assert_eq!(
            decide(&c, &other, Action::CommandRun, NOW).reason,
            Reason::ProductionNoGrant
        );
        let mut c2 = PermConfig::default();
        grant(&mut c2, Scope::Run, "t1", 30);
        assert!(decide(&c2, &prod(), Action::CommandRun, NOW).allowed());
        let other_run = Ctx {
            run_id: Some("t9".into()),
            ..prod()
        };
        assert!(!decide(&c2, &other_run, Action::CommandRun, NOW).allowed());
    }

    #[test]
    fn a_grant_only_covers_the_actions_it_names() {
        let mut c = PermConfig::default();
        c.create_grant(
            NewGrant {
                granted_by: "alice".into(),
                scope: Scope::Box,
                scope_id: "main".into(),
                actions: vec!["git.*".into()],
                reason: "ship the fix".into(),
                minutes: 30,
                factor: SecondFactor::StepUp,
                allow_unattended: false,
                max_uses: None,
            },
            NOW,
        )
        .unwrap();
        assert!(decide(&c, &prod(), Action::GitPush, NOW).allowed());
        assert_eq!(
            decide(&c, &prod(), Action::BoxDestroy, NOW).reason,
            Reason::ProductionNoGrant
        );
    }

    #[test]
    fn a_schedule_does_not_inherit_a_grant_unless_it_says_so() {
        let mut c = PermConfig::default();
        grant(&mut c, Scope::Box, "main", 30);
        let sched = Ctx {
            actor: ActorKind::Schedule,
            ..prod()
        };
        assert_eq!(
            decide(&c, &sched, Action::CommandRun, NOW).reason,
            Reason::ProductionNoGrant
        );
        let mut c2 = PermConfig::default();
        c2.create_grant(
            NewGrant {
                granted_by: "alice".into(),
                scope: Scope::Box,
                scope_id: "main".into(),
                actions: vec!["*".into()],
                reason: "the nightly deploy".into(),
                minutes: 60,
                factor: SecondFactor::StepUp,
                allow_unattended: true,
                max_uses: None,
            },
            NOW,
        )
        .unwrap();
        assert!(decide(&c2, &sched, Action::CommandRun, NOW).allowed());
    }

    #[test]
    fn a_revoked_grant_stops_at_once() {
        let mut c = PermConfig::default();
        let g = grant(&mut c, Scope::Box, "main", 30);
        assert!(decide(&c, &prod(), Action::CommandRun, NOW).allowed());
        c.revoke_grant(&g.id, "alice", NOW + 1).unwrap();
        assert_eq!(
            decide(&c, &prod(), Action::CommandRun, NOW + 2).reason,
            Reason::ProductionNoGrant
        );
        assert_eq!(
            c.revoke_grant(&g.id, "alice", NOW + 3),
            Err(PermError::AlreadyRevoked)
        );
        assert_eq!(
            c.revoke_grant("nope", "alice", NOW),
            Err(PermError::NoSuchGrant)
        );
    }

    #[test]
    fn a_limited_grant_runs_out() {
        let mut c = PermConfig::default();
        let g = c
            .create_grant(
                NewGrant {
                    granted_by: "alice".into(),
                    scope: Scope::Run,
                    scope_id: "t1".into(),
                    actions: vec!["*".into()],
                    reason: "one deploy only".into(),
                    minutes: 10,
                    factor: SecondFactor::StepUp,
                    allow_unattended: false,
                    max_uses: Some(1),
                },
                NOW,
            )
            .unwrap();
        assert!(decide(&c, &prod(), Action::CommandRun, NOW).allowed());
        c.use_grant(&g.id);
        assert!(!decide(&c, &prod(), Action::CommandRun, NOW).allowed());
        assert_eq!(c.grants[0].state(NOW), "used");
    }

    #[test]
    fn a_grant_never_extends() {
        let mut c = PermConfig::default();
        let g = grant(&mut c, Scope::Box, "main", 5);
        // using it, deciding, listing: none of it moves the expiry
        c.use_grant(&g.id);
        let _ = decide(&c, &prod(), Action::CommandRun, NOW + 60_000);
        let _ = c.settings();
        assert_eq!(c.grants[0].expires_ms, g.expires_ms);
        assert_eq!(g.expires_ms, NOW + 5 * 60_000);
        // asking again makes a new, separate record
        let g2 = grant(&mut c, Scope::Box, "main", 5);
        assert_ne!(g.id, g2.id);
        assert_eq!(c.grants.len(), 2);
    }

    #[test]
    fn a_grant_is_refused_when_it_is_too_long_too_wide_or_has_no_reason() {
        let mut c = PermConfig::default();
        let base = NewGrant {
            granted_by: "alice".into(),
            scope: Scope::Box,
            scope_id: "main".into(),
            actions: vec!["*".into()],
            reason: "ship the fix".into(),
            minutes: 30,
            factor: SecondFactor::StepUp,
            allow_unattended: false,
            max_uses: None,
        };
        let cases = [
            NewGrant {
                minutes: MAX_GRANT_MINUTES + 1,
                ..base.clone()
            },
            NewGrant {
                minutes: 0,
                ..base.clone()
            },
            NewGrant {
                reason: "fix".into(),
                ..base.clone()
            },
            NewGrant {
                scope: Scope::Person,
                ..base.clone()
            },
            NewGrant {
                scope_id: String::new(),
                ..base.clone()
            },
            NewGrant {
                actions: vec![],
                ..base.clone()
            },
            NewGrant {
                max_uses: Some(0),
                ..base.clone()
            },
        ];
        for g in cases {
            assert!(matches!(c.create_grant(g, NOW), Err(PermError::Invalid(_))));
        }
        assert!(c.grants.is_empty());
        assert!(c.create_grant(base, NOW).is_ok());
    }

    #[test]
    fn the_second_factor_is_recorded_honestly() {
        assert!(SecondFactor::StepUp.is_real());
        assert!(!SecondFactor::TypedConfirmation.is_real());
        assert!(!SecondFactor::NoSignIn.is_real());
    }

    // ---- settings -------------------------------------------------------------------------------------------------

    #[test]
    fn settings_get_ids_and_are_validated() {
        let mut c = PermConfig::default();
        c.apply_settings(PermSettings {
            default_mode: Mode::AcceptEdits,
            modes: vec![],
            rules: vec![rule(Effect::Deny, "git.*", Scope::Person, None)],
            browser_hosts: vec![],
        })
        .unwrap();
        assert_eq!(c.rules[0].id, "r1");
        assert_eq!(c.default_mode, Mode::AcceptEdits);
        let bad = |r: Rule| {
            PermConfig::default()
                .apply_settings(PermSettings {
                    default_mode: Mode::Ask,
                    modes: vec![],
                    rules: vec![r],
                    browser_hosts: vec![],
                })
                .is_err()
        };
        assert!(bad(rule(Effect::Deny, "", Scope::Person, None)));
        assert!(bad(rule(Effect::Deny, "git.push", Scope::Box, None)));
        assert!(bad(rule(Effect::Deny, "git push", Scope::Person, None)));
        assert!(bad(rule(Effect::Allow, "*", Scope::Person, None)));
    }

    #[test]
    fn glob_basics() {
        assert!(glob("*", "anything"));
        assert!(glob("git.*", "git.push"));
        assert!(!glob("git.*", "pr.open"));
        assert!(glob("a*c", "abbbc"));
        assert!(!glob("a*c", "abbbd"));
        assert!(glob("wip/*", "wip/a/b"));
        assert!(glob("exact", "exact"));
        assert!(!glob("exact", "exactly"));
    }

    #[test]
    fn an_old_store_without_permissions_loads_with_the_defaults() {
        let c: PermConfig = serde_json::from_str("{}").unwrap();
        assert_eq!(c, PermConfig::default());
    }

    #[test]
    fn the_audit_words_carry_no_command_or_path() {
        let c = PermConfig::default();
        let x = Ctx {
            command: Some(vec!["curl".into(), "https://x.example/?token=abc".into()]),
            path: Some("/work/secret.env".into()),
            ..prod()
        };
        let d = decide(&c, &x, Action::CommandRun, NOW);
        let e = audit_event(&d, &x, Action::CommandRun, "engine:claude", NOW);
        let text = format!("{e:?}");
        assert!(
            !text.contains("token=abc") && !text.contains("secret.env"),
            "{text}"
        );
        assert_eq!(e.action, "permission.deny");
        assert!(e.detail.contains("production_no_grant"));
    }

    #[test]
    fn every_action_has_a_unique_name() {
        let names: BTreeSet<&str> = Action::ALL.iter().map(|a| a.name()).collect();
        assert_eq!(names.len(), Action::ALL.len());
        for a in Action::ALL {
            let json = serde_json::to_string(&a).unwrap();
            assert_eq!(json, format!("\"{}\"", a.name()));
        }
    }

    // ---- MCP tool calls ------------------------------------------------------------------------------------------

    fn tool_ctx(tool: &str, server: &str, writes: Option<bool>) -> Ctx {
        Ctx {
            actor: ActorKind::Mcp,
            tool: Some(tool.into()),
            server: Some(server.into()),
            writes,
            ..ctx()
        }
    }

    #[test]
    fn a_tool_call_is_decidable_by_what_it_does() {
        let c = PermConfig::default();
        assert_eq!(
            decide(
                &c,
                &tool_ctx("git_status", "git", Some(false)),
                Action::ToolCall,
                NOW
            )
            .effect,
            Effect::Allow
        );
        for w in [Some(true), None] {
            assert_eq!(
                decide(&c, &tool_ctx("git_push", "git", w), Action::ToolCall, NOW).effect,
                Effect::Ask,
                "{w:?}"
            );
        }
    }

    #[test]
    fn rules_match_tool_and_server_and_deny_wins() {
        let mut deny = rule(Effect::Deny, "tool.call", Scope::Person, None);
        deny.tool = Some("shell".into());
        let mut allow = rule(Effect::Allow, "tool.call", Scope::Box, Some("main"));
        allow.server = Some("git".into());
        let c = cfg_with(vec![deny, allow]);
        assert_eq!(
            decide(
                &c,
                &tool_ctx("shell", "sh", Some(true)),
                Action::ToolCall,
                NOW
            )
            .effect,
            Effect::Deny
        );
        assert_eq!(
            decide(
                &c,
                &tool_ctx("git_push", "git", Some(true)),
                Action::ToolCall,
                NOW
            )
            .effect,
            Effect::Allow
        );
        assert_eq!(
            decide(
                &c,
                &tool_ctx("git_push", "ci", Some(true)),
                Action::ToolCall,
                NOW
            )
            .effect,
            Effect::Ask
        );
    }

    #[test]
    fn plan_only_refuses_a_writing_tool_but_not_a_reading_one() {
        let mut c = PermConfig::default();
        c.default_mode = Mode::PlanOnly;
        assert!(decide(
            &c,
            &tool_ctx("read_file", "files", Some(false)),
            Action::ToolCall,
            NOW
        )
        .allowed());
        assert_eq!(
            decide(
                &c,
                &tool_ctx("write_file", "files", Some(true)),
                Action::ToolCall,
                NOW
            )
            .reason,
            Reason::PlanOnly
        );
    }

    #[test]
    fn a_writing_tool_on_production_needs_a_grant_and_a_staging_read_does_not() {
        let c = PermConfig::default();
        let prod_write = Ctx {
            env: Environment::Production,
            ..tool_ctx("deploy", "ci", Some(true))
        };
        assert_eq!(
            decide(&c, &prod_write, Action::ToolCall, NOW).reason,
            Reason::ProductionNoGrant
        );
        let prod_unknown = Ctx {
            writes: None,
            ..prod_write.clone()
        };
        assert_eq!(
            decide(&c, &prod_unknown, Action::ToolCall, NOW).reason,
            Reason::ProductionNoGrant
        );
        let stg_read = Ctx {
            env: Environment::Staging,
            ..tool_ctx("db_read", "supabase", Some(false))
        };
        assert!(decide(&c, &stg_read, Action::ToolCall, NOW).allowed());
    }

    #[test]
    fn a_tool_call_audit_record_names_the_tool_and_never_its_arguments() {
        let c = PermConfig::default();
        let x = tool_ctx("git_push", "git", Some(true));
        let d = decide(&c, &x, Action::ToolCall, NOW);
        let e = audit_event(&d, &x, Action::ToolCall, "mcp:claude", NOW);
        assert!(e.detail.contains("tool=git_push") && e.detail.contains("server=git"));
        assert_eq!(e.action, "permission.ask");
    }

    #[test]
    fn a_chat_app_is_held_to_ask_and_no_grant_covers_it() {
        let chat = Ctx {
            actor: ActorKind::Chat,
            ..ctx()
        };
        let mut c = PermConfig::default();
        for m in [Mode::Auto, Mode::AcceptEdits] {
            c.default_mode = m;
            assert_eq!(c.mode_for(&chat), Mode::Ask, "{m:?}");
            assert_eq!(c.mode_for(&ctx()), m, "an agent keeps {m:?}");
        }
        c.default_mode = Mode::PlanOnly;
        assert_eq!(c.mode_for(&chat), Mode::PlanOnly, "stricter modes stand");
        // a grant on the box reaches an agent's run, never a chat's
        grant(&mut c, Scope::Box, "main", 30);
        assert!(c.broader_than_chat(&ctx(), NOW));
        assert!(!c.broader_than_chat(&chat, NOW));
        let p = Ctx {
            actor: ActorKind::Chat,
            ..prod()
        };
        assert_eq!(
            decide(&c, &p, Action::GitPush, NOW).effect,
            Effect::Deny,
            "a standing permission does not carry a chat app through the production gate"
        );
    }

    #[test]
    fn a_run_is_broader_than_chat_by_its_mode_or_a_grant_that_reaches_it() {
        let mut c = PermConfig::default();
        assert!(!c.broader_than_chat(&ctx(), NOW));
        c.default_mode = Mode::AcceptEdits;
        assert!(c.broader_than_chat(&ctx(), NOW));
        c.default_mode = Mode::Ask;
        grant(&mut c, Scope::Run, "other", 30);
        assert!(!c.broader_than_chat(&ctx(), NOW), "a grant on another run");
        grant(&mut c, Scope::Run, "t1", 30);
        assert!(c.broader_than_chat(&ctx(), NOW));
        assert!(!c.broader_than_chat(&ctx(), NOW + 31 * 60_000), "lapsed");
    }
}
