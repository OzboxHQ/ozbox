//! What is stored for schedules and triggers: plain JSON in the fleet store, never a secret.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use super::cron::Cron;

pub const DEFAULT_CATCH_UP_MINUTES: u32 = 120;
pub const MAX_RUNS_KEPT: usize = 500;
pub const MAX_DELIVERIES_KEPT: usize = 300;
pub const MAX_SCHEDULES: usize = 200;
pub const MAX_TRIGGERS: usize = 100;
pub const MAX_PROMPT_CHARS: usize = 8000;

fn default_catch_up() -> u32 {
    DEFAULT_CATCH_UP_MINUTES
}

/// The engine every new schedule and trigger runs on: the one a real supervisor registers.
pub const DEFAULT_ENGINE: &str = "claude-code";

/// The engine a stored item names, with the one old spelling made current. Schedules and triggers made before the fix
/// said `claude`, which no supervisor registers (only `claude-code`), so every run they fired failed with "that engine is
/// not set up". The change is made on every read, so an old file works at once and is rewritten on its next save; running
/// it again changes nothing.
pub fn current_engine(raw: &str) -> String {
    match raw.trim() {
        "claude" => DEFAULT_ENGINE.to_string(),
        other => other.to_string(),
    }
}

fn engine_on_read<'de, D: serde::Deserializer<'de>>(d: D) -> Result<String, D::Error> {
    String::deserialize(d).map(|s| current_engine(&s))
}

fn default_engine() -> String {
    DEFAULT_ENGINE.to_string()
}

fn default_true() -> bool {
    true
}

/// When a schedule fires.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum When {
    /// Five-field cron on the schedule's own time zone.
    Cron { expr: String },
    /// Every N minutes from the moment the schedule was switched on (heartbeats).
    Every { minutes: u32 },
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct Target {
    /// One box by name.
    pub box_name: Option<String>,
    /// Or the boxes labelled with this profile; the first running one is used, else a paused one is woken.
    pub profile: Option<String>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct Caps {
    /// The most one run may spend, in US cents. `None` = the fleet default.
    pub max_spend_cents: Option<u64>,
    /// The longest one run may take.
    pub max_minutes: Option<u32>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct Schedule {
    pub id: String,
    pub name: String,
    pub when: When,
    /// What the person typed ("every weekday at 9am Lagos time"), kept so the form shows it again.
    pub plain: Option<String>,
    /// The IANA zone the times are read in: the owner's, chosen when the schedule was made.
    pub time_zone: String,
    /// The person who owns it.
    pub owner: String,
    /// The agent or engine that runs it (`claude-code`, ...). An old `claude` reads as `claude-code`.
    #[serde(default = "default_engine", deserialize_with = "engine_on_read")]
    pub engine: String,
    pub prompt: Option<String>,
    pub skill: Option<String>,
    pub target: Target,
    pub caps: Caps,
    /// Where the result goes besides the run history: `alert` (a message under the routing rules) and/or `pull_request`.
    pub results_to: Vec<String>,
    /// How late a missed run may still be made up.
    #[serde(default = "default_catch_up")]
    pub catch_up_minutes: u32,
    #[serde(default = "default_true")]
    pub enabled: bool,
    /// A check-in rather than a task. Off until a person turns it on.
    pub heartbeat: bool,
    pub created_ms: u64,
    pub updated_ms: u64,
}

impl Default for Schedule {
    fn default() -> Self {
        Schedule {
            id: String::new(),
            name: String::new(),
            when: When::Cron {
                expr: "0 9 * * 1-5".into(),
            },
            plain: None,
            time_zone: "UTC".into(),
            owner: String::new(),
            engine: DEFAULT_ENGINE.into(),
            prompt: None,
            skill: None,
            target: Target::default(),
            caps: Caps::default(),
            results_to: Vec::new(),
            catch_up_minutes: DEFAULT_CATCH_UP_MINUTES,
            enabled: true,
            heartbeat: false,
            created_ms: 0,
            updated_ms: 0,
        }
    }
}

/// A message key and a detail, safe to show.
pub type Invalid = (&'static str, String);

fn safe_word(s: &str, max: usize) -> bool {
    !s.is_empty()
        && s.len() <= max
        && s.bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.'))
}

pub fn valid_id(s: &str) -> bool {
    safe_word(s, 40)
}

impl Schedule {
    pub fn validate(&self) -> Result<(), Invalid> {
        let bad = |k: &'static str, d: &str| Err((k, d.to_string()));
        if self.name.trim().is_empty() || self.name.chars().count() > 80 {
            return bad("sched.bad_name", "");
        }
        if !crate::timezone::valid_zone(&self.time_zone) {
            return bad("sched.bad_zone", &self.time_zone);
        }
        match &self.when {
            When::Cron { expr } => {
                if let Err(e) = Cron::parse(expr) {
                    return Err((e.key, e.detail));
                }
            }
            When::Every { minutes } => {
                let min = if self.heartbeat { 5 } else { 1 };
                if *minutes < min || *minutes > 1440 {
                    return bad("sched.bad_interval", &format!("{min}-1440"));
                }
            }
        }
        if !safe_word(&self.engine, 40) || self.engine.bytes().any(|b| b.is_ascii_uppercase()) {
            return bad("sched.bad_engine", "");
        }
        let has_text = self.prompt.as_deref().is_some_and(|p| !p.trim().is_empty())
            || self.skill.as_deref().is_some_and(|s| !s.trim().is_empty());
        if !has_text && !self.heartbeat {
            return bad("sched.need_prompt", "");
        }
        if self
            .prompt
            .as_deref()
            .is_some_and(|p| p.chars().count() > MAX_PROMPT_CHARS)
        {
            return bad("sched.prompt_too_long", "");
        }
        if self
            .skill
            .as_deref()
            .is_some_and(|s| !s.is_empty() && !safe_word(s, 60))
        {
            return bad("sched.bad_skill", "");
        }
        self.target.validate()?;
        if self.caps.max_spend_cents == Some(0) {
            return bad("sched.bad_cap", "spend");
        }
        if self
            .caps
            .max_minutes
            .is_some_and(|m| !(1..=1440).contains(&m))
        {
            return bad("sched.bad_cap", "minutes");
        }
        if self.catch_up_minutes > 1440 {
            return bad("sched.bad_catch_up", "");
        }
        if self.results_to.len() > 10
            || self
                .results_to
                .iter()
                .any(|r| !matches!(r.as_str(), "alert" | "pull_request"))
        {
            return bad("sched.bad_results_to", "");
        }
        if !self.owner.is_empty() && self.owner.chars().count() > 80 {
            return bad("sched.bad_owner", "");
        }
        Ok(())
    }
}

impl Target {
    pub fn validate(&self) -> Result<(), Invalid> {
        match (&self.box_name, &self.profile) {
            (Some(b), None) => {
                if ozbox_core::BoxName::new(b).is_err() {
                    return Err(("sched.bad_target", b.clone()));
                }
                Ok(())
            }
            (None, Some(p)) => {
                if !safe_word(p, 40) {
                    return Err(("sched.bad_target", p.clone()));
                }
                Ok(())
            }
            _ => Err(("sched.need_target", String::new())),
        }
    }
}

/// What the scheduler remembers about one schedule between ticks and restarts.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct SchedState {
    /// When it was last switched on: slots at or before this never run.
    pub armed_ms: u64,
    /// The latest slot served (run, skipped or recorded as missed).
    pub last_slot_ms: Option<u64>,
    /// The run in flight, if any: the next slot is skipped while there is one (Forbid).
    pub running: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RunStatus {
    /// Claimed, not yet handed to the run system.
    Starting,
    Running,
    Succeeded,
    Failed,
    /// A slot that did not run: the previous run was still going.
    Skipped,
    /// A slot that passed outside the catch-up window.
    Missed,
}

impl RunStatus {
    pub fn is_open(self) -> bool {
        matches!(self, RunStatus::Starting | RunStatus::Running)
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct RunRec {
    pub id: String,
    /// The schedule id, or the trigger id.
    pub owner_id: String,
    /// `schedule`, `manual` or `trigger`.
    pub source: String,
    pub slot_ms: Option<u64>,
    pub started_ms: u64,
    pub finished_ms: Option<u64>,
    pub status: RunStatus,
    /// Words a person reads: why it was skipped, failed or late. Never a secret.
    pub detail: String,
    /// A reason code (`overlap`, `missed`, `caught_up`, `resume_failed`, ...) the dashboard words in its own language.
    pub reason: String,
    /// Numbers and names the reason's sentence needs.
    pub args: BTreeMap<String, String>,
    pub box_name: Option<String>,
    /// The scheduler woke a paused box for this run.
    pub woke_box: bool,
    /// The run system's own reference, used to follow it.
    pub run_ref: Option<String>,
    pub cost: Option<f64>,
    pub result_url: Option<String>,
    /// The epoch of the lease the run was claimed under.
    pub epoch: u64,
}

impl Default for RunRec {
    fn default() -> Self {
        RunRec {
            id: String::new(),
            owner_id: String::new(),
            source: "schedule".into(),
            slot_ms: None,
            started_ms: 0,
            finished_ms: None,
            status: RunStatus::Starting,
            detail: String::new(),
            reason: String::new(),
            args: BTreeMap::new(),
            box_name: None,
            woke_box: false,
            run_ref: None,
            cost: None,
            result_url: None,
            epoch: 0,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Lease {
    pub holder: String,
    /// Raised every time the lease changes hands (or is retaken after it lapsed): the fence.
    pub epoch: u64,
    /// This holder's own clock: when its lease lapses, checked only by the holder itself. `0` means released.
    pub expires_ms: u64,
    /// Raised on every renewal. Another computer decides the holder is gone only when this has not moved for a full
    /// lease by *its own* clock, so the two clocks are never compared.
    #[serde(default)]
    pub beat: u64,
    /// Each would-be taker's own clock reading the first time it saw `beat`: `holder -> (beat, its time)`.
    #[serde(default)]
    pub watchers: std::collections::BTreeMap<String, (u64, u64)>,
}

impl Lease {
    pub fn new(holder: &str, epoch: u64, now_ms: u64) -> Lease {
        Lease {
            holder: holder.to_string(),
            epoch,
            expires_ms: now_ms + super::store::LEASE_MS,
            beat: 0,
            watchers: Default::default(),
        }
    }
}

/// Who fired a slot, under which epoch.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Claim {
    pub holder: String,
    pub epoch: u64,
    pub ts_ms: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Scheme {
    /// GitHub: `X-Hub-Signature-256: sha256=<hmac of the body>`, `X-GitHub-Delivery` as the id.
    Github,
    /// Our own: `X-Ozbox-Timestamp`, `X-Ozbox-Signature: v1=<hmac of "timestamp.body">`, `X-Ozbox-Delivery`.
    Generic,
    /// Stripe-style: `Stripe-Signature: t=<ts>,v1=<hmac of "ts.body">`, the body's `id` as the delivery id.
    Stripe,
}

impl Scheme {
    pub fn id(self) -> &'static str {
        match self {
            Scheme::Github => "github",
            Scheme::Generic => "generic",
            Scheme::Stripe => "stripe",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct Trigger {
    pub id: String,
    pub name: String,
    pub scheme: Scheme,
    #[serde(default = "default_engine", deserialize_with = "engine_on_read")]
    pub engine: String,
    /// The instruction. `{{field.path}}` names a field of the event; the value itself only ever appears in the data
    /// block (see `hooks::render`).
    pub template: String,
    pub skill: Option<String>,
    pub target: Target,
    pub caps: Caps,
    pub results_to: Vec<String>,
    /// GitHub only: event names to act on (`push`, `pull_request`); empty = every event but `ping`.
    pub events: Vec<String>,
    pub enabled: bool,
    pub owner: String,
    pub created_ms: u64,
    /// After a secret rotation, the old secret is still accepted until this time (milliseconds since the epoch), so
    /// the sender can be updated without a gap.
    pub previous_secret_until_ms: Option<u64>,
}

impl Default for Trigger {
    fn default() -> Self {
        Trigger {
            id: String::new(),
            name: String::new(),
            scheme: Scheme::Github,
            engine: DEFAULT_ENGINE.into(),
            template: String::new(),
            skill: None,
            target: Target::default(),
            caps: Caps::default(),
            results_to: Vec::new(),
            events: Vec::new(),
            enabled: true,
            owner: String::new(),
            created_ms: 0,
            previous_secret_until_ms: None,
        }
    }
}

impl Trigger {
    pub fn validate(&self) -> Result<(), Invalid> {
        if self.name.trim().is_empty() || self.name.chars().count() > 80 {
            return Err(("sched.bad_name", String::new()));
        }
        if !safe_word(&self.engine, 40) || self.engine.bytes().any(|b| b.is_ascii_uppercase()) {
            return Err(("sched.bad_engine", String::new()));
        }
        if self.template.trim().is_empty() {
            return Err(("trigger.need_template", String::new()));
        }
        if self.template.chars().count() > MAX_PROMPT_CHARS {
            return Err(("sched.prompt_too_long", String::new()));
        }
        if self
            .skill
            .as_deref()
            .is_some_and(|s| !s.is_empty() && !safe_word(s, 60))
        {
            return Err(("sched.bad_skill", String::new()));
        }
        self.target.validate()?;
        if self.events.len() > 30 || self.events.iter().any(|e| !safe_word(e, 40)) {
            return Err(("trigger.bad_events", String::new()));
        }
        if self.results_to.len() > 10
            || self
                .results_to
                .iter()
                .any(|r| !matches!(r.as_str(), "alert" | "pull_request"))
        {
            return Err(("sched.bad_results_to", String::new()));
        }
        if self.caps.max_spend_cents == Some(0) {
            return Err(("sched.bad_cap", "spend".into()));
        }
        if self
            .caps
            .max_minutes
            .is_some_and(|m| !(1..=1440).contains(&m))
        {
            return Err(("sched.bad_cap", "minutes".into()));
        }
        Ok(())
    }
}

/// One request to `/hooks/<id>`, kept so a person can see why it was refused. Holds no payload and no signature.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct Delivery {
    pub id: String,
    pub trigger_id: String,
    pub ts_ms: u64,
    /// `accepted`, `refused`, `ignored` or `test`.
    pub outcome: String,
    /// The reason code: `bad_signature`, `missing_signature`, `expired`, `replayed`, `too_large`, `rate_limited`, ...
    pub reason: String,
    /// The sender's delivery id (GitHub's GUID), for replay protection.
    pub delivery_id: Option<String>,
    pub event: Option<String>,
    pub size: u64,
    pub run_id: Option<String>,
}

impl Default for Delivery {
    fn default() -> Self {
        Delivery {
            id: String::new(),
            trigger_id: String::new(),
            ts_ms: 0,
            outcome: "refused".into(),
            reason: String::new(),
            delivery_id: None,
            event: None,
            size: 0,
            run_id: None,
        }
    }
}

/// A "run now" asked for from outside the server (the CLI writes it; the lease holder picks it up).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RunNow {
    pub id: String,
    pub schedule_id: String,
    pub requested_ms: u64,
    pub by: String,
}

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct Doc {
    pub schedules: Vec<Schedule>,
    pub state: BTreeMap<String, SchedState>,
    pub runs: Vec<RunRec>,
    pub triggers: Vec<Trigger>,
    pub deliveries: Vec<Delivery>,
    /// `<schedule id>@<slot ms>` to who fired it. A slot fires once, ever.
    pub claims: BTreeMap<String, Claim>,
    /// Sender delivery ids already seen: `<trigger id>:<delivery id>` to when.
    pub seen: BTreeMap<String, u64>,
    pub lease: Option<Lease>,
    pub run_now: Vec<RunNow>,
}

impl Doc {
    pub fn schedule(&self, id: &str) -> Option<&Schedule> {
        self.schedules.iter().find(|s| s.id == id)
    }

    pub fn trigger(&self, id: &str) -> Option<&Trigger> {
        self.triggers.iter().find(|t| t.id == id)
    }

    pub fn trim(&mut self, now_ms: u64) {
        let over = self.runs.len().saturating_sub(MAX_RUNS_KEPT);
        if over > 0 {
            self.runs.drain(..over);
        }
        let over = self.deliveries.len().saturating_sub(MAX_DELIVERIES_KEPT);
        if over > 0 {
            self.deliveries.drain(..over);
        }
        let cutoff = now_ms.saturating_sub(40 * 86_400_000);
        self.claims.retain(|_, c| c.ts_ms >= cutoff);
        let seen_cutoff = now_ms.saturating_sub(2 * 86_400_000);
        self.seen.retain(|_, ts| *ts >= seen_cutoff);
        self.run_now
            .retain(|r| r.requested_ms + 3_600_000 >= now_ms);
    }
}
