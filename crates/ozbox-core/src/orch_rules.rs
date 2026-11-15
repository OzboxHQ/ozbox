//! The policy of an orchestration, and the rules file that can only tighten it.
//!
//! Three layers meet here. The person's **settings** ([`OrchSettings`]) are the ceiling. A **rules file**
//! (`ozbox.orchestration.md`: a small front-matter block plus plain-language guidance the conductor reads) and the
//! **request** that starts an orchestration are [`Overrides`]. [`effective`] folds them in order and can only make
//! things stricter: limits take the smaller value, the set of things the conductor may decide can only shrink, a merge
//! approval can only move toward the person, and a permission can only be switched off. Anything a layer tried to
//! loosen is ignored and named in [`OrchPolicy::notes`], so the person sees it.
//!
//! The front matter is `key: value` lines between two `---` lines; a list is comma separated. It is parsed here and
//! never evaluated: no key runs anything, and a test command is a list of words, never a shell string.

use std::collections::BTreeSet;

use serde::{Deserialize, Serialize};

use crate::run::ActionKind;

pub const HARD_MAX_WORKERS: u8 = 16;
pub const HARD_MAX_SUB_AGENTS: u8 = 8;
pub const MAX_RULES_BYTES: usize = 32 * 1024;

/// Who must approve a merge into the base branch. Ordered from loosest to strictest.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MergeApproval {
    /// Merge as soon as the tests pass.
    None,
    /// The conductor may approve (never a request that needs a second factor).
    Conductor,
    /// The person, with their passkey where sign-in mode asks for one.
    Person,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OverlapRule {
    /// A claim that overlaps another feature's is refused.
    Refuse,
    /// The later feature waits for the earlier one to merge.
    Sequence,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum WorkerKind {
    /// A copy of the conductor's box (the default).
    Clone,
    /// A new box from a profile, size and provider.
    Create,
    /// An idle box that already exists.
    Reuse,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WorkerPref {
    pub kind: WorkerKind,
    #[serde(default)]
    pub profile: Option<String>,
    #[serde(default)]
    pub size: Option<String>,
    #[serde(default)]
    pub provider: Option<String>,
}

impl Default for WorkerPref {
    fn default() -> Self {
        Self {
            kind: WorkerKind::Clone,
            profile: None,
            size: None,
            provider: None,
        }
    }
}

/// The person's limits. Defaults: three worker boxes, three sub-agents each, one spend cap.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct OrchSettings {
    pub max_workers: u8,
    pub max_sub_agents: u8,
    pub spend_cap_cents: Option<u64>,
    /// What the conductor may decide in the approvals. Never a request that needs a second factor or touches production.
    pub conductor_may: BTreeSet<ActionKind>,
    pub merge_approval: MergeApproval,
    pub may_create_boxes: bool,
    pub destroy_after_days: u32,
}

impl Default for OrchSettings {
    fn default() -> Self {
        Self {
            max_workers: 3,
            max_sub_agents: 3,
            spend_cap_cents: Some(5000),
            conductor_may: [ActionKind::AskCommand].into_iter().collect(),
            merge_approval: MergeApproval::Person,
            may_create_boxes: true,
            destroy_after_days: 7,
        }
    }
}

impl OrchSettings {
    pub fn validate(&self) -> Result<(), String> {
        if self.max_workers == 0 || self.max_workers > HARD_MAX_WORKERS {
            return Err(format!("worker boxes: 1 to {HARD_MAX_WORKERS}"));
        }
        if self.max_sub_agents == 0 || self.max_sub_agents > HARD_MAX_SUB_AGENTS {
            return Err(format!("sub-agents: 1 to {HARD_MAX_SUB_AGENTS}"));
        }
        if self
            .spend_cap_cents
            .is_some_and(|c| c == 0 || c > 10_000_000)
        {
            return Err("spend cap: more than zero and at most $100,000".into());
        }
        if self.destroy_after_days > 365 {
            return Err("destroy after: at most 365 days".into());
        }
        Ok(())
    }
}

/// What a rules file or a request says. Every field is optional.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct Overrides {
    pub max_workers: Option<u8>,
    pub max_sub_agents: Option<u8>,
    pub spend_cap_cents: Option<u64>,
    pub conductor_may: Option<BTreeSet<ActionKind>>,
    pub merge_approval: Option<MergeApproval>,
    pub may_create_boxes: Option<bool>,
    pub destroy_after_days: Option<u32>,
    pub keep_workers: Option<bool>,
    pub test_command: Option<Vec<String>>,
    pub test_lane_box: Option<String>,
    pub worker_kind: Option<WorkerKind>,
    pub worker_profile: Option<String>,
    pub worker_size: Option<String>,
    pub worker_provider: Option<String>,
    pub on_overlap: Option<OverlapRule>,
    pub branch_prefix: Option<String>,
    pub base_branch: Option<String>,
    pub repo: Option<String>,
    pub engine: Option<String>,
    pub strict_claims: Option<bool>,
    /// The plain-language guidance the conductor and workers read.
    pub guidance: Option<String>,
}

/// The policy an orchestration runs under, after every layer is folded in.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OrchPolicy {
    pub max_workers: u8,
    pub max_sub_agents: u8,
    pub spend_cap_cents: Option<u64>,
    pub conductor_may: BTreeSet<ActionKind>,
    pub merge_approval: MergeApproval,
    pub may_create_boxes: bool,
    pub destroy_after_days: u32,
    #[serde(default)]
    pub keep_workers: bool,
    #[serde(default)]
    pub test_command: Vec<String>,
    #[serde(default)]
    pub test_lane_box: Option<String>,
    #[serde(default)]
    pub worker: WorkerPref,
    pub on_overlap: OverlapRule,
    pub branch_prefix: String,
    pub base_branch: String,
    #[serde(default)]
    pub repo: Option<String>,
    pub engine: String,
    pub strict_claims: bool,
    #[serde(default)]
    pub guidance: String,
    /// What a layer asked for that the settings do not allow, in words.
    #[serde(default)]
    pub notes: Vec<String>,
}

fn word_ok(s: &str, max: usize) -> bool {
    !s.is_empty()
        && s.len() <= max
        && s.chars()
            .all(|c| c.is_ascii_alphanumeric() || "-._/".contains(c))
        && !s.contains("..")
}

/// Fold the layers over the settings, tightening only.
pub fn effective(settings: &OrchSettings, layers: &[&Overrides]) -> OrchPolicy {
    let mut p = OrchPolicy {
        max_workers: settings.max_workers.clamp(1, HARD_MAX_WORKERS),
        max_sub_agents: settings.max_sub_agents.clamp(1, HARD_MAX_SUB_AGENTS),
        spend_cap_cents: settings.spend_cap_cents,
        conductor_may: settings.conductor_may.clone(),
        merge_approval: settings.merge_approval,
        may_create_boxes: settings.may_create_boxes,
        destroy_after_days: settings.destroy_after_days,
        keep_workers: false,
        test_command: Vec::new(),
        test_lane_box: None,
        worker: WorkerPref::default(),
        on_overlap: OverlapRule::Refuse,
        branch_prefix: "orch/".into(),
        base_branch: "main".into(),
        repo: None,
        engine: "claude-code".into(),
        strict_claims: true,
        guidance: String::new(),
        notes: Vec::new(),
    };
    for o in layers {
        if let Some(n) = o.max_workers {
            if n == 0 {
                p.notes.push("worker boxes: zero ignored".into());
            } else if n > p.max_workers {
                p.notes.push(format!(
                    "worker boxes: {n} is over the limit of {}",
                    p.max_workers
                ));
            } else {
                p.max_workers = n;
            }
        }
        if let Some(n) = o.max_sub_agents {
            if n == 0 {
                p.notes.push("sub-agents: zero ignored".into());
            } else if n > p.max_sub_agents {
                p.notes.push(format!(
                    "sub-agents: {n} is over the limit of {}",
                    p.max_sub_agents
                ));
            } else {
                p.max_sub_agents = n;
            }
        }
        if let Some(c) = o.spend_cap_cents {
            match p.spend_cap_cents {
                Some(cur) if c > cur => p
                    .notes
                    .push(format!("spend cap: {c} cents is over the limit of {cur}")),
                _ if c == 0 => p.notes.push("spend cap: zero ignored".into()),
                _ => p.spend_cap_cents = Some(c),
            }
        }
        if let Some(set) = &o.conductor_may {
            let extra: Vec<_> = set.difference(&p.conductor_may).collect();
            if !extra.is_empty() {
                p.notes.push(
                    "conductor may decide: kinds the settings do not allow were ignored".into(),
                );
            }
            p.conductor_may = p.conductor_may.intersection(set).copied().collect();
        }
        if let Some(m) = o.merge_approval {
            if m < p.merge_approval {
                p.notes
                    .push("merge approval: a looser rule than the settings was ignored".into());
            } else {
                p.merge_approval = m;
            }
        }
        if o.may_create_boxes == Some(false) {
            p.may_create_boxes = false;
        } else if o.may_create_boxes == Some(true) && !p.may_create_boxes {
            p.notes
                .push("new boxes: the settings do not allow them".into());
        }
        if let Some(d) = o.destroy_after_days {
            if d > p.destroy_after_days {
                p.notes.push(format!(
                    "destroy after: {d} days is over the limit of {}",
                    p.destroy_after_days
                ));
            } else {
                p.destroy_after_days = d;
            }
        }
        if let Some(k) = o.keep_workers {
            p.keep_workers = k;
        }
        if let Some(t) = &o.test_command {
            if t.len() <= 16
                && t.iter()
                    .all(|w| !w.is_empty() && w.len() <= 200 && !w.chars().any(char::is_control))
            {
                p.test_command = t.clone();
            } else {
                p.notes
                    .push("test command: not a list of plain words".into());
            }
        }
        if let Some(b) = &o.test_lane_box {
            if crate::name::BoxName::new(b.clone()).is_ok() {
                p.test_lane_box = Some(b.clone());
            }
        }
        if let Some(k) = o.worker_kind {
            p.worker.kind = k;
        }
        for (v, slot) in [
            (&o.worker_profile, &mut p.worker.profile),
            (&o.worker_size, &mut p.worker.size),
            (&o.worker_provider, &mut p.worker.provider),
        ] {
            if let Some(v) = v {
                if word_ok(v, 60) {
                    *slot = Some(v.clone());
                }
            }
        }
        if !p.may_create_boxes && p.worker.kind != WorkerKind::Clone {
            p.worker.kind = WorkerKind::Clone;
            p.notes
                .push("worker boxes: only clones of the conductor's box are allowed".into());
        }
        if let Some(r) = o.on_overlap {
            p.on_overlap = r;
        }
        if let Some(b) = &o.branch_prefix {
            if word_ok(b, 40) && b.ends_with('/') && !b.starts_with('/') {
                p.branch_prefix = b.clone();
            } else {
                p.notes
                    .push("branch prefix: letters, digits, - . _ and a final /".into());
            }
        }
        if let Some(b) = &o.base_branch {
            if word_ok(b, 60) {
                p.base_branch = b.clone();
            }
        }
        if let Some(r) = &o.repo {
            if word_ok(r, 200) && !r.starts_with('/') {
                p.repo = Some(r.clone());
            }
        }
        if let Some(e) = &o.engine {
            if word_ok(e, 40) && e.chars().all(|c| !c.is_ascii_uppercase()) {
                p.engine = e.clone();
            }
        }
        if o.strict_claims == Some(true) {
            p.strict_claims = true;
        } else if o.strict_claims == Some(false) {
            p.notes.push("claims: the check stays strict".into());
        }
        if let Some(g) = &o.guidance {
            if !p.guidance.is_empty() {
                p.guidance.push_str("\n\n");
            }
            p.guidance.push_str(g.trim());
        }
    }
    p
}

fn kind_of(s: &str) -> Option<ActionKind> {
    ActionKind::ALL.into_iter().find(|k| {
        serde_json::to_value(k)
            .ok()
            .and_then(|v| v.as_str().map(|x| x == s))
            .unwrap_or(false)
    })
}

fn list(v: &str) -> Vec<String> {
    v.split(',')
        .map(|x| x.trim().to_string())
        .filter(|x| !x.is_empty())
        .collect()
}

fn num<T: std::str::FromStr>(key: &str, v: &str) -> Result<T, String> {
    v.trim()
        .parse()
        .map_err(|_| format!("{key}: {v} is not a whole number"))
}

fn flag(key: &str, v: &str) -> Result<bool, String> {
    match v.trim() {
        "true" | "yes" | "on" => Ok(true),
        "false" | "no" | "off" => Ok(false),
        _ => Err(format!("{key}: use true or false")),
    }
}

/// Read `ozbox.orchestration.md`: the front matter becomes [`Overrides`], the rest is the guidance. A key this does
/// not know is an error, so a typo cannot silently drop a limit.
pub fn parse_rules(text: &str) -> Result<Overrides, String> {
    if text.len() > MAX_RULES_BYTES {
        return Err("the rules file is at most 32 KB".into());
    }
    let mut o = Overrides::default();
    let mut lines = text.lines();
    let mut body = Vec::new();
    let first = lines.clone().find(|l| !l.trim().is_empty());
    if first.map(str::trim) == Some("---") {
        let mut seen_open = false;
        let mut closed = false;
        for l in lines.by_ref() {
            if !seen_open {
                if l.trim() == "---" {
                    seen_open = true;
                }
                continue;
            }
            if l.trim() == "---" {
                closed = true;
                break;
            }
            let t = l.trim();
            if t.is_empty() || t.starts_with('#') {
                continue;
            }
            let (k, v) = t
                .split_once(':')
                .ok_or_else(|| format!("front matter: `{t}` is not key: value"))?;
            let (k, v) = (k.trim(), v.trim());
            match k {
                "max_workers" => o.max_workers = Some(num(k, v)?),
                "max_sub_agents" => o.max_sub_agents = Some(num(k, v)?),
                "spend_cap" | "spend_cap_usd" => {
                    let usd: f64 = v
                        .trim_start_matches('$')
                        .parse()
                        .map_err(|_| format!("{k}: not an amount"))?;
                    if !usd.is_finite() || usd < 0.0 {
                        return Err(format!("{k}: not an amount"));
                    }
                    o.spend_cap_cents = Some((usd * 100.0).round() as u64);
                }
                "conductor_may" => {
                    let mut set = BTreeSet::new();
                    for w in list(v) {
                        if w == "none" {
                            continue;
                        }
                        set.insert(
                            kind_of(&w)
                                .ok_or_else(|| format!("{k}: {w} is not a kind of action"))?,
                        );
                    }
                    o.conductor_may = Some(set);
                }
                "merge_approval" => {
                    o.merge_approval = Some(match v {
                        "none" => MergeApproval::None,
                        "conductor" => MergeApproval::Conductor,
                        "person" => MergeApproval::Person,
                        _ => return Err(format!("{k}: use none, conductor or person")),
                    })
                }
                "may_create_boxes" => o.may_create_boxes = Some(flag(k, v)?),
                "destroy_after_days" => o.destroy_after_days = Some(num(k, v)?),
                "keep_workers" => o.keep_workers = Some(flag(k, v)?),
                "test_command" => {
                    o.test_command = Some(v.split_whitespace().map(str::to_string).collect())
                }
                "test_lane_box" => o.test_lane_box = Some(v.to_string()),
                "worker" | "worker_kind" => {
                    o.worker_kind = Some(match v {
                        "clone" => WorkerKind::Clone,
                        "create" | "fresh" => WorkerKind::Create,
                        "reuse" => WorkerKind::Reuse,
                        _ => return Err(format!("{k}: use clone, create or reuse")),
                    })
                }
                "worker_profile" => o.worker_profile = Some(v.to_string()),
                "worker_size" => o.worker_size = Some(v.to_string()),
                "worker_provider" => o.worker_provider = Some(v.to_string()),
                "on_overlap" => {
                    o.on_overlap = Some(match v {
                        "refuse" => OverlapRule::Refuse,
                        "sequence" => OverlapRule::Sequence,
                        _ => return Err(format!("{k}: use refuse or sequence")),
                    })
                }
                "branch_prefix" => o.branch_prefix = Some(v.to_string()),
                "base_branch" => o.base_branch = Some(v.to_string()),
                "repo" => o.repo = Some(v.to_string()),
                "engine" => o.engine = Some(v.to_string()),
                "strict_claims" => o.strict_claims = Some(flag(k, v)?),
                other => return Err(format!("front matter: {other} is not a known setting")),
            }
        }
        if !closed {
            return Err("front matter: the closing --- is missing".into());
        }
        body.extend(lines);
    } else {
        body.extend(text.lines());
    }
    let guidance = body.join("\n");
    if !guidance.trim().is_empty() {
        o.guidance = Some(guidance.trim().to_string());
    }
    Ok(o)
}
