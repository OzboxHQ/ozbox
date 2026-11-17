//! Box power from chat (ADR 0050 §3): the caps an allowed power act must still fit inside, checked against a plan.
//!
//! [`super::decide`] says whether the person holds a power delegation for the box. This module says whether **this** act,
//! as the provider planned it, fits the caps that delegation carries: the size cap, the daily money cap, the count caps,
//! the per-box cooldown and, for a pause, an idle box. A refusal here is a handoff to the dashboard, never a half act.
//!
//! Pure: the caller reads the counters, the price and the box's state, and gets a verdict.

use super::records::Caps;
use crate::Size;

/// How long a box started from chat may run before it is paused again (four hours).
pub const DEADLINE_MS: u64 = 4 * 3_600_000;
/// The longest one extension may add (two hours), and it may be made once.
pub const MAX_EXTEND_HOURS: u8 = 2;
/// Two power acts on one box at least this far apart.
pub const COOLDOWN_MS: u64 = 60_000;

/// The power acts that change a box.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PowerAct {
    Resume,
    Pause,
    Extend { hours: u8 },
    Create { size: Size },
    Resize { size: Size },
}

impl PowerAct {
    /// The hours of box time the act starts, which the money cap counts.
    fn billed_hours(self) -> u64 {
        match self {
            PowerAct::Pause => 0,
            PowerAct::Extend { hours } => u64::from(hours),
            PowerAct::Resume | PowerAct::Create { .. } | PowerAct::Resize { .. } => {
                DEADLINE_MS / 3_600_000
            }
        }
    }
}

/// What this person has done with box power today, and what the box says now.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct PowerFacts {
    pub resumes_today: u32,
    pub creates_today: u32,
    /// Box time started or extended from chat today, in cents.
    pub spent_today_cents: u64,
    /// Boxes started from chat that are running now.
    pub running_from_chat: u32,
    /// The last power act on this box, 0 when none.
    pub last_on_box_ms: u64,
    /// The box's price per hour at the size it will run at, in cents. `None`: no price is known, which is never zero.
    pub hourly_cents: Option<u64>,
    /// For a pause: what the pause would end (runs, sessions, requests). Empty when the box is idle. `None`: the box could
    /// not say, which is not idle.
    pub would_end: Option<Vec<String>>,
    /// For an extend: the box was started from chat and has a deadline.
    pub has_deadline: bool,
    /// For an extend: it was extended once already.
    pub extended: bool,
}

/// Why a power act does not fit. Each has a message in the catalogue and a permanent code for the audit chain.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PowerRefusal {
    /// The delegation names no size cap: a chat may not create or resize.
    NoSizeCap,
    /// The size is above the delegation's cap.
    AboveSizeCap,
    /// A GPU size is never reached from chat.
    GpuSize,
    /// No price is known for the size, so the money cap cannot be checked.
    PriceUnknown,
    /// The day's money cap would be passed.
    MoneyCap,
    ResumesCap,
    CreatesCap,
    RunningCap,
    Cooldown,
    /// The box is not idle: what the pause would end.
    NotIdle(Vec<String>),
    /// The box could not say whether it is idle.
    IdleUnknown,
    /// Only a box started from chat has a deadline to extend.
    NoDeadline,
    /// The deadline was extended once already.
    ExtendedAlready,
}

impl PowerRefusal {
    pub fn code(&self) -> &'static str {
        match self {
            PowerRefusal::NoSizeCap => "no_size_cap",
            PowerRefusal::AboveSizeCap => "above_size_cap",
            PowerRefusal::GpuSize => "gpu_size",
            PowerRefusal::PriceUnknown => "price_unknown",
            PowerRefusal::MoneyCap => "money_cap",
            PowerRefusal::ResumesCap => "resumes_cap",
            PowerRefusal::CreatesCap => "creates_cap",
            PowerRefusal::RunningCap => "running_cap",
            PowerRefusal::Cooldown => "cooldown",
            PowerRefusal::NotIdle(_) => "not_idle",
            PowerRefusal::IdleUnknown => "idle_unknown",
            PowerRefusal::NoDeadline => "no_deadline",
            PowerRefusal::ExtendedAlready => "extended_already",
        }
    }

    /// The message-catalogue key the person reads.
    pub fn message(&self) -> &'static str {
        match self {
            PowerRefusal::NoSizeCap => "tg.power_no_size_cap",
            PowerRefusal::AboveSizeCap => "tg.power_above_size_cap",
            PowerRefusal::GpuSize => "tg.power_gpu",
            PowerRefusal::PriceUnknown => "tg.power_price_unknown",
            PowerRefusal::MoneyCap => "tg.power_money_cap",
            PowerRefusal::ResumesCap => "tg.power_resumes_cap",
            PowerRefusal::CreatesCap => "tg.power_creates_cap",
            PowerRefusal::RunningCap => "tg.power_running_cap",
            PowerRefusal::Cooldown => "tg.power_cooldown",
            PowerRefusal::NotIdle(_) => "tg.power_not_idle",
            PowerRefusal::IdleUnknown => "tg.power_idle_unknown",
            PowerRefusal::NoDeadline => "tg.power_no_deadline",
            PowerRefusal::ExtendedAlready => "tg.power_extended_already",
        }
    }
}

/// What the act will cost against the money cap, in cents, when a price is known.
pub fn projected_cents(act: PowerAct, hourly_cents: Option<u64>) -> Option<u64> {
    match act.billed_hours() {
        0 => Some(0),
        h => hourly_cents.map(|c| c.saturating_mul(h)),
    }
}

/// Whether one planned power act fits the delegation's caps. `plan_is_noop`: the provider planned nothing (the box is
/// already in that state), which is always allowed, because it changes nothing and costs nothing.
pub fn check(
    act: PowerAct,
    caps: &Caps,
    facts: &PowerFacts,
    plan_is_noop: bool,
    now_ms: u64,
) -> Result<(), PowerRefusal> {
    if plan_is_noop {
        return Ok(());
    }
    if facts.last_on_box_ms > 0 && now_ms.saturating_sub(facts.last_on_box_ms) < COOLDOWN_MS {
        return Err(PowerRefusal::Cooldown);
    }
    match act {
        PowerAct::Create { size } | PowerAct::Resize { size } => {
            if matches!(size, Size::Gpu(_)) {
                return Err(PowerRefusal::GpuSize);
            }
            let Some(cap) = caps.max_size.as_deref() else {
                return Err(PowerRefusal::NoSizeCap);
            };
            match cap.parse::<Size>() {
                Ok(c) if size <= c => {}
                _ => return Err(PowerRefusal::AboveSizeCap),
            }
        }
        PowerAct::Pause => match &facts.would_end {
            None => return Err(PowerRefusal::IdleUnknown),
            Some(v) if !v.is_empty() => return Err(PowerRefusal::NotIdle(v.clone())),
            Some(_) => {}
        },
        PowerAct::Extend { hours } => {
            if !facts.has_deadline {
                return Err(PowerRefusal::NoDeadline);
            }
            if facts.extended || hours == 0 || hours > MAX_EXTEND_HOURS {
                return Err(PowerRefusal::ExtendedAlready);
            }
        }
        PowerAct::Resume => {}
    }
    match act {
        PowerAct::Resume if facts.resumes_today >= caps.resumes_per_day => {
            return Err(PowerRefusal::ResumesCap)
        }
        PowerAct::Create { .. } if facts.creates_today >= caps.creates_per_day => {
            return Err(PowerRefusal::CreatesCap)
        }
        PowerAct::Resume | PowerAct::Create { .. } if facts.running_from_chat >= caps.running => {
            return Err(PowerRefusal::RunningCap)
        }
        _ => {}
    }
    let Some(cost) = projected_cents(act, facts.hourly_cents) else {
        return Err(PowerRefusal::PriceUnknown);
    };
    let cap = u64::from(caps.daily_usd) * 100;
    if facts.spent_today_cents.saturating_add(cost) > cap {
        return Err(PowerRefusal::MoneyCap);
    }
    Ok(())
}

/// The UTC day a moment falls in, for the daily counters.
pub fn day_of(ms: u64) -> u64 {
    ms / 86_400_000
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    const NOW: u64 = 1_800_000_000_000;

    fn caps() -> Caps {
        Caps {
            max_size: Some("M".into()),
            ..Caps::default()
        }
    }

    fn priced() -> PowerFacts {
        PowerFacts {
            hourly_cents: Some(50),
            would_end: Some(vec![]),
            ..PowerFacts::default()
        }
    }

    #[test]
    fn a_plan_that_changes_nothing_is_always_inside_the_caps() {
        let f = PowerFacts {
            resumes_today: 99,
            ..PowerFacts::default()
        };
        assert!(check(PowerAct::Resume, &caps(), &f, true, NOW).is_ok());
    }

    #[test]
    fn create_and_resize_need_a_size_cap_and_stay_at_or_below_it_and_never_a_gpu() {
        let f = priced();
        assert!(check(PowerAct::Create { size: Size::M }, &caps(), &f, false, NOW).is_ok());
        assert!(check(PowerAct::Resize { size: Size::XS }, &caps(), &f, false, NOW).is_ok());
        assert_eq!(
            check(PowerAct::Resize { size: Size::L }, &caps(), &f, false, NOW),
            Err(PowerRefusal::AboveSizeCap)
        );
        assert_eq!(
            check(PowerAct::Create { size: Size::M }, &Caps::default(), &f, false, NOW),
            Err(PowerRefusal::NoSizeCap)
        );
        let gpu = Size::Gpu(crate::size::GpuKind::Small);
        assert_eq!(
            check(PowerAct::Create { size: gpu }, &caps(), &f, false, NOW),
            Err(PowerRefusal::GpuSize)
        );
    }

    #[test]
    fn the_money_cap_counts_four_hours_and_an_unknown_price_is_never_zero() {
        // $10 a day: four hours at $2 = $8 fits, at $3 = $12 does not
        let mut f = priced();
        f.hourly_cents = Some(200);
        assert!(check(PowerAct::Resume, &caps(), &f, false, NOW).is_ok());
        f.hourly_cents = Some(300);
        assert_eq!(
            check(PowerAct::Resume, &caps(), &f, false, NOW),
            Err(PowerRefusal::MoneyCap)
        );
        f.hourly_cents = Some(200);
        f.spent_today_cents = 300;
        assert_eq!(
            check(PowerAct::Resume, &caps(), &f, false, NOW),
            Err(PowerRefusal::MoneyCap)
        );
        f.hourly_cents = None;
        f.spent_today_cents = 0;
        assert_eq!(
            check(PowerAct::Resume, &caps(), &f, false, NOW),
            Err(PowerRefusal::PriceUnknown)
        );
        // a pause costs nothing, so an unknown price does not stop it
        assert!(check(PowerAct::Pause, &caps(), &f, false, NOW).is_ok());
    }

    #[test]
    fn the_count_caps_and_the_cooldown_hold() {
        let mut f = priced();
        f.resumes_today = 6;
        assert_eq!(
            check(PowerAct::Resume, &caps(), &f, false, NOW),
            Err(PowerRefusal::ResumesCap)
        );
        let mut f = priced();
        f.creates_today = 1;
        assert_eq!(
            check(PowerAct::Create { size: Size::S }, &caps(), &f, false, NOW),
            Err(PowerRefusal::CreatesCap)
        );
        let mut f = priced();
        f.running_from_chat = 2;
        assert_eq!(
            check(PowerAct::Resume, &caps(), &f, false, NOW),
            Err(PowerRefusal::RunningCap)
        );
        let mut f = priced();
        f.last_on_box_ms = NOW - 10_000;
        assert_eq!(
            check(PowerAct::Pause, &caps(), &f, false, NOW),
            Err(PowerRefusal::Cooldown)
        );
        f.last_on_box_ms = NOW - COOLDOWN_MS;
        assert!(check(PowerAct::Pause, &caps(), &f, false, NOW).is_ok());
    }

    #[test]
    fn a_pause_needs_an_idle_box_and_names_what_it_would_end() {
        let mut f = priced();
        f.would_end = Some(vec!["a run: cargo test".into()]);
        assert_eq!(
            check(PowerAct::Pause, &caps(), &f, false, NOW),
            Err(PowerRefusal::NotIdle(vec!["a run: cargo test".into()]))
        );
        f.would_end = None;
        assert_eq!(
            check(PowerAct::Pause, &caps(), &f, false, NOW),
            Err(PowerRefusal::IdleUnknown)
        );
    }

    #[test]
    fn extend_is_once_by_at_most_two_hours_on_a_box_started_from_chat() {
        let mut f = priced();
        assert_eq!(
            check(PowerAct::Extend { hours: 2 }, &caps(), &f, false, NOW),
            Err(PowerRefusal::NoDeadline)
        );
        f.has_deadline = true;
        assert!(check(PowerAct::Extend { hours: 2 }, &caps(), &f, false, NOW).is_ok());
        assert_eq!(
            check(PowerAct::Extend { hours: 3 }, &caps(), &f, false, NOW),
            Err(PowerRefusal::ExtendedAlready)
        );
        f.extended = true;
        assert_eq!(
            check(PowerAct::Extend { hours: 1 }, &caps(), &f, false, NOW),
            Err(PowerRefusal::ExtendedAlready)
        );
    }
}
