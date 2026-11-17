//! `decide`: the one function that says what a chat act may do (ADR 0050 decision 1).
//!
//! Pure: no clock, no store, no network. The caller builds a [`Context`] from facts it has just read (the link's state, the
//! person's role **now**, the delegations whose signatures it has **just verified**, the box the act is about) and gets back
//! exactly one of [`Decision::Allow`], [`Decision::Handoff`] (a link to the dashboard; nothing is done) or
//! [`Decision::Refuse`]. An `Allow` is a value only this module can make ([`Allowed`]), and an executor takes it and asks
//! [`Allowed::confirm`] again with fresh facts at the moment it acts, so a revoke between "recorded" and "run" refuses.
//!
//! The order of the rules is the order of the sentences in the ADR, and it matters: a refusal that holds for everyone is
//! made before a question about this person, so a locked or revoked link is never told anything about what it may do.

use super::acts::{ActId, ChatAct, Needs, Reject, Tier};
use super::records::{DelegatedAct, NEW_LINK_WAIT_MS};
use crate::roles::Role;

/// The chat apps the table knows. The dashboard's own chat page has a signed-in session and is not governed here.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ChatChannel {
    Telegram,
    Slack,
    Whatsapp,
}

impl ChatChannel {
    pub const ALL: [ChatChannel; 3] = [
        ChatChannel::Telegram,
        ChatChannel::Slack,
        ChatChannel::Whatsapp,
    ];

    pub const fn name(self) -> &'static str {
        match self {
            ChatChannel::Telegram => "telegram",
            ChatChannel::Slack => "slack",
            ChatChannel::Whatsapp => "whatsapp",
        }
    }

    /// The most a channel may do. Telegram: reading, conversing, box power and the catalogue. Slack and WhatsApp keep what
    /// they have today (reading and conversing under the person's role); a new channel gets nothing until it is set here.
    pub const fn ceiling(self) -> Tier {
        match self {
            ChatChannel::Telegram => Tier::Run,
            ChatChannel::Slack | ChatChannel::Whatsapp => Tier::Converse,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LinkStatus {
    Active,
    /// `/lock`: reads only, until a passkey lifts it.
    Locked,
    Revoked,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LinkFacts {
    pub status: LinkStatus,
    pub created_ms: u64,
    pub expires_ms: u64,
}

/// What the fleet record says about the box an act is about.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct BoxFacts {
    /// Marked Production by an owner with a passkey. Nothing but metadata about it goes to a chat.
    pub production: bool,
    /// The box whose dashboard owns the fleet (`main`): off for chat unless the delegation says it was warned.
    pub hub: bool,
    /// The box that hosts this bot: it cannot be paused from chat, because it could not be resumed from chat.
    pub hosts_bot: bool,
}

/// A delegation whose signature the caller has **just verified** against a passkey that still exists. An unverified row is
/// never put here: this module trusts what it is handed, and the verification is the caller's one job.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DelegationFacts {
    pub digest: String,
    pub acts: Vec<DelegatedAct>,
    pub boxes: Vec<String>,
    pub not_before_ms: u64,
    pub expires_ms: u64,
    pub issued_ms: u64,
    /// The last time it was used, 0 when never.
    pub last_used_ms: u64,
    pub hub_ack: bool,
    pub with_link: bool,
    /// An owner's assertion naming this person is on it (a member's delegation needs one).
    pub owner_cosigned: bool,
}

#[derive(Debug, Clone)]
pub struct Context<'a> {
    pub channel: ChatChannel,
    /// The person's role on this dashboard **now**; `None` when they are no longer on its list.
    pub role: Option<Role>,
    pub link: Option<LinkFacts>,
    /// The box the act is about, when it is about one and the caller could resolve it.
    pub target_box: Option<(&'a str, BoxFacts)>,
    pub delegations: &'a [DelegationFacts],
    /// A person has a pairing window open in the dashboard.
    pub pairing_open: bool,
    pub now_ms: u64,
}

/// Why an act is refused. Each has a message in the catalogue and a permanent code for the audit chain.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Refusal {
    PersonRemoved,
    NotLinked,
    LinkRevoked,
    LinkExpired,
    LinkLocked,
    RoleForbids,
    ChannelCeiling,
    ProductionBox,
    HostsBot,
    PairingClosed,
    Approve,
    Deny,
    Stop,
    Budget,
    Secrets,
    Governance,
    Outbound,
    NotInTable,
    Rejected(Reject),
}

impl Refusal {
    pub const fn code(self) -> &'static str {
        match self {
            Refusal::PersonRemoved => "person_removed",
            Refusal::NotLinked => "not_linked",
            Refusal::LinkRevoked => "link_revoked",
            Refusal::LinkExpired => "link_expired",
            Refusal::LinkLocked => "link_locked",
            Refusal::RoleForbids => "role_forbids",
            Refusal::ChannelCeiling => "channel_ceiling",
            Refusal::ProductionBox => "production_box",
            Refusal::HostsBot => "hosts_bot",
            Refusal::PairingClosed => "pairing_closed",
            Refusal::Approve => "never_approve",
            Refusal::Deny => "never_deny",
            Refusal::Stop => "never_stop",
            Refusal::Budget => "never_budget",
            Refusal::Secrets => "never_secrets",
            Refusal::Governance => "never_governance",
            Refusal::Outbound => "never_outbound",
            Refusal::NotInTable => "not_in_table",
            Refusal::Rejected(r) => r.code(),
        }
    }

    /// The message-catalogue key the person reads.
    pub const fn message(self) -> &'static str {
        match self {
            Refusal::PersonRemoved => "chat.person_removed",
            Refusal::NotLinked | Refusal::PairingClosed => "chat.silent",
            Refusal::LinkRevoked => "chat.silent",
            Refusal::LinkExpired => "tg.link_expired",
            Refusal::LinkLocked => "tg.locked",
            Refusal::RoleForbids => "tg.role_forbids",
            Refusal::ChannelCeiling => "tg.channel_ceiling",
            Refusal::ProductionBox => "tg.production",
            Refusal::HostsBot => "tg.hosts_bot",
            Refusal::Approve => "tg.refused_approve",
            Refusal::Deny => "tg.refused_deny",
            Refusal::Stop => "tg.refused_stop",
            Refusal::Budget => "tg.refused_budget",
            Refusal::Secrets => "tg.refused_secrets",
            Refusal::Governance => "tg.refused_governance",
            Refusal::Outbound => "tg.refused_outbound",
            Refusal::NotInTable => "tg.not_in_table",
            Refusal::Rejected(Reject::NonAsciiPunctuation) => "tg.rejected_punctuation",
            Refusal::Rejected(Reject::ForeignBot) => "tg.rejected_foreign_bot",
            Refusal::Rejected(Reject::ControlCharacter | Reject::TooLong) => {
                "tg.rejected_malformed"
            }
        }
    }

    /// Whether the sender hears nothing at all (an unlinked or revoked account, a closed pairing window).
    pub const fn silent(self) -> bool {
        matches!(
            self,
            Refusal::NotLinked | Refusal::LinkRevoked | Refusal::PairingClosed
        )
    }
}

/// Why an act is a link to the dashboard instead of being done.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HandoffReason {
    /// Create (as a plan), clone, snapshot, destroy: only ever with a passkey in the dashboard.
    Tier4,
    /// No delegation covers this act on this box.
    NoDelegation,
    DelegationNotYet,
    DelegationExpired,
    /// Not used for 72 hours.
    DelegationLapsed,
    /// A link younger than a day: reads only, and power and run wait.
    NewLink,
    /// A member's delegation lacks the owner's assertion.
    NeedsOwner,
    HubBox,
    /// The policy allows it and no executor exists yet in this release.
    NotBuiltYet,
}

impl HandoffReason {
    pub const fn code(self) -> &'static str {
        match self {
            HandoffReason::Tier4 => "tier4",
            HandoffReason::NoDelegation => "no_delegation",
            HandoffReason::DelegationNotYet => "delegation_not_yet",
            HandoffReason::DelegationExpired => "delegation_expired",
            HandoffReason::DelegationLapsed => "delegation_lapsed",
            HandoffReason::NewLink => "new_link",
            HandoffReason::NeedsOwner => "needs_owner",
            HandoffReason::HubBox => "hub_box",
            HandoffReason::NotBuiltYet => "not_built_yet",
        }
    }

    pub const fn message(self) -> &'static str {
        match self {
            HandoffReason::Tier4 => "tg.handoff_tier4",
            HandoffReason::NoDelegation => "tg.handoff_no_delegation",
            HandoffReason::DelegationNotYet => "tg.handoff_not_yet",
            HandoffReason::DelegationExpired => "tg.handoff_expired",
            HandoffReason::DelegationLapsed => "tg.handoff_lapsed",
            HandoffReason::NewLink => "tg.handoff_new_link",
            HandoffReason::NeedsOwner => "tg.handoff_needs_owner",
            HandoffReason::HubBox => "tg.handoff_hub",
            HandoffReason::NotBuiltYet => "tg.handoff_not_built",
        }
    }
}

/// An act the policy allows. Only [`decide`] makes one.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Allowed {
    act: ActId,
    rule: &'static str,
    delegation: Option<String>,
}

impl Allowed {
    pub fn act(&self) -> ActId {
        self.act
    }

    /// The rule that allowed it, for the audit record.
    pub fn rule(&self) -> &'static str {
        self.rule
    }

    /// The digest of the delegation that covered it, when one did.
    pub fn delegation(&self) -> Option<&str> {
        self.delegation.as_deref()
    }

    /// Ask again with the facts of **this moment**. An executor calls this immediately before it acts, so a link that was
    /// revoked or locked, a role that was cut or a delegation that lapsed between the decision and the act refuses it.
    pub fn confirm(&self, act: &ChatAct, ctx: &Context<'_>) -> Result<(), Decision> {
        match decide(act, ctx) {
            Decision::Allow(a) if a.act == self.act => Ok(()),
            other => Err(other),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Decision {
    Allow(Allowed),
    Handoff(HandoffReason),
    Refuse(Refusal),
}

impl Decision {
    /// A short word for the audit record.
    pub fn word(&self) -> &'static str {
        match self {
            Decision::Allow(_) => "allow",
            Decision::Handoff(_) => "handoff",
            Decision::Refuse(_) => "refuse",
        }
    }

    /// The rule or reason code, for the audit record.
    pub fn code(&self) -> &'static str {
        match self {
            Decision::Allow(a) => a.rule,
            Decision::Handoff(h) => h.code(),
            Decision::Refuse(r) => r.code(),
        }
    }
}

fn allow(act: ActId, rule: &'static str, delegation: Option<String>) -> Decision {
    Decision::Allow(Allowed {
        act,
        rule,
        delegation,
    })
}

fn refusal_for_refused(id: ActId) -> Refusal {
    match id {
        ActId::Approve => Refusal::Approve,
        ActId::Deny => Refusal::Deny,
        ActId::Stop => Refusal::Stop,
        ActId::Budget => Refusal::Budget,
        ActId::Secrets => Refusal::Secrets,
        ActId::Governance => Refusal::Governance,
        ActId::Outbound => Refusal::Outbound,
        _ => Refusal::NotInTable,
    }
}

fn delegated_for(n: Needs) -> Option<DelegatedAct> {
    match n {
        Needs::Nothing => None,
        Needs::Converse => Some(DelegatedAct::Converse),
        Needs::Power => Some(DelegatedAct::Power),
        Needs::Run => Some(DelegatedAct::Run),
    }
}

/// Whether one delegation covers the act at this moment; `Err` is why not.
fn usable(
    d: &DelegationFacts,
    need: DelegatedAct,
    ctx: &Context<'_>,
    link: &LinkFacts,
    role: Role,
) -> Result<(), HandoffReason> {
    if ctx.now_ms < d.not_before_ms {
        return Err(HandoffReason::DelegationNotYet);
    }
    if ctx.now_ms >= d.expires_ms {
        return Err(HandoffReason::DelegationExpired);
    }
    let last = d.last_used_ms.max(d.issued_ms);
    if ctx.now_ms.saturating_sub(last) > super::records::DELEGATION_UNUSED_LAPSE_MS {
        return Err(HandoffReason::DelegationLapsed);
    }
    // a link made with no delegation reads for its first day; converse made in the same passkey act as the link is not
    // waited on, and power and run always are
    let waived = need == DelegatedAct::Converse && d.with_link;
    if !waived && ctx.now_ms < link.created_ms.saturating_add(NEW_LINK_WAIT_MS) {
        return Err(HandoffReason::NewLink);
    }
    if role == Role::Member && !d.owner_cosigned {
        return Err(HandoffReason::NeedsOwner);
    }
    Ok(())
}

/// What may this act do, in this context.
pub fn decide(act: &ChatAct, ctx: &Context<'_>) -> Decision {
    let row = act.row();
    let id = act.id();

    // 1. the refusals that hold for everyone, however they are linked
    if let ChatAct::Rejected(r) = act {
        return Decision::Refuse(Refusal::Rejected(*r));
    }
    if row.tier == Tier::Refused {
        return Decision::Refuse(refusal_for_refused(id));
    }

    // 2. who is asking
    let Some(link) = ctx.link else {
        return if id == ActId::Link && ctx.pairing_open {
            allow(id, "pairing", None)
        } else if id == ActId::Link {
            Decision::Refuse(Refusal::PairingClosed)
        } else {
            Decision::Refuse(Refusal::NotLinked)
        };
    };
    if link.status == LinkStatus::Revoked {
        return Decision::Refuse(Refusal::LinkRevoked);
    }
    // 3. the safe direction needs nothing but a link that is not revoked: it only makes Telegram less able, so even a person
    // who has been taken off the list may cut their own link
    if row.safe {
        return allow(id, "safe", None);
    }
    let Some(role) = ctx.role else {
        return Decision::Refuse(Refusal::PersonRemoved);
    };
    if ctx.now_ms >= link.expires_ms {
        return Decision::Refuse(Refusal::LinkExpired);
    }
    // 4. the channel's ceiling
    if row.tier != Tier::Handoff && row.tier > ctx.channel.ceiling() {
        return Decision::Refuse(Refusal::ChannelCeiling);
    }
    // 5. reading
    if row.tier == Tier::Read {
        return allow(id, "read", None);
    }
    // 6. a locked link reads and nothing else
    if link.status == LinkStatus::Locked {
        return Decision::Refuse(Refusal::LinkLocked);
    }
    // 7. a handoff is a link to the dashboard, never an act
    if row.tier == Tier::Handoff {
        return Decision::Handoff(HandoffReason::Tier4);
    }
    // 8. a viewer looks
    if role == Role::Viewer {
        return Decision::Refuse(Refusal::RoleForbids);
    }
    // 9. a Production box is metadata only: no act at all
    let (box_name, facts) = match ctx.target_box {
        Some((n, f)) => (Some(n), f),
        None => (None, BoxFacts::default()),
    };
    if row.box_scoped && facts.production {
        return Decision::Refuse(Refusal::ProductionBox);
    }
    if facts.hosts_bot
        && matches!(
            id,
            ActId::BoxPause | ActId::BoxPauseWhenIdle | ActId::BoxResize
        )
    {
        return Decision::Refuse(Refusal::HostsBot);
    }
    // 10. other chat apps keep what they have today: no delegation, the gateway's own rules
    if ctx.channel != ChatChannel::Telegram {
        return allow(id, "channel-today", None);
    }
    // 11. a delegation, signed in advance, must cover it
    let Some(need) = delegated_for(row.needs) else {
        return Decision::Refuse(Refusal::NotInTable);
    };
    let mut why = HandoffReason::NoDelegation;
    let mut used: Option<&DelegationFacts> = None;
    for d in ctx.delegations {
        if !d.acts.contains(&need) {
            continue;
        }
        if row.box_scoped {
            if let Some(b) = box_name {
                if !d.boxes.iter().any(|x| x == b) {
                    continue;
                }
            }
        }
        match usable(d, need, ctx, &link, role) {
            Ok(()) => {
                used = Some(d);
                break;
            }
            Err(r) => why = r,
        }
    }
    let Some(d) = used else {
        return Decision::Handoff(why);
    };
    if facts.hub && !d.hub_ack {
        return Decision::Handoff(HandoffReason::HubBox);
    }
    // 12. never a bare "allowed" for an act that has no executor yet
    if !row.built {
        return Decision::Handoff(HandoffReason::NotBuiltYet);
    }
    allow(
        id,
        match need {
            DelegatedAct::Converse => "converse-delegated",
            DelegatedAct::Power => "power-delegated",
            DelegatedAct::Run => "run-delegated",
        },
        Some(d.digest.clone()),
    )
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use crate::chat_policy::acts::parse_act;

    const NOW: u64 = 100 * 24 * 3_600_000;
    const DAY: u64 = 24 * 3_600_000;

    /// One representative message for every act. The match is exhaustive: an act that is not placed here does not compile,
    /// which is what makes "adding an act fails until it is placed" true of the tests as well as of the table.
    fn sample(id: ActId) -> ChatAct {
        let own = Some("oz_bot");
        let text = match id {
            ActId::Status => "/status",
            ActId::Fleet => "/fleet",
            ActId::BoxList => "/box list",
            ActId::Tasks => "/tasks",
            ActId::Log => "/log",
            ActId::Sessions => "/sessions",
            ActId::Help => "/help",
            ActId::Whoami => "/whoami",
            ActId::Usage => "/new",
            ActId::Link => "/link",
            ActId::Who => "/who",
            ActId::Boxes => "/boxes",
            ActId::Fleets => "/fleets",
            ActId::To => "/to @alpha",
            ActId::Converse => "run the tests",
            ActId::Address => "@alpha run the tests",
            ActId::New => "/new alpha fix it",
            ActId::SessionPause => "/pause",
            ActId::SessionResume => "/resume",
            ActId::Switch => "/switch t1",
            ActId::Detach => "/detach",
            ActId::Attach => "/attach alpha:%3",
            ActId::Adopt => "/adopt alpha:%3",
            ActId::BoxResume => "/box resume alpha",
            ActId::BoxPause => "/box pause alpha",
            ActId::BoxPauseWhenIdle => "/box pause alpha when-idle",
            ActId::BoxPauseCancel => "/box pause alpha cancel",
            ActId::BoxExtend => "/box extend alpha 2",
            ActId::BoxCreate => "/box create gamma m",
            ActId::BoxResize => "/box resize alpha m",
            ActId::Run => "/check git status",
            ActId::RunSession => "/run alpha fix it",
            ActId::BoxClone => "/box clone",
            ActId::BoxSnapshot => "/box snapshot",
            ActId::BoxDestroy => "/box destroy",
            ActId::Lock => "/lock",
            ActId::Unlink => "/unlink",
            ActId::Approve => "/approve",
            ActId::Deny => "/deny",
            ActId::Stop => "/stop",
            ActId::Budget => "/budget +5",
            ActId::Secrets => "/secret list",
            ActId::Governance => "/policy",
            ActId::Outbound => "/send hi",
            ActId::NotInTable => "/frobnicate",
            ActId::Rejected => "/run@other_bot ls",
        };
        let act = parse_act(text, own);
        assert_eq!(
            act.id(),
            id,
            "the sample for {} reads as {:?}",
            id.key(),
            act.id()
        );
        act
    }

    fn deleg(acts: &[DelegatedAct], boxes: &[&str]) -> DelegationFacts {
        DelegationFacts {
            digest: "d1".into(),
            acts: acts.to_vec(),
            boxes: boxes.iter().map(|s| (*s).to_string()).collect(),
            not_before_ms: NOW - 3 * DAY,
            expires_ms: NOW + 3 * DAY,
            issued_ms: NOW - 3 * DAY,
            last_used_ms: NOW - DAY,
            hub_ack: false,
            with_link: false,
            owner_cosigned: true,
        }
    }

    fn link(status: LinkStatus) -> LinkFacts {
        LinkFacts {
            status,
            created_ms: NOW - 5 * DAY,
            expires_ms: NOW + 20 * DAY,
        }
    }

    struct Fixture {
        delegations: Vec<DelegationFacts>,
        channel: ChatChannel,
        role: Option<Role>,
        link: Option<LinkFacts>,
        facts: BoxFacts,
        pairing_open: bool,
    }

    impl Fixture {
        fn new() -> Self {
            Fixture {
                delegations: vec![deleg(
                    &[
                        DelegatedAct::Converse,
                        DelegatedAct::Power,
                        DelegatedAct::Run,
                    ],
                    &["alpha"],
                )],
                channel: ChatChannel::Telegram,
                role: Some(Role::Owner),
                link: Some(link(LinkStatus::Active)),
                facts: BoxFacts::default(),
                pairing_open: false,
            }
        }

        fn decide(&self, act: &ChatAct) -> Decision {
            let ctx = Context {
                channel: self.channel,
                role: self.role,
                link: self.link,
                target_box: Some(("alpha", self.facts)),
                delegations: &self.delegations,
                pairing_open: self.pairing_open,
                now_ms: NOW,
            };
            decide(act, &ctx)
        }
    }

    #[test]
    fn exhaustive_over_every_act_channel_role_link_and_delegation_state_the_invariants_hold() {
        let mut checked = 0usize;
        let roles = [
            Some(Role::Owner),
            Some(Role::Member),
            Some(Role::Viewer),
            None,
        ];
        let links = [
            None,
            Some(link(LinkStatus::Active)),
            Some(link(LinkStatus::Locked)),
            Some(link(LinkStatus::Revoked)),
            Some(LinkFacts {
                status: LinkStatus::Active,
                created_ms: NOW - 3_600_000,
                expires_ms: NOW + 20 * DAY,
            }),
            Some(LinkFacts {
                status: LinkStatus::Active,
                created_ms: NOW - 40 * DAY,
                expires_ms: NOW - 10 * DAY,
            }),
        ];
        let boxes = [
            BoxFacts::default(),
            BoxFacts {
                production: true,
                ..BoxFacts::default()
            },
            BoxFacts {
                hub: true,
                ..BoxFacts::default()
            },
            BoxFacts {
                hosts_bot: true,
                ..BoxFacts::default()
            },
        ];
        let delegation_sets: [Vec<DelegationFacts>; 3] = [
            Vec::new(),
            vec![deleg(&[DelegatedAct::Converse], &["alpha"])],
            vec![deleg(
                &[
                    DelegatedAct::Converse,
                    DelegatedAct::Power,
                    DelegatedAct::Run,
                ],
                &["alpha"],
            )],
        ];
        for id in ActId::ALL.iter().copied() {
            let act = sample(id);
            let row = id.row();
            for channel in ChatChannel::ALL {
                for role in roles {
                    for l in links {
                        for facts in boxes {
                            for ds in &delegation_sets {
                                for pairing_open in [false, true] {
                                    checked += 1;
                                    let ctx = Context {
                                        channel,
                                        role,
                                        link: l,
                                        target_box: Some(("alpha", facts)),
                                        delegations: ds,
                                        pairing_open,
                                        now_ms: NOW,
                                    };
                                    let d = decide(&act, &ctx);
                                    let allowed = matches!(d, Decision::Allow(_));
                                    // nothing refused is ever allowed, and nothing in the refused tier reaches an executor
                                    if row.tier == Tier::Refused {
                                        assert!(matches!(d, Decision::Refuse(_)), "{}", id.key());
                                    }
                                    // an act with no executor is never a bare allow
                                    if !row.built {
                                        assert!(!allowed, "{} has no executor yet", id.key());
                                    }
                                    // a handoff-tier act is never done
                                    if row.tier == Tier::Handoff {
                                        assert!(!allowed, "{}", id.key());
                                    }
                                    if !allowed {
                                        continue;
                                    }
                                    let status = l.map(|x| x.status);
                                    assert_ne!(status, Some(LinkStatus::Revoked), "{}", id.key());
                                    if id != ActId::Link {
                                        assert!(l.is_some(), "{}: allowed with no link", id.key());
                                        assert!(
                                            role.is_some() || row.safe,
                                            "{}: person removed",
                                            id.key()
                                        );
                                    }
                                    if row.tier > Tier::Read {
                                        assert_eq!(
                                            status,
                                            Some(LinkStatus::Active),
                                            "{}",
                                            id.key()
                                        );
                                        assert_ne!(role, Some(Role::Viewer), "{}", id.key());
                                        assert!(channel.ceiling() >= row.tier, "{}", id.key());
                                        if row.box_scoped {
                                            assert!(
                                                !facts.production,
                                                "{} on Production",
                                                id.key()
                                            );
                                        }
                                        if channel == ChatChannel::Telegram {
                                            assert!(
                                                !ds.is_empty(),
                                                "{} with no delegation",
                                                id.key()
                                            );
                                        }
                                    }
                                    if let (true, Some(l)) = (row.tier > Tier::Read, l) {
                                        assert!(
                                            l.expires_ms > NOW,
                                            "{} on an expired link",
                                            id.key()
                                        );
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
        assert!(checked > 20_000, "swept {checked} combinations");
    }

    #[test]
    fn a_linked_person_reads_without_a_delegation_and_converse_needs_one_per_box() {
        let mut f = Fixture::new();
        f.delegations.clear();
        assert!(matches!(
            f.decide(&sample(ActId::Status)),
            Decision::Allow(_)
        ));
        assert_eq!(
            f.decide(&sample(ActId::Converse)),
            Decision::Handoff(HandoffReason::NoDelegation)
        );
        f.delegations = vec![deleg(&[DelegatedAct::Converse], &["bravo"])];
        assert_eq!(
            f.decide(&sample(ActId::Converse)),
            Decision::Handoff(HandoffReason::NoDelegation),
            "a delegation for another box"
        );
        f.delegations = vec![deleg(&[DelegatedAct::Converse], &["alpha"])];
        let Decision::Allow(a) = f.decide(&sample(ActId::Converse)) else {
            panic!("converse on alpha")
        };
        assert_eq!(a.rule(), "converse-delegated");
        assert_eq!(a.delegation(), Some("d1"));
    }

    #[test]
    fn power_is_allowed_inside_a_delegation_and_run_and_when_idle_stay_a_handoff_until_their_executors_exist(
    ) {
        let f = Fixture::new();
        for id in [
            ActId::BoxResume,
            ActId::BoxPause,
            ActId::BoxExtend,
            ActId::BoxCreate,
            ActId::BoxResize,
        ] {
            let Decision::Allow(a) = f.decide(&sample(id)) else {
                panic!("{} should be allowed with a power delegation", id.key())
            };
            assert_eq!(a.rule(), "power-delegated");
        }
        for id in [ActId::Run, ActId::BoxPauseWhenIdle, ActId::BoxPauseCancel] {
            assert_eq!(
                f.decide(&sample(id)),
                Decision::Handoff(HandoffReason::NotBuiltYet),
                "{}",
                id.key()
            );
        }
        // without a power delegation, power is a link to the dashboard
        let mut f = Fixture::new();
        f.delegations = vec![deleg(&[DelegatedAct::Converse], &["alpha"])];
        assert_eq!(
            f.decide(&sample(ActId::BoxResume)),
            Decision::Handoff(HandoffReason::NoDelegation)
        );
        for id in [ActId::BoxClone, ActId::BoxSnapshot, ActId::BoxDestroy] {
            assert_eq!(
                f.decide(&sample(id)),
                Decision::Handoff(HandoffReason::Tier4)
            );
        }
    }

    #[test]
    fn an_expired_not_yet_lapsed_or_young_delegation_is_a_handoff_with_its_own_reason() {
        let mut f = Fixture::new();
        let act = sample(ActId::Converse);
        f.delegations[0].expires_ms = NOW;
        assert_eq!(
            f.decide(&act),
            Decision::Handoff(HandoffReason::DelegationExpired)
        );
        f.delegations[0] = deleg(&[DelegatedAct::Converse], &["alpha"]);
        f.delegations[0].not_before_ms = NOW + 1;
        assert_eq!(
            f.decide(&act),
            Decision::Handoff(HandoffReason::DelegationNotYet)
        );
        f.delegations[0] = deleg(&[DelegatedAct::Converse], &["alpha"]);
        f.delegations[0].last_used_ms = 0;
        f.delegations[0].issued_ms = NOW - 73 * 3_600_000;
        assert_eq!(
            f.decide(&act),
            Decision::Handoff(HandoffReason::DelegationLapsed)
        );
        // a link under a day old: converse made in the same passkey act is not waited on; a later one is
        f.delegations[0] = deleg(&[DelegatedAct::Converse], &["alpha"]);
        f.link = Some(LinkFacts {
            status: LinkStatus::Active,
            created_ms: NOW - 3_600_000,
            expires_ms: NOW + 20 * DAY,
        });
        assert_eq!(f.decide(&act), Decision::Handoff(HandoffReason::NewLink));
        f.delegations[0].with_link = true;
        assert!(matches!(f.decide(&act), Decision::Allow(_)));
        // power and run are always waited on, with or without that flag
        f.delegations[0].acts = vec![DelegatedAct::Power];
        assert_eq!(
            f.decide(&sample(ActId::BoxResume)),
            Decision::Handoff(HandoffReason::NewLink)
        );
    }

    #[test]
    fn a_role_change_cuts_a_delegation_and_a_members_needs_the_owners_assertion() {
        let mut f = Fixture::new();
        let act = sample(ActId::Converse);
        assert!(matches!(f.decide(&act), Decision::Allow(_)));
        f.role = Some(Role::Viewer);
        assert_eq!(f.decide(&act), Decision::Refuse(Refusal::RoleForbids));
        f.role = None;
        assert_eq!(f.decide(&act), Decision::Refuse(Refusal::PersonRemoved));
        f.role = Some(Role::Member);
        f.delegations[0].owner_cosigned = false;
        assert_eq!(f.decide(&act), Decision::Handoff(HandoffReason::NeedsOwner));
        f.delegations[0].owner_cosigned = true;
        assert!(matches!(f.decide(&act), Decision::Allow(_)));
    }

    #[test]
    fn production_is_never_acted_on_and_the_hub_needs_its_warning_to_have_been_accepted() {
        let mut f = Fixture::new();
        f.facts.production = true;
        for id in [
            ActId::Converse,
            ActId::New,
            ActId::RunSession,
            ActId::BoxResume,
            ActId::Run,
        ] {
            assert_eq!(
                f.decide(&sample(id)),
                Decision::Refuse(Refusal::ProductionBox)
            );
        }
        assert!(matches!(
            f.decide(&sample(ActId::Status)),
            Decision::Allow(_)
        ));
        f.facts = BoxFacts {
            hub: true,
            ..BoxFacts::default()
        };
        assert_eq!(
            f.decide(&sample(ActId::Converse)),
            Decision::Handoff(HandoffReason::HubBox)
        );
        f.delegations[0].hub_ack = true;
        assert!(matches!(
            f.decide(&sample(ActId::Converse)),
            Decision::Allow(_)
        ));
        f.facts = BoxFacts {
            hosts_bot: true,
            ..BoxFacts::default()
        };
        assert_eq!(
            f.decide(&sample(ActId::BoxPause)),
            Decision::Refuse(Refusal::HostsBot)
        );
    }

    #[test]
    fn lock_reads_only_and_unlink_and_lock_work_on_a_locked_or_expired_link_but_not_a_revoked_one()
    {
        let mut f = Fixture::new();
        f.link = Some(link(LinkStatus::Locked));
        assert!(matches!(
            f.decide(&sample(ActId::Status)),
            Decision::Allow(_)
        ));
        assert_eq!(
            f.decide(&sample(ActId::Converse)),
            Decision::Refuse(Refusal::LinkLocked)
        );
        assert_eq!(
            f.decide(&sample(ActId::BoxCreate)),
            Decision::Refuse(Refusal::LinkLocked)
        );
        for id in [ActId::Lock, ActId::Unlink] {
            assert!(matches!(f.decide(&sample(id)), Decision::Allow(_)));
        }
        f.link = Some(LinkFacts {
            status: LinkStatus::Active,
            created_ms: NOW - 40 * DAY,
            expires_ms: NOW - 1,
        });
        assert_eq!(
            f.decide(&sample(ActId::Status)),
            Decision::Refuse(Refusal::LinkExpired)
        );
        assert!(matches!(
            f.decide(&sample(ActId::Unlink)),
            Decision::Allow(_)
        ));
        f.link = Some(link(LinkStatus::Revoked));
        assert_eq!(
            f.decide(&sample(ActId::Unlink)),
            Decision::Refuse(Refusal::LinkRevoked)
        );
        assert!(Refusal::LinkRevoked.silent());
    }

    #[test]
    fn an_unlinked_sender_gets_silence_and_only_a_pairing_window_lets_link_through() {
        let mut f = Fixture::new();
        f.link = None;
        assert_eq!(
            f.decide(&sample(ActId::Status)),
            Decision::Refuse(Refusal::NotLinked)
        );
        assert_eq!(
            f.decide(&sample(ActId::Link)),
            Decision::Refuse(Refusal::PairingClosed)
        );
        f.pairing_open = true;
        let Decision::Allow(a) = f.decide(&sample(ActId::Link)) else {
            panic!("a window is open")
        };
        assert_eq!(a.rule(), "pairing");
        assert!(Refusal::NotLinked.silent() && Refusal::PairingClosed.silent());
    }

    #[test]
    fn other_chat_apps_keep_what_they_have_and_never_reach_power_or_run() {
        let mut f = Fixture::new();
        for channel in [ChatChannel::Slack, ChatChannel::Whatsapp] {
            f.channel = channel;
            f.delegations.clear();
            assert!(matches!(
                f.decide(&sample(ActId::Converse)),
                Decision::Allow(_)
            ));
            for id in [ActId::BoxResume, ActId::Run, ActId::BoxCreate] {
                assert_eq!(
                    f.decide(&sample(id)),
                    Decision::Refuse(Refusal::ChannelCeiling),
                    "{}",
                    id.key()
                );
            }
        }
    }

    #[test]
    fn an_allow_is_asked_again_at_the_moment_of_the_act_and_a_revoke_in_between_refuses() {
        let mut f = Fixture::new();
        let act = sample(ActId::Converse);
        let Decision::Allow(a) = f.decide(&act) else {
            panic!()
        };
        fn ctx(f: &Fixture) -> Context<'_> {
            Context {
                channel: f.channel,
                role: f.role,
                link: f.link,
                target_box: Some(("alpha", f.facts)),
                delegations: &f.delegations,
                pairing_open: false,
                now_ms: NOW,
            }
        }
        assert_eq!(a.confirm(&act, &ctx(&f)), Ok(()));
        f.link = Some(link(LinkStatus::Revoked));
        assert_eq!(
            a.confirm(&act, &ctx(&f)),
            Err(Decision::Refuse(Refusal::LinkRevoked))
        );
        f.link = Some(link(LinkStatus::Locked));
        assert_eq!(
            a.confirm(&act, &ctx(&f)),
            Err(Decision::Refuse(Refusal::LinkLocked))
        );
        f.link = Some(link(LinkStatus::Active));
        f.delegations.clear();
        assert!(
            a.confirm(&act, &ctx(&f)).is_err(),
            "the delegation was removed"
        );
    }

    #[test]
    fn every_refusal_and_handoff_has_a_message_and_a_unique_code() {
        let refusals = [
            Refusal::PersonRemoved,
            Refusal::NotLinked,
            Refusal::LinkRevoked,
            Refusal::LinkExpired,
            Refusal::LinkLocked,
            Refusal::RoleForbids,
            Refusal::ChannelCeiling,
            Refusal::ProductionBox,
            Refusal::HostsBot,
            Refusal::PairingClosed,
            Refusal::Approve,
            Refusal::Deny,
            Refusal::Stop,
            Refusal::Budget,
            Refusal::Secrets,
            Refusal::Governance,
            Refusal::Outbound,
            Refusal::NotInTable,
            Refusal::Rejected(Reject::NonAsciiPunctuation),
            Refusal::Rejected(Reject::ForeignBot),
            Refusal::Rejected(Reject::ControlCharacter),
            Refusal::Rejected(Reject::TooLong),
        ];
        let mut codes = std::collections::BTreeSet::new();
        for r in refusals {
            assert!(!r.message().is_empty());
            codes.insert(r.code());
        }
        assert_eq!(codes.len(), refusals.len());
    }
}
