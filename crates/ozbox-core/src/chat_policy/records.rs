//! The records a passkey signs for Telegram (ADR 0050 decisions 2 and §6): a pairing window, a link and a delegation.
//!
//! Each record has one canonical encoding (the shared length-prefixed [`Encoder`], its own domain tag and version byte) and
//! **its digest is the WebAuthn challenge**, as for a decision in ADR 0041. So an assertion is bound to exactly what was
//! delegated: a settings row whose fields were edited afterwards digests to something the stored assertion does not cover,
//! and a row with no assertion has nothing to check at all. Both are refused by every executor.
//!
//! A record holds names, numbers and times only: never a token, a code or a message.

use serde::{Deserialize, Serialize};

use crate::approval_subject::{to_hex, Encoder};

pub const WINDOW_TAG: &str = "ozbox-chat-pairing-window-v1";
pub const LINK_TAG: &str = "ozbox-chat-link-v1";
pub const DELEGATION_TAG: &str = "ozbox-chat-delegation-v1";
pub const CONFIRM_TAG: &str = "ozbox-chat-link-confirm-v1";
pub const RENEW_TAG: &str = "ozbox-chat-link-renew-v1";
pub const UNLOCK_TAG: &str = "ozbox-chat-link-unlock-v1";
pub const COSIGN_TAG: &str = "ozbox-chat-delegation-owner-v1";

const MIN: u64 = 60_000;
const HOUR: u64 = 60 * MIN;
const DAY: u64 = 24 * HOUR;

/// A pairing window lives ten minutes.
pub const WINDOW_MS: u64 = 10 * MIN;
/// A link lasts thirty days and is renewed with a passkey.
pub const LINK_TTL_MS: u64 = 30 * DAY;
/// A link made with no delegation reads only for its first day, and a power or run delegation waits the same day.
pub const NEW_LINK_WAIT_MS: u64 = DAY;
/// A delegation lasts seven days unless asked otherwise, thirty at most.
pub const DELEGATION_DEFAULT_MS: u64 = 7 * DAY;
pub const DELEGATION_MAX_MS: u64 = 30 * DAY;
/// A delegation that has not been used for this long lapses.
pub const DELEGATION_UNUSED_LAPSE_MS: u64 = 72 * HOUR;
/// The most boxes one delegation may name.
pub const MAX_DELEGATED_BOXES: usize = 32;

/// What a person delegated.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DelegatedAct {
    Converse,
    Power,
    Run,
}

impl DelegatedAct {
    pub const fn name(self) -> &'static str {
        match self {
            DelegatedAct::Converse => "converse",
            DelegatedAct::Power => "power",
            DelegatedAct::Run => "run",
        }
    }
}

/// The caps a delegation carries (ADR 0050 §3). The session cap governs converse; the rest govern box power and are part of
/// the signed digest only when the delegation grants power, so a converse-only record digests as it always did.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct Caps {
    /// Sessions the person may have open from chat at once.
    pub sessions: u32,
    /// Power: the largest standard size a chat may create a box at or resize one to (`XS` to `XXL`). `None`: a chat may
    /// resume, pause and extend, but never create or resize. A GPU size is never reached from chat.
    pub max_size: Option<String>,
    /// Power: what box time started or extended from chat may cost in one day (UTC), in whole US dollars.
    pub daily_usd: u32,
    /// Power: boxes a chat may create in one day.
    pub creates_per_day: u32,
    /// Power: resumes a chat may make in one day.
    pub resumes_per_day: u32,
    /// Power: boxes started from chat that may be running at once.
    pub running: u32,
}

impl Default for Caps {
    fn default() -> Self {
        Caps {
            sessions: 3,
            max_size: None,
            daily_usd: 10,
            creates_per_day: 1,
            resumes_per_day: 6,
            running: 2,
        }
    }
}

/// The domain word that starts the power caps inside a delegation's digest.
const POWER_CAPS_TAG: &str = "power-caps-v1";

/// Why a record is refused. For a person; never a value.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RecordError(pub &'static str);

impl std::fmt::Display for RecordError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.0)
    }
}

fn name_ok(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= 64
        && s.bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.' | b'@'))
}

/// The window a person opens in the dashboard, with a fresh passkey, to pair a Telegram account.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WindowRecord {
    pub person: String,
    pub bot_id: i64,
    pub nonce: String,
    pub opened_ms: u64,
    pub expires_ms: u64,
}

impl WindowRecord {
    pub fn digest(&self) -> Result<[u8; 32], RecordError> {
        if !name_ok(&self.person) || !name_ok(&self.nonce) || self.expires_ms <= self.opened_ms {
            return Err(RecordError("that pairing window is not valid"));
        }
        let mut e = Encoder::new(WINDOW_TAG);
        e.text(&self.person)
            .u64(self.bot_id as u64)
            .text(&self.nonce)
            .u64(self.opened_ms)
            .u64(self.expires_ms);
        Ok(e.digest())
    }
}

/// A Telegram account bound to a person (ADR 0050 §6). The number is Telegram's user id, never a username.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LinkRecord {
    pub id: String,
    pub person: String,
    pub telegram_id: i64,
    pub chat_id: i64,
    pub bot_id: i64,
    /// A label the person chose ("my phone").
    pub label: String,
    pub created_ms: u64,
    pub expires_ms: u64,
}

impl LinkRecord {
    pub fn digest(&self) -> Result<[u8; 32], RecordError> {
        if !name_ok(&self.id) || !name_ok(&self.person) {
            return Err(RecordError("that link is not valid"));
        }
        if self.label.is_empty()
            || self.label.chars().count() > 40
            || self.label.chars().any(char::is_control)
        {
            return Err(RecordError("a label is 1 to 40 characters"));
        }
        if self.telegram_id <= 0 || self.chat_id != self.telegram_id {
            return Err(RecordError(
                "a link is for a private chat: the account and the chat are the same number",
            ));
        }
        if self.expires_ms <= self.created_ms || self.expires_ms - self.created_ms > LINK_TTL_MS {
            return Err(RecordError("a link lasts at most thirty days"));
        }
        let mut e = Encoder::new(LINK_TAG);
        e.text(&self.id)
            .text(&self.person)
            .u64(self.telegram_id as u64)
            .u64(self.chat_id as u64)
            .u64(self.bot_id as u64)
            .text(&self.label)
            .u64(self.created_ms)
            .u64(self.expires_ms);
        Ok(e.digest())
    }
}

/// What a person delegated to one link: the acts, the boxes and the caps, for a bounded time.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DelegationRecord {
    pub id: String,
    pub link_id: String,
    pub person: String,
    pub telegram_id: i64,
    pub bot_id: i64,
    /// Sorted, without duplicates.
    pub boxes: Vec<String>,
    /// Sorted, without duplicates.
    pub acts: Vec<DelegatedAct>,
    pub caps: Caps,
    pub not_before_ms: u64,
    pub expires_ms: u64,
    /// The person was shown the warning that `main` is the hub and turned the delegation on for it anyway.
    pub hub_ack: bool,
    /// Made in the same passkey act as the link, so the new-link wait does not apply (converse only).
    pub with_link: bool,
}

impl DelegationRecord {
    pub fn digest(&self) -> Result<[u8; 32], RecordError> {
        self.validate()?;
        let mut e = Encoder::new(DELEGATION_TAG);
        e.text(&self.id)
            .text(&self.link_id)
            .text(&self.person)
            .u64(self.telegram_id as u64)
            .u64(self.bot_id as u64)
            .count(self.boxes.len());
        for b in &self.boxes {
            e.text(b);
        }
        e.count(self.acts.len());
        for a in &self.acts {
            e.text(a.name());
        }
        e.u64(u64::from(self.caps.sessions))
            .u64(self.not_before_ms)
            .u64(self.expires_ms)
            .flag(self.hub_ack)
            .flag(self.with_link);
        if self.grants(DelegatedAct::Power) {
            e.text(POWER_CAPS_TAG)
                .text(self.caps.max_size.as_deref().unwrap_or(""))
                .u64(u64::from(self.caps.daily_usd))
                .u64(u64::from(self.caps.creates_per_day))
                .u64(u64::from(self.caps.resumes_per_day))
                .u64(u64::from(self.caps.running));
        }
        Ok(e.digest())
    }

    pub fn validate(&self) -> Result<(), RecordError> {
        if !name_ok(&self.id) || !name_ok(&self.link_id) || !name_ok(&self.person) {
            return Err(RecordError("that delegation is not valid"));
        }
        if self.boxes.is_empty() || self.boxes.len() > MAX_DELEGATED_BOXES {
            return Err(RecordError("a delegation names between 1 and 32 boxes"));
        }
        if !self.boxes.windows(2).all(|w| w[0] < w[1])
            || !self.boxes.iter().all(|b| super::acts::box_name_ok(b))
        {
            return Err(RecordError("the boxes must be real names, each once"));
        }
        if self.acts.is_empty() || !self.acts.windows(2).all(|w| w[0] < w[1]) {
            return Err(RecordError(
                "a delegation names at least one act, each once",
            ));
        }
        if self.with_link && self.acts.iter().any(|a| *a != DelegatedAct::Converse) {
            return Err(RecordError(
                "only converse can be delegated in the same step as a new link",
            ));
        }
        if self.expires_ms <= self.not_before_ms
            || self.expires_ms - self.not_before_ms > DELEGATION_MAX_MS
        {
            return Err(RecordError("a delegation lasts at most thirty days"));
        }
        if !(1..=20).contains(&self.caps.sessions) {
            return Err(RecordError("sessions: between 1 and 20"));
        }
        if self.grants(DelegatedAct::Power) {
            let c = &self.caps;
            if let Some(m) = &c.max_size {
                match m.parse::<crate::Size>() {
                    Ok(sz) if crate::Size::STANDARD.contains(&sz) => {}
                    _ => return Err(RecordError("the size cap is a standard size, XS to XXL")),
                }
            }
            if !(1..=500).contains(&c.daily_usd) {
                return Err(RecordError("the daily money cap: between 1 and 500 dollars"));
            }
            if c.creates_per_day > 10 {
                return Err(RecordError("creates a day: at most 10"));
            }
            if !(1..=50).contains(&c.resumes_per_day) {
                return Err(RecordError("resumes a day: between 1 and 50"));
            }
            if !(1..=20).contains(&c.running) {
                return Err(RecordError("boxes running from chat: between 1 and 20"));
            }
        }
        Ok(())
    }

    pub fn grants(&self, a: DelegatedAct) -> bool {
        self.acts.contains(&a)
    }
}

/// The challenge of the one passkey act that confirms a link and, when the person wants it, enables converse in the same
/// step (ADR 0050 §6 item 4): the digest of both records, so neither can be swapped after the touch.
pub fn confirm_digest(
    link: &LinkRecord,
    delegation: Option<&DelegationRecord>,
) -> Result<[u8; 32], RecordError> {
    let l = link.digest()?;
    let d = match delegation {
        Some(d) => {
            if d.link_id != link.id
                || d.telegram_id != link.telegram_id
                || d.person != link.person
                || d.bot_id != link.bot_id
            {
                return Err(RecordError("that delegation is not for this link"));
            }
            Some(d.digest()?)
        }
        None => None,
    };
    Ok(confirm_from_digests(&l, d.as_ref()))
}

/// [`confirm_digest`] from the two digests, for checking a stored assertion again without the records' own fields.
pub fn confirm_from_digests(link: &[u8; 32], delegation: Option<&[u8; 32]>) -> [u8; 32] {
    let empty: [u8; 0] = [];
    let d: &[u8] = delegation.map_or(&empty[..], |d| &d[..]);
    crate::approval_subject::digest_fields(CONFIRM_TAG, &[link, d])
}

/// What an owner signs to stand behind a member's delegation: the delegation's digest and the member it names.
pub fn cosign_digest(delegation_digest: &[u8; 32], member: &str) -> Result<[u8; 32], RecordError> {
    if !name_ok(member) {
        return Err(RecordError("that person is not valid"));
    }
    Ok(crate::approval_subject::digest_fields(
        COSIGN_TAG,
        &[delegation_digest, member.as_bytes()],
    ))
}

/// The challenge of renewing a link or lifting its lock: the link's digest and the new expiry (renew) or nothing (unlock).
pub fn renew_digest(link: &LinkRecord, new_expires_ms: u64) -> Result<[u8; 32], RecordError> {
    let l = link.digest()?;
    Ok(crate::approval_subject::digest_fields(
        RENEW_TAG,
        &[&l, &new_expires_ms.to_be_bytes()],
    ))
}

pub fn unlock_digest(link: &LinkRecord, at_ms: u64) -> Result<[u8; 32], RecordError> {
    let l = link.digest()?;
    Ok(crate::approval_subject::digest_fields(
        UNLOCK_TAG,
        &[&l, &at_ms.to_be_bytes()],
    ))
}

pub fn hex(d: &[u8; 32]) -> String {
    to_hex(d)
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    fn link() -> LinkRecord {
        LinkRecord {
            id: "l1".into(),
            person: "ada".into(),
            telegram_id: 4_000_000_001,
            chat_id: 4_000_000_001,
            bot_id: 7_000_000_002,
            label: "my phone".into(),
            created_ms: 1_000,
            expires_ms: 1_000 + LINK_TTL_MS,
        }
    }

    fn deleg() -> DelegationRecord {
        DelegationRecord {
            id: "d1".into(),
            link_id: "l1".into(),
            person: "ada".into(),
            telegram_id: 4_000_000_001,
            bot_id: 7_000_000_002,
            boxes: vec!["alpha".into(), "bravo".into()],
            acts: vec![DelegatedAct::Converse],
            caps: Caps::default(),
            not_before_ms: 1_000,
            expires_ms: 1_000 + DELEGATION_DEFAULT_MS,
            hub_ack: false,
            with_link: true,
        }
    }

    #[test]
    fn the_ids_need_more_than_thirty_two_bits_and_the_digest_covers_every_field() {
        // a Telegram user id does not fit in 32 bits: it is kept as a 64-bit integer end to end
        assert!(link().telegram_id > i64::from(i32::MAX));
        let base = link().digest().unwrap();
        let mut variants = Vec::new();
        let mut l = link();
        l.person = "bob".into();
        variants.push(l);
        let mut l = link();
        l.telegram_id += 1;
        l.chat_id += 1;
        variants.push(l);
        let mut l = link();
        l.bot_id += 1;
        variants.push(l);
        let mut l = link();
        l.label = "other".into();
        variants.push(l);
        let mut l = link();
        l.expires_ms -= 1;
        variants.push(l);
        for v in variants {
            assert_ne!(v.digest().unwrap(), base);
        }
    }

    #[test]
    fn a_link_is_for_a_private_chat_and_lasts_at_most_thirty_days() {
        let mut l = link();
        l.chat_id = -100;
        assert!(l.digest().is_err());
        let mut l = link();
        l.expires_ms += 1;
        assert!(l.digest().is_err());
        let mut l = link();
        l.label = String::new();
        assert!(l.digest().is_err());
    }

    #[test]
    fn a_delegation_digest_changes_with_any_field_so_an_edited_row_no_longer_matches() {
        let base = deleg().digest().unwrap();
        let mut d = deleg();
        d.boxes.push("charlie".into());
        assert_ne!(d.digest().unwrap(), base, "a box added to the row");
        let mut d = deleg();
        d.acts = vec![DelegatedAct::Converse, DelegatedAct::Power];
        d.with_link = false;
        assert_ne!(d.digest().unwrap(), base, "an act added to the row");
        let mut d = deleg();
        d.expires_ms += 1;
        assert_ne!(d.digest().unwrap(), base, "a longer life");
        let mut d = deleg();
        d.hub_ack = true;
        assert_ne!(d.digest().unwrap(), base);
        let mut d = deleg();
        d.caps.sessions = 9;
        assert_ne!(d.digest().unwrap(), base);
    }

    #[test]
    fn power_caps_are_signed_with_a_power_delegation_and_leave_a_converse_digest_as_it_was() {
        // a converse-only record ignores the power caps, so records signed before box power still verify
        let base = deleg().digest().unwrap();
        let mut d = deleg();
        d.caps.daily_usd = 99;
        d.caps.max_size = Some("L".into());
        assert_eq!(d.digest().unwrap(), base, "power caps are not part of a converse digest");
        let mut p = deleg();
        p.acts = vec![DelegatedAct::Power];
        p.with_link = false;
        let pd = p.digest().unwrap();
        for edit in [
            |c: &mut Caps| c.daily_usd = 11,
            |c: &mut Caps| c.max_size = Some("M".into()),
            |c: &mut Caps| c.creates_per_day = 2,
            |c: &mut Caps| c.resumes_per_day = 7,
            |c: &mut Caps| c.running = 3,
        ] {
            let mut q = p.clone();
            edit(&mut q.caps);
            assert_ne!(q.digest().unwrap(), pd, "every power cap is covered by the passkey");
        }
        for bad in [
            |c: &mut Caps| c.daily_usd = 0,
            |c: &mut Caps| c.max_size = Some("GPU-S".into()),
            |c: &mut Caps| c.max_size = Some("HUGE".into()),
            |c: &mut Caps| c.creates_per_day = 11,
            |c: &mut Caps| c.running = 0,
        ] {
            let mut q = p.clone();
            bad(&mut q.caps);
            assert!(q.validate().is_err());
        }
    }

    #[test]
    fn a_delegation_is_bounded_sorted_and_made_with_a_link_only_for_converse() {
        let mut d = deleg();
        d.expires_ms = d.not_before_ms + DELEGATION_MAX_MS + 1;
        assert!(d.validate().is_err());
        let mut d = deleg();
        d.boxes = vec!["bravo".into(), "alpha".into()];
        assert!(d.validate().is_err(), "unsorted");
        let mut d = deleg();
        d.boxes = vec!["alpha".into(), "alpha".into()];
        assert!(d.validate().is_err(), "duplicate");
        let mut d = deleg();
        d.boxes = Vec::new();
        assert!(d.validate().is_err());
        let mut d = deleg();
        d.acts = vec![DelegatedAct::Power];
        assert!(
            d.validate().is_err(),
            "power cannot ride on the link's passkey"
        );
        d.with_link = false;
        assert!(d.validate().is_ok());
    }

    #[test]
    fn the_confirm_challenge_covers_the_link_and_the_delegation_together() {
        let l = link();
        let d = deleg();
        let both = confirm_digest(&l, Some(&d)).unwrap();
        let only_link = confirm_digest(&l, None).unwrap();
        assert_ne!(both, only_link);
        let mut d2 = deleg();
        d2.boxes.push("charlie".into());
        assert_ne!(confirm_digest(&l, Some(&d2)).unwrap(), both);
        let mut other = deleg();
        other.telegram_id += 1;
        assert!(
            confirm_digest(&l, Some(&other)).is_err(),
            "another account's delegation"
        );
        // distinct domains: the same bytes never verify as another act
        assert_ne!(
            renew_digest(&l, l.expires_ms).unwrap(),
            unlock_digest(&l, l.expires_ms).unwrap()
        );
    }

    #[test]
    fn a_window_is_ten_minutes_and_its_digest_binds_the_person_and_the_bot() {
        let w = WindowRecord {
            person: "ada".into(),
            bot_id: 7_000_000_002,
            nonce: "n0nce".into(),
            opened_ms: 5,
            expires_ms: 5 + WINDOW_MS,
        };
        let d = w.digest().unwrap();
        let mut w2 = w.clone();
        w2.person = "bob".into();
        assert_ne!(w2.digest().unwrap(), d);
        let mut w3 = w.clone();
        w3.bot_id += 1;
        assert_ne!(w3.digest().unwrap(), d);
        let mut w4 = w;
        w4.expires_ms = w4.opened_ms;
        assert!(w4.digest().is_err());
    }
}
