//! What the Telegram bridge remembers: links, delegations, the replay set, the poll offset and whether it has stopped.
//!
//! This is **not** `ServerState`. That file is written without a sync, a failed write is ignored, and a file that cannot be
//! read loads as empty. Here, the replay set and the links are what stop an old command running twice and a revoked link
//! acting, so:
//!
//! * a write is a temporary file, `fsync`, a rename and an `fsync` of the folder, and **a failed write is an error** that the
//!   caller must treat as "do not act" (an update is recorded here **before** anything is done for it);
//! * a file that exists and cannot be read is an error, not an empty store: an empty store would forget every revoke and every
//!   seen update (the same rule as the sign-in file, `AuthState::try_load`);
//! * the file holds names, numbers, times and **evidence of passkey assertions** only: never a token, a code or a message.
//!
//! The assertions are what make a record real. A link or a delegation row with no assertion that matches its fields is
//! refused by every executor ([`TgStore::link_is_genuine`], [`TgStore::delegation_is_genuine`]), so a hand-edited file grants
//! nothing.

use std::path::PathBuf;

use ozbox_core::approval_subject::{from_hex, to_hex};
use ozbox_core::chat_policy::admit::SeenSet;
use ozbox_core::chat_policy::records::{
    confirm_from_digests, cosign_digest, DelegationRecord, LinkRecord,
};
use serde::{Deserialize, Serialize};

use crate::serve::auth::approval::SignedEvidence;

pub const STORE_VERSION: u32 = 1;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LinkState {
    Active,
    /// `/lock`, or the dashboard's lock: reads only until a passkey lifts it.
    Locked,
    Revoked,
}

/// A Telegram account bound to a person.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TgLink {
    pub record: LinkRecord,
    /// The record's digest, hex.
    pub digest: String,
    /// The passkey assertion that confirmed the link (and, when `confirm_with` is set, the delegation made in the same step).
    pub signed: SignedEvidence,
    /// The delegation digest the confirming assertion also covered, hex.
    pub confirm_with: Option<String>,
    pub state: LinkState,
    pub last_seen_ms: u64,
    /// When it was locked or revoked.
    pub changed_ms: Option<u64>,
    /// A renewal: the new end of the link and the passkey assertion that bought it.
    pub renewed: Option<Renewal>,
    /// An unlock that lifted a lock, and when.
    pub unlocked_ms: Option<u64>,
    /// Why it ended: `unlinked`, `revoked_by_person`, `revoked_by_owner`, `person_removed`, `lock_all`.
    pub ended: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Renewal {
    pub expires_ms: u64,
    pub signed: SignedEvidence,
}

impl TgLink {
    /// The end of the link: its own, or the renewal's (unchecked: the server uses the verified form).
    #[cfg(test)]
    pub fn expires_ms(&self) -> u64 {
        self.renewed.as_ref().map_or(self.record.expires_ms, |r| {
            r.expires_ms.max(self.record.expires_ms)
        })
    }
}

/// What a person delegated to one link.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TgDelegation {
    pub record: DelegationRecord,
    pub digest: String,
    /// The person's own assertion over the record. `None` when the delegation was made in the same passkey step as the link
    /// (the link's confirming assertion covers it).
    pub signed: Option<SignedEvidence>,
    /// A member's delegation needs an owner's assertion naming the member.
    pub owner: Option<SignedEvidence>,
    pub issued_ms: u64,
    pub last_used_ms: u64,
    pub revoked: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BotRef {
    pub id: i64,
    pub username: String,
}

/// Why the bridge stopped acting. It stays stopped across a restart until an owner says to go on.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Halt {
    /// A permanent code: `conflict`, `webhook_set`, `bot_settings`, `bad_token`, `store`, `transcript`.
    pub code: String,
    pub since_ms: u64,
    /// Words for the owner; never a token, an address or a body.
    pub detail: String,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct Counters {
    /// Messages from accounts that are not linked, counted and never answered.
    pub unlinked: u64,
    pub unlinked_last_ms: u64,
    /// Updates dropped as not fresh.
    pub too_old: u64,
    /// Replays refused.
    pub replays: u64,
}

/// What an owner marked about the fleet, for the policy (ADR 0050 §1c): boxes that are Production, and the hub.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct Marks {
    /// A Production box: a chat shows its state and nothing else, and no act is done on it.
    pub production: Vec<String>,
    /// The box whose dashboard owns the fleet (it runs the bridge): off for chat unless a delegation says its owner was warned.
    pub hub: Option<String>,
    /// Named groups of boxes a chat may address as `@<group>` (a group never shares a box's name).
    pub groups: std::collections::BTreeMap<String, Vec<String>>,
    /// How much of what an agent writes reaches a chat, per box: `full` (the default), `summary` or `metadata`. A Production
    /// box is always `metadata`, whatever is written here.
    pub detail: std::collections::BTreeMap<String, String>,
}

/// What box power from chat has used (ADR 0050 §3), so the caps hold across a restart.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct PowerLedger {
    /// The UTC day the counters are for; a new day starts them again.
    pub day: u64,
    /// person -> what they used today.
    pub used: std::collections::BTreeMap<String, PowerUsed>,
    /// box -> what chat did to it.
    pub boxes: std::collections::BTreeMap<String, BoxPower>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct PowerUsed {
    pub resumes: u32,
    pub creates: u32,
    pub spent_cents: u64,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct BoxPower {
    /// The last power act on the box from chat.
    pub last_ms: u64,
    /// A box started from chat is paused again at this moment, unless extended once.
    pub deadline_ms: Option<u64>,
    pub extended: bool,
    /// Who started it from chat (the deadline's notice goes to that link).
    pub by_person: Option<String>,
    pub chat_id: Option<i64>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct TgData {
    pub version: u32,
    pub bot: Option<BotRef>,
    pub links: Vec<TgLink>,
    pub delegations: Vec<TgDelegation>,
    pub seen: SeenSet,
    /// The next update to ask for. Moves only after the updates before it are recorded in `seen`.
    pub offset: i64,
    /// When an update was last received. After a week of silence Telegram chooses the next `update_id` at random, so a stored
    /// offset above it would hide every new update: a long silence polls from the start, and the replay set does the rest.
    pub last_update_ms: u64,
    pub halted: Option<Halt>,
    pub counters: Counters,
    pub marks: Marks,
    pub power: PowerLedger,
    /// Times (ms) of the refusals written to the audit chain in the last hour, by link, so a loop cannot fill the chain.
    pub refusal_audit: std::collections::BTreeMap<String, Vec<u64>>,
}

pub struct TgStore {
    path: Option<PathBuf>,
    pub data: TgData,
}

/// At most this many refusals of one link are written to the chain in an hour; the rest are counted.
pub const REFUSAL_AUDIT_PER_HOUR: usize = 20;

impl TgStore {
    /// An empty store that is never written (a test, or a server with no state folder).
    pub fn in_memory() -> Self {
        TgStore {
            path: None,
            data: TgData {
                version: STORE_VERSION,
                ..TgData::default()
            },
        }
    }

    /// Open the store at `path`. A missing file is an empty store; one that exists and cannot be read is an error.
    pub fn open(path: PathBuf) -> Result<Self, String> {
        let data = match std::fs::read_to_string(&path) {
            Ok(t) => serde_json::from_str::<TgData>(&t).map_err(|_| {
                format!(
                    "{} cannot be read. It holds the Telegram links and the list of messages already handled, so the bridge will not start on an empty one: restore it from a backup, or move it aside to link Telegram again",
                    path.display()
                )
            })?,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => TgData::default(),
            Err(e) => return Err(format!("{} cannot be read ({e})", path.display())),
        };
        let mut data = data;
        data.version = STORE_VERSION;
        Ok(TgStore {
            path: Some(path),
            data,
        })
    }

    #[cfg(test)]
    pub fn is_persistent(&self) -> bool {
        self.path.is_some()
    }

    /// Write the store, and only report success when it is on the disk.
    pub fn save(&self) -> Result<(), String> {
        let Some(path) = &self.path else {
            return Ok(());
        };
        use std::io::Write;
        let bad = |what: &str| format!("the Telegram state could not be written ({what})");
        if let Some(dir) = path.parent() {
            std::fs::create_dir_all(dir).map_err(|_| bad("folder"))?;
        }
        let tmp = path.with_extension("tmp");
        let mut opts = std::fs::OpenOptions::new();
        opts.write(true).create(true).truncate(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            opts.mode(0o600);
        }
        let mut f = opts.open(&tmp).map_err(|_| bad("file"))?;
        let body = serde_json::to_vec_pretty(&self.data).map_err(|_| bad("encoding"))?;
        f.write_all(&body).map_err(|_| bad("write"))?;
        f.sync_all().map_err(|_| bad("sync"))?;
        drop(f);
        std::fs::rename(&tmp, path).map_err(|_| bad("rename"))?;
        #[cfg(unix)]
        if let Some(dir) = path.parent() {
            if let Ok(d) = std::fs::File::open(dir) {
                let _ = d.sync_all();
            }
        }
        Ok(())
    }

    pub fn link(&self, id: &str) -> Option<&TgLink> {
        self.data.links.iter().find(|l| l.record.id == id)
    }

    pub fn link_mut(&mut self, id: &str) -> Option<&mut TgLink> {
        self.data.links.iter_mut().find(|l| l.record.id == id)
    }

    /// The link of a Telegram account on this bot that has not been revoked.
    pub fn live_link_of(&self, bot_id: i64, telegram_id: i64) -> Option<&TgLink> {
        self.data.links.iter().find(|l| {
            l.record.bot_id == bot_id
                && l.record.telegram_id == telegram_id
                && l.state != LinkState::Revoked
        })
    }

    pub fn delegations_of<'a>(
        &'a self,
        link_id: &'a str,
    ) -> impl Iterator<Item = &'a TgDelegation> + 'a {
        self.data
            .delegations
            .iter()
            .filter(move |d| d.record.link_id == link_id && !d.revoked)
    }

    /// Whether a link row is the one a passkey confirmed: its fields digest to what is stored, the digest is the
    /// confirming assertion's challenge, and `verify` says that assertion is real. `verify` is the caller's check of the
    /// assertion against the person's passkeys as they are now (`Auth::verify_evidence`).
    pub fn link_is_genuine(
        &self,
        l: &TgLink,
        verify: &dyn Fn(&SignedEvidence, &[u8; 32]) -> bool,
    ) -> bool {
        let Ok(d) = l.record.digest() else {
            return false;
        };
        if to_hex(&d) != l.digest || l.signed.person != l.record.person {
            return false;
        }
        let with = match &l.confirm_with {
            None => None,
            Some(h) => match from_hex(h).and_then(|b| <[u8; 32]>::try_from(b).ok()) {
                Some(b) => Some(b),
                None => return false,
            },
        };
        verify(&l.signed, &confirm_from_digests(&d, with.as_ref()))
    }

    /// Whether a delegation row is real: its fields digest to what is stored, it names this link's account, the person's own
    /// assertion (or the link's confirming one) covers the digest, and, when `owner_needed`, an owner's assertion naming the
    /// person covers it too. `owner_now` says whether a person is an owner on this dashboard now.
    pub fn delegation_is_genuine(
        &self,
        d: &TgDelegation,
        owner_needed: bool,
        verify: &dyn Fn(&SignedEvidence, &[u8; 32]) -> bool,
        owner_now: &dyn Fn(&str) -> bool,
    ) -> bool {
        let Ok(dig) = d.record.digest() else {
            return false;
        };
        if to_hex(&dig) != d.digest {
            return false;
        }
        let Some(link) = self.link(&d.record.link_id) else {
            return false;
        };
        if link.record.telegram_id != d.record.telegram_id
            || link.record.bot_id != d.record.bot_id
            || link.record.person != d.record.person
        {
            return false;
        }
        let covered = match &d.signed {
            Some(ev) => ev.person == d.record.person && verify(ev, &dig),
            // made in the same passkey step as the link: only converse, and only when the link's assertion covers it
            None => d.record.with_link && link.confirm_with.as_deref() == Some(d.digest.as_str()),
        };
        if !covered {
            return false;
        }
        if !owner_needed {
            return true;
        }
        let Some(own) = &d.owner else {
            return false;
        };
        let Ok(cs) = cosign_digest(&dig, &d.record.person) else {
            return false;
        };
        owner_now(&own.person) && verify(own, &cs)
    }

    /// Whether one more audited refusal of this link is allowed in the last hour, noting it when it is.
    pub fn refusal_audit_allowed(&mut self, link_id: &str, now_ms: u64) -> bool {
        let list = self
            .data
            .refusal_audit
            .entry(link_id.to_string())
            .or_default();
        list.retain(|t| now_ms.saturating_sub(*t) < 3_600_000);
        if list.len() >= REFUSAL_AUDIT_PER_HOUR {
            return false;
        }
        list.push(now_ms);
        true
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use ozbox_core::chat_policy::records::{Caps, DelegatedAct, LINK_TTL_MS};

    fn ev(person: &str) -> SignedEvidence {
        SignedEvidence {
            person: person.into(),
            credential_id: "c1".into(),
            authenticator_data_hex: "00".into(),
            client_data_hex: "00".into(),
            signature_hex: "00".into(),
            rp_id: "dash.example.com".into(),
            origin: "https://dash.example.com".into(),
            at_ms: 1,
        }
    }

    fn link() -> TgLink {
        let record = LinkRecord {
            id: "l1".into(),
            person: "ada".into(),
            telegram_id: 4_000_000_001,
            chat_id: 4_000_000_001,
            bot_id: 7_000_000_002,
            label: "phone".into(),
            created_ms: 1_000,
            expires_ms: 1_000 + LINK_TTL_MS,
        };
        let digest = to_hex(&record.digest().unwrap());
        TgLink {
            record,
            digest,
            signed: ev("ada"),
            confirm_with: None,
            state: LinkState::Active,
            last_seen_ms: 0,
            changed_ms: None,
            renewed: None,
            unlocked_ms: None,
            ended: None,
        }
    }

    fn deleg(with_link: bool) -> TgDelegation {
        let record = DelegationRecord {
            id: "d1".into(),
            link_id: "l1".into(),
            person: "ada".into(),
            telegram_id: 4_000_000_001,
            bot_id: 7_000_000_002,
            boxes: vec!["alpha".into()],
            acts: vec![DelegatedAct::Converse],
            caps: Caps::default(),
            not_before_ms: 1_000,
            expires_ms: 1_000 + 7 * 24 * 3_600_000,
            hub_ack: false,
            with_link,
        };
        let digest = to_hex(&record.digest().unwrap());
        TgDelegation {
            record,
            digest,
            signed: (!with_link).then(|| ev("ada")),
            owner: None,
            issued_ms: 1_000,
            last_used_ms: 0,
            revoked: false,
        }
    }

    fn store() -> TgStore {
        let mut s = TgStore::in_memory();
        s.data.links.push(link());
        s
    }

    #[test]
    fn a_link_is_genuine_only_when_its_assertion_covers_its_own_digest() {
        let s = store();
        let l = &s.data.links[0];
        let d = from_hex(&l.digest).unwrap();
        let want = confirm_from_digests(&<[u8; 32]>::try_from(d).unwrap(), None);
        let yes = |_: &SignedEvidence, c: &[u8; 32]| c == &want;
        assert!(s.link_is_genuine(l, &yes));
        // an assertion that does not verify, or one over something else
        assert!(!s.link_is_genuine(l, &|_, _| false));
        // a row whose fields were edited after the touch digests to something else
        let mut forged = l.clone();
        forged.record.person = "bob".into();
        assert!(!s.link_is_genuine(&forged, &|_, _| true));
        let mut forged = l.clone();
        forged.record.telegram_id += 1;
        forged.record.chat_id += 1;
        assert!(
            !s.link_is_genuine(&forged, &|_, _| true),
            "another account in the same row"
        );
        // an assertion by someone other than the person
        let mut other = l.clone();
        other.signed.person = "bob".into();
        assert!(!s.link_is_genuine(&other, &|_, _| true));
    }

    #[test]
    fn a_delegation_with_no_matching_assertion_is_not_genuine_and_an_edited_one_is_not_either() {
        let mut s = store();
        let own = |_: &str| true;
        let ok = |_: &SignedEvidence, _: &[u8; 32]| true;
        let d = deleg(false);
        assert!(s.delegation_is_genuine(&d, false, &ok, &own));
        // no assertion at all: a hand-written row
        let mut bare = d.clone();
        bare.signed = None;
        assert!(!s.delegation_is_genuine(&bare, false, &ok, &own));
        // the assertion does not verify
        assert!(!s.delegation_is_genuine(&d, false, &|_, _| false, &own));
        // a box added to the row after it was signed
        let mut edited = d.clone();
        edited.record.boxes.push("zulu".into());
        assert!(!s.delegation_is_genuine(&edited, false, &ok, &own));
        // an act added
        let mut edited = d.clone();
        edited.record.acts.push(DelegatedAct::Power);
        edited.record.acts.sort();
        assert!(!s.delegation_is_genuine(&edited, false, &ok, &own));
        // it must belong to a link that exists and is the same account
        let mut orphan = d.clone();
        orphan.record.link_id = "nope".into();
        assert!(!s.delegation_is_genuine(&orphan, false, &ok, &own));
        s.data.links[0].record.telegram_id += 1;
        assert!(!s.delegation_is_genuine(&d, false, &ok, &own));
    }

    #[test]
    fn a_delegation_made_with_the_link_is_covered_only_by_the_links_own_assertion() {
        let mut s = store();
        let d = deleg(true);
        let ok = |_: &SignedEvidence, _: &[u8; 32]| true;
        let own = |_: &str| true;
        assert!(
            !s.delegation_is_genuine(&d, false, &ok, &own),
            "the link's assertion did not cover it"
        );
        s.data.links[0].confirm_with = Some(d.digest.clone());
        assert!(s.delegation_is_genuine(&d, false, &ok, &own));
        let mut other = d.clone();
        other.record.boxes = vec!["bravo".into()];
        other.digest = to_hex(&other.record.digest().unwrap());
        assert!(
            !s.delegation_is_genuine(&other, false, &ok, &own),
            "a different delegation, same link"
        );
    }

    #[test]
    fn a_members_delegation_needs_an_owners_assertion_naming_them_by_someone_who_is_an_owner_now() {
        let s = store();
        let ok = |_: &SignedEvidence, _: &[u8; 32]| true;
        let mut d = deleg(false);
        assert!(
            !s.delegation_is_genuine(&d, true, &ok, &|_| true),
            "no owner assertion"
        );
        d.owner = Some(ev("boss"));
        assert!(s.delegation_is_genuine(&d, true, &ok, &|p| p == "boss"));
        assert!(
            !s.delegation_is_genuine(&d, true, &ok, &|_| false),
            "no longer an owner"
        );
        assert!(!s.delegation_is_genuine(&d, true, &|_, _| false, &|_| true));
    }

    #[test]
    fn the_store_is_written_durably_read_back_and_a_bad_file_is_an_error_not_an_empty_store() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("telegram.json");
        let mut s = TgStore::open(path.clone()).unwrap();
        assert!(s.is_persistent() && s.data.links.is_empty());
        s.data.links.push(link());
        s.data.seen.insert(7, 100, 5_000);
        s.data.offset = 101;
        s.save().unwrap();
        let again = TgStore::open(path.clone()).unwrap();
        assert_eq!(again.data.links.len(), 1);
        assert!(again.data.seen.contains(7, 100));
        assert_eq!(again.data.offset, 101);
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(
                std::fs::metadata(&path).unwrap().permissions().mode() & 0o777,
                0o600
            );
        }
        std::fs::write(&path, "{ not json").unwrap();
        assert!(
            TgStore::open(path).is_err(),
            "an unreadable file never loads as empty"
        );
        // a folder that cannot be written to is a failed save, not a silent one
        let blocked = dir.path().join("file-not-folder");
        std::fs::write(&blocked, "x").unwrap();
        let mut s =
            TgStore::open(blocked.join("telegram.json")).unwrap_or_else(|_| TgStore::in_memory());
        s.path = Some(blocked.join("telegram.json"));
        assert!(s.save().is_err());
    }

    #[test]
    fn refusals_are_written_to_the_chain_at_most_twenty_an_hour_per_link() {
        let mut s = store();
        for i in 0..REFUSAL_AUDIT_PER_HOUR {
            assert!(s.refusal_audit_allowed("l1", 1_000 + i as u64), "{i}");
        }
        assert!(!s.refusal_audit_allowed("l1", 2_000));
        assert!(
            s.refusal_audit_allowed("l2", 2_000),
            "another link has its own allowance"
        );
        assert!(
            s.refusal_audit_allowed("l1", 1_000 + 3_600_001),
            "an hour later"
        );
    }

    #[test]
    fn a_renewal_extends_the_end_and_a_lookup_ignores_revoked_links() {
        let mut s = store();
        let l = s.link_mut("l1").unwrap();
        let base = l.expires_ms();
        l.renewed = Some(Renewal {
            expires_ms: base + 1_000,
            signed: ev("ada"),
        });
        assert_eq!(s.link("l1").unwrap().expires_ms(), base + 1_000);
        assert!(s.live_link_of(7_000_000_002, 4_000_000_001).is_some());
        assert!(
            s.live_link_of(7_000_000_003, 4_000_000_001).is_none(),
            "another bot"
        );
        s.link_mut("l1").unwrap().state = LinkState::Revoked;
        assert!(s.live_link_of(7_000_000_002, 4_000_000_001).is_none());
    }
}
