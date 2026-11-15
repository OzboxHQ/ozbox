//! One-time links from a chat to the dashboard, for approvals that need a person's passkey.
//!
//! A link carries a random token. Only a keyed hash of it (HMAC-SHA256, the key held in memory for this run of the server)
//! is stored, so a copy of the server's state holds nothing that opens a link, and links stop working when the server
//! restarts. A token is used once, lapses after ten minutes, and is bound to the person it was made for. Using it does not
//! approve anything: it only names the request, and the dashboard asks for the person's passkey before it records an answer.

use ring::{
    hmac,
    rand::{SecureRandom, SystemRandom},
};

use super::text::ct_eq;

pub const TTL_MS: u64 = 10 * 60_000;
const MAX_LIVE: usize = 200;

#[derive(Debug, PartialEq, Eq)]
pub enum LinkError {
    /// Not a link made here, already used, or lapsed: one answer, so nothing is learned by trying.
    Invalid,
}

struct Entry {
    tag: Vec<u8>,
    approval_id: String,
    person: String,
    expires_ms: u64,
}

pub struct Links {
    key: hmac::Key,
    live: Vec<Entry>,
}

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

impl Links {
    pub fn new() -> Result<Self, String> {
        let rng = SystemRandom::new();
        let mut k = [0u8; 32];
        rng.fill(&mut k)
            .map_err(|_| "no secure random source".to_string())?;
        Ok(Self {
            key: hmac::Key::new(hmac::HMAC_SHA256, &k),
            live: Vec::new(),
        })
    }

    fn tag(&self, token: &str) -> Vec<u8> {
        hmac::sign(&self.key, token.as_bytes()).as_ref().to_vec()
    }

    /// Make a link token for one approval and one person.
    pub fn issue(
        &mut self,
        approval_id: &str,
        person: &str,
        now_ms: u64,
    ) -> Result<String, String> {
        self.live.retain(|e| e.expires_ms > now_ms);
        if self.live.len() >= MAX_LIVE {
            self.live.remove(0);
        }
        let mut raw = [0u8; 24];
        SystemRandom::new()
            .fill(&mut raw)
            .map_err(|_| "no secure random source".to_string())?;
        let token = hex(&raw);
        let tag = self.tag(&token);
        self.live.push(Entry {
            tag,
            approval_id: approval_id.to_string(),
            person: person.to_string(),
            expires_ms: now_ms + TTL_MS,
        });
        Ok(token)
    }

    /// Read a token without using it: what it names, for the person it was made for. Opening a link must not burn it (the
    /// advised flow opens it twice, once in Telegram's browser and once in the real one, and a preview of a pasted copy must
    /// not spend it); only an act that needs it consumes it, and a wrong person learns nothing.
    pub fn peek(&self, token: &str, person: &str, now_ms: u64) -> Result<String, LinkError> {
        if token.len() != 48 || !token.bytes().all(|b| b.is_ascii_hexdigit()) {
            return Err(LinkError::Invalid);
        }
        let tag = self.tag(token);
        self.live
            .iter()
            .find(|e| ct_eq(&e.tag, &tag))
            .filter(|e| e.expires_ms > now_ms && e.person == person)
            .map(|e| e.approval_id.clone())
            .ok_or(LinkError::Invalid)
    }

    /// Use a token once: the approval it names, for the person it was made for.
    pub fn redeem(&mut self, token: &str, person: &str, now_ms: u64) -> Result<String, LinkError> {
        if token.len() != 48 || !token.bytes().all(|b| b.is_ascii_hexdigit()) {
            return Err(LinkError::Invalid);
        }
        let tag = self.tag(token);
        let pos = self.live.iter().position(|e| ct_eq(&e.tag, &tag));
        let Some(i) = pos else {
            return Err(LinkError::Invalid);
        };
        // it is used up by the attempt, right person or not, so a guessed token cannot be tried twice
        let e = self.live.remove(i);
        if e.expires_ms <= now_ms || e.person != person {
            return Err(LinkError::Invalid);
        }
        Ok(e.approval_id)
    }

    /// For the sentinel test: what is held, as text.
    #[cfg(test)]
    pub fn held_text(&self) -> String {
        self.live
            .iter()
            .map(|e| format!("{}{}{}", hex(&e.tag), e.approval_id, e.person))
            .collect()
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn a_link_works_once_for_its_person_and_only_before_it_lapses() {
        let mut l = Links::new().unwrap();
        let t = l.issue("a1", "ada", 1_000).unwrap();
        assert_eq!(t.len(), 48);
        assert_eq!(l.redeem(&t, "ada", 2_000), Ok("a1".to_string()));
        assert_eq!(
            l.redeem(&t, "ada", 2_001),
            Err(LinkError::Invalid),
            "one time"
        );
        let t2 = l.issue("a2", "ada", 1_000).unwrap();
        assert_eq!(
            l.redeem(&t2, "bob", 2_000),
            Err(LinkError::Invalid),
            "another person"
        );
        assert_eq!(
            l.redeem(&t2, "ada", 2_001),
            Err(LinkError::Invalid),
            "and that attempt used it up"
        );
        let t3 = l.issue("a3", "ada", 1_000).unwrap();
        assert_eq!(
            l.redeem(&t3, "ada", 1_000 + TTL_MS),
            Err(LinkError::Invalid),
            "lapsed"
        );
        assert_eq!(l.redeem("zz", "ada", 1), Err(LinkError::Invalid));
        assert_eq!(l.redeem(&"0".repeat(48), "ada", 1), Err(LinkError::Invalid));
    }

    #[test]
    fn only_a_keyed_hash_is_held_never_the_token() {
        let mut l = Links::new().unwrap();
        let t = l.issue("a1", "ada", 1).unwrap();
        assert!(!l.held_text().contains(&t));
        // a link from another run of the server (another key) is worthless
        let mut other = Links::new().unwrap();
        assert_eq!(other.redeem(&t, "ada", 2), Err(LinkError::Invalid));
    }
}
