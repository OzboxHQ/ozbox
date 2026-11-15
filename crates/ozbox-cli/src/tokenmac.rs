//! Internal tokens (dashboard session ids, setup codes, single-use tickets, code-session ids) are random 256-bit values
//! that are never stored. What is stored, and what a lookup compares, is a keyed hash: HMAC-SHA256 of the token under a
//! server key that lives in the secret store, not next to the sessions file. A copy of the sessions file, a heap dump or
//! a log line therefore holds nothing a cookie can be rebuilt from, and nothing that can be checked against guesses
//! without the key.
//!
//! The keys are rotated. A rotation makes a new current key and keeps the old one for an overlap window, so a session
//! issued before it is still found (and moved to the new key the next time it is used) while the window lasts. A session
//! file written before this module existed holds plain SHA-256 keys: those are still found once and re-keyed on use, so
//! nobody is signed out by the upgrade.

use std::sync::{Arc, Mutex, OnceLock};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use ring::hmac;
use zeroize::Zeroizing;

use crate::secrets::{MemorySecrets, SecretError, SecretStore};
use crate::serve::auth::b64::{decode_url, encode_url};

/// The secret holding the keys.
pub const KEYS_SECRET: &str = "internal-hmac-keys";
const REFRESH_EVERY: Duration = Duration::from_secs(30);

#[derive(Clone)]
struct Key {
    kid: String,
    key: Zeroizing<Vec<u8>>,
}

#[derive(Clone)]
struct KeySet {
    current: Key,
    previous: Option<(Key, u64)>,
}

fn new_key() -> Result<Key, SecretError> {
    let mut raw = Zeroizing::new(vec![0u8; 32]);
    let mut kid = [0u8; 4];
    getrandom::getrandom(&mut raw)
        .and_then(|()| getrandom::getrandom(&mut kid))
        .map_err(|_| SecretError("no random numbers are available".into()))?;
    Ok(Key {
        kid: crate::notify::hex(&kid),
        key: raw,
    })
}

impl KeySet {
    /// `v1.<kid>.<key>` or `v1.<kid>.<key>.<prev kid>.<prev key>.<until ms>`: visible characters only, so any store
    /// accepts it.
    fn encode(&self) -> Zeroizing<String> {
        let mut s = format!("v1.{}.{}", self.current.kid, encode_url(&self.current.key));
        if let Some((k, until)) = &self.previous {
            s.push_str(&format!(".{}.{}.{until}", k.kid, encode_url(&k.key)));
        }
        Zeroizing::new(s)
    }

    fn decode(text: &str) -> Option<KeySet> {
        let p: Vec<&str> = text.trim().split('.').collect();
        let key = |kid: &str, k: &str| -> Option<Key> {
            let raw = decode_url(k)?;
            (raw.len() == 32 && !kid.is_empty()).then(|| Key {
                kid: kid.to_string(),
                key: Zeroizing::new(raw),
            })
        };
        match p.as_slice() {
            ["v1", kid, k] => Some(KeySet {
                current: key(kid, k)?,
                previous: None,
            }),
            ["v1", kid, k, pkid, pk, until] => Some(KeySet {
                current: key(kid, k)?,
                previous: Some((key(pkid, pk)?, until.parse().ok()?)),
            }),
            _ => None,
        }
    }

    fn tags(&self, msg: &[u8], now_ms: u64) -> Vec<[u8; 32]> {
        let one = |k: &Key| {
            let t = hmac::sign(&hmac::Key::new(hmac::HMAC_SHA256, &k.key), msg);
            let mut out = [0u8; 32];
            out.copy_from_slice(t.as_ref());
            out
        };
        let mut v = vec![one(&self.current)];
        if let Some((k, until)) = &self.previous {
            if *until > now_ms {
                v.push(one(k));
            }
        }
        v
    }
}

pub fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| u64::try_from(d.as_millis()).unwrap_or(u64::MAX))
}

/// Make the first key set, or rotate: the current key becomes the previous one for `overlap_ms`, and a new current key
/// is made. Returns the new key's id (not secret). This is what `ozbox secrets rotate-hmac` runs.
pub fn rotate(
    store: &dyn SecretStore,
    now_ms: u64,
    overlap_ms: u64,
) -> Result<String, SecretError> {
    let fresh = new_key()?;
    let kid = fresh.kid.clone();
    let existing = store.get(KEYS_SECRET)?.and_then(|t| KeySet::decode(&t));
    let set = KeySet {
        previous: existing.map(|e| (e.current, now_ms.saturating_add(overlap_ms))),
        current: fresh,
    };
    store.set(KEYS_SECRET, &set.encode())?;
    Ok(kid)
}

/// Make the keys if the store has none. Returns whether it made them.
pub fn ensure(store: &dyn SecretStore, now_ms: u64) -> Result<bool, SecretError> {
    if store.exists(KEYS_SECRET)? {
        return Ok(false);
    }
    rotate(store, now_ms, 0)?;
    Ok(true)
}

/// Computes the tags for the process. A store that answers `mac_tags` itself (the box's secrets service, which never
/// hands the keys out) is asked each time; any other store is read at most every 30 seconds.
pub struct TokenMac {
    store: Arc<dyn SecretStore>,
    cache: Mutex<Option<(Instant, KeySet)>>,
    /// Used when the store cannot be read: sessions then last only until the next restart.
    fallback: KeySet,
}

impl TokenMac {
    pub fn new(store: Arc<dyn SecretStore>) -> Self {
        let fallback = KeySet {
            current: new_key().unwrap_or(Key {
                kid: "fallback".into(),
                key: Zeroizing::new(vec![0x5a; 32]),
            }),
            previous: None,
        };
        // The keys are made here if the store has none; a store that cannot answer leaves the fallback in charge.
        let _ = ensure(store.as_ref(), now_ms());
        Self {
            store,
            cache: Mutex::new(None),
            fallback,
        }
    }

    /// A process-local key that is never stored: tests, and a run with no usable store.
    pub fn ephemeral() -> Self {
        Self::new(Arc::new(MemorySecrets::default()))
    }

    fn keys(&self) -> KeySet {
        let mut c = self.cache.lock().unwrap_or_else(|e| e.into_inner());
        if let Some((at, k)) = c.as_ref() {
            if at.elapsed() < REFRESH_EVERY {
                return k.clone();
            }
        }
        match self
            .store
            .get(KEYS_SECRET)
            .ok()
            .flatten()
            .and_then(|t| KeySet::decode(&t))
        {
            Some(k) => {
                *c = Some((Instant::now(), k.clone()));
                k
            }
            None => self.fallback.clone(),
        }
    }

    /// Hex tags of `msg`, current key first; the previous key's while its overlap lasts.
    pub fn tags_hex(&self, msg: &[u8], now_ms: u64) -> Vec<String> {
        if let Ok(Some(t)) = self.store.mac_tags(msg) {
            if !t.is_empty() {
                return t.iter().map(|x| crate::notify::hex(x)).collect();
            }
        }
        self.keys()
            .tags(msg, now_ms)
            .iter()
            .map(|x| crate::notify::hex(x))
            .collect()
    }

    #[allow(dead_code)] // for a rotation made by another process; tests call it
    /// Forget the cached keys, so the next lookup reads the store (after a rotation made by another process).
    pub fn refresh(&self) {
        *self.cache.lock().unwrap_or_else(|e| e.into_inner()) = None;
    }
}

static GLOBAL: OnceLock<TokenMac> = OnceLock::new();

/// Called once at server start with the store the keys live in. Returns false if a store was already installed.
pub fn install(store: Arc<dyn SecretStore>) -> bool {
    GLOBAL.set(TokenMac::new(store)).is_ok()
}

fn global() -> &'static TokenMac {
    GLOBAL.get_or_init(TokenMac::ephemeral)
}

/// The key a token is stored under: its HMAC under the current server key.
pub fn key_of(token: &str) -> String {
    global()
        .tags_hex(token.as_bytes(), now_ms())
        .into_iter()
        .next()
        .unwrap_or_default()
}

/// Every key a token may be stored under now: current first, then the previous key during its overlap.
pub fn lookup_keys(token: &str) -> Vec<String> {
    global().tags_hex(token.as_bytes(), now_ms())
}

/// What older versions stored: the plain SHA-256 of the token. Used only to find a session file written before the
/// HMAC existed, so it can be re-keyed.
pub fn legacy_key_of(token: &str) -> String {
    ring::digest::digest(&ring::digest::SHA256, token.as_bytes())
        .as_ref()
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use crate::serve::auth::b64::ct_eq_bytes;

    fn mac(store: Arc<dyn SecretStore>) -> TokenMac {
        TokenMac::new(store)
    }

    #[test]
    fn a_token_is_keyed_not_plainly_hashed_and_is_stable() {
        let s: Arc<dyn SecretStore> = Arc::new(MemorySecrets::default());
        let m = mac(s.clone());
        let a = m.tags_hex(b"token", 1);
        assert_eq!(a.len(), 1);
        assert_eq!(a, m.tags_hex(b"token", 2));
        assert_ne!(a[0], legacy_key_of("token"));
        assert_ne!(a, m.tags_hex(b"token2", 1));
        // another server key gives another tag
        let other = mac(Arc::new(MemorySecrets::default()));
        assert_ne!(a, other.tags_hex(b"token", 1));
        // the same store gives the same tag after a restart
        assert_eq!(a, mac(s).tags_hex(b"token", 1));
    }

    #[test]
    fn the_stored_keys_are_visible_text_that_round_trips() {
        let s = MemorySecrets::default();
        assert!(ensure(&s, 0).unwrap());
        assert!(!ensure(&s, 0).unwrap());
        rotate(&s, 1000, 500).unwrap();
        let text = s.get(KEYS_SECRET).unwrap().unwrap();
        let set = KeySet::decode(&text).unwrap();
        assert_eq!(set.previous.as_ref().map(|p| p.1), Some(1500));
        assert_eq!(set.encode().as_str(), text);
        assert!(KeySet::decode("v1.x.short").is_none() && KeySet::decode("garbage").is_none());
    }

    #[test]
    fn rotation_keeps_the_old_key_for_the_overlap_and_then_drops_it() {
        let s: Arc<dyn SecretStore> = Arc::new(MemorySecrets::default());
        let m = mac(s.clone());
        let before = m.tags_hex(b"id", 1_000).remove(0);
        rotate(s.as_ref(), 1_000, 10_000).unwrap();
        m.refresh();
        let during = m.tags_hex(b"id", 5_000);
        assert_eq!(during.len(), 2);
        assert_ne!(during[0], before, "new tokens use the new key");
        assert_eq!(
            during[1], before,
            "a session made before is still found in the window"
        );
        let after = m.tags_hex(b"id", 11_001);
        assert_eq!(after.len(), 1);
        assert!(
            !after.contains(&before),
            "after the window the old key finds nothing"
        );
        // a second rotation inside the window drops the oldest key: only one key of overlap is ever kept
        rotate(s.as_ref(), 12_000, 10_000).unwrap();
        m.refresh();
        let t = m.tags_hex(b"id", 12_500);
        assert_eq!(t.len(), 2);
        assert!(!t.contains(&before));
    }

    #[test]
    fn an_unreadable_store_falls_back_to_a_key_that_lives_only_in_memory() {
        let m = mac(Arc::new(crate::secrets::UnavailableSecrets("down")));
        let a = m.tags_hex(b"id", 1);
        assert_eq!(a.len(), 1);
        assert_eq!(a, m.tags_hex(b"id", 2));
        assert_ne!(
            a,
            mac(Arc::new(crate::secrets::UnavailableSecrets("down"))).tags_hex(b"id", 1)
        );
    }

    #[test]
    fn tags_compare_in_constant_time_by_the_helper_and_differ_per_token() {
        let m = TokenMac::ephemeral();
        let a = m.tags_hex(b"one", 0).remove(0);
        let b = m.tags_hex(b"two", 0).remove(0);
        assert!(ct_eq_bytes(a.as_bytes(), a.as_bytes()));
        assert!(!ct_eq_bytes(a.as_bytes(), b.as_bytes()));
        assert_eq!(a.len(), 64);
    }

    #[test]
    fn the_keys_are_in_no_tag_and_no_error() {
        let s = MemorySecrets::default();
        ensure(&s, 0).unwrap();
        let text = s.get(KEYS_SECRET).unwrap().unwrap();
        let key_part = text.split('.').nth(2).unwrap().to_string();
        let m = mac(Arc::new(s));
        let tag = m.tags_hex(b"x", 0).remove(0);
        assert!(!tag.contains(&key_part));
    }
}
