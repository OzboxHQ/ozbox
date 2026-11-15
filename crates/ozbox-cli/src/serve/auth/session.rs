//! Server-side sign-in sessions. The browser holds only an unguessable id in a `__Host-` cookie (Secure, HttpOnly,
//! SameSite=Strict, no Domain, path `/`); everything else lives here and can be revoked.

use std::collections::HashMap;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use super::b64::encode_url;

pub const COOKIE: &str = "__Host-ozbox_session";
pub const OAUTH_COOKIE: &str = "__Host-ozbox_oauth";
const MAX_SESSIONS: usize = 256;
/// A change that only moves `last_seen` (or a level the person can re-earn) is written at most this often. Starting,
/// rotating and ending a session are written at once, because those must survive a restart in both directions.
const FLUSH_EVERY_MS: u64 = 5_000;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Level {
    /// The first factor (GitHub, Google, Access, a setup code) passed; a passkey or authenticator code must follow.
    NeedsSecondFactor,
    /// The person has no second factor yet: only enrolling one is allowed.
    EnrollRequired,
    Full,
}

#[derive(Debug, Clone)]
pub struct Session {
    pub user: String,
    pub level: Level,
    pub created_ms: u64,
    pub last_seen_ms: u64,
    pub last_stepup_ms: Option<u64>,
    pub csrf: String,
    pub via: &'static str,
    /// A freshly made authenticator secret, held until the first code proves it works.
    pub pending_totp: Option<String>,
}

pub fn random_token(bytes: usize) -> Option<String> {
    let mut b = vec![0u8; bytes];
    getrandom::getrandom(&mut b).ok()?;
    Some(encode_url(&b))
}

/// The key a session id is stored under: its HMAC-SHA256 under the server's token key (see `crate::tokenmac`), so a copy of
/// the sessions file or a memory dump holds nothing a cookie can be rebuilt from, even by guessing.
pub fn key_of(id: &str) -> String {
    crate::tokenmac::key_of(id)
}

/// A named cookie out of a `Cookie` header.
pub fn cookie_value<'a>(header: &'a str, name: &str) -> Option<&'a str> {
    header.split(';').find_map(|p| {
        let (k, v) = p.trim().split_once('=')?;
        (k == name).then_some(v)
    })
}

/// `Set-Cookie` text. `same_site` is `Strict` for the session and `Lax` for the short OAuth transaction cookie
/// (a cross-site return from the provider would not carry a Strict one).
pub fn set_cookie(name: &str, value: &str, max_age_s: u64, same_site: &str) -> String {
    format!("{name}={value}; Path=/; Max-Age={max_age_s}; Secure; HttpOnly; SameSite={same_site}")
}

pub fn clear_cookie(name: &str) -> String {
    format!("{name}=; Path=/; Max-Age=0; Secure; HttpOnly; SameSite=Strict")
}

/// What is written for one session. The id itself never is (only its hash, the key), and neither is a half-finished
/// authenticator secret.
#[derive(Debug, Serialize, Deserialize)]
struct Stored {
    key: String,
    user: String,
    created_ms: u64,
    last_seen_ms: u64,
    #[serde(default)]
    last_stepup_ms: Option<u64>,
    csrf: String,
    via: String,
}

#[derive(Debug, Default, Serialize, Deserialize)]
struct StoredFile {
    version: u32,
    sessions: Vec<Stored>,
}

/// The sign-in methods a session can have come from. A value from a file that is none of these is shown as `restored`.
fn via_static(s: &str) -> &'static str {
    ["passkey", "setup code", "github", "google", "access"]
        .into_iter()
        .find(|v| *v == s)
        .unwrap_or("restored")
}

fn valid_key(k: &str) -> bool {
    k.len() == 64
        && k.bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

struct Store {
    path: PathBuf,
    dirty: bool,
    last_flush_ms: u64,
    /// The latest time any call reported, for changes that are not handed one.
    seen_ms: u64,
}

#[derive(Default)]
pub struct Sessions {
    map: HashMap<String, Session>,
    store: Option<Store>,
}

impl Sessions {
    /// Sessions that survive a restart: read from `path` (a file of this server's own state directory), with the idle and
    /// absolute limits applied to what is read. A missing, unreadable or damaged file is an empty one: nobody is signed
    /// in by a file that cannot be trusted, and nobody is locked out by one either.
    pub fn persistent(path: PathBuf, now_ms: u64, idle_ms: u64, absolute_ms: u64) -> Self {
        let stored: StoredFile = std::fs::read_to_string(&path)
            .ok()
            .and_then(|t| serde_json::from_str(&t).ok())
            .unwrap_or_default();
        let mut map = HashMap::new();
        for e in stored.sessions.into_iter().take(MAX_SESSIONS) {
            let live = now_ms.saturating_sub(e.last_seen_ms) < idle_ms
                && now_ms.saturating_sub(e.created_ms) < absolute_ms;
            if !valid_key(&e.key) || e.user.is_empty() || !live {
                continue;
            }
            map.insert(
                e.key,
                Session {
                    user: e.user,
                    level: Level::Full,
                    created_ms: e.created_ms,
                    last_seen_ms: e.last_seen_ms,
                    last_stepup_ms: e.last_stepup_ms,
                    csrf: e.csrf,
                    via: via_static(&e.via),
                    pending_totp: None,
                },
            );
        }
        Self {
            map,
            store: Some(Store {
                path,
                dirty: false,
                last_flush_ms: now_ms,
                seen_ms: now_ms,
            }),
        }
    }

    /// Write now. Only full sessions are kept: someone halfway through signing in starts that again after a restart.
    fn flush(&mut self, now_ms: u64) {
        let Some(store) = &mut self.store else {
            return;
        };
        let mut sessions: Vec<Stored> = self
            .map
            .iter()
            .filter(|(_, s)| s.level == Level::Full)
            .map(|(k, s)| Stored {
                key: k.clone(),
                user: s.user.clone(),
                created_ms: s.created_ms,
                last_seen_ms: s.last_seen_ms,
                last_stepup_ms: s.last_stepup_ms,
                csrf: s.csrf.clone(),
                via: s.via.to_string(),
            })
            .collect();
        sessions.sort_by(|a, b| a.key.cmp(&b.key));
        // A failed write leaves the old file, and the change is tried again at the next opportunity.
        if write_private(
            &store.path,
            &StoredFile {
                version: 1,
                sessions,
            },
        )
        .is_ok()
        {
            store.dirty = false;
            store.last_flush_ms = now_ms;
        }
    }

    /// A change that must not be lost: written now.
    fn changed(&mut self, now_ms: u64) {
        if let Some(s) = &mut self.store {
            s.dirty = true;
            s.seen_ms = s.seen_ms.max(now_ms);
        }
        self.flush(now_ms);
    }

    /// A change made without a clock reading in hand (removal, rotation): written now.
    fn changed_now(&mut self) {
        let now = self.store.as_ref().map_or(0, |s| s.seen_ms);
        self.changed(now);
    }

    /// A change that can wait a few seconds.
    fn changed_lazily(&mut self, now_ms: u64) {
        let due = match &mut self.store {
            Some(s) => {
                s.dirty = true;
                s.seen_ms = s.seen_ms.max(now_ms);
                now_ms.saturating_sub(s.last_flush_ms) >= FLUSH_EVERY_MS
            }
            None => false,
        };
        if due {
            self.flush(now_ms);
        }
    }

    /// Start a session and return its cookie id (shown once).
    pub fn create(
        &mut self,
        s: Session,
        now_ms: u64,
        idle_ms: u64,
        absolute_ms: u64,
    ) -> Option<String> {
        self.sweep(now_ms, idle_ms, absolute_ms);
        if self.map.len() >= MAX_SESSIONS {
            return None;
        }
        let id = random_token(32)?;
        self.map.insert(key_of(&id), s);
        self.changed(now_ms);
        Some(id)
    }

    /// Is the session stored under `key` still there and within its absolute lifetime? Does not touch it: a code session
    /// asking is not the person using the dashboard.
    pub fn alive(&self, key: &str, now_ms: u64, absolute_ms: u64) -> bool {
        self.map
            .get(key)
            .is_some_and(|s| now_ms.saturating_sub(s.created_ms) < absolute_ms)
    }

    /// The key this cookie id is stored under now. A session stored under the previous server key (inside a rotation's
    /// overlap) or under the plain hash an older version wrote is found and moved to the current key, so a rotation or an
    /// upgrade does not sign anyone out.
    fn find_key(&mut self, id: &str) -> Option<String> {
        let keys = crate::tokenmac::lookup_keys(id);
        let current = keys.first()?.clone();
        if self.map.contains_key(&current) {
            return Some(current);
        }
        let old = keys
            .into_iter()
            .skip(1)
            .chain(std::iter::once(crate::tokenmac::legacy_key_of(id)))
            .find(|k| self.map.contains_key(k))?;
        let s = self.map.remove(&old)?;
        self.map.insert(current.clone(), s);
        self.changed_now();
        Some(current)
    }

    /// A live session for this cookie id, with its idle and absolute limits applied. Touches `last_seen`.
    pub fn touch(
        &mut self,
        id: &str,
        now_ms: u64,
        idle_ms: u64,
        absolute_ms: u64,
    ) -> Option<(String, Session)> {
        let k = self.find_key(id)?;
        let s = self.map.get_mut(&k)?;
        if now_ms.saturating_sub(s.last_seen_ms) >= idle_ms
            || now_ms.saturating_sub(s.created_ms) >= absolute_ms
        {
            self.map.remove(&k);
            self.changed_lazily(now_ms);
            return None;
        }
        s.last_seen_ms = now_ms;
        let out = (k, s.clone());
        self.changed_lazily(now_ms);
        Some(out)
    }

    /// Whose session this is, without touching it.
    pub fn user_of(&self, key: &str) -> Option<&str> {
        self.map.get(key).map(|s| s.user.as_str())
    }

    /// The caller may change level, step-up time or the like. Written at the next opportunity (a few seconds at most),
    /// which is safe in both directions: a lost raise of level means signing in again, a lost drop cannot happen
    /// because dropping a session goes through `remove`, which writes at once.
    pub fn get_mut(&mut self, key: &str) -> Option<&mut Session> {
        if let Some(s) = &mut self.store {
            s.dirty = true;
        }
        self.map.get_mut(key)
    }

    pub fn remove(&mut self, key: &str) -> bool {
        let gone = self.map.remove(key).is_some();
        if gone {
            self.changed_now();
        }
        gone
    }

    /// Replace a session's id (after a change of level), keeping its record. Returns the new cookie id.
    pub fn rotate(&mut self, key: &str) -> Option<String> {
        let s = self.map.remove(key)?;
        let id = random_token(32)?;
        self.map.insert(key_of(&id), s);
        self.changed_now();
        Some(id)
    }

    pub fn remove_user(&mut self, user: &str) -> usize {
        let before = self.map.len();
        self.map.retain(|_, s| s.user != user);
        let n = before - self.map.len();
        if n > 0 {
            self.changed_now();
        }
        n
    }

    /// Drop every session whose person `keep` does not name (people taken off the list).
    pub fn retain_users(&mut self, keep: impl Fn(&str) -> bool) -> usize {
        let before = self.map.len();
        self.map.retain(|_, s| keep(&s.user));
        let n = before - self.map.len();
        if n > 0 {
            self.changed_now();
        }
        n
    }

    pub fn of_user(&self, user: &str) -> Vec<(String, Session)> {
        let mut v: Vec<_> = self
            .map
            .iter()
            .filter(|(_, s)| s.user == user && s.level == Level::Full)
            .map(|(k, s)| (k.clone(), s.clone()))
            .collect();
        v.sort_by_key(|(_, s)| s.created_ms);
        v
    }

    pub fn sweep(&mut self, now_ms: u64, idle_ms: u64, absolute_ms: u64) {
        let before = self.map.len();
        self.map.retain(|_, s| {
            now_ms.saturating_sub(s.last_seen_ms) < idle_ms
                && now_ms.saturating_sub(s.created_ms) < absolute_ms
        });
        if self.map.len() != before {
            self.changed_lazily(now_ms);
        }
    }
}

/// Write the file whole to a private temporary file next to it and rename it into place: a reader never sees half a
/// file, and the mode is 0600 from the first byte.
fn write_private(path: &Path, file: &StoredFile) -> std::io::Result<()> {
    use std::io::Write;
    #[cfg(unix)]
    use std::os::unix::fs::OpenOptionsExt;
    let tmp = path.with_extension("tmp");
    let mut opts = std::fs::OpenOptions::new();
    opts.write(true).create(true).truncate(true);
    #[cfg(unix)]
    opts.mode(0o600);
    let mut f = opts.open(&tmp)?;
    f.write_all(serde_json::to_string(file)?.as_bytes())?;
    f.sync_all()?;
    std::fs::rename(&tmp, path)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sess(user: &str, now: u64) -> Session {
        Session {
            user: user.into(),
            level: Level::Full,
            created_ms: now,
            last_seen_ms: now,
            last_stepup_ms: None,
            csrf: "c".into(),
            via: "passkey",
            pending_totp: None,
        }
    }

    #[test]
    fn cookies_carry_the_protective_flags() {
        let c = set_cookie(COOKIE, "abc", 60, "Strict");
        for f in ["Secure", "HttpOnly", "SameSite=Strict", "Path=/", "__Host-"] {
            assert!(c.contains(f), "{c}");
        }
        assert!(!c.contains("Domain"));
        assert!(set_cookie(OAUTH_COOKIE, "x", 60, "Lax").contains("SameSite=Lax"));
        assert_eq!(
            cookie_value("a=1; __Host-ozbox_session=zz; b=2", COOKIE),
            Some("zz")
        );
        assert_eq!(cookie_value("a=1", COOKIE), None);
    }

    #[test]
    fn idle_and_absolute_limits_and_rotation() {
        let (idle, abs) = (1000, 5000);
        let mut s = Sessions::default();
        let id = s.create(sess("a", 0), 0, idle, abs).unwrap();
        assert!(s.touch(&id, 900, idle, abs).is_some());
        assert!(s.touch(&id, 1800, idle, abs).is_some()); // kept alive
        assert!(s.touch(&id, 2900, idle, abs).is_none()); // idle
        let id = s.create(sess("a", 3000), 3000, idle, abs).unwrap();
        for t in [3900u64, 4800, 5700, 6600] {
            let _ = s.touch(&id, t, idle, abs);
        }
        assert!(s.touch(&id, 8100, idle, abs).is_none()); // absolute
                                                          // rotation: the old id stops working
        let id = s.create(sess("b", 9000), 9000, idle, abs).unwrap();
        let (key, _) = s.touch(&id, 9100, idle, abs).unwrap();
        let new = s.rotate(&key).unwrap();
        assert!(s.touch(&id, 9200, idle, abs).is_none());
        assert!(s.touch(&new, 9200, idle, abs).is_some());
        // sign out everywhere
        assert_eq!(s.remove_user("b"), 1);
        assert!(s.touch(&new, 9300, idle, abs).is_none());
    }

    #[test]
    fn ids_are_stored_hashed() {
        let k = key_of("abc");
        assert_eq!(k.len(), 64);
        assert_ne!(k, "abc");
    }
}

#[cfg(test)]
mod persistence_tests {
    use super::*;

    const IDLE: u64 = 12 * 3_600_000;
    const ABS: u64 = 7 * 24 * 3_600_000;

    fn sess(user: &str, now: u64) -> Session {
        Session {
            user: user.into(),
            level: Level::Full,
            created_ms: now,
            last_seen_ms: now,
            last_stepup_ms: None,
            csrf: "csrf-token-1".into(),
            via: "passkey",
            pending_totp: None,
        }
    }

    fn file(dir: &tempfile::TempDir) -> PathBuf {
        dir.path().join("sessions.json")
    }

    #[test]
    fn a_session_file_from_before_the_hmac_signs_nobody_out_and_is_rekeyed_on_use() {
        let dir = tempfile::tempdir().unwrap();
        let id = "legacy-cookie-id-0123456789";
        let stored = StoredFile {
            version: 1,
            sessions: vec![Stored {
                key: crate::tokenmac::legacy_key_of(id),
                user: "owner".into(),
                created_ms: 1_000,
                last_seen_ms: 1_000,
                last_stepup_ms: None,
                csrf: "csrf-token-1".into(),
                via: "passkey".into(),
            }],
        };
        std::fs::write(file(&dir), serde_json::to_string(&stored).unwrap()).unwrap();
        let mut s = Sessions::persistent(file(&dir), 2_000, IDLE, ABS);
        let (key, got) = s.touch(id, 2_000, IDLE, ABS).expect("still signed in");
        assert_eq!(got.user, "owner");
        assert_eq!(key, key_of(id), "moved to the keyed form");
        let text = std::fs::read_to_string(file(&dir)).unwrap();
        assert!(text.contains(&key_of(id)) && !text.contains(&crate::tokenmac::legacy_key_of(id)));
    }

    #[test]
    fn a_session_survives_a_restart_and_the_file_holds_no_cookie_id_and_is_private() {
        let dir = tempfile::tempdir().unwrap();
        let mut s = Sessions::persistent(file(&dir), 1_000, IDLE, ABS);
        let id = s.create(sess("owner", 1_000), 1_000, IDLE, ABS).unwrap();
        let text = std::fs::read_to_string(file(&dir)).unwrap();
        assert!(!text.contains(&id), "only the hash of the id is stored");
        assert!(text.contains(&key_of(&id)));
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(file(&dir)).unwrap().permissions().mode();
            assert_eq!(mode & 0o777, 0o600);
        }
        assert!(
            !dir.path().join("sessions.tmp").exists(),
            "the temporary file is renamed away"
        );
        drop(s);
        let mut back = Sessions::persistent(file(&dir), 2_000, IDLE, ABS);
        let (_, got) = back.touch(&id, 2_000, IDLE, ABS).expect("still signed in");
        assert_eq!(got.user, "owner");
        assert_eq!(got.csrf, "csrf-token-1");
        assert_eq!(got.level, Level::Full);
    }

    #[test]
    fn what_ended_stays_ended_after_a_restart() {
        let dir = tempfile::tempdir().unwrap();
        let mut s = Sessions::persistent(file(&dir), 0, IDLE, ABS);
        let a = s.create(sess("a", 0), 0, IDLE, ABS).unwrap();
        let b = s.create(sess("b", 0), 0, IDLE, ABS).unwrap();
        let c = s.create(sess("c", 0), 0, IDLE, ABS).unwrap();
        let (key_a, _) = s.touch(&a, 10, IDLE, ABS).unwrap();
        assert!(s.remove(&key_a));
        assert_eq!(s.remove_user("b"), 1);
        let (key_c, _) = s.touch(&c, 20, IDLE, ABS).unwrap();
        let c2 = s.rotate(&key_c).unwrap();
        let mut back = Sessions::persistent(file(&dir), 30, IDLE, ABS);
        assert!(back.touch(&a, 30, IDLE, ABS).is_none(), "revoked");
        assert!(
            back.touch(&b, 30, IDLE, ABS).is_none(),
            "signed out everywhere"
        );
        assert!(
            back.touch(&c, 30, IDLE, ABS).is_none(),
            "the rotated id is dead"
        );
        assert!(back.touch(&c2, 30, IDLE, ABS).is_some());
    }

    #[test]
    fn limits_apply_to_what_is_read_so_time_spent_stopped_counts() {
        let dir = tempfile::tempdir().unwrap();
        let mut s = Sessions::persistent(file(&dir), 0, IDLE, ABS);
        let id = s.create(sess("a", 0), 0, IDLE, ABS).unwrap();
        drop(s);
        let mut idle = Sessions::persistent(file(&dir), IDLE + 1, IDLE, ABS);
        assert!(idle.touch(&id, IDLE + 1, IDLE, ABS).is_none());
        let mut ok = Sessions::persistent(file(&dir), IDLE - 1, IDLE, ABS);
        assert!(ok.touch(&id, IDLE - 1, IDLE, ABS).is_some());
    }

    #[test]
    fn half_signed_in_people_and_pending_authenticator_secrets_are_never_written() {
        let dir = tempfile::tempdir().unwrap();
        let mut s = Sessions::persistent(file(&dir), 0, IDLE, ABS);
        let mut half = sess("half", 0);
        half.level = Level::NeedsSecondFactor;
        let half_id = s.create(half, 0, IDLE, ABS).unwrap();
        let mut full = sess("full", 0);
        full.pending_totp = Some("SECRETSECRETSECRET".into());
        let full_id = s.create(full, 0, IDLE, ABS).unwrap();
        let text = std::fs::read_to_string(file(&dir)).unwrap();
        assert!(!text.contains("SECRETSECRETSECRET"));
        let mut back = Sessions::persistent(file(&dir), 1, IDLE, ABS);
        assert!(back.touch(&half_id, 1, IDLE, ABS).is_none());
        let (_, got) = back.touch(&full_id, 1, IDLE, ABS).unwrap();
        assert_eq!(got.pending_totp, None);
    }

    #[test]
    fn a_damaged_or_hostile_file_is_an_empty_one() {
        let dir = tempfile::tempdir().unwrap();
        for bad in [
            "not json",
            "",
            "{\"version\":1,\"sessions\":[{\"key\":\"short\",\"user\":\"x\",\"created_ms\":0,\"last_seen_ms\":0,\"csrf\":\"c\",\"via\":\"passkey\"}]}",
            "{\"version\":1,\"sessions\":[{\"key\":\"../../etc\",\"user\":\"\",\"created_ms\":0,\"last_seen_ms\":0,\"csrf\":\"c\",\"via\":\"x\"}]}",
        ] {
            std::fs::write(file(&dir), bad).unwrap();
            let mut s = Sessions::persistent(file(&dir), 1, IDLE, ABS);
            assert!(s.touch("anything", 1, IDLE, ABS).is_none(), "{bad}");
            assert!(s.of_user("x").is_empty());
        }
        // an unknown sign-in method is shown as restored, never as something it was not
        assert_eq!(via_static("nope"), "restored");
        assert_eq!(via_static("github"), "github");
    }

    #[test]
    fn last_seen_is_written_at_most_every_few_seconds() {
        let dir = tempfile::tempdir().unwrap();
        let mut s = Sessions::persistent(file(&dir), 0, IDLE, ABS);
        let id = s.create(sess("a", 0), 0, IDLE, ABS).unwrap();
        let before = std::fs::read_to_string(file(&dir)).unwrap();
        s.touch(&id, 1_000, IDLE, ABS).unwrap();
        assert_eq!(
            std::fs::read_to_string(file(&dir)).unwrap(),
            before,
            "not yet"
        );
        s.touch(&id, FLUSH_EVERY_MS + 1_000, IDLE, ABS).unwrap();
        let after = std::fs::read_to_string(file(&dir)).unwrap();
        assert_ne!(after, before);
        assert!(after.contains(&format!("\"last_seen_ms\":{}", FLUSH_EVERY_MS + 1_000)));
    }

    #[test]
    fn without_a_file_nothing_is_written_anywhere() {
        let mut s = Sessions::default();
        let id = s.create(sess("a", 0), 0, IDLE, ABS).unwrap();
        assert!(s.touch(&id, 1, IDLE, ABS).is_some());
    }
}
