//! Expiring download tokens. A token is `<id>.<expires_s>.<hmac>`: the HMAC-SHA256 covers the id and the expiry, and the
//! registry (a small JSON file) holds what the id stands for. A token is valid only while its id is in the registry, so
//! revoking is deleting the entry. The path never appears in a link.

use std::path::{Path, PathBuf};

use ring::{hmac, rand::SecureRandom};
use serde::{Deserialize, Serialize};

pub const MAX_TTL_S: u64 = 24 * 3600;
pub const MIN_TTL_S: u64 = 10;
pub const MAX_ACTIVE: usize = 200;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TokenRec {
    pub id: String,
    pub created_ms: u64,
    pub expires_ms: u64,
    /// `file` or `zip`.
    pub kind: String,
    /// Paths as callers name them.
    pub paths: Vec<String>,
    /// Show it in the browser instead of saving it (images and PDFs only).
    pub inline: bool,
    /// A name for the list: the file name, or the first name and a count. Never contents.
    pub label: String,
}

#[derive(Debug, Default, Serialize, Deserialize)]
struct Registry {
    tokens: Vec<TokenRec>,
}

pub struct TokenStore {
    key: hmac::Key,
    path: PathBuf,
    reg: Registry,
}

pub fn random_hex(bytes: usize) -> String {
    let mut b = vec![0u8; bytes];
    if ring::rand::SystemRandom::new().fill(&mut b).is_err() {
        // Never fall back to something guessable: an all-zero id would be refused as a duplicate.
        b.iter_mut().for_each(|x| *x = 0);
    }
    hex(&b)
}

pub fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

fn unhex(s: &str) -> Option<Vec<u8>> {
    if !s.len().is_multiple_of(2) {
        return None;
    }
    (0..s.len() / 2)
        .map(|i| u8::from_str_radix(s.get(2 * i..2 * i + 2)?, 16).ok())
        .collect()
}

fn write_private(path: &Path, data: &[u8]) -> std::io::Result<()> {
    use std::io::Write;
    let tmp = path.with_extension("tmp");
    let mut opts = std::fs::OpenOptions::new();
    opts.create(true).write(true).truncate(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o600);
    }
    let mut f = opts.open(&tmp)?;
    f.write_all(data)?;
    f.sync_all()?;
    std::fs::rename(tmp, path)
}

impl TokenStore {
    /// Open (creating the key on first use) in `dir`.
    pub fn open(dir: &Path) -> std::io::Result<Self> {
        std::fs::create_dir_all(dir)?;
        let key_path = dir.join("token.key");
        let secret = match std::fs::read(&key_path) {
            Ok(k) if k.len() == 32 => k,
            _ => {
                let mut k = vec![0u8; 32];
                ring::rand::SystemRandom::new()
                    .fill(&mut k)
                    .map_err(|_| std::io::Error::other("no random source"))?;
                write_private(&key_path, &k)?;
                k
            }
        };
        let path = dir.join("tokens.json");
        let reg = std::fs::read(&path)
            .ok()
            .and_then(|b| serde_json::from_slice(&b).ok())
            .unwrap_or_default();
        Ok(Self {
            key: hmac::Key::new(hmac::HMAC_SHA256, &secret),
            path,
            reg,
        })
    }

    fn save(&self) {
        if let Ok(b) = serde_json::to_vec(&self.reg) {
            let _ = write_private(&self.path, &b);
        }
    }

    fn sign(&self, id: &str, exp_s: u64) -> String {
        hex(hmac::sign(&self.key, format!("{id}.{exp_s}").as_bytes()).as_ref())
    }

    /// Drop what has expired.
    pub fn sweep(&mut self, now_ms: u64) {
        let before = self.reg.tokens.len();
        self.reg.tokens.retain(|t| t.expires_ms > now_ms);
        if self.reg.tokens.len() != before {
            self.save();
        }
    }

    pub fn create(
        &mut self,
        now_ms: u64,
        ttl_s: u64,
        kind: &str,
        paths: Vec<String>,
        inline: bool,
        label: String,
    ) -> Result<(TokenRec, String), &'static str> {
        self.sweep(now_ms);
        if !(MIN_TTL_S..=MAX_TTL_S).contains(&ttl_s) {
            return Err("ttl");
        }
        if self.reg.tokens.len() >= MAX_ACTIVE {
            return Err("too_many");
        }
        let rec = TokenRec {
            id: random_hex(12),
            created_ms: now_ms,
            expires_ms: now_ms + ttl_s * 1000,
            kind: kind.to_string(),
            paths,
            inline,
            label,
        };
        let token = format!(
            "{}.{}.{}",
            rec.id,
            rec.expires_ms / 1000,
            self.sign(&rec.id, rec.expires_ms / 1000)
        );
        self.reg.tokens.push(rec.clone());
        self.save();
        Ok((rec, token))
    }

    /// The record a valid, unexpired, unrevoked token stands for.
    pub fn verify(&mut self, token: &str, now_ms: u64) -> Option<TokenRec> {
        let mut it = token.split('.');
        let (id, exp, sig) = (it.next()?, it.next()?, it.next()?);
        if it.next().is_some() || id.len() != 24 || !id.bytes().all(|b| b.is_ascii_hexdigit()) {
            return None;
        }
        let exp_s: u64 = exp.parse().ok()?;
        let sig = unhex(sig)?;
        hmac::verify(&self.key, format!("{id}.{exp_s}").as_bytes(), &sig).ok()?;
        if exp_s * 1000 <= now_ms {
            return None;
        }
        self.reg
            .tokens
            .iter()
            .find(|t| t.id == id && t.expires_ms > now_ms)
            .cloned()
    }

    pub fn revoke(&mut self, id: &str) -> bool {
        let before = self.reg.tokens.len();
        self.reg.tokens.retain(|t| t.id != id);
        let changed = self.reg.tokens.len() != before;
        if changed {
            self.save();
        }
        changed
    }

    pub fn list(&mut self, now_ms: u64) -> Vec<TokenRec> {
        self.sweep(now_ms);
        self.reg.tokens.clone()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn store() -> (tempfile::TempDir, TokenStore) {
        let d = tempfile::tempdir().unwrap();
        let s = TokenStore::open(d.path()).unwrap();
        (d, s)
    }

    fn make(s: &mut TokenStore, now: u64, ttl: u64) -> (TokenRec, String) {
        s.create(
            now,
            ttl,
            "file",
            vec!["/work/a.txt".into()],
            false,
            "a.txt".into(),
        )
        .unwrap()
    }

    #[test]
    fn a_token_works_until_it_expires() {
        let (_d, mut s) = store();
        let (rec, tok) = make(&mut s, 1_000_000, 60);
        assert_eq!(s.verify(&tok, 1_000_000).unwrap().id, rec.id);
        assert!(s.verify(&tok, 1_000_000 + 59_000).is_some());
        assert!(s.verify(&tok, 1_000_000 + 60_000).is_none());
    }

    #[test]
    fn ttl_is_between_ten_seconds_and_a_day() {
        let (_d, mut s) = store();
        for ttl in [0, 9, MAX_TTL_S + 1] {
            assert_eq!(
                s.create(0, ttl, "file", vec![], false, String::new())
                    .unwrap_err(),
                "ttl"
            );
        }
        assert!(s
            .create(0, MAX_TTL_S, "file", vec![], false, String::new())
            .is_ok());
    }

    #[test]
    fn revoking_ends_a_token_at_once_and_survives_a_restart() {
        let (d, mut s) = store();
        let (rec, tok) = make(&mut s, 0, 600);
        let (_, other) = make(&mut s, 0, 600);
        assert!(s.revoke(&rec.id));
        assert!(!s.revoke(&rec.id));
        assert!(s.verify(&tok, 1).is_none());
        assert!(s.verify(&other, 1).is_some());
        let mut again = TokenStore::open(d.path()).unwrap();
        assert!(again.verify(&tok, 1).is_none());
        assert!(
            again.verify(&other, 1).is_some(),
            "the key and registry persist"
        );
    }

    #[test]
    fn forged_or_altered_tokens_are_refused() {
        let (_d, mut s) = store();
        let (rec, tok) = make(&mut s, 0, 600);
        let parts: Vec<&str> = tok.split('.').collect();
        // Longer expiry with the old signature.
        assert!(s
            .verify(&format!("{}.{}.{}", parts[0], 99_999_999, parts[2]), 1)
            .is_none());
        // Someone else's signature.
        let (_, other) = make(&mut s, 0, 600);
        let osig = other.split('.').nth(2).unwrap();
        assert!(s
            .verify(&format!("{}.{}.{}", parts[0], parts[1], osig), 1)
            .is_none());
        for junk in [
            "",
            "a.b.c",
            "..",
            &format!("{}.x.{}", rec.id, parts[2]),
            &format!("{tok}.extra"),
        ] {
            assert!(s.verify(junk, 1).is_none(), "{junk}");
        }
        // A different key (another box) refuses it.
        let (_d2, mut s2) = store();
        assert!(s2.verify(&tok, 1).is_none());
    }

    #[test]
    fn the_key_file_is_private_and_the_registry_holds_no_secret() {
        let (d, mut s) = store();
        let (_, tok) = make(&mut s, 0, 600);
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(d.path().join("token.key"))
                .unwrap()
                .permissions()
                .mode();
            assert_eq!(mode & 0o077, 0);
        }
        let reg = std::fs::read_to_string(d.path().join("tokens.json")).unwrap();
        let sig = tok.split('.').nth(2).unwrap();
        assert!(
            !reg.contains(sig),
            "only the id is stored, never the signature"
        );
    }

    #[test]
    fn expired_entries_are_swept_and_the_registry_is_capped() {
        let (_d, mut s) = store();
        make(&mut s, 0, 10);
        assert_eq!(s.list(5_000).len(), 1);
        assert!(s.list(11_000).is_empty());
        for _ in 0..MAX_ACTIVE {
            make(&mut s, 100_000, 600);
        }
        assert_eq!(
            s.create(100_000, 60, "file", vec![], false, String::new())
                .unwrap_err(),
            "too_many"
        );
    }
}
