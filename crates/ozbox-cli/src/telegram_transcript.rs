//! The sealed per-link transcript of what was said to the Telegram bridge and what it answered (ADR 0050 §9).
//!
//! Telegram's copy of a conversation is not the record: a person can delete a chat for both sides, a bot can delete only its
//! own messages, and the vendor holds the rest. The record is this file, kept by the dashboard server in its own state
//! directory (mode 0600, owned by the account that runs it, which on a box is not the box user). Every line is encrypted
//! (AES-256-GCM, a fresh nonce each, the link and the time bound as associated data) under a key that lives in the secret
//! store, never beside the file, so a copy of the file reads as nothing.
//!
//! * The owner reads it in the dashboard; nothing sends it anywhere.
//! * It is kept for **30 days** and pruned when it is written to.
//! * The audit chain holds an **HMAC** of each message (the first characters of it), never the text and never a bare digest,
//!   so a short message cannot be guessed by enumeration and a person can still check a line against the chain.

use std::io::Write;
use std::path::PathBuf;
use std::sync::Mutex;

use ring::aead::{Aad, LessSafeKey, Nonce, UnboundKey, AES_256_GCM};
use ring::hmac;
use serde::{Deserialize, Serialize};

use crate::secrets::SecretStore;
use crate::serve::auth::b64::{decode_url, encode_url};

/// The secret holding the transcript key.
pub const KEY_SECRET: &str = "telegram-transcript-key";
/// How long a line is kept.
pub const RETENTION_MS: u64 = 30 * 24 * 3_600_000;
/// The longest text kept for one line.
pub const MAX_TEXT: usize = 4_000;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Dir {
    /// What the person sent.
    In,
    /// What the bot answered.
    Out,
}

impl Dir {
    fn word(self) -> &'static str {
        match self {
            Dir::In => "in",
            Dir::Out => "out",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct Stored {
    link: String,
    ts: u64,
    dir: Dir,
    /// HMAC-SHA256 of the message, hex: the same value the audit chain carries a prefix of.
    mac: String,
    /// base64url(nonce || ciphertext).
    ct: String,
}

/// One line, read back.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Line {
    pub link_id: String,
    pub ts_ms: u64,
    pub dir: Dir,
    pub text: String,
    pub mac: String,
}

pub struct Transcript {
    path: Option<PathBuf>,
    seal: LessSafeKey,
    mac: hmac::Key,
    lines: Mutex<Vec<Stored>>,
}

fn aad(link: &str, ts: u64, dir: Dir) -> Vec<u8> {
    format!("ozbox-telegram-transcript-v1|{link}|{ts}|{}", dir.word()).into_bytes()
}

fn rand_bytes<const N: usize>() -> Result<[u8; N], String> {
    let mut b = [0u8; N];
    getrandom::getrandom(&mut b).map_err(|_| "no random numbers are available".to_string())?;
    Ok(b)
}

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

impl Transcript {
    /// Open (or start) the transcript. The key is read from the secret store and made there the first time; a store that
    /// cannot hold one means no transcript, which the caller treats as "the bridge does not act" (nothing is done that
    /// cannot be recorded).
    pub fn open(
        path: Option<PathBuf>,
        secrets: &dyn SecretStore,
        now_ms: u64,
    ) -> Result<Self, String> {
        let key_hex = match secrets.get(KEY_SECRET).map_err(|e| e.0)? {
            Some(k) if k.len() == 64 => k,
            _ => {
                let k = hex(&rand_bytes::<32>()?);
                secrets.set(KEY_SECRET, &k).map_err(|e| e.0)?;
                k
            }
        };
        let raw = ozbox_core::approval_subject::from_hex(&key_hex)
            .filter(|r| r.len() == 32)
            .ok_or("the transcript key is not valid")?;
        let unbound =
            UnboundKey::new(&AES_256_GCM, &raw).map_err(|_| "the transcript key is not valid")?;
        let mac_seed = ring::digest::digest(
            &ring::digest::SHA256,
            &[b"ozbox-telegram-transcript-mac-v1".as_slice(), &raw].concat(),
        );
        let t = Transcript {
            path,
            seal: LessSafeKey::new(unbound),
            mac: hmac::Key::new(hmac::HMAC_SHA256, mac_seed.as_ref()),
            lines: Mutex::new(Vec::new()),
        };
        if let Some(p) = &t.path {
            if let Ok(text) = std::fs::read_to_string(p) {
                let mut v: Vec<Stored> = text
                    .lines()
                    .filter_map(|l| serde_json::from_str(l).ok())
                    .collect();
                v.retain(|s| now_ms.saturating_sub(s.ts) <= RETENTION_MS);
                if let Ok(mut g) = t.lines.lock() {
                    *g = v;
                }
            }
        }
        Ok(t)
    }

    /// The HMAC of a message, hex.
    pub fn mac_of(&self, link_id: &str, dir: Dir, text: &str) -> String {
        let mut msg = format!("{link_id}\u{0}{}\u{0}", dir.word()).into_bytes();
        msg.extend_from_slice(text.as_bytes());
        hex(hmac::sign(&self.mac, &msg).as_ref())
    }

    /// Add a line. Returns its HMAC, or an error when it could not be written: the caller then does not act.
    pub fn append(
        &self,
        link_id: &str,
        ts_ms: u64,
        dir: Dir,
        text: &str,
    ) -> Result<String, String> {
        let text: String = text.chars().take(MAX_TEXT).collect();
        let mac = self.mac_of(link_id, dir, &text);
        let nonce_bytes = rand_bytes::<12>()?;
        let mut buf = text.into_bytes();
        self.seal
            .seal_in_place_append_tag(
                Nonce::assume_unique_for_key(nonce_bytes),
                Aad::from(aad(link_id, ts_ms, dir)),
                &mut buf,
            )
            .map_err(|_| "the transcript could not be sealed".to_string())?;
        let mut blob = nonce_bytes.to_vec();
        blob.extend_from_slice(&buf);
        let line = Stored {
            link: link_id.to_string(),
            ts: ts_ms,
            dir,
            mac: mac.clone(),
            ct: encode_url(&blob),
        };
        let encoded =
            serde_json::to_string(&line).map_err(|_| "the transcript could not be written")?;
        let mut guard = self.lines.lock().map_err(|_| "the transcript is busy")?;
        if let Some(p) = &self.path {
            if let Some(dir) = p.parent() {
                let _ = std::fs::create_dir_all(dir);
            }
            let mut opts = std::fs::OpenOptions::new();
            opts.create(true).append(true);
            #[cfg(unix)]
            {
                use std::os::unix::fs::OpenOptionsExt;
                opts.mode(0o600);
            }
            let mut f = opts
                .open(p)
                .map_err(|_| "the transcript could not be written")?;
            writeln!(f, "{encoded}").map_err(|_| "the transcript could not be written")?;
            f.sync_data()
                .map_err(|_| "the transcript could not be written")?;
        }
        guard.push(line);
        // forget what is past its time: in memory now, and in the file at the next start
        if guard
            .first()
            .is_some_and(|f| ts_ms.saturating_sub(f.ts) > RETENTION_MS)
        {
            guard.retain(|s| ts_ms.saturating_sub(s.ts) <= RETENTION_MS);
            if let Some(p) = &self.path {
                let body: String = guard
                    .iter()
                    .filter_map(|s| serde_json::to_string(s).ok())
                    .map(|l| l + "\n")
                    .collect();
                let tmp = p.with_extension("tmp");
                if std::fs::write(&tmp, body).is_ok() {
                    #[cfg(unix)]
                    {
                        use std::os::unix::fs::PermissionsExt;
                        let _ =
                            std::fs::set_permissions(&tmp, std::fs::Permissions::from_mode(0o600));
                    }
                    let _ = std::fs::rename(&tmp, p);
                }
            }
        }
        Ok(mac)
    }

    /// The lines of one link, oldest first. A line that does not open (changed, or made under another key) is left out.
    pub fn read(&self, link_id: &str, now_ms: u64) -> Vec<Line> {
        let Ok(g) = self.lines.lock() else {
            return Vec::new();
        };
        g.iter()
            .filter(|s| s.link == link_id && now_ms.saturating_sub(s.ts) <= RETENTION_MS)
            .filter_map(|s| {
                let mut blob = decode_url(&s.ct)?;
                if blob.len() < 12 + 16 {
                    return None;
                }
                let ct = blob.split_off(12);
                let nonce: [u8; 12] = blob.try_into().ok()?;
                let mut ct = ct;
                let plain = self
                    .seal
                    .open_in_place(
                        Nonce::assume_unique_for_key(nonce),
                        Aad::from(aad(&s.link, s.ts, s.dir)),
                        &mut ct,
                    )
                    .ok()?;
                Some(Line {
                    link_id: s.link.clone(),
                    ts_ms: s.ts,
                    dir: s.dir,
                    text: String::from_utf8_lossy(plain).into_owned(),
                    mac: s.mac.clone(),
                })
            })
            .collect()
    }

    /// How many lines are kept, all links together.
    #[cfg(test)]
    pub fn len(&self) -> usize {
        self.lines.lock().map(|g| g.len()).unwrap_or(0)
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use crate::secrets::MemorySecrets;

    const T0: u64 = 100 * 24 * 3_600_000;

    #[test]
    fn a_line_round_trips_and_the_file_holds_no_text() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("t.jsonl");
        let secrets = MemorySecrets::default();
        let t = Transcript::open(Some(path.clone()), &secrets, T0).unwrap();
        let mac = t
            .append("l1", T0, Dir::In, "please fix the sentinel-phrase parser")
            .unwrap();
        t.append("l1", T0 + 1, Dir::Out, "Sent to t1.").unwrap();
        t.append("l2", T0 + 2, Dir::In, "another link").unwrap();
        let lines = t.read("l1", T0 + 10);
        assert_eq!(lines.len(), 2);
        assert_eq!(lines[0].text, "please fix the sentinel-phrase parser");
        assert_eq!(lines[0].mac, mac);
        assert_eq!(t.read("l2", T0 + 10).len(), 1);
        let file = std::fs::read_to_string(&path).unwrap();
        assert!(
            !file.contains("sentinel-phrase") && !file.contains("Sent to"),
            "sealed"
        );
        assert!(
            file.contains(&mac),
            "the mac is how a line is checked against the chain"
        );
        // a reopened transcript reads the same, under the same key
        let again = Transcript::open(Some(path), &secrets, T0 + 20).unwrap();
        assert_eq!(again.read("l1", T0 + 20).len(), 2);
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let p = dir.path().join("t.jsonl");
            assert_eq!(
                std::fs::metadata(p).unwrap().permissions().mode() & 0o777,
                0o600
            );
        }
    }

    #[test]
    fn another_key_reads_nothing_and_a_changed_line_is_left_out() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("t.jsonl");
        let t = Transcript::open(Some(path.clone()), &MemorySecrets::default(), T0).unwrap();
        t.append("l1", T0, Dir::In, "hello").unwrap();
        let other = Transcript::open(Some(path.clone()), &MemorySecrets::default(), T0).unwrap();
        assert!(other.read("l1", T0).is_empty(), "made under another key");
        // a line moved to another time or link no longer opens: both are bound into it
        let text = std::fs::read_to_string(&path).unwrap();
        std::fs::write(&path, text.replace("\"link\":\"l1\"", "\"link\":\"l9\"")).unwrap();
        let moved = Transcript::open(Some(path), &MemorySecrets::default(), T0).unwrap();
        assert!(moved.read("l9", T0).is_empty());
    }

    #[test]
    fn a_mac_is_keyed_and_differs_by_link_direction_and_text() {
        let t = Transcript::open(None, &MemorySecrets::default(), T0).unwrap();
        let a = t.mac_of("l1", Dir::In, "yes");
        assert_eq!(a, t.mac_of("l1", Dir::In, "yes"));
        assert_ne!(a, t.mac_of("l1", Dir::In, "no"));
        assert_ne!(a, t.mac_of("l2", Dir::In, "yes"));
        assert_ne!(a, t.mac_of("l1", Dir::Out, "yes"));
        let other = Transcript::open(None, &MemorySecrets::default(), T0).unwrap();
        assert_ne!(
            a,
            other.mac_of("l1", Dir::In, "yes"),
            "another key: a short message cannot be guessed without it"
        );
    }

    #[test]
    fn lines_older_than_thirty_days_are_forgotten() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("t.jsonl");
        let secrets = MemorySecrets::default();
        let t = Transcript::open(Some(path.clone()), &secrets, T0).unwrap();
        t.append("l1", T0, Dir::In, "old").unwrap();
        let later = T0 + RETENTION_MS + 1;
        t.append("l1", later, Dir::In, "new").unwrap();
        let lines = t.read("l1", later);
        assert_eq!(lines.len(), 1);
        assert_eq!(lines[0].text, "new");
        let reopened = Transcript::open(Some(path), &secrets, later).unwrap();
        assert_eq!(reopened.len(), 1, "gone from the file as well");
    }
}
