//! The one authenticated control path between the tool host and a session's worker (ADR 0037, amended 2026-11-11).
//!
//! The tool host makes a fresh 32-byte key for each session and hands it to the worker on the first line of its standard input,
//! the only line that is not sealed. Every line after that, in both directions, is sealed with ChaCha20-Poly1305 under a key
//! derived for that direction, bound to the session id, and numbered: a line that does not open, belongs to another session,
//! or repeats or goes back in the numbering is refused. So writing to the worker's input does not drive it, and reading its
//! output (the run's log on the box) shows neither a frame, a snapshot nor extracted data.
//!
//! An approval is a third, separate thing: a [`Grant`] says which approval request a person decided, for exactly which action
//! and which state of the page. It is a MAC under a key of its own that only the host's approvals path uses, so "the engine
//! allowed" can never be written as "a person approved".
//!
//! What this does not stop, until each run has its own Unix user: a process that already runs as the box user can read the
//! worker's memory or race it for the first line, and can read the browser profile on disk. See the ADR.

use ring::aead::{Aad, LessSafeKey, Nonce, UnboundKey, CHACHA20_POLY1305};
use ring::hmac;
use ring::rand::{SecureRandom, SystemRandom};
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use zeroize::Zeroize;

use crate::b64;

const KEY_LEN: usize = 32;

/// The session's secret. Never printed: `Debug` shows that it is there, not what it is.
#[derive(Clone, PartialEq, Eq)]
pub struct SessionKey([u8; KEY_LEN]);

impl SessionKey {
    pub fn generate() -> Result<Self, String> {
        let mut k = [0u8; KEY_LEN];
        SystemRandom::new()
            .fill(&mut k)
            .map_err(|_| "no random numbers are available on this computer".to_string())?;
        Ok(Self(k))
    }

    fn derive(&self, label: &str) -> [u8; KEY_LEN] {
        let tag = hmac::sign(
            &hmac::Key::new(hmac::HMAC_SHA256, &self.0),
            label.as_bytes(),
        );
        let mut out = [0u8; KEY_LEN];
        out.copy_from_slice(&tag.as_ref()[..KEY_LEN]);
        out
    }
}

impl Drop for SessionKey {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

impl std::fmt::Debug for SessionKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("SessionKey(..)")
    }
}

impl Serialize for SessionKey {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&b64::encode(&self.0))
    }
}

impl<'de> Deserialize<'de> for SessionKey {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let mut text = String::deserialize(d)?;
        let mut bytes = b64::decode(text.trim()).map_err(serde::de::Error::custom)?;
        text.zeroize();
        if bytes.len() != KEY_LEN || bytes.iter().all(|b| *b == 0) {
            bytes.zeroize();
            return Err(serde::de::Error::custom("the session key is not a key"));
        }
        let mut k = [0u8; KEY_LEN];
        k.copy_from_slice(&bytes);
        bytes.zeroize();
        Ok(Self(k))
    }
}

/// Which way a line travels. Each direction has its own key and its own numbering, so a reply can never be fed back in as
/// a request.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Dir {
    ToWorker,
    ToHost,
}

impl Dir {
    fn label(self) -> &'static str {
        match self {
            Dir::ToWorker => "ozbox-browser/v1/to-worker",
            Dir::ToHost => "ozbox-browser/v1/to-host",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ChannelError {
    /// Not a sealed line at all.
    Malformed,
    /// It does not open with this session's key: forged, damaged, or for another session.
    Forged,
    /// Its number is not after the last one: a line played again.
    Replayed,
}

impl ChannelError {
    pub fn sentence(&self) -> &'static str {
        match self {
            ChannelError::Malformed => "that line is not a sealed request",
            ChannelError::Forged => "that line was not sealed by this session's tool host",
            ChannelError::Replayed => "that line was already used",
        }
    }
}

/// A sealed line as it travels: its number, the request or reply id (in the clear, for routing only), and the sealed bytes.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Envelope {
    pub seq: u64,
    #[serde(default)]
    pub id: u64,
    #[serde(rename = "box")]
    pub sealed: String,
}

struct Half {
    key: LessSafeKey,
    dir: Dir,
    aad: Vec<u8>,
}

impl Half {
    fn new(k: &SessionKey, dir: Dir, session: &str) -> Result<Self, String> {
        let mut raw = k.derive(dir.label());
        let unbound = UnboundKey::new(&CHACHA20_POLY1305, &raw);
        raw.zeroize();
        let key = LessSafeKey::new(unbound.map_err(|_| "the session key could not be used")?);
        Ok(Self {
            key,
            dir,
            aad: format!("{}\0{}", dir.label(), session).into_bytes(),
        })
    }

    fn nonce(&self, seq: u64) -> Nonce {
        let mut n = [0u8; 12];
        n[0] = match self.dir {
            Dir::ToWorker => 1,
            Dir::ToHost => 2,
        };
        n[4..].copy_from_slice(&seq.to_be_bytes());
        Nonce::assume_unique_for_key(n)
    }
}

/// One end of a session's channel: it seals what it sends and opens what it receives.
pub struct Channel {
    send: Half,
    recv: Half,
    grant: hmac::Key,
    session: String,
    next_out: u64,
    last_in: u64,
}

impl Channel {
    /// The tool host's end.
    pub fn host(k: &SessionKey, session: &str) -> Result<Self, String> {
        Self::make(k, session, Dir::ToWorker, Dir::ToHost)
    }

    /// The worker's end.
    pub fn worker(k: &SessionKey, session: &str) -> Result<Self, String> {
        Self::make(k, session, Dir::ToHost, Dir::ToWorker)
    }

    fn make(k: &SessionKey, session: &str, send: Dir, recv: Dir) -> Result<Self, String> {
        let mut g = k.derive("ozbox-browser/v1/grant");
        let grant = hmac::Key::new(hmac::HMAC_SHA256, &g);
        g.zeroize();
        Ok(Self {
            send: Half::new(k, send, session)?,
            recv: Half::new(k, recv, session)?,
            grant,
            session: session.to_string(),
            next_out: 0,
            last_in: 0,
        })
    }

    /// Seal one message into a line (no newline). `id` travels in the clear so the other end can route the reply.
    pub fn seal(&mut self, id: u64, plain: &[u8]) -> String {
        self.next_out += 1;
        let seq = self.next_out;
        let mut buf = plain.to_vec();
        let ok = self.send.key.seal_in_place_append_tag(
            self.send.nonce(seq),
            Aad::from(self.send.aad.as_slice()),
            &mut buf,
        );
        let sealed = if ok.is_ok() {
            b64::encode(&buf)
        } else {
            String::new()
        };
        buf.zeroize();
        serde_json::to_string(&Envelope { seq, id, sealed }).unwrap_or_default()
    }

    /// Open one line. Its number must come after the last one opened.
    pub fn open(&mut self, line: &str) -> Result<(u64, Vec<u8>), ChannelError> {
        let env: Envelope =
            serde_json::from_str(line.trim()).map_err(|_| ChannelError::Malformed)?;
        if env.seq == 0 {
            return Err(ChannelError::Malformed);
        }
        let mut buf = b64::decode(&env.sealed).map_err(|_| ChannelError::Malformed)?;
        let plain = self
            .recv
            .key
            .open_in_place(
                self.recv.nonce(env.seq),
                Aad::from(self.recv.aad.as_slice()),
                &mut buf,
            )
            .map_err(|_| ChannelError::Forged)?
            .to_vec();
        buf.zeroize();
        // checked after it opens, so a forged line cannot move the counter
        if env.seq <= self.last_in {
            return Err(ChannelError::Replayed);
        }
        self.last_in = env.seq;
        Ok((env.id, plain))
    }

    fn grant_message(approval: &str, fingerprint: &str, risk: &str, action: &[u8]) -> Vec<u8> {
        let mut m = b"ozbox-browser/v1/grant\0".to_vec();
        for part in [approval.as_bytes(), fingerprint.as_bytes(), risk.as_bytes()] {
            m.extend_from_slice(part);
            m.push(0);
        }
        m.extend_from_slice(action);
        m
    }

    /// Mint the proof that a person approved this approval request for this action on this state of the page. Only the
    /// host's approvals path calls it, and only with the id of a request a person decided.
    pub fn grant(&self, approval: &str, fingerprint: &str, risk: &str, action: &[u8]) -> String {
        let mut m = Self::grant_message(approval, fingerprint, risk, action);
        m.extend_from_slice(self.session.as_bytes());
        b64::encode(hmac::sign(&self.grant, &m).as_ref())
    }

    /// Check a grant in constant time.
    pub fn grant_ok(
        &self,
        approval: &str,
        fingerprint: &str,
        risk: &str,
        action: &[u8],
        mac: &str,
    ) -> bool {
        let Ok(tag) = b64::decode(mac) else {
            return false;
        };
        let mut m = Self::grant_message(approval, fingerprint, risk, action);
        m.extend_from_slice(self.session.as_bytes());
        hmac::verify(&self.grant, &m, &tag).is_ok()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_line_opens_only_at_the_other_end_of_the_same_session_and_only_once() {
        let k = SessionKey::generate().unwrap();
        let mut host = Channel::host(&k, "b1").unwrap();
        let mut worker = Channel::worker(&k, "b1").unwrap();
        let line = host.seal(7, b"{\"id\":7}");
        assert!(!line.contains("\"id\":7}"), "{line}");
        assert_eq!(worker.open(&line).unwrap(), (7, b"{\"id\":7}".to_vec()));
        // played again: refused
        assert_eq!(worker.open(&line), Err(ChannelError::Replayed));
        // a reply cannot be fed back in as a request
        let reply = worker.seal(7, b"ok");
        assert_eq!(worker.open(&reply), Err(ChannelError::Forged));
        assert_eq!(host.open(&reply).unwrap().1, b"ok".to_vec());
        // another session's key, or another session id with the same key, does not open it
        let other = SessionKey::generate().unwrap();
        let mut stranger = Channel::host(&other, "b1").unwrap();
        assert_eq!(
            worker.open(&stranger.seal(8, b"x")),
            Err(ChannelError::Forged)
        );
        let mut moved = Channel::host(&k, "b2").unwrap();
        let mut fresh = Channel::worker(&k, "b1").unwrap();
        assert_eq!(fresh.open(&moved.seal(1, b"x")), Err(ChannelError::Forged));
        // a hand-written line is not a request
        assert_eq!(
            worker.open(r#"{"id":9,"op":"act","approved":true}"#),
            Err(ChannelError::Malformed)
        );
    }

    #[test]
    fn a_forged_line_does_not_move_the_counter() {
        let k = SessionKey::generate().unwrap();
        let mut host = Channel::host(&k, "b1").unwrap();
        let mut worker = Channel::worker(&k, "b1").unwrap();
        let forged = serde_json::to_string(&Envelope {
            seq: 99,
            id: 1,
            sealed: b64::encode(b"nonsense-but-long-enough-to-hold-a-tag"),
        })
        .unwrap();
        assert_eq!(worker.open(&forged), Err(ChannelError::Forged));
        assert!(worker.open(&host.seal(1, b"real")).is_ok());
    }

    #[test]
    fn a_grant_binds_the_approval_the_action_and_the_page() {
        let k = SessionKey::generate().unwrap();
        let host = Channel::host(&k, "b1").unwrap();
        let worker = Channel::worker(&k, "b1").unwrap();
        let g = host.grant("a3", "fp1", "submit", b"{\"action\":\"click\"}");
        assert!(worker.grant_ok("a3", "fp1", "submit", b"{\"action\":\"click\"}", &g));
        assert!(!worker.grant_ok("a4", "fp1", "submit", b"{\"action\":\"click\"}", &g));
        assert!(!worker.grant_ok("a3", "fp2", "submit", b"{\"action\":\"click\"}", &g));
        assert!(!worker.grant_ok("a3", "fp1", "send", b"{\"action\":\"click\"}", &g));
        assert!(!worker.grant_ok("a3", "fp1", "submit", b"{\"action\":\"press\"}", &g));
        assert!(!worker.grant_ok("a3", "fp1", "submit", b"{\"action\":\"click\"}", "AAAA"));
        let other = Channel::worker(&k, "b2").unwrap();
        assert!(!other.grant_ok("a3", "fp1", "submit", b"{\"action\":\"click\"}", &g));
    }

    #[test]
    fn the_key_is_never_printed_and_a_bad_key_is_refused() {
        let k = SessionKey::generate().unwrap();
        let text = serde_json::to_string(&k).unwrap();
        assert!(!format!("{k:?}").contains(text.trim_matches('"')));
        let back: SessionKey = serde_json::from_str(&text).unwrap();
        assert_eq!(back, k);
        assert!(serde_json::from_str::<SessionKey>("\"AAAA\"").is_err());
        assert!(
            serde_json::from_str::<SessionKey>(&format!("\"{}\"", b64::encode(&[0u8; 32])))
                .is_err()
        );
    }
}
