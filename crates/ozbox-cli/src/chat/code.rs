//! The one-time pairing code Slack and WhatsApp use: the dashboard makes it, the person sends it to the app, and the first
//! chat that sends the right one before it lapses is linked.
//!
//! Telegram does not use this. A code that the dashboard makes and the chat sends means whoever sends it first is bound, so
//! Telegram pairs the other way round (ADR 0050 §6): the person opens a pairing window in the dashboard with a passkey, the
//! bot answers the code, and the person types it back into the dashboard with a passkey.

pub const CODE_TTL_MS: u64 = 10 * 60_000;
pub const MAX_TRIES: u32 = 5;
const ALPHABET: &[u8] = b"ABCDEFGHJKLMNPQRSTUVWXYZ23456789";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Pairing {
    pub code: String,
    pub expires_ms: u64,
    pub tries: u32,
    /// The person the chat that pairs will belong to, when the code was asked for from a person's row.
    pub person: Option<String>,
}

/// A fresh 8-character code with no look-alike characters.
pub fn new_pairing(now_ms: u64) -> Result<Pairing, String> {
    let mut buf = [0u8; 8];
    getrandom::getrandom(&mut buf).map_err(|e| format!("no secure random source: {e}"))?;
    let code = buf
        .iter()
        .map(|b| ALPHABET[(*b as usize) % ALPHABET.len()] as char)
        .collect();
    Ok(Pairing {
        code,
        expires_ms: now_ms + CODE_TTL_MS,
        tries: 0,
        person: None,
    })
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn codes_use_an_unambiguous_alphabet() -> Result<(), String> {
        let p = new_pairing(5)?;
        assert_eq!(p.code.len(), 8);
        assert!(p.code.bytes().all(|b| ALPHABET.contains(&b)));
        assert_eq!(p.expires_ms, 5 + CODE_TTL_MS);
        assert_ne!(new_pairing(5)?.code, p.code);
        Ok(())
    }
}
