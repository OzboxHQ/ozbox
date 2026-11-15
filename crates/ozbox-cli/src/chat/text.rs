//! What goes out to a chat, and how fast. Pure.
//!
//! * [`outgoing`] is the one door for words leaving to a person's chat: it removes anything that looks like a key or a
//!   token, removes any exact secret value the server holds, strips control characters and bounds the length. A reply from
//!   an agent is untrusted text; it is shown, never obeyed.
//! * [`RateLimit`] holds a person to a number of messages a minute, so a chat that is flooded (or a person who is) does not
//!   run up the queue.
//! * [`Throttle`] spaces what goes back out, so a busy session does not send a message a second.

use std::collections::BTreeMap;

use ozbox_core::agent_engine::redact_line;

/// Whether two byte strings are equal, in time that does not depend on where they differ.
pub fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    a.len() == b.len() && a.iter().zip(b).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
}

/// The most characters of one agent answer a chat message carries.
pub const SUMMARY_CHARS: usize = 700;
/// The most characters of any one outgoing chat message.
pub const MESSAGE_CHARS: usize = 3_500;

/// Words for a chat: secrets removed, controls stripped, at most `max` characters.
pub fn outgoing(text: &str, secrets: &[String], max: usize) -> String {
    let cleaned: Vec<String> = text
        .lines()
        .map(|l| redact_line(l, secrets))
        .map(|l| {
            l.chars()
                .filter(|c| !c.is_control() || *c == '\t')
                .collect::<String>()
        })
        .collect();
    let mut s = cleaned.join("\n");
    // a secret split across a line break is not caught per line: the whole text is checked once more
    for sec in secrets.iter().filter(|s| s.len() >= 6) {
        s = s.replace(sec.as_str(), "[hidden]");
    }
    s.chars().take(max).collect()
}

/// An agent's answer made short for a chat: the first part, and how much more there is.
/// Returns the text and the number of characters left out.
pub fn summarise(reply: &str, secrets: &[String]) -> (String, usize) {
    let clean = outgoing(reply.trim(), secrets, usize::MAX);
    let total = clean.chars().count();
    if total <= SUMMARY_CHARS {
        return (clean, 0);
    }
    let cut: String = clean.chars().take(SUMMARY_CHARS).collect();
    // end on a word
    let cut = match cut.rfind(char::is_whitespace) {
        Some(i) if i > SUMMARY_CHARS / 2 => cut[..i].to_string(),
        _ => cut,
    };
    let left = total - cut.chars().count();
    (cut, left)
}

/// At most `limit` messages from one key in a minute.
#[derive(Debug, Default)]
pub struct RateLimit {
    seen: BTreeMap<String, Vec<u64>>,
}

impl RateLimit {
    pub const PER_MINUTE: usize = 20;

    /// Whether one more message from `key` is allowed now (and, if so, counts it).
    pub fn allow(&mut self, key: &str, now_ms: u64) -> bool {
        self.allow_with(key, now_ms, Self::PER_MINUTE)
    }

    /// As [`RateLimit::allow`] with another limit per minute.
    pub fn allow_with(&mut self, key: &str, now_ms: u64, limit: usize) -> bool {
        let v = self.seen.entry(key.to_string()).or_default();
        v.retain(|t| now_ms.saturating_sub(*t) < 60_000);
        if v.len() >= limit {
            return false;
        }
        v.push(now_ms);
        if self.seen.len() > 500 {
            self.seen
                .retain(|_, v| v.last().is_some_and(|t| now_ms.saturating_sub(*t) < 60_000));
        }
        true
    }
}

/// Spaces outgoing messages for one conversation: at least `gap_ms` apart. Messages that arrive sooner wait, and what is
/// waiting when the gap has passed is sent as one.
#[derive(Debug, Default)]
pub struct Throttle {
    last_ms: u64,
    held: Vec<String>,
}

impl Throttle {
    pub const GAP_MS: u64 = 3_000;
    pub const MAX_HELD: usize = 10;

    /// Offer a message; get back what to send now (possibly several messages joined), or nothing yet.
    pub fn offer(&mut self, text: String, now_ms: u64) -> Option<String> {
        self.held.push(text);
        if self.held.len() > Self::MAX_HELD {
            self.held.remove(0);
        }
        self.flush(now_ms)
    }

    /// What is due now, if the gap has passed.
    pub fn flush(&mut self, now_ms: u64) -> Option<String> {
        if self.held.is_empty() || now_ms.saturating_sub(self.last_ms) < Self::GAP_MS {
            return None;
        }
        self.last_ms = now_ms;
        let out = std::mem::take(&mut self.held).join("\n\n");
        Some(out.chars().take(MESSAGE_CHARS).collect())
    }

    pub fn waiting(&self) -> usize {
        self.held.len()
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    const SENTINEL: &str = "SENTINEL-SECRET-VALUE-12345";

    #[test]
    fn a_secret_never_leaves_even_split_across_lines_or_shaped_like_a_key() {
        let secrets = vec![SENTINEL.to_string()];
        let out = outgoing(&format!("the key is {SENTINEL}\nand sk-ant-api03-AAAAAAAAAAAAAAAAAAAA and ANTHROPIC_API_KEY=abc"), &secrets, 1000);
        assert!(
            !out.contains(SENTINEL) && !out.contains("AAAAAAAA") && !out.contains("=abc"),
            "{out}"
        );
        let split = outgoing(
            &format!("{}\n{}", &SENTINEL[..10], &SENTINEL[10..]),
            &secrets,
            1000,
        );
        assert!(
            split.contains(&SENTINEL[..10]),
            "pieces on separate lines are not the secret"
        );
        assert!(!outgoing("a\u{1b}[31mred\u{0}", &[], 100).contains('\u{1b}'));
    }

    #[test]
    fn a_long_answer_is_cut_on_a_word_and_says_how_much_is_left() {
        let (s, left) = summarise("short answer", &[]);
        assert_eq!((s.as_str(), left), ("short answer", 0));
        let long = "word ".repeat(400);
        let (s, left) = summarise(&long, &[]);
        assert!(s.chars().count() <= SUMMARY_CHARS && left > 1000 && s.ends_with("word"));
        assert_eq!(s.chars().count() + left, long.trim().chars().count());
    }

    #[test]
    fn a_person_is_held_to_twenty_messages_a_minute_and_the_minute_rolls() {
        let mut r = RateLimit::default();
        for i in 0..RateLimit::PER_MINUTE {
            assert!(r.allow("tg:1", i as u64), "{i}");
        }
        assert!(!r.allow("tg:1", 1_000));
        assert!(r.allow("tg:2", 1_000), "another person is unaffected");
        assert!(r.allow("tg:1", 61_000));
    }

    #[test]
    fn outgoing_messages_are_spaced_and_what_waits_goes_as_one() {
        let mut t = Throttle::default();
        assert_eq!(t.offer("a".into(), 10_000).as_deref(), Some("a"));
        assert_eq!(t.offer("b".into(), 11_000), None);
        assert_eq!(t.offer("c".into(), 12_000), None);
        assert_eq!(t.waiting(), 2);
        assert_eq!(t.flush(13_000).as_deref(), Some("b\n\nc"));
        assert_eq!(t.flush(20_000), None);
    }
}
