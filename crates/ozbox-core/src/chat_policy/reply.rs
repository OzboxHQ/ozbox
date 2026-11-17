//! What an agent writes back, made fit for a chat app (ADR 0050 §5).
//!
//! A chat app is not end to end encrypted and its vendor has no data agreement with the project, so what an agent or a
//! command printed is **untrusted text, shown and never obeyed**, and it leaves only through [`agent_output`]:
//!
//! 1. it is read into a bounded buffer ([`REDACT_BUFFER`], larger than any cap), so a secret is redacted **before** the text is
//!    cut and can never be cut into a fragment that no longer looks like a secret;
//! 2. ANSI escapes and control characters are removed;
//! 3. every exact secret value the server knows is removed, with its base64 (standard and URL-safe, padded or not), hex
//!    (lower and upper) and percent encodings;
//! 4. key-shaped words go through the one redactor (`agent_engine::redact_line`), and long high-entropy words are hidden;
//! 5. every URL is removed, the dashboard's own included: only a server-built template carries an address;
//! 6. markup and images are stripped;
//! 7. the text is cut to the box's detail level.
//!
//! The redactor is a net, not a wall: it does not stop an agent that was told to encode what it read in some other way.
//! `SECURITY.md` says so.

/// How much an agent's reply is read before anything is cut.
pub const REDACT_BUFFER: usize = 64 * 1024;
/// The most characters of one agent reply at `full`.
pub const FULL_CHARS: usize = 1_500;
/// The most characters of one agent reply at `summary`.
pub const SUMMARY_CHARS: usize = 300;
/// A word this long, or longer, with high entropy is taken for a key.
const ENTROPY_MIN_LEN: usize = 24;
const ENTROPY_BITS: f64 = 4.0;

/// How much of what an agent wrote reaches a chat, per box (ADR 0050 §5).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Default)]
pub enum Detail {
    /// State, exit code, duration and a link: no words of the agent.
    Metadata,
    /// The first few lines.
    Summary,
    /// Up to [`FULL_CHARS`].
    #[default]
    Full,
}

impl Detail {
    pub const fn name(self) -> &'static str {
        match self {
            Detail::Metadata => "metadata",
            Detail::Summary => "summary",
            Detail::Full => "full",
        }
    }

    pub fn from_name(s: &str) -> Option<Detail> {
        match s {
            "metadata" => Some(Detail::Metadata),
            "summary" => Some(Detail::Summary),
            "full" => Some(Detail::Full),
            _ => None,
        }
    }

    /// The level that applies: a Production box is metadata and cannot be set otherwise, and a turn that read an untrusted
    /// source replies at summary, never full.
    pub fn effective(set: Detail, production: bool, untrusted_turn: bool) -> Detail {
        if production {
            Detail::Metadata
        } else if untrusted_turn {
            set.min(Detail::Summary)
        } else {
            set
        }
    }

    const fn cap(self) -> usize {
        match self {
            Detail::Metadata => 0,
            Detail::Summary => SUMMARY_CHARS,
            Detail::Full => FULL_CHARS,
        }
    }
}

/// An agent's reply, ready for a chat.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Shown {
    /// The words to send. Empty at `metadata`.
    pub text: String,
    /// Characters left out by the cap (the rest is in the dashboard).
    pub left_out: usize,
    /// Something was hidden or removed (a secret, a key-shaped word, a link, markup).
    pub hid: bool,
}

/// Make an agent's reply fit for a chat at `detail`. See the module for the order of the steps.
pub fn agent_output(raw: &str, secrets: &[String], detail: Detail) -> Shown {
    let bounded = bounded(raw, REDACT_BUFFER);
    let mut s = strip_ansi(bounded);
    let before = s.clone();
    s = hide_exact(&s, secrets);
    s = s
        .lines()
        .map(|l| crate::agent_engine::redact_line(l, &[]))
        .map(|l| hide_entropy(&l))
        .collect::<Vec<_>>()
        .join("\n");
    s = strip_urls(&s);
    s = strip_markup(&s);
    let hid = s != before;
    let s = s.trim().to_string();
    let cap = detail.cap();
    let total = s.chars().count();
    if total <= cap {
        return Shown {
            text: s,
            left_out: 0,
            hid,
        };
    }
    let mut cut: String = s.chars().take(cap).collect();
    if let Some(i) = cut.rfind(char::is_whitespace) {
        if i > cap / 2 {
            cut.truncate(i);
        }
    }
    let left = total - cut.chars().count();
    Shown {
        text: cut,
        left_out: left,
        hid,
    }
}

fn bounded(s: &str, max: usize) -> &str {
    if s.len() <= max {
        return s;
    }
    let mut end = max;
    while !s.is_char_boundary(end) {
        end -= 1;
    }
    &s[..end]
}

/// Remove ANSI escape sequences (CSI, OSC and two-byte escapes) and every control character but newline and tab.
pub fn strip_ansi(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let mut it = s.chars().peekable();
    while let Some(c) = it.next() {
        if c == '\u{1b}' {
            match it.peek() {
                Some('[') => {
                    it.next();
                    for d in it.by_ref() {
                        if ('@'..='~').contains(&d) {
                            break;
                        }
                    }
                }
                Some(']') => {
                    it.next();
                    while let Some(d) = it.next() {
                        if d == '\u{7}' {
                            break;
                        }
                        if d == '\u{1b}' && it.peek() == Some(&'\\') {
                            it.next();
                            break;
                        }
                    }
                }
                Some(_) => {
                    it.next();
                }
                None => {}
            }
            continue;
        }
        if c.is_control() && c != '\n' && c != '\t' {
            continue;
        }
        out.push(c);
    }
    out
}

const B64: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

fn base64(data: &[u8], url: bool, pad: bool) -> String {
    let mut out = String::new();
    for chunk in data.chunks(3) {
        let b = [
            chunk[0],
            chunk.get(1).copied().unwrap_or(0),
            chunk.get(2).copied().unwrap_or(0),
        ];
        let n = (u32::from(b[0]) << 16) | (u32::from(b[1]) << 8) | u32::from(b[2]);
        let chars = chunk.len() + 1;
        for i in 0..4 {
            if i < chars {
                let mut c = B64[((n >> (18 - 6 * i)) & 63) as usize];
                if url {
                    c = match c {
                        b'+' => b'-',
                        b'/' => b'_',
                        x => x,
                    };
                }
                out.push(c as char);
            } else if pad {
                out.push('=');
            }
        }
    }
    out
}

fn hex(data: &[u8], upper: bool) -> String {
    data.iter()
        .map(|b| {
            if upper {
                format!("{b:02X}")
            } else {
                format!("{b:02x}")
            }
        })
        .collect()
}

fn percent(data: &[u8]) -> String {
    data.iter()
        .map(|&b| {
            if b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.' | b'~') {
                (b as char).to_string()
            } else {
                format!("%{b:02X}")
            }
        })
        .collect()
}

/// The forms a secret value is hidden in: itself and its common encodings.
pub fn encodings(secret: &str) -> Vec<String> {
    let b = secret.as_bytes();
    let mut v = vec![
        secret.to_string(),
        base64(b, false, true),
        base64(b, false, false),
        base64(b, true, false),
        hex(b, false),
        hex(b, true),
        percent(b),
    ];
    v.sort();
    v.dedup();
    // longest first, so a longer form is not left half replaced by a shorter one
    v.sort_by_key(|s| std::cmp::Reverse(s.len()));
    v
}

fn hide_exact(s: &str, secrets: &[String]) -> String {
    let mut out = s.to_string();
    for sec in secrets.iter().filter(|x| x.len() >= 6) {
        for form in encodings(sec) {
            if form.len() >= 6 {
                out = out.replace(&form, "[hidden]");
            }
        }
    }
    out
}

fn entropy(w: &str) -> f64 {
    let mut counts = [0u32; 256];
    for b in w.bytes() {
        counts[b as usize] += 1;
    }
    let n = w.len() as f64;
    counts
        .iter()
        .filter(|&&c| c > 0)
        .map(|&c| {
            let p = f64::from(c) / n;
            -p * p.log2()
        })
        .sum()
}

fn hide_entropy(line: &str) -> String {
    line.split(' ')
        .map(|w| {
            let core = w.trim_matches(|c: char| !(c.is_ascii_alphanumeric() || "+/=_-".contains(c)));
            let keyish = core.len() >= ENTROPY_MIN_LEN
                && core
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b"+/=_-".contains(&b))
                && core.bytes().any(|b| b.is_ascii_digit())
                && entropy(core) >= ENTROPY_BITS;
            if keyish {
                w.replace(core, "[hidden]")
            } else {
                w.to_string()
            }
        })
        .collect::<Vec<_>>()
        .join(" ")
}

/// Remove every address: anything with a scheme (`https://`, `ftp://`, `javascript:`), `www.` and `mailto:`.
pub fn strip_urls(s: &str) -> String {
    s.lines()
        .map(|line| {
            line.split(' ')
                .map(|w| {
                    let l = w.to_ascii_lowercase();
                    let has_scheme = l.find("://").is_some_and(|i| {
                        i > 0
                            && l[..i]
                                .trim_start_matches(|c: char| !c.is_ascii_alphabetic())
                                .bytes()
                                .all(|b| b.is_ascii_alphanumeric() || b"+.-".contains(&b))
                    });
                    if has_scheme
                        || l.trim_start_matches(|c: char| !c.is_ascii_alphanumeric())
                            .starts_with("www.")
                        || l.contains("javascript:")
                        || l.contains("data:")
                        || l.contains("mailto:")
                    {
                        "[link removed]".to_string()
                    } else {
                        w.to_string()
                    }
                })
                .collect::<Vec<_>>()
                .join(" ")
        })
        .collect::<Vec<_>>()
        .join("\n")
}

/// Remove HTML tags and Markdown images; leave the words.
pub fn strip_markup(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let mut in_tag = false;
    let chars: Vec<char> = s.chars().collect();
    let mut i = 0;
    while i < chars.len() {
        let c = chars[i];
        if c == '!' && chars.get(i + 1) == Some(&'[') {
            // a Markdown image: drop up to the closing bracket and its target
            if let Some(close) = chars[i..].iter().position(|&x| x == ']') {
                let mut j = i + close + 1;
                if chars.get(j) == Some(&'(') {
                    while j < chars.len() && chars[j] != ')' {
                        j += 1;
                    }
                }
                out.push_str("[image removed]");
                i = j + 1;
                continue;
            }
        }
        if c == '<' && chars.get(i + 1).is_some_and(|n| n.is_ascii_alphabetic() || *n == '/') {
            in_tag = true;
        } else if in_tag && c == '>' {
            in_tag = false;
        } else if !in_tag {
            out.push(c);
        }
        i += 1;
    }
    out
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    const SENTINEL: &str = "SENTINEL-value-7f3a9c2e-not-real";

    fn secrets() -> Vec<String> {
        vec![SENTINEL.to_string()]
    }

    #[test]
    fn a_secret_value_never_leaves_in_any_common_encoding() {
        for form in encodings(SENTINEL) {
            let raw = format!("here it is: {form} done");
            let out = agent_output(&raw, &secrets(), Detail::Full);
            assert!(!out.text.contains(&form), "{form} leaked: {}", out.text);
            assert!(out.hid);
        }
    }

    #[test]
    fn a_secret_that_straddles_the_cap_is_hidden_before_the_cut() {
        // the secret begins a few characters before the full cap: cut first, it would leave a fragment
        let pad = "a ".repeat((FULL_CHARS - 10) / 2);
        let raw = format!("{pad}{SENTINEL} and more words after it");
        let out = agent_output(&raw, &secrets(), Detail::Full);
        assert!(!out.text.contains("SENTINEL"), "{}", &out.text[out.text.len() - 40..]);
        assert!(!out.text.contains("7f3a9c2e"));
    }

    #[test]
    fn key_shapes_and_long_random_words_are_hidden() {
        // built by concatenation so this file holds no key-shaped literal
        let raw = format!(
            "token {}{} and Zx8Qp2Lm9Rt4Vn7Bk1Hs6Jd3Fg5Wy0Ca and AWS=1",
            "gh", "p_abcdefghijklmnopqrstuvwxyz0123"
        );
        let out = agent_output(&raw, &[], Detail::Full);
        assert!(!out.text.contains("ghp_abcdef"));
        assert!(!out.text.contains("Zx8Qp2Lm9Rt4"));
        // ordinary long words stay
        let out = agent_output("internationalisation-of-the-documentation is fine", &[], Detail::Full);
        assert!(out.text.contains("internationalisation"));
    }

    #[test]
    fn every_url_is_removed_the_dashboards_own_too() {
        let raw = "open https://dash.example.com/approve#t=abc or www.example.com or javascript:alert(1) or ftp://x.example.com/a";
        let out = agent_output(raw, &[], Detail::Full);
        for bad in ["https://", "dash.example.com", "www.example", "javascript:", "ftp://"] {
            assert!(!out.text.contains(bad), "{bad} in {}", out.text);
        }
        assert!(out.text.contains("[link removed]"));
    }

    #[test]
    fn ansi_controls_markup_and_images_are_stripped() {
        let raw = "\u{1b}[31mred\u{1b}[0m \u{1b}]8;;https://x.example\u{7}link\u{1b}]8;;\u{7} <b>bold</b> ![x](https://img.example/a.png) \u{7}bell";
        let out = agent_output(raw, &[], Detail::Full);
        assert!(!out.text.contains('\u{1b}'));
        assert!(!out.text.contains('\u{7}'));
        assert!(!out.text.contains("<b>"));
        assert!(!out.text.contains("img.example"));
        assert!(out.text.contains("red"));
        assert!(out.text.contains("bold"));
    }

    #[test]
    fn detail_levels_cap_and_production_is_metadata() {
        let long = "word ".repeat(1_000);
        let full = agent_output(&long, &[], Detail::Full);
        assert!(full.text.chars().count() <= FULL_CHARS);
        assert!(full.left_out > 0);
        let sum = agent_output(&long, &[], Detail::Summary);
        assert!(sum.text.chars().count() <= SUMMARY_CHARS);
        let meta = agent_output(&long, &[], Detail::Metadata);
        assert!(meta.text.is_empty());
        assert_eq!(Detail::effective(Detail::Full, true, false), Detail::Metadata);
        assert_eq!(Detail::effective(Detail::Full, false, true), Detail::Summary);
        assert_eq!(Detail::effective(Detail::Metadata, false, true), Detail::Metadata);
    }

    #[test]
    fn a_huge_reply_is_read_only_up_to_the_buffer() {
        let raw = "x".repeat(REDACT_BUFFER * 4);
        let out = agent_output(&raw, &[], Detail::Full);
        assert!(out.text.len() <= FULL_CHARS);
    }

    #[test]
    fn the_base64_encoder_matches_known_vectors() {
        assert_eq!(base64(b"foobar", false, true), "Zm9vYmFy");
        assert_eq!(base64(b"fooba", false, true), "Zm9vYmE=");
        assert_eq!(base64(b"foob", false, false), "Zm9vYg");
        assert_eq!(base64(&[0xfb, 0xff], true, false), "-_8");
    }
}
