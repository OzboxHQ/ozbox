//! Recognises text that looks like a key, token or password, so it can be refused before it is stored.
//!
//! This is a screen, not a guarantee: it catches the common shapes (vendor prefixes, private keys, JWTs, `name = value`
//! assignments, long random strings). It never returns the text it matched, only what kind of thing it looked like.

const PREFIXES: &[(&str, usize, &str)] = &[
    ("sk-", 20, "an API key"),
    ("sk_live_", 12, "a payment key"),
    ("sk_test_", 12, "a payment key"),
    ("rk_live_", 12, "a payment key"),
    ("pk_live_", 12, "a payment key"),
    ("ghp_", 20, "a GitHub token"),
    ("gho_", 20, "a GitHub token"),
    ("ghs_", 20, "a GitHub token"),
    ("ghu_", 20, "a GitHub token"),
    ("github_pat_", 20, "a GitHub token"),
    ("glpat-", 16, "a GitLab token"),
    ("xoxb-", 16, "a Slack token"),
    ("xoxp-", 16, "a Slack token"),
    ("xoxa-", 16, "a Slack token"),
    ("xapp-", 16, "a Slack token"),
    ("AIza", 30, "a Google API key"),
    ("ozrt_", 12, "an Oz Box run token"),
    ("ozmt_", 12, "an Oz Box tool token"),
    ("ehr_live_", 12, "an API key"),
    ("ehr_test_", 12, "an API key"),
    ("npm_", 30, "an npm token"),
    ("hf_", 30, "a Hugging Face token"),
];

const NAMES: &[&str] = &[
    "password",
    "passwd",
    "secret",
    "token",
    "api_key",
    "apikey",
    "api-key",
    "private_key",
    "private-key",
    "access_key",
    "client_secret",
];

fn is_token_char(c: char) -> bool {
    c.is_ascii_alphanumeric() || matches!(c, '_' | '-' | '+' | '/' | '=' | '.')
}

fn hex_only(s: &str) -> bool {
    s.chars().all(|c| c.is_ascii_hexdigit())
}

fn random_looking(tok: &str) -> bool {
    let t = tok.trim_matches(|c: char| matches!(c, '=' | '.' | '-' | '_' | '/'));
    if t.len() < 32 || hex_only(t) || t.contains('/') && t.matches('/').count() > 2 {
        return false;
    }
    let up = t.chars().any(|c| c.is_ascii_uppercase());
    let low = t.chars().any(|c| c.is_ascii_lowercase());
    let dig = t.chars().any(|c| c.is_ascii_digit());
    up && low && dig && !t.contains("--")
}

fn placeholder(v: &str) -> bool {
    let l = v.to_ascii_lowercase();
    v.contains('<')
        || v.contains('{')
        || v.contains('$')
        || v.contains('*')
        || v.contains('[')
        || v.contains('}')
        || (v.contains('_')
            && v.chars()
                .all(|c| c.is_ascii_uppercase() || c.is_ascii_digit() || c == '_'))
        || l.starts_with("example")
        || l.starts_with("changeme")
        || l.starts_with("your")
        || l.contains("redacted")
        || l.contains("placeholder")
        || l.chars().all(|c| c == 'x' || c == '.')
}

/// What kind of secret `text` looks like, if it does.
pub fn find_secret(text: &str) -> Option<&'static str> {
    if text.contains("-----BEGIN") && text.contains("PRIVATE KEY") {
        return Some("a private key");
    }
    for tok in text.split(|c: char| !is_token_char(c)) {
        if tok.is_empty() {
            continue;
        }
        for (p, min, what) in PREFIXES {
            if tok.starts_with(p) && tok.len() >= p.len() + min {
                return Some(what);
            }
        }
        let b = tok.as_bytes();
        if (tok.starts_with("AKIA") || tok.starts_with("ASIA"))
            && tok.len() == 20
            && b.iter()
                .all(|c| c.is_ascii_uppercase() || c.is_ascii_digit())
        {
            return Some("an AWS access key");
        }
        if tok.starts_with("eyJ") && tok.len() > 40 && tok.matches('.').count() == 2 {
            return Some("a signed token");
        }
        if random_looking(tok) {
            return Some("a long random-looking string");
        }
    }
    // name = value / name: value
    let lower = text.to_ascii_lowercase();
    for name in NAMES {
        let mut from = 0;
        while let Some(i) = lower[from..].find(name) {
            let at = from + i + name.len();
            from = at;
            let rest = &text[at..];
            let rest = rest.trim_start_matches(['"', '\'', ' ', '\t']);
            let Some(rest) = rest.strip_prefix(['=', ':']) else {
                continue;
            };
            let value: String = rest
                .trim_start_matches([' ', '\t', '"', '\''])
                .chars()
                .take_while(|c| !c.is_whitespace() && !matches!(c, '"' | '\'' | ',' | ';'))
                .collect();
            if value.len() >= 8 && !placeholder(&value) {
                return Some("a password or key written as name = value");
            }
        }
    }
    None
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn catches_the_common_shapes() {
        for s in [
            concat!("key s", "k-abcdefghijklmnopqrstuvwx"),
            concat!("gh", "p_abcdefghijklmnopqrstuvwxyz0123456789"),
            concat!("AK", "IAABCDEFGHIJKLMNOP"),
            concat!("-----BEGIN OPENSSH PRIV", "ATE ", "KEY-----\nabc"),
            concat!("pass", "word = hunter2hunter2"),
            concat!("API_", "KEY: Zk3Jd9s0aLkq"),
            concat!("tok", "en=\"abcDEF123456\""),
            concat!(
                "ey",
                "JhbGciOiJIUzI1NiJ9.ey",
                "JzdWIiOiIxMjM0NTY3ODkwIn0.abcdefghijklmnop"
            ),
            "ozrt_0123456789abcdef",
            concat!("xo", "xb-1234567890-abcdef"),
            concat!("Qm9mYXNkZjEy", "MzRBU0RGZ2hqa2xRV0VSVFlVSU9QMTIzNDU2"),
        ] {
            assert!(find_secret(s).is_some(), "should refuse: {s}");
        }
    }

    #[test]
    fn leaves_ordinary_notes_alone() {
        for s in [
            "The release runner waits for the database deploy before the app push.",
            "Commit 4a969a9e1f3c6b2d8e0a5c7b9d1f3e5a7c9b1d3f fixed the spec.",
            "Use {{secret:STRIPE_KEY}} in the command, never the value.",
            "password: <your password here>",
            "The token limit is 8000 and the secret store is encrypted.",
            "api_key = $API_KEY",
            "See docs/adr/0018-secrets-are-encrypted-and-out-of-the-agents-reach.md for why.",
            "token: x",
        ] {
            assert!(find_secret(s).is_none(), "should allow: {s}");
        }
    }

    #[test]
    fn never_repeats_what_it_matched() {
        let r = find_secret(concat!("s", "k-abcdefghijklmnopqrstuvwx")).unwrap_or("");
        assert!(!r.contains("abcdef"));
    }
}
