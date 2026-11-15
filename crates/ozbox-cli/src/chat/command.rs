//! What a person's chat message means. Pure: the same words mean the same thing in every channel.
//!
//! A message that starts with `/` is a command; anything else is the next turn of the conversation the chat is bound to.
//! A command's word may carry a bot suffix (`/status@oz_bot`), which Telegram adds in groups.

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Command {
    /// `/new <box> <prompt>`: start a supervised interactive session.
    New {
        box_name: String,
        prompt: String,
    },
    /// Plain text: the next turn.
    Say(String),
    Status,
    Log,
    Stop,
    Pause,
    Resume,
    /// `/budget +N`: dollars to add, in cents.
    Budget(u64),
    Tasks,
    Switch(String),
    /// `/sessions [box]`: the coding agents running in the person's repos.
    Sessions(Option<String>),
    /// `/attach <session>` and `/attach <session> force`.
    Attach {
        session: String,
        force: bool,
    },
    Adopt(String),
    Detach,
    Help,
    /// `/pair <code>`.
    Pair(String),
    /// A command this does not know, so the answer can say so.
    Unknown(String),
}

fn word_of(first: &str) -> &str {
    let w = first.strip_prefix('/').unwrap_or(first);
    w.split('@').next().unwrap_or(w)
}

/// "5", "5.50" and "+5" as cents. Nothing above a hundred thousand dollars, nothing negative, nothing odd.
pub fn dollars_to_cents(s: &str) -> Option<u64> {
    let s = s.trim().trim_start_matches('+');
    if s.is_empty() || s.len() > 9 || !s.chars().all(|c| c.is_ascii_digit() || c == '.') {
        return None;
    }
    let (whole, frac) = s.split_once('.').unwrap_or((s, ""));
    if whole.is_empty() && frac.is_empty() || frac.len() > 2 || s.matches('.').count() > 1 {
        return None;
    }
    let whole: u64 = if whole.is_empty() {
        0
    } else {
        whole.parse().ok()?
    };
    let frac: u64 = format!("{frac:0<2}").parse().ok()?;
    let cents = whole.checked_mul(100)?.checked_add(frac)?;
    (cents > 0 && cents <= 10_000_000).then_some(cents)
}

pub fn parse(text: &str) -> Command {
    let text = text.trim();
    if !text.starts_with('/') {
        return Command::Say(text.to_string());
    }
    let (first, rest) = match text.split_once(char::is_whitespace) {
        Some((f, r)) => (f, r.trim()),
        None => (text, ""),
    };
    match word_of(first).to_ascii_lowercase().as_str() {
        "new" => {
            let (b, prompt) = match rest.split_once(char::is_whitespace) {
                Some((b, p)) => (b, p.trim()),
                None => (rest, ""),
            };
            if b.is_empty() || prompt.is_empty() {
                Command::Unknown("new".into())
            } else {
                Command::New {
                    box_name: b.to_string(),
                    prompt: prompt.to_string(),
                }
            }
        }
        "status" => Command::Status,
        "log" => Command::Log,
        "stop" => Command::Stop,
        "pause" => Command::Pause,
        "resume" => Command::Resume,
        "budget" => {
            dollars_to_cents(rest).map_or(Command::Unknown("budget".into()), Command::Budget)
        }
        "tasks" => Command::Tasks,
        "switch" if !rest.is_empty() => {
            Command::Switch(rest.split_whitespace().next().unwrap_or("").to_string())
        }
        "sessions" => Command::Sessions(
            (!rest.is_empty()).then(|| rest.split_whitespace().next().unwrap_or("").to_string()),
        ),
        "attach" if !rest.is_empty() => {
            let mut it = rest.split_whitespace();
            let session = it.next().unwrap_or("").to_string();
            Command::Attach {
                session,
                force: it.next().is_some_and(|w| w.eq_ignore_ascii_case("force")),
            }
        }
        "adopt" if !rest.is_empty() => {
            Command::Adopt(rest.split_whitespace().next().unwrap_or("").to_string())
        }
        "detach" => Command::Detach,
        "start" | "help" => {
            if rest.is_empty() {
                Command::Help
            } else {
                // Telegram's `/start <code>` deep link carries a pairing code
                Command::Pair(rest.to_string())
            }
        }
        "pair" if !rest.is_empty() => Command::Pair(rest.to_string()),
        other => Command::Unknown(other.chars().take(20).collect()),
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn every_command_is_read_and_plain_text_is_a_turn() {
        assert_eq!(parse("hello there"), Command::Say("hello there".into()));
        assert_eq!(
            parse("/new alpha fix the parser"),
            Command::New {
                box_name: "alpha".into(),
                prompt: "fix the parser".into()
            }
        );
        assert_eq!(parse("/new alpha"), Command::Unknown("new".into()));
        assert_eq!(parse("/status@oz_bot"), Command::Status);
        assert_eq!(parse("/STATUS"), Command::Status);
        assert_eq!(parse("/budget +5"), Command::Budget(500));
        assert_eq!(parse("/budget 2.5"), Command::Budget(250));
        assert_eq!(parse("/budget -5"), Command::Unknown("budget".into()));
        assert_eq!(parse("/budget"), Command::Unknown("budget".into()));
        assert_eq!(parse("/switch t7"), Command::Switch("t7".into()));
        assert_eq!(parse("/sessions"), Command::Sessions(None));
        assert_eq!(
            parse("/sessions alpha"),
            Command::Sessions(Some("alpha".into()))
        );
        assert_eq!(
            parse("/attach alpha:%3 force"),
            Command::Attach {
                session: "alpha:%3".into(),
                force: true
            }
        );
        assert_eq!(
            parse("/attach alpha:%3"),
            Command::Attach {
                session: "alpha:%3".into(),
                force: false
            }
        );
        assert_eq!(parse("/adopt alpha:%3"), Command::Adopt("alpha:%3".into()));
        assert_eq!(parse("/start ABCD2345"), Command::Pair("ABCD2345".into()));
        assert_eq!(parse("/start"), Command::Help);
        assert_eq!(
            parse("/frobnicate now"),
            Command::Unknown("frobnicate".into())
        );
        for c in ["/log", "/stop", "/pause", "/resume", "/tasks", "/detach"] {
            assert!(
                !matches!(parse(c), Command::Say(_) | Command::Unknown(_)),
                "{c}"
            );
        }
    }

    #[test]
    fn money_is_exact_bounded_and_never_negative() {
        for (s, c) in [
            ("5", Some(500)),
            ("+0.5", Some(50)),
            ("5.", Some(500)),
            (".5", Some(50)),
            ("0", None),
            ("1e3", None),
            ("5.555", None),
            ("1.2.3", None),
            ("", None),
            ("100000", Some(10_000_000)),
            ("100001", None),
        ] {
            assert_eq!(dollars_to_cents(s), c, "{s}");
        }
    }
}
