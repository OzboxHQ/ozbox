//! A line a chat app may not type into a coding agent's terminal.
//!
//! Claude Code reads some first characters as commands of its own, not as a message, and runs them without asking whatever
//! its permission mode is: `!` runs the rest as a shell command, `#` writes a memory note, `&` starts a background task, and
//! `/` is a slash command (a custom one can pre-approve tools in its front matter). A chat app that could type such a line
//! into a terminal would hold more authority than the permission mode in force shows, so the server and the box's daemon both
//! refuse it (each on its own: neither relies on the other).

/// Whether a line starts, after any spaces, with `!`, `#`, `&` or `/`. Invisible characters (zero-width, soft hyphen, byte
/// order mark) count as spaces here, so none can hide the real first character.
pub fn starts_with_agent_command(line: &str) -> bool {
    line.chars()
        .find(|c| {
            !c.is_whitespace()
                && !matches!(
                    *c,
                    '\u{200b}'..='\u{200f}' | '\u{2060}' | '\u{feff}' | '\u{00ad}'
                )
        })
        .is_some_and(|c| matches!(c, '!' | '#' | '&' | '/'))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_line_that_starts_like_a_command_is_one() {
        for l in [
            "!ls",
            "  !ls",
            "#note",
            "&go",
            "/model",
            "\u{200b}!x",
            "\t / x",
        ] {
            assert!(starts_with_agent_command(l), "{l:?}");
        }
        for l in [
            "",
            "   ",
            "fix it! now",
            "what is # here",
            "run /tests",
            "a&b",
        ] {
            assert!(!starts_with_agent_command(l), "{l:?}");
        }
    }
}
