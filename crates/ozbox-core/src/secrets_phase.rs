//! Where the box's secrets service is in starting, as one typed word in its state file (`phase=`), shared by the service that
//! writes it and the self-test that reads it.
//!
//! The self-test used to tell a service that had used up its tries from one still trying by the last words of the state file's
//! first line, a sentence for a person: `(starting again)` against `(trying again in N s)`. A rewording of that sentence would
//! silently have changed what the self-test decides. The service now says it in a line of its own, and the sentence is only
//! read for a state file written by a service from before this line (`phase` absent).

/// The line's key in the state file.
pub const FIELD: &str = "phase";

/// What an older service wrote at the end of its first line when it had used up its tries and was exiting to be started again.
/// Read only when a state file has no `phase` line.
pub const LEGACY_GAVE_UP: &str = "(starting again)";

/// Where a not-ready service is.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Phase {
    /// It is trying again in this process, after a short wait.
    Retrying,
    /// It has used up its tries in this process and exits for the unit to start it again.
    GaveUp,
    /// It stopped for good: nothing changes until a person changes something (a configuration, or a store that cannot open).
    Stopped,
}

impl Phase {
    pub fn word(self) -> &'static str {
        match self {
            Phase::Retrying => "retrying",
            Phase::GaveUp => "gave-up",
            Phase::Stopped => "stopped",
        }
    }

    pub fn parse(word: &str) -> Option<Phase> {
        match word.trim() {
            "retrying" => Some(Phase::Retrying),
            "gave-up" => Some(Phase::GaveUp),
            "stopped" => Some(Phase::Stopped),
            _ => None,
        }
    }

    /// The phase a state file says, from its `phase=` line. `None` when it has none (an older service) or the word is unknown.
    pub fn of_state(text: &str) -> Option<Phase> {
        text.lines()
            .skip(1)
            .find_map(|l| l.trim().strip_prefix("phase="))
            .and_then(Phase::parse)
    }
}

/// Whether the service has used up its tries, from the typed line when there is one and, only for a file written before it
/// existed, from the older service's sentence.
pub fn gave_up(state_text: &str) -> bool {
    match Phase::of_state(state_text) {
        Some(p) => p == Phase::GaveUp,
        None => state_text
            .lines()
            .next()
            .is_some_and(|l| l.trim().ends_with(LEGACY_GAVE_UP)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_typed_line_decides_and_the_sentence_is_read_only_without_it() {
        for p in [Phase::Retrying, Phase::GaveUp, Phase::Stopped] {
            assert_eq!(Phase::parse(p.word()), Some(p));
        }
        // the typed line wins, whatever the sentence says
        assert!(gave_up(
            "not-ready: the key service did not answer\nphase=gave-up\n"
        ));
        assert!(!gave_up("not-ready: x (starting again)\nphase=retrying\n"));
        // an older service: the sentence
        assert!(gave_up("not-ready: x (starting again)\nkek=kms\n"));
        assert!(!gave_up("not-ready: x (trying again in 2 s)\nkek=kms\n"));
        // the key in the FIRST line (a person's words) is never taken for the line
        assert_eq!(Phase::of_state("not-ready: phase=gave-up\n"), None);
        assert_eq!(Phase::of_state("not-ready: x\nphase=maybe\n"), None);
    }
}
