//! What each first-boot step that can fail on its own ended as, and what a person does about it.
//!
//! First boot's scripts (`ozbox-user-manager.sh`, `ozbox-supervisor-setup.sh`) run as root and record one line per step in
//! [`STEPS_FILE`] (root-owned, readable by the daemon's group): `<step> <ok|failed> <reason> <attempts>`. Every later run of the
//! same step (the root helper's `enable-linger` or `ensure-supervisor`) records again, so the action that repairs a step
//! clears its failure. The box's self-test reads the file and fails, naming the step. A line it does not understand is
//! skipped, never a pass and never a failure: an older or newer script must not make the self-test lie.

/// Where first boot records its steps.
pub const STEPS_FILE: &str = "/etc/ozbox/first-boot-steps";

/// A step first boot records, with what the self-test tells a person to run when it failed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct StepInfo {
    pub name: &'static str,
    /// What the step does, in a person's words.
    pub what: &'static str,
    /// The command that runs it again (and records it again).
    pub fix: &'static str,
}

/// Every step the scripts record. A test pins the scripts to this list, both ways.
pub const STEPS: &[StepInfo] = &[
    StepInfo {
        name: "enable_linger",
        what: "letting the box user's own services start at boot and keep running after logout (linger)",
        fix: "ozbox admin <box> -- enable-linger",
    },
    StepInfo {
        name: "user_manager",
        what: "starting the box user's own service manager",
        fix: "ozbox admin <box> -- enable-linger",
    },
    StepInfo {
        name: "agent_tools",
        what: "adding the Oz Box tools to the coding agents' settings",
        fix: "ozbox admin <box> -- ensure-supervisor",
    },
];

/// One recorded step.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Step {
    pub info: StepInfo,
    pub ok: bool,
    /// A short word for why (`already-on`, `switch-user-refused`, ...); letters, digits and dashes only.
    pub reason: String,
    pub attempts: u32,
}

/// The steps in the file's text, in the order they appear. Unknown steps, unknown results and malformed lines are skipped.
pub fn parse(text: &str) -> Vec<Step> {
    text.lines().filter_map(parse_line).collect()
}

fn parse_line(line: &str) -> Option<Step> {
    let mut w = line.split_whitespace();
    let (name, result, reason, attempts) = (w.next()?, w.next()?, w.next()?, w.next()?);
    if w.next().is_some() {
        return None;
    }
    let info = *STEPS.iter().find(|s| s.name == name)?;
    let ok = match result {
        "ok" => true,
        "failed" => false,
        _ => return None,
    };
    if reason.is_empty()
        || reason.len() > 64
        || !reason
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
    {
        return None;
    }
    Some(Step {
        info,
        ok,
        reason: reason.to_string(),
        attempts: attempts.parse().ok()?,
    })
}

/// A sentence for a failed step: what did not happen, why, and what to run.
pub fn failure_text(s: &Step) -> String {
    let tries = match s.attempts {
        0 | 1 => String::new(),
        n => format!(" after {n} tries"),
    };
    format!(
        "the box's setup did not finish {}{tries} ({}). Run `{}`, which does it again and clears this",
        s.info.what, s.reason, s.info.fix
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_record_is_read_line_by_line_and_anything_else_is_skipped() {
        let t = "enable_linger ok already-on 0\n\
                 agent_tools failed switch-user-refused 4\n\
                 user_manager ok started 1\n\
                 something_new failed whatever 1\n\
                 agent_tools maybe x 1\n\
                 user_manager failed Has_Caps 1\n\
                 user_manager failed x\n\
                 user_manager failed x 1 extra\n\
                 user_manager failed x many\n\
                 \n";
        let s = parse(t);
        assert_eq!(s.len(), 3, "{s:?}");
        assert_eq!(s[0].info.name, "enable_linger");
        assert!(s[0].ok);
        assert_eq!(s[1].info.name, "agent_tools");
        assert!(!s[1].ok);
        assert_eq!(
            (s[1].reason.as_str(), s[1].attempts),
            ("switch-user-refused", 4)
        );
        assert_eq!(s[2].info.name, "user_manager");
    }

    #[test]
    fn a_failure_names_what_did_not_happen_and_the_command_that_repairs_it() {
        let s = &parse("agent_tools failed switch-user-refused 4\n")[0];
        let t = failure_text(s);
        assert!(t.contains("coding agents' settings"), "{t}");
        assert!(
            t.contains("after 4 tries") && t.contains("switch-user-refused"),
            "{t}"
        );
        assert!(t.contains("ozbox admin <box> -- ensure-supervisor"), "{t}");
        let s = &parse("enable_linger failed login-manager-no-answer 1\n")[0];
        let t = failure_text(s);
        assert!(
            !t.contains("tries") && t.contains("-- enable-linger"),
            "{t}"
        );
    }
}
