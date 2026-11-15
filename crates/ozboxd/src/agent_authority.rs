//! What a coding agent in a person's own terminal may already do without asking, so that a chat app is never handed more than
//! the dashboard's own person would be.
//!
//! A terminal agent has its own permission authority: Claude Code can run in `acceptEdits`, `auto`, `dontAsk` or
//! `bypassPermissions` mode, can have `permissions.allow` rules, and can be started with flags that skip its prompts. A
//! line typed into such a session runs under that authority, so a chat app (Telegram, Slack, WhatsApp) typing there would
//! inherit it: the person who set it up at their desk did not hand it to whoever can message the bot. Every session is
//! therefore classified, and a chat app may type only into one that is [`Authority::Plain`]:
//!
//! * `plain`: the agent asks before it does anything beyond reading: mode `default` or `plan`, no skip flag, no allow rule
//!   beyond read-only tools, no non-default `defaultMode`, no sandbox that runs commands for it, no hook of its own that can
//!   answer a permission question, no `--permission-prompt-tool`, no plugin;
//! * `elevated`: something above was found;
//! * `unknown`: it could not be established (no mode heard, not Claude Code, the process list or a settings file could not be
//!   read). Unknown is refused exactly like elevated: nothing is assumed.
//!
//! The mode comes from the `permission_mode` field of Claude Code's hook input (<https://code.claude.com/docs/en/hooks>:
//! `default`, `plan`, `acceptEdits`, `auto`, `dontAsk` or `bypassPermissions`), recorded per terminal by
//! [`crate::agent_events`]. The daemon also reads the arguments of the processes on the terminal, the user, project and local
//! Claude settings files, the folder `CLAUDE_CONFIG_DIR` points to (read from the environment of the `claude` process, as the
//! same user), the managed settings and its `managed-settings.d` drop-ins, and the footer of the screen (the mode can be changed
//! with a keystroke between two hook events; the last [`SCREEN_TAIL_LINES`] lines are read, and the footer text is pinned by
//! screens captured from a real Claude Code).
//!
//! Names that the Claude Code documentation does not state a default for (`sandbox.autoAllowBashIfSandboxed`) and facts that
//! cannot be seen from here (what a hook program or a plugin would answer) are treated conservatively: elevated or unknown,
//! never plain. A line a chat app types is a separate matter: see [`ozbox_core::agent_line`].
//!
//! MERGE OBLIGATION: ADR 0043 (standing windows and allow rules; branch `feat/agent-mcp-on-box`) is not on the branch that
//! introduced this. Whichever of the two lands second must feed the state of a standing window and of the allow rules into
//! [`Authority`] (an active standing permission for the box makes its sessions `elevated`), with a test beside
//! `a_chat_app_is_refused_in_every_elevated_case` in `agent_sessions.rs`.

/// See the module docs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Authority {
    Plain,
    Elevated,
    Unknown,
}

impl Authority {
    pub fn as_str(self) -> &'static str {
        match self {
            Authority::Plain => "plain",
            Authority::Elevated => "elevated",
            Authority::Unknown => "unknown",
        }
    }

    /// The worse of two: anything but plain wins, and elevated is the more specific.
    pub fn and(self, other: Authority) -> Authority {
        match (self, other) {
            (Authority::Plain, o) => o,
            (s, Authority::Plain) => s,
            (Authority::Elevated, _) | (_, Authority::Elevated) => Authority::Elevated,
            _ => Authority::Unknown,
        }
    }
}

/// The authority a `permission_mode` value gives. A mode never heard, or one this code has never seen, is unknown.
pub fn of_mode(mode: Option<&str>) -> Authority {
    match mode {
        Some("default" | "plan") => Authority::Plain,
        Some("acceptEdits" | "auto" | "dontAsk" | "bypassPermissions") => Authority::Elevated,
        _ => Authority::Unknown,
    }
}

fn plain_mode_value(v: &str) -> bool {
    matches!(v, "default" | "plan")
}

/// What the processes on a terminal show (`ps -ww -o pid=,args=`, one process per line).
#[derive(Debug, PartialEq, Eq)]
pub struct ProcScan {
    pub authority: Authority,
    /// The process ids of the `claude` processes, whose environment is read for `CLAUDE_CONFIG_DIR`.
    pub claude_pids: Vec<u32>,
}

/// Flags that skip, widen or hand over Claude Code's permission prompts, or that load settings, hooks or commands this code
/// cannot read from here: `--permission-prompt-tool` hands every prompt to an MCP tool that can approve it; a plugin
/// (`--plugin-dir`, `--plugin-url`) carries hooks and commands; a settings file named on the command line is out of sight.
fn flag_widens(flag: &str, value: Option<&str>) -> bool {
    match flag {
        f if f.starts_with("--dangerously") || f.starts_with("--allow-dangerously") => true,
        "--permission-mode" => !value.is_some_and(plain_mode_value),
        "--allowedTools" | "--allowed-tools" | "--settings" => true,
        "--permission-prompt-tool" | "--plugin-dir" | "--plugin-url" => true,
        _ => false,
    }
}

/// The authority the arguments of the processes on a terminal give. Only lines that mention `claude` are read. A flag that
/// skips or widens permissions is elevated (see [`flag_widens`]). No `claude` process on the terminal is unknown.
pub fn of_process_args(ps_out: &str) -> ProcScan {
    let mut claude_pids = Vec::new();
    let mut seen = false;
    for line in ps_out.lines().filter(|l| l.contains("claude")) {
        seen = true;
        let mut toks: Vec<&str> = line.split_whitespace().collect();
        if let Some(pid) = toks.first().and_then(|t| t.parse::<u32>().ok()) {
            claude_pids.push(pid);
            toks.remove(0);
        }
        for (i, t) in toks.iter().enumerate() {
            let flag = t.split('=').next().unwrap_or(t);
            let value = t
                .split_once('=')
                .map(|(_, v)| v)
                .or_else(|| toks.get(i + 1).copied());
            if flag_widens(flag, value) {
                return ProcScan {
                    authority: Authority::Elevated,
                    claude_pids,
                };
            }
        }
    }
    ProcScan {
        // no process of that name on the terminal: what runs there cannot be seen
        authority: if seen {
            Authority::Plain
        } else {
            Authority::Unknown
        },
        claude_pids,
    }
}

/// The value of `CLAUDE_CONFIG_DIR` in a process's environment (`/proc/<pid>/environ`, NUL-separated), when it is set.
pub fn config_dir_of_environ(environ: &str) -> Option<String> {
    environ
        .split('\0')
        .find_map(|kv| kv.strip_prefix("CLAUDE_CONFIG_DIR=").map(str::to_string))
}

/// Whether a `CLAUDE_CONFIG_DIR` value can be used to find settings: an absolute folder with no `..` or control characters.
pub fn usable_config_dir(dir: &str) -> bool {
    dir.starts_with('/')
        && dir.len() <= 300
        && !dir.split('/').any(|s| s == "..")
        && !dir.chars().any(char::is_control)
}

/// Tool names a `permissions.allow` entry may carry and still be read-only.
const READ_ONLY_TOOLS: [&str; 5] = ["Read", "Glob", "Grep", "LS", "NotebookRead"];

/// The authority one Claude settings file (the text of it) gives: allow rules beyond read-only tools, or a `defaultMode`
/// that is not `default` or `plan`, are elevated; text that is not JSON is unknown.
pub fn of_settings(text: &str) -> Authority {
    let Ok(v) = serde_json::from_str::<serde_json::Value>(text) else {
        return Authority::Unknown;
    };
    let Some(root) = v.as_object() else {
        return Authority::Unknown;
    };
    let mut out = Authority::Plain;
    if let Some(p) = root.get("permissions") {
        let Some(p) = p.as_object() else {
            return Authority::Unknown;
        };
        if let Some(m) = p.get("defaultMode") {
            if !m.as_str().is_some_and(plain_mode_value) {
                out = Authority::Elevated;
            }
        }
        if let Some(allow) = p.get("allow") {
            let Some(list) = allow.as_array() else {
                return Authority::Unknown;
            };
            for e in list {
                let read_only = e.as_str().is_some_and(|s| {
                    let name = s.split('(').next().unwrap_or(s).trim();
                    READ_ONLY_TOOLS.contains(&name)
                });
                if !read_only {
                    out = Authority::Elevated;
                }
            }
        }
    }
    // the old top-level spelling
    if root
        .get("allowedTools")
        .is_some_and(|a| !a.as_array().is_some_and(Vec::is_empty))
    {
        out = Authority::Elevated;
    }
    out = out.and(of_sandbox(root.get("sandbox")));
    out = out.and(of_hooks(root.get("hooks")));
    out = out.and(of_plugins(root.get("enabledPlugins")));
    // plan mode that hands over to auto mode
    if root.get("useAutoModeDuringPlan").and_then(|v| v.as_bool()) == Some(true) {
        out = Authority::Elevated;
    }
    out
}

/// `sandbox`: Claude Code runs a sandboxed Bash command without a prompt when `sandbox.enabled` and
/// `sandbox.autoAllowBashIfSandboxed` both hold (<https://code.claude.com/docs/en/sandboxing>). The documentation does not state
/// the default of `autoAllowBashIfSandboxed`, so an enabled sandbox is elevated unless the key is explicitly `false`.
fn of_sandbox(v: Option<&serde_json::Value>) -> Authority {
    let Some(v) = v else {
        return Authority::Plain;
    };
    let Some(sb) = v.as_object() else {
        return Authority::Unknown;
    };
    let auto = sb.get("autoAllowBashIfSandboxed");
    match (sb.get("enabled"), auto) {
        (_, Some(a)) if !a.is_boolean() => Authority::Unknown,
        (Some(e), _) if !e.is_boolean() => Authority::Unknown,
        (_, Some(a)) if a.as_bool() == Some(true) => Authority::Elevated,
        (Some(e), a) if e.as_bool() == Some(true) && a.and_then(|a| a.as_bool()) != Some(false) => {
            Authority::Elevated
        }
        _ => Authority::Plain,
    }
}

/// Hooks that can answer a permission question: a `PreToolUse` hook may return `permissionDecision: "allow"` and a
/// `PermissionRequest` hook `decision.behavior: "allow"` (<https://code.claude.com/docs/en/hooks>). What a hook program would
/// answer cannot be known from here, so one that is not Oz Box's own is elevated.
fn of_hooks(v: Option<&serde_json::Value>) -> Authority {
    let Some(v) = v else {
        return Authority::Plain;
    };
    let Some(h) = v.as_object() else {
        return Authority::Unknown;
    };
    let mut out = Authority::Plain;
    for ev in ["PreToolUse", "PermissionRequest"] {
        let Some(groups) = h.get(ev) else { continue };
        let Some(groups) = groups.as_array() else {
            return Authority::Unknown;
        };
        for g in groups {
            let Some(handlers) = g.get("hooks").and_then(|x| x.as_array()) else {
                return Authority::Unknown;
            };
            for handler in handlers {
                let ours = handler.get("name").and_then(|n| n.as_str())
                    == Some(crate::agent_events::MARKER);
                if !ours {
                    out = Authority::Elevated;
                }
            }
        }
    }
    out
}

/// An enabled plugin can carry hooks and commands that are not in any settings file. They cannot be seen from here.
fn of_plugins(v: Option<&serde_json::Value>) -> Authority {
    match v {
        None => Authority::Plain,
        Some(p) => match p.as_object() {
            Some(o) if o.values().all(|x| x.as_bool() != Some(true)) => Authority::Plain,
            _ => Authority::Unknown,
        },
    }
}

/// How many non-empty lines at the bottom of the screen are read for the mode indicator: more than the footer alone, so that a
/// multi-line status line or a notice drawn below it cannot push it out of sight, and bounded, so that conversation higher up
/// that merely mentions a mode is not read as the footer.
pub const SCREEN_TAIL_LINES: usize = 20;

/// The authority the bottom of a terminal screen gives: Claude Code shows its mode in the footer, and the mode can be changed
/// with a keystroke (Shift+Tab) after the last hook event. Captured from Claude Code 2.1.325: `manual mode on` (default),
/// `plan mode on`, `accept edits on`, `auto mode on`, `don't ask on`, `bypass permissions on`. Whitespace is collapsed and the
/// text lowercased, and text that merely mentions a permissive mode errs toward refusing.
pub fn of_screen(screen: &str) -> Authority {
    let lines: Vec<&str> = screen.lines().filter(|l| !l.trim().is_empty()).collect();
    let tail = lines[lines.len().saturating_sub(SCREEN_TAIL_LINES)..]
        .iter()
        .map(|l| l.split_whitespace().collect::<Vec<_>>().join(" "))
        .collect::<Vec<_>>()
        .join("\n")
        .to_lowercase()
        .replace('\u{2019}', "'");
    if [
        "bypass permissions",
        "accept edits",
        "auto-accept",
        "auto mode",
        "don't ask",
        "dont ask",
    ]
    .iter()
    .any(|m| tail.contains(m))
    {
        Authority::Elevated
    } else {
        Authority::Plain
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_permission_mode_is_classified_and_nothing_unheard_is_plain() {
        assert_eq!(of_mode(Some("default")), Authority::Plain);
        assert_eq!(of_mode(Some("plan")), Authority::Plain);
        for m in ["acceptEdits", "auto", "dontAsk", "bypassPermissions"] {
            assert_eq!(of_mode(Some(m)), Authority::Elevated, "{m}");
        }
        assert_eq!(of_mode(None), Authority::Unknown);
        assert_eq!(of_mode(Some("somethingNew")), Authority::Unknown);
    }

    #[test]
    fn process_arguments_that_skip_or_widen_permissions_are_elevated() {
        let plain = of_process_args("  10 -bash\n  11 claude\n");
        assert_eq!(plain.authority, Authority::Plain);
        assert_eq!(plain.claude_pids, vec![11]);
        assert_eq!(
            of_process_args("  11 claude --permission-mode plan\n").authority,
            Authority::Plain
        );
        for l in [
            "claude --dangerously-skip-permissions",
            "claude --allow-dangerously-skip-permissions",
            "claude --permission-mode bypassPermissions",
            "claude --permission-mode=acceptEdits",
            "claude --permission-mode auto",
            "claude --allowedTools Bash",
            "claude --allowed-tools=Bash",
            "node /usr/lib/claude --settings /tmp/x.json",
            "claude --permission-mode",
            "claude --permission-prompt-tool mcp__x__approve",
            "claude --permission-prompt-tool=mcp__x__approve",
            "claude --plugin-dir /opt/p",
            "claude --plugin-url https://x/p.zip",
        ] {
            let line = format!("  42 {l}");
            assert_eq!(of_process_args(&line).authority, Authority::Elevated, "{l}");
        }
        assert_eq!(
            of_process_args("  10 -bash\n").authority,
            Authority::Unknown
        );
        assert_eq!(of_process_args("").authority, Authority::Unknown);
    }

    #[test]
    fn the_config_folder_is_read_from_a_processs_environment() {
        assert_eq!(
            config_dir_of_environ("HOME=/h\0CLAUDE_CONFIG_DIR=/srv/c\0PATH=/x\0").as_deref(),
            Some("/srv/c")
        );
        assert_eq!(
            config_dir_of_environ("HOME=/h\0NOT_CLAUDE_CONFIG_DIR=/x\0"),
            None
        );
        assert!(usable_config_dir("/srv/c"));
        for bad in ["cfg", "/a/../b", "", "/a\nb"] {
            assert!(!usable_config_dir(bad), "{bad:?}");
        }
    }

    #[test]
    fn settings_with_allow_rules_beyond_reading_or_another_default_mode_are_elevated() {
        assert_eq!(of_settings("{}"), Authority::Plain);
        assert_eq!(
            of_settings(
                r#"{"permissions":{"allow":["Read","Read(./src/**)","Grep"],"defaultMode":"plan"}}"#
            ),
            Authority::Plain
        );
        for t in [
            r#"{"permissions":{"allow":["Bash(npm test:*)"]}}"#,
            r#"{"permissions":{"allow":["Edit"]}}"#,
            r#"{"permissions":{"allow":[7]}}"#,
            r#"{"permissions":{"defaultMode":"acceptEdits"}}"#,
            r#"{"permissions":{"defaultMode":"bypassPermissions"}}"#,
            r#"{"allowedTools":["Bash"]}"#,
        ] {
            assert_eq!(of_settings(t), Authority::Elevated, "{t}");
        }
        for t in [
            "not json",
            "[]",
            r#"{"permissions":3}"#,
            r#"{"permissions":{"allow":"x"}}"#,
        ] {
            assert_eq!(of_settings(t), Authority::Unknown, "{t}");
        }
    }

    #[test]
    fn a_sandbox_that_runs_commands_without_asking_is_elevated() {
        for t in [
            r#"{"sandbox":{"enabled":true}}"#,
            r#"{"sandbox":{"enabled":true,"autoAllowBashIfSandboxed":true}}"#,
            r#"{"sandbox":{"autoAllowBashIfSandboxed":true}}"#,
            r#"{"sandbox":{"enabled":false,"autoAllowBashIfSandboxed":true}}"#,
        ] {
            assert_eq!(of_settings(t), Authority::Elevated, "{t}");
        }
        for t in [
            r#"{"sandbox":{}}"#,
            r#"{"sandbox":{"enabled":false}}"#,
            r#"{"sandbox":{"enabled":true,"autoAllowBashIfSandboxed":false}}"#,
            r#"{"sandbox":{"allowUnsandboxedCommands":false}}"#,
        ] {
            assert_eq!(of_settings(t), Authority::Plain, "{t}");
        }
        for t in [
            r#"{"sandbox":true}"#,
            r#"{"sandbox":{"enabled":"yes"}}"#,
            r#"{"sandbox":{"autoAllowBashIfSandboxed":"yes"}}"#,
        ] {
            assert_eq!(of_settings(t), Authority::Unknown, "{t}");
        }
    }

    #[test]
    fn hooks_plugins_and_auto_mode_in_plan_are_not_plain() {
        let ours = r#"{"hooks":{"PreToolUse":[{"matcher":"Bash","hooks":[{"type":"command","name":"ozboxd hook"}]}],"Stop":[{"hooks":[{"type":"command","command":"x"}]}]}}"#;
        assert_eq!(of_settings(ours), Authority::Plain);
        for t in [
            r#"{"hooks":{"PreToolUse":[{"hooks":[{"type":"command","command":"/a.sh"}]}]}}"#,
            r#"{"hooks":{"PermissionRequest":[{"hooks":[{"type":"command","command":"/a.sh"}]}]}}"#,
            r#"{"hooks":{"PreToolUse":[{"hooks":[{"name":"ozboxd hook"},{"command":"/a.sh"}]}]}}"#,
            r#"{"useAutoModeDuringPlan":true}"#,
        ] {
            assert_eq!(of_settings(t), Authority::Elevated, "{t}");
        }
        for t in [
            r#"{"hooks":3}"#,
            r#"{"hooks":{"PreToolUse":"x"}}"#,
            r#"{"hooks":{"PreToolUse":[{"nohooks":1}]}}"#,
            r#"{"enabledPlugins":{"p@m":true}}"#,
            r#"{"enabledPlugins":[]}"#,
        ] {
            assert_eq!(of_settings(t), Authority::Unknown, "{t}");
        }
        assert_eq!(
            of_settings(r#"{"enabledPlugins":{"p@m":false}}"#),
            Authority::Plain
        );
        assert_eq!(
            of_settings(r#"{"useAutoModeDuringPlan":false}"#),
            Authority::Plain
        );
    }

    #[test]
    fn a_footer_that_names_a_permissive_mode_is_elevated() {
        assert_eq!(of_screen("hello\n? for shortcuts"), Authority::Plain);
        assert_eq!(
            of_screen("x\n  accept edits on (shift+tab to cycle)"),
            Authority::Elevated
        );
        assert_eq!(of_screen("x\n  bypass permissions on"), Authority::Elevated);
        assert_eq!(
            of_screen("x\n  \u{23f5}\u{23f5}   Accept   Edits  on"),
            Authority::Elevated
        );
        assert_eq!(of_screen("x\n  don\u{2019}t ask on"), Authority::Elevated);
        // far above the footer is conversation, not the footer
        let long = format!("accept edits\n{}", "line\n".repeat(30));
        assert_eq!(of_screen(&long), Authority::Plain);
        // a footer pushed up by a status line and notices below it is still read
        let pushed = format!("  auto mode on (shift+tab)\n{}", "status\n".repeat(12));
        assert_eq!(of_screen(&pushed), Authority::Elevated);
    }

    // Screens captured from a real Claude Code 2.1.325 (a pseudo-terminal, 120 columns, never sent a prompt; the folder name
    // and the account lines replaced): the footer in each mode, with and without a six-line status line.
    const FIXTURES: [(&str, &str, Authority); 7] = [
        (
            "default",
            include_str!("../tests/fixtures/claude-2.1.325/screen-default.txt"),
            Authority::Plain,
        ),
        (
            "plan",
            include_str!("../tests/fixtures/claude-2.1.325/screen-plan.txt"),
            Authority::Plain,
        ),
        (
            "default, status line",
            include_str!("../tests/fixtures/claude-2.1.325/screen-default-status-line.txt"),
            Authority::Plain,
        ),
        (
            "accept edits",
            include_str!("../tests/fixtures/claude-2.1.325/screen-accept-edits.txt"),
            Authority::Elevated,
        ),
        (
            "accept edits, status line",
            include_str!("../tests/fixtures/claude-2.1.325/screen-accept-edits-status-line.txt"),
            Authority::Elevated,
        ),
        (
            "auto",
            include_str!("../tests/fixtures/claude-2.1.325/screen-auto.txt"),
            Authority::Elevated,
        ),
        (
            "don't ask",
            include_str!("../tests/fixtures/claude-2.1.325/screen-dont-ask.txt"),
            Authority::Elevated,
        ),
    ];

    #[test]
    fn real_claude_code_screens_are_classified_by_their_footer() {
        for (name, screen, want) in FIXTURES {
            assert!(
                screen.contains("shift+tab to cycle") || screen.contains("manual mode on"),
                "{name}: the fixture holds a footer"
            );
            assert_eq!(of_screen(screen), want, "{name}");
        }
    }

    #[test]
    fn the_worse_authority_wins() {
        use Authority::*;
        assert_eq!(Plain.and(Plain), Plain);
        assert_eq!(Plain.and(Unknown), Unknown);
        assert_eq!(Unknown.and(Elevated), Elevated);
        assert_eq!(Elevated.and(Plain), Elevated);
    }
}
