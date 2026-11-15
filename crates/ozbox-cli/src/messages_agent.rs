//! The command line's messages for coding agents on a box (`ozbox agent-mcp`), English first. `messages::t` looks here too.

pub const EN: &[(&str, &str)] = &[
    ("agent_mcp.no_home", "Your home folder could not be found, so no agent settings were changed."),
    ("agent_mcp.unknown_engine", "{engine} is not an engine Oz Box knows. Use claude-code, codex, gemini-cli or opencode."),
    ("agent_mcp.wrote", "  {engine}: the Oz Box tools are now in {engine}'s settings."),
    ("agent_mcp.unchanged", "  {engine}: already set up."),
    ("agent_mcp.removed", "  {engine}: the Oz Box tools are out of {engine}'s settings."),
    ("agent_mcp.absent", "  {engine}: nothing of ours to remove."),
    ("agent_mcp.left_yours", "  {engine}: left alone, you already have a server named ozbox there that this program did not write."),
    ("agent_mcp.refused", "  {engine}: left alone, {why}."),
    ("agent_mcp.some_refused", "{n} engine(s) were left alone (see above); the others are set up."),
    ("agent_mcp.status_on", "  {engine}: set up."),
    ("agent_mcp.status_off", "  {engine}: not set up."),
    ("agent_mcp.next", "Start the agent in a terminal on this box and ask it to use the Oz Box browser. Turn this off any time in the dashboard (Settings, Coding agents on this box)."),
];
