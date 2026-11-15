//! The chat gateway's messages (English first). `messages::t` looks here too. These are what people read in Telegram,
//! Slack, WhatsApp and the dashboard chat, so they are short and never hold a key, a token or a command's output.

pub const EN: &[(&str, &str)] = &[
    ("chat.help", "Talk to a coding agent on your boxes. /new <box> <what to do> starts a session; then just write. /status, /log, /pause, /resume, /tasks, /switch <task>. A chat app only notifies about approvals and cannot approve, deny, stop a run or raise a spending cap; do these in the dashboard. /sessions lists agents running in your terminals; /attach <session> types into one (experimental; only into an agent that reports its own questions and asks before it does anything beyond reading, so not one in auto, accept-edits or don't-ask mode, with allow rules, a sandbox that runs commands for it, hooks or plugins of its own, or whose settings cannot be read; never a line that starts with !, #, & or /, which Claude Code acts on itself; and never to answer a question), /adopt <session> puts it on the board, /detach lets go."),
    ("chat.help_dashboard", "In this Chat only: /budget +5 adds dollars to a spending limit."),
    ("chat.not_linked", "This chat is not linked to a person on this Oz Box. Ask for a pairing code in the dashboard."),
    ("chat.paired", "Linked. You can talk to your coding agents here. Send /help."),
    ("chat.pair_bad", "That code did not work."),
    ("chat.forwarded", "A forwarded or quoted message is not an instruction, so I did not act on it. Write it as your own message if you mean it."),
    ("chat.slow_down", "Too many messages too fast. Try again in a minute."),
    ("chat.unknown", "I do not know /{word}. Send /help."),
    ("chat.new_usage", "Say which box and what to do: /new <box> <what to do>."),
    ("chat.budget_usage", "Say how many dollars to add: /budget +5."),
    ("chat.no_such_box", "There is no box called {box}."),
    ("chat.started", "Started {task} on {box}. It is queued; I will reply when the agent answers."),
    ("chat.queue_failed", "That could not be started: {why}"),
    ("chat.nothing_bound", "No session is open in this chat. Start one with /new <box> <what to do>, or pick one with /tasks and /switch <task>."),
    ("chat.not_yours", "That session belongs to someone else."),
    (
        "chat.person_removed",
        "You are no longer on this dashboard's list of people, so this chat can do nothing. Ask an owner.",
    ),
    (
        "chat.role_forbidden",
        "You are a {role} on this dashboard, and a {role} cannot {what}. Ask an owner.",
    ),
    ("chat.no_such_task", "There is no session called {task}."),
    ("chat.sent", "Sent to {task}."),
    ("chat.send_failed", "That message was not delivered: {why}"),
    ("chat.not_a_conversation", "{task} is not a conversation, so it cannot take messages."),
    ("chat.status", "{task} on {box}: {state}{waiting}. {turns} answer(s), spent {spend}."),
    ("chat.status_waiting", ", waiting for you"),
    ("chat.log_none", "No log lines yet."),
    ("chat.paused", "{task} will pause; its work is saved first. /resume continues the same conversation."),
    ("chat.resumed", "{task} is back in the queue and continues the same conversation."),
    ("chat.stop_refused", "{task} is stopped in the dashboard, not from a chat app. {where}"),
    ("chat.budget_refused", "A spend cap is raised in the dashboard, not from a chat app ({task}). {where}"),
    ("chat.stopped", "{task} is being stopped; its work is saved first."),
    ("chat.budget_added", "Added {amount} to {task}."),
    ("chat.action_failed", "That did not work: {why}"),
    ("chat.tasks_none", "No sessions yet. Start one with /new <box> <what to do>."),
    ("chat.tasks_row", "{task}  {state}  {box}  {prompt}"),
    ("chat.switched", "This chat now follows {task}."),
    ("chat.reply", "{task}: {text}"),
    ("chat.reply_more", "{task}: {text} ... ({more} more characters; ask /log or open the dashboard for the whole answer)"),
    ("chat.finished", "{task} finished."),
    ("chat.failed", "{task} stopped with an error."),
    ("chat.needs_you", "{task} needs you: {why}. Open the dashboard to decide."),
    ("chat.approval", "{task} wants to {action}. Decide it in the dashboard. {where}"),
    ("chat.approval_risky", "{task} wants to {action}. This kind needs your passkey, so it opens the dashboard. {where}"),
    ("chat.sessions_none", "No coding agents are running in your repos on any box right now."),
    ("chat.sessions_head", "Coding agents in your repos (experimental to type into):"),
    ("chat.sessions_row", "{id}  {engine}  {repo}{branch}  {level}, {state}"),
    ("chat.attached", "This chat now types into {session}. Experimental: what the agent prints is summarised here. /detach lets go."),
    ("chat.detached", "Let go."),
    ("chat.attach_refused", "{session} is not waiting for input, so I did not type into it. Add the word force to do it anyway: /attach {session} force."),
    ("chat.attach_refused_app", "{session} is not taking messages from a chat app right now: it may be asking a question of its own, which only you at its terminal or in the dashboard may answer. {where}"),
    ("chat.attach_force_refused", "A chat app does not type into an agent that is not waiting, because that could answer its own question. {where}"),
    ("chat.session_elevated", "{session} may do things without asking (auto, accept-edits or don't-ask mode, allow rules, a sandbox that runs commands for it, hooks of its own, or a standing permission), so a chat app may not type into it. Continue in the dashboard: {where}"),
    ("chat.run_elevated", "{session} runs with permissions a chat app may not use (auto or accept-edits mode, or a standing permission for its box), so a message from a chat app is not passed to it. Continue in the dashboard: {where}"),
    ("chat.session_unknown", "Oz Box cannot tell what {session} may do without asking (it is not a Claude Code session that has reported in, or its settings or process could not be read), so a chat app does not type into it. Continue in the dashboard: {where}"),
    ("chat.line_refused", "A chat app does not send a line that starts with !, #, & or /. Claude Code would run it as a shell command, a memory note, a background task or a command of its own, without asking. Write it as a sentence, or use the dashboard: {where}"),
    ("chat.attach_hooks_only", "{session} does not report its own questions to Oz Box, so a chat app cannot type into it safely. Use the dashboard. {where}"),
    ("chat.attach_gone", "{session} is not running, or it is not a coding agent in a repo."),
    ("chat.typed", "Typed into {session}."),
    ("chat.adopted", "{session} is on the board as {task}. It keeps running where it is."),
    ("chat.terminal_output", "{session}: {text}"),
    ("chat.where_link", "Open it there: {url}"),
    ("chat.where_none", "Open the dashboard on the computer that runs it."),
    ("chat.window_closed", "WhatsApp only allows free messages for 24 hours after you last wrote. Send any message to open it again."),
];

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    #[test]
    fn every_message_has_a_unique_key_and_matched_braces() {
        let mut seen = std::collections::BTreeSet::new();
        for (k, v) in super::EN {
            assert!(seen.insert(*k), "{k} is defined twice");
            assert!(k.starts_with("chat."));
            assert_eq!(v.matches('{').count(), v.matches('}').count(), "{k}");
        }
    }
}
