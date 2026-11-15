# 0021 — Chat with coding agents: one conversation model, only linked people, risky approvals by passkey

**Decision.** People talk to the coding agents on their boxes from Telegram, the dashboard, Slack and WhatsApp. One
conversation model serves all four; the agent is an ordinary supervised run (ADR 0014) that stays open between messages.

1. **A session is a run with its input kept open.** `POST /v1/runs` on the box daemon takes `keep_stdin_open`, and
   `POST /v1/runs/<id>/stdin` appends text or ends the input. The daemon never waits on the program: text goes to a writer
   thread behind a bounded queue, and a program that is not reading is a refusal, not a hang. The body limit of the socket
   is unchanged; a long prompt is sent in pieces. The Claude Code adapter reads streamed JSON turns, ends a *turn* (not the
   run) at each result, keeps the agent's session id, and continues it with `--resume` after a pause. The engine seam is
   `AgentEngine::send`; an engine without a conversation mode keeps the default and refuses.
2. **Any coding agent can report in.** The box user's agent settings get hooks that run `ozboxd hook <engine>`, merged and
   never overwriting what the person has. Claude Code and Gemini CLI use their hook systems (needs input, finished,
   permission request); Codex uses its `notify` program (finished) when the person has not set their own; Aider's
   notification command and everything else without a documented hook are the terminal fallback. A hook never gets in the
   agent's way: any failure is silence and the agent's own rules apply. A permission request that nobody answers is denied
   after nine minutes, never approved.
3. **Chat is a gateway in `ozbox serve`.** Commands are parsed by one pure function and carried out through the same code the
   dashboard uses (the task store, the supervisor, the box daemon's routes); there is no second write path. Replies are
   short, have secrets removed, and are spaced. Slack uses Socket Mode (an outbound websocket; no inbound endpoint) over a
   small client on the TLS stack already in the program, so no new dependency and no async runtime (ADR 0008). WhatsApp uses
   the Cloud API through one public, signed webhook, with the 24-hour window respected.
4. **Only linked people are heard, and text has a trust level.** A message is acted on only from an account linked to a
   person by a one-time code (Telegram's existing pairing, the same for Slack and WhatsApp). Everyone else gets no answer.
   What a person writes is their instruction. A forwarded or quoted message, what an agent printed, and what was read off a
   terminal are data. Each person is held to twenty messages a minute.
5. **Risky approvals need the passkey.** In a chat an ordinary ask-list command is approved with a button. Anything else
   (protected branch, pull request into one, production, outbound message, spend above the threshold) sends a one-time link
   to the dashboard, which asks the passkey; the chat offers only Deny. The link is random, held only as a keyed hash,
   used once, lapses in ten minutes, is bound to the person, and is worthless after a restart.
   **Amended 2026-11-13 (ADR 0041, build note 50):** a chat app never approves, denies or stops anything, and never raises a spend cap (`/budget`). The ask-list button
   and the Deny button are gone; every request is a message with a link to the dashboard, and `/stop` or `/budget` from a chat app is
   answered with a link. The rest of this item (the link's properties) stands.
6. **Terminal sessions are experimental.** `/sessions` finds agents by program and working folder under `/work/repos`, in
   the box user's own tmux only. `/attach` types one line with `tmux send-keys -l -- <text>` as a single argument, then Enter,
   after re-checking that the pane is still a coding agent (an agent that exited leaves a shell). It is refused unless the
   agent reports it is waiting, unless forced; every message is audited without its text. `/adopt` puts the session on the
   board without restarting it.

**Why.** The two failures to avoid are a chat that lets someone else drive your agents, and a chat that lets an agent
approve itself. Linked people only, text with a trust level, and passkey-only risky approvals close both; reusing the run path
keeps caps, tokens, audit and the board true for chat sessions without a second implementation.

**Costs.** A kept-open session holds a place on its box while it waits for a message. Hooks are installed per engine (by running `ozboxd hooks install` as the box user; it is not run at first boot or on upgrade) and
only where the engine's folder exists. The one exception is the session-record hooks of ADR 0049 (`SessionStart`, `SessionEnd`,
`UserPromptSubmit`, `Stop` for Claude Code), which the box installs at every boot: they keep a record and never ask, deny or report, so the asks
above still come only from the explicit install. A terminal session that reports nothing is shown as "unknown" and needs `force`.
Pending approval links and the dashboard transcript live in memory, so a restart of the server drops them. Slack and WhatsApp
are covered by recorded events and signed test calls, not yet by the real services.
