# Chat with your coding agents

Talk to a coding agent on one of your boxes from the dashboard, Telegram, Slack or WhatsApp: start a session, follow
it, answer it, and decide what it asks in the dashboard. You do not need a web IDE open. The agent is the same supervised run as in
[Agentic fleet](agentic-fleet.md): it is on the board, capped, logged, saves its work to a branch and asks before
anything risky.

See [how to read the status](README.md#how-to-read-the-status). Everything below is **Preview** at most: built and
covered by tests (the dashboard chat and the Telegram path are also covered by browser tests against the simulated
agent), not yet exercised on a real cloud box. Slack and WhatsApp are tested against recorded events and signed test
calls, not against the real services. Typing into a terminal session is marked **experimental** everywhere it appears
([ADR 0021](../adr/0021-chat-with-coding-agents.md)).

---

## 1. Start a session from your phone

**You want:** a coding agent working while you are away from your laptop.

In the dashboard open **Chat**, or message your bot:

```
/new main fix the flaky checkout test and open a pull request
```

Then write each next message as plain text. The agent's answers come back short, with secrets removed; ask `/log` or
open the dashboard for more.

**Underneath:** `/new` starts a *supervised interactive session*: Claude Code running headless with streamed input and
output kept open, through the box daemon like any run, so it has the same caps, per-run token, live log and WIP branch,
and it is a task on the board. Each message is one more turn of the same conversation.
**Status:** Preview.

## 2. Commands

| Message | Does |
|---|---|
| `/run <box> <what to do>` (or `/new`) | start a session and follow it; `/run <what to do>` uses the box this chat follows |
| plain text | the next turn of the session this chat follows |
| `/status`, `/log` | where it is, and its last log lines |
| `/pause`, `/resume` | save its work and stop it; continue the same conversation later |
| `/stop` | stop it (its work is saved first). **In the dashboard's Chat only:** Telegram, Slack and WhatsApp answer with a link to the dashboard and stop nothing |
| `/budget +5` | add five dollars to its spend limit. **In the dashboard's Chat only**, like `/stop`: a chat app answers with a link and changes nothing |
| `/tasks`, `/switch <task>` | your sessions; follow another one |
| `/sessions`, `/attach <session>`, `/adopt <session>`, `/detach` | agents in your own terminals (see 5) |
| `/fleet`, `/box list`, `/whoami`, `/help` | Telegram: the boxes and their state, who this link is and what it may do, and what a chat can do |
| `@<box> <message>`, `@<box>/<session> <message>`, `@<group> …`, `@fleet …` | Telegram: talk to the agent on a box, one session, a group of boxes or every box you may reach; each reply names its box and session |
| `/to <address>`, `/who`, `/boxes`, `/fleets` | Telegram: where plain messages go from now on, where they go now, and what you may reach |
| `/box resume`, `/box pause`, `/box extend`, `/box create`, `/box resize` | Telegram: box power, planned first and done only inside the limits you allowed with a passkey |
| `/lock`, `/unlink` | Telegram: make this link read-only until a passkey lifts the lock, or cut it. Anyone linked may; they only make Telegram less able |

**In Telegram, talking to an agent is something you allow in the dashboard first**, with a passkey, for each box and for a few days
at a time: see [Control your boxes from Telegram](telegram-control.md). Reading (`/status`, `/fleet`, `/tasks`, `/log`) needs nothing
beyond a link. Slack and WhatsApp go through the same rules, and also understand `@<box>`, `@<box>/<session>`, `@<group>`, `@fleet`, `/to`, `/who`,
`/boxes`, `/fleets` and `/run` ([section 3a there](telegram-control.md#3a-talk-to-a-box-an-agent-or-a-fleet)); box power is
Telegram's only.

**Status:** Preview.

## 3. Be told in the chat, decide in the dashboard

**You want:** to know when an agent stopped to ask, or a change on a box waits for a person, and to land on it in one tap.

Every message that asks for a person reads the same way on every channel: a title that starts with what to do, what is asked
in plain words, where (box, project, environment, with a **PRODUCTION** badge), who or what asked and why, the risk, when it
expires, one link to exactly that item in the dashboard, and a short reference you can quote. On Telegram it looks like this:

```
🔐 Approve or deny: guard override
A change was filed on a box and waits for a person with the right role.

Box main · Project shop · Environment staging
Hook: commit (pre-commit)
Asked by: box-user (uid 1000)
⚠️ Risk: Skips the secret scan for one commit.
⏳ Expires in 2 h 5 min

This message only tells you. Nothing in a chat approves, denies or cancels: decide in the dashboard, with your passkey.
Open it on dash.example.com. The link works once, only for you, for 10 minutes; after that, open the dashboard → Approvals.
Ref R1a2b3c4
[ Open in dashboard ]
```

The button under it only opens the dashboard on that request. Slack shows the same as blocks with a link button, Discord as
an embed, Teams as a card, email as a short page with a button and a plain-text copy, WhatsApp as one paragraph with the link,
an SMS as one line (`Oz Box: Approve or deny: guard override (main). Open: https://dash.example.com/go#… Ref R1a2b3c4`), and a
push notification opens the request when you tap it.

**A chat only tells you, for every kind of request:** no button approves or denies, and nothing said or pressed in a chat
approves, denies or cancels, stops or raises the spend limit of anything. The decision and who made it are in **Activity**. The
server refuses the act, so this does not depend on a button being missing.

**Underneath:** the link is made for each person when the message is sent: 24 random bytes held only as a keyed hash, for ten
minutes, for that person only, and it stops working if the server restarts. Opening it changes nothing (you can open it in
Telegram's browser and then your own). An agent's question links to **Chat**, where the request opens with Approve and Deny;
that link is spent when the page opens it. The token is always in the part of the address after `#`, which your browser never
sends to any server. Once the request is decided, the link says it was used. A shared place (a Slack channel,
an email list, a webhook) gets the request's own address instead, which asks you to sign in. When the dashboard has no public
address the message says "Open your dashboard → Approvals" rather than leave the link out silently. Other alerts (a full disk,
memory, the budget) link to their box or page the same way. No key, token, value or long agent output is ever in a message.
**Status:** Preview.

## 3a. Where the dashboard's conversation is kept

The conversation shown on the dashboard's **Chat** page is kept in the dashboard's memory, not on disk: the last 200 lines,
shown only to the person it belongs to, and gone when the dashboard restarts. The session itself and its answers stay in
**Tasks**. The page says so under the conversation. On a demo server the page also says the agent is a stand-in.

## 4. Only you are heard

Only people you have linked can talk to your agents. **Telegram is linked from your Account page with a passkey**, the other way
round from the other apps: you open a pairing window, the bot answers `/link` only while it is open, and you type its code back
and confirm with a second passkey ([the steps](telegram-control.md)). A chat linked the old way keeps receiving alerts and may read,
and must be linked again to do more. For Slack and WhatsApp, **Chat → Other chats** gives a one-time code to send to the bot in a
direct message. A message from anyone else gets no answer. A forwarded or quoted message is treated as someone else's words, not an instruction. Each person is held to twenty
messages a minute. No key or token is ever sent to a chat, and what an agent printed is shown to you, never obeyed.

**Status:** Preview.

## 5. Agents already running in your terminals (experimental)

**You want:** to talk to the Claude Code, Codex, Gemini CLI, Aider or OpenCode session you left running in tmux.

```
/sessions               which coding agents are running in your repos, with engine, repo, branch and what Oz Box can see
/attach main:%3         type your next messages into that terminal; what it prints comes back, shortened
/adopt main:%3          put it on the board as a task, without restarting it
```

Oz Box finds agents by program and working folder (under `/work/repos`), only yours. Each engine is reached the best way
it offers: Claude Code and Gemini CLI report "needs input", "finished" and permission requests through hooks; Codex and
Aider report that they finished or wait for input; the rest are plain terminals ("basic": nothing is reported, so a
session you have not attached to is shown as "unknown"). Typing is refused while an agent is not waiting for input unless
you add the word `force`, goes in as one line of text (never a shell command), and every message is audited without its text.

**A chat app never answers an agent's own question.** A line typed into a terminal would answer whatever that terminal is
asking, such as Claude Code's "Allow this command?". So Telegram, Slack and WhatsApp may type only into an agent that
reports its own questions (Claude Code and Gemini CLI, through hooks), never with `force`, and never while the agent is at a
permission prompt, an MCP question or any notice Oz Box does not recognise: they answer with a link to the dashboard and type
nothing. This is decided for each terminal on its own (another agent in the same repository finishing does not unlock it), and an
agent whose hooks have not reported from that terminal yet is not typed into. A Gemini CLI set up before this release needs its
hooks installed again before a chat app can type into it. The dashboard's own Chat keeps `force`.

**A chat app never borrows an agent's own permissions.** A line typed into a terminal runs with whatever that agent may
already do without asking, so a chat app may type only into a Claude Code session that asks before it does anything beyond
reading. These are refused, with a link to the dashboard and a reason you can read:

- a session in `auto`, `accept edits`, `don't ask` or `bypass permissions` mode, whether heard from its hooks or read from the
  bottom of its screen (the last screenful, so a long status line does not hide it);
- one started with a flag that skips or widens its permissions, hands its questions to another program
  (`--permission-prompt-tool`), loads a plugin, or names a settings file;
- one with an allow rule beyond reading files, a `defaultMode` other than the default, a sandbox that runs commands without
  asking, plan mode that hands over to auto mode, or a hook of its own that can answer a permission question, in your user,
  project or local Claude settings, in the folder `CLAUDE_CONFIG_DIR` points to, or in the managed settings
  (`/etc/claude-code/managed-settings.json` and the files in `managed-settings.d`);
- one that "may do things without asking" is told apart from one Oz Box "cannot tell" about: a session it has not heard from yet,
  one whose process or settings could not be read, one with plugins enabled (their hooks are not visible from here), and one of
  any engine other than Claude Code.

Oz Box's own allow rules and standing permissions are not read from the session's files: a standing permission never reaches a
chat app, and a run's mode is held to `ask` for a chat app (below).

**A chat app never types a line that starts with `!`, `#`, `&` or `/`.** Claude Code acts on those itself, whatever its
permission mode: `!` runs the rest as a shell command, `#` writes a memory note, `&` starts a background task, and `/` is a slash
command (a custom one can pre-approve tools). Both the server and the box's agent service refuse such a line from a chat app, so
neither relies on the other; the refusal says why and is audited without your message. Write the request as a sentence, or use the
dashboard.

The same holds for a message to a run on the board whose mode is `auto` or `accept edits`, or that a standing permission covers.
A run you start from a chat app is launched in Claude Code's `default` permission mode, not accept-edits, and no standing
permission applies to it. A run has no terminal to ask in, so what Claude Code would ask about is refused (a call that needs
approval is denied unless a hook or a prompt tool approves it): it does not edit files, and it runs only its read-only commands,
plus whatever the Claude settings of the box user already allow, a sandbox that runs commands for it, and the commands Oz Box's own
hook asks you about on the board. It does not ask you in the chat for an edit. A run that changes code is started from the dashboard.
A run started from the dashboard, by a schedule or by a trigger keeps its own mode, which for a dashboard run is accept-edits: a
chat app may still send such a run a message while its Oz Box mode is `ask`, and the run edits as it was started to.

What this does not cover:

- A line already typed keeps its turn if the mode is raised while it runs: that is your own act at the terminal.
- A line left half-typed in the agent's input box is joined with what a chat app types next, so a `!` left there makes the next
  line a shell command. Clear the prompt before you leave a terminal for a chat app.
- The classification of each session is kept for a few seconds in the list the dashboard and `/attach` read; every send looks
  again, so the keystroke that changes a mode is caught at the next send from the bottom of the screen even before Oz Box hears it.
- A box running an older Oz Box service reports no authority, so it is refused as unknown until it is updated. After a rollback the
  other way, a server older than this release cannot read a task book that holds a run started from a chat app, and the dashboard's
  own Chat is treated as a chat app by a newer box service until the server is updated too: back up the task book, and finish or
  stop those runs before rolling the server back.

Each refusal is audited with the session and the reason, never your message. The dashboard's own Chat is not held to any of this.

Without a public address the link is words ("open the dashboard"), not a path that opens nothing; **Settings → Apps** and
Chat say so when the address is missing.

**Status:** Preview, experimental.

## 6. Set up Slack and WhatsApp

Both are bring-your-own, in **Settings → Apps → Chat with coding agents**.

- **Slack:** your own Slack app with Socket Mode on. Save its app token and bot token (write-only), switch it on, link
  yourself with the code. The server opens one outbound websocket to Slack; nothing listens for Slack.
- **WhatsApp:** your own WhatsApp Business number. Save the app secret and a verify token, set the webhook in Meta to
  `https://<your dashboard address>/hooks/chat/whatsapp`, and link your number with the code. A message is accepted only
  with a valid signature, and only once. WhatsApp allows free-form replies for 24 hours after your last message; after that
  only an approved template can be sent, so a reply is held and you are told on your next message.

**Status:** Preview.
