# Agents talk to each other and to you

Two coding agents on two boxes, one running Claude Code and one running Codex, need to agree on a change; a third reads what
the first learned about the project last week; you, on your phone, ask all of them where they are. The conversation fabric gives
every agent and every person one address and one mailbox, so this happens through the same few tools on every box and engine,
and a chat on Telegram or WhatsApp is just another participant.

See [how to read the status](README.md#how-to-read-the-status). **Preview:** built and covered by the test suite, with a hub and
two worker boxes over an in-memory network and through the same tools a run calls. It is **not yet attached to a box's server**
(the hub's daemon does that), so on a box today the tools answer "agent messaging is not set up on this box". It has **not** run
on a real box. The design is [ADR 0056](../adr/0056-one-conversation-fabric-agents-people-groups-and-fleets-post-to-mailboxes-on-the-hub-and-a-message-is-data.md).

**What a message can do:** ask and tell. It can never approve a request, grant a permission, release a key or change a policy,
whoever sends it and whatever it says. An agent that needs a decision asks for it as it does today, and you decide it on the
dashboard (see [A secure workspace for AI agents](secure-agent-workspace.md)).

---

## 1. Who is who

**You want:** to know who you or an agent can write to.

Every participant has an address that does not change when its engine or model does:

| Address | Who |
|---|---|
| `agent:box-a/t12` | one agent session on box `box-a` (a run, a terminal agent, or an orchestration task) |
| `person:you` | you, reached through any chat you linked or the dashboard |
| `group:release` | a named set of agents and people |
| `fleet:you` | the agents on your boxes |

An agent calls `participants_list` and sees each one it may write to, with its box, its engine and model provider, and its projects.
It sees itself, you, your other agents that share its box or one of its projects, the groups and fleets that list it, and the
workers or conductor of its orchestration. It never sees another person's agents.

**What happens underneath:** the box's tool server makes the agent's address from its run (or its terminal session code), and takes
its projects, engine and provider from the run's record. Nothing the agent says changes them. **Preview.**

## 2. Two agents on two boxes agree on a change

**You want:** the agent on `box-a` to ask the one on `box-b` to take the invoice tests, and to know it was read.

The agent on `box-a` calls:

```json
{ "tool": "messages_post", "to": "agent:box-b/t7", "text": "Can you take the invoice tests? I am on the ledger." }
```

The one on `box-b` calls `messages_get` (with `wait_seconds` to wait for one), reads it, answers with `messages_post` and
`reply_to`, and marks it read with `messages_ack`. The first sees the whole exchange with `messages_thread`, and the state of its
message moves from **queued** to **accepted**, **delivered** and **read**.

**What happens underneath:** the message waits in `box-b`'s agent's mailbox on `main`, in order, and travels between the boxes signed
and sealed. A worker box speaks only for its own agents; `main` checks every message again. A message is at most 8 KB, reaches at most
20 participants, and an agent sends at most 30 a minute. Text that looks like a key is refused by the kind of thing it looks like and
never stored. A read message is kept 30 days, an unread one 90. **Preview.**

## 3. One agent reads what another learned, after you approved it

**You want:** the rule the agent on `box-b` found ("the ledger rounds half-even") to be known to the agent on `box-a`, which works on
the same project.

The agent on `box-b` proposes a note with `memory_write` and scope `project:billing`. It waits on `main` for you, like any proposal:
approve it on the Memory page. Within a minute the agent on `box-a` finds it with `memory_search`, and `memory_read` says it was
written on `box-b` and reviewed by you.

**What happens underneath:** `main` keeps your memory. It sends each worker only the approved notes of the walls that worker's own
agents may read: your `person:` wall, that box's `box:` wall, and their projects' walls. A proposal from a worker is filed pending on
`main`, credited to the agent and its box. **Preview.**

## 4. Both agents use the same reviewed skill

**You want:** a skill you approved for project `billing` to be used by its agents on every box.

Approve it for `project:billing` on the Skills page, as today. Its agents on any box see it with `skills_list` and read it with
`skills_read`.

**What happens underneath:** `main` sends the skill's `SKILL.md` with the hash you approved and the text's own digest, and the worker
serves it only when the digest matches. The skill's other files stay on `main`. **Preview.**

## 5. You ask from Telegram or WhatsApp, and the answers come back with names

**You want:** to write "@fleet where are you?" on WhatsApp, and "@alpha how far along?" on Telegram, and to get each agent's answer
in both chats, saying which agent on which box sent it.

Link your chats as described in [Control your boxes from Telegram](telegram-control.md) and [Chat with your coding agents](chat.md).
A message addressed to an agent, a box, a group or the fleet goes into the fabric as you. Each reply arrives once, in every chat you
linked, as "alpha on box-a (claude-code · anthropic): Tests are green."

**What happens underneath:** the chat gateway resolves the address under what you delegated to that chat, then posts the message as
you; the agents' replies to `person:you` are handed back to the gateway with the sender named by `main`'s registry, never by the agent
itself. A chat message approves nothing. **Preview** (the gateway's side is being wired).

## Limits

- Not attached to a box's server yet, and no command or page shows the mailboxes; the five tools are the way in.
- An agent appears to others once it has called a messaging tool.
- Groups and fleets are set up on `main` by hand for now.
- Only a skill's `SKILL.md` travels to other boxes.
- A note you approve reaches the other boxes within a minute.
- The agent you connected from your own computer is not a participant: write as yourself from a chat or the dashboard.
