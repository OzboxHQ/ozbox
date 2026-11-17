# 0056 — One conversation fabric: agents, people, groups and fleets post to mailboxes on the hub, and a message is data

**Status.** Accepted; **built as Preview** (2026-11-17, `feat/hub-h6-fabric`, not merged). Built and tested with a hub and two
workers over the in-memory transport and test crypto, and through the same MCP tools a run calls; **not run on a real box**, and
**not yet attached to a box's server**: the hub's daemon (ADR 0042, phase H2) and the network transport (H3) attach it, and the
integration harness (H4) runs the same scenarios over the real transport, signer and sealer. It leaves Preview with B4-19's real run.
Related: ADR 0020 (orchestration), 0021 (chat), 0024 (memory), 0025 (skills), 0041 (approvals), 0042 (the hub), 0043 (the agent's
socket), 0044 (the mesh: a message can ask and never grant), 0050 (Telegram).

**Owner's goal (2026-11-17).** Agents get and post messages between themselves, with memory and skills wired to them end to end,
across boxes, engines and model providers, and a person on Telegram or WhatsApp talks to them the same way.

## Context

Agents could already reach the Oz Box tools through a socket of their own (ADR 0043), read reviewed memory and skills on the box
they run on (ADR 0024, 0025), and a conductor could message its workers through the orchestration's mailbox (ADR 0020). But two
agents on two boxes had no way to talk unless one was the other's conductor; a worker could not read the project memory another box
had written; and a chat (ADR 0050) reached one session at a time through the gateway, not a participant that could answer back on
its own. The worker channel (ADR 0042) and the mesh (ADR 0044) give a signed, sealed, ordered link between two pinned ends; neither
is a place where messages wait for whoever they are for.

## Decision

1. **One fabric, with stable addresses.** A participant is `agent:<box>/<session>`, `person:<id>`, `group:<name>` or
   `fleet:<name>`. An agent's engine and model provider are attributes of its record, never part of its address, so a Claude Code
   session and a Codex one are addressed the same way and either can be replaced without renaming anything.
2. **Mailboxes live on the hub.** One ordered mailbox per participant, with a cursor (`after`) and a long-poll (at most 25
   seconds), threads, and per-recipient delivery states: `queued` (on the sender's box), `accepted` (stored on the hub),
   `delivered` (fetched), `read` (acknowledged), `expired` (retention ended unread), `refused` (a post queued on a worker that
   the hub refused, with its reason). A group or fleet fans out to its members when the message is posted.
3. **One door per box, the same tools for every engine.** Every agent calls five MCP tools through the tool host it already has
   (a run's token, or the ADR 0043 socket): `messages_post`, `messages_get`, `messages_thread`, `messages_ack`,
   `participants_list` (the fabric's names are `messages.post` and so on; MCP names use `_` because engines refuse a dot). An
   agent's address is made by the tool host from its session (its run, its terminal session code, or its orchestration task),
   its person, projects and delegation from the task store, its engine and provider from the run's record. Nothing the agent
   says changes any of these.
4. **Who sees whom.** An agent sees itself, its person, the agents of the **same person** that share its box or one of its
   projects, the groups and fleets of its person that list it, and what its orchestration delegates (a conductor's workers, a
   worker's conductor). A person sees every participant that acts for them. Posting needs sight; reading is one's own mailbox only;
   nothing crosses from one person's participants to another's. On the hub a caller's reach is taken from its **registered**
   record, so a caller that claims more projects gets only what it registered.
5. **Across boxes, a profile of the channel.** The fabric is its own profile of the shared channel (domain tag
   `ozbox-fabric-envelope-v1`, eight `fabric.*` kinds), carried by the hub's transport under endpoint names of its own
   (`<box>.fabric`; a box name has no dot, so these never collide with the worker channel). The envelope, sealing, signing, order,
   replay and acknowledgement are the channel's, through its signer, verifier and sealer seams. A worker keeps a replica of its own
   agents' mailboxes and queues their posts; the hub holds the authority and checks every frame again. **A worker speaks only for
   the agents homed on it**: the hub refuses a registration, a post, a receipt or a proposal that names another box's agent.
6. **Messages are data, never instructions or grants (ADR 0044).** The fabric has no operation that approves a request, releases a
   key or changes a policy, and its profile has no kind that could carry one (`approval.decision`, `keys.deliver`, `pins.set` are
   not fabric kinds and are refused). Every message an agent reads comes with a note that says so. An agent that needs a decision
   asks through ADR 0041, and a person decides it.
7. **Screened and bounded.** Text is cleaned of control and format characters, capped at 8 KB, and refused by the kind of thing it
   looks like when it looks like a key (the screen agent memory uses); it is never stored or echoed. A post reaches at most 20
   participants; a sender posts at most 30 a minute and 600 a day; a mailbox holds at most 5,000. Retention: a read message 30
   days, an unread one 90 (its sender then sees `expired`).
8. **Memory and skills on every box (amends ADR 0024 and 0025).** The hub's memory and skills stores stay the authority. The hub
   sends each worker only the **approved** notes and **approved** skills of the walls that worker's own agents may read (`person:`
   of their person, `box:` of that box, `project:` of their projects), with provenance (who wrote it, on which box, who reviewed
   it). The worker answers the same five memory tools from that replica with the same rule, checks each skill's text against its
   digest before serving it, and forwards an agent's `memory_write` to the hub, where it is filed **pending** and credited to the
   agent's fabric address and box, for a person to review as today. The scoping is unchanged.
9. **Chat is a participant (amends ADR 0050).** The chat gateway resolves `@agent`, `@box`, `@group` and `@fleet` under the
   person's delegation, then calls `fabric::bridge::post_from_chat` as the person; the chat it came from is subscribed to replies.
   `pull_replies` returns each reply addressed to every chat the person hears in, attributed by the registry ("alpha on box-a
   (codex · openai)"), and acknowledges it so it is shown once. The gateway renders it through its notice model as a reply. A chat
   message is data like any other and approves nothing.

## Consequences

- Two agents on two boxes, on different engines and providers, talk through the same five tools, and a person can join from a chat.
- Shared project memory written on one box is read on another after a person reviews it, with the box it came from.
- The hub's state grows with mailboxes; retention and the caps bound it. Every call on the hub routes what changed to the workers.
- **Benchmark:** none of the measured paths changes. The fabric is not on box create, resume, snapshot or destroy, not on `exec`,
  disk or network setup, and an agent's commands do not pass through it; a messaging tool call is one local lock and, on a worker,
  one queued frame. The pump that moves frames between boxes is the transport's (H3), outside the command path.

## What is not covered

- **Not attached to a server yet:** no box runs a fabric end until the hub's daemon (H2) does; the tools answer "agent messaging is
  not set up on this box" until then. No CLI command or dashboard page shows the mailboxes yet.
- **The network transport, the real signer and sealer** are H2's and H3's; this record is proven with the in-memory transport and
  test crypto. H4 re-runs the scenarios over the real ones.
- **Participants are registered on first use**, not discovered: an agent appears to others once it has called a messaging tool.
- **Groups and fleets are listed by hand** on the hub; a fleet that follows the person's boxes automatically is not built.
- **Only `SKILL.md` travels** to a worker; a skill's other files stay on the hub.
- **The hub reads the memory and skills stores every minute** (or when told a review happened) to refresh the walls; a note approved
  on the hub reaches the workers within that minute, not at once.
- **A person's own agent** (the agent a person connected from their computer) is not a participant: it is told to write as the
  person from a chat or the dashboard.
- **Not run on a real box.**
