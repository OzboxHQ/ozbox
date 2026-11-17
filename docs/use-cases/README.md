# Use cases

Well over a hundred worked examples of what Oz Box is for, in seventeen guides: for people who build software, and for
business, finance, creative and education work. Each example says what you want, the steps in the
dashboard and on the command line, what happens underneath, and how mature that path is.

| Guide | For |
|---|---|
| [One box](one-box.md) | one cloud workstation you code on, from anywhere |
| [Coding from anywhere](coding-from-anywhere.md) | web IDE, desktop editors, terminals that keep running, your own domain |
| [Fleets](fleets.md) | many boxes: per project, throwaway clones, budgets, a test lane |
| [Agentic fleet](agentic-fleet.md) | coding agents running supervised on your boxes: tasks, caps, approvals, schedules, triggers |
| [A task channel](task-channel.md) | your computer and a box pass questions, answers and status as signed tasks with a state and an audit record, not notes |
| [Agents talk to each other and to you](agents-talk.md) | agents on any box and engine message each other, share reviewed memory and skills, and answer you on Telegram or WhatsApp; a message never approves anything (Preview) |
| [Skills for your agents](skills.md) | your own skills, reviewed and approved before any agent sees one, and put on a box's disk for its coding agents |
| [Orchestrating a fleet](orchestrating-a-fleet.md) | one agent hands features to worker boxes: claims, contracts, a mailbox, a merge queue, rules files |
| [A secure workspace for AI agents](secure-agent-workspace.md) | an agent with no keys in reach, a limited network, ask-mode, Production out of reach, an audit log, spend limits, and when a per-request sandbox fits better |
| [Control your boxes from Telegram](telegram-control.md) | link a Telegram account with a passkey, allow a phone to talk to agents on chosen boxes, lock or cut it at any time; a chat never approves anything (Preview) |
| [Chat with your coding agents](chat.md) | talk to agents from the dashboard, Telegram, Slack or WhatsApp: start, follow, answer, approve |
| [Models and routing](models-and-routing.md) | your own model keys and cloud accounts, which engine uses which model, which engines run on a box, agents on different engines working one task, local models, spend |
| [Keeping boxes healthy](keeping-boxes-healthy.md) | upgrades, backups, restores, resizing, self-test, recovery |
| [Alerts, costs and guardrails](alerts-costs-guardrails.md) | notifications and routing, budgets and the real bill, secrets, security |
| [A browser for your agent](browser-on-the-box.md) | an agent that uses a real browser: approvals before it submits or pays, a person for CAPTCHAs, live view, take-over, replay |
| [Business and operations](business-operations.md) | inbox triage, weekly reports, market watch, proposals, support drafts, contracts, a private team assistant |
| [Finance and accounting](finance.md) | month-end reconciliation, invoices, expenses, forecasts, board packs, audit prep — the agent never moves money |
| [Creatives and media](creatives.md) | content in your voice, research packs, transcripts and show notes, media libraries, batch exports, applications |
| [Education](education.md) | course materials, quizzes, feedback drafts, admin, accessible materials, disposable lab machines — the teacher decides |

## How to read the status

Oz Box is in **Beta** (0.2.0-beta.0): the single box is real, but a feature marked **Preview** is built and tested, not yet proven on a real box. Every example carries one of these marks, and we update them as things are proven:

- **Works** — built, covered by the test suite, and exercised on a real cloud box.
- **Preview** — built and covered by the test suite (including browser tests of the dashboard), not yet exercised end to
  end on a real cloud box. Expect rough edges.
- **Planned** — designed, not built yet. Shown so you can see where it is going.

## Conventions

- Box names in the examples (`main`, `api`, `exp-1`) are yours to choose. Addresses use `example.com`.
- Every change is **plan, then apply**: the command or the dashboard shows exactly what will happen and asks before it
  does it. `--dry-run` stops after the plan; `--yes` skips the question (for scripts). Anything that cannot be undone asks
  you to type the box name.
- Everything is **bring your own**: your cloud account, your domain, your model keys, your notification accounts. Oz Box
  ships no shared app, key or server.
- Boxes have **no open inbound ports**, not even SSH. Every way in goes out through the provider's own session service or
  your tunnel ([ADR 0005](../adr/0005-no-inbound-network.md)).
- Run `ozbox <command> --help` for every option of a command.
