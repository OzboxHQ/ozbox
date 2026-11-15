# 0022 — One permission engine, time-boxed Production grants, and a hash-chained audit log

**Decision.** Every actor that can change something goes through one function, `permissions::decide`: the dashboard, the
command line, the MCP tools, the chat gateway and the run supervisor. It answers allow, ask or deny, with a stable reason and
the rule that decided. It is pure (configuration, a description of the situation, an action and a clock in; a decision out),
so every path is tested without a box, a network or a clock.

1. **Actions and situations.** An action is one of a fixed vocabulary (`file.read`, `file.write`, `command.run`, `git.push`,
   `pr.open`, `message.send`, `spend`, `resource.touch`, `run.start`, `run.stop`, `box.create`, `box.change`, `box.destroy`,
   `secret.use`, `secret.write`, `approval.decide`, `settings.change`, `grant.create`, `tool.call`). A situation names the
   person, who is acting (person, agent, chat, MCP, schedule, trigger), the box, project, run and orchestration, the
   environment (sandbox, staging, production), a path, a command, and for a tool call the tool, its server and whether it
   reads or writes. A tool call whose effect is unknown counts as a write. Nothing in the engine has to change to add an
   MCP tool: it is `tool.call` with those names.
2. **The order is the design.** (1) A matching **deny rule** wins, whatever else matches and whatever the mode. (2) **Production
   needs a grant**: any action that changes something on production is refused unless an active grant covers it. (3)
   **Plan only** refuses every change. (4) The **most specific matching rule** decides: narrower scope first (person, box,
   project, orchestration, run), then more conditions, then more literal pattern text; at equal specificity ask beats allow.
   (5) With no rule, the **mode** decides.
3. **Modes** are Ask (the default: routine things go ahead, what the approval policy singles out and everything unusual
   asks), Plan only (reads), Accept edits (Ask, plus file edits) and Auto (everything except what always needs a person:
   messages out, spending, secrets, settings, destroying a box, granting). Auto never applies to a run a schedule or trigger
   started: nobody is watching it. A mode can be set per box, project, orchestration or run; the narrowest wins.
4. **Production grants** are short and cannot be stretched. A grant is bound to one box, project, run or orchestration
   (never everything), names the actions it covers, carries a reason of at least eight characters and lasts from one minute to
   four hours. Its expiry is fixed when it is made and nothing moves it: more time is a new grant, a new record. It can be
   limited to a number of uses, it does not reach a schedule or trigger unless it says so, and revoking it takes effect
   at once. It records how it was confirmed, honestly: **a passkey or authenticator code shown moments ago** to the sign-in
   layer, a **typed confirmation** (the command line, and the dashboard when signed out, where the name of what is covered is
   typed back), or **no sign-in**. The last two are labelled "not a second factor" wherever they are shown. Approving an agent's
   request on production in the moment makes a one-use grant that is spent at once, so the record of what was let through
   has one shape.
5. **The approval policy is an input, not a rival.** What the approval policy singles out (a protected branch, an ask-list
   command, spend above a threshold) reaches the engine as `sensitive` and still asks, unless a rule says otherwise. The
   production flag of the old policy is now the engine's own gate.
6. **The audit log is a hash chain.** One append-only file of JSON lines beside the task store. Each entry carries the hash
   (SHA-256) of the entry before it; every fifty entries, or ten minutes, a checkpoint line records the sequence number and head
   hash with an HMAC tag under a seal key, and a copy goes to an anchor file. `verify` names entries that were **changed**,
   **missing** (a gap in the sequence), **out of order**, checkpoints that **do not verify**, a log that **ends before a
   sealed point**, and lines that cannot be read, in the dashboard, the API and `ozbox audit verify` (non-zero exit on failure).
   Entries after the last checkpoint are reported as not yet sealed, not as wrong.
7. **Everything goes in.** Every record the task store makes (run queued, started, paused, failed; approval requested,
   approved, denied, expired; policy and limit changes; orchestration events) is copied into the chain inside the same locked
   write that saves the store, first: if the chain cannot be written nothing is saved, so a change is never kept without its
   record. A record is chained once even if a write is retried (each carries its store's epoch and number). Permission
   decisions, grants (made, used, revoked), box lifecycle and settings changes are written too. An entry holds ids and action
   words only: never a secret value, a prompt, a command line (the text of an approval stays on the approval) or the reason
   typed into a grant (it stays on the grant).

**Why.** Before this, "may this happen?" was answered in a dozen places with different rules, production was a flag that only
made an approval ask, and the audit trail was a bounded list in a JSON file that any edit could change without a trace. A
single engine makes a rule mean the same thing on every surface; a grant makes "I let it touch production for twenty minutes
because of X" a record rather than a memory; a chain makes an edit visible.

**Consequences and what is not covered.**
- **Closed by ADR 0028.** The chain used to be written by the box user, with the seal key beside it, so a process that read the key
  could rewrite the whole chain and have it verify. On a box the chain is now written only by the secrets service (a system
  user with its own folder), the seal key is a secret in its store, and writers send it events over a socket. The box user can
  read the chain and ask for it to be checked, and cannot alter, remove or seal anything. A laptop with no such service still
  writes its own file and still has only the detection this ADR first described. What remains: the box user can still add a
  well-formed event of its own until the next checkpoint, and entries sealed before an upgrade were sealed under a key the box
  user could have read (the `audit.migrated` entry's head hash is what to pin).
- Box lifecycle and settings entries are written after the action and are best effort (the change has happened); the check
  reports a missing record as a gap in the sequence only for entries the chain did receive.
- Call sites that still decide for themselves, in addition to the engine, are listed in the project plan; they are stricter than
  the engine and kept on purpose until the engine has an equivalent rule.
- A signed-out dashboard cannot ask for a second factor. It makes the person type the name of what a grant covers and says so.
