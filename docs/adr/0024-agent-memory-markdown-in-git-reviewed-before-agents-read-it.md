# 0024 — Agent memory is Markdown in git, searched through SQLite, and reviewed before any agent reads it

**Decision.** Durable memory for agents is a git repository of plain Markdown notes beside the configuration, with a SQLite
full-text index (FTS5) over them.

1. **The files are the truth; the index is disposable.** A note is one `.md` file (a TOML front matter, then Markdown) at
   `entries/<kind>/<name>/<id>.md`. Every change is one commit whose message names the verb, the id, the scope and the actor,
   never the text. The index lives under `.index/` and is not committed; it is rebuilt whenever the repository's head moves, so
   editing, pulling or reverting with ordinary git just works, and losing the index loses nothing.
2. **Scopes are walls.** A note belongs to a person, a project or a box. An agent's session is bound to its person, its box
   and its repositories from the task store, never from anything the agent says; a scope it names that is not bound is refused.
   Absent and not-yours give the same answer.
3. **Agents propose; people approve.** What a person writes is approved at once. What an agent writes is `pending` and invisible
   to every agent, including the one that wrote it, until a person approves it. An agent cannot edit, approve or forget a note
   and cannot spend the review queue (at most 50 proposals wait per scope). Provenance (who wrote it, which task, who approved
   it and when) is part of the file. A note can expire; expired notes are hidden from agents and swept.
4. **No secret is ever stored.** Every write is scanned for the shapes of keys, tokens, private keys, signed tokens,
   `name = value` credentials and long random strings, and refused with the kind (never the text). The scan is a screen, not a
   guarantee: the answer for a real secret is still the encrypted store (ADR 0018).
5. **Memory reaches an agent only through the tool host** (`memory_search`, `memory_read`, `memory_write`; ADR 0020's MCP
   server). What comes back is labelled as recorded notes, data and not instructions. Prompt-injected text in a note is data like
   any other.

**Why.** Memory that agents can write and later read is a way for one run to instruct the next, and for a poisoned page or a
mistaken guess to become standing policy. Review in between, scopes that cannot be talked past, and a store a person can read,
diff and revert make that safe enough to be useful. Git gives history and rollback for free; SQLite gives fast search without a
service.

**Cost.** SQLite is built from source into the program (a C compiler is needed to build Oz Box, as before for the TLS stack's
build tools). Notes are small by design (8 KB, 500 per scope). Two computers each keep their own memory repository; sharing one
across computers is `git pull` and `git push` by a person, not a feature of this decision.

**Amended by [0056](0056-one-conversation-fabric-agents-people-groups-and-fleets-post-to-mailboxes-on-the-hub-and-a-message-is-data.md) (2026-11-17, Preview).** An agent on a worker box reads the memory walls it is bound to through the
same tools: the hub sends that box only the **approved** notes of the `person:`, `box:` and `project:` walls its own agents may
read, with who wrote each note, on which box, and who reviewed it. An agent there still only proposes: its `memory_write` travels to
the hub and is filed pending, credited to the agent's fabric address and box, for a person to review here. The scopes and the review
are unchanged; a note's provenance gains the box it was written on.
