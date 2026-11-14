# 0044 — The agent mesh: one typed task channel, a message can ask and never grant, and the first channel runs between a person's laptop and `main`

**Status.** Proposed; **first slice built as Preview** (2026-11-14, `feat/agent-mesh`, not merged). The format is **not frozen**. **The design and
the starting limits are owner-ratified 2026-11-15** (D2), and the mesh **leaves Preview when the real-box proof passes**; the owner decided
(D15, 2026-11-15) that a second, independent security review is not required.
**Built:** the laptop-to-`main` task channel in `ozbox_core::agent_mesh` and `ozbox tasks`: a versioned, signed, sealed envelope; tasks
with messages, status and artifacts; ordering, de-duplication, replay and restore defences; a durable store with an outbox; an audit
trail; a key-shape screen; and a command transport. Run against fakes and a real binary in CI; **not run on a real box**.
**Not built:** the approval path to the laptop (acts are refused by name), the stream transport, the hub's sealed channel, the
directory and agent cards, the model gateway, chat rooms, the fleet view, the separate service user for the router, and the public
A2A endpoint. This ADR is the core only; those are later records.

It joins ADR 0020 (orchestration), ADR 0021 (chat with coding agents), ADR 0039 (roles), ADR 0041 (one approval model) and ADR 0042
(`main` as the hub). It does not change how a Production value is released (ADR 0029).

**Owner's goal (2026-11-13).** Agents on every box talk to each other without friction, across boxes, engines and model providers
(including self-hosted ones), and a person can see and steer them. Everything is open source; a later managed offering sells hosting
and support, never features. The order chosen: the direct laptop-to-`main` channel first, because it removes a measured pain and
exercises the trust rules against the hardest receiver with no model work.

## Context

Work between a laptop and `main` moved as Markdown notes in a home folder, a person saying "`main` has a message", and SSH plus `cat`.
One release took seven hand-relayed messages, three SSH timeouts and a fresh approval each time, because "owner approved" written in a
note cannot be checked. Nothing had a state, an acknowledgement or an audit record. Orchestration (ADR 0020), chat (ADR 0021) and the
approval model (ADR 0041) each carry some messages in their own way. One protocol with a few kinds of participant does not drift.

## Decision

The mesh is a **control plane for tasks**. It carries who asked whom for what, the state of the work and its results. It never carries a
command that skips a check. The receiver decides, from facts it verified itself.

### 1. Identity: pinned peers, no directory yet

Each endpoint has a name, an Ed25519 signing key and an X25519 sealing key (`ozbox tasks init`). The other side's public keys are
**pinned** by a person who compared fingerprints by a way that is not this channel (`ozbox tasks pin`). Changing a pin is explicit
(`--replace`). Every task names an explicit target. A box is the unit of trust; a per-agent id is a courtesy and never a boundary.

### 2. The envelope

The mesh is a **profile of the shared channel** (`ozbox_core::channel`, which the worker channel of ADR 0042 uses too), not an envelope of its
own. The channel owns the version (a receiver accepts exactly the current one), the sender's and receiver's **epoch** and **incarnation**
(a receiver's is 0 only in a `hello`), a 128-bit nonce, a per-direction sequence number, a cumulative acknowledgement, a validity window of
at most ten minutes and one 2-minute clock skew, the sealed body (HPKE through `ozbox-seal`) and a signature over the sealed envelope, so a
relay verifies without opening anything. The mesh supplies its tag, its five kinds (`task`, `message`, `status`, `artifact`, `cancel`), a
96 KiB body cap and the signed `ext`, which names the task as `<sender of the task>/<task id>`. There is no mesh `resync`: a gap past the
window is refused, and the sender resends its window every round.

A receiver checks, in this order, and acts on nothing until all pass: shape and version; addressing; the signature against the **pinned**
key (all counted as **one** audit event per round, because the sender is not authenticated yet); both epochs; validity against its **own**
clock; the nonce; the seal; the body screen (so refused content is never held); the incarnation; the acknowledgement; then the sequence
window. Every later refusal is named and audited.

- **Ordered and de-duplicated.** Sequenced kinds are applied in sequence order from a bounded window; a repeat is a no-op; a gap past
  the window is refused and a resync is asked for. Tasks are stored under `<sender>/<id>`, so a peer can never overwrite a task this end sent or
  another peer's by reusing an id. The same body is the same task; **the same key with another body is refused and raised**, also after the
  task was reduced to a tombstone.
- **Replay and state loss.** A nonce is remembered for its validity. A peer's incarnation is adopted only from a signed
  `hello` that names this end's current one, and an older `hello` is refused. A restored store calls `ozbox tasks restored`, which moves its
  epoch, incarnation and audit source epoch. A store rolled back **without** saying so is caught: a reused sequence number with other content
  is refused and the sender halts instead of treating the peer's acknowledgement as delivery.
- **Journal before acknowledgement.** The state file (tasks, outbox, windows, nonces, pending audit events) is written atomically
  (temp file, fsync, rename) under a lock before anything is acknowledged. The outbox is written in the same write as the task it
  carries; nothing is sent while the lock is held, and each delivery attempt is signed afresh.
- **Limits.** Starting values: 64 KiB inline per message, 20 new tasks and 120 messages a minute per sender, 50 open tasks per sender,
  a bounded outbox, 200 messages and 50 artifacts per task, and a 32 MiB state budget. Finished tasks are reduced to a tombstone after 30
  days, so the cap measures what is open. A round takes at most a window plus two envelopes and is one write. Past a limit the task is
  `rejected` with `resource-exhausted`. A transport command is stopped after 60 seconds and its output is read through a cap.

### 3. Tasks

A task has an id (a sortable random id made by the sender), a kind, a title, messages (made of text and data parts), artifacts (stored
with a content hash), a deadline (default 24 hours) and a state: `held`, `submitted`, `working`, `input-required`,
`approval-required`, `completed`, `failed`, `canceled`, `rejected`. The shapes follow A2A's names. **This release does not claim
conformance** with the specification, and the mapping is checked when the public edge is built.

The sender owns `held` (not yet acknowledged) and its own cancel; the **receiver** owns every state after delivery. The sender never
writes a receiver's state and the receiver never writes a sender's: a status from the wrong side is ignored and audited. A cancel is a
request. A retry is a new task with the old one as its parent.

Kinds in this release: `question`, `note` (both ungated) and `laptop-act` (gated).

### 4. A message can ask, never grant

A task carries no permission, no secret, no approval and no change to the receiver's rules. Words such as "owner approved", and an
`approval_ref` field, grant nothing; a test pins both.

- **Acts are refused by name.** The one typed act, `push-ref` (repo, remote, ref, a full sha, env), is refused by the receiver as
  `approval-path-not-built`. There is **no approval path to the laptop in this release**, and a half-built one would be weaker than none.
  When it exists, a decision must be a passkey assertion the receiver verifies itself, over a digest the receiver computes from the act
  it parsed, kept in a durable spend-once record of its own (ADR 0041).
- **Production is refused in code at both ends**, with no flag or setting: an environment not known to be non-Production counts as
  Production. When the path exists, the owner's decision for a Production act is a passkey on `main`'s dashboard **plus** presence at the
  laptop (owner decision, 2026-11-13; ADR 0042 Amendment 1), and nothing weaker.
- **Keys pasted by accident are caught; the screen is not a defence against a sender trying to get one past it.** Every string in a body
  (text, titles, ids, `parent`, reasons, artifacts) is screened with the key-shape screen agent memory uses, on send and on receive, **before
  anything is held**. A refused task is stored as `[refused]` with only its id and the code, and the audit trail never holds message text.
  Base64, hex, reversed or split keys pass a shape screen.
- **Labels are claims, and an end never claims a person.** Every message an end sends says `fleet`. The receiver stamps `peer:<name>` and
  `untrusted: true` itself and keeps the sender's word only as `claimed_label`. `--for-model` wraps every piece of peer text in the same
  fenced untrusted block triggers use. Control and Unicode format characters (bidi overrides) are stripped, and line breaks from fields that
  must stay one line.
- **A cancel is a request.** The receiver records it, tells the sender it arrived, and the task ends only when the receiver moves it.
- **An act is a shape a digest can sign:** a plain branch name (no `+`, no `:`), the name of a remote and a repository pinned on the receiver
  (never a URL or a path), a full object id.

### 5. How it travels, and what it costs

`ozbox tasks sync` runs the peer's `ozbox tasks exchange` through a command the person pinned (`--via "ssh my-box ozbox"`, an argument
list, never a shell string), writes sealed envelopes to its input and reads the reply. It uses the access a person already has to the box
and opens no port. It is a request and a reply, so it is **polling**: `ozbox tasks watch` repeats it every few seconds while it is open.
The stream transport described in the earlier design (a signed, single-use challenge on the dashboard tunnel) is left for a security
review. A laptop never wakes: a task for a sleeping laptop stays `held` until it syncs, and expires at its deadline.

### 6. Audit

Audit events are written into the state in the same write as the change and then handed to the hash-chained audit log; a crash retry
cannot log one twice (each carries a source number). They name acts, task ids, peers and refusal codes, never text.

### 7. Benchmark

The mesh is control plane only and **off by default**: nothing runs on a box that never uses it, no timer, no watcher, nothing on the
`exec` path. `watch` is a foreground command. The state file is small and is written per received message; its fsync cost on the state
disk has not been measured.

## What is not covered

- **The router's key and state, on a box without the service.** On a box the channel runs as the system user `ozbox-mesh` (`ozbox tasks
  serve`, set up by `ozbox-mesh-setup.sh`): agents reach it only through an agent socket (submit, reply, inbox, status, why, cancel), the
  keyless relay a laptop's `ssh` reaches, and an admin socket for root (`init`, `pin`, `restored`). Where that service is absent the keys
  sit where the box user can read them; `tasks init` says so and every JSON task carries `store_writable_by_agents: true`. **Proven on a
  real box: not yet**, so the channel is not recommended on `main` and has no approval path until it is.
- **The relay can capture and replay, not only drop or delay.** The process that reaches the relay socket sees the sealed envelopes of
  each round, so it can keep them and push them back later. The channel refuses a replay (stale, or a nonce already seen) and counts
  the refusals once per round per peer, with no state write per envelope; the relay socket takes one round at a time and 120 a minute,
  so a replay costs at most one audit entry per round and cannot become a flood. It still cannot forge, read or change anything.
- **Rounds are cut by bytes.** A round carries at most 4 MiB as the wire counts it (and at least one message); the transports read up
  to 8 MiB, so 64 large messages drain over several rounds. A single message that could never fit is refused when it is sent.
- **The program the router runs must be root's.** The unit sets `OZBOX_TASKS_REQUIRE_ROOT_PROGRAM`, and `tasks serve` then refuses to
  start unless the program and every directory above it are owned by root and writable by no one else.
- **Rollback and restore.** `tasks restored` is the one command the rollback guard lets through. It brings the audit log up to date under
  the store's lock, drops the old numbering's pending events and only then starts the new epoch; the log de-duplicates by source epoch
  and number. A sequence number reused below the 64-number window is caught by a running digest every `hello` and `ack` carries.
- **Re-pinning a peer with new keys** fails the tasks still waiting for their first delivery to it (`peer-replaced`), so a task never
  settles as delivered by a later message that reuses its number.
- **Residual, recorded and not built:** the signing-key fingerprint reuses the `ozbox-seal-key/1` tag (a nit: different bytes, one
  format); a setgid socket directory would give the socket its group without `CAP_CHOWN`; on a store over NFS, Linux `flock` is per
  process, so two threads of one process would not exclude each other (a box's `/var/lib` is local, and a filesystem without lock
  support fails closed); a hello refused for naming the wrong receiver incarnation still sets the incarnation the next hello names
  (benign, the next hello is the peer's own).
- **A restore that does not call `ozbox tasks restored`** leaves the epoch unchanged. Captured envelopes then stay valid for their
  validity window (ten minutes) at most, and tombstones still de-duplicate.
- **A peer whose clock steps back** past its last `hello` cannot open a new session until the clock catches up (`stale-hello`).
- **A compromised host with root** can sign as the endpoint. Metadata (who, when, how much) is visible to anything that carries the traffic.
- **Approval fatigue** is the main residual risk once acts exist; the prompt rate and decision time are to be measured then.
- **No approval path, no hub transport, no directory, no worker-to-worker tasks.**

## Consequences

- The note relay between the laptop and `main` can end for questions, notes and status. Acts still go by the existing approved routes.
- A new command, `ozbox tasks`, and a new core module. The tailnet command `ozbox mesh` (ADR 0030) is unrelated.
- A later ADR adds the approval path (and the amendments to ADR 0041 it needs), the stream transport and the hub channel.

## Open questions

1. **Decided (owner, 2026-11-15, D15): the mesh leaves Preview when the real-box proof passes. A second, independent security review is
   not required.** (The earlier design asked for one before any code; this slice was built at the owner's request, Preview only.)
2. How does the laptop prove presence before a hardware key exists? Decided: the platform biometric through the keychain; never a typed
   confirmation. Built with the approval path.
3. Pairing: a code that mints the first key, or fingerprints compared by hand? Built: by hand. Recommended: a pairing code.
4. Starting limits (30-day tombstones, 200 messages and 50 artifacts per task, a 32 MiB state budget, a 60 second transport timeout) are
   **owner-ratified 2026-11-15** (D2); tuning them later is a recorded change, not an open question.
