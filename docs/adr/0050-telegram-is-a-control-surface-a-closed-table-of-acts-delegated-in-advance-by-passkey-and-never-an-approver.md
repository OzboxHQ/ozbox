# 0050 — Telegram is a control surface: a closed table of acts, delegated in advance by a passkey, and never an approver

**Status.** Accepted. **Phase P1 (the policy core and identity) is built and is Preview**: tested in CI against a fake Telegram and a
software authenticator, never run for real on a box with a phone. Phases P2 to P6 are not built. Revised 2026-11-14 after its security
review. It builds on ADR 0021 (chat with coding agents) and ADR 0041 (the
approval model) **as amended on 2026-11-13**, in which a chat app is notify-only: no Approve, no Deny, no Stop and no `/budget`,
refused by the server. Those amendments are written on the branch that built them and are not on every branch yet; this ADR cites them
by number and does not restate or edit them. It also uses ADR 0022 (permission engine and audit chain), ADR 0023 and ADR 0026
(supervised commands, the tool host), ADR 0029 (Production secrets keep no standing access), ADR 0039 (roles and the one step-up rule),
ADR 0040 (the fleet role), ADR 0043 (the agent's tools on the box) and ADR 0049 (session quiesce and resume). ADR 0042 (`main` as the
hub) is design only. The agent mesh is ADR 0044 (public, on the branch `feat/agent-mesh`); the mesh's chat companion is draft 0047;
the mesh's models and routing draft is 0046. All are cited by number only. **Amendments this ADR needs are listed in "What must
change in other records" and are not made here.**

**Owner's decisions (2026-11-12 to 2026-11-14).** Approvals are passkey-only, in the dashboard. A chat app never approves, denies,
stops a run or raises a budget, and Production is never decided from one. **On 2026-11-13 the owner widened Telegram, "first class,
well architected":** it also starts, stops and resumes boxes, chats with coding sessions and runs `/run` shell commands. This ADR is
the record that makes both true at once.

**Decisions taken under the owner's delegation (2026-11-14), each marked below "delegated decision, owner to ratify".** The review
found that converse (talking to a coding agent) is more powerful than `/run`, so converse became a delegation like power and run;
the chat profile, the delegation record, idle-only pause, the `/run` rebuild, the daily money cap and the answers to open
questions 2, 3 and 4 follow from that. The owner reads and ratifies them; until then they are this ADR's recommendation, not a
settled decision.

## Context

Today a linked Telegram account can talk to a session (ADR 0021), read status and be told that something needs a person. It cannot
decide anything, and that rule is enforced on the server, not by a missing button.

The owner wants more from a phone: wake a box, put it to sleep, steer a coding session, run a quick command. Those are real powers on
a real machine, and the account that holds them is the weakest credential in the product. A chat vendor holds it, a SIM swap or a
stolen unlocked phone takes it over with no signal to us, bots are not end to end encrypted, and the vendor has no data agreement
with the project. The Bot API tells us **no device, no IP address and no location** for a message, so "new device" cannot be detected
from Telegram at all.

"Notify-only for approvals" and "Telegram starts boxes and runs commands" are not in conflict once one thing is said plainly: **a
passkey can be spent in advance, as a bounded and revocable delegation, or at the moment of the act.** A chat app may do what a person
delegated in the dashboard beforehand, inside limits the server and the box enforce. Everything else is a link to the dashboard.

One more thing is said plainly, because the first draft missed it: **a message to a coding agent is code execution as the box user.**
Talking to an agent ("run this", "add this script and commit it") is at least as strong as a `/run`. So converse is not a free tier:
it is a delegation, it runs inside a chat profile that the box enforces, and its residual risk is written down (§7).

## Decision

1. **One closed table of acts.** Every message a linked person sends is parsed into exactly one `ChatAct`, and one pure function,
   `chat_policy::decide(channel, person, role, act, context)`, returns `Allow`, `Handoff` (a link to the dashboard, nothing done) or
   `Refuse`. The table is data in `ozbox_core`, exported to the dashboard, with a parity test, as the approval rule table is. An act not
   in the table is refused. The policy is channel-independent; each channel has a **ceiling** (Telegram: tiers 0 to 3 below; WhatsApp
   and Slack: what they have today) and a new channel gets nothing until its ceiling is set.
2. **Delegation by passkey, in advance, as a signed record.** Everything above tier 0 is switched on, per person and per box, in the
   dashboard. A delegation is a record of: the person, the Telegram numeric id, the bot id, the boxes, the acts (converse, power, run),
   the caps, `not_before` and `expires`. **Its digest is the WebAuthn challenge**, as for an ADR 0041 decision, so the assertion is
   bound to exactly what was delegated; a settings row with no matching assertion is refused by every executor. At the moment of an
   act no passkey is asked: it was spent when the delegation was made. Defaults *(delegated decision, owner to ratify)*:
   - it lasts **7 days**, **30 at most**;
   - it **lapses after 72 hours unused**;
   - it is **re-judged against the person's current role on every act** (ADR 0039 item 3), so a demotion cuts it at once;
   - it is **never made for a Production box**;
   - it is **off for `main`** (the hub, §8) unless the owner turns it on with a passkey and a warning that says why;
   - a member's delegation needs **the owner's assertion naming that member**, plus the member's own.

   **An act outside the delegation is a handoff, not a request filed from chat.**
3. **The enforcement is on the server and on the box.** The gateway applies the policy; each executor (box power, command run, session
   input) re-checks the delegation; and the box itself enforces the chat profile (§1a), because a chat bug must not become a fleet bug,
   and a chat-steered agent never calls the gateway. The refusal of `Verb::Stop` and `Effect::Budget` from every chat channel stays
   and keeps its tests; nothing here loosens it.
4. **Chat origin is a capability, not a label.** A label is never an authority input (ADR 0044 says so). A chat-origin turn runs with
   the **chat profile** (§1a): the tool host mints the turn's session with the profile's ceiling, and **every tool-host and
   permission-engine row made in that turn carries the chat-profile capability and the chat turn id**. Workers (phase 5) verify the
   signed delegation of decision 2, never a label the hub asserts. A chat-origin run has no `auto` mode, no standing grant and cannot
   widen a budget.

## 1. The acts

Tiers are about what can go wrong, not about how the command looks. "Delegation" names what a person must have switched on in the
dashboard (decision 2).

| Tier | Act (command) | Who | Needs at act time | Result |
|---|---|---|---|---|
| **0 Read** | `/status`, `/fleet`, `/box list`, `/tasks`, `/log`, `/sessions`, `/help`, `/whoami` | any linked role | nothing | short, redacted, templated; per-box detail level (§5). A Production box appears as metadata only |
| **1 Converse** | plain text to the session the chat follows; `/new <box> <prompt>` on a **running** box; `/session pause`, `/session resume`, `/switch`, `/detach`, `/attach`, `/adopt` | member or owner | a **per-box converse delegation** held by the person; not on a Production box; `/new` is inside the person's spend allowance | runs under the **chat profile** (§1a); typed only into a session at or below it (§1b), only into an agent that reports its own questions and is not at a permission prompt, never `force`, forwarded text is data |
| **2 Power** | `/box resume <box>` (alias `start`), `/box pause <box>`, `/box pause <box> when-idle`, `/box extend <box> <hours>`, `/box create <name> <size>`, `/box resize <box> <size>` | owner, or a member the owner granted *box power* | delegation: person has box power, box is opted in, inside the fleet caps and the money cap (§3). **Pause needs an idle box**; **create and resize also need the person's box power delegation to name them (owner decision D14), inside the fleet caps and the daily money cap**; a create is new spend and a resize reboots the machine, so the chat says so before it files | resumed, or paused only when idle, through a power-only role; extend only once and within the caps |
| **3 Run** | `/run <argv>` | owner, or a member the owner granted *chat run* | delegation: the command is built from the shipped catalogue (§4); box is not Production | runs in a transient no-network unit; short redacted output |
| **4 Handoff** | clone, snapshot, destroy a box; a pause of a box that is not idle; a command not in the catalogue; resume past the caps; anything an agent asks; anything above a delegation | n/a | a signed-in dashboard session and a passkey, as today | one message and a pointer link to the prefilled dashboard page; **chat files nothing** |
| **5 Refused** | approve, deny or cancel anything; `/stop` (a run); `/budget` or any cap raise; **every act on a Production box** and any touch of a Production environment; secret read, set, import or export; policy, roles, people, links of others; the allow-list, caps, delegations and Telegram settings; tunnels and the secrets ingress; every ADR 0041 scope; outbound messages; protected-branch push | n/a | n/a | refused in words, with where to go; recorded |

There is **no `stop` alias** for `/box pause`: the word "stop" means only the refused act. A new link, or a link with no delegation,
is **tier 0 only**: it reads and does nothing else (§6).

### 1a. The chat profile (enforced on the box)

*Delegated decision, owner to ratify.* Every turn that comes from chat runs under one profile, and the **box's tool host and
permission engine enforce it**, not the gateway. A person's terminal sessions are not changed by it. The profile is:

- **Always Ask.** No `auto`, no `accept-edits`.
- **The person's allow rules, grants and standing-permission windows are ignored** for a chat-origin turn.
- **Every ask-list item becomes a request filed by the agent** (ADR 0041 allows an agent to file; this is not "chat filing") and is
  decided in the dashboard with a passkey. The chat gets a **notify-only ping** that something is waiting; it never carries a button
  or a decision.
- **No fleet, orchestration, mesh-task or box-lifecycle tools** in the Oz Box tool set of that turn, and **no change to the network
  allow-list**.
- **Writes only on a branch made for chat.** `/new` creates `chat/<task-id>` and records it; for an attached terminal session
  (`/attach`, `/adopt`) the only writable branch is the one checked out at the moment of attach. **Never a protected or a default
  branch.** A write elsewhere is an ask-list item, so it becomes a dashboard request.
- **Carried by a capability, not asserted by a label.** The turn's tool-host session (and, where the engine allows it, an agent-socket
  token) is minted with the profile for that turn and carries the chat turn id (§9). A process the session starts outside the tool
  host is covered by the profile and by the per-box converse delegation, not by a label.

### 1b. Typing into existing sessions

Decision 4's profile covers what chat *starts*. This rule covers what chat *types into*, and it applies to **every chat app**
(Slack and WhatsApp included, not only Telegram). *Delegated decision, owner to ratify.* A chat line is typed into an existing session
only if that session's effective authority is **at or below the chat profile**. These are refused, with a handoff:

- a session in `auto` or `accept-edits` mode;
- a session with allow rules beyond read-only;
- a terminal agent on a box with a **standing permission** window open (ADR 0043), or a run holding a box grant;
- an agent the box cannot describe (**unknown** is refused, not guessed).

The owner who wants a different trade-off could instead suspend allow rules and standing windows for the length of a chat turn. For a
terminal agent that is hard (the actor is per process and the turn boundary is heard only through hooks), so the refusal is the default.
**This is a shipped gap, not a future one:** ADR 0021's `/attach` inherits the session's authority today, and the chat refusal is being
fixed on the chat-app branch now (chat input refused unless the session is plain default or plan; chat-started runs clamped to Ask; a
`chat.session_elevated` refusal). This ADR makes it a rule for every channel.

### 1c. Pause, idle, and the two "stops"

**Two different "stops", never confused.** `/stop` cancels a *run* and stays refused from every chat app (ADR 0041 note 50). A box
is paused with `/box pause`, which is resumable, and `/box resume` brings it back (ADR 0049 describes the session quiesce; ADR 0046
is the mesh's models draft and has nothing to do with it). Bare `/resume` and `/pause` keep meaning a *session*. A chat that sends the
wrong one gets a one-line correction, never the other act.

**Why `/box pause` is allowed when `/stop` is not: a pause of an idle box loses nothing.** ADR 0049 brings back a session *record*, not
a process; a supervised run (`claude -p`) is not recorded, a waiting `ozbox guard wait` would be abandoned, and a build or push would
be cut off. So a chat pause is allowed **only when the box is idle**, and idle is defined here once *(delegated decision, owner to
ratify)*:

- no supervised run;
- no session that is not idle at its prompt (note 50's per-pane state);
- no pending request;
- no other person's session;
- no git write in progress.

If the box is not idle, the reply **lists what the pause would end** and gives the dashboard link; nothing is done.
**`/box pause <box> when-idle`** is the chat's alternative: it is cancellable (`/box pause <box> cancel`, or any resume), it
**expires after 2 hours**, and the box daemon, not the gateway, re-checks idleness and the delegation at the moment it would fire. A
member may never pause a box that carries another person's session.

**Only the safe direction is free.** Two acts make Telegram *less* able, and are allowed to anyone linked: `/lock` (refuse every act
above tier 0 from this link until a passkey in the dashboard lifts it) and `/unlink` (cut this link). A thief gains nothing by them
that the owner cannot undo with a passkey. The laptop has `ozbox chat lock`, and the dashboard has a "lock every link" button.

**Production boxes are metadata-only.** They appear in `/status` and `/fleet` as state, exit code, duration and a link; **every other
act on them is refused**. Who sets the Production mark: **the fleet record, by an owner with a passkey, never the box itself.** A box
that is not marked is not thereby chat-reachable: tiers 1 to 3 need the positive opt-in of §3.

## 2. Passkey on a phone: the link

A handoff, a delegation, a link renewal: the chat says what it is and sends **one pointer link**. It is 24 random bytes held only as a
keyed hash, bound to the person, the act and the plan or request digest; it lives ten minutes, is sent with link previews off and
`protect_content` on, and **is a pointer, not a credential**. The signed-in person must be the bound person. The decision is a
WebAuthn assertion bound to that one plan or digest, never a Telegram button. The bot deletes the message when the link is used or
lapses (best effort; **a bot can delete its own message in a private chat for 48 hours**, and a person can delete a chat for both
sides, which is why the record is not the chat, §9).

- **Opening has no side effects; only the assertion consumes.** The advised flow (open in Telegram's in-app browser, find the passkey
  fails, open in the real browser) is two opens, and a preview fetcher of a pasted copy must not burn the link. The token is in the URL
  **fragment**, so the server, the tunnel and any proxy never log it, and the page removes it from the address bar
  (`history.replaceState`). The page sends `Referrer-Policy: no-referrer`. A test asserts the tunnel's access log never contains it.
- The link only ever points at the dashboard's configured public address, built by the server, **never from agent text**. Every
  message that carries one says the host name, so a lookalike from a leaked bot token is recognisable.
- **To verify on real phones, not to assert:** passkeys inside Telegram's built-in browser may not work (uncertain; the system browsers
  on iOS and Android generally support them), so the message says "open in your browser"; and a dashboard with **no public address**
  cannot be reached from a phone at all, so Settings → Apps says "no address: Telegram cannot hand you to the dashboard" and tier 1 to
  3 delegations are refused until there is one (ADR 0010's tunnel).
- A phone passkey is one the person's own device holds; a synced passkey is only as safe as its account. The dashboard says which kind
  was used in the record.

## 3. Starting and stopping boxes

**The credential (amends ADR 0040).** ADR 0040 has two fleet roles and a fresh passkey for every change. A passkey cannot be asked in a
chat act, and the change role is far too wide to hand to one. So a **third, power-only role**, `ozbox-fleet-power`, is added:

- It may start and stop instances that carry **both** `ozbox-managed = true` **and a positive opt-in tag, `ozbox-chat-power = true`**,
  and describe them. A deny on a *production* tag fails open for an instance with no tag or a removed tag, so the allow is positive
  and there is no deny to fall through. **Only the change role sets the opt-in tag, at a passkey act.** The role may not create,
  resize, terminate, snapshot, share, touch IAM or KMS, and `CreateTags` and `DeleteTags` are denied entirely. ADR 0040's
  `NeverTouchTheFleetManager` deny is copied (the role can never stop the host that runs the fleet). The policy simulator tests an
  untagged instance, an untagged-but-managed instance and a tag removal: all refused.
- It is assumed by `ozbox-supervisor` only, with a session of **900 seconds** (the STS minimum for `AssumeRole`; an earlier "five
  minutes" cannot be had, and ADR 0040 already uses 900 for its read role), whose `SourceIdentity` carries the person and the
  Telegram `update_id` (at most 64 characters from `[\w+=,.@-]`, so the person id is short), so every cloud call joins to the audit
  entry (ADR 0040 §7).
- **A separate setting** *(delegated decision, owner to ratify)*: `fleet.power_credentials = "standing" | "grant"`, **standing by
  default**. It is not tied to ADR 0040's `fleet.change_credentials`: under that setting's granted window the power role would
  otherwise be windowed too, and the phone would stop working exactly when the laptop is asleep. The blast radius of a standing power
  role is the start and stop of opted-in boxes, which is why it is the narrow one.
- **Honest limit of the role.** In ADR 0040's first version the supervisor can already assume the change role behind a software check.
  So this role protects against **a bug in the chat path**, not against a compromised supervisor. That is worth having, and it is all
  it buys.
- **Verify on real AWS before relying on it:** starting an instance needs no KMS permission with the AWS-managed EBS key; a
  customer-managed EBS key needs `kms:CreateGrant`, which ADR 0040 denies. If the fleet ever moves EBS to its own key, the power role
  needs a scoped `kms:CreateGrant` with `kms:GrantIsForAWSResource`.
- **Only where the provider can scope it.** AWS can. A provider whose token is project-wide (a VPS host) answers `Unsupported`: the
  command is refused in words, never half done (ADR 0003).

**Inside the caps.** Caps live in the dashboard settings, set with a passkey: boxes allowed to be running at once, resumes per person
per day, hours a chat-started box may run, concurrent chat-origin sessions per person (default 3, *delegated decision, owner to
ratify*), a per-box **opt-in list** (default: none), and a **daily money cap for chat-started box time**, computed from the catalogue
price. **Default $10 a day, an owner-set figure; mark: owner to ratify.** A resume past any cap is a handoff.

**The auto-pause deadline** *(delegated decision, owner to ratify)*. A box resumed from chat carries a deadline of **four hours**;
`/box extend` may extend it **once, by up to two hours**, inside the caps. The deadline is **enforced on the box itself**: the box
daemon arms a shutdown timer when it is resumed, and `main` sweeps as a second check, so a stopped or crashed `main` does not leave a
chat-resumed box running. The shutdown at the deadline is the same graceful path as a pause; a box that is not idle at the deadline is
quiesced and stopped anyway, because the money cap is the owner's explicit limit, and the owner is told what ended.

**Resume lists sessions, it does not relaunch them.** A chat resume starts the machine with its sessions **listed**, not re-launched
(ADR 0049's resume and ADR 0013's schedules and triggers would otherwise spend model money the chat caps do not count), unless the
delegation names it. The reply says which sessions are waiting.

**Graceful only.** A pause runs the box daemon's quiesce, then stops the machine. If the daemon cannot be reached, a chat pause is a
handoff; chat never force-stops. Resume and pause are plans (ADR 0002): an already-satisfied request plans to nothing, so a replayed
message is harmless. A per-box cooldown (60 seconds) stops flapping.

**Honest limits.** (a) **A box that hosts the bot cannot be paused from chat** (it could not be resumed from chat); this is enforced,
not advised. (b) If the host is stopped by something else, Telegram is silent until the laptop resumes it, and the docs say so. (c) A
resume from a stopped state takes as long as a cold boot; the chat says "resuming" and sends one message when ready, not a stream.
(d) A mesh task never wakes a box on its own (ADR 0044).

**Create and resize are allowed from chat, inside the fleet caps (owner decision D14, 2026-11-15)**, as Tier 2 acts built in phase P3
(box power) under the same delegation, caps and daily money cap as resume and pause. A create is new spend and a resize reboots a
machine, so each says so in the chat before it files, and each is refused past a cap. **Clone, snapshot and destroy** stay Tier 4.
The owner widened G3 to start, stop and resume; the mesh chat companion (draft 0047) runs create and resize from chat on the same
terms.

## 4. `/run`: a shipped catalogue of read-only inspectors, not a shell

*Rewritten after review; delegated decision, owner to ratify.* `/run` is **the permission engine acting for the chat origin**, like any
command (ADR 0026). It is not a remote shell, and the design does not rely on a list of forbidden program names.

- **Parsed to argv, never a shell string.** The text is split once into an argument vector with no expansion, no pipe, no
  redirection, no subshell, no environment assignment and no glob. A message with any of those is refused.
- **Templates come only from an allowlist catalogue that Oz Box ships and maintains:** read-only inspectors, each with a fixed,
  hardened argv and typed holes. The owner turns entries on, one at a time, with a passkey. There are **no free-form entries in v1**: a
  command not in the catalogue is refused with a link; whether an owner may ever add one (with a passkey and the warning "runs
  repository code: the same as a shell") is open question 6 and phase 6.
- **Programs are pinned to root-owned absolute paths.** Each template's program is an absolute path that is not writable by the box
  user, fixed when the entry is turned on and checked again when it runs. The environment the supervisor builds has an empty or fixed
  root-owned `PATH`, so a `~/.local/bin/git`, a `node_modules/.bin` entry or a symlink called `ls` is never found.
- **Git is hardened by configuration overrides, not trust.** Every git template runs with `GIT_CONFIG_NOSYSTEM=1`,
  `GIT_CONFIG_GLOBAL=/dev/null` and `-c core.fsmonitor= -c core.hooksPath=/dev/null -c core.pager=cat -c log.showSignature=false -c
  diff.external=`, plus `--no-textconv` and `--no-optional-locks`, and no aliases. A repository's own `.git/config` can therefore run
  nothing. The catalogue prefers fixed plumbing templates to porcelain.
- **Holes are typed and cannot become options.** An integer is bounded, positive and rendered as one token. A word comes from a fixed
  set and may never start with `-`. A path hole is passed as the **canonical absolute path**, after `--` wherever the program honours
  it, and opened with `openat2(RESOLVE_BENEATH | RESOLVE_NO_SYMLINKS)` or passed as a file descriptor, so a swap after the check
  fails. For any program that reads file contents, a file with more than one hard link, or one not owned by the box user, is refused
  (a hard link can alias a credential file). The argument count must match the template exactly.
- **Every `/run` runs in a transient unit** with `IPAddressDeny=any` (the closed network of ADR 0023 does **not** cover the box user's
  own commands, so the unit supplies it), a memory, CPU and process cap, a 30-second default and a 120-second ceiling, `KillMode=
  control-group`, and **the whole cgroup is killed on timeout**, so a double-forked child does not survive. No stdin, no tty, one
  command per box at a time, ten a person per hour, a working directory under `/work/repos`, and the supervisor, not the box user,
  owns the record.
- **Never in the catalogue:** `tmux`, `systemctl`, `crontab`, `at`, `claude` and every other agent engine, `ozbox` (except a fixed
  `ozbox ps` template), shells and interpreters, `find -exec`, `xargs`, `make` and every package or build runner, `awk`, `sed`,
  `tar`, `rsync`, `less`, `vim`, `cp`, `mv`, `tee`, `ln`, `chmod`, `sudo`, `ssh`, `env` and `printenv`, a download tool, `git push`
  and `git config`. They run code or write files, and `tmux send-keys` would bypass the typing rule of §1b.
- **The feature is off and the list ships empty.** Switching it on, and every entry, needs a passkey in the dashboard. A command not in
  the catalogue is refused; nothing is queued behind it.
- **Where:** only on a box that the owner opted in, and on `main` only if the owner turned it on with the §1 hub warning. Reaching
  another box is a shell on another box from `main`: it waits for ADR 0042's hub and a per-box delegation the worker itself verifies
  (phase 5).
- **Never on a Production box,** never with a Production environment, and never as a way to decide a request or read a secret.

**Alternatives for `/run`, and why not.** *A denylist by program name* (the first draft): a name is not an identity, many allowed-looking
programs run code, and the network claim it leaned on is false for the box user. *Arbitrary commands as the box user, with the
guards:* a taken-over account would plant code in a repository a person later runs. *A one-shot approval of an exact argv digest in the
dashboard, with the output sent back to the chat:* a good fit for ADR 0041's model, but it adds a scope to a built table; it is phase
6. *Two sources disagreed:* one read "run as the box user, gated by the engine", the other "empty list, output to the dashboard
only". This ADR takes the engine as the actor and the catalogue as the allow rule, shows a **short** redacted reply, and leaves "output
only in the dashboard" as a per-box detail level (§5).

## 5. What goes back to the chat

Telegram bots are not end to end encrypted and the vendor has no data agreement with the project. **No secret, no personal or
sensitive data and nothing labelled sensitive goes through a chat.**

- **Messages are templates over structured fields** (state, ids, counts, cost, box, exit code) wherever possible, never model-written.
- **Free text** (an agent's reply, a command's output) is redacted **before it is capped**: the redactor runs over a bounded buffer
  larger than the cap (64 KiB), so a secret cannot be cut at the cap into a fragment that no longer matches a secret shape. It uses the
  one redactor (ADR 0021 item 3), a secret-shape and entropy scan, **and exact-value redaction of the box's known secret values with
  their base64, hex and URL encodings**. Then ANSI is removed, images and markup are stripped, and the text is sent as plain text or
  monospace, previews off, capped near 1,500 characters with a link for the rest.
- **Every URL in free text is removed, the dashboard's own included.** Only a server-built template carries an address. Otherwise an
  agent could write a deep link that opens a prefilled dangerous page and asks the person for a passkey for a change the agent
  chose, which contradicts "agent text is never a link".
- **A turn that read an untrusted source** (ADR 0044's rule) **replies at `summary` level, never `full`.**
- **Per-box detail level:** `full`, `summary` or `metadata` (state, exit code, duration and a link). A Production box is `metadata`
  and cannot be set otherwise. A task whose context is sensitive is `metadata`.
- **Said plainly, in `SECURITY.md`:** the redactor is a net, not a wall; it does **not** stop deliberate exfiltration by a
  prompt-injected agent that encodes what it can read into its replies or into commit messages that a later read prints.
- **Replies the bot sends cannot become inputs.** The bot ignores its own messages and every message from another bot.

## 6. Identity binding

- **The binding** is a record in the dashboard's sealed state: the Telegram **numeric user id** (never a username, which can be
  changed; ids need up to 52 bits, so stored as a 64-bit integer), the chat id (equal in a private chat), the Oz Box person, the bot
  id, a label the person chose, the delegations, `linked`, `expires`, `last_seen` and a status (active, locked, revoked). A display name
  is not stored.
- **Pairing is reversed (supersedes ADR 0021's bare one-time code; delegated decision, owner to ratify).** Otherwise whoever sends a
  dashboard-minted code first, a shoulder-surfer or a holder of a leaked bot token, binds their own account. So:
  1. The person opens a **pairing window in the dashboard with a fresh passkey**. It lives ten minutes.
  2. In a **private** chat the person sends `/link` to the bot. **The bot answers pairing traffic only while a window is open;
     outside one it stays silent** (the bot does not reveal that it is there).
  3. The bot replies with a short code (held as a keyed hash, five tries). The person **types that code into the dashboard, with a
     passkey**, and the dashboard shows the bound account (the numeric id tail, and the first name as the bot saw it).
  4. **One passkey covers two things, when the person wants it:** at link time the dashboard offers **"Enable chat on this box"**,
     and the assertion's challenge is the digest of the link record *and* the converse delegation record (decision 2). Confirming the
     link and enabling converse is one passkey. A link with **no delegation is read-only** (tier 0): it can read and `/lock`, and
     nothing else.
  5. A notice goes to the person's other channels.
- **The 24-hour wait on a new link is read-only** *(delegated decision, owner to ratify)*: a link made with no delegation is tier 0
  for its first 24 hours (as for a later signing key in ADR 0041), and a **power or run delegation is refused on a link younger than
  24 hours**. A converse delegation made *in the same passkey act as the link* (item 4) is not waited on: that passkey, tapped by the
  person in the dashboard, is what the wait would otherwise stand in for. Converse, power and run are **delegations**, each 7 days by
  default (decision 2), not properties of the link. A new phone is a new link.
- **Expiry and renewal.** A link lasts **30 days** and is renewed with a passkey. The Account page lists every link with its last use
  and its delegations; unlinking is one click, a passkey for the owner and for the person's own link.
- **Revocation** takes effect on the next message: the dashboard, the laptop (`ozbox chat unlink`, `ozbox chat lock`), root, `/unlink`
  and `/lock` all work. All pending links, nonces and queued commands for that link are void, a pending auto-pause extension is
  cancelled, and **every chat-origin turn still running ends at its next tool call**. A `/run` already running ends by its own
  timeout. A revoke between "recorded" and "run" refuses (tested).
- **Lost phone.** Unlink (or `/lock` from anywhere that still has a chat) and, if the Telegram account itself is at risk, the person
  secures it with Telegram's own two-step verification and ends its other sessions; Oz Box cannot see or enforce those, and says so.
  **Revoke also catches scheduled messages**: a message can be scheduled on an unlocked phone and delivered later with its delivery
  time as `date`, and only a revoke catches those.
- **Unlinked and unknown senders get silence,** as shipped. The mesh chat companion (draft 0047) would send one refusal; this ADR keeps
  silence. Counters feed an alert, never a per-message audit row.

## 7. Threat model

| Threat | What it gets | Controls | Residual |
|---|---|---|---|
| **Telegram account takeover** (SIM swap, stolen unlocked phone, phished login code) | the person's delegations, for the link's life | a passkey to pair and to renew; 30-day link; every delegation is passkey-signed, narrow, capped, 7-day, lapsing at 72 hours unused, re-judged on the current role, opt-in per box; the chat profile on the box; Production never; a second non-Telegram channel for tiers 2 and 3 (§9); `/lock`; a new link starts read-only | until it is revoked: read; **where converse is delegated, make an agent run code on that box, inside the chat profile (below)**; resume or pause opted-in boxes inside the caps; run catalogue commands |
| **Converse as code execution** | an agent that runs shell commands, edits files and commits as the box user | converse is a per-box passkey delegation, never Production, off for `main` by default; the chat profile (§1a): always Ask, allow rules and standing windows ignored, ask-items become dashboard requests, no fleet or mesh tools, writes only on `chat/<task-id>` and never a protected branch; no typing into an elevated session (§1b); a sealed transcript (§9) | **a linked account that has converse on a box can make an agent run code on that box, inside the chat profile.** Code in the work area, on a chat branch, is reviewed before it merges, but it runs while the agent works. This is the real power the owner chose; the profile bounds it, it does not remove it |
| **Bot token leak** | send as the bot (lookalike messages); **read** what the bot is sent (commands, prompts, pairing codes) if the attacker runs a competing `getUpdates` or sets a webhook, and our poller then misses them | the token is write-only and held as a secret the box user cannot read, in the supervisor's store; the bridge runs only as `ozbox-supervisor` on a locked socket (a test pins it, ADR 0041 §5); **every `409 Conflict` on a poll is an alert and the bridge stops acting until the owner confirms** (a webhook set by someone else also returns 409 to `getUpdates`); at start `getMe` must show `can_join_groups = false`, `can_read_all_group_messages = false` and `supports_inline_queries = false`, or the bridge refuses to run; request URLs are built in one place and `/bot<token>/` is redacted in every error and log path; messages name the dashboard host; rotation: revoke at BotFather, write the new token, links are kept (bound to the bot id) | the attacker cannot make *us* act, but **can read the person's messages** until the token is rotated; so no secret is ever typed to the bot |
| **Forgery to a webhook endpoint** | a fake update | a secret token of our own, separate from the bot token, checked in constant time (header `X-Telegram-Bot-Api-Secret-Token`, 1 to 256 characters of `A-Z a-z 0-9 _ -`); the source ranges Telegram documents are a **second** check only, because behind a tunnel the source address is the tunnel's | the secret token leaks only if our state does |
| **Replay** | an old command run again | each `(bot id, update_id)` is stored as a **set** with a lifetime longer than the freshness window, and **durably recorded (flushed to disk) before the act runs**, so a crash cannot run it twice; this is a set, not a watermark, because **after a week with no updates Telegram picks the next `update_id` at random**; a message older than five minutes (two for tiers 2 and 3) is dropped with "too old, send it again"; `message.date` is Telegram's, not the sender's; lifecycle acts are idempotent plans; a restart replays nothing | a command interrupted by a crash is reported "unknown", not re-run |
| **Forwarded, quoted, edited, group, channel, business-account, scheduled messages** | text from someone else made to look like the person's | **private chats only, and each message must have** `chat.type == "private"`, `from.id == chat.id ==` the bound id, `from.is_bot` false, no `sender_chat`, no `business_connection_id`; the bot leaves any group it is added to; `forward_origin`, `reply_to_message`, `external_reply`, `quote` and `via_bot` make the text **data**, never a command; `allowed_updates = ["message"]` (the filter also does not affect updates created before it was set, so the code filters by type as well); edits are not subscribed; only text is read; `/run@botname` is accepted only for our own bot; a revoke catches scheduled messages | the person pasting a stranger's text as their own words is a person problem; it still passes the same ceiling |
| **Prompt injection through chat into a coding agent** | an agent steered by text | the person's own words are their instruction at the chat profile; text they forward or the agent reads is data in an envelope (ADR 0021 item 4); the agent's actions stay gated by the permission engine, the commit barrier and the closed network; **agent text is never turned into a command or a link the bot sends**; every URL is stripped (§5); a turn that read untrusted input replies at `summary` | a hijacked account can steer an agent inside the chat profile |
| **`/run` as a remote shell** | commands as the box user | §4: a shipped read-only catalogue, pinned root-owned programs, hardened git, a transient no-network unit with a cgroup kill, typed holes, no Production, supervised and audited | a catalogue entry with a surprising output; the catalogue is ours to maintain |
| **Chat as a way to approve** | releasing a gated step | none exists: the server refuses (ADR 0041 note 50), the table refuses, and an ask-list item from a chat turn becomes a dashboard request with a notify-only ping; a test sends every approval word and every button payload from every chat channel | none |
| **Spam and cost** | resume loops, a bill | caps, cooldowns, per-person limits (20 messages a minute, 5 power acts an hour, 10 `/run` an hour, concurrent chat sessions), the on-box auto-pause deadline, a **daily money cap**, Telegram's own limits (about one message a second to a chat, 429 `retry_after` obeyed) | a bill up to the money cap |
| **Message history on Telegram** | status and box names stay on the vendor's servers; a person can delete a chat for both sides | detail levels; `protect_content`; codes and links deleted when spent; nothing secret ever sent; the record of what was asked is the sealed transcript, not the chat (§9) | what was sent is the vendor's; the docs say it |
| **Silent outage** | commands unheard | polling resumes from the stored offset; commands older than the window are dropped, not run late; a start-up message says "back, X seconds behind" | none |

## 8. Transport and where it runs

- **Long polling is the default.** An outbound HTTPS request to the vendor, with `getUpdates` using a 30-second `timeout` (today it
  polls with a zero timeout on a tick), the offset advanced only after an update is durably recorded, and `allowed_updates` set to
  `message` alone: **no callback queries, so nothing is pressed**. It fits ADR 0005 (no inbound network) and works with no public
  address. Updates are kept by Telegram for up to 24 hours.
- **A webhook is optional,** only where the dashboard has a public address, through the same single signed public hook as the other
  chat app (ADR 0013's rule: signed, once, small), with the secret token above, `max_connections` small, and a dedupe store. It is
  never the default: it adds an inbound path for a convenience.
- **One consumer per bot.** The vendor allows either one poller or one webhook; a second consumer, or a webhook set elsewhere, makes
  `getUpdates` answer 409, which is an alert (§7). `chat.telegram.host` names the one place that runs it; a second place refuses to
  start.
- **Where: the box whose dashboard owns the fleet (`main`), as `ozbox-supervisor`, on a locked socket.** Not the laptop: it sleeps, and
  it holds the owner's Production authority, which a chat bridge should not share a process with. A laptop-only fleet may host the
  bridge for tiers 0 and 1 only. **But `main` carries the widest blast radius** (the dashboard, the supervisor, the fleet roles, the
  approval service), so **`main` is not opted in for converse or `/run` by default** *(delegated decision, owner to ratify)*: the owner
  turns it on with a passkey and a warning that `main` is the hub. Before phases 2 and 4, the `BoxLocked` and bot-token tests must pass
  (the box socket's allowed prefixes still include the bot token, ADR 0041 §5), and a B-tier test shows that a `/run` unit cannot reach
  the supervisor socket, the approval journal or the agent socket.
- **Worker boxes (ADR 0042)** are reached over the hub's sealed channel, and the worker verifies **the signed delegation of decision
  2**, never a label the hub asserts (ADR 0044: never trust `main`'s word), and applies the chat profile on its own tool host.
- **Costs.** The Bot API is free. A poll is one outbound connection. The real cost is box time: a resume is billed until the pause,
  which is why caps, the money cap, an on-box deadline and an opt-in list are part of the decision, not extras.

## 9. Audit

Every act, allowed or refused, is an entry in the audit chain (ADR 0022, ADR 0028) as actor `person:chat:telegram` for the person,
with: the act, the tier, the box, the policy decision and rule, the Telegram `update_id`, the delegation used (its digest), and the
outcome. **Every tool-host and permission-engine row made during a chat-origin turn carries the chat turn id**, so the record joins a
message to the acts it caused.

- **A sealed per-link transcript** is kept in the supervisor's state, readable by the owner in the dashboard, never sent anywhere,
  with a bounded retention (30 days). Telegram's copy and the engines' own transcripts (in the box user's home, where a steered agent
  can write) are not the record. **The chain holds an HMAC of each message under a key the supervisor holds**, never the text and never
  a bare digest, so a low-entropy message cannot be guessed by enumeration yet a person can still verify a transcript line against it.
- **`/run`** records the template id and the integer and word hole values **in clear**; path holes go in the sealed transcript;
  exit status, duration and byte count; not the output.
- A refusal of an act by a linked person is recorded (rate-limited so a loop cannot fill the chain); an unlinked sender is a counter
  only.
- **A second, non-Telegram channel is required before a tier 2 or tier 3 delegation can be made.** The dashboard's inbox is controlled
  by the same supervisor, so tier 2 and 3 acts are also **listed to the laptop on its next ingress contact and written to the
  off-box audit head**, as ADR 0041 does for a pending key enrolment. The act is notified in the same minute on the other channel,
  so a takeover shows up somewhere that is not Telegram. (Converse is covered by the sealed transcript and the turn-id join; a second
  channel is not required for it. Owner to ratify whether it should be.)

## 10. Phased build, with tests

Tiers of test: **A** is unit tests and the dashboard's simulated browser suite in CI; **B** is the real-server suite (a real daemon
and a real `ozbox serve`, no stand-ins); **C** is a real box with a real test bot and a phone, run by a person.

| Phase | Builds | Tests |
|---|---|---|
| **P0** | This ADR, its security review, the amendments below | review findings closed |
| **P1 Policy core and identity** | `chat_policy`, the act table and its dashboard export, link records, reversed passkey pairing with the link-plus-converse single assertion, signed delegation records, expiry, revoke, `/lock`, `/unlink`, freshness and the durable `(bot id, update_id)` set, audit entries, the sealed transcript, polling at 30 seconds, no callback queries, the `409` and `getMe` checks | **A:** an exhaustive table test over every act, channel, role and tier (adding an act fails until it is placed); a sweep that no refused word or payload ever reaches an executor; replay and freshness with a fake clock, **including a random `update_id` after a long gap**; group, forward, quote, edit, bot-sender, `sender_chat` and `business_connection_id` inputs and the private-chat field checks; **non-ASCII dashes and quotes refused, `/run@botname` only for our bot**; pairing limits and the **reverse-pairing confirm step**; **delegation assertions: a forged settings row with no matching assertion is refused**, and a role change cuts a delegation; **the `409` alert and the `getMe` flags**; a sentinel test that no token (including inside `/bot<token>/` errors), code or log carries a secret. **A, with a fake Telegram** (a local server for `getUpdates`, `sendMessage`, `deleteMessage`, `getMe`, `getWebhookInfo`, `setWebhook`, 429 and 409 answers, scripted updates): the whole pairing and revoke path, **and a revoke between "recorded" and "run" refuses**. **B:** the Account page and the Settings → Apps guided setup against the real server and the fake; the tunnel's access log never contains a pointer-link token. **C:** pair a real test bot from a phone |
| **P2 Converse and read at full strength** | tier 0 and tier 1 under the chat profile, the typing rule for every chat app, detail levels, the redactor extended (bounded buffer then cap, exact-value, entropy, URL and markup stripping), the handoff message and link | **A:** **the chat profile: an ask-list item from a chat turn becomes a dashboard request, never a pass; the matrix of every permission mode and every grant state, a chat line reaches a session only where §1b says; the tool set of a chat turn has no fleet, mesh or lifecycle tool; the chat turn id is on tool-host rows; writes only on `chat/<task-id>` and never a protected branch**; redaction vectors including a secret straddling the cap and the encoded forms; **every URL stripped, the dashboard's own too**; previews off. **B:** the notify-only suite still green, unchanged. **C:** the link opened on iOS and Android, including Telegram's built-in browser |
| **P3 Box power** | the power role (module and policy, with ADR 0040's amendment), `fleet.power_credentials`, caps and the daily money cap, the opt-in tag and list, the on-box deadline, idle-only pause and `when-idle`, `extend`, sessions listed not relaunched, the host-cannot-pause rule | **A:** policy documents tested against the operator policy as the other fleet roles are; **an untagged, an unopted and a tag-removed instance are refused (a policy simulator test)**; caps, cooldown and money cap with a fake clock; **a chat pause with a live run, a pending request or another person's session is a handoff that lists what it would end**; `when-idle` is cancellable and expires at 2 hours; `Unsupported` on a provider that cannot scope. **B:** resume and pause against the fake provider with a real daemon; **the on-box deadline holds with `main` stopped**. **C:** one real pause and resume of a test box on AWS, timed and recorded as a **chat-resume figure, never a lifecycle number**; and the real-AWS check that `StartInstances` needs no KMS grant |
| **P4 `/run`** | the argv parser, the shipped catalogue and its per-box switches, pinned programs, the transient no-network unit, the output path | **A:** a corpus of metacharacter and quoting attacks; a symlink, `..` and **hard-link** read; **hole values that start with `-`**; **fsmonitor and `gpg.program` vectors**; **a PATH hijack**; the environment contains nothing; redaction before the cap. **B:** real runs through the unit, with **a double-forked child killed on timeout** and **a network connect attempt refused**; **a `/run` unit cannot reach the supervisor socket, the approval journal or the agent socket**. **C:** a catalogue entry run from a phone on a worker box |
| **P5 Worker boxes** | `/run` and power across the hub, the signed delegation the worker verifies | per ADR 0042's tests plus a worker that refuses a delegation it cannot verify and a chat origin above its own chat profile |
| **P6 Optional** | a one-shot approval of an exact command in the dashboard with the result back to the chat (the only path to a command outside the catalogue); voice notes transcribed on the box; webhook mode | each its own review |

**Benchmark effect: none.** All of it is control plane on the box that hosts the dashboard. The `/run` path touches only chat-origin
commands (a transient unit around them, no hook on the command path other commands use); resume and pause use the existing provider
calls; no measured path (create, resume timing, exec, disk, network, images) changes. No claim of a speed-up is made.

## 11. Docs and changelog this will need

- A new use case, **Control your boxes from Telegram** (the acts, what a chat can never do, how a handoff works, **that converse means
  code runs on that box inside the chat profile**), with its **Works / Preview / Planned** mark: Planned until the real-box run, then
  Preview.
- The existing chat use case: the command table gains `/box` and `/run`; its "only linked people" section gains expiry, `/lock` and
  the typing rule.
- Settings → Apps guide: BotFather steps (turn group joining off, privacy mode on), the reverse pairing, the delegations, the caps and
  the daily money cap, the opt-in list, the catalogue switches, token rotation, "what Telegram can see", Telegram's own two-step
  verification.
- `docs/architecture.md` (the bridge, the power role, the chat profile), the hardening checklist (Telegram settings), `SECURITY.md`
  (the residual risk in plain words: converse is code execution on that box; the redactor does not stop exfiltration), the README's
  chat row, the CLI reference for `ozbox chat unlink` and `ozbox chat lock`.
- A changelog entry per released phase, in the user's words ("start and pause a box from your phone"), never the internals.

## What must change in other records

- **ADR 0040:** a third role, `ozbox-fleet-power`, a separate `fleet.power_credentials` setting, and the sentence "every change needs a
  fresh passkey" gains "except start and stop of an opted-in, non-Production box inside the caps, delegated in advance".
- **ADR 0021:** the pairing item (reversed, passkey both ways, silent outside a window), "one bot per fleet" stated; its Telegram
  sentence "reads" becomes this table; **the typing rule of §1b** (it is being fixed on the chat-app branch for the shipped path).
- **ADR 0041:** one sentence in note 50 pointing here for the "later decision" it left open and for the typing rule; **no** change to
  its table.
- **ADR 0044:** none to the text; this ADR relies on its "labels are never an authority input" and its claimed-branch rule.
- **The mesh chat companion (draft 0047):** it adopts this table as its `chat` ceiling. This ADR **overrides** its §2 (create and
  resize from chat, allowed within the caps: §3 and open question 1), its §5 item 4 (a "new device" alert, dropped: the Bot API gives no device or
  location; replaced by the other-channel echo of §9) and its refusal to unlinked senders (replaced by silence).

## Alternatives considered

- **Converse with no delegation** (the first draft). Rejected on review: it is code execution as the box user, stronger than `/run`.
- **A trust label (`person:chat`) as the ceiling a worker applies.** Rejected: a label is never an authority; a capability and a
  signed delegation are.
- **Webhook as the default.** Rejected: an inbound path and a public address for no gain; behind a tunnel the source address is not
  Telegram's, so the controls reduce to the secret token.
- **Buttons for confirmation.** Rejected: the owner removed every button; a button pressed by an attacker confirms as well as by the
  owner, so it buys only typo protection.
- **A Telegram Mini App or login widget as the step-up.** Rejected: it proves a Telegram identity, which is the credential in doubt.
- **One bot per box.** Rejected: a bot per fleet keeps one set of links and one place to revoke.
- **A user-account client instead of a bot.** Rejected: it would hold a person's whole account.
- **Putting the power in the existing change role.** Rejected: that role creates and destroys; the narrower role is the point.
- **A pairing code minted in the dashboard and typed into the chat.** Rejected on review: whoever sends it first is bound.
- **No passkey for the delegation, only for the act.** Rejected: a chat cannot ask for one, which would make the delegation the whole
  feature.

## Consequences and what is not covered

- A person can wake and pause opted-in boxes, steer sessions and run a short catalogue of read-only commands from a phone, and a
  taken-over account can do only that, within caps, until revoked.
- **Converse means code runs on that box**, inside the chat profile. That is the honest price of "steer a coding agent from a phone",
  and it is why it needs a passkey delegation.
- Telegram stays a notifier for every approval. Nothing in this ADR lets it decide.
- Another cloud role, a chat profile on the box and a delegation record to build, test and review; more dashboard settings to explain.
- **Not covered:** Production (never from chat, metadata only); worker boxes until the hub exists; cloning,
  snapshotting and destroying boxes (and, until box power is built, creating and resizing them); voice; groups and rooms (the mesh); chat apps other than Telegram beyond what they have (the
  typing rule applies to all of them); any claim that Telegram is private. A provider without scoped power stays unsupported. Phase P1
  is built and Preview; box power, `/run`, the chat profile and the redactor (P2 to P4) are not, and no status mark may say "Works".

## Open questions for the owner, each with a recommendation

Every recommendation changed on review is marked *delegated decision, owner to ratify*.

1. **Create and resize from chat, inside the caps, as draft 0047 proposes?** **Decided (owner, 2026-11-15, D14): allowed, within the caps.**
2. **Who may use box power: owners only, or members too?** *Recommendation (delegated decision, owner to ratify):* owner by default; a member only when the owner grants it, **with the owner's passkey naming that member**. **A member never pauses a box that carries another person's session.**
3. **Auto-pause deadline for a chat-started box.** *Recommendation (delegated decision, owner to ratify):* **four hours, extendable once, by up to two hours**, enforced **on the box**, with a **daily money cap** (default $10 a day, the owner sets the figure).
4. **Link life.** *Recommendation (delegated decision, owner to ratify):* a link lasts **30 days**; **the 24-hour wait on a new link is read-only** (tier 0, and no power or run delegation in it); **converse, power and run are separate delegations of 7 days**, lapsing after 72 hours unused.
5. **`/lock` and `/unlink` from chat.** *Recommendation:* yes; they only reduce power. Add `ozbox chat lock` and a "lock every link" button.
6. **A command not in the catalogue: a one-shot dashboard request, or an owner-added free-form entry?** **Decided (owner, 2026-11-15, D14): free-form commands are never allowed from chat.** A command outside the catalogue is refused with a link.
7. **Detail level on a Production box.** *Recommendation:* metadata only, not configurable, and no act at all.
8. **A mesh wake of a stopped host.** *Recommendation:* none; a box that hosts the bot is never paused from chat, and the laptop resumes it.
9. **Other chat apps getting the same ceiling.** *Recommendation:* Telegram first; each other app later, on its own review. They already get the typing rule of §1b.
10. **A second non-Telegram channel before converse too (it is required for tiers 2 and 3).** *Recommendation (delegated decision, owner to ratify):* not required for converse, which has the sealed transcript and the turn-id join; revisit after the first real use.

## Build notes for phase P1 

What was built, and the choices that the text above left open. Each is a decision a person can change by editing this record and the code
that follows it.

- **Where it lives.** `ozbox_core::chat_policy` is the pure core (the closed table of acts, the one parser, `decide`, the signed
  records and their digests, admission and the replay set); `ozbox-cli` holds the bridge (`serve::telegram_bridge`), the dashboard
  side (`serve::telegram_link`), the Bot API client (`telegram`), the durable store (`telegram_store`) and the sealed transcript
  (`telegram_transcript`). The act table is exported to the dashboard as `chat-acts.ts`, generated from the Rust table and compared
  by a test, as the approval rule table is.
- **An `Allow` is a value only `decide` can make**, and the executor asks again with the facts of that moment (`Allowed::confirm`)
  before it acts: a link revoked or locked, a role cut or a delegation lapsed between the record and the act refuses it.
- **An act whose executor does not exist yet is never a bare `Allow`.** Box power, create and resize, and `/run` are in the table with
  their tier and their delegation, and a person who holds the delegation gets a handoff in words ("this version cannot do it from a
  chat yet"). In P1 a delegation can only be made for converse; asking for power or run is refused with `not_available`.
- **The durable set and the links have their own file**, written with a sync and a rename, where a failed write is an error that stops
  the bridge, and a file that exists and cannot be read does not load as empty. The `(bot id, update_id)` set is written **before** the
  act it allows, and the offset moves only after.
- **A link or a delegation is real only while its assertion verifies**, against a passkey the person still has, every time it is used.
  A hand-written row, an edited row and a row whose passkey was removed are refused; the Account page says "not backed by a passkey".
- **The bot id comes from `getMe`, never from the token.** `getMe` must show the three flags off, a webhook set by someone else is
  named by its host only, and a 409 stops the bridge until an owner confirms; the stop survives a restart.
- **Polling is on a thread of its own**, 30 seconds a poll, three updates at a time (the client keeps 64 KiB of an answer and a message
  may be 4,096 characters), and one update at a time after an answer that did not parse. There is no callback query and no button.
- **Chats linked before this release** (no passkey behind them) keep receiving alerts and may read (tier 0); anything beyond that
  needs a new link with a passkey. The old "send the code the dashboard made to the bot" pairing is gone for Telegram (Slack and
  WhatsApp keep it until their own review).
- **A dashboard with no sign-in cannot link Telegram**: there is no person to bind and no passkey to sign with. It says so.
- **A member's delegation needs an owner's co-signature** (an assertion over the delegation and the member's name, by someone who is
  an owner now), including the converse delegation made in the same step as a member's link: it waits, shown as "waiting for an
  owner's passkey".
- **Production and the hub are marked by an owner** (Settings, Apps; a passkey shown a moment ago). The hub is also the box that hosts
  the bot, which is never paused from chat.
- **The audit actor is `person:<id>:chat:telegram`**, so the person joins to the record; the detail is `act`, `tier`, decision, rule,
  `update_id`, the first 12 characters of the delegation digest and the first 16 of the message's HMAC, in at most 160 characters (the
  chain cuts silently beyond that).
- **Not in P1:** `ozbox chat lock` and `ozbox chat unlink` (the dashboard's lock-every-link button, `/lock` and `/unlink` are); the
  handoff link's "consumed by the assertion" half (nothing needs one until a gated act can be prefilled); and the chat profile on the
  box, the redactor, detail levels, box power and `/run` (P2 to P4).
- **The Tier B "tunnel access log" check is weaker than this ADR's wording (§2).** The ADR asks that the tunnel's own access log never
  contain a pointer-link token. The real-server harness cannot put a logging proxy in front of the dashboard (the passkey origin is the
  server's own port), so the spec records what the **browser** sends (every request address and its referrer) and asserts the token is in
  none of them, and that the address bar drops the fragment. That shows the page never puts the token in a request line or header; it
  does not read a real tunnel's log. Closing it needs the harness to start a loopback reverse proxy whose address is the passkey origin,
  with the server on another port, and to assert on that proxy's log; and, on a real box, the owner's tier C run reading the tunnel's
  actual log.

## Amendment (2026-11-17): a chat is a participant of the conversation fabric (ADR 0056, Preview)

After the gateway resolves `@agent`, `@box`, `@group` or `@fleet` under the person's delegation, it can post the message into the
fabric as the person (`fabric::bridge::post_from_chat`), and the chat is subscribed to replies. `pull_replies` hands the gateway
each agent's reply, attributed by the fabric's registry (never by the agent's own words) and addressed to every chat the person
hears in, and the gateway renders it with its notice model as a reply. Delivery states and threads are the fabric's, the same on
every channel. Nothing here widens the closed table of acts: a chat message is data, approves nothing, and reaches only the
person's own participants. The gateway's call into the bridge is B4-32's to wire.
