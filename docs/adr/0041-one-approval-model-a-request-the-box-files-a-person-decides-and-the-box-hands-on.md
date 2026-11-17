# 0041 — One approval model: the box files a request, a person decides it where they are, and the box hands the decision to the waiting operation

**Status.** Accepted. **Amended 2026-11-13: chat apps are notify-only for approvals, with no Approve, no Deny and no Stop (§3.1, §5; build note 50).** Phases 1, 2 and 3 are built (phase 3: the guard hook files and waits, public values, file:line, bound overrides, large pushes). Written 2026-11-12. **Revised after the security review (2026-11-12)**: accept with changes,
0 Critical, 6 High, 12 Medium, 6 Low, and the owner's decisions of the same day. This text is one current design that answers the
review. **Phases 1 and 2 are built (see the notes below); phase 3 and the rest are not.** It amends ADR 0028 (item 4 and Amendments 1 to 3: the approval gate, codes and the laptop
key), ADR 0023 (the commit barrier's override) and ADR 0029 Amendment 6 §3 and §6 (the ingress account and who may approve), and
it uses ADR 0039's roles. It does not change how a Production value is released (ADR 0029): that keeps its own issuer and appears
in the same inbox. ADR 0040's fleet change window uses the same passkey machinery with its own tag (§3). ADR 0042 (main as the
hub) depends on this ADR for cross-box approvals, and the changes it asked for are folded in here (§1, §3, §7, §8, §11).

**Revised again (2026-11-12, after the consistency check of ADRs 0040 to 0042).** The check
(a consistency check across the two records) found that the key lifecycle of the delegated decisions could not be
built as written (K1 to K4). This text now says how presence is proved (§3 "Laptop key"), what a decision record carries, what "first
key" means across a new store, and that a software key never decides Production, with no opt-in. It also adds the scopes
`setup-code` and `kek-export` that ADR 0029 Amendment 9 built, and the rest of the check's rows that touch this ADR. **Phase 1 must
not freeze the record formats until the fields in §1 (`decision`) and §3 are in.**

**Phase 1 built (2026-11-12): core and service, on `feat/approval-model`.** Built: `ozbox_core::approval_subject` (the
encoding and the digest per scope, with golden vectors computed independently of the code), `ozbox_core::approval` (the
request and decision records with every K1 field, the state machine, the rule table as data with its TypeScript export
`packages/dashboard/src/api/approval-rules.ts` and a test that compares it), and the service operations in
`approval_requests.rs` (`file`, `get`, `list`, `await`, `decide_challenge`, `decide`, `spend`, `finish`, `cancel`,
`decider_revoked`, `new_epoch`, all prefixed `areq_` on the wire) on a journal of its own, sealed, off the secrets file's
lock. **They are unreachable in this release**: `Gates::enable_requests` is called only by tests, `areq_capabilities` says
`request_ops: false` until then, and no operation waits on a request. Not built: the laptop CLI and the ingress socket
(phase 2), the guard (phase 3), the dashboard inbox and the supervisor's assertion check (phase 4), the attestation verifier
that sets "has ever had a presence key" and `presence_proved` (phase 2; until then every laptop key is a software key), the
service verifying passkeys (phase 5). Decisions taken where this text was open are in "Phase 1 build notes" at the end.

**Phase 2 built (2026-11-12): the deciders, on `feat/approval-model`.** The dashboard decides with a passkey over the decide
challenge (the supervisor's routes under `/v1/approvals/requests`, the Approvals page and Settings -> Approvers), the laptop
decides over the sealed ingress route (`ozbox secrets ingress requests`), the attestation verifier makes a presence key
(G3), the "has ever had a key" markers live beside the epoch (G1), the waiting hook exists (`ozbox guard wait`), a pending
request is announced in chat as a message with a link and no button, and the service's request operations are on. The
phase 1 review's "before phase 2" list (including the key loaded from the store by id) landed with it.
Decisions taken where this text was open, and what is not built, are in "Phase 2 build notes" at the end.

**What it builds on, and where that lives today.** The ingress account and sealed route (ADR 0029 Amendment 9, `ingress_guard.rs`
and `ingress_client.rs`) were built on branch `feat/prod-secrets-p1` and merged into `main` just before this ADR (owner decision 6).
ADR 0039 (roles) has merged from `feat/dashboard-roles`, and ADR 0040 (the fleet and the scoped sockets) is on `feat/box-dashboard-fleet`;
they are cited by number. ADR 0028's Amendment 3 (the tunnel-token binding) was moved into the source (`docs/adr`) by commit `461b74a`
on `fix/upgrade-path`, which has merged into `main` (2026-11-12), so the prerequisite of phase 1 is met. The
amendment now also says that a laptop's approval code comes back over the ingress route, since `feat/prod-secrets-p1` merged
before this branch.

**Owner's goal (2026-11-12).** "Wire the dashboard to the boxes and fleet end to end, and it handles approvals, excellently well
architected", for the next release and for every open-source user.

## Why: what went wrong on the real box `main` on 2026-11-12

Five things, each from a real run (two reviews of the upgrade path and of importing keys, and a working session):

1. **A code approves a scope, not a change.** Any tunnel token, any guard override, any import could be spent by a code meant for
   one. The tunnel token is fixed on `fix/upgrade-path` (the code now signs `sha256(token)`); the guard override, the import and
   the policy change are not.
2. **The laptop is the only approver in practice.** The dashboard can mint a code for each scope, but through a form that asks
   the person to type the scope, project and change code, shows no pending change, and shows the code once to be copied. There is
   an Approvals page and a Settings page for these codes, and neither shows a pending request.
3. **A code is copied by a person from one place to another and dies after five minutes.** Relayed by hand it expired, so the lead
   ran two guard-blocked commits itself.
4. **A code or a value travels through the box user's shell.** A shell function in an rc file on `/work` can wrap even `exec` and
   `env`, and read it. Closing that is the ingress account of ADR 0029 Amendment 6 §3 and Amendment 9.
5. **The commit guard refused public values** (a public URL, a dictionary-word `NEXT_PUBLIC_*` value) and **did not say where**.

The common cause is one design choice: an approval is a short bearer code that a person carries. This ADR replaces the carrying.

## Decision

One model for every gated request, in three parts.

1. **A durable approval request** is filed by the blocked operation. It names the exact change. Nobody types a scope or a code.
2. **A decision** is made on a surface the rule table allows (dashboard and laptop; a chat app never decides), with the
   factor the table asks for. A dashboard decision is **one WebAuthn check for that one request**, with a challenge bound to the
   request id and its subject digest. The record says which factor was used.
3. **Delivery is the box's job.** The waiting operation waits on its request id. When the decision exists, the operation spends
   it, and the gate **recomputes the subject digest at spend time**. A changed subject is refused and does not burn the
   approval. No person sees, copies or types a code in the normal path.

**Two kinds of "code", never confused.** An *approval code* is the old bearer string of ADR 0028 item 4. An *authenticator code*
is a six-digit second factor (TOTP). An authenticator code never decides a request (§3). An approval code exists only as a
fallback, bound to a request id (§10).

## 1. The request object

A request is a small record kept by the secrets service (`ozbox-secrets`). Not by the dashboard.

**Why the secrets service.** It already owns the gate, the single-use rule, the audit chain (ADR 0028 item 1) and the sockets
with peer credentials. The gate that spends an approval must be the one that stores it, or a decision can be read as valid in one
place and spent in another. The dashboard, a chat channel and the laptop are **deciders and viewers**, never the store. This also
means the laptop path and the root path work with the dashboard down.

| Field | What | Never |
|---|---|---|
| `id` | 128 random bits, base32 | |
| `kind` / `scope` | one of the scopes of `SCOPE_RULES` (`import`, `policy`, `tunnel-token`, `guard-override`, `signer-enroll`, `box-secrets`, `host-guard`, and the two ADR 0029 Amendment 9 §6 M1 built, `setup-code` and `kek-export`), plus `worker-keys` (ADR 0042) and later `secret-use` (ADR 0029). A scope-only code for `setup-code` or `kek-export` is not a request: both are filed as requests too, by the laptop over ingress (§3.1) | a scope this version does not know is refused |
| `origin` | `local`, or the hub's id when the request was filed on a worker and is shown on `main` (ADR 0042) | |
| `subject` | the typed fields of §4, and `subject_digest` computed by the encoding of §4 | a value, a token, a code, a command's output |
| `display` | derived by the service (or by the root helper for the scopes that name it, §4) from `subject`, and shown as is. Each field is labelled with its source: service, root helper, or "from the box" | free text from the requester |
| `reason` | at most 200 characters from the requester, plain text, shown quoted and labelled "from the box" | never in a notification as if it were the box's own word |
| `requester` | kind and `uid` from `SO_PEERCRED` (box user, `ozbox-supervisor`, root helper, hub agent, the laptop key id), run id and engine when the kernel-attested run context has them (ADR 0029 A6 §5) | what the client claims (kept as `claimed=` only) |
| `where` | for a guard match: repo path hash, `file`, `line`, rule. For others the scope's own place | the matched text |
| `slot` | `(requester kind and uid, scope, operation key)`, the operation key defined per scope in §4. One live **pending** request per slot | |
| `epoch` | the request epoch of the store when it was filed (below) | |
| `expires_at` | the request's own, from the service's clock: **pending for 30 minutes**; once approved, **valid for 15 minutes** and **one use** (owner decision 1) | a device's clock |
| `state` | `pending`, `approved`, `spending`, `spent`, `denied`, `cancelled`, `superseded`, `expired` | |
| `decision` | who (person id or key id), through which surface, which **factor**, the key's presence class, when, and the **evidence**: for a passkey the authenticator data, client data, signature and credential id; for a laptop key its **key type**, the **signature format**, the signed message, the **authenticator data** (flags: user presence UP, user verification UV) and the **counter** where the format has them, and the digest of the attestation the key was enrolled with . A signature of an `sk` or WebAuthn key covers `authData \|\| H(message)`, not the message alone, so the format is recorded, never assumed to be "an Ed25519 signature over the message" | |
| `signed_envelope` | the envelope (id, scope, subject, digest, requester, expiry, state, epoch) signed by the service, so the hub can carry it (ADR 0042) | |

**Where it is stored.** In a **request journal**: a small file of its own, with its own lock, sealed under the same
key as the secrets store. Never in the secrets file. A request holds names, digests and counts only, so a leak of the journal
shows what was asked, never what was in it. Request churn then cannot touch the lock that `resolve` takes. The journal survives a
restart of the service, so a waiting hook does not lose its request.

**The request epoch.** The service keeps a random **epoch** outside the data a restore brings back. A new epoch is
made at every store recovery, adopt (ADR 0033), restore or blue-green replace (ADR 0038). Every non-terminal request of an older
epoch is void, and a record that comes back from a backup in state `approved` cannot be spent. The digest includes the store id,
which does not tell a restored store from its original, so the epoch does the work. The inbox says "requests were reset by a
restore".

**Who may read.** The supervisor and root: every request. The box socket (the box user and its agents): the
requests **its uid filed**, by id, plus the list of its own live ones, and only **id, scope, state, expiry and the digest**.
Never a fingerprint, a "changed or unchanged" flag or any other thing derived from a value. Nothing filed by the root helper or
the supervisor, except an id it was handed. "Its own" means the uid's, not the run's: every agent, run and the person's shell
share one box user, so run A can read run B's requests. That is honest, because the same uid can already read the other's
memory. On a worker the hub agent's socket carries `list` and `get` (§7).

**Common envelope, separate stores.** Three kinds of gated thing exist today: the agent's permission-engine asks (ADR 0022, held
by the supervisor), tool requests (ADR 0026) and, with ADR 0029, Production use requests (held by the issuer). They keep their
own stores, because the gate that spends must store. What becomes one is the **envelope**, the **rule table** (§3), the
**inbox** (§5) and the **audit words** (§8). The new object is for the gates that had only codes.

## 2. State and races

```
pending -> approved -> spending -> spent
   |          |-> expired | cancelled | superseded | denied (a revoke)
   |-> denied | cancelled | superseded | expired
```

- **A decision is a compare-and-set on `pending`** in the service. Two people at once: the first wins, the second is told "already
  approved by Alice on the dashboard (passkey), 12:03". An approve and a deny racing: the first wins.
- **An approved, unspent request can be revoked** by a deny from an approver of the same or higher authority. Recorded.
- **A spend that finds a changed subject is refused and changes nothing.** The request stays `approved` for what it was for.
- **A new filing in the same slot does not revoke an approved request.** The old approval stays spendable for its own
  digest until it is spent, expires, or the new request is **approved**, which supersedes it. The new request is a card of its
  own labelled "replaces a request Alice approved at 12:03", with what changed field by field. Every channel that has the old
  request is told. Approving the new one needs a fresh assertion (§3). So an agent that files a lookalike in the person's slot
  neither burns nor swaps the person's approval, and the person is shown the second card as a second card.
- **A spend rechecks the decider.** A laptop key is checked by the service itself: if it was revoked since, the
  approval is void. A person is known to the supervisor, not to the service, so the supervisor **pushes** `decider_revoked(person)`
  to the service when a person is demoted or removed, on its own socket, audited. Pending approvals by that person void at once.
  If the supervisor is down, the approval's 15 minutes is the bound, and the docs say so.
- **A wrong answer never burns a request and never locks a path.** A challenge is spent only by a valid signature or
  assertion. A signature check cannot be guessed, so it has no lockout. Rate limits are per socket and apply to box-user sockets
  only. Counters are per request. Garbage on a box-user socket, or relayed by the hub, never slows or locks the laptop path.
  Today's code has a global failure counter and a global challenge cap (16) that a box-user process can fill. Phase 1 fixes both
  and adds the two tests in §12.
- **Spend is crash-consistent.** The order is: compare-and-set `approved` to `spending` (durable), the audit
  line, the effect, then `spent`. A crash between leaves the request `spending`, which is refused and shown, never re-spent:
  it fails closed.

## 3. One rule table: where a scope may be approved, and with what

The table is one structure in `ozbox_core` (the same place as `SCOPE_RULES`), exported to the dashboard and the chat bridge, with a
parity test as `APPROVAL_SCOPES` has. A scope that is not in it is refused everywhere.

### The factors, said once

- **Dashboard decision.** Each Approve runs **one WebAuthn assertion for that request**, with user verification
  required. The challenge is `H("ozbox-approval-decide-v1", box id, store id, request id, subject_digest)`, built by the service
  (`decide_challenge`), never chosen by the dashboard. The supervisor verifies the assertion **in this release** and passes the
  evidence to `decide`, which stores it in `decision`. A passkey that was "shown a moment ago" for something else does not count,
  and one assertion decides one request, so one step-up never approves a batch. **One counter rule everywhere** (this ADR, ADR 0040's credential holder, ADR 0042's worker, ADR 0029's issuer): the signature
  counter is **checked when it is non-zero and refused if it goes back** (synced passkeys commonly report 0); the service also
  refuses an assertion it has seen. A request filed after the
  challenge was issued cannot be decided by it, because the challenge names the request. The challenge tag is distinct from
  ADR 0040's `ozbox-fleet-apply-v1`; the verification function is the same code, used by the supervisor, the service, ADR 0040's
  credential holder and the issuer.
- **An authenticator code never decides.** It still protects sign-in and the step-up for settings (ADR 0039). It does not satisfy
  `decide`, for any scope, and a code can be relayed through a lookalike page where a passkey cannot.
- **Laptop key.** An enrolled key (ADR 0028 item 4) with a recorded **key type**: `ed25519` (a software key, the only kind
  today), or a FIDO2 key (`sk-ssh-ed25519`, `ecdsa-sk`, or a WebAuthn P-256 credential). Its **presence class** is recorded on
  enrolment and on every decision: `laptop-key:<id>` for a key that is proved to need user presence, and
  `laptop-key:<id> (no user presence)` for every other key.
  - **Presence is proved, never declared .** It is accepted **only for a FIDO2 key whose attestation
    verifies**: format `packed` with an `x5c` chain, or `fido-u2f`, chaining to a **pinned set of vendor roots shipped with the
    program** (or the FIDO Metadata Service, with a stated offline update). **`none` and self attestation (`packed` with no `x5c`)
    are refused**: a software key can make both, and most synced passkeys return `none`. The attestation must be **bound to an
    enrolment challenge**, `H("ozbox-key-enrol-v1", box id, store id, request id, digest)` (for an `sk` key, `ssh-keygen -O
    challenge=` and `-O write-attestation=`), so an attestation made for one enrolment cannot be reused for another.
  - **Attestation shows where a key lives at enrolment, not that a signature was made with a touch.** So **every decision with a
    presence key carries its authenticator data**, and the verifier requires **UP = 1, and UV = 1 for an owner-only scope**, and
    applies the counter rule above. An `sk` key made with `-O no-touch-required` passes the attestation and shows UP = 0 in each
    signature; only this per-signature check catches it.
  - **The verifier is the service on the box** (on a worker, the worker's service; for Production, the issuer). The attestation
    travels with the key record to each of them. **A laptop-signed claim of "presence" is never enough.**
  - **A Secure Enclave key, a platform passkey and any other key whose proof is not named above are software keys**, until a
    named, checkable proof and its verifier exist and this ADR says so. (From recall, unverified: an unmanaged Mac gives a
    command-line program no proof a third party can check; App Attest needs a signed app and Apple's service; Managed Device
    Attestation needs MDM.) A platform passkey does not qualify.
  - **A software key decides only what a member may decide** (`guard-override`, and `import` of new names in a non-Production
    environment). **It never decides an owner-only scope, and nothing opts it in** (owner decision B, 2026-11-12; the
    `approvals.software_key_scopes` opt-in this paragraph first described was removed in the phase 1 review fixes, see build
    note 15). It never covers anything in the Production tier (below). `approve` with no terminal works only for a presence key.
  - **A software key never decides Production, with no opt-in** (delegated; owner to confirm): not `secret-use`, not a
    production-tagged action, not a Production use on a worker (also a `secret-use`; `worker-keys` is development and staging
    only, ADR 0042 §5), not an `import` of a value into an environment marked Production. Nothing in a policy, a box setting or an approval allows it.
- **Root** on the admin socket, and `bootstrap` on a box with no approver (below).
- **Telegram never approves any of these.** It names the change, sends a message and a link to the dashboard, nothing more (below). A chat app has no Approve, no Deny and no Stop: it never decides a request and never cancels a run (the amendment of 2026-11-13, and build note 27).

A person's role is ADR 0039's: **owner** or **member**; a viewer never decides.

### 3.1 The table for requests filed on this box

| Scope | Filed by | Dashboard (one assertion) | Laptop key with presence | Software laptop key | Telegram | Never |
|---|---|---|---|---|---|---|
| `guard-override` | the box user's hook | owner or member | yes | yes | notify-only | by the requester; for a Production-looking value (ADR 0029) |
| `import` | the laptop over ingress, or root | new names in a non-Production environment: owner or member. A replacement, any public mark, or Production: owner | yes | new non-Production names only; never Production | notify-only | filed by the box user; a value shown anywhere |
| `policy` | supervisor, laptop, root | owner. **Not** a change that turns `approvals.software_key_scopes` on, or that widens `host-guard` or `tunnel-token` after a presence key has existed: those are a laptop key with presence, or root | yes | no, unless the box opts in (never for those two changes) | notify-only | |
| `tunnel-token` | the root helper, the laptop | owner, **only until a presence key has ever been enrolled** (Delegated decision 1); after that, a laptop key with presence, or root | yes | no, never (not even opted in) | notify-only | |
| `box-secrets` | the root helper's script, the laptop | owner | yes | no, unless the box opts in | notify-only | a new address in bootstrap |
| `host-guard` | the root helper | owner, **only until a presence key has ever been enrolled** (Delegated decision 1); after that, a laptop key with presence, or root. **Loosening only** asks; tightening needs nothing | yes | no, never (not even opted in) | notify-only | |
| `signer-enroll` | supervisor, laptop, root | **revoke**: owner, any time. **Enrol**: owner, **only if this box has never had a laptop key** (Delegated decision 4); a later key waits 24 hours (below) | an enrolled presence key enrols at once | no | notify-only | on a box with no sign-in; a key whose possession is unproved; a box's enrolment ever reaching the issuer or another box |
| `setup-code`, `kek-export` (ADR 0029 A9 §6 M1) | the laptop over ingress | **not decidable on the dashboard**: `kek-export` opens every value on the box, and `setup-code` is the dashboard's own first-time code. Owner decides on the laptop | yes (a presence key) | no | notify-only | `kek-export` from the dashboard; with no second factor on the box, `setup-code` is allowed as the other first settings are, and recorded; `kek-export` is refused until one exists (ADR 0029 Amendment 9) |
| `worker-keys` (ADR 0042; development and staging only) | `main`'s hub | owner | yes | no, unless the box opts in | notify-only | a worker accepting a code; environment Production (that is a `secret-use` on the worker, ADR 0042 §5) |
| `secret-use` (Production) | the issuer | passkey via the issuer (ADR 0029 A6 §5) | laptop signer, a presence key | **never** (no opt-in) | notify-only | chat approval; bootstrap; a software key |
| agent action (ordinary, on the ask list) | the supervisor | member or owner | n/a | n/a | notify-only (a message and a link) | |
| agent action (protected branch, outbound message, spend above the threshold) | the supervisor | owner or member | n/a | n/a | notify-only | |
| agent action (tagged production) | the supervisor | **owner only**; a member may Deny it in the dashboard (ADR 0039 item 6) | n/a | n/a | notify-only | |

Rules that hold across the table:

- **The requester never approves its own request.** The box socket has no `decide`. A decision comes only from the supervisor's
  socket (a person's assertion), the root admin socket, the ingress socket with a valid laptop signature, or, on a worker, the hub
  agent's socket carrying a signed decision (§7). The signature or the assertion is the credential, never the socket alone, and
  never the box or import socket. **One exception, fail safe:** a **Deny of a pending request** relayed by the hub agent on a
  worker needs no credential (ADR 0042 §8), because `main` could deny by silence anyway; a **revoke of an approved request**
  needs its credential.
- **`signer-enroll` and the laptop key .** The dashboard may **revoke** a laptop key at any time, owner
  only, so a lost laptop is recoverable without root. It may **enrol** a key without the wait **only if this box has never had
  one** (Delegated decision 4), not "while the box has none". Every later key comes from an existing presence key or root at
  once, or from the dashboard with a **cooling-off of 24 hours**: the new key cannot approve until it ends; every existing
  approver is told on every channel; any approver or root can cancel; and the new key must prove possession by signing the
  enrolment request's digest (and, for a presence key, carry the attestation of §3 over the enrolment challenge). A software key
  cannot decide `signer-enroll`, so it cannot enrol a successor: a box that has only a software key gets its first **presence**
  key through the dashboard with the 24-hour wait, or root, or the box's opt-in. The key records `enrolled_via` (passkey, laptop
  key, root, pinned), shown by `ozbox approvals keys`. A box's `signer-enroll` never propagates to the issuer or to another box;
  a test pins it.
  - **Where "has ever had one" lives, and what a new store inherits.** Two markers, "has ever had a laptop key" and "has ever had a
    presence key", live **with the bootstrap marker** and are **cleared only by root**. Revoking every key does not clear them,
    and so does not put the box back into bootstrap. A store made by a **blue-green replace (ADR 0038), a recovery, an adopt (ADR
    0033) or a Hetzner re-create** starts with both markers **carried over** from its predecessor, and its laptop key is re-pinned
    by the laptop doing the upgrade, as ADR 0029 A9 §6 H2 does for the ingress key; if the markers cannot be carried (the
    predecessor is gone), the box re-enters the 24-hour wait. The **no-wait first enrolment exists only for a box `ozbox create`
    made fresh, with no predecessor.** The first enrolment on a box with no pinned key (a Hetzner or adopted box) is **trust on
    first use**, and the docs say so.
  - **A pending enrolment cannot be hidden by the supervisor.** The dashboard's 24-hour notice goes through channels the
    supervisor owns, so a compromised supervisor can suppress it. Therefore a pending enrolment is **listed to the laptop on its
    next ingress contact** (`ozbox approvals keys`) and is **written to the off-box audit head**, so the laptop and root can see
    and cancel it without the supervisor.
- **Chat keeps its rule** (`docs/use-cases/chat.md` §3, ADR 0029 A6 §6), owner decision 2: approving never happens in a chat for
  any of the gated scopes (the nine of §3.1, apart from agent actions). A chat message names the change and carries a **one-time link** to the dashboard card. The link
  is a **pointer, not a credential**: opening it shows the card behind the normal sign-in and consumes nothing. Only
  the assertion that decides consumes the request. The link is 24 random bytes held as a keyed hash, bound to the request id, its
  digest and the linked person, and the signed-in person must be that person. It lives ten minutes. It is sent with link
  previews off, so an unfurler cannot use it up. "Send me a new link" is not an approval.
- **A box with no sign-in** (ADR 0039 item 6) cannot be approved from its own dashboard at all. The laptop or root can.
- **A box with no approver (bootstrap)** keeps `SCOPE_RULES`'s `InBootstrap`: `import`, `policy` and `tunnel-token` are decided as
  `bootstrap` (still as a filed request, so the record has one shape); `box-secrets` for a first setting only; `signer-enroll`,
  `host-guard` and, since 2026-11-13, **`guard-override`** refused. A held change on a box with no second factor is edited, not
  let through: with no one to approve it, the box user would be approving its own override. The hold
  says how to enrol (a passkey in the dashboard, or `ozbox create` from a computer with a keychain). The rule is in both tables
  (`SCOPE_RULES` and the request rule table) and the dashboard's copy, and a test holds them together.
- **A box can narrow the table** (`approvals.surfaces.<scope> = ["laptop"]`), and narrowing is free, but only from the
  supervisor, the laptop or root, **never from the box socket**, and never to an empty set. Root can always reset it.
  Widening is a `policy` change decided on a surface that already had the scope, so a dashboard cannot grant itself one. **Once
  a presence key has ever been enrolled, only a laptop key with presence, or root, can widen `host-guard` or `tunnel-token`
  again, and only the same can turn `software_key_scopes` on; the sticky marker is not a `policy` field** , so a
  forged revoke cannot bring the dashboard path back.
- **The factor is honest in the record**: `passkey`, `laptop-key:<id>`, `laptop-key:<id> (no user presence)`, `root`,
  `bootstrap`. Never "chat", and never `passkey` for an authenticator code.

### 3.2 The table for requests filed on a worker (ADR 0042)

A request filed on a worker is verified by **the worker's own service**. `main` is a viewer and a relay, never an approver by
attestation. The row for each scope is ADR 0042 §8's; this ADR supplies the mechanism.

| Request on a worker | Decided by | What the worker's service verifies |
|---|---|---|
| agent action (ordinary), `guard-override` | the person on `main`'s dashboard, or the laptop | a **WebAuthn assertion** with the challenge of §3 (box id and store id are **the worker's**), user verification, the dashboard's origin, a credential in the **signed approver set** the laptop made (that set lists each credential with its person and role, owner or member, **members included**, ADR 0042 §8); or a laptop signature in its own format (§3) |
| agent action (protected branch, outbound message, spend) | the person | the same |
| agent action (production tag) | the owner, **a laptop key with user presence only** (ADR 0042 D1); a passkey on `main` is refused | a laptop signature with authenticator data (UP and UV), from a key whose attestation the worker holds (§3) |
| agent action in a **delegation** the laptop signed (ordinary kinds only) | the conductor | the hub's decision key and the laptop-signed delegation listing the exact kinds |
| `import`, `policy`, `tunnel-token`, `box-secrets`, `host-guard`, `signer-enroll` | **a laptop key with presence, or root**, never `main`'s dashboard (Delegated decision 2: root only until a presence key exists) | a laptop signature in its own format (Ed25519 for a software key, which cannot decide these; FIDO2 authenticator data for a presence key) over box id, store id, request id and digest |

A worker never accepts a code, and its `OZBOX_GUARD_APPROVAL` fallback is off. Where a worker may receive a Production value, and
how a worker's approver set is pinned on a provider, are ADR 0042's decisions and are not restated here. Verification of a
cross-box assertion is built in ADR 0042's phase H4, with the same function as above; the record format is frozen in this ADR's
phase 1 so that it needs no change. **Built (2026-11-17, tested with fakes):** `ozbox_core::hub::approvals::verify_fleet_decision` checks the
assertion's signature against the worker's pinned approver set and hands the request book the decision, whose own rules run again; the
secrets service answers it (2026-11-17, second pass; ADR 0042, "Integration"): `areq_hub_pending`, `areq_hub_decide` and `areq_hub_pin` on the socket the hub agent holds today (the supervisor's; a socket class of its own for the agent is not made), verified in the service against an approver set only root writes (`areq_hub_set_approvers`, admin socket; the sequence number never goes back and the set expires). Tested; not run on a real box.

## 4. What a decision binds: the subject, per scope

`subject_digest` is computed by one function, `ozbox_core::approval_subject`, used by the box and by the laptop, with golden test
vectors that both crates must produce.

**Encoding.** One version byte, the domain tag, then **length-prefixed fields** (4-byte big-endian length) in a fixed
order per scope. The box id, the store id and the scope are the first fields, so a digest cannot be reused on another box, scope
or version. A set is sorted and a duplicate is refused. Names are ASCII only, `[A-Za-z0-9_]`. The digest hashes the change's own
canonical fields directly, **never the 16-hex change code** the root helpers print (the existing `change_digest` joins words with
a space and keeps 64 bits). Golden vectors include adversarial cases: an embedded separator, an empty field, a duplicate name,
Unicode lookalikes, a field moved across a boundary. **This encoding is shared:** ADR 0040's fleet-apply challenge (`H("ozbox-fleet-apply-v1", box id, plan id, plan hash)`) and ADR 0042's channel messages use it with their own tags and the same golden vectors. A plan id is spent by its first assertion, and the credential holder refuses a repeat.

| Scope | Operation key (the slot) | Fields in the digest | Who recomputes at spend |
|---|---|---|---|
| `guard-override` (commit) | repo path hash, hook kind | the staged **tree id** (`git write-tree`), repo path hash, hook kind, and the service's own match list `(path, line, rule, key id)` and the hash of the scanned text | the hook (box user), through the service's `scan` |
| `guard-override` (push) | repo path hash, remote URL hash | the **normalised remote URL**, the pushed `ref old..new` commit ids, the match list over their text | the hook (box user) |
| `tunnel-token` | tunnel kind | `sha256(token)`, the kind, the decoded identity (cloudflared: account tag and tunnel id) | the root helper, which reads the token file first |
| `import` | project, environment | project, environment, sorted names, per name the classification (public or secret) and `sha256(salt, value)`, the project's **store generation** | the service, over the rows presented |
| `policy` | the box | sha256 of the canonical serialisation **of the parsed policy**, made by one function both sides use, and of the one it replaces. This is the digest a worker checks a declaration against: it receives the approved policy and its predecessor, recomputes `approval_subject`, and accepts only declarations contained in it (ADR 0042 §5) | the service |
| `box-secrets` | the declaration's address | the address and the change, or its removal, hashed from the fields | the root helper's script |
| `host-guard` | the action | the action and the change's fields | the root helper |
| `signer-enroll` | key fingerprint | key name, key type, public half, attestation digest, enrol or revoke | the service |
| `worker-keys` | orchestration id | orchestration id, sorted names, environment, maximum workers, time to live (a template, ADR 0042 §5; each delivery is audited with the worker and its attested key, and is not in the digest) | the service |
| `setup-code`, `kek-export` | the box | the scope, box id, store id and the service-issued challenge | the service |

**The card is derived from the digest.** What a person reads must be what is hashed.

- **Guard override.** The hook sends the text the service already scans (`--no-ext-diff --no-textconv`, so the agent's git config
  cannot change it). **The service scans it and derives the matches itself**: `file:line`, rule, "public" or not, and the matching
  key (shown to the owner's card, never to the box user). The match list is in the digest. The card is therefore the truth for the
  request that was filed. It binds the tree id, not `git diff` output.
- **Push.** The remote **URL** and the ref names are bound, not the remote name, because `git remote set-url` moves a name.
- **Tunnel token.** The root helper decodes as far as the provider allows and the card says "replaces tunnel X with tunnel Y". It
  warns loudly when the account differs from the current one: a token for someone else's tunnel sends the box's ports out through
  an account that is not the owner's.
- **Rendering.** Every requester-sourced string (file names, branch names, remote names, `reason`) is untrusted. Strip bidi and
  control characters, cap the length, show paths in code style, and escape for Telegram MarkdownV2 and Slack mrkdwn. Each field
  carries its source label. Scopes whose card is service-derived: `guard-override`, `import`, `policy`, `signer-enroll`,
  `worker-keys`. Root-helper-derived: `tunnel-token`, `box-secrets`, `host-guard`. Only `reason` is from the box.

**What the binding is worth depends on who recomputes.** Where the service or the root helper recomputes (every row but the
first two), a box user cannot swap the change after the approval: that is a real control. For `guard-override` the party that
recomputes is **the box user's own hook**. A hostile box user can skip the hook (`--no-verify`) or present the approved digest and
commit something else. So for the override the binding stops **honest tooling and accidents** and makes the card true for the
request filed. The audit records **what was approved, not what was committed**. It is not a defence against a hostile box user.
The barrier's strength against one is ADR 0023's and is unchanged (the box holds no credential to push with; the supervisor's
egress rules decide). The better design, after this release: the supervisor owns the push, has the service scan the pushed
commits, and spends a `guard-override` bound to commit ids and remote URL, so the recomputing party is not the box user. The
pre-commit hook stays as early feedback.

**The import's digest** uses a salt the sender chooses per import, so both sides can compute it. The service keeps only the
digest and never returns the salt or a per-value hash on any read path. The **keyed fingerprint** (HMAC under a key only the
service holds) is **display only**, goes **only to the supervisor and the laptop**, and is not in the digest. The laptop
recomputes the digest from the rows it sends and refuses to sign a request whose digest differs. A dashboard approver cannot
check values, so the card says plainly which names, which replace, which are public, and that the values come from the laptop.
Putting the classification and the store generation in the digest means an auto-public mark cannot slip in under a member's
approval, and an old approved import cannot be replayed after a value was rotated (it would bring back a revoked value).

The gate at spend time **recomputes the digest from the operation as it stands**. Equal: spend. Different: refuse, keep the
approval, and say what differs by field name, never a value.

## 5. Surfaces

**Dashboard, "Approvals".** The Approvals page already exists, and Settings has a separate page that mints codes. This ADR
**extends the Approvals page into the one inbox** and makes the Settings page the fallback. One card per request, newest first,
with the change shown in full (the derived fields of §4, each with its source label), who or what asked, how long it has left,
the rule ("needs your passkey", "owner only"), and Approve and Deny. The agent approvals, tool requests and Production uses
appear through the envelope. On `main` the same card appears for a worker's request, with the worker's name and a "waits on a
worker" state: the **fleet inbox** (ADR 0042). The dashboard recomputes `approval_subject` from the signed fields and refuses to
show a card whose digest does not match. A card the viewer's role cannot decide is read-only with the reason (ADR 0039 item 7).
Approving asks the service for the challenge, runs the assertion, and the supervisor verifies it and calls `decide`. The card then
shows "approved by Alice, passkey; spent by the guard's pre-commit at 12:03". The old "mint a code" form stays under "Advanced",
now minting a code **for a pending request** (§10). The page degrades when the service has no request ops, never errors.

**Telegram (and Slack, WhatsApp).** A message per request, once, with the derived fields and a link to the dashboard card (§3). **Notify-only: no button, no Approve, no Deny and no Stop, and nothing said back decides or cancels anything.** (The agent-action Approve and Deny buttons and the Telegram Deny of the first text were removed by the amendment of 2026-11-13.) Coalesced:
more than ten in an hour become one digest, and cards for one scope coalesce after three. It never carries `reason` as
the box's word and never a value. Anything a linked person does there is judged by their role as it is now (ADR 0039 item 3).
Chat surfaces exist **only where the bridge runs as `ozbox-supervisor` and the box socket is `BoxLocked`**: the bot token
(`telegram-bot-token`, `whatsapp-token`) is in the box socket's allowed prefixes today, and a box user holding it could send
lookalike links or take over the webhook. A test pins it. Card fields (repo paths, key names) go to a third party. The docs say
so, and `notify.detail = minimal` sends the scope and "open the dashboard" only.

**Laptop.** `ozbox approvals list <box>`, `show <id>` (the full subject, rendered only from fields the laptop parsed itself and
checked against the digest), `approve <id> --digest <full 64 hex>`, `deny <id>`, `keys`. The key is the pinned one and the
decision is `via=laptop-key:<id>`, with its presence class. **The full digest is required**: a prefix can be ground
by a filer who chooses the import's salt. With no terminal, `approve` works only for a presence key. For work the laptop starts
itself (`secrets import --box`, `tunnel setup`, `box-secrets`, `host-guard`), the laptop makes one signed message,
`request_and_decide`, and sends the box a **request id and a signature**, not a code. With a **software key** the laptop may not
decide the owner-only scopes of those flows: it **files** the request (a signed `file`) and says "approve it in the dashboard or
with a presence key". Before it files or decides, `request_and_decide` fetches a **service-issued challenge** (one round trip over
ingress), so replay protection does not depend on the laptop's clock or on a seen-set that must survive a restart.

## 6. Delivery: the box hands the decision to the waiting operation

A box-originated operation (a commit hook, the root helper, the box's secrets script) does this:

1. It asks its gate. The gate refuses with "needs approval" and the operation **files a request** (`file`, on its own socket class)
   and receives `{id, state: pending, expires_at}`. `capabilities` is asked **only here, on the refusal path**, never on a clean
   commit.
2. It prints one line: "Waiting for approval, request R. Decide it in the dashboard, in Telegram's link, or `ozbox approvals`.
   Ctrl-C stops waiting; the request stays for 30 minutes." and calls `await(R)`. The server holds the call for **at most 60
   seconds** and the client calls again: a long poll, not a busy loop, inside the 20 to 60 second read timeouts the service's
   clients already set. The service caps concurrent awaits per uid (16) and per request (4), and a test proves `resolve` and the
   broker still answer when the cap is hit.
3. On `approved`, the service answers with the request's `subject_digest`. The operation **recomputes** its own and spends it.
   **Spend comes only from the socket class that recomputes**: `guard-override` from the box socket (the hook); root
   scopes from the admin socket (the root helper); service scopes (`import`, `policy`, `signer-enroll`, `worker-keys`) only
   **inside the operation itself**, never as a separate `spend`. The service checks state, epoch, expiry, digest, the decider
   still being valid and the slot, then does the order of §2 (audit fail closed).
4. A hook that gave up can be run again later: the same digest **in the same slot** returns the same request (never across
   requester kinds), which is also how a looping agent does not flood. It spends it.

Nothing in 1 to 4 is a bearer value. What the service hands back is a digest, not a code. **An approval is for the change, not for
the process**, within the requester kind and the slot, and the change is what the person saw.

For a laptop-started operation the order is reversed: the laptop signs, and the signature travels with the operation. The
signature covers box id, store id, request id and subject digest, and is good once for that subject. Anything that reads it on the
way can perform **only the change that was approved**, once. That is the property the code lacked. But request ops are offered
only on the sealed route (§7), so nothing travels through the box user's shell at all.

**Expiry is the request's.** The five-minute `DEFAULT_TTL_MS` belongs to the approval code and stays only there.

## 7. No box-user shell on the path

The route is the one ADR 0029 Amendment 9 builds on `feat/prod-secrets-p1`: the `ozbox-ingress` account (root-owned home and
keys file, a forced `ozbox secrets receive`, no terminal, no `~/.ssh/rc`), a socket of its own in the secrets service, and a
request **sealed with HPKE** to a service key the laptop pinned the first time through that route. This ADR adds **operations** to
that route and to the sockets. It adds no transport of its own. **The operations added here (`file`, `get`, `list`, `await`, `decide`,
`request_and_decide`, `cancel`) join the list of sealed operations of ADR 0029 Amendment 9 §2** (that list is the code's floor, not a
ban on new operations), sealed to the service key the laptop pinned; ADR 0040's `fleet_window` is sealed to the credential holder's
key, which the laptop pins the same way.

| Path | Channel and ops | Peer identity |
|---|---|---|
| A hook or helper on the box files, awaits, spends | the box socket (`file`, `get`, `list`, `await`, and `spend` for `guard-override` only) | `SO_PEERCRED` names the uid; no `decide` |
| The root helper files, awaits, spends | the admin socket | root |
| The dashboard decides | the secrets service's **supervisor socket** (`Policy::Supervisor`, a socket of its own for `ozbox-supervisor`). Ops: `list`, `get`, `decide_challenge`, `decide`, `cancel`, `decider_revoked`. No `file`, no `spend` | the kernel names `ozbox-supervisor`; the handler has verified the assertion |
| The laptop lists, shows, files, decides | the **ingress socket**, sealed. `decide` with a laptop signature lives **here only** | the signature; the seal keeps the bytes private |
| On a worker, the hub agent relays | the hub agent's scoped socket: `list`, `get`, and the relay of a **signed** decision to `decide`; **a Deny of a pending request needs no credential, a revoke of an approved one does**. No `file`, no `spend` (ADR 0042) | the kernel names the hub agent; the decision is the credential |
| The laptop on a box with no ingress account | **no request ops and no code route**: it is refused with a sentence, as ADR 0029 A9 does | none |

ADR 0040's scoped socket is the **daemon's** socket for the dashboard user (chat and runs). It is not the secrets service's
supervisor socket, which already exists. The two are separate.

**What the seal and the binding each give.** The seal keeps the content (an import's values, a signature) from anything on the
path. The binding keeps a signature that did leak good for **one change, once**. Neither is needed for a box-originated request,
where nothing travels outside the sockets above.

**The residual gap, said plainly.** A box made before the ingress account (a Hetzner box made earlier needs a new box and a clone
of `/work`, ADR 0029 A9 §2), or an adopted machine whose sshd block was never added, has **no laptop route at all** once the
ingress route merges. Its approvers are the dashboard (assertion per request) and root, and request-bound
dashboard codes if the owner wants them (§10). The docs say so and give the re-create path. The laptop never falls back to the old
route silently.

A request, a decision or a digest never goes on a command line or in an environment. The service's answers to the box socket
carry digests and states, never a code.

## 8. Audit

Every step is a line in the audit chain written by the service (ADR 0028 item 1), in the service's own vocabulary, which no box
process can forge:

`secrets.approval.request.filed`, `.superseded`, `.decided` (who, surface, factor, presence class, decision), `.revoked`, `.spent`,
`.refused` (with the field that differed), `.expired`, `.cancelled`, `.delivered` (the await answered), `.key.enrolled`
(with `enrolled_via`).

On a decision that came from `main` for a worker, the worker's line carries `via=fleet:<main id>` and the assertion counter. `main`
writes its own: `hub.approval.shown`, `hub.approval.relayed` (request id, worker, digest first 16, who), `hub.keys.released`
(names, worker, task, time to live; never values). They share the request id and the digest prefix, so Activity joins them, and a
relayed decision that never reached the worker is shown as such. **The worker's record is the proof** (ADR 0042 §9).

Fields: id, scope, `subject_digest` (first 16), requester kind and uid, run id, decider id, surface, factor. Never a code, a value,
a token, a diff or a file's contents.

**Order and failure.** State compare-and-set, then the audit line, then the effect. **Approve and spend fail closed**:
no chain line, no effect. **Deny, revoke and cancel fail safe**: the state changes at once, and the line is written when the
chain is back, marked late. Failing closed on a deny would fail open on the change. `filed`, `expired` and `.refused` are best
effort but **counted** against the quotas of §11 in the service, so a failing chain, or a flood of refused spends, cannot be used
to flood. The dashboard's Activity reads these lines.

## 9. The guard's part

The guard is where the day's friction was, and it gets the same treatment.

- **Public values (owner decision 8).** A key can be marked **public**: stored as a configuration value, never matched by the
  barrier, never redacted. At import these prefixes are marked public: `NEXT_PUBLIC_`, `VITE_`, `EXPO_PUBLIC_`,
  `NUXT_PUBLIC_`, `REACT_APP_` and **`GATSBY_`**. The bare `PUBLIC_` prefix is **not** one (decision D2, 2026-11-13): servers and
  shells use it for values that never leave the box, so a SvelteKit or Astro project, whose `PUBLIC_*` variables are browser values,
  marks them public at import (`ozbox secrets import --public NAME`). **Built (2026-11-13):** one address
  check stands in front of both ways a value becomes public (the person's mark, and a name of a public kind): an address with user
  info (`scheme://user:password@host`) is never public, and neither is one of a short list of addresses that are themselves a
  credential (Slack, Discord and Teams webhooks, a Google Apps Script link). **Planned, not built:** the rest of the deny-list of
  secret-bearing URLs (signed object links, invite links), a path-segment high-entropy test, and a plain public URL being
  public by its shape alone; a public name or a mark is what makes a value public today. **An address with a query or
  a fragment is never public by its name** (item 64): a public address that needs a query (a TURN server's `?transport=tcp`) is
  held as a stored value, and needs the owner's explicit decision. The public mark itself still refuses `?` (a public value is
  plain text, so that it needs no quoting where it travels), so today that decision is to keep the query in its own variable, or
  an override; allowing `?` in a mark is the owner's to decide. **Never auto-public in an environment marked Production.** A name that looks public with a value that looks like a credential (`sk_live_`, `AKIA`, a private-key block, a
  long high-entropy string) is **not** marked public, and the preview says why.
- **Who may mark.** The preview shows every key's classification before the person confirms. **Auto-marks are in the import's
  digest and need the owner**: a member who approves an import cannot lower a protection through it.
  `ozbox secrets mark-public <key>` is by hand and is a `policy` change (owner), because it lowers a protection.
  `mark-secret` is not.
- **A floor for matching.** A stored value is matched in a diff only if it is at least **12 characters long** (built, item 63).
  Below the floor the value is still stored and still redacted from output, but a commit is not stopped by it, and the floor
  applies inside `scan`. **Planned, not built:** an entropy test on top of the length (so that a dictionary word of 12 or more
  characters is not a match), with tests on real false positives.
- **Where, and no names to the box user.** A refusal says `file:line` and the rule for a shape match, and `file:line`
  for a stored-value match, **without the secret's name**; the approver's card names the matching key. **Built:** the hook's printout
  (item 54). **Planned, not built (G17):** the `scan` op itself returning a count and not names to the box user (today it returns
  the names of what it matched, which is why the 12-character floor matters), and the service counting stored-value hits per hour
  and, above a threshold, no longer answering and raising an alert. Nothing counts hits today.
- **An override is a request** (`guard-override`) bound as §4 says. The hook waits (§6). A commit edited after approval is a
  different digest and is refused.
- **What a hook prints** when blocked: the matches with places, the request id and where to decide it, and "if this is a public
  value, ask the owner to mark its key public (the request names the key)".

## 10. Migration

Owner decision 7 was **no scope-only approval codes on boxes made from this release**. **Changed by the owner, 2026-11-13: codes
stay ON for every operation, on every box, until phase 3.** Phase 3 turns them off everywhere and removes the switch below.

- **A service that has request ops mints a code only for a request id.** The mint form lists pending requests and the
  code carries that request's digest, so the fallback has the same binding and differs only in transport. It is never
  carried by a laptop through the box user's shell, and never needed on a box with ingress.
- **Legacy scope-only codes are on by default until phase 3 (owner, 2026-11-13).** They are minted and accepted on every box,
  new or upgraded, unless root's file `/etc/ozbox/approvals-legacy-codes-off` is present (`approvals.legacy_codes_off`), which
  turns them off on that box. What this leaves open: a code is not bound to a request, so the weaker binding of section 10's
  fallback applies to every gate, and the dashboard's step-up can mint a code for any scope except `signer-enroll`. Phase 3
  turns codes off everywhere and removes the switch and the file. `OZBOX_GUARD_APPROVAL` keeps working with its notice until
  then. The typed-code form stays only as the break-glass of ADR 0029.
- **The laptop pins** "this box has request ops and ingress" the first time it sees it, as it pins the ingress key (ADR 0029 A9
  §2), and **never falls back silently afterwards**. A later answer that turns request ops off is refused. A fallback needs an
  explicit flag and a printed warning.
- **Capabilities, not versions.** The service answers `capabilities` with the request ops it has. The laptop, the dashboard and the
  hooks ask first, the hooks on the refusal path only. ADR 0036 keeps the program, daemon and image on one minor.
- **New laptop, old box:** refused with a sentence; nothing is sent through the box user's shell (a test). **Old
  laptop, new box:** it has no request ops and uses the code route that the ingress route allows, which on a new box is closed, so
  it is told to upgrade. **New box, old dashboard:** the inbox shows what the old dashboard knew. **New dashboard, old service:**
  the Approvals page keeps the mint form and shows "Requests need a newer box. Upgrade."
- **A box on 0.1.1** (the image on `main` today) has no request ops: its guard overrides stay codes, bound to nothing. The upgrade
  is the fix, and `ozbox upgrade` (ADR 0038) says what it brings.
- **Public marking** needs no migration for existing values: they are unmarked, so behave as today, and `ozbox secrets classify
  --apply` offers the marks as a reviewed `policy` change.
- **A restore, adopt or blue-green replace** voids pending requests by epoch (§1) and says so.
- **Hetzner and your own machines.** Nothing here uses a cloud API. The request journal is on the box. The laptop approver is
  pinned at `ozbox create` where labels allow it (ADR 0028 A1; Hetzner and adopted boxes may not be able to render it on upgrade,
  ADR 0029 A8), and for those boxes the approver is the dashboard with its per-request assertion, or root, exactly as §7 says.

## 11. Threats and failure modes

| Who or what fails | Fake request? | Flood? | Read others'? | Approve its own? | What limits it |
|---|---|---|---|---|---|
| **A compromised box user or agent** | Yes: that is the point of a request. For the scopes with a service-derived card (§4) a fake request can only describe what it would do. For `reason` it can say anything, and it is labelled "from the box". | Bounded: one live pending request per slot, the same digest returns the same request only within its slot, at most 8 pending per scope and 30 filings an hour for the box socket **counted per run where the run is attested**, with a small reserve for terminal callers; refused spends are counted; a notification digest after ten. Person-originated paths are outside this budget, so it cannot lock the owner out. | Its uid's own, by id, digest and state only. | No: the box socket has no `decide`, and the dashboard needs an assertion bound to one request. | It can socially engineer: a request that reads true because it is. It cannot burn or swap a person's approval (§2). |
| **A compromised dashboard (supervisor)** | Yes. | n/a | Yes, all. | In v1 it can **forge** a decision the table allows the dashboard to make, because the supervisor, not the service, verifies the assertion. It cannot replay an assertion for another request, batch one step-up, or use an authenticator code. | **v1 trust is the supervisor's word, narrowed by H1.** The evidence is stored, so phase 5 moves the check into the service with no format change, and old decisions become verifiable. A box can limit scopes to the laptop (§3). |
| **A compromised `main` (the hub), on a worker** | Yes (it can show a card). | n/a | Yes, `main`'s own. | **No.** It can relay, delay, hide or deny a decision, and show a misleading card. It cannot make a worker approve, because the worker's service verifies the assertion or signature itself and trusts only the laptop root key and the approver set the laptop signed. | The card is derived from the signed digest fields, and the laptop's `ozbox approvals show` is the independent check. Owner-only scopes on a worker are laptop or root only (§3.2). |
| **A lost or stolen laptop** | n/a | n/a | n/a | n/a | Revoke the key from the dashboard (owner, passkey) or root; its pending decisions die at spend (§2). A software key has no user presence and is limited to member-level scopes (§3); a passphrase on the keychain item is advised. |
| **An agent on the laptop** (prompt-injected) | n/a | n/a | n/a | Only through a software key, and only for member-level scopes. | A presence key prompts for every approval; `approve` with no terminal needs one (§3). |
| **Two people at once** | n/a | n/a | n/a | n/a | Compare-and-set; the second sees who and how (§2). |
| **The dashboard is down** | n/a | n/a | n/a | n/a | The laptop and root paths do not touch it. The hook keeps waiting, or the person decides on the laptop. |
| **The secrets service is down** | n/a | n/a | n/a | n/a | Fail closed, as today. Requests persist across a restart. A cap on awaits keeps `resolve` and the broker answering under load (§6). |
| **Telegram account takeover, or a stolen bot token** | n/a | n/a | n/a | No | It can ask for a new link. It **cannot approve, deny or stop anything**; the link opens a card that needs the linked person's assertion. The bot token is unreadable by the box user (§5). A person removed from the list is refused at once. |
| **A shell function on the box user** | n/a | n/a | n/a | n/a | Sees a request, a digest or a signature: one change, one use. On the sealed route it sees no import value. On a box with no ingress there is no laptop route at all (§7). |
| **Replay, or a restored backup** | n/a | n/a | n/a | n/a | One use; messages name box, store, request, digest and a service-issued challenge; a distinct domain tag per use; the epoch voids a restored `approved` record (§1). |
| **Clock** | n/a | n/a | n/a | n/a | Expiry is the service's. A laptop's `signed_at` is advisory, and `request_and_decide` does not rely on it (§5). |
| **A restored or replaced store** | n/a | n/a | n/a | n/a | New epoch; non-terminal requests of an older epoch are void (§1). The "has ever had a key" markers are carried over, not reset (§3.1). |
| **A forged revoke of every presence key (a compromised dashboard)** | n/a | n/a | n/a | n/a | **A denial-of-service lever, and the intended fail-safe.** Afterwards loosening `host-guard` and `tunnel-token` is **root-only** until a new presence key is enrolled, because the sticky marker stays set (§3.1). The supervisor can suppress the 24-hour notice, so a pending enrolment is listed to the laptop on its next ingress contact and written to the off-box audit head. |

## 12. How it is built, tested, and what it costs

### Build plan (one agent each; 1 to 4 for the next release)

0. **Prerequisites, not an agent of this ADR.** ADR 0029 Amendment 9's ingress account and sealed route merge from
   `feat/prod-secrets-p1` in the same release (owner decision 6; phase 2's laptop side and every "no code in the box user's
   shell" claim need it). ADR 0028 Amendment 3 moves into `docs/adr` first (done). If the ingress route slips, ship phases 1, 3 and 4 and
   say in the release notes that the laptop stays on codes until it lands.
1. **Core and service.** `ozbox_core::approval` (envelope, state machine, `approval_subject` with its encoding and golden
   vectors, the rule table with its TypeScript export and parity test). Service ops: `capabilities`, `file`, `get`, `await`,
   `decide_challenge`, `decide`, `spend`, `cancel`, `list`, `decider_revoked`. The **decision record with the assertion fields is
   frozen here**, so a later move of the check into the service changes no format. **Do not freeze it before these are in:** the key
   type, the signature format, the authenticator data and counter, and the attestation digest (§1 `decision`, §3). The request journal and its own lock, the epoch,
   the await caps and a 60-second long poll, the per-socket rate limits and per-request counters (fixing today's global ones),
   quotas, the audit order and words, bootstrap integration, the origin and `signed_envelope` fields. **The new ops stay
   unreachable until a decider ships** (behind `capabilities`). Adversarial tests from §11. **No UI, no CLI.**
2. **Laptop.** `ozbox approvals list|show|approve|deny|keys`, `request_and_decide` with the service challenge, the signed `file`
   for software keys, the presence class, the message and its domain tag, the pin of ingress and request ops, no silent fallback,
   docs and the CLI reference. Needs the ingress route.
3. **The guard.** Public marking and classification at import, `mark-public`, `classify`, the URL deny-list; the matching floor;
   `file:line`; `scan` without names; the override as a request with the waiting hook; `OZBOX_GUARD_APPROVAL` as the deprecated
   fallback; the stored-hit counter. **Never ship the waiting hook before a way to decide exists** (phase 2 or 4): otherwise
   every blocked commit waits 30 minutes on a request only root can decide. The floor, `file:line` and the `scan` change are safe
   alone; public marking is safe only with the owner gate and the URL deny-list.
4. **Dashboard and chat.** The Approvals page extended into the inbox with the card, `decide_challenge` and the supervisor's
   assertion check, the envelope for the existing agent approvals, tool requests and Production uses, the Telegram, Slack and
   WhatsApp messages with the pointer link and no button, `notify.detail`, the bot-token boundary, i18n, capability gating, the browser
   tests, the Help pages and the changelog. Safe only with the per-request assertion and the Telegram rules.
5. **After the release.** The service verifying passkey assertions itself for decisions on its own box (the check of
   `ozbox-issuer`, A9 §4), so a dashboard relays and cannot approve alone; the supervisor-owned push for `guard-override` (§4).
   **Cross-box decisions are not in this phase**: the worker's own service verifies them **in this release**, built in ADR 0042's
   phase H4 on the record frozen in phase 1 here.

**Order:** 1, then 2 and 4 in parallel, then 3.

### Test plan

- **Unit and property.** The state machine (every transition, every race, `spending` after a crash); `approval_subject` golden
  vectors identical in the box and laptop crates, with the adversarial cases of §4; the rule table against `SCOPE_RULES`, the
  dashboard's list and the chat bridge; quotas; expiry against a fake clock; the epoch (a restored `approved` record is void).
- **Adversarial, from the box user's socket.** Files fake requests (flood, duplicate, huge fields, control characters in
  `reason`); calls `decide` (refused); reads another's request; spends with a different digest (refused, approval kept); spends
  twice (second refused); replays a captured laptop signature (refused: spent); uses a code-challenge signature as a request
  signature (refused); wraps `ozbox` with a shell function and still cannot change what was approved; files in a person's slot and
  neither swaps nor burns the person's approval; spends a root scope from the box socket (refused, approval kept); opens
  thousands of `await`s and `resolve` still answers; fills the challenge cap and the laptop path still works; garbage on the box
  socket never locks the signature path; **a wrong answer never burns a request**.
- **Assertions.** An assertion for another request, another digest or another box id is refused; one assertion never decides two
  requests; an authenticator code never decides; a request filed after the challenge cannot be decided by it; a zero counter is
  accepted and a repeated assertion is not.
- **Cards.** The match list is derived by the service from the scanned text; a hook that lies about a path is caught by the digest;
  bidi and control characters are stripped; Telegram and Slack escaping; the tunnel card shows the decoded identity and warns on
  a different account; the link fetched by an unfurler consumes nothing; a different signed-in person is refused.
- **Keys.** A dashboard cannot enrol a second key inside 24 hours or without proof of possession; a software key cannot decide
  an owner-only scope or `signer-enroll`; a no-terminal `approve` with a software key is refused; the `approve --digest` prefix is
  refused; a box's enrolment never reaches the issuer; a later answer of "no request ops" is refused by a pinned laptop.
- **Migration.** A new laptop with an old box refuses and sends nothing through the box user's shell. A box without request ops
  (the 0.1.1 service): every surface says so. Every box accepts a scope-only code and `OZBOX_GUARD_APPROVAL` until phase 3 (owner,
  2026-11-13), unless root's off-switch file is present, and then refuses them.
- **Per scope, end to end on the simulated box:** the blocked operation files, waits, a decision arrives on each allowed surface
  and is refused on each forbidden one, and the operation proceeds once; then edited-after-approval is refused and the approval
  survives.
- **Guard.** False-positive fixtures from 2026-11-12 pass; real keys and private-key blocks still block; the URL deny-list
  fixtures (each webhook and signed link) are not public; the message has `file:line` and never the value or the name; `scan`
  returns no names to the box user; the stored-hit counter locks.
- **Dashboard.** Component tests for the card per role; browser tests at 390, 820 and 1440 with the dashboard, a Telegram stub and
  the laptop deciding the same request; "already decided by" for two deciders.
- **Real boxes (to call anything "Works").** AWS `main`, a Hetzner box, an adopted machine; the real Telegram flow; the 2026-11-12
  guard-blocked commits replayed. Until then every part is Planned, then Preview when CI covers it.

### Benchmark (the owner's rule, 2026-11-12)

None of this is on a measured path. **No gate adds latency to a run's `exec`**: approvals gate control-plane changes (a guard
override, an import, a token, a policy, a declaration, a host guard), and `exec`, `env run` and `secrets resolve` do not call them.
A request is filed only **after** a gate has refused, so a clean commit, an allowed import or a normal run costs what it costs
today, and `capabilities` is asked only on that refusal path. The requests live in a journal of their own, so request churn
never touches the lock `resolve` takes. The wait is a long-poll read, not a loop.

**The guard's hooks are installed in every repository under `/work`** (ADR 0023 item 4, and a timer puts them back), so the
benchmark's "Git common operations" run them. A clean diff does one scan as today; the public-value exclusion and the
entropy floor make the stored set **smaller**, so the scan is equal or faster; the tree id and the diff text are computed only
on the override path. **Phase 3 measures a clean commit with both git hooks (pre-commit and post-commit) installed, in `/work`,
before and after, on the benchmark shape (4 vCPU, 8 GiB, 40 GB)**, and a regression beyond noise blocks the phase. The size is
added to the catalog first (ADR 0042 §13). Nothing is cached for the benchmark, and nothing is keyed on benchmark repos.

## Owner decisions (2026-11-12, binding)

1. **Times.** Pending 30 minutes, approved 15 minutes, one use. Production keeps ADR 0029's own numbers. `request_and_decide`
   has no approved state: it is spent in the same call.
2. **Chat.** Chat never approves any of the nine gated scopes (§3.1: the seven of the original decision plus setup-code and kek-export). It names the change and carries a one-time link to the dashboard card; it has no Approve, Deny or Stop.
3. **Passkeys.** A per-request, digest-bound passkey check, verified by the supervisor **in this release**. An authenticator code
   never decides. The service verifies assertions itself **after** the release for a box's own decisions. **Cross-box decisions**
   (ADR 0042) are verified by the worker's own service **in this release**.
4. **Laptop keys.** The dashboard revokes a laptop key at any time. It enrols only the **first** laptop key; later keys wait 24
   hours with a notice, or come from an existing laptop key.
5. **Members** approve `guard-override` and imports of **new, non-Production names** only. Everything else is owner-only. No one
   approves their own request.
6. **The sealed ingress** (ADR 0029 Amendment 9) merges in the same release.
7. **Codes.** Scope-only codes stay on for everything until phase 3 (owner, 2026-11-13), which turns them off everywhere. Dashboard
   codes are bound to a request once that lands. A laptop code never goes through the box user's shell.
8. **Public by name.** `NEXT_PUBLIC_*`-style prefixes (with `GATSBY_` added) and plain public URLs with a deny-list of
   secret-bearing URLs; never auto-public in Production; auto-marks are in the import digest and owner-approved; mark-public by
   hand.

### Formerly open, now decided (delegated; the owner can change them)

1. **Laptop and root only for `host-guard` and `tunnel-token`, once a presence key exists:** decided, see Delegated decision 1.
   The two dashboard cells of §3.1 say so.
2. **Software keys on owner-only scopes:** decided as never (owner decision B; there is no opt-in), see Delegated decision 2.

## Consequences and what is not covered

- A new object, a new journal and a larger service surface: the request ops are a second part of the gate and must be reviewed as
  carefully as the codes.
- A compromised supervisor can still **forge** a decision in v1, because it verifies the assertion. H1 removes the cheaper
  attacks (session theft, CSRF, a batch under one step-up, code phishing). Phase 5 closes the rest for a box's own decisions.
- The guard override binds honest tooling and accidents, not a hostile box user, until the supervisor owns the push.
- On a box without the ingress account there is no laptop route. The binding makes a signature taken from the box user's shell
  useless for another change, but such a box has no laptop route to take one from.
- Agent approvals, tool requests and Production use keep their own stores; only the envelope, table, inbox and audit words are
  shared. A fourth kind of gate must choose its store with the gate that spends.
- The `secret-use` (Production) row is a pointer to ADR 0029, which keeps its own issuer; the no-software-key rule is repeated in its Amendment 9 §4.
- Not proven on a real box. Every part is Planned.

## Delegated decisions and fixes (2026-11-12, overnight)

The owner delegated these to an advisor ("pick the recommended path and ask Fable for advice"); the owner can change
them. Items 3 and 4 were checked by the consistency check and are restated here as the check asked.

1. **Laptop and root only for the riskiest scopes, once a presence key exists.** Wherever a laptop key with proven user
   presence (§3) is enrolled, loosening `host-guard` and `tunnel-token` are decided only by that key or by root, not the
   dashboard. Reason: in this release the supervisor, not the service, verifies passkey assertions (§11), so a
   compromised dashboard could forge a dashboard decision, and these two scopes turn a short compromise into a lasting
   one. The narrowing is **sticky**: once a presence key has ever been enrolled, only **a laptop key with presence, or root**,
   can widen these scopes again, so a forged revoke cannot bring the dashboard path back. The sticky marker is not a `policy`
   field, and `software_key_scopes` never extends to these two scopes. The forged-revoke consequence (root-only until a new
   presence key) is a denial-of-service lever and is stated in §11. `signer-enroll` stays as owner decision Q4.
2. **Software laptop keys never decide owner-only scopes** (no opt-in: `approvals.software_key_scopes` was removed, build note 15). A software
   key can be used by any process of the laptop user without a prompt, so a prompt-injected agent on the laptop could
   approve a box agent's request. Owner-only flows started from the laptop become "file, then approve in the dashboard";
   on a worker (§3.2) and on a box with no sign-in they are **a laptop key with presence, or root**, so root-only until a
   presence key exists. **A FIDO2 `sk` key as the root and approver key is phase 2's first deliverable** (after the release);
   a platform passkey does not qualify (item 3).
3. **Presence is proved, never declared, and Secure Enclave counts as a software key.** A key record carries its key type and
   an attestation; the service accepts "presence" only from a verified FIDO2 attestation as specified in §3 (accepted formats
   and pinned roots, `none` and self attestation refused, an enrolment challenge, authenticator data with UP, and UV for
   owner-only scopes, on every decision, and the counter rule). **The "platform's own proof for a Secure Enclave key" branch is
   removed**: no named, checkable proof and verifier exist for it, so a software P-256 key could claim it. Anything else is a
   software key. The decision record gains key type, signature format, authenticator data and the attestation digest; **phase 1
   must not freeze the formats before these fields are in.**
4. **"First key" means first ever, across a new store.** The dashboard may enrol a laptop key without the 24-hour wait only if
   this box has never had one, not "none at the moment". The "has ever had a key" and "has ever had a presence key" markers
   live with the bootstrap marker, are cleared only by root, and are **carried over** by a blue-green replace, recovery, adopt
   and a Hetzner re-create (or the box re-enters the 24-hour wait). The no-wait path exists only for a box `ozbox create` made
   fresh with no predecessor (§3.1).
5. **A software key never decides Production, with no opt-in** (new; delegated; **owner to confirm**, because it narrows an
   option ADR 0029 Amendment 6 §9 once allowed). Applies to `secret-use` (a box's own Production, or a Production use on a worker),
   a production-tagged action and an import into a Production environment. ADR 0029 A9 §4 and ADR 0042 §8 say the same.
6. **One counter rule**, in every ADR: checked when non-zero, refused if it goes back (§3).

## Phase 1 build notes (2026-11-12)

Where the text left a choice, the build took these, and phase 2 to 4 inherit them. Each is the stricter reading.

1. **Where the code lives.** `SCOPE_RULES` is in `ozbox-cli` and `ozbox-core` cannot import it, so the rule table (with its
   `bootstrap` column) is in `ozbox_core::approval` and a service test checks that every `SCOPE_RULES` scope has an equal row.
   The scopes other branches add (`setup-code`, `kek-export`, `worker-keys`, `secret-use`) are in the table already.
2. **The encoding.** The domain tag is a length-prefixed field like the rest (version byte, then `lp(tag)`, `lp(box id)`,
   `lp(store id)`, `lp(scope)`, the scope's fields). Integers are 8 bytes big-endian inside a length-prefixed field, a flag
   is one byte, a list is its count as a field then its elements (sorted, a duplicate refused). The decision challenge is
   the same encoder under `ozbox-approval-decide-v1` over the **raw** 32-byte subject digest.
3. **Facts the rules read.** Production, any public mark and a policy's sensitivity are fields **in the digest** (`production`
   on an import, `sensitivity` on a policy change), so a spend that claims differently is refused. **Production is
   defined the way the box already does** (`workload::live_reason`, `box_secrets::ENVS`): an environment is non-Production
   only if it is `dev`, `development`, `staging`, `test` or `e2e` (a parity test keeps the list equal to the box's own);
   `production`, `prod`, `live` and every name nobody listed are Production, and so is an import with a key whose name says
   `PROD` or `LIVE`. `worker-keys` takes `dev`, `development` or `staging` only. "Replaces an existing
   value" is **derived by the service** at filing (a name it cannot look up counts as stored) and kept in the record, not
   in the digest. A guard match whose rule is `production-looking` is never decided by anyone here.
4. **Requests filed by whom.** The table's "filed by" column is enforced at filing. `host-guard` is filed only for a
   **loosening** (the digest carries `loosening`, and a tightening is refused as not needing one).
5. **Cooling-off.** An approved request's 15 minutes start at the end of the 24-hour wait, not at the decision; a pending
   enrolment can be cancelled by any approver, and by root, in the wait.
6. **Passkey evidence.** Until phase 5 the supervisor verifies the assertion. The service still checks that the evidence's
   challenge equals the one it builds for this request, digest, box and store, refuses a repeated assertion and a counter
   that goes back (a zero counter is accepted and never stored), and stores the evidence as sent.
7. **Wrong-answer limits.** There is no lockout on a decider's path (a signature cannot be guessed, and a counter keyed by a
   claimed key id would be a way to lock the laptop out). What is counted: a spend refused for a changed subject is counted
   **per request** and against the box user's uid (30 an hour, then "wait"), and the box socket's filings are bounded
   (8 pending a scope, 30 an hour a uid).
8. **Spent ledger.** `spending` is written to a ledger kept beside the journal in a file of its own (`approval-state.json`,
   with the epoch) before the effect. A journal copied back inside one epoch cannot revive a spent request; one copied back
   across an epoch is void. A request found `spending` after a crash stays `spending`: refused and shown.
9. **Reserved store names** the box user can neither read, write nor list: `approval-journal-key`, `approval-store-id`,
   `approval-envelope-key`, `approval-ever-key` (set when a laptop key is enrolled), `approval-ever-presence-key`,
   `approval-software-key-scopes`. Only root's admin socket sets the last two.
10. **`await` holds a connection thread.** The service already gives each connection a thread, so the 16 a uid and 4 a
    request caps are what keep that bounded; `resolve` and `exists` are shown to answer with every cap full.
11. **The failure counters are gone, not moved** (a phase 1 item). Wrong approval codes and wrong or unknown
    laptop signatures no longer count against anything: an 80-bit code, a 128-bit nonce and an Ed25519 signature cannot be
    guessed, and the old counters were global, so the box user could lock the owner out. The challenge pool is split: the
    sockets the box user can reach share 8 live challenges, every other socket has 16 of its own, so a box-user process
    that fills its pool does not stop the supervisor or root. **Not fixed**: a laptop that reaches the box through the
    box user's own import socket (every box without the ingress account) shares that pool with the box user. ADR 0029
    Amendment 9's ingress route is what removes it.
12. **Restores.** The journal is sealed under a key the store holds; the epoch and the spent ledger are in a separate
    state directory (`enable_requests` takes both). A restore of the journal alone, or a journal copied across stores, is
    void by epoch or set aside under a new epoch (kept as `*.void-<time>` for root), and a request caught mid-spend stays
    `spending`. **A rollback that brings back the journal and the state directory together is not detectable by anything
    local**; the audit chain's off-box head is the evidence, and nothing compares it yet. **Not built**: the callers that make
    a new epoch (`areq_new_epoch`) at a recovery, an adopt or a replace, and the carrying of the "has ever had a key" markers
    across a new store: the markers are in the store, so a replaced store starts without them until that flow
    copies them.
13. **Locks.** A request operation makes one read of the store's names (one acquisition of the store's lock) to learn the
    markers, and nothing else; it never writes the store (every key it needs is made when the journal is opened). The
    claim in the benchmark section holds as: nothing on `resolve`, `exec` or `env run` calls a request operation, and a
    request operation touches the store's lock once, only after a gate has refused. `handle_from` adds one substring scan
    of the request line for `"areq_` to every request, as it already does for `"audit_` and `"approval_`.
14. **The decision record.** A laptop key's `decider` is the key's own id from the service's record, never the caller's
    word (the spend check reads it). The signed envelope carries the exact JSON text it signed, and the signature is over
    `H("ozbox-approval-envelope-v1", text)` by the shared encoder, so it cannot be replayed as another message. The golden
    vectors are a committed file (`crates/ozbox-core/testdata/approval_subject_golden.json`) made by an independent script
    (`approval_subject_golden.py`) that shares no code with the crate; the laptop crate must produce every one.

## Phase 1 review fixes (2026-11-12, second pass)

The review of the three phase 1 commits (2026-11-12) found 3 High, 6 Medium and 11 Low. These are the decisions the fixes took; they supersede the numbered notes
above where they differ. Formats 1 to 14 are frozen from here, and the golden vectors were regenerated by the independent script.

15. **No software-key opt-in (owner decision B).** The `Soft::OptIn` cell is gone: `policy`, `box-secrets` and `worker-keys` are
    `never` for a software key, like every other owner-only scope. `Ctx.software_key_scopes` and the "turns on software keys"
    policy sensitivity are removed. The store name `approval-software-key-scopes` stays reserved and nothing reads it.
16. **Decision evidence is verified, never trusted (H3).** `ozbox_core::approval_verify` is the only way to read a laptop
    decision: `verify_laptop` checks the signature with the public half of the service's own key record and returns a
    `VerifiedLaptop` whose fields (user presence, user verification, counter) are parsed out of the signed bytes and private to
    the module. Formats: `ed25519` signs the decide message; `sk-ssh-ed25519` and `ecdsa-sk` sign `SHA-256("ssh:") || flags ||
    counter || SHA-256(message)` (the evidence's `authenticator_data` is `flags || counter`); `webauthn-p256` signs
    `authData || SHA-256(clientDataJSON)` and the challenge is read from the clientDataJSON. A signature over another
    request, outcome, box or store, a format that does not belong to the key type, and anything unverifiable is refused. The
    evidence has no `flag_up`, `flag_uv`, `counter` or `challenge` input fields any more; `Decision.proven` records what the
    verifier read, for display only. A passkey assertion's challenge, presence flag and counter are likewise read from its
    own `client_data` and `authenticator_data`; its signature is still checked by the supervisor (the service holds no
    credential key before phase 5), and the rp-id hash of a WebAuthn assertion is not checked here for the same reason.
17. **The decide challenge names the outcome (M5).** `decide_challenge(ids, request, digest, outcome)` adds the word `approve`,
    `deny` or `revoke` as a field. `areq_decide_challenge` takes `outcome` (default `approve`). The text a laptop key signs is
    `ozbox-approval-decide\n` and the hex of that challenge. Golden vectors cover each outcome and the message.
18. **The signed envelope (M4).** It carries `box_id`, `store_id` and `origin` inside the signed text, drops the unsigned copy
    of the body and the carried key, and `SignedEnvelope::verify(pinned_key, ids)` is the only reader: it checks the signature
    against the verifier's own pin, parses the signed text, requires the canonical form, requires the box and store, and
    recomputes the subject digest. The key to pin is returned beside the envelope (`envelope_key`) for pairing. A full
    envelope is a golden vector.
19. **The service derives a guard override's matches (H1).** A filing carries the unified diff the hook scanned as
    `scanned_text`; the service runs `guard::check_diff` with its own stored-value scanner and builds `matches` and
    `scanned_text_hash` itself. A wire `matches` or `scanned_text_hash` is refused. A stored value that the box's own rule
    (`workload::live_reason`) calls live, and a payment-provider key shape, is a `production-looking` match. A spend does the
    same from the text the hook sends, so a changed tree is a digest mismatch. Both draw on the scan budget. At most 512
    matches bind to one approval.
20. **A policy's sensitivity is the service's reading (H2).** `Derived.policy_sensitivity` is what the service computed with
    `policy_sensitivity(old, new)` over the guarded settings of the two parsed policies; the book refuses a `policy` filing
    whose label differs. Nothing in this release hands the service parsed policies, so `areq_file` refuses `policy` until the
    policy operation exists, and that operation must call `PolicyChange::derive`.
21. **Bootstrap (M1).** A `production-looking` match is refused at filing, whoever files and whether or not a factor exists.
    A request approved as `bootstrap` is void once a second factor is enrolled (checked at filing, decision and spend).
22. **The card (M3).** A list shows its most sensitive entries first in a fixed order (Production-looking, then stored
    values; keys marked public, then names that say production) and, past 20 rows (50 key names), a `Not shown` row says
    how many more the digest binds. Long values are cut in the middle. U+061C, U+2028/2029, U+2060-2064, U+00AD, the tag
    block and the other invisible characters are refused in a field and stripped from a card.
23. **Production (M6).** The list of live value prefixes is one (`LIVE_VALUE_PREFIXES`, used by `workload::live_reason` and the
    rules). A subject holds only a digest, so `Subject::check_import_values` is what refuses, where the service sees the
    values (an import's spend), an import whose values say Production while its subject does not. A worker-key name that says
    production counts as Production: never a software key, never the dashboard.
24. **Refused-answer lines (M2).** `Gates::audit_event_bounded` writes the first 10 lines of each kind of refusal in a minute
    and counts the rest into one `coalesced=N` line at the start of the next minute: no lockout, and the count lock is not
    held while the chain is written. It covers `secrets.signer.refused` and `secrets.approval.refused`.
25. **Smaller fixes.** `cancel` of an approved request is a revoke: only root, or an enrolment still in its cooling-off, may
    (L2). `enable_requests` exists only under `cfg(test)` (L3). `await` checks visibility before taking a slot, and the
    per-request cap is per socket class (L4). A failed journal write after an approve restores the book (L9). A damaged
    journal that cannot be set aside refuses to open (L10).
26. **Not done, and why.** G2: nothing calls `areq_new_epoch`. Recovery (`secrets_recover`) replaces the store file, so the next
    `RequestService::open` finds a journal sealed under a key the new store does not hold and sets it aside under a new
    epoch; adopt (`ozbox_core::adopt`) rebuilds OpenTofu state and replace (`restore_new`) creates a box from a snapshot, and
    neither has a step on the box that can reach the admin socket on this branch. The caller belongs to the phase that
    ships the decider, with a test per flow. G1 (carrying the K3 markers to a new store), G3 (an attestation verifier) and the
    Lows L5, L6, L7, L8, L11 are left: they need the decider (L5, L6, L7, L8), another socket or an upgrade step (G1, L11), and
    nothing reaches them in this release.

## Phase 2 build notes (2026-11-12)

What the build took where the text above was open, and what it did not build. Each is the stricter reading, and 27 to 40
carry on from the numbering above.

27. **Chat is notify-only, for every row (owner decision, 2026-11-12; the agent-action row too, after the phase 2 review).** The
    rule table's chat column is one word, `notify-only`, for every scope. The ordinary agent action's Approve and Deny buttons
    were removed (its message carries a link to the dashboard), and no Telegram, Slack or WhatsApp button or reply decides
    anything. The
    service refuses a decision whose surface is `telegram` for every outcome ("a chat app only notifies"). The message for
    a pending request (`serve::approval_requests::pending_request_alerts`) goes through the alert pipeline, which sends text
    and has no button, callback or reply markup: the scope in words, the fields the service derived, who asked as the
    service sent it, and a link to `/approvals?request=<id>`. The requester's `reason` is left out of it (it is the box's
    word). Each request is told once per dashboard run (a restart tells the still-pending ones again). A test pins that no
    chat or alert source names an operation that changes a request. `notify.detail = minimal` is not built.
28. **A dashboard session may deny and revoke, never approve.** `Factor::Session` is new and its record reads "dashboard
    session (no passkey)". A deny is fail safe, so it needs the sign-in and a role, not a passkey; its authority for a revoke is
    an owner's or a member's, as a passkey's is. An approval needs the passkey assertion, as before.
29. **The passkey's relying party (N6).** The supervisor checks the assertion against the person's own passkey with
    `webauthn::verify_assertion` (rp id hash, exact origin, challenge, UP and UV) and sends the service the rp id and origin it
    used; the service checks the assertion's rp id hash and origin against them (and refuses a cross-origin frame). Until
    phase 5 that is the supervisor's word, so it is defence in depth, not independence. A laptop `webauthn-p256` key carries the
    relying party it was made for in its own record, written at enrolment; a key with none decides nothing.
30. **One counter and seen-set rule (N5).** What is remembered is the request, the key or credential and the outcome, never the
    signature bytes: an ECDSA signature rewritten as `(r, n - s)` still verifies, so a set keyed by the bytes called it new.
31. **Deny and revoke are signed (N2).** Over the sealed route a laptop deny is signed over the `deny` word and a revoke over
    `revoke`; naming a key id decides nothing. A revoke challenge can be issued, only for an approved request, and an approve
    or deny signature does not revoke (and the reverse). A key whose revoke was signed without a touch has the authority of a
    key with no presence.
32. **The key is the service's own record, loaded by id (review "before phase 2").** `approval_keystore::load_key_view` reads
    `approval-key.<id>` and `approval-key.<id>.meta` (hex of a JSON record: type, presence, attestation digest, application,
    relying party, enrolled and active-from times). A key with no record is an Ed25519 software key (every key made before
    this). Presence is `meta.presence_proved` and is set only by the verifier. A test enrols a key in a real store and decides
    through the real dispatch; another feeds a key that is not there.
33. **Presence is proved by an attestation over the service's challenge (G3), and the challenge is not the one this text
    named.** The text bound the attestation to `H("ozbox-key-enrol-v1", box id, store id, request id, digest)`, where the digest
    is the `signer-enroll` subject's, which contains the attestation's own digest: it cannot be made before the attestation.
    The build issues a **service challenge** instead (`approval_key_enrol_challenge`: a random id, the challenge
    `key_enrol_challenge(ids, id, zero digest)`, ten minutes, one use, pooled apart for the box user's sockets). The key is made
    over it (`ssh-keygen -O challenge=`, or a WebAuthn `create()`), and the enrolment names the id. The verifier
    (`attestation.rs`) accepts `packed` with an `x5c` chain or `fido-u2f`, in a WebAuthn attestation object or an OpenSSH
    `ssh-sk-attest-v01` blob, refuses `none` and self attestation, checks validity, issuer names, signatures (ECDSA P-256 and
    P-384, RSA PKCS#1), that intermediates are CAs and the leaf is not, and that the chain reaches a pinned root; then the
    signature over `authData || clientDataHash` (or the U2F layout; a blob does not say which, so both are tried), the
    relying party or application, a touch, and that the attested key is the key being enrolled. A FIDO2 key enrolled with no
    attestation is a software key of that type; one whose attestation fails is refused, not quietly downgraded.
34. **The pinned anchors (changed by the phase 2 review).** Yubico's U2F Root CA Serial 457200631 and FIDO Root CA Serial
    450203556, and the three FIDO attestation intermediates (Yubico FIDO Attestation A 1, B 1, B2 1) from
    `developers.yubico.com/PKI/yubico-intermediate.pem`, with SHA-256 fingerprints in the test that pins them. **"Yubico
    Attestation Root 1" is not pinned**: it also signs the PIV, OpenPGP, secure-domain and HSM intermediates. **The file's
    OpenPGP signature was not checked**; the owner should verify the fingerprints before a release. A root added in
    `/etc/ozbox/fido-roots.pem` (a plain file only root can write) counts too. Intermediates a vendor publishes apart from
    `x5c` are not fetched, and the FIDO Metadata Service is not used (no offline update path is built).
35. **The markers (G1).** "Has ever had a laptop key" and "has ever had a presence key" are in `approval-state.json` beside
    the epoch and the spent ledger, in a folder of its own beside the store file (`approval-state`), so replacing the store file
    does not reset them; the store's own markers still count. Enrolment sets them (the pin at first boot, and the verifier
    for presence). Only root clears them (`areq_clear_markers`, admin socket). Carrying them when the folder itself is
    lost (a Hetzner re-create) is not built: a box in that state is in the 24-hour wait, as 3.1 says.
36. **An import by request (N10).** The import operation takes `request_id` and the laptop's `salt` instead of a code. The
    service recomputes the subject from the rows as they stand (project, environment, every name, classification, the digest
    of the value under the salt, the project's generation), calls `Subject::check_import_values` where it sees the values,
    spends inside the operation, applies, then finishes the request and bumps the generation. Phase 2 classifies every value
    as a secret (public marking is phase 3), and the service, not the filer, sets the generation at filing. Approval codes
    still work (legacy path).
37. **`signer-enroll` by request.** The enrolment operation takes `request_id`: it recomputes the subject from the key's fields
    and the attestation digest, and spends inside. The 15 minutes of an approved enrolment start at the end of its 24-hour wait
    (phase 1 note 5), so the key is enrolled when the wait is over; the key's `active_from_ms` field exists and is 0 on this
    path.
38. **The decider's route on the service.** `Policy::Unsealed` (a request the ingress socket opened) is the `Ingress` class for
    the request operations; the sealed operations are `areq_capabilities`, `areq_file`, `areq_get`, `areq_list`, `areq_await`,
    `areq_decide_challenge`, `areq_decide`, `areq_cancel` and `approval_key_enrol_challenge`. The service turns the request
    operations on at start (`enable_requests` is no longer test-only), with its journal in `approval-requests` beside the store.
    A journal that cannot be opened leaves them off and says so in the log.
39. **What the supervisor's list adds.** For the supervisor class the service adds to each request `can.approve` and `can.deny`
    for the viewer's role, from the same functions `decide` applies (`dashboard_can_approve`, `dashboard_can_deny`), so a card
    never offers what the service would refuse, and the markers beside the list.
40. **Vectors from real tools (N1).** `crates/ozbox-core/testdata/real_tool_vectors.json` holds 8 `sk-ssh-ed25519` and 8
    `ecdsa-sk` signatures made through a real `ssh-agent` (OpenSSH 10.6p2, built here, with its own `sk-dummy` software provider)
    for default, `verify-required`, `application=ssh:work` and `no-touch-required` keys, and 8 WebAuthn assertions (and the
    registration object, `packed`) from Chrome 157 through its virtual authenticator. They are software providers, not
    hardware, and the sk-dummy counter is constant. They found two things the in-code signer could not: the agent's blob carries
    the flags and the counter at the top level, after the signature string; and an `ecdsa-sk` signature is `mpint r, mpint s`,
    which `parse_agent_sk_signature` turns into the DER the verifier takes. `README` and the scripts beside the file say how
    they were made. The OpenSSH tarball's checksum was computed and not compared with a published one.

**Not built in phase 2.** `request_and_decide` (a laptop-started flow that files and decides in one signed message); signing
with a hardware key through `ssh-agent` on the laptop (the laptop command signs with a software key; hardware keys are enrolled
by root or the request flow and decide on the wire, but the laptop client for them is not written); the guard hook filing and
waiting for an override (phase 3: the waiting hook is `ozbox guard wait`, and nothing calls it from `git` yet); N3 (the scanned
text bound to the tree); N4 (flushing a closed refusal window from a timer); G2 (a caller of `areq_new_epoch` at a recovery, an
adopt or a replace) and the Lows L5 to L8 and L11. G2 and N4 are still "before release". Cross-box decisions, the service
verifying passkeys itself, and `notify.detail = minimal` are not built either.

**What must be proven on a real box.** A passkey approval on a real dashboard, over a real tunnel, with the rp id and origin the
box really serves; a real FIDO2 key enrolled with `ssh-keygen -O challenge=... -O write-attestation=...` and a real attestation
chain to a Yubico root (the blob layout is built from OpenSSH's description and covered by synthetic fixtures only), then
deciding with a touch, and a no-touch signature refused; the laptop's sealed `requests` commands against a box made with the
ingress account; the chat message with its link opened from a phone; a restore that brings back an old state folder; and the
waiting hook against a service restart.

## Phase 2 review fixes (2026-11-13)

What the review of the deciders (2026-11-13) changed. Findings H1, H2, M1 to M7 and
most Lows are fixed on the branch; what is left is under "Still open".

41. **Codes with request operations on (H1, section 10).** Changed by the owner, 2026-11-13: **codes stay on for everything until
    phase 3.** A service that has the request operations still makes and accepts scope-only codes, unless root's flag file
    `/etc/ozbox/approvals-legacy-codes-off` is present (`approvals.legacy_codes_off`; on when the file is absent, so on for every
    box). With the file present it covers `approve_mint`, the laptop's challenge route and every gate. **A code bound to a request
    is not built**, so the open weakness is the unbound code; phase 3 turns codes off everywhere and removes the switch. The
    dashboard's socket enrols a key only by an approved `signer-enroll` request; the dashboard cannot mint a `signer-enroll` code either; a code enrolment on the ingress route on a box that has had
    a key waits 24 hours (`active_from_ms`). The dashboard's key revoke is an operation of its own
    (`dashboard_stepup`, set by the supervisor after an owner's fresh passkey) and makes no code; a revoke by request is
    `signer-enroll` with action `revoke`.
42. **The attestation trust (H2).** The anchors are as in 34. A `packed` leaf must be X.509 version 3, have the subject OU
    `Authenticator Attestation`, say `CA:FALSE`, and carry the AAGUID extension (not critical) equal to the authenticator data's;
    CAs must hold their path length and, if they say, certificate signing; the inner and outer signature algorithms must agree.
    A `fido-u2f` leaf is held to "not a CA" and, since the phase 2 re-check, to the layout's own shape (47). A PIV-shaped chain is a test that must be refused. **Presence authority is off
    unless root's `/etc/ozbox/approvals-presence-keys` file is present**: an attestation that verifies is recorded, and the key is
    still a software key, until a real key has been proved on a box.
43. **The attestation is verified at filing (M3).** A `signer-enroll` request carries the attestation, the service verifies it
    over its challenge when the request is filed and keeps the verdict (`approval-key.pending.<digest>`, at most 8, a week), and
    the enrolment finds it by digest. The enrolment completes after the challenge's ten minutes or a restart.
44. **Markers, generation, epoch (M2, M4, G2).** `ever_key` and `ever_presence_key` are seeded from the store's own records when the
    state file opens. An import's generation is derived from the stored rows (a digest of the names and value digests, 48 bits),
    so every writer moves it. A state folder opened beside a store with another id starts a new epoch. **A rollback of the whole
    volume (store and state together) is not detected.**
45. **The laptop recomputes the decision challenge (M5)** from the box and store ids it pinned in its pin entry the first time it
    saw the box, the request id, the full digest and the outcome, and refuses a box whose answer differs.
46. **Smaller fixes.** The chat message is marked told only when the hourly limit admitted it, and filer text loses chat markup
    (L2, L3); the enrolment writes the key's record before its public half (L4); an owner-only passkey approval needs user
    verification (L5); the dashboard's "needs a newer box" matches the older service's exact sentences (L7); `ozbox guard wait`
    backs off through a restart and a second Ctrl-C ends it (L1); the refused-spend budget is per uid and request (phase 1 L5);
    an admin decision records the peer uid (phase 1 L7); a closed refusal window's count is flushed by any later call (N4).
    Enrolment challenges have a pool per socket class (M1).

**Still open.** (N3 is closed by phase 3, items 55 and 56.) Phase 1 L6 (`worker-keys` cannot be filed until phase 4) and
L8 (a dashboard enrolment must be spent within 15 minutes of its wait ending; the service does not enrol it itself); phase 2 L6 (an
import filed with `production: true` for another environment cannot be spent) and L8 and L9 (the decide challenge is deterministic,
and its single use and expiry are the request's, not its own; a dashboard session's revoke has a passkey's authority); the
per-class window key of N4 and the size of `workload-audit.log`; a request message budget of its own. Nothing here has been run
against a real box.

## Phase 2 re-check fixes (2026-11-13)

What the re-check of the fixes above (two Medium and nine Low findings) changed.

47. **A key in its 24-hour wait is refused everywhere (NM1, NL3).** `approval_challenge` and `approval_redeem` refuse a key whose
    `active_from_ms` is ahead, with the sentence the decide path uses; redeem reads it again after the challenge is taken. The
    `fido-u2f` layout must carry exactly one certificate with a P-256 key, and a certificate from Yubico's PIV attestation arc
    (1.3.6.1.4.1.41482.3) is refused in that layout. The Yubico U2F root is still pinned. A PIV-shaped chain in the `fido-u2f`
    layout is a test that must be refused. Presence keys stay off by default; this is what had to hold before turning them on.
48. **The refused-spend budget cannot be grown with ids the caller makes up (NM2).** A request id that is not a service id (26
    base32 characters) is refused as not found before any lock, counter or journal write, on every op that names one. The list of
    refused spends adds at most 120 entries per uid and 1024 in all (these bound the list and never refuse a spend); the only refusal is 30 per (uid, request); a refusal that changed nothing does
    not rewrite the journal; the audit line carries the id cut to 26 characters.
49. **Smaller fixes.** NL1: if the request journal does not open, the dashboard still cannot make or use an enrolment code and a
    code enrolment still waits 24 hours (read from the store); the service logs it. NL2: a presence key counts as one only while
    root's presence file exists, checked when a key decides and when keys are listed (the "has ever had a presence key" marker is
    not undone, which is the stricter side). NL4: a verified attestation is kept only after the book admits the filing, is
    deleted when its request is denied, cancelled, expired or superseded, and each class of socket has its own cap of 8. NL5:
    `ozbox guard wait` backs off only when the service did not answer. NL6: filer text in a chat message loses `://` and `www.`
    forms as well as markup (a bare domain can still be linked by an app; the message's one real link is the dashboard's). NL7: a
    test drives `approve_mint` for `signer-enroll` through the real handler with codes on, codes off and a journal that failed
    to open. NL8: the Secret approvals page no longer offers a `signer-enroll` code and says what to do. NL9: a root setting
    file with the wrong owner or mode is logged at start with a warning, the effective settings are logged, and the box's
    self-test (`approval_settings_trusted`) fails until the file is fixed; both files are read only at start, so the service
    must restart to take a change.

**Recovery when a box's only laptop key is lost.** The dashboard cannot enrol a key (no code, and nothing files a request yet),
and a code enrolment needs a key. Root on the box can enrol one through the service's root socket; **there is no command for
that in this release**, so it is a manual step and a gap to close in phase 3 (an `ozbox approval-key enroll --request`, or a
root command). Revoking a lost key from the dashboard still works.

**Left open by the re-check.** Bare domains in chat text (NL6); the root-socket enrolment command above (NL8); the rollback of
the whole volume (44); the interaction of NL2 with the "ever had a presence key" marker.

**Left open by round 4.** The `fido-u2f` one-certificate rule accepts a leaf signed directly by any pinned anchor, including the
FIDO intermediates, not only the U2F root. The PIV-arc refusal and the P-256 rule are proven on synthetic fixtures only: the
`fido-u2f` leaf rules must be proven on a real key (a real Yubico U2F or FIDO attestation certificate must not carry an extension
under 1.3.6.1.4.1.41482.3) before presence keys are turned on. A request whose attestation verdict cannot be kept is cancelled
only when this filing made it; a filing that joined a request that was already live leaves that request as it was (RL3, fixed:
`cancel_if_new`, tested on the helper, not through a failing store).

50. **Amendment, 2026-11-13: chat apps are notify-only (owner decision).** §3.1 and §5 gave a chat app a Deny button, and the
    first text of the agent-action row gave it Approve and Deny. Build note 27 already removed every button from the code; this note
    removes the same words from the design so the text and the code agree. **A chat app (Telegram, Slack, WhatsApp) sends a message and a
    link to the dashboard. It has no Approve, no Deny, no Stop and no `/budget`** (raising a cap is money, like an approval; owner, 2026-11-14): nothing said or pressed there decides a request, and it does not
    cancel a run. The server refuses the act, so it is not only a missing button: a message of `/stop` or `/budget` from a chat app is answered with
    a link to the dashboard and changes nothing, whoever sends it. `/pause`, `/resume`, `/new` and plain text keep working. Approving, denying and stopping stay with the dashboard (a passkey)
    and the laptop. **Not decided here:** the owner has said that Telegram may later also start, stop and resume boxes, chat with
    sessions and run commands. That is a separate decision with its own ADR (G3), and nothing in this ADR promises it or constrains its design; if it
    comes, approvals stay notify-only.

    **How "is this terminal asking?" is decided (2026-11-14).** A chat app types a line only into a
    terminal that has *positively* said it is waiting at its prompt, and the answer is kept **per terminal, never per folder**. The
    agent's hook runs as a child of the agent, so it carries the tmux pane (`TMUX_PANE`); the daemon keeps one state per pane, and
    another agent in the same repository (or a parent or child folder) finishing says nothing about this one's open question. Fail
    closed: only `Stop` / `AfterAgent` and Claude Code's `idle_prompt` notice mean "waiting". A permission notice, an MCP question
    (`elicitation_dialog`), a notice type this code has never heard of, and a notice with no type are all "asking"; a helper agent's
    `SubagentStop` is "busy". An idle notice does not lift an open question; only the agent's next real step (a prompt, a tool call,
    `Stop`) does. "Waiting" counts only after a per-turn hook (`UserPromptSubmit`, `BeforeAgent`) has fired in that terminal, which
    is the proof the "finished" will be followed by "busy" again: Gemini's hooks gain `BeforeAgent`, and a Gemini whose hooks predate
    it is never typed into from a chat app (it shows "unknown"). The `hooks` level is a fact heard from that terminal, not the
    program's name: an agent whose hooks were never installed, or never fired, is `terminal` and is not typed into. Unproven: whether
    Claude Code can send `idle_prompt` while a dialog is open (it is treated as unable to lift a question, so it is safe either way).

**Benchmark.** No measured path is touched (`resolve`, `exec`, box create, resume, snapshot and destroy are unchanged; the request
operations are a separate branch). Two small costs are **not measured**: the service now opens the request journal and reads the
store's names once at start (a few milliseconds, on first boot and resume), and the dashboard's alert tick asks `areq_list` at
every evaluation (one read of the store's names, which can wait a moment behind `resolve`'s lock during `env run`). The fixes add
reads on the request paths only (an import's generation reads the project's values when the request is filed and spent; an
attestation is verified once at filing). None is on the clean path of a commit, and none is expected to move a headline metric.

## Phase 3 built (2026-11-13): the guard hook, on `feat/approval-phase3-guard`

A held commit or push now files a `guard-override` request, waits, and is let through only by an approval spent for the change
the hook reads again at that moment. Public values, `file:line`, a code bound to its change, and large pushes are in with it. Not
run against a real box: see the last paragraph.

53. **Public values.** The barrier no longer looks for a stored value that is public in fact: one carrying the person's public mark,
    or one stored under a name of a known public kind (`NEXT_PUBLIC_`, `VITE_`, `EXPO_PUBLIC_`, `NUXT_PUBLIC_`,
    `REACT_APP_`, `GATSBY_`, the one list `workload_policy::PUBLIC_NAME_PREFIXES`, beside the public-value rules of Amendment 12).
    A name never makes a key public: the value still passes `public_mark_refusal` (a key-shaped value, a service-role key, a
    Production-looking value or a name that says it is secret stays a secret), and a held-back scan is the service's, so the hook
    cannot widen it. In the files themselves, a public variable set to an **anonymous client JWT** is configuration and does not trip
    the signed-token rule; any other role, any other name, and every other key shape still do. Naming a variable is never a hold.
    The floor of 12 characters from section 9 is built (item 63). The bare `PUBLIC_` prefix is not in that list (item 64).
54. **`file:line`, and no name.** A hold prints the file, the line, and the rule (`stored value` is "holds a value this box stores as
    a secret"). It never prints the stored secret's name (the owner's card has it). A stored-value hit is narrowed to its line by
    halving, so a hold on a large change costs a few extra calls and a clean change costs none.
55. **A code is for one change .** `override` now needs the repository (16 hex) and the change (16 hex), and a
    scope-only code is refused there. The change is a hash of the staged **tree id** (a push: the remote's address and every
    `ref old new`) and of the held lines. The hold prints the exact `ozbox secrets approve --scope guard-override --project ... --env ...`
    to mint. **A code made for tree A does not pass tree B**, and is not spent by the attempt. `post-commit` no longer lets any commit
    stand because `OZBOX_GUARD_APPROVAL` is set: `pre-commit` leaves a marker naming the tree it let through, and `post-commit` lets
    only that tree stand. Codes stay on for this scope (owner, 2026-11-13); section 10's switch for the other scopes is unchanged.
56. **The text is read from the tree it is about to accept (N3).** The staged diff is read with `git diff-tree` on the tree id from
    `git write-tree`, not from the index. After an approval the hook reads the tree again, refuses if it is another tree, rebuilds
    the held text from it and spends the approval **with that text**, so the service's digest (tree, matches, text hash) must
    equal what was approved. A push is read again the same way from its commits. This binds honest tooling and accidents, as
    section 4 says; a hostile box user who skips the hook is still stopped only by ADR 0023's other layers.
57. **Large pushes, and what is read.** Every hook reads a change with one command and one flag set (items 59 to 61), so what
    `pre-commit` read is what `post-commit` and `pre-push` read. A push is read commit by commit (no shared 32 MiB cut that used to
    drop the rest without a word) over the commits the **target remote** does not have (item 62), and the stored-value scan goes in
    batches of about 900 KB of what JSON writes (item 66), across files and commits, so 250 commits are a handful of calls. A line
    longer than a call is scanned in overlapping windows. A service that says "too many scans" is waited for, in the open (15 s, up
    to about ten minutes), never skipped, and so are the filing and the spend of a request (item 67). More than 5000 commits that
    the remote does not have, or 768 MiB of change (item 72), is refused with the way through: push an earlier commit first
    (`git push <remote> <commit>:<branch>`), or fetch the remote first so what it has is not read again. What a hook could not read
    (git's output, a file, a commit) is a hold that names the commit, never a pass. The limits that remain are the last item of
    this section; they are the stated limits, not silent ones.
58. **The request.** The held lines (not the whole change) go to the service as `scanned_text`; it scans them, derives the matches
    and binds the hash (decision 19). More held than one request can carry (about 40 KiB, measured against the box socket's 56 KiB; item 66) says so and offers the code route. With no box
    socket (a laptop), or a service without request operations, the hold is the code route. The wait is the 31 minutes of section 6;
    Ctrl-C leaves the request. There is no "no wait" switch, and a second attempt files a new request.

**Decisions where this ADR was open.** (a) The task kept codes working, so phase 3 does **not** turn the code switch off for the
other scopes; only the guard override's code is now bound, and unbound ones are refused. (b) The held excerpt, not the full diff, is
what a request binds: a push's full text can be hundreds of megabytes and the service binds one megabyte; the full change is read and
checked by the hook, and a different change gives a different tree or `ref old new` and so a different digest. (c) A request filed for
a change whose excerpt the service scans clean (a rule only the hook applied) shows the person no matches. (d) `areq_finish` is called
as soon as the hook has decided to let the change through.

**Not proven on a real box.** The hook over the real box socket with git invoked by an agent; a dashboard passkey decision while a
commit waits; a 200-commit push over the real scan budget (120 a minute); a service restart during the wait; the laptop's code mint
with `--project` and `--env`.

## Phase 3 review fixes (2026-11-13): reading what git says, the target remote, and what a push can point at

An independent review of the phase 3 branch (fix first) found eight gaps that let a key past all three hooks without skipping one, most
of them already on the branch it was built on. The owner's decisions D1 to D4 are applied (delegated, confirmed by a second
opinion). Not run on a real box: see the end.

59. **One reader, by counting (G1).** A hunk header says how many lines the hunk holds, and exactly that many lines are content,
    whatever they start with. The old reader took an added line `++ /dev/null` for a file header and skipped every line after it.
    Now only between hunks does a line's start say what it is (`diff --git`, `---`, `+++`, `index`, a mode line); a line that is
    neither inside a hunk nor one of those is an error, and an error holds the change. The combined form of a merge (`@@@`, one prefix
    column per parent) is read the same way. What the held lines are re-read from (`held_text`) now carries real hunk counts, and a
    test reads it back as exactly the held lines.
60. **One command, one flag set (G2, G3).** `git diff-tree -p -r --root --cc --no-commit-id -U0 --no-color --no-ext-diff
    --no-textconv --text --no-renames --diff-filter=d`, for the staged tree against `HEAD` and for a commit alike. `--text` reads a
    file with a NUL byte, or one a `.gitattributes` line marks `-diff`, as the text it is; `--no-renames` shows a renamed and edited
    file whole; `--diff-filter=d` keeps everything but deletions, so a symlink turned into a file (a type change) is read. A merge
    is read from the combined diff, which is what the person who merged wrote: a conflict resolution that adds a line is read, a
    clean merge adds none and the commits it brings are read as commits. git prints a binary file of a merge without its bytes
    even with `--text`; such a file is read whole from the commit. The file names git prints are read too (item 61).
61. **Messages, tags, names (G6, V2, V10).** A commit's message, a commit's headers other than `tree` and `parent` (author,
    committer, a signature, and the `mergetag` header that `git merge <signed tag>` writes, which holds the whole tag), an annotated
    tag's message and the name of every file a change adds are read like added lines, under `<commit message>`, `<commit header>`,
    `<tag>` and `<file name>`. A name git quotes (a non-ASCII character, a tab) is unquoted from the `diff --git` line like any
    other, so the name of an empty file is read whatever it is. A message with a key takes a commit back at
    `post-commit` even when its tree was approved (the approval covered the tree). An empty file named `.env` is held by its name.
    The name of a branch or tag (a ref name) is not read.
62. **What a push has (D3(a), G4).** Pre-push excludes only the target remote's remote-tracking refs and the old shas git sends. A
    push is mapped to a configured remote only when the address git hands the hook (after every `insteadOf` and `pushInsteadOf`) is
    both one of that remote's push addresses (`git remote get-url --push --all`) and one it fetches from (`git remote get-url
    --all`), because the tracking refs record what the *fetch* address has: a `pushurl` that differs, or a `pushInsteadOf`, sends
    somewhere they say nothing about, and then nothing is excluded. A push to an address that matches no remote
    excludes nothing. `--remotes=origin` is the glob `refs/remotes/origin/*`, so a remote named `origin/fork` is excluded from it
    by name. An old sha that this repository does not have is not a failure (`git cat-file -e`): it only reads more. One
    `git update-ref refs/remotes/other/x <tip>`, or a fetch from another remote, no longer empties the scan. Tracking refs of the
    target remote remain forgeable by a hostile box user, which is the stated limit of the hooks (section 4).
63. **The floor (section 9).** A stored value of fewer than 12 characters is not looked for in a commit: a region, a port or a
    boolean held every file that said it (`AWS_REGION` alone held 77). It is still stored and still redacted from output. The
    floor is in the barrier's scan only, not in the redaction.
64. **Public by name, and addresses (D2(a) in part).** The bare `PUBLIC_` prefix is not a public name (SvelteKit and
    Astro projects mark their values at import). The query clause that
    commit 70fd5e1 added (an address under a public name with a query passes the barrier) is **removed again** (
    decision E1): its list of credential words was beaten by an encoded name (`?%74oken=`) and a comma-joined one (`?a=1,token=`),
    and no deny-list of secret-bearing addresses existed to stand behind it. An address with a query or a fragment is held as a
    stored value like any other (section 9 says what the person does). One address check now stands in front of both ways a value
    becomes public: no user info, and not a chat webhook or an Apps Script link. A value under a non-public name never passes by
    its shape. The `PROD`/`LIVE` whole-word rule of G11 is the next change.
65. **A ref can point at anything (G5).** A pushed ref that points at a blob, a tree or a tag of either is read: a tag is read and
    peeled (at most 8 deep), a blob is read whole, and a tree is read file by file with its names. An object that is none of those
    is an error.
66. **Sizes are what the service receives (G8).** A request is one line of JSON, and JSON writes a quote or a newline as two bytes
    and a control byte (a NUL in a file read with `--text`) as six. A batch is sized by its escaped length and never takes a line
    past 900 KiB: two lines of 600 KB are two calls. A line longer than a call is scanned in windows of that size. The service's
    request line is measured as it is sent, and a request it would refuse is an error that says so. What a request carries to the
    person is bounded by an estimate of 40 KiB and measured against 56 KiB, because the box socket the hook files on reads a line of
    at most 64 KiB (the held text used to be allowed 900 KB, which that socket would have refused). More than that is held without a
    request: the code route, or a smaller change.
67. **A busy minute does not waste an approval (G9, the cheap part).** Filing and spending a request take a scan slot, and a big
    push has just used the minute's slots up reading itself again. Both are now waited for the way a scan is (15 s, up to about
    ten minutes, Ctrl-C ends it), and a spend that fails says what the service said, not that the approval "does not match this
    change". Not built: not charging the budget for a spend bound to an approved request (G9's second part, G20); the re-read against an
    approved request's life is item 72.
68. **A guard code needs a second factor (D1(a), G12).** See section 9: with no second factor enrolled, a code and a request for a
    guard override are refused, and the hold says how to enrol. Confirm that `main`'s box is enrolled before this lands there.
69. **The marker (G13).** It is written as `tree head time`. `post-commit` honours it only for the same tree, made on the commit
    the marker saw as `HEAD` (or, for an amend, the commit the amend replaced), within an hour (a person writing a long message
    must not lose an approved commit: the binding does the real work and the age only stops a stale marker). Every `pre-commit`
    deletes any marker before it decides anything, so an aborted commit leaves none.
70. **Sockets and a missing service (G14).** On a box (where the image's own release record, `/etc/ozbox/image-release`, exists; not where the binary is, which Homebrew
    and `install.sh --prefix /usr/local` share with a laptop) the hooks use the box's own socket
    paths and ignore `OZBOX_IMPORT_SOCKET` and `OZBOX_SECRET_SOCKET`, so a process of the box user cannot point them at a service of
    its own that answers "clean". A missing import socket on a box is said out loud and holds the change; a laptop with none checks
    the shapes only, as before. `post-commit` no longer swallows an error: it says what it could not read and the push reads again. With the service down on
    a box, `post-commit` still checks the shapes of keys, the names of files and `.env` files (and takes a commit back for them),
    and says that stored keys were not checked.
71. **Submodules (G7).** `ozbox guard install` finds a repository whose `.git` is a file that points at its git folder (a submodule,
    a linked worktree) and installs the hooks in the folder git says is its own. No system-wide `core.hooksPath` is set (it would
    put the hook on every fresh clone, which costs a measured benchmark path, and would stop a repository's own hooks from running
    unless the wrapper chained them). A clone made after the install is reached the next time `ozbox guard install` runs.

72. **The second pass (2026-11-13).** One short round on the verification of the above, with real git in
    tests for each.
    - **V1, V5** as item 62. **V2, V10** as item 61. **V3, V9** as item 64: user info refused on the name route too, the query
      clause deferred (decision E1), and so nothing matches a parameter name any more.
    - **V4.** Every git command the hooks run sets `GIT_NO_REPLACE_OBJECTS=1` and clears `GIT_GRAFT_FILE`: `cat-file`, `rev-list`
      and `diff-tree` follow `refs/replace/*` and `pack-objects` does not, so `git replace <key commit> <clean commit>` used to make
      the push read one object and send another.
    - **V6, V7** as item 70. **V8.** The word-boundary rule treats `\uXXXX` and `\xXX` (JSON and JavaScript escapes) like `%XX`,
      so a key behind an escaped `=` is found; `task_AKIA...` is a key (an underscore is not a letter), and `taskAKIA...` is a word.
    - **V11.** A held push is read again after its approval, and an approved request lives 15 minutes. A re-read costs one scan a
      batch of about 900 KiB at about 120 a minute, so the old 2 GiB cap (about 2,300 batches, about 20 minutes) could never be
      spent. The cap is now **768 MiB** (about 870 batches, under 8 minutes), and a test ties it to the approval's life. A process
      of the box user that keeps the shared scan budget empty still stretches every wait, to hours for a big push; it never skips,
      and it fails closed.
    - **V12.** This section and the limits below were corrected to what is built.

**Known limits, stated.** These are what the guard does not do, said in one place so none of them is a surprise:

- **UTF-16.** A file stored as UTF-16 is read as the bytes it is; a literal scan does not find its text.
- **Git LFS.** A path tracked by LFS commits a pointer, and the object is uploaded by LFS's own hook afterwards. The object is not read.
- **A hostile box user.** `git commit --no-verify`, `git push --no-verify`, `git -c core.hooksPath=/dev/null`, `commit-tree` and
  `update-ref`, editing `.git/hooks`, and writing the marker skip the hooks (section 4). `post-commit` catches `--no-verify` on a
  commit; nothing checks a push after the fact. The real stops are the egress allow-list and GitHub's push protection.
- **Clean merges.** `git merge` that makes the commit itself runs `pre-merge-commit`, not `pre-commit` or `post-commit`, so a clean
  merge meets the guard at `pre-push` only (it adds nothing of its own; the commits it brings are read there). A merge concluded with
  `git commit` after a conflict meets all three.
- **Split or built keys.** A key written across two lines, or built by concatenation, beats any literal scan.
- **Ref names.** The name of a branch or tag is not read.
- **Compressed or archived files.** A zip, a gz, an office document or any other container is read as the bytes it is; a literal
  scan does not find a key inside it.
- **Repositories the install does not find.** `ozbox guard install` looks to 4 levels under `/work` and skips folders whose name
  starts with `.` and `node_modules`; a repository deeper or inside such a folder never gets hooks.
- **A new clone is unguarded for up to 5 minutes**: the hooks arrive with the install timer's next run, or by `ozbox guard install`.
- **Replace refs** (`git replace`) were a way to make `pre-push` read one object and send another; fixed by item 72 (V4). The same
  goes for a remote whose `pushurl` differs from its `url` (V1, item 62).
- **The scan budget.** A process of the box user can keep the shared budget near empty, so every wait of a big push is stretched
  (item 72, V11). It never skips and it fails closed.
- **Query addresses (decision E1).** A public address that needs a query is held like a secret (section 9).
- **G11, deferred.** The `PROD`/`LIVE` rule still matches inside a name (`NEXT_PUBLIC_PRODUCT_URL`), and a short value under a
  non-public name is skipped only by the floor.
- **G17.** The `scan` operation on the import socket returns the names of the stored secrets it matched to any process of the box
  user, and at 120 scans a minute it is a guessing oracle for a short value. The floor narrows it; returning a count and rating by
  bytes are the next change.
- **G15** (the smaller issues of the review: a public-variable line that carries two tokens, an unverified `anon` role claim, the
  missing audit event for a bypass) are not fixed here.

**Not proven on a real box (second pass).** The repeats of V1 (a `pushurl` push, and `pushInsteadOf`), V2 (an empty file whose name git
quotes), V4 (a `git replace` push) and V6 (a `--no-verify` commit with the service stopped) on a box; that `/etc/ozbox/image-release` is
present on every shipped image; a held push near 768 MiB against the real budget and an approved request's 15 minutes.

**Not proven on a real box.** Everything above is proven in tests that run real git in temporary repositories (the `++ /dev/null`
line, a NUL-byte file, a `-diff` file, a symlink turned into a file, a rename with an edit through post-commit and pre-push, a
conflict-resolution merge, a clean merge, a forged tracking ref, a push by address, a missing old sha, a real `git push` of a blob,
a tree and a tag of a blob to a bare remote, a submodule) and in tests of the service's scan and rules. Not run: Linux CI; the hooks
over the real box socket with git invoked by an agent; the 64 KiB line limit of the box socket against a real held request; a
passkey decision while a commit waits; a restart of the service during the wait; a push of about 250 commits over the real
120-a-minute budget followed by one that needs a re-read (G9); the same commit that was held on the owner's project box (the
rule printed and the card's key name settle which case it was); a hold on a box with no second factor enrolled (D1); and the
repeat of each reproduced bypass on a box: `++ /dev/null`, `-diff` and NUL files, a rename with an edit, a symlink turned into a
file, a forged tracking ref, a second remote, a ref to a blob, a key in a message, a submodule, two lines of 600 KB. The benchmark's
Git common operations on a 4 vCPU / 8 GiB / 40 GB box, with the hooks installed and absent, before and after, has not been measured.

## Settings loosening notes (2026-11-14)

- **An approval expiry raised past 8 hours IS a loosening (owner decision D16, 2026-11-15).** A longer expiry does not make fewer
  actions ask, but it keeps a stale request, filed before the context changed, approvable (or approvable from a stolen session)
  for longer. So raising the expiry above 8 hours, the default, and above what is stored, needs the fresh second factor like any
  other loosening, on the server (`ApprovalPolicy::loosens`, `LOOSENING_EXPIRY_S`) and mirrored in the dashboard's
  `policyLoosens`. Any expiry up to 8 hours, any lowering, and an unchanged long expiry are not a loosening. The comparison is
  against the stored value. The same line applies to any later delegation or approval window an ADR adds.
- **The step-up for a loosening is a time window on the session (ADR 0039), not a challenge bound to the act.** One passkey
  shown within the window authorizes every loosening and every other step-up act in it. The "one assertion decides one
  request" rule above applies to approval requests, not to settings.
- **The three monthly limits move together.** The fleet and per-person limits (`spend-caps`) and a model provider's own
  `monthly_cap_usd` (saved through settings) are one kind of change: raising or removing any of them, or dropping a capped
  provider, needs the fresh second factor, and is refused outright on a box with no sign-in. The comparison is made on the
  stored value (inside the store's lock for the policy and the limits).
- A loosening refused for lack of a fresh second factor writes a `permission.deny` event to the audit chain, like a role
  refusal. Its detail names the act and the reason, never a value.
