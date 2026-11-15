# 0028 — The audit chain has a writer of its own, the secrets service is audited, cloud-account models go through the broker, and a laptop key can approve

**Decision.** Four things ADRs 0017, 0018, 0022 and 0023 listed as "not covered" are closed, and a fifth thing (the box's own
secrets on a provider with no instance tags) is added.

1. **The audit chain is written by the secrets service, not by the box user.** The chain used to be a file the dashboard's or
   command line's own process wrote, with its seal key in a file beside it, so anything running as the box user (every agent)
   could rewrite the whole chain and seal it again (ADR 0022). Now the chain file belongs to `ozbox-secrets` in a folder of its
   own (`/work/ozbox-audit`, on the persistent disk so an upgrade keeps it; mode 0755, files 0644), and the seal key is a secret in the store (`audit-seal-key.<chain>`),
   never a file and never returned over any socket. A writer sends **events** over a socket it can already reach and gets the
   sealed entries back (`audit_append`, `audit_last_src`, `audit_verify`, `audit_seal`); the file format does not change.
   The second copy of every checkpoint (the anchor) is in a folder only the service opens, so cutting the tail off the chain is
   still caught against something the box user cannot see.

   | op | box socket | supervisor socket | admin socket |
   |---|---|---|---|
   | append, last source | yes, but not the service's own words (`secrets.*`, `audit.*`) | yes | yes |
   | verify (seals checked) | yes | yes | yes |
   | seal now | no | yes | yes |

   The client is found, not configured: `ozbox_core::audit::AuditLog::beside` uses the supervisor's socket, then the box
   socket, when one exists, and a computer that is not a box (a laptop, a test) keeps writing its own file as before. **Failing
   closed is the design**: if the socket exists and the service does not answer, an append fails, and the task store refuses
   to save a change it cannot record (ADR 0022, item 7). *(Amendment 1: on a box this holds when no socket exists too.)* A restart of the secrets service therefore pauses saves for a moment.
   Requests are cut into pieces of forty events, so a backlog after an outage never exceeds the box socket's size limit, and
   the `src` rule makes a retry idempotent.

   **Upgrading a live box.** The dashboard (the supervisor) names the old chain it wrote as files beside its store, with every
   request it makes to the service. The service reads the old files itself (it holds the file capabilities it needs for
   restic and the store), and if the box has no chain of its own yet it **continues** the old one: the lines are copied
   unchanged, the old seal key becomes `audit-seal-key.tasks` in the store (so every old checkpoint still verifies), an
   `audit.migrated` entry records the old head, and the old files are overwritten and removed. *(Amendment 1: the old chain is
   now always kept apart under its old key, and the box's chain gets a new one.)* If something already wrote a new
   chain first (the tool host, through the box socket, can), the old one is kept whole beside it as `tasks-legacy` and checked on
   its own (`verify` reports both and is only `ok` when both are); the new chain's first line names where the old one ended.
   Both paths are idempotent and finish after a crash (a marker in the store holds the old head). Only the supervisor's socket
   may name an old chain, and only lines that parse as chain lines are ever copied, so the call cannot be used to read another
   file.

   **What this still does not give.** A process of the box user can **add** a well-formed event of its own (the tool host and
   the command line share its user and write through the same socket) but cannot alter or remove one that is there, cannot
   forge a seal, and cannot write an event in the service's own vocabulary. Checkpoints written before the boundary were sealed
   under a key the box user could have read; the `audit.migrated` entry's head hash is what to pin. A root user, or anyone who
   can read the store's key-encryption key, is outside this threat model.

2. **The secrets service and the broker are audited.** Every one of these writes a line into the same chain, with names, scopes
   and counts and never a value, a token or a code: a run token issued, refused or revoked (`secrets.token.*`, with the run and
   the provider), a workload secret resolved for a command (`secrets.resolve`, project and environment; a command with no
   reference writes nothing), an approval minted, spent, refused or allowed by `bootstrap` (`secrets.approval.*`), an import, a
   declaration and a guard override (`secrets.import`, `secrets.policy.write`, `secrets.guard.override`), the box's own secrets
   loaded (`secrets.box.loaded`), a secret written or removed on a socket (`secrets.set`, `secrets.delete`), a second factor
   enrolled, and the laptop-key events below. The plain `workload-audit.log` is still written (the dashboard's "recent uses"
   reads it). A line is best effort in the service (the change it describes has happened); the task store's records are not.

3. **Bedrock, Azure OpenAI and Vertex go through the broker** (ADR 0017 item 4 no longer says they cannot). The secret
   `model-key-<id>` is either a plain token (a Bedrock API key, an Azure `api-key`, a Vertex `x-goog-api-key`, sent in its one
   header as before) or a JSON credential that the broker turns into a signed request or a short-lived token **inside the
   service**: an AWS key pair becomes a Signature Version 4 header computed for that one request (the path is encoded twice, as
   AWS requires, and `host`, `x-amz-date` and the session token are signed); an Azure client becomes a bearer token from a
   client-credentials exchange; a Google service-account key signs an RS256 JWT that is exchanged at Google's token endpoint
   (the key file's own `token_uri` is ignored). Tokens are cached in memory until a minute before they expire. The run still
   gets only its `ozrt_` token. The Bedrock region and Azure resource are validated before they become part of an address and
   are pinned with the key like any other endpoint; a Vertex request's host comes only from a valid location in its path, and
   its project is replaced with the account's own. Each component of a JSON credential is scrubbed from answers. A credential
   that does not parse or a signature that cannot be made ends in one plain sentence; nothing falls back to forwarding what the
   run sent. *(Amendment 1: only each provider's inference endpoints and model list are relayed.)* "Test connection" signs the same way. **Not verified against the real services** (the SigV4 code is checked
   against AWS's published `get-vanilla` vector, the exchanges against fakes) **or against a real engine**: Claude Code (Bedrock,
   Vertex) and Codex (Azure) get gateway-style environment variables, the other engines are refused for these providers.
4. **A laptop key can approve** (ADR 0023's "laptop-key path"). An Ed25519 key kept in the operator's keychain signs a
   challenge the box's service issued; the service holds only the public half and mints the same single-use, scoped,
   five-minute code the dashboard does, recorded as `laptop-key:<id>`. A challenge is bound to a scope, project, environment
   and key, lives sixty seconds and is spent by any answer; five wrong answers in a minute lock the gate. Enrolling and
   revoking a key are themselves gated changes (scope `signer-enroll`): ~~allowed once as `bootstrap` before any second factor
   exists~~ *(withdrawn by Amendment 1: never from a socket the box user can reach; the first key is pinned when the box is
   made)*, then only with an approval from the dashboard or from a key already enrolled, or by root. Enrolling a key counts as a
   second factor existing. `ozbox secrets approval-key enroll|revoke|list` and `ozbox secrets approve` are the laptop side; the
   box side is the import socket the box user can already reach, which is safe because nothing there is worth anything
   without a signature the box user cannot make *(true only once the first key is not the box user's to choose: Amendment 1)*.
5. **The box's own secrets on Hetzner.** Hetzner has no instance tags the box can read, so the declaration is the settings
   file the loader reads (`/etc/ozbox/box-secrets.env`), written at first boot from the module's `box_secrets_*` variables and
   on a live box by `ozbox box-secrets <box> --backend openbao --path .. --role .. [--vault-addr ..]`, the same
   plan-then-apply as AWS, through the root helper (`write-box-secrets`, `clear-box-secrets`; scope `box-secrets`, so a box with
   a second factor wants an approval, bound to the declaration and its address: Amendment 1). Only OpenBao is offered: there is no cloud role to read Parameter Store with. The file
   holds names and an address, **never a secret**, because Hetzner serves user data to every process on the box; the vault
   token is placed afterwards through the root helper (`place-bao-token`, read once from a request file, written to a root-only
   file the loader's unit reads as environment). The same environment files fix a gap on AWS too: nothing used to give the
   loader its `BAO_ADDR` or token. Changing the variables on an existing Hetzner server replaces it (its first-boot
   configuration changes), so use the command for a live box; the variables are creation-time.

6. **A fresh box's secrets service starts, says why when it cannot, and survives an upgrade** (found on a real box: the unit
   restarted every few seconds and the box user could not see why).
   - *Not configured is a state, not a crash.* The service exits **78** when it has no key for its store (or any other start-up
     configuration error; *Amendment 1: and only then: a key service, TPM, vault or disk that fails is retried*), writes `not-ready: <reason>` to `/run/ozbox-secrets/state` (world readable, names only), and the unit has
     `RestartPreventExitStatus=78`, so it is not retried every few seconds. `ozbox secrets status` from the box user reads that file
     and says what is missing and how to fix it (before, it answered only "OZBOX_SECRET_FILE must name the encrypted store").
   - *A key source on every box.* KMS (the instance role) or a TPM are used when present. First boot now sets
     `OZBOX_SECRET_ALLOW_FILE_KEK=1` when the box has no KMS key, so the key is kept in a file only the secrets user can read
     (`kek.key`, 0600). That protects the store against the box user and agents, which is the box's threat model, and **not**
     against someone who can read the disk as root; the error text says so.
   - *Upgrades keep the store.* An upgrade replaces the system disk and keeps `/work`. The service keeps a copy of its store (and
     the key file, where the key is a file) in `/work/ozbox-secrets-private` (0700, secrets user), refreshed every thirty seconds,
     and puts it back at start when the new system disk has none. It waits for `/work` first (a store made before the mount would
     overwrite the real copy). With a KMS key the copy is useless without the instance role; the audit chain itself is on `/work`.
     *(Amended by ADR 0029 Amendment 6 §9, and built in its Amendment 7: the key file is never copied to `/work`, and the copy
     is excluded from restic. The key is escrowed off the box (in the vault under the box's own path, fetched back by the secrets
     service; the laptop-keychain escrow through `ozbox upgrade` waits for the ingress account), so "upgrades keep the store"
     holds through the escrow; a file-KEK box with no escrow whose system disk is replaced recovers from the vault. The audit
     chain moves to a filesystem of its own with signed checkpoints for Production (not built).)*
   - *User services start at boot.* `user@.service` has a drop-in (`RequiresMountsFor=/work`, `After=work.mount`) in the image,
     first boot restarts the user manager once `/work` is mounted, and the self-test fails, naming them, when an enabled user unit
     is not active (`user_services_active`).
   - *`collect-logs` shows the services that matter*: the secrets service, the dashboard, the box-secrets loader, the guard
     installer, the runners, the tunnel and the web IDE connector, sixty lines each, with key-shaped text removed.

## Amendment 1 (2026-11-10): fixes from a security review of the code

A security review (2026-11-10) of the code merged that day found that **bootstrap mode** (no second factor enrolled, which is
the state of every fresh box) treated the box user as the owner, and the box user is the party a second factor guards
against. What changed, finding by finding, and what is still true:

- **The sockets were unreachable as written.** Each socket took the service's own group (a socket takes the group of the
  process that binds it, not of its directory), and connecting needs write permission on the socket, so neither the box user
  nor the supervisor could connect to the box, broker, import or supervisor socket. Every "the box user can reach" claim in
  this record and in ADR 0018 was therefore unverified on a real box. Each socket is now put in its directory's group (the
  service holds `CAP_CHOWN`), and the box daemon's self-test connects to the box, broker and import sockets as the box user
  (`secrets_sockets_reachable`).
- **The first approver is pinned from outside the box** (item 4). On a fresh box the box user could enrol its own laptop key
  through the import socket as `bootstrap` and approve everything itself from then on. Now `approval_key_enroll` and
  `approval_key_revoke` are refused on every socket but root's while no second factor exists, and the first key comes the way
  the box's own configuration does: `ozbox create` puts the public half of this computer's `laptop` key (base32, so it fits a
  Hetzner label as well as an AWS tag) in the box's `ozbox-approver` label, the first-boot setup step (root) writes it to
  `/etc/ozbox/approval-keys`, and the service enrols it once, recorded as `pinned` (a revocation sticks: the store remembers
  the pin it applied). Every enrolment records the socket it came in on. A box made without a pin (or by an older version)
  stays in bootstrap until a passkey is enrolled in the dashboard; a laptop key can then be enrolled with an approval from it.
  The dashboard does not yet mint the `signer-enroll` scope, so on such a box that path is open only from root *(it does since Amendment 2)*. One laptop
  key may approve on many boxes: enrolling it on another box sends the same public half, and revoking it on one box leaves it
  in the keychain. On AWS the label is an instance tag, which the box's role cannot change (it has no `ec2:CreateTags`), so an
  upgrade renders the same pin; a clone carries its source's labels, so the same key. A box made from the dashboard, or by
  `ozbox` before this change, has no pin.
- **The vault address is bound** (item 5). An approval for `write-box-secrets` names the declaration (scope `box-secrets`,
  project `declaration`, environment `d-` and sixteen hex digits of the sha256 of the declaration's words), which
  `ozbox box-secrets` prints with the address, so an approval for one path cannot carry a different address. A changed address
  deletes the vault token in the same step; clearing the declaration deletes it too. In bootstrap an address change, or any
  change while a token is in place, is refused: set the address with the module's variables when the box is made.
- **The broker relays inference only** (item 3). The run's token used to buy everything the cloud account's credential can
  do except reading it (a Vertex training job, Azure files and fine-tuning), none of it counted against the run's limit. Each
  provider now has an explicit allow-list (Anthropic messages and token counting; the OpenAI shape's chat, completions,
  responses and embeddings; Gemini's generate, count and embed; Bedrock runtime's invoke and converse; Azure deployments and
  `/openai/v1`; Vertex publisher models' predict, generate and count, and its OpenAI-compatible chat), plus the model list as the
  only GET; the query may name only `alt`, `api-version` and `beta`. Everything else is refused (403) before any credential is
  read. Bedrock's binary event stream is now counted, and a run with a spend limit whose provider answers in a form the broker
  cannot count is refused from then on. **The least-privilege role is still the person's job**: even Vertex's
  `roles/aiplatform.user` and Azure's "Cognitive Services OpenAI User" grant more than inference, and the allow-list is what
  narrows them for a run. Not verified against the real services.
- **The actor is the kernel's word** (item 1). An event on a socket the box user can reach is recorded as the user the kernel
  names (`uid:<n>`, from `SO_PEERCRED`, read through `rustix` in safe Rust; `box-user` where the kernel does not say), and what
  the client claimed is kept in the detail as `claimed-actor=`; only the supervisor's socket and root's may name a person. A
  client may name only the chains the service keeps (`tasks`), and a seal key is made for no other name, so the store cannot
  be grown without end.
- **No fallback, and transient failures are retried** (items 1 and 6). On a box (it has `/run/ozbox-secrets` or
  `/etc/ozbox/secrets.env`) a missing socket makes every append fail, and `OZBOX_AUDIT_SOCKET=off` is ignored, so a secrets
  service that has not started never sends the chain's writers back to a file the box user could rewrite. The service exits 78
  only for configuration (no key source, no store named, a store whose key no escrow holds); a key service, TPM, vault or disk
  that fails is retried with a growing wait, saying so in the state file, and then left to the unit, which starts it again and
  reads its settings files again.
- **A migrated chain gets a new key** (item 1). The old chain is always kept whole beside the box's as `<chain>-legacy`,
  checked with the old key (`audit-seal-key.<chain>-legacy`), and the box's chain is sealed with a fresh key from its first
  entry (`audit.migrated`, which names the old head). Before, the box's chain went on under the key the box user's own process
  had written, so anyone who had copied that file could reseal a copy of every later line.
- **Old chain files are read without following a link** (item 1). The service reads and destroys an old chain's anchor and
  key with file capabilities; it now opens only plain files with the chain file's owner, checks that what it opened is what it
  looked at, and never zeroes or removes anything else.
- **The store's key and backups**: see ADR 0029, Amendment 7.

What is still not covered: the root helper accepts any request the box user makes, so `place-bao-token` and the egress and
patch actions are gated separately (not in this amendment); the dashboard cannot yet mint `signer-enroll` *(closed in
Amendment 2)*; a box made before this change has no pinned key *(an AWS box gets one on upgrade: Amendment 2)*; the self-test's socket check fails while the secrets service is still retrying its start
(about two minutes) or is not ready, which is honest but can fail a self-test run right after boot; nothing in this amendment
is proven on a real box.

**Why.** An audit trail the audited party can rewrite is a log, not a record; an approval that only a browser can mint leaves a
laptop-only operator with the typed confirmation; and a cloud-account model provider that a run cannot use at all leaves the
broker's promise (no run ever holds a key) true only for vendors with an API key.

**Consequences and what is not covered.**
- The audit service is part of the secrets service process, so the chain is as available as the store. There is no second copy
  off the box: pinning the head hash (the dashboard shows it) is still how to hold the log to account against a root user.
- A well-formed forged line can still be **added** by the box user until the next checkpoint (every fifty entries or ten
  minutes); `verify` reports it as not yet sealed, not as wrong. Anything altered or removed is reported.
- Run tokens held by runs in flight are invalidated when the secrets service restarts (unchanged); so are challenges waiting for a
  signature.
- Laptop keys: there is no way yet to list when a key was last used from the dashboard. *(The approvals page offers every
  scope since Amendment 2.)*
- The copy of the store on `/work` is refreshed every thirty seconds, so a secret saved in the last half minute before a system
  disk is replaced can be missing from it; the file-key box has the same strength as its original, no more.
- Hetzner: the vault token has no command-line helper that writes the request file for you (it must be placed by the box user,
  then requested with `ozbox admin <box> -- place-bao-token ID`), the instance labels are not used, and a box created from
  an older module keeps whatever settings file was placed by hand.
- Cloud accounts: Gemini CLI, Aider and OpenCode are refused for Bedrock and Vertex (and Aider, OpenCode for Azure) until each has
  a verified environment; the Vertex project placeholder and Azure's `/openai/v1` path are untested against a live account.

## Amendment 2 (2026-11-11): one rule for a box with no approver, and a root helper that says which actions are gated

A security review (2026-11-11) of the merged fixes found the rules for a box with no second factor written in four places
that disagreed, the dashboard unable to mint two of the scopes the service asks for, and a root-helper action added after the
gates were built that went ungated (ADR 0029 Amendment 8). What changed:

- **One table decides what a box with no approver may do** (`secrets_approval::SCOPE_RULES`): `import`, `policy`,
  `tunnel-token` and `guard-override` are allowed and recorded as `bootstrap`; `box-secrets` is allowed for a first
  declaration only (the box's secrets script refuses a new address, or any change while a vault token is in place); and
  `signer-enroll` and `host-guard` are refused, as is any scope a version does not know. The service's gate applies it, and
  the checks that used to decide for themselves (laptop-key enrolment, the host guards) read the same table.
- **The dashboard mints every scope the service accepts**, including `signer-enroll` (a laptop key's enrolment or
  revocation, bound to the key's name) and `box-secrets` (a declaration, bound to its change code, its removal, or the vault
  token). A test compares the dashboard's list with the service's, so they cannot drift apart again. On a box with only a
  passkey, a laptop key is now enrolled with an approval from the dashboard.
- **Every root-helper action declares its gate** in one table in the helper (`ungated` with the reason, or `gated`), the
  helper refuses an action that is not in it, and the `ozbox` program keeps the same table; a test compares the two and the
  helper's `case` arms.
- **How each laptop key came to be trusted is recorded** (`pinned`, `root`, or the approval that enrolled it). A key with no
  record was enrolled by an older version, which let the box user enrol one before any second factor existed; `ozbox upgrade`
  lists such keys after an upgrade with the command that revokes one.
- **An AWS box with no pinned approver gets one on upgrade**: the new machine's first-boot configuration pins the upgrading
  computer's key, as `ozbox create` does. On Hetzner this cannot be done (ADR 0029 Amendment 8).

What is still not covered: *(closed by ADR 0039: the dashboard's routes for deleting what the bill found, permissions and
applying a plan that cannot be undone, and its tunnel changes, now use the browser's one decision, so a dashboard with no
sign-in on a box is refused there too)*.

## Amendment 3 (2026-11-12): a tunnel-token approval is for one token, and how a code reaches the person

A review of the `--approval` route for tunnel tokens found that a code approved "a tunnel-token change", not a token, while
the token and the code passed through files and processes the box user owns. Two decisions follow.

- **The approval is bound to the token.** The laptop signs the first 32 hex digits of the SHA-256 of the token in the
  approval's environment field (`ozbox secrets approve --scope tunnel-token --project <provider> --token-stdin`), which the
  gate already compares. The root helper reads the token file first, into its own memory, and only then asks the gate,
  passing the code and the token on standard input (`secrets gate --bind-token-stdin`), so rewriting the file afterwards
  changes nothing and a code made for token A is refused for token B (the refusal does not spend it). The same route binds
  the dashboard's own mint. A helper from an image before this amendment still checks the unbound code: the laptop asks the
  box which kind it has and says which command to run, and the docs say plainly that an unbound code works for any token
  until it is used.
- **Codes stay off command lines.** The request program reads a code on standard input (`--approval-stdin`) and the installer
  hands it to the program the same way; an older request program gets the code as its last word, which is the only case it is
  an argument. The laptop accepts `--approval-stdin` as well as `--approval`.

How the code comes back, and what this does not close (updated 2026-11-12, when the laptop-to-box route moved): the laptop's
`ozbox secrets approve` (like key imports, signer enrolment and revocation, and the signer list `ozbox upgrade` reads) now reaches
the box's secrets service as the `ozbox-ingress` account (ADR 0029 Amendment 9), whose forced command reads none of the box
user's start-up files; the request is sealed to the service's pinned key and the answer (the code) comes back on that account's
session, which no process of the box user is on. The box user's shell functions are no longer on that path, so a function named `exec` or `env` can no longer wrap it, and the fixed `exec /usr/bin/env -i … ozbox
secrets receive` line is gone. That route does not protect against root on the box, and a box made before the ingress account
is refused rather than reached the old way. The token and the code that `ozbox dashboard install` hands to the box's request
program still travel through the box user's login shell (it runs a script there); for them the binding is what keeps a taken code
from storing another token. Whether the dashboard's own token change reaches the helper (its request file would be owned by the
supervisor user, not the box user) is not settled and needs a run on a real box.
