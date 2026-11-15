# 0029 — Production secrets have no standing access: nothing usable at rest, nothing handed to a command, one approval per session

**Status.** Proposed. A security review (2026-11-10) found this record unsound as first written and sound with fixes; **Amendment
6 folds in the fixes and the owner's decisions, and where it disagrees with an earlier section, Amendment 6 wins** (the earlier
text is marked). Nothing is built until the owner says go. Everything here is Preview until the end-to-end suite (below) is
green in CI on a real Linux machine and the real-box gate has passed.

**Decision.** A Production key (a database URL, a payment key, a deploy token) must be usable only while a person has just
approved that exact use, only by the one declared command, and without that command ever holding the key. Nothing on the box,
at rest or in memory between uses, lets an agent, a stolen disk, a snapshot or root on the box at rest obtain one. ADR 0018
already keeps keys out of the box user's reach and refuses Production-looking keys by default; this ADR lets people put real
Production keys in anyway, safely, instead of forbidding it.

## Threat model

The attacker is a prompt-injected agent that runs as the box user and can run any command, read anything the box user can read,
open any socket the box user can open, write to `/work`, make network requests the box allows, and talk to the dashboard's
public API as the box user. It cannot become root, the secrets user, the supervisor user or a runner user. Also in scope: a
stolen or snapshotted disk, a leaked backup, an image copied elsewhere. **Out of scope:** the owner's laptop when agents also run on it (except as Amendment 6 §9 says), the key's own vendor, the
vault account itself, and a person who approves something they should not have. **Root on the running box** is not defeated;
the promise against it is narrower, and it is written once, in Amendment 6 §1: *root on a running box gets at most what one
approved session is using, for at most that session, and the audit chain records it; the box holds no credential and no role
that can fetch a Production value on its own.* Also stated there, because the first draft implied otherwise: the key is
protected, **the data the key can reach is exposed to the agent for the session**. (Replaced by Amendment 6 §1.)

## 1. No usable Production key at rest on the box

A Production-flagged secret is **not stored in the box's store as a usable value**. There are two homes, chosen per key:

- **The owner's computer (default).** The value lives in the laptop's OS keychain (the same `KeychainSecrets` that holds the
  laptop key). The box holds only a **record**: name, project, environment, a fingerprint (a keyed hash, so a leaked record cannot
  be used to guess the value), the declared hosts and the declared command. Nothing decryptable.
- **An owner-controlled vault** (OpenBao or the cloud's secret manager) that **only the off-box issuer can read** (Amendment 6
  §4); neither the laptop nor the box reads it in normal use. Same record on the box.

Each approved use is **released just in time** and **sealed to the box service's key** (Amendment 6 §§3, 4): from the issuer
for the vault home, from the laptop for the laptop home, through a dedicated ingress account, never through a process that runs
as the box user. The service keeps it only in the memory of the one injection it serves, `mlock`ed, zeroized when the use ends,
and never writes it to a file, an argument, an environment variable or a log. A disk, a snapshot or a backup therefore yields
nothing. *(The first draft delivered over the box user's SSH route; Amendment 6 §3 replaces that.)*

*Removed by Amendment 6 §4: the `sealed` at-rest option.* It depended on a KMS grant with an expiry minted from the laptop and a
key policy that checks an owner signature; neither is implementable, and while the box's role could decrypt, a sealed key was not
sealed. **Unattended Production use is not offered.** A schedule or trigger gets no Production key.

## 2. Credential injection: commands never receive the key

The command is started with **no secret** in its argv, environment, files or stdin. Instead the service gives it a path to the
credential that works only for the declared destination:

- **HTTPS.** The command's egress already goes through a per-command proxy that limits it to declared hosts (ADR 0023). A
  declaration may say `inject: {host: api.example.com, header: Authorization, scheme: Bearer, key: STRIPE_KEY}`. The proxy
  adds the header on requests to that host and **removes any header the command set with that name**; other hosts are refused and
  the header is only ever added after the destination check. The proxy terminates TLS for the declared host with a per-command CA
  the command trusts through its own trust store only; hosts with no `inject` rule are tunnelled untouched. For **Production**:
  exact hostnames only, no query-parameter form, strict re-serialisation, response scrubbing and the other rules of Amendment 6
  §7. *(Amended by Amendment 6 §7: the first draft allowed a query parameter and wildcard rules.)*
- **Databases.** The service opens one **listener per declared destination**, reachable **only from inside that run's own mount
  and network namespaces as a Unix socket** (Amendment 6 §7; the first draft's loopback TCP port was reachable by every process
  of the box), and the command connects with a connection string that has **no password**. The listener authenticates upstream
  on the command's behalf (Postgres first), **builds the startup message itself**, and verifies the real server with
  `sslmode=verify-full`. Read-only is the database role's job; the listener's `default_transaction_read_only=on` is hygiene, not
  a control, and the listener parses message framing only, never SQL. Other protocols (MySQL, Redis, SSH) are **refused for
  Production** until each has its own reviewed `Upstream::authenticate`.
- **Raw delivery** (the key in the command's environment) is **refused for a Production key, without exception**
  (Amendment 6 §7). It remains available for development and staging with the usual warning. *(The first draft let the owner
  allow it per key.)*

## 3. One approval per session, bound to what it covers

*(Rewritten by Amendment 6 §§4–6. The first draft let the supervisor mint approvals and let a person carry a code.)*

A **use request** names `{project, environment, named command, key names}`. An agent may only *request*: the request appears in
the approvals inbox (dashboard and `ozbox secrets inbox`) with its scope, the command's exact argv, the commit and directory
digest it would run, the attested requester and a diff since the last approved run. It is **not** usable by the box user or any
agent.

An approval is made **by the off-box issuer** (or, for the laptop home, by the laptop) and only when:

- a **passkey** assertion over the issuer's own challenge verifies against the keys the issuer pins (the dashboard, including the
  phone PWA, only relays), or
- a **laptop signer** signs that challenge, with the box id, store id and service-key fingerprint inside it.

It is bound to `{box, store, service key, project, environment, command, argv, directory digest, commit, stdin digest, key
names, request id, attested run}`, has a **window of at most 15 minutes** (`ttl_ms <= 900_000`) and **`uses_left`** (default 10).
**A use is one launched command.** For the vault home the issuer decrements `uses_left` and checks the window with a
compare-and-set in its own state before every release; two racing runners cannot both win. A renewal is a **fresh approval**,
re-bound to the current commit. The box holds a handle to the approval and nothing else.

Through the **permission engine** (ADR 0022) a use is a Production action on the `secret.use` action word with the environment
set to production: with no active grant it is refused; the approval *is* the grant, recorded as made, used and spent, and
confirmed `passkey` or `laptop-key` honestly. A run started by a schedule or trigger gets none. **Chat cannot approve**
(Amendment 6 §6). **Bootstrap mode refuses every Production operation** (Amendment 6 §6).

## 4. Leak and abuse controls

- **Egress** only to declared hosts (ADR 0023), enforced by the proxy and by the runner's closed network; The runner has no DNS
  at all (`IPAddressDeny=any`; the proxy resolves), and no resolver is added for it to query (Amendment 6 §7).
- **Redaction** of every value **the box holds** in everything the command returns to the agent (stdout, stderr, files read back
  through the API): the exact value and its base64 (standard and URL), hex and URL-encoded forms, with a sliding window across
  chunk boundaries. A hit is replaced with `[redacted]` and counted; the report **never names which secret matched or where**
  (it would be an oracle); a command with three hits is stopped. It does not cover values that are not on the box, and agent code
  can apply any other transform, which is why upstream **response scrubbing** (Amendment 6 §7) is the real control for injected
  keys. *(The first draft listed reversed and separator-inserted forms and named the secret; Amendment 6 §7 removes both.)*
- **Caps** per command: output bytes, wall time, CPU, number of upstream requests/statements per minute and in total, and
  concurrent connections.
- **Commit barrier** (ADR 0023) unchanged, and scoped honestly: the staged diff is scanned for values the box holds; a Production
  value that is not on the box outside a use cannot be matched (Amendment 6 §7).
- **No side channels**: the runner user has `LimitCORE=0`, `ProtectProc=invisible` and `ProcSubset=pid` (`PR_SET_DUMPABLE=0` is set before the exec but the kernel resets it for the command: see Amendment 10, revision 1),
  no swap (`MemorySwapMax=0`, secrets `mlock`ed), no `ptrace` (Yama 1 plus a different uid), and the injection process is a
  different uid from the runner (and gets the same `LimitCORE=0`, `PR_SET_DUMPABLE=0`, `MemorySwapMax=0` and `mlock`) so `/proc/<pid>/environ` and `/proc/<pid>/mem` of either are unreadable by the box user.
- **Audit** (ADR 0028): `secrets.use.requested`, `.approved`, `.refused`, `.started`, `.finished`, `.redaction` (with counts),
  `.expired`, `.renewed`: names, scopes and counts, never a value or a code. For a Production entry `.requested`, `.approved` and
  `.started` **fail closed**: no chain line, no use (Amendment 6 §9).

## 5. Least privilege is part of the feature, not a footnote

The declaration is **linted** when saved: a Production key whose declaration has no host scope, uses raw delivery, or (for a
database) connects as a role the service can see has write privileges (a read-only probe at declaration time, with the owner's
approval) produces a warning for development and staging and **a refusal for Production** (Amendment 6 §10), shown in the dashboard and
`ozbox env policy set`, and recorded. For Production, raw delivery no longer exists and a role that can write, or can read tables
outside an owner allow-list, is refused. Recipes ship in the docs:
a Postgres read-only role that cannot read sensitive tables (grant by table, not by schema, with a schema of views that omit
sensitive columns), a Stripe restricted key, a read-only cloud role. The guide opens with them: *the right way to put a
Production key in Oz Box is a key that can do little.*

## 6. How we know it holds

Three levels, all required:

1. **Unit and property tests** for each component: approval signing, verification, TTL, use count, replay and race; redaction
   over encodings and chunk splits (property tests: random values, random split points, every encoding); proxy rule matching
   and header stripping; credential injection; Postgres authentication; store and sealed-key wrapping.
2. **`secrets-e2e`, a required CI job on a real Linux VM with systemd** (GitHub's Ubuntu runners; no cloud): install the built
   `ozbox` and the units exactly as the image does (the `ozbox`, `ozbox-secrets`, `ozbox-supervisor` and `ozbox-run-<project>`
   users, sockets, the root launcher, a store with a test key-encryption key), start the real services, and as the **real box
   user** import a sentinel Production key from a "laptop" process, declare a command, request, approve with a test passkey and
   a laptop-key signature, run against a local HTTPS server and a local Postgres that **require** the credential, and assert:
   success; the key in no env, argv, output, file, journal line or core; the audit chain verifies. Then the **adversarial suite**,
   as the box user on the same machine: read `/proc/<pid>/environ` and `mem` of the runner and the injector, `ptrace`, force a
   core dump, read swap and the journal, open the store, the KEK and every socket, DNS-tunnel, defeat redaction with
   encodings and split writes, write the key to `/work`, `git commit` and `push` it, approve its own request, replay an
   approval, race a TTL and a use count. Every attempt must fail and the test asserts each.
   The review's additions are in "Additions to the `secrets-e2e` and adversarial suite" under Amendment 6 and are required too.
   One script (`scripts/secrets-e2e.sh`) runs it on any Linux machine; CONTRIBUTING documents it.
3. **A real-box gate**: the same script with `--real-box` against a test key on a real Oz box, producing a pass/fail report
   to attach to the release record.

## Shared contracts (what other parts build on)

These are fixed here so that environments, allocation, the injector, the issuer and the end-to-end suite can be built by
different people without colliding. A change to one is a change to this record. *(Rewritten to agree with Amendment 6; the
`sealed_grant` home, the chat values of `Approval.via`, the 30-minute and 4-hour ceilings and the box-held approval are gone.)*

**1. The entry model** (a record in the box's store, one per `{project, env, name}`, **signed by the owner's policy key**; the
value is separate and, for Production, never on the box):

```
Entry {
  project: String,            // [a-z0-9-]{1,20}
  env: String,                // "development" | "staging" | "production" | a custom [a-z0-9-]{1,20}
  name: String,               // ENV-style, [A-Z][A-Z0-9_]{0,63}
  kind: Kind,                 // "secret" | "plain"; a plain value that looks like a key is refused
  type: SecretType,           // model_provider | git_forge | cloud_infra | database | third_party_api | internal | plain
  home: Home,                 // "box_sealed" (development and staging only) | "laptop" | "vault"; production is laptop or vault
  fingerprint: String,        // keyed hash under a key the issuer (or the laptop) holds; never the value, never keyed on the box
  created_ms, updated_ms, updated_by,   // by = a person id or "laptop-key:<id>", never an agent
  allocation: Allocation,     // deny by default; see 2
  inject: Option<Injection>,  // how a command uses it without holding it; see 3 of Amendment 6 §7
  policy_sig: Signature,      // owner policy key over the whole record except the value; checked on load, recover and release
}
Injection { host: String /* an exact hostname for production; no wildcard */, header: String, scheme: Option<String>, key: Name }
          // a query-parameter form exists for development and staging only
EnvPolicy { env, delivery: "declared_commands" | "per_use_approval" | "zero_standing",
            raw_env_allowed: Vec<Name> /* production: always empty */, session_minutes: u32 /* production: <= 15 */,
            loosened_by: Option<{person, at_ms}> }   // production starts zero_standing
```

Plain values are stored and shown as text; secrets are never returned by any socket or API (names, kind, type, fingerprint,
updated, by). The store keeps entries under `workload.<project>.<env>.<name>` (as today) with the record in the entry's
metadata; `Entry` is serialised as JSON in that metadata, versioned (`"v": 1`; the signature is part of it).

**2. Allocation and the decision.** Allocation says who may *use* (never read) the entry:

```
Allocation {
  boxes: Vec<BoxSel>,         // BoxSel = Box(name) | Label(k=v) | Group(name) | Laptop   ("Group" = a named box group, a unit fleet)
  engines: Vec<String>,       // "claude-code" | "codex" | "gemini-cli" | custom engine id; empty = none (advisory for production, A6 §5)
  run_kinds: Vec<RunKind>,    // person | schedule | trigger | conductor | worker_on_clone (advisory for production, A6 §5)
  people: Vec<PersonId>,      // empty = none (the first draft said "any person")
  commands: Vec<String>,      // declared command names; empty = none
}
```

Empty means **none**. Clones and new boxes match only by an explicit `Box`/`Label`/`Group` selector, and the labels and groups
come from a signed **box provenance** record set by an Owner or Admin with a fresh step-up, never from a request.

The decision is `permissions::decide` with `Action::SecretUse` and the situation extended with a `SecretUse` context:

```
SecretUse { project, env, names: Vec<Name>, secret_type, box_name, box_labels, box_groups,
            engine, run_kind, person, command, argv_digest, directory_digest, commit,
            host: Option<String>, delivery: Injected | Raw /* Raw: development and staging only */, attested: RunAttestation }
```

`engine`, `run_kind` and `person` are filled **from the supervisor's attestation**, never from the request. Order (extends ADR
0022): deny rules; **Production needs a use grant** (the approval, §3), and is refused in bootstrap; the signed allocation must
match every field of the context; the environment policy's `delivery`; then the mode. The secrets service, the broker and the
runner call it and refuse on anything but allow; no component re-implements it. Refusals carry a stable reason code
(`not_allocated:box`, `not_allocated:engine`, `run_kind`, `needs_approval`, `raw_refused`, `expired`, `spent`, `bootstrap`,
`binding_changed`, `unsigned_policy`, `audit_unavailable`).

**3. The approval.** Made only by the issuer (passkey or laptop signer, or the offline recovery key for break-glass), or, for the
laptop home, by the laptop. **The box never mints one** and a person never carries a code for Production. It is never a bearer
string the box user holds: the service holds a handle, and state lives at the issuer.

```
Approval { id: random 128-bit, scope: { box_id, store_id, service_key_fp, project, env, command, argv, directory_digest, commit,
                                          stdin_digest, names (sorted), request_id, run: RunAttestation },
           via: "passkey" | "laptop-key:<id>" | "recovery:<id>", minted_ms, ttl_ms (<= 900_000), uses_left, spent: bool,
           renews: Option<id> }
RunAttestation { run_id, cgroup, engine, run_kind, person, box_id, started_ms, commit }   // supervisor-signed
```

The challenge both approver paths answer is the SHA-256 of the canonical encoding of `scope` plus `ttl_ms`, `uses_left`, a nonce
and an expiry; the laptop signs `ozbox-use-v2\n<digest hex>` after rendering the fields from its own parse of the request. A
use is spent by a compare-and-set at the issuer before any value is released.

**4. The `secrets-e2e` harness layout.** One entry point, `scripts/secrets-e2e.sh [--real-box <name>] [--only <group>]`, with
`tests/secrets-e2e/` holding: `lib.sh` (users, sockets, units, the ingress account, the store with a test key-encryption key: the
same steps as the image), `fixtures/` (a local HTTPS server and a local Postgres that **require** the credential, both refusing
without it, a local OpenBao with **real policies** and the issuer sidecar), `flow-*.sh` (staging delivered without approval to the
declared command only; production refused without approval and working with one; renewal; plain values; allocation cases), and
`attack-*.sh` (one file per attack class, run as the real box user, each asserting failure). Every script prints `PASS <name>` or
`FAIL <name>: <why>` and the runner exits non-zero on any `FAIL`; with `--real-box` it writes a report file
(`secrets-e2e-report.txt`) and runs only what a real box can (no user creation). CI job name: `secrets-e2e` (required).

## Amendment 1 (owner, 2026-11-10): approved sessions, a durable vault of your own, a full lifecycle, short-lived credentials

**Approved sessions replace per-single-use approvals.** One approval covers **one named command** for a **window** (default 15
minutes, **ceiling 15 minutes**; the first draft said 4 hours, Amendment 6 §6) and a **maximum number of uses** (default 10, the
owner's choice in Amendment 3), bound as Amendment 6 §5 says. Within it, each use is still a Production `secret.use` that is decided, injected and audited; outside
it, nothing works. Optional **environment protection rules**, modelled on GitHub's: allowed branches and commands, a **wait
timer** and required reviewers (**deferred** until an installation has more than one approver; Amendment 6 §12), and
**never for scheduled runs, triggers or clones**. An agent may only *request*; a request sits in the approvals inbox until
approved, refused or expired. Where §3 said "single-spend, use count 1", read "a session with `uses_left`" (the compare-and-set
is on `uses_left` and the window).

**The durable source of truth is a vault the user owns.** Not the box, not the laptop, nothing hosted by Oz Box. One backend
interface (`SecretBackend`, below) has implementations for **AWS Secrets Manager** (KMS-encrypted, versioned, optionally
replicated across regions) for AWS users, **OpenBao** (self-hosted) and **encrypted S3-compatible object storage** (client-side
AES-GCM under a key the user holds) for everyone else, with the existing Parameter Store/OpenBao loader (ADR 0023 item 5)
becoming its read-only subset. The laptop keychain and the box hold **only what they need**: staging values are cached sealed on
the box; Production values are fetched **by the off-box issuer** for an approved use (Amendment 6 §4) and never stored on the box. A lost laptop, a
rebuilt box or a deleted machine loses nothing: the vault is authoritative, `ozbox secrets recover` rebuilds a box's records
and caches from it, and the end-to-end suite **wipes the box store and the laptop cache and recovers from the vault** (§6).

**Lifecycle, as in AWS Secrets Manager.** Every change is a new **version**; versions carry **labels** (`CURRENT`, `PREVIOUS`,
`PENDING`, user labels); **rollback is moving a label** (instant, audited); **delete is soft** with a recovery window of 7 to 30
days (default 30) during which `restore` brings it back and nothing can use it; **rotation** is optional per secret: for development and staging a declared
**rotation command** (creates the new value at the provider, writes `PENDING`, tests it, then promotes it); **for Production never
a command the agent can run**: the issuer or the provider rotates it (Amendment 6 §8). Backends ship in phases, Secrets Manager
first (Amendment 6 §8). Every step is an audit event.

**Prefer short-lived credentials.** A secret of type `cloud_infra` may be a **role**, not a key: for `development` and `staging` the box's instance role, or an
OIDC web identity exchanged at STS (**for Production a role the off-box issuer assumes, Amendment 6 §4**), assumed **per run** with a session policy scoped to that run's allocation and a duration no
longer than the approved session (the GitHub-OIDC-to-AWS pattern). The run then holds temporary credentials that expire
by themselves. A **long-lived** cloud key is allowed with a warning and stricter defaults (never raw, session window halved,
rotation encouraged, shown in the lint).

**Naming follows GitHub and AWS.** Scopes: **fleet** (≈ organisation), **project** (≈ repository), **environment** (with
protection rules). Log **masking** works like GitHub Actions' (registered values are masked in every output, with the encodings
of §4); one **audit trail** is the chain (ADR 0028), the CloudTrail of the box.

### Contract changes

```
Entry += { version: u32, labels: Vec<String>,            // "CURRENT" | "PREVIOUS" | "PENDING" | user
           versions: Vec<{ id, created_ms, created_by, fingerprint, labels }>,   // values live in the home, not here
           deleted_at_ms: Option<u64>, recovery_until_ms: Option<u64>,
           rotation: Option<{ command: String, every_days: u32, last_ms: u64 }>,
           source: "vault:<backend>:<ref>" | "box" | "laptop",
           credential: "static" | "assumed_role" { role: String, session_policy: Option<String>, max_seconds: u32 } }
ProtectionRule { env, allowed_commands: Vec<String>, allowed_branches: Vec<String>, wait_minutes: u32 /* reserved, refused if > 0 */,
                 reviewers: u8 /* reserved, refused if > 0 */, never_for: Vec<RunKind>, session_minutes: u32 /* <= 15 */, session_uses: u32 }
Approval += { session_ends_ms, uses_left, approvers: Vec<via> }     // superseded by the rewritten contract 3; wait_until_ms is reserved

trait SecretBackend {                       // one interface; AwsSecretsManager, OpenBao, EncryptedObjectStore, Fake
  // A6 §8: split into a reader (issuer only) and a writer (laptop and issuer only); the box's build has neither.
  fn put_version(&self, r: &Ref, value: &Zeroizing<String>, labels: &[&str]) -> Result<VersionId>;
  fn get(&self, r: &Ref, label_or_version: &str) -> Result<Option<Zeroizing<String>>>;   // JIT only
  fn list_versions(&self, r: &Ref) -> Result<Vec<VersionInfo>>;                           // ids, labels, times; never values
  fn move_label(&self, r: &Ref, label: &str, to: &VersionId) -> Result<()>;               // rollback / promote
  fn soft_delete(&self, r: &Ref, recovery_days: u8) -> Result<()>;
  fn restore(&self, r: &Ref) -> Result<()>;
  fn list(&self, prefix: &str) -> Result<Vec<RefInfo>>;                                    // for `recover`
  fn rotate_hook(&self, r: &Ref) -> Result<RotationState>;                                  // optional
}
```
`Fake` backends for Secrets Manager and OpenBao are part of the unit tests; the `secrets-e2e` job runs a **local OpenBao with
real policies** (a container on the runner, never dev-mode root) so the vault path is exercised for real, including: set, new version, rollback, soft delete and
restore, rotation, and recovery after wiping the box store and the laptop cache.

## Amendment 2 (owner, 2026-11-10): approvers, notifications, chat approval, never reveal, break-glass

**Approvers.** Each environment lists named approvers (the owner by default). **One** approval is enough. The **requester can
never approve their own request** when anyone else is listed; with only the owner listed and the owner as requester, the
approval still needs the owner's own passkey or laptop key (a person, never an agent).

**Notifications, all four.** A request appears in (1) the dashboard approvals inbox, showing the exact command text, the key
names, the environment and the requesting agent, engine and box; (2) the existing alert channels (push, Telegram, Slack,
WhatsApp) with a link; (3) **chat** and (4) email, with a link. **These notify only. Chat cannot approve a Production use and offers Deny only**
(owner decision; Amendment 6 §6, which withdraws this amendment's chat approval, its TOTP safeguard and `chat_requires_totp`,
and keeps ADR 0021 item 5 and ADR 0026 item 8 as they were).

**The factor is recorded.** `Approval.via` is one of `passkey`, `laptop-key:<id>`, `recovery:<id>` (the `chat*` values are
removed); the audit chain names it.

**Never reveal.** No path (dashboard, CLI, API, a box, a socket) returns a saved value. They return name, version, labels,
fingerprint, who and when. A change is a new value. This is enforced at the backend interface (`get` is callable only by the
injector's just-in-time path, never by a request handler) and pinned by a test that greps every response type.

**Break-glass.** An **offline recovery key** (an Ed25519 key the owner keeps offline; only its public half is stored, at the
issuer; enrol and revoke are gated changes like laptop keys; the "recovery approver" of the first draft is removed, Amendment 6
§6) can approve when the usual approvers cannot. Using it **alerts every channel**, caps the session short (at most 15 minutes,
3 uses), **cannot be renewed**, and **flags the audit entry for review** (`secrets.use.recovery`), which the dashboard shows until a person acknowledges it.

### Contract changes

```
Approval.via ::= "passkey" | "laptop-key:<id>" | "recovery:<id>"                    // the chat values are removed (A6 §6)
Approval += { requester: PersonOrAgent, approver: Person, flagged_for_review: bool }
ProtectionRule += { approvers: Vec<Person> }       // default [owner]; chat_requires_totp is removed (A6 §6)
```

### Additions to the attack suite
Chat can never approve (no chat message, bound identity or code mints an approval); the requester cannot approve their own
request; a recovery approval alerts every channel, is capped, cannot be renewed, and is flagged. (The first draft's chat and TOTP
cases are replaced by the list under Amendment 6.)

## Amendment 3 (owner, 2026-11-10): the vault is created by `ozbox init`, defaults, and inheritance by clones, snapshots and backups

**`ozbox init` creates the vault**, plan-then-apply with the cost shown first: on AWS a KMS key, a Secrets Manager prefix and
the **issuer** of Amendment 6 §4, and least-privilege IAM for boxes and runs (**a box role has no read of any Production path
or key**, and no vault write; the first draft let it read "the labels a run needs", which was standing access); elsewhere an
OpenBao the user runs or an encrypted bucket. The infrastructure lives in the OpenTofu modules (additive, small).

**Defaults.** Staging: delivered only to declared commands, injected where possible, egress to declared hosts, masked, audited.
An approved session defaults to **15 minutes and 10 uses**; an environment may override up to an owner-set maximum.

**Inheritance is first-class and configurable; the default is none.** No usable secret is ever present in a **clone, snapshot or
restic backup**, and a restore never brings a key back. Per environment and per secret: `inherit: none | ask | rule`. `ask`
prompts at clone time; `rule` is a selector (for example, staging test keys to worker clones labelled `ci`). Production stays
`none` unless the owner changes it with a fresh step-up, recorded in the audit chain. `ozbox clone` shows what the source can use
and what the clone will get; `--grant` and `--no-grant` work only within the policy. Orchestration workers follow the same rule.

```
Entry += { inherit: "none" | "ask" | { rule: Selector } }          // default "none"
EnvPolicy += { inherit_default: same, inherit_changed_by: Option<{person, at_ms}> }
```
The `secrets-e2e` suite clones a box under each policy and asserts what the clone can use, and restores a backup and asserts no
key comes back.

## Amendment 4 (owner, 2026-11-10): roles, rotation deadlines, inventory export, audit retention

**Roles** (like GitHub organisation roles), enforced **in the permission engine** (ADR 0022) as a scope on `Action::SecretUse` and
the secret-management actions, not by a parallel check:

| Role | May |
|---|---|
| Owner | everything, including Production policy, approvers, recovery and role changes |
| Admin | create, rotate and allocate in the projects and environments assigned to them; approve if named |
| Member | request; use through allocated commands; set plain values in `development` |
| Viewer | see names, versions and the audit; nothing else |

A role change needs a **fresh step-up** and is audited. `Role` is part of the engine's person record: `decide` receives the
person's role for the entry's project and environment.

**Rotation, per type: warn, then enforce.** Defaults: Production 90 days, staging 180, long-lived cloud keys 90 (with a nudge
toward short-lived credentials, Amendment 1); a warning 14 days before; **past the deadline a Production use needs an explicit
Owner override until the secret is rotated**; each secret may override its period.

```
Entry += { rotate_every_days: Option<u32>, rotate_due_ms: u64, overdue_override_by: Option<{person, at_ms}> }
```

**Inventory export.** Owner and Admin may export a CSV or JSON of names, environments, versions, labels, fingerprints,
allocations, rotation dates, last use, and who changed what: **never values** (and no fingerprint beside a low-entropy flag, Amendment 6 §12). Every export is an audit event
(`secrets.inventory.exported`).

**Audit retention.** Seven years. Recent entries stay local; the full trail is **archived to the user's own vault or bucket with
Object Lock** (the same Object Lock bucket as the session logs: one bucket, not two), configurable per installation. An
archived segment carries the chain's sealed checkpoint, so it verifies against the live chain (`ozbox audit verify --archive`).

### Additions to the test suite
A Member cannot create or allocate; a Viewer cannot use; a role change without a step-up is refused; an overdue Production key is
refused without the override; an export contains no value (a sentinel is searched for in every format); archived entries verify
with the chain.

## Amendment 5 (owner, 2026-11-10): GitHub access is the user's own GitHub App, minted per run by the broker

Runs reach GitHub through **the user's own GitHub App** (bring your own; nothing hosted by Oz Box) and the credential broker.
The App's private key is a secret of type `git_forge` held **by the off-box issuer** (Amendment 6 §11), never by the box's
service; the first draft kept it in the box's service, which was standing, organisation-wide access.
For each run the broker **mints a short-lived installation access token** (the App JWT exchanged at
`POST /app/installations/{id}/access_tokens`, with `repositories` and `permissions` set from the run's allocation, `contents`
read or write per repo, and expiry at most the run's approved window, never more than one hour). **No long-lived GitHub token is
ever on a box.** The run receives only the minted token, scoped to the repos and permissions its allocation names; a worker on a
clone gets none unless the allocation names it.

```
GitForgeEntry { type: "git_forge", provider: "github_app", app_id, installation_id, private_key_ref (vault),
                allocation.repos: Vec<{ repo: "owner/name", access: "read" | "write" }> }
TokenMint { repos, permissions, expires_ms <= approved window and <= 3_600_000 }   // audited: secrets.token.issued (type git_forge)
```
Tests use a fake GitHub (JWT verified with the App's public key, token request body asserted to carry exactly the allocated
repositories and permissions).

## Amendment 6 (security review, 2026-11-10, and the owner's decisions): an issuer that is not the box, a 15-minute window, and an honest promise

**Why this exists.** A security review of this record (2026-11-10, against the code on `main` and ADRs 0017, 0018, 0021, 0022,
0023, 0026 and 0028) found the design **unsound as first written and sound with fixes**. The core idea held: the command never
holds the key, one approval covers a short session, every decision goes through the one engine, and Production keys live in the
user's own vault. But four independent paths gave a prompt-injected agent running as the box user either the plaintext
Production value or a working authenticated Production session, and the design treated "the declared command" as a trusted
principal when its code, its arguments and its outputs all belong to the agent. This amendment fixes each finding in the
review's own order of dependence and states what we promise and what we do not. **Where it disagrees with the sections above,
it wins; the sections above are marked where they are replaced.** The finding ids (C1 to C5 Critical, H1 to H10 High, M1 to M10 Medium, L1 to L7 Low) are the review's own, and the review is kept privately. Every Critical and High finding is resolved here or deferred
with a reason (the table at the end); nothing is built until the owner says go.

### 1. The promise, stated honestly (replaces the threat-model paragraph)

> **Root on a running box gets at most what one approved session is using, for at most that session, and the audit chain
> records it. The box holds no credential and no role that can fetch a Production value on its own.**

This replaces the earlier aim of "no standing access even as root", which no design that runs the agent's machine can give. The
parts of that aim that remain true: a disk, a snapshot, a backup or a copied image yields no Production value; an agent running
as the box user can neither read a Production value nor use an authenticated session it was not approved for; an approval cannot
be minted, replayed, widened or relayed by anything on the box. What does **not** hold, and is said plainly:

- **The key is protected. The data the key can reach is exposed to the agent for the session.** An approved read-only session on
  a database lets the command read whatever its role can read, and its output returns to an agent whose own network is open.
  Egress rules cover the *command*, not the box user's shell. Only a box-wide egress list in `enforce` mode (ADR 0034) limits
  what leaves the box, and it is log-only by default. So the **least-privilege key is the control**, not the proxy (§10).
  **Accepted with limits** (the owner's decision, delegated to an advisor, 2026-11-10): the output of an approved Production use
  returns to the agent, and the **least-privilege role with an owner-signed allow-list** is the control; a Production
  declaration without one is refused (§10). Every approval card shows the role and its allow-list, the fixed sentence
  *"Whatever this role can read, the agent can read for the next N minutes and send anywhere"*, the box's egress mode, the
  output cap and the window. Routing the output to the approver instead of the agent is **not** offered as a control.
- **Root on a running box** can read the injector's memory while a use is in flight and can ask the issuer (§4) for releases the
  open approval still allows. It cannot obtain a value outside an approval, and cannot make an approval.
- **A person who approves something harmful**, the laptop of the person who approves (§9), the key's own vendor, and the
  vault account itself are out of scope.
- **GitHub access** (§11) is bounded standing access within an allocation, not a Production secret.

### 2. Close the instance-metadata path (part 1)

An agent running as the box user can reach the instance role through the metadata service today (a hop limit and a token
requirement do not stop a process on the machine). So the box's **metadata service is reachable only by root, the secrets user
and the uid that runs the interruption poller**, enforced by the kernel firewall (`meta skuid`, drop for everyone else), always
on and **independent of the box-wide egress list's mode** (ADR 0034): the earlier rule that accepted the metadata address for
every program is removed. The poller moves to a uid of its own if it runs as the box user today. A test asserts that the box
user's request to the metadata service is refused and the secrets user's is not. This also closes the standing read of staging
parameters by the agent, which was a defect before this ADR.

*Built (2026-11-11).* `ozbox host-guard metadata install` (first boot, and `reinstall-ozboxd` on an older box) loads a table of
its own, `inet ozbox_metadata`, at every boot before the box daemon and the box user's services: packets to `169.254.169.254`
and `fd00:ec2::254` pass only for root, `ozbox-secrets`, `ozbox-meta` and, where it exists, `ec2-instance-connect` (the account
Instance Connect looks keys up as); every other user's are dropped, and nothing forwarded (a container) reaches it. It is not
the egress list's table, so no egress mode loosens or removes it; that table's own exemption for the address now passes only
what this one has let through. The interruption poller moved out of the box daemon to `ozboxd interruption-watch`, run as
`ozbox-meta`, which leaves the notice in effect in `/run/ozbox-meta/notice.json` for the daemon to read. It applies on Hetzner
too, where the metadata service holds the first-boot configuration. The rendered table, the install and the hand-off are
tested in CI; the assertion that the box user's request is refused and the secrets user's is not needs a real kernel and
stays in the `--real-box` gate.

### 3. Delivery goes through an ingress account and is sealed end to end

- **An ingress account.** Everything a person or laptop sends to a box's secrets service (staging imports, a laptop-home
  release, signer enrolment) enters through a dedicated account, `ozbox-ingress`: root-owned home, `AuthorizedKeysFile` outside any
  user-writable directory, `Match User` with `ForceCommand /usr/local/bin/ozbox secrets receive`, `PermitUserRC no`,
  `PermitUserEnvironment no`, no shell. The box user's `~/.bashrc`, `~/.ssh/rc` and shell functions are no longer in the path.
- **Sealing.** Every payload that carries a value or a signature is **sealed to a service key** (an X25519 key made by the
  secrets service, HPKE or age) with the request's fields as authenticated data. The laptop and the issuer **pin the key's
  fingerprint** at enrolment, in the same gated `signer-enroll` step, and keep the pin in `ozbox`'s own state, not in `~/.ssh`.
  A process that relays the bytes (the box user's shell, anything on the path) sees ciphertext. This closes the staging import
  path as well.
- **The signed message names the box.** Every signature (laptop key, recovery key) covers the box id, the store id and the
  service key's fingerprint, so a signature cannot be replayed against another box in a fleet. The laptop **renders
  only what it signs**, from fields it has parsed itself.
- **No approval codes for Production**. A Production approval has no short code that a person types into a
  box-user process. The approval lives in the issuer; the agent can only poll its own request for "approved" (§6). Codes remain
  for laptop-to-service changes on ADR 0028's paths only.

### 4. The off-box issuer is the only principal that can read Production

**The box has no credential and no role that can fetch a Production value.** That replaces: the box-role read of a vault prefix
(Amendment 3), the unnamed "fetched just in time" fetcher (Amendment 1), the KMS-grant `sealed` key (§1 above), and the GitHub
App private key in the box's service (Amendment 5).

The one principal that can read Production is an **issuer in the user's own account** that `ozbox init` creates, plan-then-apply,
with the cost shown first:

- **On AWS** a small function (a Lambda), a state table with conditional writes, and a **separate KMS key for Production** whose
  policy admits only the issuer's role. **With OpenBao** a small sidecar on the OpenBao host. **Where there is neither** (an
  encrypted bucket only, a provider with no place to run one) there is **no issuer**, and Production works only with the
  `laptop` home. Production never falls back to a box-held key.
- **What the issuer holds.** The public halves of the owner's **passkeys**, **laptop signer keys** and **offline recovery
  key**; the pinned service key's fingerprint and **signing** public key of each box; the audit signing public key (§9); the
  owner's policy-signing public key (§10). It holds the GitHub App key (§11) and the keyed-hash secret for fingerprints (so an
  export cannot become an offline oracle).
- **The issuer makes and checks the challenge itself.** The box only relays. It issues a challenge for one request (§5), verifies
  the passkey assertion or the laptop signature against the keys it pins, and records the approval **in its own state**.
  **The box never mints an approval.** The supervisor relays and attests; it does not decide.
- **Release.** To release a value the issuer's base role does **not** read secrets. It **assumes a one-secret role** (a session
  policy naming one secret and one version) for at most 900 seconds, only after an approval check passes, reads the value with
  that session, and **seals it to the box's service key**. For a role-type secret (`credential: assumed_role`) the issuer assumes
  the target role with a session policy and seals the temporary credentials instead. The box's role is not involved.
- **Per use, not per window, for the vault home.** A **use is one launched command**. The service asks the issuer for the release
  each time; the issuer decrements `uses_left` and checks the window with a compare-and-set in its state, and the service
  decrypts into `mlock`ed memory, injects, and zeroizes when the command ends. The value is **not held between uses**, so "at
  most the seconds an approved use is in flight" is true again for the vault home. A restart of the service drops
  every in-flight session; that is fail-closed and fine.
- **The `laptop` home** (the value is in the laptop's keychain, no cloud vault) has no issuer: the **laptop is the issuer** for
  that entry. It verifies the same challenge locally, seals the value to the pinned service key and sends it through the ingress
  account. It works only while the laptop is online. The service holds the value in memory for the **session window** (at most
  15 minutes) and zeroizes it at the end, counting uses on the box; this is weaker than the vault home and is labelled so at the
  point of choice. **Passkey approvals work only with the vault home and its issuer; the laptop signer approves either.**
- **The box role is pinned in code.** The module's test fails if the box's role, instance profile or any policy attached to it
  carries `secretsmanager:GetSecretValue`, `kms:Decrypt` on the Production key, any vault write (`PutSecretValue`,
  `UpdateSecretVersionStage`, `DeleteSecret`, `DeleteObjectVersion`), or any read of a Production path; and a live check on a real
  box confirms the same by trying.
- **The issuer's own record.** It writes an append-only record of every challenge, approval and release in the user's account
  (CloudTrail-style data events and its own log, in the Object Lock bucket), **independent of the box's chain**. Root on the box
  cannot suppress it.

### 5. What an approval binds, and how the run is attested

**Production commands are exact.** A Production declaration must give a **non-empty argv**; an appended argument is refused (a
declared argument schema may allow named, typed arguments, never free ones). Production runs with a **clean environment**
(allow-listed variables only, `HOME` an empty directory, `PATH` root-owned directories only), so `NODE_OPTIONS`, a user `.npmrc`
or a shell startup file cannot reach it.

**An immutable copy, not the live checkout.** When a request is made the launcher makes a **root-owned, read-only copy** of the
named commit (`git archive`), runs the command's declared `prepare` step in it if there is one (no secret, egress only to the
declared registry), and computes a **directory digest** of the result. The command runs from that copy. The agent's edits to
`/work` between approval and use, and between uses, change nothing the command runs.

**The approval binds** `{box id, store id, service key fingerprint, project, env, command, argv, directory digest, commit SHA,
stdin digest, key names, request id, run}` and the card shows them, with a **diff since the last approved run of that command**.
A branch name is never the binding (the agent can push to a branch): `allowed_branches` is a label the approver sees unless the
forge reports the branch as protected, and the binding is the commit SHA. Any change in what the command would run makes the
issuer refuse the use and ask for a fresh approval.

**The run's identity is attested, not asserted.** A use request carries no engine, run kind, person, command or label that the
service believes. The service takes the caller's process identity from the kernel (`SO_PEERCRED`, then its **cgroup**), and the
**supervisor attests** `run → {engine, run kind, person, box, started, commit}` from its own records over its own socket (the
cgroups are not delegated to the box user, so a process cannot claim another run's). No bearer token an agent can read from
`/proc/<pid>/environ` is involved. The card marks every field an agent chose as such (the command's *name* and its *reason*),
and shows the attested fields as attested.

**Allocation by engine or run kind is advisory for Production until runs have separate uids.** Runs of one box share the box
user, so one agent can observe another's process. Until each run is its own uid, Production allocation is enforced by **box,
command, person and environment**; engine and run kind are shown and recorded but are not a boundary, and the console says so.
Per-run uid separation is a later hardening; when it ships, allocation by engine becomes a control.

**Labels and groups are not request arguments**. The labels and groups that allocation and `inherit: rule` match on
are set only by an Owner or Admin with a fresh step-up, signed (§10), and copied from the box's **creation provenance** (who
made it, under which policy). A conductor agent that creates a clone cannot give it a label that matches a rule.

**Request hygiene.** At most one pending request per run and command, a small cap on pending requests per box, and an
exponential backoff after a refusal, so the inbox cannot be flooded into approval fatigue.

### 6. Approving: the window, renewal, and who can (owner decisions)

- **The window is 15 minutes, at most.** The `ttl` ceiling in the contracts is **900 000 ms**. The default is 15 minutes and 10
  uses (Amendment 3); an environment may lower either and never raise the window. The 4-hour and 30-minute ceilings are gone. A
  long-lived cloud key halves the window, as Amendment 1 said.
- **A renewal is a fresh approval.** It goes through the issuer, is **re-bound to the current commit and directory digest**, shows
  the diff since the last approval, and resets the counters. It is never an automatic extension, and the audit records it as a
  renewal of the one before.
- **Who can approve.** Only a dashboard **passkey** (including the phone PWA) verified **by the issuer**, or the **laptop signer**.
  The supervisor does not verify anything for Production. The requester cannot approve their own request when someone else is
  listed (Amendment 2, unchanged).
- **Chat cannot approve Production** (owner decision). Chat, push, email and the alert channels **notify** with a one-time link
  that opens the dashboard approval page, and chat offers **Deny only**. ADR 0021 item 5 and ADR 0026 item 8 stand unchanged;
  Amendment 2's reversal of them is withdrawn. The TOTP safeguard, `chat_requires_totp` and the `chat*` values of `Approval.via`
  are gone.
- **Break-glass is one mechanism and is not renewable.** The **offline recovery key** (an Ed25519 key the owner keeps offline;
  only the public half is stored, with the same box-binding as §3) can approve when the usual approvers cannot. It alerts every
  channel, caps the session at 15 minutes and 3 uses, **cannot be renewed**, and is flagged for review until a person
  acknowledges it. The separate "recovery approver" of Amendment 2 is removed.
- **The lockout cannot be turned against the owner**. Wrong-answer counters are **per request and per scope**, with
  exponential backoff; person-originated paths (the dashboard's supervisor socket, a signed laptop request) are **outside the
  box-socket budget**; and a challenge is spent **only by a valid signature**, never by a wrong answer. The box user cannot
  deny approvals by spamming the import socket.
- **Production is refused in bootstrap**. Until a second factor is enrolled, a Production `secret.use`, a Production
  declaration, an approver list, an `EnvPolicy` loosening, a role change or an overdue-rotation override is **refused**, not
  recorded as `bootstrap`. Enrolling the factor itself stays possible. A test pins every one of these. The entropy source for the
  gate's keys **fails closed**: a failed random read refuses to start the gate, never a key of zeros.

### 7. The proxy and the database listener

**Reachability is the kernel's job, not a password's.** The injection proxy and the database listener are **Unix sockets** under a
root-owned `0700` directory, bind-mounted **only into the run's own mount namespace**, and the run is started with its own
**network namespace** (`PrivateNetwork=yes`) in which a small relay turns the sockets into the loopback addresses ordinary clients
expect. A process outside that run, including the box user's shell and another run of the same project, has **no path** to
either, whatever it knows. libpq may also be pointed at the socket directly (`host=/run/...`). Today's TCP loopback listener
(ADR 0023 item 3) is replaced, not supplemented, for any destination with an injection rule; ADR 0023's reasoning that "another
process could use the listener" held only because the listener held no credential, which this ADR changes. The proxy password is
added to the redaction set and the command's environment is still treated as agent-visible.

**HTTPS injection (Production rules; development and staging keep the looser forms and say so):**
- injection only on an **exact hostname**, never on a wildcard egress rule; **no query-parameter injection**; header only;
- every request is **re-serialised** by a strict parser: refuse `Transfer-Encoding` together with `Content-Length`, refuse obsolete
  line folding, one request per upstream connection; ALPN forced to `http/1.1`; refuse `TRACE`, `Upgrade` and a `CONNECT` inside
  an injected connection; SNI, `Host` and `:authority` must all equal the declared host; the proxy **never follows a redirect**;
- **upstream responses are scrubbed**: the injected value and its exact, base64, hex and URL forms are removed from response
  headers and bodies (`Accept-Encoding: identity` is sent upstream and a compressed response is refused), a hit is replaced and
  counted, and the response size is capped. This is the real control against a vendor that reflects the credential (a `Location`
  header, a pagination link, an error body that quotes headers);
- the header the command set under the injected name is removed (as before); the destination host of a connection-string secret
  must equal the declared host, or the use is refused.

**Postgres (kept, hardened; Postgres is not deferred):**
- **the listener builds the startup message itself** from the declaration: user, database and `application_name`. It drops every
  client-supplied parameter except a short allow-list, refuses `replication`, and refuses `options`, so a client cannot choose a
  tenant (a pooler that picks the tenant from the user name) or override a default;
- upstream authentication: **SCRAM-SHA-256 with channel binding where the server offers it**; cleartext or MD5 only after
  `verify-full` TLS to the declared host;
- the parser follows **message framing** (it counts `Query` and `Parse` messages and bytes for the caps) but does not read SQL;
- **read-only is the database role's job, not the listener's.** `default_transaction_read_only=on` is sent as hygiene and the ADR
  no longer claims the listener can enforce it, because a client can override it in SQL (`BEGIN READ WRITE`,
  `set_config(...)`, inside a `DO` block, in an extended-protocol message);
- **the role is linted, and for Production the lint is a refusal** (§10): not a superuser; none of `pg_execute_server_program`,
  `pg_read_server_files`, `pg_write_server_files`; no usable `dblink` or `postgres_fdw`; otherwise the database server itself
  can send data out, bypassing every control on the box.

**A "use" is one launched command**: within it the number of connections, requests and statements is capped at the
framing level; one keep-alive connection is not one use among ten however many things it carries.

**Other protocols are refused for Production**, not offered raw-with-warning. A Production key for MySQL, Redis, SSH or anything
else has no delivery until its `Upstream::authenticate` exists and has been through this review. **Raw delivery of a Production
key is removed**; `raw_env_allowed` is empty for Production and the contract refuses a non-empty one.

**Redaction and the barrier cover only values the box holds**: a value that is not on the box outside a use cannot be
matched in a diff. Redaction keeps the exact, base64, hex and URL forms as hygiene; the reversed, separator-inserted and
other exotic forms of Amendment 1's and §4's list are **dropped**, because for an injected key the command never holds the value
and agent code can apply any transform to anything else. The redaction report does **not** say which name matched or where (so it
is not an oracle a command can probe a weak value with), and a **low-entropy Production value is refused at declaration**.
The DNS resolver of §4 is **removed**: the runner already has no DNS (`IPAddressDeny=any`; the proxy resolves),
and nothing the runner can query is added.

### 8. Rotation, recovery and the vault's own safety

- **Rotation never gives the command the new value**. A rotation runs **inside the issuer, or as the provider's own
  rotation** (a Secrets Manager rotation function), with built-in rotators per vendor, never as an agent-runnable "rotation
  command" for Production. The box and its commands have **no vault write**; every new version, label move and soft delete is
  made from the laptop or by the issuer under the owner's signature. The Amendment 1 sentence about a declared rotation command
  applies to development and staging only.
- **Policy records are signed**. See §10.
- **Backends are phased** (the cut). **AWS Secrets Manager ships first** with the full lifecycle (versions, labels, soft delete,
  native rotation). **OpenBao and the encrypted object store ship with current-value put and get plus owner-signed records**;
  labels, soft delete and rotation hooks on them follow. The `SecretBackend` trait is split into a **reader** (used only by the
  issuer) and a **writer** (used only by the laptop and the issuer): **the box's build has no implementation of either.**
- **The encrypted object store has a recovery recipient**: an offline age/X25519 recipient in addition to the user's
  key, so a lost laptop loses nothing (the Ed25519 recovery key cannot decrypt). The authenticated data binds
  `{name, version, env}`, so an object cannot be swapped between names or rolled back by relabelling. Object versioning plus Object
  Lock make versions real, and `s3:DeleteObjectVersion` is denied to everything on the box. Secrets Manager drops unlabelled
  versions beyond its limit, so `PREVIOUS` history is bounded; the docs say so.

### 9. The store, backups and the audit trail

**H8: the store and its key (resolved in design).** The persisted copy of the secrets store and, on a file-KEK box, `kek.key`,
was refreshed into `/work/ozbox-secrets-private` every thirty seconds (ADR 0028 item 6), and `/work` is what the daily snapshot,
a clone and the restic backup all copy. On a file-KEK box that meant **every snapshot and backup decrypted the whole store**:
staging keys, the audit seal key, tunnel and backup credentials, model keys, the internal-token key. The change:
- **`kek.key` is never copied to `/work`.** The persisted copy of the store on `/work` is ciphertext under a key that is not on
  `/work`; with KMS the instance role is also needed (and is metadata-restricted, §2).
- **`/work/ozbox-secrets-private` is excluded from restic**, as a second line.
- **The key is escrowed off the box** (the owner's decision, delegated to an advisor, 2026-11-10): in the vault, under the box's
  own path, fetched back by the secrets service through the box-secrets credential; otherwise in the laptop keychain, put back
  by `ozbox upgrade` through the ingress account (§3). So ADR 0028 item 6's "upgrades keep the store" **holds through the
  escrow**. A box with **no escrow** that loses its system disk recovers from the vault: its own secrets come back from there,
  anything that lived only on the box (a tunnel credential, a backup credential) is re-entered, and the audit signing key is
  re-made as a new epoch (below). Production records are allowed on file-KEK boxes; KMS or a TPM is recommended. (What is built
  is Amendment 7.)
- **Residual limit:** a copy of the **system volume** of a file-KEK box (a hand-made image of the root disk) includes the key and
  therefore the store's staging values. Production values are never in the store, so Production is unaffected. A box-image bake
  generates the key at first boot and carries none. This is documented as the reason to prefer KMS or a TPM.

**H10: the audit trail fails closed for Production.**
- `secrets.use.requested`, `.approved` and `.started` for a Production entry must be **written to the chain before the use
  proceeds**: no chain line, no use. (Staging keeps best effort.)
- **The chain's directory is on a filesystem of its own** (a small dedicated volume, or a loop-mounted file on the system disk),
  with a free-space floor below which a Production use is refused, so filling `/work` cannot suppress the record.
- **Checkpoints are signed with Ed25519**, not sealed with a shared HMAC key, and the **public key is pinned off the box** (in the
  issuer's configuration and the vault). Whoever can verify a segment can no longer forge one. A rebuilt box starts a new epoch
  whose first checkpoint names the old one.
- **Every checkpoint head is shipped promptly** (within a minute, not only on archive) to the Object Lock bucket by a box role that
  has `s3:PutObject` on the audit prefix and **no** `BypassGovernanceRetention` or `DeleteObjectVersion`; verification reads
  **all object versions**, so a forged later version cannot shadow the real one. A root rewrite between anchors is then caught
  against a head the box could not have changed, and the issuer's own record (§4) catches a use the box did not log.

**M1: the laptop signer.** The signer's key lives in the **Secure Enclave or a FIDO2 key with user verification** where the
laptop has one, and an approval **prompts the person with the exact request**; where there is none (a software key in the
keychain), any process of the laptop user could sign without a prompt, so the signer says so, shows the approval as
`laptop-key (no user presence)` and **the console refuses it for Production, with no override** (Amendment 9 §4). The laptop is **in the threat model**
whenever agents also run on it (the box alias and `known_hosts` are user-writable there); the pinned service key (§3) is what
stops a redirected alias from receiving a value.

### 10. Signed policy, and the least-privilege lint as a refusal

- **Every policy record is signed** by the owner's **policy key** (the laptop signer key, or issuer-attested): allocation,
  approvers, protection rules, `inherit`, `raw_env_allowed`, `EnvPolicy`, and the labels and groups of §5, plus label moves and
  soft deletes. The signature is checked on load, on `recover`, and by the issuer before a release; **an unsigned or invalid
  record is quarantined and a Production entry with one is refused**. Anything that could write the vault prefix can no longer
  plant a looser policy that a recovery would adopt. The e2e vault runs with **real policies, never dev-mode root** (dev mode
  proves nothing about what the box can do).
- **The least-privilege lint (§5) is a refusal for Production**, not a warning, when the role can read tables outside an owner
  allow-list, is a superuser, or holds the server-program, server-file, `dblink` or `postgres_fdw` powers of §7; and the lint
  runs again whenever the declaration changes. Production declarations also **refuse `writable` paths** (a command's files
  are read back by the agent) and **cap output bytes small**. A Production declaration **without an owner-signed allow-list is
  refused** (H3, decided: §1). Output goes to the agent; routing it to the approver is not offered as a control.
- **The recipes ship in the docs** (a read-only role, grants by table, a schema of views that omit sensitive columns), because
  the role is the only control that limits what the exposed data is.

### 11. GitHub, and the App key

The GitHub App's private key is held **by the issuer** (or by a KMS asymmetric key only the issuer may `kms:Sign` with), never
by the box. The box's service asks the issuer for a token for a run, naming the run's attested identity; the issuer mints the
installation access token under the allocation's repositories and permissions (at most the approved window and at most one
hour) and **seals it to the box service key**. GitHub access is therefore **standing within the allocation, bounded to
one-hour tokens, and says so**; it is not a Production approval and is not claimed to be one. **Never granted:** `workflows`,
`actions`, `secrets`, `administration`, `environments`. **Write** only to branches that are not protected on the forge; a
repository whose workflows hold Production secrets needs GitHub's own environment protection, and the docs say so.

### 12. Smaller findings and what is cut or deferred

- **Contract hygiene**. `Allocation.people` empty means **none** (it said "any person"); one TTL
  ceiling everywhere (900 000 ms); reviewers and approvers are not both specified (one approval is enough; reviewers are
  deferred); the gate's key fails closed; fingerprints use a key the issuer holds and are never exported beside low-entropy
  flags; the **injector** (the root launcher or service process, not only the runner) gets `LimitCORE=0`, `PR_SET_DUMPABLE=0`,
  `MemorySwapMax=0`, `mlock`ed buffers and no `Debug` or panic path that prints a zeroizing buffer to the journal.
- **Applied cuts** (the review's over-engineering list): the redaction encoding suite is trimmed (§7); the DNS resolver is
  deleted (§7); `sealed_grant` is deleted (§4); the full lifecycle is phased, Secrets Manager first (§8); Postgres and HTTPS
  only, with other protocols refused for Production (§7); one break-glass mechanism (§6); chat approval deleted (§6); required
  reviewers and wait timers are **deferred** until an installation has more than one approver (the fields are reserved and
  refused when non-zero) rather than cut, because the owner chose them as optional rules; **inventory export stays CSV or JSON**
  because the owner chose both; four notification channels stay, as **notification only** (§6).
- **Not built here, deferred by the owner's decision or by dependency:** a hardware user-presence requirement for every laptop
  signer (the default refuses a no-presence key for Production, §9); per-run uid separation (§5); routing Production output to the
  approver (§10).
- **Calls in the old text that this amendment removes:** the sealed home, the box-role vault read, the chat approvals and their
  TOTP, the recovery approver, raw delivery of a Production key, the DNS resolver, the 4-hour and 30-minute ceilings, and the
  GitHub App key in the box's service.

### Contract changes

The shared contracts above are rewritten to match; in summary:

```
Entry.home        ::= "box_sealed" (development, staging only) | "laptop" | "vault"        // "sealed_grant" removed; production: laptop | vault
Entry            += { policy_sig }                                                          // §10, over the record, never the value
Allocation.people : empty = none                                                            // was "any person"
Allocation       : labels and groups come from signed BoxProvenance (§5), never from a request
Injection         : { host: exact hostname (production), header, scheme, key }              // no query form, no wildcard, for production
EnvPolicy         : production.raw_env_allowed = []   production.session_minutes <= 15
ProtectionRule    : - reviewers, wait_minutes (reserved, refused if non-zero)   - chat_requires_totp
Approval          : minted and held by the issuer (or the laptop issuer); the box holds a handle only
Approval.scope   += { argv, directory_digest, commit, stdin_digest, box_id, store_id, service_key_fp, run (attested) }
Approval.via     ::= "passkey" | "laptop-key:<id>" | "recovery:<id>"                        // chat* removed
Approval.ttl_ms   <= 900_000                                                                // the one ceiling
RunAttestation    { run_id, cgroup, engine, run_kind, person, box_id, started_ms, commit }  // supervisor-signed; the service verifies
SecretBackend     : reader (issuer only) and writer (laptop and issuer only); no box implementation
```

### Additions to the `secrets-e2e` and adversarial suite

These are required, in addition to the lists above, and each attack must fail with a named reason. Items marked (real box) also
run in the `--real-box` gate, because users, sshd and the metadata service differ there.

1. **Delivery and transport.** A box-user `~/.bashrc` function or wrapper on `/usr/local/bin/ozbox`, and `~/.ssh/rc`, during
   `register` and during a use's delivery: no plaintext sentinel captured. Read `/proc/<receive pid>/fd/0` while a delivery is in
   flight. A relayed sealed payload is unreadable. (real box)
2. **Listener, proxy and instance role.** The box user connects to the database listener and to the HTTPS proxy during a session:
   refused. A command prints `$HTTPS_PROXY` and the box user uses it: refused. Another run of the same project cannot reach the
   sockets. The box user's metadata-service request is refused; with the role's own credentials, `GetSecretValue` on a Production
   ARN and `kms:Decrypt` on the Production key are refused (a module test and a live check). (real box)
3. **Identity and binding.** Use requests that spoof `engine`, `run_kind` or `person`. A second concurrent run stealing the first
   run's identity from `/proc/<pid>/environ`. Appended argv on a Production command. A modified script between approval and use,
   and between uses. A commit SHA or directory-digest change during a session (a fresh approval is required). `NODE_OPTIONS` and a user `.npmrc`
   set by the box user are not seen by a Production command.
4. **HTTPS proxy.** A query-parameter injection reflected via `Location`, a `next` link or an error body (refused for
   Production; scrubbed where allowed). `TRACE`. A `Content-Length` plus `Transfer-Encoding` smuggling pair. h2 coalescing to a
   sibling host. A wildcard rule pointing at an attacker subdomain. A gzip response carrying the key. SNI, `Host` and `:authority`
   mismatch. A redirect to another host.
5. **Postgres.** `BEGIN READ WRITE`, `set_config(...)`, and `SET` inside `DO`. A startup `options=-c ...`. `replication=database`. A
   different `user` or `database` (a pooler tenant switch). An upstream that asks for cleartext without TLS. `COPY ... TO PROGRAM`
   and `dblink` from a role the lint should have refused. The statement cap on the extended protocol.
6. **Approvals.** Bootstrap mode: a Production use and a Production policy change are refused. A global-lockout attempt: the
   person's approvals still work while the box user spams wrong codes and burns challenges. A cross-box relay of a laptop
   signature. A laptop signer invoked without user presence (must prompt, or be shown as no-presence and refused for Production).
   Approval-request flooding is rate-limited and de-duplicated. **Chat**: a chat message can never approve; the one-time link
   opens the dashboard; an agent-printed fake approval card cannot be approved; chat offers Deny only. A renewal re-binds to the
   current commit and resets the counters; break-glass cannot be renewed.
7. **Data at rest.** A sentinel in the store is absent from a restic snapshot and from a `/work` disk snapshot on a file-KEK box,
   and `kek.key` is not under `/work`. The vault: the box's token or role cannot write versions or labels or soft-delete. A tampered
   policy record is refused on `recover`. The e2e vault runs with real policies. (real box for the snapshot case)
8. **Audit.** `/work` filled to 100 percent: a Production use is **refused** (fail closed) and a staging use still runs. A forged
   archive object version is detected. A use the box did not log is visible in the issuer's own record.
9. **Writes and data.** A rotation never gives the command the new value; the box cannot write `PENDING`. Production command output
   written to `/work` is refused (no writable paths); the output cap is enforced; the redaction report names no value.
10. **Allocation.** A clone created by the conductor with a self-chosen label gets nothing.
11. **The issuer.** A passkey assertion for another request, an expired challenge, a replayed assertion and a use after `uses_left`
    is zero are all refused by the issuer, whatever the box relays; the issuer's base role cannot read a secret without a
    one-secret session; a use with the box's service key unpinned is refused.
12. **Browser (out of scope here, see the open list).** The check that `Runtime.evaluate` on a filled password field is refused or
    impossible belongs to the browser credentials record, not to this suite.

### The review's findings, one by one

| Finding | Resolution |
|---|---|
| C1 JIT delivery ends in a box-user process | Resolved: ingress account plus end-to-end sealing to a pinned service key (§3) |
| C2 The Postgres listener is an unauthenticated loopback port | Resolved: Unix sockets bind-mounted into the run's own mount and network namespaces (§7) |
| C3 The proxy's only gate is a printable password | Resolved: same as C2; password also redacted (§7) |
| C4 The agent reaches the instance role through the metadata service; the box role can read Production | Resolved: metadata restricted by uid (§2); box role pinned to have no Production read or vault write (§4); `sealed_grant` deleted (§4) |
| C5 A passkey approval had no path that is not standing access; the App key sat on the box | Resolved: the off-box issuer (§4, §11), including the owner decision for a 900-second window |
| H1 The approval bound a command name, not what runs | Resolved: exact argv, immutable root-owned copy, commit and directory digest bound, a diff on the card (§5) |
| H2 The authority in a use request was self-asserted | Resolved: kernel identity plus supervisor attestation; engine and run kind advisory until per-run uids (§5) |
| H3 "Production data cannot leave" is false | **Accepted with limits** (owner, delegated, 2026-11-10): stated plainly in the promise (§1); the signed least-privilege allow-list is the control and a declaration without one is refused; the card says what the agent can read and send (§10) |
| H4 Upstream responses can reflect the credential | Resolved: exact host, no query injection, strict re-serialisation, response scrubbing (§7) |
| H5 The listener's read-only control was unsound and startup parameters were the client's | Resolved: listener builds the startup message, SCRAM-PLUS, framing counts, role lint as a refusal; read-only is the role's job (§7) |
| H6 Bootstrap mode was not excluded | Resolved: Production refused in bootstrap, with a test (§6) |
| H7 Rotation commands held the new value | Resolved: rotation in the issuer or provider-native; the box has no vault write (§8) |
| H8 Snapshots and backups contained the store and its key | Resolved (§9): `kek.key` off `/work` and escrowed off the box, restic exclusion; the owner accepted the consequence for a box with no escrow (it recovers from the vault). Built in Amendment 7, except the laptop-keychain escrow |
| H9 The recovered policy records were unsigned | Resolved: owner-signed records, checked on load and recover (§10) |
| H10 Audit of use was best effort and suppressible | Resolved: fail closed for Production, a filesystem of its own, Ed25519 checkpoints pinned off the box, prompt shipping, the issuer's own record (§9) |

| Medium or Low | Resolution |
|---|---|
| M1 The laptop signer is a confused deputy; signatures relay across boxes | Resolved in part: box, store and service-key bound in the signature, pinned state, user-presence key where there is one; a hardware requirement is deferred with the reason in §9 |
| M2 The wrong-code lockout lets the agent deny approvals | Resolved (§6) |
| M3 Approval codes are bearer strings through the attacker's uid | Resolved: none for Production (§3) |
| M4 Chat approval contradicts ADRs 0021 and 0026 | Resolved: chat cannot approve (§6) |
| M5 "A use" was undefined | Resolved: one launched command; per-use release for the vault home (§4, §7) |
| M6 Labels and groups were agent-settable | Resolved: signed, from provenance (§5) |
| M7 The barrier and redaction cannot see off-box values; the redaction count is an oracle | Resolved: stated; no name or position reported; low-entropy values refused (§7) |
| M8 Browser autofill is outside this record | **Open**: needs its own record |
| M9 The GitHub App token scope can reach CI secrets | Resolved: forbidden permissions, branch rule (§11) |
| M10 Backend durability gaps | Resolved (§8) |
| L1 to L7 | Resolved (§6, §7, §12) |

### Owner decisions still open

- **M8.** Browser autofill and sealed browser profiles need their own record (a browser as its own uid, the debugging
  protocol held only by the tool host, fill only on the declared origin, no dashboard step-up from the box's own desktop).

*(Decided 2026-11-10, delegated to an advisor: **H3** accepted with limits, §1 and §10; **H8**'s consequence accepted with the key
escrowed off the box, §9.)*

## Amendment 7 (2026-11-10): what of Amendment 6 §9 is built, after a security review of the code

A security review (2026-11-10) of the code merged that day found that §9's H8 change was in the design only: the key file of a
file-KEK box was still copied to `/work` every thirty seconds and nothing left the folder out of a backup. Built now (ADR 0028,
Amendment 1, has the rest of the review's fixes):

- **`kek.key` is never copied to `/work`.** A copy an older version left there is used once, at the upgrade that brings this
  version (the box that made it already had it there), and then overwritten and removed; a save removes one that appears again.
  A store whose key file is missing is never given a new key.
- **Escrow in the vault**, for a box whose own secrets are on OpenBao with a token: the loader (which holds the token, the box
  user never does) puts the key at `<box secrets path>/_escrow/<box>` (KV version 2, field `kek`, the value on standard input
  only), and the secrets service, given the same root-only credential by systemd, fetches it back when a replaced system disk
  has the store but not its key. The token's policy must allow create, update and read on that one path.
- **No escrow:** the service stops `not-ready` (exit 78) with the reason, and `ozbox secrets recover-store`, run as root, sets
  the unopenable store and its `/work` copy aside (renamed, never opened) so the next start makes a new store (the root helper
  does not offer it as an action yet). While a file-KEK
  box with no escrow is running, `ozbox secrets status` says that an upgrade will start a new store. An escrow that does not
  answer (the vault down, or the token not yet placed again after a rebuild) is retried, not treated as configuration.
- **Restic:** every backup leaves out `/work/ozbox-secrets-private` whatever the settings say, no restore puts it (or the audit
  chain) back, and the secrets service refuses a restic command of any other shape.
- **Clones and restored disks:** a copy of the store on `/work` that belongs to another box (its scope says so) is removed,
  not restored. A disk snapshot or a clone cannot leave a folder out; what keeps the store unopenable there is that its key is
  not on `/work`.

**Not built:** the laptop-keychain escrow put back by `ozbox upgrade`. Without the ingress account of §3 every route from the
laptop into the box passes through a process of the box user, which could keep the key; so a box with no vault has no escrow
yet, and starts a new store when its system disk is replaced. On AWS, escrow through the box role is not offered either: the
agent reaches the instance role's credentials until the metadata restriction of §2 is built. KMS or a TPM remain the
recommendation. Nothing here is proven on a real box.

## Amendment 8 (2026-11-11): an upgrade says what happens to the store, and a recovery needs the service's word and the owner's key

A security review (2026-11-11) of the merged code found three things about Amendment 7 that a real box would meet after this
release:

- the **second** upgrade of a default box (a file-kept key, no escrow) started a new, empty store, and `ozbox upgrade` said
  nothing first;
- `recover-secrets` could be asked for by the agent, and on a KMS or TPM box whose key service was down long enough for the
  service to stop, it would set a healthy store aside;
- a fresh store after a recovery enrolled again a pinned key its owner had revoked.

What changed:

- **The service says what protects its store, in words a program reads.** Its state file
  (`/run/ozbox-secrets/state`) keeps the sentence for a person on its first line, and adds `kek=` (`kms`, `tpm2`, `keychain`,
  `passphrase` or `file`), `escrow=` (`vault` or `none`, for a file-kept key) and, when not ready, `code=`: `no-escrow` (the
  store is there and its key is not, with no copy anywhere), `config` or `transient`. Nothing decides on the sentence.
- **`ozbox upgrade` asks first.** Before anything is replaced it reads that state over the box's route, and every plan says
  the store's fate: kept (KMS, TPM, passphrase), kept through the vault's escrow, kept once (an older box that does not say,
  whose file-kept key still has a copy on `/work`), already unopenable, or lost. A store that would be lost, one that already
  cannot be opened, or a box that cannot be asked (not running, not answering), is refused, with the two ways forward: escrow the key first (box secrets on
  OpenBao with a token, or the fleet's KMS key for a new AWS box), or `--accept-new-secrets-store`, which lists what must be
  entered again and, after the reboot, sets the old store aside with this computer's pinned key before the restore steps put
  the backup credentials and the web IDE's tunnel token back into the new one. The dashboard's upgrade asks the same and
  takes the same acceptance (`accept_new_secrets_store`). The box answers through the box user's own shell, so an agent could
  make the answer say "kept"; that costs only the store the agent's own box would lose, and the refusal never depends on the
  agent to happen.
- **An AWS box can have no key file at all.** With `secrets_key_arn` and `fleet` set under `[aws]` (the `aws-secrets-key`
  module's outputs), `ozbox create` gives a new box the fleet's KMS key; the box's role may use it only for that box's own
  secrets (the encryption context names the box), so this widens nothing ADR 0018 did not grant and reads no Production
  value. The key rides the box's labels, so every later upgrade gives the new machine the key the store was sealed with,
  whatever the configuration says then: a file-kept store never comes back on a machine told to use KMS, or the reverse.
  The CLI does not create the key; `ozbox init` does not make one yet.
- **A recovery needs the service's word.** `recover-secrets` runs, as root, only when the service's own state file (a plain
  file owned by the secrets user, writable by no one else, in a folder only that user or root can write, never through a
  link) says `code=no-escrow`, `kek=file`, `escrow=none`; the service's settings choose a file-kept key; the key file is
  absent; and the unit last stopped with the exit code the service uses for that (78) and is neither starting nor running.
  A KMS or TPM box never writes `no-escrow` (its key-service failures are retried and exit 1), so a box between restarts, or
  one whose key service is down, is refused whatever its state file says.
- **And the owner's approval, made off the box.** The service is down, so it cannot spend an approval; the root helper asks
  for a one-time challenge bound to the digest of the exact store it would set aside, and accepts only a signature of it by
  the key pinned when the box was made (root-owned `/etc/ozbox/approval-keys`). `ozbox admin <box> -- recover-secrets` on
  that computer does both steps. A box with no pin can be recovered only from the machine's own console, as root
  (`ozbox secrets recover-store --console`).
- **A declared vault without its token is waited for.** A rebuilt system disk loses a vault token placed by hand (on
  Hetzner), and the service read "a vault is declared and its token is not here" as "no escrow", which would have let its
  store be set aside. It now waits, saying to place the token again; only a box that declares no vault is `no-escrow`.
- **A revoked pin stays revoked.** A revocation of the pinned key is also recorded on `/work`, beside the store's copy, in a
  file the secrets user owns; a store started anew after a recovery does not enrol that key again, and it cannot approve a
  recovery either.
- **Hetzner keeps the first-boot configuration a server was made with.** Hetzner runs a server's original user data again on
  a rebuilt disk and its rebuild takes only an image, so an upgrade there brought the new image's programs but not this
  release's root helper, setup scripts or pinned approver. The plan said so. *(This was the state when this amendment was
  written. The follow-up below replaces the rebuild with a replacement, which does deliver them.)*

**Follow-up built (2026-11-11, later): a Hetzner upgrade replaces the server, so the new first-boot configuration is delivered.**

The last bullet above named a follow-up: Hetzner keeps a server's user data for its life and a rebuild takes only an image, so an
upgrade there never brought a release's root helper, setup scripts, units or pinned approver. `ozbox upgrade` on Hetzner now
does what it does on AWS (the checked replace of the machine through OpenTofu), so the follow-up is built.

- **The upgrade is `tofu apply -replace=hcloud_server.box`** with the new image id and the box as it is now (its type after any
  resize, its disk after any growth, its labels, its pinned approver). The server is destroyed and created again from the
  current module: the new image **and the new first-boot configuration**. The module still ignores a changed image or user data
  outside an upgrade (a changed first-boot text must not plan a replacement on its own, and Hetzner cannot return a server's user
  data, so a server brought back by `ozbox adopt` would otherwise plan one); `-replace` builds from the current values, and a
  module test holds both.
- **`/work` is kept.** It is a separate volume nothing depends on. The upgrade plans first, read-only, before anything is
  stopped, and refuses unless the plan replaces the server, may also replace only the volume attachment, and neither deletes,
  replaces nor creates the volume. The plan is made again right before the apply, so what is applied is what was just checked.
  The volume's two upgrade labels (the image going to, and the type the box ran) are ignored by the module, so an apply neither
  strips nor re-adds them.
- **An interrupted upgrade is recoverable, as on AWS.** The old server is removed before the new one is created. If Hetzner
  cannot create the new one right then (a dedicated type out of stock in the location, a project limit), the create is retried a
  few times with a pause. If it still fails, `/work` is safe, the box has no server and shows as `instance missing`, and
  running the same `upgrade` again creates the server and attaches the volume. The upgrade mark lives on the **volume's** labels
  because the server it marks is the thing that is replaced.
- **The checks around it are the shared ones.** Before anything is replaced the plan says the secrets store's fate (kept, kept
  through the vault's escrow, kept once, already unopenable, or lost), refuses a store that would be lost or a box that cannot be
  asked unless the person accepts a new one. The image is checked
  to exist, to be available and to match the box's architecture. Hetzner has no signed-release list here, so `--image` takes an
  id.
- **What changes for the person.** The server gets a **new address** (a Hetzner server's public address belongs to the server;
  nothing connects in, so only an allow-list on the other side of an outbound connection would notice). A vault token placed by
  hand on the old system disk is gone and is placed again (`place-bao-token`), as it already was after a rebuild. A box with no
  pinned approver gets this computer's key in its new first-boot configuration, as on AWS.
- **A box made before this release** gets this release's root helper, setup scripts and units through its next upgrade, which
  answers the follow-up in ADR 0023 Amendment 1 (the dashboard install on an old Hetzner box).

Nothing in this amendment has run against Hetzner: the tests run the real planning and the real safety checks against a
simulated Hetzner API and a simulated `tofu`, and the module's tests prove that a replacement builds the server from the current
configuration while the volume's id stays known. **Only a real upgrade shows** that Hetzner accepts the replacement as planned
(the attachment, the new address, the first boot on a volume that already holds a filesystem) and that a failed create leaves the
box listed as missing.

**Not built.** The laptop-keychain escrow is still not built (Amendment 7), so a Hetzner box without a vault still starts a
new store on every upgrade, now only once the person accepts it. Nothing here is proven on a real box.

## Amendment 9 (2026-11-11): built: phase 1 - the ingress account, sealed delivery, two follow-ups closed, and the issuer's foundation

The owner approved building Production secrets in phases. Phase 1 is the route everything else stands on and the issuer's
logic, with nothing of the issuer deployed. **Status: Preview.** Everything below is built and tested in CI with fakes (a
recording command runner, an in-memory state table and secret reader, a throwaway socket); none of it has run on a real box
or in a real account, and the things only a real kernel, sshd or AWS can show are named at the end.

### 1. The ingress account (section 3, built)

- **The account.** `ozbox secrets ingress-setup [KEY]`, run as root by the image build and by first boot of a machine that is
  not the Oz image, makes `ozbox-ingress`: a system account whose home (`/var/lib/ozbox-ingress`) is owned by root and holds
  nothing, with `/bin/sh` as its shell once setup has succeeded (a command run through it reads no startup file; see section 6 for the order). It is not an admin action and takes
  no word from the box user, so the root helper cannot be asked to install a key.
- **The sshd block.** A `Match User ozbox-ingress` block in its own drop-in forces `ozbox secrets receive` whatever the client
  asks to run, requires a public key, and turns off the terminal, `~/.ssh/rc`, `~/.ssh/environment`, every kind of forwarding
  and tunnels. `AuthorizedKeysFile` is `/etc/ssh/ozbox-ingress/authorized_keys`, in a root-owned folder no one else can write.
  The account is let in by the existing `AllowUsers` line in the first-boot file (it now names it); the drop-in adds no
  `AllowUsers` of its own, so a machine whose first-boot file has none is never narrowed to this account alone. The setup runs
  `sshd -t` and takes the block back out if sshd refuses it, so a bad block cannot cost the box user's route.
- **The key.** Where the person's computer cannot push one (everywhere but AWS), its SSH public key is pinned when the box is
  made, in a new `ozbox-ingress` label (the same route as the approval key's `ozbox-approver` label, validated by both box
  modules, written by first boot to the root-owned file). On AWS EC2 Instance Connect also works for the account: the SSH entry
  `ozbox create` writes now has a second block, `ozbox-<box>-ingress`, with the same route and key and the account's name, and
  the key is pushed for that account. The entry is written, refreshed and removed with the box's own.
- **The service's end.** The secrets service listens on a third socket, `/run/ozbox-secrets/ingress/ingress.sock`, in a folder
  only it and the account may enter. The **box user's import socket no longer takes keys, declarations, a signer's enrolment
  or an approval's challenge or signature**: it keeps only the commit barrier's `scan`, the guard's `override` and `enrolled`.
  The route for the rest is the ingress socket alone, so what the box user's shell does cannot reach it, "or nothing".
- **Size.** First boot adds one `runcmd` line and one argument to the service's unit; the units, the sshd block and the key file
  are written by the program (`ingress_guard.rs`), not by user data. Both modules' user-data size tests stay green.

### 2. Sealed delivery (section 3, built)

- **Cipher.** HPKE (RFC 9180), base mode, DHKEM(X25519, HKDF-SHA256), HKDF-SHA256, ChaCha20-Poly1305, from the `hpke` crate
  (pure Rust, no C toolchain, no async runtime; its licences are on the `deny.toml` allow list, so the policy needed no change).
  A test opens the standard's own published message (appendix A.2.1), so a dependency that stopped interoperating fails CI.
- **The key.** The secrets service makes an X25519 key the first time it starts with an ingress socket and keeps its private
  half in its encrypted store under a name the box socket can neither write nor read. A damaged key is an error, never replaced:
  a new key would silently void every pin. `service_key` on the ingress socket answers the public half, its fingerprint (a SHA-256
  over a label and the key) and the box's name.
- **The pin.** The person's computer pins the key at the first request to a box, through the ingress route, shows the
  fingerprint, and keeps it in its own state file (`ozbox/ingress-pins.json` in the configuration folder, `0600`), not in
  `~/.ssh`. It works the fingerprint out itself and refuses an answer that names another box or another fingerprint. Every later
  request is sealed to the pinned key and carries its fingerprint; a box whose key differs answers `key_changed` and nothing
  readable was sent. `ozbox secrets ingress pin --box NAME` shows or checks the pin, and `--replace` changes it after showing
  both fingerprints and a typed confirmation. **Pinning is trust on first use through a route no process of the box user is on,
  not a step gated by an approval**: the first contact is the usual first step of a signer's enrolment (which the pinned approval
  key already gates), but the pin itself has no code to type.
- **What is bound.** The request's operation, project, environment, box, the key's fingerprint, a time and a one-time id are the
  authenticated data, and the `info` names the purpose and the box. The service refuses a request whose time is more than five
  minutes from its own, remembers every id for the window, refuses a second use (an id is spent when it is tried, opened or not),
  and checks that what was sealed says the same operation, project and environment as the label. Only eleven operations may be
  sealed (import, `capabilities`, policy, the signer and approval operations, `enrolled`, `setup_code`, `kek_export`;
  `capabilities` came with the import of any value, which asks it first and holds back an encoded value from a box that cannot
  read one); a label naming anything
  else is refused whatever it holds. **That list is the code's floor, not a ban on new operations** (consistency check, text
  only): ADR 0041 adds its request operations (`file`, `get`, `list`, `await`, `decide`, `request_and_decide`, `cancel`), sealed to
  the service key, and ADR 0040 adds `fleet_window`, **sealed to the credential holder's key** (`ozbox-fleetcred`), which the
  laptop **pins like the service key** (the same first-contact pin and `key_changed` refusal). A request or a window is refused
  unless its label names one of the listed operations.
- **What moved.** `secrets import --box`, `env policy set --box`, `approval-key enroll|revoke|list`, `secrets approve` and the
  upgrade's review of enrolled keys all send through the one function (`ssh_receive`, now sealed and as the ingress account).
  An answer is the service's own words, code included, so a refusal reaches the person's terminal with its reason.
- **Boxes made before this change** have no ingress account. The route is refused with a plain sentence that says what to do
  (`ozbox upgrade <box>`). *Corrected (2026-11-12):* this said a Hetzner box needs a new box and a clone of `/work`, which
  contradicted Amendment 8, where a Hetzner upgrade replaces the server with the current first boot. On both providers the
  upgrade pins this computer's SSH key for the account (AWS rebuilds the machine from the newer image; Hetzner replaces the
  server, and so needs a newer image than the one the box runs: a server already on the image cannot be repaired in place).
  The one-time cost is a new secrets store when the box keeps its store's key in a file, since the key cannot be escrowed
  without the account: the upgrade lists what to enter again and asks for `--accept-new-secrets-store`. **The old route is never a fallback**: nothing is sent through the box user's account, so a box that cannot
  be reached the new way is not silently reached the old way.

### 3. Two follow-ups closed through the ingress route (section 9, built)

- **The first-time dashboard code.** The supervisor, which already holds the supervisor socket, hands the code it makes to the
  secrets service (`setup_code_put`), which holds it in memory until it expires (30 minutes). It is no longer printed where the
  box user reads logs: the dashboard says only that a code was made. The owner reads it on their own computer with
  `ozbox secrets ingress setup-code --box NAME`, a sealed request answered once and recorded (`secrets.setup-code.read`, never
  the code). A dashboard run anywhere with no supervisor socket still prints its code on its own console, as before.
- **Laptop-keychain escrow of a file-kept store key.** `ozbox secrets ingress escrow --box NAME` asks the service for the key
  (sealed; recorded as `secrets.kek.exported`; refused for a box whose key is in KMS, a TPM or a passphrase) and keeps it in the
  computer's keychain; it is never printed. `ozbox upgrade` then plans the store as **kept by this computer's keychain**
  instead of lost. After the machine is replaced and the service has stopped for the missing key, the upgrade places the key
  through the ingress account (`kek_place`, the only request answered while the service is down: it needs no unsealing, so it
  travels over the SSH route to the account alone). The account writes it to a folder only it and the secrets user may enter;
  a path unit restarts the service; on start the service uses the file **only if the box keeps its key in a file, the store is
  there, the key file is not, and the key really opens that store**, and always removes it. A wrong or stale key is discarded
  and the vault's escrow is tried as before. Amendment 7's "not built: the laptop-keychain escrow" and the upgrade's
  "starts a new store" for a box with no vault no longer hold for a person who has run `escrow`; they still hold for one who has not.
  *Limit:* the key placed while the service is down is not sealed (there is no service key to seal to: it lives in the store
  that cannot be opened); it rests on the SSH route to a root-pinned account, and the keychain copy is as safe as the computer.

### 4. The off-box issuer, foundation only (section 4, built as logic and as a module, deployed nowhere)

- **The function's logic** is a new crate, `ozbox-issuer`, with no network call in it. Its state, its secret reader and its record
  are traits: `StateStore` (compare-and-set writes), `SecretReader` (one secret version, a number of seconds), `Audit`.
  **Why Rust, not TypeScript or Python:** the Lambda's runtime has no cryptography library for Ed25519, ES256 or HPKE; Rust
  compiles the same `ring` and `ozbox-seal` code the box and the laptop use into one `bootstrap` program for the custom runtime,
  so the sealing is one implementation tested once (the standard's own message), and a passkey check and a release are
  unit-tested on any machine. The runtime loop and the AWS adapters are small, need no SDK (ADR 0008) and are phase 2.
- **What it does.** A box asks (`request`); the issuer checks the box, its store id and its service key's fingerprint against
  what it pinned, **makes the challenge itself** (a message naming the request, box, store, key fingerprint, secret, version,
  the command's digest, the run, uses, window, a nonce and an expiry), and keeps it. An approver answers (`approve`) with a
  laptop key's signature **in its own format** (Ed25519 for a software key and the recovery key; FIDO2 authenticator data for a
  presence key, ADR 0041 §3) or an ES256 WebAuthn assertion (a passkey: the relying party, the exact
  origin, the challenge, user presence **and** user verification, and **the counter, checked when non-zero and refused if it goes back** (one rule in ADRs 0040 to 0042: synced passkeys report 0), are all checked); the
  approval is recorded in the issuer's own state. **The issuer accepts "the person was asked" only from a verified attestation**
  (ADR 0041 §3: a FIDO2 attestation chaining to a pinned root, over the enrolment challenge, with UP = 1 and UV = 1 on every
  signature), not from a declared class; a Secure Enclave key is a software key until a named proof and verifier exist. **A laptop
  key without proven presence is refused for Production, with no override** (delegated, 2026-11-12; **owner to confirm**: this
  replaces "unless the owner allows it"). The window is capped at 900 seconds **before** the approver signs, so they sign the window they get.
  `release` spends one use with a compare-and-set (two releases cannot spend the same one), writes the issuer's own record
  **first** (a release it cannot record does not happen), reads one secret version for 900 seconds at most, and seals it to the
  box's service key with the release's labels (box, store, key, secret, version, run, request, which use) as authenticated data.
  A use that fails after it was spent stays spent.
- **The module** `infra/tofu/modules/aws-issuer` makes the Production KMS key (only the release role decrypts; the account root
  administers and never uses; operators may encrypt, never decrypt), the **release role** (trust: the issuer's role alone; reads
  secrets under one name prefix and decrypts with that key), the issuer's **own role** (assume the release role for at most 900
  seconds, its state table, its public-key parameter, its log, an add-only record in the Object Lock bucket, **an explicit deny**
  of reading a secret, decrypting, deleting or bypassing retention), a state table with point-in-time recovery, the function and
  an `AWS_IAM` function URL, and an **invoke-only** policy a box's role may be given. Its tests pin each of those as written. **The roles are named in the reserved namespace of ADR 0040 §3.1**: the
  issuer's own role is `arn:aws:iam::<acct>:role/obx/obx-<fleet>-issuer` and the release role is
  `arn:aws:iam::<acct>:role/obx/obx-<fleet>-issuer-release`, so the daily operator's `role/ozbox-*` rights cannot reach them (a path
  alone is not an escape, fact 15 there), and `operator_policy.rs` denies both. As built on this branch the module still names them
  `ozbox-<fleet>-issuer` and `-issuer-release`; **renaming them in `infra/tofu/modules/aws-issuer`, the Production key policy and
  the operator policy is the fix for a finding of the phase 1 re-review, queued separately** and not done by this text. The
  box's own role gets nothing here, and the box module's existing test that its role has no Production read is untouched.
- **Nothing was deployed or created.** No resource exists in any account. The function's package is built and checked by the
  owner (the module takes its hash and does not fetch it).

### 5. `ozbox init` creates the fleet's secrets key and, on request, the issuer (added 2026-11-11, owner)

Amendment 3 said `ozbox init` creates the fleet key; it created the state bucket and the network only, so a real setup had to
hand-write OpenTofu for `aws-secrets-key`. Now, after the network step:

- **The key is in the plan.** One KMS key with rotation on and its alias `alias/ozbox-<fleet>-secrets`, from the `aws-secrets-key`
  module, with its state in the encrypted state bucket under `ozbox/secrets-key/<region>.tfstate`, like the other steps. It is
  shown, and created only after the person approves (`--yes` approves; `--dry-run` stops at the plan). Afterwards `init` writes
  `secrets_key_arn` and `fleet` into the `[aws]` section, so every box made from then on keeps its store's key in KMS. The
  generated module call names **no operator role**, so the daily role is given no right to the key, and `infra/aws/operator-policy.json`
  still has no `kms:` action. `init` still refuses root and long-lived access keys.
- **Two identities.** The **setup identity** runs `ozbox init` (and `ozbox harden`): it is signed in through single sign-on or an
  assumed role, used for setup, and holds the permissions that create a key (the `OzBoxKeyAdmin` permission set,
  `infra/aws/key-admin-policy.json`). The **daily operator role** makes and manages boxes and has the permissions in
  `infra/aws/operator-policy.json`, with no key rights. They may be the same person on different days; they are not the same role.
- **A setup identity that cannot create keys** is found out before anything is planned, without changing anything: the role's own
  ARN is read and `iam simulate-principal-policy` evaluates the key actions (it creates nothing). If any is denied, `init` says
  which and asks for the `OzBoxKeyAdmin` permission set, continues with the rest of setup, and **leaves boxes on the file key**,
  saying plainly what that means (it protects the store from the box user and the agents, not from someone who can read the disk
  as root, and an upgrade needs the key escrowed, Amendment 9 section 3). If the check itself cannot run (it needs `iam:GetRole`
  and `iam:SimulatePrincipalPolicy`), `init` says so and tries; a refusal at creation is reported the same way and never stops setup.
- **The issuer, the same way.** `ozbox init --issuer-package ZIP --issuer-package-sha256 HASH` also plans the `aws-issuer` module from a package the person
  built (its SHA-256 is computed from the file and given to the module; nothing is downloaded), shows it, asks, and records
  `issuer_url` and `issuer_function_arn`. Without the flag, `init` does not touch the issuer.
- **Hetzner** has no KMS. A Hetzner box keeps its store's key in the machine's TPM when it has one, and otherwise in a file only
  the secrets user can read, escrowed to OpenBao (Amendment 7) or to the owner's keychain (`ozbox secrets ingress escrow`).
  `ozbox init` creates nothing for it here.

### 6. The security review of phase 1, and what changed (2026-11-11)

An independent review of this amendment's code found the route would not work on a real box and one older exposure in the box
role. Findings and fixes, each with its test:

- **H1, the sshd block was invalid.** `PermitUserEnvironment` is global-only in sshd; inside `Match` it makes `sshd -t` fail, which
  fails the image build and, on a stock machine, removed the block and left a login-capable account with no forced command.
  Now: `PermitUserEnvironment no` is stated before the block, the block holds only keywords `Match` accepts (`ForceCommand`,
  `DisableForwarding yes`, `PermitTTY no`, `AllowTcpForwarding no`, `X11Forwarding no`, `AllowAgentForwarding no`,
  `PermitUserRC no`, the root-owned `AuthorizedKeysFile`). **Fail closed:** the account is created and left with
  `/usr/sbin/nologin` as its shell and gets `/bin/sh` only as the very last step, after the block is written and the real
  `sshd -t` accepted it; a failure at any point leaves it unable to log in, holding no key. Tests: the unit tests run the real
  `sshd -t -f` on the rendered block (and prove the check has teeth by feeding it the first version, which the same sshd
  refuses); CI installs OpenSSH and sets `OZBOX_REQUIRE_SSHD=1` so a runner without it fails instead of skipping; the install
  order is asserted.
- **H2, no existing AWS box could be reached.** `infra/aws/operator-policy.json` now allows `ec2:osuser` `ozbox` and
  `ozbox-ingress` (same tag condition; pinned by its test), and `ozbox upgrade` on AWS pins this computer's ingress key in the
  new machine's first-boot configuration when the box has none (a box that has one keeps it), and says so in the plan. Hetzner:
  user data is read at creation, so a Hetzner box made before the ingress account needs to be made again (not changed here).
- **H3, the box role could read every Parameter Store value in the account** (and, a real-box finding the same day: an upgrade
  with the fleet key planned an inline role policy, which the operator is denied, so it would have stopped the box and then
  failed, every time). AWS's `AmazonSSMManagedInstanceCore` grants `ssm:GetParameter` and `GetParameters` on `*`, which in a
  shared account includes another product's Production SecureStrings. Now **every permission a box's role has is a
  customer-managed policy `ozbox init` makes once per account** (module `aws-box-policy`, with the setup identity, permission set
  `OzBoxPolicyAdmin`, `infra/aws/box-policy-admin-policy.json`: create and maintain policies named `ozbox-box-*`, with attaching
  or granting denied), and the box module only attaches them. **There is no inline role policy in the box module** (a test
  reads its source and fails on one). One policy serves every box because each reads the box's own role tags
  (`${aws:PrincipalTag/...}`), which the module sets:
  `ozbox-box-session-manager` (what the Session Manager agent needs, no parameter or secret read);
  `ozbox-box-parameters` (read `<ozbox-secrets-path>/<ozbox-box-role>` and below, only when the tagged prefix is under `/ozbox`,
  so another product's path cannot be named); `ozbox-box-parameters-key` (decrypt a customer key only through Parameter Store);
  `ozbox-box-fleet-key-<fleet>` (encrypt and decrypt with the fleet key only for secrets whose encryption context names the
  role's `ozbox-box` tag); `ozbox-box-session-logs` (write one prefix of the locked bucket, read nothing). The operator may
  attach exactly those ARNs (`iam:PolicyARN`; the fleet one by its prefix), read them for the module's plan-time lookup, and still
  cannot create or change a policy or put an inline one. A missing policy fails the plan before anything is stopped.
  **Preflight:** an upgrade's plan is refused, before the box is stopped, if it creates, changes or destroys a resource type the
  operator cannot apply (any IAM policy, user or key), with the address and what to do; `create` has no plan step, so its guard is
  the source test. Tests: the policy module's tftests (no parameter read outside the tagged path, no secret, no wildcard,
  every decrypt conditioned and on a named key); the box module's tftests (every attached policy is the account's own
  `ozbox-box-*`, never AWS-managed; the role carries the tags the policies read; a prefix outside the root is refused; with every
  option on, only those attachments); the operator policy's test; the plan preflight's unit test; the module source test. The
  Amendment 6 §4 claim now has the test it described.
- **Moving an existing box with an empty store to the fleet key.** (Amendment 11 narrows this on AWS: the decision now rests on the box's root facts, so on a box made before that release, upgrade it first (its store is kept by escrow or this computer's copy), then run `ozbox adopt-fleet-key`; `--use-fleet-key` is refused there with a sentence that says so, and `adopt-fleet-key` itself refuses a box whose program is older.) `ozbox upgrade --use-fleet-key` (AWS) gives the new machine the
  fleet key's labels, so every later upgrade keeps the store. It is refused unless the box itself reports (a new `names=` line
  in the secrets service's state file, which counts what the owner or an agent stored and not the service's own keys) that the
  store holds nothing, that its key is in a file, and that it is running and not already on KMS; the plan says so.
- **M1, authority on the ingress route was only an SSH key.** The ingress account has its **own key**
  (`~/.ssh/ozbox_ingress_ed25519`, pinned by the label), never the box user's; every Host block (the box user's too) sets
  `ForwardAgent no`; the ingress block names its key with `IdentitiesOnly yes` on every route, Cloudflare included (M6). And
  `kek_export` and `setup_code` need, once the box has a second factor, an **approval from the laptop approval key** (new scopes
  `kek-export` and `setup-code`, which the dashboard can also mint with a passkey), spent once; with no second factor they are
  allowed as the other first settings are, and recorded. `kek_export` stays (an upgrade of a file-key box needs it) with the
  warning in `ozbox secrets ingress escrow --help` (M7) that the keychain copy opens every value on the box.
- **M2, the package hash was a tautology.** `--issuer-package` now requires `--issuer-package-sha256` (from the signed release
  manifest or a reproducible build); `init` refuses a file whose hash differs before anything is planned, and the module has a
  `precondition` that the file at `package_path` has the hash given. Tests: both.
- **M3, key administrators could give themselves Decrypt.** The Production key's policy no longer uses `kms:Create*` or
  `kms:Put*`: administration is a named list; `kms:CreateGrant` is allowed only for an AWS service acting on an account
  resource (`kms:GrantIsForAWSResource`); `kms:PutKeyPolicy` is one statement of its own for the account's administrators, and
  the key carries `ozbox-production=true`. **Proposal for `infra/aws/key-admin-policy.json` (on `main`, not changed here):**
  add `Deny kms:PutKeyPolicy, kms:CreateGrant` on keys with `aws:ResourceTag/ozbox-production = true`, so the setup identity
  cannot change the Production key's policy at all. The claim is worded as: only the release role decrypts, against everyone
  without key-policy rights, and a change of the policy is a recorded event. Tests: wildcards are refused in the policy; a
  grant needs the condition; exactly one statement allows `PutKeyPolicy`.
- **M4, the issuer's signed scope.** The scope now also binds the project, environment, commit, directory digest and the caller
  (the AWS principal the adapter sees, set from the signed call), and the release's authenticated data carries them. `Config`
  gains, per box, the caller and the secrets allocated to it; a request or a release by another caller, or for a secret not
  allocated to the box, is refused, and a run may ask for at most five approvals. Tests: each field changes the signed
  message and the card; the caller, allocation and cap checks. The adapter that derives the caller from the function URL's IAM
  identity is phase 2 (it must overwrite whatever the box sent).
- **M5, the passkey card was drawn by the box.** The issuer now makes the card (`Scope::card`, `Issuer::card`) from its own record
  of the request; the approval page and the laptop client must render that and nothing the box supplies. The page itself is
  phase 2; until then the limit stands: a box-rendered card can be mislabelled by root on the box.
- **M6** is in M1 (the `IdentityFile` on every route). **M7** is in M1 (the warning, and the approval).

**Left over, as follow-ups:**

1. Verify the issuer package against the **signed** release digest automatically (today the person supplies the hash).
2. Add the `ozbox-production` deny to `infra/aws/key-admin-policy.json` (above), and give the Production key a separate
   administrator if the owner wants `PutKeyPolicy` out of the account's hands altogether.
3. `create` has no plan step to run the operator-cannot-apply preflight on; its guard is the source test. A box made before this
   change that has an inline role policy (made by someone with rights the operator lacks) keeps it, unmanaged, until an
   administrator removes it.
4. Hetzner boxes made before the ingress account cannot get it by upgrade (user data is read at creation).
5. The Low findings (message naming the box, persisted replay list, empty-store key check, zeroizing the service key's hex,
   the setup code printed on a failed hand-over, `OZBOX_INGRESS_SOCKET` honoured by the forced command, the import size limit,
   passkey `crossOrigin`, `take_inbox` opening with `O_NOFOLLOW`, the issuer's Object Lock bucket) are untouched here.
6. A separate account or an SCP for another product's Production (the review's long-term advice).
7. **The issuer roles move into the reserved namespace.** The roles become `/obx/obx-<fleet>-issuer` and
   `/obx/obx-<fleet>-issuer-release` (§4 above, ADR 0040 §3.1), with the operator policy denying them. The code change in
   `infra/tofu/modules/aws-issuer` and the operator policy is queued separately.
8. **ADR 0041's scopes.** `setup-code` and `kek-export` (M1 above) are in ADR 0041's scope list and rule table
   (`kek-export` is never decidable from the dashboard); its request operations are added to §2's sealed list.

### What is **Works**, **Preview**, **Planned**

| Part | Status | Honest limit |
|---|---|---|
| Ingress account, sshd block, key file, socket, import socket narrowed | Preview | The block is checked by a real `sshd -t` in CI. The sshd behaviour (forced command, `AllowUsers` accumulation, EC2 Instance Connect for a second account, shell startup files) and the folder and socket permissions need a real box: the `--real-box` gate |
| Sealed delivery, pins, replay and label checks | Preview | Tested end to end across the real socket handler and the real client; not run over SSH |
| First-time code to the laptop | Preview | Same |
| Laptop-keychain escrow and the upgrade's placement | Preview | The path unit, the inbox permissions and the second start of the service need a real box |
| Issuer logic and the `aws-issuer` module | Preview | No account; the AWS adapters and the runtime loop are not written |
| `ozbox init` creating the fleet key (and, with `--issuer-package`, the issuer): plan, approval, state in the bucket, config written, the permission check | Preview | Tested with a recording runner; never run against a real account |
| The box Session Manager policy (`ozbox init`, `aws-box-policy`) replacing AWS's `AmazonSSMManagedInstanceCore` | Preview | tftests and the operator-policy test; never applied to a real account. Existing boxes swap at `ozbox upgrade` or with the commands in `infra/README.md` |
| Issuer approvals through the dashboard, notifications, rotation inside the issuer, GitHub App tokens, the box's use of a release | Planned (phase 2) | Not started |

### What this does not cover

- The old import route is gone for boxes that have the ingress account **and** for boxes that do not (they are refused, with a
  sentence); a person with an older box cannot import keys to it until it is upgraded or replaced.
- A `laptop` home for Production, the per-use release into `mlock`ed memory in the service, the proxy and the database listener
  (sections 5 to 7) are not built here.
- The `kek_place` request and the ingress route's answers are not sealed to the laptop; they rest on the SSH route to the account.
## Amendment 10 (2026-11-12): a declaration can carry plain variables, renames, pinned files, services, tools and browsers

*Numbering:* this and its revisions were written on a branch beside Amendment 9 above (the ingress account), and are numbered 10 where the two met. Where they say a laptop's request reaches "the import socket", it now reaches the secrets service through the ingress account, sealed (Amendment 9, section 2): the declaration, the import and the `capabilities` question all arrive as sealed requests and are answered as the import socket answered them before.

A first run of a real project on a real box found that a declared command could run nothing real: its PATH held none of the
catalog's tools, plain settings (`PORT`, an app URL, a clinic id) could not reach it, the runner user could not read the repository, a
declaration fixed only how the command's words *start* (so the script they run could be edited to read what the command
receives), and nothing could keep a server up for another declared command to talk to. `ozbox env policy` gains the following.
The declaration format changes, so a box is asked first (`capabilities` answers `declaration_v2`), because a box from before it would
store the declaration without the parts it does not know. The reader now **refuses** a field it does not know (`deny_unknown_fields`)
instead of dropping it, so this cannot happen again.

**Per command.**
- `vars` (fixed plain values) and `pass` (plain names a caller may supply with `--pass NAME=value`). A name must not choose a
  program or a code path (`PATH`, `HOME`, `NODE_OPTIONS`, `LD_*`, `*_PROXY`, `PLAYWRIGHT_*`, `GIT_*`, `NPM_CONFIG_*`, the variables of a
  declared tcp destination, and others); a passed name must not say it is a secret (`TOKEN`, `PASSWORD`...). A value is 1 to 512
  characters of `[A-Za-z0-9._:/@+,=-]` (the characters that need no quoting in any place it travels), must not look like a key or a
  production value (the import's detector, plus well-known key prefixes and long mixed tokens), and a passed one must not contain a
  secret the project stores. The same name cannot be set twice in a command (a secret, a rename, a fixed value, a passed value).
  This is never a way to widen the secrets a command receives: that list is `allow`/`env`, unchanged.
- `env` entries may be `{"name":"STORED","as":"TARGET"}`: the command sees the secret under another name, so no second copy
  has to be stored. A plain name serializes back to a plain string, so an existing declaration keeps its bytes. The rename is part
  of the declaration, so it is covered by the `policy` approval; the audit line shows `STORED->TARGET`.
- `pin` (`[{"file","sha256"}]`, relative to `dir`): the launcher reads each file once, hashes **those bytes**, writes them to a
  root-owned read-only copy named by the hash, and starts the unit with that copy bound read-only over the file
  (`BindReadOnlyPaths`). The check and the run use the same bytes, so there is no gap between them for a swap, and a change stops
  the run before any secret is looked up, naming the file. A pinned command takes **exactly** its declared words (no extra
  argument). The digests are inside the declaration, so the `policy` approval's subject digest (ADR 0041 §4: the canonical policy)
  covers them with no extra field. A cache keyed on device, inode, size, mtime **and ctime** saves re-reading unchanged files; ctime
  cannot be set back by the box user, and the run always uses the verified copy, so the cache is a time saver and nothing depends on
  it. **A pin covers a file's bytes and nothing it loads**: imports, `node_modules`, a package script's children, `.npmrc`. Pin them
  too, or run the secret-receiving command as one dependency-free file started directly (`node file.mjs`), not through `npm run`.
  A swap of a *directory above* the file for a link between the mount and the exec is a window of milliseconds that is not closed
  (the check refuses a link that exists at check time).
- `service: true` with `port`, optional `health` path: started with `--start` as a unit of its own, kept up until `--stop` or 4 hours,
  on loopback only (`IPAddressDeny=any` plus loopback allowed, as every command), given no secret in this version (a unit that outlives the
  launcher has no standard input to carry one, and a property would show it to `systemctl show`; **Amendment 12 changes this**: a service
  can receive secrets as credentials), started
  from a declared program, refused if the port is in use, and stopped again if its health check does not answer within 60 seconds.
  Another command in the project reaches it on the same loopback. The loopback is the box's, so a process of another project, or the
  box user, can reach the port too: a service is for a development server, not for anything that guards data.

**Per project.** `tools` (catalog names, optionally `{"name","sha256"}` with the digest of the installed tree) and `browsers`.
The box user's `~/.local/opt` is writable by the box user, so a runner is given a **root-owned copy** made by the root helper's
`runner-setup`, from paths and programs the catalog compiled into the program says (never a record in the box user's home): no
group or other write, no setuid, links that stay inside the tree, hashed again after the copy. A digest in the declaration is checked
against the source first. Without one the copy trusts the installer's checksum-verified download up to the moment of copying, and the
digest is printed so the owner can pin it. Browsers are Playwright's cache directories, copied by revision into one shared root-owned
folder, so projects on different versions find theirs side by side.

**The runner's access to the project folder.** `ensure-runner` no longer puts the runner in the box user's group (which opened the
box user's whole home, and is removed from runners an earlier image made). It grants a POSIX ACL to that one user: search-only on the
parents from `/work`, read on `dir` (`.git` excluded, default entries for new files), read and write on each `writable` folder
(default entries for the runner and the box user). `setfacl -P` throughout, and the declared folder must be its own real path.
Removing the declaration or moving the folder revokes the old grant. `ensure-runner` is ungated, so it acts only on the stored,
approved declaration and takes no path from the request.

**Not proven.** Chromium and a Next server under this sandbox (`NoNewPrivileges`, `PrivateDevices`, `ProcSubset=pid`), ACL behaviour
on mode 0600 files, `IPAddressAllow` blocking non-loopback ingress to a service, the `BindReadOnlyPaths` of a file inside a path the
unit also makes read-only, and the catalog's Playwright entry (its package list and pinned version must come from the pinned
package's own dependency table, so it stays unverified). All need a real box.

### Amendment 10, revision 1 (2026-11-12): review of the first version (one critical, three high, four medium)

The first version of Amendment 10 shared one runner user across a project's commands and relied on the unit's `PR_SET_DUMPABLE=0`
that §Side channels describes. A review found the user was shared and the flag was set nowhere, so a service the agent controlled
could read a key-receiving command's `/proc/<pid>/environ`. What changed, and what is and is not protected:

- **A user per secret-receiving command** (`ozbox-rc-<12 hex of sha256(project,command)>`, replaced in revision 2 by `ozrc-` and the full 128-bit hash, made by `runner-setup` from the stored
  declaration, with its own ACL grants and home). Services and plain commands run as the project's runner and never as such a
  user. `capabilities` answers `runner_uids`; a laptop will not send a declaration with a secret-receiving command beside another
  command to a box that does not. This, not the flag, closes the same-uid `/proc` read.
- **`PR_SET_DUMPABLE=0` is set in `exec-env` while it holds the environment line, and does NOT protect the command**: the kernel
  resets it on the `execve` that starts it. §Side channels is corrected accordingly. `MemorySwapMax=0`, `LimitCORE=0`,
  `ProtectProc=invisible` and `ProcSubset=pid` are on every unit; `PrivatePIDs=yes` is added when `systemctl --version` is 257 or
  later (never assumed).
- **Tools**: a project with a secret-receiving command must pin every tool by digest; the copy is made from one read compared with
  that digest, stored under its content name (`store/<sha256>`), with links per project. A system package cannot be pinned.
- **Browsers**: `browser_digests` per installed revision; only an approved revision is copied; a command with a secret cannot be
  marked `browser`, and only a `browser` command is told `PLAYWRIGHT_BROWSERS_PATH`.
- **Imports**: `pin_tree` pins a folder (digest of every file, `tree_scan`), run from a verified copy bound read-only. A
  secret-receiving command whose argv names a script is refused at launch unless the script, its relative imports and every package
  it needs (with their `dependencies`, non-optional peers and installed optional dependencies) are pinned, read from the verified
  bytes. Static: a computed `import()`/`require()`, `createRequire`, `eval`, `new Function`, an import without an extension, an
  absolute path, a URL, a `#` import and a shadowing `node_modules` are refused; a program that builds a path from data and runs it
  is not seen. A pinned secret-receiving command's program is `node` exactly (revision 5), and it runs `node FILE`, never `npm run`.
- **M1**: the project folder must be its own real path; pinned files are read by an `openat` walk with `O_NOFOLLOW` on every
  component; five changed pins in a minute pause the project for five minutes. **Not closed**: systemd resolves the working
  directory and bind destinations itself after the check, so a swap of a parent folder in that window remains possible. To be proven
  on a real box.
- **M2** a secret-receiving command's words may not name a file in a `writable` folder or climb out with `..`. **M3** setup records a
  stat fingerprint of each copy it made and the launcher compares it. `setup_digest` now covers which commands receive a secret.
- **The declaration's write gate**: `workload-policy.*` is never readable or writable on the box, supervisor, runner or broker
  sockets. The import socket's `policy` op is the one path; once a second factor exists it needs a `policy` approval. Before one
  exists, the first declaration of a project is accepted and a CHANGE of one is now refused (scope rule `FirstSettingOnly`), because
  the box user cannot be told from the owner and an agent could otherwise replace a declaration to receive a key. **Residual**: on a
  box with no second factor, an agent can still make the FIRST declaration of a project that has no declaration.
- **Production keys**: the `resolve` op (runner and admin sockets, exact and reference forms, box store and imported store) refuses
  a key stored as production. The flag is set at import by detection of the value, and the caller chooses `env`, so a production
  value the detector missed, imported under a staging name, is not caught here.

### Amendment 10, revision 2 (2026-11-12): second review (one critical, three high, five medium)

The second review blocked on a critical hole (a box with no second factor), a bypassable import check, digests computed from bytes the
agent could write, a parent-swap race that was reliable rather than a retry game, and a declaration that no longer loaded. What
changed:

- **N-C1.** On a box with no second factor enrolled, no declaration may give a command a secret (a first one or a replacement:
  the box user cannot be told from the owner, so an agent could declare first and receive every key imported afterwards), the
  `resolve` op hands out nothing, and an import cannot replace a stored value (it could repoint a URL an approved command sends its
  key to). A declaration with no secrets is accepted. The scope rule table is unchanged; the gate is in `policy_bootstrap_gate`.
- **N-H3, N-H1, N-L1.** A command that receives a secret gets a private view of the work area (revision 3: rooted at `/work`, not at the
  project folder, which left Node's lookups above the folder live): `TemporaryFileSystem=/work:ro`, the verified root-owned copies
  bound read-only at their paths, and the declared writable folders bound from the live folder (refused by name when missing or a
  link, no `BindPaths=-`). No folder above the project and no other project exists in the unit, so an agent-written `package.json`
  (self-reference), an optional peer, a package above the folder, a loader hook or an `.npmrc` is absent and an import of it fails
  closed; the user of such a command is granted nothing on the live project, and the project's own `package.json` files are pinned.
  The static closure check still refuses at launch what it cannot show is pinned; it is not the boundary for what it cannot read. The unit never resolves a path through the live folder, so the parent swap is closed by
  construction. Once a copy named by the approved digest exists, the launcher does not read or walk the live folder for such a
  command; the per-run fingerprint walk over tool and browser copies is gone for every command (the copies are root-owned and
  content-named, so only root could change one; they are checked once, at setup). A link refusal now counts toward the lockout.
  The command takes exactly its declared words (no `--import`, `-r`, `--env-file`, `-e`), must pin a file and name its `envs`.
  Measured on this computer: 12 packages / 1,500 files, the old per-run stat walk 31 ms, the private view 0.16 ms.
- **N-H2.** `ozbox env policy pin` refuses to run on a box (unless `--on-box`, which says it only freezes what is there) and off the
  box needs `--commit` at the box's commit and a clean checkout. Tools and browsers are digested from folders the owner extracted or
  downloaded; the box copies the box user's install only when it matches. **Not done:** root installing a tool itself from the
  catalog's checked release, and building a package tree as root from the pinned lockfile; the box user's copy is the source and the
  laptop's digest decides whether it is trusted.
- **N-M1.** The secret user is `ozrc-` plus the full 128-bit hash (26 base32 characters). A root-owned registry maps each user to
  its project and command; an existing user that is not registered for exactly that pair is refused. **N-M2.** A changed
  declaration (any field: pins, words, allow, envs, egress) is not "current", so the launcher asks for setup, which stops the run
  units by name and every process of its runner users, repeating until none is left (or refuses), before applying it. **N-M3.** A secret command's egress
  must be exact hosts, its `pass` values cannot be hosts, addresses or URLs, and the environment must be one it names. **N-M4.** A
  value stored as production (flagged, or under an environment named production, prod or live) is production under every name at
  import and at resolve, a file whose name says production is not imported under another environment, and `production_ids` lists the
  owner's own identifiers (JWT payloads included). **N-M5.** A declaration stored by an earlier version still loads; its secret
  commands are refused at launch with a sentence that says what to change, and a replacement that removes secrets is accepted on a
  box with no second factor. **N-L4.** Pins refuse a pnpm link with a message that says why.
- **Revision 3 (third round).** **NV-H1/NV-M1:** the private view is `TemporaryFileSystem=/work:ro` (above); the secret user is granted
  nothing on the live project. **NV-L1:** a missing or linked writable folder is refused by the launcher, by name. **N-M2:** see above.
  **N-H2:** `ozbox env policy pin --tool NAME --release V [--arch]` fetches the catalog's Linux release, checks it against the catalog's
  checksum and prints the digest the box will see; `--browser KIND --revision N` does the same from Playwright's CDN (no publisher
  checksum exists, so the download's hash is printed for comparison). Still not done: root installing a tool itself. **NV-L2:** "held as
  production" is a set of keyed hashes built once and rebuilt when the store file changes, so a resolve costs one hash. **N-M4:** letter
  case no longer hides an environment name or an identifier. No benchmark metric moves; real-box timings of a secret unit's start
  (the tmpfs and the binds) are still to be taken on the 4 vCPU / 8 GiB / 40 GB shape.
- **Revision 4 (fourth round).** **NV3-H1:** a project with a secret command refuses a writable folder that is `.`, has a `.` segment, a
  `node_modules`, `site-packages`, `dist-packages` or `__pycache__` segment (any letter case), overlaps a pinned folder, or sits on or
  inside the folder chain of a pinned file; at write time and again at launch (the pins do not cover Python today; the names are refused in case
  they do). **NV3-M1:** setup keeps a "stop pending" record, a copy of the setup being replaced, until its stop and the rest of the
  setup have gone through, so a refused stop (or any earlier failure) makes the next `apply` stop and revoke again, whatever declaration it
  is given, and it never reports success with no kill; `pkill` exit 1 alone means "none left" (2, 3 or no `pkill` refuses), with a
  back-off between passes. **NV3-M2:** the production question fails closed: a production candidate that cannot be read or opened (a
  key-provider blip) makes the answer "unknown", never "no", the incomplete set is not cached, and a resolve is refused with a sentence
  saying so; an import builds the set once and stops if it cannot. **NV3-L1:** the pin helper is https-only including redirects.
  **NV3-L2:** the cache stamp includes the change time. **NV3-L3:** a runner's home is emptied when its declaration changes.
  **NV3-L4:** `--revision KIND=N` per folder, and a missing digest for a folder a browser needs is refused at write time and at setup.
  **NV3-L5:** a launch holds a shared lock from "set up for this declaration" to the hand-over to `systemd-run`, setup holds it exclusively, and
  setup waits a moment and kills once more at the end (a unit `systemd-run` was still starting is the one residual window, closed by that
  second kill). **NV3-L6:** setup removes the round-2 ACL entries of a private user on an upgraded box. The Node probe test now builds the
  view from the start-up arguments themselves (copy all of `/work`, empty what `TemporaryFileSystem=` names, apply the binds). No benchmark
  metric moves (secret-unit start and setup only).
- **Revision 5 (fifth round).** **NV4-H1:** a secret command's program must be `node` (exactly that word), refused when the declaration is
  written and again at launch, with a sentence saying only Node scripts can be pinned today. The import closure and the writable-folder
  rules model Node's lookup; another program (Python's `sys.path[0]`, `python -m`) puts the script's own folder, or the working
  folder, on its path, so a writable `helper` beside a pinned `helper.py` was imported in place of it. Every secret command must pin
  a file, so no secret command escapes the rule by being unpinned; a command with no secret may run any program. The writable-folder
  rule is unchanged and is stated as it is: it refuses folders on the chain of a pinned file BELOW the project folder, not every
  top-level folder (Node never looks in the script's own folder for a bare name). **NV4-M2:** setup copies the record it replaces to
  the stop-pending marker on every apply that finds one, not only when the declaration changed, so a failed re-run of the same
  declaration no longer loses the stop. **NV4-L1:** the marker and the record are written atomically (temporary file, fsync, rename,
  fsync of the folder); a marker or record that exists but cannot be read means "stop pending", and the stop then also covers the
  users the registry names for the project. **NV4-L2:** a runner home that cannot be emptied refuses the setup. **NV4-L3:**
  `SETUP_VERSION` is 3 and stored in the record; the round-2 ACL removal runs only for a record of an earlier version, after the
  project's processes are stopped and before the grants, under the exclusive lock, so it runs once and never on a live unit (an older
  record also forces the stop). **NV3-L5 closed:** a launch holds the shared lock until its transient unit exists (systemd's unit file
  appears, or the `systemd-run` client has exited; a 10 s cap), so setup's last kill finds every unit a launch started. **NV4-L4:** a
  Linux-only test of the lock in both directions, a test of that wait, and a test that the pin client never connects to an http
  address (ureq refuses it at the connection, which every redirect hop passes through; a TLS test server was not built, so a
  redirect itself is not driven). **NV4-I2:** one browser-kind table. Not done: NV4-I1 (a self-reference through `exports` before
  `node_modules`; needs a pinned `package.json` with that name, so an agent cannot arrange it after approval). Benchmark: setup and
  secret-launch time only (a path poll of a few milliseconds per launch; no process); no headline metric moves.
- **Revision 6 (sixth round).** **NV5-H1:** a secret command is exactly `node FILE`: `argv[1]` must be a pinned file ending in `.js`,
  `.mjs`, `.cjs`, `.ts`, `.mts` or `.cts`, and nothing starting with `-` may come before it (so no `-e`, `-p`, `--import`, `--require`
  or `--loader`, and no extension-less script that Node resolves by itself). Checked when the declaration is written and again at
  launch; `check_code` now refuses when it finds no script entry instead of treating "nothing found" as "checked". Words after the
  script are the script's own: Node does not read them as options, so they are not refused. Tests cover `node tests/mint`,
  `node -e "import(...)"`, `node --import=... -e 0` and `node -p "require(...)"`. **NV5-L1:** if the unit file has not appeared after
  10 s and the `systemd-run` client is still running, the launch kills the client, runs `systemctl stop` on the unit, fails the run,
  and only then lets go of the lock (the order of the kill and the stop at PID 1 is not guaranteed; revision 7 states what does
  guarantee the failure). `lock_file` retries an
  interrupted wait and returns an error on any other `flock` failure, which setup treats as a failure and a launch as "not set up":
  no path runs without the lock. **NV5-L2:** `users.json` is written atomically; a registry that exists and cannot be read or parsed
  stops the setup (and the stop pass) instead of reading as empty. **NV5-I1:** the round-2 ACL removal is gated on a record of version
  below 3, the version that ended those ACLs, so a later bump of `SETUP_VERSION` does not repeat it. **NV5-L3 (the cheap option was
  taken, and the limit stays):** a script that receives a secret may not import `child_process`, `worker_threads`, `cluster` or `vm`
  (with or without `node:`), refused by the import check. This is a static check of the imports the box can read, not a sandbox:
  what a script starts through any other route is outside the pin, and a program it does start has its own lookup path next to any
  writable folder. A secret-bearing script is therefore a short mint script. Benchmark: none of these paths is measured; no headline
  metric moves.
- **Revision 7 (seventh round).** **NV6-H1:** a pinned PROJECT folder (`lib`) is no longer trusted as pinned bytes. Only a package
  under `node_modules/` is covered by its pin and not read; every other file the entry reaches, in a pinned folder or a pinned file,
  is read from the verified copy and followed, so an import of a writable folder (`../out/x.mjs`) or of a spawner is refused. The
  launch message no longer says to pin "the folder that holds it". Package code is trusted as the bytes the owner approved and is
  not read: a package written to import a writable folder is outside the check. **NV6-L1:** the import check also refuses
  `getBuiltinModule`, `createRequire`, `require.main`, `module.constructor`, `process.mainModule`, `process.execve`,
  `process.binding`/`dlopen`, and `require` used as anything but a direct `require('...')` call (an alias), and `module` and
  `inspector` join the refused modules. Still out of scope, and said so: `eval` and `Function` written indirectly
  (`(0, eval)(...)`, `globalThis.eval`, `Function(...)` without `new`), computed member access (`process['binding']`), a dynamic
  `import(variable)` the reader cannot see, and native add-ons. **NV6-L2:** an unreadable `users.json` no longer skips the stop: the
  users known from the records and the project are stopped and their homes emptied, and then the setup refuses. Recovery: repair or
  delete `users.json` AND remove the `ozrc-` users it named (`userdel`), then run setup again, since a runner user no record lists is
  never reused. **NV6-I1:** the run fails closed because no secret line is written until the unit exists; the kill and the stop are two
  connections to PID 1 and their order is not guaranteed. A late unit's exec-env step reads end-of-file and never runs the command.
  **NV6-I2:** a client that exits with no unit seen gets no secret line at all. **NV6-I3:** a poisoned launch-lock mutex fails closed
  ("not set up"). **NV6-I4:** the tree-cost test keeps its correctness asserts and its timing check is relative (a fingerprint costs less
  than the full digest); the absolute budget runs only with `OZBOX_PERF_ASSERT=1`. **NV6-I5:** a secret declared without a rename is
  checked against the reserved names (`NODE_OPTIONS`, `PATH`...). Benchmark: none of these paths is measured; no headline metric moves.
- **Revision 8 (eighth round, the last).** **NV7-L1:** a file read from a pinned project folder (outside `node_modules/`) may not be, or
  sit behind, a link: Node resolves a linked file's imports from the link's target folder and the walk from the path it was reached by.
  The launch check refuses it, the same way `ozbox env policy pin --entry` already does. **NV7-L2:** `mainModule`, `execve` and `dlopen`
  are refused anywhere (destructuring and `process?.` forms included), `process?.binding` like `process.binding`, `module` is allowed
  only as `module.exports` (so `module.paths`, `module.require` and `const m = module` are refused), and so is a `.constructor.constructor`
  chain. A real project's session minter and its retry helper still pass. A computed `import(x)` is REFUSED, not unseen; the wording of the
  out-of-scope list is corrected. **NV7-I1:** a helper that uses `createRequire` cannot be part of a pinned secret command. **NV7-I2:**
  the reserved-name check for a secret declared without a rename moved from loading a declaration to setting it (`secret_rules`): an
  older stored declaration with `NODE_AUTH_TOKEN` still loads and its plain commands run, and only its secret command is refused, with a
  sentence that says to rename it. **NV7-I3:** the recovery text for an unreadable `users.json` says the file is shared by every project
  on the box, to remove every `ozrc-` user on it (`getent passwd | grep '^ozrc-'`), and that deleting it affects all projects.
  Benchmark: none of these paths is measured; no headline metric moves.
- **To prove on a real box (Ubuntu 24.04, systemd 255):** that `TemporaryFileSystem=/work:ro` with `BindReadOnlyPaths=` of a file and of a
  folder, and `BindPaths=` of a writable folder, create their destinations (nested parents too) inside the tmpfs, and that no ancestor of
  the project, no sibling project and a planted `/work/repos/package.json` or `node_modules/<peer>` exist in the unit; that a stop of a
  running secret unit follows a declaration change, and that a refused stop followed by a retry still stops it (N-M2, NV3-M1); that a writable
  folder of `.` or `./x` is refused before systemd sees it and what systemd does with one; that a missing writable folder is refused by the launcher; that the working directory resolves
  inside it; a swap loop on the project folder while the unit starts; N-L3 (whether `systemd-coredump` writes `COREDUMP_ENVIRON`
  for a crash with `LimitCORE=0`, and whether the box user can read the journal); and C1 across two units. Added in revision 5: a `python3 m.py` secret command is refused on the box; a launch started during `runner-setup` waits and then refuses the old declaration, and a setup started during a launch waits for that launch's unit to exist and then stops it; a record from the round-4 program is migrated once (stop, ACL removal, new record) and `setfacl` is not run again by the next apply; setup time with two secret commands on a real project checkout.

## Amendment 11 (2026-11-12): an existing AWS box can move its store to the fleet's KMS key, in place

A box made before the fleet's KMS key existed keeps its store's key in a file on the system disk for good: Amendment 8 gave the
key to a **new** box only (it rides the box's labels, so every later upgrade keeps it), and for an existing box `ozbox upgrade`
could only say the store would be lost and offer `--accept-new-secrets-store`. Found on a real box (2026-11-12): the
configuration named the fleet key, and nothing could put it on a box that already existed.

**The route built: `ozbox adopt-fleet-key <box>`, an in-place re-wrap, not an upgrade.** It keeps what the store holds, and
no secret is entered again. Three parts, each of which says what it does (amended the same day after a review: the first
version let the box destroy its key file before the laptop had committed, decided Finish and Cancel from an answer the box
user can forge, and stopped the service for the whole re-wrap):

1. **The laptop begins.** It asks the box's **root** first (see "What the laptop decides from" below); the box must be on a
   file key that has not moved. A stale cancel mark on the box is taken away. Then OpenTofu applies the change to the one box
   in place: the role gets the account's fleet-key policy ATTACHED (encrypt and decrypt, only where the encryption context
   names this box; the daily operator role may attach exactly that policy and is denied inline ones), and the box gets a **pending** tag (`ozbox-secrets-adopt`, the key's ARN). The plan is guarded like the
   others: nothing is replaced, only that attachment may be created, only tags (and the attachment's `policy_arn`) may change, and
   `/work` is never created or destroyed. The guard also reads the plan's before/after of every updated resource, as an
   **allowlist** (second and third review): an update may change the `policy_arn` of the one role-policy attachment this step
   creates or takes back, and **tags, key by key**: only `ozbox-secrets-adopt`, `ozbox-secrets-key`, `ozbox-secrets-fleet` and
   `ozbox-fleet` (which the role gets with the grant, and which may appear or go but never be rewritten to another fleet). Every
   other tag, `ozbox-managed` first (it is the Systems Manager target condition), may not change. Nothing else may change, so a
   stale spec or a module that moved on cannot change the instance type, the metadata options the box needs to read its own
   tags, API stop protection, monitoring, a security group or another role's policy in place. An attribute or tag whose new
   value is only known after apply counts as changed, and so does any action that is not a plain create, delete or update
   (OpenTofu's `forget`, for one). The consent is the command itself; it shows
   the change and asks (`--dry-run` stops there, `--yes` skips the question). It is a separate, named command because a switch
   of the key is never a side effect of something else: not of an upgrade, and not of `--accept-new-secrets-store`.
2. **The box moves its own store.** The box's root step that already reads its instance tags (`ozbox secrets configure-box`, at
   boot and every 15 minutes) sees the tag, which nothing on the box can set, and starts the move as a unit of its own
   (`ozbox-adopt-fleet-key`; that step is a pre-start of another unit, which systemd kills after 90 seconds, and a kill half
   way would leave the service stopped). Everything runs under one lock, a kernel `flock` on `/run/ozbox-adopt/lock` (second
   review: the first version's process-named file could be held by two runs, deleted by one that did not own it, and stay
   busy for ever after a reboot). The kernel frees the lock when its holder dies or the box reboots, so no stale state exists
   and there is no takeover to get wrong; the file is never removed; `adopt-status` looks with a shared, non-blocking lock. A
   move and a cancel never run at the same time. In order:
   - **Reconcile first.** A run killed between two writes (a reboot, an OOM kill: systemd sends the unit SIGTERM) leaves the
     store and the settings disagreeing, which the service refuses. Both disagreements are decided from the files, before
     anything else: a store that says `kms` with settings that choose the file key gets the KMS settings written (after the
     probe); a store that says `file` with settings that name KMS and a key file that is there gets the file settings back.
     The next run, and `pending()`, treat either state as work, so no tag is needed to be brought out of it.
   - The move goes ahead only if the service itself says it is ready on a **file** key (never a TPM, never an already-lost
     store) and KMS passes a probe (a throwaway key wrapped and unwrapped as the secrets user, with the box's own encryption
     context, before anything is touched, so a grant that has not reached the machine yet costs the service nothing).
   - **The slow part runs on a side copy while the service keeps serving.** The store is copied beside itself (as the secrets
     user, so root never follows a link that user planted), and the copy is re-wrapped, opening with the file key explicitly
     and giving **every data key back through KMS before the copy's file is replaced**. A grant that has not reached the
     instance yet, or a context that does not match, fails here with the live store untouched and the service never stopped.
   - **A short stop.** The service stops, the live store is compared (SHA-256) with the bytes the copy was made from (a secret
     written meanwhile is not lost: the swap is not made and the next run starts over), the copy is renamed over the store, the
     settings are written (the key in, the "a file key is allowed" line out), and the service starts. Every file is written to
     a fresh temporary file (never a link), fsynced, given its owner and mode, renamed, and the folder fsynced, so a crash
     leaves the old file or the whole new one, never a partial one. The service is down for the stop, the rename and its own
     start-up, which unwraps each secret through KMS: seconds, plus roughly a second or two per secret (an estimate, not
     measured; the wait scales with the store, 60 s plus 4 s per secret, so a large store is not rolled back for being slow). If
     the service does not say `kek=kms` and ready in time, the old store and settings are put back (atomically, keeping the
     owner) and it starts on the file key it had.
   - **Nothing is destroyed yet.** The key file and the copy beside the store (`secrets.json.pre-kms`) stay until the laptop has
     committed. Only a box that carries the real label `ozbox-secrets-key` and no longer the pending tag destroys them
     (zeroed, then removed), and only once the `/work` copy is wrapped by KMS too. If the label is already there before the
     box moved (see H2 below), the box moves and commits at once, so a premature label only speeds it up.
3. **The laptop commits.** Only when the box's **root** says the service is ready on KMS, the store and its `/work` copy both
   say `kms`, the settings name this key, nothing is running and no cancel is recorded, is the real label written. That label
   is what `ozbox upgrade` reads as "the store is kept", so writing it before the box has moved would make the next upgrade
   lose the store. Then the box destroys its key file on its next look (the laptop asks it to look now) and the command waits
   for the box's root to say the key file and the copy are gone; if that does not happen in about a minute it says that the
   label is written and the key file stays until the box's next check, and never that it is gone. While the pending tag is on a
   box, an upgrade is refused (the new machine would be configured for KMS over a store the file key still seals, which never
   opens, and `recover-secrets` refuses a KMS box by design), and `--accept-new-secrets-store` does not override that.

**Cancel, and the race it closes.** The first version asked the box once, then previewed, asked the person, and
took the grant away minutes later; a move starting in between left a KMS-wrapped store, a destroyed key file and no grant. Now
the check and the act are one step on the box. `ozbox adopt-fleet-key <box> --cancel` asks the box's root to run `ozbox secrets
adopt-cancel`, which takes the box's lock, writes a root-owned **cancel mark** (the compare-and-set: no move starts, finishes or
destroys anything past it, whatever the instance tags still say, so a tag that is slow to disappear cannot revive a move), and,
if the store had already moved, re-wraps it back under the file key **from the store as it is now** (so a secret written since
is kept; the grant is still there for that) and waits for the `/work` copy to follow. Only when the box's root then says the
service is ready on the file key, the store and the copy are file-wrapped, the settings name no KMS key, the key file is there
and the mark is in place does the laptop apply "remove the tag and the grant". A box that is busy, cannot take the store back
(a KMS that cannot be used, a key file that is gone) or says anything else keeps its grant. A later `adopt-fleet-key` takes the
mark away (under the lock) before it sets the tag again. A moment with neither tag (the laptop swaps its tags, and the provider
may delete before it creates) is never read as a cancel: only the mark is.

**What the laptop decides from: the box user's SSH answer is not an authority.** `ozbox adopt-fleet-key` used to
read the box's state over SSH as the box user, and the 0.1.1 review had already shown that user can forge it (`~/.bashrc` on
`/work` can replace `cat`, or the whole output). A forged `kek=kms` would have written the durable label for a box that had not
moved; a forged `kek=file` would have revoked the grant from a box that had. The two decisions that are lasting or destructive
(commit, and revoke) are now made from facts the box's **root** prints (`ozbox secrets adopt-status`: the service's state read
through the owner-and-mode check, the `kek` label of the store and of its `/work` copy, whether the key file and the copy
exist, the cancel mark, the lock, and the box's own read of its tags) and the laptop reads through **AWS Systems Manager Run
Command**, using **a document of the fleet's own** (`ozbox-adopt-<fleet>`, made by the `aws-adopt-command` OpenTofu module, a step of `ozbox init` of its own, because the key module's identity is KMS-only), not
the stock `AWS-RunShellScript`. The laptop sends the document's SHA-256 with every command (third review: the text lives in
`infra/tofu/modules/aws-adopt-command/adopt-document.yaml`, the program carries the same file, and the intent is that Systems Manager
refuses a document whose content is anything else, so a document someone in the shared account replaced is never run as root on a box).
That last claim is NOT yet proven: the SendCommand reference does not say what Systems Manager hashes, or that a mismatch is refused.
The module therefore checks, on the apply that makes the document, that the hash the system reports equals the SHA-256 of the file
(a postcondition), the real-box list has a send with a deliberately wrong hash that must be refused, and a refused send is reported as
"the document is not the one this ozbox carries: apply the module from the same release".
Its one parameter is an enum (`status`, `arm`, `cancel`, `cancel-from-copy`) that SSM validates
before anything reaches the box, and each value runs one fixed `ozbox secrets ...` program by absolute path; the parameter is
only ever matched in a `case`, never run. The output is made by the SSM agent running that program as root; the box user is
not in that path. The shape is strict (one head line, `ozbox-adopt-status=3`, seventeen fields, each a value the box writes; `names` is
the number of secrets the store holds, which `ozbox upgrade --use-fleet-key` rests on). A box whose program is older answers an
earlier head (`=1` or `=2`, which only a build before this release did) or knows no `adopt-status` at all; the laptop reads either as
"this box is older", not as a policy problem. An answer in any other shape is unknown and nothing is decided from it. A root channel that does not answer fails closed: nothing is changed, and the message
names the permission.

**`ozbox init`'s permission pre-checks are unproven against a real account (round 6; two findings fixed in code).** Each asks IAM to simulate the step's actions for the identity, and the action lists are held equal to the resource tables by tests. The adopt check simulates against the document's ARN (`document/ozbox-adopt-<fleet>`). The key check used to evaluate every action against both the key and the alias ARN with no context, so an identity holding only `OzBoxKeyAdmin` was told "denied" whatever its policy said (its tag conditions were false and a key action against the alias is an implicit deny). It now makes one simulation per resource type: `kms:CreateKey` against `*`, `kms:CreateAlias` against the alias and the key, and every other key action against `key/*`, each with the context the apply sends (`aws:RequestTag/ozbox-managed=true`, `aws:ResourceTag/ozbox-managed=true`, `aws:TagKeys=ozbox-managed`). A denied action in any request is denied, and a request that cannot run makes the answer unknown. Its action list is exactly the key module's create and read-back set (the key's table row without its update and destroy actions, plus `kms:CreateAlias`), which now includes `kms:GetKeyPolicy` and `kms:ListResourceTags`. A test evaluates `key-admin-policy.json` against the built requests with a small local evaluator and finds every action allowed under that context (and not without it). That shows the request shape is right; it does not show that IAM's simulator agrees. Whether the real simulation reads a resource-scoped Allow and the tag conditions the way the apply is evaluated is still not known until it runs with an identity holding only `OzBoxAdoptAdmin` or `OzBoxKeyAdmin`: R6-1 is fixed in code and unproven on a real account (the real-box item). A wrong "denied" skips the step with a message (nothing is made), and a wrong "allowed" is the half-made case the equal lists exist to prevent.

**Systems Manager is a root path, and who holds it.** Oz Box otherwise holds that the box has no root
shell, and root actions go through gated, signed admin commands. Permission to send `AWS-RunShellScript` is exactly a root
shell on every box, logged only in SSM history, so it is never asked for. The operator permission is the module's output
`operator_adopt_policy_json` (`ozbox init` writes it to a file and prints the path; an administrator attaches it): `ssm:SendCommand` on **that one document** (resource ARN
`arn:aws:ssm:<region>:<account>:document/ozbox-adopt-<fleet>`) and on instances tagged `ozbox-managed=true`, plus
`ssm:GetCommandInvocation` (it takes no resource restriction in IAM, so it reads the result of **any** Run Command in the
account, a deploy by another team included; attach the policy only to a principal used for nothing else until Oz Box has an account
of its own). `ssm:CancelCommand` is not in it: the delivery timeout already stops a command that would
start late, and a running move or cancel must never be killed part way. Whoever holds it can read a box's secrets-store facts and record or take away a cancel
on it, and can have it put its pre-move copy back (`cancel-from-copy`, which loses what was saved since); they cannot run
anything else. Attach it to the role or user that runs `ozbox adopt-fleet-key`, and to nobody else. The box's role already
carries the account's `ozbox-box-session-manager` policy (it covers the Run Command agent as well as Session Manager). A computer with no fleet configured has no document to send and says so.

The SSH answer is kept for courtesy checks only (is this a box that can do its part?), never to decide. **`ozbox upgrade`'s
store check is decided the same way on AWS:** a forged `kek=kms` used to read as "kept" with no label, and
a forged `tpm2`, or `file` with an escrow, still did. On AWS the store's fate (lost, kept by escrow, kept by this computer's keychain, already lost, unknown)
is now read from the box's **root** facts (the service's own state, including its escrow word, read as root), the SSH answer
decides nothing, and when the root channel cannot answer (no document, no permission, an older box) the store is "unknown",
refused without `--accept-new-secrets-store`, **never kept** by the box's word. The one exception is this computer's own keychain: a box whose key this computer holds a copy of (the ingress escrow, made on every box since the ingress route, all of which are older than the root read) is **kept by this computer** whether the root answers "older" or cannot be reached, as it was before the root channel existed, and the upgrade puts the key back (round 5; when the root does answer, the copy keeps the store only for a ready, file-kept one, and any other answer is "unknown"); the message never sends such a person to `--accept-new-secrets-store`. A box that answers the root facts is not a legacy box and has no
copy of a file-kept key on `/work`, so what its service does not say is "unknown" too: a service that is not
ready (restarting, `/work` late, stopped), or that says a file key with no escrow word, is refused without the flag, where the
SSH path's "not said" (a service so old it has no state) still lets the upgrade through once. A box whose program is older than
the check is said to be older (the Systems Manager failure's exit code and first line are shown), not blamed on the policy. The cloud's own label (`ozbox-secrets-key`) still decides first.
An unlabelled box whose root says `kms` is "unknown" too. Elsewhere (a box with no Systems Manager) the box user's answer is
still what the check reads, and that residual stands. Cost of this: an AWS operator who has not applied the fleet module's
document or does not hold the policy sees an unlabelled box as "unknown" and must accept a new store, even if the box's escrow
would have kept it.

**What a lost race leaves, and who puts it right.** Two operators, or a command whose delivery was
delayed, could still remove the tag and the grant after a box had moved, or put the cancel mark back over a move. The box
**never puts a store back by itself**: the first version did, after two sightings, and the third review showed that "no tag"
can be a failed read and "KMS gone" any probe error, and that the box user chooses when runs happen and could, by tightening
the egress list, make KMS unreachable: a rollback of secrets nobody asked for. Now: (1) the laptop reads the box's root facts
again right before each apply (Finish and Cancel) and refuses if they no longer say what they said a moment ago; (2) the SSM
delivery timeout (120 s) is shorter than the laptop's wait, which is now delivery plus the document's whole 900 s timeout and
a margin (1140 s), and nothing sends `cancel-command`: a command the laptop stopped waiting for either never starts or is a
cancel that must finish, and the laptop says it may still be running and to ask again; an access-denied on reading the result
is reported at once and not waited out; (3) a box with a moved store, its key file and its pre-move copy, and no cancel mark
is only **reported**: the facts carry `kms_probe` (`na`, `ok`, `denied`, `failed`), asked only in that state, and only the key
service's own access-denied answer is `denied` (a timeout, a spawn failure and a throttle are `failed`). A tag read that fails
on the box is not "no tag": the run changes nothing. `ozbox adopt-fleet-key --cancel` on a box with no label then puts the copy
back only when all of these hold: the box's root says moved-and-kept and `denied`, **the cloud's own tag list** (`ec2
describe-tags`, a read that worked) shows neither label, the person confirms and then **types the box's name** (`--yes` is
neither), and everything is read again right before. A cancel whose store cannot be re-wrapped back offers the copy under the
same conditions, and says why it does not when the probe says anything but `denied`. A refused `--from-copy` writes no cancel
mark; a cancelled one leaves the mark, and says so. (4) **KMS is allowed in the box's egress list once the store is moved**: `kms.<region>` on
https, for the region in the key the root-owned secrets settings name (so from the move on, not before it: a probe on a box whose
list was tightened first waits, which only delays the move), is added to every list whatever a request says (tightening
it, leaving the region out, another region, no `aws-control` preset), and counted among the hosts that must resolve before a
list is enforced, so the box user cannot cut the store off from its key. It is opened for every user of the box, not for root and the secrets user alone
(a known limit, and a real one: the box user holds no instance credentials, but it can reach the KMS endpoint with credentials of
its own, and `kms:Encrypt` under a key in **another account** is an exfiltration channel of about 4 KB a call whose plaintext that account
can read; it passes through a list in `enforce` with no approval, and the same holds for every runner user. The ruleset has no
per-user allow set yet, so **the per-user egress rule (S4, `meta skuid`: the endpoint for root and the secrets user only) must land before anyone relies on enforce mode** against an agent; the Systems Manager endpoints are not in the always list either). A settings/store disagreement in the file
direction is settled, from the files alone, before the tags are asked for. On AWS, `ozbox upgrade --use-fleet-key` is decided from
the same root facts (the service ready on a file key, and `names` zero), never from the box user's SSH answer.

**The metadata guard is checked at Begin.** With the key granted, instance credentials can open this box's KMS-wrapped
copy on `/work`, which travels in snapshots and backups. The box's root now reports whether `inet ozbox_metadata` is loaded
(`nft list table`), and Begin refuses a box where it is not.

**A store that is written often (N6).** The box now compares the live store with the bytes the copy was made from once more
before it stops the service, so a store that already changed costs no stop. A move abandoned because the store changed waits
before it tries again, longer each time (none after the first, then 15, 30, 60 and 120 minutes, never more than 4), counted
on tmpfs; `adopt-status` carries the wait and the laptop says it. **A service left stopped (N5):** the resume paths (waiting for
the commit, finishing, cancelling) start a stopped secrets service before they read its state file, whose last contents say
"ready".

**Why this and not the replacement route.** The other candidate was to give the new machine the key during an upgrade that
already accepts a new store. It would have started a KMS-configured machine over the old file-sealed copy of the store on
`/work`; the service reads that as a transient key-service failure and retries for ever, and Amendment 8's recovery accepts
only a file-keyed box. A box would be left with no secrets service. The in-place route has no such window, keeps the store, and
needs no new root-helper action (the box's own program does the move from a tag).

**What it needs on the box.** A program that carries this step; the service says so in its state file (`adopt=kms`), the root
helper must answer `ozbox secrets adopt-status`, and `ozbox adopt-fleet-key` asks before it changes anything. A box made on a
release without it (a 0.1.1 box) is refused with nothing changed, because a new program reaches a box only with a new system
disk: `ozbox upgrade` it first (accepting a new store if it says the store would be lost; the plan names what to enter again),
**to an image built from a release that includes this step**, then run the command, which keeps whatever the new store holds.
Every upgrade after that keeps the store. A box on today's image therefore loses its store once; the in-place route keeps it
only on boxes that already run this program. The real `main` box is such a box.

**Residuals, said plainly.**
- **The old key, escrowed in a vault, still opens every copy made before the move.** The re-wrap keeps the same
  data keys, so a key escrowed before the move plus any earlier `/work` snapshot or restic backup gives the plaintext of every
  secret not changed since. The escrow entry is not removed, and `ozbox secrets rotate-data-keys` on the box only protects values
  stored after it. The command's closing message says so.
- **A store's scope is the box's name.** The role's grant binds the encryption context to the box name and the key
  policy requires the fleet tag; one box cannot open another's secrets unless it has the **same name** in the same fleet (a
  destroyed and recreated `main`, or two operators each with a `main`). Not new (Amendment 8).
- **Systems Manager must be usable by the operator**, with the fleet module's document applied in the region and the policy
  above attached. Without it nothing is moved, committed or cancelled, and an upgrade reads an unlabelled AWS box as unknown.
- **A cancel mark is the only thing that stops a move.** An operator who removes the tag without a cancel leaves the box's pending
  state as it was; the box does nothing without a tag, and a half-moved box with no tag is brought to agreement by the reconcile
  step, not reverted.

**Also fixed.** The list of boxes dropped the secrets-key label for a running machine (only a stranded one kept it), so the
plan's "kept through the fleet's KMS key" line was unreachable; it is read like the other labels now. A move resumed on a box
that carries no fleet name now refuses (the key policy matches the fleet's tag; a guessed name would leave the box probing a key
it can never use) instead of falling back to a default fleet.

**Not built.** The dashboard has no button for it (the command is the route); its upgrade shows the same refusal while a move
is pending. Left from the review's Low list: redacted KMS error codes in the probe's message (L8), and a cancel that waits only for the
service to be ready (not per secret), which is right for a file key (local unwraps) and must not be "fixed" the other way
(N8). **Per-cache-miss KMS cost:** once on KMS,
each secret the secrets service has not unwrapped in the last 5 minutes costs one `aws kms decrypt` process (an estimate of
about 0.4 to 1.0 s each, in series; not measured), so the first `ozbox env run` that reads N secrets after a pause gains about
N times that, and a warm one gains about nothing; processes that open the store themselves (the tunnel units, rotate, the
probe) get no cache. No benchmark suite touches the secrets path (the benchmark's exec does not go through `ozbox env run`),
so no headline metric (Mastra cold install, Better-Auth build, Git operations) should move; this is a user-visible latency, not
a benchmark one, and it is to be timed on a real moved box (1 and 5 secrets, cold and warm) and recorded with the release.
Nothing here is proven on a real box: the instance's tag refresh after a change, how long the grant takes to reach the machine,
Run Command's latency and the operator's permission (the custom document, its enum, the tag condition), that an in-place plan
from a real box carries no `after_unknown` attribute beyond tags (the allowlist counts one as a change), `stat /work` (root,
0755), that the `nft list table` check answers as root, how long the stop window really is with a store of 20 or more secrets,
`runuser` and the `aws` CLI working from the transient unit, and the encryption-context match are what only a real box shows.

## Amendment 12 (2026-11-13): a server can receive a secret, a declaration can name public settings, and a one-shot run has a real time limit

A real box (Ubuntu 24.04, systemd 255, Oz Box 0.1.1-alpha.0) ran Amendment 10's declaration and found four things. This amendment
states the threat model of the two new capabilities first; the code follows it.

**1. The one-shot unit used a property systemd does not have.** The launcher set `TimeoutRunSec=1800`. `systemd-run` refuses a unit
with an unknown property ("Unknown assignment"), so every one-shot `ozbox env run` failed on that box. The 30-minute limit is
`RuntimeMaxSec=1800`. A test now reads every `systemd-run` argument list the program builds (one-shot, secret command, browser
command, service, browser worker) against a list of property names systemd defines, so a misspelt name fails CI. *Limit:* that proves
spelling. Whether systemd 255 accepts each value is shown only on a real box (see the real-box list below).

**2. A declared service can receive secrets (replaces Amendment 10's "never given a secret").**

*What was wrong with the old rule.* A development server that talks to a backend needs a key, and the rule left it with plain
variables only. The reasons for the rule were real: a unit that outlives the launcher has no standard input to carry a secret on, and a
secret as a unit property (`Environment=`, `SetCredential=`) is shown to anyone who can run `systemctl show`.

*Mechanism.* systemd's `LoadCredential=NAME:PATH`. The launcher (root) writes each secret the declaration names, under the name the
service will see, as a file in `/run/ozbox-cred/<unit>/<nonce>/` (a folder of this start's own, named by 16 random hex characters, so two
starts never share one; the folders mode 0700, each file 0400, all root's), starts the unit with
`LoadCredential=NAME:/run/ozbox-cred/<unit>/<nonce>/NAME` and, once `systemd-run` has returned (the unit is `Type=exec`: systemd has run the
program, so the credentials are loaded), **deletes the files and the folder**, whatever the outcome. The unit property holds a path,
never a value. systemd copies each credential into the unit's own credentials folder (`$CREDENTIALS_DIRECTORY`), which only the
unit's user can open and which systemd keeps in memory. The secret is never an argument, never an `Environment=` line, never in
`systemctl show`, and never in a file the agent can read.

*Review round 2 (2026-11-13).* (L1) A launcher killed between staging and clearing would leave the files in `/run`. A start now first
sweeps every start folder older than two minutes, and the runner setup removes every staged folder of the project (its services are
stopped by then). (L2) A start stages in its own nonce folder and clears only that folder; a `--stop` clears the unit's whole folder.
(L3) `/run/ozbox-cred` is in the units' `InaccessiblePaths` (`-/run/ozbox-cred`, the `-` so a missing folder is no error). This does not
stop the credential from loading: systemd opens the `LoadCredential=` files in the manager, as root, while it sets up the unit's
execution (credentials are placed first), and enters the unit's mount namespace afterwards, so the hidden path is never looked for by
the unit. That is the documented order, and it is step (b) of the real-box list, which must still pass with the path hidden.

*Per command and per environment, and nothing looser.* A service that receives a secret meets **every** rule a one-shot secret
command meets, and the launcher applies them to `--start` exactly as to a run (until now every one of them was behind "run"): the
declaration is validated at launch, the caller names an environment that the declaration's `envs` lists, the program is a pinned
`node FILE` whose imports are all pinned (`check_code`, before any secret is looked up), writable folders are real folders, a value
that holds a production identifier is refused, and a value flagged production is never delivered. The service runs as the
command's **own user** (`secret_runner_user`, the user no other command shares) in the private view of `/work`, not as the project's
shared runner. What it prints in `--status` has every stored value of the project removed.

*systemd's own names are reserved (M1).* A declaration may not set `CREDENTIALS_DIRECTORY`, `RUNTIME_DIRECTORY`, `STATE_DIRECTORY`,
`CACHE_DIRECTORY`, `LOGS_DIRECTORY`, `CONFIGURATION_DIRECTORY`, `INVOCATION_ID`, `NOTIFY_SOCKET`, `MAINPID`, `JOURNAL_STREAM`,
`WATCHDOG_*`, `TRIGGER_UNIT`, or any `LISTEN_*`, `SYSTEMD_*`, `MONITOR_*`, `EXIT_*`, `SERVICE_RESULT`: systemd lets `Environment=`
override its own variables, and a redirected `CREDENTIALS_DIRECTORY` would have pointed the `exec-cred` step at a folder the agent
wrote. The same list is applied inside the `exec-cred` step to every credential name (such a name is refused, not exported), and the step
reads only a `$CREDENTIALS_DIRECTORY` that is a real directory (no link anywhere on its path) directly under `/run/credentials/`,
owned by root (or by the unit's own user, which is how systemd hands the folder over on a file system with no ACLs) and writable by
nobody else.

*Reading it.* The program reads `$CREDENTIALS_DIRECTORY/NAME`. A program that expects an environment variable declares
`"credential_env": true` on the service, and the launcher starts it through `ozbox secrets exec-cred -- PROGRAM ...`: a small step
inside the unit, run as the same user, that reads each file of `$CREDENTIALS_DIRECTORY`, sets it as a variable of that name and
becomes the program (standard input closed). After that step the secret is in the process's environment, which only the command's own
user can read (`ProtectProc=invisible`, `PrivatePIDs` where systemd has it), exactly as for a one-shot command: the credentials
folder is the safer form, and a program that can read the file should.

*What this does not close, and does not claim to.*
- **The agent can drive the server.** The service listens on the box's loopback, which the box user (and so the agent) can reach. A
  server that does something with its key when asked (a request that makes it call the backend) does it for the agent. A secret
  service is for a program whose requests the agent may make with that key, as with a one-shot command it may start.
- **A service's route out is a unit and a kernel rule, unproven on a real box.** (Part 5 above replaces "a service has no outbound
  route".) A service that holds a key reaches the project's declared hosts only, through its own proxy unit; the launcher still ends
  when the unit starts, which is why the proxy is a unit of its own. Which user may connect rests on an `nftables` rule that no test
  here can run.
- **A server's own output goes to the journal.** The launcher redacts what `--status` returns; it does not filter the journal. Whether
  the box user can read the journal is a real-box check; a server that prints its key is a server that leaks it.
- **The file exists briefly.** `/run` is a memory filesystem, and memory can be swapped. The window is from the write to the end of
  `systemd-run` (a start of a few hundred milliseconds), the folder is root's, and the unit runs as another user. A box whose swap is
  not encrypted is outside what this claims.
- **A secret service is a pinned `node FILE`.** The same rule as a one-shot secret command, deliberately not relaxed: a package
  script (`npm run start`) is not covered by a pin. A server that needs one cannot receive a secret yet.

**3. Public settings.** Some values a server needs look like secrets and are not: a project's public URL, and a hosted backend's anonymous
key, which is a JWT and is public by design (every browser that loads the app receives it). Amendment 10 refuses a plain variable that
looks like a key, correctly: it cannot tell the two apart, and no value-only rule can.

*An explicit, reviewable mark, never inferred from a value.* `ozbox secrets import --public NAME` (repeatable) stores that value with
a `public` flag in the entry (see "Where the mark lives" below). The preview and the box's audit line show which names were marked
(names only), and the import goes through the same approval as any import. **On a box with no second factor enrolled yet a mark is
refused** (a public value cannot be handed out before enrolment, and a mark planted now would outlive it): import it as an ordinary
value, or enrol first. A declaration then names `"public": ["NAME", ...]` on a command: the names are
part of the declaration, so the `policy` approval covers them. At launch the secrets service hands over a name only if it is in the
command's `public` list **and** the stored entry is marked public **and** not production, and the caller's environment is one the
command's `envs` lists. The value is delivered as plain environment (on the unit's standard input for a run, as an `Environment=`
property for a service). Redaction still removes it from what the launcher returns.

*What the mark does not do.* It does not make a secret public:
- **A mark is an allow-list (owner decision, 2026-11-13).** A value can be marked public only if it is a known public kind: a JWT whose
  payload, parsed, says `"role":"anon"` (any other role, an unreadable payload, an odd header and an escaped `service_role` are all
  refused); a value with a known public prefix (`pk_test_`, `pk_live_`, `sb_publishable_`, `phc_`); or plain text (a URL, an id, a
  word) that the key-shape rule does not flag. Everything else is refused, including every kind that is only ever secret (`sk_`,
  `sk-` (so `sk-ant-` and `sk-proj-`), `rk_`, `whsec_`, `ghp_`, `gho_`, `ghs_`, `github_pat_`, `glpat-`, `xox`, `xai-`, `AKIA`, `ASIA`,
  `sb_secret_`, `sbp_`, `npm_`, `SG.`, `re_`, `hf_`, a PEM block), a name that says secret (`SECRET`, `PASSWORD`, `TOKEN`, `PRIVATE`,
  `CREDENTIAL`, `SERVICE_ROLE`) and a production-looking value. The check runs at import **and again when the value is handed out**,
  so a rule added later also covers a value stored earlier.
- A value that is secret-shaped and **not** marked is still refused as a plain variable (Amendment 10), and is still delivered only as
  a secret.
- A public value is plain text: 1 to 2048 characters of `[A-Za-z0-9._:/@+,=-]`, so it needs no quoting where it travels, checked again
  at launch. A box that does not answer `public_values` in `capabilities` is not sent a mark (it would drop it and store a secret
  as if it were not marked): the laptop says the box needs an upgrade.
- **Where the mark lives.** The mark is inside the seal: an entry marked public is sealed under a different additional-data string, so
  flipping `public` in the store file without the store key makes the entry stop opening (it is never delivered, as public or as a
  secret); the flag in the file only tells the reader which form to try. An entry with no mark is sealed exactly as before, so every
  older store stays readable, and stays secret. A re-import without `--public` re-seals it as an ordinary secret. An older program
  reading a marked entry cannot open it, which fails closed.

**4. Tools.** A declaration with `"tools": ["node"]` puts the project's root-owned copy of the catalog's Node first on the PATH of
every command and service of the project (`/opt/ozbox-run-tools/bin/<project>`), so no absolute path is written. This was built
in Amendment 10 and is now pinned by a test that the PATH of the unit and the folder the setup fills are the same, and has a step
on the real-box list.

**Contract changes.** `Policy`: command fields `credential_env` (service only, with secrets) and `public` (names); a service may carry
`allow`/`env`. Both new fields are left out of the stored form when empty, so an older declaration keeps its bytes and the digest an
approval covers. `Meta.public`, `ImportLine.public`, `resolve` with `public`, `capabilities.public_values`, `ozbox secrets exec-cred`
(hidden, started only by the launcher).

**Benchmark.** None of this is on a measured path: no box create, resume, snapshot or destroy, no `exec` of the agent, no disk, network
or image change. Only a service start with secrets gains one root write of a few small files in a memory filesystem; no headline metric
moves.

**To prove on a real box (systemd 255, Ubuntu 24.04).** (a) `systemd-run` accepts every property the program emits, a one-shot run
completes and is stopped at 30 minutes (`RuntimeMaxSec`); (b) a service with a secret starts: `LoadCredential=` from `/run/ozbox-cred`
is read by systemd although the unit's own view hides other paths, the program reads `$CREDENTIALS_DIRECTORY/NAME`, and with
`credential_env` sees the variable; (c) `systemctl show <unit>` and `systemctl cat <unit>` contain the path and never the value;
(d) `/run/ozbox-cred` is empty after the start, after a failed start, and after `--stop`; (e) the box user cannot read the unit's
credentials folder, `/proc/<pid>/environ` of the service, or its journal (record which of the three it can read); (f) a service
refused by `envs`, an unpinned file or a production value never writes a credential; (g) a public value reaches a server as plain
environment and `systemctl show` shows it (it is public); a marked key that is a service-role JWT is refused at import; (h) a project
with `"tools":["node"]` and no absolute path runs `node --version` from the pinned copy.

### Amendment 12, part 5 (2026-11-13): a secret-holding service has a route out to its declared hosts only (the per-service egress proxy)

*Owner decision: "Yes, build it", for the next release. Until now a service that holds a key (a test server with a Stripe TEST key) could
reach this machine's loopback and nothing else, so it could not call the API the key is for.*

**The threat.** A 4-hour route is not a one-command route. A loopback proxy that lives for the length of one command is reachable by
the box user and every other project's commands for that command only; the same proxy kept for 4 hours is reachable by all of them for
4 hours, and the agent can use it to send data to a declared host. What may be reached is therefore two things: where (the project's
exact hosts, so a public URL cannot steer a key somewhere else) and by whom (only the service).

**The invariant.** The route's ports are **held and guarded before any service process exists, and released only after the last one is
dead**, on every path: a start, `--stop`, `RuntimeMaxSec` expiring, the service exiting on its own, the proxy crashing, a setup change, a
quick restart, and a launcher killed part-way. A rule that says who may *connect* is not enough: if the port is free while the service
runs, anyone can *listen* on it, and the service's own traffic (a tunnel carries no TLS check of ours) goes to them.

**Design.**

1. **Three units, one job each.** `ozbox-egress-<project>_<command>` is a transient **socket** unit made by
   `systemd-run --socket-property=ListenStream=127.0.0.1:<port>`: PID 1 binds every port of the route and keeps them for as long as the
   socket is up, whatever happens to the proxy. Its privileged `ExecStartPre=+nft -f` loads the firewall table before the ports listen and
   its `ExecStopPost=-+nft delete table` removes the table after the last user is gone. The same name's **proxy** service takes the
   sockets from `LISTEN_FDS` (`ozbox-listenfd`) and never binds; it is started **explicitly** by `systemctl start`, and `Type=notify` makes
   that call return only once the proxy has said READY, so the service is never started before the proxy listens and a proxy that
   fails fails the start. (`--socket-property` alone would start the proxy on the first connection, which gives up the READY gate, the
   firewall's order and "a dead proxy fails the service".) The proxy is `BindsTo=` and `After=` the socket. The **service**
   (`ozbox-svc-<project>_<command>`) is `BindsTo=` and `After=` both, and its `ExecStopPost=` queues `systemctl stop --no-block` of the
   proxy and then of the socket; systemd runs the socket's stop only after the service's own finishes, so the ports are released after the last
   service process is dead. `--stop` is blocking, under a per-service lock: the service first, then the proxy and the socket in one call.
   The proxy is `PartOf=` the service, has a limit of its own (the service's plus five minutes), and is `TasksMax=576`, `MemoryMax=256M` and
   `IPAddressDeny=` for the private, link-local and shared ranges. A connection cap of 256 bites before the task limit.
2. **A lost listener ends the proxy.** An accept loop that ends for any reason but its proxy being dropped ends the program with a non-zero
   status, so the service bound to it stops while systemd still holds the ports. A thread that cannot be made drops that one connection
   (it used to panic the accept loop and free the port with the unit still up).
3. **Only that service can use it, twice over.** `HTTPS_PROXY` has to be `http://127.0.0.1:<port>`: Node, curl and the usual SDKs take no
   proxy on a Unix socket, a relay in the service's unit would be a loopback port again, and a password is readable by every user of the
   box (`systemctl show`). So a kernel rule (`meta skuid != <the service's ozrc- uid> ... reject with tcp reset`, in an `inet` table at
   priority -5) refuses every connection to the route's ports from any other user, **and the proxy checks the same for itself**
   (`--uid`): for every accepted connection, the HTTPS ones and a tunnel's, it finds the client's socket in `/proc/net/tcp` and `tcp6`
   (including `::ffff:127.0.0.1`) and refuses unless its owner is the service's uid, and refuses when no line, or two lines that disagree,
   match. So a ruleset that is flushed (Ubuntu's default `nftables` configuration starts with `flush ruleset`), deleted or replaced does not
   open the proxy to the box. `sock_diag` was not used: it needs a netlink socket. The table is named by its **unit**, not its port (a
   reversible encoding, so a sweep can tell whose a table is), and each start writes its own rules file, created new, so two starts never
   load each other's rules. The `ozrc-` user is one only that service uses, which is what makes the uid mean "the service". The service keeps
   `IPAddressDeny=any`.
4. **The launcher sets the environment.** `HTTPS_PROXY`, `https_proxy` (an address with no credentials) and `NO_PROXY` are `Environment=`
   properties added once the ports are known; the names stay reserved for a declaration. `HTTP_PROXY`, `http_proxy` and `ALL_PROXY` are
   **not** set: a plain `http://` request through the proxy is a 405, and a client that wants https reads `HTTPS_PROXY`. `NODE_EXTRA_CA_CERTS`
   and `SSL_CERT_*` are not set either: TLS passes through to the declared host. A program has to honour the proxy variables.
5. **The same rules as a one-shot secret command.** The proxy is `egress::start_open_on`: a listener it is handed and no
   `Proxy-Authorization`, otherwise the one-shot proxy's code, with exact hosts only (a project that has a secret service cannot declare
   a wildcard, and the proxy refuses one in depth), the public-address check and the TLS hello check. **A service that holds no secret
   has no route** (its network stays closed), whatever the project declares.
6. **Raw `tcp` destinations are not given to a service yet.** The tunnel code is built and tested, with the same uid check and the
   same held port, but a service that receives secrets in a project that declares `tcp` is **refused with a message** until the port-squat
   regression of the list below passes on a real box; the switch is the constant `SERVICE_TCP_TUNNELS`. A one-shot `ozbox env run` still gets
   its tunnels. A tunnel carries a wire protocol with no TLS check of ours, so it is the one thing a squatted port would hurt most.
7. **Unit names cannot collide.** Units are `ozbox-svc-<project>_<command>` and `ozbox-egress-<project>_<command>`: a project or command
   name cannot contain `_`, and under the earlier hyphen name `a-b` + `c` and `a` + `b-c` were one unit. `--stop`, `--status` and `--start`
   still look for the earlier hyphen name, so a service that was running at the upgrade is found, stopped and never started twice;
   setup stops it through its user.
8. **One start or stop of a service at a time.** Each takes an exclusive `flock` of its own for the whole action (the launch lock is let go
   after every call), and a start is refused unless the service is idle under both names. A start also sweeps what a launcher killed
   part-way left (a socket or proxy whose service is not running, a stale firewall table, a rules file over a minute old), skipping any
   route whose service holds its lock. Setup stops **services first, then routes**, and its globs end in `_` so no other project's unit is
   touched.
9. **The guard covers the new properties.** `systemd_run_route_argv` and a service with a route are read by `systemd_props_guard`,
   including the `--socket-property=` names. As always, that proves spelling; whether systemd accepts each value is on the real-box list.
10. **Production stays out.** A route does not change what a service may receive: `resolve` still refuses a production key, `production_hit`
   still runs on every secret and public value, and the route is planned and started only after they pass. No "service" exception was
   added to the per-use approvals the owner requires.

**What changed in the start.** `--start` now: takes the service's lock; checks, resolves and refuses as before; refuses a `tcp` declaration;
sweeps other routes' leftovers and this one's; plans the route (rules, the service user's uid, free ports other than the service's own);
writes the ruleset; starts the socket unit (ports held, table loaded); starts the proxy and waits for READY; takes setup's launch lock
again (so a declaration applied in between is seen and the service never starts under the old one); stages the credentials; starts the
service. Every failure after the socket exists stops the service (if it was started) first, then the proxy and the socket.

**What this does not do.** The rule limits who reaches the port; it does not make the service's own traffic harmless: the box user can still
reach the service's port, so the agent can make the server call a declared host with its key (the same as before, now to the declared
hosts, and exact-host egress is what bounds where). A program that opens its own connection to a non-declared host cannot (no route). The
route needs `nft` on the box and `DynamicUser=` support. A **network namespace per service** (the service and its proxy on a private
loopback that no other process shares) would remove the shared-loopback problem altogether; it is recorded here as a future option, not built.

**To prove on a real box (unproven until the real-box run; none of it can be shown off a Linux box with systemd 255, nft and a kernel of
5.13 or later).**

1. `systemd-run` accepts every property of the three units: `--socket-property=ListenStream=` (several), `--socket-property=ExecStartPre=+`
   and `ExecStopPost=-+`, and for the proxy `Type=notify`, `NotifyAccess=main`, `DynamicUser=yes`, `BindsTo=`, `After=`, `PartOf=`,
   `TasksMax=`, `MemoryMax=`, `IPAddressAllow=` and `IPAddressDeny=`, and for the service `BindsTo=` and `After=` with two names and two
   `ExecStopPost=`. If it cannot make a socket unit this way, the fallback is an input-hook rule that ties the ports to the proxy unit's
   cgroup (`socket cgroupv2`); it shares the table's weakness, so it would not replace item 9.
2. `systemd-run` returns once the socket is up and does **not** start the proxy; `systemctl start <unit>.service` returns only after READY and
   hands the proxy its sockets as `LISTEN_FDS` in the order of the `ListenStream=` lines.
3. `+` lets `nft` load inside the socket unit, and the table exists before the ports listen. A bad ruleset, a missing `nft` or a port held by
   another user each fail the start, and the service is not started.
4. `curl -x http://127.0.0.1:<port> https://<declared host>` works as the service's user and gets a reset or a closed connection as root, as
   the box user and as another project's user, over `127.0.0.1` and from a v6 socket to `::ffff:127.0.0.1`.
5. A capture of `/proc/net/tcp` and `tcp6` from that box matches the format the parser's fixtures were written from (the owner column, the
   byte order of each word).
6. The service reaches a declared host and not an undeclared one, and cannot connect out directly.
7. `systemctl stop` of the service, its `RuntimeMaxSec` expiry (a short test limit), the program exiting by itself and the proxy being killed
   each end with no `ozbox-egress-*` unit, no `ozbox_egress_*` table and no rules file, and with the socket released after the service.
8. **The port-squat regression (this is what holds raw tcp back).** Kill the proxy with SIGKILL as root, and exhaust its tasks, and in
   each case try to bind the route's ports as the box user while the service is stopping: every bind must fail until the service is gone. A
   socket unit that itself fails would release them; this is the step that shows whether it can.
9. Delete the table by hand, then `systemctl restart nftables` on Ubuntu's default configuration: the proxy still refuses the box user.
10. Two `--start` calls at once give exactly one service, one proxy and one table, or one clean refusal.
11. A `--start` with a route left behind (kill the launcher after the socket is up) sweeps it; a stale table and a rules file are removed.
12. A setup that changes the declaration stops the service before its route, and does not touch another project whose name starts the same.
13. `--stop` and then `--start` at once works, and the old service's queued stops never stop the new proxy.
14. A service started under the earlier hyphen name before the upgrade is found by `--status`, stopped by `--stop`, and refused a second start.
15. The proxy's own network floor does not break name resolution on the box (the stub resolver on loopback is allowed; a resolver on a
    private address would need an allowance), and `fib daddr type local` is tried in place of `ip daddr 127.0.0.1` in the rule.

The Rust tests read the argument lists, the ruleset text, the order of the launcher's calls on every path, the proc-file parser, the refusals
and the migration from the old names; they do not run systemd, nft or the kernel's uid match.

## Consequences and what is not covered

*(Rewritten with Amendment 6, so this list stays true.)*

- Production keys are no longer storable in the box's store; `ozbox secrets import` of a Production-looking key becomes
  `ozbox secrets register` (a signed record on the box, the value in the vault, read only by the off-box issuer, or in the
  laptop keychain). Existing at-rest Production keys (there should be none: ADR 0018 refuses them) are reported by
  `ozbox secrets status`.
- **Root on a running box** gets at most what one approved session is using, for at most that session, and the chain and the
  issuer's own record show it. **The data a key can reach is exposed to the agent for the session** (accepted with limits: the signed least-privilege
  allow-list is the control, and every approval card says so).
- A person with the owner's passkey or laptop key can approve a harmful use; the card shows the exact argv, commit and
  attested run, and the least-privilege role is what limits the harm.
- **Unattended Production use is not offered.** There is no sealed Production key and no standing Production grant for a schedule
  or trigger.
- **Production works only where there is an issuer** (AWS, or OpenBao with its sidecar) **or with the laptop home.** A user with
  only an encrypted bucket has the laptop home for Production.
- **Passkey approval needs the vault home; the laptop home needs the laptop to be online** while the session runs.
- TLS interception for injection means the per-command CA is a sensitive file; it is made per use, held in the injector's
  memory, and trusted by the one command only.
- Protocols other than HTTPS and Postgres have **no Production delivery**; they are refused, not offered raw.
- Allocation by engine or run kind is **not a boundary for Production** until runs have separate uids.
- GitHub access is bounded standing access within an allocation (one-hour tokens), not a Production approval.
- A file-KEK box keeps its store across a rebuild only through the escrow of its key (the vault, or the laptop keychain through
  the ingress account, Amendment 9); with no escrow it recovers from the vault. KMS or a TPM keeps it without one. `ozbox upgrade`
  says which before anything is replaced, and refuses to lose a store unless the person accepts it (Amendment 8).
- A laptop signer without proven user presence (a software key, which includes a Secure Enclave key until a proof and verifier
  are named, ADR 0041 §3) is refused for Production, with no override; browser credentials are outside this record.
