# 0018 — Secrets are encrypted at rest, held by a separate user, and out of an agent's reach

**Decision.** A key, token or password is safe only if no agent process can read it, at rest or in use. Agents, and
everything they start, run as the box user, so "readable by the box user" is the same as "readable by an agent". Disk
encryption helps against a stolen disk and nothing else. The design below is for the box; a laptop keeps using the
operating system's keychain.

1. **Envelope encryption, no plaintext store.** Every secret has its own random data key. The value is sealed with
   AES-256-GCM under that key and the data key is wrapped by a key-encryption key (KEK) that is not on the disk beside
   the ciphertext. The seal's associated data is the store's id, the box or fleet it belongs to and the secret's name, so
   a ciphertext cannot be renamed, copied into another store or moved to another box and still open. The old plaintext
   file store is gone: a file in that format is encrypted on first start, the plaintext is overwritten and removed, and
   the migration is recorded.
2. **Where the KEK lives.** On AWS, one KMS key per fleet, reached with the `aws` CLI (ADR 0008: no SDK). The plaintext
   data key travels on the tool's standard input, never in an argument list or a file. The key policy lets a box's
   instance role use the key only for secrets whose encryption context names that box, lets the operator's roles use it,
   and lets the account root administer it but not decrypt. On a laptop the KEK sits in the operating system's keychain.
   On a server without KMS it is sealed to the machine's TPM, or derived from a passphrase an operator types at start and
   never stored. If the KEK cannot be reached every call fails closed with one plain message; nothing falls back.
3. **A separate identity on the box.** The store and the service that opens it belong to a system user with no login and a
   private home. The box user is not in its group. Only one socket's directory is open to the box user; through it a
   process can write a secret, ask whether one exists, ask for the keyed tag of a token, and read back a short, shrinking
   list of the dashboard's own sending keys. It can never read back a tunnel token, a backup key, a workload
   secret or the internal keys. A second socket, for the box agent's runner, only resolves `{{secret:NAME}}` references
   from a command's allow-list and refuses production-flagged keys. A third, for root, does everything. Who may connect is
   the file permission of the socket's directory (each socket is in its directory's group: ADR 0028, Amendment 1), so no
   access decision rests on peer credentials and there is no `unsafe`. The audit service reads the peer's uid (`SO_PEERCRED`,
   safe Rust) only to name the user on a chain line.
4. **Programs that need a secret are run by the secret's user.** `ozbox secrets exec` opens a secret and puts it in the
   child's environment, which only that user (and root) can read. The tunnel connector runs this way. The box user cannot
   replace that program (it is root-owned), attach to the process (Yama ptrace scope), or read its core.
5. **Internal tokens are keyed, not just hashed.** Session ids, setup codes, tickets and code-session ids are random
   256-bit values stored only as HMAC-SHA256 under a server key held in the store. The key rotates; the previous key keeps
   working for an overlap window, and a session found under it (or under the plain hash older versions wrote) is moved to
   the current key on use, so rotating or upgrading signs nobody out.
6. **Rotation.** The KEK, every data key and the internal-token key each rotate with one command, with tests. Each secret
   records when it was created and last rotated; listing shows names and ages, never values.
7. **Workload secrets fit the same store.** A `.env` key is a secret scoped by project and environment, with an owner and
   a production flag kept beside it (not inside the seal, so listing needs no key). Resolving a reference needs the name on
   the command's allow-list and refuses a production key.

**Why.** Before this the box held one plaintext file readable by every program of the box user, the tunnel token and the
backup credentials sat in files the box user could open, and session ids were plainly hashed. A prompt-injected agent could
read all of it.

8. **Workload commands run as a user of their own.** A command that needs a project's keys is started by a root launcher
   (a socket-activated unit; the box user may connect, nothing else) as `ozbox-run-<project>`, in the project's folder,
   with only its build folders writable, `/proc` of other users hidden and the service's own directories out of view. The
   values reach it through a root-only file the service manager reads, never through an argument, and the answer is the
   command's output with every known value of the project removed. The agent never shares a uid with that process, so
   `/proc/<pid>/environ` and a ptrace attach both refuse it. What a named command may receive, the program it must start
   with and where it runs come from the project's declaration in the store; a list given on the command line is ignored on
   a box. A reference to a secret in an argument is refused, because an argument is visible to every user.
9. **Run tokens are issued only to the supervisor.** `ozbox serve` claims a secret from the service when it starts, holds
   it in memory only and shows it with each request that issues a token or changes the model settings. The claim is kept
   while the supervisor proves it is alive and passes to the next claimant after 45 seconds of silence, so a restart
   recovers by itself. There is no peer-credential code and no `unsafe`.

**Consequences and what is not covered.** ADR 0023 closes the four gaps this list used to name: the supervisor now has a
user of its own, a command's network is limited to the hosts its project declares, replacing a secret or a declaration
needs a fresh second factor, and a commit holding a stored key is stopped. What remains:
- Until a second factor is enrolled, a box accepts some changes and records them as `bootstrap`: which ones is one table,
  scope by scope (ADR 0028, Amendment 2); naming an approver and loosening a box's own guards are refused. A laptop has no
  second user, so the claim still raises the bar there without closing the gap.
- The dashboard's own sending keys (chat and email tokens) are readable by the supervisor, not by the box user; the
  credential broker will take them over and the list shrinks to nothing.
- Model keys are not readable by the box user. The credential broker (ADR 0017) runs inside the secrets service and
  issues run tokens over its own socket. Only the supervisor can ask for a token (ADR 0023); a key is only ever sent to the address it was first used with: a
  provider whose address changes is refused until its key is saved again.
- Backup credentials live in the store. The daemon asks the service to run a few exact restic commands and gets output
  with every credential removed; the service holds the file capabilities restic needs to read and restore `/work`.
  What an upgrade must not lose is kept apart from them: a record that backups were set up, and the non-secret settings
  (what is backed up, how often), live in a root-owned folder on `/work`, written by the same root helper from root's own
  config, so the box user chooses none of it. The self-test fails when the record says backups exist and the credentials or the
  repository are gone, so a new store that starts without them is a loud failure, never a silent stop.
- The web IDE connector's token is stored and the connector runs under the secrets user, like the dashboard tunnel's.
- Replacing or removing a tunnel token goes through the root helper, which asks the service to spend a fresh approval
  from the dashboard (ADR 0023) before it stores anything, and records how it was allowed.
- Workload secrets can be imported (with an approval once a second factor exists) with a preview that shows no value, and a
  command receives only the names it is allowed, as a user of its own, on a closed network; what it prints has known values
  removed.
- An overwrite-then-delete of the old plaintext file is best effort on a journaled or flash disk. The disk is encrypted and
  the migrated values should be rotated with their vendors when that matters.
- (ADR 0028) The secrets service now also writes the box's audit chain, keeps its seal key in this store, and records its own
  actions (tokens, resolves, approvals, imports, declarations, loads). A laptop key can mint approvals. On Hetzner the box's
  own secrets are declared through a settings file, and the vault token reaches the loader through a root-only file.
