# 0011 — No sudo for the box user; one narrow, audited root path

**Decision.** The box user (`ozbox`) has no sudo, no password and no root shell, on the Oz image and on a machine set up from
stock Ubuntu. A box has no inbound port (ADR 0005) and the operator's cloud permissions allow SSH only as the box user, so
nobody has a root path by default. Root work that a person can legitimately need is done through one fixed path instead:
`ozbox admin <box> -- <action>`.

- The actions are a short list, enforced twice (by the program before it contacts the box, and by the root helper on the
  box): `reown` (put the box user's files on `/work` back under the box user), `reinstall-ozboxd` (install the box agent
  again from the signed image release and restart it), `restart-services` (only the box agent and its helpers) and
  `collect-logs` (bounded, read-only) and `enable-linger` (let the box user's own `systemd --user` services start at boot, for a box made before first boot did it). There is no shell, no path and no command in a request.
- The hand-off is a sticky request directory the box user can only add to, and a root-owned systemd service started from it.
  The helper checks that the request file belongs to the box user, accepts plain words only, runs the action, writes the
  answer where the box user cannot alter it, and records the request (action words and result, never file names or
  contents) in the journal and in a log file.
- The helper does **not** depend on the box agent. It is how the agent is put back when it is missing, so it is plain shell
  written by first-boot configuration, not part of `ozboxd`.
- Like every change it is shown first and confirmed (`--dry-run`, `--yes`; ADR 0002).

**Why.** Removing sudo keeps a stolen session, a malicious tool or a confused agent from becoming root. But a box that cannot
be repaired by anyone is a worse failure, and the first real upgrade showed two: an image without its agent, and files on
`/work` that the box user could not read. Each fix needs root exactly once and for one known job.

**Cost.** A new kind of repair needs a new action, a code change and a release. That is the point: the list is reviewed, not
improvised. A person with their own cloud-level access (for example a console session) can always do more; this path is only
what Oz Box offers by itself.

## Amendment 1 (security review, 2026-11-10): the box user is also where an agent runs

The helper accepts any request the box user files, and an agent runs as the box user. A security review (2026-11-10) found
actions that trusted the request as if it came from the owner. Each now holds on its own:

- **`reown`** takes a given `--from-uid` / `--from-gid` only if it is 1000 or more, not `nobody`, and not one of the box's own
  service accounts (the secrets user, the supervisor, the metadata user, any project runner), checked by the helper and again,
  by name, by the script; the script never picks such an id on its own either. A restored secrets store can no longer be
  handed to the box user.
- **`host-guard`** changes that let the box do more (the egress list loosened, a restart rule) need a fresh approval the box
  user cannot make, checked by the program (ADR 0034 and 0035, Amendment 1 of each).
- **A token file** (`replace-tunnel-token`, `place-bao-token`) is opened once, without following a link and without waiting on
  a pipe, checked on the opened descriptor (a plain file of the box user's, one name, small) and read from it, then removed
  (`ozbox host-guard take-file`, which can name only `<id>.tok` in the requests folder, and which no request reaches: the helper
  passes only `egress`, `patch` and `metadata` to `host-guard`). Checking the name and reading it again was a race the box
  user, who owns the file, could win with a link to any file root may read.
- **`collect-logs`** blanks bearer tokens, quoted values under a key that names a credential, and the known token prefixes in
  everything it returns, since the box user receives it.
- **`reinstall-ozboxd`** also installs the metadata guard (ADR 0029, Amendment 6 §2) on a box made before it.

The request file itself is still checked by name before it is read: the helper must work without the program (it is how the
program is put back), and a request is plain words checked again before any action, so a swapped request can name only an
action the list already allows.
