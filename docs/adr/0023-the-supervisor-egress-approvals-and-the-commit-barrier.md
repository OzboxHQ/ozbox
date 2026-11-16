# 0023 — The supervisor has its own user; commands have a closed network; secret writes need a fresh second factor

**Decision.** ADR 0018 left four gaps, each named in its "not covered" list. This closes them, and adds the box's own
secrets in memory. The principle is the same: assume an agent (or a poisoned test it ran) is hostile, and make what it
could do with a key, or to a key, either impossible or loud.

1. **The supervisor is a user of its own.** The dashboard (`ozbox serve`) runs as `ozbox-supervisor` from a system unit,
   with the root-owned `/usr/local/bin/ozbox` (a program in the box user's home could be replaced, which would make the
   separation theatre), everything it keeps in `/work/ozbox-supervisor` (`0700`), and the box daemon reached through the box
   group's socket. The secrets service grows a socket only that user can open (`/run/ozbox-secrets/supervisor`). What it
   serves there needs no claim: the directory is the proof. Run tokens, model settings, the dashboard's own keys and the
   internal-token tags move to it. The box user's two old sockets shrink: the box socket answers only "is this secret set"
   and "list names"; the broker socket only the proxy port and the exact restic commands. The claim stays for a laptop,
   where no second user exists.
2. **A fresh second factor before a secret can be replaced.** Only the supervisor can ask the service for an *approval*,
   and the dashboard asks only after it has checked a passkey or authenticator code shown a moment ago (the same step-up
   that protects a tunnel change). An approval is 80 random bits, bound to one scope (importing a project's keys for one
   environment, a project's declaration, a tunnel token, a one-off guard override), good once, for five minutes. The
   service keeps a keyed hash of each live code in memory only; wrong guesses are counted and lock the gate for a minute.
   `import` and `policy` on the import socket, and the root helper's tunnel-token change, refuse without one. Until the
   dashboard says a second factor exists (`enroll`), a change is allowed and recorded as `bootstrap`; once enrolled the
   marker cannot be cleared by anything but root. Every use is recorded with its scope, project and how it was allowed,
   never a value or a code. A read is still never possible.
3. **A command's network is closed.** The runner's transient unit gets `IPAddressDeny=any` and
   `IPAddressAllow=127.0.0.1 ::1`: nothing but this machine's loopback, so a program that ignores a proxy setting cannot
   connect, and nothing can reach a name server, so DNS is not a side channel. The project's declaration lists `egress`
   hosts (`api.example.com`, `*.example.com`, optionally `:port`). For those the root launcher runs an HTTPS proxy on
   loopback for the length of the command, behind a password that exists only in that command's environment file. The
   proxy answers `CONNECT` for a declared host and port, resolves the name itself and refuses non-public addresses (the
   metadata service, the box's network), and then requires the TLS hello to name the same host and not hide it. Why a
   proxy and not an address list: a declared name on a shared address (a content network, a cloud gateway) shares it with
   thousands of strangers, so an address allow-list lets a poisoned test reach any of them; the proxy checks the name.
   **Wire protocols.** A database or mail client cannot use a proxy, so a project declares each such destination under
   `tcp` (host, port, an environment prefix). For each one the launcher opens a loopback listener for exactly that
   destination for the length of the command and puts `<PREFIX>_HOST`, `_PORT`, `_ADDR` and `_REMOTE_HOST` in the
   command's environment. Every connection is resolved by the launcher, every address must be public (the metadata
   service, private and link-local ranges are refused, and one inward address among public ones refuses the lot), and the
   connection goes to one of the addresses it just checked, so a name that is rebound between two connections is refused
   the second time. Why a listener and not a `CONNECT`-style command: the clients that need this speak their own protocol and
   have no proxy setting, and a `CONNECT` the client must send is a place where a poisoned command chooses the destination;
   a listener has exactly one destination, fixed by the declaration, and cannot be pointed anywhere else. Nothing about it
   is protected by a password (a database client cannot send one), so another process of the box could use the listener;
   what it reaches is only what the box could already reach, and the database's own credentials are still needed. Where a
   protocol starts TLS (Postgres `sslmode`, STARTTLS) the declared host stays meaningful: the client verifies the server
   certificate against `<PREFIX>_REMOTE_HOST` (libpq: `host=<remote> hostaddr=127.0.0.1 port=<port>`), and the tunnel only
   ever reaches that host. Other limits: the unit's loopback is shared with the box's other loopback services (each behind
   its own credential), and egress covers a project's commands, not the box user's shell or an agent's own network.
   *(Amended by ADR 0029 Amendment 6: a loopback listener that holds a credential would be usable by every process of the box, so for
   a destination with credential injection the listener is a Unix socket inside the run's own namespaces. The sentence "another
   process of the box could use the listener" holds only for a listener that holds no credential.)*
4. **A commit barrier.** Hooks (`pre-commit`, `post-commit`, `pre-push`), installed in every repository under `/work` and put
   back by a timer when removed, stop a change that holds a private key block, a provider's key prefix, a signed token, a
   password in a connection address, an environment file, or any stored secret's value in any of the forms a value gets
   hidden in. The stored values are compared **inside the secrets service**, which answers with names; the hook never holds a
   value or a key. (Shipping HMAC fingerprints to the hook was rejected: it hands out an offline oracle for guessing a
   low-entropy secret; the scan is rate-limited instead.) `git commit --no-verify` skips `pre-commit` and cannot be
   prevented, so `post-commit` (which it does not skip) takes such a commit back with `reset --soft` and says so. The only
   way past is a spent-once `guard-override` approval, which the service records. A determined agent can still point git
   elsewhere; the closed network and the record are what stand behind the hook.
5. **The box's own secrets, in memory.** AWS Parameter Store (called natively, no SDK and no `aws` command: ADR 0029 Amendment 14) or OpenBao (by
   `bao`), behind one `Backend` trait, scoped by path to the box's role (`<prefix>/<role>/<project>/<env>/<NAME>`), only
   non-production environments, nothing production-looking. A unit pulls them at boot and every fifteen minutes as the
   secrets user and gives them to the service, which keeps them in a second store on tmpfs sealed under the same key, so
   they are never on a disk and a key revoked at the provider disappears at the next refresh. The declaration is not in a
   file or in the first-boot configuration: the OpenTofu module takes `box_secrets_backend`, `box_secrets_prefix` and
   `box_role`, writes them as instance tags, and (for Parameter Store) grants the instance role `ssm:Get*` on exactly
   `<prefix>/<role>` and below in its own account and region, and `kms:Decrypt` on a customer key only through Parameter
   Store. A root step (`ozbox secrets configure-box`, run before the loader and by `ozbox admin <box> --
   configure-box-secrets`) reads the tags from the instance metadata service and writes the loader's settings, refusing
   anything that is not a plain value; a box that is not on AWS, or has a settings file placed by hand, is left alone.
   `ozbox box-secrets <box> --backend .. --path .. --role ..` shows the change and, on a yes, writes the tags with the
   operator's credentials and has the box read them; the module's variables stay the source of truth for what the role
   may read, and the next apply puts the tags back to what they say. They are offered exactly like
   an imported `.env` (a command receives the names it may; an agent never reads one; a commit is scanned for them).

**Consequences and what is not covered.**
- The migration of an existing box is `ozbox-supervisor-setup.sh`, run at boot and by the root helper's `ensure-supervisor`
  action. It carries the dashboard's settings and state into the supervisor's folder, stops the old user unit (renamed, not
  deleted), starts the new one, and puts the old one back if the new one does not come up. The old copies stay readable by
  the box user until `ensure-supervisor finish` destroys them, so finishing it is part of the migration; keys the dashboard
  used for other boxes were copied and should be rotated afterwards.
- Restarting the secrets service (it now has the new sockets) invalidates run tokens held by runs in flight; those runs
  are issued new ones when the supervisor next speaks to it.
- The approval is carried by a person from the dashboard (Settings, Secret approvals: a code shown once, with its scope,
  project and expiry, and a list of recent uses) to the command. A laptop key that signs an approval without the dashboard
  is built in ADR 0028 (`ozbox secrets approve`).
- Egress covers a project's commands, not the box user's shell or an agent's own network.
- The hook and the barrier do not stop an agent that disables git hooks and has network it may use.

## Amendment 1 (2026-11-11): the dashboard never runs as the box user, even right after an install

A security review (2026-11-11) found that `ozbox dashboard install` started the dashboard as a service of the box user, from
the box user's home, and only the next boot (or `ozbox admin <box> -- ensure-supervisor`) moved it to its own user. Until
then every agent on the box could read its sign-in state and run-token keys, and could replace the program the move then
started. What changed:

- **The install only stages.** The box user's side writes the sign-in settings, the tunnel settings and the service file,
  and starts nothing. `ozbox dashboard install` then asks the root helper to start it as `ozbox-supervisor`
  (`ensure-supervisor expect SHA256`), and to destroy the box user's copies (`ensure-supervisor finish`). It reports success
  only once the helper says the dashboard runs as its own user.
- **The program is the box's own.** The system unit always runs the root-owned `/usr/local/bin/ozbox`; the copy an install
  puts in the box user's home is never started (this answers the review's question whether the move checks the binary: it
  does not copy it at all).
- **The sign-in settings are checked.** The staged `auth.toml` is a file the box user can rewrite between the install and the
  move, and it decides who can sign in. The install sends the sha256 of the settings it wrote; the move refuses, and starts
  nothing, when the staged file differs.
- **A failed move starts nothing as the box user.** The move puts the old box-user dashboard back only when one was running
  before it (an older install); a staged one that will not start leaves nothing running. `--rollback` after `--finish` has
  nothing of the box user's to put back and says so.
- **Only plain settings reach the supervisor's environment.** The optional `dashboard.env` is carried only as `OZBOX_`
  settings that name no program, path, socket, store, key or token (a library preload in that file would have run the box
  user's code as the supervisor).

**Still not covered.** `config.toml` (the tunnel kind and address; the token is in the store) is carried as the box user
left it, unchecked. The first-time setup code is printed to the dashboard's log, which reaches the box user through
`ozbox admin <box> -- collect-logs`, so an agent could race the person to the first sign-in; name the first person with
`--person` at install time and complete the first sign-in at once. These are follow-ups for the ingress account of ADR 0029
Amendment 6 §3, through which the person's computer could hand the supervisor its settings without the box user in between.
A box whose root helper is older than this change does not know `ensure-supervisor expect`, so `ozbox dashboard install` on
it fails, leaving the dashboard staged and not running; upgrade the box first. On Hetzner a rebuild used to keep the root helper
the box was made with (ADR 0029, Amendment 8), so on a Hetzner box made before this change the install kept failing, and
`ozbox admin <box> -- ensure-supervisor` (which does not check the sign-in settings' digest) and then `ensure-supervisor finish`
was the way. An upgrade on Hetzner now replaces the server and so brings the current root helper (ADR 0029, Amendment 8, follow-up built): upgrade
the box, then install.
