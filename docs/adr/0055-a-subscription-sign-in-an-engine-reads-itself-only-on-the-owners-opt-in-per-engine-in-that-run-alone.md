# 0055 — A subscription sign-in an engine reads itself: only on the owner's opt-in, per engine, in that run alone

**Status.** Decided (owner, 2026-11-17: "Yes, opt-in per engine"). **Preview**: built and tested in CI with fakes. No vendor
sign-in has been tried for real, and no Codex run has been started on a real box. Amends rule 4 of
[ADR 0054](0054-subscription-sign-ins-only-where-the-vendor-allows-a-tool-to-hold-them-and-never-in-an-agents-reach.md).

**Context.** ADR 0054 refused every engine that must read its own sign-in from a file or a variable: the run would hold a
long-lived credential an agent can read. It left that to a later ADR, for one named vendor, with the trade-off shown to the
person first. The owner decided to allow it, per engine, only where the person turns it on.

We read the vendors' pages again on 2026-11-17 (public pages only; no sign-in, no account):

- **Codex CLI with a ChatGPT plan** documents all of it:
  - a device-code sign-in, `codex login --device-auth`, which must first be turned on in the ChatGPT security settings;
  - the sign-in file, `auth.json` under `CODEX_HOME`, kept there when `cli_auth_credentials_store = "file"`;
  - for trusted private automation, keeping that file in a secrets manager and restoring it for a run, one run at a time,
    never for public or open-source repositories.

  Sources: [authentication](https://learn.chatgpt.com/docs/auth), [CI/CD sign-in](https://learn.chatgpt.com/docs/auth/ci-cd-auth).
- **OpenCode with a GitHub Copilot plan** documents a device sign-in (`/connect`), but not where OpenCode keeps it or how to
  point OpenCode at a stored one ([providers](https://opencode.ai/docs/providers/), [CLI](https://opencode.ai/docs/cli/)).
  Without that, Oz Box cannot put the sign-in in one run's folder and nowhere else. It stays **Planned**, with no opt-in,
  until OpenCode documents it.
- **Claude Pro or Max, Google accounts and Aider** stay as ADR 0054 marks them. The opt-in is never shown for them. The
  vendors' terms forbid a third party holding the sign-in, or there is no subscription to hold.

**Decision.** For an engine whose vendor documents both the sign-in and a way to point the engine at a stored copy, the owner
may let that engine's runs read the sign-in. Today that is only Codex with a ChatGPT plan, shown as **On your opt-in**.

1. **Off by default, per engine, the owner only.** Turning it on needs:
   - a dashboard owner (ADR 0039);
   - a passkey shown a moment ago (on a box with no sign-in it is refused);
   - the row's id typed back exactly.

   The warning comes first, through the message catalogue. It names exactly what an agent could read: the sign-in file,
   with an access token, a refresh token that keeps working until it is revoked, and the account id. It also says that a
   copy works from anywhere until it is revoked at the vendor.
2. **The vendor's own sign-in, from the dashboard.** The dashboard runs the vendor's command (`codex login --device-auth`)
   as its own user. It runs it in a private temporary folder (`0700` from creation, the engine's home and `HOME` both
   pointed there, a fixed `PATH`, nothing else inherited). It reads the command's output for the vendor's link and one-time
   code, and shows only a link on the vendor's own host.
   - Only the owner may see the code: whoever types it decides whose account the box holds.
   - Nothing is typed into the box's shell, and a sign-in already on a computer is never copied.
   - When the command ends, the file is moved into the secrets store and the folder is removed. A sign-in that does not end
     within 15 minutes is stopped.
3. **Kept where the box user cannot reach it.** The sign-in (`subscription-login-<id>`, base64 in parts) and the opt-in
   (`subscription-optin-<id>`) live only in the SecretStore (ADR 0018). Never `/work`, never settings.
   - On a box, the box user's socket cannot read, write, delete, ask about or list these names. The dashboard's own user
     (the supervisor socket) and the root helper can.
   - A dashboard that runs as the box user cannot store them, so it cannot turn the opt-in on. It says so.
   - When the box user's reach becomes one table (ADR 0018 Amendment 1), this is a row: no reach for the box user, read
     back by the supervisor.
4. **Handed to that engine's runs alone, and taken away when each ends.**
   - Only a run of the opted-in engine is handed the file, and only while the opt-in is on and a sign-in is stored. A run
     of any other engine is handed nothing.
   - The box daemon writes the file into a folder of that run in the box user's runtime directory
     (`/run/user/<uid>/ozbox-run-files/<run>/`): memory-backed, never on `/work` or a disk a snapshot or backup copies.
     The folder is `0700`, the files `0600`, created anew, and a link is never followed. The daemon sets `CODEX_HOME` to the
     folder and writes `config.toml` beside the file so Codex reads it from there.
   - The folder is removed when the run ends, is cancelled or fails to start. A daemon that starts again removes any folder
     whose run is not going.
   - The file's text is never in the run's record on disk, a log, a plan, an error or an API answer, and the program that
     starts the run sees only the variable naming the folder.
   - A daemon too old to write the file is not given the run: the dashboard stops it and asks for `ozbox upgrade`.
5. **Alone, and one at a time.** Anything running as the box user could read the folder, so a run that holds the sign-in
   runs alone on its box: it waits until nothing else runs there, and other runs wait until it ends. The vendor allows one
   run at a time per sign-in, so a second Codex run, on any box, waits too.
6. **Revoked from the dashboard.** Revoking deletes the sign-in and the opt-in from the store, so no later run is handed it.
   The answer names the runs that still have a copy until they end. The dashboard then sends the owner to the vendor's page
   to revoke the sign-in there, because only the vendor can stop a copy from working.
7. **Audited, names and ids only** (ADR 0022). The audit chain records each of these:
   - the opt-in turned on;
   - a sign-in started, completed or failed (with a reason code);
   - every hand-off to a run (the run, the box and the subscription);
   - a revoke.

**Residual risk, accepted by the owner.** An agent in an opted-in run, and any program running as the box user on that box
while the run goes, can read the sign-in and copy it. A copy keeps working from anywhere, for the person's account and plan,
until the person revokes it at the vendor. Oz Box cannot take a copy back. The controls above limit when and where the file
exists. They do not stop an agent that holds it. That is why the opt-in is off by default, per engine, behind a passkey and a
typed confirmation, with the warning shown first.

**Why.** Some people pay for a plan and want their agents to use it, and the vendor documents exactly this pattern for trusted
private machines. Saying no to everyone protects nobody who would accept the risk knowingly. Saying yes without the person's
explicit, informed choice would hand an agent a credential worth more than any run.

**What it costs.** A Codex run that uses the sign-in has its box to itself, so it can wait longer to start. A person who wants
this must sign in from the dashboard, never by copying a file.

**What is not covered.**

- **No real sign-in, and no real run.** The vendor's command, its output format and a run on a real box are untested. Today
  only Claude Code runs on a real box, so the hand-off reaches a real Codex run only once a Codex engine adapter is built. Until
  then it is exercised with the test engine.
- **The refreshed file is not written back.** Codex refreshes its tokens during a run and the vendor's pattern stores the
  refreshed file again afterwards. Oz Box does not yet, so after the vendor rotates the refresh token the person signs in
  again.
- **A run that already holds the file keeps it until it ends**, even after a revoke. The owner can stop it from Runs.
- **Any program running as the box user** during the run, beyond Oz Box's own runs (a person's terminal, a service they
  started), can read the folder. Oz Box keeps only its own runs off the box meanwhile.
- **OpenCode with GitHub Copilot** has no opt-in until OpenCode documents where it keeps the sign-in.
- **Terms change.** The rows are read again before each release that touches them; the vendor's current page wins.
