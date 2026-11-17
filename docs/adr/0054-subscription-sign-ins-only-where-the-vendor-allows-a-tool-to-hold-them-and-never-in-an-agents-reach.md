# 0054 — Subscription sign-ins: only where the vendor allows a tool to hold them, and never in an agent's reach

**Status.** Decided. **Preview**: the catalogue and the dashboard's honest status are built and tested in CI. **No sign-in is
built.** Not one vendor today documents a way for a tool like Oz Box to hold a subscription sign-in and give a run only a
short-lived token, which ADR 0017 requires. So every engine shows **Planned** or **Not offered**, with the reason.

**Context.** A person may already pay for a coding or chat plan (Claude Pro or Max, a ChatGPT plan, Gemini Code Assist, GitHub
Copilot) and want their agents to use it instead of an API key. A subscription sign-in is not an API key:

- it belongs to one person;
- the vendor's terms decide which programs may use it, and for what;
- the engine usually reads it itself, from a file or a variable, instead of sending a key that a proxy can add.

Before building anything, we read each vendor's own documentation and terms. We used public pages only: no sign-in, no
account, no credential. The pages were read on 2026-11-17, and terms change, so the vendor's current page wins.

| Engine and plan | What the vendor documents | Oz Box | Sources |
|---|---|---|---|
| Claude Code, Claude Pro or Max | `claude setup-token` makes a one-year token for scripts, via a browser sign-in; `CLAUDE_CODE_OAUTH_TOKEN` points Claude Code at it. A person may sign in to the unmodified Claude Code with their own plan, including where a platform hosts it. But a third-party developer may not collect, store or intermediate Claude.ai credentials or session tokens, or route requests through a plan's credentials on behalf of its users. | **Not offered.** Oz Box will not hold or broker it. | [legal and compliance](https://code.claude.com/docs/en/legal-and-compliance), [authentication](https://code.claude.com/docs/en/authentication) |
| Codex CLI, ChatGPT plan | A device-code sign-in (`codex login --device-auth`). For trusted private automation, the sign-in file `auth.json` may be kept in a secrets manager, restored for a run and written back after Codex refreshes it, one file per runner and never shared across concurrent jobs. API keys stay the recommended default for automation, and the pattern is not for public or open-source repositories. | **Planned.** Codex must read `auth.json` itself, so a run would hold a long-lived refresh token (rule 4 below). | [authentication](https://learn.chatgpt.com/docs/auth), [CI/CD sign-in](https://learn.chatgpt.com/docs/auth/ci-cd-auth) |
| Gemini CLI, Google account (Gemini Code Assist) | The Google sign-in needs a web browser on a machine that can talk to the terminal running Gemini CLI. Headless mode uses a credential already cached, and no setting points the CLI at a stored sign-in. Using other software to reach the services behind Gemini CLI breaks Google's terms. | **Planned.** There is no documented remote sign-in, and no documented way to hand one over. | [authentication](https://geminicli.com/docs/get-started/authentication/), [terms and privacy](https://geminicli.com/docs/resources/tos-privacy/) |
| OpenCode, Claude Pro or Max | OpenCode's provider page documents no Claude plan sign-in, and Anthropic's terms forbid one in other tools. | **Not offered.** | [OpenCode providers](https://opencode.ai/docs/providers/), [Anthropic](https://code.claude.com/docs/en/legal-and-compliance) |
| OpenCode, ChatGPT plan | OpenCode documents **Sign in with ChatGPT**. OpenAI's own Codex pages do not mention OpenCode. OpenCode documents no device code, no sign-in location and no way to point it at a stored sign-in. | **Planned.** | [OpenCode providers](https://opencode.ai/docs/providers/), [OpenAI](https://learn.chatgpt.com/docs/auth) |
| OpenCode, GitHub Copilot plan | A device sign-in, which GitHub announced it supports for paid Copilot plans (Pro, Pro+, Business, Enterprise). There is no documented sign-in location, and no way to point OpenCode at a stored one. | **Planned.** This is the closest to supportable. | [OpenCode providers](https://opencode.ai/docs/providers/), [GitHub changelog](https://github.blog/changelog/2026-01-16-github-copilot-now-supports-opencode/) |
| OpenCode, Google account | Google's terms forbid other software reaching the services behind Gemini CLI. | **Not offered.** | [terms and privacy](https://geminicli.com/docs/resources/tos-privacy/) |
| Aider | API keys only. Its Copilot recipe copies a token out of another program's home folder (`~/.config/github-copilot/apps.json`) into `OPENAI_API_KEY`. It says Copilot allows this, which we could not confirm from GitHub's own pages. | **Not offered** as a subscription. Use an API-key provider. | [Aider and Copilot](https://aider.chat/docs/llms/github.html) |

**Decision.** A subscription sign-in is a provider of the kind `subscription`, one per vendor and engine. Every future sign-in
adapter must follow these rules. Until one exists, the dashboard shows only the honest status.

1. **Only where the vendor allows it.** A row may be **Available** only when both are true:
   - the vendor's own documentation or terms allow a tool like Oz Box to hold the sign-in for runs on a remote machine;
   - an adapter is built.

   Where the terms forbid it, the row is **Not offered**, permanently, until the terms change. Where the terms do not
   address it, the row is **Planned** and says so. The dashboard links the vendor's pages and never implies a use is
   allowed. A test holds that no row is Available while no adapter exists.
2. **Who.** Only a dashboard owner (ADR 0039) may start a sign-in or revoke one. Members and viewers see the status. It is the
   person's own account and plan, and it is used only for their own boxes. It is never shared with other people, which the
   vendors' individual plans do not allow, and usage counts against the person's own plan and its limits.
3. **The vendor's own sign-in, from the dashboard.** A device code is preferred: the dashboard shows the vendor's address and
   the short code, and the person approves on the vendor's own site.
   - Nothing is typed into the box: no password, and no token pasted into a terminal.
   - A sign-in already on a computer (`~/.claude`, `~/.codex`, `~/.gemini`, an editor's token file) is **never copied** into
     Oz Box or into `/work`.
4. **Held only in the secrets store, and never given to a run in a form it can keep.** The sign-in lives only in the
   SecretStore (ADR 0018). It is never stored in settings, in `/work`, or anywhere the box user can read.
   - A run reaches the vendor only through the credential broker, with a per-run token (ADR 0017): one run, one engine,
     only the vendor's own model endpoints, ended with the run.
   - An engine that must read the sign-in itself, from a file or a variable, would hold a long-lived credential an agent can
     read. That is not done. Only a later ADR, for one named vendor, may accept it, with the trade-off shown to the person
     before they sign in.
5. **Refreshed by the service.** Refresh happens inside the secrets service, and the refreshed sign-in is written back to the
   store. Where the vendor says a sign-in may not be used by two jobs at once (Codex), runs that use it are queued one at a
   time.
6. **Revoked from the dashboard.** Revoking deletes the sign-in from the store, and every run token issued for it stops at
   once. Where the vendor offers a revoke call, Oz Box makes it. Where it does not, the dashboard says where to revoke it on
   the vendor's site.
7. **Audited.** The audit chain records each of these, with names and ids only (ADR 0022, ADR 0028):
   - a sign-in started, completed or failed;
   - a refresh failure;
   - a revoke;
   - every per-run token issued against a subscription.
8. **An engine's own login stays the person's.** Anyone may sign an engine in themselves, in a terminal on a box, with the
   engine's own command. With no model chosen, the engine then uses that login. Oz Box does not hold, refresh or hand over
   that login, and any agent that runs as the box user can read it. The dashboard says this beside the status, so the
   person can decide whether to do it on a box they share.

**Why.** It is the person's account. A tool that holds it against the vendor's terms puts that account at risk of suspension,
and a sign-in an agent can read is worth more to an attacker than any one run. Saying "not yet, and why" costs nothing. A
sign-in that lands in the wrong place cannot be taken back.

**What it costs.** For now, a person who wants their plan used must sign the engine in themselves on the box, and accept that
the agents there can read it, or use an API key or their own cloud account (ADR 0015, ADR 0028).

**What is not covered.**

- No sign-in adapter, refresh, revoke call or run hand-off is built. No vendor sign-in has been tried for real.
- The Team and Enterprise plans that come under a vendor's commercial terms are not assessed separately. A business account
  should check its own agreement.
- Terms change. Before any adapter is built, its vendor's pages are read again and the table above is updated.
