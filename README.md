# Oz Box

**Open-source cloud workstations for AI agents, and fleets of them, in your own cloud account.**

An Oz Box is a cloud machine built for AI agents and the people who work with them. It runs your agent sessions,
builds, tests and browsers on cloud hardware instead of your laptop. You reach it from any device through tunnels the box
dials out to, never an open port. You can pause it, resize it, clone it, throw it away, and run many of them together.

Nothing is hosted by this project. There is no Oz Box cloud, account, relay or default domain: the boxes live in **your**
cloud account, the dashboard runs on **your** computer or behind **your** domain, and the keys are **yours**.

> **Status: Beta (0.2.0-beta.1).** The single box is real and has been used on a real cloud account. **Beta does not mean
> every feature has been proven:** anything marked **Preview** is built and tested in CI but has not been run on a real box,
> and the agent-side controls are mostly in that group. [What works and what does not](#status) says exactly what.

## Who it is for

- **A developer** who wants a big, always-available workstation for agent sessions and long builds, reachable from a laptop,
  a tablet or a phone.
- **A small team or a lab** that runs coding agents and wants them supervised: capped, logged, asking before anything risky,
  and kept away from Production and from keys.
- **Anyone who wants a fleet** of boxes for experiments, parallel agents or a test lane, rebuilt from a versioned image with
  the work kept on a separate disk.
- **People who need control:** your account, your network, your model keys, your domain, and a licence that lets you read and
  change all of it.

## The core ideas

- **Plan, then apply.** Every change shows exactly what it will do, with cost and risk, and asks before it does it. A change
  that cannot be undone asks you to type the box name. `--dry-run` stops after the plan ([ADR 0002](docs/adr/0002-plan-then-apply.md)).
- **Your account, your domain, your keys.** Boxes are created in your cloud account with your credentials; the dashboard is
  reached through a tunnel you bring (Cloudflare, Tailscale, Caddy on your own server, or ngrok); model keys are yours
  ([ADR 0010](docs/adr/0010-bring-your-own-tunnels.md), [ADR 0015](docs/adr/0015-model-providers-and-local-ai.md)).
- **No inbound ports.** A box has no open port, not even SSH. Every way in goes out through your provider's session service
  or your tunnel, and the infrastructure tests fail on any inbound rule ([ADR 0005](docs/adr/0005-no-inbound-network.md)).
- **Agents are supervised, not trusted.** An agent runs as an ordinary user with no `sudo`. A permission engine decides what
  it may do (allow, ask you, or refuse), and every decision goes into a tamper-evident audit log
  ([ADR 0022](docs/adr/0022-permission-engine-and-tamper-evident-audit-log.md), [ADR 0026](docs/adr/0026-the-tool-host-every-tool-call-is-decided-and-recorded.md)).
- **Keys stay out of the agent's reach.** Secrets are encrypted at rest and held by a separate user, and a model key is
  added by a broker, so an agent holds a token worth one run, never a key
  ([ADR 0017](docs/adr/0017-credential-broker-per-run-tokens.md), [ADR 0018](docs/adr/0018-secrets-are-encrypted-and-out-of-the-agents-reach.md)).
- **A fleet, not a pet.** The system disk is rebuilt from a signed image; your work lives on a separate persistent `/work`
  disk that survives pausing, resizing and upgrading.
- **Any engine, any cloud.** Bring the coding agent you prefer (Claude Code first; Codex, Gemini CLI, Aider and OpenCode use
  the same interface) and the model provider you prefer, hosted or open-weight. AWS and Hetzner Cloud are supported by one
  provider interface ([ADR 0003](docs/adr/0003-provider-interface.md)).

## Try it

### Getting started

**1. Install the program.** The Beta is published as a signed GitHub pre-release. The installer verifies the signature
(it needs [`cosign`](https://docs.sigstore.dev/cosign/system_config/installation/)) and the checksum before it installs
anything, and never uses `sudo`. Pre-releases are skipped when you ask for "the latest", so name the version:

```bash
curl -fsSLO https://raw.githubusercontent.com/OzboxHQ/ozbox/main/scripts/install.sh
less install.sh                                   # read it first
sh install.sh --version 0.2.0-beta.1              # puts ozbox in ~/.local/bin
ozbox --version                                   # ozbox 0.2.0-beta.1
```

Nothing else is published for this release: no Homebrew formula, no crates.io or npm package. To build the program
yourself instead, see [Building from source](#building-from-source) (Rust stable, Node 22, a C compiler).

**2. Try it without a cloud account.** The default provider is a file-backed demo (below).

**3. Use a real cloud.** On AWS, `ozbox create` boots the newest verified Oz machine image your program can use, with no
image to build (**Preview**: see [On AWS](#on-aws)). For a real cloud you also need your cloud's own CLI signed in and OpenTofu.

In the examples below, `ozbox` is the installed program; a source build puts it at `target/release/ozbox`.

### Without a cloud account

The default provider is a file-backed demo, so you can try everything on your own computer. Its usage figures are labelled
simulated.

```bash
ozbox create demo --size S      # shows the plan, asks, then creates a demo box
ozbox list
ozbox serve                            # the dashboard on this computer only; the address with its token is printed
```

### On AWS

```bash
ozbox init --profile <your-profile> --budget 100        # a private network with no inbound rules, a state bucket, a budget
ozbox create main --size M --disk 200                   # boots the newest verified Oz image; shows the plan and monthly estimate first
ozbox connect main --ssh --write                        # an SSH entry that tunnels through your provider, no open port
ozbox ide main                                          # VS Code in your browser, on http://localhost
```

`create` boots the newest verified Oz image: one in your own account if there is one, otherwise the project's public image
for your region (**Preview**: published from one account in us-east-1, eu-west-1 and ap-southeast-1, and used only if that
account owns it and the signed release lists it; the image must be of your program's version, and this is not yet proven on a real account). Pass an image with `--image` (or set `image`
in your configuration) to boot another, or build your own in your account from [`infra/`](infra/README.md) with Packer. A budget is
required before any box can be created on a real cloud, and a box bills while it runs: `ozbox pause main` stops the compute and
keeps `/work`. Hetzner Cloud works the same way through `--provider hcloud`, with the limits in [Status](#status).

## Commands

Run `ozbox <command> --help` for every option. Every change takes `--dry-run`, `--yes` and `--json`.

### Boxes

| Command | What it does |
|---|---|
| `ozbox init` | Guided first-run setup: provider check, region, state bucket, private network, the fleet's secrets key (AWS), budget, alerts. `--issuer-package <zip> --issuer-package-sha256 <hash>` also plans the off-box issuer for Production secrets |
| `ozbox create <name> --size M` | Create a box (shows the plan first); `--tools`, `--profile`, `--label key=value`, `--disk` |
| `ozbox list` · `show <name>` · `sizes` · `providers` | List boxes, show one, the size catalogue, what each provider can do |
| `ozbox pause` · `resume` · `resize` · `snapshot` · `clone` · `destroy` | Change a box; each shows its plan and asks first. `destroy` asks you to type the name and keeps a final snapshot |
| `ozbox upgrade <name>` | Replace the system disk from a newer signed image, keep `/work`, run the self-test. An image whose signature cannot be verified is refused unless `--allow-unverified-image` is given; an upgrade that would lose the box's secrets store is refused unless `--accept-new-secrets-store` is given. On AWS, a box already on the image whose machine was made with another first boot (or has no record of it) is replaced from the same image (`--reprovision` forces it); a signed AWS image built with another first-boot configuration is refused unless `--allow-first-boot-mismatch` is given |
| `ozbox infra` | The box modules and first-boot configuration this program renders: its version, their hashes and the folder in use |
| `ozbox adopt-fleet-key <name>` | Move an AWS box's secrets store from a key kept in a file to your fleet's KMS key, in place, so an upgrade keeps it (the box re-wraps its own store; nothing is entered again) |
| `ozbox adopt <name>` | Rebuild a box's OpenTofu state from its cloud resources when the state is missing (AWS) |
| `ozbox admin <name> -- <action>` | The one root path: a short allow-list of actions, each recorded on the box. The box user has no `sudo` |
| `ozbox backup` | List, run, restore and schedule backups of `/work` |
| `ozbox tools` · `ozbox profile` | Install tools from the catalogue; save a box's tools and settings as a profile |

### Getting in

| Command | What it does |
|---|---|
| `ozbox connect <name> --ssh` | Say how to reach a box; `--ssh --write` adds an SSH entry for terminals and desktop editors |
| `ozbox ide <name>` · `desktop <name>` | The web IDE or a desktop with Firefox, on `http://localhost` or on your own address behind your sign-in |
| `ozbox open <name> --in vscode` | Open `/work/repos` in a desktop editor (VS Code, Cursor, Zed, JetBrains and others) over SSH |
| `ozbox ps <name>` | What is running on a box: tmux sessions, coding agents, listening servers |

### Agents and their guardrails

| Command | What it does |
|---|---|
| `ozbox run start\|list\|show\|logs\|cancel\|retry\|resume` | Supervised agent runs with time, token and spend caps; a run that hits a cap saves its work and asks |
| `ozbox approvals list\|approve\|deny` | What agents ask to do, and your answer |
| `ozbox permissions show\|mode\|grant\|revoke\|check` | The default mode, the active rules, and time-boxed Production grants; rules are edited in the dashboard |
| `ozbox audit list\|verify\|seal` | The tamper-evident audit log, and a check that nothing in it was changed |
| `ozbox memory` · `ozbox skills` | Notes in git that agents read once you approve them; skills usable only after you approve their exact files |
| `ozbox orch` | One conductor agent hands features to worker boxes, with claims, contracts, a mailbox and a merge queue |
| `ozbox schedule` · `ozbox trigger` | Agent runs on a schedule in your time zone, or started by signed webhooks |
| `ozbox models` · `ozbox cost` | Your model providers, which engine uses which model, usage and prices; the real cloud bill beside the estimate |

### Secrets

| Command | What it does |
|---|---|
| `ozbox secrets` | Report on the encrypted secret store (names and ages, never values), rotate its keys, import a project's `.env` keys. `ozbox secrets ingress pin\|escrow\|setup-code --box <name>`: the sealed route to a box's secrets service ([ADR 0029](docs/adr/0029-production-secrets-have-no-standing-access.md)) |
| `ozbox env run\|policy` | Run a named command with only the secrets a project declared it may receive, on a closed network except the hosts it declared |
| `ozbox guard install` | Git hooks that stop a commit or push containing a key |
| `ozbox box-secrets <name>` | Declare which non-production keys a box reads from your cloud's parameter store, into memory only |

#### Telemetry

Oz Box never asks about telemetry. It is off, nothing is read or sent, and it stays off unless you run `ozbox telemetry on
--endpoint <address you run or trust>`. `ozbox telemetry preview` prints the whole event first (a version, the operating system,
the provider's kind and a size bucket for your fleet; no names, paths, prompts or keys). See `docs/telemetry.md`.

### How you reach your boxes

`ozbox init` explains each way in and preselects the provider's own session service (no open ports, nothing extra to run):
the session service, a Headscale tailnet you run yourself, Tailscale, or Cloudflare with your own domain. You can change it
at any time; `--access` answers it without a prompt.

## The dashboard

| Command | What it does |
|---|---|
| `ozbox serve` | Serve the web dashboard on this computer only (loopback, with a random access token in the address) |
| `ozbox tunnel setup\|status\|remove` | The outbound tunnel that reaches the dashboard from outside, with your own account |
| `ozbox auth init` | The sign-in settings for a dashboard on a shared machine |
| `ozbox dashboard install <name>` | Run the dashboard and its tunnel as a service on one of your boxes, as a user of its own (never the box user) |
| `ozbox mesh setup\|policy\|allow\|join\|status` | Reach your boxes over a Headscale tailnet you run yourself; the access rules are generated from your boxes and deny box-to-box traffic by default |
| `ozbox plugin list\|add\|approve` | Provider and tunnel plugins, run only after you approve the exact program |
| `ozbox telemetry status\|preview\|on\|off` | Optional anonymous usage counts; off until you turn it on, sent only to an address you choose |

## The dashboard

A single-page app, served by the `ozbox` program, that shows boxes, fleet usage and cost, the task board, approvals,
permissions, memory, skills, chat and settings. Every change in it follows the same plan, then apply.

- **On your computer:** `ozbox serve` listens on loopback only and requires a random token on every call.
- **On your own domain:** bring a tunnel (`--tunnel cloudflare`, `tailscale-funnel`, `tailscale-serve`, `caddy` or `ngrok`) and
  give the address with `--public-url`. The server still listens on loopback only; the tunnel dials out. With a public
  address the token is replaced by sign-in: **passkeys**, or GitHub or Google (your own OAuth app) followed by an
  authenticator code, or an **identity-aware proxy** such as Cloudflare Access whose signed token the server verifies. It
  refuses to start on a public address with neither.

```bash
ozbox auth init --origin https://dash.example.com --person you,label=You
printf '%s\n' "$TUNNEL_TOKEN" | ozbox tunnel setup cloudflare --public-url https://dash.example.com --token-stdin
ozbox serve --public-url https://dash.example.com --tunnel cloudflare
```

Everyone who signs in has a role (`--person you,role=owner|member|viewer`; the first person is the owner, the rest are
members): an owner changes settings, permissions, secrets and costs, a member does the work, a viewer only looks
([ADR 0039](docs/adr/0039-dashboard-roles-owner-member-viewer-and-one-rule-for-a-dashboard-with-no-sign-in-on-a-box.md)).

`ozbox dashboard install` can instead run it as a service on a box, which then goes down whenever that box is paused or
upgraded; a machine outside the fleet is the better home ([ADR 0010](docs/adr/0010-bring-your-own-tunnels.md)).

## Security model, in short

| Property | How | Read more |
|---|---|---|
| No inbound network | Zero ingress rules; every route out; tests fail on any inbound rule | [ADR 0005](docs/adr/0005-no-inbound-network.md) |
| No `sudo` | One narrow, audited root path (`ozbox admin`) | [ADR 0011](docs/adr/0011-no-sudo-one-audited-root-path.md) |
| One door for every action | A permission engine decides every action; Production changes need a short, recorded grant | [ADR 0022](docs/adr/0022-permission-engine-and-tamper-evident-audit-log.md) |
| Every tool call decided and recorded | An MCP tool host; the log holds the decision, never the command or output | [ADR 0026](docs/adr/0026-the-tool-host-every-tool-call-is-decided-and-recorded.md) |
| Tamper-evident log | A hash chain with sealed checkpoints; `ozbox audit verify` | [ADR 0022](docs/adr/0022-permission-engine-and-tamper-evident-audit-log.md) |
| Agents never hold a model key | A credential broker and per-run tokens | [ADR 0017](docs/adr/0017-credential-broker-per-run-tokens.md) |
| Secrets out of reach | Envelope encryption, a separate user, a runner user, a closed network for declared commands, a commit barrier | [ADR 0018](docs/adr/0018-secrets-are-encrypted-and-out-of-the-agents-reach.md), [ADR 0023](docs/adr/0023-the-supervisor-egress-approvals-and-the-commit-barrier.md), [ADR 0029](docs/adr/0029-production-secrets-have-no-standing-access.md) |
| Reviewed memory and skills | Agents propose; a person approves the note or the skill's exact hash | [ADR 0024](docs/adr/0024-agent-memory-markdown-in-git-reviewed-before-agents-read-it.md), [ADR 0025](docs/adr/0025-skills-are-folders-usable-only-after-a-person-approves-their-hash.md), [ADR 0051](docs/adr/0051-a-skill-can-be-put-on-a-boxs-own-disk-only-as-the-exact-files-a-person-approved-and-the-box-checks-them-again.md) |
| Signed images | An upgrade verifies the image's release signature first | [infra/README.md](infra/README.md), [ADR 0010](docs/adr/0010-bring-your-own-tunnels.md) |

Each record also says what it does **not** cover. In short: egress limits apply to a project's declared commands, not to an
agent's own shell; and the audit log detects an edit but cannot yet stop one, because its writer and the agents share a user
on a box. Report a vulnerability privately; see [SECURITY.md](SECURITY.md).

What the software does and what stays with you is on one page: [shared responsibility](docs/shared-responsibility.md). The
review checklist for v1.0 is [docs/hardening-checklist.md](docs/hardening-checklist.md). Oz Box describes controls; it makes no
claim of certification or compliance.

## Status

Oz Box is in **Beta**, version 0.2.0-beta.1. The latest 0.2.x release is the supported one (see [SECURITY.md](SECURITY.md)),
and the signed program is published on GitHub Releases only (no package-manager packages yet). A Beta may still break between
releases (see [docs/releases.md](docs/releases.md)). We mark every worked example with one of three words, and update them as things are proven:

- **Works** is built, tested, and exercised on a real cloud box.
- **Preview** is built and tested (including browser tests of the dashboard), but not yet exercised end to end on a real cloud
  box. Expect rough edges.
- **Planned** is designed, not built.

**Proven on a real AWS box:** setting up an account, creating a box, SSH and the web IDE, pause and resume, snapshot, clone and
destroy, upgrading a box onto a newer image, and the `ozbox admin` repair path.

**Built and tested, not yet proven on a real box:** supervised agent runs, the permission engine and Production grants, the tool
host, the audit log, the credential broker and encrypted secret store, the runner user and egress proxy, memory and skills,
orchestration, schedules and triggers, chat, linking Telegram with a passkey (phase P1 of [ADR 0050](docs/adr/0050-telegram-is-a-control-surface-a-closed-table-of-acts-delegated-in-advance-by-passkey-and-never-an-approver.md); box power and `/run` are not built), local models, repository backups, bill reconciliation, the dashboard running as a
service behind your own domain, and the box memory guard (compressed swap, protected services, capped jobs; its real-box proof is
`scripts/real-box-memory-proof.sh`). Hetzner Cloud support is covered by simulated tests and has no clone.

**Not built:** a network allow-list for a whole box, a log writer an agent cannot reach, and signed skills. The
[use-case guides](docs/use-cases/README.md) say, example by example, where each stands.

## Community and support

Bugs and feature requests: [GitHub Issues](https://github.com/OzboxHQ/ozbox/issues) (use the templates). Questions and ideas:
[GitHub Discussions](https://github.com/OzboxHQ/ozbox/discussions), which are switched on when the repository goes public.
What is planned: [ROADMAP.md](ROADMAP.md). Pull requests are welcome: see [CONTRIBUTING.md](CONTRIBUTING.md). Free community
support is best effort; paid support plans are available from the company behind the project, see
[docs/releases.md](docs/releases.md). Be kind: [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md).
Releases come monthly and are supported as described in [docs/releases.md](docs/releases.md).

The code is Apache-2.0 and everything in it is open; there is no paid edition. The documentation is CC BY 4.0
([DOCS-LICENSE.md](DOCS-LICENSE.md)).

## Learn more

| | |
|---|---|
| [Use cases](docs/use-cases/README.md) | well over a hundred worked examples in fourteen guides — for software work and for business, finance, creative and education work — each marked Works, Preview or Planned |
| [A secure workspace for AI agents](docs/use-cases/secure-agent-workspace.md) | agents with no keys in reach, ask-mode, Production kept out, and when a per-request sandbox fits better |
| [Architecture](docs/architecture.md) | how the pieces fit |
| [Decision records](docs/adr/README.md) | why it is built this way, and what each decision costs |
| [Roadmap](ROADMAP.md) | where it is going |
| [Infrastructure](infra/README.md) | the image, the OpenTofu modules and the operator's permissions |
| [Contributing](CONTRIBUTING.md) | how to contribute: issues, pull requests, DCO sign-off |
| [Security](SECURITY.md) | reporting a vulnerability |

## Repository layout

| Path | What lives there |
|---|---|
| `crates/` | Rust: the `ozbox` CLI, the `ozboxd` box daemon, the providers and the shared core |
| `packages/` | TypeScript: the web dashboard |
| `infra/` | Image builds (Packer) and provider modules (OpenTofu) |
| `catalog/` | The tools catalogue: pinned, checksum-verified downloads |
| `skills/` | Example agent skills that ship with Oz Box |
| `examples/` | Example box and fleet definitions |
| `docs/` | The architecture overview, the decision records and the use-case guides |

## Building from source

The `ozbox` program embeds the web dashboard, so build the dashboard first and the program second:

```bash
cd packages/dashboard && npm ci && npm run build   # Node 22 (see packages/dashboard/.nvmrc); writes packages/dashboard/dist
cd ../.. && cargo build --release -p ozbox-cli     # embeds packages/dashboard/dist
```

A development build (`cargo build`) without the dashboard still compiles and `ozbox serve` says the dashboard is not built.
A **release** build (`--release`, or `OZBOX_RELEASE=1`) refuses to compile without it, so a program that serves the
placeholder page can not be built by accident; set `OZBOX_ALLOW_NO_DASHBOARD=1` to build a release without a UI on purpose.
The dashboard's content hash is compiled in (`/v1/info` reports it under `dashboard`), and the signed image and CLI release
manifests record the same hash. The release workflows build the dashboard once (`dashboard-build.yml`) and every program they
compile embeds that build.

## License and name

Apache License 2.0 — see [LICENSE](LICENSE) and [ADR 0009](docs/adr/0009-apache-2.md). The code is free to use, fork and sell;
the name and logo are covered by [TRADEMARKS.md](TRADEMARKS.md).
