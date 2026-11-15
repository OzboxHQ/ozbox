# Shared responsibility

Oz Box is software you run in your own cloud account. This page says what the software does and what stays with you. Oz Box
describes **controls**, which you can read in the code and test. It makes **no claim of certification or compliance** with any
standard, and using it does not make you compliant with one: that depends on how you run it and on what you put in it.

## What Oz Box does

| Area | The control |
|---|---|
| Where it runs | Everything runs in **your own account** with your own credentials. Oz Box operates no service that holds your boxes, data or keys. |
| Network | **No open ports** on a box, including SSH. Every way in is an outbound connection ([ADR 0005](adr/0005-no-inbound-network.md)). |
| Encryption | Secrets are **encrypted at rest** and held apart from the box user ([ADR 0018](adr/0018-secrets-are-encrypted-and-out-of-the-agents-reach.md)); transport uses TLS. |
| Credentials | Agents get **per-run, short-lived, scoped tokens**, never a long-lived vendor key ([ADR 0017](adr/0017-credential-broker-per-run-tokens.md)). |
| Approvals | Risky actions need a person's **approval**, by passkey for the riskiest; skills, memory and plugins do nothing until you approve their exact content ([ADR 0021](adr/0021-chat-with-coding-agents.md), [0025](adr/0025-skills-are-folders-usable-only-after-a-person-approves-their-hash.md), [0031](adr/0031-plugins-are-programs-that-speak-a-versioned-protocol.md)). |
| Audit | A **tamper-evident audit log** records decisions and tool calls without their arguments ([ADR 0022](adr/0022-permission-engine-and-tamper-evident-audit-log.md), [0026](adr/0026-the-tool-host-every-tool-call-is-decided-and-recorded.md)). |
| Retention | The audit log is **kept for seven years** by default. |
| Change control | Every change is planned, shown and confirmed before it is applied ([ADR 0002](adr/0002-plan-then-apply.md)). |
| Releases | Programs are built in public CI, signed, and verified before they are installed ([releasing](releasing.md)). |

## What you do

- **Your cloud account.** Secure it: multi-factor sign-in, least-privilege roles, budgets and alerts, and the account's own
  logging. Oz Box checks the basics when you set it up and cannot make an insecure account secure.
- **Your data.** Decide what may be put on a box or sent to a model provider, and check that the provider's terms fit the data.
  Keep regulated or personal data out of anything you have not assessed.
- **Your people.** Decide who may approve what, remove people who leave, and review approvals and the audit log.
- **Your keys.** Keep your provider keys and tokens safe, rotate them, and revoke any that may have leaked.
- **Your updates.** Install new releases and image versions of Oz Box and of the systems around it (a Headscale server, a
  tunnel, plugins you approved). A plugin runs with your permissions.
- **Your backups.** Turn on and test backups of `/work`; a snapshot is not a backup in another account.
- **Your own obligations.** Any law, contract or standard that applies to you or to your customers is yours to meet. Ask your
  own advisers; this project gives no legal or compliance advice.

## Known limits

The [hardening checklist](hardening-checklist.md) lists what has been reviewed and what is still open, including the fact that no
independent security review has been done yet.
