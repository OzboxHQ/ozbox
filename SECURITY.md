# Security policy

## Reporting a vulnerability

Please **do not** open a public issue, discussion or pull request for a security problem. Report it **privately through
GitHub's private vulnerability reporting**: open this repository's **Security** tab, choose **Report a vulnerability**, and
fill in the form. That is the only channel; there is no security e-mail address.

Include, as far as you can:

- what you found and which part it is in (the `ozbox` CLI, `ozboxd` on a box, the dashboard, the secrets service, an
  infrastructure module, an image or a release artifact);
- the version (`ozbox --version`), the provider (AWS, Hetzner Cloud or the demo) and how your box or dashboard was set up;
- how to reproduce it, ideally the smallest set of steps;
- the impact you expect: what an attacker gains, and what they need first (a box user, an agent, network access, a stolen
  token);
- whether you have told anyone else, and when you plan to disclose.

**Never include a real key, token or customer data** in a report: describe where one would be, or use a throwaway.

## What to expect

- We **read every report** and acknowledge it as soon as we can. Oz Box is a small project and we do not promise a fixed
  response time; if you have heard nothing after about a week, add a comment on the report.
- We keep you informed while we investigate, and **we will agree a disclosure date with you**: we aim to fix and disclose
  within 90 days, sooner if the problem is being exploited, and we say why if a fix needs longer.
- We **credit reporters** in the advisory and the release notes when a fix ships, unless you prefer to stay anonymous.
- There is **no paid bounty**. We are grateful all the same.

Please give us time to fix the problem before you disclose publicly, test only against systems you own, and do not access
data that is not yours.

## Supported versions

Oz Box is in Beta. **The latest 0.2.x release (starting with 0.2.0-beta.0) is the supported one** and gets features and fixes.
Once a newer minor version ships, the previous minor gets security patches for three months; see
[docs/releases.md](docs/releases.md). The `main` branch is development, not a supported release. Anything older: upgrade.

What the software does and does not protect against is written down in the decision records ([docs/adr/](docs/adr/README.md),
each with a "what is not covered" list), the [shared responsibility](docs/shared-responsibility.md) page and the
[hardening checklist](docs/hardening-checklist.md). Oz Box describes controls; it makes no claim of certification or
compliance.
