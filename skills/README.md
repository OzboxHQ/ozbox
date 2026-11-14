# skills

Skills are plain-language guidance an agent follows, in the open Agent Skills format: a folder named for the skill, holding a
`SKILL.md` (a front matter with `name`, `description` and an optional `version`, then the instructions) and, if needed, a few
text files beside it. They are not security: what an agent may do is enforced by the server (limits, claims, approvals),
whatever a skill says.

**A skill is unusable until a person approves its exact files.** These folders ship inside the program and appear in the
dashboard's Skills page (and `ozbox skills list`) as *bundled*. Install one for the whole fleet, a box or a project, read its
files, and approve them; any later change to the files asks again (ADR 0024).

| Skill | For |
|---|---|
| [`orchestrate-features`](orchestrate-features/SKILL.md) | a conductor agent that hands features to worker boxes with the Oz Box tools |
| [`release-runner`](release-runner/SKILL.md) | running a release as ordered, gated steps, stopping for a person at each gate and reporting what actually happened |
| [`ci-failure-triage`](ci-failure-triage/SKILL.md) | turning a red test run into a short list of causes, classed as regression, shared state, flaky or environment |
| [`reply-drafter`](reply-drafter/SKILL.md) | drafting a reply into a file for a person to send; never sends, keeps names and internal causes out |
| [`eval-runner`](eval-runner/SKILL.md) | running an evaluation suite against a pinned baseline and reporting regressions with evidence |
| [`keep-memory`](keep-memory/SKILL.md) | using the memory tools well: search first, propose short durable notes, never store a secret |

To add your own, choose **Add a skill** on the dashboard's Skills page (write one, or upload files), or put a folder in your
library with `ozbox skills add <folder>`; the folder's name must match the skill's `name`. Copy a bundled skill and change it
to suit you. An approved skill can also be put on a box's own disk, where its coding agents read it (ADR 0051).
