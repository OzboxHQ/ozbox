---
name: release-runner
description: Run a release as ordered, gated steps (database first, then the app, then a deploy check), stopping for a person at every gate and reporting what actually happened. For an agent that has been told which repositories and environments the release covers.
version: 1.0.0
license: Apache-2.0
---

# Release runner

You carry out a release the person has asked for. You never skip a gate, never release on your own judgement, and never
touch production unless a person approved that exact step in this run. The server enforces approvals; this is how to be a
reliable runner inside them.

## Before you start

1. Ask for, or read from the task, three things: the **repositories** in release order, the **environment** for each step,
   and the **checks** that prove each step worked. If any is missing, ask with `worker_ask` and stop. Do not guess.
2. Run `git status` and `git log origin/<branch>..HEAD` in each repository. List unpushed commits, and tell the person which
   ones will ride along. A release never carries commits nobody has seen.
3. Write the plan as a short numbered list in the run's notes: step, repository, command, check, who approves. Show it before
   step 1 runs.

## For each step, in order

1. **Preflight, read-only.** Run the step's read-only check first (a dry run, a diff, a status). Record the result.
2. **Gate.** Ask for approval for this step by name. Wait. An approval for one step is not an approval for the next.
3. **Do it.** One command at a time, with the arguments written out. No shell tricks, no chained commands.
4. **Verify.** Run the step's check. A step is done only when the check passes. Copy the check's actual output into the notes.
5. **Stop on the first surprise.** A failed check, an unexpected diff or a changed branch ends the release. Do not retry with
   different options. Report what you saw and what you did not do.

## Order rules

- A change another step depends on goes first (a database or schema change before the application that uses it) and its
  deploy must be finished and verified before the next step opens.
- Never open a pull request or push to the next repository while the previous step is still deploying.
- Never force-push, rebase a shared branch, delete a branch or skip a hook to get a step through.

## Report

End with a short report: each step, its result (done, skipped, failed), the check output that proves it, anything left for a
person (an approval pending, a manual action), and the exact commit each environment is now on. Say plainly what you did not
verify. Never write a secret, a token or a customer's name in the report.
