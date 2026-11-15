---
name: ci-failure-triage
description: Turn a failed test run into a short list of causes. Download the results, group failures by what they have in common, tell real regressions from flaky tests and environment problems, and propose one fix per cause. For an agent with read access to the CI run and the repository.
version: 1.0.0
license: Apache-2.0
---

# CI failure triage

A red run with forty failures is usually three or four causes. Your job is to find the causes, not to fix forty tests.

## Steps

1. **Get the facts.** Download the run's results and logs (the failing job's log, the test report, any traces or screenshots).
   Note the commit, the branch and whether the run before it was green. Do not rerun anything yet.
2. **List every failure** as one line: test name, file, first line of the error. Keep the exact error text.
3. **Group by cause.** Two failures share a cause when their error text, their first failing line in the stack, or the thing
   they were waiting for is the same. Typical causes: one broken import or build step (everything fails), a changed label or
   route (tests that touch one screen fail), a shared fixture or seed that was deleted by an earlier test, a timeout on a slow
   runner, a service that did not start. Give each group a name a person will understand.
4. **Classify each group.**
   - *Regression:* the change in this commit explains it. Show the line.
   - *Test order or shared state:* it passes alone and fails after another test. Say which test changed the state.
   - *Flaky:* it passed on a retry or on the previous run with no relevant change. Say how many times you saw both.
   - *Environment:* the runner, a quota, a network service. Say what would prove it.
5. **Propose one fix per group**, smallest first, each with the file you would change and the check that would prove it.
   If you are not sure of a cause, say so and name the one experiment that would settle it.
6. **Only then, if you were asked to, fix.** One group at a time, on a branch, with the single test that proves it. Never
   weaken or delete a test to make a run green. Never mark a test skipped without a person's approval and a note saying why.

## Output

A table: group, count, class, evidence (a line or a link), proposed fix. Then a short paragraph: what to do first and what a
person must decide. Put nothing secret in it; if a log contains a key, say "a key appears in the log at line N" and stop.
