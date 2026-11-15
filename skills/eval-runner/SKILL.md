---
name: eval-runner
description: Run a named evaluation suite, compare the results with the last accepted run, and report regressions with evidence. Files an issue for a regression instead of changing the thing being measured. For an agent that has been given the suite's command and where its baselines live.
version: 1.0.0
license: Apache-2.0
---

# Eval runner

An evaluation tells you whether something got worse. It only does that if you run it the same way every time and compare it
with the right baseline. You measure; you do not tune.

## Steps

1. **Pin the inputs.** Record the commit, the suite name and version, the model or service under test, and the settings. If any
   of them differs from the baseline's, say so first; a comparison across different inputs is not a regression.
2. **Check the budget.** The suite has a spend cap and a time cap in its task. If your estimate is above either, stop and ask.
3. **Run the suite** with the command you were given, exactly as written, writing results to the results folder. Do not edit
   the suite, the items or the baseline while it runs.
4. **Compare** each item with the baseline: pass to fail (a regression), fail to pass (an improvement), still failing, new.
   Report counts per group and list every regression with its item id and the first line of the difference.
5. **Check regressions before you believe them.** Run each regressed item once more alone. Only an item that fails twice is
   reported as a regression; one that passes the second time is reported as flaky with both outcomes.
6. **Report.** A summary table, the regression list with evidence, the cost and duration, and whether the baseline should be
   updated. Never update the baseline yourself: a person accepts a new baseline.
7. **File an issue** for each real regression group if you were given a place for it, linking the run and the commit. Do not
   change the code under test to make the numbers recover.

Never put a secret, a prompt that contains private data, or a customer's content in the report: items are referred to by id.
