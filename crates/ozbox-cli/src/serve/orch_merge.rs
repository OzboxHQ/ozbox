//! The merge queue's hands: `git`, run on the conductor's box through the box daemon's run API (ADR 0019).
//!
//! Every command is an argv list, never a shell string. A step is launched, then read back on the following ticks until it
//! exits, so a slow `git fetch` or a long test run never holds the server loop: each call to [`Merger`] answers `Pending`
//! until its steps are done. The person's own working tree is never touched: the branch is checked out in a separate
//! worktree under `/work/orch/`, rebased onto the base branch there, tested there, and pushed from there.
//!
//! The feature's branch must be on the repository's remote (`origin`): the worker pushes it when it is ready, and the
//! conductor's box fetches it. A repository with no remote cannot be merged this way, and the first step says so.

use std::collections::{BTreeMap, VecDeque};
use std::sync::Arc;

use ozbox_core::orch_merge::{MergeOutcome, Merger, RebaseOutcome, TestOutcome};
use ozbox_core::BoxRecord;
use serde_json::json;

use super::agent::BoxAgent;

/// What one step is and how a non-zero exit is read.
struct Step {
    argv: Vec<String>,
    cwd: String,
    /// A failure is an answer (the rebase conflicted), not an error.
    allow_fail: bool,
}

struct Flight {
    queue: VecDeque<Step>,
    run: Option<String>,
    from: u64,
    out: String,
    /// (exit code, output) of the steps already finished, in order.
    done: Vec<(i32, String)>,
}

enum Drive {
    Pending,
    Done(Vec<(i32, String)>),
}

pub struct DaemonMerger {
    agent: Arc<dyn BoxAgent>,
    rec: Option<BoxRecord>,
    flights: BTreeMap<String, Flight>,
}

fn s(v: &str) -> String {
    v.to_string()
}

fn argv(parts: &[&str]) -> Vec<String> {
    parts.iter().map(|p| p.to_string()).collect()
}

/// A branch name made safe to be a directory name.
fn dir_of(branch: &str) -> String {
    branch
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || c == '-' || c == '.' {
                c
            } else {
                '_'
            }
        })
        .collect()
}

fn tail(text: &str) -> String {
    let lines: Vec<&str> = text.lines().collect();
    let from = lines.len().saturating_sub(20);
    lines[from..].join("\n").chars().take(1500).collect()
}

impl DaemonMerger {
    pub fn new(agent: Arc<dyn BoxAgent>, rec: Option<BoxRecord>) -> Self {
        Self {
            agent,
            rec,
            flights: BTreeMap::new(),
        }
    }

    fn launch(&self, step: &Step) -> Result<String, String> {
        let rec = self
            .rec
            .as_ref()
            .ok_or("the conductor's box is not known to this server")?;
        let body = json!({ "argv": step.argv, "cwd": step.cwd, "env": {}, "labels": { "ozbox": "merge" } }).to_string();
        let (status, v) = self
            .agent
            .runs(rec, "POST", "", body.as_bytes())
            .map_err(|e| e.to_string())?;
        match status {
            200 | 201 => v["id"].as_str().map(str::to_string).ok_or_else(|| s("the box did not say which step it started")),
            404 | 405 => Err(s("the conductor's box agent is too old to run the merge steps; run `ozbox upgrade` on it")),
            429 => Err(s("the conductor's box is busy; the merge waits")),
            st => Err(format!("the conductor's box could not start a merge step (HTTP {st})")),
        }
    }

    /// Start the flight if it is new, advance it, and report. A flight is forgotten when it is done or fails.
    fn drive(&mut self, key: &str, steps: Option<Vec<Step>>) -> Result<Drive, String> {
        if !self.flights.contains_key(key) {
            let Some(steps) = steps else {
                return Err(s("no merge step is running"));
            };
            self.flights.insert(
                key.to_string(),
                Flight {
                    queue: steps.into(),
                    run: None,
                    from: 0,
                    out: String::new(),
                    done: Vec::new(),
                },
            );
        }
        loop {
            let Some(mut f) = self.flights.remove(key) else {
                return Err(s("no merge step is running"));
            };
            if f.run.is_none() {
                let Some(step) = f.queue.front() else {
                    return Ok(Drive::Done(f.done));
                };
                match self.launch(step) {
                    Ok(id) => {
                        f.run = Some(id);
                        f.from = 0;
                        f.out.clear();
                    }
                    Err(e) => {
                        // not started: nothing was run, the whole flight is dropped and asked again from the start
                        return Err(e);
                    }
                }
            }
            let (Some(rec), Some(id)) = (self.rec.clone(), f.run.clone()) else {
                return Err(s("the conductor's box is not known to this server"));
            };
            let (status, v) = self
                .agent
                .runs(&rec, "GET", &format!("/{id}/log?from={}", f.from), &[])
                .map_err(|e| e.to_string())?;
            if status != 200 {
                return Err(s(
                    "the box lost track of a merge step; the merge starts again",
                ));
            }
            let l = &v["log"];
            f.out.push_str(l["text"].as_str().unwrap_or(""));
            f.from = l["next"].as_u64().unwrap_or(f.from);
            let Some(code) = l["exit_code"].as_i64() else {
                self.flights.insert(key.to_string(), f);
                return Ok(Drive::Pending);
            };
            let step = f.queue.pop_front();
            let code = code as i32;
            let out = std::mem::take(&mut f.out);
            f.run = None;
            if code != 0 && !step.as_ref().is_some_and(|x| x.allow_fail) {
                return Err(format!("a merge step failed: {}", tail(&out)));
            }
            f.done.push((code, out));
            self.flights.insert(key.to_string(), f);
        }
    }

    fn worktree(branch: &str) -> String {
        format!("/work/orch/{}", dir_of(branch))
    }
}

impl Merger for DaemonMerger {
    fn rebase(
        &mut self,
        repo: Option<&str>,
        branch: &str,
        onto: &str,
    ) -> Result<RebaseOutcome, String> {
        let repo = repo.ok_or(
            "name the repository: the merge queue needs to know which one under /work/repos",
        )?;
        let (r, w) = (format!("/work/repos/{repo}"), Self::worktree(branch));
        let key = format!("rebase:{branch}");
        let steps = || {
            vec![
                Step {
                    argv: argv(&["git", "-C", &r, "fetch", "--prune", "origin"]),
                    cwd: r.clone(),
                    allow_fail: false,
                },
                Step {
                    argv: argv(&["git", "-C", &r, "worktree", "remove", "--force", &w]),
                    cwd: r.clone(),
                    allow_fail: true,
                },
                Step {
                    argv: argv(&[
                        "git",
                        "-C",
                        &r,
                        "worktree",
                        "add",
                        "--detach",
                        &w,
                        &format!("origin/{branch}"),
                    ]),
                    cwd: r.clone(),
                    allow_fail: false,
                },
                Step {
                    argv: argv(&["git", "-C", &w, "rebase", &format!("origin/{onto}")]),
                    cwd: w.clone(),
                    allow_fail: true,
                },
                Step {
                    argv: argv(&["git", "-C", &w, "diff", "--name-only", "--diff-filter=U"]),
                    cwd: w.clone(),
                    allow_fail: true,
                },
                Step {
                    argv: argv(&["git", "-C", &w, "rebase", "--abort"]),
                    cwd: w.clone(),
                    allow_fail: true,
                },
            ]
        };
        match self.drive(&key, Some(steps())).inspect_err(|_| {
            self.flights.remove(&key);
        })? {
            Drive::Pending => Ok(RebaseOutcome::Pending),
            Drive::Done(res) => {
                self.flights.remove(&key);
                if res.get(3).is_some_and(|(c, _)| *c == 0) {
                    // the branch was rebased in the worktree: it stays checked out there for the tests and the push
                    return Ok(RebaseOutcome::Clean);
                }
                let files: Vec<String> = res
                    .get(4)
                    .map(|(_, t)| {
                        t.lines()
                            .map(str::trim)
                            .filter(|l| !l.is_empty())
                            .take(50)
                            .map(str::to_string)
                            .collect()
                    })
                    .unwrap_or_default();
                Ok(RebaseOutcome::Conflict(if files.is_empty() {
                    vec![s("(the rebase could not complete)")]
                } else {
                    files
                }))
            }
        }
    }

    fn test(
        &mut self,
        _repo: Option<&str>,
        branch: &str,
        argv: &[String],
        lane: Option<&str>,
    ) -> Result<TestOutcome, String> {
        // A test-lane box is not used yet: the tests run on the conductor's box, in the worktree.
        let _ = lane;
        let key = format!("test:{branch}");
        let step = Step {
            argv: argv.to_vec(),
            cwd: Self::worktree(branch),
            allow_fail: true,
        };
        match self.drive(&key, Some(vec![step])).inspect_err(|_| {
            self.flights.remove(&key);
        })? {
            Drive::Pending => Ok(TestOutcome::Pending),
            Drive::Done(res) => {
                self.flights.remove(&key);
                Ok(match res.first() {
                    Some((0, _)) => TestOutcome::Pass,
                    Some((_, out)) => TestOutcome::Fail(tail(out)),
                    None => TestOutcome::Fail(s("the tests did not run")),
                })
            }
        }
    }

    fn merge(
        &mut self,
        _repo: Option<&str>,
        branch: &str,
        into: &str,
    ) -> Result<MergeOutcome, String> {
        let w = Self::worktree(branch);
        let key = format!("merge:{branch}");
        // a fast-forward of the base branch on the remote, from the rebased worktree: never forced
        let step = Step {
            argv: argv(&[
                "git",
                "-C",
                &w,
                "push",
                "origin",
                &format!("HEAD:refs/heads/{into}"),
            ]),
            cwd: w.clone(),
            allow_fail: false,
        };
        match self.drive(&key, Some(vec![step])).inspect_err(|_| {
            self.flights.remove(&key);
        })? {
            Drive::Pending => Ok(MergeOutcome::Pending),
            Drive::Done(_) => {
                self.flights.remove(&key);
                Ok(MergeOutcome::Done)
            }
        }
    }
}

/// The merge queue on the demo provider: the steps succeed at once, so the board and the queue can be shown without a box.
#[derive(Default)]
pub struct SimMerger;

impl Merger for SimMerger {
    fn rebase(&mut self, _: Option<&str>, _: &str, _: &str) -> Result<RebaseOutcome, String> {
        Ok(RebaseOutcome::Clean)
    }
    fn test(
        &mut self,
        _: Option<&str>,
        _: &str,
        _: &[String],
        _: Option<&str>,
    ) -> Result<TestOutcome, String> {
        Ok(TestOutcome::Pass)
    }
    fn merge(&mut self, _: Option<&str>, _: &str, _: &str) -> Result<MergeOutcome, String> {
        Ok(MergeOutcome::Done)
    }
}

#[cfg(test)]
mod tests;
