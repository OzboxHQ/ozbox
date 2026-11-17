# 0056 — Agents on different engines and providers share one neutral turn model, and each engine is an adapter at the edge

**Status.** Accepted. **Preview, integrated** (2026-11-17: the engine session runs inside the worker's hub agent, and a Claude-Code-like and a Codex-like program
work one fleet over the real transport in CI): built and tested in CI with fakes of each program (in-process transcripts and real
processes that check their own argv, environment and input). No Codex CLI or Gemini CLI run has been started on a real box
with a real account. Amends [ADR 0014](0014-supervised-agent-runs.md) decision 2 (engines are adapters). Related: ADR 0015
(Models routing), 0017 (per-run tokens), 0021 (hooks and notify), 0041 (approvals), 0042 (the hub), 0043 (the Oz Box tools for
agents), 0044 (the mesh), 0055 (a subscription sign-in an engine reads itself).

**Owner's goal (2026-11-17).** Agents collaborate across model providers, not only across copies of one model: Claude Code on
one box and Codex CLI on another (or both on one box) working one task through the hub, as well as two agents of the same engine do.

## Context

ADR 0014 made engines adapters behind `AgentEngine`, but only Claude Code had one. The Models routing already offered Codex,
Gemini CLI, Aider and OpenCode their providers, so a run on another engine was accepted and then refused with "that engine is
not set up". The hub (ADR 0042) carries tasks, questions, answers, status and results in frozen kinds, and the mesh (ADR 0044)
needs the same meaning on every engine. Without one definition of what a task, an ask, a reply and a result are, each engine
pair would need its own translation, and an engine's own details (its session ids, its tool-call format, its vendor) would leak
into the channel.

## Decision

1. **One neutral model, at the engine boundary** (`ozbox_core::engine_turn`). A run is seen as turns: something the agent
   said, a tool it used (its name only), an ask (a question, or an approval of an action), a reply, usage (tokens, a cost the
   engine reported, the model's name), a state (running, waiting, blocked, done, failed) and a result (a summary, a branch, a
   commit, links). It is defined once. **No engine or provider field is in a turn**: not the program, the vendor, the engine's
   session id or resume token, a tool's input or a key. Usage carries the model's name because the spend cap prices it; the
   provider it is billed to comes from the Models routing, so spend is metered per provider under the one cap that exists.
2. **The hub carries turns in its own frozen kinds** (`to_hub`, `from_hub`, the only mapping). A task is `task.assign`; a
   question is `question`, a reply `answer` and being stuck `blocked`, each as a body of exactly four fields (`orchestration`,
   `feature`, `kind`, `text`; unknown fields refused), the same shape as the hub's own answers about a feature (the merge
   queue's `conflict`, `tests-failed`, `merged`), which reach the agent as words with their kind. A reply is matched to its
   question by the task, because one agent holds one task on a worker; a question sent as plain words is a question about no
   task; the state is `status`; a result with a commit is `result`, and one without (an answer
   rather than a change) is `status` `done`. The envelope and the golden vectors are unchanged. Two new values of
   `status.state`, `done` and `failed`, are additive.
3. **An ask can ask and never grant.** An approval never becomes a message: it is handed to the ADR 0041 request flow of the
   box it happened on (the hub's approval path carries that request to `main`). A reply over the hub is data for the agent;
   only a decision made through ADR 0041 resolves a pending approval, and a session refuses a decision when nothing is waiting.
   Text that still looks like a key after redaction is refused, not sent.
4. **Each engine is an adapter that translates at its edge.** Everything an adapter starts goes through the box daemon's run
   API, as the Claude Code adapter does: the task text is the program's standard input (never argv), credentials are only in
   the process environment, and **another vendor family's credential variables are dropped at the edge**, so a Codex run can
   never read the token a Claude Code run was given (a sentinel test pins it).
   - **Claude Code** (unchanged): `claude -p --output-format stream-json`, a kept-open input for a conversation, the ask list
     as `--disallowedTools` ([headless mode](https://code.claude.com/docs/en/headless)).
   - **Codex CLI**: `codex exec --json -`, one process per turn, `codex exec ... resume <session> -` for the next message
     ([non-interactive mode](https://learn.chatgpt.com/docs/non-interactive-mode)). The per-run token is given as
     `CODEX_API_KEY` (and `OPENAI_API_KEY`), the broker's address as `-c openai_base_url=...`
     ([configuration reference](https://learn.chatgpt.com/docs/config-file/config-reference)). Codex takes no per-command
     list, so a run is sandboxed to its workspace (`workspace-write`, no network); a run started from a chat app is `read-only`.
     A run of an engine opted in to a ChatGPT sign-in (ADR 0055) is handed that sign-in by the box and nothing here.
   - **Gemini CLI**: `gemini --output-format stream-json --approval-mode auto_edit --prompt <fixed sentence>` with the task on
     standard input, one process per turn, `--resume <session>` for the next message
     ([headless mode](https://geminicli.com/docs/cli/headless/),
     [CLI reference](https://github.com/google-gemini/gemini-cli/blob/main/docs/cli/cli-reference.md)). In headless mode every
     shell command needs a confirmation nobody can give, so all are refused, not only the ask list.
   - **OpenCode stays Planned.** `opencode run` is documented, but not its machine-readable output, reading the task from
     standard input, or a settings file for one run ([CLI](https://opencode.ai/docs/cli/)). Aider is not planned in this
     release. Both are listed as `Unsupported`, with the reason, and Settings → Models says "not yet".
5. **What an engine can do is said honestly** (`engine_turn::capabilities`), and a conformance test checks each adapter does
   exactly what its row says: a conversation, the Oz Box tools inside a run (Claude Code: orchestration runs, through the
   repository's settings; Codex: yes, the server's address and the *name* of the variable that holds the run's token; Gemini
   CLI: no, it reads MCP servers only from a settings file and a file for one run is not built), the ask list command by
   command, stopping to ask (no headless engine does), tokens, and a cost the engine reports itself (Claude Code only).
   Anything not supported is `Unsupported`, never faked: an adapter that cannot ask never invents a proposal.
6. **One driver, any engine** (`EngineSession`): start a task on any adapter, read its turns, hand it a reply or ADR 0041's
   decision, stop it. In a conversation, a turn that ends waiting for the next message is the agent's question to whoever gave
   it the task. This is the API the hub's end-to-end harness uses to put a different engine on each box.

## What it does not do

- **No real run yet.** The output fields read from Gemini CLI beyond the event types the vendor documents follow the program's
  own stream formatter and are unproven; Codex's flag order with `resume` is from the vendor's page and unproven. The
  conformance suite is fakes. The owner's real run is the proof, and the marks stay Preview until it passes.
- **No approval inside a headless run.** Claude Code refuses the ask list up front; Codex and Gemini CLI refuse by sandbox or
  approval mode. An engine that stops and asks in a headless run (a permission hook, Claude Code's `--permission-prompt-tool`)
  is the next step, and it is what turns `asks_before_acting` to yes.
- **Gemini CLI runs do not reach the Oz Box tools**, and neither do Claude Code runs outside an orchestration.
- **The hub's worker does not yet apply an `answer`** itself: the approval and question path over the channel is being built
  with it (ADR 0042). The cross-provider test reads the answer at the channel layer.
- **A conversation on Codex or Gemini CLI starts a process per message**, so it costs one program start per turn.

## Benchmark

Nothing here is on a headline metric: the `realworld` suites start no engine. The agent command path gains no step for Claude
Code (one environment filter in memory). A Codex or Gemini CLI conversation starts one process per message (the program's own
start-up, not measured here: no real program runs in CI); the adapters' own work per line of output is a JSON parse.
