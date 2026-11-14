# A task channel between your computer and a box

You and a coding agent on a box (call it `main`) pass work back and forth: "is the image built?", "here is the digest",
"I need you to push this branch". Today that is notes in a folder and a person saying "main has a message". `ozbox tasks`
replaces the notes with tasks that have a state, an answer, an acknowledgement and an audit record, and that cannot be
forged, replayed or reordered on the way.

See [how to read the status](README.md#how-to-read-the-status). **Preview:** built and covered by the test suite, including a
test that runs two real endpoints through the real program. It has **not** been run against a real box. The design is
[ADR 0044](../adr/0044-the-agent-mesh-a-task-channel-where-a-message-can-ask-and-never-grant.md), and the format is not frozen.

**What a message can do:** ask. A task never carries a permission, a secret or an approval. Writing "owner approved" in one
changes nothing. An act that needs approval (for example, pushing a branch from your computer) is **refused by name** until the
passkey approval path exists, and a Production act is refused outright. This release carries questions, notes, answers, status
and results.

---

## 1. Set up the two sides once

**You want:** your computer and a box to trust each other, and nobody else.

On each side, make an identity (a name and two keys; the private halves stay in a file only you can read):

```sh
ozbox tasks init --name laptop        # on your computer
ozbox tasks init --name main          # on the box
```

Hand each side's public identity to the other **by a way you trust**, then pin it. Pinning shows both fingerprints so you can
compare them over a call or a chat that is not this channel:

```sh
ozbox tasks identity > laptop.json                      # on your computer; copy the file to the box
ozbox tasks identity > main.json                        # on the box; copy the file to your computer
ozbox tasks pin main.json --via-arg ssh --via-arg my-box --via-arg /usr/local/bin/ozbox   # on your computer
ozbox tasks pin laptop.json                             # on the box
```

`--via-arg` is one word of the command that runs `ozbox` on the other side; repeat it for each word. It is run as an argument list, never through a shell, and a word may contain spaces. Name the program by its absolute path so nothing on the other side's `PATH` can stand in for it. On a box the channel runs as its own service user (`ozbox-mesh`), so agents there use the same commands but cannot read its keys.
Use whatever reaches the box already: `ssh`, `aws ssm`, or `env OZBOX_TASKS_DIR=... ozbox` for a local test.

**Limit:** on the box, the key file is readable by the box user. Run the channel as a user your agents cannot reach.

## 2. Ask a question and get the answer

**You want:** to ask the agent on `main` something and see its answer, with a record.

```sh
ozbox tasks send --to main --title "release check" --text "is the image built?"
ozbox tasks sync                       # send what is waiting, take what main has
ozbox tasks why <id>                   # where it is, and who acts next
```

On the box, the agent (or you) reads and answers:

```sh
ozbox tasks inbox
ozbox tasks status <id>                # shows the messages and marks them read
ozbox tasks reply <id> --text "built, digest pinned" --state completed
```

Back on your computer, `ozbox tasks sync` and `ozbox tasks status <id>` show `completed` and the answer. States are `held` (not yet
delivered), `submitted`, `working`, `input-required`, `completed`, `failed`, `canceled` and `rejected`. Only the side that received a
task moves its state; `ozbox tasks cancel <id>` is a request the other side decides.

## 3. Keep it open while you work

```sh
ozbox tasks watch --every 5
```

This syncs every few seconds and prints what is new. It runs only while you keep it open, holds no keys, and does not wake a
closed laptop: a task for a sleeping computer stays `held` and is delivered when it next syncs (or expires at its deadline,
24 hours by default, or `--minutes` on `send`). It polls; there is no push stream yet.

## 4. What it refuses, and how you hear about it

- **A key or token in a message.** Text that looks like one is refused when you send it and again when it arrives, and a refused
  task keeps none of its content: `refused: key-shaped-content`.
- **An act.** `ozbox tasks push-ref --to main --repo ... --ref ... --sha ... --env staging` is delivered and comes back
  `rejected: approval-path-not-built`. With a Production environment (or any environment not known to be safe) it is refused before it
  is sent: `production-act-refused`.
- **Too much, too fast.** 20 new tasks a minute and 50 open ones per sender; past that, `resource-exhausted`.
- **A repeated or replayed message.** Ignored. The same task id with different content is refused and recorded.

`ozbox tasks why <id>` says it in plain words. Every send, receipt, state change and refusal is in the audit record by task id and
code, never by text.

## 5. After a restore

If the store was restored from a backup, run `ozbox tasks restored`. It moves to a new epoch so nothing captured earlier is
accepted, and each peer pins the new one (`ozbox tasks pin <file> --replace`).
