# 0002 — Plan, then apply

**Decision.** Every mutating command first produces a `Plan` (a list of concrete changes with a risk level), prints it, and
applies it only after confirmation (or `--yes`). `--dry-run` stops after printing. A plan carries `based_on`, a fingerprint
of the state it was computed from; applying refuses if the state has moved.

**Why.** People must see what will happen to their machines and money before it happens. Fingerprinting closes the race where
two commands plan against the same state and the second applies over the first. An already-satisfied operation plans to
nothing, so every command is idempotent and safe to retry after a network failure.

**Cost.** Providers must be able to describe a change before making it. A provider that cannot do something says so while
planning, never halfway through applying.

## Amendment, 2026-11 — first-run setup: a step that fails part way is undone, a dry run previews every step, steps are chosen by flags

`ozbox init` applies several steps one after another (the state bucket, the network, the fleet's key, the adopt document, the
box policy). Three gaps let it leave an account half set up or ask a script to answer prompts. They are closed this way:

- **A step's plan includes its undo, and the plan says so.** When a step only creates (nothing changed, replaced, destroyed or
  adopted), its plan carries the command that removes exactly the resources it was creating, and a note in the plan says that
  a failure part way removes them again. If the apply fails, that command runs and the error says whether it worked; if it did
  not, the error says what may be left. A step that changes or adopts anything older is never undone automatically, because the
  undo could reach something that was there before. The state bucket is undone only after the bucket itself was made (it is
  empty then).
- **The plan refuses what the account cannot hold.** The network's plan reads the Elastic IP and NAT gateway quotas and what
  is in use, and refuses with the numbers and the request that raises them, instead of failing in the middle of an apply. A
  quota that cannot be read is said in the plan, never taken as enough or as short.
- **`--dry-run` previews every step.** Before the state bucket exists there is no state to plan against, so each later step is
  planned against an empty local state in a scratch folder. Such a plan is marked a preview, carries no command, and is refused
  by apply.
- **Steps are chosen with flags, never with answers on standard input.** `--only` and `--skip` name steps; a step left out is
  said and nothing about it is read or planned. The state bucket cannot be left out.
- **Every step runs the same provider code.** The generated roots pin one AWS provider version and share one lock file.

**What is not covered.** A preview cannot see what an apply of an earlier step would change (it plans each step on its own).
The undo is a targeted destroy: a resource the provider created but did not record in the state before failing is not
removed by it. Quotas other than Elastic IPs and NAT gateways (VPCs per region, for example) are not read yet.
