# 0002 — Plan, then apply

**Decision.** Every mutating command first produces a `Plan` (a list of concrete changes with a risk level), prints it, and
applies it only after confirmation (or `--yes`). `--dry-run` stops after printing. A plan carries `based_on`, a fingerprint
of the state it was computed from; applying refuses if the state has moved.

**Why.** People must see what will happen to their machines and money before it happens. Fingerprinting closes the race where
two commands plan against the same state and the second applies over the first. An already-satisfied operation plans to
nothing, so every command is idempotent and safe to retry after a network failure.

**Cost.** Providers must be able to describe a change before making it. A provider that cannot do something says so while
planning, never halfway through applying.
