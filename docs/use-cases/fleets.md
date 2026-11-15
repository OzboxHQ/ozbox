# Fleets

A fleet is every box you run, driven by one `ozbox` command and one dashboard, under one budget. Boxes are cheap to
make and safe to throw away, because each one's work lives on its own `/work` disk.

See [how to read the status](README.md#how-to-read-the-status).

---

## 1. One box per project

**You want:** each codebase on its own machine, sized for it.

```
ozbox create web --size M --profile web-dev
ozbox create api --size L --label project=api
ozbox list
```

**Underneath:** `ozbox list` shows every box's state, size, disk, machine and snapshots across the regions you use; the
dashboard's fleet page shows usage and an estimated cost per box. A box that cannot be read says so, with the reason, instead of
showing empty bars, and a box whose self-test fails is listed under **Needs you**. Changes the dashboard makes to a box
(create, resume, resize, upgrade, destroy) run in the background, so the other pages keep answering while a machine starts.
On a dashboard that runs on a box, the fleet pages and every fleet change say "Fleet not connected".
**Status:** Preview (single boxes Work).

## 2. A throwaway copy for a risky experiment

**You want:** to try a big refactor without any risk to your main box.

```
ozbox snapshot main
ozbox clone main exp-1          # a new box from main's latest snapshot
# ... work, or let an agent work, on exp-1 ...
ozbox destroy exp-1             # type the name to confirm
```

**Underneath:** the clone gets its own disk made from the snapshot; `main` is never touched.
**Status:** Works (AWS: snapshot, clone and destroy ran end to end on a real box).

## 3. Different sizes for different jobs

**You want:** a small always-on box for daily work and a big one only when needed.

```
ozbox create daily --size S
ozbox create heavy --size XXL
ozbox pause heavy               # pay only for its disk until you need it
```

**Underneath:** sizes are provider-neutral (S … XXL, GPU-S, GPU-L); each provider maps them to the smallest machine
with at least those resources and says which in the plan ([ADR 0004](../adr/0004-provider-neutral-sizes.md)).
**Status:** Works (sizing); Preview for GPU sizes.

## 4. Boxes in more than one place

**You want:** some boxes on AWS and some on a cheaper VPS host.

```
ozbox create main --provider aws --size M
ozbox create side --provider hcloud --size S
ozbox providers                 # what each provider can do
```

**Underneath:** one provider interface, the same plans and the same conformance tests for every adapter
([ADR 0003](../adr/0003-provider-interface.md)). Anything a provider cannot do is refused at plan time, never half-done.
**Status:** Works (AWS); Preview (Hetzner).

## 5. A fleet budget that actually stops spending

**You want:** never to be surprised by the bill.

Set the monthly budget in `ozbox init` or Settings → Budget. Alerts go out at 50%, 80% and 100%; creating a box on a
real cloud needs a budget. A fleet cap limits how many boxes can exist at once.

**Underneath:** the estimate comes from live public prices (with their source and age); the real bill check is in
[Alerts, costs and guardrails](alerts-costs-guardrails.md).
**Status:** Preview.

## 6. A test lane

**You want:** CI-style test runs off your main box, so a full test suite never slows your editor.

```
ozbox create lane --size L --profile web-dev
```

Point heavy test runs and scheduled checks at `lane` (see [Agentic fleet](agentic-fleet.md)). Pause it outside working
hours, or let auto-pause do it.

**Status:** Preview.

## 7. Wake a sleeping box only when work is due

**You want:** boxes that cost almost nothing until a scheduled job needs them.

A schedule pointed at a paused box resumes it, runs, and lets auto-pause put it back to sleep. The schedule shows the
estimated cost of each wake.

**Status:** Preview.

## 8. The same tools on every box

**You want:** a new box ready to work in minutes.

```
ozbox profile save main web-dev --description "Node, Playwright, Claude Code"
ozbox create web2 --profile web-dev
ozbox tools plan web2 rust go           # add more later, planned first
ozbox tools install web2 rust go
```

**Status:** Preview.

## 9. Keep every box on the current image

**You want:** security updates and new tools on all boxes without losing work.

```
ozbox upgrade main --dry-run
ozbox upgrade main
```

Repeat per box (start with one you don't mind waiting on). See [Keeping boxes healthy](keeping-boxes-healthy.md).

**Status:** Works (single box, real AWS upgrades).

## 10. A conductor with worker boxes

**You want:** one box that splits a release into tasks and hands them to cheap worker boxes (including spot machines),
then gathers the results, with one board across every box.

**Status:** Planned (roadmap v0.4).
