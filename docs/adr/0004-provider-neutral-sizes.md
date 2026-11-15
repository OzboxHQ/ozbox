# 0004 — Provider-neutral sizes

**Decision.** Boxes are sized XS (4 vCPU/8 GB), S (4 vCPU/16 GB), M (8/32), L (8/64), XL (16/64), XXL (32/128), GPU-S and GPU-L. Each adapter
maps a size to its nearest machine type with at least those resources.

**Why.** People think in "bigger/smaller", not instance families, and a box definition must move between providers unchanged.

**XS (added 2026-11).** XS is 4 vCPU / 8 GiB (AWS `c7i.xlarge`; Hetzner has no dedicated 4/8 type, so XS uses `ccx23` and the plan says so). It is the shape the hpc-sandbox-benchmarks leaderboard measures, and a lighter box for small projects. S did not shrink: it stays 4/16 and stays the default for building a large app. The name follows the existing scheme: XS sits below S. Create it with `ozbox create NAME --size XS --disk 40` for a 40 GB `/work` disk (the minimum is 20; the root disk is separate).

**Cost.** The nearest machine may be larger (and dearer) than asked; the plan always shows the machine type chosen.
