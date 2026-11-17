# One box

One cloud workstation that holds your code, tools and running work, so your laptop is only a screen. Its persistent
`/work` disk survives pausing, resizing and upgrading.

See [how to read the status](README.md#how-to-read-the-status).

---

## 1. Set up Oz Box for the first time

**You want:** to go from nothing to a cloud account that is ready for boxes, safely.

1. Install the `ozbox` command and sign in to your cloud's own CLI (for AWS, `aws sso login --profile <yours>`).
2. Run `ozbox init --profile <yours> --budget <dollars a month>`.
3. Read the plan: the region, a private network with no inbound rules, a state bucket, the budget and its alerts.
   Confirm.

**Underneath:** OpenTofu creates the network and state from the modules in `infra/`; nothing listens on the internet.
A budget is required before any box can be created on a real cloud.
**Status:** Works (AWS). Hetzner: Preview.

## 2. Create your first box

**You want:** a workstation with a big persistent disk.

```
ozbox sizes                         # XS, S, M, L, XL, XXL, GPU-S, GPU-L and what each maps to
ozbox create main --size M --disk 200
```

The plan names the machine type, the disk and the monthly estimate, and that this computer gets the box's SSH entry once
it exists, so `ssh ozbox-main` works with no extra step (`--no-ssh-entry` skips it). After it is up, `ozbox show main` prints
its state, image, size and disk.

**Underneath:** the box boots the signed Oz image; first boot mounts `/work`, creates the box user and starts the box
daemon (`ozboxd`), which runs with no root powers.
**Status:** Works (the SSH entry written by `create` is Preview: tested in CI, not yet run on a real box).

## 3. Start from a profile of tools

**You want:** every new box to come with the same editors, agents and languages.

```
ozbox tools list                    # the catalogue: editors, AI agents, languages, cloud CLIs, bundles
ozbox create main --size M --tools bundle:web,claude-code,github-cli
ozbox profile save main web-dev      # keep this box's tools and settings as a profile
ozbox create api --profile web-dev
```

**Underneath:** tools are installed after boot from pinned, checksum-verified downloads, planned first.
**Status:** Preview.

## 4. Get into the box

**You want:** a shell, an editor or a desktop.

```
ozbox connect main --ssh --write    # (re)writes the SSH entry `ozbox-main` that tunnels through the provider; create writes it too
ssh ozbox-main
ozbox ide main                      # VS Code in your browser on http://localhost
ozbox open main --in vscode         # your desktop editor on /work/repos
```

**Underneath:** no port is open on the box; SSH rides the provider's session service and a key that is accepted for 60
seconds at each connection.
**Status:** Works (SSH, web IDE). Desktop editors: Preview. More in [Coding from anywhere](coding-from-anywhere.md).

## 5. Pause it at night, resume it in the morning

**You want:** to stop paying for compute when you are not working.

```
ozbox pause main                    # you pay only for the /work disk
ozbox resume main
```

You can also let it pause itself when idle (Settings → Boxes → Auto-pause).

**Underneath:** the daemon decides "idle" from real activity (CPU, sessions, runs) and saves work in progress first.
**Status:** Works (pause/resume). Auto-pause: Preview.

## 6. Make it bigger for a heavy week

**You want:** more CPU and memory for a release, without moving anything.

```
ozbox resize main --size XL --dry-run   # the new machine and cost
ozbox resize main --size XL
ozbox resize main --disk 400            # disks grow, never shrink
```

**Underneath:** the plan checks your cloud quota first, so a resize never strands a stopped box.
**Status:** Preview (quota check proven on AWS).

## 7. Keep your work in progress safe

**You want:** a restore point before something risky.

```
ozbox snapshot main
ozbox backup list main
```

**Underneath:** a snapshot of the `/work` disk, tagged to the box. Scheduled backups are in
[Keeping boxes healthy](keeping-boxes-healthy.md).
**Status:** Works.

## 8. See what the box is doing

**You want:** to know what is running and whether the box is healthy.

```
ozbox ps main                       # tmux sessions, coding agents, listening dev servers
ozbox show main
```

The dashboard's box page shows CPU, memory, disk and network over time, and its "Running on this box" list.

**Underneath:** the daemon keeps a small time-series of the box (5-second, 1-minute and 1-hour detail) and answers over
a local socket only.
**Status:** Preview.

## 9. Repair something only root can fix

**You want:** to fix the box without giving yourself or your agents root.

```
ozbox admin main -- collect-logs
ozbox admin main -- restart-services ozboxd
ozbox admin main -- reown --from-uid 1000      # hand files left by an old user id back to the box user
```

**Underneath:** the box user has no `sudo`. `ozbox admin` is the only root path: a short allow-list of actions, each
recorded on the box ([ADR 0011](../adr/0011-no-sudo-one-audited-root-path.md)).
**Status:** Works (`reown` and service restarts used on a real box).

## 10. Finish with a box

**You want:** to delete it cleanly.

```
ozbox destroy main --dry-run        # says it deletes the machine and /work, and keeps a final snapshot
ozbox destroy main                  # asks you to type the name
ozbox destroy scratch --no-final-snapshot   # a throwaway box: the plan says no copy of /work is kept; still type the name
ozbox destroy scratch --delete-snapshots    # also delete its existing snapshots: the plan lists each with its size and monthly cost
```

**Underneath:** a final snapshot is kept unless you pass `--no-final-snapshot`; the SSH entry and the stored host key are removed from this computer.
Snapshots the box already has are kept and billed after it is gone; the plan says how many. Add `--delete-snapshots` to delete them in the same plan (each is listed with its size and an estimated monthly cost; the name is still typed). Only snapshots tagged to this box are deleted, and one that another box was cloned from is refused. The final snapshot this destroy takes is kept. Or remove them first with `ozbox backup list <name>` and `ozbox backup delete <name> <id>`.
**Status:** Works (the plan's wording about kept snapshots and `--delete-snapshots` are Preview: tested in CI, not yet run on a real box).
