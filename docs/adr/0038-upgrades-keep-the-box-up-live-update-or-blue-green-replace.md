# 0038 — Upgrades keep the box up: a live update when the system disk can stay, a blue-green replace when it cannot

**Status.** Decided as a design. **Phases 1 and 2 of the build plan are built: Preview.** Phase 1 is the manifest and the
decision; phase 2 is runs that can outlive the daemon (Amendment 1). Both are covered by CI only: no image has been built from
them and nothing has run on a real box. **Every other part (phases 3 to 12) is Planned.** Nothing
here carries out a live update, and no release can offer one (see "Rules that hold before any release turns live updates on").
Today's upgrade (stop, replace the system disk, reattach `/work`, start) stays as it is and is the fallback: Works on AWS (run
on a real box), Preview on Hetzner (simulated). Each part below becomes Preview when CI covers it and Works only after the
real-box runs in the test plan.

**Phase 1 of the build plan changes no behaviour.** The image workflow
records the `upgrade` record in the signed manifest and `disk_generation` in `/etc/ozbox/image-release`, the parser reads both,
a pure decision (`ozbox_core::upgrade_kind::decide`) returns live, replace or in place with the reason, and `ozbox upgrade`'s plan
and `--json` carry one line naming it. Two things differ from the sketch in section 1, both because the generation is computed
by the image build itself (the package map and the kernel only exist after `apt` has run): `disk_generation` and the parts that
depend on the build (`kernel`, `packages`, `units`, `accounts`, `sshd`, `config`) are one value **per architecture** (a map keyed `amd64` /
`arm64`, as `ozboxd` and `ozbox` already are; a single string is read as the value for every architecture), while `first_boot` and
`build` stay one string; and `live_from` is not written until the release that ships the live updater (a manifest without it never offers a
live update). A record that is present but cannot be read is a refusal of the decision, reported in the plan as "not decided"
and not yet blocking the upgrade (that comes with phase 5). The plan's line and `--json` name what the releases call for apart
from what is done: `upgrade_kind` is `{"called_for": "live" | "replace" | "in_place" | "undecided", "carried_out": "replace",
"reason": ...}`. `carried_out` is `replace` in every release until the one that carries out a live update, and a reader keys on
`carried_out`, never on `called_for`: a plan that says "called for live" must never read as a live update having happened.
`upgrade-policy.json` supplies exactly `work_format`, `work_format_reads` and (since 2026-11-17) `secrets_keys` to the signed
record, and nothing else from that file is read. `secrets_keys` lists the store keys the release's secrets service opens by itself;
the upgrade plan refuses a box on the fleet's KMS key an image that does not list `kms` (ADR 0029 Amendment 18).

**Build status.** Part 2 of the build plan (section 9), *runs out of the daemon*, is built and **Preview**: CI covers it with a
fake of the box user's manager (the real shim, its socket, log and status file, and real programs; no systemd). Not yet run
on a real box. What exists: the run shim (`ozboxd run-shim <id> <record sha256> <runs dir>`), runs as `ozbox-run-<id>.service`
units of the box user's manager, the run record and its verification, re-adoption when the daemon starts, freeze, thaw and the
replace-pause, the controller delegation drop-in (`user@.service.d/20-ozbox-delegate.conf`) and the `user_manager_delegation`
self-test check. Everything else in this ADR is still Planned. Where the build differs from section 4 is in its amendment 1
at the end of this document.

**Decision.** `ozbox upgrade` chooses between two kinds of upgrade, from the two signed manifests involved and never from what
the box says about itself.

1. **Live update (the common case).** A release that changes only the signed programs is installed on the running machine by
   the root helper, after the manifest's signature and every file's hash are checked, and the services are restarted one at a
   time behind health checks. Terminal sessions, agent runs, SSH sessions and the web IDE keep running; they are not children
   of the box daemon any more (item 4). If any service fails its check, everything already switched goes back.
2. **Blue-green replace (when a new system disk is needed).** A second machine is built from the new image beside the running
   one, rehearsed, and kept waiting. At cut-over the old machine stops what it is doing, `/work` is unmounted, detached and
   attached to the new machine, which then starts its services. The old machine is kept stopped for a rollback window. The
   window in which the box does not answer is tens of seconds, not minutes.
3. **A stopped box is upgraded in place, as today.** Nothing is running, so there is nothing to keep up and no reason to pay
   for a second machine.

**What this is honest about.** A live update keeps processes. A blue-green replace keeps the *box*: its name, its addresses,
`/work` (where the box user's home, the secrets store's copy, the audit chain and the dashboard's state already live), the
tunnel and its sign-ins. It cannot keep a process, because `/work` is one disk that one machine mounts at a time: every process
on the old machine ends. Terminals reconnect to new shells, runs resume from a checkpoint, coding agents resume their own
conversations. "Zero downtime" is true of the live path; for a replace the promise is "a short, announced window with nothing
lost that was saved".

## 1. The manifest field that decides: `disk_generation`

A hand-set "needs a new disk" flag would be forgotten exactly once, on the release where it mattered. So the decision is
computed. The image workflow hashes, in a fixed order, everything that cannot change on a running machine and records it in the
signed manifest:

```json
"upgrade": {
  "disk_generation": "<sha256 over the parts below>",
  "disk_parts": {
    "kernel": "<version>", "packages": "<sha256 of the package map>", "first_boot": "<sha256 of infra/cloud-init/**>",
    "build": "<sha256 of infra/packer/ozbox-image/**, the image recipe>",
    "units": "<sha256 of every unit file the image or first boot writes>",
    "accounts": "<sha256 of users, groups and their members, uids, homes and shells>",
    "sshd": "<sha256 of the sshd configuration>",
    "config": "<sha256 of all of /etc but a short allow-list, the linger marks and the snaps present>"
  },
  "live_from": "0.3.0",
  "work_format": 2,
  "work_format_reads": [1, 2]
}
```

The same `disk_generation` line is written into the image's root-owned `/etc/ozbox/image-release` at build time.

- **Live** iff the target release is in the same minor as what the box runs (ADR 0036), is strictly newer, its `live_from` is at
  or below the box's applied release, and its `disk_generation` equals the generation of the image the box's disk came from.
  The program reads the box's image release from the box record and fetches *that* release's signed manifest; it does not ask
  the box. The root helper checks the same equality again against its own `/etc/ozbox/image-release`, so a box that lies, or
  a record that is wrong, fails closed. Equality means the target's image is, for everything above, the image the box already
  has, so a live-updated box really is the target release.
- **Replace** when any of that does not hold, when either manifest has no `upgrade` block (every image before this ADR), or
  across a minor version. Live updates across a minor are refused until a release proves it can (open question 6).
- `work_format` is the version of what Oz Box keeps on `/work`. A release that raises it must list the formats it reads; a
  rollback to a release that cannot read the current format is refused (section 5).
- The one-version rule (ADR 0036) is kept, with one refinement: the box's version is its **applied release** (a new root-owned
  `/var/lib/ozbox/applied-release`), and its image release is recorded beside it. `ozbox show`, the self-test, the
  compatibility refusal and `ozbox dashboard install`'s hash check all read the applied release. A box reports
  `release 0.3.2 (disk from 0.3.0, same disk generation)`.

**What may change live, and what forces a new disk.**

| Live (hashes in the manifest, installed by the root helper) | New disk (part of `disk_generation`) |
|---|---|
| `ozboxd`; the `ozbox` program, and with it the dashboard, which is embedded in it; the run shim (item 4), which is `ozboxd` itself | the kernel, and the package map (a package installed live would come from a mirror, not from the bits the release signed; security patches stay ADR 0035's separate path) |
| — (decided 2026-11-11: Chrome is never updated live; a Chrome change is always a new disk, see open question 1) | the first-boot configuration, which today includes the root helper and the setup scripts (ADR 0011: the helper is how a broken agent is repaired, so it is plain shell from first boot) |
| configuration *defaults* inside the programs (a new key must have a default that the previous first-boot configuration satisfies) | systemd units, users, groups and uids, sshd |

**A consequence to state plainly:** as the code is laid out today, the cloud-init template changes in most releases, so most
releases would be replace releases, and a bug in the root helper or in the live-update action itself can only be fixed by a
replace. Making live the common case needs the last phase of the build plan: the helper, the setup scripts and the units move
out of user data into a signed bundle in the release, and first boot shrinks to the box's identity (name, provider, pinned
approver, key ids, role). That also ends two known limits: AWS user data is close to its 16 KB ceiling, and a Hetzner rebuild
keeps the first-boot configuration the server was made with (ADR 0029, Amendment 8). Until that phase, expect a monthly minor
to be a replace. The first plan said most patches would be live; the 2026-11-13 review measured otherwise (decision 2 below),
so **most upgrades are replaces for now**.

### Rules that hold before any release turns live updates on

Phase 1 only names the kind, and no manifest carries `live_from`, so no upgrade is ever decided as live. The two rules below
(from the 2026-11-13 review) are what makes a live decision safe to act on. **Both must be true, and tested, before any release
writes `live_from`.** A guard test (`nothing_writes_live_from_until_the_adr_rules_hold`) fails the day a workflow, a script or
the policy file starts to write it; whoever does that makes the rules true first, deletes that test in the same change, and
says so here.

**1. The disk generation covers everything a running machine cannot change.** Deny by default: a file the image writes that is
not on a short, named allow-list moves the generation, so a wrong guess costs a replace and never a live update onto a disk
that lacks the change. The generation covers:

- the kernel and the package map, and the snaps present (the SSM agent comes from a snap, outside dpkg);
- the first-boot configuration, and the image recipe: the hash of `infra/packer/ozbox-image/**` (the template, `provision.sh`
  and the helper scripts), recorded as `build`, so a change to how the image is made moves it even when no package changes;
- every systemd unit and drop-in, and which are enabled;
- accounts: names, ids, home, shell **and group members** (adding the box user to a privileged group is a change to the disk);
- sshd's configuration;
- all of `/etc` but a named allow-list (`machine-id`, `hostname`, `hosts`, `resolv.conf`, the host keys, `shadow` and `gshadow`
  and the backups of `passwd` and `group`, the cloud-init network and build files, `/etc/ozbox/`): this covers `sysctl.d`, the apt
  sources, keyrings and pinning, `apt.conf.d`, `/etc/default` and the rest;
- the linger marks under `/var/lib/systemd/linger`.

Each of these has a fixture test that moves exactly its own part, and the allow-listed files have a test that they do not move
it. The first real build is what shows whether the allow-list is long enough: a file a build writes differently every time
makes two builds of one commit differ (a replace, the safe direction), and is then added to the list on purpose.

**2. The decision separates the applied release from the disk, reads both from the provider, and checks the first boot.**
Today `decide` takes one value, the laptop's record of the box's image, for both the version the box runs and the disk it has.
Once a live update exists, the box's **applied release** (what it runs) and the **disk image** (what its system disk came from)
differ: "release 0.3.2 on a disk from 0.3.0" is the normal state after one. So, before `live_from` is written:

- `decide` takes two sides for the current box: its `applied_release` and its `disk_image`. The version comparisons use the
  first and the generation comparison uses the second;
- the disk image and the box's state are read from the **provider** (the instance's image id and its state), never from the
  laptop's record, which is wrong after an interrupted upgrade or a box paused behind the laptop's back;
- the first-boot tag the box cannot change (the provider's record of the first boot the machine was made with) must equal the
  manifest's `first_boot`, or the decision is replace: equal manifests do not mean an equal box (a box made with
  `--allow-first-boot-mismatch`, or by an older program, ran another first boot than its image's manifest says);
- each rule has a test.

**3. The record's keys are fixed.** The signed record is built by `infra/packer/ozbox-image/upgrade-record.jq`, which takes
exactly `work_format`, `work_format_reads` and `secrets_keys` from the policy file; a test runs that same file against a policy file that tries
to set `disk_generation` or `live_from` and checks that nothing changed.

### Decisions of 2026-11-13

- **Most upgrades are replaces, for now (decision 2).** The package archive is **not** pinned. Both generation changes measured
  between consecutive images came from vendor repositories (Firefox, Chrome), and `claude-code` and `gh` are unpinned, so a pinned
  Ubuntu archive would not make two builds equal. Revisit at phase 4; the likely answer is a patch release that reuses the
  previous image instead of building a new one.
- **"Survive" means a session comes back, not a process.** No process survives an AWS resize (RAM is lost, and hibernating would
  write secrets to disk, against ADR 0045). **A resize stays in place:** quiesce, stop, resize, start, resume. It is not a
  blue-green replace in the first release that has it. What the first release must have, and the honest line the docs carry until a
  real-box resize proof passes ("sessions come back; running programs end"), is a session record on `/work`, quiesce before a
  resize or an upgrade, and resume at every boot (a crash, an OOM, a pause or a forced stop included).

## 2. Live update

1. **Plan** (the laptop or the dashboard): the trust gate as today (one-version compatibility, Sigstore signature, ADR 0036),
   the kind decision above, the components that differ (by hash), the services each one restarts, and what a person will
   notice (the table below). The secrets store is not touched: the plan says the store-fate check does not apply and why.
2. **Approve.** The new helper action `apply-release <version> <manifest sha256>` is **gated** in both gate tables (the helper's
   and the program's; the test that compares them covers it). An agent can file a helper request, and an ungated action would
   let it pick its moment to restart the dashboard or, without the version rule, install an older signed release with a known
   flaw. The proof is either a signature by the key pinned when the box was made, over a one-time challenge bound to the box,
   both versions and the manifest's digest (the `recover-secrets` mechanism, ADR 0029 Amendment 8), or a dashboard approval of
   a new scope `release-apply` after a fresh second factor (ADR 0023). On a box with no approver the scope follows the one
   table (ADR 0028, Amendment 2): this ADR enters it as **allowed and recorded `bootstrap`** for a strictly newer release in the
   same minor, and refused otherwise.
3. **Fetch and verify on the box.** The helper extends `ozbox-install-agent.sh` rather than adding a second downloader: it
   downloads the manifest and its bundle, verifies the Sigstore signature itself (cosign joins the image, pinned and hashed),
   requires the manifest's digest to equal the one the approval named, then downloads each changed file and installs it only if
   its hash matches. A hash from the request is never trusted on its own. Files land in
   `/usr/local/lib/ozbox/releases/<version>/` (root, `0755`); nothing that runs has changed yet.
4. **Refuse a step backwards.** The helper refuses a version that is not strictly newer than the applied release, and refuses a
   different minor. The only way back is the rollback in section 5, which also needs an approval.
5. **Switch one service at a time.** `/usr/local/bin/ozboxd` and `/usr/local/bin/ozbox` become root-owned links into the
   release folder, switched with an atomic rename. A journal (`/var/lib/ozbox/release-journal`, root) records each step before
   it happens. The order and the check after each:
   - `ozboxd`: it gets a socket unit (`ozboxd.socket`), so calls made during its restart wait in the socket instead of
     failing. Check: its health route answers and a short self-test passes.
   - The socket-started root services (the tool, backup and run launchers) need no restart: the next start uses the new
     program.
   - `ozbox-secrets`: runs are frozen (item 4) for the restart, because the credential broker and the audit writer live in it
     and an audit append fails closed while it is away (ADR 0028). Check: the store is ready, the chain verifies, and a broker
     token can be issued. Runs are thawed.
   - `ozbox-supervisor` (the dashboard): last, because it is often what asked for the update. Check: its health route over
     loopback, and its embedded dashboard hash equals the manifest's.
   - Chrome, when the release carries it: only between browser actions; open browser sessions are paused the way ADR 0037
     pauses them at a limit and resumed after.
6. **On any failed check, everything switched goes back** in reverse order, to the exact files that were running, and the
   result says which step failed and why. This automatic return needs no approval: it restores what was approved before.
7. **The helper finishes on its own.** The request is complete when it is filed; a laptop that goes away, or a dashboard that
   is restarted by the update it asked for, reads the result later (`ozbox upgrade <box> --status`). At boot, a oneshot unit
   ordered before every service reads the journal and returns to the last release that passed all its checks if a switch was
   left unfinished (power loss, a crash of the helper).
8. **The record.** The applied release goes to the box record and the instance labels, and the audit chain gets one entry per
   step (versions and outcome, never a path or a hash the person did not see).

| Who notices what, during a live update | Expected (reasoned, to be measured) |
|---|---|
| SSH sessions, tmux, terminals, coding agents in tmux, the web IDE, local models | nothing |
| Agent runs | frozen for the secrets service's restart, about 1 s; nothing if it did not change |
| Calls to the box daemon | delayed about 1 s, none refused |
| The dashboard | 2 to 5 s of "reconnecting" while it restarts; the tunnel connector is not restarted, sign-ins survive |
| A browser terminal in the dashboard | its connection drops and reconnects in 1 to 3 s; the tmux session behind it is unchanged |
| A browser session of an agent | paused and resumed, only when Chrome itself changed |

## 3. Blue-green replace

### 3.1 The final transfer: three ways compared

| Way | What it needs | Window | Verdict |
|---|---|---|---|
| **Detach and attach the same `/work` volume**, the new machine already booted and waiting | the volume unmounted on the old machine | AWS: unmount 3 to 10 s, detach 5 to 15 s, attach 5 to 15 s, mount and start 10 to 20 s, tunnel 2 to 5 s: **about 30 to 60 s, under 2 min at worst**. Hetzner: its volume actions take 5 to 20 s each: **about 40 to 90 s** | **Chosen for both providers.** No second copy that can diverge, one writer guaranteed by the cloud (a volume attaches to one machine), and the only way on Hetzner |
| Incremental snapshot, then a new volume from it | an EBS snapshot of the last changes | the final snapshot must complete before the new volume exists, then the volume loads its blocks lazily from storage: **3 to 10 min** and slow first reads, unless fast restore is paid for every hour it is on | Rejected for the cut-over. Used for the rehearsal copy and as the safety copy on AWS. Hetzner cannot snapshot volumes at all |
| rsync over a private path | one machine to accept a connection from the other | the final pass is a scan of every file on `/work` (a few million in `node_modules` takes minutes) | Rejected: it needs an inbound port, which no box has (ADR 0005, enforced by tests). A copy through the encrypted bucket keeps outbound-only but has the same scan cost |

The figures are reasoned from each provider's documented behaviour and what real upgrades showed (the old path took several
minutes on AWS). They become measured numbers in the real-box runs, and the docs quote only measured ones.

### 3.2 The new machine: standby, rehearsal, promotion

First boot is split in two, and that is the main change on the box:

- **The machine stage** needs no `/work`: packages, accounts, units, the root helper, the metadata guard, the egress guard.
- **The work stage** needs `/work` and is idempotent: the uid pinning from the disk's owner, the box user's manager (linger),
  the secrets service, `ozboxd`, the dashboard, the tunnel connectors, the timers. It runs at every boot after `/work` mounts,
  and at promotion.

A machine made with the role `standby` (a first-boot value) runs the machine stage and then waits for its `/work` volume, by
the volume's id, also given at first boot. While it is a standby, every unit that acts on the world is held off by a condition
on `/etc/ozbox/standby`: the dashboard, the tunnel connectors, schedules, backups, patch restarts, idle pause, and the box
user's own manager (so no user service the box user wrote, such as a tunnel of their own, can start). The box-wide egress list
is put in enforce mode with only what promotion needs (the provider's session and key services, the vault, the release
host), so a tunnel cannot join even by mistake.

- **AWS rehearsal.** A fresh snapshot of `/work` is taken while the box keeps working (incremental from the daily one, no pause:
  a crash-consistent copy is enough). A rehearsal volume made from it is attached to the standby, and the work stage runs in
  rehearsal mode: the self-test, the store opened read-only (proving that the key reaches the new machine: KMS through the
  label, a file key through the vault's escrow), the audit chain verified, the box user's files readable. Nothing starts that
  acts. The rehearsal volume is then detached and **deleted** (it holds a copy of the store's ciphertext), and the standby
  waits again. Real upgrades found their defects exactly here (a missing folder on `/work`, files under an old uid, user
  services that did not start), so the rehearsal is worth its few minutes.
- **Hetzner rehearsal is weaker, and says so.** Hetzner cannot make a volume from a snapshot, so a standby there proves only the
  machine stage, plus that the store's key can be reached (the vault escrow) when it is not a file on the old disk. Its
  self-test on real data is the first step after the attach, with the automatic rollback below. A Hetzner standby is reached
  over the fleet's own tailnet (ADR 0030, a one-use key for a standby name) when there is one; without one, only its state as
  the API reports it is known before cut-over.

The store-fate check (ADR 0029, Amendment 8) runs before any of this, unchanged: a store that would be lost, or a box that
cannot be asked, is refused without `--accept-new-secrets-store`. Blue-green makes the check stronger: on AWS the rehearsal
*opens* the store on the new machine before the old one stops, and a failure there stops the upgrade with the old box untouched
and its key still on its own disk.

### 3.3 Cut-over

1. **Warn.** Every person on the box's channels, the dashboard and each tmux client is told: "this box restarts on a new
   machine in 5 minutes; files and saved work are kept, running programs end". The answers are "now" and "postpone" (like the
   idle-pause warning); a postpone holds the upgrade for a limit the owner sets. `--now` skips the wait.
2. **Quiesce, still reversibly.** Each supervised run is frozen, its repository checkpointed to a `wip/` branch (ADR 0019), its
   engine session id saved on `/work`, then stopped and marked "paused for an upgrade". Coding agents found in tmux panes and
   the tmux window layout (names and folders) are recorded on `/work`. Browser sessions pause (ADR 0037). Until the next step
   everything can be thawed and the upgrade abandoned with the old box exactly as it was.
3. **Release `/work`.** A new helper action `release-work` stops the acting units, syncs and unmounts `/work`, and arms a
   dead-man timer: if no promotion is confirmed within 10 minutes, the old machine mounts `/work` again and starts its
   services, as long as the volume is still attached to it. If the old machine cannot be reached, it is stopped instead (a
   clean shutdown unmounts too). A filesystem freeze is not used: an unmount is stronger and the machine is stopping anyway.
4. **Move the volume.** The upgrading computer disarms the dead-man timer, checks that the old machine still reports `/work`
   unmounted (and refuses the detach if it was mounted again), then detaches from the old machine and attaches to the standby,
   as two calls with nothing between them. This is the only moment that depends on the computer running the upgrade
   (section 6).
5. **Promote.** The standby sees its volume, removes `/etc/ozbox/standby`, mounts `/work`, runs the work stage and its
   self-test. It needs nothing from the laptop to do this.
6. **Point everything at the new machine.**
   - **The Cloudflare tunnels need no change.** The connector's token is in the store on `/work`, so the connector that starts
     on the new machine *is* the cut-over; the hostname, the DNS record and the Access application stay as they are. The old
     connector stopped in step 3, so the two never serve at once.
   - ngrok: the same token and reserved domain, old first, then new. A tailnet (Tailscale, Headscale): the machine is a new
     node; the old node is removed and the new one takes the box's name at promotion, with a one-use key.
   - The SSH entry on this computer points at the new machine and the old host key is forgotten (as today). Other computers
     run `ozbox ssh-config` again, which reads the active machine from the record.
   - The box record: the active slot, the image and applied releases, and the provider labels.
   - The backup repository's credentials stay in the secrets store, which comes through the upgrade with the store; when it does not, they are put back from this computer when it holds them, and otherwise backups stop and the report fails with the command that sends them. Backups that were set up are then checked to answer, as part of the self-test. The managed services are put back with the steps today's upgrade already uses.
7. **Resume work.** The dashboard resumes each paused run from its checkpoint and the engine's own resume, offers to reopen each
   recorded coding agent in a new tmux window in its folder, and recreates the recorded tmux windows. Scrollback and plain shells
   are not kept, and the warning said so.
8. **Keep the old machine.** On AWS it stays stopped (its system disk costs a few cents a day; the plan shows the figure) for
   the rollback window, 24 hours by default. On Hetzner a stopped server costs as much as a running one, so the old server's
   system disk is snapshotted and the server deleted; a rollback makes it again from that snapshot. Expired old machines are
   listed as forgotten resources (ADR 0016) and removed by `ozbox upgrade <box> --finish`, or by the next upgrade.

### 3.4 How the infrastructure state holds two machines

Both box modules get **slots**: the machine becomes `for_each` over a set of slot names (`a`, `b`) with the image and the role
per slot, and the `/work` attachment follows a variable `active_slot`. Existing state moves with `moved` blocks
(`aws_instance.box` to `aws_instance.box["a"]`), so no box is touched by the move. Each step of the upgrade is its own plan
with its own guard, the same discipline as today's upgrade guard:

| Step | The plan may only |
|---|---|
| Prepare | add the standby slot's machine (and on AWS the rehearsal volume and its snapshot) |
| Rehearsed | remove the rehearsal volume and its attachment (AWS) |
| Cut over | replace the `/work` attachment (and nothing else, not the volume) |
| Roll back | replace the attachment back |
| Finish | remove the old slot's machine |

The slot attachment sets `stop_instance_before_detaching = false` (today's single attachment stops the machine first, which
would add about a minute to the window): `release-work` has already unmounted `/work`, and stopping the old machine stays the
fallback, as its own step before the cut-over plan, only when the old machine cannot be reached. `ozbox adopt` learns to find
both slots by their labels. Hetzner's blue-green therefore makes a **new server** from the current
module, which also gives it this release's first-boot configuration and pinned approver; the in-place `-replace` path stays
as the fallback for a stopped box.

## 4. Sessions and runs no longer live inside the box daemon

Today a run is a cgroup scope under `ozboxd.service`'s delegated cgroup, its pipes are held by the daemon, and a tmux server
first started from a dashboard terminal is forked from the daemon's pseudo-terminal, so it sits in the same cgroup.
`Delegate=yes` does not stop systemd from ending everything in a unit's cgroup when the unit stops, so restarting the daemon
ends them all. The change:

1. **A run is a transient service of the box user's own manager**, `ozbox-run-<id>.service`, started with an argv array
   (`systemd-run --user`) with `MemoryMax`, `MemoryHigh`, `CPUWeight` and `RuntimeMaxSec`, the same limits the daemon sets now.
   The box user's manager must delegate the memory and cpu controllers (`user@.service` drop-in, a first-boot change), or the
   limits would not hold; the self-test checks it. ADR 0019's local models are the precedent: they are already units of that
   manager.
2. **A small shim owns the run's ends.** The unit's program is `ozboxd run-shim <id>`: it writes the output to
   `/work/.ozbox/runs/<id>/log` (the daemon already reads output from a byte offset, so the API does not change), keeps the
   standard input open behind a socket only the box user can open, and records the exit status. A scope would not do: its
   process is still the daemon's child, so the daemon's pipes would close under it. The environment (secret) reaches the shim
   over that socket when it starts, never an argument or a unit property, which `ps` and `systemctl show` would print.
3. **The daemon re-adopts.** Each run's record (`run.json`: id, program name, labels, limits, the unit, the SHA-256 of a
   controlled run's capability, never a value) is on `/work`, so a restarted daemon lists `ozbox-run-*` units, reads their
   records and carries on: the log offset, the standard input, stop, and the controlled-run capability check of ADR 0037 all
   survive. The shim protocol is versioned and the daemon speaks the previous patch's version, so a run started before an
   update is driven by the daemon after it.
4. **The shared tmux server is a user service** (`tmux -D`, the box user's default socket), so the dashboard terminal, SSH and
   editors attach to a server the daemon never owns. The dashboard terminal is only an attach client and reconnects. A browser
   terminal with tmux turned off is a plain shell owned by the daemon: a live update ends it, and the plan says so first.
5. **Pause has two meanings, by path.** For a live update a run is frozen with the cgroup freezer (`systemctl --user freeze`),
   which needs no help from the engine and costs it nothing but the time. For a replace a frozen process cannot move, so the
   run is checkpointed, stopped and resumed by its engine on the new machine (section 3.3).
6. **What does not move:** the workload commands of ADR 0018 item 8 and the browser worker are already units of their own
   users; nothing changes for them.

## 5. Rollback

- **Live:** `ozbox upgrade <box> --rollback` switches the links back to the previous release kept in
  `/usr/local/lib/ozbox/releases/` (the last two are kept) and restarts in reverse order, with the same checks. It needs the
  same approval as a forward update, so the helper's step-backwards refusal holds against an agent.
- **Blue-green, before the volume moved:** abandon. The old box thaws and carries on; the standby is removed.
- **Blue-green, after:** `--rollback` quiesces the new machine, releases `/work`, moves the attachment back, starts the old
  machine (AWS) or makes it again from its snapshot (Hetzner), and points everything back. The data is the newer data: whatever
  the new machine wrote is kept. That is why `work_format` exists. A rollback to a release that cannot read the current format
  is refused, and the way back is then the safety snapshot (AWS: the one taken before the cut-over), which the plan names with
  what it would lose.
- **Automatic.** If promotion fails (the self-test, the store does not open on the real `/work`), the upgrading computer, which
  is waiting for that answer, rolls back at once. If it is no longer there, the next `--resume` does.

## 6. Failure halfway, two people at once, a laptop that goes away

**The journal and the labels say where an upgrade is.** Every blue-green step is written before it is taken: on the provider's
labels of the volume and the machines (extending today's `ozbox-upgrade-to` mark: the phase, the slots, the operator, an epoch)
and in the upgrade journal kept beside the box's infrastructure state. `ozbox upgrade <box> --resume` reads them and finishes or
rolls back; `--abort` is allowed until the volume has moved. Any computer with the box's state can resume, which is one more
reason for the bucket backend (ADR 0033).

| It stops here | What is left | Who recovers it |
|---|---|---|
| Standby being made or rehearsed | the old box untouched, still working | `--abort` removes the standby; `--resume` goes on |
| Warned or quiesced | runs frozen or checkpointed, the old box still has `/work` | `--abort` thaws everything; `--resume` goes on |
| After `release-work`, before the detach | the old box idle, `/work` unmounted | the dead-man timer brings the old box back in 10 minutes by itself |
| Between the detach and the attach | **the box is down**; the volume is free and labelled with the target slot | `--resume` from any computer with the state attaches it to the standby (or back, with `--rollback`). This is the only window that needs the upgrading computer, and it is two API calls long |
| After the attach | the new machine promotes itself and serves; the old one is idle | nothing urgent: `--resume` finishes the record, the SSH entry and the old machine |
| Promotion failed | the box is down on the new machine | the waiting computer rolls back; otherwise `--resume --rollback` |

**Two people at once.** An upgrade holds a lease for its whole length, not only the length of one `tofu apply`. With the bucket
backend the lease is an object beside the state written with a conditional write, with an epoch and a heartbeat, the scheme of
the schedules' failover (ADR 0013, addendum): a second upgrade is refused with who holds it, since when and in which phase, and
can take it over only after the heartbeat has stopped for a full lease, by its own clock. With local state there is one computer
and its own lock file. On the box, the helper takes a lock of its own for `apply-release` and `release-work`, so a laptop and a
dashboard cannot both drive one box. Steps are fenced by the epoch: a holder that was cut off and comes back is refused.

**A box cannot replace itself.** A dashboard on a box may live-update that box (it files the request and reads the answer after
its own restart), and it may replace *other* boxes. It may not drive the replace of its own box, because it runs on the machine
being stopped; it says so and names the command to run from a computer.

**Other refusals before anything changes:** no capacity for the new machine in the volume's zone or location (a volume cannot
leave it); the fleet cap or budget, which counts the standby for the length of the upgrade and shows its cost; a schedule's
window, which a replace waits for the way idle pause does.

## 7. Security

- **Nothing secret goes through the box user.** A live update moves no secret. In a replace, the store's ciphertext moves with
  the volume; the store's key reaches the new machine only as it does today (KMS by the box's label, a file key by the vault's
  escrow, or the laptop keychain through the ingress account once that exists); tunnel tokens stay in the store. The rehearsal
  copy is deleted once used.
- **The store's fate** is checked as today and, on AWS, proven on the new machine before the old one stops. Escrow, a revoked
  pin staying revoked (it is recorded on `/work`) and the recovery's double check are unchanged.
- **The pinned approver is kept.** The new machine's first boot pins the key the box record says was pinned at creation; only
  a box with none gets the upgrading computer's key, and the plan says so. On Hetzner this is now possible, because the new
  machine is a new server.
- **The release signature** is verified on the laptop (as today) and again on the box by the helper, bound to the approval. A
  step backwards needs an approval; an agent can at most bring forward a strictly newer, signed release in the same minor, and
  only where the box has no approver yet.
- **No inbound ports.** Both machines only dial out; the transfer is the cloud moving a disk.
- **One writer.** The cloud enforces it (single attach), and the standby's held units and enforced egress make sure a copy of
  the box never acts in the world.
- **Every step is reversible or gated:** live switches go back automatically; a replace is abandonable until the volume moves,
  and after it is rolled back by moving it again; the old machine is kept for the window; the steps that cannot be undone
  (deleting the old machine at `--finish`, a rollback that would need the safety snapshot) are their own plans with their own
  confirmation.
- **What the box says is never the gate.** The box answers through the box user's shell, so an agent can make it lie. The
  kind decision is made from signed manifests and the record; the helper re-checks against root-owned files; a lie can only
  cause a refusal or a replace the person sees in the plan.
- **The audit chain** gets each step, and its continuity across the replace is checked by the new machine's self-test.

## 8. Test plan

- **Unit (pure, any OS):** the kind decision over fixture manifests (equal and different generations, no `upgrade` block,
  across a minor, older, `live_from`); the work-format rollback rule; the blue-green state machine from every phase, including
  `--resume` after each, with the fake provider; the lease (takeover only after a silent full lease, fencing by epoch); the run
  record and re-adoption; the gate tables (`apply-release`, `release-work`, the `release-apply` scope in the one table); the
  plan guards of each slot step.
- **Infrastructure:** `tofu test` for both modules with slots: the `moved` blocks plan to nothing on an existing box, each step's
  plan changes only what its guard allows, zero ingress still holds; the helper's actions in its shell tests (signature, hash
  mismatch, step backwards, journal recovery, dead-man timer), with fakes for systemd.
- **End to end in CI:** a systemd container job installs release N signed with a test identity, starts a run, a tmux session and
  a frozen-capable run, applies N+1 and checks the run's process and the tmux server kept their pids, then forces a failed health
  check and checks the return to N. The demo fleet gets both kinds in the dashboard, with browser specs at the three widths.
- **Real box, before any mark moves:** on AWS and on Hetzner, each kind, with a probe on the laptop that hits the dashboard
  through the tunnel and holds an SSH session, recording the first and last failure to the second; a run that must survive a live
  update; a replace with a run that must resume; a pulled network on the laptop between the detach and the attach, recovered by
  `--resume` from a second computer; a rollback in both kinds. The measured windows replace the reasoned ones in the docs.

## 9. Build plan (in dependency order, one agent each)

1. **The manifest and the decision.** `upgrade` in the image workflow (with `disk_generation` in `/etc/ozbox/image-release`),
   the parser, the pure kind decision, and the plan line that says which kind and why. No behaviour changes yet.
2. **Runs out of the daemon.** The run shim, user units, run records and re-adoption, freeze and thaw; the controller
   delegation drop-in and its self-test.
3. **The terminal side.** The tmux server as a user service, the dashboard terminal as an attach client that reconnects, the
   tmux layout record.
4. **The helper's live update.** The release folder and links, `ozboxd.socket`, `apply-release` and the rollback with the
   journal, the boot-time recovery, the step-backwards refusal, the gates and the `release-apply` scope, cosign on the image.
5. **`ozbox upgrade` live, and the dashboard's.** Plan, approval, status, rollback, the applied release in the record and every
   reader of the version.
6. **Standby and promotion on the box.** The machine and work stages, the standby role and its held units and egress,
   promotion on the volume's arrival, `release-work` with the dead-man timer, the rehearsal mode of the self-test.
7. **Slots in both modules.** `for_each` machines, `moved` blocks, `active_slot`, the per-step guards, `adopt` for slots. (Agent
   work already in progress on Hetzner's `-replace` is the in-place fallback this keeps.)
8. **The blue-green engine and AWS.** The provider operations (prepare, cut over, roll back, finish) in the shared interface and
   the fake provider's conformance suite, the AWS adapter with the rehearsal snapshot, the journal, the labels, the lease,
   `--resume`, `--abort`, `--finish`.
9. **Quiesce and resume, and Hetzner.** Warnings and postpone, checkpoint and resume of runs and coding agents, the tunnel kinds,
   the SSH entry and the record; the Hetzner adapter with its root-disk snapshot for the rollback window.
10. **The dashboard's upgrade pages and the docs.** Both kinds, progress, rollback, the use cases and their marks, the
    changelog, `docs/releases.md`.
11. **The signed host bundle.** The helper, the scripts and the units move from user data into the release, first boot shrinks
    to the box's identity, and a reconciler applies the bundle; this is what makes live the common case. Already in place
    (ADR 0036, amendment "the box modules and the first-boot configuration belong to the program"): the program carries and
    hash-checks its own modules and first-boot configuration, the signed manifest records their hash as `first_boot` (the
    value `disk_parts.first_boot` takes in section 1, which covers the two box modules as well as `infra/cloud-init/**`), and
    each box records the hash it booted with in `/etc/ozbox/first-boot`, so a stale first boot is detected and repaired by a
    same-image replace.
12. **Real-box runs**, then the marks.

## Open questions for the owner

1. **Chrome. Decided (owner, 2026-11-11): a Chrome change is always a new-disk change.** Chrome stays an image-level package from Google's signed repository with its key pinned; a live update never fetches or carries it, so no redistribution question arises and a browser session is never paused for a live update.
2. **Who may start a live update.** Gated always (as decided here, `bootstrap` on a box with no approver), or allow an unattended
   fleet to take signed patches by itself on a schedule?
3. **The rollback window.** 24 hours stopped on AWS and a system-disk snapshot on Hetzner, or longer, or shorter?
4. **The seconds that need the laptop.** Accept them (two API calls, recoverable from any computer with the state), or run the
   cut-over from the owner's cloud account (an AWS automation document) at the cost of more infrastructure and permissions?
5. **SSH host keys.** Keep them across a replace by holding them in the store, so `known_hosts` everywhere stays valid, or keep
   forgetting the old key as today?
6. **Live across a minor version** when a release declares it can, or never?
7. **The warning.** Five minutes by default? May a postpone block an upgrade, and for how long, when the upgrade is a security
   fix?
8. **The standby's cost** counts against the fleet cap and budget (as decided here), or is an upgrade exempt?
9. **The host bundle** changes ADR 0011's statement that the root helper is written by first boot: agree to it as the last phase?

**Why.** Real upgrades took a box away for minutes and each found its defects only after the old disk was gone. Most releases
change only the programs, which can be swapped behind health checks with every process kept; the rest can be rehearsed on the
side and cut over in one short, announced, reversible step. Computing the kind from the signed manifests keeps the choice out of
anyone's memory and out of the box's word.

**Cost.** A second machine for the length of a replace, and a stopped one (AWS) or a disk snapshot (Hetzner) for the rollback
window, shown in every plan. A first boot in two stages, slots in both modules, and a run shim to maintain. A replace still ends
every process and needs the upgrading computer for two API calls. Until the host bundle lands, and the generation is shown to repeat, most upgrades are replaces.

**Consequences and what is not covered.**
- Processes do not survive a replace; files, conversations saved by engines, checkpoints and sign-ins do.
- Hetzner's rehearsal does not see the real `/work` before the cut-over.
- A live update does not touch packages, the kernel or the units; ADR 0035's patching stays the path for security packages, and
  a patch that needs a restart still waits for an idle window or a replace.
- The dashboard on a box cannot replace its own box.
- Phases 1 and 2 are built (Preview: CI only, no image built from them and nothing run on a real box). Phases 3 to 12 are
  Planned. No upgrade is carried out any way but the replace, and none can be offered as live until the rules in section 1
  hold. A run outlives a daemon restart only when the box user's manager can hold it (Amendment 1); that has not been seen on
  a box.

## Amendment 1 (2026-11-12): how phase 2 was built

Section 4, items 1 to 3 and 5, as built, and where it differs from the text above:

- **The program's argv, working directory, environment and first input all travel over the socket**, in one `start` request,
  not only the environment. An argument is not secret by rule but may carry something (a path, a flag value), and `systemctl
  show` prints a unit's command line; the unit therefore carries only `run-shim <id> <record sha256> <runs dir>`. The program
  is started by the shim from the argv array with `Command`, so there is no `sh -c 'read; exec "$@"'` gate any more: the shim is
  already inside the unit's limits when the program is born.
- **The shim takes the runs folder as its third argument** (the text names two); it is the same folder the daemon's record path
  is under, and the unit's command line is part of what the daemon verifies.
- **The daemon keeps no connection.** Every request (`status`, more input, close input) opens the shim's socket
  (`<runs dir>/<id>/io.sock`, mode 0600 in a folder of 0700), sends one frame and reads one frame. A restarted daemon therefore
  has nothing to recover but the path. A run whose shim does not answer within half a second (frozen) is treated as going.
- **The record's hash check** is of two kinds. The record's SHA-256 is part of the unit's command line, so a record edited
  after its run started, copied from another run, or paired with a unit that is not `ozboxd run-shim` for that very id and
  folder, is refused (and the shim itself refuses a record that is not the one its unit was started for). The capability's
  SHA-256 is in the record for a controlled run, so ADR 0037's check survives a restart. Beyond the hash, a record is
  refused when its folder or file is a link, is not plain, belongs to another user than the runs folder, can be written by
  others, is over 64 KiB, has a version this daemon cannot read (it reads the version it writes and the one after it, ignoring fields it does not know there) or, at its own version, an unknown field, names another run or a unit that is not
  `ozbox-run-<id>.service`, or has values out of range. A unit named `ozbox-run-*` with no record is reported too. A refused
  run is never adopted and never touched. **What this does not do:** the record and the unit are both the box user's, so the
  box user can still stop a run (`systemctl --user`) or edit a record together with a new unit. The checks stop a stale, copied
  or half-written record from being trusted; they are not a boundary against the box user.
- **A run that ended while no daemon was looking** is taken over into the history, with its output and its status; one whose
  shim vanished without a status after its unit had started (the machine was stopped) is shown as ended with 137. A run whose
  unit was never started (the daemon stopped between writing its record and starting it) has no `started` marker and is shown
  as cancelled, never as killed.
- **Queued runs are not kept** across a daemon restart (the queue was always in memory); only runs that were going are.
- **Freeze and thaw** are `RunManager::pause(PauseKind::Freeze)` and `resume()`: `systemctl --user freeze` / `thaw` on each
  run's unit, new runs wait in the queue while paused, a run's wall-clock limit does not run while it is frozen (it moves later by
  the time frozen), and a thaw that fails keeps the pause and names the run. **`PauseKind::Replace`** is the other meaning of
  pause: nothing is frozen, new runs wait, and the runs going are listed for the engine's checkpoint (build plan item 9). Neither
  is on the daemon's API yet; the helper's live update (item 4) will call them.
- **`runs.backend`** (`auto`, `unit`, `scope`) chooses the way. `auto`, the default, uses units when the box user's manager is
  running and delegates `memory` and `cpu`, and otherwise falls back to the old cgroup scopes with an incident that says why, so
  a box made from an older image keeps working. `RuntimeMaxSec` is also set on the unit, as a second line behind the daemon's own
  deadline, which is the one that counts frozen time; so the unit's is set a day past the run's limit, and a freeze shorter
  than that never ends a run as a kill.
- **The delegation self-test** (`user_manager_delegation`) reads the cgroup the units land in (`app.slice`, or the manager's
  own until it exists), so it reports what the kernel will hand to units, not what a drop-in asked for; it fails naming the
  missing controller and the fix (without advising a restart of the manager unless it says what that stops), and is `unknown`
  when it cannot read.

**Amendment 1, review round (2026-11-13).**

- **One memory plan per run, for both ways (Z1).** The cap, the throttle, the bounded swap, the group kill and the raised OOM
  score (ADR 0045) are worked out once, by `ozbox_core::memory_plan::run_limits`, before the way is chosen, and handed to
  whichever spawner starts the run. The cgroup way writes them as files; the unit way passes them as `MemoryMax=`,
  `MemoryHigh=`, `MemorySwapMax=`, `OOMPolicy=kill` (which turns on `memory.oom.group`) and `OOMScoreAdjust=`. Tests run the same
  request through both and compare the numbers, and fail if any of the four is missing from a unit's start. Not yet seen on a
  box: that systemd really sets `memory.oom.group` for `OOMPolicy=kill`, and that a unit of the user manager may take
  `OOMScoreAdjust=500`.
- **One owner for the controller delegation.** The `user@.service` drop-in that delegates `memory` and `cpu` is the memory
  guard's `10-ozbox-memory.conf`, written by `ozbox host-guard memory install` at first boot (before the manager starts) and at
  every upgrade. The image and the first-boot user-manager step no longer write a second one.
- **The way is chosen for every run (Z9).** `auto` looks at the box user's manager when each run starts, so a daemon that
  started before the manager uses units as soon as it is ready; a change of way is reported once. The daemon is ordered after
  (and wants) `user@1500.service`, and waits up to `runs.manager_wait_s` (20) at start. Runs a previous daemon left going are
  always taken over, whichever way new runs go, and a daemon that could not reach the manager looks again every five seconds
  (24 times). The self-test reports the way in use (`run_backend`): scopes are `unknown`, never a pass, naming that a restart
  of the daemon would end every run. **What this does not do:** a run started as a scope stays a scope; it is not moved.
- **Files are written whole (Z12).** The record and the exit status go to a temporary file, are flushed, renamed into place, and
  the folder is flushed.
- **Who may talk to a shim (Z13).** A shim answers only a process in the daemon's own service cgroup (named in the record, read
  from `/proc/<pid>/cgroup` of the peer the kernel reports), and the daemon sends nothing to a socket whose process is not the
  unit's main process, nor later input to one that is not the shim it first talked to. Processes outside the daemon's service (SSH
  sessions, the box user's own units) cannot reach a run's socket; dashboard terminals and runs in cgroup scopes still can,
  because they sit under that service. This is defence in depth, not a boundary between processes of the box user. Where the kernel cannot report the peer (not Linux) the shim refuses when it has a cgroup to enforce. This is defence
  in depth: the box user can still read a run's `/proc/<pid>/environ`, as before, and a connection to the shim gives an agent
  nothing it did not have (a start is bound to the record's hash and the unit's main process).
- **Round 3 (Z21 to Z24).** The daemon sends nothing to a run's socket until the manager names the unit's main process (an
  unknown or absent one is tried again, never allowed), and a run taken over while frozen has its first answer checked the
  same way. `runs.backend = "unit"` refuses a run, with the probe's reason, when the manager does not hand out `memory`
  and `cpu`; a unit run on a box without a group kill is given `OOMPolicy=continue`, so one OOM kill does not stop the whole
  run. A run's marker says `starting` before the manager is handed the unit (a start fails if that cannot be written) and
  `started` once the shim has answered. The start-up wait is only for a manager that is not running yet.
- **A run keeps part of the daemon's sandbox (Z18).** A unit of the box user's manager inherits none of `ozboxd.service`'s
  hardening, so each run is started with `NoNewPrivileges=yes`, `RestrictSUIDSGID=yes` and `LockPersonality=yes`. The rest
  (`PrivateDevices=yes`, `ProtectSystem=strict`, `ProtectHome=read-only`, with the work folder and `/tmp` writable) needs a mount
  namespace, which a user manager can only make with a user namespace; it is `runs.sandbox = "strict"`, off until a real box
  shows it works. **Until then a run in a unit has the box user's file system view and devices, as a terminal of that user
  does, and the cgroup way keeps the daemon's.**
- **Record versions (Z10, in part).** A daemon reads the record version it writes and the next one, ignoring unknown fields in
  the newer one, so a rollback of one patch does not lose a run from its list.

**Before phase 4 relies on phase 2 (not done):** the real narrowing of Z19 (admit only the system manager's `MainPID` for
`ozboxd.service`, or a separate uid once phase 3 moves terminals out of the daemon's service); frozen time across a restart
(Z25: keep the total in a status file beside the record and add it on adoption); Z10's other half (count a refused unit's `memory.current` in admission, reap a
refused folder whose unit is gone after the history window); Z15's systemd container job that restarts the real daemon with a
run going, and a test that sees a real freeze and a shim that stops answering; check on the image that `runs.sandbox =
"strict"` works and then make it the default; a decision for a run that is a scope when a live update begins (it ends with
the daemon, so the update must say so); Z11 on a real box (that a stop thaws a frozen unit, and that `RuntimeMaxSec` counts
frozen time).

**Still to prove on a real box (not covered by CI):** that `user@.service` delegates `memory` and `cpu` with that drop-in on
the image's systemd; that a run's limits hold (`MemoryMax` kills, `CPUWeight` shares); that `systemctl --user freeze` works on
the image's kernel; a daemon restart with a run going (and a `kill -9` of the daemon); the environment a program sees (it now
inherits the box user's manager's, not the daemon's); the start of a run (`systemd-run` plus the handshake, median of 40 on the
4/8/40 shape: this moves a per-run cost and has not been measured); the memory guard's proof on the unit path (cap, swap bound,
`memory.oom.group`, `oom_score_adj`); and which way `auto` picks on a fresh boot and on a box from an older image.
