# Keeping boxes healthy

Boxes are meant to live for months. The system disk is disposable and replaceable; `/work` is the part that matters,
and every operation below protects it.

See [how to read the status](README.md#how-to-read-the-status).

---

## 1. Upgrade a box to a new image

**You want:** the latest system packages, tools and box daemon, keeping all your work.

```
ozbox upgrade main --dry-run     # replaces only the machine and its /work attachment, checked by OpenTofu
ozbox upgrade main
```

**Underneath:** the image's release signature is checked first (an unverified image is refused unless you pass
`--allow-unverified-image`); work in progress is checkpointed; the machine is rebuilt (on Hetzner, replaced) from the new image; `/work` is
reattached untouched; the self-test runs; your SSH entry follows the new machine.

The plan also says what happens to the box's **secrets store**. Its copy on `/work` comes back; whether the new machine can
open it depends on where the store's key is. A key in a cloud key service (AWS: set `secrets_key_arn` and `fleet` under
`[aws]`, and make the box with them, or move an existing box with `ozbox adopt-fleet-key main`: see 1b) or a TPM is kept, and so is a key escrowed in the box's own vault (box secrets on OpenBao
with a token). A key kept only in a file on the system disk is lost with that disk: the upgrade is then refused and the plan
lists what you would have to enter again. Escrow the key first, or run it again with `--accept-new-secrets-store`; the old
store is then set aside (never deleted) with the key this computer pinned when it made the box, and the backup credentials
and the web IDE's tunnel token are put back from this computer. A box that is not running cannot be asked, so start it first
(`ozbox resume main`) or accept a new store.

**On AWS, an upgrade that may lose the store's key keeps a copy of the old system disk first.** When the key is a file on the
system disk, or ozbox cannot tell where it is (a box made on `0.1.x` cannot say, and what a box says about itself is not
believed), the plan has one more first step: an encrypted snapshot of the old system disk, tagged `ozbox-managed=true`,
`ozbox-box=<box>` and `ozbox-purpose=pre-upgrade-root`, taken before anything is stopped. Before you confirm, the plan prints a
block of its own (not a note) that says what would be lost, that the copy is kept, and the commands to run afterwards:
`ozbox secrets import … --box main` for each key, then `ozbox adopt-fleet-key main`. The snapshot's id is in the report when the
upgrade finishes, and `ozbox backup list main` shows it any time (marked as the root disk, never as a `/work` backup, and never
what `ozbox clone` or a restore picks). It holds the old store's key file, so keep it only while you need it: it is billed like any EBS
snapshot, and nothing deletes it for you while the box exists. Once your keys are entered again and `ozbox adopt-fleet-key main` has moved the store to the fleet's key,
delete it with `ozbox backup delete main <snapshot id>`. To reopen the old store from it, see 1c. Each upgrade you run takes its own copy: one that is retried after a failure, or run again, takes another, so `ozbox backup list main` may show several (the report names the one this upgrade took). `ozbox upgrade` takes the copy first, before it asks the box to end its runs and save its work (the hold it puts on new runs lasts only ten minutes from then), and waits up to thirty minutes for it (`snapshot_wait_minutes` under `[aws]` changes that). The dashboard takes it as part of the upgrade, after that preparation, so it waits five minutes only. A copy not complete in time stops the upgrade before anything is stopped, names the snapshot and says it will finish by itself and can be used; run the upgrade again when it has (the dashboard's upgrade, if it timed out, is best run with the command). **Destroying the box deletes its copies** (the plan lists them, and they are the one thing ozbox could not list afterwards): add `--keep-old-system-disks` to `ozbox destroy` to keep them, and then delete them yourself in the AWS console or with `aws ec2 delete-snapshot`, since ozbox can no longer list them once the box is gone. `--no-pre-upgrade-snapshot` turns
the copy off: the key is then destroyed with the old disk and the old store can never be opened again. A refused plan (the disk is not
encrypted, or this program's AWS permissions cannot snapshot it) says so and names that flag. No copy is taken when the store is kept
(KMS, escrow, this computer's keychain), is already lost, or is known to be empty (`--use-fleet-key`). On Hetzner no copy is kept, and
the plan says so.

On AWS, a box made without a pinned approver gets this computer's key in its new machine's first-boot configuration. After
the upgrade, laptop keys the box trusts with no record of how they were enrolled are listed, with the command that revokes
one.

**On Hetzner** an upgrade replaces the server through OpenTofu (`-replace`), as on AWS, instead of rebuilding its disk: the new
server is made from the current first-boot configuration, so this release's root helper, setup scripts, units and pinned
approver arrive with it (a rebuild would keep the ones the box was made with). `/work` is a separate volume and is kept. The
plan is checked read-only first and refused unless it replaces only the server and its attachment. Two things change: **the
server gets a new address** (nothing connects in, so only an allow-list on the other side of an outbound connection would
notice), and a vault token placed by hand on the old system disk is gone and is placed again (`ozbox admin <box> --
place-bao-token`). The old server is removed before the new one is created: if Hetzner cannot create it right then (a type
out of stock in the location, a limit), the create is retried a few times, and if it still fails `/work` is safe, the box shows
as `instance missing`, and running the same `ozbox upgrade` again finishes the job.
**Status:** Works on AWS (two real upgrades). The Hetzner replacement is Preview (tested in CI against a simulated Hetzner API
and a simulated OpenTofu, never run against Hetzner). The secrets-store check and recovery are Preview (tested in CI, not yet
on a real box).

## 1b. Move an existing AWS box's secrets store to your fleet's KMS key

**You want:** a box that was made before your fleet's KMS key existed (its secrets store's key is a file on the system disk,
so every upgrade would lose the store) to keep its store through upgrades, without entering anything again.

**Do:** with `secrets_key_arn` and `fleet` set under `[aws]` (from the `aws-secrets-key` module):

```bash
ozbox adopt-fleet-key main --dry-run    # what changes, nothing is changed
ozbox adopt-fleet-key main
```

**What happens:** `main`'s role is allowed to use your key, only for `main`'s own secrets, and the box is marked as moving.
`main` then re-wraps a copy of its store's keys under KMS itself while its secrets service keeps running (each key is given
back through KMS before anything is replaced), then stops the service, swaps the copy in and starts it again. The service is
down for that swap and its start-up: a few seconds, plus a little for every secret it unlocks when it starts (a store with 100
secrets can take a minute or two to be ready; `ozbox env run` and the dashboard's secret reads wait or retry meanwhile). The box
keeps its key file until you commit: this command reads `main`'s state **as root through AWS Systems Manager**, with a document
of your fleet's own that runs only fixed `ozbox` programs (the `aws-adopt-command` module makes it, a step of `ozbox init`; attach the policy it outputs as
`operator_adopt_policy_json` to whoever runs this command, and to nobody else; the box user's SSH answer is never trusted for this),
and only when the service, the store and the copy on `/work` are all on KMS does it write the label that makes `ozbox upgrade`
keep the store. Then `main` destroys its key file and the copy beside the store, and the command waits for `main` to say so.
What the store holds is kept.

**A box made by `0.1.x`** has a system disk that was never tagged. The move does not touch the disk's tags, and `ozbox` never
changes anything that its AWS permissions would refuse part way. If a plan ever needed to tag a disk that carries no `ozbox-managed`
tag (a module of your own, say), the command stops before it changes anything and prints what to run once, with your own
administrator sign-in, not the one `ozbox` uses: check the disk is the box's (`aws ec2 describe-volumes --volume-ids <volume>
--query 'Volumes[].Attachments[].InstanceId'`), then `aws ec2 create-tags --resources <volume> --tags Key=ozbox-managed,Value=true
Key=ozbox-box,Value=<box>`. Then run the same command again. Neither `ozbox` identity is allowed to do that itself, because it could
then mark any disk in the account as its own.

- While the move is not finished, `ozbox upgrade` refuses the box (and `--accept-new-secrets-store` does not change that): a
  new machine on the new key over a store the old key still seals would never open it. Run the command again to finish, or
  `ozbox adopt-fleet-key main --cancel`. A cancel is carried out on the box first, under the box's lock: the box records it (no
  move starts or finishes past it) and, if it had already moved, takes the store back under its file key from the store as it
  is now. The grant and the mark are taken away only after the box says it is back on its file key.
- Before it stops anything, the box checks that KMS can be used for its own secrets (the grant has reached it and the key
  matches); if not, it leaves the service alone and tries again at its next 15-minute look. If a move is cut short (a reboot),
  the box puts its store and settings back in agreement on its own at its next look.
- Before it changes anything it asks the box's root that its metadata guard is loaded (the instance role's credentials are
  otherwise reachable by the box user, and the role is about to be able to open the store's copy on `/work`) and refuses if not.
- If two of you act at once, or a command is delayed, a moved store whose tag and grant were both taken away is **reported,
  never put back by the box on its own**. `ozbox adopt-fleet-key main --cancel` then offers the copy made before the move, only
  when the cloud's own tag list shows no label on `main` and `main`'s root says the key service itself refuses it (a slow or
  blocked network is not a revoked grant), and it loses the secrets saved since the move: you are asked, then you type the box's
  name (`--yes` is not that). The same offer is made when a cancel cannot re-wrap the store. The box's firewall list always lets
  it reach the key service, whatever its user asks for. A store that keeps changing while it is re-wrapped waits longer before each
  new try, and the command says so.
- `ozbox upgrade` on an AWS box reads the store's key from the box's root the same way. When it cannot (the module's document is
  not applied, the policy is missing, the secrets service is not ready right now, or the box's program is older than the check),
  it says the store is unknown, says which, and asks for `--accept-new-secrets-store`, never "kept". A store kept by escrow on a
  box that answers needs no flag.
- The same holds for a box whose record names the fleet's KMS key. The record only says which key the new machine will be given,
  so the plan asks the box's root whether the store really opens under it, and says one of four things: **kept** (the service is
  ready on that key and the store and its copy on `/work` are sealed by it), **will be lost** (the store is still sealed by a key
  kept in a file: finish the move with `ozbox adopt-fleet-key`, or accept a new store), **already unopenable** (its file key is gone,
  so its secrets service cannot start; `--accept-new-secrets-store` upgrades and then sets the old store aside and starts a new one,
  or run `ozbox admin <name> -- recover-secrets` first; never said when this computer's keychain or the box's vault holds a copy of the key: then the plan says the store is not lost, and that `--accept-new-secrets-store` sets it aside (never deleted) and starts a new one, with the old store reopenable later: see 1c) or **unknown** (the box could not be asked, so it is never called kept; the
  upgrade asks for `--accept-new-secrets-store`). A box that is stopped is unknown too: start it and plan again.
- It reads the box first and changes nothing if the box keeps its key anywhere but a file, cannot be asked, or cannot move
  its own store. A box made on `0.1.1` or earlier cannot: upgrade it first, **to an image built from a release that includes
  this command** (an image from an older release gains nothing). If the plan says the store would be lost,
  `--accept-new-secrets-store` starts a new one and the plan lists what to enter again; this is the one time such a box loses
  its store. Then run this, which keeps whatever the new store holds. The upgrade's plan reminds you.
- A grant on the role can take a few minutes to reach the box. If the box does not say it is done in about three minutes the
  command stops and says so; run it again shortly, it carries on from where it stopped.
- A key you escrowed in a vault before the move is not removed from it, and still opens any copy of the store made before the
  move (a backup, a snapshot of `/work`) until you remove it.

**Status:** Preview (tested in CI against a simulated account and box; not yet on a real one).

## 1a. A box whose secrets store can no longer be opened

**A box with secrets of its own** (kept in AWS Parameter Store) loads them with the box's role too: no `aws` command is needed on
the box. If it could not (the role may not read its path, or Parameter Store is not reachable), the box's self-test fails
`box_secrets_loaded`, and `ozbox admin <box> -- collect-logs` shows the loader's reason (never a value). The box tries again every
fifteen minutes. A box whose secrets are in OpenBao still needs the `bao` program on it.

**A box set up for the fleet's KMS key** keeps its store's key in KMS and reaches it with the box's own role: no `aws` command is
needed on the box. If the role cannot use the key, the secrets service stays down and the box's self-test fails `secrets_key_usable`
(once the key has been failing for three minutes; sooner than that the self-test says it could not verify), naming the KMS key and what to check (the role's access to the key, the key service being reachable, the key named in
`/etc/ozbox/secrets.env`). That is not a lost store: nothing is set aside, and it starts again by itself once the key works.

**You want:** to start a new secrets store on a box whose store's key was lost with its system disk (no escrow).

```
ozbox admin main -- recover-secrets
```

**Underneath:** the box sets the old store aside (renamed, never deleted) only when its secrets service itself recorded
that the store can never be opened, and only with a signature of a one-time challenge by the key pinned when the box was
made, which this computer holds. Run it from that computer. A box with no pinned key can be recovered only at the machine's
own console, as root. Anything kept only on the box (tunnel tokens, backup credentials, imported keys, laptop keys enrolled
later) must be entered again.

Two recorded states qualify. The first is a key lost with no escrow. The second is a store sealed by a key kept in a file,
found by a box configured for the fleet's KMS key (as after `ozbox upgrade --use-fleet-key`), with that file key gone and no
copy held: the service records it as a state of its own, never as a restart, and `recover-secrets` accepts it. A store that
can be opened (its key file is there, or the kinds match) and a service that is only restarting are refused, and the refusal
names the state the box was in. A box whose program is older than 0.2.0-beta.2 still loops on this state and says nothing
the recovery can act on: `ozbox` tells you to upgrade it to an image from 0.2.0-beta.2 or later with
`--accept-new-secrets-store`.

An upgrade with `--use-fleet-key` and `--accept-new-secrets-store` does this for you: its plan says the old store will be set
aside (renamed, never deleted) and a new one started on the fleet's KMS key, and after the machine is replaced it does exactly
that, with the approval of this computer's pinned key.
**Status:** Preview.

## 1c. Recovering an old secrets store from the copy an upgrade kept

**You want:** the keys an old store held, after an upgrade that started a new store (`--accept-new-secrets-store`) on an AWS box.
You have the id of the snapshot the upgrade reported (`ozbox backup list main`: the row marked as the root disk; it is the one tagged `ozbox-purpose=pre-upgrade-root`). Nothing here is
automatic: reading the old key needs root on the box, which the box user does not have by design (ADR 0011), and putting the old
store back **displaces the new one**, so keys entered since the upgrade are not in it. The steps keep both.

**Underneath:** the old store's ciphertext was never lost (it came back on `/work`; the upgrade renamed it to
`secrets.json.lost-<time>`, both in `/var/lib/ozbox-secrets` and in `/work/ozbox-secrets-private`). Only its key, the file
`kek.key` beside the store, was on the system disk that was replaced. The snapshot has that file. The steps:

1. From your computer, make a volume from the snapshot in the box's availability zone, tagged so your operator role may use it, and attach it
   to the box as a second disk (never boot from it):
   ```
   aws ec2 create-volume --snapshot-id snap-OLD --availability-zone AZ \
     --tag-specifications 'ResourceType=volume,Tags=[{Key=ozbox-managed,Value=true},{Key=ozbox-purpose,Value=recover-old-store}]'
   aws ec2 wait volume-available --volume-ids vol-NEW
   aws ec2 attach-volume --volume-id vol-NEW --instance-id i-BOX --device /dev/sdg
   ```
   `AZ` is the box's (`aws ec2 describe-instances --instance-ids i-BOX`, `Placement`).
   The snapshot is encrypted under the key the system disk had, so your AWS sign-in needs that key's permission to make a volume from it:
   `kms:DescribeKey`, `kms:Decrypt`, `kms:GenerateDataKeyWithoutPlaintext`, `kms:ReEncrypt*` and `kms:CreateGrant` on the key (the `kms_key_arn` under
   `[aws]`, if you set one; the account's default EBS key otherwise, which needs no grant). Without them the volume is not created and nothing else is
   changed. Attach it at `/dev/sdg`, never `/dev/sdf`: ozbox finds a box's `/work` disk at `/dev/sdf` and ignores a disk attached anywhere else,
   but even so run no `ozbox` command that changes the box while the recovered disk is attached, and remove it as step 5 says.
2. Open a root shell on the box (the machine's console; a Session Manager session if your image gives one root: `ozbox admin` has no
   action for this, on purpose). Find the disk with `lsblk` and mount its root partition read-only: `mkdir /mnt/old && mount -o ro,nodev,nosuid,noexec
   /dev/nvme2n1p1 /mnt/old` (use `nouuid` as well on an XFS image).
3. Stop the secrets service and set the NEW store aside, keeping it:
   ```
   systemctl stop ozbox-secrets.service
   t=$(date +%s)
   cd /var/lib/ozbox-secrets && mv secrets.json secrets.json.new-$t && mv kek.key kek.key.new-$t
   mv /work/ozbox-secrets-private/secrets.json /work/ozbox-secrets-private/secrets.json.new-$t
   ```
4. Put the OLD store and its key where the service reads them, owned by the secrets user. The old store is the newest
   `secrets.json.lost-*` on `/work`:
   ```
   cp /work/ozbox-secrets-private/secrets.json.lost-TIME /var/lib/ozbox-secrets/secrets.json
   cp /mnt/old/var/lib/ozbox-secrets/kek.key /var/lib/ozbox-secrets/kek.key
   chown ozbox-secrets:ozbox-secrets /var/lib/ozbox-secrets/secrets.json /var/lib/ozbox-secrets/kek.key
   chmod 600 /var/lib/ozbox-secrets/secrets.json /var/lib/ozbox-secrets/kek.key
   # the copy the box keeps on /work follows the store it was made from: put the old store there too, as the new one was
   cp /work/ozbox-secrets-private/secrets.json.lost-TIME /work/ozbox-secrets-private/secrets.json
   chown --reference=/work/ozbox-secrets-private/secrets.json.new-$t /work/ozbox-secrets-private/secrets.json
   chmod --reference=/work/ozbox-secrets-private/secrets.json.new-$t /work/ozbox-secrets-private/secrets.json
   systemctl start ozbox-secrets.service
   ```
   `ozbox secrets status` (as the box user) then lists the old store's names. If the service says the store does not open, the key
   is not that store's: put your files back from the `.new-$t` copies, on `/work` as well.
5. **Before anything reboots the box**, unmount and remove the second disk: `umount /mnt/old`, then
   `aws ec2 detach-volume --volume-id vol-NEW` and `aws ec2 delete-volume --volume-id vol-NEW` from your computer. A copy of the
   old system disk must not stay attached: it holds the key.
6. Move the store to the fleet's KMS key straight away, so no later upgrade can lose it again: `ozbox adopt-fleet-key main`
   (the key file on the box is destroyed by it). When it says it finished, delete the snapshot: `ozbox backup delete main snap-OLD`.
   The new store you set aside in step 3 can be reopened the same way, or its keys entered again.

**If the old key is held in your keychain or the box's vault instead.** That is the case when the upgrade's plan said the key is held. The
upgrade still set the old store aside the same way (renamed, never deleted), and the held key was not touched, so the old store can be
reopened from it. The steps are 3 to 6 with one change: the old key (`kek.key`) comes from the held copy, not from a snapshot's disk,
so there is no volume to attach in steps 1 and 2. ozbox does not show a held key, so it is retrieved by whoever set the keychain or
the vault up. Where no copy of the key is held, the old store cannot be reopened, and the plan says it is already unopenable.

The on-box half (that the old disk's `kek.key` reopens the store the upgrade set aside, and no other key does) is checked by a
test in CI. The AWS half (a volume from the snapshot, attached and mounted) has not been run against a real account.
**Status:** Preview.

## 2. An upgrade that was interrupted

**You want:** to recover if the new machine could not start (no capacity, a quota taken by something else).

`ozbox list` shows the box as **instance missing** — `/work` is kept. Run the same command again:

```
ozbox upgrade main
```

It finishes the job. Capacity and quota errors are retried a few times with a pause before it gives up.
**Status:** Preview.

## 3. Daily backups in your own time zone

**You want:** a snapshot every night, kept for a while.

```
ozbox backup schedule --every daily --at 02:00 --keep-daily 7 --keep-weekly 4 --keep-monthly 6
```

Or **Settings → Backups**, which also shows the estimated monthly cost. On the demo provider the page says its snapshots are simulated: nothing is backed up and no box is asked. The schedule catches up after downtime and never
runs twice at once; pruning never removes a snapshot you took by hand.
**Status:** Preview.

## 4. Back up to your own repository too

**You want:** a copy outside your cloud provider (S3-compatible storage, Backblaze B2, or an SFTP server).

In **Settings → Backups**, add a repository; its password and keys are write-only. Backups to it are encrypted and
deduplicated (restic).

```
ozbox backup now main --to both
```

**Status:** Preview.

## 5. Restore a file or folder you deleted

**You want:** yesterday's version of one folder, without touching the rest of the box.

```
ozbox backup list main
ozbox backup restore main <backup-id>         # into a folder beside your files
```

**Status:** Preview.

## 6. Restore the whole box into a new one

**You want:** a working copy of the box as it was, side by side with the current one.

```
ozbox backup restore main <backup-id> --to-new-box main-restored
```

**Underneath:** one plan: create the box, send the backup credentials, restore over its empty `/work`, run the
self-test. If interrupted, running the same command again carries on.
**Status:** Preview.

## 7. Roll a box's /work back in place

**You want:** to undo a change that broke everything on the box.

```
ozbox backup restore main <backup-id> --in-place
```

High risk: you type the box name, and the current state is snapshotted first. The old disk is kept until you delete it
yourself.
**Status:** Preview.

## 8. Check a box's health

**You want:** to know that a box is really working.

The box's self-test (run after every upgrade, and from the dashboard) checks that `/work` is mounted and writable, there
is disk headroom, the filesystem fills its disk, the tools are present, the tunnels are up and a sample run works. A
failure names the failing step. It also checks that the services enabled for the box user are running. A one-time service
that already ran and finished, or that had nothing to do because its start condition was not met (such as resuming a
session when there is nothing to resume), counts as healthy while it is stopped; a service that should keep running, or one
that failed, does not.

**Status:** Preview (runs on real boxes; one check is being corrected in the next image).

## 9. Fix a box without root

**You want:** to repair ownership, restart services or reinstall the box daemon.

```
ozbox admin main -- reown
ozbox admin main -- reinstall-ozboxd
ozbox admin main -- enable-linger      # boxes made before services could run after logout
ozbox admin main -- collect-logs
```

**Status:** Works (`reown` used on a real box).

## 10. Clean up what nothing uses

**You want:** to stop paying for forgotten snapshots, images and disks.

```
ozbox cost orphans               # Oz Box's own leftovers and look-alike untagged resources, with monthly cost
ozbox cost orphans --delete <id> # only Oz Box's own; typed confirmation
```

**Status:** Preview.
