# 0033 — A box's state can live in the encrypted bucket, and `ozbox adopt` covers Hetzner

**Decision.**

1. **A second backend, chosen by configuration.** ADR 0027 kept each box's OpenTofu state in a local directory. The encrypted,
   versioned, private bucket that `ozbox init` already makes for the network can hold it instead: set `state_backend = "s3"` in
   the provider's section (`state_bucket` is already there; `state_region` for a provider with no region of its own; optionally
   `state_kms_key_id`). One object per box, `ozbox/boxes/<module>/<box>/terraform.tfstate`, one OpenTofu workspace per box as
   before. Absent or `local` changes nothing.
2. **Native S3 locking, not DynamoDB.** The lock is OpenTofu's lock file in the bucket (`use_lockfile`, OpenTofu 1.10 or newer),
   which is what the network module already uses. There is no table to create, own, pay for or grant, and bucket versioning
   (already required) is the history. The cost is the version floor: an older OpenTofu is refused with a sentence, not an
   unknown-argument error. The state bucket is AWS S3; a Hetzner fleet may use it too if it has AWS credentials, and an
   S3-compatible store from another provider is not supported yet.
3. **The module is not rewritten; a copy of it is run.** A backend type cannot be chosen from the command line, and both box
   modules declare `backend "local" {}`. With the bucket selected, OpenTofu runs in a generated copy of the module under the
   state directory: its `.tf` files with that one line made `backend "s3" {}`, and the `cloud-init` folder the module reads,
   placed at the depth it expects. Every resource address stays what it is with the local backend, so adoption, the replace
   guards and the plan checks are unchanged. The real module folder is never written to, and the copy has its own OpenTofu data
   directory. (The alternative, a generated root that wraps the module, renames every address to `module.box.*`, which breaks
   the plan guards and makes a move need `state mv`.)
4. **Moving is copy, verify, plan, keep.** `ozbox state migrate <box>|--all` (plan, then apply, like every change) copies the
   local state to the bucket, reads it back and compares lineage, serial and resources, then plans against the bucket, which
   must show no change at all. The local files stay with a note beside them. A bucket that already holds a *different* state
   for the box is never overwritten. `--switch` writes `state_backend = "s3"` into the configuration, and only when no other
   box is left with state on this computer alone. `ozbox state status` shows what is where. With the bucket selected, a box that
   has only local state is told to run `migrate`, not "no state".
5. **Backups work for either backend.** Before and after state surgery a copy is taken: copied from the local file, or pulled
   from the bucket.
6. **A stale module-local `.terraform/` is moved aside.** An install from before ADR 0027 leaves provider cache and an
   `environment` file in the module folder, which made a non-interactive `init` stop asking about state migration. The folder is
   renamed (never deleted) with a note, and OpenTofu starts from its own data directory.
7. **`ozbox adopt` on Hetzner.** Same contract as AWS, sharing one implementation (`ozbox_core::adopt`): read-only calls find
   the box's server, `/work` volume and firewall by their `ozbox-*` labels and check they belong together; they are imported in
   dependency order; known import artefacts are corrected; the result stands only if the plan changes nothing or labels only;
   otherwise the import is taken back out. The private network is an attachment on the server, so it is read from the server and
   passed as `network_id`, not imported. The Hetzner server module now ignores changes to `user_data`, which Hetzner cannot return
   and only reads at creation: without that an adopted server would plan a replacement. Adoption works with either backend.

**Why.** A laptop is a poor place for the only record of which machines a fleet owns, and a second laptop or a teammate cannot
use it. The bucket is already there, encrypted, versioned and private. The move had to be safe to try and impossible to half-do:
hence copy-verify-plan and the kept local copy.

**Cost.** Two copies exist during and after a move (the local one is dead weight until deleted). The bucket's own permissions
are now what protects every box's state: it holds resource ids and tags, never a secret. Hetzner import behaviour is covered by
tests with the API and OpenTofu simulated; the import id of the attachment and the attributes the importer leaves unset are
checked by the plan guard on a real adoption, which refuses with the attribute names if one is missed.

## Amendment 1 (security review, 2026-11-10): switching checks that every bucket copy is current

A security review (2026-11-10) found that `--switch` treated a box as moved whenever it had a workspace in the bucket, whatever
that held. A box copied on day one and changed with the local backend on day two would then plan from its day-one state (old
instance and volume ids) once the switch was made. Now, at switch time, every box with state on this computer is compared with
its copy in the bucket by lineage, serial and content: the switch is refused, naming each box and why, if a copy is missing,
belongs to another lineage, has the same serial with other content, or is older than the local one. A copy that is the same
lineage and further on (written through the bucket since, by design) is accepted. `ozbox state migrate <box>` brings an older
copy of the same lineage up to date (the push is checked the same way); a newer or different one is still never overwritten.
