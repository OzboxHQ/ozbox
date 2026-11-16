# 0053 — `ozbox init` adopts what already exists: only what Oz Box made, never replaced, and a lookup that cannot answer stops the step

**Status.** Decided. **Preview**: built and tested in CI only, with a fake command runner. It has not run against a real AWS
account.

**Decision.** Each OpenTofu step of `ozbox init` keeps its state in the encrypted state bucket, and on a fresh bucket that state
is empty. On an account set up by an earlier version, or by hand, the resources a step would make may already exist. Without
help the plan looks clean and the apply then makes a second copy (a second network and its hourly NAT gateway), makes a key and
fails because the alias is taken (leaving an orphan key), or fails "already exists". So a step now looks in the account for what
it would make, and **adopts** it.

1. **Look first, read only.** After the backend is initialised, `tofu state list` says what the step already holds. For each
   resource the module would create that the state does not hold, init reads the account by the names Oz Box itself uses: the KMS
   alias `alias/ozbox-<fleet>-secrets` and its key (`kms list-aliases`, `kms list-resource-tags`), the document
   `ozbox-adopt-<fleet>` (`ssm describe-document`), and the policies `arn:aws:iam::<account>:policy/ozbox-box-*`
   (`iam get-policy`). A resource already in the state is never looked up.
2. **Imports are written into the root.** What is found is written as OpenTofu `import` blocks in `adopt.tf` beside the step's
   generated `main.tf` (rewritten or removed on every run, so a stale file never imports something no longer wanted). Blocks, not
   `tofu import`, because they appear in the plan: the person sees **Adopt existing <thing> <id> as <address>**, then the plan's
   real remaining difference.
3. **Only what Oz Box made.** The resource must carry `ozbox-managed=true`. A look-alike without it, or a key whose tags the
   setup identity may not read (its rights read only tagged keys), is **refused** with the reason and a fix. Nothing is changed.
4. **Never a silent replacement.** A difference that can be made in place (a key policy, a document's content) is shown as a
   change. A plan that would **replace or destroy** an adopted resource is refused at plan time, so no apply command exists.
5. **A lookup that cannot answer stops the step.** Only the service's own not-found answer means "absent". A denied, failed or
   unreadable answer is never taken as absent, because that would plan a create that then fails or duplicates.
6. **The config and the account must agree.** If the config records a fleet key and the alias points at another, nothing is
   adopted. If the alias is gone but the recorded key still exists and is tagged, the key alone is adopted.
7. **A general mechanism.** Each step passes a list of adoptable resources (address in the module, how to find it, what to call
   it). The key, the adopt document and the box policies use it now. The network (found by the `ozbox-managed` tag and the
   configured subnet) and the issuer (its roles live in the reserved namespace and need an administrator) can be added to the list
   later; they are not adopted yet.

**Why.** Reality, not a progress file, is what init reads (the module's own rule), and the state bucket is new to every account
that predates it. Adoption keeps a re-run safe and cheap without asking anyone to import by hand.

**What it costs.** Up to a handful of read calls per step, each already in `OzBoxSetup` (a test lists every lookup and checks
the permission sets allow it). An adopted resource whose settings differ is changed in place on apply, which is what the module
says it should be, and the plan shows it first.

## Amendment 1 (2026-11-16): the first ownership tag on an existing disk is an administrator's, never the program's

**What happened.** `ozbox adopt-fleet-key` on a box made by `0.1.x` planned to tag the box's system disk (the module tags every
resource it makes), the system disk had never been tagged, and the apply failed part way: `UnauthorizedOperation: ec2:CreateTags`.
The grant and the "moving" mark were already applied, so the box was left half moved until an administrator tagged the disk by
hand. The operator role may tag a resource only when it is created (`TagOnCreateOnly`) or when it already carries
`ozbox-managed=true` (`ChangeOnlyTaggedResources`), and a disk made before the module tagged it carries nothing.

**Decision.**

1. **The ownership tag is conferred on an existing resource only by an account administrator.** No statement is added to the
   operator policy or to `OzBoxSetup` that lets either put `ozbox-managed` on a volume that exists. IAM cannot say "a disk attached
   to one of our machines" (a condition can read the volume's own tags and the request's, not what it is attached to), so such a
   statement would let the identity mark any volume in the account as Oz Box's and then change, detach or delete it. That undoes
   this ADR's rule 3 (only what Oz Box made). Rejected: a `CreateTags` statement for `volume/*` limited by `aws:RequestTag` and
   `aws:TagKeys`; and an `ozbox init` step that tags the disks of tagged machines (it needs the same statement on the setup identity).
   `nothing_but_an_administrator_can_give_an_existing_volume_its_first_tag` pins both policies.
2. **The change stops needing it.** The module still tags the system disk when it creates it (new boxes, and every upgrade, which
   makes a new disk), and now ignores the tags of an existing system disk (`ignore_changes`), so a plan for an old box never asks for
   the call. Nothing reads a volume's tags.
3. **A plan that would still ask for it is refused before anything is applied.** Every plan of an existing box passes one gate
   (`check_disk_tags_applicable`, in the shared plan step): an update that gives a disk with no `ozbox-managed=true` tag new tags is
   refused, naming the disk and the two commands an administrator runs once (check the disk is the box's machine's, then
   `aws ec2 create-tags`). It applies to every step of a move (begin, finish, cancel), so a box an older program half moved is
   stopped on the way out too. Values copied into the printed commands are plain identifiers or a placeholder.

**What it costs.** A custom or older module that tags an existing disk needs one administrator command per such box. The
refusal says which and why.

