# infra

Everything that builds an Oz Box machine. Three pieces fit together:

```
 packer/ozbox-image   ──builds──▶  image (AWS AMI or Hetzner snapshot): OS, code-server, KasmVNC, cloudflared, hardening
 tofu/modules/*-box   ──creates──▶ machine from that image + a separate /work volume, with no inbound path
 cloud-init/box.yaml.tftpl ──runs on first boot──▶ mounts /work (never reformats), creates the user, locks sshd to loopback
```

- **Image** (`packer/ozbox-image/`): one HCL2 template, two sources, one `scripts/provision.sh`. Everything heavy is installed here,
  each artefact pinned by version and verified by sha256 (the pins live in `ozbox-image.pkr.hcl`). Image name:
  `ozbox-<version>-<timestamp>`, tagged `ozbox-image` and `ozbox-image-version`. The image carries its box daemon: `ozboxd` is built in
  the same workflow run from the same commit, installed at `/usr/local/bin/ozboxd`, and its SHA-256 is in the signed release manifest
  (key `ozboxd`) and in `/etc/ozbox/image-release`. A machine made from stock Ubuntu installs it from that signed release at first boot.
  The box user has no sudo; the only root path is `ozbox admin` (ADR 0011).
- **Modules** (`tofu/modules/aws-box`, `tofu/modules/hcloud-box`): their variables and outputs are the interface the provider adapters use. One state workspace per box.
- **cloud-init** (`cloud-init/box.yaml.tftpl`): shared by both modules via `templatefile`. It installs no heavy software.
- **They ship inside the program.** `ozbox` embeds the `.tf`, `.tftpl` and `.sh` files of `tofu/modules/*` and
  `cloud-init/**`, extracts them to a folder keyed by its version and their hash, and checks them by hash before every use
  (ADR 0036). Its build refuses a tree with OpenTofu state, variables or a saved plan in it. The image workflow records the
  first-boot hash (`scripts/first-boot-hash.sh`) in the signed manifest as `first_boot`. On AWS each new machine is tagged
  `ozbox-first-boot` with the hash it was made with (set at creation, never in place): that tag is what `ozbox upgrade`
  trusts. Each box also writes the hash to `/etc/ozbox/first-boot`, a cross-check only. To render a box from this folder while developing, set `module_dir` and `dev_modules = true`
  under the provider's section (or pass `--dev-modules`); without `dev_modules` a different folder is ignored.

## Invariants

1. No inbound network rule of any kind. AWS: security group with zero ingress, no public IP. Hetzner: a firewall with zero rules.
2. AWS: IMDSv2 required (hop limit 1); root and `/work` volumes encrypted; the instance role carries only the account's own
   `ozbox-box-session-manager` policy (below), never AWS's `AmazonSSMManagedInstanceCore`, which can read every Parameter Store
   value in the account.
3. `/work` is a standalone volume: replacing the machine (a new image) keeps the data. First boot formats it only if it has no
   filesystem.
4. Every resource carries `ozbox-box` and `ozbox-managed`; callers cannot override them.
5. sshd listens on 127.0.0.1 only, without passwords, and accepts only keys for the `ozbox` user. A shell arrives through SSM or a
   private mesh, never a port. On AWS the key is pushed for 60 seconds by EC2 Instance Connect right before each connection
   (`ozbox connect <box> --ssh --write` creates the dedicated `~/.ssh/ozbox_ed25519` and writes an SSH entry that does the push);
   nothing is stored on the box and your main key is never used.
6. After a disk is made bigger, `/work` grows by itself within a minute. `ozbox-growfs.timer` runs `ozbox-growfs.service` as a
   one-shot with two capabilities (`CAP_SYS_RESOURCE` for ext4, `CAP_SYS_ADMIN` for xfs), no network and a read-only system; the unprivileged daemon never grows
   anything itself, it reads the result and records an incident, and its self-test checks "filesystem fills its disk".
   Boot also grows `/work`.
7. A box's first approver is pinned from outside it: the `ozbox-approver` label (an Ed25519 public key in lowercase base32,
   52 characters; `ozbox create` sets it) reaches the root setup step in the first-boot configuration, which writes
   `/etc/ozbox/approval-keys`. A malformed value fails the plan. Hetzner's first-boot configuration is sent without the
   template's comment lines, to stay under its 32 KB limit; both modules test their size with the longest values.

Hetzner volumes cannot be created from a snapshot, so the Hetzner module rejects `work_snapshot_id` and clone is not yet supported on Hetzner; `/work` backups there will use encrypted file backups to object storage.

## AWS: the network and the operator's permissions

- **Network** (`tofu/modules/aws-network`): the isolated network a box lives in. A /16 VPC, a private subnet for boxes (its only way
  out is a NAT gateway), and a public subnet that holds only that NAT gateway. Nothing gets a public IP, no ingress rule exists, and
  every resource is tagged `ozbox-managed=true`. Its `private_subnet_id` output is what the box module and `subnet_id` in the CLI
  config take. The NAT gateway bills by the hour while the network exists, so destroy the network when no box needs it.
- **Operator policy** (`aws/operator-policy.json`): the least-privilege IAM policy for the person (or role) who runs `ozbox` against an
  account. Replace `${account_id}` with the 12-digit account id before attaching it. In short: read-only describes, the Service Quotas
  and Pricing reads, the two Cost Explorer reads (`ce:GetCostAndUsage` and `ce:GetTags`, for the real bill), and the public image
  parameters; EC2 resources can be created only when tagged `ozbox-managed=true` and changed or
  deleted only when they carry that tag; IAM only for roles and instance profiles named `ozbox-*` (only the Session Manager policy can
  be attached, and roles can be passed only to EC2); Session Manager sessions only on tagged instances, with the SSH and shell
  documents; EC2 Instance Connect key pushes only to tagged instances and only for the `ozbox` user; S3 only for `ozbox-tfstate-*`
  buckets. An explicit Deny blocks creating users or keys, writing role or user policies, Organizations, Identity Center and Account
  actions, and opening an inbound security group rule. `crates/ozbox-provider-aws/tests/operator_policy.rs` pins these invariants.

- **The real bill** (`ozbox cost bill`, the dashboard's Bill page): read from Cost Explorer, filtered to spend tagged
  `ozbox-managed=true` and grouped by the `ozbox-box` tag and the service. Two things are needed in the account, and neither can be
  done by `ozbox`: turn Cost Explorer on, and activate `ozbox-managed` and `ozbox-box` as **cost-allocation tags** (Billing, Cost
  allocation tags). AWS reports by a tag only from the time it is activated, and the data trails the usage by about a day, so the
  newest days are shown but never compared with the estimate. Each Cost Explorer request costs a cent; Oz Box reads once a day.
  Hetzner Cloud has no invoice or usage API, so there the estimate is all there is.

## Building an image from GitHub Actions (sign-in trust)

The image workflow (`.github/workflows/image.yml`) signs in to your AWS account through GitHub OIDC and assumes the role in the
repository secret `AWS_IMAGE_ROLE_ARN`. Every job that signs in (the build and the publish job) runs in a GitHub
**environment named `image`**, and the role's **trust policy** admits exactly that environment of exactly your repository, by the
`sub` claim GitHub presents. The environment's required reviewer and deployment policy ARE the security boundary: that approval is what lets a
release use the role and sign its manifest, so the trust deliberately names nothing else (no branch, no tag, no wildcard).
**Before the first public release, check, because the workflow cannot check its own environment:**

1. the environment `image` has a required reviewer (not the person who starts the run) and allows deployment only from `main`
   and `image-v*`;
2. a tag ruleset restricts who can create tags `image-v*` (the client's signing identity accepts such a tag on any commit);
3. `main` is protected;
4. the role's trust is the exact subject and nothing else, and public image sharing is allowed in every publishing region
   (the workflow checks the last one before it builds).

`aws/image-build-trust-policy.json` is that trust policy, with placeholders. To pin it for a new repository:

1. Create the environment `image` in the repository (Settings, Environments) and add yourself as a required reviewer.
2. Find the repository's and its owner's numeric ids: `gh api repos/<org>/<repo> --jq '.id, .owner.id'`.
3. Replace `123456789012` with your account id, `ORG` and `REPO` with the organization and repository names, and `ORG_ID` and
   `REPO_ID` with those two ids. The subject is then `repo:<org>@<org-id>/<repo>@<repo-id>:environment:image`, the form GitHub uses
   for an organization that has the immutable-id subject claim on. If yours still uses the plain form, the subject is
   `repo:<org>/<repo>:environment:image`; the ids make it survive a rename and a re-created repository name.
4. Attach it as the role's trust relationship. The role's permissions (create and delete only resources tagged
   `ozbox-managed=true`, and, to publish, copy images to the copy regions, change an image's launch permission, and deregister an
   image and delete its snapshot) are separate.

If AWS still refuses the sign-in, the workflow stops with a message that names the subject it presented and what the role has to
trust, instead of failing deep inside the build.

### Network for the build

The build instance has no inbound path whatever: the security group (`AWS_BUILD_SG_ID`) has **no inbound rule** and Packer reaches
the instance only through Session Manager. The subnet (`AWS_BUILD_SUBNET_ID`) is either private with a route out (the default), or
a public subnet, in which case set the repository variable `AWS_BUILD_PUBLIC_IP` to `true` so the instance has an address for its
outbound traffic to the Session Manager endpoints. Nothing connects in either way.

### Public images (Preview)

By default the workflow builds **private, encrypted** images in your account and publishes nothing. The project's own release sets
the repository variable `OZBOX_IMAGE_PUBLIC` to `true`; then, in order ([ADR 0052](../docs/adr/0052-public-images-from-one-account-trusted-by-owner-and-signed-manifest.md)):

1. the images are built unencrypted (an encrypted image can never be public; a box made from it still has an encrypted root volume),
   in `us-east-1`, and copied to the other regions (`copy_regions`, default `eu-west-1,ap-southeast-1`), for both architectures;
2. the release manifest is built and signed, recording every image id per region and architecture; it is refused if any region is
   missing;
3. only then are the manifest's images tagged as ours and made public (`scripts/image/publish.sh`), and read back to check they are;
4. images outside the retention window are retired in every region (`scripts/image/retention.sh`): the AMI is
   deregistered, then its snapshot deleted. The window is the last three versions plus the newest version of each of the last
   three minors; pre-releases do not count toward it and go only after their release has shipped and 14 days have passed. A pre-release is built private and encrypted unless the run's `publish_prerelease_version` equals the version and ends in `-beta.N` (one beta may be public; never rc, alpha or dev). Nothing is scheduled. It only touches images owned by the account that carry our tags and an Oz Box name,
   never the release just made or anything newer, and does nothing if that release is not among the images. Run it without
   `--apply` for a list.

Check the first public image once by hand: launch it (or attach its snapshot's volume to a throwaway instance) and confirm the SSM
agent's state, both `authorized_keys` files and the journal are empty.

A manual run with `republish` publishes an existing release again from its own manifest (downloaded and verified against the
signing identity first); nothing is built.

A new AWS account blocks public image sharing by default, in each region. Turn it off in each region you publish to
(`aws ec2 disable-image-block-public-access --region <region>`) before the first public release. A fork that publishes its own images
sets `image_publisher` (its account id) and `release_repo` (its repository) in its users' configuration, so a client trusts that
account and that repository's signature instead of the project's.

## Where a box's state lives (ADR 0027, 0033)

By default each box's OpenTofu state is a file in Oz Box's own state directory. Set `state_backend = "s3"` in the provider's
section to keep it in the encrypted bucket `ozbox init` made instead (OpenTofu 1.10 or newer: the lock is a lock file in the
bucket, no table). Moving is explicit and safe to try:

```bash
ozbox state status                    # what is on this computer, what is in the bucket
ozbox state migrate --all --dry-run   # the plan: nothing copied
ozbox state migrate --all --switch    # copy, read back, plan to a no-op, keep the local files, then switch
```

`ozbox adopt <box>` rebuilds a box's missing state from its cloud resources on AWS and on Hetzner (found by their `ozbox-*`
tags or labels), with either backend. It finishes only if the plan changes nothing or tags/labels only, and never changes the cloud.

## Upgrading a box (OpenTofu)

`ozbox upgrade` replaces a box's machine through its module, never edits it in place: `tofu apply -replace=aws_instance.box` on
AWS, `-replace=hcloud_server.box` on Hetzner, with the new `image_id` and everything else as the box is now. The `/work` volume is a
separate resource nothing depends on, so it is kept; the plan is made first, read-only, and refused unless it replaces only the
machine and its attachment. The new machine is built from the current first-boot configuration, which is how a release's helper
scripts, units and pinned approver reach an existing box. Both modules' tests plan the replacement and assert that the volume's id
stays known; a module keeps `ignore_changes` on `image` and `user_data` so that they never plan a replacement on their own.

The browser's own Unix user (`ozbox-browser`, ADR 0037 amendment 4) is made by the image and, for a machine from stock Ubuntu, by
first boot, which runs `ozbox browser-setup` (the script is carried in the program: Hetzner's user data is nearly at its limit).

## The box-wide egress list (ADR 0034)

Optional and off by default. `ozbox box-egress <box> --mode log --preset github --preset anthropic --host api.example.com`
notes what the whole box reaches that is not on the list; `ozbox box-egress <box>` shows it; only then `--mode enforce`
drops the rest (refused until the box has run in log mode). Enforced by the kernel's packet filter on the box, from a root-owned
declaration; other parts of the box add destinations as JSON fragments in `/etc/ozbox/egress.d/`. `--list-presets` says what
each preset holds. The list follows addresses, not names (see the ADR for what that means for shared addresses).

Asking for less needs nothing more. A change that lets the box do more (turning the list off, `enforce` back to `log`, or any
new destination) is made only with a fresh approval from your second factor, because the box user, where an agent runs, files
the same requests: the plan prints the `ozbox secrets approve ... --scope host-guard --project egress --env <digest>` command,
and you run the change again with `--approval CODE`. A box with no second factor enrolled refuses such a change. A declaration
on the box that cannot be read or validated keeps the last good rules and says so first in `ozbox box-egress <box>`.

## The instance metadata service

On every box only root and the machine's own services (the secrets user, the interruption watcher's user `ozbox-meta`, and
Instance Connect's account where it exists) reach `169.254.169.254`, through a packet-filter table loaded at every boot, whatever
the egress list's mode; the box user's requests to it are dropped (ADR 0029, Amendment 6). First boot installs it; on an older
box `ozbox admin <box> -- host-guard metadata install` (or `reinstall-ozboxd`) does.

## The ingress account

Everything your computer sends to a box's secrets service (staging keys, a signer's enrolment, an approval's signature, the
first-time dashboard code coming back) enters through a dedicated account, `ozbox-ingress`, not the box user's: its home is owned
by root, its key file is in a root-owned folder (`/etc/ssh/ozbox-ingress/`), and sshd forces one command, `ozbox secrets receive`,
with no terminal, no `~/.ssh/rc` and no forwarding. Each payload is sealed to a key the box's secrets service made (HPKE), so what
a process on the way sees is ciphertext, and this computer pins that key (`ozbox secrets ingress pin --box <name>`). The Oz image
carries the account; a machine made from stock Ubuntu gets it at first boot (`ozbox secrets ingress-setup`). Your SSH public key
for it is pinned in the `ozbox-ingress` label when the box is made (on AWS, EC2 Instance Connect also pushes it for the account).
A box made before this has no ingress account and is refused with a sentence, never reached the old way (ADR 0029, Amendment 9).
`ozbox upgrade <box>` gives it the account on both providers (AWS rebuilds the machine from the newer image; Hetzner replaces the
server, so the box must move to a newer image). If the box keeps its store's key in a file, the one-time cost is a new secrets
store, because the key cannot be escrowed without the account.

## OpenTofu version

The AWS and Hetzner box modules need **OpenTofu 1.7 or newer** (they use `templatestring`, new in 1.7). On an older OpenTofu,
`tofu init` stops with an "Unsupported OpenTofu version" error that names the requirement, and `ozbox` shows that message,
before anything is created. Keeping state in the encrypted bucket needs 1.10 or newer.

## The fleet's secrets key and the two AWS identities

`ozbox init` plans the fleet's secrets key (`modules/aws-secrets-key`: one KMS key, rotation on, `alias/ozbox-<fleet>-secrets`) after
the network, with its state in the encrypted bucket, creates it only when you approve, and records `secrets_key_arn` and `fleet` in
your config so new boxes keep their store's key in KMS. It runs as your **setup identity**, which needs the `OzBoxKeyAdmin`
permission set (`infra/aws/key-admin-policy.json`); your **daily operator role**
(`infra/aws/operator-policy.json`) has no `kms:` action and is given no right to the key. If setup cannot
create keys it says what to ask an administrator for and leaves boxes on a file key. On Hetzner there is no KMS: a box uses its
TPM if it has one, otherwise a file key escrowed to OpenBao or your keychain (`ozbox secrets ingress escrow`).

### The adopt command's document (`modules/aws-adopt-command`), a step of its own

`ozbox adopt-fleet-key` reads a box's store facts as root through Systems Manager, with a document of the fleet's own
(`ozbox-adopt-<fleet>`) that runs only fixed `ozbox` programs. `ozbox init` plans it after the key, as its own step with its own
state, and applies it with the setup identity's **`OzBoxAdoptAdmin`** permission set (`infra/aws/adopt-admin-policy.json`: the
document actions on `document/ozbox-adopt-*` only; it can neither send a command nor share a document). It is not part of the key
module, whose `OzBoxKeyAdmin` set is KMS-only. Setup checks that permission before it plans, and a refusal never stops the key or
the rest of setup. When it is applied, setup writes the policy for whoever runs `ozbox adopt-fleet-key` to
`operator-adopt-policy.json` in the step's working folder and prints the path; an administrator attaches it to that sign-in and to
nobody else. A test (`tests/init_module_identity_coverage.rs`) checks that every resource type in each module `init` applies is
covered by the permission set that applies it.

## The box role's Session Manager policy, once per account (and what to run on an account that already has boxes)

A box's role carries only customer-managed policies made once per account (`tofu/modules/aws-box-policy`), never an inline policy
and never AWS's broader one: `ozbox-box-session-manager` (what the Session Manager agent needs, no read of any parameter, secret
or key), and, when a box uses them, `ozbox-box-parameters` (its own Parameter Store path, read from the role's tags, under
`/ozbox`), `ozbox-box-fleet-key-<fleet>` (the fleet key, for this box's own secrets only), `ozbox-box-parameters-key` and
`ozbox-box-session-logs`. `ozbox init` makes them (it needs the fleet key and, for session logs, `ozbox harden`, done first; run it
again to add one), once, with
the **setup identity** (it needs the `OzBoxPolicyAdmin` permission set, `infra/aws/box-policy-admin-policy.json`, with
`${account_id}` replaced). Your **daily operator role** (`infra/aws/operator-policy.json`) may attach that one policy by ARN and
cannot create or change a policy, so it cannot widen what a box's role may do. A box cannot be created or upgraded before the
policy exists; the plan says so.

On an account that already has boxes (they carry AWS's `AmazonSSMManagedInstanceCore`):

1. An administrator gives the setup identity `OzBoxPolicyAdmin` and re-applies `infra/aws/operator-policy.json` (it now allows
   attaching only the new policy, reading it, and Instance Connect for the `ozbox-ingress` account).
2. Run `ozbox init --profile <setup-profile>` and approve the "Session Manager policy" step.
3. For each box, either `ozbox upgrade <box>` (replaces the machine, swaps the attachment, pins your ingress key), or, without
   replacing the machine, swap the attachment (attach first, so Session Manager never drops):

   ```
   ACCOUNT=$(aws sts get-caller-identity --query Account --output text)
   # the box roles only: the ones tagged `ozbox-box`. (`iam:ListRoles` is not the operator's, `tag:GetResources` is, and the
   # issuer's roles live in the reserved /obx/ namespace, carry no such tag, and are refused to the operator anyway.)
   ARNS=$(aws --region us-east-1 resourcegroupstaggingapi get-resources --resource-type-filters iam:role \
       --tag-filters Key=ozbox-box --query 'ResourceTagMappingList[].ResourceARN' --output text)
   # An empty answer is NOT "nothing to do": if the tagging API does not return IAM roles in your account, the loop would run
   # zero times and exit 0, leaving every box on the broad policy. Stop instead, and list the roles another way.
   [ -n "$ARNS" ] || { echo "no box roles returned: do NOT assume there are none; check the roles in the console" >&2; exit 1; }
   for ARN in $ARNS; do
     ROLE=${ARN##*/}
     aws iam attach-role-policy --role-name "$ROLE" --policy-arn "arn:aws:iam::$ACCOUNT:policy/ozbox-box-session-manager"
     aws iam detach-role-policy --role-name "$ROLE" --policy-arn arn:aws:iam::aws:policy/AmazonSSMManagedInstanceCore
   done
   ```

   The daily operator role can run these two calls once step 1 is done. A box that used the fleet key before has its fleet-key
   policy attached the same way (`ozbox-box-fleet-key-<fleet>`) by its next `ozbox upgrade`.
4. To move a box's secrets store from a key kept in a file to the fleet key (the key `ozbox init` made): on a box made before the
   release that added the root read, **upgrade it first** (`ozbox upgrade <box>`: its store is kept by escrow or by this
   computer's copy of the key), then run **`ozbox adopt-fleet-key <box>`**, which moves the store in place, whatever it holds.
   `adopt-fleet-key` itself refuses a box whose program is older than that read, and says to upgrade first. `ozbox upgrade <box>
   --use-fleet-key` decides from what the box's own root reports through Systems Manager, so it works only on a box whose program
   has that read (made or upgraded on that release or later) and whose store holds nothing; on any older box it is refused and its
   message says the same: upgrade, then `adopt-fleet-key`. Check with
   `aws iam list-attached-role-policies --role-name <role>`: only `ozbox-box-session-manager` should be listed.

## The off-box issuer (`aws-issuer`, phase 1: not deployed anywhere)

The issuer's two roles are `/obx/obx-<fleet>-issuer` and `/obx/obx-<fleet>-issuer-release`: the reserved role namespace (ADR 0040
section 3.1), outside the `role/ozbox-*` rights of the daily operator role, which is also explicitly denied every IAM write on
`role/obx/*` and `role/obx-*` (`infra/aws/operator-policy.json`). Re-apply that policy before the first `--issuer-package`. The setup
identity's permission set (`infra/aws/key-admin-policy.json`) is denied changing a key tagged `ozbox-production` (its policy, grants
and tags, deletion and disabling, and its alias `alias/ozbox-<fleet>-production`: no create, move or delete); only an account
administrator can, and every such call is a CloudTrail event. **Changing the Production key later needs an administrator**: a
label change, a change of its policy (for example adding `operator_role_arns`), `tofu destroy` of the issuer, and the alias
create and delete the issuer apply performs (the key policy allows them to the account's administrators), so run the first
`--issuer-package` apply with an administrator's profile, not the setup identity. The issuer's OpenTofu
state is kept in the setup identity's state bucket (`ozbox-state-<account>-<region>`), which no operator-policy statement
reaches (the operator's S3 rights are `ozbox-tfstate-*` only; a test pins that the two names never overlap).

`modules/aws-issuer` is the foundation for Production secrets: a function in your own account that is the only principal able to
read Production (through a release role it assumes for at most 900 seconds with one secret named), a Production KMS key only that
role can decrypt with, and an invoke-only policy for a box's role. Its tests pin who can and cannot read. It creates no secret, no
box and nothing until you apply it, and the function's package is yours to build (the `ozbox-issuer` crate is its logic); the
`ozbox init --issuer-package <zip> --issuer-package-sha256 <hash>` plans it (the hash is from the signed release or a reproducible build; the module refuses a file that does not match) (shown, approved, recorded in your config).

## Opt-in AWS security services (ADR 0035)

```bash
ozbox harden --dry-run --guardduty-runtime --session-logs --patching    # the plan and what each costs
ozbox harden --guardduty-runtime --session-logs --patching              # apply (confirms first)
```

The `aws-security-baseline` module, with state in the encrypted bucket. Each service is independent and off unless named:

| Service | What it does | Cost |
|---|---|---|
| GuardDuty Runtime Monitoring | threat detection on the box's own processes, agent managed through Systems Manager | per vCPU of monitored machines, plus an hourly interface endpoint per watched network; the first thirty days of a new detector are free. See AWS pricing for your region |
| Session logs | shell sessions written to `ozbox-sessionlogs-<account>-<region>`, versioned, encrypted, private, locked for `--retention-days` (default 365) in governance mode; `--lock-mode compliance` cannot be undone by anyone until the retention ends | S3 storage for what is kept, for the whole lock |
| Patching | Ubuntu baseline, weekly window, installs only and never restarts, skips a box in use | no charge of its own |

Boxes created or rebuilt after this join the bucket and the patch group (`session_log_bucket`, `patch_group` in `[aws]`, which
`ozbox harden` records). The extra permissions are in `aws/security-services-policy.json`, attached only by whoever opts in;
they allow nothing that removes, unlocks or shortens a log and deny those outright, and the bucket's own policy denies replacing
or deleting itself, so after the first apply only the account's root user can loosen it. Running `ozbox harden` again with the
same options plans no change. `ozbox box-patch <box> --rule when-idle --from 2 --to 5` lets a box restart itself after patches
only inside that window of the day (UTC) once nothing has used it for a while; the default is never. Any `when-idle` rule needs
a fresh approval (`--approval CODE`, scope `host-guard`, project `patch`); `never` does not. On Hetzner there is no equivalent of these services: the
image's unattended upgrades are the patch policy, and `ozbox box-patch` works the same.

## Tests (no credentials)

```bash
tofu fmt -check -recursive infra/
infra/tofu/check-no-ingress.sh
for d in infra/tofu/modules/*/; do
  tofu -chdir="$d" init -backend=false -input=false
  tofu -chdir="$d" validate
  tofu -chdir="$d" test        # mock_provider: no account, no network beyond the provider download
done
```

Packer is validated in CI (`packer validate -syntax-only`); building an image needs cloud credentials and is a release step.
