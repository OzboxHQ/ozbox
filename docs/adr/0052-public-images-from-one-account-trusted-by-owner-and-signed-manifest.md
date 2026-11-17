# 0052 — Public images from one account: trusted by owner and by the signed manifest, never by visibility

**Status.** Decided. **Preview**: built and tested in CI only. No image has been published from the publisher account yet, and
nothing here has run against a real account. It becomes Works when the first public release is built, a clean account creates a
box from it with a bare `ozbox create`, and `ozbox upgrade` takes the next one.

**Decision.** The project publishes its machine images from one dedicated AWS account, as public AMIs, so that a person can run
`ozbox create` without building an image.

- **Where.** Built in `us-east-1`, copied to `eu-west-1` and `ap-southeast-1`, for both architectures. The last **three**
  released versions stay public; after a successful release the older Oz Box images (by their tags and name) are deregistered and
  their snapshots deleted in every region (`scripts/image/retention.sh`, a dry run unless told to apply). The release just made,
  and anything newer, is never selected, and nothing is selected at all if the release is not among the images.
- **A client trusts two things, both.** `ozbox create` with no image, and `ozbox upgrade --image latest`, pick an image in this
  order:
  1. an image named with `--image`, or `image` under `[aws]`: used as named (create already did this);
  2. the newest Oz image **in the caller's own account** (tagged `ozbox-image` and `ozbox-managed`), verified as before: an image
     the caller built or copied is a deliberate choice, and a fork that builds its own never reaches the public ones;
  3. otherwise the newest **public** image that is **owned by the publisher account** (`372115812457`, a constant in
     `ozbox-provider-aws`, overridable with `image_publisher` under `[aws]`, or turned off with `none`) **and** whose release lists
     that exact image id for that region in the **signed release manifest**, verified by the one existing path
     (`ReleaseVerifier`: cosign keyless against the workflow's identity). An image that fails either test is refused with the
     reason, and nothing is created. A look-alike public image from any other account is never a candidate, even if it is newer,
     even if its name says it is ours, even if a manifest lists it.
  Create refuses an unverified default (no `--allow-unverified` for the public path). A person who wants another image names it.
- **AWS hides a resource's tags from other accounts.** So the public path cannot rely on the `ozbox-image` tag: it reads the
  release from the image **name** (`ozbox-<version>-<timestamp>`), and uses it only to choose which manifest to fetch. Whether the
  image is trusted is decided by the manifest, never by the name.
- **The window.** Retention keeps the last **three released versions** and the newest version of each of the **last three
  minors**, so a patch-heavy minor cannot push every older minor out. A pre-release never counts toward the window and is
  retired only after its own release has shipped AND 14 days have passed (a person on a beta is given time to move). There is
  no scheduled run: a tag push or a manual run takes old versions out of use, and a manual run can ask for the list only (since the 2026-11-17 amendment, out of use means private by default, and deleting is a manual run's explicit choice). A box whose image was retired keeps running; `clone`, a create from a stale configuration and a
  rebuild from the same image are refused up front with `ozbox upgrade` as the way forward.
- **When a check fails, the lookup stops.** A public image that the manifest FOR THAT RELEASE does not list for the region is
  skipped for the next candidate. A manifest that is for another release (an old, validly signed manifest swapped in), that
  cannot be read, or that names no release is not an answer about the image and stops the lookup, so nobody with release-edit
  rights can steer clients to the previous release. A failed download or a refused signature for the best candidate is NOT: nothing is created
  and no older image is tried, so a bad day cannot silently pick a worse release. The whole lookup is bounded (90 seconds).
- **Amendment: one beta may be public (owner's decision, recorded for ratification).** The original rule was that no
  pre-release is ever public. The owner's recorded choices for the first release (`0.2.0-beta.0`, called Beta, public straight
  away) conflict with it, so one explicitly opted-in beta may be public, and only that: the workflow input
  `publish_prerelease_version` must equal the version being built and end in `-beta.N` (never rc, alpha or dev), and then the
  build is public and unencrypted; every other pre-release is private and encrypted, and a pre-release that would be public
  without the exact opt-in fails the build. The signed manifest carries `prerelease: true|false`, and the client decides what a
  pre-release is from that signed field, not from the name: a stable program skips one, a pre-release program may take it, and
  a beta program is moved to the stable image of its minor as soon as it exists (same minor, newer; `0.2.0-beta.0` takes
  `0.2.0`) and is told "a newer release is available". The beta is retired only after the final release has shipped and 14 days
  have passed. A partial publish (some images public, then a failure) is recovered by running the workflow with `republish`,
  which publishes the existing release's manifest again after verifying it.
- **Amendment: the public-image quota (owner's decision, 2026-11-16).** AWS allows only 5 public images per region by default.
  The `0.2.0-beta.2` run made its amd64 image public (the fifth) and was refused for arm64, leaving the release half public,
  because retirement ran after publishing and keeps three versions (six images), so it could never fit. Now, before publishing,
  `scripts/image/make-room.sh` makes the **oldest** public Oz Box versions **private** (launch permission removed; the image and
  snapshots stay) until the release fits, whole versions with every architecture together, never the version being published
  or an image that is not ours, and the quota is read from Service Quotas (5 if it cannot be read). The preflight fails a release
  that can never fit before anything is built, and `publish.sh` is all or nothing: it skips images that are already public, and
  rolls back the ones it made public in its own run if any other is refused. **Private (for the quota) and retired (deleted) are
  different:** old versions are made private by this process and never deleted by it; retirement stays a separate, explicit
  step (`retire_old`). A client only ever picks a public image, so a version made private is no longer offered, and a box that
  already runs it keeps running (as with retirement).
- **Which release.** Among the verified candidates, the newest one **this program can use** (same major and minor version,
  ADR 0036) comes first, then the newest. The day after a minor release the newest image is the wrong one for the older program,
  and the three retained versions are what let it keep working until it is upgraded. At most six candidates are checked.
- **The manifest decides, so an image is public only after its release is signed.** The workflow builds the images private, builds
  and signs the manifest (which records every image id per region and architecture, and refuses to be written if any region is
  missing), and only then makes the images public and retires the old ones. A failure before signing leaves nothing public that a
  client could mistake for a release. The client also walks the publisher's images newest first and takes the first the manifest
  vouches for, so a build that was made public and then failed to sign cannot take `latest` down. The same walk applies to an
  image in the caller's own account. An image is **passed over** when its release has no published, signed manifest (a 404:
  the publish step never ran), when the signed manifest does not list the image for the region, or when the manifest says it is
  a pre-release and this program is stable (a pre-release program may take one). Each one passed over is named in the upgrade
  plan (and on `create`), one line each. A check that could not be made (a download or signature failure, a manifest for another
  release) is **not** a reason to pass over: it says nothing about the image, so the lookup stops rather than fall back to an
  older one on a bad day. At most six candidates are checked, within the lookup deadline. When none verifies, `ozbox upgrade`
  refuses and names `--image` and `--allow-unverified-image`; `ozbox create` refuses and names `--image`.
- **Unencrypted images, encrypted boxes.** An encrypted snapshot can never be public, so the public release is built with
  `aws_encrypt_boot = false`. Every box made from it has an encrypted root volume (the box module encrypts it at launch), and a
  fork that does not publish gets encrypted private images (the default).
- **The build role is reachable from one place, and that place is part of the trust root.** The build, the manifest-signing and
  the publish jobs run in the GitHub environment `image`, and the role's trust names that environment by the repository's
  immutable ids (`infra/aws/image-build-trust-policy.json`: exact match, no wildcard, no branch or tag form). So **the
  environment's deployment policy and required reviewer ARE the boundary**: a person who can start a job in it can assume the
  role and sign a manifest. Two more things belong to the same root and must be locked before the first public release: who can
  push a tag `image-v*` (a tag ruleset), and the fact that the client's signing identity (`release::identity_regexp`) accepts
  `image-v*` tags on ANY commit, because the manifest is signed by the workflow at whatever ref it ran. A checklist, because the
  workflow cannot check its own environment's protection rules: (1) the environment `image` has a required reviewer who is not
  the person who started the run, and allows only `main` and `image-v*`; (2) a tag ruleset restricts creating `image-v*`;
  (3) `main` is protected; (4) the role's trust is the exact subject and nothing else.
- **The build network.** The build instance may sit in a public subnet with a public address (`aws_associate_public_ip`), for the
  outbound path to the Session Manager endpoints; the security group has **no inbound rule** and Packer still reaches the instance
  only through Session Manager, so nothing connects in.

**Why.** An image nobody can find is not a product, and a public image nobody can verify is a way to put a stranger's machine
under someone's credentials. Visibility proves nothing: anyone can publish an image named like ours. The owner account id says
who published it, and the signed manifest says that the project's workflow built and listed it; a client needs both, and the
signed manifest is the part nobody else can forge.

**Cost.** One more `describe-images` (and, once per process, a manifest download and a signature check) the first time `create`
resolves a default image; nothing on a box that is created from a named image, and nothing on `resume`. `create` from a public
image needs `curl` and `cosign` on the person's computer, as `upgrade` already does. A fork has to publish its images from its
own account and set `image_publisher` and `release_repo` to trust them.

**What is not covered.**
- There is no arm64 size to create (the catalogue has no Graviton machine), so `create` picks the x86-64 image. A box already on a
  Graviton type is matched to the arm64 image (the 2026-11-17 amendment).
- A box created from an image that is later retired keeps running; `ozbox upgrade` moves it to a current image.
- AMI deprecation is not used: a deprecated image is hidden from other accounts' searches, and making a version private (the
  default, the 2026-11-17 amendment) already hides it, so a date buys nothing, and deprecating a still-retained version would hide it from
  older programs.
- The build role's permissions are the owner's to tighten: publishing needs the image attribute change but not the snapshot
  attribute change (`ec2:ModifySnapshotAttribute` is not used), and the preflight needs `ec2:GetImageBlockPublicAccessState`, which the role's read-only `ec2:Get*` already covers.
- The build instance's SSM registration and Packer's temporary key are cleared by a transient unit when the build instance stops
  (after the agent), not while the session is open; this has not been run against a real build.
- **One-time check of the first public image (owner).** After the first public build, launch the image once, or attach its
  snapshot's volume to a throwaway instance, and confirm that the SSM agent's state (`/var/lib/amazon/ssm`, `/var/log/amazon/ssm`),
  both `authorized_keys` files (`~ubuntu`, root) and the journal are empty. The wipe has not been run against a real build.
- Public sharing of images is blocked by default in a new AWS account, per region: it has to be switched off in each of the
  three before the first release can publish.
- Nothing here has been proven against a real account.

## Amendment (2026-11-17): old versions are made private by default, the workflow runs only from a ref a box trusts, and the image matches the machine's architecture

**Old versions are made private, not deleted, unless a person asks.** Retirement deleted images by default (a tag push retired).
Deleting cannot be undone, costs the next person who rebuilds a box from that image its rebuild (`clone`, a stale configuration,
another account's record), and buys only the storage of a few snapshots. Making a version private already takes it out of every
other account's choice (a client picks only public images) while it stays restorable by hand. So `retention.sh` now makes each
version outside the window that is still public **private** and keeps its image and snapshots; `--delete` retires as before.
Both print a plan and change nothing without `--apply`. The workflow's `retire_old` is `private` (the default, and what every tag
push does), `list`, or `delete` (a manual run only).

**The workflow runs only from `main` or an `image-v*` tag.** The signed manifest's identity names `image.yml` at `refs/heads/main`
or `refs/tags/image-v*`, and a box refuses any other. A run from the program's `v*` tag (or another branch) would sign a manifest
no box trusts; it is now refused in the first job, naming the two ways that work. Accepting `v*` was rejected: it would widen the
identity every box checks to the tag the program release uses, so whoever may push a program tag could sign an image release.

**The image matches the machine.** Image lookup asked for x86-64 only, so a box on a Graviton type was offered an x86 image that
its upgrade check refused, and never found an arm64 one. The lookup now asks for the architecture of the box's own instance type
(`latest_image_for`); a create, whose sizes all map to x86 types, is unchanged.

**What is not covered.** The window still counts versions, not who still runs them. The build role needs
`servicequotas:ListServiceQuotas` to read the real public-image quota; it is the owner's to grant, and without it the scripts
assume 5 and say so. None of this has been run against a real account.

