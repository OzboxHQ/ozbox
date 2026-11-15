# 0035 — Opt-in security services: runtime monitoring, locked session logs, patching that never restarts a box in use

**Decision.**

1. **Opt-in, per service, planned first.** `ozbox harden --guardduty-runtime --session-logs --patching` plans, shows, and
   (on a yes) applies an OpenTofu module, `aws-security-baseline`, with its state in the encrypted bucket. What is named is the
   whole desired state; leaving one out plans its removal, shown as such. Nothing is on by default. The extra IAM permissions
   are a separate policy (`infra/aws/security-services-policy.json`), attached only by someone who opts in: the operator policy
   is unchanged, and the new policy can neither read nor delete nor unlock a log *(as first written this overstated it; see
   Amendment 1, item 1)*.
2. **GuardDuty Runtime Monitoring.** Turned on as an account-level feature of the region's detector, with GuardDuty managing its
   agent through Systems Manager (every box already uses it). An existing detector is used and never created or deleted by this
   *(a detector this module made is its own and stays managed; Amendment 1, item 2)*.
   Billing is per vCPU of monitored machines, and the agent needs an interface endpoint in each monitored network, which bills by
   the hour; no figure is stated here because AWS sets it. There is no Hetzner equivalent.
3. **Session logs in a bucket that is locked at creation.** Object Lock cannot be added to an existing bucket, so the bucket is
   made with it, versioned, encrypted, private, TLS-only, with a policy that forbids bypassing the lock, deleting a version or
   changing the lock. Shell sessions are logged there through the account's Session Manager preferences document. The default is
   `GOVERNANCE` for 365 days; `COMPLIANCE` (nobody, not even the account owner, can remove a log or the bucket until the
   retention ends) is a deliberate flag, because it cannot be undone and the storage bills for the whole time. Each box's role
   may write one prefix and read the bucket's encryption setting, nothing else (module variable `session_log_bucket`). The
   preferences document is one per account: if it exists it is left alone and the plan says exactly what to set by hand. Logging
   covers shell sessions; an SSH connection carried over Session Manager is encrypted end to end, so its log shows only that it
   happened.
4. **Patching installs; the owner's rule restarts.** An Ubuntu baseline, a patch group (the `Patch Group` tag, module variable
   `patch_group`), and a weekly maintenance window run `AWS-RunPatchBaseline` with `RebootOption=NoReboot`, after a pre-check
   that asks the box whether it is in use and skips it if so. A restart a kernel update needs is done only by the box itself, under
   a rule the owner sets with `ozbox box-patch`: `never` (the default: the box says it needs one and waits) or `when-idle` inside
   a window of the day (UTC) once nothing has used it for a while. "In use" is an agent run executing, a login of the box user,
   or a hold file. The decision is a pure function with tests.
5. **Hetzner.** No GuardDuty, Systems Manager or Patch Manager. The image already runs unattended upgrades daily
   (`/etc/apt/apt.conf.d/20auto-upgrades`; Ubuntu's defaults are security updates only and no automatic restart), which is the
   patch policy there; the restart rule (`ozbox box-patch`) is the
   same program and works on any provider. Session logging on Hetzner is not built: there is no managed session service, and SSH
   goes through the box's own tunnel.

**Cost.** GuardDuty and the log storage are billed by AWS and not estimated here. A locked bucket cannot be deleted until its lock
ends: turning the service off later fails that step safely and leaves the logs. The patch window's pre-check runs the box's own
program as root through Systems Manager; it is read-only (`patch check` changes nothing).

## Amendment 1 (security review, 2026-11-10): the log bucket's policy cannot be replaced, a second run changes nothing, and the box's restart rule needs an approval

A security review (2026-11-10) found three gaps. All are fixed.

1. **Whoever holds the security-services policy could unlock the logs.** It allowed `s3:PutBucketPolicy`, and the bucket policy
   did not deny it, so the holder could replace the bucket policy with one that granted itself `s3:BypassGovernanceRetention`
   and `s3:DeleteObjectVersion`, then delete logs kept in `GOVERNANCE` mode. Now the bucket policy also denies, to every
   principal and without condition, `s3:PutBucketPolicy` and `s3:DeleteBucketPolicy` (beside bypassing the lock, deleting a
   version and changing the lock or versioning). A bucket policy's Deny binds every principal of the account except its root
   user, so after the first apply only the root user can change it; a later change to that document fails by design. The
   security-services policy keeps `s3:PutBucketPolicy` (the first apply writes the policy) and `s3:PutLifecycleConfiguration`
   (a lifecycle rule cannot remove a version that is still locked), no longer allows `s3:DeleteBucket`, and adds an explicit
   Deny of bypassing the lock, deleting an object or a version, deleting the bucket policy or the bucket, and changing an
   object's retention or legal hold, so no other policy the same principal holds can grant them. The module's tests and the
   policy's own tests pin both. `GOVERNANCE` stays the default; `COMPLIANCE` remains the choice for a log nobody may remove.
2. **A second `ozbox harden` planned to destroy what the first made.** The inputs were decided from the live APIs, which
   report the module's own detector as "an existing detector" and its own preferences as "someone else's". Now the plan first
   opens the module's state (in the bucket) and keeps managing a detector or preferences document it already holds; only what
   it does not hold is asked of the APIs. The same options twice plan no change, and a test holds it.
3. **The restart rule is changed only with a fresh approval.** `ozbox box-patch <box> --rule when-idle ...` let the box user
   (an agent included) schedule restarts. Any `when-idle` rule that is not the one in force now needs an approval of scope
   `host-guard` (project `patch`), bound to the rule's words, as the egress list does (ADR 0034, Amendment 1); a box with no
   second factor refuses it. `never` needs none: it only takes restarts away, and an agent can already hold a restart off with
   the hold file.
