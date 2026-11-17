# 0040 — A box's dashboard manages the fleet through a scoped role of its own

**Status.** Proposed. **A first slice is built and is Preview (Amendment 1, 2026-11-17): the role documents, the setup module, the plan-bound gate and the dashboard's passkey step. Security review required before merge.** The rest below is design only. Revised after the security review (2026-11-12): the review
(accept with changes: 1 Critical, 5 High, 11 Medium, 9 Low findings; the review itself is kept privately) is answered in
the body below, and the owner's decisions 1 to 9 (at the end) are binding. It needs a second review of this revision before any
code. **Revised again after the consistency check of ADRs 0040 to 0042 (2026-11-12):** the batch window is scoped to an
orchestration's template (§2, §7), the fleet assertion has one encoding and a single-use rule (§2), the passkey keys come from the
laptop-signed approver set (§2), the claim service's powers match what ADR 0042 needs (§4), the Hetzner plan and apply and the
enrolment token are stated once (§6, §9), and the pool of 8 is for workers, not `main` (decision 11). Today a dashboard on a box shows that box and says "Fleet not connected: this dashboard sees only this box" (see
[coding from anywhere §9](../use-cases/coding-from-anywhere.md)); this ADR is how that changes. It narrows ADR 0029's sentence "the
box holds no credential and no role that can fetch a Production value on its own" only in wording (§9).

**Owner's decision (2026-11-12).** `main`'s dashboard gets its own narrow cloud role: only Oz Box boxes, their volumes and
snapshots; no IAM changes, no KMS use or administration, nothing else. Oz Box lives in an account of its own (decision 1), so
there is nothing else in it. The credential is never held by the box user or an agent. Reading is free. Every change (create,
pause, resume, clone, snapshot, destroy) needs a change window from the owner's laptop (decision 2), a passkey confirmation of
that exact plan, and the owner's dashboard role (ADR 0039: owner only).

## Decision

1. **Two fleet roles, assumed with short sessions, no stored key.** The setup identity makes `obx-fleet-read` and
   `obx-fleet-change` (names in the reserved namespace, §3). `main` can assume the **read** role only. The **change** role trusts
   the laptop's identity only. A window is a plan-scoped session the laptop makes, with a hard expiry, sealed to `main` (§2).
2. **Two small uids hold the cloud credentials, and the dashboard holds neither.** A credential holder (`ozbox-fleetcred`, no
   listener, no box group) is the only uid on the metadata guard's list besides today's. It takes `main`'s instance credentials,
   assumes the read role and hands the read session to the dashboard. It opens a sealed window and hands it to the apply unit.
   It never returns the instance-role credentials. The dashboard (`ozbox-supervisor`) is **not** on the guard's list (§1).
3. **Every change is verified by something the attacker on `main` cannot skip.** The laptop made the window; the credential
   holder verifies a WebAuthn assertion bound to the plan hash (§2); IAM, the claim service and an SCP refuse the rest (§3, §4).
4. **One box role per box, bound to one instance by a service `main` cannot reach** (the pool, §4). A compromised `main` cannot
   read another box's secrets by passing its role.
5. **A fleet is read from a cache, written through the same plan-then-apply path as the laptop.** `list` and `info` never call
   OpenTofu (§10). A change plans and applies a managed variant of the box module (§5) with the same engine.
6. **What a fleet role may do is a strict subset of `infra/aws/operator-policy.json`, minus everything that changes who may do
   what** (§3). The operator policy stays the ceiling; a CI test fails if a fleet policy grants an action it does not.
7. **The reserved role namespace is one rule for every protected role** (§3.1): fleet roles, pool roles, the claim service,
   the issuer roles of ADR 0029 and `main`'s own role are named so that the daily operator's `role/ozbox-*` rights cannot reach them.
8. **On Hetzner, `main` plans and the laptop applies** (decision 9, §9).

## 1. How the credential reaches a holder that is not the dashboard

The instance profile belongs to the whole machine. The kernel packet filter from ADR 0029 amendment 6 §2
(`crates/ozbox-cli/src/metadata_guard.rs`) decides which users reach 169.254.169.254: today root, `ozbox-secrets`, `ozbox-meta`
and `ec2-instance-connect`. The box user and every runner user are dropped, and nothing forwarded (a container) reaches it.

**Why not the dashboard uid.** IMDS returns the instance role's credentials to any allowed uid. `main`'s role is a box
role: on `feat/prod-secrets-p1` it still carries AWS's `AmazonSSMManagedInstanceCore` (every parameter in the account), and after
the swap it holds `main`'s own store key. The dashboard is an HTTP server the agent can reach on `127.0.0.1:7878`, it parses
answers from the box daemon (agent-controlled input), and it is in the box user's group today. Allow-listing it would hand an
HTTP-parsing bug the whole instance role. So it is not listed.

**The credential holder.** A new uid `ozbox-fleetcred`, with no network listener, no box group and no shell, is the only addition
to the guard's list. It does three things and nothing else:
1. takes the instance credentials, assumes `obx-fleet-read` (15 minutes asked, `SourceIdentity` set), and returns that read
   session over a socket that only the dashboard uid may open (peer credentials, `SO_PEERCRED`);
2. opens a **sealed window** (§2) and passes the change session to the **apply unit** (a transient uid, §6) over a file
   descriptor, one plan at a time, after it verifies the plan's passkey assertion (§2);
3. appends `fleet.session.*` entries to the audit service (§8).

It never returns the instance-role credentials, never writes a session to disk, a log or an environment, and has no outbound
network except STS and the dashboard of its own box. What the dashboard can now hold is a **read session**: the fleet inventory,
no change power, no secrets.

**Order, hard:** nothing is added to the guard until (a) decision 3 (the dashboard's scoped daemon socket, and removing
`SupplementaryGroups=ozbox` from the dashboard unit) has landed, and (b) `main` runs the narrow `aws-box-policy` policies and no
longer carries `AmazonSSMManagedInstanceCore` (migration step 6). Tests: the credential uid's packet passes; the dashboard
uid's, the box user's, a runner's and a forwarded one are dropped; the table is the guard's own and the egress list cannot loosen
it; the self-check fails closed if the uid is not in the loaded table. The guard resolves uids by name at install, so
`fleet enable` re-renders it, and a test proves the uid is in the loaded table afterwards. The instance's metadata
options stay as they are (tokens required, hop limit 1).

| Option | How | For | Against |
|---|---|---|---|
| **1. Fleet permissions on the instance role** | attach to `main`'s role | simplest | every allowed uid gets fleet powers; no read/change split; no session policy; a box from the same module inherits it |
| **2. Instance role may only assume the read role, through a dedicated uid (chosen for reads)** | `main`'s role: `sts:AssumeRole` and `sts:SetSourceIdentity` on `obx-fleet-read`; the credential holder alone passes the guard | no long-lived secret; the dashboard never holds instance credentials; sessions expire; CloudTrail shows who | root on `main` can read the inventory (acceptable: reads are free) |
| **3. A long-lived IAM user key** | key in the store | works anywhere | a standing secret at rest; the operator policy denies `iam:CreateAccessKey`; rejected |
| **4. IAM Roles Anywhere** | certificate and key for a uid | works off AWS | a standing private key, a CA to run; kept only as the way a Hetzner `main` could reach AWS state |
| **5. The laptop grants a window (chosen for changes, decision 2)** | the laptop assumes the change role with the owner's SSO and makes the session; sealed to the credential holder | root on `main` cannot change the fleet alone; the strongest | a change from a phone needs the laptop to be awake to open a window |

## 2. The change window is made of IAM, not of a setting on `main`

Decision 2 says: outside a window granted from the person's own computer, `main` can only read. That is true only if nothing on
`main` can assume the change role. So:

- **Trust.** `obx-fleet-change` trusts one principal: the owner's Identity Center permission set for fleet windows
  (`aws:PrincipalArn` `StringLike` the reserved SSO role of that permission set, with the account as principal, so a recreated
  role does not leave a dead trust). **`main`'s instance role is not in it.** MFA is enforced in Identity Center (a
  trust condition on `aws:MultiFactorAuthPresent` may not hold in an SSO session; confirm, fact 11). The role may not assume
  anything further.
- **The setting is the trust, held in IAM.** The default is "windows required". Turning that off means the administrator adds
  `main`'s credential-holder path back to the trust, which only the administrator permission set can do. `ozbox fleet status`
  prints which trust is live. Nothing on `main` can flip it, and the operator cannot (§3.1).
- **A window is a plan-scoped session policy.** `ozbox fleet window <plan-id> --for 30m` (laptop) takes the plan `main`
  prepared (a hash and a manifest of the resources it names), assumes the change role with `RoleSessionName = plan-<id>`,
  `SourceIdentity = ozbox-<person>` (the laptop sets both, so root on `main` cannot claim to be anyone: the first `SourceIdentity`
  of a chain cannot be changed) and an inline **session policy** built from the plan: the instance ARNs for a destroy, stop or
  start; the snapshot ARN for a clone; the one volume size and the one instance type for a create. The session policy also carries a
  hard expiry (`DateLessThan aws:CurrentTime`), shorter than the session. A window is therefore a plan, not 30 minutes of
  everything.
- **A batch window (ADR 0042) is scoped to one orchestration's template, not plain.** The laptop assumes the change role with
  `RoleSessionName = orch-<id>` and a session policy built from the orchestration's template: `RunInstances` **only** with the tag
  `ozbox-orchestration=<id>`, the **lane's allowed sizes** and the **pinned image id**; **no snapshot resource at all** (a hub clone
  is "same image, same profile", never a disk copy, ADR 0042 §4, so a batch never needs snapshot rights, and an explicit deny
  covers every snapshot as a source); **start, stop and terminate only on instances that carry that tag**; no destroy of any other
  box; at most **one hour** (role chaining). Its assertion is `H("ozbox-fleet-apply-v1", box id, "batch", orchestration id,
  template hash)`, given once when the orchestration starts; each plan inside it is checked against the template with **no new
  assertion**. The claim service reserves **at most `max_workers`** pool roles for the session `orch-<id>` (§4).
- **Delivery.** The laptop seals the session to the credential holder's public key (a key made at first boot, held by that uid
  only, **pinned by the laptop like the service key**, ADR 0029 Amendment 9 §2) and sends it through the ADR 0029 Amendment 9
  ingress route as the sealed operation `fleet_window`, which joins that amendment's list of sealed operations. `main` receives ciphertext. Root on `main` can read the
  session while the window is open; the design says so (§7).
- **The passkey is bound to the plan.** Before the credential holder opens a window for the apply unit, the person
  gives one WebAuthn assertion with user verification required, whose challenge is
  `H("ozbox-fleet-apply-v1", box id, plan id, plan hash)`. The challenge is **encoded as ADR 0041 §4 encodes a digest**
  (version byte, tag, length-prefixed fields, with the store id among them; shared golden vectors), and **a plan id is spent by its
  first assertion: the credential holder refuses a repeat**, so a replayed assertion cannot apply the same plan twice inside one
  window. The credential holder verifies it against the **laptop-signed approver set** (ADR 0042 §8: each credential listed with
  its person, role and, for a laptop key, its type and attestation), **not against the dashboard's passkey registry**, which a
  compromised supervisor could add a key to. An authenticator code is not accepted for a fleet change. A passkey "stepped up a moment ago" for some other plan does not count.
- **Ending early.** Deleting the trust principal stops new sessions only; a live session lives to its expiry. The kill switch
  for a live one is an **SCP in the dedicated account** (`obx-window-kill`), written in advance, attached by the Organization's
  management identity: it denies every action to sessions of the change role (and `iam:PassRole` of pool roles). The owner
  attaches it from the laptop (`ozbox fleet end-window --all`, which needs the management permission set, a separate and rare
  login). The session policy's own expiry and the 30-minute default make an early end the exception. Where the SCP is not available
  (an account outside an Organization), the answer is "a window ends at its expiry", and `ozbox init` says so.
- **What a closed window means for the product.** Reads and the cached views work. A create, resize, pause, resume, clone,
  snapshot or destroy from the dashboard says "needs a change window from your computer" with the one command. This is
  disclosed in the benchmark as unsupported, never as zero (§11).

## 3. The exact policy

Three documents and a module are made by the laptop's one-time setup (`ozbox fleet enable <box>`, Planned):
`infra/aws/fleet-trust-policy.json`, `infra/aws/fleet-read-policy.json`, `infra/aws/fleet-change-policy.json`, and
`infra/aws/modules/fleet-manager`. Variables as in the operator policy: `${account_id}`, `${regions}`, `${state_bucket}`,
`${sizes}`, `${volume_limits}`. **One-time creation needs an administrator session, not the operator policy** (the operator denies
`iam:PutRolePolicy` and `iam:CreateAccessKey` on purpose); `ozbox fleet enable` prints the documents and the module for the
owner to apply once, and records what was applied. The operator policy is not widened. `main`'s own role gets exactly
`sts:AssumeRole` and `sts:SetSourceIdentity` on the read role (two permissions; confirm, fact 17).

### 3.1 The reserved namespace, stated once

Every role that must not be reachable by the daily operator's `role/ozbox-*` rights lives under the path `/obx/` **and** has a name
starting `obx-`. The ARN is `arn:aws:iam::<acct>:role/obx/obx-<name>`. Instance profiles of the pool follow the same path.
**A path alone is not an escape:** the path is part of the ARN, and `role/ozbox-*` matches any ARN whose role part starts with
`ozbox-`, `/` included (so a path `/ozbox-issuer/` would still match, fact 15). The new scheme uses a prefix the operator pattern
cannot match at all.

| Role | Name |
|---|---|
| Fleet read, fleet change | `obx-fleet-read`, `obx-fleet-change` |
| Pool roles (one per box, §4) | `obx-pool-<nn>` |
| Claim service | `obx-claim-service` |
| `main`'s own role | `obx-main` |
| ADR 0029 issuer roles (moved into the reserved namespace in the same change) | `obx-<fleet>-issuer`, `obx-<fleet>-issuer-release` |
| Laptop-made per-box roles (today's) | stay `ozbox-<box>` (the operator makes them) |

What changes in `infra/aws/operator-policy.json`: an explicit Deny, evaluated over every Allow, on `iam:UpdateAssumeRolePolicy`,
`DeleteRole`, `Attach*`, `Detach*`, `Put*`, `TagRole`, `UntagRole`, `CreateInstanceProfile`, `AddRoleToInstanceProfile`,
`iam:PassRole` and `sts:AssumeRole` on `role/obx/*` and `instance-profile/obx/*`, and on the claim table, the claim function and
the managed state bucket's policy actions. `operator_policy.rs` checks every protected name above against the policy. The key
policy of the fleet key matches a pool role by tag, not name, so the rename breaks nothing. In the dedicated account the
same Denies are an SCP that excepts only the administrator permission set (`aws:PrincipalArn`), so even a mistaken edit to the
operator policy cannot reopen them; an SCP cannot be removed from inside the account.

### 3.2 `obx-fleet-read`

Unchanged in shape: the named `ec2:Describe*` list, `pricing:*` reads, `servicequotas:Get*`, `sts:GetCallerIdentity`, reads of
the pool and main roles only, with `aws:RequestedRegion` on every statement. Three corrections:

- **No state statements.** The read role has no `s3:*`; only a change session plans and applies.
- **It never lists `DescribeInstanceAttribute`** (it returns user data) or console output; a test pins this. The operator's
  `ec2:Describe*` does include it, so the read role is not a copy of it.
- **`ce:GetCostAndUsage` and `ce:GetTags`** are granted only when `ozbox init`'s foreign-resource check found the account clean
  and the account is a **member** account, not the management account (decision 4). A Cost Explorer request has no tag
  condition, so the account is the boundary and the tag filter is presentation. On a shared account the bill stays on the laptop.
  The dashboard shows the account total and the tagged sum and names the gap (CloudTrail, buckets, KMS, transfer).

In a dedicated account `ec2:Describe*` seeing "every instance in the region" means Oz Box's instances only, which is what makes
reads safe to give. The tag conditions on the change role stay as a second wall.

### 3.3 `obx-fleet-change` (everything the read role has, plus)

Every statement carries `aws:RequestedRegion`, and the account's region SCP is the second wall.

- **`RunInstances`.** On `instance/*`: `aws:RequestTag/ozbox-managed = true`, `ec2:MetadataHttpTokens = required`,
  `ec2:InstanceType` in `${sizes}`, tags limited to an allow-list with `ForAllValues:StringEquals aws:TagKeys`, and
  `ozbox-fleet-manager` can never be set at create. On `image/*`: an `ec2:Owner` or `ec2:ImageID` allow-list of Oz Box's images.
  On `volume/*`: `ec2:Encrypted = true`, `aws:RequestTag/ozbox-managed = true`, and `ec2:VolumeSize`, `ec2:VolumeType`,
  `ec2:VolumeIops`, `ec2:VolumeThroughput` within `${volume_limits}`. On `network-interface/*`, `subnet/*` and
  `security-group/*`: the Oz Box ones (`aws:ResourceTag/ozbox-managed = true`). On `snapshot/*` (a clone's block-device mapping
  names a snapshot): `aws:ResourceTag/ozbox-managed = true` **and not** the fleet manager's.
- **`CreateVolume`, `CreateSnapshot`**: from the operator's own statements, narrowed. A snapshot has no tags at
  creation, so `CreateSnapshot` uses `aws:RequestTag/ozbox-managed` on the snapshot and `aws:ResourceTag` only on the volume. Tag
  on create is **two** statements (one for `arn:aws:ec2:*:${account_id}:*/*`, one for `arn:aws:ec2:*::snapshot/*`), each with
  `ec2:CreateAction`. No `CreateTags` on an existing resource.
- **Start, stop, attach, detach, modify volume** on resources tagged `ozbox-managed`, volume modification within `${volume_limits}`.
- **Resize.** `ModifyInstanceAttribute` is an allow-list for **instance type only**: Allow when
  `ec2:Attribute/InstanceType` is in `${sizes}`; every other attribute is not allowed. No deny-list as the only wall. **If the
  simulator shows `ec2:Attribute/InstanceType` is absent from the request context (fact 1), no `ModifyInstanceAttribute` is granted
  in v1 and resize stays a laptop action.** The module census (§12) lists which attributes OpenTofu sends in an in-place change.
- **Destroy** (`TerminateInstances`, `DeleteVolume`) on tagged resources. No `DeleteSnapshot`.
- **`iam:PassRole`** only for a pool role that is reserved for this session and unbound (§4):
  `iam:PassedToService = ec2.amazonaws.com`, `iam:ResourceTag/ozbox-reserved-for = ${aws:userid}`, and a Deny on
  `iam:ResourceTag/ozbox-bound-instance` present. Never `main`'s role, the fleet roles, the issuer roles or the claim service
  (they are not in the pool).
- **`lambda:InvokeFunctionUrl`** on the claim service's function, nothing else.
- **State:** Get, Put, Delete on `ozbox/boxes/*` of the managed bucket (§6).

**The explicit denies** (hold whatever any other statement or a later edit says; every shape is checked in the simulator before it
is trusted):

- Fleet manager: stop, terminate, reboot, delete volume, detach, modify attribute, modify volume, modify metadata options, tag changes
  and `CreateSnapshot` **on anything tagged `ozbox-fleet-manager = true`**, and `CreateVolume` or `RunInstances` from a
  snapshot carrying that tag (`main`'s own `/work` copy holds its store copy and audit chain).
- **No IAM, no direct KMS**: `iam:Create*`, `Put*`, `Attach*`, `Detach*`, `Update*`, `Delete*`, `Add*`, `Remove*`,
  `Tag*`, `Untag*`, `Set*` (and `iam:PassRole` for any role but the reserved pool); `kms:*` with
  `"Bool": {"aws:ViaAWSService": "false"}` (EBS calls KMS on the caller's behalf for an encrypted volume, and an unconditioned deny
  would end the instance in `Client.InternalError`; proven with a canary launch, fact 2). If the volumes use a customer key, the
  allow is `kms:CreateGrant`, `GenerateDataKeyWithoutPlaintext`, `Decrypt`, `DescribeKey` on that one key with
  `kms:ViaService = ec2.<region>.amazonaws.com` and `kms:GrantIsForAWSResource = true`. Also `secretsmanager:*`, `ssm:GetParameter*`,
  `ssm:PutParameter`, `sts:AssumeRole`, `organizations:*`, `sso:*`, `account:*`, `events:*`, `cloudtrail:*`, `guardduty:*`,
  `servicequotas:RequestServiceQuotaIncrease`.
- **No shell** (decision 5): `ssm:StartSession`, `ssm:SendCommand`, `ssm:StartAutomationExecution`,
  `ec2-instance-connect:SendSSHPublicKey`, `ec2-instance-connect:SendSerialConsoleSSHPublicKey`, `ec2:GetSerialConsoleAccessStatus`.
- **No data path out:** `ebs:*` (the direct APIs read snapshot blocks), `ec2:DeleteSnapshot`, `ModifySnapshotAttribute`,
  `ModifyImageAttribute`, `CopySnapshot`, `CreateImage`, `CreateStoreImageTask`, `ExportImage`, `CreateInstanceExportTask`,
  `CreateReplaceRootVolumeTask`; reads of user data and console: `DescribeInstanceAttribute`, `GetConsoleOutput`,
  `GetConsoleScreenshot`, `GetLaunchTemplateData`.
- **No role or network swap:** `AssociateIamInstanceProfile`, `ReplaceIamInstanceProfileAssociation`,
  `ModifyInstanceMetadataOptions`, `ModifyInstanceAttribute` on `groupSet`, `userData` (`ec2:Attribute/UserData` present),
  `blockDeviceMapping`, `disableApiTermination`; security group create, authorize and revoke; VPC, subnet, gateway, route and
  address creation.

In the dedicated account, account-level block public access for EBS snapshots and AMIs is on, and the snapshot-sharing denies are
also an SCP. **The ceiling test:** every Allow in these documents is also an Allow in `operator-policy.json` with a condition at least
as narrow; the only exceptions, named in the test, are assuming the roles, the pool `PassRole` and the claim-service invocation.

**Why it cannot be used to escalate**

- *No IAM, no KMS use*, by deny and by absence. The change role never creates a role: the pool is made by the setup identity (§4).
- *A tag is only as strong as who can write it.* Tag on create only; the fleet manager's tag cannot be set at create; a one-time
  preflight lists everything that carries `ozbox-managed` and refuses to enable the fleet if anything other than Oz Box machines,
  volumes, snapshots and network parts has it.
- *No shell and no data path out* (denies above). Reaching other boxes' daemons for metrics is not offered (decision 5).
- *Cost is bounded by the policy and by the account.* Instance types, volume size, type, IOPS and throughput are conditioned.
  The account's service quotas for vCPUs and EBS are set low as the hard cap (the fleet roles cannot raise them). The setup
  identity adds an AWS Budgets action that attaches a deny at a threshold; a budget alarm alone only notifies.
- *No weakening of the metadata guard on new boxes:* `MetadataHttpTokens = required` on every launch, and modifying it is denied.
- **Still possible within a window, and said plainly:** a create from a managed box's snapshot with the attacker's boot
  configuration. No IAM condition key constrains `RunInstances` user data (recall; fact 7). The clone has its own pool role and
  cannot decrypt the source's store (§4), but the copy of the source's `/work` data is there. That is the accepted residual of "main
  can clone" **in a plan window**, which the plan-scoped session policy (§2: the one snapshot, the one type) narrows. **A batch
  window has no such residual**: its session policy names no snapshot at all (§2), so it can create only from the pinned image.

## 4. The pool of box roles, bound to one instance

Decision 6: the setup identity makes the box roles ahead of time, each scoped to its own box's secrets and parameter path. A pool
that `main` may pass from is not enough if `main` can pass a role a live box is using: the new instance would read that box's
secrets. So the binding is held in IAM, set by a service `main` cannot reach.

**The claim service.** A small function in the Oz Box account (`obx-claim-service`, an IAM-authenticated function URL, owned by the
setup identity, in the reserved namespace). Its powers: `iam:TagRole`/`UntagRole` on pool roles, `ec2:StopInstances` and
`DescribeInstances` on managed instances, and read/write on one **claim table** that nothing else may write. **Plus what ADR 0042
needs of it:** `ssm:PutParameter` and `DeleteParameter` on **pool paths only** (it writes a new box's enrolment token at bind and
wipes the per-box items at release); **its own attestation-signing key**, used to sign worker attestations once a pool role has
registered a worker's keys with it; the right to **register keys** (a worker's service, with its bound pool role, calls it); and a
**URL the pool roles may invoke once bound**: every pool-role statement needs the binding, so the call to the claim service's
function URL is granted in the pool role's policy under the same `ec2:SourceInstanceARN` condition. Tags on pool roles are
the claim record IAM reads; the table is the first-writer-wins arbiter (a conditional put).

**The sequence, for a create from a window:**
1. *Reserve.* `main`'s apply unit (change session, `plan-<id>`) calls the claim service. The service reads the caller's identity
   from the signed request (the session's `userId`, which carries the session name the laptop chose, so `main` cannot forge it),
   checks the plan is a create for this session (or, in a batch window, inside the orchestration's template and under `max_workers`), picks a free pool role by conditional put, and tags the role
   `ozbox-reserved-for = <userid>` (a reservation that expires with the window). It returns the role name.
2. *Launch.* OpenTofu launches with that role. `iam:PassRole` is allowed only for a role whose `ozbox-reserved-for` equals the
   caller's own `${aws:userid}` and that has no `ozbox-bound-instance` tag. A role in use by a live box is bound, so it is not
   passable; a role reserved for another session is not passable.
3. *Bind.* A rule on the account trail's `RunInstances` event wakes the service. It conditionally writes the binding
   (`ozbox-bound-instance = <instance ARN>`), clears the reservation, and if a second instance claims the same role it stops
   the second (first writer wins).
4. *Release.* Only the service, and only after it confirms the instance is gone (terminated), clears the binding.

**Every statement in every pool role's policy requires the binding:**
`"ArnEquals": {"ec2:SourceInstanceARN": "${aws:PrincipalTag/ozbox-bound-instance}"}`. An unbound role (tag absent) can do nothing,
so the gap between launch and bind (seconds) is harmless, and an attacker's instance with a reserved role has no power until the
service binds it. Because the service binds the first instance only, an attacker launching two instances from one reservation gets
one powerless extra, which the service stops. Nobody but the service can write the tags (denied to the change role, the operator,
and by SCP), so root on `main` can neither bind a role to its own instance nor pass a bound role.

A box waits for its bind at first boot (it retries its first secret fetch for a bounded time and then stops with a clear message;
the measured wait is in the benchmark section). A pool with no free role is a refusal that says so; a stale reservation (a window that
expired with no launch) is cleared by the service on a timer.

**What this does and does not give.** A pool role is no longer the weak point: a compromised `main` cannot read another box's
secrets, and a clone's role cannot decrypt the source's store (a clone imports its own secrets). Pool size is set at setup, so
"more boxes" means the setup identity adds roles (a recurring administrator step; accepted, and `ozbox fleet status` shows the free
count). **Fallback if the binding cannot be built:** boxes made from `main` get no secrets until the laptop places them, as ADR
0042 already does on Hetzner (`hub.worker_pin = "laptop"`). Facts 3, 4, 12 and 20 confirm the IAM behaviours this rests on.

## 5. The module variant boxes made from `main` use

The box module creates, per box, a security group, a role, an instance profile and policies. The change role denies every one
of those, so the same module cannot be planned under it. Boxes made from `main` use **`aws-box-managed`**, a variant that takes
a pre-made pool instance profile and a pre-made security group (made by the setup identity, tagged) as inputs and creates only
the instance, the `/work` volume and the attachment. The census test (§12.2) runs against this variant. `ozbox fleet adopt`
(moving a laptop-made box into the managed state) is a state move between two module shapes and is **not offered in v1**; a
laptop-made box is listed, read and watched, and a change says "this box is managed from your own computer".

## 6. Where OpenTofu state lives, and who runs it

ADR 0033 puts state in the encrypted bucket, one object per box. For boxes made or changed from `main`: a **second bucket,
`ozbox-tfstate-managed-<account>`**, versioned, private, SSE-S3 (a customer key would need `kms:Decrypt`, which the owner rules out).
The fleet change role gets Get/Put/Delete on `ozbox/boxes/*` of that bucket only. A box made from `main` is tagged
`ozbox-created-by=<box>`; the laptop's operator policy covers `ozbox-tfstate-*`, so `ozbox adopt` stays the recovery if `main` is lost.

**Bucket policy:** TLS only; deny `s3:DeleteObjectVersion`, `PutBucketVersioning`, `PutLifecycleConfiguration`,
`PutBucketPolicy` and `PutBucketAcl` to everyone except the administrator (the operator's `OzboxStateBucketsOnly` allows
`PutBucketVersioning` on `ozbox-tfstate-*`, so a laptop process could otherwise suspend versioning here; the explicit deny wins);
deny every principal but the fleet change role, the operator and the administrator.

**State stays free of secrets.** Today's first-boot data holds names and public keys only. ADR 0042's one-use enrolment token must
not go into user data **on AWS** (so not into state): it goes into the box's parameter path, written by the claim service, never in
an instance attribute. **On Hetzner, ADR 0042 §2's one-use exception applies**: there is no claim service or parameter path, so the
token goes in user data; it is one use, 30 minutes and useless without the creation secret, and Hetzner state is encrypted under a
laptop-held key, so `main` cannot read it from state. This is the one rule for both providers. If any secret-like value must be in state, OpenTofu client-side state encryption is used with a key the secrets
service releases to the apply unit only. A test fails if state carries a secret-like value (like the integration-key tests).

**Running OpenTofu.** Providers ship **in the image**, in a root-owned read-only mirror, with
`.terraform.lock.hcl` hashes pinned; `tofu init` uses `-plugin-dir` and allows no network install. This is also faster (no
download on the first create). The apply runs under its own transient uid (`ozbox-fleetapply`), which is not on the guard's list and
receives only the change session, **through an inherited file descriptor, not the environment** (same-uid processes can read
`/proc/<pid>/environ`). It has no access to the box user's files or sockets.

## 7. What happens if `main` is compromised

Rows are levels from least to most; a window is open or closed.

| Level | Window closed | Window open (one plan) | Batch window open (ADR 0042) |
|---|---|---|---|
| **Box user or agent on `main`** | Cannot reach IMDS (guard), cannot read any socket of the credential holder or apply unit. With a dashboard that has no sign-in it could read the fleet inventory, so `fleet enable` is refused on such a dashboard and fleet reads are owner and member only. | Same | Same |
| **Dashboard uid (an HTTP bug)** | A read session: the inventory. **No instance credentials, no change power, no secret.** | A read session only: the change session goes to the apply unit, not the dashboard. | Same |
| **Credential holder or apply unit** | Read session / nothing | The plan's change session: the one plan within §3's walls and the session policy. | The template's session: the orchestration's tag, sizes and image; no snapshot; at most an hour. |
| **Root on `main`** | Reads the inventory. **Cannot change the fleet**: the change role does not trust `main`. Cannot pass a pool role (§4). Everything on `main` is read, including secrets the secrets service released to it (worse than any of this, and unchanged). | The window's session (root can read it from memory while it is open): the one plan's actions, e.g. destroy the one named instance or create the one named box; a clone's copy of `/work`. Not another box's secrets (§4). | For up to an hour, inside the template: create instances with the orchestration's tag, the lane's sizes and the pinned image (up to `max_workers`); start, stop and terminate **those** instances. **No snapshot, no copy of any box's `/work`, no destroy of another box**, no other box's secrets (§4). |
| **Operator credentials on the laptop** | Cannot touch the fleet, pool, claim or issuer roles, the claim table or the managed bucket's policy (§3.1 denies and SCP). It can still do what the operator can do today to laptop-made boxes. | Same | Same |
| **Setup or administrator identity, management account** | The account | Same | Same |

**Blast radius, one line:** with a plan window open, one plan's resources in the Oz Box account; with a batch window open, for at
most an hour, instances of one orchestration's tag, size and image, and **no snapshot** (not "the one snapshot"); with it closed, a
read-only view of Oz Box's own fleet. Not any other workload's data, instances, keys, IAM or bill (there is none in the account), and not a
Production value.

**Detection.** The account gets an Organization trail that delivers to a log-archive account the Oz Box account
cannot write; EventBridge rules for the fleet roles and the claim service live in the Oz Box account and notify through the
existing alert channel with the `SourceIdentity`. A CloudTrail event by the change role whose session name has no matching
`fleet.apply.start` is the signal that the gate was skipped; the join runs **off `main`** (in `ozbox fleet status` on the laptop,
or a function in the account), because root on `main` can append to its own chain. Each `fleet.*` audit entry (or each checkpoint
head) is shipped off `main` promptly (ADR 0028's Object Lock bucket). The read-session trust also requires the session to come
from the instance's own network (`aws:SourceVpc` equal to `${aws:Ec2InstanceSourceVPC}`, through an STS VPC endpoint; fact 16);
GuardDuty's credential-exfiltration finding is the second net.

## 8. The box destroying itself, and being destroyed by a neighbour

`main` manages other boxes; it must never stop, delete or edit itself from the dashboard. Layers:

1. IAM denies stop, terminate, delete volume, detach, modify (attribute, metadata, volume), tag changes and snapshot creation on
   anything tagged `ozbox-fleet-manager = true`, and a deny on `CreateVolume` / `RunInstances` from its snapshots (§3.3). The
   setup identity puts the tag on `main`'s machine, its `/work` volume and, through the snapshot schedule, its snapshots.
2. The provider marks the box whose provider id equals this machine's instance id (read once from the metadata service by the
   credential holder) as `this box`; every plan for it is refused with a sentence ("resize or upgrade this box from your own computer").
3. The planner refuses an operation on `this box` before it asks for a passkey.
4. `main`'s role is outside the pool and cannot be passed (§3.1). A box made from `main` has a pool role that holds no fleet permission.

**Audit.** Every fleet change is an entry in the audit chain (ADR 0028), written by the audit service over the credential
holder's socket (its op set gains `audit_append` of these kinds, nothing else): `fleet.session.read`, `fleet.session.change`
(person, session name), `fleet.plan` (plan id, operation, box, plan hash), `fleet.window.open` / `fleet.window.close`,
`fleet.apply.start`, `fleet.apply.ok`, `fleet.apply.failed`, `fleet.refused` (self-target, missing assertion, role, no free pool
role). Entries carry names and ids, never an argument, a credential or a user-data value. The session name is `plan-<id>` and
`SourceIdentity` is `ozbox-<person>`; a CloudTrail event joins to its entry by those two values. If the audit service is
unreachable, a change does not start. Reads are not entered one by one; each session start is.

## 9. Hetzner (decision 9)

AWS has instance roles and Hetzner has none; parity is in the rules, not the mechanism.

- **Scope.** A Hetzner token belongs to one Cloud **project**. Oz Box has a project of its own that holds only Oz boxes
  (decision 1). `ozbox init` names the unit, recommends a fresh one, and warns with kinds and counts when it holds anything else.
- **v1 is plan on `main`, apply from the laptop.** `main`'s dashboard holds a **read-only** token (an ordinary secret in the box's
  store, released only to the credential holder, never to the box user). It reads the fleet and **prepares each change as a
  proposal**: the operation, the module and its variables, from what `main` can read (the read API), hashed. Hetzner state is
  **encrypted under a laptop-held key** (ADR 0042 §2), so `main` cannot run `tofu plan` over an existing stack. The person applies
  the proposal from the laptop with one command (`ozbox fleet apply <plan-id>`): the laptop fetches the proposal's inputs, **plans
  over the encrypted state**, adds what only it holds (the creation secret and the pins, ADR 0042 §2 and §8) **after** that
  plan, and **refuses a resource change the proposal did not name** (the diff is printed). The comparison is of the laptop's plan
  **before its own additions** with the proposal, so the additions cannot make every plan differ. `main` never holds a Read and Write token.
  A Hetzner token has no expiry and is made and removed only in the Console (recall; fact 19), so "a window" cannot be enforced on
  `main`, and a token that can delete `main`, rebuild a server with new user data, change firewalls and clear protection flags
  must not live on it. **Main-side apply on Hetzner arrives only when Hetzner offers scoped tokens** (or an off-box change proxy
  the owner runs, accepting a laptop-signed plan and enforcing its own deny list; not built now).
- **State** is in Hetzner Object Storage (decision 7). S3 keys there may span every bucket in the project (recall; fact 19), so
  the state bucket lives in **its own Cloud project** unless the keys can be scoped per bucket; versioning is on, and Object Lock
  if offered. `main` holds only the state bucket's key.
- **Self-protection** is by name and server id (§8 layers 2 and 3) plus Hetzner's **delete and rebuild protection** on `main` and
  its volume. Hetzner has no deny rule, so there is no layer 1; the setup output says any Read and Write token can remove `main`.
- **ADR 0029.** Its promise ("the box holds no credential and no role that can fetch a Production value on its own") stays
  literally true; on `main` it is narrowed in wording to "...that can read or change anything outside the Oz Box fleet", and
  `main` holds a change credential for nothing at rest: on AWS only a laptop-made window, on Hetzner none.

## 10. Keeping `list` and `info` fast

The control-plane part of the benchmark times `info` and `list`. The box-hosted fleet view must not make either slower than the
fake or the laptop's, and must never be what a person waits on.

- **No OpenTofu call on a read, ever.** A `list` is one `DescribeInstances`, one `DescribeVolumes` and one `DescribeSnapshots`
  per region, each filtered by the `ozbox-managed` tag, issued by a background refresher.
- **The refresher uses the AWS SDK in process, not the `aws` CLI**, so a refresh every 20 seconds is not three
  process spawns per region on `main`.
- **Cached describe calls.** The refresher keeps the last good answer with its time. "Open" means a dashboard connection **or an
  API client that has asked in the last 60 seconds** (the hub, a benchmark adapter): it refreshes every 20 s while open, at once
  after a change finishes, and on a person's refresh; an idle box refreshes not at all. `GET /v1/boxes` and `/v1/info` answer from
  memory in microseconds and carry `as_of`; a stale figure renders as stale. A failed refresh keeps the old answer, marked, with
  the reason.
- **Singleflight and backoff.** One refresh in flight; throttling doubles the interval up to five minutes.
- **First paint on a box** never waits on the cloud: the box's own record is available at once, the other boxes fill in when the
  first describe returns.
- The bill refreshes at most once a day, with a rate-limited refresh button (each Cost Explorer request costs money).

## 11. Benchmark

Oz Box is measured against `starslingdev/hpc-sandbox-benchmarks` (target 4 vCPU / 8 GiB / 40 GB, fresh boxes, median, nine
dimensions); this ADR's effect on each, and what is measured when it is built:

- **`control-plane` (info, list):** neutral or faster through the dashboard (memory reads with `as_of`). Two cautions: a cold dashboard has an
  empty or stale cache, so the first `list` after idle measures the cache, not the provider (report **cold and warm separately**,
  never a warm number as cold); the refresher costs CPU on `main` when `main` runs lanes (fixed by the SDK in process, §10). The
  benchmark's CLI path is unchanged; the cache serves the dashboard only, and nothing is special-cased.
- **`lifecycle` spawn from `main`.** Steps this adds in front of the plan, each to be measured and reported (estimates not
  measured): the window (laptop-side, outside the box's clock; the time to create-to-online is counted from the plan's apply);
  the credential hand-off and one STS call (about 100 to 300 ms); the **claim step** (reserve before launch, then the bind after
  `RunInstances`, likely a few seconds; the box cannot read its secrets until bound, so create-to-online includes it, and it is
  reported as its own line); and `tofu init`. **`tofu init` is removed from the critical path by pre-baking the providers into
  the image** (§6): no registry download, which would otherwise cost tens of seconds on a cold `main`. That helps every create, not the
  benchmark only.
- **`lifecycle` snapshot and teardown:** snapshot was likely broken as first drafted (the tag condition on a snapshot
  that has no tag yet); fixed in §3.3, and not measured until the simulator matrix passes. Teardown is the same module and engine.
- **A closed window** makes create, snapshot, pause, resume, clone and destroy from `main` unavailable: disclosed as unsupported, never zero.
- **`economics`:** the dedicated account adds fixed costs (an Organization trail, GuardDuty, possibly an STS VPC endpoint, the
  claim service). They are included in USD per hour, or stated apart; never hidden.
- **`realworld`, `cpu`, `disk`, `memory`, `network`, `system`:** untouched (no box image, size, mount, disk or network change; the
  guard adds one allowed uid). A 4 vCPU / 8 GiB size (`c7i.xlarge`) is still to be added to the catalog for the benchmark's shape
  (the benchmark rule: never shrink S).
- To be measured when built, on 4/8/40: `list` and `info` through the dashboard (cold, warm); create-to-online through `main`
  with the claim step and with pre-baked providers, and without.

## 12. Test plan

Nothing runs against the real account until the owner says so; everything below uses fakes first.

1. **Policy invariants (unit, CI).** Parse the documents: no Allow for `iam:*` (except the pool `PassRole`), `kms:*`,
   `ssm:GetParameter*`, `secretsmanager:*`; no mutating action on `Resource: "*"`; every Allow is in the operator policy (named
   exceptions only); the denies of §3.3 are present; the trust of the change role names the laptop's permission set and **not**
   `main`'s role; the read role has no state, no `DescribeInstanceAttribute`; no role name outside the reserved namespace
   (§3.1) and `operator_policy.rs` denies each protected name; size limits. A change fails until the expected list changes in the
   same commit.
2. **Module census (unit, CI).** Run `aws-box-managed` with the fake provider, and check that every action it needs for create,
   resize (if offered), pause, resume, clone, snapshot, destroy is in the change policy, that nothing in the policy is unused, and
   which instance attributes an in-place change sends.
3. **IAM simulator (CI with a read-only test identity, or a recorded golden file).** A matrix with an expected allow or deny each:
   tagged and untagged resources, the fleet manager and its snapshots, another region, a disallowed type, an unencrypted or oversized
   volume, `ModifyInstanceAttribute` per attribute, `PassRole` of a bound, reserved-for-another, `main`'s, a fleet and an issuer
   role, `kms:Decrypt` direct and via service, `iam:CreateRole`, `ssm:GetParameter` (denied outright; the box module takes an image
   id, not a public-parameter lookup), `s3:PutObject` in the network's key, `CreateTags` on an existing resource, a snapshot create
   and tag, a clone's snapshot in a block-device mapping, the operator's rights on every protected role name.
4. **Claim service with fakes.** Two launches race for one reservation (one is stopped); a bound role is not passable; a
   reservation expires; release only after terminate; the caller identity comes from the signed request, not the body.
5. **Credential holder, apply unit and dashboard with a fake STS and EC2 (Rust).** A read session without a change gate; a window
   is refused without owner role, without a valid assertion for this exact plan hash, for another plan, after expiry, for `this
   box`, and from an authenticator code; sessions are never in a file, a log, an environment or the audit chain (sentinel values);
   audit unreachable means no change; the dashboard uid cannot read the credential holder's socket beyond the read session.
6. **Metadata guard.** The credential uid passes; the dashboard's, the box user's, a runner's and a forwarded packet are dropped.
7. **Dashboard e2e at 390/820/1440** on a fake fleet: list from the cache with stale marking; a change needs a window and a
   plan-bound passkey; "this box" cannot be changed; an owner-only gate (ADR 0039); the not-connected state; `fleet enable` refused on
   a no-sign-in dashboard; Hetzner shows "apply from your computer" with the command.
8. **Real-box proof (owner's account, owner present, canary resources only).** The read role assumes from the credential holder only;
   the box user and a runner reach no metadata; a deliberate AccessDenied on an untagged canary instance (stop, tag, delete), on
   `kms:Decrypt`, `iam:CreateRole`, a production parameter path (**simulator only, never against real objects**); a canary create,
   resize (if offered), pause, resume, clone, snapshot and destroy through a window; the claim and bind seconds measured;
   CloudTrail joins to the audit chain; `fleet end-window` stops a live session; the preflight tag listing is clean.

## 13. Moving `main` into the dedicated account (decision 1)

Migration of `main` needs the owner's explicit go, step by step; nothing here runs without it. Each step is reversible until step 8.

1. **Prepare the account (administrator, management).** A **member** account (not the management account). SCPs: regions;
   no snapshot or AMI sharing outside the Organization; protection of the reserved namespace (§3.1); the window kill switch
   (§2). An Organization trail into a log-archive account, GuardDuty, EBS default encryption with the account's own key, block
   public access for snapshots and AMIs, low service quotas. Identity Center permission sets for the administrator, the operator and the fleet windows.
2. **Build the base (setup identity, in the new account).** The network module, the state buckets (with §6's policy), the fleet
   key, the `aws-box-policy` policies, the session-log bucket, the issuer, with every protected role named per §3.1.
   **The fleet roles, the pool and the claim service are not created yet.**
3. **Freeze `main`.** Finish and push all work. Stop agents, runs and schedules. Write a manifest of `/work` (counts and a hash list
   of the repositories plus the store copy). Record the audit chain head and ship it off the box.
4. **Take a consistent `/work` snapshot** with the instance stopped. Keep the old instance stopped, not terminated.
5. **Copy the snapshot with a migration key** in the old account whose key policy allows the new account (a snapshot encrypted
   with `aws/ebs` cannot be shared; fact 21), share the copy with the new account only (this needs the administrator, the operator has no
   `ModifySnapshotAttribute`), then copy it again in the new account under that account's own key, so nothing depends on the old account.
6. **Recreate `main` in the new account** from the copied snapshot and the same image version. Its role is `obx-main`, made by the
   setup identity, outside the pool and never passable, with only the narrow `aws-box-policy` policies and never
   `AmazonSSMManagedInstanceCore` (H1).
   - **Re-import the secrets store in the new account** (`ozbox secrets import` from the laptop). The store's key was wrapped by the
     old account's fleet key, which the new account cannot use; re-import is preferred to a cross-account re-wrap.
   - Production records move with the issuer, from the laptop.
   - Start a new audit chain segment whose first entry (`box.migrated`) names the old head.
7. **Verify, then cut over.** Check the manifest against the new `/work`; passkeys keep working if the public URL (relying-party id)
   is unchanged; re-point the tunnel; check that the old account's workloads are untouched.
8. **Retire the old copy, last, after a rollback period the owner sets.** Terminate the old `main`; keep its last snapshot as long as
   the owner wants, then delete it; schedule the migration key's deletion; remove every `ozbox-*` role, policy and bucket and
   the operator policy from the shared account (this also closes the operator-reach problem there, NH1).
9. **Move or recreate the other boxes** the same way, one at a time.
10. **Only then enable the fleet (G2)** in the new account: the fleet roles, the pool and the claim service. `ozbox init`'s
    foreign-resource census runs (Resource Explorer or per-service lists, not `tag:GetResources`, which misses untagged
    resources; on Hetzner every resource kind; kinds and counts only) and is expected to be clean. Then the simulator matrix
    and the canary proof (§12.8).

## 14. Build plan

Each phase ends in a review (Opus) before the next starts; none touches the real account without the owner. Dependencies are hard.

| Phase | What | Depends on | Review |
|---|---|---|---|
| **P0. G1: scoped socket** (built 2026-11-12, on `main`) | decision 3: a second socket for the dashboard user with the read-and-run API it needs; remove `SupplementaryGroups=ozbox`; the dashboard stops being in the box user's group | none | yes |
| **P1. Credential holder and apply unit** | `ozbox-fleetcred` and `ozbox-fleetapply` (own uids, sockets, peer checks, sealed windows, the plan-bound assertion check); the guard line **after** `main` runs the narrow box policies (migration step 6); audit kinds | P0; narrow policies on `main` | yes |
| **P2. Roles, policies, claim service, SCPs (setup, dedicated account)** | the reserved namespace; fleet roles; pool; claim service and table; operator-policy denies; SCPs; trail and alerts; bucket policy; `fleet enable` printing; the policy, census and simulator tests | P1 designs frozen; the account exists | yes |
| **P3. Dashboard fleet pages** | read from the cache; the change flow with the window; `this box`; the refusal states; Hetzner plan-on-main and laptop apply; the e2e at three widths | P1, P2 | yes |
| **P4. Migration of `main` (§13), then the other boxes, then enabling the fleet (G2)** | needs the owner's go at each step; the canary proof | P0 to P3 | yes |
| **P5. Later** | per-box shell opt-in (decision 5), AWS custom billing views, an off-box change proxy for Hetzner | P4 | yes |

## 15. Facts to confirm before build

Confirmed in the IAM policy simulator, or on a canary where stated, or from provider documentation. Nothing here is assumed true.

1. `ModifyInstanceAttribute`: are `ec2:Attribute/InstanceType` and `ec2:Attribute/UserData` in the request context, and is `ec2:InstanceType` absent? (resize, §3.3; if not, resize stays on the laptop)
2. **Canary:** does Deny `kms:*` without `aws:ViaAWSService` refuse an encrypted launch or volume, with `aws/ebs` and with a customer key?
3. `iam:PassRole` honours `iam:ResourceTag/<key>` on the role, with the value matched to a policy variable `${aws:userid}`.
4. A policy variable in a condition value: `ArnEquals ec2:SourceInstanceARN ${aws:PrincipalTag/ozbox-bound-instance}`, and the statement does nothing when the tag is absent.
5. `CreateSnapshot`: `aws:ResourceTag` on the new snapshot denies, `aws:RequestTag` allows.
6. `CreateTags` with `ec2:CreateAction = CreateSnapshot` on `arn:aws:ec2:*::snapshot/*`.
7. `RunInstances` with a snapshot block-device mapping needs Allow on the snapshot resource; no key constrains user data.
8. `ListBucket` with the `s3:prefix` condition when no prefix is sent.
9. **Real STS call:** assuming from instance-profile credentials with `DurationSeconds` above 3600 fails (chaining); the same from an SSO session.
10. A role's `MaxSessionDuration` minimum is 3600 (the 900 seconds is only what is asked).
11. `aws:MultiFactorAuthPresent` in an Identity Center session (decides where MFA is enforced).
12. Whether changing a role's tag changes `aws:PrincipalTag` for sessions already issued (the bind and the kill switch).
13. The read role is refused `DescribeInstanceAttribute`, `GetConsoleOutput` and `ebs:GetSnapshotBlock`.
14. `ModifyVolume` and `CreateVolume` honour `ec2:VolumeSize`, `VolumeType`, `VolumeIops`, `VolumeThroughput`.
15. `arn:aws:iam::<acct>:role/ozbox-*` matches a role whose path starts `/ozbox-`; and that `role/obx/*` is not matched.
16. A trust condition `aws:SourceVpc = ${aws:Ec2InstanceSourceVPC}` through an STS VPC endpoint.
17. Whether the caller needs `sts:SetSourceIdentity` in its own policy as well as in the trust.
18. Cost Explorer in a member account shows only that account; cost-allocation tags are activated in the payer account; custom billing views exist.
19. Hetzner: no token API and no expiry; Object Storage key scope; versioning and Object Lock availability.
20. An IAM-authenticated function URL passes the caller's `userId` (carrying the role session name) to the function, and EventBridge sees `RunInstances` within seconds of the call.
21. A snapshot copied under a customer key can be shared to another account and copied again under that account's key.
22. An SCP denying actions to a role's sessions applies to sessions already issued (the early end of a window).
23. `RunInstances` naming an EXISTING network interface: the interface's own subnet is in the request context as `ec2:Subnet`
    on the `network-interface` resource (so `TheLaunchsInterfaceIsInAnOzboxSubnet` refuses an interface in a foreign subnet),
    and its tags are there as `aws:ResourceTag/*` (Amendment 1, review finding M3). OWNER RUN: simulate `ec2:RunInstances` on
    `arn:aws:ec2:us-east-1:<acct>:network-interface/eni-0123456789abcdef0` with no tag (expect explicitDeny), with
    `ozbox-managed=false` (expect explicitDeny) and with `ozbox-managed=true` in an Oz subnet (expect allowed), and on
    `network-interface/*` (a new interface) in an Oz subnet (expect allowed).
24. A Deny whose `StringNotEquals` value is `${aws:PrincipalTag/ozbox-window-box}` does nothing when the session has no such tag,
    and the `Null` Deny beside it then refuses a `plan-*` session's `AttachVolume` (finding L1).
25. `ec2:AttachVolume` is evaluated against both the instance and the volume, each with its own `aws:ResourceTag/ozbox-box`.

## Consequences

- One more thing the laptop's setup makes: three documents, a module, a managed bucket, a pool of roles, a claim service, SCPs,
  a trail and one administrator step, once. Without it the dashboard stays as built today.
- Changes from the dashboard need the laptop to open a window. A phone alone can read and prepare a plan; it cannot apply.
- The pool is fixed in size until the administrator adds roles.
- The dedicated account is a real cost (trail, GuardDuty, the claim service) and a real migration (§13), with the owner's go.
- Dependent ADRs change in the same release: **0029** (the reserved role names for the issuer, NH1; the sentence in §9);
  **0041** (the passkey assertion is bound to the plan hash by the credential holder there); **0042** §3, §4 (the
  change role is assumed only inside a window, so "outside a window, the owner's passkey step-up" is wrong and becomes "outside
  a window `main` can only read"; a batch window is the orchestration's template, not a plain window; the pool role is reserved,
  launched and bound by the claim service; the enrolment token goes to a parameter path on AWS, not user data); **0041** also adds
  the `fleet_window` operation to ADR 0029 Amendment 9 §2's sealed operations (§2) and the rule that a plan id is spent by its first
  assertion.

## Owner decisions (2026-11-12, binding)

1. **A box sees nothing it does not own (Q1).** Owner: Oz Box is "a shield, like a titanium box": first class, isolated.
   `ec2:Describe*` cannot be limited by tag, so the only way to keep the read role from seeing other workloads is an
   **account of its own**: Oz Box runs in a dedicated AWS account (a member of the Organization), never in an account
   shared with another workload. For this fleet, the boxes move out of the account shared with a production application
   (migration of `main`: snapshot and recreate, planned separately, with the owner's go). For everyone: `ozbox init`
   recommends a dedicated account and warns, with what it found, when the account holds resources Oz Box does not own.
   The policy's tag conditions stay as a second wall.
2. **Changes need a change window from the laptop, by default (Q6).** Outside a window granted from the person's own
   computer (for example 30 minutes), main's dashboard can only read. A setting can turn it off; the default is on.
3. **The dashboard user reaches the box daemon through a scoped socket of its own** (the daemon-socket question): a
   second socket for `ozbox-supervisor` with the read-and-run API the dashboard needs, not membership of the box user's
   group.

   **Built (2026-11-12, release gate G1; reworked after the review the same day).** The dashboard's socket is
   `/run/ozbox-supervisor-api/daemon.sock`, and **systemd binds it, as root, in a folder root owns**
   (`ozboxd-supervisor.socket`: `SocketUser=root`, `SocketGroup=ozbox-supervisor`, `SocketMode=0660`, `DirectoryMode=0755`),
   then hands it to `ozboxd` as an inherited descriptor (socket activation, the way `ozbox-runner.socket` works). The daemon
   never binds, moves or changes the mode of it, and **no step that runs as root touches a path under `/run/ozboxd`**, which
   the box user owns and could fill with links (the first draft ran a root `install -d` there; a link planted by the box user
   would have given it any directory, and root with it). The box user is not in `ozbox-supervisor`, so it cannot connect at
   all; the daemon also checks `SO_PEERCRED` for the supervisor's uid on every connection (fails closed when the platform
   cannot say). **The dashboard is not a member of the box user's group**, in its unit or as a user (an earlier move put it
   there; the setup now takes it out), and on a box its agent connects only to that one fixed path, after checking that the
   socket is a real socket owned by root, in the dashboard's own group, mode 0660, in a root-owned folder nobody else can write
   to. There is no environment override of the path in a release build. The socket unit is written by the program's own
   supervisor setup, so a first boot, `ensure-supervisor` and the upgrade of the program or the daemon (`reinstall-ozboxd`,
   or a Hetzner rebuild, which runs the setup again) all bring it; a daemon started without it has no such socket and says so
   once in its log.

   Only the routes of one table (`ozbox_core::daemon_scope::ROUTES`) are answered; the rest get `403 route_not_allowed`, and the
   dashboard's agent does not even send them: a route off the table is "not available on a box's dashboard", never tried on the
   box user's socket (the dashboard cannot open it). The table:

   | Route | Methods |
   |---|---|
   | `/v1/health`, `/v1/metrics`, `/v1/metrics/now`, `/v1/incidents` | GET |
   | `/v1/selftest` | GET (the last result), POST (run it) |
   | `/v1/sessions`, `/v1/processes` | GET |
   | `/v1/sessions/{id}/stop`, `/v1/processes/{pid}/stop` | POST |
   | `/v1/agent-sessions`, `/v1/agent-sessions/{id}/capture` | GET |
   | `/v1/agent-sessions/{id}/send` | POST |
   | `/v1/agent-events`, `/v1/agent-events/permission/{id}` | GET (reading only) |
   | `/v1/runs` | GET (list), POST (start) |
   | `/v1/runs/{id}/log`, `/v1/runs/{id}/stdin`, `/v1/runs/{id}` | GET, POST, DELETE (cancel) |
   | `/v1/files/*` | GET and HEAD (list, read, search, download) |
   | `/v1/files/write`, `/v1/files/upload` | PUT |
   | `/v1/files/mkdir`, `/v1/files/rename`, `/v1/files/delete`, `/v1/files/trash/restore` | POST |
   | `/v1/checkpoint` | POST |
   | `/v1/terminal`, `/v1/terminal/audit` | GET (attach, audit) |

   **What the table is.** It narrows the API, not the authority. Run start (`POST /v1/runs` takes any command), the terminal and
   typing into a session already act as the box user, so whoever controls the dashboard has the box user's authority through
   them: it can run a checkpoint, a backup tool or a file edit that way. The table keeps the surface small (fewer routes and
   parsers, a named audit line for each); it is not containment. That is why file writes inside the files jail and the
   checkpoint are on it deliberately, each audited: they add nothing run start and the terminal do not already give. The
   protection that matters on this socket points the other way: the box user and its agents cannot reach the dashboard's
   process, its secrets or its socket, and the box user's own socket is not open to the dashboard.

   Also on it: skills on the box's own disk (`/v1/skills`, ADR 0051): a push writes only into the agents' skills folders, only
   the files the dashboard sends, re-checked and re-hashed by the daemon (the approval is the dashboard's check, made before it sends).

   Not on it: backups, the tool installer, local models, writing agent events (the coding agent's own hook), download links
   (`/v1/files/tokens`), emptying the trash, and **answering an agent's permission request** (`POST
   /v1/agent-events/permission/{id}`). No socket of the daemon takes that answer: a process on the box that could post it could
   approve its own request (the hook polls for the answer), and nothing yet carries the signed-in person to the daemon. Until
   the dashboard has a caller that does, the coding agent's permission hook does not wait to be denied: it hands the question
   straight back to the person in the agent's own terminal (Claude Code's `ask`; an engine with no such answer is denied at
   once), tells the event feed, and approves nothing (`PERMISSION_ANSWERS_AVAILABLE` is off). The caller to build: the signed-in
   person, a step-up for risky tools, the decision on the ADR 0028 chain, which is the approval model of
   [ADR 0041](0041-one-approval-model-a-request-the-box-files-a-person-decides-and-the-box-hands-on.md). There is no pause or resume of a run in
   the daemon's API today, so there is none here. A run started on it is admitted, capped, tokened and run as the box user
   exactly as on the box socket (the same code path).

   **Audit.** The daemon writes one line per request after its outcome, `via=supervisor route=<name> method=<m> status=<n>`, with
   the run, session or process id where the route has one, never a path, query or body; refusals are written at most once per ten
   seconds with the count held back, so a flood cannot push the real lines out of the journal. Those lines are the box's own
   claim (the daemon runs as the box user). The dashboard also writes its own line for each change it asks for
   (`via=dashboard-socket route=<name>`) to its own journal, which the box user cannot read or flood. A supervisor decision (an
   approval, a fleet change, an upgrade check) is never based on what the daemon says. The dashboard's line also covers the terminal attach (a read that puts a keyboard in a session), and the held count of a
   refusal burst is written when its interval ends, not only at the next refusal. Wiring the dashboard's line into the audit
   chain (ADR 0028) is not done yet. Benchmark effect: none on the box socket's path; on the dashboard's, one
   `getsockopt` and a scan of 30 short routes per connection, far below the cost of starting a run.
   **Second review round (2026-11-12).** Boot and upgrade, each with a test that failed before:
   - The socket unit carries **no `After=` on any service**: a socket unit is ordered before `sockets.target`, which
     `basic.target` waits for, and a service is ordered after `basic.target`, so any such line is an ordering cycle at every boot
     after the first. A test asserts it, and runs `systemd-analyze verify` on the rendered units where systemd is installed.
   - The `--socket-only` upgrade removes `SupplementaryGroups=ozbox` from an existing dashboard unit, reloads, and only then
     restarts it, because systemd grants a named group at every start whatever `/etc/group` says.
   - A socket that is down while the daemon runs is brought back by **restarting the daemon** (systemd refuses to start a socket
     whose service is running; the daemon's `Wants=` starts the socket first). On a first boot no daemon runs yet, so the socket is
     started and nothing is restarted; the template runs the setup before it starts `ozboxd`, which a test pins.
   - **The socket is never handed to a daemon that does not know it.** The setup writes the unit and drop-in only when the
     installed daemon's file carries the marker `ozbox-listenfd-protocol-1` (it is in the line the daemon logs when the socket is
     up). It never runs the daemon with a new argument to ask: an older daemon ignores an unknown argument and starts a second
     daemon. For an older daemon the units are removed and the setup says to upgrade the daemon.
   - The adopted descriptor must be a listening `AF_UNIX` `SOCK_STREAM` socket, named `ozboxd-supervisor.socket` when systemd names
     it, and every other passed descriptor is closed.
   - The removal of an earlier-copied `ssh_config` runs **as the supervisor**, not as root after a check on a folder the
     supervisor owns.
   - The daemon's self-test has a `dashboard_socket` check on a box with a dashboard user: it fails when the socket unit is installed but systemd did not hand the
     daemon the socket, or the file is missing, and says to run `ensure-supervisor`; with no socket unit (an older program beside this daemon) it is a warning to upgrade the program, never a failure (G1 F3).
   - **Benchmark effect** (`lifecycle`, spawn): none added. At first boot the socket unit is written and enabled (not started) before the
     daemon first starts and comes up with it through the daemon's `Wants=`, so the daemon is not restarted on the spawn path and a
     stopped daemon is not started by the dashboard's next poll (G1 F5); an upgrade stops and starts a running daemon once, in order (G1 F4); an upgrade restarts a running daemon once (a few
     seconds, outside the benchmark's cold-spawn path). Not measured on the 4 vCPU / 8 GiB / 40 GB shape.
   - **Open, to prove on a real box:** the broker's loopback port on a box is reachable by the box user, so a box-user process
     could bind it before the dashboard does (the broker then talks to a squatter). It can only affect the box user's own runs
     (the same user the squatter is), so it is documented rather than fixed here.
4. **The bill lives on main, well architected (Q2).** Cost Explorer filtered to the `ozbox-managed` tag; in a dedicated
   account (decision 1) the whole account's spend is Oz Box's spend, so nothing else can be seen.

### Decision 1 on every provider: the isolation unit

The rule is the same everywhere: Oz Box lives in the provider's **isolation unit**, the smallest boundary its access
control cannot see across, and shares it with no other workload. Tag or label conditions stay as a second wall.

| Provider | Oz Box's own | Why this boundary |
|---|---|---|
| AWS | account (an Organization member) | listing calls cannot be limited by tag; nothing crosses an account |
| Hetzner | Cloud project | an API token belongs to one project and sees nothing outside it |
| Google Cloud (planned) | project | IAM is granted per project |
| Azure (planned) | subscription (resource group at least) | a role scoped to a resource group cannot read outside it; a subscription is the cleaner wall |
| DigitalOcean (planned) | team | tokens belong to a team; projects group resources but do not limit what a token sees |
| Own servers | machines that run nothing else | no shared host |

`ozbox init`, on every provider, names the isolation unit, recommends a fresh one, and when the unit already holds
resources Oz Box did not create it warns and lists them (kind and count, never contents) before making anything. The
security review checks each row, including that DigitalOcean's custom-scoped tokens do not narrow visibility by project.

### Owner decisions, continued (2026-11-12)

5. **No shells on other boxes from main (Q3).** main's dashboard manages other boxes (create, pause, resume, resize,
   snapshot, clone, destroy) but cannot open a Session Manager session on them; a box's shell is reached from the person's
   own computer, as today. A per-box opt-in may come later, behind the change window.
6. **A pool of box roles made in advance (Q4).** The setup identity creates the box roles ahead of time, each scoped to its
   own box's secrets and parameter path; main's change role may pass only a role from that pool and never creates IAM
   roles. A compromised box cannot read another box's secrets.
7. **Hetzner state in S3-compatible object storage (Q5).** Hetzner Object Storage in the same Hetzner project, encrypted,
   so the state outlives main. Hetzner gets the fleet role only once that backend exists.
8. **The notice links to the public docs site (Q7)** once its page is published; until then it names the page as text.

9. **Hetzner v1: plan on main, apply from the laptop (owner, 2026-11-12).** main's dashboard holds a read-only
   Hetzner token and prepares every change as a plan; the person applies it from the laptop with one command, which
   re-plans and refuses if the plan differs. main holds no Read and Write Hetzner token. Hetzner gets main-side apply only
   once Hetzner offers scoped tokens. This refines decision 7 (state in object storage, in a project of its own if keys
   cannot be scoped) and decision 2 (a window cannot be enforced on a Hetzner token, so none is issued).

All of ADR 0040's open questions are decided (Q1 to Q7), and the body above follows decisions 1 to 9.

### Owner decisions after the revision (2026-11-12)

10. **A window can be ended early** through an SCP in the dedicated account, from the Organization's management sign-in
    (rare, emergency only); normally a window simply expires.
11. **The pool starts with 8 box roles** for workers, test lanes and headroom (up to 3 workers per orchestration); `main` has
    its own role, `obx-main`, outside the pool and never passable (§3.1). An administrator adds more pool roles.
12. **The claim step's few seconds at spawn are accepted** and measured, and reported with the benchmark numbers.

## Amendment 1 (2026-11-17): the first slice is built, and what it does not cover

**Status of this amendment: Preview. Security review required before merge.** Nothing here has run against a real account,
and nothing in a released program turns it on: a box's dashboard still says "Fleet not connected" until the credential holder
(§1) exists.

**What is built.**

1. **The role documents** (§3), beside the setup module in `infra/tofu/modules/aws-fleet-manager/` (so the program carries
   them with the module): `fleet-read-policy.json`, `fleet-cost-policy.json` (attached only when asked:
   decision 4), `fleet-change-policy.json` (the allows) and `fleet-change-guard-policy.json` (the explicit denies; one document
   would pass the managed-policy size), and the two trusts, `fleet-read-trust-policy.json` (only `obx-main`) and
   `fleet-change-trust-policy.json` (only the owner's Identity Center window permission set, with a session named `plan-*` only (no
   `orch-*` until the orchestration window is built, Amendment 1); `main` is never in it). `fleet-main-assume-policy.json` is `main`'s one permission. They are templates with one
   renderer, `ozbox_provider_aws::fleet_policy::render`, which refuses any value that is not a plain name.
2. **The setup module** `infra/tofu/modules/aws-fleet-manager` (applied once by an administrator, never the daily operator,
   which is denied every role under `/obx/`): the two roles under `/obx/`, one-hour sessions, the policies above, and the
   attachment to `obx-main`. The box module gains `fleet_manager`, which tags `main`'s machine, its `/work` and its system disk
   `ozbox-fleet-manager = true` from the moment they exist; a label cannot set that tag.
3. **The policy tests** (`crates/ozbox-provider-aws/tests/fleet_policy.rs`): a small evaluator, in the IAM order (an explicit
   deny wins, then an allow whose action, resource and every condition match), runs a matrix over the RENDERED documents:
   untagged, foreign, other-account and other-region resources are refused; `main` itself (by its tag) cannot be stopped,
   destroyed, resized, snapshotted or cloned, and nothing can be created carrying that tag; IAM, direct KMS, secrets, shells,
   data paths out and role or network swaps are denied; a launch must be tagged, of an allowed type and image, IMDSv2 only, with
   encrypted, bounded volumes; resize changes the instance type only; a pool role is passable only when reserved for this session
   and not bound; state is the managed bucket's box objects only; every allowed action is under the operator policy's ceiling
   (named exceptions); only `obx-main` may assume the read role, and `main` may never assume the change role. A condition
   operator the evaluator does not know fails the suite. Mock-provider `tofu test` covers the module's namespace, trusts and
   tokens.
4. **The gate** (`crates/ozbox-cli/src/fleet_gate.rs`, wired into the dashboard server's `apply`): a dashboard that manages
   the fleet plans and applies with the laptop's own code (no second code path), and before `apply` uses a plan up it requires
   a change a box's dashboard may make (create, resize, pause, resume, snapshot, clone, destroy), not naming the box it runs on
   (§8 layers 2 and 3), a plan id not yet spent, a change window open for exactly that plan (as the credential holder reports
   it: a name and an expiry, never a credential), and the owner's passkey over the plan's challenge
   `H("ozbox-fleet-apply-v1", box id, store id, "plan", plan id, plan hash)`, encoded as ADR 0041 §4 encodes a digest. An
   authenticator code, a laptop key, a member's or viewer's passkey, a passkey over another plan and the server's own follow-up
   (an orchestration step, which carries no person) are refused. The challenge is offered at
   `POST /v1/fleet/plans/{id}/challenge` only when nothing else would refuse the plan. Refusals and starts are written to the
   audit chain as `fleet.refused` and `fleet.apply.start`, with the box and the plan id only.
5. **The dashboard** says on its fleet pages, in managed mode, what each change needs, and when the server asks for the fleet
   passkey it fetches that plan's challenge, asks the browser for the passkey, and applies the same plan once with it.

**Review findings fixed (2026-11-17).** An independent review of the roles found one medium and three low findings. Each
fix has a policy test that failed on the earlier documents and passes now (`crates/ozbox-provider-aws/tests/fleet_policy.rs`).

- **M3, a launch on an existing network interface.** The network-interface statement of `RunInstances` allowed any interface
  in the region. A launch that names an existing interface takes that interface's subnet and security groups, so it could have
  put a box in a foreign network past the subnet and group statements. Now the interface must be in one of Oz Box's own subnets
  (`ec2:Subnet`, a documented condition key of that resource; the setup module's new `subnet_ids`), and an interface tagged
  `ozbox-managed` with any value but `true` is denied outright. This corrects §3.3, which held interfaces to the tag alone: a
  new interface has no tags until it exists, so the tag cannot be the wall.
- **L1, attaching a disk.** The fleet-manager deny now covers `AttachVolume` and `StartInstances` too (it already covered
  `DetachVolume`), so no disk can be attached to `main` and `main`'s disks cannot be attached elsewhere. And a plan window
  attaches only a disk and a machine whose `ozbox-box` tag equals the window's `ozbox-window-box` session tag: box A's detached
  disk cannot be attached to box B in B's window. A `plan-*` window without that session tag attaches nothing.
- **L2, `main`'s older snapshots.** The fleet-manager tag is on `main`'s machine and disks, but not on its snapshots (the CLI
  tags a snapshot with its box's name), and not on a system disk made before the mark (its tags are never rewritten in place).
  So everything carrying `main`'s box name (the setup module's new `fleet_manager_box`) is denied exactly as the tag is, which
  covers every snapshot of `main` ever taken, including the pre-upgrade copy of its system disk that holds the store key; and
  nothing new may be given that name. This was chosen over tagging the old snapshots: it changes nothing in the account and
  does not depend on every snapshot path copying a tag.
- **L3, the spent-plan list** is kept in the dashboard's memory only: see the next list.

A size test holds each managed policy under IAM's limit (6,144 characters without whitespace) with the longest values the
setup accepts.

**What is not covered (yet), said plainly.**

- **No credential holder, apply unit or window delivery** (§1, §2, §6: the build plan's P1). So the gate is set only in tests,
  and the dashboard on a box stays "Fleet not connected". The metadata guard's list is unchanged on purpose (the ADR's order: the
  credential holder joins it only after `main` runs the narrow box policies), and a test pins that the box user, its runs, the
  dashboard and the future credential uids are not on it. There is no `ozbox fleet window` or `ozbox fleet enable` command yet.
- **The passkey is checked against the dashboard's own passkey registry**, not yet the laptop-signed approver set (§2). A
  compromised dashboard could add a passkey there; until the approver set exists, this is the residual, and why the window
  (made on the laptop, which a compromised `main` cannot open) is the wall that matters.
- **The window is not a session policy yet**: the plan-scoped session policy (§2) is the laptop's to build with the window
  command. The gate only checks that a window named for this plan is open and not expired.
- **No pool roles, claim service, managed state bucket or SCPs** (§4, §6, §3.1's SCP): the change policy names them so it is
  complete, but they are not made. Without the pool, a create from `main` cannot pass a role, so it would fail at launch.
- **No batch window** (orchestrations, ADR 0042) and **no Hetzner** fleet role (§9).
- **The spent-plan list is in memory** (the last 4,096 plan ids; review finding L3). A dashboard restart forgets it. What still
  holds after a restart: the passkey signed that one plan's challenge, the window was opened for that one plan from your own
  computer and lasts at most an hour, and `apply` refuses a plan whose recorded state no longer matches (ADR 0002), which is the
  usual case once the plan has been applied. Keeping it durably, in the spent ledger ADR 0041 keeps beside its journal, is part
  of the credential holder's build.
- **The window must carry its box.** The window command (not built) must set the `ozbox-window-box` session tag to the plan's
  box. A batch window (`orch-*`, not built) spans several boxes, so the attach rule above does not bind it; its session policy
  must name the boxes before batch windows exist.
- **Orchestration windows: not built.** The trust no longer admits an `orch-*` session. It carries no `ozbox-window-box` tag, so
  the attach rule would not bind it, and without a session policy it could attach any ozbox-managed volume to any ozbox-managed
  machine except `main`. The trust names `plan-*` only until the batch window exists and binds its boxes (session policy or the
  same tag rule); adding `orch-*` back is part of that build.
- **An untagged interface already in an Oz Box subnet** (second review, Low) is now refused: `NeverLaunchOnAnotherOwnersInterface`
  denies `RunInstances` on `network-interface/eni-*` (an existing interface; the one a launch creates has the literal ARN
  `network-interface/*`, which that pattern does not match) unless it carries `ozbox-managed=true`. `StringNotEquals` is also true
  when the key is absent (IAM JSON policy elements reference, "Condition operators": negated operators match a missing key), so an
  untagged interface is refused too. M3's `ec2:Subnet` rule is unchanged. Not simulated in AWS: OWNER RUN NEEDED, fact 23 below.
- **Not proven in AWS's own policy simulator.** The evaluator here is ours; the facts of §15 (above all fact 1, whether
  `ec2:Attribute/InstanceType` is in the request context for a resize, fact 2, an encrypted launch under the KMS deny, and fact
  23, that an existing interface in a foreign subnet is refused) are
  an owner run with a read-only identity. If fact 1 fails, `ResizeChangesTheInstanceTypeOnly` is removed and resize stays a
  laptop action. The simulator answers only for the context it is given, so it shows how the documents decide; whether AWS
  really sends a key (fact 1) and whether an encrypted launch succeeds under the KMS deny (fact 2) are settled only by a dry run
  under the change role and a canary launch, a separate owner decision with its cost stated first.
- **The dashboard's own flow is not run end to end in a browser with a real passkey**; the browser test checks the notice at
  390, 820 and 1440 px, and the flow is tested through fakes and the server's own end-to-end test with a software
  authenticator.

**Benchmark.** None of this is on a measured path: the CLI's plan and apply, a box's image, disk, network and size mapping are
unchanged. The `list` and `info` cache (§10) and the spawn-from-`main` timings (§11) are still to be built and measured.

