# One Oz Box on AWS EC2. Its variables and outputs are the contract the provider adapters rely on.
#
# Invariants (asserted in tests/invariants.tftest.hcl):
#   - the security group has ZERO ingress rules; the box is reached only through outbound tunnels
#   - no public IP, IMDSv2 required with hop limit 1
#   - root and /work volumes are encrypted gp3, and the root volume is tagged ozbox-managed from the moment it exists
#   - /work is a standalone volume, so replacing the instance (a new image) keeps the data

locals {
  tags = merge(var.labels, {
    "ozbox-box"     = var.box_name
    "ozbox-managed" = "true"
    "ozbox-region"  = var.region
  })

  # Which first-boot configuration the machine was made with, on the machine only (never the /work volume, which
  # outlives it). It is the record `ozbox upgrade` trusts: the box cannot change its own tags, and the tag is set when the
  # machine is created and never in place (see ignore_changes below), so it always names the user data it booted with.
  first_boot_tag = var.first_boot_sha256 == "" ? {} : { "ozbox-first-boot" = var.first_boot_sha256 }

  # What the machine's system disk is created with. The operator's role may put a FIRST tag on a volume only through the launch
  # call (`ec2:CreateAction = RunInstances`), never on a volume that already exists, so they ride the launch's volume tag
  # specification (`volume_tags`, which AWS applies while it creates the disk). A disk made without them can never be snapshotted by
  # the pre-upgrade copy (it must be `ozbox-managed`), and nothing but an account administrator can tag it afterwards.
  root_volume_tags = merge(local.tags, { "ozbox-role" = "root" })

  # Patch Manager finds a box by this tag (its name has a space, which AWS requires).
  patch_tag = var.patch_group == null ? {} : { "Patch Group" = var.patch_group }

  # The box's own secrets declaration, as instance tags the box reads from the metadata service. All three or none.
  box_secrets = var.box_secrets_backend == null ? {} : {
    "ozbox-secrets-backend" = var.box_secrets_backend
    "ozbox-secrets-path"    = (var.box_secrets_prefix == null ? "" : var.box_secrets_prefix)
    "ozbox-box-role"        = (var.box_role == null ? "" : var.box_role)
  }
  # IAM name prefixes are limited to 38 characters; the box tag carries the full name.
  iam_prefix = "ozbox-${substr(var.box_name, 0, 28)}-"

  # Nitro instances expose an EBS volume as an NVMe device whose by-id name embeds the volume id
  # without its dash. This path is stable across reboots, unlike /dev/nvme1n1.
  work_device = "/dev/disk/by-id/nvme-Amazon_Elastic_Block_Store_${replace(aws_ebs_volume.work.id, "-", "")}"
}

data "aws_subnet" "this" {
  id = var.subnet_id
}

resource "aws_security_group" "box" {
  name_prefix = "ozbox-${var.box_name}-"
  description = "Oz Box ${var.box_name}: no inbound rules"
  vpc_id      = data.aws_subnet.this.vpc_id

  # Deliberately NO ingress blocks and no ingress rule resources: nothing may connect to the box.
  # Egress is open for now (package mirrors, git, tunnel endpoints). Tightening it to an allow-list
  # is a later step.
  egress {
    description = "All outbound"
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = local.tags

  lifecycle {
    create_before_destroy = true
  }
}

data "aws_iam_policy_document" "assume" {
  statement {
    actions = ["sts:AssumeRole"]

    principals {
      type        = "Service"
      identifiers = ["ec2.amazonaws.com"]
    }
  }
}

resource "aws_iam_role" "box" {
  name_prefix        = local.iam_prefix
  assume_role_policy = data.aws_iam_policy_document.assume.json
  # The tags are what the account's box policies read (`${aws:PrincipalTag/...}`): the box (the fleet key's encryption context)
  # and, with a Parameter Store declaration, its role and prefix (the one path it may read).
  tags = merge(
    local.tags,
    var.secrets_key_arn == null ? {} : { "ozbox-fleet" = coalesce(var.fleet, "unset") },
    var.box_secrets_backend == "aws-ssm" ? { "ozbox-box-role" = coalesce(var.box_role, "unset"), "ozbox-secrets-path" = coalesce(var.box_secrets_prefix, "unset") } : {},
  )

  lifecycle {
    precondition {
      condition     = var.secrets_key_arn == null || var.fleet != null
      error_message = "fleet is required with secrets_key_arn."
    }
  }
}

# Nothing in this module is an inline role policy (`aws_iam_role_policy`): the daily operator role is denied iam:PutRolePolicy on
# purpose, so a plan that needed one would fail after a box was stopped. Every permission a box's role has is a customer-managed
# policy that `ozbox init` made once (the aws-box-policy module) and that the module only ATTACHES, which the operator may do
# for exactly those policies. The policies read the box's own tags, so one policy serves every box. What a tag ties a box to is a PATH,
# not a box: two boxes the operator gives the same prefix and role read the same values (only the operator can set the tags):
#   - the fleet's secrets key, for secrets whose encryption context names this box (the `ozbox-box` tag);
#   - this box's own Parameter Store path, <prefix>/<role> under /ozbox (the `ozbox-secrets-path` and `ozbox-box-role` tags);
#   - a customer key for those parameters, only through Parameter Store;
#   - writing session logs under one prefix of the locked bucket.
data "aws_caller_identity" "this" {}

locals {
  # The path the instance role may read: the prefix and the box's role under it, nothing beside it (the policy enforces it).
  policy_arn_prefix = "arn:aws:iam::${data.aws_caller_identity.this.account_id}:policy"
}

# What the box gets for Systems Manager: the customer-managed policy `ozbox init` made once for the account (the aws-box-policy
# module), by name. NOT AWS's AmazonSSMManagedInstanceCore: that one grants ssm:GetParameter and ssm:GetParameters on every
# parameter in the account, which in a shared account includes another product's Production SecureStrings (ADR 0029,
# Amendment 9). The operator role may attach this policy and no other, and may not create or change one.
#
# The lookup makes a missing policy a plan-time error, before an upgrade stops anything.
locals {
  session_policy_arn = "${local.policy_arn_prefix}/${var.session_policy_name}"
}

data "aws_iam_policy" "session" {
  arn = local.session_policy_arn
}

# The address keeps its old name (`ssm_core`) so a box adopted or applied before this change is replaced in place by an
# upgrade (the plan shows this one resource swapped, not a new one).
resource "aws_iam_role_policy_attachment" "ssm_core" {
  role       = aws_iam_role.box.name
  policy_arn = data.aws_iam_policy.session.arn

  # Swapping the policy on an existing box is a replacement of this attachment. Create the new one first, so the role never
  # sits without Session Manager while the new machine's agent registers.
  lifecycle {
    create_before_destroy = true
  }
}

data "aws_iam_policy" "fleet_key" {
  count = var.secrets_key_arn == null ? 0 : 1
  arn   = "${local.policy_arn_prefix}/ozbox-box-fleet-key-${coalesce(var.fleet, "unset")}"
}

resource "aws_iam_role_policy_attachment" "fleet_key" {
  count      = var.secrets_key_arn == null ? 0 : 1
  role       = aws_iam_role.box.name
  policy_arn = data.aws_iam_policy.fleet_key[0].arn
}

data "aws_iam_policy" "parameters" {
  count = var.box_secrets_backend == "aws-ssm" ? 1 : 0
  arn   = "${local.policy_arn_prefix}/ozbox-box-parameters"
}

resource "aws_iam_role_policy_attachment" "parameters" {
  count      = var.box_secrets_backend == "aws-ssm" ? 1 : 0
  role       = aws_iam_role.box.name
  policy_arn = data.aws_iam_policy.parameters[0].arn

  lifecycle {
    precondition {
      condition     = var.box_secrets_prefix != null && var.box_role != null
      error_message = "box_secrets_prefix and box_role are required with box_secrets_backend."
    }
    precondition {
      condition     = startswith(coalesce(var.box_secrets_prefix, "/"), "/ozbox/")
      error_message = "box_secrets_prefix must be under /ozbox (the account's box policy reads only that root; change its parameter_root with `ozbox init` to use another)."
    }
  }
}

data "aws_iam_policy" "parameters_key" {
  count = var.box_secrets_backend == "aws-ssm" && var.box_secrets_kms_key_arn != null ? 1 : 0
  arn   = "${local.policy_arn_prefix}/ozbox-box-parameters-key"
}

resource "aws_iam_role_policy_attachment" "parameters_key" {
  count      = var.box_secrets_backend == "aws-ssm" && var.box_secrets_kms_key_arn != null ? 1 : 0
  role       = aws_iam_role.box.name
  policy_arn = data.aws_iam_policy.parameters_key[0].arn
}

data "aws_iam_policy" "session_logs" {
  count = var.session_log_bucket == null ? 0 : 1
  arn   = "${local.policy_arn_prefix}/ozbox-box-session-logs"
}

resource "aws_iam_role_policy_attachment" "session_logs" {
  count      = var.session_log_bucket == null ? 0 : 1
  role       = aws_iam_role.box.name
  policy_arn = data.aws_iam_policy.session_logs[0].arn
}

resource "aws_iam_instance_profile" "box" {
  name_prefix = local.iam_prefix
  role        = aws_iam_role.box.name
  tags        = local.tags
}

# The persistent /work disk. A standalone resource: it outlives any instance replacement.
resource "aws_ebs_volume" "work" {
  availability_zone = data.aws_subnet.this.availability_zone
  size              = var.work_disk_gb
  type              = "gp3"
  encrypted         = true
  kms_key_id        = var.kms_key_arn
  snapshot_id       = var.work_snapshot_id == "" ? null : var.work_snapshot_id
  tags              = merge(local.tags, { "ozbox-role" = "work" })

  lifecycle {
    # Replacing a volume destroys /work, so nothing that is only meaningful at creation may ever force one:
    #   - snapshot_id: a box cloned from a snapshot would otherwise plan a new, empty volume as soon as the module is
    #     applied again without the snapshot (an upgrade does exactly that);
    #   - kms_key_id: a changed account default must not re-encrypt by replacement.
    # And two tags the CLI writes on this volume (it survives the machine being replaced) mark an upgrade in progress:
    # the image it is going to, and the machine type the box ran, which is all that remains of a machine that was
    # removed before its replacement could be created.
    ignore_changes = [snapshot_id, kms_key_id, tags["ozbox-upgrade-to"], tags["ozbox-upgrade-machine"]]
  }
}

locals {
  # The first-boot template with its own comment lines removed (a `#!` line stays), before anything is put into it, as the
  # Hetzner module does: AWS takes 16 KB of user data (gzipped here), and the comments alone cost several hundred bytes of
  # it. What the template puts in (a file's content, a value) is left exactly as it is. The cloud-config marker is put back.
  template_text = replace(file("${path.module}/../../../cloud-init/box.yaml.tftpl"), "/(?m)^[ \t]*#([^!\n].*)?\n/", "")

  cloud_init = "#cloud-config\n${templatestring(local.template_text, {
    box_name    = var.box_name
    work_device = local.work_device
    provider    = "aws"
    # The fleet's secrets key (empty when the box has none); the service falls back to the machine's TPM, else refuses.
    secrets_kms_key_id = var.secrets_key_arn == null ? "" : var.secrets_key_arn
    # AWS carries the declaration as instance tags, so nothing is written from the first-boot configuration.
    box_secrets_env    = ""
    secrets_kms_region = var.secrets_key_arn == null ? "" : var.region
    scripts_dir        = "${path.module}/../../../cloud-init/scripts"
    # Where a machine that is not the Oz image gets its box daemon (the image carries its own).
    agent_release_repo = var.agent_release_repo
    agent_release_tag  = var.agent_release_tag
    runs_max_active    = var.runs_max_active
    # The module's own declaration; the box cannot verify it from inside (see the self-test).
    work_encrypted = "true"
    # The box's first approval key, pinned when it was made ("" for none; see the labels variable).
    approval_key = lookup(var.labels, "ozbox-approver", "")
    # Which first-boot configuration this is, recorded on the box ("" when the program gave none).
    first_boot_sha256 = var.first_boot_sha256
    # This computer's key for the ingress account, pinned when the box was made ("" for none; see the labels variable).
    ingress_key = lookup(var.labels, "ozbox-ingress", "")
  })}"
}

# An upgrade is `tofu apply -replace=aws_instance.box` with a new image_id. The machine and its /work attachment are
# replaced; the volume above is a separate resource that nothing depends on, so it is kept (the test
# `an_upgrade_replaces_the_machine_and_keeps_the_work_volume` holds this). The new machine's cloud-init never
# reformats a volume that already holds a filesystem.
resource "aws_instance" "box" {
  # the role's policies are in place before the machine starts (the agent registers with them), on a create and on an upgrade
  depends_on = [
    aws_iam_role_policy_attachment.ssm_core,
    aws_iam_role_policy_attachment.fleet_key,
    aws_iam_role_policy_attachment.parameters,
    aws_iam_role_policy_attachment.parameters_key,
    aws_iam_role_policy_attachment.session_logs,
  ]

  ami                         = var.image_id
  instance_type               = var.machine_type
  subnet_id                   = var.subnet_id
  vpc_security_group_ids      = [aws_security_group.box.id]
  iam_instance_profile        = aws_iam_instance_profile.box.name
  associate_public_ip_address = false

  # AWS allows 16 KB of user data, uncompressed: the first-boot configuration is sent gzip-compressed (cloud-init
  # unpacks it). `output.cloud_init` is the same text uncompressed, for review and for the module tests.
  user_data_base64            = base64gzip(local.cloud_init)
  user_data_replace_on_change = true

  metadata_options {
    http_endpoint               = "enabled"
    http_tokens                 = "required"
    http_put_response_hop_limit = 1
    # The box reads its own secrets declaration (instance tags) from here at boot.
    instance_metadata_tags = "enabled"
  }

  root_block_device {
    volume_type           = "gp3"
    volume_size           = var.root_disk_gb
    encrypted             = true
    kms_key_id            = var.kms_key_arn
    delete_on_termination = true
    # No `tags` here: the provider refuses them together with volume_tags, and applies a block's own tags with a separate call after
    # the machine is running, which the operator's role cannot make for a disk that already exists (and so a box made with only these
    # ended up with an untagged system disk).
  }

  # The launch's own volume tag specification: AWS applies it as the disk is created, which is the one moment the operator's role
  # may put a first tag on a volume (`ec2:CreateAction = RunInstances`). Never changed in place (see ignore_changes): the /work volume
  # is attached to this machine too and is not ours to relabel from here.
  volume_tags = local.root_volume_tags

  tags = merge(local.tags, local.box_secrets, local.patch_tag, local.first_boot_tag)

  lifecycle {
    precondition {
      condition     = var.box_secrets_backend == null || (var.box_secrets_prefix != null && var.box_role != null)
      error_message = "box_secrets_prefix and box_role are required with box_secrets_backend."
    }

    prevent_destroy = false

    # The first-boot configuration names the /work volume (its stable device path embeds the volume id), so a restored
    # /work, which is a new volume, would otherwise change it and replace the machine. User data is read once, at first
    # boot, and the mount is by filesystem UUID (which a snapshot keeps), so the machine must not be replaced for it.
    # This only stops an in-place diff from forcing a replacement: an upgrade (`-replace=aws_instance.box`) still builds
    # the new machine from the current configuration, with fresh user data.
    # The first-boot tag follows the user data: an in-place change (a resize) must not relabel a machine that booted with
    # older user data, so it is written only when the machine is created.
    ignore_changes = [user_data_base64, tags["ozbox-first-boot"], root_block_device[0].tags, volume_tags]
    # The system disk is tagged when it is created (see volume_tags above), and never again in place. The block's own tags are named
    # here too, so a box made with them (an earlier version) plans nothing. A box made by an
    # earlier version has a system disk with no tags at all, and the operator's AWS role may put a first tag on a disk only at
    # the moment it is created (it may change tags only on a resource that already carries ozbox-managed), so a plan that tagged
    # the old disk in place would be refused part way through an apply. Nothing reads a volume's tags: the machine is the
    # principal, and an upgrade makes a new, tagged disk.
  }
}

resource "aws_volume_attachment" "work" {
  device_name                    = "/dev/sdf"
  volume_id                      = aws_ebs_volume.work.id
  instance_id                    = aws_instance.box.id
  stop_instance_before_detaching = true
}
