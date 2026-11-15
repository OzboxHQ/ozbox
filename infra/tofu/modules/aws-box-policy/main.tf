# The ONE managed policy an Oz Box's role carries for Systems Manager: what the Session Manager and Run Command agent needs
# to register the machine and open a shell, and nothing that reads a value.
#
# It replaces AWS's AmazonSSMManagedInstanceCore, which also grants ssm:GetParameter and ssm:GetParameters on every
# parameter in the account. In an account shared with another product's SecureStrings, that let anything on a box that can
# reach its instance role (root, the secrets user) read them (ADR 0029, Amendment 9).
#
# Created ONCE per account by `ozbox init`, with the setup identity (OzBoxPolicyAdmin, infra/aws/box-policy-admin-policy.json).
# The daily operator role can attach this policy by its ARN and nothing else, and cannot create or change a policy, so it
# cannot widen what a box's role may do. A box's own Parameter Store path (box_secrets_backend) and its secrets key are
# the other policies here, each one attached by the box module and made once by `ozbox init`: nothing a box's role may do is an
# inline policy the operator would have to write (it is denied iam:PutRolePolicy on purpose), and a policy is per account, not
# per box, so each one reads the box's own tags (`${aws:PrincipalTag/...}`), which the module sets on its role.

data "aws_iam_policy_document" "session" {
  # The agent registers the machine and reports its state; documents and associations are what Run Command and Session
  # Manager are made of. None of these reads a parameter or a secret.
  statement {
    sid = "RegisterAndReceiveWork"
    actions = [
      "ssm:UpdateInstanceInformation",
      "ssm:DescribeAssociation",
      "ssm:ListAssociations",
      "ssm:ListInstanceAssociations",
      "ssm:GetDocument",
      "ssm:DescribeDocument",
      "ssm:GetManifest",
      "ssm:UpdateAssociationStatus",
      "ssm:UpdateInstanceAssociationStatus",
      "ssm:PutInventory",
      "ssm:PutComplianceItems",
      "ssm:PutConfigurePackageResult",
      "ssm:GetDeployablePatchSnapshotForInstance",
    ]
    resources = ["*"]
  }

  # The session channels the shell travels over.
  statement {
    sid = "SessionChannels"
    actions = [
      "ssmmessages:CreateControlChannel",
      "ssmmessages:CreateDataChannel",
      "ssmmessages:OpenControlChannel",
      "ssmmessages:OpenDataChannel",
    ]
    resources = ["*"]
  }

  # The message service the agent polls for commands.
  statement {
    sid = "AgentMessages"
    actions = [
      "ec2messages:AcknowledgeMessage",
      "ec2messages:DeleteMessage",
      "ec2messages:FailMessage",
      "ec2messages:GetEndpoint",
      "ec2messages:GetMessages",
      "ec2messages:SendReply",
    ]
    resources = ["*"]
  }
}

resource "aws_iam_policy" "session" {
  name        = var.name
  description = "Oz Box: what a box's role needs for Session Manager, and no read of any parameter or secret."
  policy      = data.aws_iam_policy_document.session.json

  tags = {
    "ozbox-managed" = "true"
  }
}

data "aws_caller_identity" "this" {}

# ---- a box's own parameters: <its prefix>/<its role> and below, under the parameter root, nothing else ----------------------

data "aws_iam_policy_document" "parameters" {
  statement {
    sid     = "ReadTheBoxsOwnPath"
    actions = ["ssm:GetParameter", "ssm:GetParameters", "ssm:GetParametersByPath"]
    resources = [
      "arn:aws:ssm:*:${data.aws_caller_identity.this.account_id}:parameter$${aws:PrincipalTag/ozbox-secrets-path}/$${aws:PrincipalTag/ozbox-box-role}",
      "arn:aws:ssm:*:${data.aws_caller_identity.this.account_id}:parameter$${aws:PrincipalTag/ozbox-secrets-path}/$${aws:PrincipalTag/ozbox-box-role}/*",
    ]
    # the prefix the role is tagged with must be under the parameter root, so a box can never be pointed at another product's path
    condition {
      test     = "StringLike"
      variable = "aws:PrincipalTag/ozbox-secrets-path"
      values   = ["${var.parameter_root}/*"]
    }
  }
}

resource "aws_iam_policy" "parameters" {
  name        = "ozbox-box-parameters"
  description = "Oz Box: read the box's own parameters (its tagged prefix and role, under ${var.parameter_root}) and nothing else."
  policy      = data.aws_iam_policy_document.parameters.json
  tags        = { "ozbox-managed" = "true" }
}

# ---- a customer key that encrypts those parameters: only through Parameter Store ------------------------------------------------

data "aws_iam_policy_document" "parameters_key" {
  count = var.box_secrets_kms_key_arn == null ? 0 : 1

  statement {
    sid       = "DecryptOnlyThroughParameterStore"
    actions   = ["kms:Decrypt"]
    resources = [var.box_secrets_kms_key_arn]
    condition {
      test     = "StringLike"
      variable = "kms:ViaService"
      values   = ["ssm.*.amazonaws.com"]
    }
  }
}

resource "aws_iam_policy" "parameters_key" {
  count       = var.box_secrets_kms_key_arn == null ? 0 : 1
  name        = "ozbox-box-parameters-key"
  description = "Oz Box: decrypt the box's own parameters with the customer key, only through Parameter Store."
  policy      = data.aws_iam_policy_document.parameters_key[0].json
  tags        = { "ozbox-managed" = "true" }
}

# ---- the fleet's secrets key: this box's own secrets only (the encryption context names the box) --------------------------------

data "aws_iam_policy_document" "fleet_key" {
  count = var.fleet_key_arn == null ? 0 : 1

  statement {
    sid       = "UseTheFleetKeyForThisBoxOnly"
    actions   = ["kms:Encrypt", "kms:Decrypt"]
    resources = [var.fleet_key_arn]
    condition {
      test     = "StringEquals"
      variable = "kms:EncryptionContext:scope"
      values   = ["$${aws:PrincipalTag/ozbox-box}"]
    }
  }
}

resource "aws_iam_policy" "fleet_key" {
  count       = var.fleet_key_arn == null ? 0 : 1
  name        = "ozbox-box-fleet-key-${coalesce(var.fleet, "unset")}"
  description = "Oz Box: use the fleet's secrets key for the box's own secrets only."
  policy      = data.aws_iam_policy_document.fleet_key[0].json
  tags        = { "ozbox-managed" = "true" }

  lifecycle {
    precondition {
      condition     = var.fleet != null
      error_message = "fleet is required with fleet_key_arn."
    }
  }
}

# ---- session logs: write under one prefix of the locked bucket, read nothing ------------------------------------------------------

data "aws_iam_policy_document" "session_logs" {
  count = var.session_log_bucket == null ? 0 : 1

  statement {
    sid       = "WriteSessionLogs"
    actions   = ["s3:PutObject"]
    resources = ["arn:aws:s3:::${var.session_log_bucket}/ozbox/sessions/*"]
  }

  statement {
    sid       = "SeeTheBucketIsEncrypted"
    actions   = ["s3:GetEncryptionConfiguration"]
    resources = ["arn:aws:s3:::${var.session_log_bucket}"]
  }
}

resource "aws_iam_policy" "session_logs" {
  count       = var.session_log_bucket == null ? 0 : 1
  name        = "ozbox-box-session-logs"
  description = "Oz Box: write session logs under one prefix of the locked bucket, and read nothing that was logged."
  policy      = data.aws_iam_policy_document.session_logs[0].json
  tags        = { "ozbox-managed" = "true" }
}
