# The key-encryption key for a fleet's box secrets (the encrypted store wraps each secret's data key with it).
#
# Who may use it:
#   - a box's instance role, only if the role carries the tag ozbox-fleet=<this fleet> (the box module sets it when given
#     this key) and only for secrets whose encryption context names that box: the account's fleet-key policy (aws-box-policy, attached by the box module) pins
#     kms:EncryptionContext:scope to the box's own name, so one box cannot open another box's secrets;
#   - the operator's roles listed in operator_role_arns.
# The account root can administer the key (create grants, rotate, schedule deletion) but is NOT given Encrypt or Decrypt,
# so an IAM policy in the account cannot widen who can open a secret.

locals {
  tags = merge(var.labels, {
    "ozbox-managed" = "true"
    "ozbox-fleet"   = var.name
  })
}

data "aws_iam_policy_document" "key" {
  statement {
    sid    = "AdministerButNeverUse"
    effect = "Allow"
    principals {
      type        = "AWS"
      identifiers = ["arn:aws:iam::${var.account_id}:root"]
    }
    actions = [
      "kms:Create*", "kms:Describe*", "kms:Enable*", "kms:List*", "kms:Put*", "kms:Update*", "kms:Revoke*",
      "kms:Disable*", "kms:Get*", "kms:Delete*", "kms:TagResource", "kms:UntagResource",
      "kms:ScheduleKeyDeletion", "kms:CancelKeyDeletion",
    ]
    resources = ["*"]
  }

  statement {
    sid    = "FleetBoxesUseTheirOwnSecrets"
    effect = "Allow"
    principals {
      type        = "AWS"
      identifiers = ["arn:aws:iam::${var.account_id}:root"]
    }
    actions   = ["kms:Encrypt", "kms:Decrypt", "kms:DescribeKey"]
    resources = ["*"]
    condition {
      test     = "StringEquals"
      variable = "aws:PrincipalTag/ozbox-fleet"
      values   = [var.name]
    }
    condition {
      test     = "StringLike"
      variable = "aws:PrincipalArn"
      values   = ["arn:aws:iam::${var.account_id}:role/*"]
    }
  }

  dynamic "statement" {
    for_each = length(var.operator_role_arns) > 0 ? [1] : []
    content {
      sid    = "OperatorProvisionsAndRotates"
      effect = "Allow"
      principals {
        type        = "AWS"
        identifiers = var.operator_role_arns
      }
      actions   = ["kms:Encrypt", "kms:Decrypt", "kms:DescribeKey"]
      resources = ["*"]
    }
  }
}

resource "aws_kms_key" "secrets" {
  description             = "Oz Box secrets for fleet ${var.name}"
  enable_key_rotation     = true
  deletion_window_in_days = var.deletion_window_days
  policy                  = data.aws_iam_policy_document.key.json
  tags                    = local.tags
}

resource "aws_kms_alias" "secrets" {
  name          = "alias/ozbox-${var.name}-secrets"
  target_key_id = aws_kms_key.secrets.key_id
}
