# The off-box issuer for Production secrets (ADR 0029, Amendment 6 section 4 and Amendment 9), in the owner's own account.
#
# One function is the only principal that can read Production. It does not hold the read itself: its own role cannot read a
# secret or use the Production key. After it has checked an approval it assumes a second role, the release role, for at most
# 900 seconds with a session policy that names one secret, reads that value, and seals it to the box's service key. A box has
# no credential here beyond asking: it may invoke the function and nothing else.
#
#   box instance role --invoke--> issuer function --assume (<= 900 s, one secret)--> release role --read--> Production secrets
#
# Nothing in this module creates a secret, a box or a person's key. The function's package is built by the owner.

locals {
  tags = merge(var.labels, {
    "ozbox-managed" = "true"
    "ozbox-fleet"   = var.name
    "ozbox-issuer"  = "true"
  })

  # Names, not resource attributes, so each policy can be read (and tested) as written.
  # The reserved role namespace (ADR 0040 section 3.1, ADR 0029 NH1): path /obx/, name obx-*. The daily operator role may manage
  # `role/ozbox-*` and is explicitly denied every IAM write on `role/obx/*` and `role/obx-*` (infra/aws/operator-policy.json),
  # so it cannot rewrite these roles' trust, hand them to an instance or pass them. The path is part of the ARN, so
  # `role/ozbox-*` does not match `role/obx/obx-<fleet>-issuer`.
  role_path         = "/obx/"
  issuer_role_name  = "obx-${var.name}-issuer"
  release_role_name = "obx-${var.name}-issuer-release"
  issuer_role_arn   = "arn:aws:iam::${var.account_id}:role${local.role_path}${local.issuer_role_name}"
  release_role_arn  = "arn:aws:iam::${var.account_id}:role${local.role_path}${local.release_role_name}"
  function_name     = "ozbox-${var.name}-issuer"
  function_arn      = "arn:aws:lambda:${var.region}:${var.account_id}:function:${local.function_name}"
  secrets_arn       = "arn:aws:secretsmanager:${var.region}:${var.account_id}:secret:${var.secret_name_prefix}*"
  config_param      = "/obx/${var.name}/issuer/config" # outside /ozbox, the root a box's own policy may read
  config_param_arn  = "arn:aws:ssm:${var.region}:${var.account_id}:parameter${local.config_param}"
  table_name        = "ozbox-${var.name}-issuer-state"
}

# ---- The Production key: only the release role decrypts -------------------------------------------------------------------

data "aws_iam_policy_document" "key" {
  statement {
    sid    = "AdministerButNeverUse"
    effect = "Allow"
    principals {
      type        = "AWS"
      identifiers = ["arn:aws:iam::${var.account_id}:root"]
    }
    # Named, never a wildcard: `kms:Create*` would include CreateGrant and `kms:Put*` PutKeyPolicy, each a way to give oneself
    # Decrypt. Neither is here. A key policy change is its own statement below.
    actions = [
      "kms:DescribeKey", "kms:GetKeyPolicy", "kms:GetKeyRotationStatus", "kms:ListResourceTags", "kms:ListGrants",
      "kms:EnableKeyRotation", "kms:DisableKeyRotation", "kms:UpdateKeyDescription",
      "kms:TagResource", "kms:UntagResource", "kms:ScheduleKeyDeletion", "kms:CancelKeyDeletion",
      # the issuer's alias is made, and removed on destroy, by whoever applies this module; the setup identity is
      # denied alias calls on this key and on this alias name (infra/aws/key-admin-policy.json)
      "kms:CreateAlias", "kms:DeleteAlias",
    ]
    resources = ["*"]
  }

  # Changing this policy is the one remaining way to widen who decrypts. It stays with the account's administrators (so a
  # mistake can be fixed), every use is a CloudTrail event, and the setup identity (OzBoxKeyAdmin) is denied it on keys
  # tagged ozbox-production by infra/aws/key-admin-policy.json. The claim is therefore: only the release role decrypts, against
  # everyone without key-policy rights, and a change of the policy is recorded.
  statement {
    sid    = "PolicyChangesByAccountAdministratorsOnly"
    effect = "Allow"
    principals {
      type        = "AWS"
      identifiers = ["arn:aws:iam::${var.account_id}:root"]
    }
    actions   = ["kms:PutKeyPolicy"]
    resources = ["*"]
  }

  # A grant is a second way to hand out Decrypt: only an AWS service acting on a resource of the account may create one.
  statement {
    sid    = "GrantsOnlyForAwsServices"
    effect = "Allow"
    principals {
      type        = "AWS"
      identifiers = ["arn:aws:iam::${var.account_id}:root"]
    }
    actions   = ["kms:CreateGrant"]
    resources = ["*"]
    condition {
      test     = "Bool"
      variable = "kms:GrantIsForAWSResource"
      values   = ["true"]
    }
  }

  statement {
    sid    = "OnlyTheReleaseRoleDecrypts"
    effect = "Allow"
    principals {
      type        = "AWS"
      identifiers = [local.release_role_arn]
    }
    actions   = ["kms:Decrypt", "kms:DescribeKey"]
    resources = ["*"]
  }

  dynamic "statement" {
    for_each = length(var.operator_role_arns) > 0 ? [1] : []
    content {
      sid    = "OperatorWritesNeverReads"
      effect = "Allow"
      principals {
        type        = "AWS"
        identifiers = var.operator_role_arns
      }
      actions   = ["kms:Encrypt", "kms:GenerateDataKey", "kms:DescribeKey"]
      resources = ["*"]
    }
  }
}

resource "aws_kms_key" "production" {
  description             = "Oz Box Production secrets for fleet ${var.name}: only the issuer's release role decrypts"
  enable_key_rotation     = true
  deletion_window_in_days = 30
  policy                  = data.aws_iam_policy_document.key.json
  # the mark infra/aws/key-admin-policy.json denies key-policy changes and grants on
  tags = merge(local.tags, { "ozbox-production" = "true" })
}

resource "aws_kms_alias" "production" {
  name          = "alias/ozbox-${var.name}-production"
  target_key_id = aws_kms_key.production.key_id
}

# ---- The release role: the only principal that can read Production -------------------------------------------------------

data "aws_iam_policy_document" "release_trust" {
  statement {
    sid     = "OnlyTheIssuerAssumesIt"
    effect  = "Allow"
    actions = ["sts:AssumeRole"]
    principals {
      type        = "AWS"
      identifiers = [local.issuer_role_arn]
    }
  }
}

data "aws_iam_policy_document" "release" {
  statement {
    sid       = "ReadProductionSecrets"
    effect    = "Allow"
    actions   = ["secretsmanager:GetSecretValue"]
    resources = [local.secrets_arn]
  }
  statement {
    sid       = "DecryptWithTheProductionKey"
    effect    = "Allow"
    actions   = ["kms:Decrypt"]
    resources = [aws_kms_key.production.arn]
  }
}

resource "aws_iam_role" "release" {
  name               = local.release_role_name
  path               = local.role_path
  assume_role_policy = data.aws_iam_policy_document.release_trust.json
  # an assumed session lasts 900 seconds at most (the issuer's own permission says so); AWS allows a role no less than an hour
  max_session_duration = 3600
  tags                 = local.tags
}

resource "aws_iam_role_policy" "release" {
  name   = "read-production"
  role   = aws_iam_role.release.id
  policy = data.aws_iam_policy_document.release.json
}

# ---- The issuer's own role: it cannot read a secret or use the key ------------------------------------------------------

data "aws_iam_policy_document" "lambda_trust" {
  statement {
    sid     = "TheFunctionAssumesIt"
    effect  = "Allow"
    actions = ["sts:AssumeRole"]
    principals {
      type        = "Service"
      identifiers = ["lambda.amazonaws.com"]
    }
  }
}

data "aws_iam_policy_document" "issuer" {
  statement {
    sid       = "AssumeTheReleaseRoleForFifteenMinutesAtMost"
    effect    = "Allow"
    actions   = ["sts:AssumeRole"]
    resources = [local.release_role_arn]
    condition {
      test     = "NumericLessThanEquals"
      variable = "sts:DurationSeconds"
      values   = ["900"]
    }
  }
  statement {
    sid       = "KeepItsOwnState"
    effect    = "Allow"
    actions   = ["dynamodb:GetItem", "dynamodb:PutItem", "dynamodb:UpdateItem", "dynamodb:Query"]
    resources = [aws_dynamodb_table.state.arn]
  }
  statement {
    sid       = "ReadItsPinnedPublicKeys"
    effect    = "Allow"
    actions   = ["ssm:GetParameter"]
    resources = [local.config_param_arn]
  }
  statement {
    sid       = "WriteItsLog"
    effect    = "Allow"
    actions   = ["logs:CreateLogStream", "logs:PutLogEvents"]
    resources = ["${aws_cloudwatch_log_group.issuer.arn}:*"]
  }
  dynamic "statement" {
    for_each = var.audit_bucket_arn != "" ? [1] : []
    content {
      sid       = "AddToItsOwnRecordNeverRemove"
      effect    = "Allow"
      actions   = ["s3:PutObject"]
      resources = ["${var.audit_bucket_arn}/issuer/*"]
    }
  }
  # belt and braces: whatever else is ever attached, the issuer's own role cannot read Production or take its record back
  statement {
    sid    = "NeverReadProductionItself"
    effect = "Deny"
    actions = [
      "secretsmanager:GetSecretValue", "secretsmanager:BatchGetSecretValue", "kms:Decrypt",
      "s3:DeleteObject", "s3:DeleteObjectVersion", "s3:BypassGovernanceRetention", "s3:PutObjectRetention",
      "dynamodb:DeleteItem", "dynamodb:DeleteTable",
    ]
    resources = ["*"]
  }
}

resource "aws_iam_role" "issuer" {
  name               = local.issuer_role_name
  path               = local.role_path
  assume_role_policy = data.aws_iam_policy_document.lambda_trust.json
  tags               = local.tags
}

resource "aws_iam_role_policy" "issuer" {
  name   = "issue-and-release"
  role   = aws_iam_role.issuer.id
  policy = data.aws_iam_policy_document.issuer.json
}

# ---- Its state, its pinned public keys, its log, the function --------------------------------------------------------------

resource "aws_dynamodb_table" "state" {
  name         = local.table_name
  billing_mode = "PAY_PER_REQUEST"
  hash_key     = "pk"
  attribute {
    name = "pk"
    type = "S"
  }
  point_in_time_recovery {
    enabled = true
  }
  server_side_encryption {
    enabled = true
  }
  tags = local.tags
}

# The public halves of the approvers' keys, each box's pinned service key and store id, the dashboard's relying party. All of
# it public. The owner edits it through the CLI (phase 2); the module only makes room for it.
resource "aws_ssm_parameter" "config" {
  name        = local.config_param
  type        = "String"
  value       = "{}"
  description = "The issuer's pinned public keys (no secret)"
  tags        = local.tags
  lifecycle {
    ignore_changes = [value]
  }
}

resource "aws_cloudwatch_log_group" "issuer" {
  name              = "/aws/lambda/${local.function_name}"
  retention_in_days = var.log_retention_days
  tags              = local.tags
}

resource "aws_lambda_function" "issuer" {
  function_name    = local.function_name
  role             = aws_iam_role.issuer.arn
  runtime          = "provided.al2023"
  architectures    = ["arm64"]
  handler          = "bootstrap"
  filename         = var.package_path
  source_code_hash = var.package_sha256
  timeout          = 15
  memory_size      = 256
  # one at a time per key is not needed (the state's compare-and-set decides), but a runaway caller must not run up the bill
  reserved_concurrent_executions = 10
  environment {
    variables = {
      OZBOX_ISSUER_TABLE         = aws_dynamodb_table.state.name
      OZBOX_ISSUER_CONFIG_PARAM  = local.config_param
      OZBOX_ISSUER_RELEASE_ROLE  = local.release_role_arn
      OZBOX_ISSUER_AUDIT_BUCKET  = var.audit_bucket_arn
      OZBOX_ISSUER_SECRET_PREFIX = var.secret_name_prefix
    }
  }
  depends_on = [aws_cloudwatch_log_group.issuer]
  tags       = local.tags

  # The package that is uploaded is the package whose hash the person gave. `source_code_hash` alone only decides whether the
  # function changes; it does not check the file. The person's hash comes from the signed release or a reproducible build,
  # never from the file being deployed.
  lifecycle {
    precondition {
      condition     = filebase64sha256(var.package_path) == var.package_sha256
      error_message = "the package at package_path does not have the SHA-256 given as package_sha256. Nothing was changed."
    }
  }
}

# Reached with the caller's AWS signature, never anonymously.
resource "aws_lambda_function_url" "issuer" {
  function_name      = aws_lambda_function.issuer.function_name
  authorization_type = "AWS_IAM"
}

# What a box's instance role is given to ask the issuer: invoke it, and nothing else. Attach it to the box's role; it grants no
# read of a secret, the key, the state or the record.
data "aws_iam_policy_document" "invoke" {
  statement {
    sid       = "AskTheIssuer"
    effect    = "Allow"
    actions   = ["lambda:InvokeFunctionUrl"]
    resources = [local.function_arn]
    condition {
      test     = "StringEquals"
      variable = "lambda:FunctionUrlAuthType"
      values   = ["AWS_IAM"]
    }
    # only credentials of an EC2 instance's role carry the source instance; a person or a script that assumed a box role has none,
    # so only an instance acting as the box can ask
    condition {
      test     = "Null"
      variable = "ec2:SourceInstanceARN"
      values   = ["false"]
    }
  }
}

resource "aws_iam_policy" "invoke" {
  name        = "ozbox-${var.name}-issuer-invoke"
  description = "Lets a box ask the Production issuer for an approval and a release. Reads nothing."
  policy      = data.aws_iam_policy_document.invoke.json
  tags        = local.tags
}

resource "aws_iam_role_policy_attachment" "box_invoke" {
  for_each   = toset(var.box_role_arns)
  role       = element(split("/", each.value), length(split("/", each.value)) - 1)
  policy_arn = aws_iam_policy.invoke.arn
}
