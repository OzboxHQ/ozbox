# Opt-in security services for an AWS account that runs Oz Boxes: GuardDuty Runtime Monitoring, a tamper-resistant bucket for
# Session Manager logs, and Patch Manager. Every part is off by default and independent of the others. Nothing here touches a
# box directly: boxes join through variables of the aws-box module (session_log_bucket, patch_group).
#
# What each costs is AWS's own billing, stated in docs/adr/0035: GuardDuty Runtime Monitoring bills per vCPU of monitored
# instances (and an interface endpoint per monitored VPC bills by the hour); the bucket bills for what is stored, locked for the
# whole retention; Patch Manager and maintenance windows have no charge of their own.

locals {
  tags = merge(var.labels, { "ozbox-managed" = "true" })

  bucket = "ozbox-sessionlogs-${var.account_id}-${var.region}"
}

# ---------- GuardDuty Runtime Monitoring ----------

resource "aws_guardduty_detector" "this" {
  count  = var.enable_guardduty_runtime && var.existing_guardduty_detector_id == null ? 1 : 0
  enable = true
  tags   = local.tags
}

locals {
  detector_id = var.existing_guardduty_detector_id != null ? var.existing_guardduty_detector_id : (var.enable_guardduty_runtime ? aws_guardduty_detector.this[0].id : null)
}

resource "aws_guardduty_detector_feature" "runtime" {
  count       = var.enable_guardduty_runtime ? 1 : 0
  detector_id = local.detector_id
  name        = "RUNTIME_MONITORING"
  status      = "ENABLED"

  # GuardDuty installs and updates its agent on the box through Systems Manager (which every box already uses).
  additional_configuration {
    name   = "EC2_AGENT_MANAGEMENT"
    status = "ENABLED"
  }
}

# ---------- the session-log bucket ----------

resource "aws_s3_bucket" "session_logs" {
  count               = var.enable_session_logs ? 1 : 0
  bucket              = local.bucket
  object_lock_enabled = true
  tags                = merge(local.tags, { "ozbox-role" = "session-logs" })
}

resource "aws_s3_bucket_versioning" "session_logs" {
  count  = var.enable_session_logs ? 1 : 0
  bucket = aws_s3_bucket.session_logs[0].id

  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_s3_bucket_object_lock_configuration" "session_logs" {
  count  = var.enable_session_logs ? 1 : 0
  bucket = aws_s3_bucket.session_logs[0].id

  rule {
    default_retention {
      mode = var.session_log_retention_mode
      days = var.session_log_retention_days
    }
  }

  depends_on = [aws_s3_bucket_versioning.session_logs]
}

resource "aws_s3_bucket_server_side_encryption_configuration" "session_logs" {
  count  = var.enable_session_logs ? 1 : 0
  bucket = aws_s3_bucket.session_logs[0].id

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "AES256"
    }
  }
}

resource "aws_s3_bucket_public_access_block" "session_logs" {
  count                   = var.enable_session_logs ? 1 : 0
  bucket                  = aws_s3_bucket.session_logs[0].id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_lifecycle_configuration" "session_logs" {
  count  = var.enable_session_logs ? 1 : 0
  bucket = aws_s3_bucket.session_logs[0].id

  rule {
    id     = "expire-after-the-lock"
    status = "Enabled"
    filter {}

    expiration {
      days = var.session_log_retention_days + 1
    }

    noncurrent_version_expiration {
      noncurrent_days = var.session_log_retention_days + 1
    }

    abort_incomplete_multipart_upload {
      days_after_initiation = 7
    }
  }

  depends_on = [aws_s3_bucket_versioning.session_logs]
}

# Nothing reaches the bucket except over TLS, and nothing may delete a log version, turn the lock off, or replace or remove
# this policy. A bucket policy's Deny binds every principal of the account except its root user, so once this is on, the
# only way to loosen it is the account's root user: whoever holds the security-services policy (or any other) cannot write
# a new bucket policy that grants itself BypassGovernanceRetention.
data "aws_iam_policy_document" "session_logs" {
  count = var.enable_session_logs ? 1 : 0

  statement {
    sid     = "TlsOnly"
    effect  = "Deny"
    actions = ["s3:*"]
    resources = [
      aws_s3_bucket.session_logs[0].arn,
      "${aws_s3_bucket.session_logs[0].arn}/*",
    ]
    principals {
      type        = "*"
      identifiers = ["*"]
    }
    condition {
      test     = "Bool"
      variable = "aws:SecureTransport"
      values   = ["false"]
    }
  }

  statement {
    sid    = "NoOneBypassesTheLockOrDeletesAVersion"
    effect = "Deny"
    actions = [
      "s3:BypassGovernanceRetention",
      "s3:DeleteObjectVersion",
      "s3:PutBucketObjectLockConfiguration",
      "s3:PutBucketVersioning",
      "s3:PutBucketPolicy",
      "s3:DeleteBucketPolicy",
    ]
    resources = [
      aws_s3_bucket.session_logs[0].arn,
      "${aws_s3_bucket.session_logs[0].arn}/*",
    ]
    principals {
      type        = "*"
      identifiers = ["*"]
    }
  }
}

resource "aws_s3_bucket_policy" "session_logs" {
  count  = var.enable_session_logs ? 1 : 0
  bucket = aws_s3_bucket.session_logs[0].id
  policy = data.aws_iam_policy_document.session_logs[0].json

  # The policy forbids changing the lock, versioning and itself afterwards, so it goes on last. A later change to this
  # document fails by design (only the account's root user can replace it).
  depends_on = [
    aws_s3_bucket_public_access_block.session_logs,
    aws_s3_bucket_object_lock_configuration.session_logs,
    aws_s3_bucket_versioning.session_logs,
    aws_s3_bucket_server_side_encryption_configuration.session_logs,
    aws_s3_bucket_lifecycle_configuration.session_logs,
  ]
}

# Session Manager's preferences: shell sessions are written to the bucket. One document per account and region.
resource "aws_ssm_document" "session_preferences" {
  count           = var.enable_session_logs && var.manage_session_preferences ? 1 : 0
  name            = "SSM-SessionManagerRunShell"
  document_type   = "Session"
  document_format = "JSON"
  tags            = local.tags

  content = jsonencode({
    schemaVersion = "1.0"
    description   = "Session Manager preferences, set by Oz Box: shell sessions are logged to a locked bucket."
    sessionType   = "Standard_Stream"
    inputs = {
      s3BucketName                = aws_s3_bucket.session_logs[0].id
      s3KeyPrefix                 = "ozbox/sessions"
      s3EncryptionEnabled         = true
      cloudWatchLogGroupName      = ""
      cloudWatchEncryptionEnabled = false
      cloudWatchStreamingEnabled  = false
      idleSessionTimeout          = "20"
      maxSessionDuration          = ""
      runAsEnabled                = false
      runAsDefaultUser            = ""
      shellProfile = {
        linux   = ""
        windows = ""
      }
    }
  })

  depends_on = [aws_s3_bucket_policy.session_logs]
}

# ---------- Patch Manager ----------

resource "aws_ssm_patch_baseline" "ubuntu" {
  count            = var.enable_patching ? 1 : 0
  name             = "ozbox-ubuntu"
  description      = "Ubuntu patches for Oz Boxes, approved after a delay. Installing never restarts a box."
  operating_system = "UBUNTU"
  tags             = local.tags

  approval_rule {
    approve_after_days = var.patch_approve_after_days
    compliance_level   = "HIGH"

    patch_filter {
      key    = "PRIORITY"
      values = ["Required", "Important", "Standard"]
    }
    patch_filter {
      key    = "PRODUCT"
      values = ["*"]
    }
  }
}

resource "aws_ssm_patch_group" "ozbox" {
  count       = var.enable_patching ? 1 : 0
  baseline_id = aws_ssm_patch_baseline.ubuntu[0].id
  patch_group = var.patch_group
}

# Before installing, the box is asked whether it is in use (an agent run, a login, a hold file). If it is, the window skips it
# and tries again next week. The check is the box's own program; it changes nothing.
resource "aws_ssm_document" "patch_precheck" {
  count           = var.enable_patching ? 1 : 0
  name            = "ozbox-patch-precheck"
  document_type   = "Command"
  document_format = "JSON"
  tags            = local.tags

  content = jsonencode({
    schemaVersion = "2.2"
    description   = "Fails when the box is in use, so the patch window skips it."
    mainSteps = [{
      action = "aws:runShellScript"
      name   = "precheck"
      inputs = { runCommand = ["/usr/local/bin/ozbox host-guard patch check"] }
    }]
  })
}

resource "aws_ssm_maintenance_window" "patch" {
  count             = var.enable_patching ? 1 : 0
  name              = "ozbox-patch"
  description       = "Weekly patching for Oz Boxes. Installs; never restarts."
  schedule          = var.patch_schedule
  schedule_timezone = var.patch_schedule_timezone
  duration          = 3
  cutoff            = 1
  tags              = local.tags
}

resource "aws_ssm_maintenance_window_target" "boxes" {
  count         = var.enable_patching ? 1 : 0
  window_id     = aws_ssm_maintenance_window.patch[0].id
  name          = "ozbox-boxes"
  resource_type = "INSTANCE"

  targets {
    key    = "tag:Patch Group"
    values = [var.patch_group]
  }
}

resource "aws_ssm_maintenance_window_task" "install" {
  count           = var.enable_patching ? 1 : 0
  window_id       = aws_ssm_maintenance_window.patch[0].id
  name            = "install-patches"
  task_type       = "RUN_COMMAND"
  task_arn        = "AWS-RunPatchBaseline"
  priority        = 1
  max_concurrency = "2"
  max_errors      = "1"

  targets {
    key    = "WindowTargetIds"
    values = [aws_ssm_maintenance_window_target.boxes[0].id]
  }

  task_invocation_parameters {
    run_command_parameters {
      timeout_seconds = 3600

      parameter {
        name   = "Operation"
        values = ["Install"]
      }
      # The owner's restart rule is the only thing that restarts a box (see `ozbox box-patch`).
      parameter {
        name   = "RebootOption"
        values = ["NoReboot"]
      }
      parameter {
        name   = "PreInstallHookDocName"
        values = [aws_ssm_document.patch_precheck[0].name]
      }
    }
  }
}
