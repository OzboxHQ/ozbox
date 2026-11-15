# Runs with no credentials and no network: every provider is mocked.

mock_provider "aws" {
  mock_data "aws_iam_policy_document" {
    defaults = {
      json = "{\"Version\":\"2012-10-17\",\"Statement\":[]}"
    }
  }
}

variables {
  account_id = "123456789012"
  region     = "us-east-1"
}

run "everything_is_off_by_default" {
  command = apply

  assert {
    condition     = length(aws_guardduty_detector.this) == 0 && length(aws_guardduty_detector_feature.runtime) == 0
    error_message = "no GuardDuty unless asked for"
  }

  assert {
    condition     = length(aws_s3_bucket.session_logs) == 0 && length(aws_ssm_document.session_preferences) == 0
    error_message = "no bucket and no change to Session Manager unless asked for"
  }

  assert {
    condition     = length(aws_ssm_patch_baseline.ubuntu) == 0 && length(aws_ssm_maintenance_window.patch) == 0
    error_message = "no patching unless asked for"
  }

  assert {
    condition     = output.session_log_bucket == null && output.patch_group == null && output.guardduty_detector_id == null
    error_message = "the outputs say nothing is on"
  }
}

run "guardduty_runtime_monitoring_installs_its_agent_through_systems_manager" {
  command = apply

  variables {
    enable_guardduty_runtime = true
  }

  assert {
    condition     = length(aws_guardduty_detector.this) == 1 && aws_guardduty_detector_feature.runtime[0].name == "RUNTIME_MONITORING" && aws_guardduty_detector_feature.runtime[0].status == "ENABLED"
    error_message = "Runtime Monitoring is turned on with a detector of our own"
  }

  assert {
    condition     = length([for c in aws_guardduty_detector_feature.runtime[0].additional_configuration : c if c.name == "EC2_AGENT_MANAGEMENT" && c.status == "ENABLED"]) == 1
    error_message = "GuardDuty manages the agent"
  }
}

run "an_existing_detector_is_used_and_never_created_or_owned" {
  command = apply

  variables {
    enable_guardduty_runtime       = true
    existing_guardduty_detector_id = "12abc34d567e8fa901bc2d34e56789f0"
  }

  assert {
    condition     = length(aws_guardduty_detector.this) == 0 && aws_guardduty_detector_feature.runtime[0].detector_id == "12abc34d567e8fa901bc2d34e56789f0"
    error_message = "the module only turns the feature on in the detector that is there"
  }
}

run "the_session_log_bucket_is_locked_versioned_encrypted_private_and_tls_only" {
  command = apply

  variables {
    enable_session_logs = true
  }

  assert {
    condition     = aws_s3_bucket.session_logs[0].bucket == "ozbox-sessionlogs-123456789012-us-east-1" && aws_s3_bucket.session_logs[0].object_lock_enabled == true
    error_message = "object lock is set when the bucket is made (it cannot be added later)"
  }

  assert {
    condition     = aws_s3_bucket_versioning.session_logs[0].versioning_configuration[0].status == "Enabled"
    error_message = "object lock needs versioning"
  }

  assert {
    condition     = one(aws_s3_bucket_object_lock_configuration.session_logs[0].rule).default_retention[0].mode == "GOVERNANCE" && one(aws_s3_bucket_object_lock_configuration.session_logs[0].rule).default_retention[0].days == 365
    error_message = "the default is governance mode, a year: the irreversible mode is a deliberate choice"
  }

  assert {
    condition     = aws_s3_bucket_public_access_block.session_logs[0].block_public_acls && aws_s3_bucket_public_access_block.session_logs[0].restrict_public_buckets
    error_message = "the bucket is private"
  }

  assert {
    condition     = length([for s in data.aws_iam_policy_document.session_logs[0].statement : s if s.sid == "TlsOnly" && s.effect == "Deny"]) == 1 && length([for s in data.aws_iam_policy_document.session_logs[0].statement : s if s.sid == "NoOneBypassesTheLockOrDeletesAVersion" && contains(s.actions, "s3:BypassGovernanceRetention")]) == 1
    error_message = "TLS only, and nobody bypasses the lock or deletes a version"
  }

  # Whoever holds the security-services policy must not be able to swap this policy for one that lets it bypass the lock.
  assert {
    condition     = length([for s in data.aws_iam_policy_document.session_logs[0].statement : s if s.effect == "Deny" && one(s.principals).identifiers == toset(["*"]) && length(setsubtract(["s3:BypassGovernanceRetention", "s3:DeleteObjectVersion", "s3:PutBucketObjectLockConfiguration", "s3:PutBucketVersioning", "s3:PutBucketPolicy", "s3:DeleteBucketPolicy"], s.actions)) == 0 && length(s.condition) == 0]) == 1
    error_message = "the bucket policy must deny, to everyone and without condition, bypassing the lock, deleting a version, changing the lock or versioning, and replacing or deleting the policy itself"
  }

  # The policy a person attaches to opt in grants nothing that could unlock a log, and denies it outright.
  assert {
    condition     = alltrue([for st in jsondecode(file("${path.module}/../../../aws/security-services-policy.json")).Statement : st.Effect != "Allow" || length(setintersection(toset(flatten([st.Action])), toset(["s3:BypassGovernanceRetention", "s3:DeleteObjectVersion", "s3:DeleteBucketPolicy", "s3:DeleteBucket", "s3:PutObjectRetention", "s3:PutObjectLegalHold", "s3:*"]))) == 0])
    error_message = "the security-services policy must not allow anything that removes, unlocks or shortens a session log"
  }

  assert {
    condition     = length([for st in jsondecode(file("${path.module}/../../../aws/security-services-policy.json")).Statement : st if st.Effect == "Deny" && length(setsubtract(["s3:BypassGovernanceRetention", "s3:DeleteObjectVersion", "s3:DeleteBucketPolicy"], flatten([st.Action]))) == 0]) == 1
    error_message = "the security-services policy must also deny bypassing the lock, deleting a version and deleting the bucket policy itself"
  }

  assert {
    condition     = length(aws_ssm_document.session_preferences) == 1 && aws_ssm_document.session_preferences[0].name == "SSM-SessionManagerRunShell" && strcontains(aws_ssm_document.session_preferences[0].content, "ozbox/sessions") && strcontains(aws_ssm_document.session_preferences[0].content, "\"s3EncryptionEnabled\":true")
    error_message = "Session Manager is told to log shell sessions to the bucket, encrypted"
  }
}

run "compliance_mode_and_the_account_preferences_are_choices" {
  command = apply

  variables {
    enable_session_logs        = true
    session_log_retention_mode = "COMPLIANCE"
    session_log_retention_days = 2190
    manage_session_preferences = false
  }

  assert {
    condition     = one(aws_s3_bucket_object_lock_configuration.session_logs[0].rule).default_retention[0].mode == "COMPLIANCE" && one(aws_s3_bucket_object_lock_configuration.session_logs[0].rule).default_retention[0].days == 2190
    error_message = "compliance mode and a six-year retention are possible"
  }

  assert {
    condition     = length(aws_ssm_document.session_preferences) == 0
    error_message = "the account's Session Manager preferences are left alone when asked"
  }
}

run "a_bad_retention_is_refused" {
  command = plan

  variables {
    enable_session_logs        = true
    session_log_retention_mode = "SOMETIMES"
  }

  expect_failures = [var.session_log_retention_mode]
}

run "patching_installs_weekly_and_never_restarts_and_skips_a_box_in_use" {
  command = apply

  variables {
    enable_patching = true
  }

  assert {
    condition     = aws_ssm_patch_baseline.ubuntu[0].operating_system == "UBUNTU" && aws_ssm_patch_group.ozbox[0].patch_group == "ozbox"
    error_message = "an Ubuntu baseline for the ozbox patch group"
  }

  assert {
    condition     = one(aws_ssm_maintenance_window_target.boxes[0].targets).key == "tag:Patch Group" && contains(one(aws_ssm_maintenance_window_target.boxes[0].targets).values, "ozbox")
    error_message = "the window reaches boxes by the Patch Group tag"
  }

  assert {
    condition     = aws_ssm_maintenance_window_task.install[0].task_arn == "AWS-RunPatchBaseline" && length([for p in one(one(aws_ssm_maintenance_window_task.install[0].task_invocation_parameters).run_command_parameters).parameter : p if p.name == "RebootOption" && p.values == tolist(["NoReboot"])]) == 1
    error_message = "the task never restarts a box"
  }

  assert {
    condition     = length([for p in one(one(aws_ssm_maintenance_window_task.install[0].task_invocation_parameters).run_command_parameters).parameter : p if p.name == "PreInstallHookDocName" && p.values == tolist(["ozbox-patch-precheck"])]) == 1 && strcontains(aws_ssm_document.patch_precheck[0].content, "host-guard patch check")
    error_message = "the window asks the box whether it is in use first"
  }

  assert {
    condition     = output.patch_group == "ozbox"
    error_message = "the patch group is an output for the box module"
  }
}

run "every_resource_that_can_be_tagged_carries_the_managed_tag" {
  command = apply

  variables {
    enable_guardduty_runtime = true
    enable_session_logs      = true
    enable_patching          = true
  }

  assert {
    condition     = aws_guardduty_detector.this[0].tags["ozbox-managed"] == "true" && aws_s3_bucket.session_logs[0].tags["ozbox-managed"] == "true" && aws_ssm_patch_baseline.ubuntu[0].tags["ozbox-managed"] == "true" && aws_ssm_maintenance_window.patch[0].tags["ozbox-managed"] == "true"
    error_message = "everything is tagged ozbox-managed"
  }
}
