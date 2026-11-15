# Creation-time options. Its own file, so it starts from an empty state: a volume that exists already ignores a changed
# snapshot or key (see the lifecycle block), which is exactly what the upgrade tests rely on.

# Runs with no credentials and no network: every provider is mocked.

mock_provider "aws" {
  mock_data "aws_subnet" {
    defaults = {
      vpc_id            = "vpc-0123456789abcdef0"
      availability_zone = "us-east-1a"
    }
  }
  mock_data "aws_caller_identity" {
    defaults = {
      account_id = "123456789012"
    }
  }
  mock_data "aws_iam_policy_document" {
    defaults = {
      json = "{\"Version\":\"2012-10-17\",\"Statement\":[]}"
    }
  }
}

variables {
  box_name     = "dev-1"
  machine_type = "m7i.4xlarge"
  work_disk_gb = 200
  image_id     = "ami-0123456789abcdef0"
  region       = "us-east-1"
  subnet_id    = "subnet-0123456789abcdef0"
  labels       = { team = "example" }
}

run "kms_key_and_snapshot_are_optional" {
  command = apply

  variables {
    kms_key_arn      = "arn:aws:kms:us-east-1:123456789012:key/00000000-0000-0000-0000-000000000000"
    work_snapshot_id = "snap-0123456789abcdef0"
  }

  assert {
    condition     = aws_ebs_volume.work.snapshot_id == "snap-0123456789abcdef0"
    error_message = "a clone must restore /work from the snapshot"
  }

  assert {
    condition     = aws_ebs_volume.work.kms_key_id == "arn:aws:kms:us-east-1:123456789012:key/00000000-0000-0000-0000-000000000000"
    error_message = "the given KMS key must be used for /work"
  }
}

run "the_secrets_key_is_optional_and_scoped_to_this_box" {
  command = apply

  variables {
    secrets_key_arn = "arn:aws:kms:us-east-1:123456789012:key/00000000-0000-0000-0000-000000000000"
    fleet           = "fleet-a"
  }

  assert {
    condition     = length(aws_iam_role_policy_attachment.fleet_key) == 1 && aws_iam_role.box.tags["ozbox-fleet"] == "fleet-a"
    error_message = "a box given the fleet key attaches the account's fleet-key policy and carries the fleet tag"
  }

  assert {
    condition     = endswith(aws_iam_role_policy_attachment.fleet_key[0].policy_arn, ":policy/ozbox-box-fleet-key-fleet-a")
    error_message = "the policy is the account's own, named for the fleet; the box's tag (ozbox-box) is what scopes it to this box"
  }

  assert {
    condition     = aws_iam_role.box.tags["ozbox-box"] == var.box_name
    error_message = "the fleet-key policy reads the role's ozbox-box tag as the encryption context"
  }
}

run "without_a_secrets_key_nothing_extra_is_attached" {
  command = apply

  assert {
    condition     = length(aws_iam_role_policy_attachment.fleet_key) == 0 && !contains(keys(aws_iam_role.box.tags), "ozbox-fleet")
    error_message = "no key, no policy, no fleet tag"
  }
}

run "a_box_that_declares_secrets_gets_tags_and_the_parameters_policy_for_its_own_path" {
  command = apply

  variables {
    box_secrets_backend = "aws-ssm"
    box_secrets_prefix  = "/ozbox/dev"
    box_role            = "main"
  }

  assert {
    condition = (
      aws_instance.box.tags["ozbox-secrets-backend"] == "aws-ssm" &&
      aws_instance.box.tags["ozbox-secrets-path"] == "/ozbox/dev" &&
      aws_instance.box.tags["ozbox-box-role"] == "main"
    )
    error_message = "the declaration is written as instance tags, which is where the box reads it"
  }

  # the account's parameters policy reads the ROLE's tags: the one path this box may read
  assert {
    condition = (
      aws_iam_role.box.tags["ozbox-secrets-path"] == "/ozbox/dev" &&
      aws_iam_role.box.tags["ozbox-box-role"] == "main" &&
      length(aws_iam_role_policy_attachment.parameters) == 1 &&
      endswith(aws_iam_role_policy_attachment.parameters[0].policy_arn, ":policy/ozbox-box-parameters")
    )
    error_message = "the role is tagged with its prefix and role and attaches the parameters policy"
  }

  assert {
    condition     = aws_instance.box.metadata_options[0].instance_metadata_tags == "enabled"
    error_message = "the box reads its tags from the metadata service"
  }

  assert {
    condition     = !contains(keys(aws_instance.box.tags), "ozbox-secrets-key")
    error_message = "no secret value or key appears in a tag"
  }
}

run "a_customer_key_for_the_parameters_is_one_more_attachment_and_only_with_aws_ssm" {
  command = apply

  variables {
    box_secrets_backend     = "aws-ssm"
    box_secrets_prefix      = "/ozbox/dev"
    box_role                = "main"
    box_secrets_kms_key_arn = "arn:aws:kms:us-east-1:123456789012:key/00000000-0000-0000-0000-000000000000"
  }

  assert {
    condition     = length(aws_iam_role_policy_attachment.parameters_key) == 1 && endswith(aws_iam_role_policy_attachment.parameters_key[0].policy_arn, ":policy/ozbox-box-parameters-key")
    error_message = "the customer key is usable through the account's parameters-key policy (Parameter Store only)"
  }
}

run "an_openbao_box_is_tagged_and_gets_no_aws_read_policy" {
  command = apply

  variables {
    box_secrets_backend = "openbao"
    box_secrets_prefix  = "/ozbox/dev"
    box_role            = "main"
  }

  assert {
    condition     = length(aws_iam_role_policy_attachment.parameters) == 0 && aws_instance.box.tags["ozbox-secrets-backend"] == "openbao" && !contains(keys(aws_iam_role.box.tags), "ozbox-box-role")
    error_message = "OpenBao is reached with its own token, so no AWS permission is granted and the role carries no path tag"
  }
}

run "without_a_declaration_there_are_no_tags_and_no_policy" {
  command = apply

  assert {
    condition     = length(aws_iam_role_policy_attachment.parameters) == 0 && !contains(keys(aws_instance.box.tags), "ozbox-secrets-backend") && !contains(keys(aws_instance.box.tags), "ozbox-box-role")
    error_message = "a box that declares nothing is unchanged"
  }
}

run "a_backend_needs_its_prefix_and_role" {
  command = plan

  variables {
    box_secrets_backend = "aws-ssm"
  }

  # the instance now waits for the attachment (depends_on), so the attachment is where this fails first
  expect_failures = [aws_iam_role_policy_attachment.parameters]
}

run "a_prefix_that_could_widen_the_grant_is_refused" {
  command = plan

  variables {
    box_secrets_backend = "aws-ssm"
    box_secrets_prefix  = "/ozbox/../other"
    box_role            = "main"
  }

  expect_failures = [var.box_secrets_prefix]
}

run "a_prefix_outside_the_parameter_root_is_refused_so_another_path_outside_the_root_cannot_be_named" {
  command = plan

  variables {
    box_secrets_backend = "aws-ssm"
    box_secrets_prefix  = "/otherproduct/app"
    box_role            = "main"
  }

  expect_failures = [aws_iam_role_policy_attachment.parameters]
}

run "session_logs_and_patching_are_off_unless_asked_for" {
  command = apply

  assert {
    condition     = length(aws_iam_role_policy_attachment.session_logs) == 0
    error_message = "no session-log permission without a bucket"
  }

  assert {
    condition     = !contains(keys(aws_instance.box.tags), "Patch Group")
    error_message = "no patch group tag unless one is given"
  }
}

run "a_session_log_bucket_attaches_the_session_logs_policy" {
  command = apply

  variables {
    session_log_bucket = "ozbox-sessionlogs-123456789012-us-east-1"
    patch_group        = "ozbox"
  }

  assert {
    condition     = length(aws_iam_role_policy_attachment.session_logs) == 1 && endswith(aws_iam_role_policy_attachment.session_logs[0].policy_arn, ":policy/ozbox-box-session-logs")
    error_message = "the role attaches the account's session-logs policy (write one prefix, read nothing)"
  }

  assert {
    condition     = aws_instance.box.tags["Patch Group"] == "ozbox"
    error_message = "the box carries the patch group tag"
  }
}

run "a_bad_session_log_bucket_name_is_refused" {
  command = plan

  variables {
    session_log_bucket = "Not A Bucket"
  }

  expect_failures = [var.session_log_bucket]
}

# The operator role is denied iam:PutRolePolicy on purpose, and the plan of an upgrade must be able to finish: this module has
# no inline role policy, so it needs no IAM action the operator cannot do. The only IAM resources it applies are the role, the
# instance profile and ATTACHMENTS of policies `ozbox init` made (the operator may attach exactly those).
run "the_module_plans_no_inline_role_policy_with_every_option_on" {
  command = plan

  variables {
    secrets_key_arn         = "arn:aws:kms:us-east-1:123456789012:key/11111111-1111-1111-1111-111111111111"
    fleet                   = "fleet-a"
    box_secrets_backend     = "aws-ssm"
    box_secrets_prefix      = "/ozbox/dev"
    box_role                = "main"
    box_secrets_kms_key_arn = "arn:aws:kms:us-east-1:123456789012:key/22222222-2222-2222-2222-222222222222"
    session_log_bucket      = "ozbox-sessionlogs-123456789012-us-east-1"
  }

  # the attachments the box makes are exactly these, each one of the account's own ozbox-box-* policies
  assert {
    condition = alltrue([
      for a in concat(
        [aws_iam_role_policy_attachment.ssm_core],
        aws_iam_role_policy_attachment.fleet_key,
        aws_iam_role_policy_attachment.parameters,
        aws_iam_role_policy_attachment.parameters_key,
        aws_iam_role_policy_attachment.session_logs,
      ) : can(regex("^arn:aws:iam::[0-9]{12}:policy/ozbox-box-", a.policy_arn))
    ])
    error_message = "every policy a box's role carries is one of the account's own ozbox-box-* policies, never an AWS-managed one"
  }
}

# The instance's own precondition (aws-box/main.tf, aws_instance.box): the attachment's precondition does not apply to a
# backend that attaches nothing (OpenBao), so only the instance refuses a backend with no prefix or role.
run "an_instance_refuses_a_backend_with_no_prefix_even_when_no_policy_is_attached" {
  command = plan

  variables {
    box_secrets_backend = "openbao"
  }

  expect_failures = [aws_instance.box]
}
