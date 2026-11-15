# Runs with no credentials and no network: every provider is mocked.

mock_provider "aws" {
  mock_data "aws_iam_policy_document" {
    defaults = {
      json = "{\"Version\":\"2012-10-17\",\"Statement\":[]}"
    }
  }
}

run "the_policy_names_the_prefix_the_setup_identity_is_scoped_to" {
  command = plan

  assert {
    condition     = aws_iam_policy.session.name == "ozbox-box-session-manager"
    error_message = "the default name is the one the box module and the operator policy name"
  }
}

run "a_name_outside_the_prefix_is_refused" {
  command = plan

  variables {
    name = "something-else"
  }

  expect_failures = [var.name]
}

# The point of the module: Session Manager works, and nothing in it reads a parameter or a secret, decrypts, or reaches S3.
run "the_policy_lets_session_manager_work_and_reads_no_value" {
  command = plan

  assert {
    condition = alltrue([
      for a in flatten([for s in data.aws_iam_policy_document.session.statement : s.actions]) :
      !can(regex("(?i)^(ssm:(GetParameter|GetParameters|GetParametersByPath|DescribeParameters|ListTagsForResource)|secretsmanager:|kms:|s3:|iam:|sts:|\\*)", a))
    ])
    error_message = "the box's Session Manager policy must not read a parameter or secret, decrypt, reach S3, or use a wildcard action"
  }

  assert {
    condition = alltrue([
      for p in ["ssm:UpdateInstanceInformation", "ssmmessages:CreateDataChannel", "ssmmessages:OpenDataChannel", "ec2messages:GetMessages"] :
      contains(flatten([for s in data.aws_iam_policy_document.session.statement : s.actions]), p)
    ])
    error_message = "the agent needs these to register and to open a shell"
  }

  assert {
    condition = alltrue([
      for a in flatten([for s in data.aws_iam_policy_document.session.statement : s.actions]) :
      can(regex("^(ssm|ssmmessages|ec2messages):[A-Za-z]+$", a))
    ])
    error_message = "only Systems Manager's own services, each action named"
  }

  assert {
    condition     = alltrue([for s in data.aws_iam_policy_document.session.statement : s.effect == null || s.effect == "Allow"])
    error_message = "an allow-list"
  }
}

# The policies that replace what used to be inline role policies in the box module. Each reads the box's own tags, so one policy
# serves every box. A box reads the path its tags name (prefix and role), not a path of its own: two boxes tagged with the same
# prefix and role read the same values, and only the operator sets the tags.
run "the_parameters_policy_reads_only_the_tagged_path_under_the_root" {
  command = plan

  assert {
    condition = alltrue([
      for s in data.aws_iam_policy_document.parameters.statement :
      alltrue([for a in s.actions : startswith(a, "ssm:Get")]) &&
      alltrue([for r in s.resources : strcontains(r, "$${aws:PrincipalTag/ozbox-secrets-path}") && strcontains(r, "$${aws:PrincipalTag/ozbox-box-role}")])
    ])
    error_message = "only parameter reads, and only the path the role is tagged with (its prefix and its role)"
  }

  assert {
    condition = alltrue([
      for s in data.aws_iam_policy_document.parameters.statement :
      length(s.condition) == 1 && [for c in s.condition : c.variable][0] == "aws:PrincipalTag/ozbox-secrets-path" && [for c in s.condition : join(",", c.values)][0] == "/ozbox/*"
    ])
    error_message = "the tagged prefix must be under the parameter root, so another product's path cannot be named"
  }
}

run "the_fleet_key_policy_uses_the_key_only_for_the_tagged_box" {
  command = plan

  variables {
    fleet         = "fleet-a"
    fleet_key_arn = "arn:aws:kms:us-east-1:123456789012:key/00000000-0000-0000-0000-000000000000"
  }

  assert {
    condition = alltrue([
      for s in data.aws_iam_policy_document.fleet_key[0].statement :
      s.resources == toset(["arn:aws:kms:us-east-1:123456789012:key/00000000-0000-0000-0000-000000000000"]) &&
      s.actions == toset(["kms:Encrypt", "kms:Decrypt"]) &&
      length(s.condition) == 1 &&
      [for c in s.condition : c.variable][0] == "kms:EncryptionContext:scope" &&
      [for c in s.condition : join(",", c.values)][0] == "$${aws:PrincipalTag/ozbox-box}"
    ])
    error_message = "the fleet key: encrypt and decrypt for secrets whose encryption context names the role's own box, on that key only"
  }

  assert {
    condition     = aws_iam_policy.fleet_key[0].name == "ozbox-box-fleet-key-fleet-a"
    error_message = "named for the fleet, which is what the operator may attach"
  }
}

run "no_fleet_key_policy_without_a_key_and_no_session_log_policy_without_a_bucket" {
  command = plan

  assert {
    condition     = length(aws_iam_policy.fleet_key) == 0 && length(aws_iam_policy.session_logs) == 0 && length(aws_iam_policy.parameters_key) == 0
    error_message = "only what was asked for"
  }
}

run "the_parameters_key_policy_decrypts_only_through_parameter_store_and_the_session_log_policy_never_reads" {
  command = plan

  variables {
    box_secrets_kms_key_arn = "arn:aws:kms:us-east-1:123456789012:key/00000000-0000-0000-0000-000000000000"
    session_log_bucket      = "ozbox-sessionlogs-123456789012-us-east-1"
  }

  assert {
    condition = alltrue([
      for s in data.aws_iam_policy_document.parameters_key[0].statement :
      s.actions == toset(["kms:Decrypt"]) && [for c in s.condition : c.variable][0] == "kms:ViaService"
    ])
    error_message = "kms:Decrypt on the customer key only when called through Parameter Store"
  }

  assert {
    condition = alltrue([
      for s in data.aws_iam_policy_document.session_logs[0].statement :
      !anytrue([for a in s.actions : a == "s3:GetObject" || a == "s3:DeleteObject" || endswith(a, ":*")])
    ])
    error_message = "the box may write session logs but never read or delete them"
  }
}

# Gathered over every policy the module makes: no Secrets Manager, no wildcard action, every kms:Decrypt conditioned and on a
# named key.
run "across_every_policy_no_secrets_manager_no_wildcard_action_and_no_decrypt_outside_the_named_keys" {
  command = plan

  variables {
    fleet                   = "fleet-a"
    fleet_key_arn           = "arn:aws:kms:us-east-1:123456789012:key/11111111-1111-1111-1111-111111111111"
    box_secrets_kms_key_arn = "arn:aws:kms:us-east-1:123456789012:key/22222222-2222-2222-2222-222222222222"
    session_log_bucket      = "ozbox-sessionlogs-123456789012-us-east-1"
  }

  assert {
    condition = alltrue([
      for s in concat(
        data.aws_iam_policy_document.session.statement,
        data.aws_iam_policy_document.parameters.statement,
        data.aws_iam_policy_document.parameters_key[0].statement,
        data.aws_iam_policy_document.fleet_key[0].statement,
        data.aws_iam_policy_document.session_logs[0].statement,
      ) :
      !anytrue([for a in s.actions : startswith(a, "secretsmanager:") || a == "*" || endswith(a, ":*")]) &&
      (!contains(s.actions, "kms:Decrypt") || (length(s.condition) > 0 && !contains(s.resources, "*")))
    ])
    error_message = "no Secrets Manager, no wildcard action, and every kms:Decrypt is conditioned and on a named key"
  }
}
