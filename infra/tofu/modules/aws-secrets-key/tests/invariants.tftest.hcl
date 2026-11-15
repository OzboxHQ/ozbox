# Runs with no credentials and no network: every provider is mocked.

mock_provider "aws" {
  mock_data "aws_iam_policy_document" {
    defaults = {
      json = "{\"Version\":\"2012-10-17\",\"Statement\":[]}"
    }
  }
}

variables {
  name       = "fleet-a"
  account_id = "123456789012"
}

run "rotation_is_on_and_deletion_is_recoverable" {
  command = apply

  assert {
    condition     = aws_kms_key.secrets.enable_key_rotation == true
    error_message = "the secrets key must rotate"
  }

  assert {
    condition     = aws_kms_key.secrets.deletion_window_in_days >= 7
    error_message = "a deleted key must be recoverable for at least seven days"
  }

  assert {
    condition     = aws_kms_alias.secrets.name == "alias/ozbox-fleet-a-secrets"
    error_message = "the alias names the fleet"
  }
}

run "the_policy_never_lets_the_account_root_decrypt" {
  command = plan

  variables {
    operator_role_arns = ["arn:aws:iam::123456789012:role/operator"]
  }

  assert {
    condition     = length([for s in data.aws_iam_policy_document.key.statement : s if s.sid == "AdministerButNeverUse" && !contains(flatten([for a in s.actions : [a]]), "kms:Decrypt") && !contains(s.actions, "kms:*")]) == 1
    error_message = "the administrative statement must not carry Decrypt or kms:*"
  }

  assert {
    condition     = length([for s in data.aws_iam_policy_document.key.statement : s if s.sid == "FleetBoxesUseTheirOwnSecrets" && length(s.condition) == 2]) == 1
    error_message = "box access must be conditioned on the fleet tag and a role principal"
  }

  assert {
    condition     = length([for s in data.aws_iam_policy_document.key.statement : s if s.sid == "OperatorProvisionsAndRotates"]) == 1
    error_message = "the operator statement is present when roles are given"
  }
}

run "no_operator_statement_without_operator_roles" {
  command = plan

  assert {
    condition     = length([for s in data.aws_iam_policy_document.key.statement : s if s.sid == "OperatorProvisionsAndRotates"]) == 0
    error_message = "no operator roles, no operator statement"
  }
}

run "a_bad_account_id_is_refused" {
  command = plan

  variables {
    account_id = "not-an-account"
  }

  expect_failures = [var.account_id]
}

run "operator_roles_must_be_role_arns" {
  command = plan

  variables {
    operator_role_arns = ["arn:aws:iam::123456789012:user/someone"]
  }

  expect_failures = [var.operator_role_arns]
}
