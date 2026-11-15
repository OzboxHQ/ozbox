# Runs with no credentials and no network: every provider is mocked. These pin who can read Production and who cannot.

mock_provider "aws" {
  mock_data "aws_iam_policy_document" {
    defaults = {
      json = "{\"Version\":\"2012-10-17\",\"Statement\":[]}"
    }
  }
  mock_resource "aws_iam_role" {
    defaults = { arn = "arn:aws:iam::123456789012:role/mock" }
  }
  mock_resource "aws_iam_policy" {
    defaults = { arn = "arn:aws:iam::123456789012:policy/mock" }
  }
  mock_resource "aws_kms_key" {
    defaults = { arn = "arn:aws:kms:us-east-1:123456789012:key/00000000-0000-0000-0000-000000000000" }
  }
  mock_resource "aws_dynamodb_table" {
    defaults = { arn = "arn:aws:dynamodb:us-east-1:123456789012:table/mock" }
  }
  mock_resource "aws_cloudwatch_log_group" {
    defaults = { arn = "arn:aws:logs:us-east-1:123456789012:log-group:/aws/lambda/mock" }
  }
  mock_resource "aws_lambda_function" {
    defaults = { arn = "arn:aws:lambda:us-east-1:123456789012:function:mock" }
  }
}

variables {
  name           = "fleet-a"
  account_id     = "123456789012"
  region         = "us-east-1"
  package_path   = "tests/package.zip"
  package_sha256 = "8W0F7GspJI0sYa2x6SY/eOT3us4blVAUotF4cs/kBk0="
}

run "the_issuers_own_role_can_neither_read_a_secret_nor_use_the_key" {
  command = plan

  # no allow statement names a secret read, a decrypt, a wildcard action or a wildcard resource
  assert {
    condition = length([
      for s in data.aws_iam_policy_document.issuer.statement : s
      if s.effect == "Allow" && (
        length([for a in s.actions : a if startswith(a, "secretsmanager:") || startswith(a, "kms:") || a == "*" || endswith(a, ":*")]) > 0
        || contains(s.resources, "*")
      )
    ]) == 0
    error_message = "the issuer's own role must not be allowed any secret, key or wildcard access"
  }

  assert {
    condition = length([
      for s in data.aws_iam_policy_document.issuer.statement : s
      if s.sid == "NeverReadProductionItself" && s.effect == "Deny"
      && contains(s.actions, "secretsmanager:GetSecretValue") && contains(s.actions, "kms:Decrypt")
      && contains(s.actions, "s3:DeleteObjectVersion") && contains(s.actions, "s3:BypassGovernanceRetention")
    ]) == 1
    error_message = "an explicit deny must keep the issuer's own role from reading Production or removing its record"
  }
}

run "it_assumes_only_the_release_role_for_fifteen_minutes_at_most" {
  command = plan

  assert {
    condition = length([
      for s in data.aws_iam_policy_document.issuer.statement : s
      if contains(s.actions, "sts:AssumeRole")
    ]) == 1
    error_message = "the issuer has exactly one way to assume a role"
  }

  assert {
    condition = length([
      for s in data.aws_iam_policy_document.issuer.statement : s
      if contains(s.actions, "sts:AssumeRole") && length(s.resources) == 1 && contains(s.resources, "arn:aws:iam::123456789012:role/obx/obx-fleet-a-issuer-release")
    ]) == 1
    error_message = "the assume must name the release role alone"
  }

  assert {
    condition = length([
      for s in data.aws_iam_policy_document.issuer.statement : s
      if contains(s.actions, "sts:AssumeRole") && length(s.condition) == 1
    ]) == 1
    error_message = "the assume must carry exactly one condition"
  }

  assert {
    condition = length([
      for s in data.aws_iam_policy_document.issuer.statement : s
      if contains(s.actions, "sts:AssumeRole")
      && length([for c in s.condition : c if c.variable == "sts:DurationSeconds" && c.test == "NumericLessThanEquals" && length(c.values) == 1 && contains(c.values, "900")]) == 1
    ]) == 1
    error_message = "the assume must be capped at 900 seconds"
  }
}

run "only_the_issuer_assumes_the_release_role_and_it_reads_only_production_names" {
  command = plan

  assert {
    condition = (
      length(data.aws_iam_policy_document.release_trust.statement) == 1
      && one(data.aws_iam_policy_document.release_trust.statement).actions == toset(["sts:AssumeRole"])
      && length(one(data.aws_iam_policy_document.release_trust.statement).principals) == 1
      && one(one(data.aws_iam_policy_document.release_trust.statement).principals).identifiers == toset(["arn:aws:iam::123456789012:role/obx/obx-fleet-a-issuer"])
    )
    error_message = "the release role must trust the issuer's role and no one else"
  }

  assert {
    condition = length([
      for s in data.aws_iam_policy_document.release.statement : s
      if s.sid == "ReadProductionSecrets" && s.resources == toset(["arn:aws:secretsmanager:us-east-1:123456789012:secret:ozbox/production/*"])
      && s.actions == toset(["secretsmanager:GetSecretValue"])
    ]) == 1
    error_message = "the release role reads secrets under the Production prefix only"
  }

  assert {
    condition     = aws_iam_role.release.max_session_duration == 3600
    error_message = "AWS allows a role no less than an hour; the issuer's own permission is what caps a session at 900 seconds"
  }
}

run "the_production_key_is_decrypted_by_the_release_role_alone" {
  command = plan

  variables {
    operator_role_arns = ["arn:aws:iam::123456789012:role/operator"]
  }

  assert {
    condition     = aws_kms_key.production.enable_key_rotation == true && aws_kms_key.production.deletion_window_in_days >= 7
    error_message = "the key rotates and a deletion is recoverable"
  }

  # who may Decrypt: the release role, once, and nobody else in any statement
  assert {
    condition = length([
      for s in data.aws_iam_policy_document.key.statement : s
      if contains(s.actions, "kms:Decrypt") || contains(s.actions, "kms:*")
    ]) == 1
    error_message = "exactly one key-policy statement may allow Decrypt"
  }

  assert {
    condition = length([
      for s in data.aws_iam_policy_document.key.statement : s
      if s.sid == "OnlyTheReleaseRoleDecrypts"
      && length(s.principals) == 1
      && one(s.principals).identifiers == toset(["arn:aws:iam::123456789012:role/obx/obx-fleet-a-issuer-release"])
    ]) == 1
    error_message = "the Decrypt statement must name the release role alone"
  }

  assert {
    condition = length([
      for s in data.aws_iam_policy_document.key.statement : s
      if s.sid == "AdministerButNeverUse" && !contains(s.actions, "kms:Decrypt") && !contains(s.actions, "kms:*") && !contains(s.actions, "kms:Encrypt")
    ]) == 1
    error_message = "the account root administers the key and never uses it"
  }

  assert {
    condition = length([
      for s in data.aws_iam_policy_document.key.statement : s
      if s.sid == "OperatorWritesNeverReads" && !contains(s.actions, "kms:Decrypt") && contains(s.actions, "kms:Encrypt")
    ]) == 1
    error_message = "an operator may write Production secrets and never read them"
  }

  # no principal is a wildcard
  assert {
    condition = length([
      for s in data.aws_iam_policy_document.key.statement : s
      if length([for p in s.principals : p if contains(p.identifiers, "*")]) > 0
    ]) == 0
    error_message = "no statement of the key policy may name everyone"
  }
}

run "no_operator_statement_without_operator_roles" {
  command = plan

  assert {
    condition     = length([for s in data.aws_iam_policy_document.key.statement : s if s.sid == "OperatorWritesNeverReads"]) == 0
    error_message = "no operator statement without operator roles"
  }
}

run "the_function_is_reached_only_with_an_aws_signature_and_holds_no_secret_in_its_settings" {
  command = plan

  assert {
    condition     = aws_lambda_function_url.issuer.authorization_type == "AWS_IAM"
    error_message = "the function's address must require an AWS signature"
  }

  assert {
    condition = length([
      for k, v in aws_lambda_function.issuer.environment[0].variables : k
      if can(regex("(?i)(secret_value|password|token|api_key|private)", k))
    ]) == 0
    error_message = "the function's settings hold names and addresses, never a secret"
  }

  assert {
    condition     = aws_lambda_function.issuer.runtime == "provided.al2023" && aws_lambda_function.issuer.handler == "bootstrap"
    error_message = "the function is the ozbox-issuer program on a custom runtime"
  }
}

run "its_state_is_recoverable_and_a_box_may_only_invoke" {
  command = plan

  assert {
    condition     = aws_dynamodb_table.state.point_in_time_recovery[0].enabled == true && aws_dynamodb_table.state.billing_mode == "PAY_PER_REQUEST"
    error_message = "the state table recovers to a point in time"
  }

  assert {
    condition = (
      length(data.aws_iam_policy_document.invoke.statement) == 1
      && one(data.aws_iam_policy_document.invoke.statement).actions == toset(["lambda:InvokeFunctionUrl"])
      && one(data.aws_iam_policy_document.invoke.statement).effect == "Allow"
    )
    error_message = "what a box is given is the right to invoke the issuer, and nothing else"
  }
}

run "boxes_are_attached_the_invoke_policy_only" {
  command = plan

  variables {
    box_role_arns = ["arn:aws:iam::123456789012:role/ozbox-dev"]
  }

  assert {
    condition     = length(aws_iam_role_policy_attachment.box_invoke) == 1 && aws_iam_role_policy_attachment.box_invoke["arn:aws:iam::123456789012:role/ozbox-dev"].role == "ozbox-dev"
    error_message = "a box role gets the invoke policy"
  }
}

run "the_issuers_record_can_be_added_to_and_never_removed" {
  command = plan

  variables {
    audit_bucket_arn = "arn:aws:s3:::example-object-lock"
  }

  assert {
    condition = length([
      for s in data.aws_iam_policy_document.issuer.statement : s
      if s.sid == "AddToItsOwnRecordNeverRemove" && s.actions == toset(["s3:PutObject"]) && s.resources == toset(["arn:aws:s3:::example-object-lock/issuer/*"])
    ]) == 1
    error_message = "the issuer may add objects under issuer/ and nothing else"
  }
}

run "bad_inputs_are_refused" {
  command = plan

  variables {
    secret_name_prefix = "/leading/slash/"
  }

  expect_failures = [var.secret_name_prefix]
}

# the package that is uploaded is the one whose hash the person gave (which the CLI takes from the signed release,
# never from the file itself).
run "a_package_that_does_not_match_the_given_hash_is_refused" {
  command = plan

  variables {
    package_sha256 = "47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU="
  }

  expect_failures = [aws_lambda_function.issuer]
}

# no wildcard administration, no unconditional grant, and the only way left to change the key policy is the
# account administrators' PutKeyPolicy (recorded, and denied to the setup identity on keys tagged ozbox-production).
run "no_principal_but_the_release_role_can_decrypt_or_hand_out_decrypt_without_a_recorded_policy_change" {
  command = plan

  # no wildcard action in any statement of the key policy (a wildcard would include Decrypt, CreateGrant and PutKeyPolicy)
  assert {
    condition = alltrue([
      for s in data.aws_iam_policy_document.key.statement :
      alltrue([for a in s.actions : !strcontains(a, "*")])
    ])
    error_message = "the key policy names its actions; a wildcard would include kms:CreateGrant and kms:PutKeyPolicy"
  }

  # a grant is for an AWS service only
  assert {
    condition = alltrue([
      for s in data.aws_iam_policy_document.key.statement :
      !contains(s.actions, "kms:CreateGrant") || (
        length(s.condition) == 1 && [for c in s.condition : c.variable][0] == "kms:GrantIsForAWSResource" && join(",", [for c in s.condition : join(",", c.values)]) == "true"
      )
    ])
    error_message = "kms:CreateGrant only for an AWS service acting on an account resource"
  }

  # the policy can be changed by the account administrators alone, in a statement of its own
  assert {
    condition = length([
      for s in data.aws_iam_policy_document.key.statement : s
      if contains(s.actions, "kms:PutKeyPolicy")
      && length(s.actions) == 1
      && length(s.principals) == 1
      && one(s.principals).identifiers == toset(["arn:aws:iam::123456789012:root"])
    ]) == 1 && length([for s in data.aws_iam_policy_document.key.statement : s if contains(s.actions, "kms:PutKeyPolicy")]) == 1
    error_message = "exactly one statement may allow PutKeyPolicy, for the account's administrators, and nothing else in it"
  }

  # the mark the setup identity's policy denies policy changes on
  assert {
    condition     = aws_kms_key.production.tags["ozbox-production"] == "true"
    error_message = "the Production key carries ozbox-production=true"
  }
}

# the two roles live in the reserved /obx/ namespace, outside every pattern the daily operator may manage
# (`role/ozbox-*`), so it can neither rewrite their trust nor pass them to an instance.
run "the_issuer_roles_are_in_the_reserved_namespace_the_operator_cannot_manage" {
  command = plan

  assert {
    condition     = aws_iam_role.issuer.path == "/obx/" && aws_iam_role.release.path == "/obx/"
    error_message = "both issuer roles must be created under the /obx/ path"
  }
  assert {
    condition     = startswith(aws_iam_role.issuer.name, "obx-") && startswith(aws_iam_role.release.name, "obx-")
    error_message = "both issuer roles must be named obx-*"
  }
  assert {
    condition = alltrue([
      for r in [aws_iam_role.issuer, aws_iam_role.release] :
      !startswith("${r.path}${r.name}", "ozbox-") && startswith("${r.path}${r.name}", "/obx/obx-")
    ])
    error_message = "the issuer roles' ARNs must fall outside the operator's role/ozbox-* pattern"
  }
}

# the issuer's alias is created (and removed on destroy) under the key policy, with no use of the key.
run "the_alias_can_be_made_and_removed_and_the_key_still_cannot_be_used_by_its_administrators" {
  command = plan

  assert {
    condition = length([
      for s in data.aws_iam_policy_document.key.statement : s
      if s.sid == "AdministerButNeverUse" && contains(s.actions, "kms:CreateAlias") && contains(s.actions, "kms:DeleteAlias")
      && !contains(s.actions, "kms:Decrypt") && !contains(s.actions, "kms:CreateGrant") && !contains(s.actions, "kms:PutKeyPolicy")
    ]) == 1
    error_message = "the alias must be creatable and deletable without any way to use the key or change its policy"
  }
}

# only an instance acting as the box can ask the issuer; assumed-role credentials carry no source instance.
run "only_instance_credentials_can_invoke_the_issuer" {
  command = plan

  assert {
    condition = length([
      for c in one(data.aws_iam_policy_document.invoke.statement).condition : c
      if c.test == "Null" && c.variable == "ec2:SourceInstanceARN" && contains(c.values, "false")
    ]) == 1
    error_message = "the invoke permission must require ec2:SourceInstanceARN to be present"
  }
}
