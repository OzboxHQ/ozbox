# Runs with no credentials and no network: every provider is mocked.

mock_provider "aws" {
  mock_data "aws_iam_policy_document" {
    defaults = {
      json = "{\"Version\":\"2012-10-17\",\"Statement\":[]}"
    }
  }

  mock_data "aws_region" {
    defaults = {
      name = "us-east-1"
    }
  }

  # What Systems Manager reports as the document's hash: the SHA-256 of adopt-document.yaml, which the ozbox program pins
  # (`ADOPT_DOCUMENT` in the provider's Rust test). Editing the file means editing this too, on purpose.
  mock_resource "aws_ssm_document" {
    defaults = {
      hash = "3ee210517c2bf7941619126b5e18829ff71f14e43a4d177ba1bb0788c1527fa7"
    }
  }
}

variables {
  name       = "fleet-a"
  account_id = "123456789012"
}

run "the_adopt_document_runs_only_fixed_programs_chosen_by_an_enum" {
  command = plan

  assert {
    condition     = aws_ssm_document.adopt.name == "ozbox-adopt-fleet-a" && aws_ssm_document.adopt.document_type == "Command"
    error_message = "the document is named for the fleet, and is a command document"
  }

  assert {
    condition     = yamldecode(aws_ssm_document.adopt.content).parameters.action.allowedValues == ["status", "arm", "cancel", "cancel-from-copy"]
    error_message = "the only parameter is an enum of exactly the four fixed actions"
  }

  assert {
    condition     = length(keys(yamldecode(aws_ssm_document.adopt.content).parameters)) == 1
    error_message = "the document takes no parameter but the enum"
  }

  # the parameter is only ever matched in a case statement; it is never run, and no other placeholder is in the script
  assert {
    condition     = length(regexall("\\{\\{", join("", yamldecode(aws_ssm_document.adopt.content).mainSteps[0].inputs.runCommand))) == 1
    error_message = "exactly one placeholder (the matched word) is in the script"
  }

  assert {
    condition     = !strcontains(aws_ssm_document.adopt.content, "eval") && !strcontains(aws_ssm_document.adopt.content, "bash -c") && !strcontains(aws_ssm_document.adopt.content, "sh -c")
    error_message = "the script never evaluates its parameter"
  }

  # each word runs one fixed program by absolute path; cancel-from-copy is the only one that loses secrets, and it is the only one with --from-copy
  assert {
    condition = (
      strcontains(aws_ssm_document.adopt.content, "status) exec /usr/local/bin/ozbox secrets adopt-status ;;") &&
      strcontains(aws_ssm_document.adopt.content, "arm) exec /usr/local/bin/ozbox secrets adopt-arm ;;") &&
      strcontains(aws_ssm_document.adopt.content, "cancel) exec /usr/local/bin/ozbox secrets adopt-cancel ;;") &&
      strcontains(aws_ssm_document.adopt.content, "cancel-from-copy) exec /usr/local/bin/ozbox secrets adopt-cancel --from-copy ;;") &&
      length(regexall("--from-copy", aws_ssm_document.adopt.content)) == 1
    )
    error_message = "every word maps to its one fixed program, and only cancel-from-copy passes --from-copy"
  }

  # the laptop waits longer than this (the delivery timeout plus this one, and a margin), so it never gives up on a running cancel
  assert {
    condition     = yamldecode(aws_ssm_document.adopt.content).mainSteps[0].inputs.timeoutSeconds == "900"
    error_message = "the execution timeout is 900 seconds, which the CLI's wait is built on"
  }

  # the text comes from the file the CLI carries, and its hash is an output
  assert {
    condition     = aws_ssm_document.adopt.content == file("${path.module}/adopt-document.yaml") && output.adopt_document_sha256 == sha256(file("${path.module}/adopt-document.yaml"))
    error_message = "the document is the file, and its hash is published"
  }
}

run "the_operator_may_send_only_the_adopt_document_to_managed_boxes" {
  command = plan

  assert {
    condition     = length([for s in data.aws_iam_policy_document.operator_adopt.statement : s if s.sid == "SendOnlyTheAdoptDocument" && contains(s.actions, "ssm:SendCommand") && length(s.resources) == 1 && one(s.resources) == "arn:aws:ssm:us-east-1:123456789012:document/ozbox-adopt-fleet-a"]) == 1
    error_message = "SendCommand is allowed on the adopt document alone"
  }

  assert {
    condition = length([for s in data.aws_iam_policy_document.operator_adopt.statement : s if s.sid == "ToBoxesOzBoxManages" &&
      length(s.condition) == 1 &&
      length(s.resources) == 1 && one(s.resources) == "arn:aws:ec2:us-east-1:123456789012:instance/*" &&
      length([for c in s.condition : c if c.test == "StringEquals" && c.variable == "ssm:resourceTag/ozbox-managed" && length(c.values) == 1 && contains(c.values, "true")]) == 1
    ]) == 1
    error_message = "the instances it may be sent to are limited by the ozbox-managed=true tag (and only that), on instances in this account and region"
  }

  # the one statement that cannot be limited to a resource (IAM has no resource type for it) holds read access to a result and nothing else
  assert {
    condition = length([for s in data.aws_iam_policy_document.operator_adopt.statement : s if contains(s.resources, "*") &&
      length(s.actions) == 1 && contains(s.actions, "ssm:GetCommandInvocation")
    ]) == 1 && length([for s in data.aws_iam_policy_document.operator_adopt.statement : s if contains(s.resources, "*")]) == 1
    error_message = "the only statement on every resource allows reading a command's result, and nothing else"
  }

  assert {
    condition     = length([for s in data.aws_iam_policy_document.operator_adopt.statement : s if length([for a in s.actions : a if a == "ssm:CancelCommand" || a == "ssm:*" || a == "ssm:UpdateDocument" || a == "ssm:CreateDocument"]) > 0]) == 0
    error_message = "the operator can neither stop a command (a running move must not be killed part way) nor change a document"
  }

  assert {
    condition     = length(data.aws_iam_policy_document.operator_adopt.statement) == 3
    error_message = "exactly three statements: send the document, to managed boxes, and read a result"
  }

  assert {
    condition     = length([for s in data.aws_iam_policy_document.operator_adopt.statement : s if contains(s.actions, "ssm:SendCommand") && contains(s.resources, "*")]) == 0
    error_message = "SendCommand is never allowed on every resource (that would reach AWS-RunShellScript)"
  }

  assert {
    condition     = length([for s in data.aws_iam_policy_document.operator_adopt.statement : s if length([for r in s.resources : r if strcontains(r, "AWS-RunShellScript")]) > 0]) == 0
    error_message = "the stock shell document is never named"
  }
}
