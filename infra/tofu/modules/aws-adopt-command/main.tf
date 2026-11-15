# The one root command an operator may send to a box through AWS Systems Manager Run Command (ADR 0029 Amendment 11).
#
# `ozbox adopt-fleet-key` reads a box's secrets-store facts, and takes a recorded cancel away or records one, as ROOT on the
# box, through SSM, because what the box user says over SSH can be forged. The stock `AWS-RunShellScript` document would let
# anyone allowed to send it run ANY command as root on every box, so this module defines a document of its own:
#
#   - its only parameter is `action`, an enum SSM itself validates before anything reaches the box;
#   - each value maps to one fixed `ozbox` program by absolute path, and the shell never sees the parameter as anything but
#     a word to match (no value is ever run);
#   - the operator permission below allows SendCommand on THIS document only, and on instances this tool manages.
#
# The operator permission is an output (`operator_adopt_policy_json`): attach it to the role or user that runs
# `ozbox adopt-fleet-key`. It never allows AWS-RunShellScript, an arbitrary document, or a command on an instance the tool
# did not make.

# Made by `ozbox init` as a step of its own, with the setup identity's `OzBoxAdoptAdmin` permission set (infra/aws/adopt-admin-policy.json:
# the Systems Manager document actions on `document/ozbox-adopt-*` and nothing else). It is NOT part of aws-secrets-key, whose
# identity (`OzBoxKeyAdmin`) is KMS-only.

data "aws_region" "this" {}

locals {
  adopt_document = "ozbox-adopt-${var.name}"
  tags = merge(var.labels, {
    "ozbox-managed" = "true"
    "ozbox-fleet"   = var.name
  })
}

resource "aws_ssm_document" "adopt" {
  name            = local.adopt_document
  document_type   = "Command"
  document_format = "YAML"
  target_type     = "/AWS::EC2::Instance"
  tags            = local.tags

  # The text lives in its own file because the laptop pins its SHA-256 on every command it sends (`--document-hash`): the
  # ozbox program carries the same file. Whether Systems Manager itself REFUSES a send whose pinned hash differs from the document's is
  # unproven (the API reference does not say so); the CLI pins the hash on every send, and real-box check 1 settles whether it is enforced.
  content = file("${path.module}/adopt-document.yaml")

  # What Systems Manager says it hashed must be what the CLI pins (the SHA-256 of that file's bytes). Nothing in the API
  # reference says what the system hashes, or that a mismatch is refused, so this is checked on the apply that makes the
  # document: a wrong assumption stops there, with a reason, instead of refusing (or, worse, not refusing) every command later.
  lifecycle {
    postcondition {
      condition     = self.hash == sha256(file("${path.module}/adopt-document.yaml"))
      error_message = "Systems Manager hashed the adopt document differently from the SHA-256 of its file, so the hash `ozbox adopt-fleet-key` sends with each command would not match it. Nothing in the fleet depends on the document yet. Do not use `ozbox adopt-fleet-key` with this module version; report it with the hash Systems Manager gave (`aws ssm describe-document --name ozbox-adopt-<fleet> --query Document.Hash`)."
    }
  }
}

data "aws_iam_policy_document" "operator_adopt" {
  statement {
    sid       = "SendOnlyTheAdoptDocument"
    effect    = "Allow"
    actions   = ["ssm:SendCommand"]
    resources = ["arn:aws:ssm:${data.aws_region.this.name}:${var.account_id}:document/${local.adopt_document}"]
  }

  statement {
    sid       = "ToBoxesOzBoxManages"
    effect    = "Allow"
    actions   = ["ssm:SendCommand"]
    resources = ["arn:aws:ec2:${data.aws_region.this.name}:${var.account_id}:instance/*"]
    condition {
      test     = "StringEquals"
      variable = "ssm:resourceTag/ozbox-managed"
      values   = ["true"]
    }
  }

  # This action takes no resource-level restriction in IAM: it reads a command's result, and cannot start or stop anything. It
  # reaches every Run Command in the account, so attach the policy only to a principal used for nothing else until Oz Box has an
  # account of its own. `ssm:CancelCommand` is not here on purpose: the delivery timeout already stops a command that would
  # start late, and a running move must never be killed part way.
  statement {
    sid       = "ReadACommandThatWasSent"
    effect    = "Allow"
    actions   = ["ssm:GetCommandInvocation"]
    resources = ["*"]
  }
}
