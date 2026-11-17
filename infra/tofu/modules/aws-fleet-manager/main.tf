# A box's dashboard manages the fleet through scoped roles of its own (ADR 0040).
#
# Applied ONCE per account by an administrator (not the daily operator, which is denied every role under /obx/ on purpose):
#   - obx-fleet-read: what main's dashboard may read about the fleet. Only main's own role (obx-main) may assume it, and only
#     through main's credential holder (the dashboard and the box user cannot reach the metadata service).
#   - obx-fleet-change: create, resize, pause, resume, clone and destroy ozbox-managed resources, and nothing that changes who
#     may do what. Only the owner's own sign-in on their computer may assume it (a change window, one plan at a time).
#   - obx-fleet-assume-read: the one permission main's role gets, attached to obx-main.
#
# The documents live in infra/aws/fleet-*.json, the one source the program and its tests read too. The tokens are filled here
# with the same rule `ozbox_provider_aws::fleet_policy::render` uses (a list replaces its quoted token), and a Rust test holds
# the two to the same tokens. Invariants are in tests/invariants.tftest.hcl. Nothing here opens a port or makes a key.

data "aws_caller_identity" "this" {}

locals {
  account = data.aws_caller_identity.this.account_id
  docs    = "${path.module}/../../../aws"

  main_role_arn        = "arn:aws:iam::${local.account}:role/obx/obx-main"
  window_principal_arn = "arn:aws:iam::${local.account}:role/aws-reserved/sso.amazonaws.com/AWSReservedSSO_${var.window_permission_set}_*"

  files = {
    read         = "fleet-read-policy.json"
    cost         = "fleet-cost-policy.json"
    change       = "fleet-change-policy.json"
    change_guard = "fleet-change-guard-policy.json"
    read_trust   = "fleet-read-trust-policy.json"
    change_trust = "fleet-change-trust-policy.json"
    main_assume  = "fleet-main-assume-policy.json"
  }

  rendered = {
    for k, f in local.files : k => replace(replace(replace(replace(replace(replace(replace(replace(replace(
      file("${local.docs}/${f}"),
      "\"$${regions}\"", jsonencode(var.regions)),
      "\"$${sizes}\"", jsonencode(var.machine_types)),
      "\"$${image_ids}\"", jsonencode(var.image_ids)),
      "$${account_id}", local.account),
      "$${max_volume_gb}", tostring(var.max_volume_gb)),
      "$${max_iops}", tostring(var.max_iops)),
      "$${max_throughput}", tostring(var.max_throughput)),
      "$${main_role_arn}", local.main_role_arn),
    "$${window_principal_arn}", local.window_principal_arn)
  }

  tags = { "ozbox-managed" = "true" }
}

resource "aws_iam_role" "read" {
  name                 = "obx-fleet-read"
  path                 = "/obx/"
  description          = "Oz Box: main's dashboard reads the fleet. Assumed only by main's own role."
  assume_role_policy   = local.rendered.read_trust
  max_session_duration = 3600
  tags                 = local.tags
}

resource "aws_iam_role" "change" {
  name                 = "obx-fleet-change"
  path                 = "/obx/"
  description          = "Oz Box: one plan's change, in a window the owner opens from their own computer. main is not in its trust."
  assume_role_policy   = local.rendered.change_trust
  max_session_duration = 3600
  tags                 = local.tags
}

resource "aws_iam_policy" "read" {
  name   = "obx-fleet-read"
  path   = "/obx/"
  policy = local.rendered.read
  tags   = local.tags
}

resource "aws_iam_policy" "cost" {
  count  = var.read_costs ? 1 : 0
  name   = "obx-fleet-cost"
  path   = "/obx/"
  policy = local.rendered.cost
  tags   = local.tags
}

resource "aws_iam_policy" "change" {
  name   = "obx-fleet-change"
  path   = "/obx/"
  policy = local.rendered.change
  tags   = local.tags
}

resource "aws_iam_policy" "change_guard" {
  name   = "obx-fleet-change-guard"
  path   = "/obx/"
  policy = local.rendered.change_guard
  tags   = local.tags
}

resource "aws_iam_policy" "main_assume" {
  name   = "obx-fleet-assume-read"
  path   = "/obx/"
  policy = local.rendered.main_assume
  tags   = local.tags
}

resource "aws_iam_role_policy_attachment" "read" {
  role       = aws_iam_role.read.name
  policy_arn = aws_iam_policy.read.arn
}

resource "aws_iam_role_policy_attachment" "cost" {
  count      = var.read_costs ? 1 : 0
  role       = aws_iam_role.read.name
  policy_arn = aws_iam_policy.cost[0].arn
}

resource "aws_iam_role_policy_attachment" "change" {
  role       = aws_iam_role.change.name
  policy_arn = aws_iam_policy.change.arn
}

resource "aws_iam_role_policy_attachment" "change_guard" {
  role       = aws_iam_role.change.name
  policy_arn = aws_iam_policy.change_guard.arn
}

# main's own role (obx-main) is made by the setup identity when main moves into Oz Box's own account (ADR 0040 §13); this
# module only gives it the one permission it needs.
resource "aws_iam_role_policy_attachment" "main_assume" {
  role       = "obx-main"
  policy_arn = aws_iam_policy.main_assume.arn
}
