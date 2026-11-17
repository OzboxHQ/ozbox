# Runs with no credentials and no network: every provider is mocked.

mock_provider "aws" {
  mock_data "aws_caller_identity" {
    defaults = {
      account_id = "123456789012"
    }
  }
  mock_resource "aws_iam_role" {
    defaults = {
      arn = "arn:aws:iam::123456789012:role/obx/obx-fleet-x"
    }
  }
  mock_resource "aws_iam_policy" {
    defaults = {
      arn = "arn:aws:iam::123456789012:policy/obx/obx-fleet-x"
    }
  }
}

variables {
  regions               = ["us-east-1"]
  machine_types         = ["m7i.xlarge", "c7i.xlarge"]
  image_ids             = ["ami-0123456789abcdef0"]
  window_permission_set = "OzboxFleetWindow"
  subnet_ids            = ["subnet-0123456789abcdef0"]
  fleet_manager_box     = "main"
}

# Review finding M3: a launch's network interface, new or existing, is held to Oz Box's subnets.
run "a_launchs_interface_is_held_to_ozbox_subnets" {
  command = apply

  assert {
    condition = one([
      for st in jsondecode(aws_iam_policy.change.policy).Statement : st.Condition.ArnLike["ec2:Subnet"]
      if st.Resource == "arn:aws:ec2:*:123456789012:network-interface/*"
    ]) == ["arn:aws:ec2:*:123456789012:subnet/subnet-0123456789abcdef0"]
    error_message = "the network-interface statement names exactly the given subnets"
  }
}

# Review findings L1 and L2: main is denied by its box name as well as by its tag, attach included.
run "main_is_denied_by_its_name" {
  command = apply

  assert {
    condition = length([
      for st in jsondecode(aws_iam_policy.change_guard.policy).Statement : st
      if st.Effect == "Deny" && try(st.Condition.StringEquals["aws:ResourceTag/ozbox-box"], "") == "main" && try(contains(st.Action, "ec2:AttachVolume"), false)
    ]) == 1
    error_message = "the guard denies everything carrying main's box name, attaching a disk included"
  }
}

run "a_subnet_that_is_not_a_subnet_id_is_refused" {
  command = plan

  variables {
    subnet_ids = ["subnet-0123456789abcdef0", "*"]
  }

  expect_failures = [var.subnet_ids]
}

run "a_fleet_manager_name_that_could_widen_the_deny_is_refused" {
  command = plan

  variables {
    fleet_manager_box = "m*"
  }

  expect_failures = [var.fleet_manager_box]
}

run "both_roles_are_in_the_reserved_namespace_the_operator_cannot_touch" {
  command = apply

  assert {
    condition     = aws_iam_role.read.path == "/obx/" && aws_iam_role.change.path == "/obx/"
    error_message = "the fleet roles live under /obx/ (ADR 0040 §3.1)"
  }

  assert {
    condition     = startswith(aws_iam_role.read.name, "obx-") && startswith(aws_iam_role.change.name, "obx-")
    error_message = "the fleet roles' names start obx-, which the operator's role/ozbox-* rights cannot match"
  }

  assert {
    condition     = alltrue([for p in [aws_iam_policy.read, aws_iam_policy.change, aws_iam_policy.change_guard, aws_iam_policy.main_assume] : p.path == "/obx/" && startswith(p.name, "obx-")])
    error_message = "the fleet policies are in the reserved namespace too"
  }

  assert {
    condition     = aws_iam_role.read.max_session_duration == 3600 && aws_iam_role.change.max_session_duration == 3600
    error_message = "sessions are short"
  }
}

run "only_main_assumes_the_read_role_and_main_never_assumes_the_change_role" {
  command = apply

  assert {
    condition     = jsondecode(aws_iam_role.read.assume_role_policy).Statement[0].Condition.ArnEquals["aws:PrincipalArn"] == "arn:aws:iam::123456789012:role/obx/obx-main"
    error_message = "the read role trusts main's own role, nothing else"
  }

  assert {
    condition     = !strcontains(aws_iam_role.change.assume_role_policy, "obx-main")
    error_message = "main's role is never in the change role's trust"
  }

  assert {
    condition     = jsondecode(aws_iam_role.change.assume_role_policy).Statement[0].Condition.ArnLike["aws:PrincipalArn"] == "arn:aws:iam::123456789012:role/aws-reserved/sso.amazonaws.com/AWSReservedSSO_OzboxFleetWindow_*"
    error_message = "the change role trusts the owner's window permission set"
  }

  assert {
    condition     = alltrue([for r in [aws_iam_role.read, aws_iam_role.change] : jsondecode(r.assume_role_policy).Statement[0].Principal.AWS == "arn:aws:iam::123456789012:root"])
    error_message = "the principal is this account, never a wildcard"
  }

  assert {
    condition     = aws_iam_role_policy_attachment.main_assume.role == "obx-main"
    error_message = "the assume permission goes to main's own role"
  }
}

run "every_token_is_filled_and_lists_are_json_arrays" {
  command = apply

  assert {
    condition     = alltrue([for k, t in local.rendered : !strcontains(replace(t, "$${aws:", ""), "$${")])
    error_message = "a document has a placeholder nothing filled"
  }

  assert {
    condition     = jsondecode(aws_iam_policy.change.policy).Statement[0].Condition.StringEquals["aws:RequestedRegion"] == ["us-east-1"]
    error_message = "the regions are a JSON list"
  }

  assert {
    condition     = length([for s in jsondecode(aws_iam_policy.change_guard.policy).Statement : s if s.Effect != "Deny"]) == 0
    error_message = "the guard document holds only denies"
  }

  assert {
    condition     = length(aws_iam_policy.cost) == 0
    error_message = "the bill is not read unless asked for"
  }
}

run "the_bill_is_read_only_when_asked" {
  command = apply

  variables {
    read_costs = true
  }

  assert {
    condition     = length(aws_iam_policy.cost) == 1 && length(aws_iam_role_policy_attachment.cost) == 1
    error_message = "read_costs attaches the cost document to the read role"
  }
}

run "a_permission_set_name_that_could_widen_the_trust_is_refused" {
  command = plan

  variables {
    window_permission_set = "*"
  }

  expect_failures = [var.window_permission_set]
}

run "an_image_that_is_not_an_ami_is_refused" {
  command = plan

  variables {
    image_ids = ["ami-0123456789abcdef0", "*"]
  }

  expect_failures = [var.image_ids]
}

# Second review, Low 1: an orch-* session has no ozbox-window-box tag, so the trust admits plan-* sessions only.
run "only_plan_sessions_may_assume_the_change_role" {
  command = apply

  assert {
    condition     = jsondecode(aws_iam_role.change.assume_role_policy).Statement[0].Condition.StringLike["sts:RoleSessionName"] == "plan-*"
    error_message = "the change role trusts plan-* sessions only until the orchestration window is built"
  }

  assert {
    condition     = !strcontains(aws_iam_role.change.assume_role_policy, "orch-")
    error_message = "no orch-* session in the trust"
  }
}

# Second review, Low 2: an existing interface (ARN network-interface/eni-...) without ozbox-managed=true is refused, tagged
# otherwise or not at all; the interface a launch creates (literal ARN network-interface/*) is not matched by eni-*.
run "an_existing_untagged_interface_is_refused" {
  command = apply

  assert {
    condition = length([
      for st in jsondecode(aws_iam_policy.change_guard.policy).Statement : st
      if st.Sid == "NeverLaunchOnAnotherOwnersInterface"
      && st.Effect == "Deny"
      && st.Resource == "arn:aws:ec2:*:123456789012:network-interface/eni-*"
      && st.Condition.StringNotEquals["aws:ResourceTag/ozbox-managed"] == "true"
      && !contains(keys(st.Condition), "Null")
    ]) == 1
    error_message = "the deny covers every existing interface not tagged ozbox-managed=true, untagged included, and not the launch's new one"
  }
}
