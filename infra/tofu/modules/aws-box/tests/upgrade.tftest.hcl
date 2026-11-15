# An upgrade is `apply -replace=aws_instance.box` with a new image_id, applied on top of a real box. These runs share
# state, as `tofu test` runs in one file do: a box is created, then the module is PLANNED with the new image, and the
# plan must replace the machine while the /work volume id stays a known value (a volume that was to be replaced would
# have an id "known after apply", and the condition below could not be evaluated, which fails the run).

# Runs with no credentials and no network: every provider is mocked.

mock_provider "aws" {
  mock_data "aws_subnet" {
    defaults = {
      vpc_id            = "vpc-0123456789abcdef0"
      availability_zone = "us-east-1a"
    }
  }
  mock_data "aws_caller_identity" {
    defaults = { account_id = "123456789012" }
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
  # the first-boot hash the program passes; the machine is tagged with it when it is created
  first_boot_sha256 = "1111111111111111111111111111111111111111111111111111111111111111"
}

run "create" {
  command = apply

  assert {
    condition     = aws_instance.box.tags["ozbox-first-boot"] == "1111111111111111111111111111111111111111111111111111111111111111"
    error_message = "the machine must carry the first-boot hash it was made with, as a tag the box cannot change"
  }

  assert {
    condition     = !contains(keys(aws_ebs_volume.work.tags), "ozbox-first-boot")
    error_message = "the first-boot tag belongs to the machine, not to the /work volume that outlives it"
  }

  assert {
    condition     = strcontains(output.cloud_init, "first_boot_sha256=%s") && strcontains(output.cloud_init, "'1111111111111111111111111111111111111111111111111111111111111111'")
    error_message = "the first-boot configuration must write its own record on the box"
  }
}

run "an_in_place_change_does_not_relabel_the_machine" {
  command = plan

  variables {
    first_boot_sha256 = "2222222222222222222222222222222222222222222222222222222222222222"
  }

  # Without a replace the machine keeps the user data it booted with, so it must keep the tag that names it.
  assert {
    condition     = aws_instance.box.tags["ozbox-first-boot"] == "1111111111111111111111111111111111111111111111111111111111111111"
    error_message = "an in-place apply must not move the first-boot tag of a machine that was not replaced"
  }
}

# `ozbox adopt-fleet-key` moves an EXISTING box to the fleet's secrets key by applying the module with `secrets_key_arn`, `fleet`
# and the pending label on top of the box that was made without them. Only the role's tags and ONE policy ATTACHMENT may appear
# (the daily operator role may attach the account's customer-managed fleet-key policy and is denied iam:PutRolePolicy on
# purpose, so nothing inline): the machine and the /work volume are the same objects (their ids are known values in the plan,
# which a replaced resource's would not be), and the first-boot configuration (user data, which the box read once) is not
# rewritten.
run "adding_the_secrets_key_later_changes_the_role_in_place_and_replaces_nothing" {
  command = plan

  variables {
    secrets_key_arn = "arn:aws:kms:us-east-1:123456789012:key/00000000-0000-0000-0000-000000000000"
    fleet           = "fleet-a"
    labels = {
      team                  = "example"
      "ozbox-secrets-adopt" = "arn:aws:kms:us-east-1:123456789012:key/00000000-0000-0000-0000-000000000000"
    }
  }

  assert {
    condition     = length(aws_instance.box.id) > 0 && length(aws_ebs_volume.work.id) > 0 && length(aws_volume_attachment.work.id) > 0
    error_message = "moving a box to the fleet key must not replace the machine, its attachment or /work (their ids must be known in the plan)"
  }

  assert {
    condition     = length(aws_iam_role_policy_attachment.fleet_key) == 1 && aws_iam_role.box.tags["ozbox-fleet"] == "fleet-a"
    error_message = "the role gets the fleet key's managed policy attached and the fleet tag"
  }

  assert {
    condition     = aws_iam_role_policy_attachment.fleet_key[0].policy_arn == "arn:aws:iam::123456789012:policy/ozbox-box-fleet-key-fleet-a"
    error_message = "the attachment is the account's fleet-key policy for this fleet, by name, and no other"
  }

  assert {
    condition     = aws_iam_role.box.tags["ozbox-box"] == "dev-1"
    error_message = "the grant stays pinned to this box's own secrets: the policy's condition reads the role's ozbox-box tag"
  }

  assert {
    condition     = aws_instance.box.ami == "ami-0123456789abcdef0" && aws_instance.box.tags["ozbox-first-boot"] == "1111111111111111111111111111111111111111111111111111111111111111"
    error_message = "the machine keeps its image and its first-boot record"
  }
}

run "a_same_image_replace_writes_the_new_first_boot_tag" {
  command = plan

  plan_options {
    replace = [aws_instance.box]
  }

  variables {
    first_boot_sha256 = "2222222222222222222222222222222222222222222222222222222222222222"
  }

  # `-replace` builds a new machine from the current configuration, so it is tagged with THIS program's hash, not the
  # old machine's (ignore_changes only shields a machine that is kept).
  assert {
    condition     = aws_instance.box.tags["ozbox-first-boot"] == "2222222222222222222222222222222222222222222222222222222222222222"
    error_message = "a replaced machine must carry the first-boot hash of the program that replaced it"
  }
}

run "the_first_boot_hash_must_be_a_lowercase_sha256" {
  command = plan

  variables {
    first_boot_sha256 = "ABC"
  }

  expect_failures = [var.first_boot_sha256]
}

run "an_upgrade_replaces_the_machine_and_keeps_the_work_volume" {
  command = plan

  variables {
    image_id = "ami-0fedcba9876543210"
  }

  assert {
    condition     = aws_instance.box.ami == "ami-0fedcba9876543210"
    error_message = "the machine must be rebuilt from the new image"
  }

  assert {
    condition     = length(aws_ebs_volume.work.id) > 0 && length(output.work_volume_id) > 0
    error_message = "an upgrade must keep the very same /work volume (its id must not be unknown in the plan)"
  }

  assert {
    condition     = aws_ebs_volume.work.size == 200 && aws_ebs_volume.work.encrypted == true
    error_message = "an upgrade must not change the /work volume"
  }
}

run "a_changed_snapshot_or_key_is_ignored_on_an_existing_volume" {
  command = plan

  variables {
    image_id         = "ami-0fedcba9876543210"
    work_snapshot_id = "snap-0123456789abcdef0"
    kms_key_arn      = "arn:aws:kms:us-east-1:123456789012:key/00000000-0000-0000-0000-000000000000"
  }

  # Both of these force a new volume when they change. The module must keep what the box was created with, so the
  # planned values are the old ones, not the ones asked for now (an upgrade that no longer names the snapshot a clone
  # was restored from would otherwise plan an empty /work).
  assert {
    condition     = aws_ebs_volume.work.snapshot_id != "snap-0123456789abcdef0" && aws_ebs_volume.work.kms_key_id != "arn:aws:kms:us-east-1:123456789012:key/00000000-0000-0000-0000-000000000000"
    error_message = "a changed snapshot or key must never be applied to the /work volume of an existing box"
  }
}

# Restoring /work from a snapshot is `plan -replace=aws_ebs_volume.work` with the snapshot: the replacement volume is
# made from it (ignore_changes only shields an EXISTING volume from a changed snapshot, never a new one). A mock provider
# cannot show that the machine is left alone (it has no replace-on-change rules); the adapter checks that against the
# real plan before it touches anything (`check_restore_preview`), and refuses the restore if the machine would change.
run "a_restored_work_volume_is_made_from_the_snapshot" {
  command = plan

  plan_options {
    replace = [aws_ebs_volume.work]
  }

  variables {
    work_snapshot_id = "snap-0123456789abcdef0"
  }

  assert {
    condition     = aws_ebs_volume.work.snapshot_id == "snap-0123456789abcdef0"
    error_message = "the replacement /work volume must be made from the snapshot"
  }

  assert {
    condition     = aws_ebs_volume.work.size == 200 && aws_ebs_volume.work.encrypted == true
    error_message = "the replacement /work volume keeps the box's size and encryption"
  }
}
