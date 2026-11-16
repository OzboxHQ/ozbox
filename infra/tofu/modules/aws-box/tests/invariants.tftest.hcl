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
}

run "no_inbound_rules" {
  command = apply

  assert {
    condition     = length(aws_security_group.box.ingress) == 0
    error_message = "the security group must have zero ingress rules"
  }

  assert {
    condition     = length(aws_security_group.box.egress) == 1
    error_message = "egress is open for now (single allow-all rule); tightening is a later allow-list"
  }
}

run "instance_is_private_and_hardened" {
  command = apply

  assert {
    condition     = aws_instance.box.associate_public_ip_address == false
    error_message = "the box must not have a public IP"
  }

  assert {
    condition     = aws_instance.box.metadata_options[0].http_tokens == "required"
    error_message = "IMDSv2 must be required"
  }

  assert {
    condition     = aws_instance.box.metadata_options[0].http_put_response_hop_limit == 1
    error_message = "IMDS hop limit must be 1 so containers cannot reach it"
  }

  assert {
    condition     = aws_instance.box.root_block_device[0].encrypted == true
    error_message = "the root volume must be encrypted"
  }

  assert {
    condition     = aws_instance.box.root_block_device[0].volume_type == "gp3"
    error_message = "the root volume must be gp3"
  }

  assert {
    condition     = aws_instance.box.ami == "ami-0123456789abcdef0" && aws_instance.box.instance_type == "m7i.4xlarge"
    error_message = "the instance must use the requested image and type"
  }
}

run "work_volume_is_separate_and_encrypted" {
  command = apply

  assert {
    condition     = aws_ebs_volume.work.encrypted == true && aws_ebs_volume.work.type == "gp3"
    error_message = "/work must be an encrypted gp3 volume"
  }

  assert {
    condition     = aws_ebs_volume.work.size == 200
    error_message = "/work must have the requested size"
  }

  assert {
    condition     = aws_volume_attachment.work.volume_id == aws_ebs_volume.work.id
    error_message = "/work must be attached as its own volume"
  }

  assert {
    condition     = aws_instance.box.root_block_device[0].delete_on_termination == true && length(aws_instance.box.ebs_block_device) == 0
    error_message = "/work must not be an inline block device of the instance"
  }

  assert {
    condition     = output.work_volume_id == aws_ebs_volume.work.id
    error_message = "work_volume_id output must be the /work volume"
  }
}

run "only_the_session_manager_policy_is_attached_and_it_is_not_awss_which_reads_every_parameter" {
  command = apply

  assert {
    condition     = endswith(aws_iam_role_policy_attachment.ssm_core.policy_arn, ":policy/ozbox-box-session-manager")
    error_message = "the box role carries the account's own Session Manager policy"
  }

  assert {
    condition     = !strcontains(aws_iam_role_policy_attachment.ssm_core.policy_arn, "AmazonSSMManagedInstanceCore") && !startswith(aws_iam_role_policy_attachment.ssm_core.policy_arn, "arn:aws:iam::aws:")
    error_message = "AmazonSSMManagedInstanceCore grants ssm:GetParameter(s) on every parameter in the account; no AWS-managed policy is attached"
  }
}

# A box that declares nothing carries only the Session Manager policy: no parameter read, no key, no session-log write.
run "a_box_that_declares_nothing_carries_only_the_session_manager_policy" {
  command = apply

  assert {
    condition = (
      length(aws_iam_role_policy_attachment.fleet_key) == 0 &&
      length(aws_iam_role_policy_attachment.parameters) == 0 &&
      length(aws_iam_role_policy_attachment.parameters_key) == 0 &&
      length(aws_iam_role_policy_attachment.session_logs) == 0
    )
    error_message = "no declaration, no extra policy"
  }
}

run "labels_on_every_taggable_resource" {
  command = apply

  assert {
    condition = alltrue([
      for t in [
        aws_instance.box.tags,
        aws_ebs_volume.work.tags,
        aws_security_group.box.tags,
        aws_iam_role.box.tags,
        aws_iam_instance_profile.box.tags,
        aws_instance.box.root_block_device[0].tags,
      ] : t["ozbox-box"] == "dev-1" && t["ozbox-managed"] == "true" && t["team"] == "example"
    ])
    error_message = "every taggable resource needs ozbox-box, ozbox-managed and the caller's labels"
  }
}

# The operator's AWS role may put a first tag on a disk only when the disk is created, so a system disk that is not tagged
# ozbox-managed from its first moment could never be tagged later by anything the daily role runs (an old box's was not).
run "the_system_disk_is_ours_from_the_moment_it_is_created" {
  command = apply

  assert {
    condition = (
      aws_instance.box.root_block_device[0].tags["ozbox-managed"] == "true" &&
      aws_instance.box.root_block_device[0].tags["ozbox-box"] == "dev-1" &&
      aws_instance.box.root_block_device[0].tags["ozbox-role"] == "root"
    )
    error_message = "the system disk must carry ozbox-managed, ozbox-box and its role in the tags it is created with"
  }
}

run "caller_cannot_override_reserved_labels" {
  command = apply

  variables {
    labels = { "ozbox-box" = "other", "ozbox-managed" = "false" }
  }

  assert {
    condition     = aws_instance.box.tags["ozbox-box"] == "dev-1" && aws_instance.box.tags["ozbox-managed"] == "true"
    error_message = "reserved labels are set by the module"
  }
}

run "user_data_creates_the_repos_directory_for_the_box_user" {
  command = apply

  assert {
    condition     = strcontains(output.cloud_init, "install -d -m 0750 -o ozbox -g ozbox /work/repos")
    error_message = "cloud-init must create /work/repos owned by the box user, on a new disk and an existing one"
  }

  assert {
    condition = (
      strcontains(output.cloud_init, "ozbox-tools.path") &&
      strcontains(output.cloud_init, "d /run/ozbox-tools/requests 1770 root ozbox") &&
      !strcontains(output.cloud_init, "ProtectHome=false")
    )
    error_message = "the tool installer's privileged helper must be a path-triggered one-shot with a sticky request directory"
  }
}

run "user_data_keeps_the_box_users_numeric_id_across_an_upgrade" {
  command = apply

  assert {
    condition = (
      strcontains(output.cloud_init, "disk_uid=") &&
      strcontains(output.cloud_init, "usermod -u") &&
      strcontains(output.cloud_init, "getent passwd")
    )
    error_message = "a new system disk must adopt the numeric id that owns the files on an existing /work"
  }
}

run "user_data_mounts_work_only_when_empty" {
  command = apply

  assert {
    condition     = strcontains(output.cloud_init, "blkid -p") && strcontains(output.cloud_init, "wipefs -n") && strcontains(output.cloud_init, "nofail")
    error_message = "cloud-init must detect an existing filesystem and mount with nofail"
  }
}

run "user_data_grows_the_filesystem_with_least_privilege" {
  command = apply

  assert {
    condition = (
      strcontains(output.cloud_init, "ozbox-growfs.service") &&
      strcontains(output.cloud_init, "ozbox-growfs.timer") &&
      strcontains(output.cloud_init, "CapabilityBoundingSet=CAP_SYS_ADMIN CAP_SYS_RESOURCE") &&
      strcontains(output.cloud_init, "PrivateNetwork=true") &&
      strcontains(output.cloud_init, "NoNewPrivileges=true") &&
      strcontains(output.cloud_init, "Wants=network-online.target ozbox-growfs.service")
    )
    error_message = "the filesystem grows through a dedicated one-shot unit with one capability and no network, never through the unprivileged daemon"
  }

  assert {
    condition     = strcontains(output.cloud_init, "resize2fs") && strcontains(output.cloud_init, "xfs_growfs")
    error_message = "cloud-init must grow ext4 and xfs filesystems"
  }
}

run "user_data_keeps_ssh_on_loopback_for_the_box_user_only" {
  command = apply

  assert {
    condition = (
      strcontains(output.cloud_init, "ListenAddress 127.0.0.1") &&
      strcontains(output.cloud_init, "AllowUsers ozbox") &&
      strcontains(output.cloud_init, "AuthenticationMethods publickey") &&
      strcontains(output.cloud_init, "PasswordAuthentication no")
    )
    error_message = "sshd must listen on loopback only and accept only keys, for the ozbox user only"
  }
}

run "user_data_gives_the_box_user_the_pinned_id" {
  command = apply

  assert {
    condition     = strcontains(output.cloud_init, "uid: 1500")
    error_message = "the box user must be created with the fixed id the Oz image uses"
  }
}

run "user_data_installs_instance_connect_on_aws" {
  command = apply

  assert {
    condition     = strcontains(output.cloud_init, "ec2-instance-connect")
    error_message = "an AWS box must be able to accept a key pushed for 60 seconds"
  }
}

run "box_name_valid_examples" {
  command = plan

  variables {
    box_name = "a"
  }
}

run "box_name_rejects_uppercase" {
  command = plan

  variables {
    box_name = "Dev"
  }

  expect_failures = [var.box_name]
}

run "box_name_rejects_leading_digit" {
  command = plan

  variables {
    box_name = "1dev"
  }

  expect_failures = [var.box_name]
}

run "box_name_rejects_trailing_hyphen" {
  command = plan

  variables {
    box_name = "dev-"
  }

  expect_failures = [var.box_name]
}

run "box_name_rejects_double_hyphen" {
  command = plan

  variables {
    box_name = "de--v"
  }

  expect_failures = [var.box_name]
}

run "box_name_rejects_too_long" {
  command = plan

  variables {
    box_name = "a2345678901234567890123456789012345678901"
  }

  expect_failures = [var.box_name]
}

run "box_name_accepts_exactly_40" {
  command = plan

  variables {
    box_name = "a234567890123456789012345678901234567890"
  }
}

run "user_data_installs_the_backup_credentials_helper_with_a_narrow_hand_off" {
  command = apply

  assert {
    condition     = strcontains(output.cloud_init, "ExecStart=/usr/local/bin/ozboxd backup-root") && strcontains(output.cloud_init, "d /run/ozbox-backup/requests 1770 root ozbox -")
    error_message = "backup credentials reach the box only through the root helper and a sticky request directory"
  }

  assert {
    condition     = strcontains(output.cloud_init, "ReadWritePaths=/etc/ozbox /run/ozbox-backup") && strcontains(output.cloud_init, "ReadWritePaths=-/run/ozbox-backup/requests")
    error_message = "the helper may write only /etc/ozbox and its spool, and the daemon only the request directory"
  }
}

run "user_data_gets_ozboxd_only_from_the_signed_release_and_never_on_the_oz_image" {
  command = apply

  assert {
    condition     = strcontains(output.cloud_init, "/usr/local/sbin/ozbox-install-agent.sh ||") && strcontains(output.cloud_init, "OZBOX_RELEASE_REPO=\"OzboxHQ/ozbox\"") && strcontains(output.cloud_init, "OZBOX_RELEASE_TAG=\"\"")
    error_message = "first boot installs ozboxd from the signed release of the configured repository"
  }

  assert {
    condition     = strcontains(output.cloud_init, "path: /usr/local/sbin/ozbox-install-agent.sh") && strcontains(output.cloud_init, "OZBOX_RELEASE_REPO") && !strcontains(output.cloud_init, "encoding: gz+b64")
    error_message = "the installer is written to the machine as plain text (the whole user data is gzipped once on AWS; compressing each script again made it larger) so a stock machine can run it"
  }
}

run "user_data_re_owns_old_files_before_any_service_starts" {
  command = apply

  assert {
    condition     = strcontains(output.cloud_init, "/usr/local/sbin/ozbox-reown.sh ||") && strcontains(output.cloud_init, "path: /usr/local/sbin/ozbox-reown.sh")
    error_message = "the work-setup script re-owns files that carry an old box user id"
  }

  assert {
    condition     = length(regexall("(?s)ozbox-work-setup\\.sh\\].*ozbox-install-agent\\.sh \\|\\|.*enable, --now, ozboxd\\.service", output.cloud_init)) == 1
    error_message = "work setup (and so the re-own) runs before ozboxd is installed or any service is enabled"
  }
}

run "user_data_installs_the_narrow_root_admin_path" {
  command = apply

  assert {
    condition     = strcontains(output.cloud_init, "ExecStart=/usr/local/sbin/ozbox-admin.sh") && strcontains(output.cloud_init, "d /run/ozbox-admin/requests 1770 root ozbox -")
    error_message = "admin actions reach root only through a sticky request directory and one allow-listed script"
  }

  assert {
    condition     = !strcontains(output.cloud_init, "sudoers") && !strcontains(output.cloud_init, "NOPASSWD")
    error_message = "the box user gets no sudo"
  }

  assert {
    condition     = !strcontains(output.cloud_init, "ConditionPathExists=/usr/local/bin/ozboxd\n\n      # It does not depend on ozboxd")
    error_message = "the admin helper must not need ozboxd, it is how ozboxd is put back"
  }
}

run "user_data_fits_the_providers_limit" {
  command = apply

  assert {
    condition     = length(base64gzip(output.cloud_init)) * 3 / 4 <= 15360
    error_message = "the compressed first-boot configuration must stay under the 16 KB AWS user-data limit"
  }
}

# The same limit with every value the template reads at the longest its variable allows (or, where a variable has no
# limit of its own, longer than any real one), not only the defaults.
run "user_data_fits_the_providers_limit_with_the_longest_values" {
  command = apply

  variables {
    box_name           = "a123456789-123456789-123456789-12345678z"
    region             = "ap-southeast-3"
    secrets_key_arn    = "arn:aws-us-gov:kms:ap-southeast-3:123456789012:key/0123abcd-0123-abcd-0123-0123456789ab"
    fleet              = "a123456789-123456789-12345678z"
    agent_release_repo = "an-owner-name-of-thirty-nine-characters/a-repository-name-of-one-hundred-characters-a-repository-name-of-one-hundred"
    agent_release_tag  = "image-v0.123.456-rc.789-and-some-more-words-to-make-it-very-long"
    runs_max_active    = 64
  }

  assert {
    # 15 360 bytes is the 16 KB AWS limit less a 1 KB margin, so a small addition to the template is a warning here and not
    # a machine that cannot be created. Measured 2026-11-12: 13 797 bytes with these values.
    condition     = length(var.box_name) == 40 && length(base64gzip(output.cloud_init)) * 3 / 4 <= 15360
    error_message = "the compressed first-boot configuration must stay at most 15360 bytes (1 KB under AWS's 16 KB user-data limit) with the longest values: it is ${length(base64gzip(output.cloud_init)) * 3 / 4}"
  }
}

run "the_box_does_not_run_its_own_backup_schedule" {
  command = apply

  assert {
    condition     = strcontains(output.cloud_init, "[backup]\n      enabled = false\n")
    error_message = "the box's own backup timer must be explicitly off: the dashboard server owns the schedule, and both on would back /work up twice"
  }
}

run "user_data_hands_secrets_setup_to_a_script_and_carries_no_secret" {
  command = apply

  assert {
    condition = (
      strcontains(output.cloud_init, "/usr/local/sbin/ozbox-secrets-setup.sh") &&
      strcontains(output.cloud_init, "[bash, /usr/local/sbin/ozbox-secrets-setup.sh, \"dev-1\"")
    )
    error_message = "the secrets setup script and the box's scope must be in the user data"
  }

  assert {
    # The helper scripts are plain text on AWS and the admin script names the legacy cloudflared.env (it migrates it
    # away), so the check is that no file of that name is WRITTEN by the user data, not that the word never appears.
    condition     = !strcontains(output.cloud_init, "TUNNEL_TOKEN=ey") && !can(regex("path: [^\n]*cloudflared\\.env", output.cloud_init))
    error_message = "no secret value or box-readable secret file may appear in the user data"
  }
}

run "the_daemon_caps_agent_runs_to_the_size_and_keeps_the_home_service_manager_reachable" {
  command = apply

  variables {
    runs_max_active = 6
  }

  assert {
    condition     = strcontains(output.cloud_init, "[runs]") && strcontains(output.cloud_init, "max_active = 6")
    error_message = "the daemon's configuration must carry the cap for the box's size"
  }

  assert {
    condition     = length(regexall("(?s)ozboxd\\.service\n.*?ProtectHome=read-only", output.cloud_init)) == 1
    error_message = "the daemon reaches the box user's service manager under /run/user, which ProtectHome=true hides"
  }
}

run "a_cap_outside_one_to_sixty_four_is_refused" {
  command = plan

  variables {
    runs_max_active = 0
  }

  expect_failures = [var.runs_max_active]
}

run "only_the_machines_own_services_reach_the_metadata_service" {
  command = apply

  assert {
    condition     = strcontains(output.cloud_init, "/usr/local/bin/ozbox host-guard metadata install aws ||") && length(regexall("(?s)host-guard metadata install.*enable, --now, ozboxd\\.service", output.cloud_init)) == 1
    error_message = "first boot installs the metadata guard before the box daemon starts"
  }
}

# The box's first approval key is pinned from outside the box: the label becomes a root-owned file at first boot.
run "a_pinned_approval_key_is_written_root_owned_at_first_boot" {
  command = apply

  variables {
    labels = { team = "example", "ozbox-approver" = "abcdefghijklmnopqrstuvwxyz234567abcdefghijklmnopqrst" }
  }

  assert {
    condition     = strcontains(output.cloud_init, "ozbox-secrets-setup.sh, \"dev-1\", \"\", \"\", \"abcdefghijklmnopqrstuvwxyz234567abcdefghijklmnopqrst\"]")
    error_message = "the pinned approval key must reach the root setup step from the label"
  }

  assert {
    condition     = length(base64gzip(output.cloud_init)) * 3 / 4 < 16384
    error_message = "the pin must still fit the 16 KB AWS user-data limit"
  }
}

run "no_pin_passes_an_empty_approval_key" {
  command = apply

  assert {
    condition     = strcontains(output.cloud_init, "ozbox-secrets-setup.sh, \"dev-1\", \"\", \"\", \"\"]")
    error_message = "a box made without a pin passes an empty key, and the setup step writes no file"
  }
}

run "a_malformed_pin_is_refused" {
  command = plan

  variables {
    labels = { "ozbox-approver" = "not-a-key" }
  }

  expect_failures = [var.labels]
}

# The ingress account (ADR 0029, amendment 9): the person's SSH key reaches first boot from a label, like the approval key.
run "the_ingress_account_is_made_at_first_boot_with_the_key_from_the_label" {
  command = apply

  variables {
    labels = { "ozbox-ingress" = "abcdefghijklmnopqrstuvwxyz234567abcdefghijklmnopqrst" }
  }

  assert {
    condition     = strcontains(output.cloud_init, "ozbox secrets ingress-setup 'abcdefghijklmnopqrstuvwxyz234567abcdefghijklmnopqrst'")
    error_message = "the ingress key must reach the setup step from the label"
  }

  assert {
    condition     = strcontains(output.cloud_init, "AllowUsers ozbox ozbox-ingress")
    error_message = "sshd must let the ingress account in, and only it besides the box user"
  }

  assert {
    condition     = strcontains(output.cloud_init, "--ingress-socket /run/ozbox-secrets/ingress/ingress.sock")
    error_message = "the secrets service must listen on the ingress socket"
  }

  assert {
    condition     = length(base64gzip(output.cloud_init)) * 3 / 4 < 16384
    error_message = "the ingress key must still fit the 16 KB AWS user-data limit"
  }
}

run "no_ingress_label_passes_an_empty_key_and_the_account_is_still_made" {
  command = apply

  assert {
    condition     = strcontains(output.cloud_init, "ozbox secrets ingress-setup ''")
    error_message = "a box with no ingress label still gets the account, with no key"
  }
}

run "a_malformed_ingress_key_is_refused" {
  command = plan

  variables {
    labels = { "ozbox-ingress" = "not-a-key" }
  }

  expect_failures = [var.labels]
}

# The 16 KB check with the longest values the variables allow, not only the defaults.
run "user_data_fits_the_limit_with_the_longest_values" {
  command = apply

  variables {
    box_name           = "a-box-name-that-is-forty-characters-long"
    region             = "ap-southeast-4"
    labels             = { team = "example", "ozbox-approver" = "abcdefghijklmnopqrstuvwxyz234567abcdefghijklmnopqrst", "ozbox-ingress" = "abcdefghijklmnopqrstuvwxyz234567abcdefghijklmnopqrst" }
    secrets_key_arn    = "arn:aws:kms:ap-southeast-4:123456789012:key/01234567-89ab-cdef-0123-456789abcdef"
    fleet              = "a-fleet-name"
    agent_release_repo = "an-owner-name-of-thirty-nine-characters/a-repository-name-that-is-quite-a-lot-longer-than-any-real-one-would-be"
    agent_release_tag  = "image-v123.456.789-rc.123456789"
    runs_max_active    = 64
  }

  assert {
    condition     = length(base64gzip(output.cloud_init)) * 3 / 4 < 16384
    error_message = "the compressed first-boot configuration must stay under the 16 KB AWS user-data limit with the longest values"
  }
}
