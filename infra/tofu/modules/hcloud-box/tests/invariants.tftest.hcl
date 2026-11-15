# Runs with no credentials and no network: the provider is mocked.

mock_provider "hcloud" {
  # Hetzner ids are numbers; the default mock would invent strings.
  mock_resource "hcloud_firewall" {
    defaults = { id = 1001 }
  }
  mock_resource "hcloud_volume" {
    defaults = { id = 2002 }
  }
  mock_resource "hcloud_server" {
    defaults = { id = 3003 }
  }
}

variables {
  box_name     = "dev-1"
  machine_type = "ccx43"
  work_disk_gb = 200
  image_id     = "123456"
  region       = "fsn1"
  labels       = { team = "example" }
}

run "no_inbound_rules" {
  command = apply

  assert {
    condition     = length(hcloud_firewall.box.rule) == 0
    error_message = "the firewall must have zero rules, so every inbound connection is dropped"
  }

  assert {
    condition     = contains(hcloud_server.box.firewall_ids, tonumber(hcloud_firewall.box.id))
    error_message = "the firewall must be attached to the server"
  }
}

run "server_uses_requested_image_and_type" {
  command = apply

  assert {
    condition     = hcloud_server.box.server_type == "ccx43" && hcloud_server.box.image == "123456" && hcloud_server.box.location == "fsn1"
    error_message = "the server must use the requested type, image and location"
  }

  assert {
    condition     = output.machine_type == "ccx43"
    error_message = "machine_type output must echo the type used"
  }
}

run "work_volume_is_separate" {
  command = apply

  assert {
    condition     = hcloud_volume.work.size == 200
    error_message = "/work must have the requested size"
  }

  assert {
    condition     = tostring(hcloud_volume_attachment.work.volume_id) == tostring(hcloud_volume.work.id)
    error_message = "/work must be attached as its own volume"
  }

  assert {
    condition     = output.work_volume_id == hcloud_volume.work.id
    error_message = "work_volume_id output must be the /work volume"
  }
}

run "labels_on_every_resource" {
  command = apply

  assert {
    condition = alltrue([
      for t in [
        hcloud_server.box.labels,
        hcloud_volume.work.labels,
        hcloud_firewall.box.labels,
      ] : t["ozbox-box"] == "dev-1" && t["ozbox-managed"] == "true" && t["team"] == "example"
    ])
    error_message = "every resource needs ozbox-box, ozbox-managed and the caller's labels"
  }
}

run "caller_cannot_override_reserved_labels" {
  command = apply

  variables {
    labels = { "ozbox-box" = "other", "ozbox-managed" = "false" }
  }

  assert {
    condition     = hcloud_server.box.labels["ozbox-box"] == "dev-1" && hcloud_server.box.labels["ozbox-managed"] == "true"
    error_message = "reserved labels are set by the module"
  }
}

run "snapshot_restore_is_rejected" {
  command = plan

  variables {
    work_snapshot_id = "12345"
  }

  expect_failures = [var.work_snapshot_id]
}

run "private_network_is_optional" {
  command = apply

  variables {
    network_id = 4242
  }

  assert {
    condition     = length(hcloud_server.box.network) == 1
    error_message = "the server must attach to the private network when one is given"
  }
}

run "user_data_carries_no_reviewer_comments_but_keeps_the_cloud_config_header" {
  command = apply

  assert {
    condition     = startswith(hcloud_server.box.user_data, "#cloud-config\n") && !can(regex("(?m)^[ \t]+# ", hcloud_server.box.user_data))
    error_message = "Hetzner's user data is sent without the template's comment lines, which leaves room under its 32 KB limit"
  }
}

# A security review (2026-11-11): the comment-stripping pattern ran over the rendered user data, so a line of a file's
# content that starts with `#` and means something (an `#include`, a sudoers `#includedir`) would be dropped silently. It
# now runs over the template's own text before anything is put into it.
run "comments_are_dropped_from_the_template_text_not_from_what_is_put_into_it" {
  command = apply

  assert {
    condition     = !can(regex("(?m)^[ \t]*#[^!]", local.template_text)) && strcontains(local.template_text, "write_files:")
    error_message = "the template's own comment lines are dropped before it is rendered, and nothing else of it"
  }

  assert {
    condition     = strcontains(hcloud_server.box.user_data, "path: /usr/local/sbin/ozbox-admin.sh") && strcontains(hcloud_server.box.user_data, "hostname: dev-1")
    error_message = "what the template puts in is still there after the comments are dropped"
  }

  # The Hetzner render has only about 1 to 2 KB of headroom under 32,768 bytes: measure the next template addition here.
  assert {
    condition     = length(hcloud_server.box.user_data) < 32768
    error_message = "Hetzner takes at most 32 KB of user data"
  }
}

run "user_data_creates_the_repos_directory_for_the_box_user" {
  command = apply

  assert {
    condition     = strcontains(hcloud_server.box.user_data, "install -d -m 0750 -o ozbox -g ozbox /work/repos")
    error_message = "cloud-init must create /work/repos owned by the box user, on a new disk and an existing one"
  }

  assert {
    condition = (
      strcontains(hcloud_server.box.user_data, "ozbox-tools.path") &&
      strcontains(hcloud_server.box.user_data, "d /run/ozbox-tools/requests 1770 root ozbox") &&
      !strcontains(hcloud_server.box.user_data, "ProtectHome=false")
    )
    error_message = "the tool installer's privileged helper must be a path-triggered one-shot with a sticky request directory"
  }
}

run "user_data_mounts_work_only_when_empty" {
  command = apply

  assert {
    condition     = strcontains(hcloud_server.box.user_data, "blkid -p") && strcontains(hcloud_server.box.user_data, "wipefs -n") && strcontains(hcloud_server.box.user_data, "nofail")
    error_message = "cloud-init must detect an existing filesystem and mount with nofail"
  }
}

run "box_name_valid_example" {
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

run "user_data_grows_the_filesystem_with_least_privilege" {
  command = apply

  assert {
    condition = (
      strcontains(hcloud_server.box.user_data, "ozbox-growfs.service") &&
      strcontains(hcloud_server.box.user_data, "ozbox-growfs.timer") &&
      strcontains(hcloud_server.box.user_data, "CapabilityBoundingSet=CAP_SYS_ADMIN CAP_SYS_RESOURCE") &&
      strcontains(hcloud_server.box.user_data, "PrivateNetwork=true") &&
      strcontains(hcloud_server.box.user_data, "NoNewPrivileges=true") &&
      strcontains(hcloud_server.box.user_data, "Wants=network-online.target ozbox-growfs.service")
    )
    error_message = "the filesystem grows through a dedicated one-shot unit with one capability and no network, never through the unprivileged daemon"
  }

  assert {
    condition     = strcontains(hcloud_server.box.user_data, "resize2fs") && strcontains(hcloud_server.box.user_data, "xfs_growfs")
    error_message = "cloud-init must grow ext4 and xfs filesystems"
  }
}

run "user_data_keeps_ssh_on_loopback_for_the_box_user_only" {
  command = apply

  assert {
    condition = (
      strcontains(hcloud_server.box.user_data, "ListenAddress 127.0.0.1") &&
      strcontains(hcloud_server.box.user_data, "AllowUsers ozbox") &&
      strcontains(hcloud_server.box.user_data, "AuthenticationMethods publickey") &&
      strcontains(hcloud_server.box.user_data, "PasswordAuthentication no")
    )
    error_message = "sshd must listen on loopback only and accept only keys, for the ozbox user only"
  }
}

run "user_data_has_no_instance_connect_off_aws" {
  command = apply

  assert {
    condition     = !strcontains(hcloud_server.box.user_data, "ec2-instance-connect")
    error_message = "only an AWS box installs EC2 Instance Connect"
  }
}

run "user_data_installs_the_backup_credentials_helper_with_a_narrow_hand_off" {
  command = apply

  assert {
    condition     = strcontains(hcloud_server.box.user_data, "ExecStart=/usr/local/bin/ozboxd backup-root") && strcontains(hcloud_server.box.user_data, "d /run/ozbox-backup/requests 1770 root ozbox -")
    error_message = "backup credentials reach the box only through the root helper and a sticky request directory"
  }

  assert {
    condition     = strcontains(hcloud_server.box.user_data, "ReadWritePaths=/etc/ozbox /run/ozbox-backup") && strcontains(hcloud_server.box.user_data, "ReadWritePaths=-/run/ozbox-backup/requests")
    error_message = "the helper may write only /etc/ozbox and its spool, and the daemon only the request directory"
  }
}

run "user_data_gets_ozboxd_only_from_the_signed_release_and_never_on_the_oz_image" {
  command = apply

  assert {
    condition     = strcontains(hcloud_server.box.user_data, "/usr/local/sbin/ozbox-install-agent.sh ||") && strcontains(hcloud_server.box.user_data, "OZBOX_RELEASE_REPO=\"OzboxHQ/ozbox\"") && strcontains(hcloud_server.box.user_data, "OZBOX_RELEASE_TAG=\"\"")
    error_message = "first boot installs ozboxd from the signed release of the configured repository"
  }

  assert {
    condition     = strcontains(hcloud_server.box.user_data, "path: /usr/local/sbin/ozbox-install-agent.sh") && strcontains(hcloud_server.box.user_data, "encoding: gz+b64")
    error_message = "the installer is written to the machine (compressed) so a stock machine can run it"
  }
}

run "user_data_re_owns_old_files_before_any_service_starts" {
  command = apply

  assert {
    condition     = strcontains(hcloud_server.box.user_data, "/usr/local/sbin/ozbox-reown.sh ||") && strcontains(hcloud_server.box.user_data, "path: /usr/local/sbin/ozbox-reown.sh")
    error_message = "the work-setup script re-owns files that carry an old box user id"
  }

  assert {
    condition     = length(regexall("(?s)ozbox-work-setup\\.sh\\].*ozbox-install-agent\\.sh \\|\\|.*enable, --now, ozboxd\\.service", hcloud_server.box.user_data)) == 1
    error_message = "work setup (and so the re-own) runs before ozboxd is installed or any service is enabled"
  }
}

run "user_data_installs_the_narrow_root_admin_path" {
  command = apply

  assert {
    condition     = strcontains(hcloud_server.box.user_data, "ExecStart=/usr/local/sbin/ozbox-admin.sh") && strcontains(hcloud_server.box.user_data, "d /run/ozbox-admin/requests 1770 root ozbox -")
    error_message = "admin actions reach root only through a sticky request directory and one allow-listed script"
  }

  assert {
    condition     = !strcontains(hcloud_server.box.user_data, "sudoers") && !strcontains(hcloud_server.box.user_data, "NOPASSWD")
    error_message = "the box user gets no sudo"
  }

  assert {
    condition     = !strcontains(hcloud_server.box.user_data, "ConditionPathExists=/usr/local/bin/ozboxd\n\n      # It does not depend on ozboxd")
    error_message = "the admin helper must not need ozboxd, it is how ozboxd is put back"
  }
}

run "user_data_fits_the_providers_limit" {
  command = apply

  assert {
    condition     = startswith(hcloud_server.box.user_data, "#cloud-config\n")
    error_message = "the first line must stay the cloud-config marker when comments are dropped"
  }

  assert {
    condition     = length(regexall("(?m)^[ \t]*#[^!]", hcloud_server.box.user_data)) == 1
    error_message = "comment lines of the template are dropped on Hetzner (only the marker and #! lines stay)"
  }

  assert {
    condition     = length(hcloud_server.box.user_data) < 32768
    error_message = "the first-boot configuration must stay under the 32 KB Hetzner user-data limit"
  }
}

run "the_box_does_not_run_its_own_backup_schedule" {
  command = apply

  assert {
    condition     = length(regexall("\\[backup\\]\n      enabled = false\n", hcloud_server.box.user_data)) == 1
    error_message = "the box's own backup timer must be explicitly off: the dashboard server owns the schedule, and both on would back /work up twice"
  }
}

run "the_daemon_caps_agent_runs_to_the_size_and_keeps_the_home_service_manager_reachable" {
  command = apply

  variables {
    runs_max_active = 6
  }

  assert {
    condition     = strcontains(hcloud_server.box.user_data, "[runs]") && strcontains(hcloud_server.box.user_data, "max_active = 6")
    error_message = "the daemon's configuration must carry the cap for the box's size"
  }

  assert {
    condition     = length(regexall("(?s)ozboxd\\.service\n.*?ProtectHome=read-only", hcloud_server.box.user_data)) == 1
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
    condition     = strcontains(hcloud_server.box.user_data, "/usr/local/bin/ozbox host-guard metadata install hcloud ||") && length(regexall("(?s)host-guard metadata install.*enable, --now, ozboxd\\.service", hcloud_server.box.user_data)) == 1
    error_message = "first boot installs the metadata guard before the box daemon starts"
  }
}
