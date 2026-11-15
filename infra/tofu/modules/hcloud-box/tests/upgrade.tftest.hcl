# An upgrade is `apply -replace=hcloud_server.box` with a new image_id, applied on top of a real box. These runs share state,
# as `tofu test` runs in one file do: a box is created, then the module is PLANNED with the replacement, and the plan must
# build the server from the current configuration (new image, new first-boot configuration) while the /work volume keeps its
# id (a volume that was to be replaced would have an id "known after apply", and the condition below could not be evaluated,
# which fails the run).

# Runs with no credentials and no network: the provider is mocked.

mock_provider "hcloud" {
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

run "create" {
  command = apply
}

run "without_a_replace_a_new_image_or_new_user_data_does_not_touch_the_server" {
  command = plan

  variables {
    image_id = "654321"
    labels   = { team = "example", "ozbox-approver" = "abcdefghijklmnopqrstuvwxyz234567abcdefghijklmnopqrst" }
  }

  assert {
    condition     = hcloud_server.box.image == "123456" && !strcontains(hcloud_server.box.user_data, "abcdefghijklmnopqrstuvwxyz234567abcdefghijklmnopqrst")
    error_message = "a changed image or first-boot configuration must not plan a replacement on its own (only an upgrade, with -replace, builds from them)"
  }
}

run "an_upgrade_replaces_the_server_from_the_current_configuration_and_keeps_the_work_volume" {
  command = plan

  plan_options {
    replace = [hcloud_server.box]
  }

  variables {
    image_id = "654321"
    labels   = { team = "example", "ozbox-approver" = "abcdefghijklmnopqrstuvwxyz234567abcdefghijklmnopqrst" }
  }

  assert {
    condition     = hcloud_server.box.image == "654321"
    error_message = "the server must be built from the new image"
  }

  assert {
    condition     = strcontains(hcloud_server.box.user_data, "abcdefghijklmnopqrstuvwxyz234567abcdefghijklmnopqrst")
    error_message = "the replacement must carry the CURRENT first-boot configuration (here, a newly pinned approver): that is the point of replacing rather than rebuilding"
  }

  assert {
    condition     = tostring(hcloud_volume.work.id) == "2002" && tostring(output.work_volume_id) == "2002"
    error_message = "an upgrade must keep the very same /work volume (its id must not be unknown in the plan)"
  }

  assert {
    condition     = hcloud_volume.work.size == 200
    error_message = "an upgrade must not change the /work volume"
  }

  assert {
    condition     = hcloud_firewall.box.name == "ozbox-dev-1" && length(hcloud_firewall.box.rule) == 0
    error_message = "the firewall is kept and still has no rules"
  }
}

# The upgrade passes the box's size, so a resize made since the box was created is not undone.
run "a_resized_box_keeps_its_machine_type_and_disk_through_an_upgrade" {
  command = plan

  plan_options {
    replace = [hcloud_server.box]
  }

  variables {
    image_id     = "654321"
    machine_type = "ccx53"
    work_disk_gb = 300
  }

  assert {
    condition     = hcloud_server.box.server_type == "ccx53" && hcloud_volume.work.size == 300
    error_message = "the planned server and volume follow the variables the adapter passes, which are the box as it is now"
  }
}
