# The first-boot hash the program passes reaches the box's own record (its own file: user_data is read only at creation,
# so state is per file). Runs with no credentials and no network: the provider is mocked.

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
  box_name          = "dev-1"
  machine_type      = "ccx43"
  work_disk_gb      = 200
  image_id          = "123456"
  region            = "fsn1"
  first_boot_sha256 = "1111111111111111111111111111111111111111111111111111111111111111"
}

# The comment lines of the template are dropped for Hetzner's size limit; the line that writes the record must survive.
run "the_record_line_survives_the_comment_stripping" {
  command = apply

  assert {
    condition     = strcontains(hcloud_server.box.user_data, "printf 'first_boot_sha256=%s\\n' '1111111111111111111111111111111111111111111111111111111111111111' >/etc/ozbox/first-boot")
    error_message = "the first-boot configuration must write the hash it was rendered with to the box's own record"
  }
}

run "the_first_boot_hash_must_be_a_lowercase_sha256" {
  command = plan

  variables {
    first_boot_sha256 = "1111111111111111111111111111111111111111111111111111111111111111A"
  }

  expect_failures = [var.first_boot_sha256]
}
