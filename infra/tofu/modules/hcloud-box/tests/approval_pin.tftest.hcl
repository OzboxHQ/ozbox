# The box's first approval key, pinned from outside the box (its own file: user_data is read only at creation, so state is
# per file). Runs with no credentials and no network: the provider is mocked.

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
}

# The label becomes a root-owned file at first boot; a base32 key fits a Hetzner label value (63 characters).
run "a_pinned_approval_key_is_written_root_owned_at_first_boot" {
  command = apply

  # with the longest box-secrets declaration too, so the size check below measures the worst case
  variables {
    labels                 = { "ozbox-approver" = "abcdefghijklmnopqrstuvwxyz234567abcdefghijklmnopqrst" }
    box_secrets_backend    = "openbao"
    box_secrets_prefix     = "/ozbox/a-long-prefix-for-the-size-check"
    box_role               = "a-role-name-of-thirty-two-chars"
    box_secrets_vault_addr = "https://vault.a-long-vault-host-name-for-the-size-check.example.com:8200"
  }

  assert {
    condition     = length(hcloud_server.box.user_data) < 32768
    error_message = "Hetzner accepts at most 32 KB of user data, and the pin must still fit"
  }

  assert {
    condition     = strcontains(hcloud_server.box.user_data, "ozbox-secrets-setup.sh, \"dev-1\", \"\", \"\", \"abcdefghijklmnopqrstuvwxyz234567abcdefghijklmnopqrst\"]")
    error_message = "the pinned approval key must reach the root setup step from the label"
  }
}

run "a_malformed_ingress_key_is_refused" {
  command = plan

  variables {
    labels = { "ozbox-ingress" = "not-a-key" }
  }

  expect_failures = [var.labels]
}

run "a_malformed_pin_is_refused" {
  command = plan

  variables {
    labels = { "ozbox-approver" = "not-a-key" }
  }

  expect_failures = [var.labels]
}
