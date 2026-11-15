# The person's SSH key for the ingress account (its own file: user_data is read only at creation, so state is per file).
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
}

# The person's SSH key for the ingress account (ADR 0029, amendment 9), with the approval key and the longest box-secrets
# declaration too: the user data must still fit Hetzner's 32 KB.
run "an_ingress_key_is_written_at_first_boot_and_the_user_data_still_fits" {
  command = apply

  variables {
    labels = {
      "ozbox-approver" = "abcdefghijklmnopqrstuvwxyz234567abcdefghijklmnopqrst"
      "ozbox-ingress"  = "zyxwvutsrqponmlkjihgfedcba234567zyxwvutsrqponmlkjihg"
    }
    box_secrets_backend    = "openbao"
    box_secrets_prefix     = "/ozbox/a-long-prefix-for-the-size-check"
    box_role               = "a-role-name-of-thirty-two-chars"
    box_secrets_vault_addr = "https://vault.a-long-vault-host-name-for-the-size-check.example.com:8200"
  }

  assert {
    condition     = length(hcloud_server.box.user_data) < 32768
    error_message = "Hetzner accepts at most 32 KB of user data, and the ingress key must still fit"
  }

  assert {
    condition     = strcontains(hcloud_server.box.user_data, "ozbox secrets ingress-setup 'zyxwvutsrqponmlkjihgfedcba234567zyxwvutsrqponmlkjihg'")
    error_message = "the ingress key must reach the setup step from the label"
  }
}

