# The box's own secrets declaration on a provider with no instance tags: a settings file written at first boot. Runs with
# no credentials and no network: the provider is mocked.

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

run "an_openbao_declaration_becomes_the_loaders_settings_file_and_nothing_else" {
  command = apply

  variables {
    box_secrets_backend    = "openbao"
    box_secrets_prefix     = "/ozbox/dev"
    box_role               = "main"
    box_secrets_vault_addr = "https://vault.example.com:8200"
  }

  assert {
    condition     = strcontains(hcloud_server.box.user_data, "path: /etc/ozbox/box-secrets.env") && strcontains(hcloud_server.box.user_data, "encoding: b64")
    error_message = "the declaration must be written as the loader's settings file"
  }

  assert {
    condition     = strcontains(base64decode(local.box_secrets_env_b64), "OZBOX_BOX_SECRETS_BACKEND=openbao\nOZBOX_BOX_SECRETS_PATH=/ozbox/dev\nOZBOX_BOX_ROLE=main\nBAO_ADDR=https://vault.example.com:8200\n")
    error_message = "the settings file must be exactly the names the loader reads"
  }

  assert {
    condition     = length(hcloud_server.box.user_data) < 32768
    error_message = "a declared box's first-boot configuration must still fit the 32 KB Hetzner user-data limit"
  }

  assert {
    condition     = !strcontains(lower(local.box_secrets_env), "token") && !strcontains(hcloud_server.box.user_data, "BAO_TOKEN")
    error_message = "a vault token must never be in user data: every process on the box can read it"
  }
}

run "only_openbao_is_offered_on_hetzner" {
  command = plan

  variables {
    box_secrets_backend = "aws-ssm"
    box_secrets_prefix  = "/ozbox/dev"
    box_role            = "main"
  }

  expect_failures = [var.box_secrets_backend]
}

run "a_declaration_needs_a_path_and_a_role" {
  command = plan

  variables {
    box_secrets_backend = "openbao"
  }

  expect_failures = [hcloud_server.box]
}

run "a_path_with_dots_or_a_bad_address_is_refused" {
  command = plan

  variables {
    box_secrets_backend    = "openbao"
    box_secrets_prefix     = "/a/../b"
    box_role               = "main"
    box_secrets_vault_addr = "http://vault.example.com"
  }

  expect_failures = [var.box_secrets_prefix, var.box_secrets_vault_addr]
}
