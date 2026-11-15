# No declaration: no settings file (its own file: user_data is read only at creation, so state is per file). Runs with
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

run "no_declaration_writes_no_settings_file" {
  command = apply

  assert {
    condition     = !strcontains(hcloud_server.box.user_data, "path: /etc/ozbox/box-secrets.env")
    error_message = "a box with no declaration must not carry a box-secrets.env"
  }
}

