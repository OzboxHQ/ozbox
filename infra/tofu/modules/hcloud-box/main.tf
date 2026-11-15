# One Oz Box on Hetzner Cloud. Its variables and outputs are the contract the provider adapters rely on.
#
# Invariants (asserted in tests/invariants.tftest.hcl):
#   - the firewall has ZERO inbound rules and is attached to the server
#   - the public IP exists only so the box can dial out; nothing can dial in
#   - /work is a standalone volume, so replacing the server (an upgrade) keeps the data
#
# Hetzner volumes cannot be created from a snapshot. Cloning /work on this provider is therefore
# done by the adapter by copying data (see variables.tf); work_snapshot_id must stay empty.

locals {
  labels = merge(var.labels, {
    "ozbox-box"     = var.box_name
    "ozbox-managed" = "true"
  })

  # The box's own secrets declaration. Hetzner has no instance tags the box can read, so it is the settings file the loader
  # reads, written at first boot. It holds names and an address, never a secret: user data is readable by every process on
  # the box, so the vault token is placed afterwards through the root helper (`ozbox admin <box> -- place-bao-token`).
  # The text is the same shape `ozbox admin <box> -- write-box-secrets` writes (tests/ pins both).
  box_secrets_env = var.box_secrets_backend == null ? "" : join("\n", concat([
    "# written by ozbox write-box-secrets (no instance tags here)",
    "OZBOX_BOX_SECRETS_BACKEND=${var.box_secrets_backend}",
    "OZBOX_BOX_SECRETS_PATH=${var.box_secrets_prefix == null ? "" : var.box_secrets_prefix}",
    "OZBOX_BOX_ROLE=${var.box_role == null ? "" : var.box_role}",
  ], var.box_secrets_mount == "secret" ? [] : ["OZBOX_BOX_SECRETS_MOUNT=${var.box_secrets_mount}"], var.box_secrets_vault_addr == null ? [] : ["BAO_ADDR=${var.box_secrets_vault_addr}"], [""]))

  box_secrets_env_b64 = base64encode(local.box_secrets_env)

  # The first-boot template with its own comment lines removed (a `#!` line stays), before anything is put into it.
  template_text = replace(file("${path.module}/../../../cloud-init/box.yaml.tftpl"), "/(?m)^[ \t]*#([^!\n].*)?\n/", "")

  # Hetzner exposes an attached volume at a stable by-id path.
  work_device = "/dev/disk/by-id/scsi-0HC_Volume_${hcloud_volume.work.id}"
}

# A firewall with no rules drops all inbound traffic. Outbound is unrestricted.
resource "hcloud_firewall" "box" {
  name   = "ozbox-${var.box_name}"
  labels = local.labels
  # Deliberately NO rule blocks: nothing may connect to the box.
}

resource "hcloud_volume" "work" {
  name     = "ozbox-${var.box_name}-work"
  size     = var.work_disk_gb
  location = var.region
  format   = null # formatted by cloud-init, and only when empty
  labels   = merge(local.labels, { "ozbox-role" = "work" })

  lifecycle {
    # Two labels the CLI writes on this volume (it survives the server being replaced) mark an upgrade in progress: the image
    # it is going to, and the server type the box ran, which is all that remains of a server that was removed before its
    # replacement could be created. An apply must neither strip nor re-add them.
    ignore_changes = [labels["ozbox-upgrade-to"], labels["ozbox-upgrade-machine"]]
  }
}

resource "hcloud_server" "box" {
  name         = "ozbox-${var.box_name}"
  server_type  = var.machine_type
  image        = var.image_id
  location     = var.region
  firewall_ids = [hcloud_firewall.box.id]
  labels       = local.labels

  # Hetzner takes 32 KB of user data, counted as sent, so the comment lines of the template's own text are dropped
  # before it is rendered, as they are from the helper scripts (a `#!` line stays). What the template puts in (a file's
  # content, a value) is left exactly as it is: a line of content that starts with `#` keeps its meaning. The first line,
  # the cloud-config marker, is put back.
  user_data = "#cloud-config\n${templatestring(local.template_text, {
    box_name           = var.box_name
    work_device        = local.work_device
    provider           = "hcloud"
    secrets_kms_key_id = ""
    secrets_kms_region = ""
    scripts_dir        = "${path.module}/../../../cloud-init/scripts"
    # Where a machine that is not the Oz image gets its box daemon (the image carries its own).
    agent_release_repo = var.agent_release_repo
    agent_release_tag  = var.agent_release_tag
    runs_max_active    = var.runs_max_active
    # The module's own declaration; the box cannot verify it from inside (see the self-test).
    work_encrypted  = "false"
    box_secrets_env = local.box_secrets_env
    # The box's first approval key, pinned when it was made ("" for none; see the labels variable).
    approval_key = lookup(var.labels, "ozbox-approver", "")
    # Which first-boot configuration this is, recorded on the box ("" when the program gave none).
    first_boot_sha256 = var.first_boot_sha256
    # This computer's key for the ingress account, pinned when the box was made ("" for none; see the labels variable).
    ingress_key = lookup(var.labels, "ozbox-ingress", "")
  })}"

  # The public address is for outbound traffic only; the firewall drops everything inbound.
  public_net {
    ipv4_enabled = true
    ipv6_enabled = true
  }

  dynamic "network" {
    for_each = var.network_id == null ? [] : [var.network_id]
    content {
      network_id = network.value
    }
  }

  lifecycle {
    prevent_destroy = false
    precondition {
      condition     = var.box_secrets_backend == null || (var.box_secrets_prefix != null && var.box_role != null)
      error_message = "box_secrets_prefix and box_role are required with box_secrets_backend."
    }
    # An upgrade is `tofu apply -replace=hcloud_server.box` with a new image_id: the server is destroyed and created again
    # from the CURRENT configuration (the new image and the new first-boot configuration, which Hetzner keeps for a
    # server's life and runs again on a rebuilt disk, so a rebuild could never deliver it). The attachment is replaced with
    # it; the volume above is a separate resource nothing depends on, so /work is kept (tests/upgrade.tftest.hcl holds this).
    # Outside an upgrade a changed image or user_data must NOT plan a replacement: the state would otherwise name the image
    # of the last upgrade only, and a server brought back into the state by `ozbox adopt` would plan one for user_data,
    # which Hetzner cannot return. `-replace` is not an in-place diff, so these are still built from the current values.
    ignore_changes = [image, user_data]
  }
}

resource "hcloud_volume_attachment" "work" {
  volume_id = hcloud_volume.work.id
  server_id = hcloud_server.box.id
  automount = false
}
