variable "box_name" {
  type        = string
  description = "Validated box name: lowercase letters, digits and single hyphens, starting with a letter, at most 40 characters."

  validation {
    condition     = can(regex("^[a-z]([a-z0-9-]{0,38}[a-z0-9])?$", var.box_name))
    error_message = "box_name must start with a lowercase letter, contain only lowercase letters, digits and hyphens, end with a letter or digit, and be at most 40 characters."
  }

  validation {
    condition     = !strcontains(var.box_name, "--")
    error_message = "box_name must not contain two hyphens in a row."
  }
}

variable "machine_type" {
  type        = string
  description = "Hetzner server type the adapter mapped the size to, for example ccx43."
}

variable "work_disk_gb" {
  type        = number
  description = "Size of the persistent /work volume in GB (Hetzner volumes are 10 to 10240)."

  validation {
    condition     = var.work_disk_gb >= 10
    error_message = "Hetzner volumes are at least 10 GB."
  }
}

variable "image_id" {
  type        = string
  description = "Image (snapshot) id or name to boot the root disk from."
}

variable "region" {
  type        = string
  description = "Hetzner location, for example fsn1 or ash."
}

variable "labels" {
  type        = map(string)
  default     = {}
  description = "Extra labels. ozbox-box and ozbox-managed are always set by the module and cannot be overridden. Hetzner label values allow letters, digits, hyphens, underscores and dots."
  # ozbox-approver pins the box's first approval key (an Ed25519 public key, lowercase base32): first boot writes it to a
  # root-owned file and the secrets service enrols it, so the first approver never comes from inside the box.
  validation {
    condition     = !contains(keys(var.labels), "ozbox-approver") || can(regex("^[a-z2-7]{52}$", lookup(var.labels, "ozbox-approver", "")))
    error_message = "The ozbox-approver label must be an Ed25519 public key in lowercase base32 (52 characters)."
  }
  # ozbox-ingress pins the SSH public key of the computer that reaches the box's secrets service through the ingress account
  # (ADR 0029 amendment 9): first boot writes it to a root-owned file no process of the box user can change.
  validation {
    condition     = !contains(keys(var.labels), "ozbox-ingress") || can(regex("^[a-z2-7]{52}$", lookup(var.labels, "ozbox-ingress", "")))
    error_message = "The ozbox-ingress label must be an Ed25519 SSH public key in lowercase base32 (52 characters)."
  }
}

variable "work_snapshot_id" {
  type        = string
  default     = ""
  description = "Not supported on Hetzner: volumes cannot be created from a snapshot. Must stay empty; the adapter restores a clone by copying data instead."

  validation {
    condition     = var.work_snapshot_id == ""
    error_message = "Hetzner Cloud volumes cannot be restored from a snapshot. Leave work_snapshot_id empty and clone /work by copying data over the private network."
  }
}

variable "network_id" {
  type        = number
  default     = null
  description = "Attach the server to this private network (for a WireGuard or other mesh). null attaches none."
}

variable "agent_release_repo" {
  type        = string
  default     = "OzboxHQ/ozbox"
  description = "GitHub repository (owner/name) whose signed image release carries ozboxd, for a machine that is not the Oz image. The Oz image carries its own and ignores this."

  validation {
    condition     = can(regex("^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$", var.agent_release_repo))
    error_message = "agent_release_repo must look like owner/name."
  }
}

variable "runs_max_active" {
  type        = number
  default     = 64
  description = "The most agent runs the box daemon runs at once. The adapter sets it from the size (XS 1, S 2, M 4, L 6, XL 8, XXL 16)."

  validation {
    condition     = var.runs_max_active >= 1 && var.runs_max_active <= 64 && floor(var.runs_max_active) == var.runs_max_active
    error_message = "runs_max_active must be a whole number from 1 to 64."
  }
}

variable "agent_release_tag" {
  type        = string
  default     = ""
  description = "The image release (image-v<version>) to take ozboxd from on a machine that is not the Oz image. Empty: the newest image release."

  validation {
    condition     = var.agent_release_tag == "" || can(regex("^image-v[0-9a-z.-]+$", var.agent_release_tag))
    error_message = "agent_release_tag must be empty or look like image-v2026.11.09."
  }
}

variable "box_secrets_backend" {
  type        = string
  default     = null
  description = "Where this box's own secrets (Staging keys for its role) are kept. Only openbao on Hetzner: there is no instance role to read Parameter Store with. null: the box keeps none. Written at first boot as /etc/ozbox/box-secrets.env; changing it on an existing server replaces the server (its first-boot configuration changes), so use `ozbox box-secrets` for a live box."

  validation {
    condition     = var.box_secrets_backend == null || coalesce(var.box_secrets_backend, "-") == "openbao"
    error_message = "box_secrets_backend must be openbao on Hetzner."
  }
}

variable "box_secrets_prefix" {
  type        = string
  default     = null
  description = "The path prefix the box's secrets live under in the vault, like /ozbox/dev. The box reads <prefix>/<box_role> and below."

  validation {
    condition     = var.box_secrets_prefix == null || can(regex("^/[A-Za-z0-9_-]+(/[A-Za-z0-9_-]+)*$", coalesce(var.box_secrets_prefix, "/")))
    error_message = "box_secrets_prefix must start with / and hold plain path segments (letters, digits, _ and -), with no trailing slash and no dots."
  }

  validation {
    condition     = var.box_secrets_prefix == null || length(coalesce(var.box_secrets_prefix, "")) <= 100
    error_message = "box_secrets_prefix must be at most 100 characters."
  }
}

variable "box_role" {
  type        = string
  default     = null
  description = "The box's role, the path segment its secrets are scoped by (like main or worker). Required with box_secrets_backend."

  validation {
    condition     = var.box_role == null || can(regex("^[a-z0-9-]{1,32}$", coalesce(var.box_role, "-")))
    error_message = "box_role must be 1 to 32 lowercase letters, digits and dashes."
  }
}

variable "box_secrets_mount" {
  type        = string
  default     = "secret"
  description = "The OpenBao KV mount the box reads."

  validation {
    condition     = can(regex("^[a-z0-9_-]{1,32}$", var.box_secrets_mount))
    error_message = "box_secrets_mount must be 1 to 32 lowercase letters, digits, dashes and underscores."
  }
}

variable "box_secrets_vault_addr" {
  type        = string
  default     = null
  description = "The OpenBao address, https://host or https://host:port. An address is not a secret; the token is, and is never a variable (place it with `ozbox admin <box> -- place-bao-token`)."

  validation {
    condition     = var.box_secrets_vault_addr == null || can(regex("^https://[a-z0-9]([a-z0-9.-]*[a-z0-9])?(:[0-9]{2,5})?$", coalesce(var.box_secrets_vault_addr, "-")))
    error_message = "box_secrets_vault_addr must be https://host or https://host:port."
  }
}

variable "first_boot_sha256" {
  type        = string
  default     = ""
  description = "The first-boot hash of the modules and cloud-init the program renders (the ozbox program passes it). Recorded on the box in /etc/ozbox/first-boot, so an upgrade can tell a box made with another first-boot configuration. Empty records nothing to compare."

  validation {
    condition     = can(regex("^([0-9a-f]{64})?$", var.first_boot_sha256))
    error_message = "first_boot_sha256 must be empty or a lowercase SHA-256 in hex."
  }
}
