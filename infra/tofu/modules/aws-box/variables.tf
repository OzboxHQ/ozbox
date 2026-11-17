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
  description = "EC2 instance type the adapter mapped the size to, for example m7i.4xlarge."
}

variable "work_disk_gb" {
  type        = number
  description = "Size of the persistent /work volume in GiB."

  validation {
    condition     = var.work_disk_gb >= 1
    error_message = "work_disk_gb must be at least 1."
  }
}

variable "image_id" {
  type        = string
  description = "AMI id to boot the root disk from."
}

variable "region" {
  type        = string
  description = "AWS region. The caller configures the provider with it; the module records it in a tag."
}

variable "labels" {
  type        = map(string)
  default     = {}
  description = "Extra tags. ozbox-box and ozbox-managed are always set by the module and cannot be overridden."
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
  # ozbox-fleet-manager marks the box that manages the fleet; only the fleet_manager variable sets it (ADR 0040 §8).
  validation {
    condition     = !contains(keys(var.labels), "ozbox-fleet-manager")
    error_message = "ozbox-fleet-manager is set by the fleet_manager variable, never as a label."
  }
}

variable "work_snapshot_id" {
  type        = string
  default     = ""
  description = "Restore /work from this EBS snapshot (clone). Empty creates a blank volume."
}

variable "subnet_id" {
  type        = string
  description = "A PRIVATE subnet. The box never gets a public IP; it reaches the internet through a NAT or endpoints."
}

variable "kms_key_arn" {
  type        = string
  default     = null
  description = "KMS key for the root and /work volumes. null uses the AWS-managed EBS key."
}

variable "root_disk_gb" {
  type        = number
  default     = 60
  description = "Size of the root volume in GiB."
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

variable "secrets_key_arn" {
  type        = string
  default     = null
  description = "The fleet's secrets key (the aws-secrets-key module's key_arn). When set, the box's instance role is tagged with the fleet and may encrypt and decrypt only secrets whose encryption context names this box."

  validation {
    condition     = var.secrets_key_arn == null || can(regex("^arn:aws[a-z-]*:kms:[a-z0-9-]+:[0-9]{12}:key/[0-9a-f-]+$", var.secrets_key_arn))
    error_message = "secrets_key_arn must be a KMS key ARN."
  }
}

variable "fleet" {
  type        = string
  default     = null
  description = "The fleet name the secrets key was made for (the aws-secrets-key module's fleet output). Required with secrets_key_arn."

  validation {
    condition     = var.fleet == null || can(regex("^[a-z]([a-z0-9-]{0,28}[a-z0-9])?$", var.fleet))
    error_message = "fleet must be lowercase letters, digits and hyphens."
  }
}

variable "box_secrets_backend" {
  type        = string
  default     = null
  description = "Where this box's own secrets (Staging keys for its role) are kept: aws-ssm (Parameter Store) or openbao. null: the box keeps none. Written as an instance tag; the box reads it at boot. Nothing about it is in the first-boot configuration."

  validation {
    condition     = var.box_secrets_backend == null || contains(["aws-ssm", "openbao"], coalesce(var.box_secrets_backend, "-"))
    error_message = "box_secrets_backend must be aws-ssm or openbao."
  }
}

variable "box_secrets_prefix" {
  type        = string
  default     = null
  description = "The path prefix the box's secrets live under, like /ozbox/dev. With aws-ssm the instance role may read exactly <prefix>/<box_role> and below, and nothing else."

  validation {
    condition     = var.box_secrets_prefix == null || can(regex("^/[A-Za-z0-9_.-]+(/[A-Za-z0-9_.-]+)*$", coalesce(var.box_secrets_prefix, "/")))
    error_message = "box_secrets_prefix must start with / and hold plain path segments (letters, digits, _ . -), with no trailing slash."
  }

  validation {
    condition     = var.box_secrets_prefix == null || (!strcontains(coalesce(var.box_secrets_prefix, ""), "..") && length(coalesce(var.box_secrets_prefix, "")) <= 100)
    error_message = "box_secrets_prefix must not contain .. and must be at most 100 characters."
  }
}

variable "box_role" {
  type        = string
  default     = null
  description = "The box's role, the path segment its secrets are scoped by (like main or worker). Required with box_secrets_backend."

  validation {
    condition     = var.box_role == null || can(regex("^[a-z0-9]([a-z0-9-]{0,30}[a-z0-9])?$", coalesce(var.box_role, "-")))
    error_message = "box_role must be lowercase letters, digits and dashes, at most 32 characters."
  }
}

variable "box_secrets_kms_key_arn" {
  type        = string
  default     = null
  description = "The customer-managed KMS key the SecureString parameters are encrypted with, when not the AWS-managed SSM key. The box may decrypt with it only through Parameter Store."

  validation {
    condition     = var.box_secrets_kms_key_arn == null || can(regex("^arn:aws[a-z-]*:kms:[a-z0-9-]+:[0-9]{12}:key/[0-9a-f-]+$", coalesce(var.box_secrets_kms_key_arn, "-")))
    error_message = "box_secrets_kms_key_arn must be a KMS key ARN."
  }
}

variable "session_log_bucket" {
  type        = string
  default     = null
  description = "The locked bucket Session Manager writes session logs to (the aws-security-baseline module's session_log_bucket output). When set, the box's instance role may write only under ozbox/sessions/ in that bucket (and read its encryption setting, which the agent checks). null: no change to the role."

  validation {
    condition     = var.session_log_bucket == null || can(regex("^[a-z0-9][a-z0-9.-]{1,61}[a-z0-9]$", coalesce(var.session_log_bucket, "-")))
    error_message = "session_log_bucket must be a bucket name."
  }
}

variable "patch_group" {
  type        = string
  default     = null
  description = "The Patch Manager patch group (the aws-security-baseline module's patch_group output). When set, the box carries the tag Patch Group so the fleet's patch baseline and maintenance window reach it. null: no tag, the account's default baseline applies."

  validation {
    condition     = var.patch_group == null || can(regex("^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$", coalesce(var.patch_group, "-")))
    error_message = "patch_group must be letters, digits, dots, dashes or underscores."
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

variable "session_policy_name" {
  type        = string
  default     = "ozbox-box-session-manager"
  description = "The customer-managed policy a box's role carries for Systems Manager (made once per account by `ozbox init`, the aws-box-policy module). It must exist in the account before a box is created or upgraded."

  validation {
    condition     = can(regex("^ozbox-box-[a-z0-9-]{1,40}$", var.session_policy_name))
    error_message = "session_policy_name must start with ozbox-box- (the operator role may attach only a policy of that name)."
  }
}

variable "fleet_manager" {
  type        = bool
  default     = false
  description = "This box manages the fleet from its own dashboard (ADR 0040). Tags the machine and its disks ozbox-fleet-manager=true, which the fleet roles are denied any change to: main can never stop, destroy, resize, snapshot or clone itself through them."
}
