variable "name" {
  type        = string
  default     = "ozbox-box-session-manager"
  description = "The policy's name. The operator role may attach exactly this policy (by ARN) to a box's role, and the box module looks it up by this name: change it in both places or not at all."

  validation {
    condition     = can(regex("^ozbox-box-[a-z0-9-]{1,40}$", var.name))
    error_message = "the name must start with ozbox-box- (the setup identity's permissions are scoped to that prefix)."
  }
}

variable "parameter_root" {
  type        = string
  default     = "/ozbox"
  description = "The Parameter Store path every box's own secrets live under (a box declares <root>/<name>/<role>). A box's role may read only <its prefix>/<its role>, and only when its prefix is under this root, so it can never name another product's parameters."

  validation {
    condition     = can(regex("^/[A-Za-z0-9_.-]+$", var.parameter_root))
    error_message = "parameter_root must be one path segment starting with /, like /ozbox."
  }
}

variable "fleet" {
  type        = string
  default     = null
  description = "The fleet name (the aws-secrets-key module's fleet output). With fleet_key_arn, makes ozbox-box-fleet-key-<fleet>."

  validation {
    condition     = var.fleet == null || can(regex("^[a-z]([a-z0-9-]{0,28}[a-z0-9])?$", var.fleet))
    error_message = "fleet must be lowercase letters, digits and hyphens."
  }
}

variable "fleet_key_arn" {
  type        = string
  default     = null
  description = "The fleet's secrets key (the aws-secrets-key module's key_arn). A box's role may use it only for secrets whose encryption context names that box (its ozbox-box tag)."

  validation {
    condition     = var.fleet_key_arn == null || can(regex("^arn:aws[a-z-]*:kms:[a-z0-9-]+:[0-9]{12}:key/[0-9a-f-]+$", var.fleet_key_arn))
    error_message = "fleet_key_arn must be a KMS key ARN."
  }
}

variable "box_secrets_kms_key_arn" {
  type        = string
  default     = null
  description = "A customer key that encrypts the box's own parameters: a box's role may decrypt with it only through Parameter Store."

  validation {
    condition     = var.box_secrets_kms_key_arn == null || can(regex("^arn:aws[a-z-]*:kms:[a-z0-9-]+:[0-9]{12}:key/[0-9a-f-]+$", var.box_secrets_kms_key_arn))
    error_message = "box_secrets_kms_key_arn must be a KMS key ARN."
  }
}

variable "session_log_bucket" {
  type        = string
  default     = null
  description = "The locked session-log bucket (the aws-security-baseline module's), when session logging is on."
}
