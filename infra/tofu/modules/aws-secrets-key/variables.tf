variable "name" {
  type        = string
  default     = "ozbox"
  description = "Name of the fleet this key belongs to: lowercase letters, digits and single hyphens, starting with a letter, at most 30 characters."

  validation {
    condition     = can(regex("^[a-z]([a-z0-9-]{0,28}[a-z0-9])?$", var.name)) && !strcontains(var.name, "--")
    error_message = "name must start with a lowercase letter, contain only lowercase letters, digits and single hyphens, end with a letter or digit, and be at most 30 characters."
  }
}

variable "account_id" {
  type        = string
  description = "The AWS account id that owns the key (twelve digits). Its root may administer the key but never use it to decrypt."

  validation {
    condition     = can(regex("^[0-9]{12}$", var.account_id))
    error_message = "account_id must be twelve digits."
  }
}

variable "operator_role_arns" {
  type        = list(string)
  default     = []
  description = "IAM roles of the operator that may encrypt and decrypt with the key (to provision and rotate secrets). Nobody else but this fleet's boxes can."

  validation {
    condition     = alltrue([for a in var.operator_role_arns : can(regex("^arn:aws[a-z-]*:iam::[0-9]{12}:role/.+$", a))])
    error_message = "operator_role_arns must be IAM role ARNs."
  }
}

variable "labels" {
  type        = map(string)
  default     = {}
  description = "Extra tags."
}

variable "deletion_window_days" {
  type        = number
  default     = 30
  description = "How long a deleted key can still be recovered (7 to 30)."

  validation {
    condition     = var.deletion_window_days >= 7 && var.deletion_window_days <= 30
    error_message = "deletion_window_days must be between 7 and 30."
  }
}
