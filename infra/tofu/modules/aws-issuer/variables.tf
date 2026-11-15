variable "name" {
  type        = string
  default     = "ozbox"
  description = "Name of the fleet this issuer serves: lowercase letters, digits and single hyphens, starting with a letter, at most 24 characters."

  validation {
    condition     = can(regex("^[a-z]([a-z0-9-]{0,22}[a-z0-9])?$", var.name)) && !strcontains(var.name, "--")
    error_message = "name must start with a lowercase letter, contain only lowercase letters, digits and single hyphens, end with a letter or digit, and be at most 24 characters."
  }
}

variable "account_id" {
  type        = string
  description = "The AWS account that holds the Production secrets and runs the issuer (twelve digits). Its root may administer the Production key but never use it to decrypt."

  validation {
    condition     = can(regex("^[0-9]{12}$", var.account_id))
    error_message = "account_id must be twelve digits."
  }
}

variable "region" {
  type        = string
  description = "The region the issuer and the Production secrets are in."

  validation {
    condition     = can(regex("^[a-z]{2}(-[a-z]+)+-[0-9]$", var.region))
    error_message = "region must look like us-east-1."
  }
}

variable "secret_name_prefix" {
  type        = string
  default     = "ozbox/production/"
  description = "Every Production secret's name starts with this. It is what the one role that can read Production is allowed to name, and it ends with a slash."

  validation {
    condition     = can(regex("^[A-Za-z0-9/_+=.@-]+/$", var.secret_name_prefix)) && !startswith(var.secret_name_prefix, "/")
    error_message = "secret_name_prefix must be letters, digits and /_+=.@- , end with a slash and not start with one."
  }
}

variable "package_path" {
  type        = string
  default     = "issuer.zip"
  description = "The issuer function's package: a zip holding the `bootstrap` program built from the ozbox-issuer crate. Built by the owner and checked against package_sha256; this module does not build or fetch it."
}

variable "package_sha256" {
  type        = string
  description = "The package's SHA-256, base64 (what `openssl dgst -sha256 -binary issuer.zip | base64` prints). The function does not change unless this does."

  validation {
    condition     = can(regex("^[A-Za-z0-9+/]{43}=$", var.package_sha256))
    error_message = "package_sha256 must be a base64 SHA-256 (44 characters ending in =)."
  }
}

variable "audit_bucket_arn" {
  type        = string
  default     = ""
  description = "The Object Lock bucket the issuer's own record is written to (its ARN), or empty for none. The issuer may add objects under issuer/ and nothing else: no delete, no bypass of retention."

  validation {
    condition     = var.audit_bucket_arn == "" || can(regex("^arn:aws[a-z-]*:s3:::[a-z0-9.-]{3,63}$", var.audit_bucket_arn))
    error_message = "audit_bucket_arn must be a bucket ARN, or empty."
  }
}

variable "operator_role_arns" {
  type        = list(string)
  default     = []
  description = "The owner's roles that may write Production secrets (encrypt with the Production key). They cannot read: decrypting is the release role's alone."

  validation {
    condition     = alltrue([for a in var.operator_role_arns : can(regex("^arn:aws[a-z-]*:iam::[0-9]{12}:role/.+$", a))])
    error_message = "operator_role_arns must be IAM role ARNs."
  }
}

variable "box_role_arns" {
  type        = list(string)
  default     = []
  description = "Boxes' instance roles that may ask the issuer for an approval and a release (invoke only). Not given any read of Production."

  validation {
    condition     = alltrue([for a in var.box_role_arns : can(regex("^arn:aws[a-z-]*:iam::[0-9]{12}:role/.+$", a))])
    error_message = "box_role_arns must be IAM role ARNs."
  }
}

variable "log_retention_days" {
  type        = number
  default     = 365
  description = "How long the function's own log is kept."
}

variable "labels" {
  type        = map(string)
  default     = {}
  description = "Extra tags."
}
