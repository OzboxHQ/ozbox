variable "name" {
  type        = string
  default     = "ozbox"
  description = "Name of the fleet this document belongs to (the same name as the fleet's secrets key): lowercase letters, digits and single hyphens, starting with a letter, at most 30 characters."

  validation {
    condition     = can(regex("^[a-z]([a-z0-9-]{0,28}[a-z0-9])?$", var.name)) && !strcontains(var.name, "--")
    error_message = "name must start with a lowercase letter, contain only lowercase letters, digits and single hyphens, end with a letter or digit, and be at most 30 characters."
  }
}

variable "account_id" {
  type        = string
  description = "The AWS account id the document is made in (twelve digits)."

  validation {
    condition     = can(regex("^[0-9]{12}$", var.account_id))
    error_message = "account_id must be twelve digits."
  }
}

variable "labels" {
  type        = map(string)
  default     = {}
  description = "Extra tags."
}
